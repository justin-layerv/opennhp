#!/usr/bin/env bash
# classify-nhp-server-restart-evidence.sh — decide what a non-zero systemd
# NRestarts counter on an nhp-server instance actually means.
#
# Reads an evidence report on stdin (collected by verify-knock-ready.sh's
# on-instance probe) and prints a verdict plus a one-line, observation-only
# detail string:
#
#   verdict=<token>
#   detail=<what was actually observed>
#
# Exit status: 0 when the deploy gate may proceed, 1 when it must fail,
# 2 on usage error.
#
# ---------------------------------------------------------------------------
# Why this exists
# ---------------------------------------------------------------------------
# The post-switch gate used to treat *any* NRestarts >= 1 as an application
# crash and assert the PR #1096 regression class (panic: send on closed
# channel) in its error message. NRestarts alone cannot support that claim.
#
# Sandbox deploy 31340465407 (2026-08-09) failed the gate on this journal:
#
#   Started nhp-server.service
#   Main process exited, code=exited, status=125/n/a
#   Scheduled restart job, restart counter is at 1
#   Started nhp-server.service          <- healthy 6 s later
#
#   docker: Error response from daemon: failed to create task for container:
#   failed to initialize logging driver: failed to create Cloudwatch log stream
#
# Exit 125 is docker's "the run command itself failed" — here the awslogs
# driver could not create its CloudWatch log stream. The container never
# started, no Go code ran, and systemd's Restart=always/RestartSec=5 policy
# recovered it in seconds, exactly as designed. The gate nevertheless failed
# the `validate` job, which skipped `scale-down-previous` and left
# `safe_to_release=false`, retaining /layerv-nhp-sandbox/qurl-live-env-lock for
# its full 14400 s TTL: four hours of blocked sandbox deploys for the whole
# team, plus an error message sending the reader after a panic that never
# happened.
#
# ---------------------------------------------------------------------------
# What separates the two classes
# ---------------------------------------------------------------------------
# The load-bearing signal is the *unit exit status*, not the restart count:
#
#   * 125 is emitted by the docker CLI when the daemon refuses the run. The
#     container's entrypoint never executes, so it cannot be an nhp-server
#     defect.
#   * A Go panic terminates the process with status 2, and any signal death
#     (SIGSEGV, SIGKILL, the OOM killer's 137) reports as a non-125 status.
#
# So panic and OOM evidence corroborate the message but are not what keeps the
# classification safe: a genuine #1096-class panic is caught by the exit status
# even if its stack trace never reaches the unit journal (the unit runs
# `docker run` with --log-driver=awslogs, so container output goes to
# CloudWatch; it also reaches the journal via the attached CLI streams, but
# this classifier does not depend on that).
#
# `systemctl show -p ExecMainStatus` is deliberately NOT part of the evidence:
# it reports the status of the *surviving* process, so it reads 0 on exactly
# the instance whose previous start attempt failed. It is not proof of health.
#
# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------
#   clean             NRestarts=0. Nothing restarted.                  (pass)
#   infra_selfhealed  Every restart is an exit-125 container-start failure,
#                     the unit is running now, and the count is within
#                     MAX_SELF_HEALED_RESTARTS.                        (pass)
#   app_crash         A Go panic, an OOM kill, or a non-125 abnormal exit of
#                     the server process itself.                       (fail)
#   infra_unstable    All-125 container-start failures, but the unit has not
#                     converged or has flapped past the budget. Not an
#                     application defect, but not self-healed either.  (fail)
#   indeterminate     The report is malformed, or restarts outnumber the
#                     failures that would explain them. Fail closed.   (fail)
#
# MAX_SELF_HEALED_RESTARTS (env, default 2) bounds how much container-start
# flapping still counts as "self-healed". A transient CloudWatch Logs or
# daemon blip costs one or two attempts; a dozen is an infrastructure fault
# that an operator should see even though the fleet happens to be up.

set -euo pipefail

if [[ $# -ne 0 ]]; then
  echo "usage: $0 < evidence-report" >&2
  exit 2
fi

MAX_SELF_HEALED_RESTARTS="${MAX_SELF_HEALED_RESTARTS:-2}"
if ! [[ "$MAX_SELF_HEALED_RESTARTS" =~ ^[0-9]+$ ]]; then
  echo "usage: MAX_SELF_HEALED_RESTARTS must be a non-negative integer; got '$MAX_SELF_HEALED_RESTARTS'" >&2
  exit 2
fi

nrestarts=""
activestate=""
substate=""
exits=""
panics=""
oom=""
daemonerr=""

# Parse `key=value`, value being the rest of the line (DAEMONERR carries '='
# and ':'). Unknown keys are ignored so the on-instance probe can add evidence
# without a lockstep change here.
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ "$line" != *=* ]] && continue
  key="${line%%=*}"
  value="${line#*=}"
  case "$key" in
    NRESTARTS) nrestarts="$value" ;;
    ACTIVESTATE) activestate="$value" ;;
    SUBSTATE) substate="$value" ;;
    EXITS) exits="$value" ;;
    PANICS) panics="$value" ;;
    OOM) oom="$value" ;;
    DAEMONERR) daemonerr="$value" ;;
  esac
done

# emit VERDICT DETAIL — single exit point so every branch is shaped alike.
emit() {
  local verdict="$1" detail="$2"

  # The detail lands inside a `::error::`/`::warning::` workflow command, which
  # is newline-terminated; a raw journal line could otherwise end the
  # annotation early and split the rest into unattributed log output.
  detail="${detail//$'\r'/ }"
  detail="${detail//$'\n'/ }"

  printf 'verdict=%s\n' "$verdict"
  printf 'detail=%s\n' "$detail"

  case "$verdict" in
    clean|infra_selfhealed) exit 0 ;;
    *) exit 1 ;;
  esac
}

for required in "$nrestarts:NRESTARTS" "$activestate:ACTIVESTATE" "$substate:SUBSTATE" "$panics:PANICS" "$oom:OOM"; do
  if [[ -z "${required%%:*}" ]]; then
    emit indeterminate "evidence report is missing ${required#*:} — cannot classify the restart"
  fi
done

for numeric in "NRestarts:$nrestarts" "panic-line count:$panics" "OOM-line count:$oom"; do
  if ! [[ "${numeric#*:}" =~ ^[0-9]+$ ]]; then
    emit indeterminate "evidence report carries a non-numeric ${numeric%%:*} ('${numeric#*:}') — cannot classify the restart"
  fi
done

if [[ "$nrestarts" == "0" ]]; then
  emit clean "NRestarts=0"
fi

# Split `code:status,code:status,` into the non-zero exits — a status=0 entry
# is the deploy's own `systemctl restart` stop path, not a failed start.
#
# Every array expansion below uses the `${a[@]+...}` guard: bash 4.3 and older
# treat `"${empty[@]}"` as unbound under `set -u`, and this script is also run
# straight from a developer's shell.
nonzero_exits=()
exit_entries=()
IFS=',' read -r -a exit_entries <<<"$exits" || true
for entry in ${exit_entries[@]+"${exit_entries[@]}"}; do
  [[ -z "$entry" ]] && continue
  [[ "${entry##*:}" == "0" ]] && continue
  nonzero_exits+=("$entry")
done

observed="NRestarts=$nrestarts"
if [[ ${#nonzero_exits[@]} -gt 0 ]]; then
  observed+="; abnormal unit exits: ${nonzero_exits[*]}"
else
  observed+="; no abnormal unit exit recorded in the journal"
fi
if [[ "$panics" == "0" ]]; then
  observed+="; Go panic in journal: absent"
else
  observed+="; Go panic in journal: PRESENT ($panics line(s))"
fi
if [[ "$oom" == "0" ]]; then
  observed+="; OOM kill: absent"
else
  observed+="; OOM kill: PRESENT"
fi
observed+="; unit now: $activestate/$substate"

if [[ "$panics" != "0" ]]; then
  emit app_crash "$observed — the server process panicked during this deploy. This is the regression class fixed by PR #1096 (panic: send on closed channel). Investigate journalctl -u nhp-server on this instance before re-deploying."
fi

if [[ "$oom" != "0" ]]; then
  emit app_crash "$observed — the server process was killed by the OOM killer during this deploy. Check the instance's memory headroom and the server's allocation profile before re-deploying."
fi

# Any abnormal exit that is not docker's own 125 means the container's
# entrypoint ran and the server process itself died.
container_start_failures=0
for entry in ${nonzero_exits[@]+"${nonzero_exits[@]}"}; do
  if [[ "$entry" == "exited:125" ]]; then
    container_start_failures=$((container_start_failures + 1))
  else
    emit app_crash "$observed — exit $entry is the server process terminating abnormally, not a container-start failure (docker reports its own failures as exit 125). Investigate journalctl -u nhp-server on this instance before re-deploying."
  fi
done

if [[ -n "$daemonerr" ]]; then
  observed+="; last docker daemon error: $daemonerr"
fi

if [[ "$container_start_failures" -lt "$nrestarts" ]]; then
  emit indeterminate "$observed — only $container_start_failures of $nrestarts restart(s) are explained by a container-start failure; the remainder has no recorded cause. Investigate journalctl -u nhp-server on this instance before re-deploying."
fi

if [[ "$activestate" != "active" || "$substate" != "running" ]]; then
  emit infra_unstable "$observed — every restart is a docker container-start failure (exit 125), so no nhp-server code ran, but the unit has not converged to active/running."
fi

if [[ "$nrestarts" -gt "$MAX_SELF_HEALED_RESTARTS" ]]; then
  emit infra_unstable "$observed — every restart is a docker container-start failure (exit 125) and the unit is running now, but $nrestarts restarts exceeds the self-heal budget of $MAX_SELF_HEALED_RESTARTS. Treat this as an infrastructure fault (container runtime, log driver, or registry), not an nhp-server defect."
fi

emit infra_selfhealed "$observed — docker failed to start the container (exit 125), so no nhp-server code ran; systemd's Restart=always policy recovered it and the unit is healthy. Not an application crash."
