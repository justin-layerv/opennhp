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
#   app_crash         A non-125 abnormal exit of the server process itself, or
#                     an OOM kill.                                     (fail)
#   infra_unstable    All-125 container-start failures, but the unit has not
#                     converged or has flapped past the budget. Not an
#                     application defect, but not self-healed either.  (fail)
#   indeterminate     The report is malformed, or restarts outnumber the
#                     failures that would explain them. Fail closed.   (fail)
#
# Note what does NOT appear above: a panic-marker branch. Panic text is
# corroboration, never the verdict — see the block above the OOM check.
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

# KEEP THIS ASSIGNMENT ON ONE LINE in this exact form: Part E of
# tests/lints/blue-green-restart-classification/run-fixtures.sh extracts the
# default with an anchored sed to compare it against Go's maxSelfHealedRestarts.
# Reformatting does not silently disable the fence (it fails loudly with
# "asserting nothing") but will turn CI red unexpectedly.
MAX_SELF_HEALED_RESTARTS="${MAX_SELF_HEALED_RESTARTS:-2}"
# Bounded to 9 digits like the journal-derived counters below, for the same
# reason: an all-digit value that overflows bash's signed 64-bit arithmetic
# wraps rather than erroring, and a wrapped budget makes `nrestarts > MAX`
# answer arbitrarily. The override is operator-controlled and Part E of
# tests/lints/blue-green-restart-classification/run-fixtures.sh fences that no
# workflow sets it at all, so this is defence in depth rather than a reachable
# path — but it costs nothing and keeps one validation rule in this script
# instead of two.
if ! [[ "$MAX_SELF_HEALED_RESTARTS" =~ ^[0-9]{1,9}$ ]]; then
  echo "usage: MAX_SELF_HEALED_RESTARTS must be a non-negative integer of at most 9 digits; got '$MAX_SELF_HEALED_RESTARTS'" >&2
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

# ORDER IS LOAD-BEARING: this presence loop must stay AHEAD of the numeric loop
# below. A present-but-empty counter (`PANICS=`) has to report "missing PANICS",
# which is what the Go side reports for the same input — reversing the two would
# report "non-numeric" here and diverge the drivers on an identical report.
# Fenced, not just documented: swapping the loops turns several corpus cases red.
for required in "$nrestarts:NRESTARTS" "$activestate:ACTIVESTATE" "$substate:SUBSTATE" "$panics:PANICS" "$oom:OOM"; do
  if [[ -z "${required%%:*}" ]]; then
    emit indeterminate "evidence report is missing ${required#*:} — cannot classify the restart"
  fi
done

# Bounded to 9 digits, not just ^[0-9]+$. An all-digit value that overflows
# bash's signed 64-bit arithmetic wraps rather than erroring, and a wrapped
# NRestarts sailed through the accounting and budget comparisons to
# infra_selfhealed — the gate PASSING on a corrupted counter. Go's parseCounter
# applies the same bound, so both now reject it identically. A real NRestarts
# never approaches 9 digits.
for numeric in "NRestarts:$nrestarts" "panic-line count:$panics" "OOM-line count:$oom"; do
  if ! [[ "${numeric#*:}" =~ ^[0-9]{1,9}$ ]]; then
    emit indeterminate "evidence report carries a non-numeric or implausibly large ${numeric%%:*} (\"${numeric#*:}\") — cannot classify the restart"
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
  # An entry without a colon is malformed and is dropped rather than guessed
  # at — the same thing the Go classifier in tests/smoke/restart_evidence.go
  # does, so the two cannot diverge on it. Dropping is safe because a dropped
  # entry explains no restart, so the accounting check below still fails it
  # closed as indeterminate.
  [[ "$entry" != *:* ]] && continue
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
  observed+="; Go panic in journal: PRESENT"
fi
if [[ "$oom" == "0" ]]; then
  observed+="; OOM kill: absent"
else
  observed+="; OOM kill: PRESENT"
fi
observed+="; unit now: $activestate/$substate"

# Panic evidence is CORROBORATION, not its own decision branch. The verdict is
# carried by the exit status — a panicking process exits 2, so the non-125
# branch below catches a real panic whether or not its stack trace reached the
# journal. Pre-empting that with `panics != 0` made the panic grep decisive,
# which is how an application log line beginning at column 0 with `panic: `
# could turn an unrelated container-start self-heal into a claimed #1096
# regression. Kept as message material and as the two fail-closed cases below,
# which is exactly as far as this signal can carry.
#
# OOM stays decisive, unlike panic text, because it is systemd's own
# unit-scoped statement that it killed the process — not a string that
# application output can forge.
if [[ "$oom" != "0" ]]; then
  emit app_crash "$observed — the server process was killed by the OOM killer during this deploy. Check the instance's memory headroom and the server's allocation profile before re-deploying."
fi

# Any abnormal exit that is not docker's own 125 means the container's
# entrypoint ran and the server process itself died.
investigate="Investigate journalctl -u nhp-server on this instance before re-deploying."

container_start_failures=0
for entry in ${nonzero_exits[@]+"${nonzero_exits[@]}"}; do
  if [[ "$entry" == "exited:125" ]]; then
    container_start_failures=$((container_start_failures + 1))
  elif [[ "$panics" != "0" ]]; then
    emit app_crash "$observed — exit $entry with a Go panic in the journal: the server process panicked during this deploy. This is the regression class fixed by PR #1096 (panic: send on closed channel). $investigate"
  else
    emit app_crash "$observed — exit $entry is the server process terminating abnormally, not a container-start failure (docker reports its own failures as exit 125). $investigate"
  fi
done

if [[ -n "$daemonerr" ]]; then
  observed+="; last docker daemon error: $daemonerr"
fi

# Restarts nothing accounts for. When a panic marker is also present this is
# the likely shape of a real panic whose exit line never reached the scanned
# journal (journald rate-limiting drops systemd's follow-up lines during a
# multi-thousand-line goroutine dump), so say so rather than reporting a bare
# accounting gap.
# The two emits below are sequential rather than if/else on purpose: emit
# always exits (0 or 1), so the first one that fires ends the process. If emit
# is ever refactored to RETURN, this block must become an if/else — the Go
# mirror is naturally safe because it returns.
if [[ "$container_start_failures" -lt "$nrestarts" ]]; then
  if [[ "$panics" != "0" ]]; then
    emit indeterminate "$observed — only $container_start_failures of $nrestarts restart(s) are explained by a container-start failure, and a Go panic marker is present without a matching exit line. Most likely a real panic whose exit line was dropped from the journal. $investigate"
  fi
  emit indeterminate "$observed — only $container_start_failures of $nrestarts restart(s) are explained by a container-start failure; the remainder has no recorded cause. $investigate"
fi

if [[ "$activestate" != "active" || "$substate" != "running" ]]; then
  emit infra_unstable "$observed — every restart is a docker container-start failure (exit 125), so no nhp-server code ran, but the unit has not converged to active/running."
fi

if [[ "$nrestarts" -gt "$MAX_SELF_HEALED_RESTARTS" ]]; then
  emit infra_unstable "$observed — every restart is a docker container-start failure (exit 125) and the unit is running now, but $nrestarts restarts exceeds the self-heal budget of $MAX_SELF_HEALED_RESTARTS. Treat this as an infrastructure fault (container runtime, log driver, or registry), not an nhp-server defect."
fi

selfhealed_detail="$observed — docker failed to start the container (exit 125), so no nhp-server code ran; systemd's Restart=always policy recovered it and the unit is healthy. Not an application crash."

# A panic marker here caused NONE of the restarts: every one is accounted for
# by an exit 125, which a panicking process cannot produce (a real panic exits
# 2, and would have been caught either as a non-125 abnormal exit or as an
# unexplained restart above). So it is a recovered panic or an application log
# line beginning at column 0 with a panic marker.
#
# Surfaced loudly, but NOT made the verdict. Failing here would make panic text
# decisive exactly where the exit-status accounting is complete and says the
# deploy is fine — the same disproportionate response, and the same four-hour
# lock, that this classifier exists to remove, just triggered by a log-line
# shape instead of a bare counter.
if [[ "$panics" != "0" ]]; then
  selfhealed_detail+=" NOTE: a Go panic marker appears in this boot's journal but caused none of the restarts — most likely a recovered panic or a log line beginning with a panic marker. Worth a look; not a reason to block the deploy."
fi

emit infra_selfhealed "$selfhealed_detail"
