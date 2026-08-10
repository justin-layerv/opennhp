#!/usr/bin/env bash
# verify-knock-ready.sh — poll every InService instance in an ASG until
# all report AC peers connected via /health/knock-ready, then verify the
# server process did not crash during the deploy window.
#
# Usage: verify-knock-ready.sh <asg-name> <label> <timeout-minutes> [check-nrestarts]
#
# Exits 0 if all instances report healthy across two consecutive
# iterations AND (when check-nrestarts=true, the default) none restarted
# in a way that indicates an application crash. Exits 1 otherwise.
#
# A non-zero systemd NRestarts counter is the trigger for that second
# check, not the verdict: docker failing to start the container (exit 125,
# e.g. a transient CloudWatch Logs error in the awslogs driver) increments
# it just as a Go panic does, but no nhp-server code ran and systemd's
# Restart=always policy heals it in seconds. The evidence probe and
# classify-nhp-server-restart-evidence.sh separate the two; treating them
# alike cost four hours of blocked sandbox deploys on 2026-08-09.
#
# check-nrestarts (4th arg, default "true"): pass "false" when the
# target ASG is long-lived (e.g., pre-switch invocations against the
# active color). NRestarts is a per-boot counter that persists for
# the instance's lifetime, so on a fleet that's been up for hours
# or days it accumulates across unrelated incidents and the probe
# returns stale data. Keep the default "true" when the fleet was
# just refreshed (post-switch against the newly-active color);
# NRestarts=0 at launch means any non-zero reading is this deploy's
# window and the probe is semantically correct.
#
# Exit status: 0 all healthy, 1 a gate failed, 2 a usage or ENVIRONMENT error
# (bad check-nrestarts argument, or a missing jq — see the preflight below).
#
# Uses SSM RunShellScript to curl each instance's /health/knock-ready
# endpoint. Captures stderr from AWS CLI calls to surface real errors
# (not swallow them with 2>/dev/null).
#
# Why this is separate from verify-asg-instances-healthy.sh:
# knock-ready requires parsing the JSON response body to extract
# ac_peers.message for diagnostics, plus handling the KNOCK_NOT_READY
# fallback from curl failures. The generic script only checks exit codes.
#
# Why two consecutive iterations + NRestarts check:
# On every sandbox blue/green deploy prior to PR #1096, the nhp-server
# process crash-looped (panic: send on closed channel during AC
# registration race). systemd restarted it with a ~5 s gap each time.
# The previous single-iteration "all ready" check was structurally
# blind to this pattern — a one-off snapshot could land between crash
# cycles while the system was still broken. Two consecutive
# observations catch the flap; the NRestarts counter catches any crash
# that happened during the window but stabilised before the final
# observation.

set -euo pipefail

# Resolved from BASH_SOURCE, not $PWD: the workflow invokes this by repo-root
# relative path, but the fixtures run it from elsewhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# jq parses every SSM response here and builds the evidence probe's parameters.
# It has always been required (the pre-existing readiness probe parses .Status
# and .StandardOutputContent with it); state that up front so a runner without
# it fails with this line instead of a confusing mid-probe parse error.
#
# Only jq is checked, not every dependency: aws/mktemp/tr fail loudly and
# obviously by name, whereas a missing jq surfaced as an empty parse deep
# inside a probe. This is a targeted fix for that one ambiguous failure, not a
# claim that the script is dependency-complete.
if ! command -v jq >/dev/null 2>&1; then
  echo "::error::verify-knock-ready.sh requires jq (used to build SSM parameters and parse every command invocation)"
  exit 2
fi

ASG_NAME="${1:?Usage: verify-knock-ready.sh <asg-name> <label> <timeout-minutes> [check-nrestarts]}"
LABEL="${2:?}"
TIMEOUT_MINUTES="${3:?}"
CHECK_NRESTARTS="${4:-true}"
if [[ "$CHECK_NRESTARTS" != "true" && "$CHECK_NRESTARTS" != "false" ]]; then
  echo "::error::check-nrestarts must be 'true' or 'false'; got '$CHECK_NRESTARTS'"
  exit 2
fi

# Discover InService instances
mapfile -t INSTANCE_IDS < <(aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names "$ASG_NAME" \
  --query "AutoScalingGroups[0].Instances[?LifecycleState=='InService'].InstanceId" \
  --output text | tr '\t' '\n' | grep -v '^$' | sort)

if [[ ${#INSTANCE_IDS[@]} -eq 0 ]]; then
  echo "::error::[$LABEL] No InService instances in ASG $ASG_NAME"
  exit 1
fi
echo "[$LABEL] Checking ${#INSTANCE_IDS[@]} instance(s): ${INSTANCE_IDS[*]}"

# _ssm_run INSTANCE_ID COMMANDS_JSON POLL_SLEEP
#
# Send an SSM RunShellScript command, poll GetCommandInvocation until
# it reaches a terminal state, and capture the command's stdout.
# On Success: prints the captured stdout and returns 0.
# On any failure (send error, poll timeout, non-Success terminal):
# prints a short human-readable reason and returns 1.
#
# ABI note: every failure path returns 1 -- callers MUST guard the
# invocation with `if !` or `|| <fallback>`. verify_no_crashes fans
# this out through check_restart_evidence into background subshells that
# inherit `set -euo pipefail`; an unguarded non-zero would kill the
# subshell before the caller's result capture landed. Every AWS CLI
# invocation inside this function is correspondingly guarded by
# `if !`/`|| <fallback>` so transient errors bubble up through the
# function's return code instead of tripping set -e mid-body.
#
# Fuses Status and StandardOutputContent into one GetCommandInvocation
# call via jq. The pre-refactor code issued two calls (one for status,
# one for output) which added a round-trip per probe.
#
# Requires bash >= 4.4 for the function-scoped RETURN trap (no
# functrace inheritance by default). GitHub Actions' ubuntu-latest
# ships bash 5.x; do not downgrade to older runner images without
# revisiting the nested trap interaction between _ssm_run and
# verify_no_crashes.
_ssm_run() {
  local instance_id="$1"
  local commands_json="$2"
  local poll_sleep="$3"
  local cmd_id status resp stderr_file captured_err

  stderr_file=$(mktemp)
  trap 'rm -f "$stderr_file"' RETURN

  if ! cmd_id=$(aws ssm send-command \
      --instance-ids "$instance_id" \
      --document-name "AWS-RunShellScript" \
      --timeout-seconds 30 \
      --parameters "$commands_json" \
      --query "Command.CommandId" --output text 2>"$stderr_file"); then
    captured_err=$(tr '\n' ' ' < "$stderr_file")
    echo "send-command: ${captured_err:0:200}"
    return 1
  fi

  sleep "$poll_sleep"
  status="Pending"
  resp=""
  for _ in 1 2 3 4; do
    if resp=$(aws ssm get-command-invocation \
        --command-id "$cmd_id" --instance-id "$instance_id" \
        --output json 2>"$stderr_file"); then
      status=$(jq -r '.Status // "Pending"' <<<"$resp")
    else
      status="Pending"
      resp=""
    fi
    case "$status" in
      Success|Failed|TimedOut|Cancelled) break ;;
    esac
    sleep "$poll_sleep"
  done

  if [[ "$status" != "Success" ]]; then
    captured_err=$(tr '\n' ' ' < "$stderr_file")
    if [[ -n "$captured_err" ]]; then
      echo "status=$status: ${captured_err:0:200}"
    else
      echo "status=$status"
    fi
    return 1
  fi

  jq -r '.StandardOutputContent // ""' <<<"$resp"
  return 0
}

# check_one INSTANCE_ID → echoes "ready <detail>" / "not_ready <detail>" / "ssm_failed <detail>"
check_one() {
  local instance_id="$1"
  local output

  # curl -sS without -f: /health/knock-ready returns 503 with a JSON
  # body when ACs aren't connected — we want to parse both 200 and
  # 503 bodies. 2>&1 merges curl stderr into stdout for diagnostics.
  # || echo KNOCK_NOT_READY is a fallback if curl itself fails.
  if ! output=$(_ssm_run "$instance_id" \
      'commands=["curl -sS http://127.0.0.1:8888/health/knock-ready 2>&1 || echo KNOCK_NOT_READY"]' \
      3); then
    echo "ssm_failed $output"
    return
  fi

  # curl failure path
  if [[ "$output" == *"KNOCK_NOT_READY"* ]]; then
    local curl_err
    curl_err=$(printf '%s' "$output" \
      | grep -v '^KNOCK_NOT_READY$' \
      | tr '\n' ' ' \
      | head -c 200)
    if [[ -n "$curl_err" ]]; then
      echo "not_ready ${curl_err}"
    else
      echo "not_ready"
    fi
    return
  fi

  # Parse JSON response
  local parsed body_status ac_msg
  parsed=$(echo "$output" | jq -r '"\(.status // "")|\(.checks.ac_peers.message // "no message")"' 2>/dev/null) || parsed=""
  if [[ -z "$parsed" ]]; then
    echo "not_ready"
    return
  fi
  body_status="${parsed%%|*}"
  ac_msg="${parsed#*|}"
  if [[ "$body_status" == "healthy" ]]; then
    echo "ready ${ac_msg}"
    return
  fi
  echo "not_ready ${ac_msg}"
}

# RESTART_EVIDENCE_SCRIPT is the on-instance probe. NRestarts alone cannot
# tell an application crash from a docker container-start failure that
# systemd's Restart=always policy already healed, so the probe collects the
# evidence that can: the unit's abnormal exit statuses (docker reports its own
# failures as 125), whether a Go panic or OOM kill appears in the journal, and
# whether the unit is running right now.
#
# Deliberately NOT collected: `systemctl show -p ExecMainStatus`. It reports
# the SURVIVING process's status, so it reads 0 on exactly the instance whose
# previous start attempt failed — it looks healthy when a start failed and is
# not proof of anything.
#
# Scoped to `-b` (this boot) to match NRestarts' own per-boot semantics, which
# is sound precisely because the crash probe only runs against a just-refreshed
# fleet (see verify_no_crashes). `-n` bounds the scan on an instance that has
# been up longer than expected.
#
# The `|| true` after each `grep -c` is not only guarding grep's exit-1
# "no match": a grep runtime error (exit 2) is swallowed the same way, leaving
# the field EMPTY rather than 0. That is deliberate and fails closed — an empty
# counter is non-numeric to the classifier, which returns indeterminate instead
# of silently reading a failed scan as "no panics".
#
# Every field is reduced to one line on the instance so the report stays a
# small key=value document; DAEMONERR is additionally bounded and stripped of
# the characters that would break the report's line framing.
#
# OOM matches only systemd's own unit-scoped message. The kernel's
# "Out of memory: Killed process" line carries no _SYSTEMD_UNIT, so
# `journalctl -u` never returns it — an earlier version grepped for it and
# for `oom-kill:` too, which could not have matched anything. A container OOM
# also surfaces as exit 137 (128+SIGKILL), which the exit-status branch fails
# on regardless.
#
# DAEMONERR skips "No such container": the unit's own
# `ExecStartPre=-/usr/bin/docker stop|rm nhp-server` emits that on every clean
# start, so it is the LAST daemon error in the journal after a failed start
# that systemd then retried successfully. Reporting it would name the harmless
# line and hide the failure that actually caused the restart. Confirmed
# against a live sandbox instance, where a healthy unit's only daemon error
# is exactly this.
# shellcheck disable=SC2016  # single-quoted on purpose: every $ and \ in here
# is for the remote shell, not this one. Expanding locally would ship the
# runner's empty variables to the instance.
RESTART_EVIDENCE_SCRIPT='set -u
u=nhp-server
printf "NRESTARTS=%s\n" "$(systemctl show $u --property=NRestarts --value 2>/dev/null)"
printf "ACTIVESTATE=%s\n" "$(systemctl show $u --property=ActiveState --value 2>/dev/null)"
printf "SUBSTATE=%s\n" "$(systemctl show $u --property=SubState --value 2>/dev/null)"
j=$(journalctl -u $u -b -n 20000 --no-pager -o cat 2>/dev/null || true)
printf "EXITS=%s\n" "$(printf "%s\n" "$j" | sed -n "s/.*Main process exited, code=\([a-z]*\), status=\([0-9]*\).*/\1:\2/p" | tr "\n" ",")"
printf "PANICS=%s\n" "$(printf "%s\n" "$j" | grep -cE "^(panic: |fatal error: |goroutine [0-9]+ \[running\]:)" || true)"
printf "OOM=%s\n" "$(printf "%s\n" "$j" | grep -c "killed by the OOM killer" || true)"
printf "DAEMONERR=%s\n" "$(printf "%s\n" "$j" | grep -oE "Error response from daemon: .*" | grep -v "No such container" | tail -n 1 | tr -d "\r" | cut -c1-200 | tr -d "\n")"'

# _restart_evidence_probe_once INSTANCE_ID → one evidence probe attempt.
# Echoes the multi-line evidence report on success, or a single
# "probe_failed: <detail>" line on any failure. Never exits non-zero (see
# _ssm_run's contract).
_restart_evidence_probe_once() {
  local instance_id="$1"
  local output params

  # Built with jq rather than the CLI's `commands=[...]` shorthand: the probe
  # script contains quotes, brackets and backslashes that the shorthand parser
  # would mangle.
  params=$(jq -nc --arg c "$RESTART_EVIDENCE_SCRIPT" '{commands:[$c]}')

  # poll_sleep=4, not the readiness probe's 3, because this is the HEAVIER
  # command — it reads the boot journal and runs four passes over it, where the
  # readiness probe is one loopback curl. A window that expires before a
  # slow-but-successful probe returns would read as probe_failed and fail the
  # deploy closed, which is the same false-red this script exists to stop.
  #
  # The observable window is 4 x poll_sleep = 16 s, NOT 5 x. _ssm_run sleeps
  # once up front and then checks at the TOP of each of four iterations, so
  # statuses are seen at t=4/8/12/16; the fourth iteration's trailing sleep is
  # dead time no check follows. (That loop shape predates this probe and is
  # shared with the readiness path, so it is left alone rather than reshaped
  # here.)
  #
  # 16 s is the whole execution budget, NOT 30 s: send-command's
  # --timeout-seconds bounds DELIVERY to the instance, not how long the command
  # may run, so a probe whose on-instance work exceeds the poll window reads as
  # probe_failed on both the attempt and the retry — failing the deploy closed,
  # the very false-red this file exists to stop.
  #
  # Measured on a live sandbox server instance (up 1h33m): the whole boot
  # journal was 29 lines / 2,280 bytes and the full probe took 53 ms — roughly
  # a 300x margin. `-n 20000` is nowhere near binding on a freshly-refreshed
  # fleet, which is the only fleet this probe runs against. If that margin ever
  # erodes, the fix is to bound the on-instance journalctl scan, not to raise
  # the poll count: more polls widen the window for a probe that is already
  # too slow, while a tighter scan makes it fast again.
  if ! output=$(_ssm_run "$instance_id" "$params" 4); then
    echo "probe_failed: $output"
    return
  fi

  # NRESTARTS is the one field with no meaningful default — its absence means
  # the probe ran but produced nothing usable, which must not reach the
  # classifier as a parseable-but-empty report.
  if ! grep -q '^NRESTARTS=[0-9]' <<<"$output"; then
    echo "probe_failed: parse $(tr '\n' ' ' <<<"${output:0:120}")"
    return
  fi

  printf '%s\n' "$output"
}

# check_restart_evidence INSTANCE_ID → echoes the evidence report for
# nhp-server, or a "probe_failed: ..." line if the SSM call itself errored.
#
# A user-driven `systemctl restart` does NOT increment NRestarts — only
# unexpected exits re-executed via Restart=. A non-zero counter therefore
# means the unit did restart unexpectedly during this deploy window; what it
# does NOT tell you is whether nhp-server crashed or whether docker failed to
# start the container at all. classify-nhp-server-restart-evidence.sh draws
# that line from the rest of this report.
#
# Wraps _restart_evidence_probe_once with a single retry on probe_failed.
# The readiness gate above has already proven SSM works against these
# instances, so a single transient-throttle or eventual-consistency
# hiccup should not turn the deploy red. A real IAM/connectivity
# break re-fails after the retry and still produces the same
# fail-closed probe_failed output.
check_restart_evidence() {
  local instance_id="$1"
  local result

  result=$(_restart_evidence_probe_once "$instance_id")
  if [[ "$result" != probe_failed* ]]; then
    printf '%s\n' "$result"
    return
  fi

  sleep 2
  _restart_evidence_probe_once "$instance_id"
}

# verify_no_crashes runs check_restart_evidence against every instance and
# classifies each report. Returns 0 when every instance either never
# restarted or restarted only because docker could not start the container
# and systemd already healed it; 1 otherwise (including on probe failures —
# we fail closed, because we cannot confirm the deploy was clean without the
# evidence).
#
# The pass-with-warning case is deliberate. Before it existed, a transient
# CloudWatch Logs failure inside docker's awslogs driver (exit 125, container
# never started, healthy again 6 s later) failed this gate as a #1096-class Go
# panic. That failed the `validate` job, which skipped `scale-down-previous`
# and left `safe_to_release=false`, retaining the shared sandbox lock for its
# full four-hour TTL — see docs/runbooks/sandbox-live-env-lock.md. Failing the
# gate but releasing the lock was the wrong trade: the listeners have already
# moved by this point, so a failure here also strands the previous color
# scaled up, which is exactly the unreconciled state the lock exists to fence.
# A fleet that converged should finish converging.
#
# NRestarts is a per-boot counter (systemd resets it when the unit is
# first started on the host). The "fresh instance" invariant (NRestarts
# begins at 0 on launch) only holds when the target ASG was just
# refreshed -- hence the caller-side gate: this function is only
# invoked when check-nrestarts=true (default, post-switch). Pre-switch
# callers pass "false" because they target the long-lived active ASG
# whose NRestarts accumulates unrelated historical crashes. When the
# gate is honored, any non-zero reading means the nhp-server process
# exited unexpectedly during THIS deploy window, which is the signal
# we want to catch.
#
# Probes run in parallel -- one background subshell per instance,
# each capturing its single-line result to a per-instance tempfile --
# so the wall-clock cost stays ~one SSM round-trip regardless of fleet
# size. Results are read back in INSTANCE_IDS order for deterministic
# log output.
#
# Throttling note: each check_restart_evidence attempt issues up to 1
# send-command + 4 get-command-invocation calls, and retries once on
# probe_failed (so ~10 SSM API calls per instance worst case, all
# concurrent across the fleet). Current sandbox + prod fleets are
# small enough that this is well below the SSM per-region soft
# limits, but a fleet substantially larger than ~10 instances may
# need staggered dispatch or a bounded worker pool to avoid
# ThrottlingException landing in the probe_failed branch and
# masking a real crash-free deploy as fail-closed.
verify_no_crashes() {
  local failed=false
  local inst report verdict detail line tmpdir
  local -a pids=()

  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' RETURN

  for inst in "${INSTANCE_IDS[@]}"; do
    check_restart_evidence "$inst" > "$tmpdir/$inst" 2>&1 &
    pids+=("$!")
  done

  # Collect all PIDs before inspecting results so one slow probe can't
  # fail closed early while others are still in flight.
  for pid in "${pids[@]}"; do
    wait "$pid" || true
  done

  for inst in "${INSTANCE_IDS[@]}"; do
    report=$(<"$tmpdir/$inst")

    # An unusable report (probe_failed prefix, empty file from a killed
    # subshell) never reaches the classifier, so it can never be reported
    # as a specific verdict about the deploy.
    if [[ "$report" == probe_failed* || -z "$report" ]]; then
      echo "::error::[$LABEL] $inst: restart-evidence probe failed — cannot confirm the deploy window was crash-free (${report:-empty response})"
      failed=true
      continue
    fi

    verdict=""
    detail=""
    while IFS= read -r line; do
      case "$line" in
        verdict=*) verdict="${line#verdict=}" ;;
        detail=*) detail="${line#detail=}" ;;
      esac
    done < <(bash "$SCRIPT_DIR/classify-nhp-server-restart-evidence.sh" <<<"$report" || true)

    case "$verdict" in
      clean)
        echo "[$LABEL] $inst: $detail"
        ;;
      infra_selfhealed)
        # Pass, loudly. The deploy is sound but an operator should still see
        # that the container runtime blipped.
        echo "::warning::[$LABEL] $inst: nhp-server restarted during this deploy, but not because of an application crash. $detail"
        ;;
      app_crash|infra_unstable|indeterminate)
        echo "::error::[$LABEL] $inst: nhp-server restart classified as '$verdict'. $detail"
        failed=true
        ;;
      *)
        echo "::error::[$LABEL] $inst: restart-evidence classifier returned no verdict — cannot confirm the deploy window was crash-free. Report: $(tr '\n' ' ' <<<"$report")"
        failed=true
        ;;
    esac
  done

  [[ "$failed" == "false" ]]
}

# Poll loop
#
# We require CONSECUTIVE_REQUIRED full-ready observations in a row, not
# a single one, so a transient "all ready" snapshot between crash cycles
# cannot pass the gate. After the final observation, verify_no_crashes
# catches any crash that happened earlier in the window but stabilised
# before our polling cadence observed it. See PR #1096 and the header
# comment for the rationale.
DEADLINE=$(($(date +%s) + TIMEOUT_MINUTES * 60))
ITERATION=0
CONSECUTIVE_READY=0
CONSECUTIVE_REQUIRED=2
while [[ $(date +%s) -lt $DEADLINE ]]; do
  ITERATION=$((ITERATION + 1))
  REMAINING=$(( (DEADLINE - $(date +%s)) / 60 ))

  ALL_READY=true
  for inst in "${INSTANCE_IDS[@]}"; do
    result=$(check_one "$inst")
    kind="${result%% *}"
    detail="${result#* }"
    [[ "$kind" == "$detail" ]] && detail=""
    case "$kind" in
      ready)
        echo "[$LABEL] [iter $ITERATION, ${REMAINING}m left] $inst: ready ($detail)"
        ;;
      not_ready)
        echo "[$LABEL] [iter $ITERATION, ${REMAINING}m left] $inst: not yet ($detail)"
        ALL_READY=false
        ;;
      ssm_failed)
        if [[ -n "$detail" ]]; then
          echo "[$LABEL] [iter $ITERATION, ${REMAINING}m left] $inst: SSM failed ($detail), retrying"
        else
          echo "[$LABEL] [iter $ITERATION, ${REMAINING}m left] $inst: SSM failed, retrying"
        fi
        ALL_READY=false
        ;;
      *)
        echo "[$LABEL] [iter $ITERATION, ${REMAINING}m left] $inst: unknown result '$result'"
        ALL_READY=false
        ;;
    esac
  done

  if [[ "$ALL_READY" == "true" ]]; then
    CONSECUTIVE_READY=$((CONSECUTIVE_READY + 1))
    echo "[$LABEL] iter $ITERATION: all ${#INSTANCE_IDS[@]} instance(s) ready (consecutive=$CONSECUTIVE_READY/$CONSECUTIVE_REQUIRED)"
    if [[ $CONSECUTIVE_READY -ge $CONSECUTIVE_REQUIRED ]]; then
      if [[ "$CHECK_NRESTARTS" == "false" ]]; then
        echo "[$LABEL] Reached $CONSECUTIVE_REQUIRED consecutive all-ready iterations; crash probe disabled (check-nrestarts=false -- target ASG is long-lived, NRestarts reflects accumulated history not this deploy window)"
        exit 0
      fi
      echo "[$LABEL] Reached $CONSECUTIVE_REQUIRED consecutive all-ready iterations; verifying no crash occurred during the deploy window"
      if verify_no_crashes; then
        echo "[$LABEL] All ${#INSTANCE_IDS[@]} instance(s) stable and crash-free"
        exit 0
      fi
      echo "::error::[$LABEL] Knock-readiness converged but at least one instance restarted for a reason this gate will not pass; see the per-instance classification above"
      exit 1
    fi
  else
    if [[ $CONSECUTIVE_READY -gt 0 ]]; then
      echo "[$LABEL] iter $ITERATION: ready streak broken — resetting consecutive count from $CONSECUTIVE_READY to 0"
    fi
    CONSECUTIVE_READY=0
  fi
  # LOAD-BEARING: this 10s inter-iteration sleep, combined with
  # CONSECUTIVE_REQUIRED=2, defines the gate's full convergence cost
  # (≈10s sleep + handshake RTT) that's mirrored as
  # blueGreenGateConvergenceCost in
  # endpoints/ac/registration_resilience_test.go's
  # worst_case_fire_plus_convergence_fits_workflow_minimum_gate
  # subtest. A bump here without a matching bump there silently
  # narrows the override-regime safety margin — see PR #1726.
  sleep 10
done

echo "::error::[$LABEL] Did not reach $CONSECUTIVE_REQUIRED consecutive all-ready iterations within ${TIMEOUT_MINUTES} minutes"
exit 1
