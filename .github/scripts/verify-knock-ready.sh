#!/usr/bin/env bash
# verify-knock-ready.sh — poll every InService instance in an ASG until
# all report AC peers connected via /health/knock-ready, then verify the
# server process did not crash during the deploy window.
#
# Usage: verify-knock-ready.sh <asg-name> <label> <timeout-minutes> [check-nrestarts]
#
# Exits 0 if all instances report healthy across two consecutive
# iterations AND (when check-nrestarts=true, the default) none have
# a non-zero systemd NRestarts counter. Exits 1 otherwise.
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
# this out through check_nrestarts into background subshells that
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

# _nrestarts_probe_once INSTANCE_ID → one NRestarts probe attempt.
# Echoes the integer counter on success, or "probe_failed: <detail>"
# on any failure. Never exits non-zero (see _ssm_run's contract).
_nrestarts_probe_once() {
  local instance_id="$1"
  local output

  if ! output=$(_ssm_run "$instance_id" \
      'commands=["systemctl show nhp-server --property=NRestarts --value"]' \
      2); then
    echo "probe_failed: $output"
    return
  fi

  output=$(tr -d '[:space:]' <<<"$output")
  if [[ "$output" =~ ^[0-9]+$ ]]; then
    echo "$output"
  else
    echo "probe_failed: parse ${output:0:80}"
  fi
}

# check_nrestarts INSTANCE_ID → echoes the systemd NRestarts counter
# for nhp-server ("0" on a healthy never-crashed process), or
# "probe_failed" if the SSM call itself errored. A user-driven
# `systemctl restart` does NOT increment this counter — only
# unexpected exits re-executed via Restart=. Any non-zero value is
# therefore a direct signal that the process crashed during this
# deploy window.
#
# Wraps _nrestarts_probe_once with a single retry on probe_failed.
# The readiness gate above has already proven SSM works against these
# instances, so a single transient-throttle or eventual-consistency
# hiccup should not turn the deploy red. A real IAM/connectivity
# break re-fails after the retry and still produces the same
# fail-closed probe_failed output.
check_nrestarts() {
  local instance_id="$1"
  local result

  result=$(_nrestarts_probe_once "$instance_id")
  if [[ "$result" != probe_failed* ]]; then
    echo "$result"
    return
  fi

  sleep 2
  _nrestarts_probe_once "$instance_id"
}

# verify_no_crashes runs check_nrestarts against every instance and
# echoes an "::error::" line for each non-zero counter. Returns 0 if
# every instance reports NRestarts=0, 1 otherwise (including on probe
# failures — we fail closed, because we cannot confirm the deploy was
# clean without the counter).
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
# Throttling note: each check_nrestarts attempt issues up to 1
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
  local inst n tmpdir
  local -a pids=()

  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' RETURN

  for inst in "${INSTANCE_IDS[@]}"; do
    check_nrestarts "$inst" > "$tmpdir/$inst" 2>&1 &
    pids+=("$!")
  done

  # Collect all PIDs before inspecting results so one slow probe can't
  # fail closed early while others are still in flight.
  for pid in "${pids[@]}"; do
    wait "$pid" || true
  done

  for inst in "${INSTANCE_IDS[@]}"; do
    n=$(<"$tmpdir/$inst")
    # The "crashed" branch only fires on a bare positive integer.
    # Anything else (probe_failed prefix, empty file from a killed
    # subshell, typo'd sentinel) falls through to the catch-all
    # probe-failure branch -- never misreported as "crashed N times".
    if [[ "$n" == "0" ]]; then
      echo "[$LABEL] $inst: NRestarts=0"
    elif [[ "$n" =~ ^[1-9][0-9]*$ ]]; then
      echo "::error::[$LABEL] $inst: nhp-server NRestarts=$n — the server process crashed $n time(s) during this deploy. This is the regression class fixed by PR #1096 (panic: send on closed channel). Investigate journalctl -u nhp-server on this instance before re-deploying."
      failed=true
    else
      echo "::error::[$LABEL] $inst: NRestarts probe failed — cannot confirm the deploy window was crash-free ($n)"
      failed=true
    fi
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
      echo "::error::[$LABEL] Knock-readiness converged but at least one instance crashed during the deploy window"
      exit 1
    fi
  else
    if [[ $CONSECUTIVE_READY -gt 0 ]]; then
      echo "[$LABEL] iter $ITERATION: ready streak broken — resetting consecutive count from $CONSECUTIVE_READY to 0"
    fi
    CONSECUTIVE_READY=0
  fi
  sleep 10
done

echo "::error::[$LABEL] Did not reach $CONSECUTIVE_REQUIRED consecutive all-ready iterations within ${TIMEOUT_MINUTES} minutes"
exit 1
