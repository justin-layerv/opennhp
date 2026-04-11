#!/usr/bin/env bash
# verify-knock-ready.sh — poll every InService instance in an ASG until
# all report AC peers connected via /health/knock-ready.
#
# Usage: verify-knock-ready.sh <asg-name> <label> <timeout-minutes>
#
# Exits 0 if all instances report healthy within the timeout.
# Exits 1 if any instance fails to reach healthy.
#
# Uses SSM RunShellScript to curl each instance's /health/knock-ready
# endpoint. Captures stderr from AWS CLI calls to surface real errors
# (not swallow them with 2>/dev/null).
#
# Why this is separate from verify-asg-instances-healthy.sh:
# knock-ready requires parsing the JSON response body to extract
# ac_peers.message for diagnostics, plus handling the KNOCK_NOT_READY
# fallback from curl failures. The generic script only checks exit codes.

set -euo pipefail

ASG_NAME="${1:?Usage: verify-knock-ready.sh <asg-name> <label> <timeout-minutes>}"
LABEL="${2:?}"
TIMEOUT_MINUTES="${3:?}"

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

# check_one INSTANCE_ID → echoes "ready <detail>" / "not_ready <detail>" / "ssm_failed <detail>"
check_one() {
  local instance_id="$1"
  local cmd_id status output stderr_file captured_err

  stderr_file=$(mktemp)

  # SSM --timeout-seconds 30 is the API minimum.
  # curl -sS without -f: /health/knock-ready returns 503 with JSON body
  # when ACs aren't connected — we want to parse both 200 and 503 bodies.
  # 2>&1 merges curl stderr into stdout for diagnostics.
  # || echo KNOCK_NOT_READY: fallback if curl itself fails.
  if ! cmd_id=$(aws ssm send-command \
      --instance-ids "$instance_id" \
      --document-name "AWS-RunShellScript" \
      --timeout-seconds 30 \
      --parameters 'commands=["curl -sS http://127.0.0.1:8888/health/knock-ready 2>&1 || echo KNOCK_NOT_READY"]' \
      --query "Command.CommandId" --output text 2>"$stderr_file"); then
    captured_err=$(tr '\n' ' ' < "$stderr_file")
    rm -f "$stderr_file"
    echo "ssm_failed send-command: ${captured_err:0:200}"
    return
  fi

  # Poll for SSM command completion (up to ~15s)
  sleep 3
  status="Pending"
  for _ in 1 2 3 4; do
    status=$(aws ssm get-command-invocation \
      --command-id "$cmd_id" --instance-id "$instance_id" \
      --query "Status" --output text 2>"$stderr_file") || status="Pending"
    case "$status" in
      Success|Failed|TimedOut|Cancelled) break ;;
    esac
    sleep 3
  done

  if [[ "$status" != "Success" ]]; then
    captured_err=$(tr '\n' ' ' < "$stderr_file")
    rm -f "$stderr_file"
    if [[ -n "$captured_err" ]]; then
      echo "ssm_failed status=$status: ${captured_err:0:200}"
    else
      echo "ssm_failed status=$status"
    fi
    return
  fi

  output=$(aws ssm get-command-invocation \
    --command-id "$cmd_id" --instance-id "$instance_id" \
    --query "StandardOutputContent" --output text 2>/dev/null) || output=""
  rm -f "$stderr_file"

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

# Poll loop
DEADLINE=$(($(date +%s) + TIMEOUT_MINUTES * 60))
ITERATION=0
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
    echo "[$LABEL] All ${#INSTANCE_IDS[@]} instance(s) report AC peers connected"
    exit 0
  fi
  sleep 10
done

echo "::error::[$LABEL] Not all instances reported AC peers after ${TIMEOUT_MINUTES} minutes"
exit 1
