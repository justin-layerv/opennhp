#!/bin/bash
# Verify every InService instance in an ASG responds to a local health check.
# Requires Bash 4+ for associative arrays used to dedupe SSM failure details.
#
# Linked invariants in Go tests: nhp/tests/smoke/03_ssm_runbook_test.go
# fences the two regressions this script has already hit:
#   - TestSSMRunbook_TimeoutMeetsAPIMinimum pins --timeout-seconds 30
#     as the API minimum (PR #1005 used 15 and silently failed).
#   - TestSSMRunbook_ShellCmdHasNoDoubleQuotes Go-side-checks the
#     runtime guard below, so a future edit that tries to
#     embed `"` inside commands=[...] is caught at PR time.
# Keep the two files in sync: changes here should trigger a review of
# the corresponding smoke test.
#
# Why this exists (and why we can't use `aws elbv2 describe-target-health`
# for the standby side of blue/green):
#
#   Blue/green deploys only attach ONE color's target groups to the NLB
#   listener at a time. The standby color's target groups have no listener
#   — and NLB refuses to run health checks on a target group that has no
#   listener pointing at it, so `describe-target-health` returns the
#   permanent state "unused / Target.NotInUse". That means the standby TG
#   can never flip to "healthy", the pre-switch health gate can never pass,
#   and every blue/green deploy times out after the health check window
#   no matter how fit the new instances actually are.
#
#   The correct shape of the check is therefore an out-of-band probe that
#   talks directly to each standby instance (via SSM RunShellScript) and
#   asks "are you up and responding?" — exactly what NLB *would* ask if
#   the target group were attached. Once this script passes, the listener
#   switch is safe because the "Switch Traffic" step then flips the NLB
#   to the standby TG, and NLB starts its own health checks from "initial"
#   state on targets we already know are live.
#
# Usage: verify-asg-instances-healthy.sh <asg_name> <label> <timeout_minutes> <shell_cmd>
#
#   asg_name         — ASG whose InService instances we probe
#   label            — tag prefixed to every log line (e.g. "Server-Standby")
#   timeout_minutes  — how long to keep retrying before giving up
#   shell_cmd        — command run via SSM on each instance. Must exit 0
#                      when the instance is healthy and non-zero otherwise.
#                      Run under /bin/sh by SSM's AWS-RunShellScript, so
#                      pipelines, &&, ||, and redirection all work.
#                      MUST NOT contain double quotes — the command is
#                      embedded into the AWS CLI shorthand parameter
#                      `commands=["..."]`. Single quotes and every other
#                      shell metacharacter are fine.
#
# Example:
#   verify-asg-instances-healthy.sh layerv-nhp-sandbox-server-green \
#     "Server-Standby" 5 \
#     'docker exec nhp-server wget -q -O - http://127.0.0.1:8888/health/live >/dev/null'
#
# Exit codes: 0 on success, 1 on timeout or ASG empty, 2 on argument error.

set -euo pipefail

if (( BASH_VERSINFO[0] < 4 )); then
  echo "verify-asg-instances-healthy.sh requires Bash 4+ for associative arrays" >&2
  exit 2
fi

if [[ $# -lt 4 ]]; then
  echo "Usage: $0 <asg_name> <label> <timeout_minutes> <shell_cmd>" >&2
  exit 2
fi

ASG_NAME="$1"
LABEL="$2"
TIMEOUT_MINUTES="$3"
SHELL_CMD="$4"

# check_one must run in this shell so SSM_HEALTH_DETAIL_DUMPED persists
# across retry iterations; CHECK_ONE_RESULT carries the return category
# without command substitution creating a subshell.
declare -A SSM_HEALTH_DETAIL_DUMPED=()
CHECK_ONE_RESULT=""

print_ssm_content() {
  local instance_id="$1"
  local stream_name="$2"
  local content="$3"

  # Keep the None guard for any future --output text query path; AWS CLI
  # renders null text fields as the literal string "None".
  if [[ -z "$content" || "$content" == "None" ]]; then
    return 0
  fi

  echo "[$LABEL] $instance_id health command ${stream_name} (first 40 lines, 500 chars/line):" >&2
  printf '%s\n' "$content" | sed -n '1,40p' | cut -c1-500 >&2
}

hash_ssm_failure_detail() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    cksum | awk '{print $1 ":" $2}'
  fi
}

print_ssm_failure_details_once() {
  local instance_id="$1"
  local status="$2"
  local response_code="$3"
  local stdout_content="$4"
  local stderr_content="$5"
  local detail_hash detail_key

  # Dump verbose details once per unique instance+payload for the whole run;
  # the lightweight status breadcrumb above still prints every retry iteration.
  detail_hash=$(printf '%s\0%s\0%s\0%s' "$status" "$response_code" "$stdout_content" "$stderr_content" | hash_ssm_failure_detail)
  detail_key="${instance_id}:${detail_hash}"
  if [[ -n "${SSM_HEALTH_DETAIL_DUMPED[$detail_key]:-}" ]]; then
    return 0
  fi
  SSM_HEALTH_DETAIL_DUMPED[$detail_key]=1

  print_ssm_content "$instance_id" "stdout" "$stdout_content"
  print_ssm_content "$instance_id" "stderr" "$stderr_content"
}

if ! [[ "$TIMEOUT_MINUTES" =~ ^[0-9]+$ ]] || (( TIMEOUT_MINUTES < 1 )); then
  echo "::error::[$LABEL] timeout_minutes must be a positive integer, got '$TIMEOUT_MINUTES'" >&2
  exit 2
fi

echo "[$LABEL] Verifying instance health on ASG: $ASG_NAME (timeout ${TIMEOUT_MINUTES}m)"

# Enumerate InService instances once up-front. The ASG should already be
# stable by the time this script runs (instance refresh has completed),
# so we don't re-poll the ASG on every iteration — if an instance
# terminates mid-check the outer loop will catch it when SSM fails.
# The `tr + grep -v ^$` dance is required because AWS CLI emits a single
# empty line when the query returns nothing — without the filter, mapfile
# creates a 1-element array containing "" and the downstream count check
# passes with an invalid instance id.
mapfile -t INSTANCE_IDS < <(aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names "$ASG_NAME" \
  --query "AutoScalingGroups[0].Instances[?LifecycleState=='InService'].InstanceId" \
  --output text | tr '\t' '\n' | grep -v '^$' | sort)

if [[ ${#INSTANCE_IDS[@]} -eq 0 ]]; then
  echo "::error::[$LABEL] No InService instances found in ASG $ASG_NAME" >&2
  exit 1
fi
echo "[$LABEL] Probing ${#INSTANCE_IDS[@]} instance(s): ${INSTANCE_IDS[*]}"

# Guard-rail: the AWS CLI shorthand `commands=["..."]` has no way to
# escape an embedded double quote, so reject the command up front rather
# than failing mid-loop with an opaque "Invalid JSON" error.
if [[ "$SHELL_CMD" == *'"'* ]]; then
  echo "::error::[$LABEL] shell_cmd must not contain double quotes (got: $SHELL_CMD)" >&2
  exit 2
fi

# Run $SHELL_CMD on a single instance via SSM and set CHECK_ONE_RESULT to:
#   ok          — command exited 0
#   unhealthy   — command completed with non-zero exit
#   ssm_failed  — SSM itself did not reach a terminal state
#
# `--timeout-seconds 30` is the minimum the SSM API accepts; it bounds
# how long SSM itself will wait for the command to be delivered before
# giving up. The poll loop below bounds how long *we* wait for SSM to
# return — combined worst-case is ~20s per instance per iteration.
check_one() {
  local instance_id="$1"
  local cmd_id status invocation_json response_code stdout_content stderr_content
  local parsed_response_code parsed_stdout_content parsed_stderr_content

  CHECK_ONE_RESULT=""

  cmd_id=$(aws ssm send-command \
    --instance-ids "$instance_id" \
    --document-name "AWS-RunShellScript" \
    --timeout-seconds 30 \
    --parameters "commands=[\"$SHELL_CMD\"]" \
    --query "Command.CommandId" --output text 2>/dev/null) || { CHECK_ONE_RESULT="ssm_failed"; return; }

  # Give SSM a moment to schedule, then poll for completion. Treat any
  # terminal status as "stop polling" so we don't burn the full window
  # waiting on a command that has already given up.
  sleep 3
  for _ in 1 2 3 4 5; do
    status=$(aws ssm get-command-invocation \
      --command-id "$cmd_id" --instance-id "$instance_id" \
      --query "Status" --output text 2>/dev/null) || status="Pending"
    case "$status" in
      Success|Failed|TimedOut|Cancelled) break ;;
    esac
    sleep 3
  done

  case "$status" in
    Success)
      CHECK_ONE_RESULT="ok"
      ;;
    Failed|TimedOut|Cancelled)
      response_code="unknown"
      stdout_content=""
      stderr_content=""
      if invocation_json=$(aws ssm get-command-invocation \
        --command-id "$cmd_id" --instance-id "$instance_id" \
        --query "{ResponseCode:ResponseCode,StandardOutputContent:StandardOutputContent,StandardErrorContent:StandardErrorContent}" \
        --output json 2>/dev/null); then
        if command -v jq >/dev/null 2>&1; then
          if parsed_response_code=$(jq -r '.ResponseCode // "unknown"' <<<"$invocation_json" 2>/dev/null) \
            && parsed_stdout_content=$(jq -r '.StandardOutputContent // ""' <<<"$invocation_json" 2>/dev/null) \
            && parsed_stderr_content=$(jq -r '.StandardErrorContent // ""' <<<"$invocation_json" 2>/dev/null); then
            response_code="$parsed_response_code"
            stdout_content="$parsed_stdout_content"
            stderr_content="$parsed_stderr_content"
          else
            stdout_content="$invocation_json"
          fi
        else
          # GitHub's Ubuntu runners include jq, and neighboring deploy helpers
          # rely on it too. If a local runner lacks jq, still dump the bounded
          # raw invocation JSON so the failure is not reduced to a status line.
          stdout_content="$invocation_json"
        fi
      fi

      echo "[$LABEL] $instance_id health command status=$status response_code=$response_code" >&2
      print_ssm_failure_details_once \
        "$instance_id" "$status" "$response_code" "$stdout_content" "$stderr_content" || true
      CHECK_ONE_RESULT="unhealthy"
      ;;
    *)
      CHECK_ONE_RESULT="ssm_failed"
      ;;
  esac
}

DEADLINE=$(($(date +%s) + TIMEOUT_MINUTES * 60))
ITERATION=0
while [[ $(date +%s) -lt $DEADLINE ]]; do
  ITERATION=$((ITERATION + 1))
  REMAINING=$(( (DEADLINE - $(date +%s)) / 60 ))

  ALL_OK=true
  for inst in "${INSTANCE_IDS[@]}"; do
    check_one "$inst"
    case "$CHECK_ONE_RESULT" in
      ok)
        echo "[$LABEL] [iter $ITERATION, ${REMAINING}m left] $inst: ok"
        ;;
      unhealthy)
        echo "[$LABEL] [iter $ITERATION, ${REMAINING}m left] $inst: unhealthy (exit non-zero)"
        ALL_OK=false
        ;;
      ssm_failed)
        echo "[$LABEL] [iter $ITERATION, ${REMAINING}m left] $inst: SSM unreachable, retrying"
        ALL_OK=false
        ;;
    esac
  done

  if [[ "$ALL_OK" == "true" ]]; then
    echo "[$LABEL] All ${#INSTANCE_IDS[@]} instance(s) passed health check — proceeding"
    exit 0
  fi
  sleep 10
done

echo "::error::[$LABEL] Not all instances passed health check after ${TIMEOUT_MINUTES} minutes" >&2
exit 1
