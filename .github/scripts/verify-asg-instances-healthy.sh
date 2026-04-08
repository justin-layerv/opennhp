#!/bin/bash
# Verify every InService instance in an ASG responds to a local health check.
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

if [[ $# -lt 4 ]]; then
  echo "Usage: $0 <asg_name> <label> <timeout_minutes> <shell_cmd>" >&2
  exit 2
fi

ASG_NAME="$1"
LABEL="$2"
TIMEOUT_MINUTES="$3"
SHELL_CMD="$4"

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

# Run $SHELL_CMD on a single instance via SSM and return one of:
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
  local cmd_id status

  cmd_id=$(aws ssm send-command \
    --instance-ids "$instance_id" \
    --document-name "AWS-RunShellScript" \
    --timeout-seconds 30 \
    --parameters "commands=[\"$SHELL_CMD\"]" \
    --query "Command.CommandId" --output text 2>/dev/null) || { echo "ssm_failed"; return; }

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
    Success)             echo "ok" ;;
    Failed|TimedOut|Cancelled) echo "unhealthy" ;;
    *)                   echo "ssm_failed" ;;
  esac
}

DEADLINE=$(($(date +%s) + TIMEOUT_MINUTES * 60))
ITERATION=0
while [[ $(date +%s) -lt $DEADLINE ]]; do
  ITERATION=$((ITERATION + 1))
  REMAINING=$(( (DEADLINE - $(date +%s)) / 60 ))

  ALL_OK=true
  for inst in "${INSTANCE_IDS[@]}"; do
    result=$(check_one "$inst")
    case "$result" in
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
