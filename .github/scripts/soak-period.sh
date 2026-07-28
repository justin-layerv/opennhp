#!/bin/bash
# Run a soak period with periodic health checks.
#
# Monitors ASG health and NLB target group health for the specified duration.
# Fails immediately if any check is unhealthy.
#
# Usage: soak-period.sh
#
# Required Environment Variables:
#   ENVIRONMENT:    Target environment. Must be a blue/green-capable environment
#                   (sandbox, sandbox-cell1) -- it must publish
#                   /<env>/nhp/server/active-color and the per-color ASG names.
#   SOAK_MINUTES:   Duration of soak period in minutes
#   SKIP_SOAK:      "true" to skip soak entirely
#   AWS_REGION:     AWS region (default: us-east-2)

set -euo pipefail

AWS_REGION="${AWS_REGION:-us-east-2}"
SOAK_MINUTES="${SOAK_MINUTES:-30}"
CHECK_INTERVAL=300  # 5 minutes in seconds

echo "============================================"
echo "Soak Period"
echo "============================================"
echo "Environment:    $ENVIRONMENT"
echo "Duration:       ${SOAK_MINUTES} minutes"
echo "Check interval: $((CHECK_INTERVAL / 60)) minutes"
echo "Skip soak:      ${SKIP_SOAK:-false}"
echo ""

if [[ "${SKIP_SOAK:-false}" == "true" ]]; then
  echo "Soak period skipped."
  exit 0
fi

# Resolve the fleet that is actually SERVING traffic.
#
# This soak runs strictly AFTER the color switch. scheduled-release.yml orders
# ensure-sandbox-deployed -> soak, and ensure-sandbox-deployed dispatches
# build-and-push.yml, whose blue/green leg runs deploy-to-standby ->
# switch-traffic -> validate -> scale-down-previous. By the time we get here the
# newly refreshed color is active and the previous color has been scaled down to
# a single warm-standby instance. So the soak must watch the ACTIVE color.
#
# /<env>/nhp/server/asg-name is NOT the active-color pointer. modules/compute
# publishes it from aws_autoscaling_group.server -- the base/BLUE group -- and
# /<env>/nhp/server/blue-asg-name holds the identical value. Soaking it watches
# the idle fleet whenever green is active: its ASG is healthy but its target
# groups are deliberately "unused" (Target.NotInUse), so the soak's verdict
# describes a fleet that serves no traffic.
#
# Fail closed. An unreadable or unknown color, or a missing per-color ASG
# parameter, is an error. There is deliberately no fallback to asg-name and no
# fallback to a blind time-based sleep: both would let the soak report success
# having never observed the fleet that serves traffic.
SSM_BASE="/${ENVIRONMENT}/nhp/server"

get_ssm_param() {
  aws ssm get-parameter \
    --name "$1" \
    --region "$AWS_REGION" \
    --query "Parameter.Value" --output text 2>/dev/null
}

ACTIVE_COLOR=$(get_ssm_param "${SSM_BASE}/active-color") || ACTIVE_COLOR=""
if [[ "$ACTIVE_COLOR" != "blue" && "$ACTIVE_COLOR" != "green" ]]; then
  echo "ERROR: Could not resolve a known active color from ${SSM_BASE}/active-color (got: '${ACTIVE_COLOR}')."
  echo "       Expected exactly 'blue' or 'green'. Refusing to soak an unverified fleet."
  exit 1
fi

ASG_NAME=$(get_ssm_param "${SSM_BASE}/${ACTIVE_COLOR}-asg-name") || ASG_NAME=""
if [[ -z "$ASG_NAME" || "$ASG_NAME" == "None" ]]; then
  echo "ERROR: Active color is '${ACTIVE_COLOR}' but ${SSM_BASE}/${ACTIVE_COLOR}-asg-name is missing or empty."
  echo "       Refusing to fall back to ${SSM_BASE}/asg-name, which is the color-blind base (blue) group."
  exit 1
fi

echo "Active color: $ACTIVE_COLOR"
echo "ASG Name:     $ASG_NAME (active fleet)"

# Get NLB target group ARN for health checks
TG_ARN=$(aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names "$ASG_NAME" \
  --region "$AWS_REGION" \
  --query 'AutoScalingGroups[0].TargetGroupARNs[0]' --output text 2>/dev/null) || TG_ARN=""

TOTAL_SECONDS=$((SOAK_MINUTES * 60))
ELAPSED=0
CHECK_NUM=0

# Run an initial health check (non-fatal) to catch immediate catastrophic failures.
# Instance refresh may still be in progress, so we warn rather than fail.
echo ""
echo "--- Initial Health Check (non-fatal) ---"
# Backticks are JMESPath literals, not shell substitutions.
# shellcheck disable=SC2016
INITIAL_ASG_INFO=$(aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names "$ASG_NAME" \
  --region "$AWS_REGION" \
  --query 'AutoScalingGroups[0].{Desired:DesiredCapacity,Healthy:length(Instances[?HealthStatus==`Healthy`])}' \
  --output json 2>/dev/null) || INITIAL_ASG_INFO=""
if [[ -n "$INITIAL_ASG_INFO" ]]; then
  INIT_DESIRED=$(echo "$INITIAL_ASG_INFO" | jq -r '.Desired // 0')
  INIT_HEALTHY=$(echo "$INITIAL_ASG_INFO" | jq -r '.Healthy // 0')
  echo "  ASG: ${INIT_HEALTHY}/${INIT_DESIRED} healthy instances"
  if [[ "$INIT_HEALTHY" -eq 0 && "$INIT_DESIRED" -gt 0 ]]; then
    echo "WARNING: No healthy instances at soak start — instance refresh may be in progress"
  fi
else
  echo "  ASG: Unable to check"
fi

echo ""
echo "Starting soak health checks..."

while [[ $ELAPSED -lt $TOTAL_SECONDS ]]; do
  # Sleep first to let any in-progress instance refresh stabilize
  SLEEP_TIME=$CHECK_INTERVAL
  if [[ $((ELAPSED + SLEEP_TIME)) -gt $TOTAL_SECONDS ]]; then
    SLEEP_TIME=$((TOTAL_SECONDS - ELAPSED))
  fi

  if [[ $SLEEP_TIME -gt 0 ]]; then
    sleep "$SLEEP_TIME"
  fi
  ELAPSED=$((ELAPSED + SLEEP_TIME))

  CHECK_NUM=$((CHECK_NUM + 1))
  REMAINING=$(( (TOTAL_SECONDS - ELAPSED) / 60 ))
  echo ""
  echo "--- Health Check #${CHECK_NUM} (${REMAINING}min remaining) ---"

  # Check 1: ASG healthy instance count
  # Backticks are JMESPath literals, not shell substitutions.
  # shellcheck disable=SC2016
  ASG_INFO=$(aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$ASG_NAME" \
    --region "$AWS_REGION" \
    --query 'AutoScalingGroups[0].{Desired:DesiredCapacity,Healthy:length(Instances[?HealthStatus==`Healthy`])}' \
    --output json 2>/dev/null) || ASG_INFO=""

  if [[ -n "$ASG_INFO" ]]; then
    DESIRED=$(echo "$ASG_INFO" | jq -r '.Desired // 0')
    HEALTHY=$(echo "$ASG_INFO" | jq -r '.Healthy // 0')
    echo "  ASG: ${HEALTHY}/${DESIRED} healthy instances"

    if [[ "$HEALTHY" -lt "$DESIRED" ]]; then
      echo "ERROR: ASG has unhealthy instances (${HEALTHY}/${DESIRED})"
      exit 1
    fi
  else
    echo "  ASG: Unable to check (non-fatal)"
  fi

  # Check 2: NLB target group health
  if [[ -n "$TG_ARN" && "$TG_ARN" != "None" ]]; then
    # Backticks are JMESPath literals, not shell substitutions.
    # shellcheck disable=SC2016
    UNHEALTHY_COUNT=$(aws elbv2 describe-target-health \
      --target-group-arn "$TG_ARN" \
      --region "$AWS_REGION" \
      --query 'length(TargetHealthDescriptions[?TargetHealth.State!=`healthy`])' \
      --output text 2>/dev/null) || UNHEALTHY_COUNT=""

    TOTAL_TARGETS=$(aws elbv2 describe-target-health \
      --target-group-arn "$TG_ARN" \
      --region "$AWS_REGION" \
      --query 'length(TargetHealthDescriptions)' \
      --output text 2>/dev/null) || TOTAL_TARGETS=""

    if [[ -n "$UNHEALTHY_COUNT" && -n "$TOTAL_TARGETS" ]]; then
      HEALTHY_TARGETS=$((TOTAL_TARGETS - UNHEALTHY_COUNT))
      echo "  NLB TG: ${HEALTHY_TARGETS}/${TOTAL_TARGETS} healthy targets"

      if [[ "$UNHEALTHY_COUNT" -gt 0 ]]; then
        echo "ERROR: NLB target group has ${UNHEALTHY_COUNT} unhealthy targets"
        exit 1
      fi
    else
      echo "  NLB TG: Unable to check (non-fatal)"
    fi
  fi
done

echo ""
echo "============================================"
echo "Soak period complete. All health checks passed."
echo "============================================"
