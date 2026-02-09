#!/bin/bash
# Run a soak period with periodic health checks.
#
# Monitors ASG health and NLB target group health for the specified duration.
# Fails immediately if any check is unhealthy.
#
# Usage: soak-period.sh
#
# Required Environment Variables:
#   ENVIRONMENT:    Target environment (sandbox, prod)
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

# Get ASG name from SSM
ASG_NAME=$(aws ssm get-parameter \
  --name "/${ENVIRONMENT}/nhp/server/asg-name" \
  --region "$AWS_REGION" \
  --query "Parameter.Value" --output text 2>/dev/null) || ASG_NAME=""

if [[ -z "$ASG_NAME" ]]; then
  echo "WARNING: Could not read ASG name from SSM. Falling back to time-based soak only."
  sleep "$((SOAK_MINUTES * 60))"
  echo "Soak period complete (time-based only)."
  exit 0
fi

echo "ASG Name: $ASG_NAME"

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
