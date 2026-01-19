#!/bin/bash
# Wait for ASG instance refresh to complete with optional canary health check.
# Usage: wait-for-instance-refresh.sh <asg-name> <refresh-id> [health-check-command] [max-iterations]
#
# Arguments:
#   asg-name:             Name of the Auto Scaling Group
#   refresh-id:           Instance refresh ID to monitor
#   health-check-command: Optional SSM command to verify instance health (default: skip health check)
#   max-iterations:       Optional max wait iterations, each 10s (default: 60 = 10 minutes)
#
# Exit codes:
#   0 - Instance refresh completed successfully
#   1 - Instance refresh failed or cancelled

set -euo pipefail

ASG_NAME="${1:?Usage: $0 <asg-name> <refresh-id> [health-check-command] [max-iterations]}"
REFRESH_ID="${2:?Usage: $0 <asg-name> <refresh-id> [health-check-command] [max-iterations]}"
HEALTH_CHECK_CMD="${3:-}"
MAX_ITERATIONS="${4:-60}"

echo "Waiting for instance refresh..."
CANARY_CHECKED="false"

for _i in $(seq 1 "$MAX_ITERATIONS"); do
  sleep 10

  # Single API call to get both status and percentage (halves API calls per iteration)
  REFRESH_DATA=$(aws autoscaling describe-instance-refreshes \
    --auto-scaling-group-name "$ASG_NAME" \
    --instance-refresh-ids "$REFRESH_ID" \
    --query "InstanceRefreshes[0].[Status,PercentageComplete]" \
    --output text)
  STATUS=$(echo "$REFRESH_DATA" | awk '{print $1}')
  PERCENTAGE=$(echo "$REFRESH_DATA" | awk '{print $2}')

  echo "Status: $STATUS, Progress: ${PERCENTAGE}%"

  case "$STATUS" in
    "Successful")
      echo "Instance refresh completed successfully"
      exit 0
      ;;
    "Failed"|"Cancelled")
      echo "Instance refresh failed: $STATUS"
      exit 1
      ;;
    "Pending"|"InProgress")
      # Run canary health check once when first instance is replaced
      # Check PERCENTAGE != "None" explicitly (AWS returns "None" before progress starts)
      if [[ "$PERCENTAGE" != "None" && "$PERCENTAGE" -gt 0 && "$CANARY_CHECKED" == "false" ]]; then
        CANARY_CHECKED="true"

        # Skip health check if no command provided
        if [[ -z "$HEALTH_CHECK_CMD" ]]; then
          echo "Canary instance replaced (health check skipped)"
          continue
        fi

        echo "Canary instance replaced, verifying health..."

        INSTANCE_ID=$(aws autoscaling describe-auto-scaling-groups \
          --auto-scaling-group-names "$ASG_NAME" \
          --query "AutoScalingGroups[0].Instances[?LifecycleState=='InService'].InstanceId | [0]" \
          --output text)

        if [[ -n "$INSTANCE_ID" && "$INSTANCE_ID" != "None" ]]; then
          echo "Verifying health on instance: $INSTANCE_ID"

          COMMAND_ID=$(aws ssm send-command \
            --instance-ids "$INSTANCE_ID" \
            --document-name "AWS-RunShellScript" \
            --parameters "commands=[\"$HEALTH_CHECK_CMD\"]" \
            --query "Command.CommandId" \
            --output text 2>/dev/null || echo "")

          if [[ -n "$COMMAND_ID" ]]; then
            sleep 10
            SSM_STATUS=$(aws ssm get-command-invocation \
              --command-id "$COMMAND_ID" \
              --instance-id "$INSTANCE_ID" \
              --query "Status" \
              --output text 2>/dev/null || echo "Unknown")

            if [[ "$SSM_STATUS" == "Success" ]]; then
              echo "Canary health check passed"
            else
              echo "Canary health check: $SSM_STATUS (continuing...)"
            fi
          fi
        fi
      fi
      ;;
  esac
done

echo "ERROR: Instance refresh timed out after $((MAX_ITERATIONS * 10)) seconds"
exit 1
