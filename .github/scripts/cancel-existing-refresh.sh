#!/bin/bash
# Cancel any existing ASG instance refresh before starting a new one.
# Usage: cancel-existing-refresh.sh <asg-name>
#
# This script checks for InProgress or Pending instance refreshes and cancels
# them, waiting up to 90s for cancellation to complete. This prevents the
# "InstanceRefreshInProgress" error when starting a new refresh.

set -euo pipefail

ASG_NAME="${1:?Usage: $0 <asg-name>}"

echo "::group::Cancel existing instance refresh on $ASG_NAME"

EXISTING_REFRESH=$(aws autoscaling describe-instance-refreshes \
  --auto-scaling-group-name "$ASG_NAME" \
  --query "InstanceRefreshes[?Status=='InProgress' || Status=='Pending'].InstanceRefreshId | [0]" \
  --output text)

if [[ -z "$EXISTING_REFRESH" || "$EXISTING_REFRESH" == "None" ]]; then
  echo "No existing instance refresh found"
  echo "::endgroup::"
  exit 0
fi

echo "Found existing instance refresh: $EXISTING_REFRESH - cancelling..."
# Use || true to handle race condition where refresh completes between check and cancel
aws autoscaling cancel-instance-refresh --auto-scaling-group-name "$ASG_NAME" || true

# Wait for cancellation to complete (max 90s)
CANCEL_STATUS=""
for _ in {1..18}; do
  sleep 5
  CANCEL_STATUS=$(aws autoscaling describe-instance-refreshes \
    --auto-scaling-group-name "$ASG_NAME" \
    --instance-refresh-ids "$EXISTING_REFRESH" \
    --query "InstanceRefreshes[0].Status" \
    --output text)
  echo "Cancellation status: $CANCEL_STATUS"
  if [[ "$CANCEL_STATUS" == "Cancelled" || "$CANCEL_STATUS" == "Failed" ]]; then
    break
  fi
done

# Verify cancellation completed
if [[ "$CANCEL_STATUS" != "Cancelled" && "$CANCEL_STATUS" != "Failed" ]]; then
  echo "ERROR: Instance refresh cancellation timed out for $ASG_NAME (status: $CANCEL_STATUS)"
  echo "::endgroup::"
  exit 1
fi

echo "Instance refresh cancelled successfully"
echo "::endgroup::"
