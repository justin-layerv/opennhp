#!/usr/bin/env bash
# tail-deploy-logs.sh — Stream CloudWatch startup logs to the GitHub Actions console.
#
# Usage:
#   ./.github/scripts/tail-deploy-logs.sh <component> <environment> [cell_id]
#
# Examples:
#   ./.github/scripts/tail-deploy-logs.sh server prod cell0
#   ./.github/scripts/tail-deploy-logs.sh ac prod
#
# Runs in the foreground, streaming logs until killed (typically via background &).
# The caller is responsible for killing this process when the deploy finishes.

set -euo pipefail

COMPONENT="${1:?Usage: tail-deploy-logs.sh <server|ac> <environment> [cell_id]}"
ENVIRONMENT="${2:?Usage: tail-deploy-logs.sh <server|ac> <environment> [cell_id]}"
CELL_ID="${3:-cell0}"

# Build log group name based on component
if [[ "$COMPONENT" == "server" ]]; then
  LOG_GROUP="/layerv/nhp/${ENVIRONMENT}/${CELL_ID}/server"
elif [[ "$COMPONENT" == "ac" ]]; then
  LOG_GROUP="/layerv/nhp/${ENVIRONMENT}/ac"
else
  echo "Unknown component: $COMPONENT (expected 'server' or 'ac')"
  exit 1
fi

# Filter for startup, shutdown, error, and connection events.
# This keeps the output focused — no noisy knock/request traffic.
FILTER_PATTERN='?"Starting" ?"started" ?"initialized" ?"Listening" ?"listening" ?"registered" ?"ERROR" ?"FATAL" ?"panic" ?"Shutdown" ?"draining" ?"peer" ?"connected" ?"health"'

echo "::group::📡 Live logs: ${LOG_GROUP}"
trap 'echo "::endgroup::"' EXIT
echo "Tailing ${COMPONENT} logs (filtered for startup/error events)..."
echo ""

# aws logs tail --follow streams new log events as they arrive.
# --since 5m catches events from shortly before this script started.
# Errors are suppressed (log group may not exist yet on first deploy).
aws logs tail "$LOG_GROUP" \
  --follow \
  --since 5m \
  --format short \
  --filter-pattern "$FILTER_PATTERN" \
  --region "${AWS_REGION:-us-east-2}" \
  2>/dev/null || echo "(Log tailing ended — group may not exist yet)"
