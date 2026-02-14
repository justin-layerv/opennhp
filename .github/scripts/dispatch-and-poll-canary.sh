#!/bin/bash
# Dispatch a canary-deploy workflow and poll until completion.
#
# Handles the full lifecycle: dispatch → find triggered run → poll with
# progress visibility (active sub-jobs) → report result.
#
# Usage: dispatch-and-poll-canary.sh <component> <image-tag> <environment> <cell-id>
#
# Required Environment Variables:
#   GH_TOKEN or GITHUB_TOKEN: GitHub token for workflow dispatch
#   GITHUB_REPOSITORY:        Owner/repo (e.g., layervai/nhp)
#   GITHUB_OUTPUT:            GitHub Actions output file
#
# Outputs (via GITHUB_OUTPUT):
#   run_url:  URL of the dispatched canary-deploy workflow run
#
# Exit codes:
#   0 - Canary deploy succeeded
#   1 - Canary deploy failed, timed out, or could not be found

set -euo pipefail

if [[ $# -lt 4 ]]; then
  echo "Usage: $0 <component> <image-tag> <environment> <cell-id>"
  echo "  component:    server or ac"
  echo "  image-tag:    Docker image tag (commit SHA)"
  echo "  environment:  Target environment (prod)"
  echo "  cell-id:      Cell identifier (e.g., cell0)"
  exit 1
fi

COMPONENT="$1"
IMAGE_TAG="$2"
ENVIRONMENT="$3"
CELL_ID="$4"

POLL_INTERVAL=30
POLL_TIMEOUT=2400  # 40 minutes (10-min buffer before 50-min job timeout)
FIND_RETRIES=6

echo "::notice::Deploying $COMPONENT via canary (Step Functions)"

# --- Dispatch ---
DISPATCH_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

gh workflow run canary-deploy.yml \
  --ref main \
  -f component="$COMPONENT" \
  -f image_tag="$IMAGE_TAG" \
  -f environment="$ENVIRONMENT" \
  -f cell_id="$CELL_ID"

# --- Find triggered run ---
echo "Waiting for canary-deploy run to appear..."
RUN_ID=""
for i in $(seq 1 $FIND_RETRIES); do
  sleep 10
  RUN_ID=$(gh run list \
    --workflow canary-deploy.yml \
    --json databaseId,createdAt,status \
    --jq "[.[] | select(.createdAt >= \"$DISPATCH_TIME\") | select(.status == \"in_progress\" or .status == \"queued\" or .status == \"completed\")] | .[0].databaseId // empty" \
    2>/dev/null || echo "")
  if [[ -n "$RUN_ID" ]]; then
    echo "Found run: $RUN_ID"
    break
  fi
  echo "  Waiting for workflow run (attempt $i/$FIND_RETRIES)..."
done

if [[ -z "$RUN_ID" ]]; then
  echo "::error::Could not find canary-deploy run for $COMPONENT after ${FIND_RETRIES} attempts"
  exit 1
fi

RUN_URL="https://github.com/$GITHUB_REPOSITORY/actions/runs/$RUN_ID"
echo "run_url=$RUN_URL" >> "$GITHUB_OUTPUT"
echo "::notice::Canary deploy run: $RUN_URL"

# --- Poll until completion ---
echo "Polling $COMPONENT canary deploy (run: $RUN_ID, timeout: ${POLL_TIMEOUT}s)..."
ELAPSED=0
LAST_JOBS=""

while [[ $ELAPSED -lt $POLL_TIMEOUT ]]; do
  STATUS=$(gh run view "$RUN_ID" --json status,conclusion --jq '.status' 2>/dev/null || echo "unknown")

  if [[ "$STATUS" == "completed" ]]; then
    CONCLUSION=$(gh run view "$RUN_ID" --json conclusion --jq '.conclusion' 2>/dev/null || echo "unknown")
    if [[ "$CONCLUSION" == "success" ]]; then
      echo "::notice::${COMPONENT^} canary deploy completed successfully."
      exit 0
    else
      echo "::error::${COMPONENT^} canary deploy failed with conclusion: $CONCLUSION"
      echo "::error::Run URL: $RUN_URL"
      exit 1
    fi
  fi

  # Show which canary sub-jobs are running for progress visibility
  CURRENT_JOBS=$(gh run view "$RUN_ID" --json jobs --jq '[.jobs[] | select(.status != "completed") | .name] | join(", ")' 2>/dev/null || echo "")
  if [[ -n "$CURRENT_JOBS" && "$CURRENT_JOBS" != "$LAST_JOBS" ]]; then
    echo "  Active: $CURRENT_JOBS (${ELAPSED}s elapsed)"
    LAST_JOBS="$CURRENT_JOBS"
  else
    echo "  Status: $STATUS (${ELAPSED}s elapsed)"
  fi

  sleep "$POLL_INTERVAL"
  ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

echo "::error::Timed out waiting for $COMPONENT canary deploy (${POLL_TIMEOUT}s)"
exit 1
