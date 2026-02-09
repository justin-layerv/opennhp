#!/bin/bash
# Promote a sandbox-validated deployment to production via canary deployment.
#
# Deploys server and AC sequentially using the canary-deploy workflow,
# which uses AWS Step Functions for automated rollout with health checks
# and automatic rollback.
#
# Usage: promote-to-prod.sh
#
# Required Environment Variables:
#   IMAGE_TAG:       Docker image tag to deploy (commit SHA)
#   GH_TOKEN:        GitHub token for workflow dispatch
#   AWS_REGION:      AWS region (default: us-east-2)
#
# Outputs (via GITHUB_OUTPUT):
#   method:          How production was deployed (canary)

set -euo pipefail

AWS_REGION="${AWS_REGION:-us-east-2}"
POLL_INTERVAL=30
POLL_TIMEOUT=2700  # 45 minutes
SSM_DEPLOYED_COMMIT="/prod/nhp/deploy/deployed-commit"
SSM_DEPLOYED_AT="/prod/nhp/deploy/deployed-at"

echo "============================================"
echo "Promote to Production (Canary)"
echo "============================================"
echo "Image Tag:   $IMAGE_TAG"
echo ""

# Poll a workflow run until completion
poll_workflow_run() {
  local run_id="$1"
  local label="$2"
  local elapsed=0

  echo "Polling $label (run: $run_id, timeout: ${POLL_TIMEOUT}s)..."
  while [[ $elapsed -lt $POLL_TIMEOUT ]]; do
    STATUS=$(gh run view "$run_id" --json status,conclusion --jq '.status' 2>/dev/null || echo "unknown")

    if [[ "$STATUS" == "completed" ]]; then
      CONCLUSION=$(gh run view "$run_id" --json conclusion --jq '.conclusion' 2>/dev/null || echo "unknown")
      if [[ "$CONCLUSION" == "success" ]]; then
        echo "$label completed successfully."
        return 0
      else
        echo "ERROR: $label completed with conclusion: $CONCLUSION"
        echo "Run URL: https://github.com/$GITHUB_REPOSITORY/actions/runs/$run_id"
        return 1
      fi
    fi

    echo "  Status: $STATUS (${elapsed}s elapsed)"
    sleep "$POLL_INTERVAL"
    elapsed=$((elapsed + POLL_INTERVAL))
  done

  echo "ERROR: Timed out waiting for $label (${POLL_TIMEOUT}s)"
  return 1
}

# Find a workflow run created after $dispatch_time.
# Uses createdAt to disambiguate sequential dispatches of the same workflow.
find_triggered_run() {
  local workflow="$1"
  local dispatch_time="$2"  # ISO 8601 timestamp taken before gh workflow run
  local retries=6
  local run_id=""

  for i in $(seq 1 $retries); do
    sleep 10
    # List recent runs and pick the first one created after dispatch_time
    run_id=$(gh run list \
      --workflow "$workflow" \
      --json databaseId,createdAt,status \
      --jq "[.[] | select(.createdAt >= \"$dispatch_time\") | select(.status == \"in_progress\" or .status == \"queued\" or .status == \"completed\")] | .[0].databaseId // empty" \
      2>/dev/null || echo "")

    if [[ -n "$run_id" ]]; then
      echo "$run_id"
      return 0
    fi
    echo "  Waiting for workflow run to appear (attempt $i/$retries)..." >&2
  done

  echo ""
  return 1
}

# Deploy server via canary
echo "--- Deploying NHP Server (canary) ---"
SERVER_DISPATCH_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
gh workflow run canary-deploy.yml \
  --ref main \
  -f component=server \
  -f image_tag="$IMAGE_TAG" \
  -f environment=prod

SERVER_RUN_ID=$(find_triggered_run "canary-deploy.yml" "$SERVER_DISPATCH_TIME")
if [[ -z "$SERVER_RUN_ID" ]]; then
  echo "ERROR: Could not find canary-deploy run for server"
  exit 1
fi
poll_workflow_run "$SERVER_RUN_ID" "Server canary deploy"

# Deploy AC via canary
echo ""
echo "--- Deploying AC (canary) ---"
AC_DISPATCH_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
gh workflow run canary-deploy.yml \
  --ref main \
  -f component=ac \
  -f image_tag="$IMAGE_TAG" \
  -f environment=prod

AC_RUN_ID=$(find_triggered_run "canary-deploy.yml" "$AC_DISPATCH_TIME")
if [[ -z "$AC_RUN_ID" ]]; then
  echo "ERROR: Could not find canary-deploy run for AC"
  exit 1
fi
poll_workflow_run "$AC_RUN_ID" "AC canary deploy"

echo "method=canary" >> "$GITHUB_OUTPUT"

# Update deployment tracking
echo ""
echo "Updating production deployment tracking..."
aws ssm put-parameter \
  --name "$SSM_DEPLOYED_COMMIT" \
  --value "$IMAGE_TAG" --type String --overwrite \
  --region "$AWS_REGION" || echo "::warning::Failed to update SSM $SSM_DEPLOYED_COMMIT"
aws ssm put-parameter \
  --name "$SSM_DEPLOYED_AT" \
  --value "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --type String --overwrite \
  --region "$AWS_REGION" || echo "::warning::Failed to update SSM $SSM_DEPLOYED_AT"

echo ""
echo "============================================"
echo "Production Promotion Complete"
echo "============================================"
echo "Image Tag: $IMAGE_TAG"
