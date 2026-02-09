#!/bin/bash
# Ensure sandbox has the specified commit deployed via blue/green deployment.
#
# This script checks whether the target commit is already deployed to sandbox.
# If not, it ensures the image exists in ECR (triggering a build if needed),
# then deploys to sandbox using the blue-green-deploy workflow.
#
# Usage: ensure-sandbox-deployed.sh
#
# Required Environment Variables:
#   HEAD_SHA:                Full git commit SHA to deploy
#   SANDBOX_ALREADY:         "true" if sandbox already has this commit deployed
#   GH_TOKEN:                GitHub token for workflow dispatch
#   AWS_REGION:              AWS region (default: us-east-2)
#
# Outputs (via GITHUB_OUTPUT):
#   image_tag:               The image tag that is/will be deployed
#   method:                  How deployment was handled (already-deployed|blue-green|build-then-blue-green)

set -euo pipefail

AWS_REGION="${AWS_REGION:-us-east-2}"
ECR_REPO_SERVER="layerv/nhp-server"
SSM_DEPLOYED_COMMIT="/sandbox/nhp/deploy/deployed-commit"
SSM_DEPLOYED_AT="/sandbox/nhp/deploy/deployed-at"
POLL_INTERVAL=30
POLL_TIMEOUT=2700  # 45 minutes

echo "============================================"
echo "Ensure Sandbox Deployed (Blue/Green)"
echo "============================================"
echo "HEAD SHA:          $HEAD_SHA"
echo "Sandbox Already:   ${SANDBOX_ALREADY:-false}"
echo ""

# If sandbox already has this commit, skip
if [[ "${SANDBOX_ALREADY:-false}" == "true" ]]; then
  echo "Sandbox already has commit $HEAD_SHA deployed. Skipping."
  echo "image_tag=$HEAD_SHA" >> "$GITHUB_OUTPUT"
  echo "method=already-deployed" >> "$GITHUB_OUTPUT"
  exit 0
fi

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
find_triggered_run() {
  local workflow="$1"
  local dispatch_time="$2"
  local retries=6
  local run_id=""

  for i in $(seq 1 $retries); do
    sleep 10
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

# Step 1: Ensure image exists in ECR
echo "Checking ECR for image tag: $HEAD_SHA"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

IMAGE_EXISTS="false"
if aws ecr describe-images \
  --repository-name "$ECR_REPO_SERVER" \
  --image-ids imageTag="$HEAD_SHA" \
  --region "$AWS_REGION" > /dev/null 2>&1; then
  IMAGE_EXISTS="true"
  echo "Image found in ECR: $ECR_REGISTRY/$ECR_REPO_SERVER:$HEAD_SHA"
fi

BUILD_METHOD="blue-green"

if [[ "$IMAGE_EXISTS" != "true" ]]; then
  # Image not in ECR - build it first via build-and-push (build only, no deploy)
  echo ""
  echo "Image not found in ECR. Triggering build-and-push to build image..."
  BUILD_METHOD="build-then-blue-green"

  # Check for an already-running build-and-push workflow
  ACTIVE_RUN_ID=$(gh run list \
    --workflow build-and-push.yml \
    --branch main \
    --status in_progress \
    --json databaseId \
    --jq '.[0].databaseId // empty' 2>/dev/null || echo "")

  if [[ -n "$ACTIVE_RUN_ID" ]]; then
    echo "Found active build-and-push run: $ACTIVE_RUN_ID. Waiting for it to complete."
    RUN_ID="$ACTIVE_RUN_ID"
  else
    BUILD_DISPATCH_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    gh workflow run build-and-push.yml \
      --ref main \
      -f environment=sandbox \
      -f deploy=false

    RUN_ID=$(find_triggered_run "build-and-push.yml" "$BUILD_DISPATCH_TIME")
    if [[ -z "$RUN_ID" ]]; then
      echo "ERROR: Could not find build-and-push run"
      exit 1
    fi
    echo "Triggered build-and-push run: $RUN_ID"
  fi

  poll_workflow_run "$RUN_ID" "Image build (build-and-push)"
  echo ""
  echo "Image built successfully. Proceeding to blue/green deployment."
fi

# Step 2: Deploy to sandbox via blue/green
echo ""
echo "--- Deploying to Sandbox (blue/green) ---"
BG_DISPATCH_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
gh workflow run blue-green-deploy.yml \
  --ref main \
  -f environment=sandbox \
  -f component=both \
  -f action=deploy \
  -f image_tag="$HEAD_SHA"

BG_RUN_ID=$(find_triggered_run "blue-green-deploy.yml" "$BG_DISPATCH_TIME")
if [[ -z "$BG_RUN_ID" ]]; then
  echo "ERROR: Could not find blue-green-deploy run"
  exit 1
fi
echo "Triggered blue-green-deploy run: $BG_RUN_ID"
poll_workflow_run "$BG_RUN_ID" "Sandbox blue/green deploy"

# Update deployment tracking
echo ""
echo "Updating sandbox deployment tracking..."
aws ssm put-parameter \
  --name "$SSM_DEPLOYED_COMMIT" \
  --value "$HEAD_SHA" --type String --overwrite \
  --region "$AWS_REGION" || echo "::warning::Failed to update SSM $SSM_DEPLOYED_COMMIT"
aws ssm put-parameter \
  --name "$SSM_DEPLOYED_AT" \
  --value "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --type String --overwrite \
  --region "$AWS_REGION" || echo "::warning::Failed to update SSM $SSM_DEPLOYED_AT"

echo "image_tag=$HEAD_SHA" >> "$GITHUB_OUTPUT"
echo "method=$BUILD_METHOD" >> "$GITHUB_OUTPUT"
