#!/bin/bash
# Ensure sandbox has the specified commit deployed through build-and-push.yml.
#
# This script checks whether the target commit is already deployed to sandbox.
# If not, it dispatches build-and-push.yml in sandbox deploy mode. That workflow
# owns image build decisions, blue/green rollout, relay/qurl deploy checks, live
# app-image drift detection, and deployed-commit stamping. Do not bypass it with
# a direct blue-green-deploy.yml dispatch here.
#
# Usage: ensure-sandbox-deployed.sh
#
# Required Environment Variables:
#   HEAD_SHA:                Full git commit SHA to deploy
#   SANDBOX_ALREADY:         "true" if sandbox already has this commit deployed
#   GH_TOKEN:                GitHub token for workflow dispatch
#
# Outputs (via GITHUB_OUTPUT):
#   image_tag:               The image tag that is/will be deployed
#   method:                  How deployment was handled (already-deployed|build-and-push-deploy)

set -euo pipefail

POLL_INTERVAL="${POLL_INTERVAL:-30}"
POLL_TIMEOUT="${POLL_TIMEOUT:-9000}"  # 150 minutes; build-and-push may run tests, infra, and blue/green.
FIND_RETRIES="${FIND_RETRIES:-24}"
FIND_DELAY_SECONDS="${FIND_DELAY_SECONDS:-5}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================"
echo "Ensure Sandbox Deployed (build-and-push)"
echo "============================================"
echo "HEAD SHA:          $HEAD_SHA"
echo "Sandbox Already:   ${SANDBOX_ALREADY:-false}"
echo ""

# If sandbox already has this commit, skip
if [[ "${SANDBOX_ALREADY:-false}" == "true" ]]; then
  # This trusts the deployed-commit stamping invariant: build-and-push.yml
  # writes the value only after live active image tags prove the target app tree.
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

echo ""
echo "--- Deploying to Sandbox via build-and-push.yml ---"
echo "build-and-push owns the app-image drift gate and deployed-commit update."
CORRELATION_ID="${GITHUB_RUN_ID:-manual}-${GITHUB_RUN_ATTEMPT:-1}-$(date +%s)-$$"
echo "correlation_id: $CORRELATION_ID"
gh workflow run build-and-push.yml \
  --ref main \
  -f environment=sandbox \
  -f deploy=true \
  -f correlation_id="$CORRELATION_ID"

if ! RUN_ID=$("$SCRIPT_DIR/find-dispatched-run.sh" \
    build-and-push.yml "$CORRELATION_ID" "$FIND_RETRIES" "$FIND_DELAY_SECONDS"); then
  echo "ERROR: Could not find build-and-push run for correlation_id=$CORRELATION_ID"
  exit 1
fi
echo "Triggered build-and-push run: $RUN_ID"
poll_workflow_run "$RUN_ID" "Sandbox deploy (build-and-push)"

echo "image_tag=$HEAD_SHA" >> "$GITHUB_OUTPUT"
echo "method=build-and-push-deploy" >> "$GITHUB_OUTPUT"
