#!/bin/bash
# Dispatch a blue-green-deploy workflow and poll until completion.
#
# Mirrors dispatch-and-poll-canary.sh, but for the blue-green-deploy.yml
# workflow. Centralises the dispatch + find-triggered-run + poll logic so
# build-and-push.yml's sandbox deploy path uses this helper instead of inline
# copies that drift over time.
#
# Usage: dispatch-and-poll-blue-green.sh <environment> <component> <image-tag>
#
# Required Environment Variables:
#   GH_TOKEN or GITHUB_TOKEN: GitHub token for workflow dispatch
#   GITHUB_REPOSITORY:        Owner/repo (e.g., layervai/nhp)
#   GITHUB_OUTPUT:            GitHub Actions output file (optional; ignored if unset)
#
# Optional Environment Variables:
#   POLL_TIMEOUT:             Total seconds to poll for completion (default 2400 = 40 min)
#   POLL_INTERVAL:            Seconds between status polls (default 30)
#   FIND_RETRIES:             How many 5s attempts to find the dispatched run
#                             (default 24 → 120s window). `gh run list` has an
#                             empirically-observed ~30s eventual-consistency
#                             delay before freshly-dispatched runs appear
#                             (measured 2026-04-08: dispatch returns at t=2s,
#                             run shows up in list at t=30s). Any retry window
#                             under ~45s races the GitHub API and fails in
#                             practice. 120s is 4x the observed worst case.
#   CELL_ID:                  Cell identifier to pass to blue-green-deploy.yml
#                             for DeploymentWindow markers and AC assignment
#                             cleanup (default: cell0).
#   BLUE_GREEN_ACTION:         deploy (default) or prepare-only.
#   PROTOCOL_PROFILE:          Declared image profile (default: legacy-aop-v1).
#
# Outputs (via GITHUB_OUTPUT, when set):
#   run_id:   Numeric run ID of the dispatched workflow
#   run_url:  Web URL of the dispatched workflow run
#
# Exit codes:
#   0 - Blue/green deploy succeeded
#   1 - Blue/green deploy failed, timed out, or could not be found

set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <environment> <component> <image-tag>" >&2
  echo "  environment:  sandbox | prod" >&2
  echo "  component:    server | ac | both" >&2
  echo "  image-tag:    Docker image tag (commit SHA)" >&2
  exit 1
fi

ENVIRONMENT="$1"
COMPONENT="$2"
IMAGE_TAG="$3"
CELL_ID="${CELL_ID:-cell0}"
BLUE_GREEN_ACTION="${BLUE_GREEN_ACTION:-deploy}"
PROTOCOL_PROFILE="${PROTOCOL_PROFILE:-legacy-aop-v1}"

case "$BLUE_GREEN_ACTION" in
  deploy|prepare-only) ;;
  *) echo "::error::BLUE_GREEN_ACTION must be deploy or prepare-only" >&2; exit 2 ;;
esac

POLL_INTERVAL="${POLL_INTERVAL:-30}"
POLL_TIMEOUT="${POLL_TIMEOUT:-2400}"  # 40 min default
FIND_RETRIES="${FIND_RETRIES:-24}"

if [[ -z "${GITHUB_REPOSITORY:-}" ]]; then
  echo "::error::GITHUB_REPOSITORY must be set" >&2
  exit 1
fi

echo "::notice::Dispatching blue/green deploy"
echo "  environment: $ENVIRONMENT"
echo "  component:   $COMPONENT"
echo "  cell_id:     $CELL_ID"
echo "  image_tag:   $IMAGE_TAG"
echo "  action:      $BLUE_GREEN_ACTION"
echo "  profile:     $PROTOCOL_PROFILE"
echo "  timeout:     ${POLL_TIMEOUT}s"

# --- Dispatch ---
# Generate a unique correlation id for this dispatch and pass it to
# blue-green-deploy.yml as an input. The dispatched workflow encodes
# the id into its run-name via `[corr:<id>]`, which find-dispatched-run.sh
# then matches on exactly. This eliminates the timestamp/status race
# that the previous createdAt + status filter had — a concurrent dispatch,
# a run held by the concurrency group (status=waiting), and a run that
# fast-fails before we get to poll it are all handled the same way,
# because the correlation id is the single ground truth.
#
# Format: ${GITHUB_RUN_ID:-manual}-${GITHUB_RUN_ATTEMPT:-1}-$(epoch)-$$
#   - GITHUB_RUN_ID makes the id traceable to the parent CI run
#   - GITHUB_RUN_ATTEMPT covers re-runs of the same parent
#   - epoch + PID cover manual invocations without CI vars
# The `-$$` PID component is harmless noise in CI but lets a human
# running this script twice in quick succession locally get two
# distinct ids.
CORRELATION_ID="${GITHUB_RUN_ID:-manual}-${GITHUB_RUN_ATTEMPT:-1}-$(date +%s)-$$"
echo "correlation_id: $CORRELATION_ID"

gh workflow run blue-green-deploy.yml \
  --ref main \
  -f environment="$ENVIRONMENT" \
  -f component="$COMPONENT" \
  -f action="$BLUE_GREEN_ACTION" \
  -f image_tag="$IMAGE_TAG" \
  -f protocol_profile="$PROTOCOL_PROFILE" \
  -f cell_id="$CELL_ID" \
  -f correlation_id="$CORRELATION_ID"

# --- Find triggered run ---
echo "Waiting for blue-green-deploy run to appear..."
if ! RUN_ID=$(./.github/scripts/find-dispatched-run.sh \
    blue-green-deploy.yml "$CORRELATION_ID" "$FIND_RETRIES" 5); then
  echo "::error::Could not find blue-green-deploy run for correlation_id=$CORRELATION_ID" >&2
  exit 1
fi
echo "Found run: $RUN_ID"

# Sanity check: RUN_ID must be numeric. The jq filter above is supposed to
# return a databaseId (integer), but if the GitHub API ever returns
# something unexpected we don't want to silently use it as a path argument
# to `gh run view`.
if ! [[ "$RUN_ID" =~ ^[0-9]+$ ]]; then
  echo "::error::Got non-numeric run id from gh run list: '$RUN_ID'" >&2
  exit 1
fi

RUN_URL="https://github.com/$GITHUB_REPOSITORY/actions/runs/$RUN_ID"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "run_id=$RUN_ID"
    echo "run_url=$RUN_URL"
  } >> "$GITHUB_OUTPUT"
fi
echo "::notice::Blue/green deploy run: $RUN_URL"

# --- Poll until completion ---
echo "Polling blue/green deploy (run: $RUN_ID, timeout: ${POLL_TIMEOUT}s)..."
ELAPSED=0
LAST_STATUS=""
LAST_ACTIVE_JOBS=""

while [[ $ELAPSED -lt $POLL_TIMEOUT ]]; do
  STATUS=$(gh run view "$RUN_ID" --json status --jq '.status' 2>/dev/null || echo "unknown")

  if [[ "$STATUS" == "completed" ]]; then
    CONCLUSION=$(gh run view "$RUN_ID" --json conclusion --jq '.conclusion' 2>/dev/null || echo "unknown")
    if [[ "$CONCLUSION" == "success" ]]; then
      echo "::notice::Blue/green deploy completed successfully"
      exit 0
    else
      echo "::error::Blue/green deploy failed with conclusion: $CONCLUSION" >&2
      echo "::error::Run URL: $RUN_URL" >&2
      # Surface the failed job names so the operator can jump straight to
      # the failing step in the dispatched workflow without having to open
      # the run URL.
      FAILED_JOBS=$(gh run view "$RUN_ID" --json jobs \
        --jq '[.jobs[] | select(.conclusion == "failure" or .conclusion == "cancelled" or .conclusion == "timed_out") | .name] | join(", ")' \
        2>/dev/null || echo "")
      if [[ -n "$FAILED_JOBS" ]]; then
        echo "::error::Failed jobs: $FAILED_JOBS" >&2
      fi
      exit 1
    fi
  fi

  # Only echo when status changes, to keep CI logs readable.
  if [[ "$STATUS" != "$LAST_STATUS" ]]; then
    REMAINING=$(( (POLL_TIMEOUT - ELAPSED) / 60 ))
    echo "  Status: $STATUS (${REMAINING}m remaining)"
    LAST_STATUS="$STATUS"
  fi

  # Job-level visibility: print which sub-jobs are currently in progress
  # whenever that set changes. Mirrors dispatch-and-poll-canary.sh so
  # operators tailing the log can see "we're in deploy-to-standby" rather
  # than just "in_progress".
  ACTIVE_JOBS=$(gh run view "$RUN_ID" --json jobs \
    --jq '[.jobs[] | select(.status == "in_progress") | .name] | sort | join(", ")' \
    2>/dev/null || echo "")
  if [[ -n "$ACTIVE_JOBS" && "$ACTIVE_JOBS" != "$LAST_ACTIVE_JOBS" ]]; then
    echo "    Active: $ACTIVE_JOBS"
    LAST_ACTIVE_JOBS="$ACTIVE_JOBS"
  fi

  sleep "$POLL_INTERVAL"
  ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

echo "::error::Blue/green deploy timed out after ${POLL_TIMEOUT}s" >&2
echo "::error::Run URL: $RUN_URL" >&2
exit 1
