#!/usr/bin/env bash
# Verify the exact attended build-only authority used by schema-3 recovery.
# This is intentionally stricter than overall workflow success: force-build
# must have executed, the full endpoint race suite and server+AC image and
# attestation steps must have completed, and every live deployment job must be
# skipped.

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <run-id> <run-attempt> <source-sha>" >&2
  exit 2
fi
RUN_ID=$1
RUN_ATTEMPT=$2
SOURCE_SHA=$3
REPOSITORY=${GITHUB_REPOSITORY:-layervai/nhp}
: "${GH_TOKEN:?GH_TOKEN is required}"

[[ "$REPOSITORY" == layervai/nhp && "$RUN_ID" =~ ^[1-9][0-9]*$ &&
   "$RUN_ATTEMPT" =~ ^[1-9][0-9]*$ && "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo "build-only run authority is malformed" >&2; exit 2;
}

run=$(gh api "repos/${REPOSITORY}/actions/runs/${RUN_ID}/attempts/${RUN_ATTEMPT}")
jq -e --arg repository "$REPOSITORY" --arg run "$RUN_ID" --arg sha "$SOURCE_SHA" \
  --argjson attempt "$RUN_ATTEMPT" '
  (.id | tostring) == $run and .repository.full_name == $repository and
  .head_repository.full_name == $repository and .head_sha == $sha and
  .head_branch == "main" and .event == "workflow_dispatch" and
  .run_attempt == $attempt and .status == "completed" and .conclusion == "success" and
  (.path == ".github/workflows/build-and-push.yml" or
   .path == ($repository + "/.github/workflows/build-and-push.yml@refs/heads/main"))
' >/dev/null <<<"$run" || {
  echo "repair build is not the exact successful attended main workflow attempt" >&2
  exit 1
}

jobs=$(gh api --paginate \
  "repos/${REPOSITORY}/actions/runs/${RUN_ID}/attempts/${RUN_ATTEMPT}/jobs?per_page=100" --slurp)
jq -e '
  [.[].jobs[]] as $jobs |
  def exact_job($name; $conclusion):
    [$jobs[] | select(.name == $name and .conclusion == $conclusion)] | length == 1;
  def exact_step($job; $name; $conclusion):
    [$jobs[] | select(.name == $job) | .steps[]? |
      select(.name == $name and .conclusion == $conclusion)] | length == 1;
  exact_job("Detect Changes"; "success") and
  exact_step("Detect Changes"; "Force build override"; "success") and
  # At the reviewed 422b1d9 workflow, the sandbox environment guard runs for
  # every deploy=true dispatch and is skipped only for deploy=false.  The
  # skipped guard is direct, non-caller-supplied no-deploy evidence for this
  # historical run.
  exact_job("Sandbox Environment Guard"; "skipped") and
  exact_job("Sandbox App Image Drift"; "skipped") and
  exact_job("Test"; "success") and
  exact_step("Test"; "Skip notice"; "skipped") and
  exact_step("Test"; "Run tests (privileged container for iptables)"; "success") and
  (["Build server", "Build ac"] | all(. as $job |
    exact_job($job; "success") and
    exact_step($job; "Skip notice"; "skipped") and
    exact_step($job; "Build image"; "success") and
    exact_step($job; "Generate SBOM"; "success") and
    exact_step($job; "Push to ECR"; "success") and
    exact_step($job; "Capture pushed image digest"; "success") and
    exact_step($job; "Attest build provenance (SLSA)"; "success") and
    exact_step($job; "Attest SBOM"; "success") and
    exact_step($job; "Attestation summary"; "success"))) and
  (["Deploy Sandbox - Infrastructure",
    "Deploy Sandbox - QURL Service",
    "Deploy Sandbox - Relay",
    "Deploy Sandbox - Blue/Green",
    "Deploy Sandbox cell1 - Infrastructure",
    "Deploy Sandbox cell1 - Blue/Green",
    "Deploy Sandbox - Control",
    "Deploy Sandbox - Validate",
    "NHP Smoke (sandbox)"] | all(. as $job | exact_job($job; "skipped")))
' >/dev/null <<<"$jobs" || {
  echo "repair build did not prove exact force-build/no-deploy server+AC attestation authority" >&2
  exit 1
}

printf 'v1|%s|%s|%s\n' "$RUN_ID" "$RUN_ATTEMPT" "$SOURCE_SHA"
