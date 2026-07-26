#!/usr/bin/env bash

set -euo pipefail

repository="${1:-}"
run_id="${2:-}"
max_attempts="${3:-}"
timeout_mode="${4:-}"
output_file="${5:-}"

if [[ "$repository" != "layervai/qurl-connector" && "$repository" != "layervai/qurl-go" ]]; then
  echo "::error::client repository is outside the UDP proof allowlist"
  exit 2
fi
if [[ ! "$run_id" =~ ^[1-9][0-9]*$ ]]; then
  echo "::error::client run ID must be a positive integer"
  exit 2
fi
if [[ ! "$max_attempts" =~ ^[1-9][0-9]*$ ]]; then
  echo "::error::poll attempt count must be a positive integer"
  exit 2
fi
if [[ "$timeout_mode" != "allow" && "$timeout_mode" != "fail" ]]; then
  echo "::error::timeout mode must be allow or fail"
  exit 2
fi
if [[ -z "$output_file" ]]; then
  echo "::error::completed-run output file is required"
  exit 2
fi
: "${GH_TOKEN:?GH_TOKEN is required}"

error_file="$(mktemp)"
trap 'rm -f "$error_file"' EXIT
error_logged=false

# A prior token window may already have captured the completed run. Reuse that
# immutable evidence instead of spending another API request after token refresh.
if [[ -s "$output_file" ]] &&
  jq -e '.status == "completed"' "$output_file" >/dev/null 2>&1; then
  exit 0
fi

for attempt in $(seq 1 "$max_attempts"); do
  # The 2> redirect below re-truncates error_file on every attempt, so no
  # explicit reset is needed here.
  if body="$(gh api "repos/${repository}/actions/runs/${run_id}" 2>"$error_file")" &&
    jq -e '.status == "completed"' <<<"$body" >/dev/null; then
    printf '%s\n' "$body" >"$output_file"
    exit 0
  fi
  if [[ "$error_logged" == "false" && -s "$error_file" ]]; then
    echo "::warning::GitHub run polling failed; the bounded retry will continue"
    sed 's/^/  /' "$error_file"
    error_logged=true
  fi
  if (( attempt < max_attempts )); then
    sleep 15
  fi
done

if [[ "$timeout_mode" == "allow" ]]; then
  exit 0
fi
echo "::error::client proof exceeded the bounded verification windows"
exit 1
