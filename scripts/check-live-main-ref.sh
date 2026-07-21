#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 1 ]] || [[ ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: $0 <expected-lowercase-40-hex-main-sha>" >&2
  exit 2
fi

expected_sha="$1"

if [[ -z "${GH_TOKEN:-}" ]]; then
  echo "ERROR: GH_TOKEN is required for the authenticated live-main read" >&2
  exit 2
fi

repository="${GITHUB_REPOSITORY:-}"
if [[ ! "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "ERROR: GITHUB_REPOSITORY must be an owner/repository pair" >&2
  exit 2
fi

# Keep the GitHub credential process-scoped. Unlike an authenticated git
# remote, this API read does not materialize checkout credentials in the
# repository config where a later Terraform process could inherit them.
live_ref_json="$(GH_DEBUG='' DEBUG='' GH_TRACE='' \
  gh api "repos/$repository/git/ref/heads/main")"
reported_ref="$(jq -er '.ref | select(type == "string")' <<<"$live_ref_json")"
object_type="$(jq -er '.object.type | select(type == "string")' <<<"$live_ref_json")"
live_sha="$(jq -er '.object.sha | select(type == "string")' <<<"$live_ref_json")"

if [[ "$object_type" != "commit" ]] || \
  [[ ! "$live_sha" =~ ^[0-9a-f]{40}$ ]] || \
  [[ "$reported_ref" != "refs/heads/main" ]] || \
  [[ "$live_sha" != "$expected_sha" ]]; then
  echo "ERROR: live refs/heads/main does not exactly match reviewed SHA $expected_sha" >&2
  exit 1
fi
