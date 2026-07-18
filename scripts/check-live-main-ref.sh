#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 1 ]] || [[ ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: $0 <expected-lowercase-40-hex-main-sha>" >&2
  exit 2
fi

expected_sha="$1"
live_ref="$(git ls-remote --exit-code origin refs/heads/main)"
line_count="$(awk 'NF { count++ } END { print count + 0 }' <<<"$live_ref")"
live_sha="$(awk 'NF { print $1 }' <<<"$live_ref")"
reported_ref="$(awk 'NF { print $2 }' <<<"$live_ref")"

if [[ "$line_count" -ne 1 ]] || \
  [[ ! "$live_sha" =~ ^[0-9a-f]{40}$ ]] || \
  [[ "$reported_ref" != "refs/heads/main" ]] || \
  [[ "$live_sha" != "$expected_sha" ]]; then
  echo "ERROR: live refs/heads/main does not exactly match reviewed SHA $expected_sha" >&2
  exit 1
fi
