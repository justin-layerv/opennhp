#!/usr/bin/env bash

# Capture a race-checked identity for the current versioned sandbox Control
# state. The raw state remains runner-local; callers publish only the summary.
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <new-evidence-directory>" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
evidence_dir="$1"
state_bucket="layerv-terraform-state-767397897469"
state_key="nhp/sandbox/control/terraform.tfstate"
lock_key="${state_key}.tflock"
identity_filter='{VersionId,ETag,ContentLength,ServerSideEncryption,SSEKMSKeyId}'

if [[ -e "$evidence_dir" ]]; then
  echo "ERROR: evidence directory already exists: $evidence_dir" >&2
  exit 2
fi
mkdir -m 700 "$evidence_dir"

assert_lock_absent() {
  local stdout_file="$evidence_dir/lock-head.json"
  local stderr_file="$evidence_dir/lock-head.err"
  local status
  set +e
  aws s3api head-object --bucket "$state_bucket" --key "$lock_key" \
    >"$stdout_file" 2>"$stderr_file"
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    echo "ERROR: sandbox Control state is locked; refusing to capture it." >&2
    exit 1
  fi
  if ! grep -Eq '\(404\)|Not Found|NoSuchKey' "$stderr_file"; then
    sed 's/^/AWS: /' "$stderr_file" >&2
    echo "ERROR: could not prove sandbox Control lock absence." >&2
    exit 1
  fi
  rm -f "$stdout_file" "$stderr_file"
}

assert_lock_absent
aws s3api head-object --bucket "$state_bucket" --key "$state_key" \
  --output json >"$evidence_dir/state-head-before.json"
version_id="$(jq -er '.VersionId | select(type == "string" and length > 0 and . != "null")' \
  "$evidence_dir/state-head-before.json")"
aws s3api get-object --bucket "$state_bucket" --key "$state_key" \
  --version-id "$version_id" "$evidence_dir/state.tfstate" >/dev/null
aws s3api head-object --bucket "$state_bucket" --key "$state_key" \
  --output json >"$evidence_dir/state-head-after.json"
assert_lock_absent

jq -S "$identity_filter" \
  "$evidence_dir/state-head-before.json" >"$evidence_dir/head-before.identity.json"
jq -S "$identity_filter" \
  "$evidence_dir/state-head-after.json" >"$evidence_dir/head-after.identity.json"
if ! cmp -s "$evidence_dir/head-before.identity.json" "$evidence_dir/head-after.identity.json"; then
  echo "ERROR: sandbox Control state changed during capture; retry from a fresh plan." >&2
  exit 1
fi
mv "$evidence_dir/state-head-after.json" "$evidence_dir/state-head.json"

python3 "$repo_root/.github/scripts/check-control-sandbox-update.py" state \
  "$evidence_dir/state.tfstate" "$evidence_dir/state-head.json" \
  | tee "$evidence_dir/state-summary.json"
