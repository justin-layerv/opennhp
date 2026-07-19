#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <empty-evidence-directory>" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
evidence_dir="$1"
state_bucket="layerv-terraform-state-767397897469"
state_key="nhp/sandbox/control/terraform.tfstate"
lock_key="${state_key}.tflock"

if [[ -e "$evidence_dir" ]]; then
  echo "ERROR: evidence directory already exists: $evidence_dir" >&2
  exit 2
fi
mkdir -m 700 "$evidence_dir"

aws s3api head-object \
  --bucket "$state_bucket" \
  --key "$state_key" \
  --output json >"$evidence_dir/state-head.json"

version_id="$(jq -er '.VersionId | select(type == "string" and length > 0 and . != "null")' \
  "$evidence_dir/state-head.json")"
aws s3api get-object \
  --bucket "$state_bucket" \
  --key "$state_key" \
  --version-id "$version_id" \
  "$evidence_dir/state.tfstate" >/dev/null

set +e
aws s3api head-object --bucket "$state_bucket" --key "$lock_key" \
  >"$evidence_dir/lock-head.json" 2>"$evidence_dir/lock-head.err"
lock_status=$?
set -e
if [[ "$lock_status" -eq 0 ]]; then
  echo "ERROR: Control state lock exists; refusing partial recovery." >&2
  exit 1
fi
if ! grep -Eq '\(404\)|Not Found|NoSuchKey' "$evidence_dir/lock-head.err"; then
  sed 's/^/AWS: /' "$evidence_dir/lock-head.err" >&2
  echo "ERROR: Could not prove Control state lock absence." >&2
  exit 1
fi
rm -f "$evidence_dir/lock-head.json" "$evidence_dir/lock-head.err"

python3 "$repo_root/.github/scripts/check-control-sandbox-first-apply.py" \
  partial-state "$evidence_dir/state.tfstate" "$evidence_dir/state-head.json" \
  | tee "$evidence_dir/partial-state-summary.json"
