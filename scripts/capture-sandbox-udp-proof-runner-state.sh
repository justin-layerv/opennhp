#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <output-directory>" >&2
  exit 2
fi

output_directory=$1
bucket=layerv-terraform-state-767397897469
key=nhp/sandbox-udp-proof-runner/terraform.tfstate
expected_account=767397897469
expected_kms_key_arn=arn:aws:kms:us-east-2:767397897469:key/289dbe35-ab5a-4752-8564-4c96c607c9f4

mkdir -p "$output_directory"
chmod 700 "$output_directory"

account_id=$(aws sts get-caller-identity --query Account --output text)
if [[ "$account_id" != "$expected_account" ]]; then
  echo "unexpected AWS account: $account_id" >&2
  exit 1
fi

set +e
lock_error=$(aws s3api head-object \
  --bucket "$bucket" \
  --key "${key}.tflock" \
  --output json 2>&1)
lock_status=$?
set -e
if [[ "$lock_status" -eq 0 ]]; then
  echo "Terraform state is locked; refusing to capture a racing snapshot" >&2
  exit 1
fi
if [[ "$lock_error" != *"404"* && "$lock_error" != *"NoSuchKey"* && "$lock_error" != *"Not Found"* ]]; then
  echo "could not prove the Terraform lock object is absent: $lock_error" >&2
  exit 1
fi

aws s3api head-object \
  --bucket "$bucket" \
  --key "$key" \
  --output json >"$output_directory/head.json"

version_id=$(jq -er '.VersionId | select(type == "string" and length > 0 and . != "null")' \
  "$output_directory/head.json")
aws s3api get-object \
  --bucket "$bucket" \
  --key "$key" \
  --version-id "$version_id" \
  "$output_directory/state.tfstate" >/dev/null

jq -e '
  .ServerSideEncryption == "aws:kms" and
  (.ContentLength | type == "number" and . > 0) and
  (.ETag | type == "string" and length > 0)
' "$output_directory/head.json" >/dev/null
if [[ $(jq -er '.SSEKMSKeyId' "$output_directory/head.json") != "$expected_kms_key_arn" ]]; then
  echo "Terraform state uses an unexpected KMS key" >&2
  exit 1
fi

actual_size=$(wc -c <"$output_directory/state.tfstate" | tr -d ' ')
expected_size=$(jq -er '.ContentLength' "$output_directory/head.json")
if [[ "$actual_size" != "$expected_size" ]]; then
  echo "downloaded state length does not match S3 metadata" >&2
  exit 1
fi

state_sha256=$(sha256sum "$output_directory/state.tfstate" | awk '{print $1}')
jq -e '
  .version == 4 and
  (.serial | type == "number" and . >= 0 and floor == .) and
  (.lineage | type == "string" and test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))
' "$output_directory/state.tfstate" >/dev/null

jq -n \
  --arg account_id "$account_id" \
  --arg bucket "$bucket" \
  --arg key "$key" \
  --arg version_id "$version_id" \
  --arg etag "$(jq -er '.ETag' "$output_directory/head.json")" \
  --arg kms_key_arn "$(jq -er '.SSEKMSKeyId' "$output_directory/head.json")" \
  --arg lineage "$(jq -er '.lineage' "$output_directory/state.tfstate")" \
  --arg state_sha256 "$state_sha256" \
  --argjson content_length "$actual_size" \
  --argjson serial "$(jq -er '.serial' "$output_directory/state.tfstate")" \
  '{
    account_id: $account_id,
    bucket: $bucket,
    content_length: $content_length,
    etag: $etag,
    key: $key,
    kms_key_arn: $kms_key_arn,
    lineage: $lineage,
    serial: $serial,
    sha256: $state_sha256,
    version_id: $version_id
  }' >"$output_directory/state-summary.json"
