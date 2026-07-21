#!/usr/bin/env bash

# Read-only readiness proof for the sandbox Control OTP pepper. This script must
# never repair missing state: verification that mutates would mask drift.
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "usage: $0 <secret-arn> <expected-kms-key-arn> <region> <evidence-directory>" >&2
  exit 2
fi

secret_arn="$1"
expected_kms_key_arn="$2"
region="$3"
evidence_dir="$4"
# The permanent verifier creates this directory before invoking its component
# verifiers. Keep this idempotent while still tightening an existing directory
# from the runner's default mode.
install -d -m 700 "$evidence_dir"

aws secretsmanager describe-secret \
  --region "$region" \
  --secret-id "$secret_arn" \
  --output json >"$evidence_dir/secret-metadata.json"
if [[ "$(jq -er '.KmsKeyId' "$evidence_dir/secret-metadata.json")" != \
  "$expected_kms_key_arn" ]]; then
  echo "ERROR: OTP pepper secret is not encrypted by the exact authority data KMS key" >&2
  exit 1
fi

expected_version_token="$(printf '%s' "$secret_arn" | sha256sum | awk '{print $1}')"
if [[ ! "$expected_version_token" =~ ^[0-9a-f]{64}$ ]]; then
  echo "ERROR: could not derive the deterministic secret-version token" >&2
  exit 1
fi

aws secretsmanager list-secret-version-ids \
  --region "$region" \
  --secret-id "$secret_arn" \
  --include-deprecated \
  --output json >"$evidence_dir/secret-versions.json"
version_count="$(jq -er '.Versions | length' "$evidence_dir/secret-versions.json")"
current_count="$(jq -er '[.Versions[] | select(.VersionStages == ["AWSCURRENT"])] | length' \
  "$evidence_dir/secret-versions.json")"
token_count="$(jq -er --arg token "$expected_version_token" \
  '[.Versions[] | select(.VersionId == $token and .VersionStages == ["AWSCURRENT"])] | length' \
  "$evidence_dir/secret-versions.json")"
if [[ "$version_count" -ne 1 || "$current_count" -ne 1 || "$token_count" -ne 1 ]]; then
  echo "ERROR: OTP pepper must have exactly its deterministic version labeled only AWSCURRENT; verification will not repair it" >&2
  exit 1
fi

jq -n \
  --arg token "$expected_version_token" \
  '{ready:true,verified_read_only:true,secret_version_token_sha256:$token}' \
  >"$evidence_dir/secret-verification-summary.json"
