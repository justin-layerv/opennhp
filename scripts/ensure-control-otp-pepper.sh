#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "usage: $0 <secret-arn> <expected-kms-key-arn> <region> <evidence-directory>" >&2
  exit 2
fi

secret_arn="$1"
expected_kms_key_arn="$2"
region="$3"
evidence_dir="$4"
mkdir -p "$evidence_dir"

aws secretsmanager describe-secret \
  --region "$region" \
  --secret-id "$secret_arn" \
  --output json >"$evidence_dir/secret-metadata.json"
if [[ "$(jq -er '.KmsKeyId' "$evidence_dir/secret-metadata.json")" != \
  "$expected_kms_key_arn" ]]; then
  echo "ERROR: OTP pepper secret is not encrypted by the exact authority data KMS key" >&2
  exit 1
fi

# The ARN is stable for the life of this secret, so a lost PutSecretValue
# response retries the same version ID. A same-ARN version/history conflict is
# deliberately not recoverable here: a different random candidate would still
# use this token and fail closed. Operators must repair ambiguous staging or,
# when appropriate, recreate the full secret so its ARN and token both change.
client_request_token="$(printf '%s' "$secret_arn" | sha256sum | awk '{print $1}')"
if [[ ! "$client_request_token" =~ ^[0-9a-f]{64}$ ]]; then
  echo "ERROR: could not derive the deterministic secret-version token" >&2
  exit 1
fi

count_secret_versions() {
  local versions_file="$1"
  # Set these globals intentionally for the before/after call-site assertions.
  version_count="$(jq -er '.Versions | length' "$versions_file")"
  current_count="$(jq -er '[.Versions[] | select(.VersionStages == ["AWSCURRENT"])] | length' \
    "$versions_file")"
  token_count="$(jq -er --arg token "$client_request_token" \
    '[.Versions[] | select(.VersionId == $token and .VersionStages == ["AWSCURRENT"])] | length' \
    "$versions_file")"
}

aws secretsmanager list-secret-version-ids \
  --region "$region" \
  --secret-id "$secret_arn" \
  --include-deprecated \
  --output json >"$evidence_dir/secret-versions-before.json"
count_secret_versions "$evidence_dir/secret-versions-before.json"
seeded_this_run=false
if [[ "$version_count" -eq 0 && "$current_count" -eq 0 ]]; then
  secret_file=""
  cleanup_secret_file() {
    if [[ -n "$secret_file" ]]; then
      rm -f -- "$secret_file"
    fi
  }
  trap cleanup_secret_file EXIT
  secret_file="$(mktemp)"
  chmod 600 "$secret_file"
  generated_secret="$(
    aws secretsmanager get-random-password \
      --region "$region" \
      --password-length 48 \
      --exclude-punctuation \
      --query RandomPassword \
      --output text
  )"
  if [[ "${#generated_secret}" -ne 48 ]]; then
    echo "ERROR: Secrets Manager did not generate the requested 48-character pepper" >&2
    exit 1
  fi
  printf '%s' "$generated_secret" >"$secret_file"
  unset generated_secret
  aws secretsmanager put-secret-value \
    --region "$region" \
    --secret-id "$secret_arn" \
    --client-request-token "$client_request_token" \
    --secret-string "file://$secret_file" \
    >/dev/null
  rm -f -- "$secret_file"
  secret_file=""
  trap - EXIT
  seeded_this_run=true
elif [[ "$version_count" -ne 1 || "$current_count" -ne 1 || "$token_count" -ne 1 ]]; then
  echo "ERROR: OTP pepper has ambiguous or missing AWSCURRENT history; repair staging or recreate the full secret before retrying" >&2
  exit 1
fi

aws secretsmanager list-secret-version-ids \
  --region "$region" \
  --secret-id "$secret_arn" \
  --include-deprecated \
  --output json >"$evidence_dir/secret-versions-after.json"
count_secret_versions "$evidence_dir/secret-versions-after.json"
if [[ "$version_count" -ne 1 || "$current_count" -ne 1 || "$token_count" -ne 1 ]]; then
  echo "ERROR: OTP pepper secret must have exactly its deterministic version labeled only AWSCURRENT" >&2
  exit 1
fi

jq -n \
  --arg token "$client_request_token" \
  --argjson seeded_this_run "$seeded_this_run" \
  '{ready:true,seeded_this_run:$seeded_this_run,secret_version_token_sha256:$token}' \
  >"$evidence_dir/secret-seed-summary.json"
