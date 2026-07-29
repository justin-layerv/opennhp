#!/usr/bin/env bash
#
# Capture the current non-secret proof-account digest binding and render the
# exact Terraform variable file that corresponds to it. ParameterNotFound is
# the expected first-apply state; every other read failure remains fatal.

set -euo pipefail

: "${AWS_REGION:?AWS_REGION is required}"
: "${PROOF_ACCOUNT_SOURCE_SECRET:?PROOF_ACCOUNT_SOURCE_SECRET is required}"
: "${PROOF_ACCOUNT_SHA_PARAMETER:?PROOF_ACCOUNT_SHA_PARAMETER is required}"

readonly output_dir="${1:-}"
[[ "$output_dir" == /* ]] || {
  echo "usage: capture-sandbox-udp-proof-account-binding.sh <absolute-output-dir>" >&2
  exit 2
}
[[ ! -e "$output_dir" ]] || {
  echo "::error::proof-account binding output path already exists"
  exit 1
}

umask 077
mkdir -m 700 "$output_dir"
readonly value_file="$output_dir/value"
readonly parameter_error_file="$output_dir/parameter-read-error"
readonly secret_file="$output_dir/source-secret.json"
readonly secret_error_file="$output_dir/secret-read-error"
credential=""
secret_sha256=""
secret_version_id=""
value=""
parameter_version=""
cleanup_sensitive() {
  credential=""
  rm -f "$secret_file" "$secret_error_file" "$value_file" "$parameter_error_file"
}
trap cleanup_sensitive EXIT

secret_state="missing"
if aws secretsmanager get-secret-value \
  --secret-id "$PROOF_ACCOUNT_SOURCE_SECRET" \
  --region "$AWS_REGION" \
  --output json >"$secret_file" 2>"$secret_error_file"; then
  jq -e \
    '.SecretString | type == "string" and
      length == 51 and
      test("^lv_test_[A-Za-z0-9_-]{43}$")' \
    "$secret_file" >/dev/null || {
    echo "::error::proof-account source credential has the wrong wire format"
    exit 1
  }
  credential="$(jq -er '.SecretString | select(type == "string")' "$secret_file")"
  secret_version_id="$(
    jq -er '.VersionId | select(type == "string" and length >= 1 and length <= 256)' \
      "$secret_file"
  )"
  secret_sha256="$(printf '%s' "$credential" | sha256sum | awk '{print $1}')"
  secret_state="seeded"
elif ! grep -q 'ResourceNotFoundException' "$secret_error_file"; then
  echo "::error::could not read the proof-account source credential"
  cat "$secret_error_file" >&2
  exit 1
fi

parameter_state="missing"
if aws ssm get-parameter \
  --name "$PROOF_ACCOUNT_SHA_PARAMETER" \
  --region "$AWS_REGION" \
  --output json >"$value_file" 2>"$parameter_error_file"; then
  value="$(jq -er '.Parameter.Value' "$value_file")"
  [[ "$value" =~ ^[0-9a-f]{64}$ ]] || {
    echo "::error::proof-account digest parameter is malformed"
    exit 1
  }
  parameter_version="$(
    jq -er '.Parameter.Version | select(type == "number" and . >= 1 and floor == .)' \
      "$value_file"
  )"
  parameter_state="configured"
elif ! grep -q 'ParameterNotFound' "$parameter_error_file"; then
  echo "::error::could not read the proof-account digest parameter"
  cat "$parameter_error_file" >&2
  exit 1
fi

if [[ "$secret_state" == "missing" && "$parameter_state" == "missing" ]]; then
  jq -nS '{
    state:"unconfigured",
    sha256:null,
    secret_version_id:null,
    parameter_state:"missing",
    parameter_version:null
  }' >"$output_dir/binding.json"
  jq -nS '{}' >"$output_dir/terraform.tfvars.json"
elif [[ "$secret_state" == "seeded" ]]; then
  if [[ "$parameter_state" == "configured" && "$value" != "$secret_sha256" ]]; then
    echo "::error::proof-account source credential does not match its digest parameter"
    exit 1
  fi
  jq -nS \
    --arg sha256 "$secret_sha256" \
    --arg secret_version_id "$secret_version_id" \
    --arg parameter_state "$parameter_state" \
    --argjson parameter_version "${parameter_version:-null}" \
    '{
      state:"configured",
      sha256:$sha256,
      secret_version_id:$secret_version_id,
      parameter_state:$parameter_state,
      parameter_version:$parameter_version
    }' >"$output_dir/binding.json"
  jq -nS --arg sha256 "$secret_sha256" \
    '{proof_account_credential_sha256:$sha256}' \
    >"$output_dir/terraform.tfvars.json"
else
  echo "::error::proof-account digest exists without its source credential"
  exit 1
fi
