#!/usr/bin/env bash
#
# Converge and remove the fixed sandbox proof account used by qurl-go's real
# NHP_OTP -> NHP_REG proof. The stable credential is seeded out of band in
# Secrets Manager. This script verifies its Terraform-pinned digest, creates
# only the two exact Control rows needed for OTP authorization, then copies the
# credential into a run-bound secret that only the private proof runner can
# read. Plaintext is never printed or passed in an argv.

set -euo pipefail

readonly action="${1:-}"
readonly controller_run_id="${2:-}"
readonly controller_run_attempt="${3:-}"

: "${AWS_REGION:?AWS_REGION is required}"
: "${PROOF_ACCOUNT_SOURCE_SECRET:?PROOF_ACCOUNT_SOURCE_SECRET is required}"
: "${PROOF_ACCOUNT_SHA_PARAMETER:?PROOF_ACCOUNT_SHA_PARAMETER is required}"
: "${PROOF_ACCOUNT_KEY_TABLE:?PROOF_ACCOUNT_KEY_TABLE is required}"
: "${PROOF_ACCOUNT_CUSTOMER_TABLE:?PROOF_ACCOUNT_CUSTOMER_TABLE is required}"
: "${PROOF_ACCOUNT_OWNER_ID:?PROOF_ACCOUNT_OWNER_ID is required}"
: "${PROOF_ACCOUNT_KEY_ID:?PROOF_ACCOUNT_KEY_ID is required}"
: "${PROOF_ACCOUNT_EMAIL:?PROOF_ACCOUNT_EMAIL is required}"
: "${PROOF_ACCOUNT_JIT_SECRET_PREFIX:?PROOF_ACCOUNT_JIT_SECRET_PREFIX is required}"
: "${JIT_KMS_KEY_ARN:?JIT_KMS_KEY_ARN is required}"

[[ "$action" == "prepare" || "$action" == "cleanup" ]] || {
  echo "usage: manage_udp_proof_account.sh prepare|cleanup <controller-run-id> <controller-run-attempt>" >&2
  exit 2
}
[[ "$controller_run_id" =~ ^[1-9][0-9]{0,19}$ ]] || {
  echo "::error::controller run ID must be a positive integer"
  exit 1
}
[[ "$controller_run_attempt" =~ ^[1-9][0-9]{0,5}$ ]] || {
  echo "::error::controller run attempt must be a positive integer"
  exit 1
}
[[ "$PROOF_ACCOUNT_OWNER_ID" =~ ^[a-z0-9-]{3,64}$ ]] || {
  echo "::error::proof owner ID is malformed"
  exit 1
}
[[ "$PROOF_ACCOUNT_KEY_ID" =~ ^key_[A-Za-z0-9]{12}$ ]] || {
  echo "::error::proof account key ID is malformed"
  exit 1
}
[[ "$PROOF_ACCOUNT_EMAIL" =~ ^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$ ]] || {
  echo "::error::proof mailbox address is malformed"
  exit 1
}

readonly ephemeral_secret_id="${PROOF_ACCOUNT_JIT_SECRET_PREFIX}${controller_run_id}/${controller_run_attempt}"
work_dir="$(mktemp -d)"
chmod 700 "$work_dir"
credential=""
cleanup_local() {
  credential=""
  rm -rf "$work_dir"
}
trap cleanup_local EXIT

get_bound_hash() {
  local expected_hash
  expected_hash="$(
    aws ssm get-parameter \
      --name "$PROOF_ACCOUNT_SHA_PARAMETER" \
      --region "$AWS_REGION" \
      --query 'Parameter.Value' \
      --output text
  )"
  [[ "$expected_hash" =~ ^[0-9a-f]{64}$ ]] || {
    echo "::error::proof account credential digest is malformed"
    return 1
  }
  printf '%s' "$expected_hash"
}

delete_account_row() {
  local key_hash="$1"
  printf '{"key_hash":{"S":"%s"}}\n' "$key_hash" >"$work_dir/delete-key.json"
  aws dynamodb delete-item \
    --table-name "$PROOF_ACCOUNT_KEY_TABLE" \
    --key "file://$work_dir/delete-key.json" \
    --condition-expression 'attribute_not_exists(key_hash) OR (key_hash = :hash AND owner_id = :owner AND key_id = :key_id)' \
    --expression-attribute-values "file://$work_dir/delete-values.json" \
    --region "$AWS_REGION" >/dev/null
}

assert_account_row_absent() {
  local key_hash="$1"
  printf '{"key_hash":{"S":"%s"}}\n' "$key_hash" >"$work_dir/read-key.json"
  aws dynamodb get-item \
    --table-name "$PROOF_ACCOUNT_KEY_TABLE" \
    --key "file://$work_dir/read-key.json" \
    --consistent-read \
    --region "$AWS_REGION" \
    --output json >"$work_dir/read-key-result.json"
  jq -e 'has("Item") | not' "$work_dir/read-key-result.json" >/dev/null || {
    echo "::error::proof account key row still exists after cleanup"
    return 1
  }
}

delete_run_secret() {
  local error_file="$work_dir/delete-secret.err"
  if aws secretsmanager delete-secret \
    --secret-id "$ephemeral_secret_id" \
    --force-delete-without-recovery \
    --region "$AWS_REGION" >/dev/null 2>"$error_file"; then
    return 0
  fi
  if grep -q 'ResourceNotFoundException' "$error_file"; then
    return 0
  fi
  echo "::error::could not remove the exact run-bound proof credential"
  return 1
}

expected_hash="$(get_bound_hash)"
printf \
  '{":hash":{"S":"%s"},":owner":{"S":"%s"},":key_id":{"S":"%s"}}\n' \
  "$expected_hash" "$PROOF_ACCOUNT_OWNER_ID" "$PROOF_ACCOUNT_KEY_ID" \
  >"$work_dir/delete-values.json"

if [[ "$action" == "cleanup" ]]; then
  delete_account_row "$expected_hash"
  assert_account_row_absent "$expected_hash"
  delete_run_secret
  echo "Removed the run-bound qurl-go proof account credential."
  exit 0
fi

aws secretsmanager get-secret-value \
  --secret-id "$PROOF_ACCOUNT_SOURCE_SECRET" \
  --region "$AWS_REGION" \
  --output json >"$work_dir/source-secret.json"
jq -e '.SecretString | type == "string" and length == 51 and test("^lv_test_[A-Za-z0-9_-]{43}$")' \
  "$work_dir/source-secret.json" >/dev/null || {
  echo "::error::proof account credential has the wrong wire format"
  exit 1
}
credential="$(jq -er '.SecretString | select(type == "string")' "$work_dir/source-secret.json")"
rm -f "$work_dir/source-secret.json"

actual_hash="$(printf '%s' "$credential" | sha256sum | cut -d' ' -f1)"
[[ "$actual_hash" == "$expected_hash" ]] || {
  echo "::error::proof account credential does not match its Terraform-pinned digest"
  exit 1
}
echo "::add-mask::$credential"

now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# The controller's full budget is 165 minutes and the disposable runner's hard
# deadline is 180 minutes. Four hours leaves one hour of clock/cleanup margin
# while ensuring a lost controller cannot leave the stable credential usable.
expires_at="$(date -u -d '+4 hours' +%Y-%m-%dT%H:%M:%SZ)"
retention_ttl="$(date -u -d '+34 days' +%s)"
printf '{"auth0_subject":{"S":"%s"}}\n' "$PROOF_ACCOUNT_OWNER_ID" >"$work_dir/customer-key.json"

validate_exact_system_customer() {
  local result_file="$1"
  jq -e \
    --arg owner "$PROOF_ACCOUNT_OWNER_ID" \
    --arg email "$PROOF_ACCOUNT_EMAIL" \
    '.Item == {
      "auth0_subject": {"S": $owner},
      "created_at": {"S": .Item.created_at.S},
      "current_period_usage": {"N": "0"},
      "email": {"S": $email},
      "frozen": {"BOOL": false},
      "frozen_reason": {"S": ""},
      "spending_cap_cents": {"N": "0"},
      "tier": {"S": "system"},
      "unit_price_cents": {"N": "0"},
      "updated_at": {"S": .Item.updated_at.S}
    } and
    (.Item.created_at.S | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
    (.Item.updated_at.S | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))' \
    "$result_file" >/dev/null
}

aws dynamodb get-item \
  --table-name "$PROOF_ACCOUNT_CUSTOMER_TABLE" \
  --key "file://$work_dir/customer-key.json" \
  --consistent-read \
  --region "$AWS_REGION" \
  --output json >"$work_dir/customer-before.json"

if jq -e 'has("Item") | not' "$work_dir/customer-before.json" >/dev/null; then
  printf \
    '{"auth0_subject":{"S":"%s"},"email":{"S":"%s"},"tier":{"S":"system"},"frozen":{"BOOL":false},"frozen_reason":{"S":""},"created_at":{"S":"%s"},"updated_at":{"S":"%s"},"current_period_usage":{"N":"0"},"spending_cap_cents":{"N":"0"},"unit_price_cents":{"N":"0"}}\n' \
    "$PROOF_ACCOUNT_OWNER_ID" "$PROOF_ACCOUNT_EMAIL" "$now" "$now" \
    >"$work_dir/customer-item.json"
  aws dynamodb put-item \
    --table-name "$PROOF_ACCOUNT_CUSTOMER_TABLE" \
    --item "file://$work_dir/customer-item.json" \
    --condition-expression 'attribute_not_exists(auth0_subject)' \
    --region "$AWS_REGION" >/dev/null
elif ! validate_exact_system_customer "$work_dir/customer-before.json"; then
  echo "::error::proof customer must already be the exact system/unlimited owner"
  exit 1
fi

aws dynamodb get-item \
  --table-name "$PROOF_ACCOUNT_CUSTOMER_TABLE" \
  --key "file://$work_dir/customer-key.json" \
  --consistent-read \
  --region "$AWS_REGION" \
  --output json >"$work_dir/customer-result.json"
validate_exact_system_customer "$work_dir/customer-result.json" || {
  echo "::error::proof customer row failed its exact post-write contract"
  exit 1
}

key_prefix="${credential:0:12}"
printf \
  '{"key_hash":{"S":"%s"},"key_id":{"S":"%s"},"key_prefix":{"S":"%s"},"owner_id":{"S":"%s"},"name":{"S":"sandbox UDP OTP proof"},"scopes":{"SS":["qurl:read"]},"status":{"S":"active"},"has_counter":{"BOOL":false},"has_agent_counter":{"BOOL":false},"created_at":{"S":"%s"},"expires_at":{"S":"%s"},"ttl":{"N":"%s"}}\n' \
  "$expected_hash" "$PROOF_ACCOUNT_KEY_ID" "$key_prefix" "$PROOF_ACCOUNT_OWNER_ID" "$now" "$expires_at" "$retention_ttl" \
  >"$work_dir/account-key-item.json"
printf \
  '{":owner":{"S":"%s"},":key_id":{"S":"%s"},":prefix":{"S":"%s"},":active":{"S":"active"},":name":{"S":"sandbox UDP OTP proof"},":scope":{"S":"qurl:read"},":false":{"BOOL":false}}\n' \
  "$PROOF_ACCOUNT_OWNER_ID" "$PROOF_ACCOUNT_KEY_ID" "$key_prefix" \
  >"$work_dir/account-key-values.json"

aws dynamodb put-item \
  --table-name "$PROOF_ACCOUNT_KEY_TABLE" \
  --item "file://$work_dir/account-key-item.json" \
  --condition-expression 'attribute_not_exists(key_hash) OR (owner_id = :owner AND key_id = :key_id AND key_prefix = :prefix AND #status = :active AND #name = :name AND contains(scopes, :scope) AND (attribute_not_exists(has_counter) OR has_counter = :false) AND (attribute_not_exists(has_agent_counter) OR has_agent_counter = :false))' \
  --expression-attribute-names '{"#status":"status","#name":"name"}' \
  --expression-attribute-values "file://$work_dir/account-key-values.json" \
  --region "$AWS_REGION" >/dev/null

printf '{"key_hash":{"S":"%s"}}\n' "$expected_hash" >"$work_dir/read-key.json"
aws dynamodb get-item \
  --table-name "$PROOF_ACCOUNT_KEY_TABLE" \
  --key "file://$work_dir/read-key.json" \
  --consistent-read \
  --region "$AWS_REGION" \
  --output json >"$work_dir/account-key-result.json"
jq -e \
  --arg hash "$expected_hash" \
  --arg owner "$PROOF_ACCOUNT_OWNER_ID" \
  --arg key_id "$PROOF_ACCOUNT_KEY_ID" \
  --arg prefix "$key_prefix" \
  --arg expires_at "$expires_at" \
  --arg ttl "$retention_ttl" \
  '.Item == {
    "created_at": {"S": .Item.created_at.S},
    "expires_at": {"S": $expires_at},
    "has_agent_counter": {"BOOL": false},
    "has_counter": {"BOOL": false},
    "key_hash": {"S": $hash},
    "key_id": {"S": $key_id},
    "key_prefix": {"S": $prefix},
    "name": {"S": "sandbox UDP OTP proof"},
    "owner_id": {"S": $owner},
    "scopes": {"SS": ["qurl:read"]},
    "status": {"S": "active"},
    "ttl": {"N": $ttl}
  } and (.Item.created_at.S | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))' \
  "$work_dir/account-key-result.json" >/dev/null || {
  echo "::error::proof account key row failed its exact post-write contract"
  delete_account_row "$expected_hash"
  assert_account_row_absent "$expected_hash"
  exit 1
}

# Use a CLI input file so the plaintext credential never appears in the
# process list. The file is mode 0600 under the mode 0700 temporary directory.
printf \
  '{"Name":"%s","Description":"Run-bound qurl-go UDP OTP proof account credential","KmsKeyId":"%s","SecretString":"%s","Tags":[{"Key":"Environment","Value":"sandbox"},{"Key":"Purpose","Value":"udp-proof-account-credential-run"},{"Key":"GitHubRunId","Value":"%s"},{"Key":"GitHubRunAttempt","Value":"%s"}]}\n' \
  "$ephemeral_secret_id" "$JIT_KMS_KEY_ARN" "$credential" \
  "$controller_run_id" "$controller_run_attempt" \
  >"$work_dir/create-secret.json"

if ! aws secretsmanager create-secret \
  --cli-input-json "file://$work_dir/create-secret.json" \
  --region "$AWS_REGION" >/dev/null; then
  if ! delete_account_row "$expected_hash" || ! assert_account_row_absent "$expected_hash"; then
    echo "::error::run-bound secret creation failed and proof account cleanup did not converge"
    exit 1
  fi
  exit 1
fi

credential=""
rm -f "$work_dir/create-secret.json"
echo "Prepared the run-bound qurl-go proof account."
