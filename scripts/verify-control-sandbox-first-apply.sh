#!/usr/bin/env bash

# Permanent sandbox verifier. Run it only from a reviewed, serialized Control
# workflow; it is intentionally not scheduled and remains independent of the
# retired one-time first-apply workflow.
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: $0 <control-terraform-root> <empty-evidence-directory> <verified-runtime-tfvars>" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
terraform_root="$(cd "$1" && pwd)"
evidence_dir="$2"
runtime_contract_var_file="$3"
region="us-east-2"
state_kms_key_arn="arn:aws:kms:us-east-2:767397897469:key/289dbe35-ab5a-4752-8564-4c96c607c9f4"
checker="$repo_root/.github/scripts/check-control-sandbox-first-apply.py"

if [[ ! -f "$runtime_contract_var_file" || -L "$runtime_contract_var_file" ]]; then
  echo "ERROR: verified runtime tfvars must be a regular non-symlink file" >&2
  exit 1
fi
if [[ "$(stat -c '%a' "$runtime_contract_var_file")" != "600" ]]; then
  echo "ERROR: verified runtime tfvars must have exact mode 600" >&2
  exit 1
fi

if [[ -e "$evidence_dir" ]] && [[ -n "$(find "$evidence_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "ERROR: evidence directory must be empty: $evidence_dir" >&2
  exit 1
fi
install -d -m 700 "$evidence_dir"

terraform -chdir="$terraform_root" state list >"$evidence_dir/state-list.txt"
python3 "$checker" state-list "$evidence_dir/state-list.txt" \
  | tee "$evidence_dir/state-list-summary.json"

set +e
terraform -chdir="$terraform_root" plan \
  -input=false \
  -lock-timeout=5m \
  -var-file="$runtime_contract_var_file" \
  -detailed-exitcode \
  -out="$evidence_dir/post-apply.tfplan" \
  >"$evidence_dir/post-apply-plan.txt"
plan_status=$?
set -e
if [[ "$plan_status" -ne 0 ]]; then
  echo "ERROR: refresh-enabled post-apply plan must be an exact no-op (exit 0), got $plan_status" >&2
  exit 1
fi
terraform -chdir="$terraform_root" show -json "$evidence_dir/post-apply.tfplan" \
  >"$evidence_dir/post-apply-plan.json"
python3 "$checker" plan "$evidence_dir/post-apply-plan.json" \
  | tee "$evidence_dir/post-apply-plan-summary.json"
python3 "$checker" state "$evidence_dir/post-apply-plan.json" \
  | tee "$evidence_dir/refreshed-state-summary.json"

"$repo_root/scripts/verify-control-sandbox-live-boundary.sh" \
  "$evidence_dir/post-apply-plan.json" \
  "$evidence_dir"

state_value() {
  local address="$1"
  local attribute="$2"
  jq -er \
    --arg address "$address" \
    --arg attribute "$attribute" \
    '[.prior_state.values.root_module
      | recurse(.child_modules[]?)
      | .resources[]?
      | select(.mode == "managed" and .address == $address)
      | .values[$attribute]][0]' \
    "$evidence_dir/post-apply-plan.json"
}

vpc_id="$(state_value 'module.control.aws_vpc.control' id)"
flow_log_id="$(state_value 'module.control.aws_flow_log.control' id)"
secret_arn="$(state_value 'module.control.aws_secretsmanager_secret.otp_pepper' arn)"
authority_data_key_arn="$(state_value 'module.control.aws_kms_key.authority_data' arn)"

"$repo_root/scripts/verify-control-otp-pepper.sh" \
  "$secret_arn" \
  "$authority_data_key_arn" \
  "$region" \
  "$evidence_dir"
client_request_token="$(jq -er '.secret_version_token_sha256' \
  "$evidence_dir/secret-verification-summary.json")"
secret_verified_read_only="$(jq -er '.verified_read_only' \
  "$evidence_dir/secret-verification-summary.json")"

jq -n \
  --arg vpc_id "$vpc_id" \
  --arg flow_log_id "$flow_log_id" \
  --arg state_kms_key_arn "$state_kms_key_arn" \
  --arg secret_version_token "$client_request_token" \
  --argjson secret_verified_read_only "$secret_verified_read_only" \
  '{vpc_id:$vpc_id,flow_log_id:$flow_log_id,state_kms_key_arn:$state_kms_key_arn,
    state_versioned:true,dark_boundary_verified:true,secret_ready:true,
    secret_verified_read_only:$secret_verified_read_only,
    secret_version_token_sha256:$secret_version_token,post_apply_plan:"no-op"}' \
  | tee "$evidence_dir/verification-summary.json"
