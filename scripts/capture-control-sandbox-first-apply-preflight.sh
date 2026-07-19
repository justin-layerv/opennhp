#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <empty-evidence-directory>" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
evidence_dir="$1"
account_id="767397897469"
region="us-east-2"
role_name="nhp-sandbox-github-actions"
policy_arn="arn:aws:iam::${account_id}:policy/nhp-sandbox-github-actions-terraform-apply-data"
state_bucket="layerv-terraform-state-${account_id}"
state_key="nhp/sandbox/control/terraform.tfstate"
lock_key="${state_key}.tflock"

if [[ -e "$evidence_dir" ]] && [[ -n "$(find "$evidence_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "ERROR: evidence directory must be empty: $evidence_dir" >&2
  exit 1
fi
mkdir -p "$evidence_dir"

aws sts get-caller-identity --output json >"$evidence_dir/caller.json"
aws iam get-policy --policy-arn "$policy_arn" --output json >"$evidence_dir/policy.json"
policy_version="$(jq -er '.Policy.DefaultVersionId' "$evidence_dir/policy.json")"
aws iam get-policy-version \
  --policy-arn "$policy_arn" \
  --version-id "$policy_version" \
  --output json >"$evidence_dir/policy-version.json"
aws iam list-attached-role-policies \
  --role-name "$role_name" \
  --output json >"$evidence_dir/attached-policies.json"
aws iam get-account-summary --output json >"$evidence_dir/account-summary.json"

control_write_actions=(
  elasticache:CreateUser
  elasticache:ModifyUser
  elasticache:DeleteUser
  elasticache:CreateUserGroup
  elasticache:ModifyUserGroup
  elasticache:DeleteUserGroup
  elasticache:AddTagsToResource
  elasticache:RemoveTagsFromResource
)
control_read_actions=(
  elasticache:DescribeUsers
  elasticache:DescribeUserGroups
  elasticache:ListTagsForResource
)
control_actions=("${control_write_actions[@]}" "${control_read_actions[@]}")
control_resources=(
  "arn:aws:elasticache:${region}:${account_id}:user:layerv-nhp-sandbox-control-otp-auth"
  "arn:aws:elasticache:${region}:${account_id}:usergroup:layerv-nhp-sandbox-control-otp-users"
)
cell_resources=(
  "arn:aws:elasticache:${region}:${account_id}:user:layerv-nhp-sandbox-cell0-forbidden"
  "arn:aws:elasticache:${region}:${account_id}:usergroup:layerv-nhp-sandbox-cell0-forbidden"
)
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::${account_id}:role/${role_name}" \
  --action-names "${control_actions[@]}" \
  --resource-arns "${control_resources[@]}" \
  --output json >"$evidence_dir/control-simulation.json"
# The role has unrelated policies conditioned on aws:ResourceAccount. IAM's
# simulator reports that context as missing on otherwise implicit-deny actions,
# so provide the exact account already encoded in every cell ARN. Supplying the
# real request context preserves fail-closed evaluation: any in-account wildcard
# write grant would become allowed here and fail the checker.
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::${account_id}:role/${role_name}" \
  --action-names "${control_write_actions[@]}" \
  --resource-arns "${cell_resources[@]}" \
  --context-entries \
    "ContextKeyName=aws:ResourceAccount,ContextKeyValues=${account_id},ContextKeyType=string" \
  --output json >"$evidence_dir/cell-write-simulation.json"
# Deliberately omit context here: the reviewed Describe*/List* allow is
# unconditional. A future condition must surface as missing context and stop
# this exact preflight rather than being silently accepted.
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::${account_id}:role/${role_name}" \
  --action-names "${control_read_actions[@]}" \
  --resource-arns "${cell_resources[@]}" \
  --output json >"$evidence_dir/cell-read-simulation.json"

aws ec2 describe-vpc-endpoint-services \
  --region "$region" \
  --service-names "com.amazonaws.${region}.email" \
  --output json >"$evidence_dir/endpoint-service.json"
aws kms describe-key \
  --region "$region" \
  --key-id alias/terraform-state \
  --output json >"$evidence_dir/state-kms.json"
aws s3api get-bucket-versioning \
  --bucket "$state_bucket" \
  --output json >"$evidence_dir/bucket-versioning.json"

assert_absent() {
  local key="$1"
  local label="$2"
  local stdout_file="${evidence_dir}/${label}-head.json"
  local stderr_file="${evidence_dir}/${label}-head.err"
  local status
  set +e
  aws s3api head-object \
    --bucket "$state_bucket" \
    --key "$key" \
    --output json >"$stdout_file" 2>"$stderr_file"
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    echo "ERROR: $label already exists at s3://${state_bucket}/${key}" >&2
    exit 1
  fi
  if ! grep -Eq '\(404\)|Not Found|NoSuchKey' "$stderr_file"; then
    sed 's/^/AWS: /' "$stderr_file" >&2
    echo "ERROR: could not prove $label absence" >&2
    exit 1
  fi
  rm -f "$stdout_file" "$stderr_file"
}

assert_absent "$state_key" state
assert_absent "$lock_key" lock
jq -n \
  --arg bucket "$state_bucket" \
  --arg state_key "$state_key" \
  --arg lock_key "$lock_key" \
  '{bucket:$bucket,state_key:$state_key,lock_key:$lock_key,state_exists:false,lock_exists:false}' \
  >"$evidence_dir/state-status.json"

python3 "$repo_root/.github/scripts/check-control-sandbox-first-apply.py" \
  preflight "$evidence_dir" | tee "$evidence_dir/preflight-summary.json"
