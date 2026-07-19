#!/usr/bin/env bash

# Permanent operator-invoked sandbox verifier. Run it only from the reviewed
# apply path; it is intentionally not scheduled or wired to the retired
# one-time first-apply workflow.
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: $0 <control-terraform-root> <empty-evidence-directory>" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
terraform_root="$(cd "$1" && pwd)"
evidence_dir="$2"
region="us-east-2"
state_bucket="layerv-terraform-state-767397897469"
state_key="nhp/sandbox/control/terraform.tfstate"
state_kms_key_arn="arn:aws:kms:us-east-2:767397897469:key/289dbe35-ab5a-4752-8564-4c96c607c9f4"
control_prefix="layerv-nhp-sandbox-control"
checker="$repo_root/.github/scripts/check-control-sandbox-first-apply.py"

if [[ -e "$evidence_dir" ]] && [[ -n "$(find "$evidence_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "ERROR: evidence directory must be empty: $evidence_dir" >&2
  exit 1
fi
mkdir -p "$evidence_dir"

terraform -chdir="$terraform_root" state list >"$evidence_dir/state-list.txt"
python3 "$checker" state-list "$evidence_dir/state-list.txt" \
  | tee "$evidence_dir/state-list-summary.json"

set +e
terraform -chdir="$terraform_root" plan \
  -input=false \
  -lock=false \
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
dynamodb_endpoint_id="$(state_value 'module.control.aws_vpc_endpoint.dynamodb' id)"
flow_log_id="$(state_value 'module.control.aws_flow_log.control' id)"
flow_log_destination="$(state_value 'module.control.aws_flow_log.control' log_destination)"
flow_log_role_arn="$(state_value 'module.control.aws_flow_log.control' iam_role_arn)"
secret_arn="$(state_value 'module.control.aws_secretsmanager_secret.otp_pepper' arn)"
authority_data_key_arn="$(state_value 'module.control.aws_kms_key.authority_data' arn)"
route_table_ids=()
for index in 0 1 2; do
  route_table_ids+=("$(state_value "module.control.aws_route_table.isolated[$index]" id)")
done

jq -n \
  --arg vpc_id "$vpc_id" \
  --arg dynamodb_endpoint_id "$dynamodb_endpoint_id" \
  --arg flow_log_id "$flow_log_id" \
  --arg flow_log_destination "$flow_log_destination" \
  --arg flow_log_role_arn "$flow_log_role_arn" \
  --arg rtb0 "${route_table_ids[0]}" \
  --arg rtb1 "${route_table_ids[1]}" \
  --arg rtb2 "${route_table_ids[2]}" \
  '{vpc_id:$vpc_id,dynamodb_endpoint_id:$dynamodb_endpoint_id,
    flow_log_id:$flow_log_id,flow_log_destination:$flow_log_destination,
    flow_log_role_arn:$flow_log_role_arn,
    isolated_route_table_ids:[$rtb0,$rtb1,$rtb2]}' \
  >"$evidence_dir/expected-live.json"

aws ec2 describe-route-tables \
  --region "$region" \
  --filters "Name=vpc-id,Values=$vpc_id" \
  --output json >"$evidence_dir/route-tables.json"
aws ec2 describe-internet-gateways \
  --region "$region" \
  --filters "Name=attachment.vpc-id,Values=$vpc_id" \
  --output json >"$evidence_dir/internet-gateways.json"
aws ec2 describe-egress-only-internet-gateways \
  --region "$region" \
  --filters "Name=attachment.vpc-id,Values=$vpc_id" \
  --output json >"$evidence_dir/egress-only-internet-gateways.json"
aws ec2 describe-nat-gateways \
  --region "$region" \
  --filter "Name=vpc-id,Values=$vpc_id" \
  --output json >"$evidence_dir/nat-gateways.json"
aws ec2 describe-vpc-peering-connections \
  --region "$region" \
  --output json \
  | jq --arg vpc_id "$vpc_id" \
    '{VpcPeeringConnections:[.VpcPeeringConnections[]
      | select(.RequesterVpcInfo.VpcId == $vpc_id or .AccepterVpcInfo.VpcId == $vpc_id)]}' \
    >"$evidence_dir/vpc-peerings.json"
aws ec2 describe-transit-gateway-attachments \
  --region "$region" \
  --filters "Name=resource-id,Values=$vpc_id" \
  --output json >"$evidence_dir/transit-gateway-attachments.json"

flow_ready=false
for attempt in $(seq 1 20); do
  aws ec2 describe-flow-logs \
    --region "$region" \
    --filter "Name=resource-id,Values=$vpc_id" \
    --output json >"$evidence_dir/flow-logs.json"
  flow_status="$(jq -er --arg id "$flow_log_id" \
    '[.FlowLogs[] | select(.FlowLogId == $id) | .FlowLogStatus][0] // "MISSING"' \
    "$evidence_dir/flow-logs.json")"
  delivery_status="$(jq -er --arg id "$flow_log_id" \
    '[.FlowLogs[] | select(.FlowLogId == $id) | .DeliverLogsStatus][0] // "MISSING"' \
    "$evidence_dir/flow-logs.json")"
  delivery_error="$(jq -r --arg id "$flow_log_id" \
    '[.FlowLogs[] | select(.FlowLogId == $id) | .DeliverLogsErrorMessage][0] // ""' \
    "$evidence_dir/flow-logs.json")"
  if [[ "$flow_status" == "ACTIVE" && "$delivery_status" == "SUCCESS" && -z "$delivery_error" ]]; then
    flow_ready=true
    break
  fi
  if [[ "$flow_status" == "FAILED" || "$delivery_status" == "FAILED" || -n "$delivery_error" ]]; then
    echo "ERROR: VPC Flow Log reached a terminal/error state" >&2
    exit 1
  fi
  if ((attempt < 20)); then
    sleep 15
  fi
done
if [[ "$flow_ready" != true ]]; then
  echo "ERROR: VPC Flow Log did not reach ACTIVE/SUCCESS within 20 checks over roughly five minutes plus AWS API latency" >&2
  exit 1
fi

aws s3api head-object \
  --bucket "$state_bucket" \
  --key "$state_key" \
  --output json >"$evidence_dir/state-head.json"
aws lambda list-functions --region "$region" --output json \
  | jq --arg prefix "$control_prefix" \
    '[.Functions[] | select(.FunctionName | startswith($prefix))]' \
    >"$evidence_dir/control-lambdas.json"
aws elbv2 describe-load-balancers --region "$region" --output json \
  | jq --arg prefix "$control_prefix" \
    '[.LoadBalancers[] | select((.LoadBalancerName // "") | startswith($prefix))]' \
    >"$evidence_dir/control-load-balancers.json"

python3 "$checker" live "$evidence_dir" \
  | tee "$evidence_dir/live-boundary-summary.json"

"$repo_root/scripts/ensure-control-otp-pepper.sh" \
  "$secret_arn" \
  "$authority_data_key_arn" \
  "$region" \
  "$evidence_dir"
client_request_token="$(jq -er '.secret_version_token_sha256' \
  "$evidence_dir/secret-seed-summary.json")"
secret_seeded_this_run="$(jq -er '.seeded_this_run' \
  "$evidence_dir/secret-seed-summary.json")"

jq -n \
  --arg vpc_id "$vpc_id" \
  --arg flow_log_id "$flow_log_id" \
  --arg state_kms_key_arn "$state_kms_key_arn" \
  --arg secret_version_token "$client_request_token" \
  --argjson secret_seeded_this_run "$secret_seeded_this_run" \
  '{vpc_id:$vpc_id,flow_log_id:$flow_log_id,state_kms_key_arn:$state_kms_key_arn,
    state_versioned:true,dark_boundary_verified:true,secret_ready:true,
    secret_seeded_this_run:$secret_seeded_this_run,
    secret_version_token_sha256:$secret_version_token,post_apply_plan:"no-op"}' \
  | tee "$evidence_dir/verification-summary.json"
