#!/usr/bin/env bash

# Prove the live, existing sandbox Control VPC remains dark. The Terraform JSON
# supplies only reviewed resource IDs; AWS queries detect untracked routes and
# attachments that remote-state equality cannot see.
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: $0 <terraform-show-plan-json> <evidence-directory>" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
plan_json="$1"
evidence_dir="$2"
region="us-east-2"
state_bucket="layerv-terraform-state-767397897469"
state_key="nhp/sandbox/control/terraform.tfstate"
control_prefix="layerv-nhp-sandbox-control"
checker="$repo_root/.github/scripts/check-control-sandbox-first-apply.py"

if [[ ! -f "$plan_json" ]]; then
  echo "ERROR: Terraform plan JSON does not exist: $plan_json" >&2
  exit 2
fi
# The permanent verifier passes its already-created evidence directory here.
# install -d is idempotent and reapplies the private mode to that directory.
install -d -m 700 "$evidence_dir"
for output in \
  expected-live.json \
  route-tables.json \
  internet-gateways.json \
  egress-only-internet-gateways.json \
  nat-gateways.json \
  vpc-peerings.json \
  transit-gateway-attachments.json \
  flow-logs.json \
  state-head.json \
  control-lambdas.json \
  control-load-balancers.json \
  live-boundary-summary.json; do
  if [[ -e "$evidence_dir/$output" ]]; then
    echo "ERROR: refusing to reuse live-boundary evidence file: $evidence_dir/$output" >&2
    exit 2
  fi
done

state_value() {
  local address="$1"
  local attribute="$2"
  local value
  if ! value="$(jq -er \
    --arg address "$address" \
    --arg attribute "$attribute" \
    '[.prior_state.values.root_module
      | recurse(.child_modules[]?)
      | .resources[]?
      | select(.mode == "managed" and .address == $address)
      | .values[$attribute]][0]' \
    "$plan_json")"; then
    echo "ERROR: live-boundary state lookup found no '$attribute' for managed resource '$address' — the Control resource set may have drifted (address renamed/removed) or the plan JSON is malformed. Failing closed." >&2
    return 1
  fi
  printf '%s\n' "$value"
}

vpc_id="$(state_value 'module.control.aws_vpc.control' id)"
dynamodb_endpoint_id="$(state_value 'module.control.aws_vpc_endpoint.dynamodb' id)"
flow_log_id="$(state_value 'module.control.aws_flow_log.control' id)"
flow_log_destination="$(state_value 'module.control.aws_flow_log.control' log_destination)"
flow_log_role_arn="$(state_value 'module.control.aws_flow_log.control' iam_role_arn)"
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

# Post-apply the flow log may still be converging, so the default budget is
# generous (~5 min). Pre-apply the flow log is already steady-state, so that
# caller sets FLOW_LOG_MAX_ATTEMPTS low to avoid spinning inside the held
# deploy-sandbox-infra lock; a transient non-SUCCESS then fails closed pre-apply.
max_attempts="${FLOW_LOG_MAX_ATTEMPTS:-20}"
if [[ ! "$max_attempts" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: FLOW_LOG_MAX_ATTEMPTS must be a positive integer" >&2
  exit 2
fi
flow_ready=false
for ((attempt = 1; attempt <= max_attempts; attempt++)); do
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
  if ((attempt < max_attempts)); then
    sleep 15
  fi
done
if [[ "$flow_ready" != true ]]; then
  echo "ERROR: VPC Flow Log did not reach ACTIVE/SUCCESS within $max_attempts checks at 15-second intervals" >&2
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
