#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -gt 1 ]]; then
  echo "usage: $0 [terraform-show-json]" >&2
  exit 2
fi

plan_json="${1:-}"
repo_root="${NHP_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
module_dir="${repo_root}/terraform/modules/connector-authority-foundation"
control_dir="${repo_root}/terraform/control"
scan_paths=("$module_dir" "$control_dir")

for scan_path in "${scan_paths[@]}"; do
  if [[ ! -d "$scan_path" ]]; then
    echo "ERROR: Connector Authority scan path is missing: ${scan_path}" >&2
    exit 1
  fi
done

scan_tf_regex() {
  local pattern="$1"
  local status=0

  grep -R -nH -E --include='*.tf' -- "$pattern" "${scan_paths[@]}" || status=$?
  case "$status" in
    0 | 1)
      return "$status"
      ;;
    *)
      echo "ERROR: Connector Authority Terraform scan failed with status ${status}" >&2
      return 2
      ;;
  esac
}

forbidden_resource_types=(
  aws_api_gateway_rest_api
  aws_apigatewayv2_api
  aws_ec2_transit_gateway_connect
  aws_ec2_transit_gateway_peering_attachment
  aws_ec2_transit_gateway_peering_attachment_accepter
  aws_ec2_transit_gateway_vpc_attachment
  aws_ec2_transit_gateway_vpc_attachment_accepter
  aws_default_route_table
  aws_eip
  aws_egress_only_internet_gateway
  aws_internet_gateway
  aws_lambda_alias
  aws_lambda_function
  aws_lambda_function_url
  aws_lb
  aws_lb_listener
  aws_nat_gateway
  aws_route
  aws_route53_record
  aws_vpc_peering_connection
  aws_vpc_peering_connection_accepter
  aws_vpc_peering_connection_options
)

for resource_type in "${forbidden_resource_types[@]}"; do
  status=0
  scan_tf_regex "resource[[:space:]]+\"${resource_type}\"" || status=$?
  case "$status" in
    0)
      echo "ERROR: dark Connector Authority foundation must not declare ${resource_type}" >&2
      exit 1
      ;;
    1) ;;
    *) exit "$status" ;;
  esac
done

# aws_route_table accepts nested route blocks and a route list attribute. Both
# forms compile into the parent resource and would otherwise bypass the
# forbidden aws_route resource-type fence. Keep this lexical and fail closed
# so compact one-line declarations and either HCL spelling are rejected.
status=0
scan_tf_regex '(^|[[:space:]{])route[[:space:]]*([=]|[{])' || status=$?
case "$status" in
  0)
    echo "ERROR: dark Connector Authority foundation must not declare inline route blocks or route attributes" >&2
    exit 1
    ;;
  1) ;;
  *) exit "$status" ;;
esac

if [[ -n "$plan_json" ]]; then
  if [[ ! -r "$plan_json" ]]; then
    echo "ERROR: Connector Authority plan JSON is not readable: ${plan_json}" >&2
    exit 1
  fi
  if jq -e 'has("resource_changes")' "$plan_json" >/dev/null; then
    if ! jq -e '(.resource_changes | type) == "array"' "$plan_json" >/dev/null; then
      echo "ERROR: Connector Authority plan JSON resource_changes must be an array" >&2
      exit 1
    fi
  elif ! jq -e '(.resource_drift | type) == "array" and (.resource_drift | length) > 0' "$plan_json" >/dev/null; then
    echo "ERROR: Connector Authority plan JSON must contain a resource_changes array or non-empty resource_drift array" >&2
    exit 1
  fi

  destructive_resources="$(jq -r '
    (.resource_changes[]?, .resource_drift[]?)
    | select(.change.actions | index("delete"))
    | "\(.address) [\(.change.actions | join(","))]"
  ' "$plan_json")"
  if [[ -n "$destructive_resources" ]]; then
    echo "ERROR: dark Connector Authority plan contains destructive actions:" >&2
    echo "$destructive_resources" >&2
    exit 1
  fi

  for resource_type in "${forbidden_resource_types[@]}"; do
    addresses="$(jq -r --arg resource_type "$resource_type" '
      (.resource_changes[]?, .resource_drift[]?)
      | select(.type == $resource_type and .change.after != null)
      | .address
    ' "$plan_json")"
    if [[ -n "$addresses" ]]; then
      echo "ERROR: dark Connector Authority plan contains ${resource_type}:" >&2
      echo "$addresses" >&2
      exit 1
    fi
  done

  # The AWS provider marks after_unknown.route=true for clean route tables, so
  # unknown route metadata is not evidence of an inline declaration. The
  # lexical source fence above owns that case; plan JSON independently rejects
  # every known non-empty route list.
  inline_route_tables="$(jq -r '
    (.resource_changes[]?, .resource_drift[]?)
    | select(.type == "aws_route_table" and .change.after != null)
    | select(((.change.after.route? // []) | length) > 0)
    | .address
  ' "$plan_json")"
  if [[ -n "$inline_route_tables" ]]; then
    echo "ERROR: dark Connector Authority plan contains inline route declarations:" >&2
    echo "$inline_route_tables" >&2
    exit 1
  fi
fi

# Keep this deliberately lexical rather than value-only: URLs hidden in lists,
# maps, templates, or heredocs are still HTTP dependencies. Terraform comments
# under these roots must cite docs without spelling an HTTP URL so the security
# fence cannot gain parser-shaped blind spots.
status=0
scan_tf_regex 'https?://' || status=$?
case "$status" in
  0)
    echo "ERROR: Connector Authority foundation must not contain HTTP URLs; cite a repository issue number or relative documentation path instead" >&2
    exit 1
    ;;
  1) ;;
  *) exit "$status" ;;
esac

for environment in sandbox prod; do
  backend="${repo_root}/terraform/control/environments/${environment}/backend.tf"
  expected="nhp/${environment}/control/terraform.tfstate"
  if [[ ! -r "$backend" ]]; then
    echo "ERROR: ${environment} control backend is not readable: ${backend}" >&2
    exit 1
  fi

  backend_key=""
  backend_key_count=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^[[:space:]]*key[[:space:]]*=[[:space:]]*\"([^\"]+)\"[[:space:]]*$ ]]; then
      backend_key="${BASH_REMATCH[1]}"
      backend_key_count=$((backend_key_count + 1))
    fi
  done <"$backend"

  if [[ "$backend_key_count" -ne 1 || "$backend_key" != "$expected" ]]; then
    echo "ERROR: ${environment} control backend must use ${expected}" >&2
    exit 1
  fi
done

sandbox_wrapper="${control_dir}/environments/sandbox/main.tf"
prod_wrapper="${control_dir}/environments/prod/main.tf"
if [[ ! -r "$sandbox_wrapper" || ! -r "$prod_wrapper" ]]; then
  echo "ERROR: Connector Authority environment module wrappers must both be readable" >&2
  exit 1
fi
if ! cmp -s "$sandbox_wrapper" "$prod_wrapper"; then
  echo "ERROR: Connector Authority sandbox and prod module wrappers must remain byte-identical" >&2
  exit 1
fi

sandbox_outputs="${control_dir}/environments/sandbox/outputs.tf"
prod_outputs="${control_dir}/environments/prod/outputs.tf"
if [[ ! -r "$sandbox_outputs" || ! -r "$prod_outputs" ]]; then
  echo "ERROR: Connector Authority environment output wrappers must both be readable" >&2
  exit 1
fi
if ! cmp -s "$sandbox_outputs" "$prod_outputs"; then
  echo "ERROR: Connector Authority sandbox and prod output wrappers must remain byte-identical" >&2
  exit 1
fi

echo "Connector Authority foundation contract is clean"
