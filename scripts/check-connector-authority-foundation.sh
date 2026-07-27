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
  # aws_internet_gateway, aws_lb, aws_lb_listener, and aws_route are legitimized
  # by the Connector Hub public UDP edge slice (Step 5): one edge IGW, one public
  # route table with a single 0.0.0.0/0 route to it, and the public UDP-62206 Hub
  # NLB + listener in the public subnets. Like the authority runtime functions
  # they are NOT free here -- they are gated instead by the exact inventory +
  # transition contract in check-control-sandbox-first-apply.py, which admits
  # them only as the exact Hub-edge set and asserts the internet route lives ONLY
  # on the public edge route table (the isolated workload tables stay local-only).
  # aws_lambda_function and aws_lambda_alias are similarly legitimized by the
  # Connector Authority runtime slice. aws_lambda_function_url,
  # aws_egress_only_internet_gateway, aws_nat_gateway, and aws_eip stay forbidden:
  # the authority never exposes a public URL/API Gateway/ALB route, the Hub
  # workers hold no public IP, and the edge needs no NAT or elastic IP.
  aws_lambda_function_url
  aws_nat_gateway
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

  # Three exact replacements are intentional:
  #
  # * a tainted Connector Authority FUNCTION replan recreates a function left
  #   Failed by an earlier partial apply;
  # * the one-time Authority function-SG generation change removes the live
  #   predecessor's inline VPC-CIDR rule. Omitting that rule from configuration
  #   would leave it unmanaged, so the clean SG must replace it;
  # * the one-time Hub NLB source-fence migration MUST replace the NLB and its
  #   listener: AWS cannot add a security group to an NLB created without one.
  #   The NLB is create-before-destroy, but the listener must be
  #   destroy-before-create because AWS forbids one target group from serving
  #   listeners on two load balancers, so each address is admitted only in its
  #   exact action order; the Python convergence checker proves the new
  #   NLB/SG/worker graph.
  #
  # The function-SG generation change also has an exact DEPOSED continuation.
  # Its create_before_destroy replacement created the generation-2 group and
  # repointed every function, but the generation-1 delete could not complete
  # while published function versions still pinned that group to live Lambda
  # ENIs, so Terraform left the predecessor object deposed and pending delete.
  # That single reviewed object is admitted below; deposed deletes are NOT
  # admitted generally. Remove this branch once the object is reaped, together
  # with the deposed sites in the first-apply checker; KEEP the shared
  # legacy_authority_sg_before helper, which the replacement above still uses.
  #
  # Keep the SG admissions self-contained and exact here as well as in the
  # first-apply checker. Any retained/substituted CIDR or any other delete stays
  # destructive.
  destructive_resources="$(jq -r '
    # The exact generation-1 function-SG before-state, shared by the replacement
    # and its deposed continuation so both admissions cannot drift apart. Kept
    # field-for-field in lockstep with _is_exact_legacy_authority_sg_before in
    # the first-apply checker so the two guards agree across languages too.
    def legacy_authority_sg_before:
      .name_prefix == "layerv-nhp-sandbox-control-ca-fn-"
      and .description == (
        "Connector Authority function ENIs; egress to Control dependency "
        + "endpoints only"
      )
      and (.vpc_id | test("^vpc-[0-9a-f]+$"))
      and ((.ingress // []) == [])
      and (
        [.egress[]? | select(
          .description == "HTTPS to Control interface endpoints (KMS) in-VPC"
          and .cidr_blocks == ["10.102.0.0/16"]
          and .ipv6_cidr_blocks == []
          and .prefix_list_ids == []
          and .security_groups == []
          and .self == false
          and .protocol == "tcp"
          and .from_port == 443
          and .to_port == 443
        )] | length
      ) == 1
      and (
        [.egress[]? | select(
          .description == "HTTPS to the DynamoDB gateway endpoint prefix list"
          and .cidr_blocks == []
          and .ipv6_cidr_blocks == []
          and (.prefix_list_ids | length) == 1
          and (.prefix_list_ids[0] | test("^pl-[0-9a-f]+$"))
          and .security_groups == []
          and .self == false
          and .protocol == "tcp"
          and .from_port == 443
          and .to_port == 443
        )] | length
      ) == 1
      and (.egress | length) == 2;

    (.resource_changes[]?, .resource_drift[]?)
    | select(.change.actions | index("delete"))
    | select(
        ((
          (.address | startswith("module.control.aws_lambda_function.authority["))
          and (
            (.change.actions == ["delete", "create"])
            or (.change.actions == ["create", "delete"])
          )
        ) or (
          .address == "module.control.aws_security_group.authority_lambda[0]"
          and .type == "aws_security_group"
          and (.deposed // null) == null
          and .change.actions == ["create", "delete"]
          and .change.replace_paths == [["name_prefix"]]
          and (.change.before | legacy_authority_sg_before)
          and .change.after.name_prefix == "layerv-nhp-sandbox-control-ca-fn-v2-"
          and .change.before.vpc_id == .change.after.vpc_id
          and ((.change.after.ingress // []) == [])
          and ((.change.after.egress // []) == [])
          and .change.after_unknown.ingress == true
          and .change.after_unknown.egress == true
        ) or (
          .address == "module.control.aws_security_group.authority_lambda[0]"
          and .type == "aws_security_group"
          and .mode == "managed"
          and .deposed == "4a2844f4"
          and .change.actions == ["delete"]
          and .change.after == null
          and .change.before.id == "sg-0584cd75da80a2c7d"
          and (.change.before | legacy_authority_sg_before)
        ) or (
          # The one reviewed removal of the detached legacy Connector OTP Redis
          # user (NHP #3362): a net delete, admitted only at its exact reviewed
          # before-state. Kept field-for-field in lockstep with
          # _is_exact_legacy_otp_user_delete in the first-apply checker, which
          # separately refuses to combine it with any other Control change.
          # Remove this branch once the delete is applied, together with the
          # LEGACY_OTP_REDIS_USER_* sites in that checker.
          .address == "module.control.aws_elasticache_user.otp_authority"
          and .type == "aws_elasticache_user"
          and .mode == "managed"
          and (.deposed // null) == null
          and .change.actions == ["delete"]
          and .change.after == null
          and .change.before.user_id == "layerv-nhp-sandbox-control-otp-auth"
          and .change.before.user_name == "layerv-nhp-sandbox-control-otp-auth"
          and .change.before.access_string == (
            "on ~connector:* -@all +@connection +@read +@write +@scripting"
          )
          and .change.before.engine == "redis"
          and ((.change.before.user_group_ids // []) == [])
          and ((.change.before.authentication_mode | length) == 1)
          and .change.before.authentication_mode[0].type == "iam"
          and .change.before.authentication_mode[0].password_count == 0
          and ((.change.before.authentication_mode[0].passwords // []) == [])
        ) or (
          .address == "module.control.aws_lb.hub[0]"
          and .change.actions == ["create", "delete"]
        ) or (
          .address == "module.control.aws_lb_listener.hub[0]"
          and .change.actions == ["delete", "create"]
        )) | not
      )
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

  # The AWS provider marks after_unknown.route=true for a clean route table at
  # CREATE, so a freshly-created edge table has after.route=null and is not
  # flagged. Once the edge is live, a no-op refresh reports the KNOWN route list
  # populated by the standalone aws_route resource -- that reflection is not an
  # inline declaration, so skip unchanged (no-op/read) tables. A real inline
  # route entering on a create/update/replace still surfaces a known non-empty
  # route list and is rejected; and the unconditional lexical source fence above
  # owns authored inline routes on every run regardless of plan action.
  inline_route_tables="$(jq -r '
    (.resource_changes[]?, .resource_drift[]?)
    | select(.type == "aws_route_table" and .change.after != null)
    | select(.change.actions != ["no-op"] and .change.actions != ["read"])
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

# This source guard intentionally pins the temporary Authority-first holdback.
# The reviewed restoration PR must update it and its fixtures to the true-only
# sandbox latch described in the rollout ledger.
require_catalog_materialization_holdback() {
  local variables_file="$1"
  local environment="$2"
  local variable_block

  if ! variable_block="$(
    awk -v name='provisioned_cell_catalog_materialization_enabled' '
      $0 ~ "^[[:space:]]*variable[[:space:]]+\"" name "\"[[:space:]]*\\{[[:space:]]*$" {
        if (seen != 0 || capture != 0) {
          exit 2
        }
        seen = 1
        capture = 1
      }
      capture != 0 {
        print
      }
      capture != 0 && $0 ~ "^}[[:space:]]*$" {
        capture = 0
      }
      END {
        if (seen != 1 || capture != 0) {
          exit 2
        }
      }
    ' "$variables_file"
  )"; then
    echo "ERROR: ${environment} Control variables must declare exactly one closed provisioned-cell materialization gate" >&2
    exit 1
  fi

  local default_count
  local false_default_count
  local condition_count
  local false_condition_count
  default_count="$(grep -E -c \
    '^[[:space:]]*default[[:space:]]*=' <<<"$variable_block" || true)"
  false_default_count="$(grep -E -c \
    '^[[:space:]]*default[[:space:]]*=[[:space:]]*false[[:space:]]*$' \
    <<<"$variable_block" || true)"
  condition_count="$(grep -E -c \
    '^[[:space:]]*condition[[:space:]]*=' <<<"$variable_block" || true)"
  false_condition_count="$(grep -E -c \
    '^[[:space:]]*condition[[:space:]]*=[[:space:]]*!var\.provisioned_cell_catalog_materialization_enabled[[:space:]]*$' \
    <<<"$variable_block" || true)"

  if [[ "$default_count" -ne 1 || "$false_default_count" -ne 1 ||
        "$condition_count" -ne 1 || "$false_condition_count" -ne 1 ]]; then
    echo "ERROR: ${environment} Control variables must hard-lock provisioned-cell catalog materialization false during the Authority-first holdback" >&2
    exit 1
  fi
}

# Both roots compose the same child-module interface. Sandbox may open the
# latch only through the exact-main generated tfvars; production locks both
# inputs dark at the variable boundary.
for environment in sandbox prod; do
  environment_root="${control_dir}/environments/${environment}"
  wrapper_count="$(grep -E -c \
    '^[[:space:]]*authority_runtime_contract_evidence_verified[[:space:]]*=[[:space:]]*var\.authority_runtime_contract_evidence_verified[[:space:]]*$' \
    "${environment_root}/main.tf" || true)"
  if [[ "$wrapper_count" -ne 1 ]]; then
    echo "ERROR: ${environment} Control wrapper must pass the internal evidence latch exactly once from its root variable" >&2
    exit 1
  fi
  catalog_wrapper_count="$(grep -E -c \
    '^[[:space:]]*provisioned_cell_catalog_materialization_enabled[[:space:]]*=[[:space:]]*var\.provisioned_cell_catalog_materialization_enabled[[:space:]]*$' \
    "${environment_root}/main.tf" || true)"
  if [[ "$catalog_wrapper_count" -ne 1 ]]; then
    echo "ERROR: ${environment} Control wrapper must pass the provisioned-cell materialization gate exactly once from its root variable" >&2
    exit 1
  fi
  require_catalog_materialization_holdback \
    "${environment_root}/variables.tf" "$environment"
  # Reject any COMMITTED tfvars in the Control root (a committed *.auto.tfvars /
  # *.auto.tfvars.json would be terraform-auto-loaded and could open the latch),
  # but EXCLUDE the sanctioned exact-main runtime output
  # `authority-runtime.generated.tfvars.json`: the workflow's byte-verifying
  # generator writes it into this root at plan time (it is git-ignored and
  # atomically overwritten every run), so its presence on disk here is expected
  # and is the only supported way to open the sandbox latch (see the comment
  # above). Matching it was a regression from adding the `.json` variants.
  if find "$environment_root" -maxdepth 1 -type f \
    \( -name '*.tfvars' -o -name '*.tfvars.json' \
       -o -name '*.auto.tfvars' -o -name '*.auto.tfvars.json' \) \
    ! -name 'authority-runtime.generated.tfvars.json' -print -quit \
    | grep -q .; then
    echo "ERROR: ${environment} Control root must not commit runtime tfvars" >&2
    exit 1
  fi
done

prod_variables="${control_dir}/environments/prod/variables.tf"
for required in \
  'Production Authority runtime contract must remain null throughout sandbox measurement.' \
  'Production Authority evidence latch must remain false throughout sandbox measurement.'; do
  if ! grep -Fq "$required" "$prod_variables"; then
    echo "ERROR: production Control variables must fail closed: ${required}" >&2
    exit 1
  fi
done

# The deployed Authority image is selected by the reviewed measurement basis,
# never by the publisher-owned SSM parameter. qurl-service's build-and-deploy
# workflow rewrites that parameter on every push to its main, so reading it here
# let an unrelated repository's release invalidate every Control plan the moment
# it published. Forbid the read outright rather than requiring it.
ssm_read_count="$(
  { grep -R -h -E --include='*.tf' \
      'data[[:space:]]+"aws_ssm_parameter"[[:space:]]+"authority_runtime_digest"' \
      "$module_dir" || true; } | wc -l | tr -d ' '
)"
ecr_read_count="$(
  { grep -R -h -E --include='*.tf' \
      'data[[:space:]]+"aws_ecr_image"[[:space:]]+"authority_runtime"' \
      "$module_dir" || true; } | wc -l | tr -d ' '
)"
if [[ "$ssm_read_count" -ne 0 ]]; then
  echo "ERROR: Connector Authority runtime must not read the publisher-owned SSM digest; the reviewed basis selects the deployed image" >&2
  exit 1
fi
if [[ "$ecr_read_count" -ne 1 ]]; then
  echo "ERROR: Connector Authority runtime must declare exactly one conditional ECR digest read" >&2
  exit 1
fi
# The ECR read must resolve the basis digest, which is what proves the reviewed
# pin refers to a real published image.
if ! grep -Fq 'image_digest    = local.authority_contract_global.authority_image_digest' \
  "${module_dir}/ecr.tf"; then
  echo "ERROR: Connector Authority ECR read must resolve the reviewed basis digest" >&2
  exit 1
fi
if ! grep -Fq 'count = local.authority_runtime_contract_enabled ? 1 : 0' \
  "${module_dir}/ecr.tf"; then
  echo "ERROR: Connector Authority runtime ECR read must remain conditional on the verified contract" >&2
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
