#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
checker="${repo_root}/scripts/check-connector-authority-foundation.sh"
fixture_root="$(mktemp -d)"
trap 'rm -rf "$fixture_root"' EXIT

module_dir="${fixture_root}/terraform/modules/connector-authority-foundation"
control_dir="${fixture_root}/terraform/control"
mkdir -p "$module_dir" "${control_dir}/environments/sandbox" "${control_dir}/environments/prod"

write_backend() {
  local environment="$1"
  local key="$2"

  printf '%s\n' \
    'terraform {' \
    '  backend "s3" {' \
    "    key = \"${key}\"" \
    '  }' \
    '}' >"${control_dir}/environments/${environment}/backend.tf"
}

write_clean_fixture() {
  rm -f \
    "${control_dir}/environments/sandbox/"*.tfvars \
    "${control_dir}/environments/sandbox/"*.tfvars.json \
    "${control_dir}/environments/sandbox/"*.auto.tfvars \
    "${control_dir}/environments/sandbox/"*.auto.tfvars.json \
    "${control_dir}/environments/prod/"*.tfvars \
    "${control_dir}/environments/prod/"*.tfvars.json \
    "${control_dir}/environments/prod/"*.auto.tfvars \
    "${control_dir}/environments/prod/"*.auto.tfvars.json
  printf '%s\n' \
    '# Provider documentation belongs outside this zero-HTTP Terraform root.' \
    'resource "aws_vpc" "control" {}' >"${module_dir}/main.tf"
  printf '%s\n' \
    'locals {' \
    '  authority_image_source_permitted = !local.authority_image_tracks_publish || var.environment != "prod"' \
    '}' \
    'locals {' \
    '  identity = (' \
    '    local.authority_image_source_permitted &&' \
    '    true' \
    '  )' \
    '}' \
    'data "aws_ssm_parameter" "authority_image_publish" {' \
    '  count = local.authority_runtime_contract_enabled && local.authority_image_tracks_publish ? 1 : 0' \
    '  name = local.authority_image_digest_parameter_name' \
    '}' \
    'data "aws_ecr_image" "authority_runtime" {' \
    '  count = local.authority_runtime_contract_enabled ? 1 : 0' \
    '  image_digest    = local.authority_runtime_image_digest' \
    '}' >"${module_dir}/ecr.tf"
  printf '%s\n' \
    'module "connector_authority_foundation" {' \
    '  source = "../../../modules/connector-authority-foundation"' \
    '  authority_runtime_contract = var.authority_runtime_contract' \
    '  authority_runtime_contract_evidence_verified     = var.authority_runtime_contract_evidence_verified' \
    '  provisioned_cell_catalog_materialization_enabled = var.provisioned_cell_catalog_materialization_enabled' \
    '}' >"${control_dir}/environments/sandbox/main.tf"
  cp "${control_dir}/environments/sandbox/main.tf" "${control_dir}/environments/prod/main.tf"
  printf '%s\n' \
    'variable "authority_runtime_contract" { default = null }' \
    'variable "authority_runtime_contract_evidence_verified" { default = false }' \
    'variable "provisioned_cell_catalog_materialization_enabled" {' \
    '  default = true' \
    '  validation {' \
    '    condition = var.provisioned_cell_catalog_materialization_enabled' \
    '  }' \
    '}' \
    >"${control_dir}/environments/sandbox/variables.tf"
  printf '%s\n' \
    'variable "authority_runtime_contract" { default = null }' \
    'variable "authority_runtime_contract_evidence_verified" { default = false }' \
    'variable "authority_runtime_functions_enabled" { default = false }' \
    'variable "hub_edge_enabled" { default = false }' \
    'variable "hub_worker_enabled" { default = false }' \
    'variable "provisioned_cell_catalog_materialization_enabled" {' \
    '  default = true' \
    '  validation {' \
    '    condition = var.provisioned_cell_catalog_materialization_enabled' \
    '  }' \
    '}' >"${control_dir}/environments/prod/variables.tf"
  printf '%s\n' \
    'output "vpc_id" {' \
    '  value = module.connector_authority_foundation.vpc_id' \
    '}' >"${control_dir}/environments/sandbox/outputs.tf"
  cp "${control_dir}/environments/sandbox/outputs.tf" "${control_dir}/environments/prod/outputs.tf"
  write_backend sandbox 'nhp/sandbox/control/terraform.tfstate'
  write_backend prod 'nhp/prod/control/terraform.tfstate'
}

expect_failure() {
  local expected="$1"
  shift

  local output
  if output=$("$@" 2>&1); then
    echo "ERROR: command unexpectedly passed: $*" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    echo "ERROR: failure did not contain '$expected':" >&2
    echo "$output" >&2
    exit 1
  fi
}

expect_success() {
  local output
  if ! output=$("$@" 2>&1); then
    echo "ERROR: command unexpectedly failed: $*" >&2
    echo "$output" >&2
    exit 1
  fi
}

# Exercise the checked-in wrappers before the synthetic fixture matrix. This
# catches Terraform-fmt alignment or other real-source drift that a simplified
# fixture could otherwise mask.
NHP_REPO_ROOT="$repo_root" "$checker" >/dev/null

# The clean fixture deliberately uses Terraform-fmt alignment around "=". The
# source guard must accept that whitespace while keeping the lhs/rhs exact.
write_clean_fixture
NHP_REPO_ROOT="$fixture_root" "$checker" >/dev/null

plan_json="${fixture_root}/control.tfplan.json"
printf '%s\n' '{"resource_changes":[]}' >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

printf '%s\n' '{"resource_changes":[{"address":"aws_vpc.control","type":"aws_vpc","change":{"actions":["update"],"after":{"tags":{"Purpose":"dark"}}}}]}' >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

printf '%s\n' '{"resource_drift":[{"address":"aws_iam_role.authority_publisher","type":"aws_iam_role","change":{"actions":["update"],"after":{"inline_policy":[]}}}]}' >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

# The runtime slice legitimizes aws_lambda_function/aws_lambda_alias; the exact
# inventory/transition contract in check-control-sandbox-first-apply.py gates
# them. This lexical fence therefore admits them in both source and plan JSON.
printf '%s\n' '{"resource_changes":[{"address":"module.control.aws_lambda_function.authority[\"layerv-nhp-sandbox-ca-ia\"]","type":"aws_lambda_function","change":{"actions":["create"],"after":{"function_name":"layerv-nhp-sandbox-ca-ia"}}}]}' >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

printf '%s\n' '{"resource_changes":[{"address":"module.control.aws_lambda_alias.authority[\"layerv-nhp-sandbox-ca-ia:blue\"]","type":"aws_lambda_alias","change":{"actions":["create"],"after":{"name":"blue"}}}]}' >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

# A public Lambda URL surface stays forbidden (no API Gateway / function URL / ALB).
printf '%s\n' '{"resource_changes":[{"address":"aws_lambda_function_url.forbidden","type":"aws_lambda_function_url","change":{"actions":["create"],"after":{"function_name":"forbidden"}}}]}' >"$plan_json"
expect_failure 'plan contains aws_lambda_function_url' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' '{"resource_changes":[{"address":"aws_vpc.removed","type":"aws_vpc","change":{"actions":["delete"],"after":null}}]}' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' '{"resource_changes":[{"address":"aws_vpc.replaced","type":"aws_vpc","change":{"actions":["delete","create"],"after":{"cidr_block":"10.102.0.0/16"}}}]}' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# The one-time generation-2 Authority SG replacement is admitted only for the
# exact observed legacy predecessor and an empty replacement. This is the
# deliberate revocation path for the predecessor's VPC-CIDR inline rule.
replacement_plan='{"resource_changes":[{"address":"module.control.aws_security_group.authority_lambda[0]","type":"aws_security_group","change":{"actions":["create","delete"],"before":{"name_prefix":"layerv-nhp-sandbox-control-ca-fn-","description":"Connector Authority function ENIs; egress to Control dependency endpoints only","vpc_id":"vpc-abc123","ingress":[],"egress":[{"description":"HTTPS to Control interface endpoints (KMS) in-VPC","cidr_blocks":["10.102.0.0/16"],"ipv6_cidr_blocks":[],"prefix_list_ids":[],"security_groups":[],"self":false,"protocol":"tcp","from_port":443,"to_port":443},{"description":"HTTPS to the DynamoDB gateway endpoint prefix list","cidr_blocks":[],"ipv6_cidr_blocks":[],"prefix_list_ids":["pl-abc123"],"security_groups":[],"self":false,"protocol":"tcp","from_port":443,"to_port":443}]},"after":{"name_prefix":"layerv-nhp-sandbox-control-ca-fn-v2-","vpc_id":"vpc-abc123"},"after_unknown":{"ingress":true,"egress":true},"replace_paths":[["name_prefix"]]}}]}'
printf '%s\n' "$replacement_plan" >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

# Each mutation below starts from the admitted fixture above, so every case
# proves exactly the one field it changes.
printf '%s\n' "$replacement_plan" | jq '.resource_changes[0].change.before.egress[0].cidr_blocks = ["0.0.0.0/0"]' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# The shared before-state proof is kept in lockstep with the first-apply
# checker: a repurposed group description or a malformed VPC id is not the
# reviewed generation-1 predecessor.
printf '%s\n' "$replacement_plan" | jq '.resource_changes[0].change.before.description = "repurposed"' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$replacement_plan" | jq '.resource_changes[0].change.before.vpc_id = "not-a-vpc"' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# The DEPOSED continuation of that same replacement: the generation-2 group is
# live and every function already points at it, but the generation-1 delete
# could not complete while published function versions still pinned it, so the
# predecessor stayed deposed and pending delete. Admitted only as the exact
# reviewed object -- its deposed key, its live id, and the same generation-1
# before-state as the replacement above.
deposed_plan='{"resource_changes":[{"address":"module.control.aws_security_group.authority_lambda[0]","type":"aws_security_group","mode":"managed","deposed":"4a2844f4","change":{"actions":["delete"],"before":{"id":"sg-0584cd75da80a2c7d","name_prefix":"layerv-nhp-sandbox-control-ca-fn-","description":"Connector Authority function ENIs; egress to Control dependency endpoints only","vpc_id":"vpc-abc123","ingress":[],"egress":[{"description":"HTTPS to Control interface endpoints (KMS) in-VPC","cidr_blocks":["10.102.0.0/16"],"ipv6_cidr_blocks":[],"prefix_list_ids":[],"security_groups":[],"self":false,"protocol":"tcp","from_port":443,"to_port":443},{"description":"HTTPS to the DynamoDB gateway endpoint prefix list","cidr_blocks":[],"ipv6_cidr_blocks":[],"prefix_list_ids":["pl-abc123"],"security_groups":[],"self":false,"protocol":"tcp","from_port":443,"to_port":443}]},"after":null}}]}'
printf '%s\n' "$deposed_plan" >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

# A DIFFERENT deposed key is a different, unreviewed object.
printf '%s\n' "$deposed_plan" | jq '.resource_changes[0].deposed = "deadbeef"' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# A different live id under the reviewed key is not the reviewed object either.
printf '%s\n' "$deposed_plan" | jq '.resource_changes[0].change.before.id = "sg-0000000000000000f"' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# The admission is pinned to the generation-1 before-state: a widened egress
# CIDR, an extra egress rule, or a retained ingress rule all stay destructive.
printf '%s\n' "$deposed_plan" | jq '.resource_changes[0].change.before.egress[0].cidr_blocks = ["0.0.0.0/0"]' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$deposed_plan" | jq '.resource_changes[0].change.before.egress += [{"description":"extra","cidr_blocks":["10.0.0.0/8"],"ipv6_cidr_blocks":[],"prefix_list_ids":[],"security_groups":[],"self":false,"protocol":"tcp","from_port":443,"to_port":443}]' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$deposed_plan" | jq '.resource_changes[0].change.before.ingress = [{"description":"retained","cidr_blocks":["10.102.0.0/16"],"ipv6_cidr_blocks":[],"prefix_list_ids":[],"security_groups":[],"self":false,"protocol":"tcp","from_port":443,"to_port":443}]' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$deposed_plan" | jq '.resource_changes[0].change.before.description = "repurposed"' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$deposed_plan" | jq '.resource_changes[0].change.before.vpc_id = "not-a-vpc"' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# The one reviewed removal of the detached legacy Connector OTP Redis user
# (NHP #3362): a net delete admitted only at its exact reviewed before-state.
legacy_otp_user_plan='{"resource_changes":[{"address":"module.control.aws_elasticache_user.otp_authority","type":"aws_elasticache_user","mode":"managed","change":{"actions":["delete"],"before":{"user_id":"layerv-nhp-sandbox-control-otp-auth","user_name":"layerv-nhp-sandbox-control-otp-auth","access_string":"on ~connector:* -@all +@connection +@read +@write +@scripting","engine":"redis","user_group_ids":[],"authentication_mode":[{"type":"iam","password_count":0,"passwords":[]}]},"after":null}}]}'
printf '%s\n' "$legacy_otp_user_plan" >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

# A widened ACL means the user drifted; review it rather than destroying it.
printf '%s\n' "$legacy_otp_user_plan" | jq '.resource_changes[0].change.before.access_string = "on ~* +@all"' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# A password-backed identity means a long-lived Redis credential still exists.
printf '%s\n' "$legacy_otp_user_plan" | jq '.resource_changes[0].change.before.authentication_mode = [{"type":"password","password_count":1,"passwords":[]}]' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# Still attached to a user group is not the detached user this cleanup reviewed.
printf '%s\n' "$legacy_otp_user_plan" | jq '.resource_changes[0].change.before.user_group_ids = ["layerv-nhp-sandbox-control-otp-users"]' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# The admission is pinned to this one address: no other Redis user may be
# deleted on the strength of the same before-state shape.
printf '%s\n' "$legacy_otp_user_plan" | jq '.resource_changes[0].address = "module.control.aws_elasticache_user.otp_issuer"' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# A deposed object at that address is never the reviewed delete.
printf '%s\n' "$legacy_otp_user_plan" | jq '.resource_changes[0].deposed = "4a2844f4"' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# Deposed deletes are NOT admitted generally: the same exact shape at any other
# address, or any other deposed resource, stays destructive.
printf '%s\n' "$deposed_plan" | jq '.resource_changes[0].address = "module.control.aws_security_group.interface_endpoints"' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' '{"resource_changes":[{"address":"module.control.aws_vpc.control","type":"aws_vpc","mode":"managed","deposed":"4a2844f4","change":{"actions":["delete"],"before":{"id":"vpc-abc123"},"after":null}}]}' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# A deposed object must not be able to satisfy the REPLACEMENT admission.
printf '%s\n' '{"resource_changes":[{"address":"module.control.aws_security_group.authority_lambda[0]","type":"aws_security_group","mode":"managed","deposed":"4a2844f4","change":{"actions":["create","delete"],"before":{"name_prefix":"layerv-nhp-sandbox-control-ca-fn-","vpc_id":"vpc-abc123","ingress":[],"egress":[{"description":"HTTPS to Control interface endpoints (KMS) in-VPC","cidr_blocks":["10.102.0.0/16"],"ipv6_cidr_blocks":[],"prefix_list_ids":[],"security_groups":[],"self":false,"protocol":"tcp","from_port":443,"to_port":443},{"description":"HTTPS to the DynamoDB gateway endpoint prefix list","cidr_blocks":[],"ipv6_cidr_blocks":[],"prefix_list_ids":["pl-abc123"],"security_groups":[],"self":false,"protocol":"tcp","from_port":443,"to_port":443}]},"after":{"name_prefix":"layerv-nhp-sandbox-control-ca-fn-v2-","vpc_id":"vpc-abc123"},"after_unknown":{"ingress":true,"egress":true},"replace_paths":[["name_prefix"]]}}]}' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# A tainted Connector Authority hub FUNCTION replace (delete+create) is the
# authority-runtime-slice-retry recovery for a Failed function, not a teardown.
printf '%s\n' '{"resource_changes":[{"address":"module.control.aws_lambda_function.authority[\"layerv-nhp-sandbox-ca-ia\"]","type":"aws_lambda_function","change":{"actions":["delete","create"],"after":{"function_name":"layerv-nhp-sandbox-ca-ia"}}}]}' >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

# The two exact attended-proof provisioned-concurrency replacements recover
# configs tainted when the old image failed Lambda initialization. The shell
# fence owns only address/type/action admission; the workflow's Python checker
# proves their complete before/after state and the accompanying image update.
proof_pc_plan='{"resource_changes":[{"address":"module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-pm\"]","type":"aws_lambda_provisioned_concurrency_config","mode":"managed","change":{"actions":["delete","create"],"before":{"function_name":"layerv-nhp-sandbox-ca-pm","id":"layerv-nhp-sandbox-ca-pm,blue","provisioned_concurrent_executions":1,"qualifier":"blue","skip_destroy":false,"timeouts":null},"after":{"function_name":"layerv-nhp-sandbox-ca-pm","provisioned_concurrent_executions":1,"qualifier":"blue","skip_destroy":false,"timeouts":null},"after_unknown":{"id":true}}}]}'
printf '%s\n' "$proof_pc_plan" >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

printf '%s\n' "$proof_pc_plan" \
  | jq '.resource_changes[0].address = "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-pcr\"]"' \
  >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

# No other provisioned-concurrency config, action order, deposed object, or
# resource type can borrow the recovery exception.
printf '%s\n' "$proof_pc_plan" \
  | jq '.resource_changes[0].address = "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-lrt\"]"' \
  >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$proof_pc_plan" \
  | jq '.resource_changes[0].change.actions = ["create", "delete"]' \
  >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$proof_pc_plan" \
  | jq '.resource_changes[0].deposed = "4a2844f4"' \
  >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$proof_pc_plan" \
  | jq '.resource_changes[0].type = "aws_lambda_function"' \
  >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# The one exact failed proof-policy prepare recovery may replace the three
# inactive green IA/RA/ICR allocations. Its complete 12-change envelope keeps
# this from becoming a general provisioned-concurrency replacement exception.
proof_prepare_recovery_plan="$(
  jq -n '
    def change($address; $type; $actions; $before; $after; $after_unknown):
      {
        address: $address,
        type: $type,
        mode: "managed",
        change: {
          actions: $actions,
          before: $before,
          after: $after,
          after_unknown: $after_unknown
        }
      };
    def pc_replace($name):
      change(
        "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-\($name)\"]";
        "aws_lambda_provisioned_concurrency_config";
        ["delete", "create"];
        {
          function_name: "layerv-nhp-sandbox-ca-\($name)",
          id: "layerv-nhp-sandbox-ca-\($name),green",
          provisioned_concurrent_executions: 0,
          qualifier: "green",
          region: "us-east-2",
          skip_destroy: false,
          timeouts: null
        };
        {
          function_name: "layerv-nhp-sandbox-ca-\($name)",
          provisioned_concurrent_executions: 2,
          qualifier: "green",
          region: "us-east-2",
          skip_destroy: false,
          timeouts: null
        };
        {id: true}
      ) + {action_reason: "replace_because_tainted"};
    def pm_create:
      change(
        "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-pm\"]";
        "aws_lambda_provisioned_concurrency_config";
        ["create"];
        null;
        {
          function_name: "layerv-nhp-sandbox-ca-pm",
          provisioned_concurrent_executions: 1,
          qualifier: "green",
          region: "us-east-2",
          skip_destroy: false,
          timeouts: null
        };
        {id: true}
      );

    {
      resource_changes: (
        (
          ["ia", "icr", "pm", "ra"]
          | map(
              change(
                "module.control.aws_lambda_alias.authority[\"layerv-nhp-sandbox-ca-\(.):green\"]";
                "aws_lambda_alias";
                ["update"];
                {};
                {};
                {}
              )
            )
        )
        + (
          ["ia", "icr", "pm", "ra"]
          | map(
              change(
                "module.control.aws_lambda_function.authority[\"layerv-nhp-sandbox-ca-\(.)\"]";
                "aws_lambda_function";
                ["update"];
                {};
                {};
                {}
              )
            )
        )
        + (["ia", "icr", "ra"] | map(pc_replace(.)))
        + [pm_create]
      ),
      resource_drift: []
    }
  '
)"
printf '%s\n' "$proof_prepare_recovery_plan" >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

# The PR configuration gate plans with -refresh=false, so its exact tainted
# replacements read the configured state value 2 rather than the live failed
# value 0. Both complete envelopes are reviewed; a mixed basis is not.
printf '%s\n' "$proof_prepare_recovery_plan" \
  | jq '(.resource_changes[] | select(.address | contains("authority_proof_standby")) | select(.change.actions == ["delete", "create"]) | .change.before.provisioned_concurrent_executions) = 2' \
  >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

printf '%s\n' "$proof_prepare_recovery_plan" \
  | jq '(.resource_changes[] | select(.address | contains("authority_proof_standby[\"layerv-nhp-sandbox-ca-ia\"]")) | .change.before.provisioned_concurrent_executions) = 2' \
  >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$proof_prepare_recovery_plan" \
  | jq '.resource_changes |= reverse' \
  >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

printf '%s\n' "$proof_prepare_recovery_plan" \
  | jq '.resource_changes += [{"address":"module.control.aws_iam_role.unchanged","type":"aws_iam_role","mode":"managed","change":{"actions":["no-op"],"before":{},"after":{},"after_unknown":{}}}]' \
  >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

printf '%s\n' "$proof_prepare_recovery_plan" \
  | jq '.resource_changes += [{"address":"module.control.aws_iam_role.smuggled","type":"aws_iam_role","mode":"managed","change":{"actions":["update"],"before":{},"after":{},"after_unknown":{}}}]' \
  >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$proof_prepare_recovery_plan" \
  | jq 'del(.resource_changes[] | select(.address == "module.control.aws_lambda_alias.authority[\"layerv-nhp-sandbox-ca-pm:green\"]"))' \
  >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$proof_prepare_recovery_plan" \
  | jq '(.resource_changes[] | select(.address | contains("authority_proof_standby[\"layerv-nhp-sandbox-ca-ia\"]")) | .change.after.provisioned_concurrent_executions) = 3' \
  >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$proof_prepare_recovery_plan" \
  | jq '(.resource_changes[] | select(.address | contains("authority_proof_standby[\"layerv-nhp-sandbox-ca-ia\"]")) | .change.before.id) = "wrong,green"' \
  >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$proof_prepare_recovery_plan" \
  | jq '(.resource_changes[] | select(.address | contains("authority_proof_standby[\"layerv-nhp-sandbox-ca-ia\"]")) | .change.before.extra) = true' \
  >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$proof_prepare_recovery_plan" \
  | jq '(.resource_changes[] | select(.address | contains("authority_proof_standby[\"layerv-nhp-sandbox-ca-ia\"]")) | .action_reason) = null' \
  >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$proof_prepare_recovery_plan" \
  | jq '(.resource_changes[] | select(.address | contains("authority_proof_standby[\"layerv-nhp-sandbox-ca-ia\"]")) | .mode) = "data"' \
  >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$proof_prepare_recovery_plan" \
  | jq '.resource_drift = [{"address":"aws_vpc.smuggled","type":"aws_vpc","mode":"managed","change":{"actions":["delete"],"before":{},"after":null}}]' \
  >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' "$proof_prepare_recovery_plan" \
  | jq '.resource_drift = {}' \
  >"$plan_json"
expect_failure 'resource_drift must be an array when present' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# A PURE delete of an authority function (not a replace) is still destructive.
printf '%s\n' '{"resource_changes":[{"address":"module.control.aws_lambda_function.authority[\"layerv-nhp-sandbox-ca-ia\"]","type":"aws_lambda_function","change":{"actions":["delete"],"after":null}}]}' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# The source-fence migration creates the replacement NLB first, but must remove
# the old listener before attaching the same target group to the new NLB.
printf '%s\n' '{"resource_changes":[{"address":"module.control.aws_lb.hub[0]","type":"aws_lb","change":{"actions":["create","delete"],"after":{"name":"layerv-nhp-sandbox-control-hub-edge"}}}]}' >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

printf '%s\n' '{"resource_changes":[{"address":"module.control.aws_lb_listener.hub[0]","type":"aws_lb_listener","change":{"actions":["delete","create"],"after":{"port":62206,"protocol":"UDP"}}}]}' >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

# Reversing either exact lifecycle order is not the reviewed migration.
printf '%s\n' '{"resource_changes":[{"address":"module.control.aws_lb.hub[0]","type":"aws_lb","change":{"actions":["delete","create"],"after":{"name":"layerv-nhp-sandbox-control-hub-edge"}}}]}' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' '{"resource_changes":[{"address":"module.control.aws_lb_listener.hub[0]","type":"aws_lb_listener","change":{"actions":["create","delete"],"after":{"port":62206,"protocol":"UDP"}}}]}' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# A Hub image deploy replaces the immutable ECS task definition. The shell
# destructive-action fence delegates this one exact shape to the authoritative
# Python validator; it must not maintain a weaker duplicate in jq.
hub_worker_plan="$(
  jq -n \
    --arg old_image '767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-hub@sha256:7777777777777777777777777777777777777777777777777777777777777777' \
    --arg new_image '767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-hub@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' \
    '{
      resource_changes: [{
        address: "module.control.aws_ecs_task_definition.hub[0]",
        type: "aws_ecs_task_definition",
        mode: "managed",
        change: {
          actions: ["delete", "create"],
          before: {
            family: "hub",
            cpu: "512",
            memory: "1024",
            execution_role_arn: "arn:aws:iam::767397897469:role/hub-exec",
            task_role_arn: "arn:aws:iam::767397897469:role/hub-task",
            container_definitions: ([{
              name: "hub",
              image: $old_image,
              essential: true,
              portMappings: [{containerPort: 62206}]
            }, {
              name: "hub-init",
              image: $old_image,
              essential: false
            }] | tojson),
            enable_fault_injection: false,
            ipc_mode: "",
            pid_mode: "",
            volume: [{
              name: "hub-etc",
              configure_at_launch: false,
              docker_volume_configuration: [],
              efs_volume_configuration: [],
              fsx_windows_file_server_volume_configuration: [],
              host_path: "",
              s3files_volume_configuration: []
            }],
            arn: "arn:aws:ecs:us-east-2:767397897469:task-definition/hub:1",
            arn_without_revision: "arn:aws:ecs:us-east-2:767397897469:task-definition/hub",
            id: "hub",
            revision: 1,
            tags_all: {}
          },
          after: {
            family: "hub",
            cpu: "512",
            memory: "1024",
            execution_role_arn: "arn:aws:iam::767397897469:role/hub-exec",
            task_role_arn: "arn:aws:iam::767397897469:role/hub-task",
            container_definitions: ([{
              name: "hub",
              image: $new_image,
              essential: true,
              portMappings: [{containerPort: 62206}]
            }, {
              name: "hub-init",
              image: $new_image,
              essential: false
            }] | tojson),
            ipc_mode: null,
            pid_mode: null,
            volume: [{
              name: "hub-etc",
              docker_volume_configuration: [],
              efs_volume_configuration: [],
              fsx_windows_file_server_volume_configuration: [],
              host_path: "",
              s3files_volume_configuration: []
            }],
            tags_all: {}
          },
          after_unknown: {
            arn: true,
            arn_without_revision: true,
            id: true,
            revision: true,
            enable_fault_injection: true,
            volume: [{
              configure_at_launch: true,
              docker_volume_configuration: [],
              efs_volume_configuration: [],
              fsx_windows_file_server_volume_configuration: [],
              s3files_volume_configuration: []
            }]
          },
          replace_paths: [["container_definitions"]]
        }
      }]
    }'
)"
printf '%s\n' "$hub_worker_plan" >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

# Same repository name in a foreign registry is not the reviewed artifact.
printf '%s\n' "$hub_worker_plan" \
  | jq '.resource_changes[0].change.after.container_definitions |= (fromjson | .[0].image |= sub("767397897469"; "000000000000") | tojson)' \
    >"$plan_json"
expect_failure 'failed its exact image-only contract' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# The observed Terraform lifecycle is destroy then create; reversing it is a
# different transition and must remain destructive.
printf '%s\n' "$hub_worker_plan" \
  | jq '.resource_changes[0].change.actions = ["create", "delete"]' \
    >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# A second destructive change prevents the replacement from borrowing this lane.
printf '%s\n' "$hub_worker_plan" \
  | jq '.resource_changes += [{"address":"aws_vpc.smuggled","type":"aws_vpc","mode":"managed","change":{"actions":["delete","create"],"before":{},"after":{}}}]' \
    >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' '{"resource_changes":[{"address":"aws_route_table.isolated[0]","type":"aws_route_table","change":{"actions":["create"],"after":{"route":[]},"after_unknown":{"route":true}}}]}' >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

printf '%s\n' '{"resource_changes":[{"address":"aws_route_table.isolated[0]","type":"aws_route_table","change":{"actions":["create"],"after":{"route":[{"cidr_block":"0.0.0.0/0","network_interface_id":"eni-123"}]},"after_unknown":{"route":[]}}}]}' >"$plan_json"
expect_failure 'plan contains inline route declarations' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# A live public-edge route table on a no-op refresh reports the KNOWN route list
# populated by the standalone aws_route resource; that reflection is not an
# inline declaration and must not be flagged. Regression: pre-fix this
# false-positived on every plan once slice 5a's edge went live.
printf '%s\n' '{"resource_changes":[{"address":"module.control.aws_route_table.hub_public[0]","type":"aws_route_table","change":{"actions":["no-op"],"after":{"route":[{"cidr_block":"0.0.0.0/0","gateway_id":"igw-abc"}]},"after_unknown":{"route":false}}}]}' >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

printf '%s\n' '{"format_version":"1.2"}' >"$plan_json"
expect_failure 'must contain a resource_changes array or non-empty resource_drift array' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' '{"resource_changes":null,"resource_drift":[{"address":"aws_iam_role.authority_publisher","type":"aws_iam_role","change":{"actions":["update"]}}]}' >"$plan_json"
expect_failure 'resource_changes must be an array' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# Runtime-slice resource types are admitted in source; a public URL surface is not.
printf '%s\n' 'resource "aws_lambda_function" "authority" {}' >>"${module_dir}/main.tf"
printf '%s\n' 'resource "aws_lambda_alias" "authority" {}' >>"${module_dir}/main.tf"
NHP_REPO_ROOT="$fixture_root" "$checker" >/dev/null

write_clean_fixture
printf '%s\n' 'resource "aws_lambda_function_url" "forbidden" {}' >>"${module_dir}/main.tf"
expect_failure 'must not declare aws_lambda_function_url' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
printf '%s\n' 'resource "aws_egress_only_internet_gateway" "forbidden" {}' >>"${module_dir}/main.tf"
expect_failure 'must not declare aws_egress_only_internet_gateway' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
printf '%s\n' 'resource "aws_default_route_table" "forbidden" {}' >>"${module_dir}/main.tf"
expect_failure 'must not declare aws_default_route_table' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
printf '%s\n' 'resource "aws_route_table" "forbidden" { route { cidr_block = "0.0.0.0/0" } }' >>"${module_dir}/main.tf"
expect_failure 'must not declare inline route blocks or route attributes' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
printf '%s\n' 'resource "aws_route_table" "forbidden" { route = [{ cidr_block = "0.0.0.0/0" }] }' >>"${module_dir}/main.tf"
expect_failure 'must not declare inline route blocks or route attributes' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
printf '%s\n' 'endpoint = "https://bootstrap.example.test"' >>"${module_dir}/main.tf"
expect_failure 'must not contain HTTP URLs; cite a repository issue number or relative documentation path instead' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
printf '%s\n' '# https://docs.example.test is intentionally rejected too' >>"${module_dir}/main.tf"
expect_failure 'must not contain HTTP URLs; cite a repository issue number or relative documentation path instead' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
write_backend sandbox 'nhp/sandbox/wrong/terraform.tfstate'
expect_failure 'sandbox control backend must use' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
printf '%s\n' '# unintended environment drift' >>"${control_dir}/environments/prod/main.tf"
expect_failure 'module wrappers must remain byte-identical' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
sed -E -i.bak \
  '/^[[:space:]]*authority_runtime_contract_evidence_verified[[:space:]]*=[[:space:]]*var\.authority_runtime_contract_evidence_verified[[:space:]]*$/d' \
  "${control_dir}/environments/sandbox/main.tf"
rm "${control_dir}/environments/sandbox/main.tf.bak"
cp "${control_dir}/environments/sandbox/main.tf" "${control_dir}/environments/prod/main.tf"
expect_failure 'must pass the internal evidence latch exactly once' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
sed -E -i.bak \
  '/^[[:space:]]*provisioned_cell_catalog_materialization_enabled[[:space:]]*=[[:space:]]*var\.provisioned_cell_catalog_materialization_enabled[[:space:]]*$/d' \
  "${control_dir}/environments/sandbox/main.tf"
rm "${control_dir}/environments/sandbox/main.tf.bak"
cp "${control_dir}/environments/sandbox/main.tf" "${control_dir}/environments/prod/main.tf"
expect_failure 'must pass the provisioned-cell materialization gate exactly once' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
for environment in sandbox prod; do
  printf '%s\n' \
    '  provisioned_cell_catalog_materialization_enabled = var.provisioned_cell_catalog_materialization_enabled' \
    >>"${control_dir}/environments/${environment}/main.tf"
done
expect_failure 'must pass the provisioned-cell materialization gate exactly once' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
sed -i.bak \
  '/^variable "provisioned_cell_catalog_materialization_enabled" {$/,/^}$/d' \
  "${control_dir}/environments/sandbox/variables.tf"
rm "${control_dir}/environments/sandbox/variables.tf.bak"
expect_failure 'sandbox Control variables must declare exactly one closed provisioned-cell materialization gate' \
  env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
printf '%s\n' \
  'variable "provisioned_cell_catalog_materialization_enabled" {' \
  '  default = true' \
  '  validation {' \
  '    condition = var.provisioned_cell_catalog_materialization_enabled' \
  '  }' \
  '}' >>"${control_dir}/environments/sandbox/variables.tf"
expect_failure 'sandbox Control variables must declare exactly one closed provisioned-cell materialization gate' \
  env NHP_REPO_ROOT="$fixture_root" "$checker"

# The restoration pins opposite polarities per environment: sandbox owns the two
# reviewed rows (true-only latch), production stays dark (false-only latch).
# Flipping either half of either latch -- including flipping one environment to
# the OTHER environment's pinned polarity -- must fail closed.
for environment in sandbox prod; do
  # Both roots now latch materialization TRUE: sandbox owns its two reviewed
  # rows, production owns the review-pinned cell0 row. Removing a live catalog
  # row is a drain/migrate procedure, not an input flip, in either environment.
  expected='true'
  wrong='false'
  condition_flip='s/condition = var\./condition = !var./'

  write_clean_fixture
  sed -i.bak \
    "/variable \"provisioned_cell_catalog_materialization_enabled\"/,/^}\$/s/  default = ${expected}/  default = ${wrong}/" \
    "${control_dir}/environments/${environment}/variables.tf"
  rm "${control_dir}/environments/${environment}/variables.tf.bak"
  expect_failure "${environment} Control variables must hard-lock provisioned-cell catalog materialization ${expected}" \
    env NHP_REPO_ROOT="$fixture_root" "$checker"

  write_clean_fixture
  sed -i.bak \
    "/variable \"provisioned_cell_catalog_materialization_enabled\"/,/^}\$/${condition_flip}" \
    "${control_dir}/environments/${environment}/variables.tf"
  rm "${control_dir}/environments/${environment}/variables.tf.bak"
  expect_failure "${environment} Control variables must hard-lock provisioned-cell catalog materialization ${expected}" \
    env NHP_REPO_ROOT="$fixture_root" "$checker"
done

write_clean_fixture
printf '%s\n' '{}' >"${control_dir}/environments/sandbox/unreviewed.auto.tfvars"
expect_failure 'must not commit runtime tfvars' env NHP_REPO_ROOT="$fixture_root" "$checker"

# The sanctioned exact-main runtime output authority-runtime.generated.tfvars.json
# is written into the Control root by the workflow generator at plan time and is
# the ONLY supported way to open the sandbox latch — it must be ALLOWED even
# though it matches *.tfvars.json. (The guard previously matched it, which broke
# the enablement plan.)
write_clean_fixture
printf '%s\n' '{}' >"${control_dir}/environments/sandbox/authority-runtime.generated.tfvars.json"
expect_success env NHP_REPO_ROOT="$fixture_root" "$checker"

# Any OTHER committed *.tfvars.json / *.auto.tfvars.json is still rejected —
# Terraform auto-loads it and it could open the latch, so Finding 1 is preserved.
write_clean_fixture
printf '%s\n' '{}' >"${control_dir}/environments/sandbox/evil.auto.tfvars.json"
expect_failure 'must not commit runtime tfvars' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
printf '%s\n' '{}' >"${control_dir}/environments/sandbox/evil.tfvars.json"
expect_failure 'must not commit runtime tfvars' env NHP_REPO_ROOT="$fixture_root" "$checker"

# Production Control accepts a real runtime contract now, so the fail-closed
# property is no longer "a validation rejects every open value" — it is that
# every gate DEFAULTS closed, so only the reviewed production dispatch can open
# one. Mutate each gate's default open in turn and require the checker to catch
# it; a gate that is simply absent must also fail.
for gate_case in \
  'authority_runtime_contract:null:"opened"' \
  'authority_runtime_contract_evidence_verified:false:true' \
  'authority_runtime_functions_enabled:false:true' \
  'hub_edge_enabled:false:true' \
  'hub_worker_enabled:false:true'; do
  gate_name="${gate_case%%:*}"
  gate_rest="${gate_case#*:}"
  gate_closed="${gate_rest%%:*}"
  gate_open="${gate_rest#*:}"

  write_clean_fixture
  sed -i.bak \
    "s/variable \"${gate_name}\" { default = ${gate_closed} }/variable \"${gate_name}\" { default = ${gate_open} }/" \
    "${control_dir}/environments/prod/variables.tf"
  rm "${control_dir}/environments/prod/variables.tf.bak"
  expect_failure "production Control gate ${gate_name} must fail closed" \
    env NHP_REPO_ROOT="$fixture_root" "$checker"

  write_clean_fixture
  sed -i.bak "/variable \"${gate_name}\" {/d" \
    "${control_dir}/environments/prod/variables.tf"
  rm "${control_dir}/environments/prod/variables.tf.bak"
  expect_failure "production Control variables must declare ${gate_name}" \
    env NHP_REPO_ROOT="$fixture_root" "$checker"
done

write_clean_fixture
# Remove only the ECR block; both reads share ecr.tf, and deleting the file
# would trip the publish-read check first and prove nothing about this one.
sed -i.bak '/data "aws_ecr_image" "authority_runtime"/,+3d' "${module_dir}/ecr.tf"
rm "${module_dir}/ecr.tf.bak"
expect_failure 'must declare exactly one conditional ECR digest read' env NHP_REPO_ROOT="$fixture_root" "$checker"

# Dropping the publish read entirely would silently strip an environment's
# ability to track main.
write_clean_fixture
sed -i.bak '/data "aws_ssm_parameter" "authority_image_publish"/,+3d' "${module_dir}/ecr.tf"
rm "${module_dir}/ecr.tf.bak"
expect_failure 'exactly one publish-parameter read' env NHP_REPO_ROOT="$fixture_root" "$checker"

# Ungating the publish read would make a pinned contract perform a
# publisher-owned read it has no business performing.
write_clean_fixture
sed -i.bak 's#count = local.authority_runtime_contract_enabled \&\& local.authority_image_tracks_publish ? 1 : 0#count = local.authority_runtime_contract_enabled ? 1 : 0#' \
  "${module_dir}/ecr.tf"
rm "${module_dir}/ecr.tf.bak"
expect_failure 'gated on the contract AND the publish_parameter source' env NHP_REPO_ROOT="$fixture_root" "$checker"

# Reading the managed resource's attribute instead of the known local defers the
# read to apply, and a digest unknown at plan cannot be gated at plan.
write_clean_fixture
sed -i.bak 's#name = local.authority_image_digest_parameter_name#name = aws_ssm_parameter.authority_image_digest.name#' \
  "${module_dir}/ecr.tf"
rm "${module_dir}/ecr.tf.bak"
expect_failure 'known parameter-name local' env NHP_REPO_ROOT="$fixture_root" "$checker"

# The ECR read must resolve whatever the declared source produced.
write_clean_fixture
sed -i.bak 's#image_digest    = local.authority_runtime_image_digest#image_digest    = "sha256:deadbeef"#' \
  "${module_dir}/ecr.tf"
rm "${module_dir}/ecr.tf.bak"
expect_failure 'ECR read must resolve the source-selected digest' env NHP_REPO_ROOT="$fixture_root" "$checker"

# Deleting the prod rule, or defining it and never consuming it, must both fail.
write_clean_fixture
sed -i.bak '/authority_image_source_permitted = /d' "${module_dir}/ecr.tf"
rm -f "${module_dir}/ecr.tf.bak"
expect_failure 'must define authority_image_source_permitted' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
sed -i.bak '/^    local.authority_image_source_permitted &&$/d' "${module_dir}/ecr.tf"
rm -f "${module_dir}/ecr.tf.bak"
expect_failure 'must be consumed by the contract identity check' env NHP_REPO_ROOT="$fixture_root" "$checker"

# The original defect: comparing the reviewed basis against the live publish
# parameter. Reintroducing that coupling must fail closed.
write_clean_fixture
printf '%s\n' \
  'locals {' \
  '  drifted = local.authority_contract_global.authority_image_digest == "sha256:deadbeef"' \
  '}' >>"${module_dir}/ecr.tf"
expect_failure 'must not be compared against the publish parameter' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
printf '%s\n' '# unintended output drift' >>"${control_dir}/environments/prod/outputs.tf"
expect_failure 'output wrappers must remain byte-identical' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
fake_bin="${fixture_root}/fake-bin"
mkdir -p "$fake_bin"
printf '%s\n' '#!/usr/bin/env bash' 'exit 2' >"${fake_bin}/grep"
chmod +x "${fake_bin}/grep"
expect_failure 'Terraform scan failed with status 2' env \
  PATH="${fake_bin}:${PATH}" NHP_REPO_ROOT="$fixture_root" "$checker"

# Mechanical lockstep guard (review #3855): the shell fence's hardcoded
# steady-PC completion witness must name exactly the Python checker's
# AUTHORITY_RUNTIME_FUNCTIONS. A function add/remove that touches only one
# side fails here instead of silently desynchronizing the two gates.
python3 - "$repo_root" <<'LOCKSTEP'
import importlib.util
import re
import sys

repo_root = sys.argv[1]
spec = importlib.util.spec_from_file_location(
    "checker", f"{repo_root}/.github/scripts/check-control-sandbox-first-apply.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
python_expected = sorted(module.AUTHORITY_RUNTIME_FUNCTIONS)

shell_source = open(
    f"{repo_root}/scripts/check-connector-authority-foundation.sh"
).read()
# The completion witness's argjson array, anchored on its variable name and
# closed at the array's end -- not on indentation, so an unrelated argjson
# added elsewhere cannot silently become the compared block.
match = re.search(r"--argjson expected '\[(.*?)\]'", shell_source, re.DOTALL)
if match is None:
    sys.exit("FAIL: completion witness --argjson expected array not found")
shell_expected = sorted(
    set(
        re.findall(
            r"provisioned_concurrency_config\.authority\[\\\"([a-z0-9-]+)\\\"\]",
            match.group(1),
        )
    )
)
if shell_expected != python_expected:
    sys.exit(
        "FAIL: shell completion witness and Python AUTHORITY_RUNTIME_FUNCTIONS "
        f"disagree:\n  shell:  {shell_expected}\n  python: {python_expected}"
    )
if len(shell_expected) != 11:
    sys.exit(f"FAIL: expected 11 witnessed functions, extracted {len(shell_expected)}")
LOCKSTEP

echo "Connector Authority foundation checker fixtures passed"
