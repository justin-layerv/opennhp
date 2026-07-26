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
    'data "aws_ecr_image" "authority_runtime" {' \
    '  count = local.authority_runtime_contract_enabled ? 1 : 0' \
    '  image_digest    = local.authority_contract_global.authority_image_digest' \
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
    '  default = false' \
    '  validation {' \
    '    condition = !var.provisioned_cell_catalog_materialization_enabled' \
    '  }' \
    '}' \
    >"${control_dir}/environments/sandbox/variables.tf"
  printf '%s\n' \
    'variable "authority_runtime_contract" {' \
    '  default = null' \
    '  validation { error_message = "Production Authority runtime contract must remain null throughout sandbox measurement." }' \
    '}' \
    'variable "authority_runtime_contract_evidence_verified" {' \
    '  default = false' \
    '  validation { error_message = "Production Authority evidence latch must remain false throughout sandbox measurement." }' \
    '}' \
    'variable "provisioned_cell_catalog_materialization_enabled" {' \
    '  default = false' \
    '  validation {' \
    '    condition = !var.provisioned_cell_catalog_materialization_enabled' \
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
printf '%s\n' '{"resource_changes":[{"address":"module.control.aws_security_group.authority_lambda[0]","type":"aws_security_group","change":{"actions":["create","delete"],"before":{"name_prefix":"layerv-nhp-sandbox-control-ca-fn-","vpc_id":"vpc-abc123","ingress":[],"egress":[{"description":"HTTPS to Control interface endpoints (KMS) in-VPC","cidr_blocks":["10.102.0.0/16"],"ipv6_cidr_blocks":[],"prefix_list_ids":[],"security_groups":[],"self":false,"protocol":"tcp","from_port":443,"to_port":443},{"description":"HTTPS to the DynamoDB gateway endpoint prefix list","cidr_blocks":[],"ipv6_cidr_blocks":[],"prefix_list_ids":["pl-abc123"],"security_groups":[],"self":false,"protocol":"tcp","from_port":443,"to_port":443}]},"after":{"name_prefix":"layerv-nhp-sandbox-control-ca-fn-v2-","vpc_id":"vpc-abc123"},"after_unknown":{"ingress":true,"egress":true},"replace_paths":[["name_prefix"]]}}]}' >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

jq '.resource_changes[0].change.before.egress[0].cidr_blocks = ["0.0.0.0/0"]' \
  "$plan_json" >"${plan_json}.tmp"
mv "${plan_json}.tmp" "$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

# A tainted Connector Authority hub FUNCTION replace (delete+create) is the
# authority-runtime-slice-retry recovery for a Failed function, not a teardown.
printf '%s\n' '{"resource_changes":[{"address":"module.control.aws_lambda_function.authority[\"layerv-nhp-sandbox-ca-ia\"]","type":"aws_lambda_function","change":{"actions":["delete","create"],"after":{"function_name":"layerv-nhp-sandbox-ca-ia"}}}]}' >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

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
  '  default = false' \
  '  validation {' \
  '    condition = !var.provisioned_cell_catalog_materialization_enabled' \
  '  }' \
  '}' >>"${control_dir}/environments/sandbox/variables.tf"
expect_failure 'sandbox Control variables must declare exactly one closed provisioned-cell materialization gate' \
  env NHP_REPO_ROOT="$fixture_root" "$checker"

for environment in sandbox prod; do
  write_clean_fixture
  sed -i.bak \
    '/variable "provisioned_cell_catalog_materialization_enabled"/,/^}$/s/  default = false/  default = true/' \
    "${control_dir}/environments/${environment}/variables.tf"
  rm "${control_dir}/environments/${environment}/variables.tf.bak"
  expect_failure "${environment} Control variables must hard-lock provisioned-cell catalog materialization false" \
    env NHP_REPO_ROOT="$fixture_root" "$checker"

  write_clean_fixture
  sed -i.bak \
    '/variable "provisioned_cell_catalog_materialization_enabled"/,/^}$/s/condition = !var\./condition = var./' \
    "${control_dir}/environments/${environment}/variables.tf"
  rm "${control_dir}/environments/${environment}/variables.tf.bak"
  expect_failure "${environment} Control variables must hard-lock provisioned-cell catalog materialization false" \
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

write_clean_fixture
sed -i.bak '/Production Authority evidence latch must remain false/d' \
  "${control_dir}/environments/prod/variables.tf"
rm "${control_dir}/environments/prod/variables.tf.bak"
expect_failure 'production Control variables must fail closed' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
rm "${module_dir}/ecr.tf"
expect_failure 'must declare exactly one conditional ECR digest read' env NHP_REPO_ROOT="$fixture_root" "$checker"

# Reintroducing the publisher-owned SSM digest read must fail closed. That read
# is what let a qurl-service publish invalidate every Control plan, so the
# contract forbids it rather than merely not requiring it.
write_clean_fixture
printf '%s\n' \
  'data "aws_ssm_parameter" "authority_runtime_digest" {' \
  '  count = local.authority_runtime_contract_enabled ? 1 : 0' \
  '}' >>"${module_dir}/ecr.tf"
expect_failure 'must not read the publisher-owned SSM digest' env NHP_REPO_ROOT="$fixture_root" "$checker"

# The ECR read must resolve the reviewed basis digest, not some other source.
write_clean_fixture
sed -i.bak 's#image_digest    = local.authority_contract_global.authority_image_digest#image_digest    = "sha256:deadbeef"#' \
  "${module_dir}/ecr.tf"
rm "${module_dir}/ecr.tf.bak"
expect_failure 'ECR read must resolve the reviewed basis digest' env NHP_REPO_ROOT="$fixture_root" "$checker"

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

echo "Connector Authority foundation checker fixtures passed"
