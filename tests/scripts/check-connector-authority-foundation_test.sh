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
    'data "aws_ssm_parameter" "authority_runtime_digest" {' \
    '  count = local.authority_runtime_contract_enabled ? 1 : 0' \
    '}' \
    'data "aws_ecr_image" "authority_runtime" {' \
    '  count = local.authority_runtime_contract_enabled ? 1 : 0' \
    '}' >"${module_dir}/ecr.tf"
  printf '%s\n' \
    'module "connector_authority_foundation" {' \
    '  source = "../../../modules/connector-authority-foundation"' \
    '  authority_runtime_contract = var.authority_runtime_contract' \
    '  authority_runtime_contract_evidence_verified = var.authority_runtime_contract_evidence_verified' \
    '}' >"${control_dir}/environments/sandbox/main.tf"
  cp "${control_dir}/environments/sandbox/main.tf" "${control_dir}/environments/prod/main.tf"
  printf '%s\n' \
    'variable "authority_runtime_contract" { default = null }' \
    'variable "authority_runtime_contract_evidence_verified" { default = false }' \
    >"${control_dir}/environments/sandbox/variables.tf"
  printf '%s\n' \
    'variable "authority_runtime_contract" {' \
    '  default = null' \
    '  validation { error_message = "Production Authority runtime contract must remain null throughout sandbox measurement." }' \
    '}' \
    'variable "authority_runtime_contract_evidence_verified" {' \
    '  default = false' \
    '  validation { error_message = "Production Authority evidence latch must remain false throughout sandbox measurement." }' \
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

write_clean_fixture
NHP_REPO_ROOT="$fixture_root" "$checker" >/dev/null

plan_json="${fixture_root}/control.tfplan.json"
printf '%s\n' '{"resource_changes":[]}' >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

printf '%s\n' '{"resource_changes":[{"address":"aws_vpc.control","type":"aws_vpc","change":{"actions":["update"],"after":{"tags":{"Purpose":"dark"}}}}]}' >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

printf '%s\n' '{"resource_drift":[{"address":"aws_iam_role.authority_publisher","type":"aws_iam_role","change":{"actions":["update"],"after":{"inline_policy":[]}}}]}' >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

printf '%s\n' '{"resource_changes":[{"address":"aws_lambda_function.forbidden","type":"aws_lambda_function","change":{"actions":["create"],"after":{"name":"forbidden"}}}]}' >"$plan_json"
expect_failure 'plan contains aws_lambda_function' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' '{"resource_changes":[{"address":"aws_vpc.removed","type":"aws_vpc","change":{"actions":["delete"],"after":null}}]}' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' '{"resource_changes":[{"address":"aws_vpc.replaced","type":"aws_vpc","change":{"actions":["delete","create"],"after":{"cidr_block":"10.102.0.0/16"}}}]}' >"$plan_json"
expect_failure 'plan contains destructive actions' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' '{"resource_changes":[{"address":"aws_route_table.isolated[0]","type":"aws_route_table","change":{"actions":["create"],"after":{"route":[]},"after_unknown":{"route":true}}}]}' >"$plan_json"
NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json" >/dev/null

printf '%s\n' '{"resource_changes":[{"address":"aws_route_table.isolated[0]","type":"aws_route_table","change":{"actions":["create"],"after":{"route":[{"cidr_block":"0.0.0.0/0","network_interface_id":"eni-123"}]},"after_unknown":{"route":[]}}}]}' >"$plan_json"
expect_failure 'plan contains inline route declarations' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' '{"format_version":"1.2"}' >"$plan_json"
expect_failure 'must contain a resource_changes array or non-empty resource_drift array' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' '{"resource_changes":null,"resource_drift":[{"address":"aws_iam_role.authority_publisher","type":"aws_iam_role","change":{"actions":["update"]}}]}' >"$plan_json"
expect_failure 'resource_changes must be an array' env NHP_REPO_ROOT="$fixture_root" "$checker" "$plan_json"

printf '%s\n' 'resource "aws_lambda_function" "forbidden" {}' >>"${module_dir}/main.tf"
expect_failure 'must not declare aws_lambda_function' env NHP_REPO_ROOT="$fixture_root" "$checker"

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
sed -i.bak \
  '/authority_runtime_contract_evidence_verified = var.authority_runtime_contract_evidence_verified/d' \
  "${control_dir}/environments/sandbox/main.tf"
rm "${control_dir}/environments/sandbox/main.tf.bak"
cp "${control_dir}/environments/sandbox/main.tf" "${control_dir}/environments/prod/main.tf"
expect_failure 'must pass the internal evidence latch exactly once' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
printf '%s\n' '{}' >"${control_dir}/environments/sandbox/unreviewed.auto.tfvars"
expect_failure 'must not commit generated runtime tfvars' env NHP_REPO_ROOT="$fixture_root" "$checker"

# The generated latch tfvars is emitted as JSON (authority-runtime.generated.tfvars.json)
# and Terraform auto-loads *.tfvars.json / *.auto.tfvars.json, so the committed-tfvars
# guard must reject those variants too — otherwise a committed *.auto.tfvars.json could
# open the sandbox evidence latch (which has no root-variable validation).
write_clean_fixture
printf '%s\n' '{}' >"${control_dir}/environments/sandbox/authority-runtime.generated.tfvars.json"
expect_failure 'must not commit generated runtime tfvars' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
printf '%s\n' '{}' >"${control_dir}/environments/sandbox/evil.auto.tfvars.json"
expect_failure 'must not commit generated runtime tfvars' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
sed -i.bak '/Production Authority evidence latch must remain false/d' \
  "${control_dir}/environments/prod/variables.tf"
rm "${control_dir}/environments/prod/variables.tf.bak"
expect_failure 'production Control variables must fail closed' env NHP_REPO_ROOT="$fixture_root" "$checker"

write_clean_fixture
rm "${module_dir}/ecr.tf"
expect_failure 'must declare exactly one conditional SSM digest read' env NHP_REPO_ROOT="$fixture_root" "$checker"

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
