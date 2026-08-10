#!/usr/bin/env bash
# Fixture tests for .github/scripts/classify-terraform-plan-pr-changes.sh.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${REPO_ROOT}/.github/scripts/classify-terraform-plan-pr-changes.sh"

PASS=0
FAIL=0

assert_contains() {
	local name="$1"
	local haystack="$2"
	local needle="$3"

	if [[ "$haystack" == *"$needle"* ]]; then
		printf '  PASS: %s\n' "$name"
		PASS=$((PASS + 1))
	else
		printf '  FAIL: %s — output did not contain %q\n' "$name" "$needle" >&2
		printf '        full output:\n' >&2
		printf '%s\n' "$haystack" | sed 's/^/          /' >&2
		FAIL=$((FAIL + 1))
	fi
}

run_case() {
	local name="$1"
	local expected_terraform_changed="$2"
	local expected_prod_only="$3"
	local expected_workflow_added="$4"
	shift 4

	local input
	input="$(mktemp)"
	printf '%s\n' "$@" > "$input"

	local output
	if ! output="$("$SCRIPT" "$input" 2>&1)"; then
		printf '  FAIL: %s — classifier exited non-zero\n' "$name" >&2
		printf '%s\n' "$output" | sed 's/^/          /' >&2
		FAIL=$((FAIL + 1))
		rm -f "$input"
		return
	fi
	rm -f "$input"

	assert_contains "$name terraform_changed" "$output" "terraform_changed=$expected_terraform_changed"
	assert_contains "$name prod_only_terraform_changed" "$output" "prod_only_terraform_changed=$expected_prod_only"
	assert_contains "$name terraform_plan_workflow_added" "$output" "terraform_plan_workflow_added=$expected_workflow_added"
}

echo "Running classify-terraform-plan-pr-changes fixtures"

run_case "root terraform markdown is docs-only" false false false \
	$'M\tterraform/README.md'
run_case "prod markdown is docs-only despite prod glob" false false false \
	$'M\tterraform/environments/prod/README.md'
run_case "prod terraform is prod-only" true true false \
	$'M\tterraform/environments/prod/main.tf'
run_case "staged prod IAM root is prod-only" true true false \
	$'M\tterraform/staged/qurl-agent-transact-iam/main.tf'
run_case "staged prod IAM README is docs-only" false false false \
	$'M\tterraform/staged/qurl-agent-transact-iam/README.md'
run_case "shared terraform triggers sandbox plan" true false false \
	$'M\tterraform/modules/ecr/main.tf'
run_case "plan workflow modification triggers sandbox plan" true false false \
	$'M\t.github/workflows/terraform-plan-pr.yml'
run_case "plan workflow addition sets bootstrap flag" true false true \
	$'A\t.github/workflows/terraform-plan-pr.yml'
run_case "lambda packaging helper triggers sandbox plan" true false false \
	$'M\t.github/actions/build-lambda-packages/action.yml'
# The fetch-auth0-token.sh case that lived here was removed with #3284: the
# helper is deleted and the Auth0 provider retired, so there is no Auth0
# credential for this workflow to fetch and no plan input to guard.
run_case "classifier helper triggers sandbox plan" true false false \
	$'M\t.github/scripts/classify-terraform-plan-pr-changes.sh'
run_case "relay DMZ checker triggers sandbox plan" true false false \
	$'M\t.github/scripts/check-relay-dmz-plan.py'
run_case "relay DMZ checker companion triggers sandbox plan" true false false \
	$'M\t.github/scripts/check-relay-dmz-plan-next.py'
run_case "Connector Authority contract checker triggers sandbox plan" true false false \
	$'M\tscripts/check-connector-authority-foundation.sh'
run_case "Control foundation checker triggers sandbox plan" true false false \
	$'M\t.github/scripts/check-control-sandbox-first-apply.py'
run_case "Authority evidence generator triggers sandbox plan" true false false \
	$'M\t.github/scripts/generate-connector-authority-runtime-contract.py'
run_case "Authority evidence manifest triggers sandbox plan" true false false \
	$'M\tdocs/evidence/connector-authority/v1/sandbox-measurement-basis.json'
run_case "Authority evidence generator tests trigger sandbox plan" true false false \
	$'M\ttests/scripts/test_generate_connector_authority_runtime_contract.py'
# The gate file supplies the generator flags, so editing it changes the planned
# Control graph as surely as editing the Terraform. A gate-only PR is precisely
# the one that must not report success without a plan.
run_case "Control runtime gate file triggers sandbox plan" true false false \
	$'M\t.github/control-sandbox-runtime-gates.json'
run_case "Control runtime gate reader triggers sandbox plan" true false false \
	$'M\t.github/scripts/control-sandbox-runtime-gates.py'
run_case "control CIDR preflight triggers sandbox plan" true false false \
	$'M\tscripts/check-control-vpc-cidr-overlap.sh'
run_case "unrelated docs stay skipped" false false false \
	$'M\tdocs/runbooks/example.md'
run_case "prod terraform plus prod docs stays prod-only" true true false \
	$'M\tterraform/environments/prod/main.tf' \
	$'M\tterraform/environments/prod/README.md'
run_case "prod terraform plus shared terraform is not prod-only" true false false \
	$'M\tterraform/environments/prod/main.tf' \
	$'M\tterraform/modules/ecr/main.tf'

if [[ "$FAIL" -gt 0 ]]; then
	printf '\n[classify-terraform-plan-pr-changes_test.sh] %d passed, %d failed\n' "$PASS" "$FAIL" >&2
	exit 1
fi

printf '\n[classify-terraform-plan-pr-changes_test.sh] %d passed, %d failed\n' "$PASS" "$FAIL"
