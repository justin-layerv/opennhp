#!/usr/bin/env bash
# Classify changed files for the Terraform Plan (PR) required check.
#
# Output is written as GitHub Actions key=value pairs on stdout and, when
# running in Actions, to $GITHUB_OUTPUT.

set -euo pipefail

usage() {
	echo "usage: $0 <changed-files.tsv> [merge-base]" >&2
}

if [[ "$#" -lt 1 || "$#" -gt 2 ]]; then
	usage
	exit 2
fi

changed_files="$1"
merge_base="${2:-}"

if [[ ! -f "$changed_files" ]]; then
	echo "ERROR: changed-files TSV not found: $changed_files" >&2
	exit 2
fi

emit_output() {
	local key="$1"
	local value="$2"

	printf '%s=%s\n' "$key" "$value"
	if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
		printf '%s=%s\n' "$key" "$value" >> "$GITHUB_OUTPUT"
	fi
}

terraform_changed=false
prod_env_changed=false
non_prod_plan_input_changed=false
terraform_plan_workflow_added=false

while IFS=$'\t' read -r status file _rest; do
	[[ -n "$file" ]] || continue

	# Keep this list in sync with every local file that can change the
	# sandbox plan graph without living under terraform/.
	case "$file" in
		# Bash case globs let * span /, so this also matches nested prod
		# markdown. Keep it before terraform/environments/prod/*: prod docs
		# are intentionally doc-only and should not request AWS creds.
		terraform/*.md)
			;;
		terraform/environments/prod/*)
			terraform_changed=true
			prod_env_changed=true
			;;
		# This temporary root is production-only and has its own state and
		# post-merge saved-plan workflow. Never gate it on the unrelated
		# sandbox legacy-root plan.
		terraform/staged/qurl-agent-transact-iam/*)
			terraform_changed=true
			prod_env_changed=true
			;;
		# Membership rule for this arm: the file can change the sandbox plan
		# graph. Two entries are non-obvious —
		# .github/control-sandbox-runtime-gates.json and its reader qualify
		# because terraform-plan-pr.yml derives the Authority runtime generator
		# flags from them, so a gate-only PR that did not land here would report
		# success with no AWS credentials and no plan at all.
		terraform/*|.github/workflows/terraform-plan-pr.yml|.github/actions/build-lambda-packages/*|.github/scripts/classify-terraform-plan-pr-changes.sh|.github/scripts/check-relay-dmz-plan*.py|.github/scripts/check-control-sandbox-first-apply.py|.github/scripts/generate-connector-authority-runtime-contract.py|.github/control-sandbox-runtime-gates.json|.github/scripts/control-sandbox-runtime-gates.py|docs/evidence/connector-authority/v1/*|scripts/check-connector-authority-foundation.sh|scripts/check-control-vpc-cidr-overlap.sh|tests/scripts/test_generate_connector_authority_runtime_contract.py)
			terraform_changed=true
			non_prod_plan_input_changed=true
			;;
	esac

	if [[ "$file" == ".github/workflows/terraform-plan-pr.yml" && "$status" == "A" ]]; then
		if [[ -z "$merge_base" ]] || ! git cat-file -e "$merge_base:$file" 2>/dev/null; then
			terraform_plan_workflow_added=true
		fi
	fi
done < "$changed_files"

prod_only_terraform_changed=false
if [[ "$terraform_changed" == "true" && "$prod_env_changed" == "true" && "$non_prod_plan_input_changed" == "false" ]]; then
	prod_only_terraform_changed=true
fi

emit_output "terraform_changed" "$terraform_changed"
emit_output "prod_only_terraform_changed" "$prod_only_terraform_changed"
emit_output "terraform_plan_workflow_added" "$terraform_plan_workflow_added"

if [[ "$terraform_changed" == "true" ]]; then
	echo "Terraform plan inputs changed - running sandbox plan"
else
	echo "No Terraform plan inputs changed - reporting success without AWS credentials"
fi
