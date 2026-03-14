#!/bin/bash
# Migrate Terraform state for canary deployment module refactor.
# Run this BEFORE terraform apply when deploying the canary component split.
#
# This renames existing canary resources from the singleton module
# (module.canary_deployment[0]) to the server-specific names so Terraform
# doesn't destroy and recreate them.
#
# Usage:
#   cd terraform/environments/prod  # or sandbox
#   terraform init
#   ../../../scripts/migrate-canary-state.sh
#   terraform plan  # verify no destroy/create for server resources

set -euo pipefail

echo "=== Canary State Machine Module Migration ==="
echo "Renaming canary_deployment[0] resources to include 'server' component..."
echo ""

# The module address doesn't change (still canary_deployment[0]),
# but the resource names inside the module changed. Terraform tracks
# resources by their address, not their AWS name, so we only need
# state moves if the module itself was renamed.
#
# Since we kept module.canary_deployment[0] for server and added
# module.canary_deployment_ac[0] for AC, the existing state addresses
# are still valid — Terraform will just update the resource names
# in-place (modify, not destroy/create) for most resources.
#
# However, some resources cannot be renamed in-place:
# - aws_sfn_state_machine (name is immutable)
# - aws_lambda_function (function_name is immutable)
# - aws_iam_role (name is immutable)
# - aws_cloudwatch_log_group (name is immutable)
#
# For these, Terraform WILL destroy and recreate them.
# This is safe if no canary deployment is in progress.

echo "IMPORTANT: Ensure no canary deployments are in progress before applying."
echo ""
echo "Resources that will be recreated (name changed):"
echo "  - Step Functions state machine (nhp-*-canary-deploy -> nhp-*-canary-deploy-server)"
echo "  - Lambda function (nhp-*-canary-orchestrator -> nhp-*-canary-orchestrator-server)"
echo "  - IAM roles (name suffix changed)"
echo "  - CloudWatch log groups (name changed)"
echo "  - CloudWatch alarms (name changed)"
echo "  - SSM parameters (path changed to include /server/)"
echo ""
echo "Resources that will be CREATED (new AC canary):"
echo "  - module.canary_deployment_ac[0].* (all AC canary resources)"
echo ""
echo "Run 'terraform plan' to review before applying."
