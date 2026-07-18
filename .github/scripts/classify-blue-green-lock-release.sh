#!/usr/bin/env bash
# Decide whether a blue/green run reached a terminal state where its exact-owner
# sandbox qURL lock may be released. Keep this decision executable and tested:
# the workflow must fail closed when a mutation is not followed by successful
# validation and, for deploys, actual previous-color scale-down convergence.

set -euo pipefail

if [[ $# -ne 9 ]]; then
  echo "usage: $0 <action> <dry-run> <prepare-result> <deploy-result> <switch-result> <validate-result> <scale-down-result> <deploy-server> <deploy-ac>" >&2
  exit 2
fi

action=$1
dry_run=$2
prepare_result=$3
deploy_result=$4
switch_result=$5
validate_result=$6
scale_down_result=$7
deploy_server=$8
deploy_ac=$9

safe_to_release=false

# A true dry run never mutates. Prepare only reads state and validates inputs,
# so a failure there is also safe. If prepare succeeds but selects no component,
# every mutating step is conditionally skipped; release that read-only no-op.
if [[ "$dry_run" == "true" || "$prepare_result" != "success" ]]; then
  safe_to_release=true
elif [[ "$deploy_server" != "true" && "$deploy_ac" != "true" ]]; then
  safe_to_release=true
elif [[ "$switch_result" == "success" && "$validate_result" == "success" ]]; then
  case "$action" in
    deploy)
      if [[ "$deploy_result" == "success" && "$scale_down_result" == "success" ]]; then
        safe_to_release=true
      fi
      ;;
    rollback|switch-only)
      safe_to_release=true
      ;;
  esac
fi

printf '%s\n' "$safe_to_release"
