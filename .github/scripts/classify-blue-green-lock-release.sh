#!/usr/bin/env bash
# Decide whether a blue/green run reached a terminal state where its exact-owner
# sandbox qURL lock may be released. Keep this decision executable and tested:
# the workflow must fail closed when a mutation is not followed by successful
# validation and, for deploys, actual previous-color scale-down convergence.
#
# The test the lock actually cares about is whether THE LIVE BOUNDARY MOVED, not
# whether the run went green. A run that never reached switch-traffic left the
# customer path byte-identical to how it found it and must release, or every
# failed roll pins the shared mutex for its full TTL and the next waiter inherits
# the same fate the moment that TTL lapses.

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
elif [[ "$action" == "prepare-only" && "$deploy_result" == "success" && "$switch_result" == "skipped" ]]; then
  # Standby image/profile/capacity mutations are intentionally non-serving.
  # A successful prepare-only run never moves a listener or active-color key.
  safe_to_release=true
# switch-traffic is the ONLY job that mutates the live boundary: every
# `aws elbv2 modify-listener` and the authoritative active-color SSM write live
# in blue-green-switch.sh, which nothing else invokes. Its guard is
# `needs.deploy-to-standby.result == 'success' || == 'skipped'`, so a 'skipped'
# switch proves deploy-to-standby failed or was cancelled BEFORE any listener
# moved: the active color still serves exactly what it served when this run
# acquired the lock, and the protected qv2 customer path never changed.
#
# What a failed deploy-to-standby does leave behind is standby-only residue - a
# scaled-up standby ASG, a refreshed standby fleet, an updated standby image-tag
# parameter. None of it is in a live target group, both colors running at once
# is the normal mid-roll state this workflow is built around, and the next run's
# prepare/deploy-to-standby reconciles it from scratch. Holding the mutex for
# that residue bought nothing and cost every later deploy the full TTL.
#
# Cancellation DURING switch-traffic is deliberately excluded: a 'cancelled'
# switch can mean listeners moved partway (public UDP flipped, internal relay
# not), which is exactly the half-switched boundary the mutex exists to fence.
elif [[ "$switch_result" == "skipped" ]]; then
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
