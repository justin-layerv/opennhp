#!/usr/bin/env bash
# Forward-only attended recovery for the one schema-2 durable-AOP cutover that
# reached old_servers_terminated at the original e9 source.  This script does
# not reinterpret or overwrite that event.  It adopts the exact state and hard
# lock into schema 3, binds an independently attested repair build, refreshes
# both already-active server fleets and the already-active AC fleet, and retains
# the original lock until every durable authority, topology check, and live
# customer lifecycle execution has passed.

set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <repair-source-sha> <repair-build-run-id> <repair-build-run-attempt> <confirmation>" >&2
  exit 2
fi

REPAIR_SOURCE_SHA=$1
REPAIR_BUILD_RUN_ID=$2
REPAIR_BUILD_RUN_ATTEMPT=$3
CONFIRMATION=$4
ORIGINAL_SOURCE_SHA=${CUTOVER_ORIGINAL_SOURCE_SHA:-e9b11398a4cea98da6ae5b41cfe635562e1b7c72}
ORIGINAL_RUN_ID=${CUTOVER_ORIGINAL_RUN_ID:-32635672597}
ORIGINAL_RUN_ATTEMPT=1
ORIGINAL_CANCELLED_JOB_COUNT=28
ORIGINAL_CELL1_FAILURE_JOB_ID=97187875176
ORIGINAL_VALIDATION_CANCELLED_JOB_ID=97191982507
RECOVERY_ORCHESTRATOR_SHA=${CUTOVER_RECOVERY_ORCHESTRATOR_SHA:-${GITHUB_SHA:-}}
# Exact admin-squash-merged #3935 authority. The fixed-path manifest is
# recomputed from this Git tree and independently rechecked through GitHub's
# tree API before any schema-3 adoption or fleet refresh.
APPROVED_REPAIR_SOURCE_SHA=422b1d9acac53d50fe5602158fb02c8120ef108d
APPROVED_REPAIR_RUNTIME_MANIFEST=2895963905453d61874858171529968efe8e18e5450d41842854fd2784d1ec78
APPROVED_CUSTOMER_INFRA_SHA=d30d3fce3a6c3cf15e1340a5106b6cc76bce7e82
APPROVED_INTEGRATIONS_SHA=356ecd44bbf09fca392247d971bbc093b337d4e5
APPROVED_CONNECTOR_PR_HEAD_SHA=16dd7d3c835bf4f44b212e2d6a34205a3c04a8d8
APPROVED_CUSTOMER_CLIENT_ID=oScYkXhLitBPO6gBjxo4Rwyw37AdoNPy
APPROVED_CUSTOMER_SUBJECT=${APPROVED_CUSTOMER_CLIENT_ID}@clients
APPROVED_CUSTOMER_EMAIL=oscykxhlitbpo6gbjxo4rwyw37adonpy-clients@machine.notify.layerv.xyz
APPROVED_CUSTOMER_TABLE=layerv-nhp-sandbox-control-qurl-customers
# The first repaired controller stopped at the exact live SSM v15
# cell1_refreshing boundary. One successor may adopt only those exact bytes and
# rewrites the controller authority on its first state transition. This is not
# a general source-compatibility list. The workflow establishes successor trust
# before AWS credentials by requiring expected_recovery_sha == GITHUB_SHA and
# checking out that exact live main commit; the future squash SHA therefore is
# not a caller-controlled static allowlist entry here.
APPROVED_RECOVERY_HANDOFF_PREDECESSOR_SHA=c83dfec827b216cd23fb95f08c157318e1153087
APPROVED_RECOVERY_HANDOFF_STATE_VERSION=15
APPROVED_RECOVERY_HANDOFF_STATE_DIGEST=18cc92713387304aa319684fe4aea851ab1a3326ba53e4895e25a8be3f1d494d
GITHUB_REPOSITORY=${GITHUB_REPOSITORY:-layervai/nhp}
AWS_REGION=${AWS_REGION:-us-east-2}
export AWS_REGION GITHUB_REPOSITORY

[[ "$REPAIR_SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "repair source must be exact lowercase 40-hex" >&2; exit 2; }
[[ "$REPAIR_SOURCE_SHA" == "$APPROVED_REPAIR_SOURCE_SHA" ]] || {
  echo "repair source is not the exact approved merged #3935 source; recovery checkpoint remains fail-closed" >&2
  exit 2
}
[[ "$REPAIR_BUILD_RUN_ID" =~ ^[1-9][0-9]*$ ]] || { echo "repair build run id must be a positive integer" >&2; exit 2; }
[[ "$REPAIR_BUILD_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]] || { echo "repair build run attempt must be a positive integer" >&2; exit 2; }
[[ "$RECOVERY_ORCHESTRATOR_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "recovery orchestrator SHA must be exact lowercase 40-hex" >&2; exit 2; }
[[ "$CONFIRMATION" == ADOPT_EXACT_E9_DURABLE_AOP_REPAIR ]] || { echo "recovery confirmation is not exact" >&2; exit 2; }
: "${GH_TOKEN:?GH_TOKEN is required}"

CUSTOMER_LIFECYCLE_RUN_ID=${CUTOVER_CUSTOMER_LIFECYCLE_RUN_ID:-}
CUSTOMER_LIFECYCLE_RUN_ATTEMPT=${CUTOVER_CUSTOMER_LIFECYCLE_RUN_ATTEMPT:-}
CONNECTOR_LIFECYCLE_RUN_ID=${CUTOVER_CONNECTOR_LIFECYCLE_RUN_ID:-}
CONNECTOR_LIFECYCLE_RUN_ATTEMPT=${CUTOVER_CONNECTOR_LIFECYCLE_RUN_ATTEMPT:-}
if [[ -z "$CUSTOMER_LIFECYCLE_RUN_ID$CUSTOMER_LIFECYCLE_RUN_ATTEMPT$CONNECTOR_LIFECYCLE_RUN_ID$CONNECTOR_LIFECYCLE_RUN_ATTEMPT" ]]; then
  LIFECYCLE_MODE=deferred
elif [[ "$CUSTOMER_LIFECYCLE_RUN_ID" =~ ^[1-9][0-9]*$ &&
        "$CUSTOMER_LIFECYCLE_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ &&
        "$CONNECTOR_LIFECYCLE_RUN_ID" =~ ^[1-9][0-9]*$ &&
        "$CONNECTOR_LIFECYCLE_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]; then
  LIFECYCLE_MODE=terminal
else
  echo "customer and connector lifecycle selectors must be four positive integers or all omitted" >&2
  exit 2
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
STATE_PARAM=/sandbox/nhp/cutovers/durable-aop-v1/state
LOCK_PARAM=/layerv-nhp-sandbox/qurl-live-env-lock
FLOOR_PARAM=/sandbox/nhp/minimum-protocol-profile
TARGET_PROFILE=durable-aop-v1
ORIGINAL_OWNER="nhp:${ORIGINAL_RUN_ID}:durable-aop-cutover:${ORIGINAL_SOURCE_SHA}"
APPROVED_ORIGINAL_STATE_VERSION=7
APPROVED_ORIGINAL_STATE_DIGEST=e7ed20adde2ce9e143c9505027a73e415e5dd3d4a9d0c950c912d6398cc5d13e
APPROVED_ORIGINAL_LOCK_VERSION=2
APPROVED_ORIGINAL_LOCK_DIGEST=6c7224d78837a4d56547409439d9bce30efa9b214367c4f19fd13cc3fe3b2ebd
APPROVED_ORIGINAL_STATE='{"ac":{"new_asg":"layerv-nhp-sandbox-ac-green","new_attestation":"v2|durable-aop-v1|e9b11398a4cea98da6ae5b41cfe635562e1b7c72|layerv/nhp-ac|sha256:2e38672ef7680c60521694c3f2a59e9a74ed8f2d56bfe1fb41a97f3040b4e279|layerv-nhp-sandbox-ac-green","new_color":"green","old_asg":"layerv-nhp-sandbox-ac","old_color":"blue","old_desired":3,"old_max":3,"old_min":3},"cell0":{"new_asg":"layerv-nhp-sandbox-server","new_attestation":"v2|durable-aop-v1|e9b11398a4cea98da6ae5b41cfe635562e1b7c72|layerv/nhp-server|sha256:94a5d91373ca261e4edfffc2ca743768b7da573bacd9dadac87c2dd7d0cbc1f4|layerv-nhp-sandbox-server","new_color":"blue","old_asg":"layerv-nhp-sandbox-server-green","old_color":"green"},"cell1":{"new_asg":"layerv-nhp-sandbox-cell1-server-green","new_attestation":"v2|durable-aop-v1|e9b11398a4cea98da6ae5b41cfe635562e1b7c72|layerv/nhp-server|sha256:94a5d91373ca261e4edfffc2ca743768b7da573bacd9dadac87c2dd7d0cbc1f4|layerv-nhp-sandbox-cell1-server-green","new_color":"green","old_asg":"layerv-nhp-sandbox-cell1-server","old_color":"blue"},"image":"e9b11398a4cea98da6ae5b41cfe635562e1b7c72","lock_owner":"nhp:32635672597:durable-aop-cutover:e9b11398a4cea98da6ae5b41cfe635562e1b7c72","orchestrator_sha":"e9b11398a4cea98da6ae5b41cfe635562e1b7c72","phase":"old_servers_terminated","schema":2}'
APPROVED_ORIGINAL_LOCK='{"created_at":1787485146,"expires_at":253402300799,"image":"e9b11398a4cea98da6ae5b41cfe635562e1b7c72","kind":"durable-aop-cutover-recovery","orchestrator_sha":"e9b11398a4cea98da6ae5b41cfe635562e1b7c72","owner":"nhp:32635672597:durable-aop-cutover:e9b11398a4cea98da6ae5b41cfe635562e1b7c72","schema":1}'
REFRESH_PREFERENCES='{"MinHealthyPercentage":100,"MaxHealthyPercentage":200,"InstanceWarmup":60,"SkipMatching":false}'
VERIFY_PROVENANCE=${CUTOVER_VERIFY_PROVENANCE_SCRIPT:-$ROOT/.github/scripts/verify-durable-aop-image-provenance.sh}
VERIFY_BUILD_ONLY=$ROOT/.github/scripts/verify-durable-aop-build-only-run.sh
VERIFY_ASG=${CUTOVER_VERIFY_ASG_HEALTH_SCRIPT:-$ROOT/.github/scripts/verify-asg-instances-healthy.sh}
VERIFY_LIFECYCLE=${CUTOVER_VERIFY_LIFECYCLE_SCRIPT:-$ROOT/.github/scripts/verify-durable-aop-recovery-lifecycle.sh}
VERIFY_TOPOLOGY=${CUTOVER_VERIFY_TOPOLOGY_SCRIPT:-$ROOT/.github/scripts/verify-durable-aop-cutover-recovery-ready.sh}
VERIFY_CUSTOMER_LIFECYCLE=$ROOT/.github/scripts/verify-durable-aop-customer-lifecycle-run.sh
VERIFY_CONNECTOR_LIFECYCLE=$ROOT/.github/scripts/verify-durable-aop-connector-lifecycle-run.sh
OWNER_PROJECTOR=${CUTOVER_OWNER_PROJECTOR_SCRIPT:-$ROOT/terraform/scripts/project-qurl-sharing-customer-tier.py}
WAIT_REFRESH=${CUTOVER_WAIT_REFRESH_SCRIPT:-$ROOT/.github/scripts/wait-for-instance-refresh.sh}
ORIGINAL_ROOT=${CUTOVER_ORIGINAL_SOURCE_ROOT:-$ROOT}
REFRESH_TIMEOUT_MINUTES=${CUTOVER_REPAIR_REFRESH_TIMEOUT_MINUTES:-30}

emit_recovery_outcome() {
  local outcome=$1
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'recovery_outcome=%s\n' "$outcome" >>"$GITHUB_OUTPUT"
  fi
}

get_optional() { bash "$ROOT/scripts/ssm-read-optional.sh" "$1"; }
get_param() { aws ssm get-parameter --name "$1" --query Parameter.Value --output text --region "$AWS_REGION"; }
get_param_version() { aws ssm get-parameter --name "$1" --query Parameter.Version --output text --region "$AWS_REGION"; }
put_param() { aws ssm put-parameter --name "$1" --value "$2" --type String --overwrite --region "$AWS_REGION" >/dev/null; }
delete_optional() {
  local name=$1 err
  if ! err=$(aws ssm delete-parameter --name "$name" --region "$AWS_REGION" 2>&1 >/dev/null); then
    grep -q ParameterNotFound <<<"$err" || { printf '%s\n' "$err" >&2; return 1; }
  fi
}

ensure_exact_floor() {
  local current err
  current=$(get_optional "$FLOOR_PARAM")
  if [[ -z "$current" ]]; then
    if ! err=$(aws ssm put-parameter --name "$FLOOR_PARAM" --value "$TARGET_PROFILE" \
      --type String --no-overwrite --region "$AWS_REGION" 2>&1 >/dev/null); then
      grep -q ParameterAlreadyExists <<<"$err" || { printf '%s\n' "$err" >&2; return 1; }
    fi
    current=$(get_param "$FLOOR_PARAM")
  fi
  [[ "$current" == "$TARGET_PROFILE" && "$(get_param "$FLOOR_PARAM")" == "$TARGET_PROFILE" ]] || {
    echo "durable profile floor is unexpected; recovery never overwrites floor authority" >&2
    return 1
  }
}

slot_image_param() { [[ "$3" == green ]] && printf '/%s/nhp/%s/green-image-tag\n' "$1" "$2" || printf '/%s/nhp/%s/image-tag\n' "$1" "$2"; }
slot_asg_param() { [[ "$3" == green ]] && printf '/%s/nhp/%s/green-asg-name\n' "$1" "$2" || printf '/%s/nhp/%s/asg-name\n' "$1" "$2"; }
slot_attestation_param() { printf '/%s/nhp/%s/%s-prepared-slot-attestation\n' "$1" "$2" "$3"; }
slot_profile_param() { printf '/%s/nhp/%s/%s-protocol-profile\n' "$1" "$2" "$3"; }

canonical_digest() { printf '%s' "$1" | sha256sum | awk '{print $1}'; }

require_hard_lock() {
  local lock version digest
  lock=$(get_param "$LOCK_PARAM")
  version=$(get_param_version "$LOCK_PARAM")
  jq -e --arg owner "$ORIGINAL_OWNER" --arg image "$ORIGINAL_SOURCE_SHA" '
    type == "object" and length == 7 and .schema == 1 and
    .kind == "durable-aop-cutover-recovery" and .owner == $owner and
    .image == $image and .orchestrator_sha == $image and
    (.created_at | type == "number" and . > 0 and floor == .) and
    .expires_at == 253402300799
  ' >/dev/null <<<"$lock" || {
    echo "original non-expiring e9 recovery lock is missing or mutated" >&2
    return 1
  }
  LOCK_JSON=$(jq -cS . <<<"$lock")
  digest=$(canonical_digest "$LOCK_JSON")
  [[ "$version" == "$APPROVED_ORIGINAL_LOCK_VERSION" &&
     "$LOCK_JSON" == "$APPROVED_ORIGINAL_LOCK" &&
     "$digest" == "$APPROVED_ORIGINAL_LOCK_DIGEST" ]] || {
    echo "live recovery lock is not the exact pinned SSM v${APPROVED_ORIGINAL_LOCK_VERSION} incident authority" >&2
    return 1
  }
}

validate_original_state() {
  local raw=$1 canonical digest
  jq -e --arg image "$ORIGINAL_SOURCE_SHA" --arg owner "$ORIGINAL_OWNER" '
    type == "object" and length == 8 and .schema == 2 and .image == $image and
    .orchestrator_sha == $image and .lock_owner == $owner and
    .phase == "old_servers_terminated" and
    ([.ac,.cell0,.cell1] | all(type == "object")) and
    (.ac | length == 8) and (.cell0 | length == 5) and (.cell1 | length == 5) and
    ([.ac.old_color,.ac.new_color,.cell0.old_color,.cell0.new_color,.cell1.old_color,.cell1.new_color] |
      all(. == "blue" or . == "green")) and
    (.ac.old_color != .ac.new_color) and (.cell0.old_color != .cell0.new_color) and
    (.cell1.old_color != .cell1.new_color) and
    ([.ac.old_asg,.ac.new_asg,.cell0.old_asg,.cell0.new_asg,.cell1.old_asg,.cell1.new_asg] |
      all(type == "string" and length > 0)) and
    (.ac.old_min | type == "number" and . >= 0 and floor == .) and
    (.ac.old_max | type == "number" and . > 0 and floor == .) and
    (.ac.old_desired | type == "number" and . > 0 and floor == .) and
    (.ac.old_max >= .ac.old_desired and .ac.old_desired >= .ac.old_min) and
    ([.ac.new_attestation,.cell0.new_attestation,.cell1.new_attestation] |
      all(type == "string" and startswith("v2|durable-aop-v1|")))
  ' >/dev/null <<<"$raw" || {
    echo "recovery only adopts the exact canonical schema-2 e9 old_servers_terminated state" >&2
    return 1
  }
  canonical=$(jq -cS . <<<"$raw")
  digest=$(canonical_digest "$canonical")
  [[ "$canonical" == "$APPROVED_ORIGINAL_STATE" && "$digest" == "$APPROVED_ORIGINAL_STATE_DIGEST" ]] || {
    echo "schema-2 state is not the exact pinned SSM v${APPROVED_ORIGINAL_STATE_VERSION} incident authority" >&2
    return 1
  }
}

assert_original_history() {
  local historical_state historical_lock live_lock
  historical_state=$(get_param "${STATE_PARAM}:${ORIGINAL_STATE_VERSION}")
  historical_state=$(jq -cS . <<<"$historical_state")
  [[ "$historical_state" == "$ORIGINAL_STATE" ]] || {
    echo "schema-3 adoption evidence no longer matches its exact SSM parameter versions" >&2
    return 1
  }
  live_lock=$(get_optional "$LOCK_PARAM")
  if [[ -n "$live_lock" ]]; then
    historical_lock=$(get_param "${LOCK_PARAM}:${ORIGINAL_LOCK_VERSION}")
    historical_lock=$(jq -cS . <<<"$historical_lock")
    [[ "$historical_lock" == "$ORIGINAL_LOCK" ]] || {
      echo "schema-3 lock evidence no longer matches exact SSM lock version" >&2
      return 1
    }
  else
    [[ "$PHASE" == complete ]] || {
      echo "schema-3 recovery lock disappeared before COMPLETE" >&2
      return 1
    }
  fi
  [[ "$ORIGINAL_STATE_VERSION" == "$APPROVED_ORIGINAL_STATE_VERSION" &&
     "$ORIGINAL_LOCK_VERSION" == "$APPROVED_ORIGINAL_LOCK_VERSION" &&
     "$ORIGINAL_STATE_DIGEST" == "$APPROVED_ORIGINAL_STATE_DIGEST" &&
     "$ORIGINAL_LOCK_DIGEST" == "$APPROVED_ORIGINAL_LOCK_DIGEST" &&
     "$ORIGINAL_STATE" == "$APPROVED_ORIGINAL_STATE" && "$ORIGINAL_LOCK" == "$APPROVED_ORIGINAL_LOCK" ]] || {
    echo "schema-3 adoption evidence is not the hard-pinned live incident authority" >&2
    return 1
  }
}

load_pinned_original_history() {
  local raw=$1
  ORIGINAL_STATE_VERSION=$(jq -er '.original.state_version | select(type == "number" and floor == .)' <<<"$raw")
  ORIGINAL_LOCK_VERSION=$(jq -er '.original.lock_version | select(type == "number" and floor == .)' <<<"$raw")
  [[ "$ORIGINAL_STATE_VERSION" == "$APPROVED_ORIGINAL_STATE_VERSION" &&
     "$ORIGINAL_LOCK_VERSION" == "$APPROVED_ORIGINAL_LOCK_VERSION" ]] || {
    echo "schema-3 ledger does not point at the exact pinned incident parameter versions" >&2
    return 1
  }
  ORIGINAL_STATE=$(get_param "${STATE_PARAM}:${ORIGINAL_STATE_VERSION}")
  ORIGINAL_STATE=$(jq -cS . <<<"$ORIGINAL_STATE")
  ORIGINAL_STATE_DIGEST=$(canonical_digest "$ORIGINAL_STATE")
  ORIGINAL_LOCK=$(jq -cS .original.lock <<<"$raw")
  ORIGINAL_LOCK_DIGEST=$(canonical_digest "$ORIGINAL_LOCK")
  [[ "$ORIGINAL_STATE" == "$APPROVED_ORIGINAL_STATE" &&
     "$ORIGINAL_STATE_DIGEST" == "$APPROVED_ORIGINAL_STATE_DIGEST" &&
     "$ORIGINAL_LOCK" == "$APPROVED_ORIGINAL_LOCK" &&
     "$ORIGINAL_LOCK_DIGEST" == "$APPROVED_ORIGINAL_LOCK_DIGEST" ]] || {
    echo "schema-3 ledger historical authorities differ from the exact pinned incident" >&2
    return 1
  }
}

validate_build_run() {
  local receipt
  receipt=$("$VERIFY_BUILD_ONLY" "$REPAIR_BUILD_RUN_ID" "$REPAIR_BUILD_RUN_ATTEMPT" "$REPAIR_SOURCE_SHA")
  [[ "$receipt" == "v1|${REPAIR_BUILD_RUN_ID}|${REPAIR_BUILD_RUN_ATTEMPT}|${REPAIR_SOURCE_SHA}" ]] || {
    echo "repair build-only receipt is malformed" >&2; return 1;
  }
}

validate_runtime_source() {
  local tree path blob computed manifest_lines=''
  # This manifest is repo-defined and source-addressed, unlike the temporary
  # reviewer workspace hash used while the runtime patch was still dirty.  Git
  # blob IDs bind exact bytes; the outer SHA-256 binds the fixed production path order and
  # prevents a same-content file substitution.
  tree=$(gh api "repos/${GITHUB_REPOSITORY}/git/trees/${REPAIR_SOURCE_SHA}?recursive=1")
  for path in \
    endpoints/ac/httpac.go \
    endpoints/ac/msghandler.go \
    endpoints/server/ac_session_control_admission.go \
    endpoints/server/httpserver.go \
    endpoints/server/msghandler.go \
    endpoints/server/session_control_owner_task_snapshot_store.go \
    endpoints/server/session_control_store.go \
    endpoints/server/session_control_target_attach_store.go \
    endpoints/server/session_control_target_store.go \
    endpoints/server/session_control_task_runtime.go \
    endpoints/server/session_control_task_store.go \
    endpoints/server/udpserver.go; do
    blob=$(jq -er --arg path "$path" '[.tree[] | select(.path == $path and .type == "blob") | .sha] | select(length == 1) | .[0] | select(test("^[0-9a-f]{40}$"))' <<<"$tree") || {
      echo "repair runtime source is missing canonical blob $path" >&2; return 1;
    }
    manifest_lines+="${blob}  ${path}"$'\n'
  done
  computed=$(printf '%s' "$manifest_lines" | sha256sum | awk '{print $1}')
  [[ "$computed" == "$APPROVED_REPAIR_RUNTIME_MANIFEST" ]] || {
    echo "repair runtime manifest mismatch: computed=$computed approved=$APPROVED_REPAIR_RUNTIME_MANIFEST" >&2
    return 1
  }
}

validate_original_run() {
  local run conclusion jobs
  run=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${ORIGINAL_RUN_ID}")
  jq -e --arg sha "$ORIGINAL_SOURCE_SHA" --argjson run_id "$ORIGINAL_RUN_ID" \
    --argjson run_attempt "$ORIGINAL_RUN_ATTEMPT" '
    .id == $run_id and .run_attempt == $run_attempt and
    .repository.full_name == "layervai/nhp" and .head_repository.full_name == "layervai/nhp" and
    .head_sha == $sha and .head_branch == "main" and .event == "push" and .status == "completed" and
    (.conclusion == "failure" or .conclusion == "timed_out" or .conclusion == "cancelled") and
    (.path == ".github/workflows/build-and-push.yml" or
     .path == "layervai/nhp/.github/workflows/build-and-push.yml@refs/heads/main")
  ' >/dev/null <<<"$run" || {
    echo "original cutover run is not the exact failed e9 main run" >&2
    return 1
  }

  conclusion=$(jq -er '.conclusion' <<<"$run")
  [[ "$conclusion" == cancelled ]] || return 0

  # This immutable attempt has 28 jobs, so exact page count/length parity proves
  # the per_page=100 response is complete. Cancellation is authoritative only when
  # the exact cell1 deploy failure caused the exact downstream validation
  # cancellation. This is not a general cancelled-run allowance.
  jobs=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${ORIGINAL_RUN_ID}/attempts/${ORIGINAL_RUN_ATTEMPT}/jobs?per_page=100")
  jq -e --arg sha "$ORIGINAL_SOURCE_SHA" --argjson run_id "$ORIGINAL_RUN_ID" \
    --argjson run_attempt "$ORIGINAL_RUN_ATTEMPT" --argjson expected_count "$ORIGINAL_CANCELLED_JOB_COUNT" \
    --argjson cell1_id "$ORIGINAL_CELL1_FAILURE_JOB_ID" \
    --argjson validation_id "$ORIGINAL_VALIDATION_CANCELLED_JOB_ID" '
    .total_count == $expected_count and (.jobs | type == "array") and
    (.jobs | length == $expected_count) and
    ([.jobs[] | select(.name == "Deploy Sandbox cell1 - Blue/Green")] | length == 1) and
    ([.jobs[] | select(.name == "Deploy Sandbox - Validate")] | length == 1) and
    ([.jobs[] | select(.id == $cell1_id)] | length == 1) and
    ([.jobs[] | select(.id == $validation_id)] | length == 1) and
    ([.jobs[] | select(.name == "Deploy Sandbox cell1 - Blue/Green")][0] |
      .id == $cell1_id and .run_id == $run_id and .run_attempt == $run_attempt and
      .workflow_name == "Build and Deploy NHP" and .head_sha == $sha and .head_branch == "main" and
      .status == "completed" and .conclusion == "failure") and
    ([.jobs[] | select(.name == "Deploy Sandbox - Validate")][0] |
      .id == $validation_id and .run_id == $run_id and .run_attempt == $run_attempt and
      .workflow_name == "Build and Deploy NHP" and .head_sha == $sha and .head_branch == "main" and
      .status == "completed" and .conclusion == "cancelled")
  ' >/dev/null <<<"$jobs" || {
    echo "cancelled original cutover run lacks the exact cell1-failure/validation-cancelled authority" >&2
    return 1
  }
}

assert_asg_zero() {
  local asg=$1 state
  state=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$asg" \
    --query 'AutoScalingGroups[0].[MinSize,MaxSize,DesiredCapacity,length(Instances)]' \
    --output text --region "$AWS_REGION")
  [[ "$state" == $'0\t0\t0\t0' || "$state" == '0 0 0 0' ]] || {
    echo "retired fleet $asg no longer has exact 0/0/0/0 authority: $state" >&2
    return 1
  }
}

assert_adopted_topology() {
  local old
  for old in "$(jq -r .ac.old_asg <<<"$ORIGINAL_STATE")" \
             "$(jq -r .cell0.old_asg <<<"$ORIGINAL_STATE")" \
             "$(jq -r .cell1.old_asg <<<"$ORIGINAL_STATE")"; do
    assert_asg_zero "$old"
  done
}

assert_schema2_live_authority() {
  local env component color asg attestation
  while IFS=$'\t' read -r env component color asg attestation; do
    [[ "$(get_param "/${env}/nhp/${component}/active-color")" == "$color" ]] || {
      echo "$env $component active color no longer matches the e9 ledger" >&2; return 1;
    }
    [[ "$(get_param "$(slot_asg_param "$env" "$component" "$color")")" == "$asg" ]] || {
      echo "$env $component active ASG no longer matches the e9 ledger" >&2; return 1;
    }
    [[ "$(get_param "$(slot_image_param "$env" "$component" "$color")")" == "$ORIGINAL_SOURCE_SHA" ]] || {
      echo "$env $component is not still serving the exact e9 image at adoption" >&2; return 1;
    }
    [[ "$(get_param "$(slot_attestation_param "$env" "$component" "$color")")" == "$attestation" ]] || {
      echo "$env $component prepared attestation no longer matches the e9 ledger" >&2; return 1;
    }
  done < <(jq -r '
    ["sandbox","ac",.ac.new_color,.ac.new_asg,.ac.new_attestation],
    ["sandbox","server",.cell0.new_color,.cell0.new_asg,.cell0.new_attestation],
    ["sandbox-cell1","server",.cell1.new_color,.cell1.new_asg,.cell1.new_attestation] | @tsv
  ' <<<"$ORIGINAL_STATE")
}

assert_completed_repair_slot() {
  local env=$1 component=$2 color=$3 asg=$4 provenance=$5 expected
  expected=$(expected_repair_attestation "$provenance" "$asg")
  [[ "$(get_param "/${env}/nhp/${component}/active-color")" == "$color" &&
     "$(get_param "$(slot_asg_param "$env" "$component" "$color")")" == "$asg" &&
     "$(get_param "$(slot_image_param "$env" "$component" "$color")")" == "$REPAIR_SOURCE_SHA" &&
     "$(get_param "$(slot_profile_param "$env" "$component" "$color")")" == "v1|${TARGET_PROFILE}|${REPAIR_SOURCE_SHA}" &&
     "$(get_param "$(slot_attestation_param "$env" "$component" "$color")")" == "$expected" ]] || {
    echo "$env $component completed repair authority has drifted" >&2
    return 1
  }
}

state_phase_order() {
  case "$1" in
    adopted) echo 10 ;;
    cell0_refreshing) echo 20 ;;
    cell0_refreshed) echo 30 ;;
    cell1_refreshing) echo 40 ;;
    cell1_refreshed) echo 50 ;;
    ac_refreshing) echo 60 ;;
    repaired) echo 70 ;;
    validated) echo 80 ;;
    complete) echo 90 ;;
    *) echo "invalid schema-3 recovery phase '$1'" >&2; return 1 ;;
  esac
}

validate_owner_intent() {
  jq -e --arg client "$APPROVED_CUSTOMER_CLIENT_ID" --arg subject "$APPROVED_CUSTOMER_SUBJECT" \
    --arg email "$APPROVED_CUSTOMER_EMAIL" --arg table "$APPROVED_CUSTOMER_TABLE" \
    --arg region "$AWS_REGION" --arg source "$REPAIR_SOURCE_SHA" '
    type == "object" and length == 15 and
    .schema == "layerv.durable-aop-customer-owner-intent.v1" and
    .client_id == $client and .subject == $subject and .email == $email and
    .table == $table and .region == $region and .source_sha == $source and
    (.provisioned_at | type == "string" and
      test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
    (.action == "create" or .action == "promote" or .action == "replay") and
    (.expected_row_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    ([.expected_created_at,.expected_updated_at] |
      all(type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))) and
    (.expected_usage | type == "string" and test("^(0|[1-9][0-9]*)$")) and
    (.expected_assigned_cell_id | type == "string" and
      (. == "" or test("^[a-z0-9]+(-[a-z0-9]+)*$"))) and
    ((.action == "create" and .before_row_sha256 == "absent") or
     (.action == "promote" and (.before_row_sha256 | test("^[0-9a-f]{64}$"))) or
     (.action == "replay" and .before_row_sha256 == .expected_row_sha256))
  ' >/dev/null <<<"$OWNER_INTENT" || {
    echo "schema-3 customer-owner intent is malformed or cross-bound" >&2
    return 1
  }
}

validate_owner_authority() {
  [[ -n "$OWNER_AUTHORITY" ]] || return 1
  jq -e '
    type == "object" and (keys | sort) == ["intent","status"] and
    (.status == "preparing" or .status == "ready") and (.intent | type == "object")
  ' >/dev/null <<<"$OWNER_AUTHORITY" || {
    echo "schema-3 customer-owner authority is malformed" >&2
    return 1
  }
  OWNER_STATUS=$(jq -r .status <<<"$OWNER_AUTHORITY")
  OWNER_INTENT=$(jq -cS .intent <<<"$OWNER_AUTHORITY")
  validate_owner_intent
}

validate_customer_lifecycle_receipt() {
  local version repository run attempt infra_sha integrations_sha artifact_id artifact_digest
  local producer_run producer_attempt nhp_artifact_id nhp_artifact_digest repair_sha recovery_sha
  local build_run build_attempt server_digest ac_digest authority_sha extra
  IFS='|' read -r version repository run attempt infra_sha integrations_sha artifact_id artifact_digest \
    producer_run producer_attempt nhp_artifact_id nhp_artifact_digest repair_sha recovery_sha \
    build_run build_attempt server_digest ac_digest authority_sha extra <<<"$CUSTOMER_LIFECYCLE_RECEIPT"
  [[ -z "$extra" && "$version" == v2 && "$repository" == layervai/qurl-integrations-infra &&
     "$run" =~ ^[1-9][0-9]*$ && "$attempt" =~ ^[1-9][0-9]*$ &&
     "$infra_sha" == "$APPROVED_CUSTOMER_INFRA_SHA" &&
     "$integrations_sha" == "$APPROVED_INTEGRATIONS_SHA" &&
     "$artifact_id" =~ ^[1-9][0-9]*$ && "$artifact_digest" =~ ^sha256:[0-9a-f]{64}$ &&
     "$producer_run" =~ ^[1-9][0-9]*$ && "$producer_attempt" =~ ^[1-9][0-9]*$ &&
     "$nhp_artifact_id" =~ ^[1-9][0-9]*$ && "$nhp_artifact_digest" =~ ^sha256:[0-9a-f]{64}$ &&
     "$repair_sha" == "$REPAIR_SOURCE_SHA" && "$recovery_sha" == "$RECOVERY_ORCHESTRATOR_SHA" &&
     "$build_run" == "$REPAIR_BUILD_RUN_ID" && "$build_attempt" == "$REPAIR_BUILD_RUN_ATTEMPT" &&
     "$server_digest" == "${SERVER_REPAIR_PROVENANCE##*|}" &&
     "$ac_digest" == "${AC_REPAIR_PROVENANCE##*|}" &&
     "$authority_sha" =~ ^[0-9a-f]{64}$ ]] || {
    echo "customer lifecycle receipt is malformed or cross-bound to another repair" >&2
    return 1
  }
}

validate_connector_lifecycle_receipt() {
  local version repository run attempt merge_sha pr_head_sha qurl_go_sha artifact_id artifact_digest
  local controller_run controller_attempt producer_run producer_attempt controller_sha nhp_sha server_digest extra
  IFS='|' read -r version repository run attempt merge_sha pr_head_sha qurl_go_sha artifact_id artifact_digest \
    controller_run controller_attempt producer_run producer_attempt controller_sha nhp_sha server_digest extra \
    <<<"$CONNECTOR_LIFECYCLE_RECEIPT"
  [[ -z "$extra" && "$version" == v1 && "$repository" == layervai/qurl-connector &&
     "$run" =~ ^[1-9][0-9]*$ && "$attempt" =~ ^[1-9][0-9]*$ &&
     "$merge_sha" =~ ^[0-9a-f]{40}$ && "$pr_head_sha" == "$APPROVED_CONNECTOR_PR_HEAD_SHA" &&
     "$qurl_go_sha" == d02c25995df085f0437c7a572714c26e907a8a59 &&
     "$artifact_id" =~ ^[1-9][0-9]*$ && "$artifact_digest" =~ ^sha256:[0-9a-f]{64}$ &&
     "$controller_run" =~ ^[1-9][0-9]*$ && "$controller_attempt" =~ ^[1-9][0-9]*$ &&
     "$producer_run" =~ ^[1-9][0-9]*$ && "$producer_attempt" =~ ^[1-9][0-9]*$ &&
     "$controller_sha" == "$RECOVERY_ORCHESTRATOR_SHA" && "$nhp_sha" == "$REPAIR_SOURCE_SHA" &&
     "$server_digest" == "${SERVER_REPAIR_PROVENANCE##*|}" ]] || {
    echo "connector lifecycle receipt is malformed or cross-bound to another repair" >&2
    return 1
  }
}

validate_phase_fields() {
  local expected_server_c0 expected_server_c1 expected_ac
  expected_server_c0=$(expected_repair_attestation "$SERVER_REPAIR_PROVENANCE" "$(jq -r .cell0.new_asg <<<"$ORIGINAL_STATE")")
  expected_server_c1=$(expected_repair_attestation "$SERVER_REPAIR_PROVENANCE" "$(jq -r .cell1.new_asg <<<"$ORIGINAL_STATE")")
  expected_ac=$(expected_repair_attestation "$AC_REPAIR_PROVENANCE" "$(jq -r .ac.new_asg <<<"$ORIGINAL_STATE")")
  [[ -z "$CELL0_REPAIR_REFRESH_ID" || "$CELL0_REPAIR_REFRESH_ID" =~ ^[A-Za-z0-9-]+$ ]]
  [[ -z "$CELL1_REPAIR_REFRESH_ID" || "$CELL1_REPAIR_REFRESH_ID" =~ ^[A-Za-z0-9-]+$ ]]
  [[ -z "$AC_REPAIR_REFRESH_ID" || "$AC_REPAIR_REFRESH_ID" =~ ^[A-Za-z0-9-]+$ ]]
  [[ -z "$REPAIR_REFRESH_INTENT" || "$REPAIR_REFRESH_INTENT" =~ ^v1\|[0-9a-f]{64}\|(-|[A-Za-z0-9-]+)$ ]]
  if [[ -n "$OWNER_AUTHORITY" ]]; then
    validate_owner_authority
  else
    OWNER_STATUS=
    OWNER_INTENT=
  fi
  case "$PHASE" in
    adopted)
      [[ -z "$CELL0_REPAIR_ATTESTATION$CELL1_REPAIR_ATTESTATION$AC_REPAIR_ATTESTATION" &&
         -z "$CELL0_REPAIR_REFRESH_ID$CELL1_REPAIR_REFRESH_ID$AC_REPAIR_REFRESH_ID" &&
         -z "$REPAIR_REFRESH_INTENT" &&
         -z "$OWNER_AUTHORITY" &&
         -z "$CUSTOMER_LIFECYCLE_RECEIPT$CONNECTOR_LIFECYCLE_RECEIPT" ]]
      ;;
    cell0_refreshing)
      [[ -z "$CELL0_REPAIR_ATTESTATION$CELL1_REPAIR_ATTESTATION$AC_REPAIR_ATTESTATION" &&
         -z "$CELL1_REPAIR_REFRESH_ID$AC_REPAIR_REFRESH_ID" &&
         -z "$OWNER_AUTHORITY" &&
         -z "$CUSTOMER_LIFECYCLE_RECEIPT$CONNECTOR_LIFECYCLE_RECEIPT" ]]
      [[ -z "$CELL0_REPAIR_REFRESH_ID" || -z "$REPAIR_REFRESH_INTENT" ]]
      ;;
    cell0_refreshed)
      [[ "$CELL0_REPAIR_ATTESTATION" == "$expected_server_c0" && -n "$CELL0_REPAIR_REFRESH_ID" &&
         -z "$REPAIR_REFRESH_INTENT" &&
         -z "$OWNER_AUTHORITY" &&
         -z "$CELL1_REPAIR_ATTESTATION$AC_REPAIR_ATTESTATION$CELL1_REPAIR_REFRESH_ID$AC_REPAIR_REFRESH_ID" &&
         -z "$CUSTOMER_LIFECYCLE_RECEIPT$CONNECTOR_LIFECYCLE_RECEIPT" ]]
      ;;
    cell1_refreshing)
      [[ "$CELL0_REPAIR_ATTESTATION" == "$expected_server_c0" && -z "$CELL1_REPAIR_ATTESTATION" &&
         -n "$CELL0_REPAIR_REFRESH_ID" &&
         -z "$OWNER_AUTHORITY" &&
         -z "$AC_REPAIR_ATTESTATION$AC_REPAIR_REFRESH_ID" &&
         -z "$CUSTOMER_LIFECYCLE_RECEIPT$CONNECTOR_LIFECYCLE_RECEIPT" ]]
      [[ -z "$CELL1_REPAIR_REFRESH_ID" || -z "$REPAIR_REFRESH_INTENT" ]]
      ;;
    cell1_refreshed)
      [[ "$CELL0_REPAIR_ATTESTATION" == "$expected_server_c0" && "$CELL1_REPAIR_ATTESTATION" == "$expected_server_c1" &&
         -n "$CELL0_REPAIR_REFRESH_ID" && -n "$CELL1_REPAIR_REFRESH_ID" && -z "$REPAIR_REFRESH_INTENT" &&
         -z "$OWNER_AUTHORITY" &&
         -z "$AC_REPAIR_ATTESTATION$AC_REPAIR_REFRESH_ID$CUSTOMER_LIFECYCLE_RECEIPT$CONNECTOR_LIFECYCLE_RECEIPT" ]]
      ;;
    ac_refreshing)
      [[ "$CELL0_REPAIR_ATTESTATION" == "$expected_server_c0" && "$CELL1_REPAIR_ATTESTATION" == "$expected_server_c1" &&
         -n "$CELL0_REPAIR_REFRESH_ID" && -n "$CELL1_REPAIR_REFRESH_ID" &&
         -z "$OWNER_AUTHORITY" &&
         -z "$AC_REPAIR_ATTESTATION$CUSTOMER_LIFECYCLE_RECEIPT$CONNECTOR_LIFECYCLE_RECEIPT" ]]
      [[ -z "$AC_REPAIR_REFRESH_ID" || -z "$REPAIR_REFRESH_INTENT" ]]
      ;;
    repaired)
      [[ "$CELL0_REPAIR_ATTESTATION" == "$expected_server_c0" && "$CELL1_REPAIR_ATTESTATION" == "$expected_server_c1" &&
         "$AC_REPAIR_ATTESTATION" == "$expected_ac" && -n "$CELL0_REPAIR_REFRESH_ID" &&
         -n "$CELL1_REPAIR_REFRESH_ID" && -n "$AC_REPAIR_REFRESH_ID" &&
         -z "$REPAIR_REFRESH_INTENT" &&
         -z "$CUSTOMER_LIFECYCLE_RECEIPT$CONNECTOR_LIFECYCLE_RECEIPT" ]]
      [[ -z "$OWNER_AUTHORITY" || "$OWNER_STATUS" == preparing || "$OWNER_STATUS" == ready ]]
      ;;
    validated|complete)
      [[ "$CELL0_REPAIR_ATTESTATION" == "$expected_server_c0" && "$CELL1_REPAIR_ATTESTATION" == "$expected_server_c1" &&
         "$AC_REPAIR_ATTESTATION" == "$expected_ac" && -n "$CELL0_REPAIR_REFRESH_ID" &&
         -n "$CELL1_REPAIR_REFRESH_ID" && -n "$AC_REPAIR_REFRESH_ID" &&
         -z "$REPAIR_REFRESH_INTENT" &&
         "$OWNER_STATUS" == ready &&
         -n "$CUSTOMER_LIFECYCLE_RECEIPT" && -n "$CONNECTOR_LIFECYCLE_RECEIPT" ]]
      validate_customer_lifecycle_receipt
      validate_connector_lifecycle_receipt
      ;;
  esac || {
    echo "schema-3 phase $PHASE has an impossible refresh, attestation, or lifecycle-receipt tuple" >&2
    return 1
  }
}

write_state() {
  local next=$1 c0=${CELL0_REPAIR_ATTESTATION:-} c1=${CELL1_REPAIR_ATTESTATION:-} ac=${AC_REPAIR_ATTESTATION:-}
  local c0_refresh=${CELL0_REPAIR_REFRESH_ID:-} c1_refresh=${CELL1_REPAIR_REFRESH_ID:-} ac_refresh=${AC_REPAIR_REFRESH_ID:-}
  local refresh_intent=${REPAIR_REFRESH_INTENT:-}
  local owner_authority=${OWNER_AUTHORITY:-}
  local customer_lifecycle=${CUSTOMER_LIFECYCLE_RECEIPT:-} connector_lifecycle=${CONNECTOR_LIFECYCLE_RECEIPT:-}
  STATE=$(jq -cn --arg phase "$next" \
    --arg original_digest "$ORIGINAL_STATE_DIGEST" --argjson original_version "$ORIGINAL_STATE_VERSION" \
    --argjson lock "$ORIGINAL_LOCK" --arg lock_digest "$ORIGINAL_LOCK_DIGEST" \
    --argjson lock_version "$ORIGINAL_LOCK_VERSION" --arg recovery_sha "$RECOVERY_ORCHESTRATOR_SHA" \
    --arg repair_sha "$REPAIR_SOURCE_SHA" \
    --arg build_run "$REPAIR_BUILD_RUN_ID" --arg build_attempt "$REPAIR_BUILD_RUN_ATTEMPT" \
    --arg runtime_manifest "$APPROVED_REPAIR_RUNTIME_MANIFEST" \
    --arg server_provenance "$SERVER_REPAIR_PROVENANCE" --arg ac_provenance "$AC_REPAIR_PROVENANCE" \
    --arg cell0_attestation "$c0" --arg cell1_attestation "$c1" --arg ac_attestation "$ac" \
    --arg cell0_refresh_id "$c0_refresh" --arg cell1_refresh_id "$c1_refresh" --arg ac_refresh_id "$ac_refresh" \
    --arg customer_lifecycle "$customer_lifecycle" --arg connector_lifecycle "$connector_lifecycle" '
      {schema:3,phase:$phase,original:{state_version:$original_version,state_sha256:$original_digest,
       lock:$lock,lock_version:$lock_version,lock_sha256:$lock_digest},
       repair:{orchestrator_sha:$recovery_sha,source_sha:$repair_sha,build_run_id:$build_run,
         build_run_attempt:$build_attempt,
         runtime_manifest:$runtime_manifest,server_provenance:$server_provenance,
         ac_provenance:$ac_provenance,cell0_attestation:$cell0_attestation,
         cell1_attestation:$cell1_attestation,ac_attestation:$ac_attestation,
         cell0_refresh_id:$cell0_refresh_id,cell1_refresh_id:$cell1_refresh_id,ac_refresh_id:$ac_refresh_id,
         customer_lifecycle:$customer_lifecycle,connector_lifecycle:$connector_lifecycle}}')
  if [[ -n "$refresh_intent" ]]; then
    STATE=$(jq -c --arg intent "$refresh_intent" '.repair.refresh_intent = $intent' <<<"$STATE")
  fi
  if [[ -n "$owner_authority" ]]; then
    [[ -z "$refresh_intent" ]] || { echo "owner authority and refresh intent cannot coexist" >&2; return 1; }
    STATE=$(jq -c --argjson owner "$owner_authority" '.repair.owner = $owner' <<<"$STATE")
  fi
  if [[ "${RECOVERY_HANDOFF_PENDING:-false}" == true ]]; then
    [[ "$(jq -r .repair.orchestrator_sha <<<"$STATE")" == "$RECOVERY_ORCHESTRATOR_SHA" ]] || {
      echo "schema-3 one-hop state transition did not install successor authority" >&2
      return 1
    }
  fi
  put_param "$STATE_PARAM" "$STATE"
  [[ "$(get_param "$STATE_PARAM")" == "$STATE" ]] || { echo "schema-3 state write did not strongly round trip" >&2; return 1; }
  RECOVERY_HANDOFF_PENDING=false
  PHASE=$next
  echo "durable AOP repair phase: $PHASE"
}

load_schema3() {
  local raw=$1 stored_recovery_sha state_version canonical digest
  jq -e --arg original_digest "$ORIGINAL_STATE_DIGEST" --arg lock_digest "$ORIGINAL_LOCK_DIGEST" \
    --arg recovery_sha "$RECOVERY_ORCHESTRATOR_SHA" \
    --arg predecessor_sha "$APPROVED_RECOVERY_HANDOFF_PREDECESSOR_SHA" --arg repair_sha "$REPAIR_SOURCE_SHA" \
    --arg build_run "$REPAIR_BUILD_RUN_ID" --arg build_attempt "$REPAIR_BUILD_RUN_ATTEMPT" \
    --arg runtime_manifest "$APPROVED_REPAIR_RUNTIME_MANIFEST" \
    --arg server_provenance "$SERVER_REPAIR_PROVENANCE" --arg ac_provenance "$AC_REPAIR_PROVENANCE" '
    type == "object" and length == 4 and .schema == 3 and
    (.phase | type == "string") and (.original | type == "object" and length == 5) and
    .original.state_sha256 == $original_digest and .original.lock_sha256 == $lock_digest and
    (.original.lock | type == "object") and
    (.original.state_version | type == "number" and . > 0 and floor == .) and
    (.original.lock_version | type == "number" and . > 0 and floor == .) and
    (.repair | type == "object" and
      ((length == 15 and (has("refresh_intent") | not) and (has("owner") | not)) or
       (length == 16 and
         (((.refresh_intent | type == "string") and (has("owner") | not)) or
          ((.owner | type == "object") and (has("refresh_intent") | not)))))) and
    (.repair.orchestrator_sha == $recovery_sha or .repair.orchestrator_sha == $predecessor_sha) and
    .repair.source_sha == $repair_sha and
    .repair.build_run_id == $build_run and .repair.build_run_attempt == $build_attempt and
    .repair.runtime_manifest == $runtime_manifest and
    .repair.server_provenance == $server_provenance and .repair.ac_provenance == $ac_provenance and
    ([.repair.cell0_attestation,.repair.cell1_attestation,.repair.ac_attestation,
      .repair.cell0_refresh_id,.repair.cell1_refresh_id,.repair.ac_refresh_id,
      .repair.customer_lifecycle,.repair.connector_lifecycle] | all(type == "string"))
  ' >/dev/null <<<"$raw" || { echo "schema-3 recovery state is malformed or belongs to another repair" >&2; return 1; }
  stored_recovery_sha=$(jq -er '.repair.orchestrator_sha' <<<"$raw")
  RECOVERY_HANDOFF_PENDING=false
  state_version=$(get_param_version "$STATE_PARAM")
  [[ "$state_version" =~ ^[1-9][0-9]*$ ]] || {
    echo "schema-3 state version is not a canonical positive decimal" >&2
    return 1
  }
  if [[ "$stored_recovery_sha" == "$APPROVED_RECOVERY_HANDOFF_PREDECESSOR_SHA" ]]; then
    canonical=$(jq -cS . <<<"$raw")
    digest=$(canonical_digest "$canonical")
    [[ "$RECOVERY_ORCHESTRATOR_SHA" != "$APPROVED_RECOVERY_HANDOFF_PREDECESSOR_SHA" &&
       "$state_version" == "$APPROVED_RECOVERY_HANDOFF_STATE_VERSION" &&
       "$digest" == "$APPROVED_RECOVERY_HANDOFF_STATE_DIGEST" &&
       "$(jq -r .phase <<<"$raw")" == cell1_refreshing &&
       -n "${LIVE_LOCK:-}" && "$LOCK_JSON" == "$ORIGINAL_LOCK" ]] || {
      echo "schema-3 predecessor authority is not the exact live one-hop handoff boundary" >&2
      return 1
    }
    RECOVERY_HANDOFF_PENDING=true
  else
    [[ "$state_version" != "$APPROVED_RECOVERY_HANDOFF_STATE_VERSION" ]] || {
      echo "schema-3 SSM v${APPROVED_RECOVERY_HANDOFF_STATE_VERSION} cannot self-assert successor authority" >&2
      return 1
    }
  fi
  validate_original_state "$ORIGINAL_STATE"
  [[ "$ORIGINAL_LOCK" == "$APPROVED_ORIGINAL_LOCK" &&
     "$ORIGINAL_LOCK_DIGEST" == "$APPROVED_ORIGINAL_LOCK_DIGEST" &&
     "$LOCK_JSON" == "$ORIGINAL_LOCK" ]] || {
    echo "schema-3 state does not bind the exact original hard-lock history" >&2; return 1;
  }
  STATE=$raw
  PHASE=$(jq -r .phase <<<"$STATE")
  state_phase_order "$PHASE" >/dev/null
  CELL0_REPAIR_ATTESTATION=$(jq -r .repair.cell0_attestation <<<"$STATE")
  CELL1_REPAIR_ATTESTATION=$(jq -r .repair.cell1_attestation <<<"$STATE")
  AC_REPAIR_ATTESTATION=$(jq -r .repair.ac_attestation <<<"$STATE")
  CELL0_REPAIR_REFRESH_ID=$(jq -r .repair.cell0_refresh_id <<<"$STATE")
  CELL1_REPAIR_REFRESH_ID=$(jq -r .repair.cell1_refresh_id <<<"$STATE")
  AC_REPAIR_REFRESH_ID=$(jq -r .repair.ac_refresh_id <<<"$STATE")
  REPAIR_REFRESH_INTENT=$(jq -r '.repair.refresh_intent // ""' <<<"$STATE")
  OWNER_AUTHORITY=$(jq -cS '.repair.owner // empty' <<<"$STATE")
  CUSTOMER_LIFECYCLE_RECEIPT=$(jq -r .repair.customer_lifecycle <<<"$STATE")
  CONNECTOR_LIFECYCLE_RECEIPT=$(jq -r .repair.connector_lifecycle <<<"$STATE")
  validate_phase_fields
  assert_original_history
}

assert_original_fleet_authority() {
  local env=$1 component=$2 color=$3 expected_asg=$4 expected_attestation=$5
  [[ "$(get_param "$(slot_asg_param "$env" "$component" "$color")")" == "$expected_asg" ]] || {
    echo "$env $component adopted ASG authority drifted" >&2; return 1;
  }
  [[ "$(get_param "/${env}/nhp/${component}/active-color")" == "$color" ]] || {
    echo "$env $component active color drifted from the adopted incident" >&2; return 1;
  }
  if [[ "$component" == ac ]]; then
    [[ "$(get_param "$(slot_image_param "$env" "$component" "$color")")" == "$ORIGINAL_SOURCE_SHA" ]] || {
      echo "$env $component adopted image authority drifted" >&2; return 1;
    }
    [[ "$(get_param "$(slot_attestation_param "$env" "$component" "$color")")" == "$expected_attestation" ]] || {
      echo "$env $component adopted attestation authority drifted" >&2; return 1;
    }
  fi
}

expected_repair_attestation() {
  printf 'v2|%s|%s|%s\n' "$TARGET_PROFILE" "${1#v1|}" "$2"
}

refresh_intent_digest() {
  local label=$1 asg=$2
  printf 'v1\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
    "$label" "$asg" "$REPAIR_SOURCE_SHA" "$REPAIR_BUILD_RUN_ID" "$REPAIR_BUILD_RUN_ATTEMPT" \
    "$RECOVERY_ORCHESTRATOR_SHA" "$REFRESH_PREFERENCES" | sha256sum | awk '{print $1}'
}

get_refresh_intent() {
  [[ "$1" == cell0 || "$1" == cell1 || "$1" == ac ]] || {
    echo "unknown repair refresh label '$1'" >&2
    return 1
  }
  printf '%s\n' "${REPAIR_REFRESH_INTENT:-}"
}

set_refresh_intent() {
  [[ "$1" == cell0 || "$1" == cell1 || "$1" == ac ]] || {
    echo "unknown repair refresh label '$1'" >&2
    return 1
  }
  REPAIR_REFRESH_INTENT=$2
}

list_bounded_refreshes() {
  local asg=$1 result
  # AWS defines this response in descending creation-timestamp order.  The
  # classifier below relies on that service contract and accepts at most one
  # exact successor immediately before its persisted prior-ID boundary.  A
  # boundary missing from this bounded newest-20 page is corruption, not a
  # reason to scan an unbounded history or start another refresh.
  result=$(aws autoscaling describe-instance-refreshes --auto-scaling-group-name "$asg" \
    --max-records 20 --output json --region "$AWS_REGION") || return
  jq -e '
    type == "object" and (.InstanceRefreshes | type == "array" and length <= 20) and
    ([.InstanceRefreshes[] | .InstanceRefreshId] |
      all(type == "string" and test("^[A-Za-z0-9-]+$")) and length == (unique | length))
  ' >/dev/null <<<"$result" || {
    echo "instance-refresh inventory for $asg is malformed or unbounded" >&2
    return 1
  }
  printf '%s\n' "$result"
}

prepare_refresh_intent() {
  local label=$1 asg=$2 intent expected inventory prior
  intent=$(get_refresh_intent "$label")
  expected=$(refresh_intent_digest "$label" "$asg")
  if [[ -n "$intent" ]]; then
    [[ "$intent" =~ ^v1\|${expected}\|(-|[A-Za-z0-9-]+)$ ]] || {
      echo "$label refresh intent is malformed or belongs to another repair" >&2
      return 1
    }
    LAST_REFRESH_INTENT=$intent
    return 0
  fi

  inventory=$(list_bounded_refreshes "$asg") || return
  jq -e '[.InstanceRefreshes[] | select(.Status == "Pending" or .Status == "InProgress")] | length == 0' \
    >/dev/null <<<"$inventory" || {
    echo "$label has an unowned in-progress refresh; refusing to create recovery intent" >&2
    return 1
  }
  prior=$(jq -r '.InstanceRefreshes[0].InstanceRefreshId // "-"' <<<"$inventory")
  intent="v1|${expected}|${prior}"
  set_refresh_intent "$label" "$intent"
  write_state "$PHASE"
  LAST_REFRESH_INTENT=$intent
}

classify_intent_refresh() {
  local label=$1 asg=$2 intent=$3 inventory prior candidate count prior_index
  prior=${intent##*|}
  inventory=$(list_bounded_refreshes "$asg") || return
  count=$(jq -r '.InstanceRefreshes | length' <<<"$inventory") || return
  if [[ "$prior" == - ]]; then
    (( count <= 1 )) || {
      echo "$label refresh history advanced more than once after its durable intent" >&2
      return 1
    }
    (( count == 1 )) || return 2
    candidate=$(jq -r '.InstanceRefreshes[0].InstanceRefreshId' <<<"$inventory")
  else
    prior_index=$(jq -r --arg prior "$prior" \
      '[.InstanceRefreshes[].InstanceRefreshId] | index($prior) // -1' <<<"$inventory")
    if (( prior_index == 0 )); then
      return 2
    fi
    (( prior_index == 1 )) || {
      echo "$label refresh history does not have one exact successor to its durable boundary" >&2
      return 1
    }
    candidate=$(jq -r '.InstanceRefreshes[0].InstanceRefreshId' <<<"$inventory")
  fi
  jq -e --arg id "$candidate" --argjson preferences "$REFRESH_PREFERENCES" '
    [.InstanceRefreshes[] | select(.InstanceRefreshId == $id)] as $matches |
    ($matches | length == 1) and
    ($matches[0].Status == "Pending" or $matches[0].Status == "InProgress" or $matches[0].Status == "Successful") and
    $matches[0].Preferences == $preferences
  ' >/dev/null <<<"$inventory" || {
    echo "$label candidate refresh is not the exact repair shape" >&2
    return 1
  }
  printf '%s\n' "$candidate"
}

record_refresh_id() {
  local label=$1 refresh_id=$2
  case "$label" in
    cell0) CELL0_REPAIR_REFRESH_ID=$refresh_id ;;
    cell1) CELL1_REPAIR_REFRESH_ID=$refresh_id ;;
    ac) AC_REPAIR_REFRESH_ID=$refresh_id ;;
    *) echo "unknown repair refresh label '$label'" >&2; return 1 ;;
  esac
  REPAIR_REFRESH_INTENT=
  write_state "$PHASE"
}

refresh_active_component() {
  local env=$1 component=$2 color=$3 asg=$4 label=$5 persisted=$6 persisted_refresh=$7 provenance=$8 health=$9
  local image_param profile_param attestation_param expected image attestation refresh_id in_progress max_iterations original_attestation
  local intent classify_status
  image_param=$(slot_image_param "$env" "$component" "$color")
  profile_param=$(slot_profile_param "$env" "$component" "$color")
  attestation_param=$(slot_attestation_param "$env" "$component" "$color")
  expected=$(expected_repair_attestation "$provenance" "$asg")
  if [[ -z "$persisted_refresh" ]]; then
    prepare_refresh_intent "$label" "$asg"
    intent=$LAST_REFRESH_INTENT
  else
    intent=
  fi
  [[ -z "$persisted" || "$persisted" == "$expected" ]] || { echo "$label persisted repair attestation changed" >&2; return 1; }
  [[ "$(get_param "/${env}/nhp/${component}/active-color")" == "$color" ]] || {
    echo "$label active color drifted before repair refresh" >&2; return 1;
  }
  [[ "$(get_param "$(slot_asg_param "$env" "$component" "$color")")" == "$asg" ]] || {
    echo "$label active ASG drifted before repair refresh" >&2; return 1;
  }
  image=$(get_param "$image_param")
  [[ "$image" == "$ORIGINAL_SOURCE_SHA" || "$image" == "$REPAIR_SOURCE_SHA" ]] || {
    echo "$label active image was mutated outside the adopted recovery" >&2; return 1;
  }
  attestation=$(get_optional "$attestation_param")
  if [[ "$image" == "$REPAIR_SOURCE_SHA" && "$attestation" == "$expected" &&
        "$(get_param "$profile_param")" == "v1|${TARGET_PROFILE}|${REPAIR_SOURCE_SHA}" ]]; then
    "$VERIFY_ASG" "$asg" "$label-repair" 15 "$health"
    LAST_REPAIR_ATTESTATION=$expected
    return 0
  fi
  if [[ "$component" == ac ]]; then original_attestation=$(jq -r .ac.new_attestation <<<"$ORIGINAL_STATE"); else original_attestation=$(jq -r ".${label}.new_attestation" <<<"$ORIGINAL_STATE"); fi
  [[ -z "$attestation" || "$attestation" == "$expected" || "$attestation" == "$original_attestation" ]] || {
    echo "$label prepared attestation was mutated outside recovery" >&2; return 1;
  }
  if [[ -n "$persisted_refresh" ]]; then
    [[ "$persisted_refresh" =~ ^[A-Za-z0-9-]+$ ]] || { echo "$label persisted refresh id is malformed" >&2; return 1; }
    in_progress=$(aws autoscaling describe-instance-refreshes --auto-scaling-group-name "$asg" \
      --instance-refresh-ids "$persisted_refresh" --query 'InstanceRefreshes[0].Status' \
      --output text --region "$AWS_REGION")
    [[ "$in_progress" == Pending || "$in_progress" == InProgress || "$in_progress" == Successful ]] || {
      echo "$label persisted refresh $persisted_refresh is missing or terminally failed ($in_progress)" >&2
      return 1
    }
    refresh_id=$persisted_refresh
  else
    classify_status=0
    refresh_id=$(classify_intent_refresh "$label" "$asg" "$intent") || classify_status=$?
    (( classify_status == 0 || classify_status == 2 )) || return "$classify_status"
  fi
  delete_optional "$attestation_param"
  put_param "$image_param" "$REPAIR_SOURCE_SHA"
  put_param "$profile_param" "v1|${TARGET_PROFILE}|${REPAIR_SOURCE_SHA}"
  if [[ -z "$persisted_refresh" && "$classify_status" == 2 ]]; then
    refresh_id=$(aws autoscaling start-instance-refresh --auto-scaling-group-name "$asg" \
      --preferences "$REFRESH_PREFERENCES" \
      --query InstanceRefreshId --output text --region "$AWS_REGION")
    [[ "$refresh_id" =~ ^[A-Za-z0-9-]+$ ]] || { echo "$label refresh id is malformed" >&2; return 1; }
    record_refresh_id "$label" "$refresh_id"
  elif [[ -z "$persisted_refresh" ]]; then
    record_refresh_id "$label" "$refresh_id"
  fi
  [[ "$refresh_id" =~ ^[A-Za-z0-9-]+$ ]] || { echo "$label refresh id is malformed" >&2; return 1; }
  max_iterations=$((REFRESH_TIMEOUT_MINUTES * 6))
  # Test fixtures replace this helper with a source-compatible deterministic
  # implementation; production always uses the checked-in path above.
  # shellcheck disable=SC1090,SC1091
  source "$WAIT_REFRESH"
  wait_for_instance_refresh "$asg" "$refresh_id" '' "$max_iterations" "$label" 10 3
  "$VERIFY_ASG" "$asg" "$label-repair" 15 "$health"
  put_param "$attestation_param" "$expected"
  [[ "$(get_param "$image_param")" == "$REPAIR_SOURCE_SHA" && "$(get_param "$profile_param")" == "v1|${TARGET_PROFILE}|${REPAIR_SOURCE_SHA}" &&
     "$(get_param "$attestation_param")" == "$expected" ]] || { echo "$label repair authority did not converge" >&2; return 1; }
  LAST_REPAIR_ATTESTATION=$expected
}

validate_original_run
validate_build_run
validate_runtime_source
SERVER_REPAIR_PROVENANCE=$("$VERIFY_PROVENANCE" layerv/nhp-server "$REPAIR_SOURCE_SHA")
AC_REPAIR_PROVENANCE=$("$VERIFY_PROVENANCE" layerv/nhp-ac "$REPAIR_SOURCE_SHA")
[[ "$SERVER_REPAIR_PROVENANCE" == "v1|${REPAIR_SOURCE_SHA}|layerv/nhp-server|sha256:"* ]] || { echo "server repair provenance is malformed" >&2; exit 1; }
[[ "$AC_REPAIR_PROVENANCE" == "v1|${REPAIR_SOURCE_SHA}|layerv/nhp-ac|sha256:"* ]] || { echo "AC repair provenance is malformed" >&2; exit 1; }

RAW_STATE=$(get_param "$STATE_PARAM")
LIVE_LOCK=$(get_optional "$LOCK_PARAM")
if jq -e '.schema == 3 and .phase == "complete"' >/dev/null 2>&1 <<<"$RAW_STATE" && [[ -z "$LIVE_LOCK" ]]; then
  load_pinned_original_history "$RAW_STATE"
  LOCK_JSON=$ORIGINAL_LOCK
  load_schema3 "$RAW_STATE"
  assert_adopted_topology
  AC_COLOR=$(jq -r .ac.new_color <<<"$ORIGINAL_STATE"); AC_ASG=$(jq -r .ac.new_asg <<<"$ORIGINAL_STATE")
  CELL0_COLOR=$(jq -r .cell0.new_color <<<"$ORIGINAL_STATE"); CELL0_ASG=$(jq -r .cell0.new_asg <<<"$ORIGINAL_STATE")
  CELL1_COLOR=$(jq -r .cell1.new_color <<<"$ORIGINAL_STATE"); CELL1_ASG=$(jq -r .cell1.new_asg <<<"$ORIGINAL_STATE")
  assert_completed_repair_slot sandbox server "$CELL0_COLOR" "$CELL0_ASG" "$SERVER_REPAIR_PROVENANCE"
  assert_completed_repair_slot sandbox-cell1 server "$CELL1_COLOR" "$CELL1_ASG" "$SERVER_REPAIR_PROVENANCE"
  assert_completed_repair_slot sandbox ac "$AC_COLOR" "$AC_ASG" "$AC_REPAIR_PROVENANCE"
  validate_customer_lifecycle_receipt
  validate_connector_lifecycle_receipt
  "$OWNER_PROJECTOR" verify-current --intent-json "$OWNER_INTENT" >/dev/null
  [[ "$(get_param "$FLOOR_PARAM")" == "$TARGET_PROFILE" ]] || { echo "completed durable profile floor is missing" >&2; exit 1; }
  echo "durable AOP schema-3 recovery is already complete at repair source $REPAIR_SOURCE_SHA"
  exit 0
fi
require_hard_lock
if jq -e '.schema == 2' >/dev/null 2>&1 <<<"$RAW_STATE"; then
  validate_original_state "$RAW_STATE"
  ORIGINAL_STATE=$(jq -cS . <<<"$RAW_STATE")
  ORIGINAL_STATE_VERSION=$(get_param_version "$STATE_PARAM")
  ORIGINAL_STATE_DIGEST=$(canonical_digest "$ORIGINAL_STATE")
  ORIGINAL_LOCK=$(jq -cS . <<<"$LOCK_JSON")
  ORIGINAL_LOCK_VERSION=$(get_param_version "$LOCK_PARAM")
  ORIGINAL_LOCK_DIGEST=$(canonical_digest "$ORIGINAL_LOCK")
  [[ "$ORIGINAL_STATE_VERSION" == "$APPROVED_ORIGINAL_STATE_VERSION" &&
     "$ORIGINAL_LOCK_VERSION" == "$APPROVED_ORIGINAL_LOCK_VERSION" &&
     "$ORIGINAL_STATE_DIGEST" == "$APPROVED_ORIGINAL_STATE_DIGEST" &&
     "$ORIGINAL_LOCK_DIGEST" == "$APPROVED_ORIGINAL_LOCK_DIGEST" ]] || {
    echo "live schema-2 state/lock versions are not the pinned incident authority" >&2
    exit 1
  }
  PHASE=adopted
  CELL0_REPAIR_ATTESTATION=
  CELL1_REPAIR_ATTESTATION=
  AC_REPAIR_ATTESTATION=
  CELL0_REPAIR_REFRESH_ID=
  CELL1_REPAIR_REFRESH_ID=
  AC_REPAIR_REFRESH_ID=
  REPAIR_REFRESH_INTENT=
  OWNER_AUTHORITY=
  OWNER_STATUS=
  OWNER_INTENT=
  CUSTOMER_LIFECYCLE_RECEIPT=
  CONNECTOR_LIFECYCLE_RECEIPT=
  assert_adopted_topology
  assert_schema2_live_authority
  write_state adopted
else
  load_pinned_original_history "$RAW_STATE"
  load_schema3 "$RAW_STATE"
fi

assert_adopted_topology

AC_COLOR=$(jq -r .ac.new_color <<<"$ORIGINAL_STATE")
AC_ASG=$(jq -r .ac.new_asg <<<"$ORIGINAL_STATE")
AC_ATTESTATION=$(jq -r .ac.new_attestation <<<"$ORIGINAL_STATE")
CELL0_COLOR=$(jq -r .cell0.new_color <<<"$ORIGINAL_STATE")
CELL0_ASG=$(jq -r .cell0.new_asg <<<"$ORIGINAL_STATE")
CELL1_COLOR=$(jq -r .cell1.new_color <<<"$ORIGINAL_STATE")
CELL1_ASG=$(jq -r .cell1.new_asg <<<"$ORIGINAL_STATE")

require_hard_lock
if (( $(state_phase_order "$PHASE") < $(state_phase_order ac_refreshing) )); then
  assert_original_fleet_authority sandbox ac "$AC_COLOR" "$AC_ASG" "$AC_ATTESTATION"
fi
assert_original_fleet_authority sandbox server "$CELL0_COLOR" "$CELL0_ASG" "$(jq -r .cell0.new_attestation <<<"$ORIGINAL_STATE")"
assert_original_fleet_authority sandbox-cell1 server "$CELL1_COLOR" "$CELL1_ASG" "$(jq -r .cell1.new_attestation <<<"$ORIGINAL_STATE")"

if (( $(state_phase_order "$PHASE") < $(state_phase_order cell0_refreshed) )); then
  [[ "$PHASE" == cell0_refreshing ]] || write_state cell0_refreshing
  refresh_active_component sandbox server "$CELL0_COLOR" "$CELL0_ASG" cell0 "$CELL0_REPAIR_ATTESTATION" \
    "$CELL0_REPAIR_REFRESH_ID" "$SERVER_REPAIR_PROVENANCE" 'curl -sfS -o /dev/null http://127.0.0.1:8888/health/live'
  CELL0_REPAIR_ATTESTATION=$LAST_REPAIR_ATTESTATION
  write_state cell0_refreshed
fi
if (( $(state_phase_order "$PHASE") < $(state_phase_order cell1_refreshed) )); then
  [[ "$PHASE" == cell1_refreshing ]] || write_state cell1_refreshing
  refresh_active_component sandbox-cell1 server "$CELL1_COLOR" "$CELL1_ASG" cell1 "$CELL1_REPAIR_ATTESTATION" \
    "$CELL1_REPAIR_REFRESH_ID" "$SERVER_REPAIR_PROVENANCE" 'curl -sfS -o /dev/null http://127.0.0.1:8888/health/live'
  CELL1_REPAIR_ATTESTATION=$LAST_REPAIR_ATTESTATION
  write_state cell1_refreshed
fi
if (( $(state_phase_order "$PHASE") < $(state_phase_order repaired) )); then
  [[ "$PHASE" == ac_refreshing ]] || write_state ac_refreshing
  refresh_active_component sandbox ac "$AC_COLOR" "$AC_ASG" ac "$AC_REPAIR_ATTESTATION" \
    "$AC_REPAIR_REFRESH_ID" "$AC_REPAIR_PROVENANCE" 'systemctl is-active --quiet nhp-acd && systemctl is-active --quiet traefik && curl -sfS -o /dev/null http://127.0.0.1:8080/ping'
  AC_REPAIR_ATTESTATION=$LAST_REPAIR_ATTESTATION
  write_state repaired
fi

# Fleet repair is durable before customer-owner preparation. The exact owner
# intent, including its expected final row digest, is then persisted under the
# repaired state before the first DynamoDB mutation. A lost response can only
# classify against that precommitted digest.
if [[ "$PHASE" == repaired && -z "$OWNER_AUTHORITY" ]]; then
  OWNER_INTENT=$("$OWNER_PROJECTOR" plan \
    --table "$APPROVED_CUSTOMER_TABLE" \
    --client-id "$APPROVED_CUSTOMER_CLIENT_ID" \
    --region "$AWS_REGION" \
    --provisioned-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --source-sha "$REPAIR_SOURCE_SHA")
  OWNER_INTENT=$(jq -cS . <<<"$OWNER_INTENT")
  validate_owner_intent
  OWNER_STATUS=preparing
  OWNER_AUTHORITY=$(jq -cn --argjson intent "$OWNER_INTENT" '{status:"preparing",intent:$intent}')
  write_state repaired
fi
if [[ "$PHASE" == repaired && "$OWNER_STATUS" == preparing ]]; then
  owner_digest=$("$OWNER_PROJECTOR" apply --intent-json "$OWNER_INTENT")
  [[ "$owner_digest" == "$(jq -r .expected_row_sha256 <<<"$OWNER_INTENT")" ]] || {
    echo "customer-owner projector did not return the precommitted final row digest" >&2
    exit 1
  }
  OWNER_STATUS=ready
  OWNER_AUTHORITY=$(jq -cn --argjson intent "$OWNER_INTENT" '{status:"ready",intent:$intent}')
  write_state repaired
elif [[ "$PHASE" == repaired && "$OWNER_STATUS" == ready ]]; then
  owner_digest=$("$OWNER_PROJECTOR" verify --intent-json "$OWNER_INTENT")
  [[ "$owner_digest" == "$(jq -r .expected_row_sha256 <<<"$OWNER_INTENT")" ]] || {
    echo "ready customer owner differs from its precommitted final row digest" >&2
    exit 1
  }
fi

if [[ "$LIFECYCLE_MODE" == deferred ]]; then
  require_hard_lock
  emit_recovery_outcome repaired_owner_ready_waiting_for_lifecycle
  echo "durable AOP schema-3 recovery reached repaired+owner_ready; lifecycle selectors are intentionally deferred and the hard lock remains held"
  exit 0
fi

require_hard_lock
refresh_active_component sandbox server "$CELL0_COLOR" "$CELL0_ASG" cell0 "$CELL0_REPAIR_ATTESTATION" \
  "$CELL0_REPAIR_REFRESH_ID" "$SERVER_REPAIR_PROVENANCE" 'curl -sfS -o /dev/null http://127.0.0.1:8888/health/live'
CELL0_REPAIR_ATTESTATION=$LAST_REPAIR_ATTESTATION
refresh_active_component sandbox-cell1 server "$CELL1_COLOR" "$CELL1_ASG" cell1 "$CELL1_REPAIR_ATTESTATION" \
  "$CELL1_REPAIR_REFRESH_ID" "$SERVER_REPAIR_PROVENANCE" 'curl -sfS -o /dev/null http://127.0.0.1:8888/health/live'
CELL1_REPAIR_ATTESTATION=$LAST_REPAIR_ATTESTATION
refresh_active_component sandbox ac "$AC_COLOR" "$AC_ASG" ac "$AC_REPAIR_ATTESTATION" \
  "$AC_REPAIR_REFRESH_ID" "$AC_REPAIR_PROVENANCE" 'systemctl is-active --quiet nhp-acd && systemctl is-active --quiet traefik && curl -sfS -o /dev/null http://127.0.0.1:8080/ping'
AC_REPAIR_ATTESTATION=$LAST_REPAIR_ATTESTATION

if [[ "$PHASE" != complete ]]; then
  "$VERIFY_ASG" "$AC_ASG" schema3-ac-ready 15 \
    'systemctl is-active --quiet nhp-acd && curl -sfS -o /dev/null http://127.0.0.1:8888/nhp-ac/ready'
  CUTOVER_EXPECTED_CELL0_ASG=$CELL0_ASG CUTOVER_STABILITY_SECONDS=${CUTOVER_STABILITY_SECONDS:-30} \
    "$VERIFY_LIFECYCLE"
  CUTOVER_ORIGINAL_SOURCE_ROOT=$ORIGINAL_ROOT CUTOVER_EXPECTED_CELL1_ASG=$CELL1_ASG \
    CUTOVER_EXPECTED_CELL1_COLOR=$CELL1_COLOR "$VERIFY_TOPOLOGY" "$CELL1_ASG" cutover-cell1 15 true
  : "${CUTOVER_CUSTOMER_GH_TOKEN:?CUTOVER_CUSTOMER_GH_TOKEN is required for terminal customer lifecycle verification}"
  : "${CUTOVER_CONNECTOR_GH_TOKEN:?CUTOVER_CONNECTOR_GH_TOKEN is required for terminal connector lifecycle verification}"
  candidate_lifecycle=$(CUTOVER_EXPECTED_REPAIR_SOURCE_SHA=$REPAIR_SOURCE_SHA \
    CUTOVER_EXPECTED_RECOVERY_ORCHESTRATOR_SHA=$RECOVERY_ORCHESTRATOR_SHA \
    CUTOVER_EXPECTED_REPAIR_BUILD_RUN_ID=$REPAIR_BUILD_RUN_ID \
    CUTOVER_EXPECTED_REPAIR_BUILD_RUN_ATTEMPT=$REPAIR_BUILD_RUN_ATTEMPT \
    CUTOVER_EXPECTED_SERVER_DIGEST=${SERVER_REPAIR_PROVENANCE##*|} \
    CUTOVER_EXPECTED_AC_DIGEST=${AC_REPAIR_PROVENANCE##*|} \
    CUTOVER_EXPECTED_CELL0_COLOR=$CELL0_COLOR CUTOVER_EXPECTED_CELL0_ASG=$CELL0_ASG \
    CUTOVER_EXPECTED_CELL1_COLOR=$CELL1_COLOR CUTOVER_EXPECTED_CELL1_ASG=$CELL1_ASG \
    CUTOVER_EXPECTED_AC_COLOR=$AC_COLOR CUTOVER_EXPECTED_AC_ASG=$AC_ASG \
    "$VERIFY_CUSTOMER_LIFECYCLE")
  [[ -z "$CUSTOMER_LIFECYCLE_RECEIPT" || "$CUSTOMER_LIFECYCLE_RECEIPT" == "$candidate_lifecycle" ]] || {
    echo "protected customer lifecycle receipt differs from the schema-3 ledger" >&2
    exit 1
  }
  CUSTOMER_LIFECYCLE_RECEIPT=$candidate_lifecycle
  candidate_connector_lifecycle=$(GH_TOKEN=$CUTOVER_CONNECTOR_GH_TOKEN \
    CUTOVER_EXPECTED_REPAIR_SOURCE_SHA=$REPAIR_SOURCE_SHA \
    CUTOVER_EXPECTED_NHP_CONTROLLER_SOURCE_SHA=$RECOVERY_ORCHESTRATOR_SHA \
    CUTOVER_EXPECTED_NHP_SERVER_DIGEST=${SERVER_REPAIR_PROVENANCE##*|} "$VERIFY_CONNECTOR_LIFECYCLE")
  [[ -z "$CONNECTOR_LIFECYCLE_RECEIPT" || "$CONNECTOR_LIFECYCLE_RECEIPT" == "$candidate_connector_lifecycle" ]] || {
    echo "protected connector lifecycle receipt differs from the schema-3 ledger" >&2
    exit 1
  }
  CONNECTOR_LIFECYCLE_RECEIPT=$candidate_connector_lifecycle
  if (( $(state_phase_order "$PHASE") < $(state_phase_order validated) )); then
    write_state validated
  fi
fi

require_hard_lock
[[ "$(get_param /sandbox/nhp/ac/active-color)" == "$AC_COLOR" ]] || {
  echo "active AC color drifted before terminal recovery" >&2; exit 1;
}
[[ "$(get_param /sandbox/nhp/server/active-color)" == "$CELL0_COLOR" ]] || {
  echo "active cell0 server color drifted before terminal recovery" >&2; exit 1;
}
[[ "$(get_param /sandbox-cell1/nhp/server/active-color)" == "$CELL1_COLOR" ]] || {
  echo "active cell1 server color drifted before terminal recovery" >&2; exit 1;
}
"$OWNER_PROJECTOR" verify-current --intent-json "$OWNER_INTENT" >/dev/null
ensure_exact_floor
"$OWNER_PROJECTOR" verify-current --intent-json "$OWNER_INTENT" >/dev/null
[[ "$PHASE" == complete ]] || write_state complete

# The exact original owner remains the lock owner throughout adoption and all
# partial refreshes.  Only an exact schema-3 COMPLETE is allowed to release it.
require_hard_lock
AWS_REGION=$AWS_REGION bash "$ROOT/.github/scripts/ssm-live-env-lock.sh" release "$LOCK_PARAM" "$ORIGINAL_OWNER" 14400 7200
emit_recovery_outcome complete
echo "durable AOP schema-3 recovery complete at repair source $REPAIR_SOURCE_SHA"
