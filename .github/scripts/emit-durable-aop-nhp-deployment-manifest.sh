#!/usr/bin/env bash
# Emit the one immutable deployment-authority input consumed by the protected
# customer lifecycle workflows.  No image/source/profile value is accepted
# from the caller: the exact completed refresh authority comes from the durable
# schema-3 ledger and is re-proved against the live fleets before emission.

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <schema3-recovery-run-id> <schema3-recovery-run-attempt> <output-json>" >&2
  exit 2
fi

RECOVERY_RUN_ID=$1
RECOVERY_RUN_ATTEMPT=$2
OUTPUT=$3
AWS_REGION=${AWS_REGION:-us-east-2}
GITHUB_REPOSITORY=${GITHUB_REPOSITORY:-}
PRODUCER_SHA=${GITHUB_SHA:-}
PRODUCER_RUN_ID=${GITHUB_RUN_ID:-}
PRODUCER_RUN_ATTEMPT=${GITHUB_RUN_ATTEMPT:-}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
STATE_PARAM=/sandbox/nhp/cutovers/durable-aop-v1/state
LOCK_PARAM=/layerv-nhp-sandbox/qurl-live-env-lock
FLOOR_PARAM=/sandbox/nhp/minimum-protocol-profile
PROFILE=durable-aop-v1
APPROVED_RUNTIME_MANIFEST=2895963905453d61874858171529968efe8e18e5450d41842854fd2784d1ec78
APPROVED_REPAIR_SOURCE_SHA=422b1d9acac53d50fe5602158fb02c8120ef108d
APPROVED_ORIGINAL_STATE_VERSION=7
APPROVED_ORIGINAL_STATE_DIGEST=e7ed20adde2ce9e143c9505027a73e415e5dd3d4a9d0c950c912d6398cc5d13e
APPROVED_ORIGINAL_LOCK_VERSION=2
APPROVED_ORIGINAL_LOCK_DIGEST=6c7224d78837a4d56547409439d9bce30efa9b214367c4f19fd13cc3fe3b2ebd
VERIFY_PROVENANCE=${CUTOVER_VERIFY_PROVENANCE_SCRIPT:-$ROOT/.github/scripts/verify-durable-aop-image-provenance.sh}
VERIFY_BUILD_ONLY=$ROOT/.github/scripts/verify-durable-aop-build-only-run.sh
VERIFY_ASG=${CUTOVER_VERIFY_ASG_HEALTH_SCRIPT:-$ROOT/.github/scripts/verify-asg-instances-healthy.sh}
export AWS_REGION GITHUB_REPOSITORY

[[ "$RECOVERY_RUN_ID" =~ ^[1-9][0-9]*$ && "$RECOVERY_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]] || {
  echo "schema-3 recovery run id/attempt must be positive integers" >&2; exit 2;
}
[[ "$PRODUCER_RUN_ID" =~ ^[1-9][0-9]*$ && "$PRODUCER_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]] || {
  echo "producer run id/attempt must be positive integers" >&2; exit 2;
}
[[ "$GITHUB_REPOSITORY" == layervai/nhp && "$PRODUCER_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo "producer must run from an exact layervai/nhp source" >&2; exit 2;
}
[[ "$OUTPUT" == */durable-aop-nhp-deployment.json || "$OUTPUT" == durable-aop-nhp-deployment.json ]] || {
  echo "deployment manifest output must use the canonical filename" >&2; exit 2;
}
: "${GH_TOKEN:?GH_TOKEN is required}"

get_param() {
  aws ssm get-parameter --name "$1" --query Parameter.Value --output text --region "$AWS_REGION"
}
get_optional() { bash "$ROOT/scripts/ssm-read-optional.sh" "$1"; }
slot_image_param() { [[ "$3" == green ]] && printf '/%s/nhp/%s/green-image-tag\n' "$1" "$2" || printf '/%s/nhp/%s/image-tag\n' "$1" "$2"; }
slot_asg_param() { [[ "$3" == green ]] && printf '/%s/nhp/%s/green-asg-name\n' "$1" "$2" || printf '/%s/nhp/%s/asg-name\n' "$1" "$2"; }
slot_attestation_param() { printf '/%s/nhp/%s/%s-prepared-slot-attestation\n' "$1" "$2" "$3"; }
slot_profile_param() { printf '/%s/nhp/%s/%s-protocol-profile\n' "$1" "$2" "$3"; }
canonical_asg() {
  local env=$1 component=$2 color=$3 base
  base="layerv-nhp-${env}-${component}"
  [[ "$color" == green ]] && printf '%s-green\n' "$base" || printf '%s\n' "$base"
}

STATE=$(get_param "$STATE_PARAM")
STATE=$(jq -cS . <<<"$STATE")
jq -e --arg manifest "$APPROVED_RUNTIME_MANIFEST" \
  --arg state_digest "$APPROVED_ORIGINAL_STATE_DIGEST" --arg lock_digest "$APPROVED_ORIGINAL_LOCK_DIGEST" \
  --argjson state_version "$APPROVED_ORIGINAL_STATE_VERSION" --argjson lock_version "$APPROVED_ORIGINAL_LOCK_VERSION" '
  type == "object" and (keys | sort) == ["original","phase","repair","schema"] and
  .schema == 3 and .phase == "repaired" and
  (.original | type == "object" and
    (keys | sort) == ["lock","lock_sha256","lock_version","state_sha256","state_version"]) and
  (.original.lock | type == "object") and
  .original.state_version == $state_version and .original.lock_version == $lock_version and
  .original.state_sha256 == $state_digest and .original.lock_sha256 == $lock_digest and
  (.repair | type == "object" and (keys | sort) ==
    ["ac_attestation","ac_provenance","ac_refresh_id","build_run_attempt","build_run_id",
     "cell0_attestation","cell0_refresh_id","cell1_attestation","cell1_refresh_id",
     "connector_lifecycle","customer_lifecycle","orchestrator_sha","runtime_manifest",
     "server_provenance","source_sha"]) and
  .repair.runtime_manifest == $manifest and
  ([.repair.orchestrator_sha,.repair.source_sha] | all(type == "string" and test("^[0-9a-f]{40}$"))) and
  ([.repair.build_run_id,.repair.build_run_attempt] | all(type == "string" and test("^[1-9][0-9]*$"))) and
  ([.repair.cell0_attestation,.repair.cell1_attestation,.repair.ac_attestation,
    .repair.cell0_refresh_id,.repair.cell1_refresh_id,.repair.ac_refresh_id] |
    all(type == "string" and length > 0)) and
  .repair.customer_lifecycle == "" and .repair.connector_lifecycle == ""
' >/dev/null <<<"$STATE" || {
  echo "deployment producer requires the exact pre-lifecycle schema-3 REPAIRED authority" >&2
  exit 1
}

embedded_state=$(get_param "${STATE_PARAM}:${APPROVED_ORIGINAL_STATE_VERSION}")
embedded_state=$(jq -cS . <<<"$embedded_state")
embedded_lock=$(jq -cS .original.lock <<<"$STATE")
computed_state_digest=$(printf '%s' "$embedded_state" | sha256sum | awk '{print $1}')
computed_lock_digest=$(printf '%s' "$embedded_lock" | sha256sum | awk '{print $1}')
[[ "$computed_state_digest" == "$APPROVED_ORIGINAL_STATE_DIGEST" &&
   "$computed_state_digest" == "$(jq -r .original.state_sha256 <<<"$STATE")" &&
   "$computed_lock_digest" == "$APPROVED_ORIGINAL_LOCK_DIGEST" &&
   "$computed_lock_digest" == "$(jq -r .original.lock_sha256 <<<"$STATE")" ]] || {
  echo "deployment producer state/lock digests do not match the exact canonical bound authorities" >&2
  exit 1
}
jq -e '
  .schema == 2 and .phase == "old_servers_terminated" and
  .image == "e9b11398a4cea98da6ae5b41cfe635562e1b7c72" and
  .orchestrator_sha == .image and
  .lock_owner == "nhp:32635672597:durable-aop-cutover:e9b11398a4cea98da6ae5b41cfe635562e1b7c72"
' >/dev/null <<<"$embedded_state" || { echo "historical incident state shape is malformed" >&2; exit 1; }
jq -e '
  .schema == 1 and .kind == "durable-aop-cutover-recovery" and
  .owner == "nhp:32635672597:durable-aop-cutover:e9b11398a4cea98da6ae5b41cfe635562e1b7c72" and
  .image == "e9b11398a4cea98da6ae5b41cfe635562e1b7c72" and .orchestrator_sha == .image and
  .created_at == 1787485146 and .expires_at == 253402300799
' >/dev/null <<<"$embedded_lock" || { echo "historical incident lock shape is malformed" >&2; exit 1; }

REPAIR_SOURCE_SHA=$(jq -r .repair.source_sha <<<"$STATE")
[[ "$REPAIR_SOURCE_SHA" == "$APPROVED_REPAIR_SOURCE_SHA" ]] || {
  echo "deployment producer is not finalized for the exact merged #3935 source" >&2; exit 1;
}
RECOVERY_SOURCE_SHA=$(jq -r .repair.orchestrator_sha <<<"$STATE")
BUILD_RUN_ID=$(jq -r .repair.build_run_id <<<"$STATE")
BUILD_RUN_ATTEMPT=$(jq -r .repair.build_run_attempt <<<"$STATE")
[[ "$PRODUCER_SHA" == "$RECOVERY_SOURCE_SHA" ]] || {
  echo "producer source differs from the exact schema-3 recovery controller" >&2; exit 1;
}

live_lock=$(get_param "$LOCK_PARAM")
live_lock=$(jq -cS . <<<"$live_lock")
[[ "$live_lock" == "$embedded_lock" ]] || {
  echo "original non-expiring recovery lock changed before deployment authority capture" >&2; exit 1;
}
[[ -z "$(get_optional "$FLOOR_PARAM")" ]] || {
  echo "durable profile floor exists before protected lifecycle validation" >&2; exit 1;
}

recovery_run=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${RECOVERY_RUN_ID}/attempts/${RECOVERY_RUN_ATTEMPT}")
jq -e --arg sha "$RECOVERY_SOURCE_SHA" --argjson attempt "$RECOVERY_RUN_ATTEMPT" '
  .head_sha == $sha and .head_branch == "main" and .event == "workflow_dispatch" and
  .run_attempt == $attempt and .status == "completed" and
  (.conclusion == "failure" or .conclusion == "timed_out") and
  (.path == ".github/workflows/recover-sandbox-durable-aop-schema3.yml" or
   .path == "layervai/nhp/.github/workflows/recover-sandbox-durable-aop-schema3.yml@refs/heads/main")
' >/dev/null <<<"$recovery_run" || {
  echo "selected schema-3 recovery run is not the exact completed repaired controller attempt" >&2; exit 1;
}

build_receipt=$("$VERIFY_BUILD_ONLY" "$BUILD_RUN_ID" "$BUILD_RUN_ATTEMPT" "$REPAIR_SOURCE_SHA")
[[ "$build_receipt" == "v1|${BUILD_RUN_ID}|${BUILD_RUN_ATTEMPT}|${REPAIR_SOURCE_SHA}" ]] || {
  echo "schema-3 build-only receipt is malformed" >&2; exit 1;
}

SERVER_PROVENANCE=$("$VERIFY_PROVENANCE" layerv/nhp-server "$REPAIR_SOURCE_SHA")
AC_PROVENANCE=$("$VERIFY_PROVENANCE" layerv/nhp-ac "$REPAIR_SOURCE_SHA")
[[ "$SERVER_PROVENANCE" == "$(jq -r .repair.server_provenance <<<"$STATE")" &&
   "$AC_PROVENANCE" == "$(jq -r .repair.ac_provenance <<<"$STATE")" ]] || {
  echo "live image provenance differs from schema-3 repair authority" >&2; exit 1;
}
SERVER_DIGEST=${SERVER_PROVENANCE##*|}
AC_DIGEST=${AC_PROVENANCE##*|}
[[ "$SERVER_DIGEST" =~ ^sha256:[0-9a-f]{64}$ && "$AC_DIGEST" =~ ^sha256:[0-9a-f]{64}$ &&
   "$SERVER_DIGEST" != "$AC_DIGEST" ]] || {
  echo "server and AC deployment digests must be distinct canonical SHA-256 values" >&2; exit 1;
}

prove_deployment() {
  local label=$1 env=$2 component=$3 color=$4 asg=$5 digest=$6 provenance=$7 attestation=$8 refresh_id=$9 health=${10}
  local expected_asg expected_attestation refresh_status asg_json
  [[ "$color" == blue || "$color" == green ]] || { echo "$label active color is malformed" >&2; return 1; }
  expected_asg=$(canonical_asg "$env" "$component" "$color")
  [[ "$asg" == "$expected_asg" ]] || { echo "$label active ASG is not canonical for its color" >&2; return 1; }
  expected_attestation="v2|${PROFILE}|${provenance#v1|}|${asg}"
  [[ "$attestation" == "$expected_attestation" ]] || { echo "$label schema-3 attestation is malformed" >&2; return 1; }
  [[ "$(get_param "/${env}/nhp/${component}/active-color")" == "$color" &&
     "$(get_param "$(slot_asg_param "$env" "$component" "$color")")" == "$asg" &&
     "$(get_param "$(slot_image_param "$env" "$component" "$color")")" == "$REPAIR_SOURCE_SHA" &&
     "$(get_param "$(slot_profile_param "$env" "$component" "$color")")" == "v1|${PROFILE}|${REPAIR_SOURCE_SHA}" &&
     "$(get_param "$(slot_attestation_param "$env" "$component" "$color")")" == "$attestation" ]] || {
    echo "$label live slot authority differs from schema-3 repair" >&2; return 1;
  }
  refresh_status=$(aws autoscaling describe-instance-refreshes --auto-scaling-group-name "$asg" \
    --instance-refresh-ids "$refresh_id" --query 'InstanceRefreshes[0].Status' --output text --region "$AWS_REGION")
  [[ "$refresh_status" == Successful ]] || { echo "$label exact repair refresh is not successful" >&2; return 1; }
  asg_json=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names "$asg" --output json --region "$AWS_REGION")
  jq -e --arg asg "$asg" '
    .AutoScalingGroups as $groups |
    ($groups | type == "array" and length == 1) and
    ($groups[0] as $g |
      $g.AutoScalingGroupName == $asg and ($g.MinSize | type == "number" and . > 0 and floor == .) and
      ($g.DesiredCapacity | type == "number" and . > 0 and floor == .) and
      ($g.MaxSize | type == "number" and . >= $g.DesiredCapacity and floor == .) and
      ($g.Instances | type == "array" and length == $g.DesiredCapacity and
        all(.LifecycleState == "InService" and .HealthStatus == "Healthy")))
  ' >/dev/null <<<"$asg_json" || { echo "$label active ASG is not fully healthy" >&2; return 1; }
  "$VERIFY_ASG" "$asg" "deployment-${label}" 15 "$health"
  DEPLOYMENT_JSON=$(jq -cn --arg environment "$env" --arg component "$component" \
    --arg color "$color" --arg asg "$asg" --arg digest "$digest" \
    '{environment:$environment,component:$component,active_color:$color,active_asg:$asg,image_digest:$digest}')
}

CELL0_COLOR=$(jq -r .cell0.new_color <<<"$embedded_state")
CELL0_ASG=$(jq -r .cell0.new_asg <<<"$embedded_state")
CELL1_COLOR=$(jq -r .cell1.new_color <<<"$embedded_state")
CELL1_ASG=$(jq -r .cell1.new_asg <<<"$embedded_state")
AC_COLOR=$(jq -r .ac.new_color <<<"$embedded_state")
AC_ASG=$(jq -r .ac.new_asg <<<"$embedded_state")

prove_deployment cell0 sandbox server "$CELL0_COLOR" "$CELL0_ASG" "$SERVER_DIGEST" "$SERVER_PROVENANCE" \
  "$(jq -r .repair.cell0_attestation <<<"$STATE")" "$(jq -r .repair.cell0_refresh_id <<<"$STATE")" \
  'curl -sfS -o /dev/null http://127.0.0.1:8888/health/live'
CELL0_DEPLOYMENT=$DEPLOYMENT_JSON
prove_deployment cell1 sandbox-cell1 server "$CELL1_COLOR" "$CELL1_ASG" "$SERVER_DIGEST" "$SERVER_PROVENANCE" \
  "$(jq -r .repair.cell1_attestation <<<"$STATE")" "$(jq -r .repair.cell1_refresh_id <<<"$STATE")" \
  'curl -sfS -o /dev/null http://127.0.0.1:8888/health/live'
CELL1_DEPLOYMENT=$DEPLOYMENT_JSON
prove_deployment ac sandbox ac "$AC_COLOR" "$AC_ASG" "$AC_DIGEST" "$AC_PROVENANCE" \
  "$(jq -r .repair.ac_attestation <<<"$STATE")" "$(jq -r .repair.ac_refresh_id <<<"$STATE")" \
  'systemctl is-active --quiet nhp-acd && curl -sfS -o /dev/null http://127.0.0.1:8888/nhp-ac/ready'
AC_DEPLOYMENT=$DEPLOYMENT_JSON

mkdir -p "$(dirname "$OUTPUT")"
tmp="${OUTPUT}.tmp"
jq -cS -n --arg repair "$REPAIR_SOURCE_SHA" --arg recovery "$RECOVERY_SOURCE_SHA" \
  --arg build_run "$BUILD_RUN_ID" --arg build_attempt "$BUILD_RUN_ATTEMPT" \
  --arg producer_run "$PRODUCER_RUN_ID" --arg producer_attempt "$PRODUCER_RUN_ATTEMPT" \
  --arg producer_head "$PRODUCER_SHA" --arg server_digest "$SERVER_DIGEST" --arg ac_digest "$AC_DIGEST" \
  --argjson cell0 "$CELL0_DEPLOYMENT" --argjson cell1 "$CELL1_DEPLOYMENT" --argjson ac "$AC_DEPLOYMENT" '
  {schema:"layerv.durable-aop-nhp-deployment.v1",repository:"layervai/nhp",environment:"sandbox",
   profile:"durable-aop-v1",repair_source_sha:$repair,recovery_orchestrator_sha:$recovery,
   build:{workflow:".github/workflows/build-and-push.yml",run_id:$build_run,run_attempt:$build_attempt,head_sha:$repair},
   producer:{workflow:".github/workflows/udp-proof-deployment-manifest.yml",source_sha:$recovery,
     run_id:$producer_run,run_attempt:$producer_attempt,head_sha:$producer_head},
   images:{server:{repository:"layerv/nhp-server",digest:$server_digest},
     ac:{repository:"layerv/nhp-ac",digest:$ac_digest}},
   deployments:{cell0:$cell0,cell1:$cell1,ac:$ac}}
' >"$tmp"
[[ $(wc -c <"$tmp") -le 65536 ]] || { rm -f "$tmp"; echo "deployment manifest exceeds 64 KiB" >&2; exit 1; }
jq -e 'type == "object"' >/dev/null "$tmp"
mv "$tmp" "$OUTPUT"
echo "emitted exact repaired NHP deployment authority: $OUTPUT"
