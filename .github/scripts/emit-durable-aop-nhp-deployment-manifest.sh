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
STALE_JOURNAL_PARAM=/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement
LOCK_PARAM=/layerv-nhp-sandbox/qurl-live-env-lock
OWNER_PROJECTOR=${CUTOVER_OWNER_PROJECTOR_SCRIPT:-$ROOT/terraform/scripts/project-qurl-sharing-customer-tier.py}
SESSION_CONTROL_DELETE_IAM=${CUTOVER_SESSION_CONTROL_DELETE_IAM_SCRIPT:-$ROOT/.github/scripts/apply-durable-aop-session-control-delete-iam.py}
OWNER_CLIENT_ID=oScYkXhLitBPO6gBjxo4Rwyw37AdoNPy
OWNER_SUBJECT=${OWNER_CLIENT_ID}@clients
OWNER_EMAIL=oscykxhlitbpo6gbjxo4rwyw37adonpy-clients@machine.notify.layerv.xyz
OWNER_TABLE=layerv-nhp-sandbox-control-qurl-customers
FLOOR_PARAM=/sandbox/nhp/minimum-protocol-profile
PROFILE=durable-aop-v1
APPROVED_RUNTIME_MANIFEST=2895963905453d61874858171529968efe8e18e5450d41842854fd2784d1ec78
APPROVED_REPAIR_SOURCE_SHA=422b1d9acac53d50fe5602158fb02c8120ef108d
APPROVED_STALE_SOURCE_STATE_VERSION=22
APPROVED_STALE_SOURCE_STATE_DIGEST=b972283f4d37bfa6b2d672b531a6d87a5ab305e0973d5a24d5d19e75f45ef348
APPROVED_STALE_INCIDENT_PLAN_DIGEST=f434ce1e13c69f8749e9004be26304002e7e8da28939815d062f643124abcfc6
# Exact merged runtime source and successful claim-free build-only run. Both
# image/SBOM attestations succeeded and every deployment job was skipped.
APPROVED_STALE_RUNTIME_SOURCE_SHA=f32335420d67fd235a6fb6598a1fc3d8eaf8dda7
APPROVED_STALE_RUNTIME_MANIFEST=906c0461bf3d44175750b91ec9251de114da0c3646750287656803e3783d5ed0
APPROVED_STALE_RUNTIME_BUILD_RUN_ID=32682520698
APPROVED_STALE_RUNTIME_BUILD_RUN_ATTEMPT=1
APPROVED_STALE_RUNTIME_SERVER_DIGEST=sha256:0921191723fd6a4919f22e0dded5775411bb08a682dc9d9f9a69fdcded7674c9
APPROVED_STALE_RUNTIME_AC_DIGEST=sha256:773bd37e915ac767f57e7656b5c038a8f2c70348901b1e81572584d6cfad566e
APPROVED_IAM_HANDOFF_PREDECESSOR_SHA=e668a60b81f14b55278c83d0c79e4f760adeac29
APPROVED_IAM_HANDOFF_CELL0_PRIOR_REFRESH_ID=ea9dae3d-22f8-478e-a9ec-91eb9b9f53fb
APPROVED_IAM_HANDOFF_CELL0_REFRESH_ID=771e74d1-3299-4c03-b7f4-6fdb3b11e6bd
APPROVED_IAM_HANDOFF_CELL0_INTENT_SHA256=f8d70d3357b301c55f806d34e3d70d0f1f7706999fc2d08d8e5c87fe627b5d50
APPROVED_IAM_HANDOFF_CELL1_PRIOR_REFRESH_ID=dc5ab358-ef4e-45a8-bf81-d18112a2ce9c
APPROVED_IAM_HANDOFF_CELL1_REFRESH_ID=8f88f6af-4f02-4f03-8ac9-c6c62fdcb051
APPROVED_IAM_HANDOFF_CELL1_INTENT_SHA256=0765d6c4bdb0940be956b253156d192b9761c90e2fec175d4300b167912174d0
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
[[ "$APPROVED_STALE_RUNTIME_SOURCE_SHA" != 0000000000000000000000000000000000000000 &&
   "$APPROVED_STALE_RUNTIME_MANIFEST" != 0000000000000000000000000000000000000000000000000000000000000000 &&
   "$APPROVED_STALE_RUNTIME_BUILD_RUN_ID" =~ ^[1-9][0-9]*$ &&
   "$APPROVED_STALE_RUNTIME_BUILD_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]] || {
  echo "deployment producer runtime recovery authority is not finalized" >&2
  exit 2
}

get_param() {
  aws ssm get-parameter --name "$1" --query Parameter.Value --output text --region "$AWS_REGION"
}
get_param_version() {
  aws ssm get-parameter --name "$1" --query Parameter.Version --output text --region "$AWS_REGION"
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
canonical_digest() { printf '%s' "$1" | sha256sum | awk '{print $1}'; }
immutable_image_selector() {
  local provenance=$1 schema source repository digest extra
  IFS='|' read -r schema source repository digest extra <<<"$provenance"
  [[ "$schema" == v1 && "$source" =~ ^[0-9a-f]{40}$ &&
     "$repository" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ &&
     "$digest" =~ ^sha256:[0-9a-f]{64}$ && -z "$extra" ]] || return 1
  printf '%s@%s\n' "$source" "$digest"
}
decode_stale_journal() {
  printf '%s' "$1" | python3 -c '
import base64, gzip, json, sys
raw = sys.stdin.buffer.read(); value = json.loads(raw)
if set(value) != {"encoding", "payload", "schema"} or value["encoding"] != "gzip-base64" or value["schema"] != "layerv.durable-aop-stale-target-journal-envelope.v1": raise SystemExit(1)
if json.dumps(value, sort_keys=True, separators=(",", ":")).encode() != raw: raise SystemExit(1)
decoded = gzip.decompress(base64.b64decode(value["payload"], validate=True))
if len(decoded) > 65536: raise SystemExit(1)
parsed = json.loads(decoded)
if json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode() != decoded: raise SystemExit(1)
sys.stdout.buffer.write(decoded)
'
}
fence_digest() {
  local fence=$1
  {
    printf '\0%s' v1
    for field in ac_id public_key boot_id flush_generation version authority_version counted_active_slot \
      control_cell_id activated_control_version ready_control_version aak_enqueued_at_ms aak_transaction_id \
      created_at_ms prepared_at_ms; do
      printf '\0%s' "$(jq -r ".${field}" <<<"$fence")"
    done
  } | sha256sum | awk '{print $1}'
}
directory_digest() {
  local receipt=$1
  {
    printf '\0%s' v1
    for field in cell_id version active_fence_count admission_blocked overflow_close_count \
      overflow_leader_event_id overflow_leader_prepared_directory_version \
      overflow_leader_selected_directory_version created_at_ms updated_at_ms; do
      printf '\0%s' "$(jq -r ".${field}" <<<"$receipt")"
    done
  } | sha256sum | awk '{print $1}'
}
validate_directory_receipt() {
  local receipt=$1 count=$2
  jq -e --arg count "$count" '
    type == "object" and (keys | sort) ==
      ["active_fence_count","admission_blocked","cell_id","created_at_ms","directory_sha256",
       "overflow_close_count","overflow_leader_event_id","overflow_leader_prepared_directory_version",
       "overflow_leader_selected_directory_version","schema","updated_at_ms","version"] and
    .schema == "layerv.durable-aop-fence-directory-receipt.v1" and .cell_id == "cell0" and
    .active_fence_count == $count and .admission_blocked == false and
    ([.version,.active_fence_count,.overflow_close_count,.overflow_leader_prepared_directory_version,
      .overflow_leader_selected_directory_version,.created_at_ms,.updated_at_ms] |
      all(type == "string" and test("^(0|[1-9][0-9]*)$"))) and
    .overflow_close_count == "0" and .overflow_leader_event_id == "" and
    .overflow_leader_prepared_directory_version == "0" and
    .overflow_leader_selected_directory_version == "0" and
    (.directory_sha256 | type == "string" and test("^[0-9a-f]{64}$"))
  ' >/dev/null <<<"$receipt" &&
    [[ "$(directory_digest "$receipt")" == "$(jq -r .directory_sha256 <<<"$receipt")" ]]
}

validate_starting_directory_receipt() {
  local receipt=$1 count
  count=$(jq -er '
    .active_fence_count |
    select(type == "string" and test("^[1-9][0-9]{0,3}$") and (tonumber <= 1024))
  ' <<<"$receipt") || return 1
  validate_directory_receipt "$receipt" "$count"
}
validate_retirement_plan() {
  local plan=$1 schema=$2 prefix=$3 min=$4 max=$5 count index target fence
  jq -e --arg schema "$schema" --arg prefix "$prefix" --argjson min "$min" --argjson max "$max" '
    type == "object" and (keys | sort) == ["ac_id","control_cell_id","region","schema","table","targets"] and
    .schema == $schema and .table == "layerv-nhp-sandbox-cell0-nhp-session-control" and
    .region == "us-east-2" and .ac_id == "layerv-ac-tf" and .control_cell_id == "cell0" and
    (.targets | type == "array" and length >= $min and length <= $max) and
    ([.targets[].id] == [range(1;(.targets|length)+1) | ($prefix + (.|tostring))]) and
    ([.targets[] | (keys | sort) == ["fence","fence_sha256","id"] and
      (.fence_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (.fence | type == "object" and (keys | sort) ==
        ["aak_enqueued_at_ms","aak_transaction_id","ac_id","activated_control_version","authority_version",
         "boot_id","control_cell_id","counted_active_slot","created_at_ms","flush_generation","prepared_at_ms",
         "public_key","ready_control_version","version"] and
        .ac_id == "layerv-ac-tf" and .control_cell_id == "cell0" and .counted_active_slot == true and
        .activated_control_version == "0" and .ready_control_version == "0" and
        .aak_enqueued_at_ms == "0" and .aak_transaction_id == "0" and
        ([.flush_generation,.version,.authority_version,.created_at_ms,.prepared_at_ms] |
          all(type == "string" and test("^[1-9][0-9]*$"))) and
        ([.public_key,.boot_id] | all(type == "string" and length > 0)))] | all)
  ' >/dev/null <<<"$plan" || return 1
  count=$(jq '.targets|length' <<<"$plan")
  for ((index=0; index<count; index++)); do
    target=$(jq -c --argjson i "$index" '.targets[$i]' <<<"$plan")
    fence=$(jq -cS .fence <<<"$target")
    [[ "$(fence_digest "$fence")" == "$(jq -r .fence_sha256 <<<"$target")" ]] || return 1
  done
}
validate_retired_ledger() {
  local plan=$1 ledger=$2 count index planned row receipt version authority
  count=$(jq '.targets|length' <<<"$plan")
  [[ "$(jq 'length' <<<"$ledger")" == "$count" ]] || return 1
  for ((index=0; index<count; index++)); do
    planned=$(jq -c --argjson i "$index" '.targets[$i]' <<<"$plan")
    row=$(jq -c --argjson i "$index" '.[$i]' <<<"$ledger")
    receipt=$(jq -cS .receipt <<<"$row")
    version=$(( $(jq -r .fence.version <<<"$planned") + 1 ))
    authority=$(( $(jq -r .fence.authority_version <<<"$planned") + 1 ))
    jq -e --arg id "$(jq -r .id <<<"$planned")" --arg fence "$(jq -r .fence_sha256 <<<"$planned")" \
      --arg key "$(jq -r .fence.public_key <<<"$planned")" --arg version "$version" --arg authority "$authority" '
      (keys | sort) == ["fence_sha256","id","receipt","status"] and
      .id == $id and .fence_sha256 == $fence and .status == "retired" and
      (.receipt | type == "object" and (keys | sort) ==
        ["authority_version","counted_active_slot","public_key","retired_at_ms","retired_target_sha256",
         "schema","target_id","version"] and
        .schema == "layerv.durable-aop-stale-target-retirement-receipt.v1" and
        .target_id == $id and .public_key == $key and .version == $version and
        .authority_version == $authority and .counted_active_slot == false and
        (.retired_at_ms | type == "string" and test("^[1-9][0-9]*$")) and
        (.retired_target_sha256 | type == "string" and test("^[0-9a-f]{64}$")))
    ' >/dev/null <<<"$row" || return 1
  done
}

STATE=$(get_param "$STATE_PARAM")
STATE=$(jq -cS . <<<"$STATE")
jq -e --arg manifest "$APPROVED_RUNTIME_MANIFEST" \
  --arg runtime_source "$APPROVED_STALE_RUNTIME_SOURCE_SHA" \
  --arg runtime_manifest "$APPROVED_STALE_RUNTIME_MANIFEST" \
  --arg runtime_build "$APPROVED_STALE_RUNTIME_BUILD_RUN_ID" \
  --arg runtime_attempt "$APPROVED_STALE_RUNTIME_BUILD_RUN_ATTEMPT" \
  --arg stale_source_digest "$APPROVED_STALE_SOURCE_STATE_DIGEST" \
  --arg incident_plan_digest "$APPROVED_STALE_INCIDENT_PLAN_DIGEST" \
  --arg stale_source_version "$APPROVED_STALE_SOURCE_STATE_VERSION" \
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
     "connector_lifecycle","customer_lifecycle","orchestrator_sha","owner","runtime_manifest",
     "server_provenance","source_sha","stale_target_retirement_ref"]) and
  .repair.runtime_manifest == $manifest and
  ([.repair.orchestrator_sha,.repair.source_sha] | all(type == "string" and test("^[0-9a-f]{40}$"))) and
  ([.repair.build_run_id,.repair.build_run_attempt] | all(type == "string" and test("^[1-9][0-9]*$"))) and
  ([.repair.cell0_attestation,.repair.cell1_attestation,.repair.ac_attestation,
    .repair.cell0_refresh_id,.repair.cell1_refresh_id,.repair.ac_refresh_id] |
    all(type == "string" and length > 0)) and
  (.repair.owner | type == "object" and (keys | sort) == ["intent","status"] and .status == "ready") and
  (.repair.owner.intent | type == "object" and length == 15) and
  .repair.customer_lifecycle == "" and .repair.connector_lifecycle == "" and
  (.repair.stale_target_retirement_ref | type == "object" and (keys | sort) == ["parameter","sha256","version"] and
    .parameter == "/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement" and
    (.version | type == "number" and . > 0 and floor == .) and (.sha256 | test("^[0-9a-f]{64}$")))
' >/dev/null <<<"$STATE" || {
  echo "deployment producer requires the completed runtime-retirement schema-3 authority" >&2
  exit 1
}

JOURNAL_REF=$(jq -cS .repair.stale_target_retirement_ref <<<"$STATE")
JOURNAL_VERSION=$(jq -r .version <<<"$JOURNAL_REF")
JOURNAL_ENVELOPE=$(get_param "${STALE_JOURNAL_PARAM}:${JOURNAL_VERSION}"); JOURNAL_ENVELOPE=$(jq -cS . <<<"$JOURNAL_ENVELOPE")
[[ "$(get_param_version "$STALE_JOURNAL_PARAM")" == "$JOURNAL_VERSION" &&
   "$(get_param "$STALE_JOURNAL_PARAM" | jq -cS .)" == "$JOURNAL_ENVELOPE" &&
   ${#JOURNAL_ENVELOPE} -lt 4096 && "$(canonical_digest "$JOURNAL_ENVELOPE")" == "$(jq -r .sha256 <<<"$JOURNAL_REF")" ]] || {
  echo "deployment producer stale-target journal reference is not current and exact" >&2
  exit 1
}
JOURNAL=$(decode_stale_journal "$JOURNAL_ENVELOPE")
jq -e --arg stale_source_version "$APPROVED_STALE_SOURCE_STATE_VERSION" \
  --arg stale_source_digest "$APPROVED_STALE_SOURCE_STATE_DIGEST" \
  --arg incident_plan_digest "$APPROVED_STALE_INCIDENT_PLAN_DIGEST" \
  --arg runtime_source "$APPROVED_STALE_RUNTIME_SOURCE_SHA" \
  --arg runtime_manifest "$APPROVED_STALE_RUNTIME_MANIFEST" \
  --arg runtime_build "$APPROVED_STALE_RUNTIME_BUILD_RUN_ID" \
  --arg runtime_attempt "$APPROVED_STALE_RUNTIME_BUILD_RUN_ATTEMPT" '
  . as $j |
    ($j | type == "object" and (keys | sort) ==
      ["incident_plan","incident_plan_sha256","incident_targets","runtime","schema","source_state_sha256",
       "source_state_version","status"]) and
    $j.schema == "layerv.durable-aop-stale-target-retirement-journal.v1" and $j.status == "complete" and
    $j.source_state_version == $stale_source_version and $j.source_state_sha256 == $stale_source_digest and
    $j.incident_plan_sha256 == $incident_plan_digest and
    ($j.incident_plan | type == "object") and ($j.incident_targets | type == "array" and length == 3) and
    ([ $j.incident_targets[].status ] | all(. == "retired")) and
    ($j.runtime | type == "object" and (keys | sort) ==
      ["ac","ac_provenance","build_run_attempt","build_run_id","cell0","cell1","fence_drain","fence_start",
       "predecessor_plan","predecessor_plan_sha256","predecessor_targets","preferences","runtime_manifest",
       "server_provenance","server_refresh_orchestrator_sha","session_control_delete_iam","source_sha"]) and
    $j.runtime.source_sha == $runtime_source and $j.runtime.runtime_manifest == $runtime_manifest and
    $j.runtime.build_run_id == $runtime_build and $j.runtime.build_run_attempt == $runtime_attempt and
    ($j.runtime.server_provenance | type == "string") and ($j.runtime.ac_provenance | type == "string") and
    ($j.runtime.fence_start | type == "object") and
    ($j.runtime.fence_drain | type == "object" and .active_fence_count == "0") and
    ($j.runtime.predecessor_plan | type == "object") and
    ($j.runtime.predecessor_plan_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    ($j.runtime.predecessor_targets | type == "array" and length >= 1 and length <= 3) and
    ([ $j.runtime.predecessor_targets[].status ] | all(. == "retired")) and
    ([ $j.runtime.cell0, $j.runtime.cell1, $j.runtime.ac ] | all(
      type == "object" and (keys | sort) == ["asg","attestation","intent_sha256","prior_refresh_id","refresh_id"] and
      (.intent_sha256 | test("^[0-9a-f]{64}$")) and
      ([.asg,.attestation,.prior_refresh_id,.refresh_id] | all(type == "string" and length > 0))))
' >/dev/null <<<"$JOURNAL" || {
  echo "deployment producer requires the completed exact stale-target journal" >&2
  exit 1
}
IAM_INTENT=$(jq -cS .runtime.session_control_delete_iam.intent <<<"$JOURNAL")
IAM_RECEIPT=$(jq -cS .runtime.session_control_delete_iam.receipt <<<"$JOURNAL")
[[ "$(jq -r .runtime.session_control_delete_iam.status <<<"$JOURNAL")" == ready &&
   "$($SESSION_CONTROL_DELETE_IAM verify --intent-json "$IAM_INTENT" | jq -cS .)" == "$IAM_RECEIPT" ]] || {
  echo "deployment producer session-control IAM authority is not live and exact" >&2
  exit 1
}
RUNTIME=$(jq -cS .runtime <<<"$JOURNAL")
INCIDENT_PLAN=$(jq -cS .incident_plan <<<"$JOURNAL")
PREDECESSOR_PLAN=$(jq -cS .runtime.predecessor_plan <<<"$JOURNAL")
[[ "$(canonical_digest "$INCIDENT_PLAN")" == "$APPROVED_STALE_INCIDENT_PLAN_DIGEST" &&
   "$(canonical_digest "$PREDECESSOR_PLAN")" == "$(jq -r .runtime.predecessor_plan_sha256 <<<"$JOURNAL")" ]] || {
  echo "deployment producer retirement plan bytes differ from their durable digests" >&2
  exit 1
}
if ! validate_retirement_plan "$INCIDENT_PLAN" layerv.durable-aop-stale-target-retirement-plan.v1 stale-ac-target- 3 3 ||
   ! validate_retirement_plan "$PREDECESSOR_PLAN" layerv.durable-aop-predecessor-target-plan.v1 predecessor- 1 3 ||
   ! validate_retired_ledger "$INCIDENT_PLAN" "$(jq -c .incident_targets <<<"$JOURNAL")" ||
   ! validate_retired_ledger "$PREDECESSOR_PLAN" "$(jq -c .runtime.predecessor_targets <<<"$JOURNAL")"; then
  echo "deployment producer target-retirement ledger is malformed or torn" >&2
  exit 1
fi
FENCE_START=$(jq -cS .runtime.fence_start <<<"$JOURNAL")
FENCE_DRAIN=$(jq -cS .runtime.fence_drain <<<"$JOURNAL")
validate_starting_directory_receipt "$FENCE_START" && validate_directory_receipt "$FENCE_DRAIN" 0 &&
  [[ "$(jq -r .created_at_ms <<<"$FENCE_START")" == "$(jq -r .created_at_ms <<<"$FENCE_DRAIN")" &&
     "$(jq -r .version <<<"$FENCE_DRAIN")" -ge "$(jq -r .version <<<"$FENCE_START")" &&
     "$(jq -r .updated_at_ms <<<"$FENCE_DRAIN")" -ge "$(jq -r .updated_at_ms <<<"$FENCE_START")" ]] || {
  echo "deployment producer fence-directory drain authority is malformed" >&2
  exit 1
}

REFRESH_PREFERENCES='{"MinHealthyPercentage":100,"MaxHealthyPercentage":200,"InstanceWarmup":60,"SkipMatching":false}'
validate_runtime_intent() {
  local label=$1 asg=$2 provenance=$3 intent_orchestrator=$4 plan_digest=${5:--}
  local component prior expected_attestation expected_intent
  component=$(jq -c --arg label "$label" '.[$label]' <<<"$RUNTIME")
  expected_attestation="v2|${PROFILE}|${provenance#v1|}|${asg}"
  prior=$(jq -r .prior_refresh_id <<<"$component")
  expected_intent=$(printf 'v2\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
    "$label" "$asg" "$APPROVED_STALE_RUNTIME_SOURCE_SHA" "$APPROVED_STALE_RUNTIME_BUILD_RUN_ID" \
    "$APPROVED_STALE_RUNTIME_BUILD_RUN_ATTEMPT" "$provenance" "$intent_orchestrator" \
    "$REFRESH_PREFERENCES" "$prior" "$plan_digest" | sha256sum | awk '{print $1}')
  [[ "$(jq -r .asg <<<"$component")" == "$asg" &&
     "$(jq -r .attestation <<<"$component")" == "$expected_attestation" &&
     "$prior" =~ ^(-|[A-Za-z0-9-]+)$ && "$(jq -r .refresh_id <<<"$component")" =~ ^[A-Za-z0-9-]+$ &&
     "$(jq -r .intent_sha256 <<<"$component")" == "$expected_intent" ]]
}
SERVER_REFRESH_ORCHESTRATOR_SHA=$(jq -r .server_refresh_orchestrator_sha <<<"$RUNTIME")
[[ "$SERVER_REFRESH_ORCHESTRATOR_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo "deployment producer server-refresh controller authority is malformed" >&2
  exit 1
}
if [[ "$SERVER_REFRESH_ORCHESTRATOR_SHA" == "$APPROVED_IAM_HANDOFF_PREDECESSOR_SHA" ]]; then
  jq -e --arg c0_prior "$APPROVED_IAM_HANDOFF_CELL0_PRIOR_REFRESH_ID" \
    --arg c0_refresh "$APPROVED_IAM_HANDOFF_CELL0_REFRESH_ID" \
    --arg c0_intent "$APPROVED_IAM_HANDOFF_CELL0_INTENT_SHA256" \
    --arg c1_prior "$APPROVED_IAM_HANDOFF_CELL1_PRIOR_REFRESH_ID" \
    --arg c1_refresh "$APPROVED_IAM_HANDOFF_CELL1_REFRESH_ID" \
    --arg c1_intent "$APPROVED_IAM_HANDOFF_CELL1_INTENT_SHA256" '
    .cell0.prior_refresh_id == $c0_prior and .cell0.refresh_id == $c0_refresh and
    .cell0.intent_sha256 == $c0_intent and .cell1.prior_refresh_id == $c1_prior and
    .cell1.refresh_id == $c1_refresh and .cell1.intent_sha256 == $c1_intent
  ' >/dev/null <<<"$RUNTIME" || {
    echo "deployment producer predecessor server-refresh authority is not the exact live pair" >&2
    exit 1
  }
else
  [[ "$SERVER_REFRESH_ORCHESTRATOR_SHA" == "$(jq -r .repair.orchestrator_sha <<<"$STATE")" ]] || {
    echo "deployment producer server-refresh controller differs from the recovery authority" >&2
    exit 1
  }
fi
if ! validate_runtime_intent cell0 layerv-nhp-sandbox-server "$(jq -r .server_provenance <<<"$RUNTIME")" \
     "$SERVER_REFRESH_ORCHESTRATOR_SHA" ||
   ! validate_runtime_intent cell1 layerv-nhp-sandbox-cell1-server-green "$(jq -r .server_provenance <<<"$RUNTIME")" \
     "$SERVER_REFRESH_ORCHESTRATOR_SHA" ||
   ! validate_runtime_intent ac layerv-nhp-sandbox-ac-green "$(jq -r .ac_provenance <<<"$RUNTIME")" \
     "$(jq -r .repair.orchestrator_sha <<<"$STATE")" "$(jq -r .predecessor_plan_sha256 <<<"$RUNTIME")"; then
  echo "deployment producer runtime-refresh intent authority is malformed" >&2
  exit 1
fi

OWNER_INTENT=$(jq -cS .repair.owner.intent <<<"$STATE")
jq -e --arg client "$OWNER_CLIENT_ID" --arg subject "$OWNER_SUBJECT" --arg email "$OWNER_EMAIL" \
  --arg table "$OWNER_TABLE" --arg region "$AWS_REGION" --arg source "$(jq -r .repair.source_sha <<<"$STATE")" '
  .schema == "layerv.durable-aop-customer-owner-intent.v1" and
  .client_id == $client and .subject == $subject and .email == $email and
  .table == $table and .region == $region and .source_sha == $source and
  (.action == "create" or .action == "promote" or .action == "replay") and
  (.expected_row_sha256 | type == "string" and test("^[0-9a-f]{64}$"))
' >/dev/null <<<"$OWNER_INTENT" || {
  echo "deployment producer owner-ready authority is malformed" >&2
  exit 1
}
"$OWNER_PROJECTOR" verify --intent-json "$OWNER_INTENT" >/dev/null

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

HISTORICAL_REPAIR_SOURCE_SHA=$(jq -r .repair.source_sha <<<"$STATE")
[[ "$HISTORICAL_REPAIR_SOURCE_SHA" == "$APPROVED_REPAIR_SOURCE_SHA" ]] || {
  echo "deployment producer is not finalized for the exact merged #3935 source" >&2; exit 1;
}
REPAIR_SOURCE_SHA=$(jq -r .source_sha <<<"$RUNTIME")
RECOVERY_SOURCE_SHA=$(jq -r .repair.orchestrator_sha <<<"$STATE")
BUILD_RUN_ID=$(jq -r .build_run_id <<<"$RUNTIME")
BUILD_RUN_ATTEMPT=$(jq -r .build_run_attempt <<<"$RUNTIME")
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
  .conclusion == "success" and
  (.path == ".github/workflows/recover-sandbox-durable-aop-schema3.yml" or
   .path == "layervai/nhp/.github/workflows/recover-sandbox-durable-aop-schema3.yml@refs/heads/main")
' >/dev/null <<<"$recovery_run" || {
  echo "selected schema-3 recovery run is not the exact completed repaired controller attempt" >&2; exit 1;
}

build_receipt=$("$VERIFY_BUILD_ONLY" "$BUILD_RUN_ID" "$BUILD_RUN_ATTEMPT" "$REPAIR_SOURCE_SHA")
[[ "$build_receipt" == "v1|${BUILD_RUN_ID}|${BUILD_RUN_ATTEMPT}|${REPAIR_SOURCE_SHA}" ]] || {
  echo "schema-3 build-only receipt is malformed" >&2; exit 1;
}

SERVER_PROVENANCE=$("$VERIFY_PROVENANCE" layerv/nhp-server "$REPAIR_SOURCE_SHA" \
  "$BUILD_RUN_ID" "$BUILD_RUN_ATTEMPT" "$APPROVED_STALE_RUNTIME_SERVER_DIGEST")
AC_PROVENANCE=$("$VERIFY_PROVENANCE" layerv/nhp-ac "$REPAIR_SOURCE_SHA" \
  "$BUILD_RUN_ID" "$BUILD_RUN_ATTEMPT" "$APPROVED_STALE_RUNTIME_AC_DIGEST")
[[ "$SERVER_PROVENANCE" == "$(jq -r .server_provenance <<<"$RUNTIME")" &&
   "$AC_PROVENANCE" == "$(jq -r .ac_provenance <<<"$RUNTIME")" &&
   "$SERVER_PROVENANCE" == "v1|${REPAIR_SOURCE_SHA}|layerv/nhp-server|${APPROVED_STALE_RUNTIME_SERVER_DIGEST}" &&
   "$AC_PROVENANCE" == "v1|${REPAIR_SOURCE_SHA}|layerv/nhp-ac|${APPROVED_STALE_RUNTIME_AC_DIGEST}" ]] || {
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
  local expected_asg expected_attestation selector refresh_status asg_json
  [[ "$color" == blue || "$color" == green ]] || { echo "$label active color is malformed" >&2; return 1; }
  expected_asg=$(canonical_asg "$env" "$component" "$color")
  [[ "$asg" == "$expected_asg" ]] || { echo "$label active ASG is not canonical for its color" >&2; return 1; }
  expected_attestation="v2|${PROFILE}|${provenance#v1|}|${asg}"
  selector=$(immutable_image_selector "$provenance")
  [[ "$attestation" == "$expected_attestation" ]] || { echo "$label schema-3 attestation is malformed" >&2; return 1; }
  [[ "$(get_param "/${env}/nhp/${component}/active-color")" == "$color" &&
     "$(get_param "$(slot_asg_param "$env" "$component" "$color")")" == "$asg" &&
     "$(get_param "$(slot_image_param "$env" "$component" "$color")")" == "$selector" &&
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
  "$(jq -r .cell0.attestation <<<"$RUNTIME")" "$(jq -r .cell0.refresh_id <<<"$RUNTIME")" \
  'curl -sfS -o /dev/null http://127.0.0.1:8888/health/live'
CELL0_DEPLOYMENT=$DEPLOYMENT_JSON
prove_deployment cell1 sandbox-cell1 server "$CELL1_COLOR" "$CELL1_ASG" "$SERVER_DIGEST" "$SERVER_PROVENANCE" \
  "$(jq -r .cell1.attestation <<<"$RUNTIME")" "$(jq -r .cell1.refresh_id <<<"$RUNTIME")" \
  'curl -sfS -o /dev/null http://127.0.0.1:8888/health/live'
CELL1_DEPLOYMENT=$DEPLOYMENT_JSON
prove_deployment ac sandbox ac "$AC_COLOR" "$AC_ASG" "$AC_DIGEST" "$AC_PROVENANCE" \
  "$(jq -r .ac.attestation <<<"$RUNTIME")" "$(jq -r .ac.refresh_id <<<"$RUNTIME")" \
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
