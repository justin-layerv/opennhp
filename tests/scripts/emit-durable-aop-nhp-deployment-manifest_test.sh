#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/helpers" "$WORK/repo/.github"
cp -R "$ROOT/.github/scripts" "$WORK/repo/.github/scripts"
ln -s "$ROOT/scripts" "$WORK/repo/scripts"
ln -s "$ROOT/terraform" "$WORK/repo/terraform"
SCRIPT=$WORK/repo/.github/scripts/emit-durable-aop-nhp-deployment-manifest.sh
export FAKE_PARAMS=$WORK/params
REPAIR=422b1d9acac53d50fe5602158fb02c8120ef108d
RECOVERY=abcdefabcdefabcdefabcdefabcdefabcdefabcd
SERVER_DIGEST=sha256:0921191723fd6a4919f22e0dded5775411bb08a682dc9d9f9a69fdcded7674c9
AC_DIGEST=sha256:773bd37e915ac767f57e7656b5c038a8f2c70348901b1e81572584d6cfad566e
RUNTIME=2895963905453d61874858171529968efe8e18e5450d41842854fd2784d1ec78
LIVE_SOURCE=f32335420d67fd235a6fb6598a1fc3d8eaf8dda7
LIVE_RUNTIME=906c0461bf3d44175750b91ec9251de114da0c3646750287656803e3783d5ed0
ORIGINAL=e9b11398a4cea98da6ae5b41cfe635562e1b7c72
ORIGINAL_OWNER="nhp:32635672597:durable-aop-cutover:${ORIGINAL}"
ORIGINAL_STATE_DIGEST=e7ed20adde2ce9e143c9505027a73e415e5dd3d4a9d0c950c912d6398cc5d13e
ORIGINAL_LOCK_DIGEST=6c7224d78837a4d56547409439d9bce30efa9b214367c4f19fd13cc3fe3b2ebd
export REPAIR RECOVERY LIVE_SOURCE SERVER_DIGEST AC_DIGEST
export LIVE_SERVER_SELECTOR=${LIVE_SOURCE}@${SERVER_DIGEST}
export LIVE_AC_SELECTOR=${LIVE_SOURCE}@${AC_DIGEST}
export FAKE_OWNER_ACTIONS=$WORK/owner-actions
export FAKE_IAM_ACTIONS=$WORK/iam-actions
export FAKE_AWS_ACTIONS=$WORK/aws-actions
export FAKE_READ_COUNTS=$WORK/read-counts
STATE_VERSION=31
MAIN_JOURNAL_VERSION=19
ACTIVE_READY_JOURNAL_VERSION=10
QUERY_IAM_JOURNAL_VERSION=2
export STATE_VERSION MAIN_JOURNAL_VERSION ACTIVE_READY_JOURNAL_VERSION QUERY_IAM_JOURNAL_VERSION
(cd "$ROOT/endpoints" && GOWORK=off KBS_SKIP_INIT=1 \
  go run ./cmd/session-control-stale-target-retirement plan) >"$WORK/incident-plan.json"
[[ "$(printf '%s' "$(jq -cS . "$WORK/incident-plan.json")" | sha256sum | awk '{print $1}')" == \
  f434ce1e13c69f8749e9004be26304002e7e8da28939815d062f643124abcfc6 ]]

set_param() {
  local name=$1 value=$2
  awk -F '\t' -v name="$name" '$1 != name' "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"
  printf '%s\t%s\n' "$name" "$value" >>"$FAKE_PARAMS.tmp"
  mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
}

cat >"$WORK/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
service=$1 operation=$2; shift 2
opt() { local key=$1 prior=; shift; for arg in "$@"; do [[ "$prior" == "$key" ]] && { printf '%s' "$arg"; return; }; prior=$arg; done; }
case "$service/$operation" in
  ssm/get-parameter)
    name=$(opt --name "$@")
    query=$(opt --query "$@")
    if [[ "$name" == */active-ready-predecessors* || "$name" == */session-control-query-iam* ]]; then
      [[ $# == 9 && $1 == --name && $2 == "$name" && $3 == --with-decryption &&
         $4 == --query && $5 == "$query" && $6 == --output && $7 == text &&
         $8 == --region && $9 == us-east-2 ]] || exit 99
      printf 'active-read\t%s\t%s\n' "$name" "$query" >>"$FAKE_AWS_ACTIONS"
    else
      [[ $# == 8 && $1 == --name && $2 == "$name" && $3 == --query && $4 == "$query" &&
         $5 == --output && $6 == text && $7 == --region && $8 == us-east-2 ]] || exit 99
    fi
    if [[ "$query" == Parameter.Version ]]; then
      case "$name" in
        */state) printf '%s\n' "$STATE_VERSION" ;;
        */stale-target-retirement) printf '%s\n' "$MAIN_JOURNAL_VERSION" ;;
        */active-ready-predecessors) printf '%s\n' "$ACTIVE_READY_JOURNAL_VERSION" ;;
        */session-control-query-iam) printf '%s\n' "$QUERY_IAM_JOURNAL_VERSION" ;;
        *) echo "unexpected version authority $name" >&2; exit 99 ;;
      esac
      exit 0
    fi
    value=$(awk -F '\t' -v name="$name" '$1 == name {print substr($0,index($0,"\t")+1); found=1} END {exit !found}' "$FAKE_PARAMS") || {
      echo ParameterNotFound >&2; exit 254;
    }
    if [[ "${FAKE_DRIFT_PARAM:-}" == "$name" ]]; then
      key=$(printf '%s' "$name" | sha256sum | awk '{print $1}')
      count=0; [[ ! -f "$FAKE_READ_COUNTS/$key" ]] || count=$(cat "$FAKE_READ_COUNTS/$key")
      count=$((count + 1)); printf '%s\n' "$count" >"$FAKE_READ_COUNTS/$key"
      if [[ "$count" == 2 ]]; then
        if [[ "$name" == */state ]]; then value=$(jq -cS '.phase="validated"' <<<"$value")
        else value=$(jq -cS '.payload += "A"' <<<"$value")
        fi
      fi
    fi
    printf '%s\n' "$value"
    ;;
  ssm/describe-parameters)
    [[ $# == 6 && $1 == --parameter-filters && $3 == --output && $4 == json &&
       $5 == --region && $6 == us-east-2 ]] || exit 99
    case "$2" in
      'Key=Name,Option=Equals,Values=/sandbox/nhp/cutovers/durable-aop-v1/active-ready-predecessors')
        name=/sandbox/nhp/cutovers/durable-aop-v1/active-ready-predecessors
        version=$ACTIVE_READY_JOURNAL_VERSION metadata_mode=${FAKE_ACTIVE_METADATA_MODE:-exact}
        printf 'active-metadata\n' >>"$FAKE_AWS_ACTIONS"
        ;;
      'Key=Name,Option=Equals,Values=/sandbox/nhp/cutovers/durable-aop-v1/session-control-query-iam')
        name=/sandbox/nhp/cutovers/durable-aop-v1/session-control-query-iam
        version=$QUERY_IAM_JOURNAL_VERSION metadata_mode=${FAKE_QUERY_METADATA_MODE:-exact}
        printf 'query-metadata\n' >>"$FAKE_AWS_ACTIONS"
        ;;
      *) exit 99 ;;
    esac
    type=SecureString key=alias/aws/ssm tier=Standard data_type=text
    case $metadata_mode in
      exact) ;;
      wrong_type) type=String ;;
      wrong_key) key=alias/other ;;
      wrong_tier) tier=Advanced ;;
      wrong_data_type) data_type=aws:ec2:image ;;
      wrong_version) version=$((version + 1)) ;;
      missing) printf '{"Parameters":[]}\n'; exit 0 ;;
      extra) jq -cn --arg name "$name" --arg version "$version" '{Parameters:[{Name:$name,Type:"SecureString",KeyId:"alias/aws/ssm",Tier:"Standard",DataType:"text",Version:($version|tonumber),Unknown:true}]}'; exit 0 ;;
      *) exit 98 ;;
    esac
    jq -cn --arg name "$name" --arg type "$type" --arg key "$key" --arg tier "$tier" --arg data "$data_type" --arg version "$version" \
      '{Parameters:[{Name:$name,Type:$type,KeyId:$key,Tier:$tier,DataType:$data,Version:($version|tonumber)}]}'
    ;;
  autoscaling/describe-instance-refreshes)
    [[ "${FAKE_REFRESH_FAILED:-}" != true ]] && printf 'Successful\n' || printf 'Failed\n'
    ;;
  autoscaling/describe-auto-scaling-groups)
    asg=$(opt --auto-scaling-group-names "$@")
    health=Healthy; [[ "${FAKE_ASG_UNHEALTHY:-}" != true ]] || health=Unhealthy
    jq -cn --arg asg "$asg" --arg health "$health" \
      '{AutoScalingGroups:[{AutoScalingGroupName:$asg,MinSize:1,MaxSize:4,DesiredCapacity:1,
        Instances:[{InstanceId:"i-1",LifecycleState:"InService",HealthStatus:$health}]}]}'
    ;;
  *) echo "unexpected aws $service/$operation $*" >&2; exit 99 ;;
esac
EOF

cat >"$WORK/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args="$*"
if [[ "$args" == *'/actions/runs/700/attempts/2'* ]]; then
  conclusion=${FAKE_RECOVERY_CONCLUSION:-success}
  jq -cn --arg sha "$RECOVERY" --arg conclusion "$conclusion" \
    '{head_sha:$sha,head_branch:"main",event:"workflow_dispatch",run_attempt:2,status:"completed",conclusion:$conclusion,path:".github/workflows/recover-sandbox-durable-aop-schema3.yml"}'
elif [[ "$args" == *'/actions/runs/32682520698/attempts/1/jobs'* ]]; then
  jq -cn '
    def step($n;$c): {name:$n,conclusion:$c};
    def build($n): {name:$n,conclusion:"success",steps:[step("Skip notice";"skipped"),
      step("Build image";"success"),step("Generate SBOM";"success"),step("Push to ECR";"success"),
      step("Capture pushed image digest";"success"),step("Attest build provenance (SLSA)";"success"),
      step("Attest SBOM";"success"),step("Attestation summary";"success")]};
    [{jobs:[{name:"Detect Changes",conclusion:"success",steps:[step("Force build override";"success")]},
      {name:"Sandbox Environment Guard",conclusion:"skipped"},
      {name:"Sandbox App Image Drift",conclusion:"skipped"},
      {name:"Test",conclusion:"success",steps:[step("Skip notice";"skipped"),
        step("Run tests (privileged container for iptables)";"success")]},
      build("Build server"),build("Build ac"),
      {name:"Deploy Sandbox - Infrastructure",conclusion:"skipped"},{name:"Deploy Sandbox - QURL Service",conclusion:"skipped"},
      {name:"Deploy Sandbox - Relay",conclusion:"skipped"},{name:"Deploy Sandbox - Blue/Green",conclusion:"skipped"},
      {name:"Deploy Sandbox cell1 - Infrastructure",conclusion:"skipped"},{name:"Deploy Sandbox cell1 - Blue/Green",conclusion:"skipped"},
      {name:"Deploy Sandbox - Control",conclusion:"skipped"},{name:"Deploy Sandbox - Validate",conclusion:"skipped"},
      {name:"NHP Smoke (sandbox)",conclusion:"skipped"}]}]'
elif [[ "$args" == *'/actions/runs/32682520698/attempts/1'* ]]; then
  sha=$LIVE_SOURCE; [[ "${FAKE_BUILD_DRIFT:-}" != true ]] || sha=9999999999999999999999999999999999999999
  jq -cn --arg sha "$sha" \
    '{id:32682520698,repository:{full_name:"layervai/nhp"},head_repository:{full_name:"layervai/nhp"},head_sha:$sha,head_branch:"main",event:"workflow_dispatch",run_attempt:1,status:"completed",conclusion:"success",path:".github/workflows/build-and-push.yml"}'
else
  echo "unexpected gh $args" >&2
  exit 99
fi
EOF

cat >"$WORK/helpers/provenance" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 5 && "$2" == "$LIVE_SOURCE" && "$3" == 32682520698 && "$4" == 1 ]]
if [[ "$1" == layerv/nhp-server ]]; then digest=$SERVER_DIGEST; else digest=$AC_DIGEST; fi
[[ "$5" == "$digest" ]]
printf 'v1|%s|%s|%s\n' "$2" "$1" "$digest"
EOF
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$WORK/helpers/verify-asg"
cat >"$WORK/helpers/owner" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${FAKE_OWNER_VERIFY_FAIL:-}" != true ]] || exit 1
[[ "$1" == verify && "$2" == --intent-json ]]
intent=$3
jq -e --arg repair "$REPAIR" '
  (keys | sort) == ["action","before_row_sha256","client_id","email","expected_assigned_cell_id",
    "expected_created_at","expected_row_sha256","expected_updated_at","expected_usage","provisioned_at",
    "region","schema","source_sha","subject","table"] and
  .schema == "layerv.durable-aop-customer-owner-intent.v1" and
  .client_id == "oScYkXhLitBPO6gBjxo4Rwyw37AdoNPy" and
  .subject == "oScYkXhLitBPO6gBjxo4Rwyw37AdoNPy@clients" and
  .email == "oscykxhlitbpo6gbjxo4rwyw37adonpy-clients@machine.notify.layerv.xyz" and
  .table == "layerv-nhp-sandbox-control-qurl-customers" and .region == "us-east-2" and
  .source_sha == $repair and .expected_row_sha256 == ("d" * 64)
' >/dev/null <<<"$intent"
printf 'verify\n' >>"$FAKE_OWNER_ACTIONS"
jq -r .expected_row_sha256 <<<"$intent"
EOF
cat >"$WORK/helpers/delete-iam" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${FAKE_IAM_VERIFY_FAIL:-}" != true ]] || exit 1
[[ "$1" == verify && "$2" == --intent-json ]]
intent=$3
jq -e '
  (keys | sort) == ["action","attached_role","attached_role_id","before_default_version","before_policy_sha256",
    "before_versions","desired_default_version","desired_policy_sha256","desired_versions","enclosing_operation","leading_keys",
    "policy_arn","policy_id","policy_name","policy_path","prune_version","schema","table_arn"] and
  .schema == "layerv.durable-aop-session-control-delete-iam-intent.v1" and
  .policy_arn == "arn:aws:iam::767397897469:policy/layerv-nhp-sandbox-dynamodb-read" and
  .policy_id == "ANPA3FLD2UT65P2XBQDPY" and .policy_name == "layerv-nhp-sandbox-dynamodb-read" and
  .policy_path == "/" and .attached_role == "layerv-nhp-sandbox-server" and
  .attached_role_id == "AROA3FLD2UT64E3ZXY7UH" and
  .table_arn == "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-nhp-session-control" and
  .action == "dynamodb:DeleteItem" and .enclosing_operation == "TransactWriteItems" and
  .leading_keys == ["ACTIVE#ba9c4949557b0a0b68c6354dbdec84ab68d0e9af183243ac4ac1b89cf0b0c153","EVENT#*"] and
  .before_default_version == "v8" and .before_versions == ["v4","v5","v6","v7","v8"] and
  .before_policy_sha256 == "5c7a320579ae3651861e16014816358eca255e42159e6bcfbe9ea181a29c4073" and
  .prune_version == "v4" and .desired_default_version == "v9" and
  .desired_versions == ["v5","v6","v7","v8","v9"] and
  .desired_policy_sha256 == "c08cde9b65bb0e088ae7534c28f4f7a751ff6888f432bbc451949615b941b4c1"
' >/dev/null <<<"$intent"
printf 'verify\n' >>"$FAKE_IAM_ACTIONS"
jq -cn '
  {schema:"layerv.durable-aop-session-control-delete-iam-receipt.v1",
   policy_arn:"arn:aws:iam::767397897469:policy/layerv-nhp-sandbox-dynamodb-read",
   policy_id:"ANPA3FLD2UT65P2XBQDPY",attached_role:"layerv-nhp-sandbox-server",
   attached_role_id:"AROA3FLD2UT64E3ZXY7UH",
   table_arn:"arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-nhp-session-control",
   action:"dynamodb:DeleteItem",enclosing_operation:"TransactWriteItems",
   leading_keys:["ACTIVE#ba9c4949557b0a0b68c6354dbdec84ab68d0e9af183243ac4ac1b89cf0b0c153","EVENT#*"],
   default_version:"v9",versions:["v5","v6","v7","v8","v9"],
   policy_sha256:"c08cde9b65bb0e088ae7534c28f4f7a751ff6888f432bbc451949615b941b4c1"}
'
EOF
cat >"$WORK/helpers/query-iam" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${FAKE_QUERY_IAM_VERIFY_FAIL:-}" != true ]] || exit 1
[[ "$1" == verify && "$2" == --intent-json ]]
intent=$3
keys='["AC#c1f4c688a88e7309e89533f7e95343901da66587f3bb03f98539a16fccf33be2","TARGET#2b6e9d783ef49c0df152d3a640d63b8846bb056b6ed1672fb27829ac340b85b1","TARGET#71844969e300ec3c25da593e211196c45a03736a57c3850a3bcfab30d5c005f1","TARGET#a8d6468608a3380b602b53c11365972843f0a4ecde6fd44e9aae6a97509e313b","TARGETWORK#2e858d866b8756b13117959015df2228a2f9582e24152035b5962b0142aa0420","TARGETWORK#316b00aa5b86de97fd481b7af9cb1ef1a6a432aba90a9c768c26b4bcd4ea4665","TARGETWORK#76dc3461739e82e34f454d811b88ac0e90e0bf4e2bdcf77b5f160b018975ac92"]'
jq -e --argjson keys "$keys" '
  (keys | sort) == ["action","attached_role","attached_role_id","before_default_version","before_policy_sha256",
    "before_versions","desired_default_version","desired_policy_sha256","desired_versions","leading_keys",
    "policy_arn","policy_id","policy_name","policy_path","prune_version","schema","table_arn"] and
  .schema == "layerv.durable-aop-session-control-query-iam-intent.v1" and
  .policy_arn == "arn:aws:iam::767397897469:policy/nhp-sandbox-github-actions-terraform-apply-data" and
  .policy_id == "ANPA3FLD2UT62EB536PKL" and .policy_name == "nhp-sandbox-github-actions-terraform-apply-data" and
  .policy_path == "/" and .attached_role == "nhp-sandbox-github-actions" and
  .attached_role_id == "AROA3FLD2UT6QBE2U53EL" and
  .table_arn == "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-nhp-session-control" and
  .action == "dynamodb:Query" and .leading_keys == $keys and
  .before_default_version == "v21" and .before_versions == ["v17","v18","v19","v20","v21"] and
  .before_policy_sha256 == "de72b914f4019aa10587414dd759bb4b46e2dcd1843d3183b913547c17129433" and
  .prune_version == "v17" and .desired_default_version == "v22" and
  .desired_versions == ["v18","v19","v20","v21","v22"] and
  .desired_policy_sha256 == "161dc3acd79e1f63accca5df94da0c4deeebebe1271b202f648fcb853ba1f9ce"
' >/dev/null <<<"$intent"
printf 'query-verify\n' >>"$FAKE_IAM_ACTIONS"
jq -cnS --argjson keys "$keys" '{schema:"layerv.durable-aop-session-control-query-iam-receipt.v1",
  policy_arn:"arn:aws:iam::767397897469:policy/nhp-sandbox-github-actions-terraform-apply-data",
  policy_id:"ANPA3FLD2UT62EB536PKL",attached_role:"nhp-sandbox-github-actions",
  attached_role_id:"AROA3FLD2UT6QBE2U53EL",
  table_arn:"arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-nhp-session-control",
  action:"dynamodb:Query",leading_keys:$keys,default_version:"v22",
  versions:["v18","v19","v20","v21","v22"],
  policy_sha256:"161dc3acd79e1f63accca5df94da0c4deeebebe1271b202f648fcb853ba1f9ce"}'
EOF
chmod +x "$WORK/bin/"* "$WORK/helpers/"*

fixture_fence_digest() {
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

fixture_owner_digest() {
  local owner=$1 field
  {
    for field in cell_id ac_id public_key lifecycle_version work_version task_count pending_count phase boot_id \
      flush_generation target_version target_authority_version target_counted_active_slot activated_control_version \
      ready_control_version target_created_at_ms target_prepared_at_ms target_updated_at_ms aak_enqueued_at_ms \
      aak_transaction_id created_at_ms updated_at_ms retired_at_ms; do
      printf '\0%s' "$(jq -r ".${field}" <<<"$owner")"
    done
  } | sha256sum | awk '{print $1}'
}

fixture_target_session_pk() {
  local fence=$1
  printf 'v1\0%s\0%s\0%s\0%s\0%s' \
    "$(jq -r .control_cell_id <<<"$fence")" "$(jq -r .ac_id <<<"$fence")" \
    "$(jq -r .public_key <<<"$fence")" "$(jq -r .boot_id <<<"$fence")" \
    "$(jq -r .flush_generation <<<"$fence")" | sha256sum | awk '{print "TARGET#" $1}'
}

fixture_active_ready_plan() {
  local plan index fence owner
  plan=$(jq -cn '
    def fence($i): {ac_id:"layerv-ac-tf",public_key:("ready-key-"+($i|tostring)),boot_id:("ready-boot-"+($i|tostring)),
      flush_generation:"4",version:"46",authority_version:"7",counted_active_slot:true,control_cell_id:"cell0",
      activated_control_version:"250",ready_control_version:"250",aak_enqueued_at_ms:"1787550000000",
      aak_transaction_id:"1",created_at_ms:"1787540000000",prepared_at_ms:"1787545000000"};
    def owner($i): {cell_id:"cell0",ac_id:"layerv-ac-tf",public_key:("ready-key-"+($i|tostring)),
      lifecycle_version:"9",work_version:"7",task_count:"0",pending_count:"0",phase:"READY",
      boot_id:("ready-boot-"+($i|tostring)),flush_generation:"4",target_version:"46",target_authority_version:"7",
      target_counted_active_slot:true,activated_control_version:"250",ready_control_version:"250",
      target_created_at_ms:"1787540000000",target_prepared_at_ms:"1787545000000",target_updated_at_ms:"1787550000000",
      aak_enqueued_at_ms:"1787550000000",aak_transaction_id:"1",created_at_ms:"1787540000000",
      updated_at_ms:"1787550000000",retired_at_ms:"0"};
    {schema:"layerv.durable-aop-active-ready-predecessor-plan.v1",table:"layerv-nhp-sandbox-cell0-nhp-session-control",
     region:"us-east-2",ac_id:"layerv-ac-tf",control_cell_id:"cell0",
     targets:[range(1;4) | {id:("active-ready-predecessor-"+(.|tostring)),fence:(fence(.)),
       fence_sha256:"",owner:(owner(.)),owner_sha256:""}]}')
  for index in 0 1 2; do
    fence=$(jq -c --argjson index "$index" '.targets[$index].fence' <<<"$plan")
    owner=$(jq -c --argjson index "$index" '.targets[$index].owner' <<<"$plan")
    plan=$(jq -c --argjson index "$index" --arg fence_sha "$(fixture_fence_digest "$fence")" \
      --arg owner_sha "$(fixture_owner_digest "$owner")" \
      '.targets[$index].fence_sha256=$fence_sha | .targets[$index].owner_sha256=$owner_sha' <<<"$plan")
  done
  jq -cS . <<<"$plan"
}

fixture_active_ready_complete() {
  local plan=$1 directory_sha=$2 targets='[]' index planned id fence owner decommission latch quiescence receipt row
  local plan_sha quiescence_sha
  plan_sha=$(printf '%s' "$plan" | sha256sum | awk '{print $1}')
  for index in 0 1 2; do
    planned=$(jq -c --argjson index "$index" '.targets[$index]' <<<"$plan")
    id=$(jq -r .id <<<"$planned")
    fence=$(jq -cS .fence <<<"$planned")
    owner=$(jq -cS .owner <<<"$planned")
    decommission=$(jq -cS '.phase="DECOMMISSIONING" | .lifecycle_version=((.lifecycle_version|tonumber)+1|tostring)' <<<"$owner")
    latch=$(jq -cn --arg id "$id" --arg fence "$(jq -r .fence_sha256 <<<"$planned")" \
      --argjson owner "$decommission" --arg owner_sha "$(fixture_owner_digest "$decommission")" \
      --arg directory "$directory_sha" \
      '{schema:"layerv.durable-aop-active-ready-latch-receipt.v1",target_id:$id,
       fence_sha256:$fence,owner:$owner,owner_sha256:$owner_sha,directory_sha256:$directory}')
    quiescence=$(jq -cn --arg id "$id" --arg fence "$(jq -r .fence_sha256 <<<"$planned")" \
      --arg owner_sha "$(fixture_owner_digest "$decommission")" --arg session "$(fixture_target_session_pk "$fence")" \
      --arg directory "$directory_sha" \
      '{schema:"layerv.durable-aop-active-ready-quiescence-receipt.v1",target_id:$id,
       fence_sha256:$fence,owner_sha256:$owner_sha,owner_task_count:"0",owner_pending_count:"0",
       target_session_pk:$session,target_session_count:"0",directory_sha256:$directory}')
    receipt=$(jq -cn --arg id "$id" --arg key "$(jq -r .public_key <<<"$fence")" \
      --arg version "$(( $(jq -r .version <<<"$fence") + 1 ))" \
      --arg authority "$(( $(jq -r .authority_version <<<"$fence") + 1 ))" \
      '{schema:"layerv.durable-aop-stale-target-retirement-receipt.v1",target_id:$id,
       public_key:$key,version:$version,authority_version:$authority,counted_active_slot:false,
       retired_at_ms:"1787560000000",retired_target_sha256:("d"*64)}')
    row=$(jq -cn --arg id "$id" --arg fence "$(jq -r .fence_sha256 <<<"$planned")" \
      --argjson latch "$latch" --argjson quiescence "$quiescence" --argjson receipt "$receipt" \
      '{id:$id,fence_sha256:$fence,status:"retired",latch_receipt:$latch,
       quiescence_receipt:$quiescence,receipt:$receipt}')
    targets=$(jq -c --argjson row "$row" '. + [$row]' <<<"$targets")
  done
  quiescence_sha=$(jq -cS '[.[] | .status="quiescent" | del(.receipt)]' <<<"$targets" | sha256sum | awk '{print $1}')
  jq -cS -n --arg recovery "$RECOVERY" --arg plan_sha "$plan_sha" --arg quiescence_sha "$quiescence_sha" \
    --arg directory "$directory_sha" --argjson plan "$plan" --argjson targets "$targets" '
    {schema:"layerv.durable-aop-active-ready-predecessor-journal.v1",status:"complete",
     source_state_version:30,source_state_sha256:"4268c108fe2685c5a475d05f2ec98d5d58c54618dc3934289b97bc0da855dca6",
     source_main_journal_parameter:"/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement",
     source_main_journal_version:8,source_main_journal_sha256:"49a0da6ea26c551ed99f51ad1e1a4608aa89ab7d1f97a40f22c2c12ce99b1a5c",
     orchestrator_sha:$recovery,fence_drain_sha256:$directory,plan:$plan,plan_sha256:$plan_sha,
     quiescence_sha256:$quiescence_sha,targets:$targets}'
}

fixture_directory_receipt() {
  local count=$1 version=$2 updated=$3 blocked=${4:-false} overflow=${5:-0}
  local event=${6:-} prepared=${7:-0} selected=${8:-0} digest
  digest=$({
    printf '\0%s' v1 cell0 "$version" "$count" "$blocked" "$overflow" "$event" "$prepared" "$selected" \
      1787530000000 "$updated"
  } | sha256sum | awk '{print $1}')
  jq -cn --arg count "$count" --arg version "$version" --argjson blocked "$blocked" --arg overflow "$overflow" \
    --arg event "$event" --arg prepared "$prepared" --arg selected "$selected" \
    --arg updated "$updated" --arg digest "$digest" '
    {schema:"layerv.durable-aop-fence-directory-receipt.v1",cell_id:"cell0",version:$version,
     active_fence_count:$count,admission_blocked:$blocked,overflow_close_count:$overflow,overflow_leader_event_id:$event,
     overflow_leader_prepared_directory_version:$prepared,overflow_leader_selected_directory_version:$selected,
     created_at_ms:"1787530000000",updated_at_ms:$updated,directory_sha256:$digest}'
}

fixture_retired_ledger() {
  local plan=$1
  jq -c '[.targets[] | {id,fence_sha256,status:"retired",receipt:{
    schema:"layerv.durable-aop-stale-target-retirement-receipt.v1",target_id:.id,
    public_key:.fence.public_key,version:((.fence.version|tonumber)+1|tostring),
    authority_version:((.fence.authority_version|tonumber)+1|tostring),counted_active_slot:false,
    retired_at_ms:"1787540000000",retired_target_sha256:("d"*64)}}]' <<<"$plan"
}

encode_fixture_journal() {
  python3 -c 'import base64,gzip,json,sys; raw=sys.stdin.buffer.read(); json.loads(raw); print(json.dumps({"encoding":"gzip-base64","payload":base64.b64encode(gzip.compress(raw,9,mtime=0)).decode(),"schema":"layerv.durable-aop-stale-target-journal-envelope.v1"},sort_keys=True,separators=(",",":")))'
}

encode_active_ready_journal() {
  python3 -c 'import base64,gzip,json,sys; raw=sys.stdin.buffer.read(); json.loads(raw); print(json.dumps({"encoding":"gzip-base64","payload":base64.b64encode(gzip.compress(raw,9,mtime=0)).decode(),"schema":"layerv.durable-aop-active-ready-predecessor-journal-envelope.v1"},sort_keys=True,separators=(",",":")))'
}

encode_query_iam_journal() {
  python3 -c 'import base64,gzip,json,sys; raw=sys.stdin.buffer.read(); json.loads(raw); print(json.dumps({"encoding":"gzip-base64","payload":base64.b64encode(gzip.compress(raw,9,mtime=0)).decode(),"schema":"layerv.durable-aop-session-control-query-iam-journal-envelope.v1"},sort_keys=True,separators=(",",":")))'
}

decode_fixture_journal() {
  python3 -c 'import base64,gzip,json,sys; v=json.load(sys.stdin); sys.stdout.buffer.write(gzip.decompress(base64.b64decode(v["payload"],validate=True)))'
}

decode_active_ready_journal() {
  python3 -c 'import base64,gzip,json,sys; v=json.load(sys.stdin); sys.stdout.buffer.write(gzip.decompress(base64.b64decode(v["payload"],validate=True)))'
}

decode_query_iam_journal() {
  python3 -c 'import base64,gzip,json,sys; v=json.load(sys.stdin); sys.stdout.buffer.write(gzip.decompress(base64.b64decode(v["payload"],validate=True)))'
}

mutate_fixture_journal() {
  local filter=$1 envelope journal digest state
  envelope=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
  journal=$(printf '%s' "$envelope" | decode_fixture_journal | jq -cS "$filter")
  envelope=$(printf '%s' "$journal" | encode_fixture_journal)
  digest=$(printf '%s' "$envelope" | sha256sum | awk '{print $1}')
  set_param /sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement "$envelope"
  set_param "/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement:${MAIN_JOURNAL_VERSION}" "$envelope"
  state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
  set_param /sandbox/nhp/cutovers/durable-aop-v1/state \
    "$(jq -c --arg digest "$digest" '.repair.stale_target_retirement_ref.sha256=$digest' <<<"$state")"
}

mutate_active_ready_journal() {
  local filter=$1 envelope journal
  envelope=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/active-ready-predecessors" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
  journal=$(printf '%s' "$envelope" | decode_active_ready_journal | jq -cS "$filter")
  envelope=$(printf '%s' "$journal" | encode_active_ready_journal)
  install_active_ready_envelope "$envelope"
}

install_active_ready_envelope() {
  local envelope=$1 digest main main_envelope main_digest state
  digest=$(printf '%s' "$envelope" | sha256sum | awk '{print $1}')
  set_param /sandbox/nhp/cutovers/durable-aop-v1/active-ready-predecessors "$envelope"
  set_param "/sandbox/nhp/cutovers/durable-aop-v1/active-ready-predecessors:${ACTIVE_READY_JOURNAL_VERSION}" "$envelope"
  main_envelope=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
  main=$(printf '%s' "$main_envelope" | decode_fixture_journal | \
    jq -cS --arg digest "$digest" '.runtime.ready_predecessor_ref.sha256=$digest')
  main_envelope=$(printf '%s' "$main" | encode_fixture_journal)
  main_digest=$(printf '%s' "$main_envelope" | sha256sum | awk '{print $1}')
  set_param /sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement "$main_envelope"
  set_param "/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement:${MAIN_JOURNAL_VERSION}" "$main_envelope"
  state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
  set_param /sandbox/nhp/cutovers/durable-aop-v1/state \
    "$(jq -c --arg digest "$main_digest" '.repair.stale_target_retirement_ref.sha256=$digest' <<<"$state")"
}

mutate_query_iam_journal() {
  local filter=$1 envelope journal
  envelope=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/session-control-query-iam" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
  journal=$(printf '%s' "$envelope" | decode_query_iam_journal | jq -cS "$filter")
  envelope=$(printf '%s' "$journal" | encode_query_iam_journal)
  install_query_iam_envelope "$envelope"
}

install_query_iam_envelope() {
  local envelope=$1 digest main main_envelope main_digest state
  digest=$(printf '%s' "$envelope" | sha256sum | awk '{print $1}')
  set_param /sandbox/nhp/cutovers/durable-aop-v1/session-control-query-iam "$envelope"
  set_param "/sandbox/nhp/cutovers/durable-aop-v1/session-control-query-iam:${QUERY_IAM_JOURNAL_VERSION}" "$envelope"
  main_envelope=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
  main=$(printf '%s' "$main_envelope" | decode_fixture_journal | \
    jq -cS --arg digest "$digest" '.runtime.session_control_query_iam_ref.sha256=$digest')
  main_envelope=$(printf '%s' "$main" | encode_fixture_journal)
  main_digest=$(printf '%s' "$main_envelope" | sha256sum | awk '{print $1}')
  set_param /sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement "$main_envelope"
  set_param "/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement:${MAIN_JOURNAL_VERSION}" "$main_envelope"
  state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
  set_param /sandbox/nhp/cutovers/durable-aop-v1/state \
    "$(jq -c --arg digest "$main_digest" '.repair.stale_target_retirement_ref.sha256=$digest' <<<"$state")"
}

seed() {
  : >"$FAKE_PARAMS"
  rm -rf "$FAKE_READ_COUNTS"
  mkdir -p "$FAKE_READ_COUNTS"
  local server_provenance="v1|${REPAIR}|layerv/nhp-server|${SERVER_DIGEST}"
  local ac_provenance="v1|${REPAIR}|layerv/nhp-ac|${AC_DIGEST}"
  local live_server_provenance="v1|${LIVE_SOURCE}|layerv/nhp-server|${SERVER_DIGEST}"
  local live_ac_provenance="v1|${LIVE_SOURCE}|layerv/nhp-ac|${AC_DIGEST}"
  local lock original_state state journal envelope journal_digest incident_plan incident_ledger fence_start fence_drain
  local active_plan active_journal active_envelope active_digest active_plan_digest active_quiescence_digest ac_plan_digest
  local query_keys query_intent query_receipt query_journal query_envelope query_digest
  local preferences c0_intent c1_intent ac_intent
  local iam_intent iam_receipt
  original_state=$(jq -cn --arg image "$ORIGINAL" --arg owner "$ORIGINAL_OWNER" '
    {schema:2,image:$image,orchestrator_sha:$image,lock_owner:$owner,phase:"old_servers_terminated",
     ac:{old_color:"blue",new_color:"green",old_asg:"layerv-nhp-sandbox-ac",new_asg:"layerv-nhp-sandbox-ac-green",old_min:3,old_max:3,old_desired:3,new_attestation:("v2|durable-aop-v1|"+$image+"|layerv/nhp-ac|sha256:2e38672ef7680c60521694c3f2a59e9a74ed8f2d56bfe1fb41a97f3040b4e279|layerv-nhp-sandbox-ac-green")},
     cell0:{old_color:"green",new_color:"blue",old_asg:"layerv-nhp-sandbox-server-green",new_asg:"layerv-nhp-sandbox-server",new_attestation:("v2|durable-aop-v1|"+$image+"|layerv/nhp-server|sha256:94a5d91373ca261e4edfffc2ca743768b7da573bacd9dadac87c2dd7d0cbc1f4|layerv-nhp-sandbox-server")},
     cell1:{old_color:"blue",new_color:"green",old_asg:"layerv-nhp-sandbox-cell1-server",new_asg:"layerv-nhp-sandbox-cell1-server-green",new_attestation:("v2|durable-aop-v1|"+$image+"|layerv/nhp-server|sha256:94a5d91373ca261e4edfffc2ca743768b7da573bacd9dadac87c2dd7d0cbc1f4|layerv-nhp-sandbox-cell1-server-green")}}')
  lock=$(jq -cn --arg owner "$ORIGINAL_OWNER" --arg image "$ORIGINAL" \
    '{schema:1,kind:"durable-aop-cutover-recovery",owner:$owner,image:$image,orchestrator_sha:$image,created_at:1787485146,expires_at:253402300799}')
  [[ "$(printf '%s' "$(jq -cS . <<<"$original_state")" | sha256sum | awk '{print $1}')" == "$ORIGINAL_STATE_DIGEST" ]]
  [[ "$(printf '%s' "$(jq -cS . <<<"$lock")" | sha256sum | awk '{print $1}')" == "$ORIGINAL_LOCK_DIGEST" ]]
  incident_plan=$(jq -cS . "$WORK/incident-plan.json")
  incident_ledger=$(fixture_retired_ledger "$incident_plan")
  fence_start=$(fixture_directory_receipt "${FAKE_FENCE_START_COUNT:-82}" 83 1787553983425 \
    "${FAKE_FENCE_START_BLOCKED:-false}" "${FAKE_FENCE_START_OVERFLOW:-0}" \
    "${FAKE_FENCE_START_EVENT:-}" "${FAKE_FENCE_START_PREPARED:-0}" "${FAKE_FENCE_START_SELECTED:-0}")
  # The later version pins that zero-target closes may arrive after the exact
  # starting snapshot; terminal publication still requires stable zero.
  fence_drain=$(fixture_directory_receipt 0 106 1787555000000)
  active_plan=$(fixture_active_ready_plan)
  active_journal=$(fixture_active_ready_complete "$active_plan" "$(jq -r .directory_sha256 <<<"$fence_drain")")
  active_envelope=$(printf '%s' "$active_journal" | encode_active_ready_journal)
  active_digest=$(printf '%s' "$active_envelope" | sha256sum | awk '{print $1}')
  active_plan_digest=$(jq -r .plan_sha256 <<<"$active_journal")
  active_quiescence_digest=$(jq -r .quiescence_sha256 <<<"$active_journal")
  ac_plan_digest=$(printf 'v1\n%s\n%s\n' "$active_plan_digest" "$active_quiescence_digest" | \
    sha256sum | awk '{print $1}')
  preferences='{"MinHealthyPercentage":100,"MaxHealthyPercentage":200,"InstanceWarmup":60,"SkipMatching":false}'
  c0_intent=$(printf 'v2\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
    cell0 layerv-nhp-sandbox-server "$LIVE_SOURCE" 32682520698 1 "$live_server_provenance" "$RECOVERY" \
    "$preferences" prior-cell0 - | sha256sum | awk '{print $1}')
  c1_intent=$(printf 'v2\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
    cell1 layerv-nhp-sandbox-cell1-server-green "$LIVE_SOURCE" 32682520698 1 "$live_server_provenance" "$RECOVERY" \
    "$preferences" prior-cell1 - | sha256sum | awk '{print $1}')
  ac_intent=$(printf 'v2\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
    ac layerv-nhp-sandbox-ac-green "$LIVE_SOURCE" 32682520698 1 "$live_ac_provenance" "$RECOVERY" \
    "$preferences" prior-ac "$ac_plan_digest" | sha256sum | awk '{print $1}')
  iam_intent=$(jq -cn '
    {schema:"layerv.durable-aop-session-control-delete-iam-intent.v1",
     policy_arn:"arn:aws:iam::767397897469:policy/layerv-nhp-sandbox-dynamodb-read",
     policy_id:"ANPA3FLD2UT65P2XBQDPY",policy_name:"layerv-nhp-sandbox-dynamodb-read",policy_path:"/",
     attached_role:"layerv-nhp-sandbox-server",attached_role_id:"AROA3FLD2UT64E3ZXY7UH",
     table_arn:"arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-nhp-session-control",
     action:"dynamodb:DeleteItem",enclosing_operation:"TransactWriteItems",
     leading_keys:["ACTIVE#ba9c4949557b0a0b68c6354dbdec84ab68d0e9af183243ac4ac1b89cf0b0c153","EVENT#*"],
     before_default_version:"v8",before_versions:["v4","v5","v6","v7","v8"],
     before_policy_sha256:"5c7a320579ae3651861e16014816358eca255e42159e6bcfbe9ea181a29c4073",
     prune_version:"v4",desired_default_version:"v9",desired_versions:["v5","v6","v7","v8","v9"],
     desired_policy_sha256:"c08cde9b65bb0e088ae7534c28f4f7a751ff6888f432bbc451949615b941b4c1"}')
  iam_receipt=$(jq -cn '
    {schema:"layerv.durable-aop-session-control-delete-iam-receipt.v1",
     policy_arn:"arn:aws:iam::767397897469:policy/layerv-nhp-sandbox-dynamodb-read",
     policy_id:"ANPA3FLD2UT65P2XBQDPY",attached_role:"layerv-nhp-sandbox-server",
     attached_role_id:"AROA3FLD2UT64E3ZXY7UH",
     table_arn:"arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-nhp-session-control",
     action:"dynamodb:DeleteItem",enclosing_operation:"TransactWriteItems",
     leading_keys:["ACTIVE#ba9c4949557b0a0b68c6354dbdec84ab68d0e9af183243ac4ac1b89cf0b0c153","EVENT#*"],
     default_version:"v9",versions:["v5","v6","v7","v8","v9"],
     policy_sha256:"c08cde9b65bb0e088ae7534c28f4f7a751ff6888f432bbc451949615b941b4c1"}')
  query_keys='["AC#c1f4c688a88e7309e89533f7e95343901da66587f3bb03f98539a16fccf33be2","TARGET#2b6e9d783ef49c0df152d3a640d63b8846bb056b6ed1672fb27829ac340b85b1","TARGET#71844969e300ec3c25da593e211196c45a03736a57c3850a3bcfab30d5c005f1","TARGET#a8d6468608a3380b602b53c11365972843f0a4ecde6fd44e9aae6a97509e313b","TARGETWORK#2e858d866b8756b13117959015df2228a2f9582e24152035b5962b0142aa0420","TARGETWORK#316b00aa5b86de97fd481b7af9cb1ef1a6a432aba90a9c768c26b4bcd4ea4665","TARGETWORK#76dc3461739e82e34f454d811b88ac0e90e0bf4e2bdcf77b5f160b018975ac92"]'
  query_intent=$(jq -cnS --argjson keys "$query_keys" '{schema:"layerv.durable-aop-session-control-query-iam-intent.v1",
    policy_arn:"arn:aws:iam::767397897469:policy/nhp-sandbox-github-actions-terraform-apply-data",
    policy_id:"ANPA3FLD2UT62EB536PKL",policy_name:"nhp-sandbox-github-actions-terraform-apply-data",policy_path:"/",
    attached_role:"nhp-sandbox-github-actions",attached_role_id:"AROA3FLD2UT6QBE2U53EL",
    table_arn:"arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-nhp-session-control",
    action:"dynamodb:Query",leading_keys:$keys,before_default_version:"v21",
    before_versions:["v17","v18","v19","v20","v21"],
    before_policy_sha256:"de72b914f4019aa10587414dd759bb4b46e2dcd1843d3183b913547c17129433",
    prune_version:"v17",desired_default_version:"v22",desired_versions:["v18","v19","v20","v21","v22"],
    desired_policy_sha256:"161dc3acd79e1f63accca5df94da0c4deeebebe1271b202f648fcb853ba1f9ce"}')
  query_receipt=$(jq -cnS --argjson keys "$query_keys" '{schema:"layerv.durable-aop-session-control-query-iam-receipt.v1",
    policy_arn:"arn:aws:iam::767397897469:policy/nhp-sandbox-github-actions-terraform-apply-data",
    policy_id:"ANPA3FLD2UT62EB536PKL",attached_role:"nhp-sandbox-github-actions",
    attached_role_id:"AROA3FLD2UT6QBE2U53EL",
    table_arn:"arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-nhp-session-control",
    action:"dynamodb:Query",leading_keys:$keys,default_version:"v22",versions:["v18","v19","v20","v21","v22"],
    policy_sha256:"161dc3acd79e1f63accca5df94da0c4deeebebe1271b202f648fcb853ba1f9ce"}')
  query_journal=$(jq -cnS --argjson intent "$query_intent" --argjson receipt "$query_receipt" \
    '{intent:$intent,receipt:$receipt,status:"ready"}')
  query_envelope=$(printf '%s' "$query_journal" | encode_query_iam_journal)
  query_digest=$(printf '%s' "$query_envelope" | sha256sum | awk '{print $1}')
  state=$(jq -cn --arg repair "$REPAIR" --arg recovery "$RECOVERY" --arg runtime "$RUNTIME" \
    --arg live_source "$LIVE_SOURCE" --arg live_runtime "$LIVE_RUNTIME" \
    --arg server "$server_provenance" --arg ac "$ac_provenance" \
    --arg live_server "$live_server_provenance" --arg live_ac "$live_ac_provenance" \
    --argjson incident_plan "$incident_plan" --argjson incident_ledger "$incident_ledger" \
    --arg active_parameter /sandbox/nhp/cutovers/durable-aop-v1/active-ready-predecessors \
    --argjson active_version "$ACTIVE_READY_JOURNAL_VERSION" --arg active_digest "$active_digest" \
    --arg query_parameter /sandbox/nhp/cutovers/durable-aop-v1/session-control-query-iam \
    --argjson query_version "$QUERY_IAM_JOURNAL_VERSION" --arg query_digest "$query_digest" \
    --argjson fence_start "$fence_start" \
    --argjson fence_drain "$fence_drain" --argjson preferences "$preferences" \
    --arg c0_intent "$c0_intent" --arg c1_intent "$c1_intent" --arg ac_intent "$ac_intent" \
    --argjson iam_intent "$iam_intent" --argjson iam_receipt "$iam_receipt" \
    --argjson lock "$lock" --arg state_digest "$ORIGINAL_STATE_DIGEST" --arg lock_digest "$ORIGINAL_LOCK_DIGEST" '
    {schema:3,phase:"repaired",original:{state_version:7,state_sha256:$state_digest,
      lock:$lock,lock_version:2,lock_sha256:$lock_digest},
     repair:{orchestrator_sha:$recovery,source_sha:$repair,build_run_id:"800",build_run_attempt:"3",
      runtime_manifest:$runtime,server_provenance:$server,ac_provenance:$ac,
      cell0_attestation:("v2|durable-aop-v1|"+$repair+"|layerv/nhp-server|"+($server|split("|")[-1])+"|layerv-nhp-sandbox-server"),
      cell1_attestation:("v2|durable-aop-v1|"+$repair+"|layerv/nhp-server|"+($server|split("|")[-1])+"|layerv-nhp-sandbox-cell1-server-green"),
      ac_attestation:("v2|durable-aop-v1|"+$repair+"|layerv/nhp-ac|"+($ac|split("|")[-1])+"|layerv-nhp-sandbox-ac-green"),
      cell0_refresh_id:"refresh-cell0",cell1_refresh_id:"refresh-cell1",ac_refresh_id:"refresh-ac",
      customer_lifecycle:"",connector_lifecycle:"",
      owner:{status:"ready",intent:{schema:"layerv.durable-aop-customer-owner-intent.v1",
        action:"create",before_row_sha256:"absent",client_id:"oScYkXhLitBPO6gBjxo4Rwyw37AdoNPy",
        subject:"oScYkXhLitBPO6gBjxo4Rwyw37AdoNPy@clients",
        email:"oscykxhlitbpo6gbjxo4rwyw37adonpy-clients@machine.notify.layerv.xyz",
        table:"layerv-nhp-sandbox-control-qurl-customers",region:"us-east-2",source_sha:$repair,
        provisioned_at:"2026-08-23T21:00:00Z",expected_created_at:"2026-08-23T21:00:00Z",
        expected_updated_at:"2026-08-23T21:00:00Z",expected_usage:"0",expected_assigned_cell_id:"",
        expected_row_sha256:("d"*64)}},
      stale_target_retirement:{schema:"layerv.durable-aop-stale-target-retirement-journal.v1",status:"complete",
        source_state_version:"22",source_state_sha256:"b972283f4d37bfa6b2d672b531a6d87a5ab305e0973d5a24d5d19e75f45ef348",
        incident_plan_sha256:"f434ce1e13c69f8749e9004be26304002e7e8da28939815d062f643124abcfc6",
        incident_plan:$incident_plan,incident_targets:$incident_ledger,
        runtime:{source_sha:$live_source,build_run_id:"32682520698",build_run_attempt:"1",runtime_manifest:$live_runtime,
          server_provenance:$live_server,ac_provenance:$live_ac,preferences:$preferences,
          cell0:{asg:"layerv-nhp-sandbox-server",attestation:("v2|durable-aop-v1|"+$live_source+"|layerv/nhp-server|"+($live_server|split("|")[-1])+"|layerv-nhp-sandbox-server"),prior_refresh_id:"prior-cell0",intent_sha256:$c0_intent,refresh_id:"runtime-cell0"},
          cell1:{asg:"layerv-nhp-sandbox-cell1-server-green",attestation:("v2|durable-aop-v1|"+$live_source+"|layerv/nhp-server|"+($live_server|split("|")[-1])+"|layerv-nhp-sandbox-cell1-server-green"),prior_refresh_id:"prior-cell1",intent_sha256:$c1_intent,refresh_id:"runtime-cell1"},
          ac:{asg:"layerv-nhp-sandbox-ac-green",attestation:("v2|durable-aop-v1|"+$live_source+"|layerv/nhp-ac|"+($live_ac|split("|")[-1])+"|layerv-nhp-sandbox-ac-green"),prior_refresh_id:"prior-ac",intent_sha256:$ac_intent,refresh_id:"runtime-ac"},
          server_refresh_orchestrator_sha:$recovery,
          session_control_delete_iam:{status:"ready",intent:$iam_intent,receipt:$iam_receipt},
          session_control_query_iam_ref:{parameter:$query_parameter,version:$query_version,sha256:$query_digest},
          fence_start:$fence_start,fence_drain:$fence_drain,
          predecessor_plan:null,predecessor_plan_sha256:"",predecessor_targets:[],
          ready_predecessor_ref:{parameter:$active_parameter,version:$active_version,sha256:$active_digest}}}}}')
  journal=$(jq -cS .repair.stale_target_retirement <<<"$state")
  envelope=$(printf '%s' "$journal" | encode_fixture_journal)
  journal_digest=$(printf '%s' "$envelope" | sha256sum | awk '{print $1}')
  state=$(jq -c --arg parameter /sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement \
    --argjson version "$MAIN_JOURNAL_VERSION" --arg digest "$journal_digest" '
      del(.repair.stale_target_retirement) |
      .repair.stale_target_retirement_ref={parameter:$parameter,version:$version,sha256:$digest}
    ' <<<"$state")
  set_param /sandbox/nhp/cutovers/durable-aop-v1/state "$state"
  set_param /sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement "$envelope"
  set_param "/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement:${MAIN_JOURNAL_VERSION}" "$envelope"
  set_param /sandbox/nhp/cutovers/durable-aop-v1/active-ready-predecessors "$active_envelope"
  set_param "/sandbox/nhp/cutovers/durable-aop-v1/active-ready-predecessors:${ACTIVE_READY_JOURNAL_VERSION}" "$active_envelope"
  set_param /sandbox/nhp/cutovers/durable-aop-v1/session-control-query-iam "$query_envelope"
  set_param "/sandbox/nhp/cutovers/durable-aop-v1/session-control-query-iam:${QUERY_IAM_JOURNAL_VERSION}" "$query_envelope"
  set_param /layerv-nhp-sandbox/qurl-live-env-lock "$lock"
  set_param /sandbox/nhp/cutovers/durable-aop-v1/state:7 "$original_state"
  set_param /layerv-nhp-sandbox/qurl-live-env-lock:2 "$lock"
  for spec in \
    'sandbox server blue layerv-nhp-sandbox-server' \
    'sandbox-cell1 server green layerv-nhp-sandbox-cell1-server-green' \
    'sandbox ac green layerv-nhp-sandbox-ac-green'; do
    read -r env component color asg <<<"$spec"
    if [[ "$component" == ac ]]; then provenance=$live_ac_provenance; else provenance=$live_server_provenance; fi
    set_param "/${env}/nhp/${component}/active-color" "$color"
    suffix=; [[ "$color" == green ]] && suffix=green-
    set_param "/${env}/nhp/${component}/${suffix}asg-name" "$asg"
    if [[ "$component" == ac ]]; then selector=$LIVE_AC_SELECTOR; else selector=$LIVE_SERVER_SELECTOR; fi
    set_param "/${env}/nhp/${component}/${suffix}image-tag" "$selector"
    set_param "/${env}/nhp/${component}/${color}-protocol-profile" "v1|durable-aop-v1|${LIVE_SOURCE}"
    set_param "/${env}/nhp/${component}/${color}-prepared-slot-attestation" \
      "v2|durable-aop-v1|${provenance#v1|}|${asg}"
  done
}

invoke() {
  PATH="$WORK/bin:$PATH" AWS_REGION=us-east-2 GH_TOKEN=x GITHUB_REPOSITORY=layervai/nhp \
    GITHUB_SHA=$RECOVERY GITHUB_RUN_ID=900 GITHUB_RUN_ATTEMPT=4 \
    CUTOVER_VERIFY_PROVENANCE_SCRIPT=$WORK/helpers/provenance \
    CUTOVER_VERIFY_ASG_HEALTH_SCRIPT=$WORK/helpers/verify-asg \
    CUTOVER_OWNER_PROJECTOR_SCRIPT=$WORK/helpers/owner \
    CUTOVER_SESSION_CONTROL_DELETE_IAM_SCRIPT=$WORK/helpers/delete-iam \
    CUTOVER_SESSION_CONTROL_QUERY_IAM_SCRIPT=$WORK/helpers/query-iam \
    "$SCRIPT" 700 2 "$WORK/durable-aop-nhp-deployment.json"
}

seed
: >"$FAKE_OWNER_ACTIONS"
: >"$FAKE_IAM_ACTIONS"
: >"$FAKE_AWS_ACTIONS"
invoke >/dev/null
[[ "$(cat "$FAKE_OWNER_ACTIONS")" == verify ]]
[[ "$(grep -c '^verify$' "$FAKE_IAM_ACTIONS")" == 1 ]]
[[ "$(grep -c '^query-verify$' "$FAKE_IAM_ACTIONS")" == 1 ]]
[[ "$(grep -c '^active-metadata$' "$FAKE_AWS_ACTIONS")" == 1 ]]
[[ "$(grep -c '^query-metadata$' "$FAKE_AWS_ACTIONS")" == 1 ]]
[[ "$(grep -c $'^active-read\t/sandbox/nhp/cutovers/durable-aop-v1/active-ready-predecessors:10\tParameter.Value$' "$FAKE_AWS_ACTIONS")" == 1 ]]
[[ "$(grep -c $'^active-read\t/sandbox/nhp/cutovers/durable-aop-v1/active-ready-predecessors\tParameter.Version$' "$FAKE_AWS_ACTIONS")" == 2 ]]
[[ "$(grep -c $'^active-read\t/sandbox/nhp/cutovers/durable-aop-v1/active-ready-predecessors\tParameter.Value$' "$FAKE_AWS_ACTIONS")" == 2 ]]
[[ "$(grep -c $'^active-read\t/sandbox/nhp/cutovers/durable-aop-v1/session-control-query-iam:2\tParameter.Value$' "$FAKE_AWS_ACTIONS")" == 1 ]]
[[ "$(grep -c $'^active-read\t/sandbox/nhp/cutovers/durable-aop-v1/session-control-query-iam\tParameter.Version$' "$FAKE_AWS_ACTIONS")" == 2 ]]
[[ "$(grep -c $'^active-read\t/sandbox/nhp/cutovers/durable-aop-v1/session-control-query-iam\tParameter.Value$' "$FAKE_AWS_ACTIONS")" == 2 ]]
jq -e --arg repair "$LIVE_SOURCE" --arg recovery "$RECOVERY" --arg server "$SERVER_DIGEST" --arg ac "$AC_DIGEST" '
  (keys | sort) == ["build","deployments","environment","images","producer","profile","recovery_orchestrator_sha","repair_source_sha","repository","schema"] and
  .schema == "layerv.durable-aop-nhp-deployment.v1" and .repair_source_sha == $repair and
  .recovery_orchestrator_sha == $recovery and .build.run_id == "32682520698" and .build.run_attempt == "1" and
  .producer.run_id == "900" and .producer.run_attempt == "4" and
  .images.server.digest == $server and .images.ac.digest == $ac and $server != $ac and
  .deployments.cell0.active_asg == "layerv-nhp-sandbox-server" and
  .deployments.cell1.active_asg == "layerv-nhp-sandbox-cell1-server-green" and
  .deployments.ac.active_asg == "layerv-nhp-sandbox-ac-green" and
  ([.. | scalars] | all(type == "string"))
' >/dev/null "$WORK/durable-aop-nhp-deployment.json"
[[ $(wc -c <"$WORK/durable-aop-nhp-deployment.json") -le 65536 ]]

# Completed journals retain the exact starting receipt, but its count is an
# incident snapshot rather than a historical constant. Both the minimum and
# store-capacity boundaries remain publishable after a stable zero drain.
for count in 1 1024; do
  export FAKE_FENCE_START_COUNT=$count
  seed
  : >"$FAKE_OWNER_ACTIONS"
  : >"$FAKE_IAM_ACTIONS"
  invoke >/dev/null
done
unset FAKE_FENCE_START_COUNT

# Invalid, noncanonical, blocked, or overflow starting authorities cannot
# authorize a deployment manifest even when their digest is self-consistent.
for authority in zero above_capacity noncanonical admission_blocked overflow; do
  unset FAKE_FENCE_START_COUNT FAKE_FENCE_START_BLOCKED FAKE_FENCE_START_OVERFLOW \
    FAKE_FENCE_START_EVENT FAKE_FENCE_START_PREPARED FAKE_FENCE_START_SELECTED
  case "$authority" in
    zero) export FAKE_FENCE_START_COUNT=0 ;;
    above_capacity) export FAKE_FENCE_START_COUNT=1025 ;;
    noncanonical) export FAKE_FENCE_START_COUNT=01 ;;
    admission_blocked) export FAKE_FENCE_START_BLOCKED=true ;;
    overflow)
      export FAKE_FENCE_START_BLOCKED=true FAKE_FENCE_START_OVERFLOW=1
      export FAKE_FENCE_START_EVENT=11111111111111111111111111111111
      export FAKE_FENCE_START_PREPARED=82 FAKE_FENCE_START_SELECTED=83
      ;;
  esac
  seed
  : >"$FAKE_OWNER_ACTIONS"
  if invoke >/dev/null 2>&1; then
    echo "deployment producer accepted invalid starting fence authority: $authority" >&2
    exit 1
  fi
done
unset FAKE_FENCE_START_COUNT FAKE_FENCE_START_BLOCKED FAKE_FENCE_START_OVERFLOW \
  FAKE_FENCE_START_EVENT FAKE_FENCE_START_PREPARED FAKE_FENCE_START_SELECTED

for mode in recovery_failure recovery_timed_out recovery_cancelled build_drift refresh_failed asg_unhealthy \
  equal_digest floor_present slot_drift owner_missing owner_preparing owner_client_drift owner_source_drift \
  owner_digest_drift owner_live_verify_failed \
  server_orchestrator_missing server_orchestrator_drift server_predecessor_nonlive \
  iam_missing iam_preparing iam_policy_drift iam_role_drift iam_table_drift iam_action_drift iam_enclosing_operation_drift \
  iam_leading_key_drift iam_default_drift iam_version_drift iam_digest_drift iam_live_verify_failed \
  query_ref_missing query_ref_parameter query_ref_version query_ref_digest query_status query_intent_drift \
  query_receipt_drift query_live_verify_failed query_metadata_type query_metadata_key query_metadata_tier \
  query_metadata_data query_metadata_version query_metadata_missing query_metadata_extra query_torn \
  journal_missing journal_status journal_source journal_build journal_manifest journal_source_digest \
  incident_plan_digest incident_fence_digest incident_receipt fence_start_malformed fence_drain_count fence_drain_digest \
  component_intent predecessor_plan_digest predecessor_receipt active_ref_missing active_ref_parameter \
  active_ref_version active_ref_digest active_status active_plan_digest active_fence_digest active_owner_digest \
  active_latch_receipt active_quiescence_receipt active_retirement_receipt active_target_order active_extra \
  active_oversize active_metadata_type active_metadata_key active_metadata_tier active_metadata_data \
  active_metadata_version active_metadata_missing active_metadata_extra state_torn main_torn active_torn \
  state_validated historical_state_mutated embedded_lock_mutated ledger_state_digest_mutated \
  ledger_lock_digest_mutated; do
  seed
  : >"$FAKE_OWNER_ACTIONS"
  : >"$FAKE_IAM_ACTIONS"
  unset FAKE_RECOVERY_CONCLUSION FAKE_BUILD_DRIFT FAKE_REFRESH_FAILED FAKE_ASG_UNHEALTHY \
    FAKE_OWNER_VERIFY_FAIL FAKE_IAM_VERIFY_FAIL FAKE_QUERY_IAM_VERIFY_FAIL FAKE_ACTIVE_METADATA_MODE \
    FAKE_QUERY_METADATA_MODE FAKE_DRIFT_PARAM
  export AC_DIGEST=sha256:773bd37e915ac767f57e7656b5c038a8f2c70348901b1e81572584d6cfad566e
  case "$mode" in
    recovery_failure) export FAKE_RECOVERY_CONCLUSION=failure ;;
    recovery_timed_out) export FAKE_RECOVERY_CONCLUSION=timed_out ;;
    recovery_cancelled) export FAKE_RECOVERY_CONCLUSION=cancelled ;;
    build_drift) export FAKE_BUILD_DRIFT=true ;;
    refresh_failed) export FAKE_REFRESH_FAILED=true ;;
    asg_unhealthy) export FAKE_ASG_UNHEALTHY=true ;;
    equal_digest) export AC_DIGEST=$SERVER_DIGEST ;;
    floor_present) set_param /sandbox/nhp/minimum-protocol-profile durable-aop-v1 ;;
    slot_drift) set_param /sandbox/nhp/server/image-tag "${LIVE_SOURCE}@sha256:$(printf '9%.0s' {1..64})" ;;
    state_validated)
      value=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
      set_param /sandbox/nhp/cutovers/durable-aop-v1/state "$(jq -c '.phase="validated"' <<<"$value")"
      ;;
    owner_missing)
      value=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
      set_param /sandbox/nhp/cutovers/durable-aop-v1/state "$(jq -c 'del(.repair.owner)' <<<"$value")"
      ;;
    owner_preparing)
      value=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
      set_param /sandbox/nhp/cutovers/durable-aop-v1/state "$(jq -c '.repair.owner.status="preparing"' <<<"$value")"
      ;;
    owner_client_drift)
      value=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
      set_param /sandbox/nhp/cutovers/durable-aop-v1/state "$(jq -c '.repair.owner.intent.client_id="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"' <<<"$value")"
      ;;
    owner_source_drift)
      value=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
      set_param /sandbox/nhp/cutovers/durable-aop-v1/state "$(jq -c '.repair.owner.intent.source_sha=("9"*40)' <<<"$value")"
      ;;
    owner_digest_drift)
      value=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
      set_param /sandbox/nhp/cutovers/durable-aop-v1/state "$(jq -c '.repair.owner.intent.expected_row_sha256=("9"*64)' <<<"$value")"
      ;;
    owner_live_verify_failed)
      export FAKE_OWNER_VERIFY_FAIL=true
      ;;
    server_orchestrator_missing)
      mutate_fixture_journal 'del(.runtime.server_refresh_orchestrator_sha)'
      ;;
    server_orchestrator_drift)
      mutate_fixture_journal '.runtime.server_refresh_orchestrator_sha=("9"*40)'
      ;;
    server_predecessor_nonlive)
      mutate_fixture_journal '.runtime.server_refresh_orchestrator_sha="e668a60b81f14b55278c83d0c79e4f760adeac29"'
      ;;
    iam_missing)
      mutate_fixture_journal 'del(.runtime.session_control_delete_iam)'
      ;;
    iam_preparing)
      mutate_fixture_journal '.runtime.session_control_delete_iam={status:"preparing",intent:.runtime.session_control_delete_iam.intent,receipt:null}'
      ;;
    iam_policy_drift)
      mutate_fixture_journal '.runtime.session_control_delete_iam.intent.policy_id="OTHER"'
      ;;
    iam_role_drift)
      mutate_fixture_journal '.runtime.session_control_delete_iam.intent.attached_role="other-role"'
      ;;
    iam_table_drift)
      mutate_fixture_journal '.runtime.session_control_delete_iam.intent.table_arn="arn:aws:dynamodb:us-east-2:767397897469:table/other"'
      ;;
    iam_action_drift)
      mutate_fixture_journal '.runtime.session_control_delete_iam.intent.action="dynamodb:PutItem"'
      ;;
    iam_enclosing_operation_drift)
      mutate_fixture_journal '.runtime.session_control_delete_iam.intent.enclosing_operation="DeleteItem"'
      ;;
    iam_leading_key_drift)
      mutate_fixture_journal '.runtime.session_control_delete_iam.intent.leading_keys=["EVENT#*"]'
      ;;
    iam_default_drift)
      mutate_fixture_journal '.runtime.session_control_delete_iam.receipt.default_version="v10"'
      ;;
    iam_version_drift)
      mutate_fixture_journal '.runtime.session_control_delete_iam.receipt.versions=["v6","v7","v8","v9","v10"]'
      ;;
    iam_digest_drift)
      mutate_fixture_journal '.runtime.session_control_delete_iam.receipt.policy_sha256=("9"*64)'
      ;;
    iam_live_verify_failed)
      export FAKE_IAM_VERIFY_FAIL=true
      ;;
    query_ref_missing) mutate_fixture_journal 'del(.runtime.session_control_query_iam_ref)' ;;
    query_ref_parameter) mutate_fixture_journal '.runtime.session_control_query_iam_ref.parameter="/sandbox/nhp/cutovers/durable-aop-v1/other"' ;;
    query_ref_version) mutate_fixture_journal '.runtime.session_control_query_iam_ref.version=1' ;;
    query_ref_digest) mutate_fixture_journal '.runtime.session_control_query_iam_ref.sha256=("9"*64)' ;;
    query_status) mutate_query_iam_journal '.status="preparing" | .receipt=null' ;;
    query_intent_drift) mutate_query_iam_journal '.intent.leading_keys=["TARGET#other"]' ;;
    query_receipt_drift) mutate_query_iam_journal '.receipt.default_version="v23"' ;;
    query_live_verify_failed) export FAKE_QUERY_IAM_VERIFY_FAIL=true ;;
    query_metadata_type) export FAKE_QUERY_METADATA_MODE=wrong_type ;;
    query_metadata_key) export FAKE_QUERY_METADATA_MODE=wrong_key ;;
    query_metadata_tier) export FAKE_QUERY_METADATA_MODE=wrong_tier ;;
    query_metadata_data) export FAKE_QUERY_METADATA_MODE=wrong_data_type ;;
    query_metadata_version) export FAKE_QUERY_METADATA_MODE=wrong_version ;;
    query_metadata_missing) export FAKE_QUERY_METADATA_MODE=missing ;;
    query_metadata_extra) export FAKE_QUERY_METADATA_MODE=extra ;;
    query_torn) export FAKE_DRIFT_PARAM=/sandbox/nhp/cutovers/durable-aop-v1/session-control-query-iam ;;
    journal_missing)
      value=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
      set_param /sandbox/nhp/cutovers/durable-aop-v1/state "$(jq -c 'del(.repair.stale_target_retirement_ref)' <<<"$value")"
      ;;
    journal_status)
      mutate_fixture_journal '.status="predecessor_retiring"'
      ;;
    journal_source)
      mutate_fixture_journal '.runtime.source_sha=("9"*40)'
      ;;
    journal_build)
      mutate_fixture_journal '.runtime.build_run_id="801"'
      ;;
    journal_manifest)
      mutate_fixture_journal '.runtime.runtime_manifest=("9"*64)'
      ;;
    journal_source_digest)
      mutate_fixture_journal '.source_state_sha256=("9"*64)'
      ;;
    incident_plan_digest)
      mutate_fixture_journal '.incident_plan_sha256=("9"*64)'
      ;;
    incident_fence_digest)
      mutate_fixture_journal '.incident_plan.targets[0].fence_sha256=("9"*64)'
      ;;
    incident_receipt)
      mutate_fixture_journal '.incident_targets[0].receipt.version="999"'
      ;;
    fence_start_malformed)
      mutate_fixture_journal '.runtime.fence_start.active_fence_count={}'
      ;;
    fence_drain_count)
      mutate_fixture_journal '.runtime.fence_drain.active_fence_count="1"'
      ;;
    fence_drain_digest)
      mutate_fixture_journal '.runtime.fence_drain.directory_sha256=("9"*64)'
      ;;
    component_intent)
      mutate_fixture_journal '.runtime.ac.intent_sha256=("9"*64)'
      ;;
    predecessor_plan_digest)
      mutate_fixture_journal '.runtime.predecessor_plan_sha256=("9"*64)'
      ;;
    predecessor_receipt)
      mutate_fixture_journal '.runtime.predecessor_targets[0].receipt.authority_version="99"'
      ;;
    active_ref_missing)
      mutate_fixture_journal 'del(.runtime.ready_predecessor_ref)'
      ;;
    active_ref_parameter)
      mutate_fixture_journal '.runtime.ready_predecessor_ref.parameter="/sandbox/nhp/cutovers/durable-aop-v1/other"'
      ;;
    active_ref_version)
      mutate_fixture_journal '.runtime.ready_predecessor_ref.version += 1'
      ;;
    active_ref_digest)
      mutate_fixture_journal '.runtime.ready_predecessor_ref.sha256=("9"*64)'
      ;;
    active_status)
      mutate_active_ready_journal '.status="retiring"'
      ;;
    active_plan_digest)
      mutate_active_ready_journal '.plan_sha256=("9"*64)'
      ;;
    active_fence_digest)
      mutate_active_ready_journal '.plan.targets[0].fence_sha256=("9"*64)'
      ;;
    active_owner_digest)
      mutate_active_ready_journal '.plan.targets[0].owner_sha256=("9"*64)'
      ;;
    active_latch_receipt)
      mutate_active_ready_journal '.targets[0].latch_receipt.owner_sha256=("9"*64)'
      ;;
    active_quiescence_receipt)
      mutate_active_ready_journal '.targets[1].quiescence_receipt.target_session_count="1"'
      ;;
    active_retirement_receipt)
      mutate_active_ready_journal '.targets[2].receipt.authority_version="99"'
      ;;
    active_target_order)
      mutate_active_ready_journal '.targets |= reverse'
      ;;
    active_extra)
      mutate_active_ready_journal '.unexpected=true'
      ;;
    active_oversize)
      payload=$(printf 'A%.0s' {1..4100})
      install_active_ready_envelope "$(jq -cS -n --arg payload "$payload" \
        '{encoding:"gzip-base64",payload:$payload,schema:"layerv.durable-aop-active-ready-predecessor-journal-envelope.v1"}')"
      ;;
    active_metadata_type) export FAKE_ACTIVE_METADATA_MODE=wrong_type ;;
    active_metadata_key) export FAKE_ACTIVE_METADATA_MODE=wrong_key ;;
    active_metadata_tier) export FAKE_ACTIVE_METADATA_MODE=wrong_tier ;;
    active_metadata_data) export FAKE_ACTIVE_METADATA_MODE=wrong_data_type ;;
    active_metadata_version) export FAKE_ACTIVE_METADATA_MODE=wrong_version ;;
    active_metadata_missing) export FAKE_ACTIVE_METADATA_MODE=missing ;;
    active_metadata_extra) export FAKE_ACTIVE_METADATA_MODE=extra ;;
    state_torn) export FAKE_DRIFT_PARAM=/sandbox/nhp/cutovers/durable-aop-v1/state ;;
    main_torn) export FAKE_DRIFT_PARAM=/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement ;;
    active_torn) export FAKE_DRIFT_PARAM=/sandbox/nhp/cutovers/durable-aop-v1/active-ready-predecessors ;;
    historical_state_mutated)
      value=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state:7" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
      set_param /sandbox/nhp/cutovers/durable-aop-v1/state:7 "$(jq -c '.cell0.new_asg="mutated"' <<<"$value")"
      ;;
    embedded_lock_mutated)
      value=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
      set_param /sandbox/nhp/cutovers/durable-aop-v1/state "$(jq -c '.original.lock.created_at += 1' <<<"$value")"
      ;;
    ledger_state_digest_mutated)
      value=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
      set_param /sandbox/nhp/cutovers/durable-aop-v1/state "$(jq -c '.original.state_sha256=("9"*64)' <<<"$value")"
      ;;
    ledger_lock_digest_mutated)
      value=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
      set_param /sandbox/nhp/cutovers/durable-aop-v1/state "$(jq -c '.original.lock_sha256=("9"*64)' <<<"$value")"
      ;;
  esac
  if invoke >/dev/null 2>&1; then echo "deployment producer accepted $mode authority" >&2; exit 1; fi
done

echo "emit-durable-aop-nhp-deployment-manifest: strict authority tests passed"
