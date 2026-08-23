#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT=$ROOT/.github/scripts/emit-durable-aop-nhp-deployment-manifest.sh
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/helpers"
export FAKE_PARAMS=$WORK/params
REPAIR=422b1d9acac53d50fe5602158fb02c8120ef108d
RECOVERY=abcdefabcdefabcdefabcdefabcdefabcdefabcd
SERVER_DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
AC_DIGEST=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
RUNTIME=2895963905453d61874858171529968efe8e18e5450d41842854fd2784d1ec78
ORIGINAL=e9b11398a4cea98da6ae5b41cfe635562e1b7c72
ORIGINAL_OWNER="nhp:32635672597:durable-aop-cutover:${ORIGINAL}"
ORIGINAL_STATE_DIGEST=e7ed20adde2ce9e143c9505027a73e415e5dd3d4a9d0c950c912d6398cc5d13e
ORIGINAL_LOCK_DIGEST=6c7224d78837a4d56547409439d9bce30efa9b214367c4f19fd13cc3fe3b2ebd
export REPAIR RECOVERY SERVER_DIGEST AC_DIGEST
export FAKE_OWNER_ACTIONS=$WORK/owner-actions

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
    awk -F '\t' -v name="$name" '$1 == name {print substr($0,index($0,"\t")+1); found=1} END {exit !found}' "$FAKE_PARAMS" || {
      echo ParameterNotFound >&2; exit 254;
    }
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
elif [[ "$args" == *'/actions/runs/800/attempts/3/jobs'* ]]; then
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
elif [[ "$args" == *'/actions/runs/800/attempts/3'* ]]; then
  sha=$REPAIR; [[ "${FAKE_BUILD_DRIFT:-}" != true ]] || sha=9999999999999999999999999999999999999999
  jq -cn --arg sha "$sha" \
    '{id:800,repository:{full_name:"layervai/nhp"},head_repository:{full_name:"layervai/nhp"},head_sha:$sha,head_branch:"main",event:"workflow_dispatch",run_attempt:3,status:"completed",conclusion:"success",path:".github/workflows/build-and-push.yml"}'
else
  echo "unexpected gh $args" >&2
  exit 99
fi
EOF

cat >"$WORK/helpers/provenance" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == layerv/nhp-server ]]; then digest=$SERVER_DIGEST; else digest=$AC_DIGEST; fi
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
chmod +x "$WORK/bin/"* "$WORK/helpers/"*

seed() {
  : >"$FAKE_PARAMS"
  local server_provenance="v1|${REPAIR}|layerv/nhp-server|${SERVER_DIGEST}"
  local ac_provenance="v1|${REPAIR}|layerv/nhp-ac|${AC_DIGEST}"
  local lock original_state state
  original_state=$(jq -cn --arg image "$ORIGINAL" --arg owner "$ORIGINAL_OWNER" '
    {schema:2,image:$image,orchestrator_sha:$image,lock_owner:$owner,phase:"old_servers_terminated",
     ac:{old_color:"blue",new_color:"green",old_asg:"layerv-nhp-sandbox-ac",new_asg:"layerv-nhp-sandbox-ac-green",old_min:3,old_max:3,old_desired:3,new_attestation:("v2|durable-aop-v1|"+$image+"|layerv/nhp-ac|sha256:2e38672ef7680c60521694c3f2a59e9a74ed8f2d56bfe1fb41a97f3040b4e279|layerv-nhp-sandbox-ac-green")},
     cell0:{old_color:"green",new_color:"blue",old_asg:"layerv-nhp-sandbox-server-green",new_asg:"layerv-nhp-sandbox-server",new_attestation:("v2|durable-aop-v1|"+$image+"|layerv/nhp-server|sha256:94a5d91373ca261e4edfffc2ca743768b7da573bacd9dadac87c2dd7d0cbc1f4|layerv-nhp-sandbox-server")},
     cell1:{old_color:"blue",new_color:"green",old_asg:"layerv-nhp-sandbox-cell1-server",new_asg:"layerv-nhp-sandbox-cell1-server-green",new_attestation:("v2|durable-aop-v1|"+$image+"|layerv/nhp-server|sha256:94a5d91373ca261e4edfffc2ca743768b7da573bacd9dadac87c2dd7d0cbc1f4|layerv-nhp-sandbox-cell1-server-green")}}')
  lock=$(jq -cn --arg owner "$ORIGINAL_OWNER" --arg image "$ORIGINAL" \
    '{schema:1,kind:"durable-aop-cutover-recovery",owner:$owner,image:$image,orchestrator_sha:$image,created_at:1787485146,expires_at:253402300799}')
  [[ "$(printf '%s' "$(jq -cS . <<<"$original_state")" | sha256sum | awk '{print $1}')" == "$ORIGINAL_STATE_DIGEST" ]]
  [[ "$(printf '%s' "$(jq -cS . <<<"$lock")" | sha256sum | awk '{print $1}')" == "$ORIGINAL_LOCK_DIGEST" ]]
  state=$(jq -cn --arg repair "$REPAIR" --arg recovery "$RECOVERY" --arg runtime "$RUNTIME" \
    --arg server "$server_provenance" --arg ac "$ac_provenance" \
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
        expected_row_sha256:("d"*64)}}}}')
  set_param /sandbox/nhp/cutovers/durable-aop-v1/state "$state"
  set_param /layerv-nhp-sandbox/qurl-live-env-lock "$lock"
  set_param /sandbox/nhp/cutovers/durable-aop-v1/state:7 "$original_state"
  set_param /layerv-nhp-sandbox/qurl-live-env-lock:2 "$lock"
  for spec in \
    'sandbox server blue layerv-nhp-sandbox-server' \
    'sandbox-cell1 server green layerv-nhp-sandbox-cell1-server-green' \
    'sandbox ac green layerv-nhp-sandbox-ac-green'; do
    read -r env component color asg <<<"$spec"
    if [[ "$component" == ac ]]; then provenance=$ac_provenance; else provenance=$server_provenance; fi
    set_param "/${env}/nhp/${component}/active-color" "$color"
    suffix=; [[ "$color" == green ]] && suffix=green-
    set_param "/${env}/nhp/${component}/${suffix}asg-name" "$asg"
    set_param "/${env}/nhp/${component}/${suffix}image-tag" "$REPAIR"
    set_param "/${env}/nhp/${component}/${color}-protocol-profile" "v1|durable-aop-v1|${REPAIR}"
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
    "$SCRIPT" 700 2 "$WORK/durable-aop-nhp-deployment.json"
}

seed
: >"$FAKE_OWNER_ACTIONS"
invoke >/dev/null
[[ "$(cat "$FAKE_OWNER_ACTIONS")" == verify ]]
jq -e --arg repair "$REPAIR" --arg recovery "$RECOVERY" --arg server "$SERVER_DIGEST" --arg ac "$AC_DIGEST" '
  (keys | sort) == ["build","deployments","environment","images","producer","profile","recovery_orchestrator_sha","repair_source_sha","repository","schema"] and
  .schema == "layerv.durable-aop-nhp-deployment.v1" and .repair_source_sha == $repair and
  .recovery_orchestrator_sha == $recovery and .build.run_id == "800" and .build.run_attempt == "3" and
  .producer.run_id == "900" and .producer.run_attempt == "4" and
  .images.server.digest == $server and .images.ac.digest == $ac and $server != $ac and
  .deployments.cell0.active_asg == "layerv-nhp-sandbox-server" and
  .deployments.cell1.active_asg == "layerv-nhp-sandbox-cell1-server-green" and
  .deployments.ac.active_asg == "layerv-nhp-sandbox-ac-green" and
  ([.. | scalars] | all(type == "string"))
' >/dev/null "$WORK/durable-aop-nhp-deployment.json"
[[ $(wc -c <"$WORK/durable-aop-nhp-deployment.json") -le 65536 ]]

for mode in recovery_failure recovery_timed_out recovery_cancelled build_drift refresh_failed asg_unhealthy \
  equal_digest floor_present slot_drift owner_missing owner_preparing owner_client_drift owner_source_drift \
  owner_digest_drift owner_live_verify_failed \
  state_validated historical_state_mutated embedded_lock_mutated ledger_state_digest_mutated \
  ledger_lock_digest_mutated; do
  seed
  : >"$FAKE_OWNER_ACTIONS"
  unset FAKE_RECOVERY_CONCLUSION FAKE_BUILD_DRIFT FAKE_REFRESH_FAILED FAKE_ASG_UNHEALTHY \
    FAKE_OWNER_VERIFY_FAIL
  export AC_DIGEST=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  case "$mode" in
    recovery_failure) export FAKE_RECOVERY_CONCLUSION=failure ;;
    recovery_timed_out) export FAKE_RECOVERY_CONCLUSION=timed_out ;;
    recovery_cancelled) export FAKE_RECOVERY_CONCLUSION=cancelled ;;
    build_drift) export FAKE_BUILD_DRIFT=true ;;
    refresh_failed) export FAKE_REFRESH_FAILED=true ;;
    asg_unhealthy) export FAKE_ASG_UNHEALTHY=true ;;
    equal_digest) export AC_DIGEST=$SERVER_DIGEST ;;
    floor_present) set_param /sandbox/nhp/minimum-protocol-profile durable-aop-v1 ;;
    slot_drift) set_param /sandbox/nhp/server/image-tag 9999999999999999999999999999999999999999 ;;
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
