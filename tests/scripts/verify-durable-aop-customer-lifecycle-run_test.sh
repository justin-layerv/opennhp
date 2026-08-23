#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT_SOURCE=$ROOT/.github/scripts/verify-durable-aop-customer-lifecycle-run.sh
INFRA=cccccccccccccccccccccccccccccccccccccccc
INTEGRATIONS=dddddddddddddddddddddddddddddddddddddddd
REPAIR=0000000000000000000000000000000000000000
RECOVERY=2222222222222222222222222222222222222222
SERVER_DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
AC_DIGEST=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/customer" "$WORK/bad-customer" "$WORK/bad-journey" "$WORK/bad-auth" \
  "$WORK/bad-integration" "$WORK/repo/.github/scripts"
SCRIPT=$WORK/repo/.github/scripts/verify-durable-aop-customer-lifecycle-run.sh
sed -e "s/^APPROVED_INFRA_SHA=.*/APPROVED_INFRA_SHA=$INFRA/" \
  -e "s/^APPROVED_INTEGRATIONS_SHA=.*/APPROVED_INTEGRATIONS_SHA=$INTEGRATIONS/" \
  "$SCRIPT_SOURCE" >"$SCRIPT"
cp "$ROOT/.github/scripts/verify-durable-aop-build-only-run.sh" "$WORK/repo/.github/scripts/"
chmod +x "$SCRIPT"

printf '\tdep\tgithub.com/layervai/qurl-go\tv0.8.0\th1:Tw8291djSj3LT+aGWPW7PPuIEBeAKcIG3h2CddxFlzk=\n\tbuild\tvcs.revision=%s\n\tbuild\tvcs.modified=false\n' \
  "$INTEGRATIONS" >"$WORK/customer/qurl.modules.txt"
cp "$WORK/customer/qurl.modules.txt" "$WORK/customer/test.modules.txt"
jq -S -n --arg integrations "$INTEGRATIONS" '
  {schema:"layerv.qurl-sharing-canary.v2",integrations_sha:$integrations,
   source_kind:"pull_request",pull_request_number:1247,source_profile:"cli_only",
   qurl_go:{path:"github.com/layervai/qurl-go",version:"v0.8.0",
     sum:"h1:Tw8291djSj3LT+aGWPW7PPuIEBeAKcIG3h2CddxFlzk=",
     go_mod_sum:"h1:zujbZnolKJzJEDyKwgUqulhHSi0sZeU2w1x+nle/yeM="},qurl_connector:null,
   connector_attended_gate:{required:true,satisfied_by_this_run:false,
     repository:"layervai/qurl-connector",pull_request:609,
     workflow:".github/workflows/sandbox-smoke.yml",job:"Attended Connector UDP proof (strict)"}}
' >"$WORK/customer/selection.json"

jq -cS -n --arg repair "$REPAIR" --arg recovery "$RECOVERY" \
  --arg server "$SERVER_DIGEST" --arg ac "$AC_DIGEST" '
  {schema:"layerv.durable-aop-nhp-deployment.v1",repository:"layervai/nhp",
   environment:"sandbox",profile:"durable-aop-v1",repair_source_sha:$repair,
   recovery_orchestrator_sha:$recovery,
   build:{workflow:".github/workflows/build-and-push.yml",run_id:"55",run_attempt:"4",head_sha:$repair},
   producer:{workflow:".github/workflows/udp-proof-deployment-manifest.yml",source_sha:$recovery,
     run_id:"66",run_attempt:"3",head_sha:$recovery},
   images:{server:{repository:"layerv/nhp-server",digest:$server},ac:{repository:"layerv/nhp-ac",digest:$ac}},
   deployments:{
     cell0:{environment:"sandbox",component:"server",active_color:"green",active_asg:"layerv-nhp-sandbox-server-green",image_digest:$server},
     cell1:{environment:"sandbox-cell1",component:"server",active_color:"blue",active_asg:"layerv-nhp-sandbox-cell1-server",image_digest:$server},
     ac:{environment:"sandbox",component:"ac",active_color:"green",active_asg:"layerv-nhp-sandbox-ac-green",image_digest:$ac}}}
' >"$WORK/deployment.json"
python3 - "$WORK/deployment.json" "$WORK/nhp.zip" <<'PY'
import pathlib, sys, zipfile
with zipfile.ZipFile(sys.argv[2], "w", zipfile.ZIP_DEFLATED) as z:
    z.write(sys.argv[1], "durable-aop-nhp-deployment.json")
PY
NHP_DIGEST=sha256:$(sha256sum "$WORK/nhp.zip" | awk '{print $1}')

jq -S -n --slurpfile deployment "$WORK/deployment.json" --arg digest "$NHP_DIGEST" '
  {schema:"layerv.durable-aop-nhp-authority.v1",deployment:$deployment[0],
   artifact:{repository:"layervai/nhp",name:("durable-aop-nhp-deployment-"+$deployment[0].repair_source_sha),id:"99",digest:$digest}}
' >"$WORK/customer/nhp-deployment-authority.json"
AUTHORITY_SHA=$(sha256sum "$WORK/customer/nhp-deployment-authority.json" | awk '{print $1}')
QURL_MODULES_SHA=$(sha256sum "$WORK/customer/qurl.modules.txt" | awk '{print $1}')
TEST_MODULES_SHA=$(sha256sum "$WORK/customer/test.modules.txt" | awk '{print $1}')
SELECTION_SHA=$(sha256sum "$WORK/customer/selection.json" | awk '{print $1}')
QURL_SHA=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
TEST_SHA=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
printf '%s  qurl\n%s  qurl-sharing-sandbox.test\n%s  qurl.modules.txt\n%s  test.modules.txt\n%s  selection.json\n' \
  "$QURL_SHA" "$TEST_SHA" "$QURL_MODULES_SHA" "$TEST_MODULES_SHA" "$SELECTION_SHA" \
  >"$WORK/customer/verified-subjects.sha256"

jq -S -n --arg infra "$INFRA" --arg integrations "$INTEGRATIONS" \
  --arg qurl_sha "$QURL_SHA" --arg test_sha "$TEST_SHA" \
  --arg qurl_modules "$QURL_MODULES_SHA" --arg test_modules "$TEST_MODULES_SHA" \
  --arg authority_sha "$AUTHORITY_SHA" --slurpfile authority "$WORK/customer/nhp-deployment-authority.json" '
  {schema:"layerv.durable-aop-lifecycle-receipt.v4",
   orchestrator:{repository:"layervai/qurl-integrations-infra",workflow:".github/workflows/qurl-sharing-sandbox.yml",sha:$infra,run_id:77,run_attempt:2},
   source:{repository:"layervai/qurl-integrations",sha:$integrations,kind:"pull_request",pull_request_number:1247,profile:"cli_only"},
   modules:{qurl_go:{path:"github.com/layervai/qurl-go",version:"v0.8.0",sum:"h1:Tw8291djSj3LT+aGWPW7PPuIEBeAKcIG3h2CddxFlzk=",go_mod_sum:"h1:zujbZnolKJzJEDyKwgUqulhHSi0sZeU2w1x+nle/yeM="},qurl_connector:null},
   nhp_deployment:{authority_sha256:$authority_sha,authority:$authority[0]},
   subjects:{
     qurl:{sha256:$qurl_sha,modules_sha256:$qurl_modules,build_attestation:{verified:true,repository:"layervai/qurl-integrations-infra",workflow:".github/workflows/qurl-sharing-sandbox.yml",source_ref:"refs/heads/main",source_sha:$infra}},
     test_harness:{sha256:$test_sha,modules_sha256:$test_modules,build_attestation:{verified:true,repository:"layervai/qurl-integrations-infra",workflow:".github/workflows/qurl-sharing-sandbox.yml",source_ref:"refs/heads/main",source_sha:$infra}}},
   customer_auth:{mode:"auth0_public_api_key",auth0_jwt:"passed",
     public_api_key_create:"passed",key_authenticated_lifecycle:"passed",
     public_api_key_revoke:"passed",post_cache_horizon_rejection:"passed",
     sandbox_credential_endpoint:false,sandbox_credential_selector:null,
     operations:{create:{method:"POST",path:"/v1/api-keys",status:201,auth:"auth0_jwt"},
       identity:{method:"GET",path:"/v1/me",status:200,auth:"api_key"},
       revoke:{method:"DELETE",path:"/v1/api-keys/{key_id}",status:204,auth:"auth0_jwt"},
       rejection:{method:"GET",path:"/v1/me",status:401,auth:"revoked_api_key",after_cache_horizon:true}}},
   live_customer_steps:{
     sequential_lifecycle:{name:"TestSandboxLocalPublishLifecycleSmoke",runtimes:["hardened_container","host"],result:"passed",two_distinct_registered_sessions:"passed",exact_retire_each_session:"passed",replacement_admission:"passed",durable_identity_continuity:"passed"},
     sibling_continuity:{name:"TestSandboxLocalPublishSiblingContinuity",runtimes:["hardened_container","host"],result:"passed",two_real_processes:"passed",get_a_and_b_before_retire:"passed",retire_a:"passed",get_b_while_a_retired:"passed",restart_a_same_state_resource:"passed",get_a_and_b_after_restart:"passed",exact_retire_cleanup:"passed"},
     crid_lifecycle:{name:"TestSandboxCRIDJourney",runtime:"host",result:"passed",create_list_resolve_get_delete:"passed",idempotent_resource_delete:"passed"}},
   integration_tests:{
     nhp:{repository:"layervai/nhp",source_sha:$authority[0].deployment.repair_source_sha,workflow:".github/workflows/build-and-push.yml",run_id:55,run_attempt:4,event:"workflow_dispatch",job:"Test",step:"Run tests (privileged container for iptables)",result:"passed",tests:["TestE2E_RelayCrossServer_KnockForwardedToRemoteAC_AckReturnsViaRelay","TestExactSessionFleetCompensationClosesRemoteForwardedSessionOnly","TestHandleKnockRequestSendFailureCompensatesRemoteAdmissions","TestHandleRelayForward_ExactSessionRetirementReturnsDurableReceipt","TestSessionControlLifecycleRecoveryResumesAfterCompleteAndClearsClosingDueAuthority","TestSessionControlRecoveryClosesReservedCrashGapAfterAckEnqueue"]},
     qurl_go:{repository:"layervai/qurl-go",source_sha:"d02c25995df085f0437c7a572714c26e907a8a59",workflow:".github/workflows/ci.yml",run_id:32621063743,run_attempt:1,event:"push",job:"vet + test -race",step:"go test -race + coverage",result:"passed",tests:["TestConnectAgentRuntime_LostRAKRestartExactReplayAfterTicketExpiry","TestConnectAgentRuntime_ResumesPersistedCandidateAfterLostCompletionReply","TestConsumeNativeExactSessionCloseReply_StrictAuthority","TestRetireRegisteredAgentSession_ClassifiesReceiptAndTransportFailures","TestRetireRegisteredAgentSession_UsesExactReceiptOriginalEndpointAndRetriesIdempotently"]},
     qurl_integrations:{repository:"layervai/qurl-integrations",source_sha:$integrations,workflow:".github/workflows/cli.yml",run_id:32658570640,run_attempt:1,event:"pull_request",job:"cli / test",step:"Run tests with coverage",result:"passed",tests:["TestNativeBlocksNewCycleAdmissionUntilPriorReceiptRetires","TestNativeEndCycleRetriesExactReceiptUntilAccepted","TestNativeLostKnockReplyDoesNotFabricateRetirement","TestNativeLostReplyConsumesAttemptWithoutFabricatingReceipt","TestNativeRetirementFailureBlocksReplacementAdmission","TestNativeUsesMonotonicAttemptsAndRetiresEveryReceipt"]}},
   connector_attended_gate:{required:true,satisfied_by_this_run:false,repository:"layervai/qurl-connector",pull_request:609,workflow:".github/workflows/sandbox-smoke.yml",job:"Attended Connector UDP proof (strict)"}}
' >"$WORK/customer/durable-aop-lifecycle-receipt.json"

python3 - "$WORK/customer" "$WORK/customer.zip" <<'PY'
import pathlib, sys, zipfile
root = pathlib.Path(sys.argv[1])
with zipfile.ZipFile(sys.argv[2], "w", zipfile.ZIP_DEFLATED) as z:
    for path in sorted(root.iterdir()): z.write(path, path.name)
PY
CUSTOMER_DIGEST=sha256:$(sha256sum "$WORK/customer.zip" | awk '{print $1}')

cp -R "$WORK/customer/." "$WORK/bad-customer/"
jq '.nhp_deployment.authority.deployment.images.server.digest="sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"' \
  "$WORK/bad-customer/durable-aop-lifecycle-receipt.json" >"$WORK/bad-receipt"
mv "$WORK/bad-receipt" "$WORK/bad-customer/durable-aop-lifecycle-receipt.json"
python3 - "$WORK/bad-customer" "$WORK/bad-customer.zip" <<'PY'
import pathlib, sys, zipfile
root = pathlib.Path(sys.argv[1])
with zipfile.ZipFile(sys.argv[2], "w", zipfile.ZIP_DEFLATED) as z:
    for path in sorted(root.iterdir()): z.write(path, path.name)
PY
BAD_CUSTOMER_DIGEST=sha256:$(sha256sum "$WORK/bad-customer.zip" | awk '{print $1}')

cp -R "$WORK/customer/." "$WORK/bad-journey/"
jq '.live_customer_steps.sibling_continuity.get_b_while_a_retired="failed"' \
  "$WORK/bad-journey/durable-aop-lifecycle-receipt.json" >"$WORK/bad-receipt"
mv "$WORK/bad-receipt" "$WORK/bad-journey/durable-aop-lifecycle-receipt.json"
python3 - "$WORK/bad-journey" "$WORK/bad-journey.zip" <<'PY'
import pathlib, sys, zipfile
root = pathlib.Path(sys.argv[1])
with zipfile.ZipFile(sys.argv[2], "w", zipfile.ZIP_DEFLATED) as z:
    for path in sorted(root.iterdir()): z.write(path, path.name)
PY
BAD_JOURNEY_DIGEST=sha256:$(sha256sum "$WORK/bad-journey.zip" | awk '{print $1}')

cp -R "$WORK/customer/." "$WORK/bad-auth/"
jq '.customer_auth.sandbox_credential_selector="/internal/v1/sandbox-sharing"' \
  "$WORK/bad-auth/durable-aop-lifecycle-receipt.json" >"$WORK/bad-receipt"
mv "$WORK/bad-receipt" "$WORK/bad-auth/durable-aop-lifecycle-receipt.json"
python3 - "$WORK/bad-auth" "$WORK/bad-auth.zip" <<'PY'
import pathlib, sys, zipfile
root = pathlib.Path(sys.argv[1])
with zipfile.ZipFile(sys.argv[2], "w", zipfile.ZIP_DEFLATED) as z:
    for path in sorted(root.iterdir()): z.write(path, path.name)
PY
BAD_AUTH_DIGEST=sha256:$(sha256sum "$WORK/bad-auth.zip" | awk '{print $1}')

cp -R "$WORK/customer/." "$WORK/bad-integration/"
jq '.integration_tests.nhp.tests[0]="TestNotExecuted"' \
  "$WORK/bad-integration/durable-aop-lifecycle-receipt.json" >"$WORK/bad-receipt"
mv "$WORK/bad-receipt" "$WORK/bad-integration/durable-aop-lifecycle-receipt.json"
python3 - "$WORK/bad-integration" "$WORK/bad-integration.zip" <<'PY'
import pathlib, sys, zipfile
root = pathlib.Path(sys.argv[1])
with zipfile.ZipFile(sys.argv[2], "w", zipfile.ZIP_DEFLATED) as z:
    for path in sorted(root.iterdir()): z.write(path, path.name)
PY
BAD_INTEGRATION_DIGEST=sha256:$(sha256sum "$WORK/bad-integration.zip" | awk '{print $1}')

export FAKE_MODE=ok FAKE_INFRA=$INFRA FAKE_INTEGRATIONS=$INTEGRATIONS FAKE_REPAIR=$REPAIR
export FAKE_RECOVERY=$RECOVERY FAKE_CUSTOMER_ZIP=$WORK/customer.zip FAKE_CUSTOMER_DIGEST=$CUSTOMER_DIGEST
export FAKE_BAD_CUSTOMER_ZIP=$WORK/bad-customer.zip FAKE_BAD_CUSTOMER_DIGEST=$BAD_CUSTOMER_DIGEST
export FAKE_BAD_JOURNEY_ZIP=$WORK/bad-journey.zip FAKE_BAD_JOURNEY_DIGEST=$BAD_JOURNEY_DIGEST
export FAKE_BAD_AUTH_ZIP=$WORK/bad-auth.zip FAKE_BAD_AUTH_DIGEST=$BAD_AUTH_DIGEST
export FAKE_BAD_INTEGRATION_ZIP=$WORK/bad-integration.zip FAKE_BAD_INTEGRATION_DIGEST=$BAD_INTEGRATION_DIGEST
export FAKE_NHP_ZIP=$WORK/nhp.zip FAKE_NHP_DIGEST=$NHP_DIGEST

cat >"$WORK/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args="$*"
if [[ "$args" == *'repos/layervai/qurl-integrations-infra/'* ]]; then
  [[ "${GH_TOKEN:-}" == customer-x ]] || { echo "qurl-infra API used the wrong token" >&2; exit 98; }
elif [[ "$args" == *'repos/layervai/nhp/'* ]]; then
  [[ "${GH_TOKEN:-}" == x ]] || { echo "NHP API used the wrong token" >&2; exit 98; }
elif [[ "$args" == *'repos/layervai/qurl-go/'* || "$args" == *'repos/layervai/qurl-integrations/'* ]]; then
  echo "public API was incorrectly called through authenticated gh" >&2; exit 98
else
  echo "unexpected gh repository route: $args" >&2; exit 98
fi
if [[ "$args" == *'/actions/runs/77/attempts/2/jobs'* ]]; then
  steps='["Verify exact qurl-integrations source","Verify qurl-connector module selection","Verify qurl-integrations binary attestation","Verify exact repaired NHP deployment authority","Verify exact lifecycle integration-test authorities","Acquire customer Auth0 JWT through public API","Create ordinary customer API key","Run host customer-lifecycle smoke","Run host sibling-continuity journey","Run host CRID lifecycle journey","Run hardened customer-lifecycle smoke","Run hardened sibling-continuity journey","Revoke ordinary customer API key","Verify revoked key rejection after cache horizon","Build immutable durable AOP lifecycle receipt","Upload immutable durable AOP lifecycle receipt"]'
  [[ "$FAKE_MODE" != missing_step ]] || steps='["Verify exact qurl-integrations source"]'
  jq -cn --argjson steps "$steps" '[{jobs:[{name:"Protected qURL sharing sandbox lifecycle",conclusion:"success",steps:[$steps[]|{name:.,conclusion:"success"}]}]}]'
elif [[ "$args" == *'/actions/runs/77/artifacts'* ]]; then
  digest=$FAKE_CUSTOMER_DIGEST
  [[ "$FAKE_MODE" != authority_mutation ]] || digest=$FAKE_BAD_CUSTOMER_DIGEST
  [[ "$FAKE_MODE" != journey_mutation ]] || digest=$FAKE_BAD_JOURNEY_DIGEST
  [[ "$FAKE_MODE" != auth_mutation ]] || digest=$FAKE_BAD_AUTH_DIGEST
  [[ "$FAKE_MODE" != integration_mutation ]] || digest=$FAKE_BAD_INTEGRATION_DIGEST
  jq -cn --arg name "durable-aop-lifecycle-receipt-${FAKE_INTEGRATIONS}" --arg digest "$digest" \
    '[{artifacts:[{id:88,name:$name,digest:$digest,expired:false,size_in_bytes:1000,workflow_run:{id:77}}]}]'
elif [[ "$args" == *'/actions/artifacts/88/zip'* ]]; then
  if [[ "$FAKE_MODE" == authority_mutation ]]; then cat "$FAKE_BAD_CUSTOMER_ZIP"
  elif [[ "$FAKE_MODE" == journey_mutation ]]; then cat "$FAKE_BAD_JOURNEY_ZIP"
  elif [[ "$FAKE_MODE" == auth_mutation ]]; then cat "$FAKE_BAD_AUTH_ZIP"
  elif [[ "$FAKE_MODE" == integration_mutation ]]; then cat "$FAKE_BAD_INTEGRATION_ZIP"
  else cat "$FAKE_CUSTOMER_ZIP"; fi
elif [[ "$args" == *'/actions/runs/66/artifacts'* ]]; then
  jq -cn --arg name "durable-aop-nhp-deployment-${FAKE_REPAIR}" --arg digest "$FAKE_NHP_DIGEST" \
    '[{artifacts:[{id:99,name:$name,digest:$digest,expired:false,size_in_bytes:500,workflow_run:{id:66}}]}]'
elif [[ "$args" == *'/actions/artifacts/99/zip'* ]]; then
  if [[ "$FAKE_MODE" == nhp_zip_drift ]]; then printf x; else cat "$FAKE_NHP_ZIP"; fi
elif [[ "$args" == *'/actions/runs/77/attempts/2'* ]]; then
  conclusion=success; [[ "$FAKE_MODE" != failed_customer_run ]] || conclusion=failure
  jq -cn --arg sha "$FAKE_INFRA" --arg conclusion "$conclusion" '{id:77,repository:{full_name:"layervai/qurl-integrations-infra"},head_repository:{full_name:"layervai/qurl-integrations-infra"},head_sha:$sha,head_branch:"main",event:"workflow_dispatch",run_attempt:2,status:"completed",conclusion:$conclusion,path:".github/workflows/qurl-sharing-sandbox.yml"}'
elif [[ "$args" == *'/actions/runs/66/attempts/3'* ]]; then
  sha=$FAKE_RECOVERY; [[ "$FAKE_MODE" != producer_drift ]] || sha=8888888888888888888888888888888888888888
  jq -cn --arg sha "$sha" '{id:66,repository:{full_name:"layervai/nhp"},head_repository:{full_name:"layervai/nhp"},head_sha:$sha,head_branch:"main",event:"workflow_dispatch",run_attempt:3,status:"completed",conclusion:"success",path:".github/workflows/udp-proof-deployment-manifest.yml"}'
elif [[ "$args" == *'/actions/runs/55/attempts/4/jobs'* ]]; then
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
elif [[ "$args" == *'/actions/runs/55/attempts/4'* ]]; then
  sha=$FAKE_REPAIR; [[ "$FAKE_MODE" != build_drift ]] || sha=7777777777777777777777777777777777777777
  jq -cn --arg sha "$sha" '{id:55,repository:{full_name:"layervai/nhp"},head_repository:{full_name:"layervai/nhp"},head_sha:$sha,head_branch:"main",event:"workflow_dispatch",run_attempt:4,status:"completed",conclusion:"success",path:".github/workflows/build-and-push.yml"}'
else
  echo "unexpected gh call: $args" >&2; exit 2
fi
EOF
chmod +x "$WORK/bin/gh"

cat >"$WORK/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ -z ${GH_TOKEN:-} && -z ${GITHUB_TOKEN:-} && -z ${NHP_GH_TOKEN:-} &&
   -z ${CUSTOMER_GH_TOKEN:-} && -z ${PUBLIC_GH_TOKEN:-} &&
   -z ${CUTOVER_CUSTOMER_GH_TOKEN:-} && -z ${CUTOVER_CONNECTOR_GH_TOKEN:-} ]] || {
  echo "public API request inherited an authorization token" >&2; exit 98;
}
for arg in "$@"; do
  [[ ${arg,,} != *authorization* ]] || { echo "public API request supplied an Authorization option" >&2; exit 98; }
done

disable=0 fail=0 silent=0 show_error=0 tls=0 proto=0 no_redirect=0 bounded=0 output= url=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --disable) disable=1; shift ;;
    --fail) fail=1; shift ;;
    --silent) silent=1; shift ;;
    --show-error) show_error=1; shift ;;
    --tlsv1.2) tls=1; shift ;;
    --proto) [[ $2 == '=https' ]]; proto=1; shift 2 ;;
    --max-redirs) [[ $2 == 0 ]]; no_redirect=1; shift 2 ;;
    --connect-timeout) [[ $2 == 10 ]]; shift 2 ;;
    --max-time) [[ $2 == 30 ]]; shift 2 ;;
    --max-filesize) [[ $2 == 4194304 ]]; bounded=1; shift 2 ;;
    --header)
      [[ $2 == 'Accept: application/vnd.github+json' || $2 == 'X-GitHub-Api-Version: 2022-11-28' ]]
      shift 2
      ;;
    --output) output=$2; shift 2 ;;
    --write-out) [[ $2 == '%{http_code}' ]]; shift 2 ;;
    https://api.github.com/*) [[ -z $url ]]; url=$1; shift ;;
    *) echo "unexpected curl fixture argument: $1" >&2; exit 98 ;;
  esac
done
[[ $disable == 1 && $fail == 1 && $silent == 1 && $show_error == 1 && $tls == 1 &&
   $proto == 1 && $no_redirect == 1 && $bounded == 1 && -n $output && -n $url ]]

if [[ ${FAKE_MODE:-} == public_oversize ]]; then
  head -c 4194305 /dev/zero | tr '\0' x >"$output"
elif [[ ${FAKE_MODE:-} == public_malformed ]]; then
  printf '{' >"$output"
else
  path=${url#https://api.github.com/}
  total=1
  [[ ${FAKE_MODE:-} != public_unbounded ]] || total=101
  [[ ${FAKE_MODE:-} != public_incomplete_page ]] || total=2
  case "$path" in
    repos/layervai/qurl-go/git/ref/tags/v0.8.0)
      sha=d02c25995df085f0437c7a572714c26e907a8a59
      [[ ${FAKE_MODE:-} != qurl_go_tag_drift ]] || sha=9999999999999999999999999999999999999999
      jq -cn --arg sha "$sha" '{ref:"refs/tags/v0.8.0",object:{sha:$sha,type:"commit",url:("https://api.github.com/repos/layervai/qurl-go/git/commits/"+$sha)}}' >"$output"
      ;;
    repos/layervai/qurl-go/actions/runs/32621063743/attempts/1)
      conclusion=success; [[ ${FAKE_MODE:-} != qurl_go_run_failed ]] || conclusion=failure
      jq -cn --arg conclusion "$conclusion" '{id:32621063743,repository:{full_name:"layervai/qurl-go"},head_repository:{full_name:"layervai/qurl-go"},head_sha:"d02c25995df085f0437c7a572714c26e907a8a59",head_branch:"main",event:"push",run_attempt:1,status:"completed",conclusion:$conclusion,path:".github/workflows/ci.yml"}' >"$output"
      ;;
    repos/layervai/qurl-go/actions/runs/32621063743/attempts/1/jobs?per_page=100)
      conclusion=success; [[ ${FAKE_MODE:-} != qurl_go_job_failed ]] || conclusion=failure
      jq -cn --arg conclusion "$conclusion" --argjson total "$total" '{total_count:$total,jobs:[{name:"vet + test -race",conclusion:$conclusion,steps:[{name:"go test -race + coverage",conclusion:$conclusion}]}]}' >"$output"
      ;;
    repos/layervai/qurl-integrations/actions/runs/32658570640/attempts/1)
      conclusion=failure; [[ ${FAKE_MODE:-} != integrations_run_failed ]] || conclusion=success
      sha=$FAKE_INTEGRATIONS; [[ ${FAKE_MODE:-} != integrations_run_drift ]] || sha=9999999999999999999999999999999999999999
      branch=fix/exact-session-lifecycle-smoke; [[ ${FAKE_MODE:-} != integrations_branch_drift ]] || branch=other
      pr=1247; [[ ${FAKE_MODE:-} != integrations_pr_drift ]] || pr=1248
      base=f1aa5795a0d45b73bd06fbf64d1dc179c4dc2a29
      [[ ${FAKE_MODE:-} != integrations_base_drift ]] || base=9999999999999999999999999999999999999999
      jq -cn --arg sha "$sha" --arg conclusion "$conclusion" --arg branch "$branch" --arg base "$base" --argjson pr "$pr" '{id:32658570640,repository:{full_name:"layervai/qurl-integrations"},head_repository:{full_name:"layervai/qurl-integrations"},head_sha:$sha,head_branch:$branch,event:"pull_request",run_attempt:1,status:"completed",conclusion:$conclusion,path:".github/workflows/cli.yml",pull_requests:[{number:$pr,head:{sha:$sha},base:{sha:$base}}]}' >"$output"
      ;;
    repos/layervai/qurl-integrations/actions/runs/32658570640/attempts/1/jobs?per_page=100)
      conclusion=success; [[ ${FAKE_MODE:-} != integrations_job_failed ]] || conclusion=failure
      sha=$FAKE_INTEGRATIONS; [[ ${FAKE_MODE:-} != integrations_run_drift ]] || sha=9999999999999999999999999999999999999999
      jq -cn --arg sha "$sha" --arg conclusion "$conclusion" --argjson total "$total" '{total_count:$total,jobs:[{name:"cli / test",head_sha:$sha,conclusion:$conclusion,steps:[{name:"Run tests with coverage",conclusion:$conclusion}]}]}' >"$output"
      ;;
    *) echo "unexpected or crossed public API route: $url" >&2; exit 98 ;;
  esac
fi
printf '%s' "$([[ ${FAKE_MODE:-} == public_non_200 ]] && printf 503 || printf 200)"
EOF
chmod +x "$WORK/bin/curl"

run_script() {
  local target=$1
  PATH="$WORK/bin:$PATH" GH_TOKEN=x CUTOVER_CUSTOMER_GH_TOKEN=${CUSTOMER_TOKEN:-customer-x} \
    CUTOVER_CUSTOMER_LIFECYCLE_RUN_ID=77 CUTOVER_CUSTOMER_LIFECYCLE_RUN_ATTEMPT=2 \
    CUTOVER_CUSTOMER_LIFECYCLE_INFRA_SHA=$INFRA CUTOVER_CUSTOMER_LIFECYCLE_INTEGRATIONS_SHA=$INTEGRATIONS \
    CUTOVER_EXPECTED_REPAIR_SOURCE_SHA=$REPAIR CUTOVER_EXPECTED_RECOVERY_ORCHESTRATOR_SHA=$RECOVERY \
    CUTOVER_EXPECTED_REPAIR_BUILD_RUN_ID=55 CUTOVER_EXPECTED_REPAIR_BUILD_RUN_ATTEMPT=4 \
    CUTOVER_EXPECTED_SERVER_DIGEST=$SERVER_DIGEST CUTOVER_EXPECTED_AC_DIGEST=$AC_DIGEST \
    CUTOVER_EXPECTED_CELL0_COLOR=green CUTOVER_EXPECTED_CELL0_ASG=layerv-nhp-sandbox-server-green \
    CUTOVER_EXPECTED_CELL1_COLOR=blue CUTOVER_EXPECTED_CELL1_ASG=layerv-nhp-sandbox-cell1-server \
    CUTOVER_EXPECTED_AC_COLOR=green CUTOVER_EXPECTED_AC_ASG=layerv-nhp-sandbox-ac-green "$target"
}
run() { run_script "$SCRIPT"; }

receipt=$(run)
[[ "$receipt" == "v2|layervai/qurl-integrations-infra|77|2|${INFRA}|${INTEGRATIONS}|88|${CUSTOMER_DIGEST}|66|3|99|${NHP_DIGEST}|${REPAIR}|${RECOVERY}|55|4|${SERVER_DIGEST}|${AC_DIGEST}|${AUTHORITY_SHA}" ]]
if CUSTOMER_TOKEN=wrong run >/dev/null 2>&1; then
  echo "customer lifecycle verifier accepted the wrong private-repository token" >&2
  exit 1
fi
for mode in failed_customer_run missing_step authority_mutation journey_mutation auth_mutation integration_mutation \
  qurl_go_tag_drift qurl_go_run_failed qurl_go_job_failed integrations_run_failed integrations_run_drift \
  integrations_branch_drift integrations_pr_drift integrations_base_drift integrations_job_failed \
  producer_drift build_drift nhp_zip_drift public_non_200 public_oversize public_malformed \
  public_unbounded public_incomplete_page; do
  export FAKE_MODE=$mode
  if run >/dev/null 2>&1; then
    echo "customer lifecycle verifier accepted $mode authority" >&2
    exit 1
  fi
done

sed "s/curl --disable/curl --disable --header 'Authorization: Bearer injected'/" \
  "$SCRIPT" >"$WORK/public-auth-header.sh"
chmod +x "$WORK/public-auth-header.sh"
if FAKE_MODE=ok run_script "$WORK/public-auth-header.sh" >"$WORK/public-auth-header.log" 2>&1; then
  echo "customer lifecycle verifier sent an Authorization header to a public API" >&2
  exit 1
fi
grep -F "public API request supplied an Authorization option" "$WORK/public-auth-header.log" >/dev/null

sed 's/curl --disable/GH_TOKEN=leaked curl --disable/' "$SCRIPT" >"$WORK/public-token-leak.sh"
chmod +x "$WORK/public-token-leak.sh"
if FAKE_MODE=ok run_script "$WORK/public-token-leak.sh" >"$WORK/public-token-leak.log" 2>&1; then
  echo "customer lifecycle verifier leaked a token to a public API" >&2
  exit 1
fi
grep -F "public API request inherited an authorization token" "$WORK/public-token-leak.log" >/dev/null

sed 's/^QURL_GO_REPOSITORY=.*/QURL_GO_REPOSITORY=layervai\/nhp/' "$SCRIPT" >"$WORK/public-crossed-route.sh"
chmod +x "$WORK/public-crossed-route.sh"
if FAKE_MODE=ok run_script "$WORK/public-crossed-route.sh" >"$WORK/public-crossed-route.log" 2>&1; then
  echo "customer lifecycle verifier accepted a crossed public repository route" >&2
  exit 1
fi
grep -F "repository authority transport classification is invalid" "$WORK/public-crossed-route.log" >/dev/null

echo "verify-durable-aop-customer-lifecycle-run: all tests passed"
