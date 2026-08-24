#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT=$ROOT/.github/scripts/recover-durable-aop-cutover-schema3.sh
ORIGINAL=e9b11398a4cea98da6ae5b41cfe635562e1b7c72
REPAIR=422b1d9acac53d50fe5602158fb02c8120ef108d
RECOVERY=abcdefabcdefabcdefabcdefabcdefabcdefabcd
RUNTIME=f32335420d67fd235a6fb6598a1fc3d8eaf8dda7
RECOVERY_PREDECESSOR=519bed05f0dc5ea2e40a0f45afffb8e86cc729be
RECOVERY_HANDOFF_STATE_DIGEST=bf64f92a30915349c4561bedda2ba84c967e2060e1ac46baa66435338104d9fe
STALE_RETIREMENT_PREDECESSOR=84ed10e2773c49894b3c2c5f2fccdcdfa52b447d
STALE_RETIREMENT_STATE_DIGEST=b972283f4d37bfa6b2d672b531a6d87a5ab305e0973d5a24d5d19e75f45ef348
MANIFEST=2895963905453d61874858171529968efe8e18e5450d41842854fd2784d1ec78
OWNER="nhp:32635672597:durable-aop-cutover:${ORIGINAL}"
ORIGINAL_STATE_DIGEST=e7ed20adde2ce9e143c9505027a73e415e5dd3d4a9d0c950c912d6398cc5d13e
ORIGINAL_LOCK_DIGEST=6c7224d78837a4d56547409439d9bce30efa9b214367c4f19fd13cc3fe3b2ebd
SERVER_DIGEST=sha256:d758d39bf760e44bcdba4e56d464ff98e7adc887ebe426a06a7ab9e261fccfcb
AC_DIGEST=sha256:16188f567aa0e169a70eed8e75c370ffda532e1d3bce0eec8f439be582d559fb
RUNTIME_SERVER_DIGEST=sha256:0921191723fd6a4919f22e0dded5775411bb08a682dc9d9f9a69fdcded7674c9
RUNTIME_AC_DIGEST=sha256:773bd37e915ac767f57e7656b5c038a8f2c70348901b1e81572584d6cfad566e
RUNTIME_SERVER_SELECTOR=${RUNTIME}@${RUNTIME_SERVER_DIGEST}
RUNTIME_AC_SELECTOR=${RUNTIME}@${RUNTIME_AC_DIGEST}
CONNECTOR=2222222222222222222222222222222222222222
CONNECTOR_PR=16dd7d3c835bf4f44b212e2d6a34205a3c04a8d8
CONNECTOR_BASE=e70923168818da0b8002e5e63e7dcfe9e060ba12
CONNECTOR_TREE=4444444444444444444444444444444444444444
QURL_GO=d02c25995df085f0437c7a572714c26e907a8a59
INFRA=d30d3fce3a6c3cf15e1340a5106b6cc76bce7e82
INTEGRATIONS=356ecd44bbf09fca392247d971bbc093b337d4e5
export QURL_GO
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/helpers" "$WORK/connector-artifact"
mkdir -p "$WORK/repo/.github"
cp -R "$ROOT/.github/scripts" "$WORK/repo/.github/scripts"
ln -s "$ROOT/scripts" "$WORK/repo/scripts"
ln -s "$ROOT/terraform" "$WORK/repo/terraform"
SCRIPT=$WORK/repo/.github/scripts/recover-durable-aop-cutover-schema3.sh
export FAKE_PARAMS=$WORK/params FAKE_ASGS=$WORK/asgs FAKE_ACTIONS=$WORK/actions
export FAKE_PROVENANCE_CALLS=$WORK/provenance-calls
export FAKE_ORIGINAL_STATE_RECORD=$WORK/original-state FAKE_ORIGINAL_LOCK_RECORD=$WORK/original-lock
export FAKE_STATE_VERSION_FILE=$WORK/state-version
export FAKE_JOURNAL_VERSION_FILE=$WORK/journal-version
export FAKE_PREDECESSOR_ORPHAN_VERSION_FILE=$WORK/predecessor-orphan-version
export FAKE_ORIGINAL=$ORIGINAL FAKE_REPAIR=$REPAIR FAKE_SERVER_DIGEST=$SERVER_DIGEST FAKE_AC_DIGEST=$AC_DIGEST
export RUNTIME_SERVER_DIGEST RUNTIME_AC_DIGEST
export RUNTIME_SERVER_SELECTOR RUNTIME_AC_SELECTOR
export FAKE_RECOVERY=$RECOVERY FAKE_CONNECTOR=$CONNECTOR FAKE_CONNECTOR_PR=$CONNECTOR_PR
export FAKE_CONNECTOR_BASE=$CONNECTOR_BASE
export FAKE_CONNECTOR_TREE=$CONNECTOR_TREE
export FAKE_INFRA=$INFRA FAKE_INTEGRATIONS=$INTEGRATIONS
export RUNTIME

# The one-time recovery selector is consumed unchanged by both launch-template
# boot paths. Docker's tag@digest reference keeps the source tag readable while
# the digest, rather than the mutable tag, selects the pulled image bytes.
[[ "$RUNTIME_SERVER_SELECTOR" =~ ^[0-9a-f]{40}@sha256:[0-9a-f]{64}$ &&
   "$RUNTIME_AC_SELECTOR" =~ ^[0-9a-f]{40}@sha256:[0-9a-f]{64}$ ]]
grep -F 'docker pull "$ECR_REPO:$IMAGE_TAG"' "$ROOT/terraform/modules/compute/user_data.sh.tpl" >/dev/null
grep -F 'NHP_IMAGE_TAG=$IMAGE_TAG' "$ROOT/terraform/modules/compute/user_data.sh.tpl" >/dev/null
grep -F '$${NHP_ECR_REPO}:$${NHP_IMAGE_TAG}"' "$ROOT/terraform/modules/compute/user_data.sh.tpl" >/dev/null
grep -F 'docker pull "$ECR_REPO:$IMAGE_TAG"' "$ROOT/terraform/modules/ac/user_data.sh.tpl" >/dev/null
grep -F 'docker create "$ECR_REPO:$IMAGE_TAG"' "$ROOT/terraform/modules/ac/user_data.sh.tpl" >/dev/null

(cd "$ROOT/endpoints" && GOWORK=off KBS_SKIP_INIT=1 go run ./cmd/session-control-stale-target-retirement plan) >"$WORK/stale-target-plan.json"
cat >"$WORK/helpers/stale-retire" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
directory_receipt() {
  local count=$1 version=$2 updated=$3 blocked=${4:-false} overflow=${5:-0}
  local event=${6:-} prepared=${7:-0} selected=${8:-0} digest
  digest=$({
    printf '\0%s' v1 cell0 "$version" "$count" "$blocked" "$overflow" "$event" "$prepared" "$selected" \
      1787530000000 "$updated"
  } | sha256sum | awk '{print $1}')
  jq -cn --arg version "$version" --arg count "$count" --argjson blocked "$blocked" --arg overflow "$overflow" \
    --arg event "$event" --arg prepared "$prepared" --arg selected "$selected" \
    --arg updated "$updated" --arg digest "$digest" '
    {schema:"layerv.durable-aop-fence-directory-receipt.v1",cell_id:"cell0",version:$version,
     active_fence_count:$count,admission_blocked:$blocked,overflow_close_count:$overflow,overflow_leader_event_id:$event,
     overflow_leader_prepared_directory_version:$prepared,overflow_leader_selected_directory_version:$selected,
     created_at_ms:"1787530000000",updated_at_ms:$updated,directory_sha256:$digest}'
}
decode_journal() {
  printf '%s' "$1" | python3 -c 'import base64,gzip,json,sys; v=json.load(sys.stdin); sys.stdout.buffer.write(gzip.decompress(base64.b64decode(v["payload"],validate=True)))'
}
case ${1:-} in
  plan) cat "$FAKE_STALE_TARGET_PLAN" ;;
  snapshot-fence-directory)
    case ${FAKE_FENCE_START_AUTHORITY:-valid} in
      valid) directory_receipt "${FAKE_FENCE_START_COUNT:-82}" 83 1787553983425 ;;
      malformed) printf '{"schema":' ;;
      noncanonical) directory_receipt 01 83 1787553983425 ;;
      admission_blocked) directory_receipt 82 83 1787553983425 true ;;
      overflow) directory_receipt 82 83 1787553983425 true 1 11111111111111111111111111111111 82 83 ;;
      *) exit 98 ;;
    esac
    ;;
  verify-fence-drain)
    if [[ "${FAKE_FENCE_DRAIN_INCOMPLETE:-}" == true ]]; then exit 75; fi
    printf 'verify-fence-drain\n' >>"$FAKE_ACTIONS"
    # Version 106 models fences that arrived after the exact v83/count-82
    # starting snapshot. Only the stable zero successor authorizes retirement.
    directory_receipt 0 106 1787555000000
    ;;
  snapshot-predecessors)
		printf 'snapshot-predecessors\n' >>"$FAKE_ACTIONS"
    jq -cn '{schema:"layerv.durable-aop-predecessor-target-plan.v1",table:"layerv-nhp-sandbox-cell0-nhp-session-control",region:"us-east-2",ac_id:"layerv-ac-tf",control_cell_id:"cell0",targets:[
      {id:"predecessor-1",fence_sha256:"ac8512dc6d0cac5a9ddfe5b471458418bab6c55d1b9df6aa49a26abb748c9967",fence:{ac_id:"layerv-ac-tf",public_key:"current-predecessor",boot_id:"boot-current",flush_generation:"3",version:"49",authority_version:"5",counted_active_slot:true,control_cell_id:"cell0",activated_control_version:"0",ready_control_version:"0",aak_enqueued_at_ms:"0",aak_transaction_id:"0",created_at_ms:"1787529555693",prepared_at_ms:"1787533540595"}}]}'
    ;;
  retire)
    shift
    id= table= region=
    while (($#)); do
      case $1 in --target-id) id=$2; shift 2;; --table) table=$2; shift 2;; --region) region=$2; shift 2;; *) exit 98;; esac
    done
    [[ "$table" == layerv-nhp-sandbox-cell0-nhp-session-control && "$region" == us-east-2 ]]
    target=$(jq -ce --arg id "$id" '.targets[] | select(.id == $id)' "$FAKE_STALE_TARGET_PLAN")
    printf 'retire\t%s\n' "$id" >>"$FAKE_ACTIONS"
    jq -cn --arg id "$id" --arg key "$(jq -r .fence.public_key <<<"$target")" \
      --arg version "$(( $(jq -r .fence.version <<<"$target") + 1 ))" \
      --arg authority "$(( $(jq -r .fence.authority_version <<<"$target") + 1 ))" '
      {schema:"layerv.durable-aop-stale-target-retirement-receipt.v1",target_id:$id,public_key:$key,
       version:$version,authority_version:$authority,counted_active_slot:false,retired_at_ms:"1787539000000",
       retired_target_sha256:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
    ;;
  retire-predecessor)
    shift
    id=
    while (($#)); do
      case $1 in --target-id) id=$2; shift 2;; *) exit 98;; esac
    done
    [[ "$id" == predecessor-1 ]]
		printf 'retire-predecessor\t%s\n' "$id" >>"$FAKE_ACTIONS"
    state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
    ref=$(jq -er '.repair.stale_target_retirement_ref.version' <<<"$state")
    read -r current_version <"$FAKE_JOURNAL_VERSION_FILE"
    current=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
    historical=$(awk -F '\t' -v n="/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement:${ref}" '$1==n {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
    if [[ "$current_version" == "$ref" ]]; then
      [[ "$current" == "$historical" ]]
      jq -cn --arg id "$id" '{schema:"layerv.durable-aop-stale-target-retirement-receipt.v1",target_id:$id,public_key:"current-predecessor",version:"50",authority_version:"6",counted_active_slot:false,retired_at_ms:"1787540000000",retired_target_sha256:"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}'
    elif [[ "$current_version" == "$((ref + 1))" ]]; then
      old=$(decode_journal "$historical")
      successor=$(decode_journal "$current")
      old_target=$(jq -cS --arg id "$id" '.runtime.predecessor_targets[] | select(.id==$id)' <<<"$old")
      new_target=$(jq -cS --arg id "$id" '.runtime.predecessor_targets[] | select(.id==$id)' <<<"$successor")
      [[ "$(jq -r .status <<<"$old_target")" == pending && "$(jq -r .status <<<"$new_target")" == retired ]]
      normalized=$(jq -cS --arg id "$id" --argjson target "$old_target" '(.runtime.predecessor_targets[] | select(.id==$id))=$target' <<<"$successor")
      [[ "$normalized" == "$(jq -cS . <<<"$old")" ]]
      printf '%s\n' "$current_version" >"$FAKE_PREDECESSOR_ORPHAN_VERSION_FILE"
      printf 'retire-predecessor-orphan\t%s\t%s\n' "$id" "$current_version" >>"$FAKE_ACTIONS"
      jq -cS .receipt <<<"$new_target"
    else
      exit 98
    fi
    ;;
  *) exit 98 ;;
esac
EOF
chmod +x "$WORK/helpers/stale-retire"
export FAKE_STALE_TARGET_PLAN=$WORK/stale-target-plan.json

jq -cn --arg connector "$CONNECTOR" --arg controller "$RECOVERY" '
  {schema_version:1,phase:"pre_removal",repository:"layervai/qurl-connector",commit_sha:$connector,
   run_id:"901",run_attempt:"2",nhp_controller_run_id:"66",nhp_controller_run_attempt:"3",
   dispatch_correlation_id:"nhp-66-3-connector-pre_removal-0123456789abcdef0123456789abcdef",
   gate_passed:true,input_outcome:"success",enforcement_outcome:"success",inputs_unchanged:true,
   counts:{blocking:0,failures:0,skips:0,implemented:12,exact_passes:12},
   provenance_valid:true,two_cell_provenance:true,typed_evidence_complete:true,
   deployment_producer:{repository:"layervai/nhp",workflow_path:".github/workflows/udp-proof-deployment-manifest.yml",
     run_id:"55",run_attempt:"4",head_sha:$controller,artifact_id:"54",
     artifact_digest:"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
' >"$WORK/connector-artifact/strict-sandbox-proof.evidence.json"
jq -cn --arg connector "$CONNECTOR" --arg qurl_go "$QURL_GO" --arg nhp "$RUNTIME" --arg digest "$RUNTIME_SERVER_DIGEST" '
  {schema_version:1,phase:"pre_removal",retirement_state:"http_lifecycle_present",
   repositories:{qurl_connector:$connector,qurl_go:$qurl_go,nhp:$nhp},connector_modules:{qurl_go:$qurl_go},
   images:{nhp_cell0:$digest,nhp_cell1:$digest}}
' >"$WORK/connector-artifact/sandbox-deployment-manifest.json"
for name in deployment-runtime-inputs.json strict-typed-evidence.json strict-proof-scenarios.json typed-evidence-contract.json; do
  printf '{"present":true}\n' >"$WORK/connector-artifact/$name"
done
python3 - "$WORK/connector-artifact" "$WORK/connector-proof.zip" <<'PY'
import pathlib
import sys
import zipfile
source, target = map(pathlib.Path, sys.argv[1:])
with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as bundle:
    for path in sorted(source.iterdir()):
        bundle.write(path, path.name)
PY
export FAKE_CONNECTOR_ZIP=$WORK/connector-proof.zip
FAKE_CONNECTOR_ZIP_DIGEST=sha256:$(sha256sum "$FAKE_CONNECTOR_ZIP" | awk '{print $1}')
export FAKE_CONNECTOR_ZIP_DIGEST
export FAKE_CONNECTOR_ZIP_SIZE
FAKE_CONNECTOR_ZIP_SIZE=$(stat -f %z "$FAKE_CONNECTOR_ZIP" 2>/dev/null || stat -c %s "$FAKE_CONNECTOR_ZIP")

# Build the exact six-file protected customer artifact plus its independently
# downloadable one-file NHP deployment artifact. The recovery controller must
# verify both byte sets; green workflow metadata alone is insufficient.
python3 - "$WORK" "$RUNTIME" "$RECOVERY" "$RUNTIME_SERVER_DIGEST" "$RUNTIME_AC_DIGEST" "$INFRA" "$INTEGRATIONS" <<'PY'
import hashlib, json, pathlib, sys, zipfile
root = pathlib.Path(sys.argv[1])
repair, recovery, server, ac, infra, integrations = sys.argv[2:]
customer = root / "customer-artifact"
customer.mkdir()
modules = f"\tdep\tgithub.com/layervai/qurl-go\tv0.8.0\th1:Tw8291djSj3LT+aGWPW7PPuIEBeAKcIG3h2CddxFlzk=\n\tbuild\tvcs.revision={integrations}\n\tbuild\tvcs.modified=false\n"
(customer / "qurl.modules.txt").write_text(modules)
(customer / "test.modules.txt").write_text(modules)
gate = {"required": True, "satisfied_by_this_run": False, "repository": "layervai/qurl-connector",
        "pull_request": 609, "workflow": ".github/workflows/sandbox-smoke.yml",
        "job": "Attended Connector UDP proof (strict)"}
qurl_go = {"path": "github.com/layervai/qurl-go", "version": "v0.8.0",
           "sum": "h1:Tw8291djSj3LT+aGWPW7PPuIEBeAKcIG3h2CddxFlzk=",
           "go_mod_sum": "h1:zujbZnolKJzJEDyKwgUqulhHSi0sZeU2w1x+nle/yeM="}
selection = {"schema": "layerv.qurl-sharing-canary.v2", "integrations_sha": integrations,
             "source_kind": "pull_request", "pull_request_number": 1247, "source_profile": "cli_only",
             "qurl_go": qurl_go, "qurl_connector": None, "connector_attended_gate": gate}
def canonical(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2, separators=(",", ": ")) + "\n")
canonical(customer / "selection.json", selection)
deployment = {
    "schema": "layerv.durable-aop-nhp-deployment.v1", "repository": "layervai/nhp",
    "environment": "sandbox", "profile": "durable-aop-v1", "repair_source_sha": repair,
    "recovery_orchestrator_sha": recovery,
    "build": {"workflow": ".github/workflows/build-and-push.yml", "run_id": "32682520698", "run_attempt": "1", "head_sha": repair},
    "producer": {"workflow": ".github/workflows/udp-proof-deployment-manifest.yml", "source_sha": recovery,
                 "run_id": "66", "run_attempt": "3", "head_sha": recovery},
    "images": {"server": {"repository": "layerv/nhp-server", "digest": server},
               "ac": {"repository": "layerv/nhp-ac", "digest": ac}},
    "deployments": {
        "cell0": {"environment": "sandbox", "component": "server", "active_color": "blue", "active_asg": "layerv-nhp-sandbox-server", "image_digest": server},
        "cell1": {"environment": "sandbox-cell1", "component": "server", "active_color": "green", "active_asg": "layerv-nhp-sandbox-cell1-server-green", "image_digest": server},
        "ac": {"environment": "sandbox", "component": "ac", "active_color": "green", "active_asg": "layerv-nhp-sandbox-ac-green", "image_digest": ac}}}
deployment_path = root / "durable-aop-nhp-deployment.json"
deployment_path.write_text(json.dumps(deployment, sort_keys=True, separators=(",", ":")) + "\n")
with zipfile.ZipFile(root / "nhp-deployment.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.write(deployment_path, deployment_path.name)
nhp_digest = "sha256:" + hashlib.sha256((root / "nhp-deployment.zip").read_bytes()).hexdigest()
authority = {"schema": "layerv.durable-aop-nhp-authority.v1", "deployment": deployment,
             "artifact": {"repository": "layervai/nhp", "name": f"durable-aop-nhp-deployment-{repair}",
                          "id": "903", "digest": nhp_digest}}
canonical(customer / "nhp-deployment-authority.json", authority)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
qurl_sha, test_sha = "1" * 64, "2" * 64
subjects = {"qurl": qurl_sha, "qurl-sharing-sandbox.test": test_sha,
            "qurl.modules.txt": sha(customer / "qurl.modules.txt"),
            "test.modules.txt": sha(customer / "test.modules.txt"),
            "selection.json": sha(customer / "selection.json")}
(customer / "verified-subjects.sha256").write_text("".join(f"{digest}  {name}\n" for name, digest in subjects.items()))
attestation = {"verified": True, "repository": "layervai/qurl-integrations-infra",
               "workflow": ".github/workflows/qurl-sharing-sandbox.yml", "source_ref": "refs/heads/main", "source_sha": infra}
receipt = {
    "schema": "layerv.durable-aop-lifecycle-receipt.v4",
    "orchestrator": {"repository": "layervai/qurl-integrations-infra", "workflow": ".github/workflows/qurl-sharing-sandbox.yml",
                     "sha": infra, "run_id": 900, "run_attempt": 2},
    "source": {"repository": "layervai/qurl-integrations", "sha": integrations, "kind": "pull_request", "pull_request_number": 1247, "profile": "cli_only"},
    "modules": {"qurl_go": qurl_go, "qurl_connector": None},
    "nhp_deployment": {"authority_sha256": sha(customer / "nhp-deployment-authority.json"), "authority": authority},
    "subjects": {"qurl": {"sha256": qurl_sha, "modules_sha256": subjects["qurl.modules.txt"], "build_attestation": attestation},
                 "test_harness": {"sha256": test_sha, "modules_sha256": subjects["test.modules.txt"], "build_attestation": attestation}},
    "customer_auth": {"mode": "auth0_public_api_key", "auth0_jwt": "passed",
                      "public_api_key_create": "passed", "key_authenticated_lifecycle": "passed",
                      "public_api_key_revoke": "passed", "post_cache_horizon_rejection": "passed",
                      "sandbox_credential_endpoint": False, "sandbox_credential_selector": None,
                      "operations": {
                          "create": {"method": "POST", "path": "/v1/api-keys", "status": 201, "auth": "auth0_jwt"},
                          "identity": {"method": "GET", "path": "/v1/me", "status": 200, "auth": "api_key"},
                          "revoke": {"method": "DELETE", "path": "/v1/api-keys/{key_id}", "status": 204, "auth": "auth0_jwt"},
                          "rejection": {"method": "GET", "path": "/v1/me", "status": 401, "auth": "revoked_api_key", "after_cache_horizon": True}}},
    "live_customer_steps": {
        "sequential_lifecycle": {"name": "TestSandboxLocalPublishLifecycleSmoke", "runtimes": ["hardened_container", "host"], "result": "passed", "two_distinct_registered_sessions": "passed", "exact_retire_each_session": "passed", "replacement_admission": "passed", "durable_identity_continuity": "passed"},
        "sibling_continuity": {"name": "TestSandboxLocalPublishSiblingContinuity", "runtimes": ["hardened_container", "host"], "result": "passed", "two_real_processes": "passed", "get_a_and_b_before_retire": "passed", "retire_a": "passed", "get_b_while_a_retired": "passed", "restart_a_same_state_resource": "passed", "get_a_and_b_after_restart": "passed", "exact_retire_cleanup": "passed"},
        "crid_lifecycle": {"name": "TestSandboxCRIDJourney", "runtime": "host", "result": "passed", "create_list_resolve_get_delete": "passed", "idempotent_resource_delete": "passed"}},
    "integration_tests": {
        "nhp": {"repository": "layervai/nhp", "source_sha": repair, "workflow": ".github/workflows/build-and-push.yml", "run_id": 32682520698, "run_attempt": 1, "event": "workflow_dispatch", "job": "Test", "step": "Run tests (privileged container for iptables)", "result": "passed", "tests": ["TestE2E_RelayCrossServer_KnockForwardedToRemoteAC_AckReturnsViaRelay", "TestExactSessionFleetCompensationClosesRemoteForwardedSessionOnly", "TestHandleKnockRequestSendFailureCompensatesRemoteAdmissions", "TestHandleRelayForward_ExactSessionRetirementReturnsDurableReceipt", "TestSessionControlLifecycleRecoveryResumesAfterCompleteAndClearsClosingDueAuthority", "TestSessionControlRecoveryClosesReservedCrashGapAfterAckEnqueue"]},
        "qurl_go": {"repository": "layervai/qurl-go", "source_sha": "d02c25995df085f0437c7a572714c26e907a8a59", "workflow": ".github/workflows/ci.yml", "run_id": 32621063743, "run_attempt": 1, "event": "push", "job": "vet + test -race", "step": "go test -race + coverage", "result": "passed", "tests": ["TestConnectAgentRuntime_LostRAKRestartExactReplayAfterTicketExpiry", "TestConnectAgentRuntime_ResumesPersistedCandidateAfterLostCompletionReply", "TestConsumeNativeExactSessionCloseReply_StrictAuthority", "TestRetireRegisteredAgentSession_ClassifiesReceiptAndTransportFailures", "TestRetireRegisteredAgentSession_UsesExactReceiptOriginalEndpointAndRetriesIdempotently"]},
        "qurl_integrations": {"repository": "layervai/qurl-integrations", "source_sha": integrations, "workflow": ".github/workflows/cli.yml", "run_id": 32658570640, "run_attempt": 1, "event": "pull_request", "job": "cli / test", "step": "Run tests with coverage", "result": "passed", "tests": ["TestNativeBlocksNewCycleAdmissionUntilPriorReceiptRetires", "TestNativeEndCycleRetriesExactReceiptUntilAccepted", "TestNativeLostKnockReplyDoesNotFabricateRetirement", "TestNativeLostReplyConsumesAttemptWithoutFabricatingReceipt", "TestNativeRetirementFailureBlocksReplacementAdmission", "TestNativeUsesMonotonicAttemptsAndRetiresEveryReceipt"]}},
    "connector_attended_gate": gate}
canonical(customer / "durable-aop-lifecycle-receipt.json", receipt)
with zipfile.ZipFile(root / "customer-receipt.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for path in sorted(customer.iterdir()): z.write(path, path.name)
customer_digest = "sha256:" + hashlib.sha256((root / "customer-receipt.zip").read_bytes()).hexdigest()
(root / "customer-fixture.env").write_text(
    f"FAKE_CUSTOMER_ZIP_DIGEST={customer_digest}\nFAKE_NHP_ZIP_DIGEST={nhp_digest}\n"
    f"FAKE_AUTHORITY_SHA={sha(customer / 'nhp-deployment-authority.json')}\n")
PY
export FAKE_CUSTOMER_ZIP=$WORK/customer-receipt.zip FAKE_NHP_ZIP=$WORK/nhp-deployment.zip
set -a
# shellcheck source=/dev/null
source "$WORK/customer-fixture.env"
set +a
export FAKE_CUSTOMER_ZIP_DIGEST FAKE_NHP_ZIP_DIGEST FAKE_AUTHORITY_SHA

cat >"$WORK/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
svc=$1 op=$2; shift 2
opt() { local key=$1 prev=; shift; for arg in "$@"; do [[ "$prev" == "$key" ]] && { printf '%s' "$arg"; return; }; prev=$arg; done; }
decode_journal() {
  printf '%s' "$1" | python3 -c 'import base64,gzip,json,sys; v=json.load(sys.stdin); sys.stdout.buffer.write(gzip.decompress(base64.b64decode(v["payload"],validate=True)))'
}
case "$svc/$op" in
  ssm/get-parameter)
    name=$(opt --name "$@"); query=$(opt --query "$@")
    if [[ "$query" == Parameter.Version ]]; then
      if [[ "$name" == */stale-target-retirement ]]; then
			[[ -s "$FAKE_JOURNAL_VERSION_FILE" ]] || { echo ParameterNotFound >&2; exit 254; }
			cat "$FAKE_JOURNAL_VERSION_FILE"
		elif [[ "$name" == */state ]]; then
        if [[ "${FAKE_STATE_VERSION_READ_ERROR:-}" == true ]]; then
          echo "injected state version read failure" >&2
          exit 75
        fi
        if [[ -s "${FAKE_STATE_VERSION_FILE:-}" ]]; then cat "$FAKE_STATE_VERSION_FILE"; else printf '%s\n' "${FAKE_STATE_VERSION:-7}"; fi
      else
        printf '%s\n' "${FAKE_LOCK_VERSION:-2}"
      fi
      exit 0
    fi
    if [[ "$name" == */state:7 ]]; then cat "$FAKE_ORIGINAL_STATE_RECORD"; exit 0; fi
    if [[ "$name" == */qurl-live-env-lock:2 ]]; then cat "$FAKE_ORIGINAL_LOCK_RECORD"; exit 0; fi
    awk -F '\t' -v n="$name" '$1==n {print substr($0,index($0,"\t")+1); found=1} END {exit !found}' "$FAKE_PARAMS" || { echo ParameterNotFound >&2; exit 254; }
    ;;
  ssm/put-parameter)
    name=$(opt --name "$@"); value=$(opt --value "$@")
    if [[ " $* " == *' --no-overwrite '* ]] && awk -F '\t' -v n="$name" '$1==n {found=1} END {exit !found}' "$FAKE_PARAMS"; then
      echo ParameterAlreadyExists >&2
      exit 254
    fi
    if [[ -n "${FAKE_FAIL_COMPLETE_STATE_ONCE:-}" && "$name" == */state &&
          "$(jq -r '.phase // empty' <<<"$value")" == complete && ! -e "$FAKE_FAIL_COMPLETE_STATE_ONCE" ]]; then
      : >"$FAKE_FAIL_COMPLETE_STATE_ONCE"
      exit 75
    fi
		if [[ "$name" == */state && -n "${FAKE_FAIL_STATE_ONCE_PER_JOURNAL_VERSION_FILE:-}" &&
		      -s "$FAKE_JOURNAL_VERSION_FILE" ]]; then
			read -r journal_version <"$FAKE_JOURNAL_VERSION_FILE"
			if ! grep -Fxq "$journal_version" "$FAKE_FAIL_STATE_ONCE_PER_JOURNAL_VERSION_FILE" 2>/dev/null; then
				printf '%s\n' "$journal_version" >>"$FAKE_FAIL_STATE_ONCE_PER_JOURNAL_VERSION_FILE"
				exit 75
			fi
		fi
		if [[ "$name" == */stale-target-retirement ]]; then
			version=0; [[ ! -s "$FAKE_JOURNAL_VERSION_FILE" ]] || read -r version <"$FAKE_JOURNAL_VERSION_FILE"
			version=$((version + 1))
			printf '%s\n' "$version" >"$FAKE_JOURNAL_VERSION_FILE"
			awk -F '\t' -v n="$name" -v historical="${name}:${version}" '$1!=n && $1!=historical' "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"
			printf '%s\t%s\n%s:%s\t%s\n' "$name" "$value" "$name" "$version" "$value" >>"$FAKE_PARAMS.tmp"
		else
			awk -F '\t' -v n="$name" '$1!=n' "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"
			printf '%s\t%s\n' "$name" "$value" >>"$FAKE_PARAMS.tmp"
		fi
		mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
    if [[ "$name" == */state && -s "${FAKE_STATE_VERSION_FILE:-}" ]]; then
      read -r version <"$FAKE_STATE_VERSION_FILE"
      printf '%s\n' "$((version + 1))" >"$FAKE_STATE_VERSION_FILE"
    fi
    printf 'put\t%s\n' "$name" >>"$FAKE_ACTIONS"
		if [[ "$name" == */state && -s "$FAKE_PREDECESSOR_ORPHAN_VERSION_FILE" ]]; then
			read -r orphan_version <"$FAKE_PREDECESSOR_ORPHAN_VERSION_FILE"
			[[ "$(jq -r '.repair.stale_target_retirement_ref.version // 0' <<<"$value")" == "$orphan_version" ]]
			printf 'predecessor-orphan-state-adopt\t%s\n' "$orphan_version" >>"$FAKE_ACTIONS"
			rm -f "$FAKE_PREDECESSOR_ORPHAN_VERSION_FILE"
		fi
		if [[ "$name" == */stale-target-retirement && "$(decode_journal "$value" | jq -r .status)" == ac_intent ]]; then
			printf 'put-predecessor-journal\t%s\n' \
				"$(decode_journal "$value" | jq -r .runtime.predecessor_plan_sha256)" >>"$FAKE_ACTIONS"
		fi
    if [[ "$name" == */state && -n "${FAKE_FAIL_AFTER_STATE_PHASE:-}" &&
          "$(jq -r '.phase // empty' <<<"$value")" == "$FAKE_FAIL_AFTER_STATE_PHASE" &&
          -n "${FAKE_FAIL_AFTER_STATE_WRITE_ONCE:-}" && ! -e "$FAKE_FAIL_AFTER_STATE_WRITE_ONCE" ]]; then
      : >"$FAKE_FAIL_AFTER_STATE_WRITE_ONCE"
      exit 75
    fi
    ;;
  ssm/delete-parameter)
    name=$(opt --name "$@")
    if ! awk -F '\t' -v n="$name" '$1==n {found=1} END {exit !found}' "$FAKE_PARAMS"; then echo ParameterNotFound >&2; exit 254; fi
    awk -F '\t' -v n="$name" '$1!=n' "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"; mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
    printf 'delete\t%s\n' "$name" >>"$FAKE_ACTIONS"
    ;;
  autoscaling/describe-auto-scaling-groups)
    name=$(opt --auto-scaling-group-names "$@"); query=$(opt --query "$@")
    read -r min max desired instances < <(awk -v n="$name" '$1==n {print $2,$3,$4,$5; found=1} END {exit !found}' "$FAKE_ASGS")
    if [[ "$query" == *MinSize* ]]; then printf '%s\t%s\t%s\t%s\n' "$min" "$max" "$desired" "$instances"; else
      jq -cn --arg name "$name" --argjson min "$min" --argjson max "$max" --argjson desired "$desired" --argjson instances "$instances" \
        '{AutoScalingGroups:[{AutoScalingGroupName:$name,MinSize:$min,MaxSize:$max,DesiredCapacity:$desired,Instances:[range(0;$instances)|{InstanceId:("i-"+(.|tostring)),LifecycleState:"InService",HealthStatus:"Healthy"}]}]}'
    fi
    ;;
  autoscaling/describe-instance-refreshes)
    if [[ " $* " == *' --instance-refresh-ids '* ]]; then
      printf '%s\n' "${FAKE_PERSISTED_REFRESH_STATUS:-Successful}"
    else
      name=$(opt --auto-scaling-group-name "$@")
      if [[ -n "${FAKE_REFRESH_LIST_COUNT_FILE:-}" ]]; then
        count=0; [[ ! -e "$FAKE_REFRESH_LIST_COUNT_FILE" ]] || read -r count <"$FAKE_REFRESH_LIST_COUNT_FILE"
        count=$((count + 1)); printf '%s\n' "$count" >"$FAKE_REFRESH_LIST_COUNT_FILE"
        [[ "$count" != "${FAKE_REFRESH_LIST_FAIL_AT:-0}" ]] || exit 75
      fi
      if [[ "${FAKE_UNOWNED_REFRESH:-}" == true ]]; then
        refresh_id=refresh-unowned
      else
        marker=$(awk '/^owner-(apply|verify)$/ {line=NR} END {print line+0}' "$FAKE_ACTIONS")
        refresh_id=$(awk -F '\t' -v n="$name" -v marker="$marker" \
          'NR>marker && $1=="refresh" && $2==n {v=$3} END {print v}' "$FAKE_ACTIONS")
      fi
      status=${FAKE_REFRESH_STATUS:-InProgress}
      prior=false; [[ "${FAKE_PRIOR_REFRESH:-}" != true ]] || prior=true
      if [[ "${marker:-0}" -gt 0 ]]; then prior=true; fi
      if [[ -n "$refresh_id" ]]; then
        max=200; [[ "${FAKE_REFRESH_BAD_PREFS:-}" != true ]] || max=199
        jq -cn --arg id "$refresh_id" --arg status "$status" --argjson max "$max" \
          --argjson extra "${FAKE_REFRESH_EXTRA:-false}" --argjson prior "$prior" \
          --argjson drop_prior "${FAKE_DROP_PRIOR:-false}" \
          '{InstanceRefreshes:([{InstanceRefreshId:$id,Status:$status,
            Preferences:{MinHealthyPercentage:100,MaxHealthyPercentage:$max,InstanceWarmup:60,SkipMatching:false}}] +
            (if $extra then [{InstanceRefreshId:"refresh-extra",Status:"Successful",
              Preferences:{MinHealthyPercentage:100,MaxHealthyPercentage:200,InstanceWarmup:60,SkipMatching:false}}] else [] end) +
            (if $drop_prior then [range(0;19) | {InstanceRefreshId:("other-"+tostring),Status:"Successful",
              Preferences:{MinHealthyPercentage:100,MaxHealthyPercentage:200,InstanceWarmup:60,SkipMatching:false}}]
             elif $prior then [{InstanceRefreshId:"refresh-prior",Status:"Successful",
              Preferences:{MinHealthyPercentage:100,MaxHealthyPercentage:200,InstanceWarmup:60,SkipMatching:false}}]
             else [] end))}'
      elif [[ "$prior" == true ]]; then
        jq -cn '{InstanceRefreshes:[{InstanceRefreshId:"refresh-prior",Status:"Successful",
          Preferences:{MinHealthyPercentage:100,MaxHealthyPercentage:200,InstanceWarmup:60,SkipMatching:false}}]}'
      else
        printf '{"InstanceRefreshes":[]}\n'
      fi
    fi
    ;;
  autoscaling/start-instance-refresh)
    name=$(opt --auto-scaling-group-name "$@")
    marker=$(awk '/^owner-(apply|verify)$/ {line=NR} END {print line+0}' "$FAKE_ACTIONS")
    refresh_id=refresh-$name
    [[ "$marker" -eq 0 ]] || refresh_id=runtime-refresh-$name
    printf 'refresh\t%s\t%s\n' "$name" "$refresh_id" >>"$FAKE_ACTIONS"
    if [[ -n "${FAKE_START_LOST_ONCE:-}" && ! -e "$FAKE_START_LOST_ONCE" ]]; then
      : >"$FAKE_START_LOST_ONCE"
      exit 75
    fi
    printf '%s\n' "$refresh_id"
    ;;
  *) echo "unexpected aws $svc/$op $*" >&2; exit 99 ;;
esac
EOF

cat >"$WORK/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args="$*"
if [[ "$args" == *'repos/layervai/qurl-integrations-infra/'* ]]; then
  [[ "${GH_TOKEN:-}" == customer-x ]] || { echo "qurl-infra API used the wrong token" >&2; exit 98; }
elif [[ "$args" == *'repos/layervai/qurl-connector/'* ]]; then
  [[ "${GH_TOKEN:-}" == connector-x ]] || { echo "qurl-connector API used the wrong token" >&2; exit 98; }
elif [[ "$args" == *'repos/layervai/nhp/'* ]]; then
  [[ "${GH_TOKEN:-}" == x ]] || { echo "NHP API used a private lifecycle token" >&2; exit 98; }
elif [[ "$args" == *'repos/layervai/qurl-go/'* || "$args" == *'repos/layervai/qurl-integrations/'* ]]; then
  echo "public API was incorrectly called through authenticated gh" >&2; exit 98
else
  [[ "${GH_TOKEN:-}" == x ]] || { echo "NHP API used a private lifecycle token" >&2; exit 98; }
fi
if [[ "$args" == *'/actions/runs/32635672597/attempts/1/jobs?per_page=100'* ]]; then
  [[ "${FAKE_ORIGINAL_JOBS_MUTATION:-}" != unavailable ]] || exit 97
  jq -cn --arg sha "$FAKE_ORIGINAL" --arg mutation "${FAKE_ORIGINAL_JOBS_MUTATION:-}" '
    def job($id;$name;$conclusion):
      {id:$id,name:$name,run_id:32635672597,run_attempt:1,workflow_name:"Build and Deploy NHP",
       head_sha:$sha,head_branch:"main",status:"completed",conclusion:$conclusion};
    ([range(0;26) | job(97000000000+.;("Historical job "+(.|tostring));"success")] +
     [job(97187875176;"Deploy Sandbox cell1 - Blue/Green";"failure"),
      job(97191982507;"Deploy Sandbox - Validate";"cancelled")]) as $base |
    ($base |
      if $mutation == "cell1_missing" then .[26].name="Other cell1 job"
      elif $mutation == "cell1_duplicate" then .[0]=.[26]
      elif $mutation == "cell1_id_duplicate" then .[0].id=.[26].id
      elif $mutation == "cell1_id" then .[26].id=97187875177
      elif $mutation == "cell1_status" then .[26].status="in_progress"
      elif $mutation == "cell1_conclusion" then .[26].conclusion="cancelled"
      elif $mutation == "cell1_source" then .[26].head_sha="9999999999999999999999999999999999999999"
      elif $mutation == "cell1_run" then .[26].run_id=32635672598
      elif $mutation == "cell1_attempt" then .[26].run_attempt=2
      elif $mutation == "cell1_workflow" then .[26].workflow_name="Other workflow"
      elif $mutation == "validation_missing" then .[27].name="Other validation job"
      elif $mutation == "validation_duplicate" then .[0]=.[27]
      elif $mutation == "validation_id_duplicate" then .[0].id=.[27].id
      elif $mutation == "validation_id" then .[27].id=97191982508
      elif $mutation == "validation_status" then .[27].status="in_progress"
      elif $mutation == "validation_conclusion" then .[27].conclusion="skipped"
      elif $mutation == "validation_source" then .[27].head_sha="9999999999999999999999999999999999999999"
      elif $mutation == "validation_run" then .[27].run_id=32635672598
      elif $mutation == "validation_attempt" then .[27].run_attempt=2
      elif $mutation == "validation_workflow" then .[27].workflow_name="Other workflow"
      elif $mutation == "short_page" then .[0:27]
      else . end) as $jobs |
    {total_count:(if $mutation == "wrong_count" then 29 else 28 end),jobs:$jobs}'
elif [[ "$args" == *'/actions/runs/32635672597' ]]; then
  jq -cn --arg sha "$FAKE_ORIGINAL" --arg conclusion "${FAKE_ORIGINAL_CONCLUSION:-cancelled}" \
    --arg mutation "${FAKE_ORIGINAL_RUN_MUTATION:-}" '
    {id:32635672597,run_attempt:1,repository:{full_name:"layervai/nhp"},head_repository:{full_name:"layervai/nhp"},
     head_sha:$sha,head_branch:"main",event:"push",status:"completed",conclusion:$conclusion,path:".github/workflows/build-and-push.yml"} |
    if $mutation == "id" then .id=32635672598
    elif $mutation == "attempt" then .run_attempt=2
    elif $mutation == "repository" then .repository.full_name="other/nhp"
    elif $mutation == "head_repository" then .head_repository.full_name="other/nhp"
    elif $mutation == "source" then .head_sha="9999999999999999999999999999999999999999"
    elif $mutation == "branch" then .head_branch="feature"
    elif $mutation == "event" then .event="workflow_dispatch"
    elif $mutation == "status" then .status="in_progress"
    elif $mutation == "path" then .path=".github/workflows/other.yml"
    elif $mutation == "conclusion" then .conclusion="success"
    elif $mutation == "unrelated_cancelled" then .id=32635679999 | .head_sha="8888888888888888888888888888888888888888"
    else . end'
elif [[ "$args" == *'/actions/runs/900/attempts/2/jobs'* ]]; then
  steps='["Verify exact qurl-integrations source","Verify qurl-connector module selection","Verify qurl-integrations binary attestation","Verify exact repaired NHP deployment authority","Verify exact lifecycle integration-test authorities","Acquire customer Auth0 JWT through public API","Create ordinary customer API key","Run host customer-lifecycle smoke","Run host sibling-continuity journey","Run host CRID lifecycle journey","Run hardened customer-lifecycle smoke","Run hardened sibling-continuity journey","Revoke ordinary customer API key","Verify revoked key rejection after cache horizon","Build immutable durable AOP lifecycle receipt","Upload immutable durable AOP lifecycle receipt"]'
  jq -cn --argjson steps "$steps" '[{jobs:[{name:"Protected qURL sharing sandbox lifecycle",conclusion:"success",steps:[$steps[]|{name:.,conclusion:"success"}]}]}]'
elif [[ "$args" == *'/actions/runs/900/artifacts'* ]]; then
  jq -cn --arg digest "$FAKE_CUSTOMER_ZIP_DIGEST" --arg integrations "$FAKE_INTEGRATIONS" '[{artifacts:[{id:901,name:("durable-aop-lifecycle-receipt-"+$integrations),digest:$digest,expired:false,size_in_bytes:1000,workflow_run:{id:900}}]}]'
elif [[ "$args" == *'/actions/artifacts/901/zip'* ]]; then
  cat "$FAKE_CUSTOMER_ZIP"
elif [[ "$args" == *'/actions/runs/900/attempts/2'* ]]; then
  jq -cn --arg infra "$FAKE_INFRA" '{id:900,repository:{full_name:"layervai/qurl-integrations-infra"},head_repository:{full_name:"layervai/qurl-integrations-infra"},head_sha:$infra,head_branch:"main",event:"workflow_dispatch",run_attempt:2,status:"completed",conclusion:"success",path:".github/workflows/qurl-sharing-sandbox.yml"}'
elif [[ "$args" == *'/git/ref/tags/v0.8.0'* ]]; then
  jq -cn --arg sha "$QURL_GO" '{ref:"refs/tags/v0.8.0",object:{sha:$sha,type:"commit",url:("https://api.github.com/repos/layervai/qurl-go/git/commits/"+$sha)}}'
elif [[ "$args" == *'/actions/runs/32621063743/attempts/1/jobs'* ]]; then
  jq -cn '[{jobs:[{name:"vet + test -race",conclusion:"success",steps:[{name:"go test -race + coverage",conclusion:"success"}]}]}]'
elif [[ "$args" == *'/actions/runs/32621063743/attempts/1'* ]]; then
  jq -cn --arg sha "$QURL_GO" '{id:32621063743,repository:{full_name:"layervai/qurl-go"},head_repository:{full_name:"layervai/qurl-go"},head_sha:$sha,head_branch:"main",event:"push",run_attempt:1,status:"completed",conclusion:"success",path:".github/workflows/ci.yml"}'
elif [[ "$args" == *'/actions/runs/32658570640/attempts/1/jobs'* ]]; then
  jq -cn --arg integrations "$FAKE_INTEGRATIONS" '[{jobs:[{name:"cli / test",head_sha:$integrations,conclusion:"success",steps:[{name:"Run tests with coverage",conclusion:"success"}]}]}]'
elif [[ "$args" == *'/actions/runs/32658570640/attempts/1'* ]]; then
  jq -cn --arg integrations "$FAKE_INTEGRATIONS" '{id:32658570640,repository:{full_name:"layervai/qurl-integrations"},head_repository:{full_name:"layervai/qurl-integrations"},head_sha:$integrations,head_branch:"fix/exact-session-lifecycle-smoke",event:"pull_request",run_attempt:1,status:"completed",conclusion:"failure",path:".github/workflows/cli.yml",pull_requests:[{number:1247,head:{sha:$integrations},base:{sha:"f1aa5795a0d45b73bd06fbf64d1dc179c4dc2a29"}}]}'
elif [[ "$args" == *'/actions/runs/66/artifacts'* ]]; then
  jq -cn --arg name "durable-aop-nhp-deployment-${RUNTIME}" --arg digest "$FAKE_NHP_ZIP_DIGEST" '[{artifacts:[{id:903,name:$name,digest:$digest,expired:false,size_in_bytes:500,workflow_run:{id:66}}]}]'
elif [[ "$args" == *'/actions/artifacts/903/zip'* ]]; then
  cat "$FAKE_NHP_ZIP"
elif [[ "$args" == *'/actions/runs/66/attempts/3'* ]]; then
  jq -cn --arg sha "$FAKE_RECOVERY" '{id:66,repository:{full_name:"layervai/nhp"},head_repository:{full_name:"layervai/nhp"},head_sha:$sha,head_branch:"main",event:"workflow_dispatch",run_attempt:3,status:"completed",conclusion:"success",path:".github/workflows/udp-proof-deployment-manifest.yml"}'
elif [[ "$args" == *'/actions/runs/901/attempts/2/jobs'* ]]; then
  steps='["Authenticate exact deployment manifest","Run exact strict proof inventory","Build allowlisted strict proof evidence","Upload non-secret strict proof evidence","Require complete published proof gate"]'
  jq -cn --argjson steps "$steps" '[{jobs:[{name:"Attended Connector UDP proof (strict)",conclusion:"success",steps:[$steps[]|{name:.,conclusion:"success"}]}]}]'
elif [[ "$args" == *'/actions/runs/901/artifacts'* ]]; then
  jq -cn --arg name "strict-sandbox-proof-pre_removal-${FAKE_CONNECTOR}-2" --arg digest "$FAKE_CONNECTOR_ZIP_DIGEST" \
    --argjson size "$FAKE_CONNECTOR_ZIP_SIZE" '[{artifacts:[{id:902,name:$name,digest:$digest,size_in_bytes:$size,expired:false}]}]'
elif [[ "$args" == *'/actions/artifacts/902/zip'* ]]; then
  cat "$FAKE_CONNECTOR_ZIP"
elif [[ "$args" == *'/actions/runs/901' ]]; then
  jq -cn --arg sha "$FAKE_CONNECTOR" \
    '{repository:{full_name:"layervai/qurl-connector"},head_repository:{full_name:"layervai/qurl-connector"},head_sha:$sha,head_branch:"main",event:"workflow_dispatch",run_attempt:2,status:"completed",conclusion:"success",path:".github/workflows/sandbox-smoke.yml"}'
elif [[ "$args" == *"/git/commits/${FAKE_CONNECTOR_PR}"* ]]; then
  jq -cn --arg sha "$FAKE_CONNECTOR_PR" --arg tree "$FAKE_CONNECTOR_TREE" '{sha:$sha,tree:{sha:$tree}}'
elif [[ "$args" == *"/compare/${FAKE_CONNECTOR_BASE}...${FAKE_CONNECTOR_PR}"* ]]; then
  jq -cn --arg base "$FAKE_CONNECTOR_BASE" --arg head "$FAKE_CONNECTOR_PR" \
    '{status:"ahead",ahead_by:2,behind_by:0,base_commit:{sha:$base},merge_base_commit:{sha:$base},commits:[{sha:$head}]}'
elif [[ "$args" == *"/git/commits/${FAKE_CONNECTOR}"* ]]; then
  jq -cn --arg sha "$FAKE_CONNECTOR" --arg tree "$FAKE_CONNECTOR_TREE" --arg parent "$FAKE_CONNECTOR_BASE" \
    '{sha:$sha,tree:{sha:$tree},parents:[{sha:$parent}],verification:{verified:true,reason:"valid"}}'
elif [[ "$args" == *'/git/ref/heads/main'* ]]; then
  jq -cn --arg sha "$FAKE_CONNECTOR" '{ref:"refs/heads/main",object:{sha:$sha,type:"commit"}}'
elif [[ "$args" == *'/git/trees/'* ]]; then
  target_blob=9de09c2cb4a8a8bf8ba9d4c2bf1bfb5263331e5d
  ac_msghandler_blob=4355055da1fe1392a8e131d37791ecfd10245a45
  [[ "$args" != *"/git/trees/${RUNTIME}"* ]] || ac_msghandler_blob=43417a8ffcee8d4ff54b8016d4f490bd5d500811
  [[ "${FAKE_RUNTIME_MANIFEST_FAILURE:-}" != true ]] || target_blob=2222222222222222222222222222222222222222
  jq -cn --arg target_blob "$target_blob" --arg ac_msghandler_blob "$ac_msghandler_blob" '{tree:[
    {path:"endpoints/ac/httpac.go",type:"blob",sha:"4edf08ab08cc21da891fcfa7e699d3a85c430724"},
    {path:"endpoints/ac/msghandler.go",type:"blob",sha:$ac_msghandler_blob},
    {path:"endpoints/server/ac_session_control_admission.go",type:"blob",sha:"3b0ee01158dcd1f7732aa26ace332adaefdc017e"},
    {path:"endpoints/server/httpserver.go",type:"blob",sha:"b4357fbcce03c07da9b96628141632a456dea499"},
    {path:"endpoints/server/msghandler.go",type:"blob",sha:"52f2d2a01549c1617a10b8bdbfd94bfe6ba686b6"},
    {path:"endpoints/server/session_control_owner_task_snapshot_store.go",type:"blob",sha:"da37520b9a1a75a99c1058e31b0a91151e7ac740"},
    {path:"endpoints/server/session_control_store.go",type:"blob",sha:"806dad6ad032110fd5c320408d287d347e782909"},
    {path:"endpoints/server/session_control_target_attach_store.go",type:"blob",sha:"24ad8fb125140f97d4fdfbd39465df61f79641b8"},
    {path:"endpoints/server/session_control_target_store.go",type:"blob",sha:$target_blob},
    {path:"endpoints/server/session_control_task_runtime.go",type:"blob",sha:"3bac389b4480960ae876c1c1c83308c23950aab5"},
    {path:"endpoints/server/session_control_task_store.go",type:"blob",sha:"8ae42e853c07623809083aace48517ea8bbe52b7"},
    {path:"endpoints/server/udpserver.go",type:"blob",sha:"85a178523f14f11fe01132f2b154783f959c2a6e"}]}'
elif [[ "$args" == *'/actions/runs/32682520698/attempts/1/jobs'* ||
        "$args" == *'/actions/runs/88/attempts/2/jobs'* ||
        "$args" == *'/actions/runs/32656742290/attempts/1/jobs'* ]]; then
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
elif [[ "$args" == *'/actions/runs/32682520698/attempts/1'* ||
        "$args" == *'/actions/runs/88/attempts/2'* ||
        "$args" == *'/actions/runs/32656742290/attempts/1'* ]]; then
  conclusion=success; [[ "${FAKE_BUILD_FAILURE:-}" != true ]] || conclusion=failure
  if [[ "$args" == *'/32656742290/'* ]]; then run=32656742290 attempt=1; sha=$FAKE_REPAIR
  elif [[ "$args" == *'/32682520698/'* ]]; then run=32682520698 attempt=1; sha=$RUNTIME
  else run=88 attempt=2; sha=$FAKE_REPAIR; fi
  jq -cn --arg sha "$sha" --arg conclusion "$conclusion" --argjson run "$run" --argjson attempt "$attempt" \
    '{id:$run,repository:{full_name:"layervai/nhp"},head_repository:{full_name:"layervai/nhp"},head_sha:$sha,head_branch:"main",event:"workflow_dispatch",run_attempt:$attempt,status:"completed",conclusion:$conclusion,path:".github/workflows/build-and-push.yml"}'
else
  echo "unexpected gh $args" >&2
  exit 99
fi
EOF

cat >"$WORK/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ -z ${GH_TOKEN:-} && -z ${GITHUB_TOKEN:-} && -z ${NHP_GH_TOKEN:-} &&
   -z ${CUSTOMER_GH_TOKEN:-} && -z ${PUBLIC_GH_TOKEN:-} &&
   -z ${CUTOVER_CUSTOMER_GH_TOKEN:-} && -z ${CUTOVER_CONNECTOR_GH_TOKEN:-} ]]
for arg in "$@"; do [[ ${arg,,} != *authorization* ]]; done
output= url=; disable=0; fail=0; silent=0; show_error=0; tls=0; proto=0; no_redirect=0; bounded=0
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
    --header) [[ $2 == 'Accept: application/vnd.github+json' || $2 == 'X-GitHub-Api-Version: 2022-11-28' ]]; shift 2 ;;
    --output) output=$2; shift 2 ;;
    --write-out) [[ $2 == '%{http_code}' ]]; shift 2 ;;
    https://api.github.com/*) [[ -z $url ]]; url=$1; shift ;;
    *) echo "unexpected curl fixture argument: $1" >&2; exit 98 ;;
  esac
done
[[ $disable == 1 && $fail == 1 && $silent == 1 && $show_error == 1 && $tls == 1 &&
   $proto == 1 && $no_redirect == 1 && $bounded == 1 && -n $output && -n $url ]]
case "${url#https://api.github.com/}" in
  repos/layervai/qurl-go/git/ref/tags/v0.8.0)
    jq -cn --arg sha "$QURL_GO" '{ref:"refs/tags/v0.8.0",object:{sha:$sha,type:"commit",url:("https://api.github.com/repos/layervai/qurl-go/git/commits/"+$sha)}}' >"$output"
    ;;
  repos/layervai/qurl-go/actions/runs/32621063743/attempts/1)
    jq -cn --arg sha "$QURL_GO" '{id:32621063743,repository:{full_name:"layervai/qurl-go"},head_repository:{full_name:"layervai/qurl-go"},head_sha:$sha,head_branch:"main",event:"push",run_attempt:1,status:"completed",conclusion:"success",path:".github/workflows/ci.yml"}' >"$output"
    ;;
  repos/layervai/qurl-go/actions/runs/32621063743/attempts/1/jobs?per_page=100)
    jq -cn '{total_count:1,jobs:[{name:"vet + test -race",conclusion:"success",steps:[{name:"go test -race + coverage",conclusion:"success"}]}]}' >"$output"
    ;;
  repos/layervai/qurl-integrations/actions/runs/32658570640/attempts/1)
    jq -cn --arg integrations "$FAKE_INTEGRATIONS" '{id:32658570640,repository:{full_name:"layervai/qurl-integrations"},head_repository:{full_name:"layervai/qurl-integrations"},head_sha:$integrations,head_branch:"fix/exact-session-lifecycle-smoke",event:"pull_request",run_attempt:1,status:"completed",conclusion:"failure",path:".github/workflows/cli.yml",pull_requests:[{number:1247,head:{sha:$integrations},base:{sha:"f1aa5795a0d45b73bd06fbf64d1dc179c4dc2a29"}}]}' >"$output"
    ;;
  repos/layervai/qurl-integrations/actions/runs/32658570640/attempts/1/jobs?per_page=100)
    jq -cn --arg integrations "$FAKE_INTEGRATIONS" '{total_count:1,jobs:[{name:"cli / test",head_sha:$integrations,conclusion:"success",steps:[{name:"Run tests with coverage",conclusion:"success"}]}]}' >"$output"
    ;;
  *) echo "unexpected public API route: $url" >&2; exit 98 ;;
esac
printf 200
EOF

cat >"$WORK/helpers/provenance" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${FAKE_PROVENANCE_FAILURE:-}" != true ]] || exit 73
[[ $# == 5 && "$3" =~ ^[1-9][0-9]*$ && "$4" =~ ^[1-9][0-9]*$ ]]
printf '%s\t%s\t%s\t%s\t%s\n' "$@" >>"$FAKE_PROVENANCE_CALLS"
call_count=$(wc -l <"$FAKE_PROVENANCE_CALLS" | tr -d ' ')
[[ "${FAKE_PROVENANCE_FAILURE_AT:-}" != "$call_count" ]] || exit 73
if [[ "$2" == "$RUNTIME" && "$1" == layerv/nhp-server ]]; then
  digest=$RUNTIME_SERVER_DIGEST; [[ "$3" == 32682520698 && "$4" == 1 ]]
elif [[ "$2" == "$RUNTIME" && "$1" == layerv/nhp-ac ]]; then
  digest=$RUNTIME_AC_DIGEST; [[ "$3" == 32682520698 && "$4" == 1 ]]
elif [[ "$2" == "$FAKE_REPAIR" && "$1" == layerv/nhp-server ]]; then digest=$FAKE_SERVER_DIGEST
elif [[ "$2" == "$FAKE_REPAIR" && "$1" == layerv/nhp-ac ]]; then digest=$FAKE_AC_DIGEST
else exit 72
fi
[[ "$5" == "$digest" ]]
printf 'v1|%s|%s|%s\n' "$2" "$1" "$digest"
EOF
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$WORK/helpers/verify"
cat >"$WORK/helpers/wait" <<'EOF'
#!/usr/bin/env bash
wait_for_instance_refresh() {
  if [[ -n "${FAKE_WAIT_FAIL_ONCE:-}" && ! -e "$FAKE_WAIT_FAIL_ONCE" ]]; then
    : >"$FAKE_WAIT_FAIL_ONCE"
    return 74
  fi
  return 0
}
EOF
cat >"$WORK/helpers/wait-with-production-metric-source" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# Production wait-for-instance-refresh.sh sources this dependency. The schema-3
# controller then sources the wait helper once for each of cell0, cell1, and AC
# in the same strict shell. Keep this fixture fast while preserving that exact
# repeated-source boundary.
source "${FAKE_METRIC_HELPER:?}"
printf 'metric-wait-source\n' >>"$FAKE_ACTIONS"
wait_for_instance_refresh() {
  printf 'metric-wait-call\t%s\n' "$1" >>"$FAKE_ACTIONS"
  if [[ -n "${FAKE_METRIC_WAIT_FAIL_ASG:-}" && "$1" == "$FAKE_METRIC_WAIT_FAIL_ASG" &&
        -n "${FAKE_METRIC_WAIT_FAIL_ONCE:-}" && ! -e "$FAKE_METRIC_WAIT_FAIL_ONCE" ]]; then
    : >"$FAKE_METRIC_WAIT_FAIL_ONCE"
    return 75
  fi
}
EOF
cat >"$WORK/helpers/owner" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
digest=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
case "$1" in
  plan)
    printf 'owner-plan\n' >>"$FAKE_ACTIONS"
    shift
    source= client= table= region= timestamp=
    while (( $# )); do
      case "$1" in
        --source-sha) source=$2; shift 2 ;;
        --client-id) client=$2; shift 2 ;;
        --table) table=$2; shift 2 ;;
        --region) region=$2; shift 2 ;;
        --provisioned-at) timestamp=$2; shift 2 ;;
        *) exit 98 ;;
      esac
    done
    jq -cn --arg client "$client" --arg subject "${client}@clients" \
      --arg email "${client,,}-clients@machine.notify.layerv.xyz" --arg table "$table" \
      --arg region "$region" --arg source "$source" --arg timestamp "$timestamp" --arg digest "$digest" \
      '{schema:"layerv.durable-aop-customer-owner-intent.v1",action:"create",before_row_sha256:"absent",
        client_id:$client,subject:$subject,email:$email,table:$table,region:$region,source_sha:$source,
        provisioned_at:$timestamp,expected_row_sha256:$digest,expected_created_at:$timestamp,
        expected_updated_at:$timestamp,expected_usage:"0",expected_assigned_cell_id:""}'
    ;;
  apply|verify|verify-current)
    mode=$1; shift
    printf 'owner-%s\n' "$mode" >>"$FAKE_ACTIONS"
    [[ "$1" == --intent-json && -n "$2" ]]
    digest=$(jq -er .expected_row_sha256 <<<"$2")
		[[ "$digest" == dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd ||
		   "$digest" == cac7d0380fc97736575d2701ef0ccc08927b511cd8646c83785c1be8b30f1b8b ]]
    if [[ "$mode" == apply && -n "${FAKE_OWNER_APPLY_FAIL_ONCE:-}" && ! -e "$FAKE_OWNER_APPLY_FAIL_ONCE" ]]; then
      : >"$FAKE_OWNER_APPLY_FAIL_ONCE"
      exit 75
    fi
    printf '%s\n' "$digest"
    ;;
  *) exit 98 ;;
esac
EOF
chmod +x "$WORK/bin/"* "$WORK/helpers/"*

seed() {
  : >"$FAKE_ACTIONS"
  : >"$FAKE_PROVENANCE_CALLS"
  rm -f "$FAKE_STATE_VERSION_FILE" "$FAKE_JOURNAL_VERSION_FILE" "$FAKE_PREDECESSOR_ORPHAN_VERSION_FILE"
  jq -cn --arg image "$ORIGINAL" --arg owner "$OWNER" '
    {schema:2,image:$image,orchestrator_sha:$image,lock_owner:$owner,phase:"old_servers_terminated",
     ac:{old_color:"blue",new_color:"green",old_asg:"layerv-nhp-sandbox-ac",new_asg:"layerv-nhp-sandbox-ac-green",old_min:3,old_max:3,old_desired:3,new_attestation:("v2|durable-aop-v1|"+$image+"|layerv/nhp-ac|sha256:2e38672ef7680c60521694c3f2a59e9a74ed8f2d56bfe1fb41a97f3040b4e279|layerv-nhp-sandbox-ac-green")},
     cell0:{old_color:"green",new_color:"blue",old_asg:"layerv-nhp-sandbox-server-green",new_asg:"layerv-nhp-sandbox-server",new_attestation:("v2|durable-aop-v1|"+$image+"|layerv/nhp-server|sha256:94a5d91373ca261e4edfffc2ca743768b7da573bacd9dadac87c2dd7d0cbc1f4|layerv-nhp-sandbox-server")},
     cell1:{old_color:"blue",new_color:"green",old_asg:"layerv-nhp-sandbox-cell1-server",new_asg:"layerv-nhp-sandbox-cell1-server-green",new_attestation:("v2|durable-aop-v1|"+$image+"|layerv/nhp-server|sha256:94a5d91373ca261e4edfffc2ca743768b7da573bacd9dadac87c2dd7d0cbc1f4|layerv-nhp-sandbox-cell1-server-green")}}' >"$WORK/state"
  [[ "$(printf '%s' "$(jq -cS . "$WORK/state")" | sha256sum | awk '{print $1}')" == "$ORIGINAL_STATE_DIGEST" ]]
  lock=$(jq -cn --arg owner "$OWNER" --arg image "$ORIGINAL" '{schema:1,kind:"durable-aop-cutover-recovery",owner:$owner,image:$image,orchestrator_sha:$image,created_at:1787485146,expires_at:253402300799}')
  [[ "$(printf '%s' "$(jq -cS . <<<"$lock")" | sha256sum | awk '{print $1}')" == "$ORIGINAL_LOCK_DIGEST" ]]
  cp "$WORK/state" "$FAKE_ORIGINAL_STATE_RECORD"
  printf '%s\n' "$lock" >"$FAKE_ORIGINAL_LOCK_RECORD"
  {
    printf '/sandbox/nhp/cutovers/durable-aop-v1/state\t%s\n' "$(cat "$WORK/state")"
    printf '/layerv-nhp-sandbox/qurl-live-env-lock\t%s\n' "$lock"
    printf '/sandbox/nhp/ac/active-color\tgreen\n/sandbox/nhp/ac/green-asg-name\tlayerv-nhp-sandbox-ac-green\n/sandbox/nhp/ac/green-image-tag\t%s\n' "$ORIGINAL"
    printf '/sandbox/nhp/ac/green-protocol-profile\tv1|durable-aop-v1|%s\n' "$ORIGINAL"
    printf '/sandbox/nhp/ac/green-prepared-slot-attestation\tv2|durable-aop-v1|%s|layerv/nhp-ac|sha256:2e38672ef7680c60521694c3f2a59e9a74ed8f2d56bfe1fb41a97f3040b4e279|layerv-nhp-sandbox-ac-green\n' "$ORIGINAL"
    printf '/sandbox/nhp/server/active-color\tblue\n/sandbox/nhp/server/asg-name\tlayerv-nhp-sandbox-server\n/sandbox/nhp/server/image-tag\t%s\n' "$ORIGINAL"
    printf '/sandbox/nhp/server/blue-protocol-profile\tv1|durable-aop-v1|%s\n' "$ORIGINAL"
    printf '/sandbox/nhp/server/blue-prepared-slot-attestation\tv2|durable-aop-v1|%s|layerv/nhp-server|sha256:94a5d91373ca261e4edfffc2ca743768b7da573bacd9dadac87c2dd7d0cbc1f4|layerv-nhp-sandbox-server\n' "$ORIGINAL"
    printf '/sandbox-cell1/nhp/server/active-color\tgreen\n/sandbox-cell1/nhp/server/green-asg-name\tlayerv-nhp-sandbox-cell1-server-green\n/sandbox-cell1/nhp/server/green-image-tag\t%s\n' "$ORIGINAL"
    printf '/sandbox-cell1/nhp/server/green-protocol-profile\tv1|durable-aop-v1|%s\n' "$ORIGINAL"
    printf '/sandbox-cell1/nhp/server/green-prepared-slot-attestation\tv2|durable-aop-v1|%s|layerv/nhp-server|sha256:94a5d91373ca261e4edfffc2ca743768b7da573bacd9dadac87c2dd7d0cbc1f4|layerv-nhp-sandbox-cell1-server-green\n' "$ORIGINAL"
  } >"$FAKE_PARAMS"
  printf 'layerv-nhp-sandbox-ac 0 0 0 0\nlayerv-nhp-sandbox-server-green 0 0 0 0\nlayerv-nhp-sandbox-cell1-server 0 0 0 0\nlayerv-nhp-sandbox-ac-green 1 4 1 1\nlayerv-nhp-sandbox-server 1 4 1 1\nlayerv-nhp-sandbox-cell1-server-green 1 4 1 1\n' >"$FAKE_ASGS"
}

set_fixture_param() {
  local name=$1 value=$2
  awk -F '\t' -v n="$name" '$1!=n' "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"
  printf '%s\t%s\n' "$name" "$value" >>"$FAKE_PARAMS.tmp"
  mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
}

decode_fixture_journal() {
	python3 -c 'import base64,gzip,json,sys; v=json.load(sys.stdin); sys.stdout.buffer.write(gzip.decompress(base64.b64decode(v["payload"],validate=True)))'
}

encode_fixture_journal() {
	python3 -c 'import base64,gzip,json,sys; raw=sys.stdin.buffer.read(); json.loads(raw); print(json.dumps({"encoding":"gzip-base64","payload":base64.b64encode(gzip.compress(raw,9,mtime=0)).decode(),"schema":"layerv.durable-aop-stale-target-journal-envelope.v1"},sort_keys=True,separators=(",",":")))'
}

read_fixture_journal() {
	awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement" {print substr($0,index($0,"\t")+1)}' \
		"$FAKE_PARAMS" | decode_fixture_journal
}

seed_live_orchestrator_handoff() {
  local lock state canonical
  seed
  lock=$(cat "$FAKE_ORIGINAL_LOCK_RECORD")
  state=$(jq -cn --argjson lock "$lock" --arg repair "$REPAIR" --arg predecessor "$RECOVERY_PREDECESSOR" \
    --arg server_digest "$SERVER_DIGEST" --arg ac_digest "$AC_DIGEST" \
    --arg state_digest "$ORIGINAL_STATE_DIGEST" --arg lock_digest "$ORIGINAL_LOCK_DIGEST" '
    {schema:3,phase:"repaired",
     original:{state_version:7,state_sha256:$state_digest,lock:$lock,lock_version:2,lock_sha256:$lock_digest},
     repair:{orchestrator_sha:$predecessor,source_sha:$repair,build_run_id:"32656742290",build_run_attempt:"1",
       runtime_manifest:"2895963905453d61874858171529968efe8e18e5450d41842854fd2784d1ec78",
       server_provenance:("v1|"+$repair+"|layerv/nhp-server|"+$server_digest),
       ac_provenance:("v1|"+$repair+"|layerv/nhp-ac|"+$ac_digest),
       cell0_attestation:("v2|durable-aop-v1|"+$repair+"|layerv/nhp-server|"+$server_digest+"|layerv-nhp-sandbox-server"),
       cell1_attestation:("v2|durable-aop-v1|"+$repair+"|layerv/nhp-server|"+$server_digest+"|layerv-nhp-sandbox-cell1-server-green"),
       ac_attestation:("v2|durable-aop-v1|"+$repair+"|layerv/nhp-ac|"+$ac_digest+"|layerv-nhp-sandbox-ac-green"),
       cell0_refresh_id:"ea9dae3d-22f8-478e-a9ec-91eb9b9f53fb",
       cell1_refresh_id:"dc5ab358-ef4e-45a8-bf81-d18112a2ce9c",
       ac_refresh_id:"b58f804d-6ed2-4f15-90df-749e2e0f93fb",
       customer_lifecycle:"",connector_lifecycle:""}}')
  canonical=$(jq -cS . <<<"$state")
  [[ "$(printf '%s' "$canonical" | sha256sum | awk '{print $1}')" == "$RECOVERY_HANDOFF_STATE_DIGEST" ]]
  set_fixture_param /sandbox/nhp/cutovers/durable-aop-v1/state "$canonical"
  set_fixture_param /sandbox/nhp/server/image-tag "$REPAIR"
  set_fixture_param /sandbox/nhp/server/blue-protocol-profile "v1|durable-aop-v1|${REPAIR}"
  set_fixture_param /sandbox/nhp/server/blue-prepared-slot-attestation \
    "v2|durable-aop-v1|${REPAIR}|layerv/nhp-server|${SERVER_DIGEST}|layerv-nhp-sandbox-server"
  set_fixture_param /sandbox-cell1/nhp/server/green-image-tag "$REPAIR"
  set_fixture_param /sandbox-cell1/nhp/server/green-protocol-profile "v1|durable-aop-v1|${REPAIR}"
  set_fixture_param /sandbox-cell1/nhp/server/green-prepared-slot-attestation \
    "v2|durable-aop-v1|${REPAIR}|layerv/nhp-server|${SERVER_DIGEST}|layerv-nhp-sandbox-cell1-server-green"
  set_fixture_param /sandbox/nhp/ac/green-image-tag "$REPAIR"
  set_fixture_param /sandbox/nhp/ac/green-protocol-profile "v1|durable-aop-v1|${REPAIR}"
  set_fixture_param /sandbox/nhp/ac/green-prepared-slot-attestation \
    "v2|durable-aop-v1|${REPAIR}|layerv/nhp-ac|${AC_DIGEST}|layerv-nhp-sandbox-ac-green"
  printf '20\n' >"$FAKE_STATE_VERSION_FILE"
}

seed_live_stale_retirement_handoff() {
  local lock state canonical
  seed
  lock=$(cat "$FAKE_ORIGINAL_LOCK_RECORD")
  state=$(jq -cn --argjson lock "$lock" --arg repair "$REPAIR" --arg predecessor "$STALE_RETIREMENT_PREDECESSOR" \
    --arg server_digest "$SERVER_DIGEST" --arg ac_digest "$AC_DIGEST" \
    --arg state_digest "$ORIGINAL_STATE_DIGEST" --arg lock_digest "$ORIGINAL_LOCK_DIGEST" '
    {schema:3,phase:"repaired",
     original:{state_version:7,state_sha256:$state_digest,lock:$lock,lock_version:2,lock_sha256:$lock_digest},
     repair:{orchestrator_sha:$predecessor,source_sha:$repair,build_run_id:"32656742290",build_run_attempt:"1",
       runtime_manifest:"2895963905453d61874858171529968efe8e18e5450d41842854fd2784d1ec78",
       server_provenance:("v1|"+$repair+"|layerv/nhp-server|"+$server_digest),
       ac_provenance:("v1|"+$repair+"|layerv/nhp-ac|"+$ac_digest),
       cell0_attestation:("v2|durable-aop-v1|"+$repair+"|layerv/nhp-server|"+$server_digest+"|layerv-nhp-sandbox-server"),
       cell1_attestation:("v2|durable-aop-v1|"+$repair+"|layerv/nhp-server|"+$server_digest+"|layerv-nhp-sandbox-cell1-server-green"),
       ac_attestation:("v2|durable-aop-v1|"+$repair+"|layerv/nhp-ac|"+$ac_digest+"|layerv-nhp-sandbox-ac-green"),
       cell0_refresh_id:"ea9dae3d-22f8-478e-a9ec-91eb9b9f53fb",
       cell1_refresh_id:"dc5ab358-ef4e-45a8-bf81-d18112a2ce9c",
       ac_refresh_id:"b58f804d-6ed2-4f15-90df-749e2e0f93fb",customer_lifecycle:"",connector_lifecycle:"",
       owner:{status:"ready",intent:{schema:"layerv.durable-aop-customer-owner-intent.v1",action:"create",
         before_row_sha256:"absent",client_id:"oScYkXhLitBPO6gBjxo4Rwyw37AdoNPy",
         subject:"oScYkXhLitBPO6gBjxo4Rwyw37AdoNPy@clients",
         email:"oscykxhlitbpo6gbjxo4rwyw37adonpy-clients@machine.notify.layerv.xyz",
         table:"layerv-nhp-sandbox-control-qurl-customers",region:"us-east-2",source_sha:$repair,
         provisioned_at:"2026-08-24T00:38:03Z",
         expected_row_sha256:"cac7d0380fc97736575d2701ef0ccc08927b511cd8646c83785c1be8b30f1b8b",
         expected_created_at:"2026-08-24T00:38:03Z",expected_updated_at:"2026-08-24T00:38:03Z",
         expected_usage:"0",expected_assigned_cell_id:""}}}}')
  canonical=$(jq -cS . <<<"$state")
  [[ "$(printf '%s' "$canonical" | sha256sum | awk '{print $1}')" == "$STALE_RETIREMENT_STATE_DIGEST" ]]
  set_fixture_param /sandbox/nhp/cutovers/durable-aop-v1/state "$canonical"
  set_fixture_param /sandbox/nhp/server/image-tag "$REPAIR"
  set_fixture_param /sandbox/nhp/server/blue-protocol-profile "v1|durable-aop-v1|${REPAIR}"
  set_fixture_param /sandbox/nhp/server/blue-prepared-slot-attestation \
    "v2|durable-aop-v1|${REPAIR}|layerv/nhp-server|${SERVER_DIGEST}|layerv-nhp-sandbox-server"
  set_fixture_param /sandbox-cell1/nhp/server/green-image-tag "$REPAIR"
  set_fixture_param /sandbox-cell1/nhp/server/green-protocol-profile "v1|durable-aop-v1|${REPAIR}"
  set_fixture_param /sandbox-cell1/nhp/server/green-prepared-slot-attestation \
    "v2|durable-aop-v1|${REPAIR}|layerv/nhp-server|${SERVER_DIGEST}|layerv-nhp-sandbox-cell1-server-green"
  set_fixture_param /sandbox/nhp/ac/green-image-tag "$REPAIR"
  set_fixture_param /sandbox/nhp/ac/green-protocol-profile "v1|durable-aop-v1|${REPAIR}"
  set_fixture_param /sandbox/nhp/ac/green-prepared-slot-attestation \
    "v2|durable-aop-v1|${REPAIR}|layerv/nhp-ac|${AC_DIGEST}|layerv-nhp-sandbox-ac-green"
  printf '22\n' >"$FAKE_STATE_VERSION_FILE"
}

invoke() {
  PATH="$WORK/bin:$PATH" AWS_REGION=us-east-2 GH_TOKEN=x CUTOVER_CUSTOMER_GH_TOKEN=customer-x \
    CUTOVER_CONNECTOR_GH_TOKEN=connector-x GITHUB_REPOSITORY=layervai/nhp \
    CUTOVER_RECOVERY_ORCHESTRATOR_SHA=${INVOKE_RECOVERY_SHA:-$RECOVERY} \
    CUTOVER_VERIFY_PROVENANCE_SCRIPT=$WORK/helpers/provenance CUTOVER_VERIFY_ASG_HEALTH_SCRIPT=$WORK/helpers/verify \
    CUTOVER_VERIFY_LIFECYCLE_SCRIPT=$WORK/helpers/verify CUTOVER_VERIFY_TOPOLOGY_SCRIPT=$WORK/helpers/verify \
    CUTOVER_OWNER_PROJECTOR_SCRIPT=$WORK/helpers/owner \
    CUTOVER_STALE_TARGET_RETIRE_SCRIPT=$WORK/helpers/stale-retire \
    FAKE_METRIC_HELPER=$ROOT/.github/scripts/emit-deployment-window-metric.sh \
    CUTOVER_WAIT_REFRESH_SCRIPT=${FAKE_WAIT_HELPER:-$WORK/helpers/wait} CUTOVER_STABILITY_SECONDS=1 \
    CUTOVER_CUSTOMER_LIFECYCLE_RUN_ID=${LIFECYCLE_RUN_ID:-} CUTOVER_CUSTOMER_LIFECYCLE_RUN_ATTEMPT=${LIFECYCLE_RUN_ATTEMPT:-} \
    CUTOVER_CUSTOMER_LIFECYCLE_INFRA_SHA=${LIFECYCLE_INFRA_SHA:-} CUTOVER_CUSTOMER_LIFECYCLE_INTEGRATIONS_SHA=${LIFECYCLE_INTEGRATIONS_SHA:-} \
    CUTOVER_CONNECTOR_LIFECYCLE_RUN_ID=${CONNECTOR_RUN_ID:-} CUTOVER_CONNECTOR_LIFECYCLE_RUN_ATTEMPT=${CONNECTOR_RUN_ATTEMPT:-} \
    CUTOVER_CONNECTOR_LIFECYCLE_SOURCE_SHA=${CONNECTOR_SOURCE_SHA:-} CUTOVER_CONNECTOR_NHP_CONTROLLER_RUN_ID=${CONNECTOR_CONTROLLER_RUN_ID:-} \
    CUTOVER_CONNECTOR_PR_HEAD_SHA=${CONNECTOR_PR_HEAD_SHA:-} \
    CUTOVER_CONNECTOR_NHP_CONTROLLER_RUN_ATTEMPT=${CONNECTOR_CONTROLLER_RUN_ATTEMPT:-} \
    "$SCRIPT" "$REPAIR" "${INVOKE_BUILD_RUN_ID:-88}" "${INVOKE_BUILD_RUN_ATTEMPT:-2}" ADOPT_EXACT_E9_DURABLE_AOP_REPAIR
}

# The exact production incident ended as cancelled because one immutable cell1
# deploy job failed and the downstream validation job was cancelled. Every
# missing, ambiguous, or mutated field in that two-job authority fails before
# the controller reads or writes AWS state.
for mutation in id attempt repository head_repository source branch event status path conclusion unrelated_cancelled; do
  seed
  export FAKE_ORIGINAL_RUN_MUTATION=$mutation
  if invoke >/dev/null 2>&1; then
    echo "cancelled original run accepted mutated run authority: $mutation" >&2
    exit 1
  fi
  if [[ -s "$FAKE_ACTIONS" ]]; then
    echo "cancelled original run envelope mutation reached AWS: $mutation" >&2
    exit 1
  fi
  unset FAKE_ORIGINAL_RUN_MUTATION
done

for mutation in \
  cell1_missing cell1_duplicate cell1_id_duplicate cell1_id cell1_status cell1_conclusion cell1_source \
  cell1_run cell1_attempt cell1_workflow validation_missing validation_duplicate \
  validation_id_duplicate validation_id validation_status validation_conclusion validation_source validation_run \
  validation_attempt validation_workflow short_page wrong_count unavailable; do
  seed
  export FAKE_ORIGINAL_JOBS_MUTATION=$mutation
  if invoke >/dev/null 2>&1; then
    echo "cancelled original run accepted mutated jobs authority: $mutation" >&2
    exit 1
  fi
  if [[ -s "$FAKE_ACTIONS" ]]; then
    echo "cancelled original run mutation reached AWS: $mutation" >&2
    exit 1
  fi
  unset FAKE_ORIGINAL_JOBS_MUTATION
done

# The pre-existing exact failure and timeout classifications do not depend on
# the cancelled-run jobs exception. Make that page unavailable and prove both
# paths advance to the separate build-only authority check.
for conclusion in failure timed_out; do
  seed
  export FAKE_ORIGINAL_CONCLUSION=$conclusion FAKE_ORIGINAL_JOBS_MUTATION=unavailable FAKE_BUILD_FAILURE=true
  output=$(invoke 2>&1 || true)
  grep -q 'repair build is not the exact successful attended main workflow attempt' <<<"$output" || {
    echo "exact $conclusion original run did not retain its existing classification" >&2
    exit 1
  }
  [[ ! -s "$FAKE_ACTIONS" ]]
  unset FAKE_ORIGINAL_CONCLUSION FAKE_ORIGINAL_JOBS_MUTATION FAKE_BUILD_FAILURE
done

# Lifecycle selectors are classified before any GitHub or AWS read. All four
# may be omitted for the repaired+owner_ready checkpoint; otherwise each pair
# must be complete and every value must be a positive integer.
for selector_case in partial_customer missing_connector malformed_customer malformed_connector zero_attempt; do
  seed
  unset LIFECYCLE_RUN_ID LIFECYCLE_RUN_ATTEMPT CONNECTOR_RUN_ID CONNECTOR_RUN_ATTEMPT
  case "$selector_case" in
    partial_customer) export LIFECYCLE_RUN_ID=900 ;;
    missing_connector) export LIFECYCLE_RUN_ID=900 LIFECYCLE_RUN_ATTEMPT=2 ;;
    malformed_customer)
      export LIFECYCLE_RUN_ID=nope LIFECYCLE_RUN_ATTEMPT=2 CONNECTOR_RUN_ID=901 CONNECTOR_RUN_ATTEMPT=2 ;;
    malformed_connector)
      export LIFECYCLE_RUN_ID=900 LIFECYCLE_RUN_ATTEMPT=2 CONNECTOR_RUN_ID=x CONNECTOR_RUN_ATTEMPT=2 ;;
    zero_attempt)
      export LIFECYCLE_RUN_ID=900 LIFECYCLE_RUN_ATTEMPT=0 CONNECTOR_RUN_ID=901 CONNECTOR_RUN_ATTEMPT=2 ;;
  esac
  if invoke >/dev/null 2>&1; then
    echo "malformed lifecycle selector tuple was accepted: $selector_case" >&2
    exit 1
  fi
  [[ ! -s "$FAKE_ACTIONS" ]]
done
unset LIFECYCLE_RUN_ID LIFECYCLE_RUN_ATTEMPT CONNECTOR_RUN_ID CONNECTOR_RUN_ATTEMPT

# The second live stop is schema-3 SSM v20 at repaired with all three exact
# fleet attestations and no owner authority. Its one reviewed successor may
# resume only those bytes. The first owner-preparing write must make the exact
# v20 -> v21 transition and install the successor SHA before any customer-row
# mutation is attempted.
export INVOKE_BUILD_RUN_ID=32656742290 INVOKE_BUILD_RUN_ATTEMPT=1
seed_live_orchestrator_handoff
export FAKE_OWNER_APPLY_FAIL_ONCE=$WORK/live-owner-apply-failed
if handoff_output=$(invoke 2>&1); then
  echo "live predecessor handoff unexpectedly passed the injected owner apply stop" >&2
  exit 1
fi
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$(jq -r .phase <<<"$state")" == repaired && "$(jq -r .repair.owner.status <<<"$state")" == preparing ]] || {
  echo "live predecessor handoff stopped before the committed v21 owner boundary: $handoff_output" >&2
  exit 1
}
[[ "$(jq -r .repair.orchestrator_sha <<<"$state")" == "$RECOVERY" ]]
[[ "$(jq -r .repair.cell1_attestation <<<"$state")" == \
  "v2|durable-aop-v1|${REPAIR}|layerv/nhp-server|${SERVER_DIGEST}|layerv-nhp-sandbox-cell1-server-green" ]]
[[ "$(jq -r .repair.ac_attestation <<<"$state")" == \
  "v2|durable-aop-v1|${REPAIR}|layerv/nhp-ac|${AC_DIGEST}|layerv-nhp-sandbox-ac-green" ]]
[[ "$(cat "$FAKE_STATE_VERSION_FILE")" == 21 ]]
intent_before=$(jq -cS .repair.owner.intent <<<"$state")
[[ "$(grep -c '^owner-plan$' "$FAKE_ACTIONS")" == 1 ]]
if grep -q $'^refresh\t' "$FAKE_ACTIONS"; then
  echo "repaired v20 handoff repeated a completed fleet refresh" >&2
  exit 1
fi
grep -q '/layerv-nhp-sandbox/qurl-live-env-lock' "$FAKE_PARAMS"
if grep -q '/sandbox/nhp/minimum-protocol-profile' "$FAKE_PARAMS"; then exit 1; fi
unset FAKE_OWNER_APPLY_FAIL_ONCE
output=$(invoke)
grep -q 'reached repaired+owner_ready' <<<"$output"
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$(jq -r .phase <<<"$state")" == repaired ]]
[[ "$(jq -r .repair.orchestrator_sha <<<"$state")" == "$RECOVERY" ]]
[[ "$(jq -r .repair.owner.status <<<"$state")" == ready ]]
[[ "$(jq -cS .repair.owner.intent <<<"$state")" == "$intent_before" ]]
[[ "$(cat "$FAKE_STATE_VERSION_FILE")" -gt 22 ]]
journal=$(read_fixture_journal)
[[ "$(jq -r .status <<<"$journal")" == complete ]]
[[ "$(grep -c '^owner-plan$' "$FAKE_ACTIONS")" == 1 ]]
[[ "$(grep -c '^snapshot-predecessors$' "$FAKE_ACTIONS")" == 1 ]]
[[ "$(grep -c $'^retire-predecessor\t' "$FAKE_ACTIONS")" == 1 ]]
journal_line=$(grep -n $'^put-predecessor-journal\t' "$FAKE_ACTIONS" | cut -d: -f1)
ac_refresh_line=$(grep -n $'^refresh\tlayerv-nhp-sandbox-ac-green\t' "$FAKE_ACTIONS" | cut -d: -f1)
predecessor_retire_line=$(grep -n $'^retire-predecessor\t' "$FAKE_ACTIONS" | cut -d: -f1)
[[ -n "$journal_line" && "$journal_line" -lt "$ac_refresh_line" && "$ac_refresh_line" -lt "$predecessor_retire_line" ]] || {
	echo "predecessor retirement was not ordered after its durable plan and AC refresh" >&2
	exit 1
}
grep -q '/layerv-nhp-sandbox/qurl-live-env-lock' "$FAKE_PARAMS"
if grep -q '/sandbox/nhp/minimum-protocol-profile' "$FAKE_PARAMS"; then exit 1; fi
cp "$FAKE_PARAMS" "$WORK/params.handoff-current"
cp "$FAKE_STATE_VERSION_FILE" "$WORK/state-version.handoff-current"
cp "$FAKE_JOURNAL_VERSION_FILE" "$WORK/journal-version.handoff-current"

# Exact successor replay is allowed. A changed predecessor ledger, a v20 state
# that self-asserts the successor, or any third controller source fails before
# a state write, fleet action, or owner mutation.
: >"$FAKE_ACTIONS"
invoke >/dev/null
if grep -Eq $'^(put|delete|refresh|owner-plan|owner-apply|snapshot-predecessors|retire-predecessor)\t?' "$FAKE_ACTIONS"; then
  echo "exact successor replay performed a mutation" >&2
  exit 1
fi

# The AC intent commits the canonical predecessor-plan digest before the AC
# refresh. A caller-selected extra fence cannot be added later even if its
# plan, per-fence digest, and pending ledger entry are made self-consistent:
# the precommitted AC intent no longer matches and rejection occurs before any
# resnapshot or retirement call.
cp "$WORK/params.handoff-current" "$FAKE_PARAMS"
cp "$WORK/journal-version.handoff-current" "$FAKE_JOURNAL_VERSION_FILE"
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
journal=$(read_fixture_journal)
mutated=$(jq -c '
  (.incident_plan.targets[0] |
    .id="predecessor-2") as $extra |
  .runtime.predecessor_plan.targets += [$extra] |
  .runtime.predecessor_targets +=
    [{id:$extra.id,fence_sha256:$extra.fence_sha256,status:"pending"}]
' <<<"$journal")
plan=$(jq -cS .runtime.predecessor_plan <<<"$mutated")
mutated=$(jq -cS --arg digest "$(printf '%s' "$plan" | sha256sum | awk '{print $1}')" \
  '.runtime.predecessor_plan_sha256=$digest' <<<"$mutated")
envelope=$(printf '%s' "$mutated" | encode_fixture_journal)
version=$(jq -r .repair.stale_target_retirement_ref.version <<<"$state")
set_fixture_param /sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement "$envelope"
set_fixture_param "/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement:${version}" "$envelope"
state=$(jq -c --arg digest "$(printf '%s' "$envelope" | sha256sum | awk '{print $1}')" \
	'.repair.stale_target_retirement_ref.sha256=$digest' <<<"$state")
set_fixture_param /sandbox/nhp/cutovers/durable-aop-v1/state "$state"
: >"$FAKE_ACTIONS"
if invoke >/dev/null 2>&1; then
	echo "caller-selected predecessor fence was accepted after plan precommit" >&2
	exit 1
fi
if grep -Eq '^(snapshot-predecessors|retire-predecessor)' "$FAKE_ACTIONS"; then
	echo "mutated predecessor plan reached snapshot or retirement" >&2
	exit 1
fi
cp "$WORK/params.handoff-current" "$FAKE_PARAMS"
cp "$WORK/journal-version.handoff-current" "$FAKE_JOURNAL_VERSION_FILE"
for mutation in \
  predecessor_bytes wrong_phase owner_present wrong_state_version missing_lock changed_lock \
  successor_at_v20 third_stored predecessor_as_current; do
  seed_live_orchestrator_handoff
  state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
  unset INVOKE_RECOVERY_SHA
  case "$mutation" in
    predecessor_bytes) mutated=$(jq -c '.repair.ac_refresh_id="changed-refresh"' <<<"$state") ;;
    wrong_phase) mutated=$(jq -c '.phase="ac_refreshing"' <<<"$state") ;;
    owner_present) mutated=$(jq -c '.repair.owner={status:"ready",intent:{}}' <<<"$state") ;;
    wrong_state_version)
      mutated=$state
      printf '21\n' >"$FAKE_STATE_VERSION_FILE"
      ;;
    missing_lock)
      mutated=$state
      awk -F '\t' '$1!="/layerv-nhp-sandbox/qurl-live-env-lock"' "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"
      mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
      ;;
    changed_lock)
      mutated=$state
      lock=$(awk -F '\t' '$1=="/layerv-nhp-sandbox/qurl-live-env-lock" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
      set_fixture_param /layerv-nhp-sandbox/qurl-live-env-lock "$(jq -c '.created_at += 1' <<<"$lock")"
      ;;
    successor_at_v20) mutated=$(jq -c --arg sha "$RECOVERY" '.repair.orchestrator_sha=$sha' <<<"$state") ;;
    third_stored) mutated=$(jq -c '.repair.orchestrator_sha="9999999999999999999999999999999999999999"' <<<"$state") ;;
    predecessor_as_current)
      mutated=$state
      export INVOKE_RECOVERY_SHA=$RECOVERY_PREDECESSOR
      ;;
  esac
  set_fixture_param /sandbox/nhp/cutovers/durable-aop-v1/state "$mutated"
  : >"$FAKE_ACTIONS"
  if invoke >/dev/null 2>&1; then
    echo "invalid one-hop orchestrator authority was accepted: $mutation" >&2
    exit 1
  fi
  if [[ -s "$FAKE_ACTIONS" ]]; then
    echo "invalid one-hop orchestrator authority reached an AWS mutation: $mutation" >&2
    exit 1
  fi
done
unset INVOKE_RECOVERY_SHA

cp "$WORK/params.handoff-current" "$FAKE_PARAMS"
cp "$WORK/state-version.handoff-current" "$FAKE_STATE_VERSION_FILE"
cp "$WORK/journal-version.handoff-current" "$FAKE_JOURNAL_VERSION_FILE"
: >"$FAKE_ACTIONS"
export INVOKE_RECOVERY_SHA=9999999999999999999999999999999999999999
if invoke >/dev/null 2>&1; then
  echo "current schema-3 replay accepted a third controller source" >&2
  exit 1
fi
[[ ! -s "$FAKE_ACTIONS" ]]
unset INVOKE_RECOVERY_SHA INVOKE_BUILD_RUN_ID INVOKE_BUILD_RUN_ATTEMPT

# The recovery start is a stable, strongly read incident receipt, not a
# hard-coded historical count. Counts 1 and the store capacity 1024 are valid;
# zero, above-capacity, noncanonical, malformed, blocked, and overflow
# authorities fail before the first durable state/image/refresh/DDB mutation.
export INVOKE_BUILD_RUN_ID=32656742290 INVOKE_BUILD_RUN_ATTEMPT=1
for count in 1 1024; do
  seed_live_stale_retirement_handoff
  export FAKE_FENCE_START_COUNT=$count
  export FAKE_FAIL_AFTER_STATE_PHASE=repaired
  export FAKE_FAIL_AFTER_STATE_WRITE_ONCE="$WORK/fence-start-${count}-state-stop"
  rm -f "$FAKE_FAIL_AFTER_STATE_WRITE_ONCE"
  : >"$FAKE_ACTIONS"
  if invoke >/dev/null 2>&1; then
    echo "capacity-bounded fence start $count did not stop after its durable state reference" >&2
    exit 1
  fi
  journal=$(read_fixture_journal)
  [[ "$(jq -r .runtime.fence_start.active_fence_count <<<"$journal")" == "$count" &&
     "$(jq -r .status <<<"$journal")" == cell0_intent ]]
  if grep -Eq $'^(refresh|retire|retire-predecessor)\t' "$FAKE_ACTIONS"; then
    echo "fence start $count reached a refresh or retirement before journal/state persistence" >&2
    exit 1
  fi
done
unset FAKE_FENCE_START_COUNT FAKE_FAIL_AFTER_STATE_PHASE FAKE_FAIL_AFTER_STATE_WRITE_ONCE

for authority in zero above_capacity noncanonical malformed admission_blocked overflow; do
  seed_live_stale_retirement_handoff
  unset FAKE_FENCE_START_COUNT FAKE_FENCE_START_AUTHORITY
  case "$authority" in
    zero) export FAKE_FENCE_START_COUNT=0 ;;
    above_capacity) export FAKE_FENCE_START_COUNT=1025 ;;
    *) export FAKE_FENCE_START_AUTHORITY=$authority ;;
  esac
  : >"$FAKE_ACTIONS"
  if invoke >/dev/null 2>&1; then
    echo "invalid starting fence authority was accepted: $authority" >&2
    exit 1
  fi
  if grep -Eq $'^(put|delete|refresh|owner-plan|owner-apply|snapshot-predecessors|retire|retire-predecessor)\t?' \
    "$FAKE_ACTIONS"; then
    echo "invalid starting fence authority reached a mutation: $authority" >&2
    cat "$FAKE_ACTIONS" >&2
    exit 1
  fi
done
unset FAKE_FENCE_START_COUNT FAKE_FENCE_START_AUTHORITY

# The third incident boundary is the exact live schema-3 v22 state after the
# canonical owner reached READY. Only the reviewed 84ed predecessor may hand
# that byte-for-byte state to this controller. The first durable write creates
# the cell0 runtime-refresh intent, advances v22 -> v23, and installs the
# current controller SHA before any image or instance-refresh mutation.
export INVOKE_BUILD_RUN_ID=32656742290 INVOKE_BUILD_RUN_ATTEMPT=1
seed_live_stale_retirement_handoff
: >"$FAKE_ACTIONS"
export FAKE_FAIL_AFTER_STATE_PHASE=repaired
export FAKE_FAIL_AFTER_STATE_WRITE_ONCE=$WORK/stale-v23-write-stop
if stale_handoff_output=$(invoke 2>&1); then
  echo "exact v22 stale-target handoff unexpectedly passed the injected v23 stop" >&2
  exit 1
fi
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$(cat "$FAKE_STATE_VERSION_FILE")" == 23 ]] || {
  echo "exact v22 stale-target handoff stopped before v23: $stale_handoff_output" >&2
  exit 1
}
[[ "$(jq -r .repair.orchestrator_sha <<<"$state")" == "$RECOVERY" ]]
journal=$(read_fixture_journal)
[[ "$(jq -r .status <<<"$journal")" == cell0_intent ]]
[[ "$(jq -r .source_state_version <<<"$journal")" == 22 ]]
[[ "$(jq -r .source_state_sha256 <<<"$journal")" == "$STALE_RETIREMENT_STATE_DIGEST" ]]
[[ "$(jq -r .runtime.fence_start.active_fence_count <<<"$journal")" == 82 &&
   "$(jq -r .runtime.fence_start.version <<<"$journal")" == 83 ]]
if grep -q $'^refresh\t' "$FAKE_ACTIONS"; then
  echo "v22 handoff started a refresh before its v23 intent was durable" >&2
  exit 1
fi
unset FAKE_FAIL_AFTER_STATE_PHASE FAKE_FAIL_AFTER_STATE_WRITE_ONCE

# Even after both f323 server refreshes, an incomplete fence drain retains the
# hard lock and journal and cannot reach either incident or predecessor target
# retirement. This is also the safe retry boundary if later arrivals increased
# the count after the exact starting receipt was committed.
seed_live_stale_retirement_handoff
export FAKE_FENCE_DRAIN_INCOMPLETE=true
: >"$FAKE_ACTIONS"
if invoke >/dev/null 2>&1; then
  echo "incomplete zero-target fence drain was accepted" >&2
  exit 1
fi
grep -q $'^refresh\tlayerv-nhp-sandbox-server\t' "$FAKE_ACTIONS"
grep -q $'^refresh\tlayerv-nhp-sandbox-cell1-server-green\t' "$FAKE_ACTIONS"
if grep -Eq $'^(retire|retire-predecessor)\t' "$FAKE_ACTIONS"; then
  echo "target retirement ran before the directory reached stable zero" >&2
  exit 1
fi
grep -q '/layerv-nhp-sandbox/qurl-live-env-lock' "$FAKE_PARAMS"
if grep -q '/sandbox/nhp/minimum-protocol-profile' "$FAKE_PARAMS"; then exit 1; fi
unset FAKE_FENCE_DRAIN_INCOMPLETE

# Every mutation of the exact historical state/version/owner/lock boundary is
# rejected before a state write or refresh. A third controller source cannot
# self-select itself as the reviewed successor.
for mutation in bytes version owner digest missing_lock changed_lock third_stored predecessor_current; do
  seed_live_stale_retirement_handoff
  state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
  unset INVOKE_RECOVERY_SHA
  case "$mutation" in
    bytes) mutated=$(jq -c '.repair.ac_refresh_id="changed-refresh"' <<<"$state") ;;
    version)
      mutated=$state
      printf '23\n' >"$FAKE_STATE_VERSION_FILE"
      ;;
    owner) mutated=$(jq -c '.repair.owner.intent.expected_usage="1"' <<<"$state") ;;
    digest) mutated=$(jq -c '.repair.owner.intent.expected_row_sha256="9999999999999999999999999999999999999999999999999999999999999999"' <<<"$state") ;;
    missing_lock)
      mutated=$state
      awk -F '\t' '$1!="/layerv-nhp-sandbox/qurl-live-env-lock"' "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"
      mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
      ;;
    changed_lock)
      mutated=$state
      lock=$(awk -F '\t' '$1=="/layerv-nhp-sandbox/qurl-live-env-lock" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
      set_fixture_param /layerv-nhp-sandbox/qurl-live-env-lock "$(jq -c '.created_at += 1' <<<"$lock")"
      ;;
    third_stored) mutated=$(jq -c '.repair.orchestrator_sha="9999999999999999999999999999999999999999"' <<<"$state") ;;
    predecessor_current)
      mutated=$state
      export INVOKE_RECOVERY_SHA=$STALE_RETIREMENT_PREDECESSOR
      ;;
  esac
  set_fixture_param /sandbox/nhp/cutovers/durable-aop-v1/state "$mutated"
  : >"$FAKE_ACTIONS"
  if invoke >/dev/null 2>&1; then
    echo "mutated exact v22 stale-target handoff was accepted: $mutation" >&2
    exit 1
  fi
  if grep -Eq $'^(put|delete|refresh)\t' "$FAKE_ACTIONS"; then
    echo "mutated exact v22 stale-target handoff reached a mutation: $mutation" >&2
    exit 1
  fi
done
unset INVOKE_RECOVERY_SHA

# Every journal transition is crash-safe at the exact journal-put-before-state
# boundary. The first failure leaves an initial-create orphan with schema-3
# still at v22. Each retry adopts only that exact version, commits its state
# reference, and advances until the next journal version. Thus every journal
# version is stopped once before its state reference and the final retry
# converges without replanning authority.
seed_live_stale_retirement_handoff
: >"$FAKE_ACTIONS"
export FAKE_FAIL_STATE_ONCE_PER_JOURNAL_VERSION_FILE=$WORK/journal-state-crash-versions
rm -f "$FAKE_FAIL_STATE_ONCE_PER_JOURNAL_VERSION_FILE"
journal_crash_attempts=0
journal_crash_complete=false
while (( journal_crash_attempts < 40 )); do
	if journal_crash_output=$(invoke 2>&1); then
		journal_crash_complete=true
		break
	fi
	journal_crash_attempts=$((journal_crash_attempts + 1))
	if (( journal_crash_attempts == 1 )); then
		state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
		[[ "$(cat "$FAKE_STATE_VERSION_FILE")" == 22 &&
		   "$(jq -r '.repair.stale_target_retirement_ref // empty' <<<"$state")" == "" &&
		   "$(cat "$FAKE_JOURNAL_VERSION_FILE")" == 1 ]] || {
			echo "initial journal create did not stop as an unreferenced v1 orphan" >&2; exit 1;
		}
	fi
done
unset FAKE_FAIL_STATE_ONCE_PER_JOURNAL_VERSION_FILE
[[ "$journal_crash_complete" == true ]] || {
	echo "journal-put-before-state crash sequence did not converge: $journal_crash_output" >&2; exit 1;
}
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
journal_version=$(cat "$FAKE_JOURNAL_VERSION_FILE")
journal=$(read_fixture_journal)
[[ "$(jq -r .repair.stale_target_retirement_ref.version <<<"$state")" == "$journal_version" &&
   "$(jq -r .status <<<"$journal")" == complete &&
   "$(wc -l <"$WORK/journal-state-crash-versions" | tr -d ' ')" == "$journal_version" ]] || {
	echo "not every journal update was recovered through its exact state-reference crash boundary" >&2; exit 1;
}
[[ "$(jq -r .runtime.fence_start.active_fence_count <<<"$journal")" == 82 &&
   "$(jq -r .runtime.fence_start.version <<<"$journal")" == 83 &&
   "$(jq -r .runtime.fence_drain.active_fence_count <<<"$journal")" == 0 &&
   "$(jq -r .runtime.fence_drain.version <<<"$journal")" == 106 ]] || {
  echo "later-arriving fences did not retain the exact start and stable-zero successor receipts" >&2
  exit 1
}
cell0_refresh_line=$(grep -n $'^refresh\tlayerv-nhp-sandbox-server\t' "$FAKE_ACTIONS" | head -1 | cut -d: -f1)
cell1_refresh_line=$(grep -n $'^refresh\tlayerv-nhp-sandbox-cell1-server-green\t' "$FAKE_ACTIONS" | head -1 | cut -d: -f1)
fence_drain_line=$(grep -n '^verify-fence-drain$' "$FAKE_ACTIONS" | head -1 | cut -d: -f1)
incident_retire_line=$(grep -n $'^retire\t' "$FAKE_ACTIONS" | head -1 | cut -d: -f1)
[[ "$cell0_refresh_line" -lt "$fence_drain_line" && "$cell1_refresh_line" -lt "$fence_drain_line" &&
   "$fence_drain_line" -lt "$incident_retire_line" ]] || {
  echo "server refresh, stable-zero drain, and target retirement ordering drifted" >&2
  exit 1
}
awk 'NR != $1 {exit 1}' "$WORK/journal-state-crash-versions"
grep -Eq $'^retire-predecessor-orphan\tpredecessor-1\t[1-9][0-9]*$' "$FAKE_ACTIONS" || {
	echo "predecessor DDB replay did not consume the exact journal N+1 orphan before state-reference adoption" >&2
	exit 1
}
grep -Eq $'^predecessor-orphan-state-adopt\t[1-9][0-9]*$' "$FAKE_ACTIONS" || {
	echo "exact predecessor journal N+1 orphan did not become the same schema-3 state reference" >&2
	exit 1
}
grep -q '/layerv-nhp-sandbox/qurl-live-env-lock' "$FAKE_PARAMS"
if grep -q '/sandbox/nhp/minimum-protocol-profile' "$FAKE_PARAMS"; then exit 1; fi

# A state reference admits at most one exact derived successor. An unrelated
# but internally valid current v+1, a v+2 current value, or a state reference
# to a version that was never verified all fail before any mutation.
cp "$FAKE_PARAMS" "$WORK/params.journal-crash-complete"
cp "$FAKE_STATE_VERSION_FILE" "$WORK/state-version.journal-crash-complete"
cp "$FAKE_JOURNAL_VERSION_FILE" "$WORK/journal-version.journal-crash-complete"
for mutation in unrelated_successor extra_successor unverified_reference; do
	cp "$WORK/params.journal-crash-complete" "$FAKE_PARAMS"
	cp "$WORK/state-version.journal-crash-complete" "$FAKE_STATE_VERSION_FILE"
	cp "$WORK/journal-version.journal-crash-complete" "$FAKE_JOURNAL_VERSION_FILE"
	state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
	version=$(jq -r .repair.stale_target_retirement_ref.version <<<"$state")
	envelope=$(awk -F '\t' -v n="/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement:${version}" \
		'$1==n {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
	journal=$(printf '%s' "$envelope" | decode_fixture_journal)
	mutated=$(jq -cS '.runtime.cell0.refresh_id="unrelated-successor"' <<<"$journal")
	unrelated=$(printf '%s' "$mutated" | encode_fixture_journal)
	case "$mutation" in
		unrelated_successor)
			successor=$((version + 1))
			set_fixture_param /sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement "$unrelated"
			set_fixture_param "/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement:${successor}" "$unrelated"
			printf '%s\n' "$successor" >"$FAKE_JOURNAL_VERSION_FILE"
			;;
		extra_successor)
			successor=$((version + 2))
			set_fixture_param /sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement "$unrelated"
			set_fixture_param "/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement:${successor}" "$unrelated"
			printf '%s\n' "$successor" >"$FAKE_JOURNAL_VERSION_FILE"
			;;
		unverified_reference)
			successor=$((version + 1))
			state=$(jq -c --argjson version "$successor" --arg digest "$(printf '%s' "$unrelated" | sha256sum | awk '{print $1}')" \
				'.repair.stale_target_retirement_ref.version=$version | .repair.stale_target_retirement_ref.sha256=$digest' <<<"$state")
			set_fixture_param /sandbox/nhp/cutovers/durable-aop-v1/state "$state"
			;;
	esac
	: >"$FAKE_ACTIONS"
	if invoke >/dev/null 2>&1; then echo "journal authority accepted $mutation" >&2; exit 1; fi
	if grep -Eq $'^(put|delete|refresh|retire-|owner-plan|owner-apply|snapshot-)\t?' "$FAKE_ACTIONS"; then
		echo "journal authority mutation reached a write-capable action: $mutation" >&2; exit 1
	fi
done

# An unrelated orphan at initial creation is never self-pinned as authority.
seed_live_stale_retirement_handoff
unrelated=$(printf '%s' '{"schema":"unrelated"}' | encode_fixture_journal)
set_fixture_param /sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement "$unrelated"
set_fixture_param /sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement:1 "$unrelated"
printf '1\n' >"$FAKE_JOURNAL_VERSION_FILE"
: >"$FAKE_ACTIONS"
if invoke >/dev/null 2>&1; then echo "unrelated initial journal orphan was adopted" >&2; exit 1; fi
if grep -Eq $'^(put|refresh|retire-)\t' "$FAKE_ACTIONS"; then
	echo "unrelated initial journal orphan reached a mutation" >&2; exit 1
fi

unset INVOKE_BUILD_RUN_ID INVOKE_BUILD_RUN_ATTEMPT

# A malformed successor-version read cannot bypass the exact v20 exclusion.
cp "$WORK/params.handoff-current" "$FAKE_PARAMS"
cp "$WORK/journal-version.handoff-current" "$FAKE_JOURNAL_VERSION_FILE"
printf 'unreadable\n' >"$FAKE_STATE_VERSION_FILE"
: >"$FAKE_ACTIONS"
export INVOKE_BUILD_RUN_ID=32656742290 INVOKE_BUILD_RUN_ATTEMPT=1
if invoke >/dev/null 2>&1; then
  echo "current schema-3 replay accepted a malformed state version" >&2
  exit 1
fi
[[ ! -s "$FAKE_ACTIONS" ]]
cp "$WORK/state-version.handoff-current" "$FAKE_STATE_VERSION_FILE"
cp "$WORK/journal-version.handoff-current" "$FAKE_JOURNAL_VERSION_FILE"
: >"$FAKE_ACTIONS"
export FAKE_STATE_VERSION_READ_ERROR=true
if invoke >/dev/null 2>&1; then
  echo "current schema-3 replay accepted a failed state version read" >&2
  exit 1
fi
[[ ! -s "$FAKE_ACTIONS" ]]
unset FAKE_STATE_VERSION_READ_ERROR
unset INVOKE_BUILD_RUN_ID INVOKE_BUILD_RUN_ATTEMPT

# The production controller sources its wait dependency once per repaired
# fleet. Stop after the persisted cell1 refresh, then resume in a new shell and
# prove its cell1 + AC repeated sources reach the repaired boundary.
seed
export FAKE_WAIT_HELPER=$WORK/helpers/wait-with-production-metric-source
export FAKE_METRIC_WAIT_FAIL_ASG=layerv-nhp-sandbox-cell1-server-green
export FAKE_METRIC_WAIT_FAIL_ONCE=$WORK/metric-cell1-wait-failed
if invoke >/dev/null 2>&1; then
  echo "injected cell1 wait failure unexpectedly completed" >&2
  exit 1
fi
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$(jq -r .phase <<<"$state")" == cell1_refreshing ]]
[[ -n "$(jq -r .repair.cell0_attestation <<<"$state")" ]]
[[ -n "$(jq -r .repair.cell1_refresh_id <<<"$state")" ]]
[[ "$(jq -r .repair.cell1_attestation <<<"$state")" == "" ]]
unset FAKE_METRIC_WAIT_FAIL_ASG FAKE_METRIC_WAIT_FAIL_ONCE
output=$(invoke)
grep -q 'reached repaired+owner_ready' <<<"$output"
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$(jq -r .phase <<<"$state")" == repaired ]]
[[ "$(jq -r .repair.owner.status <<<"$state")" == ready ]]
[[ "$(grep -c '^metric-wait-source$' "$FAKE_ACTIONS")" == 7 ]]
[[ "$(grep -c $'^metric-wait-call\t' "$FAKE_ACTIONS")" == 7 ]]
[[ "$(grep -c $'^metric-wait-call\tlayerv-nhp-sandbox-server$' "$FAKE_ACTIONS")" == 2 ]]
[[ "$(grep -c $'^metric-wait-call\tlayerv-nhp-sandbox-cell1-server-green$' "$FAKE_ACTIONS")" == 3 ]]
[[ "$(grep -c $'^metric-wait-call\tlayerv-nhp-sandbox-ac-green$' "$FAKE_ACTIONS")" == 2 ]]
unset FAKE_WAIT_HELPER

# Crash after the durable owner intent but before a confirmed customer write
# retains `repaired` + owner.preparing. The retry applies that same intent and
# cannot choose a new final digest or timestamp.
seed
export FAKE_OWNER_APPLY_FAIL_ONCE=$WORK/owner-apply-failed
if invoke >/dev/null 2>&1; then echo "injected owner apply crash unexpectedly completed" >&2; exit 1; fi
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$(jq -r .phase <<<"$state")" == repaired && "$(jq -r .repair.owner.status <<<"$state")" == preparing ]]
intent_before=$(jq -cS .repair.owner.intent <<<"$state")
grep -q '/layerv-nhp-sandbox/qurl-live-env-lock' "$FAKE_PARAMS"
if grep -q '/sandbox/nhp/minimum-protocol-profile' "$FAKE_PARAMS"; then exit 1; fi
unset FAKE_OWNER_APPLY_FAIL_ONCE
invoke >/dev/null
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$(jq -r .repair.owner.status <<<"$state")" == ready ]]
[[ "$(jq -cS .repair.owner.intent <<<"$state")" == "$intent_before" ]]
[[ "$(grep -c '^owner-plan$' "$FAKE_ACTIONS")" == 1 ]]

seed
# A crash/error after the schema-3 phase write and active image update retains
# the hard lock and exact adoption evidence.  Retrying the same repair source
# safely reruns the refresh and advances; it never falls back to schema 2.
export FAKE_WAIT_FAIL_ONCE=$WORK/wait-failed
if invoke >/dev/null 2>&1; then echo "injected refresh crash unexpectedly completed" >&2; exit 1; fi
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$(jq -r .phase <<<"$state")" == cell0_refreshing ]]
grep -q '/layerv-nhp-sandbox/qurl-live-env-lock' "$FAKE_PARAMS"
unset FAKE_WAIT_FAIL_ONCE
# The no-selector attempt performs all three forward refreshes, persists and
# converges the exact owner intent, then returns deliberate partial success.
# It cannot invent lifecycle receipts or release the hard lock.
output=$(invoke)
grep -q 'reached repaired+owner_ready' <<<"$output"
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$(jq -r .schema <<<"$state")" == 3 && "$(jq -r .phase <<<"$state")" == repaired ]]
[[ "$(jq -r .repair.owner.status <<<"$state")" == ready ]]
[[ "$(jq -r .repair.owner.intent.client_id <<<"$state")" == oScYkXhLitBPO6gBjxo4Rwyw37AdoNPy ]]
[[ "$(jq -r .repair.owner.intent.subject <<<"$state")" == oScYkXhLitBPO6gBjxo4Rwyw37AdoNPy@clients ]]
[[ "$(jq -r .repair.owner.intent.source_sha <<<"$state")" == "$REPAIR" ]]
[[ "$(jq -r .original.state_version <<<"$state")" == 7 ]]
[[ "$(jq -r .original.state_sha256 <<<"$state")" == "$ORIGINAL_STATE_DIGEST" ]]
[[ "$(jq -r .original.lock_version <<<"$state")" == 2 ]]
[[ "$(jq -r .original.lock_sha256 <<<"$state")" == "$ORIGINAL_LOCK_DIGEST" ]]
[[ "$(jq -r .repair.runtime_manifest <<<"$state")" == "$MANIFEST" ]]
[[ "$(jq -r .repair.build_run_attempt <<<"$state")" == 2 ]]
[[ "$(jq -r .repair.cell0_refresh_id <<<"$state")" == refresh-layerv-nhp-sandbox-server ]]
[[ "$(grep -c $'^refresh\tlayerv-nhp-sandbox-server\t' "$FAKE_ACTIONS")" == 2 ]]
envelope=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
(( ${#state} < 4096 && ${#envelope} < 4096 )) || {
	echo "schema-3 state or stale-target journal exceeds the SSM standard-parameter limit" >&2; exit 1;
}
[[ "$(awk -F '\t' '$1=="/sandbox/nhp/server/image-tag" {print $2}' "$FAKE_PARAMS")" == "$RUNTIME_SERVER_SELECTOR" ]]
[[ "$(awk -F '\t' '$1=="/sandbox-cell1/nhp/server/green-image-tag" {print $2}' "$FAKE_PARAMS")" == "$RUNTIME_SERVER_SELECTOR" ]]
[[ "$(awk -F '\t' '$1=="/sandbox/nhp/ac/green-image-tag" {print $2}' "$FAKE_PARAMS")" == "$RUNTIME_AC_SELECTOR" ]]
grep -q '/layerv-nhp-sandbox/qurl-live-env-lock' "$FAKE_PARAMS"
if grep -q '/sandbox/nhp/minimum-protocol-profile' "$FAKE_PARAMS"; then exit 1; fi

# Exact no-selector replay is successful and performs no additional fleet
# refresh after the repaired+owner_ready boundary.
refresh_count=$(grep -c $'^refresh\t' "$FAKE_ACTIONS")
output=$(invoke)
grep -q 'reached repaired+owner_ready' <<<"$output"
[[ "$(grep -c $'^refresh\t' "$FAKE_ACTIONS")" == "$refresh_count" ]]

# The repaired owner authority is closed and source-bound. A self-consistent
# state edit cannot substitute another client/source/final digest.
cp "$FAKE_PARAMS" "$WORK/params.owner-ready"
for mutation in client source digest; do
  cp "$WORK/params.owner-ready" "$FAKE_PARAMS"
  state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
  case "$mutation" in
    client) mutated=$(jq -c '.repair.owner.intent.client_id="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"' <<<"$state") ;;
    source) mutated=$(jq -c '.repair.owner.intent.source_sha="9999999999999999999999999999999999999999"' <<<"$state") ;;
    digest) mutated=$(jq -c '.repair.owner.intent.expected_row_sha256="9999999999999999999999999999999999999999999999999999999999999999"' <<<"$state") ;;
  esac
  awk -F '\t' -v value="$mutated" '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {$0=$1 "\t" value} {print}' \
    "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"; mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
  if invoke >/dev/null 2>&1; then echo "mutated owner authority was accepted: $mutation" >&2; exit 1; fi
done
cp "$WORK/params.owner-ready" "$FAKE_PARAMS"

# Once the runtime-retirement journal exists, READY cannot move back to
# PREPARING even with the same owner intent. The earlier injected owner-apply
# crash pins the valid pre-journal self-heal boundary.
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
mutated=$(jq -c '.repair.owner.status="preparing"' <<<"$state")
awk -F '\t' -v value="$mutated" '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {$0=$1 "\t" value} {print}' \
  "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"; mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
if invoke >/dev/null 2>&1; then
  echo "post-journal owner status rollback was accepted" >&2
  exit 1
fi
cp "$WORK/params.owner-ready" "$FAKE_PARAMS"
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")

# A self-consistent-looking phase jump cannot skip the three durable refresh
# ids/attestations or the two protected receipts.
cp "$FAKE_PARAMS" "$WORK/params.repaired"
mutated=$(jq -c '.phase="complete"' <<<"$state")
awk -F '\t' -v value="$mutated" '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {$0=$1 "\t" value} {print}' \
  "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"; mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
if invoke >/dev/null 2>&1; then echo "impossible schema-3 phase tuple was accepted" >&2; exit 1; fi
mv "$WORK/params.repaired" "$FAKE_PARAMS"

cp "$FAKE_ORIGINAL_STATE_RECORD" "$WORK/original-state.saved"
sed 's/"old_asg":"layerv-nhp-sandbox-ac"/"old_asg":"ac-mutated"/' "$FAKE_ORIGINAL_STATE_RECORD" >"$FAKE_ORIGINAL_STATE_RECORD.tmp"
mv "$FAKE_ORIGINAL_STATE_RECORD.tmp" "$FAKE_ORIGINAL_STATE_RECORD"
if invoke >/dev/null 2>&1; then echo "mutated original SSM history was accepted" >&2; exit 1; fi
mv "$WORK/original-state.saved" "$FAKE_ORIGINAL_STATE_RECORD"

export LIFECYCLE_RUN_ID=900 LIFECYCLE_RUN_ATTEMPT=2 LIFECYCLE_INFRA_SHA=$INFRA
export LIFECYCLE_INTEGRATIONS_SHA=$INTEGRATIONS
export CONNECTOR_RUN_ID=901 CONNECTOR_RUN_ATTEMPT=2 CONNECTOR_SOURCE_SHA=$CONNECTOR
export CONNECTOR_PR_HEAD_SHA=$CONNECTOR_PR
export CONNECTOR_CONTROLLER_RUN_ID=66 CONNECTOR_CONTROLLER_RUN_ATTEMPT=3
invoke >/dev/null
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$(jq -r .phase <<<"$state")" == complete ]]
[[ "$(jq -r .repair.customer_lifecycle <<<"$state")" == v2\|layervai/qurl-integrations-infra\|900\|2\|* ]]
[[ "$(jq -r .repair.connector_lifecycle <<<"$state")" == v1\|layervai/qurl-connector\|901\|2\|* ]]
(( ${#state} <= 4096 )) || { echo "complete schema-3 state exceeds the SSM standard-parameter limit" >&2; exit 1; }
if grep -q '/layerv-nhp-sandbox/qurl-live-env-lock' "$FAKE_PARAMS"; then exit 1; fi
[[ "$(awk -F '\t' '$1=="/sandbox/nhp/minimum-protocol-profile" {print $2}' "$FAKE_PARAMS")" == durable-aop-v1 ]]
invoke >/dev/null
[[ "$(awk -F '\t' '$1=="/sandbox/nhp/minimum-protocol-profile" {print $2}' "$FAKE_PARAMS")" == durable-aop-v1 ]]

# COMPLETE replay has no hard lock and therefore must keep the reviewed source
# identities inside both stored lifecycle receipts as terminal authority. A
# different but shape-valid SHA cannot satisfy replay.
cp "$FAKE_PARAMS" "$WORK/params.complete"
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
mutated=$(jq -c --arg old "$INFRA" --arg new 9999999999999999999999999999999999999999 \
  '.repair.customer_lifecycle |= sub($old;$new)' <<<"$state")
awk -F '\t' -v value="$mutated" '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {$0=$1 "\t" value} {print}' \
  "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"; mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
if invoke >/dev/null 2>&1; then echo "COMPLETE replay accepted another customer infra SHA" >&2; exit 1; fi

cp "$WORK/params.complete" "$FAKE_PARAMS"
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
mutated=$(jq -c --arg old "$INTEGRATIONS" --arg new 9999999999999999999999999999999999999999 \
  '.repair.customer_lifecycle |= sub($old;$new)' <<<"$state")
awk -F '\t' -v value="$mutated" '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {$0=$1 "\t" value} {print}' \
  "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"; mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
if invoke >/dev/null 2>&1; then echo "COMPLETE replay accepted another integrations SHA" >&2; exit 1; fi

cp "$WORK/params.complete" "$FAKE_PARAMS"
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
mutated=$(jq -c --arg old "$CONNECTOR_PR" --arg new 9999999999999999999999999999999999999999 \
  '.repair.connector_lifecycle |= sub($old;$new)' <<<"$state")
awk -F '\t' -v value="$mutated" '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {$0=$1 "\t" value} {print}' \
  "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"; mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
if invoke >/dev/null 2>&1; then echo "COMPLETE replay accepted another connector PR head SHA" >&2; exit 1; fi

# Shape-valid receipt substitution cannot move COMPLETE to a different repaired
# server image digest.
cp "$WORK/params.complete" "$FAKE_PARAMS"
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
mutated=$(jq -c --arg old "$RUNTIME_SERVER_DIGEST" --arg new sha256:9999999999999999999999999999999999999999999999999999999999999999 \
  '.repair.connector_lifecycle |= sub($old;$new)' <<<"$state")
awk -F '\t' -v value="$mutated" '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {$0=$1 "\t" value} {print}' \
  "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"; mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
if invoke >/dev/null 2>&1; then echo "cross-repair connector lifecycle receipt was accepted" >&2; exit 1; fi

# The customer receipt independently binds both repaired image digests and the
# NHP deployment authority bytes; a shape-valid substitution must fail replay.
seed
export LIFECYCLE_RUN_ID=900 LIFECYCLE_RUN_ATTEMPT=2 LIFECYCLE_INFRA_SHA=$INFRA
export LIFECYCLE_INTEGRATIONS_SHA=$INTEGRATIONS
export CONNECTOR_RUN_ID=901 CONNECTOR_RUN_ATTEMPT=2 CONNECTOR_SOURCE_SHA=$CONNECTOR
export CONNECTOR_PR_HEAD_SHA=$CONNECTOR_PR CONNECTOR_CONTROLLER_RUN_ID=66 CONNECTOR_CONTROLLER_RUN_ATTEMPT=3
invoke >/dev/null
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
mutated=$(jq -c --arg old "$RUNTIME_AC_DIGEST" --arg new sha256:9999999999999999999999999999999999999999999999999999999999999999 \
  '.repair.customer_lifecycle |= sub($old;$new)' <<<"$state")
awk -F '\t' -v value="$mutated" '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {$0=$1 "\t" value} {print}' \
  "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"; mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
if invoke >/dev/null 2>&1; then echo "cross-repair customer lifecycle receipt was accepted" >&2; exit 1; fi

# Provenance and original-state mutation fail before adoption or refresh.
seed
export FAKE_PROVENANCE_FAILURE=true
if invoke >/dev/null 2>&1; then echo "missing repair provenance was accepted" >&2; exit 1; fi
unset FAKE_PROVENANCE_FAILURE
[[ ! -s "$FAKE_ACTIONS" ]]
seed
export FAKE_PROVENANCE_FAILURE_AT=4
if invoke >/dev/null 2>&1; then echo "missing fourth image authority was accepted" >&2; exit 1; fi
unset FAKE_PROVENANCE_FAILURE_AT
[[ ! -s "$FAKE_ACTIONS" && "$(wc -l <"$FAKE_PROVENANCE_CALLS" | tr -d ' ')" == 4 ]]
diff -u <(cat <<EOF
layerv/nhp-server	$REPAIR	88	2	$SERVER_DIGEST
layerv/nhp-ac	$REPAIR	88	2	$AC_DIGEST
layerv/nhp-server	$RUNTIME	32682520698	1	$RUNTIME_SERVER_DIGEST
layerv/nhp-ac	$RUNTIME	32682520698	1	$RUNTIME_AC_DIGEST
EOF
) "$FAKE_PROVENANCE_CALLS"
export FAKE_RUNTIME_MANIFEST_FAILURE=true
if invoke >/dev/null 2>&1; then echo "unreviewed runtime manifest was accepted" >&2; exit 1; fi
unset FAKE_RUNTIME_MANIFEST_FAILURE
# An unrelated in-progress refresh is never adopted as repaired authority, and
# the preflight refuses it before changing the active image/profile slots.
seed
export FAKE_UNOWNED_REFRESH=true
if invoke >/dev/null 2>&1; then echo "unowned instance refresh was adopted" >&2; exit 1; fi
unset FAKE_UNOWNED_REFRESH
[[ "$(awk -F '\t' '$1=="/sandbox/nhp/server/image-tag" {print $2}' "$FAKE_PARAMS")" == "$ORIGINAL" ]]
if grep -q $'^refresh\t' "$FAKE_ACTIONS"; then echo "unowned refresh preflight started another refresh" >&2; exit 1; fi
# Portable mutation: replace only the state row's exact phase.
seed
sed 's/"phase":"old_servers_terminated"/"phase":"validated"/' "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"; mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
if invoke >/dev/null 2>&1; then echo "mutated original schema-2 phase was adopted" >&2; exit 1; fi

# StartInstanceRefresh has no client token.  The controller first persists an
# exact intent and bounded prior-refresh boundary, so a lost start response is
# classified and adopted once without creating a second refresh.
seed
export FAKE_START_LOST_ONCE=$WORK/start-lost
if invoke >/dev/null 2>&1; then echo "lost refresh response unexpectedly completed" >&2; exit 1; fi
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$(jq -r .phase <<<"$state")" == cell0_refreshing ]]
[[ "$(jq -r .repair.cell0_refresh_id <<<"$state")" == "" ]]
[[ "$(jq -r .repair.refresh_intent <<<"$state")" =~ ^v1\|[0-9a-f]{64}\|-$ ]]
[[ "$(grep -c $'^refresh\tlayerv-nhp-sandbox-server\t' "$FAKE_ACTIONS")" == 1 ]]
[[ "$(awk -F '\t' '$1=="/sandbox/nhp/server/image-tag" {print $2}' "$FAKE_PARAMS")" == "$REPAIR" ]]
[[ "$(awk -F '\t' '$1=="/sandbox/nhp/server/blue-protocol-profile" {print $2}' "$FAKE_PARAMS")" == "v1|durable-aop-v1|${REPAIR}" ]]
if grep -q '^/sandbox/nhp/server/blue-prepared-slot-attestation' "$FAKE_PARAMS"; then
  echo "repair attestation survived before the committed refresh completed" >&2; exit 1
fi
unset FAKE_START_LOST_ONCE
invoke >/dev/null
[[ "$(grep -c $'^refresh\tlayerv-nhp-sandbox-server\t' "$FAKE_ACTIONS")" == 2 ]]

# A crash after the durable intent but before the StartInstanceRefresh call
# leaves no AWS refresh and resumes from that exact intent.
seed
export FAKE_REFRESH_LIST_COUNT_FILE=$WORK/list-count-intent-crash FAKE_REFRESH_LIST_FAIL_AT=2
if invoke >/dev/null 2>&1; then echo "intent-before-start crash unexpectedly completed" >&2; exit 1; fi
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$(jq -r .phase <<<"$state")" == cell0_refreshing ]]
[[ "$(jq -r .repair.refresh_intent <<<"$state")" =~ ^v1\|[0-9a-f]{64}\|-$ ]]
if grep -q $'^refresh\t' "$FAKE_ACTIONS"; then echo "refresh started before the injected intent crash" >&2; exit 1; fi
unset FAKE_REFRESH_LIST_COUNT_FILE FAKE_REFRESH_LIST_FAIL_AT
invoke >/dev/null
[[ "$(grep -c $'^refresh\tlayerv-nhp-sandbox-server\t' "$FAKE_ACTIONS")" == 2 ]]

# With existing history, only the one newest exact successor to the recorded
# boundary is eligible for adoption. A missing/out-of-window boundary fails.
seed
export FAKE_PRIOR_REFRESH=true FAKE_START_LOST_ONCE=$WORK/start-lost-with-prior
if invoke >/dev/null 2>&1; then exit 1; fi
unset FAKE_START_LOST_ONCE
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$(jq -r .repair.refresh_intent <<<"$state")" == v1\|*\|refresh-prior ]]
invoke >/dev/null
[[ "$(grep -c $'^refresh\tlayerv-nhp-sandbox-server\t' "$FAKE_ACTIONS")" == 2 ]]
seed
export FAKE_START_LOST_ONCE=$WORK/start-lost-missing-prior
if invoke >/dev/null 2>&1; then exit 1; fi
unset FAKE_START_LOST_ONCE
export FAKE_PRIOR_REFRESH=true FAKE_DROP_PRIOR=true
if invoke >/dev/null 2>&1; then echo "missing bounded prior refresh was adopted" >&2; exit 1; fi
unset FAKE_PRIOR_REFRESH FAKE_DROP_PRIOR

# A candidate with different preferences or more than one successor to the
# durable history boundary is not ours and is never adopted.
seed
export FAKE_START_LOST_ONCE=$WORK/start-lost-bad-prefs
if invoke >/dev/null 2>&1; then exit 1; fi
unset FAKE_START_LOST_ONCE
export FAKE_REFRESH_BAD_PREFS=true
if invoke >/dev/null 2>&1; then echo "refresh with mutated preferences was adopted" >&2; exit 1; fi
unset FAKE_REFRESH_BAD_PREFS
[[ "$(grep -c $'^refresh\tlayerv-nhp-sandbox-server\t' "$FAKE_ACTIONS")" == 1 ]]
export FAKE_REFRESH_EXTRA=true
if invoke >/dev/null 2>&1; then echo "multiple post-intent refreshes were adopted" >&2; exit 1; fi
unset FAKE_REFRESH_EXTRA

# Both a newly discovered candidate and an already-recorded refresh must fail
# closed once AWS reports a terminal failure/cancellation.
for terminal in Failed Cancelled; do
  seed
  export FAKE_START_LOST_ONCE=$WORK/start-lost-terminal-$terminal
  if invoke >/dev/null 2>&1; then exit 1; fi
  unset FAKE_START_LOST_ONCE
  export FAKE_REFRESH_STATUS=$terminal
  if invoke >/dev/null 2>&1; then echo "terminal $terminal candidate refresh was adopted" >&2; exit 1; fi
  unset FAKE_REFRESH_STATUS

  seed
  export FAKE_WAIT_FAIL_ONCE=$WORK/wait-terminal-$terminal
  if invoke >/dev/null 2>&1; then exit 1; fi
  unset FAKE_WAIT_FAIL_ONCE
  export FAKE_PERSISTED_REFRESH_STATUS=$terminal
  if invoke >/dev/null 2>&1; then echo "terminal $terminal persisted refresh was resumed" >&2; exit 1; fi
  unset FAKE_PERSISTED_REFRESH_STATUS
done

# Shape-valid live authorities at any other SSM version/value are not eligible
# for this one attended incident recovery.
seed
export FAKE_STATE_VERSION=8
if invoke >/dev/null 2>&1; then echo "wrong live state version was adopted" >&2; exit 1; fi
unset FAKE_STATE_VERSION
export FAKE_LOCK_VERSION=3
if invoke >/dev/null 2>&1; then echo "wrong live lock version was adopted" >&2; exit 1; fi
unset FAKE_LOCK_VERSION
seed
awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {v=substr($0,index($0,"\t")+1); sub("layerv-nhp-sandbox-server-green","mutated-old-server",v); $0=$1 "\t" v} {print}' \
  "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"
mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
if invoke >/dev/null 2>&1; then echo "same-shape mutated live state was adopted" >&2; exit 1; fi
seed
awk -F '\t' '$1=="/layerv-nhp-sandbox/qurl-live-env-lock" {v=substr($0,index($0,"\t")+1); sub("1787485146","1787485147",v); $0=$1 "\t" v} {print}' \
  "$FAKE_PARAMS" >"$FAKE_PARAMS.tmp"
mv "$FAKE_PARAMS.tmp" "$FAKE_PARAMS"
if invoke >/dev/null 2>&1; then echo "same-shape mutated live lock was adopted" >&2; exit 1; fi

# The irreversible floor is create-once/exact-replay authority.  Unknown
# values survive unchanged, while a crash after exact creation and before the
# COMPLETE write retains the lock and resumes forward without overwriting it.
seed
printf '/sandbox/nhp/minimum-protocol-profile\tfuture-profile\n' >>"$FAKE_PARAMS"
if invoke >/dev/null 2>&1; then echo "unexpected existing profile floor was overwritten" >&2; exit 1; fi
[[ "$(awk -F '\t' '$1=="/sandbox/nhp/minimum-protocol-profile" {print $2}' "$FAKE_PARAMS")" == future-profile ]]

seed
export FAKE_FAIL_COMPLETE_STATE_ONCE=$WORK/fail-complete-state
if invoke >/dev/null 2>&1; then echo "injected floor-before-COMPLETE crash unexpectedly completed" >&2; exit 1; fi
state=$(awk -F '\t' '$1=="/sandbox/nhp/cutovers/durable-aop-v1/state" {print substr($0,index($0,"\t")+1)}' "$FAKE_PARAMS")
[[ "$(jq -r .phase <<<"$state")" == validated ]]
[[ "$(awk -F '\t' '$1=="/sandbox/nhp/minimum-protocol-profile" {print $2}' "$FAKE_PARAMS")" == durable-aop-v1 ]]
grep -q '/layerv-nhp-sandbox/qurl-live-env-lock' "$FAKE_PARAMS"
unset FAKE_FAIL_COMPLETE_STATE_ONCE
invoke >/dev/null
[[ "$(grep -c $'^put\t/sandbox/nhp/minimum-protocol-profile$' "$FAKE_ACTIONS")" == 1 ]]
if grep -q '/layerv-nhp-sandbox/qurl-live-env-lock' "$FAKE_PARAMS"; then exit 1; fi

echo "recover-durable-aop-cutover-schema3: crash/retry/provenance/mutation tests passed"
