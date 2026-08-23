#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT=$ROOT/.github/scripts/verify-durable-aop-connector-lifecycle-run.sh
CONNECTOR=2222222222222222222222222222222222222222
CONNECTOR_PR=16dd7d3c835bf4f44b212e2d6a34205a3c04a8d8
CONNECTOR_BASE=e70923168818da0b8002e5e63e7dcfe9e060ba12
CONNECTOR_TREE=4444444444444444444444444444444444444444
CONNECTOR_MAIN=5555555555555555555555555555555555555555
NHP=0123456789012345678901234567890123456789
RECOVERY=9999999999999999999999999999999999999999
QURL_GO=d02c25995df085f0437c7a572714c26e907a8a59
SERVER_DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/artifact"
export FAKE_MODE=ok FAKE_CONNECTOR=$CONNECTOR FAKE_CONNECTOR_PR=$CONNECTOR_PR FAKE_CONNECTOR_BASE=$CONNECTOR_BASE \
  FAKE_CONNECTOR_TREE=$CONNECTOR_TREE FAKE_CONNECTOR_MAIN=$CONNECTOR_MAIN FAKE_NHP=$NHP \
  FAKE_SERVER_DIGEST=$SERVER_DIGEST

grep -q "APPROVED_CONNECTOR_PR_HEAD_SHA=${CONNECTOR_PR}" "$SCRIPT"
grep -q "APPROVED_CONNECTOR_PR_BASE_SHA=${CONNECTOR_BASE}" "$SCRIPT"
if grep -qE 'APPROVED_CONNECTOR_MERGE_SHA|CUTOVER_CONNECTOR_LIFECYCLE_SOURCE_SHA|/pulls/609' "$SCRIPT"; then
  echo "connector verifier accepts a compile-time or caller-supplied merge SHA" >&2
  exit 1
fi

jq -cn --arg connector "$CONNECTOR" --arg controller "$RECOVERY" '
  {schema_version:1,phase:"pre_removal",repository:"layervai/qurl-connector",commit_sha:$connector,
   run_id:"77",run_attempt:"2",nhp_controller_run_id:"66",nhp_controller_run_attempt:"3",
   dispatch_correlation_id:"nhp-66-3-connector-pre_removal-0123456789abcdef0123456789abcdef",
   gate_passed:true,input_outcome:"success",enforcement_outcome:"success",inputs_unchanged:true,
   counts:{blocking:0,failures:0,skips:0,implemented:12,exact_passes:12},
   provenance_valid:true,two_cell_provenance:true,typed_evidence_complete:true,
   deployment_producer:{repository:"layervai/nhp",workflow_path:".github/workflows/udp-proof-deployment-manifest.yml",
     run_id:"55",run_attempt:"4",head_sha:$controller,artifact_id:"54",
     artifact_digest:"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
' >"$WORK/artifact/strict-sandbox-proof.evidence.json"
jq -cn --arg connector "$CONNECTOR" --arg qurl_go "$QURL_GO" --arg nhp "$NHP" --arg digest "$SERVER_DIGEST" '
  {schema_version:1,phase:"pre_removal",retirement_state:"http_lifecycle_present",
   repositories:{qurl_connector:$connector,qurl_go:$qurl_go,nhp:$nhp},
   connector_modules:{qurl_go:$qurl_go},images:{nhp_cell0:$digest,nhp_cell1:$digest}}
' >"$WORK/artifact/sandbox-deployment-manifest.json"
for name in deployment-runtime-inputs.json strict-typed-evidence.json strict-proof-scenarios.json typed-evidence-contract.json; do
  printf '{"present":true}\n' >"$WORK/artifact/$name"
done
python3 - "$WORK/artifact" "$WORK/proof.zip" <<'PY'
import pathlib
import sys
import zipfile

source, target = map(pathlib.Path, sys.argv[1:])
with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as bundle:
    for path in sorted(source.iterdir()):
        bundle.write(path, path.name)
PY
export FAKE_ZIP=$WORK/proof.zip
FAKE_ZIP_DIGEST=sha256:$(sha256sum "$FAKE_ZIP" | awk '{print $1}')
export FAKE_ZIP_DIGEST
export FAKE_ZIP_SIZE
FAKE_ZIP_SIZE=$(stat -f %z "$FAKE_ZIP" 2>/dev/null || stat -c %s "$FAKE_ZIP")

cat >"$WORK/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args="$*"
if [[ "$args" == *'/actions/runs/77/attempts/2/jobs'* ]]; then
  conclusion=success; [[ "$FAKE_MODE" != missing_step ]] || conclusion=failed
  steps='["Authenticate exact deployment manifest","Run exact strict proof inventory","Build allowlisted strict proof evidence","Upload non-secret strict proof evidence","Require complete published proof gate"]'
  jq -cn --arg conclusion "$conclusion" --argjson steps "$steps" \
    '[{jobs:[{name:"Attended Connector UDP proof (strict)",conclusion:"success",steps:[$steps[]|{name:.,conclusion:$conclusion}]}]}]'
elif [[ "$args" == *'/actions/runs/77/artifacts'* ]]; then
  digest=$FAKE_ZIP_DIGEST; [[ "$FAKE_MODE" != artifact_drift ]] || digest=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  jq -cn --arg name "strict-sandbox-proof-pre_removal-${FAKE_CONNECTOR}-2" --arg digest "$digest" \
    --argjson size "$FAKE_ZIP_SIZE" '[{artifacts:[{id:88,name:$name,digest:$digest,size_in_bytes:$size,expired:false}]}]'
elif [[ "$args" == *'/actions/artifacts/88/zip'* ]]; then
  cat "$FAKE_ZIP"
elif [[ "$args" == *'/actions/runs/77'* ]]; then
  conclusion=success; [[ "$FAKE_MODE" != failed_run ]] || conclusion=failure
  repo=layervai/qurl-connector; head_repo=$repo
  [[ "$FAKE_MODE" != run_repo_drift ]] || repo=layervai/other
  [[ "$FAKE_MODE" != run_head_repo_drift ]] || head_repo=layervai/other
  jq -cn --arg sha "$FAKE_CONNECTOR" --arg conclusion "$conclusion" --arg repo "$repo" --arg head_repo "$head_repo" \
    '{repository:{full_name:$repo},head_repository:{full_name:$head_repo},
      head_sha:$sha,head_branch:"main",event:"workflow_dispatch",run_attempt:2,
      status:"completed",conclusion:$conclusion,path:".github/workflows/sandbox-smoke.yml"}'
elif [[ "$args" == *"/git/commits/${FAKE_CONNECTOR_PR}"* ]]; then
  sha=$FAKE_CONNECTOR_PR; tree=$FAKE_CONNECTOR_TREE
  [[ "$FAKE_MODE" != reviewed_commit_drift ]] || sha=1111111111111111111111111111111111111111
  [[ "$FAKE_MODE" != reviewed_tree_drift ]] || tree=1111111111111111111111111111111111111111
  jq -cn --arg sha "$sha" --arg tree "$tree" '{sha:$sha,tree:{sha:$tree}}'
elif [[ "$args" == *"/compare/${FAKE_CONNECTOR_BASE}...${FAKE_CONNECTOR_PR}"* ]]; then
  status=ahead; base=$FAKE_CONNECTOR_BASE; head=$FAKE_CONNECTOR_PR; ahead=2; behind=0
  [[ "$FAKE_MODE" != base_status_drift ]] || status=diverged
  [[ "$FAKE_MODE" != base_sha_drift ]] || base=1111111111111111111111111111111111111111
  [[ "$FAKE_MODE" != base_head_drift ]] || head=1111111111111111111111111111111111111111
  jq -cn --arg status "$status" --arg base "$base" --arg head "$head" \
    --argjson ahead "$ahead" --argjson behind "$behind" \
    '{status:$status,ahead_by:$ahead,behind_by:$behind,base_commit:{sha:$base},merge_base_commit:{sha:$base},commits:[{sha:$head}]}'
elif [[ "$args" == *"/git/commits/${FAKE_CONNECTOR}"* ]]; then
  tree=$FAKE_CONNECTOR_TREE; parent=$FAKE_CONNECTOR_BASE; verified=true; reason=valid
  [[ "$FAKE_MODE" != run_tree_drift ]] || tree=1111111111111111111111111111111111111111
  [[ "$FAKE_MODE" != run_parent_drift ]] || parent=1111111111111111111111111111111111111111
  [[ "$FAKE_MODE" != run_signature_drift ]] || { verified=false; reason=unsigned; }
  jq -cn --arg sha "$FAKE_CONNECTOR" --arg tree "$tree" --arg parent "$parent" \
    --argjson verified "$verified" --arg reason "$reason" \
    '{sha:$sha,tree:{sha:$tree},parents:[{sha:$parent}],verification:{verified:$verified,reason:$reason}}'
elif [[ "$args" == *'/git/ref/heads/main'* ]]; then
  sha=$FAKE_CONNECTOR_MAIN; ref=refs/heads/main; type=commit
  [[ "$FAKE_MODE" != main_ref_malformed ]] || sha=invalid
  [[ "$FAKE_MODE" != main_ref_name_drift ]] || ref=refs/heads/release
  [[ "$FAKE_MODE" != main_ref_type_drift ]] || type=tag
  [[ "$FAKE_MODE" != main_equal ]] || sha=$FAKE_CONNECTOR
  jq -cn --arg sha "$sha" --arg ref "$ref" --arg type "$type" '{ref:$ref,object:{sha:$sha,type:$type}}'
elif [[ "$args" == *"/compare/${FAKE_CONNECTOR}...${FAKE_CONNECTOR_MAIN}"* ]]; then
  status=ahead; base=$FAKE_CONNECTOR; ahead=1; behind=0
  [[ "$FAKE_MODE" != main_not_ancestor ]] || { status=diverged; base=1111111111111111111111111111111111111111; behind=1; }
  jq -cn --arg status "$status" --arg base "$base" --argjson ahead "$ahead" --argjson behind "$behind" \
    '{status:$status,ahead_by:$ahead,behind_by:$behind,base_commit:{sha:$base},merge_base_commit:{sha:$base}}'
else
  echo "unexpected gh call: $args" >&2
  exit 99
fi
EOF
chmod +x "$WORK/bin/gh"

run() {
  PATH="$WORK/bin:$PATH" GH_TOKEN=x CUTOVER_CONNECTOR_LIFECYCLE_RUN_ID=77 \
    CUTOVER_CONNECTOR_LIFECYCLE_RUN_ATTEMPT=2 \
    CUTOVER_EXPECTED_REPAIR_SOURCE_SHA=$NHP CUTOVER_EXPECTED_NHP_CONTROLLER_SOURCE_SHA=$RECOVERY \
    CUTOVER_EXPECTED_NHP_SERVER_DIGEST=$SERVER_DIGEST \
    CUTOVER_CONNECTOR_NHP_CONTROLLER_RUN_ID=66 CUTOVER_CONNECTOR_NHP_CONTROLLER_RUN_ATTEMPT=3 "$SCRIPT"
}

proof=$(run)
[[ "$proof" == "v1|layervai/qurl-connector|77|2|${CONNECTOR}|${CONNECTOR_PR}|${QURL_GO}|88|${FAKE_ZIP_DIGEST}|66|3|55|4|${RECOVERY}|${NHP}|${SERVER_DIGEST}" ]]
FAKE_MODE=main_equal
[[ "$(run)" == "$proof" ]]
for mode in reviewed_commit_drift reviewed_tree_drift base_status_drift base_sha_drift base_head_drift \
  run_tree_drift run_parent_drift run_signature_drift run_repo_drift run_head_repo_drift \
  main_ref_malformed main_ref_name_drift main_ref_type_drift main_not_ancestor failed_run missing_step artifact_drift; do
  export FAKE_MODE=$mode
  if run >/dev/null 2>&1; then
    echo "connector lifecycle verifier accepted $mode authority" >&2
    exit 1
  fi
done

echo "verify-durable-aop-connector-lifecycle-run: all tests passed"
