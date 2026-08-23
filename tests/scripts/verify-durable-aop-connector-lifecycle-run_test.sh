#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT=$ROOT/.github/scripts/verify-durable-aop-connector-lifecycle-run.sh
CONNECTOR=0000000000000000000000000000000000000000
CONNECTOR_PR=0000000000000000000000000000000000000000
NHP=0123456789012345678901234567890123456789
RECOVERY=9999999999999999999999999999999999999999
QURL_GO=d02c25995df085f0437c7a572714c26e907a8a59
SERVER_DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/artifact"
export FAKE_MODE=ok FAKE_CONNECTOR=$CONNECTOR FAKE_CONNECTOR_PR=$CONNECTOR_PR FAKE_NHP=$NHP FAKE_SERVER_DIGEST=$SERVER_DIGEST

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
if [[ "$args" == *'/pulls/609'* ]]; then
  head=$FAKE_CONNECTOR_PR; merge=$FAKE_CONNECTOR; merged=true; state=closed
  [[ "$FAKE_MODE" != pr_drift ]] || head=1111111111111111111111111111111111111111
  [[ "$FAKE_MODE" != unmerged ]] || { merged=false; state=open; }
  jq -cn --arg head "$head" --arg merge "$merge" --arg state "$state" --argjson merged "$merged" \
    '{number:609,state:$state,merged:$merged,merge_commit_sha:$merge,head:{sha:$head,repo:{full_name:"layervai/qurl-connector"}}}'
elif [[ "$args" == *'/actions/runs/77/attempts/2/jobs'* ]]; then
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
  jq -cn --arg sha "$FAKE_CONNECTOR" --arg conclusion "$conclusion" \
    '{head_sha:$sha,head_branch:"main",event:"workflow_dispatch",run_attempt:2,
      status:"completed",conclusion:$conclusion,path:".github/workflows/sandbox-smoke.yml"}'
else
  echo "unexpected gh call: $args" >&2
  exit 99
fi
EOF
chmod +x "$WORK/bin/gh"

run() {
  PATH="$WORK/bin:$PATH" GH_TOKEN=x CUTOVER_CONNECTOR_LIFECYCLE_RUN_ID=77 \
    CUTOVER_CONNECTOR_LIFECYCLE_RUN_ATTEMPT=2 CUTOVER_CONNECTOR_LIFECYCLE_SOURCE_SHA=$CONNECTOR \
    CUTOVER_CONNECTOR_PR_HEAD_SHA=$CONNECTOR_PR \
    CUTOVER_EXPECTED_REPAIR_SOURCE_SHA=$NHP CUTOVER_EXPECTED_NHP_CONTROLLER_SOURCE_SHA=$RECOVERY \
    CUTOVER_EXPECTED_NHP_SERVER_DIGEST=$SERVER_DIGEST \
    CUTOVER_CONNECTOR_NHP_CONTROLLER_RUN_ID=66 CUTOVER_CONNECTOR_NHP_CONTROLLER_RUN_ATTEMPT=3 "$SCRIPT"
}

proof=$(run)
[[ "$proof" == "v1|layervai/qurl-connector|77|2|${CONNECTOR}|${CONNECTOR_PR}|${QURL_GO}|88|${FAKE_ZIP_DIGEST}|66|3|55|4|${RECOVERY}|${NHP}|${SERVER_DIGEST}" ]]
for mode in pr_drift unmerged failed_run missing_step artifact_drift; do
  export FAKE_MODE=$mode
  if run >/dev/null 2>&1; then
    echo "connector lifecycle verifier accepted $mode authority" >&2
    exit 1
  fi
done

echo "verify-durable-aop-connector-lifecycle-run: all tests passed"
