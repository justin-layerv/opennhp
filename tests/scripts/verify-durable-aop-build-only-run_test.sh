#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT=$ROOT/.github/scripts/verify-durable-aop-build-only-run.sh
SHA=0000000000000000000000000000000000000000
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"
export FAKE_MODE=ok FAKE_SHA=$SHA

cat >"$WORK/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args="$*"
if [[ "$args" == *'/actions/runs/55/attempts/4/jobs'* ]]; then
  force=success; [[ "$FAKE_MODE" != force_missing ]] || force=skipped
  digest=success; [[ "$FAKE_MODE" != missing_digest ]] || digest=skipped
  provenance=success; [[ "$FAKE_MODE" != missing_attestation ]] || provenance=skipped
  sbom=success; [[ "$FAKE_MODE" != missing_sbom ]] || sbom=skipped
  sbom_attest=success; [[ "$FAKE_MODE" != missing_sbom_attestation ]] || sbom_attest=skipped
  test_job=success; [[ "$FAKE_MODE" != test_failed ]] || test_job=failure
  test_step=success; [[ "$FAKE_MODE" != tests_skipped ]] || test_step=skipped
  deploy=skipped; [[ "$FAKE_MODE" != deploy_true ]] || deploy=success
  jq -cn --arg force "$force" --arg digest "$digest" --arg provenance "$provenance" \
    --arg sbom "$sbom" --arg sbom_attest "$sbom_attest" --arg test_job "$test_job" \
    --arg test_step "$test_step" --arg deploy "$deploy" '
    def step($name;$conclusion): {name:$name,conclusion:$conclusion};
    def build($name): {name:$name,conclusion:"success",steps:[
      step("Skip notice";"skipped"),step("Build image";"success"),step("Generate SBOM";$sbom),
      step("Push to ECR";"success"),step("Capture pushed image digest";$digest),
      step("Attest build provenance (SLSA)";$provenance),step("Attest SBOM";$sbom_attest),
      step("Attestation summary";"success")]};
    [{jobs:[
      {name:"Detect Changes",conclusion:"success",steps:[step("Force build override";$force)]},
      {name:"Sandbox Environment Guard",conclusion:$deploy},
      {name:"Sandbox App Image Drift",conclusion:$deploy},
      {name:"Test",conclusion:$test_job,steps:[step("Skip notice";"skipped"),
        step("Run tests (privileged container for iptables)";$test_step)]},
      build("Build server"),build("Build ac"),
      {name:"Deploy Sandbox - Infrastructure",conclusion:$deploy},
      {name:"Deploy Sandbox - QURL Service",conclusion:"skipped"},
      {name:"Deploy Sandbox - Relay",conclusion:"skipped"},
      {name:"Deploy Sandbox - Blue/Green",conclusion:"skipped"},
      {name:"Deploy Sandbox cell1 - Infrastructure",conclusion:"skipped"},
      {name:"Deploy Sandbox cell1 - Blue/Green",conclusion:"skipped"},
      {name:"Deploy Sandbox - Control",conclusion:"skipped"},
      {name:"Deploy Sandbox - Validate",conclusion:"skipped"},
      {name:"NHP Smoke (sandbox)",conclusion:"skipped"}]}]'
else
  event=workflow_dispatch; conclusion=success; sha=$FAKE_SHA; attempt=4
  [[ "$FAKE_MODE" != push_failed ]] || { event=push; conclusion=failure; }
  [[ "$FAKE_MODE" != wrong_head ]] || sha=1111111111111111111111111111111111111111
  [[ "$FAKE_MODE" != wrong_attempt ]] || attempt=5
  jq -cn --arg event "$event" --arg conclusion "$conclusion" --arg sha "$sha" --argjson attempt "$attempt" '
    {id:55,repository:{full_name:"layervai/nhp"},head_repository:{full_name:"layervai/nhp"},
     head_sha:$sha,head_branch:"main",event:$event,run_attempt:$attempt,status:"completed",
     conclusion:$conclusion,path:".github/workflows/build-and-push.yml"}'
fi
EOF
chmod +x "$WORK/bin/gh"

run() { PATH="$WORK/bin:$PATH" GH_TOKEN=x GITHUB_REPOSITORY=layervai/nhp "$SCRIPT" 55 4 "$SHA"; }
[[ "$(run)" == "v1|55|4|${SHA}" ]]
for mode in push_failed force_missing missing_digest missing_attestation missing_sbom missing_sbom_attestation test_failed tests_skipped deploy_true wrong_head wrong_attempt; do
  export FAKE_MODE=$mode
  if run >/dev/null 2>&1; then
    echo "build-only verifier accepted $mode authority" >&2
    exit 1
  fi
done

echo "verify-durable-aop-build-only-run: all tests passed"
