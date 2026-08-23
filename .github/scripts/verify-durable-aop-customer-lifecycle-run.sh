#!/usr/bin/env bash
# Verify the protected qurl-integrations-infra execution receipt and its
# transitive deployment and integration-test authority. The selected workflow
# must execute the real public-auth direct customer journeys. Relay, retry,
# lost-response, and crash behavior are accepted only from exact named tests on
# exact successful source-bound jobs; metadata alone is never acceptance.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
VERIFY_BUILD_ONLY=$ROOT/.github/scripts/verify-durable-aop-build-only-run.sh
CUSTOMER_REPOSITORY=layervai/qurl-integrations-infra
CUSTOMER_WORKFLOW=.github/workflows/qurl-sharing-sandbox.yml
NHP_REPOSITORY=layervai/nhp
NHP_PRODUCER_WORKFLOW=.github/workflows/udp-proof-deployment-manifest.yml
QURL_GO_REPOSITORY=layervai/qurl-go
QURL_GO_SOURCE_SHA=d02c25995df085f0437c7a572714c26e907a8a59
QURL_GO_CI_WORKFLOW=.github/workflows/ci.yml
QURL_GO_CI_RUN_ID=32621063743
QURL_GO_CI_RUN_ATTEMPT=1
QURL_INTEGRATIONS_CI_RUN_ID=32658570640
QURL_INTEGRATIONS_CI_RUN_ATTEMPT=1
QURL_INTEGRATIONS_PR=1247
QURL_INTEGRATIONS_PR_BASE=f1aa5795a0d45b73bd06fbf64d1dc179c4dc2a29
QURL_INTEGRATIONS_PR_BRANCH=fix/exact-session-lifecycle-smoke
# Exact merged protected-lane source plus the reviewed customer source whose
# named CLI integration job is bound below. Changes require a new review and
# receipt contract; callers cannot override either value.
APPROVED_INFRA_SHA=d30d3fce3a6c3cf15e1340a5106b6cc76bce7e82
APPROVED_INTEGRATIONS_SHA=356ecd44bbf09fca392247d971bbc093b337d4e5
RUN_ID=${CUTOVER_CUSTOMER_LIFECYCLE_RUN_ID:?CUTOVER_CUSTOMER_LIFECYCLE_RUN_ID is required}
RUN_ATTEMPT=${CUTOVER_CUSTOMER_LIFECYCLE_RUN_ATTEMPT:?CUTOVER_CUSTOMER_LIFECYCLE_RUN_ATTEMPT is required}
REPAIR_SHA=${CUTOVER_EXPECTED_REPAIR_SOURCE_SHA:?CUTOVER_EXPECTED_REPAIR_SOURCE_SHA is required}
RECOVERY_SHA=${CUTOVER_EXPECTED_RECOVERY_ORCHESTRATOR_SHA:?CUTOVER_EXPECTED_RECOVERY_ORCHESTRATOR_SHA is required}
BUILD_RUN_ID=${CUTOVER_EXPECTED_REPAIR_BUILD_RUN_ID:?CUTOVER_EXPECTED_REPAIR_BUILD_RUN_ID is required}
BUILD_RUN_ATTEMPT=${CUTOVER_EXPECTED_REPAIR_BUILD_RUN_ATTEMPT:?CUTOVER_EXPECTED_REPAIR_BUILD_RUN_ATTEMPT is required}
SERVER_DIGEST=${CUTOVER_EXPECTED_SERVER_DIGEST:?CUTOVER_EXPECTED_SERVER_DIGEST is required}
AC_DIGEST=${CUTOVER_EXPECTED_AC_DIGEST:?CUTOVER_EXPECTED_AC_DIGEST is required}
CELL0_COLOR=${CUTOVER_EXPECTED_CELL0_COLOR:?CUTOVER_EXPECTED_CELL0_COLOR is required}
CELL0_ASG=${CUTOVER_EXPECTED_CELL0_ASG:?CUTOVER_EXPECTED_CELL0_ASG is required}
CELL1_COLOR=${CUTOVER_EXPECTED_CELL1_COLOR:?CUTOVER_EXPECTED_CELL1_COLOR is required}
CELL1_ASG=${CUTOVER_EXPECTED_CELL1_ASG:?CUTOVER_EXPECTED_CELL1_ASG is required}
AC_COLOR=${CUTOVER_EXPECTED_AC_COLOR:?CUTOVER_EXPECTED_AC_COLOR is required}
AC_ASG=${CUTOVER_EXPECTED_AC_ASG:?CUTOVER_EXPECTED_AC_ASG is required}
: "${GH_TOKEN:?GH_TOKEN is required}"
NHP_GH_TOKEN=$GH_TOKEN
CUSTOMER_GH_TOKEN=${CUTOVER_CUSTOMER_GH_TOKEN:?CUTOVER_CUSTOMER_GH_TOKEN is required}
unset GH_TOKEN GITHUB_TOKEN PUBLIC_GH_TOKEN CUTOVER_CUSTOMER_GH_TOKEN CUTOVER_CONNECTOR_GH_TOKEN

[[ "$RUN_ID" =~ ^[1-9][0-9]*$ && "$RUN_ATTEMPT" =~ ^[1-9][0-9]*$ &&
   "$BUILD_RUN_ID" =~ ^[1-9][0-9]*$ && "$BUILD_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]] || {
  echo "lifecycle and build run identities must be positive integers" >&2; exit 2;
}
for sha in "$REPAIR_SHA" "$RECOVERY_SHA"; do
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "lifecycle source SHAs must be exact lowercase 40-hex" >&2; exit 2; }
done
for digest in "$SERVER_DIGEST" "$AC_DIGEST"; do
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "expected image digests must be canonical SHA-256" >&2; exit 2; }
done
[[ "$SERVER_DIGEST" != "$AC_DIGEST" ]] || { echo "server and AC image digests must be distinct" >&2; exit 2; }
for color in "$CELL0_COLOR" "$CELL1_COLOR" "$AC_COLOR"; do
  [[ "$color" == blue || "$color" == green ]] || { echo "expected active colors must be blue or green" >&2; exit 2; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
customer_gh() {
  env -u GITHUB_TOKEN -u NHP_GH_TOKEN -u PUBLIC_GH_TOKEN \
    GH_TOKEN="$CUSTOMER_GH_TOKEN" gh "$@"
}
nhp_gh() {
  env -u GITHUB_TOKEN -u CUSTOMER_GH_TOKEN -u PUBLIC_GH_TOKEN \
    GH_TOKEN="$NHP_GH_TOKEN" gh "$@"
}

public_api_get() {
  local path=$1 output=$2 status bytes
  status=$(env -u GH_TOKEN -u GITHUB_TOKEN -u NHP_GH_TOKEN -u CUSTOMER_GH_TOKEN \
    -u PUBLIC_GH_TOKEN -u CUTOVER_CUSTOMER_GH_TOKEN -u CUTOVER_CONNECTOR_GH_TOKEN \
    curl --disable --fail --silent --show-error \
      --proto '=https' --tlsv1.2 --max-redirs 0 \
      --connect-timeout 10 --max-time 30 --max-filesize 4194304 \
      --header 'Accept: application/vnd.github+json' \
      --header 'X-GitHub-Api-Version: 2022-11-28' \
      --output "$output" --write-out '%{http_code}' \
      "https://api.github.com/$path") || {
    echo "public GitHub authority request failed" >&2
    return 1
  }
  [[ "$status" == 200 ]] || {
    echo "public GitHub authority request did not return 200" >&2
    return 1
  }
  [[ -f "$output" && ! -L "$output" ]] || {
    echo "public GitHub authority response is not a regular file" >&2
    return 1
  }
  bytes=$(wc -c <"$output" | tr -d '[:space:]')
  [[ "$bytes" =~ ^[0-9]+$ && "$bytes" -gt 0 && "$bytes" -le 4194304 ]] || {
    echo "public GitHub authority response exceeds the bounded size" >&2
    return 1
  }
  jq -e . "$output" >/dev/null || {
    echo "public GitHub authority response is not JSON" >&2
    return 1
  }
}

authority_api_get() {
  local access=$1 repository=$2 path=$3 output=$4
  case "$access:$repository" in
    private:layervai/nhp)
      nhp_gh api "$path" >"$output"
      ;;
    public:layervai/qurl-go)
      [[ "$path" == "repos/layervai/qurl-go/git/ref/tags/v0.8.0" ||
         "$path" == "repos/layervai/qurl-go/actions/runs/${QURL_GO_CI_RUN_ID}/attempts/${QURL_GO_CI_RUN_ATTEMPT}" ||
         "$path" == "repos/layervai/qurl-go/actions/runs/${QURL_GO_CI_RUN_ID}/attempts/${QURL_GO_CI_RUN_ATTEMPT}/jobs?per_page=100" ]] || {
        echo "public qurl-go authority route is not allowlisted" >&2
        return 1
      }
      public_api_get "$path" "$output"
      ;;
    public:layervai/qurl-integrations)
      [[ "$path" == "repos/layervai/qurl-integrations/actions/runs/${QURL_INTEGRATIONS_CI_RUN_ID}/attempts/${QURL_INTEGRATIONS_CI_RUN_ATTEMPT}" ||
         "$path" == "repos/layervai/qurl-integrations/actions/runs/${QURL_INTEGRATIONS_CI_RUN_ID}/attempts/${QURL_INTEGRATIONS_CI_RUN_ATTEMPT}/jobs?per_page=100" ]] || {
        echo "public qurl-integrations authority route is not allowlisted" >&2
        return 1
      }
      public_api_get "$path" "$output"
      ;;
    *)
      echo "repository authority transport classification is invalid" >&2
      return 1
      ;;
  esac
}

verify_run() {
  local access=$1 repository=$2 run_id=$3 attempt=$4 head=$5 workflow=$6 event=$7 label=$8 run
  local run_file
  run_file=$(mktemp "$WORK/run.XXXXXX")
  authority_api_get "$access" "$repository" \
    "repos/${repository}/actions/runs/${run_id}/attempts/${attempt}" "$run_file"
  run=$(<"$run_file")
  jq -e --arg repository "$repository" --arg run_id "$run_id" --arg head "$head" \
    --arg workflow "$workflow" --arg event "$event" --argjson attempt "$attempt" '
      (.id | tostring) == $run_id and .repository.full_name == $repository and
      .head_repository.full_name == $repository and .head_sha == $head and .head_branch == "main" and
      .event == $event and .run_attempt == $attempt and .status == "completed" and
      .conclusion == "success" and
      (.path == $workflow or .path == ($repository + "/" + $workflow + "@refs/heads/main"))
    ' >/dev/null <<<"$run" || {
      echo "$label is not the exact successful trusted-main workflow attempt" >&2
      return 1
    }
}

verify_job_step() {
  local access=$1 repository=$2 run_id=$3 attempt=$4 job=$5 step=$6 label=$7 jobs
  local jobs_file
  jobs_file=$(mktemp "$WORK/jobs.XXXXXX")
  authority_api_get "$access" "$repository" \
    "repos/${repository}/actions/runs/${run_id}/attempts/${attempt}/jobs?per_page=100" "$jobs_file"
  jq -e '.total_count <= 100 and (.jobs | type == "array") and (.jobs | length) == .total_count' \
    "$jobs_file" >/dev/null || {
    echo "$label job list exceeds the bounded single-page authority" >&2
    return 1
  }
  jobs=$(<"$jobs_file")
  jq -e --arg job "$job" --arg step "$step" '
    [.jobs[] | select(.name == $job and .conclusion == "success")] as $jobs |
    ($jobs | length == 1) and
    ([$jobs[0].steps[]? | select(.name == $step and .conclusion == "success")] | length == 1)
  ' >/dev/null <<<"$jobs" || {
    echo "$label lacks the exact successful job and step" >&2
    return 1
  }
}

verify_integrations_pr_job_authority() {
  local run jobs run_file jobs_file
  run_file=$(mktemp "$WORK/integrations-run.XXXXXX")
  authority_api_get public layervai/qurl-integrations \
    "repos/layervai/qurl-integrations/actions/runs/${QURL_INTEGRATIONS_CI_RUN_ID}/attempts/${QURL_INTEGRATIONS_CI_RUN_ATTEMPT}" \
    "$run_file"
  run=$(<"$run_file")
  jq -e --arg run_id "$QURL_INTEGRATIONS_CI_RUN_ID" --arg head "$INTEGRATIONS_SHA" \
    --arg branch "$QURL_INTEGRATIONS_PR_BRANCH" --arg base "$QURL_INTEGRATIONS_PR_BASE" \
    --argjson attempt "$QURL_INTEGRATIONS_CI_RUN_ATTEMPT" --argjson pr "$QURL_INTEGRATIONS_PR" '
      (.id | tostring) == $run_id and
      .repository.full_name == "layervai/qurl-integrations" and
      .head_repository.full_name == "layervai/qurl-integrations" and
      .head_sha == $head and .head_branch == $branch and .event == "pull_request" and
      .run_attempt == $attempt and .status == "completed" and .conclusion == "failure" and
      .path == ".github/workflows/cli.yml" and
      (.pull_requests | type == "array" and length == 1 and .[0].number == $pr and
        .[0].head.sha == $head and .[0].base.sha == $base)
    ' >/dev/null <<<"$run" || {
      echo "qurl-integrations lifecycle integration run is not the exact reviewed PR attempt" >&2
      return 1
    }
  jobs_file=$(mktemp "$WORK/integrations-jobs.XXXXXX")
  authority_api_get public layervai/qurl-integrations \
    "repos/layervai/qurl-integrations/actions/runs/${QURL_INTEGRATIONS_CI_RUN_ID}/attempts/${QURL_INTEGRATIONS_CI_RUN_ATTEMPT}/jobs?per_page=100" \
    "$jobs_file"
  jq -e '.total_count <= 100 and (.jobs | type == "array") and (.jobs | length) == .total_count' \
    "$jobs_file" >/dev/null || {
    echo "qurl-integrations lifecycle job list exceeds the bounded single-page authority" >&2
    return 1
  }
  jobs=$(<"$jobs_file")
  jq -e --arg head "$INTEGRATIONS_SHA" '
    [.jobs[] | select(.name == "cli / test" and .head_sha == $head and .conclusion == "success")] as $jobs |
    ($jobs | length == 1) and
    ([$jobs[0].steps[]? | select(.name == "Run tests with coverage" and .conclusion == "success")] | length == 1)
  ' >/dev/null <<<"$jobs" || {
    echo "qurl-integrations lifecycle integration run lacks the exact successful source-bound CLI job" >&2
    return 1
  }
}

INTEGRATIONS_SHA=$APPROVED_INTEGRATIONS_SHA
[[ "$INTEGRATIONS_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo "qurl-integrations lifecycle source is not the final reviewed authority" >&2; exit 1;
}
customer_run=$(customer_gh api "repos/${CUSTOMER_REPOSITORY}/actions/runs/${RUN_ID}/attempts/${RUN_ATTEMPT}")
INFRA_SHA=$(jq -er --arg repository "$CUSTOMER_REPOSITORY" --arg run "$RUN_ID" \
  --arg workflow "$CUSTOMER_WORKFLOW" --argjson attempt "$RUN_ATTEMPT" '
  select((.id | tostring) == $run and .repository.full_name == $repository and
    .head_repository.full_name == $repository and .head_branch == "main" and
    .event == "workflow_dispatch" and .run_attempt == $attempt and
    .status == "completed" and .conclusion == "success" and
    (.path == $workflow or .path == ($repository + "/" + $workflow + "@refs/heads/main"))) |
  .head_sha | select(type == "string" and test("^[0-9a-f]{40}$"))
' <<<"$customer_run") || {
  echo "customer lifecycle run is not the exact successful trusted-main workflow attempt" >&2; exit 1;
}
[[ "$INFRA_SHA" == "$APPROVED_INFRA_SHA" ]] || {
  echo "qurl-infra lifecycle source is not the final reviewed execution authority" >&2; exit 1;
}

jobs=$(customer_gh api --paginate \
  "repos/${CUSTOMER_REPOSITORY}/actions/runs/${RUN_ID}/attempts/${RUN_ATTEMPT}/jobs?per_page=100" --slurp)
jq -e '
  [.[].jobs[] | select(.name == "Protected qURL sharing sandbox lifecycle")] as $protected |
  ($protected | length == 1) and ($protected[0].conclusion == "success") and
  ($protected[0].steps as $steps |
   ["Verify exact qurl-integrations source",
    "Verify qurl-connector module selection",
    "Verify qurl-integrations binary attestation",
    "Verify exact repaired NHP deployment authority",
    "Acquire customer Auth0 JWT through public API",
    "Create ordinary customer API key",
    "Run host customer-lifecycle smoke",
    "Run host sibling-continuity journey",
    "Run host CRID lifecycle journey",
    "Run hardened customer-lifecycle smoke",
    "Run hardened sibling-continuity journey",
    "Verify exact lifecycle integration-test authorities",
    "Revoke ordinary customer API key",
    "Verify revoked key rejection after cache horizon",
    "Build immutable durable AOP lifecycle receipt",
    "Upload immutable durable AOP lifecycle receipt"] |
   all(. as $required | [$steps[] | select(.name == $required and .conclusion == "success")] | length == 1))
' >/dev/null <<<"$jobs" || {
  echo "protected lifecycle job did not execute every required customer journey" >&2; exit 1;
}

artifact_name="durable-aop-lifecycle-receipt-${INTEGRATIONS_SHA}"
artifacts=$(customer_gh api --paginate \
  "repos/${CUSTOMER_REPOSITORY}/actions/runs/${RUN_ID}/artifacts?per_page=100" --slurp)
artifact=$(jq -ce --arg name "$artifact_name" --arg run "$RUN_ID" '
  [.[].artifacts[] | select(.name == $name and .expired == false)] |
  select(length == 1) | .[0] |
  select((.id | type == "number" and . > 0) and
         (.digest | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
         (.size_in_bytes | type == "number" and . > 0 and . <= 1048576) and
         (.workflow_run.id | tostring) == $run)
' <<<"$artifacts") || {
  echo "protected lifecycle artifact identity is malformed" >&2; exit 1;
}
artifact_id=$(jq -r '.id | tostring' <<<"$artifact")
artifact_digest=$(jq -r .digest <<<"$artifact")
customer_gh api "repos/${CUSTOMER_REPOSITORY}/actions/artifacts/${artifact_id}/zip" >"$WORK/customer.zip"
[[ "sha256:$(sha256_file "$WORK/customer.zip")" == "$artifact_digest" ]] || {
  echo "downloaded lifecycle artifact digest differs from GitHub authority" >&2; exit 1;
}

python3 - "$WORK/customer.zip" "$WORK/customer" <<'PY'
import pathlib, stat, sys, zipfile
archive, output = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
expected = {
    "durable-aop-lifecycle-receipt.json", "nhp-deployment-authority.json",
    "qurl.modules.txt", "selection.json", "test.modules.txt",
    "verified-subjects.sha256",
}
with zipfile.ZipFile(archive) as zf:
    infos = zf.infolist()
    if len(infos) != 6 or {i.filename for i in infos} != expected:
        raise SystemExit("lifecycle artifact does not have the exact six-file contract")
    total = 0
    output.mkdir(mode=0o700)
    for info in infos:
        mode = info.external_attr >> 16
        if pathlib.PurePosixPath(info.filename).name != info.filename or stat.S_ISLNK(mode):
            raise SystemExit("lifecycle artifact contains an unsafe member")
        if info.file_size > 262144:
            raise SystemExit("lifecycle artifact member exceeds 256 KiB")
        total += info.file_size
        if total > 1048576:
            raise SystemExit("lifecycle artifact exceeds 1 MiB")
        (output / info.filename).write_bytes(zf.read(info))
PY

RECEIPT=$WORK/customer/durable-aop-lifecycle-receipt.json
AUTHORITY=$WORK/customer/nhp-deployment-authority.json
SELECTION=$WORK/customer/selection.json
QURL_MODULES=$WORK/customer/qurl.modules.txt
TEST_MODULES=$WORK/customer/test.modules.txt
SUBJECTS=$WORK/customer/verified-subjects.sha256
jq -S . "$AUTHORITY" >"$WORK/authority.canonical"
cmp -s "$AUTHORITY" "$WORK/authority.canonical" || {
  echo "NHP deployment authority is not canonical jq-S JSON" >&2; exit 1;
}
authority_sha=$(sha256_file "$AUTHORITY")
selection_sha=$(sha256_file "$SELECTION")
qurl_modules_sha=$(sha256_file "$QURL_MODULES")
test_modules_sha=$(sha256_file "$TEST_MODULES")

jq -e --arg integrations "$INTEGRATIONS_SHA" '
  type == "object" and
  (keys | sort) == ["connector_attended_gate","integrations_sha","pull_request_number","qurl_connector","qurl_go","schema","source_kind","source_profile"] and
  .schema == "layerv.qurl-sharing-canary.v2" and .integrations_sha == $integrations and
  .source_kind == "pull_request" and .pull_request_number == 1247 and .source_profile == "cli_only" and
  .qurl_connector == null and
  .qurl_go == {path:"github.com/layervai/qurl-go",version:"v0.8.0",
    sum:"h1:Tw8291djSj3LT+aGWPW7PPuIEBeAKcIG3h2CddxFlzk=",
    go_mod_sum:"h1:zujbZnolKJzJEDyKwgUqulhHSi0sZeU2w1x+nle/yeM="} and
  .connector_attended_gate == {required:true,satisfied_by_this_run:false,
    repository:"layervai/qurl-connector",pull_request:609,
    workflow:".github/workflows/sandbox-smoke.yml",job:"Attended Connector UDP proof (strict)"}
' "$SELECTION" >/dev/null || { echo "selection.json is not exact CLI lifecycle authority" >&2; exit 1; }

qurl_go_sum=$(jq -r .qurl_go.sum "$SELECTION")
for modules in "$QURL_MODULES" "$TEST_MODULES"; do
  grep -Fx $'\tdep\tgithub.com/layervai/qurl-go\tv0.8.0\t'"$qurl_go_sum" "$modules" >/dev/null || {
    echo "built lifecycle subject lacks exact qurl-go v0.8.0 authority" >&2; exit 1;
  }
  ! grep -Fq $'\tdep\tgithub.com/layervai/qurl-connector\t' "$modules" || {
    echo "CLI-only lifecycle subject unexpectedly includes qurl-connector" >&2; exit 1;
  }
done

jq -e --arg infra "$INFRA_SHA" --arg integrations "$INTEGRATIONS_SHA" \
  --arg run "$RUN_ID" --argjson attempt "$RUN_ATTEMPT" \
  --arg authority_sha "$authority_sha" --arg qurl_modules_sha "$qurl_modules_sha" \
  --arg test_modules_sha "$test_modules_sha" --slurpfile authority "$AUTHORITY" \
  --slurpfile selection "$SELECTION" '
  type == "object" and
  (keys | sort) == ["connector_attended_gate","customer_auth","integration_tests","live_customer_steps","modules","nhp_deployment","orchestrator","schema","source","subjects"] and
  .schema == "layerv.durable-aop-lifecycle-receipt.v4" and
  .orchestrator == {repository:"layervai/qurl-integrations-infra",
    workflow:".github/workflows/qurl-sharing-sandbox.yml",sha:$infra,
    run_id:($run|tonumber),run_attempt:$attempt} and
  .source == {repository:"layervai/qurl-integrations",sha:$integrations,kind:"pull_request",
    pull_request_number:1247,profile:"cli_only"} and
  .modules == {qurl_go:$selection[0].qurl_go,qurl_connector:null} and
  .nhp_deployment == {authority_sha256:$authority_sha,authority:$authority[0]} and
  (.subjects | type == "object" and (keys | sort) == ["qurl","test_harness"]) and
  ([.subjects.qurl,.subjects.test_harness] | all(
    (keys | sort) == ["build_attestation","modules_sha256","sha256"] and
    (.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    (.modules_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    .build_attestation == {verified:true,repository:"layervai/qurl-integrations-infra",
      workflow:".github/workflows/qurl-sharing-sandbox.yml",source_ref:"refs/heads/main",source_sha:$infra})) and
  .subjects.qurl.modules_sha256 == $qurl_modules_sha and
  .subjects.test_harness.modules_sha256 == $test_modules_sha and
  .customer_auth == {
    mode:"auth0_public_api_key",
    auth0_jwt:"passed",
    public_api_key_create:"passed",
    key_authenticated_lifecycle:"passed",
    public_api_key_revoke:"passed",
    post_cache_horizon_rejection:"passed",
    sandbox_credential_endpoint:false,
    sandbox_credential_selector:null,
    operations:{
      create:{method:"POST",path:"/v1/api-keys",status:201,auth:"auth0_jwt"},
      identity:{method:"GET",path:"/v1/me",status:200,auth:"api_key"},
      revoke:{method:"DELETE",path:"/v1/api-keys/{key_id}",status:204,auth:"auth0_jwt"},
      rejection:{method:"GET",path:"/v1/me",status:401,auth:"revoked_api_key",after_cache_horizon:true}}} and
  .live_customer_steps == {
    sequential_lifecycle:{name:"TestSandboxLocalPublishLifecycleSmoke",runtimes:["hardened_container","host"],result:"passed",
      two_distinct_registered_sessions:"passed",exact_retire_each_session:"passed",
      replacement_admission:"passed",durable_identity_continuity:"passed"},
    sibling_continuity:{name:"TestSandboxLocalPublishSiblingContinuity",runtimes:["hardened_container","host"],result:"passed",
      two_real_processes:"passed",get_a_and_b_before_retire:"passed",retire_a:"passed",
      get_b_while_a_retired:"passed",restart_a_same_state_resource:"passed",
      get_a_and_b_after_restart:"passed",exact_retire_cleanup:"passed"},
    crid_lifecycle:{name:"TestSandboxCRIDJourney",runtime:"host",result:"passed",
      create_list_resolve_get_delete:"passed",idempotent_resource_delete:"passed"}} and
  .integration_tests == {
    nhp:{repository:"layervai/nhp",source_sha:$authority[0].deployment.repair_source_sha,
      workflow:".github/workflows/build-and-push.yml",run_id:($authority[0].deployment.build.run_id|tonumber),
      run_attempt:($authority[0].deployment.build.run_attempt|tonumber),event:"workflow_dispatch",
      job:"Test",step:"Run tests (privileged container for iptables)",result:"passed",
      tests:["TestE2E_RelayCrossServer_KnockForwardedToRemoteAC_AckReturnsViaRelay",
        "TestExactSessionFleetCompensationClosesRemoteForwardedSessionOnly",
        "TestHandleKnockRequestSendFailureCompensatesRemoteAdmissions",
        "TestHandleRelayForward_ExactSessionRetirementReturnsDurableReceipt",
        "TestSessionControlLifecycleRecoveryResumesAfterCompleteAndClearsClosingDueAuthority",
        "TestSessionControlRecoveryClosesReservedCrashGapAfterAckEnqueue"]},
    qurl_go:{repository:"layervai/qurl-go",source_sha:"d02c25995df085f0437c7a572714c26e907a8a59",
      workflow:".github/workflows/ci.yml",run_id:32621063743,run_attempt:1,event:"push",
      job:"vet + test -race",step:"go test -race + coverage",result:"passed",
      tests:["TestConnectAgentRuntime_LostRAKRestartExactReplayAfterTicketExpiry",
        "TestConnectAgentRuntime_ResumesPersistedCandidateAfterLostCompletionReply",
        "TestConsumeNativeExactSessionCloseReply_StrictAuthority",
        "TestRetireRegisteredAgentSession_ClassifiesReceiptAndTransportFailures",
        "TestRetireRegisteredAgentSession_UsesExactReceiptOriginalEndpointAndRetriesIdempotently"]},
    qurl_integrations:{repository:"layervai/qurl-integrations",source_sha:$integrations,
      workflow:".github/workflows/cli.yml",run_id:32658570640,run_attempt:1,event:"pull_request",
      job:"cli / test",step:"Run tests with coverage",result:"passed",
      tests:["TestNativeBlocksNewCycleAdmissionUntilPriorReceiptRetires",
        "TestNativeEndCycleRetriesExactReceiptUntilAccepted",
        "TestNativeLostKnockReplyDoesNotFabricateRetirement",
        "TestNativeLostReplyConsumesAttemptWithoutFabricatingReceipt",
        "TestNativeRetirementFailureBlocksReplacementAdmission",
        "TestNativeUsesMonotonicAttemptsAndRetiresEveryReceipt"]}} and
  (.integration_tests.qurl_integrations.run_id | type == "number" and . > 0) and
  (.integration_tests.qurl_integrations.run_attempt | type == "number" and . > 0) and
  .connector_attended_gate == {required:true,satisfied_by_this_run:false,
    repository:"layervai/qurl-connector",pull_request:609,
    workflow:".github/workflows/sandbox-smoke.yml",job:"Attended Connector UDP proof (strict)"}
' "$RECEIPT" >/dev/null || { echo "lifecycle execution receipt is malformed or cross-bound" >&2; exit 1; }

qurl_sha=$(jq -r .subjects.qurl.sha256 "$RECEIPT")
test_sha=$(jq -r .subjects.test_harness.sha256 "$RECEIPT")
python3 - "$SUBJECTS" "$qurl_sha" "$test_sha" "$qurl_modules_sha" "$test_modules_sha" "$selection_sha" <<'PY'
import pathlib, re, sys
expected = {
    "qurl": sys.argv[2], "qurl-sharing-sandbox.test": sys.argv[3],
    "qurl.modules.txt": sys.argv[4], "test.modules.txt": sys.argv[5],
    "selection.json": sys.argv[6],
}
seen = {}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
    if not match or match.group(2) in seen:
        raise SystemExit("verified-subjects contains a malformed or duplicate row")
    seen[match.group(2)] = match.group(1)
if seen != expected:
    raise SystemExit("verified-subjects does not bind the exact lifecycle subjects")
PY

qurl_go_tag_file=$WORK/qurl-go-tag.json
authority_api_get public "$QURL_GO_REPOSITORY" \
  "repos/${QURL_GO_REPOSITORY}/git/ref/tags/v0.8.0" "$qurl_go_tag_file"
qurl_go_tag=$(<"$qurl_go_tag_file")
jq -e --arg sha "$QURL_GO_SOURCE_SHA" '
  .ref == "refs/tags/v0.8.0" and .object.sha == $sha and .object.type == "commit" and
  (.object.url | type == "string" and endswith("/git/commits/" + $sha))
' >/dev/null <<<"$qurl_go_tag" || {
  echo "qurl-go v0.8.0 tag is not the exact reviewed integration source" >&2; exit 1;
}
verify_run public "$QURL_GO_REPOSITORY" "$QURL_GO_CI_RUN_ID" "$QURL_GO_CI_RUN_ATTEMPT" \
  "$QURL_GO_SOURCE_SHA" "$QURL_GO_CI_WORKFLOW" push "qurl-go lifecycle integration tests"
verify_job_step public "$QURL_GO_REPOSITORY" "$QURL_GO_CI_RUN_ID" "$QURL_GO_CI_RUN_ATTEMPT" \
  "vet + test -race" "go test -race + coverage" "qurl-go lifecycle integration tests"

verify_integrations_pr_job_authority

jq -e --arg repair "$REPAIR_SHA" --arg recovery "$RECOVERY_SHA" \
  --arg build_run "$BUILD_RUN_ID" --arg build_attempt "$BUILD_RUN_ATTEMPT" \
  --arg server_digest "$SERVER_DIGEST" --arg ac_digest "$AC_DIGEST" \
  --arg c0_color "$CELL0_COLOR" --arg c0_asg "$CELL0_ASG" \
  --arg c1_color "$CELL1_COLOR" --arg c1_asg "$CELL1_ASG" \
  --arg ac_color "$AC_COLOR" --arg ac_asg "$AC_ASG" '
  type == "object" and (keys | sort) == ["artifact","deployment","schema"] and
  .schema == "layerv.durable-aop-nhp-authority.v1" and
  (.artifact | type == "object" and (keys | sort) == ["digest","id","name","repository"] and
    .repository == "layervai/nhp" and .name == ("durable-aop-nhp-deployment-" + $repair) and
    (.id | type == "string" and test("^[1-9][0-9]*$")) and
    (.digest | type == "string" and test("^sha256:[0-9a-f]{64}$"))) and
  (.deployment as $d |
    ($d | type == "object" and (keys | sort) == ["build","deployments","environment","images","producer","profile","recovery_orchestrator_sha","repair_source_sha","repository","schema"]) and
    $d.schema == "layerv.durable-aop-nhp-deployment.v1" and $d.repository == "layervai/nhp" and
    $d.environment == "sandbox" and $d.profile == "durable-aop-v1" and
    $d.repair_source_sha == $repair and $d.recovery_orchestrator_sha == $recovery and
    $d.build == {workflow:".github/workflows/build-and-push.yml",run_id:$build_run,
      run_attempt:$build_attempt,head_sha:$repair} and
    ($d.producer | type == "object" and (keys | sort) == ["head_sha","run_attempt","run_id","source_sha","workflow"] and
      .workflow == ".github/workflows/udp-proof-deployment-manifest.yml" and
      .source_sha == $recovery and .head_sha == $recovery and
      (.run_id | type == "string" and test("^[1-9][0-9]*$")) and
      (.run_attempt | type == "string" and test("^[1-9][0-9]*$"))) and
    $d.images == {server:{repository:"layerv/nhp-server",digest:$server_digest},
      ac:{repository:"layerv/nhp-ac",digest:$ac_digest}} and
    $d.deployments == {
      cell0:{environment:"sandbox",component:"server",active_color:$c0_color,active_asg:$c0_asg,image_digest:$server_digest},
      cell1:{environment:"sandbox-cell1",component:"server",active_color:$c1_color,active_asg:$c1_asg,image_digest:$server_digest},
      ac:{environment:"sandbox",component:"ac",active_color:$ac_color,active_asg:$ac_asg,image_digest:$ac_digest}})
' "$AUTHORITY" >/dev/null || { echo "embedded NHP deployment authority differs from this schema-3 repair" >&2; exit 1; }

producer_run=$(jq -r .deployment.producer.run_id "$AUTHORITY")
producer_attempt=$(jq -r .deployment.producer.run_attempt "$AUTHORITY")
nhp_artifact_id=$(jq -r .artifact.id "$AUTHORITY")
nhp_artifact_digest=$(jq -r .artifact.digest "$AUTHORITY")
verify_run private "$NHP_REPOSITORY" "$producer_run" "$producer_attempt" "$RECOVERY_SHA" \
  "$NHP_PRODUCER_WORKFLOW" workflow_dispatch "NHP deployment producer"
build_receipt=$(GH_TOKEN=$NHP_GH_TOKEN GITHUB_REPOSITORY=$NHP_REPOSITORY \
  "$VERIFY_BUILD_ONLY" "$BUILD_RUN_ID" "$BUILD_RUN_ATTEMPT" "$REPAIR_SHA")
[[ "$build_receipt" == "v1|${BUILD_RUN_ID}|${BUILD_RUN_ATTEMPT}|${REPAIR_SHA}" ]] || {
  echo "NHP repair build-only receipt is malformed" >&2; exit 1;
}

nhp_artifacts=$(nhp_gh api --paginate \
  "repos/${NHP_REPOSITORY}/actions/runs/${producer_run}/artifacts?per_page=100" --slurp)
jq -e --arg id "$nhp_artifact_id" --arg name "durable-aop-nhp-deployment-${REPAIR_SHA}" \
  --arg digest "$nhp_artifact_digest" --arg run "$producer_run" '
  [.[].artifacts[] | select(.name == $name and .expired == false)] |
  length == 1 and (.[0] |
    (.id | tostring) == $id and .digest == $digest and
    (.size_in_bytes | type == "number" and . > 0 and . <= 131072) and
    (.workflow_run.id | tostring) == $run)
' >/dev/null <<<"$nhp_artifacts" || {
  echo "embedded NHP artifact identity differs from GitHub authority" >&2; exit 1;
}
nhp_gh api "repos/${NHP_REPOSITORY}/actions/artifacts/${nhp_artifact_id}/zip" >"$WORK/nhp.zip"
[[ "sha256:$(sha256_file "$WORK/nhp.zip")" == "$nhp_artifact_digest" ]] || {
  echo "downloaded NHP artifact digest differs from GitHub authority" >&2; exit 1;
}
python3 - "$WORK/nhp.zip" "$WORK/deployment.json" <<'PY'
import pathlib, stat, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as zf:
    infos = zf.infolist()
    if len(infos) != 1 or infos[0].filename != "durable-aop-nhp-deployment.json":
        raise SystemExit("NHP deployment artifact does not have the exact one-file contract")
    info = infos[0]
    if stat.S_ISLNK(info.external_attr >> 16) or info.file_size > 65536:
        raise SystemExit("NHP deployment artifact member is unsafe or oversized")
    pathlib.Path(sys.argv[2]).write_bytes(zf.read(info))
PY
jq -cS . "$WORK/deployment.json" >"$WORK/deployment.canonical"
cmp -s "$WORK/deployment.json" "$WORK/deployment.canonical" || {
  echo "downloaded NHP deployment manifest is not canonical compact JSON" >&2; exit 1;
}
jq -e --slurpfile authority "$AUTHORITY" '. == $authority[0].deployment' \
  "$WORK/deployment.json" >/dev/null || {
  echo "downloaded NHP deployment manifest differs from embedded authority" >&2; exit 1;
}

printf 'v2|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
  "$CUSTOMER_REPOSITORY" "$RUN_ID" "$RUN_ATTEMPT" "$INFRA_SHA" "$INTEGRATIONS_SHA" \
  "$artifact_id" "$artifact_digest" "$producer_run" "$producer_attempt" \
  "$nhp_artifact_id" "$nhp_artifact_digest" "$REPAIR_SHA" "$RECOVERY_SHA" \
  "$BUILD_RUN_ID" "$BUILD_RUN_ATTEMPT" "$SERVER_DIGEST" "$AC_DIGEST" "$authority_sha"
