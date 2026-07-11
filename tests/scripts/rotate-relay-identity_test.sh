#!/usr/bin/env bash

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/rotate-relay-identity.sh"
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "$TMP_ROOT"' EXIT

pass=0
fail=0
LAST_OUT=""
LAST_RC=0
LAST_STATE=""

ok() { pass=$((pass + 1)); printf '  PASS %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL %s: %s\n' "$1" "$2"; }

make_fake_aws() {
  local bin="$1"
  mkdir -p "$bin"
  cat >"$bin/sleep" <<'SLEEP'
#!/usr/bin/env bash
exit 0
SLEEP
  chmod +x "$bin/sleep"
  cat >"$bin/aws" <<'AWS'
#!/usr/bin/env bash
set -euo pipefail
state=${FAKE_AWS_STATE:?}
printf '%q ' "$@" >>"$state/argv"
printf '\n' >>"$state/argv"

arg_after() {
  local wanted=$1 previous=""
  shift
  for arg in "$@"; do
    if [[ "$previous" == "$wanted" ]]; then printf '%s' "$arg"; return; fi
    previous=$arg
  done
}

case "$1 $2" in
  "sts get-caller-identity")
    printf '%s\n' "${FAKE_ACCOUNT:-123456789012}"
    ;;
  "secretsmanager describe-secret")
    region=$(arg_after --region "$@")
    name=$(arg_after --secret-id "$@")
    actual_name=${FAKE_SECRET_NAME:-$name}
    arn_region=${FAKE_ARN_REGION:-$region}
    jq -n --arg arn "arn:aws:secretsmanager:${arn_region}:${FAKE_ACCOUNT:-123456789012}:secret:${actual_name}-abcdef" --arg name "$actual_name" '{ARN:$arn,Name:$name}'
    ;;
  "lambda get-function-configuration")
    region=$(arg_after --region "$@")
    name=$(arg_after --function-name "$@")
    jq -n --arg arn "arn:aws:lambda:${region}:${FAKE_ACCOUNT:-123456789012}:function:${FAKE_FUNCTION_NAME:-$name}" '{FunctionArn:$arn}'
    ;;
  "lambda invoke")
    response_file=${!#}
    payload_uri=$(arg_after --payload "$@")
    payload_file=${payload_uri#fileb://}
    action=$(jq -r .Action "$payload_file")
    printf '%s\n' "$action" >>"$state/actions"
    if [[ "${FAKE_LAMBDA_INVOKE_MODE:-success}" == throttle ]]; then
      echo "An error occurred (TooManyRequestsException): PRIVATE-SENTINEL" >&2
      exit 254
    fi
    if [[ "${FAKE_FUNCTION_ERROR:-false}" == true ]]; then
      printf '{"errorMessage":"PRIVATE-SENTINEL"}' >"$response_file"
      printf '{"StatusCode":200,"FunctionError":"Unhandled"}\n'
      exit 0
    fi
    if [[ "$action" == stage-pending ]]; then
      token=$(jq -r .ResourceProperties.ClientRequestToken "$payload_file")
      jq -n --arg token "$token" '{action:"stage-pending",currentVersionId:"old",pendingVersionId:$token,pendingPublicKey:"NEWPUBLIC="}' >"$response_file"
    elif [[ "$action" == publish-current ]]; then
      printf '{"action":"publish-current","currentVersionId":"old","currentPublicKey":"OLDPUBLIC="}' >"$response_file"
    else
      case "${FAKE_STATUS_MODE:-normal}" in
        normal)
          printf '{"action":"status","versions":{"AWSCURRENT":{"versionId":"old","publicKey":"OLDPUBLIC="},"AWSPENDING":{"versionId":"new","publicKey":"NEWPUBLIC="}}}' >"$response_file"
          ;;
        repair)
          printf '{"action":"status","versions":{"AWSCURRENT":{"versionId":"new","publicKey":"NEWPUBLIC="},"AWSPENDING":{"versionId":"new","publicKey":"NEWPUBLIC="},"AWSPREVIOUS":{"versionId":"old","publicKey":"OLDPUBLIC="}}}' >"$response_file"
          ;;
        complete)
          printf '{"action":"status","versions":{"AWSCURRENT":{"versionId":"new","publicKey":"NEWPUBLIC="},"AWSPREVIOUS":{"versionId":"old","publicKey":"OLDPUBLIC="}}}' >"$response_file"
          ;;
        rollback-repair)
          printf '{"action":"status","versions":{"AWSCURRENT":{"versionId":"old","publicKey":"OLDPUBLIC="},"AWSPREVIOUS":{"versionId":"new","publicKey":"NEWPUBLIC="}}}' >"$response_file"
          ;;
        mismatch)
          printf '{"action":"status","versions":{"AWSCURRENT":{"versionId":"unexpected","publicKey":"OTHER="}}}' >"$response_file"
          ;;
      esac
    fi
    printf '{"StatusCode":%s}\n' "${FAKE_LAMBDA_STATUS_CODE:-200}"
    ;;
  "ssm get-parameter")
    count_file="$state/ssm-get-count"
    count=0
    [[ -f "$count_file" ]] && count=$(cat "$count_file")
    count=$((count + 1))
    printf '%s' "$count" >"$count_file"
    case "${FAKE_PUBLISHED_MODE:-success}" in
      success) printf '%s\n' "${FAKE_PUBLISHED_KEY:-OLDPUBLIC=}" ;;
      retry-then-success)
        if [[ "$count" -lt 3 ]]; then
          echo "An error occurred (ThrottlingException) when calling GetParameter" >&2
          exit 254
        fi
        printf '%s\n' "${FAKE_PUBLISHED_KEY:-OLDPUBLIC=}"
        ;;
      empty) printf '\n' ;;
      missing)
        echo "An error occurred (ParameterNotFound) when calling GetParameter" >&2
        exit 254
        ;;
      *) echo "unsupported FAKE_PUBLISHED_MODE" >&2; exit 2 ;;
    esac
    ;;
  "secretsmanager update-secret-version-stage")
    stage=$(arg_after --version-stage "$@")
    printf 'update-%s\n' "$stage" >>"$state/mutations"
    ;;
  "ssm put-parameter")
    printf 'put-parameter\n' >>"$state/mutations"
    ;;
  *)
    echo "unexpected aws invocation: $*" >&2
    exit 91
    ;;
esac
AWS
  chmod +x "$bin/aws"
}

run_case() {
  local name=$1
  shift
  local -a environment_overrides=()
  while (($#)) && [[ "$1" == *=* ]]; do
    environment_overrides+=("$1")
    shift
  done
  local dir="$TMP_ROOT/$name"
  mkdir -p "$dir/bin" "$dir/state" "$dir/tmp"
  make_fake_aws "$dir/bin"
  LAST_STATE="$dir/state"
  set +e
  LAST_OUT=$(env PATH="$dir/bin:$PATH" FAKE_AWS_STATE="$dir/state" TMPDIR="$dir/tmp" \
    "${environment_overrides[@]}" "$SCRIPT" --environment sandbox --region us-east-2 "$@" 2>&1)
  LAST_RC=$?
  set -e
}

assert_rc() {
  if [[ $LAST_RC -eq $2 ]]; then ok "$1"; else bad "$1" "expected rc $2, got $LAST_RC: $LAST_OUT"; fi
}
assert_contains() {
  if [[ "$LAST_OUT" == *"$2"* ]]; then ok "$1"; else bad "$1" "missing '$2': $LAST_OUT"; fi
}
assert_no_mutations() {
  if [[ ! -s "$LAST_STATE/mutations" ]]; then ok "$1"; else bad "$1" "unexpected mutations: $(cat "$LAST_STATE/mutations" 2>/dev/null)"; fi
}

echo "Running rotate-relay-identity tests..."

run_case status status
assert_rc "status succeeds" 0
assert_contains "status returns only public topology" '"AWSCURRENT"'
if ! grep -q 'get-secret-value' "$LAST_STATE/argv" && [[ "$LAST_OUT" != *PRIVATE-SENTINEL* ]]; then ok "status never reads or emits private material"; else bad "status never reads or emits private material" "$LAST_OUT"; fi
if [[ -z "$(find "$TMP_ROOT/status/tmp" -mindepth 1 -print -quit)" ]]; then ok "temporary invocation files are cleaned"; else bad "temporary invocation files are cleaned" "files remain"; fi

run_case sync-current sync-current
assert_rc "sync-current succeeds" 0
assert_contains "sync-current uses the non-generating publish action" '"action":"publish-current"'
if [[ "$(cat "$LAST_STATE/actions")" == "publish-current" ]]; then ok "sync-current never calls ensure-current"; else bad "sync-current never calls ensure-current" "$(cat "$LAST_STATE/actions")"; fi

uuid=123e4567-e89b-42d3-a456-426614174000
run_case stage stage --token "$uuid"
assert_rc "stage succeeds with explicit UUIDv4" 0
assert_contains "stage reports exact pending id" "\"pendingVersionId\":\"$uuid\""
assert_no_mutations "stage does not promote or publish"

run_case confirmation promote --expected-current-id old --expected-pending-id new --confirm wrong
assert_rc "promotion requires exact confirmation" 2
assert_no_mutations "failed confirmation performs no mutation"

run_case mismatch FAKE_STATUS_MODE=mismatch promote --expected-current-id old --expected-pending-id new --confirm PROMOTE:new
assert_rc "promotion rejects unexpected topology" 1
assert_no_mutations "topology mismatch performs no mutation"

run_case promote promote --expected-current-id old --expected-pending-id new --confirm PROMOTE:new
assert_rc "normal promotion succeeds" 0
expected=$'update-AWSCURRENT\nput-parameter\nupdate-AWSPENDING'
actual=$(cat "$LAST_STATE/mutations" 2>/dev/null)
if [[ "$actual" == "$expected" ]]; then ok "promotion stage/parameter/cleanup ordering is exact"; else bad "promotion stage/parameter/cleanup ordering is exact" "$actual"; fi

run_case repair FAKE_STATUS_MODE=repair promote --expected-current-id old --expected-pending-id new --confirm PROMOTE:new
assert_rc "partial promotion is repairable" 0
expected=$'put-parameter\nupdate-AWSPENDING'
actual=$(cat "$LAST_STATE/mutations" 2>/dev/null)
if [[ "$actual" == "$expected" ]]; then ok "repair does not move AWSCURRENT twice"; else bad "repair does not move AWSCURRENT twice" "$actual"; fi

run_case complete FAKE_STATUS_MODE=complete FAKE_PUBLISHED_KEY=NEWPUBLIC= promote --expected-current-id old --expected-pending-id new --confirm PROMOTE:new
assert_rc "completed promotion retry is idempotent" 0
assert_no_mutations "completed promotion retry performs no mutation"

run_case function-error FAKE_FUNCTION_ERROR=true status
assert_rc "Lambda FunctionError is detected" 1
if [[ "$LAST_OUT" != *PRIVATE-SENTINEL* ]]; then ok "FunctionError response is redacted"; else bad "FunctionError response is redacted" "$LAST_OUT"; fi

run_case invoke-non-200 FAKE_LAMBDA_STATUS_CODE=202 status
assert_rc "non-200 Lambda invocation status is rejected" 1
assert_contains "non-200 Lambda invocation status is classified" "identity Lambda invocation did not return StatusCode 200"
assert_no_mutations "non-200 Lambda invocation performs no mutation"

run_case invoke-throttle FAKE_LAMBDA_INVOKE_MODE=throttle status
assert_rc "Lambda client/API throttling is detected" 1
assert_contains "Lambda throttling is distinguished from FunctionError" "unable to invoke identity Lambda (client/API error such as throttling)"
if [[ "$LAST_OUT" != *"invalid identity Lambda response"* && "$LAST_OUT" != *PRIVATE-SENTINEL* ]]; then ok "Lambda throttle response is classified and redacted"; else bad "Lambda throttle response is classified and redacted" "$LAST_OUT"; fi
assert_no_mutations "Lambda throttling performs no mutation"

# Promote captures invoke_identity through command substitution. Freeze the
# exact path where a non-zero AWS CLI status could otherwise be masked by Bash
# errexit semantics and parsed as an empty/stale Lambda response.
run_case promote-invoke-throttle FAKE_LAMBDA_INVOKE_MODE=throttle promote --expected-current-id old --expected-pending-id new --confirm PROMOTE:new
assert_rc "promotion detects Lambda client/API throttling" 1
assert_contains "promotion classifies Lambda throttling before response parsing" "unable to invoke identity Lambda (client/API error such as throttling)"
if [[ "$LAST_OUT" != *"invalid identity Lambda response"* && "$LAST_OUT" != *PRIVATE-SENTINEL* ]]; then ok "promotion throttle response is classified and redacted"; else bad "promotion throttle response is classified and redacted" "$LAST_OUT"; fi
assert_no_mutations "promotion throttling performs no mutation"

run_case wrong-region FAKE_ARN_REGION=us-west-2 status
assert_rc "secret ARN region mismatch is rejected" 1
assert_no_mutations "wrong-region rejection performs no mutation"

run_case missing-public-parameter FAKE_PUBLISHED_MODE=missing promote --expected-current-id old --expected-pending-id new --confirm PROMOTE:new
assert_rc "promotion fails closed when the public parameter is absent" 1
assert_contains "missing public parameter has an operator-facing error" "ERROR: unable to read public-key parameter /sandbox/nhp/relay/identity/current-public-key after 3 attempts"
if [[ "$(cat "$LAST_STATE/ssm-get-count")" == 3 ]]; then ok "missing public parameter read is retried exactly three times"; else bad "missing public parameter read is retried exactly three times" "$(cat "$LAST_STATE/ssm-get-count")"; fi
assert_no_mutations "missing public parameter performs no mutation"

run_case retry-public-parameter FAKE_PUBLISHED_MODE=retry-then-success promote --expected-current-id old --expected-pending-id new --confirm PROMOTE:new
assert_rc "promotion absorbs bounded transient public-parameter reads" 0
if [[ "$(cat "$LAST_STATE/ssm-get-count")" == 3 ]]; then ok "transient public parameter read retries exactly to success"; else bad "transient public parameter read retries exactly to success" "$(cat "$LAST_STATE/ssm-get-count")"; fi
expected=$'update-AWSCURRENT\nput-parameter\nupdate-AWSPENDING'
actual=$(cat "$LAST_STATE/mutations" 2>/dev/null)
if [[ "$actual" == "$expected" ]]; then ok "retried public read preserves promotion mutation ordering"; else bad "retried public read preserves promotion mutation ordering" "$actual"; fi

run_case empty-public-parameter FAKE_PUBLISHED_MODE=empty promote --expected-current-id old --expected-pending-id new --confirm PROMOTE:new
assert_rc "promotion fails closed when the public parameter is empty" 1
assert_contains "empty public parameter has an operator-facing error" "returned an empty value"
assert_no_mutations "empty public parameter performs no mutation"

run_case rollback FAKE_STATUS_MODE=complete FAKE_PUBLISHED_KEY=NEWPUBLIC= rollback --expected-current-id new --expected-previous-id old --confirm ROLLBACK:old
assert_rc "guarded rollback succeeds" 0
expected=$'update-AWSCURRENT\nput-parameter'
actual=$(cat "$LAST_STATE/mutations" 2>/dev/null)
if [[ "$actual" == "$expected" ]]; then ok "rollback moves the stage before publishing"; else bad "rollback moves the stage before publishing" "$actual"; fi

run_case rollback-repair FAKE_STATUS_MODE=rollback-repair FAKE_PUBLISHED_KEY=NEWPUBLIC= rollback --expected-current-id new --expected-previous-id old --confirm ROLLBACK:old
assert_rc "partial rollback is repairable" 0
expected='put-parameter'
actual=$(cat "$LAST_STATE/mutations" 2>/dev/null)
if [[ "$actual" == "$expected" ]]; then ok "rollback repair does not move AWSCURRENT twice"; else bad "rollback repair does not move AWSCURRENT twice" "$actual"; fi

if grep -Eq 'set -[^[:space:]]*x' "$SCRIPT"; then bad "helper never enables xtrace" "set -x found"; else ok "helper never enables xtrace"; fi
if grep -Eq '^[[:space:]]*aws[[:space:]]+secretsmanager[[:space:]]+get-secret-value' "$SCRIPT"; then bad "helper has no get-secret-value code path" "forbidden command found"; else ok "helper has no get-secret-value code path"; fi

echo "Passed: $pass"
echo "Failed: $fail"
((fail == 0))
