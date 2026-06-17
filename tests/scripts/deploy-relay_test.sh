#!/usr/bin/env bash
# deploy-relay_test.sh - fixture tests for .github/scripts/deploy-relay.sh.
# ----------------------------------------------------------------------------
# The relay deploy helper owns the dark-skip/loud-fail SSM probe, the app-only
# image-tag write, and the ASG refresh dispatch. These cases cover the PR-body
# behavioral simulation plus loud-fail branches with a fake aws CLI so the
# contract stays regression-protected under `make lint-workflows` /
# validate-workflows.yml.
#
# Usage: bash tests/scripts/deploy-relay_test.sh

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/deploy-relay.sh"
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "$TMP_ROOT"' EXIT

pass=0
fail=0
failures=""
LAST_OUT=""
LAST_RC=0
LAST_STATE_DIR=""
LAST_SUMMARY=""

report_pass() { pass=$((pass + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
report_fail() {
  fail=$((fail + 1))
  failures+="  FAIL $1: $2\n"
  printf '  \033[31mFAIL\033[0m %s\n      %s\n' "$1" "$2"
}

make_fake_commands() {
  local dir="$1"
  mkdir -p "$dir"

  cat > "$dir/sleep" <<'SLEEP'
#!/usr/bin/env bash
exit 0
SLEEP
  chmod +x "$dir/sleep"

  cat > "$dir/aws" <<'AWS'
#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="${FAKE_AWS_STATE_DIR:?}"
ENVIRONMENT="${FAKE_ENVIRONMENT:-sandbox}"
EXPECTED_ASG_PARAM="/${ENVIRONMENT}/nhp/relay/asg-name"
EXPECTED_IMAGE_TAG_PARAM="/${ENVIRONMENT}/nhp/relay/image-tag"
EXPECTED_ASG_NAME="${FAKE_ASG_NAME:-layerv-nhp-sandbox-relay}"
EXPECTED_IMAGE_TAG="${FAKE_IMAGE_TAG:-}"

arg_after() {
  local want="$1" prev=""
  shift
  for arg in "$@"; do
    if [[ "$prev" == "$want" ]]; then
      printf '%s' "$arg"
      return 0
    fi
    prev="$arg"
  done
  return 1
}

has_arg() {
  local want="$1"
  shift
  for arg in "$@"; do
    [[ "$arg" == "$want" ]] && return 0
  done
  return 1
}

if [[ "$#" -lt 2 ]]; then
  echo "unexpected aws invocation: $*" >&2
  exit 2
fi

NAME=$(arg_after --name "$@" || true)
VALUE=$(arg_after --value "$@" || true)
ASG_NAME=$(arg_after --auto-scaling-group-name "$@" || true)

case "$1 $2" in
  "ssm get-parameter")
    count_file="$STATE_DIR/get-count"
    count=0
    [[ -f "$count_file" ]] && count=$(cat "$count_file")
    count=$((count + 1))
    printf '%s' "$count" > "$count_file"

    if [[ "$NAME" != "$EXPECTED_ASG_PARAM" ]]; then
      echo "unexpected get-parameter name: got '$NAME', expected '$EXPECTED_ASG_PARAM'" >&2
      exit 2
    fi

    case "${FAKE_GET_MODE:-success}" in
      success)
        printf '%s\n' "$EXPECTED_ASG_NAME"
        ;;
      notfound)
        echo "An error occurred (ParameterNotFound) when calling GetParameter for $NAME" >&2
        exit 255
        ;;
      error)
        echo "An error occurred (AccessDeniedException) when calling GetParameter for $NAME" >&2
        exit 254
        ;;
      error-mentions-notfound)
        echo "An error occurred (AccessDeniedException) when calling GetParameter for $NAME: message mentions ParameterNotFound but is not that error code" >&2
        exit 254
        ;;
      retry-then-success)
        if [[ "$count" -lt 3 ]]; then
          echo "An error occurred (ThrottlingException) when calling GetParameter for $NAME" >&2
          exit 254
        fi
        printf '%s\n' "$EXPECTED_ASG_NAME"
        ;;
      none)
        printf 'None\n'
        ;;
      empty)
        ;;
      *)
        echo "unsupported FAKE_GET_MODE: ${FAKE_GET_MODE:-}" >&2
        exit 2
        ;;
    esac
    ;;

  "ssm put-parameter")
    if [[ "${FAKE_EXPECT_PUT:-false}" != "true" ]]; then
      echo "unexpected put-parameter call" >&2
      exit 2
    fi
    if [[ "$NAME" != "$EXPECTED_IMAGE_TAG_PARAM" ]]; then
      echo "unexpected put-parameter name: got '$NAME', expected '$EXPECTED_IMAGE_TAG_PARAM'" >&2
      exit 2
    fi
    if [[ "$VALUE" != "$EXPECTED_IMAGE_TAG" ]]; then
      echo "unexpected put-parameter value: got '$VALUE', expected '$EXPECTED_IMAGE_TAG'" >&2
      exit 2
    fi
    if ! has_arg --overwrite "$@"; then
      echo "put-parameter missing --overwrite" >&2
      exit 2
    fi
    case "${FAKE_PUT_MODE:-success}" in
      success)
        ;;
      error)
        echo "An error occurred (AccessDeniedException) when calling PutParameter for $NAME" >&2
        exit 252
        ;;
      *)
        echo "unsupported FAKE_PUT_MODE: ${FAKE_PUT_MODE:-}" >&2
        exit 2
        ;;
    esac
    printf '%s=%s\n' "$NAME" "$VALUE" > "$STATE_DIR/put"
    printf '{"Version":7,"Tier":"Standard"}\n'
    ;;

  "autoscaling start-instance-refresh")
    if [[ "$ASG_NAME" != "$EXPECTED_ASG_NAME" ]]; then
      echo "unexpected ASG name: got '$ASG_NAME', expected '$EXPECTED_ASG_NAME'" >&2
      exit 2
    fi
    printf '%s\n' "$ASG_NAME" > "$STATE_DIR/refresh"
    case "${FAKE_REFRESH_MODE:-success}" in
      success)
        printf 'refresh-123\n'
        ;;
      inprogress)
        echo "An error occurred (InstanceRefreshInProgress) when calling StartInstanceRefresh" >&2
        exit 254
        ;;
      error)
        echo "An error occurred (ValidationError) when calling StartInstanceRefresh" >&2
        exit 253
        ;;
      *)
        echo "unsupported FAKE_REFRESH_MODE: ${FAKE_REFRESH_MODE:-}" >&2
        exit 2
        ;;
    esac
    ;;

  *)
    echo "unexpected aws invocation: $*" >&2
    exit 2
    ;;
esac
AWS
  chmod +x "$dir/aws"
}

run_case() {
  local name="$1" app_changed="$2" image_tag="$3"
  shift 3
  run_case_env sandbox "$name" "$app_changed" "$image_tag" "$@"
}

run_case_env() {
  local environment="$1" name="$2" app_changed="$3" image_tag="$4"
  shift 4
  local case_dir="$TMP_ROOT/$name"
  mkdir -p "$case_dir/bin" "$case_dir/state"
  make_fake_commands "$case_dir/bin"
  LAST_STATE_DIR="$case_dir/state"
  LAST_SUMMARY="$case_dir/summary.md"
  LAST_OUT=$(env \
    PATH="$case_dir/bin:$PATH" \
    GITHUB_STEP_SUMMARY="$LAST_SUMMARY" \
    FAKE_AWS_STATE_DIR="$LAST_STATE_DIR" \
    FAKE_ENVIRONMENT="$environment" \
    FAKE_IMAGE_TAG="$image_tag" \
    "$@" \
    "$SCRIPT" "$environment" "$app_changed" "$image_tag" 2>&1)
  LAST_RC=$?
}

assert_rc() {
  local label="$1" want="$2"
  if [[ "$LAST_RC" -eq "$want" ]]; then
    report_pass "$label"
  else
    report_fail "$label" "rc=$LAST_RC, want $want; output: $LAST_OUT"
  fi
}

assert_contains() {
  local label="$1" needle="$2"
  if [[ "$LAST_OUT" == *"$needle"* ]]; then
    report_pass "$label"
  else
    report_fail "$label" "output did not contain '$needle'; output: $LAST_OUT"
  fi
}

assert_file_exists() {
  local label="$1" path="$2"
  if [[ -f "$path" ]]; then
    report_pass "$label"
  else
    report_fail "$label" "missing file $path"
  fi
}

assert_file_absent() {
  local label="$1" path="$2"
  if [[ ! -e "$path" ]]; then
    report_pass "$label"
  else
    report_fail "$label" "unexpected file $path"
  fi
}

assert_file_equals() {
  local label="$1" path="$2" want="$3"
  local got=""
  [[ -f "$path" ]] && got=$(cat "$path")
  if [[ "$got" == "$want" ]]; then
    report_pass "$label"
  else
    report_fail "$label" "got '$got', want '$want'"
  fi
}

assert_file_contains() {
  local label="$1" path="$2" needle="$3"
  local got=""
  [[ -f "$path" ]] && got=$(cat "$path")
  if [[ "$got" == *"$needle"* ]]; then
    report_pass "$label"
  else
    report_fail "$label" "file $path did not contain '$needle'; got: $got"
  fi
}

echo "Running deploy-relay tests..."

LAST_OUT=$("$SCRIPT" sandbox true 2>&1)
LAST_RC=$?
assert_rc "wrong arg count fails" 1
assert_contains "wrong arg count prints usage" "Usage: "

run_case dark-skip true deadbeef FAKE_GET_MODE=notfound
assert_rc "dark relay skips cleanly" 0
assert_contains "dark skip emits notice" "relay not deployed in sandbox"
assert_file_absent "dark skip does not write image tag" "$LAST_STATE_DIR/put"
assert_file_absent "dark skip does not refresh ASG" "$LAST_STATE_DIR/refresh"

run_case_env prod prod-dark-skip true deadbeef FAKE_GET_MODE=notfound
assert_rc "prod dark relay skips cleanly" 0
assert_contains "prod dark skip uses prod param path" "/prod/nhp/relay/asg-name absent"
assert_file_absent "prod dark skip does not write image tag" "$LAST_STATE_DIR/put"
assert_file_absent "prod dark skip does not refresh ASG" "$LAST_STATE_DIR/refresh"

run_case asg-none-loud-fail true cafe1234 FAKE_GET_MODE=none
assert_rc "None ASG value fails loud" 1
assert_contains "None ASG emits Actions error" "::error::/sandbox/nhp/relay/asg-name resolved to None"
assert_file_absent "None ASG does not write image tag" "$LAST_STATE_DIR/put"
assert_file_absent "None ASG does not refresh ASG" "$LAST_STATE_DIR/refresh"
assert_file_contains "None ASG writes step summary" "$LAST_SUMMARY" "returned \`None\`"

run_case asg-empty-loud-fail true cafe1234 FAKE_GET_MODE=empty
assert_rc "empty ASG value fails loud" 1
assert_contains "empty ASG emits Actions error" "::error::/sandbox/nhp/relay/asg-name resolved to an empty value"
assert_file_absent "empty ASG does not write image tag" "$LAST_STATE_DIR/put"
assert_file_absent "empty ASG does not refresh ASG" "$LAST_STATE_DIR/refresh"
assert_file_contains "empty ASG writes step summary" "$LAST_SUMMARY" "returned an empty value"

run_case ssm-retry-then-success true cafe1234 FAKE_GET_MODE=retry-then-success FAKE_EXPECT_PUT=true
assert_rc "SSM retry-then-success deploy succeeds" 0
assert_file_equals "SSM retry-then-success retries three times" "$LAST_STATE_DIR/get-count" "3"
assert_file_equals "SSM retry-then-success writes image tag" "$LAST_STATE_DIR/put" "/sandbox/nhp/relay/image-tag=cafe1234"
assert_file_equals "SSM retry-then-success starts refresh" "$LAST_STATE_DIR/refresh" "layerv-nhp-sandbox-relay"

run_case empty-image-tag-loud-fail true "" FAKE_GET_MODE=success
assert_rc "empty image tag fails loud" 1
assert_contains "empty image tag emits Actions error" "::error::Image tag is empty on the app-changed deploy path"
assert_file_absent "empty image tag does not write image tag" "$LAST_STATE_DIR/put"
assert_file_absent "empty image tag does not refresh ASG" "$LAST_STATE_DIR/refresh"
assert_file_contains "empty image tag writes step summary" "$LAST_SUMMARY" "image tag was empty"

run_case lit-app-changed true cafe1234 FAKE_GET_MODE=success FAKE_EXPECT_PUT=true
assert_rc "lit app-changed deploy succeeds" 0
assert_file_equals "app-changed writes the new image tag" "$LAST_STATE_DIR/put" "/sandbox/nhp/relay/image-tag=cafe1234"
assert_file_equals "app-changed starts instance refresh" "$LAST_STATE_DIR/refresh" "layerv-nhp-sandbox-relay"
assert_contains "app-changed records refresh id" "Started relay instance refresh: refresh-123"

run_case lit-infra-only false cafe1234 FAKE_GET_MODE=success
assert_rc "lit infra-only refresh succeeds" 0
assert_file_absent "infra-only does not write github.sha tag" "$LAST_STATE_DIR/put"
assert_file_equals "infra-only still refreshes fleet" "$LAST_STATE_DIR/refresh" "layerv-nhp-sandbox-relay"
assert_contains "infra-only emits unchanged-tag notice" "keeping the current relay image tag"

run_case ssm-loud-fail true cafe1234 FAKE_GET_MODE=error FAKE_EXPECT_PUT=true
assert_rc "non-not-found SSM failure fails loud" 1
assert_contains "SSM failure emits Actions error" "::error::Failed to read /sandbox/nhp/relay/asg-name"
assert_file_equals "SSM failure retries three times" "$LAST_STATE_DIR/get-count" "3"
assert_file_absent "SSM failure does not write image tag" "$LAST_STATE_DIR/put"
assert_file_absent "SSM failure does not refresh ASG" "$LAST_STATE_DIR/refresh"
assert_file_contains "SSM failure writes step summary" "$LAST_SUMMARY" "could not read /sandbox/nhp/relay/asg-name"

run_case ssm-error-mentions-notfound true cafe1234 \
  FAKE_GET_MODE=error-mentions-notfound \
  FAKE_EXPECT_PUT=true
assert_rc "SSM error mentioning ParameterNotFound fails loud" 1
assert_contains "SSM error mentioning ParameterNotFound emits Actions error" "::error::Failed to read /sandbox/nhp/relay/asg-name"
assert_file_equals "SSM error mentioning ParameterNotFound retries three times" "$LAST_STATE_DIR/get-count" "3"
assert_file_absent "SSM error mentioning ParameterNotFound does not write image tag" "$LAST_STATE_DIR/put"
assert_file_absent "SSM error mentioning ParameterNotFound does not refresh ASG" "$LAST_STATE_DIR/refresh"
assert_file_contains "SSM error mentioning ParameterNotFound writes step summary" "$LAST_SUMMARY" "could not read /sandbox/nhp/relay/asg-name"

run_case put-loud-fail true cafe1234 \
  FAKE_GET_MODE=success \
  FAKE_EXPECT_PUT=true \
  FAKE_PUT_MODE=error
assert_rc "put-parameter failure fails loud" 1
assert_contains "put failure emits Actions error" "::error::Failed to update SSM parameter /sandbox/nhp/relay/image-tag"
assert_file_absent "put failure does not record tag write" "$LAST_STATE_DIR/put"
assert_file_absent "put failure does not refresh ASG" "$LAST_STATE_DIR/refresh"
assert_file_contains "put failure writes step summary" "$LAST_SUMMARY" "could not update /sandbox/nhp/relay/image-tag"

run_case refresh-loud-fail true cafe1234 \
  FAKE_GET_MODE=success \
  FAKE_EXPECT_PUT=true \
  FAKE_REFRESH_MODE=error
assert_rc "instance-refresh failure fails loud" 1
assert_file_equals "refresh failure writes app tag first" "$LAST_STATE_DIR/put" "/sandbox/nhp/relay/image-tag=cafe1234"
assert_file_equals "refresh failure attempts ASG refresh" "$LAST_STATE_DIR/refresh" "layerv-nhp-sandbox-relay"
assert_contains "refresh failure emits Actions error" "::error::Failed to start relay instance refresh on layerv-nhp-sandbox-relay:"
assert_contains "refresh failure surfaces AWS error" "ValidationError"
assert_file_contains "refresh failure writes step summary" "$LAST_SUMMARY" "could not start instance refresh on \`layerv-nhp-sandbox-relay\`"

run_case refresh-in-progress true cafe1234 \
  FAKE_GET_MODE=success \
  FAKE_EXPECT_PUT=true \
  FAKE_REFRESH_MODE=inprogress
assert_rc "existing instance refresh is accepted" 0
assert_file_equals "refresh-in-progress still writes app tag first" "$LAST_STATE_DIR/put" "/sandbox/nhp/relay/image-tag=cafe1234"
assert_file_equals "refresh-in-progress attempts ASG refresh" "$LAST_STATE_DIR/refresh" "layerv-nhp-sandbox-relay"
assert_contains "refresh-in-progress emits notice" "already in progress"

echo ""
echo "Passed: $pass"
echo "Failed: $fail"
if [[ "$fail" -gt 0 ]]; then
  printf '\nFailures:\n%b' "$failures"
  exit 1
fi
