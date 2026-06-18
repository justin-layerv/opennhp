#!/usr/bin/env bash
# Fixture tests for .github/scripts/wait-for-instance-refresh.sh.
#
# Usage: bash tests/scripts/wait-for-instance-refresh_test.sh

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/wait-for-instance-refresh.sh"
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "$TMP_ROOT"' EXIT

pass=0
fail=0
failures=""
LAST_OUT=""
LAST_RC=0
LAST_STATE_DIR=""

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
EXPECTED_ASG="${FAKE_ASG_NAME:-asg-test}"
EXPECTED_REFRESH="${FAKE_REFRESH_ID:-refresh-test}"

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

ASG_NAME=$(arg_after --auto-scaling-group-name "$@" || true)
REFRESH_ID=$(arg_after --instance-refresh-ids "$@" || true)

case "$1 $2" in
  "autoscaling describe-instance-refreshes")
    if [[ "$ASG_NAME" != "$EXPECTED_ASG" ]]; then
      echo "unexpected ASG name: got '$ASG_NAME', expected '$EXPECTED_ASG'" >&2
      exit 2
    fi
    if [[ "$REFRESH_ID" != "$EXPECTED_REFRESH" ]]; then
      echo "unexpected refresh id: got '$REFRESH_ID', expected '$EXPECTED_REFRESH'" >&2
      exit 2
    fi
    count_file="$STATE_DIR/describe-count"
    count=0
    [[ -f "$count_file" ]] && count=$(cat "$count_file")
    count=$((count + 1))
    printf '%s' "$count" > "$count_file"

    case "${FAKE_DESCRIBE_MODE:-successful}" in
      successful)
        if [[ "$count" -lt 2 ]]; then
          printf 'InProgress\t50\n'
        else
          printf 'Successful\t100\n'
        fi
        ;;
      transient-then-success)
        if [[ "$count" -eq 1 ]]; then
          echo "An error occurred (ThrottlingException) when calling DescribeInstanceRefreshes" >&2
          exit 254
        fi
        printf 'Successful\t100\n'
        ;;
      persistent-error)
        echo "An error occurred (AccessDeniedException) when calling DescribeInstanceRefreshes" >&2
        exit 253
        ;;
      failed)
        printf 'Failed\t50\n'
        ;;
      never-terminal)
        printf 'InProgress\t10\n'
        ;;
      canary)
        if [[ "$count" -lt 2 ]]; then
          printf 'InProgress\t50\n'
        else
          printf 'Successful\t100\n'
        fi
        ;;
      *)
        echo "unsupported FAKE_DESCRIBE_MODE: ${FAKE_DESCRIBE_MODE:-}" >&2
        exit 2
        ;;
    esac
    ;;

  "autoscaling describe-auto-scaling-groups")
    printf 'i-canary\n'
    ;;

  "ssm send-command")
    printf 'cmd-canary\n'
    ;;

  "ssm get-command-invocation")
    printf 'Success\n'
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
  local name="$1"
  shift
  local case_dir="$TMP_ROOT/$name"
  mkdir -p "$case_dir/bin" "$case_dir/state"
  make_fake_commands "$case_dir/bin"
  LAST_STATE_DIR="$case_dir/state"
  LAST_OUT=$(env \
    PATH="$case_dir/bin:$PATH" \
    FAKE_AWS_STATE_DIR="$LAST_STATE_DIR" \
    "$@" \
    "$SCRIPT" asg-test refresh-test "" 5 2>&1)
  LAST_RC=$?
}

run_source_case() {
  local name="$1"
  shift
  local case_dir="$TMP_ROOT/$name"
  mkdir -p "$case_dir/bin" "$case_dir/state"
  make_fake_commands "$case_dir/bin"
  LAST_STATE_DIR="$case_dir/state"
  LAST_OUT=$(env \
    PATH="$case_dir/bin:$PATH" \
    FAKE_AWS_STATE_DIR="$LAST_STATE_DIR" \
    "$@" \
    bash -c "set -euo pipefail; source \"\$1\"; wait_for_instance_refresh asg-test refresh-test \"\" 5 Blue 0 2" bash "$SCRIPT" 2>&1)
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

echo "Running wait-for-instance-refresh tests..."

run_case cli-success FAKE_DESCRIBE_MODE=successful
assert_rc "CLI succeeds after non-terminal poll" 0
assert_contains "CLI prints successful completion" "Instance refresh refresh-test completed successfully"
assert_file_equals "CLI polled twice" "$LAST_STATE_DIR/describe-count" "2"

run_source_case source-transient FAKE_DESCRIBE_MODE=transient-then-success
assert_rc "sourceable helper tolerates one describe blip" 0
assert_contains "sourceable helper keeps caller label" "Blue instance refresh refresh-test completed successfully"
assert_file_equals "sourceable helper retried after transient error" "$LAST_STATE_DIR/describe-count" "2"

run_case persistent-error FAKE_DESCRIBE_MODE=persistent-error
assert_rc "persistent describe errors fail loud" 1
assert_contains "persistent describe error surfaces cause" "AccessDeniedException"
assert_file_equals "persistent describe error stops after default budget" "$LAST_STATE_DIR/describe-count" "3"

run_case terminal-failed FAKE_DESCRIBE_MODE=failed
assert_rc "terminal Failed status fails" 1
assert_contains "terminal Failed status names refresh" "ended Failed"

run_source_case timeout FAKE_DESCRIBE_MODE=never-terminal
assert_rc "non-terminal refresh times out" 1
assert_contains "timeout emits bounded wait failure" "did not converge within"
assert_file_equals "timeout honors source max iterations" "$LAST_STATE_DIR/describe-count" "5"

mkdir -p "$TMP_ROOT/canary-health/bin" "$TMP_ROOT/canary-health/state"
make_fake_commands "$TMP_ROOT/canary-health/bin"
LAST_OUT=$(env \
  PATH="$TMP_ROOT/canary-health/bin:$PATH" \
  FAKE_AWS_STATE_DIR="$TMP_ROOT/canary-health/state" \
  FAKE_DESCRIBE_MODE=canary \
  "$SCRIPT" asg-test refresh-test "echo ok" 5 2>&1)
LAST_RC=$?
assert_rc "canary command path succeeds" 0
assert_contains "canary command path runs health check" "Canary health check passed"

echo ""
echo "Passed: $pass"
echo "Failed: $fail"
if [[ "$fail" -gt 0 ]]; then
  printf '\nFailures:\n%b' "$failures"
  exit 1
fi
