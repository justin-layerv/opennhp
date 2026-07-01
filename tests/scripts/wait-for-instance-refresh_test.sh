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
if [[ -n "${FAKE_AWS_STATE_DIR:-}" ]]; then
  printf '%s\n' "$*" >> "$FAKE_AWS_STATE_DIR/sleep-log"
fi
exit 0
SLEEP
  chmod +x "$dir/sleep"

  cat > "$dir/date" <<'DATE'
#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${FAKE_DATE_SEQUENCE:-}" ]]; then
  STATE_DIR="${FAKE_AWS_STATE_DIR:?}"
  count_file="$STATE_DIR/date-count"
  count=0
  [[ -f "$count_file" ]] && count=$(cat "$count_file")
  count=$((count + 1))
  printf '%s' "$count" > "$count_file"
  read -r -a values <<< "$FAKE_DATE_SEQUENCE"
  index=$((count - 1))
  if ((index >= ${#values[@]})); then
    index=$((${#values[@]} - 1))
  fi
  printf '%s\n' "${values[$index]}"
  exit 0
fi
if [[ -n "${FAKE_DATE_FAIL:-}" ]]; then
  echo "simulated date failure" >&2
  exit 1
fi

/bin/date "$@"
DATE
  chmod +x "$dir/date"

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
REGION=$(arg_after --region "$@" || true)

if [[ -n "${FAKE_EXPECT_REGION:-}" ]]; then
  if [[ "$REGION" != "$FAKE_EXPECT_REGION" ]]; then
    echo "unexpected region: got '$REGION', expected '$FAKE_EXPECT_REGION'" >&2
    exit 2
  fi
  printf '%s %s:%s\n' "$1" "$2" "$REGION" >> "$STATE_DIR/region-log"
fi

case "$1 $2" in
  "cloudwatch put-metric-data")
    count_file="$STATE_DIR/deployment-window-count"
    count=0
    [[ -f "$count_file" ]] && count=$(cat "$count_file")
    count=$((count + 1))
    printf '%s' "$count" > "$count_file"
    printf '%s\n' "$*" >> "$STATE_DIR/deployment-window-log"
    ;;

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
      nonconsecutive-errors)
        case "$count" in
          1 | 3)
            echo "An error occurred (ThrottlingException) when calling DescribeInstanceRefreshes" >&2
            exit 254
            ;;
          2)
            printf 'InProgress\t50\n'
            ;;
          *)
            printf 'Successful\t100\n'
            ;;
        esac
        ;;
      persistent-error)
        echo "An error occurred (AccessDeniedException) when calling DescribeInstanceRefreshes" >&2
        exit 253
        ;;
      failed)
        printf 'Failed\t50\n'
        ;;
      cancelled)
        printf 'Cancelled\t50\n'
        ;;
      rollback-failed)
        printf 'RollbackFailed\t50\n'
        ;;
      rollback-successful)
        printf 'RollbackSuccessful\t50\n'
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
    if [[ -n "${FAKE_EMPTY_COMMAND_ID:-}" ]]; then
      exit 0
    fi
    printf 'cmd-canary\n'
    ;;

  "ssm get-command-invocation")
    printf '%s\n' "${FAKE_SSM_STATUS:-Success}"
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

run_source_case_with_interval() {
  local name="$1" interval="$2"
  shift 2
  local case_dir="$TMP_ROOT/$name"
  mkdir -p "$case_dir/bin" "$case_dir/state"
  make_fake_commands "$case_dir/bin"
  LAST_STATE_DIR="$case_dir/state"
  LAST_OUT=$(env \
    PATH="$case_dir/bin:$PATH" \
    FAKE_AWS_STATE_DIR="$LAST_STATE_DIR" \
    "$@" \
    bash -c "set -euo pipefail; source \"\$1\"; wait_for_instance_refresh asg-test refresh-test \"\" 5 Blue \"\$2\" 2" bash "$SCRIPT" "$interval" 2>&1)
  LAST_RC=$?
}

run_source_deadline_case() {
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
    bash -c "set -euo pipefail; source \"\$1\"; wait_for_instance_refresh asg-test refresh-test \"\" 5 Blue 1 2 0" bash "$SCRIPT" 2>&1)
  LAST_RC=$?
}

run_source_live_deadline_case() {
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
    bash -c "set -euo pipefail; source \"\$1\"; wait_for_instance_refresh asg-test refresh-test \"\" 5 Blue 1 2 105" bash "$SCRIPT" 2>&1)
  LAST_RC=$?
}

run_source_label_case() {
  local name="$1" label="$2"
  shift 2
  local case_dir="$TMP_ROOT/$name"
  mkdir -p "$case_dir/bin" "$case_dir/state"
  make_fake_commands "$case_dir/bin"
  LAST_STATE_DIR="$case_dir/state"
  LAST_OUT=$(env \
    PATH="$case_dir/bin:$PATH" \
    FAKE_AWS_STATE_DIR="$LAST_STATE_DIR" \
    "$@" \
    bash -c "set -euo pipefail; source \"\$1\"; wait_for_instance_refresh asg-test refresh-test \"\" 5 \"\$2\" 0 2" bash "$SCRIPT" "$label" 2>&1)
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

assert_not_contains() {
  local label="$1" needle="$2"
  if [[ "$LAST_OUT" != *"$needle"* ]]; then
    report_pass "$label"
  else
    report_fail "$label" "output unexpectedly contained '$needle'; output: $LAST_OUT"
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

assert_file_first_line_equals() {
  local label="$1" path="$2" want="$3"
  local got=""
  [[ -f "$path" ]] && got=$(sed -n '1p' "$path")
  if [[ "$got" == "$want" ]]; then
    report_pass "$label"
  else
    report_fail "$label" "first line got '$got', want '$want'"
  fi
}

echo "Running wait-for-instance-refresh tests..."

run_case cli-success FAKE_DESCRIBE_MODE=successful
assert_rc "CLI succeeds after non-terminal poll" 0
assert_contains "CLI prints successful completion" "Instance refresh completed successfully"
assert_file_equals "CLI polled twice" "$LAST_STATE_DIR/describe-count" "2"

run_source_case source-transient FAKE_DESCRIBE_MODE=transient-then-success
assert_rc "sourceable helper tolerates one describe blip" 0
assert_contains "sourceable helper keeps caller label" "Blue instance refresh refresh-test completed successfully"
assert_file_equals "sourceable helper retried after transient error" "$LAST_STATE_DIR/describe-count" "2"

run_source_case source-error-reset FAKE_DESCRIBE_MODE=nonconsecutive-errors
assert_rc "sourceable helper resets error budget after successful describe" 0
assert_contains "error-budget reset case eventually succeeds" "Blue instance refresh refresh-test completed successfully"
assert_file_equals "error-budget reset case reaches fourth poll" "$LAST_STATE_DIR/describe-count" "4"

run_source_case deployment-window-heartbeat \
  FAKE_DATE_SEQUENCE="100 161" \
  FAKE_DESCRIBE_MODE=successful \
  DEPLOYMENT_WINDOW_ENVIRONMENT=prod \
  DEPLOYMENT_WINDOW_CELL_ID=cell0 \
  DEPLOYMENT_WINDOW_COMPONENT=server \
  DEPLOYMENT_WINDOW_STRATEGY=promote \
  DEPLOYMENT_WINDOW_EMIT_INTERVAL_SECONDS=60
assert_rc "sourceable helper with deployment-window heartbeat succeeds" 0
assert_contains "deployment-window heartbeat logs metric push" "DeploymentWindow metric pushed (Environment=prod Cell=cell0 Component=server Strategy=promote)"
assert_file_equals "deployment-window heartbeat emits during each long poll interval" "$LAST_STATE_DIR/deployment-window-count" "2"

run_source_case deployment-window-date-failure \
  FAKE_DATE_FAIL=1 \
  FAKE_DESCRIBE_MODE=successful \
  DEPLOYMENT_WINDOW_ENVIRONMENT=prod \
  DEPLOYMENT_WINDOW_CELL_ID=cell0 \
  DEPLOYMENT_WINDOW_COMPONENT=ac \
  DEPLOYMENT_WINDOW_STRATEGY=promote \
  DEPLOYMENT_WINDOW_EMIT_INTERVAL_SECONDS=60
assert_rc "deployment-window heartbeat date failure still succeeds" 0
assert_contains "deployment-window heartbeat date failure warns" "::warning::date +%s failed while throttling DeploymentWindow heartbeat; using shell monotonic fallback"
assert_file_equals "deployment-window heartbeat date failure throttles on shell fallback" "$LAST_STATE_DIR/deployment-window-count" "1"

run_case persistent-error FAKE_DESCRIBE_MODE=persistent-error
assert_rc "persistent describe errors fail loud" 1
assert_contains "persistent describe error surfaces cause" "AccessDeniedException"
assert_file_equals "persistent describe error stops after default budget" "$LAST_STATE_DIR/describe-count" "3"

run_case terminal-failed FAKE_DESCRIBE_MODE=failed
assert_rc "terminal Failed status fails" 1
assert_contains "terminal Failed preserves CLI message" "Instance refresh failed: Failed"

run_case terminal-cancelled FAKE_DESCRIBE_MODE=cancelled
assert_rc "terminal Cancelled status fails" 1
assert_contains "terminal Cancelled preserves CLI message" "Instance refresh failed: Cancelled"

run_case terminal-rollback-failed FAKE_DESCRIBE_MODE=rollback-failed
assert_rc "terminal RollbackFailed status fails" 1
assert_contains "terminal RollbackFailed preserves CLI-style message" "Instance refresh failed: RollbackFailed"

run_case terminal-rollback-successful FAKE_DESCRIBE_MODE=rollback-successful
assert_rc "terminal RollbackSuccessful status fails" 1
assert_contains "terminal RollbackSuccessful preserves CLI-style message" "Instance refresh failed: RollbackSuccessful"

run_source_label_case relay-label Relay FAKE_DESCRIBE_MODE=successful
assert_rc "Relay label path succeeds" 0
assert_contains "Relay label emits relay subject" "Relay instance refresh refresh-test completed successfully"

run_source_case_with_interval timeout 1 FAKE_DESCRIBE_MODE=never-terminal
assert_rc "non-terminal refresh times out" 1
assert_contains "sourceable non-Instance timeout emits GitHub annotation by default" "::error::Blue instance refresh"
assert_contains "timeout emits bounded wait failure" "did not converge within 4s"
assert_file_equals "timeout honors source max iterations" "$LAST_STATE_DIR/describe-count" "5"

run_case cli-timeout FAKE_DESCRIBE_MODE=never-terminal
assert_rc "CLI timeout fails" 1
assert_contains "CLI timeout preserves standalone message" "ERROR: Instance refresh timed out after 40 seconds"
assert_not_contains "CLI timeout does not emit GitHub annotation by default" "::error::"
assert_file_equals "CLI timeout honors max iterations" "$LAST_STATE_DIR/describe-count" "5"

run_source_deadline_case expired-deadline FAKE_DESCRIBE_MODE=successful
assert_rc "expired deadline fails before first describe" 1
assert_contains "expired deadline emits bounded wait failure" "did not converge within 4s"
assert_file_equals "expired deadline does not describe refresh" "$LAST_STATE_DIR/describe-count" ""

run_source_live_deadline_case mid-roll-deadline FAKE_DESCRIBE_MODE=never-terminal FAKE_DATE_SEQUENCE="100 100 105"
assert_rc "mid-roll deadline fails" 1
assert_contains "mid-roll deadline emits deadline budget" "did not converge within 5s"
assert_file_equals "mid-roll deadline stops after one describe" "$LAST_STATE_DIR/describe-count" "1"

mkdir -p "$TMP_ROOT/canary-health/bin" "$TMP_ROOT/canary-health/state"
make_fake_commands "$TMP_ROOT/canary-health/bin"
LAST_OUT=$(env \
  PATH="$TMP_ROOT/canary-health/bin:$PATH" \
  FAKE_AWS_STATE_DIR="$TMP_ROOT/canary-health/state" \
  FAKE_DESCRIBE_MODE=canary \
  INSTANCE_REFRESH_HEALTH_CHECK_SETTLE_SECONDS=0 \
  "$SCRIPT" asg-test refresh-test "echo ok" 5 2>&1)
LAST_RC=$?
assert_rc "canary command path succeeds" 0
assert_contains "canary command path runs health check" "Canary health check passed"
assert_file_first_line_equals "canary command path honors settle override" "$TMP_ROOT/canary-health/state/sleep-log" "0"

mkdir -p "$TMP_ROOT/canary-failure/bin" "$TMP_ROOT/canary-failure/state"
make_fake_commands "$TMP_ROOT/canary-failure/bin"
LAST_OUT=$(env \
  PATH="$TMP_ROOT/canary-failure/bin:$PATH" \
  FAKE_AWS_STATE_DIR="$TMP_ROOT/canary-failure/state" \
  FAKE_DESCRIBE_MODE=canary \
  FAKE_SSM_STATUS=Failed \
  "$SCRIPT" asg-test refresh-test "echo ok" 5 2>&1)
LAST_RC=$?
assert_rc "canary failure branch still completes refresh" 0
assert_contains "canary failure branch logs continuing status" "Canary health check: Failed (continuing...)"

mkdir -p "$TMP_ROOT/canary-empty-command/bin" "$TMP_ROOT/canary-empty-command/state"
make_fake_commands "$TMP_ROOT/canary-empty-command/bin"
LAST_OUT=$(env \
  PATH="$TMP_ROOT/canary-empty-command/bin:$PATH" \
  FAKE_AWS_STATE_DIR="$TMP_ROOT/canary-empty-command/state" \
  FAKE_DESCRIBE_MODE=canary \
  FAKE_EMPTY_COMMAND_ID=1 \
  "$SCRIPT" asg-test refresh-test "echo ok" 5 2>&1)
LAST_RC=$?
assert_rc "canary empty command id still completes refresh" 0
assert_contains "canary empty command id targets instance" "Verifying health on instance: i-canary"
assert_not_contains "canary empty command id skips invocation read" "Canary health check passed"

run_case region-forwarding \
  AWS_REGION=us-west-2 \
  FAKE_DESCRIBE_MODE=successful \
  FAKE_EXPECT_REGION=us-west-2
assert_rc "AWS_REGION forwarding succeeds" 0
assert_file_equals "AWS_REGION forwarded to describe calls" "$LAST_STATE_DIR/region-log" $'autoscaling describe-instance-refreshes:us-west-2\nautoscaling describe-instance-refreshes:us-west-2'

echo ""
echo "Passed: $pass"
echo "Failed: $fail"
if [[ "$fail" -gt 0 ]]; then
  printf '\nFailures:\n%b' "$failures"
  exit 1
fi
