#!/usr/bin/env bash
# Fixture tests for .github/scripts/prune-missing-asg-target-groups.sh.
#
# Usage: bash tests/scripts/prune-missing-asg-target-groups_test.sh

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/prune-missing-asg-target-groups.sh"
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
TG_FILE="$STATE_DIR/target-groups"

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

contains_word() {
  local needle="$1"
  local value
  shift
  for value in "$@"; do
    if [[ "$value" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

init_target_groups() {
  if [[ ! -f "$TG_FILE" ]]; then
    printf '%s' "${FAKE_ASG_TARGET_GROUPS:-}" > "$TG_FILE"
  fi
}

collect_target_group_args() {
  local collecting=false
  local arg
  shift 0
  for arg in "$@"; do
    if [[ "$collecting" == "true" ]]; then
      if [[ "$arg" == --* ]]; then
        return 0
      fi
      printf '%s\n' "$arg"
    elif [[ "$arg" == "--target-group-arns" ]]; then
      collecting=true
    fi
  done
}

remove_target_groups_from_file() {
  local target_groups_to_remove=("$@")
  local current_text
  local tg
  local current=()
  local kept=()
  current_text=$(cat "$TG_FILE")
  read -r -a current <<< "$current_text"
  for tg in "${current[@]}"; do
    if ! contains_word "$tg" "${target_groups_to_remove[@]}"; then
      kept+=("$tg")
    fi
  done
  printf '%s' "${kept[*]}" > "$TG_FILE"
}

case "$1 $2" in
  "autoscaling describe-auto-scaling-groups")
    init_target_groups
    asg_name=$(arg_after --auto-scaling-group-names "$@" || true)
    query=$(arg_after --query "$@" || true)
    if [[ "$asg_name" != "$EXPECTED_ASG" ]]; then
      echo "unexpected ASG name: got '$asg_name', expected '$EXPECTED_ASG'" >&2
      exit 2
    fi
    if [[ "$query" == join* ]]; then
      # Mirrors the AWS CLI text shape used by the script: count<TAB>ARNs. The
      # PR validation covers the actual AWS CLI/JMESPath evaluator with dry-run.
      if [[ -n "${FAKE_INITIAL_DESCRIBE_ERROR:-}" ]]; then
        echo "An error occurred (${FAKE_INITIAL_DESCRIBE_ERROR}) when calling the DescribeAutoScalingGroups operation" >&2
        exit 254
      fi
      if [[ -n "${FAKE_INITIAL_DESCRIBE_FAILS:-}" ]]; then
        count_file="$STATE_DIR/initial-describe-count"
        count=0
        [[ -f "$count_file" ]] && count=$(cat "$count_file")
        count=$((count + 1))
        printf '%s' "$count" > "$count_file"
        if ((count <= FAKE_INITIAL_DESCRIBE_FAILS)); then
          echo "An error occurred (ThrottlingException) when calling the DescribeAutoScalingGroups operation" >&2
          exit 254
        fi
      fi
      if [[ -f "$STATE_DIR/detach-log" && -n "${FAKE_WAIT_DESCRIBE_FAILS:-}" ]]; then
        count_file="$STATE_DIR/wait-describe-count"
        count=0
        [[ -f "$count_file" ]] && count=$(cat "$count_file")
        count=$((count + 1))
        printf '%s' "$count" > "$count_file"
        if ((count <= FAKE_WAIT_DESCRIBE_FAILS)); then
          echo "An error occurred (ThrottlingException) when calling the DescribeAutoScalingGroups operation" >&2
          exit 254
        fi
      fi
      if [[ -f "$STATE_DIR/detach-log" && "${FAKE_ASG_MISSING_AFTER_DETACH:-false}" == "true" ]]; then
        printf '0\t\n'
        exit 0
      fi
      if [[ -f "$STATE_DIR/detach-log" && -n "${FAKE_DETACH_CLEAR_AFTER_WAIT_POLLS:-}" ]]; then
        count_file="$STATE_DIR/wait-clear-count"
        count=0
        [[ -f "$count_file" ]] && count=$(cat "$count_file")
        count=$((count + 1))
        printf '%s' "$count" > "$count_file"
        if ((count > FAKE_DETACH_CLEAR_AFTER_WAIT_POLLS)); then
          mapfile -t detached_arns < "$STATE_DIR/detach-log"
          remove_target_groups_from_file "${detached_arns[@]}"
        fi
      fi
      if [[ "${FAKE_ASG_EXISTS:-true}" == "false" ]]; then
        printf '0\t\n'
      elif [[ -s "$TG_FILE" ]]; then
        printf '1\t'
        cat "$TG_FILE"
        printf '\n'
      else
        printf '1\t\n'
      fi
      exit 0
    fi
    echo "unexpected autoscaling describe query: $query" >&2
    exit 2
    ;;

  "elbv2 describe-target-groups")
    tg=$(arg_after --target-group-arns "$@" || true)
    if [[ -n "${FAKE_RETRYABLE_DESCRIBE_FOR:-}" && "$tg" == "$FAKE_RETRYABLE_DESCRIBE_FOR" ]]; then
      count_file="$STATE_DIR/elbv2-describe-count-${tg//[^A-Za-z0-9]/_}"
      count=0
      [[ -f "$count_file" ]] && count=$(cat "$count_file")
      count=$((count + 1))
      printf '%s' "$count" > "$count_file"
      if ((count <= ${FAKE_RETRYABLE_DESCRIBE_FAILS:-1})); then
        echo "An error occurred (ThrottlingException) when calling the DescribeTargetGroups operation" >&2
        exit 254
      fi
    fi
    if [[ -n "${FAKE_DESCRIBE_ERROR_FOR:-}" && "$tg" == "$FAKE_DESCRIBE_ERROR_FOR" ]]; then
      echo "An error occurred (AccessDenied) when calling the DescribeTargetGroups operation" >&2
      exit 254
    fi
    read -r -a missing <<< "${FAKE_MISSING_TARGET_GROUPS:-}"
    if contains_word "$tg" "${missing[@]}"; then
      echo "An error occurred (TargetGroupNotFound) when calling the DescribeTargetGroups operation: Target groups '$tg' not found" >&2
      exit 254
    fi
    printf '%s\n' "$tg"
    ;;

  "autoscaling detach-load-balancer-target-groups")
    init_target_groups
    asg_name=$(arg_after --auto-scaling-group-name "$@" || true)
    if [[ "$asg_name" != "$EXPECTED_ASG" ]]; then
      echo "unexpected ASG name: got '$asg_name', expected '$EXPECTED_ASG'" >&2
      exit 2
    fi
    count_file="$STATE_DIR/detach-call-count"
    count=0
    [[ -f "$count_file" ]] && count=$(cat "$count_file")
    count=$((count + 1))
    printf '%s' "$count" > "$count_file"
    if [[ "${FAKE_DETACH_FAIL:-false}" == "true" ]]; then
      echo "detach failed" >&2
      exit 253
    fi
    if [[ -n "${FAKE_DETACH_FAIL_ON_CALL:-}" && "$count" == "$FAKE_DETACH_FAIL_ON_CALL" ]]; then
      echo "detach failed" >&2
      exit 253
    fi
    mapfile -t detach_arns < <(collect_target_group_args "$@")
    printf '%s\n' "${detach_arns[@]}" >> "$STATE_DIR/detach-log"
    if [[ "${FAKE_DETACH_NOOP:-false}" == "true" ]]; then
      exit 0
    fi
    if [[ -n "${FAKE_DETACH_CLEAR_AFTER_WAIT_POLLS:-}" ]]; then
      exit 0
    fi
    remove_target_groups_from_file "${detach_arns[@]}"
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
    TMPDIR="$case_dir/state" \
    FAKE_AWS_STATE_DIR="$LAST_STATE_DIR" \
    WAIT_TIMEOUT_SECONDS=2 \
    WAIT_INTERVAL_SECONDS=0 \
    ALLOW_ZERO_WAIT_INTERVAL=true \
    "$@" \
    "$SCRIPT" asg-test 2>&1)
  LAST_RC=$?
}

run_case_zero_wait_interval_disallowed() {
  local name="$1"
  local case_dir="$TMP_ROOT/$name"
  mkdir -p "$case_dir/bin" "$case_dir/state"
  make_fake_commands "$case_dir/bin"
  LAST_STATE_DIR="$case_dir/state"
  LAST_OUT=$(env \
    PATH="$case_dir/bin:$PATH" \
    TMPDIR="$case_dir/state" \
    FAKE_AWS_STATE_DIR="$LAST_STATE_DIR" \
    WAIT_TIMEOUT_SECONDS=2 \
    WAIT_INTERVAL_SECONDS=0 \
    "$SCRIPT" asg-test 2>&1)
  LAST_RC=$?
}

run_case_without_asg() {
  local name="$1"
  local case_dir="$TMP_ROOT/$name"
  mkdir -p "$case_dir/bin" "$case_dir/state"
  make_fake_commands "$case_dir/bin"
  LAST_STATE_DIR="$case_dir/state"
  LAST_OUT=$(env \
    PATH="$case_dir/bin:$PATH" \
    TMPDIR="$case_dir/state" \
    FAKE_AWS_STATE_DIR="$LAST_STATE_DIR" \
    ASG_NAME= \
    "$SCRIPT" 2>&1)
  LAST_RC=$?
}

assert_success() {
  local name="$1"
  if [[ "$LAST_RC" -eq 0 ]]; then
    report_pass "$name"
  else
    report_fail "$name" "rc=$LAST_RC out='$LAST_OUT'"
  fi
}

assert_failure() {
  local name="$1"
  if [[ "$LAST_RC" -ne 0 ]]; then
    report_pass "$name"
  else
    report_fail "$name" "rc=0 out='$LAST_OUT'"
  fi
}

assert_out_has() {
  local name="$1" needle="$2"
  if [[ "$LAST_OUT" == *"$needle"* ]]; then
    report_pass "$name"
  else
    report_fail "$name" "out='$LAST_OUT' missing '$needle'"
  fi
}

assert_no_detach() {
  local name="$1"
  if [[ ! -f "$LAST_STATE_DIR/detach-log" ]]; then
    report_pass "$name"
  else
    report_fail "$name" "unexpected detach: $(cat "$LAST_STATE_DIR/detach-log")"
  fi
}

assert_detached() {
  local name="$1" expected="$2"
  local got=""
  [[ -f "$LAST_STATE_DIR/detach-log" ]] && got=$(cat "$LAST_STATE_DIR/detach-log")
  if [[ "$got" == "$expected" ]]; then
    report_pass "$name"
  else
    report_fail "$name" "detached '$got' (want '$expected')"
  fi
}

assert_detach_calls() {
  local name="$1" expected="$2"
  local got="0"
  [[ -f "$LAST_STATE_DIR/detach-call-count" ]] && got=$(cat "$LAST_STATE_DIR/detach-call-count")
  if [[ "$got" == "$expected" ]]; then
    report_pass "$name"
  else
    report_fail "$name" "detach calls '$got' (want '$expected')"
  fi
}

echo "Running prune-missing-asg-target-groups tests..."

run_case_without_asg "empty-asg-name"
assert_failure "empty ASG name fails"
assert_out_has "empty ASG name explains prepare output issue" "Standby ASG name is empty"

run_case_zero_wait_interval_disallowed "zero-wait-interval-disallowed"
assert_failure "zero wait interval fails outside fixture harness"
assert_out_has "zero wait interval explains fixture-only override" "WAIT_INTERVAL_SECONDS must be at least 1"

run_case "no-target-groups" FAKE_ASG_TARGET_GROUPS=""
assert_failure "no target groups fails closed"
assert_out_has "no target groups reports missing load balancer registration" "has no target groups"
assert_no_detach "no target groups does not detach"

run_case "all-present" FAKE_ASG_TARGET_GROUPS="arn:tg:present-1 arn:tg:present-2"
assert_success "all target groups present succeeds"
assert_out_has "all target groups present says valid" "associations are valid"
assert_no_detach "all target groups present does not detach"

run_case "missing-pruned" \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present arn:tg:missing" \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing"
assert_success "missing target group is pruned"
assert_out_has "missing target group warns" "references deleted target group"
assert_out_has "missing target group summary warns replacement is external" "pruning only removes stale ARNs"
assert_detached "missing target group detach call" "arn:tg:missing"

run_case "validation-retryable-then-success" \
  VALIDATION_RETRY_INTERVAL_SECONDS=0 \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present arn:tg:missing" \
  FAKE_RETRYABLE_DESCRIBE_FOR="arn:tg:present" \
  FAKE_RETRYABLE_DESCRIBE_FAILS=1 \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing"
assert_success "retryable validation describe error retries"
assert_out_has "retryable validation describe warning is visible" "Retryable error validating target group"
assert_detached "retryable validation still prunes missing target group" "arn:tg:missing"

run_case "initial-describe-retryable-then-success" \
  VALIDATION_RETRY_INTERVAL_SECONDS=0 \
  FAKE_INITIAL_DESCRIBE_FAILS=1 \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present arn:tg:missing" \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing"
assert_success "retryable initial ASG describe error retries"
assert_out_has "retryable initial ASG describe warning is visible" "Retryable error reading ASG asg-test target-group associations"
assert_detached "retryable initial ASG describe still prunes missing target group" "arn:tg:missing"

run_case "initial-summary-newline-layout" \
  DRY_RUN=true \
  FAKE_ASG_TARGET_GROUPS=$'arn:tg:present\narn:tg:missing' \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing"
assert_success "initial ASG summary newline layout parses"
assert_out_has "initial ASG summary newline layout reaches dry-run detach" "[DRY RUN] Would detach"
assert_no_detach "initial ASG summary newline layout does not detach"

run_case "initial-describe-nonretryable-error" \
  FAKE_INITIAL_DESCRIBE_ERROR=AccessDenied \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present arn:tg:missing" \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing"
assert_failure "non-retryable initial ASG describe error fails"
assert_out_has "non-retryable initial ASG describe error has annotation" "Failed to read ASG asg-test target-group associations"
assert_out_has "non-retryable initial ASG describe error surfaces cause" "AccessDenied"
assert_no_detach "non-retryable initial ASG describe error does not detach"

run_case "initial-describe-retryable-exhausted" \
  VALIDATION_RETRIES=2 \
  VALIDATION_RETRY_INTERVAL_SECONDS=0 \
  FAKE_INITIAL_DESCRIBE_FAILS=99 \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present arn:tg:missing" \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing"
assert_failure "retryable initial ASG describe exhaustion fails"
assert_out_has "retryable initial ASG describe exhaustion surfaces context" "ThrottlingException"
assert_no_detach "retryable initial ASG describe exhaustion does not detach"

run_case "validation-retryable-exhausted" \
  VALIDATION_RETRIES=2 \
  VALIDATION_RETRY_INTERVAL_SECONDS=0 \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present arn:tg:missing" \
  FAKE_RETRYABLE_DESCRIBE_FOR="arn:tg:present" \
  FAKE_RETRYABLE_DESCRIBE_FAILS=99 \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing"
assert_failure "retryable validation describe exhaustion fails"
assert_out_has "retryable validation exhaustion surfaces context" "Failed to validate target group arn:tg:present"
assert_no_detach "retryable validation exhaustion does not detach"

run_case "all-target-groups-missing" \
  FAKE_ASG_TARGET_GROUPS="arn:tg:missing-1 arn:tg:missing-2" \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing-1 arn:tg:missing-2"
assert_failure "all missing target groups fail closed"
assert_out_has "all missing target groups error is visible" "Every target group currently attached"
assert_no_detach "all missing target groups does not detach"

run_case "dry-run-all-target-groups-missing" \
  DRY_RUN=true \
  FAKE_ASG_TARGET_GROUPS="arn:tg:missing-1 arn:tg:missing-2" \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing-1 arn:tg:missing-2"
assert_failure "dry-run all missing target groups still fails closed"
assert_out_has "dry-run all missing target groups explains intentional failure" "[DRY RUN]"
assert_no_detach "dry-run all missing target groups does not detach"

run_case "multiple-missing-pruned" \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present arn:tg:missing-1 arn:tg:missing-2" \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing-1 arn:tg:missing-2"
assert_success "multiple missing target groups are pruned"
assert_detached "multiple missing target group detach call" $'arn:tg:missing-1\narn:tg:missing-2'

eleven_missing="arn:tg:m01 arn:tg:m02 arn:tg:m03 arn:tg:m04 arn:tg:m05 arn:tg:m06 arn:tg:m07 arn:tg:m08 arn:tg:m09 arn:tg:m10 arn:tg:m11"
read -r -a eleven_missing_array <<< "$eleven_missing"
expected_eleven_missing=$(printf '%s\n' "${eleven_missing_array[@]}")
expected_first_ten_missing=$(printf '%s\n' "${eleven_missing_array[@]:0:10}")
run_case "chunked-detach" \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present $eleven_missing" \
  FAKE_MISSING_TARGET_GROUPS="$eleven_missing"
assert_success "more than ten missing target groups are pruned"
assert_detach_calls "more than ten missing target groups are chunked" "2"
assert_detached "more than ten missing target groups detach every missing ARN" "$expected_eleven_missing"

run_case "chunked-detach-second-call-fails" \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present $eleven_missing" \
  FAKE_MISSING_TARGET_GROUPS="$eleven_missing" \
  FAKE_DETACH_FAIL_ON_CALL=2
assert_failure "chunked detach second call failure fails"
assert_detach_calls "chunked detach second call failure reaches second chunk" "2"
assert_detached "chunked detach second call failure records first chunk" "$expected_first_ten_missing"
assert_out_has "chunked detach second call failure has annotation" "Failed to detach deleted target group association"

run_case "wait-describe-transient" \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present arn:tg:missing" \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing" \
  FAKE_WAIT_DESCRIBE_FAILS=1
assert_success "transient wait-loop describe failure retries"
assert_out_has "transient wait-loop describe warning is visible" "Retryable error reading ASG asg-test target-group associations"

run_case "wait-clears-on-second-poll" \
  WAIT_INTERVAL_SECONDS=1 \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present arn:tg:missing" \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing" \
  FAKE_DETACH_CLEAR_AFTER_WAIT_POLLS=1
assert_success "wait-loop succeeds after delayed ASG detach visibility"
assert_out_has "wait-loop logs delayed detach visibility" "Waiting for ASG asg-test to drop deleted target group(s): arn:tg:missing"
assert_detached "wait-loop delayed detach records missing target group" "arn:tg:missing"

run_case "wait-timeout" \
  WAIT_TIMEOUT_SECONDS=0 \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present arn:tg:missing" \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing" \
  FAKE_DETACH_NOOP=true
assert_failure "wait-loop timeout fails"
assert_out_has "wait-loop timeout reports remaining target group" "Timed out waiting for ASG asg-test to drop deleted target group(s): arn:tg:missing"

run_case "wait-describe-permanent-timeout" \
  WAIT_TIMEOUT_SECONDS=0 \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present arn:tg:missing" \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing" \
  FAKE_WAIT_DESCRIBE_FAILS=99
assert_failure "permanent wait-loop describe failure fails after retries"
assert_out_has "permanent wait-loop describe failure surfaces context" "Failed to read ASG asg-test target-group associations"

run_case "wait-asg-missing-after-detach" \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present arn:tg:missing" \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing" \
  FAKE_ASG_MISSING_AFTER_DETACH=true
assert_failure "missing ASG during wait fails"
assert_out_has "missing ASG during wait reports disappeared ASG" "Auto Scaling group disappeared"

run_case "dry-run" \
  DRY_RUN=true \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present arn:tg:missing" \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing"
assert_success "dry run with missing target group succeeds"
assert_out_has "dry run reports detach" "[DRY RUN] Would detach"
assert_no_detach "dry run does not detach"

run_case "describe-error" \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present arn:tg:denied" \
  FAKE_DESCRIBE_ERROR_FOR="arn:tg:denied"
assert_failure "non-TargetGroupNotFound describe failure fails"
assert_out_has "non-TargetGroupNotFound describe failure surfaces context" "Failed to validate target group"
assert_no_detach "describe failure does not detach"

run_case "detach-fails" \
  FAKE_ASG_TARGET_GROUPS="arn:tg:present arn:tg:missing" \
  FAKE_MISSING_TARGET_GROUPS="arn:tg:missing" \
  FAKE_DETACH_FAIL=true
assert_failure "detach failure fails"
assert_out_has "detach failure has annotation" "Failed to detach deleted target group association"
assert_out_has "detach failure surfaces aws error" "detach failed"

run_case "asg-not-found" FAKE_ASG_EXISTS=false
assert_failure "missing ASG fails"
assert_out_has "missing ASG reports ASG name" "Auto Scaling group not found: asg-test"
assert_no_detach "missing ASG does not detach"

echo ""
echo "Passed: $pass"
echo "Failed: $fail"
if [ "$fail" -gt 0 ]; then
  printf '\nFailures:\n%b' "$failures"
  exit 1
fi
