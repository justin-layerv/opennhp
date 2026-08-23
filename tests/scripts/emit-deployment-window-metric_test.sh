#!/usr/bin/env bash
# Fixture tests for .github/scripts/emit-deployment-window-metric.sh.
#
# Usage: bash tests/scripts/emit-deployment-window-metric_test.sh

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/emit-deployment-window-metric.sh"
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
  if [[ "${values[$index]}" == "FAIL" ]]; then
    echo "simulated date failure" >&2
    exit 1
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
count_file="$STATE_DIR/aws-count"
count=0
[[ -f "$count_file" ]] && count=$(cat "$count_file")
count=$((count + 1))
printf '%s' "$count" > "$count_file"
printf '%s\n' "$*" > "$STATE_DIR/aws-args"
printf '%s\n' "$*" > "$STATE_DIR/aws-args-$count"
printf '%s\n' "$*" >> "$STATE_DIR/aws-args-log"

if [[ "$*" != cloudwatch\ put-metric-data* ]]; then
  echo "unexpected aws invocation: $*" >&2
  exit 2
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dimensions)
      shift
      if [[ "${1:-}" != Environment=*,Cell=* ]]; then
        echo "unexpected --dimensions form: ${1:-<missing>}" >&2
        exit 2
      fi
      ;;
    Name=*)
      echo "unexpected bare Name= dimension argument: $1" >&2
      exit 2
      ;;
  esac
  shift
done

case "${FAKE_PUT_MODE:-success}" in
  success)
    exit 0
    ;;
  fail)
    echo "ThrottlingException: simulated put-metric-data failure" >&2
    exit 254
    ;;
  fail-once)
    if [[ "$count" -eq 1 ]]; then
      echo "ThrottlingException: simulated first put-metric-data failure" >&2
      exit 254
    fi
    exit 0
    ;;
  *)
    echo "unsupported FAKE_PUT_MODE: ${FAKE_PUT_MODE:-}" >&2
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
  local bin_dir="$case_dir/bin"
  mkdir -p "$case_dir"
  make_fake_commands "$bin_dir"

  LAST_STATE_DIR="$case_dir"
  LAST_OUT="$case_dir/out"
  PATH="$bin_dir:$PATH" FAKE_AWS_STATE_DIR="$case_dir" "$@" >"$LAST_OUT" 2>&1
  LAST_RC=$?
}

assert_rc() {
  local label="$1" want="$2"
  if [[ "$LAST_RC" -eq "$want" ]]; then
    report_pass "$label"
  else
    report_fail "$label" "got exit $LAST_RC, want $want; output: $(cat "$LAST_OUT")"
  fi
}

assert_contains() {
  local label="$1" needle="$2"
  if grep -Fq -- "$needle" "$LAST_OUT"; then
    report_pass "$label"
  else
    report_fail "$label" "missing '$needle'; output: $(cat "$LAST_OUT")"
  fi
}

assert_file_contains() {
  local label="$1" path="$2" needle="$3"
  if grep -Fq -- "$needle" "$path"; then
    report_pass "$label"
  else
    local got=""
    [[ -f "$path" ]] && got=$(cat "$path")
    report_fail "$label" "missing '$needle'; file had: $got"
  fi
}

assert_file_not_contains() {
  local label="$1" path="$2" needle="$3"
  if ! grep -Fq -- "$needle" "$path"; then
    report_pass "$label"
  else
    report_fail "$label" "unexpected '$needle'; file had: $(cat "$path")"
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

echo "Running emit-deployment-window-metric tests..."

# shellcheck disable=SC2016
run_case double-source bash -c \
  'set -euo pipefail; source "$1"; source "$1"; declare -p DEPLOYMENT_WINDOW_METRIC_NAMESPACE; [[ "$(declare -p DEPLOYMENT_WINDOW_METRIC_NAMESPACE)" == declare\ -*r* ]]; printf "namespace-readonly\n"' \
  bash "$SCRIPT"
assert_rc "metric helper can be sourced twice in one strict shell" 0
assert_contains "double source preserves the exact namespace" 'DEPLOYMENT_WINDOW_METRIC_NAMESPACE="LayerV/NHP/Deploy"'
assert_contains "double source leaves the namespace readonly" "namespace-readonly"
assert_file_equals "double source performs no AWS operation" "$LAST_STATE_DIR/aws-count" ""

# shellcheck disable=SC2016
run_case exact-mutable-source env DEPLOYMENT_WINDOW_METRIC_NAMESPACE=LayerV/NHP/Deploy \
  bash -c 'set -euo pipefail; source "$1"; declare -p DEPLOYMENT_WINDOW_METRIC_NAMESPACE; [[ "$(declare -p DEPLOYMENT_WINDOW_METRIC_NAMESPACE)" == declare\ -*r* ]]; printf "namespace-readonly\n"' bash "$SCRIPT"
assert_rc "exact caller namespace is accepted" 0
assert_contains "exact caller namespace is sealed readonly" "namespace-readonly"

# shellcheck disable=SC2016
run_case hostile-source env DEPLOYMENT_WINDOW_METRIC_NAMESPACE=Hostile/Namespace \
  bash -c 'set -euo pipefail; source "$1"' bash "$SCRIPT"
assert_rc "wrong preexisting namespace fails closed" 1
assert_contains "wrong namespace reports authority mismatch" \
  "ERROR: DEPLOYMENT_WINDOW_METRIC_NAMESPACE has unexpected authority 'Hostile/Namespace'"
assert_file_equals "wrong namespace fails before AWS" "$LAST_STATE_DIR/aws-count" ""

run_case success bash "$SCRIPT" prod cell0 server promote
assert_rc "single emit succeeds" 0
assert_contains "success message includes log-only breadcrumbs" "DeploymentWindow/DeploymentWindowRun metrics pushed (Environment=prod Cell=cell0 Component=server Strategy=promote)"
assert_file_equals "single emit publishes window and run marker atomically" "$LAST_STATE_DIR/aws-count" "1"
assert_file_contains "metric namespace is deploy-only" "$LAST_STATE_DIR/aws-args-log" "--namespace LayerV/NHP/Deploy"
assert_file_contains "metric-data mode is used" "$LAST_STATE_DIR/aws-args-log" "--metric-data"
assert_file_contains "window metric is present" "$LAST_STATE_DIR/aws-args-log" "MetricName=DeploymentWindow,"
assert_file_contains "run marker metric is present" "$LAST_STATE_DIR/aws-args-log" "MetricName=DeploymentWindowRun,"
assert_file_contains "put metric has bounded connect timeout" "$LAST_STATE_DIR/aws-args-log" "--cli-connect-timeout 5"
assert_file_contains "put metric has bounded read timeout" "$LAST_STATE_DIR/aws-args-log" "--cli-read-timeout 10"
assert_file_not_contains "dimensions shorthand is not mixed with metric-data" "$LAST_STATE_DIR/aws-args-log" "--dimensions"
assert_file_contains "environment dimension is present" "$LAST_STATE_DIR/aws-args-log" "Name=Environment,Value=prod"
assert_file_contains "cell dimension is present" "$LAST_STATE_DIR/aws-args-log" "Name=Cell,Value=cell0"
assert_file_not_contains "component stays log-only, not a dimension" "$LAST_STATE_DIR/aws-args-log" "Component="
assert_file_not_contains "strategy stays log-only, not a dimension" "$LAST_STATE_DIR/aws-args-log" "Strategy="

run_case put-failure env FAKE_PUT_MODE=fail bash "$SCRIPT" prod cell0 ac canary
assert_rc "put-metric-data failure is non-blocking" 0
assert_contains "failure emits warning" "::warning::Failed to push DeploymentWindow/DeploymentWindowRun metrics (Environment=prod Cell=cell0 Component=ac Strategy=canary); continuing"

run_case missing-args bash "$SCRIPT" prod cell0
assert_rc "missing log-only args fail fast" 1

# shellcheck disable=SC2016
run_case throttled-helper env \
  FAKE_DATE_SEQUENCE="100 110 161" \
  DEPLOYMENT_WINDOW_ENVIRONMENT=prod \
  DEPLOYMENT_WINDOW_CELL_ID=cell0 \
  DEPLOYMENT_WINDOW_COMPONENT=server \
  DEPLOYMENT_WINDOW_STRATEGY=canary-poll \
  DEPLOYMENT_WINDOW_EMIT_INTERVAL_SECONDS=60 \
  bash -c 'set -euo pipefail; source "$1"; emit_deployment_window_metric_throttled; emit_deployment_window_metric_throttled; emit_deployment_window_metric_throttled' bash "$SCRIPT"
assert_rc "throttled helper succeeds" 0
assert_file_equals "throttled helper emits only after interval" "$LAST_STATE_DIR/aws-count" "2"

# shellcheck disable=SC2016
run_case throttled-helper-retries-failed-put env \
  FAKE_PUT_MODE=fail-once \
  FAKE_DATE_SEQUENCE="100 110" \
  DEPLOYMENT_WINDOW_ENVIRONMENT=prod \
  DEPLOYMENT_WINDOW_CELL_ID=cell0 \
  DEPLOYMENT_WINDOW_COMPONENT=server \
  DEPLOYMENT_WINDOW_STRATEGY=canary-poll \
  DEPLOYMENT_WINDOW_EMIT_INTERVAL_SECONDS=60 \
  bash -c 'set -euo pipefail; source "$1"; emit_deployment_window_metric_throttled; emit_deployment_window_metric_throttled' bash "$SCRIPT"
assert_rc "throttled helper retries failed put" 0
assert_contains "throttled helper failed put warns" "::warning::Failed to push DeploymentWindow/DeploymentWindowRun metrics (Environment=prod Cell=cell0 Component=server Strategy=canary-poll); continuing"
assert_file_equals "failed put does not advance throttle" "$LAST_STATE_DIR/aws-count" "2"

# shellcheck disable=SC2016
run_case invalid-interval-helper env \
  FAKE_DATE_SEQUENCE="100 110" \
  DEPLOYMENT_WINDOW_ENVIRONMENT=prod \
  DEPLOYMENT_WINDOW_CELL_ID=cell0 \
  DEPLOYMENT_WINDOW_COMPONENT=ac \
  DEPLOYMENT_WINDOW_STRATEGY=promote \
  DEPLOYMENT_WINDOW_EMIT_INTERVAL_SECONDS=bogus \
  bash -c 'set -euo pipefail; source "$1"; emit_deployment_window_metric_throttled; emit_deployment_window_metric_throttled' bash "$SCRIPT"
assert_rc "invalid interval helper succeeds" 0
assert_file_equals "invalid interval falls back to 60s throttle" "$LAST_STATE_DIR/aws-count" "1"

# shellcheck disable=SC2016
run_case partially-configured-helper env \
  DEPLOYMENT_WINDOW_ENVIRONMENT=prod \
  DEPLOYMENT_WINDOW_CELL_ID=cell0 \
  DEPLOYMENT_WINDOW_COMPONENT=server \
  bash -c 'set -euo pipefail; source "$1"; emit_deployment_window_metric_throttled; emit_deployment_window_metric_throttled' bash "$SCRIPT"
assert_rc "partially configured helper succeeds" 0
assert_contains "partially configured helper warns once" "::warning::DeploymentWindow heartbeat partially configured; set DEPLOYMENT_WINDOW_ENVIRONMENT, DEPLOYMENT_WINDOW_CELL_ID, DEPLOYMENT_WINDOW_COMPONENT, and DEPLOYMENT_WINDOW_STRATEGY to enable long-poll suppression"
assert_file_equals "partially configured helper does not emit" "$LAST_STATE_DIR/aws-count" ""

# shellcheck disable=SC2016
run_case date-failure-helper env \
  FAKE_DATE_FAIL=1 \
  DEPLOYMENT_WINDOW_ENVIRONMENT=prod \
  DEPLOYMENT_WINDOW_CELL_ID=cell0 \
  DEPLOYMENT_WINDOW_COMPONENT=server \
  DEPLOYMENT_WINDOW_STRATEGY=promote \
  DEPLOYMENT_WINDOW_EMIT_INTERVAL_SECONDS=60 \
  bash -c 'set -euo pipefail; source "$1"; emit_deployment_window_metric_throttled; emit_deployment_window_metric_throttled' bash "$SCRIPT"
assert_rc "date-failure helper succeeds" 0
assert_contains "date-failure helper warns" "::warning::date +%s failed while throttling DeploymentWindow heartbeat; using shell monotonic fallback"
assert_file_equals "date-failure helper uses fallback throttle" "$LAST_STATE_DIR/aws-count" "1"

# shellcheck disable=SC2016
run_case mixed-clock-throttle env \
  FAKE_DATE_SEQUENCE="FAIL 100" \
  DEPLOYMENT_WINDOW_ENVIRONMENT=prod \
  DEPLOYMENT_WINDOW_CELL_ID=cell0 \
  DEPLOYMENT_WINDOW_COMPONENT=server \
  DEPLOYMENT_WINDOW_STRATEGY=promote \
  DEPLOYMENT_WINDOW_EMIT_INTERVAL_SECONDS=60 \
  bash -c 'set -euo pipefail; source "$1"; SECONDS=1061; emit_deployment_window_metric_throttled; emit_deployment_window_metric_throttled' bash "$SCRIPT"
assert_rc "mixed clock helper succeeds" 0
assert_file_equals "recent monotonic fallback throttles later epoch clock" "$LAST_STATE_DIR/aws-count" "1"

if [[ "$fail" -ne 0 ]]; then
  printf '\n%s' "$failures"
  exit 1
fi

printf 'emit-deployment-window-metric tests passed (%d assertions).\n' "$pass"
