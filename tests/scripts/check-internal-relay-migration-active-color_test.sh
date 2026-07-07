#!/usr/bin/env bash
# Fixture tests for .github/scripts/check-internal-relay-migration-active-color.sh

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/check-internal-relay-migration-active-color.sh"

pass=0
fail=0
failures=""
report_pass() { pass=$((pass + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); failures+="  FAIL $1: $2\n"; printf '  \033[31mFAIL\033[0m %s\n      %s\n' "$1" "$2"; }

make_fake_aws() {
  local dir="$1"
  cat > "$dir/aws" <<'AWS'
#!/usr/bin/env bash
set -uo pipefail
printf '%s\n' "$*" >> "$FAKE_AWS_CALLS"

if [[ "${1:-}" != "ssm" || "${2:-}" != "get-parameter" ]]; then
  echo "fake-aws: unexpected command: $*" >&2
  exit 64
fi

if [[ "${FAKE_ACTIVE_COLOR:-__MISSING__}" == "__MISSING__" ]]; then
  exit 255
fi

printf '%s\n' "$FAKE_ACTIVE_COLOR"
AWS
  chmod +x "$dir/aws"
}

write_plan() {
  local path="$1" action_json="$2"
  cat > "$path" <<JSON
{
  "resource_changes": [
    {
      "address": "module.nhp.module.compute.aws_lb_target_group.udp_internal_green[0]",
      "change": { "actions": $action_json }
    }
  ]
}
JSON
}

run_case() {
  local active_color="$1" plan_file="$2"
  local bindir
  bindir=$(mktemp -d)
  make_fake_aws "$bindir"
  export FAKE_ACTIVE_COLOR="$active_color" FAKE_AWS_CALLS="$WORK/aws-calls"
  : > "$FAKE_AWS_CALLS"
  OUT=$(PATH="$bindir:$PATH" AWS_REGION=us-east-2 bash "$SCRIPT" sandbox "$plan_file" 2>&1)
  RC=$?
  rm -rf "$bindir"
}

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: check-internal-relay-migration-active-color tests require jq" >&2
  exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
RC=0
OUT=""

echo "Running internal relay migration active-color guard tests..."

NOOP_PLAN="$WORK/noop-plan.json"
cat > "$NOOP_PLAN" <<'JSON'
{
  "resource_changes": [
    {
      "address": "module.nhp.module.compute.aws_lb_target_group.udp_internal_green[0]",
      "change": { "actions": ["no-op"] }
    }
  ]
}
JSON
run_case "__MISSING__" "$NOOP_PLAN"
if [[ "$RC" -eq 0 ]] && [[ ! -s "$FAKE_AWS_CALLS" ]] \
   && [[ "$OUT" == *"guard not needed"* ]]; then
  report_pass "no-op plan exits without reading SSM"
else
  report_fail "no-op plan exits without SSM" "rc=$RC calls=$(cat "$FAKE_AWS_CALLS") out=<<<$OUT>>>"
fi

CREATE_PLAN="$WORK/create-plan.json"
write_plan "$CREATE_PLAN" '["create"]'
run_case "blue" "$CREATE_PLAN"
if [[ "$RC" -eq 0 ]] && [[ "$OUT" == *"guard passed"* ]] \
   && grep -q "/sandbox/nhp/server/active-color" "$FAKE_AWS_CALLS"; then
  report_pass "create plan passes while active color is blue"
else
  report_fail "create plan passes blue" "rc=$RC calls=$(cat "$FAKE_AWS_CALLS") out=<<<$OUT>>>"
fi

run_case "green" "$CREATE_PLAN"
if [[ "$RC" -ne 0 ]] && [[ "$OUT" == *"Refusing to apply"* ]] \
   && [[ "$OUT" == *"active-color is green"* ]]; then
  report_pass "create plan fails while active color is green"
else
  report_fail "create plan fails green" "rc=$RC out=<<<$OUT>>>"
fi

run_case "__MISSING__" "$CREATE_PLAN"
if [[ "$RC" -eq 0 ]] && [[ "$OUT" == *"greenfield blue/green apply"* ]]; then
  report_pass "create plan allows absent active-color as greenfield"
else
  report_fail "create plan allows missing active-color" "rc=$RC out=<<<$OUT>>>"
fi

REPLACE_PLAN="$WORK/replace-plan.json"
write_plan "$REPLACE_PLAN" '["delete", "create"]'
run_case "red" "$REPLACE_PLAN"
if [[ "$RC" -ne 0 ]] && [[ "$OUT" == *"unexpected value 'red'"* ]]; then
  report_pass "replace plan rejects unexpected active-color values"
else
  report_fail "replace plan rejects unexpected active-color" "rc=$RC out=<<<$OUT>>>"
fi

echo
if [[ "$fail" -gt 0 ]]; then
  printf '\033[31m%d passed, %d failed\033[0m\n' "$pass" "$fail"
  printf '%b' "$failures"
  exit 1
fi
printf '\033[32mAll %d tests passed\033[0m\n' "$pass"
