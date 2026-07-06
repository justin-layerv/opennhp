#!/usr/bin/env bash
# ensure-sandbox-deployed_test.sh — regression tests for scheduled sandbox deploy routing.
# Ensures scheduled-release cannot bypass build-and-push.yml's app-image drift
# gate or deployed-commit post-switch gate by dispatching blue-green directly.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/ensure-sandbox-deployed.sh"
BUILD_AND_PUSH_WORKFLOW="$REPO_ROOT/.github/workflows/build-and-push.yml"

pass=0
fail=0
failures=""

report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() {
  fail=$((fail + 1))
  printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"
  failures+=$'\n'"- $1: $2"
}

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    report_pass "$label"
  else
    report_fail "$label" "missing '$needle' in: $haystack"
  fi
}

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    report_fail "$label" "unexpected '$needle' in: $haystack"
  else
    report_pass "$label"
  fi
}

run_already_deployed_case() {
  local dir out rc gh_log
  dir=$(mktemp -d)
  out="$dir/github_output"
  gh_log="$dir/gh.log"
  mkdir -p "$dir/bin"
  cat > "$dir/bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$GH_LOG"
exit 42
EOF
  chmod +x "$dir/bin/gh"

  PATH="$dir/bin:$PATH" GH_LOG="$gh_log" GITHUB_OUTPUT="$out" HEAD_SHA=0123456789abcdef0123456789abcdef01234567 SANDBOX_ALREADY=true \
    "$SCRIPT" >/dev/null 2>"$dir/stderr"
  rc=$?

  if [[ "$rc" -eq 0 ]]; then
    report_pass "already-deployed exits zero"
  else
    report_fail "already-deployed exits zero" "rc=$rc stderr=$(<"$dir/stderr")"
  fi
  if [[ ! -s "$gh_log" ]]; then
    report_pass "already-deployed does not call gh"
  else
    report_fail "already-deployed does not call gh" "$(<"$gh_log")"
  fi
  assert_contains "already-deployed outputs image tag" "$(<"$out")" "image_tag=0123456789abcdef0123456789abcdef01234567"
  assert_contains "already-deployed outputs method" "$(<"$out")" "method=already-deployed"

  rm -rf "$dir"
}

run_dispatch_case() {
  local dir out rc gh_output gh_log aws_log
  dir=$(mktemp -d)
  out="$dir/github_output"
  gh_log="$dir/gh.log"
  aws_log="$dir/aws.log"
  mkdir -p "$dir/bin"

  cat > "$dir/bin/gh" <<'EOF'
#!/usr/bin/env bash
args="$*"
echo "$args" >> "$GH_LOG"
case "$args" in
  "workflow run build-and-push.yml --ref main -f environment=sandbox -f deploy=true -f correlation_id="*)
    exit 0
    ;;
  run\ list\ --workflow\ build-and-push.yml*)
    echo "4242"
    exit 0
    ;;
  "run view 4242 --json status,conclusion --jq .status")
    echo "completed"
    exit 0
    ;;
  "run view 4242 --json conclusion --jq .conclusion")
    echo "success"
    exit 0
    ;;
  *)
    echo "unexpected gh args: $args" >&2
    exit 99
    ;;
esac
EOF
  chmod +x "$dir/bin/gh"

  cat > "$dir/bin/aws" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$AWS_LOG"
exit 97
EOF
  chmod +x "$dir/bin/aws"

  PATH="$dir/bin:$PATH" GH_LOG="$gh_log" AWS_LOG="$aws_log" GITHUB_REPOSITORY=layervai/nhp GITHUB_OUTPUT="$out" \
    HEAD_SHA=abcdefabcdefabcdefabcdefabcdefabcdefabcd SANDBOX_ALREADY=false FIND_DELAY_SECONDS=0 FIND_RETRIES=1 POLL_INTERVAL=0 POLL_TIMEOUT=5 \
    "$SCRIPT" >"$dir/stdout" 2>"$dir/stderr"
  rc=$?
  gh_output=$(<"$gh_log")

  if [[ "$rc" -eq 0 ]]; then
    report_pass "dispatch path exits zero"
  else
    report_fail "dispatch path exits zero" "rc=$rc stdout=$(<"$dir/stdout") stderr=$(<"$dir/stderr")"
  fi
  assert_contains "dispatches build-and-push deploy mode" "$gh_output" "workflow run build-and-push.yml --ref main -f environment=sandbox -f deploy=true"
  assert_contains "passes correlation id to build-and-push" "$gh_output" "-f correlation_id="
  assert_contains "finds build-and-push by correlation id" "$gh_output" "run list --workflow build-and-push.yml --limit 50 --json databaseId,displayTitle"
  assert_not_contains "does not use timestamp-based run matching" "$gh_output" "createdAt"
  assert_not_contains "lets build-and-push drift gate decide rebuild need" "$gh_output" "force_build=true"
  assert_not_contains "does not dispatch blue-green directly" "$gh_output" "blue-green-deploy.yml"
  if [[ ! -s "$aws_log" ]]; then
    report_pass "does not write deployed-commit directly"
  else
    report_fail "does not write deployed-commit directly" "$(<"$aws_log")"
  fi
  assert_contains "dispatch path outputs image tag" "$(<"$out")" "image_tag=abcdefabcdefabcdefabcdefabcdefabcdefabcd"
  assert_contains "dispatch path outputs method" "$(<"$out")" "method=build-and-push-deploy"

  rm -rf "$dir"
}

run_workflow_correlation_case() {
  local workflow
  workflow=$(<"$BUILD_AND_PUSH_WORKFLOW")

  assert_contains "build-and-push run-name embeds correlation id" "$workflow" "[corr:{0}]"
  assert_contains "build-and-push declares correlation input" "$workflow" "correlation_id:"
  assert_contains "build-and-push correlation input references shared finder" "$workflow" "find-dispatched-run.sh"
}

echo "ensure-sandbox-deployed:"
run_workflow_correlation_case
run_already_deployed_case
run_dispatch_case

echo ""
echo "Passed: $pass"
echo "Failed: $fail"
if [[ "$fail" -gt 0 ]]; then
  printf '\nFailures:%s\n' "$failures"
  exit 1
fi
