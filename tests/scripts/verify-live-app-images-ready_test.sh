#!/usr/bin/env bash
# Fixture tests for .github/scripts/verify-live-app-images-ready.sh.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/verify-live-app-images-ready.sh"

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

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

fake_resolver="$tmpdir/resolve-live-app-image-required.sh"
cat > "$fake_resolver" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail

echo "$*" > "$ARGS_LOG"
case "${MODE:-fresh}" in
  fresh)
    {
      echo "app_image_required=false"
      echo "server_tag=server-ok"
      echo "ac_tag=ac-ok"
      echo "relay_tag=relay-ok"
    } >> "$GITHUB_OUTPUT"
    ;;
  stale)
    {
      echo "app_image_required=true"
      echo "server_tag=server-old"
      echo "ac_tag=ac-old"
      echo "relay_tag=relay-old"
    } >> "$GITHUB_OUTPUT"
    ;;
  stale-dark-relay)
    {
      echo "app_image_required=true"
      echo "server_tag=server-old"
      echo "ac_tag=ac-old"
    } >> "$GITHUB_OUTPUT"
    ;;
  fail)
    echo "resolver boom" >&2
    exit 42
    ;;
  *)
    echo "unknown fake resolver mode: ${MODE:-}" >&2
    exit 99
    ;;
esac
FAKE
chmod +x "$fake_resolver"

run_case() {
  local name="$1" mode="$2" want_rc="$3" want="$4" not_want="${5:-}"
  local out rc args_log
  args_log="$tmpdir/args-${name//[^A-Za-z0-9_]/_}.log"

  out=$(ARGS_LOG="$args_log" MODE="$mode" RESOLVE_LIVE_APP_IMAGE_REQUIRED="$fake_resolver" "$SCRIPT" sandbox abcdef1234567890 2>&1)
  rc=$?

  if [[ "$want_rc" == "0" && "$rc" -eq 0 && "$out" == *"$want"* ]]; then
    report_pass "$name exits zero with expected output"
  elif [[ "$want_rc" != "0" && "$rc" -ne 0 && "$out" == *"$want"* ]]; then
    report_pass "$name fails with expected output"
  else
    report_fail "$name" "rc=$rc output='$out' want_rc=$want_rc containing '$want'"
  fi

  if [[ -n "$not_want" ]]; then
    assert_not_contains "$name omits unexpected output" "$out" "$not_want"
  fi
  if [[ -s "$args_log" && "$(<"$args_log")" == "sandbox abcdef1234567890" ]]; then
    report_pass "$name passes environment and SHA through"
  else
    report_fail "$name passes environment and SHA through" "args='$([[ -e "$args_log" ]] && cat "$args_log")'"
  fi
}

echo "verify-live-app-images-ready:"

run_case "fresh tags" fresh 0 "Live sandbox app image tags contain app tree for abcdef1234567890"
run_case "stale tags" stale 1 "Refusing to update /sandbox/nhp/deploy/deployed-commit to abcdef1234567890"
run_case "dark relay stale tags" stale-dark-relay 1 "ac active tag:     ac-old" "relay image tag:"
run_case "resolver failure" fail 1 "resolver boom"

usage_out=$("$SCRIPT" sandbox 2>&1)
usage_rc=$?
if [[ "$usage_rc" -eq 2 && "$usage_out" == *"Usage:"* ]]; then
  report_pass "usage rejects missing SHA"
else
  report_fail "usage rejects missing SHA" "rc=$usage_rc output='$usage_out'"
fi

echo ""
echo "Passed: $pass"
echo "Failed: $fail"
if [[ "$fail" -gt 0 ]]; then
  printf '\nFailures:%s\n' "$failures"
  exit 1
fi
