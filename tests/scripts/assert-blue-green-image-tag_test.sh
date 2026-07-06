#!/usr/bin/env bash
# assert-blue-green-image-tag_test.sh
# ----------------------------------------------------------------------------
# Unit tests for .github/scripts/assert-blue-green-image-tag.sh. The workflow-
# level structural test proves where the helper runs; these fixtures prove the
# helper fails closed on stale active/standby app bytes and delegates slot
# resolution to the shared resolver.
#
# Usage: bash tests/scripts/assert-blue-green-image-tag_test.sh
# ============================================================================

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/assert-blue-green-image-tag.sh"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

pass=0
fail=0
report_pass() { pass=$((pass + 1)); printf '  PASS %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); printf '  FAIL %s\n      %s\n' "$1" "$2"; }

make_resolver() {
  local path="$1" tag="$2" exit_code="${3:-0}"
  cat > "$path" <<EOF
#!/usr/bin/env bash
printf '%s %s %s\n' "\$1" "\$2" "\$3" >> "$TMP_DIR/resolver.calls"
if [[ "$exit_code" -ne 0 ]]; then
  echo "::error::synthetic resolver failure" >&2
  exit "$exit_code"
fi
printf '%s' "$tag"
EOF
  chmod +x "$path"
}

run_helper() {
  local resolver="$1" environment="$2" component="$3" slot="$4" expected="$5"
  OUT_FILE="$TMP_DIR/out"
  ERR_FILE="$TMP_DIR/err"
  : > "$OUT_FILE"
  : > "$ERR_FILE"
  RESOLVE_ACTIVE_IMAGE_TAG_SCRIPT="$resolver" \
    "$SCRIPT" "$environment" "$component" "$slot" "$expected" >"$OUT_FILE" 2>"$ERR_FILE"
  CODE=$?
}

assert_code() {
  local label="$1" want="$2"
  if [[ "$CODE" -eq "$want" ]]; then
    report_pass "$label"
  else
    report_fail "$label" "exit code $CODE, want $want; stdout=$(<"$OUT_FILE") stderr=$(<"$ERR_FILE")"
  fi
}

assert_out_contains() {
  local label="$1" needle="$2"
  if grep -Fq -- "$needle" "$OUT_FILE"; then
    report_pass "$label"
  else
    report_fail "$label" "stdout missing: $needle; stdout=$(<"$OUT_FILE")"
  fi
}

assert_err_contains() {
  local label="$1" needle="$2"
  if grep -Fq -- "$needle" "$ERR_FILE"; then
    report_pass "$label"
  else
    report_fail "$label" "stderr missing: $needle; stderr=$(<"$ERR_FILE")"
  fi
}

assert_resolver_calls() {
  local label="$1" want="$2"
  local got=""
  [[ -f "$TMP_DIR/resolver.calls" ]] && got=$(<"$TMP_DIR/resolver.calls")
  if [[ "$got" == "$want" ]]; then
    report_pass "$label"
  else
    report_fail "$label" "resolver calls = '$got', want '$want'"
  fi
}

reset_calls() {
  rm -f "$TMP_DIR/resolver.calls"
}

echo "assert-blue-green-image-tag:"

if [[ ! -x "$SCRIPT" ]]; then
  report_fail "helper is executable" "$SCRIPT is missing or not executable"
else
  report_pass "helper is executable"
fi

resolver="$TMP_DIR/resolver"

reset_calls
make_resolver "$resolver" "sha-good"
run_helper "$resolver" sandbox server active sha-good
assert_code "matching active server tag exits zero" 0
assert_out_contains "matching active server tag prints expected tag" "server expected active tag: sha-good"
assert_out_contains "matching active server tag prints resolved tag" "server resolved active tag: sha-good"
assert_resolver_calls "matching active server tag resolves sandbox server active" "sandbox server active"

reset_calls
make_resolver "$resolver" "sha-old"
run_helper "$resolver" sandbox ac active sha-new
assert_code "stale active AC tag fails" 1
assert_err_contains "stale active AC tag refuses success" "Refusing to report blue/green success against stale app bytes"
assert_err_contains "stale active AC tag gives half-switched remediation" "Traffic may already be switched"
assert_err_contains "stale active AC tag names re-run component" "component=ac"
assert_resolver_calls "stale active AC tag resolves sandbox ac active" "sandbox ac active"

reset_calls
make_resolver "$resolver" "sha-green"
run_helper "$resolver" sandbox server standby sha-green
assert_code "matching standby server tag exits zero" 0
assert_out_contains "matching standby server tag prints expected tag" "server expected standby tag: sha-green"
assert_out_contains "matching standby server tag prints resolved tag" "server resolved standby tag: sha-green"
assert_resolver_calls "matching standby server tag resolves sandbox server standby" "sandbox server standby"

reset_calls
make_resolver "$resolver" "sha-old"
run_helper "$resolver" sandbox ac standby sha-new
assert_code "stale standby AC tag fails" 1
assert_err_contains "stale standby AC tag refuses success" "Refusing to report blue/green success against stale app bytes"
assert_err_contains "stale standby AC tag gives pre-switch remediation" "Traffic has not been switched by this assertion"
assert_err_contains "stale standby AC tag names re-run component" "component=ac"
assert_resolver_calls "stale standby AC tag resolves sandbox ac standby" "sandbox ac standby"

reset_calls
make_resolver "$resolver" "sha-unused"
run_helper "$resolver" sandbox server active ""
assert_code "empty target tag fails before resolver" 1
assert_err_contains "empty target tag reports validation bug" "Server target image tag is empty"
assert_resolver_calls "empty target tag does not resolve" ""

reset_calls
make_resolver "$resolver" "sha-unused"
run_helper "$resolver" prod server standby sha-prod
assert_code "non-sandbox skips" 0
assert_out_contains "non-sandbox prints skip notice" "Server standby-slot assertion skipped"
assert_resolver_calls "non-sandbox does not resolve" ""

reset_calls
make_resolver "$resolver" "sha-unused"
run_helper "$resolver" sandbox relay active sha-relay
assert_code "invalid component fails" 1
assert_err_contains "invalid component reports allowed values" "Invalid component 'relay'"
assert_resolver_calls "invalid component does not resolve" ""

reset_calls
make_resolver "$resolver" "sha-unused"
run_helper "$resolver" sandbox server passive sha-any
assert_code "invalid slot fails" 1
assert_err_contains "invalid slot reports allowed values" "Invalid slot 'passive'"
assert_resolver_calls "invalid slot does not resolve" ""

reset_calls
make_resolver "$resolver" "sha-unused" 42
run_helper "$resolver" sandbox server active sha-any
assert_code "active resolver failure propagates" 42
assert_err_contains "active resolver failure keeps resolver error" "synthetic resolver failure"
assert_resolver_calls "active resolver failure calls sandbox server active" "sandbox server active"

reset_calls
make_resolver "$resolver" "sha-unused" 43
run_helper "$resolver" sandbox server standby sha-any
assert_code "standby resolver failure propagates" 43
assert_err_contains "standby resolver failure keeps resolver error" "synthetic resolver failure"
assert_resolver_calls "standby resolver failure calls sandbox server standby" "sandbox server standby"

echo
echo "  passed: $pass  failed: $fail"
[[ "$fail" -eq 0 ]]
