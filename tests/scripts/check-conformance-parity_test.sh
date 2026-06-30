#!/usr/bin/env bash
# check-conformance-parity_test.sh — fixture tests for
# scripts/check-conformance-parity.sh
# ----------------------------------------------------------------------------
# Exercise the DECISION logic of the parity check (the byte-compare, the
# missing-file guard, the OK/DRIFT messages and exit codes) with synthetic
# vector files and NO network. The real script resolves its two
# issuer_signature_vectors.json copies via `go mod download` (Go module cache)
# and `npm ci` (npm node_modules); both of those resolution steps are skipped
# when GO_VECTOR / NPM_VECTOR are already set in the environment (the test
# seam), so this points both at mktemp files and asserts the outcome directly.
#
# Catches regressions in the compare logic in particular the false-green case
# where a missing path silently compares as an empty string instead of failing.
# Mirrors tests/scripts/check-golden-vectors_test.sh's harness (pass/fail
# counters, EXIT-trap tempdir cleanup, explicit exit-code assertions) and is
# run in the same place (validate-workflows.yml + `make lint-workflows`).
#
# Usage: bash tests/scripts/check-conformance-parity_test.sh
# ============================================================================

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/check-conformance-parity.sh"

pass=0
fail=0
failures=""

report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() {
  fail=$((fail + 1))
  failures="${failures}  ✗ $1: $2"$'\n'
  printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"
}

# Tempdir cleanup via a single EXIT trap rather than per-test `trap ... RETURN`:
# a RETURN trap is global and fires on EVERY later function's return too, so once
# a trap-less helper/test is on the stack it would reference an out-of-scope
# $tmp and trip `set -u`. Accumulate dirs and remove them once at exit instead.
_tmpdirs=()
_cleanup_tmpdirs() {
  local d
  for d in ${_tmpdirs[@]+"${_tmpdirs[@]}"}; do
    [ -n "$d" ] && rm -rf "$d"
  done
}
trap _cleanup_tmpdirs EXIT
_mktemp_d() {
  local d
  d="$(mktemp -d)"
  _tmpdirs+=("$d")
  printf '%s' "$d"
}

# Run the real script with both resolution steps bypassed: GO_VECTOR/NPM_VECTOR
# pre-set means no `go mod download` and no `npm ci` — only the compare/guard
# logic runs against the two given paths. Capture stdout+stderr together (the
# DRIFT/ERROR text goes to stderr) so the message assertions can see it.
_run() {
  GO_VECTOR="$1" NPM_VECTOR="$2" bash "$SCRIPT" 2>&1
}

# ---- identical bytes → exit 0, OK message -----------------------------------
test_identical_bytes() {
  local name="identical bytes → exit 0, OK message"
  local tmp
  tmp="$(_mktemp_d)"
  printf 'same-vector-bytes\n' >"$tmp/go.json"
  printf 'same-vector-bytes\n' >"$tmp/npm.json"
  local out rc=0
  out="$(_run "$tmp/go.json" "$tmp/npm.json")" || rc=$?
  if [ "$rc" -ne 0 ]; then
    report_fail "$name" "expected exit 0, got $rc. Output: $out"
    return
  fi
  if ! grep -q "OK:" <<<"$out"; then
    report_fail "$name" "expected an OK message, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- differing bytes → exit 1, DRIFT message --------------------------------
test_differing_bytes() {
  local name="differing bytes → exit 1, DRIFT message"
  local tmp
  tmp="$(_mktemp_d)"
  printf 'go-vector-bytes\n' >"$tmp/go.json"
  printf 'npm-vector-bytes-DIFFERENT\n' >"$tmp/npm.json"
  local out rc=0
  out="$(_run "$tmp/go.json" "$tmp/npm.json")" || rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit, got 0. Output: $out"
    return
  fi
  if ! grep -q "DRIFT:" <<<"$out"; then
    report_fail "$name" "expected DRIFT message, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- missing file → exit 1 (the false-green guard) --------------------------
# Point one side at a path that does not exist. The guard must FAIL rather than
# let cmp compare against an empty/absent file — the classic silent-pass bug.
test_missing_file() {
  local name="missing file → exit 1, does-not-exist guard fires"
  local tmp
  tmp="$(_mktemp_d)"
  printf 'go-vector-bytes\n' >"$tmp/go.json"
  # npm side intentionally never created.
  local out rc=0
  out="$(_run "$tmp/go.json" "$tmp/does-not-exist.json")" || rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit on missing file, got 0. Output: $out"
    return
  fi
  if ! grep -q "does not exist" <<<"$out"; then
    report_fail "$name" "expected 'does not exist' guard message, got: $out"
    return
  fi
  report_pass "$name"
}

echo "Running check-conformance-parity_test.sh"
test_identical_bytes
test_differing_bytes
test_missing_file

printf '\n[check-conformance-parity_test.sh] %d passed, %d failed\n' "$pass" "$fail"
if [ "$fail" -gt 0 ]; then
  printf 'Failures:\n'
  printf '%b' "$failures"
  exit 1
fi
