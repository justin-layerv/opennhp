#!/usr/bin/env bash
# check-agent-reg-vector-drift_test.sh — fixture tests for
# scripts/check-agent-reg-vector-drift.sh
# ----------------------------------------------------------------------------
# Exercise the DECISION logic of the upstream-drift check (byte-compare, the
# absence/fetch-failure skips, the missing-local guard, and the OK/DRIFT/SKIP
# messages and exit codes) with synthetic inputs and NO network / NO gh.
#
# The real script fetches the canonical agent_registration_golden.json from
# layervai/qurl-conformance via `gh api`; that fetch is bypassed whenever
# REMOTE_VECTOR is set (the test seam):
#   REMOTE_VECTOR=<path>         -> compare the local copy against that file
#   REMOTE_VECTOR=__ABSENT__     -> simulate a 404 at the source ref  (skip 0)
#   REMOTE_VECTOR=__FETCHFAIL__  -> simulate a transient fetch failure (skip 0)
# so this points at mktemp files / sentinels and asserts the outcome directly.
#
# The one behavior that MUST hold: real drift (canonical present, bytes differ)
# fails 1, while every not-our-fault condition (upstream not published yet,
# network/GitHub outage) SKIPS 0 rather than flapping the build. A missing LOCAL
# copy is a repo defect and must fail, not skip.
#
# Because the real script derives LOCAL_VECTOR from its own location
# (REPO_ROOT/nhp/core/testdata/...), the "missing local file" case runs a COPY
# of the script from a throwaway REPO_ROOT that has no testdata tree, so the
# guard fires without disturbing the real vendored file.
#
# Mirrors tests/scripts/check-conformance-parity_test.sh's harness (pass/fail
# counters, EXIT-trap tempdir cleanup, explicit exit-code assertions) and is run
# in the same place (validate-workflows.yml + `make lint-workflows`).
#
# Usage: bash tests/scripts/check-agent-reg-vector-drift_test.sh
# ============================================================================

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/check-agent-reg-vector-drift.sh"
LOCAL_VECTOR="$REPO_ROOT/nhp/core/testdata/agent_registration_golden.json"

pass=0
fail=0
failures=""

report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() {
  fail=$((fail + 1))
  failures="${failures}  ✗ $1: $2"$'\n'
  printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"
}

# Tempdir cleanup via a single EXIT trap (not per-test `trap ... RETURN`): a
# RETURN trap is global and fires on EVERY later function's return too, so a
# trap-less test on the stack would reference an out-of-scope $tmp under `set
# -u`. Accumulate dirs, remove them once at exit. (Same rationale as the
# conformance-parity fixture test.)
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

# Run the real script with the network fetch bypassed via REMOTE_VECTOR. Capture
# stdout+stderr together (SKIP/DRIFT/ERROR text goes to stderr) so the message
# assertions can see it.
_run() {
  REMOTE_VECTOR="$1" bash "$SCRIPT" 2>&1
}

# ---- identical bytes → exit 0, OK message -----------------------------------
# Feed the real local vendored file's OWN bytes as the "canonical" so the
# compare is a true match regardless of what the frozen vectors currently are.
test_identical_bytes() {
  local name="canonical == local → exit 0, OK message"
  local tmp
  tmp="$(_mktemp_d)"
  cp "$LOCAL_VECTOR" "$tmp/canonical.json"
  local out rc=0
  out="$(_run "$tmp/canonical.json")" || rc=$?
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

# ---- differing bytes → exit 1, DRIFT message (the whole point) ---------------
test_drift() {
  local name="canonical != local → exit 1, DRIFT message"
  local tmp
  tmp="$(_mktemp_d)"
  # A canonical that is the local bytes plus one appended byte => guaranteed drift.
  cat "$LOCAL_VECTOR" >"$tmp/canonical.json"
  printf 'X' >>"$tmp/canonical.json"
  local out rc=0
  out="$(_run "$tmp/canonical.json")" || rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit on drift, got 0. Output: $out"
    return
  fi
  if ! grep -q "DRIFT:" <<<"$out"; then
    report_fail "$name" "expected DRIFT message, got: $out"
    return
  fi
  # The remediation must surface the canonical sha so a re-sync can update the pin.
  if ! grep -q "agentRegFixtureSHA256" <<<"$out"; then
    report_fail "$name" "expected the re-sync hint naming agentRegFixtureSHA256, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- canonical absent at source ref (404) → SKIP 0 --------------------------
# Pre-publication is the CURRENT real state (the file is not on qurl-conformance
# main yet). It must NOT redden the build.
test_absent_remote_skips() {
  local name="canonical absent upstream (404) → exit 0, SKIP message"
  local out rc=0
  out="$(_run "__ABSENT__")" || rc=$?
  if [ "$rc" -ne 0 ]; then
    report_fail "$name" "expected exit 0 on upstream absence, got $rc. Output: $out"
    return
  fi
  if ! grep -q "SKIP:" <<<"$out"; then
    report_fail "$name" "expected a SKIP message, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- transient fetch failure → SKIP 0 ---------------------------------------
# A network/GitHub outage is not vector drift; skip rather than flap.
test_fetch_failure_skips() {
  local name="fetch failure (network/5xx) → exit 0, SKIP message"
  local out rc=0
  out="$(_run "__FETCHFAIL__")" || rc=$?
  if [ "$rc" -ne 0 ]; then
    report_fail "$name" "expected exit 0 on fetch failure, got $rc. Output: $out"
    return
  fi
  if ! grep -q "SKIP:" <<<"$out"; then
    report_fail "$name" "expected a SKIP message, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- injected REMOTE_VECTOR path missing → exit 1 (seam guard) --------------
# A bogus injected path must fail loudly, never silently compare empty.
test_injected_missing_path() {
  local name="injected REMOTE_VECTOR path missing → exit 1"
  local tmp
  tmp="$(_mktemp_d)"
  local out rc=0
  out="$(_run "$tmp/does-not-exist.json")" || rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit on a missing injected path, got 0. Output: $out"
    return
  fi
  report_pass "$name"
}

# ---- missing LOCAL vendored copy → exit 1 (repo-defect guard) ---------------
# Runs a COPY of the script from a throwaway REPO_ROOT with no testdata tree, so
# the local-file guard fires without touching the real vendored file. The guard
# runs before any fetch, so REMOTE_VECTOR is irrelevant here (set to __ABSENT__
# to be certain no network is attempted even if ordering ever changes).
test_missing_local_copy() {
  local name="missing local vendored copy → exit 1, ERROR guard"
  local tmp
  tmp="$(_mktemp_d)"
  mkdir -p "$tmp/scripts"
  cp "$SCRIPT" "$tmp/scripts/check-agent-reg-vector-drift.sh"
  # No $tmp/nhp/core/testdata/... exists => LOCAL_VECTOR is absent under this root.
  local out rc=0
  out="$(REMOTE_VECTOR="__ABSENT__" bash "$tmp/scripts/check-agent-reg-vector-drift.sh" 2>&1)" || rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit when the local copy is missing, got 0. Output: $out"
    return
  fi
  if ! grep -q "local vendored vector not found" <<<"$out"; then
    report_fail "$name" "expected the missing-local-file guard message, got: $out"
    return
  fi
  report_pass "$name"
}

echo "Running check-agent-reg-vector-drift_test.sh"
test_identical_bytes
test_drift
test_absent_remote_skips
test_fetch_failure_skips
test_injected_missing_path
test_missing_local_copy

printf '\n[check-agent-reg-vector-drift_test.sh] %d passed, %d failed\n' "$pass" "$fail"
if [ "$fail" -gt 0 ]; then
  printf 'Failures:\n'
  printf '%b' "$failures"
  exit 1
fi
