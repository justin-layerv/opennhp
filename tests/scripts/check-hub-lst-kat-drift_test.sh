#!/usr/bin/env bash
# check-hub-lst-kat-drift_test.sh — fixture tests for
# scripts/check-hub-lst-kat-drift.sh
# ----------------------------------------------------------------------------
# Exercise the DECISION logic of the Hub LST KAT drift check (per-label compare,
# the absence/fetch-failure skips, the missing-local and missing-marker guards,
# and the OK/DRIFT/ERROR messages and exit codes) with synthetic inputs and NO
# network / NO gh.
#
# The real script fetches connector_hub_lst_cookie_v1_vectors.json from
# layervai/qurl-conformance via `gh api`; that fetch is bypassed whenever
# REMOTE_VECTOR is set, and the local Go file is overridable via LOCAL_KAT_FILE:
#   REMOTE_VECTOR=<path>         -> compare against that JSON
#   REMOTE_VECTOR=__ABSENT__     -> simulate a 404 at the source ref  (skip 0)
#   REMOTE_VECTOR=__FETCHFAIL__  -> simulate a transient fetch failure (skip 0)
#
# The one behavior that MUST hold: real drift (canonical present, a value
# differs) fails 1, while every not-our-fault condition (upstream not published
# yet, network/GitHub outage) SKIPS 0 rather than flapping the build. A missing
# local file or a missing marker is a repo defect and must fail, not skip.
#
# Mirrors tests/scripts/check-agent-reg-vector-drift_test.sh's harness (pass/fail
# counters, EXIT-trap tempdir cleanup, explicit exit-code assertions) and runs in
# the same place (`make lint-workflows`).
#
# Usage: bash tests/scripts/check-hub-lst-kat-drift_test.sh
# ============================================================================

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/check-hub-lst-kat-drift.sh"

pass=0
fail=0
failures=""

report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() {
  fail=$((fail + 1))
  failures="${failures}  ✗ $1: $2"$'\n'
  printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"
}

# Accumulate tempdirs and remove them once at exit — a per-test RETURN trap is
# global and would fire on every later function return too (same rationale as the
# sibling fixture tests).
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

# The four values the fence compares, as a synthetic self-consistent pair: a Go
# file carrying the markers and a canonical JSON carrying the same values.
_write_local_go() {
  local path="$1" pubkey="$2" prefix="$3" cookie="$4" digest="$5"
  cat >"$path" <<EOF
package core

const (
	hubLSTProofServerPubKeyHex = "${pubkey}" // nhp-golden-vector: hub-lst-proof-server-static-pubkey
	hubLSTProofHeaderPrefixHex = "${prefix}" // nhp-golden-vector: hub-lst-proof-header-prefix
	hubLSTProofRawCookieHex    = "${cookie}" // nhp-golden-vector: hub-lst-proof-raw-cookie
	hubLSTProofExpectedDigest  = "${digest}" // nhp-golden-vector: hub-lst-proof-expected-digest
)
EOF
}

_write_canonical_json() {
  local path="$1" pubkey="$2" prefix="$3" cookie="$4" digest="$5"
  cat >"$path" <<EOF
{
  "proof_digest_kat": {
    "hub_server_static_public_key_hex": "${pubkey}",
    "header_prefix_hex": "${prefix}",
    "raw_cookie_hex": "${cookie}",
    "expected_digest_hex": "${digest}"
  }
}
EOF
}

_run() {
  local local_go="$1" remote="$2"
  LOCAL_KAT_FILE="$local_go" REMOTE_VECTOR="$remote" bash "$SCRIPT" 2>&1
}

echo "check-hub-lst-kat-drift.sh fixture tests"

# ---- all four values agree → exit 0, OK -------------------------------------
{
  tmp="$(_mktemp_d)"
  _write_local_go "$tmp/kat.go" "aa11" "bb22" "cc33" "dd44"
  _write_canonical_json "$tmp/canon.json" "aa11" "bb22" "cc33" "dd44"
  out="$(_run "$tmp/kat.go" "$tmp/canon.json")"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    report_fail "in-sync KAT exits 0" "exit=$rc out=$out"
  elif ! printf '%s' "$out" | grep -q "OK: Hub LST proof KAT lockstep"; then
    report_fail "in-sync KAT reports OK" "out=$out"
  elif ! printf '%s' "$out" | grep -q "(4 values)"; then
    report_fail "in-sync KAT compares all four values" "out=$out"
  else
    report_pass "in-sync KAT exits 0 with OK over all four values"
  fi
}

# ---- the expected digest drifts → exit 1, names the label -------------------
{
  tmp="$(_mktemp_d)"
  _write_local_go "$tmp/kat.go" "aa11" "bb22" "cc33" "dd44"
  _write_canonical_json "$tmp/canon.json" "aa11" "bb22" "cc33" "dd45"
  out="$(_run "$tmp/kat.go" "$tmp/canon.json")"
  rc=$?
  if [ "$rc" -ne 1 ]; then
    report_fail "drifted digest exits 1" "exit=$rc out=$out"
  elif ! printf '%s' "$out" | grep -q "DRIFT.*hub-lst-proof-expected-digest"; then
    report_fail "drifted digest names the label" "out=$out"
  else
    report_pass "drifted digest exits 1 and names the label"
  fi
}

# ---- the header prefix drifts (the version-byte regression shape) → exit 1 ---
# This is the case that matters most: the prefix carries the protocol version
# bytes, so a 1.1 -> 1.0 regression on one side only shows up here.
{
  tmp="$(_mktemp_d)"
  _write_local_go "$tmp/kat.go" "aa11" "c1d2e3f4c1d7e33101000004" "cc33" "dd44"
  _write_canonical_json "$tmp/canon.json" "aa11" "c1d2e3f4c1d7e33101010004" "cc33" "dd44"
  out="$(_run "$tmp/kat.go" "$tmp/canon.json")"
  rc=$?
  if [ "$rc" -ne 1 ]; then
    report_fail "drifted header prefix exits 1" "exit=$rc out=$out"
  elif ! printf '%s' "$out" | grep -q "DRIFT.*hub-lst-proof-header-prefix"; then
    report_fail "drifted header prefix names the label" "out=$out"
  else
    report_pass "drifted header prefix exits 1 and names the label"
  fi
}

# ---- a marker was removed → exit 1 (repo defect, not a skip) ----------------
{
  tmp="$(_mktemp_d)"
  _write_local_go "$tmp/kat.go" "aa11" "bb22" "cc33" "dd44"
  # Drop the raw-cookie marker comment, keeping the literal.
  sed -i.bak 's| // nhp-golden-vector: hub-lst-proof-raw-cookie||' "$tmp/kat.go"
  _write_canonical_json "$tmp/canon.json" "aa11" "bb22" "cc33" "dd44"
  out="$(_run "$tmp/kat.go" "$tmp/canon.json")"
  rc=$?
  if [ "$rc" -ne 1 ]; then
    report_fail "missing marker exits 1" "exit=$rc out=$out"
  elif ! printf '%s' "$out" | grep -q "no 'nhp-golden-vector: hub-lst-proof-raw-cookie' vector found"; then
    report_fail "missing marker is reported" "out=$out"
  else
    report_pass "missing marker exits 1 as a repo defect"
  fi
}

# ---- the canonical lost the proof_digest_kat object → exit 1 ----------------
{
  tmp="$(_mktemp_d)"
  _write_local_go "$tmp/kat.go" "aa11" "bb22" "cc33" "dd44"
  printf '{"something_else": {}}\n' >"$tmp/canon.json"
  out="$(_run "$tmp/kat.go" "$tmp/canon.json")"
  rc=$?
  if [ "$rc" -ne 1 ]; then
    report_fail "canonical layout change exits 1" "exit=$rc out=$out"
  elif ! printf '%s' "$out" | grep -q "no 'proof_digest_kat' object"; then
    report_fail "canonical layout change is reported" "out=$out"
  else
    report_pass "canonical layout change exits 1 rather than false-greening"
  fi
}

# ---- canonical vanished upstream → exit 1 (NOT a skip) ----------------------
# Deliberately unlike check-agent-reg-vector-drift.sh: our canonical is published
# on CANONICAL_REF, so a 404 means it moved or was removed and the fence must
# alarm rather than silently switch itself off.
{
  tmp="$(_mktemp_d)"
  _write_local_go "$tmp/kat.go" "aa11" "bb22" "cc33" "dd44"
  out="$(_run "$tmp/kat.go" "__ABSENT__")"
  rc=$?
  if [ "$rc" -ne 1 ]; then
    report_fail "absent canonical exits 1" "exit=$rc out=$out"
  elif ! printf '%s' "$out" | grep -q "moved or was removed upstream"; then
    report_fail "absent canonical explains the removal" "out=$out"
  else
    report_pass "absent canonical exits 1 (a vanished canonical alarms)"
  fi
}

# ---- transient fetch failure → SKIP 0 ---------------------------------------
{
  tmp="$(_mktemp_d)"
  _write_local_go "$tmp/kat.go" "aa11" "bb22" "cc33" "dd44"
  out="$(_run "$tmp/kat.go" "__FETCHFAIL__")"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    report_fail "fetch failure skips 0" "exit=$rc out=$out"
  elif ! printf '%s' "$out" | grep -q "^SKIP:"; then
    report_fail "fetch failure prints SKIP" "out=$out"
  else
    report_pass "fetch failure skips 0 (an outage is not drift)"
  fi
}

# ---- the local KAT file is missing → exit 1 (repo defect) -------------------
{
  tmp="$(_mktemp_d)"
  _write_canonical_json "$tmp/canon.json" "aa11" "bb22" "cc33" "dd44"
  out="$(_run "$tmp/does-not-exist.go" "$tmp/canon.json")"
  rc=$?
  if [ "$rc" -ne 1 ]; then
    report_fail "missing local file exits 1" "exit=$rc out=$out"
  elif ! printf '%s' "$out" | grep -q "ERROR: local KAT file not found"; then
    report_fail "missing local file is reported" "out=$out"
  else
    report_pass "missing local file exits 1 as a repo defect"
  fi
}

# ---- the REAL repo file carries every marker the script asks for ------------
# Guards against the markers being dropped or renamed in nhp/core during a
# refactor: uses the real Go file with a synthetic canonical built from its own
# extracted values, so it asserts marker PRESENCE without pinning the values.
{
  tmp="$(_mktemp_d)"
  real_go="$REPO_ROOT/nhp/core/hub_lst_cookie_test.go"
  extract() {
    sed -nE "s/^.*\"([^\"]*)\"[,;[:space:]]*\/\/.*nhp-golden-vector:[[:space:]]*$1([[:space:]]|\$).*/\1/p" "$real_go"
  }
  _write_canonical_json "$tmp/canon.json" \
    "$(extract hub-lst-proof-server-static-pubkey)" \
    "$(extract hub-lst-proof-header-prefix)" \
    "$(extract hub-lst-proof-raw-cookie)" \
    "$(extract hub-lst-proof-expected-digest)"
  out="$(_run "$real_go" "$tmp/canon.json")"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    report_fail "real nhp/core file carries all four markers" "exit=$rc out=$out"
  else
    report_pass "real nhp/core file carries all four markers"
  fi
}

echo ""
if [ "$fail" -ne 0 ]; then
  printf '\033[31mFAIL\033[0m: %d passed, %d failed\n' "$pass" "$fail"
  printf '%s' "$failures"
  exit 1
fi
printf '\033[32mPASS\033[0m: %d passed\n' "$pass"
