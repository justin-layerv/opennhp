#!/usr/bin/env bash
# check-golden-vectors_test.sh — fixture tests for scripts/check-golden-vectors.sh
# ----------------------------------------------------------------------------
# Write synthetic Go + TS files for BOTH cross-language pairs into a tempdir
# that mimics the repo layout, symlink the real script in (it resolves
# REPO_ROOT from its own location), and assert exit code + key output lines.
# Catches regressions in the marker extractor and the multi-pair loop — in
# particular the false-green case where a parser regression makes a file
# extract to an empty set and a pair passes vacuously. Run BEFORE the real
# check in CI for exactly that reason.
#
# The generalized script errors if ANY file across ANY pair is missing or has
# no marked vectors, so every case stands up all four files and keeps the pair
# it is NOT testing in-sync, isolating one failure mode at a time.
#
# Usage: bash tests/scripts/check-golden-vectors_test.sh
# ============================================================================

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/check-golden-vectors.sh"

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

# In-sync const blocks for each pair. Values are arbitrary quoted strings — the
# cross-check compares the two files' copies, not the values' validity.
FP_GO_OK=$'\tconst wantA = "AAAAAAAAAAA" // nhp-golden-vector: fp-a\n\tconst wantB = "BBBBBBBBBBB" // nhp-golden-vector: fp-b'
FP_TS_OK=$'  const WANT_A = "AAAAAAAAAAA"; // nhp-golden-vector: fp-a\n  const WANT_B = "BBBBBBBBBBB"; // nhp-golden-vector: fp-b'
KDF_GO_OK=$'\t\tdst0: "1111111111111111", // nhp-golden-vector: kdf-a\n\t\tdst1: "2222222222222222", // nhp-golden-vector: kdf-b'
KDF_TS_OK=$'    dst0: "1111111111111111", // nhp-golden-vector: kdf-a\n    dst1: "2222222222222222", // nhp-golden-vector: kdf-b'

# A minimal file body: two prose mentions of the marker that must BOTH be
# ignored — one with no quoted value, and one with a quoted word *before* the
# marker (there the // precedes the quote, so the trailing-// anchor rejects it)
# — followed by the parameterized marked const block. The in-sync count
# assertion below proves both prose lines are excluded.
_body() {
  cat <<EOF
// nhp-golden-vector: prose mention with the marker but no quoted value.
// a "quoted" word appears before the marker here: nhp-golden-vector: ignoreme
$1
EOF
}

# Stand up all four files (both pairs) at their real relative paths, plus a
# scripts/ symlink to the real script.
_make_fixture_repo() {
  local dir="$1" fp_go="$2" fp_ts="$3" kdf_go="$4" kdf_ts="$5"
  mkdir -p "$dir/scripts" "$dir/nhp/utils" "$dir/nhp/core" \
    "$dir/endpoints/js-agent/test"
  ln -sf "$SCRIPT" "$dir/scripts/check-golden-vectors.sh"
  printf '%s\n' "$(_body "$fp_go")" >"$dir/nhp/utils/crypto_fingerprint_test.go"
  printf '%s\n' "$(_body "$fp_ts")" >"$dir/endpoints/js-agent/test/fingerprint.test.ts"
  printf '%s\n' "$(_body "$kdf_go")" >"$dir/nhp/core/kdf_test.go"
  printf '%s\n' "$(_body "$kdf_ts")" >"$dir/endpoints/js-agent/test/kdf.test.ts"
}

_run() { (cd "$1" && bash scripts/check-golden-vectors.sh 2>&1); }

# ---- test: both pairs in-sync; prose lines excluded from the count ----------
test_all_in_sync() {
  local name="both pairs in-sync → exit 0, count excludes prose lines"
  local tmp
  tmp="$(_mktemp_d)"
  _make_fixture_repo "$tmp" "$FP_GO_OK" "$FP_TS_OK" "$KDF_GO_OK" "$KDF_TS_OK"
  local out rc=0
  out="$(_run "$tmp")" || rc=$?
  if [ "$rc" -ne 0 ]; then
    report_fail "$name" "expected exit 0, got $rc. Output: $out"
    return
  fi
  if ! grep -q "2 pairs, 4 vectors" <<<"$out"; then
    report_fail "$name" "expected '2 pairs, 4 vectors' (prose excluded), got: $out"
    return
  fi
  report_pass "$name"
}

# ---- drift: one pair drifts on a single value; the other stays in-sync ------
# Parameterized so each pair is exercised identically (same exit/DRIFT/named-
# file/both-sides assertions) — proving the loop attributes the drift to the
# correct pair regardless of its position in PAIRS. Tempdirs are reclaimed by the
# shared EXIT trap (see _mktemp_d), so this needs no per-call cleanup.
_assert_pair_drift() {
  local name="$1" fp_ts="$2" kdf_ts="$3" expect_file="$4" orig="$5" drift="$6"
  local tmp
  tmp="$(_mktemp_d)"
  _make_fixture_repo "$tmp" "$FP_GO_OK" "$fp_ts" "$KDF_GO_OK" "$kdf_ts"
  local out rc=0
  out="$(_run "$tmp")" || rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit, got 0. Output: $out"
    return
  fi
  if ! grep -q "DRIFT:" <<<"$out"; then
    report_fail "$name" "expected DRIFT message, got: $out"
    return
  fi
  if ! grep -q "$expect_file" <<<"$out"; then
    report_fail "$name" "expected '$expect_file' named, got: $out"
    return
  fi
  if ! grep -q "$orig" <<<"$out" || ! grep -q "$drift" <<<"$out"; then
    report_fail "$name" "expected both sides ($orig / $drift), got: $out"
    return
  fi
  report_pass "$name"
}

test_fingerprint_drift() {
  local fp_ts_drift
  fp_ts_drift=$'  const WANT_A = "ZZZZZZZZZZZ"; // nhp-golden-vector: fp-a\n  const WANT_B = "BBBBBBBBBBB"; // nhp-golden-vector: fp-b'
  _assert_pair_drift "fingerprint pair value drift → exit 1, names that pair" \
    "$fp_ts_drift" "$KDF_TS_OK" "fingerprint.test.ts" \
    "fp-a=AAAAAAAAAAA" "fp-a=ZZZZZZZZZZZ"
}

test_kdf_drift() {
  local kdf_ts_drift
  kdf_ts_drift=$'    dst0: "9999999999999999", // nhp-golden-vector: kdf-a\n    dst1: "2222222222222222", // nhp-golden-vector: kdf-b'
  _assert_pair_drift "kdf pair value drift → exit 1, names that pair" \
    "$FP_TS_OK" "$kdf_ts_drift" "kdf_test.go" \
    "kdf-a=1111111111111111" "kdf-a=9999999999999999"
}

# ---- test: a pair has no marked vectors (the false-green guard) -------------
test_missing_marker() {
  local name="no marked vectors on the kdf TS side → exit 1, not vacuous pass"
  local tmp
  tmp="$(_mktemp_d)"
  # Empty kdf TS const block: only the prose mention remains (marker, no quote).
  _make_fixture_repo "$tmp" "$FP_GO_OK" "$FP_TS_OK" "$KDF_GO_OK" ""
  local out rc=0
  out="$(_run "$tmp")" || rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit on empty extraction, got 0. Output: $out"
    return
  fi
  if ! grep -q "no .* vectors found in" <<<"$out"; then
    report_fail "$name" "expected 'no ... vectors found in' error, got: $out"
    return
  fi
  if ! grep -q "kdf.test.ts" <<<"$out"; then
    report_fail "$name" "expected the empty (kdf TS) path named, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- test: a source file is missing entirely -------------------------------
test_missing_file() {
  local name="kdf Go file missing → exit 1, clear error"
  local tmp
  tmp="$(_mktemp_d)"
  _make_fixture_repo "$tmp" "$FP_GO_OK" "$FP_TS_OK" "$KDF_GO_OK" "$KDF_TS_OK"
  rm -f "$tmp/nhp/core/kdf_test.go"
  local out rc=0
  out="$(_run "$tmp")" || rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit, got 0. Output: $out"
    return
  fi
  if ! grep -q "missing" <<<"$out"; then
    report_fail "$name" "expected 'missing' error, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- test: a duplicate label within one file → loud error ------------------
test_duplicate_label() {
  local name="duplicate label in one file → exit 1, names it"
  local tmp
  tmp="$(_mktemp_d)"
  local kdf_ts_dup
  kdf_ts_dup=$'    dst0: "1111111111111111", // nhp-golden-vector: kdf-a\n    dst1: "2222222222222222", // nhp-golden-vector: kdf-a'
  _make_fixture_repo "$tmp" "$FP_GO_OK" "$FP_TS_OK" "$KDF_GO_OK" "$kdf_ts_dup"
  local out rc=0
  out="$(_run "$tmp")" || rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit, got 0. Output: $out"
    return
  fi
  if ! grep -q "duplicate" <<<"$out"; then
    report_fail "$name" "expected 'duplicate' error, got: $out"
    return
  fi
  if ! grep -q "kdf-a" <<<"$out"; then
    report_fail "$name" "expected the duplicated label named, got: $out"
    return
  fi
  report_pass "$name"
}

# ---- real-tree fence: every PAIRS source is in validate-workflows.yml paths --
# Runs against the REAL repo (not a tempdir): asserts every file the lint reads
# (`--list-sources`) is covered by a literal or wildcard entry in the workflow's
# `paths:` trigger, so an edit to any vector file actually re-fires this lint.
# Without it, adding a pair to PAIRS but forgetting the workflow paths would
# silently skip CI on a one-sided edit. Mirrors check-asp-and-ac-id-lockstep.
test_workflow_trigger_paths_cover_lint_sources() {
  local name="workflow trigger paths cover all PAIRS sources"
  local workflow="$REPO_ROOT/.github/workflows/validate-workflows.yml"
  if [ ! -f "$workflow" ]; then
    report_fail "$name" "workflow missing: $workflow"
    return
  fi
  local missing="" src
  while IFS= read -r src; do
    [ -z "$src" ] && continue
    # Covered by a literal path entry?
    if grep -qE "^[[:space:]]*-[[:space:]]+\"${src}\"" "$workflow"; then
      continue
    fi
    # ...or by a wildcard entry whose `**`-stripped prefix is a dir prefix.
    local covered=0 pattern prefix
    while IFS= read -r pattern; do
      pattern=$(printf '%s' "$pattern" | sed -E 's/^[[:space:]]*-[[:space:]]+"//;s/"$//')
      case "$pattern" in
        *'**')
          prefix="${pattern%/**}"
          if [[ "$src" == "$prefix"/* ]] || [ "$src" = "$prefix" ]; then
            covered=1
            break
          fi
          ;;
      esac
    done < <(grep -E '^[[:space:]]*-[[:space:]]+".*\*\*"' "$workflow")
    [ "$covered" -eq 1 ] || missing="${missing}    ${src}"$'\n'
  done < <(bash "$SCRIPT" --list-sources)
  if [ -n "$missing" ]; then
    report_fail "$name" "validate-workflows.yml paths do not cover these PAIRS sources (add them so an edit re-fires the lint):"$'\n'"$missing"
    return
  fi
  report_pass "$name"
}

echo "Running check-golden-vectors_test.sh"
test_all_in_sync
test_fingerprint_drift
test_kdf_drift
test_missing_marker
test_missing_file
test_duplicate_label
test_workflow_trigger_paths_cover_lint_sources

printf '\n[check-golden-vectors_test.sh] %d passed, %d failed\n' "$pass" "$fail"
if [ "$fail" -gt 0 ]; then
  printf 'Failures:\n'
  printf '%b' "$failures"
  exit 1
fi
