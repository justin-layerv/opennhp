#!/usr/bin/env bash
# run-fixtures.sh
# ----------------------------------------------------------------------------
# Regression fixtures for scripts/check-redirect-url-drift.sh (#1325).
#
# Each fixture is a pair of synthetic Go files (`plugin.go`, `smoke.go`)
# under fixtures/<name>/. The runner invokes the lint script with each
# pair as positional args and asserts the expected exit code.
#
# Why fixtures: the production lint runs against the two real source
# files and is self-validating in the happy path — but a regression in
# the regex (e.g., a future tightening that drops backtick raw-string
# support, or weakens the start-of-line anchor) wouldn't surface until
# a real drift coincides with the bug. Fixtures pre-flush every failure
# mode the lint claims to catch on every CI run.
#
# Mirrors the pattern of tests/lints/terraform-prod-drift/run-fixtures.sh:
# array-of-specs, lockstep consistency check between array and on-disk
# fixture dirs, single trapped tempdir.
#
# Usage:
#   ./tests/lints/redirect-url-drift/run-fixtures.sh
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
FIXTURES_DIR="${REPO_ROOT}/tests/lints/redirect-url-drift/fixtures"
LINT_SCRIPT="${REPO_ROOT}/scripts/check-redirect-url-drift.sh"

if [ ! -x "$LINT_SCRIPT" ]; then
  echo "ERROR: lint script not executable: $LINT_SCRIPT" >&2
  exit 1
fi

# (fixture-name, expected-exit). Update README.md's table in lockstep
# when adding a row.
FIXTURES=(
  "in-sync|0"
  "backtick-raw|0"
  "lockstep-rename|0"
  "comment-line|0"
  "block-comment-go-style|0"
  "mixed-quote-in-sync|0"
  "value-drift|1"
  "name-rename-smoke-only|1"
  "name-rename-plugin-only|1"
  "empty-value-both|1"
  "typed-declaration|1"
  "var-declaration|1"
  "multiple-declarations|1"
)

# Lockstep consistency check: the FIXTURES array and the on-disk
# fixture/ directories must agree. A fixture dir added without a
# matching array entry (or vice versa) would silently never run.
# Mirrors the sibling lint's pattern in
# tests/lints/terraform-prod-drift/run-fixtures.sh.
declared_names=$(for spec in "${FIXTURES[@]}"; do echo "${spec%%|*}"; done | sort)
on_disk_names=$(find "$FIXTURES_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort)
if [ "$declared_names" != "$on_disk_names" ]; then
  echo "::error::fixture name mismatch between FIXTURES array and fixtures/ directory. Update both in lockstep." >&2
  diff <(echo "$declared_names") <(echo "$on_disk_names") >&2 || true
  exit 1
fi

# Single trapped tempdir for all per-fixture log captures, so a SIGINT
# between mktemp and rm doesn't leak a tempfile.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Synthesize fixtures that can't live on disk because git/editor
# tooling would normalize them away. Each generated fixture is checked
# against the lint via run_synth (defined below), independent of the
# directory-based FIXTURES array above.
synth_dir="$TMP/synth"
mkdir -p "$synth_dir"
# CRLF fixture: same value on both sides, but plugin file uses CRLF
# line endings. The script protects against this through regex bounding
# (`"[^"]*"` terminates at the closing quote, so a trailing `\r` is
# naturally outside the match). The fixture would surface as a failure
# if a future regex relaxation ever allowed trailing characters past
# the closing delimiter.
printf '//go:build ignore\r\n\r\npackage fixture\r\n\r\nconst redirectURLField = "redirect_url"\r\n' \
  > "$synth_dir/crlf-plugin.go"
printf '//go:build ignore\n\npackage fixture\n\nconst redirectURLField = "redirect_url"\n' \
  > "$synth_dir/lf-smoke.go"

echo "Running redirect-url-drift fixtures..."

PASS=0
FAIL=0
for spec in "${FIXTURES[@]}"; do
  IFS='|' read -r name expected <<<"$spec"
  plugin="${FIXTURES_DIR}/${name}/plugin.go"
  smoke="${FIXTURES_DIR}/${name}/smoke.go"
  out="${TMP}/${name}.log"
  actual=0
  "$LINT_SCRIPT" "$plugin" "$smoke" >"$out" 2>&1 || actual=$?
  if [ "$actual" -ne "$expected" ]; then
    echo "  FAIL: $name — expected exit $expected, got $actual" >&2
    echo "        plugin: $plugin" >&2
    echo "        smoke:  $smoke" >&2
    echo "        lint output:" >&2
    sed 's/^/          /' "$out" >&2
    FAIL=$((FAIL + 1))
    continue
  fi
  printf '  PASS: %-25s (exit %d as expected)\n' "$name" "$actual"
  PASS=$((PASS + 1))
done

# run_synth <name> <plugin-path> <smoke-path> <expected-exit>
# ----------------------------------------------------------
# Same shape as the array-driven loop, for fixtures that can't live
# on-disk under fixtures/ (CRLF would be normalized by git; the
# missing-file case is literally a missing file).
run_synth() {
  local name="$1"
  local plugin="$2"
  local smoke="$3"
  local expected="$4"
  local out="${TMP}/synth-${name}.log"
  local actual=0
  "$LINT_SCRIPT" "$plugin" "$smoke" >"$out" 2>&1 || actual=$?
  if [ "$actual" -ne "$expected" ]; then
    echo "  FAIL: synth/$name — expected exit $expected, got $actual" >&2
    sed 's/^/          /' "$out" >&2
    FAIL=$((FAIL + 1))
    return
  fi
  printf '  PASS: %-25s (exit %d as expected)\n' "synth/$name" "$actual"
  PASS=$((PASS + 1))
}

# CRLF on the plugin side, LF on smoke. Equality should still hold
# because the script strips trailing CR before compare.
run_synth crlf-line-ending "$synth_dir/crlf-plugin.go" "$synth_dir/lf-smoke.go" 0
# Missing file on either side: the script's `[ ! -e "$file" ]` branch
# fires with a clear "missing $file" error. The two run_synth calls
# below cover symmetric coverage (missing on either side) — same
# rationale as the `name-rename-{plugin,smoke}-only` pair: locks the
# symmetry in against a future per-side regex split.
run_synth missing-smoke "$synth_dir/lf-smoke.go" "$synth_dir/does-not-exist.go" 1
run_synth missing-plugin "$synth_dir/does-not-exist.go" "$synth_dir/lf-smoke.go" 1
# One-arg rejection: the CLI takes either zero or two positional args.
# Calling with one would silently mix a custom path with the default
# sibling — exit 2 is the usage-error code.
out="${TMP}/synth-one-arg-rejected.log"
actual=0
"$LINT_SCRIPT" "$synth_dir/lf-smoke.go" >"$out" 2>&1 || actual=$?
if [ "$actual" -ne 2 ]; then
  echo "  FAIL: synth/one-arg-rejected — expected exit 2, got $actual" >&2
  sed 's/^/          /' "$out" >&2
  FAIL=$((FAIL + 1))
else
  printf '  PASS: %-25s (exit 2 as expected)\n' "synth/one-arg-rejected"
  PASS=$((PASS + 1))
fi

if [ "$FAIL" -gt 0 ]; then
  echo "$FAIL fixture(s) failed, $PASS passed." >&2
  exit 1
fi
echo "All $PASS redirect-url-drift fixtures passed."
