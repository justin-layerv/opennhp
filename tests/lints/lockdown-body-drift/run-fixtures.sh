#!/usr/bin/env bash
# run-fixtures.sh
# ----------------------------------------------------------------------------
# Regression fixtures for scripts/check-lockdown-body-drift.sh (#1645).
#
# Each fixture is a synthetic trio under fixtures/<name>/:
#   - main.tf      (TF_FILE)          — local + lockdown rule + SSM parameter
#   - resolver.go  (GO_RESOLVER_FILE) — the smoke resolver (param name only)
#   - fence.go     (GO_FENCE_FILE)    — the smoke fence (no map literal)
# The runner invokes the lint with each trio via its 3-arg override interface
# and asserts the expected exit code.
#
# Why fixtures: the production lint runs against the three real source files and
# self-validates in the happy path — but a regression in one of its greps (e.g.
# a future anchor change, or the count-gate awk extractor drifting after a TF
# fmt rule change) wouldn't surface until a real drift coincides with the bug.
# These fixtures pre-flush every failure mode the lint claims to catch, on every
# CI run, and exercise the otherwise-unused 3-arg override interface.
#
# Mirrors the pattern of tests/lints/redirect-url-drift/run-fixtures.sh:
# array-of-specs, lockstep consistency check between the array and the on-disk
# fixture dirs, single trapped tempdir.
#
# Usage:
#   ./tests/lints/lockdown-body-drift/run-fixtures.sh
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
FIXTURES_DIR="${REPO_ROOT}/tests/lints/lockdown-body-drift/fixtures"
LINT_SCRIPT="${REPO_ROOT}/scripts/check-lockdown-body-drift.sh"

if [ ! -x "$LINT_SCRIPT" ]; then
  echo "ERROR: lint script not executable: $LINT_SCRIPT" >&2
  exit 1
fi

# (fixture-name, expected-exit). Update README.md's table in lockstep when
# adding a row. Each broken fixture isolates ONE of the lint's invariants.
FIXTURES=(
  "in-sync|0"                      # all six invariants satisfied
  "missing-local|1"                # check 1: local.public_internal_lockdown_body = jsonencode(...) gone
  "message-body-inlined|1"         # check 2: rule message_body re-inlined (not the local)
  "value-inlined|1"                # check 3: SSM param value re-inlined (not the local)
  "fence-literal-reintroduced|1"   # check 4a: Go map literal resurrected
  "tf-param-name-drift|1"          # check 4b: TF param name lost the suffix
  "resolver-name-drift|1"          # check 4b: resolver names a different param
  "resolver-comment-only|1"        # check 4b: suffix survives only in a resolver comment
  "count-gate-drift|1"             # check 5: rule and param count gates differ
  "count-missing|1"                # check 5: rule lost its count line (no silent later-resource grab)
  "ct-drift|1"                     # check 6: TF content_type != the fence's publicALBLockdownExpectedCT
  "unrelated-content-type|0"       # check 6: an unrelated content_type elsewhere must NOT trip it
)

# Lockstep consistency check: the FIXTURES array and the on-disk fixture/
# directories must agree. A fixture dir added without a matching array entry
# (or vice versa) would silently never run. Mirrors the sibling lints.
declared_names=$(for spec in "${FIXTURES[@]}"; do echo "${spec%%|*}"; done | sort)
on_disk_names=$(find "$FIXTURES_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort)
if [ "$declared_names" != "$on_disk_names" ]; then
  echo "::error::fixture name mismatch between FIXTURES array and fixtures/ directory. Update both in lockstep." >&2
  diff <(echo "$declared_names") <(echo "$on_disk_names") >&2 || true
  exit 1
fi

# Single trapped tempdir for per-fixture log captures.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Running lockdown-body-drift fixtures..."

PASS=0
FAIL=0
for spec in "${FIXTURES[@]}"; do
  IFS='|' read -r name expected <<<"$spec"
  tf="${FIXTURES_DIR}/${name}/main.tf"
  resolver="${FIXTURES_DIR}/${name}/resolver.go"
  fence="${FIXTURES_DIR}/${name}/fence.go"
  out="${TMP}/${name}.log"
  actual=0
  "$LINT_SCRIPT" "$tf" "$resolver" "$fence" >"$out" 2>&1 || actual=$?
  if [ "$actual" -ne "$expected" ]; then
    echo "  FAIL: $name — expected exit $expected, got $actual" >&2
    echo "        tf:       $tf" >&2
    echo "        resolver: $resolver" >&2
    echo "        fence:    $fence" >&2
    echo "        lint output:" >&2
    sed 's/^/          /' "$out" >&2
    FAIL=$((FAIL + 1))
    continue
  fi
  printf '  PASS: %-28s (exit %d as expected)\n' "$name" "$actual"
  PASS=$((PASS + 1))
done

echo "lockdown-body-drift fixtures: ${PASS} passed, ${FAIL} failed."
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
