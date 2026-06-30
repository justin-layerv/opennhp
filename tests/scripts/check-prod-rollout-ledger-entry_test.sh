#!/usr/bin/env bash
# check-prod-rollout-ledger-entry_test.sh — fixture tests for
# .github/scripts/check-prod-rollout-ledger-entry.sh, the `select:added` branch
# of the prod-rollout-tasks gate.
# ----------------------------------------------------------------------------
# Given a newline-separated changed-file list on stdin, the helper passes iff a
# ledger entry (any file under docs/runbooks/prod-rollout-ledger/ except its
# README) is present. These cases fence:
#   - a real entry passes, alone or among unrelated files;
#   - the README alone does NOT count (a docs-only ledger touch isn't an entry);
#   - no ledger file, and empty input, fail closed with a ::error:: annotation;
#   - the path is anchored at the start, so a ledger path nested under some
#     other directory does not satisfy the match.
#
# Usage: bash tests/scripts/check-prod-rollout-ledger-entry_test.sh
# ============================================================================

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${REPO_ROOT}/.github/scripts/check-prod-rollout-ledger-entry.sh"

PASS=0
FAIL=0

# expect_pass NAME INPUT — asserts the helper exits 0 for the given file list.
# `printf '%s\n'` mirrors how the workflow pipes the changed-file list in.
expect_pass() {
	local name="$1" input="$2" code
	printf '%s\n' "$input" | "$SCRIPT" >/dev/null 2>&1
	code=$?
	if [[ "$code" -eq 0 ]]; then
		printf '  PASS: %s\n' "$name"
		PASS=$((PASS + 1))
	else
		printf '  FAIL: %s — expected exit 0, got %d\n' "$name" "$code" >&2
		FAIL=$((FAIL + 1))
	fi
}

# expect_fail NAME INPUT — asserts the helper rejects (non-zero) and annotates.
expect_fail() {
	local name="$1" input="$2" err code
	err="$(printf '%s\n' "$input" | "$SCRIPT" 2>&1 >/dev/null)"
	code=$?
	if [[ "$code" -eq 0 ]]; then
		printf '  FAIL: %s — expected non-zero exit, got 0\n' "$name" >&2
		FAIL=$((FAIL + 1))
		return
	fi
	if [[ "$err" != *"::error::"* ]]; then
		printf '  FAIL: %s — expected a ::error:: annotation, got %q\n' "$name" "$err" >&2
		FAIL=$((FAIL + 1))
		return
	fi
	printf '  PASS: %s\n' "$name"
	PASS=$((PASS + 1))
}

ENTRY='docs/runbooks/prod-rollout-ledger/2026-06-30-pr-2900-foo.md'
README='docs/runbooks/prod-rollout-ledger/README.md'

echo "Passes (a ledger entry is present):"
expect_pass "entry alone"               "$ENTRY"
expect_pass "entry among other files"   $'nhp/foo.go\n'"$ENTRY"$'\ndocs/bar.md'
expect_pass "entry plus the README"     "$README"$'\n'"$ENTRY"

echo "Fails (no ledger entry):"
expect_fail "README only"               "$README"
expect_fail "unrelated files only"      $'nhp/foo.go\ndocs/ARCHITECTURE.md'
expect_fail "empty input"               ""
expect_fail "ledger path not anchored"  'examples/docs/runbooks/prod-rollout-ledger/x.md'

echo
printf 'check-prod-rollout-ledger-entry: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
