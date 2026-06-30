#!/usr/bin/env bash
# check-prod-rollout-tasks-body_test.sh — fixture tests for
# .github/scripts/check-prod-rollout-tasks-body.sh, the decision logic behind
# the `prod-rollout-tasks / Check PR body` gate.
# ----------------------------------------------------------------------------
# The gate's regex-heavy body parsing and its bot-identity exemption used to
# live inline in the workflow, untested. These cases fence the behaviour that
# matters:
#   - Dependabot PRs are exempt, and the match is EXACT (`dependabot[bot]`), so
#     a look-alike author such as `notdependabot[bot]` is not exempted.
#   - The exemption beats the draft branch and ignores the body entirely.
#   - Exactly one checkbox is required; zero, two, or a missing section fail
#     with a `::error::` annotation (dropping the annotation regresses the
#     operator-facing failure message).
#   - GitHub's CRLF body lines, the `-`/`*`/`+` bullet variants, and `[X]`/`[x]`
#     are all accepted, matching the `[[:space:]]*$` / `[-*+]` / `[xX]` anchors.
#
# Usage: bash tests/scripts/check-prod-rollout-tasks-body_test.sh
# ============================================================================

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${REPO_ROOT}/.github/scripts/check-prod-rollout-tasks-body.sh"

PASS=0
FAIL=0

# expect_pass NAME AUTHOR DRAFT BODY EXPECTED_TOKEN
# Asserts the script exits 0 and prints exactly EXPECTED_TOKEN on stdout.
expect_pass() {
	local name="$1" author="$2" draft="$3" body="$4" expected="$5"
	local out code
	out="$(PR_AUTHOR="$author" PR_DRAFT="$draft" PR_BODY="$body" "$SCRIPT" 2>/dev/null)"
	code=$?
	if [[ "$code" -ne 0 ]]; then
		printf '  FAIL: %s — expected exit 0, got %d\n' "$name" "$code" >&2
		FAIL=$((FAIL + 1))
		return
	fi
	if [[ "$out" != "$expected" ]]; then
		printf '  FAIL: %s — expected token %q, got %q\n' "$name" "$expected" "$out" >&2
		FAIL=$((FAIL + 1))
		return
	fi
	printf '  PASS: %s\n' "$name"
	PASS=$((PASS + 1))
}

# expect_fail NAME AUTHOR DRAFT BODY
# Asserts the script rejects (non-zero exit) and writes a `::error::` to stderr.
# Non-zero rather than exactly 1, so a future distinct error exit stays covered.
expect_fail() {
	local name="$1" author="$2" draft="$3" body="$4"
	local err code
	err="$(PR_AUTHOR="$author" PR_DRAFT="$draft" PR_BODY="$body" "$SCRIPT" 2>&1 >/dev/null)"
	code=$?
	if [[ "$code" -eq 0 ]]; then
		printf '  FAIL: %s — expected non-zero exit, got 0\n' "$name" >&2
		FAIL=$((FAIL + 1))
		return
	fi
	if [[ "$err" != *"::error::"* ]]; then
		printf '  FAIL: %s — expected a ::error:: annotation on stderr, got %q\n' "$name" "$err" >&2
		FAIL=$((FAIL + 1))
		return
	fi
	printf '  PASS: %s\n' "$name"
	PASS=$((PASS + 1))
}

NONE_BODY=$'## Prod Rollout Tasks\n\n- [x] Confirmed this PR has no prod rollout tasks'
ADDED_BODY=$'## Prod Rollout Tasks\n\n- [x] Added a prod rollout ledger entry'
BOTH_BODY=$'## Prod Rollout Tasks\n- [x] Added a prod rollout ledger entry\n- [x] Confirmed this PR has no prod rollout tasks'
ZERO_BODY=$'## Prod Rollout Tasks\n- [ ] Added a prod rollout ledger entry\n- [ ] Confirmed this PR has no prod rollout tasks'
# A later `## ` heading must bound the section so checkboxes below it do not count.
SCOPED_BODY=$'## Prod Rollout Tasks\n- [x] Confirmed this PR has no prod rollout tasks\n\n## Checklist\n- [x] Added a prod rollout ledger entry'
# A `### ` sub-heading is content WITHIN the section, not a boundary, so the box
# under it is still counted — two boxes here, which must fail.
SUBHEAD_BODY=$'## Prod Rollout Tasks\n- [x] Confirmed this PR has no prod rollout tasks\n### Notes\n- [x] Added a prod rollout ledger entry'
# GitHub serves PR bodies with CRLF line endings; the anchors must absorb the \r.
CRLF_BODY=$'## Prod Rollout Tasks\r\n\r\n- [x] Confirmed this PR has no prod rollout tasks\r'
# `*` and `+` are valid Markdown bullets, and GitHub renders `[X]` checked too.
STAR_BODY=$'## Prod Rollout Tasks\n* [X] Confirmed this PR has no prod rollout tasks'

echo "Exemptions:"
expect_pass "dependabot, empty body"          "dependabot[bot]" "false" ""            "pass:dependabot"
expect_pass "dependabot ignores body"         "dependabot[bot]" "false" "$ADDED_BODY"  "pass:dependabot"
expect_pass "dependabot beats draft"          "dependabot[bot]" "true"  ""            "pass:dependabot"
expect_pass "human draft, empty body"         "octocat"         "true"  ""            "pass:draft"

echo "Exact bot-identity match (no loosening):"
expect_fail "look-alike author not exempt"    "notdependabot[bot]" "false" ""
expect_fail "bare 'dependabot' not exempt"    "dependabot"         "false" ""

echo "Box selection:"
expect_pass "one box: no tasks"               "octocat" "false" "$NONE_BODY"   "select:none"
expect_pass "one box: added entry"            "octocat" "false" "$ADDED_BODY"  "select:added"
expect_pass "section bounded by next heading" "octocat" "false" "$SCOPED_BODY" "select:none"
expect_pass "CRLF body lines absorbed"        "octocat" "false" "$CRLF_BODY"   "select:none"
expect_pass "star bullet + [X] accepted"      "octocat" "false" "$STAR_BODY"   "select:none"

echo "Failures (must annotate):"
expect_fail "missing section"                 "octocat" "false" "no section here"
expect_fail "zero boxes checked"              "octocat" "false" "$ZERO_BODY"
expect_fail "two boxes checked"               "octocat" "false" "$BOTH_BODY"
expect_fail "sub-heading does not bound"      "octocat" "false" "$SUBHEAD_BODY"

echo
printf 'check-prod-rollout-tasks-body: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
