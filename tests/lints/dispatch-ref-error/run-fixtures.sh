#!/usr/bin/env bash
# run-fixtures.sh
# ----------------------------------------------------------------------------
# Contract tests for scripts/print-dispatch-ref-error.sh.
#
# The script is called by build-and-push.yml's `setup` job when
# workflow_dispatch fires from a non-main ref. It must:
#   1. Exit 1 unconditionally (the workflow's `if:` gate has
#      already determined the dispatch is invalid; the script's
#      job is to render the error and fail).
#   2. Reflect $GITHUB_REF in the error annotation, so the
#      operator sees what they actually dispatched against.
#   3. Include the load-bearing strings: the gh command to
#      re-dispatch, the trust-policy reference (#1121), and the
#      `refs/heads/main` requirement.
#
# Why fixture-test a 30-line shell script: the script's whole
# purpose is to be the operator's first explanation of why the
# dispatch failed. A regression that drops the gh command, the
# refs/heads/main requirement, or the #1121 cross-reference
# silently degrades the failure UX without changing exit code,
# and the workflow's own logs would still look "correct" to
# CI. These tests pin every claim the PR description makes
# about the message.
#
# Usage:
#   ./tests/lints/dispatch-ref-error/run-fixtures.sh
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="${REPO_ROOT}/scripts/print-dispatch-ref-error.sh"

if [[ ! -x "${SCRIPT}" ]]; then
	echo "ERROR: script not executable: ${SCRIPT}" >&2
	exit 1
fi

PASS=0
FAIL=0

assert_contains() {
	local name="$1" haystack="$2" needle="$3"
	if [[ "${haystack}" == *"${needle}"* ]]; then
		printf '  PASS: %s\n' "${name}"
		PASS=$((PASS + 1))
	else
		printf '  FAIL: %s — output did not contain %q\n' "${name}" "${needle}" >&2
		printf '        full output:\n' >&2
		printf '%s\n' "${haystack}" | sed 's/^/          /' >&2
		FAIL=$((FAIL + 1))
	fi
}

# ---------------------------------------------------------------------------
# Run once with a representative feature-branch ref. Capture stderr
# (where the script writes), retain exit code separately so a
# non-1 exit is its own failure.
# ---------------------------------------------------------------------------
TEST_REF="refs/heads/chore/some-feature-branch"
EXIT=0
# Capture stdout (where the script writes ::error:: annotations to
# match the repo convention used by build-and-push.yml's other
# echo "::error::..." invocations).
OUT="$(GITHUB_REF="${TEST_REF}" "${SCRIPT}" 2>/dev/null)" || EXIT=$?

if [[ "${EXIT}" -ne 1 ]]; then
	echo "  FAIL: feature-branch ref must exit 1, got ${EXIT}" >&2
	echo "        full output:" >&2
	printf '%s\n' "${OUT}" | sed 's/^/          /' >&2
	FAIL=$((FAIL + 1))
else
	printf '  PASS: feature-branch ref exits 1\n'
	PASS=$((PASS + 1))
fi

assert_contains "annotation declares invalid dispatch ref"      "${OUT}" "::error title=Invalid dispatch ref::"
assert_contains "got-clause reflects passed-in ref"             "${OUT}" "${TEST_REF}"
assert_contains "states refs/heads/main requirement"            "${OUT}" "refs/heads/main"
assert_contains "names sts:AssumeRoleWithWebIdentity rejection" "${OUT}" "sts:AssumeRoleWithWebIdentity"
assert_contains "cross-references issue #1121"                  "${OUT}" "#1121"
assert_contains "gh workflow run command shown"                 "${OUT}" "gh workflow run build-and-push.yml --ref main"
assert_contains "force_build flag mentioned"                    "${OUT}" "force_build=true"
assert_contains "explains this is manual recovery"              "${OUT}" "manual recovery"
assert_contains "states deploys fire automatically on main"     "${OUT}" "automatically on push to main"

# ---------------------------------------------------------------------------
# GITHUB_REF unset must not crash; the script substitutes
# `<unknown>` so the operator at least sees an annotation.
# ---------------------------------------------------------------------------
EXIT=0
OUT_UNSET="$(env -u GITHUB_REF "${SCRIPT}" 2>/dev/null)" || EXIT=$?
if [[ "${EXIT}" -ne 1 ]]; then
	echo "  FAIL: missing GITHUB_REF must still exit 1, got ${EXIT}" >&2
	FAIL=$((FAIL + 1))
else
	printf '  PASS: missing GITHUB_REF still exits 1\n'
	PASS=$((PASS + 1))
fi
assert_contains "unset GITHUB_REF substitutes <unknown>"        "${OUT_UNSET}" "<unknown>"

# ---------------------------------------------------------------------------
# stderr must be empty — repo convention (and GitHub Actions') routes
# `::error::` annotations through stdout. Every other `::error::` in
# build-and-push.yml is `echo "::error::..."` (stdout). Sanity-check
# that this script doesn't accidentally split the message across both
# streams or leak diagnostics on stderr that the runner won't render.
# ---------------------------------------------------------------------------
STDERR="$(GITHUB_REF="${TEST_REF}" "${SCRIPT}" 2>&1 >/dev/null || true)"
if [[ -n "${STDERR}" ]]; then
	echo "  FAIL: script wrote to stderr (must be stdout-only)" >&2
	echo "        stderr:" >&2
	printf '%s\n' "${STDERR}" | sed 's/^/          /' >&2
	FAIL=$((FAIL + 1))
else
	printf '  PASS: stderr empty (annotations go to stdout only)\n'
	PASS=$((PASS + 1))
fi

# ---------------------------------------------------------------------------
# Defense-in-depth: a forged GITHUB_REF containing command-substitution
# syntax must print literally, never execute. Bash heredoc parameter
# expansion is single-pass, so `$(...)` in a value is not re-evaluated
# — but a future refactor that swapped `cat <<EOF` for `eval` or a
# printf format-string would silently break this. Pin the contract.
# Refs also can't legitimately contain `$(`, but we don't want to rely
# on that — the script is the bottom of the trust chain on this path.
# ---------------------------------------------------------------------------
EXIT=0
PWN_TOKEN='$(echo PWNED)'
OUT_PWN="$(GITHUB_REF="refs/heads/${PWN_TOKEN}" "${SCRIPT}" 2>/dev/null)" || EXIT=$?
if [[ "${EXIT}" -ne 1 ]]; then
	echo "  FAIL: command-substitution-containing ref must still exit 1, got ${EXIT}" >&2
	FAIL=$((FAIL + 1))
elif [[ "${OUT_PWN}" == *"PWNED"* ]] && [[ "${OUT_PWN}" != *"${PWN_TOKEN}"* ]]; then
	echo "  FAIL: command substitution executed (PWNED appeared without literal \$(...))" >&2
	echo "        output:" >&2
	printf '%s\n' "${OUT_PWN}" | sed 's/^/          /' >&2
	FAIL=$((FAIL + 1))
elif [[ "${OUT_PWN}" != *"${PWN_TOKEN}"* ]]; then
	echo "  FAIL: literal command-substitution token missing from output" >&2
	echo "        expected to find: ${PWN_TOKEN}" >&2
	FAIL=$((FAIL + 1))
else
	printf '  PASS: command-substitution in ref prints literally (no execution)\n'
	PASS=$((PASS + 1))
fi

if [[ "${FAIL}" -gt 0 ]]; then
	echo "" >&2
	echo "${FAIL} fixture(s) failed, ${PASS} passed." >&2
	exit 1
fi
echo "All ${PASS} dispatch-ref-error fixtures passed."
