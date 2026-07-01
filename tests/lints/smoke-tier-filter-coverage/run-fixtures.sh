#!/usr/bin/env bash
# run-fixtures.sh
# ----------------------------------------------------------------------------
# Regression fence for the array-membership test in
# scripts/check-smoke-tier-filter-coverage.sh.
#
# That lint tests membership in two places (token-without-test and
# test-without-token). Both used a
#
#     printf '%s\n' "${arr[@]}" | grep -qx "$needle"
#
# idiom. `grep -qx` exits on its first match and closes the pipe, so
# `printf` — still writing the rest of the array — is killed by SIGPIPE
# (or gets EPIPE) and exits non-zero. Under the script's
# `set -o pipefail`, the pipeline's status becomes that non-zero code
# EVEN THOUGH grep matched, so `if ! <pipeline>` misread the hit as a
# miss and emitted a spurious "filter token has no matching
# declaration" error. It was an intermittent, timing-dependent CI flake
# (green on re-run) with signature:
#
#     scripts/check-smoke-tier-filter-coverage.sh: line NNN: printf:
#         write error: Broken pipe
#     ERROR [...]: filter token '...' has no matching ... — silent no-op
#     FAIL: 1 RUN_FILTER coverage error(s)
#
# The fix replaced both pipelines with a pure-bash `array_contains`
# helper — no subprocess, no pipe, so SIGPIPE is impossible.
#
# Because the flake is a race, a live run cannot reliably reproduce it
# (it passes on most runs), so this fence is STRUCTURAL: it asserts the
# vulnerable idiom is gone from the script's executable lines and
# unit-tests the pure-bash replacement extracted from source. That
# deterministically fails the moment anyone reintroduces a
# `printf … | grep -q` membership test — where a single live run would
# not. The lint's real-suite behavior is exercised by the adjacent
# "Check smoke RUN_FILTER coverage" gate in validate-workflows.yml, so
# this fixture stays a fast, deterministic source-level fence and does
# not re-run the script itself.
#
# Usage:
#   ./tests/lints/smoke-tier-filter-coverage/run-fixtures.sh
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="${REPO_ROOT}/scripts/check-smoke-tier-filter-coverage.sh"

if [[ ! -f "${SCRIPT}" ]]; then
	echo "ERROR: script not found: ${SCRIPT}" >&2
	exit 1
fi

PASS=0
FAIL=0
pass() { printf '  PASS: %s\n' "$1"; PASS=$((PASS + 1)); }
fail() {
	printf '  FAIL: %s\n' "$1" >&2
	FAIL=$((FAIL + 1))
}

# ---------------------------------------------------------------------------
# Test 1 (structural fence): the banned `printf … | grep -q` membership
# idiom must not appear on any EXECUTABLE line. Comment lines that
# document the old pattern start with `#`, so they are excluded — the
# fence must not trip on its own explanation.
#
# Scope: this catches a same-line `printf … | grep -q`/`-m` pipe — the
# realistic way the fixed idiom comes back (an early-exiting grep is the
# natural tool for a membership test). Two gaps are left by design,
# since closing them needs real shell parsing (disproportionate for a
# lint's lint): a pipe split across a line continuation, and a non-grep
# early-closer (`head`, `sed q`). The maintainers' standing convention
# is capture-then-test (see check-base-image-pebble-purge.sh), and a
# reviewer is the backstop for the residual. Narrow-but-deterministic is
# the deliberate trade.
# ---------------------------------------------------------------------------
offenders="$(grep -nE 'printf.*\|.*grep -[qm]' "${SCRIPT}" | grep -vE '^[0-9]+:[[:space:]]*#' || true)"
if [[ -z "${offenders}" ]]; then
	pass "no 'printf … | grep -q/-m' membership pipeline in executable lines"
else
	fail "vulnerable 'printf … | grep -q/-m' idiom reintroduced (SIGPIPE-under-pipefail flake):"
	printf '%s\n' "${offenders}" | sed 's/^/          /' >&2
fi

# The subprocess-free replacement must exist and actually be used at the
# (previously vulnerable) callsites.
if grep -qE '^array_contains\(\) \{' "${SCRIPT}"; then
	pass "array_contains helper is defined"
else
	fail "array_contains helper is missing"
fi

uses="$(grep -cE '(^|[^A-Za-z0-9_])array_contains ' "${SCRIPT}" || true)"
if [[ "${uses}" -ge 2 ]]; then
	pass "array_contains is used at the membership callsites (${uses} references)"
else
	fail "array_contains expected at >=2 callsites, found ${uses}"
fi

# ---------------------------------------------------------------------------
# Test 2 (unit): pull the REAL array_contains out of the script (no
# drift-prone copy) and pin its exact-match semantics — the property
# that makes it a correct drop-in for the old `grep -qx` whole-line
# match. Cover a present element at each position, an absent element,
# and the empty/no-candidate expansions the callsites pass via
# "${arr[@]:-}".
# ---------------------------------------------------------------------------
eval "$(sed -n '/^array_contains() {/,/^}/p' "${SCRIPT}")"
if ! declare -F array_contains >/dev/null; then
	fail "could not extract array_contains from ${SCRIPT}"
else
	semantics_ok=1
	array_contains A A B C || semantics_ok=0   # present, first
	array_contains B A B C || semantics_ok=0   # present, middle
	array_contains C A B C || semantics_ok=0   # present, last
	! array_contains Z A B C || semantics_ok=0 # absent
	! array_contains X "" || semantics_ok=0    # empty expansion -> absent
	! array_contains X || semantics_ok=0       # no candidates -> absent
	if [[ "${semantics_ok}" -eq 1 ]]; then
		pass "array_contains exact-match semantics (present / absent / empty)"
	else
		fail "array_contains returned an incorrect membership result"
	fi
fi

if [[ "${FAIL}" -gt 0 ]]; then
	echo "" >&2
	echo "${FAIL} fixture(s) failed, ${PASS} passed." >&2
	exit 1
fi
echo "All ${PASS} smoke-tier-filter-coverage fixtures passed."
