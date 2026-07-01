#!/usr/bin/env bash
# run-fixtures.sh
# ----------------------------------------------------------------------------
# Regression fence for the notify-block membership test in
# scripts/check-packer-failure-surfaced.sh. This header is the CANONICAL
# explanation of the flake class (it holds the grep-able signature); the
# script's need() helper and the workflow step keep only a one-line
# summary + a pointer back here.
#
# That lint's need() helper asserts a required wiring pattern appears in
# the multi-line $notify_block. It used to do so with
#
#     if ! printf '%s\n' "$notify_block" | grep -qE "$1"; then
#
# `grep -q` exits on its first match and closes the read end of the pipe,
# so the still-writing printf (the multi-line $notify_block) hits a closed
# pipe. bash's printf builtin catches the EPIPE, prints `write error:
# Broken pipe`, and exits non-zero (an external printf would instead die
# from SIGPIPE, exit 141) — either way the left side of the pipe is
# non-zero. Under the script's `set -o pipefail` the pipeline inherits
# that status EVEN THOUGH grep matched, so `if ! <pipeline>` misreads the
# hit as a miss and emits a spurious "✗ <message>" failure. Since need()'s
# whole job is to assert the packer-failure notify wiring EXISTS, that
# false negative red-flakes the fence — intermittent, timing-dependent,
# green on re-run. This is the same class
# scripts/check-base-image-pebble-purge.sh documents and guards against
# with capture-then-test.
#
# The fix drains grep (capture-then-test, no -q) so printf always finishes.
#
# Because the flake is a race, a live run cannot reliably reproduce it (it
# passes on most runs), so this fence is STRUCTURAL: it asserts the
# vulnerable idiom is gone from the script's executable lines, plus a
# behavioral unit test of the REAL need() extracted from source and driven
# with a multi-line block whose match is on the FIRST line (the exact
# early-close shape the race corrupted). need()'s full wiring semantics
# (A1–A5) stay covered by tests/scripts/check-packer-failure-surfaced_test.sh
# and the adjacent "Check Packer Build AMI failures" gate in
# validate-workflows.yml, so this fixture stays a fast, deterministic
# source-level fence and does not re-run the script itself.
#
# Usage:
#   ./tests/lints/packer-failure-surfaced/run-fixtures.sh
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="${REPO_ROOT}/scripts/check-packer-failure-surfaced.sh"

if [[ ! -f "${SCRIPT}" ]]; then
  echo "ERROR: script not found: ${SCRIPT}" >&2
  exit 1
fi

# Counters are UPPER-case (PASS/FAIL) on purpose: the need() we extract
# below sets a lower-case `fail` VARIABLE as its own miss flag, and this
# file also defines a `fail()` reporter FUNCTION. All three are distinct
# (bash keeps variable and function namespaces separate; the counter is a
# different name), so extracting and driving need() cannot clobber them.
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
# natural tool for a membership test). Two gaps are left by design, since
# closing them needs real shell parsing (disproportionate for a lint's
# lint): a pipe split across a line continuation, and a non-grep
# early-closer (`head`, `sed q`) — e.g. the sibling need_order() pipes into
# `grep -nE … | head -1`, but it captures into a var with a trailing
# `|| true`, so grep's status never gates a branch and it is deliberately
# out of scope. The maintainers' standing convention is capture-then-test
# (see check-base-image-pebble-purge.sh), and a reviewer is the backstop
# for the residual. Narrow-but-deterministic is the deliberate trade.
# ---------------------------------------------------------------------------
offenders="$(grep -nE 'printf.*\|.*grep -[qm]' "${SCRIPT}" | grep -vE '^[0-9]+:[[:space:]]*#' || true)"
if [[ -z "${offenders}" ]]; then
  pass "no 'printf … | grep -q/-m' membership pipeline in executable lines"
else
  fail "vulnerable 'printf … | grep -q/-m' idiom reintroduced (SIGPIPE-under-pipefail flake):"
  printf '%s\n' "${offenders}" | sed 's/^/          /' >&2
fi

# The capture-then-test replacement must actually be present: a drained
# `grep -E` (no -q) whose result is captured into a var, so printf can
# never be cut off mid-write.
if grep -qE 'hit=\$\(printf .* \| grep -E ' "${SCRIPT}"; then
  pass "need() captures drained 'grep -E' output (no early close)"
else
  fail "need() no longer uses the capture-then-test form (grep -E into a var)"
fi

# ---------------------------------------------------------------------------
# Test 2 (unit): pull the REAL need() out of the script (no drift-prone
# copy) and drive it with a MULTI-LINE $notify_block whose match is on the
# FIRST line — the exact shape that made the old `printf | grep -q` race
# (an early match while printf is still writing later lines). A present
# first-line pattern must NOT flag a failure (precisely the case the race
# corrupted); an absent pattern must. This pins the observable behavior the
# capture-then-test replacement has to preserve. (A match on a later line
# would exercise the identical drained-grep path, so it adds no coverage
# over the first-line case and is omitted.)
# ---------------------------------------------------------------------------
eval "$(sed -n '/^need() {/,/^}/p' "${SCRIPT}")"
if ! declare -F need >/dev/null; then
  fail "could not extract need() from ${SCRIPT}"
else
  # need() reads two globals: $notify_block (the haystack) and $fail (the
  # flag it sets to 1 on a miss). We set both, then assert $fail after each
  # call. The present pattern is anchored/plain (never leading with '-',
  # which grep would parse as an option), matching how the real callsites
  # pass ERE patterns.
  # shellcheck disable=SC2034  # read by the eval'd need() as a global; the
  # reference is inside the extracted function body, invisible to shellcheck.
  notify_block=$'  notify:\n    needs:\n      - build\n      - packer-build\n    steps:\n      - run: echo done'
  semantics_ok=1

  fail=0
  need 'notify:' 'first-line match' 2>/dev/null
  [ "${fail}" -eq 0 ] || semantics_ok=0   # match on line 1 -> no false failure

  fail=0
  need 'no-such-wiring-xyz' 'genuine miss' 2>/dev/null
  [ "${fail}" -eq 1 ] || semantics_ok=0   # genuine miss -> reported

  if [[ "${semantics_ok}" -eq 1 ]]; then
    pass "need() flags a genuine miss but not a first-line match (SIGPIPE-safe)"
  else
    fail "need() returned an incorrect membership result"
  fi
fi

if [[ "${FAIL}" -gt 0 ]]; then
  echo "" >&2
  echo "${FAIL} fixture(s) failed, ${PASS} passed." >&2
  exit 1
fi
echo "All ${PASS} packer-failure-surfaced fixtures passed."
