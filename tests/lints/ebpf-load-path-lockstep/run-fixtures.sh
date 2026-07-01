#!/usr/bin/env bash
# run-fixtures.sh
# ----------------------------------------------------------------------------
# Regression fence for the Dockerfile-path membership test in
# scripts/check-ebpf-load-path-lockstep.sh. This header is the CANONICAL
# explanation of the flake class (it holds the grep-able signature); the
# script helper and the workflow step keep only a one-line summary + a
# pointer back here.
#
# That lint checks both wanted eBPF object paths appear in the Dockerfile
# guard's path set ($dk_paths, a multi-line string). It used to do so with
#
#     printf '%s\n' "$dk_paths" | grep -qxF "$want_xdp" || mismatch+=…
#
# `grep -qxF` exits on its first match and closes the read end of the
# pipe, so the still-writing printf (the multi-line $dk_paths) hits a
# closed pipe. bash's printf builtin catches the EPIPE, prints
# `write error: Broken pipe`, and exits non-zero (an external printf would
# instead die from SIGPIPE, exit 141) — either way the left side of the
# pipe is non-zero. Under the script's `set -o pipefail` the pipeline
# inherits that status EVEN THOUGH grep matched — when the wanted path is
# present AND early in $dk_paths — so the `|| mismatch+=` branch fires
# spuriously and reports a false "Dockerfile.ac.aws guard is missing
# <path>" drift. Intermittent, timing-dependent, green on re-run. This is
# the same class scripts/check-base-image-pebble-purge.sh documents and
# guards against with capture-then-test.
#
# The fix replaced both pipelines with a pure-bash `lines_contain` helper
# — no subprocess, no pipe, so the race is impossible. The guard paths are
# fixed strings, so exact per-line equality is identical to grep -qxF's
# whole-line fixed-string match.
#
# Because the flake is a race, a live run cannot reliably reproduce it (it
# passes on most runs), so this fence is STRUCTURAL: it asserts the
# vulnerable idiom is gone from the script's executable lines and
# unit-tests the pure-bash replacement extracted from source. That
# deterministically fails the moment anyone reintroduces a
# `printf … | grep -q` membership test. The lint's real drift-detection
# behavior is exercised by tests/scripts/check-ebpf-load-path-lockstep_test.sh
# and the adjacent "Check eBPF load-path" gate in validate-workflows.yml,
# so this fixture stays a fast, deterministic source-level fence and does
# not re-run the script itself.
#
# Usage:
#   ./tests/lints/ebpf-load-path-lockstep/run-fixtures.sh
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="${REPO_ROOT}/scripts/check-ebpf-load-path-lockstep.sh"

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
# natural tool for a membership test). Two gaps are left by design, since
# closing them needs real shell parsing (disproportionate for a lint's
# lint): a pipe split across a line continuation, and a non-grep
# early-closer (`head`, `sed q`). The maintainers' standing convention is
# capture-then-test (see check-base-image-pebble-purge.sh), and a reviewer
# is the backstop for the residual. Narrow-but-deterministic is the
# deliberate trade.
# ---------------------------------------------------------------------------
offenders="$(grep -nE 'printf.*\|.*grep -[qm]' "${SCRIPT}" | grep -vE '^[0-9]+:[[:space:]]*#' || true)"
if [[ -z "${offenders}" ]]; then
  pass "no 'printf … | grep -q/-m' membership pipeline in executable lines"
else
  fail "vulnerable 'printf … | grep -q/-m' idiom reintroduced (SIGPIPE-under-pipefail flake):"
  printf '%s\n' "${offenders}" | sed 's/^/          /' >&2
fi

# The subprocess-free replacement must exist and actually be used at the
# (previously vulnerable) xdp + tc callsites.
if grep -qE '^lines_contain\(\) \{' "${SCRIPT}"; then
  pass "lines_contain helper is defined"
else
  fail "lines_contain helper is missing"
fi

# Count only EXECUTABLE callsites — filter the comment line that also names
# the helper, so removing a real callsite can't be masked by a prose mention
# keeping the count >= 2.
uses="$(grep -nE '(^|[^A-Za-z0-9_])lines_contain ' "${SCRIPT}" | grep -cvE '^[0-9]+:[[:space:]]*#' || true)"
if [[ "${uses}" -ge 2 ]]; then
  pass "lines_contain is used at >=2 executable callsites (${uses})"
else
  fail "lines_contain expected at >=2 executable callsites, found ${uses}"
fi

# ---------------------------------------------------------------------------
# Test 2 (unit): pull the REAL lines_contain out of the script (no
# drift-prone copy) and pin its exact WHOLE-LINE membership semantics — the
# property that makes it a correct drop-in for the old `grep -qxF`. Cover a
# present element at each line position, an absent element, a single-line
# block, the empty block, and — critically — that a substring of a line
# does NOT match (proving it is a whole-line `-x` test, not a substring
# search), using realistic guard paths.
# ---------------------------------------------------------------------------
eval "$(sed -n '/^lines_contain() {/,/^}/p' "${SCRIPT}")"
if ! declare -F lines_contain >/dev/null; then
  fail "could not extract lines_contain from ${SCRIPT}"
else
  block=$'etc/nhp_ebpf_xdp.o\netc/tc_egress.o\netc/extra.o'
  semantics_ok=1
  lines_contain 'etc/nhp_ebpf_xdp.o' "${block}" || semantics_ok=0  # present, first
  lines_contain 'etc/tc_egress.o' "${block}"    || semantics_ok=0  # present, middle
  lines_contain 'etc/extra.o' "${block}"        || semantics_ok=0  # present, last
  ! lines_contain 'etc/absent.o' "${block}"     || semantics_ok=0  # absent
  lines_contain 'only.o' 'only.o'               || semantics_ok=0  # single-line block, present
  ! lines_contain 'only.o' ''                   || semantics_ok=0  # empty block -> absent
  ! lines_contain 'etc/nhp_ebpf_xdp' "${block}" || semantics_ok=0  # substring != whole line
  if [[ "${semantics_ok}" -eq 1 ]]; then
    pass "lines_contain whole-line membership semantics (present / absent / empty / substring)"
  else
    fail "lines_contain returned an incorrect membership result"
  fi
fi

if [[ "${FAIL}" -gt 0 ]]; then
  echo "" >&2
  echo "${FAIL} fixture(s) failed, ${PASS} passed." >&2
  exit 1
fi
echo "All ${PASS} ebpf-load-path-lockstep fixtures passed."
