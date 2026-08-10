#!/usr/bin/env bash
# Fixture suite for .github/scripts/check-tfvars-reach-the-module.py.
#
# The checker's parser has real edge surface -- column-zero-only assignment
# matching, heredoc skipping, nested map literals, comment stripping -- and a
# fence nobody fences will rot the first time someone "simplifies" one of those.
# Each case below is a synthetic environments directory the checker is pointed
# at directly, so these assert behaviour without touching the real tree.
#
# PASS cases must exit 0. FAIL cases must exit 1 AND emit the expected marker,
# so a case cannot pass for the wrong reason (a crash also exits non-zero).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKER="$(cd "$HERE/../../.." && pwd)/.github/scripts/check-tfvars-reach-the-module.py"

if [ ! -f "$CHECKER" ]; then
  echo "FATAL: checker not found at $CHECKER" >&2
  exit 1
fi

failures=0

expect_pass() {
  local case_dir="$1"
  local out
  if out="$(python3 "$CHECKER" "$HERE/$case_dir" 2>&1)"; then
    echo "ok    $case_dir (passed as expected)"
  else
    echo "FAIL  $case_dir: expected exit 0, got non-zero" >&2
    echo "$out" | sed 's/^/        /' >&2
    failures=$((failures + 1))
  fi
}

expect_fail() {
  local case_dir="$1" marker="$2" out rc
  set +e
  out="$(python3 "$CHECKER" "$HERE/$case_dir" 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    echo "FAIL  $case_dir: expected a failure, got exit 0 — the fence is not detecting this" >&2
    failures=$((failures + 1))
  elif ! printf '%s' "$out" | grep -q "$marker"; then
    echo "FAIL  $case_dir: failed, but without the expected '$marker' marker — wrong reason" >&2
    echo "$out" | sed 's/^/        /' >&2
    failures=$((failures + 1))
  else
    echo "ok    $case_dir (rejected with $marker)"
  fi
}

# Declared and forwarded: the shape every flag should have.
expect_pass clean
# Indented keys inside a map literal are not root variables.
expect_pass nested-literal
# Heredoc bodies, and an inline "<<" inside a value, must not be misread as
# assignments or as heredoc openers.
expect_pass heredoc

# The #3811 shape: set in tfvars, never declared by the root.
expect_fail inert INERT
# The other half: declared by the root, never forwarded to the module.
expect_fail unpassed UNPASSED
# A commented-out pass-through is not a pass-through.
expect_fail commented-passthrough UNPASSED

if [ "$failures" -ne 0 ]; then
  echo
  echo "tfvars reachability fixtures: FAILED ($failures case(s))" >&2
  exit 1
fi

echo
echo "tfvars reachability fixtures: OK"
