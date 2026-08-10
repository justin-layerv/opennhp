#!/usr/bin/env bash
# Fixture suite for .github/scripts/check-iam-description-charset.py.
#
# The two cases that matter most are the PASS ones: Latin-1 supplement
# characters are ALLOWED by IAM, and non-IAM resources must be ignored entirely
# (the Secrets Manager description in terraform/agent_otp_ses.tf carries an em
# dash and applies fine today). A checker that simply banned all non-ASCII
# would reject both and get reverted the first time it fired.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKER="$(cd "$HERE/../../.." && pwd)/.github/scripts/check-iam-description-charset.py"

if [ ! -f "$CHECKER" ]; then
  echo "FATAL: checker not found at $CHECKER" >&2
  exit 1
fi

failures=0

expect_pass() {
  local case_dir="$1" out
  if out="$(python3 "$CHECKER" "$HERE/$case_dir" 2>&1)"; then
    echo "ok    $case_dir (accepted as expected)"
  else
    echo "FAIL  $case_dir: expected exit 0, got non-zero" >&2
    echo "$out" | sed 's/^/        /' >&2
    failures=$((failures + 1))
  fi
}

expect_fail() {
  local case_dir="$1" codepoint="$2" out rc
  set +e
  out="$(python3 "$CHECKER" "$HERE/$case_dir" 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    echo "FAIL  $case_dir: expected rejection, got exit 0 — the fence is not detecting this" >&2
    failures=$((failures + 1))
  elif ! printf '%s' "$out" | grep -q "$codepoint"; then
    echo "FAIL  $case_dir: rejected, but did not name $codepoint — wrong reason" >&2
    echo "$out" | sed 's/^/        /' >&2
    failures=$((failures + 1))
  else
    echo "ok    $case_dir (rejected, naming $codepoint)"
  fi
}

expect_pass clean
# Latin-1 supplement is inside IAM's allowed range. Rejecting it would be a
# false positive on a description AWS accepts.
expect_pass latin1-ok
# Only aws_iam_role / aws_iam_policy carry this constraint.
expect_pass non-iam-resource

# The exact character that broke sandbox in #3827.
expect_fail emdash U+2014
expect_fail curly-quote U+201C
expect_fail nbsp U+00A0
# Review found both of these as false negatives: a bad character could hide
# behind an inline comment, or after a heredoc whose body closed a JSON object
# at column zero and ended block tracking early. Either kept the fence green
# while reintroducing the #3827 bug.
expect_fail trailing-comment U+2014
expect_fail heredoc-brace U+2014

if [ "$failures" -ne 0 ]; then
  echo
  echo "IAM description charset fixtures: FAILED ($failures case(s))" >&2
  exit 1
fi

echo
echo "IAM description charset fixtures: OK"
