#!/usr/bin/env bash
# plan-blue-green-dispatch_test.sh — fixture tests for
# .github/scripts/plan-blue-green-dispatch.sh
# ----------------------------------------------------------------------------
# The plan script decides how build-and-push.yml's infra-only deploy path
# dispatches blue-green-deploy.yml: one `both <tag>` dispatch when server and
# AC share an active tag, or two per-component dispatches when they've drifted.
# This fences that contract — most importantly the safety property that a
# drifted pair dispatches each component at its OWN tag and NEVER deploys one
# component at the other's tag (which would push the wrong image to a live
# component), and that a blank tag fails closed instead of dispatching an
# empty image_tag.
#
# The script is pure (no AWS / no gh), so each case just invokes the REAL
# script and asserts stdout + exit code.
#
# Usage: bash tests/scripts/plan-blue-green-dispatch_test.sh

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/plan-blue-green-dispatch.sh"

pass=0
fail=0
failures=""
report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); failures+="  ✗ $1: $2\n"; printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"; }

# _run <args...> -> sets GOT (stdout), ERR (stderr), and RC (exit code)
GOT=""; ERR=""; RC=0
_run() {
  local errfile; errfile=$(mktemp)
  GOT=$("$SCRIPT" "$@" 2>"$errfile"); RC=$?
  ERR=$(cat "$errfile"); rm -f "$errfile"
}

# _assert_plan <name> <expected-stdout> <args...> — expect rc=0 and exact stdout
_assert_plan() {
  local name="$1" want="$2"; shift 2
  _run "$@"
  if [[ "$RC" -eq 0 && "$GOT" == "$want" ]]; then report_pass "$name"
  else report_fail "$name" "rc=$RC out='$GOT' (want rc=0 out='$want')"; fi
}

# _assert_fail <name> <args...> — expect non-zero exit and no stdout plan
_assert_fail() {
  local name="$1"; shift
  _run "$@"
  if [[ "$RC" -ne 0 && -z "$GOT" ]]; then report_pass "$name"
  else report_fail "$name" "rc=$RC out='$GOT' (want non-zero, empty stdout)"; fi
}

# _assert_stderr_has <name> <needle> <args...> — expect rc=0 with needle on stderr
_assert_stderr_has() {
  local name="$1" needle="$2"; shift 2
  _run "$@"
  if [[ "$RC" -eq 0 && "$ERR" == *"$needle"* ]]; then report_pass "$name"
  else report_fail "$name" "rc=$RC stderr='$ERR' (want rc=0 stderr containing '$needle')"; fi
}

# _assert_stderr_lacks <name> <needle> <args...> — expect rc=0 with needle absent
_assert_stderr_lacks() {
  local name="$1" needle="$2"; shift 2
  _run "$@"
  if [[ "$RC" -eq 0 && "$ERR" != *"$needle"* ]]; then report_pass "$name"
  else report_fail "$name" "rc=$RC stderr='$ERR' (want rc=0 stderr without '$needle')"; fi
}

echo "Running plan-blue-green-dispatch tests..."

# Equal tags collapse to a single both-component dispatch. This is also the
# app-changed path, where both components are freshly built at one github.sha.
_assert_plan "equal tags -> single both dispatch" \
  "both 1a2b3c4d" 1a2b3c4d 1a2b3c4d

# Drifted tags fan out to one dispatch per component, server first, each at
# its OWN tag. The exact two-line match is the core safety assertion: the AC
# line carries the AC tag, never the server tag.
_assert_plan "drifted tags -> server then ac, each at own tag" \
  "server srv1111
ac ac2222" srv1111 ac2222

# Order/identity guard, stated explicitly: the inverse drift (AC newer than
# server) still pairs each component with its own tag.
_assert_plan "drift is per-component, not positional" \
  "server oldserver
ac newac" oldserver newac

# Drift surfaces a ::warning:: CI annotation so persistent drift is visible to
# operators; matched tags stay quiet so the signal is not drowned in noise.
_assert_stderr_has "drift emits a ::warning:: annotation" "::warning::" srv1111 ac2222
_assert_stderr_lacks "matched tags emit no warning" "::warning::" 1a2b3c4d 1a2b3c4d

# Fail closed: a blank tag must never become an empty image_tag dispatch.
_assert_fail "empty server tag rejected" "" ac2222
_assert_fail "empty ac tag rejected" srv1111 ""
_assert_fail "both tags empty rejected" "" ""

# ...and a whitespace-only or whitespace-bearing tag is just as invalid (a real
# tag is a whitespace-free SHA/ref); catching it here beats a reject deep inside
# a dispatched blue-green-deploy.yml run.
_assert_fail "whitespace-only server tag rejected" " " ac2222
_assert_fail "embedded-whitespace tag rejected" "bad tag" ac2222

# Input validation: wrong argument count exits before printing a plan.
_assert_fail "missing ac arg rejected" srv1111
_assert_fail "no args rejected"
_assert_fail "too many args rejected" srv1111 ac2222 extra

echo ""
echo "Passed: $pass"
echo "Failed: $fail"
if [ "$fail" -gt 0 ]; then
  printf '\nFailures:\n%b' "$failures"
  exit 1
fi
