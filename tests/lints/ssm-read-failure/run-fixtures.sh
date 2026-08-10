#!/usr/bin/env bash
# run-fixtures.sh
# ----------------------------------------------------------------------------
# Regression fixtures for the unreadable-vs-absent SSM split in
# scripts/trigger-prod-deploy.sh (PR #3750).
#
# The script must never present a failed read as a definite state. A read that
# errors — throttling, a timeout, expired credentials, a denied permission — is
# neither "absent" nor "corrupted", and reporting it as either sends the
# operator chasing a fault that does not exist. That is exactly what happened
# on 2026-08-08: /sandbox/nhp/server/active-color read empty during an AWS slow
# period and the preflight aborted with "SSM parameter may be corrupted".
#
# These fixtures exist because the first attempt at the fix was silently a
# no-op: it appended the failure record inside read_ssm, which every caller
# invokes through a command substitution, so the append mutated a subshell copy
# and the parent's gate could never fire. `bash -n` and `shellcheck` both passed
# on that version. Only executing the failure path catches it, so that is what
# this does.
#
# How it works: each fixture puts fake `aws` and `gh` shims on PATH, points the
# script at them, and asserts on which diagnosis the operator actually gets.
#
# Mirrors the pattern of the other tests/lints/*/run-fixtures.sh suites.
#
# Usage:
#   ./tests/lints/ssm-read-failure/run-fixtures.sh
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="${REPO_ROOT}/scripts/trigger-prod-deploy.sh"

if [ ! -x "$SCRIPT" ]; then
  echo "ERROR: script not executable: $SCRIPT" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

SHIM_DIR="$TMP/bin"
mkdir -p "$SHIM_DIR"

# Fake AWS CLI. Succeeds for every read except the one named by FIXTURE_FAIL_PARAM,
# which fails with FIXTURE_FAIL_MSG on stderr — the shape the real CLI uses.
# FIXTURE_STDERR_NOISE, when set, is emitted on stderr for *successful* reads to
# stand in for a deprecation/credential-source warning.
cat > "$SHIM_DIR/aws" <<'SHIM'
#!/usr/bin/env bash
set -uo pipefail
svc="${1:-}"; op="${2:-}"

if [ "$svc" = "sts" ]; then
  echo '{"Account":"000000000000","Arn":"arn:aws:iam::000000000000:user/fixture"}'
  exit 0
fi

if [ "$svc" = "ssm" ] && [ "$op" = "get-parameter" ]; then
  name=""
  while [ $# -gt 0 ]; do
    [ "$1" = "--name" ] && name="${2:-}"
    shift
  done

  # Emitted before any error line, because that is where it lands in reality:
  # these warnings come from TLS/import time, ahead of the API call itself.
  [ -n "${FIXTURE_STDERR_NOISE:-}" ] && echo "$FIXTURE_STDERR_NOISE" >&2

  # Space-separated list, so a case can fail more than one parameter and
  # exercise the gate's plural count.
  if [ -n "$name" ]; then
    case " ${FIXTURE_FAIL_PARAM:-} " in
      *" $name "*)
        echo "${FIXTURE_FAIL_MSG}" >&2
        exit 254
        ;;
    esac
  fi

  if [ -n "${FIXTURE_NOTFOUND_PARAM:-}" ] && [ "$name" = "$FIXTURE_NOTFOUND_PARAM" ]; then
    echo "An error occurred (ParameterNotFound) when calling the GetParameter operation: " >&2
    exit 254
  fi

  # Fails with nothing on stderr at all — a killed or crashed CLI.
  if [ -n "${FIXTURE_SILENT_FAIL_PARAM:-}" ] && [ "$name" = "$FIXTURE_SILENT_FAIL_PARAM" ]; then
    exit 254
  fi

  case "$name" in
    */active-color)   printf '%s' "${FIXTURE_ACTIVE_COLOR:-blue}" ;;
    */deployed-at)    printf '%s' "2026-08-09T00:00:00Z" ;;
    */deploy/state)   printf '%s' "deployed" ;;
    *)                printf '%s' "abc1234def5678901234567890abcdef12345678" ;;
  esac
  exit 0
fi

exit 0
SHIM

cat > "$SHIM_DIR/gh" <<'SHIM'
#!/usr/bin/env bash
# Enough of `gh` to clear preflight; nothing here should be reached before the
# SSM-read gate, and anything after it is out of scope for these fixtures.
set -uo pipefail
case "${1:-} ${2:-}" in
  "auth token") echo "gho_fixture"; exit 0 ;;
  "api user")   echo "fixture-operator"; exit 0 ;;
esac
echo "[]"
exit 0
SHIM

chmod +x "$SHIM_DIR/aws" "$SHIM_DIR/gh"

failed=0
ran=0

# run_case <description> <expect-substring> <forbid-substring> <env-assignments...>
#
# Runs the script under --dry-run with the shims on PATH and a throwaway HOME
# (the script appends to ~/.nhp-deploy.log; a test must not touch the real one).
# Asserts the operator's output contains <expect-substring> and does not contain
# <forbid-substring>. Pass "" to skip either assertion.
run_case() {
  local desc="$1" expect="$2" forbid="$3"
  shift 3

  ran=$((ran + 1))

  local case_home="$TMP/home.$ran"
  mkdir -p "$case_home"

  local out
  set +e
  out=$(env "$@" \
    HOME="$case_home" \
    PATH="$SHIM_DIR:$PATH" \
    "$SCRIPT" --dry-run 2>&1)
  set -e

  local problem=""
  if [ -n "$expect" ] && ! grep -qF "$expect" <<<"$out"; then
    problem="missing expected substring: '$expect'"
  fi
  if [ -z "$problem" ] && [ -n "$forbid" ] && grep -qF "$forbid" <<<"$out"; then
    problem="contains forbidden substring: '$forbid'"
  fi

  if [ -z "$problem" ]; then
    printf "  ok    %s\n" "$desc"
  else
    printf "  FAIL  %s — %s\n" "$desc" "$problem" >&2
    printf "        ---- output ----\n%s\n        ----------------\n" "$out" >&2
    failed=$((failed + 1))
  fi
}

echo "Running trigger-prod-deploy SSM-read fixtures..."

# 1. The regression that motivated these fixtures. A hard failure on a plain
#    read_ssm parameter must reach the gate. Before the subshell fix this
#    printed "may be corrupted" instead — the gate could never fire.
run_case "read_ssm hard failure is reported as unreadable" \
  "Could not read 1 deployment parameter(s)" \
  "may be corrupted" \
  FIXTURE_FAIL_PARAM=/prod/nhp/server/image-tag \
  "FIXTURE_FAIL_MSG=An error occurred (ThrottlingException) when calling the GetParameter operation: Rate exceeded"

# 2. The AWS error text itself has to survive to the operator — "retry" and
#    "check your credentials" are different next steps.
run_case "the underlying AWS error reaches the operator" \
  "ThrottlingException" \
  "" \
  FIXTURE_FAIL_PARAM=/prod/nhp/server/image-tag \
  "FIXTURE_FAIL_MSG=An error occurred (ThrottlingException) when calling the GetParameter operation: Rate exceeded"

# 3. The actual 2026-08-08 incident: active-color is read inside the blue/green
#    resolver, not by read_ssm, so a fix that covers only read_ssm leaves the
#    reported failure reporting itself as corrupted state.
run_case "resolver active-color read failure is reported as unreadable" \
  "Could not read 1 deployment parameter(s)" \
  "may be corrupted" \
  FIXTURE_FAIL_PARAM=/sandbox/nhp/server/active-color \
  "FIXTURE_FAIL_MSG=An error occurred (ThrottlingException) when calling the GetParameter operation: Rate exceeded"

# 4. A failure on the resolver's *slot* read (the second SSM call it makes) is
#    equally unreadable, and takes the same path.
run_case "resolver slot read failure is reported as unreadable" \
  "Could not read" \
  "may be corrupted" \
  FIXTURE_FAIL_PARAM=/sandbox/nhp/ac/image-tag \
  "FIXTURE_FAIL_MSG=An error occurred (AccessDeniedException) when calling the GetParameter operation: denied"

# 5. Fail-closed is unchanged: an unreadable parameter still stops the promote.
#    A gate that only prints a nicer message would be worse than the bug.
ran=$((ran + 1))
mkdir -p "$TMP/home.$ran"
set +e
env FIXTURE_FAIL_PARAM=/sandbox/nhp/server/active-color \
  "FIXTURE_FAIL_MSG=An error occurred (ThrottlingException) when calling the GetParameter operation: Rate exceeded" \
  HOME="$TMP/home.$ran" PATH="$SHIM_DIR:$PATH" "$SCRIPT" --dry-run >/dev/null 2>&1
gate_exit=$?
set -e
# Exactly 1, not merely non-zero: that is the gate's own exit, so a script that
# crashed its way to a non-zero status would not pass for failing closed.
if [ "$gate_exit" -eq 1 ]; then
  printf "  ok    an unreadable parameter still fails closed (exit=%d)\n" "$gate_exit"
else
  printf "  FAIL  an unreadable parameter must exit 1, got %d\n" "$gate_exit" >&2
  failed=$((failed + 1))
fi

# 6. ParameterNotFound is the one failure that legitimately means "absent". It
#    must stay on the empty-value path, or every optional parameter turns into
#    a spurious read failure and the gate blocks a healthy promote.
run_case "ParameterNotFound is absent, not unreadable" \
  "" \
  "Could not read" \
  FIXTURE_NOTFOUND_PARAM=/prod/nhp/relay/image-tag

# 7. Success-path stderr must not be spliced into the value. Merging the two
#    with 2>&1 turns a harmless CLI warning into a value that fails the SHA
#    check — re-creating the "corrupted" misdiagnosis from the other direction.
run_case "a CLI warning on a successful read does not corrupt the value" \
  "" \
  "may be corrupted" \
  "FIXTURE_STDERR_NOISE=urllib3 v2 only supports OpenSSL 1.1.1+, currently the ssl module is compiled with LibreSSL"

# 8. A genuinely bad active-color is bad *state*, not an unreadable parameter.
#    The resolver rejects it, and it must not be laundered into "retry".
run_case "an unexpected active-color is not reported as unreadable" \
  "" \
  "Could not read" \
  FIXTURE_ACTIVE_COLOR=purple

# 9. The two above, together. A warning precedes the error on stderr, because
#    that is when the CLI emits it — so classifying "absent" from the first
#    stderr line alone reads the warning and misses the ParameterNotFound
#    behind it. An absent optional parameter would then block a healthy
#    promote, which is both a regression against the old `2>/dev/null` and the
#    same warning class this fix exists to keep out of the value.
run_case "ParameterNotFound behind a CLI warning is still absent" \
  "" \
  "Could not read" \
  FIXTURE_NOTFOUND_PARAM=/prod/nhp/relay/image-tag \
  "FIXTURE_STDERR_NOISE=urllib3 v2 only supports OpenSSL 1.1.1+, currently the ssl module is compiled with LibreSSL 2.8.3"

# 10. The other half of reading past a leading warning: when the read really did
#     fail, the operator must be shown the API error and not the warning that
#     happened to print ahead of it. "Retry" and "fix your OpenSSL" are very
#     different next steps.
run_case "the API error, not a leading warning, is reported" \
  "ThrottlingException" \
  "" \
  FIXTURE_FAIL_PARAM=/prod/nhp/server/image-tag \
  "FIXTURE_FAIL_MSG=An error occurred (ThrottlingException) when calling the GetParameter operation: Rate exceeded" \
  "FIXTURE_STDERR_NOISE=urllib3 v2 only supports OpenSSL 1.1.1+, currently the ssl module is compiled with LibreSSL 2.8.3"

# 11. The plural count. Two failing parameters must be reported as two, which
#     also pins the round-3 claim that the number counts entries: the resolver
#     failure below spans two underlying reads (active-color, then the slot)
#     yet contributes exactly one entry, so two failures here — one resolver,
#     one plain read — must print 2 and not 3.
run_case "two failures are counted as two" \
  "Could not read 2 deployment parameter(s)" \
  "" \
  "FIXTURE_FAIL_PARAM=/sandbox/nhp/server/active-color /prod/nhp/server/image-tag" \
  "FIXTURE_FAIL_MSG=An error occurred (ThrottlingException) when calling the GetParameter operation: Rate exceeded"

# 12. A fully clean run must get *past* the gate. Fixtures 6-8 only assert that
#     "Could not read" is absent, which a script that died earlier would also
#     satisfy — so without this, a gate that fired spuriously on an all-healthy
#     read set could still pass the whole suite.
run_case "a clean run reaches the normal exit" \
  "Nothing to deploy" \
  "Could not read"

# 13. Gate ordering. An unreadable deployed-commit must not be reported as an
#     absent one: the empty-commit check sits after the gate precisely so a
#     throttled read stops saying "Deploy to sandbox first" — which sends the
#     operator to redeploy sandbox over what is really a transient AWS fault.
run_case "an unreadable sandbox commit is not 'deploy to sandbox first'" \
  "Could not read" \
  "No sandbox commit found" \
  FIXTURE_FAIL_PARAM=/sandbox/nhp/deploy/deployed-commit \
  "FIXTURE_FAIL_MSG=An error occurred (ThrottlingException) when calling the GetParameter operation: Rate exceeded"

# 14. Don't announce success over a section that just failed a read. The
#     progress line is not worth an operator reading "loaded" immediately above
#     "could not read".
run_case "no 'parameters loaded' claim when a read failed" \
  "Could not read" \
  "parameters loaded" \
  FIXTURE_FAIL_PARAM=/sandbox/nhp/deploy/deployed-commit \
  "FIXTURE_FAIL_MSG=An error occurred (ThrottlingException) when calling the GetParameter operation: Rate exceeded"

# 15. A CLI that fails while saying nothing — killed, or crashed before it could
#     report. There is no AWS error to quote, so the entry falls back to naming
#     the exit status. Still a failure, still gated: an empty entry would be the
#     "confidently says nothing" version of the bug this all exists to fix.
run_case "a failure with no stderr still names the exit status" \
  "exited 254 with no stderr" \
  "" \
  FIXTURE_SILENT_FAIL_PARAM=/prod/nhp/server/image-tag

echo ""
if [ "$failed" -gt 0 ]; then
  echo "FAILED: $failed of $ran fixture(s) failed" >&2
  exit 1
fi
echo "PASSED: all $ran fixtures passed"
