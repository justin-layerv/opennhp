#!/usr/bin/env bash
# run-fixtures.sh
# ----------------------------------------------------------------------------
# Regression fixtures for how scripts/trigger-prod-deploy.sh reports a blocked
# run — to the operator (PR #3750) and to a machine (the --json contract).
#
# 1. Unreadable is not absent, and not corrupted. A read that errors —
#    throttling, a timeout, expired credentials, a denied permission — is
#    neither, and reporting it as either sends the operator chasing a fault that
#    does not exist. That is exactly what happened on 2026-08-08:
#    /sandbox/nhp/server/active-color read empty during an AWS slow period and
#    the preflight aborted with "SSM parameter may be corrupted".
#
# 2. --json means JSON on every exit. It is a documented machine interface
#    (CLAUDE.md, Common Commands), and a consumer piping to jq must be able to
#    tell a blocked run from a crashed one. Every gate therefore emits an
#    {"ok":false,"error":...} document on stdout while the coloured text stays
#    on stderr, and still exits non-zero.
#
# These fixtures exist because the first attempt at (1) was silently a no-op: it
# appended the failure record inside read_ssm, which every caller invokes through
# a command substitution, so the append mutated a subshell copy and the parent's
# gate could never fire. `bash -n` and `shellcheck` both passed on that version.
# Only executing the failure path catches it, so that is what this does.
#
# How it works: each fixture puts fake `aws` and `gh` shims on PATH, points the
# script at them, and asserts on which diagnosis the operator — or the consumer
# — actually gets.
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
#
# Other knobs, added for the --json failure-document fixtures:
#   FIXTURE_STS_FAIL      — get-caller-identity fails, so preflight blocks
#   FIXTURE_VALUE_PARAM   — glob; parameters matching it read as FIXTURE_VALUE
#                           (a glob, not an exact name, so one knob can put the
#                           same bad value in both the server and AC slots — a
#                           bad value in only one of them trips the tag-mismatch
#                           gate first and never reaches the SHA-shape check)
cat > "$SHIM_DIR/aws" <<'SHIM'
#!/usr/bin/env bash
set -uo pipefail
svc="${1:-}"; op="${2:-}"

if [ "$svc" = "sts" ]; then
  if [ -n "${FIXTURE_STS_FAIL:-}" ]; then
    echo "Unable to locate credentials. You can configure credentials by running \"aws configure\"." >&2
    exit 255
  fi
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

  if [ -n "${FIXTURE_VALUE_PARAM:-}" ]; then
    # Unquoted on purpose: FIXTURE_VALUE_PARAM is a glob pattern.
    case "$name" in
      $FIXTURE_VALUE_PARAM) printf '%s' "${FIXTURE_VALUE:-}"; exit 0 ;;
    esac
  fi

  case "$name" in
    */active-color)   printf '%s' "${FIXTURE_ACTIVE_COLOR:-blue}" ;;
    # Relative, not a fixed date: the soak gate compares this to "now", and a
    # hardcoded timestamp would drift from "2h ago" into a stale-sandbox warning
    # and eventually break the fixtures that promote. BSD date first (macOS),
    # GNU second (CI) — the same split the script's own time_ago does.
    */deployed-at)    date -u -v-2H +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null \
                        || date -u -d "2 hours ago" +"%Y-%m-%dT%H:%M:%SZ" ;;
    */deploy/state)   printf '%s' "deployed" ;;
    *)                printf '%s' "abc1234def5678901234567890abcdef12345678" ;;
  esac
  exit 0
fi

exit 0
SHIM

cat > "$SHIM_DIR/gh" <<'SHIM'
#!/usr/bin/env bash
# Enough of `gh` to clear preflight and the in-flight/CI checks. The fixtures
# that stop at the SSM-read gate never reach past `auth token`; the ones that
# reach a promotable state need the two `run list` answers below.
set -uo pipefail
case "${1:-} ${2:-}" in
  "auth token") echo "gho_fixture"; exit 0 ;;
  "api user")   echo "fixture-operator"; exit 0 ;;
esac

if [ "${1:-} ${2:-}" = "run list" ]; then
  for a in "$@"; do
    # No in-flight promotion: the script treats empty output as "none", so this
    # must print nothing at all rather than an empty JSON array.
    if [ "$a" = "--status=in_progress" ]; then
      exit 0
    fi
  done
  # No recent build-and-push runs to match the image against — a warning in the
  # script, not a block, which keeps these fixtures off the gh-run-detail paths.
  echo "[]"
  exit 0
fi

echo "[]"
exit 0
SHIM

# A `jq` that always fails, for the fixture that proves the error document is
# built without it (preflight Check 5 fails when jq is missing, so the report of
# that failure cannot itself need jq). Kept out of SHIM_DIR — it goes on PATH
# only for the one case that asks for it, via BROKEN_JQ_DIR.
BROKEN_JQ_DIR="$TMP/brokenjq"
mkdir -p "$BROKEN_JQ_DIR"
cat > "$BROKEN_JQ_DIR/jq" <<'SHIM'
#!/usr/bin/env bash
echo "jq: error: fixture jq always fails" >&2
exit 1
SHIM

# Absolute path to the real jq, resolved before any shim goes on PATH, so the
# assertions below can still parse output from a run whose jq is broken.
JQ="$(command -v jq)"
if [ -z "$JQ" ]; then
  echo "ERROR: jq is required to run these fixtures" >&2
  exit 1
fi

chmod +x "$SHIM_DIR/aws" "$SHIM_DIR/gh" "$BROKEN_JQ_DIR/jq"

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

# run_json_case <description> <jq-filter> <expect-exit> <expect-stderr> \
#               <path-prefix> <env...>
#
# The --json counterpart of run_case. Unlike run_case it must NOT merge the two
# streams: the whole point of --json is that stdout carries one parseable
# document while the human-readable text stays on stderr, and merging them would
# pass a script that had regressed to printing coloured text on stdout.
#
# Asserts three things: stdout parses as JSON (as a whole — a run that leaked one
# line of prose alongside the document fails here), <jq-filter> is truthy against
# it, and the exit status is exactly <expect-exit>. <expect-stderr>, when
# non-empty, must appear on stderr — that is the half of the contract that says
# the operator-facing text did not move or disappear. <path-prefix>, when
# non-empty, goes on PATH ahead of the shims; assertions always use the real jq
# at $JQ, so a case can hand the script a broken one.
run_json_case() {
  local desc="$1" filter="$2" expect_exit="$3" expect_stderr="$4" path_prefix="$5"
  shift 5

  ran=$((ran + 1))

  local case_home="$TMP/home.$ran" err_file="$TMP/stderr.$ran"
  mkdir -p "$case_home"

  local out status
  set +e
  out=$(env "$@" \
    HOME="$case_home" \
    PATH="${path_prefix:+${path_prefix}:}$SHIM_DIR:$PATH" \
    "$SCRIPT" --json 2>"$err_file")
  status=$?
  set -e

  local problem=""
  if ! "$JQ" -e . >/dev/null 2>&1 <<<"$out"; then
    problem="stdout is not a parseable JSON document"
  fi
  if [ -z "$problem" ] && ! "$JQ" -e "$filter" >/dev/null 2>&1 <<<"$out"; then
    problem="jq filter not satisfied: $filter"
  fi
  if [ -z "$problem" ] && [ "$status" -ne "$expect_exit" ]; then
    problem="expected exit $expect_exit, got $status"
  fi
  if [ -z "$problem" ] && [ -n "$expect_stderr" ] && ! grep -qF "$expect_stderr" "$err_file"; then
    problem="stderr is missing the operator-facing text: '$expect_stderr'"
  fi

  if [ -z "$problem" ]; then
    printf "  ok    %s\n" "$desc"
  else
    printf "  FAIL  %s — %s\n" "$desc" "$problem" >&2
    printf "        ---- stdout ----\n%s\n        ---- stderr ----\n%s\n        ----------------\n" \
      "$out" "$(cat "$err_file")" >&2
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
# --------------------------------------------------------------------------
# --json failure documents.
#
# --json is a documented machine interface (CLAUDE.md, Common Commands), but
# every gate above used to honour it only on the way to success: a blocked run
# printed coloured text and exited 1, so `... --json | jq` saw a non-zero status
# and either empty stdout or raw ANSI escapes — indistinguishable from the
# script crashing. Each case below asserts the three things that together make
# the interface trustworthy: stdout parses, the kind is machine-readable, and
# the run still fails closed.
# --------------------------------------------------------------------------

# 16. The read-failure path, the one this suite was built around. An unreadable
#     parameter has to reach a --json consumer as data, not as an empty stdout it
#     cannot tell apart from a crash.
run_json_case "--json emits a parseable document on the read-failure path" \
  '.ok == false and .error == "ssm_read_failed"' \
  1 \
  "Could not read 1 deployment parameter(s)" \
  "" \
  FIXTURE_FAIL_PARAM=/prod/nhp/server/image-tag \
  "FIXTURE_FAIL_MSG=An error occurred (ThrottlingException) when calling the GetParameter operation: Rate exceeded"

# 17. The AWS error text has to survive into the document, not just into stderr:
#     a consumer deciding between "retry" and "fix your credentials" needs the
#     specific failure, and `detail` is where it lives.
run_json_case "the AWS error reaches the --json document's detail" \
  '.detail | length == 1 and (.[0] | test("ThrottlingException") and test("/prod/nhp/server/image-tag"))' \
  1 \
  "" \
  "" \
  FIXTURE_FAIL_PARAM=/prod/nhp/server/image-tag \
  "FIXTURE_FAIL_MSG=An error occurred (ThrottlingException) when calling the GetParameter operation: Rate exceeded"

# 18. Same for the resolver's read (the 2026-08-08 incident's actual path): the
#     failure is recorded from a different place in the script, and must land in
#     the same document with the same kind.
run_json_case "a resolver read failure reports the same --json kind" \
  '.ok == false and .error == "ssm_read_failed" and (.detail[0] | test("active-color"))' \
  1 \
  "" \
  "" \
  FIXTURE_FAIL_PARAM=/sandbox/nhp/server/active-color \
  "FIXTURE_FAIL_MSG=An error occurred (AccessDeniedException) when calling the GetParameter operation: denied"

# 19. The other two gates named in the same review. "Nothing deployed to
#     sandbox" and "that value is not a SHA" are different operator actions, so
#     they are different kinds rather than one generic failure.
run_json_case "an absent sandbox commit is its own --json kind" \
  '.ok == false and .error == "no_sandbox_commit"' \
  1 \
  "No sandbox commit found" \
  "" \
  FIXTURE_NOTFOUND_PARAM=/sandbox/nhp/deploy/deployed-commit

# 20. A bad SHA also has to be *escaped* into the document — this value carries
#     the quote and backslash that would produce unparseable output if the
#     document were built by string-concatenating raw SSM values.
run_json_case "a bad sandbox SHA is reported, and escaped, as JSON" \
  '.ok == false and .error == "invalid_sandbox_commit" and (.detail[0] | test("not-a-sha"))' \
  1 \
  "is not a valid git SHA" \
  "" \
  FIXTURE_VALUE_PARAM=/sandbox/nhp/deploy/deployed-commit \
  'FIXTURE_VALUE=not-a-sha "quoted" and back\slash'

run_json_case "a bad prod SHA is reported as its own --json kind" \
  '.ok == false and .error == "invalid_prod_commit"' \
  1 \
  "is not a valid git SHA" \
  "" \
  FIXTURE_VALUE_PARAM=/prod/nhp/deploy/deployed-commit \
  FIXTURE_VALUE=HEAD

# 21. A non-SHA image tag in *both* blue/green slots clears the tag-mismatch
#     gate and reaches the promotion-tag shape check. Same class of failure as
#     the commit checks, reported one gate later.
run_json_case "a bad server image tag is reported as JSON" \
  '.ok == false and .error == "invalid_image_tag"' \
  1 \
  "is not a valid git SHA" \
  "" \
  "FIXTURE_VALUE_PARAM=/sandbox/nhp/*/image-tag" \
  FIXTURE_VALUE=v1.2.3-not-a-sha

# 22. Preflight is the one gate that can fail *because* jq is missing, so its
#     document is the one that most has to exist. It also carries the individual
#     checks that tripped, not just "preflight failed".
run_json_case "a preflight failure is reported as JSON, with the failed checks" \
  '.ok == false and .error == "preflight_failed" and (.detail | length >= 1)
     and (.detail | join(" ") | test("AWS_PROFILE=layerv"))' \
  1 \
  "Preflight failed" \
  "" \
  FIXTURE_STS_FAIL=1

# 23. ...and the document must be built without jq, or the missing-jq preflight
#     failure reports itself by failing again. A jq that always errors stands in
#     for an absent one (Check 5 only looks for the executable), and the
#     assertions use the real jq resolved before the shims went on PATH.
run_json_case "the --json document is built without jq" \
  '.ok == false and .error == "preflight_failed"' \
  1 \
  "" \
  "$BROKEN_JQ_DIR" \
  FIXTURE_STS_FAIL=1

# 24. The backstop: `set -Eeuo pipefail` can end the run at an unguarded command
#     — here any of the script's own jq calls, since this run's jq always fails —
#     and in --json mode that used to mean exit non-zero with empty stdout, the
#     exact hole this closes.
run_json_case "an unguarded mid-run failure still yields a document" \
  '.ok == false and .error == "unexpected_error"' \
  1 \
  "" \
  "$BROKEN_JQ_DIR" \
  FIXTURE_VALUE_PARAM=/prod/nhp/deploy/deployed-commit \
  FIXTURE_VALUE=9999999999999999999999999999999999999999

# 25. Not every non-promotable outcome is a failure. "Nothing to deploy" exits 0
#     and builds no command, and used to print nothing at all on stdout — a
#     parse error for the consumer, from a run that went perfectly.
run_json_case "nothing-to-deploy is a document, not empty stdout" \
  '.ok == true and .status == "nothing_to_deploy"' \
  0 \
  "Nothing to deploy" \
  ""

# 26. The promotable document is the one consumers actually parse, and it gained
#     the .ok/.status discriminator the cases above key off. Reading it back here
#     keeps a stray comma in that jq filter from shipping.
run_json_case "the promotable document carries the same discriminator" \
  '.ok == true and .status == "promotable" and (.command | test("promote-to-prod.yml"))
     and .workflow_inputs.image_tag == "abc1234def5678901234567890abcdef12345678"' \
  0 \
  "" \
  "" \
  FIXTURE_VALUE_PARAM=/prod/nhp/deploy/deployed-commit \
  FIXTURE_VALUE=9999999999999999999999999999999999999999

# 27. An unparseable *argument* is still an unparseable-output risk: the usage
#     error used to go to stdout, where it would land in front of a consumer
#     expecting JSON. Both orders matter — the mode is not resolved yet when the
#     bad argument comes first, so that case has to look at the whole argument
#     list rather than at how far parsing had got.
#
# check_unknown_arg <description> <script args...> — its own runner because it is
# the only case that passes a second argument alongside --json.
check_unknown_arg() {
  local desc="$1"
  shift

  ran=$((ran + 1))
  mkdir -p "$TMP/home.$ran"

  local out status
  set +e
  out=$(env HOME="$TMP/home.$ran" PATH="$SHIM_DIR:$PATH" "$SCRIPT" "$@" 2>/dev/null)
  status=$?
  set -e

  if [ "$status" -ne 0 ] && "$JQ" -e \
      '.ok == false and .error == "unknown_argument" and .detail == ["--nope"]' \
      >/dev/null 2>&1 <<<"$out"; then
    printf "  ok    %s\n" "$desc"
  else
    printf "  FAIL  %s — no unknown_argument document on stdout (exit=%d)\n" "$desc" "$status" >&2
    printf "        ---- stdout ----\n%s\n        ----------------\n" "$out" >&2
    failed=$((failed + 1))
  fi
}

check_unknown_arg "an unknown argument after --json is reported as JSON" --json --nope
check_unknown_arg "an unknown argument before --json is reported as JSON" --nope --json

# 28. The other half of the contract: --json is the only mode that gets a
#     document. A dry-run that started printing JSON would break the operator
#     output these fixtures were written to protect.
run_case "--dry-run output carries no JSON document" \
  "Could not read 1 deployment parameter(s)" \
  '{"ok":' \
  FIXTURE_FAIL_PARAM=/prod/nhp/server/image-tag \
  "FIXTURE_FAIL_MSG=An error occurred (ThrottlingException) when calling the GetParameter operation: Rate exceeded"

echo ""
if [ "$failed" -gt 0 ]; then
  echo "FAILED: $failed of $ran fixture(s) failed" >&2
  exit 1
fi
echo "PASSED: all $ran fixtures passed"
