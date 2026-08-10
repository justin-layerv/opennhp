#!/usr/bin/env bash
# run-fixtures.sh
# ----------------------------------------------------------------------------
# Regression fixtures for the blue/green post-switch crash gate: what a
# non-zero systemd NRestarts counter on an nhp-server instance is allowed to
# conclude.
#
# The bug these exist to prevent
# -----------------------------
# The gate treated ANY NRestarts >= 1 as an application crash and asserted the
# PR #1096 regression class (panic: send on closed channel) in its error
# message. Sandbox deploy 31340465407 (2026-08-09) failed on:
#
#   Main process exited, code=exited, status=125/n/a
#   docker: Error response from daemon: failed to create task for container:
#   failed to initialize logging driver: failed to create Cloudwatch log stream
#
# Exit 125 is docker's own "the run command failed" — the awslogs driver could
# not create its CloudWatch log stream, the container never started, no Go code
# ran, and systemd's Restart=always policy recovered it in 6 seconds. There was
# no panic. The cost of calling it one anyway was not the red run: the failing
# `validate` job skipped `scale-down-previous` and left `safe_to_release=false`,
# retaining /layerv-nhp-sandbox/qurl-live-env-lock for its full 14400 s TTL —
# four hours of blocked sandbox deploys for the whole team, plus an error
# message sending the reader after a panic that never happened.
#
# What is actually pinned here
# ----------------------------
# Part A drives .github/scripts/classify-nhp-server-restart-evidence.sh over
# the branch matrix directly. Part B runs the REAL verify-knock-ready.sh
# end-to-end against a fake AWS CLI, because a classifier the gate does not
# consult is decoration: a refactor that drops the call, mis-reads the verdict,
# or inverts the pass/fail mapping passes Part A untouched and fails Part B.
#
# The load-bearing safety property is in E3: a Go panic exits the process with
# status 2, so the gate still fails on one even when no stack trace reaches the
# journal (the unit runs `docker run --log-driver=awslogs`, so container output
# goes to CloudWatch). Panic-text detection improves the message; the exit
# status is what keeps the classification safe.
#
# Mirrors the pattern of the other tests/lints/*/run-fixtures.sh suites.
#
# Usage:
#   ./tests/lints/blue-green-restart-classification/run-fixtures.sh
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CLASSIFIER="${REPO_ROOT}/.github/scripts/classify-nhp-server-restart-evidence.sh"
GATE="${REPO_ROOT}/.github/scripts/verify-knock-ready.sh"

for required in "$CLASSIFIER" "$GATE"; do
  if [ ! -x "$required" ]; then
    echo "ERROR: script not executable: $required" >&2
    exit 1
  fi
done

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required to run these fixtures" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failed=0
ran=0

pass() { printf "  ok    %s\n" "$1"; }
fail() {
  printf "  FAIL  %s — %s\n" "$1" "$2" >&2
  if [ -n "${3:-}" ]; then
    printf "        ---- output ----\n%s\n        ----------------\n" "$3" >&2
  fi
  failed=$((failed + 1))
}

# ============================================================================
# Part A — the classifier's branch matrix.
#
# classify_case <description> <expect-verdict> <expect-exit> <report>
#
# Asserts the verdict token AND the exit status, because the two are a
# contract: the gate maps tokens to pass/fail, and a token that stopped
# carrying its own exit status would let a fail-verdict through any caller
# that checks only `$?`.
# ============================================================================
classify_case() {
  local desc="$1" expect_verdict="$2" expect_exit="$3" report="$4"
  shift 4

  ran=$((ran + 1))

  local out status verdict
  set +e
  out=$(env "$@" "$CLASSIFIER" <<<"$report" 2>&1)
  status=$?
  set -e

  verdict=$(sed -n 's/^verdict=//p' <<<"$out")

  if [ "$verdict" != "$expect_verdict" ]; then
    fail "$desc" "expected verdict '$expect_verdict', got '$verdict'" "$out"
    return
  fi
  if [ "$status" -ne "$expect_exit" ]; then
    fail "$desc" "expected exit $expect_exit, got $status" "$out"
    return
  fi
  pass "$desc"
}

# classify_detail_case <description> <expect-substring> <forbid-substring> <report>
# The message half of the contract. "states what was observed" is the fix;
# a verdict that is right while the text still sends the operator hunting a
# panic has not fixed the expensive part.
classify_detail_case() {
  local desc="$1" expect="$2" forbid="$3" report="$4"

  ran=$((ran + 1))

  local out detail
  set +e
  out=$("$CLASSIFIER" <<<"$report" 2>&1)
  set -e
  detail=$(sed -n 's/^detail=//p' <<<"$out")

  if [ -n "$expect" ] && ! grep -qF "$expect" <<<"$detail"; then
    fail "$desc" "detail is missing '$expect'" "$detail"
    return
  fi
  if [ -n "$forbid" ] && grep -qF "$forbid" <<<"$detail"; then
    fail "$desc" "detail must not contain '$forbid'" "$detail"
    return
  fi
  pass "$desc"
}

# The 2026-08-09 incident, byte-for-byte in shape. EXITS carries the stop-path
# `exited:0` ahead of the failure, which is what the journal really holds.
INCIDENT_REPORT='NRESTARTS=1
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:0,exited:125,
PANICS=0
OOM=0
DAEMONERR=Error response from daemon: failed to create task for container: failed to initialize logging driver: failed to create Cloudwatch log stream'

echo "Running blue/green restart-classification fixtures..."
echo "  Part A — classifier branch matrix"

classify_case "a never-restarted unit is clean" \
  clean 0 'NRESTARTS=0
ACTIVESTATE=active
SUBSTATE=running
EXITS=
PANICS=0
OOM=0'

# 1. The headline regression. This exact report must not fail the gate.
classify_case "the 2026-08-09 exit-125 self-heal passes" \
  infra_selfhealed 0 "$INCIDENT_REPORT"

# 2. A Go panic is still a crash, and still the thing the gate exists to catch.
classify_case "a Go panic in the journal is an app crash" \
  app_crash 1 'NRESTARTS=1
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:2,
PANICS=3
OOM=0'

# 3. The safety property. Container stdout goes to CloudWatch via the awslogs
#    driver, so a panic's stack trace can be absent from the journal entirely.
#    Exit 2 is not 125, so the gate must still fail — without this, the fix
#    would trade a false positive for a false negative on the one regression
#    class it was built for.
classify_case "an abnormal exit with no panic text is still an app crash" \
  app_crash 1 'NRESTARTS=1
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:2,
PANICS=0
OOM=0'

classify_case "a signal death is an app crash" \
  app_crash 1 'NRESTARTS=1
ACTIVESTATE=active
SUBSTATE=running
EXITS=killed:11,
PANICS=0
OOM=0'

classify_case "an OOM kill is an app crash" \
  app_crash 1 'NRESTARTS=1
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:137,
PANICS=0
OOM=1'

# The previous case is decided by exit 137 alone, so it does not actually
# exercise the OOM branch. This one does: memory pressure can make the
# container start fail (125) AND trip the kernel OOM killer, and an instance
# under memory pressure must not be waved through as "self-healed".
classify_case "an OOM kill outranks a container-start failure" \
  app_crash 1 'NRESTARTS=1
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:125,
PANICS=0
OOM=1'

# 4. One 125 alongside one real crash is a crash. A fix that stopped at "does
#    any 125 appear?" would launder the panic sitting next to it.
classify_case "a 125 mixed with an abnormal exit is an app crash" \
  app_crash 1 'NRESTARTS=2
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:125,exited:2,
PANICS=0
OOM=0'

# 5. Restarts the evidence cannot account for are not self-healed — they are
#    unexplained, and fail closed as such rather than being waved through.
classify_case "restarts outnumbering their causes are indeterminate" \
  indeterminate 1 'NRESTARTS=2
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:125,
PANICS=0
OOM=0'

# 6. "Self-healed" has to mean healed. A unit still down is an infrastructure
#    fault the deploy must not pass over.
classify_case "an unconverged unit does not pass as self-healed" \
  infra_unstable 1 'NRESTARTS=1
ACTIVESTATE=activating
SUBSTATE=auto-restart
EXITS=exited:125,
PANICS=0
OOM=0'

# 7. A budget, so a container runtime flapping a dozen times is visible even
#    though every individual restart is "only" a 125.
classify_case "container-start flapping past the budget fails" \
  infra_unstable 1 'NRESTARTS=8
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:125,exited:125,exited:125,exited:125,exited:125,exited:125,exited:125,exited:125,
PANICS=0
OOM=0'

classify_case "the self-heal budget is configurable" \
  infra_selfhealed 0 'NRESTARTS=8
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:125,exited:125,exited:125,exited:125,exited:125,exited:125,exited:125,exited:125,
PANICS=0
OOM=0' MAX_SELF_HEALED_RESTARTS=8

# 8. Fail closed on evidence we cannot read, rather than defaulting to either
#    verdict. A missing field is not a healthy field.
classify_case "a report missing a required field is indeterminate" \
  indeterminate 1 'NRESTARTS=1
EXITS=exited:125,
PANICS=0
OOM=0'

classify_case "a non-numeric counter is indeterminate" \
  indeterminate 1 'NRESTARTS=yes
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:125,
PANICS=0
OOM=0'

classify_case "an empty report is indeterminate" \
  indeterminate 1 ''

# 9. The message contract. The #1096 claim is now earned, not asserted.
classify_detail_case "the self-heal message states the observation, not #1096" \
  "Go panic in journal: absent" \
  "#1096" \
  "$INCIDENT_REPORT"

classify_detail_case "the self-heal message names docker as the cause" \
  "docker failed to start the container (exit 125)" \
  "" \
  "$INCIDENT_REPORT"

classify_detail_case "the daemon error reaches the operator" \
  "failed to create Cloudwatch log stream" \
  "" \
  "$INCIDENT_REPORT"

classify_detail_case "an observed panic still names #1096" \
  "#1096" \
  "" \
  'NRESTARTS=1
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:2,
PANICS=3
OOM=0'

# A crash proven only by its exit status must say so and must NOT borrow the
# panic wording — that is the misdiagnosis this whole suite is about, pointed
# the other way.
classify_detail_case "a panic-less crash reports its exit status, not #1096" \
  "exit exited:2" \
  "#1096" \
  'NRESTARTS=1
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:2,
PANICS=0
OOM=0'

# The detail lands inside a `::error::` workflow command; an embedded newline
# would end the annotation early and orphan the rest.
ran=$((ran + 1))
multiline_detail=$("$CLASSIFIER" <<<'NRESTARTS=1
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:125,
PANICS=0
OOM=0
DAEMONERR=Error response from daemon: one
two' || true)
if [ "$(grep -c '^detail=' <<<"$multiline_detail")" -eq 1 ] &&
   [ "$(wc -l <<<"$multiline_detail" | tr -d ' ')" -eq 2 ]; then
  pass "the detail line stays a single line"
else
  fail "the detail line stays a single line" "detail spans multiple lines" "$multiline_detail"
fi

# ============================================================================
# Part B — the real gate, end to end.
#
# A fake AWS CLI answers the ASG lookup, the knock-ready curl, and the
# restart-evidence probe. `sleep` is stubbed out so the gate's load-bearing
# 10 s inter-iteration pause (mirrored as blueGreenGateConvergenceCost in
# endpoints/ac/registration_resilience_test.go — do not change it to speed
# these up) costs nothing here.
# ============================================================================
echo "  Part B — verify-knock-ready.sh end to end"

SHIM_DIR="$TMP/bin"
mkdir -p "$SHIM_DIR"

cat > "$SHIM_DIR/aws" <<'SHIM'
#!/usr/bin/env bash
# Fake AWS CLI. Reads its answers out of $FIXTURE_DIR:
#   instances                    space-separated InService instance ids
#   knock.<instance>             /health/knock-ready response body
#   evidence.<instance>          restart-evidence report
#   evidence.<instance>.fail     if present, the evidence probe errors
set -uo pipefail
svc="${1:-}"; op="${2:-}"

arg_after() {
  local want="$1"; shift
  while [ $# -gt 0 ]; do
    if [ "$1" = "$want" ]; then printf '%s' "${2:-}"; return; fi
    shift
  done
}

if [ "$svc" = "autoscaling" ] && [ "$op" = "describe-auto-scaling-groups" ]; then
  tr ' ' '\t' < "$FIXTURE_DIR/instances"
  exit 0
fi

if [ "$svc" = "ssm" ] && [ "$op" = "send-command" ]; then
  inst="$(arg_after --instance-ids "$@")"
  params="$(arg_after --parameters "$@")"
  case "$params" in
    *knock-ready*) kind=knock ;;
    *NRESTARTS*)   kind=evidence ;;
    *)             kind=unknown ;;
  esac
  printf 'cmd-%s-%s' "$kind" "$inst"
  exit 0
fi

if [ "$svc" = "ssm" ] && [ "$op" = "get-command-invocation" ]; then
  cmd="$(arg_after --command-id "$@")"
  rest="${cmd#cmd-}"
  kind="${rest%%-*}"
  inst="${rest#*-}"

  if [ -f "$FIXTURE_DIR/$kind.$inst.fail" ]; then
    jq -nc '{Status:"Failed",StandardOutputContent:""}'
    exit 0
  fi

  body_file="$FIXTURE_DIR/$kind.$inst"
  [ -f "$body_file" ] || body_file="$FIXTURE_DIR/$kind"
  jq -nc --rawfile c "$body_file" '{Status:"Success",StandardOutputContent:$c}'
  exit 0
fi

exit 0
SHIM

# Instant sleep. The gate needs two consecutive all-ready iterations, so a real
# one would cost 10 s per case for nothing this suite is testing.
cat > "$SHIM_DIR/sleep" <<'SHIM'
#!/usr/bin/env bash
exit 0
SHIM

chmod +x "$SHIM_DIR/aws" "$SHIM_DIR/sleep"

HEALTHY_KNOCK='{"status":"healthy","checks":{"ac_peers":{"message":"3 AC peers connected"}}}'

# gate_case <description> <expect-exit> <expect-substring> <forbid-substring> \
#           <check-nrestarts> <instance-spec...>
#
# Each instance-spec is `<instance-id>=<evidence-report|FAIL>`.
gate_case() {
  local desc="$1" expect_exit="$2" expect="$3" forbid="$4" check_nrestarts="$5"
  shift 5

  ran=$((ran + 1))

  local dir="$TMP/fixture.$ran"
  mkdir -p "$dir"

  local ids=() spec inst body
  for spec in "$@"; do
    inst="${spec%%=*}"
    body="${spec#*=}"
    ids+=("$inst")
    printf '%s' "$HEALTHY_KNOCK" > "$dir/knock.$inst"
    if [ "$body" = "FAIL" ]; then
      : > "$dir/evidence.$inst.fail"
      : > "$dir/evidence.$inst"
    else
      printf '%s\n' "$body" > "$dir/evidence.$inst"
    fi
  done
  printf '%s' "${ids[*]}" > "$dir/instances"

  local out status
  set +e
  out=$(env FIXTURE_DIR="$dir" PATH="$SHIM_DIR:$PATH" \
    "$GATE" fixture-asg post-switch 1 "$check_nrestarts" 2>&1)
  status=$?
  set -e

  if [ "$status" -ne "$expect_exit" ]; then
    fail "$desc" "expected exit $expect_exit, got $status" "$out"
    return
  fi
  if [ -n "$expect" ] && ! grep -qF "$expect" <<<"$out"; then
    fail "$desc" "output is missing '$expect'" "$out"
    return
  fi
  if [ -n "$forbid" ] && grep -qF "$forbid" <<<"$out"; then
    fail "$desc" "output must not contain '$forbid'" "$out"
    return
  fi
  pass "$desc"
}

# E1. The regression, replayed against the real gate on the real instance id
#     from deploy 31340465407. This is the case that cost four hours.
gate_case "the 2026-08-09 deploy now passes the post-switch gate" \
  0 "::warning::" "::error::" true \
  "i-0f08e951e10b5206c=$INCIDENT_REPORT"

gate_case "the passing self-heal does not assert the #1096 panic class" \
  0 "not because of an application crash" "#1096" true \
  "i-0f08e951e10b5206c=$INCIDENT_REPORT"

# E2. The gate still catches what it was built to catch.
gate_case "a Go panic still fails the post-switch gate" \
  1 "#1096" "" true \
  'i-0aaa=NRESTARTS=1
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:2,
PANICS=4
OOM=0'

# E3. ...including when the stack trace never reached the journal.
gate_case "an abnormal exit with no panic text still fails the gate" \
  1 "app_crash" "" true \
  'i-0aaa=NRESTARTS=1
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:2,
PANICS=0
OOM=0'

gate_case "a clean fleet passes with no warning" \
  0 "NRestarts=0" "::warning::" true \
  'i-0aaa=NRESTARTS=0
ACTIVESTATE=active
SUBSTATE=running
EXITS=
PANICS=0
OOM=0'

# E4. Fail closed when the probe itself cannot answer. The retry inside
#     check_restart_evidence must not turn an unreadable instance into a pass.
gate_case "an unreadable evidence probe fails closed" \
  1 "restart-evidence probe failed" "" true \
  "i-0aaa=FAIL"

# E5. Unexplained restarts stay red end to end.
gate_case "an unexplained restart fails the gate" \
  1 "indeterminate" "" true \
  'i-0aaa=NRESTARTS=3
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:125,
PANICS=0
OOM=0'

# E6. Fan-out: one bad instance in a healthy fleet must still fail, and the
#     self-healed sibling must not be reported as a crash.
gate_case "one crashed instance fails a fleet whose sibling self-healed" \
  1 "app_crash" "" true \
  "i-0aaa=$INCIDENT_REPORT" \
  'i-0bbb=NRESTARTS=1
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:2,
PANICS=2
OOM=0'

gate_case "a fleet of self-healed instances passes" \
  0 "::warning::" "::error::" true \
  "i-0aaa=$INCIDENT_REPORT" \
  "i-0bbb=$INCIDENT_REPORT"

# E7. The pre-switch caller is unchanged: check-nrestarts=false skips the probe
#     entirely, because it targets a long-lived fleet whose counter is history.
gate_case "check-nrestarts=false still skips the probe entirely" \
  0 "crash probe disabled" "::error::" false \
  'i-0aaa=NRESTARTS=9
ACTIVESTATE=active
SUBSTATE=running
EXITS=exited:2,
PANICS=9
OOM=0'

# ============================================================================
# Part C — the on-instance probe script.
#
# Parts A and B both start from a report that already exists. The shell that
# produces it runs on the instance via SSM, so nothing above executes a single
# line of it: a wrong sed capture there yields `EXITS=` for every instance,
# every restart becomes unexplained, and the gate fails closed on healthy
# deploys — the same outage with a different message.
#
# So extract that script verbatim out of verify-knock-ready.sh and run it here
# against fake systemctl/journalctl, using real systemd journal text. The
# extraction is canaried below: if the markers stop matching, this fails loudly
# rather than passing on zero assertions.
# ============================================================================
echo "  Part C — the on-instance evidence probe"

PROBE="$(awk "/^RESTART_EVIDENCE_SCRIPT='/{f=1; sub(/^RESTART_EVIDENCE_SCRIPT='/, \"\")} f{print} f && /'\$/{exit}" "$GATE" | sed "\$s/'\$//")"

ran=$((ran + 1))
if [ "$(wc -l <<<"$PROBE" | tr -d ' ')" -ge 8 ] &&
   grep -q 'NRESTARTS=' <<<"$PROBE" &&
   grep -q 'DAEMONERR=' <<<"$PROBE"; then
  pass "the probe script extracts from verify-knock-ready.sh"
else
  fail "the probe script extracts from verify-knock-ready.sh" \
    "extraction markers no longer match — Part C is asserting nothing" "$PROBE"
fi

cat > "$SHIM_DIR/systemctl" <<'SHIM'
#!/usr/bin/env bash
# `systemctl show <unit> --property=X --value`
set -uo pipefail
for a in "$@"; do
  case "$a" in
    --property=NRestarts)   printf '%s\n' "${FIXTURE_NRESTARTS:-0}";   exit 0 ;;
    --property=ActiveState) printf '%s\n' "${FIXTURE_ACTIVESTATE:-active}";  exit 0 ;;
    --property=SubState)    printf '%s\n' "${FIXTURE_SUBSTATE:-running}";    exit 0 ;;
  esac
done
exit 0
SHIM

cat > "$SHIM_DIR/journalctl" <<'SHIM'
#!/usr/bin/env bash
set -uo pipefail
cat "$FIXTURE_JOURNAL"
SHIM

chmod +x "$SHIM_DIR/systemctl" "$SHIM_DIR/journalctl"

# Real systemd/docker output. The unit runs `docker run` attached, so the
# daemon's refusal lands in the unit journal alongside systemd's own lines.
#
# The `No such container` lines are not filler: the unit's
# `ExecStartPre=-/usr/bin/docker stop|rm nhp-server` emits them on every start,
# including the successful retry AFTER the failure. They are therefore the
# last daemon errors in the journal, and a probe that simply tailed the last
# one would report the harmless line and hide the CloudWatch failure that
# actually caused the restart. Verified against a live sandbox instance, whose
# healthy unit's only daemon error is exactly this.
cat > "$TMP/journal.incident" <<'JOURNAL'
Stopping nhp-server.service...
✅ Server stopped gracefully
nhp-server.service: Deactivated successfully.
Stopped nhp-server.service.
Started nhp-server.service.
Error response from daemon: No such container: nhp-server
docker: Error response from daemon: failed to create task for container: failed to initialize logging driver: failed to create Cloudwatch log stream.
nhp-server.service: Main process exited, code=exited, status=125/n/a
nhp-server.service: Failed with result 'exit-code'.
nhp-server.service: Scheduled restart job, restart counter is at 1.
Error response from daemon: No such container: nhp-server
Started nhp-server.service.
JOURNAL

cat > "$TMP/journal.panic" <<'JOURNAL'
Started nhp-server.service.
panic: send on closed channel

goroutine 137 [running]:
github.com/layervai/nhp/endpoints/server.(*UdpServer).sendMessageToPeer(...)
nhp-server.service: Main process exited, code=exited, status=2/INVALIDARGUMENT
nhp-server.service: Scheduled restart job, restart counter is at 1.
Started nhp-server.service.
JOURNAL

cat > "$TMP/journal.clean" <<'JOURNAL'
Started nhp-server.service.
Server listening on 0.0.0.0:62206
JOURNAL

# probe_case <description> <expect-verdict> <journal> <env...>
# Runs the extracted probe, then feeds its real output to the real classifier.
probe_case() {
  local desc="$1" expect_verdict="$2" journal="$3"
  shift 3

  ran=$((ran + 1))

  local report out verdict
  set +e
  report=$(env FIXTURE_JOURNAL="$journal" PATH="$SHIM_DIR:$PATH" "$@" \
    bash -c "$PROBE" 2>&1)
  out=$("$CLASSIFIER" <<<"$report" 2>&1)
  set -e

  verdict=$(sed -n 's/^verdict=//p' <<<"$out")

  if [ "$verdict" = "$expect_verdict" ]; then
    pass "$desc"
  else
    fail "$desc" "expected verdict '$expect_verdict', got '$verdict'" "$report"
  fi
}

probe_case "the real 2026-08-09 journal classifies as self-healed" \
  infra_selfhealed "$TMP/journal.incident" FIXTURE_NRESTARTS=1

probe_case "a real panic journal classifies as an app crash" \
  app_crash "$TMP/journal.panic" FIXTURE_NRESTARTS=1

probe_case "a quiet journal on a never-restarted unit is clean" \
  clean "$TMP/journal.clean" FIXTURE_NRESTARTS=0

# The parser's own output, asserted directly: a sed capture that silently
# stopped matching would otherwise still produce a plausible verdict above.
ran=$((ran + 1))
incident_report=$(env FIXTURE_JOURNAL="$TMP/journal.incident" FIXTURE_NRESTARTS=1 \
  PATH="$SHIM_DIR:$PATH" bash -c "$PROBE" 2>&1 || true)
probe_problem=""
grep -qx 'NRESTARTS=1' <<<"$incident_report" || probe_problem="NRESTARTS not parsed"
grep -qx 'EXITS=exited:125,' <<<"$incident_report" || probe_problem="${probe_problem:-EXITS not parsed as exited:125}"
grep -qx 'PANICS=0' <<<"$incident_report" || probe_problem="${probe_problem:-PANICS miscounted}"
grep -qx 'OOM=0' <<<"$incident_report" || probe_problem="${probe_problem:-OOM miscounted}"
grep -q 'DAEMONERR=Error response from daemon: failed to create task' <<<"$incident_report" ||
  probe_problem="${probe_problem:-DAEMONERR not captured}"
# The retry's harmless ExecStartPre noise must not become the reported cause.
! grep -q 'DAEMONERR=.*No such container' <<<"$incident_report" ||
  probe_problem="${probe_problem:-DAEMONERR reports the benign ExecStartPre error}"
if [ -z "$probe_problem" ]; then
  pass "the probe parses systemd's exit line, panic count and daemon error"
else
  fail "the probe parses systemd's exit line, panic count and daemon error" \
    "$probe_problem" "$incident_report"
fi

# The panic journal's counts, likewise — `goroutine N [running]:` and the
# `panic:` line are both expected to register.
ran=$((ran + 1))
panic_report=$(env FIXTURE_JOURNAL="$TMP/journal.panic" FIXTURE_NRESTARTS=1 \
  PATH="$SHIM_DIR:$PATH" bash -c "$PROBE" 2>&1 || true)
if grep -qx 'EXITS=exited:2,' <<<"$panic_report" && grep -qx 'PANICS=2' <<<"$panic_report"; then
  pass "the probe records a panic's exit status and stack markers"
else
  fail "the probe records a panic's exit status and stack markers" \
    "expected EXITS=exited:2, and PANICS=2" "$panic_report"
fi

# ============================================================================
# Part D — the shared decision table.
#
# The same question is answered twice: here for the blue/green deploy gate,
# and by classifyRestartEvidence in tests/smoke/restart_evidence.go for the
# smoke suite's Tier 1 deploy-stability fence. They cannot share code — this
# one is shell on a GitHub runner collecting evidence with a piped on-instance
# script, and the smoke suite may not send that (tests/smoke/CLAUDE.md rule 8,
# plus the rejectPatterns tripwire that bars pipes and command substitution).
#
# So they share tests/fixtures/nhp-server-restart-evidence/ instead. This part
# drives the shell classifier over it; TestRestartEvidenceCorpus drives the Go
# one over the same cases. A decision changed on one side and not the other
# turns exactly one of the two red.
# ============================================================================
# read_needles FILE → one non-empty assertion substring per line, nothing if the
# file is absent (assertions are optional per case).
#
# The `|| [ -n "$line" ]` and the trim are load-bearing: without them a file
# saved WITHOUT a trailing newline loses its last line, and a padded needle is
# grepped verbatim here while the Go driver trims — either way the two drivers
# assert different sets, which is the cross-driver drift this corpus exists to
# eliminate. Self-tested below.
read_needles() {
  local file="$1" line
  [ -f "$file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [ -n "$line" ] && printf '%s\n' "$line"
  done < "$file"
}

echo "  Part D — shared corpus (drift fence vs the Go classifier)"

CORPUS="${REPO_ROOT}/tests/fixtures/nhp-server-restart-evidence"
corpus_cases=0

for case_dir in "$CORPUS"/*/; do
  [ -d "$case_dir" ] || continue
  case_name="$(basename "$case_dir")"
  corpus_cases=$((corpus_cases + 1))
  ran=$((ran + 1))

  if [ ! -f "$case_dir/report" ] || [ ! -f "$case_dir/verdict" ]; then
    fail "corpus: $case_name" "case is missing report or verdict" ""
    continue
  fi

  want=$(tr -d '[:space:]' < "$case_dir/verdict")
  set +e
  got_out=$("$CLASSIFIER" < "$case_dir/report" 2>&1)
  set -e
  got=$(sed -n 's/^verdict=//p' <<<"$got_out")
  got_detail=$(sed -n 's/^detail=//p' <<<"$got_out")

  if [ "$got" != "$want" ]; then
    fail "corpus: $case_name" "verdict '$got', corpus says '$want'" "$got_out"
    continue
  fi

  problem=""
  while IFS= read -r needle; do
    grep -qF "$needle" <<<"$got_detail" || problem="detail is missing '$needle'"
  done < <(read_needles "$case_dir/detail-contains")
  if [ -z "$problem" ]; then
    while IFS= read -r needle; do
      grep -qF "$needle" <<<"$got_detail" && problem="detail must not contain '$needle'"
    done < <(read_needles "$case_dir/detail-excludes")
  fi

  if [ -z "$problem" ]; then
    pass "corpus: $case_name → $got"
  else
    fail "corpus: $case_name" "$problem" "$got_detail"
  fi
done

ran=$((ran + 1))
if [ "$corpus_cases" -ge 10 ]; then
  pass "the shared corpus still has its cases ($corpus_cases)"
else
  fail "the shared corpus still has its cases" \
    "only $corpus_cases case(s) in $CORPUS — the shared decision table lost cases" ""
fi

# ============================================================================
# Part E — the shared COLLECTOR corpus.
#
# Part D pins the two decision tables against each other, but it starts from a
# report that already exists. There are two COLLECTORS as well — this side's
# piped on-instance script, and the --grep probes plus Go parsers in
# tests/smoke/restart_evidence.go — and two collectors reading the same journal
# can build different reports. A verdict is only as good as the lines it was
# built from, so agreeing on the decision while disagreeing on the evidence
# reproduces the original outage with matching verdicts.
#
# It has already happened twice: the Go side matched only `^panic:` where this
# script matches `fatal error:` and `goroutine N [running]:` too, and this
# script's `tr "\n" " "` left a trailing space on DAEMONERR that the Go side
# trimmed.
#
# So each case in tests/fixtures/nhp-server-restart-journals/ holds journal text
# plus unit state, and the one report both collectors must produce from it. This
# part drives the on-instance script over them; TestRestartEvidenceJournalCorpus
# drives the Go collector over the same journals.
# ============================================================================
echo "  Part E — shared journal corpus (drift fence vs the Go collector)"

JOURNAL_CORPUS="${REPO_ROOT}/tests/fixtures/nhp-server-restart-journals"
journal_cases=0

for case_dir in "$JOURNAL_CORPUS"/*/; do
  [ -d "$case_dir" ] || continue
  case_name="$(basename "$case_dir")"
  journal_cases=$((journal_cases + 1))
  ran=$((ran + 1))

  if [ ! -f "$case_dir/journal" ] || [ ! -f "$case_dir/unit" ] || [ ! -f "$case_dir/report" ]; then
    fail "journal corpus: $case_name" "case is missing journal, unit or report" ""
    continue
  fi

  # Daemon-error lines must be ASCII, and this checks it rather than trusting
  # the README to be obeyed.
  #
  # `cut -c1-200` in the on-instance script counts CHARACTERS under a UTF-8
  # locale (BSD/macOS) and BYTES under GNU coreutils, while the Go collector
  # slices 200 bytes. A multi-byte daemon error at or over that boundary
  # therefore passes on Linux CI and fails a macOS `make lint-workflows`, as a
  # byte-diff on a report that looks correct. Caught ahead of that comparison so
  # the message names the cause.
  #
  # Scoped to the daemon-error line because that is the only text `cut -c`
  # touches: EXITS goes through a line-wise sed, and PANICS/OOM through
  # `grep -c` on ASCII patterns, none of which is locale-sensitive. Journals may
  # therefore keep real non-ASCII elsewhere — the unit's own stop handler logs
  # "✅ Server stopped gracefully", and a fixture that dropped it to satisfy a
  # blanket ASCII rule would be less faithful for no gain.
  #
  # LC_ALL=C makes the bracket expression byte-wise: every byte of a multi-byte
  # sequence is >= 0x80, so it is neither [:print:] nor [:space:].
  case_daemon_lines=$(grep -o 'Error response from daemon:.*' "$case_dir/journal" || true)
  if printf '%s' "$case_daemon_lines" | LC_ALL=C grep -q '[^[:print:][:space:]]'; then
    fail "journal corpus: $case_name" \
      "the daemon-error line carries non-ASCII bytes; keep it ASCII — cut -c is character-based under a UTF-8 locale and byte-based under GNU coreutils, so this case would pass on Linux CI and fail on macOS. See the corpus README." \
      "$case_daemon_lines"
    continue
  fi

  # `unit` holds the three values systemctl would report, in the same
  # key=value shape as the report so both sides read it identically.
  case_nrestarts=$(sed -n 's/^NRESTARTS=//p' "$case_dir/unit")
  case_activestate=$(sed -n 's/^ACTIVESTATE=//p' "$case_dir/unit")
  case_substate=$(sed -n 's/^SUBSTATE=//p' "$case_dir/unit")

  set +e
  got_report=$(env FIXTURE_JOURNAL="$case_dir/journal" \
    FIXTURE_NRESTARTS="$case_nrestarts" \
    FIXTURE_ACTIVESTATE="$case_activestate" \
    FIXTURE_SUBSTATE="$case_substate" \
    PATH="$SHIM_DIR:$PATH" bash -c "$PROBE" 2>&1)
  set -e

  # Compared byte for byte against the committed report, trailing newline
  # aside. A normalising comparison here would have hidden the DAEMONERR
  # trailing space that this fence was written to catch — and THIS is the only
  # side that can see a regression in the script, because it is the only side
  # that runs it. The Go counterpart's inputs are the committed report and its
  # own collector's output, so nothing this script does can change its result.
  if [ "$got_report" = "$(cat "$case_dir/report")" ]; then
    pass "journal corpus: $case_name"
  else
    fail "journal corpus: $case_name" \
      "the on-instance script no longer produces this case's report" \
      "$(diff <(cat "$case_dir/report") <(printf '%s\n' "$got_report") || true)"
  fi
done

ran=$((ran + 1))
if [ "$journal_cases" -ge 5 ]; then
  pass "the shared journal corpus still has its cases ($journal_cases)"
else
  fail "the shared journal corpus still has its cases" \
    "only $journal_cases case(s) in $JOURNAL_CORPUS — the shared collector corpus lost cases" ""
fi

# ============================================================================
# Part F — cross-file lockstep: the offline smoke -run allow-list, the
# self-heal budget default shared by the two classifiers, and the corpus needle
# reader itself.
# ============================================================================
echo "  Part F — cross-file lockstep"

ran=$((ran + 1))
printf '  padded-needle  \n' > "$TMP/padded.txt"
if [ "$(read_needles "$TMP/padded.txt")" = "padded-needle" ]; then
  pass "corpus needle reader trims padding, as the Go driver does"
else
  fail "corpus needle reader trims padding, as the Go driver does" \
    "the two drivers would grep different substrings" ""
fi

ran=$((ran + 1))
printf 'first\nlast-without-trailing-newline' > "$TMP/needles.txt"
if [ "$(read_needles "$TMP/needles.txt" | wc -l | tr -d ' ')" = "2" ]; then
  pass "corpus needle reader keeps a last line with no trailing newline"
else
  fail "corpus needle reader keeps a last line with no trailing newline" \
    "read_needles dropped it — shell and Go drivers would assert different sets" ""
fi

# The self-heal budget lives in two languages; the corpus pins it only at the
# DEFAULT, so compare the defaults directly.
ran=$((ran + 1))
# shellcheck disable=SC2016  # the ${...} is literal text being matched in the
# classifier's source, not an expansion for this shell to perform.
shell_budget=$(sed -n 's/^MAX_SELF_HEALED_RESTARTS="${MAX_SELF_HEALED_RESTARTS:-\([0-9]*\)}"$/\1/p' "$CLASSIFIER")
go_budget=$(sed -n 's/^const maxSelfHealedRestarts = \([0-9]*\)$/\1/p' "${REPO_ROOT}/tests/smoke/restart_evidence.go")
if [ -z "$shell_budget" ] || [ -z "$go_budget" ]; then
  fail "self-heal budget default matches between shell and Go" \
    "could not extract both defaults (shell='$shell_budget' go='$go_budget') — extraction markers drifted, so this fence is asserting nothing" ""
elif [ "$shell_budget" = "$go_budget" ]; then
  pass "self-heal budget default matches between shell and Go ($shell_budget)"
else
  fail "self-heal budget default matches between shell and Go" \
    "shell default $shell_budget, Go const $go_budget" ""
fi

# ...and nothing may set the env override, which would move the shell budget
# while the Go const stayed put. Scoped to all of .github/ (the classifier's
# invoker lives in .github/scripts/), excluding the classifier's own default.
ran=$((ran + 1))
override_hits=$(grep -rn 'MAX_SELF_HEALED_RESTARTS' "${REPO_ROOT}/.github" 2>/dev/null \
  | grep -v 'classify-nhp-server-restart-evidence.sh' || true)
if [ -n "$override_hits" ]; then
  fail "nothing under .github mentions MAX_SELF_HEALED_RESTARTS" \
    "something references the env override; if this is only a documentation mention, narrow this grep to an assignment form" \
    "$override_hits"
else
  pass "nothing under .github mentions MAX_SELF_HEALED_RESTARTS"
fi

# The offline -run allow-list is duplicated in the workflow and the Makefile and
# fenced by nothing else; and comparing the two copies cannot catch a test BOTH
# omit, so the allow-list must also be shown to select every offline test.
extract_run_pattern() {
  sed -n "s/.*-run '\([^']*\)'.*/\1/p" "$1" | grep 'TestRestartEvidence' | head -1
}
wf_pattern=$(extract_run_pattern "${REPO_ROOT}/.github/workflows/nhp-smoke-pr.yml")

ran=$((ran + 1))
ssm_gated='skipIfNoSSMProbes|requireRemote|requireActive|describeInServiceInstances|getSSMParameter|requireServingASG|requireCWLogs'
offline_files="tests/smoke/restart_evidence_test.go tests/smoke/06_server_deploy_stability_test.go"
offline_missing=""
for offline_file in $offline_files; do
  [ -f "${REPO_ROOT}/${offline_file}" ] || offline_missing="$offline_missing $offline_file"
done
missed=""
offline_count=0
seen_any=0
while IFS="$(printf '\t')" read -r test_name test_body; do
  seen_any=1
  printf '%s' "$test_body" | grep -qE "$ssm_gated" && continue
  offline_count=$((offline_count + 1))
  printf '%s' "$test_name" | grep -qE "$wf_pattern" || missed="$missed $test_name"
done < <(awk '
  /^func Test[A-Za-z0-9_]+\(/ { name=$2; sub(/\(.*/,"",name); body=""; inbody=1; next }
  inbody && /^}/ { printf "%s\t%s\n", name, body; inbody=0; next }
  inbody { body = body " " $0 }
' "${REPO_ROOT}/tests/smoke/restart_evidence_test.go" \
  "${REPO_ROOT}/tests/smoke/06_server_deploy_stability_test.go")

if [ -n "$offline_missing" ]; then
  fail "the offline allow-list selects every offline test" \
    "scanned file(s) missing:$offline_missing — moved or renamed, so this fence silently stopped covering them" ""
elif [ "$seen_any" -eq 0 ] || [ "$offline_count" -eq 0 ]; then
  fail "the offline allow-list selects every offline test" \
    "found no offline Test functions — the awk extraction drifted, so this fence is asserting nothing" ""
elif [ -n "$missed" ]; then
  fail "the offline allow-list selects every offline test" \
    "the -run pattern does not select:$missed — they compile at PR time but never execute" "pattern: $wf_pattern"
else
  pass "the offline allow-list selects every offline test ($offline_count)"
fi

echo ""
# A suite that asserted nothing would otherwise report success.
if [ "$ran" -lt 25 ]; then
  echo "FAILED: only $ran fixtures ran — the suite lost cases" >&2
  exit 1
fi
if [ "$failed" -gt 0 ]; then
  echo "FAILED: $failed of $ran fixture(s) failed" >&2
  exit 1
fi
echo "PASSED: all $ran fixtures passed"
