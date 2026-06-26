#!/usr/bin/env bash
# run-fixtures.sh
# ----------------------------------------------------------------------------
# Regression fixtures for scripts/run-fuzz.sh (#1653).
#
# scripts/run-fuzz.sh is the only thing distinguishing a real Go-fuzz
# crasher from the upstream coordinator deadline-race flake on the
# `fuzz-quick` CI job. A silent regression in the wrapper would
# re-introduce both failure modes — false-red on every PR (deadline
# race no longer soft-passed) or false-green that masks a real crasher
# (a refactor that flips the conditional logic). Either is silent.
# These fixtures fence each branch of the wrapper's decision tree so
# that lint-time catches a regression before it lands.
#
# How it works: each fixture installs a fake `go` shim on PATH that
# emulates a single go-test outcome (happy path, real crasher writing
# a reproducer file, deadline-race signature, build failure, etc.),
# invokes the wrapper, and asserts the expected exit code.
#
# Mirrors the pattern of the other tests/lints/*/run-fixtures.sh suites.
#
# Usage:
#   ./tests/lints/run-fuzz/run-fixtures.sh
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WRAPPER="${REPO_ROOT}/scripts/run-fuzz.sh"
FUZZ_NAME="FuzzAgentKnockMsg"

if [ ! -x "$WRAPPER" ]; then
  echo "ERROR: wrapper not executable: $WRAPPER" >&2
  exit 1
fi

# Single trapped tempdir for all per-fixture working dirs and shims.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

failed=0
ran=0

# run_case <description> <expected-exit> <go-shim-script-body>
#
# Spawns a fresh CWD with a fake `go` shim that emits the given output
# and exits with the script's status. Invokes the wrapper and asserts
# the wrapper's exit code matches expected. Output goes to /dev/null
# so a real failure is the only thing that prints.
run_case() {
  local desc="$1" expected="$2" body="$3"
  ran=$((ran + 1))

  local case_dir
  case_dir="$(mktemp -d "$TMP/case.XXXXXX")"

  printf '%s\n' "$body" > "$case_dir/go"
  chmod +x "$case_dir/go"

  local got
  set +e
  ( cd "$case_dir" && PATH="$case_dir:$PATH" "$WRAPPER" ./test/ "$FUZZ_NAME" 15s ) >/dev/null 2>&1
  got=$?
  set -e

  if [ "$got" -eq "$expected" ]; then
    printf "  ok    %s (exit=%d)\n" "$desc" "$got"
  else
    printf "  FAIL  %s (exit=%d, expected=%d)\n" "$desc" "$got" "$expected" >&2
    failed=$((failed + 1))
  fi
}

echo "Running run-fuzz wrapper fixtures..."

# 1. Happy path: go test exits 0, no testdata. Wrapper must pass through 0.
run_case "happy-path" 0 '#!/usr/bin/env bash
echo "PASS"
exit 0'

# 2. go-test exit 1 with the bare string "context deadline exceeded"
#    but no `--- FAIL: <NAME>` line. Must NOT soft-pass — the awk
#    signature requires the full FAIL/indent pair.
run_case "deadline-race-no-FAIL-line" 1 '#!/usr/bin/env bash
echo "context deadline exceeded"
exit 1'

# 3. Full deadline-race signature: `--- FAIL: <NAME> (Xs)` immediately
#    followed by `    context deadline exceeded`, no testdata file
#    written. This is the upstream Go-fuzz coordinator race the wrapper
#    exists to soft-pass. Must exit 0.
run_case "deadline-race-full-signature" 0 '#!/usr/bin/env bash
echo "fuzz: elapsed: 15s, execs: 261299 (19230/sec)"
echo "--- FAIL: FuzzAgentKnockMsg (15.05s)"
echo "    context deadline exceeded"
echo "FAIL"
exit 1'

# 4. Real crasher: go-test writes a reproducer to
#    testdata/fuzz/<NAME>/<sha> and exits 1. Wrapper must propagate
#    failure — soft-pass MUST NOT swallow a real crasher even if some
#    code path also emits the deadline-race string.
run_case "real-crasher" 1 '#!/usr/bin/env bash
mkdir -p ./test/testdata/fuzz/FuzzAgentKnockMsg
printf "go test fuzz v1\n[]byte(\"crash\")\n" > ./test/testdata/fuzz/FuzzAgentKnockMsg/abc123
echo "--- FAIL: FuzzAgentKnockMsg (0.10s)"
echo "    panic: index out of range"
echo "    Failing input written to testdata/fuzz/FuzzAgentKnockMsg/abc123"
exit 1'

# 5. Build failure: exit 2, no fuzz output, no testdata. Wrapper must
#    propagate the original exit code (not collapse to 0 or 1).
run_case "build-failure-exit-2" 2 '#!/usr/bin/env bash
echo "./test/foo.go:42:5: undefined: bar" >&2
exit 2'

# 6. Real fuzz failure with stray "context deadline exceeded" elsewhere.
#    The line `--- FAIL: <NAME>` is present but the immediately-next
#    line is NOT the deadline-race detail — the awk pair must reject
#    soft-pass. This is the case the round-1 review explicitly flagged
#    as the soft-pass-narrowing regression.
run_case "real-failure-with-stray-deadline-string" 1 '#!/usr/bin/env bash
echo "warning: a downstream lib log line saying context deadline exceeded"
echo "--- FAIL: FuzzAgentKnockMsg (0.05s)"
echo "    knock_test.go:23: unexpected: assertion failed"
echo "FAIL"
exit 1'

# 7. Deadline-race signature scoped to a DIFFERENT target name (the
#    one we are running is FuzzAgentKnockMsg; the FAIL line names
#    FuzzSomeOther). Wrapper must propagate — the awk first-line
#    match anchors on `^--- FAIL: $name( |$)` so a wrong-target
#    signature can't trigger soft-pass.
run_case "race-signature-different-target" 1 '#!/usr/bin/env bash
echo "--- FAIL: FuzzSomeOther (15.05s)"
echo "    context deadline exceeded"
echo "FAIL"
exit 1'

# 8. Subtest seed-corpus FAIL line (e.g., `--- FAIL: FuzzAgentKnockMsg/seed#01`).
#    A real seed `t.Fatal` produces a slash-suffixed FAIL line, NOT
#    space/EOL-suffixed — must reject soft-pass. Round-2 review
#    explicitly flagged this as a class the awk regex needs to exclude.
run_case "subtest-seed-fail" 1 '#!/usr/bin/env bash
echo "--- FAIL: FuzzAgentKnockMsg/seed#01 (0.00s)"
echo "    context deadline exceeded"
echo "FAIL"
exit 1'

# 9. BOTH signals present: a real crasher reproducer is written to
#    testdata/fuzz/<NAME>/<sha> AND the output also contains the full
#    deadline-race signature (`--- FAIL: <NAME> (Xs)` immediately
#    followed by `    context deadline exceeded`). Pathological but
#    plausible — slow CI runner, OOM-killed worker that managed to
#    write a reproducer before being terminated. Wrapper must
#    propagate exit 1: the file-write check at scripts/run-fuzz.sh:104
#    runs BEFORE the awk soft-pass block, so a real crasher always
#    wins. Round-3 review explicitly asked for this fixture so the
#    conditional ordering can never be flipped silently by a refactor.
run_case "real-crasher-with-deadline-race-co-occurring" 1 '#!/usr/bin/env bash
mkdir -p ./test/testdata/fuzz/FuzzAgentKnockMsg
printf "go test fuzz v1\n[]byte(\"crash\")\n" > ./test/testdata/fuzz/FuzzAgentKnockMsg/abc123
echo "fuzz: elapsed: 15s, execs: 261299 (19230/sec)"
echo "--- FAIL: FuzzAgentKnockMsg (15.05s)"
echo "    context deadline exceeded"
echo "    Failing input written to testdata/fuzz/FuzzAgentKnockMsg/abc123"
echo "FAIL"
exit 1'

echo
if [ "$failed" -ne 0 ]; then
  echo "::error::run-fuzz fixtures: ${failed}/${ran} failed" >&2
  exit 1
fi
echo "run-fuzz fixtures: all ${ran} passed"
