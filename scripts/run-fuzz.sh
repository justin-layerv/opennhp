#!/usr/bin/env bash
# run-fuzz.sh
# ----------------------------------------------------------------------------
# Run a single Go fuzz target and distinguish a real crashing input from
# the upstream Go-fuzz coordinator deadline-race flake.
#
# Background
# ----------
# `go test -fuzz=NAME -fuzztime=DURATION` periodically reports
#     --- FAIL: NAME (Xs)
#         context deadline exceeded
#     FAIL
# on the 2-worker GitHub runner when the fuzz coordinator's deadline
# expires while a worker is mid-iteration. The harness has not found a
# bug in this case — it is the test runner's own RPC timing out as it
# tries to shut workers down at the deadline boundary. We have hit this
# class of flake repeatedly: nhp#1188 / qurl-service#325 (the prior
# 10s -> 15s `FUZZTIME_QUICK` bump) and nhp#1649 (red `fuzz-quick` on a
# terraform-only PR that could not have introduced a Go crasher).
#
# Bumping the budget was a probabilistic mitigation, not a structural
# fix: any duration deadline can fall mid-iteration on a busy runner.
#
# How we tell the two apart
# -------------------------
# Real Go-fuzz crashers ALWAYS write a reproducer file at
#     <pkg>/testdata/fuzz/<NAME>/<sha>
# (Go's documented contract — the file lets a follow-up run replay the
# input and reproduce the panic). This is also exactly what the
# `fuzz-failure-corpus` artifact upload in ubuntu-build.yml uploads.
#
# This wrapper:
#   1. snapshots <pkg>/testdata/fuzz/<NAME>/ before the run,
#   2. runs `go test -fuzz=NAME -fuzztime=DURATION`,
#   3. on non-zero exit, diffs testdata/fuzz/<NAME>/ for any new file:
#       - new file present  => real crasher, propagate failure
#       - no new file AND output contains "context deadline exceeded"
#                           => deadline-race flake, log a CI warning
#                              and exit 0
#       - anything else     => propagate failure (build error, panic
#                              before the fuzz runner started, etc.)
#
# We deliberately scope the soft-pass branch to BOTH "no crasher file"
# AND "context deadline exceeded" in the output — never to a bare
# non-zero exit — so we cannot silently mask a legitimate failure mode
# we have not seen before.
#
# Usage: scripts/run-fuzz.sh <pkg> <fuzz-name> <fuzz-time> [extra go-test args...]
#
# Example: scripts/run-fuzz.sh ./test/ FuzzAgentKnockMsg 15s

set -uo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: $0 <pkg> <fuzz-name> <fuzz-time> [extra go-test args...]" >&2
  exit 64
fi

pkg="$1"
name="$2"
fuzztime="$3"
shift 3

# Snapshot the per-fuzzer testdata directory so we can detect a new
# crasher reproducer regardless of any pre-existing committed corpus.
# We deliberately do NOT mkdir -p the dir up front: on a clean checkout
# where no fuzzer has ever crashed, doing so would leave empty
# `testdata/fuzz/<NAME>/` paths behind every run for no benefit (git
# does not track them but local checkouts get untracked dirs). go-test
# creates the dir itself when it actually writes a reproducer; we just
# treat a missing dir as an empty before-set.
testdata_dir="${pkg%/}/testdata/fuzz/${name}"

before="$(mktemp)"
out="$(mktemp)"
after="$(mktemp)"
trap 'rm -f "$before" "$out" "$after"' EXIT

snapshot_testdata() {
  local target="$1"
  if [ -d "$testdata_dir" ]; then
    ( cd "$testdata_dir" && find . -type f -print 2>/dev/null | sort > "$target" )
  else
    : > "$target"
  fi
}

snapshot_testdata "$before"

# Capture combined stdout+stderr while still streaming live to the
# caller (CI log readability). PIPESTATUS preserves the go-test exit
# through the tee pipeline; with `set -uo pipefail` (no -e) at the
# top, a non-zero go-test status does not terminate the script and we
# can branch on $status directly.
go test -run='^$' -fuzz="$name" -fuzztime="$fuzztime" "$@" "$pkg" 2>&1 | tee "$out"
status="${PIPESTATUS[0]}"

if [ "$status" -eq 0 ]; then
  exit 0
fi

snapshot_testdata "$after"
new_files="$(comm -13 "$before" "$after" || true)"

if [ -n "$new_files" ]; then
  # Real crasher: a reproducer was written during this run. Surface
  # the path so the operator can find it in the uploaded artifact.
  # GHA workflow commands (::error::, ::warning::) are parsed from
  # stdout per the documented contract, so do not redirect to stderr.
  echo "::error::Fuzz target ${name} produced new crashing input(s) under ${testdata_dir}:"
  while IFS= read -r f; do
    [ -n "$f" ] && echo "  ${testdata_dir}/${f#./}"
  done <<< "$new_files"
  exit "$status"
fi

# No crasher file written. The deadline-race flake has a tight
# signature: the line `--- FAIL: <NAME> (Xs)` is immediately followed
# by `    context deadline exceeded` (4-space indent — that is Go's
# standard FAIL detail format). We match the pair exactly: a real
# fuzz failure whose top-level error is something else (e.g. a seed
# `t.Fatal`) does NOT trigger soft-pass even if "context deadline
# exceeded" appears elsewhere in the output (a downstream library
# log line, an unrelated subtest, etc.). awk is used because POSIX
# grep cannot enforce "next line is exactly X" without GNU-specific
# context flag combinations.
#
# MAINTENANCE SIGNAL: `    context deadline exceeded` is a Go test-runner
# internal string, not part of any stable contract. If a Go toolchain
# bump reformats it (adds a colon, adds a worker ID prefix, changes the
# indent), the wrapper will silently regress to flaky reds (the safe
# direction — failures still surface, just no longer soft-pass). When
# `fuzz-quick` starts going red on terraform-only PRs again after a Go
# version bump, this is the first place to look. The fence below
# (tests/lints/run-fuzz/run-fixtures.sh) will also start failing.
if awk -v n="$name" '
  $0 ~ ("^--- FAIL: " n "( |$)") { nxt = 1; next }
  nxt { nxt = 0; if ($0 == "    context deadline exceeded") { found = 1; exit } }
  END { exit !found }
' "$out"; then
  echo "::warning::Fuzz target ${name} hit the upstream Go-fuzz coordinator deadline race (no crashing input written). Treating as a flake; see scripts/run-fuzz.sh for the rationale."
  # Preserve the captured fuzz output for post-hoc debugging. The
  # workflow's `if: failure()` artifact upload won't fire on a
  # soft-pass, and the trap deletes $out, so the GHA inline log is
  # otherwise the only record of how often / on which target the
  # race fires. Truncate to the last 100 lines to keep the summary
  # readable across many fuzzers per run.
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "<details><summary>fuzz-flake: ${name} (${fuzztime})</summary>"
      echo
      echo '```'
      tail -n 100 "$out"
      echo '```'
      echo "</details>"
    } >> "$GITHUB_STEP_SUMMARY"
  fi
  exit 0
fi

# Unknown non-zero exit with no crasher and no deadline-race signature.
# Propagate so we do not silently mask a new failure mode.
exit "$status"
