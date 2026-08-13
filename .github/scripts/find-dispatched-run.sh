#!/bin/bash
# Find a workflow run that this process just dispatched, using a
# correlation ID echoed in the run's display name.
#
# Background: the previous dispatch-and-poll scripts tried to find
# "the run I just dispatched" by filtering `gh run list` on
# `createdAt >= dispatch_time` plus a coarse status filter. That has
# two known failure modes:
#
#   1. A parallel dispatch (another CI job or a human) can land in
#      the same time window and get matched by mistake. The scripts
#      relied on `[.[] | ... | .[0]]` picking the most recent run,
#      but "most recent" is meaningless when two dispatches land
#      microseconds apart.
#
#   2. GitHub reports held-by-concurrency dispatches as `status=waiting`
#      (not `queued`), so a run held by the blue-green-${env}
#      concurrency group or the environment approval gate was
#      invisible to any filter that didn't explicitly include
#      `waiting`. The finder loop timed out after its retry budget
#      even though the dispatched run existed all along.
#
# This helper takes a different approach: the dispatched workflow
# sets `run-name:` to include a unique correlation ID passed in as
# a workflow input, and this script finds runs by exact correlation
# ID match in the `displayTitle` field — no timestamp windowing,
# no status filtering. A held run is found the same as a running
# one the same as a fast-failing one. The correlation ID is the
# entire ground truth.
#
# Usage:
#   find-dispatched-run.sh <workflow> <correlation_id> [retries] [delay_seconds]
#
#   workflow        — workflow filename (e.g. blue-green-deploy.yml)
#   correlation_id  — exact string the dispatched run's displayTitle
#                     must contain (typically "[corr:<id>]")
#   retries         — max poll attempts before giving up (default 24)
#   delay_seconds   — sleep between attempts (default 5)
#
# Total worst-case wait is retries * delay_seconds. The default
# 24 * 5 = 120s covers the empirically-measured ~30s
# eventual-consistency delay between `gh workflow run` returning and
# the dispatched run showing up in `gh run list` (measured 2026-04-08
# on this repo: dispatch returned at t=2s, run first visible in list
# at t=30s — see this PR's description for the measurement script
# and outcome).
# Anything under ~45s races the GitHub API in practice and fails
# intermittently; 120s is 4x the observed worst case. Bump `retries`
# if a particular caller genuinely needs more patience, but do not
# lower the default without re-measuring the latency.
#
# Writes the run's databaseId to stdout on success. Returns 1 with
# an error message on timeout.

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <workflow> <correlation_id> [retries] [delay_seconds]" >&2
  exit 2
fi

WORKFLOW="$1"
CORRELATION_ID="$2"
RETRIES="${3:-24}"
DELAY="${4:-5}"

if [[ -z "${GITHUB_REPOSITORY:-}" ]]; then
  echo "::error::GITHUB_REPOSITORY must be set" >&2
  exit 2
fi

# Run names are set by the dispatched workflow's `run-name:` field as
# a single string that embeds the correlation ID inside `[corr:...]`.
# Match on exact substring — jq's `contains` is deliberately naive so
# an injection attack (some other caller happening to embed the same
# id) is the least of our problems compared to the current silent
# failure mode.
#
# `--limit 50` is a bigger window than the default to survive a burst
# of dispatches (Dependabot batches, back-to-back manual deploys, etc.)
# pushing the target run past the first page before the finder polls.
# 50 covers >2x the busiest historical CI pattern with negligible
# extra API cost.
GH_STDERR=$(mktemp)
trap 'rm -f "$GH_STDERR"' EXIT
GH_ERROR_LOGGED=0

for i in $(seq 1 "$RETRIES"); do
  run_id=$(gh run list \
    --workflow "$WORKFLOW" \
    --limit 50 \
    --json databaseId,displayTitle \
    --jq "[.[] | select(.displayTitle | contains(\"[corr:${CORRELATION_ID}]\"))] | .[0].databaseId // empty" \
    2>"$GH_STDERR" || echo "")

  if [[ -n "$run_id" ]]; then
    echo "$run_id"
    exit 0
  fi

  # Surface gh CLI errors the first time they occur. Without this, a
  # transient API failure / auth blip / network issue burns the entire
  # retry budget while only printing "no match yet" messages, leaving
  # the operator to guess whether the run is genuinely missing or gh
  # itself is broken. Log once and keep retrying — the underlying
  # condition may clear on its own.
  if (( GH_ERROR_LOGGED == 0 )) && [[ -s "$GH_STDERR" ]]; then
    echo "  [find-dispatched-run] gh CLI emitted errors on attempt $i (will keep retrying):" >&2
    sed 's/^/    /' "$GH_STDERR" >&2
    GH_ERROR_LOGGED=1
  fi

  if (( i < RETRIES )); then
    echo "  [find-dispatched-run] no match yet for [corr:${CORRELATION_ID}] (attempt $i/$RETRIES), sleeping ${DELAY}s..." >&2
    sleep "$DELAY"
  fi
done

echo "::error::find-dispatched-run: no $WORKFLOW run matched [corr:${CORRELATION_ID}] after ${RETRIES} attempts (~$((RETRIES * DELAY))s)" >&2
exit 1
