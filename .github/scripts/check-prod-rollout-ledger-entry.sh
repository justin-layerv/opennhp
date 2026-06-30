#!/usr/bin/env bash
# check-prod-rollout-ledger-entry.sh — confirm a PR diff carries a prod rollout
# ledger entry, for the `select:added` branch of the prod-rollout-tasks gate.
#
# Reads a newline-separated list of changed file paths on stdin (the caller
# fetches them and filters out pure deletions first). Exits 0 if at least one
# path is a ledger entry — any file under docs/runbooks/prod-rollout-ledger/
# other than its README — otherwise exits 1 with a `::error::` annotation.
# Pure (no network) so it is unit-tested by
# tests/scripts/check-prod-rollout-ledger-entry_test.sh; the network fetch
# stays in the workflow.
#
# Usage: printf '%s\n' "$changed_files" | check-prod-rollout-ledger-entry.sh
set -euo pipefail

# Match any added/modified/renamed ledger entry: a path under the ledger dir
# other than its README. `|| true` keeps a no-match grep from tripping
# `set -o pipefail`, and avoiding `grep -q` keeps the pipe open so the upstream
# grep never takes SIGPIPE regardless of the changed-file count.
entry_files=$(grep -E '^docs/runbooks/prod-rollout-ledger/.+' \
	| grep -vE '^docs/runbooks/prod-rollout-ledger/README\.md$' || true)

if [ -z "$entry_files" ]; then
	echo "::error::The PR body says a prod rollout ledger entry was added, but no added/modified file under docs/runbooks/prod-rollout-ledger/ (other than README.md) is in the PR diff." >&2
	exit 1
fi
