#!/usr/bin/env bash
# check-dispatch-concurrency-isolation.sh — guard the build-and-push concurrency contract.
# ----------------------------------------------------------------------------
# A workflow_dispatch of build-and-push.yml that carries a correlation_id came
# from a parent pipeline blocking on that exact run (see find-dispatched-run.sh).
# It must therefore be immune to cancellation by unrelated dispatches:
#
#   * its concurrency group must be discriminated by correlation_id, and
#   * cancel-in-progress must be false for it.
#
# When both dispatch kinds shared one nhp-<env>-<ref>-workflow_dispatch lane with
# cancel-in-progress, any ad-hoc sandbox deploy silently killed the
# scheduled-release pipeline's build. The pipeline then failed after a ~85-minute
# wait, and the cancelled run carried no failure to point at — so the release
# stopped promoting to prod for weeks without ever reporting a red build.
#
# Manual dispatches (no correlation_id) must keep cancelling each other: clicking
# the button twice should supersede, not queue.
#
# Override the inspected file with BUILD_AND_PUSH_WF for fixture testing.
# Usage: bash scripts/check-dispatch-concurrency-isolation.sh
# ============================================================================

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/.." && pwd)
WF="${BUILD_AND_PUSH_WF:-$REPO_ROOT/.github/workflows/build-and-push.yml}"

fail() { printf '::error::%s\n' "$1" >&2; exit 1; }

[ -f "$WF" ] || fail "workflow not found: $WF"

# Top-level concurrency block: from the `concurrency:` line at column 0 to the
# next line that starts at column 0. Job-level blocks are indented and so are
# never captured here.
block=$(awk '
  /^concurrency:[[:space:]]*$/ { inblock = 1; next }
  inblock && /^[^[:space:]#]/  { exit }
  inblock                       { print }
' "$WF")

[ -n "$block" ] || fail "no top-level concurrency block in $WF"

group=$(printf '%s\n' "$block" | grep -E '^[[:space:]]+group:' || true)
cancel=$(printf '%s\n' "$block" | grep -E '^[[:space:]]+cancel-in-progress:' || true)

[ -n "$group" ]  || fail "concurrency block has no group:"
[ -n "$cancel" ] || fail "concurrency block has no cancel-in-progress:"

case "$group" in
  *correlation_id*) ;;
  *) fail "concurrency group does not mention correlation_id, so a pipeline-dispatched build shares a lane with ad-hoc dispatches and can be cancelled by one. See the comment above the concurrency block in build-and-push.yml." ;;
esac

case "$cancel" in
  *correlation_id*) ;;
  *) fail "cancel-in-progress does not exclude correlation_id dispatches, so an unrelated manual deploy can cancel a build a parent pipeline is blocking on. See the comment above the concurrency block in build-and-push.yml." ;;
esac

echo "OK: dispatches carrying a correlation_id are isolated from ad-hoc cancellation"
