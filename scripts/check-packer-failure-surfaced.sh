#!/usr/bin/env bash
# check-packer-failure-surfaced.sh
# ----------------------------------------------------------------------------
# Fence the `notify`-job wiring in build-and-push.yml so a failing
# `Packer Build AMI` can never go silent again (issue #2252).
#
# Failure mode this guards: on a push to main, a packer bake failure skips
# `Terraform Pre-Deploy Checks` (which is gated on packer success-or-skip),
# which skips `deploy-sandbox-infra`, which leaves SANDBOX_DEPLOYED=false. The
# notify job then falls into its `"$BUILD_RESULT" == "success"` branch and
# renders a GREEN "NHP Build successful" — masking the bake failure. That is
# exactly how the #2239 AC-AMI bug reddened every main run for ~12h with no
# Slack alert and silently blocked the prod promote preflight (see PR #2251).
#
# packer-build is intentionally not a required status check (it's skipped on
# the PR path), so the only signal for a post-merge bake failure is the notify
# Slack message. This lint pins the three pieces of wiring that make that
# signal exist:
#
#   A1. packer-build is in the notify job's `needs:`        (result available)
#   A2. PACKER_RESULT is forwarded from needs.packer-build.result (Slack env)
#   A3. the status logic forces a failure when PACKER_RESULT == "failure"
#       (otherwise a bake failure with a green build renders green)
#   A4. that PACKER_RESULT == "failure" branch is evaluated BEFORE the
#       BUILD_RESULT == "success" branch (the #2252 regression is an *ordering*
#       bug; A3 alone — existence — wouldn't catch a reorder)
#
# Detection is string-grep based, scoped to the notify job block, so it stays
# runnable without a YAML parser. NOTE: A3/A4 pin the *canonical* shell form
# (`"$PACKER_RESULT" == "failure"`); a behavior-preserving rewrite — single
# brackets, `= "failure"`, reordered operands, a `case` — would trip a false
# positive. That's intended (the fence pins one form); if you deliberately
# reshape that branch, update these patterns in lockstep. The fixture test
# alongside (tests/scripts/check-packer-failure-surfaced_test.sh) covers the
# extractor and each assertion with a paired bad fixture.
#
# Usage:
#   ./scripts/check-packer-failure-surfaced.sh                 → exit 0 ok, 1 drift
#   BUILD_AND_PUSH_WF=/path/to/fixture.yml ./scripts/check-packer-failure-surfaced.sh
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Reads exactly one file: build-and-push.yml. It lives under the broad
# `.github/workflows/**` entry already in validate-workflows.yml's trigger
# paths, so this lint re-fires on any edit to it (no per-file --list-sources
# contract needed, unlike check-asp-and-ac-id-lockstep.sh which reads many
# individually-listed sources). BUILD_AND_PUSH_WF lets the fixture test point
# at a synthetic workflow.
WF="${BUILD_AND_PUSH_WF:-$REPO_ROOT/.github/workflows/build-and-push.yml}"

if [ ! -f "$WF" ]; then
  echo "check-packer-failure-surfaced: workflow not found: $WF" >&2
  exit 1
fi

# Extract the `notify:` job block: from the `^  notify:` key to the next
# 2-space top-level job key (or EOF). Scoping A1 to this block matters —
# `- packer-build` also appears in other jobs' needs (e.g. Terraform
# Pre-Deploy Checks), so a whole-file grep would pass even if notify drops it.
notify_block="$(awk '
  /^  notify:[[:space:]]*$/ { inblk = 1; print; next }
  inblk && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { inblk = 0 }
  inblk { print }
' "$WF")"

if [ -z "$notify_block" ]; then
  echo "check-packer-failure-surfaced: could not locate the 'notify:' job in $WF" >&2
  exit 1
fi

fail=0
need() { # need <egrep-pattern> <human message>
  if ! printf '%s\n' "$notify_block" | grep -qE "$1"; then
    printf '  \033[31m✗\033[0m %s\n' "$2" >&2
    fail=1
  fi
}

# A1: packer-build in notify.needs
need '^[[:space:]]*-[[:space:]]+packer-build([[:space:]]|$)' \
  "notify job is missing 'packer-build' in its needs: — a packer bake failure won't reach the Slack step (#2252)"

# A2: PACKER_RESULT forwarded from the matrix-aggregated result
need 'PACKER_RESULT:[[:space:]]*\$\{\{[[:space:]]*needs\.packer-build\.result' \
  "notify job does not forward PACKER_RESULT from needs.packer-build.result"

# A3: status logic forces a failure/red message on a packer failure.
# shellcheck disable=SC2016  # literal grep pattern; the '$' must NOT expand
need '"\$PACKER_RESULT"[[:space:]]*==[[:space:]]*"failure"' \
  "notify job does not treat PACKER_RESULT==failure as a failure — a packer bake failure would render a green message"

# A4: the packer-failure branch must be evaluated BEFORE the build-success
# branch. This is the load-bearing ordering: on a main push, build succeeds in
# parallel while a bake failure cascades into a skipped deploy, so if the
# build-success branch wins first the message renders green — the exact #2252
# regression. A3 only proves the branch exists; A4 proves it runs first, so a
# refactor that moved the packer check below the build-success elif (which slips
# past A3) is caught here. (Skipped if either line is absent — A3 covers a
# missing packer branch.)
# `|| true`: under this script's `set -euo pipefail`, a no-match `grep -n`
# returns non-zero and the pipefail'd substitution would trip errexit *here* —
# aborting before the `-n` guards and the final FAIL summary below, defeating
# the documented graceful-skip. Tolerate the empty capture so the guards run.
# shellcheck disable=SC2016  # literal grep patterns; '$' must NOT expand
pk_line=$(printf '%s\n' "$notify_block" | grep -nE '"\$PACKER_RESULT"[[:space:]]*==[[:space:]]*"failure"' | head -1 | cut -d: -f1) || true
# shellcheck disable=SC2016
bd_line=$(printf '%s\n' "$notify_block" | grep -nE '"\$BUILD_RESULT"[[:space:]]*==[[:space:]]*"success"' | head -1 | cut -d: -f1) || true
if [ -n "$pk_line" ] && [ -n "$bd_line" ] && [ "$pk_line" -ge "$bd_line" ]; then
  printf '  \033[31m✗\033[0m %s\n' "notify job checks PACKER_RESULT==failure (line $pk_line) at/after BUILD_RESULT==success (line $bd_line) — a bake failure with a green build would still render green; the packer branch must be evaluated first (#2252)" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "check-packer-failure-surfaced: FAIL — a Packer Build AMI failure could go silent. See issue #2252 / PR #2251." >&2
  exit 1
fi

echo "check-packer-failure-surfaced: OK — packer-build failures are surfaced in the notify job."
