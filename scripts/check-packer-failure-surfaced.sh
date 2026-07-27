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
#   A5. the DEPLOY_FAILED == "true" branch is evaluated BEFORE the
#       SANDBOX_VALIDATE == "success" branch. Same class of ordering bug as A4:
#       a green validate must not mask a failed/cancelled smoke or blue/green
#       and render a green "successful" deploy. (Skipped if either line is
#       absent, mirroring A4.)
#   A6. a *cancelled* packer leg is classified as a preempted run and reported
#       BEFORE the BUILD_RESULT == "success" branch. A cancelled leg cascades
#       identically to a failed one — terraform-plan is gated on packer
#       success-or-skip, so the whole sandbox deploy chain skips — but A3/A4
#       only pin the "failure" arm, so a cancelled leg fell through to
#       BUILD_RESULT=="success" and rendered a green "NHP Build successful" for
#       a run that deployed nothing. That is not hypothetical: the shared
#       `packer-build-<env>` concurrency group used to cancel the pending packer
#       leg of every run in a merge burst (GitHub keeps one pending job per
#       group), so this fired on 7 consecutive main runs on 2026-07-27.
#
#       Cancellation is a run-level property, not a packer one — the sandbox
#       infra/qURL/relay deploys hold shared groups too and preempt the same
#       way — so notify folds them all into one PREEMPTED_LEG determination.
#       A6 therefore checks two things: PACKER_RESULT=="cancelled" is still
#       examined (packer feeds that determination), and the PREEMPTED_LEG arms
#       run before the green branch can win. The order half is anchored on the
#       `elif` form so it pins the *status-branch* arm, not the earlier
#       bookkeeping blocks that compute the superseded-run lookup.
#
#   A7. fences the other half of the same bug — the packer-build job's own
#       concurrency group, which decides whether a cancellation happens at all.
#       The group expression must test for the literal 'false' (→ per-run group)
#       and fall through to the SHARED group. This is a polarity assertion, and
#       polarity is the one thing actionlint cannot check: `== 'true'` is
#       equally valid YAML and equally green, but inverts the failure
#       direction. Written that way round, any wiring breakage — the output
#       renamed, a paths-filter upgrade emitting `True`/`1`, a typo — silently
#       degrades to per-run groups and drops the SSM-overwrite protection the
#       shared group exists to provide, with nothing anywhere to signal it.
#       Tested against 'false', those same breakages degrade to "serialize
#       every run": no lost race, and self-announcing, since the preemption it
#       causes now posts the A6 "superseded" message. A7 keeps the safe
#       polarity from being "simplified" back to the obvious one.
#
#       A7 also subsumes the `changes`-in-needs check it replaced: if the
#       reference survives, actionlint rejects an undeclared `needs.changes`
#       (same validate-workflows job, earlier step); if it does not survive,
#       A7's own pattern stops matching. There is no third case.
#
# Detection is string-grep based, scoped to the notify job block (A1–A6) and the
# packer-build job block (A7), so it stays runnable without a YAML parser.
#
# NOTE: A3/A4/A5 pin the *canonical* shell form
# (`"$PACKER_RESULT" == "failure"`, `"$DEPLOY_FAILED" == "true"`,
# `"$SANDBOX_VALIDATE" == "success"`); a behavior-preserving rewrite — single
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

# Same extractor, pointed at the packer-build job (A7/A8). Scoping matters for
# the same reason it does for notify: `concurrency:` and `needs:` blocks appear
# in most jobs in this workflow, so a whole-file grep would happily match some
# other job's wiring and pass while packer-build's was broken.
packer_block="$(awk '
  /^  packer-build:[[:space:]]*$/ { inblk = 1; print; next }
  inblk && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { inblk = 0 }
  inblk { print }
' "$WF")"

if [ -z "$packer_block" ]; then
  echo "check-packer-failure-surfaced: could not locate the 'packer-build:' job in $WF" >&2
  exit 1
fi

fail=0
need_in() { # need_in <block> <egrep-pattern> <human message>
  # Capture-then-test, not `printf '%s\n' "$block" | grep -qE`: a
  # drained `grep -E` (no -q) can't close the pipe early, so the printf
  # builtin never hits EPIPE mid-write and gets flipped from a match into a
  # spurious miss under pipefail (full derivation in
  # tests/lints/packer-failure-surfaced/run-fixtures.sh; same convention as
  # check-base-image-pebble-purge.sh). `|| true` absorbs grep's no-match
  # exit under errexit. (need_order below is already safe: it captures into
  # a var with a trailing `|| true`, so grep's status never gates a branch.)
  # One semantic delta from grep -qE: a pattern whose only match is a blank
  # line reads as a miss here (captured output is empty) — the A1-A8 wiring
  # patterns all match non-empty content, so that edge never bites.
  local hit
  hit=$(printf '%s\n' "$1" | grep -E "$2" || true)
  if [ -z "$hit" ]; then
    printf '  \033[31m✗\033[0m %s\n' "$3" >&2
    fail=1
  fi
}

# need — need_in against $notify_block, which is most of the assertions here.
# One body, so the SIGPIPE-safe form above can't drift between the two.
need() { # need <egrep-pattern> <human message>
  need_in "$notify_block" "$1" "$2"
}

# need_order — fail when <first-pattern> is evaluated AT/AFTER <second-pattern>
# in the notify block; the first branch must come first. Both patterns absent
# -> skip (graceful; a missing branch is covered by the existence `need` checks).
# The `|| true` tolerates grep's no-match exit under `set -euo pipefail` so the
# `-n` guards run instead of errexit aborting before the FAIL summary below.
#
# `head -1` takes the FIRST match, so callers must pass patterns that target the
# canonical branch-condition form `"$VAR" == "value"`. The other shapes of the
# same vars in the notify block are deliberately NOT matched and so don't shift
# the captured line: the `DEPLOY_FAILED="true"` assignment (no `==`) and the
# `for result in … ; [[ "$result" == "failure" ]]` loop (matches $result, not
# $SANDBOX_VALIDATE). If a future edit adds an earlier `[[ "$VAR" == "value" ]]`
# for that same var, revisit these patterns — head -1 would then capture it.
need_order() { # need_order <first-egrep> <second-egrep> <human message>
  local first="$1" second="$2" msg="$3" l1 l2
  l1=$(printf '%s\n' "$notify_block" | grep -nE "$first" | head -1 | cut -d: -f1) || true
  l2=$(printf '%s\n' "$notify_block" | grep -nE "$second" | head -1 | cut -d: -f1) || true
  if [ -n "$l1" ] && [ -n "$l2" ] && [ "$l1" -ge "$l2" ]; then
    printf '  \033[31m✗\033[0m %s (first branch line %s, second branch line %s)\n' "$msg" "$l1" "$l2" >&2
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
# branch — the load-bearing #2252 ordering. On a main push, build succeeds in
# parallel while a bake failure cascades into a skipped deploy; if build-success
# wins first the message renders green. A3 proves the branch exists; A4 proves
# it runs first (a reorder that slips past A3 is caught here).
# shellcheck disable=SC2016  # literal grep patterns; '$' must NOT expand
need_order '"\$PACKER_RESULT"[[:space:]]*==[[:space:]]*"failure"' \
  '"\$BUILD_RESULT"[[:space:]]*==[[:space:]]*"success"' \
  "notify job checks PACKER_RESULT==failure at/after BUILD_RESULT==success — a bake failure with a green build would still render green; the packer branch must be evaluated first (#2252)"

# A5: the deploy-failure branch must be evaluated BEFORE the validate-success
# branch — same class as A4, one level down. Inside the build-success branch a
# green SANDBOX_VALIDATE must not win ahead of DEPLOY_FAILED, or a failed/
# cancelled smoke or blue/green renders a green "successful" deploy.
# shellcheck disable=SC2016  # literal grep patterns; '$' must NOT expand
need_order '"\$DEPLOY_FAILED"[[:space:]]*==[[:space:]]*"true"' \
  '"\$SANDBOX_VALIDATE"[[:space:]]*==[[:space:]]*"success"' \
  "notify job checks DEPLOY_FAILED==true at/after SANDBOX_VALIDATE==success — a green validate would mask a failed/cancelled smoke or blue/green and render green; the deploy-failure branch must be evaluated first"

# A6: a cancelled packer leg must feed the preempted-run determination, and
# that determination must be reported before the build-success branch. Same
# cascade as a failure (terraform-plan is gated on packer success-or-skip → the
# deploy chain skips), so the same green-message masking applies; A3/A4 only
# cover the "failure" arm.
# shellcheck disable=SC2016  # literal grep pattern; the '$' must NOT expand
need '"\$PACKER_RESULT"[[:space:]]*==[[:space:]]*"cancelled"' \
  "notify job does not examine PACKER_RESULT==cancelled — a preempted packer leg skips the whole deploy chain and would render a green 'NHP Build successful'"

# The `elif`-anchored pattern targets the status-branch arm specifically. The
# bookkeeping blocks above it (superseded-run lookup, Packer field text) also
# test PREEMPTED_LEG but open with `if`, so head -1 would otherwise capture one
# of those and the ordering check would prove nothing.
# shellcheck disable=SC2016  # literal grep patterns; '$' must NOT expand
need_order 'elif[[:space:]]+\[\[[[:space:]]*-n[[:space:]]+"\$PREEMPTED_LEG"' \
  '"\$BUILD_RESULT"[[:space:]]*==[[:space:]]*"success"' \
  "notify job checks PREEMPTED_LEG at/after BUILD_RESULT==success — a preempted run with a green build would still render green; the preempted branch must be evaluated first"

# A7: fail-closed polarity — see the header for why this is the assertion that
# actionlint structurally cannot make.
need_in "$packer_block" \
  "group:.*needs\.changes\.outputs\.packer[[:space:]]*==[[:space:]]*'false'" \
  "packer-build's concurrency group is not conditioned on needs.changes.outputs.packer == 'false' — the fail-closed polarity is load-bearing: any other form (notably == 'true') makes a broken wire degrade to per-run groups and silently lose AMI-bake serialization"

if [ "$fail" -ne 0 ]; then
  echo "check-packer-failure-surfaced: FAIL — a Packer Build AMI failure could go silent. See issue #2252 / PR #2251." >&2
  exit 1
fi

echo "check-packer-failure-surfaced: OK — packer-build failures are surfaced in the notify job."
