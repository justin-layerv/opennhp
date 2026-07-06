#!/usr/bin/env bash
# check-app-image-line-rendered.sh
# ----------------------------------------------------------------------------
# Fence the "App image" line in build-and-push.yml's `notify` job so a re-roll
# of the existing image can never silently masquerade as a fresh code ship
# (issue #2264).
#
# Sibling of check-packer-failure-surfaced.sh, but a DIFFERENT invariant family:
# that fence guards "a failure must surface" (A1-A5 — never render green on a
# failed bake / smoke). This one guards "a success must be labeled accurately" —
# the notify message must say whether the deploy shipped a newly-built binary
# (`rebuilt → <sha>`), re-rolled the existing one (`unchanged …`), or couldn't
# tell (`rebuild status unknown …`). Without that distinction a terraform/config/
# CI-only deploy looks identical to shipping the commit's code, which is exactly
# how a stale binary can look "live" for days (the freeze this line was added to
# break). PR #2263 added the line; its three-way rendering shipped untested.
#
# The logic lives in the notify job's `run:` block:
#
#   APP_IMAGE=""
#   if [[ "$SANDBOX_DEPLOYED" == "true" ]]; then
#     if   [[ "$APP_REBUILT" == "true"  ]]; then APP_IMAGE="rebuilt → \`<sha>\`"
#     elif [[ "$APP_REBUILT" == "false" ]]; then APP_IMAGE="unchanged — …"
#     else                                       APP_IMAGE="rebuild status unknown — …"
#     fi
#   fi
#   ...
#   if [[ -n "$APP_IMAGE" ]]; then  # renders the *App image:* Slack block
#
# This is value-mapping, NOT ordering: the three branches test distinct values
# of one variable (APP_REBUILT), so unlike A4/A5 the order is irrelevant to
# correctness — there is intentionally no need_order assertion here. What breaks
# the line is a branch/string deleted or gutted, the sha (or its source wiring)
# dropped, the APP_REBUILT input wiring pruned, or the render block detached from
# its gate. This lint pins each:
#
#   C1.  `app-image-build-required` ∈ notify.needs (APP_REBUILT's source job)
#   C2.  APP_REBUILT consumes
#        needs.app-image-build-required.outputs.app_image_build_required
#   C4.  `setup` ∈ notify.needs              (IMAGE_TAG's source job)
#   C5.  IMAGE_TAG forwarded from needs.setup.outputs.image_tag (else the rebuilt
#        branch's short sha resolves to empty backticks)
#   C6.  the rebuilt branch condition  "$APP_REBUILT" == "true"
#   C7.  the rebuilt branch carries the short sha  ${IMAGE_TAG:0:7}  (else a
#        "rebuilt →" with no tag — useless; its source is pinned by C4/C5)
#   C8.  the unchanged branch condition  "$APP_REBUILT" == "false"
#   C9.  the unchanged branch emits an APP_IMAGE string containing the
#        distinguishing token `unchanged`
#   C10. the unknown/fallback branch (the `else`) emits an APP_IMAGE string
#        containing the distinguishing token `unknown`
#   C11. the whole computation is gated on "$SANDBOX_DEPLOYED" == "true", tied to
#        the APP_IMAGE="" initializer (else the line renders on build-only runs)
#   C12. the *App image:* Slack block is present AND tied to its `-n "$APP_IMAGE"`
#        render gate (else the computed line never reaches Slack, or an empty
#        "App image:" renders on no-deploy runs)
#
# C11/C12 are proximity checks (need_window): a bare "both strings exist
# somewhere" can't tell that the gate still guards the thing it's supposed to
# guard. Pinning the anchor→target window catches a detached gate that two
# existence greps miss.
#
# Detection is string-grep based, scoped to the notify job block, so it stays
# runnable without a YAML parser. NOTE: C5/C7 pin the *canonical* shell form
# (`"$APP_REBUILT" == "true"`/`"false"`), and C8/C9 pin only the distinguishing
# token (`unchanged`/`unknown`) inside the APP_IMAGE assignment — robust to
# rewording the surrounding Slack prose, but a change to that token itself (or a
# branch-condition rewrite: single brackets, a `case`) trips the fence. That's
# intended: the token is what makes a re-roll distinguishable from a fresh ship,
# so it IS the invariant; if you change it (or reshape a branch condition),
# update these patterns in lockstep. Likewise C1/C4 pin the multi-line
# block-list `needs:` form the notify job uses today; a refactor to the flow
# form (`needs: [app-image-build-required, setup]`) would false-fail and must update them in
# lockstep (the sibling packer fence pins `- packer-build` the same way). The
# fixture test alongside
# (tests/scripts/check-app-image-line-rendered_test.sh) covers the extractor and
# each assertion with a paired bad fixture.
#
# Usage:
#   ./scripts/check-app-image-line-rendered.sh                 → exit 0 ok, 1 drift
#   BUILD_AND_PUSH_WF=/path/to/fixture.yml ./scripts/check-app-image-line-rendered.sh
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Reads exactly one file: build-and-push.yml. It lives under the broad
# `.github/workflows/**` entry already in validate-workflows.yml's trigger
# paths, so this lint re-fires on any edit to it. BUILD_AND_PUSH_WF lets the
# fixture test point at a synthetic workflow.
WF="${BUILD_AND_PUSH_WF:-$REPO_ROOT/.github/workflows/build-and-push.yml}"

if [ ! -f "$WF" ]; then
  echo "check-app-image-line-rendered: workflow not found: $WF" >&2
  exit 1
fi

# Extract the `notify:` job block: from the `^  notify:` key to the next 2-space
# top-level job key (or EOF). Scoping to this block matters — `- changes` and
# `SANDBOX_DEPLOYED == "true"` also appear in other jobs / elsewhere, so a
# whole-file grep could pass even if the notify rendering is gutted. Mirrors the
# extractor in check-packer-failure-surfaced.sh.
notify_block="$(awk '
  /^  notify:[[:space:]]*$/ { inblk = 1; print; next }
  inblk && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { inblk = 0 }
  inblk { print }
' "$WF")"

if [ -z "$notify_block" ]; then
  echo "check-app-image-line-rendered: could not locate the 'notify:' job in $WF" >&2
  exit 1
fi

fail=0
# `-e` lets a pattern that begins with `-` through without grep parsing it as an
# option flag — defensive, since need()/need_window() take arbitrary
# caller-supplied patterns.
need() { # need <egrep-pattern> <human message>
  if ! grep -qE -e "$1" <<<"$notify_block"; then
    printf '  \033[31m✗\033[0m %s\n' "$2" >&2
    fail=1
  fi
}

# need_window — fail when <target> is not found within <gap> lines AT/AFTER the
# first <anchor> match (or when <anchor> is absent). Ties a gate/initializer to
# the thing it guards: a bare "both strings exist somewhere in the block" can't
# tell that the gate was detached from (or the guarded block deleted out from
# under) it. `head -1` takes the first anchor; `|| true` tolerates grep's
# `grep -m 1` takes the first anchor without piping into `head`; that avoids a
# GNU grep/pipefail false negative when the real notify block is large.
need_window() { # need_window <anchor-egrep> <gap> <target-egrep> <human message>
  local anchor="$1" gap="$2" target="$3" msg="$4" aline anchor_match slice
  anchor_match=$(grep -nE -m 1 -e "$anchor" <<<"$notify_block" || true)
  aline="${anchor_match%%:*}"
  if [ -z "$aline" ]; then
    printf '  \033[31m✗\033[0m %s (anchor not found)\n' "$msg" >&2
    fail=1
    return
  fi
  slice=$(awk -v s="$aline" -v g="$gap" 'NR>=s && NR<=s+g' <<<"$notify_block")
  if ! grep -qE -e "$target" <<<"$slice"; then
    printf '  \033[31m✗\033[0m %s (not found within %s lines of its anchor)\n' "$msg" "$gap" >&2
    fail=1
  fi
}

# C1: the shared classifier job is in notify.needs (source of APP_REBUILT).
need '^[[:space:]]*-[[:space:]]+app-image-build-required([[:space:]]|$)' \
  "notify job is missing 'app-image-build-required' in its needs: — APP_REBUILT can't resolve, so the App-image line is always 'unknown' (#2264)"

# C2: APP_REBUILT consumes the shared classifier output.
need 'APP_REBUILT:[[:space:]]*\$\{\{[[:space:]]*needs\.app-image-build-required\.outputs\.app_image_build_required' \
  "notify job does not consume app-image-build-required.outputs.app_image_build_required — the App-image line would not reflect rebuilt/unchanged state"

# C4: the `setup` job is in notify.needs (source of IMAGE_TAG).
need '^[[:space:]]*-[[:space:]]+setup([[:space:]]|$)' \
  "notify job is missing 'setup' in its needs: — IMAGE_TAG can't resolve, so the rebuilt branch's short sha is empty (#2264)"

# C5: IMAGE_TAG forwarded from needs.setup.outputs.image_tag (the source the
# rebuilt branch's ${IMAGE_TAG:0:7} below depends on; without it C6's sha is
# present in the code but resolves to empty backticks at runtime).
need 'IMAGE_TAG:[[:space:]]*\$\{\{[[:space:]]*needs\.setup\.outputs\.image_tag' \
  "notify job does not forward IMAGE_TAG from needs.setup.outputs.image_tag — the rebuilt branch would render an empty short sha"

# C6: the rebuilt branch condition.
# shellcheck disable=SC2016  # literal grep pattern; the '$' must NOT expand
need '"\$APP_REBUILT"[[:space:]]*==[[:space:]]*"true"' \
  "notify job is missing the APP_REBUILT==true branch — a fresh app-image ship would not be labeled 'rebuilt'"

# C7: the rebuilt branch carries the short sha (a bare "rebuilt →" is useless).
# shellcheck disable=SC2016  # literal grep pattern; the '$' must NOT expand
need 'APP_IMAGE=.*\$\{IMAGE_TAG:0:7\}' \
  "notify job's rebuilt branch dropped the \${IMAGE_TAG:0:7} short sha — 'rebuilt' would render without the shipped tag"

# C8: the unchanged branch condition.
# shellcheck disable=SC2016  # literal grep pattern; the '$' must NOT expand
need '"\$APP_REBUILT"[[:space:]]*==[[:space:]]*"false"' \
  "notify job is missing the APP_REBUILT==false branch — a re-roll would not be labeled 'unchanged'"

# C9: the unchanged branch emits an APP_IMAGE string carrying the `unchanged`
# token. Pinned within the APP_IMAGE assignment (not bare) and as a token (not
# the full prose) so rewording the rest of the message doesn't false-fail.
need 'APP_IMAGE=.*unchanged' \
  "notify job's unchanged branch no longer sets an 'unchanged' APP_IMAGE string — a re-roll could masquerade as a fresh ship (#2264)"

# C10: the unknown/fallback branch (the `else`) emits an APP_IMAGE string carrying
# the `unknown` token. Must stay anchored to APP_IMAGE= — bare `unknown` also
# appears in the unrelated DURATION="unknown" logic in this same block.
need 'APP_IMAGE=.*unknown' \
  "notify job's fallback branch no longer sets an 'unknown' APP_IMAGE string — an unreported rebuild status would render wrong or empty"

# C11: the computation is gated on SANDBOX_DEPLOYED==true, tied to the
# APP_IMAGE="" initializer so the gate can't be detached and leave the line
# rendering on build-only runs (where no deploy happened). gap=6 gives an
# inserted comment or two between the initializer and the gate some slack (the
# real distance is 1) while staying well short of the next SANDBOX_DEPLOYED gate
# (~50 lines later at the render block), so it can't latch onto the wrong one.
# shellcheck disable=SC2016  # literal grep patterns; the '$' must NOT expand
need_window 'APP_IMAGE=""' 6 '"\$SANDBOX_DEPLOYED"[[:space:]]*==[[:space:]]*"true"' \
  "notify job's App-image computation is not gated on SANDBOX_DEPLOYED==true — it would render on build-only runs that never deployed"

# C12: the *App image:* Slack block is present AND tied to its `-n "$APP_IMAGE"`
# render gate, so the computed line actually reaches Slack and an empty line
# can't render on a no-deploy run. gap=14 vs a real distance of 6: this Slack
# `section` block is the part most likely to grow (added fields), and unlike
# C10 the target `*App image:*` is unique in the block, so a wider window can't
# latch the wrong line — it only adds edit-resilience.
# shellcheck disable=SC2016  # literal grep patterns; the '$' must NOT expand
need_window '\[\[[[:space:]]+-n[[:space:]]+"\$APP_IMAGE"' 14 '\*App image:\*' \
  "notify job's *App image:* Slack block is missing or detached from its -n \"\$APP_IMAGE\" render gate — the computed line never reaches Slack (#2264)"

if [ "$fail" -ne 0 ]; then
  echo "check-app-image-line-rendered: FAIL — the notify App-image line could mislabel a deploy. See issue #2264 / PR #2263." >&2
  exit 1
fi

echo "check-app-image-line-rendered: OK — the notify App-image line rendering is intact."
