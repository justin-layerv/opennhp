#!/usr/bin/env bash
# check-app-image-line-rendered_test.sh — fixture tests for
# scripts/check-app-image-line-rendered.sh
# ----------------------------------------------------------------------------
# Builds synthetic build-and-push.yml workflows in a tempdir, points the lint
# at each via BUILD_AND_PUSH_WF, and asserts exit code. Covers the notify-block
# extractor and each of the eleven assertions (C1-C11) with a paired bad fixture
# that breaks exactly one piece, plus the notify-absent case. The final case
# runs the lint against the real repo tree, so this one invocation both
# unit-tests the detector and enforces the wiring on the actual workflow.
#
# Usage: bash tests/scripts/check-app-image-line-rendered_test.sh
# ============================================================================

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-app-image-line-rendered.sh"

pass=0
fail=0
report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# assert_exit <label> <fixture-file-or-empty-for-real> <expected-exit>
assert_exit() {
  local label="$1" wf="$2" want="$3" got
  if [ -n "$wf" ]; then
    BUILD_AND_PUSH_WF="$wf" bash "$SCRIPT" >/dev/null 2>&1
  else
    bash "$SCRIPT" >/dev/null 2>&1
  fi
  got=$?
  if [ "$got" -eq "$want" ]; then
    report_pass "$label"
  else
    report_fail "$label" "expected exit $want, got $got"
  fi
}

# ---- Fixture builder -------------------------------------------------------
# make_wf <variant> — emits a synthetic notify job that satisfies every
# assertion EXCEPT the one named by <variant> (which is broken in isolation):
#   good              — all assertions satisfied (exit 0)
#   no_needs_changes  — drop `- changes` from notify.needs            (C1)
#   no_env_rebuilt    — drop the APP_REBUILT env line                 (C2)
#   no_needs_setup    — drop `- setup` from notify.needs              (C3)
#   no_env_image_tag  — drop the IMAGE_TAG env line                   (C4)
#   no_rebuilt_cond   — rebuilt branch tests a different var          (C5)
#   no_rebuilt_sha    — rebuilt branch drops ${IMAGE_TAG:0:7}         (C6)
#   no_unchanged_cond — unchanged branch tests a different var        (C7)
#   no_unchanged_str  — unchanged branch sets a non-canonical string  (C8)
#   no_unknown_str    — fallback branch sets a non-canonical string   (C9)
#   no_outer_gate     — replace SANDBOX_DEPLOYED gate with `if true`  (C10)
#   no_render_gate    — render the block WITHOUT the `-n` gate        (C11 anchor)
#   no_render_block   — keep the gate but drop the *App image:* block (C11 target)
#   no_notify         — emit no notify job at all (could-not-locate)
make_wf() {
  local variant="$1"
  local f="$TMP/wf_${variant}_$RANDOM.yml"
  {
    echo "name: Build and Deploy NHP"
    echo "on:"
    echo "  push:"
    echo "    branches: [ main ]"
    echo "jobs:"
    echo "  changes:"
    echo "    name: Detect Changes"
    echo "    steps:"
    echo "      - run: echo detect"
    if [ "$variant" = "no_notify" ]; then
      # No notify job -> the lint's could-not-locate guard fires.
      echo "  build:"
      echo "    name: Build"
      echo "    steps:"
      echo "      - run: echo build"
    else
      echo "  notify:"
      echo "    name: Notify"
      echo "    needs:"
      echo "      - build"
      [ "$variant" != "no_needs_changes" ] && echo "      - changes"
      [ "$variant" != "no_needs_setup" ] && echo "      - setup"
      echo "      - deploy-sandbox-infra"
      echo "    steps:"
      echo "      - name: Notify Slack"
      echo "        env:"
      echo "          BUILD_RESULT: \${{ needs.build.result }}"
      [ "$variant" != "no_env_rebuilt" ] && echo "          APP_REBUILT: \${{ needs.changes.outputs.app }}"
      [ "$variant" != "no_env_image_tag" ] && echo "          IMAGE_TAG: \${{ needs.setup.outputs.image_tag }}"
      echo "        run: |"
      echo "          SANDBOX_DEPLOYED=\"true\""
      echo "          APP_IMAGE=\"\""
      # C10 outer gate (or a decoy `if true` that omits the SANDBOX_DEPLOYED==true form)
      if [ "$variant" = "no_outer_gate" ]; then
        echo "          if true; then"
      else
        echo "          if [[ \"\$SANDBOX_DEPLOYED\" == \"true\" ]]; then"
      fi
      # C5 rebuilt condition
      if [ "$variant" = "no_rebuilt_cond" ]; then
        echo "            if [[ \"\$SOMETHING_ELSE\" == \"true\" ]]; then"
      else
        echo "            if [[ \"\$APP_REBUILT\" == \"true\" ]]; then"
      fi
      # C6 rebuilt sha
      if [ "$variant" = "no_rebuilt_sha" ]; then
        echo "              APP_IMAGE=\"rebuilt (tag omitted)\""
      else
        echo "              APP_IMAGE=\"rebuilt → \\\`\${IMAGE_TAG:0:7}\\\`\""
      fi
      # C7 unchanged condition
      if [ "$variant" = "no_unchanged_cond" ]; then
        echo "            elif [[ \"\$ANOTHER_VAR\" == \"false\" ]]; then"
      else
        echo "            elif [[ \"\$APP_REBUILT\" == \"false\" ]]; then"
      fi
      # C8 unchanged string
      if [ "$variant" = "no_unchanged_str" ]; then
        echo "              APP_IMAGE=\"config-only deploy\""
      else
        echo "              APP_IMAGE=\"unchanged — infra/config only (app binary not rebuilt)\""
      fi
      echo "            else"
      # C9 unknown/fallback string
      if [ "$variant" = "no_unknown_str" ]; then
        echo "              APP_IMAGE=\"status not reported\""
      else
        echo "              APP_IMAGE=\"rebuild status unknown (changes job did not report)\""
      fi
      echo "            fi"
      echo "          fi"
      # C11 render gate + *App image:* block. no_render_gate drops the `-n`
      # anchor (block renders unconditionally); no_render_block keeps the gate
      # but detaches the *App image:* target; the canonical form has both.
      if [ "$variant" = "no_render_gate" ]; then
        echo "          BLOCKS=\"\$BLOCKS,{\\\"text\\\": \\\"*App image:* \$APP_IMAGE\\\"}\""
      else
        echo "          if [[ -n \"\$APP_IMAGE\" ]]; then"
        if [ "$variant" = "no_render_block" ]; then
          echo "            BLOCKS=\"\$BLOCKS,{\\\"text\\\": \\\"placeholder\\\"}\""
        else
          echo "            BLOCKS=\"\$BLOCKS,{\\\"text\\\": \\\"*App image:* \$APP_IMAGE\\\"}\""
        fi
        echo "          fi"
      fi
    fi
    # A trailing job after notify — exercises the extractor's end boundary
    # (notify is not the last job; its block must stop here).
    echo "  post-deploy-monitor:"
    echo "    name: Post Deploy Monitor"
    echo "    steps:"
    echo "      - run: echo monitor"
  } > "$f"
  printf '%s' "$f"
}

echo "check-app-image-line-rendered fixtures:"

# Good: every assertion satisfied -> exit 0
assert_exit "good: all App-image assertions satisfied" \
  "$(make_wf good)" 0

# C1: changes dropped from notify.needs -> exit 1
assert_exit "bad C1: 'changes' missing from notify.needs" \
  "$(make_wf no_needs_changes)" 1

# C2: APP_REBUILT env not forwarded -> exit 1
assert_exit "bad C2: APP_REBUILT env not forwarded from needs.changes.outputs.app" \
  "$(make_wf no_env_rebuilt)" 1

# C3: setup dropped from notify.needs -> exit 1
assert_exit "bad C3: 'setup' missing from notify.needs" \
  "$(make_wf no_needs_setup)" 1

# C4: IMAGE_TAG env not forwarded -> exit 1
assert_exit "bad C4: IMAGE_TAG env not forwarded from needs.setup.outputs.image_tag" \
  "$(make_wf no_env_image_tag)" 1

# C5: rebuilt branch tests a different var -> exit 1
assert_exit "bad C5: rebuilt branch no longer keys on APP_REBUILT==true" \
  "$(make_wf no_rebuilt_cond)" 1

# C6: rebuilt branch dropped the short sha -> exit 1
assert_exit "bad C6: rebuilt branch dropped \${IMAGE_TAG:0:7}" \
  "$(make_wf no_rebuilt_sha)" 1

# C7: unchanged branch tests a different var -> exit 1
assert_exit "bad C7: unchanged branch no longer keys on APP_REBUILT==false" \
  "$(make_wf no_unchanged_cond)" 1

# C8: unchanged branch's string gutted -> exit 1
assert_exit "bad C8: unchanged branch no longer sets the 'unchanged …' string" \
  "$(make_wf no_unchanged_str)" 1

# C9: fallback branch's string gutted -> exit 1
assert_exit "bad C9: fallback branch no longer sets 'rebuild status unknown …'" \
  "$(make_wf no_unknown_str)" 1

# C10: SANDBOX_DEPLOYED gate replaced with `if true` -> exit 1
assert_exit "bad C10: App-image computation not gated on SANDBOX_DEPLOYED==true" \
  "$(make_wf no_outer_gate)" 1

# C11 anchor: render gate removed (block renders unconditionally) -> exit 1
assert_exit "bad C11: *App image:* block detached from its -n \$APP_IMAGE gate" \
  "$(make_wf no_render_gate)" 1

# C11 target: gate present but *App image:* block gone -> exit 1
assert_exit "bad C11: -n \$APP_IMAGE gate present but *App image:* block missing" \
  "$(make_wf no_render_block)" 1

# No notify job at all -> exit 1 (could-not-locate)
assert_exit "bad: notify job entirely absent" \
  "$(make_wf no_notify)" 1

# Real tree: the actual build-and-push.yml must already satisfy the lint
assert_exit "real tree: build-and-push.yml App-image rendering is present" "" 0

echo
echo "  passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
