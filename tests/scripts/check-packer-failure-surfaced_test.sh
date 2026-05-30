#!/usr/bin/env bash
# check-packer-failure-surfaced_test.sh — fixture tests for
# scripts/check-packer-failure-surfaced.sh
# ----------------------------------------------------------------------------
# Builds synthetic build-and-push.yml workflows in a tempdir, points the lint
# at each via BUILD_AND_PUSH_WF, and asserts exit code. Covers the notify-block
# extractor and each of the three assertions with a paired bad fixture, plus a
# scope fixture proving A1 is checked *inside* the notify job (not file-wide,
# where `- packer-build` appears in other jobs' needs). The final case runs the
# lint against the real repo tree, so this one invocation both unit-tests the
# detector and enforces the wiring on the actual workflow.
#
# Usage: bash tests/scripts/check-packer-failure-surfaced_test.sh
# ============================================================================

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-packer-failure-surfaced.sh"

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
# Flags ("1" includes the piece, anything else omits it; $3 is an enum):
#   $1 needs_packer   — `- packer-build` in notify.needs
#   $2 env_packer     — PACKER_RESULT env forwarded
#   $3 logic_packer   — status branch: ok=packer checked before build-success,
#                       after=packer checked after build-success (wrong order),
#                       missing=no packer branch
#   $4 decoy_needs    — a separate job BEFORE notify whose needs lists
#                       packer-build (tests the extractor's start boundary)
#   $5 include_notify — emit the notify job at all
#   $6 trailing_decoy — a job AFTER notify whose needs lists packer-build
#                       (tests the extractor's end boundary — notify isn't last)
make_wf() {
  local needs_packer="$1" env_packer="$2" logic_packer="$3" decoy_needs="$4" include_notify="$5" trailing_decoy="${6:-0}"
  local f="$TMP/wf_${needs_packer}${env_packer}${logic_packer}${decoy_needs}${include_notify}${trailing_decoy}_$RANDOM.yml"
  {
    echo "name: Build and Deploy NHP"
    echo "on:"
    echo "  push:"
    echo "    branches: [ main ]"
    echo "jobs:"
    echo "  packer-build:"
    echo "    name: Packer Build AMI"
    echo "    steps:"
    echo "      - run: echo bake"
    if [ "$decoy_needs" = "1" ]; then
      # A different job that legitimately depends on packer-build. The lint
      # must NOT count this toward A1 — only notify.needs counts.
      echo "  terraform-pre-deploy:"
      echo "    name: Terraform Pre-Deploy Checks"
      echo "    needs:"
      echo "      - packer-build"
      echo "    steps:"
      echo "      - run: echo plan"
    fi
    if [ "$include_notify" = "1" ]; then
      echo "  notify:"
      echo "    name: Notify"
      echo "    needs:"
      echo "      - build"
      [ "$needs_packer" = "1" ] && echo "      - packer-build"
      echo "      - deploy-sandbox-infra"
      echo "    steps:"
      echo "      - name: Notify Slack"
      echo "        env:"
      echo "          BUILD_RESULT: \${{ needs.build.result }}"
      [ "$env_packer" = "1" ] && echo "          PACKER_RESULT: \${{ needs.packer-build.result }}"
      echo "        run: |"
      case "$logic_packer" in
        ok)
          # Correct: packer-failure checked BEFORE build-success.
          echo "          if [[ \"\$PACKER_RESULT\" == \"failure\" ]]; then"
          echo "            COLOR=\"#dc3545\""
          echo "          elif [[ \"\$BUILD_RESULT\" == \"success\" ]]; then"
          echo "            COLOR=\"#36a64f\""
          echo "          fi"
          ;;
        after)
          # Wrong order: build-success wins first, so a packer failure with a
          # green build renders green — the exact #2252 regression. The packer
          # branch still EXISTS (A3 passes); only A4's ordering check catches it.
          echo "          if [[ \"\$BUILD_RESULT\" == \"success\" ]]; then"
          echo "            COLOR=\"#36a64f\""
          echo "          elif [[ \"\$PACKER_RESULT\" == \"failure\" ]]; then"
          echo "            COLOR=\"#dc3545\""
          echo "          fi"
          ;;
        *) # missing: no packer branch at all (A3 fails)
          echo "          if [[ \"\$BUILD_RESULT\" == \"success\" ]]; then"
          echo "            COLOR=\"#36a64f\""
          echo "          fi"
          ;;
      esac
    fi
    if [ "$trailing_decoy" = "1" ]; then
      # A job emitted AFTER notify whose needs lists packer-build. The awk
      # extractor must stop at this job's `^  key:$` line, so its needs must
      # NOT count toward A1 — i.e. notify is no longer the last job in the file.
      echo "  post-deploy-monitor:"
      echo "    name: Post Deploy Monitor"
      echo "    needs:"
      echo "      - packer-build"
      echo "    steps:"
      echo "      - run: echo monitor"
    fi
  } > "$f"
  printf '%s' "$f"
}

echo "check-packer-failure-surfaced fixtures:"

# Good: all three present, packer checked first -> exit 0
assert_exit "good: packer wired into needs + env + failure logic (correct order)" \
  "$(make_wf 1 1 ok 0 1)" 0

# A1 missing: packer-build absent from notify.needs -> exit 1
assert_exit "bad A1: packer-build dropped from notify.needs" \
  "$(make_wf 0 1 ok 0 1)" 1

# A1 scope: packer-build only in another job's needs, not notify's -> exit 1
assert_exit "bad A1 (scope): packer-build in a decoy job's needs, not notify's" \
  "$(make_wf 0 1 ok 1 1)" 1

# A2 missing: PACKER_RESULT not forwarded -> exit 1
assert_exit "bad A2: PACKER_RESULT env not forwarded" \
  "$(make_wf 1 0 ok 0 1)" 1

# A3 missing: no failure branch on PACKER_RESULT -> exit 1
assert_exit "bad A3: status logic ignores PACKER_RESULT==failure" \
  "$(make_wf 1 1 missing 0 1)" 1

# A4 wrong order: packer-failure checked AFTER build-success -> exit 1.
# Branch exists (A3 passes) but the ordering reintroduces the silent failure.
assert_exit "bad A4: PACKER_RESULT==failure checked after BUILD_RESULT==success" \
  "$(make_wf 1 1 after 0 1)" 1

# End boundary: notify is NOT the last job (a job follows it). A correct notify
# + a trailing job must still pass -> exit 0 (extractor stops at the trailing job).
assert_exit "good: notify followed by another job (extractor end-bounds correctly)" \
  "$(make_wf 1 1 ok 0 1 1)" 0

# End-boundary scope: packer-build only in a job AFTER notify, not notify's own
# needs -> exit 1 (the extractor must not leak the trailing job's needs into A1).
assert_exit "bad A1 (trailing scope): packer-build in a job after notify, not notify's" \
  "$(make_wf 0 1 ok 0 1 1)" 1

# No notify job at all -> exit 1 (could-not-locate)
assert_exit "bad: notify job entirely absent" \
  "$(make_wf 1 1 ok 0 0)" 1

# Real tree: the actual build-and-push.yml must already satisfy the lint
assert_exit "real tree: build-and-push.yml notify wiring is present" "" 0

echo
echo "  passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
