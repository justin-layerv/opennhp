#!/usr/bin/env bash
# check-packer-failure-surfaced_test.sh — fixture tests for
# scripts/check-packer-failure-surfaced.sh
# ----------------------------------------------------------------------------
# Builds synthetic build-and-push.yml workflows in a tempdir, points the lint
# at each via BUILD_AND_PUSH_WF, and asserts exit code. Covers the notify-block
# extractor and each of the lint's assertions with a paired bad fixture, plus a
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
#   $3 logic_packer   — status branch:
#                       ok=failure and cancelled both checked before
#                         build-success,
#                       after=failure checked after build-success (wrong A4
#                         order; the cancelled arm is kept as a leading plain
#                         `if` so A6's elif-anchored order check skips and A4 is
#                         the sole cause),
#                       missing=no packer branch at all (fails A3 *and* A6
#                         existence — both describe the same absent branch),
#                       nocancel=failure arm only, correctly ordered — the
#                         pre-fix shape, isolating A6 existence,
#                       cancelafter=cancelled arm placed after build-success,
#                         isolating A6 ordering
#   $4 decoy_needs    — a separate job BEFORE notify whose needs lists
#                       packer-build (tests the extractor's start boundary)
#   $5 include_notify — emit the notify job at all
#   $6 trailing_decoy — a job AFTER notify whose needs lists packer-build
#                       (tests the extractor's end boundary — notify isn't last)
make_wf() {
  local needs_packer="$1" env_packer="$2" logic_packer="$3" decoy_needs="$4" include_notify="$5" trailing_decoy="${6:-0}"
  # $7 logic_deploy — deploy-failure vs validate-success branch ordering (A5):
  #   ok=deploy-failure checked first, after=validate-success first (wrong),
  #   ''=omit the branch entirely (A5 skips). Defaults to omit so the
  #   packer-focused fixtures above are unaffected.
  local logic_deploy="${7:-}"
  # $8 packer_wiring — the packer-build job's own concurrency group (A7):
  #   ok=fail-closed `== 'false'` polarity,
  #   failopen=the group tests `== 'true'` — valid YAML, green actionlint, and
  #     a silent loss of AMI-bake serialization on any wiring breakage.
  local packer_wiring="${8:-ok}"
  local f="$TMP/wf_${needs_packer}${env_packer}${logic_packer}${decoy_needs}${include_notify}${trailing_decoy}${logic_deploy}${packer_wiring}_$RANDOM.yml"
  {
    echo "name: Build and Deploy NHP"
    echo "on:"
    echo "  push:"
    echo "    branches: [ main ]"
    echo "jobs:"
    echo "  packer-build:"
    echo "    name: Packer Build AMI"
    echo "    needs: [changes, setup]"
    echo "    concurrency:"
    if [ "$packer_wiring" = "failopen" ]; then
      echo "      group: \${{ needs.changes.outputs.packer == 'true' && format('packer-build-{0}', matrix.environment) || format('packer-build-{0}-{1}', matrix.environment, github.run_id) }}"
    else
      echo "      group: \${{ needs.changes.outputs.packer == 'false' && format('packer-build-{0}-{1}', matrix.environment, github.run_id) || format('packer-build-{0}', matrix.environment) }}"
    fi
    echo "      cancel-in-progress: false"
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
          # Correct: a cancelled packer leg feeds PREEMPTED_LEG, and both the
          # failure and preempted arms are checked BEFORE build-success.
          echo "          if [[ \"\$PACKER_RESULT\" == \"cancelled\" ]]; then"
          echo "            PREEMPTED_LEG=\"Packer AMI bake\""
          echo "          fi"
          echo "          if [[ \"\$PACKER_RESULT\" == \"failure\" ]]; then"
          echo "            COLOR=\"#dc3545\""
          echo "          elif [[ -n \"\$PREEMPTED_LEG\" ]]; then"
          echo "            COLOR=\"#6c757d\""
          echo "          elif [[ \"\$BUILD_RESULT\" == \"success\" ]]; then"
          echo "            COLOR=\"#36a64f\""
          echo "          fi"
          ;;
        after)
          # Wrong order: build-success wins first, so a packer failure with a
          # green build renders green — the exact #2252 regression. The packer
          # branch still EXISTS (A3 passes), and PREEMPTED_LEG is computed but
          # never branched on with an `elif`, so A6's ordering check has nothing
          # to match and skips — leaving A4 as the only assertion that fires.
          echo "          if [[ \"\$PACKER_RESULT\" == \"cancelled\" ]]; then"
          echo "            PREEMPTED_LEG=\"Packer AMI bake\""
          echo "          fi"
          echo "          if [[ \"\$BUILD_RESULT\" == \"success\" ]]; then"
          echo "            COLOR=\"#36a64f\""
          echo "          elif [[ \"\$PACKER_RESULT\" == \"failure\" ]]; then"
          echo "            COLOR=\"#dc3545\""
          echo "          fi"
          ;;
        nocancel)
          # The pre-fix shape: failure arm present and correctly ordered, but a
          # cancelled leg is never examined — so a preempted run falls through
          # to build-success and renders a green "NHP Build successful" for a
          # run that deployed nothing. A3/A4 both pass; only A6 existence fires.
          echo "          if [[ \"\$PACKER_RESULT\" == \"failure\" ]]; then"
          echo "            COLOR=\"#dc3545\""
          echo "          elif [[ \"\$BUILD_RESULT\" == \"success\" ]]; then"
          echo "            COLOR=\"#36a64f\""
          echo "          fi"
          ;;
        cancelafter)
          # Preempted arm exists but sits AFTER build-success, so it never runs
          # on a green build — same masking as `nocancel`, reached by a reorder
          # rather than a deletion. A6 existence passes; only A6 ordering fires.
          #
          # The plain-`if` PREEMPTED_LEG bookkeeping block below is load-bearing
          # for the test, not decoration: it sits BEFORE build-success, so
          # need_order's `head -1` would capture it — and the ordering check
          # would pass — if A6's pattern were not anchored on `elif`. This
          # fixture is what fails if someone "simplifies" that anchor away.
          echo "          if [[ \"\$PACKER_RESULT\" == \"cancelled\" ]]; then"
          echo "            PREEMPTED_LEG=\"Packer AMI bake\""
          echo "          fi"
          echo "          if [[ -n \"\$PREEMPTED_LEG\" ]]; then"
          echo "            NOTE=\"superseded\""
          echo "          fi"
          echo "          if [[ \"\$PACKER_RESULT\" == \"failure\" ]]; then"
          echo "            COLOR=\"#dc3545\""
          echo "          elif [[ \"\$BUILD_RESULT\" == \"success\" ]]; then"
          echo "            COLOR=\"#36a64f\""
          echo "          elif [[ -n \"\$PREEMPTED_LEG\" ]]; then"
          echo "            COLOR=\"#6c757d\""
          echo "          fi"
          ;;
        *) # missing: no packer branch at all (A3 and A6 existence both fail)
          echo "          if [[ \"\$BUILD_RESULT\" == \"success\" ]]; then"
          echo "            COLOR=\"#36a64f\""
          echo "          fi"
          ;;
      esac
      # Optional deploy-failure vs validate-success branch (A5 ordering).
      case "$logic_deploy" in
        ok)
          # Correct: deploy-failure checked BEFORE validate-success.
          echo "          if [[ \"\$DEPLOY_FAILED\" == \"true\" ]]; then"
          echo "            COLOR=\"#dc3545\""
          echo "          elif [[ \"\$SANDBOX_VALIDATE\" == \"success\" ]]; then"
          echo "            COLOR=\"#36a64f\""
          echo "          fi"
          ;;
        after)
          # Wrong order: validate-success wins first, so a failed/cancelled
          # smoke with a green validate renders green. A5's ordering catches it.
          echo "          if [[ \"\$SANDBOX_VALIDATE\" == \"success\" ]]; then"
          echo "            COLOR=\"#36a64f\""
          echo "          elif [[ \"\$DEPLOY_FAILED\" == \"true\" ]]; then"
          echo "            COLOR=\"#dc3545\""
          echo "          fi"
          ;;
        *) : ;;  # omit: no deploy/validate branch -> A5 gracefully skips
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
# (also trips A6 existence — one absent branch, both assertions describe it)
assert_exit "bad A3: status logic ignores PACKER_RESULT==failure" \
  "$(make_wf 1 1 missing 0 1)" 1

# A6 missing: failure arm correct, but a cancelled leg is never examined ->
# exit 1. This is the exact pre-fix shape, where a concurrency-preempted packer
# leg skipped the whole deploy chain and still rendered "NHP Build successful".
assert_exit "bad A6: status logic never examines PACKER_RESULT==cancelled" \
  "$(make_wf 1 1 nocancel 0 1)" 1

# A6 wrong order: the preempted arm is checked AFTER build-success -> exit 1.
# The arm exists (A6 existence passes) but never runs on a green build. This
# fixture also pins A6's `elif` anchor — see the cancelafter arm in make_wf.
assert_exit "bad A6: PREEMPTED_LEG checked after BUILD_RESULT==success" \
  "$(make_wf 1 1 cancelafter 0 1)" 1

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

# A5 good: deploy-failure checked BEFORE validate-success -> exit 0.
assert_exit "good A5: DEPLOY_FAILED==true checked before SANDBOX_VALIDATE==success" \
  "$(make_wf 1 1 ok 0 1 0 ok)" 0

# A5 wrong order: validate-success checked first -> exit 1. A green validate
# would mask a failed smoke and render green (the bug A5 fences).
assert_exit "bad A5: SANDBOX_VALIDATE==success checked before DEPLOY_FAILED==true" \
  "$(make_wf 1 1 ok 0 1 0 after)" 1

# A7: fail-OPEN polarity (`== 'true'`). Valid YAML, green actionlint, and every
# wiring breakage silently degrades to per-run groups — losing the SSM-overwrite
# serialization the shared group exists to provide -> exit 1.
assert_exit "bad A7: concurrency group uses fail-open '== true' polarity" \
  "$(make_wf 1 1 ok 0 1 0 '' failopen)" 1

# Real tree: the actual build-and-push.yml must already satisfy the lint
assert_exit "real tree: build-and-push.yml notify wiring is present" "" 0

# ---- Superseded-lookup jq filter -------------------------------------------
# The A1–A7 assertions above are string-grep membership checks; they can prove
# the superseded-run lookup is *wired*, never that its jq filter *computes* the
# right successor. That filter is the piece most likely to drift silently under
# a gh/gojq upgrade, so drive it directly.
#
# The filter is EXTRACTED from the workflow rather than copied, so this can't
# pass against a stale duplicate. Engine note: the workflow runs it through
# `gh --jq` (gojq); this runs it through jq. The constructs used here —
# select/min_by/`//`/empty — are identical across both.
WF_REAL="$REPO_ROOT/.github/workflows/build-and-push.yml"
JQ_FILTER=$(sed -n 's/.*--jq "\(.*\)".*/\1/p' "$WF_REAL" | head -1)
JQ_FILTER=${JQ_FILTER//\$\{GITHUB_RUN_NUMBER\}/100}

if [ -z "$JQ_FILTER" ]; then
  report_fail "extract superseded-lookup jq filter from build-and-push.yml" \
    "no '--jq \"...\"' line found — the lookup moved or was reshaped"
else
  # assert_jq <label> <input-json> <expected-stdout>
  assert_jq() {
    local label="$1" input="$2" want="$3" got
    got=$(printf '%s' "$input" | jq -r "$JQ_FILTER" 2>/dev/null) || got="<error>"
    if [ "$got" = "$want" ]; then
      report_pass "$label"
    else
      report_fail "$label" "expected '$want', got '$got'"
    fi
  }

  # The immediate successor wins, not merely "some newer run".
  assert_jq "jq: picks the nearest newer run" \
    '{"workflow_runs":[{"run_number":103},{"run_number":101},{"run_number":100}]}' '101'

  # The API returns runs created-desc, so min_by (not "first match") is what
  # makes the ordering correct. This fails if min_by is swapped for .[0]/first.
  assert_jq "jq: min_by beats input order (API returns desc)" \
    '{"workflow_runs":[{"run_number":150},{"run_number":102},{"run_number":101}]}' '101'

  # This run is the tip -> no successor -> empty -> notify's amber
  # "stopped early" path. Must NOT emit "null".
  assert_jq "jq: no newer run yields empty (not null)" \
    '{"workflow_runs":[{"run_number":100},{"run_number":99}]}' ''

  # Same, via an empty page.
  assert_jq "jq: empty run list yields empty" '{"workflow_runs":[]}' ''

  # Strictly-greater, not >=: the run must never name itself as its successor.
  assert_jq "jq: excludes this run's own number" \
    '{"workflow_runs":[{"run_number":100}]}' ''

  # A 5xx body has no .workflow_runs; jq errors, and the workflow's
  # `2>/dev/null || SUPERSEDED_BY=""` funnels that to the amber path too.
  assert_jq "jq: malformed payload errors (routed to amber)" \
    '{"message":"Server Error"}' '<error>'
fi

echo
echo "  passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
