#!/usr/bin/env bash
# check-control-leg-surfaced_test.sh — fixture tests for
# scripts/check-control-leg-surfaced.sh
# ----------------------------------------------------------------------------
# Builds synthetic build-and-push.yml workflows in a tempdir, points the lint at
# each via BUILD_AND_PUSH_WF, and asserts exit code. Every assertion C1–C6 gets
# a paired bad fixture, so a lint that silently stopped checking something fails
# here rather than passing forever. Two scope fixtures prove the job-block
# extractor's boundaries: decoy jobs before and after carrying the very strings
# the lint looks for must not satisfy it. The final case runs the lint against
# the real repo tree, so one invocation both unit-tests the detector and
# enforces the wiring on the actual workflow.
#
# Usage: bash tests/scripts/check-control-leg-surfaced_test.sh
# ============================================================================

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-control-leg-surfaced.sh"

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
# Flags ("1" includes the correct piece, anything else breaks it):
#   $1 needs_control   — `- deploy-sandbox-control` in notify.needs         (C1)
#   $2 env_control     — SANDBOX_CONTROL forwarded from the job result      (C2)
#   $3 loop_control    — SANDBOX_CONTROL in the DEPLOY_FAILED loop          (C3)
#   $4 status_control  — Control rendered in the SANDBOX_STATUS string      (C4)
#   $5 shared_lock     — shared deploy-sandbox-infra group vs its own       (C5)
#   $6 gate_file       — gates read from the committed file vs literals     (C6)
#   $7 include_control — emit the deploy-sandbox-control job at all
#   $8 decoys          — emit jobs before AND after that carry the strings
# shellcheck disable=SC2016  # every echo below emits literal workflow text:
# '${{ ... }}' and '$SANDBOX_*' are what the fixture must contain, not values to
# expand here.
make_wf() {
  local needs_control="$1" env_control="$2" loop_control="$3" status_control="$4"
  local shared_lock="$5" gate_file="$6" include_control="${7:-1}" decoys="${8:-0}"
  local f="$TMP/wf-$RANDOM$RANDOM.yml"

  {
    echo 'name: Build'
    echo 'jobs:'

    # The other half of the C5 equality. Its group is what Control's must match,
    # so shared_lock=infra-renamed below moves THIS one and leaves Control alone
    # — the case a Control-side literal assertion would have passed.
    echo '  deploy-sandbox-infra:'
    echo '    concurrency:'
    if [ "$shared_lock" = "infra-renamed" ]; then
      echo '      group: deploy-sandbox-cell0'
    else
      echo '      group: deploy-sandbox-infra'
    fi
    echo '      cancel-in-progress: false'
    echo '    steps:'
    echo '      - run: terraform apply'

    if [ "$decoys" = "1" ]; then
      # Leading decoy: carries every string the lint greps for, in a job that
      # is neither notify nor deploy-sandbox-control. If the extractor's start
      # boundary is wrong, these satisfy the assertions and the bad fixtures
      # below stop failing.
      echo '  decoy-before:'
      echo '    needs:'
      echo '      - deploy-sandbox-control'
      echo '    concurrency:'
      echo '      group: deploy-sandbox-infra'
      echo '      cancel-in-progress: false'
      echo '    steps:'
      echo '      - run: .github/scripts/control-sandbox-runtime-gates.py flags'
    fi

    if [ "$include_control" = "1" ]; then
      echo '  deploy-sandbox-control:'
      echo '    needs: [setup, deploy-sandbox-infra]'
      echo '    concurrency:'
      case "$shared_lock" in
        1|infra-renamed)
          echo '      group: deploy-sandbox-infra'
          echo '      cancel-in-progress: false'
          ;;
        *)
          # The plausible "cleanup": its own group. Nothing else in CI notices,
          # and Control and cell0 become free to apply concurrently.
          echo '      group: deploy-sandbox-control'
          echo '      cancel-in-progress: true'
          ;;
      esac
      echo '    steps:'
      echo '      - name: Generate'
      echo '        run: |'
      case "$gate_file" in
        1)
          # The production form: capture into a plain assignment so `set -e`
          # can still see the reader's exit status, then split, then refuse the
          # fully-dark (teardown) shape.
          echo '          gate_flag_text="$(.github/scripts/control-sandbox-runtime-gates.py flags)"'
          echo '          mapfile -t gate_flags <<<"$gate_flag_text"'
          echo '          if [[ "${#gate_flags[@]}" -eq 0 || -z "${gate_flags[0]}" ]]; then'
          echo '            echo "::error::The committed Control gate file is fully dark."'
          echo '            exit 1'
          echo '          fi'
          ;;
        no-dark-guard)
          # Reads the gate file the right way, but the fully-dark fail-closed
          # check is gone. Every other assertion still passes and an all-dark
          # commit would auto-apply a Hub/Authority teardown.
          echo '          gate_flag_text="$(.github/scripts/control-sandbox-runtime-gates.py flags)"'
          echo '          mapfile -t gate_flags <<<"$gate_flag_text"'
          ;;
        procsub)
          # Reads from the gate file and looks correct, but process
          # substitution discards the reader's exit status — a failing reader
          # yields an empty array and the generator falls through to the dark
          # Terraform defaults. C6 must reject this even though the script IS
          # referenced.
          echo '          mapfile -t gate_flags < <(.github/scripts/control-sandbox-runtime-gates.py flags)'
          ;;
        *)
          # Literal flags: drifts out of lockstep with the dispatch workflow,
          # and a lost gate file degrades to the dark Terraform defaults.
          echo '          gate_flags=(--hub-edge-enabled --hub-worker-enabled)'
          ;;
      esac
    fi

    echo '  notify:'
    echo '    needs:'
    echo '      - deploy-sandbox-infra'
    if [ "$needs_control" = "1" ]; then
      echo '      - deploy-sandbox-control'
    fi
    echo '    steps:'
    echo '      - name: Notify Slack'
    echo '        env:'
    echo '          SANDBOX_INFRA: ${{ needs.deploy-sandbox-infra.result }}'
    if [ "$env_control" = "1" ]; then
      echo '          SANDBOX_CONTROL: ${{ needs.deploy-sandbox-control.result }}'
    fi
    echo '        run: |'
    if [ "$loop_control" = "1" ]; then
      echo '          for result in "$SANDBOX_INFRA" "$SANDBOX_CONTROL"; do'
    else
      echo '          for result in "$SANDBOX_INFRA"; do'
    fi
    echo '            :'
    echo '          done'
    if [ "$status_control" = "1" ]; then
      echo '          SANDBOX_STATUS="$(status_emoji "$SANDBOX_INFRA") Infra → $(control_emoji) Control"'
    else
      echo '          SANDBOX_STATUS="$(status_emoji "$SANDBOX_INFRA") Infra"'
    fi

    if [ "$decoys" = "1" ]; then
      # Trailing decoy: proves the extractor's end boundary. notify is not the
      # last job in the real workflow either.
      echo '  decoy-after:'
      echo '    needs:'
      echo '      - deploy-sandbox-control'
      echo '    concurrency:'
      echo '      group: deploy-sandbox-infra'
      echo '      cancel-in-progress: false'
      echo '    steps:'
      echo '      - run: .github/scripts/control-sandbox-runtime-gates.py flags'
    fi
  } >"$f"
  printf '%s' "$f"
}

echo "check-control-leg-surfaced fixtures:"

assert_exit "all wiring present → pass" "$(make_wf 1 1 1 1 1 1)" 0
assert_exit "C1 notify.needs drops the Control job → fail" "$(make_wf 0 1 1 1 1 1)" 1
assert_exit "C2 SANDBOX_CONTROL not forwarded → fail" "$(make_wf 1 0 1 1 1 1)" 1
assert_exit "C3 Control missing from DEPLOY_FAILED loop → fail" "$(make_wf 1 1 0 1 1 1)" 1
assert_exit "C4 Control missing from the status pipeline → fail" "$(make_wf 1 1 1 0 1 1)" 1
assert_exit "C5 Control given its own concurrency group → fail" "$(make_wf 1 1 1 1 0 1)" 1
# The half a Control-side literal assertion could never catch: Control still
# says deploy-sandbox-infra, but INFRA renamed its group, so the lock is split
# and the two roots can apply against the same estate concurrently.
assert_exit "C5 infra renames its group, splitting the lock → fail" "$(make_wf 1 1 1 1 infra-renamed 1)" 1
assert_exit "C6 gates hardcoded instead of read from the file → fail" "$(make_wf 1 1 1 1 1 0)" 1
# The regression the surrounding comments warn about, and the one a
# "reads from the gate file" check alone would wave through.
assert_exit "C6 gates read via process substitution → fail" "$(make_wf 1 1 1 1 1 procsub)" 1
# C7: the single guard between an all-dark commit and an unattended teardown of
# the Hub and the Authority runtime. Everything else about this fixture is
# correct, which is exactly why the guard needs its own assertion.
assert_exit "C7 fully-dark fail-closed guard deleted → fail" "$(make_wf 1 1 1 1 1 no-dark-guard)" 1
assert_exit "Control job absent entirely → fail" "$(make_wf 1 1 1 1 1 1 0)" 1

# Scope: decoy jobs before and after carry every grepped string. With correct
# block extraction the broken pieces are still detected; with a file-wide grep
# these would all pass.
assert_exit "decoys present, wiring correct → pass" "$(make_wf 1 1 1 1 1 1 1 1)" 0
assert_exit "decoys cannot satisfy C1 for notify → fail" "$(make_wf 0 1 1 1 1 1 1 1)" 1
assert_exit "decoys cannot satisfy C5 for the Control job → fail" "$(make_wf 1 1 1 1 0 1 1 1)" 1
assert_exit "decoys cannot satisfy C6 for the Control job → fail" "$(make_wf 1 1 1 1 1 0 1 1)" 1

# The real tree. Both a detector test and the live wiring enforcement.
assert_exit "real build-and-push.yml is correctly wired" "" 0

echo
printf 'passed: %d, failed: %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
