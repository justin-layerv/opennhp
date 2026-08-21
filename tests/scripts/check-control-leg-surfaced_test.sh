#!/usr/bin/env bash
# check-control-leg-surfaced_test.sh — fixture tests for
# scripts/check-control-leg-surfaced.sh
# ----------------------------------------------------------------------------
# Builds synthetic build-and-push.yml workflows in a tempdir, points the lint at
# each via BUILD_AND_PUSH_WF, and asserts exit code. Every assertion C1–C10 gets
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
#   $9 barrier         — same-run Control authorization shape (C8)
#   $10 dag            — downstream cell/runtime/validate graph (C9)
#   $11 upstream_plan  — emit a forbidden pre-Control saved plan (C10)
#   $12 large_infra    — pad the infra job beyond a pipe buffer
# shellcheck disable=SC2016  # every echo below emits literal workflow text:
# '${{ ... }}' and '$SANDBOX_*' are what the fixture must contain, not values to
# expand here.
make_wf() {
  local needs_control="$1" env_control="$2" loop_control="$3" status_control="$4"
  local shared_lock="$5" gate_file="$6" include_control="${7:-1}" decoys="${8:-0}"
  local barrier="${9:-1}" dag="${10:-1}" upstream_plan="${11:-0}"
  local large_infra="${12:-0}"
  local f="$TMP/wf-$RANDOM$RANDOM.yml"

  {
    echo 'name: Build'
    echo 'jobs:'

    echo '  terraform-plan:'
    echo '    steps:'
    echo '      - run: terraform validate'
    if [ "$upstream_plan" = "1" ]; then
      echo '      - run: |'
      echo '          terraform plan -out=tfplan'
    elif [ "$upstream_plan" = "inline" ]; then
      echo '      - run: terraform plan -out=tfplan'
    fi

    # The other half of the C5 equality. Its group is what Control's must match,
    # so shared_lock=infra-renamed below moves THIS one and leaves Control alone
    # — the case a Control-side literal assertion would have passed.
    echo '  deploy-sandbox-infra:'
    if [ "$barrier" = "no-infra-need" ]; then
      echo '    needs: [setup]'
    else
      echo '    needs: [setup, deploy-sandbox-control]'
    fi
    echo '    if: |'
    echo "      needs.deploy-sandbox-control.result == 'success' &&"
    if [ "$barrier" != "no-infra-output" ]; then
      echo "      needs.deploy-sandbox-control.outputs.consumer_rollout_ready == 'true'"
    else
      echo '      true'
    fi
    echo '    concurrency:'
    if [ "$shared_lock" = "infra-renamed" ]; then
      echo '      group: deploy-sandbox-cell0'
    else
      echo '      group: deploy-sandbox-infra'
    fi
    echo '      cancel-in-progress: false'
    echo '    steps:'
    if [ "$large_infra" = "1" ]; then
      # group_of finds the concurrency group near the start of the block. Keep
      # enough unread tail to reproduce Linux printf's EPIPE if the extractor
      # regresses to an early-exiting producer pipeline under pipefail.
      for _ in $(seq 1 65536); do
        echo '      # large infra block padding for extractor EPIPE regression'
      done
    fi
    echo '      - run: |'
    echo '          if ! terraform plan -out=tfplan -no-color; then exit 1; fi'
    echo '          terraform apply -auto-approve tfplan'

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
      if [ "$barrier" = "control-cycles" ]; then
        echo '    needs: [setup, deploy-sandbox-infra]'
      else
        echo '    needs: [setup]'
      fi
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
      if [ "$barrier" != "no-output" ]; then
        echo '    outputs:'
        echo '      consumer_rollout_ready: ${{ steps.authorize-consumers.outputs.ready }}'
      fi
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
      echo '      - name: Verify Control apply'
      echo '        id: verify'
      echo '        run: true'
      echo '      - name: Verify promotion'
      echo '        id: promote-verify'
      echo '        run: true'
      echo '      - name: Authorize fresh cell planning'
      echo '        id: authorize-consumers'
      echo '        if: >-'
      echo '          success() &&'
      if [ "$barrier" != "no-fresh" ]; then
        echo "          steps.freshness.outputs.fresh == 'true' &&"
      fi
      case "$barrier" in
        no-verify)
          echo "          steps.plan.outputs.control_status == 'converged' &&"
          ;;
        *)
          echo "          (steps.plan.outputs.control_status == 'converged' || steps.verify.outcome == 'success') &&"
          ;;
      esac
      if [ "$barrier" != "no-promote" ]; then
        echo "          (steps.promote-detect.outputs.promote != 'true' || steps.promote-verify.outcome == 'success')"
      else
        echo '          true'
      fi
      echo '        run: echo ready=true >>"$GITHUB_OUTPUT"'
    fi

    echo '  deploy-sandbox-blue-green:'
    if [ "$dag" = "missing-cell0-runtime" ]; then
      echo '    needs: [setup]'
    else
      echo '    needs: [setup, deploy-sandbox-infra]'
    fi
    echo '    steps:'
    echo '      - run: deploy-cell0-runtime'

    echo '  deploy-sandbox-cell1-infra:'
    if [ "$dag" = "missing-cell1-plan" ]; then
      echo '    needs: [setup]'
    else
      echo '    needs: [deploy-sandbox-infra]'
    fi
    echo '    steps:'
    echo '      - run: |'
    echo '          terraform plan -no-color -out=tfplan'
    echo '          terraform apply -no-color -auto-approve tfplan'

    echo '  deploy-sandbox-cell1-blue-green:'
    if [ "$dag" = "missing-cell1-runtime" ]; then
      echo '    needs: [deploy-sandbox-cell1-infra]'
    else
      echo '    needs: [deploy-sandbox-blue-green, deploy-sandbox-cell1-infra]'
    fi
    echo '    steps:'
    echo '      - run: deploy-cell1-runtime'

    echo '  deploy-sandbox-validate:'
    if [ "$dag" = "missing-validate-runtime" ]; then
      echo '    needs: [deploy-sandbox-infra, deploy-sandbox-blue-green, deploy-sandbox-control]'
    else
      echo '    needs: [setup, deploy-sandbox-infra, deploy-sandbox-blue-green, deploy-sandbox-cell1-blue-green, deploy-sandbox-control]'
    fi
    echo '    if: |'
    if [ "$barrier" != "no-validate-output" ]; then
      echo "      needs.deploy-sandbox-control.outputs.consumer_rollout_ready == 'true'"
    else
      echo '      true'
    fi
    echo '    steps:'
    echo '      - run: validate-live-aliases'

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

# C8: a superseded Control leg is job-successful, so only the separately
# verified positive output may release a cell plan. The verify and promotion
# fixtures also model interrupted/partial Control transitions: neither may
# authorize consumers until the next run finishes the exact retry.
assert_exit "C8 consumer authorization output deleted → fail" \
  "$(make_wf 1 1 1 1 1 1 1 0 no-output)" 1
assert_exit "C8 cell0 infers readiness from Control success alone → fail" \
  "$(make_wf 1 1 1 1 1 1 1 0 no-infra-output)" 1
assert_exit "C8 cell0 no longer depends directly on Control → fail" \
  "$(make_wf 1 1 1 1 1 1 1 0 no-infra-need)" 1
assert_exit "C8 superseded Control may authorize consumers → fail" \
  "$(make_wf 1 1 1 1 1 1 1 0 no-fresh)" 1
assert_exit "C8 partial Control apply may authorize consumers → fail" \
  "$(make_wf 1 1 1 1 1 1 1 0 no-verify)" 1
assert_exit "C8 unverified selector promotion may authorize consumers → fail" \
  "$(make_wf 1 1 1 1 1 1 1 0 no-promote)" 1
assert_exit "C8 Control depends on cell0 and reverses the barrier → fail" \
  "$(make_wf 1 1 1 1 1 1 1 0 control-cycles)" 1
assert_exit "C8 validation drops the same-run authorization → fail" \
  "$(make_wf 1 1 1 1 1 1 1 0 no-validate-output)" 1

# C9/C10: the complete rollout is Control -> fresh cell plans -> both runtime
# refreshes -> validation. These fixtures break one edge at a time and add the
# exact forbidden pre-Control saved plan.
assert_exit "C9 cell0 runtime can precede its fresh plan → fail" \
  "$(make_wf 1 1 1 1 1 1 1 0 1 missing-cell0-runtime)" 1
assert_exit "C9 cell1 plan can precede cell0 authorization → fail" \
  "$(make_wf 1 1 1 1 1 1 1 0 1 missing-cell1-plan)" 1
assert_exit "C9 cell1 runtime drops the cell0 runtime edge → fail" \
  "$(make_wf 1 1 1 1 1 1 1 0 1 missing-cell1-runtime)" 1
assert_exit "C9 validation can run before cell1 runtime → fail" \
  "$(make_wf 1 1 1 1 1 1 1 0 1 missing-validate-runtime)" 1
assert_exit "C10 upstream job creates a four-op saved plan → fail" \
  "$(make_wf 1 1 1 1 1 1 1 0 1 1 1)" 1
assert_exit "C10 inline upstream plan cannot bypass the fence → fail" \
  "$(make_wf 1 1 1 1 1 1 1 0 1 1 inline)" 1

# Scope: decoy jobs before and after carry every grepped string. With correct
# block extraction the broken pieces are still detected; with a file-wide grep
# these would all pass.
assert_exit "decoys present, wiring correct → pass" "$(make_wf 1 1 1 1 1 1 1 1)" 0
assert_exit "decoys cannot satisfy C1 for notify → fail" "$(make_wf 0 1 1 1 1 1 1 1)" 1
assert_exit "decoys cannot satisfy C5 for the Control job → fail" "$(make_wf 1 1 1 1 0 1 1 1)" 1
assert_exit "decoys cannot satisfy C6 for the Control job → fail" "$(make_wf 1 1 1 1 1 0 1 1)" 1

# Portability: the real workflow exceeded the Linux pipe buffer and exposed a
# `printf | awk` EPIPE that macOS did not reproduce. Pin the large-block shape
# so group extraction stays producer-pipeline-free on every runner.
assert_exit "large infra block does not turn an early group match into EPIPE" \
  "$(make_wf 1 1 1 1 1 1 1 0 1 1 0 1)" 0

# The real tree. Both a detector test and the live wiring enforcement.
assert_exit "real build-and-push.yml is correctly wired" "" 0

echo
printf 'passed: %d, failed: %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
