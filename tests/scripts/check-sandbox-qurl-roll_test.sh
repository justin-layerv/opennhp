#!/usr/bin/env bash
# check-sandbox-qurl-roll_test.sh — regression guard for #1634.
# ----------------------------------------------------------------------------
# build-and-push.yml's sandbox TF apply registers a new qurl-service task-def
# revision when a qurl env var changes, but aws_ecs_service.qurl carries
# lifecycle.ignore_changes = [task_definition] — so the running service never
# advances unless CI rolls it. Prod (promote-to-prod.yml deploy-qurl) did;
# sandbox did not, so env-var changes silently no-op'd until a downstream
# consumer 403'd (qurl-service #335). The deploy-sandbox-qurl job closes that
# gap. The same validate job now also owns the qURL JS-agent → relay bootstrap
# smoke (#2680), so this test fences that relay ordering/wiring too. It fails
# if the load-bearing pieces regress or are removed, so those gaps cannot
# silently reopen.
#
# Asserted against the REAL build-and-push.yml (not a fixture) — the invariants
# are simple wiring checks plus the one load-bearing smoke-before-tracking order
# check, so a real-tree assertion is the proportionate guard. The job block is
# extracted by awk and each assertion is scoped to it, so an unrelated match
# elsewhere in the file cannot satisfy a check (and a future reorder that moves
# these lines OUT of the job fails loud).
#
# Usage: bash tests/scripts/check-sandbox-qurl-roll_test.sh
# ============================================================================

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
WF="$REPO_ROOT/.github/workflows/build-and-push.yml"

pass=0
fail=0
report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"; }

if [[ ! -f "$WF" ]]; then
  report_fail "workflow present" "build-and-push.yml not found at $WF"
  echo; echo "  passed: $pass  failed: $fail"; exit 1
fi

# Extract a workflow job block: from its `  <job>:` header (2-space indent =
# job level) up to the next job header at the same indent. Comment lines
# (`  # ...`) are not job headers, so extraction does not stop on the comment
# banner that precedes the next job.
extract_job() {
  awk -v job="$1" '
    $0 ~ "^  " job ":[[:space:]]*$" { capture=1; print; next }
    capture && /^  [A-Za-z][A-Za-z0-9_-]*:[[:space:]]*$/ { exit }
    capture { print }
  ' "$WF"
}

# assert_in <block> <job-name> <label> <ERE> — the pattern must appear within
# the extracted job block. Scoping to the block (not the whole file) means a
# match elsewhere can't satisfy a check, and a reorder that moves a line out of
# the job fails loud.
assert_in() {
  local block="$1" job="$2" label="$3" re="$4"
  if grep -Eq -- "$re" <<< "$block"; then
    report_pass "$label"
  else
    report_fail "$label" "pattern not found in $job job: $re"
  fi
}

# Extract a named step block from an already-extracted job block, stopping at the
# next step at the same indentation. Keeps step-specific gates from being
# satisfied by the same expression elsewhere in the job.
extract_step() {
  local block="$1" step="$2"
  awk -v step="$step" '
    $0 ~ "^[[:space:]]*- name: " step "[[:space:]]*$" { capture=1; print; next }
    capture && /^[[:space:]]*- name: / { exit }
    capture { print }
  ' <<< "$block"
}

assert_step_in() {
  local block="$1" job="$2" step="$3" label="$4" re="$5"
  local step_block
  step_block=$(extract_step "$block" "$step")
  if [[ -z "$step_block" ]]; then
    report_fail "$label" "step not found in $job job: $step"
    return
  fi
  assert_in "$step_block" "$job step '$step'" "$label" "$re"
}

assert_step_not_in() {
  local block="$1" job="$2" step="$3" label="$4" re="$5"
  local step_block
  step_block=$(extract_step "$block" "$step")
  if [[ -z "$step_block" ]]; then
    report_fail "$label" "step not found in $job job: $step"
    return
  fi
  if grep -Eq -- "$re" <<< "$step_block"; then
    report_fail "$label" "unexpected pattern found in $job step '$step': $re"
  else
    report_pass "$label"
  fi
}

assert_step_order() {
  local block="$1" job="$2" before="$3" after="$4" label="$5"
  local before_line after_line
  before_line=$(grep -nF -- "- name: $before" <<< "$block" | head -n1 | cut -d: -f1)
  after_line=$(grep -nF -- "- name: $after" <<< "$block" | head -n1 | cut -d: -f1)
  if [[ -z "$before_line" || -z "$after_line" ]]; then
    report_fail "$label" "missing step(s) in $job job: before='$before' after='$after'"
  elif [[ "$before_line" -lt "$after_line" ]]; then
    report_pass "$label"
  else
    report_fail "$label" "step '$before' must appear before '$after' in $job job"
  fi
}

echo "check-sandbox-qurl-roll:"

JOB=$(extract_job deploy-sandbox-qurl)
if [[ -z "$JOB" ]]; then
  report_fail "deploy-sandbox-qurl job exists" \
    "no '  deploy-sandbox-qurl:' job header found in build-and-push.yml"
  echo; echo "  passed: $pass  failed: $fail"; exit 1
fi
report_pass "deploy-sandbox-qurl job exists"

# Gated on the TF-apply job — that is the job that registers new revisions.
assert_in "$JOB" deploy-sandbox-qurl "gated on deploy-sandbox-infra success" \
  'needs\.deploy-sandbox-infra\.result == .success.'

# Rolls via the shared deployer (ECS circuit-breaker + post-roll verify),
# rather than a bespoke force-new-deployment that would re-pull the same image.
assert_in "$JOB" deploy-sandbox-qurl "invokes deploy-ecs-service.sh" \
  'deploy-ecs-service\.sh'

# Idempotency guard: compare running vs latest task def, advance only on diff.
# Without all three, the roll would fire on every push-to-main deploy.
assert_in "$JOB" deploy-sandbox-qurl "reads running task def (describe-services)" \
  'aws ecs describe-services'
assert_in "$JOB" deploy-sandbox-qurl "reads latest task def (describe-task-definition)" \
  'aws ecs describe-task-definition'
# SC2016: the $RUNNING/$LATEST in the grep pattern are literal text to match
# in the workflow, not shell expansions — single-quoting is intentional.
# shellcheck disable=SC2016
assert_in "$JOB" deploy-sandbox-qurl "skips when running == latest (no-op guard)" \
  '"\$RUNNING" == "\$LATEST"'

# Image tag comes from the SSM source of truth, NOT derived from the task def
# (deriving could downgrade the image if qurl-CI pushed between apply and roll).
assert_in "$JOB" deploy-sandbox-qurl "reads image tag from SSM qurl-api-image-tag" \
  'qurl-api-image-tag'
assert_in "$JOB" deploy-sandbox-qurl "preserves qurl-service SSM image writer" \
  'PRESERVE_SSM_IMAGE_TAG: "true"'

# Loud-fail / quiet-skip: genuine absence of the cluster/service params skips;
# everything else fails the job. Guard the skip notice so it cannot be deleted
# into a hard failure on the not-deployed path (or vice-versa).
assert_in "$JOB" deploy-sandbox-qurl "skips cleanly when qurl not deployed (::notice::)" \
  'qurl not deployed in sandbox'
# A sustained SSM error must NOT masquerade as "not deployed": only a genuine
# ParameterNotFound is the skip signal, everything else fails loud (#1634
# hidden-skip class). Fences the ssm_probe not-found-vs-other-error distinction.
assert_in "$JOB" deploy-sandbox-qurl "is-deployed probe distinguishes ParameterNotFound" \
  '(ParameterNotFound)'
assert_in "$JOB" deploy-sandbox-qurl "is-deployed probe uses an explicit not-found sentinel" \
  'SSM_PARAM_NOT_FOUND'
assert_in "$JOB" deploy-sandbox-qurl "empty qurl SSM params fail loud" \
  'returned empty/None'

# Ordering guard (#1634): deploy-sandbox-validate — and nhp-smoke-sandbox, which
# needs it (tier: all exercises the qurl resolve path that 403'd in the
# incident) — must wait for the roll, else smoke can race a slow roll and go red
# on a healthy deploy. deploy-sandbox-qurl runs parallel to blue-green, so the
# only thing forcing this order is validate's needs/if edge. Validate orders
# after the roll (needs) but only skips on `cancelled` (NOT on a roll failure —
# that must not suppress independent server/AC smoke). Assert both.
VALIDATE=$(extract_job deploy-sandbox-validate)
if [[ -z "$VALIDATE" ]]; then
  report_fail "deploy-sandbox-validate job exists" \
    "no '  deploy-sandbox-validate:' job header found in build-and-push.yml"
else
  assert_in "$VALIDATE" deploy-sandbox-validate "validate needs deploy-sandbox-qurl (orders smoke after roll)" \
    'needs:.*deploy-sandbox-qurl'
  assert_in "$VALIDATE" deploy-sandbox-validate "validate skips only on cancelled qurl (not on roll failure)" \
    "needs\.deploy-sandbox-qurl\.result != 'cancelled'"

  # Relay ordering/smoke guard (#2680): once qurl.link is in JS-agent mode, a
  # green sandbox deploy must prove the shipped verifier + deployed agent bundle
  # can traverse the real relay. The smoke has teeth only if validate waits for
  # a successful relay deploy leg and passes the same qurl.link origin resolved
  # from SSM to the helper.
  assert_in "$VALIDATE" deploy-sandbox-validate "validate needs deploy-sandbox-relay (orders smoke after relay roll)" \
    'needs:.*deploy-sandbox-relay'
  assert_in "$VALIDATE" deploy-sandbox-validate "validate gates relay smoke on relay deploy success" \
    "needs\.deploy-sandbox-relay\.result == 'success'"
  assert_step_in "$VALIDATE" deploy-sandbox-validate "Setup Node for qURL relay smoke" "setup-node for relay smoke is gated on relay deploy success" \
    "needs\.deploy-sandbox-relay\.result == 'success'"
  assert_step_order "$VALIDATE" deploy-sandbox-validate "Smoke qURL JS-agent relay bootstrap" "Update Deployment Tracking" \
    "relay smoke runs before deployment tracking"
  assert_step_not_in "$VALIDATE" deploy-sandbox-validate "Smoke qURL JS-agent relay bootstrap" "relay smoke is not continue-on-error" \
    'continue-on-error'
  assert_step_in "$VALIDATE" deploy-sandbox-validate "Smoke qURL JS-agent relay bootstrap" "relay smoke has bounded headroom" \
    'timeout-minutes:[[:space:]]*5'
  assert_step_in "$VALIDATE" deploy-sandbox-validate "Update Deployment Tracking" "deployment tracking records only after relay success" \
    "needs\.deploy-sandbox-relay\.result == 'success'"
  assert_step_in "$VALIDATE" deploy-sandbox-validate "Update Deployment Tracking" "deployment tracking requires prior step success" \
    'success\(\).*needs\.deploy-sandbox-relay\.result'
  assert_in "$VALIDATE" deploy-sandbox-validate "relay smoke uses the SSM-resolved qurl link URL" \
    'QURL_LINK_URL:.*qurl-domain-sandbox\.outputs\.qurl_link_url'
  # SC2016: the $QURL_LINK_URL in the grep pattern is literal workflow text.
  # shellcheck disable=SC2016
  assert_in "$VALIDATE" deploy-sandbox-validate "relay smoke invokes qurl-relay-bootstrap-smoke helper" \
    'node scripts/qurl-relay-bootstrap-smoke\.mjs "\$QURL_LINK_URL"'
fi

echo
echo "  passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
