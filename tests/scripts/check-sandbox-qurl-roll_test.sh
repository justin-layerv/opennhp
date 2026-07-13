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
PLAN_WF="$REPO_ROOT/.github/workflows/terraform-plan-pr.yml"

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
extract_job_from() {
  local file="$1" job="$2"
  awk -v job="$job" '
    $0 ~ "^  " job ":[[:space:]]*$" { capture=1; print; next }
    capture && /^  [A-Za-z][A-Za-z0-9_-]*:[[:space:]]*$/ { exit }
    capture { print }
  ' "$file"
}

extract_job() {
  extract_job_from "$WF" "$1"
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
    /^[[:space:]]*- name: / && $0 == "      - name: " step { capture=1; print; next }
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

assert_text_order() {
  local block="$1" scope="$2" before="$3" after="$4" label="$5"
  local before_line after_line
  before_line=$(grep -nF -- "$before" <<< "$block" | head -n1 | cut -d: -f1)
  after_line=$(grep -nF -- "$after" <<< "$block" | head -n1 | cut -d: -f1)
  if [[ -z "$before_line" || -z "$after_line" ]]; then
    report_fail "$label" "missing text in $scope: before='$before' after='$after'"
  elif [[ "$before_line" -lt "$after_line" ]]; then
    report_pass "$label"
  else
    report_fail "$label" "'$before' must appear before '$after' in $scope"
  fi
}

echo "check-sandbox-qurl-roll:"

SETUP=$(extract_job setup)
if [[ -z "$SETUP" ]]; then
  report_fail "setup job exists" \
    "no '  setup:' job header found in build-and-push.yml"
else
  report_pass "setup job exists"
  assert_step_in "$SETUP" setup "Set metadata" "setup image tag is always the workflow commit" \
    'image_tag=\$\{\{ github\.sha \}\}'
fi

GUARD=$(extract_job sandbox-environment-guard)
if [[ -z "$GUARD" ]]; then
  report_fail "sandbox-environment-guard job exists" \
    "no '  sandbox-environment-guard:' job header found in build-and-push.yml"
else
  report_pass "sandbox-environment-guard job exists"
  assert_in "$GUARD" sandbox-environment-guard "environment guard runs on pull requests as API smoke" \
    'github\.event_name == .pull_request.'
  assert_in "$GUARD" sandbox-environment-guard "environment guard can read deployment environment metadata" \
    'deployments: read'
  assert_in "$GUARD" sandbox-environment-guard "environment guard checks sandbox protection rules" \
    'protection_rules'
  assert_in "$GUARD" sandbox-environment-guard "environment guard fails protected sandbox env red" \
    'must not wait for approval'
fi

DRIFT=$(extract_job sandbox-app-image-drift)
if [[ -z "$DRIFT" ]]; then
  report_fail "sandbox-app-image-drift job exists" \
    "no '  sandbox-app-image-drift:' job header found in build-and-push.yml"
else
  report_pass "sandbox-app-image-drift job exists"
  assert_in "$DRIFT" sandbox-app-image-drift "drift waits for sandbox environment guard" \
    'needs:.*sandbox-environment-guard'
  # SC2016: $HEAD_SHA is literal workflow text in the grep pattern.
  # shellcheck disable=SC2016
  assert_in "$DRIFT" sandbox-app-image-drift "drift job compares live tags against HEAD" \
    'resolve-live-app-image-required\.sh sandbox "\$HEAD_SHA"'
fi

APPBUILD=$(extract_job app-image-build-required)
if [[ -z "$APPBUILD" ]]; then
  report_fail "app-image-build-required job exists" \
    "no '  app-image-build-required:' job header found in build-and-push.yml"
else
  report_pass "app-image-build-required job exists"
  assert_in "$APPBUILD" app-image-build-required "app-image build classifier waits for changes and drift" \
    'needs:.*changes.*sandbox-app-image-drift'
  assert_in "$APPBUILD" app-image-build-required "app-image build classifier exposes a single workflow output" \
    'app_image_build_required'
  assert_in "$APPBUILD" app-image-build-required "app-image build classifier folds app changes and live drift" \
    'APP_CHANGED_THIS_COMMIT.*LIVE_APP_IMAGE_REQUIRED'
fi

BUILD=$(extract_job build)
if [[ -z "$BUILD" ]]; then
  report_fail "build job exists" \
    "no '  build:' job header found in build-and-push.yml"
else
  assert_in "$BUILD" build "build waits for sandbox environment guard" \
    'needs:.*sandbox-environment-guard'
  assert_in "$BUILD" build "build requires sandbox environment guard success/skipped" \
    'sandbox-environment-guard\.result == .success.'
  assert_in "$BUILD" build "build waits for sandbox app-image drift detection" \
    'needs:.*sandbox-app-image-drift'
  assert_in "$BUILD" build "build waits for app-image build classification" \
    'needs:.*app-image-build-required'
  assert_in "$BUILD" build "build consumes the single app-image build classification output" \
    'app-image-build-required\.outputs\.app_image_build_required'
fi

JOB=$(extract_job deploy-sandbox-qurl)
if [[ -z "$JOB" ]]; then
  report_fail "deploy-sandbox-qurl job exists" \
    "no '  deploy-sandbox-qurl:' job header found in build-and-push.yml"
  echo; echo "  passed: $pass  failed: $fail"; exit 1
fi
report_pass "deploy-sandbox-qurl job exists"

INFRA=$(extract_job deploy-sandbox-infra)
if [[ -z "$INFRA" ]]; then
  report_fail "deploy-sandbox-infra job exists" \
    "no '  deploy-sandbox-infra:' job header found in build-and-push.yml"
else
  assert_in "$INFRA" deploy-sandbox-infra "infra deploy waits for sandbox environment guard" \
    'needs:.*sandbox-environment-guard'
  assert_in "$INFRA" deploy-sandbox-infra "infra deploy requires sandbox environment guard success/skipped" \
    'sandbox-environment-guard\.result == .success.'
  assert_in "$INFRA" deploy-sandbox-infra "infra deploy consumes the single app-image build classification output" \
    'app-image-build-required\.outputs\.app_image_build_required'
  assert_step_order "$INFRA" deploy-sandbox-infra \
    "Handle ASG Attachment Migrations and Taint Recovery" \
    "Verify relay DMZ plan contract before apply" \
    "final Terraform plan is checked after every recovery path"
  RECOVERY_STEP=$(extract_step "$INFRA" "Handle ASG Attachment Migrations and Taint Recovery")
  assert_text_order "$RECOVERY_STEP" "deploy-sandbox-infra recovery step" \
    "            preflight_relay_dmz_boundary_noop" \
    'terraform state rm "$att"' \
    "relay DMZ boundary is checked before any Terraform state mutation"
  assert_in "$RECOVERY_STEP" "deploy-sandbox-infra recovery step" \
    "recovery preflight invokes the relay DMZ checker" \
    'check-relay-dmz-plan\.py'
  assert_in "$RECOVERY_STEP" "deploy-sandbox-infra recovery step" \
    "recovery preflight requires PR 0 state convergence" \
    '--require-pr0-applied'
  assert_in "$RECOVERY_STEP" "deploy-sandbox-infra recovery step" \
    "recovery preflight requires a no-op DMZ boundary" \
    '--require-dmz-boundary-noop'
  assert_in "$RECOVERY_STEP" "deploy-sandbox-infra recovery step" \
    "recovery preflight checks its dedicated saved-plan JSON" \
    'plan-boundary-preflight\.json'
  if grep -Eq -- '--allow-disabled' <<< "$RECOVERY_STEP"; then
    report_fail "recovery preflight cannot use bootstrap tolerance" \
      "unexpected --allow-disabled in recovery preflight"
  else
    report_pass "recovery preflight cannot use bootstrap tolerance"
  fi
  assert_step_order "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ plan contract before apply" \
    "Terraform Apply" \
    "relay DMZ plan contract gates Terraform apply"
  assert_step_order "$INFRA" deploy-sandbox-infra \
    "Terraform Apply" \
    "Verify AWS CLI major for relay DMZ detector" \
    "AWS CLI major is fenced before the structural live detector"
  assert_step_order "$INFRA" deploy-sandbox-infra \
    "Verify AWS CLI major for relay DMZ detector" \
    "Verify relay DMZ structural boundary" \
    "live structural proof runs only after the AWS CLI major fence"
  assert_step_in "$INFRA" deploy-sandbox-infra \
    "Verify AWS CLI major for relay DMZ detector" \
    "structural detector accepts only AWS CLI v2 stderr contracts" \
    '\^aws-cli/2\\\.'
  assert_step_order "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ structural boundary" \
    "Verify relay DMZ post-apply idempotency" \
    "post-apply idempotency runs after live structural proof"
  assert_step_order "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ post-apply idempotency" \
    "Get Terraform Outputs" \
    "infra outputs are withheld until post-apply idempotency passes"
  assert_step_in "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ plan contract before apply" \
    "pre-apply gate checks the final plan JSON" \
    'check-relay-dmz-plan\.py'
  assert_step_in "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ plan contract before apply" \
    "pre-apply gate requires PR 0 state convergence" \
    '--require-pr0-applied'
  assert_step_in "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ plan contract before apply" \
    "automatic apply requires the relay DMZ boundary to be converged" \
    '--require-dmz-boundary-noop'
  assert_step_in "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ plan contract before apply" \
    "pre-apply gate checks the final plan artifact after all strict modes" \
    'plan-show\.json'
  assert_step_in "$INFRA" deploy-sandbox-infra "Terraform Apply" \
    "Terraform apply consumes the checked saved plan" \
    'terraform apply -auto-approve tfplan'
  assert_step_in "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ post-apply idempotency" \
    "post-apply gate requires an empty detailed-exitcode plan" \
    'terraform plan -detailed-exitcode'
  assert_step_in "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ post-apply idempotency" \
    "post-apply plan is rechecked against the final DMZ contract" \
    '--require-pr0-applied relay-dmz-post-apply\.json'
  assert_step_not_in "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ post-apply idempotency" \
    "post-apply validation does not require a no-op boundary twice" \
    '--require-dmz-boundary-noop'
  assert_step_not_in "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ post-apply idempotency" \
    "post-apply validation cannot use bootstrap tolerance" \
    '--allow-disabled'
  assert_step_not_in "$INFRA" deploy-sandbox-infra "Terraform Apply" \
    "Terraform apply has no unchecked fresh-plan fallback" \
    'terraform apply -auto-approve[[:space:]]*$'
fi

PLAN_JOB=$(extract_job_from "$PLAN_WF" terraform-plan)
if [[ -z "$PLAN_JOB" ]]; then
  report_fail "terraform PR-plan job exists" \
    "no '  terraform-plan:' job header found in terraform-plan-pr.yml"
else
  report_pass "terraform PR-plan job exists"
  assert_step_in "$PLAN_JOB" terraform-plan \
    "Check relay DMZ plan contract" \
    "PR plan invokes the relay DMZ checker" \
    'check-relay-dmz-plan\.py tfplan\.json'
  for strict_flag in --require-pr0-applied --require-dmz-boundary-noop --allow-disabled; do
    assert_step_not_in "$PLAN_JOB" terraform-plan \
      "Check relay DMZ plan contract" \
      "PR plan remains observation-only without $strict_flag" \
      "$strict_flag"
  done
fi

if grep -R -Eq -- '--allow-disabled' "$REPO_ROOT/.github/workflows"; then
  report_fail "deployed workflows never use bootstrap-only --allow-disabled" \
    "found --allow-disabled in a workflow caller"
else
  report_pass "deployed workflows never use bootstrap-only --allow-disabled"
fi

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
  # SC2016: $NEW_SHA is literal workflow text in the grep pattern.
  # shellcheck disable=SC2016
  assert_step_in "$VALIDATE" deploy-sandbox-validate "Update Deployment Tracking" "deployment tracking re-checks live app image drift" \
    'verify-live-app-images-ready\.sh sandbox "\$NEW_SHA"'
  assert_step_in "$VALIDATE" deploy-sandbox-validate "Update Deployment Tracking" "deployment tracking refuses stale live app images" \
    'verify-live-app-images-ready\.sh'
  assert_in "$VALIDATE" deploy-sandbox-validate "relay smoke uses the SSM-resolved qurl link URL" \
    'QURL_LINK_URL:.*qurl-domain-sandbox\.outputs\.qurl_link_url'
  # SC2016: the $QURL_LINK_URL in the grep pattern is literal workflow text.
  # shellcheck disable=SC2016
  assert_in "$VALIDATE" deploy-sandbox-validate "relay smoke invokes qurl-relay-bootstrap-smoke helper" \
    'node scripts/qurl-relay-bootstrap-smoke\.mjs "\$QURL_LINK_URL"'
fi

RELAY=$(extract_job deploy-sandbox-relay)
if [[ -z "$RELAY" ]]; then
  report_fail "deploy-sandbox-relay job exists" \
    "no '  deploy-sandbox-relay:' job header found in build-and-push.yml"
else
  assert_in "$RELAY" deploy-sandbox-relay "relay deploy waits for app-image build classification" \
    'needs:.*app-image-build-required'
  assert_step_in "$RELAY" deploy-sandbox-relay "Deploy relay (SSM image-tag + ASG instance refresh)" "relay treats stale live app images as app-changed" \
    'APP_IMAGE_BUILD_REQUIRED'
  assert_in "$RELAY" deploy-sandbox-relay "relay job timeout covers refresh plus functional DMZ retry budget" \
    'timeout-minutes: 35'
  assert_step_order "$RELAY" deploy-sandbox-relay \
    "Verify AWS CLI major for relay DMZ detector" \
    "Verify relay DMZ functional boundary" \
    "AWS CLI major is fenced before the functional live detector"
  assert_step_in "$RELAY" deploy-sandbox-relay \
    "Verify AWS CLI major for relay DMZ detector" \
    "functional detector accepts only AWS CLI v2 stderr contracts" \
    '\^aws-cli/2\\\.'
  assert_step_in "$RELAY" deploy-sandbox-relay "Verify relay DMZ functional boundary" "functional DMZ gate retains its 10-minute retry budget" \
    'check-relay-dmz-live\.py --mode functional --environment sandbox --wait-seconds 600'
fi

BLUEGREEN=$(extract_job deploy-sandbox-blue-green)
if [[ -z "$BLUEGREEN" ]]; then
  report_fail "deploy-sandbox-blue-green job exists" \
    "no '  deploy-sandbox-blue-green:' job header found in build-and-push.yml"
else
  assert_in "$BLUEGREEN" deploy-sandbox-blue-green "blue/green waits for build and drift detection" \
    'needs:.*app-image-build-required.*build'
  assert_step_in "$BLUEGREEN" deploy-sandbox-blue-green "Resolve Image Tag" "blue/green deploys github.sha when app image drift requires it" \
    'APP_IMAGE_BUILD_REQUIRED'
fi

NOTIFY=$(extract_job notify)
if [[ -z "$NOTIFY" ]]; then
  report_fail "notify job exists" \
    "no '  notify:' job header found in build-and-push.yml"
else
  assert_in "$NOTIFY" notify "notify waits on sandbox environment guard" \
    'sandbox-environment-guard'
  assert_in "$NOTIFY" notify "notify reports the single app-image build classification output" \
    'APP_REBUILT: \$\{\{ needs\.app-image-build-required\.outputs\.app_image_build_required \}\}'
fi

echo
echo "  passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
