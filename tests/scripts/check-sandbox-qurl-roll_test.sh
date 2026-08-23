#!/usr/bin/env bash
# check-sandbox-qurl-roll_test.sh — regression guard for #1634.
# ----------------------------------------------------------------------------
# build-and-push.yml's sandbox TF apply registers a new qurl-service task-def
# revision when a qurl env var changes, but aws_ecs_service.qurl carries
# lifecycle.ignore_changes = [task_definition] — so the running service never
# advances unless CI rolls it. Prod (promote-to-prod.yml deploy-qurl) did;
# sandbox did not, so env-var changes silently no-op'd until a downstream
# consumer 403'd (qurl-service #335). The deploy-sandbox-qurl job closes that
# gap. It must also hold qurl-service's shared sandbox live-environment lock
# across every possible ECS mutation (#3244), so an NHP main roll cannot replace
# an exact PR image during the mandatory pre-merge qv2 proof. The server/AC
# blue-green workflow holds that same cross-repo mutex because the qv2 proof
# also requires a stable NHP admission boundary. The same validate job now also
# owns the qURL JS-agent → relay bootstrap
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
BLUE_GREEN_WF="$REPO_ROOT/.github/workflows/blue-green-deploy.yml"
PLAN_WF="$REPO_ROOT/.github/workflows/terraform-plan-pr.yml"
ECR_MODULE_PATH="$REPO_ROOT/terraform/modules/ecr/main.tf"
LOCK_RUNBOOK_PATH="$REPO_ROOT/docs/runbooks/sandbox-live-env-lock.md"
RUNBOOK_INDEX_PATH="$REPO_ROOT/docs/runbooks/README.md"
BLUE_GREEN_LOCK_CLASSIFIER="$REPO_ROOT/.github/scripts/classify-blue-green-lock-release.sh"

pass=0
fail=0
report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"; }

if [[ ! -f "$WF" ]]; then
  report_fail "workflow present" "build-and-push.yml not found at $WF"
  echo; echo "  passed: $pass  failed: $fail"; exit 1
fi
if [[ ! -f "$BLUE_GREEN_WF" ]]; then
  report_fail "blue/green workflow present" "blue-green-deploy.yml not found at $BLUE_GREEN_WF"
  echo; echo "  passed: $pass  failed: $fail"; exit 1
fi
if [[ ! -f "$BLUE_GREEN_LOCK_CLASSIFIER" ]]; then
  report_fail "blue/green lock classifier present" \
    "classify-blue-green-lock-release.sh not found at $BLUE_GREEN_LOCK_CLASSIFIER"
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

pattern_precedes_pattern() {
  local block="$1" before_re="$2" after_re="$3"
  local before_line after_line
  # Every matching guard invocation must precede the first mutation. Using the
  # last guard match prevents an earlier valid call from masking a later one.
  before_line=$(grep -nE -- "$before_re" <<< "$block" | tail -n1 | cut -d: -f1)
  after_line=$(grep -nE -- "$after_re" <<< "$block" | head -n1 | cut -d: -f1)
  [[ -n "$before_line" && -n "$after_line" && "$before_line" -lt "$after_line" ]]
}

assert_pattern_order() {
  local block="$1" scope="$2" before_re="$3" after_re="$4" label="$5"
  if pattern_precedes_pattern "$block" "$before_re" "$after_re"; then
    report_pass "$label"
  else
    report_fail "$label" "ordered patterns missing or reversed in $scope: before='$before_re' after='$after_re'"
  fi
}

# These are shared by the matcher self-tests and the real workflow assertion so
# the fixtures cannot silently exercise a more permissive pattern.
BOUNDARY_PREFLIGHT_CALL_RE='^[[:space:]]+preflight_relay_dmz_boundary[[:space:]]*$'
# SC2016: $att is literal workflow text in the matcher pattern.
# shellcheck disable=SC2016
STATE_MUTATION_RE='terraform state rm "\$att"'

echo "check-sandbox-qurl-roll:"

# Execute the same classifier used by the workflow. These table cases protect
# semantic outcomes that regex-only workflow checks cannot prove.
run_lock_classifier_case() {
  local expected=$1 label=$2
  shift 2
  local actual
  if ! actual=$(bash "$BLUE_GREEN_LOCK_CLASSIFIER" "$@"); then
    report_fail "$label" "classifier exited nonzero"
  elif [[ "$actual" == "$expected" ]]; then
    report_pass "$label"
  else
    report_fail "$label" "expected safe_to_release=$expected, got $actual"
  fi
}

# args: action dry-run prepare deploy switch validate scale-down server ac
run_lock_classifier_case true "lock classifier releases a true dry run" \
  deploy true success skipped success skipped skipped true true
run_lock_classifier_case true "lock classifier releases a pre-mutation prepare failure" \
  deploy false failure skipped skipped skipped skipped false false
run_lock_classifier_case true "lock classifier releases a read-only no-component no-op" \
  deploy false success skipped skipped skipped skipped false false
run_lock_classifier_case true "lock classifier releases a fully verified deploy" \
  deploy false success success success success success true true
run_lock_classifier_case true "lock classifier releases successful prepare-only standby work" \
  prepare-only false success success skipped skipped skipped true true
run_lock_classifier_case false "lock classifier retains a deploy with skipped validation" \
  deploy false success success success skipped success true true
run_lock_classifier_case false "lock classifier retains a deploy before scale-down convergence" \
  deploy false success success success success failure true true
run_lock_classifier_case false "lock classifier retains a failed traffic switch" \
  deploy false success success failure skipped skipped true false
run_lock_classifier_case true "lock classifier releases a validated rollback" \
  rollback false success skipped success success skipped true false
run_lock_classifier_case true "lock classifier releases a validated switch-only run" \
  switch-only false success skipped success success skipped false true
run_lock_classifier_case false "lock classifier retains a rollback with skipped validation" \
  rollback false success skipped success skipped skipped true false
run_lock_classifier_case false "lock classifier retains an unknown mutating action" \
  unexpected false success success success success success true true

if grep -Eq 'relay_dmz_''cutover|RELAY_DMZ_''CUTOVER' "$WF"; then
  report_fail "one-time relay DMZ cutover authorization is removed" \
    "build-and-push.yml still contains a standing relay DMZ cutover bypass"
else
  report_pass "one-time relay DMZ cutover authorization is removed"
fi

ORDER_MATCHER_REINDENTED_FIXTURE=$'  preflight_relay_dmz_boundary() {\n    :\n  }\n\tpreflight_relay_dmz_boundary\n  terraform state rm "$att"'
if pattern_precedes_pattern "$ORDER_MATCHER_REINDENTED_FIXTURE" \
  "$BOUNDARY_PREFLIGHT_CALL_RE" "$STATE_MUTATION_RE"; then
  report_pass "order matcher tolerates invocation reindentation"
else
  report_fail "order matcher tolerates invocation reindentation" \
    "reindented call was not found before the state mutation"
fi

ORDER_MATCHER_DEFINITION_ONLY_FIXTURE=$'  preflight_relay_dmz_boundary() {\n    :\n  }\n  terraform state rm "$att"'
if pattern_precedes_pattern "$ORDER_MATCHER_DEFINITION_ONLY_FIXTURE" \
  "$BOUNDARY_PREFLIGHT_CALL_RE" "$STATE_MUTATION_RE"; then
  report_fail "order matcher rejects a function definition as an invocation" \
    "definition-only fixture satisfied the invocation-before-mutation guard"
else
  report_pass "order matcher rejects a function definition as an invocation"
fi

ORDER_MATCHER_POST_MUTATION_CALL_FIXTURE=$'  preflight_relay_dmz_boundary\n  terraform state rm "$att"\n  preflight_relay_dmz_boundary'
if pattern_precedes_pattern "$ORDER_MATCHER_POST_MUTATION_CALL_FIXTURE" \
  "$BOUNDARY_PREFLIGHT_CALL_RE" "$STATE_MUTATION_RE"; then
  report_fail "order matcher rejects an invocation after state mutation" \
    "an earlier valid call masked a second call after the state mutation"
else
  report_pass "order matcher rejects an invocation after state mutation"
fi

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
  assert_pattern_order "$RECOVERY_STEP" "deploy-sandbox-infra recovery step" \
    "$BOUNDARY_PREFLIGHT_CALL_RE" "$STATE_MUTATION_RE" \
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
    "recovery preflight admits only the reviewed UDP source-fence replacement" \
    '--allow-udp-source-fence-replacement'
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
    "AWS CLI major is fenced immediately after the checked apply"
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
    "pre-apply gate admits only the reviewed UDP source-fence replacement" \
    '--allow-udp-source-fence-replacement'
  assert_step_in "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ plan contract before apply" \
    "pre-apply gate checks the final plan artifact after all strict modes" \
    'plan-show\.json'
  assert_step_in "$INFRA" deploy-sandbox-infra "Terraform Apply" \
    "Terraform apply consumes the checked saved plan" \
    'terraform apply -auto-approve tfplan'
  assert_step_in "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ post-apply idempotency" \
    "post-apply gate creates a saved plan for exact JSON validation" \
    'terraform plan -no-color'
  assert_step_not_in "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ post-apply idempotency" \
    "post-apply gate does not trust setup-terraform detailed-exitcode" \
    'detailed-exitcode|PIPESTATUS|plan_rc'
  assert_step_in "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ post-apply idempotency" \
    "post-apply plan is rechecked against the final DMZ contract" \
    '--require-pr0-applied'
  assert_step_in "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ post-apply idempotency" \
    "post-apply validation fails closed on every fenced DMZ mutation" \
    '--require-dmz-boundary-noop'
  assert_step_in "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ post-apply idempotency" \
    "post-apply validation requires the converged UDP source-fenced topology" \
    '--require-udp-source-fenced-topology'
  assert_step_not_in "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ post-apply idempotency" \
    "post-apply validation removes the UDP source-fence replacement allowance" \
    '--allow-udp-source-fence-replacement'
  assert_step_not_in "$INFRA" deploy-sandbox-infra \
    "Verify relay DMZ post-apply idempotency" \
    "post-apply validation cannot use bootstrap tolerance" \
    '--allow-disabled'
  assert_step_not_in "$INFRA" deploy-sandbox-infra "Terraform Apply" \
    "Terraform apply has no unchecked fresh-plan fallback" \
    'terraform apply -auto-approve[[:space:]]*$'
  assert_step_in "$INFRA" deploy-sandbox-infra "Get Terraform Outputs" \
    "infra outputs read Terraform state once as JSON" \
    'terraform output -json'
  assert_step_not_in "$INFRA" deploy-sandbox-infra "Get Terraform Outputs" \
    "nullable etcd output cannot leak a setup-terraform diagnostic" \
    'terraform output -raw etcd_endpoint'
  assert_step_in "$INFRA" deploy-sandbox-infra "Get Terraform Outputs" \
    "nullable etcd output becomes an empty integration-test endpoint" \
    '\.etcd_endpoint\.value // empty'
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
    'check-relay-dmz-plan\.py'
  assert_step_in "$PLAN_JOB" terraform-plan \
    "Check relay DMZ plan contract" \
    "PR plan checks its saved plan artifact" \
    'tfplan\.json'
  assert_step_in "$PLAN_JOB" terraform-plan \
    "Check relay DMZ plan contract" \
    "PR plan fails closed outside the reviewed DMZ migration" \
    '--require-dmz-boundary-noop'
  assert_step_in "$PLAN_JOB" terraform-plan \
    "Check relay DMZ plan contract" \
    "PR plan admits only the reviewed UDP source-fence replacement" \
    '--allow-udp-source-fence-replacement'
  for strict_flag in --require-pr0-applied --allow-disabled; do
    assert_step_not_in "$PLAN_JOB" terraform-plan \
      "Check relay DMZ plan contract" \
      "PR plan does not use $strict_flag" \
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

# Cross-repo live-environment mutex (#3244). The local action and helpers are
# byte-for-byte copies of qurl-service@d506fa61; the Python contract test verifies
# the provenance manifest, hashes, schema, and runtime behavior. Acquire before
# any roll path, release the same owner only after verified success/no-op, and
# retain it after an unverified outcome.
# The two-hour waiter remains below the four-hour stale TTL, while the
# three-hour job timeout leaves deployment headroom.
LOCK_ACTION='uses: \./\.github/actions/sandbox-live-env-lock'
assert_in "$JOB" deploy-sandbox-qurl "qURL sandbox lock uses the vendored producer action" \
  "$LOCK_ACTION"
assert_in "$JOB" deploy-sandbox-qurl "qURL sandbox lock uses the shared SSM parameter" \
  'ssm-parameter-name: /layerv-nhp-sandbox/qurl-live-env-lock'
assert_step_in "$JOB" deploy-sandbox-qurl \
  "Acquire qURL sandbox live-environment lock" \
  "qURL sandbox lock acquisition uses the explicit workflow region" \
  'aws-region: \$\{\{ env\.AWS_REGION \}\}'
assert_step_in "$JOB" deploy-sandbox-qurl \
  "Release qURL sandbox live-environment lock" \
  "qURL sandbox lock release uses the explicit workflow region" \
  'aws-region: \$\{\{ env\.AWS_REGION \}\}'
assert_in "$JOB" deploy-sandbox-qurl "qURL sandbox lock owner is unique to the NHP run attempt" \
  'owner: nhp:\$\{\{ github\.run_id \}\}:\$\{\{ github\.run_attempt \}\}:deploy-sandbox-qurl'
assert_in "$JOB" deploy-sandbox-qurl "qURL sandbox lock stale TTL remains four hours" \
  "ttl-seconds: '14400'"
assert_in "$JOB" deploy-sandbox-qurl "qURL sandbox lock waiter remains two hours" \
  "wait-seconds: '7200'"
assert_in "$JOB" deploy-sandbox-qurl "qURL sandbox roll timeout covers lock wait and deployment" \
  'timeout-minutes: 180'
assert_step_in "$JOB" deploy-sandbox-qurl \
  "Configure AWS credentials" \
  "qURL sandbox AWS session covers the complete three-hour job ceiling" \
  'role-duration-seconds: 10800'
if [[ ! -f "$ECR_MODULE_PATH" ]]; then
  report_fail "qURL sandbox AWS role duration source exists" \
    "missing $ECR_MODULE_PATH"
else
  ECR_MODULE=$(<"$ECR_MODULE_PATH")
  assert_in "$ECR_MODULE" terraform/modules/ecr/main.tf \
    "qURL sandbox AWS role permits the requested three-hour session" \
    'max_session_duration = var\.environment == "sandbox" \? 10800 : 3600'
fi
assert_step_order "$JOB" deploy-sandbox-qurl \
  "Acquire qURL sandbox live-environment lock" \
  "Roll qurl-service to latest task def" \
  "qURL sandbox lock is acquired before the roll can mutate ECS"
assert_step_order "$JOB" deploy-sandbox-qurl \
  "Roll qurl-service to latest task def" \
  "Release qURL sandbox live-environment lock" \
  "qURL sandbox lock is held through the complete ECS roll"
assert_step_in "$JOB" deploy-sandbox-qurl \
  "Release qURL sandbox live-environment lock" \
  "qURL sandbox lock releases only after a verified roll success or no-op" \
  "steps\.roll-qurl\.outcome == 'success'"
assert_step_not_in "$JOB" deploy-sandbox-qurl \
  "Release qURL sandbox live-environment lock" \
  "qURL sandbox lock release failure leaves the NHP job red" \
  'continue-on-error: true'
assert_step_in "$JOB" deploy-sandbox-qurl \
  "Surface qURL sandbox lock release failure" \
  "qURL sandbox lock release failure is visible immediately" \
  "steps\.release-qurl-sandbox-live-env-lock\.outcome == 'failure'"
assert_step_order "$JOB" deploy-sandbox-qurl \
  "Release qURL sandbox live-environment lock" \
  "Retain qURL sandbox live-environment lock after roll failure" \
  "qURL sandbox failure-retention branch follows the owned release branch"
assert_step_in "$JOB" deploy-sandbox-qurl \
  "Retain qURL sandbox live-environment lock after roll failure" \
  "qURL sandbox lock is retained on every unverified roll outcome" \
  "steps\.roll-qurl\.outcome != 'success'"
assert_step_in "$JOB" deploy-sandbox-qurl \
  "Retain qURL sandbox live-environment lock after roll failure" \
  "qURL sandbox retained roll emits the dual-stream failure metric" \
  'emit-sandbox-lock-failure-metric\.sh RollFailedRetained release'
assert_step_in "$JOB" deploy-sandbox-qurl \
  "Retain qURL sandbox live-environment lock after roll failure" \
  "qURL sandbox lock retention fails independently of prior step state" \
  'exit 1'
assert_step_in "$JOB" deploy-sandbox-qurl \
  "Retain qURL sandbox live-environment lock after roll failure" \
  "qURL sandbox lock retention points operators to the recovery runbook" \
  'docs/runbooks/sandbox-live-env-lock\.md'

if [[ ! -f "$LOCK_RUNBOOK_PATH" ]]; then
  report_fail "qURL sandbox lock recovery runbook exists" \
    "missing $LOCK_RUNBOOK_PATH"
else
  report_pass "qURL sandbox lock recovery runbook exists"
  LOCK_RUNBOOK=$(<"$LOCK_RUNBOOK_PATH")
  assert_in "$LOCK_RUNBOOK" sandbox-live-env-lock.md \
    "lock runbook documents the qurl-service owner shape" \
    'qurl-service:<run_id>:<run_attempt>:<job-name>'
  assert_in "$LOCK_RUNBOOK" sandbox-live-env-lock.md \
    "lock runbook documents the NHP owner shape" \
    'nhp:<run_id>:<run_attempt>:deploy-sandbox-qurl'
  assert_in "$LOCK_RUNBOOK" sandbox-live-env-lock.md \
    "lock runbook documents the NHP blue/green owner shape" \
    'nhp:<run_id>:<run_attempt>:blue-green'
  assert_in "$LOCK_RUNBOOK" sandbox-live-env-lock.md \
    "lock runbook pins the same producer contract" \
    'd506fa61a06c7b8b18b5d69dfe65dae15bd19270'
  assert_in "$LOCK_RUNBOOK" sandbox-live-env-lock.md \
    "lock runbook documents the alarm-first dual-stream contract" \
    'A dimensionless sample drives the Terraform-managed paging alarm'
  assert_in "$LOCK_RUNBOOK" sandbox-live-env-lock.md \
    "lock runbook requires cross-repo fanout on producer changes" \
    'qurl-service/issues/1245'
  assert_in "$LOCK_RUNBOOK" sandbox-live-env-lock.md \
    "lock runbook explains why rerun cannot recover a retained lock" \
    'Re-running a failed job does not recover its retained lock'
  assert_in "$LOCK_RUNBOOK" sandbox-live-env-lock.md \
    "lock runbook documents the credential-duration safety bound" \
    'requests a 10,800-second AWS session'
  assert_in "$LOCK_RUNBOOK" sandbox-live-env-lock.md \
    "lock runbook separates proof isolation from the AC admission defect" \
    'nhp/issues/2123'
  assert_in "$LOCK_RUNBOOK" sandbox-live-env-lock.md \
    "lock runbook forbids release before stable task proof" \
    'The deployment is stable with no pending tasks'
fi

if [[ -f "$RUNBOOK_INDEX_PATH" ]] && \
  grep -Fq '[Sandbox qURL live-environment lock](sandbox-live-env-lock.md)' "$RUNBOOK_INDEX_PATH"; then
  report_pass "qURL sandbox lock runbook is indexed"
else
  report_fail "qURL sandbox lock runbook is indexed" \
    "docs/runbooks/README.md does not link sandbox-live-env-lock.md"
fi

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
    'timeout-minutes: 45'
  assert_step_order "$RELAY" deploy-sandbox-relay \
    "Verify AWS CLI major for relay DMZ detector" \
    "Verify relay DMZ functional boundary" \
    "AWS CLI major is fenced before the functional live detector"
  assert_step_in "$RELAY" deploy-sandbox-relay \
    "Verify AWS CLI major for relay DMZ detector" \
    "functional detector accepts only AWS CLI v2 stderr contracts" \
    '\^aws-cli/2\\\.'
  assert_step_in "$RELAY" deploy-sandbox-relay "Verify relay DMZ functional boundary" "functional DMZ gate uses a 20-minute retry budget for eventually-consistent GuardDuty coverage" \
    'check-relay-dmz-live\.py --mode functional --environment sandbox --wait-seconds 1200'
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

# qurl-service's exact-image smoke crosses the repository boundary, so the
# child blue/green workflow itself (not only build-and-push's dispatcher) must
# hold the shared SSM lock. This covers direct/manual dispatches and keeps the
# lock alive through post-switch validation and previous-color scale-down.
BG_ACQUIRE=$(extract_job_from "$BLUE_GREEN_WF" acquire-qurl-live-env-lock)
BG_PREPARE=$(extract_job_from "$BLUE_GREEN_WF" prepare)
BG_SCALE_DOWN=$(extract_job_from "$BLUE_GREEN_WF" scale-down-previous)
BG_FINALIZE=$(extract_job_from "$BLUE_GREEN_WF" finalize-qurl-live-env-lock)
BG_NOTIFY=$(extract_job_from "$BLUE_GREEN_WF" notify)

if [[ -z "$BG_ACQUIRE" ]]; then
  report_fail "blue/green lock-acquire job exists" \
    "no '  acquire-qurl-live-env-lock:' job header found in blue-green-deploy.yml"
else
  assert_in "$BG_ACQUIRE" acquire-qurl-live-env-lock "blue/green lock waiter has the full two-hour budget" \
    'timeout-minutes:[[:space:]]*180'
  assert_in "$BG_ACQUIRE" acquire-qurl-live-env-lock "blue/green lock waiter requests a three-hour AWS session" \
    'role-duration-seconds:[[:space:]]*10800'
  assert_step_in "$BG_ACQUIRE" acquire-qurl-live-env-lock "Acquire sandbox live-environment lock" "blue/green acquires the shared qURL SSM mutex" \
    'ssm-parameter-name:[[:space:]]*/layerv-nhp-sandbox/qurl-live-env-lock'
  assert_step_in "$BG_ACQUIRE" acquire-qurl-live-env-lock "Acquire sandbox live-environment lock" "blue/green owner is exact-run scoped" \
    'owner:[[:space:]]*nhp:\$\{\{ github\.run_id \}\}:\$\{\{ github\.run_attempt \}\}:blue-green'
  assert_step_in "$BG_ACQUIRE" acquire-qurl-live-env-lock "Acquire sandbox live-environment lock" "blue/green lock keeps the canonical TTL" \
    "ttl-seconds:[[:space:]]*'14400'"
  assert_step_in "$BG_ACQUIRE" acquire-qurl-live-env-lock "Acquire sandbox live-environment lock" "blue/green lock keeps the canonical wait budget" \
    "wait-seconds:[[:space:]]*'7200'"
fi

if [[ -z "$BG_PREPARE" ]]; then
  report_fail "blue/green prepare job exists" \
    "no '  prepare:' job header found in blue-green-deploy.yml"
else
  assert_in "$BG_PREPARE" prepare "blue/green prepare cannot race ahead of lock acquisition" \
    'needs:[[:space:]]*acquire-qurl-live-env-lock'
fi

if [[ -z "$BG_SCALE_DOWN" ]]; then
  report_fail "blue/green scale-down job exists" \
    "no '  scale-down-previous:' job header found in blue-green-deploy.yml"
else
  assert_in "$BG_SCALE_DOWN" scale-down-previous "old-color convergence has a bounded job budget" \
    'timeout-minutes:[[:space:]]*10'
  assert_step_in "$BG_SCALE_DOWN" scale-down-previous "Wait for Previous Colors to Reach Warm Standby" "old-color convergence uses a bounded state deadline" \
    'deadline=\$\(\(SECONDS \+ 300\)\)'
  assert_step_in "$BG_SCALE_DOWN" scale-down-previous "Wait for Previous Colors to Reach Warm Standby" "old-color convergence checks actual instance count" \
    'length\(Instances\)'
  assert_step_in "$BG_SCALE_DOWN" scale-down-previous "Wait for Previous Colors to Reach Warm Standby" "old-color convergence requires one healthy InService instance" \
    'healthy_in_service.*==.*1'
  assert_step_in "$BG_SCALE_DOWN" scale-down-previous "Wait for Previous Colors to Reach Warm Standby" "old-color convergence reports a bounded timeout" \
    'did not reach one healthy InService warm-standby instance within 300 seconds'
  assert_step_in "$BG_SCALE_DOWN" scale-down-previous "Wait for Previous Colors to Reach Warm Standby" "old-color convergence fails closed" \
    'exit 1'
fi

if [[ -z "$BG_FINALIZE" ]]; then
  report_fail "blue/green lock-finalize job exists" \
    "no '  finalize-qurl-live-env-lock:' job header found in blue-green-deploy.yml"
else
  # Unconditional always(): the acquire job can be cancelled after it has already
  # written the SSM parameter, so gating finalization on that job's result leaks
  # the lock for its full TTL. Exact-owner release makes the ungated run safe.
  assert_in "$BG_FINALIZE" finalize-qurl-live-env-lock "blue/green lock finalization runs after failed, cancelled, or unacquired dependencies" \
    "if: always\(\)$"
  for dependency in prepare deploy-to-standby switch-traffic validate scale-down-previous; do
    assert_in "$BG_FINALIZE" finalize-qurl-live-env-lock "blue/green lock finalize waits for $dependency" \
      "-[[:space:]]*$dependency"
  done
  assert_step_in "$BG_FINALIZE" finalize-qurl-live-env-lock "Classify blue/green terminal state" "workflow invokes the executable lock classifier" \
    'classify-blue-green-lock-release\.sh'
  assert_step_in "$BG_FINALIZE" finalize-qurl-live-env-lock "Classify blue/green terminal state" "classifier receives component mutation flags" \
    'DEPLOY_SERVER.*DEPLOY_AC'
  assert_step_in "$BG_FINALIZE" finalize-qurl-live-env-lock "Release sandbox live-environment lock" "blue/green releases only its exact owner" \
    'owner:[[:space:]]*nhp:\$\{\{ github\.run_id \}\}:\$\{\{ github\.run_attempt \}\}:blue-green'
  assert_step_in "$BG_FINALIZE" finalize-qurl-live-env-lock "Retain sandbox live-environment lock after blue/green failure" "failed blue/green emits shared retained-lock telemetry" \
    'emit-sandbox-lock-failure-metric\.sh RollFailedRetained release'
  assert_step_in "$BG_FINALIZE" finalize-qurl-live-env-lock "Retain sandbox live-environment lock after blue/green failure" "failed blue/green retention remains red" \
    'exit 1'
fi

if [[ -z "$BG_NOTIFY" ]]; then
  report_fail "blue/green notify job exists" \
    "no '  notify:' job header found in blue-green-deploy.yml"
else
  assert_in "$BG_NOTIFY" notify "blue/green notification waits for lock finalization" \
    'needs:.*finalize-qurl-live-env-lock'
  assert_in "$BG_NOTIFY" notify "blue/green notification surfaces lock failure" \
    'FAILED \(sandbox live-environment lock\)'
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
