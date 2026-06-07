#!/usr/bin/env bash
# check-sandbox-qurl-roll_test.sh — regression guard for #1634.
# ----------------------------------------------------------------------------
# build-and-push.yml's sandbox TF apply registers a new qurl-service task-def
# revision when a qurl env var changes, but aws_ecs_service.qurl carries
# lifecycle.ignore_changes = [task_definition] — so the running service never
# advances unless CI rolls it. Prod (promote-to-prod.yml deploy-qurl) did;
# sandbox did not, so env-var changes silently no-op'd until a downstream
# consumer 403'd (qurl-service #335). The deploy-sandbox-qurl job closes that
# gap. This test fails if the load-bearing pieces of that job regress or are
# removed, so the gap cannot silently reopen.
#
# Asserted against the REAL build-and-push.yml (not a fixture) — the invariants
# are simple presence checks, not subtle ordering, so a real-tree assertion is
# the proportionate guard. The job block is extracted by awk and each assertion
# is scoped to it, so an unrelated match elsewhere in the file cannot satisfy a
# check (and a future reorder that moves these lines OUT of the job fails loud).
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
  if printf '%s\n' "$block" | grep -Eq -- "$re"; then
    report_pass "$label"
  else
    report_fail "$label" "pattern not found in $job job: $re"
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
  'ParameterNotFound'

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
fi

echo
echo "  passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
