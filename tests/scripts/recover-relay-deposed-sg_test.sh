#!/usr/bin/env bash
# Fixture tests for .github/scripts/recover-relay-deposed-sg.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCRIPT="$REPO_ROOT/.github/scripts/recover-relay-deposed-sg.sh"

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

PASS=0
FAIL=0

report_pass() {
  echo "PASS: $1"
  PASS=$((PASS + 1))
}

report_fail() {
  echo "FAIL: $1 - $2" >&2
  FAIL=$((FAIL + 1))
}

make_fixture_repo() {
  local dir="$1"
  mkdir -p "$dir/endpoints" "$dir/terraform"
  git -C "$dir" init -q
  git -C "$dir" config user.email test@example.com
  git -C "$dir" config user.name "Test User"

  echo "package relay" > "$dir/endpoints/relay.go"
  git -C "$dir" add endpoints/relay.go
  git -C "$dir" commit -q -m "app"
  APP_SHA="$(git -C "$dir" rev-parse HEAD)"

  echo "# infra" > "$dir/terraform/main.tf"
  git -C "$dir" add terraform/main.tf
  git -C "$dir" commit -q -m "infra"
  INFRA_SHA="$(git -C "$dir" rev-parse HEAD)"
}

make_stubs() {
  local dir="$1"
  mkdir -p "$dir/bin"
  cat > "$dir/bin/aws" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$AWS_LOG"
tag=""
for arg in "$@"; do
  case "$arg" in
    imageTag=*) tag="${arg#imageTag=}" ;;
  esac
done
if [[ "${AWS_DESCRIBE_FAIL:-}" == "1" ]]; then
  echo "An error occurred (ThrottlingException) when calling the DescribeImages operation: throttled" >&2
  exit 42
elif [[ "${AWS_DESCRIBE_FAIL:-}" == "flaky" ]]; then
  count_file="${AWS_LOG}.describe-count"
  count=0
  [[ -f "$count_file" ]] && count=$(cat "$count_file")
  if (( count < AWS_DESCRIBE_FAIL_COUNT )); then
    printf '%s' "$((count + 1))" > "$count_file"
    echo "An error occurred (ThrottlingException) when calling the DescribeImages operation: throttled" >&2
    exit 42
  fi
elif [[ "${AWS_DESCRIBE_FAIL:-}" == "repo" ]]; then
  echo "An error occurred (RepositoryNotFoundException) when calling the DescribeImages operation: The repository with name layerv/nhp-relay does not exist in the registry." >&2
  exit 254
fi
if [[ "${1:-}" == "ssm" && "${2:-}" == "get-parameter" ]]; then
  if [[ "${AWS_CURRENT_TAG:-}" == "__missing__" ]]; then
    echo "An error occurred (ParameterNotFound) when calling the GetParameter operation: Parameter not found" >&2
    exit 254
  fi
  printf '%s\n' "${AWS_CURRENT_TAG:-}"
  exit 0
fi
if [[ "${1:-}" == "ecr" && "${2:-}" == "describe-images" ]]; then
  if [[ -n "${AWS_PRESENT_TAG:-}" && "$tag" != "$AWS_PRESENT_TAG" ]]; then
    echo "An error occurred (ImageNotFoundException) when calling the DescribeImages operation: The image with imageId {imageTag: $tag} does not exist within the repository." >&2
    exit 254
  fi
  exit 0
fi
echo "unexpected aws call: $*" >&2
exit 2
STUB
  chmod +x "$dir/bin/aws"

  cat > "$dir/deploy-helper" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$HELPER_LOG"
STUB
  chmod +x "$dir/deploy-helper"
}

run_recovery() {
  local name="$1" repo="$2" app_changed="$3" image_tag="$4" present_tag="${5:-}" aws_fail="${6:-0}"
  local aws_fail_count="${7:-1}"
  local current_tag="${8:-}"
  local aws_bin_override="${9:-}"
  local environment="${10:-sandbox}"
  local allow_prod="${11:-0}"
  local dir="$TMP_ROOT/$name"
  local recovery_aws_bin="aws"
  mkdir -p "$dir"
  make_stubs "$dir"
  if [[ "$aws_bin_override" == "custom" ]]; then
    ln -s "$dir/bin/aws" "$dir/bin/custom-aws"
    recovery_aws_bin="$dir/bin/custom-aws"
  fi
  AWS_LOG="$dir/aws.log" \
  HELPER_LOG="$dir/helper.log" \
  GITHUB_STEP_SUMMARY="$dir/summary.md" \
  AWS_DESCRIBE_FAIL="$aws_fail" \
  AWS_DESCRIBE_FAIL_COUNT="$aws_fail_count" \
  AWS_PRESENT_TAG="$present_tag" \
  AWS_CURRENT_TAG="$current_tag" \
  AWS_REGION="us-east-2" \
  PATH="$dir/bin:$PATH" \
  RECOVERY_CANDIDATE_LIMIT="${RECOVERY_CANDIDATE_LIMIT_OVERRIDE:-10}" \
  RECOVERY_ECR_LOOKUP_RETRY_DELAY_SECS=0 \
  RECOVER_RELAY_ALLOW_PROD="$allow_prod" \
  RECOVER_RELAY_AWS_BIN="$recovery_aws_bin" \
  RECOVER_RELAY_REPO_ROOT="$repo" \
  RECOVER_RELAY_DEPLOY_HELPER="$dir/deploy-helper" \
    "$SCRIPT" "$environment" "$app_changed" "$image_tag" > "$dir/out.log" 2> "$dir/err.log"
}

assert_success() {
  local name="$1" repo="$2" app_changed="$3" image_tag="$4"
  local present_tag="${5:-}" aws_fail="${6:-0}" aws_fail_count="${7:-1}"
  local current_tag="${8:-}" aws_bin_override="${9:-}"
  if run_recovery "$name" "$repo" "$app_changed" "$image_tag" "$present_tag" "$aws_fail" "$aws_fail_count" "$current_tag" "$aws_bin_override"; then
    report_pass "$name exits 0"
  else
    report_fail "$name exits 0" "script failed"
  fi
}

assert_failure() {
  local name="$1" repo="$2" app_changed="$3" image_tag="$4"
  local present_tag="${5:-}" aws_fail="${6:-1}"
  local aws_fail_count="${7:-1}"
  if run_recovery "$name" "$repo" "$app_changed" "$image_tag" "$present_tag" "$aws_fail" "$aws_fail_count"; then
    report_fail "$name exits nonzero" "script unexpectedly succeeded"
  else
    report_pass "$name exits nonzero"
  fi
}

assert_file_contains() {
  local name="$1" path="$2" needle="$3"
  if [[ ! -f "$path" ]]; then
    report_fail "$name" "missing file $path"
    return
  fi
  if grep -Fq "$needle" "$path"; then
    report_pass "$name"
  else
    report_fail "$name" "expected '$needle' in $path; got: $(cat "$path")"
  fi
}

assert_file_absent() {
  local name="$1" path="$2"
  if [[ -e "$path" ]]; then
    report_fail "$name" "unexpected file $path with: $(cat "$path")"
  else
    report_pass "$name"
  fi
}

FIXTURE_REPO="$TMP_ROOT/repo"
make_fixture_repo "$FIXTURE_REPO"

WORKFLOW_SHA="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ABSENT_SHA="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

if run_recovery "prod-refuses-without-override" "$FIXTURE_REPO" true "$WORKFLOW_SHA" "$WORKFLOW_SHA" 0 1 "" "" prod; then
  report_fail "prod recovery refuses without override" "script unexpectedly succeeded"
else
  report_pass "prod recovery refuses without override"
fi
assert_file_contains "prod refusal explains override" "$TMP_ROOT/prod-refuses-without-override/err.log" "RECOVER_RELAY_ALLOW_PROD=1"
assert_file_absent "prod refusal does not inspect AWS" "$TMP_ROOT/prod-refuses-without-override/aws.log"
assert_file_absent "prod refusal does not deploy" "$TMP_ROOT/prod-refuses-without-override/helper.log"

if run_recovery "prod-override-allows" "$FIXTURE_REPO" true "$WORKFLOW_SHA" "$WORKFLOW_SHA" 0 1 "" "" prod 1; then
  report_pass "prod override allows recovery"
else
  report_fail "prod override allows recovery" "script failed"
fi
assert_file_contains "prod override deploys prod helper call" "$TMP_ROOT/prod-override-allows/helper.log" "prod true $WORKFLOW_SHA"

assert_success "app-changed-tag" "$FIXTURE_REPO" true "$WORKFLOW_SHA"
assert_file_contains "app-changed verifies workflow tag" "$TMP_ROOT/app-changed-tag/aws.log" "imageTag=$WORKFLOW_SHA"
assert_file_contains "app-changed deploys workflow tag" "$TMP_ROOT/app-changed-tag/helper.log" "sandbox true $WORKFLOW_SHA"

assert_failure "app-changed-missing-ecr-image" "$FIXTURE_REPO" true "$WORKFLOW_SHA" "$ABSENT_SHA" 0
assert_file_contains "app-changed missing image reports absent tag" "$TMP_ROOT/app-changed-missing-ecr-image/err.log" "was not found in ECR"
assert_file_absent "app-changed missing image does not deploy" "$TMP_ROOT/app-changed-missing-ecr-image/helper.log"

assert_failure "invalid-workflow-tag" "$FIXTURE_REPO" true "not-a-sha" "" 0
assert_file_contains "invalid workflow tag reports SHA shape" "$TMP_ROOT/invalid-workflow-tag/err.log" "not a full lowercase git SHA"
assert_file_absent "invalid workflow tag does not deploy" "$TMP_ROOT/invalid-workflow-tag/helper.log"

RECOVERY_CANDIDATE_LIMIT_OVERRIDE=invalid \
  assert_failure "invalid-candidate-limit" "$FIXTURE_REPO" false "$INFRA_SHA" "" 0
assert_file_contains "invalid candidate limit reports config error" "$TMP_ROOT/invalid-candidate-limit/err.log" "RECOVERY_CANDIDATE_LIMIT must be a positive integer"

assert_success "infra-recovers-latest-app-tag" "$FIXTURE_REPO" false "$INFRA_SHA" "$APP_SHA"
assert_file_contains "infra recovery checks head candidate first" "$TMP_ROOT/infra-recovers-latest-app-tag/aws.log" "imageTag=$INFRA_SHA"
assert_file_contains "infra recovery verifies latest app tag" "$TMP_ROOT/infra-recovers-latest-app-tag/aws.log" "imageTag=$APP_SHA"
assert_file_contains "infra recovery deploys latest app tag" "$TMP_ROOT/infra-recovers-latest-app-tag/helper.log" "sandbox true $APP_SHA"

assert_success "infra-recovers-push-head-tag" "$FIXTURE_REPO" false "$INFRA_SHA" "$INFRA_SHA"
assert_file_contains "infra recovery deploys push-head tag" "$TMP_ROOT/infra-recovers-push-head-tag/helper.log" "sandbox true $INFRA_SHA"

assert_success "aws-bin-override" "$FIXTURE_REPO" false "$INFRA_SHA" "$INFRA_SHA" 0 1 "" "custom"
assert_file_contains "aws bin override still verifies image" "$TMP_ROOT/aws-bin-override/aws.log" "imageTag=$INFRA_SHA"

assert_success "infra-warns-on-ssm-tag-override" "$FIXTURE_REPO" false "$INFRA_SHA" "$INFRA_SHA" 0 1 "$APP_SHA"
assert_file_contains "infra recovery warns before overriding current SSM tag" "$TMP_ROOT/infra-warns-on-ssm-tag-override/err.log" "will update /sandbox/nhp/relay/image-tag from current SSM image tag $APP_SHA to recovery image tag $INFRA_SHA"
assert_file_contains "infra recovery records override warning summary" "$TMP_ROOT/infra-warns-on-ssm-tag-override/summary.md" "current relay image tag \`$APP_SHA\` will be replaced"

assert_success "ecr-transient-error-retries" "$FIXTURE_REPO" false "$INFRA_SHA" "$INFRA_SHA" "flaky" 1
assert_file_contains "transient ECR error reports retry" "$TMP_ROOT/ecr-transient-error-retries/err.log" "retrying (1/3)"
assert_file_contains "transient ECR retry still deploys" "$TMP_ROOT/ecr-transient-error-retries/helper.log" "sandbox true $INFRA_SHA"

assert_failure "absent-image-exhausts-candidates" "$FIXTURE_REPO" false "$INFRA_SHA" "$ABSENT_SHA" 0
assert_file_contains "absent image reports candidate exhaustion" "$TMP_ROOT/absent-image-exhausts-candidates/err.log" "latest 10 commit(s)"
assert_file_absent "absent image does not deploy" "$TMP_ROOT/absent-image-exhausts-candidates/helper.log"

SHALLOW_REPO="$TMP_ROOT/shallow-repo"
git clone -q --depth=1 "file://$FIXTURE_REPO" "$SHALLOW_REPO"
assert_failure "shallow-checkout-exhaustion" "$SHALLOW_REPO" false "$INFRA_SHA" "$ABSENT_SHA" 0
assert_file_contains "shallow checkout reports truncated scan" "$TMP_ROOT/shallow-checkout-exhaustion/err.log" "checkout history is shallow"

assert_failure "ecr-lookup-error" "$FIXTURE_REPO" false "$INFRA_SHA"
assert_file_contains "ECR lookup error is not treated as absent" "$TMP_ROOT/ecr-lookup-error/err.log" "ECR lookup failed while checking relay image"
assert_file_absent "ECR lookup error does not deploy" "$TMP_ROOT/ecr-lookup-error/helper.log"

assert_failure "ecr-repository-error" "$FIXTURE_REPO" false "$INFRA_SHA" "" "repo"
assert_file_contains "ECR repository error is not treated as absent" "$TMP_ROOT/ecr-repository-error/err.log" "RepositoryNotFoundException"
assert_file_absent "ECR repository error does not deploy" "$TMP_ROOT/ecr-repository-error/helper.log"

if [[ "$FAIL" -gt 0 ]]; then
  echo "$FAIL failure(s), $PASS pass(es)" >&2
  exit 1
fi

echo "$PASS pass(es)"
