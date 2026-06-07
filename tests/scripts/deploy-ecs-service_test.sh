#!/usr/bin/env bash
# deploy-ecs-service_test.sh - fixture tests for .github/scripts/deploy-ecs-service.sh
# ----------------------------------------------------------------------------
# The deploy helper must fail closed on real ECS rollbacks, but it must not
# misclassify a successful qurl-service deploy as a rollback when qurl-service's
# own CI advances the same ECS service while this helper is waiting.
#
# Each case puts fake aws/sleep commands on PATH and runs the real helper.
#
# Usage: bash tests/scripts/deploy-ecs-service_test.sh

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/deploy-ecs-service.sh"

pass=0
fail=0
failures=""
LAST_OUT=""
LAST_RC=0

report_pass() { pass=$((pass + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); failures+="  FAIL $1: $2\n"; printf '  \033[31mFAIL\033[0m %s\n      %s\n' "$1" "$2"; }

make_fake_commands() {
  local dir="$1"

  cat > "$dir/sleep" <<'SLEEP'
#!/usr/bin/env bash
exit 0
SLEEP
  chmod +x "$dir/sleep"

  cat > "$dir/aws" <<'AWS'
#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="${FAKE_AWS_STATE_DIR:?}"
ACCOUNT="767397897469"
REGION="us-east-2"
FAMILY="layerv-nhp-sandbox-cell0-qurl-api"
REPO="$ACCOUNT.dkr.ecr.$REGION.amazonaws.com/layerv/nhp-qurl"

INITIAL_REV="${FAKE_INITIAL_REV-620}"
LATEST_REV="${FAKE_LATEST_REV-621}"
REGISTERED_REV="${FAKE_REGISTERED_REV-622}"
FINAL_TASK_DEF="${FAKE_FINAL_TASK_DEF-$REGISTERED_REV}"
FINAL_FAMILY="${FAKE_FINAL_FAMILY-$FAMILY}"
SSM_IMAGE_TAG="${FAKE_SSM_IMAGE_TAG-9335f9c}"
ACTIVE_IMAGE_TAG="${FAKE_ACTIVE_IMAGE_TAG-$SSM_IMAGE_TAG}"
ACTIVE_CONTAINER_SHAPE="${FAKE_ACTIVE_CONTAINER_SHAPE-normal}"
SSM_IMAGE_TAG_ERROR="${FAKE_SSM_IMAGE_TAG_ERROR-false}"
DESCRIBE_ACTIVE_ERROR="${FAKE_DESCRIBE_ACTIVE_ERROR-false}"
REGISTER_TASKDEF_WHITESPACE="${FAKE_REGISTER_TASKDEF_WHITESPACE-false}"
REGISTER_TASKDEF_INTERIOR_WHITESPACE="${FAKE_REGISTER_TASKDEF_INTERIOR_WHITESPACE-false}"
EXPECTED_SSM_PUT_NAME="${FAKE_EXPECTED_SSM_PUT_NAME-/layerv-nhp-sandbox/qurl-api-image-tag}"
EXPECTED_SSM_PUT_VALUE="${FAKE_EXPECTED_SSM_PUT_VALUE-9335f9c}"
MAIN_ROLLOUT="${FAKE_MAIN_ROLLOUT-COMPLETED}"
MAIN_STABLE="${FAKE_MAIN_STABLE-true}"
MAIN_STABLE_AFTER_READS="${FAKE_MAIN_STABLE_AFTER_READS-1}"
MAIN_DESIRED="${FAKE_MAIN_DESIRED-1}"
MAIN_DESCRIBE_NULL="${FAKE_MAIN_DESCRIBE_NULL-false}"
TASKDEF_NONE_AFTER_INITIAL_READS="${FAKE_TASKDEF_NONE_AFTER_INITIAL_READS-0}"
CONCURRENT_ROLLOUT="${FAKE_CONCURRENT_ROLLOUT-COMPLETED}"
CONCURRENT_STABLE="${FAKE_CONCURRENT_STABLE-true}"
CONCURRENT_STABLE_AFTER_READS="${FAKE_CONCURRENT_STABLE_AFTER_READS-0}"
CONCURRENT_DESCRIBE_EMPTY="${FAKE_CONCURRENT_DESCRIBE_EMPTY-false}"
CONCURRENT_DESCRIBE_EMPTY_ON_READS="${FAKE_CONCURRENT_DESCRIBE_EMPTY_ON_READS-}"
CONCURRENT_STALE_PRIMARY_READS="${FAKE_CONCURRENT_STALE_PRIMARY_READS-0}"
CONCURRENT_PRIMARY_TASK_DEF="${FAKE_CONCURRENT_PRIMARY_TASK_DEF-}"

arg_after() {
  local want="$1" prev=""
  shift
  for arg in "$@"; do
    if [[ "$prev" == "$want" ]]; then
      printf '%s' "$arg"
      return 0
    fi
    prev="$arg"
  done
  return 1
}

QUERY=$(arg_after --query "$@" || true)
NAME=$(arg_after --name "$@" || true)
TASK_DEFINITION=$(arg_after --task-definition "$@" || true)
VALUE=$(arg_after --value "$@" || true)

task_def_arn_for() {
  local family="$1" revision="$2"
  printf 'arn:aws:ecs:%s:%s:task-definition/%s:%s' "$REGION" "$ACCOUNT" "$family" "$revision"
}

task_def_arn() {
  task_def_arn_for "$FAMILY" "$1"
}

final_task_def_arn() {
  if [[ "$FINAL_TASK_DEF" == arn:* ]]; then
    printf '%s' "$FINAL_TASK_DEF"
  else
    task_def_arn_for "$FINAL_FAMILY" "$FINAL_TASK_DEF"
  fi
}

task_def_json() {
  local revision="$1" tag="$2" shape="${3:-normal}" family="${4:-$FAMILY}"
  local arn
  arn=$(task_def_arn_for "$family" "$revision")
  case "$shape" in
    normal)
      printf '{"taskDefinitionArn":"%s","family":"%s","containerDefinitions":[{"name":"qurl-api","image":"%s:%s"},{"name":"adot","image":"public.ecr.aws/aws-observability/aws-otel-collector:latest"}]}\n' \
        "$arn" "$family" "$REPO" "$tag"
      ;;
    missing)
      printf '{"taskDefinitionArn":"%s","family":"%s","containerDefinitions":[{"name":"adot","image":"public.ecr.aws/aws-observability/aws-otel-collector:latest"}]}\n' \
        "$arn" "$family"
      ;;
    ambiguous)
      printf '{"taskDefinitionArn":"%s","family":"%s","containerDefinitions":[{"name":"qurl-api","image":"%s:%s"},{"name":"qurl-api","image":"%s:%s"}]}\n' \
        "$arn" "$family" "$REPO" "$tag" "$REPO" "$tag"
      ;;
    malformed)
      printf '{"taskDefinitionArn":'
      ;;
    *)
      echo "unsupported container shape: $shape" >&2
      exit 2
      ;;
  esac
}

csv_contains() {
  local csv="$1" want="$2"
  local item
  local -a items=()
  if [[ -z "$csv" ]]; then
    return 1
  fi
  IFS=',' read -r -a items <<< "$csv"
  for item in "${items[@]}"; do
    if [[ "$item" == "$want" ]]; then
      return 0
    fi
  done
  return 1
}

if [[ "$1 $2" == "ssm put-parameter" ]]; then
  has_overwrite=false
  for arg in "$@"; do
    if [[ "$arg" == "--overwrite" ]]; then
      has_overwrite=true
    fi
  done
  if [[ "$NAME" != "$EXPECTED_SSM_PUT_NAME" ]]; then
    echo "unexpected put-parameter name: got '$NAME', expected '$EXPECTED_SSM_PUT_NAME'" >&2
    exit 2
  fi
  if [[ "$VALUE" != "$EXPECTED_SSM_PUT_VALUE" ]]; then
    echo "unexpected put-parameter value: got '$VALUE', expected '$EXPECTED_SSM_PUT_VALUE'" >&2
    exit 2
  fi
  if [[ "$has_overwrite" != "true" ]]; then
    echo "put-parameter missing --overwrite" >&2
    exit 2
  fi
  printf '{"Version":342,"Tier":"Standard"}\n'
  exit 0
fi

if [[ "$1 $2" == "ssm get-parameter" ]]; then
  case "$NAME" in
    */qurl-ecs-cluster)
      printf '%s\n' "$FAMILY"
      ;;
    */qurl-ecs-service)
      printf '%s\n' "$FAMILY"
      ;;
    */qurl-api-image-tag)
      if [[ "$SSM_IMAGE_TAG_ERROR" == "true" ]]; then
        echo "An error occurred (ThrottlingException) when calling GetParameter for $NAME" >&2
        exit 255
      fi
      printf '%s\n' "$SSM_IMAGE_TAG"
      ;;
    *)
      echo "An error occurred (ParameterNotFound) when calling GetParameter for $NAME" >&2
      exit 255
      ;;
  esac
  exit 0
fi

if [[ "$1 $2" == "ecs describe-services" ]]; then
  case "$QUERY" in
    "services[0].taskDefinition")
      count_file="$STATE_DIR/taskdef-read-count"
      count=0
      [[ -f "$count_file" ]] && count=$(cat "$count_file")
      count=$((count + 1))
      printf '%s' "$count" > "$count_file"
      if [[ "$count" -eq 1 ]]; then
        task_def_arn "$INITIAL_REV"
      elif [[ "$TASKDEF_NONE_AFTER_INITIAL_READS" =~ ^[0-9]+$ && "$((count - 1))" -le "$TASKDEF_NONE_AFTER_INITIAL_READS" ]]; then
        printf 'None'
      else
        final_task_def_arn
      fi
      printf '\n'
      ;;
    "services[0].deployments")
      deployments_count_file="$STATE_DIR/deployments-read-count"
      deployments_count=0
      [[ -f "$deployments_count_file" ]] && deployments_count=$(cat "$deployments_count_file")
      deployments_count=$((deployments_count + 1))
      printf '%s' "$deployments_count" > "$deployments_count_file"
      if [[ "$MAIN_DESCRIBE_NULL" == "true" ]]; then
        printf 'null\n'
        exit 0
      fi
      if [[ "$deployments_count" -gt "$MAIN_STABLE_AFTER_READS" && "$CONCURRENT_DESCRIBE_EMPTY" == "true" ]]; then
        printf '[]\n'
        exit 0
      fi
      rollout="$MAIN_ROLLOUT"
      running=1
      desired="$MAIN_DESIRED"
      pending=0
      active_deployment=""
      primary_task_def=$(final_task_def_arn)
      if [[ "$MAIN_STABLE" != "true" || "$deployments_count" -lt "$MAIN_STABLE_AFTER_READS" ]]; then
        running=0
        pending="$desired"
        active_deployment=',{"status":"ACTIVE","taskDefinition":"arn:aws:ecs:us-east-2:767397897469:task-definition/layerv-nhp-sandbox-cell0-qurl-api:621","desiredCount":1,"runningCount":1,"pendingCount":0,"rolloutState":"COMPLETED"}'
      elif [[ "$deployments_count" -gt "$MAIN_STABLE_AFTER_READS" ]]; then
        concurrent_read=$((deployments_count - MAIN_STABLE_AFTER_READS))
        if csv_contains "$CONCURRENT_DESCRIBE_EMPTY_ON_READS" "$concurrent_read"; then
          printf '[]\n'
          exit 0
        fi
        if [[ -n "$CONCURRENT_PRIMARY_TASK_DEF" ]]; then
          if [[ "$CONCURRENT_PRIMARY_TASK_DEF" == arn:* ]]; then
            primary_task_def="$CONCURRENT_PRIMARY_TASK_DEF"
          else
            primary_task_def=$(task_def_arn_for "$FINAL_FAMILY" "$CONCURRENT_PRIMARY_TASK_DEF")
          fi
        fi
        if [[ "$CONCURRENT_STALE_PRIMARY_READS" =~ ^[0-9]+$ && "$concurrent_read" -le "$CONCURRENT_STALE_PRIMARY_READS" ]]; then
          primary_task_def=$(task_def_arn_for "$FINAL_FAMILY" 624)
        fi
        rollout="$CONCURRENT_ROLLOUT"
        concurrent_stable_now="$CONCURRENT_STABLE"
        if [[ "$CONCURRENT_STABLE_AFTER_READS" =~ ^[0-9]+$ && "$CONCURRENT_STABLE_AFTER_READS" -gt 0 ]]; then
          if [[ "$concurrent_read" -ge "$CONCURRENT_STABLE_AFTER_READS" ]]; then
            concurrent_stable_now=true
          else
            concurrent_stable_now=false
          fi
        fi
        if [[ "$concurrent_stable_now" != "true" ]]; then
          running=0
          desired=1
          pending=1
          active_deployment=',{"status":"ACTIVE","taskDefinition":"arn:aws:ecs:us-east-2:767397897469:task-definition/layerv-nhp-sandbox-cell0-qurl-api:622","desiredCount":1,"runningCount":1,"pendingCount":0,"rolloutState":"COMPLETED"}'
        fi
      fi
      printf '[{"status":"PRIMARY","taskDefinition":"%s","desiredCount":%s,"runningCount":%s,"pendingCount":%s,"rolloutState":"%s"}%s]\n' \
        "$primary_task_def" "$desired" "$running" "$pending" "$rollout" "$active_deployment"
      ;;
    "services[0].events[:10]")
      printf '[]\n'
      ;;
    *)
      echo "unsupported describe-services query: $QUERY" >&2
      exit 2
      ;;
  esac
  exit 0
fi

if [[ "$1 $2" == "ecs describe-task-definition" ]]; then
  if [[ "$QUERY" == "taskDefinition.taskDefinitionArn" ]]; then
    task_def_arn "$LATEST_REV"
    printf '\n'
    exit 0
  fi

  if [[ "$QUERY" == "taskDefinition" ]]; then
    case "$TASK_DEFINITION" in
      "$FAMILY")
        task_def_json "$LATEST_REV" 9335f9c
        ;;
      "$(task_def_arn "$REGISTERED_REV")")
        task_def_json "$REGISTERED_REV" 9335f9c
        ;;
      "$(final_task_def_arn)")
        if [[ "$DESCRIBE_ACTIVE_ERROR" == "true" ]]; then
          echo "An error occurred (AccessDeniedException) when calling DescribeTaskDefinition" >&2
          exit 255
        fi
        task_def_json "${FINAL_TASK_DEF##*:}" "$ACTIVE_IMAGE_TAG" "$ACTIVE_CONTAINER_SHAPE" "$FINAL_FAMILY"
        ;;
      *)
        echo "unsupported task definition: $TASK_DEFINITION" >&2
        exit 2
        ;;
    esac
    exit 0
  fi

  echo "unsupported describe-task-definition query: $QUERY" >&2
  exit 2
fi

if [[ "$1 $2" == "ecs register-task-definition" ]]; then
  registered_arn=$(task_def_arn "$REGISTERED_REV")
  if [[ "$REGISTER_TASKDEF_INTERIOR_WHITESPACE" == "true" ]]; then
    printf '%s\n' "${registered_arn/layerv-nhp-sandbox-cell0/layerv-nhp sandbox-cell0}"
  elif [[ "$REGISTER_TASKDEF_WHITESPACE" == "true" ]]; then
    printf '  %s  \n' "$registered_arn"
  else
    printf '%s\n' "$registered_arn"
  fi
  exit 0
fi

if [[ "$1 $2" == "ecs update-service" ]]; then
  printf 'UpdateService\n'
  exit 0
fi

echo "unsupported aws call: $*" >&2
exit 2
AWS
  chmod +x "$dir/aws"
}

run_case() {
  local dir out script_ssm_prefix env_arg
  dir=$(mktemp -d)
  out="$dir/out.txt"
  script_ssm_prefix="layerv-nhp-sandbox"
  for env_arg in "$@"; do
    case "$env_arg" in
      SCRIPT_SSM_PREFIX=*)
        script_ssm_prefix="${env_arg#*=}"
        ;;
    esac
  done
  make_fake_commands "$dir"
  env \
    PATH="$dir:$PATH" \
    FAKE_AWS_STATE_DIR="$dir" \
    FAKE_EXPECTED_SSM_PUT_NAME="/${script_ssm_prefix}/qurl-api-image-tag" \
    FAKE_EXPECTED_SSM_PUT_VALUE=9335f9c \
    AWS_REGION=us-east-2 \
    "$@" \
    bash "$SCRIPT" "$script_ssm_prefix" 9335f9c >"$out" 2>&1
  LAST_RC=$?
  LAST_OUT=$(cat "$out")
  rm -rf "$dir"
}

assert_success_contains() {
  local name="$1" needle="$2"
  if [[ "$LAST_RC" -eq 0 && "$LAST_OUT" == *"$needle"* ]]; then
    report_pass "$name"
  else
    report_fail "$name" "rc=$LAST_RC; expected output to contain: $needle"
  fi
}

assert_failure_contains() {
  local name="$1" needle="$2"
  if [[ "$LAST_RC" -ne 0 && "$LAST_OUT" == *"$needle"* ]]; then
    report_pass "$name"
  else
    report_fail "$name" "rc=$LAST_RC; expected failure output to contain: $needle"
  fi
}

echo "Running deploy-ecs-service tests..."

run_case FAKE_FINAL_TASK_DEF=622
assert_success_contains "accepts exact registered task def" \
  "Verified: service is running the new task def"
assert_success_contains "exact deploy summary reports registered task def" \
  "Task Def:    arn:aws:ecs:us-east-2:767397897469:task-definition/layerv-nhp-sandbox-cell0-qurl-api:622"

run_case PRESERVE_SSM_IMAGE_TAG=true FAKE_FINAL_TASK_DEF=622
assert_success_contains "preserve mode leaves sandbox SSM tag untouched" \
  "SSM parameter preserved: /layerv-nhp-sandbox/qurl-api-image-tag = 9335f9c"

run_case PRESERVE_SSM_IMAGE_TAG=true FAKE_FINAL_TASK_DEF=622 FAKE_SSM_IMAGE_TAG=3dc4f14
assert_success_contains "preserve mode adopts current sandbox SSM tag" \
  "SSM image tag changed since caller read it: requested 9335f9c, current 3dc4f14."
assert_success_contains "preserve mode summary reports adopted image" \
  "Image:       767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-qurl:3dc4f14"

run_case PRESERVE_SSM_IMAGE_TAG=true FAKE_FINAL_TASK_DEF=622 FAKE_SSM_IMAGE_TAG=$' 3dc4f14 '
assert_success_contains "preserve mode trims surrounding SSM tag whitespace" \
  "SSM image tag changed since caller read it: requested 9335f9c, current 3dc4f14."

run_case PRESERVE_SSM_IMAGE_TAG=true FAKE_FINAL_TASK_DEF=622 FAKE_SSM_IMAGE_TAG=$'3d c4f14'
assert_failure_contains "preserve mode rejects interior SSM tag whitespace" \
  "SSM image tag in /layerv-nhp-sandbox/qurl-api-image-tag contains interior whitespace"

run_case SCRIPT_SSM_PREFIX=layerv-nhp-prod PRESERVE_SSM_IMAGE_TAG=true FAKE_FINAL_TASK_DEF=622
assert_failure_contains "preserve mode is sandbox-only" \
  "PRESERVE_SSM_IMAGE_TAG=true is supported only for sandbox"

run_case FAKE_FINAL_TASK_DEF=622 FAKE_REGISTER_TASKDEF_WHITESPACE=true
assert_success_contains "trims registered task-def ARN whitespace" \
  "Verified: service is running the new task def"

run_case FAKE_REGISTER_TASKDEF_INTERIOR_WHITESPACE=true
assert_failure_contains "rejects registered task-def ARN interior whitespace" \
  "registered task definition ARN contains interior whitespace"

run_case FAKE_FINAL_TASK_DEF=622 FAKE_TASKDEF_NONE_AFTER_INITIAL_READS=2
assert_success_contains "retries empty post-rollout task-def reads before accepting exact match" \
  "Verified: service is running the new task def"

run_case SCRIPT_SSM_PREFIX=layerv-nhp-prod FAKE_FINAL_TASK_DEF=622
assert_success_contains "prod accepts exact registered task def" \
  "Verified: service is running the new task def"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=3dc4f14 FAKE_ACTIVE_IMAGE_TAG=3dc4f14
assert_success_contains "accepts newer same-family task def when active image matches current SSM tag" \
  "Verified: service is running newer task def"
assert_success_contains "concurrent deploy logs superseded task def semantics" \
  "was superseded by a concurrent deploy"
assert_success_contains "concurrent deploy summary reports actual active task def" \
  "Task Def:    arn:aws:ecs:us-east-2:767397897469:task-definition/layerv-nhp-sandbox-cell0-qurl-api:623"
assert_success_contains "concurrent deploy summary reports actual active image" \
  "Image:       767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-qurl:3dc4f14"

run_case FAKE_FINAL_TASK_DEF=623
assert_success_contains "accepts newer same-family task def carrying this run's image tag" \
  "Verified: service is running newer task def"

run_case SCRIPT_SSM_PREFIX=layerv-nhp-prod FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=3dc4f14 FAKE_ACTIVE_IMAGE_TAG=3dc4f14
assert_failure_contains "prod keeps strict exact-match semantics for newer same-family task def" \
  "concurrent forward-deploy tolerance is enabled only for sandbox"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=3dc4f14 FAKE_ACTIVE_IMAGE_TAG=3dc4f14 FAKE_CONCURRENT_STABLE_AFTER_READS=3
assert_success_contains "observes in-flight concurrent deploy before accepting it" \
  "[concurrent 0s] PRIMARY: 0/1 running, 1 pending | rollout: COMPLETED | draining: 1"
assert_success_contains "waits through an in-flight concurrent deploy until it stabilizes" \
  "[concurrent 30s] PRIMARY: 1/1 running, 0 pending | rollout: COMPLETED | draining: 0"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=3dc4f14 FAKE_ACTIVE_IMAGE_TAG=3dc4f14 FAKE_CONCURRENT_STALE_PRIMARY_READS=1 FAKE_CONCURRENT_STABLE_AFTER_READS=2
assert_success_contains "tolerates one stale non-matching concurrent PRIMARY read" \
  "returned non-matching PRIMARY task def"
assert_success_contains "accepts concurrent deploy after stale read clears" \
  "Verified: service is running newer task def"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=3dc4f14 FAKE_ACTIVE_IMAGE_TAG=3dc4f14 FAKE_MAIN_STABLE_AFTER_READS=40 FAKE_CONCURRENT_STABLE_AFTER_READS=2
assert_success_contains "concurrent wait floor allows a second stability read near budget end" \
  "[concurrent 15s] PRIMARY: 1/1 running, 0 pending | rollout: COMPLETED | draining: 0"

run_case FAKE_FINAL_TASK_DEF=620
assert_failure_contains "still rejects rollback to prior task def" \
  "ECS circuit breaker rolled back or another deploy moved the service to an unrelated/stale task def."

run_case FAKE_MAIN_ROLLOUT=FAILED
assert_failure_contains "fails loud when main deployment rollout fails" \
  "ECS deployment rollout FAILED"
assert_failure_contains "main deployment failure reports observed primary task def" \
  "PRIMARY task def at failure"

run_case FAKE_MAIN_DESCRIBE_NULL=true
assert_failure_contains "treats null deployment list as empty wait data" \
  "returned empty/missing data 3 consecutive iterations"
assert_failure_contains "times out after null deployment list without jq abort" \
  "Timed out waiting for ECS service stability"

run_case FAKE_MAIN_DESIRED=0
assert_failure_contains "does not treat scaled-to-zero completed rollout as stable" \
  "Timed out waiting for ECS service stability"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=3dc4f14 FAKE_ACTIVE_IMAGE_TAG=stale
assert_failure_contains "rejects newer same-family task def with stale image" \
  "This is neither the registered task def nor a verified current-image concurrent deploy."

run_case FAKE_FINAL_TASK_DEF=623 FAKE_FINAL_FAMILY=other-qurl-service FAKE_SSM_IMAGE_TAG=3dc4f14 FAKE_ACTIVE_IMAGE_TAG=3dc4f14
assert_failure_contains "rejects newer different-family task def" \
  "ECS circuit breaker rolled back or another deploy moved the service to an unrelated/stale task def."

run_case FAKE_FINAL_TASK_DEF=not-a-rev
assert_failure_contains "rejects malformed running task def ARN before concurrent verification" \
  "Running task-def ARN failed shape validation"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG_ERROR=true
assert_failure_contains "fails loud when concurrent SSM image read fails" \
  "Could not read current image tag"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=$'3d c4f14' FAKE_ACTIVE_IMAGE_TAG=3dc4f14
assert_failure_contains "rejects concurrent SSM tag interior whitespace" \
  "current SSM image tag in /layerv-nhp-sandbox/qurl-api-image-tag contains interior whitespace"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=
assert_failure_contains "rejects empty concurrent SSM image tag" \
  "Current image tag in /layerv-nhp-sandbox/qurl-api-image-tag is empty"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=None
assert_failure_contains "rejects None concurrent SSM image tag" \
  "Current image tag in /layerv-nhp-sandbox/qurl-api-image-tag is empty"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=3dc4f14 FAKE_DESCRIBE_ACTIVE_ERROR=true
assert_failure_contains "fails loud when newer task def describe fails" \
  "Could not describe newer running task def"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=3dc4f14 FAKE_ACTIVE_CONTAINER_SHAPE=missing
assert_failure_contains "fails loud when newer task def lacks primary container" \
  "No container named 'qurl-api' in newer running task definition"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=3dc4f14 FAKE_ACTIVE_CONTAINER_SHAPE=ambiguous
assert_failure_contains "fails loud when newer task def has duplicate primary container" \
  "Multiple containers named 'qurl-api' in newer running task definition"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=3dc4f14 FAKE_ACTIVE_CONTAINER_SHAPE=malformed
assert_failure_contains "fails loud when newer task def JSON is malformed" \
  "Could not extract primary container image from newer running task definition"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=3dc4f14 FAKE_ACTIVE_IMAGE_TAG=3dc4f14 FAKE_CONCURRENT_ROLLOUT=FAILED
assert_failure_contains "fails loud when concurrent deployment rollout fails" \
  "Concurrent ECS deployment rollout FAILED"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=3dc4f14 FAKE_ACTIVE_IMAGE_TAG=3dc4f14 FAKE_CONCURRENT_PRIMARY_TASK_DEF=624
assert_failure_contains "fails loud when concurrent verification is superseded again" \
  "was superseded by another task def while verifying stability"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=3dc4f14 FAKE_ACTIVE_IMAGE_TAG=3dc4f14 FAKE_CONCURRENT_PRIMARY_TASK_DEF=624 FAKE_CONCURRENT_DESCRIBE_EMPTY_ON_READS=2
assert_failure_contains "keeps supersede streak across one empty concurrent describe read" \
  "was superseded by another task def while verifying stability"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=3dc4f14 FAKE_ACTIVE_IMAGE_TAG=3dc4f14 FAKE_CONCURRENT_DESCRIBE_EMPTY=true
assert_failure_contains "warns when concurrent describe-services data is missing" \
  "returned empty/missing data 3 consecutive iterations during concurrent deploy verification"
assert_failure_contains "times out after missing concurrent describe-services data" \
  "Timed out waiting for concurrent task def"

run_case FAKE_FINAL_TASK_DEF=623 FAKE_SSM_IMAGE_TAG=3dc4f14 FAKE_ACTIVE_IMAGE_TAG=3dc4f14 FAKE_CONCURRENT_STABLE=false
assert_failure_contains "times out when concurrent deployment never stabilizes" \
  "Timed out waiting for concurrent task def"

echo ""
echo "Passed: $pass"
echo "Failed: $fail"
if [[ "$fail" -gt 0 ]]; then
  printf '\nFailures:\n%b' "$failures"
  exit 1
fi
