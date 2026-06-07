#!/bin/bash
# Deploy an ECS service by registering a new task definition revision.
#
# Instead of `--force-new-deployment` (which re-pulls the same image), this script
# creates a new task definition revision with the updated image tag. ECS circuit
# breaker handles automatic rollback if the new revision fails health checks.
#
# Usage: deploy-ecs-service.sh <ssm-prefix> <new-image-tag>
# Example: deploy-ecs-service.sh layerv-nhp-prod ae6f825
#
# Prerequisites:
#   - SSM parameters exist:
#       /<prefix>/qurl-api-image-tag
#       /<prefix>/qurl-ecs-cluster
#       /<prefix>/qurl-ecs-service
#   - IAM permissions:
#       ecs:RegisterTaskDefinition, ecs:UpdateService,
#       ecs:DescribeTaskDefinition, ecs:DescribeServices,
#       iam:PassRole, ssm:PutParameter, ssm:GetParameter
#
# What it does:
#   1. Updates SSM image tag parameter
#   2. Gets the LATEST task definition revision (not the one running on the service,
#      since Terraform may have created a newer revision with updated env vars)
#   3. Replaces the image tag and registers a new task definition revision
#   4. Updates ECS service to use new task definition
#   5. Waits for service stability (ECS circuit breaker handles rollback)
#
# Success contract:
#   - Default/prod path: exit 0 means the requested task definition is stable.
#   - Sandbox-only concurrent path: exit 0 may mean qurl-service's own deploy
#     won the last-writer race and the service is stable on the current SSM
#     image. The final summary logs the actual active image/task definition.
#   - PRESERVE_SSM_IMAGE_TAG=true is sandbox-only and leaves qurl-service's SSM
#     tag as the source of truth instead of rewriting it from the caller's
#     earlier read.

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <ssm-prefix> <new-image-tag>"
  echo "  ssm-prefix:    SSM parameter prefix (e.g., layerv-nhp-prod)"
  echo "  new-image-tag: Docker image tag to deploy (e.g., commit SHA)"
  exit 1
fi

SSM_PREFIX="$1"
NEW_IMAGE_TAG="$2"
AWS_REGION="${AWS_REGION:-us-east-2}"
PRESERVE_SSM_IMAGE_TAG="${PRESERVE_SSM_IMAGE_TAG:-false}"
ALLOW_CONCURRENT_FORWARD_DEPLOY=false
if [[ "$SSM_PREFIX" == "layerv-nhp-sandbox" ]]; then
  # Sandbox qurl-service has an independent main-branch deploy workflow that
  # writes /layerv-nhp-sandbox/qurl-api-image-tag before ECS update-service.
  # That cross-repo ordering lets this helper distinguish a healthy concurrent
  # forward deploy from a circuit-breaker rollback. Prod promote-to-prod is
  # serialized by workflow concurrency, so keep prod on strict exact-match.
  ALLOW_CONCURRENT_FORWARD_DEPLOY=true
fi

if [[ -z "$NEW_IMAGE_TAG" ]]; then
  echo "ERROR: new-image-tag cannot be empty"
  exit 1
fi

# Best-effort: a transient describe-services error here must not mask the
# real failure this helper is being called to explain. Defined at the top
# so any step after Step 2 (which assigns ECS_CLUSTER / ECS_SERVICE) can
# use it on failure. Uses `${VAR:-}` so calling it before Step 2 just
# emits a polite "(unavailable)" instead of dying on `set -u`. The
# explicit `if !` + `return 0` form keeps the helper truly best-effort
# under `set -e` regardless of caller context.
# TRAP PREREQUISITE: this helper writes to script-scope EVENTS_ERR_FILE
# which is cleaned up by the script-level EXIT/INT/TERM trap registered
# below (~line 174). Callers that invoke this BEFORE the trap is set
# would risk a tempfile leak on signal — every current callsite is
# after the trap, so this is forward-defensive documentation.
dump_ecs_events() {
  echo "Recent ECS service events:"
  if [[ -z "${ECS_CLUSTER:-}" || -z "${ECS_SERVICE:-}" ]]; then
    echo "  (cluster/service not yet resolved — dump unavailable from this point in the script)"
    return 0
  fi
  # Stderr to temp file so an IAM-denied describe yields the actual
  # error rather than just "(failed)" — this helper exists to debug
  # rollback, so masking errors defeats the purpose.
  # Uses script-scope EVENTS_ERR_FILE (declared at the top of this
  # script) instead of a local var so the script-level trap can clean
  # it up if a signal arrives between mktemp and the inner rm -f.
  local events_json
  EVENTS_ERR_FILE=$(mktemp)
  if ! events_json=$(aws ecs describe-services \
      --cluster "$ECS_CLUSTER" \
      --services "$ECS_SERVICE" \
      --query "services[0].events[:10]" --output json \
      --region "$AWS_REGION" 2>"$EVENTS_ERR_FILE"); then
    echo "  (failed to fetch service events)"
    if [[ -s "$EVENTS_ERR_FILE" ]]; then
      while IFS= read -r line; do
        printf '    %s\n' "$line"
      done < "$EVENTS_ERR_FILE"
    fi
    rm -f "$EVENTS_ERR_FILE"
    EVENTS_ERR_FILE=""
    return 0
  fi
  rm -f "$EVENTS_ERR_FILE"
  EVENTS_ERR_FILE=""
  # Distinguish service-deleted from service-with-no-events.
  if [[ -z "$events_json" || "$events_json" == "null" ]]; then
    echo "  (service not found — was it deleted between Step 2 and now?)"
    return 0
  fi
  # jq runtime failure → events_count="" → falls through to the
  # formatter+raw-JSON-dump path below (intentional). Only
  # events_count=="0" returns the "no recent events" branch — empty
  # is a different signal (jq failed, dump raw to be safe).
  local events_count
  if ! events_count=$(jq 'length' <<< "$events_json" 2>/dev/null); then
    events_count=""
  fi
  if [[ "$events_count" == "0" ]]; then
    echo "  (no recent events)"
    return 0
  fi
  # List form (not table) — ECS event messages exceed table-friendly
  # widths and would truncate the operator-actionable part.
  jq -r '.[] | "  [\(.createdAt[:19])] \(.message)"' <<< "$events_json" 2>/dev/null || {
    # Fallback: if jq fails for any reason, dump the raw JSON.
    echo "$events_json"
  }
  return 0
}

normalize_token_output() {
  local label="$1"
  local value="$2"

  # AWS CLI --output text can include harmless surrounding whitespace. Interior
  # whitespace is corrupt for image tags and ARNs, so reject instead of repairing.
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"

  if [[ "$value" == *[[:space:]]* ]]; then
    echo "ERROR: $label contains interior whitespace; refusing to silently repair it." >&2
    return 1
  fi

  printf '%s\n' "$value"
}

extract_primary_image() {
  local task_def_json="$1"
  local label="$2"
  local list_available="${3:-false}"
  local missing_hint="${4:-}"
  local image

  if ! image=$(jq -r --arg name "$PRIMARY_CONTAINER" '
    [.containerDefinitions[] | select(.name == $name)] as $matches
    | if ($matches | length) == 0 then "MISSING"
      elif ($matches | length) > 1 then "AMBIGUOUS"
      else $matches[0].image
      end' <<< "$task_def_json"); then
    echo "ERROR: Could not extract primary container image from $label (task definition JSON parse failed)." >&2
    return 1
  fi
  if [[ -z "$image" || "$image" == "null" ]]; then
    echo "ERROR: Could not extract primary container image from $label (empty image value)." >&2
    return 1
  fi
  if [[ "$image" == "MISSING" ]]; then
    echo "ERROR: No container named '$PRIMARY_CONTAINER' in $label." >&2
    if [[ "$list_available" == "true" ]]; then
      echo "Available containers:" >&2
      echo "$task_def_json" | jq -r '.containerDefinitions[].name | "  - \(.)"' >&2
    fi
    if [[ -n "$missing_hint" ]]; then
      echo "$missing_hint" >&2
    fi
    return 1
  fi
  if [[ "$image" == "AMBIGUOUS" ]]; then
    echo "ERROR: Multiple containers named '$PRIMARY_CONTAINER' in $label." >&2
    return 1
  fi

  printf '%s\n' "$image"
}

STABILITY_WAIT_ELAPSED=0
# Precondition: callers have resolved ECS_CLUSTER/ECS_SERVICE/AWS_REGION and
# WAIT_INTERVAL; failure diagnostics include NEW_TASK_DEF_ARN when available.
wait_for_stable_deployment() {
  local timeout="$1"
  local expected_task_def="${2:-}"
  local elapsed=0
  local describe_fail_streak=0
  local supersede_mismatch_streak=0
  local describe_fail_warn_threshold="${DESCRIBE_FAIL_WARN_THRESHOLD:-3}"
  local deployment_status
  local primary_task_def primary_running primary_desired primary_pending active_count rollout

  while [[ $elapsed -lt $timeout ]]; do
    deployment_status=$(aws ecs describe-services \
      --cluster "$ECS_CLUSTER" \
      --services "$ECS_SERVICE" \
      --query "services[0].deployments" --output json \
      --region "$AWS_REGION" 2>/dev/null || echo "[]")

    if [[ "$deployment_status" == "[]" || "$deployment_status" == "null" || -z "$deployment_status" ]]; then
      describe_fail_streak=$((describe_fail_streak + 1))
      # Warn at the threshold, then re-warn every Nth iteration after.
      # `% THRESHOLD == 0` re-emits at threshold, 2xthreshold, 3xthreshold,
      # ... so an operator debugging a sustained outage live keeps getting
      # signal instead of one warning followed by silent minutes.
      if (( describe_fail_streak >= describe_fail_warn_threshold \
         && describe_fail_streak % describe_fail_warn_threshold == 0 )); then
        if [[ -n "$expected_task_def" ]]; then
          echo "::warning::aws ecs describe-services has returned empty/missing data $describe_fail_streak consecutive iterations during concurrent deploy verification — likely IAM/network/throttle issue. Wait-loop continues; check CloudTrail if the concurrent wait times out."
        else
          echo "::warning::aws ecs describe-services has returned empty/missing data $describe_fail_streak consecutive iterations — likely IAM/network/throttle issue. Wait-loop continues; check CloudTrail if the wait times out."
        fi
      fi
      deployment_status="[]"
    else
      describe_fail_streak=0
    fi

    # pendingCount is progress-log-only; stability is desired/running plus
    # zero draining ACTIVE deployments.
    if ! read -r primary_task_def primary_running primary_desired primary_pending active_count rollout < <(
      jq -r '
        if type != "array" then empty
        else
          ([.[] | select(.status == "PRIMARY")] | .[0]) as $primary
          | [
              ($primary.taskDefinition // "__MISSING_TASK_DEF__"),
              (($primary.runningCount // 0) | tostring),
              (($primary.desiredCount // 0) | tostring),
              (($primary.pendingCount // 0) | tostring),
              (([.[] | select(.status == "ACTIVE")] | length) | tostring),
              ($primary.rolloutState // "unknown")
            ]
          | @tsv
        end
      ' <<< "$deployment_status"
    ); then
      echo "ERROR: Could not parse ECS deployment status JSON while waiting for stability."
      dump_ecs_events
      exit 1
    fi
    if [[ "$primary_task_def" == "__MISSING_TASK_DEF__" ]]; then
      primary_task_def=""
    fi

    if [[ -n "$expected_task_def" ]]; then
      echo "  [concurrent ${elapsed}s] PRIMARY: ${primary_running}/${primary_desired} running, ${primary_pending} pending | rollout: ${rollout} | draining: ${active_count} | taskDef: ${primary_task_def##*/}"

      if [[ -n "$primary_task_def" && "$primary_task_def" != "$expected_task_def" ]]; then
        supersede_mismatch_streak=$((supersede_mismatch_streak + 1))
        if (( supersede_mismatch_streak >= 2 )); then
          echo "ERROR: Concurrent task def $expected_task_def was superseded by another task def while verifying stability: $primary_task_def"
          echo "  Refusing to chase multiple deploys in one run; rerun after the service settles."
          dump_ecs_events
          exit 1
        fi
        echo "::warning::aws ecs describe-services returned non-matching PRIMARY task def while verifying $expected_task_def: $primary_task_def. Waiting one more interval to rule out an eventually-consistent stale read."
      elif [[ "$primary_task_def" == "$expected_task_def" ]]; then
        supersede_mismatch_streak=0
      fi
    else
      echo "  [${elapsed}s] PRIMARY: ${primary_running}/${primary_desired} running, ${primary_pending} pending | rollout: ${rollout} | draining: ${active_count}"
    fi

    # `primary_desired -gt 0` guards against a degenerate scaled-to-zero
    # service: 0/0 running + COMPLETED would otherwise satisfy the
    # `running == desired` test and report "stable" on a service with
    # no tasks. qurl-service runs >=1 today; this guard future-proofs
    # against a manual scale-to-zero through this script.
    if [[ "$rollout" == "COMPLETED" \
       && "$primary_desired" -gt 0 \
       && "$primary_running" -eq "$primary_desired" \
       && "$active_count" -eq 0 ]]; then
      if [[ -z "$expected_task_def" ]]; then
        echo "  Service stable: all tasks running, rollout complete."
        break
      fi
      if [[ "$primary_task_def" == "$expected_task_def" ]]; then
        break
      fi
    fi

    if [[ "$rollout" == "FAILED" ]]; then
      if [[ -n "$expected_task_def" ]]; then
        echo "ERROR: Concurrent ECS deployment rollout FAILED while verifying $expected_task_def."
      else
        echo "ERROR: ECS deployment rollout FAILED (circuit breaker triggered rollback)"
        if [[ -n "${NEW_TASK_DEF_ARN:-}" && -n "$primary_task_def" ]]; then
          echo "  PRIMARY task def at failure: $primary_task_def (registered by this run: $NEW_TASK_DEF_ARN)"
        fi
      fi
      dump_ecs_events
      exit 1
    fi

    sleep "$WAIT_INTERVAL"
    elapsed=$((elapsed + WAIT_INTERVAL))
  done

  if [[ $elapsed -ge $timeout ]]; then
    if [[ -n "$expected_task_def" ]]; then
      echo "ERROR: Timed out waiting for concurrent task def $expected_task_def to stabilize (remaining budget ${timeout}s)."
    else
      echo "ERROR: Timed out waiting for ECS service stability (${timeout}s)"
      echo "  Check ECS console for deployment status."
    fi
    dump_ecs_events
    exit 1
  fi

  STABILITY_WAIT_ELAPSED=$elapsed
}

echo "============================================"
echo "ECS Service Deploy"
echo "============================================"
echo "SSM Prefix:  $SSM_PREFIX"
echo "Image Tag:   $NEW_IMAGE_TAG"
echo ""

# Step 1: Update or preserve the SSM image tag
SSM_IMAGE_TAG_PARAM="/${SSM_PREFIX}/qurl-api-image-tag"
if [[ "$PRESERVE_SSM_IMAGE_TAG" == "true" ]]; then
  if [[ "$ALLOW_CONCURRENT_FORWARD_DEPLOY" != "true" ]]; then
    echo "ERROR: PRESERVE_SSM_IMAGE_TAG=true is supported only for sandbox concurrent qurl rolls."
    exit 1
  fi
  echo "Step 1: Preserving SSM parameter and refreshing current image tag: $SSM_IMAGE_TAG_PARAM"
  if ! PRESERVED_IMAGE_TAG=$(aws ssm get-parameter \
      --name "$SSM_IMAGE_TAG_PARAM" \
      --query "Parameter.Value" --output text \
      --region "$AWS_REGION"); then
    echo "ERROR: Could not read SSM image tag from $SSM_IMAGE_TAG_PARAM while PRESERVE_SSM_IMAGE_TAG=true."
    exit 1
  fi
  if ! PRESERVED_IMAGE_TAG=$(normalize_token_output "SSM image tag in $SSM_IMAGE_TAG_PARAM" "$PRESERVED_IMAGE_TAG"); then
    exit 1
  fi
  if [[ -z "$PRESERVED_IMAGE_TAG" || "$PRESERVED_IMAGE_TAG" == "None" ]]; then
    echo "ERROR: SSM image tag in $SSM_IMAGE_TAG_PARAM is empty while PRESERVE_SSM_IMAGE_TAG=true."
    exit 1
  fi
  if [[ "$PRESERVED_IMAGE_TAG" != "$NEW_IMAGE_TAG" ]]; then
    echo "  SSM image tag changed since caller read it: requested $NEW_IMAGE_TAG, current $PRESERVED_IMAGE_TAG."
  fi
  NEW_IMAGE_TAG="$PRESERVED_IMAGE_TAG"
  echo "  SSM parameter preserved: $SSM_IMAGE_TAG_PARAM = $NEW_IMAGE_TAG"
else
  echo "Step 1: Updating SSM parameter: $SSM_IMAGE_TAG_PARAM"
  aws ssm put-parameter \
    --name "$SSM_IMAGE_TAG_PARAM" \
    --value "$NEW_IMAGE_TAG" \
    --type String \
    --overwrite \
    --region "$AWS_REGION"
  echo "  SSM parameter updated: $SSM_IMAGE_TAG_PARAM = $NEW_IMAGE_TAG"
fi
echo ""

# Step 2: Read ECS cluster and service names from SSM
echo "Step 2: Reading ECS cluster and service from SSM..."
ECS_CLUSTER=$(aws ssm get-parameter \
  --name "/${SSM_PREFIX}/qurl-ecs-cluster" \
  --query "Parameter.Value" --output text \
  --region "$AWS_REGION")
ECS_SERVICE=$(aws ssm get-parameter \
  --name "/${SSM_PREFIX}/qurl-ecs-service" \
  --query "Parameter.Value" --output text \
  --region "$AWS_REGION")

echo "  ECS Cluster: $ECS_CLUSTER"
echo "  ECS Service: $ECS_SERVICE"
echo ""

# Step 3: Get latest task definition revision
# IMPORTANT: Use the latest revision (from describe-task-definition with family name),
# NOT the one currently running on the service (from describe-services). Terraform may
# have created a newer revision with updated env vars that the service hasn't adopted
# yet (due to ignore_changes = [task_definition] on the ECS service resource).
echo "Step 3: Getting latest task definition revision..."

# Get the task definition family name from the running service. Stderr
# is captured to a temp file (NOT 2>&1) so an AWS-CLI warning written
# to stderr on a successful read does not contaminate the ARN — the
# ARN is then `sed`-extracted into TASK_DEF_FAMILY below, where any
# stray text would silently produce a corrupt family name. Mirrors the
# pattern used in promote-to-prod.yml's stale-terraform SSM read.
# Pre-declare every tempfile (DESC + later-allocated VERIFY/TASK_DEF/
# REGISTER + the dump_ecs_events helper's EVENTS_ERR_FILE) as empty
# BEFORE registering the trap, so a signal between the trap
# registration and any mktemp can't leak a partially-allocated file.
# The trap clean-up uses `${VAR:-}` for safety — a still-empty var
# expands to "" and `rm -f ""` is a no-op.
#
# Adding a new tempfile anywhere downstream MUST: (a) add an empty
# pre-declaration here, (b) extend the trap pattern below, (c) leave
# the trap call as the only registration in the file. Any second
# `trap` call elsewhere replaces this one and risks leaking earlier
# temp files.
DESC_ERR_FILE=""
VERIFY_ERR_FILE=""
TASK_DEF_FILE=""
REGISTER_ERR_FILE=""
SSM_VERIFY_ERR_FILE=""
ACTIVE_TASK_DEF_ERR_FILE=""
EVENTS_ERR_FILE=""  # used inside dump_ecs_events helper; covered here for signal-safety
# EXIT covers normal exits + set-e exits; INT/TERM cover Ctrl-C / kill.
# CI runners shouldn't see signals in practice but explicit > implicit.
trap 'rm -f "${DESC_ERR_FILE:-}" "${VERIFY_ERR_FILE:-}" "${TASK_DEF_FILE:-}" "${REGISTER_ERR_FILE:-}" "${SSM_VERIFY_ERR_FILE:-}" "${ACTIVE_TASK_DEF_ERR_FILE:-}" "${EVENTS_ERR_FILE:-}"' EXIT INT TERM
DESC_ERR_FILE=$(mktemp)
if ! RUNNING_TASK_DEF_ARN=$(aws ecs describe-services \
    --cluster "$ECS_CLUSTER" \
    --services "$ECS_SERVICE" \
    --query "services[0].taskDefinition" --output text \
    --region "$AWS_REGION" 2>"$DESC_ERR_FILE"); then
  echo "ERROR: aws ecs describe-services failed in Step 3:"
  while IFS= read -r line; do
    printf '  %s\n' "$line"
  done < "$DESC_ERR_FILE"
  dump_ecs_events
  exit 1
fi

if [[ -z "$RUNNING_TASK_DEF_ARN" || "$RUNNING_TASK_DEF_ARN" == "None" ]]; then
  echo "ERROR: Could not find task definition for service $ECS_SERVICE"
  dump_ecs_events
  exit 1
fi

# Extract family name (everything before the last colon+revision)
TASK_DEF_FAMILY=$(echo "$RUNNING_TASK_DEF_ARN" | sed 's/.*task-definition\///' | sed 's/:[0-9]*$//')
echo "  Running task definition: $RUNNING_TASK_DEF_ARN"
echo "  Task definition family: $TASK_DEF_FAMILY"

# Fetch the LATEST revision (describe-task-definition with family name returns latest)
CURRENT_TASK_DEF_ARN=$(aws ecs describe-task-definition \
  --task-definition "$TASK_DEF_FAMILY" \
  --query "taskDefinition.taskDefinitionArn" --output text \
  --region "$AWS_REGION")
echo "  Latest task definition: $CURRENT_TASK_DEF_ARN"

CURRENT_TASK_DEF=$(aws ecs describe-task-definition \
  --task-definition "$TASK_DEF_FAMILY" \
  --query "taskDefinition" --output json \
  --region "$AWS_REGION")

# Pick the primary container by name. Default matches the SSM key
# convention this script reads from (/<prefix>/qurl-api-image-tag),
# so today's single-container task defs keep working unconfigured.
# Override via the env var when a future consumer's primary
# container has a different name. The same-repo-sidecar safety
# discussion lives at the MATCHING_REPO_COUNT guard below.
PRIMARY_CONTAINER="${PRIMARY_CONTAINER:-qurl-api}"

if ! CURRENT_IMAGE=$(extract_primary_image "$CURRENT_TASK_DEF" "task definition" true "  Set PRIMARY_CONTAINER env var to match the desired container."); then
  exit 1
fi

echo "  Primary container: $PRIMARY_CONTAINER"
echo "  Current image: $CURRENT_IMAGE"
echo ""

# Step 4: Replace image tag in container definitions
echo "Step 4: Creating new task definition with image tag: $NEW_IMAGE_TAG"

# Extract the image repo (everything before the last colon).
#
# Assumes tag-form `repo:tag` not digest-form `repo@sha256:abc`. The
# codebase uses tag-form everywhere (terraform/modules/* references,
# CI image-tag SSM parameters), so digest-form would be a deliberate
# break. Detect and reject it explicitly so the failure mode is loud
# rather than producing a malformed `repo@sha256` string that fails
# later at register-task-definition with a less-obvious error.
if [[ "$CURRENT_IMAGE" == *"@sha256:"* ]]; then
  echo "ERROR: digest-form image not supported by this script: $CURRENT_IMAGE"
  echo "  Set the image to tag-form (repo:tag) before running this deploy."
  exit 1
fi
# Bash parameter expansion `${var%pattern}` strips the shortest
# trailing match — `:*` removes the colon-and-tag suffix. No subshell
# or sed required, and no SC2001 lint warning.
IMAGE_REPO="${CURRENT_IMAGE%:*}"
if [[ -z "$IMAGE_REPO" || "$IMAGE_REPO" == "$CURRENT_IMAGE" ]]; then
  echo "ERROR: Could not parse image repository from: $CURRENT_IMAGE"
  exit 1
fi
# Same-repo sidecar guard. The Step 4 jq filter updates every
# container whose image starts with `$IMAGE_REPO:`, so a future
# sidecar that shares the primary's ECR repo (e.g.,
# `nhp-qurl:debug-sidecar` alongside `nhp-qurl:main`) would both
# get bumped to the new tag — usually wrong. Reject that here.
# Sidecars from a different repo (today's case: ADOT collector
# from `public.ecr.aws/aws-observability/...`) don't match the
# prefix and are correctly left alone. The structural fix is to
# update the Step 4 filter to target by container name (tracked
# as a follow-up); until then, this guard fences the failure mode.
MATCHING_REPO_COUNT=$(echo "$CURRENT_TASK_DEF" | jq --arg repo "$IMAGE_REPO" '[.containerDefinitions[] | select(.image | startswith($repo + ":"))] | length')
if [[ "$MATCHING_REPO_COUNT" != "1" ]]; then
  echo "ERROR: Expected exactly 1 container with image repo '$IMAGE_REPO', found $MATCHING_REPO_COUNT."
  echo "  A sidecar sharing the primary's ECR repo would be silently bumped to the new tag by the prefix-based update at Step 4. Update the jq filter to target by container name before allowing this layout."
  exit 1
fi
NEW_IMAGE="${IMAGE_REPO}:${NEW_IMAGE_TAG}"
echo "  New image: $NEW_IMAGE"

# Build new task definition JSON:
# - Replace image tag in all container definitions that use the same repo
# - Strip ECS-managed fields that cannot be passed to register-task-definition
NEW_TASK_DEF=$(echo "$CURRENT_TASK_DEF" | jq \
  --arg new_image "$NEW_IMAGE" \
  --arg repo "$IMAGE_REPO" \
  '.containerDefinitions = [.containerDefinitions[] | if (.image | startswith($repo + ":")) then .image = $new_image else . end] | del(.taskDefinitionArn, .revision, .status, .registeredAt, .registeredBy, .deregisteredAt, .compatibilities, .requiresAttributes)')
echo ""

# Step 5: Register new task definition
echo "Step 5: Registering new task definition revision..."
TASK_DEF_FILE=$(mktemp)  # cleanup via the EXIT trap above
echo "$NEW_TASK_DEF" > "$TASK_DEF_FILE"
# `if !` + stderr capture mirrors Step 3's pattern. Under set -e the
# bare command would exit with the AWS CLI's stderr leaking
# uncaptured; explicit capture lets us prefix the failure with
# context before re-raising.
REGISTER_ERR_FILE=$(mktemp)  # cleanup via the EXIT trap above
if ! NEW_TASK_DEF_ARN=$(aws ecs register-task-definition \
    --cli-input-json "file://$TASK_DEF_FILE" \
    --query "taskDefinition.taskDefinitionArn" --output text \
    --region "$AWS_REGION" 2>"$REGISTER_ERR_FILE"); then
  echo "ERROR: aws ecs register-task-definition failed:"
  while IFS= read -r line; do
    printf '  %s\n' "$line"
  done < "$REGISTER_ERR_FILE"
  exit 1
fi
if ! NEW_TASK_DEF_ARN=$(normalize_token_output "registered task definition ARN" "$NEW_TASK_DEF_ARN"); then
  exit 1
fi

echo "  New task definition: $NEW_TASK_DEF_ARN"
echo ""

# Step 6: Update ECS service to use new task definition
echo "Step 6: Updating ECS service..."
aws ecs update-service \
  --cluster "$ECS_CLUSTER" \
  --service "$ECS_SERVICE" \
  --task-definition "$NEW_TASK_DEF_ARN" \
  --query "service.deployments[*].{status: status, desired: desiredCount, running: runningCount, taskDef: taskDefinition}" \
  --output table \
  --region "$AWS_REGION"
echo ""

# Step 7: Wait for service stability with progress output
echo "Step 7: Waiting for ECS service to stabilize..."
echo "  (ECS circuit breaker will auto-rollback if health checks fail)"

WAIT_TIMEOUT=600  # 10 minutes
WAIT_INTERVAL=15
WAIT_ELAPSED=0
# Empty stdout from describe-services (set when 2>/dev/null swallows an
# IAM/network/throttle error) would otherwise look like "0/0 running" until the
# timeout. Surface a warning after repeated empty reads while still allowing
# transient throttles to resolve within the budget.
DESCRIBE_FAIL_WARN_THRESHOLD=3

# The first wait settles the service before the exact task-def check below. If a
# sandbox qurl-service deploy became PRIMARY during the wait, the post-loop
# verification routes it through the fail-closed concurrent path.
wait_for_stable_deployment "$WAIT_TIMEOUT"
WAIT_ELAPSED=$STABILITY_WAIT_ELAPSED

# rolloutState=COMPLETED is also the terminal state of a circuit-breaker
# rollback (running the *previous* task def), so the wait-loop's stability
# check is necessary but not sufficient. Compare the service's current task
# def to the one we registered. Exact match proves this rollout. Older or
# different-family task defs remain a rollback failure. In sandbox only, a newer
# same-family task def can also happen when qurl-service's own CI deploy advances
# the service while this helper is waiting. That sandbox path is accepted only
# after verifying the newer task def's primary image against the current SSM
# source of truth and confirming the newer deployment is stable. Prod stays on
# strict exact-match semantics because promote-to-prod is serialized by workflow
# concurrency. The sandbox tolerance depends on the concurrent deploy also being
# the last SSM writer; if the ECS winner and SSM winner differ, the image compare
# below fails closed. In the sandbox concurrent path, green means "the service is
# settled on the current SSM image", not "this invocation's registered task def
# stayed active." Empty / "None" output triggers the same fail-loud branch as a
# mismatch — if we cannot verify, we cannot claim success.
#
# Invariant the single-shot verify relies on: this code only runs after
# ROLLOUT=COMPLETED, which is when ECS guarantees `services[0].
# taskDefinition` reflects the resolved post-stability state. The retry
# below absorbs API-side hiccups, not deployment flapping.
#
# Retry up to 3 times to absorb transient describe-services throttling /
# eventual consistency: in practice ECS does not flap post-stability, but
# a single read is exposed to API-side hiccups that would block a healthy
# deploy on a false-positive empty/None response.
#
# The first valid (non-empty, non-"None") response is authoritative: we
# do NOT reconcile across attempts. Across-attempt reconciliation would
# add complexity for two symmetric and vanishingly-rare cases:
#   - Stale read returning $NEW_TASK_DEF_ARN exactly while ECS still
#     hasn't actually committed the rollout (false positive: claim
#     success when state is still settling).
#   - Stale read returning the OLD ARN after ECS already committed the
#     new task def (false negative: trip a phantom rollback alarm).
# Both require a multi-attempt cross-AZ stale-cache pattern that the
# post-stability invariant ECS enforces makes near-impossible. The
# runbook's recovery path (re-trigger after operator inspection) covers
# the false-negative case if it ever fires.
#
# Stderr is captured to a temp file per attempt. On final fail-loud,
# the last attempt's stderr is emitted so an operator debugging a 3x-IAM-
# denied state has something to act on (mirrors Step 3 + the SSM read in
# promote-to-prod.yml).
VERIFY_ERR_FILE=$(mktemp)  # cleanup via the EXIT trap above
RUNNING_TASK_DEF_AFTER=""
for attempt in 1 2 3; do
  : > "$VERIFY_ERR_FILE"
  RUNNING_TASK_DEF_AFTER=$(aws ecs describe-services \
    --cluster "$ECS_CLUSTER" \
    --services "$ECS_SERVICE" \
    --query "services[0].taskDefinition" --output text \
    --region "$AWS_REGION" 2>"$VERIFY_ERR_FILE" || echo "")
  # Normalize AWS CLI --output text surrounding whitespace before empty/None
  # checks; reject interior whitespace instead of silently repairing an ARN.
  if ! RUNNING_TASK_DEF_AFTER=$(normalize_token_output "running task definition ARN after rollout" "$RUNNING_TASK_DEF_AFTER"); then
    exit 1
  fi
  if [[ -n "$RUNNING_TASK_DEF_AFTER" && "$RUNNING_TASK_DEF_AFTER" != "None" ]]; then
    break
  fi
  if [[ $attempt -lt 3 ]]; then
    # Linear backoff (3s, 6s) — small total worst-case wait (~9s before
    # fail-loud) is enough to absorb a legitimate API hiccup while
    # surfacing a real outage promptly. AWS guidance suggests
    # exponential for sustained-throttle scenarios, but the rare
    # in-deploy hiccup we're absorbing here is bounded enough that
    # linear is simpler and equally effective.
    BACKOFF=$((attempt * 3))
    # Use ::warning:: rather than a plain echo so the per-attempt
    # message surfaces in the GitHub Actions UI's annotations panel
    # — debugging a 3x-failed verify shouldn't require scrolling the
    # full step log.
    echo "::warning::describe-services attempt $attempt returned '${RUNNING_TASK_DEF_AFTER:-<empty>}', retrying in ${BACKOFF}s..."
    if [[ -s "$VERIFY_ERR_FILE" ]]; then
      while IFS= read -r line; do
        printf '  %s\n' "$line"
      done < "$VERIFY_ERR_FILE"
    fi
    sleep "$BACKOFF"
  fi
done

if [[ -z "$RUNNING_TASK_DEF_AFTER" || "$RUNNING_TASK_DEF_AFTER" == "None" ]]; then
  echo "ERROR: Could not read running task definition after rollout to verify it matches $NEW_TASK_DEF_ARN (got '${RUNNING_TASK_DEF_AFTER:-<empty>}' after 3 attempts)."
  if [[ -s "$VERIFY_ERR_FILE" ]]; then
    echo "Last attempt's stderr:"
    while IFS= read -r line; do
      printf '  %s\n' "$line"
    done < "$VERIFY_ERR_FILE"
  fi
  dump_ecs_events
  exit 1
fi

# Defensive shape validation: a task-def ARN matches
# `arn:aws:ecs:<region>:<account>:task-definition/<family>:<rev>`. If
# AWS CLI ever started writing a JSON-parse warning to stdout under
# load, the warning text would land in $RUNNING_TASK_DEF_AFTER and
# the != $NEW_TASK_DEF_ARN comparison below would false-positive a
# rollback. Reject anything that doesn't look like a task-def ARN
# at all so the failure mode is loud (regex mismatch error) not
# silent (phantom rollback alarm). The regex is permissive on
# region/account/family content but pins the structural prefix
# /^arn:aws:ecs:[^:]+:[0-9]+:task-definition\// + revision suffix.
# Partition-tolerant: matches commercial (arn:aws:), GovCloud
# (arn:aws-us-gov:), China (arn:aws-cn:), or any future partition.
# Today prod is us-east-2 commercial only, but the partition prefix
# is one of the few stable parts of an ARN — widening here is free.
if ! [[ "$RUNNING_TASK_DEF_AFTER" =~ ^arn:[a-z0-9-]+:ecs:[^:]+:[0-9]{12}:task-definition/[^:]+:[0-9]+$ ]]; then
  echo "ERROR: Running task-def ARN failed shape validation: '$RUNNING_TASK_DEF_AFTER'"
  echo "  Expected: arn:aws:ecs:<region>:<account>:task-definition/<family>:<rev>"
  echo "  This usually means AWS CLI emitted unexpected output (parse warning, debug log) on stdout."
  dump_ecs_events
  exit 1
fi

DEPLOYED_TASK_DEF_ARN="$NEW_TASK_DEF_ARN"
DEPLOYED_IMAGE="$NEW_IMAGE"

if [[ "$RUNNING_TASK_DEF_AFTER" != "$NEW_TASK_DEF_ARN" ]]; then
  NEW_TASK_DEF_FAMILY_ARN="${NEW_TASK_DEF_ARN%:*}"
  RUNNING_TASK_DEF_FAMILY_ARN="${RUNNING_TASK_DEF_AFTER%:*}"
  NEW_TASK_DEF_REVISION="${NEW_TASK_DEF_ARN##*:}"
  RUNNING_TASK_DEF_REVISION="${RUNNING_TASK_DEF_AFTER##*:}"

  FORWARD_SAME_FAMILY=false
  if [[ "$RUNNING_TASK_DEF_FAMILY_ARN" == "$NEW_TASK_DEF_FAMILY_ARN" \
     && "$NEW_TASK_DEF_REVISION" =~ ^[0-9]+$ \
     && "$RUNNING_TASK_DEF_REVISION" =~ ^[0-9]+$ ]] \
     && (( 10#$RUNNING_TASK_DEF_REVISION > 10#$NEW_TASK_DEF_REVISION )); then
    FORWARD_SAME_FAMILY=true
  fi

  if [[ "$FORWARD_SAME_FAMILY" == "true" && "$ALLOW_CONCURRENT_FORWARD_DEPLOY" == "true" ]]; then
    echo "::notice::ECS service advanced past the task def registered by this run ($NEW_TASK_DEF_ARN -> $RUNNING_TASK_DEF_AFTER); verifying as a concurrent deploy."

    SSM_VERIFY_ERR_FILE=$(mktemp)  # cleanup via the EXIT trap above
    if ! CURRENT_SSM_IMAGE_TAG=$(aws ssm get-parameter \
        --name "$SSM_IMAGE_TAG_PARAM" \
        --query "Parameter.Value" --output text \
        --region "$AWS_REGION" 2>"$SSM_VERIFY_ERR_FILE"); then
      echo "ERROR: Could not read current image tag from $SSM_IMAGE_TAG_PARAM while verifying concurrent deploy:"
      while IFS= read -r line; do
        printf '  %s\n' "$line"
      done < "$SSM_VERIFY_ERR_FILE"
      dump_ecs_events
      exit 1
    fi
    rm -f "$SSM_VERIFY_ERR_FILE"
    SSM_VERIFY_ERR_FILE=""
    if ! CURRENT_SSM_IMAGE_TAG=$(normalize_token_output "current SSM image tag in $SSM_IMAGE_TAG_PARAM" "$CURRENT_SSM_IMAGE_TAG"); then
      exit 1
    fi
    if [[ -z "$CURRENT_SSM_IMAGE_TAG" || "$CURRENT_SSM_IMAGE_TAG" == "None" ]]; then
      echo "ERROR: Current image tag in $SSM_IMAGE_TAG_PARAM is empty while verifying concurrent deploy."
      dump_ecs_events
      exit 1
    fi

    ACTIVE_TASK_DEF_ERR_FILE=$(mktemp)  # cleanup via the EXIT trap above
    if ! ACTIVE_TASK_DEF=$(aws ecs describe-task-definition \
        --task-definition "$RUNNING_TASK_DEF_AFTER" \
        --query "taskDefinition" --output json \
        --region "$AWS_REGION" 2>"$ACTIVE_TASK_DEF_ERR_FILE"); then
      echo "ERROR: Could not describe newer running task def $RUNNING_TASK_DEF_AFTER while verifying concurrent deploy:"
      while IFS= read -r line; do
        printf '  %s\n' "$line"
      done < "$ACTIVE_TASK_DEF_ERR_FILE"
      dump_ecs_events
      exit 1
    fi
    rm -f "$ACTIVE_TASK_DEF_ERR_FILE"
    ACTIVE_TASK_DEF_ERR_FILE=""

    if ! ACTIVE_IMAGE=$(extract_primary_image "$ACTIVE_TASK_DEF" "newer running task definition $RUNNING_TASK_DEF_AFTER" true "  Check the qurl-service task definition container name or set PRIMARY_CONTAINER for this workflow."); then
      dump_ecs_events
      exit 1
    fi

    # Deliberately use tag form and the repo from the task def this helper read
    # earlier. This sandbox-only branch relies on qurl-service writing the same
    # short SHA tag to SSM before update-service; a concurrent deploy that
    # changes repos, switches to digest pinning, or regresses that ordering fails
    # closed rather than being accepted as a same-image race.
    EXPECTED_CONCURRENT_IMAGE="${IMAGE_REPO}:${CURRENT_SSM_IMAGE_TAG}"
    if [[ "$ACTIVE_IMAGE" != "$EXPECTED_CONCURRENT_IMAGE" ]]; then
      echo "ERROR: ECS service advanced to newer task def $RUNNING_TASK_DEF_AFTER, but '$PRIMARY_CONTAINER' uses $ACTIVE_IMAGE."
      echo "  Expected current SSM image: $EXPECTED_CONCURRENT_IMAGE"
      echo "  This is neither the registered task def nor a verified current-image concurrent deploy."
      dump_ecs_events
      exit 1
    fi

    echo "  Concurrent task def image matches current SSM tag; waiting for that deployment to be stable."
    # Best-effort stay inside the original 600s roll budget. The main wait loop
    # already consumed WAIT_ELAPSED seconds; a superseding deploy gets the
    # remaining time, floored to two intervals for the immediate post-verify
    # race (two reads spanning one interval). The job-level timeout has headroom
    # for that floor plus the 30s ALB settle, rather than two independent 600s
    # waits.
    CONCURRENT_WAIT_TIMEOUT=$((WAIT_TIMEOUT - WAIT_ELAPSED))
    MIN_CONCURRENT_WAIT_TIMEOUT=$((2 * WAIT_INTERVAL))
    if (( CONCURRENT_WAIT_TIMEOUT < MIN_CONCURRENT_WAIT_TIMEOUT )); then
      CONCURRENT_WAIT_TIMEOUT=$MIN_CONCURRENT_WAIT_TIMEOUT
    fi
    wait_for_stable_deployment "$CONCURRENT_WAIT_TIMEOUT" "$RUNNING_TASK_DEF_AFTER"

    DEPLOYED_TASK_DEF_ARN="$RUNNING_TASK_DEF_AFTER"
    DEPLOYED_IMAGE="$ACTIVE_IMAGE"
    echo "  Verified: service is running newer task def $DEPLOYED_TASK_DEF_ARN with current image $DEPLOYED_IMAGE."
    echo "  This run's registered task def $NEW_TASK_DEF_ARN was superseded by a concurrent deploy; treating the service as healthy on the current SSM image."
  else
    if [[ "$FORWARD_SAME_FAMILY" == "true" ]]; then
      echo "ERROR: ECS service advanced to newer task def $RUNNING_TASK_DEF_AFTER, but concurrent forward-deploy tolerance is enabled only for sandbox (prefix: layerv-nhp-sandbox; got: $SSM_PREFIX)."
      echo "  Prod keeps strict exact-match semantics because promote-to-prod is serialized by workflow concurrency."
      dump_ecs_events
      exit 1
    fi
    echo "ERROR: ECS service is running $RUNNING_TASK_DEF_AFTER, not the registered $NEW_TASK_DEF_ARN."
    echo "  ECS circuit breaker rolled back or another deploy moved the service to an unrelated/stale task def."
    echo "  ECS rolloutState=COMPLETED can still mean rollback to a previous task def; exact task-def verification is required before success."
    dump_ecs_events
    exit 1
  fi
else
  echo "  Verified: service is running the new task def $NEW_TASK_DEF_ARN."
fi

# Step 8: Post-stability settling period
# After ECS reports stability, ALB target deregistration and connection draining
# may still be in progress. Old tasks can serve stale responses until
# deregistration completes (configured to 30s in Terraform). A 30s settling
# period ensures the ALB has fully shifted traffic to new targets.
SETTLE_SECONDS=30
echo ""
echo "Step 8: Waiting ${SETTLE_SECONDS}s for ALB connection draining..."
sleep "$SETTLE_SECONDS"
echo "  Settling complete."

echo ""
echo "============================================"
echo "ECS Service Deploy Complete"
echo "============================================"
echo "SSM Prefix:  $SSM_PREFIX"
echo "Image:       $DEPLOYED_IMAGE"
echo "Task Def:    $DEPLOYED_TASK_DEF_ARN"
echo "Service:     $ECS_SERVICE"
echo "Cluster:     $ECS_CLUSTER"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "deployed_image=$DEPLOYED_IMAGE"
    echo "deployed_task_def_arn=$DEPLOYED_TASK_DEF_ARN"
  } >> "$GITHUB_OUTPUT"
fi
