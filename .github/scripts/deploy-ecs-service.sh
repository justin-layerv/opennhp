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

echo "============================================"
echo "ECS Service Deploy"
echo "============================================"
echo "SSM Prefix:  $SSM_PREFIX"
echo "Image Tag:   $NEW_IMAGE_TAG"
echo ""

# Step 1: Update SSM parameter with new image tag
SSM_IMAGE_TAG_PARAM="/${SSM_PREFIX}/qurl-api-image-tag"
echo "Step 1: Updating SSM parameter: $SSM_IMAGE_TAG_PARAM"
aws ssm put-parameter \
  --name "$SSM_IMAGE_TAG_PARAM" \
  --value "$NEW_IMAGE_TAG" \
  --type String \
  --overwrite \
  --region "$AWS_REGION"
echo "  SSM parameter updated: $SSM_IMAGE_TAG_PARAM = $NEW_IMAGE_TAG"
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
EVENTS_ERR_FILE=""  # used inside dump_ecs_events helper; covered here for signal-safety
# EXIT covers normal exits + set-e exits; INT/TERM cover Ctrl-C / kill.
# CI runners shouldn't see signals in practice but explicit > implicit.
trap 'rm -f "${DESC_ERR_FILE:-}" "${VERIFY_ERR_FILE:-}" "${TASK_DEF_FILE:-}" "${REGISTER_ERR_FILE:-}" "${EVENTS_ERR_FILE:-}"' EXIT INT TERM
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

# Single-container guard: this script derives `IMAGE_REPO` from
# containerDefinitions[0] and the jq filter at Step 4 updates EVERY
# container whose image starts with `$IMAGE_REPO:`. A multi-container
# task where a sidecar shares the repo (e.g., `nhp-qurl:debug-sidecar`
# alongside `nhp-qurl:main`) would have both bumped to the same new
# tag — usually wrong. qurl-service runs single-container today;
# guard so a future multi-container layout fails loud rather than
# silently mis-tagging the sidecar.
CONTAINER_COUNT=$(echo "$CURRENT_TASK_DEF" | jq '.containerDefinitions | length')
if [[ "$CONTAINER_COUNT" != "1" ]]; then
  echo "ERROR: This script only supports single-container task definitions (found $CONTAINER_COUNT containers)."
  echo "  If you need multi-container support, the jq filter at Step 4 must be updated to target a specific container by name, not by repo prefix."
  exit 1
fi

# Extract current image for logging
CURRENT_IMAGE=$(echo "$CURRENT_TASK_DEF" | jq -r '.containerDefinitions[0].image // "unknown"')
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
# Counter for consecutive describe-services parse failures. Empty
# stdout (set when 2>/dev/null swallows an IAM/network/throttle error)
# would otherwise cascade to PRIMARY_DESIRED=0 and silently log
# "0/0 running" for the full WAIT_TIMEOUT before the timeout branch
# fires. After 3 consecutive failures, surface a ::warning:: so an
# operator watching the run log gets a hint that AWS calls are
# failing — without abandoning the loop (transient throttles do
# resolve within the budget).
DESCRIBE_FAIL_STREAK=0
DESCRIBE_FAIL_WARN_THRESHOLD=3

while [[ $WAIT_ELAPSED -lt $WAIT_TIMEOUT ]]; do
  DEPLOYMENT_STATUS=$(aws ecs describe-services \
    --cluster "$ECS_CLUSTER" \
    --services "$ECS_SERVICE" \
    --query "services[0].deployments" --output json \
    --region "$AWS_REGION" 2>/dev/null || echo "[]")

  if [[ "$DEPLOYMENT_STATUS" == "[]" || -z "$DEPLOYMENT_STATUS" ]]; then
    DESCRIBE_FAIL_STREAK=$((DESCRIBE_FAIL_STREAK + 1))
    # Warn at the threshold, then re-warn every Nth iteration after.
    # `% THRESHOLD == 0` re-emits at threshold, 2×threshold, 3×threshold,
    # ... so an operator debugging a sustained outage live keeps getting
    # signal instead of one warning followed by silent minutes.
    if (( DESCRIBE_FAIL_STREAK >= DESCRIBE_FAIL_WARN_THRESHOLD \
       && DESCRIBE_FAIL_STREAK % DESCRIBE_FAIL_WARN_THRESHOLD == 0 )); then
      echo "::warning::aws ecs describe-services has returned empty/missing data $DESCRIBE_FAIL_STREAK consecutive iterations — likely IAM/network/throttle issue. Wait-loop continues; check CloudTrail if WAIT_TIMEOUT trips."
    fi
  else
    DESCRIBE_FAIL_STREAK=0
  fi

  PRIMARY_RUNNING=$(echo "$DEPLOYMENT_STATUS" | jq '[.[] | select(.status == "PRIMARY")] | .[0].runningCount // 0')
  PRIMARY_DESIRED=$(echo "$DEPLOYMENT_STATUS" | jq '[.[] | select(.status == "PRIMARY")] | .[0].desiredCount // 0')
  PRIMARY_PENDING=$(echo "$DEPLOYMENT_STATUS" | jq '[.[] | select(.status == "PRIMARY")] | .[0].pendingCount // 0')
  ACTIVE_COUNT=$(echo "$DEPLOYMENT_STATUS" | jq '[.[] | select(.status == "ACTIVE")] | length')
  ROLLOUT=$(echo "$DEPLOYMENT_STATUS" | jq -r '[.[] | select(.status == "PRIMARY")] | .[0].rolloutState // "unknown"')

  echo "  [${WAIT_ELAPSED}s] PRIMARY: ${PRIMARY_RUNNING}/${PRIMARY_DESIRED} running, ${PRIMARY_PENDING} pending | rollout: ${ROLLOUT} | draining: ${ACTIVE_COUNT}"

  # `PRIMARY_DESIRED -gt 0` guards against a degenerate scaled-to-zero
  # service: 0/0 running + COMPLETED would otherwise satisfy the
  # `RUNNING -eq DESIRED` test and report "stable" on a service with
  # no tasks. qurl-service runs ≥1 today; this guard future-proofs
  # against a manual scale-to-zero through this script.
  if [[ "$ROLLOUT" == "COMPLETED" \
     && "$PRIMARY_DESIRED" -gt 0 \
     && "$PRIMARY_RUNNING" -eq "$PRIMARY_DESIRED" \
     && "$ACTIVE_COUNT" -eq 0 ]]; then
    echo "  Service stable: all tasks running, rollout complete."
    break
  fi

  if [[ "$ROLLOUT" == "FAILED" ]]; then
    echo "ERROR: ECS deployment rollout FAILED (circuit breaker triggered rollback)"
    dump_ecs_events
    exit 1
  fi

  sleep "$WAIT_INTERVAL"
  WAIT_ELAPSED=$((WAIT_ELAPSED + WAIT_INTERVAL))
done

if [[ $WAIT_ELAPSED -ge $WAIT_TIMEOUT ]]; then
  echo "ERROR: Timed out waiting for ECS service stability (${WAIT_TIMEOUT}s)"
  echo "  Check ECS console for deployment status."
  dump_ecs_events
  exit 1
fi

# rolloutState=COMPLETED is also the terminal state of a circuit-breaker
# rollback (running the *previous* task def), so the wait-loop's stability
# check is necessary but not sufficient. Compare the service's current task
# def to the one we registered; if they differ, ECS rolled back. Empty /
# "None" output triggers the same fail-loud branch as a mismatch — if we
# cannot verify, we cannot claim success.
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
  # Belt-and-suspenders: strip ALL whitespace (interior + trailing).
  # `--output text` could emit trailing whitespace that would slip
  # past the ARN shape regex below as a phantom rollback alarm
  # (string compare against $NEW_TASK_DEF_ARN which has no whitespace).
  # The shape regex would catch interior whitespace anyway, so the
  # global strip is simpler than a trailing-only loop.
  RUNNING_TASK_DEF_AFTER="${RUNNING_TASK_DEF_AFTER//[[:space:]]/}"
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

if [[ "$RUNNING_TASK_DEF_AFTER" != "$NEW_TASK_DEF_ARN" ]]; then
  echo "ERROR: ECS service is running $RUNNING_TASK_DEF_AFTER, not the registered $NEW_TASK_DEF_ARN."
  echo "  ECS circuit breaker rolled back. The rollout reached COMPLETED on the previous task def, masking the failure."
  dump_ecs_events
  exit 1
fi
echo "  Verified: service is running the new task def $NEW_TASK_DEF_ARN."

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
echo "Image:       $NEW_IMAGE"
echo "Task Def:    $NEW_TASK_DEF_ARN"
echo "Service:     $ECS_SERVICE"
echo "Cluster:     $ECS_CLUSTER"
