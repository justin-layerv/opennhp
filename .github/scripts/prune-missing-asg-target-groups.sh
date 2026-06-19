#!/usr/bin/env bash
# Remove stale target-group associations from an Auto Scaling group.
#
# ASG launch validation fails with "One or more target groups not found" when
# the group still carries an ELB target-group ARN that has already been deleted.
# This script only detaches ARNs that ELBv2 confirms are TargetGroupNotFound.
# It adds one read-only ELBv2 describe call per attached target group; standby
# ASGs normally have a small target-group set, and the deploy unblock is worth it.
# It uses the caller's AWS environment (AWS_REGION / AWS_DEFAULT_REGION /
# AWS_PROFILE), matching the blue-green deploy workflow and manual AWS CLI use.
#
# Usage: prune-missing-asg-target-groups.sh <asg-name>

set -euo pipefail

usage() {
  echo "Usage: $0 <asg-name>" >&2
}

ASG_NAME="${1:-${ASG_NAME:-}}"
DRY_RUN="${DRY_RUN:-false}"
WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-60}"
WAIT_INTERVAL_SECONDS="${WAIT_INTERVAL_SECONDS:-5}"
VALIDATION_RETRIES="${VALIDATION_RETRIES:-4}"
VALIDATION_RETRY_INTERVAL_SECONDS="${VALIDATION_RETRY_INTERVAL_SECONDS:-2}"
ALLOW_ZERO_WAIT_INTERVAL="${ALLOW_ZERO_WAIT_INTERVAL:-false}"
DETACH_TARGET_GROUP_BATCH_SIZE=10
ERROR_FILE=$(mktemp "${TMPDIR:-/tmp}/prune-asg-tg-error.XXXXXX")
trap 'rm -f "$ERROR_FILE"' EXIT

if [[ -z "$ASG_NAME" ]]; then
  echo "::error::Standby ASG name is empty; prepare output missing or ASG_NAME not set." >&2
  usage
  exit 2
fi

# WAIT_TIMEOUT_SECONDS accepts 0 so tests/manual probes can force one immediate
# post-detach read; the deploy workflow uses the 60s default.
if ! [[ "$WAIT_TIMEOUT_SECONDS" =~ ^[0-9]+$ && "$WAIT_INTERVAL_SECONDS" =~ ^[0-9]+$ && "$VALIDATION_RETRIES" =~ ^[1-9][0-9]*$ && "$VALIDATION_RETRY_INTERVAL_SECONDS" =~ ^[0-9]+$ ]]; then
  echo "::error::WAIT_TIMEOUT_SECONDS, WAIT_INTERVAL_SECONDS, VALIDATION_RETRIES, and VALIDATION_RETRY_INTERVAL_SECONDS must be valid non-negative integers; VALIDATION_RETRIES must be at least 1" >&2
  exit 2
fi

if [[ "$WAIT_INTERVAL_SECONDS" == "0" && "$ALLOW_ZERO_WAIT_INTERVAL" != "true" ]]; then
  echo "::error::WAIT_INTERVAL_SECONDS must be at least 1 outside the fixture harness" >&2
  exit 2
fi

parse_target_groups() {
  local text="$1"
  if [[ -z "$text" || "$text" == "None" ]]; then
    return 0
  fi
  printf '%s\n' "$text" | tr '[:space:]' '\n' | sed '/^$/d'
}

describe_asg_summary() {
  local attempt=1
  local describe_error
  local output
  # JMESPath literal: backticks are AWS CLI syntax, not shell expansion. Use
  # JSON string literals for tab/newline so this does not depend on jmespath's
  # deprecated raw-literal fallback.
  # Shell fixtures cover the count<TAB>newline-joined output layout; live PR
  # validation covers the real AWS CLI/JMESPath evaluator for this expression.
  # shellcheck disable=SC2016
  local asg_summary_query='join(`"\t"`, [to_string(length(AutoScalingGroups)), join(`"\n"`, not_null(AutoScalingGroups[0].TargetGroupARNs, `[]`))])'

  while true; do
    if output=$(aws autoscaling describe-auto-scaling-groups \
      --auto-scaling-group-names "$ASG_NAME" \
      --query "$asg_summary_query" \
      --output text 2>"$ERROR_FILE"); then
      printf '%s\n' "$output"
      return 0
    fi

    describe_error=$(<"$ERROR_FILE")
    if ((attempt >= VALIDATION_RETRIES)) || ! is_retryable_describe_error "$describe_error"; then
      echo "::error::Failed to read ASG $ASG_NAME target-group associations" >&2
      echo "$describe_error" >&2
      return 1
    fi

    echo "::warning::Retryable error reading ASG $ASG_NAME target-group associations (attempt $attempt/$VALIDATION_RETRIES): $describe_error" >&2
    sleep "$VALIDATION_RETRY_INTERVAL_SECONDS"
    attempt=$((attempt + 1))
  done
}

contains_arn() {
  local needle="$1"
  shift
  local arn
  for arn in "$@"; do
    if [[ "$arn" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

detach_missing_target_groups() {
  local target_groups_to_detach=("$@")
  local start=0
  local chunk=()
  # AWS DetachLoadBalancerTargetGroups accepts at most 10 target-group ARNs.
  # A later chunk can fail after earlier chunks detach; reruns are idempotent
  # because the script re-describes the ASG before deciding what remains stale.
  while ((start < ${#target_groups_to_detach[@]})); do
    chunk=("${target_groups_to_detach[@]:start:DETACH_TARGET_GROUP_BATCH_SIZE}")
    if ! aws autoscaling detach-load-balancer-target-groups \
      --auto-scaling-group-name "$ASG_NAME" \
      --target-group-arns "${chunk[@]}" 2>"$ERROR_FILE"; then
      local detach_error
      detach_error=$(<"$ERROR_FILE")
      echo "::error::Failed to detach deleted target group association(s) from ASG $ASG_NAME: ${chunk[*]}" >&2
      echo "$detach_error" >&2
      exit 1
    fi
    start=$((start + DETACH_TARGET_GROUP_BATCH_SIZE))
  done
}

is_retryable_describe_error() {
  local error="$1"
  # AWS CLI v2 exposes these transient cases through stderr in this shell path;
  # keep the matcher allow-listed so unknown errors still stop the deploy.
  [[ "$error" == *"Throttling"* ||
    "$error" == *"RequestLimitExceeded"* ||
    "$error" == *"TooManyRequests"* ||
    "$error" == *"ServiceUnavailable"* ||
    "$error" == *"InternalError"* ||
    "$error" == *"InternalFailure"* ||
    "$error" == *"temporarily unavailable"* ||
    "$error" == *"HTTP 500"* ||
    "$error" == *"HTTP 502"* ||
    "$error" == *"HTTP 503"* ||
    "$error" == *"HTTP 504"* ]]
}

describe_elbv2_target_group() {
  local target_group="$1"
  local attempt=1
  local describe_error

  while true; do
    if aws elbv2 describe-target-groups \
      --target-group-arns "$target_group" \
      --query 'TargetGroups[0].TargetGroupArn' \
      --output text >/dev/null 2>"$ERROR_FILE"; then
      return 0
    fi

    describe_error=$(<"$ERROR_FILE")
    if [[ "$describe_error" == *"TargetGroupNotFound"* ]]; then
      # Treat not-found as authoritative for deploy-time pruning: these target
      # groups are Terraform-managed long-lived infra, not just-created outputs.
      return 2
    fi

    if ((attempt >= VALIDATION_RETRIES)) || ! is_retryable_describe_error "$describe_error"; then
      return 1
    fi

    echo "::warning::Retryable error validating target group $target_group for ASG $ASG_NAME (attempt $attempt/$VALIDATION_RETRIES): $describe_error" >&2
    sleep "$VALIDATION_RETRY_INTERVAL_SECONDS"
    attempt=$((attempt + 1))
  done
}

if ! asg_summary=$(describe_asg_summary); then
  exit 1
fi
asg_count="${asg_summary%%$'\t'*}"
if [[ "$asg_summary" == "$asg_count" ]]; then
  target_groups_text=""
else
  target_groups_text="${asg_summary#*$'\t'}"
fi

if [[ "$asg_count" != "1" ]]; then
  echo "::error::Auto Scaling group not found: $ASG_NAME" >&2
  exit 1
fi

mapfile -t target_groups < <(parse_target_groups "$target_groups_text")

if ((${#target_groups[@]} == 0)); then
  echo "::error::ASG $ASG_NAME has no target groups. Refusing to scale a standby ASG with no load balancer registration; run Terraform to attach valid target groups first." >&2
  exit 1
fi

missing=()
for target_group in "${target_groups[@]}"; do
  # Validate one ARN at a time: a batched ELBv2 describe fails the entire call
  # when any ARN is missing, which hides exactly which ASG association is stale.
  if describe_elbv2_target_group "$target_group"; then
    echo "Validated target group exists: $target_group"
    continue
  else
    # Keep this in the `else`: after the `if` compound completes, `$?` becomes
    # the compound status rather than the helper's return code.
    describe_rc=$?
  fi

  if [[ "$describe_rc" == "2" ]]; then
    echo "::warning::ASG $ASG_NAME references deleted target group: $target_group"
    missing+=("$target_group")
  else
    describe_error=$(<"$ERROR_FILE")
    echo "::error::Failed to validate target group $target_group for ASG $ASG_NAME" >&2
    echo "$describe_error" >&2
    exit 1
  fi
done

if ((${#missing[@]} == 0)); then
  echo "ASG $ASG_NAME target-group associations are valid."
  exit 0
fi

if ((${#missing[@]} == ${#target_groups[@]})); then
  # Intentional even for DRY_RUN: an ASG with no valid target groups is a deeper
  # infra break, not a stale-association cleanup.
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "::error::[DRY RUN] Every target group currently attached to ASG $ASG_NAME is deleted. Dry-run fails intentionally because the deploy would be unsafe; run Terraform to reattach valid target groups before scaling or switching traffic." >&2
  else
    echo "::error::Every target group currently attached to ASG $ASG_NAME is deleted. Refusing to detach all target groups during deploy; run Terraform to reattach valid target groups before scaling or switching traffic." >&2
  fi
  exit 1
fi

echo "::warning::ASG $ASG_NAME has ${#missing[@]} deleted target group association(s); pruning only removes stale ARNs and does not attach replacement target groups. Run Terraform if a target group was recreated under a new ARN."

if [[ "$DRY_RUN" == "true" ]]; then
  echo "[DRY RUN] Would detach missing target group(s) from ASG $ASG_NAME:"
  printf '  %s\n' "${missing[@]}"
  exit 0
fi

echo "::notice::Detaching ${#missing[@]} deleted target group association(s) from ASG $ASG_NAME"
detach_missing_target_groups "${missing[@]}"

deadline=$((SECONDS + WAIT_TIMEOUT_SECONDS))
while true; do
  if ! current_summary=$(describe_asg_summary); then
    exit 1
  fi
  current_count="${current_summary%%$'\t'*}"
  if [[ "$current_summary" == "$current_count" ]]; then
    current_text=""
  else
    current_text="${current_summary#*$'\t'}"
  fi

  if [[ "$current_count" != "1" ]]; then
    # A zero-count exact-name lookup after detach means the workflow's ASG output
    # disappeared or the ASG was deleted; fail fast instead of polling a missing
    # deploy target.
    echo "::error::Auto Scaling group disappeared while waiting for deleted target group associations to detach: $ASG_NAME" >&2
    exit 1
  fi

  mapfile -t current_target_groups < <(parse_target_groups "$current_text")

  remaining=()
  for target_group in "${missing[@]}"; do
    if ((${#current_target_groups[@]} > 0)) && contains_arn "$target_group" "${current_target_groups[@]}"; then
      remaining+=("$target_group")
    fi
  done

  if ((${#remaining[@]} == 0)); then
    echo "ASG $ASG_NAME no longer references deleted target group(s)."
    exit 0
  fi

  if ((SECONDS >= deadline)); then
    echo "::error::Timed out waiting for ASG $ASG_NAME to drop deleted target group(s): ${remaining[*]}" >&2
    exit 1
  fi

  echo "Waiting for ASG $ASG_NAME to drop deleted target group(s): ${remaining[*]}"
  sleep "$WAIT_INTERVAL_SECONDS"
done
