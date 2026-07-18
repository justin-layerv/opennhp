#!/usr/bin/env bash
# Acquire or release a live-environment lock backed by a single SSM parameter.
#
# GitHub Actions concurrency groups cancel older pending jobs when a third run
# queues for the same group, even with cancel-in-progress=false. This helper
# lets live sandbox jobs wait inside their own run instead, so a queued qv2 smoke
# is not marked cancelled before it can prove the customer path.
set -euo pipefail

usage() {
  echo "usage: $0 acquire|release <ssm-param> <owner> [ttl-seconds] [wait-seconds]" >&2
}

action="${1:-}"
param="${2:-}"
owner="${3:-}"
aws_region="${AWS_REGION:-}"
# Fallbacks mirror sandbox-live-env-lock/action.yml's ttl-seconds/wait-seconds
# defaults; the action always forwards both, so these only apply to a bare CLI
# invocation. Keep them in sync with the action so a direct caller preserves the
# wait < ttl relationship the contract test asserts.
ttl_seconds="${4:-14400}"
wait_seconds="${5:-7200}"

if [[ -z "$action" || -z "$param" || -z "$owner" ]]; then
  usage
  exit 2
fi
if [[ -z "$aws_region" ]]; then
  echo "::error::AWS_REGION must be set before using the sandbox live-environment lock" >&2
  exit 2
fi

lock_value() {
  local now expires_at
  now="$(date -u +%s)"
  expires_at=$((now + ttl_seconds))
  jq -cn \
    --arg owner "$owner" \
    --argjson created_at "$now" \
    --argjson expires_at "$expires_at" \
    '{owner: $owner, created_at: $created_at, expires_at: $expires_at}'
}

emit_lock_metric() {
  local reason="$1"

  # Telemetry must never replace the lock path's specific annotation or return
  # code, including when the vendored helper is absent or invalid. The failure
  # phase forwarded to the helper is the script-global acquire/release action:
  # it is validated by the entry case statement, never reassigned, and matches
  # this file's documented dynamic-scoping style (see parse_lock_fields). The
  # vendored cross-repo contract shape is the external helper's own
  # `<reason> <action>` positional interface, which is unchanged.
  if ! bash "$(dirname "${BASH_SOURCE[0]}")/emit-sandbox-lock-failure-metric.sh" \
    "$reason" "$action"; then
    echo "::warning title=Sandbox live-environment lock metric helper failed::Metric helper failed for reason=$reason action=$action; continuing with primary fail-closed lock handling." >&2
  fi
}

# Read the current lock value to stdout (empty when the parameter is absent).
# Delegate ParameterNotFound-vs-real-AWS-error classification to the shared
# optional SSM reader used by the qURL deploy/smoke paths. This script lives in
# .github/scripts; the reader is the repo-root scripts/ssm-read-optional.sh.
read_lock() {
  bash "$(dirname "${BASH_SOURCE[0]}")/../../scripts/ssm-read-optional.sh" "$param"
}

read_lock_or_fail() {
  local context="$1"
  local value

  if ! value="$(read_lock)"; then
    emit_lock_metric "ReadFailed"
    echo "::error title=Sandbox live-environment lock read failed::Failed to read $param while $context. This is an AWS/SSM failure, not a qv2 admission result; failing closed without retry. See docs/runbooks/sandbox-live-env-lock.md." >&2
    return 3
  fi
  printf '%s' "$value"
}

parse_lock_fields() {
  local raw="$1"
  local parsed_owner parsed_expires_at

  if ! IFS=$'\t' read -r parsed_owner parsed_expires_at \
    < <(jq -er '[.owner, .expires_at] | @tsv' <<<"$raw" 2>/dev/null); then
    return 1
  fi

  if [[ -z "$parsed_owner" || ! "$parsed_expires_at" =~ ^[0-9]+$ || "$parsed_expires_at" -le 0 ]]; then
    return 1
  fi

  # Bash dynamic scoping writes these caller-local variables declared by
  # acquire_lock and release_lock; keep this helper next to those call sites if
  # it grows.
  current_owner="$parsed_owner"
  expires_at="$parsed_expires_at"
}

delete_lock_if_unchanged() {
  local expected_value="$1"
  local reason="$2"
  local latest_value delete_err

  # SSM Parameter Store has no compare-and-delete primitive. Re-read the value
  # immediately before delete and leave the lock alone if another owner moved it.
  # A writer can still appear between this read and delete, so stale-break is
  # best-effort crash recovery. The long TTL keeps healthy holders out of this
  # path; the follow-up acquire still uses --no-overwrite and fails closed if a
  # lock exists.
  latest_value="$(read_lock_or_fail "checking whether the lock changed before delete")" || return $?
  if [[ "$latest_value" != "$expected_value" ]]; then
    echo "::notice::Not deleting live-environment lock $param for $reason; lock changed while waiting"
    return 1
  fi

  if ! delete_err="$(aws ssm delete-parameter \
    --name "$param" \
    --region "$aws_region" 2>&1 >/dev/null)"; then
    emit_lock_metric "DeleteFailed"
    echo "::warning title=Sandbox live-environment lock delete failed::Failed to delete $param for $reason after confirming the owner; lock remains until manual reconciliation or stale TTL. See docs/runbooks/sandbox-live-env-lock.md. AWS error: $delete_err" >&2
    return 2
  fi
}

acquire_lock() {
  local deadline now err_file current current_owner expires_at value delete_status
  deadline=$(($(date -u +%s) + wait_seconds))
  err_file="$(mktemp)"
  trap 'rm -f "$err_file"' EXIT

  while true; do
    value="$(lock_value)"
    if aws ssm put-parameter \
      --name "$param" \
      --type String \
      --value "$value" \
      --region "$aws_region" \
      --no-overwrite > /dev/null 2>"$err_file"; then
      echo "Acquired live-environment lock: $param owner=$owner"
      exit 0
    fi

    # AWS CLI reports SSM's conditional-write contention as ParameterAlreadyExists.
    # If that text ever changes, fail closed as an AWS error instead of assuming
    # the lock is safely held by another job.
    if ! grep -q ParameterAlreadyExists "$err_file"; then
      emit_lock_metric "PutFailed"
      echo "::error::failed to acquire live-environment lock $param: $(cat "$err_file")" >&2
      exit 1
    fi

    now="$(date -u +%s)"
    current="$(read_lock_or_fail "waiting to acquire the lock")" || exit $?
    current_owner=""
    expires_at=0
    if [[ -n "$current" ]]; then
      # One jq pass extracts both fields; @tsv keeps owners with spaces intact.
      # Unparseable lock values fail closed. They may represent manual writes or
      # partial recovery work, and deleting them automatically can release a live
      # sandbox mutation.
      if ! parse_lock_fields "$current"; then
        emit_lock_metric "Malformed"
        echo "::error title=Malformed sandbox live-environment lock::SSM lock $param is present but is not valid lock JSON with owner and numeric expires_at. Follow docs/runbooks/sandbox-live-env-lock.md: verify no sandbox live-env job is running, restore the sandbox task definition if needed, then delete or repair the lock manually." >&2
        exit 1
      fi
    fi

    # expires_at is 0 (no lock present) or a positive integer validated by
    # parse_lock_fields, so the "> 0" guard distinguishes a real expiry from
    # the empty-lock sentinel; no numeric re-check is needed here.
    if [[ "$expires_at" -gt 0 && "$now" -gt "$expires_at" ]]; then
      echo "::warning::Deleting stale live-environment lock $param owned by ${current_owner:-unknown}; expired at $expires_at"
      if delete_lock_if_unchanged "$current" "stale-lock break"; then
        continue
      else
        delete_status=$?
      fi
      if [[ "$delete_status" -ne 1 ]]; then
        exit "$delete_status"
      fi
      continue
    fi

    if [[ "$now" -ge "$deadline" ]]; then
      emit_lock_metric "Contention"
      echo "::error title=Sandbox live-environment lock contention::Timed out waiting for $param; current owner=${current_owner:-unknown}; expires_at=${expires_at:-unknown}. This is sandbox mutex contention, not a qv2 admission result. See docs/runbooks/sandbox-live-env-lock.md." >&2
      exit 1
    fi

    echo "Waiting for live-environment lock $param; current owner=${current_owner:-unknown}"
    sleep 15
  done
}

release_lock() {
  local current current_owner expires_at delete_status
  current="$(read_lock_or_fail "releasing the lock")" || return $?
  if [[ -z "$current" ]]; then
    echo "Live-environment lock already absent: $param"
    return 0
  fi

  current_owner=""
  expires_at=0
  if ! parse_lock_fields "$current"; then
    emit_lock_metric "Malformed"
    echo "::error title=Malformed sandbox live-environment lock::SSM lock $param is present but is not valid lock JSON with owner and numeric expires_at. Not releasing an unparseable lock automatically; follow docs/runbooks/sandbox-live-env-lock.md." >&2
    return 1
  fi

  if [[ "$current_owner" != "$owner" ]]; then
    echo "::notice::Not releasing live-environment lock $param; owner is ${current_owner:-unknown}, not $owner"
    return 0
  fi

  if delete_lock_if_unchanged "$current" "owner release"; then
    echo "Released live-environment lock: $param owner=$owner"
    return 0
  else
    delete_status=$?
    if [[ "$delete_status" -eq 1 ]]; then
      return 0
    fi
    return "$delete_status"
  fi
}

case "$action" in
  acquire)
    acquire_lock
    ;;
  release)
    release_lock
    ;;
  *)
    usage
    exit 2
    ;;
esac
