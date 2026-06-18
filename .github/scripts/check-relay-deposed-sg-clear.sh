#!/usr/bin/env bash
# check-relay-deposed-sg-clear.sh - fail closed if a deposed relay node SG
# still has ENIs attached, optionally after the recovery refresh.
#
# Usage:
#   check-relay-deposed-sg-clear.sh [--detect-only|--needs-recovery] <terraform-show-plan-file>
#
# Normal mode exits 0 when no deposed relay node SG is present, or when every
# deposed relay node SG in the plan has no dependent ENIs. --detect-only exits
# 0 when the plan contains a parseable deposed relay node SG, 1 when absent,
# and >1 on parser drift/errors; it never calls AWS. --needs-recovery exits 0
# only when a deposed relay node SG still has ENIs attached, 1 when absent or
# already clear, and >1 on parser drift/AWS errors.
#
# The default resource address is intentionally the relay node SG that caused the
# sandbox incident. Other relay SGs can be checked by overriding
# RELAY_DEPOSED_SG_RESOURCE_ADDR, but the workflow keeps the live recovery hook
# node-scoped because the relay ALB SG already freezes description drift.

set -euo pipefail

MODE="require-clear"
case "${1:-}" in
  --detect-only)
    MODE="detect"
    shift
    ;;
  --needs-recovery)
    MODE="needs-recovery"
    shift
    ;;
esac

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 [--detect-only|--needs-recovery] <terraform-show-plan-file>" >&2
  exit 2
fi

PLAN_FILE="$1"
AWS_REGION="${AWS_REGION:-us-east-2}"
# us-east-2 is the repo's current AWS region default; workflow callers can
# still override AWS_REGION explicitly if relay ever moves regions.
AWS_BIN="${CHECK_RELAY_DEPOSED_SG_AWS_BIN:-aws}"
JQ_BIN="${CHECK_RELAY_DEPOSED_SG_JQ_BIN:-jq}"
RELAY_DEPOSED_SG_RESOURCE_ADDR="${RELAY_DEPOSED_SG_RESOURCE_ADDR:-module.nhp.module.relay[0].aws_security_group.relay}"
PARSE_DEPOSED_WITHOUT_ID=42
CHECK_MAX_ITERATIONS="${RELAY_DEPOSED_SG_CHECK_MAX_ITERATIONS:-1}"
CHECK_INTERVAL_SECS="${RELAY_DEPOSED_SG_CHECK_INTERVAL_SECS:-10}"

if [[ ! -r "$PLAN_FILE" ]]; then
  echo "::error::Terraform plan file is not readable: $PLAN_FILE" >&2
  exit 2
fi
if [[ -z "$RELAY_DEPOSED_SG_RESOURCE_ADDR" ]]; then
  echo "::error::RELAY_DEPOSED_SG_RESOURCE_ADDR must not be empty" >&2
  exit 2
fi
if [[ ! "$CHECK_MAX_ITERATIONS" =~ ^[1-9][0-9]*$ ]]; then
  echo "::error::RELAY_DEPOSED_SG_CHECK_MAX_ITERATIONS must be a positive integer, got: $(printf %q "$CHECK_MAX_ITERATIONS")" >&2
  exit 2
fi
if [[ ! "$CHECK_INTERVAL_SECS" =~ ^[0-9]+$ ]]; then
  echo "::error::RELAY_DEPOSED_SG_CHECK_INTERVAL_SECS must be a non-negative integer, got: $(printf %q "$CHECK_INTERVAL_SECS")" >&2
  exit 2
fi

plan_file_first_nonspace_char() {
  awk '
    NF {
      sub(/^[[:space:]]*/, "")
      print substr($0, 1, 1)
      exit
    }
  ' "$PLAN_FILE"
}

parse_text_deposed_relay_sg_ids() {
  # CI passes Terraform's JSON plan to avoid rendered-plan drift. Keep this text
  # parser for manual incident use when an operator already has `terraform show`
  # output rather than the binary plan needed for `terraform show -json`.
  # Header matching is intentionally exact. Header-format drift falls through
  # to Terraform's original DeleteSecurityGroup failure, while body/id drift
  # after a matched header fails closed via PARSE_DEPOSED_WITHOUT_ID.
  awk \
    -v missing_rc="$PARSE_DEPOSED_WITHOUT_ID" \
    -v resource_addr="$RELAY_DEPOSED_SG_RESOURCE_ADDR" '
    BEGIN {
      header_prefix = "  # " resource_addr " (deposed object "
      header_suffix = ") will be destroyed"
    }

    function close_block() {
      if (in_block && !block_has_id) {
        missing_id = 1
      }
      in_block = 0
      block_has_id = 0
    }

    index($0, header_prefix) == 1 && substr($0, length($0) - length(header_suffix) + 1) == header_suffix {
      close_block()
      seen = 1
      in_block = 1
      block_has_id = 0
      next
    }

    in_block && /^  # / {
      close_block()
    }

    in_block && /^[[:space:]]*-[[:space:]]+id[[:space:]]+=/ {
      if (match($0, /"sg-[0-9a-f]+"/)) {
        print substr($0, RSTART + 1, RLENGTH - 2)
        block_has_id = 1
        id_count++
      }
    }

    END {
      close_block()
      if (seen && (missing_id || id_count == 0)) {
        exit missing_rc
      }
    }
  ' "$PLAN_FILE"
}

parse_json_deposed_relay_sg_ids() {
  local match_count
  local ids
  local id
  local id_count=0
  local invalid_id=0

  if ! command -v "$JQ_BIN" >/dev/null 2>&1; then
    echo "::error::jq is required to parse Terraform plan JSON for deposed relay security groups." >&2
    return 2
  fi

  # shellcheck disable=SC2016 # $resource_addr is a jq variable, not a shell variable.
  if ! match_count=$("$JQ_BIN" -r --arg resource_addr "$RELAY_DEPOSED_SG_RESOURCE_ADDR" '
    [
      .resource_changes[]?
      | select(.address == $resource_addr)
      | select((.deposed // null) != null)
      | select((.change.actions // []) == ["delete"])
    ]
    | length
  ' "$PLAN_FILE"); then
    echo "::error::Failed to parse Terraform plan JSON for deposed relay node security groups." >&2
    return 2
  fi
  if [[ ! "$match_count" =~ ^[0-9]+$ ]]; then
    echo "::error::Unexpected Terraform plan JSON match count while parsing deposed relay node security groups: $(printf %q "$match_count")" >&2
    return 2
  fi
  if (( match_count == 0 )); then
    return 0
  fi

  # shellcheck disable=SC2016 # $resource_addr is a jq variable, not a shell variable.
  if ! ids=$("$JQ_BIN" -r --arg resource_addr "$RELAY_DEPOSED_SG_RESOURCE_ADDR" '
    .resource_changes[]?
    | select(.address == $resource_addr)
    | select((.deposed // null) != null)
    | select((.change.actions // []) == ["delete"])
    | .change.before.id? // empty
  ' "$PLAN_FILE"); then
    echo "::error::Failed to extract deposed relay node security group ids from Terraform plan JSON." >&2
    return 2
  fi

  while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    if [[ ! "$id" =~ ^sg-[0-9a-f]+$ ]]; then
      invalid_id=1
      continue
    fi
    printf '%s\n' "$id"
    id_count=$((id_count + 1))
  done <<< "$ids"

  if (( invalid_id != 0 || id_count != match_count )); then
    return "$PARSE_DEPOSED_WITHOUT_ID"
  fi
}

parse_deposed_relay_sg_ids() {
  local first_char
  first_char="$(plan_file_first_nonspace_char)"
  if [[ "$first_char" == "{" ]]; then
    parse_json_deposed_relay_sg_ids
  else
    parse_text_deposed_relay_sg_ids
  fi
}

set +e
DEPOSED_RELAY_SG_IDS="$(parse_deposed_relay_sg_ids)"
PARSE_STATUS=$?
set -e

if [[ "$PARSE_STATUS" -eq "$PARSE_DEPOSED_WITHOUT_ID" ]]; then
  echo "::error::Detected deposed relay node security group in Terraform plan but could not extract its security group id; Terraform output format may have changed." >&2
  exit 2
fi
if [[ "$PARSE_STATUS" -ne 0 ]]; then
  echo "::error::Failed to parse Terraform plan for deposed relay node security groups." >&2
  exit "$PARSE_STATUS"
fi

if [[ -z "$DEPOSED_RELAY_SG_IDS" ]]; then
  if [[ "$MODE" == "detect" || "$MODE" == "needs-recovery" ]]; then
    exit 1
  fi
  exit 0
fi

if [[ "$MODE" == "detect" ]]; then
  exit 0
fi

ATTACHED_DETAILS=()
while IFS= read -r sg_id; do
  [[ -z "$sg_id" ]] && continue
  SG_CLEAR="false"
  for ((attempt = 1; attempt <= CHECK_MAX_ITERATIONS; attempt++)); do
    if ! DEPENDENT_ENIS=$("$AWS_BIN" ec2 describe-network-interfaces \
        --region "$AWS_REGION" \
        --filters "Name=group-id,Values=$sg_id" \
        --query 'NetworkInterfaces[].NetworkInterfaceId' \
        --output text); then
      if (( attempt < CHECK_MAX_ITERATIONS )); then
        echo "::warning::Failed to inspect ENI attachments for deposed relay SG $sg_id; retrying attachment check ($attempt/$CHECK_MAX_ITERATIONS)..." >&2
        sleep "$CHECK_INTERVAL_SECS"
        continue
      fi
      echo "::error::Failed to inspect ENI attachments for deposed relay SG $sg_id after $CHECK_MAX_ITERATIONS check attempt(s)." >&2
      exit 2
    fi

    DEPENDENT_ENIS_COMPACT="${DEPENDENT_ENIS//[[:space:]]/}"
    # Text-mode EC2 list queries normally render an empty array as empty output;
    # keep "None" as a defensive guard for AWS CLI text-mode oddities.
    if [[ -z "$DEPENDENT_ENIS_COMPACT" || "$DEPENDENT_ENIS_COMPACT" == "None" ]]; then
      SG_CLEAR="true"
      break
    fi

    if [[ "$MODE" == "needs-recovery" ]]; then
      break
    fi

    if (( attempt < CHECK_MAX_ITERATIONS )); then
      echo "Deposed relay SG $sg_id still has ENI(s): $DEPENDENT_ENIS; retrying attachment check ($attempt/$CHECK_MAX_ITERATIONS)..." >&2
      sleep "$CHECK_INTERVAL_SECS"
    fi
  done

  if [[ "$SG_CLEAR" != "true" ]]; then
    ATTACHED_DETAILS+=("$sg_id:$DEPENDENT_ENIS")
  fi
done <<< "$DEPOSED_RELAY_SG_IDS"

if [[ "${#ATTACHED_DETAILS[@]}" -eq 0 ]]; then
  if [[ "$MODE" == "needs-recovery" ]]; then
    echo "::notice::Deposed relay node security group cleanup is already ENI-clear; recovery refresh is not needed." >&2
    exit 1
  fi
  exit 0
fi

if [[ "$MODE" == "needs-recovery" ]]; then
  echo "::warning::Deposed relay node security group still has attached ENIs; recovery refresh is required: ${ATTACHED_DETAILS[*]}" >&2
  exit 0
fi

echo "::error::Relay SG recovery did not clear all deposed SG ENI attachments after $CHECK_MAX_ITERATIONS check attempt(s): ${ATTACHED_DETAILS[*]}. Terraform would likely hit DependencyViolation at DeleteSecurityGroup; inspect the relay ASG instance refresh and ENI attachments before retrying." >&2
exit 1
