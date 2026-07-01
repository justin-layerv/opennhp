#!/usr/bin/env bash
# Wait for ASG instance refresh to complete with optional canary health check.
# Usage: wait-for-instance-refresh.sh <asg-name> <refresh-id> [health-check-command] [max-iterations]
#
# Arguments:
#   asg-name:             Name of the Auto Scaling Group
#   refresh-id:           Instance refresh ID to monitor
#   health-check-command: Optional SSM command to verify instance health (default: skip health check)
#   max-iterations:       Optional max wait iterations, each 10s (default: 60 = 10 minutes)
#
# Sourceable function:
#   wait_for_instance_refresh <asg-name> <refresh-id> [health-check-command]
#     [max-iterations] [label] [poll-interval-seconds] [max-describe-errors]
#     [deadline-epoch-seconds] [emit-github-annotations]
#
# Environment:
#   AWS_REGION: Region to pass to AWS CLI calls when set.
#   DEPLOYMENT_WINDOW_ENVIRONMENT, DEPLOYMENT_WINDOW_CELL_ID,
#   DEPLOYMENT_WINDOW_COMPONENT, DEPLOYMENT_WINDOW_STRATEGY: when all are set,
#     emit the revocation DeploymentWindow metric while polling long refreshes.
#   DEPLOYMENT_WINDOW_EMIT_INTERVAL_SECONDS: minimum seconds between heartbeat
#     emits from this shell (default: 60).
#   INSTANCE_REFRESH_HEALTH_CHECK_SETTLE_SECONDS: Seconds to wait before reading
#     a canary SSM command result (default: 10).
#
# Exit codes:
#   0 - Instance refresh completed successfully
#   1 - Instance refresh failed or cancelled

wait_refresh_aws() {
  if [[ -n "${AWS_REGION:-}" ]]; then
    aws "$@" --region "$AWS_REGION"
  else
    aws "$@"
  fi
}

WAIT_REFRESH_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=.github/scripts/emit-deployment-window-metric.sh
source "$WAIT_REFRESH_SCRIPT_DIR/emit-deployment-window-metric.sh"

wait_refresh_timeout() {
  local label="$1"
  local subject="$2"
  local refresh_id="$3"
  local asg_name="$4"
  local seconds="$5"
  local emit_github_annotations="$6"

  # Preserve standalone CLI output for callers that may read this script
  # directly, while sourced CI callers can opt into GitHub annotations.
  if [[ "$label" == "Instance" && "$emit_github_annotations" != "true" ]]; then
    echo "ERROR: Instance refresh timed out after ${seconds} seconds"
  elif [[ "$emit_github_annotations" == "true" ]]; then
    echo "::error::$subject $refresh_id on $asg_name did not converge within ${seconds}s."
  else
    echo "ERROR: $subject $refresh_id on $asg_name did not converge within ${seconds}s."
  fi
}

wait_refresh_failure() {
  local label="$1"
  local subject="$2"
  local refresh_id="$3"
  local asg_name="$4"
  local status="$5"
  local emit_github_annotations="$6"

  # Same three output modes as timeout: legacy CLI text, GitHub annotation, or
  # plain ERROR for non-Actions sourced callers.
  if [[ "$label" == "Instance" && "$emit_github_annotations" != "true" ]]; then
    echo "Instance refresh failed: $status"
  elif [[ "$emit_github_annotations" == "true" ]]; then
    echo "::error::$subject $refresh_id on $asg_name ended $status before converging."
  else
    echo "ERROR: $subject $refresh_id on $asg_name ended $status before converging."
  fi
}

wait_for_instance_refresh() {
  local asg_name="${1:?Usage: wait_for_instance_refresh <asg-name> <refresh-id> [health-check-command] [max-iterations] [label] [poll-interval-seconds] [max-describe-errors] [deadline-epoch-seconds] [emit-github-annotations]}"
  local refresh_id="${2:?Usage: wait_for_instance_refresh <asg-name> <refresh-id> [health-check-command] [max-iterations] [label] [poll-interval-seconds] [max-describe-errors] [deadline-epoch-seconds] [emit-github-annotations]}"
  local health_check_cmd="${3:-}"
  local max_iterations="${4:-60}"
  local label="${5:-Instance}"
  local poll_interval_seconds="${6:-10}"
  local max_describe_errors="${7:-3}"
  local deadline_epoch_seconds="${8:-}"
  local emit_github_annotations="${9:-}"
  local health_check_settle_seconds="${INSTANCE_REFRESH_HEALTH_CHECK_SETTLE_SECONDS:-10}"
  local canary_checked="false"
  local command_id describe_err instance_id refresh_data ssm_status status percentage iteration
  local consecutive_errors=0
  local subject="$label instance refresh"
  local timeout_seconds=0
  local now_seconds remaining_seconds progress_suffix

  if [[ "$label" == "Instance" ]]; then
    subject="Instance refresh"
  fi
  if [[ -z "$emit_github_annotations" ]]; then
    if [[ "$label" == "Instance" ]]; then
      emit_github_annotations="false"
    else
      emit_github_annotations="true"
    fi
  fi

  if ((max_iterations > 1)); then
    timeout_seconds=$(((max_iterations - 1) * poll_interval_seconds))
  fi
  if [[ -n "$deadline_epoch_seconds" ]]; then
    now_seconds=$(date +%s || printf '0')
    if ((deadline_epoch_seconds > now_seconds)); then
      timeout_seconds=$((deadline_epoch_seconds - now_seconds))
    fi
  fi

  echo "Waiting for $subject..."
  describe_err=$(mktemp)
  for ((iteration = 1; iteration <= max_iterations; iteration++)); do
    emit_deployment_window_metric_throttled

    if [[ -n "$deadline_epoch_seconds" ]]; then
      now_seconds=$(date +%s || printf '0')
    fi
    if [[ -n "$deadline_epoch_seconds" && "$now_seconds" -ge "$deadline_epoch_seconds" ]]; then
      rm -f "$describe_err"
      wait_refresh_timeout "$label" "$subject" "$refresh_id" "$asg_name" "$timeout_seconds" "$emit_github_annotations"
      return 1
    fi

    # Single call for both fields. A transient AWS CLI/API failure is tolerated,
    # but repeated describe failures fail loud with the captured cause instead
    # of riding the full timeout to a generic "did not converge".
    if refresh_data=$(wait_refresh_aws autoscaling describe-instance-refreshes \
        --auto-scaling-group-name "$asg_name" \
        --instance-refresh-ids "$refresh_id" \
        --query "InstanceRefreshes[0].[Status,PercentageComplete]" \
        --output text 2>"$describe_err"); then
      consecutive_errors=0
    else
      consecutive_errors=$((consecutive_errors + 1))
      if ((consecutive_errors >= max_describe_errors)); then
        if [[ "$emit_github_annotations" == "true" ]]; then
          echo "::error::$label refresh poll: describe-instance-refreshes failed ${consecutive_errors}x in a row on $asg_name (IAM/throttle?):"
        else
          echo "ERROR: $label refresh poll: describe-instance-refreshes failed ${consecutive_errors}x in a row on $asg_name (IAM/throttle?):"
        fi
        cat "$describe_err" >&2
        rm -f "$describe_err"
        return 1
      fi
      refresh_data=""
    fi

    status=$(printf '%s' "$refresh_data" | awk '{print $1}')
    percentage=$(printf '%s' "$refresh_data" | awk '{print $2}')
    if [[ ! "$percentage" =~ ^[0-9]+$ ]]; then percentage=0; fi

    progress_suffix="iter $iteration/$max_iterations"
    if [[ -n "$deadline_epoch_seconds" ]]; then
      remaining_seconds=$((deadline_epoch_seconds - now_seconds))
      if ((remaining_seconds < 0)); then remaining_seconds=0; fi
      progress_suffix+=", $(((remaining_seconds + 59) / 60))m remaining"
    fi
    echo "[$label refresh $refresh_id] $progress_suffix - status=${status:-<none>} progress=${percentage}%"

    case "$status" in
      "Successful")
        if [[ "$label" == "Instance" ]]; then
          echo "Instance refresh completed successfully"
        else
          echo "$subject $refresh_id completed successfully on $asg_name."
        fi
        rm -f "$describe_err"
        return 0
        ;;
      "Failed" | "Cancelled" | "RollbackFailed" | "RollbackSuccessful")
        wait_refresh_failure "$label" "$subject" "$refresh_id" "$asg_name" "$status" "$emit_github_annotations"
        rm -f "$describe_err"
        return 1
        ;;
      "Pending" | "InProgress")
        # Run canary health check once when first instance is replaced.
        if [[ "$percentage" -gt 0 && "$canary_checked" == "false" ]]; then
          canary_checked="true"

          if [[ -z "$health_check_cmd" ]]; then
            if [[ "$label" == "Instance" ]]; then
              echo "Canary instance replaced (health check skipped)"
            fi
          else
            echo "Canary instance replaced, verifying health..."

            instance_id=$(wait_refresh_aws autoscaling describe-auto-scaling-groups \
              --auto-scaling-group-names "$asg_name" \
              --query "AutoScalingGroups[0].Instances[?LifecycleState=='InService'].InstanceId | [0]" \
              --output text 2>/dev/null || echo "")

            if [[ -n "$instance_id" && "$instance_id" != "None" ]]; then
              echo "Verifying health on instance: $instance_id"

              command_id=$(wait_refresh_aws ssm send-command \
                --instance-ids "$instance_id" \
                --document-name "AWS-RunShellScript" \
                --parameters "commands=[\"$health_check_cmd\"]" \
                --query "Command.CommandId" \
                --output text 2>/dev/null || echo "")

              if [[ -n "$command_id" ]]; then
                sleep "$health_check_settle_seconds"
                ssm_status=$(wait_refresh_aws ssm get-command-invocation \
                  --command-id "$command_id" \
                  --instance-id "$instance_id" \
                  --query "Status" \
                  --output text 2>/dev/null || echo "Unknown")

                if [[ "$ssm_status" == "Success" ]]; then
                  echo "Canary health check passed"
                else
                  echo "Canary health check: $ssm_status (continuing...)"
                fi
              fi
            fi
          fi
        fi
        ;;
      *)
        : # Empty, None, or unexpected non-terminal text: keep polling.
        ;;
    esac

    if ((iteration < max_iterations)); then
      sleep "$poll_interval_seconds"
    fi
  done

  rm -f "$describe_err"
  wait_refresh_timeout "$label" "$subject" "$refresh_id" "$asg_name" "$timeout_seconds" "$emit_github_annotations"
  return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -euo pipefail

  ASG_NAME="${1:?Usage: $0 <asg-name> <refresh-id> [health-check-command] [max-iterations]}"
  REFRESH_ID="${2:?Usage: $0 <asg-name> <refresh-id> [health-check-command] [max-iterations]}"
  HEALTH_CHECK_CMD="${3:-}"
  MAX_ITERATIONS="${4:-60}"

  wait_for_instance_refresh "$ASG_NAME" "$REFRESH_ID" "$HEALTH_CHECK_CMD" "$MAX_ITERATIONS"
fi
