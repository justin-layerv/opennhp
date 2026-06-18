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
# Exit codes:
#   0 - Instance refresh completed successfully
#   1 - Instance refresh failed or cancelled

wait_for_instance_refresh() {
  local asg_name="${1:?Usage: wait_for_instance_refresh <asg-name> <refresh-id> [health-check-command] [max-iterations] [label] [poll-interval-seconds] [max-describe-errors]}"
  local refresh_id="${2:?Usage: wait_for_instance_refresh <asg-name> <refresh-id> [health-check-command] [max-iterations] [label] [poll-interval-seconds] [max-describe-errors]}"
  local health_check_cmd="${3:-}"
  local max_iterations="${4:-60}"
  local label="${5:-Instance}"
  local poll_interval_seconds="${6:-10}"
  local max_describe_errors="${7:-3}"
  local canary_checked="false"
  local command_id describe_err instance_id refresh_data ssm_status status percentage iteration
  local consecutive_errors=0
  local subject="$label instance refresh"
  local aws_region_args=()

  if [[ "$label" == "Instance" ]]; then
    subject="Instance refresh"
  fi

  if [[ -n "${AWS_REGION:-}" ]]; then
    aws_region_args=(--region "$AWS_REGION")
  fi

  echo "Waiting for $subject..."
  describe_err=$(mktemp)
  for ((iteration = 1; iteration <= max_iterations; iteration++)); do
    sleep "$poll_interval_seconds"

    # Single call for both fields. A transient AWS CLI/API failure is tolerated,
    # but repeated describe failures fail loud with the captured cause instead
    # of riding the full timeout to a generic "did not converge".
    if refresh_data=$(aws autoscaling describe-instance-refreshes \
        --auto-scaling-group-name "$asg_name" \
        --instance-refresh-ids "$refresh_id" \
        --query "InstanceRefreshes[0].[Status,PercentageComplete]" \
        --output text \
        "${aws_region_args[@]}" 2>"$describe_err"); then
      consecutive_errors=0
    else
      consecutive_errors=$((consecutive_errors + 1))
      if ((consecutive_errors >= max_describe_errors)); then
        echo "::error::$label refresh poll: describe-instance-refreshes failed ${consecutive_errors}x in a row on $asg_name (IAM/throttle?):"
        cat "$describe_err" >&2
        rm -f "$describe_err"
        return 1
      fi
      refresh_data=""
    fi

    status=$(printf '%s' "$refresh_data" | awk '{print $1}')
    percentage=$(printf '%s' "$refresh_data" | awk '{print $2}')
    if [[ ! "$percentage" =~ ^[0-9]+$ ]]; then percentage=0; fi

    echo "[$label refresh $refresh_id] iter $iteration/$max_iterations - status=${status:-<none>} progress=${percentage}%"

    case "$status" in
      "Successful")
        echo "$subject $refresh_id completed successfully on $asg_name."
        rm -f "$describe_err"
        return 0
        ;;
      "Failed" | "Cancelled")
        echo "::error::$subject $refresh_id on $asg_name ended $status before converging."
        rm -f "$describe_err"
        return 1
        ;;
      "Pending" | "InProgress")
        # Run canary health check once when first instance is replaced.
        if [[ "$percentage" =~ ^[0-9]+$ && "$percentage" -gt 0 && "$canary_checked" == "false" ]]; then
          canary_checked="true"

          if [[ -z "$health_check_cmd" ]]; then
            echo "Canary instance replaced (health check skipped)"
            continue
          fi

          echo "Canary instance replaced, verifying health..."

          instance_id=$(aws autoscaling describe-auto-scaling-groups \
            --auto-scaling-group-names "$asg_name" \
            --query "AutoScalingGroups[0].Instances[?LifecycleState=='InService'].InstanceId | [0]" \
            --output text \
            "${aws_region_args[@]}")

          if [[ -n "$instance_id" && "$instance_id" != "None" ]]; then
            echo "Verifying health on instance: $instance_id"

            command_id=$(aws ssm send-command \
              --instance-ids "$instance_id" \
              --document-name "AWS-RunShellScript" \
              --parameters "commands=[\"$health_check_cmd\"]" \
              --query "Command.CommandId" \
              --output text \
              "${aws_region_args[@]}" 2>/dev/null || echo "")

            if [[ -n "$command_id" ]]; then
              sleep "$poll_interval_seconds"
              ssm_status=$(aws ssm get-command-invocation \
                --command-id "$command_id" \
                --instance-id "$instance_id" \
                --query "Status" \
                --output text \
                "${aws_region_args[@]}" 2>/dev/null || echo "Unknown")

              if [[ "$ssm_status" == "Success" ]]; then
                echo "Canary health check passed"
              else
                echo "Canary health check: $ssm_status (continuing...)"
              fi
            fi
          fi
        fi
        ;;
      *)
        : # Empty, None, or unexpected non-terminal text: keep polling.
        ;;
    esac
  done

  rm -f "$describe_err"
  echo "::error::$subject $refresh_id on $asg_name did not converge within $((max_iterations * poll_interval_seconds))s."
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
