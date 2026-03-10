#!/bin/bash
# Shared helper functions for AC instance scripts.
# Downloaded to /home/ubuntu/scripts/lib.sh at boot.
# Source this file from other scripts:
#   source /home/ubuntu/scripts/lib.sh 2>/dev/null || true

# retry_with_backoff — Run a command with exponential backoff retries.
#   Usage: retry_with_backoff <max_attempts> <initial_delay> <max_delay> <command...>
#   Example: retry_with_backoff 10 2 60 apt-get install -y docker.io
retry_with_backoff() {
    local max_attempts=$1 delay=$2 max_delay=$3
    shift 3
    local attempt=1
    while true; do
        if "$@"; then
            return 0
        fi
        if [ "$attempt" -ge "$max_attempts" ]; then
            echo "ERROR: $* failed after $max_attempts attempts"
            return 1
        fi
        echo "$* failed (attempt $attempt/$max_attempts), retrying in ${delay}s..."
        sleep "$delay"
        attempt=$((attempt + 1))
        delay=$((delay * 2))
        if [ "$delay" -gt "$max_delay" ]; then
            delay=$max_delay
        fi
    done
}

# publish_cw_metric — Publish a single CloudWatch metric to the LayerV/NHP namespace.
#   Usage: publish_cw_metric <metric_name> <value> [unit] [dimensions]
#   Example: publish_cw_metric "DiskUsagePercent" "85" "Percent" "Component=AC,InstanceId=i-123"
#   Requires: AWS CLI. Uses $REGION if set, falls back to us-east-1.
#   Fails silently if aws CLI unavailable or put-metric-data fails.
publish_cw_metric() {
    local metric_name=$1 value=$2 unit=${3:-Count} dimensions=${4:-""}
    local args=(
        --region "${REGION:-us-east-1}"
        --namespace "LayerV/NHP"
        --metric-name "$metric_name"
        --value "$value"
        --unit "$unit"
    )
    [[ -n "$dimensions" ]] && args+=(--dimensions "$dimensions")
    aws cloudwatch put-metric-data "${args[@]}" 2>/dev/null || {
        echo "WARNING: Failed to publish CloudWatch metric $metric_name"
        return 0
    }
}
