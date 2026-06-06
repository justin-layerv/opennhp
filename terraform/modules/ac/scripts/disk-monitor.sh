#!/bin/bash
# Monitor disk space and publish CloudWatch metrics
# SSM Parameters: Threshold
# Note: Requires AWS CLI and ec2 instance profile with cloudwatch:PutMetricData

THRESHOLD="{{ Threshold }}"
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)

# Ensure snap binaries are in PATH (for AWS CLI)
export PATH="/snap/bin:$PATH"

# Source shared helpers (retry, metrics)
source /home/ubuntu/scripts/lib.sh 2>/dev/null || true

# Get disk usage percentage for root filesystem
DISK_USAGE=$(df / | awk 'NR==2 {gsub(/%/,""); print $5}')

echo "Instance: $INSTANCE_ID"
echo "Disk usage: $DISK_USAGE%"
echo "Threshold: $THRESHOLD%"

# Publish metric to CloudWatch (unified namespace with Go app metrics).
#
# Dimension set is {Component=AC} ONLY — deliberately no InstanceId. The
# disk_usage_high alarm and the dashboard widget both read {Component=AC};
# tagging InstanceId here put every instance on its own per-instance stream,
# so the {Component=AC} stream the alarm/widget watch never existed and the
# alarm sat in permanent OK (issue #968). With InstanceId dropped, the fleet
# aggregates into one stream and `statistic = Maximum` on the alarm pages on
# the worst instance's disk usage. Per-instance identification is still
# available from this script's echo output captured by SSM run-command — the
# InstanceId CW dimension was not consumed by any alarm or dashboard.
if declare -f publish_cw_metric &>/dev/null; then
  publish_cw_metric "DiskUsagePercent" "$DISK_USAGE" "Percent" "Component=AC"
else
  aws cloudwatch put-metric-data \
    --region "$REGION" \
    --namespace "LayerV/NHP" \
    --metric-name "DiskUsagePercent" \
    --dimensions Component=AC \
    --value "$DISK_USAGE" \
    --unit Percent
fi

# Warning if above threshold
if [ "$DISK_USAGE" -ge "$THRESHOLD" ]; then
  echo "WARNING: Disk usage ($DISK_USAGE%) exceeds threshold ($THRESHOLD%)"
  exit 1
fi

echo "Disk usage is within acceptable limits"
