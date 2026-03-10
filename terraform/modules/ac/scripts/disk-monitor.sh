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

# Publish metric to CloudWatch (unified namespace with Go app metrics)
if declare -f publish_cw_metric &>/dev/null; then
  publish_cw_metric "DiskUsagePercent" "$DISK_USAGE" "Percent" "Component=AC,InstanceId=$INSTANCE_ID"
else
  aws cloudwatch put-metric-data \
    --region "$REGION" \
    --namespace "LayerV/NHP" \
    --metric-name "DiskUsagePercent" \
    --dimensions Component=AC,InstanceId="$INSTANCE_ID" \
    --value "$DISK_USAGE" \
    --unit Percent
fi

# Warning if above threshold
if [ "$DISK_USAGE" -ge "$THRESHOLD" ]; then
  echo "WARNING: Disk usage ($DISK_USAGE%) exceeds threshold ($THRESHOLD%)"
  exit 1
fi

echo "Disk usage is within acceptable limits"
