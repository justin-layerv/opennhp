#!/bin/bash
# Update SSM parameter with new image tag and optionally trigger ASG instance refresh.
# This script enables app-only deployments without running terraform apply.
#
# Usage: update-ssm-image-tag.sh <environment> <component> <image-tag> [--refresh]
#
# Arguments:
#   environment:  Target environment (sandbox, prod)
#   component:    NHP component (server, ac)
#   image-tag:    Docker image tag to deploy (typically commit SHA)
#   --refresh:    Optional flag to trigger ASG instance refresh after SSM update
#
# Environment Variables (for instance refresh):
#   AWS_REGION:   AWS region (default: us-east-2)
#
# Examples:
#   # Update SSM parameter only (new instances will use this tag)
#   ./update-ssm-image-tag.sh sandbox server abc1234
#
#   # Update SSM and trigger instance refresh
#   ./update-ssm-image-tag.sh sandbox server abc1234 --refresh
#
# Exit codes:
#   0 - Success
#   1 - Failed to update SSM parameter
#   2 - Failed to trigger instance refresh
#   3 - Instance refresh failed or cancelled

set -euo pipefail

# Parse arguments
if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <environment> <component> <image-tag> [--refresh]"
  echo "  environment: sandbox, prod"
  echo "  component:   server, ac"
  echo "  image-tag:   Docker image tag (e.g., commit SHA)"
  echo "  --refresh:   Optional flag to trigger ASG instance refresh"
  exit 1
fi

ENVIRONMENT="${1}"
COMPONENT="${2}"
IMAGE_TAG="${3}"
DO_REFRESH="${4:-}"

AWS_REGION="${AWS_REGION:-us-east-2}"

# Validate environment
if [[ "$ENVIRONMENT" != "sandbox" && "$ENVIRONMENT" != "prod" ]]; then
  echo "ERROR: Invalid environment '$ENVIRONMENT'. Must be 'sandbox' or 'prod'."
  exit 1
fi

# Validate component
if [[ "$COMPONENT" != "server" && "$COMPONENT" != "ac" ]]; then
  echo "ERROR: Invalid component '$COMPONENT'. Must be 'server' or 'ac'."
  exit 1
fi

# SSM parameter paths
SSM_IMAGE_TAG_PARAM="/${ENVIRONMENT}/nhp/${COMPONENT}/image-tag"
SSM_ASG_NAME_PARAM="/${ENVIRONMENT}/nhp/${COMPONENT}/asg-name"

echo "============================================"
echo "SSM Image Tag Update"
echo "============================================"
echo "Environment: $ENVIRONMENT"
echo "Component:   $COMPONENT"
echo "Image Tag:   $IMAGE_TAG"
echo "SSM Param:   $SSM_IMAGE_TAG_PARAM"
echo ""

# Update SSM parameter with new image tag
echo "Updating SSM parameter..."
if ! aws ssm put-parameter \
  --name "$SSM_IMAGE_TAG_PARAM" \
  --value "$IMAGE_TAG" \
  --type String \
  --overwrite \
  --region "$AWS_REGION"; then
  echo "ERROR: Failed to update SSM parameter $SSM_IMAGE_TAG_PARAM"
  exit 1
fi
echo "SSM parameter updated successfully: $SSM_IMAGE_TAG_PARAM = $IMAGE_TAG"

# Exit if no refresh requested
if [[ "$DO_REFRESH" != "--refresh" ]]; then
  echo ""
  echo "SSM parameter updated. New instances will use image tag: $IMAGE_TAG"
  echo "To deploy to existing instances, trigger instance refresh manually or use --refresh flag."
  exit 0
fi

# Trigger instance refresh
echo ""
echo "============================================"
echo "Triggering Instance Refresh"
echo "============================================"

# Get ASG name from SSM
echo "Fetching ASG name from SSM: $SSM_ASG_NAME_PARAM"
ASG_NAME=$(aws ssm get-parameter \
  --name "$SSM_ASG_NAME_PARAM" \
  --region "$AWS_REGION" \
  --query "Parameter.Value" \
  --output text 2>/dev/null) || {
  echo "ERROR: Failed to get ASG name from SSM parameter $SSM_ASG_NAME_PARAM"
  echo "This parameter should be created by Terraform. Run terraform apply first."
  exit 2
}

if [[ -z "$ASG_NAME" || "$ASG_NAME" == "None" ]]; then
  echo "ERROR: ASG name not found in SSM parameter $SSM_ASG_NAME_PARAM"
  exit 2
fi
echo "ASG Name: $ASG_NAME"

# Cancel any existing instance refresh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -x "$SCRIPT_DIR/cancel-existing-refresh.sh" ]]; then
  "$SCRIPT_DIR/cancel-existing-refresh.sh" "$ASG_NAME" || true
fi

# Set refresh preferences based on component
if [[ "$COMPONENT" == "server" ]]; then
  MIN_HEALTHY=90
else
  MIN_HEALTHY=50
fi

# SkipMatching must be false because the Docker image tag is stored in SSM and
# read at boot, not baked into the launch template. When the image tag changes,
# the launch template stays the same, so SkipMatching would incorrectly skip
# replacement.
echo "Starting instance refresh..."
REFRESH_ID=$(aws autoscaling start-instance-refresh \
  --auto-scaling-group-name "$ASG_NAME" \
  --preferences "{
    \"MinHealthyPercentage\": $MIN_HEALTHY,
    \"InstanceWarmup\": 180,
    \"MaxHealthyPercentage\": 110,
    \"SkipMatching\": false
  }" \
  --query "InstanceRefreshId" \
  --output text \
  --region "$AWS_REGION") || {
  echo "ERROR: Failed to start instance refresh for $ASG_NAME"
  exit 2
}

echo "Instance Refresh ID: $REFRESH_ID"

# Wait for instance refresh to complete
if [[ -x "$SCRIPT_DIR/wait-for-instance-refresh.sh" ]]; then
  "$SCRIPT_DIR/wait-for-instance-refresh.sh" "$ASG_NAME" "$REFRESH_ID"
else
  echo "WARNING: wait-for-instance-refresh.sh not found, refresh started but not monitored"
  echo "Check AWS console for refresh status: $REFRESH_ID"
fi

echo ""
echo "============================================"
echo "Deployment Complete"
echo "============================================"
echo "Environment: $ENVIRONMENT"
echo "Component:   $COMPONENT"
echo "Image Tag:   $IMAGE_TAG"
echo "ASG:         $ASG_NAME"
echo "Refresh ID:  $REFRESH_ID"
