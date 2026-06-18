#!/bin/bash
# Update SSM parameter with new image tag and optionally trigger ASG instance refresh.
# This script enables app-only deployments without running terraform apply.
#
# Usage: update-ssm-image-tag.sh <environment> <component> <image-tag> [--refresh]
#
# Arguments:
#   environment:  Target environment — prod only. Sandbox writes are
#                 routed through blue-green-deploy.yml (which writes the
#                 standby slot via active-color indirection). See
#                 scripts/check-image-tag-writer-allowlist.sh for why.
#   component:    NHP component (server, ac, reverse-tunnel-server)
#   image-tag:    Docker image tag to deploy (typically commit SHA)
#   --refresh:    Optional flag to trigger ASG instance refresh after SSM update
#
# Environment Variables (for instance refresh):
#   AWS_REGION:   AWS region (default: us-east-2)
#
# Examples:
#   # Update SSM parameter only (new instances will use this tag)
#   ./update-ssm-image-tag.sh prod server abc1234
#
#   # Update SSM and trigger instance refresh
#   ./update-ssm-image-tag.sh prod server abc1234 --refresh
#
# Exit codes:
#   0 - Success
#   1 - Failed to update SSM parameter / invalid args
#   2 - Failed to trigger instance refresh
#   3 - Instance refresh failed or cancelled

set -euo pipefail

# Parse arguments
if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <environment> <component> <image-tag> [--refresh]"
  echo "  environment: prod   (sandbox writes go through blue-green-deploy.yml)"
  echo "  component:   server, ac, reverse-tunnel-server"
  echo "  image-tag:   Docker image tag (e.g., commit SHA)"
  echo "  --refresh:   Optional flag to trigger ASG instance refresh"
  exit 1
fi

ENVIRONMENT="${1}"
COMPONENT="${2}"
IMAGE_TAG="${3}"
DO_REFRESH="${4:-}"

AWS_REGION="${AWS_REGION:-us-east-2}"
export AWS_REGION

# Validate environment.
#
# This helper is the prod-canary slot writer (only caller is
# promote-to-prod.yml). Sandbox uses blue/green via
# blue-green-deploy.yml — which writes the STANDBY slot via
# active-color indirection. Letting this helper write
# /sandbox/nhp/<component>/image-tag would re-introduce a second
# uncoordinated writer of that slot, which is the exact class of
# bug PR #2026 closed (see scripts/check-image-tag-writer-allowlist.sh
# for the full background; #2028 tracks widening the detector to
# also cover boto3-shaped writers). Reject sandbox at the boundary.
if [[ "$ENVIRONMENT" == "sandbox" ]]; then
  echo "ERROR: update-ssm-image-tag.sh is prod-only. Use blue-green-deploy.yml for sandbox image-tag updates (it writes the standby slot via active-color indirection)." >&2
  exit 1
fi
if [[ "$ENVIRONMENT" != "prod" ]]; then
  echo "ERROR: Invalid environment '$ENVIRONMENT'. Must be 'prod'."
  exit 1
fi

# Validate component
if [[ "$COMPONENT" != "server" && "$COMPONENT" != "ac" && "$COMPONENT" != "reverse-tunnel-server" ]]; then
  echo "ERROR: Invalid component '$COMPONENT'. Must be 'server', 'ac', or 'reverse-tunnel-server'."
  exit 1
fi

# Validate the image-tag string at the helper boundary (defense-in-depth).
# Callers already validate their own tags — deploy-server/ac pass commit SHAs;
# deploy-qrts's resolve-frps-tag enforces Docker's TagRegexp upstream — but this
# helper is the shared prod-canary slot writer, so it re-checks rather than
# trusting every present and future caller. The pattern is Docker's own tag
# grammar (alnum/underscore start, then alnum/._- up to 128 chars), which keeps
# shell metacharacters out of the value before it reaches SSM / any downstream
# interpolation.
if [[ ! "$IMAGE_TAG" =~ ^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$ ]]; then
  echo "ERROR: Invalid image tag '$IMAGE_TAG'. Must match Docker tag grammar ^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}\$ (alphanumerics, '.', '_', '-'; <=128 chars)." >&2
  exit 1
fi

# ECR repository names (images are always in the sandbox account ECR)
declare -A ECR_REPOS=(
  ["server"]="layerv/nhp-server"
  ["ac"]="layerv/nhp-ac"
  ["reverse-tunnel-server"]="layerv/qurl-reverse-tunnel-server"
)
ECR_REPO="${ECR_REPOS[$COMPONENT]}"

# SSM parameter paths
SSM_IMAGE_TAG_PARAM="/${ENVIRONMENT}/nhp/${COMPONENT}/image-tag"
SSM_ASG_NAME_PARAM="/${ENVIRONMENT}/nhp/${COMPONENT}/asg-name"

# Single source of truth for the slot path: this writer derives it; CI callers
# (e.g. the deploy-qrts summary) read it back from here instead of re-declaring
# the literal in workflow env. No-op outside Actions (GITHUB_OUTPUT unset).
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "ssm_image_tag_param=${SSM_IMAGE_TAG_PARAM}" >> "$GITHUB_OUTPUT"
fi

echo "============================================"
echo "SSM Image Tag Update"
echo "============================================"
echo "Environment: $ENVIRONMENT"
echo "Component:   $COMPONENT"
echo "Image Tag:   $IMAGE_TAG"
echo "ECR Repo:    $ECR_REPO"
echo "SSM Param:   $SSM_IMAGE_TAG_PARAM"
echo ""

# Verify image exists in ECR before updating SSM.
# This prevents SSM poisoning when a build failed or an image was evicted
# by lifecycle policies. Instances that boot with a missing image tag will
# fail to start, causing ASG boot loops.
echo "Verifying image exists in ECR: $ECR_REPO:$IMAGE_TAG..."
if ! aws ecr describe-images \
  --repository-name "$ECR_REPO" \
  --image-ids imageTag="$IMAGE_TAG" \
  --query "imageDetails[0].imagePushedAt" \
  --output text \
  --region "$AWS_REGION" > /dev/null 2>&1; then
  echo "ERROR: Image $ECR_REPO:$IMAGE_TAG not found in ECR."
  echo "The image may have been evicted by lifecycle policy or the build may have failed."
  echo "SSM parameter NOT updated — this prevents ASG boot loops."
  exit 1
fi
echo "Image verified: $ECR_REPO:$IMAGE_TAG exists in ECR"
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

# Min-healthy-percentage during the rolling instance refresh, per component.
#
# Explicit per-component (like ECR_REPOS above) rather than an `else` default,
# so the safety requirement is declared, not inherited: 50% keeps the fleet
# serving when the prod ASG runs >= 2 instances (ac N/N/N, qrts 3/3/3 — 50%
# rolls 1 at a time, keeping the rest). server runs a larger fleet at 90%. A new
# component must add its own entry here — `set -u` makes a missing key fail
# loud (caught by the component validation above), instead of silently
# inheriting an unsafe value.
declare -A COMPONENT_MIN_HEALTHY=(
  ["server"]="90"
  ["ac"]="50"
  ["reverse-tunnel-server"]="50"
)
MIN_HEALTHY="${COMPONENT_MIN_HEALTHY[$COMPONENT]}"

# Max status polls for wait-for-instance-refresh.sh, per component. The helper
# polls immediately, then sleeps 10s between attempts, so the default 60 polls
# allow 59 sleeps (~590s) plus describe latency. Explicit per-component (like
# COMPONENT_MIN_HEALTHY above) rather than the script default: the
# reverse-tunnel-server 3/3/3 fleet rolls one instance at a time at 50%
# min-healthy with a 180s warmup, so a full refresh runs ~11 min — the old
# ~10-min default timed out mid-roll and false-failed deploy-qrts even though
# the refresh had succeeded (prod run 26736875324). 150 polls (~1490s plus
# describe latency) clears that with headroom, under deploy-qrts's 30-min job
# timeout. server/ac deploy via canary in mature prod and only reach this wait
# on a greenfield first-deploy fallback, where ~590s holds — bump their entry if
# a larger first-deploy fleet ever needs it. `set -u` makes a missing key fail
# loud (caught by the component validation above).
declare -A COMPONENT_REFRESH_MAX_ITERATIONS=(
  ["server"]="60"
  ["ac"]="60"
  ["reverse-tunnel-server"]="150"
)
REFRESH_MAX_ITERATIONS="${COMPONENT_REFRESH_MAX_ITERATIONS[$COMPONENT]}"

# Runtime guard: AWS computes MinHealthyPercentage against the ASG's *live*
# DesiredCapacity at refresh time, not the >=2 the table assumes. If a fleet is
# ever scaled to a single instance (manual debugging, a cost tfvar), no
# percentage both makes progress AND keeps a host in service — replacing the
# one instance either stalls (min-healthy rounds up to the whole fleet) or drops
# it (rounds to 0). Refuse rather than risk a surprise prod outage or a hung
# deploy; the operator scales to >=2 for a zero-downtime refresh, or replaces
# the instance out-of-band if a brief outage is acceptable.
DESIRED_CAPACITY=$(aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names "$ASG_NAME" \
  --query "AutoScalingGroups[0].DesiredCapacity" \
  --output text \
  --region "$AWS_REGION" 2>/dev/null) || DESIRED_CAPACITY=""
if [[ "$DESIRED_CAPACITY" =~ ^[0-9]+$ && "$DESIRED_CAPACITY" -lt 2 ]]; then
  echo "ERROR: ASG $ASG_NAME has DesiredCapacity=$DESIRED_CAPACITY (<2). A rolling refresh at MIN_HEALTHY=${MIN_HEALTHY}% cannot keep $COMPONENT in service while replacing its only instance — it would stall or drop prod. Scale the ASG to >=2 for a zero-downtime refresh, or replace the instance out-of-band if a brief outage is acceptable." >&2
  exit 2
fi
if [[ ! "$DESIRED_CAPACITY" =~ ^[0-9]+$ ]]; then
  echo "::warning::Could not read DesiredCapacity for $ASG_NAME (got '${DESIRED_CAPACITY:-empty}') — proceeding with MIN_HEALTHY=${MIN_HEALTHY}% unchecked. Verify the ASG runs >=2 instances."
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

# Wait for instance refresh to complete. Source the helper instead of invoking
# its standalone CLI so this CI path can keep GitHub annotations on failures
# while the helper still preserves legacy CLI output for direct callers.
if [[ -x "$SCRIPT_DIR/wait-for-instance-refresh.sh" ]]; then
  # shellcheck source=.github/scripts/wait-for-instance-refresh.sh
  source "$SCRIPT_DIR/wait-for-instance-refresh.sh"
  wait_for_instance_refresh "$ASG_NAME" "$REFRESH_ID" "" "$REFRESH_MAX_ITERATIONS" "Instance" 10 3 "" true
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
