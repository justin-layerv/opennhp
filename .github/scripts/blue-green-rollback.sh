#!/bin/bash
# Blue/Green Rollback Script
#
# Performs instant rollback by switching NLB traffic back to the previous color.
# This is the fastest possible rollback - just an NLB listener change.
#
# Usage: blue-green-rollback.sh <environment>
#
# Arguments:
#   environment - Environment name (sandbox, prod)
#
# Environment Variables (optional):
#   AWS_REGION  - AWS region (default: us-east-2)
#   DRY_RUN     - Set to "true" to show what would be done without executing
#
# Example:
#   ./blue-green-rollback.sh sandbox
#   DRY_RUN=true ./blue-green-rollback.sh prod

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_rollback() { echo -e "${BLUE}[ROLLBACK]${NC} $*"; }

# Validate arguments
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <environment>"
    echo "  environment: sandbox, prod"
    exit 1
fi

ENVIRONMENT="$1"
AWS_REGION="${AWS_REGION:-us-east-2}"
DRY_RUN="${DRY_RUN:-false}"

log_rollback "=========================================="
log_rollback "INITIATING ROLLBACK"
log_rollback "Environment: $ENVIRONMENT"
log_rollback "=========================================="

[[ "$DRY_RUN" == "true" ]] && log_warn "DRY RUN MODE - No changes will be made"

# SSM parameter base path
SSM_BASE="/${ENVIRONMENT}/nhp/server"

# Function to get SSM parameter
get_ssm_param() {
    local param_name="$1"
    aws ssm get-parameter \
        --name "$param_name" \
        --query "Parameter.Value" \
        --output text \
        --region "$AWS_REGION" 2>/dev/null || echo ""
}

# Get current active color
CURRENT_COLOR=$(get_ssm_param "${SSM_BASE}/active-color")
if [[ -z "$CURRENT_COLOR" ]]; then
    log_error "Failed to get current active color from SSM"
    exit 1
fi

# Determine rollback target
if [[ "$CURRENT_COLOR" == "blue" ]]; then
    ROLLBACK_TARGET="green"
else
    ROLLBACK_TARGET="blue"
fi

log_rollback "Current active color: $CURRENT_COLOR"
log_rollback "Rolling back to: $ROLLBACK_TARGET"

# Get last switch timestamp for logging
LAST_SWITCH=$(get_ssm_param "${SSM_BASE}/last-switch-timestamp")
if [[ -n "$LAST_SWITCH" ]]; then
    log_info "Last switch was at: $LAST_SWITCH"
fi

# Verify rollback target has instances
log_info "Verifying $ROLLBACK_TARGET ASG has healthy instances..."

if [[ "$ROLLBACK_TARGET" == "green" ]]; then
    ASG_NAME=$(get_ssm_param "${SSM_BASE}/green-asg-name")
else
    ASG_NAME=$(get_ssm_param "${SSM_BASE}/asg-name")
fi

if [[ -z "$ASG_NAME" ]]; then
    log_error "Failed to get $ROLLBACK_TARGET ASG name from SSM"
    exit 1
fi

# Check ASG instance count
INSTANCE_COUNT=$(aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "$ASG_NAME" \
    --query "AutoScalingGroups[0].Instances[?HealthStatus=='Healthy'] | length(@)" \
    --output text \
    --region "$AWS_REGION")

# Validate INSTANCE_COUNT is a valid number (AWS CLI could return error text)
if [[ ! "$INSTANCE_COUNT" =~ ^[0-9]+$ ]] || [[ "$INSTANCE_COUNT" == "0" ]]; then
    log_error "$ROLLBACK_TARGET ASG ($ASG_NAME) has no healthy instances!"
    log_error "Cannot rollback to an ASG with no capacity."
    log_error "You may need to scale up the $ROLLBACK_TARGET ASG first."
    [[ ! "$INSTANCE_COUNT" =~ ^[0-9]+$ ]] && log_error "Got unexpected value: $INSTANCE_COUNT"
    exit 1
fi

log_info "$ROLLBACK_TARGET ASG has $INSTANCE_COUNT healthy instance(s)"

# Confirm rollback (if interactive)
if [[ -t 0 && "$DRY_RUN" != "true" ]]; then
    echo ""
    log_warn "This will immediately switch all traffic from $CURRENT_COLOR to $ROLLBACK_TARGET."
    read -p "Continue with rollback? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Rollback cancelled."
        exit 0
    fi
fi

# Record rollback initiation time (integer seconds for bash arithmetic)
ROLLBACK_START=$(date +%s)

# Execute switch using the switch script
log_rollback "Executing traffic switch..."
if [[ "$DRY_RUN" == "true" ]]; then
    DRY_RUN=true "$SCRIPT_DIR/blue-green-switch.sh" "$ENVIRONMENT" "$ROLLBACK_TARGET"
else
    "$SCRIPT_DIR/blue-green-switch.sh" "$ENVIRONMENT" "$ROLLBACK_TARGET"
fi

# Calculate rollback duration (integer seconds)
ROLLBACK_END=$(date +%s)
ROLLBACK_DURATION=$((ROLLBACK_END - ROLLBACK_START))

# Update timestamp with ROLLBACK suffix for audit trail
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
if [[ "$DRY_RUN" != "true" ]]; then
    aws ssm put-parameter \
        --name "${SSM_BASE}/last-switch-timestamp" \
        --value "${TIMESTAMP}-ROLLBACK" \
        --type "String" \
        --overwrite \
        --region "$AWS_REGION" \
        --output text > /dev/null
fi

log_rollback "=========================================="
log_rollback "ROLLBACK COMPLETE"
log_rollback "Previous active: $CURRENT_COLOR"
log_rollback "New active: $ROLLBACK_TARGET"
log_rollback "Rollback duration: ${ROLLBACK_DURATION}s"
log_rollback "Timestamp: ${TIMESTAMP}-ROLLBACK"
log_rollback "=========================================="

# Provide next steps
echo ""
log_info "Next steps:"
log_info "1. Verify traffic is flowing correctly to $ROLLBACK_TARGET"
log_info "2. Investigate issues with the $CURRENT_COLOR deployment"
log_info "3. Once fixed, deploy again using the blue-green-deploy workflow"
