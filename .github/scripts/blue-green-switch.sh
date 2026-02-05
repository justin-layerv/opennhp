#!/bin/bash
# Blue/Green NLB Listener Switch Script
#
# Switches NLB listeners from one color's target groups to another.
# Reads target group ARNs from SSM parameters.
#
# Usage: blue-green-switch.sh <environment> <target-color>
#
# Arguments:
#   environment   - Environment name (sandbox, prod)
#   target-color  - Color to switch to (blue or green)
#
# Environment Variables (optional):
#   AWS_REGION    - AWS region (default: us-east-2)
#   DRY_RUN       - Set to "true" to show what would be done without executing
#
# Example:
#   ./blue-green-switch.sh sandbox green
#   DRY_RUN=true ./blue-green-switch.sh sandbox blue

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Validate arguments
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <environment> <target-color>"
    echo "  environment: sandbox, prod"
    echo "  target-color: blue, green"
    exit 1
fi

ENVIRONMENT="$1"
TARGET_COLOR="$2"
AWS_REGION="${AWS_REGION:-us-east-2}"
DRY_RUN="${DRY_RUN:-false}"

# Validate target color
if [[ "$TARGET_COLOR" != "blue" && "$TARGET_COLOR" != "green" ]]; then
    log_error "Invalid target color: $TARGET_COLOR. Must be 'blue' or 'green'."
    exit 1
fi

log_info "Switching traffic to $TARGET_COLOR in $ENVIRONMENT environment"
log_info "AWS Region: $AWS_REGION"
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
log_info "Current active color: $CURRENT_COLOR"

if [[ "$CURRENT_COLOR" == "$TARGET_COLOR" ]]; then
    log_warn "Traffic is already routed to $TARGET_COLOR. Nothing to do."
    exit 0
fi

# Get listener ARNs
UDP_LISTENER_ARN=$(get_ssm_param "${SSM_BASE}/udp-listener-arn")
if [[ -z "$UDP_LISTENER_ARN" ]]; then
    log_error "Failed to get UDP listener ARN from SSM"
    exit 1
fi
log_info "UDP Listener ARN: $UDP_LISTENER_ARN"

# Get target group ARNs based on target color
if [[ "$TARGET_COLOR" == "blue" ]]; then
    UDP_TARGET_GROUP_ARN=$(get_ssm_param "${SSM_BASE}/blue-udp-tg-arn")
else
    UDP_TARGET_GROUP_ARN=$(get_ssm_param "${SSM_BASE}/green-udp-tg-arn")
fi

if [[ -z "$UDP_TARGET_GROUP_ARN" ]]; then
    log_error "Failed to get $TARGET_COLOR UDP target group ARN from SSM"
    exit 1
fi
log_info "Target UDP TG ARN: $UDP_TARGET_GROUP_ARN"

# Get rollback target group ARN (current color) in case we need to revert
if [[ "$CURRENT_COLOR" == "blue" ]]; then
    ROLLBACK_UDP_TG_ARN=$(get_ssm_param "${SSM_BASE}/blue-udp-tg-arn")
else
    ROLLBACK_UDP_TG_ARN=$(get_ssm_param "${SSM_BASE}/green-udp-tg-arn")
fi

# Switch UDP listener
log_info "Switching UDP listener to $TARGET_COLOR target group..."
if [[ "$DRY_RUN" != "true" ]]; then
    aws elbv2 modify-listener \
        --listener-arn "$UDP_LISTENER_ARN" \
        --default-actions "Type=forward,TargetGroupArn=$UDP_TARGET_GROUP_ARN" \
        --region "$AWS_REGION" \
        --output text > /dev/null
    log_info "UDP listener switched successfully"
else
    log_info "[DRY RUN] Would execute: aws elbv2 modify-listener --listener-arn $UDP_LISTENER_ARN --default-actions Type=forward,TargetGroupArn=$UDP_TARGET_GROUP_ARN"
fi

UDP_SWITCHED=true

# Check if HTTPS listener exists (QURL enabled)
HTTPS_LISTENER_ARN=$(get_ssm_param "${SSM_BASE}/https-listener-arn")
if [[ -n "$HTTPS_LISTENER_ARN" ]]; then
    log_info "HTTPS Listener ARN: $HTTPS_LISTENER_ARN"

    if [[ "$TARGET_COLOR" == "blue" ]]; then
        HTTPS_TARGET_GROUP_ARN=$(get_ssm_param "${SSM_BASE}/blue-https-tg-arn")
    else
        HTTPS_TARGET_GROUP_ARN=$(get_ssm_param "${SSM_BASE}/green-https-tg-arn")
    fi

    # Validate consistency: if HTTPS listener exists, TG ARN must also exist
    if [[ -z "$HTTPS_TARGET_GROUP_ARN" ]]; then
        log_error "HTTPS listener exists but $TARGET_COLOR HTTPS target group ARN is missing from SSM"
        log_error "This indicates a configuration inconsistency. Check SSM parameters."
        # Rollback UDP listener since we can't complete the switch atomically
        if [[ "$UDP_SWITCHED" == "true" && "$DRY_RUN" != "true" ]]; then
            log_warn "Rolling back UDP listener to $CURRENT_COLOR..."
            aws elbv2 modify-listener \
                --listener-arn "$UDP_LISTENER_ARN" \
                --default-actions "Type=forward,TargetGroupArn=$ROLLBACK_UDP_TG_ARN" \
                --region "$AWS_REGION" \
                --output text > /dev/null
            log_warn "UDP listener rolled back"
        fi
        exit 1
    fi
    log_info "Target HTTPS TG ARN: $HTTPS_TARGET_GROUP_ARN"

    log_info "Switching HTTPS listener to $TARGET_COLOR target group..."
    if [[ "$DRY_RUN" != "true" ]]; then
        if ! aws elbv2 modify-listener \
            --listener-arn "$HTTPS_LISTENER_ARN" \
            --default-actions "Type=forward,TargetGroupArn=$HTTPS_TARGET_GROUP_ARN" \
            --region "$AWS_REGION" \
            --output text > /dev/null; then
            log_error "HTTPS listener switch failed!"
            # Rollback UDP listener to maintain consistency
            log_warn "Rolling back UDP listener to $CURRENT_COLOR..."
            aws elbv2 modify-listener \
                --listener-arn "$UDP_LISTENER_ARN" \
                --default-actions "Type=forward,TargetGroupArn=$ROLLBACK_UDP_TG_ARN" \
                --region "$AWS_REGION" \
                --output text > /dev/null
            log_warn "UDP listener rolled back. Traffic remains on $CURRENT_COLOR."
            exit 1
        fi
        log_info "HTTPS listener switched successfully"
    else
        log_info "[DRY RUN] Would execute: aws elbv2 modify-listener --listener-arn $HTTPS_LISTENER_ARN --default-actions Type=forward,TargetGroupArn=$HTTPS_TARGET_GROUP_ARN"
    fi
else
    log_info "No HTTPS listener configured (QURL not enabled)"
fi

# Update active color in SSM
# NOTE: SSM is updated AFTER listener switch intentionally. If the script fails between
# listener switch and SSM update, state becomes temporarily inconsistent. This is handled by:
# 1. The validate job's reconciliation check detects listener/SSM mismatch
# 2. Re-running the workflow will correct the state
# We don't use a "switching" transitional state to keep the logic simple and avoid
# additional failure modes (e.g., stuck in "switching" state).
log_info "Updating active color in SSM to $TARGET_COLOR..."
if [[ "$DRY_RUN" != "true" ]]; then
    aws ssm put-parameter \
        --name "${SSM_BASE}/active-color" \
        --value "$TARGET_COLOR" \
        --type "String" \
        --overwrite \
        --region "$AWS_REGION" \
        --output text > /dev/null
    log_info "SSM active-color updated"
else
    log_info "[DRY RUN] Would execute: aws ssm put-parameter --name ${SSM_BASE}/active-color --value $TARGET_COLOR"
fi

# Update switch timestamp
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
log_info "Recording switch timestamp: $TIMESTAMP"
if [[ "$DRY_RUN" != "true" ]]; then
    aws ssm put-parameter \
        --name "${SSM_BASE}/last-switch-timestamp" \
        --value "$TIMESTAMP" \
        --type "String" \
        --overwrite \
        --region "$AWS_REGION" \
        --output text > /dev/null
fi

log_info "=========================================="
log_info "Traffic switch complete!"
log_info "Previous active: $CURRENT_COLOR"
log_info "New active: $TARGET_COLOR"
log_info "Timestamp: $TIMESTAMP"
log_info "=========================================="
