#!/bin/bash
# Blue/Green NLB Listener Switch Script
#
# Switches NLB listeners from one color's target groups to another.
# Reads target group ARNs from SSM parameters.
#
# Usage: blue-green-switch.sh <environment> <target-color> [component]
#
# Arguments:
#   environment   - Environment name (sandbox, prod)
#   target-color  - Color to switch to (blue or green)
#   component     - Component to switch (server, ac). Defaults to "server".
#
# Environment Variables (optional):
#   AWS_REGION    - AWS region (default: us-east-2)
#   DRY_RUN       - Set to "true" to show what would be done without executing
#
# Example:
#   ./blue-green-switch.sh sandbox green
#   ./blue-green-switch.sh sandbox green ac
#   DRY_RUN=true ./blue-green-switch.sh sandbox blue server

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
    echo "Usage: $0 <environment> <target-color> [component]"
    echo "  environment: sandbox, prod"
    echo "  target-color: blue, green"
    echo "  component: server (default), ac"
    exit 1
fi

ENVIRONMENT="$1"
TARGET_COLOR="$2"
COMPONENT="${3:-server}"
AWS_REGION="${AWS_REGION:-us-east-2}"
DRY_RUN="${DRY_RUN:-false}"

# Validate target color
if [[ "$TARGET_COLOR" != "blue" && "$TARGET_COLOR" != "green" ]]; then
    log_error "Invalid target color: $TARGET_COLOR. Must be 'blue' or 'green'."
    exit 1
fi

# Validate component
if [[ "$COMPONENT" != "server" && "$COMPONENT" != "ac" ]]; then
    log_error "Invalid component: $COMPONENT. Must be 'server' or 'ac'."
    exit 1
fi

log_info "Switching $COMPONENT traffic to $TARGET_COLOR in $ENVIRONMENT environment"
log_info "AWS Region: $AWS_REGION"
[[ "$DRY_RUN" == "true" ]] && log_warn "DRY RUN MODE - No changes will be made"

# SSM parameter base path
SSM_BASE="/${ENVIRONMENT}/nhp/${COMPONENT}"

# Function to get SSM parameter
get_ssm_param() {
    local param_name="$1"
    aws ssm get-parameter \
        --name "$param_name" \
        --query "Parameter.Value" \
        --output text \
        --region "$AWS_REGION" 2>/dev/null || echo ""
}

# Point a listener's default action at a target group. Used both for normal
# active-color switches and for rollback to the current color.
modify_listener() {
    aws elbv2 modify-listener \
        --listener-arn "$1" \
        --default-actions "Type=forward,TargetGroupArn=$2" \
        --region "$AWS_REGION" \
        --output text > /dev/null
}

# Resolve a color's target group ARN for a given listener type from SSM.
# Names follow ${SSM_BASE}/{color}-{type}-tg-arn, e.g. blue udp,
# green internal-udp, or blue https.
tg_arn() {
    get_ssm_param "${SSM_BASE}/${1}-${2}-tg-arn"
}

# Roll back every listener already switched in this transaction, in reverse
# order (internal relay before primary), so a failed multi-listener switch leaves
# all traffic on $CURRENT_COLOR. Safe under set -u: rollback vars are
# pre-initialized, and rollback TGs are validated before their listeners switch.
rollback_switched_listeners() {
    [[ "$DRY_RUN" == "true" ]] && return 0
    if [[ "$INTERNAL_RELAY_SWITCHED" == "true" ]]; then
        log_warn "Rolling back internal relay UDP listener to $CURRENT_COLOR..."
        modify_listener "$INTERNAL_RELAY_LISTENER_ARN" "$ROLLBACK_INTERNAL_RELAY_TG_ARN"
        log_warn "internal relay UDP listener rolled back"
    fi
    if [[ "$PRIMARY_SWITCHED" == "true" ]]; then
        log_warn "Rolling back ${PRIMARY_LISTENER_TYPE} listener to $CURRENT_COLOR..."
        modify_listener "$PRIMARY_LISTENER_ARN" "$ROLLBACK_PRIMARY_TG_ARN"
        log_warn "${PRIMARY_LISTENER_TYPE} listener rolled back. Traffic remains on $CURRENT_COLOR."
    fi
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

# Component-specific listener type mapping
# Each component uses different NLB listener protocols:
#   Server: primary=UDP (port 62206, knock packets), secondary=HTTPS (port 443, QURL plugin)
#   AC:     primary=TCP (port 443, TLS passthrough to Traefik), no secondary
# SSM parameter names follow the pattern: /${env}/nhp/${component}/{color}-{protocol}-tg-arn
if [[ "$COMPONENT" == "server" ]]; then
    PRIMARY_LISTENER_TYPE="udp"
    SECONDARY_LISTENER_TYPE="https"
else
    PRIMARY_LISTENER_TYPE="tcp"
    SECONDARY_LISTENER_TYPE=""
fi

# Get primary listener ARN.
#
# #2628: when nhp-server is private (take_server_private=true), Terraform removes the
# public UDP NLB and its "${SSM_BASE}/udp-listener-arn" parameter. The relay->server
# hop is still a real traffic switch point: it uses the INTERNAL NLB listener and
# per-color internal UDP TGs, so this script must flip that listener before writing
# active-color.
#
# A missing listener alone is NOT enough to skip: a botched public apply, SSM drift,
# or an accidental param deletion on a PUBLIC server would otherwise silently skip the
# traffic switch and report the deploy green. So fall back to the internal listener
# ONLY when the Terraform-written "${SSM_BASE}/take-server-private" marker positively
# confirms "true"; if the public listener is missing and the marker is anything else
# (absent / "false"), fail loudly — that is a broken public deploy, not a private
# server. A missing primary listener for the AC component is still a real fault
# regardless.
PRIMARY_LISTENER_ARN=$(get_ssm_param "${SSM_BASE}/${PRIMARY_LISTENER_TYPE}-listener-arn")
if [[ -z "$PRIMARY_LISTENER_ARN" ]]; then
    if [[ "$COMPONENT" == "server" ]]; then
        SERVER_PRIVATE=$(get_ssm_param "${SSM_BASE}/take-server-private")
        if [[ "$SERVER_PRIVATE" == "true" ]]; then
            log_warn "No public ${PRIMARY_LISTENER_TYPE} listener ARN in SSM and take-server-private=true — nhp-server is private (#2628). Switching the internal relay UDP listener instead."
            PRIMARY_LISTENER_TYPE="internal-udp"
            PRIMARY_LISTENER_ARN=$(get_ssm_param "${SSM_BASE}/${PRIMARY_LISTENER_TYPE}-listener-arn")
            if [[ -z "$PRIMARY_LISTENER_ARN" ]]; then
                log_error "take-server-private=true but ${SSM_BASE}/${PRIMARY_LISTENER_TYPE}-listener-arn is missing. The relay path has no active-color switch point; failing before active-color can drift."
                exit 1
            fi
        else
            log_error "No public ${PRIMARY_LISTENER_TYPE} listener ARN in SSM, but take-server-private is not 'true' (got '${SERVER_PRIVATE:-<absent>}'). A public server must have its listener — failing loudly (likely a partial apply or SSM drift) rather than silently skipping the traffic switch."
            exit 1
        fi
    else
        log_error "Failed to get ${PRIMARY_LISTENER_TYPE} listener ARN from SSM"
        exit 1
    fi
else
    log_info "Primary (${PRIMARY_LISTENER_TYPE}) Listener ARN: $PRIMARY_LISTENER_ARN"
fi

PRIMARY_SWITCHED=false
ROLLBACK_PRIMARY_TG_ARN=""
INTERNAL_RELAY_SWITCHED=false
INTERNAL_RELAY_LISTENER_ARN=""
ROLLBACK_INTERNAL_RELAY_TG_ARN=""

# Get target group ARNs based on target color
PRIMARY_TARGET_GROUP_ARN=$(tg_arn "$TARGET_COLOR" "$PRIMARY_LISTENER_TYPE")

if [[ -z "$PRIMARY_TARGET_GROUP_ARN" ]]; then
    if [[ "$PRIMARY_LISTENER_TYPE" == "internal-udp" ]]; then
        log_error "take-server-private=true but ${SSM_BASE}/${TARGET_COLOR}-internal-udp-tg-arn is missing. The relay path has no active-color switch point; failing before active-color can drift."
    else
        log_error "Failed to get $TARGET_COLOR ${PRIMARY_LISTENER_TYPE} target group ARN from SSM"
    fi
    exit 1
fi
log_info "Target ${PRIMARY_LISTENER_TYPE} TG ARN: $PRIMARY_TARGET_GROUP_ARN"

# Get rollback target group ARN (current color) in case we need to revert
ROLLBACK_PRIMARY_TG_ARN=$(tg_arn "$CURRENT_COLOR" "$PRIMARY_LISTENER_TYPE")
if [[ -z "$ROLLBACK_PRIMARY_TG_ARN" ]]; then
    if [[ "$PRIMARY_LISTENER_TYPE" == "internal-udp" ]]; then
        log_error "take-server-private=true but ${SSM_BASE}/${CURRENT_COLOR}-internal-udp-tg-arn is missing. The relay path cannot be rolled back safely; failing before active-color can drift."
    else
        log_error "Failed to get current-color $CURRENT_COLOR ${PRIMARY_LISTENER_TYPE} rollback target group ARN from SSM"
    fi
    exit 1
fi

# Switch primary listener
log_info "Switching ${PRIMARY_LISTENER_TYPE} listener to $TARGET_COLOR target group..."
if [[ "$DRY_RUN" != "true" ]]; then
    if ! modify_listener "$PRIMARY_LISTENER_ARN" "$PRIMARY_TARGET_GROUP_ARN"; then
        log_error "${PRIMARY_LISTENER_TYPE} listener switch failed before any later listener or active-color write; no rollback needed"
        exit 1
    fi
    log_info "${PRIMARY_LISTENER_TYPE} listener switched successfully"
else
    log_info "[DRY RUN] Would execute: aws elbv2 modify-listener --listener-arn $PRIMARY_LISTENER_ARN --default-actions Type=forward,TargetGroupArn=$PRIMARY_TARGET_GROUP_ARN"
fi

PRIMARY_SWITCHED=true

# If the internal relay UDP listener exists alongside a public UDP listener,
# switch it in the same active-color transaction. In private-server mode the
# fallback above made internal-udp the primary listener, so this block is skipped.
# In dual-listener migration mode there is a brief cross-listener skew window:
# public UDP flips first, then internal relay. active-color is written only after
# both switches succeed, and any internal relay failure rolls public UDP back.
if [[ "$COMPONENT" == "server" && "$PRIMARY_LISTENER_TYPE" != "internal-udp" ]]; then
    INTERNAL_RELAY_LISTENER_ARN=$(get_ssm_param "${SSM_BASE}/internal-udp-listener-arn")
    if [[ -n "$INTERNAL_RELAY_LISTENER_ARN" ]]; then
        INTERNAL_RELAY_TARGET_TG_ARN=$(tg_arn "$TARGET_COLOR" "internal-udp")
        ROLLBACK_INTERNAL_RELAY_TG_ARN=$(tg_arn "$CURRENT_COLOR" "internal-udp")

        if [[ -z "$INTERNAL_RELAY_TARGET_TG_ARN" || -z "$ROLLBACK_INTERNAL_RELAY_TG_ARN" ]]; then
            log_error "Internal relay listener exists but one or more internal UDP target group ARNs are missing from SSM"
            rollback_switched_listeners
            exit 1
        fi

        log_info "Switching internal relay UDP listener to $TARGET_COLOR target group..."
        if [[ "$DRY_RUN" != "true" ]]; then
            if ! modify_listener "$INTERNAL_RELAY_LISTENER_ARN" "$INTERNAL_RELAY_TARGET_TG_ARN"; then
                log_error "internal relay UDP listener switch failed!"
                rollback_switched_listeners
                exit 1
            fi
            log_info "internal relay UDP listener switched successfully"
        else
            log_info "[DRY RUN] Would execute: aws elbv2 modify-listener --listener-arn $INTERNAL_RELAY_LISTENER_ARN --default-actions Type=forward,TargetGroupArn=$INTERNAL_RELAY_TARGET_TG_ARN"
        fi
        INTERNAL_RELAY_SWITCHED=true
    fi
fi

# Check if secondary listener exists (server only - HTTPS for QURL)
if [[ -n "$SECONDARY_LISTENER_TYPE" ]]; then
    SECONDARY_LISTENER_ARN=$(get_ssm_param "${SSM_BASE}/${SECONDARY_LISTENER_TYPE}-listener-arn")
    if [[ -n "$SECONDARY_LISTENER_ARN" ]]; then
        log_info "Secondary (${SECONDARY_LISTENER_TYPE}) Listener ARN: $SECONDARY_LISTENER_ARN"

        SECONDARY_TARGET_GROUP_ARN=$(tg_arn "$TARGET_COLOR" "$SECONDARY_LISTENER_TYPE")

        # Validate consistency: if secondary listener exists, TG ARN must also exist
        if [[ -z "$SECONDARY_TARGET_GROUP_ARN" ]]; then
            log_error "${SECONDARY_LISTENER_TYPE} listener exists but $TARGET_COLOR ${SECONDARY_LISTENER_TYPE} target group ARN is missing from SSM"
            log_error "This indicates a configuration inconsistency. Check SSM parameters."
            # Rollback primary listener since we can't complete the switch atomically
            rollback_switched_listeners
            exit 1
        fi
        log_info "Target ${SECONDARY_LISTENER_TYPE} TG ARN: $SECONDARY_TARGET_GROUP_ARN"

        log_info "Switching ${SECONDARY_LISTENER_TYPE} listener to $TARGET_COLOR target group..."
        if [[ "$DRY_RUN" != "true" ]]; then
            if ! modify_listener "$SECONDARY_LISTENER_ARN" "$SECONDARY_TARGET_GROUP_ARN"; then
                log_error "${SECONDARY_LISTENER_TYPE} listener switch failed!"
                # Roll the primary listener back to maintain consistency, but only if it
                # was actually switched. This guard matches the TG-missing rollback above
                # and avoids a `set -u` error if a future optional-listener path reaches
                # this branch before primary switching.
                rollback_switched_listeners
                exit 1
            fi
            log_info "${SECONDARY_LISTENER_TYPE} listener switched successfully"
        else
            log_info "[DRY RUN] Would execute: aws elbv2 modify-listener --listener-arn $SECONDARY_LISTENER_ARN --default-actions Type=forward,TargetGroupArn=$SECONDARY_TARGET_GROUP_ARN"
        fi
    else
        log_info "No ${SECONDARY_LISTENER_TYPE} listener configured"
    fi
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
log_info "Component: $COMPONENT"
log_info "Previous active: $CURRENT_COLOR"
log_info "New active: $TARGET_COLOR"
log_info "Timestamp: $TIMESTAMP"
log_info "=========================================="
