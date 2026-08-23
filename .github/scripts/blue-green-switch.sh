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
#   RECONCILE_CURRENT - Set to "true" to re-apply the current active color to
#                       every listener instead of treating it as a no-op
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
RECONCILE_CURRENT="${RECONCILE_CURRENT:-false}"

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

if [[ "$RECONCILE_CURRENT" != "true" && "$RECONCILE_CURRENT" != "false" ]]; then
    log_error "RECONCILE_CURRENT must be 'true' or 'false'."
    exit 1
fi

log_info "Switching $COMPONENT traffic to $TARGET_COLOR in $ENVIRONMENT environment"
log_info "AWS Region: $AWS_REGION"
[[ "$DRY_RUN" == "true" ]] && log_warn "DRY RUN MODE - No changes will be made"

# SSM parameter base path
SSM_BASE="/${ENVIRONMENT}/nhp/${COMPONENT}"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROFILE_ORDER_SCRIPT="$SCRIPT_DIR/nhp-profile-order.sh"

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
# order, so a failed multi-listener switch leaves all traffic on $CURRENT_COLOR.
# Rollback is best effort across every listener: one failed repair must not stop
# the remaining repairs from being attempted.
rollback_switched_listeners() {
    [[ "$DRY_RUN" == "true" ]] && return 0
    local rollback_failed=false
    if [[ "$SECONDARY_SWITCHED" == "true" ]]; then
        log_warn "Rolling back ${SECONDARY_LISTENER_TYPE} listener to $CURRENT_COLOR..."
        if ! modify_listener "$SECONDARY_LISTENER_ARN" "$ROLLBACK_SECONDARY_TG_ARN"; then
            log_error "Failed to roll back ${SECONDARY_LISTENER_TYPE} listener"
            rollback_failed=true
        else
            log_warn "${SECONDARY_LISTENER_TYPE} listener rolled back"
        fi
    fi
    if [[ "$INTERNAL_RELAY_SWITCHED" == "true" ]]; then
        log_warn "Rolling back internal relay UDP listener to $CURRENT_COLOR..."
        if ! modify_listener "$INTERNAL_RELAY_LISTENER_ARN" "$ROLLBACK_INTERNAL_RELAY_TG_ARN"; then
            log_error "Failed to roll back internal relay UDP listener"
            rollback_failed=true
        else
            log_warn "internal relay UDP listener rolled back"
        fi
    fi
    if [[ "$PRIMARY_SWITCHED" == "true" ]]; then
        log_warn "Rolling back ${PRIMARY_LISTENER_TYPE} listener to $CURRENT_COLOR..."
        if ! modify_listener "$PRIMARY_LISTENER_ARN" "$ROLLBACK_PRIMARY_TG_ARN"; then
            log_error "Failed to roll back ${PRIMARY_LISTENER_TYPE} listener"
            rollback_failed=true
        else
            log_warn "${PRIMARY_LISTENER_TYPE} listener rolled back"
        fi
    fi
    [[ "$rollback_failed" == "false" ]]
}

# Get current active color
CURRENT_COLOR=$(get_ssm_param "${SSM_BASE}/active-color")
if [[ -z "$CURRENT_COLOR" ]]; then
    log_error "Failed to get current active color from SSM"
    exit 1
fi
log_info "Current active color: $CURRENT_COLOR"

# A slot becomes permanently ineligible once the shared sandbox profile floor
# advances beyond it. Slot records bind the operator-declared profile to the
# exact image tag; legacy slots created before this mechanism have no record and
# are treated as legacy-aop-v1. This guard lives in the mutation helper as well
# as the workflow so rollback/switch-only callers cannot bypass it.
MINIMUM_PROFILE=$(AWS_REGION="$AWS_REGION" bash "$SCRIPT_DIR/../../scripts/ssm-read-optional.sh" \
    "/sandbox/nhp/minimum-protocol-profile")
MINIMUM_PROFILE=${MINIMUM_PROFILE:-legacy-aop-v1}
TARGET_RECORD=$(AWS_REGION="$AWS_REGION" bash "$SCRIPT_DIR/../../scripts/ssm-read-optional.sh" \
    "${SSM_BASE}/${TARGET_COLOR}-protocol-profile")
TARGET_PROFILE=legacy-aop-v1
if [[ -n "$TARGET_RECORD" ]]; then
    if [[ "$TARGET_COLOR" == "green" ]]; then
        TARGET_IMAGE_PARAM="${SSM_BASE}/green-image-tag"
    else
        TARGET_IMAGE_PARAM="${SSM_BASE}/image-tag"
    fi
    TARGET_IMAGE=$(get_ssm_param "$TARGET_IMAGE_PARAM")
    if [[ -z "$TARGET_IMAGE" ]]; then
        log_error "Target slot has a profile record but no image tag: $TARGET_IMAGE_PARAM"
        exit 1
    fi
    TARGET_PROFILE=${TARGET_RECORD#v1|}
    TARGET_PROFILE=${TARGET_PROFILE%%|*}
    if ! "$PROFILE_ORDER_SCRIPT" assert-record "$TARGET_RECORD" "$TARGET_PROFILE" "$TARGET_IMAGE"; then
        log_error "Target slot profile record does not bind its current image"
        exit 1
    fi
fi
if ! "$PROFILE_ORDER_SCRIPT" assert-at-least "$TARGET_PROFILE" "$MINIMUM_PROFILE"; then
    log_error "Refusing to activate $COMPONENT/$TARGET_COLOR profile=$TARGET_PROFILE below minimum=$MINIMUM_PROFILE"
    exit 1
fi

# Before the global floor advances, a newer-profile slot is prewarm-only. Only
# the dedicated durable cutover ledger can authorize its activation, and each
# component has an exact predecessor phase. This closes the direct-helper and
# switch-only seams without a caller-controlled bypass flag.
TARGET_PROFILE_ORDER=$("$PROFILE_ORDER_SCRIPT" order "$TARGET_PROFILE")
MINIMUM_PROFILE_ORDER=$("$PROFILE_ORDER_SCRIPT" order "$MINIMUM_PROFILE")
if ((TARGET_PROFILE_ORDER > MINIMUM_PROFILE_ORDER)); then
    CUTOVER_STATE=$(AWS_REGION="$AWS_REGION" bash "$SCRIPT_DIR/../../scripts/ssm-read-optional.sh" \
        "/sandbox/nhp/cutovers/durable-aop-v1/state")
    if [[ -z "$CUTOVER_STATE" ]]; then
        log_error "Refusing to activate a newer protocol profile without the dedicated cutover ledger"
        exit 1
    fi
    case "$ENVIRONMENT/$COMPONENT" in
        sandbox/ac) REQUIRED_PHASE_ORDER=20 ;;
        sandbox/server) REQUIRED_PHASE_ORDER=30 ;;
        sandbox-cell1/server) REQUIRED_PHASE_ORDER=40 ;;
        *) log_error "No durable cutover phase is defined for $ENVIRONMENT/$COMPONENT"; exit 1 ;;
    esac
    CUTOVER_PHASE_ORDER=$(jq -er --arg image "$TARGET_IMAGE" '
        select(type == "object" and .schema == 2 and .image == $image and
          .orchestrator_sha == $image and (.lock_owner | type == "string" and length > 0)) |
        .phase |
        if . == "ponr" then 20
        elif . == "ac_switched" then 30
        elif . == "cell0_switched" then 40
        elif . == "cell1_switched" then 50
        elif . == "old_servers_terminated" then 60
        elif . == "validated" then 70
        elif . == "complete" then 80
        else empty
        end
    ' <<<"$CUTOVER_STATE") || {
        log_error "Dedicated cutover ledger is malformed, has the wrong image, or is pre-PONR"
        exit 1
    }
    if ((CUTOVER_PHASE_ORDER < REQUIRED_PHASE_ORDER)); then
        log_error "Dedicated cutover ledger has not reached the required phase for $ENVIRONMENT/$COMPONENT"
        exit 1
    fi
fi
log_info "Protocol profile gate passed: target=$TARGET_PROFILE minimum=$MINIMUM_PROFILE"

if [[ "$CURRENT_COLOR" == "$TARGET_COLOR" ]]; then
    if [[ "$RECONCILE_CURRENT" != "true" ]]; then
        log_warn "Traffic is already routed to $TARGET_COLOR. Nothing to do."
        exit 0
    fi
    log_warn "Reconciling every listener to the existing active color $TARGET_COLOR."
fi

# Component-specific listener type mapping
# Each component uses different NLB listener protocols:
#   Server: primary=UDP (port 443, knock packets), secondary=HTTPS (port 8443, QURL plugin)
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
# The assigned-cell public UDP 443 listener is required for UDP SDKs. The
# private internal listener is a second switch point for browser-relay traffic,
# not a fallback for an absent public edge.
PRIMARY_LISTENER_ARN=$(get_ssm_param "${SSM_BASE}/${PRIMARY_LISTENER_TYPE}-listener-arn")
if [[ -z "$PRIMARY_LISTENER_ARN" ]]; then
    log_error "Failed to get required ${PRIMARY_LISTENER_TYPE} listener ARN from SSM"
    exit 1
else
    log_info "Primary (${PRIMARY_LISTENER_TYPE}) Listener ARN: $PRIMARY_LISTENER_ARN"
fi

PRIMARY_SWITCHED=false
ROLLBACK_PRIMARY_TG_ARN=""
INTERNAL_RELAY_SWITCHED=false
INTERNAL_RELAY_LISTENER_ARN=""
INTERNAL_RELAY_TARGET_TG_ARN=""
ROLLBACK_INTERNAL_RELAY_TG_ARN=""
SECONDARY_SWITCHED=false
SECONDARY_LISTENER_ARN=""
SECONDARY_TARGET_GROUP_ARN=""
ROLLBACK_SECONDARY_TG_ARN=""

# Preflight the internal listener contract before moving the public edge. A
# deployed relay ASG makes this listener mandatory; when the relay is dark the
# listener may be absent. If present in either case, both color TGs must exist.
if [[ "$COMPONENT" == "server" ]]; then
    RELAY_ASG_NAME=$(get_ssm_param "/${ENVIRONMENT}/nhp/relay/asg-name")
    INTERNAL_RELAY_LISTENER_ARN=$(get_ssm_param "${SSM_BASE}/internal-udp-listener-arn")
    if [[ -n "$RELAY_ASG_NAME" && -z "$INTERNAL_RELAY_LISTENER_ARN" ]]; then
        log_error "Relay ASG $RELAY_ASG_NAME is deployed but the required internal UDP listener ARN is missing from SSM"
        exit 1
    fi
    if [[ -n "$INTERNAL_RELAY_LISTENER_ARN" ]]; then
        INTERNAL_RELAY_TARGET_TG_ARN=$(tg_arn "$TARGET_COLOR" "internal-udp")
        ROLLBACK_INTERNAL_RELAY_TG_ARN=$(tg_arn "$CURRENT_COLOR" "internal-udp")
        if [[ -z "$INTERNAL_RELAY_TARGET_TG_ARN" || -z "$ROLLBACK_INTERNAL_RELAY_TG_ARN" ]]; then
            log_error "Internal relay listener exists but one or more internal UDP target group ARNs are missing from SSM"
            exit 1
        fi
    fi
fi

# Preflight the optional secondary listener before the first mutation. If the
# listener exists, both target and rollback target groups are mandatory so any
# later failure can restore the complete current-color topology.
if [[ -n "$SECONDARY_LISTENER_TYPE" ]]; then
    SECONDARY_LISTENER_ARN=$(get_ssm_param "${SSM_BASE}/${SECONDARY_LISTENER_TYPE}-listener-arn")
    if [[ -n "$SECONDARY_LISTENER_ARN" ]]; then
        log_info "Secondary (${SECONDARY_LISTENER_TYPE}) Listener ARN: $SECONDARY_LISTENER_ARN"
        SECONDARY_TARGET_GROUP_ARN=$(tg_arn "$TARGET_COLOR" "$SECONDARY_LISTENER_TYPE")
        ROLLBACK_SECONDARY_TG_ARN=$(tg_arn "$CURRENT_COLOR" "$SECONDARY_LISTENER_TYPE")
        if [[ -z "$SECONDARY_TARGET_GROUP_ARN" || -z "$ROLLBACK_SECONDARY_TG_ARN" ]]; then
            log_error "${SECONDARY_LISTENER_TYPE} listener exists but one or more ${SECONDARY_LISTENER_TYPE} target group ARNs are missing from SSM"
            exit 1
        fi
        log_info "Target ${SECONDARY_LISTENER_TYPE} TG ARN: $SECONDARY_TARGET_GROUP_ARN"
    else
        log_info "No ${SECONDARY_LISTENER_TYPE} listener configured"
    fi
fi

# Get target group ARNs based on target color
PRIMARY_TARGET_GROUP_ARN=$(tg_arn "$TARGET_COLOR" "$PRIMARY_LISTENER_TYPE")

if [[ -z "$PRIMARY_TARGET_GROUP_ARN" ]]; then
    log_error "Failed to get $TARGET_COLOR ${PRIMARY_LISTENER_TYPE} target group ARN from SSM"
    exit 1
fi
log_info "Target ${PRIMARY_LISTENER_TYPE} TG ARN: $PRIMARY_TARGET_GROUP_ARN"

# Get rollback target group ARN (current color) in case we need to revert
ROLLBACK_PRIMARY_TG_ARN=$(tg_arn "$CURRENT_COLOR" "$PRIMARY_LISTENER_TYPE")
if [[ -z "$ROLLBACK_PRIMARY_TG_ARN" ]]; then
    log_error "Failed to get current-color $CURRENT_COLOR ${PRIMARY_LISTENER_TYPE} rollback target group ARN from SSM"
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

# If the internal relay UDP listener exists alongside the required public UDP
# listener, switch it in the same active-color transaction. There is a brief
# cross-listener skew window:
# public UDP flips first, then internal relay. active-color is written only after
# both switches succeed, and any internal relay failure rolls public UDP back.
if [[ "$COMPONENT" == "server" ]]; then
    if [[ -n "$INTERNAL_RELAY_LISTENER_ARN" ]]; then
        log_info "Switching internal relay UDP listener to $TARGET_COLOR target group..."
        if [[ "$DRY_RUN" != "true" ]]; then
            if ! modify_listener "$INTERNAL_RELAY_LISTENER_ARN" "$INTERNAL_RELAY_TARGET_TG_ARN"; then
                log_error "internal relay UDP listener switch failed!"
                rollback_switched_listeners || log_error "One or more listener rollbacks failed"
                exit 1
            fi
            log_info "internal relay UDP listener switched successfully"
        else
            log_info "[DRY RUN] Would execute: aws elbv2 modify-listener --listener-arn $INTERNAL_RELAY_LISTENER_ARN --default-actions Type=forward,TargetGroupArn=$INTERNAL_RELAY_TARGET_TG_ARN"
        fi
        INTERNAL_RELAY_SWITCHED=true
    fi
fi

# Switch the preflighted secondary listener (server HTTPS for QURL), if present.
if [[ -n "$SECONDARY_LISTENER_ARN" ]]; then
        log_info "Switching ${SECONDARY_LISTENER_TYPE} listener to $TARGET_COLOR target group..."
        if [[ "$DRY_RUN" != "true" ]]; then
            if ! modify_listener "$SECONDARY_LISTENER_ARN" "$SECONDARY_TARGET_GROUP_ARN"; then
                log_error "${SECONDARY_LISTENER_TYPE} listener switch failed!"
                rollback_switched_listeners || log_error "One or more listener rollbacks failed"
                exit 1
            fi
            log_info "${SECONDARY_LISTENER_TYPE} listener switched successfully"
        else
            log_info "[DRY RUN] Would execute: aws elbv2 modify-listener --listener-arn $SECONDARY_LISTENER_ARN --default-actions Type=forward,TargetGroupArn=$SECONDARY_TARGET_GROUP_ARN"
        fi
        SECONDARY_SWITCHED=true
fi

# Update active color in SSM
# SSM is the authoritative active-color marker and is written only after every
# listener succeeds. A failed write rolls every listener back; leaving listeners
# on the target color with a stale marker would make the next deployment unsafe.
log_info "Updating active color in SSM to $TARGET_COLOR..."
if [[ "$DRY_RUN" != "true" ]]; then
    if ! aws ssm put-parameter \
        --name "${SSM_BASE}/active-color" \
        --value "$TARGET_COLOR" \
        --type "String" \
        --overwrite \
        --region "$AWS_REGION" \
        --output text > /dev/null; then
        log_error "Failed to update authoritative active-color marker; rolling listeners back"
        rollback_switched_listeners || log_error "One or more listener rollbacks failed"
        exit 1
    fi
    log_info "SSM active-color updated"
else
    log_info "[DRY RUN] Would execute: aws ssm put-parameter --name ${SSM_BASE}/active-color --value $TARGET_COLOR"
fi

# Update switch timestamp
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
log_info "Recording switch timestamp: $TIMESTAMP"
if [[ "$DRY_RUN" != "true" ]]; then
    if ! aws ssm put-parameter \
        --name "${SSM_BASE}/last-switch-timestamp" \
        --value "$TIMESTAMP" \
        --type "String" \
        --overwrite \
        --region "$AWS_REGION" \
        --output text > /dev/null; then
        log_warn "Failed to record non-authoritative switch timestamp"
    fi
fi

log_info "=========================================="
log_info "Traffic switch complete!"
log_info "Component: $COMPONENT"
log_info "Previous active: $CURRENT_COLOR"
log_info "New active: $TARGET_COLOR"
log_info "Timestamp: $TIMESTAMP"
log_info "=========================================="
