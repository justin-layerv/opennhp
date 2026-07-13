#!/bin/bash
# NHP Deployment Validation Script
# Run this after terraform apply to verify the deployment is healthy
#
# Usage: ./scripts/validate-deployment.sh [sandbox|prod]
#
# Prerequisites:
# - AWS CLI configured with appropriate profile
# - etcdctl installed (for etcd checks)
# - nc (netcat) installed (for connectivity checks)

set -euo pipefail

ENV="${1:-sandbox}"

# Detect if running in CI (AWS credentials via env vars) or locally (AWS profile)
if [[ -n "${AWS_ACCESS_KEY_ID:-}" ]]; then
    # CI environment - credentials are in env vars, no profile needed
    run_aws() { aws "$@"; }
    AWS_PROFILE_PREFIX=""
else
    # Local environment - use profile
    AWS_PROFILE="${AWS_PROFILE:-layerv}"
    run_aws() { AWS_PROFILE=$AWS_PROFILE aws "$@"; }
    AWS_PROFILE_PREFIX="AWS_PROFILE=$AWS_PROFILE "
fi

echo "==========================================="
echo "NHP Deployment Validation - ${ENV}"
echo "==========================================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAILED=1
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

info() {
    echo -e "       $1"
}

FAILED=0

# 1. Check AWS connectivity
echo "1. AWS Connectivity"
echo "-------------------"
if run_aws sts get-caller-identity &>/dev/null; then
    ACCOUNT=$(run_aws sts get-caller-identity --query Account --output text)
    pass "AWS credentials valid (account: $ACCOUNT)"
else
    fail "AWS credentials invalid or expired"
fi
echo ""

# 2. Check NHP Server
echo "2. NHP Server"
echo "-------------"
NHP_NLB=$(run_aws elbv2 describe-load-balancers \
    --query "LoadBalancers[?contains(LoadBalancerName, 'nhp-${ENV}-nlb')].DNSName | [0]" \
    --output text 2>/dev/null || true)

if [ -n "$NHP_NLB" ] && [ "$NHP_NLB" != "None" ]; then
    pass "NHP NLB found: $NHP_NLB"

    # Check DNS resolution
    if host "$NHP_NLB" &>/dev/null; then
        pass "NLB DNS resolves"
    else
        fail "NLB DNS resolution failed"
    fi

    # Check UDP port reachability (basic test)
    if timeout 2 bash -c "echo -n '' | nc -u -w1 $NHP_NLB 62206" &>/dev/null; then
        pass "UDP port 62206 reachable"
    else
        warn "UDP port 62206 test inconclusive (may be normal for NHP)"
    fi
else
    # UDP SDKs require the public NHP server NLB for their assigned cell. The
    # private relay NLB is not a substitute and must not turn this into a skip.
    fail "Public assigned-cell NHP NLB not found"
fi
echo ""

# 3. Check AC Instances
echo "3. AC Instances"
echo "---------------"
AC_INSTANCES=$(run_aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=*nhp-${ENV}*ac*,*nhp*ac*${ENV}*" "Name=instance-state-name,Values=running" \
    --query 'Reservations[*].Instances[*].[InstanceId,PrivateIpAddress,State.Name]' \
    --output text 2>/dev/null || true)

if [ -n "$AC_INSTANCES" ] && [ "$AC_INSTANCES" != "None" ]; then
    AC_COUNT=$(echo "$AC_INSTANCES" | wc -l | tr -d ' ')
    pass "Found $AC_COUNT running AC instance(s)"
    echo "$AC_INSTANCES" | while read -r id ip state; do
        info "  $id: $ip ($state)"
    done
else
    warn "No AC instances found (may be expected if using different naming)"
fi
echo ""

# 4. Check etcd (if endpoints are configured)
echo "4. etcd Configuration"
echo "---------------------"
ETCD_ENDPOINT="${ETCD_ENDPOINT:-}"
if [ -n "$ETCD_ENDPOINT" ]; then
    if command -v etcdctl &>/dev/null; then
        # Check etcd health
        if ETCDCTL_API=3 etcdctl --endpoints="$ETCD_ENDPOINT" endpoint health &>/dev/null; then
            pass "etcd cluster healthy"

            # Check for NHP config
            if ETCDCTL_API=3 etcdctl --endpoints="$ETCD_ENDPOINT" get /nhp/config --print-value-only &>/dev/null; then
                pass "/nhp/config exists"
            else
                fail "/nhp/config not found - config seeder Lambda may not have run"
            fi

            # Count AC registrations
            AC_REG_COUNT=$(ETCDCTL_API=3 etcdctl --endpoints="$ETCD_ENDPOINT" get /nhp/ac-registry/ --prefix --keys-only 2>/dev/null | grep -c "/" || echo 0)
            info "$AC_REG_COUNT AC(s) registered in etcd"
        else
            fail "etcd connection failed"
        fi
    else
        warn "etcdctl not installed, skipping etcd checks"
        info "Install with: brew install etcd"
    fi
else
    warn "ETCD_ENDPOINT not set, skipping etcd checks"
    info "Set with: export ETCD_ENDPOINT=https://etcd.example.com:2379"
fi
echo ""

# 5. Check Secrets Manager
echo "5. Secrets Manager"
echo "------------------"
# Use describe-secret on known names (more specific IAM permissions)
SERVER_SECRET="layerv-nhp-${ENV}-server"
if run_aws secretsmanager describe-secret --secret-id "$SERVER_SECRET" &>/dev/null; then
    pass "NHP server key found: $SERVER_SECRET"
else
    warn "NHP server key not found: $SERVER_SECRET"
fi

# Check for per-instance AC keys (parallel for performance at scale)
if [ -n "$AC_INSTANCES" ] && [ "$AC_INSTANCES" != "None" ]; then
    AC_KEY_TMPDIR=$(mktemp -d)
    cleanup_ac_tmpdir() { [[ -d "${AC_KEY_TMPDIR:-}" ]] && rm -rf "$AC_KEY_TMPDIR"; }
    trap cleanup_ac_tmpdir EXIT
    while read -r id _ _; do
        (
            AC_SECRET="layerv-nhp-${ENV}-ac-${id}"
            if timeout 30 run_aws secretsmanager describe-secret --secret-id "$AC_SECRET" &>/dev/null; then
                touch "$AC_KEY_TMPDIR/$id"
            fi
        ) &
    done <<< "$AC_INSTANCES"
    wait
    AC_KEY_COUNT=$(find "$AC_KEY_TMPDIR" -type f | wc -l | tr -d ' ')
    AC_EXPECTED=$(echo "$AC_INSTANCES" | wc -l | tr -d ' ')
    if [ "$AC_KEY_COUNT" -eq 0 ] && [ "$AC_EXPECTED" -gt 0 ]; then
        warn "No AC keys found in Secrets Manager (expected $AC_EXPECTED based on running instances)"
    else
        info "$AC_KEY_COUNT AC private key(s) in Secrets Manager"
    fi
else
    info "Skipping AC key check (no instances found)"
fi
echo ""

# 6. Check CloudWatch Logs
echo "6. CloudWatch Logs"
echo "------------------"
LOG_GROUPS=$(run_aws logs describe-log-groups \
    --query "logGroups[?contains(logGroupName, 'nhp')].logGroupName" \
    --output text 2>/dev/null || true)

if [ -n "$LOG_GROUPS" ] && [ "$LOG_GROUPS" != "None" ]; then
    LOG_COUNT=$(echo "$LOG_GROUPS" | wc -w | tr -d ' ')
    pass "Found $LOG_COUNT NHP log group(s)"
    for lg in $LOG_GROUPS; do
        info "  $lg"
    done
else
    warn "No NHP log groups found"
fi
echo ""

# 7. Certificate Validation
echo "7. AWS RSA-2048 Certificates"
echo "---------------------------"
REGION=$(run_aws configure get region 2>/dev/null || echo "us-east-2")
info "Current region: $REGION"

# The certificate validation is done in Go tests (aws_certs_test.go)
# Here we just remind the user to run the tests
info "Run certificate tests: KBS_SKIP_INIT=1 go test -v ./server -run 'AWS'"
echo ""

# Summary
echo "==========================================="
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All critical checks passed!${NC}"
else
    echo -e "${RED}Some checks failed. Review above output.${NC}"
fi
echo "==========================================="
echo ""
echo "Next steps:"
echo "  1. Run Go integration tests:"
echo "     cd nhp && KBS_SKIP_INIT=1 go test -v ./server -run 'AWS'"
echo ""
echo "  2. Check AC logs:"
echo "     ${AWS_PROFILE_PREFIX}aws logs tail /aws/ec2/nhp-ac-${ENV} --follow"
echo ""
echo "  3. Check server logs:"
echo "     ${AWS_PROFILE_PREFIX}aws logs tail /aws/ec2/nhp-server-${ENV} --follow"
echo ""

exit $FAILED
