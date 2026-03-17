#!/bin/bash
# NHP Production Deployment Helper
# Reads deployment state from sandbox + prod AWS accounts, validates health,
# detects changed components, and triggers the promote-to-prod workflow.
#
# Usage:
#   ./scripts/trigger-prod-deploy.sh             # Interactive: show summary -> confirm -> deploy
#   ./scripts/trigger-prod-deploy.sh --dry-run   # Show summary + command only (no prompt)
#   ./scripts/trigger-prod-deploy.sh --json      # Machine-readable JSON output (no prompt)
#
# Prerequisites:
#   - AWS CLI with profiles: layerv (sandbox), layerv-prod (prod)
#   - GitHub CLI authenticated (gh auth login)
#   - Git repository with full history (not shallow)

set -Eeuo pipefail

# =============================================================================
# Arguments
# =============================================================================

MODE="interactive"
SKIP_SOAK=false

for arg in "$@"; do
    case "$arg" in
        --dry-run)
            MODE="dry-run"
            ;;
        --json)
            MODE="json"
            ;;
        --skip-soak)
            SKIP_SOAK=true
            ;;
        --help|-h)
            echo "NHP Production Deployment Helper"
            echo ""
            echo "Usage:"
            echo "  ./scripts/trigger-prod-deploy.sh               # Interactive: show summary -> confirm -> deploy"
            echo "  ./scripts/trigger-prod-deploy.sh --dry-run     # Show summary + command only (no prompt)"
            echo "  ./scripts/trigger-prod-deploy.sh --json        # Machine-readable JSON output (no prompt)"
            echo "  ./scripts/trigger-prod-deploy.sh --skip-soak   # Skip the 30m sandbox soak time check"
            echo ""
            echo "Prerequisites:"
            echo "  - AWS CLI with profiles: layerv (sandbox), layerv-prod (prod)"
            echo "  - GitHub CLI authenticated (gh auth login)"
            echo "  - Git repository with full history (not shallow)"
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Run with --help for usage."
            exit 1
            ;;
    esac
done

# =============================================================================
# Constants and helpers
# =============================================================================

REGION="us-east-2"

# Script state
PREFLIGHT_FAILED=0
declare -a WARNINGS=()

# SSM parameter paths — centralized for easy maintenance if paths change
# Sandbox (AWS_PROFILE=layerv)
SSM_SANDBOX_COMMIT="/sandbox/nhp/deploy/deployed-commit"
SSM_SANDBOX_DEPLOYED_AT="/sandbox/nhp/deploy/deployed-at"
SSM_SANDBOX_STATE="/sandbox/nhp/deploy/state"
SSM_SANDBOX_SERVER_TAG="/sandbox/nhp/server/image-tag"
SSM_SANDBOX_AC_TAG="/sandbox/nhp/ac/image-tag"
SSM_SANDBOX_QURL_TAG="/layerv-nhp-sandbox/qurl-api-image-tag"
# Prod (AWS_PROFILE=layerv-prod)
SSM_PROD_COMMIT="/prod/nhp/deploy/deployed-commit"
SSM_PROD_DEPLOYED_AT="/prod/nhp/deploy/deployed-at"
SSM_PROD_STATE="/prod/nhp/deploy/state"
SSM_PROD_SERVER_TAG="/prod/nhp/server/image-tag"
SSM_PROD_AC_TAG="/prod/nhp/ac/image-tag"
SSM_PROD_QURL_TAG="/layerv-nhp-prod/qurl-api-image-tag"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; PREFLIGHT_FAILED=1; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "         $1"; }
header() { echo -e "\n  ${BOLD}${CYAN}$1${NC}"; echo -e "  ${CYAN}$(printf '─%.0s' $(seq 1 ${#1}))${NC}"; }

# read_ssm — read an SSM parameter from a given AWS profile
# Returns the parameter value, or empty string on failure
read_ssm() {
    local profile="$1" param="$2"
    AWS_PROFILE="$profile" aws ssm get-parameter \
        --name "$param" \
        --query "Parameter.Value" \
        --output text \
        --region "$REGION" \
        --no-cli-pager 2>/dev/null || echo ""
}

# time_ago — convert ISO 8601 timestamp to human-readable relative time
time_ago() {
    local ts="$1"
    if [[ -z "$ts" || "$ts" == "(not set)" ]]; then echo "unknown"; return; fi
    local now ts_epoch diff
    now=$(date +%s)
    # macOS uses `date -j -f` for parsing; Linux/CI uses `date -d`.
    # Try macOS first (no-op on Linux), fall back to GNU date.
    if date -j -u -f "%Y-%m-%dT%H:%M:%S" "${ts%%[Z+]*}" +%s &>/dev/null 2>&1; then
        ts_epoch=$(date -j -u -f "%Y-%m-%dT%H:%M:%S" "${ts%%[Z+]*}" +%s 2>/dev/null)
    else
        ts_epoch=$(date -d "$ts" +%s 2>/dev/null || echo "0")
    fi
    diff=$(( now - ts_epoch ))
    if (( diff < 3600 )); then echo "$(( diff / 60 ))m ago"
    elif (( diff < 86400 )); then echo "$(( diff / 3600 ))h ago"
    else echo "$(( diff / 86400 ))d ago"
    fi
}

# minutes_since — return integer minutes since the given ISO 8601 timestamp
minutes_since() {
    local ts="$1"
    if [[ -z "$ts" || "$ts" == "(not set)" ]]; then echo "999999"; return; fi
    local now ts_epoch
    now=$(date +%s)
    # macOS uses `date -j -f` for parsing; Linux/CI uses `date -d`
    if date -j -u -f "%Y-%m-%dT%H:%M:%S" "${ts%%[Z+]*}" +%s &>/dev/null 2>&1; then
        ts_epoch=$(date -j -u -f "%Y-%m-%dT%H:%M:%S" "${ts%%[Z+]*}" +%s 2>/dev/null)
    else
        ts_epoch=$(date -d "$ts" +%s 2>/dev/null || echo "0")
    fi
    echo $(( (now - ts_epoch) / 60 ))
}

# commit_subject — get the one-line subject for a commit SHA
commit_subject() {
    git log -1 --format="%s" "$1" 2>/dev/null || echo "(unknown)"
}

# Audit log — append deployment events to a local log file
AUDIT_LOG="${HOME}/.nhp-deploy.log"
touch "$AUDIT_LOG" && chmod 600 "$AUDIT_LOG" 2>/dev/null || true
OPERATOR=""

get_operator() {
    if [[ -z "$OPERATOR" ]]; then
        OPERATOR=$(gh api user --jq '.login' 2>/dev/null || echo "unknown")
    fi
    echo "$OPERATOR"
}

audit_log() {
    local action="$1" extra="${2:-}"
    local ts entry
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    entry="${ts} | ${action} | operator=$(get_operator) | sandbox=${SANDBOX_COMMIT:-unknown} | image_tag=${PROMOTION_TAG:-unknown} | prod=${PROD_COMMIT:-unknown}"
    if [[ -n "$extra" ]]; then
        entry="${entry} | ${extra}"
    fi
    echo "$entry" >> "$AUDIT_LOG"
}

# =============================================================================
# Section 1: Preflight Checks — credentials and environment
# =============================================================================

echo ""
echo "  =============================================="
echo "    PROD DEPLOYMENT — layerv-nhp"
echo "  =============================================="

header "PREFLIGHT"

# Check 1: AWS sandbox credentials (single call — cache output)
if STS_SANDBOX=$(AWS_PROFILE=layerv aws sts get-caller-identity --region "$REGION" --no-cli-pager --output json 2>&1); then
    SANDBOX_ACCOUNT=$(echo "$STS_SANDBOX" | jq -r '.Account')
    pass "AWS sandbox credentials valid (account: $SANDBOX_ACCOUNT)"
else
    fail "Cannot access sandbox AWS account. Configure AWS_PROFILE=layerv."
fi

# Check 2: AWS prod credentials (single call — cache output)
if STS_PROD=$(AWS_PROFILE=layerv-prod aws sts get-caller-identity --region "$REGION" --no-cli-pager --output json 2>&1); then
    PROD_ACCOUNT=$(echo "$STS_PROD" | jq -r '.Account')
    pass "AWS prod credentials valid (account: $PROD_ACCOUNT)"
else
    fail "Cannot access prod AWS account. Configure AWS_PROFILE=layerv-prod."
fi

# Check 3: GitHub CLI (gh auth status exits non-zero if ANY account has issues,
# even if the active account is fine — so check the active account specifically)
if gh auth token &>/dev/null; then
    pass "GitHub CLI authenticated"
else
    fail "GitHub CLI not authenticated. Run: gh auth login"
fi

# Check 4: Git repository
if git rev-parse --is-inside-work-tree &>/dev/null; then
    pass "Inside git repository"
else
    fail "Must run from inside the nhp git repository."
fi

# Check 5: jq (required for JSON mode and CI status parsing)
if command -v jq &>/dev/null; then
    pass "jq available"
else
    fail "jq not found. Install with: brew install jq"
fi

# Hard exit if basic preflight checks failed
if [[ "$PREFLIGHT_FAILED" -ne 0 ]]; then
    echo ""
    echo -e "  ${RED}Preflight failed. Fix the above issues and retry.${NC}"
    exit 1
fi

# =============================================================================
# Section 2: Read SSM State — fetch deployment metadata from both accounts
# =============================================================================

header "READING DEPLOYMENT STATE"

# Sandbox (profile=layerv)
SANDBOX_COMMIT=$(read_ssm "layerv" "$SSM_SANDBOX_COMMIT")
SANDBOX_DEPLOYED_AT=$(read_ssm "layerv" "$SSM_SANDBOX_DEPLOYED_AT")
SANDBOX_STATE=$(read_ssm "layerv" "$SSM_SANDBOX_STATE")
SANDBOX_SERVER_TAG=$(read_ssm "layerv" "$SSM_SANDBOX_SERVER_TAG")
SANDBOX_AC_TAG=$(read_ssm "layerv" "$SSM_SANDBOX_AC_TAG")
SANDBOX_QURL_TAG=$(read_ssm "layerv" "$SSM_SANDBOX_QURL_TAG")

info "Sandbox SSM parameters loaded"

# Prod (profile=layerv-prod)
PROD_COMMIT=$(read_ssm "layerv-prod" "$SSM_PROD_COMMIT")
PROD_DEPLOYED_AT=$(read_ssm "layerv-prod" "$SSM_PROD_DEPLOYED_AT")
PROD_STATE=$(read_ssm "layerv-prod" "$SSM_PROD_STATE")
PROD_SERVER_TAG=$(read_ssm "layerv-prod" "$SSM_PROD_SERVER_TAG")
PROD_AC_TAG=$(read_ssm "layerv-prod" "$SSM_PROD_AC_TAG")
PROD_QURL_TAG=$(read_ssm "layerv-prod" "$SSM_PROD_QURL_TAG")

info "Prod SSM parameters loaded"

# Replace empty values with "(not set)" for display
SANDBOX_DEPLOYED_AT="${SANDBOX_DEPLOYED_AT:-(not set)}"
SANDBOX_STATE="${SANDBOX_STATE:-(not set)}"
SANDBOX_SERVER_TAG="${SANDBOX_SERVER_TAG:-(not set)}"
SANDBOX_AC_TAG="${SANDBOX_AC_TAG:-(not set)}"
SANDBOX_QURL_TAG="${SANDBOX_QURL_TAG:-(not set)}"
PROD_COMMIT="${PROD_COMMIT:-(not set)}"
PROD_DEPLOYED_AT="${PROD_DEPLOYED_AT:-(not set)}"
PROD_STATE="${PROD_STATE:-(not set)}"
PROD_SERVER_TAG="${PROD_SERVER_TAG:-(not set)}"
PROD_AC_TAG="${PROD_AC_TAG:-(not set)}"
PROD_QURL_TAG="${PROD_QURL_TAG:-(not set)}"

# Hard block: no sandbox commit means nothing to deploy
if [[ -z "$SANDBOX_COMMIT" ]]; then
    fail "No sandbox commit found. Deploy to sandbox first, or check SSM parameter: ${SSM_SANDBOX_COMMIT}"
    echo ""
    echo -e "  ${RED}Cannot proceed without a sandbox deployment.${NC}"
    exit 1
fi

# Validate commit SHA format (security: prevent injection via compromised SSM)
if [[ ! "$SANDBOX_COMMIT" =~ ^[a-f0-9]{7,40}$ ]]; then
    fail "Sandbox commit '${SANDBOX_COMMIT}' is not a valid git SHA. SSM parameter may be corrupted."
    echo ""
    echo -e "  ${RED}Cannot proceed with invalid commit SHA.${NC}"
    exit 1
fi

if [[ "$PROD_COMMIT" != "(not set)" && ! "$PROD_COMMIT" =~ ^[a-f0-9]{7,40}$ ]]; then
    fail "Prod commit '${PROD_COMMIT}' is not a valid git SHA. SSM parameter may be corrupted."
    echo ""
    echo -e "  ${RED}Cannot proceed with invalid commit SHA.${NC}"
    exit 1
fi

# Early exit: sandbox and prod already at the same commit AND same image tags
if [[ "$SANDBOX_COMMIT" == "$PROD_COMMIT" && -n "$SANDBOX_COMMIT" \
    && "$SANDBOX_SERVER_TAG" == "$PROD_SERVER_TAG" \
    && "$SANDBOX_AC_TAG" == "$PROD_AC_TAG" ]]; then
    info "Sandbox and prod at same commit (${SANDBOX_COMMIT:0:7}) with matching image tags. Nothing to deploy."
    exit 0
fi

# =============================================================================
# Section 3: Deployment State Checks — hard blocks
# =============================================================================

header "DEPLOYMENT STATE"

# Check: Prod deployment lock
if [[ "$PROD_STATE" == "deploying" ]]; then
    fail "Prod deployment in progress (state='deploying'). Use force_unlock in GitHub Actions UI if stale."
else
    pass "Prod not in deployment lock (state='${PROD_STATE}')"
fi

# Warn if last prod deployment failed — environment may be partially broken
if [[ "$PROD_STATE" == "failed" ]]; then
    msg="Last prod deployment failed. Deploying on top of a potentially broken environment."
    warn "$msg"
    WARNINGS+=("$msg")
fi

# Check: Sandbox deploy state
# Note: /sandbox/nhp/deploy/state may not exist if the build-and-push workflow
# doesn't set it. Infer "deployed" from the presence of deployed-commit/deployed-at.
if [[ "$SANDBOX_STATE" == "deployed" ]]; then
    pass "Sandbox in expected state ('deployed')"
elif [[ "$SANDBOX_STATE" == "(not set)" && -n "$SANDBOX_COMMIT" && "$SANDBOX_DEPLOYED_AT" != "(not set)" ]]; then
    pass "Sandbox deploy state inferred as 'deployed' (state param not set, but deployed-commit exists)"
elif [[ "$SANDBOX_STATE" == "deploying" ]]; then
    fail "Sandbox deployment in progress (state='deploying'). Wait for it to finish."
else
    fail "Sandbox is in state '${SANDBOX_STATE}'. Fix sandbox before promoting."
fi

# Check: In-flight workflow runs
IN_FLIGHT=$(gh run list --workflow=promote-to-prod.yml --status=in_progress --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || echo "")
if [[ -n "$IN_FLIGHT" ]]; then
    fail "promote-to-prod workflow already in progress (run #${IN_FLIGHT}). Wait or cancel it first."
else
    pass "No in-flight promote-to-prod workflows"
fi

# =============================================================================
# Section 4: Sandbox Health Validation — hard blocks
# =============================================================================

header "SANDBOX HEALTH"

# Determine PROMOTION_TAG first — needed by the CI check below.
# The promote-to-prod workflow uses a SINGLE image_tag for both server and AC
# ECR lookups. If the tags diverge, the workflow will fail for one component.
if [[ "$SANDBOX_SERVER_TAG" != "(not set)" && "$SANDBOX_AC_TAG" != "(not set)" \
    && "$SANDBOX_SERVER_TAG" != "$SANDBOX_AC_TAG" ]]; then
    fail "Server tag (${SANDBOX_SERVER_TAG:0:7}) != AC tag (${SANDBOX_AC_TAG:0:7}). Cannot use single image_tag for both."
    echo -e "  ${RED}Fix: re-deploy sandbox to bring server/AC tags back in sync.${NC}"
    exit 1
fi

# Use the server image tag (from SSM) since that reflects what's actually in ECR.
# deployed-commit can diverge from image tags when builds skip image creation
# (e.g., terraform-only or CI-only commits).
PROMOTION_TAG="$SANDBOX_SERVER_TAG"

# Validate image tag format (same SHA check as deployed-commit)
if [[ ! "$PROMOTION_TAG" =~ ^[a-f0-9]{7,40}$ ]]; then
    fail "Server image tag '${PROMOTION_TAG}' is not a valid git SHA. SSM parameter may be corrupted."
    exit 1
fi

# Check: CI status for the images we're promoting
# Look for the build that produced PROMOTION_TAG, not just the latest run.
# The latest run may have failed on terraform while our images are from
# an earlier successful build.
IMAGE_CI=$(gh run list --workflow=build-and-push.yml --branch main --limit 10 --json databaseId,conclusion,headSha 2>/dev/null || echo "[]")
if [[ -n "$IMAGE_CI" && "$IMAGE_CI" != "[]" ]]; then
    # Find the run that matches our image tag (PROMOTION_TAG = commit SHA)
    MATCHING_RUN=$(echo "$IMAGE_CI" | jq -r --arg sha "$PROMOTION_TAG" '[.[] | select(.headSha | startswith($sha))][0] // empty' 2>/dev/null || echo "")
    LATEST_RUN=$(echo "$IMAGE_CI" | jq -r '.[0]' 2>/dev/null || echo "")

    if [[ -n "$MATCHING_RUN" ]]; then
        # Found the exact build that produced our images
        IMG_CI_ID=$(echo "$MATCHING_RUN" | jq -r '.databaseId // "?"')
        IMG_CI_CONCLUSION=$(echo "$MATCHING_RUN" | jq -r '.conclusion // "unknown"')

        if [[ "$IMG_CI_CONCLUSION" == "success" ]]; then
            pass "CI run for image ${PROMOTION_TAG:0:7}: success (#${IMG_CI_ID})"
        else
            # Run failed overall — check if the BUILD jobs specifically succeeded.
            # A CI run can fail on deploy/test steps while images were built fine.
            # Job names "Build server" and "Build ac" come from the build matrix in build-and-push.yml.
            BUILD_STATUS=$(gh run view "$IMG_CI_ID" --json jobs \
                --jq '[.jobs[] | select(.name | startswith("Build ")) | .conclusion]' 2>/dev/null || echo "[]")
            BUILD_COUNT=$(echo "$BUILD_STATUS" | jq 'length' 2>/dev/null || echo "0")
            BUILD_FAILURES=$(echo "$BUILD_STATUS" | jq '[.[] | select(. != "success")] | length' 2>/dev/null || echo "0")

            if [[ "$BUILD_COUNT" -eq 0 ]]; then
                fail "CI run for image ${PROMOTION_TAG:0:7}: ${IMG_CI_CONCLUSION} (#${IMG_CI_ID}). Could not find Build jobs to verify."
            elif [[ "$BUILD_FAILURES" -eq 0 ]]; then
                pass "Build jobs for image ${PROMOTION_TAG:0:7}: success (run #${IMG_CI_ID} overall: ${IMG_CI_CONCLUSION})"
                msg="CI run #${IMG_CI_ID} failed on non-build steps (${IMG_CI_CONCLUSION}) but images were built successfully"
                warn "$msg"
                WARNINGS+=("$msg")
            else
                fail "CI run for image ${PROMOTION_TAG:0:7}: ${IMG_CI_CONCLUSION} (#${IMG_CI_ID}). Build jobs did not all succeed."
            fi
        fi
    else
        # Image build is older than last 10 runs — fall back to latest run check
        warn "Could not find CI run for image ${PROMOTION_TAG:0:7} in recent history"
    fi

    # Also check the latest run — warn if it failed (indicates sandbox issues)
    LATEST_CONCLUSION=$(echo "$LATEST_RUN" | jq -r '.conclusion // ""')
    LATEST_ID=$(echo "$LATEST_RUN" | jq -r '.databaseId // "?"')
    if [[ "$LATEST_CONCLUSION" == "failure" ]]; then
        msg="Latest sandbox CI run failed (#${LATEST_ID}) — may indicate infrastructure issues"
        warn "$msg"
        WARNINGS+=("$msg")
    elif [[ "$LATEST_CONCLUSION" == "" ]]; then
        msg="Latest sandbox CI run still in progress (#${LATEST_ID})"
        warn "$msg"
        WARNINGS+=("$msg")
    fi
else
    warn "Could not check sandbox CI status"
fi

# Check: Soak time >= 30 minutes
# SOAK_MINUTES is reused later for the 48h staleness warning
SOAK_MINUTES=0
if [[ "$SANDBOX_DEPLOYED_AT" == "(not set)" ]]; then
    warn "Sandbox deployed-at timestamp not set — cannot verify soak time"
    WARNINGS+=("Sandbox soak time unknown (deployed-at not set)")
else
    SOAK_MINUTES=$(minutes_since "$SANDBOX_DEPLOYED_AT")
    if (( SOAK_MINUTES < 30 )) && [[ "$SKIP_SOAK" != "true" ]]; then
        fail "Sandbox deployed only ${SOAK_MINUTES}m ago. Minimum 30m soak required. Use --skip-soak to override."
    elif (( SOAK_MINUTES < 30 )); then
        warn "Sandbox deployed only ${SOAK_MINUTES}m ago (soak check skipped via --skip-soak)"
        WARNINGS+=("Soak time skipped (${SOAK_MINUTES}m < 30m)")
    else
        pass "Sandbox soak time: $(time_ago "$SANDBOX_DEPLOYED_AT") (min: 30m)"
    fi
fi

# Check: Server image exists in ECR
# Use the actual image tag from SSM (not deployed-commit) — the build-and-push
# workflow updates deployed-commit even for terraform-only changes that don't
# build images, so deployed-commit may have no corresponding ECR image.
if [[ "$SANDBOX_SERVER_TAG" == "(not set)" ]]; then
    fail "Sandbox server image tag not set in SSM (${SSM_SANDBOX_SERVER_TAG})."
elif AWS_PROFILE=layerv aws ecr describe-images \
    --repository-name layerv/nhp-server \
    --image-ids imageTag="${SANDBOX_SERVER_TAG}" \
    --region "$REGION" --no-cli-pager &>/dev/null; then
    pass "Server image ${SANDBOX_SERVER_TAG:0:7} exists in ECR"
else
    fail "Server image ${SANDBOX_SERVER_TAG} not found in ECR."
fi

# Check: AC image exists in ECR
if [[ "$SANDBOX_AC_TAG" == "(not set)" ]]; then
    fail "Sandbox AC image tag not set in SSM (${SSM_SANDBOX_AC_TAG})."
elif AWS_PROFILE=layerv aws ecr describe-images \
    --repository-name layerv/nhp-ac \
    --image-ids imageTag="${SANDBOX_AC_TAG}" \
    --region "$REGION" --no-cli-pager &>/dev/null; then
    pass "AC image ${SANDBOX_AC_TAG:0:7} exists in ECR"
else
    fail "AC image ${SANDBOX_AC_TAG} not found in ECR."
fi

# Hard exit if any deployment state or health checks failed
if [[ "$PREFLIGHT_FAILED" -ne 0 ]]; then
    echo ""
    echo -e "  ${RED}Deployment checks failed. Fix the above issues and retry.${NC}"
    exit 1
fi

# Emit promotion tag warning after all hard checks pass
if [[ "$SANDBOX_SERVER_TAG" != "$SANDBOX_COMMIT" ]]; then
    msg="Image tag (${SANDBOX_SERVER_TAG:0:7}) differs from deployed-commit (${SANDBOX_COMMIT:0:7}) — using image tag for promotion"
    warn "$msg"
    WARNINGS+=("$msg")
fi

# =============================================================================
# Section 5: Safety Warnings — non-blocking but worth noting
# =============================================================================

# Sandbox commit behind main
MAIN_HEAD=$(git rev-parse --short=7 main 2>/dev/null || echo "")
if [[ -n "$MAIN_HEAD" && "${SANDBOX_COMMIT:0:7}" != "$MAIN_HEAD" ]]; then
    BEHIND=$(git rev-list --count "${SANDBOX_COMMIT}..main" 2>/dev/null || echo "?")
    if [[ "$BEHIND" != "0" && "$BEHIND" != "?" ]]; then
        msg="Sandbox commit ${SANDBOX_COMMIT:0:7} is ${BEHIND} commit(s) behind main (${MAIN_HEAD})"
        warn "$msg"
        WARNINGS+=("$msg")
    fi
fi

# Sandbox age > 48h (reuse SOAK_MINUTES from earlier)
if (( SOAK_MINUTES > 2880 )); then
    msg="Sandbox deployed $(time_ago "$SANDBOX_DEPLOYED_AT"). Consider re-deploying sandbox with latest main."
    warn "$msg"
    WARNINGS+=("$msg")
fi

# First prod deploy
FIRST_DEPLOY=false
if [[ -z "$PROD_COMMIT" || "$PROD_COMMIT" == "(not set)" || "$PROD_COMMIT" == "initial" || "$PROD_COMMIT" == "never" ]]; then
    FIRST_DEPLOY=true
    msg="No previous prod deployment found. All components will be deployed."
    warn "$msg"
    WARNINGS+=("$msg")
fi

# =============================================================================
# Section 6: Component Change Detection
# =============================================================================

deploy_server=false
deploy_ac=false
deploy_qurl=false
run_terraform=false
SERVER_REASON=""
AC_REASON=""
QURL_REASON=""
TF_REASON=""

if [[ "$FIRST_DEPLOY" == "true" ]]; then
    # First deployment — deploy everything
    deploy_server=true
    deploy_ac=true
    run_terraform=true
    deploy_qurl=true
    SERVER_REASON="first prod deployment"
    AC_REASON="first prod deployment"
    TF_REASON="first prod deployment"
    QURL_REASON="first prod deployment"
else
    # Server/AC: always deployed together — they share Go modules (nhp/, endpoints/)
    # and are built from the same commit. Compare image tags directly rather than
    # git diff, since deployed-commit can diverge from image tags.
    if [[ "$PROMOTION_TAG" != "$PROD_SERVER_TAG" ]]; then
        deploy_server=true
        deploy_ac=true
        SERVER_REASON="image tag changed: ${PROD_SERVER_TAG:0:7} → ${PROMOTION_TAG:0:7}"
        AC_REASON="image tag changed: ${PROD_AC_TAG:0:7} → ${PROMOTION_TAG:0:7}"
    fi

    # Terraform: use full commit range (terraform runs from main HEAD, not from image tag)
    if ! CHANGED_FILES=$(git diff --name-only "${PROD_COMMIT}..${SANDBOX_COMMIT}" 2>&1); then
        warn "Git history too shallow for diff. Run: git fetch --unshallow"
        if [[ "$deploy_server" == "false" ]]; then
            warn "Deploying all components as fallback."
            deploy_server=true
            deploy_ac=true
            SERVER_REASON="git diff failed (shallow clone?)"
            AC_REASON="git diff failed (shallow clone?)"
        fi
        run_terraform=true
        TF_REASON="git diff failed (shallow clone?)"
    else

        # Terraform
        if echo "$CHANGED_FILES" | grep -qE '^terraform/'; then
            run_terraform=true
            TF_REASON="changes in terraform/"

            # Warn if terraform changes exist beyond what was in the image-producing build.
            # This means terraform changes were introduced after the last image build and
            # may not have been successfully applied to sandbox yet.
            if [[ "$PROMOTION_TAG" != "$SANDBOX_COMMIT" ]]; then
                TF_UNCOMMITTED=$(git diff --name-only "${PROMOTION_TAG}..${SANDBOX_COMMIT}" 2>/dev/null | grep -c '^terraform/' || true)
                if (( TF_UNCOMMITTED > 0 )); then
                    msg="Terraform has ${TF_UNCOMMITTED} file(s) changed after image build (${PROMOTION_TAG:0:7}..${SANDBOX_COMMIT:0:7}). These may not be validated in sandbox."
                    warn "$msg"
                    WARNINGS+=("$msg")
                fi
            fi
        fi
    fi

    # QURL (separate repo — compare tags across environments)
    if [[ "$SANDBOX_QURL_TAG" != "(not set)" && "$SANDBOX_QURL_TAG" != "$PROD_QURL_TAG" ]]; then
        deploy_qurl=true
        QURL_REASON="tag changed: ${PROD_QURL_TAG} → ${SANDBOX_QURL_TAG}"
    fi

    # Fallback: if no components detected but commits differ
    if [[ "$deploy_server" == "false" && "$deploy_ac" == "false" && "$run_terraform" == "false" && "$deploy_qurl" == "false" ]]; then
        warn "No component changes detected but commits differ. Deploying all as safety fallback."
        deploy_server=true
        deploy_ac=true
        run_terraform=true
        SERVER_REASON="safety fallback (no specific changes detected)"
        AC_REASON="safety fallback (no specific changes detected)"
        TF_REASON="safety fallback (no specific changes detected)"
        WARNINGS+=("No specific component changes detected — deploying all as safety fallback")
    fi
fi

# =============================================================================
# Section 7: Compute Changelog
# =============================================================================

CHANGELOG=""
CHANGELOG_COUNT=0
if [[ "$FIRST_DEPLOY" == "false" && "$PROD_COMMIT" != "(not set)" ]]; then
    CHANGELOG=$(git log --oneline "${PROD_COMMIT}..${SANDBOX_COMMIT}" 2>/dev/null || echo "")
    if [[ -n "$CHANGELOG" ]]; then
        CHANGELOG_COUNT=$(echo "$CHANGELOG" | wc -l | tr -d ' ')
    fi
    if (( CHANGELOG_COUNT > 20 )); then
        msg="${CHANGELOG_COUNT} commits in this promotion. Consider deploying more frequently."
        warn "$msg"
        WARNINGS+=("$msg")
    fi
fi

# =============================================================================
# Section 8: Build Component List and GH Command
# =============================================================================

# Build component list for display and confirmation
DEPLOY_COMPONENTS=()
if [[ "$deploy_server" == "true" ]]; then DEPLOY_COMPONENTS+=("NHP Server"); fi
if [[ "$deploy_ac" == "true" ]]; then DEPLOY_COMPONENTS+=("Access Controller"); fi
if [[ "$deploy_qurl" == "true" ]]; then DEPLOY_COMPONENTS+=("QURL Service"); fi
if [[ "$run_terraform" == "true" ]]; then DEPLOY_COMPONENTS+=("Terraform"); fi

COMPONENT_LIST=$(IFS=", "; echo "${DEPLOY_COMPONENTS[*]}")

# QURL image tag — always explicit
QURL_TAG_FOR_COMMAND="${SANDBOX_QURL_TAG:-}"
if [[ "$QURL_TAG_FOR_COMMAND" == "(not set)" ]]; then
    QURL_TAG_FOR_COMMAND=""
fi

# Build the gh workflow run command as an array (avoids eval)
# Uses PROMOTION_TAG (actual ECR image tag) not SANDBOX_COMMIT (which may lack images)
GH_CMD=(gh workflow run promote-to-prod.yml --ref main
    -f "image_tag=${PROMOTION_TAG}"
    -f "deploy_server=${deploy_server}" -f "deploy_ac=${deploy_ac}"
    -f "deploy_qurl=${deploy_qurl}" -f "run_terraform=${run_terraform}"
)
if [[ -n "$QURL_TAG_FOR_COMMAND" ]]; then
    GH_CMD+=(-f "qurl_image_tag=${QURL_TAG_FOR_COMMAND}")
fi
GH_CMD+=(-f "cell_id=cell0")

# String form for display and JSON output
GH_COMMAND="${GH_CMD[*]}"

# =============================================================================
# Section 9: JSON Output (early exit if --json)
# =============================================================================

if [[ "$MODE" == "json" ]]; then
    # Build warnings JSON array
    WARNINGS_JSON="[]"
    if (( ${#WARNINGS[@]} > 0 )); then
        WARNINGS_JSON=$(printf '%s\n' "${WARNINGS[@]}" | jq -R . | jq -s .)
    fi

    # Build changelog JSON array
    CHANGELOG_JSON="[]"
    if [[ -n "$CHANGELOG" ]]; then
        CHANGELOG_JSON=$(echo "$CHANGELOG" | jq -R . | jq -s .)
    fi

    jq -n \
        --argjson preflight_passed "$([ $PREFLIGHT_FAILED -eq 0 ] && echo true || echo false)" \
        --arg sandbox_commit "$SANDBOX_COMMIT" \
        --arg sandbox_deployed_at "$SANDBOX_DEPLOYED_AT" \
        --arg sandbox_state "$SANDBOX_STATE" \
        --arg sandbox_server_tag "$SANDBOX_SERVER_TAG" \
        --arg sandbox_ac_tag "$SANDBOX_AC_TAG" \
        --arg sandbox_qurl_tag "$SANDBOX_QURL_TAG" \
        --arg prod_commit "$PROD_COMMIT" \
        --arg prod_deployed_at "$PROD_DEPLOYED_AT" \
        --arg prod_state "$PROD_STATE" \
        --arg prod_server_tag "$PROD_SERVER_TAG" \
        --arg prod_ac_tag "$PROD_AC_TAG" \
        --arg prod_qurl_tag "$PROD_QURL_TAG" \
        --argjson deploy_server "$deploy_server" \
        --argjson deploy_ac "$deploy_ac" \
        --argjson deploy_qurl "$deploy_qurl" \
        --argjson run_terraform "$run_terraform" \
        --arg command "$GH_COMMAND" \
        --arg image_tag "$PROMOTION_TAG" \
        --arg qurl_image_tag "${QURL_TAG_FOR_COMMAND:-}" \
        --argjson first_deploy "$([[ "$FIRST_DEPLOY" == "true" ]] && echo true || echo false)" \
        --argjson changelog_count "$CHANGELOG_COUNT" \
        --argjson warnings "$WARNINGS_JSON" \
        --argjson changelog "$CHANGELOG_JSON" \
        '{
          preflight: { all_passed: $preflight_passed },
          first_deploy: $first_deploy,
          sandbox: {
            commit: $sandbox_commit,
            deployed_at: $sandbox_deployed_at,
            state: $sandbox_state,
            server_tag: $sandbox_server_tag,
            ac_tag: $sandbox_ac_tag,
            qurl_tag: $sandbox_qurl_tag
          },
          prod: {
            commit: $prod_commit,
            deployed_at: $prod_deployed_at,
            state: $prod_state,
            server_tag: $prod_server_tag,
            ac_tag: $prod_ac_tag,
            qurl_tag: $prod_qurl_tag
          },
          components: {
            deploy_server: $deploy_server,
            deploy_ac: $deploy_ac,
            deploy_qurl: $deploy_qurl,
            run_terraform: $run_terraform
          },
          command: $command,
          workflow_inputs: {
            image_tag: $image_tag,
            qurl_image_tag: $qurl_image_tag,
            cell_id: "cell0"
          },
          changelog: {
            count: $changelog_count,
            commits: $changelog
          },
          warnings: $warnings
        }'

    audit_log "JSON" "components=${COMPONENT_LIST}"
    exit 0
fi

# =============================================================================
# Section 10: Display Summary (shown for interactive and dry-run modes)
# =============================================================================

# --- Sandbox ---
header "SANDBOX (source)"
echo "  Commit:   ${SANDBOX_COMMIT:0:7} — $(commit_subject "$SANDBOX_COMMIT")"
echo "  Deployed: ${SANDBOX_DEPLOYED_AT} ($(time_ago "$SANDBOX_DEPLOYED_AT"))"
echo "  Tags:     server=${SANDBOX_SERVER_TAG}  ac=${SANDBOX_AC_TAG}  qurl=${SANDBOX_QURL_TAG}"
echo "  State:    ${SANDBOX_STATE}"

# --- Production ---
header "PRODUCTION (target)"
echo "  Commit:   ${PROD_COMMIT:0:7} — $(commit_subject "$PROD_COMMIT")"
echo "  Deployed: ${PROD_DEPLOYED_AT} ($(time_ago "$PROD_DEPLOYED_AT"))"
echo "  Tags:     server=${PROD_SERVER_TAG}  ac=${PROD_AC_TAG}  qurl=${PROD_QURL_TAG}"
echo "  State:    ${PROD_STATE}"

# --- Changelog ---
if [[ "$FIRST_DEPLOY" == "true" ]]; then
    header "CHANGELOG"
    echo "  First deployment — no changelog available"
elif (( CHANGELOG_COUNT > 0 )); then
    header "CHANGELOG (${CHANGELOG_COUNT} commits)"
    echo "$CHANGELOG" | head -20 | while read -r line; do echo "  $line"; done
    if (( CHANGELOG_COUNT > 20 )); then
        echo "  ... and $((CHANGELOG_COUNT - 20)) more"
    fi
fi

# --- Components ---
header "COMPONENTS"
if [[ "$deploy_server" == "true" ]]; then
    echo -e "  ${GREEN}[DEPLOY]${NC}  NHP Server       — ${SERVER_REASON}"
else
    echo -e "  ${YELLOW}[SKIP]${NC}    NHP Server       — no changes detected"
fi
if [[ "$deploy_ac" == "true" ]]; then
    echo -e "  ${GREEN}[DEPLOY]${NC}  Access Controller — ${AC_REASON}"
else
    echo -e "  ${YELLOW}[SKIP]${NC}    Access Controller — no changes detected"
fi
if [[ "$deploy_qurl" == "true" ]]; then
    echo -e "  ${GREEN}[DEPLOY]${NC}  QURL Service      — ${QURL_REASON}"
else
    if [[ "$SANDBOX_QURL_TAG" != "(not set)" ]]; then
        echo -e "  ${YELLOW}[SKIP]${NC}    QURL Service      — same tag (${SANDBOX_QURL_TAG})"
    else
        echo -e "  ${YELLOW}[SKIP]${NC}    QURL Service      — no QURL tag configured"
    fi
fi
if [[ "$run_terraform" == "true" ]]; then
    echo -e "  ${GREEN}[DEPLOY]${NC}  Terraform         — ${TF_REASON}"
else
    echo -e "  ${YELLOW}[SKIP]${NC}    Terraform         — no changes detected"
fi

# --- Command ---
header "COMMAND"
echo "  gh workflow run promote-to-prod.yml --ref main \\"
echo "    -f image_tag=${PROMOTION_TAG} \\"
echo "    -f deploy_server=${deploy_server} \\"
echo "    -f deploy_ac=${deploy_ac} \\"
echo "    -f deploy_qurl=${deploy_qurl} \\"
echo "    -f run_terraform=${run_terraform} \\"
if [[ -n "$QURL_TAG_FOR_COMMAND" ]]; then
    echo "    -f qurl_image_tag=${QURL_TAG_FOR_COMMAND} \\"
fi
echo "    -f cell_id=cell0"

# =============================================================================
# Section 11: Dry-run vs Interactive Execution
# =============================================================================

if [[ "$MODE" == "dry-run" ]]; then
    echo ""
    echo -e "  ${YELLOW}DRY RUN — command shown above. No action taken.${NC}"
    audit_log "DRY_RUN" "components=${COMPONENT_LIST}"
    exit 0
fi

# Interactive mode: prompt for confirmation
echo ""
echo -e "  ${BOLD}Deploy ${COMPONENT_LIST} to PROD?${NC}"
echo -e "  Image tag: ${PROMOTION_TAG:0:7} → Production"
read -r -p "  [y/N]: " confirm
echo ""

if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo -e "  ${YELLOW}Aborted.${NC} Run with --dry-run to review without prompting."
    audit_log "ABORTED" "reason=user_cancelled"
    exit 0
fi

# Re-check for in-flight workflows just before triggering (narrows the race window)
RECHECK_IN_FLIGHT=$(gh run list --workflow=promote-to-prod.yml --status=in_progress --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || echo "")
if [[ -n "$RECHECK_IN_FLIGHT" ]]; then
    echo -e "  ${RED}Aborted: promote-to-prod workflow started since checks ran (run #${RECHECK_IN_FLIGHT}).${NC}"
    audit_log "ABORTED" "reason=concurrent_workflow_detected | run=${RECHECK_IN_FLIGHT}"
    exit 1
fi

# Execute the workflow
echo -e "  ${CYAN}Triggering workflow...${NC}"
if OUTPUT=$("${GH_CMD[@]}" 2>&1); then
    # Poll for the new run ID (up to 5 attempts, 1s apart)
    RUN_ID=""
    for _ in 1 2 3 4 5; do
        sleep 1
        RUN_ID=$(gh run list --workflow=promote-to-prod.yml --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || echo "")
        if [[ -n "$RUN_ID" && "$RUN_ID" != "null" ]]; then break; fi
        RUN_ID=""
    done
    RUN_ID="${RUN_ID:-?}"

    echo -e "  ${GREEN}Workflow triggered!${NC} Run #${RUN_ID}"
    audit_log "DEPLOYED" "components=${COMPONENT_LIST} | run=${RUN_ID}"

    echo ""
    header "NEXT STEPS"
    echo "  1. Watch the run:"
    echo "     gh run watch ${RUN_ID}"
    echo ""
    echo "  2. If deployment fails and needs rollback:"
    echo "     gh workflow run promote-to-prod.yml --ref main \\"
    echo "       -f rollback=true -f image_tag=${PROMOTION_TAG}"
    echo ""
    echo "  3. If deployment lock is stuck:"
    echo "     GitHub Actions UI → promote-to-prod → Run workflow → force_unlock=true"
    echo ""
else
    echo -e "  ${RED}Failed to trigger workflow:${NC}"
    echo "  $OUTPUT"
    audit_log "TRIGGER_FAILED" "components=${COMPONENT_LIST} | error=$(echo "$OUTPUT" | head -1)"
    exit 1
fi
