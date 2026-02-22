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

for arg in "$@"; do
    case "$arg" in
        --dry-run)
            MODE="dry-run"
            ;;
        --json)
            MODE="json"
            ;;
        --help|-h)
            echo "NHP Production Deployment Helper"
            echo ""
            echo "Usage:"
            echo "  ./scripts/trigger-prod-deploy.sh             # Interactive: show summary -> confirm -> deploy"
            echo "  ./scripts/trigger-prod-deploy.sh --dry-run   # Show summary + command only (no prompt)"
            echo "  ./scripts/trigger-prod-deploy.sh --json      # Machine-readable JSON output (no prompt)"
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
    if date -j -f "%Y-%m-%dT%H:%M:%S" "${ts%%[Z+]*}" +%s &>/dev/null 2>&1; then
        ts_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%S" "${ts%%[Z+]*}" +%s 2>/dev/null)
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
    if date -j -f "%Y-%m-%dT%H:%M:%S" "${ts%%[Z+]*}" +%s &>/dev/null 2>&1; then
        ts_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%S" "${ts%%[Z+]*}" +%s 2>/dev/null)
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
    entry="${ts} | ${action} | operator=$(get_operator) | sandbox=${SANDBOX_COMMIT:-unknown} | prod=${PROD_COMMIT:-unknown}"
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

# Check 1: AWS sandbox credentials
if AWS_PROFILE=layerv aws sts get-caller-identity --region "$REGION" --no-cli-pager &>/dev/null; then
    SANDBOX_ACCOUNT=$(AWS_PROFILE=layerv aws sts get-caller-identity --query Account --output text --region "$REGION" --no-cli-pager)
    pass "AWS sandbox credentials valid (account: $SANDBOX_ACCOUNT)"
else
    fail "Cannot access sandbox AWS account. Configure AWS_PROFILE=layerv."
fi

# Check 2: AWS prod credentials
if AWS_PROFILE=layerv-prod aws sts get-caller-identity --region "$REGION" --no-cli-pager &>/dev/null; then
    PROD_ACCOUNT=$(AWS_PROFILE=layerv-prod aws sts get-caller-identity --query Account --output text --region "$REGION" --no-cli-pager)
    pass "AWS prod credentials valid (account: $PROD_ACCOUNT)"
else
    fail "Cannot access prod AWS account. Configure AWS_PROFILE=layerv-prod."
fi

# Check 3: GitHub CLI
if gh auth status &>/dev/null; then
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

# Early exit: sandbox and prod already at the same commit
if [[ "$SANDBOX_COMMIT" == "$PROD_COMMIT" && -n "$SANDBOX_COMMIT" ]]; then
    info "Sandbox and prod at same commit (${SANDBOX_COMMIT:0:7}). Nothing to deploy."
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

# Check: Sandbox deploy state
if [[ "$SANDBOX_STATE" == "deployed" ]]; then
    pass "Sandbox in expected state ('deployed')"
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

# Check: Last sandbox CI was green
LAST_CI=$(gh run list --workflow=deploy-to-sandbox.yml --branch main --limit 1 --json databaseId,conclusion --jq '.[0]' 2>/dev/null || echo "")
if [[ -n "$LAST_CI" ]]; then
    CI_CONCLUSION=$(echo "$LAST_CI" | jq -r '.conclusion // "unknown"')
    CI_ID=$(echo "$LAST_CI" | jq -r '.databaseId // "?"')
    if [[ "$CI_CONCLUSION" == "success" ]]; then
        pass "Last sandbox CI run: success (#${CI_ID})"
    else
        fail "Last sandbox CI run: ${CI_CONCLUSION} (#${CI_ID}). Fix sandbox first."
    fi
else
    warn "Could not check sandbox CI status"
fi

# Check: Soak time >= 30 minutes
SOAK_MINUTES=$(minutes_since "$SANDBOX_DEPLOYED_AT")
if (( SOAK_MINUTES < 30 )); then
    fail "Sandbox deployed only ${SOAK_MINUTES}m ago. Minimum 30m soak required."
else
    pass "Sandbox soak time: $(time_ago "$SANDBOX_DEPLOYED_AT") (min: 30m)"
fi

# Check: Server image exists in ECR
if AWS_PROFILE=layerv aws ecr describe-images \
    --repository-name layerv/nhp-server \
    --image-ids imageTag="${SANDBOX_COMMIT}" \
    --region "$REGION" --no-cli-pager &>/dev/null; then
    pass "Server image ${SANDBOX_COMMIT:0:7} exists in ECR"
else
    fail "Server image ${SANDBOX_COMMIT} not found in ECR."
fi

# Check: AC image exists in ECR
if AWS_PROFILE=layerv aws ecr describe-images \
    --repository-name layerv/nhp-ac \
    --image-ids imageTag="${SANDBOX_COMMIT}" \
    --region "$REGION" --no-cli-pager &>/dev/null; then
    pass "AC image ${SANDBOX_COMMIT:0:7} exists in ECR"
else
    fail "AC image ${SANDBOX_COMMIT} not found in ECR."
fi

# Hard exit if any deployment state or health checks failed
if [[ "$PREFLIGHT_FAILED" -ne 0 ]]; then
    echo ""
    echo -e "  ${RED}Deployment checks failed. Fix the above issues and retry.${NC}"
    exit 1
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

# Sandbox age > 48h
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
    # Get changed files between prod and sandbox commits
    if ! CHANGED_FILES=$(git diff --name-only "${PROD_COMMIT}..${SANDBOX_COMMIT}" 2>&1); then
        warn "Git history too shallow for diff. Run: git fetch --unshallow"
        warn "Deploying all components as fallback."
        deploy_server=true
        deploy_ac=true
        run_terraform=true
        SERVER_REASON="git diff failed (shallow clone?)"
        AC_REASON="git diff failed (shallow clone?)"
        TF_REASON="git diff failed (shallow clone?)"
    else
        # NHP Server + AC (always together — shared Go modules)
        if echo "$CHANGED_FILES" | grep -qE '^(nhp/|endpoints/|docker/|examples/|\.github/workflows/)'; then
            deploy_server=true
            deploy_ac=true
            # Collect which paths matched for the reason string
            MATCHED_PATHS=$(echo "$CHANGED_FILES" | grep -oE '^(nhp|endpoints|docker|examples|\.github/workflows)/' | sort -u | tr '\n' ', ' | sed 's/,$//')
            SERVER_REASON="code changes in ${MATCHED_PATHS}"
            AC_REASON="code changes in ${MATCHED_PATHS}"
        fi

        # Terraform
        if echo "$CHANGED_FILES" | grep -qE '^terraform/'; then
            run_terraform=true
            TF_REASON="changes in terraform/"
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
GH_CMD=(gh workflow run promote-to-prod.yml --ref main
    -f "image_tag=${SANDBOX_COMMIT}"
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
        --arg image_tag "$SANDBOX_COMMIT" \
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
echo "    -f image_tag=${SANDBOX_COMMIT} \\"
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
echo -e "  Sandbox commit: ${SANDBOX_COMMIT:0:7} → Production"
read -r -p "  [y/N]: " confirm
echo ""

if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo -e "  ${YELLOW}Aborted.${NC} Run with --dry-run to review without prompting."
    audit_log "ABORTED" "reason=user_cancelled"
    exit 0
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
    echo "       -f rollback=true -f image_tag=${SANDBOX_COMMIT}"
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
