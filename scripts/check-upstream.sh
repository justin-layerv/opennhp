#!/bin/bash
# Check for new upstream commits since last review
# Run monthly or when you suspect upstream has security fixes
#
# Usage: ./scripts/check-upstream.sh

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Read baseline from UPSTREAM_SYNC.md
SYNC_FILE="docs/UPSTREAM_SYNC.md"
if [ ! -f "$SYNC_FILE" ]; then
    echo -e "${RED}Error: $SYNC_FILE not found${NC}"
    echo "Please ensure you're running this from the repository root"
    exit 1
fi

# Parse baseline from markdown table: | **Last reviewed upstream SHA** | bd6b7538 |
# Only take the first match (the actual table row, not comments)
BASELINE=$(grep "Last reviewed upstream SHA" "$SYNC_FILE" | head -1 | awk -F'|' '{print $3}' | tr -d ' ')

if [ -z "$BASELINE" ]; then
    echo -e "${YELLOW}Warning: Could not read baseline from $SYNC_FILE${NC}"
    echo "Using origin/main as fallback (will show more commits)"
    BASELINE="origin/main"
elif ! [[ "$BASELINE" =~ ^[0-9a-fA-F]{7,40}$ ]]; then
    echo -e "${RED}Error: Invalid baseline SHA format: '$BASELINE'${NC}"
    echo "Expected 7-40 hex characters. Check $SYNC_FILE format."
    exit 1
fi

echo "=== Upstream Sync Check ==="
echo "Baseline SHA: $BASELINE"
echo ""

# Ensure upstream remote exists
if ! git remote | grep -q upstream; then
    echo "Adding upstream remote..."
    git remote add upstream https://github.com/OpenNHP/opennhp.git
fi

echo "Fetching upstream..."
git fetch upstream --quiet

echo ""
echo "=== NEW commits since last review ==="
git log --oneline "$BASELINE..upstream/main"

echo ""
COUNT=$(git rev-list --count "$BASELINE..upstream/main")
echo "=== Total: $COUNT new commits ==="

if [ "$COUNT" -eq 0 ]; then
    echo -e "${GREEN}Nothing new to review!${NC}"
    exit 0
fi

echo ""
echo "=== Quick Categorization ==="

echo ""
echo -e "${RED}Security/Panic fixes (SYNC THESE):${NC}"
SECURITY=$(git log --oneline "$BASELINE..upstream/main" --grep="security\|panic\|crash\|vuln\|CVE" | grep -v "deps\|CI\|workflow" || true)
if [ -z "$SECURITY" ]; then
    echo "  (none found)"
else
    echo "$SECURITY"
fi

echo ""
echo -e "${YELLOW}Auto-skip (GMSM/KGC/CI/deps):${NC}"
SKIP_COUNT=$(git log --oneline "$BASELINE..upstream/main" | grep -iE "gmsm|sm2|sm3|sm4|kgc|deps:|workflow|release-please|dependabot" | wc -l | xargs)
echo "  Count: $SKIP_COUNT commits"

echo ""
echo "Other (need manual review):"
OTHER_COMMITS=$(git log --oneline "$BASELINE..upstream/main" | grep -viE "gmsm|sm2|sm3|sm4|kgc|deps:|workflow|release-please|dependabot|security|panic|crash|vuln|CVE" || true)
OTHER_COUNT=$(echo "$OTHER_COMMITS" | grep -c . || echo 0)
if [ -z "$OTHER_COMMITS" ]; then
    echo "  (none)"
elif [ "$OTHER_COUNT" -gt 10 ]; then
    echo "$OTHER_COMMITS" | head -10
    echo -e "  ${YELLOW}... and $((OTHER_COUNT - 10)) more (run 'git log $BASELINE..upstream/main' for full list)${NC}"
else
    echo "$OTHER_COMMITS"
fi

echo ""
echo "=== Next Steps ==="
echo "1. Review the security commits above - sync immediately if any"
echo "2. Review 'Other' commits - quick triage using Decision Matrix"
echo "3. Update docs/UPSTREAM_SYNC.md with new baseline SHA"
echo "4. Create sync PR if needed: git checkout -b sync/upstream-<desc>"
echo ""
echo "New upstream HEAD: $(git rev-parse upstream/main)"
