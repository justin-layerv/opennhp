#!/usr/bin/env bash
# clear-ac-assignments.sh — delete all AC assignments from DynamoDB
# so the next AC registration creates fresh assignments pointing to
# the new active servers.
#
# Usage: clear-ac-assignments.sh <environment> <cell-id>
#
# This is necessary during blue-green deploys because the assignment
# table stores server private IPs. After a blue-green switch, those
# IPs belong to the old (now standby) servers. Without clearing,
# the auto-assignment logic sends NHP_ARD pointing ACs to stale servers.

set -euo pipefail

ENVIRONMENT="${1:?Usage: clear-ac-assignments.sh <environment> <cell-id>}"
CELL_ID="${2:?}"

TABLE_NAME="layerv-nhp-${ENVIRONMENT}-${CELL_ID}-ac-assignments"

echo "Clearing AC assignments from DynamoDB table: $TABLE_NAME"

# Scan for all AC IDs. Let AWS CLI errors propagate (set -e) so
# misconfigured credentials or wrong table name fail the deploy step
# instead of silently skipping the clear and reproducing the stale-IP bug.
#
# Pagination: the table has one row per AC (typically 3-6). A single
# scan page (1 MB) holds ~10k+ small items, so pagination is not needed.
AC_IDS=$(aws dynamodb scan \
  --table-name "$TABLE_NAME" \
  --projection-expression "ac_id" \
  --query "Items[].ac_id.S" \
  --output text)

if [[ -z "$AC_IDS" ]]; then
  echo "No AC assignments found — table is already empty"
  exit 0
fi

COUNT=0
FAILED=0
for AC_ID in $AC_IDS; do
  # Use jq for safe JSON key construction (defensive against unexpected characters).
  KEY_JSON=$(jq -n --arg id "$AC_ID" '{"ac_id": {"S": $id}}')
  if aws dynamodb delete-item \
    --table-name "$TABLE_NAME" \
    --key "$KEY_JSON"; then
    COUNT=$((COUNT + 1))
    echo "  Deleted assignment for: $AC_ID"
  else
    FAILED=$((FAILED + 1))
    echo "  WARNING: Failed to delete assignment for: $AC_ID"
  fi
done

if [[ "$COUNT" -eq 0 && "$FAILED" -gt 0 ]]; then
  echo "ERROR: All $FAILED delete(s) failed — stale assignments remain, aborting deploy"
  exit 1
elif [[ "$FAILED" -gt 0 ]]; then
  echo "WARNING: $FAILED of $((COUNT + FAILED)) delete(s) failed — check errors above"
fi
echo "Cleared $COUNT AC assignment(s) from $TABLE_NAME"
