#!/usr/bin/env bash
# rotate-cookie-keys.sh — Rotate NHP server cookie session keys
#
# This script performs a graceful key rotation:
#   1. Reads the current secret from Secrets Manager
#   2. Moves "current" keys → "previous" (for read-only backward compat)
#   3. Generates new "current" keys via AWS secretsmanager:GetRandomPassword
#   4. Updates the secret with both current and previous key sets
#   5. Optionally triggers an ASG instance refresh
#
# During the rolling refresh:
#   - New instances write cookies with new keys
#   - New instances can still READ cookies signed with old keys
#   - Sessions are preserved until the previous keys are removed
#
# Usage:
#   AWS_PROFILE=layerv ./rotate-cookie-keys.sh <secret-id> [--refresh <asg-name>]
#
# Examples:
#   # Rotate keys only (manual instance refresh later)
#   AWS_PROFILE=layerv ./rotate-cookie-keys.sh layerv-nhp-sandbox-cookie-secret
#
#   # Rotate keys and trigger instance refresh
#   AWS_PROFILE=layerv ./rotate-cookie-keys.sh layerv-nhp-sandbox-cookie-secret --refresh nhp-sandbox-server
set -euo pipefail

SECRET_ID="${1:?Usage: rotate-cookie-keys.sh <secret-id> [--refresh <asg-name>]}"
REFRESH_FLAG="${2:-}"
ASG_NAME="${3:-}"

echo "=== Cookie Key Rotation ==="
echo "Secret: $SECRET_ID"

# 1. Read current secret
echo "Reading current secret..."
CURRENT_JSON=$(aws secretsmanager get-secret-value \
  --secret-id "$SECRET_ID" \
  --query SecretString --output text)

# Extract current keys to become previous
PREV_AUTH=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; print(json.loads(sys.stdin.read())['current']['auth_key'])")
PREV_ENCRYPT=$(echo "$CURRENT_JSON" | python3 -c "import json,sys; print(json.loads(sys.stdin.read())['current']['encrypt_key'])")

echo "Current auth_key prefix: ${PREV_AUTH:0:4}..."

# 2. Generate new keys
echo "Generating new keys via AWS..."
NEW_AUTH=$(aws secretsmanager get-random-password \
  --password-length 32 --exclude-punctuation \
  --query RandomPassword --output text)
NEW_ENCRYPT=$(aws secretsmanager get-random-password \
  --password-length 32 --exclude-punctuation \
  --query RandomPassword --output text)

echo "New auth_key prefix: ${NEW_AUTH:0:4}..."

# 3. Build new secret JSON with current + previous
NEW_JSON=$(python3 -c "
import json
print(json.dumps({
    'current': {
        'auth_key': '$NEW_AUTH',
        'encrypt_key': '$NEW_ENCRYPT'
    },
    'previous': {
        'auth_key': '$PREV_AUTH',
        'encrypt_key': '$PREV_ENCRYPT'
    }
}, separators=(',', ':')))")

# 4. Update secret
echo "Updating secret..."
aws secretsmanager put-secret-value \
  --secret-id "$SECRET_ID" \
  --secret-string "$NEW_JSON"

echo "Secret updated successfully."
echo "  current.auth_key:  ${NEW_AUTH:0:4}..."
echo "  previous.auth_key: ${PREV_AUTH:0:4}..."

# 5. Optionally trigger instance refresh
if [ "$REFRESH_FLAG" = "--refresh" ] && [ -n "$ASG_NAME" ]; then
  echo ""
  echo "Triggering instance refresh for ASG: $ASG_NAME"
  REFRESH_ID=$(aws autoscaling start-instance-refresh \
    --auto-scaling-group-name "$ASG_NAME" \
    --query 'InstanceRefreshId' --output text)
  echo "Instance refresh started: $REFRESH_ID"
  echo "Monitor with: aws autoscaling describe-instance-refreshes --auto-scaling-group-name $ASG_NAME"
else
  echo ""
  echo "No instance refresh triggered. To apply the new keys:"
  echo "  aws autoscaling start-instance-refresh --auto-scaling-group-name <asg-name>"
fi

echo ""
echo "After all instances are refreshed, you can optionally remove the previous keys:"
echo "  aws secretsmanager put-secret-value --secret-id $SECRET_ID \\"
echo "    --secret-string '{\"current\":{\"auth_key\":\"...\",\"encrypt_key\":\"...\"}}'"
