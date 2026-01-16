#!/bin/bash
# generate-console-ac-license.sh
# Generates a license key for Console AC and stores it securely.
#
# This script:
# 1. Generates a random 32-character license key
# 2. Computes bcrypt hash of the key
# 3. Stores plaintext key in AWS Secrets Manager
# 4. Outputs the hash for use in Terraform variables
#
# Prerequisites:
#   - AWS CLI configured with appropriate profile
#   - Python 3 with bcrypt package (pip install bcrypt)
#
# Usage:
#   ./generate-console-ac-license.sh <environment>
#
# Example:
#   AWS_PROFILE=layerv ./generate-console-ac-license.sh sandbox
#
# After running, add the output hash to your terraform.tfvars:
#   console_ac_license_key_hash = "<hash from output>"

set -euo pipefail

ENVIRONMENT="${1:-sandbox}"
AWS_REGION="${AWS_REGION:-us-east-2}"
SECRET_NAME="layerv-nhp-${ENVIRONMENT}/console-ac-license-key"

echo "=== Console AC License Key Generator ==="
echo "Environment: $ENVIRONMENT"
echo "Region: $AWS_REGION"
echo "Secret name: $SECRET_NAME"
echo ""

# Check for Python and bcrypt
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is required but not installed."
    exit 1
fi

if ! python3 -c "import bcrypt" &> /dev/null; then
    echo "Error: Python bcrypt package is required."
    echo "Install with: pip install bcrypt"
    exit 1
fi

# Check if secret already exists
EXISTING_SECRET=$(aws secretsmanager describe-secret --secret-id "$SECRET_NAME" --region "$AWS_REGION" 2>/dev/null || echo "")

if [ -n "$EXISTING_SECRET" ]; then
    echo "Warning: Secret '$SECRET_NAME' already exists."
    read -p "Do you want to rotate it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted. Existing secret unchanged."
        echo ""
        echo "To retrieve the existing hash, run:"
        echo "  aws secretsmanager get-secret-value --secret-id $SECRET_NAME --region $AWS_REGION --query 'SecretString' --output text | jq -r '.hash'"
        exit 0
    fi
fi

# Generate random 32-character license key (alphanumeric)
LICENSE_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(24)[:32])")

# Generate bcrypt hash (cost factor 10)
# Uses stdin to avoid exposing key in process arguments (visible via ps aux)
LICENSE_HASH=$(echo -n "$LICENSE_KEY" | python3 -c "
import sys
import bcrypt
key = sys.stdin.read().encode()
salt = bcrypt.gensalt(rounds=10)
hash = bcrypt.hashpw(key, salt)
print(hash.decode())
")

echo "Generated license key: ${LICENSE_KEY:0:8}... (truncated for security)"
echo "Generated bcrypt hash: ${LICENSE_HASH:0:20}..."
echo ""

# Store in Secrets Manager (both key and hash for reference)
SECRET_VALUE=$(cat <<EOF
{
  "key": "$LICENSE_KEY",
  "hash": "$LICENSE_HASH"
}
EOF
)

if [ -n "$EXISTING_SECRET" ]; then
    # Update existing secret
    aws secretsmanager put-secret-value \
        --secret-id "$SECRET_NAME" \
        --secret-string "$SECRET_VALUE" \
        --region "$AWS_REGION" > /dev/null
    echo "Updated secret in Secrets Manager: $SECRET_NAME"
else
    # Create new secret
    aws secretsmanager create-secret \
        --name "$SECRET_NAME" \
        --description "License key for Console AC in $ENVIRONMENT environment" \
        --secret-string "$SECRET_VALUE" \
        --region "$AWS_REGION" > /dev/null
    echo "Created secret in Secrets Manager: $SECRET_NAME"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Add this to your terraform.tfvars (or set as environment variable):"
echo ""
echo "  console_ac_license_key_hash = \"$LICENSE_HASH\""
echo ""
echo "Or export as TF_VAR:"
echo ""
echo "  export TF_VAR_console_ac_license_key_hash='$LICENSE_HASH'"
echo ""
echo "The Console AC will automatically read the license key from Secrets Manager at boot."
