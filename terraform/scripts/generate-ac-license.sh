#!/bin/bash
# generate-ac-license.sh
# Generates a license key for standalone AC and stores it securely.
#
# This script:
# 1. Generates a random 32-character license key
# 2. Computes bcrypt hash of the key (for validation)
# 3. Computes SHA256 hash of the key (for DynamoDB lookup)
# 4. Stores plaintext key in AWS Secrets Manager
# 5. Outputs all values for use in Terraform variables
#
# Prerequisites:
#   - AWS CLI configured with appropriate profile
#   - Python 3 with bcrypt package (pip install bcrypt)
#
# Usage:
#   ./generate-ac-license.sh <environment> [customer_id]
#
# Example:
#   AWS_PROFILE=layerv ./generate-ac-license.sh sandbox
#   AWS_PROFILE=layerv ./generate-ac-license.sh sandbox 01HXYZ1234567890ABCDEFGHIJ
#
# After running, add the output values to your terraform.tfvars:
#   ac_customer_id        = "<customer_id from output>"
#   ac_license_key        = "<license_key from output>"
#   ac_license_key_hash   = "<bcrypt_hash from output>"
#   ac_license_key_sha256 = "<sha256_hash from output>"

set -euo pipefail

ENVIRONMENT="${1:-sandbox}"
# Default to nil ULID for LayerV system customer (26 zeros in Crockford base32)
CUSTOMER_ID="${2:-00000000000000000000000000}"
AWS_REGION="${AWS_REGION:-us-east-2}"
SECRET_NAME="layerv-nhp-${ENVIRONMENT}/ac-license-key"

echo "=== Standalone AC License Key Generator ==="
echo "Environment: $ENVIRONMENT"
echo "Customer ID: $CUSTOMER_ID"
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
        echo "To retrieve the existing values, run:"
        echo "  aws secretsmanager get-secret-value --secret-id $SECRET_NAME --region $AWS_REGION --query 'SecretString' --output text | jq"
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

# Generate SHA256 hash (for DynamoDB lookup)
LICENSE_SHA256=$(echo -n "$LICENSE_KEY" | sha256sum | cut -d' ' -f1)

echo "Generated license key: ${LICENSE_KEY:0:8}... (truncated for security)"
echo "Generated bcrypt hash: ${LICENSE_HASH:0:20}..."
echo "Generated SHA256 hash: ${LICENSE_SHA256:0:16}..."
echo ""

# Store in Secrets Manager (key, hashes, and customer_id for reference)
SECRET_VALUE=$(cat <<EOF
{
  "key": "$LICENSE_KEY",
  "hash": "$LICENSE_HASH",
  "sha256": "$LICENSE_SHA256",
  "customer_id": "$CUSTOMER_ID"
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
        --description "License key for standalone AC in $ENVIRONMENT environment" \
        --secret-string "$SECRET_VALUE" \
        --region "$AWS_REGION" > /dev/null
    echo "Created secret in Secrets Manager: $SECRET_NAME"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Add these to your terraform.tfvars (or set as environment variables):"
echo ""
echo "  ac_customer_id        = \"$CUSTOMER_ID\""
echo "  ac_license_key        = \"$LICENSE_KEY\""
echo "  ac_license_key_hash   = \"$LICENSE_HASH\""
echo "  ac_license_key_sha256 = \"$LICENSE_SHA256\""
echo ""
echo "Or export as TF_VARs:"
echo ""
echo "  export TF_VAR_ac_customer_id='$CUSTOMER_ID'"
echo "  export TF_VAR_ac_license_key='$LICENSE_KEY'"
echo "  export TF_VAR_ac_license_key_hash='$LICENSE_HASH'"
echo "  export TF_VAR_ac_license_key_sha256='$LICENSE_SHA256'"
echo ""
echo "The standalone AC will read the license key from terraform.tfvars at deploy time."
echo "The key is also stored in Secrets Manager for reference: $SECRET_NAME"
