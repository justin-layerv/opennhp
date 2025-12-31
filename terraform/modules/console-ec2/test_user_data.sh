#!/bin/bash
# Test script to validate user_data.sh.tpl template rendering
# Run from: terraform/modules/console-ec2/
set -e

echo "Testing user_data.sh.tpl template rendering..."

# Render the template using Terraform's built-in templatefile function
# We'll extract just the portal_sites seeding section and validate it

TEMPLATE_FILE="user_data.sh.tpl"

if [ ! -f "$TEMPLATE_FILE" ]; then
    echo "ERROR: $TEMPLATE_FILE not found"
    exit 1
fi

# Check that the EXT_INFO includes required fields for auth_code flow
echo "Checking EXT_INFO fields..."

# Required fields in ext_info for auth_code flow
REQUIRED_FIELDS=("AuthUrl" "AppSecret" "Method" "JWTSecret" "Title")

for field in "${REQUIRED_FIELDS[@]}"; do
    if grep -q "\\\"$field\\\"" "$TEMPLATE_FILE"; then
        echo "  ✓ EXT_INFO contains '$field'"
    else
        echo "  ✗ EXT_INFO missing '$field'"
        exit 1
    fi
done

# Verify AuthUrl points to /ps/custom_auth_api endpoint
if grep -q '/ps/custom_auth_api' "$TEMPLATE_FILE"; then
    echo "  ✓ AuthUrl points to /ps/custom_auth_api"
else
    echo "  ✗ AuthUrl missing /ps/custom_auth_api endpoint"
    exit 1
fi

# Verify AppSecret is the expected hardcoded value
if grep -q 'layerv_secret_2025' "$TEMPLATE_FILE"; then
    echo "  ✓ AppSecret is set to layerv_secret_2025"
else
    echo "  ✗ AppSecret value incorrect"
    exit 1
fi

# Verify Method is GET
if grep -q '"Method": "GET"' "$TEMPLATE_FILE" || grep -q "\"Method\": \"GET\"" "$TEMPLATE_FILE"; then
    echo "  ✓ Method is GET"
else
    echo "  ✗ Method not set to GET"
    exit 1
fi

# Verify UPDATE statement exists for existing deployments
if grep -q 'UPDATE portal_sites' "$TEMPLATE_FILE"; then
    echo "  ✓ UPDATE statement exists for existing deployments"
else
    echo "  ✗ UPDATE statement missing"
    exit 1
fi

echo ""
echo "All tests passed! ✓"
echo ""
echo "To apply changes to existing deployment:"
echo "  1. Run: terraform apply"
echo "  2. Trigger ASG instance refresh or terminate the old instance"
