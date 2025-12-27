#!/bin/bash
#
# Generate TLS certificates for etcd and store in AWS Secrets Manager
#
# Usage:
#   ./scripts/generate-etcd-certs.sh sandbox
#   ./scripts/generate-etcd-certs.sh prod
#
# Prerequisites:
#   - AWS CLI configured with appropriate permissions
#   - openssl installed
#
# This script generates:
#   - CA certificate (valid 10 years)
#   - Server certificate (valid 1 year)
#   - Stores them in Secrets Manager as JSON

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
ENVIRONMENT="${1:-}"
if [[ -z "$ENVIRONMENT" ]]; then
    echo -e "${RED}Error: Environment required${NC}"
    echo "Usage: $0 <sandbox|prod>"
    exit 1
fi

if [[ "$ENVIRONMENT" != "sandbox" && "$ENVIRONMENT" != "prod" ]]; then
    echo -e "${RED}Error: Environment must be 'sandbox' or 'prod'${NC}"
    exit 1
fi

# AWS Configuration
AWS_REGION="${AWS_REGION:-us-east-2}"
SECRET_NAME="layerv-nhp-${ENVIRONMENT}-etcd-tls"

# Certificate configuration
CA_DAYS=3650        # 10 years
SERVER_DAYS=365     # 1 year
KEY_SIZE=2048

# DNS names for the certificate
DNS_NAMES=(
    "localhost"
    "etcd.nhp.${ENVIRONMENT}.internal"
    "etcd-0.nhp.${ENVIRONMENT}.internal"
    "etcd-1.nhp.${ENVIRONMENT}.internal"
    "etcd-2.nhp.${ENVIRONMENT}.internal"
)

# Create temp directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo -e "${GREEN}Generating etcd TLS certificates for ${ENVIRONMENT}${NC}"
echo "Temp directory: $TEMP_DIR"

# Generate CA private key
echo -e "${YELLOW}Generating CA private key...${NC}"
openssl genrsa -out "$TEMP_DIR/ca.key" $KEY_SIZE 2>/dev/null

# Generate CA certificate
echo -e "${YELLOW}Generating CA certificate (valid ${CA_DAYS} days)...${NC}"
openssl req -x509 -new -nodes \
    -key "$TEMP_DIR/ca.key" \
    -sha256 \
    -days $CA_DAYS \
    -out "$TEMP_DIR/ca.crt" \
    -subj "/CN=etcd-ca/O=LayerV"

# Generate server private key
echo -e "${YELLOW}Generating server private key...${NC}"
openssl genrsa -out "$TEMP_DIR/server.key" $KEY_SIZE 2>/dev/null

# Create SAN config
echo -e "${YELLOW}Creating certificate config with SANs...${NC}"
cat > "$TEMP_DIR/server.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = etcd-server
O = LayerV

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
EOF

# Add DNS names to config
i=1
for dns in "${DNS_NAMES[@]}"; do
    echo "DNS.$i = $dns" >> "$TEMP_DIR/server.cnf"
    ((i++))
done

# Add localhost IP
echo "IP.1 = 127.0.0.1" >> "$TEMP_DIR/server.cnf"

# Generate server CSR
echo -e "${YELLOW}Generating server certificate signing request...${NC}"
openssl req -new \
    -key "$TEMP_DIR/server.key" \
    -out "$TEMP_DIR/server.csr" \
    -config "$TEMP_DIR/server.cnf"

# Sign server certificate with CA
echo -e "${YELLOW}Signing server certificate (valid ${SERVER_DAYS} days)...${NC}"
openssl x509 -req \
    -in "$TEMP_DIR/server.csr" \
    -CA "$TEMP_DIR/ca.crt" \
    -CAkey "$TEMP_DIR/ca.key" \
    -CAcreateserial \
    -out "$TEMP_DIR/server.crt" \
    -days $SERVER_DAYS \
    -sha256 \
    -extensions v3_req \
    -extfile "$TEMP_DIR/server.cnf"

# Verify certificates
echo -e "${YELLOW}Verifying certificates...${NC}"
openssl verify -CAfile "$TEMP_DIR/ca.crt" "$TEMP_DIR/server.crt"

# Display certificate info
echo -e "${GREEN}Certificate details:${NC}"
openssl x509 -in "$TEMP_DIR/server.crt" -noout -subject -issuer -dates
echo ""
echo "Subject Alternative Names:"
openssl x509 -in "$TEMP_DIR/server.crt" -noout -ext subjectAltName

# Create JSON payload for Secrets Manager
echo -e "${YELLOW}Creating Secrets Manager payload...${NC}"
CA_CERT=$(cat "$TEMP_DIR/ca.crt")
SERVER_CERT=$(cat "$TEMP_DIR/server.crt")
SERVER_KEY=$(cat "$TEMP_DIR/server.key")

# Use jq if available, otherwise use python
if command -v jq &> /dev/null; then
    jq -n \
        --arg ca "$CA_CERT" \
        --arg cert "$SERVER_CERT" \
        --arg key "$SERVER_KEY" \
        '{caCert: $ca, serverCert: $cert, serverKey: $key}' > "$TEMP_DIR/secret.json"
else
    python3 -c "
import json
ca = '''$CA_CERT'''
cert = '''$SERVER_CERT'''
key = '''$SERVER_KEY'''
print(json.dumps({'caCert': ca, 'serverCert': cert, 'serverKey': key}))
" > "$TEMP_DIR/secret.json"
fi

# Check if secret exists
echo -e "${YELLOW}Checking if secret exists in AWS...${NC}"
if aws secretsmanager describe-secret --secret-id "$SECRET_NAME" --region "$AWS_REGION" &>/dev/null; then
    echo -e "${YELLOW}Secret exists, updating...${NC}"
    aws secretsmanager put-secret-value \
        --secret-id "$SECRET_NAME" \
        --secret-string file://"$TEMP_DIR/secret.json" \
        --region "$AWS_REGION"
    echo -e "${GREEN}Secret updated successfully!${NC}"
else
    echo -e "${RED}Secret does not exist: $SECRET_NAME${NC}"
    echo "Please run terraform apply first to create the secret, then re-run this script."
    exit 1
fi

# Summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}TLS Certificates Generated Successfully${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Secret Name: $SECRET_NAME"
echo "Region: $AWS_REGION"
echo ""
echo "CA Certificate:"
echo "  - Valid for: $CA_DAYS days ($(date -d "+$CA_DAYS days" +%Y-%m-%d 2>/dev/null || date -v+${CA_DAYS}d +%Y-%m-%d))"
echo ""
echo "Server Certificate:"
echo "  - Valid for: $SERVER_DAYS days ($(date -d "+$SERVER_DAYS days" +%Y-%m-%d 2>/dev/null || date -v+${SERVER_DAYS}d +%Y-%m-%d))"
echo "  - DNS Names: ${DNS_NAMES[*]}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Force a new ECS deployment to pick up the new certificates:"
echo "   aws ecs update-service --cluster layerv-nhp-${ENVIRONMENT}-etcd \\"
echo "     --service layerv-nhp-${ENVIRONMENT}-etcd-0 --force-new-deployment \\"
echo "     --region $AWS_REGION"
echo ""
echo "2. Refresh ASG instances to pick up the CA certificate:"
echo "   aws autoscaling start-instance-refresh \\"
echo "     --auto-scaling-group-name layerv-nhp-${ENVIRONMENT}-ac --region $AWS_REGION"
echo "   aws autoscaling start-instance-refresh \\"
echo "     --auto-scaling-group-name layerv-nhp-${ENVIRONMENT}-server --region $AWS_REGION"
