#!/bin/bash
# Custom Domain Certificate Sync
# Fetches custom domain certs from SSM Parameter Store
# and rebuilds /home/ubuntu/traefik/custom-domains.toml
#
# Modes:
#   Full sync (default): Fetches ALL certs, rebuilds config, cleans stale dirs
#   Incremental (--domain <domain>): Fetches single domain cert, appends to config
#
# Triggered by:
# - Custom Domain Cert Lambda (after provisioning/renewal)
# - AC instance boot (user_data.sh)
# - 6-hourly SSM association
set -euo pipefail

SSM_CERT_PREFIX="${SSM_CERT_PREFIX:-/nhp/certs}"
TRAEFIK_DIR="${TRAEFIK_DIR:-/home/ubuntu/traefik}"
CERT_DIR="${TRAEFIK_DIR}/certs/custom-domains"
CONFIG_FILE="${TRAEFIK_DIR}/custom-domains.toml"
REGION="${AWS_REGION:-us-east-2}"

# Parse args
SYNC_MODE="full"
TARGET_DOMAIN=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --domain) TARGET_DOMAIN="$2"; SYNC_MODE="incremental"; shift 2 ;;
        *) shift ;;
    esac
done

echo "Starting custom domain certificate sync (mode: $SYNC_MODE) at $(date)"

# Ensure snap binaries are in PATH (for AWS CLI)
export PATH="/snap/bin:$PATH"

# Source shared helpers (retry, metrics)
source /home/ubuntu/scripts/lib.sh 2>/dev/null || true

# Clean up temp files on exit (TEMP_CONFIG set later in both incremental and full mode)
trap 'rm -f "$TEMP_CONFIG" 2>/dev/null' EXIT
TEMP_CONFIG=""

# Create directories
mkdir -p "$CERT_DIR"

# ==============================================================================
# Append a [[tls.certificates]] entry to a TOML config file
# Args: $1=domain_cert_dir $2=config_file
# ==============================================================================
append_tls_entry() {
    local DOMAIN_CERT_DIR="$1"
    local CONFIG="$2"
    cat >> "$CONFIG" << DOMAINEOF

[[tls.certificates]]
  certFile = "${DOMAIN_CERT_DIR}/fullchain.pem"
  keyFile = "${DOMAIN_CERT_DIR}/privkey.pem"
DOMAINEOF
}

# ==============================================================================
# Validate and write a single domain's cert to disk + TOML
# Args: $1=domain $2=key_value $3=chain_value
# Returns: 0 on success, 1 on failure
# ==============================================================================
process_domain_cert() {
    local DOMAIN="$1"
    local KEY_VALUE="$2"
    local CHAIN_VALUE="$3"

    # Validate domain is DNS-safe
    if ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$ ]]; then
        echo "WARNING: Invalid domain name format: $DOMAIN, skipping"
        return 1
    fi

    # Reject path traversal sequences
    if [[ "$DOMAIN" == *".."* ]]; then
        echo "WARNING: Invalid domain path (contains '..'): $DOMAIN, skipping"
        return 1
    fi

    # Reject wildcard domains
    if [[ "$DOMAIN" == *"*"* ]]; then
        echo "WARNING: Wildcard domains not supported: $DOMAIN, skipping"
        return 1
    fi

    echo "Processing certificate for: $DOMAIN"

    # Create domain cert directory
    local DOMAIN_CERT_DIR="$CERT_DIR/$DOMAIN"
    mkdir -p "$DOMAIN_CERT_DIR"

    # Write cert files
    echo "$CHAIN_VALUE" > "$DOMAIN_CERT_DIR/fullchain.pem"
    echo "$KEY_VALUE" > "$DOMAIN_CERT_DIR/privkey.pem"

    # Set permissions and ownership
    chmod 600 "$DOMAIN_CERT_DIR/privkey.pem"
    chmod 644 "$DOMAIN_CERT_DIR/fullchain.pem"
    chown ubuntu:ubuntu "$DOMAIN_CERT_DIR/privkey.pem" "$DOMAIN_CERT_DIR/fullchain.pem"

    # Verify cert is not expired and extract expiry date
    local CERT_INFO
    CERT_INFO=$(openssl x509 -in "$DOMAIN_CERT_DIR/fullchain.pem" -noout -checkend 0 -enddate 2>/dev/null) || {
        echo "WARNING: Certificate for $DOMAIN is expired or invalid, skipping"
        return 1
    }
    local CERT_EXPIRY
    CERT_EXPIRY=$(echo "$CERT_INFO" | grep '^notAfter=' | cut -d= -f2)

    # Verify private key matches certificate
    local CERT_MOD KEY_MOD
    CERT_MOD=$(openssl x509 -noout -modulus -in "$DOMAIN_CERT_DIR/fullchain.pem" 2>/dev/null) || {
        echo "WARNING: Cannot read certificate modulus for $DOMAIN, skipping"
        return 1
    }
    KEY_MOD=$(openssl rsa -noout -modulus -in "$DOMAIN_CERT_DIR/privkey.pem" 2>/dev/null) || {
        echo "WARNING: Cannot read private key modulus for $DOMAIN, skipping"
        return 1
    }
    if [ "$CERT_MOD" != "$KEY_MOD" ]; then
        echo "WARNING: Certificate/key mismatch for $DOMAIN, skipping"
        return 1
    fi

    echo "  Certificate loaded, expires: $CERT_EXPIRY"
    return 0
}

# ==============================================================================
# Fetch a single SSM parameter value (with decryption)
# Args: $1=parameter_name
# ==============================================================================
fetch_ssm_param() {
    aws ssm get-parameter \
        --region "$REGION" \
        --name "$1" \
        --with-decryption \
        --query 'Parameter.Value' --output text 2>/dev/null
}

# ==============================================================================
# Incremental mode: fetch single domain, append to config
# ==============================================================================
if [ "$SYNC_MODE" = "incremental" ] && [ -n "$TARGET_DOMAIN" ]; then
    echo "Incremental sync for domain: $TARGET_DOMAIN"

    # Fetch key and chain params for this domain
    KEY_VALUE=$(fetch_ssm_param "$SSM_CERT_PREFIX/$TARGET_DOMAIN/key") || {
        echo "ERROR: Failed to fetch key param for $TARGET_DOMAIN"
        exit 1
    }

    CHAIN_VALUE=$(fetch_ssm_param "$SSM_CERT_PREFIX/$TARGET_DOMAIN/chain") || {
        echo "ERROR: Failed to fetch chain param for $TARGET_DOMAIN"
        exit 1
    }

    # Guard against empty SSM parameter values (edge case)
    if [ -z "$KEY_VALUE" ] || [ -z "$CHAIN_VALUE" ]; then
        echo "ERROR: Empty cert data for $TARGET_DOMAIN"
        exit 1
    fi

    if process_domain_cert "$TARGET_DOMAIN" "$KEY_VALUE" "$CHAIN_VALUE"; then
        DOMAIN_CERT_DIR="$CERT_DIR/$TARGET_DOMAIN"

        # Append TLS cert entry to config (or create if missing)
        if [ ! -f "$CONFIG_FILE" ]; then
            echo "# Custom Domain Traefik Configuration" > "$CONFIG_FILE"
            echo "# Auto-generated by custom-domain-cert-sync.sh" >> "$CONFIG_FILE"
        fi

        # Remove existing entry for this domain if present, then append
        # Use a temp file to avoid partial writes
        TEMP_CONFIG=$(mktemp)

        # Remove the entire [[tls.certificates]] block for this domain
        # Assumes blocks are exactly 3 lines (header + certFile + keyFile)
        # as generated by append_tls_entry(). Also consumes preceding blank line.
        # Uses index() for exact path match (not regex) to avoid substring collisions
        awk -v dir="$DOMAIN_CERT_DIR" '
            /^\[\[tls\.certificates\]\]/ {
                header = $0; getline l1; getline l2
                if (index(l1, dir) || index(l2, dir)) next  # skip this block
                print header; print l1; print l2; next
            }
            /^$/ {
                blank = $0; if (getline > 0) {
                    if (/^\[\[tls\.certificates\]\]/) {
                        header = $0; getline l1; getline l2
                        if (index(l1, dir) || index(l2, dir)) next
                        print blank; print header; print l1; print l2; next
                    }
                    print blank; print; next
                }
                print blank; next
            }
            { print }
        ' "$CONFIG_FILE" > "$TEMP_CONFIG" 2>/dev/null || true

        append_tls_entry "$DOMAIN_CERT_DIR" "$TEMP_CONFIG"

        chmod 644 "$TEMP_CONFIG"
        chown ubuntu:ubuntu "$TEMP_CONFIG"
        mv "$TEMP_CONFIG" "$CONFIG_FILE"

        echo "Incremental sync complete for $TARGET_DOMAIN"
    else
        echo "ERROR: Failed to process cert for $TARGET_DOMAIN"
        exit 1
    fi

    exit 0
fi

# ==============================================================================
# Full mode: fetch all certs, rebuild config, clean stale dirs
# ==============================================================================
echo "Listing custom domain certificates from SSM..."

# Fetch all params under the cert prefix (key, chain, meta)
# get-parameters-by-path returns max 10 per page; the CLI handles pagination
ALL_PARAMS=$(aws ssm get-parameters-by-path \
    --region "$REGION" \
    --path "$SSM_CERT_PREFIX/" \
    --recursive \
    --with-decryption \
    --output json 2>/dev/null || echo '{"Parameters":[]}')

# Filter to /key and /chain params only, group by domain, extract cert data
# jq handles the filtering that JMESPath can't do reliably
DOMAINS_JSON=$(echo "$ALL_PARAMS" | jq '
    [.Parameters[] | select(.Name | (endswith("/key") or endswith("/chain")))]
    | group_by(.Name | split("/")[:-1] | join("/"))
    | map({
        domain: (.[0].Name | split("/") | .[-2]),
        key: (map(select(.Name | endswith("/key"))) | .[0].Value // ""),
        chain: (map(select(.Name | endswith("/chain"))) | .[0].Value // "")
      })
    | map(select(.key != "" and .chain != ""))
') || {
    echo "ERROR: Failed to parse SSM parameters with jq"
    exit 1
}

if [ "$(echo "$DOMAINS_JSON" | jq 'length')" = "0" ] || [ -z "$DOMAINS_JSON" ]; then
    echo "No custom domain certificates found"
    echo "# No custom domains configured" > "$CONFIG_FILE"
    chown ubuntu:ubuntu "$CONFIG_FILE"
    echo "Done"
    exit 0
fi

DOMAIN_COUNT_TOTAL=$(echo "$DOMAINS_JSON" | jq 'length')

# Start building new config
TEMP_CONFIG=$(mktemp)
echo "# Custom Domain Traefik Configuration" > "$TEMP_CONFIG"
echo "# Auto-generated by custom-domain-cert-sync.sh at $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$TEMP_CONFIG"
echo "# DO NOT EDIT MANUALLY" >> "$TEMP_CONFIG"
echo "" >> "$TEMP_CONFIG"

DOMAIN_COUNT=0
FAILED_COUNT=0
ACTIVE_DOMAINS=""

# Process each domain (per-element jq extraction required because PEM values are multi-line)
for i in $(seq 0 $((DOMAIN_COUNT_TOTAL - 1))); do
    DOMAIN=$(echo "$DOMAINS_JSON" | jq -r ".[$i].domain")
    KEY_VALUE=$(echo "$DOMAINS_JSON" | jq -r ".[$i].key")
    CHAIN_VALUE=$(echo "$DOMAINS_JSON" | jq -r ".[$i].chain")

    if process_domain_cert "$DOMAIN" "$KEY_VALUE" "$CHAIN_VALUE"; then
        DOMAIN_CERT_DIR="$CERT_DIR/$DOMAIN"

        # Append TLS cert entry only (catch-all router handles routing)
        append_tls_entry "$DOMAIN_CERT_DIR" "$TEMP_CONFIG"

        ACTIVE_DOMAINS="$ACTIVE_DOMAINS $DOMAIN"
        DOMAIN_COUNT=$((DOMAIN_COUNT + 1))
    else
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
done

# Remove stale cert directories for domains no longer in SSM
if [ -d "$CERT_DIR" ]; then
    for DIR in "$CERT_DIR"/*/; do
        [ -d "$DIR" ] || continue
        DIR_DOMAIN=$(basename "$DIR")
        if ! echo "$ACTIVE_DOMAINS" | grep -Fwq "$DIR_DOMAIN"; then
            echo "Removing stale cert directory for: $DIR_DOMAIN"
            rm -rf "$DIR"
        fi
    done
fi

# Set ownership and permissions before atomic replace so Traefik
# never sees incorrect ownership between mv and chown.
chmod 644 "$TEMP_CONFIG"
chown ubuntu:ubuntu "$TEMP_CONFIG"
if ! mv "$TEMP_CONFIG" "$CONFIG_FILE"; then
    echo "ERROR: Failed to update config file"
    exit 1
fi

echo ""
echo "============================================"
echo "Custom domain cert sync complete"
echo "  Domains loaded: $DOMAIN_COUNT"
echo "  Failures: $FAILED_COUNT"
echo "============================================"

# Publish sync metrics to CloudWatch for operational visibility
if declare -f publish_cw_metric &>/dev/null; then
  publish_cw_metric "CertSyncDomainsLoaded" "$DOMAIN_COUNT" "Count" "Component=AC"
  publish_cw_metric "CertSyncFailures" "$FAILED_COUNT" "Count" "Component=AC"
else
  aws cloudwatch put-metric-data \
    --namespace "LayerV/NHP" \
    --metric-data "[{\"MetricName\":\"CertSyncDomainsLoaded\",\"Value\":$DOMAIN_COUNT,\"Unit\":\"Count\",\"Dimensions\":[{\"Name\":\"Component\",\"Value\":\"AC\"}]},{\"MetricName\":\"CertSyncFailures\",\"Value\":$FAILED_COUNT,\"Unit\":\"Count\",\"Dimensions\":[{\"Name\":\"Component\",\"Value\":\"AC\"}]}]" \
    --region "$REGION" 2>&1 || echo "WARNING: Failed to publish CloudWatch metrics"
fi

# Traefik file provider is configured with watch=true in user_data.sh.tpl
# (providers.file.directory + watch = true), so it automatically picks up
# changes to custom-domains.toml. No restart needed.
