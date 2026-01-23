#!/bin/bash
# Console EC2 User Data Script - Management plane with embedded AC
#
# This template configures the Console application server AND an embedded AC.
# For standalone customer ACs, see: terraform/modules/ac/user_data.sh.tpl
#
# The embedded AC portion (config.toml, firewall rules) shares patterns with
# the standalone AC template. When updating AC config structure, review both
# templates to keep them in sync.
set -ex

exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
echo "Starting Console EC2 installation at $(date)"
echo "Mode: ${internal_only ? "INTERNAL (behind AC/NHP)" : "EXTERNAL (public)"}"

export DEBIAN_FRONTEND=noninteractive

# Retry apt-get commands with exponential backoff (Ubuntu runs unattended-upgrades on boot which holds locks)
apt_get_with_retry() {
    local max_attempts=10
    local delay=2
    local max_delay=60
    local attempt=1
    while true; do
        if apt-get "$@"; then
            return 0
        fi
        if [ $attempt -ge $max_attempts ]; then
            echo "ERROR: apt-get $* failed after $max_attempts attempts"
            return 1
        fi
        echo "apt-get $* failed (attempt $attempt/$max_attempts), retrying in $${delay}s..."
        sleep $delay
        attempt=$((attempt + 1))
        delay=$((delay * 2))
        if [ $delay -gt $max_delay ]; then
            delay=$max_delay
        fi
    done
}

apt_get_with_retry update -y

%{ if internal_only }
# Internal mode: minimal packages (no TLS/certbot needed)
apt_get_with_retry install -y nginx docker.io curl jq unzip dnsutils
%{ else }
# External mode: full packages including certbot for TLS
apt_get_with_retry install -y nginx certbot python3-certbot-nginx python3-certbot-dns-route53 docker.io curl jq unzip dnsutils
%{ endif }

# Install AWS CLI v2
if ! command -v aws &> /dev/null; then
  echo "Installing AWS CLI v2..."
  curl -sL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
  unzip -q /tmp/awscliv2.zip -d /tmp
  /tmp/aws/install
  rm -rf /tmp/aws /tmp/awscliv2.zip
fi
aws --version

# Start Docker
systemctl enable docker
systemctl start docker

# Wait for Docker to be ready
for i in {1..30}; do docker info && break || sleep 2; done

# ============================================================================
# Get RDS Credentials from Secrets Manager
# ============================================================================

echo "Fetching RDS credentials from Secrets Manager..."
REGION="${region}"
RDS_SECRET=$(aws secretsmanager get-secret-value --secret-id "${rds_secret_arn}" --region "$REGION" --query SecretString --output text)
RDS_USERNAME=$(echo "$RDS_SECRET" | jq -r '.username')
RDS_PASSWORD=$(echo "$RDS_SECRET" | jq -r '.password')

echo "RDS credentials retrieved"

# ============================================================================
# NHP Protection: Install nhp-acd and Configure iptables (always enabled)
# This provides true network-level hiding - port 443 is DROP'd by default
# and only opened after successful NHP knock adds user IP to ipset.
# ============================================================================

echo "Setting up NHP Protection (true network-level hiding)..."

# Install iptables and ipset for firewall rules
apt_get_with_retry install -y iptables ipset python3-cryptography

# ============================================================================
# NHP Firewall Setup - ipset and iptables rules for zero-trust access control
# ============================================================================
#
# SECURITY MODEL: FAIL-CLOSED (Deny by Default)
# ==============================================
# This firewall implements a "fail-closed" security posture:
#
# 1. Port 443 is DROP'd by default via iptables
# 2. Only IPs in the 'defaultset' ipset can access port 443
# 3. IPs are added to 'defaultset' only after successful NHP knock
# 4. ipset entries have 120-second timeout and require re-knock
#
# FAILURE MODES:
# - If nhp-acd daemon fails: No one can access port 443 (secure)
# - If NHP Server is unreachable: No new knocks succeed (secure)
# - If Console crashes: Existing ipset entries still work until timeout
#
# This ensures unauthorized access is impossible even if NHP components fail.
# ============================================================================
echo "Setting up NHP firewall with ipset and iptables..."

# Get instance metadata
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
LOCAL_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4 || echo "")

echo "Instance ID: $INSTANCE_ID"
echo "Local IP: $LOCAL_IP"
echo "Public IP: $PUBLIC_IP"

# Validate required metadata
if [ -z "$INSTANCE_ID" ]; then
    echo "ERROR: Failed to fetch INSTANCE_ID from IMDS"
    exit 1
fi
if [ -z "$LOCAL_IP" ]; then
    echo "ERROR: Failed to fetch LOCAL_IP from IMDS"
    exit 1
fi

# Create ipsets for NHP traffic control
# - defaultset: active sessions after successful knock (120s timeout)
# - tempset: temporary entries for initial knock (5s timeout)
ipset -exist create defaultset hash:ip,port,ip counters maxelem 1000000 timeout 120
ipset -exist create defaultset_down hash:ip,port,ip counters maxelem 1000000 timeout 121
ipset -exist create tempset hash:net,port counters maxelem 1000000 timeout 5

echo "ipsets created successfully"

# Create NHP_DENY chain for logging and dropping unauthorized traffic
iptables -N NHP_DENY 2>/dev/null || true
iptables -F NHP_DENY
iptables -A NHP_DENY -j LOG --log-prefix "[NHP-DENY] " --log-level 6 --log-ip-options
iptables -A NHP_DENY -j DROP

# Clear existing rules to avoid duplicates
iptables -F INPUT

# Setup INPUT chain rules
echo "Configuring INPUT chain..."

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow SSH from VPC (for management/debugging)
iptables -A INPUT -p tcp -s "${vpc_cidr}" --dport 22 -j ACCEPT

# Allow Console port from VPC (for internal NLB traffic from AC)
iptables -A INPUT -p tcp -s "${vpc_cidr}" --dport ${console_port} -j ACCEPT

# Allow NHP knock port from VPC (NHP Server sends knocks here)
iptables -A INPUT -p udp -s "${vpc_cidr}" --dport 62206 -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# ipset rules: tempset -> defaultset promotion, then accept
iptables -A INPUT -m set --match-set tempset src,dst -j SET --add-set defaultset src,dst,dst
iptables -A INPUT -m set --match-set defaultset src,dst,dst -j SET --add-set defaultset_down src,dst,dst
iptables -A INPUT -m set --match-set defaultset src,dst,dst -j LOG --log-prefix "[NHP-ACCEPT] " --log-level 6 --log-ip-options
iptables -A INPUT -m set --match-set defaultset src,dst,dst -j ACCEPT
iptables -A INPUT -m set --match-set tempset src,dst -j ACCEPT

# Port 443 (protected) - DROP unless in ipset (handled by NHP_DENY)
# Traffic must pass ipset check above to reach port 443
iptables -A INPUT -p tcp --dport 443 -j NHP_DENY

# Default policy
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

echo "NHP firewall setup complete - port 443 is DROP'd by default"

# ============================================================================
# rsyslog configuration for NHP logging
# ============================================================================
echo "Configuring rsyslog for NHP logging..."

mkdir -p /opt/layerv/nhp-ac/logs
chmod 755 /opt/layerv/nhp-ac/logs

if [ -d /etc/rsyslog.d ]; then
    cat > /etc/rsyslog.d/10-nhplog.conf << RSYSLOGEOF
# NHP Firewall Logging Configuration
template(name="NHPFormat" type="string" string="%timegenerated:8:19% $LOCAL_IP %syslogtag% %msg:::drop-last-lf%\n")
template(name="NHPAcceptFile" type="string" string="/opt/layerv/nhp-ac/logs/nhp_accept-%\$YEAR%-%\$MONTH%-%\$DAY%.log")
template(name="NHPDenyFile" type="string" string="/opt/layerv/nhp-ac/logs/nhp_deny-%\$YEAR%-%\$MONTH%-%\$DAY%.log")

:msg,contains,"[NHP-ACCEPT]" ?NHPAcceptFile;NHPFormat
& stop
:msg,contains,"[NHP-DENY]" ?NHPDenyFile;NHPFormat
& stop
RSYSLOGEOF

    systemctl restart rsyslog || true
    echo "rsyslog configured for NHP logging"
fi

# ============================================================================
# Fetch NHP Server Public Key and Generate Console AC Keypair
# ============================================================================

echo "Fetching NHP Server public key from Secrets Manager..."
SERVER_SECRET=$(aws secretsmanager get-secret-value --secret-id "${nhp_server_secret_arn}" --region "$REGION" --query SecretString --output text)
SERVER_PUBLIC_KEY=$(echo "$SERVER_SECRET" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('publicKey', d.get('PubKeyBase64', '')))" 2>/dev/null || echo "")
if [ -z "$SERVER_PUBLIC_KEY" ]; then
  echo "FATAL: Could not extract server public key from secret"
  echo "NHP protection requires the server public key for ECDH handshake"
  exit 1
fi
echo "Server public key retrieved: $${SERVER_PUBLIC_KEY:0:20}..."

# Fetch Console AC license key from Secrets Manager (if configured)
%{ if nhp_console_ac_license_secret_arn != null ~}
echo "Fetching Console AC license key from Secrets Manager..."
LICENSE_SECRET=$(aws secretsmanager get-secret-value --secret-id "${nhp_console_ac_license_secret_arn}" --region "$REGION" --query SecretString --output text)
CONSOLE_AC_LICENSE_KEY=$(echo "$LICENSE_SECRET" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])" 2>/dev/null || echo "")
if [ -z "$CONSOLE_AC_LICENSE_KEY" ]; then
  echo "WARNING: Could not extract license key from secret, continuing without license key"
  CONSOLE_AC_LICENSE_KEY=""
else
  echo "License key retrieved successfully"
fi
%{ else ~}
CONSOLE_AC_LICENSE_KEY=""
echo "WARNING: No license secret ARN configured, Console AC will use empty license key"
%{ endif ~}

# Generate Curve25519 keypair for Console AC
echo "Generating Curve25519 keypair for Console AC..."

# Static secret name - shared across instance replacements for stable AC identity
CONSOLE_AC_SECRET_NAME="${name_prefix}-console-ac"

# Check for existing keypair
EXISTING_SECRET=$(aws secretsmanager get-secret-value --secret-id "$CONSOLE_AC_SECRET_NAME" --region "$REGION" --query SecretString --output text 2>/dev/null || echo "")

if [ -n "$EXISTING_SECRET" ]; then
  echo "Found existing Console AC keypair (shared across instances)"
  # Support both snake_case (new) and camelCase (legacy) secret formats
  PRIVATE_KEY=$(echo "$EXISTING_SECRET" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('private_key', d.get('privateKey', '')))")
  PUBLIC_KEY=$(echo "$EXISTING_SECRET" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('public_key', d.get('publicKey', '')))")
  # Validate extracted keys
  if [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ]; then
    echo "FATAL: Could not extract keys from existing secret (missing private_key or public_key)"
    echo "Secret content may be corrupted. Check: $CONSOLE_AC_SECRET_NAME"
    exit 1
  fi
else
  echo "Generating new Curve25519 keypair..."

  KEYPAIR=$(python3 << 'KEYGEN_EOF'
import json
import base64
import sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

# Generate new X25519 keypair
private_key = X25519PrivateKey.generate()

# Get raw bytes
private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)
public_bytes = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

# Validate key lengths (X25519 keys are always 32 bytes)
if len(private_bytes) != 32 or len(public_bytes) != 32:
    print(json.dumps({"error": f"Invalid key lengths: private={len(private_bytes)}, public={len(public_bytes)}"}), file=sys.stderr)
    sys.exit(1)

# Encode as base64 (snake_case keys for consistency with AWS conventions)
result = {
    'private_key': base64.b64encode(private_bytes).decode(),
    'public_key': base64.b64encode(public_bytes).decode()
}

print(json.dumps(result))
KEYGEN_EOF
)

  # Validate keypair generation succeeded
  if [ -z "$KEYPAIR" ]; then
    echo "FATAL: Keypair generation produced no output"
    exit 1
  fi

  if ! echo "$KEYPAIR" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'private_key' in d and 'public_key' in d" 2>/dev/null; then
    echo "FATAL: Keypair generation failed - missing keys"
    echo "$KEYPAIR"
    exit 1
  fi

  PRIVATE_KEY=$(echo "$KEYPAIR" | python3 -c "import sys,json; print(json.load(sys.stdin)['private_key'])")
  PUBLIC_KEY=$(echo "$KEYPAIR" | python3 -c "import sys,json; print(json.load(sys.stdin)['public_key'])")

  # Store keypair in Secrets Manager (shared across instance replacements)
  # Using snake_case keys for consistency with AWS conventions
  SECRET_VALUE=$(cat << SECRETEOF
{
  "private_key": "$PRIVATE_KEY",
  "public_key": "$PUBLIC_KEY",
  "ac_id": "console-ac",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
SECRETEOF
)

  KMS_ARG=""
%{ if secrets_kms_key_arn != "" ~}
  KMS_ARG="--kms-key-id ${secrets_kms_key_arn}"
%{ endif ~}
  if aws secretsmanager create-secret \
    --name "$CONSOLE_AC_SECRET_NAME" \
    --secret-string "$SECRET_VALUE" \
    $KMS_ARG \
    --tags "Key=Environment,Value=${internal_only ? "internal" : "external"}" "Key=Component,Value=console-ac" \
    --region "$REGION" 2>/dev/null; then
    echo "Created new secret: $CONSOLE_AC_SECRET_NAME"
  else
    # Secret creation failed - likely race condition with another instance, or IAM/KMS issue
    echo "Secret creation failed, attempting to fetch existing keypair..."
    EXISTING_SECRET=$(aws secretsmanager get-secret-value --secret-id "$CONSOLE_AC_SECRET_NAME" --region "$REGION" --query SecretString --output text) || {
      echo "FATAL: Could not create or fetch Console AC secret. Check IAM permissions and KMS key access."
      exit 1
    }
    # Support both snake_case (new) and camelCase (legacy) secret formats
    PRIVATE_KEY=$(echo "$EXISTING_SECRET" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('private_key', d.get('privateKey', '')))")
    PUBLIC_KEY=$(echo "$EXISTING_SECRET" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('public_key', d.get('publicKey', '')))")
    # Validate extracted keys
    if [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ]; then
      echo "FATAL: Could not extract keys from fetched secret (missing private_key or public_key)"
      echo "Secret content may be corrupted. Check: $CONSOLE_AC_SECRET_NAME"
      exit 1
    fi
    echo "Using existing keypair from secret: $CONSOLE_AC_SECRET_NAME"
  fi
fi

echo "Console AC keypair ready (public key: $${PUBLIC_KEY:0:20}...)"

# Console AC ID - used for both etcd registration and portal_sites config
# Static ID ensures resource records remain valid across instance replacements
CONSOLE_AC_ID="console-ac"
export CONSOLE_AC_ID

# ============================================================================
# Fetch etcd TLS Certificates for AC Registration
# ============================================================================

%{ if etcd_endpoint != null && etcd_tls_secret_arn != null ~}
echo "Fetching etcd TLS certificates for Console AC registration..."
mkdir -p /opt/layerv/nhp-ac/etc/tls

ETCD_TLS_SECRET=$(aws secretsmanager get-secret-value \
  --secret-id "${etcd_tls_secret_arn}" \
  --region "$REGION" \
  --query SecretString --output text)

# Extract CA certificate
echo "$ETCD_TLS_SECRET" | python3 -c "import sys,json; print(json.load(sys.stdin)['caCert'])" \
  > /opt/layerv/nhp-ac/etc/tls/ca.crt
chmod 644 /opt/layerv/nhp-ac/etc/tls/ca.crt

# Extract client certificate and key for mTLS
echo "$ETCD_TLS_SECRET" | python3 -c "import sys,json; print(json.load(sys.stdin)['clientCert'])" \
  > /opt/layerv/nhp-ac/etc/tls/client.crt
chmod 644 /opt/layerv/nhp-ac/etc/tls/client.crt

echo "$ETCD_TLS_SECRET" | python3 -c "import sys,json; print(json.load(sys.stdin)['clientKey'])" \
  > /opt/layerv/nhp-ac/etc/tls/client.key
chmod 600 /opt/layerv/nhp-ac/etc/tls/client.key

echo "etcd TLS certificates installed for Console AC"

# ============================================================================
# Register Console AC in etcd
# Server watches /nhp/ac-registry/* and trusts ACs listed there
# ============================================================================

echo "Registering Console AC in etcd..."

# CONSOLE_AC_ID was defined above (before etcd block)

# Wait for etcd DNS
ETCD_HOST=$(echo "${etcd_endpoint}" | sed 's|https://||' | sed 's|:.*||')
MAX_DNS_ATTEMPTS=30
DNS_ATTEMPT=1
while [ $DNS_ATTEMPT -le $MAX_DNS_ATTEMPTS ]; do
  if getent hosts "$ETCD_HOST" > /dev/null 2>&1; then
    echo "etcd DNS resolved: $ETCD_HOST"
    break
  fi
  echo "Waiting for etcd DNS (attempt $DNS_ATTEMPT/$MAX_DNS_ATTEMPTS)..."
  sleep 10
  DNS_ATTEMPT=$((DNS_ATTEMPT + 1))
done

if [ $DNS_ATTEMPT -gt $MAX_DNS_ATTEMPTS ]; then
  echo "FATAL: etcd DNS resolution failed for $ETCD_HOST"
  exit 1
fi

# Register using Python (same pattern as regular AC module)
# NOTE: Heredoc without quotes allows Terraform and shell variable interpolation
REGISTRATION_RESULT=$(python3 << REGISTER_CONSOLE_AC_EOF
import json
import ssl
import urllib.request
import base64
import sys
import time

# Configuration - shell/Terraform interpolated at runtime
etcd_endpoint = "${etcd_endpoint}"
instance_id = "$INSTANCE_ID"
public_key = "$PUBLIC_KEY"
local_ip = "$LOCAL_IP"
console_ac_id = "$CONSOLE_AC_ID"

# TLS certificate paths
ca_path = "/opt/layerv/nhp-ac/etc/tls/ca.crt"
cert_path = "/opt/layerv/nhp-ac/etc/tls/client.crt"
key_path = "/opt/layerv/nhp-ac/etc/tls/client.key"

# Build registration entry (TOML format for consistency with regular ACs)
registered_at = int(time.time())
registry_value = f'''# Console AC Registry Entry (auto-registered by Console EC2)
PublicKey = "{public_key}"
InstanceId = "{instance_id}"
Ip = "{local_ip}"
Port = 62206
RegisteredAt = {registered_at}
ACId = "{console_ac_id}"
'''

# Create SSL context with client cert
ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
ssl_context.load_verify_locations(ca_path)
ssl_context.load_cert_chain(cert_path, key_path)

# Register with retry
max_retries = 5
for attempt in range(1, max_retries + 1):
    try:
        url = f"{etcd_endpoint}/v3/kv/put"
        key = f"/nhp/ac-registry/{console_ac_id}"
        key_b64 = base64.b64encode(key.encode()).decode()
        value_b64 = base64.b64encode(registry_value.encode()).decode()

        data = json.dumps({
            'key': key_b64,
            'value': value_b64
        }).encode()

        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')

        with urllib.request.urlopen(req, context=ssl_context, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            print(json.dumps({"success": True, "ac_id": console_ac_id, "attempt": attempt}))
            sys.exit(0)

    except Exception as e:
        print(f"Attempt {attempt}/{max_retries} failed: {e}", file=sys.stderr)
        if attempt < max_retries:
            time.sleep(2 ** attempt)
        else:
            print(json.dumps({"success": False, "error": str(e)}))
            sys.exit(1)
REGISTER_CONSOLE_AC_EOF
)

# Check registration result
if echo "$REGISTRATION_RESULT" | python3 -c "import sys,json; result=json.load(sys.stdin); sys.exit(0 if result.get('success') else 1)"; then
  echo "Successfully registered Console AC in etcd: $CONSOLE_AC_ID"
else
  echo "FATAL: Failed to register Console AC in etcd"
  echo "$REGISTRATION_RESULT"
  exit 1
fi
%{ else ~}
# etcd not configured - using DynamoDB storage backend
# Console App will register AC in DynamoDB during InitNHP() (see Console PR #62)
# CONSOLE_AC_ID is already defined above and will be used in portal_sites config
echo "etcd not configured - AC registration will be handled by Console App via DynamoDB"
%{ endif ~}

# ============================================================================
# Install nhp-acd Binary from AC ECR Image
# ============================================================================

%{ if nhp_ac_repo_url != null ~}
echo "Extracting nhp-acd binary from AC image..."

aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "${account_id}.dkr.ecr.${region}.amazonaws.com"

# Pull AC image and extract nhp-acd binary
# Use explicit image_tag to ensure binary version matches Terraform-managed config
docker pull "${nhp_ac_repo_url}:${image_tag}" || {
  echo "ERROR: Could not pull AC image with tag ${image_tag}"
  echo "This likely means the image hasn't been built yet for this commit"
  exit 1
}

if docker images | grep -q "nhp-ac"; then
  CONTAINER_ID=$(docker create "${nhp_ac_repo_url}:${image_tag}")

  mkdir -p /opt/layerv/nhp-ac/etc

  # Extract nhp-acd binary
  docker cp "$CONTAINER_ID:/nhp-ac/nhp-acd" /opt/layerv/nhp-ac/nhp-acd || \
  docker cp "$CONTAINER_ID:/opt/layerv/nhp-ac/nhp-acd" /opt/layerv/nhp-ac/nhp-acd || {
    echo "WARNING: Could not extract nhp-acd binary"
  }

  chmod +x /opt/layerv/nhp-ac/nhp-acd 2>/dev/null || true

  docker rm "$CONTAINER_ID"
  echo "nhp-acd binary extracted"
fi
%{ endif ~}

# ============================================================================
# Configure nhp-acd
# ============================================================================

if [ -f "/opt/layerv/nhp-ac/nhp-acd" ]; then
  echo "Configuring nhp-acd..."

  # Create nhp-acd config
  cat > /opt/layerv/nhp-ac/etc/config.toml << CONFIGEOF
# NHP-AC Configuration for Console (infrastructure-managed)
# This AC protects the Console's port 443 via iptables/ipset

ACId = "$CONSOLE_AC_ID"
DefaultIp = "$LOCAL_IP"
PrivateKeyBase64 = "$PRIVATE_KEY"
DefaultCipherScheme = 0
IpPassMode = 0
LogLevel = 4
AuthServiceId = "passcode"
ResourceIds = ["${console_app_id}"]
FilterMode = 0

# Cloud mode registration (required fields)
# See docs/design/PLUGGABLE_STORAGE_BACKEND.md Section 6.2 for license validation flow
#
# ServerEndpoint uses the Cloud Map internal DNS for NHP Server:
# - Console EC2 is in the same VPC as NHP Servers, so it can reach them via internal DNS
# - This avoids the timeout issue when Console tries to reach public NLB from private subnet
# - License validation uses LicenseKey SHA256 only (globally unique)
ServerEndpoint = "${nhp_server_cloudmap_dns}"
LicenseKey = "$CONSOLE_AC_LICENSE_KEY"
ACVersion = "0.6.0"
ServerPubKeyBase64 = "$SERVER_PUBLIC_KEY"
ServerPort = 62206
CONFIGEOF

  # Note: server.toml is NOT created for cloud mode
  # The AC uses ServerEndpoint (Cloud Map internal DNS) for registration instead of static server list
  # See docs/design/PLUGGABLE_STORAGE_BACKEND.md for cloud mode architecture

  # Create nhp-acd systemd service
  cat > /etc/systemd/system/nhp-acd.service << SVCEOF
[Unit]
Description=NHP Access Controller Daemon (Console)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/layerv/nhp-ac
ExecStart=/opt/layerv/nhp-ac/nhp-acd run
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF

  systemctl daemon-reload
  systemctl enable nhp-acd
  # NOTE: nhp-acd will be started AFTER Console registers this AC in DynamoDB
  # See "Start nhp-acd after Console registers AC" section below

  echo "nhp-acd service configured (will start after Console registers AC)"
else
  echo "WARNING: nhp-acd binary not available, iptables protection is in place but knocks won't work"
fi

echo "NHP Protection setup complete (nhp-acd pending Console startup)"

# ============================================================================
# NHP Protection: Configure nginx for HTTPS on port 443 (protected domain)
# This is for direct access via the protected NLB after NHP knock
# ============================================================================

echo "Installing certbot for protected domain TLS..."
apt_get_with_retry install -y certbot python3-certbot-nginx python3-certbot-dns-route53

echo "Configuring nginx for protected domain (HTTPS on port 443)..."

# Create nginx config for protected domain with TLS
# This runs alongside the internal mode config (if enabled)
# Note: Using heredoc WITHOUT quotes so Terraform variables are interpolated
# nginx variables ($host, $remote_addr, etc.) use \$ to escape
cat > /etc/nginx/sites-available/console-protected << PROTECTEDEOF
# Console API - NHP-Protected Domain nginx configuration
# Proxies HTTPS from public NLB to Console Docker container (after NHP knock)
# TLS termination happens on nginx

upstream console_backend_protected {
    server 127.0.0.1:8080;
    keepalive 32;
}

# HTTPS - Protected domain server (no HTTP redirect needed - users access via NHP knock)
server {
    listen 443 ssl http2;
    server_name ${protected_hostname} _;

    # TLS certificates (certbot or self-signed)
    ssl_certificate /etc/letsencrypt/live/${protected_hostname}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${protected_hostname}/privkey.pem;

    # SSL configuration
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Logging
    access_log /var/log/nginx/console-protected-access.log;
    error_log /var/log/nginx/console-protected-error.log;

    # Health check (for debugging - iptables blocks until knock anyway)
    location /health {
        access_log off;
        return 200 'OK - NHP Protected';
        add_header Content-Type text/plain;
    }

    # Proxy all requests to Console
    location / {
        proxy_pass http://console_backend_protected;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Connection "";

        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # For file uploads
        client_max_body_size 50M;
    }
}
PROTECTEDEOF

# Enable the protected domain config
ln -sf /etc/nginx/sites-available/console-protected /etc/nginx/sites-enabled/console-protected

# Create web root for ACME challenges
mkdir -p /var/www/html

# Obtain TLS certificate for protected domain
echo "Obtaining Let's Encrypt certificate for ${protected_hostname}..."

%{ if hosted_zone_id != null }
# Use DNS-01 challenge with Route 53
certbot certonly \
    --dns-route53 \
    --dns-route53-propagation-seconds 60 \
    -d "${protected_hostname}" \
    --email "${acme_email}" \
    --agree-tos \
    --non-interactive \
    --keep-until-expiring || {
    echo "WARNING: DNS-01 certbot failed, trying HTTP-01..."
    # Fallback to HTTP-01 (port 80 is open for ACME challenges)
    certbot certonly \
        --webroot \
        --webroot-path /var/www/html \
        -d "${protected_hostname}" \
        --email "${acme_email}" \
        --agree-tos \
        --non-interactive \
        --keep-until-expiring || true
}
%{ else }
# Use HTTP-01 challenge (port 80 is open for ACME challenges)
certbot certonly \
    --webroot \
    --webroot-path /var/www/html \
    -d "${protected_hostname}" \
    --email "${acme_email}" \
    --agree-tos \
    --non-interactive \
    --keep-until-expiring || true
%{ endif }

# Fallback to self-signed if certbot fails
if [ ! -f "/etc/letsencrypt/live/${protected_hostname}/fullchain.pem" ]; then
    echo "WARNING: Failed to obtain Let's Encrypt certificate, using self-signed"
    mkdir -p /etc/letsencrypt/live/${protected_hostname}
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/letsencrypt/live/${protected_hostname}/privkey.pem \
        -out /etc/letsencrypt/live/${protected_hostname}/fullchain.pem \
        -subj "/CN=${protected_hostname}"
fi

# Test and reload nginx
nginx -t && systemctl reload nginx

echo "nginx configured for protected domain (HTTPS on port 443)"

%{ if internal_only }
# ============================================================================
# Internal Mode: Configure nginx for HTTP-only (AC handles TLS)
# ============================================================================

echo "Configuring nginx for internal mode (HTTP-only on port ${console_port})..."

cat > /etc/nginx/sites-available/console << 'NGINXEOF'
# Console API - Internal Mode (Portal Domain) nginx configuration
# This is the LOGIN PORTAL - only login-related paths are allowed.
# After login, users are redirected to the protected domain.
#
# SECURITY: All paths except login-related ones return 403.
# This prevents accessing authenticated APIs on the portal domain.
#
# Port mapping:
# - External (NLB): ${console_port} (8888)
# - Internal (Docker): 8080

upstream console_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen ${console_port};
    server_name ${domain_name} _;

    # Use VPC DNS resolver with 30s TTL to handle Cloud Map DNS changes
    resolver 169.254.169.253 valid=30s ipv6=off;

    # Logging
    access_log /var/log/nginx/console-access.log;
    error_log /var/log/nginx/console-error.log;

    # ===========================================================================
    # WHITELISTED PATHS - Only these are allowed on the portal domain
    # ===========================================================================

    # Health check endpoint (for NLB health checks)
    # Proxies to Console's /health which verifies DB connectivity
    location /health {
        access_log off;
        proxy_pass http://console_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Connection "";
        proxy_connect_timeout 5s;
        proxy_read_timeout 5s;
    }

%{ if nhp_server_endpoint != null ~}
    # NHP Server plugins endpoint (for auth_code action after Console login)
    location /plugins/ {
        set $nhp_server_upstream http://${nhp_server_endpoint};
        proxy_pass $nhp_server_upstream;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Connection "";
        proxy_connect_timeout 30s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
%{ endif ~}

    # Static assets (JS, CSS, images for login page)
    location /assets/ {
        proxy_pass http://console_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Connection "";
    }

    # Login APIs (captcha, login)
    location /base/ {
        proxy_pass http://console_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Connection "";
        proxy_connect_timeout 30s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Tenant login/registration
    location /TT/ {
        proxy_pass http://console_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Connection "";
        proxy_connect_timeout 30s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # =======================================================================
    # Portal public APIs - explicit location blocks (safer than nginx `if`)
    # =======================================================================

    # Portal Sites public endpoints
    location = /ps/getPortalSitesPublic { proxy_pass http://console_backend; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; }
    location = /ps/FindSiteByApplicationId { proxy_pass http://console_backend; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; }
    location = /ps/registerByApp { proxy_pass http://console_backend; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; }
    location = /ps/createPortalSitesByURL { proxy_pass http://console_backend; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; }
    # custom_auth_api: Both variants needed - NHP SDK adds trailing slash in server-to-server calls
    location = /ps/custom_auth_api { proxy_pass http://console_backend; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; }
    location = /ps/custom_auth_api/ { proxy_pass http://console_backend; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; }
    location /ps/ { return 403; }  # Block all other /ps/ endpoints

    # PassCode endpoints (all public)
    location /PC/ {
        proxy_pass http://console_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Connection "";
    }

    # Portal App Categories public endpoints
    location = /PACs/getPortalAppCategrayPublic { proxy_pass http://console_backend; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; }
    location = /pacs/getPortalACsPublic { proxy_pass http://console_backend; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; }
    location /PACs/ { return 403; }
    location /pacs/ { return 403; }

    # NHP public endpoints
    location = /pnhps/getPortalNHPServerPublic { proxy_pass http://console_backend; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; }
    location = /nc/getPortalNHPConnectorPublic { proxy_pass http://console_backend; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; }
    location /pnhps/ { return 403; }
    location /nc/ { return 403; }

    # Public info endpoints
    location = /info/getInfoPublic { proxy_pass http://console_backend; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; }
    location = /info/getInfoDataSource { proxy_pass http://console_backend; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; }
    location /info/ { return 403; }

    # File uploads (needed for some portal features)
    location /uploads/ {
        client_max_body_size 50M;
        proxy_pass http://console_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Connection "";
    }

    # Favicon and logos
    location ~ ^/(favicon\.ico|logo.*\.png)$ {
        proxy_pass http://console_backend;
        proxy_set_header Host $host;
    }

    # Root path - serve index.html only (login page entry point)
    location = / {
        proxy_pass http://console_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Connection "";
    }

    # ===========================================================================
    # CATCH-ALL: Block everything else with 403 Forbidden
    # ===========================================================================
    location / {
        return 403 '{"error": "Access denied. Use the protected domain after login."}';
        add_header Content-Type application/json;
    }
}
NGINXEOF

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/console /etc/nginx/sites-enabled/

nginx -t
systemctl enable nginx
systemctl restart nginx

echo "nginx configured for internal mode (HTTP on port ${console_port})"

%{ else }
# ============================================================================
# External Mode: Configure nginx with TLS via Let's Encrypt
# ============================================================================

echo "Configuring nginx (initial HTTP config for certbot)..."

cat > /etc/nginx/sites-available/console << 'NGINXEOF'
# Console - Initial HTTP config for Let's Encrypt

server {
    listen 80;
    server_name ${domain_name};

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}
NGINXEOF

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/console /etc/nginx/sites-enabled/

nginx -t
systemctl enable nginx
systemctl restart nginx

echo "nginx started with initial HTTP config"

# ============================================================================
# Obtain Let's Encrypt Certificate
# ============================================================================

echo "Obtaining Let's Encrypt certificate for ${domain_name}..."
sleep 5

%{ if hosted_zone_id != null }
# Use DNS-01 challenge with Route 53
certbot certonly \
    --dns-route53 \
    --dns-route53-propagation-seconds 60 \
    -d "${domain_name}" \
    --email "${acme_email}" \
    --agree-tos \
    --non-interactive \
    --keep-until-expiring
%{ else }
# Use HTTP-01 challenge
certbot certonly \
    --webroot \
    --webroot-path /var/www/html \
    -d "${domain_name}" \
    --email "${acme_email}" \
    --agree-tos \
    --non-interactive \
    --keep-until-expiring
%{ endif }

# Fallback to self-signed if certbot fails
if [ ! -f "/etc/letsencrypt/live/${domain_name}/fullchain.pem" ]; then
    echo "WARNING: Failed to obtain Let's Encrypt certificate, using self-signed"
    mkdir -p /etc/letsencrypt/live/${domain_name}
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/letsencrypt/live/${domain_name}/privkey.pem \
        -out /etc/letsencrypt/live/${domain_name}/fullchain.pem \
        -subj "/CN=${domain_name}"
fi

echo "Certificate obtained"
%{ endif }

# ============================================================================
# Pull and Run Console Docker Container
# ============================================================================

echo "Pulling Console Docker image..."
# Read image tag from SSM at boot time (allows Console CI to deploy independently)
echo "Reading Console image tag from SSM: ${console_image_tag_ssm_param}"
CONSOLE_IMAGE_TAG=$(aws ssm get-parameter --name "${console_image_tag_ssm_param}" --query 'Parameter.Value' --output text --region "$REGION") || {
  echo "ERROR: SSM GetParameter API call failed for ${console_image_tag_ssm_param}"
  exit 1
}
if [ -z "$CONSOLE_IMAGE_TAG" ] || [ "$CONSOLE_IMAGE_TAG" = "None" ]; then
  echo "ERROR: Console image tag is empty or None (SSM parameter: ${console_image_tag_ssm_param})"
  exit 1
fi
CONSOLE_IMAGE="${console_image_repo}:$CONSOLE_IMAGE_TAG"
echo "Console image: $CONSOLE_IMAGE"
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "${account_id}.dkr.ecr.${region}.amazonaws.com"
docker pull "$CONSOLE_IMAGE"

echo "Starting Console container..."
# Console app listens on port 8888 inside the container (from config.docker.yaml)
# Internal mode: nginx on host proxies from 8888 to container via host port 8080
# External mode: nginx proxies from ${console_port} to container via host port 8080
CONTAINER_PORT=8888
HOST_PORT=8080

docker run -d \
    --name console \
    --restart always \
    -p 127.0.0.1:$HOST_PORT:$CONTAINER_PORT \
    -e "GVA_CONFIG_SYSTEM_ADDR=$CONTAINER_PORT" \
    -e "GVA_CONFIG_SYSTEM_DBTYPE=pgsql" \
    -e "GVA_CONFIG_SYSTEM_COOKIEDOMAIN=${cookie_domain}" \
    -e "GVA_CONFIG_PGSQL_PATH=${rds_endpoint}" \
    -e "GVA_CONFIG_PGSQL_PORT=${rds_port}" \
    -e "GVA_CONFIG_PGSQL_DBNAME=${rds_database_name}" \
    -e "GVA_CONFIG_PGSQL_USERNAME=$RDS_USERNAME" \
    -e "GVA_CONFIG_PGSQL_PASSWORD=$RDS_PASSWORD" \
    -e "GVA_CONFIG_PGSQL_CONFIG=sslmode=require TimeZone=UTC" \
    -e "GVA_CONFIG_PGSQL_SSLMODE=require" \
    -e "GVA_CONFIG_ACCESSCONTROLLERS=${ac_config_json}" \
    -e "GVA_AUTO_INIT=false" \
%{ if admin_password != null ~}
    -e "GVA_ADMIN_PASSWORD=${admin_password}" \
%{ endif ~}
    -e "GVA_CONFIG_NHP_ENABLED=${nhp_server_assignment_enabled}" \
    -e "GVA_CONFIG_NHP_REGION=${nhp_region}" \
%{ if nhp_dynamodb_ac_assignments_table != null ~}
    -e "GVA_CONFIG_NHP_DYNAMODB_AC_ASSIGNMENTS_TABLE=${nhp_dynamodb_ac_assignments_table}" \
%{ endif ~}
%{ if nhp_dynamodb_server_ac_index_table != null ~}
    -e "GVA_CONFIG_NHP_DYNAMODB_SERVER_AC_INDEX_TABLE=${nhp_dynamodb_server_ac_index_table}" \
%{ endif ~}
    -e "GVA_CONFIG_NHP_CLOUDMAP_NAMESPACE=${nhp_cloudmap_namespace}" \
    -e "GVA_CONFIG_NHP_CLOUDMAP_SERVICE_NAME=${nhp_cloudmap_service_name}" \
    -e "GVA_CONFIG_NHP_ASSIGNMENT_SERVERS_PER_AC=${nhp_assignment_servers_per_ac}" \
    -e "GVA_CONFIG_NHP_ASSIGNMENT_REQUIRE_DISTINCT_AZS=${nhp_assignment_require_distinct_azs}" \
    -e "GVA_CONFIG_NHP_HEALTH_MONITOR_CHECK_INTERVAL_SECONDS=${nhp_health_monitor_check_interval}" \
    -e "GVA_CONFIG_NHP_HEALTH_MONITOR_OPERATION_TIMEOUT_SECONDS=${nhp_health_monitor_operation_timeout}" \
%{ if nhp_ac_repo_url != null ~}
    -e "GVA_CONFIG_NHP_CONSOLE_AC_ENABLED=${nhp_console_ac_enabled}" \
    -e "GVA_CONFIG_NHP_CONSOLE_AC_SECRET_NAME=${name_prefix}-console-ac" \
    -e "GVA_CONFIG_NHP_CONSOLE_AC_ID=console-ac" \
    -e "GVA_CONFIG_NHP_CONSOLE_AC_RESOURCE_FQDN=${protected_hostname != null ? protected_hostname : domain_name}" \
    -e "GVA_CONFIG_NHP_CONSOLE_AC_CUSTOMER_ID=${nhp_console_ac_customer_id}" \
%{ endif ~}
%{ if nhp_dynamodb_licenses_table != null ~}
    -e "GVA_CONFIG_NHP_DYNAMODB_LICENSES_TABLE=${nhp_dynamodb_licenses_table}" \
%{ endif ~}
%{ if nhp_dynamodb_licenses_customer_index != null ~}
    -e "GVA_CONFIG_NHP_DYNAMODB_LICENSES_CUSTOMER_INDEX=${nhp_dynamodb_licenses_customer_index}" \
%{ endif ~}
%{ if nhp_dynamodb_licenses_auth0_subject_index != null ~}
    -e "GVA_CONFIG_NHP_DYNAMODB_LICENSES_AUTH0_SUBJECT_INDEX=${nhp_dynamodb_licenses_auth0_subject_index}" \
%{ endif ~}
%{ if nhp_dynamodb_resources_table != null ~}
    -e "GVA_CONFIG_NHP_DYNAMODB_RESOURCES_TABLE=${nhp_dynamodb_resources_table}" \
%{ endif ~}
%{ if internal_service_token != null ~}
    -e "GVA_CONFIG_INTERNAL_SERVICE_TOKEN=${internal_service_token}" \
%{ endif ~}
%{ if provisioning_resource_id != null ~}
    -e "GVA_CONFIG_INTERNAL_PROVISIONING_RESOURCE_ID=${provisioning_resource_id}" \
%{ endif ~}
%{ if provisioning_default_tier != null ~}
    -e "GVA_CONFIG_INTERNAL_PROVISIONING_DEFAULT_TIER=${provisioning_default_tier}" \
%{ endif ~}
%{ if provisioning_default_max_acs != null ~}
    -e "GVA_CONFIG_INTERNAL_PROVISIONING_DEFAULT_MAX_ACS=${provisioning_default_max_acs}" \
%{ endif ~}
    "$CONSOLE_IMAGE"

# Wait for console to be healthy (max 150 seconds = 30 * 5s)
HEALTH_TIMEOUT=150
HEALTH_CHECK_PASSED=false
echo "Waiting for Console to be healthy (timeout: $${HEALTH_TIMEOUT}s)..."
for i in {1..30}; do
    HEALTH_RESPONSE=$(curl -s --max-time 5 -w "\nHTTP_CODE:%%{http_code}" http://127.0.0.1:$HOST_PORT/health 2>&1)
    CURL_EXIT_CODE=$?

    if echo "$HEALTH_RESPONSE" | grep -q "healthy"; then
        echo "Console is healthy after $((i * 5)) seconds"
        HEALTH_CHECK_PASSED=true
        break
    fi

    # Log detailed failure information for debugging
    if [ $CURL_EXIT_CODE -ne 0 ]; then
        echo "Health check attempt $i/30 failed: curl error (exit code: $CURL_EXIT_CODE)"
    else
        HTTP_CODE=$(echo "$HEALTH_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
        echo "Health check attempt $i/30 failed: HTTP $HTTP_CODE"
        echo "  Response: $(echo "$HEALTH_RESPONSE" | grep -v "HTTP_CODE:")"
    fi
    sleep 5
done

if [ "$HEALTH_CHECK_PASSED" != "true" ]; then
    echo "FATAL: Console health check failed after $${HEALTH_TIMEOUT}s"
    echo "Console container logs:"
    docker logs console --tail 50 2>&1 || true
    echo "Failing instance startup - Console must be healthy before proceeding"
    exit 1
fi

# ============================================================================
# Start nhp-acd after Console registers AC
# Console registers its AC in DynamoDB during InitNHP() before HTTP server starts.
# By the time /health returns OK, the AC assignment is already in DynamoDB.
# ============================================================================

if [ -f "/opt/layerv/nhp-ac/nhp-acd" ] && systemctl is-enabled nhp-acd &>/dev/null; then
    echo "Starting nhp-acd service (Console has registered AC in DynamoDB)..."
    systemctl start nhp-acd

    # Verify it started
    sleep 2
    if systemctl is-active nhp-acd &>/dev/null; then
        echo "nhp-acd service started successfully"
    else
        echo "WARNING: nhp-acd failed to start"
        systemctl status nhp-acd --no-pager || true
    fi
fi

%{ if !internal_only }
# ============================================================================
# External Mode: Configure nginx with HTTPS (final config)
# ============================================================================

echo "Configuring nginx with HTTPS..."

cat > /etc/nginx/sites-available/console << 'NGINXEOF'
# Console API - nginx configuration
# Proxies HTTPS to Console Docker container

upstream console_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

# HTTP - Redirect to HTTPS
server {
    listen 80;
    server_name ${domain_name};

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

# HTTPS - Main server
server {
    listen 443 ssl http2;
    server_name ${domain_name};

    ssl_certificate /etc/letsencrypt/live/${domain_name}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain_name}/privkey.pem;

    # SSL configuration
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Logging
    access_log /var/log/nginx/console-access.log;
    error_log /var/log/nginx/console-error.log;

    # Health check - proxies to Console's /health which verifies DB connectivity
    location /health {
        access_log off;
        proxy_pass http://console_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Connection "";
        proxy_connect_timeout 5s;
        proxy_read_timeout 5s;
    }

    # Proxy all requests to Console
    location / {
        proxy_pass http://console_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";

        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # For file uploads
        client_max_body_size 50M;
    }
}
NGINXEOF

nginx -t && systemctl reload nginx

echo "nginx configured with HTTPS proxy to Console"

# ============================================================================
# Setup Certificate Renewal
# ============================================================================

mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/nginx-reload.sh << 'HOOKEOF'
#!/bin/bash
systemctl reload nginx
HOOKEOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/nginx-reload.sh

systemctl enable certbot.timer
systemctl start certbot.timer
%{ endif }

# ============================================================================
# Create Console Health Check Service
# ============================================================================

cat > /etc/systemd/system/console-health.service << 'SVCEOF'
[Unit]
Description=Console Health Monitor
After=docker.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do if ! docker ps | grep -q console; then docker start console 2>/dev/null || true; fi; sleep 30; done'
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable console-health
systemctl start console-health

%{ if seed_console_resource }
# ============================================================================
# Seed Console Resource in RDS (for NHP protection)
# ============================================================================

echo "Seeding Console resource in RDS for NHP protection..."

# Install PostgreSQL client for seeding Console resource
apt_get_with_retry install -y postgresql-client

# Build the SQL to insert Console portal site (idempotent - only if not exists)
# This creates the Console as a protected resource that AC/NHP Server can route to
CONSOLE_APP_ID="${console_app_id}"
CONSOLE_SITE_NAME="LayerV Console"
%{ if protected_hostname != null ~}
# Two-domain architecture: login domain vs protected domain
# Login domain (domain_name): console.nhp.layerv.xyz - Traefik bypass for login page
# Protected domain (protected_hostname): console2.apps.layerv.xyz - NHP-protected Console app
# NOTE: site_url column is what NHP SDK uses for redirect_url, NOT ext_info.RedirectUrl
CONSOLE_SITE_URL="https://${protected_hostname}/"
CONSOLE_HOSTNAME="${protected_hostname}"
%{ else ~}
CONSOLE_SITE_URL="https://${console_app_id}${ac_domain}/"
CONSOLE_HOSTNAME="${console_app_id}${ac_domain}"
%{ endif ~}
CONSOLE_INTERNAL_NLB="${console_internal_nlb}"
CONSOLE_PORT="${console_port}"
AC_NLB_DNS="${ac_nlb_dns}"
COOKIE_DOMAIN="${cookie_domain}"

# Resolve AC NLB DNS to an IP address for ipset rules
# ipset requires IP addresses, not hostnames
AC_NLB_IP=$(dig +short "$AC_NLB_DNS" | head -1)
if [ -z "$AC_NLB_IP" ]; then
    echo "ERROR: Failed to resolve AC NLB DNS '$AC_NLB_DNS' to IP address"
    exit 1
fi
echo "AC NLB DNS: $AC_NLB_DNS -> IP: $AC_NLB_IP"
%{ if auth_signing_key != null ~}
JWT_SECRET="${auth_signing_key}"
%{ else ~}
JWT_SECRET="$CONSOLE_APP_ID"
%{ endif ~}
OPENTIME=3600
TOKEN_EXPIRE=86400

# Build ServiceInfo JSON (backend target)
SERVICE_INFO=$(cat <<SRVEOF
{"ip": "$CONSOLE_INTERNAL_NLB", "port": $CONSOLE_PORT, "scheme": "http", "path": "/"}
SRVEOF
)

# Build Resources JSON (AC routing config)
# ac_id determines which AC receives NHP_AOP message from Server
# ip must be an actual IP address (not DNS) because AC uses it in ipset rules
# Route knocks to Console's own AC (NHP protection is always enabled)
# CONSOLE_AC_ID was set after keypair generation (before etcd block)
# Use LOCAL_IP since Console AC runs on this same instance
RESOURCES=$(cat <<RESEOF
[{"ac_id": "$CONSOLE_AC_ID", "hostname": "$CONSOLE_HOSTNAME", "ip": "$LOCAL_IP", "port": 443, "maskhost": false, "protocol": "tcp"}]
RESEOF
)

# Build ExtInfo JSON (required by passcode plugin for auth_code flow)
# AuthUrl: Console's token validation endpoint called by NHP Server
# AppSecret: Must match the hardcoded value in Console's /ps/custom_auth_api endpoint
# Method: HTTP method for AuthUrl call
# NOTE: redirect_url comes from site_url column, NOT ext_info
AUTH_URL="http://$CONSOLE_INTERNAL_NLB:$CONSOLE_PORT/ps/custom_auth_api"
APP_SECRET="layerv_secret_2025"
EXT_INFO=$(cat <<EXTEOF
{"Title": "LayerV Console", "JWTSecret": "$JWT_SECRET", "AuthUrl": "$AUTH_URL", "AppSecret": "$APP_SECRET", "Method": "GET"}
EXTEOF
)

# Run the seed SQL (upsert pattern - insert if not exists, update if exists)
PGPASSWORD="$RDS_PASSWORD" psql -h "${rds_endpoint}" -p ${rds_port} -U "$RDS_USERNAME" -d "${rds_database_name}" <<SQLEOF
-- Insert Console portal site if not exists
INSERT INTO portal_sites (
    created_at, updated_at, site_name, site_url, app_id, jwt_secret,
    cookie_domain, opentime, skip_auth, is_private, organization,
    service_info, resources, ext_info, grant_users, grant_groups, main_app_config,
    token_expire, status, category
)
SELECT
    NOW(), NOW(), '$CONSOLE_SITE_NAME', '$CONSOLE_SITE_URL', '$CONSOLE_APP_ID', '$JWT_SECRET',
    '$COOKIE_DOMAIN', $OPENTIME, false, false, 'LayerV',
    '$SERVICE_INFO'::jsonb, '$RESOURCES'::jsonb, '$EXT_INFO'::jsonb, '[]'::jsonb, '[]'::jsonb, '{}'::jsonb,
    $TOKEN_EXPIRE, 'active', 'system'
WHERE NOT EXISTS (
    SELECT 1 FROM portal_sites WHERE app_id = '$CONSOLE_APP_ID'
);

-- Update existing Console portal site with correct config (for existing deployments)
-- This ensures site_url, ext_info, etc. are set correctly for the auth_code flow
UPDATE portal_sites
SET
    updated_at = NOW(),
    site_url = '$CONSOLE_SITE_URL',
    ext_info = '$EXT_INFO'::jsonb,
    service_info = '$SERVICE_INFO'::jsonb,
    resources = '$RESOURCES'::jsonb,
    jwt_secret = '$JWT_SECRET'
WHERE app_id = '$CONSOLE_APP_ID';

-- Log the result
DO \$\$
BEGIN
    IF EXISTS (SELECT 1 FROM portal_sites WHERE app_id = '$CONSOLE_APP_ID') THEN
        RAISE NOTICE 'Console resource exists in portal_sites (app_id: %)', '$CONSOLE_APP_ID';
    ELSE
        RAISE NOTICE 'Failed to create Console resource';
    END IF;
END \$\$;
SQLEOF

if [ $? -eq 0 ]; then
    echo "Console resource seeded successfully in RDS"
else
    echo "WARNING: Failed to seed Console resource in RDS (may already exist or DB not ready)"
fi
%{ endif }

# ============================================================================
# Final Checks
# ============================================================================

echo "Performing final checks..."
systemctl status nginx --no-pager
docker ps

echo "Console EC2 installation complete at $(date)"
%{ if internal_only }
echo "Mode: Internal (NHP-protected via AC)"
echo "Internal endpoint: http://${domain_name}:${console_port}"
%{ else }
echo "Mode: External (public access)"
echo "API Endpoint: https://${domain_name}"
%{ endif }
