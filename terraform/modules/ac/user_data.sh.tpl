#!/bin/bash
# NHP AC User Data Script - Standalone AC for customer deployments
#
# This template configures a standalone AC that protects customer resources.
# For the Console's embedded AC, see: terraform/modules/console-ec2/user_data.sh.tpl
#
# Both templates share similar AC configuration patterns (config.toml, firewall rules).
# When updating AC config structure, review both templates to keep them in sync.
set -ex

exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
echo "Starting NHP AC installation at $(date)"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
# Note: awscli package deprecated in Ubuntu 24.04, using unzip + curl for AWS CLI v2
apt-get install -y jq curl docker.io gettext-base iptables ipset unzip

# Install AWS CLI v2 (works on all Ubuntu versions)
if ! command -v aws &> /dev/null; then
  echo "Installing AWS CLI v2..."
  curl -sL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
  unzip -q /tmp/awscliv2.zip -d /tmp
  /tmp/aws/install
  rm -rf /tmp/aws /tmp/awscliv2.zip
fi
aws --version

# Enable and start Docker
systemctl enable docker
systemctl start docker

# Wait for Docker to be ready
for i in {1..30}; do docker info && break || sleep 2; done

REGION="${region}"
ACCOUNT_ID="${account_id}"

TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
LOCAL_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)

# Create directories
mkdir -p /opt/layerv/nhp-ac/etc
mkdir -p /opt/layerv/nhp-ac/log
mkdir -p /home/ubuntu/traefik
mkdir -p /home/ubuntu/traefik/plugins-local
mkdir -p /var/log/traefik
mkdir -p /acme

# ============================================================================
# AC Deployment - Fully Infrastructure Driven
# All services pulled from ECR and installed as native systemd services.
# This enables traefik-plugins repo to deploy plugins via SSM.
#
# Services on AC:
# - traefik.service: HTTPS proxy (443, 80) - proxies *.apps traffic
# - nhp-acd.service: AC daemon (localhost:62206 TCP, handles knock packets)
# ============================================================================

# Login to ECR and pull AC image
ECR_REPO="${ac_repo_url}"
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "${account_id}.dkr.ecr.${region}.amazonaws.com"

echo "Pulling AC image from ECR..."
docker pull "$ECR_REPO:${image_tag}" || docker pull "$ECR_REPO:${environment}" || {
  echo "ERROR: Could not pull AC image from ECR"
  exit 1
}

# Extract binaries from Docker image
echo "Extracting binaries from AC image..."
CONTAINER_ID=$(docker create "$ECR_REPO:${image_tag}")

# Extract Traefik binary
docker cp "$CONTAINER_ID:/usr/local/bin/traefik" /usr/local/bin/traefik
chmod +x /usr/local/bin/traefik

# Extract nhp-acd binary and config
docker cp "$CONTAINER_ID:/nhp-ac" /opt/layerv/nhp-ac-extracted || true
if [ -d "/opt/layerv/nhp-ac-extracted" ]; then
  cp -r /opt/layerv/nhp-ac-extracted/* /opt/layerv/nhp-ac/
fi

# Extract iptables defaults script
docker cp "$CONTAINER_ID:/iptables_defaults.sh" /opt/layerv/nhp-ac/iptables_defaults.sh || true
chmod +x /opt/layerv/nhp-ac/iptables_defaults.sh 2>/dev/null || true

# Cleanup container
docker rm "$CONTAINER_ID"

echo "Binaries extracted successfully"

# ============================================================================
# NHP Firewall Setup - ipset and iptables rules for zero-trust access control
# This creates the firewall infrastructure that nhp-acd uses to dynamically
# allow/deny traffic based on successful NHP knocks.
# ============================================================================
echo "Setting up NHP firewall with ipset and iptables..."

# Create ipsets for NHP traffic control
# - tempset: temporary entries for initial knock (5s timeout)
# - defaultset: active sessions after successful knock (120s timeout)
# - defaultset_down: downstream tracking (121s timeout)
ipset -exist create defaultset hash:ip,port,ip counters maxelem 1000000 timeout 120
ipset -exist create defaultset_down hash:ip,port,ip counters maxelem 1000000 timeout 121
ipset -exist create tempset hash:net,port counters maxelem 1000000 timeout 5

echo "ipsets created successfully"

# Create NHP_DENY chain for logging and dropping unauthorized traffic
iptables -N NHP_DENY 2>/dev/null || true
iptables -C NHP_DENY -d "$LOCAL_IP" -j LOG --log-prefix "[NHP-DENY] " --log-level 6 --log-ip-options 2>/dev/null || \
    iptables -A NHP_DENY -d "$LOCAL_IP" -j LOG --log-prefix "[NHP-DENY] " --log-level 6 --log-ip-options
iptables -C NHP_DENY -d "$LOCAL_IP" -j DROP 2>/dev/null || \
    iptables -A NHP_DENY -d "$LOCAL_IP" -j DROP

# Setup INPUT chain rules
echo "Configuring INPUT chain..."

# ipset rules: tempset -> defaultset promotion, then accept
iptables -C INPUT -m set --match-set tempset src,dst -j SET --add-set defaultset src,dst,dst 2>/dev/null || \
    iptables -A INPUT -m set --match-set tempset src,dst -j SET --add-set defaultset src,dst,dst
iptables -C INPUT -m set --match-set defaultset src,dst,dst -j SET --add-set defaultset_down src,dst,dst 2>/dev/null || \
    iptables -A INPUT -m set --match-set defaultset src,dst,dst -j SET --add-set defaultset_down src,dst,dst
iptables -C INPUT -m set --match-set defaultset src,dst,dst -j LOG --log-prefix "[NHP-ACCEPT] " --log-level 6 --log-ip-options 2>/dev/null || \
    iptables -A INPUT -m set --match-set defaultset src,dst,dst -j LOG --log-prefix "[NHP-ACCEPT] " --log-level 6 --log-ip-options
iptables -C INPUT -m set --match-set defaultset src,dst,dst -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -m set --match-set defaultset src,dst,dst -j ACCEPT
iptables -C INPUT -m set --match-set tempset src,dst -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -m set --match-set tempset src,dst -j ACCEPT

# Allow loopback
iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT -i lo -j ACCEPT

# Allow SSH from VPC (for management/debugging)
iptables -C INPUT -p tcp -s "${vpc_cidr}" --dport 22 -j ACCEPT 2>/dev/null || \
    iptables -I INPUT -p tcp -s "${vpc_cidr}" --dport 22 -j ACCEPT

# Allow HTTPS (443) from anywhere - NLB preserves client IP, security at app layer
iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || \
    iptables -I INPUT -p tcp --dport 443 -j ACCEPT

# Allow HTTP (80) from anywhere - for ACME challenge and redirects to HTTPS
iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || \
    iptables -I INPUT -p tcp --dport 80 -j ACCEPT

# Allow portal (8888) from VPC
iptables -C INPUT -p tcp -s "${vpc_cidr}" --dport 8888 -j ACCEPT 2>/dev/null || \
    iptables -I INPUT -p tcp -s "${vpc_cidr}" --dport 8888 -j ACCEPT

# Allow established connections
iptables -C INPUT -m state --state ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT

# Default deny for INPUT (jump to NHP_DENY for logging)
iptables -C INPUT -j NHP_DENY 2>/dev/null || iptables -A INPUT -j NHP_DENY

# Setup FORWARD chain rules
echo "Configuring FORWARD chain..."

iptables -C FORWARD -m set --match-set defaultset src,dst,dst -j SET --add-set defaultset_down src,dst,dst 2>/dev/null || \
    iptables -A FORWARD -m set --match-set defaultset src,dst,dst -j SET --add-set defaultset_down src,dst,dst
iptables -C FORWARD -m set --match-set defaultset src,dst,dst -j LOG --log-prefix "[NHP-FORWARD] " --log-level 6 --log-ip-options 2>/dev/null || \
    iptables -A FORWARD -m set --match-set defaultset src,dst,dst -j LOG --log-prefix "[NHP-FORWARD] " --log-level 6 --log-ip-options
iptables -C FORWARD -m set --match-set defaultset src,dst,dst -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -m set --match-set defaultset src,dst,dst -j ACCEPT
iptables -C FORWARD -m state --state ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -m state --state ESTABLISHED -j ACCEPT
iptables -C FORWARD -j NHP_DENY 2>/dev/null || iptables -A FORWARD -j NHP_DENY

# Set chain policies
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

echo "NHP firewall setup complete"

# ============================================================================
# rsyslog configuration for NHP logging
# Routes NHP firewall logs to dedicated log files for monitoring
# ============================================================================
echo "Configuring rsyslog for NHP logging..."

mkdir -p /opt/layerv/nhp-ac/logs
chmod 755 /opt/layerv/nhp-ac/logs

if [ -d /etc/rsyslog.d ]; then
    cat > /etc/rsyslog.d/10-nhplog.conf << RSYSLOGEOF
# NHP Firewall Logging Configuration
template(name="NHPFormat" type="string" string="%timegenerated:8:19% $LOCAL_IP %syslogtag% %msg:::drop-last-lf%\n")
template(name="NHPAcceptFile" type="string" string="/opt/layerv/nhp-ac/logs/nhp_accept-%\$YEAR%-%\$MONTH%-%\$DAY%.log")
template(name="NHPForwardFile" type="string" string="/opt/layerv/nhp-ac/logs/nhp_forward-%\$YEAR%-%\$MONTH%-%\$DAY%.log")
template(name="NHPDenyFile" type="string" string="/opt/layerv/nhp-ac/logs/nhp_deny-%\$YEAR%-%\$MONTH%-%\$DAY%.log")

:msg,contains,"[NHP-ACCEPT]" ?NHPAcceptFile;NHPFormat
& stop
:msg,contains,"[NHP-FORWARD]" ?NHPForwardFile;NHPFormat
& stop
:msg,contains,"[NHP-DENY]" ?NHPDenyFile;NHPFormat
& stop
RSYSLOGEOF

    systemctl restart rsyslog || true
    echo "rsyslog configured for NHP logging"
fi

# ============================================================================
# Per-Instance AC Key Generation
# Each AC instance generates its own Curve25519 keypair and stores it in
# Secrets Manager. This provides per-instance isolation and revocation capability.
# The AC registers with NHP servers using cloud mode credentials.
# ============================================================================

# Install cryptography library for key generation
apt-get install -y python3-cryptography

# Per-instance secret name
AC_SECRET_NAME="${name_prefix}-ac-$INSTANCE_ID"

echo "Checking for existing AC keypair in Secrets Manager..."

# Try to get existing secret for this instance
EXISTING_SECRET=$(aws secretsmanager get-secret-value --secret-id "$AC_SECRET_NAME" --region "$REGION" --query SecretString --output text 2>/dev/null || echo "")

if [ -n "$EXISTING_SECRET" ]; then
  echo "Found existing keypair for this instance"
  PRIVATE_KEY=$(echo "$EXISTING_SECRET" | python3 -c "import sys,json; print(json.load(sys.stdin)['privateKey'])")
  PUBLIC_KEY=$(echo "$EXISTING_SECRET" | python3 -c "import sys,json; print(json.load(sys.stdin)['publicKey'])")
else
  echo "Generating new Curve25519 keypair for this instance..."

  # Generate keypair using Python cryptography library
  # Note: Using serialization API for compatibility with Ubuntu 22.04's python3-cryptography 3.4.8
  KEYPAIR=$(python3 << 'KEYGEN_EOF'
import json
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

# Generate new X25519 keypair
private_key = X25519PrivateKey.generate()

# Get raw bytes using serialization API (compatible with cryptography 3.4+)
private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)
public_bytes = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

# Encode as base64
result = {
    'privateKey': base64.b64encode(private_bytes).decode(),
    'publicKey': base64.b64encode(public_bytes).decode()
}

print(json.dumps(result))
KEYGEN_EOF
)

  PRIVATE_KEY=$(echo "$KEYPAIR" | python3 -c "import sys,json; print(json.load(sys.stdin)['privateKey'])")
  PUBLIC_KEY=$(echo "$KEYPAIR" | python3 -c "import sys,json; print(json.load(sys.stdin)['publicKey'])")

  echo "Storing keypair in Secrets Manager..."

  # Create the secret with the keypair
  SECRET_VALUE=$(cat << SECRETEOF
{
  "privateKey": "$PRIVATE_KEY",
  "publicKey": "$PUBLIC_KEY",
  "instanceId": "$INSTANCE_ID",
  "createdAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
SECRETEOF
)

  # Create or update the secret
  KMS_ARG=""
%{ if secrets_kms_key_arn != "" }
  KMS_ARG="--kms-key-id ${secrets_kms_key_arn}"
%{ endif }
  if aws secretsmanager create-secret \
    --name "$AC_SECRET_NAME" \
    --secret-string "$SECRET_VALUE" \
    $KMS_ARG \
    --tags "Key=Environment,Value=${environment}" "Key=InstanceId,Value=$INSTANCE_ID" \
    --region "$REGION" 2>/dev/null; then
    echo "Created new secret: $AC_SECRET_NAME"
  else
    # Secret might already exist (from previous failed boot), update it
    aws secretsmanager put-secret-value \
      --secret-id "$AC_SECRET_NAME" \
      --secret-string "$SECRET_VALUE" \
      --region "$REGION"
    echo "Updated existing secret: $AC_SECRET_NAME"
  fi
fi

echo "AC keypair ready (public key: $${PUBLIC_KEY:0:20}...)"

# ============================================================================
# Fetch NHP Server Public Key
# Required for AC to communicate with NHP servers via cloud registration
# ============================================================================
echo "Fetching NHP Server public key from Secrets Manager..."
SERVER_SECRET=$(aws secretsmanager get-secret-value --secret-id "${server_secret_arn}" --region "$REGION" --query SecretString --output text)
SERVER_PUBLIC_KEY=$(echo "$SERVER_SECRET" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('publicKey', d.get('PubKeyBase64', '')))" 2>/dev/null || echo "")
if [ -z "$SERVER_PUBLIC_KEY" ]; then
  echo "FATAL: Could not extract server public key from secret"
  exit 1
fi
echo "Server public key retrieved: $${SERVER_PUBLIC_KEY:0:20}..."

# ============================================================================
# NHP-ACD Configuration Files
# Generate all config files for the AC daemon
# ============================================================================

# Generate AC config.toml with environment-specific values
# Cloud mode: AC registers with NHP server using credentials
cat > /opt/layerv/nhp-ac/etc/config.toml << CONFIGEOF
# NHP-AC base config (infrastructure-managed)
# Generated by Terraform user_data
# Cloud mode: Uses ServerEndpoint for registration with license credentials

ACId = "${ac_id}"
DefaultIp = "$LOCAL_IP"
PrivateKeyBase64 = "$PRIVATE_KEY"
DefaultCipherScheme = 0
IpPassMode = 0
LogLevel = 4
AuthServiceId = "${auth_service_id}"
ResourceIds = ${resource_ids}
FilterMode = 0

# Cloud mode registration credentials (license key is globally unique)
LicenseKey = "${license_key}"
ServerEndpoint = "${server_endpoint}"
ServerPubKeyBase64 = "$SERVER_PUBLIC_KEY"
CONFIGEOF
echo "NHP-ACD config.toml created (cloud mode)"

# HTTP server config for NHP-ACD
cat > /opt/layerv/nhp-ac/etc/http.toml << 'HTTPEOF'
# HTTP server config for NHP-ACD
# This is the NHP protocol's HTTP interface, not Traefik's HTTPS
EnableHttp = true
EnableTLS = false
HttpListenIp = "127.0.0.1"
HttpListenPort = 8888
HTTPEOF
echo "NHP-ACD HTTP config created"

# Traefik configuration for this environment
# Note: traefik-plugins repo deploys plugins to /home/ubuntu/traefik/plugins-local via SSM
cat > /home/ubuntu/traefik/traefik.toml << TRAEFIKEOF
[global]
  checkNewVersion = false
  sendAnonymousUsage = false

[log]
  level = "INFO"
  filePath = "/var/log/traefik/traefik.log"

[accessLog]
  filePath = "/var/log/traefik/access.log"

[api]
  dashboard = true
  insecure = true

[ping]
  entryPoint = "traefik"

[entryPoints]
  [entryPoints.https]
    address = ":443"
    # ProxyProtocol for NLB - preserves client IP
    [entryPoints.https.proxyProtocol]
      trustedIPs = ["${vpc_cidr}"]
    [entryPoints.https.forwardedHeaders]
      trustedIPs = ["${vpc_cidr}"]
  [entryPoints.http]
    address = ":80"
    [entryPoints.http.http.redirections.entryPoint]
      to = "https"
      scheme = "https"
  [entryPoints.traefik]
    address = ":8080"

[certificatesResolvers.letsencrypt.acme]
  email = "${acme_email}"
  storage = "/home/ubuntu/traefik/acme.json"
  caServer = "${acme_ca_server}"
  [certificatesResolvers.letsencrypt.acme.dnsChallenge]
    provider = "route53"
    resolvers = ["1.1.1.1:53", "8.8.8.8:53"]
    # Route 53 DNS propagation can take up to 60 seconds
    [certificatesResolvers.letsencrypt.acme.dnsChallenge.propagation]
      delayBeforeChecks = "60s"

[providers.file]
  directory = "/home/ubuntu/traefik/"
  watch = true

# NOTE: [experimental.localPlugins] section is managed by traefik-plugins repo via SSM
# The traefik-plugins deployment will add this section with plugin definitions
TRAEFIKEOF

# Create Traefik dynamic configuration (routes to nhp-acd and NHP Server)
cat > /home/ubuntu/traefik/dynamic.toml << DYNAMICEOF
# Traefik Dynamic Configuration
# Routes:
%{ if console_domain != null && console_backend_url != null ~}
# - Host(${console_domain}) → Console EC2 (BYPASSES nhp-acd for login page)
%{ endif ~}
# - /plugins/* → NHP Server HTTP (passcode login, auth endpoints)
# - /* → nhp-acd (protected resource access, refresh)

[http.routers]
%{ if console_domain != null && console_backend_url != null ~}
  # Console route - BYPASSES nhp-acd for login page access
  # Console handles its own JWT auth, NHP integration is client-side after login
  # See docs/ARCHITECTURE.md "Console NHP Integration" section
  # NOTE: Both console_domain AND console_backend_url must be set to avoid 502 errors
  # (a router without a matching service causes Traefik to return 502)
  [http.routers.console]
    rule = "Host(\`${console_domain}\`)"
    service = "console"
    entryPoints = ["https"]
    priority = 20
    [http.routers.console.tls]
      certResolver = "letsencrypt"
      [[http.routers.console.tls.domains]]
        main = "${domain_name}"
        sans = ["*.${domain_name}"]

%{ endif ~}
  # Route /plugins to NHP Server for passcode login and auth
  [http.routers.nhp-plugins]
    rule = "PathPrefix(\`/plugins\`)"
    service = "nhp-server"
    entryPoints = ["https"]
    priority = 10
    [http.routers.nhp-plugins.tls]
      certResolver = "letsencrypt"
      [[http.routers.nhp-plugins.tls.domains]]
        main = "${domain_name}"
        sans = ["*.${domain_name}"]

  # Default route to nhp-acd for protected resource access
  [http.routers.nhp-ac]
    rule = "PathPrefix(\`/\`)"
    service = "nhp-ac"
    entryPoints = ["https"]
    priority = 1
    [http.routers.nhp-ac.tls]
      certResolver = "letsencrypt"
      [[http.routers.nhp-ac.tls.domains]]
        main = "${domain_name}"
        sans = ["*.${domain_name}"]

[http.services]
%{ if console_domain != null && console_backend_url != null ~}
  # Console backend (bypasses nhp-acd)
  # NOTE: This service is only created when both console_domain AND console_backend_url are set
  # to ensure the router and service are always created together (prevents 502 errors)
  [http.services.console.loadBalancer]
    [[http.services.console.loadBalancer.servers]]
      url = "${console_backend_url}"

%{ endif ~}
  # NHP Server HTTP for plugin endpoints (passcode login, auth)
  # Note: NHP Server HTTP listens on 8888 (same port as nhp-acd uses for internal comms)
  [http.services.nhp-server.loadBalancer]
    [[http.services.nhp-server.loadBalancer.servers]]
      url = "http://server.${namespace_name}:8888"

  # nhp-acd for protected resource routing
  [http.services.nhp-ac.loadBalancer]
    [[http.services.nhp-ac.loadBalancer.servers]]
      url = "http://127.0.0.1:8888"
DYNAMICEOF

# Add production domain routers if configured
%{ if length(production_domains) > 0 }
cat >> /home/ubuntu/traefik/dynamic.toml << PRODDYNAMICEOF

# Production domain routers (certificates via cross-account ACME)
%{ for idx, domain in production_domains ~}
  [http.routers.prod-${idx}]
    rule = "HostRegexp(\`^.+\\\\.${domain}\$\`) || Host(\`${domain}\`)"
    service = "nhp-ac"
    entryPoints = ["https"]
    priority = 10
    [http.routers.prod-${idx}.tls]
      certResolver = "letsencrypt"
      [[http.routers.prod-${idx}.tls.domains]]
        main = "${domain}"
        sans = ["*.${domain}"]
%{ endfor ~}
PRODDYNAMICEOF
%{ endif }

# Add additional TLS domain routers (same account, uses standard ACME)
%{ if length(additional_tls_domains) > 0 }
cat >> /home/ubuntu/traefik/dynamic.toml << ADDTLSEOF

# Additional TLS domain routers (same account ACME)
%{ for idx, domain in additional_tls_domains ~}
  [http.routers.addtls-${idx}]
    rule = "HostRegexp(\`^.+\\\\.${domain}\$\`) || Host(\`${domain}\`)"
    service = "nhp-ac"
    entryPoints = ["https"]
    priority = 10
    [http.routers.addtls-${idx}.tls]
      certResolver = "letsencrypt"
      [[http.routers.addtls-${idx}.tls.domains]]
        main = "${domain}"
        sans = ["*.${domain}"]
%{ endfor ~}
ADDTLSEOF
%{ endif }

# Create ACME storage
touch /home/ubuntu/traefik/acme.json
chmod 600 /home/ubuntu/traefik/acme.json
chown -R ubuntu:ubuntu /home/ubuntu/traefik

# ============================================================================
# Systemd Services
# ============================================================================

# Traefik systemd service
# Note: When cross_account_route53_role_arn is set, Traefik will use that role for
# ALL Route 53 operations. This means:
# - Production domains (qurl.site, qurl.link) in layerv-mgmt will work
# - Local domains (nhp.layerv.xyz) in layerv account will NOT work unless the
#   cross-account role also has access to those zones
# For mixed-domain scenarios, consider running separate AC instances.
cat > /etc/systemd/system/traefik.service << SVCEOF
[Unit]
Description=Traefik HTTPS Proxy
Documentation=https://doc.traefik.io/traefik/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/traefik --configFile=/home/ubuntu/traefik/traefik.toml
Restart=always
RestartSec=5
Environment="AWS_REGION=${region}"
%{ if cross_account_route53_role_arn != null ~}
Environment="AWS_ASSUME_ROLE_ARN=${cross_account_route53_role_arn}"
%{ endif ~}

[Install]
WantedBy=multi-user.target
SVCEOF

# nhp-acd systemd service (listens on localhost:8888 for HTTP, localhost:62206 for NHP)
cat > /etc/systemd/system/nhp-acd.service << SVCEOF
[Unit]
Description=NHP Access Controller Daemon
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

# Cloud Map registration script
CLOUDMAP_SERVICE_ID="${cloudmap_service_id}"

cat > /opt/layerv/nhp-ac/cloudmap-register.sh << 'CMEOF'
#!/bin/bash
set -e
SERVICE_ID="${cloudmap_service_id}"
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
LOCAL_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4)
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
echo "Registering AC instance $INSTANCE_ID ($PUBLIC_IP) with Cloud Map service $SERVICE_ID"
aws servicediscovery register-instance \
  --service-id "$SERVICE_ID" \
  --instance-id "$INSTANCE_ID" \
  --attributes "AWS_INSTANCE_IPV4=$LOCAL_IP,PUBLIC_IP=$PUBLIC_IP,AVAILABILITY_ZONE=$AZ,HTTPS_PORT=443,NHP_PORT=62206" \
  --region "$REGION"
echo "AC instance registered successfully"
CMEOF
chmod +x /opt/layerv/nhp-ac/cloudmap-register.sh

cat > /opt/layerv/nhp-ac/cloudmap-deregister.sh << 'CMEOF'
#!/bin/bash
set -e
SERVICE_ID="${cloudmap_service_id}"
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
echo "Deregistering AC instance $INSTANCE_ID from Cloud Map service $SERVICE_ID"
aws servicediscovery deregister-instance \
  --service-id "$SERVICE_ID" \
  --instance-id "$INSTANCE_ID" \
  --region "$REGION" || true
echo "AC instance deregistered"
CMEOF
chmod +x /opt/layerv/nhp-ac/cloudmap-deregister.sh

# Health monitor for Cloud Map
cat > /opt/layerv/nhp-ac/health-monitor.sh << 'HEALTHEOF'
#!/bin/bash
SERVICE_ID="${cloudmap_service_id}"
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
while true; do
  # Check critical services
  TRAEFIK_OK=$(systemctl is-active traefik 2>/dev/null || echo "inactive")
  NHPACD_OK=$(systemctl is-active nhp-acd 2>/dev/null || echo "inactive")

  if [[ "$TRAEFIK_OK" == "active" && "$NHPACD_OK" == "active" ]]; then
    HEALTH_STATUS="HEALTHY"
  else
    HEALTH_STATUS="UNHEALTHY"
  fi

  aws servicediscovery update-instance-custom-health-status \
    --service-id "$SERVICE_ID" \
    --instance-id "$INSTANCE_ID" \
    --status "$HEALTH_STATUS" \
    --region "$REGION" 2>/dev/null || true
  sleep 30
done
HEALTHEOF
chmod +x /opt/layerv/nhp-ac/health-monitor.sh

# Systemd services for Cloud Map registration
cat > /etc/systemd/system/nhp-cloudmap-register.service << SVCEOF
[Unit]
Description=Register NHP AC with Cloud Map
After=network-online.target traefik.service nhp-acd.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/layerv/nhp-ac/cloudmap-register.sh
RemainAfterExit=yes
ExecStop=/opt/layerv/nhp-ac/cloudmap-deregister.sh

[Install]
WantedBy=multi-user.target
SVCEOF

cat > /etc/systemd/system/nhp-health-monitor.service << SVCEOF
[Unit]
Description=NHP AC Health Monitor (Cloud Map)
After=network.target nhp-cloudmap-register.service

[Service]
Type=simple
ExecStart=/opt/layerv/nhp-ac/health-monitor.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF

# ============================================================================
# Fetch Traefik Plugins from S3
# Plugins are uploaded by traefik-plugins repo, configs rendered by Terraform.
# This ensures plugins persist across ASG instance refreshes.
# ============================================================================
%{ if plugin_bucket_name != null && length(traefik_plugins) > 0 }
echo "Downloading Traefik plugins from S3..."
PLUGIN_BUCKET="${plugin_bucket_name}"

%{ for plugin_name, plugin in traefik_plugins ~}
echo "Downloading Traefik plugin: ${plugin_name} (version: ${plugin.version})"
mkdir -p /home/ubuntu/traefik/plugins-local/src/${plugin_name}

# Download plugin files
aws s3 sync "s3://$PLUGIN_BUCKET/${plugin.plugin_key}" \
  /home/ubuntu/traefik/plugins-local/src/${plugin_name}/ \
  --region "$REGION" || {
    echo "Warning: Could not download ${plugin_name} Traefik plugin"
  }

%{ if plugin.config_key != null ~}
# Download plugin config (rendered by Terraform)
aws s3 cp "s3://$PLUGIN_BUCKET/${plugin.config_key}" \
  /home/ubuntu/traefik/plugins-local/src/${plugin_name}/config.toml \
  --region "$REGION" || {
    echo "Warning: Could not download ${plugin_name} plugin config"
  }
%{ endif ~}

echo "Traefik plugin ${plugin_name} installed"
%{ endfor ~}

chown -R ubuntu:ubuntu /home/ubuntu/traefik/plugins-local
echo "All Traefik plugins downloaded from S3"
%{ else }
echo "No Traefik plugins configured, skipping S3 download"
%{ endif }

# Reload systemd and enable/start all services
systemctl daemon-reload
systemctl enable traefik nhp-acd nhp-cloudmap-register nhp-health-monitor
systemctl start traefik
systemctl start nhp-acd
systemctl start nhp-cloudmap-register
systemctl start nhp-health-monitor

echo "NHP AC installation complete at $(date)"
echo "Instance ID: $INSTANCE_ID"
echo "Public IP: $PUBLIC_IP"
echo "Local IP: $LOCAL_IP"
echo ""
echo "Services (fully infrastructure-driven from ECR):"
echo "  - Traefik (HTTPS proxy): :443, :80, dashboard :8080"
echo "  - nhp-acd: localhost:8888 (HTTP), localhost:62206 (NHP)"
echo ""
echo "Traefik plugins directory: /home/ubuntu/traefik/plugins-local"
echo "  (managed by traefik-plugins repo via SSM)"
