#!/bin/bash
set -ex

exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
echo "Starting NHP Server installation at $(date)"

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
# Note: awscli package deprecated in Ubuntu 24.04, using unzip + curl for AWS CLI v2
apt_get_with_retry install -y jq docker.io curl unzip

# Install AWS CLI v2 (works on all Ubuntu versions)
if ! command -v aws &> /dev/null; then
  echo "Installing AWS CLI v2..."
  curl -sL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
  unzip -q /tmp/awscliv2.zip -d /tmp
  /tmp/aws/install
  rm -rf /tmp/aws /tmp/awscliv2.zip
fi
aws --version

systemctl enable docker
systemctl start docker

for i in {1..30}; do docker info && break || sleep 2; done

# Fix DNS for Go's pure resolver (doesn't work with systemd-resolved stub)
# Disable stub listener and point to real VPC DNS resolver
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/disable-stub.conf << 'DNSEOF'
[Resolve]
DNSStubListener=no
DNSEOF
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
systemctl restart systemd-resolved
echo "DNS configured to use VPC resolver directly"

SECRET_ARN="${secret_arn}"
REGION="${region}"
SECRET=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --region "$REGION" --query SecretString --output text)
PRIVATE_KEY=$(echo "$SECRET" | jq -r ".privateKey")
HOSTNAME=$(echo "$SECRET" | jq -r ".hostname")

TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
LOCAL_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)

mkdir -p /opt/layerv/nhp-server/etc
mkdir -p /opt/layerv/nhp-server/log

cat > /opt/layerv/nhp-server/etc/config.toml << CONFIGEOF
PrivateKeyBase64 = "$PRIVATE_KEY"
DefaultCipherScheme = 0
ListenIp = ""
ListenPort = 62206
Hostname = "$HOSTNAME"
LogLevel = 3
DisableAgentValidation = false
%{ if dev_mode }
Dev = true
%{ endif }
%{ if resource_mode == "api" }
ResourceMode = "api"
%{ if auth_url != null }
AuthUrl = "${auth_url}"
%{ endif }
%{ if auth_signing_key != null }
SigningKey = "${auth_signing_key}"
%{ endif }
%{ if auth_aes_key != null }
AesKey = "${auth_aes_key}"
%{ endif }
%{ endif }

[webrtc]
Enable = false
CONFIGEOF

# ============================================================================
# Storage Backend Configuration - Separate file (storage.toml)
# Server looks for storage.toml specifically, not config.toml [Storage] section.
# Controls where AC assignments, licenses, and resources are stored.
# - "dynamodb" (default): AWS DynamoDB for cloud deployments
# - "etcd": etcd for on-prem deployments (feature flag)
# ============================================================================
cat > /opt/layerv/nhp-server/etc/storage.toml << STORAGEEOF
# Storage backend configuration
# The Go code unmarshals directly into StorageConfig struct, so no [Storage] wrapper.
# See endpoints/server/config.go loadStorageConfig() for parsing logic.
Backend = "${storage_backend}"

%{ if storage_backend == "dynamodb" ~}
[DynamoDB]
Region = "${dynamodb_region}"
%{ if dynamodb_licenses_table != null ~}
LicensesTable = "${dynamodb_licenses_table}"
%{ endif ~}
%{ if dynamodb_ac_assignments_table != null ~}
ACAssignmentsTable = "${dynamodb_ac_assignments_table}"
%{ endif ~}
%{ if dynamodb_resources_table != null ~}
ResourcesTable = "${dynamodb_resources_table}"
%{ endif ~}
%{ endif ~}

%{ if storage_backend == "etcd" && etcd_endpoint != "" ~}
[Etcd]
Endpoints = ["${etcd_endpoint}"]
%{ if etcd_tls_secret_arn != "" ~}
TLS = true
CACert = "/nhp-server/etc/tls/ca.crt"
ClientCert = "/nhp-server/etc/tls/client.crt"
ClientKey = "/nhp-server/etc/tls/client.key"
%{ endif ~}
%{ endif ~}

[Cache]
MaxEntries = 10000
DefaultTTL = 60
ReassignmentTTL = 5
ReassignmentWindow = 300
STORAGEEOF

# NHP Server uses local config.toml for base config (UDP port 62206)
# Configure HTTP server for plugin endpoints (passcode login, OIDC, etc.)
# Demo Gateway routes qurl.link/{appId} to this endpoint
# Note: Port 8888 is used consistently (matches etcd config and AC Traefik routing)
cat > /opt/layerv/nhp-server/etc/http.toml << 'HTTPEOF'
EnableHttp = true
EnableTLS = false
HttpListenIp = ""
HttpListenPort = 8888
HTTPEOF

# ============================================================================
# etcd Configuration for AC Registry Discovery
# Server watches /nhp/ac-registry/ prefix to dynamically discover ACs.
# Each AC registers its public key and AWS identity when it starts.
# This enables per-AC keypairs and dynamic scaling without static ac.toml.
# ============================================================================
%{ if multi_tenant && etcd_endpoint != "" }
echo "Configuring etcd connection for AC registry discovery..."
mkdir -p /opt/layerv/nhp-server/etc/tls

# Fetch etcd TLS certificates from Secrets Manager (CA + client certs for mTLS)
%{ if etcd_tls_secret_arn != "" }
echo "Fetching etcd TLS certificates..."
ETCD_TLS_SECRET=$(aws secretsmanager get-secret-value --secret-id "${etcd_tls_secret_arn}" --region "$REGION" --query SecretString --output text)

# Extract CA certificate
echo "$ETCD_TLS_SECRET" | jq -r '.caCert' > /opt/layerv/nhp-server/etc/tls/ca.crt
chmod 644 /opt/layerv/nhp-server/etc/tls/ca.crt
echo "etcd CA certificate installed"

# Extract client certificate and key for mTLS authentication
echo "$ETCD_TLS_SECRET" | jq -r '.clientCert' > /opt/layerv/nhp-server/etc/tls/client.crt
chmod 644 /opt/layerv/nhp-server/etc/tls/client.crt
echo "$ETCD_TLS_SECRET" | jq -r '.clientKey' > /opt/layerv/nhp-server/etc/tls/client.key
chmod 600 /opt/layerv/nhp-server/etc/tls/client.key
echo "etcd client certificate and key installed for mTLS"
%{ endif }

# Create remote.toml for etcd connection
# Server uses this to:
# 1. Watch /nhp/ac-registry/ prefix for AC registrations
# 2. Load shared config from /nhp/config (if seeded)
cat > /opt/layerv/nhp-server/etc/remote.toml << 'REMOTEEOF'
Provider = "etcd"
Key = "nhp/config"
Endpoints = ["${etcd_endpoint}"]
%{ if etcd_tls_secret_arn != "" }
TLS = true
CACert = "/nhp-server/etc/tls/ca.crt"
ClientCert = "/nhp-server/etc/tls/client.crt"
ClientKey = "/nhp-server/etc/tls/client.key"
%{ endif }
REMOTEEOF
echo "etcd remote.toml configured: ${etcd_endpoint}"

# ============================================================================
# etcd is used ONLY for AC registry discovery (dynamic)
# Static config (HttpConfig, plugins) comes from local files
# ============================================================================
echo "etcd configured for AC registry only (no static config seeding needed)"
%{ else }
echo "etcd not configured (multi_tenant=${multi_tenant}), using local config only"
%{ endif }

CLOUDMAP_SERVICE_ID="${cloudmap_service_id}"

cat > /opt/layerv/nhp-server/cloudmap-register.sh << 'CMEOF'
#!/bin/bash
set -e
SERVICE_ID="${cloudmap_service_id}"
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
LOCAL_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
echo "Registering instance $INSTANCE_ID ($LOCAL_IP) with Cloud Map service $SERVICE_ID"
aws servicediscovery register-instance \
  --service-id "$SERVICE_ID" \
  --instance-id "$INSTANCE_ID" \
  --attributes "AWS_INSTANCE_IPV4=$LOCAL_IP,AVAILABILITY_ZONE=$AZ,NHP_PORT=62206" \
  --region "$REGION"
echo "Instance registered successfully"
CMEOF
chmod +x /opt/layerv/nhp-server/cloudmap-register.sh

cat > /opt/layerv/nhp-server/cloudmap-deregister.sh << 'CMEOF'
#!/bin/bash
set -e
SERVICE_ID="${cloudmap_service_id}"
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
echo "Deregistering instance $INSTANCE_ID from Cloud Map service $SERVICE_ID"
aws servicediscovery deregister-instance \
  --service-id "$SERVICE_ID" \
  --instance-id "$INSTANCE_ID" \
  --region "$REGION" || true
echo "Instance deregistered"
CMEOF
chmod +x /opt/layerv/nhp-server/cloudmap-deregister.sh

cat > /opt/layerv/nhp-server/health-monitor.sh << HEALTHEOF
#!/bin/bash
# Health monitor: Updates Cloud Map status and triggers ASG replacement for persistent failures
#
# Detection timeline:
# - Startup grace: 60s (wait for container to fully initialize)
# - Check interval: 10s
# - Unhealthy threshold: 6 consecutive failures (60s)
# - After threshold: Mark instance unhealthy in ASG, triggering replacement
#
# Health check: HTTP port 8888 (same as NLB target group health check)
# This ensures consistency between NLB routing and ASG health status.
#
# This allows systemd to recover transient failures (RestartSec=5s) before
# escalating to instance replacement.

SERVICE_ID="${cloudmap_service_id}"
CHECK_INTERVAL=10
UNHEALTHY_THRESHOLD=6  # 6 checks @ 10s = 60s before ASG replacement
UNHEALTHY_COUNT=0
STARTUP_GRACE=60  # Wait for container to fully initialize before checking

# Get instance metadata (IMDSv2)
TOKEN=\$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=\$(curl -s -H "X-aws-ec2-metadata-token: \$TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
REGION=\$(curl -s -H "X-aws-ec2-metadata-token: \$TOKEN" http://169.254.169.254/latest/meta-data/placement/region)

echo "Health monitor started: instance=\$INSTANCE_ID region=\$REGION"
echo "Startup grace period: waiting \$STARTUP_GRACE seconds for container to initialize..."
sleep \$STARTUP_GRACE
echo "Startup grace complete, beginning health checks"

while true; do
  # Check if container is running AND HTTP port 8888 is responding
  # Uses HTTP GET to port 8888 (NLB uses TCP, but HTTP confirms app is serving)
  # Note: Don't use curl -f because server returns 404 on root endpoint
  if docker ps --format '{{.Names}}' | grep -q '^nhp-server\$' && \
     curl -s --connect-timeout 2 --max-time 5 http://127.0.0.1:8888/ -o /dev/null; then
    HEALTH_STATUS="HEALTHY"
    UNHEALTHY_COUNT=0
  else
    HEALTH_STATUS="UNHEALTHY"
    UNHEALTHY_COUNT=\$((UNHEALTHY_COUNT + 1))
    echo "Unhealthy check \$UNHEALTHY_COUNT/\$UNHEALTHY_THRESHOLD"
  fi

  # Update Cloud Map status
  aws servicediscovery update-instance-custom-health-status \\
    --service-id "\$SERVICE_ID" \\
    --instance-id "\$INSTANCE_ID" \\
    --status "\$HEALTH_STATUS" \\
    --region "\$REGION" 2>/dev/null || true

  # Trigger ASG replacement after persistent failures
  if [ \$UNHEALTHY_COUNT -ge \$UNHEALTHY_THRESHOLD ]; then
    echo "Unhealthy threshold reached, marking instance unhealthy in ASG"
    aws autoscaling set-instance-health \\
      --instance-id "\$INSTANCE_ID" \\
      --health-status Unhealthy \\
      --region "\$REGION" 2>&1 || echo "Failed to set instance health"
    # Continue monitoring - ASG will terminate this instance
  fi

  sleep \$CHECK_INTERVAL
done
HEALTHEOF
chmod +x /opt/layerv/nhp-server/health-monitor.sh

cat > /etc/systemd/system/nhp-health-monitor.service << SVCEOF
[Unit]
Description=NHP Health Monitor (Cloud Map)
After=network.target docker.service nhp-cloudmap-register.service

[Service]
Type=simple
ExecStart=/opt/layerv/nhp-server/health-monitor.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF

cat > /etc/systemd/system/nhp-cloudmap-register.service << SVCEOF
[Unit]
Description=Register NHP Server with Cloud Map
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/layerv/nhp-server/cloudmap-register.sh
RemainAfterExit=yes
ExecStop=/opt/layerv/nhp-server/cloudmap-deregister.sh

[Install]
WantedBy=multi-user.target
SVCEOF

ECR_REPO="${server_repo_url}"
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "${account_id}.dkr.ecr.${region}.amazonaws.com"

docker pull "$ECR_REPO:${image_tag}" || docker pull "$ECR_REPO:${environment}" || echo "Warning: Could not pull image"

# ============================================================================
# NHP Server Plugins
# Plugins are now baked into the Docker image at build time.
# See docker/Dockerfile.server for plugin build configuration.
# This eliminates Go version mismatch issues between server and plugins.
# ============================================================================
echo "Plugins are baked into the Docker image - no S3 download needed"

# ============================================================================
# Create resource.toml - registers Auth Service Provider IDs
# Plugins are statically compiled - no PluginPath needed
# The server uses AuthSvcId to look up plugins in the registry
# ============================================================================
%{ if length(server_plugins) > 0 ~}
echo "Creating resource.toml (Auth Service Provider config)..."
cat > /opt/layerv/nhp-server/etc/resource.toml << 'RESEOF'
# Auth Service Provider Configuration
# Plugins are statically compiled into the server binary
# Generated by Terraform

%{ for plugin_name in server_plugins ~}
[${plugin_name}]
# Plugin "${plugin_name}" is compiled into the server

%{ endfor ~}
RESEOF
echo "resource.toml created for plugins: ${join(", ", server_plugins)}"

# Create plugin config directories and configs
%{ for plugin_name in server_plugins ~}
mkdir -p /opt/layerv/nhp-server/plugins/${plugin_name}/etc
%{ endfor ~}

# Passcode plugin config (uses API mode with Console as auth backend)
%{ if contains(server_plugins, "passcode") ~}
cat > /opt/layerv/nhp-server/plugins/passcode/etc/config.toml << PLUGINEOF
# Passcode plugin configuration
# ResourceMode: "api" uses Console API, "file" uses local resource.toml
ResourceMode = "${resource_mode}"
# AuthUrl: Console internal NLB for API mode
AuthUrl = "${auth_url}"
# JWT/Encryption settings (optional, Console provides these)
%{ if auth_signing_key != null ~}
SigningKey = "${auth_signing_key}"
%{ endif ~}
%{ if auth_aes_key != null ~}
AesKey = "${auth_aes_key}"
%{ endif ~}
PLUGINEOF
echo "Created passcode plugin config"
%{ endif ~}
%{ else ~}
echo "No plugins configured, skipping resource.toml creation"
%{ endif ~}

cat > /etc/systemd/system/nhp-server.service << SVCEOF
[Unit]
Description=LayerV NHP Server
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
Restart=always
RestartSec=5
ExecStartPre=-/usr/bin/docker stop nhp-server
ExecStartPre=-/usr/bin/docker rm nhp-server
ExecStart=/usr/bin/docker run --rm --name nhp-server \
  --net=host \
  -v /opt/layerv/nhp-server/etc:/nhp-server/etc:ro \
  -v /opt/layerv/nhp-server/log:/nhp-server/logs \
  -v /opt/layerv/nhp-server/plugins:/nhp-server/plugins:ro \
  ${server_repo_url}:${image_tag}
ExecStop=/usr/bin/docker stop nhp-server

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable nhp-cloudmap-register nhp-health-monitor nhp-server
systemctl start nhp-cloudmap-register
systemctl start nhp-health-monitor
systemctl start nhp-server || echo "NHP server start deferred"

echo "NHP Server installation complete at $(date)"
