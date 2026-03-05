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

for _ in {1..30}; do docker info && break || sleep 2; done

# ============================================================================
# CloudWatch Agent - Publishes mem_used_percent and disk_used_percent
# Enables NHP Infrastructure dashboard panels for instance-level metrics
# ============================================================================
echo "Installing CloudWatch Agent..."
CW_AGENT_DEB="/tmp/amazon-cloudwatch-agent.deb"
curl -sfL "https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb" -o "$CW_AGENT_DEB"
if [ ! -s "$CW_AGENT_DEB" ]; then
  echo "WARNING: CloudWatch Agent download failed, skipping CW Agent install"
else
  # Retry dpkg install - unattended-upgrades holds the dpkg lock on fresh instances
  for dpkg_attempt in $(seq 1 10); do
    if dpkg -i "$CW_AGENT_DEB"; then
      break
    fi
    if [ "$dpkg_attempt" -eq 10 ]; then
      echo "WARNING: dpkg -i CloudWatch Agent failed after 10 attempts, skipping"
      rm -f "$CW_AGENT_DEB"
      break
    fi
    echo "dpkg locked (attempt $dpkg_attempt/10), retrying in $${dpkg_attempt}s..."
    sleep "$dpkg_attempt"
  done
  rm -f "$CW_AGENT_DEB"

  mkdir -p /opt/aws/amazon-cloudwatch-agent/etc
  cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'CWEOF'
{
  "metrics": {
    "namespace": "LayerV/NHP",
    "metrics_collected": {
      "mem": {
        "measurement": ["mem_used_percent"],
        "metrics_collection_interval": 60
      },
      "disk": {
        "measurement": ["disk_used_percent"],
        "resources": ["/"],
        "metrics_collection_interval": 60
      }
    },
    "append_dimensions": {
      "InstanceId": "$${aws:InstanceId}",
      "AutoScalingGroupName": "$${aws:AutoScalingGroupName}"
    }
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/opt/layerv/nhp-server/log/server-*.log",
            "log_group_name": "/layerv/nhp/${environment}/${cell_id}/server",
            "log_stream_name": "{instance_id}/server",
            "timezone": "UTC"
          }
        ]
      }
    }
  }
}
CWEOF

  if [ -x /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl ]; then
    /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
      -a fetch-config -m ec2 \
      -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s
    echo "CloudWatch Agent installed and started"
  else
    echo "WARNING: CloudWatch Agent binary not found, skipping configuration"
  fi
fi

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
LogLevel = ${log_level}
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

# Cloud Map configuration for server health discovery.
# Used to filter stale AC assignments pointing to terminated servers.
%{ if cloudmap_enabled ~}
[CloudMap]
Enabled = true
Region = "${dynamodb_region}"
NamespaceName = "${cloudmap_namespace_name}"
ServiceName = "${cloudmap_service_name}"
CacheTTL = 30
OperationTimeout = 5
%{ endif ~}
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
%{ if multi_tenant && storage_backend == "etcd" && etcd_endpoint != "" }
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
echo "etcd not configured (storage_backend=${storage_backend}), using local config only"
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
# Extract registry domain from repo URL (handles cross-account ECR where images
# live in sandbox but instances run in prod).
ECR_REGISTRY="$(echo "$ECR_REPO" | cut -d/ -f1)"
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$ECR_REGISTRY"

# ============================================================================
# Blue/Green Deployment: Detect Deploy Color
# Instances are tagged with DeployColor (blue or green) by the ASG.
# Green instances read from a different SSM parameter for their image tag.
#
# Detection strategy (in order):
# 1. IMDS instance tags (instant, requires instance_metadata_tags=enabled)
# 2. EC2 DescribeTags API with exponential backoff (handles IMDS unavailable)
# ============================================================================
echo "Detecting deployment color from instance tags..."

# Try IMDS first (instant, no API dependency)
# Requires $TOKEN from IMDSv2 session established earlier in this script
get_deploy_color_from_imds() {
    DEPLOY_COLOR=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
      http://169.254.169.254/latest/meta-data/tags/instance/DeployColor 2>/dev/null) || DEPLOY_COLOR=""
    if [ -n "$DEPLOY_COLOR" ] && [ "$DEPLOY_COLOR" != "None" ] && [ "$DEPLOY_COLOR" != "Not Found" ]; then
        echo "Detected deployment color from IMDS: $DEPLOY_COLOR"
        return 0
    fi
    DEPLOY_COLOR=""
    return 1
}

# Fallback: EC2 DescribeTags API with exponential backoff
get_deploy_color_from_api() {
    local max_attempts=12
    local delay=5
    local max_delay=30
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        DEPLOY_COLOR=$(aws ec2 describe-tags \
          --filters "Name=resource-id,Values=$INSTANCE_ID" "Name=key,Values=DeployColor" \
          --query "Tags[0].Value" \
          --output text \
          --region "$REGION" 2>/dev/null) || DEPLOY_COLOR=""

        # Check if we got a valid color (not empty, not "None")
        if [ -n "$DEPLOY_COLOR" ] && [ "$DEPLOY_COLOR" != "None" ]; then
            echo "Detected deployment color from API: $DEPLOY_COLOR (attempt $attempt)"
            return 0
        fi

        if [ $attempt -lt $max_attempts ]; then
            echo "DeployColor tag not found (attempt $attempt/$max_attempts), retrying in $${delay}s..."
            sleep $delay
            attempt=$((attempt + 1))
            delay=$((delay * 2))
            if [ $delay -gt $max_delay ]; then
                delay=$max_delay
            fi
        else
            echo "DeployColor tag not found after $max_attempts attempts"
            return 1
        fi
    done
}

get_deploy_color_with_retry() {
    get_deploy_color_from_imds && return 0
    echo "IMDS tag not available, falling back to EC2 API..."
    get_deploy_color_from_api
}

# Try to detect deploy color with retries
ENABLE_BLUE_GREEN="${enable_blue_green}"

if get_deploy_color_with_retry; then
    echo "Using deployment color: $DEPLOY_COLOR"
else
    if [ "$ENABLE_BLUE_GREEN" = "true" ]; then
        # When blue/green is enabled, tag detection failure is a critical error.
        # Defaulting to blue could cause green instances to use wrong image tag.
        echo "ERROR: DeployColor tag not found but blue/green deployment is enabled!"
        echo "ERROR: This instance may be misconfigured. Check ASG tag propagation."
        echo "ERROR: Failing hard to prevent incorrect deployment."
        exit 1
    else
        # When blue/green is disabled, default to blue for backward compatibility
        DEPLOY_COLOR="blue"
        echo "DeployColor tag not found, defaulting to: $DEPLOY_COLOR"
    fi
fi

# ============================================================================
# SSM-based Image Tag Lookup
# Read the image tag from SSM Parameter Store for CI/CD-driven deployments.
# Blue and green ASGs use different SSM parameters for independent deployments.
# ============================================================================
BLUE_SSM_PARAM="${ssm_image_tag_parameter}"

# Green ASG uses a different SSM parameter path
if [ "$DEPLOY_COLOR" = "green" ]; then
  SSM_IMAGE_TAG_PARAM="/${environment}/nhp/server/green-image-tag"
  echo "Green deployment: using SSM parameter $SSM_IMAGE_TAG_PARAM"
else
  SSM_IMAGE_TAG_PARAM="$BLUE_SSM_PARAM"
  echo "Blue deployment: using SSM parameter $SSM_IMAGE_TAG_PARAM"
fi

echo "Fetching image tag from SSM parameter: $SSM_IMAGE_TAG_PARAM"
IMAGE_TAG=$(aws ssm get-parameter \
  --name "$SSM_IMAGE_TAG_PARAM" \
  --region "$REGION" \
  --query "Parameter.Value" \
  --output text) || {
  echo "ERROR: Failed to fetch image tag from SSM parameter: $SSM_IMAGE_TAG_PARAM"
  echo "SSM is the source of truth for image tags. Ensure the parameter exists and has a value."
  exit 1
}

if [ -z "$IMAGE_TAG" ] || [ "$IMAGE_TAG" = "None" ] || [ "$IMAGE_TAG" = "initial" ]; then
  echo "ERROR: SSM parameter $SSM_IMAGE_TAG_PARAM has no valid image tag (got: '$IMAGE_TAG')"
  echo "Deploy an image first via CI/CD before launching instances."
  exit 1
fi

echo "Using image tag from SSM: $IMAGE_TAG"

docker pull "$ECR_REPO:$IMAGE_TAG" || {
  echo "ERROR: Could not pull server image with tag $IMAGE_TAG"
  echo "This likely means the image hasn't been built yet for this commit"
  exit 1
}

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
# Plugin "${plugin_name}" is compiled into the server (no external path needed)
PluginPath = ""

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

# ============================================================================
# QURL Plugin Configuration
# Fetches service token from Secrets Manager and prepares environment variables
# for the Docker container. The QURL plugin handles token resolution for the
# qurl.link → qurl.site authentication flow.
# ============================================================================
%{ if qurl_enabled ~}
echo "Fetching QURL service token from Secrets Manager..."
QURL_SERVICE_TOKEN=$(aws secretsmanager get-secret-value \
  --secret-id "${qurl_service_token_secret_arn}" \
  --region "$REGION" \
  --query SecretString --output text) || {
    echo "ERROR: Failed to fetch QURL service token from Secrets Manager"
    exit 1
}
if [ -z "$QURL_SERVICE_TOKEN" ]; then
  echo "ERROR: QURL service token is empty"
  exit 1
fi
echo "QURL plugin configured: api_url=${qurl_api_url}, allowed_domain=${qurl_allowed_redirect_domain}"
%{ endif ~}

# ============================================================================
# Create environment files for systemd service
# Security: Secrets are stored in a separate file from non-sensitive config.
# This follows defense-in-depth - if the main env file is exposed, secrets
# remain protected in a dedicated file with strict permissions.
#
# Files created:
# - /opt/layerv/nhp-server/etc/env: Non-sensitive runtime config (644 ok)
# - /opt/layerv/nhp-server/etc/secrets.env: Sensitive credentials (600 required)
# ============================================================================

%{ if cloudfront_cidrs_ssm_parameter != null ~}
# Fetch CloudFront origin-facing CIDRs for trusted proxy configuration
echo "Fetching CloudFront CIDRs from SSM..."
CF_CIDRS=$(aws ssm get-parameter \
  --name "${cloudfront_cidrs_ssm_parameter}" \
  --region "$REGION" \
  --query "Parameter.Value" --output text) || {
  echo "FATAL: Failed to fetch CloudFront CIDRs from SSM. Server would not trust any proxies."
  exit 1
}
%{ endif ~}

# Non-sensitive environment variables
cat > /opt/layerv/nhp-server/etc/env << ENVEOF
NHP_IMAGE_TAG=$IMAGE_TAG
NHP_ECR_REPO=${server_repo_url}
NHP_ENVIRONMENT=${environment}
NHP_CELL_ID=${cell_id}
%{ if qurl_enabled ~}
QURL_API_URL=${qurl_api_url}
QURL_ALLOWED_REDIRECT_DOMAIN=${qurl_allowed_redirect_domain}
QURL_API_TIMEOUT=${qurl_api_timeout}
QURL_MAX_IDLE_CONNS=${qurl_max_idle_conns}
QURL_MAX_IDLE_CONNS_PER_HOST=${qurl_max_idle_conns_per_host}
QURL_IDLE_CONN_TIMEOUT=${qurl_idle_conn_timeout}
%{ endif ~}
%{ if cloudfront_cidrs_ssm_parameter != null ~}
NHP_TRUSTED_PROXY_CIDRS=$CF_CIDRS
%{ endif ~}
%{ if cors_allowed_origins != "" ~}
NHP_CORS_ALLOWED_ORIGINS=${cors_allowed_origins}
%{ endif ~}
ENVEOF
chmod 644 /opt/layerv/nhp-server/etc/env
echo "Created environment file with image tag: $IMAGE_TAG"

# Sensitive secrets - separate file with restricted permissions
# Create with restrictive permissions before writing any content
touch /opt/layerv/nhp-server/etc/secrets.env
chmod 600 /opt/layerv/nhp-server/etc/secrets.env

# Fetch cookie session keys from Secrets Manager (shared across all instances)
# Secret contains JSON with current + optional previous key pairs for rotation.
# Base64-encoded before writing to env file to avoid shell/heredoc quoting issues.
echo "Fetching cookie session keys from Secrets Manager..."
COOKIE_KEYS_JSON=$(aws secretsmanager get-secret-value \
  --secret-id "${cookie_secret_arn}" \
  --region "$REGION" \
  --query SecretString --output text) || {
    echo "ERROR: Failed to fetch cookie session keys from Secrets Manager"
    exit 1
}
if [ -z "$COOKIE_KEYS_JSON" ]; then
  echo "ERROR: Cookie session keys secret is empty"
  exit 1
fi

# Validate JSON structure has required fields
echo "$COOKIE_KEYS_JSON" | python3 -c "
import json, sys
d = json.loads(sys.stdin.read())
assert 'current' in d, 'missing current key set'
assert 'auth_key' in d['current'], 'missing current.auth_key'
assert 'encrypt_key' in d['current'], 'missing current.encrypt_key'
" || {
  echo "ERROR: Cookie secret JSON missing required fields (current.auth_key, current.encrypt_key)"
  exit 1
}

# Base64-encode for safe transport through env file and docker --env-file
NHP_COOKIE_KEYS=$(echo -n "$COOKIE_KEYS_JSON" | base64 -w 0)

cat > /opt/layerv/nhp-server/etc/secrets.env << SECRETSEOF
NHP_COOKIE_KEYS=$NHP_COOKIE_KEYS
%{ if qurl_enabled ~}
# QURL service authentication token - fetched from Secrets Manager
# This file contains sensitive credentials and should NOT be readable by other users
QURL_SERVICE_TOKEN=$QURL_SERVICE_TOKEN
%{ endif ~}
SECRETSEOF
echo "Created secrets file with cookie keys and service credentials"

cat > /etc/systemd/system/nhp-server.service << 'SVCEOF'
[Unit]
Description=LayerV NHP Server
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
Restart=always
RestartSec=5
# Non-sensitive config (image tag, repo, timeouts)
EnvironmentFile=/opt/layerv/nhp-server/etc/env
# Sensitive secrets (service tokens) - separate file with restricted permissions
EnvironmentFile=/opt/layerv/nhp-server/etc/secrets.env
ExecStartPre=-/usr/bin/docker stop nhp-server
ExecStartPre=-/usr/bin/docker rm nhp-server
ExecStart=/bin/bash -c "docker run --rm --name nhp-server \
  --net=host \
  -v /opt/layerv/nhp-server/etc:/nhp-server/etc:ro \
  -v /opt/layerv/nhp-server/log:/nhp-server/logs \
  -v /opt/layerv/nhp-server/plugins:/nhp-server/plugins:ro \
  --env-file /opt/layerv/nhp-server/etc/env \
  --env-file /opt/layerv/nhp-server/etc/secrets.env \
  $${NHP_ECR_REPO}:$${NHP_IMAGE_TAG}"
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
