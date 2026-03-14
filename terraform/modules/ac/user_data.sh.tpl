#!/bin/bash
# NHP AC User Data Script - Standalone AC for customer deployments
#
# This template configures a standalone AC that protects customer resources.
set -ex

exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
echo "Starting NHP AC installation at $(date)"

export DEBIAN_FRONTEND=noninteractive

# Define retry helper inline (needed before AWS CLI and REGION are available)
mkdir -p /home/ubuntu/scripts
retry_with_backoff() {
    local max_attempts=$1 delay=$2 max_delay=$3; shift 3
    local attempt=1
    while true; do
        if "$@"; then return 0; fi
        if [ "$attempt" -ge "$max_attempts" ]; then echo "ERROR: $* failed after $max_attempts attempts"; return 1; fi
        echo "$* failed (attempt $attempt/$max_attempts), retrying in $${delay}s..."
        sleep "$delay"; attempt=$((attempt + 1)); delay=$((delay * 2))
        if [ "$delay" -gt "$max_delay" ]; then delay=$max_delay; fi
    done
}
apt_get_with_retry() { retry_with_backoff 10 2 60 apt-get "$@"; }

apt_get_with_retry update -y
# Note: awscli package deprecated in Ubuntu 24.04, using unzip + curl for AWS CLI v2
apt_get_with_retry install -y jq curl docker.io gettext-base iptables ipset unzip
# iptables-persistent is pre-seeded to skip interactive prompts during install
echo iptables-persistent iptables-persistent/autosave_v4 boolean false | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections
apt_get_with_retry install -y iptables-persistent

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
            "file_path": "/opt/layerv/nhp-ac/logs/ac-*.log",
            "log_group_name": "/layerv/nhp/${environment}/ac",
            "log_stream_name": "{instance_id}/ac",
            "timezone": "UTC"
          },
          {
            "file_path": "/opt/layerv/nhp-ac/logs/nhp_accept-*.log",
            "log_group_name": "/layerv/nhp/${environment}/ac",
            "log_stream_name": "{instance_id}/nhp-accept",
            "timezone": "UTC"
          },
          {
            "file_path": "/opt/layerv/nhp-ac/logs/nhp_deny-*.log",
            "log_group_name": "/layerv/nhp/${environment}/ac",
            "log_stream_name": "{instance_id}/nhp-deny",
            "timezone": "UTC"
          },
          {
            "file_path": "/opt/layerv/nhp-ac/logs/nhp_forward-*.log",
            "log_group_name": "/layerv/nhp/${environment}/ac",
            "log_stream_name": "{instance_id}/nhp-forward",
            "timezone": "UTC"
          },
          {
            "file_path": "/var/log/traefik/access.log",
            "log_group_name": "/layerv/nhp/${environment}/ac",
            "log_stream_name": "{instance_id}/traefik-access",
            "timezone": "UTC"
          },
          {
            "file_path": "/var/log/traefik/traefik.log",
            "log_group_name": "/layerv/nhp/${environment}/ac",
            "log_stream_name": "{instance_id}/traefik",
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

REGION="${region}"
ACCOUNT_ID="${account_id}"

# Download shared helper library now that REGION is available
%{ if lib_script_s3_uri != "" }
aws s3 cp "${lib_script_s3_uri}" /home/ubuntu/scripts/lib.sh --region "$REGION" 2>/dev/null || true
if [ -f /home/ubuntu/scripts/lib.sh ]; then
    source /home/ubuntu/scripts/lib.sh
fi
%{ endif }

TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
LOCAL_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)

%{ if enable_egress_eips ~}
# ============================================================================
# Elastic IP Association
# Claim an unassociated EIP from the pool for stable egress IP.
# Customers whitelist these IPs on their origin firewalls.
# ============================================================================
echo "Attempting to claim an Elastic IP from pool ${eip_pool_tag}..."
EIP_CLAIMED=false
for attempt in 1 2 3 4 5; do
  ALLOC_ID=$(aws ec2 describe-addresses \
    --filters "Name=tag:EIPPool,Values=${eip_pool_tag}" \
    --query 'Addresses[?AssociationId==`null`].AllocationId | [0]' \
    --output text --region "$REGION")

  if [ "$ALLOC_ID" = "None" ] || [ -z "$ALLOC_ID" ]; then
    echo "WARNING: No available EIPs in pool (attempt $attempt/5)"
    sleep $(( RANDOM % 3 + attempt * 2 ))
    continue
  fi

  if aws ec2 associate-address \
    --allocation-id "$ALLOC_ID" \
    --instance-id "$INSTANCE_ID" \
    --region "$REGION"; then
    echo "Successfully claimed EIP allocation $ALLOC_ID"
    sleep 2
    PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
      http://169.254.169.254/latest/meta-data/public-ipv4)
    echo "EIP associated. New public IP: $PUBLIC_IP"
    EIP_CLAIMED=true
    break
  else
    echo "EIP $ALLOC_ID was claimed by another instance (attempt $attempt/5), retrying..."
    sleep $(( RANDOM % 3 + attempt * 2 ))
  fi
done

if [ "$EIP_CLAIMED" = "false" ]; then
  echo "FATAL: Could not claim an EIP after 5 attempts. Instance cannot serve traffic without a stable IP."
  echo "Check that enough EIPs are allocated (ac_max_capacity) and AWS EIP quota is sufficient."
  # Cooldown before exit to prevent ASG from rapidly cycling replacement instances
  # when EIP pool is genuinely exhausted (e.g., all allocated EIPs are in use).
  sleep 120
  exit 1
fi
%{ endif ~}

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
GREEN_SSM_PARAM="${ssm_green_image_tag_parameter}"
if [ "$DEPLOY_COLOR" = "green" ] && [ -n "$GREEN_SSM_PARAM" ]; then
  SSM_IMAGE_TAG_PARAM="$GREEN_SSM_PARAM"
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

echo "Pulling AC image from ECR..."
docker pull "$ECR_REPO:$IMAGE_TAG" || {
  echo "ERROR: Could not pull AC image with tag $IMAGE_TAG"
  echo "This likely means the image hasn't been built yet for this commit"
  exit 1
}

# Extract binaries from Docker image
echo "Extracting binaries from AC image..."
CONTAINER_ID=$(docker create "$ECR_REPO:$IMAGE_TAG")

# Extract Traefik binary
docker cp "$CONTAINER_ID:/usr/local/bin/traefik" /usr/local/bin/traefik
chmod +x /usr/local/bin/traefik

# Extract nhp-acd binary and config
docker cp "$CONTAINER_ID:/nhp-ac" /opt/layerv/nhp-ac-extracted || true
if [ -d "/opt/layerv/nhp-ac-extracted" ]; then
  cp -r /opt/layerv/nhp-ac-extracted/* /opt/layerv/nhp-ac/
fi

# Remove server.toml from release artifact - cloud mode uses ServerEndpoint in config.toml
# The release artifact may contain stale development server addresses
rm -f /opt/layerv/nhp-ac/etc/server.toml

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
# - tempset: temporary entries for initial knock (configurable timeout, default 5s)
# - defaultset: active sessions after successful knock (configurable timeout, default 120s)
# - defaultset_down: downstream tracking (defaultset timeout + 1s)
ipset -exist create defaultset hash:ip,port,ip counters maxelem 1000000 timeout ${ipset_default_timeout}
ipset -exist create defaultset_down hash:ip,port,ip counters maxelem 1000000 timeout $((${ipset_default_timeout} + 1))
ipset -exist create tempset hash:net,port counters maxelem 1000000 timeout ${ipset_temp_timeout}

echo "IPv4 ipsets created successfully (defaultset timeout=${ipset_default_timeout}s, tempset timeout=${ipset_temp_timeout}s)"

# Create IPv6 ipsets (required for clients connecting via IPv6)
# The NHP AC code uses *_v6 suffixed sets for IPv6 addresses.
# Without these, ipset add fails and the NHP knock returns "ipset operation failed".
IP6TABLES=$(which ip6tables 2>/dev/null)
IPSET6_OK=0
if [ -n "$IP6TABLES" ]; then
    echo "Setting up IPv6 ipsets..."
    ipset -exist create defaultset_v6 hash:ip,port,ip family inet6 counters maxelem 1000000 timeout ${ipset_default_timeout} 2>/dev/null || true
    ipset -exist create defaultset_down_v6 hash:ip,port,ip family inet6 counters maxelem 1000000 timeout $((${ipset_default_timeout} + 1)) 2>/dev/null || true
    ipset -exist create tempset_v6 hash:net,port family inet6 counters maxelem 1000000 timeout ${ipset_temp_timeout} 2>/dev/null || true

    # Verify IPv6 ipset creation
    IPSET6_OK=1
    ipset list defaultset_v6 > /dev/null 2>&1 || IPSET6_OK=0
    if [ $IPSET6_OK -eq 1 ]; then
        echo "IPv6 ipsets created successfully"
    else
        echo "WARNING: IPv6 ipset creation failed, IPv6 clients will not be supported"
    fi
fi

# Apply IPv4 iptables rules atomically via iptables-restore.
# This avoids the race condition where individual iptables commands leave
# a brief window with incomplete rules, and ensures crash recovery leaves
# either the old complete ruleset or the new complete ruleset in place.
echo "Applying IPv4 iptables rules atomically via iptables-restore..."

# Two-stage evaluation: Terraform's templatefile() substitutes variables like
# vpc_cidr and ipset_*_timeout when rendering this template to the final
# user-data script. The single-quoted heredoc delimiter (<<'IPTABLES_RULES')
# prevents bash from expanding anything at runtime, but by that point Terraform
# has already replaced all template references with their literal values.
if ! iptables-restore <<'IPTABLES_RULES'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:NHP_DENY - [0:0]
-A NHP_DENY -j LOG --log-prefix "[NHP-DENY] " --log-level 6 --log-ip-options
-A NHP_DENY -j DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -s ${vpc_cidr} --dport 22 -j ACCEPT
-A INPUT -p tcp -s ${vpc_cidr} --dport 8080 -j ACCEPT
-A INPUT -p tcp -s ${vpc_cidr} --dport 8888 -j ACCEPT
-A INPUT -m state --state ESTABLISHED -j ACCEPT
-A INPUT -m set --match-set tempset src,dst -j SET --add-set defaultset src,dst,dst
-A INPUT -m set --match-set defaultset src,dst,dst -j SET --add-set defaultset_down src,dst,dst
-A INPUT -m set --match-set defaultset src,dst,dst -j LOG --log-prefix "[NHP-ACCEPT] " --log-level 6 --log-ip-options
-A INPUT -m set --match-set defaultset src,dst,dst -j ACCEPT
-A INPUT -m set --match-set tempset src,dst -j ACCEPT
-A INPUT -j NHP_DENY
-A FORWARD -m set --match-set defaultset src,dst,dst -j SET --add-set defaultset_down src,dst,dst
-A FORWARD -m set --match-set defaultset src,dst,dst -j LOG --log-prefix "[NHP-FORWARD] " --log-level 6 --log-ip-options
-A FORWARD -m set --match-set defaultset src,dst,dst -j ACCEPT
-A FORWARD -m state --state ESTABLISHED -j ACCEPT
-A FORWARD -j NHP_DENY
COMMIT
IPTABLES_RULES
then
    echo "ERROR: iptables-restore failed — new IPv4 rules not applied, previous rules retained"
    exit 1
fi

echo "IPv4 NHP firewall setup complete (applied atomically)"

# Persist IPv4 rules across reboots via iptables-persistent
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
echo "IPv4 iptables rules persisted to /etc/iptables/rules.v4"

# ============================================================================
# IPv6 firewall rules (mirrors IPv4 NHP ipset rules using *_v6 sets)
# Applied atomically via ip6tables-restore for the same safety guarantees.
#
# Note: IPv4 VPC CIDR rules (SSH/8080/8888) are intentionally omitted here.
# AWS VPC CIDRs are IPv4-only; internal traffic uses IPv4 addressing.
# ============================================================================
if [ -n "$IP6TABLES" ] && [ $IPSET6_OK -eq 1 ]; then
    echo "Applying IPv6 iptables rules atomically via ip6tables-restore..."

    if ! ip6tables-restore <<'IP6TABLES_RULES'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:NHP_DENY - [0:0]
-A NHP_DENY -j LOG --log-prefix "[NHP-DENY6] " --log-level 6 --log-ip-options
-A NHP_DENY -j DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED -j ACCEPT
-A INPUT -m set --match-set tempset_v6 src,dst -j SET --add-set defaultset_v6 src,dst,dst
-A INPUT -m set --match-set defaultset_v6 src,dst,dst -j SET --add-set defaultset_down_v6 src,dst,dst
-A INPUT -m set --match-set defaultset_v6 src,dst,dst -j LOG --log-prefix "[NHP-ACCEPT6] " --log-level 6 --log-ip-options
-A INPUT -m set --match-set defaultset_v6 src,dst,dst -j ACCEPT
-A INPUT -m set --match-set tempset_v6 src,dst -j ACCEPT
-A INPUT -j NHP_DENY
-A FORWARD -m set --match-set defaultset_v6 src,dst,dst -j SET --add-set defaultset_down_v6 src,dst,dst
-A FORWARD -m set --match-set defaultset_v6 src,dst,dst -j LOG --log-prefix "[NHP-FORWARD6] " --log-level 6 --log-ip-options
-A FORWARD -m set --match-set defaultset_v6 src,dst,dst -j ACCEPT
-A FORWARD -m state --state ESTABLISHED -j ACCEPT
-A FORWARD -j NHP_DENY
COMMIT
IP6TABLES_RULES
    then
        echo "ERROR: ip6tables-restore failed — new IPv6 rules not applied, previous rules retained"
        exit 1
    fi

    # Persist IPv6 rules across reboots
    ip6tables-save > /etc/iptables/rules.v6
    echo "IPv6 NHP firewall setup complete (applied atomically)"
else
    echo "Skipping IPv6 firewall setup (ip6tables not available or IPv6 ipsets failed)"
fi

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

:msg,contains,"[NHP-ACCEPT" ?NHPAcceptFile;NHPFormat
& stop
:msg,contains,"[NHP-FORWARD" ?NHPForwardFile;NHPFormat
& stop
:msg,contains,"[NHP-DENY" ?NHPDenyFile;NHPFormat
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
apt_get_with_retry install -y python3-cryptography

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
LogLevel = ${log_level}
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

# ============================================================================
# QURL Router Plugin Configuration
# Fetches service token from Secrets Manager for QURL API authentication
# ============================================================================
%{ if qurl_router_enabled && qurl_service_token_secret_arn != null ~}
echo "Fetching QURL service token from Secrets Manager..."
# Use timeout to prevent hanging if Secrets Manager is unreachable (30s is sufficient for retries)
QURL_SERVICE_TOKEN=$(timeout 30 aws secretsmanager get-secret-value \
  --secret-id "${qurl_service_token_secret_arn}" \
  --region "$REGION" \
  --query SecretString --output text) || {
    echo "ERROR: Failed to fetch QURL service token from Secrets Manager (timeout or auth failure)"
    exit 1
}
if [ -z "$QURL_SERVICE_TOKEN" ]; then
  echo "ERROR: QURL service token is empty"
  exit 1
fi
echo "QURL service token retrieved successfully"
%{ endif ~}

# ============================================================================
# Centralized TLS Certificate Management
# Fetches TLS certificate from Secrets Manager instead of per-instance ACME.
# This scales to thousands of ACs without hitting Let's Encrypt rate limits.
# NOTE: This is an interim solution - consider Vault PKI for production at scale.
# ============================================================================
%{ if centralized_cert_enabled && centralized_cert_secret_arn != "" ~}
echo "Fetching centralized TLS certificate from Secrets Manager..."
mkdir -p /home/ubuntu/traefik/certs
chmod 700 /home/ubuntu/traefik/certs

# Fetch certificate secret and write directly to files (avoids secret in shell variables/process memory)
# First fetch to temp file, validate, then extract components
CERT_TEMP=$(mktemp)
trap "rm -f $CERT_TEMP" EXIT

timeout 30 aws secretsmanager get-secret-value \
  --secret-id "${centralized_cert_secret_arn}" \
  --region "$REGION" \
  --query SecretString --output text > "$CERT_TEMP" || {
    echo "ERROR: Failed to fetch TLS certificate from Secrets Manager"
    rm -f "$CERT_TEMP"
    exit 1
}

# Validate we got actual certificate data (not placeholder)
if jq -e '.status == "pending"' "$CERT_TEMP" > /dev/null 2>&1; then
    echo "ERROR: Certificate not yet generated. Run: aws lambda invoke --function-name ${acme_lambda_function_name} --payload '{\"force_renew\":true}' /dev/stdout"
    rm -f "$CERT_TEMP"
    exit 1
fi

# Extract and write certificate components directly from temp file
# Use jq -e to fail if field is null/missing (prevents writing "null" to files)
jq -e -r '.private_key // empty' "$CERT_TEMP" > /home/ubuntu/traefik/certs/privkey.pem || {
    echo "ERROR: Certificate secret missing 'private_key' field"
    rm -f "$CERT_TEMP"
    exit 1
}
jq -e -r '.certificate // empty' "$CERT_TEMP" > /home/ubuntu/traefik/certs/cert.pem || {
    echo "ERROR: Certificate secret missing 'certificate' field"
    rm -f "$CERT_TEMP"
    exit 1
}
jq -e -r '.chain // empty' "$CERT_TEMP" > /home/ubuntu/traefik/certs/chain.pem || {
    echo "ERROR: Certificate secret missing 'chain' field"
    rm -f "$CERT_TEMP"
    exit 1
}
jq -e -r '.fullchain // empty' "$CERT_TEMP" > /home/ubuntu/traefik/certs/fullchain.pem || {
    echo "ERROR: Certificate secret missing 'fullchain' field"
    rm -f "$CERT_TEMP"
    exit 1
}

# Securely delete temp file (keep EXIT trap - rm -f on non-existent file is harmless)
rm -f "$CERT_TEMP"

# Secure permissions - only ubuntu (Traefik user) can read private key
chmod 600 /home/ubuntu/traefik/certs/privkey.pem
chmod 644 /home/ubuntu/traefik/certs/cert.pem
chmod 644 /home/ubuntu/traefik/certs/chain.pem
chmod 644 /home/ubuntu/traefik/certs/fullchain.pem
chown ubuntu:ubuntu /home/ubuntu/traefik/certs /home/ubuntu/traefik/certs/*.pem

# Verify certificate is valid and log info (single openssl invocation)
CERT_INFO=$(openssl x509 -in /home/ubuntu/traefik/certs/cert.pem -noout -checkend 0 -subject -enddate 2>/dev/null) || {
    echo "ERROR: Certificate has expired or is invalid"
    exit 1
}
CERT_SUBJECT=$(echo "$CERT_INFO" | grep '^subject=' | cut -d= -f2-)
CERT_EXPIRY=$(echo "$CERT_INFO" | grep '^notAfter=' | cut -d= -f2)
echo "Certificate loaded: $CERT_SUBJECT, expires: $CERT_EXPIRY"

%{ endif ~}

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
    # ProxyProtocol required because NLB target group has proxy_protocol_v2 enabled
    # This affects ALL traffic including health checks
    [entryPoints.traefik.proxyProtocol]
      trustedIPs = ["${vpc_cidr}"]

%{ if centralized_cert_enabled ~}
# Centralized certificate from Secrets Manager (no per-instance ACME)
# Certificate files are fetched at boot time and stored locally
# NOTE: This is an interim solution - consider Vault PKI for production at scale
[tls.stores]
  [tls.stores.default]
    [tls.stores.default.defaultCertificate]
      certFile = "/home/ubuntu/traefik/certs/fullchain.pem"
      keyFile = "/home/ubuntu/traefik/certs/privkey.pem"
%{ else ~}
# Per-instance ACME certificate resolver (Let's Encrypt)
# WARNING: This does not scale well - use centralized_cert_enabled for large deployments
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
%{ endif ~}

[providers.file]
  directory = "/home/ubuntu/traefik/"
  watch = true

%{ if qurl_router_enabled ~}
# QURL Router Plugin - routes *.qurl.site requests to target backends
[experimental.localPlugins]
  [experimental.localPlugins.qurl-router]
    moduleName = "github.com/traefik/qurl-router"
%{ else ~}
# NOTE: [experimental.localPlugins] section is managed by traefik-plugins repo via SSM
# The traefik-plugins deployment will add this section with plugin definitions
%{ endif ~}
TRAEFIKEOF

# Create Traefik dynamic configuration (routes to nhp-acd and NHP Server)
cat > /home/ubuntu/traefik/dynamic.toml << DYNAMICEOF
# Traefik Dynamic Configuration
#
# Router priority hierarchy (higher number = matched first):
#   15 - qurl-site          *.qurl.site subdomain routing
#   10 - nhp-plugins        /plugins/* to NHP Server
#   10 - prod-*/addtls-*    production domain routes (when ACME enabled)
#    2 - custom-domain-catchall  custom domains via qurl-router middleware
#    1 - nhp-ac             fallback to nhp-acd for protected resource access

[http.routers]
  # Route /plugins to NHP Server for passcode login and auth
  [http.routers.nhp-plugins]
    rule = "PathPrefix(\`/plugins\`)"
    service = "nhp-server"
    entryPoints = ["https"]
    priority = 10
%{ if centralized_cert_enabled ~}
    # TLS uses centralized certificate from default store
    [http.routers.nhp-plugins.tls]
%{ else ~}
    [http.routers.nhp-plugins.tls]
      certResolver = "letsencrypt"
      [[http.routers.nhp-plugins.tls.domains]]
        main = "${domain_name}"
        sans = ["*.${domain_name}"]
%{ endif ~}

  # Default route to nhp-acd for protected resource access
  [http.routers.nhp-ac]
    rule = "PathPrefix(\`/\`)"
    service = "nhp-ac"
    entryPoints = ["https"]
    priority = 1
%{ if centralized_cert_enabled ~}
    # TLS uses centralized certificate from default store
    [http.routers.nhp-ac.tls]
%{ else ~}
    [http.routers.nhp-ac.tls]
      certResolver = "letsencrypt"
      [[http.routers.nhp-ac.tls.domains]]
        main = "${domain_name}"
        sans = ["*.${domain_name}"]
%{ endif ~}

[http.services]
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
# NOTE: When centralized_cert_enabled=true, ACME is disabled. Production domains
# would need their own centralized certificate configuration.
%{ if length(production_domains) > 0 && !centralized_cert_enabled }
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
# NOTE: When centralized_cert_enabled=true, ACME is disabled. Additional TLS domains
# must be included in the centralized certificate's SAN list.
%{ if length(additional_tls_domains) > 0 && !centralized_cert_enabled }
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

# ============================================================================
# QURL Router Plugin Dynamic Configuration
# Routes *.qurl.site requests through the QURL router plugin
# ============================================================================
%{ if qurl_router_enabled ~}
cat >> /home/ubuntu/traefik/dynamic.toml << QURLDYNAMICEOF

# QURL Router - routes *.${qurl_router_base_domain} to target backends
[http.middlewares.qurl-router.plugin.qurl-router]
  qurlApiUrl = "${qurl_router_api_url}"
  serviceToken = "$QURL_SERVICE_TOKEN"
  baseDomain = "${qurl_router_base_domain}"
  cacheTtl = ${qurl_router_cache_ttl}
  negativeCacheTtl = ${qurl_router_negative_cache_ttl}
  maxCacheSize = ${qurl_router_max_cache_size}
  apiTimeout = ${qurl_router_api_timeout}
  proxyTimeout = ${qurl_router_proxy_timeout}
  cacheShards = ${qurl_router_cache_shards}
  circuitBreakerThreshold = 5
  circuitBreakerTimeout = 30
  evictionPercent = 10

[http.routers.qurl-site]
  rule = "HostRegexp(\`^.+\\\\.${qurl_router_base_domain}\$\`)"
  service = "qurl-backend"
  entryPoints = ["https"]
  priority = 15
  middlewares = ["qurl-router"]
%{ if centralized_cert_enabled ~}
  # TLS uses centralized certificate - qurl domain must be in cert SANs
  [http.routers.qurl-site.tls]
%{ else ~}
  [http.routers.qurl-site.tls]
    certResolver = "letsencrypt"
    [[http.routers.qurl-site.tls.domains]]
      main = "${qurl_router_base_domain}"
      sans = ["*.${qurl_router_base_domain}"]
%{ endif ~}

# QURL backend service - placeholder required by Traefik config validation.
# The qurl-router middleware dynamically resolves the actual backend URL
# by querying the QURL Service API. This placeholder is never actually used.
[http.services.qurl-backend.loadBalancer]
  passHostHeader = true
  [[http.services.qurl-backend.loadBalancer.servers]]
    url = "http://127.0.0.1:9999"
QURLDYNAMICEOF
echo "QURL router configuration added"
%{ endif }

%{ if qurl_router_enabled ~}
# Custom domain routing: custom-domains.toml contains ONLY [[tls.certificates]]
# entries (no per-domain routers). Traefik matches certs to incoming SNI
# hostnames by the cert's SAN/CN. The catch-all router below handles routing
# for any domain that presents a matching TLS cert.
cat >> /home/ubuntu/traefik/dynamic.toml << 'CUSTOMDOMAINEOF'

# Catch-all router for custom domains — low priority (above nhp-ac at 1) so
# custom domains hit qurl-router before falling through to nhp-acd.
# Domains without a matching TLS cert get Traefik's default self-signed cert,
# causing a browser certificate mismatch warning (ERR_CERT_COMMON_NAME_INVALID).
[http.routers.custom-domain-catchall]
  rule = "HostRegexp(`^.+$`)"
  service = "qurl-backend"
  entryPoints = ["https"]
  priority = 2
  middlewares = ["qurl-router"]
  [http.routers.custom-domain-catchall.tls]
CUSTOMDOMAINEOF
echo "Custom domain routing enabled (catch-all router + TLS certs via custom-domains.toml)"
%{ endif ~}

%{ if !centralized_cert_enabled ~}
# Create ACME storage (only needed for per-instance ACME, not centralized certs)
touch /home/ubuntu/traefik/acme.json
chmod 600 /home/ubuntu/traefik/acme.json
%{ endif ~}

# Initialize empty custom-domains.toml (cert sync will populate it)
echo "# No custom domains configured" > /home/ubuntu/traefik/custom-domains.toml

# Restrict dynamic.toml permissions (contains service tokens)
chmod 600 /home/ubuntu/traefik/dynamic.toml
# Set ownership on config files (certs already owned from earlier; plugins set after download)
chown ubuntu:ubuntu /home/ubuntu/traefik /home/ubuntu/traefik/*.toml /home/ubuntu/traefik/*.json 2>/dev/null || true

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
# WorkingDirectory required for local plugins - Traefik looks for plugins at
# plugins-local/src/{moduleName}/ relative to this directory
WorkingDirectory=/home/ubuntu/traefik
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
# Download Custom Domain Cert Sync Script from S3
# This script is also run via SSM associations for periodic syncing.
# Stored in S3 instead of inline to stay under the 16KB user_data limit.
# ============================================================================
%{ if cert_sync_script_s3_uri != "" }
aws s3 cp "${cert_sync_script_s3_uri}" /home/ubuntu/scripts/custom-domain-cert-sync.sh --region "$REGION"
chmod +x /home/ubuntu/scripts/custom-domain-cert-sync.sh
chown ubuntu:ubuntu /home/ubuntu/scripts/custom-domain-cert-sync.sh
%{ else }
echo "No cert sync script S3 URI configured, skipping download"
%{ endif }

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

# ============================================================================
# Custom Domain Certificate Sync (on boot)
# Fetches all certs from SSM Parameter Store and creates custom-domains.toml.
# Traefik file watcher will pick up the config changes automatically.
# ============================================================================
echo "Syncing custom domain certificates..."
export SSM_CERT_PREFIX="/nhp/certs"
export AWS_REGION="${region}"
export TRAEFIK_DIR="/home/ubuntu/traefik"
bash /home/ubuntu/scripts/custom-domain-cert-sync.sh || echo "WARNING: Custom domain cert sync failed (non-fatal)"

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
