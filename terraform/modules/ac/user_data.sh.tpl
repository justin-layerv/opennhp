#!/bin/bash
# NHP AC User Data Script - Standalone AC for customer deployments
#
# This template configures a standalone AC that protects customer resources.
#
# ESCAPE INVARIANT — when adding a Terraform interpolation reference to
# a bash comment in this template, escape the leading dollar sign with
# another dollar sign if the variable can interpolate to a multi-line
# value. Today every comment interpolation here is a single-value
# primitive (port numbers, hostnames) so none of them need escaping;
# the multi-line case is what broke the sandbox server fleet in PR
# #2044. See terraform/CLAUDE.md § "templatefile() multi-line vars in
# bash comments must be escaped" for the rule and examples, and
# `terraform_data.qurl_router_frp_server_urls_comment_escape_fence`
# in modules/ac/main.tf for the live plan-time enforcement pattern
# (the compute-side `frps_overlay_comment_escape_fence` was retired
# in #1976 with the overlay itself; this AC-side fence is now the
# only instance).
set -ex

exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
echo "Starting NHP AC installation at $(date)"

mkdir -p /home/ubuntu/scripts

# The custom AC AMI (packer/nhp-ac.pkr.hcl) must bake every runtime package/tool
# below. Do not install packages or repair missing tooling during boot: that
# would put AC startup back on external package/tooling availability, where a
# transient upstream outage can abort user_data under `set -e` before
# Traefik/docker come up. If this check fails, the AMI is incomplete and should
# be rebuilt instead of self-healed here.
# Keep xtrace quiet while probing packages; the explicit missing list below is
# the operator-facing diagnostic if validation fails.
set +x
declare -a MISSING_BAKED_PACKAGES=()

package_installed() {
  local package=$1 status
  status=$(dpkg-query -W -f='$${Status}' "$package" 2>/dev/null || true)
  [ "$status" = "install ok installed" ]
}

require_baked_binary() {
  local package=$1 binary=$2
  if ! package_installed "$package" || ! command -v "$binary" >/dev/null 2>&1; then
    MISSING_BAKED_PACKAGES+=("$package")
  fi
}

require_baked_python_module() {
  local package=$1 module=$2
  if ! package_installed "$package" || ! python3 -c "import $module" >/dev/null 2>&1; then
    MISSING_BAKED_PACKAGES+=("$package")
  fi
}

require_baked_command() {
  local dependency=$1 binary=$2
  if ! command -v "$binary" >/dev/null 2>&1; then
    MISSING_BAKED_PACKAGES+=("$dependency")
  fi
}

require_baked_binary "jq" "jq"
require_baked_binary "curl" "curl"
require_baked_binary "docker.io" "docker"
require_baked_binary "gettext-base" "envsubst"
require_baked_binary "iptables" "iptables"
require_baked_binary "ipset" "ipset"
require_baked_binary "unzip" "unzip"
require_baked_binary "netcat-openbsd" "nc"
require_baked_binary "iptables-persistent" "netfilter-persistent"
require_baked_binary "ca-certificates" "update-ca-certificates"
require_baked_command "awscli-v2" "aws"
# python3-cryptography is a library package, so validate the importable module
# in addition to dpkg status instead of trying to normalize it to command -v.
require_baked_python_module "python3-cryptography" "cryptography"

if [ "$${#MISSING_BAKED_PACKAGES[@]}" -gt 0 ]; then
  echo "ERROR: AC AMI is missing baked runtime packages/tools: $${MISSING_BAKED_PACKAGES[*]}"
  echo "Rebuild the AC AMI with packer/nhp-ac.pkr.hcl; user_data intentionally does not run apt-get at boot."
  exit 1
fi
set -x
echo "All baked runtime dependencies present; skipping apt-get at boot"

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
# Capped, jittered backoff between EIP claim attempts. The linear term is
# capped so a deadline-bounded claim keeps polling roughly every 10-14s
# instead of sleeping ever-longer and missing a freed EIP, and the jitter
# decorrelates the near-simultaneous standby AC boots that poll the same
# pool. Caps each sleep to the remaining budget so no single sleep runs past
# EIP_CLAIM_DEADLINE (an AWS call already in flight can still push total
# wall-clock slightly beyond it — the loop never *sleeps* past the deadline,
# it just lets an in-progress attempt finish). All arithmetic stays in
# $(( )) expansions (never a bare (( )) command) to remain safe under
# `set -e`.
eip_backoff_sleep() {
  local n=$1
  local backoff=$(( RANDOM % 5 + ( n < 5 ? n : 5 ) * 2 ))
  local remaining=$(( EIP_CLAIM_DEADLINE - $(date +%s) ))
  if [ "$remaining" -le 0 ]; then return 0; fi
  if [ "$backoff" -gt "$remaining" ]; then backoff="$remaining"; fi
  sleep "$backoff"
}

echo "Attempting to claim an Elastic IP from pool ${eip_pool_tag}..."
EIP_CLAIMED=false
EIP_CLAIM_START=$(date +%s)
# Bound the claim by a deadline, not a fixed attempt count. During a
# blue/green standby instance refresh the pool churns: AWS releases a
# terminated instance's EIP asynchronously (eventual consistency), so a
# freshly-launched replacement can briefly observe zero free EIPs even
# though the pool has nominal headroom (2*max+1). The old 5-attempt (~45s)
# budget lost that race intermittently — one standby AC would FATAL-exit
# with "No available EIPs", never start nhp-acd/traefik, and fail the
# blue/green Verify Standby Health gate (observed 2026-07-01: sandbox
# deploy run 28492685955, 1 of 3 standby ACs; run 28486896507 hit the same).
# Retry until the deadline so the release has time to propagate; a genuinely
# exhausted pool still FATAL-exits, just after a bounded wait. This 300s
# budget assumes the blue/green Verify Standby Health window is at or near
# its 15-min default (blue-green-deploy.yml input
# standby_health_timeout_minutes, range 2-60 min). A deploy invoked with a
# very tight window (near the 2-min floor) will fail the standby gate on any
# AC that has to wait out EIP propagation regardless of this budget — that's
# a pool-provisioning problem (tracked in #2982), not something user_data can
# tune around since it can't see that input. The two values live in separate
# files with no lint linking them, so if the default is lowered, lower this
# too.
EIP_CLAIM_BUDGET_SECONDS=300
EIP_CLAIM_DEADLINE=$(( EIP_CLAIM_START + EIP_CLAIM_BUDGET_SECONDS ))
attempt=0
while [ "$(date +%s)" -lt "$EIP_CLAIM_DEADLINE" ]; do
  attempt=$(( attempt + 1 ))
  if ! AVAILABLE_EIPS=$(aws ec2 describe-addresses \
    --filters "Name=tag:EIPPool,Values=${eip_pool_tag}" \
    --query 'Addresses[?AssociationId==`null`].AllocationId' \
    --output text --region "$REGION"); then
    echo "WARNING: failed to list available EIPs in pool (attempt $attempt), retrying..." >&2
    eip_backoff_sleep "$attempt"
    continue
  fi

  # describe-addresses separates ids with tabs/newlines; normalize to spaces
  # and split. Empty or whitespace-only output yields a 0-length array — no
  # free EIP right now (release lag during refresh churn, or true exhaustion).
  # The `<<<` here-string appends a trailing newline, so `read` returns 0 (not
  # EOF-nonzero) even on empty input — keep it a here-string, not a pipe, to
  # stay safe under `set -e`.
  AVAILABLE_EIPS="$${AVAILABLE_EIPS//$'\t'/ }"
  AVAILABLE_EIPS="$${AVAILABLE_EIPS//$'\n'/ }"
  read -r -a AVAILABLE_EIP_IDS <<< "$AVAILABLE_EIPS"
  AVAILABLE_EIP_COUNT=$${#AVAILABLE_EIP_IDS[@]}
  if [ "$AVAILABLE_EIP_COUNT" -eq 0 ]; then
    echo "WARNING: No available EIPs in pool (attempt $attempt)"
    eip_backoff_sleep "$attempt"
    continue
  fi
  # Keep this as an assignment: under set -e, a bare (( ... )) command
  # exits 1 when RANDOM % count evaluates to 0.
  EIP_INDEX=$(( RANDOM % AVAILABLE_EIP_COUNT ))
  ALLOC_ID="$${AVAILABLE_EIP_IDS[$EIP_INDEX]}"

  # Do not let concurrent AC boots steal an EIP that another AC has just
  # claimed. The AWS API defaults to allowing reassociation unless told
  # otherwise, which can leave the displaced instance serving on its
  # auto-assigned public IP.
  if aws ec2 associate-address \
    --allocation-id "$ALLOC_ID" \
    --instance-id "$INSTANCE_ID" \
    --no-allow-reassociation \
    --region "$REGION"; then
    echo "Successfully claimed EIP allocation $ALLOC_ID"
    EIP_PUBLIC_IP=$(aws ec2 describe-addresses \
      --allocation-ids "$ALLOC_ID" \
      --query 'Addresses[0].PublicIp' \
      --output text --region "$REGION" 2>/dev/null || true)
    if [ -n "$EIP_PUBLIC_IP" ] && [ "$EIP_PUBLIC_IP" != "None" ]; then
      PUBLIC_IP="$EIP_PUBLIC_IP"
      PUBLIC_IP_SOURCE="eip_describe"
    else
      # Log/metric fallback only; IMDS may briefly lag the EIP association.
      PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
        http://169.254.169.254/latest/meta-data/public-ipv4)
      PUBLIC_IP_SOURCE="imds_fallback"
    fi
    echo "EIP associated. New public IP: $PUBLIC_IP"
    EIP_CLAIMED=true
    EIP_CLAIM_END=$(date +%s)
    EIP_CLAIM_DURATION=$(( EIP_CLAIM_END - EIP_CLAIM_START ))
    # Structured log line for incident investigation. CloudWatch metric
    # timestamps are aggregated to 1-minute periods, so when investigating
    # an EIP pool spike operators want to correlate the metric peak with
    # the exact instance and exact allocation that consumed the slot.
    # JSON format so CloudWatch Logs Insights can query on individual
    # fields without regex parsing.
    #
    # Construct via `jq -nc --arg` so any quote, backslash, or newline
    # that ever sneaks into a string field is properly escaped instead of
    # corrupting the JSON. Numeric fields use --argjson with explicit
    # integer validation so a non-numeric value falls back to 0 rather
    # than producing invalid JSON. jq is part of the AC base image
    # (installed alongside the AWS CLI in user_data setup above).
    if ! [[ "$EIP_CLAIM_DURATION" =~ ^[0-9]+$ ]]; then EIP_CLAIM_DURATION=0; fi
    if ! [[ "$attempt" =~ ^[0-9]+$ ]]; then attempt=0; fi
    if ! jq -nc \
        --arg event "eip_claimed" \
        --arg instance_id "$INSTANCE_ID" \
        --arg allocation_id "$ALLOC_ID" \
        --arg public_ip "$PUBLIC_IP" \
        --arg public_ip_source "$PUBLIC_IP_SOURCE" \
        --argjson duration_seconds "$EIP_CLAIM_DURATION" \
        --argjson attempts "$attempt" \
        --arg az "$AZ" \
        --arg environment "${environment}" \
        '{event: $event, instance_id: $instance_id, allocation_id: $allocation_id, public_ip: $public_ip, public_ip_source: $public_ip_source, duration_seconds: $duration_seconds, attempts: $attempts, az: $az, environment: $environment}'; then
      echo "WARNING: failed to emit eip_claimed structured log line (boot continues)" >&2
    fi
    # Emit EIP claim success metrics to CloudWatch. Log on failure (but
    # still proceed with boot) so a missing IAM grant or AWS API outage
    # leaves a breadcrumb in cloud-init-output.log instead of silently
    # producing an empty dashboard.
    if ! aws cloudwatch put-metric-data \
      --namespace "LayerV/NHP" \
      --metric-data \
        "MetricName=EIPClaimSuccess,Value=1,Unit=Count,Dimensions=[{Name=Component,Value=AC},{Name=Environment,Value=${environment}}]" \
        "MetricName=EIPClaimDuration,Value=$EIP_CLAIM_DURATION,Unit=Seconds,Dimensions=[{Name=Component,Value=AC},{Name=Environment,Value=${environment}}]" \
      --region "$REGION"; then
      echo "WARNING: failed to publish EIP claim success metrics (boot continues)" >&2
    fi
    break
  else
    echo "Failed to claim EIP $ALLOC_ID (attempt $attempt), retrying..."
    eip_backoff_sleep "$attempt"
  fi
done

if [ "$EIP_CLAIMED" = "false" ]; then
  echo "FATAL: Could not claim an EIP after $attempt attempts over $(( $(date +%s) - EIP_CLAIM_START ))s. Instance cannot serve traffic without a stable IP."
  echo "Check that enough EIPs are allocated (ac_max_capacity) and AWS EIP quota is sufficient."
  # Emit EIP claim failure metric to CloudWatch. We deliberately log on
  # failure (without aborting the cooldown / exit path) so the operator can
  # tell apart "metric never published" from "metric published but no
  # alarm" when triaging EIP exhaustion incidents.
  if ! aws cloudwatch put-metric-data \
    --namespace "LayerV/NHP" \
    --metric-name "EIPClaimFailure" \
    --value 1 --unit Count \
    --dimensions "Component=AC,Environment=${environment}" \
    --region "$REGION"; then
    echo "WARNING: failed to publish EIPClaimFailure metric (still proceeding to terminate)" >&2
  fi
  # Cooldown before exit to prevent ASG from rapidly cycling replacement instances
  # when EIP pool is genuinely exhausted (e.g., all allocated EIPs are in use).
  # NOTE: the deadline-bounded claim loop above already makes each instance
  # linger ~5 min before reaching here, so it now provides most of this
  # anti-cycle protection; the cooldown is retained as extra margin and can
  # likely shrink if the claim budget grows.
  sleep 120
  exit 1
fi

# Report current EIP pool utilization to CloudWatch.
# Note: these metrics are reported AFTER this instance has claimed its EIP,
# so on first boot the utilization already includes this instance's claim.
# Use a single describe-addresses call to atomically read both total and
# associated counts (avoids a race window where another instance claims or
# releases an EIP between two separate API calls).
#
# We do NOT discard stderr from describe-addresses or put-metric-data: a
# silent failure here would hide a real IAM/credential regression and leave
# the EIP pool dashboard empty with no breadcrumbs in /var/log/cloud-init-output.
if EIP_COUNTS=$(aws ec2 describe-addresses \
  --filters "Name=tag:EIPPool,Values=${eip_pool_tag}" \
  --query '[length(Addresses), length(Addresses[?AssociationId!=`null`])]' \
  --output text --region "$REGION"); then
  EIP_TOTAL=$(echo "$EIP_COUNTS" | awk '{print $1}')
  EIP_ASSOCIATED=$(echo "$EIP_COUNTS" | awk '{print $2}')
  # Validate both values are non-empty positive integers before doing
  # arithmetic. A regex check is more reliable than relying on `[ -gt ]`
  # exit codes for non-numeric input (which return 2, not 1, on bash).
  if [[ "$EIP_TOTAL" =~ ^[0-9]+$ ]] && [[ "$EIP_ASSOCIATED" =~ ^[0-9]+$ ]] && [ "$EIP_TOTAL" -gt 0 ]; then
    EIP_UTILIZATION=$(( EIP_ASSOCIATED * 100 / EIP_TOTAL ))
    EIP_AVAILABLE=$(( EIP_TOTAL - EIP_ASSOCIATED ))
    if ! aws cloudwatch put-metric-data \
      --namespace "LayerV/NHP" \
      --metric-data \
        "MetricName=EIPPoolUtilizationPercent,Value=$EIP_UTILIZATION,Unit=Percent,Dimensions=[{Name=Component,Value=AC},{Name=Environment,Value=${environment}}]" \
        "MetricName=EIPPoolAvailable,Value=$EIP_AVAILABLE,Unit=Count,Dimensions=[{Name=Component,Value=AC},{Name=Environment,Value=${environment}}]" \
        "MetricName=EIPPoolTotal,Value=$EIP_TOTAL,Unit=Count,Dimensions=[{Name=Component,Value=AC},{Name=Environment,Value=${environment}}]" \
      --region "$REGION"; then
      echo "WARNING: failed to publish EIP pool utilization metrics to CloudWatch (boot continues)" >&2
    fi
    echo "EIP pool utilization: $EIP_ASSOCIATED/$EIP_TOTAL ($EIP_UTILIZATION%) -- $EIP_AVAILABLE available"
  else
    echo "WARNING: EIP describe-addresses returned non-numeric counts (total='$EIP_TOTAL', associated='$EIP_ASSOCIATED'), skipping metric publish" >&2
  fi
else
  echo "WARNING: aws ec2 describe-addresses for EIP pool failed, skipping utilization metrics" >&2
fi
%{ endif ~}

# Create directories
mkdir -p /opt/layerv/nhp-ac/etc
mkdir -p /opt/layerv/nhp-ac/log
mkdir -p /home/ubuntu/traefik
mkdir -p /home/ubuntu/traefik/plugins-local
mkdir -p /var/log/traefik
# (No `mkdir -p /acme`: that path belongs to the container variant in
# docker/Dockerfile.ac.aws — the native Traefik here stores ACME state at
# /home/ubuntu/traefik/acme.json, and /acme is unreachable under
# ProtectSystem=strict anyway. Removed so it doesn't read as load-bearing.)

# ============================================================================
# Dedicated unprivileged user for Traefik (#1090)
#
# Traefik runs internet-facing on :80/:443, so an upstream RCE as root is the
# scariest blast radius on this host. Drop it to a service account that keeps
# only CAP_NET_BIND_SERVICE (granted on the traefik.service unit below).
# Mirrors the frps service-user pattern in
# terraform/modules/qurl-reverse-tunnel-server/user_data.sh.tpl.
#
# The working dir + all certs/config stay under /home/ubuntu/traefik because
# the traefik-plugins repo deploys middleware there via SSM against that
# hardcoded path (relocating to /opt/layerv is a cross-repo change tracked
# separately). nhp-traefik therefore needs to TRAVERSE /home/ubuntu: grant
# o+x only (traverse, not read/list). Note this is a WORLD grant (every local
# uid gains traverse, not just nhp-traefik); acceptable because the traefik
# subtree's secrets are 0600 and nothing else under /home/ubuntu is world-
# readable. A precisely-scoped `setfacl -m u:nhp-traefik:--x` is the tighter
# alternative, folded into the /opt/layerv relocation follow-up (#2382). The
# traefik subtree itself is chowned to nhp-traefik at each cert/config write
# site below and the periodic
# custom-domain-cert-sync.sh. Traefik only READS the deployed plugin sources
# (world-readable), so their owner is not load-bearing; the 0600 secrets
# (privkey.pem, acme.json, dynamic.toml) are what must be nhp-traefik-owned.
# ============================================================================
if ! getent group nhp-traefik >/dev/null 2>&1; then
  groupadd --system nhp-traefik
fi
if ! getent passwd nhp-traefik >/dev/null 2>&1; then
  # --home-dir matches WorkingDirectory (a ReadWritePath) so $HOME points at a
  # real, writable dir rather than a nonexistent /home/nhp-traefik; --no-create-home
  # because mkdir above already created it.
  useradd --system --gid nhp-traefik --no-create-home --home-dir /home/ubuntu/traefik --shell /usr/sbin/nologin nhp-traefik
fi
# Sentinel marking this as a post-#1090 non-root-Traefik instance. The periodic
# custom-domain-cert-sync.sh uses it to tell "nhp-traefik legitimately absent
# (pre-#1090 box → benign ubuntu fallback)" apart from "nhp-traefik
# unexpectedly absent on a refreshed box (partial user_data → fail LOUD instead
# of silently re-owning the 0600 privkey to ubuntu and breaking TLS)". Written
# only after the useradd above succeeds, so its presence implies the user exists.
touch /etc/nhp-traefik-nonroot
chmod o+x /home/ubuntu
chown nhp-traefik:nhp-traefik /home/ubuntu/traefik /var/log/traefik

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
# maxelem caps kernel memory consumption from ipset population attacks
# (#1160 T3-08); was 1,000,000. Default of 10,000 sized to the worst-case
# legitimate ceiling: 80 pps sustained × 120s defaultset timeout ≈ 9,600
# concurrent entries, rounded up. Sandbox/prod observe 0 at steady state;
# the cap exists to bound the attack ceiling, not to track typical load.
# Applied per-ipset; AC creates 6 sets (3 IPv4 + 3 IPv6), so worst-case
# kernel residency per instance is 6 × ipset_max_elements.
ipset -exist create defaultset hash:ip,port,ip counters maxelem ${ipset_max_elements} timeout ${ipset_default_timeout}
ipset -exist create defaultset_down hash:ip,port,ip counters maxelem ${ipset_max_elements} timeout $((${ipset_default_timeout} + 1))
ipset -exist create tempset hash:net,port counters maxelem ${ipset_max_elements} timeout ${ipset_temp_timeout}

echo "IPv4 ipsets created successfully (defaultset timeout=${ipset_default_timeout}s, tempset timeout=${ipset_temp_timeout}s, maxelem=${ipset_max_elements})"

# Create IPv6 ipsets (required for clients connecting via IPv6)
# The NHP AC code uses *_v6 suffixed sets for IPv6 addresses.
# Without these, ipset add fails and the NHP knock returns "ipset operation failed".
IP6TABLES=$(which ip6tables 2>/dev/null)
IPSET6_OK=0
if [ -n "$IP6TABLES" ]; then
    echo "Setting up IPv6 ipsets..."
    ipset -exist create defaultset_v6 hash:ip,port,ip family inet6 counters maxelem ${ipset_max_elements} timeout ${ipset_default_timeout} 2>/dev/null || true
    ipset -exist create defaultset_down_v6 hash:ip,port,ip family inet6 counters maxelem ${ipset_max_elements} timeout $((${ipset_default_timeout} + 1)) 2>/dev/null || true
    ipset -exist create tempset_v6 hash:net,port family inet6 counters maxelem ${ipset_max_elements} timeout ${ipset_temp_timeout} 2>/dev/null || true

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
-A INPUT -p tcp -s ${vpc_cidr} --dport ${ac_health_check_port} -j ACCEPT
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
# Note: IPv4 VPC CIDR rules (SSH/health-check/8888) are intentionally omitted here.
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

# python3-cryptography (used for key generation below) is verified in the baked
# runtime dependency check near the top of this script.

# Per-instance secret name
AC_SECRET_NAME="${name_prefix}-ac-$INSTANCE_ID"

echo "Checking for existing AC keypair in Secrets Manager..."

# SECURITY: same xtrace-leak class as the SERVER_SECRET / QURL_SERVICE_TOKEN
# blocks below. Under `set -x` the assignment `EXISTING_SECRET=$(aws …)`
# traces `+ EXISTING_SECRET='{"privateKey":"…"}'` (bash expands captured
# stdout into the assignment's trace line). The downstream
# `echo "$EXISTING_SECRET" | python3 …`, `echo "$KEYPAIR" | python3 …`,
# `SECRET_VALUE=$(cat << … SECRETEOF)`, and
# `aws secretsmanager create-secret --secret-string "$SECRET_VALUE"` all
# emit the AC's X25519 private key into user-data.log → CloudWatch.
# Bracket the whole fetch/generate/store block with `set +x` / `set -x`.
# Scrub intermediates afterwards; `$PRIVATE_KEY` is only consumed by the
# config.toml heredoc below, which is safe (bash does not xtrace heredoc
# bodies), so we leave it set and `unset` it immediately after the
# heredoc writes. Heredoc-safety applies to here-*documents* (`<<`) only;
# here-strings (`<<<`) *are* traced with expansion, so any future edit
# switching to `<<<` would need its own `set +x` bracket.
set +x

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
    # Secret might already exist (from previous failed boot), update it.
    # Fail-fast re-enables `set -x` so the FATAL trace hits user-data.log
    # with xtrace on (matches the SERVER_SECRET / QURL_SERVICE_TOKEN
    # failure-path pattern for uniform on-call observability).
    aws secretsmanager put-secret-value \
      --secret-id "$AC_SECRET_NAME" \
      --secret-string "$SECRET_VALUE" \
      --region "$REGION" || {
        set -x
        echo "FATAL: Failed to put-secret-value for $AC_SECRET_NAME"
        exit 1
    }
    echo "Updated existing secret: $AC_SECRET_NAME"
  fi
fi
# $KEYPAIR and $SECRET_VALUE only exist on the generate-new branch;
# `unset` is a no-op for variables that were never set, so the single
# call handles both branches safely.
unset EXISTING_SECRET KEYPAIR SECRET_VALUE
set -x

echo "AC keypair ready (public key: $${PUBLIC_KEY:0:20}...)"

# ============================================================================
# Fetch NHP Server Public Key
# Required for AC to communicate with NHP servers via cloud registration
# ============================================================================
echo "Fetching NHP Server public key from Secrets Manager..."
# SECURITY: this script runs under `set -ex`; the top-level `exec` redirect
# ships stderr (including xtrace) to user-data.log → CloudWatch Logs (30 day
# sandbox / 365 day prod retention; see the `retention_in_days` ternary in
# modules/ac/main.tf). Under `set -x` the `SERVER_SECRET=$(aws …)` assignment
# traces `+ SERVER_SECRET='{"privateKey":"…"}'` (bash expands the captured
# stdout into the assignment's trace line), and the `echo "$SERVER_SECRET" |
# python3 …` pipeline below traces the same JSON again. Bracket fetch +
# extract with `set +x` / `set -x`, and scrub the private half after extract
# as defence-in-depth. (See the AC keypair block comment above for the
# `<<<` here-string future-regression trap — same invariant applies here.)
set +x
SERVER_SECRET=$(aws secretsmanager get-secret-value --secret-id "${server_secret_arn}" --region "$REGION" --query SecretString --output text) || {
  set -x
  echo "FATAL: Could not fetch server secret from Secrets Manager"
  exit 1
}
SERVER_PUBLIC_KEY=$(echo "$SERVER_SECRET" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('publicKey', d.get('PubKeyBase64', '')))" 2>/dev/null || echo "")
unset SERVER_SECRET
set -x
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
# SECURITY: config.toml holds the AC's PrivateKeyBase64 (per-instance
# X25519 private key) and ${license_key} (`sensitive=true` in
# modules/ac/variables.tf — globally unique server-registration credential).
# Cloud-init's default umask leaves files created by `cat > …` at mode 644;
# create the inode + chmod 600 first so the key + license never sit at
# world-readable mode. Mirrors the server-module fix (#1389).
touch /opt/layerv/nhp-ac/etc/config.toml
chmod 600 /opt/layerv/nhp-ac/etc/config.toml
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
FilterMode = ${ac_filter_mode}
# LB health-check port. Traefik receives the probe on this TCP port and routes
# the qURL/TLS target-group health check to nhp-acd readiness. In
# FilterMode_EBPFXDP the AC admits this port through the XDP whitelist at
# startup so the NLB probe isn't fail-closed dropped; MUST equal the
# target-group health_check port (both are sourced from
# local.ac_health_check_port in terraform/modules/ac).
HealthCheckPort = ${ac_health_check_port}

# L3 flush-on-expiry. Toml keys match the Go struct field names
# (endpoints/ac/config.go) — not the json tags, which the toml unmarshaler
# does not honor. Defaults of false/true preserve pre-flush behavior; see
# docs/runbooks/l3-flush-*.md for the rollout sequence and the safety
# auto-default fenced in endpoints/ac/config.go::updateBaseConfig.
EnableL3FlushOnExpiry = ${enable_l3_flush_on_expiry}
L3FlushDryRun = ${l3_flush_dry_run}
L3FlushRealModeAcknowledged = ${l3_flush_real_mode_acknowledged}
L3FlushConntrackBackend = "${l3_flush_conntrack_backend}"
L3FlushConntrackPoolSize = ${l3_flush_conntrack_pool_size}

# Cloud mode registration credentials (license key is globally unique)
LicenseKey = "${license_key}"
ServerEndpoint = "${server_endpoint}"
ServerPubKeyBase64 = "$SERVER_PUBLIC_KEY"

# Environment dim for AC publisher's CloudWatch metrics. Must match
# the Environment value used by Region-keyed alarms in
# terraform/modules/ac/monitoring.tf — otherwise NewACRegistration
# falls back to "unknown" and every alarm sits in INSUFFICIENT_DATA /
# breaching-on-missing forever (see Metric/Alarm Dim-Set Rules in
# CLAUDE.md and the registration-stale alarm latched since 2026-04-24).
Environment = "${environment}"
CONFIGEOF
# Scrub $PRIVATE_KEY now that it's landed in config.toml — it has no further
# consumer in this script, and unsetting it prevents any future downstream
# edit (e.g. a `<<<` here-string or a `--key "$PRIVATE_KEY"` invocation,
# neither of which are heredoc-trace-safe) from silently reintroducing the
# xtrace-leak class this PR closes.
unset PRIVATE_KEY
echo "NHP-ACD config.toml created (cloud mode)"

# HTTP server config for NHP-ACD
cat > /opt/layerv/nhp-ac/etc/http.toml << 'HTTPEOF'
# HTTP server config for NHP-ACD
# This is the NHP protocol's HTTP interface, not Traefik's HTTPS. Keep it
# plaintext: Traefik's nhp-ac service points at http://127.0.0.1:8888, and the
# public AC target-group readiness check now depends on that local hop.
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
# SECURITY: xtrace-leak guard — see SERVER_SECRET block above (and the AC
# keypair block further above for the `<<<` here-string trap). The
# `[ -z "$QURL_SERVICE_TOKEN" ]` test would otherwise trace the token value.
# The token is later materialised into Traefik's dynamic config via a
# heredoc; bash does not xtrace heredoc bodies, so that line stays safe
# under the re-enabled `set -x`.
set +x
QURL_SERVICE_TOKEN=$(timeout 30 aws secretsmanager get-secret-value \
  --secret-id "${qurl_service_token_secret_arn}" \
  --region "$REGION" \
  --query SecretString --output text) || {
    set -x
    echo "ERROR: Failed to fetch QURL service token from Secrets Manager (timeout or auth failure)"
    exit 1
}
if [ -z "$QURL_SERVICE_TOKEN" ]; then
  set -x
  echo "ERROR: QURL service token is empty"
  exit 1
fi
set -x
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

# Secure permissions - only nhp-traefik (the Traefik service user) can read the
# private key (mode 0600, so ownership is load-bearing here).
chmod 600 /home/ubuntu/traefik/certs/privkey.pem
chmod 644 /home/ubuntu/traefik/certs/cert.pem
chmod 644 /home/ubuntu/traefik/certs/chain.pem
chmod 644 /home/ubuntu/traefik/certs/fullchain.pem
chown nhp-traefik:nhp-traefik /home/ubuntu/traefik/certs /home/ubuntu/traefik/certs/*.pem

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
cat > /home/ubuntu/traefik/traefik.toml << 'TRAEFIKEOF'
[global]
  checkNewVersion = false
  sendAnonymousUsage = false

[log]
  level = "INFO"
  filePath = "/var/log/traefik/traefik.log"

[accessLog]
  filePath = "/var/log/traefik/access.log"

[api]
  # API and dashboard stay off. With the insecure API enabled, Traefik would
  # create its reserved `traefik` entrypoint and serve API/dashboard requests
  # there ahead of file-provider routers — which made the NLB readiness route
  # return Traefik's own 404 even with the nhp-ac-ready router loaded. dashboard
  # is explicitly false so a future secure api@internal router can't accidentally
  # re-expose it.
  dashboard = false
  insecure = false

[ping]
  entryPoint = "nhp-health"

[entryPoints]
  [entryPoints.https]
    address = ":443"
    # The public AC NLB preserves client IP at L3. Do not enable Proxy Protocol
    # on this entrypoint unless the AC TCP target groups also stop preserving
    # client IP; otherwise the browser's public IP is the TCP peer that Traefik
    # evaluates for Proxy Protocol trust and the TLS stream can fail before HTTP.
    [entryPoints.https.forwardedHeaders]
      trustedIPs = ["${vpc_cidr}"]
  [entryPoints.http]
    address = ":80"
    [entryPoints.http.http.redirections.entryPoint]
      to = "https"
      scheme = "https"
  [entryPoints.nhp-health]
    address = ":${ac_health_check_port}"
%{ if frp_control_upstream_host != "" ~}
  # TRANSITIONAL — places the AC in the FRPS data plane as a userspace
  # TCP forwarder. Target shape is AC-as-firewall-manager only, with
  # FRPS-side ipset updated out-of-band; this entrypoint and the
  # paired `frps-control.toml` router/service below are removal work
  # then. Sibling resources: NLB listener, TG, ASG attachment, and SG
  # ingress in `modules/ac/main.tf`. Tracking:
  # https://github.com/layervai/nhp/issues/2019.
  #
  # FRPS-behind-AC entrypoint. Customer frpc lands here via the AC NLB
  # (TCP listener at port ${frp_control_port}) after the AC kernel ipset
  # gate has admitted its SYN per a verified NHP knock. The ipset gate
  # is a coarse source-IP pre-filter; the primary identity-bound access
  # control is the per-client X25519 key-authenticated knock + opaque
  # knock-token validation at FRP-Login via nhp-server's
  # `/token/validate` (qurl-reverse-tunnel-server #98). Traefik forwards
  # the TCP stream to the private FRPS instance via the
  # `frps-control` TCP router below. See SLACK_QURL_ROLLOUT.md §6.
  #
  # No proxyProtocol: the FRP control channel doesn't speak PP, and the
  # NLB FRPS-control listener (modules/ac/main.tf::aws_lb_listener.frps_control)
  # is configured WITHOUT proxy_protocol_v2 on the TG. Preserved client IP
  # for the ipset fence is delivered by NLB default-mode (no PP) — instance
  # sees `agent_ip → ac_local_ip:${frp_control_port}` natively.
  #
  # Bind IPv4-only. Go's net.Listen on `:${frp_control_port}` resolves to
  # `[::]:${frp_control_port}` (dual-stack) and accepts v4-mapped and v6
  # SYNs. The AC SG ingress and `defaultset` ipset are v4-only, so any v6
  # connectivity reaching the AC (dual-stack subnet, future v6 NLB,
  # link-local v6) would route around the ipset fence. `0.0.0.0` keeps
  # the Traefik bind aligned with what the ipset gate actually filters.
  # `nc -z 127.0.0.1 ${frp_control_port}` later in user_data still works:
  # IPv4 loopback hits the v4 bind directly.
  [entryPoints.frps-control]
    address = "0.0.0.0:${frp_control_port}"
%{ endif ~}
%{ for name, upstream in frp_control_additional_upstreams ~}
  [entryPoints.frps-control-${name}]
    address = "0.0.0.0:${upstream.listen_port}"
%{ endfor ~}

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
# SECURITY: dynamic.toml carries the QURL service bearer token in the
# `[http.middlewares.qurl-router-middleware.plugin.qurl-router]` block when
# `qurl_router_enabled` (live in sandbox + prod tfvars). The post-write
# `chmod 600 /home/ubuntu/traefik/dynamic.toml` was ~240 lines below — across
# cert fetch, ACME storage init, and other network-bound steps — leaving the
# token at default umask (644) for the duration. Set 600 on the inode now,
# before any heredoc writes; mode persists across the `cat >` truncate and
# the subsequent `cat >>` appends. Same bug class as #1389.
touch /home/ubuntu/traefik/dynamic.toml
chmod 600 /home/ubuntu/traefik/dynamic.toml
cat > /home/ubuntu/traefik/dynamic.toml << DYNAMICEOF
# Traefik Dynamic Configuration
#
# Router priority hierarchy (higher number = matched first):
#  101 - nhp-ac-ready-deny :443 rewrites ${ac_admission_ready_path} variants to a 404 path
#  100 - nhp-ac-ready      :${ac_health_check_port} ${ac_admission_ready_path} to nhp-acd readiness
#   20 - frp-control        /.well-known/layerv-frp or /~!frp → FRP WebSocket (when deploy_frps)
#   15 - qurl-site          *.qurl.site subdomain routing
#   10 - nhp-plugins        /plugins/* to NHP Server
#   10 - prod-*/addtls-*    production domain routes (when ACME enabled)
#    2 - custom-domain-catchall  custom domains via qurl-router middleware
#    1 - nhp-ac             fallback to nhp-acd for protected resource access

[http.routers]
  # NLB qURL/TLS target health must prove nhp-acd can receive admissions.
  [http.routers.nhp-ac-ready]
    rule = "Path(\`${ac_admission_ready_path}\`)"
    service = "nhp-ac"
    entryPoints = ["nhp-health"]
    priority = 100

  # Keep the readiness bit internal to the NLB health-check entrypoint. Without
  # this https router, the priority-1 nhp-ac fallback would also serve
  # ${ac_admission_ready_path} after a knock. Rewriting to an impossible
  # nhp-acd path intentionally returns the same 404 independent of readiness
  # state via gin's default NoRoute handler, using existing backend routing
  # instead of adding another custom response plugin to the AC boot path.
  # This reserves ${ac_admission_ready_path} and its subpaths on public :443
  # across proxied protected resources, by design, to keep the readiness signal
  # from leaking through qurl-site or the nhp-ac fallback route.
  [http.routers.nhp-ac-ready-deny]
    rule = "Path(\`${ac_admission_ready_path}\`) || PathPrefix(\`${ac_admission_ready_path}/\`)"
    service = "nhp-ac"
    entryPoints = ["https"]
    middlewares = ["nhp-ac-ready-internal-only"]
    priority = 101
%{ if centralized_cert_enabled ~}
    # TLS uses centralized certificate from default store
    [http.routers.nhp-ac-ready-deny.tls]
%{ else ~}
    [http.routers.nhp-ac-ready-deny.tls]
      certResolver = "letsencrypt"
      [[http.routers.nhp-ac-ready-deny.tls.domains]]
        main = "${domain_name}"
        sans = ["*.${domain_name}"]
%{ endif ~}

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

[http.middlewares]
  [http.middlewares.nhp-ac-ready-internal-only.replacePath]
    path = "/__nhp_ac_ready_internal_only"

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
  # Router-side HRW dispatch (traefik-plugins #134). Default false in
  # PR 3; PR 4 prod tfvars flips enableInstanceHrw=true once the
  # qurl-reverse-tunnel-server fleet is at 2/AZ on MULTIVALUE Cloud Map
  # routing. The plugin reads instanceDiscoveryTtl as the freshness
  # window for boundary→IP resolution — IPs aged out of the window
  # are not dialable.
  enableInstanceHrw = ${qurl_router_enable_instance_hrw}
  instanceDiscoveryTtl = ${qurl_router_instance_discovery_ttl_seconds}
  enableQurlSiteAuthz = ${qurl_router_enable_qurl_site_authz}${qurl_router_connector_routing_gate}
  # Per-AZ qurl-reverse-tunnel-server boundary allowlist. Plural field
  # \`frpServerUrls\` (plugin Config: FRPServerURLs []string) — the legacy
  # singular \`frpServerUrl\` was dropped from the plugin's Config struct,
  # so emitting \`frpServerUrl = ""\` is silently ignored and leaves the
  # plural list empty. With an empty plural list the plugin's ServeHTTP
  # hits the \`q.frpFallback == nil\` gate on every tunnel resource and
  # silentDrop's (when enableQurlSiteAuthz=true) or 502s — per-resource
  # \`upstream_addr\` from the QURL API is consulted ONLY after that gate
  # passes. So this MUST be non-empty for tunnel resources to route at
  # all; the entries are the operator-declared allowlist that
  # per-resource upstream_addr values are checked against.
  #
  # Shape MUST match qurl-service's BuildUpstreamAddr output
  # (qurl-service:internal/service/upstream_assign.go::BuildUpstreamAddr
  # — http://frps-{az}.{frps_domain}:{frps_port}) so the runtime
  # set-membership check passes. Root assembly fills this from
  # var.frps_az_suffixes + module.data.namespace_name +
  # var.frps_vhost_http_port to keep both sides in sync.
  #
  # The templatefile for-loop below emits a trailing comma after the
  # last entry. Traefik 3.x (pinned at TRAEFIK_VERSION in
  # docker/Dockerfile.ac.aws) uses pelletier/go-toml v2 for dynamic
  # config parsing, which is TOML 1.0.0 spec-compliant and accepts
  # trailing commas in arrays.
  frpServerUrls = [
%{ for url in qurl_router_frp_server_urls ~}
    "${url}",
%{ endfor ~}
  ]

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

%{ if frp_server_host != "" && qurl_router_enabled ~}
# FRP tunnel server routes - WebSocket control channel and vhost HTTP
#
# DEAD CODE as of #1499. The only in-tree caller (terraform/main.tf) welds
# `frp_server_host = ""`, so this `if frp_server_host != ""` branch never
# evaluates true under the current root wiring. With the per-AZ
# qurl-reverse-tunnel-server fleet, frpc connects to its assigned per-AZ
# instance directly via the API-supplied `frps_addr` (no Traefik FRP-control
# router needed), and the qurl-router plugin reads the same `frps_addr`
# for vhost HTTP forwarding (no `frpServerUrl` fallback needed — see
# traefik-plugins #95). This block plus the `frp_server_host` /
# `frp_control_port` / `frp_vhost_http_port` variables are all slated for
# deletion in a follow-up cleanup PR once the per-AZ rollout is verified
# in prod; retained here only because this PR is scope-limited to the
# cross-repo plumbing.
#
# Original guard rationale (still accurate if the variable is ever
# re-wired): both `frp_server_host` AND `qurl_router_enabled`. The FRP
# control channel without the qurl-router plugin would be half-wired —
# clients can connect and register tunnels, but vhost HTTP (customer
# subdomain routing through the plugin to frps:8080) would be missing.
# Without both, don't advertise the control endpoint.
cat >> /home/ubuntu/traefik/dynamic.toml << 'FRPDYNAMICEOF'

# FRP WebSocket control channel
#
# Two paths reach the same FRPS service:
#
#   1. /.well-known/layerv-frp — RFC 8615 reserved namespace, originally
#      added so a customer-app catch-all on / couldn't hijack FRP control
#      traffic. Reaches FRPS via the `frp-path-rewrite` middleware.
#   2. /~!frp — the path FRP's WebSocket upgrade handler hardcodes
#      (`pkg/util/net/websocket.go::FrpWebsocketPath` in
#      github.com/fatedier/frp). Stock qurl-reverse-tunnel-client clients use this path
#      directly (FRP v0.68 has no `transport.subPath` config option to
#      override it), so without an explicit router for this path the
#      WebSocket request would fall through to the customer catch-all
#      (`nhp-ac` priority 1) and 404. The `replacePath` middleware is
#      a no-op when the incoming path is already `/~!frp`, so the same
#      service + middleware chain handles both inputs.
#
# If the internal FRP WebSocket path changes in a future FRP version,
# update BOTH:
#   - http.middlewares.frp-path-rewrite.replacePath.path
#   - The Path() match for the direct route below
#
# Note: Traefik 3.x forwards `Upgrade` and `Connection` headers for WebSocket
# handshakes by default. If anyone ever adds a `headers` middleware to this
# router chain, both headers must be preserved or the FRP control channel
# breaks.
[http.middlewares.frp-path-rewrite.replacePath]
  path = "/~!frp"

[http.routers.frp-control]
  rule = "Path(`/.well-known/layerv-frp`) || Path(`/~!frp`)"
  service = "frp-control"
  middlewares = ["frp-path-rewrite"]
  entryPoints = ["https"]
  priority = 20
%{ if centralized_cert_enabled ~}
  [http.routers.frp-control.tls]
%{ else ~}
  [http.routers.frp-control.tls]
    certResolver = "letsencrypt"
    [[http.routers.frp-control.tls.domains]]
      main = "${domain_name}"
      sans = ["*.${domain_name}"]
%{ endif ~}

[http.services.frp-control.loadBalancer]
  [[http.services.frp-control.loadBalancer.servers]]
    url = "http://${frp_server_host}:${frp_control_port}"
FRPDYNAMICEOF
echo "FRP tunnel server routes added (ingress /.well-known/layerv-frp or /~!frp -> ${frp_server_host}:${frp_control_port})"
%{ endif ~}

%{ if frp_control_upstream_host != "" || length(frp_control_additional_upstreams) > 0 ~}
# ============================================================================
# FRPS-behind-AC TCP entrypoint forwarder (SLACK_QURL_ROLLOUT.md §6)
#
# TRANSITIONAL — this block (entrypoint binding + dynamic-file router +
# service) places the AC in the FRPS data plane as a userspace TCP
# forwarder. Target shape is AC-as-firewall-manager only, with FRPS-side
# ipset updated out-of-band; this whole section is removal work then.
# Paired Terraform resources live in `modules/ac/main.tf` (NLB listener,
# TG, ASG attachment, SG ingress on port ${frp_control_port}). Tracking:
# https://github.com/layervai/nhp/issues/2019.
# ============================================================================
#
# Customer frpc dials `connect.layerv.{ai,xyz}:${frp_control_port}` (public DNS
# → AC NLB:${frp_control_port}). The NLB target group has TCP passthrough
# without PROXY protocol, so the AC instance sees the connection at L4 as
# `agent_ip → ac_local_ip:${frp_control_port}`. The AC kernel iptables
# default-DROPs INPUT and admits this SYN only when the FRPS-specific NHP
# knock has added `(agent_ip, ${frp_control_port}, ac_local_ip)` to the
# `defaultset` ipset (see nhp/endpoints/ac/msghandler.go `HandleAccessControl`,
# and the empty `Addr.Ip` the bridge synthesizes for the agent flow which
# triggers the DefaultIp substitution). The ipset entry is a coarse
# source-IP pre-filter; identity-bound access control comes from the
# per-client X25519 key-authenticated knock + knock-token validation at
# FRP-Login (qurl-reverse-tunnel-server #98).
#
# Once admitted, Traefik's TCP entrypoint on `:${frp_control_port}` accepts
# the connection and forwards it via this TCP router to the private FRPS
# instance at `${frp_control_upstream_host}:${frp_control_port}`. The
# downstream leg is over the VPC private network; the FRPS SG only accepts
# AC SG ingress, so no public actor can reach FRPS:${frp_control_port}
# directly.
#
# Router rule `HostSNI(\`*\`)` is plain TCP (no TLS / SNI). FRP's control
# channel uses yamux-over-TCP; TLS termination is a future concern handled
# at the NHP layer's keypair-authenticated session boundary.
#
# Why a separate file (not appended to dynamic.toml): a future PR may
# rework the dynamic.toml priority hierarchy on the legacy `frp-control`
# HTTP router (lines 1308-1357). Splitting the TCP entrypoint out keeps
# the FRPS-behind-AC config independent of that churn. Traefik's
# `[providers.file] directory = "/home/ubuntu/traefik/"` watches the
# whole directory, so a separate file is picked up automatically.
# Heredoc delimiter is single-quoted (`'FRPSCTRLEOF'`) so bash leaves the
# body literal — no variable/command substitution. Same pattern as the
# overlay heredoc in `compute/user_data.sh.tpl`. Terraform's
# `${frp_control_upstream_host}` / `${frp_control_port}` are resolved
# by `templatefile()` BEFORE bash sees the file, so the quoted delimiter
# doesn't suppress them; the quoting protects the backticks in
# `HostSNI(`*`)` from bash command-substitution.
cat > /home/ubuntu/traefik/frps-control.toml << 'FRPSCTRLEOF'
# FRPS control channel TCP forwarder — Wave 5 FRPS-behind-AC topology.
#
# Two distinct hostnames are in play; do not conflate them:
#   1. Customer-facing dial target (the value of `Hostname` the
#      nhp-server returns in the agent's knock ack, e.g.
#      `connect.layerv.{ai,xyz}`) — sourced from
#      `var.connect_layerv_host` in the root tfvars and written into
#      the DDB seed row's `resource_fqdn` field (terraform/resources.tf).
#      Resolves publicly to this AC's NLB.
#   2. Internal upstream this Traefik TCP service forwards to (e.g.
#      `frps-{az}.nhp.{env}.internal`) — sourced from
#      `var.frp_control_upstream_host` (= `local.tunnel_server_primary_host`
#      in the root) plus any per-AZ additional upstreams. VPC-private,
#      FRPS SG only accepts AC SG.
#
# The whole point of the 2026-05-18 redesign was splitting these:
# customer-facing dial target ≠ internal upstream. This file configures
# only the AC-userspace → internal-FRPS leg (#2). The customer-facing
# DNS (#1) lives in `terraform/main.tf::aws_route53_record.connect{_cross_account}`.

%{ if frp_control_upstream_host != "" ~}
[tcp.routers.frps-control]
  rule = "HostSNI(`*`)"
  service = "frps-control"
  entryPoints = ["frps-control"]

[tcp.services.frps-control.loadBalancer]
  [[tcp.services.frps-control.loadBalancer.servers]]
    address = "${frp_control_upstream_host}:${frp_control_port}"
%{ endif ~}
%{ for name, upstream in frp_control_additional_upstreams ~}

[tcp.routers.frps-control-${name}]
  rule = "HostSNI(`*`)"
  service = "frps-control-${name}"
  entryPoints = ["frps-control-${name}"]

[tcp.services.frps-control-${name}.loadBalancer]
  [[tcp.services.frps-control-${name}.loadBalancer.servers]]
    address = "${upstream.upstream_host}:${upstream.upstream_port}"
%{ endfor ~}
FRPSCTRLEOF
chmod 644 /home/ubuntu/traefik/frps-control.toml
echo "FRPS-behind-AC TCP forwarder added (listener ports: ${join(" ", frp_control_listener_ports)})"
%{ endif ~}

%{ if !centralized_cert_enabled ~}
# Create ACME storage (only needed for per-instance ACME, not centralized certs)
touch /home/ubuntu/traefik/acme.json
chmod 600 /home/ubuntu/traefik/acme.json
%{ endif ~}

# Initialize empty custom-domains.toml (cert sync will populate it)
echo "# No custom domains configured" > /home/ubuntu/traefik/custom-domains.toml

# dynamic.toml mode is set to 600 at creation time above (before the heredoc
# writes), so no late chmod is needed here.
# Set ownership on the config files Traefik reads (the dir itself is already
# nhp-traefik-owned from the user-creation block above; certs are owned
# earlier, plugins after download). acme.json and dynamic.toml are mode 0600,
# so nhp-traefik ownership is load-bearing — a genuine chown failure must
# surface under set -e rather than be masked by a blanket `|| true`. The
# per-file existence check handles the only legitimate "missing" case
# (acme.json exists only when !centralized_cert_enabled; the *.toml glob
# always matches).
for f in /home/ubuntu/traefik/*.toml /home/ubuntu/traefik/*.json; do
  [ -e "$f" ] && chown nhp-traefik:nhp-traefik "$f"
done

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
User=nhp-traefik
Group=nhp-traefik
# Bind :80/:443 as a non-root user by keeping only the privileged-port
# capability (#1090). NoNewPrivileges is compatible with AmbientCapabilities:
# systemd raises the ambient set before exec.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
PrivateTmp=yes
# strict makes the whole filesystem read-only except ReadWritePaths. Traefik
# writes ACME state (acme.json) under the working dir and its logs to
# /var/log/traefik. ProtectHome is intentionally omitted: the working dir
# lives under /home/ubuntu/traefik (kept there for the traefik-plugins SSM
# contract), and ProtectSystem=strict already renders /home read-only — the
# ReadWritePaths below re-grant write only to the two dirs Traefik needs.
ProtectSystem=strict
ReadWritePaths=/home/ubuntu/traefik /var/log/traefik
# Carve the plugin sources back to read-only inside the ReadWritePaths parent so
# a compromised Traefik cannot rewrite its own Yaegi plugin code for
# persistence. Supported: a ReadOnlyPaths subtree under a ReadWritePaths parent
# applies to the subtree. The root-running SSM plugin deploy is outside this
# namespace and still updates the real dir.
ReadOnlyPaths=/home/ubuntu/traefik/plugins-local
# (ReadOnlyPaths=/usr/local/bin/traefik would be redundant under
# ProtectSystem=strict, which already mounts the whole FS read-only — dropped
# in favor of the directives below.) These add real defense-in-depth and are
# all safe for a userspace HTTP proxy that never tunes the kernel, loads
# modules, manages cgroups, or creates suid files. RestrictAddressFamilies is
# intentionally NOT set: Go's resolver/netlink usage makes scoping it
# runtime-risky without sandbox validation.
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
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

# nhp-acd systemd service (listens on localhost:8888 for HTTP, localhost:62206 for NHP).
# Environment="AWS_REGION=..." is required: nhp-acd hard-fails without it,
# and systemd does not inherit env from the boot shell. Roll out via ASG
# instance refresh — a binary swap on a live instance without re-rendering
# this unit will crash-loop the AC.
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
Environment="AWS_REGION=${region}"

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

# Keep plugins-local owned by ubuntu (NOT nhp-traefik): Traefik only READS the
# world-readable Yaegi plugin sources, so it needn't own them — and owning +
# ReadWritePaths would let a compromised Traefik rewrite its own plugin code
# (a clean RCE persistence vector, the exact blast radius this PR shrinks). The
# unit additionally pins plugins-local ReadOnlyPaths. The cross-repo
# traefik-plugins SSM deploy runs as root outside Traefik's namespace, so it is
# unaffected by either.
chown -R ubuntu:ubuntu /home/ubuntu/traefik/plugins-local
echo "All Traefik plugins downloaded from S3"
%{ else }
echo "No Traefik plugins configured, skipping S3 download"
%{ endif }

# Reload systemd and enable/start all services
systemctl daemon-reload
systemctl enable traefik nhp-acd nhp-cloudmap-register nhp-health-monitor

# Fail-closed boot-ordering guard for the FRPS-behind-AC redesign.
# `aws_vpc_security_group_ingress_rule.ac_frps_control` opens
# 0.0.0.0/0 → tcp/${frp_control_port} on the AC SG, and the AC
# kernel iptables default-DROP INPUT + `defaultset` ipset is the
# real L3/L4 fence. The ipset setup above must be in place BEFORE
# `systemctl start traefik` binds the listener — otherwise there's
# a boot-window where an unauthenticated SYN can reach Traefik
# directly. If a future refactor reorders the firewall setup below
# Traefik's start, this guard fails the boot loudly instead of
# silently leaking the listener.
#
# The check is fail-closed in all failure modes: a missing rule
# trips the `grep -q` to non-zero (the intended fence), and a
# missing iptables binary / lockfile contention / kernel module
# load failure also produces non-zero (because pipefail propagates
# the upstream iptables exit). `set -o pipefail` is scoped to a
# subshell so it doesn't bleed into the rest of the user_data.
#
# The grep pattern anchors on the full ACCEPT-rule shape, not just
# the `match-set defaultset` substring — the substring would also
# match the LOG / SET / defaultset_v6 lines, so a regression that
# stripped `-j ACCEPT` while leaving the LOG rule would slip past
# a substring match. Matches the precision of the plan-time
# render-check in `modules/ac/main.tf::terraform_data.ac_user_data_frps_control_traefik_render_check`.
#
# Two-part check: (1) the ACCEPT rule is present, AND (2) the INPUT
# chain default policy is DROP. A regression that flipped INPUT's
# policy from DROP back to ACCEPT would silently re-leak port 7000
# even with the rule still in place; the policy check catches that.
%{ if frp_control_upstream_host != "" || length(frp_control_additional_upstreams) > 0 ~}
# Use `iptables -S` for both checks — its save-format output puts the
# target after the match conditions (matching the regex below) and
# is deterministic across kernel/iptables versions, unlike `-L` which
# is column-formatted and target-first. The regex anchors on the
# exact rule shape from the IPv4 iptables rules block above (line
# `-A INPUT -m set --match-set defaultset src,dst,dst -j ACCEPT`).
if ! (set -o pipefail; iptables -S INPUT | grep -qE "^-A INPUT -m set --match-set defaultset src,dst,dst -j ACCEPT$"); then
  echo "FATAL: defaultset ACCEPT rule missing from INPUT chain (or iptables itself failed) — refusing to start Traefik on a host where the AC kernel L3/L4 gate is not in place. See SLACK_QURL_ROLLOUT.md §6." >&2
  exit 1
fi
if ! (set -o pipefail; iptables -S INPUT | grep -q "^-P INPUT DROP"); then
  echo "FATAL: INPUT chain default policy is not DROP — the AC kernel L3/L4 gate depends on default-DROP + explicit-ACCEPT-on-ipset-match. Refusing to start Traefik. See SLACK_QURL_ROLLOUT.md §6." >&2
  exit 1
fi
%{ endif ~}

systemctl start traefik
systemctl start nhp-acd
systemctl start nhp-cloudmap-register
systemctl start nhp-health-monitor

# Post-Traefik-start listener-bind verification for the FRPS-behind-AC
# topology. Traefik's `/ping` returns 200 once the process is alive
# but says nothing about whether the `entryPoints.frps-control`
# listener actually bound on `:${frp_control_port}` — a malformed
# `frps-control.toml`, a port collision, or a Traefik startup race
# would silently leave the public TG healthy and customer SYNs
# hanging at the listener layer. `nc -z 127.0.0.1 <port>` after
# start checks the bind directly; failure surfaces in
# `/var/log/user-data.log` rather than waiting for the post-deploy
# smoke check in #2007.
#
# Load-bearing dependency: this `nc -z` to 127.0.0.1 traverses the
# `-A INPUT -i lo -j ACCEPT` rule (rendered into the IPv4 iptables
# rules block above) — which bypasses the `defaultset` ipset gate
# for loopback traffic. If a future tightening narrows the lo
# ACCEPT rule (e.g. to specific dst ports), this check needs the
# matching exception or it will silently fail-closed in production.
#
# Budget: 60s with 1s `nc -w 1` per attempt. Heavily-loaded cold AMI
# boots (Traefik plugin downloads, image pulls in parallel) can push
# Traefik bind well past the 10-20s "happy path." 60s gives realistic
# headroom while still failing fast vs. a forever-hung Traefik. If
# the sandbox bring-up shows P99 bind times approaching this limit,
# raise the loop count and revisit Traefik startup-cost reduction.
#
# SCOPE: this is a BIND-TIME fence only, NOT a runtime liveness check.
# A Traefik that binds successfully here and then segfaults / wedges
# later (kernel listener up, accept loop wedged, RSTs back to clients)
# is invisible to this loop — `/ping:${ac_health_check_port}` would still return 200 from
# whatever Traefik state holds the HTTP server thread, and the
# frps-control TG HC stays green. Runtime liveness for the frps-control
# listener is the job of #2007's post-deploy smoke (TCP+FRP handshake
# from a knocked-in agent); don't conflate the two.
%{ if frp_control_upstream_host != "" || length(frp_control_additional_upstreams) > 0 ~}
# Precheck: `nc` is validated at the top of user_data as a baked
# netcat-openbsd dependency; keep this local guard so the loop below
# does not FATAL with the misleading "Traefik didn't bind" message
# if the AMI is incomplete.
if ! command -v nc >/dev/null 2>&1; then
  echo "FATAL: nc binary not found — netcat-openbsd is missing from the baked AC AMI. The post-Traefik listener-bind verification cannot run." >&2
  exit 1
fi
for FRPS_CONTROL_PORT in ${join(" ", frp_control_listener_ports)}; do
  echo "Waiting for Traefik listener on tcp/$FRPS_CONTROL_PORT..."
  TRAEFIK_LISTENER_OK=0
  for _ in $(seq 1 60); do
    if nc -z -w 1 127.0.0.1 "$FRPS_CONTROL_PORT" 2>/dev/null; then
      TRAEFIK_LISTENER_OK=1
      break
    fi
    sleep 1
  done
  if [ "$TRAEFIK_LISTENER_OK" != "1" ]; then
    echo "FATAL: Traefik did not bind tcp/$FRPS_CONTROL_PORT within ~60s — the frps-control entrypoint failed to bind. Check journalctl -u traefik for parse errors in /home/ubuntu/traefik/frps-control.toml. See #2007 for the broader observability story." >&2
    # Pull this instance out of service. `exit 1` alone marks user_data
    # as failed in cloud-init but does NOT auto-terminate the instance:
    # Traefik's systemd unit is already started, its `/ping:${ac_health_check_port}`
    # endpoint still returns 200, and the ASG would keep this instance
    # in service indefinitely with a half-broken Traefik (every other
    # entrypoint up, frps-control silently dropping SYNs). Stopping the
    # Traefik unit fails every port-${ac_health_check_port} TG health/readiness probe
    # (including ac_tcp and `aws_lb_target_group.ac_frps_control`), so
    # the NLB sheds load on every entrypoint, the ASG's
    # `ELB`-source HC marks the instance unhealthy, and a replacement
    # instance launches. Trade-off: this also takes the AC out of
    # service for QURL routing (which Traefik was serving fine) — but
    # a half-broken Traefik with no frps-control listener is the worse
    # of the two states for the FRPS-behind-AC topology and the ASG
    # replacement covers QURL via the next healthy instance. A future
    # enhancement could shell out to `aws autoscaling set-instance-health
    # --health-status Unhealthy` here if granular failure reporting is
    # needed; the canonical pattern lives at
    # `terraform/modules/compute/user_data.sh.tpl:601` (the nhp-server's
    # equivalent fail-fast path) and requires the instance to carry the
    # matching IAM perms (the AC role would need
    # `autoscaling:SetInstanceHealth` added at
    # `terraform/modules/ac/main.tf` IAM block — out of scope for this fix).
    systemctl stop traefik || true
    exit 1
  fi
  echo "Traefik listener on tcp/$FRPS_CONTROL_PORT is up."
done
%{ endif ~}

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
echo "  - Traefik (HTTPS proxy): :443, :80, health :${ac_health_check_port}"
echo "  - nhp-acd: localhost:8888 (HTTP), localhost:62206 (NHP)"
echo ""
echo "Traefik plugins directory: /home/ubuntu/traefik/plugins-local"
echo "  (managed by traefik-plugins repo via SSM)"
