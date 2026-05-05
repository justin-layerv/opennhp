#!/bin/bash
# QURL FRP Server User Data Script
#
# Bootstraps a qurl-frps instance: installs dependencies, writes frps.toml
# config (values resolved by Terraform templatefile() at plan time), starts
# the FRP server as a systemd service, and registers with Cloud Map for
# service discovery.
#
# Debugging notes for on-call:
# - Docker is installed, used ONCE to pull the qurl-frps image and extract
#   the binary, then `systemctl disable --now docker` is run to free ~150MB
#   RSS on the t3.small and shrink the attack surface. If you need to
#   re-extract the binary (e.g., swap image_tag by hand for a hotfix), run
#   `sudo systemctl enable --now docker` first before re-running the
#   extraction block.
# - The binary is pulled from either `/usr/local/bin/nhp-frps` or `/nhp-frps`
#   inside the image (first path tried, fall back to the second). If the
#   qurl-frps image layout changes again, BOTH paths below need to track;
#   the image's CI should pin its own path so this stays in lockstep.
set -ex

exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
echo "Starting QURL FRP server installation at $(date)"

export DEBIAN_FRONTEND=noninteractive

# Retry helper (consistent with AC module pattern)
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
apt_get_with_retry install -y jq curl unzip docker.io

# Install AWS CLI v2
if ! command -v aws &> /dev/null; then
  echo "Installing AWS CLI v2..."
  curl -sL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
  unzip -q /tmp/awscliv2.zip -d /tmp
  /tmp/aws/install
  rm -rf /tmp/aws /tmp/awscliv2.zip
fi
aws --version

# Enable and start Docker (for pulling binary from ECR if needed)
systemctl enable docker
systemctl start docker
for i in {1..30}; do docker info >/dev/null 2>&1 && break || sleep 2; done
if ! docker info >/dev/null 2>&1; then
  # Fail-fast matches the SSM/Secrets pattern below; otherwise `docker login`
  # and `docker pull` produce confusing errors whose root cause is the daemon.
  echo "FATAL: Docker daemon did not start within 60 seconds"
  exit 1
fi

# ============================================================================
# CloudWatch Agent
# The CPU (cpu_usage_active) and memory (mem_used_percent) alarms in
# monitoring.tf depend on the CW Agent publishing custom metrics. If the
# agent silently fails to install, those alarms use `treat_missing_data =
# "notBreaching"` and go permanently green, masking real instance distress.
# Treat install failure as fatal — matches the SSM / Secrets Manager / Docker
# daemon fail-fast pattern below and makes the ASG cycle the instance so the
# no-healthy-instance alarm fires with the underlying error in user-data.log.
# ============================================================================
echo "Installing CloudWatch Agent..."
CW_AGENT_DEB="/tmp/amazon-cloudwatch-agent.deb"
if ! curl -sfL "https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb" -o "$CW_AGENT_DEB" || [ ! -s "$CW_AGENT_DEB" ]; then
  echo "FATAL: CloudWatch Agent download failed — CPU/memory alarms would stay green on a degraded instance."
  exit 1
fi
# Unattended-upgrades can hold the apt lock for 60-90s on first boot, so
# use the same exponential backoff helper as apt-get above rather than a
# short linear loop. 6 attempts × up to 30s ≈ 2 min max.
if ! retry_with_backoff 6 5 30 dpkg -i "$CW_AGENT_DEB"; then
  echo "FATAL: dpkg -i CloudWatch Agent failed after retries — CPU/memory alarms would stay green on a degraded instance."
  exit 1
fi
rm -f "$CW_AGENT_DEB"

mkdir -p /opt/aws/amazon-cloudwatch-agent/etc
# CloudWatch Agent config notes:
# - `append_dimensions` adds `{InstanceId, AutoScalingGroupName}` to every
#   published metric. CloudWatch treats each distinct dimension combination
#   as its own metric, so the memory alarm in monitoring.tf (which queries
#   on `{AutoScalingGroupName}` alone) would miss these without the
#   `aggregation_dimensions` block below — it republishes each metric at
#   the additional rollup `{AutoScalingGroupName}` (dropping `InstanceId`)
#   so the alarm dimension set actually matches a published series.
#   Without this, the alarm sits in INSUFFICIENT_DATA forever and goes
#   silently green under `treat_missing_data = "notBreaching"`.
# - CPU is deliberately NOT collected via CW Agent. The native
#   `AWS/EC2 CPUUtilization` metric is already aggregable by
#   `AutoScalingGroupName` when the launch template has detailed
#   monitoring enabled (it does — `monitoring { enabled = true }` in the
#   ASG launch template). Using it avoids the CW Agent's per-CPU
#   fan-out (`cpu=cpu0|cpu1|...`) and the `aggregation_dimensions` vs.
#   `totalcpu` interplay, which is easy to get subtly wrong. Matches
#   what the AC module does.
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
    },
    "aggregation_dimensions": [
      ["AutoScalingGroupName"],
      ["InstanceId", "AutoScalingGroupName"]
    ]
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/opt/layerv/qurl-frps/logs/frps.log",
            "log_group_name": "${log_group_name}",
            "log_stream_name": "{instance_id}/frps",
            "timezone": "UTC"
          },
          {
            "file_path": "/var/log/user-data.log",
            "log_group_name": "${log_group_name}",
            "log_stream_name": "{instance_id}/user-data",
            "timezone": "UTC"
          }
        ]
      }
    }
  }
}
CWEOF

if [ ! -x /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl ]; then
  echo "FATAL: CloudWatch Agent installed but binary not found at expected path."
  exit 1
fi
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s
echo "CloudWatch Agent installed and started"

REGION="${region}"
ACCOUNT_ID="${account_id}"

# Note: the cloudmap-register.sh and cloudmap-deregister.sh scripts below
# each fetch their own IMDSv2 token + instance metadata at runtime (they run
# as separate systemd units, not as part of this bootstrap script), so we
# deliberately don't pre-fetch INSTANCE_ID / LOCAL_IP / AZ here.

# ============================================================================
# Create service user + directories
# FRP server binds ports 7000 (control) and 8080 (vhost HTTP) — both >1024,
# so no root privileges are needed. Run as a dedicated unprivileged user
# to limit blast radius if the FRP process is ever compromised.
# ============================================================================
if ! id -u frps >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin frps
fi

mkdir -p /opt/layerv/qurl-frps/etc
mkdir -p /opt/layerv/qurl-frps/logs

# ============================================================================
# Read image tag from SSM (for downloading the correct binary version).
# Fail fast on SSM error — the parameter is created by Terraform and updated
# by CI, so a read failure almost certainly means IAM/network misconfiguration.
# Silently falling back to "latest" would mask that and pull a stale or wrong
# binary.
# ============================================================================
IMAGE_TAG=$(aws ssm get-parameter \
  --name "${ssm_image_tag_param}" \
  --query "Parameter.Value" \
  --output text \
  --region "$REGION") || {
  echo "FATAL: Could not read qurl-frps image tag from SSM parameter ${ssm_image_tag_param}"
  exit 1
}

echo "Using qurl-frps image tag: $IMAGE_TAG"

# ============================================================================
# Download qurl-frps binary
# Pull from ECR as a Docker image and extract the binary.
# ============================================================================
echo "Downloading qurl-frps binary..."
ECR_REGISTRY="$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com"
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$ECR_REGISTRY"

FRPS_IMAGE="$ECR_REGISTRY/layerv/qurl-frps:$IMAGE_TAG"
# Let docker's stderr flow to user-data.log (via `exec 2>&1` at the top) so
# on-call sees the root cause (expired token / image not found / timeout)
# instead of a bare "Could not pull from ECR" falling through to the S3
# fallback.
# Binary permissions are set to 0755 by the `chmod` below (after ownership
# transfer), so the ECR and S3 branches just drop the file in place.
if docker pull "$FRPS_IMAGE"; then
  # Extract binary from container image. If BOTH `docker cp` branches fail,
  # the chained `||` collapses to a non-zero exit and `set -e` trips before
  # the `docker rm` below — leaving an orphan container behind. Install a
  # scoped EXIT trap that force-removes the container regardless of which
  # path we take out. Traps nest by subshell scope; we pop it on the normal
  # path after `docker rm` so the rest of the script isn't affected.
  CONTAINER_ID=$(docker create "$FRPS_IMAGE")
  trap 'docker rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true' EXIT
  docker cp "$CONTAINER_ID:/usr/local/bin/nhp-frps" /opt/layerv/qurl-frps/nhp-frps || \
    docker cp "$CONTAINER_ID:/nhp-frps" /opt/layerv/qurl-frps/nhp-frps
  docker rm "$CONTAINER_ID"
  trap - EXIT
  # Reclaim the image layers (best-effort). Each instance only ever pulls once
  # at boot — new images arrive via ASG instance refresh, not in-place — but
  # keeping the layers around has no upside on a single-service host. Let
  # stderr flow to user-data.log (via `exec 2>&1`) so disk-pressure
  # investigations don't have to re-run the command manually.
  docker rmi "$FRPS_IMAGE" || true
  echo "Binary extracted from ECR image"
else
  echo "WARNING: Could not pull from ECR, checking if binary exists on S3..."
%{ if plugin_bucket_name != "" ~}
  # Bucket name is threaded from root (module.plugins.bucket_name) — kept in
  # lockstep with the frps_s3_fallback IAM grant (which scopes to
  # ${plugin_bucket_name}/binaries/qurl-frps/*) so the two can't diverge.
  # `--expected-bucket-owner` defends against a misconfigured bucket policy
  # (or rewritten plugin_bucket_name var) ever pointing at a foreign
  # bucket; AWS will fail the request with 403 AccessDenied rather than
  # serving content from an attacker-controlled bucket. sha256 integrity
  # verification for the object itself is tracked in #1258.
  aws s3 cp "s3://${plugin_bucket_name}/binaries/qurl-frps/$IMAGE_TAG/nhp-frps" \
    /opt/layerv/qurl-frps/nhp-frps --region "$REGION" \
    --expected-bucket-owner "$ACCOUNT_ID" || {
    echo "FATAL: Could not download qurl-frps binary"
    exit 1
  }
  echo "Binary downloaded from S3"
%{ else ~}
  echo "FATAL: S3 fallback not configured (plugin_bucket_name empty). ECR-only mode; no alternative path."
  exit 1
%{ endif ~}
fi

# Sanity-check the extracted binary: if `docker cp` of the first path
# succeeded but wrote a truncated or zero-byte file (rare — disk pressure,
# malformed image layer), systemd would later fail with an opaque
# "exec format error" rather than a clear extraction failure. Check size
# here and FATAL before the service ever starts. The `aws s3 cp` branch
# exits non-zero on most failure modes, but a 0-byte object slipping
# through would be caught here too.
if [ ! -s /opt/layerv/qurl-frps/nhp-frps ]; then
  echo "FATAL: Binary at /opt/layerv/qurl-frps/nhp-frps is missing or zero-byte after extraction."
  exit 1
fi

# Docker was needed only for the one-shot ECR pull + `docker cp` above.
# Stop and disable the daemon now that the binary lives on disk — frees
# ~150MB RSS on a t3.small and removes an unused attack surface. A future
# re-extraction (e.g., debugging) would need `systemctl enable --now docker`.
systemctl disable --now docker || true

# ============================================================================
# Write frps.toml configuration
# ============================================================================
echo "Writing frps.toml configuration..."
# Note: The heredoc delimiter is shell-quoted ('FRPSEOF') so bash won't
# interpolate $variables at runtime. However, Terraform templatefile()
# resolves all $${} references (frps_bind_port, etc.) at plan time,
# before this script ever reaches the instance. This is intentional.
# WARNING: heredoc below is NOT shell-interpolated — $VAR at runtime is literal.
cat > /opt/layerv/qurl-frps/etc/frps.toml << 'FRPSEOF'
# QURL FRP Server Configuration
# Generated by user_data.sh.tpl at boot time

bindPort = ${frps_bind_port}
vhostHTTPPort = ${frps_vhost_http_port}
subDomainHost = "${frps_subdomain_host}"

# Logging
log.to = "/opt/layerv/qurl-frps/logs/frps.log"
log.level = "info"
log.maxDays = 7

# Transport
transport.maxPoolCount = 10
transport.tcpMux = true

# Web dashboard (localhost only, for debugging via SSM)
webServer.addr = "127.0.0.1"
webServer.port = ${frps_dashboard_port}
FRPSEOF

# frps.toml has no secrets (bindPort, vhostHTTPPort, subDomainHost, log/
# transport/webServer knobs). Standard config-file perms — reserve 0600
# for the env file, which does carry the QURL API token.
chmod 644 /opt/layerv/qurl-frps/etc/frps.toml
echo "frps.toml written"

# Transfer ownership to the frps service user now that config + binary exist.
# The logs dir needs write access; etc/ and the binary need read/execute.
chown -R frps:frps /opt/layerv/qurl-frps
chmod 755 /opt/layerv/qurl-frps/nhp-frps

# ============================================================================
# Fetch QURL API token and create systemd service
# The nhp-frps binary reads QURL_API_URL + QURL_API_TOKEN env vars to enable
# its built-in auth plugin. Without these, tunnel auth is disabled and any
# client can register proxies.
#
# SECURITY: the script runs under `set -ex`, and the top-level `exec` redirect
# ships stderr (including xtrace) to user-data.log → CloudWatch Logs with
# 30–90 day retention. A command like `printf 'TOKEN=%s\n' "$QURL_API_TOKEN"`
# would, under `set -x`, emit a trace line with the token expanded. We bracket
# the entire secret-handling section (fetch → trim → check → write to env
# file) with `set +x` / `set -x` so xtrace never sees the value. Command
# substitution stdout is captured by the variable assignment, not logged.
# ============================================================================
QURL_API_TOKEN=""
set +x
%{ if qurl_api_token_secret_arn != "" ~}
# Token ARN is configured: the FRP auth plugin REQUIRES this token to validate
# tunnel client connections. A fetch failure (IAM glitch, secret rotation
# without policy follow-up, role propagation lag) must be fatal — booting with
# tunnel auth disabled would let any client register arbitrary proxies.
# Fail-fast so the ASG cycles the instance and the no-healthy-instance alarm
# pages on-call with the underlying error visible in user-data log.
echo "Fetching QURL API token from Secrets Manager..."
QURL_API_TOKEN=$(aws secretsmanager get-secret-value \
  --secret-id "${qurl_api_token_secret_arn}" \
  --query "SecretString" \
  --output text \
  --region "$REGION") || {
  set -x
  echo "FATAL: Could not fetch QURL API token from Secrets Manager. Refusing to start with tunnel auth disabled."
  exit 1
}
# aws ... --output text can append a trailing newline; strip CR/LF so the
# token doesn't leak whitespace into the HTTP Authorization header. Trim
# before the emptiness check so a whitespace-only secret still fails fast.
QURL_API_TOKEN=$(printf '%s' "$QURL_API_TOKEN" | tr -d '\r\n')
if [ -z "$QURL_API_TOKEN" ]; then
  set -x
  echo "FATAL: QURL API token secret is empty. Refusing to start with tunnel auth disabled."
  exit 1
fi
# Reject JSON-shaped secrets. The variable description + runbook say the
# secret MUST be a raw token string; some LayerV secrets (e.g., Auth0 creds)
# are stored as `{"token":"..."}` JSON and `--query SecretString --output text`
# returns the whole blob verbatim. Fail fast with an actionable message
# rather than emitting an invalid Authorization header that the auth plugin
# would reject with opaque 401s.
case "$QURL_API_TOKEN" in
  \{*|\[*)
    set -x
    echo "FATAL: QURL API token secret appears to be JSON. Must be a raw token string."
    exit 1
    ;;
esac
# Reject embedded whitespace (tabs, internal spaces, form feeds, etc.). The
# CR/LF trim above handles trailing newlines, but systemd `EnvironmentFile`
# semantics around quoting of internal whitespace are subtle, and a
# well-formed service token (JWT / base64url) never contains whitespace.
# Failing here with an actionable message beats emitting a mangled
# `Authorization` header that the auth plugin rejects with opaque 401s.
case "$QURL_API_TOKEN" in
  *[[:space:]]*)
    set -x
    echo "FATAL: QURL API token contains internal whitespace. Expected a raw JWT or base64url token."
    exit 1
    ;;
esac
%{ endif ~}

# Write environment file for systemd (keeps secrets out of unit file).
# Use `umask 077` in a subshell so the file is created mode 0600 from the
# start — closes the brief root-readable window between `cat >` and `chmod`.
# The URL is a Terraform template literal (resolved at plan time). The token
# is written via `printf` so a rotated token containing `$`, backticks, or
# backslashes is treated as a literal value — not re-interpreted by the
# shell the way an unquoted `cat <<EOF` heredoc would.
(
  umask 077
  : > /opt/layerv/qurl-frps/etc/env
  # QURL_API_URL <- module variable `qurl_api_internal_url` (root
  # wiring at terraform/main.tf, routed through
  # local.qurl_consumer_api_url). The variable name describes the use
  # case; the env-var name is what nhp-frps reads at runtime.
  printf 'QURL_API_URL=%s\n' '${qurl_api_internal_url}' >> /opt/layerv/qurl-frps/etc/env
  printf 'QURL_API_TOKEN=%s\n' "$QURL_API_TOKEN" >> /opt/layerv/qurl-frps/etc/env
)
# Re-enable xtrace now that the secret is no longer on any command line.
set -x
chown frps:frps /opt/layerv/qurl-frps/etc/env

cat > /etc/systemd/system/qurl-frps.service << 'SERVICEEOF'
[Unit]
Description=QURL FRP Server
After=network-online.target
Wants=network-online.target
# Declare the crash-loop-exhausted thresholds explicitly so the `BindsTo=`
# cloudmap-deregister contract is self-documenting: 5 starts within 60s
# trips systemd into `failed`, which stops the register unit and runs
# ExecStop on the deregister one. Systemd's defaults happen to be the
# same, but pinning them here prevents a future default change from
# silently altering the deregister behavior.
StartLimitBurst=5
StartLimitIntervalSec=60

[Service]
Type=simple
User=frps
Group=frps
ExecStart=/opt/layerv/qurl-frps/nhp-frps -c /opt/layerv/qurl-frps/etc/frps.toml
EnvironmentFile=/opt/layerv/qurl-frps/etc/env
Restart=always
RestartSec=5
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

# Defense-in-depth sandbox: the process doesn't need write access outside
# its own logs dir, doesn't need /home, and shouldn't see other processes.
# ProtectSystem=strict covers /usr /boot /efi but leaves /opt writable for
# the process's own UID — since frps owns /opt/layerv/qurl-frps (via the
# `chown -R frps:frps` earlier), a compromised process could otherwise
# rewrite its own binary on disk. ReadOnlyPaths pins the code path + config
# read-only while still allowing writes under ReadWritePaths (logs only).
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=/opt/layerv/qurl-frps/nhp-frps /opt/layerv/qurl-frps/etc
ReadWritePaths=/opt/layerv/qurl-frps/logs

[Install]
WantedBy=multi-user.target
SERVICEEOF

# ============================================================================
# Logrotate for frps.log
# FRP's built-in log config only supports time-based rotation (log.maxDays).
# On a chatty day (auth-plugin rejections, tunnel storms), the log can grow
# unbounded within 7 days and fill the 30GB root volume. logrotate caps size.
# CloudWatch Agent ships logs to CW Logs independently; this only guards disk.
# ============================================================================
cat > /etc/logrotate.d/qurl-frps << 'LOGROTATEEOF'
/opt/layerv/qurl-frps/logs/frps.log {
    size 100M
    rotate 5
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
LOGROTATEEOF

systemctl daemon-reload
systemctl enable qurl-frps
systemctl start qurl-frps
echo "qurl-frps systemd service started"

# Wait for FRP server to be ready (fail boot if it never starts).
# Probes the dashboard port written into frps.toml above — both come from
# the same frps_dashboard_port template variable so they can't drift.
#
# TODO(#1260): the FRP dashboard is currently unauthenticated on 127.0.0.1.
# When #1260 lands basic-auth on the dashboard, this probe must either
# (a) supply credentials via `curl -u user:pass`, (b) point at a new
# unauthenticated `/healthz`-style endpoint exposed by frps, or
# (c) switch to a port-open check (e.g., `nc -z 127.0.0.1 $port`) so the
# auth change doesn't silently cause every new instance to fail the
# 60s readiness window and get killed by the ASG.
FRP_READY=false
for i in {1..30}; do
  if curl -sf http://127.0.0.1:${frps_dashboard_port}/api/serverinfo > /dev/null 2>&1; then
    echo "FRP server is ready"
    FRP_READY=true
    break
  fi
  echo "Waiting for FRP server to start (attempt $i/30)..."
  sleep 2
done

if [ "$FRP_READY" != "true" ]; then
  echo "FATAL: FRP server failed to start after 60 seconds"
  exit 1
fi

# ============================================================================
# Cloud Map registration/deregistration (matches AC module pattern)
# Uses a systemd oneshot service with ExecStop so Cloud Map is cleaned up
# on instance shutdown/termination, preventing stale DNS records.
# ============================================================================
cat > /opt/layerv/qurl-frps/cloudmap-register.sh << 'REGEOF'
#!/bin/bash
set -e
SERVICE_ID="${cloudmap_service_id}"
# IMDSv2 calls get --max-time + --retry. Without them, a slow/flaky IMDS on
# shutdown would hang `ExecStop=cloudmap-deregister.sh` until systemd's
# TimeoutStopSec kicked in (default 90s), extending the ASG terminate path
# exactly when Cloud Map cleanup matters most. Same shape here for symmetry.
IMDS_CURL=(curl -sf --max-time 5 --retry 3)
TOKEN=$("$${IMDS_CURL[@]}" -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$("$${IMDS_CURL[@]}" -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
LOCAL_IP=$("$${IMDS_CURL[@]}" -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
AZ=$("$${IMDS_CURL[@]}" -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
REGION=$("$${IMDS_CURL[@]}" -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
echo "Registering FRPS instance $INSTANCE_ID ($LOCAL_IP) with Cloud Map service $SERVICE_ID"
aws servicediscovery register-instance \
  --service-id "$SERVICE_ID" \
  --instance-id "$INSTANCE_ID" \
  --attributes "AWS_INSTANCE_IPV4=$LOCAL_IP,AVAILABILITY_ZONE=$AZ" \
  --region "$REGION"
echo "FRPS instance registered successfully"
REGEOF
chmod +x /opt/layerv/qurl-frps/cloudmap-register.sh

cat > /opt/layerv/qurl-frps/cloudmap-deregister.sh << 'DEREGEOF'
#!/bin/bash
set -e
SERVICE_ID="${cloudmap_service_id}"
# See cloudmap-register.sh for rationale on --max-time / --retry.
IMDS_CURL=(curl -sf --max-time 5 --retry 3)
TOKEN=$("$${IMDS_CURL[@]}" -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$("$${IMDS_CURL[@]}" -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
REGION=$("$${IMDS_CURL[@]}" -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
echo "Deregistering FRPS instance $INSTANCE_ID from Cloud Map service $SERVICE_ID"
aws servicediscovery deregister-instance \
  --service-id "$SERVICE_ID" \
  --instance-id "$INSTANCE_ID" \
  --region "$REGION" || true
echo "FRPS instance deregistered"
DEREGEOF
chmod +x /opt/layerv/qurl-frps/cloudmap-deregister.sh

cat > /etc/systemd/system/frps-cloudmap-register.service << SVCEOF
[Unit]
Description=Register QURL FRP Server with Cloud Map
After=network-online.target qurl-frps.service
# BindsTo ties registration lifecycle to qurl-frps: if the FRP service stops
# (crash-loop exhausted, manual stop), systemd will also stop this unit,
# which triggers ExecStop (deregister). Without this, a dead FRP process
# leaves a stale Cloud Map record serving traffic until ASG replaces the
# instance.
BindsTo=qurl-frps.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/layerv/qurl-frps/cloudmap-register.sh
RemainAfterExit=yes
ExecStop=/opt/layerv/qurl-frps/cloudmap-deregister.sh

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable frps-cloudmap-register
systemctl start frps-cloudmap-register
echo "Registered with Cloud Map as frps.${namespace_name} (with deregistration on shutdown)"

echo "QURL FRP server installation complete at $(date)"
