#!/bin/bash
# QURL FRP Server User Data Script
#
# Bootstraps a qurl-reverse-tunnel-server instance: installs dependencies, writes frps.toml
# config (values resolved by Terraform templatefile() at plan time), starts
# the FRP server as a systemd service, and registers with Cloud Map for
# service discovery.
#
# Debugging notes for on-call:
# - Docker is installed, used ONCE to pull the qurl-reverse-tunnel-server image and extract
#   the binary, then `systemctl disable --now docker` is run to free ~150MB
#   RSS on the t3.small and shrink the attack surface. If you need to
#   re-extract the binary (e.g., swap image_tag by hand for a hotfix), run
#   `sudo systemctl enable --now docker` first before re-running the
#   extraction block.
# - The binary is pulled from `/usr/local/bin/qurl-reverse-tunnel-server` (canonical, matches
#   the qurl-reverse-tunnel-server Dockerfile) with fallback to the legacy
#   `/usr/local/bin/nhp-frps` and `/nhp-frps` paths for older images still
#   pinned in SSM history. If the qurl-reverse-tunnel-server image layout changes again, ALL
#   THREE paths below need to track; the image's CI should pin its own path
#   so this stays in lockstep. A `WARN: legacy fallback ...` line is logged
#   when a non-canonical path hits — query CloudWatch for it before dropping
#   the legacy branches.
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
            "file_path": "/opt/layerv/qurl-reverse-tunnel-server/logs/frps.log",
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

mkdir -p /opt/layerv/qurl-reverse-tunnel-server/etc
mkdir -p /opt/layerv/qurl-reverse-tunnel-server/logs

# ============================================================================
# Read image tag from SSM (for downloading the correct binary version).
# Fail fast on SSM error — the parameter is created and updated by rts CI's
# docker-publish workflow (no Terraform-side `aws_ssm_parameter`; see
# modules/qurl-reverse-tunnel-server/ssm.tf header for the ownership split),
# so a read failure means either rts CI has not yet published this env (no
# image to boot) or IAM/network misconfiguration. Silently falling back to
# "latest" would mask that and pull a stale or wrong binary.
# ============================================================================
IMAGE_TAG=$(aws ssm get-parameter \
  --name "${ssm_image_tag_param}" \
  --query "Parameter.Value" \
  --output text \
  --region "$REGION") || {
  echo "FATAL: Could not read qurl-reverse-tunnel-server image tag from SSM parameter ${ssm_image_tag_param}"
  exit 1
}

echo "Using qurl-reverse-tunnel-server image tag: $IMAGE_TAG"

# ============================================================================
# Download qurl-reverse-tunnel-server binary
# Pull from ECR as a Docker image and extract the binary.
# ============================================================================
echo "Downloading qurl-reverse-tunnel-server binary..."
ECR_REGISTRY="$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com"
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$ECR_REGISTRY"

FRPS_IMAGE="$ECR_REGISTRY/layerv/qurl-reverse-tunnel-server:$IMAGE_TAG"
# The in-image path named by the signed build receipt. Keep in lockstep with
# QRTS_BUILD_RECEIPT_BINARY_PATH in
# .github/scripts/collect_udp_proof_deployment_evidence.py — the runtime
# attestation below reconstructs the receipt byte-for-byte from this constant,
# so a silent drift here shows up as an unexplained producer failure.
RECEIPT_BINARY_PATH=/usr/local/bin/qurl-reverse-tunnel-server
# Let docker's stderr flow to user-data.log (via `exec 2>&1` at the top) so
# on-call sees the root cause (expired token / image not found / timeout)
# instead of a bare "Could not pull from ECR" falling through to the S3
# fallback.
# Binary permissions are set to 0755 by the `chmod` below (after ownership
# transfer), so the ECR and S3 branches just drop the file in place.
if docker pull "$FRPS_IMAGE"; then
  # Extract binary from container image. If ALL three `docker cp` branches
  # fail, the chained `||` collapses to a non-zero exit and `set -e` trips
  # before the `docker rm` below — leaving an orphan container behind.
  # Install a scoped EXIT trap that force-removes the container regardless
  # of which path we take out. Traps nest by subshell scope; we pop it on
  # the normal path after `docker rm` so the rest of the script isn't
  # affected.
  CONTAINER_ID=$(docker create "$FRPS_IMAGE")
  trap 'docker rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true' EXIT
  # Container path: the qurl-reverse-tunnel-server Dockerfile installs the
  # binary at /usr/local/bin/qurl-reverse-tunnel-server (canonical binary name across the
  # qurl-reverse-tunnel-server source repo and the systemd unit; the ECR
  # repo it ships in is `layerv/qurl-reverse-tunnel-server`). The
  # /usr/local/bin/nhp-frps and /nhp-frps fallbacks remain for older
  # bootstrap images that pre-date the rename. Each legacy hit emits a
  # `WARN: legacy fallback ...` line to user-data.log → CloudWatch so a
  # single Logs Insights query gates the eventual cleanup; without that
  # signal "nobody complained" is the only proxy for safe-to-drop.
  # IMAGE_BINARY_PATH records which in-image path actually won, because only
  # the canonical one is named by the signed build receipt the runtime
  # attestation reconstructs below.
  IMAGE_BINARY_PATH="$RECEIPT_BINARY_PATH"
  docker cp "$CONTAINER_ID:/usr/local/bin/qurl-reverse-tunnel-server" /opt/layerv/qurl-reverse-tunnel-server/nhp-frps || {
    echo "WARN: legacy fallback to /usr/local/bin/nhp-frps — image is pre-rename"
    IMAGE_BINARY_PATH=/usr/local/bin/nhp-frps
    docker cp "$CONTAINER_ID:/usr/local/bin/nhp-frps" /opt/layerv/qurl-reverse-tunnel-server/nhp-frps
  } || {
    echo "WARN: legacy fallback to /nhp-frps — image is even older"
    IMAGE_BINARY_PATH=/nhp-frps
    docker cp "$CONTAINER_ID:/nhp-frps" /opt/layerv/qurl-reverse-tunnel-server/nhp-frps
  }
  docker rm "$CONTAINER_ID"
  trap - EXIT

  # ==========================================================================
  # Runtime-attestation boot capture
  #
  # Written here and nowhere else, while the extraction image is still on the
  # box. This is the only moment a qRTS node can honestly observe the ECR
  # digest and OCI revision of the image its binary came from: `docker rmi`
  # below destroys that evidence, and the running service keeps no container to
  # re-inspect. Re-deriving it later from the SSM image-tag parameter would be
  # worse than nothing — a mutable pointer cannot prove what THIS instance
  # booted, which is the entire reason
  # terraform/modules/runtime-attestation-store exists.
  #
  # `build_receipt_sha256` is the SHA-256 of the canonical build receipt
  # layervai/qurl-reverse-tunnel-server's Docker Publish workflow signs: a
  # fixed-layout ASCII line over (schema_version, source_revision, binary_path,
  # binary_sha256) with a trailing newline. The node RECONSTRUCTS it from its
  # own observations rather than fetching it, so it can only match when the
  # binary on this disk is byte-identical to the one that was signed. The
  # producer re-derives the same value from the cosign-verified attestation and
  # fails closed on any divergence, so a node cannot talk its way past a
  # mismatch.
  #
  # Deliberately NOT written on the two legacy `docker cp` paths or on the S3
  # fallback below: the signed receipt names /usr/local/bin/qurl-reverse-tunnel-
  # server, and an S3-sourced binary carries no ECR provenance at all. In both
  # cases the correct output is no capture — the collector then fails closed
  # with "qRTS boot capture is missing" instead of publishing a claim this node
  # cannot support.
  # ==========================================================================
  IMAGE_DIGEST=$(docker image inspect "$FRPS_IMAGE" \
    --format '{{range .RepoDigests}}{{println .}}{{end}}' 2>/dev/null \
    | grep -F "$ECR_REGISTRY/layerv/qurl-reverse-tunnel-server@" \
    | cut -d'@' -f2 | sort -u || true)
  IMAGE_DIGEST_COUNT=$(printf '%s\n' "$IMAGE_DIGEST" | grep -c . || true)
  SOURCE_REVISION=$(docker image inspect "$FRPS_IMAGE" \
    --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' 2>/dev/null || true)
  INSTALLED_BINARY_SHA256=$(sha256sum /opt/layerv/qurl-reverse-tunnel-server/nhp-frps | cut -d' ' -f1 || true)

  if [ "$IMAGE_BINARY_PATH" = "$RECEIPT_BINARY_PATH" ] &&
    [ "$IMAGE_DIGEST_COUNT" = "1" ] &&
    printf '%s' "$IMAGE_DIGEST" | grep -Eq '^sha256:[0-9a-f]{64}$' &&
    printf '%s' "$SOURCE_REVISION" | grep -Eq '^[0-9a-f]{40}$' &&
    printf '%s' "$INSTALLED_BINARY_SHA256" | grep -Eq '^[0-9a-f]{64}$'; then
    BUILD_RECEIPT_SHA256=$(printf \
      '{"schema_version":1,"source_revision":"%s","binary_path":"%s","binary_sha256":"%s"}\n' \
      "$SOURCE_REVISION" "$RECEIPT_BINARY_PATH" "$INSTALLED_BINARY_SHA256" \
      | sha256sum | cut -d' ' -f1)
    install -d -m 0755 -o root -g root /var/lib/layerv/runtime-attestation
    BOOT_CAPTURE_STAGED=$(mktemp)
    jq -n \
      --arg image_digest "$IMAGE_DIGEST" \
      --arg source_revision "$SOURCE_REVISION" \
      --arg build_receipt_sha256 "$BUILD_RECEIPT_SHA256" \
      --arg installed_binary_sha256 "$INSTALLED_BINARY_SHA256" \
      '{
        image_digest: $image_digest,
        source_revision: $source_revision,
        build_receipt_sha256: $build_receipt_sha256,
        installed_binary_sha256: $installed_binary_sha256,
        source_kind: "ecr_build_receipt"
      }' >"$BOOT_CAPTURE_STAGED"
    install -m 0644 -o root -g root "$BOOT_CAPTURE_STAGED" \
      /var/lib/layerv/runtime-attestation/boot-capture.json
    rm -f "$BOOT_CAPTURE_STAGED"
    echo "Wrote runtime-attestation boot capture for $IMAGE_DIGEST ($SOURCE_REVISION)"
  else
    echo "WARN: no runtime-attestation boot capture written (in-image path '$IMAGE_BINARY_PATH', digest '$IMAGE_DIGEST', revision '$SOURCE_REVISION'). This node cannot prove its runtime provenance, so the collector will fail closed and the UDP-proof manifest producer will refuse to emit a manifest for this fleet."
  fi

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
  # lockstep with the frps_s3_fallback IAM grant (which scopes to BOTH
  # ${plugin_bucket_name}/binaries/qurl-reverse-tunnel-server/* AND the
  # legacy ${plugin_bucket_name}/binaries/qurl-frps/* prefix) so the
  # canonical-then-legacy fallback chain below can't AccessDenied on the
  # legacy branch. The legacy grant + branch exist to keep the S3
  # fallback usable across the rebrand transition: if qurl-reverse-tunnel-
  # server's publishing CI is still writing to `binaries/qurl-frps/`
  # when an instance boots and ECR is degraded, we don't want to be
  # stuck. Drop both the legacy grant and the legacy branch in lockstep
  # once the publish target has migrated and at least one cycle of S3
  # objects under the new prefix has been written.
  # `--expected-bucket-owner` defends against a misconfigured bucket policy
  # (or rewritten plugin_bucket_name var) ever pointing at a foreign
  # bucket; AWS will fail the request with 403 AccessDenied rather than
  # serving content from an attacker-controlled bucket. sha256 integrity
  # verification for the object itself is tracked in #1258.
  aws s3 cp "s3://${plugin_bucket_name}/binaries/qurl-reverse-tunnel-server/$IMAGE_TAG/nhp-frps" \
    /opt/layerv/qurl-reverse-tunnel-server/nhp-frps --region "$REGION" \
    --expected-bucket-owner "$ACCOUNT_ID" || {
    echo "WARN: legacy fallback to s3://.../binaries/qurl-frps/ — publish target is pre-rename"
    aws s3 cp "s3://${plugin_bucket_name}/binaries/qurl-frps/$IMAGE_TAG/nhp-frps" \
      /opt/layerv/qurl-reverse-tunnel-server/nhp-frps --region "$REGION" \
      --expected-bucket-owner "$ACCOUNT_ID" || {
      echo "FATAL: Could not download qurl-reverse-tunnel-server binary from either prefix"
      exit 1
    }
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
if [ ! -s /opt/layerv/qurl-reverse-tunnel-server/nhp-frps ]; then
  echo "FATAL: Binary at /opt/layerv/qurl-reverse-tunnel-server/nhp-frps is missing or zero-byte after extraction."
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
cat > /opt/layerv/qurl-reverse-tunnel-server/etc/frps.toml << 'FRPSEOF'
# QURL FRP Server Configuration
# Generated by user_data.sh.tpl at boot time

bindPort = ${frps_bind_port}
vhostHTTPPort = ${frps_vhost_http_port}
subDomainHost = "${frps_subdomain_host}"

# Logging
log.to = "/opt/layerv/qurl-reverse-tunnel-server/logs/frps.log"
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
chmod 644 /opt/layerv/qurl-reverse-tunnel-server/etc/frps.toml
echo "frps.toml written"

# Transfer ownership to the frps service user now that config + binary exist.
# The logs dir needs write access; etc/ and the binary need read/execute.
chown -R frps:frps /opt/layerv/qurl-reverse-tunnel-server
chmod 755 /opt/layerv/qurl-reverse-tunnel-server/nhp-frps

# ============================================================================
# Runtime min-client-version gate.
# qurl-reverse-tunnel-server reads MIN_CLIENT_VERSION_FILE and hot-reloads it
# internally. This timer keeps the local file synced with SSM so ops can raise
# or lower the connector floor without an instance refresh. The server polls
# and reopens the path, so the atomic rename below is observed by the running
# process rather than depending on an inode-scoped file watch.
# ============================================================================
MIN_CLIENT_VERSION_FILE="${min_client_version_file}"
MIN_CLIENT_VERSION_SYNC_SCRIPT="/usr/local/bin/qurl-min-client-version-sync.sh"

cat > "$MIN_CLIENT_VERSION_SYNC_SCRIPT" << 'MINCLIENTEOF'
#!/bin/bash
set -euo pipefail

REGION="${region}"
PARAM_NAME="${ssm_min_client_version_param}"
DISABLED_VALUE="${min_client_version_disabled}"
TARGET="${min_client_version_file}"
TMP=$(mktemp "$TARGET.XXXXXX")

emit_sync_failure_metric() {
  command -v aws &>/dev/null && aws cloudwatch put-metric-data \
    --namespace "LayerV/NHP" \
    --metric-name "FRPSMinClientVersionSyncFailure" \
    --value 1 --unit Count \
    --dimensions "Component=frps,Environment=${environment}" \
    --region "$REGION" 2>/dev/null || true
}

cleanup() {
  local status=$?
  rm -f "$TMP"
  if [ "$status" -ne 0 ]; then
    emit_sync_failure_metric
  fi
  exit "$status"
}
trap cleanup EXIT

raw=$(aws ssm get-parameter \
  --name "$PARAM_NAME" \
  --query "Parameter.Value" \
  --output text \
  --region "$REGION")
raw=$(printf '%s' "$raw" | tr -d '\r\n')

if [ "$raw" = "$DISABLED_VALUE" ]; then
  raw=""
fi

# Runtime SSM edits bypass Terraform validation; reject malformed updates here
# so operator typos keep the prior known-good file instead of poisoning FRPS.
SEMVER_RE='^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
if [ -n "$raw" ] && [[ ! "$raw" =~ $SEMVER_RE ]]; then
  echo "ERROR: $PARAM_NAME value must be disabled or semantic version MAJOR.MINOR.PATCH without build metadata; got '$raw'" >&2
  exit 1
fi

printf '%s' "$raw" > "$TMP"
chown frps:frps "$TMP"
chmod 0640 "$TMP"
mv "$TMP" "$TARGET"
trap - EXIT
MINCLIENTEOF
chmod 755 "$MIN_CLIENT_VERSION_SYNC_SCRIPT"

cat > /etc/systemd/system/qurl-min-client-version-sync.service << 'MINCLIENTSERVICEEOF'
[Unit]
Description=Sync qURL connector minimum version from SSM
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/qurl-min-client-version-sync.sh
MINCLIENTSERVICEEOF

cat > /etc/systemd/system/qurl-min-client-version-sync.timer << 'MINCLIENTTIMEREOF'
[Unit]
Description=Refresh qURL connector minimum version from SSM

[Timer]
# 30s is the intended kill-switch propagation target. RandomizedDelaySec avoids
# every FRPS instance polling SSM at exactly the same second.
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s
RandomizedDelaySec=10s
Unit=qurl-min-client-version-sync.service

[Install]
WantedBy=timers.target
MINCLIENTTIMEREOF

if retry_with_backoff 3 2 10 "$MIN_CLIENT_VERSION_SYNC_SCRIPT"; then
  echo "min-client-version synced from SSM"
else
  # Availability wins during boot: seed "disabled" so FRPS can start, then let
  # the timer recover the intended floor. The sync-failure metric alarms during
  # this temporary fail-open window.
  echo "WARN: Could not sync min-client-version from SSM during boot after retries. Seeding disabled policy; timer will keep retrying."
  : > "$MIN_CLIENT_VERSION_FILE"
  chown frps:frps "$MIN_CLIENT_VERSION_FILE"
  chmod 0640 "$MIN_CLIENT_VERSION_FILE"
fi

# ============================================================================
# Fetch shared secrets and create systemd service.
# In tunnel-auth mode the binary reads QURL_API_URL +
# QURL_INTERNAL_SERVICE_TOKEN for qurl-service auth and
# NHP_SERVER_INTERNAL_URL + NHP_INTERNAL_AUTH_SECRET for knock-token
# validation. Missing values are fatal: modern multi-tenant images refuse to
# start instead of falling back to an open tunnel server.
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
# Token ARN is configured: qurl-reverse-tunnel-server REQUIRES this token to
# authenticate its internal calls to qurl-service. A fetch failure (IAM glitch,
# secret rotation without policy follow-up, role propagation lag) must be
# fatal so the ASG cycles the instance and the no-healthy-instance alarm pages
# on-call with the underlying error visible in user-data log.
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

NHP_INTERNAL_AUTH_SECRET=""
%{ if qurl_tunnel_auth_mode == "tunnel-auth" ~}
echo "Fetching NHP internal auth secret from Secrets Manager..."
NHP_INTERNAL_AUTH_SECRET=$(aws secretsmanager get-secret-value \
  --secret-id "${nhp_internal_auth_secret_arn}" \
  --query "SecretString" \
  --output text \
  --region "$REGION") || {
  set -x
  echo "FATAL: Could not fetch NHP internal auth secret from Secrets Manager. Refusing to start without knock-token validation."
  exit 1
}
# Keep this hygiene in lockstep with QURL_API_TOKEN above. The NHP secret is
# the HMAC key used to sign knock-token validation requests; accepting hidden
# CR/LF, JSON blobs, or whitespace would make every validator call fail with
# opaque HMAC mismatches at runtime.
NHP_INTERNAL_AUTH_SECRET=$(printf '%s' "$NHP_INTERNAL_AUTH_SECRET" | tr -d '\r\n')
if [ -z "$NHP_INTERNAL_AUTH_SECRET" ]; then
  set -x
  echo "FATAL: NHP internal auth secret is empty. Refusing to start without knock-token validation."
  exit 1
fi
case "$NHP_INTERNAL_AUTH_SECRET" in
  \{*|\[*)
    set -x
    echo "FATAL: NHP internal auth secret appears to be JSON. Must be a raw HMAC secret string."
    exit 1
    ;;
esac
case "$NHP_INTERNAL_AUTH_SECRET" in
  *[[:space:]]*)
    set -x
    echo "FATAL: NHP internal auth secret contains internal whitespace. Expected a raw alphanumeric secret."
    exit 1
    ;;
esac
if [ "$${#NHP_INTERNAL_AUTH_SECRET}" -lt 32 ]; then
  set -x
  echo "FATAL: NHP internal auth secret is shorter than the 32-byte floor (got $${#NHP_INTERNAL_AUTH_SECRET})."
  exit 1
fi

# Active-registration identity. The router must dial the exact FRP instance
# that accepted the client tunnel, not a load-balanced boundary name, so the
# published upstream endpoint is the instance's private vhost listener. The
# boundary label is the public NHP-protected control ingress that led to this
# AZ, useful for forensics and future placement policy but not a routing key.
TUNNEL_IMDS_CURL=(curl -sf --max-time 5 --retry 3)
TUNNEL_IMDS_TOKEN=$("$${TUNNEL_IMDS_CURL[@]}" -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") || {
  set -x
  echo "FATAL: active-registration IMDSv2 token fetch failed."
  exit 1
}
TUNNEL_INSTANCE_ID=$("$${TUNNEL_IMDS_CURL[@]}" -H "X-aws-ec2-metadata-token: $TUNNEL_IMDS_TOKEN" http://169.254.169.254/latest/meta-data/instance-id) || {
  set -x
  echo "FATAL: active-registration IMDS instance-id lookup failed."
  exit 1
}
TUNNEL_LOCAL_IP=$("$${TUNNEL_IMDS_CURL[@]}" -H "X-aws-ec2-metadata-token: $TUNNEL_IMDS_TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4) || {
  set -x
  echo "FATAL: active-registration IMDS local-ipv4 lookup failed."
  exit 1
}
TUNNEL_AZ=$("$${TUNNEL_IMDS_CURL[@]}" -H "X-aws-ec2-metadata-token: $TUNNEL_IMDS_TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone) || {
  set -x
  echo "FATAL: active-registration IMDS availability-zone lookup failed."
  exit 1
}
TUNNEL_AZ_SUFFIX="$${TUNNEL_AZ: -1}"
if ! [[ "$TUNNEL_AZ_SUFFIX" =~ ^[a-z]$ ]]; then
  set -x
  echo "FATAL: active-registration AZ suffix '$TUNNEL_AZ_SUFFIX' (from AZ '$TUNNEL_AZ') is not a single lowercase letter."
  exit 1
fi
declare -A QURL_TUNNEL_PUBLIC_CONTROL_PORTS=(
%{ for suffix, port in tunnel_server_az_control_ports ~}
  ["${suffix}"]="${port}"
%{ endfor ~}
)
QURL_TUNNEL_PUBLIC_CONTROL_PORT="$${QURL_TUNNEL_PUBLIC_CONTROL_PORTS[$TUNNEL_AZ_SUFFIX]:-}"
if [ -z "$QURL_TUNNEL_PUBLIC_CONTROL_PORT" ]; then
  set -x
  echo "FATAL: no public control port configured for active-registration AZ suffix '$TUNNEL_AZ_SUFFIX'."
  exit 1
fi
QURL_TUNNEL_INSTANCE_ENDPOINT_VALUE="http://$${TUNNEL_LOCAL_IP}:${frps_vhost_http_port}"
QURL_TUNNEL_BOUNDARY_VALUE="${connect_layerv_host}:$${QURL_TUNNEL_PUBLIC_CONTROL_PORT}"
%{ endif ~}

# Write environment file for systemd (keeps secrets out of unit file).
# Use `umask 077` in a subshell so the file is created mode 0600 from the
# start — closes the brief root-readable window between `cat >` and `chmod`.
# The URL is a Terraform template literal (resolved at plan time). The token
# is written via `printf` so a rotated token containing `$`, backticks, or
# backslashes is treated as a literal value — not re-interpreted by the
# shell the way an unquoted `cat <<EOF` heredoc would.
#
# Env shape depends on qurl_tunnel_auth_mode:
#   ""             - module-compat legacy env shape: QURL_API_URL +
#                    QURL_API_TOKEN. Current multi-tenant images are
#                    plan-gated away from this branch by the root module.
#   "tunnel-auth"  - knock-token-as-identity mode:
#                    QURL_API_URL + QURL_INTERNAL_SERVICE_TOKEN +
#                    QURL_TUNNEL_AUTH_MODE=tunnel-auth +
#                    NHP_SERVER_INTERNAL_URL + NHP_INTERNAL_AUTH_SECRET +
#                    QURL_TUNNEL_INSTANCE_* active-registration metadata.
#                    qurl-reverse-tunnel-server validates the AC-issued
#                    knock token with nhp-server, authorizes NewProxy via
#                    qurl-service POST /internal/v1/tunnel/auth-by-owner,
#                    and publishes active target rows for qurl-router.
(
  umask 077
  : > /opt/layerv/qurl-reverse-tunnel-server/etc/env
  # QURL_API_URL <- module variable `qurl_api_internal_url` (root
  # wiring at terraform/main.tf, routed through
  # local.qurl_consumer_api_url). The variable name describes the use
  # case; the env-var name is what nhp-frps reads at runtime.
  printf 'QURL_API_URL=%s\n' '${qurl_api_internal_url}' >> /opt/layerv/qurl-reverse-tunnel-server/etc/env
  printf 'MIN_CLIENT_VERSION_FILE=%s\n' "$MIN_CLIENT_VERSION_FILE" >> /opt/layerv/qurl-reverse-tunnel-server/etc/env
%{ if qurl_tunnel_auth_mode == "tunnel-auth" ~}
  # Reaching this branch with $QURL_API_TOKEN unset/empty would write
  # QURL_INTERNAL_SERVICE_TOKEN= silently — qurl-reverse-tunnel-server would then boot
  # in tunnel-auth mode with no shared secret, surfacing as opaque
  # 401s on /internal/v1/tunnel/auth-by-owner at runtime. The token-fetch +
  # JSON/whitespace/empty-string validation block above is gated on
  # qurl_api_token_secret_arn != "", so what keeps this branch from
  # ever running with an empty token is the ASG precondition in
  # ../main.tf ("tunnel-auth requires qurl_api_token_secret_arn").
  # If you ever loosen that precondition, also extend the validation
  # block above to fire in tunnel-auth mode regardless of ARN.
  printf 'QURL_TUNNEL_AUTH_MODE=tunnel-auth\n' >> /opt/layerv/qurl-reverse-tunnel-server/etc/env
  printf 'QURL_INTERNAL_SERVICE_TOKEN=%s\n' "$QURL_API_TOKEN" >> /opt/layerv/qurl-reverse-tunnel-server/etc/env
  printf 'NHP_SERVER_INTERNAL_URL=%s\n' '${nhp_server_internal_url}' >> /opt/layerv/qurl-reverse-tunnel-server/etc/env
  printf 'NHP_INTERNAL_AUTH_SECRET=%s\n' "$NHP_INTERNAL_AUTH_SECRET" >> /opt/layerv/qurl-reverse-tunnel-server/etc/env
  printf 'QURL_TUNNEL_INSTANCE_ENDPOINT=%s\n' "$QURL_TUNNEL_INSTANCE_ENDPOINT_VALUE" >> /opt/layerv/qurl-reverse-tunnel-server/etc/env
  printf 'QURL_TUNNEL_INSTANCE_ID=%s\n' "$TUNNEL_INSTANCE_ID" >> /opt/layerv/qurl-reverse-tunnel-server/etc/env
  printf 'QURL_TUNNEL_INSTANCE_AZ=%s\n' "$TUNNEL_AZ" >> /opt/layerv/qurl-reverse-tunnel-server/etc/env
  printf 'QURL_TUNNEL_BOUNDARY=%s\n' "$QURL_TUNNEL_BOUNDARY_VALUE" >> /opt/layerv/qurl-reverse-tunnel-server/etc/env
%{ else ~}
  printf 'QURL_API_TOKEN=%s\n' "$QURL_API_TOKEN" >> /opt/layerv/qurl-reverse-tunnel-server/etc/env
%{ endif ~}
)
# Re-enable xtrace now that the secret is no longer on any command line.
set -x
unset QURL_API_TOKEN NHP_INTERNAL_AUTH_SECRET
chown frps:frps /opt/layerv/qurl-reverse-tunnel-server/etc/env

cat > /etc/systemd/system/qurl-reverse-tunnel-server.service << 'SERVICEEOF'
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
ExecStart=/opt/layerv/qurl-reverse-tunnel-server/nhp-frps -c /opt/layerv/qurl-reverse-tunnel-server/etc/frps.toml
EnvironmentFile=/opt/layerv/qurl-reverse-tunnel-server/etc/env
Restart=always
RestartSec=5
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

# Defense-in-depth sandbox: the process doesn't need write access outside
# its own logs dir, doesn't need /home, and shouldn't see other processes.
# ProtectSystem=strict covers /usr /boot /efi but leaves /opt writable for
# the process's own UID — since frps owns /opt/layerv/qurl-reverse-tunnel-server (via the
# `chown -R frps:frps` earlier), a compromised process could otherwise
# rewrite its own binary on disk. ReadOnlyPaths pins the code path + config
# read-only while still allowing writes under ReadWritePaths (logs only).
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=/opt/layerv/qurl-reverse-tunnel-server/nhp-frps /opt/layerv/qurl-reverse-tunnel-server/etc
ReadWritePaths=/opt/layerv/qurl-reverse-tunnel-server/logs

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
cat > /etc/logrotate.d/qurl-reverse-tunnel-server << 'LOGROTATEEOF'
/opt/layerv/qurl-reverse-tunnel-server/logs/frps.log {
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
systemctl enable --now qurl-min-client-version-sync.timer
systemctl enable qurl-reverse-tunnel-server
systemctl start qurl-reverse-tunnel-server
echo "qurl-reverse-tunnel-server systemd service started"

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
  # Exit without completing the launch hook: the instance never leaves
  # Pending:Wait, and the hook applies its default_result at heartbeat_timeout
  # (qurl-reverse-tunnel-server#195). We deliberately do NOT signal ABANDON here
  # — see the launch-readiness block near the end of this script for why all
  # failures fall through to default_result uniformly.
  exit 1
fi

# ============================================================================
# Cloud Map registration/deregistration (per-AZ, see module header for rationale)
# Uses a systemd oneshot service with ExecStop so Cloud Map is cleaned up
# on instance shutdown/termination, preventing stale DNS records.
#
# The instance reads its AZ/color from IMDS at runtime, derives the stable
# Cloud Map service name, resolves that name to the current service ID, and
# registers. Do not render service IDs into user_data: the launch template
# is create-before-destroy, and that dependency propagates CBD into the
# static-name Cloud Map services, making routing_policy replacement
# impossible.
# ============================================================================
# CI extracts this script by matching the next heredoc opener exactly;
# update .github/workflows/ubuntu-build.yml if the path or delimiter changes.
cat > /opt/layerv/qurl-reverse-tunnel-server/cloudmap-common.sh << 'CLOUDMAP_COMMON_EOF'
#!/bin/bash
# Sourced by scripts with different set-flag policies; do not add `set -e`
# here or deregister's warn-and-exit-0 contract will become brittle.

export AWS_PAGER=""

lookup_cloudmap_service_id() {
  local service_name="$1"
  local region="$2"
  local namespace_id="$3"
  local attempt output err_file err

  if [ -z "$service_name" ] || [ -z "$region" ] || [ -z "$namespace_id" ]; then
    echo "ERROR: lookup_cloudmap_service_id requires service name, region, and namespace ID" >&2
    return 1
  fi
  # Keep this regex in lockstep with `var.frps_az_suffixes` validation:
  # suffixes are a single lowercase letter, so the derived names are
  # `frps-$${suffix}` or `frps-green-$${suffix}`.
  # Do not widen this without adding a real JMESPath string escaper below.
  if ! [[ "$service_name" =~ ^frps(-green)?-[a-z]$ ]]; then
    echo "ERROR: Cloud Map service name '$service_name' is not a supported FRPS per-AZ service name" >&2
    return 1
  fi

  err_file=$(mktemp) || {
    echo "ERROR: mktemp failed while preparing Cloud Map lookup for service '$service_name' in namespace '$namespace_id'" >&2
    return 1
  }
  for attempt in 1 2 3 4 5; do
    : > "$err_file"
    # AWS CLI v2 auto-paginates list-services by default; do not add
    # --no-paginate here, or a large namespace could hide services beyond page 1.
    # The read timeout is per HTTP call/page, not a cap on the full paginated
    # list operation.
    # `--query` filters client-side after list-services returns the namespace's
    # services; keep this namespace dedicated to FRPS-scale service counts.
    # The service_name regex above keeps this JMESPath literal safe. If that
    # contract widens, escape service_name for JMESPath before interpolating it.
    if output=$(aws servicediscovery list-services \
      --region "$region" \
      --cli-connect-timeout 3 \
      --cli-read-timeout 5 \
      --filters "Name=NAMESPACE_ID,Values=$namespace_id,Condition=EQ" \
      --query "Services[?Name=='$service_name'].Id | [0]" \
      --output text 2>"$err_file"); then
      rm -f "$err_file"
      # No match is a successful AWS/API call; with this exact
      # `--query ... --output text` shape AWS CLI renders it as "None".
      # Normalize that sentinel to empty stdout so callers can distinguish
      # missing-service config from API/permission/reachability failure by
      # checking only exit code plus empty/non-empty output.
      if [ "$output" = "None" ]; then
        return 0
      fi
      printf '%s\n' "$output"
      return 0
    fi

    err=$(cat "$err_file" 2>/dev/null || true)
    echo "WARN: Cloud Map list-services failed for service '$service_name' in namespace '$namespace_id' (attempt $attempt/5): $${err:-<empty stderr>}" >&2
    if [ "$attempt" -lt 5 ]; then
      sleep $((attempt * 2))
    fi
  done

  rm -f "$err_file"
  echo "ERROR: Cloud Map list-services failed after 5 attempts for service '$service_name' in namespace '$namespace_id'. This is a Cloud Map API/permission/reachability failure, not a missing-service configuration." >&2
  return 1
}
CLOUDMAP_COMMON_EOF
chmod 0644 /opt/layerv/qurl-reverse-tunnel-server/cloudmap-common.sh
# common.sh is sourced, not executed; keep it readable but not executable.

# CI extracts this script by matching the next heredoc opener exactly;
# update .github/workflows/ubuntu-build.yml if the path or delimiter changes.
cat > /opt/layerv/qurl-reverse-tunnel-server/cloudmap-register.sh << 'CLOUDMAP_REGISTER_EOF'
#!/bin/bash
set -e
NAMESPACE_ID='${namespace_id}'
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
# shellcheck disable=SC1091
. /opt/layerv/qurl-reverse-tunnel-server/cloudmap-common.sh
# DeployColor IMDS tag — propagated at launch by both ASGs when
# `var.enable_blue_green = true`: green via the always-propagate `tag`
# block in blue_green.tf, blue via the dynamic `tag` block in main.tf
# gated on `var.enable_blue_green`. When blue/green is DISABLED the
# blue ASG omits the tag entirely (no resource diff for non-blue/green
# deploys), and the IMDS read returns 404; we default to blue in that
# case so the existing single-color contract isn't perturbed.
#
# CR-flagged failure mode this addresses: a green-tagged instance hitting
# a transient IMDS hiccup during boot (network timeout, missing token)
# used to fall through to "blue" via `|| echo "blue"`, registering
# against the WRONG Cloud Map service since the blue map is populated.
#
# We distinguish three outcomes by inspecting the HTTP status code (not
# curl's exit-22 catch-all): an unauthenticated 401 / forbidden 403 from
# IMDS — token expired or refused — would also map to curl exit 22 under
# `-f`, and silently defaulting those to "blue" would re-open the same
# fault class. Only a literal 404 means "tag legitimately absent on this
# instance".
#   - HTTP 200 → tag is present, DEPLOY_COLOR holds the value.
#   - HTTP 404 → tag absent (non-blue/green deploys), default to "blue".
#   - any other status (401/403/5xx) or curl-level failure (DNS, connect,
#     timeout) → IMDS is unreachable or rejecting. We've already retried
#     (--retry 3 in IMDS_CURL); refuse to guess a color and exit 1.
#     Better to crash-loop the instance and page on no-healthy than to
#     silently register against the wrong color's Cloud Map service. The
#     empty-AZ watchdog (#1542) catches the resulting empty-AZ
#     registration count.
DEPLOY_COLOR_TMP="$(mktemp)"
# Bash `trap` does not compose — a second `trap ... EXIT` silently
# replaces this one. If you add another EXIT trap later in this
# script, fold the cleanup commands together (e.g.,
# `trap 'rm -f "$DEPLOY_COLOR_TMP"; <other-cleanup>' EXIT`) rather
# than emitting a separate trap statement.
trap 'rm -f "$DEPLOY_COLOR_TMP"' EXIT
set +e
DEPLOY_COLOR_HTTP=$(curl -s --max-time 5 --retry 3 -o "$DEPLOY_COLOR_TMP" -w '%%{http_code}' \
  -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/tags/instance/DeployColor)
DEPLOY_COLOR_RC=$?
set -e
if [ $DEPLOY_COLOR_RC -ne 0 ]; then
  echo "FATAL: IMDS curl for DeployColor tag failed at the transport layer (curl exit $DEPLOY_COLOR_RC, http=$DEPLOY_COLOR_HTTP) after retries — refusing to guess a color and silently mis-register against the wrong Cloud Map service."
  exit 1
fi
if [ "$DEPLOY_COLOR_HTTP" = "200" ]; then
  DEPLOY_COLOR=$(cat "$DEPLOY_COLOR_TMP")
  # Empty-body 200 is treated as FATAL, not a fall-through to "blue".
  # IMDS shouldn't return 200 with an empty body for an existing tag,
  # but a future IMDS regression or a misconfigured tag value would
  # otherwise mis-register a green-tagged instance against the blue
  # Cloud Map service via the empty-DEPLOY_COLOR fallback below.
  # Matches the non-200/non-404 branch posture: refuse to guess.
  if [ -z "$DEPLOY_COLOR" ]; then
    echo "FATAL: IMDS DeployColor tag returned HTTP 200 with an empty body — refusing to guess a color. This shouldn't happen; the tag is either present (200 + value) or absent (404). An empty 200 likely means an IMDS regression or a deploy that mis-set the tag value."
    exit 1
  fi
elif [ "$DEPLOY_COLOR_HTTP" = "404" ]; then
  # The strict service-name branch below depends on this missing-tag path
  # setting a literal blue value rather than leaving DEPLOY_COLOR empty.
  DEPLOY_COLOR="blue" # tag legitimately absent (non-blue/green deploys)
else
  echo "FATAL: IMDS DeployColor tag returned HTTP $DEPLOY_COLOR_HTTP (not 200 or 404) — refusing to guess a color. 401/403 likely means the IMDSv2 token expired or was rejected; 5xx means IMDS is degraded. Either way, defaulting to 'blue' would silently mis-register a green-tagged instance against the blue Cloud Map service."
  exit 1
fi
# Defense in depth: this used to be the catch-all for the
# `|| echo "blue"` fallback the script previously had. The HTTP-status
# branching above now handles the 404 case explicitly and FATALs on
# empty-200, so this is unreachable in normal flow. Kept as a final
# safety net in case a future refactor reintroduces a default-blue
# path without going through HTTP-status branching.
if [ -z "$DEPLOY_COLOR" ]; then
  DEPLOY_COLOR="blue"
fi
if [[ "$DEPLOY_COLOR" != "blue" && "$DEPLOY_COLOR" != "green" ]]; then
  echo "FATAL: DeployColor IMDS tag is '$DEPLOY_COLOR' — must be 'blue' or 'green' (or absent for blue)."
  exit 1
fi
# Trailing AZ letter ("us-east-2a" -> "a"). Bash 4+ negative substring.
# IMPORTANT: the leading space inside `: -1` is REQUIRED -- without the
# space, $${AZ:-1} is the default-value operator and would silently set
# AZ_SUFFIX="1" if AZ were empty. The empty-AZ case is also caught
# below by the empty-SERVICE_ID FATAL, but don't compress this space.
AZ_SUFFIX="$${AZ: -1}"
# Defensive: AZ_SUFFIX must be a single lowercase letter. Standard AWS AZ
# names match (`us-east-2a`, `us-east-2b`, ...). Local Zone / Wavelength
# names like `us-east-1-bos-1a` happen to extract a valid letter, while
# `us-east-1-wl1-bos-wlz-1` extracts `1` — explicit regex check makes
# the failure mode unambiguous in the boot log instead of falling through
# as "no service configured for suffix '1'".
if ! [[ "$AZ_SUFFIX" =~ ^[a-z]$ ]]; then
  echo "FATAL: AZ_SUFFIX '$AZ_SUFFIX' (extracted from AZ '$AZ') is not a single lowercase letter — qurl-reverse-tunnel-server only supports standard AWS AZs (us-east-2a etc.)."
  exit 1
fi
if [ "$DEPLOY_COLOR" = "green" ]; then
  SERVICE_NAME="frps-green-$AZ_SUFFIX"
elif [ "$DEPLOY_COLOR" = "blue" ]; then
  SERVICE_NAME="frps-$AZ_SUFFIX"
else
  echo "FATAL: DeployColor IMDS tag '$DEPLOY_COLOR' is not 'blue' or 'green'; refusing to register"
  exit 1
fi
SERVICE_ID=$(lookup_cloudmap_service_id "$SERVICE_NAME" "$REGION" "$NAMESPACE_ID") || {
  echo "FATAL: Cloud Map service lookup failed for '$SERVICE_NAME' in namespace '$NAMESPACE_ID'; refusing to start without a registration target."
  exit 1
}
if [ -z "$SERVICE_ID" ]; then
  # FATAL on register — better to crash-loop the instance and page on
  # no-healthy-instance than to silently boot an instance that no
  # qurl-service hash will ever target.
  echo "FATAL: no Cloud Map service named '$SERVICE_NAME' in namespace '$NAMESPACE_ID' for color '$DEPLOY_COLOR', AZ suffix '$AZ_SUFFIX' (full AZ '$AZ')."
  exit 1
fi
echo "Registering qurl-reverse-tunnel-server instance $INSTANCE_ID ($LOCAL_IP, AZ=$AZ, color=$DEPLOY_COLOR) with Cloud Map service $SERVICE_ID ($SERVICE_NAME)"
for attempt in 1 2 3 4 5; do
  if aws servicediscovery register-instance \
    --service-id "$SERVICE_ID" \
    --instance-id "$INSTANCE_ID" \
    --attributes "AWS_INSTANCE_IPV4=$LOCAL_IP,AVAILABILITY_ZONE=$AZ" \
    --region "$REGION" \
    --cli-connect-timeout 3 \
    --cli-read-timeout 5; then
    echo "FRPS instance registered successfully"
    exit 0
  fi
  echo "WARN: Cloud Map register-instance failed for service '$SERVICE_ID' (attempt $attempt/5)" >&2
  if [ "$attempt" -lt 5 ]; then
    sleep $((attempt * 2))
  fi
done
echo "FATAL: Cloud Map register-instance failed after 5 attempts for service '$SERVICE_ID' ($SERVICE_NAME)" >&2
exit 1
CLOUDMAP_REGISTER_EOF
chmod +x /opt/layerv/qurl-reverse-tunnel-server/cloudmap-register.sh

# CI extracts this script by matching the next heredoc opener exactly;
# update .github/workflows/ubuntu-build.yml if the path or delimiter changes.
cat > /opt/layerv/qurl-reverse-tunnel-server/cloudmap-deregister.sh << 'CLOUDMAP_DEREGISTER_EOF'
#!/bin/bash
# Intentionally NOT `set -e`: this script's contract is "warn and exit 0
# whenever the AZ-suffix lookup is unworkable" (missing mapping, malformed
# suffix). With `set -e`, a failed IMDS curl would exit non-zero before
# AZ_SUFFIX is computed, so the WARN branches below would be unreachable
# in exactly the IMDS-hung-on-shutdown scenario where leniency matters
# most. Each IMDS curl below has its own `|| { WARN; exit 0 }` so the
# warn-and-skip story is uniform across "missing suffix", "malformed
# suffix", and "IMDS dead". Register-side keeps `set -e` (FATAL on
# register is the right call — see cloudmap-register.sh).
NAMESPACE_ID='${namespace_id}'
# See cloudmap-register.sh for rationale on --max-time / --retry.
IMDS_CURL=(curl -sf --max-time 5 --retry 3)
TOKEN=$("$${IMDS_CURL[@]}" -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") || { echo "WARN: IMDS token request failed; skipping deregister"; exit 0; }
INSTANCE_ID=$("$${IMDS_CURL[@]}" -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id) || { echo "WARN: IMDS instance-id lookup failed; skipping deregister"; exit 0; }
AZ=$("$${IMDS_CURL[@]}" -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone) || { echo "WARN: IMDS AZ lookup failed; skipping deregister"; exit 0; }
REGION=$("$${IMDS_CURL[@]}" -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region) || { echo "WARN: IMDS region lookup failed; skipping deregister"; exit 0; }
# shellcheck disable=SC1091
. /opt/layerv/qurl-reverse-tunnel-server/cloudmap-common.sh
# DeployColor — see cloudmap-register.sh for rationale on the
# HTTP-status branching. Deregister is intentionally lenient (the
# script's contract is "warn and exit 0 whenever lookup is
# unworkable"), so any non-200/non-404 response WARN-and-skips here
# rather than the register-side FATAL. A 404 still defaults to "blue"
# so non-blue-green deploys deregister from the only color they ever
# registered to.
DEPLOY_COLOR_TMP="$(mktemp)"
# Bash `trap` does not compose — see the matching comment in
# cloudmap-register.sh. If you add another EXIT trap later in this
# script, fold the cleanup commands together rather than emitting a
# separate `trap` statement (the second one would silently replace
# this one and leave $DEPLOY_COLOR_TMP behind on exit).
trap 'rm -f "$DEPLOY_COLOR_TMP"' EXIT
DEPLOY_COLOR_HTTP=$(curl -s --max-time 5 --retry 3 -o "$DEPLOY_COLOR_TMP" -w '%%{http_code}' \
  -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/tags/instance/DeployColor) || {
    echo "WARN: IMDS curl for DeployColor tag failed at the transport layer; skipping deregister."
    exit 0
}
if [ "$DEPLOY_COLOR_HTTP" = "200" ]; then
  DEPLOY_COLOR=$(cat "$DEPLOY_COLOR_TMP")
  # Empty-body 200: WARN-and-skip rather than register-side FATAL.
  # Same posture as the non-200/non-404 branch — don't guess.
  if [ -z "$DEPLOY_COLOR" ]; then
    echo "WARN: IMDS DeployColor tag returned HTTP 200 with empty body; skipping deregister to avoid mis-targeting the wrong color."
    exit 0
  fi
elif [ "$DEPLOY_COLOR_HTTP" = "404" ]; then
  DEPLOY_COLOR="blue" # tag legitimately absent
else
  echo "WARN: IMDS DeployColor tag returned HTTP $DEPLOY_COLOR_HTTP (not 200 or 404); skipping deregister to avoid mis-targeting the wrong color."
  exit 0
fi
if [ -z "$DEPLOY_COLOR" ]; then
  DEPLOY_COLOR="blue"
fi
AZ_SUFFIX="$${AZ: -1}"
# Same defensive check as cloudmap-register.sh (see comment there).
# WARN-and-continue here matches the existing deregister leniency:
# missing-suffix is one of several reasons we'd skip the AWS call.
if ! [[ "$AZ_SUFFIX" =~ ^[a-z]$ ]]; then
  echo "WARN: AZ_SUFFIX '$AZ_SUFFIX' (extracted from AZ '$AZ') is not a single lowercase letter; skipping deregister"
  exit 0
fi
if [ "$DEPLOY_COLOR" = "green" ]; then
  SERVICE_NAME="frps-green-$AZ_SUFFIX"
elif [ "$DEPLOY_COLOR" = "blue" ]; then
  SERVICE_NAME="frps-$AZ_SUFFIX"
else
  # WARN-and-skip on unrecognized color in deregister (not FATAL —
  # parallel with the missing-suffix branch below).
  echo "WARN: DeployColor IMDS tag '$DEPLOY_COLOR' is not 'blue' or 'green'; skipping deregister"
  exit 0
fi
SERVICE_ID=$(lookup_cloudmap_service_id "$SERVICE_NAME" "$REGION" "$NAMESPACE_ID") || {
  echo "WARN: Cloud Map service lookup failed for '$SERVICE_NAME' in namespace '$NAMESPACE_ID'; skipping deregister."
  exit 0
}
if [ -z "$SERVICE_ID" ]; then
  # Don't FATAL on deregister. Just log and exit clean; the ASG replace cycle
  # will eventually reap the stale registration via TTL or the planned #1089
  # health check work.
  echo "WARN: no Cloud Map service named '$SERVICE_NAME' in namespace '$NAMESPACE_ID' for color '$DEPLOY_COLOR', AZ suffix '$AZ_SUFFIX' (full AZ '$AZ'); skipping deregister"
  exit 0
fi
echo "Deregistering qurl-reverse-tunnel-server instance $INSTANCE_ID from Cloud Map service $SERVICE_ID ($SERVICE_NAME, color=$DEPLOY_COLOR, suffix=$AZ_SUFFIX)"
DEREGISTER_ERR_FILE="$(mktemp)" || { echo "WARN: mktemp failed while preparing Cloud Map deregister; continuing shutdown"; exit 0; }
for attempt in 1 2 3 4 5; do
  : > "$DEREGISTER_ERR_FILE"
  if aws servicediscovery deregister-instance \
    --service-id "$SERVICE_ID" \
    --instance-id "$INSTANCE_ID" \
    --region "$REGION" \
    --cli-connect-timeout 3 \
    --cli-read-timeout 5 2>"$DEREGISTER_ERR_FILE"; then
    rm -f "$DEREGISTER_ERR_FILE"
    echo "FRPS instance deregistered"
    exit 0
  fi
  err=$(cat "$DEREGISTER_ERR_FILE" 2>/dev/null || true)
  # AWS CLI v2 surfaces this as text shaped like
  # "An error occurred (InstanceNotFound) ...". Substring matching is safe:
  # if the wording ever drifts, we only fall back to retry-then-warn.
  if printf '%s\n' "$err" | grep -q 'InstanceNotFound'; then
    rm -f "$DEREGISTER_ERR_FILE"
    echo "WARN: Cloud Map instance '$INSTANCE_ID' was not registered in service '$SERVICE_ID' ($SERVICE_NAME); treating stale-service shutdown as already deregistered" >&2
    exit 0
  fi
  echo "WARN: Cloud Map deregister-instance failed for service '$SERVICE_ID' (attempt $attempt/5): $${err:-<empty stderr>}" >&2
  if [ "$attempt" -lt 5 ]; then
    sleep $((attempt * 2))
  fi
done
rm -f "$DEREGISTER_ERR_FILE"
echo "WARN: Cloud Map deregister-instance failed after 5 attempts for service '$SERVICE_ID' ($SERVICE_NAME); continuing shutdown" >&2
exit 0
CLOUDMAP_DEREGISTER_EOF
chmod +x /opt/layerv/qurl-reverse-tunnel-server/cloudmap-deregister.sh

cat > /etc/systemd/system/frps-cloudmap-register.service << SVCEOF
[Unit]
Description=Register QURL FRP Server with Cloud Map
After=network-online.target qurl-reverse-tunnel-server.service
# BindsTo ties registration lifecycle to qurl-reverse-tunnel-server: if the FRP service stops
# (crash-loop exhausted, manual stop), systemd will also stop this unit,
# which triggers ExecStop (deregister). Without this, a dead FRP process
# leaves a stale Cloud Map record serving traffic until ASG replaces the
# instance.
BindsTo=qurl-reverse-tunnel-server.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/layerv/qurl-reverse-tunnel-server/cloudmap-register.sh
RemainAfterExit=yes
ExecStop=/opt/layerv/qurl-reverse-tunnel-server/cloudmap-deregister.sh
# Worst degraded path is IMDS retries plus Cloud Map lookup and
# register/deregister retries. Keep the service budget above that bound so
# systemd does not kill the script in the middle of its own bounded retry
# policy during a brief Cloud Map or IMDS blip.
TimeoutStartSec=240
TimeoutStopSec=240

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable frps-cloudmap-register
systemctl start frps-cloudmap-register
echo "Registered with Cloud Map as frps.${namespace_name} (with deregistration on shutdown)"

# ============================================================================
# ASG launch-readiness gate — release to InService (qurl-reverse-tunnel-server#195)
# ============================================================================
# The instance launched into an EC2_INSTANCE_LAUNCHING hook and has sat in
# Pending:Wait (NOT InService) for this whole bootstrap. FRP is now serving (the
# readiness probe above) and Cloud Map registration succeeded, so we complete the
# hook with CONTINUE — the first point at which an ASG-health consumer (the
# post-deploy smoke selects InService && Healthy) may safely select this box.
#
# This is the ONLY hook signal user_data sends, and only ever CONTINUE. Every
# failure path before here `exit 1`s WITHOUT signaling, so a broken boot stays in
# Pending:Wait and the hook applies its `default_result` at `heartbeat_timeout`,
# uniformly. We never signal ABANDON from user_data (full rationale + the
# CONTINUE-safe-default story: see `var.frps_launch_readiness_default_result`):
# chiefly so the CONTINUE phase can't loop a broken steady-state scale-out into
# ABANDON->relaunch, and so no EXIT trap is needed (the docker-extraction block's
# scoped trap would clobber one). Trade-off: broken boots resolve at
# heartbeat_timeout latency, not promptly.
#
# Identity is resolved at the point of use; describe-asg + complete-lifecycle-action
# both retry, and either failing falls through to default_result (never fails boot).
if systemctl is-active --quiet frps-cloudmap-register; then
  FRPS_LC_IMDS=(curl -sf --max-time 5 --retry 3)
  FRPS_LC_TOKEN=$("$${FRPS_LC_IMDS[@]}" -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" || true)
  FRPS_INSTANCE_ID=$("$${FRPS_LC_IMDS[@]}" -H "X-aws-ec2-metadata-token: $FRPS_LC_TOKEN" http://169.254.169.254/latest/meta-data/instance-id || true)
  FRPS_ASG_NAME=""
  __frps_resolve_asg_name() {
    FRPS_ASG_NAME=$(aws autoscaling describe-auto-scaling-instances \
      --region "$REGION" \
      --instance-ids "$FRPS_INSTANCE_ID" \
      --query 'AutoScalingInstances[0].AutoScalingGroupName' \
      --output text)
    [ -n "$FRPS_ASG_NAME" ] && [ "$FRPS_ASG_NAME" != "None" ]
  }
  if [ -n "$FRPS_INSTANCE_ID" ] && retry_with_backoff 5 2 20 __frps_resolve_asg_name; then
    # A WARN below can also be a lost-ack on an ALREADY-applied CONTINUE: if the
    # first call succeeded AWS-side but the response was dropped, the retry hits
    # "no pending lifecycle action" and returns non-zero. The instance still
    # proceeds to InService, so treat this WARN as informational, not a failure.
    retry_with_backoff 5 2 20 aws autoscaling complete-lifecycle-action \
      --region "$REGION" \
      --auto-scaling-group-name "$FRPS_ASG_NAME" \
      --lifecycle-hook-name "${frps_launch_lifecycle_hook_name}" \
      --instance-id "$FRPS_INSTANCE_ID" \
      --lifecycle-action-result CONTINUE \
      || echo "WARN: complete-lifecycle-action CONTINUE failed after retries; instance falls through to the hook default_result at heartbeat_timeout (or a lost-ack on an already-applied CONTINUE — harmless)"
  else
    echo "WARN: could not resolve instance-id/ASG name; instance falls through to the hook default_result at heartbeat_timeout"
  fi
else
  # Defensive/unreachable: `systemctl start frps-cloudmap-register` above runs
  # under set -e and the unit is Type=oneshot, so a failed register already
  # aborts the script there (unsignaled => default_result). Kept as a guard.
  echo "FATAL: frps-cloudmap-register is not active after start; exiting without completing the hook (instance falls through to default_result at heartbeat_timeout)."
  exit 1
fi

echo "QURL FRP server installation complete at $(date)"
