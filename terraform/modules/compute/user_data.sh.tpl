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

# =============================================================================
# Package Installation - Skip if already present (for custom AMI optimization)
# With base Ubuntu AMI: ~60-90 seconds for apt-get + installs
# With custom AMI (Docker pre-installed): ~0 seconds
# Note: awscli package deprecated in Ubuntu 24.04, using unzip + curl for AWS CLI v2
# =============================================================================
declare -a PACKAGES_NEEDED=()
command -v jq >/dev/null 2>&1 || PACKAGES_NEEDED+=("jq")
command -v docker >/dev/null 2>&1 || PACKAGES_NEEDED+=("docker.io")
command -v curl >/dev/null 2>&1 || PACKAGES_NEEDED+=("curl")
command -v unzip >/dev/null 2>&1 || PACKAGES_NEEDED+=("unzip")

if [ "$${#PACKAGES_NEEDED[@]}" -gt 0 ]; then
  echo "Installing missing packages:$${PACKAGES_NEEDED[*]}"
  apt_get_with_retry update -y
  apt_get_with_retry install -y "$${PACKAGES_NEEDED[@]}"
else
  echo "All packages already installed, skipping apt-get (custom AMI detected)"
fi

# Install AWS CLI v2 if not present (works on all Ubuntu versions)
if ! command -v aws >/dev/null 2>&1; then
  echo "Installing AWS CLI v2..."
  curl -sL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
  unzip -q /tmp/awscliv2.zip -d /tmp
  /tmp/aws/install
  rm -rf /tmp/aws /tmp/awscliv2.zip
else
  echo "AWS CLI already installed, skipping"
fi
aws --version

# Start Docker (may already be running on custom AMI)
systemctl enable docker
systemctl start docker || true

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

# Fix DNS for Go's pure resolver (doesn't work with systemd-resolved stub).
# The Docker-optimized AMI built by packer/nhp-server-docker.pkr.hcl bakes
# this drop-in in, so the normal-boot path is the no-op branch below.
#
# The else branch is a recovery fallback, NOT an expected code path. If we
# ever hit it on a real instance it means either (a) the AMI bake step was
# accidentally removed, or (b) someone launched against a non-baked AMI
# (the PR explicitly forbids this). We surface the failure four ways so it's
# discoverable in production monitoring without needing log searches:
#   1. Cloud-init-output WARNING line (visible in EC2 console + on-instance)
#   2. /var/log/nhp-dns-fallback host stamp (grep-able from the host)
#   3. syslog/journald entry via `logger -p user.alert` (collected by the
#      CloudWatch agent + visible in `journalctl -t nhp-user-data`)
#   4. CloudWatch custom metric LayerV/NHP/DnsFallbackHit so the team can
#      build a dashboard panel + alarm that fires the moment any new
#      instance hits this path. Best-effort: failure to emit the metric
#      must NOT block the instance from coming up.
# The work itself still runs so the instance comes up with working DNS
# instead of failing.
if [ -f /etc/systemd/resolved.conf.d/disable-stub.conf ] && grep -q '^DNSStubListener=no' /etc/systemd/resolved.conf.d/disable-stub.conf; then
  echo "DNS already configured by baked AMI; skipping user_data DNS setup"
else
  echo "WARNING: DNS fallback path hit — AMI was expected to ship with /etc/systemd/resolved.conf.d/disable-stub.conf but it is missing. This indicates the Docker-optimized AMI bake step regressed or a non-baked AMI was launched. Investigate."
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) DNS fallback path hit on $(hostname)" >> /var/log/nhp-dns-fallback
  logger -t nhp-user-data -p user.alert "DNS fallback path hit; AMI bake step missing disable-stub.conf"
  # Emit a CloudWatch custom metric so dashboards/alarms can detect this
  # without log-grepping. The instance role grants PutMetricData scoped to
  # the LayerV/NHP namespace (compute/main.tf::aws_iam_role.server). The
  # InstanceId dimension is fetched via IMDSv2; on the rare chance that
  # also fails, we fall back to "unknown" so the metric still emits.
  CW_TOKEN=$(curl -fsS -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || echo "")
  CW_INSTANCE_ID=$(curl -fsS -H "X-aws-ec2-metadata-token: $CW_TOKEN" "http://169.254.169.254/latest/meta-data/instance-id" 2>/dev/null || echo "unknown")
  aws cloudwatch put-metric-data \
    --region "${region}" \
    --namespace "LayerV/NHP" \
    --metric-name "DnsFallbackHit" \
    --value 1 \
    --unit Count \
    --dimensions "InstanceId=$CW_INSTANCE_ID" \
    || echo "WARNING: failed to emit DnsFallbackHit CloudWatch metric (continuing)"
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/disable-stub.conf << 'DNSEOF'
[Resolve]
DNSStubListener=no
DNSEOF
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  systemctl restart systemd-resolved
  echo "DNS configured to use VPC resolver directly (user_data fallback — see warning above)"
fi

SECRET_ARN="${secret_arn}"
REGION="${region}"
# SECURITY: this script runs under `set -ex`; the top-level `exec` redirect
# ships stderr (including xtrace) to user-data.log → CloudWatch Logs (30 day
# sandbox / 365 day prod retention; see the `retention_in_days` ternary in
# modules/compute/main.tf). Under `set -x` the `SECRET=$(aws …)` assignment
# would otherwise trace `+ SECRET='{"privateKey":"…"}'` (bash expands the
# captured stdout into the assignment's trace line), and the two `jq`
# pipelines below would trace the same JSON again. This is the **fleet-wide**
# server private key — leakage would force a whole-fleet AC re-key.
# Bracket fetch + extract with `set +x` / `set -x`, scrub `$SECRET`, and
# `unset $PRIVATE_KEY` after the config.toml heredoc lands it on disk
# (the heredoc body itself is not traced by bash). Mirrors the
# EXISTING_SECRET / KEYPAIR block in modules/ac/user_data.sh.tpl (PR #1304,
# issue #1268) — that block is AC reading its own per-instance private key
# from Secrets Manager; this block is the structural equivalent for the
# server (fleet-wide private key, higher blast radius). Heredoc safety
# applies to here-*documents* (`<<`) only; here-strings (`<<<`)
# *are* traced with expansion, so any future edit switching to `<<<`
# would need its own `set +x` bracket.
# Note on the `|| { set -x; echo FATAL; exit 1; }` catches in this and
# the QURL/COOKIE blocks below. The FATAL echo itself lands in
# user-data.log regardless of xtrace state via the top-of-script
# `exec > >(tee …)` redirect — the `set -x` re-enable only adds the
# `+ echo 'FATAL: …'` trace line for stream symmetry. The `||` catch
# itself is the load-bearing piece: under `set -e`, a failed `aws ...`
# inside a `set +x` bracket would otherwise terminate the script with
# xtrace off, so any future cleanup or logging added between the catch
# and `exit 1` would run untraced. Keep the catch + `set -x` even if
# the body is just an `exit 1`.
#
# Pipefail caveat: this script does not set `pipefail`, so the `echo
# "$VAR" | jq -er '.field'` pipelines below catch jq failure only
# because jq is the rightmost command. Any future edit that adds a
# post-jq filter (`| sed`, `| tr`, `| tee`, etc.) would mask jq's exit
# even with `-e`. Either preserve the rightmost-jq invariant or add
# `set -o pipefail` here. #1305's CI lint is the structural fence.
set +x
SECRET=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --region "$REGION" --query SecretString --output text) || {
  set -x
  echo "FATAL: Could not fetch server secret from Secrets Manager"
  exit 1
}
PRIVATE_KEY=$(echo "$SECRET" | jq -er ".privateKey") || {
  set -x
  echo "FATAL: Could not extract privateKey from server secret JSON (missing or null)"
  exit 1
}
HOSTNAME=$(echo "$SECRET" | jq -er ".hostname") || {
  set -x
  echo "FATAL: Could not extract hostname from server secret JSON (missing or null)"
  exit 1
}
unset SECRET
set -x

echo "Fetching overload-cookie signing key from Secrets Manager..."
set +x
COOKIE_SIGNING_KEY_SECRET=$(aws secretsmanager get-secret-value \
  --secret-id "${overload_cookie_secret_arn}" \
  --region "$REGION" \
  --query SecretString --output text) || {
    set -x
    echo "FATAL: Could not fetch overload-cookie signing key from Secrets Manager"
    exit 1
}
COOKIE_SIGNING_KEY_B64=$(COOKIE_SIGNING_KEY_SECRET="$COOKIE_SIGNING_KEY_SECRET" python3 - <<'PY'
import base64
import os
import sys

secret = os.environ["COOKIE_SIGNING_KEY_SECRET"]
try:
    decoded = base64.b64decode(secret, validate=True)
except Exception:
    decoded = None

# Prefer the seeded base64 form when it decodes to exactly 32 bytes. Legacy
# raw 32-character strings are accepted only when they are not valid 32-byte
# base64 secrets.
if decoded is not None and len(decoded) == 32:
    print(secret)
elif len(secret.encode("utf-8")) == 32:
    print(base64.b64encode(secret.encode("utf-8")).decode("ascii"))
else:
    print(
        "FATAL: overload-cookie signing key secret must be base64-encoded 32 bytes "
        f"or a legacy 32-byte string (got {len(secret)} chars)",
        file=sys.stderr,
    )
    sys.exit(1)
PY
) || {
  set -x
  echo "FATAL: invalid overload-cookie signing key in Secrets Manager"
  exit 1
}
unset COOKIE_SIGNING_KEY_SECRET
set -x

TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Fail fast at each IMDS stage with a precise diagnostic so the operator
# can tell token-fetch failures apart from metadata-fetch failures. The
# downstream consumers of $INSTANCE_ID (the docker --log-opt
# awslogs-stream flag below, Cloud Map registration, etc.) produce
# cryptic cascading errors if the value is empty, so we die here
# instead. `set -ex` propagates the exit; echo first so the reason is
# visible in /var/log/user-data.log.
if [ -z "$TOKEN" ]; then
  echo "FATAL: IMDS token fetch returned empty; cannot retrieve instance metadata"
  exit 1
fi

INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
LOCAL_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)

if [ -z "$INSTANCE_ID" ]; then
  echo "FATAL: IMDS returned empty instance-id (token ok but metadata fetch failed); cannot continue"
  exit 1
fi

mkdir -p /opt/layerv/nhp-server/etc
mkdir -p /opt/layerv/nhp-server/log

# SECURITY: config.toml carries the **fleet-wide** NHP server PrivateKeyBase64
# (and, in api mode, $auth_signing_key / $auth_aes_key — both `sensitive=true`
# in modules/compute/variables.tf). Cloud-init's default umask leaves files
# created by `cat > …` at mode 644; a co-tenant or non-root host process
# would observe the private key on disk between heredoc-write and any later
# tightening. Mirror the secrets.env pattern (`grep -n 'touch.*secrets.env'`
# in this file): create the inode + chmod 600 *before* any secret content
# lands. chmod 600 set on
# the inode persists across the heredoc's truncate-and-rewrite — bash's
# `>` does not reset mode. Closes #1389.
touch /opt/layerv/nhp-server/etc/config.toml
chmod 600 /opt/layerv/nhp-server/etc/config.toml
set +x
if ! cat > /opt/layerv/nhp-server/etc/config.toml << CONFIGEOF
PrivateKeyBase64 = "$PRIVATE_KEY"
DefaultCipherScheme = 0
ListenIp = ""
ListenPort = 62206
Hostname = "$HOSTNAME"
LogLevel = ${log_level}
DisableAgentValidation = false
DisableRelayValidation = ${relay_enabled}
CookieSigningKeyBase64 = "$COOKIE_SIGNING_KEY_B64"
CookieTimeWindowSeconds = ${overload_cookie_time_window_seconds}
EnableKnockACFanout = ${enable_knock_ac_fanout}
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
then
  set -x
  echo "FATAL: Could not write nhp-server config.toml"
  exit 1
fi
set -x
# Scrub $PRIVATE_KEY: prevents any future edit (e.g. `<<<` here-string or
# `--key "$PRIVATE_KEY"` invocation, neither of which are heredoc-trace-safe)
# from silently reintroducing the xtrace-leak class this PR closes.
# Mirrors the AC user_data PRIVATE_KEY scrub in PR #1304. $HOSTNAME is not
# sensitive and has no consumer past this heredoc — left alone (an `unset`
# here would not restore bash's auto-populated built-in, just leave it
# empty for any subsequent read).
unset PRIVATE_KEY COOKIE_SIGNING_KEY_B64

%{ if relay_enabled ~}
# ============================================================================
# relay.toml — NHP_RELAY peer registration (#2208 5c). When a relay is deployed
# (relay_enabled), root passes the current relay PUBLIC key plus any temporary
# overlap key. The server never reads the relay private-key secret. One
# `[[Relays]]` entry is rendered per key so rotation can establish dual trust
# before AWSCURRENT moves, refresh the relay fleet, then retire the old key.
# Paired with DisableRelayValidation=true in config.toml above — both are gated
# on relay_enabled, so prod (deploy_relay=false) stays behaviorally dark.
# Boot-only: changing the trust list requires a server instance refresh.
# ============================================================================
cat > /opt/layerv/nhp-server/etc/relay.toml << 'RELAYEOF'
${relay_toml}
RELAYEOF
echo "relay.toml written with ${length(relay_trusted_public_keys_b64)} trusted relay public key(s)"
%{ else ~}
# Relay disabled: do not write relay.toml; DisableRelayValidation also remains false.
%{ endif ~}

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
%{ if dynamodb_ac_assignment_authority_table != null ~}
ACAssignmentAuthorityTable = "${dynamodb_ac_assignment_authority_table}"
%{ endif ~}
%{ if dynamodb_resources_table != null ~}
ResourcesTable = "${dynamodb_resources_table}"
%{ endif ~}
%{ if dynamodb_agent_keys_table != null ~}
AgentKeysTable = "${dynamodb_agent_keys_table}"
%{ endif ~}
%{ if dynamodb_ack_tokens_table != null ~}
AckTokensTable = "${dynamodb_ack_tokens_table}"
%{ endif ~}
%{ if dynamodb_session_control_table != null ~}
SessionControlTable = "${dynamodb_session_control_table}"
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
ServiceID = "${cloudmap_service_id}"
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
# Connection-level timeouts:
# - IdleTimeoutMs MUST exceed CloudFront's origin_keepalive_timeout (see
#   terraform/main.tf::aws_cloudfront_distribution.qurl_resolve); otherwise
#   CF reuses a connection the server has already FIN'd and the next POST
#   to /plugins/qurl returns 502 to the viewer. The
#   `terraform_data.http_keepalive_contract` preconditions hard-fail
#   plan/apply on a violation.
# - WriteTimeoutMs covers handler exec + response write (Go net/http
#   semantics). Sized for the resolve handler's NHP-knock + AC-dispatch
#   tail latency. Must stay below CF's origin_read_timeout (60s) so the
#   server, not CF, owns the slow-handler timeout.
# - ReadTimeoutMs covers reading the full request bytes. Sized for slow
#   client uploads under degraded network conditions; the qurl POST body
#   is ~25 bytes but TCP windows can stall, and a tight read timeout
#   adds slowloris exposure with no real benefit at this body size.
#
# Looking for ReadHeaderTimeoutMs? It's intentionally NOT exposed via
# http.toml — pinned to 5s in endpoints/server/httpserver.go to bound
# slowloris-headers exposure independently of ReadTimeoutMs (which
# governs body reads). The right value is the same everywhere; making
# it tunable would invite the wrong knob being turned (an operator
# lengthening ReadTimeoutMs shouldn't accidentally widen the slowloris
# window).
ReadTimeoutMs  = ${http_read_timeout_ms}
WriteTimeoutMs = ${http_write_timeout_ms}
IdleTimeoutMs  = ${http_idle_timeout_ms}
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
# SECURITY: xtrace-leak guard — see SERVER fetch above. The
# `ETCD_TLS_SECRET=$(aws …)` assignment would otherwise trace the full
# JSON envelope, and each `echo "$ETCD_TLS_SECRET" | jq -r '.<field>'`
# pipeline would trace it again. Anyone with CloudWatch Logs read on
# this server's user-data log group could impersonate the server
# against etcd for the configured retention window and read/write
# /nhp/config and /nhp/ac-registry/*. Bracket fetch + extract with
# `set +x` / `set -x`, scrub `$ETCD_TLS_SECRET` after the cert files
# land on disk.
set +x
ETCD_TLS_SECRET=$(aws secretsmanager get-secret-value --secret-id "${etcd_tls_secret_arn}" --region "$REGION" --query SecretString --output text) || {
  set -x
  echo "FATAL: Could not fetch etcd TLS bundle from Secrets Manager"
  exit 1
}

# Extract CA certificate. `jq -er` exits non-zero on null/missing field
# (vs `jq -r` which writes the literal string "null" and exits 0) — the
# `||` catch below relies on that to surface a malformed secret as a
# FATAL line rather than silently writing "null" into ca.crt and failing
# later in mTLS handshake.
echo "$ETCD_TLS_SECRET" | jq -er '.caCert' > /opt/layerv/nhp-server/etc/tls/ca.crt || {
  set -x
  echo "FATAL: Could not extract caCert from etcd TLS secret (missing or null)"
  exit 1
}
chmod 644 /opt/layerv/nhp-server/etc/tls/ca.crt
echo "etcd CA certificate installed"

# Extract client certificate and key for mTLS authentication
echo "$ETCD_TLS_SECRET" | jq -er '.clientCert' > /opt/layerv/nhp-server/etc/tls/client.crt || {
  set -x
  echo "FATAL: Could not extract clientCert from etcd TLS secret (missing or null)"
  exit 1
}
chmod 644 /opt/layerv/nhp-server/etc/tls/client.crt
echo "$ETCD_TLS_SECRET" | jq -er '.clientKey' > /opt/layerv/nhp-server/etc/tls/client.key || {
  set -x
  echo "FATAL: Could not extract clientKey from etcd TLS secret (missing or null)"
  exit 1
}
chmod 600 /opt/layerv/nhp-server/etc/tls/client.key
echo "etcd client certificate and key installed for mTLS"
unset ETCD_TLS_SECRET
set -x
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

# Passcode plugin config
%{ if contains(server_plugins, "passcode") ~}
# SECURITY: in api mode this file holds $auth_signing_key and $auth_aes_key
# (both `sensitive=true` in modules/compute/variables.tf). chmod 600 the
# inode before the heredoc writes so the keys never land at the default
# cloud-init umask (644). Same class as the server config.toml fix above
# (#1389).
touch /opt/layerv/nhp-server/plugins/passcode/etc/config.toml
chmod 600 /opt/layerv/nhp-server/plugins/passcode/etc/config.toml
cat > /opt/layerv/nhp-server/plugins/passcode/etc/config.toml << PLUGINEOF
# Passcode plugin configuration
# ResourceMode: "api" uses external auth API, "file" uses local resource.toml
ResourceMode = "${resource_mode}"
# AuthUrl: Auth backend endpoint for API mode
%{ if auth_url != null ~}
AuthUrl = "${auth_url}"
%{ endif ~}
# JWT/Encryption settings
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
echo "No plugins configured, skipping plugin section of resource.toml"
%{ endif ~}

# ============================================================================
# QURL Plugin Configuration
# Fetches service token from Secrets Manager and prepares environment variables
# for the Docker container. The QURL plugin handles token resolution for the
# qurl.link → qurl.site authentication flow.
# ============================================================================
%{ if qurl_enabled ~}
echo "Fetching QURL service token from Secrets Manager..."
# SECURITY: xtrace-leak guard — see SERVER fetch above. The
# `QURL_SERVICE_TOKEN=$(aws …)` assignment and the `[ -z "$QURL_SERVICE_TOKEN" ]`
# test would otherwise trace the bearer token. The token is later
# materialised into the `SECRETSEOF` heredoc below; bash does not xtrace
# heredoc bodies, so that line stays safe under the re-enabled `set -x`.
# Re-enable `set -x` inside the FATAL branches so the failure trace hits
# user-data.log under xtrace.
set +x
QURL_SERVICE_TOKEN=$(aws secretsmanager get-secret-value \
  --secret-id "${qurl_service_token_secret_arn}" \
  --region "$REGION" \
  --query SecretString --output text) || {
    set -x
    echo "ERROR: Failed to fetch QURL service token from Secrets Manager"
    exit 1
}
if [ -z "$QURL_SERVICE_TOKEN" ]; then
  set -x
  echo "ERROR: QURL service token is empty"
  exit 1
fi
set -x
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
NHP_ENVIRONMENT=${protocol_environment}
NHP_CELL_ID=${cell_id}
%{ if connector_authority_cell_config != null ~}
# Complete assigned-cell Connector Authority graph. Lambda private DNS resolves
# through the cell's exact-policy interface endpoint; no public/NAT path is used.
NHP_CONNECTOR_REGISTRATION_AWS_REGION=${connector_authority_cell_config.aws_region}
NHP_CONNECTOR_REGISTRATION_AWS_ACCOUNT_ID=${connector_authority_cell_config.aws_account_id}
NHP_CONNECTOR_REGISTRATION_ISSUE_OTP_ALIAS_ARN=${connector_authority_cell_config.issue_registration_otp_alias_arn}
NHP_CONNECTOR_REGISTRATION_ACTIVATE_ALIAS_ARN=${connector_authority_cell_config.activate_registration_alias_arn}
NHP_CONNECTOR_REGISTRATION_COMPLETE_ALIAS_ARN=${connector_authority_cell_config.complete_registration_alias_arn}
NHP_CONNECTOR_REGISTRATION_AUTHORITY_LAMBDA_TIMEOUT=${connector_authority_cell_config.authority_lambda_timeout}
NHP_CONNECTOR_REGISTRATION_HANDLER_BUDGET=${connector_authority_cell_config.handler_budget}
NHP_CONNECTOR_REGISTRATION_PACKET_BUDGET=${connector_authority_cell_config.packet_budget}
NHP_CONNECTOR_REGISTRATION_RESPONSE_RESERVE=${connector_authority_cell_config.response_reserve}
NHP_CONNECTOR_REGISTRATION_WRITE_BUDGET=${connector_authority_cell_config.write_budget}
NHP_CONNECTOR_CREDENTIAL_RECOVERY_AWS_REGION=${connector_authority_cell_config.aws_region}
NHP_CONNECTOR_CREDENTIAL_RECOVERY_AWS_ACCOUNT_ID=${connector_authority_cell_config.aws_account_id}
NHP_CONNECTOR_CREDENTIAL_RECOVERY_ALIAS_ARN=${connector_authority_cell_config.complete_credential_recovery_alias_arn}
%{ if connector_authority_cell_config.resolve_connector_resource_alias_arn != null ~}
NHP_CONNECTOR_RESOURCE_AWS_REGION=${connector_authority_cell_config.aws_region}
NHP_CONNECTOR_RESOURCE_AWS_ACCOUNT_ID=${connector_authority_cell_config.aws_account_id}
NHP_CONNECTOR_RESOURCE_ALIAS_ARN=${connector_authority_cell_config.resolve_connector_resource_alias_arn}
%{ endif ~}
%{ endif ~}
# Instance identity and stderr log target for the docker awslogs driver.
# The docker --log-driver=awslogs flags in the systemd unit (below)
# reference these at container start so runtime panics written to
# os.Stderr land in CloudWatch Logs instead of being dropped to
# /var/lib/docker/containers/*/json.log on the host.
#
# NHP_STDERR_LOG_GROUP is passed directly from Terraform
# (aws_cloudwatch_log_group.server_stderr.name in compute/main.tf)
# so the group name cannot drift between the TF-managed resource
# and the docker --log-opt value. If the naming convention changes,
# only the TF resource needs updating.
INSTANCE_ID=$INSTANCE_ID
NHP_STDERR_LOG_GROUP=${server_stderr_log_group}
AWS_REGION=${region}
AWS_DEFAULT_REGION=${region}
# KBS (confidential-containers key broker) has a package-level init() that, at
# server startup, generates a cosign keypair under
# /opt/confidential-containers/kbs/repository (root-owned in the image) and
# panics on failure — under the non-root --user (#1090) that MkdirAll would
# EACCES -> panic -> crash-loop the server. We skip it: the /kbs/v0/* routes
# are upstream-OpenNHP TEE attestation endpoints, not part of the qURL flow (no
# LayerV client routes to them), and the key was regenerated on every container
# start (ephemeral --rm overlay), so it could never have backed a real
# attestation consumer anyway. The routes stay registered but inert
# (GetResource is request-time and simply finds no repository). If KBS is ever
# made a real prod feature, drop KBS_SKIP_INIT and give it a persistent,
# uid-owned repository dir.
KBS_SKIP_INIT=1
%{ if qurl_enabled ~}
QURL_API_URL=${qurl_api_url}
QURL_ALLOWED_REDIRECT_DOMAIN=${qurl_allowed_redirect_domain}
QURL_API_TIMEOUT=${qurl_api_timeout}
QURL_MAX_IDLE_CONNS=${qurl_max_idle_conns}
QURL_MAX_IDLE_CONNS_PER_HOST=${qurl_max_idle_conns_per_host}
QURL_IDLE_CONN_TIMEOUT=${qurl_idle_conn_timeout}
%{ if qurl_v2_admission_enabled ~}
# qURL v2 admission (NHP-server independent verifier). Rendered only when admission
# is enabled, so an off env's user_data is byte-unchanged (no fleet roll until the
# coordinated enable). The trust store value is base64-encoded (base64encode() in the
# compute module; the qURL plugin's LoadConfig decodes it), so the JSON survives both
# the systemd EnvironmentFile= and docker --env-file reads of this file intact with no
# quote-handling dependency. Same transport pattern as NHP_COOKIE_KEYS below.
QURL_V2_ADMISSION_ENABLED=true
QURL_V2_ISSUER_TRUST_STORE=${qurl_v2_issuer_trust_store}
%{ endif ~}
%{ if agent_otp_registration_enabled ~}
# Agent-registration email OTP (T1) — NHP-server QURL plugin side. Rendered only
# when the plugin's agent-OTP registration path is enabled, so a dark env's
# user_data is byte-unchanged (no fleet roll until the coordinated PATH B enable,
# flipped in lockstep with qurl-service's QURL_AGENT_OTP_ENABLED).
AGENT_OTP_REGISTRATION_ENABLED=true
%{ endif ~}
%{ endif ~}
%{ if cloudfront_cidrs_ssm_parameter != null ~}
NHP_TRUSTED_PROXY_CIDRS=$CF_CIDRS
%{ endif ~}
%{ if cors_allowed_origins != "" ~}
NHP_CORS_ALLOWED_ORIGINS=${cors_allowed_origins}
%{ endif ~}
%{ if internal_auth_require ~}
NHP_INTERNAL_AUTH_REQUIRE=true
%{ endif ~}
%{ if knock_headertype_verify_require ~}
NHP_KNOCK_HEADERTYPE_VERIFY=true
%{ endif ~}
# qURL v2 immediate-revocation proof engine (#2793). Terraform-managed fleets
# set this explicitly so NHP_REV fanout is retried until each targeted AC slot
# ACKs (NHP_RVA) or ages out to RevocationAgedOut; the Go binary's absent-env
# default remains off for unmanaged/pre-ACK deployments.
NHP_REVOCATION_RETRY_ENABLED=${revocation_retry_enabled}
NHP_REVOCATION_RETRY_INTERVAL_SECONDS=${revocation_retry_interval_seconds}
NHP_REVOCATION_RETRY_AGE_OUT_SECONDS=${revocation_retry_age_out_seconds}
# Knock-port DoS hardening (#1159): UDP receive buffer target (bytes).
# Paired with the net.core.rmem_max sysctl below; bumping just one side
# lets the kernel silently clamp the socket back to the default. Boot
# log emits a clamp warning if rmem_max is lower than this target.
NHP_UDP_RECV_BUFFER_BYTES=${udp_recv_buffer_bytes}
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
# SECURITY: xtrace-leak guard — see SERVER fetch above. The
# `COOKIE_KEYS_JSON=$(aws …)` assignment, the `[ -z "$COOKIE_KEYS_JSON" ]`
# test, the `echo "$COOKIE_KEYS_JSON" | python3 -c "…"` validation pipe,
# and the `base64 -w 0` pipeline would all trace the cookie-signing /
# encryption keys under `set -x`. Leakage lets an attacker forge session
# cookies for the full CloudWatch Logs retention window. `$NHP_COOKIE_KEYS`
# is consumed by the `SECRETSEOF` heredoc below — bash does not xtrace
# heredoc bodies, so we leave it set; `$COOKIE_KEYS_JSON` has no
# downstream consumer once base64 lands, so we scrub it. Re-enable
# `set -x` inside FATAL branches so the failure trace hits user-data.log
# under xtrace.
set +x
COOKIE_KEYS_JSON=$(aws secretsmanager get-secret-value \
  --secret-id "${cookie_secret_arn}" \
  --region "$REGION" \
  --query SecretString --output text) || {
    set -x
    echo "ERROR: Failed to fetch cookie session keys from Secrets Manager"
    exit 1
}
if [ -z "$COOKIE_KEYS_JSON" ]; then
  set -x
  echo "ERROR: Cookie session keys secret is empty"
  exit 1
fi

# Validate JSON structure has required fields. Safe under `set +x`: the
# python3 stdin pipe is not traced (xtrace off), and python3's stderr is
# bounded — AssertionError emits the literal assertion message
# ('missing current key set' etc.) plus a traceback referencing <string>
# line numbers, and JSONDecodeError emits position info ('Expecting value:
# line N column M (char K)') with at most a single character of context,
# never the full document. Future edits that add `print(d)` for debugging
# would defeat that invariant — keep the validator output-free.
echo "$COOKIE_KEYS_JSON" | python3 -c "
import json, sys
d = json.loads(sys.stdin.read())
assert 'current' in d, 'missing current key set'
assert 'auth_key' in d['current'], 'missing current.auth_key'
assert 'encrypt_key' in d['current'], 'missing current.encrypt_key'
" || {
  set -x
  echo "ERROR: Cookie secret JSON missing required fields (current.auth_key, current.encrypt_key)"
  exit 1
}

# Base64-encode for safe transport through env file and docker --env-file
NHP_COOKIE_KEYS=$(echo -n "$COOKIE_KEYS_JSON" | base64 -w 0)
unset COOKIE_KEYS_JSON
set -x

# Fetch the NHP internal auth HMAC secret (signed by qurl-service on outbound
# /nhp/internal/knock requests; verified by this server). Fail-closed if the
# secret is missing or shorter than the 32-byte floor the verifier enforces —
# an undersized secret would pass docker start only to crash at construction.
echo "Fetching NHP internal auth secret from Secrets Manager..."
# SECURITY: xtrace-leak guard. This script runs under `set -ex` with the
# top-level `exec > >(tee /var/log/user-data.log ...)`, so `set -x` trace
# lines land in CloudWatch. The `NHP_INTERNAL_AUTH_SECRET=$(aws …)`
# assignment would otherwise trace as `+ NHP_INTERNAL_AUTH_SECRET='<48-char
# HMAC key>'` — bash expands command-substitution stdout into the
# assignment's trace line. Mirrors the AC-module fix landed in PR #1304
# (issue #1268).
set +x
NHP_INTERNAL_AUTH_SECRET=$(aws secretsmanager get-secret-value \
  --secret-id "${nhp_internal_auth_secret_arn}" \
  --region "$REGION" \
  --query SecretString --output text) || {
    set -x
    echo "ERROR: Failed to fetch NHP internal auth secret from Secrets Manager"
    exit 1
}
if [ "$${#NHP_INTERNAL_AUTH_SECRET}" -lt 32 ]; then
  set -x
  echo "ERROR: NHP internal auth secret is shorter than the 32-byte floor (got $${#NHP_INTERNAL_AUTH_SECRET}); aborting."
  exit 1
fi
set -x

cat > /opt/layerv/nhp-server/etc/secrets.env << SECRETSEOF
NHP_COOKIE_KEYS=$NHP_COOKIE_KEYS
# NHP_INTERNAL_AUTH_SECRET is written raw. The seed in terraform/main.tf
# uses `--exclude-punctuation` so the alphabet is [A-Za-z0-9] only; that's
# the contract that makes this safe through the env file and docker
# --env-file transports. Widening the alphabet requires base64-encoding
# here and decoding on the server side (mirror NHP_COOKIE_KEYS above).
NHP_INTERNAL_AUTH_SECRET=$NHP_INTERNAL_AUTH_SECRET
%{ if qurl_enabled ~}
# QURL service authentication token - fetched from Secrets Manager
# This file contains sensitive credentials and should NOT be readable by other users
QURL_SERVICE_TOKEN=$QURL_SERVICE_TOKEN
%{ endif ~}
SECRETSEOF
# Defense-in-depth: these secrets are no longer needed in the shell
# environment after the heredoc writes them. Unset so a future edit that
# accidentally references one of them can't resurrect the xtrace-leak class.
# `NHP_COOKIE_KEYS` is base64-encoded — encoding obscures from casual log
# scanning but is fully reversible; treat the variable as still-sensitive
# session-key material. `QURL_SERVICE_TOKEN` is the raw bearer token.
# Matches the PR #1304 defense-in-depth scrub pattern.
unset NHP_INTERNAL_AUTH_SECRET NHP_COOKIE_KEYS QURL_SERVICE_TOKEN
echo "Created secrets file with cookie keys, internal auth secret, and service credentials"

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
  --user ${nhp_server_uid}:${nhp_server_gid} \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --log-driver=awslogs \
  --log-opt awslogs-region=$${AWS_REGION} \
  --log-opt awslogs-group=$${NHP_STDERR_LOG_GROUP} \
  --log-opt awslogs-stream=$${INSTANCE_ID} \
  --log-opt awslogs-create-group=false \
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

# ============================================================================
# Kernel UDP receive-buffer ceiling (#1159)
#
# SetReadBuffer(8 MiB) in the Go server is silently clamped to
# net.core.rmem_max — a small buffer fills under flood and the kernel
# starts dropping LEGITIMATE knocks first, giving the attacker a free
# amplifier. Raise the ceiling here; the server then bumps the listen
# socket and logs a Warning if the ceiling is still too low (so a
# regression that drops this drop-in stays loud, not silent).
#
# Container note: nhp-server runs with --net=host so the listen socket
# uses the host's net namespace and inherits these sysctls. If the
# server is ever moved off host networking, switch to per-namespace
# tuning or use SO_RCVBUFFORCE with CAP_NET_ADMIN.
# ============================================================================
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/60-nhp-knock-rcvbuf.conf << SYSCTLEOF
# Managed by terraform/modules/compute/user_data.sh.tpl (#1159).
# Paired with NHP_UDP_RECV_BUFFER_BYTES in the server env file.
# Only rmem_max is required for SetReadBuffer to take effect; we
# intentionally do NOT raise rmem_default to avoid bumping the kernel
# default for unrelated UDP sockets on this host (chronyd, dhcp, etc).
net.core.rmem_max = ${udp_recv_buffer_bytes}
SYSCTLEOF
# Apply live so the running server picks it up on this boot — without
# this, the values land only on the next reboot and the in-progress
# server start clamps. `|| true` because user_data runs under set -ex
# and we want a hardened-kernel / namespace surprise to surface as the
# Go-side clamp Warning, not as a fatal cloud-init exit. The drop-in
# above persists, so any future reboot still gets the raised ceiling.
sysctl -w "net.core.rmem_max=${udp_recv_buffer_bytes}" || true
# Echo the kernel's actual rmem_max into the cloud-init log so a
# post-mortem doesn't have to SSM into the host to see whether the
# bump took. If sysctl -w failed silently above, the printed value
# will be the kernel default (e.g. ~212992 on Ubuntu) — same signal
# the Go-side clamp Warning will emit later, surfaced earlier.
RMEM_MAX_ACTUAL=$(cat /proc/sys/net/core/rmem_max 2>/dev/null || echo "<read-failed>")
echo "Configured UDP receive-buffer ceiling: requested ${udp_recv_buffer_bytes}, kernel rmem_max=$${RMEM_MAX_ACTUAL}"

# ============================================================================
# iptables Rate Limiting for NHP Knock Port (UDP 62206)
#
# Kernel-level rate limiting to mitigate UDP flood DoS attacks before packets
# reach the application. This is the first line of defense; the Go server
# has additional per-source-IP application-level rate limiting as defense-in-depth.
# These rules are packet-type agnostic: every UDP packet to 62206 is capped,
# including both initial KNK and follow-up RKN packets.
#
# Layered limits, evaluated top-down (first match wins):
# 1. Global cap: drop all UDP knock packets above ${knock_global_rate_limit_pps}
#    pps aggregate, burst ${knock_global_rate_limit_burst}. Defends against
#    distributed low-rate floods that stay under per-IP limits but aggregate
#    above the server's ECDH throughput (#1159). Uses --hashlimit-above
#    --hashlimit-mode dstip — the bucket key is the packet destination IP,
#    which on a single-ENI instance is one value, so this is effectively a
#    single-bucket cap. (A multi-IP / dual-stack instance would split into
#    one bucket per dst IP; iptables is IPv4-only here so v6 is a follow-up
#    item — see #1498.) -m limit was the alternative but has no
#    "match-above-rate" inverse, only "match-up-to-rate", so a distinct
#    ABOVE-limit DROP rule needs the hashlimit module's --hashlimit-above
#    operator.
# 2. Per-source-IP cap: 100 pps sustained, burst 50, via -m hashlimit srcip.
#    Falls through to ACCEPT when under the per-IP budget. Defends against
#    a single noisy client.
# 3. Default DROP: anything that didn't ACCEPT above gets dropped.
#
# IMPORTANT: per-IP values must match DefaultRateLimiterConfig() in
# endpoints/server/ratelimiter.go. Change both together. The global cap
# has no app-level mirror today (iptables-only); see #1159 for the
# rationale and the standing follow-up for an app-level global limiter.
# ============================================================================
echo "Configuring iptables rate limiting for UDP port 62206..."

# Install iptables if not already present (usually pre-installed on Ubuntu)
which iptables > /dev/null 2>&1 || apt_get_with_retry install -y iptables

# Hold a fail-closed guard across rule replacement. Without it, a re-run of
# user_data would briefly leave the old terminal ACCEPT ahead of the newly
# appended drop layers. If configuration aborts mid-update, the guard remains
# and UDP/62206 stays closed instead of silently becoming unrated.
iptables -C INPUT -p udp --dport 62206 \
  -m comment --comment nhp-knock-reconfigure-guard -j DROP 2>/dev/null || \
  iptables -I INPUT 1 -p udp --dport 62206 \
    -m comment --comment nhp-knock-reconfigure-guard -j DROP

# Idempotency: delete each rule first (best-effort, ignore errors if not
# present) before appending. This prevents duplicate rules accumulating if
# user_data runs more than once on the same instance — for example after
# `cloud-init clean && cloud-init init` for debugging, or after a re-image
# that bakes prior rules into the AMI. The per-source and terminal-admit rules
# below have a fixed spec, so a literal `iptables -D` with the same spec
# always matches and is enough.
#
# The global cap is parameterized (rate + burst), so a literal `-D` would
# fail to match if the operator changes knock_global_rate_limit_pps
# between user_data runs (or flips it to 0). The result would be the OLD
# rule sitting at a lower line number than the new one — old rate fires
# first, new rate never takes effect. Walk INPUT by --line-numbers and
# delete every rule referencing the global hashlimit name BEFORE the
# conditional add, so changes and disable both work cleanly.
#
# State note: --hashlimit-name keys persist in /proc/net/ipt_hashlimit/
# across delete-add cycles. The line-walk above only removes the rule;
# stale bucket state lingers until the xt_hashlimit module is unloaded
# (or reboot). Not a correctness problem — the new rule is what matters —
# but if you're debugging counters, `cat /proc/net/ipt_hashlimit/<name>`
# is where they live.

# Always remove every prior nhp_knock_global rule from INPUT — survives
# both rate changes between runs and the pps=0 disable case. Sort
# descending so each delete leaves earlier line numbers stable.
for line in $(iptables -L INPUT --line-numbers -n 2>/dev/null | awk '/nhp_knock_global/ {print $1}' | sort -rn); do
  iptables -D INPUT "$line" 2>/dev/null || true
done

# Rate limit UDP knock packets per source IP using hashlimit module BEFORE the
# aggregate cap. A few high-rate sources must not consume the shared aggregate
# allowance and randomly shed a low-rate legitimate client. Source rotation
# below this limit still reaches the aggregate cap that follows.
# --hashlimit-above: match only traffic above the source's allowance
# --hashlimit-burst: initial burst allowance
# --hashlimit-mode srcip: track by source IP
# --hashlimit-htable-expire: cleanup idle entries after 120s
iptables -D INPUT -p udp --dport 62206 \
  -m hashlimit \
  --hashlimit-above 100/sec \
  --hashlimit-burst 50 \
  --hashlimit-mode srcip \
  --hashlimit-name nhp_knock \
  --hashlimit-htable-expire 120000 \
  -m comment --comment nhp-knock-per-source-drop \
  -j DROP 2>/dev/null || true
# Remove the pre-#3184 accept-then-default-drop shape on re-run/upgrade.
iptables -D INPUT -p udp --dport 62206 \
  -m hashlimit \
  --hashlimit-upto 100/sec \
  --hashlimit-burst 50 \
  --hashlimit-mode srcip \
  --hashlimit-name nhp_knock \
  --hashlimit-htable-expire 120000 \
  -m comment --comment nhp-knock-per-source-accept \
  -j ACCEPT 2>/dev/null || true
iptables -D INPUT -p udp --dport 62206 \
  -m hashlimit \
  --hashlimit-upto 100/sec \
  --hashlimit-burst 50 \
  --hashlimit-mode srcip \
  --hashlimit-name nhp_knock \
  --hashlimit-htable-expire 120000 \
  -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p udp --dport 62206 \
  -m hashlimit \
  --hashlimit-above 100/sec \
  --hashlimit-burst 50 \
  --hashlimit-mode srcip \
  --hashlimit-name nhp_knock \
  --hashlimit-htable-expire 120000 \
  -m comment --comment nhp-knock-per-source-drop \
  -j DROP

# Remove the old terminal-drop forms; the new chain admits traffic explicitly
# after both independent drop layers.
iptables -D INPUT -p udp --dport 62206 \
  -m comment --comment nhp-knock-per-source-drop -j DROP 2>/dev/null || true
iptables -D INPUT -p udp --dport 62206 -j DROP 2>/dev/null || true

%{ if knock_global_rate_limit_pps > 0 ~}
# Global cap: after noisy individual sources are shed, drop remaining knocks
# above the aggregate rate regardless of source IP. This is the distributed
# low-rate/spoof-rotation backstop. Operators who want per-IP-only fallback set
# knock_global_rate_limit_pps = 0; the walk-and-delete above removes any old
# aggregate rule before this conditional block.
iptables -A INPUT -p udp --dport 62206 \
  -m hashlimit \
  --hashlimit-above ${knock_global_rate_limit_pps}/sec \
  --hashlimit-burst ${knock_global_rate_limit_burst} \
  --hashlimit-mode dstip \
  --hashlimit-name nhp_knock_global \
  -m comment --comment nhp-knock-global-drop \
  -j DROP
echo "iptables global cap: ${knock_global_rate_limit_pps} pps sustained, burst ${knock_global_rate_limit_burst}"
%{ else ~}
echo "iptables global cap: DISABLED (knock_global_rate_limit_pps=0)"
%{ endif ~}

# Every surviving UDP/62206 packet is admitted after both drop layers. The
# marker is load-bearing for exact edge-ingress telemetry.
iptables -D INPUT -p udp --dport 62206 \
  -m comment --comment nhp-knock-admitted -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p udp --dport 62206 \
  -m comment --comment nhp-knock-admitted -j ACCEPT

# Admission is fully ordered and observable; remove the fail-closed update
# guard only after all steady-state rules are installed.
iptables -D INPUT -p udp --dport 62206 \
  -m comment --comment nhp-knock-reconfigure-guard -j DROP

echo "iptables per-IP rate limiting configured: 100 pps sustained, burst 50 per source IP"

# Emit per-layer UDP admission evidence through the existing CloudWatch Agent
# log path. The collector publishes EMF deltas for kernel UDP errors, receive-
# buffer drops, and both iptables drop layers; its heartbeat/error series makes
# a missing rule or dead collector distinguishable from a quiet edge.
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else "nhp-udp-edge-metrics requires Python >= 3.10")'
cat > /usr/local/bin/nhp-udp-edge-metrics << 'PYEOF'
${udp_edge_metrics_script}
PYEOF
chmod 0755 /usr/local/bin/nhp-udp-edge-metrics

# The collector uses a fixed EMF filename so the CloudWatch Agent can tail it;
# rotate it independently from the date-stamped application logs. copytruncate
# preserves the tailed inode while bounding long-lived-instance disk usage.
which logrotate >/dev/null 2>&1 || apt_get_with_retry install -y logrotate
cat > /etc/logrotate.d/nhp-udp-edge-metrics << 'EOF'
/opt/layerv/nhp-server/log/server-udp-edge-metrics.log {
    daily
    rotate 7
    maxsize 10M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF

cat > /etc/systemd/system/nhp-udp-edge-metrics.service << EOF
[Unit]
Description=NHP UDP edge metrics collector
After=network-online.target amazon-cloudwatch-agent.service

[Service]
Type=oneshot
Environment=NHP_ENVIRONMENT=${protocol_environment}
Environment=NHP_CELL_ID=${cell_id}
Environment=INSTANCE_ID=$INSTANCE_ID
Environment=NHP_GLOBAL_RATE_LIMIT_ENABLED=${knock_global_rate_limit_pps > 0}
ExecStart=/usr/local/bin/nhp-udp-edge-metrics
User=root
Group=root
EOF

cat > /etc/systemd/system/nhp-udp-edge-metrics.timer << 'EOF'
[Unit]
Description=Collect NHP UDP edge metrics every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=5s
RandomizedDelaySec=5s
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now nhp-udp-edge-metrics.timer
systemctl start nhp-udp-edge-metrics.service

# ============================================================================
# Dedicated unprivileged user for the nhp-server container (#1090)
#
# The container drops to uid:gid ${nhp_server_uid}:${nhp_server_gid} via
# `--user` in the systemd unit above so that an upstream-CVE RCE inside the
# container lands on an unprivileged uid rather than root. No Linux
# capabilities are required: the listener binds 8888/TCP + 62206/UDP (both >
# 1024) and the UDP receive buffer is sized host-side via net.core.rmem_max
# (the server uses SetReadBuffer/SO_RCVBUF, not SO_RCVBUFFORCE which would need
# CAP_NET_ADMIN — see the rmem_max drop-in above). Because no caps are needed,
# the run line also `--cap-drop=ALL` and `--security-opt=no-new-privileges:true`
# to reinforce the same post-RCE threat model. (Dev-only caveat: the `--prof`
# flag writes cpu.prf into the root-owned WORKDIR and would fail under --user;
# the prod ENTRYPOINT runs `run`, which never sets it.)
#
# Why a fixed numeric uid (not `User=`/name like the native frps unit): docker
# `--user` resolves names against the CONTAINER's /etc/passwd, and the
# ubuntu:26.04 runtime image has no nhp-server entry — so a name would fail to
# start. We pin the uid:gid from the nhp_server_uid/nhp_server_gid locals on
# the host (a named account for `ps`/`ls` auditability, well above the
# system-uid range to avoid AMI package collisions); Terraform renders the same
# numerics into `--user` at plan time, so the two cannot drift. Resolving the
# uid at runtime is not an option because systemd performs its own
# `$`-expansion on ExecStart before bash runs, so `$(id -u …)` is undefined.
#
# Ownership the non-root process needs (must run AFTER all etc files exist and
# BEFORE the service starts):
#   - etc (:ro mount): the uid must own the 0600 files it reads (config.toml
#     always; tls/client.key only when storage_backend=etcd). We chown the
#     whole etc tree rather than an explicit file list because client.key/tls
#     are absent under the dynamodb backend, and a future 0600 addition should
#     not silently become unreadable. The :ro mount means even owned files
#     cannot be rewritten from inside a compromised container.
#   - We then RE-ASSERT root on env/secrets.env: those are consumed only by the
#     root docker CLI via --env-file, never by the container, so secrets.env
#     (0600) stays container-unreadable on the mount.
#   - log (rw mount): the server writes its logs here.
# Mirrors the frps service-user pattern in
# terraform/modules/qurl-reverse-tunnel-server/user_data.sh.tpl.
# ============================================================================
# Pin uid:gid to match the `--user` numerics rendered above (both come from the
# nhp_server_uid/nhp_server_gid locals). Guard by name (idempotent re-run) AND
# by number: if the gid/uid is already held by an unrelated account on the AMI,
# fail loudly here rather than emit an opaque groupadd/useradd error under
# `set -e` that would boot the instance with no server (and crash-loop the ASG
# against the same AMI).
if ! getent group nhp-server >/dev/null 2>&1; then
  if getent group ${nhp_server_gid} >/dev/null 2>&1; then
    echo "FATAL: gid ${nhp_server_gid} already held by '$(getent group ${nhp_server_gid} | cut -d: -f1)'; cannot pin nhp-server" >&2
    exit 1
  fi
  groupadd --gid ${nhp_server_gid} nhp-server
fi
if ! getent passwd nhp-server >/dev/null 2>&1; then
  if getent passwd ${nhp_server_uid} >/dev/null 2>&1; then
    echo "FATAL: uid ${nhp_server_uid} already held by '$(getent passwd ${nhp_server_uid} | cut -d: -f1)'; cannot pin nhp-server" >&2
    exit 1
  fi
  useradd --uid ${nhp_server_uid} --gid ${nhp_server_gid} --no-create-home --shell /usr/sbin/nologin nhp-server
fi
chown -R nhp-server:nhp-server /opt/layerv/nhp-server/etc /opt/layerv/nhp-server/log
for f in env secrets.env; do
  [ -e "/opt/layerv/nhp-server/etc/$f" ] && chown root:root "/opt/layerv/nhp-server/etc/$f"
done
%{ if length(server_plugins) > 0 ~}
# Plugins are statically compiled into the server binary now (PluginPath=""),
# but per-plugin CONFIG is still staged here and mounted :ro — e.g. the passcode
# plugin's etc/config.toml is mode 0600, so the uid must own it to read it.
# Only chown when plugins were actually staged — with no plugins the dir is
# docker-auto-created 0755 root and an empty :ro mount is still traversable.
chown -R nhp-server:nhp-server /opt/layerv/nhp-server/plugins
%{ endif ~}

systemctl daemon-reload
systemctl enable nhp-cloudmap-register nhp-health-monitor nhp-server
systemctl start nhp-cloudmap-register
systemctl start nhp-health-monitor
systemctl start nhp-server || echo "NHP server start deferred"

echo "NHP Server installation complete at $(date)"
