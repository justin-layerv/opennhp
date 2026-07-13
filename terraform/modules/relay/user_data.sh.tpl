#!/bin/bash
# NHP-Relay node bootstrap (#2208). Runs on the server AMI (Docker + awscli +
# the systemd-resolved stub-disable fix used when resolving the internal NLB at
# startup). Pulls the relay image, renders relay.toml from the fleet keypair, and
# runs nhp-relayd as a systemd-managed container on the HOST network so its
# private UDP source is the stable, server-reachable instance IP and authenticated
# server returns reach the same bound socket without a Docker NAT translation.
set -ex
exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
echo "Starting NHP-Relay installation at $(date)"

REGION="${region}"

report_failure() {
  echo "BOOTSTRAP FAILED: $1"
  command -v aws &>/dev/null && aws cloudwatch put-metric-data \
    --namespace "LayerV/NHP" \
    --metric-name "BootstrapFailure" \
    --value 1 --unit Count \
    --dimensions "Component=relay,Environment=${environment}" \
    --region "$REGION" 2>/dev/null || true
}
# Guarded fatal: emit the BootstrapFailure metric on the explicit-exit paths the
# ERR trap can't see (||-guarded commands, [ -z ] checks — the likeliest boot
# failures). set -x first so the failure trace lands even when called from inside
# a set +x secret block; the message is a static string (no secret).
fatal() {
  set -x
  report_failure "$1"
  exit 1
}
trap 'report_failure "unexpected error on line $LINENO"' ERR

# No ec2messages endpoint exists in the DMZ. SSM Agent 3.3.40.0 and newer uses
# ssmmessages whenever available; fail before starting the relay if the baked
# AMI is too old to satisfy that management-path contract.
SSM_AGENT_MIN_VERSION="3.3.40.0"
SSM_AGENT_BIN="$(command -v amazon-ssm-agent 2>/dev/null || true)"
if [ -z "$SSM_AGENT_BIN" ]; then
  for candidate in /snap/amazon-ssm-agent/current/amazon-ssm-agent /usr/bin/amazon-ssm-agent; do
    if [ -x "$candidate" ]; then
      SSM_AGENT_BIN="$candidate"
      break
    fi
  done
fi
if [ -z "$SSM_AGENT_BIN" ]; then
  fatal "amazon-ssm-agent is missing from the relay AMI"
fi
SSM_AGENT_VERSION="$($SSM_AGENT_BIN -version 2>&1 | grep -Eo '[0-9]+(\.[0-9]+){3}' | head -n 1 || true)"
if [ -z "$SSM_AGENT_VERSION" ]; then
  fatal "could not parse the amazon-ssm-agent version"
fi
if [ "$(printf '%s\n' "$SSM_AGENT_MIN_VERSION" "$SSM_AGENT_VERSION" | sort -V | head -n 1)" != "$SSM_AGENT_MIN_VERSION" ]; then
  fatal "amazon-ssm-agent is older than the required 3.3.40.0 floor"
fi
echo "Validated amazon-ssm-agent $SSM_AGENT_VERSION (minimum $SSM_AGENT_MIN_VERSION)"

# The relay has no NAT path to Ubuntu repositories. OS patching is immutable:
# rebuild the shared AMI, advance its SSM pointer, and refresh the relay ASG.
# Disable internet-backed apt timers so they do not fail noisily forever or
# create a false impression that in-place patching is succeeding.
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service 2>/dev/null || true

# Docker is pre-baked into the server AMI; ensure the daemon is up.
systemctl enable docker
systemctl start docker || true
for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break || sleep 2; done

# Instance id for the awslogs stream name (region is templated in above).
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
if [ -z "$INSTANCE_ID" ]; then
  fatal "IMDS returned empty instance-id; cannot continue"
fi
INSTANCE_PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
if [ -z "$INSTANCE_PRIVATE_IP" ]; then
  fatal "IMDS returned empty local-ipv4; cannot continue"
fi

# ECR login (handles cross-account: registry domain is the repo URL's host).
ECR_REPO="${relay_repo_url}"
ECR_REGISTRY="$(echo "$ECR_REPO" | cut -d/ -f1)"
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$ECR_REGISTRY"

# Image tag from SSM (CI source of truth; see modules/relay/compute.tf).
SSM_IMAGE_TAG_PARAM="${ssm_image_tag_parameter}"
IMAGE_TAG=$(aws ssm get-parameter --name "$SSM_IMAGE_TAG_PARAM" --region "$REGION" --query "Parameter.Value" --output text) ||
  fatal "failed to fetch relay image tag from SSM ($SSM_IMAGE_TAG_PARAM)"
if [ -z "$IMAGE_TAG" ] || [ "$IMAGE_TAG" = "None" ] || [ "$IMAGE_TAG" = "initial" ]; then
  fatal "SSM parameter $SSM_IMAGE_TAG_PARAM has no valid image tag (got '$IMAGE_TAG')"
fi
echo "Using relay image tag from SSM: $IMAGE_TAG"

docker pull "$ECR_REPO:$IMAGE_TAG" ||
  fatal "could not pull relay image $ECR_REPO:$IMAGE_TAG"

# ── relay TLS + relay.toml ──
# Pinned uid:gid for the non-root relay container (#1090). The mounted
# relay.toml carries the fleet private key, so create the inode + chmod 600 +
# chown to the runtime uid BEFORE the secret lands, then keep the heredoc body
# off xtrace (bash does not trace heredoc bodies; the private-key fetch below is
# bracketed with set +x).
RELAY_UID=10001
RELAY_GID=10001
mkdir -p /opt/layerv/nhp-relay/etc
mkdir -p /opt/layerv/nhp-relay/tls
touch /opt/layerv/nhp-relay/etc/relay.toml
chmod 600 /opt/layerv/nhp-relay/etc/relay.toml
chmod 700 /opt/layerv/nhp-relay/tls
chown "$RELAY_UID:$RELAY_GID" \
  /opt/layerv/nhp-relay/etc \
  /opt/layerv/nhp-relay/etc/relay.toml \
  /opt/layerv/nhp-relay/tls

# ALB HTTPS target groups encrypt to the relay backend but do not validate the
# target certificate, so a per-instance self-signed cert is sufficient for the
# in-VPC backend leg. ALB target-side cert validation is irrelevant today; SANs
# are included anyway so future validating probes do not inherit a CN-only cert.
# The bounded lifetime is hygiene, not an availability guard. The ALB-only SG
# path remains the authenticated boundary.
command -v openssl >/dev/null 2>&1 || fatal "openssl is required to generate relay backend TLS cert"
openssl req -help 2>&1 | grep -q -- "-addext" ||
  fatal "openssl req -addext support (OpenSSL >= 1.1.1) is required to generate relay backend TLS cert SANs"
(
  umask 077
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 397 \
    -subj "/CN=nhp-relay.${environment}.internal" \
    -addext "subjectAltName=DNS:nhp-relay.${environment}.internal,DNS:localhost,IP:$INSTANCE_PRIVATE_IP,IP:127.0.0.1" \
    -keyout /opt/layerv/nhp-relay/tls/tls.key \
    -out /opt/layerv/nhp-relay/tls/tls.crt
)
chmod 600 /opt/layerv/nhp-relay/tls/tls.key
chmod 644 /opt/layerv/nhp-relay/tls/tls.crt
chown "$RELAY_UID:$RELAY_GID" /opt/layerv/nhp-relay/tls/tls.key /opt/layerv/nhp-relay/tls/tls.crt

# SECURITY: the relay private key is the fleet-wide NHP_RELAY identity. Under
# set -x the `SECRET=$(aws ...)` assignment and the jq pipe would trace it into
# user-data.log → CloudWatch. Bracket fetch + extract with set +x, scrub $SECRET.
set +x
SECRET=$(aws secretsmanager get-secret-value --secret-id "${secret_arn}" --region "$REGION" --query SecretString --output text) ||
  fatal "could not fetch relay secret from Secrets Manager"
PRIVATE_KEY=$(echo "$SECRET" | jq -er ".privateKey") ||
  fatal "could not extract privateKey from relay secret JSON (missing or null)"
unset SECRET
set -x

# `>` truncates the existing inode in place — it preserves the chmod 600 + chown
# set above, so the fleet private key never lands at the default cloud-init umask.
cat > /opt/layerv/nhp-relay/etc/relay.toml << CONFIGEOF
# Generated by Terraform (modules/relay/user_data.sh.tpl).
listen_addr = ":${listen_port}"
# Private socket used to send NHP_RLY to a cell and receive its authenticated
# return. Native UDP SDKs connect directly to their assigned cell's public NLB.
udp_listen_addr = "0.0.0.0:${udp_listen_port}"
private_key = "$PRIVATE_KEY"
# Behind the ALB, which terminates client TLS, re-encrypts to this relay over
# backend TLS, APPENDS the real client IP to the END of X-Forwarded-For (so the
# RIGHTMOST entry is the ALB-attested IP), and is the only path to the relay
# (relay SG ingress = ALB only). The relay reads this header for the AC-pinhole
# client IP — it MUST take the rightmost entry, not the leftmost (a client can
# pre-seed a spoofed leftmost value); the rightmost parse is #2622.
source_addr_mode = "trusted_header"
trusted_header = "X-Forwarded-For"
enable_tls = true
tls_cert_file = "/nhp-relay/tls/tls.crt"
tls_key_file = "/nhp-relay/tls/tls.key"
trusted_proxy = true
# #2631: browser Origins allowed to call the relay cross-origin — the qURL knock
# portal only (qurl.link). Exact-match, comma-separated. Empty disables CORS. The
# relay echoes the matched origin, never "*".
cors_allowed_origins = "${cors_allowed_origins}"
%{ for s in cell_servers ~}

[[servers]]
name = "${s.name}"
public_key = "${s.public_key}"
host = "${s.host}"
port = ${s.port}
%{ endfor ~}
CONFIGEOF
unset PRIVATE_KEY

# ── systemd unit ──
# --network host: the relay's private UDP socket binds the instance network
#   directly, giving it a stable server-reachable source and same-socket return.
# --user: non-root runtime (#1090); the relay binds >1024 and needs no caps. The
#   mounted relay.toml is chowned to this uid above so the container can read it.
# --log-driver awslogs: stdout/stderr → CloudWatch (the instance role grants
#   CreateLogStream/PutLogEvents on the group).
# -e AWS_REGION / NHP_ENVIRONMENT (#2649): the relay's CloudWatch metrics
#   publisher (endpoints/metrics, mirroring nhp-server) needs AWS_REGION to
#   resolve the CloudWatch endpoint for PutMetricData — the instance role already
#   grants cloudwatch:PutMetricData scoped to the LayerV/NHP namespace (this
#   file's BootstrapFailure emit + compute.tf) — and NHP_ENVIRONMENT for the
#   metric's Environment dimension (the cell is attached per-shed; the relay
#   fronts all cells, so there is no single NHP_CELL_ID here). The healthcheck URL
#   is rendered from listen_port so the container liveness probe follows the same
#   port as relay.toml and the ALB target group.
cat > /etc/systemd/system/nhp-relayd.service << SVCEOF
[Unit]
Description=NHP-Relay daemon (#2208)
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Restart=always
RestartSec=5
TimeoutStartSec=0
ExecStartPre=-/usr/bin/docker rm -f nhp-relay
ExecStart=/usr/bin/docker run --rm --name nhp-relay \\
  --network host \\
  --user $RELAY_UID:$RELAY_GID \\
  -e AWS_REGION=${region} \\
  -e NHP_ENVIRONMENT=${environment} \\
  -e NHP_RELAY_HEALTHCHECK_URL=https://localhost:${listen_port}/health/live \\
  -v /opt/layerv/nhp-relay/etc/relay.toml:/nhp-relay/etc/relay.toml:ro \\
  -v /opt/layerv/nhp-relay/tls:/nhp-relay/tls:ro \\
  --log-driver=awslogs \\
  --log-opt awslogs-region=${region} \\
  --log-opt awslogs-group=${log_group} \\
  --log-opt awslogs-stream=$INSTANCE_ID/relay \\
  $ECR_REPO:$IMAGE_TAG run
ExecStop=/usr/bin/docker stop nhp-relay

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable nhp-relayd.service
systemctl start nhp-relayd.service
echo "NHP-Relay started with image tag: $IMAGE_TAG"
