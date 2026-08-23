# AC Module - Access Controller with Embedded Traefik
#
# This module deploys the NHP Access Controller (AC) as an EC2 Auto Scaling Group.
# The AC has Traefik embedded for:
# - TLS termination with automatic Let's Encrypt certificates (DNS-01 challenge)
# - Proxying HTTPS requests to protected resources
#
# Traffic flows:
# - NLB (TCP 443) -> AC instances: For web/HTTPS traffic via Traefik
# - Direct to AC public IPs: For NHP protocol client connections after knock
#
# Note: Traefik PLUGINS are deployed separately by the traefik-plugins project,
# which updates the AC instances via SSM. This module only deploys the base AC.

# CloudFront WAF requires us-east-1 provider
terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 6.27"
      configuration_aliases = [aws.us_east_1]
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
  }
}

# ==================== Data Sources ====================

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  # True when an SNS alert destination is actually wired. trimspace guards
  # against a whitespace-only ARN; try() handles the null default.
  sns_destination_present = try(trimspace(var.alerts_sns_topic_arn) != "", false)

  # The load-balancer health-check port. Traefik receives the probe on this
  # port; the qURL/TLS target groups use ac_admission_ready_path so a target is
  # healthy only when nhp-acd has a recently confirmed assigned-server datapath
  # for admissions. This deliberately fails closed for an AC with no server
  # path; a correlated AC->server loss can make every public target unhealthy
  # after interval*unhealthy_threshold, so rollout verification must prove
  # server blue/green and registration flips do not zero the fleet.
  # The 30s freshness window is therefore the production rollout's most
  # important gate: an otherwise-routine server flip must leave every active AC
  # with at least one connected, fresh assigned-server path.
  # SINGLE SOURCE OF TRUTH shared by (1) the ac_tcp / ac_tcp_green target-group
  # health_check blocks and (2) the AC's config.toml `HealthCheckPort`. In
  # FilterMode_EBPFXDP the AC admits this exact port through the XDP whitelist
  # at startup (endpoints/ac/udpac.go::ebpfInfraExemptRules); if the probed
  # port and the admitted port ever diverge, the XDP datapath fail-closed drops
  # the NLB probe, every AC target flaps unhealthy, and the NLB black-holes the
  # fleet. Keeping both TG colors and the datapath on this one local is what
  # makes that divergence structurally impossible. The
  # `ac_user_data_health_check_port_render_check` resource below asserts the
  # config.toml render, mirroring the FilterMode render guard.
  ac_health_check_port    = 8080
  ac_admission_ready_path = "/nhp-ac/ready"
  # Single-line anchors intentionally trade contiguous-block precision for
  # indentation-stable rendering checks, matching the sibling render fences in
  # this module. The rollout ledger's qURL smoke covers the full routed path.
  ac_admission_ready_route_render_anchors = [
    "[entryPoints.nhp-health]",
    "address = \":${local.ac_health_check_port}\"",
    "[http.routers.nhp-ac-ready]",
    "rule = \"Path(\\`${local.ac_admission_ready_path}\\`)\"",
    "service = \"nhp-ac\"",
    "entryPoints = [\"nhp-health\"]",
    "priority = 100",
    "[http.routers.nhp-ac-ready-deny]",
    "rule = \"Path(\\`${local.ac_admission_ready_path}\\`) || PathPrefix(\\`${local.ac_admission_ready_path}/\\`)\"",
    "entryPoints = [\"https\"]",
    "middlewares = [\"nhp-ac-ready-internal-only\"]",
    "priority = 101",
    "[http.routers.nhp-ac-ready-deny.tls]",
    "[http.middlewares.nhp-ac-ready-internal-only.replacePath]",
    "path = \"/__nhp_ac_ready_internal_only\"",
    "[http.services.nhp-ac.loadBalancer]",
    "[[http.services.nhp-ac.loadBalancer.servers]]",
    "url = \"http://127.0.0.1:8888\"",
  ]
}

resource "terraform_data" "sns_alerts_contract" {
  lifecycle {
    precondition {
      # Core monitoring alarms can be action-less; only blue/green and reconciliation alarms require this SNS destination.
      condition     = !(var.enable_blue_green || var.enable_secret_reconciliation) || !var.enable_sns_alerts || local.sns_destination_present
      error_message = "enable_sns_alerts=true requires a non-empty alerts_sns_topic_arn. Keep alarm resource counts gated on enable_sns_alerts, but wire the SNS ARN before enabling the gate."
    }
  }
}

check "sns_alerts_gate_matches_destination" {
  assert {
    condition     = !(var.enable_blue_green || var.enable_secret_reconciliation) || var.enable_sns_alerts || !local.sns_destination_present
    error_message = "alerts_sns_topic_arn is set but enable_sns_alerts=false, so blue/green deployment and reconciliation SNS alarms will not be created. Set enable_sns_alerts=true or clear alerts_sns_topic_arn."
  }
}

# ==================== AC Secret (Private Key) ====================
# The AC needs a Curve25519 private key to operate.
# We generate this using a Lambda similar to the server module.

resource "aws_iam_role" "keygen_lambda" {
  name = "${var.name_prefix}-ac-keygen-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "keygen_lambda_basic" {
  role       = aws_iam_role.keygen_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "keygen_lambda_secrets" {
  name = "secrets-access"
  role = aws_iam_role.keygen_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue"
        ]
        Resource = aws_secretsmanager_secret.ac.arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
        Resource = var.secrets_kms_key_arn != null ? [var.secrets_kms_key_arn] : []
      }
    ]
  })
}

# Lambda function to generate Curve25519 keys for AC
resource "aws_lambda_function" "keygen" {
  function_name = "${var.name_prefix}-ac-keygen"
  role          = aws_iam_role.keygen_lambda.arn
  handler       = "index.handler"
  runtime       = "nodejs22.x"
  timeout       = 30

  filename         = data.archive_file.keygen_lambda.output_path
  source_code_hash = data.archive_file.keygen_lambda.output_base64sha256

  tags = var.tags
}

data "archive_file" "keygen_lambda" {
  type        = "zip"
  output_path = "${path.module}/keygen_lambda.zip"

  source {
    content  = <<-EOF
const { SecretsManagerClient, PutSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
const crypto = require('crypto');

exports.handler = async (event) => {
  const { SecretId, ACId, Environment } = event.ResourceProperties || event;

  // Generate a random 32-byte private key (Curve25519)
  const privateKey = crypto.randomBytes(32);
  const privateKeyBase64 = privateKey.toString('base64');

  const client = new SecretsManagerClient();

  const secretValue = JSON.stringify({
    privateKey: privateKeyBase64,
    acId: ACId || 'ac-' + Environment,
    environment: Environment,
  });

  await client.send(new PutSecretValueCommand({
    SecretId: SecretId,
    SecretString: secretValue,
  }));

  return {
    PhysicalResourceId: event.PhysicalResourceId || SecretId,
  };
};
EOF
    filename = "index.js"
  }
}

# Store AC configuration in Secrets Manager
resource "aws_secretsmanager_secret" "ac" {
  name                    = "${var.name_prefix}-ac"
  description             = "NHP AC private key and configuration"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = var.secrets_kms_key_arn

  tags = var.tags
}

# Custom resource to invoke Lambda for key generation
resource "aws_lambda_invocation" "keygen" {
  function_name = aws_lambda_function.keygen.function_name

  input = jsonencode({
    RequestType = "Create"
    ResourceProperties = {
      SecretId    = aws_secretsmanager_secret.ac.id
      ACId        = "${var.environment}-ac"
      Environment = var.environment
    }
  })

  depends_on = [aws_iam_role_policy.keygen_lambda_secrets]

  lifecycle {
    ignore_changes = [input]
  }
}

# AMI Selection (fail-fast, no fallback):
# 1. If var.ac_ami_id is set directly, use it
# 2. Otherwise, read from SSM parameter /{environment}/nhp/ac/ami-id
#
# The AMI must be pre-built with the AC runtime packages installed. Without a
# custom AMI, Terraform fails at plan time with a clear error instead of
# launching vanilla Ubuntu that user_data intentionally refuses to self-heal
# with apt at boot.
#
# Build and publish AMI:
#   cd packer && packer build -var 'environment=sandbox' \
#     -var 'runtime_packages_only=true' nhp-ac.pkr.hcl
#   aws ssm put-parameter --name "/sandbox/nhp/ac/ami-id" \
#     --value "ami-xxx" --type String --overwrite
#
# Naming aligned with sibling /${env}/nhp/ac/* parameters
# (image-tag, asg-name, active-color, ...).
data "aws_ssm_parameter" "ac_ami" {
  count = var.ac_ami_id == null ? 1 : 0
  name  = "/${var.environment}/nhp/ac/ami-id"
}

# ==================== Locals ====================

locals {
  is_prod    = var.environment == "prod"
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.id

  # Fail fast: either var.ac_ami_id is set, or SSM parameter must exist.
  ac_ami_id = var.ac_ami_id != null ? var.ac_ami_id : data.aws_ssm_parameter.ac_ami[0].value

  ac_runtime_apt_regex = "(?m)^[[:space:]]*(?:\\([[:space:]]*)?(?:(?:sudo|env|command)[[:space:]]+|[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]+[[:space:]]+)*(?:apt_get_with_retry|(?:/[^[:space:]]+/)?(?:apt-get|apt|aptitude))[[:space:]]+(?:update|install|upgrade|dist-upgrade|full-upgrade)\\b"

  resolved_max_capacity             = coalesce(var.ac_max_capacity, local.is_prod ? 6 : 3)
  resolved_deletion_spike_threshold = coalesce(var.secret_reconciliation_deletion_spike_threshold, local.is_prod ? 10 : 60)
  eip_pool_tag                      = "${var.name_prefix}-ac"

  # FRPS control channel TG name. Computed once so the resource
  # `name` attribute and the length precondition cannot drift.
  # Matches the sibling `ac_tcp` TG pattern (fixed `name`, not
  # `name_prefix`) — the AWS provider's `name_prefix` is limited to
  # 6 chars (the 26-char appended suffix takes the rest of the
  # 32-char name budget), which is too short to carry a descriptive
  # identifier. The trade-off is that a future regional rename of
  # `var.name_prefix` will hit `DuplicateTargetGroup` and need a
  # two-apply migration; see the lifecycle comment on the resource
  # for details.
  ac_frps_control_tg_name = replace("${var.name_prefix}-ac-frps-ctl", "_", "-")

  ac_frps_control_additional_tg_names = {
    for name, _ in var.frp_control_additional_upstreams :
    name => replace("${var.name_prefix}-ac-frps-${name}", "_", "-")
  }

  frp_control_listener_ports = concat(
    var.frp_control_upstream_host != "" ? [var.frp_control_port] : [],
    [for _, upstream in var.frp_control_additional_upstreams : upstream.listen_port],
  )
}

# Route 53 hosted zone lookup for DNS-01 challenge
# Skip lookup when hosted_zone_id is provided directly (cross-account zones)
data "aws_route53_zone" "main" {
  count        = var.hosted_zone_id == null ? 1 : 0
  name         = "${var.hosted_zone}."
  private_zone = false
}

locals {
  resolved_zone_id  = var.hosted_zone_id != null ? var.hosted_zone_id : data.aws_route53_zone.main[0].zone_id
  resolved_zone_arn = var.hosted_zone_id != null ? "arn:aws:route53:::hostedzone/${var.hosted_zone_id}" : data.aws_route53_zone.main[0].arn
}

# Same-account AC DNS records consume the parent Terraform CI role's scoped
# Route53 record-change grants. On a cutover apply, wait for those inline IAM
# policies to propagate before issuing ChangeResourceRecordSets.
resource "time_sleep" "route53_record_change_iam_propagation" {
  count = !var.skip_dns_records && length(var.route53_record_change_iam_propagation_triggers) > 0 ? 1 : 0

  triggers = var.route53_record_change_iam_propagation_triggers

  create_duration = var.route53_record_change_iam_propagation_duration
}

# Security Group for AC instances
# AC runs multiple services:
# - Traefik (443/tcp, 80/tcp): HTTPS web proxy for *.apps traffic
# - Portal (8888/tcp): User portal UI/API
# - ConnectorClient (4732/tcp, 62206/udp): NHP connector, receives knock packets
# - nhp-acd (62206/tcp localhost): Internal AC daemon, not exposed
#
# SECURITY NOTE: The following ports are INTENTIONALLY open to 0.0.0.0/0 by design:
# - 443/80: Web traffic - must be publicly accessible
# - 8888 (Portal): User authentication portal - must be accessible before NHP auth
# - 4732/62206 (NHP): Zero Trust protocol - clients connect from anywhere
# Security is enforced at the application layer via the NHP protocol, not network ACLs.
# When CloudFront is enabled, web traffic (443/80) is protected by WAF at the edge.
resource "aws_security_group" "ac" {
  name_prefix = "${var.name_prefix}-ac-"
  vpc_id      = var.vpc_id
  description = "Security group for AC instances"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-sg-ac"
    Component = "ac"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# --- AC SG Rules (separate resources to avoid inline/standalone conflicts) ---

# HTTPS - Traefik web proxy (NLB + direct access)
# Protected by CloudFront + WAF when enable_cloudfront=true
resource "aws_vpc_security_group_ingress_rule" "ac_https" {
  security_group_id = aws_security_group.ac.id
  description       = "HTTPS - Traefik proxy (WAF protected via CloudFront)"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${var.name_prefix}-ac-https"
  }
}

# HTTP - Traefik (redirect to HTTPS, ACME HTTP-01)
resource "aws_vpc_security_group_ingress_rule" "ac_http" {
  security_group_id = aws_security_group.ac.id
  description       = "HTTP - Traefik redirect/ACME"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${var.name_prefix}-ac-http"
  }
}

# Portal service - INTENTIONALLY PUBLIC
# This is the authentication entry point for the Zero Trust model.
# Users must access the portal to initiate NHP authentication.
resource "aws_vpc_security_group_ingress_rule" "ac_portal" {
  security_group_id = aws_security_group.ac.id
  description       = "Portal service (Zero Trust auth entry point)"
  from_port         = 8888
  to_port           = 8888
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${var.name_prefix}-ac-portal"
  }
}

# NHP ConnectorClient - TCP - INTENTIONALLY PUBLIC
# Clients connect here after completing NHP knock authentication.
# Security is enforced by the NHP protocol, not network restrictions.
resource "aws_vpc_security_group_ingress_rule" "ac_nhp_connector" {
  security_group_id = aws_security_group.ac.id
  description       = "NHP ConnectorClient (protocol-secured)"
  from_port         = 4732
  to_port           = 4732
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${var.name_prefix}-ac-nhp-connector"
  }
}

# NHP knock packets - UDP - INTENTIONALLY PUBLIC
# Zero Trust: knock packets can come from anywhere.
# Only authenticated knocks are processed by the NHP protocol.
resource "aws_vpc_security_group_ingress_rule" "ac_nhp_knock" {
  security_group_id = aws_security_group.ac.id
  description       = "NHP knock packets (protocol-secured)"
  from_port         = 62206
  to_port           = 62206
  ip_protocol       = "udp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${var.name_prefix}-ac-nhp-knock"
  }
}

# =============================================================================
# TRANSITIONAL — places AC in FRPS data plane as a userspace TCP forwarder.
#
# The AC instance is NOT the long-term home for FRPS data-plane traffic. This
# resource (and its siblings: `aws_lb_target_group.ac_frps_control`,
# `aws_lb_listener.frps_control`, `aws_autoscaling_attachment.ac_frps_control`,
# the `entryPoints.frps-control` + `frps-control.toml` blocks in
# `user_data.sh.tpl`) exists only to satisfy the hard constraint that the
# FRP/reverse-tunnel server must not be internet-accessible except through
# AC pinholing — until the AC pushes ipset deltas to FRPS out-of-band and
# FRPS has its own controlled public ingress.
#
# Target shape: AC stays a control-plane firewall manager (key-authenticated
# knock → opaque token → FRPS `/token/validate` is the primary identity-bound
# access control); FRPS has its own ingress; this listener + Traefik
# forwarder block is removal work then.
#
# Tracking: https://github.com/layervai/nhp/issues/2019 ("AC out of the FRPS
# data path"). Cross-reference this block when reading any of the four
# sibling resources or the two `user_data.sh.tpl` blocks above.
# =============================================================================
#
# FRPS control channel TCP - INTENTIONALLY PUBLIC (AC kernel ipset is the real gate)
# Customer frpc dials this port at `connect.layerv.{ai,xyz}:${frp_control_port}`
# (NLB:7000 below). AC kernel default-drops INPUT; a verified FRPS-specific NHP
# knock adds `(agent_ip, ${frp_control_port}, ac_local_ip)` to the `defaultset`
# ipset, and the existing `-A INPUT -m set --match-set defaultset src,dst,dst -j ACCEPT`
# rule permits the SYN. Once admitted, Traefik's TCP entrypoint on `${frp_control_port}`
# forwards to the private FRPS instance — see `user_data.sh.tpl`. The SG opening
# matches the same posture as `ac_https` / `ac_portal` / `ac_nhp_knock`: the L3/L4
# fence lives in the application layer, not in the SG.
#
# Gated on the same `var.frp_control_upstream_host != ""` switch as the
# NLB listener + TG + Traefik entrypoint. Greenfield envs that opt out
# of FRPS-behind-AC get NO public 7000/tcp opening on the AC SG — the
# rule's existence and the listener that depends on it stay in lockstep,
# and compliance scanners (Trivy / Prowler / CIS) won't flag a public
# port-7000 ingress on every non-FRPS env.
#
# Boot-time ordering invariant (depended on by this SG opening): in
# `user_data.sh.tpl`, the iptables default-DROP INPUT + ipset
# `defaultset` setup runs at the `# NHP Firewall Setup` marker
# BEFORE the `systemctl start traefik` invocation. Traefik's `/ping`
# doesn't return 200 until Traefik is up, so the NLB TG healthcheck
# cannot race ahead of the ipset gate — by the time the instance is
# TG-healthy, the kernel gate is in place. The fail-closed shell
# guard right before `systemctl start traefik` enforces this at
# runtime; a future user_data reorder that puts iptables setup
# BELOW Traefik's start will trip the guard and exit non-zero
# instead of silently leaking the listener.
resource "aws_vpc_security_group_ingress_rule" "ac_frps_control" {
  count = var.frp_control_upstream_host != "" ? 1 : 0

  security_group_id = aws_security_group.ac.id
  description       = "FRPS control channel (NHP-gated at AC kernel ipset)"
  from_port         = var.frp_control_port
  to_port           = var.frp_control_port
  ip_protocol       = "tcp"
  # IPv4-only by design. The AC NLB has IPv4 listeners only today
  # (the existing `ac_https` / `ac_nhp_knock` rules likewise open
  # IPv4 only), and the customer frpc binary connects over IPv4.
  # If a future PR adds IPv6 NLB listeners, mirror this rule with
  # `cidr_ipv6 = "::/0"` AND verify the `defaultset_v6` ipset rule
  # carries the same `match-set defaultset_v6 src,dst,dst -j ACCEPT`
  # treatment for port 7000.
  cidr_ipv4 = "0.0.0.0/0"

  # Matches sibling SG ingress rules in this module which set only
  # `Name`. If `var.tags` propagation becomes a module-wide
  # requirement, switch all sibling rules in lockstep rather than
  # diverging this one.
  tags = {
    Name = "${var.name_prefix}-ac-frps-control"
  }
}

resource "aws_vpc_security_group_ingress_rule" "ac_frps_control_additional" {
  for_each = var.frp_control_additional_upstreams

  security_group_id = aws_security_group.ac.id
  description       = "FRPS control channel ${each.key} (NHP-gated at AC kernel ipset)"
  from_port         = each.value.listen_port
  to_port           = each.value.listen_port
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${var.name_prefix}-ac-frps-control-${each.key}"
  }
}

# SSH (for SSM, admin) - VPC only
resource "aws_vpc_security_group_ingress_rule" "ac_ssh" {
  security_group_id = aws_security_group.ac.id
  description       = "SSH from VPC"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  cidr_ipv4         = var.vpc_cidr

  tags = {
    Name = "${var.name_prefix}-ac-ssh"
  }
}

# Traefik health/readiness endpoint - VPC only (for NLB health checks).
# The dedicated nhp-health entrypoint serves Traefik ping plus the nhp-acd
# admission-readiness route, so VPC peers can observe this AC's
# server-connectivity state. The public :443 router hides the same path behind
# a constant 404.
resource "aws_vpc_security_group_ingress_rule" "ac_traefik_health" {
  security_group_id = aws_security_group.ac.id
  description       = "Traefik health/readiness check from VPC (NLB)"
  # Sourced from the same local as the TG health_check blocks, the AC's
  # config.toml HealthCheckPort, and the EBPFXDP datapath exemption. This ENI
  # gate sits upstream of XDP in BOTH filter modes, so wiring it here completes
  # the single-source-of-truth end-to-end — otherwise a future port change
  # would move every other layer but leave the SG dropping the probe one hop
  # earlier (the same failure class this fix closes).
  from_port   = local.ac_health_check_port
  to_port     = local.ac_health_check_port
  ip_protocol = "tcp"
  cidr_ipv4   = var.vpc_cidr

  tags = {
    Name = "${var.name_prefix}-ac-traefik-health"
  }
}

# All outbound
resource "aws_vpc_security_group_egress_rule" "ac_all" {
  security_group_id = aws_security_group.ac.id
  description       = "All outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${var.name_prefix}-ac-egress"
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "ac" {
  name              = "/layerv/nhp/${var.environment}/ac"
  retention_in_days = local.is_prod ? 365 : 30
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-logs-ac"
    Component = "ac"
  })
}

# =============================================================================
# SSM Parameters for Deployment State
# These parameters enable CI/CD to update image tags without Terraform apply.
# Instances read the image tag from SSM at boot time.
# =============================================================================

# Current deployed image tag - updated by CI/CD after successful builds
resource "aws_ssm_parameter" "image_tag" {
  name        = "/${var.environment}/nhp/ac/image-tag"
  description = "NHP AC Docker image tag - updated by CI/CD"
  type        = "String"
  value       = var.image_tag

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-ssm-image-tag"
    Component = "ac"
  })

  # Allow CI/CD to update the value without TF drift
  lifecycle {
    ignore_changes = [value]
  }
}

# ASG name - used by CI/CD scripts to trigger instance refresh
resource "aws_ssm_parameter" "asg_name" {
  name        = "/${var.environment}/nhp/ac/asg-name"
  description = "NHP AC Auto Scaling Group name - used by CI/CD for instance refresh"
  type        = "String"
  value       = aws_autoscaling_group.ac.name

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-ssm-asg-name"
    Component = "ac"
  })
}

# ==================== Plugin Configuration ====================
# Traefik plugins are now managed by the unified plugins module.
# This module receives plugin_bucket_name from the plugins module and uses
# it to download plugins at boot time.
#
# Migration note: The old ${var.name_prefix}-traefik-plugins bucket has been
# replaced by the unified ${var.name_prefix}-plugins bucket from the plugins module.

# IAM Role for AC instances
resource "aws_iam_role" "ac" {
  name = "${var.name_prefix}-ac"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ac_ssm" {
  role       = aws_iam_role.ac.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Attach plugin download policy (from plugins module)
resource "aws_iam_role_policy_attachment" "ac_plugins" {
  count      = length(var.traefik_plugins) > 0 ? 1 : 0
  role       = aws_iam_role.ac.name
  policy_arn = var.plugin_download_policy_arn
}

resource "aws_iam_role_policy" "ac" {
  name = "ac-permissions"
  role = aws_iam_role.ac.id

  lifecycle {
    # QURL service token is required when QURL router is enabled
    # Use try() because Terraform doesn't short-circuit evaluate - accessing .enabled on null fails
    precondition {
      condition     = try(var.qurl_router_config.enabled, false) == false || var.qurl_service_token_secret_arn != null
      error_message = "qurl_service_token_secret_arn is required when qurl_router_config.enabled = true"
    }
  }

  # Build policy with conditional statements using concat
  # Statements with optional resources (QURL token, KMS key) are only included when configured
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      # Base statements (always present)
      [
        # Route53 access for ACME DNS-01 challenge
        {
          Sid    = "Route53ACME"
          Effect = "Allow"
          Action = [
            "route53:GetChange",
            "route53:ChangeResourceRecordSets",
            "route53:ListResourceRecordSets"
          ]
          Resource = concat(
            [local.resolved_zone_arn, "arn:aws:route53:::change/*"],
            [for zone_id in var.production_zone_ids : "arn:aws:route53:::hostedzone/${zone_id}"]
          )
        },
        {
          Sid      = "Route53ListZones"
          Effect   = "Allow"
          Action   = ["route53:ListHostedZonesByName"]
          Resource = "*"
        },
        # ECR access
        {
          Sid      = "ECRAuth"
          Effect   = "Allow"
          Action   = ["ecr:GetAuthorizationToken"]
          Resource = "*"
        },
        {
          Sid    = "ECRPull"
          Effect = "Allow"
          Action = [
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchGetImage"
          ]
          Resource = var.ac_repo_arn
        },
        # Secrets Manager - read NHP server public key
        {
          Sid      = "SecretsReadServerKey"
          Effect   = "Allow"
          Action   = ["secretsmanager:GetSecretValue"]
          Resource = [var.server_secret_arn]
        },
        # Secrets Manager - create and manage per-instance AC secrets
        # Each AC creates {prefix}-ac-{instance-id} for its private key
        {
          Sid    = "SecretsCreatePerInstance"
          Effect = "Allow"
          Action = [
            "secretsmanager:CreateSecret",
            "secretsmanager:PutSecretValue",
            "secretsmanager:GetSecretValue",
            "secretsmanager:TagResource",
            "secretsmanager:DescribeSecret"
          ]
          Resource = "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:${var.name_prefix}-ac-i-*"
        },
        # Cloud Map registration
        {
          Sid    = "CloudMapRegister"
          Effect = "Allow"
          Action = [
            "servicediscovery:RegisterInstance",
            "servicediscovery:DeregisterInstance",
            "servicediscovery:UpdateInstanceCustomHealthStatus",
            "servicediscovery:GetInstance"
          ]
          Resource = aws_service_discovery_service.ac.arn
        },
        {
          Sid    = "CloudMapDiscover"
          Effect = "Allow"
          Action = [
            "servicediscovery:DiscoverInstances",
            "servicediscovery:GetNamespace",
            "servicediscovery:GetService"
          ]
          Resource = "*"
        },
        # CloudWatch Logs
        {
          Sid    = "CloudWatchLogs"
          Effect = "Allow"
          Action = [
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ]
          Resource = "${aws_cloudwatch_log_group.ac.arn}:*"
        },
        {
          Sid      = "DenyDeploymentWindowNamespace"
          Effect   = "Deny"
          Action   = ["cloudwatch:PutMetricData"]
          Resource = "*"
          # Defense-in-depth: keep app instances out of the deploy-only
          # suppressor namespace even if a future allow broadens.
          Condition = {
            StringEquals = {
              "cloudwatch:namespace" = "LayerV/NHP/Deploy"
            }
          }
        },
        # CloudWatch Metrics (disk monitor script + Go app metrics, all use LayerV/NHP)
        {
          Sid      = "CloudWatchMetrics"
          Effect   = "Allow"
          Action   = ["cloudwatch:PutMetricData"]
          Resource = "*"
          Condition = {
            StringEquals = {
              "cloudwatch:namespace" = ["LayerV/NHP"]
            }
          }
        },
        # SSM Parameter Store access for deployment state (image tags)
        {
          Sid    = "SSMParameterAccess"
          Effect = "Allow"
          Action = ["ssm:GetParameter", "ssm:GetParameters"]
          Resource = [
            "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/nhp/ac/*"
          ]
        },
        # EC2 DescribeTags for blue/green deployment color detection
        {
          Sid      = "EC2DescribeTags"
          Effect   = "Allow"
          Action   = ["ec2:DescribeTags"]
          Resource = ["*"]
        },
      ],
      # Custom domain certificate access (for cert sync script — SSM Parameter Store)
      [
        {
          Sid    = "SSMCustomDomainCertsRead"
          Effect = "Allow"
          Action = [
            "ssm:GetParameter",
            "ssm:GetParametersByPath"
          ]
          Resource = [
            "arn:aws:ssm:${local.region}:${local.account_id}:parameter/nhp/certs/*"
          ]
        },
      ],
      # Conditional: QURL service token access (only when configured)
      var.qurl_service_token_secret_arn != null ? [
        {
          Sid      = "SecretsReadQurlServiceToken"
          Effect   = "Allow"
          Action   = ["secretsmanager:GetSecretValue"]
          Resource = [var.qurl_service_token_secret_arn]
        }
      ] : [],
      # Conditional: Centralized TLS certificate access (for scalable cert management)
      var.centralized_cert_secret_arn != null ? [
        {
          Sid      = "SecretsReadTLSCertificate"
          Effect   = "Allow"
          Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
          Resource = [var.centralized_cert_secret_arn]
        }
      ] : [],
      # Conditional: EIP association for stable egress IPs (only when enabled)
      # Note: ec2:DescribeAddresses and ec2:AssociateAddress do not support
      # resource-level permissions — Resource: "*" is required by AWS.
      var.enable_egress_eips ? [
        {
          Sid    = "EIPAssociation"
          Effect = "Allow"
          Action = [
            "ec2:DescribeAddresses",
            "ec2:AssociateAddress"
          ]
          Resource = "*"
        }
      ] : [],
      # Conditional: KMS for Secrets Manager (only when KMS key is configured)
      var.secrets_kms_key_arn != null ? [
        {
          Sid      = "KMSForSecrets"
          Effect   = "Allow"
          Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
          Resource = [var.secrets_kms_key_arn]
        }
      ] : [],
    )
  })
}

# Cross-account Route 53 access for production domains
resource "aws_iam_role_policy" "ac_cross_account_route53" {
  count = var.cross_account_route53_role_arn != null ? 1 : 0

  name = "cross-account-route53"
  role = aws_iam_role.ac.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AssumeRoute53Role"
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = var.cross_account_route53_role_arn
    }]
  })
}

# Traefik plugins deploy bucket access (for traefik-plugins CI/CD)
resource "aws_iam_role_policy" "ac_traefik_plugins_deploy" {
  count = var.traefik_plugins_deploy_bucket_arn != null ? 1 : 0

  name = "traefik-plugins-deploy"
  role = aws_iam_role.ac.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "TraefikPluginsS3Download"
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:ListBucket"
      ]
      Resource = [
        var.traefik_plugins_deploy_bucket_arn,
        "${var.traefik_plugins_deploy_bucket_arn}/*"
      ]
    }]
  })
}

# Upload user_data init script to S3 (rendered template exceeds EC2's 16KB user_data limit)
resource "aws_s3_object" "init_script" {
  count = var.plugin_bucket_name != null ? 1 : 0

  bucket       = var.plugin_bucket_name
  key          = "scripts/ac-init.sh"
  content      = local.user_data
  content_type = "text/x-shellscript"
}

# Shared helper library (retry, metrics) sourced by other scripts
resource "aws_s3_object" "lib_script" {
  count = var.plugin_bucket_name != null ? 1 : 0

  bucket       = var.plugin_bucket_name
  key          = "scripts/lib.sh"
  source       = "${path.module}/scripts/lib.sh"
  source_hash  = filemd5("${path.module}/scripts/lib.sh")
  content_type = "text/x-shellscript"
}

# Custom domain cert sync script (downloaded at boot and by SSM)
resource "aws_s3_object" "cert_sync_script" {
  count = var.plugin_bucket_name != null ? 1 : 0

  bucket       = var.plugin_bucket_name
  key          = "scripts/custom-domain-cert-sync.sh"
  source       = "${path.module}/scripts/custom-domain-cert-sync.sh"
  source_hash  = filemd5("${path.module}/scripts/custom-domain-cert-sync.sh")
  content_type = "text/x-shellscript"
}

# IAM policy for AC instances to download scripts from S3
resource "aws_iam_role_policy" "ac_scripts_download" {
  count = var.plugin_bucket_arn != null ? 1 : 0

  name = "scripts-download"
  role = aws_iam_role.ac.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ScriptsS3Download"
      Effect = "Allow"
      Action = ["s3:GetObject"]
      Resource = [
        "${var.plugin_bucket_arn}/scripts/*"
      ]
    }]
  })
}

resource "aws_iam_instance_profile" "ac" {
  name = "${var.name_prefix}-ac"
  role = aws_iam_role.ac.name

  tags = var.tags
}

# Cloud Map Service for AC discovery
resource "aws_service_discovery_service" "ac" {
  name        = "ac"
  description = "NHP Access Controller"

  dns_config {
    namespace_id = var.namespace_id

    dns_records {
      ttl  = 30
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  # No health_check_custom_config - instances register/deregister explicitly

  tags = var.tags
}

# User data script
locals {
  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    region                = local.region
    account_id            = local.account_id
    ac_repo_url           = var.ac_repo_url
    environment           = var.environment
    domain_name           = var.domain_name
    acme_email            = var.acme_email
    acme_ca_server        = coalesce(var.use_production_acme, local.is_prod) ? "https://acme-v02.api.letsencrypt.org/directory" : "https://acme-staging-v02.api.letsencrypt.org/directory"
    cloudmap_service_id   = aws_service_discovery_service.ac.id
    namespace_name        = var.namespace_name
    vpc_cidr              = var.vpc_cidr
    ipset_default_timeout = var.ipset_default_timeout
    ipset_temp_timeout    = var.ipset_temp_timeout
    ipset_max_elements    = var.ipset_max_elements
    # L3 flush-on-expiry — defaults preserve pre-flush behavior. The Go-side
    # first-load safety (endpoints/ac/config.go::updateBaseConfig) forces
    # dry-run on a boot where real flush is requested without the distinct
    # durable acknowledgement. Operators set that bit only after dry-run soak.
    enable_l3_flush_on_expiry       = var.enable_l3_flush_on_expiry
    l3_flush_dry_run                = var.l3_flush_dry_run
    l3_flush_real_mode_acknowledged = var.l3_flush_real_mode_acknowledged
    l3_flush_conntrack_backend      = lower(var.l3_flush_conntrack_backend)
    l3_flush_conntrack_pool_size    = var.l3_flush_conntrack_pool_size
    # Per-instance key generation
    name_prefix         = var.name_prefix
    secrets_kms_key_arn = var.secrets_kms_key_arn != null ? var.secrets_kms_key_arn : ""
    # AC configuration options
    log_level            = var.log_level
    ac_filter_mode       = var.ac_filter_mode
    ac_health_check_port = local.ac_health_check_port
    ac_id                = var.ac_id
    auth_service_id      = var.auth_service_id
    resource_ids         = jsonencode(var.resource_ids)
    server_secret_arn    = var.server_secret_arn
    # Cloud mode registration (license key is globally unique)
    license_key     = var.license_key
    server_endpoint = var.server_endpoint
    # Production domains (cross-account ACME)
    cross_account_route53_role_arn = var.cross_account_route53_role_arn
    production_domains             = var.production_domains
    additional_tls_domains         = var.additional_tls_domains
    # Traefik plugins (from unified plugins module)
    plugin_bucket_name = var.plugin_bucket_name
    traefik_plugins    = var.traefik_plugins
    # Deployment configuration
    ssm_image_tag_parameter       = aws_ssm_parameter.image_tag.name
    enable_blue_green             = var.enable_blue_green
    ssm_green_image_tag_parameter = var.enable_blue_green ? aws_ssm_parameter.green_image_tag[0].name : ""
    # QURL Router Plugin configuration
    qurl_router_enabled            = var.qurl_router_config != null ? var.qurl_router_config.enabled : false
    qurl_router_api_url            = var.qurl_router_config != null ? var.qurl_router_config.api_url : ""
    qurl_router_base_domain        = var.qurl_router_config != null ? var.qurl_router_config.base_domain : ""
    qurl_router_cache_ttl          = var.qurl_router_config != null ? var.qurl_router_config.cache_ttl : 60
    qurl_router_negative_cache_ttl = var.qurl_router_config != null ? var.qurl_router_config.negative_cache_ttl : 30
    qurl_router_max_cache_size     = var.qurl_router_config != null ? var.qurl_router_config.max_cache_size : 1000
    qurl_router_api_timeout        = var.qurl_router_config != null ? var.qurl_router_config.api_timeout : 5
    qurl_router_proxy_timeout      = var.qurl_router_config != null ? var.qurl_router_config.proxy_timeout : 30
    qurl_router_cache_shards       = var.qurl_router_config != null ? var.qurl_router_config.cache_shards : 16
    # Router-side HRW dispatch (traefik-plugins #134). Both fields render
    # unconditionally into the plugin config so the rendered TOML shape
    # is stable across the PR 3 → PR 4 flip — flipping
    # `enable_instance_hrw` is a value change on an existing key, not a
    # structural change in dynamic.toml.
    #
    # Important: dynamic.toml is rendered ONLY by user_data at instance
    # boot. Flipping this in tfvars produces a launch-template diff (the
    # base64gzip(local.user_data) hash changes) and an LT version bump,
    # but EXISTING AC instances retain the old dynamic.toml on disk
    # until an ASG instance refresh replaces them. So PR 4 must trigger
    # an AC instance refresh (or the canary state machine equivalent)
    # after applying — Traefik's file-watcher only sees the new value
    # on an instance launched against the new LT version.
    qurl_router_enable_instance_hrw            = var.qurl_router_config != null ? var.qurl_router_config.enable_instance_hrw : false
    qurl_router_instance_discovery_ttl_seconds = var.qurl_router_config != null ? var.qurl_router_config.instance_discovery_ttl_seconds : 20
    qurl_router_enable_qurl_site_authz         = var.qurl_router_config != null ? var.qurl_router_config.enable_qurl_site_authz : false
    # Render the routing cutover through a focused template so its exact TOML
    # shape is covered without constructing this provider-heavy module in a
    # unit test. False renders the empty string, preserving byte-identical user
    # data (and therefore a no-op plan) while the gate is unset. True starts
    # with a newline and appends the exact plugin field to the preceding line.
    # The production render fence below proves the final AC user data contains
    # the field if and only if the caller requested it.
    qurl_router_connector_routing_gate = chomp(templatefile("${path.module}/qurl_router_connector_routing_gate.toml.tpl", {
      require_connector_routing_id = var.qurl_router_config != null ? var.qurl_router_config.require_connector_routing_id : false
    }))
    # Per-AZ qurl-reverse-tunnel-server boundaries (plural `frpServerUrls` in
    # the plugin Config). Empty = tunnel routing disabled at the plugin
    # gate, regardless of any per-resource upstream_addr the API returns
    # — see the field doc in variables.tf for the load-bearing detail.
    qurl_router_frp_server_urls   = var.qurl_router_config != null ? var.qurl_router_config.frp_server_urls : []
    qurl_service_token_secret_arn = var.qurl_service_token_secret_arn
    ac_admission_ready_path       = local.ac_admission_ready_path
    # Centralized certificate management (for scalable AC deployments)
    centralized_cert_enabled    = var.centralized_cert_enabled
    centralized_cert_secret_arn = var.centralized_cert_secret_arn != null ? var.centralized_cert_secret_arn : ""
    centralized_cert_domains    = var.centralized_cert_domains
    acme_lambda_function_name   = var.acme_lambda_function_name
    # Scripts downloaded from S3 to avoid user_data 16KB limit
    lib_script_s3_uri       = var.plugin_bucket_name != null ? "s3://${var.plugin_bucket_name}/scripts/lib.sh" : ""
    cert_sync_script_s3_uri = var.plugin_bucket_name != null ? "s3://${var.plugin_bucket_name}/scripts/custom-domain-cert-sync.sh" : ""
    # Egress EIP configuration
    enable_egress_eips = var.enable_egress_eips
    eip_pool_tag       = local.eip_pool_tag
    # FRP tunnel server integration
    frp_server_host                  = var.frp_server_host
    frp_control_port                 = var.frp_control_port
    frp_vhost_http_port              = var.frp_vhost_http_port
    frp_control_upstream_host        = var.frp_control_upstream_host
    frp_control_additional_upstreams = var.frp_control_additional_upstreams
    frp_control_listener_ports       = local.frp_control_listener_ports
  })
}

resource "terraform_data" "frps_control_listener_port_preconditions" {
  count = length(local.frp_control_listener_ports) > 0 ? 1 : 0

  input = join(",", [for port in local.frp_control_listener_ports : tostring(port)])

  # Standalone fence by design: Terraform evaluates lifecycle
  # preconditions at plan time even without a downstream consumer, and
  # `input` makes port-set changes visible in the plan.
  lifecycle {
    precondition {
      condition     = length(distinct(local.frp_control_listener_ports)) == length(local.frp_control_listener_ports)
      error_message = "FRPS control listener ports must be unique. The primary frp_control_port and every frp_control_additional_upstreams[*].listen_port are public AC NLB listeners and cannot share a port."
    }
  }
}

# Plan-time render lint for the AC datapath selector. The eBPF rollout
# gates read the deployed config.toml `FilterMode` line through SSM, so
# this must render as unquoted numeric TOML and must stay connected to
# var.ac_filter_mode rather than drifting back to a literal.
resource "terraform_data" "ac_user_data_filter_mode_render_check" {
  input = sha256(local.user_data)

  lifecycle {
    precondition {
      condition     = strcontains(local.user_data, "\nFilterMode = ${var.ac_filter_mode}\n")
      error_message = "AC user_data must render config.toml with unquoted numeric `FilterMode = var.ac_filter_mode` so the eBPF rollout smoke can verify the active datapath."
    }
  }
}

# Plan-time render lint for the five operator-drivable L3 flush-on-expiry
# fields in config.toml. All five are env-root tfvars levers consumed by the AC
# at config load (endpoints/ac/config.go), so a template typo/refactor that
# drops any line silently no-ops the operator's IaC control with no plan-time
# failure: EnableL3FlushOnExpiry / L3FlushDryRun are the #2192 flush flags;
# L3FlushConntrackBackend / L3FlushConntrackPoolSize drive the #2940 netlink
# rollout gate. Anchors are boolean/quoted/numeric TOML lines rendered
# adjacently in user_data.sh.tpl.
resource "terraform_data" "ac_user_data_l3_conntrack_render_check" {
  input = sha256(local.user_data)

  lifecycle {
    precondition {
      condition = alltrue([
        strcontains(local.user_data, "\nEnableL3FlushOnExpiry = ${var.enable_l3_flush_on_expiry}\n"),
        strcontains(local.user_data, "\nL3FlushDryRun = ${var.l3_flush_dry_run}\n"),
        strcontains(local.user_data, "\nL3FlushRealModeAcknowledged = ${var.l3_flush_real_mode_acknowledged}\n"),
        strcontains(local.user_data, "\nL3FlushConntrackBackend = \"${lower(var.l3_flush_conntrack_backend)}\"\n"),
        strcontains(local.user_data, "\nL3FlushConntrackPoolSize = ${var.l3_flush_conntrack_pool_size}\n"),
      ])
      error_message = "AC user_data must render EnableL3FlushOnExpiry, L3FlushDryRun, L3FlushRealModeAcknowledged, L3FlushConntrackBackend, and L3FlushConntrackPoolSize into config.toml so the flush-on-expiry authority and netlink rollout gate can be driven through managed Terraform config."
    }
  }
}

# Fences the L3 flush-on-expiry master switch + dry-run guard into config.toml,
# the same way the conntrack knobs above are fenced. These render on adjacent
# template lines (user_data.sh.tpl) and are now operator-drivable from env
# tfvars, so assert they reach the AC and a rollout flip can't silently no-op.
resource "terraform_data" "ac_user_data_l3_flush_render_check" {
  input = sha256(local.user_data)

  lifecycle {
    precondition {
      condition = alltrue([
        strcontains(local.user_data, "\nEnableL3FlushOnExpiry = ${var.enable_l3_flush_on_expiry}\n"),
        strcontains(local.user_data, "\nL3FlushDryRun = ${var.l3_flush_dry_run}\n"),
        strcontains(local.user_data, "\nL3FlushRealModeAcknowledged = ${var.l3_flush_real_mode_acknowledged}\n"),
      ])
      error_message = "AC user_data must render EnableL3FlushOnExpiry, L3FlushDryRun, and L3FlushRealModeAcknowledged into config.toml so the L3 flush-on-expiry rollout can be driven through managed Terraform config."
    }
  }
}

# The AC datapath admits exactly this port through the XDP whitelist in
# FilterMode_EBPFXDP (endpoints/ac/udpac.go::ebpfInfraExemptRules). It MUST be
# the same port the target groups health-check, and both come from
# local.ac_health_check_port — this render check asserts config.toml carries it
# as unquoted numeric TOML so a datapath/health-check divergence can't ship.
resource "terraform_data" "ac_user_data_health_check_port_render_check" {
  input = sha256(local.user_data)

  lifecycle {
    precondition {
      condition     = strcontains(local.user_data, "\nHealthCheckPort = ${local.ac_health_check_port}\n")
      error_message = "AC user_data must render config.toml with unquoted numeric `HealthCheckPort = local.ac_health_check_port` so FilterMode_EBPFXDP admits the load-balancer probe on the same port the target groups health-check."
    }
  }
}

resource "terraform_data" "ac_user_data_admission_ready_route_render_check" {
  input = sha256(local.user_data)

  lifecycle {
    precondition {
      condition = alltrue([
        for anchor in local.ac_admission_ready_route_render_anchors :
        strcontains(local.user_data, anchor)
      ])
      error_message = "AC user_data must render a dedicated Traefik nhp-health entrypoint/router for local.ac_admission_ready_path to nhp-acd on 127.0.0.1:8888 plus an https-entrypoint rewrite that keeps the readiness bit internal; the ac_tcp health checks depend on nhp-acd readiness, not Traefik process liveness."
    }
  }
}

# Plan-time render lint for the FRPS-behind-AC Traefik bits. The TG
# healthcheck for `ac_frps_control` probes Traefik's `/ping` on the
# dedicated health-check port, which confirms the Traefik PROCESS is
# alive but says nothing about whether the `entryPoints.frps-control`
# listener on the customer-facing port actually bound or whether
# `frps-control.toml` parsed
# and installed the TCP router. A templatefile-render regression
# (template-condition typo, accidental deletion of one of the two
# `%{ if frp_control_upstream_host != "" ~}` blocks in
# `user_data.sh.tpl`) would let CI + apply pass while customer SYNs
# silently hang at the Traefik listener layer.
#
# Hard fence (precondition on a terraform_data resource, gated on FRPS
# being enabled): apply refuses if either rendered literal is missing.
# Rationale for hard-vs-soft: a Traefik schema rewrite that renames
# `[entryPoints.…]` IS a deliberate change the operator will update
# the asserts for; a typo or accidental deletion of a templatefile-if
# block is silent and produces a fleet-wide knock-but-no-listener
# regression that takes hours to diagnose. The cost of a stale
# literal at schema-rewrite time is one PR; the cost of the typo
# silently shipping is much higher.
resource "terraform_data" "ac_user_data_frps_control_traefik_render_check" {
  count = (var.frp_control_upstream_host != "" || length(var.frp_control_additional_upstreams) > 0) ? 1 : 0

  # Re-evaluate when the rendered user_data changes so the precondition
  # re-runs on every render. `sha256` (vs `md5`) avoids Trivy/CIS
  # flagging md5 use even in non-cryptographic contexts; the choice is
  # incidental — any change-detecting hash works.
  input = sha256(local.user_data)

  lifecycle {
    precondition {
      # All three literals MUST appear in the rendered user_data when
      # FRPS is enabled:
      #   - `[entryPoints.frps-control]`: Traefik static config binding
      #     the listener on `:${frp_control_port}`.
      #   - `[tcp.routers.frps-control]`: dynamic-file router that
      #     forwards admitted TCP streams to the internal FRPS instance.
      #   - The full iptables-rule line for `defaultset` (NOT just the
      #     substring `match-set defaultset`, which also appears in
      #     comment headers — the substring would silently pass even
      #     after a regression that deleted the rule line but left
      #     the documentation block). The runtime boot guard at the
      #     end of user_data still catches the deletion via
      #     `iptables -L INPUT -n | grep`, but this plan-time fence
      #     anchors on the rule line to avoid the comment-only false
      #     positive.
      # Any one missing means the templatefile-condition guard on the
      # three `frp_control_upstream_host != ""` blocks has regressed.
      # The TG `/ping` healthcheck wouldn't catch any of them.
      condition = (
        strcontains(local.user_data, "-A INPUT -m set --match-set defaultset src,dst,dst -j ACCEPT") &&
        (
          var.frp_control_upstream_host == "" ||
          (
            strcontains(local.user_data, "[entryPoints.frps-control]") &&
            strcontains(local.user_data, "[tcp.routers.frps-control]") &&
            strcontains(local.user_data, "[tcp.services.frps-control.loadBalancer]")
          )
        ) &&
        alltrue([
          for name, upstream in var.frp_control_additional_upstreams :
          strcontains(local.user_data, "[entryPoints.frps-control-${name}]") &&
          strcontains(local.user_data, "[tcp.routers.frps-control-${name}]") &&
          strcontains(local.user_data, "[tcp.services.frps-control-${name}.loadBalancer]") &&
          strcontains(local.user_data, "[[tcp.services.frps-control-${name}.loadBalancer.servers]]\n    address = \"${upstream.upstream_host}:${upstream.upstream_port}\"")
        ])
      )
      error_message = "AC user_data render is missing one of the FRPS-control Traefik entrypoints/routers/services or the `-A INPUT -m set --match-set defaultset src,dst,dst -j ACCEPT` iptables rule despite FRPS control ingress being configured. A templatefile-condition regression in `user_data.sh.tpl` would silently produce this. The TG `/ping` healthcheck wouldn't catch any of them — see lifecycle comment on aws_lb_target_group.ac_frps_control."
    }
  }
}

# DO NOT REMOVE — load-bearing plan-time fence. Structurally decoupled
# from `aws_launch_template.ac` (the consumer of this template), so a
# future cleanup pass might mistake it for unused; it's not. Prophylactic
# even today (the only ref to the var is `%{ for }`, not `${...}`), so
# more important to flag than the compute sibling.
#
# Bash-comment escape fence for multi-line `qurl_router_frp_server_urls`.
# Implements the rule documented in terraform/CLAUDE.md
# ("templatefile() multi-line vars in bash comments must be escaped"). The
# compute module previously carried a sibling fence on the FRPS overlay var
# (`terraform_data.frps_overlay_comment_escape_fence`), retired in #1976
# when the overlay itself was deleted; this AC-side fence is now the only
# live instance of the pattern. The list interpolates to multiple
# `"http://..."` TOML lines; any future `${qurl_router_frp_server_urls}` ref
# inside a bash comment in user_data.sh.tpl would inject body lines that
# don't start with `#`, and bash would execute them when the rendered script
# runs. This fence catches a regression that adds an unescaped
# `${qurl_router_frp_server_urls}` inside a bash comment.
#
# RENAME WARNING: if this template var is ever renamed, update the regex
# (and the error_message below) to match the new name — otherwise this
# fence silently no-ops.
resource "terraform_data" "qurl_router_frp_server_urls_comment_escape_fence" {
  lifecycle {
    precondition {
      # `(^|[[:space:]])#` — comment anchor: either line-start `#` or a `#`
      # preceded by whitespace (trailing inline comment).
      # `(?:[^\n]*[^$\n])?` — optional prefix where the LAST char before
      # `${var}` is non-`$`. The optional `?` lets `#${var}` (no separator)
      # match; the `[^$\n]` last-char enforces the var ref isn't escaped
      # via `$${var}`. `[^\n]*` (not `[^$\n]*`) so an unrelated earlier
      # `$RESOURCE` on the same line doesn't block matching a later
      # unescaped `${qurl_router_frp_server_urls}` ref.
      condition = length(regexall(
        "(?m)(^|[[:space:]])#(?:[^\\n]*[^$\\n])?\\$\\{qurl_router_frp_server_urls\\}",
        file("${path.module}/user_data.sh.tpl"),
      )) == 0
      # HCL escape note: `$${...}` in source renders as `${...}` in the
      # plan-time message; `$$$${...}` renders as `$${...}`. So this string
      # shows operators an unescaped `${var}` (the bug) and the escaped
      # `$${var}` (the fix), both in plain Terraform-comment syntax.
      error_message = "user_data.sh.tpl has an unescaped `$${qurl_router_frp_server_urls}` Terraform interpolation inside a bash comment. The value is a multi-line list of `\"http://...\"` TOML lines; bash-comment syntax does not suppress Terraform interpolation, so the multi-line body would be injected into the comment block and lines without `#` would bash-execute when the rendered script runs. Either move the ref outside the bash comment (control flow with `%%{ for ... }` is fine), or double-escape with a second `$` so the token becomes `$$$${qurl_router_frp_server_urls}` and templatefile() emits the literal instead. See terraform/CLAUDE.md \"templatefile() multi-line vars in bash comments must be escaped\"."
    }
  }
}

# DO NOT REMOVE - load-bearing plan-time fence. AC runtime dependencies must be
# baked into the AMI, not installed by user_data. Any executable apt site here
# puts boot back on the public Ubuntu mirror path and can regress standby health
# during transient mirror sync windows. This scans the full init template and
# this file's small launch-template bootstrap heredoc for obvious apt
# invocations; it is intentionally a source-scan fence, not a full shell parser,
# and it does not inspect rendered output from future template interpolations.
# That boundary is acceptable because today's template inputs are data values,
# not shell fragments; add a rendered-output apt fence if that ever changes.
#
# Lockstep: adding a `require_baked_*` check in user_data.sh.tpl MUST land with
# the matching packer/nhp-ac.pkr.hcl bake change. Pairing stricter user_data
# validation with a stale AC AMI fails loud by design.
resource "terraform_data" "ac_user_data_runtime_apt_guard_fence" {
  lifecycle {
    precondition {
      condition = length(concat(
        regexall(
          local.ac_runtime_apt_regex,
          file("${path.module}/user_data.sh.tpl"),
        ),
        regexall(
          local.ac_runtime_apt_regex,
          file("${path.module}/main.tf"),
        ),
      )) == 0
      error_message = "AC user_data/bootstrap must not run apt update/install/upgrade at boot. Bake runtime dependencies into the AC AMI and validate them in user_data instead of adding runtime package installs."
    }
  }
}

# Render-shape fence for the qurl-router middleware block. When the
# router is enabled, the rendered user_data MUST contain the
# `frpServerUrls = [` literal — a templatefile-condition regression
# (accidental deletion, typo in the field name) would silently leave
# the qurl-router middleware with an empty allowlist, regressing the
# silent-drop/502 failure mode this PR fixes. Same precondition pattern
# as `ac_user_data_frps_control_traefik_render_check` above; sibling
# rather than merged because that resource is gated on a different
# variable (`frp_control_upstream_host`) and using a separate resource
# keeps the error_message specific to the regression that produced it.
#
# Gate on `enabled` (not just non-null-ness): the `frpServerUrls = [`
# literal renders inside `%{ if qurl_router_enabled ~}` in
# user_data.sh.tpl, and the template-side `qurl_router_enabled` is
# `var.qurl_router_config.enabled` (locals block above). A
# module-direct consumer passing `{ enabled = false, ... }` is a
# legitimate disabled config, not a regression — gating only on
# non-null-ness would false-positive there. The in-tree caller
# (`terraform/main.tf`) only ever builds the object with
# `enabled = true`, so this is purely for module-API stability with
# external callers.
resource "terraform_data" "ac_user_data_qurl_router_render_check" {
  count = (var.qurl_router_config != null && var.qurl_router_config.enabled) ? 1 : 0

  # Re-evaluate when the rendered user_data changes so the precondition
  # re-runs on every render. Same pattern as
  # `ac_user_data_frps_control_traefik_render_check` above.
  input = sha256(local.user_data)

  lifecycle {
    precondition {
      # Asserting on `frpServerUrls = [` (with the opening bracket and
      # equals — NOT just the substring `frpServerUrls`, which also
      # appears in comment headers above the field, so a substring
      # match would silently pass after a regression that deleted the
      # field assignment but left the documentation block).
      condition     = strcontains(local.user_data, "frpServerUrls = [")
      error_message = "AC user_data render is missing the `frpServerUrls = [` literal in the qurl-router middleware block despite qurl_router_config.enabled=true. A templatefile-condition regression (deletion or typo in `user_data.sh.tpl`) would silently produce this and leave the plugin's allowlist empty, regressing the silentDrop/502 failure mode #2134 fixed — see the field doc in `variables.tf` for the load-bearing detail."
    }
    precondition {
      # When the caller threaded a non-empty list, the rendered user_data
      # MUST contain at least one `"http://frps-` entry — the literal
      # shape `BuildUpstreamAddr` emits and the only place this prefix
      # appears in the rendered output. Catches a `%{ for }` regression
      # that emitted an empty array body despite non-empty input (e.g.
      # accidentally renaming the iteration variable so `${url}`
      # expands to nothing). Skipped when the caller passes `[]` —
      # that's the legitimate `deploy_frps=false` rendering posture.
      condition = (
        length(var.qurl_router_config.frp_server_urls) == 0
        || strcontains(local.user_data, "\"http://frps-")
      )
      error_message = "qurl_router_config.frp_server_urls is non-empty but the rendered user_data has no `\"http://frps-` entries in the qurl-router middleware block. A templatefile `%%{ for }` regression (renamed iteration variable, lost interpolation) would silently produce this and leave the plugin's allowlist empty, regressing the silentDrop/502 failure mode #2134 fixed."
    }
    precondition {
      # False deliberately omits the field so an unset/default-dark variable
      # produces byte-identical user data and no launch-template plan. The
      # plugin's bool zero-value is false. True must render exactly once: a
      # dropped module input would otherwise make the cutover impossible, and
      # duplicates would make the active startup posture ambiguous.
      condition = length(regexall(
        "(?m)^  enableQurlSiteAuthz = (true|false)\n  requireConnectorRoutingID = true$",
        local.user_data,
      )) == (var.qurl_router_config.require_connector_routing_id ? 1 : 0)
      error_message = "AC user_data must omit `requireConnectorRoutingID` while qurl_router_config.require_connector_routing_id=false and render exactly one `requireConnectorRoutingID = true` immediately after `enableQurlSiteAuthz` when enabled. The gate is startup-only; missing, moved, duplicated, or stale rendering would make the fleet's active cutover posture unauditable."
    }
  }
}

# Narrow cross-stack readiness fence. The root token depends on the
# qurl-service internal-ALB certificate validation and DNS alias. Keeping that
# edge here, next to the sole runtime consumer, avoids making unrelated AC
# data sources and Route53 records unknown during every internal-ALB change.
# This resource deliberately remains present with input="" when the internal
# ALB path is disabled. Its enabled token is unknown on a first apply, so using
# token != "" as count would make count unknown and fail planning; the empty
# token carries no live certificate/alias instance edge and is inert.
# The launch template depends on this resource only for ordering: a later token
# update intentionally does not create a new template version or roll the fleet.
resource "terraform_data" "qurl_internal_alb_readiness" {
  input = var.qurl_internal_alb_readiness_token
}

# Launch Template
resource "aws_launch_template" "ac" {
  name_prefix   = "${var.name_prefix}-ac-"
  image_id      = local.ac_ami_id
  instance_type = local.is_prod ? "c6i.xlarge" : "t3.medium"

  iam_instance_profile {
    arn = aws_iam_instance_profile.ac.arn
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.ac.id]
  }

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = 50
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.ebs_kms_key_arn
      delete_on_termination = true
    }
  }

  # Full init script is stored in S3 (exceeds EC2's 16KB user_data limit).
  # This bootstrap validates the baked AWS CLI/curl tools, downloads the init
  # script, and execs it. It intentionally does not install missing tools at
  # boot; the AC launch template is pinned to local.ac_ami_id and the AMI must
  # be rebuilt if bootstrap dependencies are absent.
  # An md5 of the rendered local.user_data is embedded so a content change
  # forces a launch template version bump (and thus an instance refresh on
  # the next deploy). See the in-heredoc comment for why md5(local.user_data)
  # instead of the S3 object's etag.
  # Keep in sync with modules/compute/main.tf::aws_launch_template.server.
  # The apt-guard fixture extracts this BOOTSTRAP heredoc by delimiter; update
  # tests/lints/ac-apt-guard/run-fixtures.sh if the assignment shape changes.
  user_data = var.plugin_bucket_name != null ? base64encode(<<-BOOTSTRAP
#!/bin/bash
set -ex
exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
# Init script hash — md5 of local.user_data, NOT the S3 object's etag.
# The hash bumps the launch-template version whenever content changes.
# Referencing aws_s3_object.init_script[0].etag here triggers the AWS
# provider's "inconsistent values for sensitive attribute" bug on
# user_data updates: TF pre-computes one etag client-side, the apply-time
# S3 upload yields a different etag (sensitivity-handling or encoding
# divergence in the provider), and plan-expansion fails. md5(local.user_data)
# is computed entirely client-side, so it can't disagree with itself
# between plan and apply.
# Keep in sync with modules/compute/main.tf::aws_launch_template.server.
# Init script hash: ${md5(local.user_data)}
# Report bootstrap failures to CloudWatch for operational visibility
report_failure() {
  echo "BOOTSTRAP FAILED: $1"
  local region="$${REGION:-}"
  [ -n "$region" ] && command -v aws &>/dev/null && aws cloudwatch put-metric-data \
    --namespace "LayerV/NHP" \
    --metric-name "BootstrapFailure" \
    --value 1 --unit Count \
    --dimensions "Component=ac,Environment=${var.environment}" \
    --region "$region" 2>/dev/null || true
}
trap 'report_failure "unexpected error on line $LINENO"' ERR
for binary in aws curl; do
  if ! command -v "$binary" >/dev/null 2>&1; then
    report_failure "missing baked bootstrap dependency: $binary"
    exit 1
  fi
done
# Retry helper (same as user_data.sh.tpl)
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
# Get region from IMDSv2
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
# Download full init script from S3
retry_with_backoff 3 5 30 aws s3 cp "s3://${var.plugin_bucket_name}/scripts/ac-init.sh" /tmp/ac-init.sh --region "$REGION"
chmod +x /tmp/ac-init.sh
exec /tmp/ac-init.sh
BOOTSTRAP
  ) : base64gzip(local.user_data) # WARNING: will fail if rendered template exceeds EC2's 16KB user_data limit

  monitoring {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags = var.tags

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      Name      = "${var.name_prefix}-ac"
      Component = "ac"
    })
  }

  lifecycle {
    create_before_destroy = true

    precondition {
      condition     = !var.server_nlb_source_fenced || var.enable_egress_eips
      error_message = "server_nlb_source_fenced requires enable_egress_eips so every AC registration source has a stable exact /32."
    }

    precondition {
      condition     = !var.server_nlb_source_fenced || var.server_nlb_security_group_id != ""
      error_message = "server_nlb_security_group_id is required when server_nlb_source_fenced is true."
    }

    precondition {
      condition     = !var.centralized_cert_enabled || length(var.centralized_cert_domains) > 0
      error_message = "centralized_cert_domains must not be empty when centralized_cert_enabled is true."
    }

    precondition {
      condition     = !var.centralized_cert_enabled || (var.centralized_cert_secret_arn != null && var.centralized_cert_secret_arn != "")
      error_message = "centralized_cert_secret_arn must be provided when centralized_cert_enabled is true."
    }
  }

  # The user_data hash is md5(local.user_data), not the S3 object's etag, so
  # there is no longer an attribute reference for TF to infer this from. The
  # S3 init script is still a runtime hard dependency: an instance launched
  # against this LT does `aws s3 cp` of the script at boot, so the object
  # must exist by the time the ASG can launch. Without this explicit edge,
  # an update path could land the LT (and trigger a refresh) before the
  # parallel S3 PUT, and a fresh instance would fetch stale init content.
  depends_on = [
    aws_s3_object.init_script,
    terraform_data.qurl_internal_alb_readiness,
  ]
}

# Auto Scaling Group - in PUBLIC subnets for direct access
resource "aws_autoscaling_group" "ac" {
  name                = "${var.name_prefix}-ac"
  vpc_zone_identifier = var.public_subnet_ids
  min_size            = coalesce(var.ac_min_capacity, local.is_prod ? 2 : 1)
  max_size            = local.resolved_max_capacity
  desired_capacity    = coalesce(var.ac_min_capacity, local.is_prod ? 2 : 1)

  launch_template {
    id      = aws_launch_template.ac.id
    version = aws_launch_template.ac.latest_version
  }

  health_check_type         = "EC2"
  health_check_grace_period = 180 # Reduced from 300s - AC startup is typically ~90-120s

  # Publish ASG group metrics to CloudWatch (AWS/AutoScaling namespace).
  # Without this, metrics like GroupInServiceInstances are not emitted.
  # Keep GroupDesiredCapacity + GroupInServiceInstances: green standby
  # capacity-deficit alarms use them as their publishable replacement for
  # AWS's non-existent GroupUnHealthyInstanceCount ASG group metric.
  enabled_metrics = [
    "GroupInServiceInstances",
    "GroupDesiredCapacity",
    "GroupMinSize",
    "GroupMaxSize",
    "GroupPendingInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances",
  ]

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-ac"
    propagate_at_launch = true
  }

  # Blue/green deployment: tag blue ASG for color detection in user_data
  tag {
    key                 = "DeployColor"
    value               = "blue"
    propagate_at_launch = true
  }

  # SSM parameter path for image tag - matches green ASG's ImageTagSSMParam tag
  tag {
    key                 = "ImageTagSSMParam"
    value               = aws_ssm_parameter.image_tag.name
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = var.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
    # CI/CD manages capacity on this ASG during blue/green switches.
    # See the matching comment on `aws_autoscaling_group.server` in
    # compute/main.tf for the full rationale — short version: when
    # blue-green-deploy.yml scales this ASG down to warm standby,
    # the next `terraform apply` would reset desired_capacity/
    # min_size back to `var.ac_min_capacity` unless we ignore them.
    # Capacity and process suspension are deployment-owned. The durable-AOP
    # one-way cut sets a retired color to min=max=desired=0 and suspends all
    # scaling; only a later exact-image blue/green prepare may restore it.
    ignore_changes = [desired_capacity, min_size, max_size, suspended_processes]
  }
}

# Network Load Balancer for HTTPS traffic
resource "aws_lb" "ac" {
  name               = replace("${var.name_prefix}-ac-nlb", "_", "-")
  internal           = false
  load_balancer_type = "network"
  subnets            = var.public_subnet_ids

  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = local.is_prod

  tags = var.tags
}

# TCP Target Group (TLS passthrough to Traefik).
#
# Keep Proxy Protocol v2 OFF on this target group. The NLB already preserves the
# browser source IP at L3 (`preserve_client_ip = true`), which is what both the
# NHP pinhole and qurl-router need. Adding Proxy Protocol on top of preserved
# client IP prepends bytes before the TLS ClientHello; Traefik's Proxy Protocol
# trust check then sees the public browser IP as the TCP peer rather than an NLB
# node, so the stream can die before any qurl-router authorize call is made.
resource "aws_lb_target_group" "ac_tcp" {
  name               = replace("${var.name_prefix}-ac-tcp", "_", "-")
  port               = 443
  protocol           = "TCP"
  vpc_id             = var.vpc_id
  target_type        = "instance"
  preserve_client_ip = true
  proxy_protocol_v2  = false

  # HTTP health check routed by Traefik to nhp-acd readiness. Port 443 is
  # blocked by default for NHP port hiding - only opened after knock. A target
  # must have at least one healthy assigned server before the NLB sends
  # qURL/TLS traffic to it. This proves admission readiness, not the full :443
  # TLS passthrough leg; the qURL smoke in the rollout ledger covers that path.
  # Rollout note: health_check.path updates in place. Do not apply this path
  # cutover to an active AC fleet still running user_data without the
  # nhp-ac-ready router, or every old target can 404 the probe and go unhealthy
  # after the 30s*3 unhealthy window. See the PR #3050 rollout ledger.
  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = tostring(local.ac_health_check_port)
    path                = local.ac_admission_ready_path
    matcher             = "200"
    interval            = 30
    timeout             = 6
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay = 30

  # See compute/main.tf::aws_lb_target_group.https for the rationale
  # behind connection_termination=true on blue/green-managed TCP TGs.
  # The AC NLB participates in the same flip pattern as the server
  # NLB; without RST-on-dereg, in-flight TLS flows on a draining AC
  # instance leave CloudFront (and any direct *.qurl.site client)
  # waiting on their read timeout instead of cleanly retrying on the
  # new color. The 2026-05-22 sandbox incident hit the server path
  # first, but the AC path is structurally identical.
  #
  # **Blast-radius note for AC port 443**: this TG fronts Traefik's
  # TLS passthrough → qurl-router (httputil.ReverseProxy + Hijacker,
  # which CAN support WebSocket/SSE/streaming responses if customer
  # backends use them). Today's known QURL targets are all
  # short-poll request/response (login portal redirects,
  # fileviewer page loads, S3 GETs), so the streaming case is
  # latent capability not active traffic. Before the 2026-05-22 fix,
  # an AC instance shrink during blue/green gave in-flight flows up
  # to deregistration_delay=30s to complete. After the fix, they get
  # an immediate RST and the client must reconnect (standard web
  # behaviour for deploy-time blips — clients should already handle
  # ECONNRESET → retry). The trade-off is intentional: the
  # silent-stall failure mode (60s spinner → closed L3 firewall)
  # is strictly worse for the dominant request/response traffic
  # pattern than a clean RST is for the (presently latent) streaming
  # case.
  #
  # **Duplicate-POST corollary**: on RST after an in-flight POST,
  # CloudFront (or other retry-on-connection-error upstreams) will
  # replay the request. For qURL token-consume flows on the SERVER
  # path the qurl-service DDB conditional update is idempotent — a
  # retry returns 403 not a double-consume. On THIS TG (AC TLS
  # passthrough → customer backends), the qurl-router proxy
  # forwards retries transparently; non-idempotent customer
  # backends could see duplicate writes on a deploy-time blip
  # where before the 2026-05-22 fix they would have seen a 60s
  # stall instead. The
  # alternative is strictly worse for the dominant request/response
  # case.
  #
  # **Customer-endpoint audit as of 2026-05-22**: all known
  # production QURL targets are GET / idempotent token-exchange
  # flows (login portal redirects, fileviewer page loads, S3
  # presigned-GET). No known non-idempotent customer POST endpoint
  # exists on this path today. Future customer onboarding of a
  # non-idempotent POST should weigh duplicate-write risk during
  # deploy windows against the alternative 60s-stall failure mode;
  # target-aware drain work tracked at #2130.
  #
  # If a future customer integration depends on the old drain
  # window, the right fix is target-aware draining in the deploy
  # procedure, not flipping this attribute back off — that work is
  # filed at #2130 (target-aware drain) with preflight observability
  # at #2127 (streaming-traffic detection on this TG).
  connection_termination = true

  tags = var.tags
}

# Attach ASG to Target Group
resource "aws_autoscaling_attachment" "ac" {
  autoscaling_group_name = aws_autoscaling_group.ac.name
  lb_target_group_arn    = aws_lb_target_group.ac_tcp.arn
}

# HTTPS Listener (TLS passthrough - Traefik handles TLS)
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.ac.arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ac_tcp.arn
  }

  tags = var.tags

  lifecycle {
    # blue-green-switch.sh flips default_action.target_group_arn on
    # every traffic switch. Without this ignore, `terraform apply`
    # resets the listener back to the blue TG within seconds of a
    # successful green switch. See compute/main.tf::aws_lb_listener.udp
    # for the full explanation of the drift mode.
    ignore_changes = [default_action]
  }
}

# ==================== FRPS Control Channel NLB Listener ====================
#
# TRANSITIONAL — see banner on `aws_vpc_security_group_ingress_rule.ac_frps_control`
# above and https://github.com/layervai/nhp/issues/2019 ("AC out of the FRPS
# data path"). This NLB listener + its sibling TG + ASG attachment + the
# Traefik `entryPoints.frps-control` / `frps-control.toml` blocks in
# `user_data.sh.tpl` collectively place the AC in the FRPS data plane as a
# userspace TCP forwarder. Target shape is AC-as-firewall-manager only, with
# FRPS-side ipset updated out-of-band; this whole block is removal work then.
#
# Public TCP listener for the FRPS control channel at
# `connect.layerv.{ai,xyz}:${frp_control_port}`. This is the customer-facing
# ingress that the DDB seed row's `resource_fqdn` field (→ ResourceInfo.Hostname) resolves to;
# the AC kernel's existing ipset fence (default-DROP INPUT, permit via
# `-A INPUT -m set --match-set defaultset src,dst,dst -j ACCEPT`) gates each
# SYN per NHP knock — a coarse source-IP pre-filter while the AC is in the
# data path. The primary, fine-grained access-control mechanism is the
# per-client X25519 key-authenticated knock + opaque-token validation at
# FRP-Login via nhp-server's `/token/validate` (qurl-reverse-tunnel-server
# #98). See SLACK_QURL_ROLLOUT.md §6 (FRPS-behind-AC redesign 2026-05-18)
# for the full design and packet flow.
#
# Pre-redesign: no public 7000 listener; FRPS:7000 was reachable only from
# the AC SG via the legacy `/.well-known/layerv-frp` Traefik route on port
# 443. The FRPS-specific NHP knock added ipset entries keyed on the internal
# FRPS dst_ip — a triple no AC kernel packet ever matched. Result: token
# issuance worked, L3/L4 gate did not. This listener is the missing piece.
#
# Why TCP and not TLS:
#   - The FRP control channel uses its own framing (yamux-over-TCP); TLS
#     termination at the NLB would require terminating FRP's protocol too.
#   - Confidentiality/integrity for the tunnel payload are owned by NHP's
#     keypair-authenticated session plus the AC's ipset gate on each SYN.
#     The control channel ride on top of that boundary.
#   - Mirrors the `ac_tcp` HTTPS listener's TCP passthrough posture (TLS
#     terminates at Traefik on the AC instance).
#
# Why a separate TG and not reuse `ac_tcp`:
#   - `ac_tcp` healthchecks on nhp-acd admission readiness for knocked-in
#     HTTPS/qURL resource flows. The FRPS control entrypoint has a separate
#     documented `/ping` caveat below; the new TG exists because the
#     listener-to-TG binding is 1:1 and the listener targets a different port.
#   - Proxy Protocol v2 is intentionally OFF here (the FRP control channel
#     doesn't speak PP, and the Traefik TCP entrypoint would need
#     `proxyProtocol` awareness to accept it). Preserving client IP for
#     the ipset fence is explicit below and handled by the NLB at L4
#     without PP — AC instance sees `agent_ip → ac_local_ip:port`.
#
# Conditional on FRPS deployment: when `var.frp_control_upstream_host` is
# empty (greenfield env, no FRPS), the listener + TG aren't created. The
# SG ingress rule (above) is gated on the same predicate, so non-FRPS
# envs have NO public 7000/tcp opening on the AC SG (avoids compliance-
# scanner noise on every non-FRPS env).
resource "aws_lb_target_group" "ac_frps_control" {
  count = var.frp_control_upstream_host != "" ? 1 : 0

  name        = local.ac_frps_control_tg_name
  port        = var.frp_control_port
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  # Explicit for reader symmetry with `ac_tcp`; this FRPS-control TG is outside
  # the qurl.site transport contract fenced by `ac_tcp_target_group_drift`.
  preserve_client_ip = true

  # Healthcheck caveat: Traefik `/ping` on the dedicated health-check
  # port confirms the Traefik process is alive but does NOT verify the
  # `entryPoints.frps-control` listener on `:${var.frp_control_port}`
  # actually bound or that `frps-control.toml` parsed and installed the
  # TCP router. A drift
  # mode scoped to the new entrypoint (typo in template render,
  # quote-escape regression, partial templatefile output) keeps `/ping`
  # returning 200 while customer SYNs to `:7000` hang at the Traefik
  # listener layer. A real port-7000 TCP probe is not viable from the
  # NLB: the AC kernel ipset gate blocks all unknocked SYNs to that
  # port, including NLB health-check probes, so a TCP HC would have
  # to be ipset-allowlisted — which would defeat the gate's own posture.
  # The acceptable mitigation is a post-deploy smoke check that runs on
  # every deploy and asserts a knocked-in agent can complete TCP+FRP
  # handshake. Tracked in #2007 (FRPS-behind-AC observability +
  # post-deploy verification gates).
  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = tostring(local.ac_health_check_port)
    path                = "/ping"
    matcher             = "200"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay = 30

  # **NOT setting connection_termination=true here** (cf. ac_tcp and
  # the compute TGs). The dominant traffic on this TG is the customer
  # frpc agent's long-lived yamux-multiplexed control session
  # (one persistent TCP per active reverse tunnel), NOT short-lived
  # request/response. The trade-off framing on ac_tcp ("silent 60s
  # stall is strictly worse than a clean RST for the dominant
  # request/response pattern; rare streaming case gets a reconnect")
  # does NOT carry over verbatim — for FRP control, the streaming
  # case IS the dominant pattern. Setting connection_termination=true
  # would force every connected agent to ECONNRESET + re-knock + FRP
  # re-login simultaneously on every AC blue/green flip; the
  # thundering-herd shape (knock storm, ipset churn, FRPS login
  # burst) could pressure MetricACConnEviction and FRPS rate limits.
  # Avoiding that thundering-herd shape IS the reason we keep the
  # AWS default here.
  #
  # **What deregistration_delay actually does on this TG**: with
  # connection_termination=false,
  # the 30s delay controls how long the LB stops routing NEW
  # connections to the deregistering target while keeping it in the
  # TG. It does NOT extend the instance's lifecycle — EC2/ASG
  # termination is governed by ASG lifecycle hooks + the
  # application's SIGTERM-to-exit window. In-flight yamux RPC
  # survival on a draining AC instance therefore depends on the
  # application's graceful-shutdown timing, NOT on this TG attribute.
  # A future operator tuning either should know they're disjoint
  # knobs (cf. compute/main.tf::aws_lb_target_group.https for the
  # same disjoint-roles writeup on the connection_termination=true
  # side).
  #
  # Removal of this whole TG is tracked in #2019 (AC out of the
  # FRPS data path); after that lands the question becomes moot.
  # Until then, AWS default (connection_termination=false) is the
  # correct value here.

  tags = var.tags

  # NOTE on TG-name renames: fixed `name` attribute (consistent with
  # sibling `ac_tcp` TG). The AWS provider's `name_prefix` is limited
  # to 6 chars, which is too short for a descriptive identifier — see
  # the `ac_frps_control_tg_name` local for that constraint. AWS
  # forbids two TGs sharing a `name`, so a future change to
  # `var.name_prefix` will hit `DuplicateTargetGroup` at apply time.
  # `create_before_destroy = true` would NOT help here: CBD requires
  # the replacement to fit in the namespace, and the namespace
  # collision on `name` is exactly the constraint. Fix path at rename
  # time is a two-apply migration: taint the TG → detach attachments
  # manually → re-apply.
  lifecycle {
    # AWS hard-limits TG names at 32 chars. Today's sandbox/prod
    # values are well under (`nhp-{env}-ac-frps-ctl` ≈ 22-27 chars),
    # but a future regional `name_prefix` (e.g.
    # `nhp-prod-us-west-2`) would silently exceed and surface as a
    # cryptic AWS error at apply time. Fail at plan instead.
    precondition {
      condition     = length(local.ac_frps_control_tg_name) <= 32
      error_message = "aws_lb_target_group.ac_frps_control.name (`${local.ac_frps_control_tg_name}`, length=${length(local.ac_frps_control_tg_name)}) exceeds the 32-char AWS limit. Shorten var.name_prefix (current value: `${var.name_prefix}`) or accept the truncation in a follow-up rename."
    }
  }
}

resource "aws_lb_target_group" "ac_frps_control_additional" {
  for_each = var.frp_control_additional_upstreams

  name        = local.ac_frps_control_additional_tg_names[each.key]
  port        = each.value.listen_port
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  # Same contract scope as the primary FRPS-control TG above.
  preserve_client_ip = true

  # Same caveat as the primary `ac_frps_control` TG: `/ping` proves the
  # Traefik process is alive, not that this specific FRPS-control TCP
  # entrypoint parsed and bound. A real TCP health check would be blocked
  # by the NHP ipset gate unless allowlisted, which would defeat the gate.
  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = tostring(local.ac_health_check_port)
    path                = "/ping"
    matcher             = "200"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  # Mirrors the primary FRPS-control TG. These connections are long-lived
  # FRP yamux control sessions, so `connection_termination=true` would turn
  # every AC refresh into a synchronized re-knock/re-login storm.
  deregistration_delay = 30

  tags = var.tags

  # NOTE on TG-name renames: same fixed-name/two-apply migration caveat as
  # `ac_frps_control`. The provider's `name_prefix` is too short for a
  # descriptive identifier, and AWS rejects replacement TGs with duplicate
  # names during create-before-destroy.
  lifecycle {
    precondition {
      condition     = length(local.ac_frps_control_additional_tg_names[each.key]) <= 32
      error_message = "aws_lb_target_group.ac_frps_control_additional[${each.key}].name (`${local.ac_frps_control_additional_tg_names[each.key]}`, length=${length(local.ac_frps_control_additional_tg_names[each.key])}) exceeds the 32-char AWS limit. Shorten var.name_prefix or the additional-upstream key."
    }
  }
}

# TRANSITIONAL — see banner on the NLB listener above and nhp #2019.
# Removal of the AC from the FRPS data plane unwinds this attachment.
resource "aws_autoscaling_attachment" "ac_frps_control" {
  count = var.frp_control_upstream_host != "" ? 1 : 0

  autoscaling_group_name = aws_autoscaling_group.ac.name
  lb_target_group_arn    = aws_lb_target_group.ac_frps_control[0].arn
}

resource "aws_autoscaling_attachment" "ac_frps_control_additional" {
  for_each = var.frp_control_additional_upstreams

  autoscaling_group_name = aws_autoscaling_group.ac.name
  lb_target_group_arn    = aws_lb_target_group.ac_frps_control_additional[each.key].arn
}

resource "aws_lb_listener" "frps_control" {
  count = var.frp_control_upstream_host != "" ? 1 : 0

  load_balancer_arn = aws_lb.ac.arn
  port              = var.frp_control_port
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ac_frps_control[0].arn
  }

  tags = var.tags
}

resource "aws_lb_listener" "frps_control_additional" {
  for_each = var.frp_control_additional_upstreams

  # Rollout note: these public listeners and their NHP DDB rows can apply
  # before every existing AC instance has refreshed user_data and bound the
  # matching Traefik entrypoint. Standard clients knock the placement-neutral
  # qurl-tunnel-server resource; nhp-server selects one of these suffix rows
  # and returns its public host:port in the ACK.
  load_balancer_arn = aws_lb.ac.arn
  port              = each.value.listen_port
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ac_frps_control_additional[each.key].arn
  }

  tags = var.tags
}

# Route 53 record for AC (points to NLB when CloudFront is disabled)
# When CloudFront is enabled, the ac_cloudfront record takes precedence
resource "aws_route53_record" "ac" {
  count   = !var.skip_dns_records && !var.enable_cloudfront ? 1 : 0
  zone_id = local.resolved_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.ac.dns_name
    zone_id                = aws_lb.ac.zone_id
    evaluate_target_health = true
  }

  depends_on = [time_sleep.route53_record_change_iam_propagation]
}

# Wildcard record for tenant subdomains (points to CloudFront if enabled, otherwise NLB)
resource "aws_route53_record" "ac_wildcard" {
  count   = !var.skip_dns_records ? 1 : 0
  zone_id = local.resolved_zone_id
  name    = "*.${var.domain_name}"
  type    = "A"

  alias {
    name                   = var.enable_cloudfront ? aws_cloudfront_distribution.ac[0].domain_name : aws_lb.ac.dns_name
    zone_id                = var.enable_cloudfront ? aws_cloudfront_distribution.ac[0].hosted_zone_id : aws_lb.ac.zone_id
    evaluate_target_health = !var.enable_cloudfront
  }

  depends_on = [time_sleep.route53_record_change_iam_propagation]
}

# ==================== CloudFront + WAF ====================
# CloudFront provides edge caching and enables WAF protection
# WAF must be CLOUDFRONT scope and created in us-east-1

# ACM Certificate for CloudFront (must be in us-east-1)
resource "aws_acm_certificate" "cloudfront" {
  count                     = var.enable_cloudfront ? 1 : 0
  provider                  = aws.us_east_1
  domain_name               = var.domain_name
  subject_alternative_names = ["*.${var.domain_name}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = var.tags
}

resource "aws_route53_record" "cloudfront_cert_validation" {
  for_each = var.enable_cloudfront ? {
    for dvo in aws_acm_certificate.cloudfront[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = local.resolved_zone_id

  depends_on = [time_sleep.route53_record_change_iam_propagation]
}

resource "aws_acm_certificate_validation" "cloudfront" {
  count                   = var.enable_cloudfront ? 1 : 0
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.cloudfront[0].arn
  validation_record_fqdns = [for record in aws_route53_record.cloudfront_cert_validation : record.fqdn]
}

# WAF Web ACL for CloudFront (CLOUDFRONT scope, us-east-1)
resource "aws_wafv2_web_acl" "cloudfront" {
  count       = var.enable_cloudfront ? 1 : 0
  provider    = aws.us_east_1
  name        = "${var.name_prefix}-cf-waf"
  description = "WAF for CloudFront - AC module"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # Rate limiting
  rule {
    name     = "RateLimit"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = local.is_prod ? 5000 : 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - Common Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-common-rules"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - IP Reputation
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 4

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-cf-waf"
    sampled_requests_enabled   = true
  }

  tags = var.tags
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "ac" {
  count           = var.enable_cloudfront ? 1 : 0
  enabled         = true
  is_ipv6_enabled = true
  comment         = "CloudFront for ${var.name_prefix} AC"
  aliases         = [var.domain_name, "*.${var.domain_name}"]
  web_acl_id      = aws_wafv2_web_acl.cloudfront[0].arn
  price_class     = local.is_prod ? "PriceClass_All" : "PriceClass_100"

  origin {
    domain_name = aws_lb.ac.dns_name
    origin_id   = "nlb"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
      # Note: Origin certificate validation disabled since NLB doesn't have a matching cert
      # Security is maintained via VPC and security groups
    }
  }

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "nlb"

    forwarded_values {
      query_string = true
      headers      = ["*"]

      cookies {
        forward = "all"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0
    compress               = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.cloudfront[0].certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  tags = var.tags

  depends_on = [aws_acm_certificate_validation.cloudfront]
}

# Update Route 53 record to point to CloudFront when enabled
resource "aws_route53_record" "ac_cloudfront" {
  count   = var.enable_cloudfront ? 1 : 0
  zone_id = local.resolved_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.ac[0].domain_name
    zone_id                = aws_cloudfront_distribution.ac[0].hosted_zone_id
    evaluate_target_health = false
  }

  depends_on = [time_sleep.route53_record_change_iam_propagation]
}

# ==================== DynamoDB License Seeding ====================
# Seeds the AC's license in DynamoDB for cloud mode registration
# License keys are globally unique, so license_key_sha256 is the sole partition key

resource "aws_dynamodb_table_item" "ac_license" {
  count      = var.nhp_dynamodb_licenses_table != null && var.license_key_sha256 != "" ? 1 : 0
  table_name = var.nhp_dynamodb_licenses_table
  hash_key   = "license_key_sha256"

  item = jsonencode({
    license_key_sha256 = { S = var.license_key_sha256 }
    license_key_hash   = { S = var.license_key_hash }
    customer_id        = { S = var.customer_id } # Informational only
    resource_id        = { S = var.ac_id }
    tier               = { S = "system" }
    max_acs            = { N = "10" }
    expires_at         = { N = "0" }
    active             = { BOOL = true }
  })

  lifecycle {
    ignore_changes = [item]
  }
}

# ============================================================================
# Blue/green AC TCP target group drift detection
#
# The blue AC TCP target group (aws_lb_target_group.ac_tcp in main.tf) and
# the green AC TCP target group (aws_lb_target_group.ac_tcp_green in
# blue_green.tf) MUST have identical health-check + dereg semantics. They
# serve the same TLS-passthrough traffic from AC instances; any divergence
# means a blue/green swap will behave asymmetrically.
#
# Parallel to compute/main.tf::https_target_group_blue_green_drift —
# created here as part of the 2026-05-22 sandbox incident remediation, which
# added connection_termination=true on both colors and surfaced the
# comment-decay risk on a now-second cross-color "keep these in sync" pair.
# Health-check fields included for the same reason as the compute check
# (round-2 review of #252 caught a manual drift between blue/green via
# /health/live vs /health/knock-ready).
#
# Non-blocking warning — `terraform plan` shows the warning, the operator
# resolves it by aligning the blocks together (and updating the comment
# cross-references at both sites so the next reader knows it was deliberate).
# ============================================================================
check "ac_tcp_target_group_drift" {
  assert {
    condition = (
      !var.enable_blue_green ||
      length(aws_lb_target_group.ac_tcp_green) == 0 ||
      (
        aws_lb_target_group.ac_tcp.health_check[0].path == aws_lb_target_group.ac_tcp_green[0].health_check[0].path &&
        aws_lb_target_group.ac_tcp.health_check[0].port == aws_lb_target_group.ac_tcp_green[0].health_check[0].port &&
        aws_lb_target_group.ac_tcp.health_check[0].protocol == aws_lb_target_group.ac_tcp_green[0].health_check[0].protocol &&
        aws_lb_target_group.ac_tcp.health_check[0].matcher == aws_lb_target_group.ac_tcp_green[0].health_check[0].matcher &&
        aws_lb_target_group.ac_tcp.health_check[0].interval == aws_lb_target_group.ac_tcp_green[0].health_check[0].interval &&
        aws_lb_target_group.ac_tcp.health_check[0].timeout == aws_lb_target_group.ac_tcp_green[0].health_check[0].timeout &&
        aws_lb_target_group.ac_tcp.health_check[0].healthy_threshold == aws_lb_target_group.ac_tcp_green[0].health_check[0].healthy_threshold &&
        aws_lb_target_group.ac_tcp.health_check[0].unhealthy_threshold == aws_lb_target_group.ac_tcp_green[0].health_check[0].unhealthy_threshold
      )
    )
    error_message = "BLUE/GREEN AC HEALTH CHECK DRIFT: aws_lb_target_group.ac_tcp.health_check (main.tf) and aws_lb_target_group.ac_tcp_green.health_check (blue_green.tf) have diverged. Both target groups serve the same TLS-passthrough traffic and MUST have identical health check configurations or a blue/green swap will silently change health-check semantics. Diff the two health_check blocks and align them."
  }

  assert {
    condition = (
      !var.enable_blue_green ||
      length(aws_lb_target_group.ac_tcp_green) == 0 ||
      (
        # Terraform check assertions error on mismatched comparison types:
        # the provider exposes deregistration_delay as a string, so normalize
        # it before comparing to the numeric contract below.
        # The boolean attributes are explicitly set on both referenced target
        # groups; if a future refactor drops one, tobool(null) makes this
        # non-blocking check warn instead of silently weakening this transport
        # contract. CI's contract test is the hard gate.
        tobool(aws_lb_target_group.ac_tcp.connection_termination) &&
        tobool(aws_lb_target_group.ac_tcp_green[0].connection_termination) &&
        tobool(aws_lb_target_group.ac_tcp.preserve_client_ip) &&
        tobool(aws_lb_target_group.ac_tcp_green[0].preserve_client_ip) &&
        !tobool(aws_lb_target_group.ac_tcp.proxy_protocol_v2) &&
        !tobool(aws_lb_target_group.ac_tcp_green[0].proxy_protocol_v2) &&
        tonumber(aws_lb_target_group.ac_tcp.deregistration_delay) == 30 &&
        tonumber(aws_lb_target_group.ac_tcp_green[0].deregistration_delay) == 30
      )
    )
    error_message = "BLUE/GREEN AC TCP SEMANTICS VALUE-ANCHOR: aws_lb_target_group.ac_tcp and aws_lb_target_group.ac_tcp_green must both satisfy connection_termination=true, deregistration_delay=30, preserve_client_ip=true, and proxy_protocol_v2=false. The 2026-05-22 incident regresses if either color drops connection_termination=true; qURL v2 stalls before qurl-router if Proxy Protocol is reintroduced on top of NLB client-IP preservation. Edit both colors AND this assert in the same PR; comment cross-reference at blue_green.tf::ac_tcp_green carries the rationale."
  }
}
