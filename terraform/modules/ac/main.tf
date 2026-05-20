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
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 6.27"
      configuration_aliases = [aws.us_east_1]
    }
  }
}

# ==================== Data Sources ====================

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

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

# Ubuntu 24.04 LTS (Noble Numbat) - latest LTS with updated python3-cryptography
data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/noble/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

# ==================== Locals ====================

locals {
  is_prod    = var.environment == "prod"
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.id

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

# Traefik health check endpoint - VPC only (for NLB health checks)
# Port 8080 is Traefik's dashboard/ping entrypoint
resource "aws_vpc_security_group_ingress_rule" "ac_traefik_health" {
  security_group_id = aws_security_group.ac.id
  description       = "Traefik health check from VPC (NLB)"
  from_port         = 8080
  to_port           = 8080
  ip_protocol       = "tcp"
  cidr_ipv4         = var.vpc_cidr

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
        # Route 53 permissions required for Cloud Map DNS integration with custom health checks
        {
          Sid    = "Route53HealthCheck"
          Effect = "Allow"
          Action = [
            "route53:CreateHealthCheck",
            "route53:DeleteHealthCheck",
            "route53:UpdateHealthCheck",
            "route53:GetHealthCheck"
          ]
          Resource = "*"
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
    # Per-instance key generation
    name_prefix         = var.name_prefix
    secrets_kms_key_arn = var.secrets_kms_key_arn != null ? var.secrets_kms_key_arn : ""
    # AC configuration options
    log_level         = var.log_level
    ac_id             = var.ac_id
    auth_service_id   = var.auth_service_id
    resource_ids      = jsonencode(var.resource_ids)
    server_secret_arn = var.server_secret_arn
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
    qurl_service_token_secret_arn              = var.qurl_service_token_secret_arn
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
    frp_server_host           = var.frp_server_host
    frp_control_port          = var.frp_control_port
    frp_vhost_http_port       = var.frp_vhost_http_port
    frp_control_upstream_host = var.frp_control_upstream_host
  })
}

# Plan-time render lint for the FRPS-behind-AC Traefik bits. The TG
# healthcheck for `ac_frps_control` probes Traefik's `/ping` on :8080,
# which confirms the Traefik PROCESS is alive but says nothing about
# whether the `entryPoints.frps-control` listener on the customer-
# facing port actually bound or whether `frps-control.toml` parsed
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
  count = var.frp_control_upstream_host != "" ? 1 : 0

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
        strcontains(local.user_data, "[entryPoints.frps-control]") &&
        strcontains(local.user_data, "[tcp.routers.frps-control]") &&
        strcontains(local.user_data, "-A INPUT -m set --match-set defaultset src,dst,dst -j ACCEPT")
      )
      error_message = "AC user_data render is missing one of `[entryPoints.frps-control]`, `[tcp.routers.frps-control]`, or the `-A INPUT -m set --match-set defaultset src,dst,dst -j ACCEPT` iptables rule despite frp_control_upstream_host being set. A templatefile-condition regression in `user_data.sh.tpl` would silently produce this. The TG `/ping` healthcheck wouldn't catch any of them — see lifecycle comment on aws_lb_target_group.ac_frps_control."
    }
  }
}

# Launch Template
resource "aws_launch_template" "ac" {
  name_prefix   = "${var.name_prefix}-ac-"
  image_id      = data.aws_ssm_parameter.ubuntu_ami.value
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
  # This bootstrap installs AWS CLI, downloads the init script, and execs it.
  # An md5 of the rendered local.user_data is embedded so a content change
  # forces a launch template version bump (and thus an instance refresh on
  # the next deploy). See the in-heredoc comment for why md5(local.user_data)
  # instead of the S3 object's etag.
  # Keep in sync with modules/compute/main.tf::aws_launch_template.server.
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
  command -v aws &>/dev/null && aws cloudwatch put-metric-data \
    --namespace "LayerV/NHP" \
    --metric-name "BootstrapFailure" \
    --value 1 --unit Count \
    --dimensions "Component=ac,Environment=${var.environment}" \
    --region "$REGION" 2>/dev/null || true
}
trap 'report_failure "unexpected error on line $LINENO"' ERR
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
apt_get_with_retry() { retry_with_backoff 10 2 60 apt-get "$@"; }
# Install unzip (not present on Ubuntu 24.04 minimal AMI)
export DEBIAN_FRONTEND=noninteractive
apt_get_with_retry update -y
apt_get_with_retry install -y unzip
# Install AWS CLI v2
curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
unzip -qo /tmp/awscliv2.zip -d /tmp && /tmp/aws/install --update
rm -rf /tmp/awscliv2.zip /tmp/aws
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
    ignore_changes = [desired_capacity, min_size]
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

# TCP Target Group (TLS passthrough to Traefik)
# Proxy Protocol v2 enabled to preserve client IP for NHP firewall rules
resource "aws_lb_target_group" "ac_tcp" {
  name              = replace("${var.name_prefix}-ac-tcp", "_", "-")
  port              = 443
  protocol          = "TCP"
  vpc_id            = var.vpc_id
  target_type       = "instance"
  proxy_protocol_v2 = true

  # HTTP health check on Traefik's ping endpoint (port 8080)
  # Port 443 is blocked by default for NHP port hiding - only opened after knock
  # Port 8080 is allowed from VPC CIDR for health checks
  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "8080"
    path                = "/ping"
    matcher             = "200"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay = 30

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
# ingress that the FRPS resource.toml overlay's `Hostname` field resolves to;
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
#   - `ac_tcp` healthchecks on Traefik's port 8080 `/ping` — appropriate
#     for the HTTPS entrypoint. The FRPS control entrypoint uses the same
#     Traefik process and the same `/ping` is fine; the new TG exists
#     because the listener-to-TG binding is 1:1 and the listener targets
#     a different port.
#   - Proxy Protocol v2 is intentionally OFF here (the FRP control channel
#     doesn't speak PP, and the Traefik TCP entrypoint would need
#     `proxyProtocol` awareness to accept it). Preserving client IP for
#     the ipset fence is handled by the NLB's default mode (no PP), which
#     forwards client IP at L4 — AC instance sees `agent_ip → ac_local_ip:port`.
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

  # Healthcheck caveat: Traefik `/ping` on 8080 confirms the Traefik
  # process is alive but does NOT verify the `entryPoints.frps-control`
  # listener on `:${var.frp_control_port}` actually bound or that
  # `frps-control.toml` parsed and installed the TCP router. A drift
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
    port                = "8080"
    path                = "/ping"
    matcher             = "200"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay = 30

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

# TRANSITIONAL — see banner on the NLB listener above and nhp #2019.
# Removal of the AC from the FRPS data plane unwinds this attachment.
resource "aws_autoscaling_attachment" "ac_frps_control" {
  count = var.frp_control_upstream_host != "" ? 1 : 0

  autoscaling_group_name = aws_autoscaling_group.ac.name
  lb_target_group_arn    = aws_lb_target_group.ac_frps_control[0].arn
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
