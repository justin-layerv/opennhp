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
  runtime       = "nodejs20.x"
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

  # Validate that console_domain and console_backend_url are either both set or both null.
  # A mismatch would cause Traefik to create a router without a matching service (502 error).
  # This validation fails fast at plan time rather than silently misconfiguring Traefik.
  _console_routing_valid = (
    (var.console_domain == null && var.console_backend_url == null) ||
    (var.console_domain != null && var.console_backend_url != null)
  )
  # Use tobool() on a string to force a plan-time error with a custom message.
  # When valid, returns true; when invalid, tobool("error message") throws.
  _validate_console_routing = local._console_routing_valid ? true : tobool(
    "Console routing configuration error: console_domain and console_backend_url must both be set or both be null. This prevents Traefik from creating a router without a matching service (which causes 502 errors). Got: console_domain=${var.console_domain == null ? "null" : "\"${var.console_domain}\""}, console_backend_url=${var.console_backend_url == null ? "null" : "\"${var.console_backend_url}\""}"
  )
}

# Route 53 hosted zone lookup for DNS-01 challenge
data "aws_route53_zone" "main" {
  name         = "${var.hosted_zone}."
  private_zone = false
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

  # HTTPS - Traefik web proxy (NLB + direct access)
  # Protected by CloudFront + WAF when enable_cloudfront=true
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS - Traefik proxy (WAF protected via CloudFront)"
  }

  # HTTP - Traefik (redirect to HTTPS, ACME HTTP-01)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP - Traefik redirect/ACME"
  }

  # Portal service - INTENTIONALLY PUBLIC
  # This is the authentication entry point for the Zero Trust model.
  # Users must access the portal to initiate NHP authentication.
  ingress {
    from_port   = 8888
    to_port     = 8888
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Portal service (Zero Trust auth entry point)"
  }

  # NHP ConnectorClient - TCP - INTENTIONALLY PUBLIC
  # Clients connect here after completing NHP knock authentication.
  # Security is enforced by the NHP protocol, not network restrictions.
  ingress {
    from_port   = 4732
    to_port     = 4732
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "NHP ConnectorClient (protocol-secured)"
  }

  # NHP knock packets - UDP - INTENTIONALLY PUBLIC
  # Zero Trust: knock packets can come from anywhere.
  # Only authenticated knocks are processed by the NHP protocol.
  ingress {
    from_port   = 62206
    to_port     = 62206
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "NHP knock packets (protocol-secured)"
  }

  # SSH (for SSM, admin) - VPC only
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "SSH from VPC"
  }

  # Traefik health check endpoint - VPC only (for NLB health checks)
  # Traefik exposes /ping on port 8080 for health monitoring
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Traefik health check from VPC (NLB)"
  }

  # All outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound"
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-sg-ac"
    Component = "ac"
  })

  lifecycle {
    create_before_destroy = true
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
            [data.aws_route53_zone.main.arn, "arn:aws:route53:::change/*"],
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
        # CloudWatch Metrics (for disk monitoring)
        {
          Sid      = "CloudWatchMetrics"
          Effect   = "Allow"
          Action   = ["cloudwatch:PutMetricData"]
          Resource = "*"
          Condition = {
            StringEquals = {
              "cloudwatch:namespace" = "NHP/AC"
            }
          }
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
# Note: Depends on local._validate_console_routing to force validation before template rendering
locals {
  user_data = local._validate_console_routing ? templatefile("${path.module}/user_data.sh.tpl", {
    region              = local.region
    account_id          = local.account_id
    ac_repo_url         = var.ac_repo_url
    environment         = var.environment
    domain_name         = var.domain_name
    acme_email          = var.acme_email
    acme_ca_server      = coalesce(var.use_production_acme, local.is_prod) ? "https://acme-v02.api.letsencrypt.org/directory" : "https://acme-staging-v02.api.letsencrypt.org/directory"
    cloudmap_service_id = aws_service_discovery_service.ac.id
    namespace_name      = var.namespace_name
    vpc_cidr            = var.vpc_cidr
    # Per-instance key generation
    name_prefix         = var.name_prefix
    secrets_kms_key_arn = var.secrets_kms_key_arn != null ? var.secrets_kms_key_arn : ""
    # AC configuration options
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
    image_tag = var.image_tag
    # Console backend routing (for NHP-protected Console)
    console_backend_url = var.console_backend_url
    console_domain      = var.console_domain
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
    qurl_service_token_secret_arn  = var.qurl_service_token_secret_arn
  }) : null # Validation failed - this branch never executes (tobool throws first)
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

  # Gzip compress user data to stay under 16KB limit (AWS auto-decompresses)
  user_data = base64gzip(local.user_data)

  monitoring {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
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
  }
}

# Auto Scaling Group - in PUBLIC subnets for direct access
resource "aws_autoscaling_group" "ac" {
  name                = "${var.name_prefix}-ac"
  vpc_zone_identifier = var.public_subnet_ids
  min_size            = local.is_prod ? 2 : 1
  max_size            = local.is_prod ? 6 : 3
  desired_capacity    = local.is_prod ? 2 : 1

  launch_template {
    id      = aws_launch_template.ac.id
    version = "$Latest"
  }

  health_check_type         = "EC2"
  health_check_grace_period = 180 # Reduced from 300s - AC startup is typically ~90-120s

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
      instance_warmup        = 180 # Reduced from 300s - aligns with health_check_grace_period
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-ac"
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
  }
}

# Network Load Balancer for HTTPS traffic
resource "aws_lb" "ac" {
  name               = replace("${var.name_prefix}-ac-nlb", "_", "-")
  internal           = false
  load_balancer_type = "network"
  subnets            = var.public_subnet_ids

  enable_cross_zone_load_balancing = true

  tags = var.tags
}

# HTTPS Target Group (TCP passthrough to Traefik)
# Proxy Protocol v2 enabled to preserve client IP for NHP firewall rules
resource "aws_lb_target_group" "https" {
  name              = replace("${var.name_prefix}-ac-https", "_", "-")
  port              = 443
  protocol          = "TCP"
  vpc_id            = var.vpc_id
  target_type       = "instance"
  proxy_protocol_v2 = true

  # HTTP health check on Traefik's ping endpoint
  # Verifies Traefik is running and can respond to requests
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
  lb_target_group_arn    = aws_lb_target_group.https.arn
}

# HTTPS Listener (TLS passthrough - Traefik handles TLS)
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.ac.arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.https.arn
  }

  tags = var.tags
}

# Route 53 record for AC (points to NLB when CloudFront is disabled)
# When CloudFront is enabled, the ac_cloudfront record takes precedence
resource "aws_route53_record" "ac" {
  count   = var.enable_cloudfront ? 0 : 1
  zone_id = data.aws_route53_zone.main.zone_id
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
  zone_id = data.aws_route53_zone.main.zone_id
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
  zone_id         = data.aws_route53_zone.main.zone_id
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
  zone_id = data.aws_route53_zone.main.zone_id
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
  count      = var.nhp_dynamodb_licenses_table != null ? 1 : 0
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
