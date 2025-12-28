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
      version               = "~> 5.0"
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
  region     = data.aws_region.current.name
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

  # SSH (for SSM, health checks, admin) - VPC only
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "SSH from VPC"
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

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
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
      # Secrets Manager - read shared secrets (etcd TLS, server public key)
      {
        Sid      = "SecretsReadShared"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = compact([var.etcd_tls_secret_arn, var.server_secret_arn])
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
      # KMS for Secrets Manager (encrypt for create, decrypt for read)
      {
        Sid      = "KMSForSecrets"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
        Resource = var.secrets_kms_key_arn != null ? [var.secrets_kms_key_arn] : []
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
      # Note: S3 plugin access is now handled via plugin_download_policy_arn
      # from the plugins module (attached separately below)
    ]
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

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = var.tags
}

# User data script
locals {
  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    region              = local.region
    account_id          = local.account_id
    ac_repo_url         = var.ac_repo_url
    environment         = var.environment
    domain_name         = var.domain_name
    acme_email          = var.acme_email
    acme_ca_server      = local.is_prod ? "https://acme-v02.api.letsencrypt.org/directory" : "https://acme-staging-v02.api.letsencrypt.org/directory"
    etcd_endpoint       = var.etcd_endpoint
    etcd_tls_secret_arn = var.etcd_tls_secret_arn
    cloudmap_service_id = aws_service_discovery_service.ac.id
    namespace_name      = var.namespace_name
    vpc_cidr            = var.vpc_cidr
    # Per-instance key generation
    name_prefix         = var.name_prefix
    secrets_kms_key_arn = var.secrets_kms_key_arn != null ? var.secrets_kms_key_arn : ""
    # AC configuration options
    auth_service_id   = var.auth_service_id
    resource_ids      = jsonencode(var.resource_ids)
    server_nlb_dns    = var.server_nlb_dns
    server_secret_arn = var.server_secret_arn
    # Production domains (cross-account ACME)
    cross_account_route53_role_arn = var.cross_account_route53_role_arn
    production_domains             = var.production_domains
    # Traefik plugins (from unified plugins module)
    plugin_bucket_name = var.plugin_bucket_name
    traefik_plugins    = var.traefik_plugins
    # Deployment configuration
    image_tag = var.image_tag
  })
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
  health_check_grace_period = 300

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
      instance_warmup        = 300
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

  health_check {
    enabled             = true
    protocol            = "TCP"
    port                = "22"
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

# ==================== Per-AC Key Infrastructure ====================
# This section implements per-instance AC keys with AWS Instance Identity
# verification. Each AC generates its own keypair and registers with etcd.
#
# Components:
# 1. etcd config seeder - writes /nhp/config (server peers, no private keys)
# 2. AC cleanup Lambda - removes registry entries on termination
# 3. ASG lifecycle hook - triggers cleanup on instance termination
# 4. Security group for Lambda VPC access

# Security group for Lambdas that need etcd access
resource "aws_security_group" "lambda_etcd" {
  count       = var.etcd_endpoint != null ? 1 : 0
  name_prefix = "${var.name_prefix}-lambda-etcd-"
  vpc_id      = var.vpc_id
  description = "Security group for Lambdas accessing etcd"

  # etcd client port outbound
  egress {
    from_port   = 2379
    to_port     = 2379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "etcd client port"
  }

  # HTTPS for AWS APIs
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS for AWS APIs"
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-sg-lambda-etcd"
    Component = "ac"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# ==================== etcd Config Seeder ====================
# Seeds /nhp/config with server peers and HTTP config (no private keys)

resource "aws_iam_role" "etcd_seeder" {
  count = var.etcd_endpoint != null ? 1 : 0
  name  = "${var.name_prefix}-etcd-seeder"

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

resource "aws_iam_role_policy_attachment" "etcd_seeder_basic" {
  count      = var.etcd_endpoint != null ? 1 : 0
  role       = aws_iam_role.etcd_seeder[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "etcd_seeder_vpc" {
  count      = var.etcd_endpoint != null ? 1 : 0
  role       = aws_iam_role.etcd_seeder[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "etcd_seeder" {
  count = var.etcd_endpoint != null ? 1 : 0
  name  = "etcd-seeder"
  role  = aws_iam_role.etcd_seeder[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = compact([
          var.etcd_tls_secret_arn,
          var.server_secret_arn
        ])
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.secrets_kms_key_arn != null ? [var.secrets_kms_key_arn] : []
      }
    ]
  })
}

data "archive_file" "etcd_seeder" {
  count       = var.etcd_endpoint != null ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/etcd_seeder.zip"

  source {
    content  = <<-PYTHON
import json
import os
import ssl
import tempfile
import urllib.request
import urllib.error
import base64
import boto3

def handler(event, context):
    """
    Seeds etcd with NHP config (server peers, HTTP config).
    Does NOT write any private keys to etcd.
    """
    print(f"etcd seeder event: {json.dumps(event)}")

    if event.get('RequestType') == 'Delete':
        return {'PhysicalResourceId': event.get('PhysicalResourceId', 'etcd-config')}

    props = event.get('ResourceProperties', event)
    etcd_endpoint = props['EtcdEndpoint']
    tls_secret_arn = props['TlsSecretArn']
    server_secret_arn = props.get('ServerSecretArn', '')
    server_nlb_dns = props.get('ServerNlbDns', '')
    auth_service_id = props.get('AuthServiceId', 'layerv')
    resource_ids = props.get('ResourceIds', ['default'])
    environment = props.get('Environment', 'sandbox')

    secrets = boto3.client('secretsmanager')

    # Get TLS certs
    tls_secret = json.loads(secrets.get_secret_value(SecretId=tls_secret_arn)['SecretString'])
    ca_cert = tls_secret['caCert']
    client_cert = tls_secret['clientCert']
    client_key = tls_secret['clientKey']

    # Get server public key
    server_public_key = ''
    if server_secret_arn:
        try:
            server_secret = json.loads(secrets.get_secret_value(SecretId=server_secret_arn)['SecretString'])
            server_public_key = server_secret.get('publicKey', '')
        except Exception as e:
            print(f"Warning: Could not get server public key: {e}")

    # Build TOML config (no private keys!)
    config_toml = f'''# NHP AC Configuration (seeded by Terraform)
# This config is read by ACs on startup.
# Private keys are stored in per-instance Secrets Manager secrets.

[HttpConfig]
EnableHttp = true
EnableTLS = false
HttpListenPort = 8888

# Server peers - ACs dial OUT to these servers
[[Servers]]
Hostname = "{server_nlb_dns}"
Ip = ""
Port = 62206
PubKeyBase64 = "{server_public_key}"
ExpireTime = 1924991999
'''

    # Write to etcd using HTTPS API
    # etcd v3 uses gRPC, but also exposes a JSON gateway
    # For simplicity, we use the etcdctl approach via subprocess or direct API

    # Create temp files for TLS
    with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
        f.write(ca_cert)
        ca_path = f.name
    with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
        f.write(client_cert)
        cert_path = f.name
    with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as f:
        f.write(client_key)
        key_path = f.name

    try:
        # Create SSL context with client cert
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_context.load_verify_locations(ca_path)
        ssl_context.load_cert_chain(cert_path, key_path)

        # etcd v3 JSON gateway for PUT
        # PUT /v3/kv/put with JSON body
        url = f"{etcd_endpoint}/v3/kv/put"

        # etcd v3 API expects base64-encoded key and value
        key_b64 = base64.b64encode(b'/nhp/config').decode()
        value_b64 = base64.b64encode(config_toml.encode()).decode()

        data = json.dumps({
            'key': key_b64,
            'value': value_b64
        }).encode()

        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')

        with urllib.request.urlopen(req, context=ssl_context, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            print(f"etcd put result: {result}")

        print("Successfully seeded /nhp/config in etcd")

    finally:
        # Cleanup temp files
        import os
        os.unlink(ca_path)
        os.unlink(cert_path)
        os.unlink(key_path)

    return {'PhysicalResourceId': event.get('PhysicalResourceId', 'etcd-config')}
PYTHON
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "etcd_seeder" {
  count            = var.etcd_endpoint != null ? 1 : 0
  function_name    = "${var.name_prefix}-etcd-seeder"
  role             = aws_iam_role.etcd_seeder[0].arn
  handler          = "lambda_function.handler"
  runtime          = "python3.11"
  timeout          = 60
  filename         = data.archive_file.etcd_seeder[0].output_path
  source_code_hash = data.archive_file.etcd_seeder[0].output_base64sha256

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda_etcd[0].id]
  }

  tags = var.tags
}

resource "aws_lambda_invocation" "etcd_seeder" {
  count         = var.etcd_endpoint != null ? 1 : 0
  function_name = aws_lambda_function.etcd_seeder[0].function_name

  input = jsonencode({
    RequestType = "Create"
    ResourceProperties = {
      EtcdEndpoint    = var.etcd_endpoint
      TlsSecretArn    = var.etcd_tls_secret_arn
      ServerSecretArn = var.server_secret_arn
      ServerNlbDns    = var.server_nlb_dns
      AuthServiceId   = var.auth_service_id
      ResourceIds     = var.resource_ids
      Environment     = var.environment
    }
  })

  triggers = {
    # Re-seed when config changes
    server_nlb_dns  = var.server_nlb_dns
    auth_service_id = var.auth_service_id
    resource_ids    = jsonencode(var.resource_ids)
  }

  depends_on = [aws_iam_role_policy.etcd_seeder]
}

# ==================== AC Cleanup Lambda ====================
# Cleans up AC registry entries and secrets on instance termination

resource "aws_iam_role" "ac_cleanup" {
  count = var.etcd_endpoint != null ? 1 : 0
  name  = "${var.name_prefix}-ac-cleanup"

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

resource "aws_iam_role_policy_attachment" "ac_cleanup_basic" {
  count      = var.etcd_endpoint != null ? 1 : 0
  role       = aws_iam_role.ac_cleanup[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "ac_cleanup_vpc" {
  count      = var.etcd_endpoint != null ? 1 : 0
  role       = aws_iam_role.ac_cleanup[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "ac_cleanup" {
  count = var.etcd_endpoint != null ? 1 : 0
  name  = "ac-cleanup"
  role  = aws_iam_role.ac_cleanup[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [var.etcd_tls_secret_arn]
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:DeleteSecret"]
        Resource = "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:${var.name_prefix}-ac-i-*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.secrets_kms_key_arn != null ? [var.secrets_kms_key_arn] : []
      },
      {
        Effect   = "Allow"
        Action   = ["autoscaling:CompleteLifecycleAction"]
        Resource = aws_autoscaling_group.ac.arn
      },
      {
        # Required by audit Lambda to compare registry against running instances
        Effect   = "Allow"
        Action   = ["ec2:DescribeInstances"]
        Resource = "*"
      }
    ]
  })
}

data "archive_file" "ac_cleanup" {
  count       = var.etcd_endpoint != null ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/ac_cleanup.zip"

  source {
    content  = <<-PYTHON
import json
import os
import ssl
import tempfile
import urllib.request
import base64
import boto3

def handler(event, context):
    """
    Cleans up AC registry entry and secrets when instance terminates.
    Triggered by ASG lifecycle hook via SNS.
    """
    print(f"AC cleanup event: {json.dumps(event)}")

    secrets = boto3.client('secretsmanager')
    autoscaling = boto3.client('autoscaling')

    # Parse SNS message
    for record in event.get('Records', []):
        message = json.loads(record['Sns']['Message'])

        lifecycle_hook = message.get('LifecycleHookName')
        asg_name = message.get('AutoScalingGroupName')
        instance_id = message.get('EC2InstanceId')
        lifecycle_token = message.get('LifecycleActionToken')

        if not instance_id:
            print("No instance ID in message, skipping")
            continue

        print(f"Cleaning up instance: {instance_id}")

        # Get etcd TLS certs
        tls_secret_arn = os.environ['TLS_SECRET_ARN']
        etcd_endpoint = os.environ['ETCD_ENDPOINT']
        name_prefix = os.environ['NAME_PREFIX']

        try:
            tls_secret = json.loads(secrets.get_secret_value(SecretId=tls_secret_arn)['SecretString'])
            ca_cert = tls_secret['caCert']
            client_cert = tls_secret['clientCert']
            client_key = tls_secret['clientKey']

            # Create temp files for TLS
            with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
                f.write(ca_cert)
                ca_path = f.name
            with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
                f.write(client_cert)
                cert_path = f.name
            with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as f:
                f.write(client_key)
                key_path = f.name

            # Create SSL context
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ssl_context.load_verify_locations(ca_path)
            ssl_context.load_cert_chain(cert_path, key_path)

            # Delete from etcd registry
            url = f"{etcd_endpoint}/v3/kv/deleterange"
            key = f"/nhp/ac-registry/{instance_id}"
            key_b64 = base64.b64encode(key.encode()).decode()

            data = json.dumps({
                'key': key_b64
            }).encode()

            req = urllib.request.Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/json')

            try:
                with urllib.request.urlopen(req, context=ssl_context, timeout=30) as resp:
                    result = json.loads(resp.read().decode())
                    print(f"etcd delete result: {result}")
            except Exception as e:
                print(f"Warning: Failed to delete etcd entry: {e}")

            # Cleanup temp files
            os.unlink(ca_path)
            os.unlink(cert_path)
            os.unlink(key_path)

        except Exception as e:
            print(f"Warning: etcd cleanup failed: {e}")

        # Delete Secrets Manager secret
        secret_name = f"{name_prefix}-ac-{instance_id}"
        try:
            secrets.delete_secret(
                SecretId=secret_name,
                ForceDeleteWithoutRecovery=True
            )
            print(f"Deleted secret: {secret_name}")
        except secrets.exceptions.ResourceNotFoundException:
            print(f"Secret not found (already deleted?): {secret_name}")
        except Exception as e:
            print(f"Warning: Failed to delete secret: {e}")

        # Complete lifecycle action
        if lifecycle_hook and asg_name and lifecycle_token:
            try:
                autoscaling.complete_lifecycle_action(
                    LifecycleHookName=lifecycle_hook,
                    AutoScalingGroupName=asg_name,
                    LifecycleActionToken=lifecycle_token,
                    LifecycleActionResult='CONTINUE'
                )
                print(f"Completed lifecycle action for {instance_id}")
            except Exception as e:
                print(f"Warning: Failed to complete lifecycle action: {e}")

    return {'statusCode': 200}
PYTHON
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "ac_cleanup" {
  count            = var.etcd_endpoint != null ? 1 : 0
  function_name    = "${var.name_prefix}-ac-cleanup"
  role             = aws_iam_role.ac_cleanup[0].arn
  handler          = "lambda_function.handler"
  runtime          = "python3.11"
  timeout          = 120
  filename         = data.archive_file.ac_cleanup[0].output_path
  source_code_hash = data.archive_file.ac_cleanup[0].output_base64sha256

  environment {
    variables = {
      TLS_SECRET_ARN = var.etcd_tls_secret_arn
      ETCD_ENDPOINT  = var.etcd_endpoint
      NAME_PREFIX    = var.name_prefix
    }
  }

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda_etcd[0].id]
  }

  tags = var.tags
}

# SNS topic for lifecycle hook
resource "aws_sns_topic" "ac_lifecycle" {
  count = var.etcd_endpoint != null ? 1 : 0
  name  = "${var.name_prefix}-ac-lifecycle"

  tags = var.tags
}

resource "aws_sns_topic_subscription" "ac_cleanup" {
  count     = var.etcd_endpoint != null ? 1 : 0
  topic_arn = aws_sns_topic.ac_lifecycle[0].arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.ac_cleanup[0].arn
}

resource "aws_lambda_permission" "ac_cleanup_sns" {
  count         = var.etcd_endpoint != null ? 1 : 0
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ac_cleanup[0].function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.ac_lifecycle[0].arn
}

# IAM role for ASG lifecycle hook to publish to SNS
resource "aws_iam_role" "asg_lifecycle" {
  count = var.etcd_endpoint != null ? 1 : 0
  name  = "${var.name_prefix}-asg-lifecycle"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "autoscaling.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "asg_lifecycle" {
  count = var.etcd_endpoint != null ? 1 : 0
  name  = "sns-publish"
  role  = aws_iam_role.asg_lifecycle[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sns:Publish"
      Resource = aws_sns_topic.ac_lifecycle[0].arn
    }]
  })
}

# ASG lifecycle hook for instance termination
resource "aws_autoscaling_lifecycle_hook" "ac_termination" {
  count                  = var.etcd_endpoint != null ? 1 : 0
  name                   = "${var.name_prefix}-ac-termination"
  autoscaling_group_name = aws_autoscaling_group.ac.name
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
  default_result         = "CONTINUE"
  heartbeat_timeout      = 300

  notification_target_arn = aws_sns_topic.ac_lifecycle[0].arn
  role_arn                = aws_iam_role.asg_lifecycle[0].arn
}

# ==================== Weekly Audit Lambda ====================
# Cleans up orphaned AC registry entries and secrets where the instance no longer exists

data "archive_file" "ac_audit" {
  count       = var.etcd_endpoint != null ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/.terraform/ac_audit.zip"

  source {
    content  = <<-PYTHON
import json
import boto3
import ssl
import tempfile
import urllib.request
import base64
import os

def handler(event, context):
    """
    Weekly audit to clean up orphaned AC registry entries and secrets.
    Compares etcd registry entries with running EC2 instances.
    """
    print("Starting AC registry audit")

    # Get configuration from environment
    etcd_endpoint = os.environ['ETCD_ENDPOINT']
    tls_secret_arn = os.environ['TLS_SECRET_ARN']
    name_prefix = os.environ['NAME_PREFIX']
    region = os.environ.get('AWS_REGION', 'us-east-2')

    secrets = boto3.client('secretsmanager')
    ec2 = boto3.client('ec2')

    # Get TLS certs
    tls_secret = json.loads(secrets.get_secret_value(SecretId=tls_secret_arn)['SecretString'])
    ca_cert = tls_secret['caCert']
    client_cert = tls_secret['clientCert']
    client_key = tls_secret['clientKey']

    # Create temp files for TLS
    with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
        f.write(ca_cert)
        ca_path = f.name
    with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
        f.write(client_cert)
        cert_path = f.name
    with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as f:
        f.write(client_key)
        key_path = f.name

    try:
        # Create SSL context
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_context.load_verify_locations(ca_path)
        ssl_context.load_cert_chain(cert_path, key_path)

        # Get all AC registry entries from etcd
        url = f"{etcd_endpoint}/v3/kv/range"
        prefix = "/nhp/ac-registry/"
        prefix_b64 = base64.b64encode(prefix.encode()).decode()
        # Range end is prefix with last byte incremented
        range_end = prefix[:-1] + chr(ord(prefix[-1]) + 1)
        range_end_b64 = base64.b64encode(range_end.encode()).decode()

        data = json.dumps({
            'key': prefix_b64,
            'range_end': range_end_b64
        }).encode()

        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')

        registry_entries = {}
        with urllib.request.urlopen(req, context=ssl_context, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            for kv in result.get('kvs', []):
                key = base64.b64decode(kv['key']).decode()
                instance_id = key.replace(prefix, '')
                registry_entries[instance_id] = key

        print(f"Found {len(registry_entries)} registry entries")

        if not registry_entries:
            print("No registry entries to audit")
            return {'orphans_cleaned': 0}

        # Get running instances with our name prefix
        response = ec2.describe_instances(
            Filters=[
                {'Name': 'instance-state-name', 'Values': ['running', 'pending']},
                {'Name': 'tag:Name', 'Values': [f'{name_prefix}*']}
            ]
        )

        running_instances = set()
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                running_instances.add(instance['InstanceId'])

        print(f"Found {len(running_instances)} running instances")

        # Find orphaned entries (in registry but not running)
        orphaned = set(registry_entries.keys()) - running_instances
        print(f"Found {len(orphaned)} orphaned entries")

        # Clean up orphaned entries
        cleaned = 0
        for instance_id in orphaned:
            print(f"Cleaning up orphaned entry: {instance_id}")

            # Delete from etcd
            key = registry_entries[instance_id]
            key_b64 = base64.b64encode(key.encode()).decode()
            delete_url = f"{etcd_endpoint}/v3/kv/deleterange"
            delete_data = json.dumps({'key': key_b64}).encode()
            delete_req = urllib.request.Request(delete_url, data=delete_data, method='POST')
            delete_req.add_header('Content-Type', 'application/json')

            try:
                with urllib.request.urlopen(delete_req, context=ssl_context, timeout=30) as resp:
                    print(f"Deleted etcd entry for {instance_id}")
            except Exception as e:
                print(f"Failed to delete etcd entry for {instance_id}: {e}")

            # Delete secret
            secret_name = f"{name_prefix}-ac-{instance_id}"
            try:
                secrets.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
                print(f"Deleted secret for {instance_id}")
            except secrets.exceptions.ResourceNotFoundException:
                print(f"Secret not found for {instance_id} (already deleted)")
            except Exception as e:
                print(f"Failed to delete secret for {instance_id}: {e}")

            cleaned += 1

        print(f"Audit complete: cleaned {cleaned} orphaned entries")
        return {'orphans_cleaned': cleaned}

    finally:
        # Cleanup temp files
        os.unlink(ca_path)
        os.unlink(cert_path)
        os.unlink(key_path)
PYTHON
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "ac_audit" {
  count            = var.etcd_endpoint != null ? 1 : 0
  function_name    = "${var.name_prefix}-ac-audit"
  role             = aws_iam_role.ac_cleanup[0].arn # Reuse cleanup role
  handler          = "lambda_function.handler"
  runtime          = "python3.11"
  timeout          = 300
  filename         = data.archive_file.ac_audit[0].output_path
  source_code_hash = data.archive_file.ac_audit[0].output_base64sha256

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda_etcd[0].id]
  }

  environment {
    variables = {
      ETCD_ENDPOINT  = var.etcd_endpoint
      TLS_SECRET_ARN = var.etcd_tls_secret_arn
      NAME_PREFIX    = var.name_prefix
    }
  }

  tags = var.tags
}

# CloudWatch Event Rule for weekly audit (every Sunday at 3 AM UTC)
resource "aws_cloudwatch_event_rule" "ac_audit_schedule" {
  count               = var.etcd_endpoint != null ? 1 : 0
  name                = "${var.name_prefix}-ac-audit-schedule"
  description         = "Weekly AC registry audit"
  schedule_expression = "cron(0 3 ? * SUN *)"

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "ac_audit" {
  count     = var.etcd_endpoint != null ? 1 : 0
  rule      = aws_cloudwatch_event_rule.ac_audit_schedule[0].name
  target_id = "ac-audit-lambda"
  arn       = aws_lambda_function.ac_audit[0].arn
}

resource "aws_lambda_permission" "ac_audit_cloudwatch" {
  count         = var.etcd_endpoint != null ? 1 : 0
  statement_id  = "AllowCloudWatchInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ac_audit[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ac_audit_schedule[0].arn
}
