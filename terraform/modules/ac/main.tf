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
    content = <<-EOF
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

data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
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
    Name = "${var.name_prefix}-ac"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "ac" {
  name              = "/layerv/nhp-ac/${var.environment}"
  retention_in_days = local.is_prod ? 365 : 30
  kms_key_id        = var.logs_kms_key_arn

  tags = var.tags
}

# ==================== S3 Bucket for Traefik Plugins ====================
# This bucket stores Traefik plugins that are deployed by the traefik-plugins repo.
# AC instances fetch plugins from this bucket on boot, ensuring new instances
# have plugins immediately available (not just via SSM to running instances).

resource "aws_s3_bucket" "plugins" {
  bucket = "${var.name_prefix}-traefik-plugins"

  tags = merge(var.tags, {
    Purpose = "Traefik plugins storage"
  })
}

resource "aws_s3_bucket_versioning" "plugins" {
  bucket = aws_s3_bucket.plugins.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "plugins" {
  bucket = aws_s3_bucket.plugins.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "plugins" {
  bucket = aws_s3_bucket.plugins.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

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
      # Secrets Manager for AC private key, etcd credentials, and TLS certificates
      {
        Sid      = "SecretsAccess"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = compact([aws_secretsmanager_secret.ac.arn, var.etcd_secret_arn, var.etcd_tls_secret_arn])
      },
      # KMS decrypt for Secrets Manager (secrets are KMS-encrypted)
      {
        Sid      = "KMSDecrypt"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
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
      # S3 access for Traefik plugins
      # AC instances fetch plugins from S3 on boot
      {
        Sid    = "PluginBucketRead"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.plugins.arn,
          "${aws_s3_bucket.plugins.arn}/*"
        ]
      }
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
    ac_secret_arn       = aws_secretsmanager_secret.ac.arn
    cloudmap_service_id = aws_service_discovery_service.ac.id
    namespace_name      = var.namespace_name
    vpc_cidr            = var.vpc_cidr
    # AC configuration options
    auth_service_id = var.auth_service_id
    resource_ids    = jsonencode(var.resource_ids)
    server_nlb_dns  = var.server_nlb_dns
    # Production domains (cross-account ACME)
    cross_account_route53_role_arn = var.cross_account_route53_role_arn
    production_domains             = var.production_domains
    # Traefik plugins bucket
    plugin_bucket = aws_s3_bucket.plugins.id
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
      Name = "${var.name_prefix}-ac"
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
resource "aws_lb_target_group" "https" {
  name        = replace("${var.name_prefix}-ac-https", "_", "-")
  port        = 443
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "instance"

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
