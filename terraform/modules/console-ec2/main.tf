# Console EC2 Module
# Deploys the LayerV Console API on EC2 with nginx + Docker
#
# Architecture:
# Internet → NLB (TCP 443) → nginx (TLS) → Console Docker (port 8888)
#
# The Console API handles:
# - createPortalSitesByURL - creates portal sites for demo
# - Other portal management endpoints

# ==================== Validation ====================

# Validate required variables for NHP protection (always enabled)
check "nhp_protection_requirements" {
  assert {
    condition = (
      var.nhp_server_secret_arn != null &&
      var.nhp_ac_repo_url != null &&
      var.nhp_ac_ecr_repo_arn != null &&
      var.nhp_server_cloudmap_dns != null &&
      var.protected_hostname != null &&
      var.protected_hosted_zone_id != null
    )
    error_message = <<-EOT
      NHP protection is always enabled. The following variables are required:
        - nhp_server_secret_arn
        - nhp_ac_repo_url
        - nhp_ac_ecr_repo_arn
        - nhp_server_cloudmap_dns
        - protected_hostname
        - protected_hosted_zone_id
    EOT
  }
}

# ==================== Data Sources ====================

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Ubuntu 24.04 LTS (Noble Numbat)
data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/noble/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

# ==================== Locals ====================

locals {
  is_prod      = var.environment == "prod"
  console_name = "${var.name_prefix}-console-ec2"

  # Build AC config JSON for container environment
  ac_config_json = jsonencode({
    enabled = length(var.ac_configs) > 0
    acs     = var.ac_configs
  })
}

# ==================== CloudWatch Log Group ====================

resource "aws_cloudwatch_log_group" "console" {
  name              = "/layerv/nhp/${var.environment}/console-ec2"
  retention_in_days = local.is_prod ? 365 : 30
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${local.console_name}-logs"
    Component = "console"
  })
}

# ==================== IAM Role ====================

resource "aws_iam_role" "console" {
  name = local.console_name

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

resource "aws_iam_role_policy_attachment" "console_ssm" {
  role       = aws_iam_role.console.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

locals {
  # Pre-compute resource lists to check for empty arrays
  # Note: License secret ARN uses wildcard suffix because AWS adds random chars to secret ARNs
  license_secret_arn_pattern = var.nhp_console_ac_license_secret_arn != null ? "${var.nhp_console_ac_license_secret_arn}*" : null
  secrets_manager_resources  = compact([var.rds_secret_arn, var.nhp_server_secret_arn, var.etcd_tls_secret_arn, local.license_secret_arn_pattern])
  ecr_repo_resources         = compact([var.ecr_repo_arn, var.nhp_ac_ecr_repo_arn])
  dynamodb_resources = compact([
    var.nhp_dynamodb_ac_assignments_table != null ? "arn:aws:dynamodb:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:table/${var.nhp_dynamodb_ac_assignments_table}" : "",
    var.nhp_dynamodb_ac_assignments_table != null ? "arn:aws:dynamodb:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:table/${var.nhp_dynamodb_ac_assignments_table}/index/*" : "",
    var.nhp_dynamodb_server_ac_index_table != null ? "arn:aws:dynamodb:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:table/${var.nhp_dynamodb_server_ac_index_table}" : "",
    var.nhp_dynamodb_server_ac_index_table != null ? "arn:aws:dynamodb:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:table/${var.nhp_dynamodb_server_ac_index_table}/index/*" : "",
    var.nhp_dynamodb_licenses_table != null ? "arn:aws:dynamodb:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:table/${var.nhp_dynamodb_licenses_table}" : ""
  ])
  route53_zone_resources = compact(distinct([
    var.hosted_zone_id != null ? "arn:aws:route53:::hostedzone/${var.hosted_zone_id}" : "",
    var.protected_hosted_zone_id != null ? "arn:aws:route53:::hostedzone/${var.protected_hosted_zone_id}" : ""
  ]))
}

resource "aws_iam_role_policy" "console" {
  name = "console-permissions"
  role = aws_iam_role.console.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      # CloudWatch Logs - always included
      [{
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.console.arn}:*"
      }],
      # Secrets Manager - RDS credentials, NHP Server secret, and etcd TLS certs (only if resources exist)
      length(local.secrets_manager_resources) > 0 ? [{
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = local.secrets_manager_resources
      }] : [],
      # Secrets Manager - Create per-instance AC secret (always included, wildcard pattern)
      [{
        Effect = "Allow"
        Action = [
          "secretsmanager:CreateSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:GetSecretValue",
          "secretsmanager:TagResource",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "arn:aws:secretsmanager:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:secret:${var.name_prefix}-console-ac-*"
      }],
      # KMS for secrets encryption/decryption (only when KMS key ARN is provided)
      var.secrets_kms_key_arn != null ? [{
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
        Resource = [var.secrets_kms_key_arn]
      }] : [],
      # ECR - GetAuthorizationToken (always needed for Docker login)
      [{
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      }],
      # ECR - pull console image (and AC image when NHP protection enabled)
      length(local.ecr_repo_resources) > 0 ? [{
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = local.ecr_repo_resources
      }] : [],
      # NHP Server Assignment: DynamoDB access for AC assignments (only if tables are configured)
      length(local.dynamodb_resources) > 0 ? [{
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:BatchGetItem",
          "dynamodb:BatchWriteItem"
        ]
        Resource = local.dynamodb_resources
      }] : [],
      # NHP Server Assignment: CloudMap for server discovery
      # Note: DiscoverInstances requires Resource = "*" per AWS IAM documentation.
      [{
        Effect   = "Allow"
        Action   = ["servicediscovery:DiscoverInstances"]
        Resource = "*"
      }],
      # Route 53 for certbot DNS-01 challenge - list operations (always needed)
      [{
        Effect = "Allow"
        Action = [
          "route53:ListHostedZones",
          "route53:GetChange"
        ]
        Resource = "*"
      }],
      # Route 53 - zone-specific operations (only if zones are configured)
      length(local.route53_zone_resources) > 0 ? [{
        Effect = "Allow"
        Action = [
          "route53:ChangeResourceRecordSets",
          "route53:ListResourceRecordSets"
        ]
        Resource = local.route53_zone_resources
      }] : [],
      # SSM - read Console image tag at boot time
      [{
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = "arn:aws:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:parameter${var.console_image_tag_ssm_param}"
      }]
    )
  })
}

resource "aws_iam_instance_profile" "console" {
  name = local.console_name
  role = aws_iam_role.console.name

  tags = var.tags
}

# ==================== Security Groups ====================

resource "aws_security_group" "console" {
  name_prefix = "${local.console_name}-"
  vpc_id      = var.vpc_id
  description = "Security group for Console EC2"

  # External mode: HTTP from anywhere (for ACME challenges and HTTPS redirect)
  # Note: Port 443 is handled by the unconditional NHP protection rule below
  dynamic "ingress" {
    for_each = var.internal_only ? [] : [1]
    content {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "HTTP for ACME and redirect (external mode)"
    }
  }

  # Internal mode: Allow HTTP from AC security group
  dynamic "ingress" {
    for_each = var.internal_only && var.ac_security_group_id != null ? [1] : []
    content {
      from_port       = var.console_port
      to_port         = var.console_port
      protocol        = "tcp"
      security_groups = [var.ac_security_group_id]
      description     = "HTTP from AC (internal mode)"
    }
  }

  # Internal mode: Allow HTTP from VPC (for NLB health checks and Traefik)
  dynamic "ingress" {
    for_each = var.internal_only ? [1] : []
    content {
      from_port   = var.console_port
      to_port     = var.console_port
      protocol    = "tcp"
      cidr_blocks = [var.vpc_cidr]
      description = "HTTP from VPC (internal mode)"
    }
  }

  # NHP Protection: Allow port 443 from anywhere (iptables DROP until knock)
  # Security group allows the traffic, but iptables on the instance will DROP it
  # until nhp-acd adds the client IP to ipset after successful NHP knock.
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from anywhere (iptables-protected via NHP)"
  }

  # NHP Protection: Allow NHP knock port (UDP 62206) from NHP Server
  # nhp-acd needs to receive knocks from NHP Server
  ingress {
    from_port   = 62206
    to_port     = 62206
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
    description = "NHP knock packets from NHP Server"
  }

  # SSH from VPC
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
    Name      = "${local.console_name}-sg"
    Component = "console"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Allow Console to access RDS
resource "aws_vpc_security_group_ingress_rule" "rds_from_console" {
  security_group_id            = var.rds_security_group_id
  description                  = "PostgreSQL from Console EC2"
  from_port                    = var.rds_port
  to_port                      = var.rds_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.console.id

  tags = {
    Name = "${local.console_name}-to-rds"
  }
}

# ==================== User Data ====================

locals {
  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    domain_name                 = var.domain_name
    acme_email                  = var.acme_email
    console_image_repo          = var.console_image_repo
    console_image_tag_ssm_param = var.console_image_tag_ssm_param
    console_port                = var.console_port
    rds_endpoint                = var.rds_endpoint
    rds_port                    = var.rds_port
    rds_database_name           = var.rds_database_name
    rds_secret_arn              = var.rds_secret_arn
    cookie_domain               = var.cookie_domain
    ac_config_json              = local.ac_config_json
    region                      = data.aws_region.current.id
    account_id                  = data.aws_caller_identity.current.account_id
    hosted_zone_id              = var.hosted_zone_id
    internal_only               = var.internal_only
    # RDS seeding for NHP Console resource
    seed_console_resource = var.seed_console_resource
    console_app_id        = var.console_app_id
    ac_nlb_dns            = var.ac_nlb_dns
    ac_domain             = var.ac_domain
    protected_hostname    = var.protected_hostname
    console_internal_nlb  = aws_lb.console.dns_name
    # NHP Server endpoint for /plugins/* routing
    nhp_server_endpoint = var.nhp_server_endpoint
    # Admin password (passed to GVA_ADMIN_PASSWORD for initial setup if needed)
    admin_password   = var.admin_password
    auth_signing_key = var.auth_signing_key
    # AC ID for knock routing (must match AC module's ac_id)
    ac_id = var.ac_id
    # NHP Protection (always enabled)
    nhp_server_secret_arn   = var.nhp_server_secret_arn
    nhp_ac_repo_url         = var.nhp_ac_repo_url
    image_tag               = var.image_tag
    nhp_server_cloudmap_dns = var.nhp_server_cloudmap_dns
    vpc_cidr                = var.vpc_cidr
    name_prefix             = var.name_prefix
    secrets_kms_key_arn     = var.secrets_kms_key_arn != null ? var.secrets_kms_key_arn : ""
    # etcd for Console AC registration
    etcd_endpoint       = var.etcd_endpoint
    etcd_tls_secret_arn = var.etcd_tls_secret_arn
    # NHP Server Assignment
    nhp_server_assignment_enabled        = var.nhp_server_assignment_enabled
    nhp_region                           = var.nhp_region
    nhp_dynamodb_ac_assignments_table    = var.nhp_dynamodb_ac_assignments_table
    nhp_dynamodb_server_ac_index_table   = var.nhp_dynamodb_server_ac_index_table
    nhp_cloudmap_namespace               = var.nhp_cloudmap_namespace
    nhp_cloudmap_service_name            = var.nhp_cloudmap_service_name
    nhp_assignment_servers_per_ac        = var.nhp_assignment_servers_per_ac
    nhp_health_monitor_check_interval    = var.nhp_health_monitor_check_interval
    nhp_health_monitor_operation_timeout = var.nhp_health_monitor_operation_timeout
    nhp_console_ac_license_secret_arn    = var.nhp_console_ac_license_secret_arn
    nhp_console_ac_customer_id           = var.nhp_console_ac_customer_id
  })
}

# ==================== Launch Template ====================

resource "aws_launch_template" "console" {
  name_prefix   = "${local.console_name}-"
  image_id      = data.aws_ssm_parameter.ubuntu_ami.value
  instance_type = var.instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.console.arn
  }

  network_interfaces {
    # No public IP in internal mode (behind AC/NHP)
    associate_public_ip_address = var.internal_only ? false : true
    security_groups             = [aws_security_group.console.id]
  }

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = 30
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.ebs_kms_key_arn
      delete_on_termination = true
    }
  }

  # Gzip user_data to stay under 16KB limit (especially with NHP protection enabled)
  user_data = base64gzip(local.user_data)

  monitoring {
    enabled = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
    # Hop limit 2 required for Docker containers to access IMDS through bridge network
    http_put_response_hop_limit = 2
  }

  tags = var.tags

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      Name      = local.console_name
      Component = "console"
    })
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ==================== Auto Scaling Group ====================

resource "aws_autoscaling_group" "console" {
  name = local.console_name
  # Use private subnets in internal mode (behind AC/NHP)
  vpc_zone_identifier = var.internal_only ? var.private_subnet_ids : var.public_subnet_ids
  min_size            = 1
  max_size            = 2
  desired_capacity    = 1

  launch_template {
    id      = aws_launch_template.console.id
    version = "$Latest"
  }

  # Use ELB health checks so ASG considers target group health, not just EC2 status.
  # In internal mode, the internal TG has HTTP health checks to /health endpoint.
  # Unhealthy instances (app crash, DB unreachable) will be automatically replaced.
  health_check_type         = "ELB"
  health_check_grace_period = 300

  # Target groups: internal or external mode, plus protected (always enabled)
  # NOTE: Must include protected target group here, not via aws_autoscaling_attachment,
  # because target_group_arns is declarative and would override any separate attachments.
  target_group_arns = concat(
    var.internal_only ? [aws_lb_target_group.internal[0].arn] : [
      aws_lb_target_group.https[0].arn,
      aws_lb_target_group.http[0].arn
    ],
    [aws_lb_target_group.protected.arn]
  )

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
      instance_warmup        = 300
    }
  }

  tag {
    key                 = "Name"
    value               = local.console_name
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

# ==================== Network Load Balancer ====================

resource "aws_lb" "console" {
  name               = replace(local.console_name, "_", "-")
  internal           = var.internal_only
  load_balancer_type = "network"
  # Internal mode: private subnets; External mode: public subnets
  subnets = var.internal_only ? var.private_subnet_ids : var.public_subnet_ids

  enable_cross_zone_load_balancing = true

  tags = var.tags
}

# ==================== External Mode Target Groups (TLS on nginx) ====================

# HTTPS Target Group (external mode only)
resource "aws_lb_target_group" "https" {
  count = var.internal_only ? 0 : 1

  name        = replace("${var.name_prefix}-con-https", "_", "-")
  port        = 443
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
    enabled             = true
    protocol            = "TCP"
    port                = "443"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay = 30

  tags = var.tags
}

# HTTP Target Group (external mode only)
resource "aws_lb_target_group" "http" {
  count = var.internal_only ? 0 : 1

  name        = replace("${var.name_prefix}-con-http", "_", "-")
  port        = 80
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
    enabled             = true
    protocol            = "TCP"
    port                = "80"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay = 30

  tags = var.tags
}

# HTTPS Listener (external mode only)
resource "aws_lb_listener" "https" {
  count = var.internal_only ? 0 : 1

  load_balancer_arn = aws_lb.console.arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.https[0].arn
  }

  tags = var.tags
}

# HTTP Listener (external mode only)
resource "aws_lb_listener" "http" {
  count = var.internal_only ? 0 : 1

  load_balancer_arn = aws_lb.console.arn
  port              = 80
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.http[0].arn
  }

  tags = var.tags
}

# ==================== Internal Mode Target Group (HTTP from AC) ====================

# Internal HTTP Target Group (internal mode only)
resource "aws_lb_target_group" "internal" {
  count = var.internal_only ? 1 : 0

  name        = replace("${var.name_prefix}-con-int", "_", "-")
  port        = var.console_port
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
    enabled             = true
    protocol            = "HTTP"
    path                = "/health"
    port                = tostring(var.console_port)
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay = 30

  tags = var.tags
}

# Internal HTTP Listener (internal mode only)
resource "aws_lb_listener" "internal" {
  count = var.internal_only ? 1 : 0

  load_balancer_arn = aws_lb.console.arn
  port              = var.console_port
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.internal[0].arn
  }

  tags = var.tags
}

# ==================== Route 53 Record ====================

# External mode: Create Route 53 record pointing to Console NLB
# Internal mode: DNS record is created separately to point to AC NLB
resource "aws_route53_record" "console" {
  count = var.hosted_zone_id != null && !var.internal_only ? 1 : 0

  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.console.dns_name
    zone_id                = aws_lb.console.zone_id
    evaluate_target_health = true
  }
}

# ==================== NHP Protected NLB (True Network Hiding) ====================
# NHP protection is always enabled. This public NLB routes protected traffic to Console.
# Console's iptables DROP all port 443 traffic until NHP knock adds user IP to ipset.

resource "aws_lb" "protected" {
  name               = replace("${var.name_prefix}-con-prot", "_", "-")
  internal           = false # Internet-facing for protected access
  load_balancer_type = "network"
  subnets            = var.public_subnet_ids

  enable_cross_zone_load_balancing = true

  tags = merge(var.tags, {
    Name      = "${local.console_name}-protected-nlb"
    Component = "console"
    Purpose   = "NHP-protected access"
  })
}

resource "aws_lb_target_group" "protected" {
  name        = replace("${var.name_prefix}-con-prot", "_", "-")
  port        = 443
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  # Health check on SSH (port 22) instead of port 443 because:
  # - iptables DROP policy blocks port 443 until NHP knock succeeds
  # - NLB health checks would always fail on port 443
  # - SSH from VPC CIDR is allowed in iptables rules for management access
  # - This verifies the instance is running, even if app health isn't directly checked
  # Trade-off: Instance can be "healthy" even if nginx/Console is down, but this is
  # acceptable since NHP protection is the primary concern and Console has its own
  # health monitor service (console-health.service) that auto-restarts Docker.
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

resource "aws_lb_listener" "protected" {
  load_balancer_arn = aws_lb.protected.arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.protected.arn
  }

  tags = var.tags
}

# NOTE: Protected target group attachment is now included directly in
# aws_autoscaling_group.console.target_group_arns above. Using a separate
# aws_autoscaling_attachment would conflict with the declarative target_group_arns,
# causing the attachment to be removed on subsequent applies.

# Route 53 record for protected domain (e.g., console2.apps.layerv.xyz)
resource "aws_route53_record" "protected" {
  count = var.protected_hosted_zone_id != null && var.protected_hostname != null ? 1 : 0

  zone_id = var.protected_hosted_zone_id
  name    = var.protected_hostname
  type    = "A"

  alias {
    name                   = aws_lb.protected.dns_name
    zone_id                = aws_lb.protected.zone_id
    evaluate_target_health = true
  }
}

# ==================== ASG Lifecycle Hook for Cleanup ====================
# Cleans up orphaned resources when Console EC2 instances terminate:
# - AC assignments in DynamoDB
# - AC keypair secrets in Secrets Manager

# Lambda function to clean up resources on instance termination
resource "aws_lambda_function" "console_cleanup" {
  function_name = "${local.console_name}-cleanup"
  description   = "Cleans up Console AC resources on instance termination"
  runtime       = "python3.12"
  handler       = "index.handler"
  timeout       = 30
  memory_size   = 128

  role = aws_iam_role.cleanup_lambda.arn

  filename         = data.archive_file.cleanup_lambda.output_path
  source_code_hash = data.archive_file.cleanup_lambda.output_base64sha256

  environment {
    variables = {
      DYNAMODB_TABLE = var.nhp_dynamodb_ac_assignments_table != null ? var.nhp_dynamodb_ac_assignments_table : ""
      SECRET_PREFIX  = "${var.name_prefix}-console-ac-"
      AWS_REGION_VAR = data.aws_region.current.id
    }
  }

  tags = merge(var.tags, {
    Name      = "${local.console_name}-cleanup"
    Component = "console"
  })
}

# Lambda source code
data "archive_file" "cleanup_lambda" {
  type        = "zip"
  output_path = "${path.module}/lambda_cleanup.zip"

  source {
    content  = <<-PYTHON
import boto3
import json
import os

def handler(event, context):
    """
    Clean up Console AC resources when an EC2 instance terminates.

    Triggered by ASG lifecycle hook via EventBridge.
    Deletes:
    - AC assignment from DynamoDB (console-ac-{instance_id})
    - AC keypair from Secrets Manager ({prefix}{instance_id})
    """
    print(f"Received event: {json.dumps(event)}")

    # Extract instance ID from lifecycle hook event
    detail = event.get('detail', {})
    instance_id = detail.get('EC2InstanceId')

    if not instance_id:
        print("No instance ID found in event, skipping cleanup")
        return {'statusCode': 200, 'body': 'No instance ID'}

    print(f"Cleaning up resources for instance: {instance_id}")

    region = os.environ.get('AWS_REGION_VAR', os.environ.get('AWS_REGION', 'us-east-2'))
    dynamodb_table = os.environ.get('DYNAMODB_TABLE', '')
    secret_prefix = os.environ.get('SECRET_PREFIX', '')

    # Clean up DynamoDB AC assignment
    if dynamodb_table:
        try:
            dynamodb = boto3.client('dynamodb', region_name=region)
            ac_id = f"console-ac-{instance_id}"

            dynamodb.delete_item(
                TableName=dynamodb_table,
                Key={'ac_id': {'S': ac_id}}
            )
            print(f"Deleted DynamoDB assignment: {ac_id}")
        except Exception as e:
            print(f"Failed to delete DynamoDB assignment: {e}")

    # Clean up Secrets Manager keypair
    if secret_prefix:
        try:
            secrets = boto3.client('secretsmanager', region_name=region)
            secret_name = f"{secret_prefix}{instance_id}"

            secrets.delete_secret(
                SecretId=secret_name,
                ForceDeleteWithoutRecovery=True
            )
            print(f"Deleted secret: {secret_name}")
        except secrets.exceptions.ResourceNotFoundException:
            print(f"Secret not found (already deleted): {secret_name}")
        except Exception as e:
            print(f"Failed to delete secret: {e}")

    # Complete the lifecycle action
    asg_name = detail.get('AutoScalingGroupName')
    lifecycle_hook = detail.get('LifecycleHookName')
    lifecycle_token = detail.get('LifecycleActionToken')

    if asg_name and lifecycle_hook and lifecycle_token:
        try:
            asg = boto3.client('autoscaling', region_name=region)
            asg.complete_lifecycle_action(
                AutoScalingGroupName=asg_name,
                LifecycleHookName=lifecycle_hook,
                LifecycleActionToken=lifecycle_token,
                LifecycleActionResult='CONTINUE'
            )
            print(f"Completed lifecycle action for {instance_id}")
        except Exception as e:
            print(f"Failed to complete lifecycle action: {e}")

    return {'statusCode': 200, 'body': f'Cleaned up {instance_id}'}
PYTHON
    filename = "index.py"
  }
}

# IAM role for cleanup Lambda
resource "aws_iam_role" "cleanup_lambda" {
  name = "${local.console_name}-cleanup-lambda"

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

  tags = merge(var.tags, {
    Name      = "${local.console_name}-cleanup-lambda"
    Component = "console"
  })
}

# IAM policy for cleanup Lambda
resource "aws_iam_role_policy" "cleanup_lambda" {
  name = "cleanup-permissions"
  role = aws_iam_role.cleanup_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.console_name}-cleanup:*"
      },
      {
        Sid    = "DynamoDBCleanup"
        Effect = "Allow"
        Action = [
          "dynamodb:DeleteItem"
        ]
        Resource = var.nhp_dynamodb_ac_assignments_table != null ? "arn:aws:dynamodb:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:table/${var.nhp_dynamodb_ac_assignments_table}" : "*"
      },
      {
        Sid    = "SecretsManagerCleanup"
        Effect = "Allow"
        Action = [
          "secretsmanager:DeleteSecret"
        ]
        Resource = "arn:aws:secretsmanager:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:secret:${var.name_prefix}-console-ac-*"
      },
      {
        Sid    = "ASGLifecycleComplete"
        Effect = "Allow"
        Action = [
          "autoscaling:CompleteLifecycleAction"
        ]
        Resource = aws_autoscaling_group.console.arn
      }
    ]
  })
}

# ASG lifecycle hook for termination
resource "aws_autoscaling_lifecycle_hook" "console_termination" {
  name                   = "${local.console_name}-termination-cleanup"
  autoscaling_group_name = aws_autoscaling_group.console.name
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
  heartbeat_timeout      = 60
  default_result         = "CONTINUE"
}

# EventBridge rule to trigger Lambda on lifecycle hook
resource "aws_cloudwatch_event_rule" "console_termination" {
  name        = "${local.console_name}-termination"
  description = "Triggers cleanup Lambda when Console EC2 terminates"

  event_pattern = jsonencode({
    source      = ["aws.autoscaling"]
    detail-type = ["EC2 Instance-terminate Lifecycle Action"]
    detail = {
      AutoScalingGroupName = [aws_autoscaling_group.console.name]
    }
  })

  tags = merge(var.tags, {
    Name      = "${local.console_name}-termination"
    Component = "console"
  })
}

# EventBridge target - Lambda function
resource "aws_cloudwatch_event_target" "console_cleanup" {
  rule      = aws_cloudwatch_event_rule.console_termination.name
  target_id = "console-cleanup-lambda"
  arn       = aws_lambda_function.console_cleanup.arn
}

# Permission for EventBridge to invoke Lambda
resource "aws_lambda_permission" "eventbridge_cleanup" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.console_cleanup.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.console_termination.arn
}

# CloudWatch Log Group for cleanup Lambda
resource "aws_cloudwatch_log_group" "cleanup_lambda" {
  name              = "/aws/lambda/${local.console_name}-cleanup"
  retention_in_days = local.is_prod ? 30 : 7

  tags = merge(var.tags, {
    Name      = "${local.console_name}-cleanup-logs"
    Component = "console"
  })
}

# ==================== SSM Parameters for CI/CD ====================

# Store console public URL for GitHub Actions to use during Docker builds
resource "aws_ssm_parameter" "console_public_url" {
  name        = "/layerv/nhp/${var.environment}/console/public_url"
  description = "Console public URL for VITE_LOGIN_URL (used by GitHub Actions)"
  type        = "String"
  value       = var.internal_only ? "https://${var.console_app_id}${var.ac_domain}" : "https://${var.domain_name}"

  tags = merge(var.tags, {
    Component = "console"
  })
}

# ==================== Console AC License Seeding ====================
# Seeds DynamoDB with a license record for Console's embedded AC.
# This enables license validation in cloud mode (storage_backend=dynamodb).
# License keys are globally unique, so license_key_sha256 is the sole partition key.
# See docs/design/PLUGGABLE_STORAGE_BACKEND.md Section 6.2 for details.

resource "aws_dynamodb_table_item" "console_ac_license" {
  # Only create if DynamoDB table AND both license key hashes are provided
  # AC registration will fail without valid license key hashes
  count = (
    var.nhp_dynamodb_licenses_table != null &&
    var.nhp_console_ac_license_key_hash != null && var.nhp_console_ac_license_key_hash != "" &&
    var.nhp_console_ac_license_key_sha256 != null && var.nhp_console_ac_license_key_sha256 != ""
  ) ? 1 : 0

  table_name = var.nhp_dynamodb_licenses_table
  hash_key   = "license_key_sha256"

  item = jsonencode({
    license_key_sha256 = {
      S = var.nhp_console_ac_license_key_sha256 # SHA256 of plaintext key (partition key)
    }
    license_key_hash = {
      S = var.nhp_console_ac_license_key_hash # bcrypt hash (for validation)
    }
    customer_id = {
      S = var.nhp_console_ac_customer_id # Informational only
    }
    resource_id = {
      S = "console" # Resource identifier (informational)
    }
    tier = {
      S = "system"
    }
    max_acs = {
      N = "1"
    }
    expires_at = {
      N = "0" # Never expires
    }
    active = {
      BOOL = true
    }
    # Note: created_at and updated_at are set by Console when writing licenses.
    # For Terraform-seeded licenses, these fields are omitted (system bootstrap).
  })

  lifecycle {
    # Prevent recreation if item already exists with different attributes
    ignore_changes = [item]
  }
}
