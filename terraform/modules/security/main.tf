# Security Module
# WAFv2 Web ACL for DDoS protection and common vulnerability protection
#
# Note: WAF can be attached to CloudFront, ALB, or API Gateway.
# For NLB-based services, deploy CloudFront in front first.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  is_prod = var.environment == "prod"
}

# WAFv2 Web ACL - can be used with CloudFront (CLOUDFRONT scope) or regional resources (REGIONAL scope)
resource "aws_wafv2_web_acl" "main" {
  name        = "${var.name_prefix}-waf"
  description = "WAF Web ACL for LayerV NHP"
  scope       = var.waf_scope

  default_action {
    allow {}
  }

  # Rule 1: Rate limiting - prevent DDoS
  rule {
    name     = "RateLimit"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.rate_limit_requests
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: AWS Managed Rules - Common Rule Set
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

  # Rule 3: AWS Managed Rules - Known Bad Inputs
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

  # Rule 4: AWS Managed Rules - IP Reputation List
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

  # Rule 5: Block requests from anonymous proxies (production only)
  dynamic "rule" {
    for_each = local.is_prod ? [1] : []
    content {
      name     = "AWSManagedRulesAnonymousIpList"
      priority = 5

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesAnonymousIpList"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name_prefix}-anonymous-ip"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-waf"
    sampled_requests_enabled   = true
  }

  tags = var.tags
}

# CloudWatch Log Group for WAF logs
resource "aws_cloudwatch_log_group" "waf" {
  count             = var.enable_waf_logging ? 1 : 0
  name              = "aws-waf-logs-${var.name_prefix}"
  retention_in_days = local.is_prod ? 90 : 30
  kms_key_id        = var.logs_kms_key_arn

  tags = var.tags
}

# WAF Logging Configuration
resource "aws_wafv2_web_acl_logging_configuration" "main" {
  count                   = var.enable_waf_logging ? 1 : 0
  log_destination_configs = [aws_cloudwatch_log_group.waf[0].arn]
  resource_arn            = aws_wafv2_web_acl.main.arn

  logging_filter {
    default_behavior = "KEEP"

    filter {
      behavior = "KEEP"
      condition {
        action_condition {
          action = "BLOCK"
        }
      }
      requirement = "MEETS_ANY"
    }
  }
}

# ==================== GuardDuty ====================
# Threat detection service for AWS accounts

resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = false
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  finding_publishing_frequency = local.is_prod ? "FIFTEEN_MINUTES" : "SIX_HOURS"

  tags = var.tags
}

# ==================== Security Hub ====================
# Centralized security findings and compliance checks

resource "aws_securityhub_account" "main" {
  count                     = var.enable_security_hub ? 1 : 0
  enable_default_standards  = false
  auto_enable_controls      = true
  control_finding_generator = "SECURITY_CONTROL"
}

# Enable AWS Foundational Security Best Practices standard
resource "aws_securityhub_standards_subscription" "aws_foundational" {
  count         = var.enable_security_hub ? 1 : 0
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.id}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.main]
}

# Enable CIS AWS Foundations Benchmark
resource "aws_securityhub_standards_subscription" "cis" {
  count         = var.enable_security_hub && local.is_prod ? 1 : 0
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.id}::standards/cis-aws-foundations-benchmark/v/1.4.0"

  depends_on = [aws_securityhub_account.main]
}

# Send GuardDuty findings to Security Hub
resource "aws_securityhub_product_subscription" "guardduty" {
  count       = var.enable_security_hub && var.enable_guardduty ? 1 : 0
  product_arn = "arn:aws:securityhub:${data.aws_region.current.id}::product/aws/guardduty"

  depends_on = [aws_securityhub_account.main]
}

# ==================== AWS Config ====================
# Configuration compliance and drift detection

resource "aws_config_configuration_recorder" "main" {
  count    = var.enable_aws_config ? 1 : 0
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported = true
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

resource "aws_iam_role" "config" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-config"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "config.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_aws_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3" {
  count = var.enable_aws_config ? 1 : 0
  name  = "config-s3-delivery"
  role  = aws_iam_role.config[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:PutObject",
        "s3:PutObjectAcl"
      ]
      Resource = "${aws_s3_bucket.config[0].arn}/*"
      Condition = {
        StringEquals = {
          "s3:x-amz-acl" = "bucket-owner-full-control"
        }
      }
    }]
  })
}

# S3 bucket for Config delivery
resource "aws_s3_bucket" "config" {
  count  = var.enable_aws_config ? 1 : 0
  bucket = "${var.name_prefix}-config-${data.aws_caller_identity.current.account_id}"

  tags = var.tags
}

resource "aws_s3_bucket_versioning" "config" {
  count  = var.enable_aws_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  count  = var.enable_aws_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  count  = var.enable_aws_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_config_delivery_channel" "main" {
  count          = var.enable_aws_config ? 1 : 0
  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = aws_s3_bucket.config[0].id

  snapshot_delivery_properties {
    delivery_frequency = "Six_Hours"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  count      = var.enable_aws_config ? 1 : 0
  name       = aws_config_configuration_recorder.main[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# ==================== AWS Config Rules ====================

# EBS volumes should be encrypted
resource "aws_config_config_rule" "ebs_encrypted" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-ebs-encrypted"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# S3 buckets should have server-side encryption
resource "aws_config_config_rule" "s3_encrypted" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-s3-encrypted"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# IAM users should have MFA enabled
resource "aws_config_config_rule" "iam_mfa" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-iam-mfa"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Root account should have MFA enabled
resource "aws_config_config_rule" "root_mfa" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-root-mfa"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Security groups should not allow unrestricted SSH
resource "aws_config_config_rule" "restricted_ssh" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-restricted-ssh"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# VPC flow logs should be enabled
resource "aws_config_config_rule" "vpc_flow_logs" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-vpc-flow-logs"

  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# CloudTrail should be enabled
resource "aws_config_config_rule" "cloudtrail_enabled" {
  count = var.enable_aws_config ? 1 : 0
  name  = "${var.name_prefix}-cloudtrail-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# ==================== IAM Permission Boundaries ====================
# Permission boundaries restrict the maximum permissions for IAM entities
# These should be attached to all IAM roles to enforce least privilege

resource "aws_iam_policy" "permission_boundary" {
  name        = "${var.name_prefix}-permission-boundary"
  description = "Permission boundary for all IAM roles in the NHP infrastructure"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEC2AndECSActions"
        Effect = "Allow"
        Action = [
          "ec2:*",
          "ecs:*",
          "ecr:*",
          "elasticfilesystem:*",
          "autoscaling:*",
          "elasticloadbalancing:*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = data.aws_region.current.id
          }
        }
      },
      {
        Sid    = "AllowLoggingAndMonitoring"
        Effect = "Allow"
        Action = [
          "logs:*",
          "cloudwatch:*",
          "sns:*",
          "events:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowSecretsAndSSM"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:UpdateSecretVersionStage",
          "secretsmanager:GetRandomPassword",
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath",
          "ssmmessages:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowServiceDiscovery"
        Effect = "Allow"
        Action = [
          "servicediscovery:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowRoute53ForACME"
        Effect = "Allow"
        Action = [
          "route53:GetChange",
          "route53:ChangeResourceRecordSets",
          "route53:ListResourceRecordSets",
          "route53:ListHostedZonesByName"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowKMSForEncryption"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "DenyPrivilegeEscalation"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:CreateRole",
          "iam:CreatePolicy",
          "iam:AttachUserPolicy",
          "iam:AttachRolePolicy",
          "iam:PutUserPolicy",
          "iam:PutRolePolicy",
          "iam:DeleteRolePermissionsBoundary",
          "iam:DeleteUserPermissionsBoundary"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenySensitiveServices"
        Effect = "Deny"
        Action = [
          "organizations:*",
          "account:*",
          "iam:DeactivateMFADevice",
          "iam:DeleteAccessKey",
          "iam:DeleteUser",
          "iam:UpdateLoginProfile"
        ]
        Resource = "*"
      }
    ]
  })

  tags = var.tags
}

# ==================== CloudTrail ====================
# API call audit logging for security and compliance

resource "aws_s3_bucket" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = "${var.name_prefix}-cloudtrail-${data.aws_caller_identity.current.account_id}"

  tags = var.tags
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.logs_kms_key_arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    id     = "archive-and-delete"
    status = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = local.is_prod ? 365 : 180
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail[0].arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:trail/${var.name_prefix}-trail"
          }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "AWS:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:trail/${var.name_prefix}-trail"
          }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  count             = var.enable_cloudtrail ? 1 : 0
  name              = "/aws/cloudtrail/${var.name_prefix}"
  retention_in_days = local.is_prod ? 365 : 90
  kms_key_id        = var.logs_kms_key_arn

  tags = var.tags
}

resource "aws_iam_role" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0
  name  = "${var.name_prefix}-cloudtrail"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0
  name  = "cloudtrail-logs"
  role  = aws_iam_role.cloudtrail[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "main" {
  count                         = var.enable_cloudtrail ? 1 : 0
  name                          = "${var.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail[0].id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail[0].arn
  kms_key_id                    = var.logs_kms_key_arn

  # Log data events for S3 and Lambda (optional, can increase costs)
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = var.tags

  depends_on = [aws_s3_bucket_policy.cloudtrail]

  # Ignore kms_key_id changes when SCP blocks CloudTrail updates
  lifecycle {
    ignore_changes = [kms_key_id]
  }
}
