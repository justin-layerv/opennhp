# ==============================================================================
# Custom Domain Certificate Manager Module
# ==============================================================================
#
# Manages TLS certificates for customer custom domains using Let's Encrypt.
# Uses DNS-01 challenge with CNAME delegation pattern:
#   - Customer sets: _acme-challenge.secure.example.com CNAME secure--example--com.acme.layerv.xyz
#   - Lambda creates TXT record at secure--example--com.acme.layerv.xyz
#   - Let's Encrypt follows CNAME, finds TXT, validates domain
#
# This avoids requiring customers to grant us access to their DNS zones.
#
# Security features:
# - Private keys generated in Lambda, never in Terraform state
# - KMS CMK encryption for all secrets
# - Least-privilege IAM roles
# - Comprehensive audit logging via CloudTrail
# - Automated renewal with alerting
#
# Usage:
#   module "custom_domain_cert" {
#     source = "../modules/custom-domain-cert"
#
#     name_prefix             = "layerv-nhp-sandbox"
#     environment             = "sandbox"
#     acme_base_domain        = "layerv.xyz"
#     acme_email              = "admin@layerv.xyz"
#     use_production_acme     = true
#     kms_key_arn             = module.kms.secrets_kms_key_arn
#     qurl_domains_table_name = module.dynamodb.qurl_domains_table_name
#     qurl_domains_table_arn  = module.dynamodb.qurl_domains_table_arn
#     ac_instance_tag         = "layerv-nhp-sandbox-ac"
#     alert_emails            = ["alerts@layerv.ai"]
#   }
#
# ==============================================================================

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.0"
    }
  }
}

locals {
  is_prod = var.environment == "prod" || var.environment == "production"

  # ACME directory URLs
  acme_directory = var.use_production_acme ? "https://acme-v02.api.letsencrypt.org/directory" : "https://acme-staging-v02.api.letsencrypt.org/directory"

  # ACME delegation zone
  acme_zone_name = "acme.${var.acme_base_domain}"

  # Resource naming
  function_name = "${var.name_prefix}-custom-domain-cert-manager"

  # KMS key
  kms_key_arn = var.kms_key_arn

  # SNS topic - use provided or create new
  sns_topic_arn = var.use_existing_sns_topic ? var.existing_sns_topic_arn : aws_sns_topic.alerts[0].arn

  # Common tags
  common_tags = merge(var.tags, {
    Module      = "custom-domain-cert"
    Component   = "custom-domain-cert"
    Environment = var.environment
  })
}

# ==============================================================================
# Route53 Hosted Zone - ACME Delegation
# ==============================================================================
#
# This zone holds TXT records for DNS-01 challenges. Customers point their
# _acme-challenge.{domain} CNAME to {subdomain}.acme.{base_domain}, and we
# create TXT records here.

resource "aws_route53_zone" "acme" {
  name    = local.acme_zone_name
  comment = "ACME DNS-01 delegation zone for custom domain certificates (${var.environment})"

  tags = merge(local.common_tags, {
    Name = local.acme_zone_name
  })
}

# ==============================================================================
# Secrets Manager - ACME Account Key (Shared)
# ==============================================================================
#
# Single ACME account key shared across all custom domain cert operations.
# Persisted to avoid hitting Let's Encrypt account creation rate limits.

resource "aws_secretsmanager_secret" "acme_account" {
  name                    = "${var.name_prefix}-custom-domain-acme-account"
  description             = "Shared ACME account key for custom domain certificate issuance"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = local.kms_key_arn

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-custom-domain-acme-account"
  })
}

# ==============================================================================
# SNS Topic for Alerts
# ==============================================================================

resource "aws_sns_topic" "alerts" {
  count = !var.use_existing_sns_topic ? 1 : 0

  name              = "${var.name_prefix}-custom-domain-cert-alerts"
  kms_master_key_id = local.kms_key_arn

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-custom-domain-cert-alerts"
  })
}

resource "aws_sns_topic_subscription" "email" {
  for_each = !var.use_existing_sns_topic ? toset(var.alert_emails) : toset([])

  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = each.value
}

# ==============================================================================
# Lambda Function - Custom Domain Certificate Manager
# ==============================================================================

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/build/package"
  output_path = "${path.module}/build/lambda-custom-domain-cert.zip"
}

resource "aws_lambda_function" "cert_manager" {
  function_name = local.function_name
  description   = "Custom domain certificate manager using ACME DNS-01 with CNAME delegation"
  role          = aws_iam_role.lambda.arn

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  handler          = "custom_domain_cert_manager.handler"
  runtime          = "python3.12"
  architectures    = ["x86_64"]
  timeout          = 600
  memory_size      = 512

  environment {
    variables = {
      ACME_ZONE_ID            = aws_route53_zone.acme.zone_id
      ACME_ZONE_NAME          = local.acme_zone_name
      ACME_ACCOUNT_SECRET_ARN = aws_secretsmanager_secret.acme_account.arn
      KMS_KEY_ARN             = local.kms_key_arn != null ? local.kms_key_arn : ""
      ACME_EMAIL              = var.acme_email
      ACME_DIRECTORY          = local.acme_directory
      SNS_TOPIC_ARN           = local.sns_topic_arn
      QURL_DOMAINS_TABLE      = var.qurl_domains_table_name
      SECRETS_PREFIX          = var.secrets_prefix
      AC_INSTANCE_TAG         = var.ac_instance_tag
    }
  }

  tracing_config {
    mode = "Active"
  }

  # Limit to 1 concurrent execution to prevent race conditions when multiple
  # domains provision simultaneously (shared ACME account key, Route53 zone writes).
  reserved_concurrent_executions = 1

  tags = merge(local.common_tags, {
    Name = local.function_name
  })

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.lambda_permissions
  ]
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 30
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(local.common_tags, {
    Name = "/aws/lambda/${local.function_name}"
  })
}

# ==============================================================================
# IAM Role and Policies for Lambda
# ==============================================================================

resource "aws_iam_role" "lambda" {
  name = "${local.function_name}-role"

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

  tags = merge(local.common_tags, {
    Name = "${local.function_name}-role"
  })
}

resource "aws_iam_role_policy" "lambda_permissions" {
  name = "${local.function_name}-permissions"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # CloudWatch Logs
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.lambda.arn}:*"
      },

      # Secrets Manager - ACME account key (read/write)
      {
        Sid    = "SecretsManagerACMEAccount"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = aws_secretsmanager_secret.acme_account.arn
      },

      # Secrets Manager - Create/read/write custom domain cert secrets
      {
        Sid    = "SecretsManagerCustomDomainCerts"
        Effect = "Allow"
        Action = [
          "secretsmanager:CreateSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:TagResource"
        ]
        Resource = "arn:aws:secretsmanager:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:secret:${var.secrets_prefix}/*"
      },

      # Secrets Manager - ListSecrets (no resource restriction)
      {
        Sid    = "SecretsManagerList"
        Effect = "Allow"
        Action = [
          "secretsmanager:ListSecrets"
        ]
        Resource = "*"
      },

      # Route53 - DNS-01 Challenge in ACME delegation zone
      {
        Sid    = "Route53DNSChallenge"
        Effect = "Allow"
        Action = [
          "route53:ChangeResourceRecordSets",
          "route53:ListResourceRecordSets"
        ]
        Resource = aws_route53_zone.acme.arn
      },
      {
        Sid    = "Route53GetChange"
        Effect = "Allow"
        Action = [
          "route53:GetChange"
        ]
        Resource = "arn:aws:route53:::change/*"
      },

      # DynamoDB - Update domain status
      {
        Sid    = "DynamoDBDomainStatus"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:UpdateItem"
        ]
        Resource = var.qurl_domains_table_arn
      },

      # SNS - Publish alerts
      {
        Sid    = "SNSPublish"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = local.sns_topic_arn
      },

      # CloudWatch - Publish certificate metrics
      {
        Sid    = "CloudWatchMetrics"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "NHP/CustomDomainCerts"
          }
        }
      },

      # SSM - Trigger cert sync on AC instances
      {
        Sid    = "SSMSendCommand"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation"
        ]
        Resource = [
          "arn:aws:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:document/AWS-RunShellScript",
          "arn:aws:ec2:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:instance/*"
        ]
      },

      # X-Ray tracing
      {
        Sid    = "XRayTracing"
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords"
        ]
        Resource = "*"
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# KMS Permissions (conditional)
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_kms_specific" {
  count = var.has_kms_key ? 1 : 0
  name  = "${local.function_name}-kms"
  role  = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "KMSOperations"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = local.kms_key_arn
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_kms_wildcard" {
  count = !var.has_kms_key ? 1 : 0
  name  = "${local.function_name}-kms"
  role  = aws_iam_role.lambda.id

  # When no explicit KMS key is provided, Secrets Manager uses the AWS-managed
  # key (aws/secretsmanager). We must use Resource="*" because the key ARN isn't
  # known at plan time. ViaService + CallerAccount restrict to same-account
  # Secrets Manager operations only.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "KMSOperations"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService"    = "secretsmanager.${data.aws_region.current.id}.amazonaws.com"
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# ==============================================================================
# EventBridge - Daily Renewal Scan
# ==============================================================================

resource "aws_cloudwatch_event_rule" "renewal_scan" {
  name                = "${var.name_prefix}-custom-domain-cert-renewal"
  description         = "Daily scan for custom domain certificates approaching expiry"
  schedule_expression = "rate(1 day)"

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-custom-domain-cert-renewal"
  })
}

resource "aws_cloudwatch_event_target" "renewal_scan" {
  rule = aws_cloudwatch_event_rule.renewal_scan.name
  arn  = aws_lambda_function.cert_manager.arn

  input = jsonencode({
    type = "renewal_scan"
  })
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cert_manager.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.renewal_scan.arn
}

# ==============================================================================
# CloudWatch Alarms
# ==============================================================================

# Alarm for Lambda errors
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.name_prefix}-custom-domain-cert-manager-errors"
  alarm_description   = "Custom domain certificate manager Lambda errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.cert_manager.function_name
  }

  alarm_actions = [local.sns_topic_arn]
  ok_actions    = [local.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-custom-domain-cert-manager-errors"
  })
}

# Alarm for cert provisioning failures (custom metric)
resource "aws_cloudwatch_metric_alarm" "cert_provisioning_failures" {
  alarm_name          = "${var.name_prefix}-custom-domain-cert-provisioning-failures"
  alarm_description   = "Custom domain certificate provisioning failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ProvisioningFailures"
  namespace           = "NHP/CustomDomainCerts"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  alarm_actions = [local.sns_topic_arn]
  ok_actions    = [local.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-custom-domain-cert-provisioning-failures"
  })
}

# ==============================================================================
# Data Sources
# ==============================================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
