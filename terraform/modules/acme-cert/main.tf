# ==============================================================================
# ACME Certificate Manager Module
# ==============================================================================
#
# Provides centralized TLS certificate management for AC fleet using Let's Encrypt.
# Certificates are stored in AWS Secrets Manager and fetched by AC instances on boot.
#
# NOTE: This is an interim solution for scalable certificate management.
# For production at scale, consider migrating to HashiCorp Vault PKI which provides:
# - Internal CA (no external dependencies)
# - Short-lived certificates (hours vs 90 days)
# - Dynamic certificate issuance
# - Better revocation support
# See: docs/VAULT_PKI_MIGRATION.md (TODO)
#
# Security features:
# - Private keys generated in Lambda, never in Terraform state
# - KMS CMK encryption for all secrets
# - Least-privilege IAM roles
# - Comprehensive audit logging via CloudTrail
# - Automated renewal with alerting
#
# Usage:
#   module "acme_cert" {
#     source = "../modules/acme-cert"
#
#     name_prefix         = "layerv-nhp-sandbox"
#     environment         = "sandbox"
#     domains             = ["nhp.layerv.xyz", "*.nhp.layerv.xyz"]
#     hosted_zone_id      = "Z1234567890ABC"
#     acme_email          = "admin@layerv.xyz"
#     use_production_acme = true
#     kms_key_arn         = module.kms.secrets_kms_key_arn
#     alert_emails        = ["alerts@layerv.ai"]
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

  # Resource naming
  function_name = "${var.name_prefix}-acme-cert-manager"
  secret_name   = "${var.name_prefix}-tls-certificate"

  # KMS key - use provided or create new
  kms_key_arn = var.kms_key_arn != null ? var.kms_key_arn : (var.create_kms_key ? aws_kms_key.cert[0].arn : null)

  # SNS topic - use provided or create new
  sns_topic_arn = var.existing_sns_topic_arn != null ? var.existing_sns_topic_arn : aws_sns_topic.alerts[0].arn

  # Common tags
  common_tags = merge(var.tags, {
    Module      = "acme-cert"
    Environment = var.environment
  })
}

# ==============================================================================
# KMS Key (Optional - if not using existing)
# ==============================================================================

resource "aws_kms_key" "cert" {
  count = var.create_kms_key ? 1 : 0

  description             = "KMS key for ${var.name_prefix} TLS certificate encryption"
  deletion_window_in_days = local.is_prod ? 30 : 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowRootAccount"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowSecretsManager"
        Effect = "Allow"
        Principal = {
          Service = "secretsmanager.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowLambda"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda.arn
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-cert-kms"
  })
}

resource "aws_kms_alias" "cert" {
  count = var.create_kms_key ? 1 : 0

  name          = "alias/${var.name_prefix}-cert"
  target_key_id = aws_kms_key.cert[0].key_id
}

# ==============================================================================
# Secrets Manager - Certificate Storage
# ==============================================================================

resource "aws_secretsmanager_secret" "certificate" {
  name                    = local.secret_name
  description             = "TLS certificate for ${join(", ", var.domains)}"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = local.kms_key_arn

  tags = merge(local.common_tags, {
    Name    = local.secret_name
    Domains = join(",", var.domains)
  })
}

# Initial placeholder - Lambda will populate with real cert
resource "aws_secretsmanager_secret_version" "certificate_placeholder" {
  secret_id = aws_secretsmanager_secret.certificate.id
  secret_string = jsonencode({
    status  = "pending"
    message = "Certificate not yet generated. Invoke Lambda to generate."
    domains = var.domains
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ACME account key secret - persists account across Lambda invocations
# This prevents hitting Let's Encrypt's account creation rate limits
resource "aws_secretsmanager_secret" "acme_account" {
  name                    = "${var.name_prefix}-acme-account"
  description             = "ACME account key for Let's Encrypt (persisted across Lambda invocations)"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = local.kms_key_arn

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-acme-account"
  })
}

# ==============================================================================
# SNS Topic for Alerts
# ==============================================================================

resource "aws_sns_topic" "alerts" {
  count = var.existing_sns_topic_arn == null ? 1 : 0

  name              = "${var.name_prefix}-acme-cert-alerts"
  kms_master_key_id = local.kms_key_arn

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-acme-cert-alerts"
  })
}

resource "aws_sns_topic_subscription" "email" {
  for_each = var.existing_sns_topic_arn == null ? toset(var.alert_emails) : toset([])

  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = each.value
}

# ==============================================================================
# Lambda Function - Certificate Manager
# ==============================================================================

# NOTE: We use third-party Klayers (https://github.com/keithrozario/Klayers) for
# Python cryptography, acme, and dnspython libraries. These are version-pinned
# but hosted in account 770693421928. If these become unavailable, you'll need to
# build and host your own layers. See docs/design/CERTIFICATE_MANAGEMENT.md.

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/.terraform/lambda-acme-cert.zip"
}

resource "aws_lambda_function" "cert_manager" {
  function_name = local.function_name
  description   = "ACME certificate manager for ${join(", ", var.domains)}"
  role          = aws_iam_role.lambda.arn

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  handler          = "acme_cert_manager.handler"
  runtime          = "python3.12"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory

  # Use AWS-provided cryptography layer
  layers = [
    "arn:aws:lambda:${data.aws_region.current.id}:770693421928:layer:Klayers-p312-cryptography:5",
    "arn:aws:lambda:${data.aws_region.current.id}:770693421928:layer:Klayers-p312-acme:1",
    "arn:aws:lambda:${data.aws_region.current.id}:770693421928:layer:Klayers-p312-dnspython:1"
  ]

  environment {
    variables = {
      DOMAINS                    = join(",", var.domains)
      SECRET_ARN                 = aws_secretsmanager_secret.certificate.arn
      ACME_ACCOUNT_SECRET_ARN    = aws_secretsmanager_secret.acme_account.arn
      KMS_KEY_ARN                = local.kms_key_arn
      ACME_EMAIL                 = var.acme_email
      ACME_DIRECTORY             = local.acme_directory
      HOSTED_ZONE_ID             = var.hosted_zone_id
      RENEWAL_DAYS_BEFORE_EXPIRY = tostring(var.renewal_days_before_expiry)
      SNS_TOPIC_ARN              = local.sns_topic_arn
    }
  }

  # VPC configuration (optional)
  dynamic "vpc_config" {
    for_each = var.vpc_id != null ? [1] : []
    content {
      subnet_ids         = var.subnet_ids
      security_group_ids = var.security_group_ids
    }
  }

  # Ensure we don't accidentally log sensitive data
  tracing_config {
    mode = "Active"
  }

  reserved_concurrent_executions = 1 # Prevent concurrent certificate operations

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
  retention_in_days = var.lambda_log_retention_days
  kms_key_id        = local.kms_key_arn

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

      # Secrets Manager - Read/Write certificate secret
      {
        Sid    = "SecretsManagerCertificate"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = aws_secretsmanager_secret.certificate.arn
      },

      # Secrets Manager - Read/Write ACME account key (persisted across invocations)
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

      # KMS - Encrypt/Decrypt secrets
      {
        Sid    = "KMSOperations"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = local.kms_key_arn != null ? [local.kms_key_arn] : ["*"]
        Condition = local.kms_key_arn == null ? {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${data.aws_region.current.id}.amazonaws.com"
          }
        } : null
      },

      # Route 53 - DNS-01 Challenge
      {
        Sid    = "Route53DNSChallenge"
        Effect = "Allow"
        Action = [
          "route53:ChangeResourceRecordSets",
          "route53:ListResourceRecordSets"
        ]
        Resource = "arn:aws:route53:::hostedzone/${var.hosted_zone_id}"
      },
      {
        Sid    = "Route53GetChange"
        Effect = "Allow"
        Action = [
          "route53:GetChange"
        ]
        Resource = "arn:aws:route53:::change/*"
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

      # CloudWatch - Publish certificate expiry metric
      {
        Sid    = "CloudWatchMetrics"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "NHP/Certificates"
          }
        }
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

# VPC execution policy (if Lambda in VPC)
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  count      = var.vpc_id != null ? 1 : 0
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# ==============================================================================
# EventBridge - Scheduled Renewal
# ==============================================================================

resource "aws_cloudwatch_event_rule" "renewal" {
  name                = "${var.name_prefix}-acme-cert-renewal"
  description         = "Trigger certificate renewal check for ${join(", ", var.domains)}"
  schedule_expression = var.renewal_schedule

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-acme-cert-renewal"
  })
}

resource "aws_cloudwatch_event_target" "renewal" {
  rule = aws_cloudwatch_event_rule.renewal.name
  arn  = aws_lambda_function.cert_manager.arn

  input = jsonencode({
    type = "scheduled"
  })
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cert_manager.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.renewal.arn
}

# ==============================================================================
# CloudWatch Alarms
# ==============================================================================

# Alarm for Lambda errors
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.name_prefix}-acme-cert-manager-errors"
  alarm_description   = "ACME certificate manager Lambda errors"
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
    Name = "${var.name_prefix}-acme-cert-manager-errors"
  })
}

# Alarm for certificate expiry (custom metric published by Lambda)
resource "aws_cloudwatch_metric_alarm" "cert_expiry" {
  alarm_name          = "${var.name_prefix}-tls-cert-expiry"
  alarm_description   = "TLS certificate expiring soon for ${join(", ", var.domains)}"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "DaysUntilExpiry"
  namespace           = "NHP/Certificates"
  period              = 86400 # 1 day
  statistic           = "Minimum"
  threshold           = var.renewal_days_before_expiry
  treat_missing_data  = "breaching" # Missing data means we can't verify cert status

  dimensions = {
    SecretArn = aws_secretsmanager_secret.certificate.arn
  }

  alarm_actions = [local.sns_topic_arn]
  ok_actions    = [local.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-tls-cert-expiry"
  })
}

# ==============================================================================
# Data Sources
# ==============================================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
