# Developer Portal - Credential Provisioner Lambda
#
# Handles developer credential registration and email verification.
# Creates Auth0 M2M applications and sends API keys via email.

# ==============================================================================
# Lambda Package
# ==============================================================================

data "archive_file" "credentials" {
  type        = "zip"
  source_file = "${path.module}/lambda/credential_provisioner.py"
  output_path = "${path.module}/lambda/credential_provisioner.zip"
}

# ==============================================================================
# Lambda Function
# ==============================================================================

resource "aws_lambda_function" "credentials" {
  depends_on = [aws_cloudwatch_log_group.credentials]

  filename         = data.archive_file.credentials.output_path
  function_name    = "${var.name_prefix}-credential-provisioner"
  role             = aws_iam_role.credentials.arn
  handler          = "credential_provisioner.lambda_handler"
  source_code_hash = data.archive_file.credentials.output_base64sha256
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = merge(
      {
        AUTH0_MGMT_SECRET_NAME     = var.auth0_mgmt_secret_name
        CREDENTIALS_TABLE_NAME     = aws_dynamodb_table.credentials.name
        RATE_TABLE_NAME            = aws_dynamodb_table.rate_limits.name
        FROM_EMAIL                 = var.from_email
        NOTIFY_EMAIL               = var.notify_email
        SITE_URL                   = var.site_url
        VERIFY_URL                 = var.verify_url
        ALLOWED_ORIGINS            = join(",", var.allowed_origins)
        AUTH0_DOMAIN               = var.auth0_domain
        QURL_API_AUDIENCE          = var.qurl_api_audience
        SES_REGION                 = var.ses_region
        REGISTRATION_RATE_LIMIT_IP = tostring(var.registration_rate_limit_ip)
        REGISTRATION_RATE_WINDOW   = tostring(var.registration_rate_window)
        VERIFY_RATE_LIMIT_IP       = tostring(var.verify_rate_limit_ip)
        VERIFY_RATE_WINDOW         = tostring(var.verify_rate_window)
      },
      var.ci_bypass_secret_name != null ? {
        CI_BYPASS_SECRET_NAME = var.ci_bypass_secret_name
      } : {}
    )
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-credential-provisioner"
    Component = local.component
  })
}

# ==============================================================================
# CloudWatch Log Group
# ==============================================================================

resource "aws_cloudwatch_log_group" "credentials" {
  name              = "/aws/lambda/${var.name_prefix}-credential-provisioner"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-credential-provisioner-logs"
    Component = local.component
  })
}

# ==============================================================================
# IAM Role
# ==============================================================================

resource "aws_iam_role" "credentials" {
  name = "${var.name_prefix}-credential-provisioner-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-credential-provisioner-role"
    Component = local.component
  })
}

resource "aws_iam_role_policy_attachment" "credentials_basic" {
  role       = aws_iam_role.credentials.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "credentials_xray" {
  role       = aws_iam_role.credentials.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy" "credentials" {
  name = "${var.name_prefix}-credential-provisioner-policy"
  role = aws_iam_role.credentials.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "DynamoDBCredentials"
          Effect = "Allow"
          Action = [
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:DeleteItem",
            "dynamodb:Query"
          ]
          Resource = [
            aws_dynamodb_table.credentials.arn,
            aws_dynamodb_table.rate_limits.arn
          ]
        },
        {
          Sid      = "SecretsManagerAuth0"
          Effect   = "Allow"
          Action   = ["secretsmanager:GetSecretValue"]
          Resource = "arn:aws:secretsmanager:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:secret:${var.auth0_mgmt_secret_name}-*"
        },
        {
          Sid      = "CloudWatchMetrics"
          Effect   = "Allow"
          Action   = ["cloudwatch:PutMetricData"]
          Resource = "*"
          Condition = {
            StringEquals = {
              "cloudwatch:namespace" = "LayerV/DeveloperPortal"
            }
          }
        },
        {
          Sid    = "SESEmail"
          Effect = "Allow"
          Action = [
            "ses:SendEmail",
            "ses:SendRawEmail"
          ]
          Resource = "*"
          Condition = {
            StringEquals = {
              "ses:FromAddress" = var.from_email
            }
          }
        }
      ],
      var.dynamodb_kms_key_arn != null ? [
        {
          Sid    = "KMSDecrypt"
          Effect = "Allow"
          Action = [
            "kms:Decrypt",
            "kms:GenerateDataKey"
          ]
          Resource = var.dynamodb_kms_key_arn
        }
      ] : [],
      var.ci_bypass_secret_name != null ? [
        {
          Sid      = "SecretsManagerCIBypass"
          Effect   = "Allow"
          Action   = ["secretsmanager:GetSecretValue"]
          Resource = "arn:aws:secretsmanager:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:secret:${var.ci_bypass_secret_name}-*"
        }
      ] : []
    )
  })
}

# ==============================================================================
# CloudWatch Alarm (optional)
# ==============================================================================

resource "aws_cloudwatch_metric_alarm" "credentials_errors" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-credential-provisioner-errors"
  alarm_description   = "Credential provisioner Lambda function errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.credentials.function_name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-credential-provisioner-errors"
    Component = local.component
  })
}
