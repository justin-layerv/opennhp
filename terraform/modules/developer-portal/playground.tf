# Developer Portal - Playground Proxy Lambda
#
# Proxies playground requests to the QURL API with M2M authentication.
# Enforces rate limits, TTL caps, and URL validation.

# ==============================================================================
# Lambda Package
# ==============================================================================

data "archive_file" "playground" {
  type        = "zip"
  source_file = "${path.module}/lambda/playground_proxy.py"
  output_path = "${path.module}/lambda/playground_proxy.zip"
}

# ==============================================================================
# Lambda Function
# ==============================================================================

resource "aws_lambda_function" "playground" {
  depends_on = [aws_cloudwatch_log_group.playground]

  filename         = data.archive_file.playground.output_path
  function_name    = "${var.name_prefix}-playground-proxy"
  role             = aws_iam_role.playground.arn
  handler          = "playground_proxy.lambda_handler"
  source_code_hash = data.archive_file.playground.output_base64sha256
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = merge(
      {
        QURL_API_URL                 = var.qurl_api_url
        M2M_SECRET_NAME              = var.playground_m2m_secret_name
        RATE_TABLE_NAME              = aws_dynamodb_table.rate_limits.name
        ALLOWED_ORIGINS              = join(",", var.allowed_origins)
        AUTH0_DOMAIN                 = var.auth0_domain
        PLAYGROUND_IP_RATE_LIMIT     = tostring(var.playground_ip_rate_limit)
        PLAYGROUND_GLOBAL_RATE_LIMIT = tostring(var.playground_global_rate_limit)
        RATE_WINDOW                  = tostring(var.playground_rate_window)
      },
      var.ci_bypass_secret_name != null ? {
        CI_BYPASS_SECRET_NAME = var.ci_bypass_secret_name
      } : {}
    )
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-playground-proxy"
    Component = local.component
  })
}

# ==============================================================================
# CloudWatch Log Group
# ==============================================================================

resource "aws_cloudwatch_log_group" "playground" {
  name              = "/aws/lambda/${var.name_prefix}-playground-proxy"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-playground-proxy-logs"
    Component = local.component
  })
}

# ==============================================================================
# IAM Role
# ==============================================================================

resource "aws_iam_role" "playground" {
  name = "${var.name_prefix}-playground-proxy-role"

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
    Name      = "${var.name_prefix}-playground-proxy-role"
    Component = local.component
  })
}

resource "aws_iam_role_policy_attachment" "playground_basic" {
  role       = aws_iam_role.playground.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "playground_xray" {
  role       = aws_iam_role.playground.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy" "playground" {
  name = "${var.name_prefix}-playground-proxy-policy"
  role = aws_iam_role.playground.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "DynamoDBRateLimits"
          Effect = "Allow"
          Action = [
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem"
          ]
          Resource = aws_dynamodb_table.rate_limits.arn
        },
        {
          Sid      = "SecretsManagerM2M"
          Effect   = "Allow"
          Action   = ["secretsmanager:GetSecretValue"]
          Resource = "arn:aws:secretsmanager:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:secret:${var.playground_m2m_secret_name}-*"
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

resource "aws_cloudwatch_metric_alarm" "playground_errors" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-playground-proxy-errors"
  alarm_description   = "Playground proxy Lambda function errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.playground.function_name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-playground-proxy-errors"
    Component = local.component
  })
}
