# Developer Portal - Auth0 Test App Cleanup Lambda
#
# Weekly Lambda that deletes orphaned Auth0 M2M applications created by
# integration tests (matching 'QURL Developer - playwright-*' older than 24h).

# ==============================================================================
# Lambda Package
# ==============================================================================

data "archive_file" "cleanup" {
  type        = "zip"
  source_file = "${path.module}/lambda/auth0_cleanup.py"
  output_path = "${path.module}/lambda/auth0_cleanup.zip"
}

# ==============================================================================
# Lambda Function
# ==============================================================================

resource "aws_lambda_function" "cleanup" {
  depends_on = [aws_cloudwatch_log_group.cleanup]

  filename         = data.archive_file.cleanup.output_path
  function_name    = "${var.name_prefix}-auth0-cleanup"
  role             = aws_iam_role.cleanup.arn
  handler          = "auth0_cleanup.lambda_handler"
  source_code_hash = data.archive_file.cleanup.output_base64sha256
  runtime          = "python3.12"
  timeout          = 300
  memory_size      = 128

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      AUTH0_MGMT_SECRET_NAME = var.auth0_mgmt_secret_name
      AUTH0_DOMAIN           = var.auth0_domain
      APP_NAME_PREFIX        = "QURL Developer - playwright-"
      MAX_AGE_HOURS          = "24"
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-cleanup"
    Component = local.component
  })
}

# ==============================================================================
# CloudWatch Log Group
# ==============================================================================

resource "aws_cloudwatch_log_group" "cleanup" {
  name              = "/aws/lambda/${var.name_prefix}-auth0-cleanup"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-cleanup-logs"
    Component = local.component
  })
}

# ==============================================================================
# IAM Role
# ==============================================================================

resource "aws_iam_role" "cleanup" {
  name = "${var.name_prefix}-auth0-cleanup-role"

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
    Name      = "${var.name_prefix}-auth0-cleanup-role"
    Component = local.component
  })
}

resource "aws_iam_role_policy_attachment" "cleanup_basic" {
  role       = aws_iam_role.cleanup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "cleanup_xray" {
  role       = aws_iam_role.cleanup.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy" "cleanup" {
  name = "${var.name_prefix}-auth0-cleanup-policy"
  role = aws_iam_role.cleanup.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid      = "SecretsManagerAuth0"
          Effect   = "Allow"
          Action   = ["secretsmanager:GetSecretValue"]
          Resource = "arn:aws:secretsmanager:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:secret:${var.auth0_mgmt_secret_name}-*"
        }
      ],
      var.logs_kms_key_arn != null ? [
        {
          Sid    = "KMSDecryptLogs"
          Effect = "Allow"
          Action = [
            "kms:Decrypt",
            "kms:GenerateDataKey"
          ]
          Resource = var.logs_kms_key_arn
        }
      ] : []
    )
  })
}

# ==============================================================================
# CloudWatch Events Rule (weekly schedule)
# ==============================================================================

resource "aws_cloudwatch_event_rule" "cleanup_schedule" {
  name                = "${var.name_prefix}-auth0-cleanup-schedule"
  description         = "Weekly cleanup of orphaned Auth0 test applications"
  schedule_expression = "cron(0 3 ? * SUN *)" # Every Sunday at 3am UTC

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-cleanup-schedule"
    Component = local.component
  })
}

resource "aws_cloudwatch_event_target" "cleanup_target" {
  rule = aws_cloudwatch_event_rule.cleanup_schedule.name
  arn  = aws_lambda_function.cleanup.arn
}

resource "aws_lambda_permission" "cleanup_events" {
  statement_id  = "AllowCloudWatchEventsInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cleanup.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cleanup_schedule.arn
}

# ==============================================================================
# CloudWatch Alarm (optional)
# ==============================================================================

resource "aws_cloudwatch_metric_alarm" "cleanup_errors" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-auth0-cleanup-errors"
  alarm_description   = "Auth0 test app cleanup Lambda function errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.cleanup.function_name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-cleanup-errors"
    Component = local.component
  })
}
