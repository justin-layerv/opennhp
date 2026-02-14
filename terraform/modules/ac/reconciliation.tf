# ==================== AC Secret Reconciliation ====================
#
# Scheduled Lambda that cleans up orphaned per-instance AC secrets.
# AC instances create Secrets Manager entries at boot (private keys),
# but these are never cleaned up on termination. This reconciliation
# runs daily, compares secrets against live instances, and deletes orphans.

# ==================== Lambda Package ====================

data "archive_file" "secret_reconciliation" {
  count = var.enable_secret_reconciliation ? 1 : 0

  type        = "zip"
  source_file = "${path.module}/lambda/ac_secret_reconciliation.py"
  output_path = "${path.module}/lambda/ac_secret_reconciliation.zip"
}

# ==================== CloudWatch Log Group ====================

resource "aws_cloudwatch_log_group" "secret_reconciliation" {
  count = var.enable_secret_reconciliation ? 1 : 0

  name              = "/aws/lambda/${var.name_prefix}-ac-secret-reconciliation"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-secret-reconciliation-logs"
    Component = "ac"
  })
}

# ==================== Lambda Function ====================

resource "aws_lambda_function" "secret_reconciliation" {
  count = var.enable_secret_reconciliation ? 1 : 0

  # Ensure log group is created first with KMS encryption and retention settings
  # Without this, Lambda auto-creates a log group without encryption
  depends_on = [aws_cloudwatch_log_group.secret_reconciliation]

  filename         = data.archive_file.secret_reconciliation[0].output_path
  function_name    = "${var.name_prefix}-ac-secret-reconciliation"
  role             = aws_iam_role.secret_reconciliation[0].arn
  handler          = "ac_secret_reconciliation.handler"
  source_code_hash = data.archive_file.secret_reconciliation[0].output_base64sha256
  runtime          = "python3.11"
  timeout          = 120
  memory_size      = 128

  environment {
    variables = {
      SECRET_PREFIXES      = jsonencode(["${var.name_prefix}-ac-i-", "${var.name_prefix}-console-ac-i-"])
      RECOVERY_WINDOW_DAYS = local.is_prod ? "7" : "0"
      ENVIRONMENT          = var.environment
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-secret-reconciliation"
    Component = "ac"
  })
}

# ==================== IAM Role ====================

resource "aws_iam_role" "secret_reconciliation" {
  count = var.enable_secret_reconciliation ? 1 : 0

  name = "${var.name_prefix}-ac-secret-reconciliation"

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

# ==================== IAM Policies ====================

# Secrets Manager access: list all secrets, delete only AC per-instance secrets
resource "aws_iam_role_policy" "secret_reconciliation_secrets" {
  count = var.enable_secret_reconciliation ? 1 : 0

  name = "secrets-access"
  role = aws_iam_role.secret_reconciliation[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid      = "ListSecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:ListSecrets"]
        Resource = "*"
      },
      {
        Sid    = "DeleteOrphanedSecrets"
        Effect = "Allow"
        Action = ["secretsmanager:DeleteSecret"]
        Resource = [
          "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:${var.name_prefix}-ac-i-*",
          "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:${var.name_prefix}-console-ac-i-*"
        ]
      }
      ], var.secrets_kms_key_arn != null ? [{
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = [var.secrets_kms_key_arn]
    }] : [])
  })
}

# EC2 read-only access for checking instance state
resource "aws_iam_role_policy" "secret_reconciliation_ec2" {
  count = var.enable_secret_reconciliation ? 1 : 0

  name = "ec2-describe"
  role = aws_iam_role.secret_reconciliation[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DescribeInstances"
        Effect   = "Allow"
        Action   = ["ec2:DescribeInstances"]
        Resource = "*"
      }
    ]
  })
}

# CloudWatch Metrics for observability
resource "aws_iam_role_policy" "secret_reconciliation_metrics" {
  count = var.enable_secret_reconciliation ? 1 : 0

  name = "cloudwatch-metrics"
  role = aws_iam_role.secret_reconciliation[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PutMetricData"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
      }
    ]
  })
}

# CloudWatch Logs via managed policy
resource "aws_iam_role_policy_attachment" "secret_reconciliation_logs" {
  count = var.enable_secret_reconciliation ? 1 : 0

  role       = aws_iam_role.secret_reconciliation[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ==================== EventBridge Schedule ====================

resource "aws_cloudwatch_event_rule" "secret_reconciliation" {
  count = var.enable_secret_reconciliation ? 1 : 0

  name                = "${var.name_prefix}-ac-secret-reconciliation"
  description         = "Daily cleanup of orphaned per-instance AC secrets"
  schedule_expression = "rate(1 day)"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-secret-reconciliation-rule"
    Component = "ac"
  })
}

resource "aws_cloudwatch_event_target" "secret_reconciliation" {
  count = var.enable_secret_reconciliation ? 1 : 0

  rule      = aws_cloudwatch_event_rule.secret_reconciliation[0].name
  target_id = "ac-secret-reconciliation"
  arn       = aws_lambda_function.secret_reconciliation[0].arn
}

resource "aws_lambda_permission" "secret_reconciliation" {
  count = var.enable_secret_reconciliation ? 1 : 0

  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.secret_reconciliation[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.secret_reconciliation[0].arn
}

# ==================== CloudWatch Alarm ====================

resource "aws_cloudwatch_metric_alarm" "secret_reconciliation_errors" {
  count = var.enable_secret_reconciliation && var.alerts_sns_topic_arn != null ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-secret-reconciliation-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "AC secret reconciliation Lambda errors - orphaned secrets may not be cleaned"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.secret_reconciliation[0].function_name
  }

  alarm_actions = [var.alerts_sns_topic_arn]
  ok_actions    = [var.alerts_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-secret-reconciliation-errors"
    Component = "ac"
  })
}

# Alarm on unexpected deletion spikes (could indicate mass instance termination or misconfiguration)
resource "aws_cloudwatch_metric_alarm" "secret_reconciliation_deletion_spike" {
  count = var.enable_secret_reconciliation && var.alerts_sns_topic_arn != null ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-secret-reconciliation-deletion-spike"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "OrphanedSecretsDeleted"
  namespace           = "LayerV/NHP"
  period              = 86400 # 1 day (matches Lambda schedule)
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "Unusually high number of orphaned AC secrets deleted - may indicate mass termination or misconfiguration"
  treat_missing_data  = "notBreaching"

  dimensions = {
    Environment = var.environment
  }

  alarm_actions = [var.alerts_sns_topic_arn]
  ok_actions    = [var.alerts_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-secret-reconciliation-deletion-spike"
    Component = "ac"
  })
}
