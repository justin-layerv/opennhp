# Billing - Lambda Functions
#
# Six Lambda functions for Stripe billing integration:
# 1. checkout_session  - Stripe Checkout & Portal session creation (API-facing)
# 2. stripe_webhook    - Stripe webhook event processing (API-facing)
# 3. usage_reporter    - SQS consumer, reports metered usage to Stripe
# 4. reconciliation    - Daily usage count reconciliation
# 5. payment_grace     - Hourly payment grace period enforcement
# 6. invoices          - Customer invoice retrieval (API-facing)

# ==============================================================================
# Lambda Packages
# ==============================================================================

data "archive_file" "checkout_session" {
  type        = "zip"
  source_file = "${path.module}/lambda/checkout_session.py"
  output_path = "${path.module}/lambda/checkout_session.zip"
}

data "archive_file" "stripe_webhook" {
  type        = "zip"
  source_file = "${path.module}/lambda/stripe_webhook.py"
  output_path = "${path.module}/lambda/stripe_webhook.zip"
}

data "archive_file" "usage_reporter" {
  type        = "zip"
  source_file = "${path.module}/lambda/usage_reporter.py"
  output_path = "${path.module}/lambda/usage_reporter.zip"
}

data "archive_file" "reconciliation" {
  type        = "zip"
  source_file = "${path.module}/lambda/reconciliation.py"
  output_path = "${path.module}/lambda/reconciliation.zip"
}

data "archive_file" "payment_grace" {
  type        = "zip"
  source_file = "${path.module}/lambda/payment_grace.py"
  output_path = "${path.module}/lambda/payment_grace.zip"
}

data "archive_file" "invoices" {
  type        = "zip"
  source_file = "${path.module}/lambda/invoices.py"
  output_path = "${path.module}/lambda/invoices.zip"
}

# ==============================================================================
# 1. Checkout Session Lambda (API-facing)
# ==============================================================================

resource "aws_lambda_function" "checkout_session" {
  depends_on = [aws_cloudwatch_log_group.checkout_session]

  filename         = data.archive_file.checkout_session.output_path
  function_name    = "${var.name_prefix}-billing-checkout-session"
  role             = aws_iam_role.checkout_session.arn
  handler          = "checkout_session.lambda_handler"
  source_code_hash = data.archive_file.checkout_session.output_base64sha256
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      STRIPE_SECRET_NAME   = var.stripe_secret_name
      STRIPE_API_BASE_URL  = var.stripe_api_base_url
      CUSTOMERS_TABLE_NAME = var.customers_table_name
      GROWTH_PRICE_ID      = var.growth_price_id
      BASE_FEE_PRICE_ID    = var.base_fee_price_id
      SUCCESS_URL          = var.success_url
      CANCEL_URL           = var.cancel_url
      ALLOWED_ORIGINS      = join(",", var.allowed_origins)
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-checkout-session"
    Component = local.component
  })
}

resource "aws_cloudwatch_log_group" "checkout_session" {
  name              = "/aws/lambda/${var.name_prefix}-billing-checkout-session"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-checkout-session-logs"
    Component = local.component
  })
}

# ==============================================================================
# 2. Stripe Webhook Lambda (API-facing)
# ==============================================================================

resource "aws_lambda_function" "stripe_webhook" {
  depends_on = [aws_cloudwatch_log_group.stripe_webhook]

  filename         = data.archive_file.stripe_webhook.output_path
  function_name    = "${var.name_prefix}-billing-stripe-webhook"
  role             = aws_iam_role.stripe_webhook.arn
  handler          = "stripe_webhook.lambda_handler"
  source_code_hash = data.archive_file.stripe_webhook.output_base64sha256
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      STRIPE_WEBHOOK_SECRET_NAME = var.stripe_webhook_secret_name
      STRIPE_SECRET_NAME         = var.stripe_secret_name
      STRIPE_API_BASE_URL        = var.stripe_api_base_url
      CUSTOMERS_TABLE_NAME       = var.customers_table_name
      WEBHOOK_DEDUP_TABLE_NAME   = aws_dynamodb_table.webhook_dedup.name
      SNS_TOPIC_ARN              = var.sns_topic_arn
      ALLOWED_ORIGINS            = join(",", var.allowed_origins)
      GRACE_PERIOD_DAYS          = var.grace_period_days
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-stripe-webhook"
    Component = local.component
  })
}

resource "aws_cloudwatch_log_group" "stripe_webhook" {
  name              = "/aws/lambda/${var.name_prefix}-billing-stripe-webhook"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-stripe-webhook-logs"
    Component = local.component
  })
}

# ==============================================================================
# 3. Usage Reporter Lambda (SQS consumer)
# ==============================================================================

resource "aws_lambda_function" "usage_reporter" {
  depends_on = [aws_cloudwatch_log_group.usage_reporter]

  filename         = data.archive_file.usage_reporter.output_path
  function_name    = "${var.name_prefix}-billing-usage-reporter"
  role             = aws_iam_role.usage_reporter.arn
  handler          = "usage_reporter.lambda_handler"
  source_code_hash = data.archive_file.usage_reporter.output_base64sha256
  runtime          = "python3.12"
  # batch_size=10 × 15s Stripe API timeout = 150s worst case; 180s adds headroom
  timeout     = 180
  memory_size = 128

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      STRIPE_SECRET_NAME       = var.stripe_secret_name
      STRIPE_API_BASE_URL      = var.stripe_api_base_url
      CUSTOMERS_TABLE_NAME     = var.customers_table_name
      BILLING_AUDIT_TABLE_NAME = var.billing_audit_table_name
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-usage-reporter"
    Component = local.component
  })
}

resource "aws_cloudwatch_log_group" "usage_reporter" {
  name              = "/aws/lambda/${var.name_prefix}-billing-usage-reporter"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-usage-reporter-logs"
    Component = local.component
  })
}

# ==============================================================================
# 4. Reconciliation Lambda (EventBridge scheduled)
# ==============================================================================

resource "aws_lambda_function" "reconciliation" {
  depends_on = [aws_cloudwatch_log_group.reconciliation]

  filename         = data.archive_file.reconciliation.output_path
  function_name    = "${var.name_prefix}-billing-reconciliation"
  role             = aws_iam_role.reconciliation.arn
  handler          = "reconciliation.lambda_handler"
  source_code_hash = data.archive_file.reconciliation.output_base64sha256
  runtime          = "python3.12"
  timeout          = 120
  memory_size      = 128

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      CUSTOMERS_TABLE_NAME     = var.customers_table_name
      BILLING_AUDIT_TABLE_NAME = var.billing_audit_table_name
      METRICS_NAMESPACE        = var.metrics_namespace
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-reconciliation"
    Component = local.component
  })
}

resource "aws_cloudwatch_log_group" "reconciliation" {
  name              = "/aws/lambda/${var.name_prefix}-billing-reconciliation"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-reconciliation-logs"
    Component = local.component
  })
}

# ==============================================================================
# 5. Payment Grace Lambda (EventBridge scheduled)
# ==============================================================================

resource "aws_lambda_function" "payment_grace" {
  depends_on = [aws_cloudwatch_log_group.payment_grace]

  filename         = data.archive_file.payment_grace.output_path
  function_name    = "${var.name_prefix}-billing-payment-grace"
  role             = aws_iam_role.payment_grace.arn
  handler          = "payment_grace.lambda_handler"
  source_code_hash = data.archive_file.payment_grace.output_base64sha256
  runtime          = "python3.12"
  timeout          = 120
  memory_size      = 128

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      CUSTOMERS_TABLE_NAME = var.customers_table_name
      FROM_EMAIL           = var.from_email
      SES_REGION           = var.ses_region
      STRIPE_SECRET_NAME   = var.stripe_secret_name
      STRIPE_API_BASE_URL  = var.stripe_api_base_url
      DOWNGRADE_AFTER_DAYS = var.downgrade_after_days
      METRICS_NAMESPACE    = var.metrics_namespace
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-payment-grace"
    Component = local.component
  })
}

resource "aws_cloudwatch_log_group" "payment_grace" {
  name              = "/aws/lambda/${var.name_prefix}-billing-payment-grace"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-payment-grace-logs"
    Component = local.component
  })
}

# ==============================================================================
# 6. Invoices Lambda (API-facing)
# ==============================================================================

resource "aws_lambda_function" "invoices" {
  depends_on = [aws_cloudwatch_log_group.invoices]

  filename         = data.archive_file.invoices.output_path
  function_name    = "${var.name_prefix}-billing-invoices"
  role             = aws_iam_role.invoices.arn
  handler          = "invoices.lambda_handler"
  source_code_hash = data.archive_file.invoices.output_base64sha256
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      STRIPE_SECRET_NAME   = var.stripe_secret_name
      STRIPE_API_BASE_URL  = var.stripe_api_base_url
      CUSTOMERS_TABLE_NAME = var.customers_table_name
      ALLOWED_ORIGINS      = join(",", var.allowed_origins)
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-invoices"
    Component = local.component
  })
}

resource "aws_cloudwatch_log_group" "invoices" {
  name              = "/aws/lambda/${var.name_prefix}-billing-invoices"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-invoices-logs"
    Component = local.component
  })
}

# ==============================================================================
# CloudWatch Alarms (optional)
# ==============================================================================

# User-facing Lambdas (checkout_session, invoices) use threshold=5 because
# transient client errors (invalid input, missing customer) are expected.
# Background Lambdas (webhook, usage_reporter, reconciliation, payment_grace)
# use threshold=0 because any error indicates a system problem.

resource "aws_cloudwatch_metric_alarm" "checkout_session_errors" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-billing-checkout-session-errors"
  alarm_description   = "Billing checkout session Lambda function errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 5 # User-facing — see comment above
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.checkout_session.function_name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-checkout-session-errors"
    Component = local.component
  })
}

resource "aws_cloudwatch_metric_alarm" "stripe_webhook_errors" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-billing-stripe-webhook-errors"
  alarm_description   = "Billing Stripe webhook Lambda function errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.stripe_webhook.function_name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-stripe-webhook-errors"
    Component = local.component
  })
}

resource "aws_cloudwatch_metric_alarm" "usage_reporter_errors" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-billing-usage-reporter-errors"
  alarm_description   = "Billing usage reporter Lambda function errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.usage_reporter.function_name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-usage-reporter-errors"
    Component = local.component
  })
}

resource "aws_cloudwatch_metric_alarm" "reconciliation_errors" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-billing-reconciliation-errors"
  alarm_description   = "Billing reconciliation Lambda function errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.reconciliation.function_name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-reconciliation-errors"
    Component = local.component
  })
}

resource "aws_cloudwatch_metric_alarm" "payment_grace_errors" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-billing-payment-grace-errors"
  alarm_description   = "Billing payment grace Lambda function errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.payment_grace.function_name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-payment-grace-errors"
    Component = local.component
  })
}

resource "aws_cloudwatch_metric_alarm" "invoices_errors" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-billing-invoices-errors"
  alarm_description   = "Billing invoices Lambda function errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 5 # User-facing — see comment above
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.invoices.function_name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-invoices-errors"
    Component = local.component
  })
}

# ==============================================================================
# Business Metric Alarms
# ==============================================================================

resource "aws_cloudwatch_metric_alarm" "accounts_frozen" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-billing-accounts-frozen"
  alarm_description   = "Customer accounts frozen due to payment failure or spending cap"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "AccountsFrozen"
  namespace           = var.metrics_namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-accounts-frozen"
    Component = local.component
  })
}

resource "aws_cloudwatch_metric_alarm" "usage_discrepancy" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-billing-usage-discrepancy"
  alarm_description   = "Billing usage discrepancy detected during reconciliation"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ReconciliationDiscrepanciesFound"
  namespace           = var.metrics_namespace
  period              = 86400 # Daily reconciliation
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-usage-discrepancy"
    Component = local.component
  })
}

resource "aws_cloudwatch_metric_alarm" "stripe_cancellation_failed" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-billing-stripe-cancellation-failed"
  alarm_description   = "Stripe subscription cancellation failed during downgrade — manual intervention needed"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "StripeCancellationFailed"
  namespace           = var.metrics_namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-stripe-cancellation-failed"
    Component = local.component
  })
}

resource "aws_cloudwatch_metric_alarm" "webhook_dedup_errors" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-billing-webhook-dedup-errors"
  alarm_description   = "Webhook dedup DynamoDB table system errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SystemErrors"
  namespace           = "AWS/DynamoDB"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = aws_dynamodb_table.webhook_dedup.name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-webhook-dedup-errors"
    Component = local.component
  })
}
