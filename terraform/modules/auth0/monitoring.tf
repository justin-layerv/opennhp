# CloudWatch alarms for Auth0 secret rotation Lambda
# Conditional on enable_rotation — no resources created when rotation is disabled.

# ==============================================================================
# Lambda Invocation Errors
# ==============================================================================
# Fires when the rotation Lambda encounters unhandled errors. Any single error
# is concerning because a failed rotation leaves secrets in a partial state
# (AWSPENDING exists but was never promoted to AWSCURRENT).

resource "aws_cloudwatch_metric_alarm" "rotation_lambda_errors" {
  count = var.enable_rotation && var.alarm_sns_topic_arn != null ? 1 : 0

  alarm_name          = "${var.name_prefix}-auth0-rotation-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Auth0 secret rotation Lambda invocation errors detected. Check CloudWatch logs at /aws/lambda/${var.name_prefix}-auth0-rotation for details."
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.auth0_rotation[0].function_name
  }

  alarm_actions = [var.alarm_sns_topic_arn]
  ok_actions    = [var.alarm_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-rotation-errors"
    Component = "auth0"
  })
}

# ==============================================================================
# Lambda Duration (approaching timeout)
# ==============================================================================
# The rotation Lambda has a 120s timeout. Alert when duration exceeds the
# configurable threshold (default 100s / 83%) to catch latency issues before
# they cause timeouts.

resource "aws_cloudwatch_metric_alarm" "rotation_lambda_duration" {
  count = var.enable_rotation && var.alarm_sns_topic_arn != null ? 1 : 0

  alarm_name          = "${var.name_prefix}-auth0-rotation-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = 300 # 5 minutes
  statistic           = "Maximum"
  threshold           = var.rotation_alarm_duration_threshold_ms
  alarm_description   = "Auth0 secret rotation Lambda duration exceeded ${var.rotation_alarm_duration_threshold_ms}ms (timeout is 120s). Investigate Auth0 API latency."
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.auth0_rotation[0].function_name
  }

  alarm_actions = [var.alarm_sns_topic_arn]
  ok_actions    = [var.alarm_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-rotation-duration"
    Component = "auth0"
  })
}

# ==============================================================================
# Secrets Approaching Expiry (rotation not completing on schedule)
# ==============================================================================
# Secrets Manager publishes a "DaysSinceLastRotation" metric. If the secret
# hasn't rotated within the expected window (rotation_days + grace period),
# alert so operators can investigate before credentials expire or drift.
#
# Note: This uses the AWS/SecretsManager namespace metric that AWS publishes
# automatically when rotation is configured on a secret.

resource "aws_cloudwatch_metric_alarm" "rotation_overdue" {
  count = var.enable_rotation && var.alarm_sns_topic_arn != null ? 1 : 0

  alarm_name          = "${var.name_prefix}-auth0-rotation-overdue"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "DaysSinceLastRotation"
  namespace           = "AWS/SecretsManager"
  period              = 86400 # 24 hours
  statistic           = "Maximum"
  threshold           = var.rotation_days + var.rotation_alarm_grace_days
  alarm_description   = "Auth0 backend secret has not rotated in ${var.rotation_days + var.rotation_alarm_grace_days} days (expected every ${var.rotation_days} days). Rotation may be failing silently."
  treat_missing_data  = "notBreaching"

  dimensions = {
    SecretName = aws_secretsmanager_secret.auth0_backend.name
  }

  alarm_actions = [var.alarm_sns_topic_arn]
  ok_actions    = [var.alarm_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-rotation-overdue"
    Component = "auth0"
  })
}

# ==============================================================================
# Lambda Throttles
# ==============================================================================
# The rotation Lambda uses reserved_concurrent_executions = 1. If Secrets
# Manager retries overlap, invocations get throttled. This is usually benign
# (SM retries) but sustained throttling indicates a stuck rotation.

resource "aws_cloudwatch_metric_alarm" "rotation_lambda_throttles" {
  count = var.enable_rotation && var.alarm_sns_topic_arn != null ? 1 : 0

  alarm_name          = "${var.name_prefix}-auth0-rotation-throttles"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  metric_name         = "Throttles"
  namespace           = "AWS/Lambda"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = var.rotation_alarm_throttle_threshold
  alarm_description   = "Auth0 secret rotation Lambda throttled ${var.rotation_alarm_throttle_threshold}+ times in 10 minutes. Rotation may be stuck or retrying excessively."
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.auth0_rotation[0].function_name
  }

  alarm_actions = [var.alarm_sns_topic_arn]
  ok_actions    = [var.alarm_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-rotation-throttles"
    Component = "auth0"
  })
}
