# Billing - EventBridge Scheduled Rules
#
# Scheduled rules for background billing tasks:
# - Daily usage reconciliation
# - Hourly payment grace period checks

# ==============================================================================
# Daily Reconciliation
# ==============================================================================

resource "aws_cloudwatch_event_rule" "reconciliation" {
  name                = "${var.name_prefix}-billing-reconciliation"
  description         = "Daily billing usage reconciliation"
  schedule_expression = "rate(1 day)"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-reconciliation"
    Component = local.component
  })
}

resource "aws_cloudwatch_event_target" "reconciliation" {
  rule = aws_cloudwatch_event_rule.reconciliation.name
  arn  = aws_lambda_function.reconciliation.arn
}

resource "aws_lambda_permission" "reconciliation_events" {
  statement_id  = "AllowCloudWatchEventsInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.reconciliation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.reconciliation.arn
}

# ==============================================================================
# Hourly Payment Grace Check
# ==============================================================================

resource "aws_cloudwatch_event_rule" "payment_grace" {
  name                = "${var.name_prefix}-billing-payment-grace"
  description         = "Hourly payment grace period check"
  schedule_expression = "rate(1 hour)"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-payment-grace"
    Component = local.component
  })
}

resource "aws_cloudwatch_event_target" "payment_grace" {
  rule = aws_cloudwatch_event_rule.payment_grace.name
  arn  = aws_lambda_function.payment_grace.arn
}

resource "aws_lambda_permission" "payment_grace_events" {
  statement_id  = "AllowCloudWatchEventsInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.payment_grace.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.payment_grace.arn
}
