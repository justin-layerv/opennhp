# Billing - SQS Queues
#
# Usage events queue for decoupling QURL usage tracking from Stripe reporting.
# Dead-letter queue captures messages that fail processing after 3 attempts.
#
# Producer: The QURL service (Go, in the qurl repo) publishes a message to
# this queue each time a paying customer creates a QURL. The QURL service's
# IAM role needs sqs:SendMessage on this queue ARN — that permission is
# granted in the qurl repo's Terraform, not here.
#
# Consumer: The usage_reporter Lambda (this module) reads from the queue via
# an event source mapping and reports each event to Stripe as a metered
# usage record.

# ==============================================================================
# Usage Events Queue
# ==============================================================================

resource "aws_sqs_queue" "usage_events" {
  name                       = "${var.name_prefix}-billing-usage-events"
  visibility_timeout_seconds = 270   # >= 1.5x usage_reporter Lambda timeout (180s)
  message_retention_seconds  = 86400 # 1 day
  receive_wait_time_seconds  = 20    # long polling
  kms_master_key_id          = var.sqs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-usage-events"
    Component = local.component
  })
}

# ==============================================================================
# Dead-Letter Queue
# ==============================================================================

resource "aws_sqs_queue" "usage_events_dlq" {
  name                      = "${var.name_prefix}-billing-usage-events-dlq"
  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = var.sqs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-usage-events-dlq"
    Component = local.component
  })
}

# ==============================================================================
# Redrive Policy
# ==============================================================================

resource "aws_sqs_queue_redrive_policy" "usage_events" {
  queue_url = aws_sqs_queue.usage_events.id
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.usage_events_dlq.arn
    maxReceiveCount     = 3
  })
}

# ==============================================================================
# Lambda Event Source Mapping
# ==============================================================================

resource "aws_lambda_event_source_mapping" "usage_reporter" {
  event_source_arn                   = aws_sqs_queue.usage_events.arn
  function_name                      = aws_lambda_function.usage_reporter.arn
  batch_size                         = 10
  maximum_batching_window_in_seconds = 30
  function_response_types            = ["ReportBatchItemFailures"]
}

# ==============================================================================
# CloudWatch Alarms (optional)
# ==============================================================================

resource "aws_cloudwatch_metric_alarm" "usage_queue_backlog" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-billing-usage-queue-backlog"
  alarm_description   = "Usage events queue backlog growing — processing may be falling behind"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3 # 3 consecutive periods to avoid transient spikes
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.usage_events.name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-usage-queue-backlog"
    Component = local.component
  })
}

resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-billing-usage-dlq-messages"
  alarm_description   = "Messages in billing usage events dead-letter queue"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.usage_events_dlq.name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-usage-dlq-messages"
    Component = local.component
  })
}
