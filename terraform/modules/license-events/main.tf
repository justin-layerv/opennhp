# License Events Module
# SNS topic and SQS queues for license change notifications
#
# Architecture:
# Console API → SNS Topic → SQS Queue → QURL Service
#
# Events:
# - license.created: New license provisioned
# - license.updated: License tier changed (upgrade/downgrade)
# - license.deleted: License revoked
#
# The QURL service subscribes to the SQS queue and invalidates
# its in-memory license cache when events are received.

# ==================== Data Sources ====================

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# ==================== Locals ====================

locals {
  # Include cell_id in both names for multi-cell deployment consistency
  topic_name = "${var.name_prefix}-${var.cell_id}-license-events"
  queue_name = "${var.name_prefix}-${var.cell_id}-license-events-queue"
}

# ==================== SNS Topic ====================

resource "aws_sns_topic" "license_events" {
  name              = local.topic_name
  kms_master_key_id = var.kms_key_arn

  tags = merge(var.tags, {
    Name      = local.topic_name
    Component = "license-events"
  })
}

# Topic policy allowing console service to publish
resource "aws_sns_topic_policy" "license_events" {
  arn = aws_sns_topic.license_events.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowConsolePublish"
        Effect = "Allow"
        Principal = {
          AWS = var.console_service_role_arn
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.license_events.arn
      },
      {
        Sid    = "AllowSQSSubscribe"
        Effect = "Allow"
        Principal = {
          Service = "sqs.amazonaws.com"
        }
        Action   = "sns:Subscribe"
        Resource = aws_sns_topic.license_events.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sqs_queue.license_events.arn
          }
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# ==================== SQS Queue ====================

# Main queue for license events
resource "aws_sqs_queue" "license_events" {
  name = local.queue_name
  # Visibility timeout should be >= consumer processing time to prevent duplicate delivery.
  # QURL service processes license events quickly (<5s typical), so 60s provides ample margin.
  # If consumer timeout increases, this should be adjusted accordingly.
  visibility_timeout_seconds = 60
  message_retention_seconds  = 86400 # 1 day
  receive_wait_time_seconds  = 20    # Long polling

  # Encryption
  kms_master_key_id = var.kms_key_arn

  # Dead letter queue
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.license_events_dlq.arn
    maxReceiveCount     = 3
  })

  tags = merge(var.tags, {
    Name      = local.queue_name
    Component = "license-events"
    Cell      = var.cell_id
  })
}

# Dead letter queue for failed messages
resource "aws_sqs_queue" "license_events_dlq" {
  name                      = "${local.queue_name}-dlq"
  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = var.kms_key_arn

  tags = merge(var.tags, {
    Name      = "${local.queue_name}-dlq"
    Component = "license-events"
    Cell      = var.cell_id
  })
}

# Queue policy allowing SNS to send messages
resource "aws_sqs_queue_policy" "license_events" {
  queue_url = aws_sqs_queue.license_events.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSNSMessages"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.license_events.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.license_events.arn
          }
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# ==================== SNS Subscription ====================

resource "aws_sns_topic_subscription" "license_events_sqs" {
  topic_arn = aws_sns_topic.license_events.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.license_events.arn

  # Disable raw message delivery (keep SNS envelope with metadata)
  raw_message_delivery = false
}

# ==================== CloudWatch Alarm ====================

# Alarm for DLQ messages (indicates processing failures)
resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  count = var.enable_dlq_alarm ? 1 : 0

  alarm_name          = "${local.queue_name}-dlq-messages"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "License events DLQ has messages - check for processing failures"

  dimensions = {
    QueueName = aws_sqs_queue.license_events_dlq.name
  }

  alarm_actions = var.alarm_sns_topic_arn != null ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name      = "${local.queue_name}-dlq-alarm"
    Component = "license-events"
    Cell      = var.cell_id
  })
}
