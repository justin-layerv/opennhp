# Monitoring Module
# CloudWatch Dashboard, Alarms, SNS Topic, Slack Integration

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  enable_slack = var.enable_slack_notifications && var.slack_workspace_id != "" && var.slack_channel_id != ""

  # Alarm behavior for missing data:
  # - prod: default to "breaching" (alert when metrics stop)
  # - non-prod: default to "notBreaching" (quiet during deploys)
  # Can be overridden via var.alarm_on_missing_data
  alarm_missing_data = var.alarm_on_missing_data != null ? (
    var.alarm_on_missing_data ? "breaching" : "notBreaching"
  ) : (var.environment == "prod" ? "breaching" : "notBreaching")
}

# SNS Topic for Alerts
resource "aws_sns_topic" "alerts" {
  name         = "${var.name_prefix}-${var.cell_id}-alerts"
  display_name = "NHP ${var.environment} ${var.cell_id} Alerts"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-alerts"
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# SNS Topic Policy - allows CloudWatch, EventBridge, and account to publish
resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts_policy.json
}

data "aws_iam_policy_document" "alerts_policy" {
  # Allow CloudWatch Alarms to publish
  statement {
    sid    = "AllowCloudWatchAlarms"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # Allow EventBridge to publish (for GuardDuty and other event-driven alerts)
  statement {
    sid    = "AllowEventBridge"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # Allow same-account principals to publish and subscribe
  statement {
    sid    = "AllowAccountAccess"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions = [
      "sns:Publish",
      "sns:Subscribe",
      "sns:GetTopicAttributes",
      "sns:SetTopicAttributes",
      "sns:AddPermission",
      "sns:RemovePermission",
      "sns:DeleteTopic",
      "sns:ListSubscriptionsByTopic"
    ]
    resources = [aws_sns_topic.alerts.arn]
  }
}

# Email subscriptions for CloudWatch alarm notifications (B8 alert routing)
# NOTE: Each email address must confirm the subscription via a link sent by AWS.
# Subscriptions remain "PendingConfirmation" until confirmed and will not receive alerts.
resource "aws_sns_topic_subscription" "alert_emails" {
  for_each  = toset(var.alert_emails)
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

# AWS Chatbot IAM Role for Slack integration
resource "aws_iam_role" "chatbot" {
  count = local.enable_slack ? 1 : 0
  name  = "${var.name_prefix}-${var.cell_id}-chatbot"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "chatbot.amazonaws.com"
      }
    }]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-chatbot"
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

resource "aws_iam_role_policy" "chatbot" {
  count = local.enable_slack ? 1 : 0
  name  = "chatbot-notifications"
  role  = aws_iam_role.chatbot[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:Describe*",
          "cloudwatch:Get*",
          "cloudwatch:List*"
        ]
        Resource = "*"
      }
    ]
  })
}

# AWS Chatbot Slack Channel Configuration
resource "aws_chatbot_slack_channel_configuration" "alerts" {
  count              = local.enable_slack ? 1 : 0
  configuration_name = "${var.name_prefix}-${var.cell_id}-alerts"
  iam_role_arn       = aws_iam_role.chatbot[0].arn
  slack_channel_id   = var.slack_channel_id
  slack_team_id      = var.slack_workspace_id
  sns_topic_arns     = [aws_sns_topic.alerts.arn]

  guardrail_policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
  logging_level         = "INFO"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-slack-alerts"
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "LayerV-NHP-${var.environment}-${var.cell_id}"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "NLB Active Flows"
          region = data.aws_region.current.id
          metrics = [
            ["AWS/NetworkELB", "ActiveFlowCount", "LoadBalancer", var.nlb_arn_suffix]
          ]
          period = 60
          stat   = "Sum"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "NLB Processed Bytes"
          region = data.aws_region.current.id
          metrics = [
            ["AWS/NetworkELB", "ProcessedBytes", "LoadBalancer", var.nlb_arn_suffix]
          ]
          period = 60
          stat   = "Sum"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "ASG Instance Count"
          region = data.aws_region.current.id
          metrics = [
            ["AWS/AutoScaling", "GroupInServiceInstances", "AutoScalingGroupName", var.asg_name],
            [".", "GroupDesiredCapacity", ".", "."],
            [".", "GroupMinSize", ".", "."],
            [".", "GroupMaxSize", ".", "."]
          ]
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "ASG CPU Utilization"
          region = data.aws_region.current.id
          metrics = [
            ["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", var.asg_name]
          ]
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "ASG Network Traffic"
          region = data.aws_region.current.id
          metrics = [
            ["AWS/EC2", "NetworkIn", "AutoScalingGroupName", var.asg_name],
            [".", "NetworkOut", ".", "."]
          ]
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "NHP Custom Metrics (when available)"
          region = data.aws_region.current.id
          metrics = [
            ["LayerV/NHP", "KnockRequests", "Environment", var.environment],
            [".", "AuthSuccess", ".", "."],
            [".", "AuthFailure", ".", "."]
          ]
          period = 60
          stat   = "Sum"
          view   = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "NHP Knock Latency p99 (when available)"
          region = data.aws_region.current.id
          metrics = [
            ["LayerV/NHP", "KnockLatency", "Environment", var.environment]
          ]
          period = 60
          stat   = "p99"
          view   = "timeSeries"
        }
      }
    ]
  })
}

# High CPU Alarm
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "CPU utilization exceeded 80%"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    AutoScalingGroupName = var.asg_name
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# Unhealthy Hosts Alarm
resource "aws_cloudwatch_metric_alarm" "unhealthy_hosts" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-unhealthy-hosts"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = 60
  statistic           = "Maximum"
  threshold           = 1
  alarm_description   = "More than 1 unhealthy host detected"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.nlb_arn_suffix
    TargetGroup  = var.target_group_arn_suffix
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# No Healthy Hosts Alarm (Critical)
resource "aws_cloudwatch_metric_alarm" "no_healthy_hosts" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-no-healthy-hosts"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  alarm_description   = "CRITICAL: No healthy hosts available"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = local.alarm_missing_data

  dimensions = {
    LoadBalancer = var.nlb_arn_suffix
    TargetGroup  = var.target_group_arn_suffix
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# NLB TCP Reset Count - potential connectivity issues
resource "aws_cloudwatch_metric_alarm" "tcp_resets" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-tcp-resets"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "TCP_Target_Reset_Count"
  namespace           = "AWS/NetworkELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  alarm_description   = "High TCP reset count - potential target issues"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.nlb_arn_suffix
    TargetGroup  = var.target_group_arn_suffix
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# ASG Group In Service Instances
resource "aws_cloudwatch_metric_alarm" "low_instance_count" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-low-instances"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "GroupInServiceInstances"
  namespace           = "AWS/AutoScaling"
  period              = 60
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "ASG has fewer than expected in-service instances"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = local.alarm_missing_data

  dimensions = {
    AutoScalingGroupName = var.asg_name
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# Network Traffic Anomaly - sudden drop
resource "aws_cloudwatch_metric_alarm" "network_in_low" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-network-in-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 5
  metric_name         = "NetworkIn"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 1000
  alarm_description   = "Network ingress dropped significantly - potential service issue"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    AutoScalingGroupName = var.asg_name
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# Storage Health Alarm (custom metric from application — covers etcd or DynamoDB)
resource "aws_cloudwatch_metric_alarm" "storage_health" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-storage-health"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  metric_name         = "StorageHealthy"
  namespace           = "LayerV/NHP"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  alarm_description   = "Storage backend health check failing"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    Environment = var.environment
    Cell        = var.cell_id
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# NHP Authentication Failures
resource "aws_cloudwatch_metric_alarm" "auth_failures" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-auth-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "AuthFailure"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  alarm_description   = "High rate of authentication failures"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    Environment = var.environment
    Cell        = var.cell_id
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# Knock Latency p99
resource "aws_cloudwatch_metric_alarm" "high_latency" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-high-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "KnockLatency"
  namespace           = "LayerV/NHP"
  period              = 60
  extended_statistic  = "p99"
  threshold           = 500
  alarm_description   = "NHP knock latency p99 exceeded 500ms"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    Environment = var.environment
    Cell        = var.cell_id
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# ==================== DynamoDB Monitoring ====================

# DynamoDB Throttled Requests - indicates capacity issues
resource "aws_cloudwatch_metric_alarm" "dynamodb_throttled" {
  for_each = var.enable_dynamodb_monitoring ? toset(var.dynamodb_table_names) : toset([])

  alarm_name          = "${var.name_prefix}-${var.cell_id}-dynamodb-throttled-${each.value}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ThrottledRequests"
  namespace           = "AWS/DynamoDB"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "DynamoDB table ${each.value} experiencing throttling"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = each.value
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# DynamoDB System Errors - backend errors from DynamoDB
resource "aws_cloudwatch_metric_alarm" "dynamodb_system_errors" {
  for_each = var.enable_dynamodb_monitoring ? toset(var.dynamodb_table_names) : toset([])

  alarm_name          = "${var.name_prefix}-${var.cell_id}-dynamodb-errors-${each.value}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "SystemErrors"
  namespace           = "AWS/DynamoDB"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "DynamoDB table ${each.value} experiencing system errors"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = each.value
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# DynamoDB Read Latency - high latency may indicate issues
resource "aws_cloudwatch_metric_alarm" "dynamodb_read_latency" {
  for_each = var.enable_dynamodb_monitoring ? toset(var.dynamodb_table_names) : toset([])

  alarm_name          = "${var.name_prefix}-${var.cell_id}-dynamodb-latency-${each.value}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "SuccessfulRequestLatency"
  namespace           = "AWS/DynamoDB"
  period              = 60
  statistic           = "Average"
  threshold           = 100 # 100ms - DynamoDB should be single-digit ms normally
  alarm_description   = "DynamoDB table ${each.value} read latency exceeded 100ms"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = each.value
    Operation = "GetItem"
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}
