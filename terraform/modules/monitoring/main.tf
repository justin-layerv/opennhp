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
      },
      {
        type   = "metric"
        x      = 0
        y      = 18
        width  = 12
        height = 6
        properties = {
          title  = "AC Registration Health"
          region = data.aws_region.current.id
          metrics = [
            ["LayerV/NHP", "ACPeerCount", "Environment", var.environment, "Cell", var.cell_id, { "stat" : "Average", "label" : "AC Peers" }],
            ["LayerV/NHP", "ACRegistrationSuccess", "Environment", var.environment, "Cell", var.cell_id, { "stat" : "Sum", "label" : "Reg Success" }],
            ["LayerV/NHP", "ACRegistrationFailure", "Environment", var.environment, "Cell", var.cell_id, { "stat" : "Sum", "label" : "Reg Failure" }]
          ]
          period  = 300
          view    = "timeSeries"
          stacked = false
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
# Requires 3 consecutive minutes at zero to fire, which filters out transient
# blips during instance refresh (sandbox blue/green swaps typically recover in
# ~2 minutes). A real outage still alerts within 3 minutes. Safe for prod
# canary deploys too — canary replaces one instance at a time, so
# HealthyHostCount never hits zero during normal prod deployments.
resource "aws_cloudwatch_metric_alarm" "no_healthy_hosts" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-no-healthy-hosts"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  alarm_description   = "CRITICAL: No healthy hosts for 3 consecutive minutes"
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

# ==================== AC Registration Health (issue #239) ====================

# evaluation_periods=2 at period=600 (20 minutes total) is load-bearing:
# a single blue/green AC deploy produces ~15 minutes of zero peers while
# old ACs disconnect and new ACs boot + register (observed 2026-04-09:
# 15:49–16:04 UTC, single deploy). Back-to-back deploys extend this to
# ~35 minutes. The 20-minute window rides through a single deploy with
# margin but fires within 20 minutes if peers genuinely stay at zero
# outside of a deploy cycle.
#
# The previous threshold (3×60s = 3 minutes) fired on every deploy,
# generating false alarms during normal operations.
resource "aws_cloudwatch_metric_alarm" "ac_peer_count_low" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-ac-peer-count-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ACPeerCount"
  namespace           = "LayerV/NHP"
  period              = 600
  statistic           = "Minimum"
  threshold           = 1
  alarm_description   = "Server has zero connected AC peers for 20 minutes. Knock requests will fail. If this coincides with a deploy, the alarm should auto-resolve once ACs re-register."
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

resource "aws_cloudwatch_metric_alarm" "ac_registration_latency" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-ac-registration-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "ACRegistrationLatency"
  namespace           = "LayerV/NHP"
  period              = 300
  extended_statistic  = "p99"
  threshold           = 1000
  alarm_description   = "AC registration latency p99 exceeded 1s on server side."
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

# ============================================================================
# Server process observability: ServerPanic / ServerStartupEvent
#
# The nhp-server container's docker awslogs driver routes its stdout and
# stderr to var.server_stderr_log_group_name. Go's runtime writes panics
# directly to os.Stderr, bypassing the server's structured file logger,
# so the existing /server log group will not see a panic; this log group
# is where they surface.
#
# The two metric filters below convert specific line patterns in that
# stream into CloudWatch metrics in LayerV/NHP. The patterns are:
#
#   ServerPanic          - matches "panic:" which is what the Go
#                          runtime emits at the start of every panic
#                          stack trace (package runtime, gopanic).
#   ServerStartupEvent   - matches "NHP-Server is running!" which is
#                          the fixed banner emitted once per process
#                          start from main.go (see nhp-server banner).
#
# Both are strings we emit ourselves (Go runtime + our own main banner),
# so they are low-churn and maintained by the same team that owns the
# alarms. Any intentional change to either string updates the filter in
# the same PR.
# ============================================================================

resource "aws_cloudwatch_log_metric_filter" "server_panic" {
  name           = "${var.name_prefix}-${var.cell_id}-server-panic"
  log_group_name = var.server_stderr_log_group_name
  # Quoted to match the literal "panic:" prefix that Go's runtime
  # writes at the start of every panic. Avoids matching the word
  # "panic" used elsewhere (e.g., in application log messages).
  #
  # Coupling note: this filter assumes no application code in
  # endpoints/server/ writes the literal "panic:" to stdout. Verified
  # today — all panic-recovery paths in nhp/core/device.go route
  # through fmt.Errorf / the structured file logger, not stdout. If
  # a future contributor adds a fmt.Printf("...panic: %s...", ...)
  # call reaching stdout, this alarm will fire as a false positive.
  # The 7-day retention on the stderr group and the alarm's SNS
  # routing make such a regression noisy and quickly diagnosable.
  pattern = "\"panic:\""

  metric_transformation {
    name          = "ServerPanic"
    namespace     = "LayerV/NHP"
    value         = "1"
    default_value = "0"
    dimensions = {
      Environment = var.environment
      Cell        = var.cell_id
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "server_startup_event" {
  name           = "${var.name_prefix}-${var.cell_id}-server-startup-event"
  log_group_name = var.server_stderr_log_group_name
  # Match the banner printed once per process start. The banner is
  # written as `fmt.Printf("  %s🚀 NHP-Server%s is running!\n",
  # colorBold, colorReset)` in endpoints/server/main/main.go, so the
  # actual bytes on stdout are
  #   "  \033[1m🚀 NHP-Server\033[0m is running!\n"
  # The ANSI reset (`\033[0m`) sits between "NHP-Server" and
  # " is running!", breaking the contiguous substring. A single-quoted
  # filter for the literal phrase therefore never matches.
  # CloudWatch Logs treats space-separated quoted terms as AND, so
  # splitting into two terms catches the banner regardless of any
  # ANSI bytes (or future ornamentation) sitting between them. This
  # is the only line in the binary's output where the bold "NHP-Server"
  # substring co-occurs with "is running!", so false positives are not
  # a concern.
  pattern = "\"NHP-Server\" \"is running!\""

  metric_transformation {
    name          = "ServerStartupEvent"
    namespace     = "LayerV/NHP"
    value         = "1"
    default_value = "0"
    dimensions = {
      Environment = var.environment
      Cell        = var.cell_id
    }
  }
}

# Any panic at all is actionable. treat_missing_data=notBreaching means
# a quiet log group (no "panic:" lines) does not fire the alarm -- the
# metric filter emits 0 on each log event that does not match, which
# keeps the time series populated, but in periods with no log events at
# all the series is missing rather than zero.
resource "aws_cloudwatch_metric_alarm" "server_panic" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-server-panic"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.server_panic.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.server_panic.metric_transformation[0].namespace
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  # Kept under ~160 chars so CloudWatch console list views do not
  # truncate the description; full rationale lives in the comment
  # block above the resource.
  alarm_description = "nhp-server panic in last minute. Each panic kills the process (systemd restarts). Regression class: PR #1096."
  alarm_actions     = [aws_sns_topic.alerts.arn]
  ok_actions        = [aws_sns_topic.alerts.arn]
  # INSUFFICIENT_DATA also routes to SNS: for this alarm, the
  # stderr log group being silent for >1 minute means either no
  # instances are running (a separate deploy/capacity issue worth
  # paging on) or the awslogs driver stopped reporting, which is
  # exactly the "we can't see panics anymore" failure mode this
  # PR closes. treat_missing_data=notBreaching prevents the alarm
  # state from flipping to ALARM, but insufficient_data_actions
  # still notifies so we know about the blackout.
  insufficient_data_actions = [aws_sns_topic.alerts.arn]
  treat_missing_data        = "notBreaching"

  dimensions = {
    Environment = var.environment
    Cell        = var.cell_id
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# Fleet-wide startup counter. Threshold of 4 is chosen so a normal
# blue/green deploy (3 new instances, 3 startup events in the window)
# does not trip, while a real crash loop (observed at 5-8 restarts per
# instance per 5-minute window in the PR #1096 incident) does.
#
# If the fleet scales past 3 servers, revisit this threshold alongside
# buildServerMetricDimensions(). Per-instance alarming is a follow-up
# that requires SetGaugeFuncWithDims on the metric publisher.
#
# Known overlap scenario: if a Terraform instance refresh on the blue
# fleet coincides with a blue/green deploy spinning up the green fleet,
# the 5-minute window could see 6 startup events (3 replaced blue + 3
# new green) and trip the threshold as a false positive. The per-
# instance alarm in PR #1099 covers the same failure class without
# being sensitive to fleet-wide start bursts, so in practice that one
# is the source of truth for single-instance crash loops.
# datapoints_to_alarm = 2 below also absorbs this by requiring the
# high-startup state to persist for two consecutive 5-minute windows
# (+5 min detection latency) before paging — a real crash loop at
# 5-8 starts per instance per 5 minutes sustains comfortably above
# the threshold across both windows.
resource "aws_cloudwatch_metric_alarm" "server_crash_loop" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-server-crash-loop"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  metric_name         = aws_cloudwatch_log_metric_filter.server_startup_event.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.server_startup_event.metric_transformation[0].namespace
  period              = 300
  statistic           = "Sum"
  # Fleet of N servers × 1 start per blue/green deploy = N startup
  # events in the window. Currently N = 3, so threshold of 4 catches
  # the first crash-loop restart beyond a normal deploy. If the fleet
  # scales to N=4 this alarm must be re-tuned to N+1; a per-instance
  # alarm driven by the EMF-emitted ServerStartupEvent counter
  # (follow-up PR) will obsolete this tuning.
  threshold          = 4
  alarm_description  = "nhp-server >4 starts in 5-min window, sustained 2 windows (crash-loop; PR #1096). Normal blue/green produces 3 starts."
  alarm_actions      = [aws_sns_topic.alerts.arn]
  ok_actions         = [aws_sns_topic.alerts.arn]
  treat_missing_data = "notBreaching"

  dimensions = {
    Environment = var.environment
    Cell        = var.cell_id
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}
