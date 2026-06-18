# Monitoring Module
# CloudWatch Dashboard, Alarms, SNS Topic, Slack Integration

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  # When chatbot_owned_externally is true (prod after cross-repo handoff), the
  # external Chatbot config in another stack subscribes our SNS topic and we
  # skip creating our own — Chatbot's (workspace, channel) uniqueness is
  # account-wide, so two configs for the same pair can't co-exist.
  enable_slack = var.enable_slack_notifications && var.slack_workspace_id != "" && var.slack_channel_id != "" && !var.chatbot_owned_externally

  # Alarm behavior for missing data:
  # - prod: default to "breaching" (alert when metrics stop)
  # - non-prod: default to "notBreaching" (quiet during deploys)
  # Can be overridden via var.alarm_on_missing_data
  alarm_missing_data = var.alarm_on_missing_data != null ? (
    var.alarm_on_missing_data ? "breaching" : "notBreaching"
  ) : (var.environment == "prod" ? "breaching" : "notBreaching")

  # Suffix for log-filter-emitted metric names that need per-cell
  # isolation when CloudWatch Dimensions aren't available (AWS
  # rejects dimensions on substring-match filter patterns). Kept in
  # a local so the two filter blocks below, plus any future ones,
  # stay on one convention without drifting into ad-hoc interpolations.
  metric_name_suffix = "${var.environment}-${var.cell_id}"

  # Evaluation window for the server_instance_restart alarm's period
  # attribute. Sized to fit a single blue/green deploy (~3 min) with
  # margin, so a clean deploy produces one bucket of startup events
  # rather than smearing across two.
  server_restart_period_seconds = 300

  ack_token_shared_store_failure_alarms = {
    init = {
      metric_name = "ACKTokenSharedStoreInitFailure"
      suffix      = "ack-token-shared-store-init-failure"
      description = "NHP server failed to initialize the configured ACK token shared store; reverse-tunnel validation may regress to single-process scope."
    }
    write = {
      metric_name = "ACKTokenSharedStoreWriteFailure"
      suffix      = "ack-token-shared-store-write-failure"
      description = "NHP completed AC operations but failed to persist ACK token metadata; knocks fail closed with ErrServerTokenPersistFailed."
    }
    read = {
      metric_name = "ACKTokenSharedStoreReadFailure"
      suffix      = "ack-token-shared-store-read-failure"
      description = "NHP internal token validation missed the local cache and failed to read the ACK token shared store; FRPS validation returns infrastructure failure."
    }
  }

  internal_security_failure_alarms = {
    token_validate_failure = {
      metric_name = "InternalTokenValidateFailure"
      suffix      = "internal-token-validate-failure"
      threshold   = 10
      description = "NHP internal token validation returned not_found/expired more than 10 times in 5 minutes. Check CallerIP/Reason breakdown streams for token grinding, replay, or a caller routing to the wrong server."
    }
  }

  # Knock forward-path health alarms (issue #2449). Both share the
  # single-event-detector shape below (see the resource for the calibration
  # rationale); they differ only in which counter they watch. A map + for_each
  # (the ack_token_shared_store_failure_alarms pattern above) keeps their
  # identical tuning in one place so the anticipated "raise datapoints_to_alarm
  # once traffic grows" edit is a single change, not two that can drift.
  knock_forward_path_alarms = {
    # The "forward machinery broke" signal: ForwardHttpKnock errored after every
    # assigned peer failed (a non-2xx peer response — the original 400 — lands
    # here). Does NOT fire when the forward is never attempted or a peer returns
    # a structured no-AC ack over HTTP 200 — those land only on KnockNoAC.
    forward_failure = {
      metric_name = "KnockForwardFailure"
      suffix      = "knock-forward-failure"
      description = "nhp-server cross-server knock forwarding failed in the trailing hour. The forward is the no-local-AC safety net; baseline is zero (path is cold), so any failure is the first sign it is breaking and resolves risk user-facing 500s."
    }
    # The user-facing 500 driver and broad superset catch. Most plausible benign
    # single event: a back-to-back AC deploy briefly leaving an AC uncovered on
    # every replica → one self-healing 500 — correlate an isolated page with the
    # deploy timeline (cannot be tuned out at this traffic; accepted).
    no_ac = {
      metric_name = "KnockNoAC"
      suffix      = "knock-no-ac"
      description = "nhp-server served a knock with no AC in the trailing hour (user-facing 500, ErrACConnectionNotFound — neither a local AC connection nor a forward could serve it). Baseline is zero; correlate an isolated page with AC deploys."
    }
  }
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

  # Allow AWS Chatbot to subscribe this topic. Required when
  # chatbot_owned_externally = true so an external Chatbot configuration
  # (e.g., website CDK's ProdSlackChannel in us-east-1) can subscribe this
  # topic in us-east-2. The same-account-root statement above probably also
  # covers this in practice, but service-principal authority for cross-region
  # subscribes isn't formally guaranteed by the account-root path — making it
  # explicit removes that ambiguity. Statement is unconditional (also active
  # when chatbot_owned_externally = false) so an in-module Chatbot config
  # subscribe path is identically authorized.
  statement {
    sid    = "AllowChatbotSubscribe"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["chatbot.amazonaws.com"]
    }

    actions = [
      "sns:Subscribe",
      "sns:GetTopicAttributes",
      "sns:ListSubscriptionsByTopic"
    ]
    resources = [aws_sns_topic.alerts.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
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
          # Dims must be {Environment, Cell} to match the server publisher's
          # emitted stream (buildServerMetricDimensions, endpoints/server/
          # udpserver.go); an Environment-only row selects a non-existent
          # stream and renders empty. Metric is KnockRequest (singular — the
          # MetricKnockRequest constant), not KnockRequests. See #2454.
          metrics = [
            ["LayerV/NHP", "KnockRequest", "Environment", var.environment, "Cell", var.cell_id],
            [".", "AuthSuccess", ".", ".", ".", "."],
            [".", "AuthFailure", ".", ".", ".", "."]
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
          # {Environment, Cell} to match the publisher stream — see the NHP
          # Custom Metrics widget above and #2454.
          metrics = [
            ["LayerV/NHP", "KnockLatency", "Environment", var.environment, "Cell", var.cell_id]
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
      },
      {
        # Knock forward-path health (issue #2449) — surfaces the safety-net
        # forwarding whose silent 100%-failure this dashboard previously hid.
        # All three counters rest at zero (the path is cold), so the signal is
        # any line lifting off zero; see the runbook for what each means. Dims
        # {Environment, Cell} match the server publisher's stream.
        type   = "metric"
        x      = 12
        y      = 18
        width  = 12
        height = 6
        properties = {
          title  = "Knock Forward Health (when available)"
          region = data.aws_region.current.id
          metrics = [
            ["LayerV/NHP", "KnockForwardSuccess", "Environment", var.environment, "Cell", var.cell_id, { "label" : "Forward Success" }],
            [".", "KnockForwardFailure", ".", ".", ".", ".", { "label" : "Forward Failure" }],
            [".", "KnockNoAC", ".", ".", ".", ".", { "label" : "No AC (500)" }]
          ]
          period  = 300
          stat    = "Sum"
          view    = "timeSeries"
          stacked = false
        }
      },
      {
        # Server forward-send safety (issue #2679). ServerForwardTargetDrop is
        # emitted by the server publisher with {Environment, Cell}; the async
        # runtime panic recovery is log-filter-derived and bakes env/cell into
        # the metric name because quoted/JSON log-filter patterns cannot use
        # CloudWatch metric dimensions. Target Drop is healthy when absent or
        # zero; Async Runtime Panic Recovery should stay flat zero.
        type   = "metric"
        x      = 0
        y      = 24
        width  = 24
        height = 6
        properties = {
          title  = "Server Forward Safety"
          region = data.aws_region.current.id
          metrics = [
            ["LayerV/NHP", "ServerForwardTargetDrop", "Environment", var.environment, "Cell", var.cell_id, { "label" : "Target Drop" }],
            [aws_cloudwatch_log_metric_filter.server_async_runtime_panic.metric_transformation[0].namespace, aws_cloudwatch_log_metric_filter.server_async_runtime_panic.metric_transformation[0].name, { "label" : "Async Runtime Panic Recovery" }]
          ]
          period  = 300
          stat    = "Sum"
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
#
# NOTE: This dim points at the UDP TG (port 62206). NLB does not publish
# TCP_Target_Reset_Count for UDP target groups, so the metric never has
# data — combined with `treat_missing_data = "notBreaching"` below, the
# alarm reports OK forever. The HTTPS sibling below is the one that
# actually fires on origin RST events behind CloudFront's keep-alive pool.
# Kept for now to avoid breaking dashboards keyed on this alarm name; safe
# to delete in a follow-up (tracked in #1798).
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

# NLB HTTPS-TG TCP Reset Count — the dim that actually carries data for
# the resolve.qurl.link → NLB:443 → server:8888 origin path. Origin-side
# RSTs here surface as CloudFront 502s on POST /plugins/qurl when CF reuses
# a stale keep-alive (race against the server's IdleTimeout). Threshold
# matches the UDP-TG alarm for parity; tune separately once we have a
# steady-state baseline post timeout fix.
resource "aws_cloudwatch_metric_alarm" "tcp_resets_https" {
  count               = var.https_target_group_arn_suffix != null ? 1 : 0
  alarm_name          = "${var.name_prefix}-${var.cell_id}-tcp-resets-https"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "TCP_Target_Reset_Count"
  namespace           = "AWS/NetworkELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  alarm_description   = "Origin RSTs on the HTTPS target group (server :8888). Mid-stream resets here cause CloudFront 502 on resolve.qurl.link POSTs."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.nlb_arn_suffix
    TargetGroup  = var.https_target_group_arn_suffix
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# Green HTTPS TG sibling — same fence as tcp_resets_https, scoped to the
# green-color target group. Required because blue/green flips the listener
# default action between blue and green TGs (see compute/blue_green.tf::
# aws_lb_listener.https default_action_target_group_arn). Without this,
# origin RSTs that happen while green is the active color would not page.
# Mirrors the green_tg_no_healthy_targets pattern in blue_green.tf:548.
# Only created when the caller is blue/green-enabled (the green TG output
# is null in canary deployments).
resource "aws_cloudwatch_metric_alarm" "tcp_resets_https_green" {
  count               = var.https_green_target_group_arn_suffix != null ? 1 : 0
  alarm_name          = "${var.name_prefix}-${var.cell_id}-tcp-resets-https-green"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "TCP_Target_Reset_Count"
  namespace           = "AWS/NetworkELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  alarm_description   = "Origin RSTs on the GREEN HTTPS target group (server :8888). Same class as tcp-resets-https; this fence covers the post-blue/green-flip window when green serves traffic."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.nlb_arn_suffix
    TargetGroup  = var.https_green_target_group_arn_suffix
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

# Overload-cookie shared-key drift. The nhp-server publisher reports this as a
# persistent gauge with the exact base dim set {Environment, Cell}: 1 means an
# instance booted with a random per-process overload-cookie signing key, 0 means
# CookieSigningKeyBase64 was configured. Any non-zero value in a load-balanced
# cell breaks cross-instance COK->RKN verification during overload (#2611), so
# alert on the first breaching window. treat_missing_data stays notBreaching so
# brand-new envs and metric-publisher outages are handled by the existing
# publisher/heartbeat alarms rather than this sparse state signal.
resource "aws_cloudwatch_metric_alarm" "overload_cookie_process_local_key" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-overload-cookie-process-local-key"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "OverloadCookieProcessLocalKey"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Maximum"
  threshold           = 1
  alarm_description   = "nhp-server is running with a random per-process overload-cookie signing key. Multi-instance COK->RKN verification requires CookieSigningKeyBase64 to be configured consistently across the cell. #2611."
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

# Overload-cookie mint failures. Core fails closed when it cannot enqueue a
# usable COK after deciding to reject-with-cookie, so any base-counter event
# means at least one client was told to retry without receiving a cookie it can
# satisfy. The Go publisher also emits a Reason-dimensioned breakdown for
# attribution; this alarm intentionally keys on the base {Environment, Cell}
# stream so it does not miss sparse or newly-added reason values.
resource "aws_cloudwatch_metric_alarm" "overload_cookie_mint_failure" {
  alarm_name = "${var.name_prefix}-${var.cell_id}-overload-cookie-mint-failure"
  # Match the sparse-counter shape used by knock_forward_path: any non-zero
  # 5-minute bucket in the trailing hour pages, while missing data is normal.
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 12
  datapoints_to_alarm = 1
  metric_name         = "OverloadCookieMintFailure"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "nhp-server failed to mint or marshal an overload COK after returning ErrServerRejectWithCookie, so affected agents cannot complete the retry. Inspect the Reason dimension for missing_remote_binding, wrong_peer_pubkey_length, missing_cookie_store, or marshal_failed. #2611."
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

# ACK token shared-store failures. These counters are emitted by the
# nhp-server CloudWatch publisher with the exact dimension set
# {Environment, Cell}; keep the alarm dimensions in lockstep with
# buildServerMetricDimensions() in endpoints/server/udpserver.go.
resource "aws_cloudwatch_metric_alarm" "ack_token_shared_store_failure" {
  for_each = local.ack_token_shared_store_failure_alarms

  alarm_name          = "${var.name_prefix}-${var.cell_id}-${each.value.suffix}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = each.value.metric_name
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "${each.value.description} Runbook: docs/runbooks/nhp-ack-token-shared-store.md."
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

# Internal-surface security failures. The Go publisher dual-publishes
# these as:
#   - a base stream at {Environment, Cell}, which alarms can match, and
#   - dimensioned breakdown streams (CallerIP/Reason) for attribution.
resource "aws_cloudwatch_metric_alarm" "internal_security_failure" {
  for_each = local.internal_security_failure_alarms

  alarm_name          = "${var.name_prefix}-${var.cell_id}-${each.value.suffix}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = each.value.metric_name
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = each.value.threshold
  alarm_description   = each.value.description
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
    Issue     = "1140"
  })
}

# Internal-auth signer unavailable on the destructive AC revocation sweep fast
# path (issue #2475). The on-demand sweep endpoint
# (POST /nhp/internal/ac-revocations/sweep[/<acId>]) is permanently strict;
# when it is hit while the server has no NHP_INTERNAL_AUTH_SECRET configured it
# rejects with 401 BEFORE HMAC verification and emits this counter — kept
# distinct from InternalAuthFailStrict (a bad caller signature). A non-zero
# value is deployment/secret drift, not an attack, so this automates the F5
# runbook's "alert the platform owner" step (docs/runbooks/f5-revoked-pubkey-paging.md).
#
# REACTIVE by construction: the counter only increments when an operator
# actually invokes the sweep during an incident — it cannot surface the missing
# secret BEFORE the endpoint is needed. Its value is (1) paging the platform
# owner who holds the secret and may not be the operator running the sweep, and
# (2) an alarm trail. A proactive detector would need a synthetic signed probe
# (cf. the knock-forward-path synthetic-probe follow-up on #2449); out of scope
# for this low-threshold alarm.
#
# Emitted via Publisher.IncrCounter (endpoints/metrics/publisher.go) with the
# base server dim set {Environment, Cell} (buildServerMetricDimensions,
# endpoints/server/udpserver.go) — the same selector knock_forward_path /
# server_publisher_failures rely on. Key on exactly those two dims or the alarm
# sits in INSUFFICIENT_DATA forever (terraform/CLAUDE.md "Metric / Alarm
# Dim-Set Rules").
#
# Single-event detector (datapoints_to_alarm=1 over a 1-hour lookback),
# mirroring knock_forward_path: at this traffic a "consecutive nonzero windows"
# alarm could never accumulate, so one breaching 5-min window in the trailing
# hour pages. eval=12 keeps the alarm visibly RED through the incident hour and
# suppresses a re-page on operator sweep retries. treat_missing_data is
# hardcoded "notBreaching" — NOT the module's alarm_missing_data local, which
# resolves to "breaching" in prod and would turn this always-absent event
# counter into a permanent false page.
resource "aws_cloudwatch_metric_alarm" "internal_auth_signer_unavailable" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-internal-auth-signer-unavailable"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 12
  datapoints_to_alarm = 1
  metric_name         = "InternalAuthSignerUnavailable"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "nhp-server rejected an operator-triggered AC revocation sweep because NHP_INTERNAL_AUTH_SECRET is not configured (signed fast path returned 401) in the trailing hour. Deployment/secret drift, not a bad caller signature — alert the platform owner to restore the secret before depending on the on-demand sweep. Reactive: fires only once an operator hits the endpoint. Runbook: docs/runbooks/f5-revoked-pubkey-paging.md. #2475."
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

# ==================== Knock Forward Path Health (issue #2449) ====================
#
# The server-to-server HTTP knock forward is the safety net for "this server
# lacks a local AC connection": when the NLB hashes a resolve to a server with
# no local AC for the requested resource, the server forwards the knock to an
# assigned peer that does hold it (intended to cover blue/green AC-connection
# churn). That path was silently 100% broken for an unknown period — the
# forwarder shipped a request missing `resId`, every receiver replied 400, and
# the resolve fell through to a user-facing 500 (ErrACConnectionNotFound). It
# went unnoticed because neither failure signal was alarmed. These two alarms
# close that gap.
#
# Both counters are emitted via Publisher.IncrCounter (endpoints/metrics/
# publisher.go), so they carry the publisher's base dim set {Environment,
# Cell} — identical selector to buildServerMetricDimensions
# (endpoints/server/udpserver.go) and the server-publisher-failures alarm
# above. Keep the dimensions {} blocks in lockstep with it.
#
# TUNING — these are single-event detectors, by necessity. Calibration query
# (2026-06-10, prod/cell0, 13 days): KnockNoAC, KnockForwardFailure, AND
# KnockForwardSuccess were ALL flat zero; KnockRequest ran ~1-2 knocks/hour.
# Two consequences drive the shape below:
#   1. At ~1 knock/hr a "consecutive nonzero 5-min windows" alarm can never
#      accumulate — it would be permanently inert even with forwarding 100%
#      broken (the exact dead-alarm this issue exists to kill). So M-of-N with
#      datapoints_to_alarm=1 over a 1-hour lookback (eval=12 @ period=300):
#      page on the FIRST breaching 5-min window in the trailing hour.
#   2. KnockForwardSuccess=0 means the forward path was never exercised in
#      that window — it is COLD, not proven-healthy. The zero baseline does
#      NOT prove these alarms stay quiet through deploys (there were no
#      forwards to succeed or fail). Treat a single benign transient page as
#      an accepted tradeoff at this traffic, not something the data rules out.
# Raise datapoints_to_alarm (and/or threshold) once prod sustains multiple
# knocks per 5-min window and a benign transient baseline actually appears.
# Note for that retune: the two counters have different granularity —
# KnockForwardFailure increments per failed RESOURCE (inside httpserver.go's
# `for resName` loop) while KnockNoAC increments once per KNOCK, so on a
# multi-resource knock KnockForwardFailure's Sum can exceed the knock count;
# they are not directly comparable as rates. Irrelevant to these threshold>0
# single-event alarms, but it matters for a rate model.
# The reliable long-term detector for a cold path is a synthetic forward probe
# (how this bug was found); these passive counters only fire when real traffic
# happens to hit the broken path. Tracked as a follow-up on #2449.

# No composite (KnockForwardSuccess == 0 while KnockForwardFailure > 0): KnockNoAC
# is already a superset of KnockForwardFailure (it also fires when no server holds
# the AC or a forward is skipped), so this pair covers the broken-forward
# signature and user impact without a third alarm. Per-counter semantics are on
# the knock_forward_path_alarms map entries.
resource "aws_cloudwatch_metric_alarm" "knock_forward_path" {
  for_each = local.knock_forward_path_alarms

  alarm_name = "${var.name_prefix}-${var.cell_id}-${each.value.suffix}"
  # `> 0` (rather than the ack-token map's `>= 1`) deliberately matches
  # server_publisher_failures — the behavioral sibling whose sparse-counter +
  # datapoints_to_alarm + notBreaching shape these alarms mirror. Identical to
  # `>= 1` for an integer Sum counter; we copy ack-token only for the for_each
  # structure, not its single-period tuning.
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 12
  datapoints_to_alarm = 1
  metric_name         = each.value.metric_name
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "${each.value.description} Runbook: docs/runbooks/knock-forward-path.md. #2449."
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

# ART replay-gate drops (#2513). nhp-server emits ARTReplayGateDrop when the
# per-connection strict-less-than replay gate drops a matched NHP_ART packet,
# i.e. a live knock transaction was affected. It is an availability signal, not
# just a replay-defense signal: a nonzero rate during bursty legitimate knocks
# means the strict gate is too twitchy and should be loosened while the ART
# dedupe cache remains the replay defense.
#
# DIM SET — {Environment, Cell}: emitted via Publisher.IncrCounter from
# endpoints/server/udpserver.go with buildServerMetricDimensions(), matching the
# other server sparse-counter alarms in this module.
#
# SHAPE — same traffic-gated sparse-counter detector as knock_forward_path:
# page on the first breaching 5-minute bucket in a trailing hour, then tune only
# after real traffic establishes a benign baseline.
resource "aws_cloudwatch_metric_alarm" "art_replay_gate_drop" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-art-replay-gate-drop"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 12
  datapoints_to_alarm = 1
  metric_name         = "ARTReplayGateDrop"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "nhp-server dropped >=1 matched NHP_ART packet at the replay gate in the trailing hour. This can fail a live knock; if it appears during legitimate burst traffic, loosen the strict replay gate tolerance while keeping the ART dedupe cache. #2513."
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
    Issue     = "2513"
  })
}

# Server-forward target drops (issue #2679, follow-up from PR #2673). The
# counter increments when the server-to-server NHP_FWD send path refuses to
# synthesize/reuse ConnData because the peer tuple is not a safe configured
# server target or because that UDP tuple is owned by a non-promotable
# AC/DB/WebRTC connection. Steady state is exactly zero; a non-zero value means
# assignment/peer-map drift or a tuple-owner collision that would otherwise only
# live in logs.
#
# DIM SET: {Environment, Cell}, emitted via Publisher.IncrCounter with the
# server publisher's base dimensions (buildServerMetricDimensions in
# endpoints/server/udpserver.go). Keep this selector in lockstep with the Go
# publisher.
#
# SHAPE: same sparse-counter, single-event detector as knock_forward_path. The
# failure class is traffic-gated and should never happen in steady state, so one
# breaching 5-minute bucket in the trailing hour is actionable.
resource "aws_cloudwatch_metric_alarm" "server_forward_target_drop" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-server-forward-target-drop"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 12
  datapoints_to_alarm = 1
  metric_name         = "ServerForwardTargetDrop"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "nhp-server dropped >=1 outbound NHP_FWD target in the trailing hour. Steady state is zero; investigate server assignment/peer-map drift or a tuple-owner collision. Runbook: docs/runbooks/server-forward-safety.md. #2679 / PR #2673."
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
    Issue     = "2679"
  })
}

# Relay-forward rejects: "relay enabled but forwards rejected" (#2643, part of
# #2208). nhp-server emits RelayForwardReject (MetricRelayForwardReject,
# endpoints/server/relay.go) on every NHP_RLY forward it drops PRE-AUTH — most
# operationally, the empty-relayPeerMap rejection (relay.go lookupRelayPeer
# gate) that a server booting WITHOUT relay.toml produces. The boot trap: with
# deploy_relay=true a transient Secrets Manager / IAM-lag failure makes
# user_data skip writing relay.toml, the server starts with a nil relayPeerMap,
# and it rejects EVERY relayed knock while only logging a user-data WARNING — a
# silent misconfiguration. A sustained nonzero rate while the relay is wired is
# also an attack signal (a non-relay peer injecting NHP_RLY, or a spoofed
# SourceAddr). Either way: page.
#
# DIM SET — {Environment, Cell}: emitted via Publisher.IncrCounter
# (endpoints/metrics/publisher.go) with the publisher's base dims only (no extra
# dims), i.e. EXACTLY buildServerMetricDimensions() in
# endpoints/server/udpserver.go. Identical selector to knock_forward_path /
# server_publisher_failures above. Keep this dimensions{} block in lockstep with
# buildServerMetricDimensions() — a wrong/partial dim set sits in
# INSUFFICIENT_DATA forever and never pages (terraform/CLAUDE.md "Metric / Alarm
# Dim-Set Rules"); `terraform validate` cannot catch a dim mismatch.
#
# SHAPE — single-event detector matching knock_forward_path, NOT the relay
# module's bootstrap-failure (eval=1) shape. BootstrapFailure is boot-driven
# (emits reliably the instant an instance fails to boot), so one 5-min window
# suffices. RelayForwardReject is TRAFFIC-gated and sparse — same profile as
# KnockForwardFailure (prod knock traffic ~1-2/hr, repo memory). At that rate a
# single 5-min window would flap between sparse rejects and sit OK in most
# windows even during an active misconfiguration, so we use the
# knock_forward_path lookback: datapoints_to_alarm=1 over evaluation_periods=12
# @ period=300 (a 1-hour trailing window) — page on the FIRST breaching 5-min
# bucket in the trailing hour. threshold=0 + GreaterThanThreshold reads "fire on
# Sum > 0" (>= 1 reject). Both are datapoints_to_alarm=1 single-event detectors;
# they differ only in lookback, which follows the traffic profile. Raise
# datapoints_to_alarm / threshold once a relay carries real traffic (#6) and a
# benign transient reject baseline appears.
#
# GATING — count on the STATIC var.deploy_relay only (not enable_sns_alerts: the
# SNS topic is created in THIS module, so its ARN is plan-time-known and no
# count-depends-on-computed guard is needed — that guard lives in compute purely
# because compute receives a computed cross-module ARN, #2664/#2665). With
# deploy_relay=false (prod today) the counter can never increment, so the alarm
# would be a permanently-dead INSUFFICIENT_DATA fixture there; gating keeps it
# only where a relay is wired. notBreaching: the counter is traffic-gated, so a
# quiet window is genuinely reject-free, not a broken publisher (that case is
# backstopped by server_publisher_failures / the absence-of-metric alarms).
resource "aws_cloudwatch_metric_alarm" "relay_forward_reject" {
  count = var.deploy_relay ? 1 : 0

  alarm_name = "${var.name_prefix}-${var.cell_id}-relay-forward-reject"
  # `> 0` matches knock_forward_path / server_publisher_failures (identical to
  # `>= 1` for an integer Sum counter); copied for behavioral-sibling parity.
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 12
  datapoints_to_alarm = 1
  metric_name         = "RelayForwardReject"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "nhp-server rejected >=1 NHP_RLY relay forward in the trailing hour while the relay is deployed. Most likely the server booted without relay.toml (transient Secrets Manager / IAM lag → user_data skipped writing it → empty relayPeerMap rejects every relayed knock, logged only as a user-data WARNING); a sustained rate can also be a spoofed/unregistered NHP_RLY sender. Check the cell server's user-data.log for the relay-secret fetch and that relay.toml exists, and server logs for HandleRelayForward drops. #2643."
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
    Issue     = "2643"
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

# DynamoDB throttling — per-table read+write throttle events.
#
# Uses ReadThrottleEvents + WriteThrottleEvents (combined via FILL metric math),
# NOT ThrottledRequests. AWS publishes ThrottledRequests only at the
# {TableName, Operation} granularity, so the previous {TableName}-only alarm
# selected a non-existent metric stream and — with treat_missing_data =
# "notBreaching" — sat OK forever and NEVER fired (the silent-alarm failure mode
# in terraform/CLAUDE.md's "Metric / Alarm Dim-Set Rules"; confirmed via
# `aws cloudwatch list-metrics` in #1912). Read/WriteThrottleEvents ARE published
# at {TableName} alone (per the AWS docs), so they are the correct table-level
# primitive. This mirrors the proven pattern already used for the QURL hot-path
# tables in modules/dynamodb/alarms.tf (qurl_api_keys / qurl_agent_keys).
resource "aws_cloudwatch_metric_alarm" "dynamodb_throttled" {
  for_each = var.enable_dynamodb_monitoring ? toset(var.dynamodb_table_names) : toset([])

  alarm_name          = "${var.name_prefix}-${var.cell_id}-dynamodb-throttled-${each.value}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 0
  alarm_description   = "DynamoDB table ${each.value} throttling (read+write throttle events) sustained 2 consecutive minutes — a sustained throttle on a PAY_PER_REQUEST table means adaptive capacity hasn't caught up and requests are failing."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  # FILL(reads,0)+FILL(writes,0): DynamoDB only publishes Read/WriteThrottleEvents
  # in periods where a throttle actually lands, so a read-only burst yields
  # reads=N, writes=<empty>. FILL substitutes 0 for the empty series so the sum
  # is well-defined (see modules/dynamodb/alarms.tf for the same rationale).
  metric_query {
    id          = "throttles"
    expression  = "FILL(reads, 0) + FILL(writes, 0)"
    label       = "Throttle events"
    return_data = true
  }
  metric_query {
    id = "reads"
    metric {
      metric_name = "ReadThrottleEvents"
      namespace   = "AWS/DynamoDB"
      period      = 60
      stat        = "Sum"
      dimensions = {
        TableName = each.value
      }
    }
  }
  metric_query {
    id = "writes"
    metric {
      metric_name = "WriteThrottleEvents"
      namespace   = "AWS/DynamoDB"
      period      = 60
      stat        = "Sum"
      dimensions = {
        TableName = each.value
      }
    }
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# The former `dynamodb_system_errors` alarm (SystemErrors, {TableName}) was
# REMOVED in #1912: SystemErrors is published only at {TableName, Operation}
# (same as ThrottledRequests), so the {TableName}-only alarm never matched a
# stream and never fired — it gave zero real coverage. A working per-table
# SystemErrors alarm needs SUM(SEARCH(...)) across operations, and DDB-side HTTP
# 500s on PAY_PER_REQUEST are SDK-retried, low-value noise — not worth a novel
# alarm shape. Tracked in #2445 if per-table 5xx coverage is ever needed.

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
# Server process observability: ServerPanic (log-filter) + ServerStartupEvent (EMF)
#
# The nhp-server container's docker awslogs driver routes stdout+stderr
# to var.server_stderr_log_group_name.
#
# ServerPanic
#   Matches "panic:" written by Go's runtime (package runtime, gopanic)
#   at the start of every panic stack trace, bypassing the structured
#   file logger. MUST stay on the log-metric-filter path because a
#   panicking process can't emit its own metric.
#
# ServerStartupEvent
#   Emitted as CloudWatch Embedded Metric Format (EMF) JSON from
#   recordServerStartup() in endpoints/server/msghandler.go at process
#   start. CloudWatch auto-extracts the dimensioned metric from the
#   log stream without a filter resource -- this is the single source
#   of truth. See #1106 for the migration rationale.
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
    # Cell-scoped metric name (not "ServerPanic" + dimensions) because
    # AWS rejects dimensions on quoted-string filter patterns --
    # "The specified filter pattern does not support dimensions".
    # Dimensions would need to come from extracted log fields, but the
    # Environment/Cell values are intrinsic to the log group, not the
    # log content. Baking them into the metric name keeps per-cell
    # isolation without the extractor.
    name          = "ServerPanic-${local.metric_name_suffix}"
    namespace     = "LayerV/NHP"
    value         = "1"
    default_value = "0"
  }
}

# Async ErrRuntimePanic recoveries (issue #2679, follow-up from PR #2673).
# PR #2673 made msgToPacketRoutine recover residual packet-send panics so they
# become dropped messages instead of process restarts. That means the raw
# stderr "panic:" detector above no longer sees this class; the structured
# logger writes the recovery line to var.server_log_group_name instead.
#
# Match the stable routine name plus ErrRuntimePanic's operator-facing message
# string in the raw JSON log line, not a broad "panic" substring, so ordinary
# explanatory log lines do not increment the alarm metric. This intentionally
# uses CloudWatch's quoted-term syntax instead of a JSON selector: env/cell are
# carried by the log group/metric name, and the stable terms are guarded by Go
# and parity tests without coupling the alarm to a field path. The scope is
# intentionally limited to msgToPacketRoutine; add or widen a filter if another
# structured recover() site starts converting ErrRuntimePanic into dropped work.
# The raw AND match is deliberate: only the recovery line should emit both terms.
resource "aws_cloudwatch_log_metric_filter" "server_async_runtime_panic" {
  name           = "${var.name_prefix}-${var.cell_id}-server-async-runtime-panic"
  log_group_name = var.server_log_group_name
  pattern        = "\"msgToPacketRoutine\" \"runtime panic encountered\""

  metric_transformation {
    # Cell-scoped metric name because the Environment/Cell values are supplied
    # by the log group and not by fields in the JSON log event.
    name          = "ServerAsyncRuntimePanic-${local.metric_name_suffix}"
    namespace     = "LayerV/NHP"
    value         = "1"
    default_value = "0"
  }
}

# NOTE: The ServerStartupEvent log-metric-filter that previously lived
# here (substring match on the startup banner) was removed in the EMF
# migration (issue #1106). The Go server now emits the metric directly
# via CloudWatch Embedded Metric Format from recordServerStartup() in
# endpoints/server/msghandler.go; CloudWatch auto-extracts the
# dimensioned metric from stdout-captured log events without a filter.
# server_crash_loop (fleet-wide) was retired in the same migration.
# server_instance_restart below picks up that fleet-wide crash-loop
# detection role (PR #1109 reshaped it from an attempted per-instance
# SEARCH+MAX design to a classic aggregate alarm after AWS rejected
# SEARCH in metric alarms). See ARCHITECTURE.md "Alarms Coupled to
# Fleet Size" for the threshold rationale.

# Any panic at all is actionable. The filter emits 1 on each match
# and 0 otherwise (default_value = "0"), so every evaluation window
# produces a datapoint -- the alarm fires on real matches, never on
# the absence of log events. treat_missing_data = notBreaching is a
# safety net for the edge where the log group itself goes silent
# (no instances running, awslogs driver failure); insufficient_data
# still pages via the alarm's insufficient_data_actions so we learn
# about the blackout.
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

  # No dimensions block: env/cell are baked into the metric_name
  # (see server_panic filter's metric_transformation above).

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# A recovered async runtime panic is still a zero-baseline availability signal:
# the process stayed up, but the specific outbound message was dropped. Page
# intentionally on the first recovery in a 5-minute bucket, then auto-resolve
# after one clean bucket; use the structured log line's stack trace to identify
# the residual packet-send panic.
resource "aws_cloudwatch_metric_alarm" "server_async_runtime_panic" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-server-async-runtime-panic"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.server_async_runtime_panic.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.server_async_runtime_panic.metric_transformation[0].namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "nhp-server recovered >=1 async ErrRuntimePanic in msgToPacketRoutine in the last 5 minutes; the process stayed up but outbound messages were dropped. Inspect the structured server log stack trace. Runbook: docs/runbooks/server-forward-safety.md. #2679 / PR #2673."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  # The filter's default_value emits zero while structured logs are flowing;
  # keep missing data quiet as a silence fallback rather than paging on a
  # naturally quiet log window. Unlike server_panic, this event detector omits
  # insufficient_data_actions because losing the stderr panic stream is a
  # stronger blackout signal than a quiet structured recovery metric.
  treat_missing_data = "notBreaching"

  # No dimensions block: env/cell are baked into the metric_name
  # (see server_async_runtime_panic filter's metric_transformation above).

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
    Issue     = "2679"
  })
}

# ============================================================================
# Server restart alarm (crash-loop detection; #1099 origin, reshaped in #1109)
#
# The alarm watches the FLEET-WIDE ServerStartupEvent sum in a 5-min
# window and pages when it exceeds what a normal deploy produces.
#
# We originally tried a per-instance design (SEARCH+MAX over the
# per-InstanceId series). AWS CloudWatch metric alarms don't accept
# the SEARCH expression -- it's dashboards/console only -- so every
# apply of the per-instance form failed with
#   ValidationError: SEARCH is not supported on Metric Alarms
# Since ASG churn means we can't pre-enumerate InstanceIds in TF,
# per-instance alarming via metric alarms isn't possible at all.
# The per-InstanceId series is still emitted by recordServerStartup
# (endpoints/server/msghandler.go) and available for dashboard /
# ad-hoc investigation; this alarm is the automated page.
#
# Threshold: fleet of N server instances × 1 startup per blue/green
# deploy = N events in the window. Current N=3, so threshold=3 with
# GreaterThanThreshold trips on the first crash-loop restart beyond
# a normal deploy (4th event). If the fleet grows past 3, bump to
# the new N (see docs/ARCHITECTURE.md "Alarms Coupled to Fleet Size").
#
# datapoints_to_alarm = evaluation_periods = 2 absorbs the known
# overlap scenario where a Terraform instance refresh on blue
# coincides with a blue/green deploy spinning up green -- the
# 5-min window could see up to 2N = 6 starts once, not sustained,
# so we require two consecutive breaches before paging.
#
# Shares transport with server_panic (docker awslogs → CWL → metric
# extraction); different detection mechanism (EMF auto-extract vs
# substring log filter). Awslogs outage darkens both; EMF parser
# regression darkens only this one.
# ============================================================================
resource "aws_cloudwatch_metric_alarm" "server_instance_restart" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-server-instance-restart"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  metric_name         = "ServerStartupEvent"
  namespace           = "LayerV/NHP"
  period              = local.server_restart_period_seconds
  statistic           = "Sum"
  # threshold = 3 + comparison_operator = GreaterThanThreshold means
  # the alarm fires on the 4th start in a 5-min window -- i.e., the
  # FIRST crash-loop restart beyond a normal blue/green deploy of 3
  # instances. threshold = 4 here would require a second extra
  # restart to trip, a silent off-by-one.
  threshold          = 3
  alarm_description  = "nhp-server fleet >3 starts in 5-min window, sustained 2 windows (crash-loop; PR #1096). Normal blue/green produces 3 starts; the 4th is a restart."
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

# ============================================================================
# Cloud Map registration self-healing alarms (issue #1681)
#
# Each nhp-server instance asserts its presence in Cloud Map at boot,
# then re-asserts every 5 minutes via cloudMapRegisterRefreshRoutine
# (endpoints/server/udpserver.go). The prod #1681 incident: us-east-2c
# server failed to register at boot, no retry/refresh, sat invisible
# to auto-assignment for ~2 weeks until a deploy. These three alarms
# fence the failure modes the self-healing introduces:
#
#   - CloudMapRegisterFailure       boot retry budget exhausted
#   - CloudMapRegisterRefreshFailure  refresh loop hitting Cloud Map errors
#   - CloudMapRegisterRefresh         success heartbeat (alarm on absence)
#
# Dim set {Environment, Cell} matches buildServerMetricDimensions
# (endpoints/server/udpserver.go::buildServerMetricDimensions). Adding or
# removing a dim here breaks the metric stream selector silently.
# ============================================================================
resource "aws_cloudwatch_metric_alarm" "server_cloudmap_register_failure" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-server-cloudmap-register-failure"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CloudMapRegisterFailure"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "nhp-server boot Cloud Map register exhausted retry budget; instance invisible to auto-assignment until refresh recovers (#1681)."
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

# Heartbeat alarm: CloudMapRegisterRefresh fires once per successful tick of
# every server's refresh loop, so in steady state the fleet-wide Sum over a
# 10-min window is ≈ N_servers × 2 ticks × <success rate>. Zero across two
# consecutive 10-min windows (20 min) means every server's refresh goroutine
# has wedged or every server is dead — both are page-worthy and neither is a
# normal deploy footprint. treat_missing_data = "breaching" is intentional:
# the publisher only emits counters that were incremented this interval, so
# a wedged refresh routine (or a dead fleet) produces missing data, not
# zero data — treating missing as breaching catches that blackout case.
#
# Greenfield caveat: a fresh `terraform apply` on a brand-new env creates
# this alarm before any server has run a refresh tick (first tick fires at
# +5min after server boot). On a one-shot greenfield create, this alarm
# may transit ALARM for the first 20 minutes while servers come up; ack
# during the bring-up. Operationally rare enough that the simpler config
# wins over the alternatives (notBreaching loses real failure visibility;
# disabling actions during burn-in adds drift risk). For an existing env
# this is a pure additive deploy and there is no missing-data window.
resource "aws_cloudwatch_metric_alarm" "server_cloudmap_register_refresh_heartbeat" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-server-cloudmap-register-refresh-heartbeat"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  metric_name         = "CloudMapRegisterRefresh"
  namespace           = "LayerV/NHP"
  period              = 600
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "nhp-server fleet emitted zero Cloud Map register refreshes for 20 min; refresh goroutine wedged or fleet dark (#1681)."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "breaching"

  dimensions = {
    Environment = var.environment
    Cell        = var.cell_id
  }

  tags = merge(var.tags, {
    Component = "monitoring"
    Cell      = var.cell_id
  })
}

# Sustained refresh failures point at Cloud Map auth, quota, or service-level
# issues — the self-heal mechanism is in place but losing ground. Threshold of
# 3 in a 15-min window distinguishes a single transient hiccup from a real
# upstream regression.
resource "aws_cloudwatch_metric_alarm" "server_cloudmap_register_refresh_failure" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-server-cloudmap-register-refresh-failure"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  metric_name         = "CloudMapRegisterRefreshFailure"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "nhp-server Cloud Map register refresh failed in 3 consecutive 5-min windows; investigate Cloud Map auth/quota/availability (#1681)."
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

# ============================================================================
# Metric publisher failure alarm (#1707)
#
# PublisherFailures is incremented once per PutMetricData batch error by the
# server's CloudWatch publisher (endpoints/metrics/publisher.go::flush ->
# MetricPublisherFailure). It pages when the publisher is partially or
# intermittently failing to publish — throttling, transient IAM/STS, one bad
# batch — a class that was otherwise only a log.Warning that silently dropped
# metrics.
#
# Coverage boundary (intentional, per #1707 step 3): catches the case where the
# CloudWatch client EXISTS but some calls fail. It does NOT catch total
# publisher death — when NewPublisher can't load AWS config the publisher is
# nil and emits nothing, so this self-reported counter rides the same dead
# channel. That blackout is caught by the absence alarm
# `server-cloudmap-register-refresh-heartbeat` above (treat_missing_data
# ="breaching"). The two are complementary, not redundant.
#
# Dim set {Environment, Cell} matches buildServerMetricDimensions
# (endpoints/server/udpserver.go) — same selector as the Cloud Map alarms;
# Sum aggregates the cell's server fleet.
#
# Sensitivity: 2 failing 5-min windows within 15 min absorbs a single isolated
# transient throttle while paging on sustained degradation in <=10 min.
# notBreaching because the counter is sparse (only emitted on a flush that had
# a failed batch).
resource "aws_cloudwatch_metric_alarm" "server_publisher_failures" {
  alarm_name          = "${var.name_prefix}-${var.cell_id}-server-publisher-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 2
  metric_name         = "PublisherFailures"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "nhp-server CloudWatch metric publisher reported PutMetricData batch failures in 2 of the last 3 five-minute windows; metrics partially/intermittently dropped (throttling, IAM/STS, transient AWS). Does NOT cover total publisher death — see server-cloudmap-register-refresh-heartbeat. #1707."
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
