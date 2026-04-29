# CloudWatch monitoring for QURL FRP server instances
# Alarms for instance health, CPU, memory, and log error rate

locals {
  sns_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
}

# ==================== CloudWatch Alarms ====================

# No in-service instances - PAGE severity
# If the single FRP server instance is terminated (e.g., failed status check),
# GroupInServiceInstances drops to 0 and all tunnel traffic is disrupted.
# Note: StatusCheckFailed in AWS/EC2 uses InstanceId as its dimension and
# cannot be aggregated by AutoScalingGroupName. GroupInServiceInstances in
# AWS/AutoScaling is the correct ASG-level health signal.
resource "aws_cloudwatch_metric_alarm" "instance_status_check_failed" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-frps-no-healthy-instance"
  comparison_operator = "LessThanThreshold"
  # 3 × 60s tolerance: the min=max=1 ASG briefly drops to 0 in-service
  # instances during every instance refresh (no surge capacity possible).
  # 3 evaluation periods is enough to ride through a normal ~2 min refresh
  # gap without paging, while still firing within 3-4 min for real outages.
  evaluation_periods = 3
  metric_name        = "GroupInServiceInstances"
  namespace          = "AWS/AutoScaling"
  period             = 60
  statistic          = "Minimum"
  threshold          = 1
  alarm_description  = "FRP server has had no in-service instances for 3 consecutive minutes. Tunnel traffic is disrupted until ASG launches a replacement."
  treat_missing_data = "breaching"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.frps.name
  }

  alarm_actions = local.sns_actions
  ok_actions    = local.sns_actions

  tags = merge(var.tags, {
    Name     = "${var.name_prefix}-frps-no-healthy-instance"
    Severity = "page"
  })
}

# CPU > 80% for 5 minutes - TICKET severity
# Sustained high CPU may indicate too many concurrent FRP tunnels for the
# instance size. Uses native `AWS/EC2 CPUUtilization` rather than a CW Agent
# custom metric: AWS publishes CPUUtilization aggregated by
# `AutoScalingGroupName` when the ASG's instances have detailed monitoring
# enabled (they do — `monitoring { enabled = true }` in the launch
# template), and the aggregation is correct and boring (average across
# instances, not across per-cpu fanout). This matches the AC module's
# high_cpu alarm pattern and avoids the subtle trap where a CW Agent
# `cpu_usage_active` metric published with `{InstanceId, AutoScalingGroupName}`
# would never match an alarm querying on `{AutoScalingGroupName}` alone.
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-frps-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "FRP server CPU exceeds 80% for 5 minutes. Consider upgrading instance type or reducing tunnel count."
  treat_missing_data  = "notBreaching"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.frps.name
  }

  alarm_actions = local.sns_actions
  ok_actions    = local.sns_actions

  tags = merge(var.tags, {
    Name     = "${var.name_prefix}-frps-cpu-high"
    Severity = "ticket"
  })
}

# Memory > 85% for 5 minutes - TICKET severity
# Requires CloudWatch Agent to publish mem_used_percent metric. The alarm
# dimension set `{AutoScalingGroupName}` only matches a published series
# because the CW Agent config in `user_data.sh.tpl` declares
# `aggregation_dimensions = [["AutoScalingGroupName"], ["InstanceId",
# "AutoScalingGroupName"]]` — without the ASG-only rollup in that list, the
# raw series `{InstanceId, AutoScalingGroupName}` would never match an
# alarm on `{AutoScalingGroupName}` alone and the alarm would sit in
# INSUFFICIENT_DATA, silently green under `treat_missing_data = "notBreaching"`.
#
# `treat_missing_data = "notBreaching"` (rather than "breaching") is
# intentional for the burn-in window tracked in #1091: swapping to
# "breaching" would page on every brief CW Agent publication gap (config
# reload, package upgrade, IAM role propagation) before we've characterised
# the steady-state publication cadence. The install-fatal fail-fast in
# user_data covers the "agent never started" case; #1091's burn-in decides
# when to flip this flag for the agent-crashes-post-boot case.
resource "aws_cloudwatch_metric_alarm" "memory_high" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-frps-memory-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "mem_used_percent"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Maximum"
  threshold           = 85
  alarm_description   = "FRP server memory exceeds 85% for 5 minutes. Check for connection leaks or upgrade instance type."
  treat_missing_data  = "notBreaching"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.frps.name
  }

  alarm_actions = local.sns_actions
  ok_actions    = local.sns_actions

  tags = merge(var.tags, {
    Name     = "${var.name_prefix}-frps-memory-high"
    Severity = "ticket"
  })
}

# Log error rate > 1/min - TICKET severity
# Monitors the FRP server log group for error-level messages.
resource "aws_cloudwatch_log_metric_filter" "frps_errors" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  name           = "${var.name_prefix}-frps-errors"
  log_group_name = aws_cloudwatch_log_group.frps.name
  # Match FRP's bracket-format error tag `[E]` — a single unambiguous
  # quoted term keeps CloudWatch's filter parser happy. The bare substring
  # `ERROR` is deliberately excluded (matches benign `handled error case`
  # strings). Structured JSON (`"level":"error"`) is NOT added here until
  # #1091 verifies what FRP actually emits — in quoted-term syntax,
  # `"level":"error"` tokenizes as two separate quoted strings with a
  # literal colon between them, not as one substring, and would silently
  # never match. Keep the filter shape testable via
  # `aws logs test-metric-filter` before widening.
  #
  # FRP version assumption: this pattern targets the bracket-tag log
  # format used by FRP ≤ v0.51. Structured JSON logging is available
  # since v0.52 and is the default in later versions. If the qurl-frps
  # image pins or upgrades to FRP ≥ v0.52 with structured JSON, this
  # filter will stop matching and the alarm will silently green — pin
  # the FRP version in the qurl-frps image CI, and when it bumps, update
  # this filter together (or revisit #1091 to switch to JSON).
  pattern = "\"[E]\""

  metric_transformation {
    name      = "FRPSErrorCount"
    namespace = "LayerV/NHP"
    value     = "1"
    dimensions = {
      Component = "frps"
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "log_error_rate" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-frps-log-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FRPSErrorCount"
  namespace           = "LayerV/NHP"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "FRP server error log rate exceeds 1/min. Check logs for auth plugin failures or client connection issues."
  treat_missing_data  = "notBreaching"

  dimensions = {
    Component = "frps"
  }

  alarm_actions = local.sns_actions
  ok_actions    = local.sns_actions

  tags = merge(var.tags, {
    Name     = "${var.name_prefix}-frps-log-error-rate"
    Severity = "ticket"
  })
}
