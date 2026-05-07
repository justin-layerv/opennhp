# CloudWatch monitoring for QURL FRP server instances
# Alarms for instance health, CPU, memory, and log error rate

locals {
  sns_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
}

# ==================== CloudWatch Alarms ====================

# No in-service instances - PAGE severity
# Fleet-level survival check: fires when the qurl-reverse-tunnel-server
# fleet drops below 1 in-service instance and ALL tunnel traffic is
# disrupted. Per-AZ blast radius is finer-grained than this alarm covers
# — losing 1 of 3 instances under the per-AZ fanout already disrupts
# ~1/3 of tunnels (the Cloud Map service for the lost instance's AZ goes
# empty, NXDOMAIN for any OwnerID hashing there). Per-AZ skew detection
# is tracked in #1542 and must land before the deploy_frps flip; this
# alarm stays as the fleet-survival backstop underneath that finer alarm.
# Note: StatusCheckFailed in AWS/EC2 uses InstanceId as its dimension and
# cannot be aggregated by AutoScalingGroupName. GroupInServiceInstances in
# AWS/AutoScaling is the correct ASG-level health signal.
resource "aws_cloudwatch_metric_alarm" "instance_status_check_failed" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-frps-no-healthy-instance"
  comparison_operator = "LessThanThreshold"
  # 3 × 60s tolerance: ASG briefly drops below desired during every
  # instance refresh; 3 evaluation periods rides through a normal ~2 min
  # refresh gap without paging, while still firing within 3-4 min for
  # real outages.
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

# Fleet undersized - TICKET severity
# Per-AZ Cloud Map fanout (#1499) requires one ASG instance per AZ
# suffix at steady state. When `desired_capacity > 1` (the production
# multi-AZ posture), GroupInServiceInstances persistently below the
# desired capacity indicates a stuck launch / capacity error / ICE in
# one AZ — qurl-service's hash will route some OwnerIDs to a Cloud Map
# service with zero registrations, returning NXDOMAIN. The pure
# "no-healthy-instance" alarm above only fires at < 1, which misses
# the partial-degradation case.
#
# Skipped when desired_capacity == 1 to avoid noise on the module's
# default sizing (single-AZ test fixtures, isolated-module deploys).
# Threshold = desired_capacity, evaluated as "below" — so a fleet of 3
# with only 2 in-service trips this alarm even though
# GroupInServiceInstances >= 1 (the page alarm) is satisfied.
#
# Avoiding flap on instance refresh: the smoothing in this alarm comes
# from `evaluation_periods = 15`, NOT from `statistic = Average`.
# `AWS/AutoScaling::GroupInServiceInstances` publishes at 1-minute
# resolution, so with `period = 60` there is exactly one sample per
# period — Average ≡ Minimum ≡ Maximum at this granularity. Requiring
# 15 consecutive sub-threshold periods (CloudWatch's default M-of-N is
# N-of-N) is what lets a 3-instance rolling refresh ride through: the
# refresh briefly drops to 2 in-service for ~1-2 min per instance,
# total ~6-10 min, which trips at most 6-10 of the 15 periods → no
# alarm. A degenerate stuck launch sustains 2 for 16+ min and fires.
# `Average` is retained for forward compatibility should AWS ever
# publish `GroupInServiceInstances` at sub-minute resolution via
# `GroupMetricsCollection`; today it is functionally equivalent to
# `Minimum`, and the alarm semantics depend on the evaluation_periods
# count, not on the statistic.
#
# `treat_missing_data = "notBreaching"` here is intentionally asymmetric
# with the page-severity `instance_status_check_failed` alarm above
# (which uses `"breaching"`). Rationale: a metric publication gap on
# `GroupInServiceInstances` is itself an AWS/AutoScaling outage — the
# page alarm correctly escalates that, since "is the fleet alive" is
# unknown and the safe default is to wake someone up. The ticket alarm
# would just generate noise on the same gap (we'd open a ticket about
# fleet capacity when the underlying signal is missing, not when the
# fleet is actually undersized). If you're tempted to "fix" this to
# match the page alarm, don't — keep them asymmetric.
resource "aws_cloudwatch_metric_alarm" "fleet_undersized" {
  count = var.enable_cloudwatch_alarms && var.desired_capacity > 1 ? 1 : 0

  alarm_name          = "${var.name_prefix}-frps-fleet-undersized"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 15
  metric_name         = "GroupInServiceInstances"
  namespace           = "AWS/AutoScaling"
  period              = 60
  statistic           = "Average"
  threshold           = var.desired_capacity
  alarm_description   = "qurl-reverse-tunnel-server fleet is below desired capacity (${var.desired_capacity}) for 15 consecutive minutes. Per-AZ Cloud Map fanout requires one instance per AZ — partial degradation routes some OwnerIDs to NXDOMAIN. Check ASG activity history for capacity errors / ICE / failed launches."
  treat_missing_data  = "notBreaching"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.frps.name
  }

  alarm_actions = local.sns_actions
  ok_actions    = local.sns_actions

  tags = merge(var.tags, {
    Name     = "${var.name_prefix}-frps-fleet-undersized"
    Severity = "ticket"
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
  # since v0.52 and is the default in later versions. If the qurl-reverse-tunnel-server
  # image pins or upgrades to FRP ≥ v0.52 with structured JSON, this
  # filter will stop matching and the alarm will silently green — pin
  # the FRP version in the qurl-reverse-tunnel-server image CI, and when it bumps, update
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
