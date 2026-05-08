# Canary Deployment Module - CloudWatch Alarms
# Health monitoring alarms for canary deployments with EventBridge auto-rollback.

# ==============================================================================
# CloudWatch Metric Alarms
# ==============================================================================

# Alarm: Unhealthy hosts detected in target group during canary deployment
# Skipped when `disable_nlb_health_checks = true` (frps path — no NLB).
resource "aws_cloudwatch_metric_alarm" "canary_unhealthy" {
  count               = var.disable_nlb_health_checks ? 0 : 1
  alarm_name          = "${var.name_prefix}-canary-${var.component}-unhealthy-hosts"
  alarm_description   = "Canary deployment (${var.component}): unhealthy hosts detected in target group"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    TargetGroup  = var.target_group_arn_suffix
    LoadBalancer = var.nlb_arn_suffix
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-canary-${var.component}-unhealthy-alarm"
    Component = "canary"
    Cell      = var.cell_id
  })
}

# Alarm: High CPU utilization on ASG during canary deployment
resource "aws_cloudwatch_metric_alarm" "canary_high_cpu" {
  alarm_name          = "${var.name_prefix}-canary-${var.component}-high-cpu"
  alarm_description   = "Canary deployment (${var.component}): CPU utilization exceeds ${var.max_cpu_percent}% threshold"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = var.max_cpu_percent
  treat_missing_data  = "notBreaching"

  dimensions = {
    AutoScalingGroupName = var.asg_name
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-canary-${var.component}-cpu-alarm"
    Component = "canary"
    Cell      = var.cell_id
  })
}

# Alarm: No healthy hosts in target group (CRITICAL safety net)
# Skipped when `disable_nlb_health_checks = true` (frps path — no NLB).
# For frps, the per-AZ Cloud Map empty-registration alarm (#1542 in
# `modules/qurl-reverse-tunnel-server/monitoring_empty_az.tf`) covers the same fault
# class — registrations missing from a per-AZ service.
resource "aws_cloudwatch_metric_alarm" "canary_low_healthy" {
  count               = var.disable_nlb_health_checks ? 0 : 1
  alarm_name          = "${var.name_prefix}-canary-${var.component}-no-healthy-hosts"
  alarm_description   = "CRITICAL: Canary deployment (${var.component}) - no healthy hosts in target group"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  treat_missing_data  = "breaching"

  dimensions = {
    TargetGroup  = var.target_group_arn_suffix
    LoadBalancer = var.nlb_arn_suffix
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-canary-${var.component}-healthy-alarm"
    Component = "canary"
    Cell      = var.cell_id
  })
}

# Alarm: ASG unhealthy instance count > 0 (NLB-disabled path).
#
# Closes the cr-flagged auto-rollback gap on the frps path: with
# `disable_nlb_health_checks = true` the NLB-keyed alarms are skipped
# and the composite alarm rule degenerates to CPU-only — but a binary
# that boots, fails Cloud Map registration, then crash-loops never
# spikes CPU. Adding `GroupUnHealthyInstanceCount > 0` here gives the
# EventBridge auto-rollback path a fast (60s × 1 evaluation period)
# trigger that doesn't depend on the SFN reaching its next checkpoint.
#
# Pre-existing-fleet noise: `GroupUnHealthyInstanceCount` is the ASG's
# count of EC2-health-check-failed instances, not user_data-failure
# instances. A spurious EC2 health hiccup on an unrelated instance
# would also fire this alarm and roll back the canary. The 1-period
# evaluation window is tight enough to catch a real failure within
# ~60s but loose enough that a transient EC2 status-check flap usually
# clears before alarming. If false rollbacks become a problem, raise
# evaluation_periods to 2.
resource "aws_cloudwatch_metric_alarm" "canary_asg_unhealthy" {
  count               = var.disable_nlb_health_checks ? 1 : 0
  alarm_name          = "${var.name_prefix}-canary-${var.component}-asg-unhealthy"
  alarm_description   = "Canary deployment (${var.component}): ASG reports unhealthy instance(s). Closes the auto-rollback gap on the NLB-disabled path."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "GroupUnHealthyInstanceCount"
  namespace           = "AWS/AutoScaling"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    AutoScalingGroupName = var.asg_name
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-canary-${var.component}-asg-unhealthy-alarm"
    Component = "canary"
    Cell      = var.cell_id
  })
}

# ==============================================================================
# Composite Alarm
# ==============================================================================

locals {
  # Composite alarm rule: ANY constituent alarm in ALARM state triggers
  # rollback. NLB-keyed clauses are dropped when
  # `disable_nlb_health_checks = true` (frps path) — there's nothing
  # publishing NLB metrics for those alarms to evaluate against. The
  # ASG-unhealthy alarm replaces them on the frps path so the composite
  # never collapses to CPU-only (which would miss crash-loop / failed-
  # registration regressions that don't spike CPU).
  #
  # NLB-vs-ASG alarm subsumption posture (cr-flagged check):
  #   - NLB path:  unhealthy_hosts > 0       OR cpu OR low_healthy(<1)
  #   - ASG path:  GroupUnHealthyInstanceCount > 0 OR cpu
  # ASG `GroupUnHealthyInstanceCount > 0` fully subsumes NLB
  # `unhealthy_hosts > 0` (every NLB-unhealthy instance is also
  # ASG-unhealthy once the EC2 health check trips), and matches NLB
  # `low_healthy < N` only at N=1 (which is the canary's actual
  # constant — `canary_low_healthy.threshold = 1` in this same file).
  # If a future change raises that threshold, the ASG path needs an
  # additional explicit `low_healthy` clause to maintain equivalence.
  canary_alarm_rule = (
    var.disable_nlb_health_checks
    ? join(" OR ", [
      "ALARM(\"${aws_cloudwatch_metric_alarm.canary_high_cpu.alarm_name}\")",
      "ALARM(\"${aws_cloudwatch_metric_alarm.canary_asg_unhealthy[0].alarm_name}\")",
    ])
    : join(" OR ", [
      "ALARM(\"${aws_cloudwatch_metric_alarm.canary_unhealthy[0].alarm_name}\")",
      "ALARM(\"${aws_cloudwatch_metric_alarm.canary_high_cpu.alarm_name}\")",
      "ALARM(\"${aws_cloudwatch_metric_alarm.canary_low_healthy[0].alarm_name}\")",
    ])
  )
  canary_alarm_description = (
    var.disable_nlb_health_checks
    ? "Canary deployment health (${var.component}): triggers on high CPU OR ASG unhealthy instance(s). NLB-keyed health checks disabled — the ASG-unhealthy alarm closes the gap on crash-loop / failed-registration regressions that don't spike CPU."
    : "Canary deployment health (${var.component}): triggers on unhealthy hosts, high CPU, or no healthy hosts"
  )
}

# Composite alarm: ANY canary health issue triggers rollback
resource "aws_cloudwatch_composite_alarm" "canary_health" {
  alarm_name        = "${var.name_prefix}-canary-${var.component}-health"
  alarm_description = local.canary_alarm_description

  alarm_rule = local.canary_alarm_rule

  alarm_actions = [var.alerts_sns_topic_arn]
  ok_actions    = [var.alerts_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-canary-${var.component}-health-composite"
    Component = "canary"
    Cell      = var.cell_id
  })
}

# ==============================================================================
# EventBridge Auto-Rollback
# ==============================================================================

# EventBridge rule: trigger Lambda rollback when composite alarm fires
# This is a backup rollback mechanism independent of Step Functions
resource "aws_cloudwatch_event_rule" "canary_alarm_rollback" {
  name        = "${var.name_prefix}-canary-${var.component}-alarm-rollback"
  description = "Triggers canary rollback when health composite alarm fires"

  event_pattern = jsonencode({
    source      = ["aws.cloudwatch"]
    detail-type = ["CloudWatch Alarm State Change"]
    detail = {
      alarmName = [aws_cloudwatch_composite_alarm.canary_health.alarm_name]
      state = {
        value = ["ALARM"]
      }
    }
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-canary-${var.component}-alarm-rollback-rule"
    Component = "canary"
    Cell      = var.cell_id
  })
}

# EventBridge target: invoke Lambda with rollback action
resource "aws_cloudwatch_event_target" "canary_alarm_rollback" {
  rule      = aws_cloudwatch_event_rule.canary_alarm_rollback.name
  target_id = "canary-alarm-rollback"
  arn       = aws_lambda_function.orchestrator.arn

  input_transformer {
    input_paths = {
      time = "$.time"
    }

    input_template = jsonencode({
      action       = "alarm_triggered_rollback"
      alarm_name   = aws_cloudwatch_composite_alarm.canary_health.alarm_name
      trigger_time = "<time>"
    })
  }
}

# Lambda permission: allow EventBridge to invoke the orchestrator Lambda
resource "aws_lambda_permission" "eventbridge_rollback" {
  statement_id  = "AllowEventBridgeCanaryRollback"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.orchestrator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.canary_alarm_rollback.arn
}
