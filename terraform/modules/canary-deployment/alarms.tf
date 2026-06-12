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

# Alarm: ASG capacity deficit > 0 (NLB-disabled path).
#
# Closes the cr-flagged auto-rollback gap on the frps path: with
# `disable_nlb_health_checks = true` the NLB-keyed alarms are skipped
# and the composite alarm rule degenerates to CPU-only — but a binary
# that boots, fails Cloud Map registration, then crash-loops never
# spikes CPU. Adding a capacity-deficit alarm here gives the EventBridge
# auto-rollback path a signal that does not depend on the SFN reaching
# its next checkpoint.
#
# `GroupUnHealthyInstanceCount` is not an AWS/AutoScaling enabled metric.
# Use the accepted ASG metrics instead: `GroupDesiredCapacity -
# GroupInServiceInstances` is positive while the ASG has fewer in-service
# instances than it wants. The window is the instance warmup rounded up to
# whole minutes plus one extra period so normal refresh warmup has a
# chance to settle before the asynchronous rollback tripwire fires. At the
# default 180s warmup this is 4 consecutive 60s periods: one period of
# margin after warmup, with the #2041 failure-injection gate validating
# the real canary-window behavior after apply. The lifecycle precondition
# below keeps that tripwire faster than the SFN checkpoint cadence; equal
# windows are rejected because they leave no rollback margin.
resource "aws_cloudwatch_metric_alarm" "canary_asg_unhealthy" {
  count               = var.disable_nlb_health_checks ? 1 : 0
  alarm_name          = "${var.name_prefix}-canary-${var.component}-asg-unhealthy"
  alarm_description   = "Canary deployment (${var.component}): ASG capacity deficit persists after instance warmup. Closes the auto-rollback gap on the NLB-disabled path."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = local.canary_asg_capacity_deficit_evaluation_periods
  datapoints_to_alarm = local.canary_asg_capacity_deficit_evaluation_periods
  threshold           = 0
  # Belt-and-suspenders for whole-expression no-data states; the FILLs
  # make normal partial input gaps explicit.
  treat_missing_data = "notBreaching"

  metric_query {
    id = "capacity_deficit"
    # FILL bias is intentional for one-sided gaps: missing desired is treated
    # as "nothing wanted"; missing in-service with desired present should read
    # as a full deficit. The rollout ledger verifies CloudWatch's fresh-series
    # and one-input-missing behavior after apply.
    expression  = "FILL(desired, 0) - FILL(in_service, 0)"
    label       = "ASG desired capacity minus in-service instances"
    return_data = true
  }

  metric_query {
    id = "desired"
    metric {
      metric_name = "GroupDesiredCapacity"
      namespace   = "AWS/AutoScaling"
      period      = 60
      stat        = "Average"
      dimensions = {
        AutoScalingGroupName = var.asg_name
      }
    }
  }

  metric_query {
    id = "in_service"
    metric {
      metric_name = "GroupInServiceInstances"
      namespace   = "AWS/AutoScaling"
      period      = 60
      stat        = "Average"
      dimensions = {
        AutoScalingGroupName = var.asg_name
      }
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-canary-${var.component}-asg-unhealthy-alarm"
    Component = "canary"
    Cell      = var.cell_id
  })

  lifecycle {
    precondition {
      condition     = local.canary_asg_capacity_deficit_window_seconds < var.checkpoint_delay_seconds
      error_message = "canary_asg_unhealthy alarm window (${local.canary_asg_capacity_deficit_window_seconds}s) must be shorter than checkpoint_delay_seconds (${var.checkpoint_delay_seconds}s). Lower instance_warmup_seconds, raise checkpoint_delay_seconds, or add a separate fast rollback signal before enabling the NLB-disabled canary path."
    }
  }
}

# ==============================================================================
# Composite Alarm
# ==============================================================================

locals {
  canary_asg_capacity_deficit_evaluation_periods = ceil(var.instance_warmup_seconds / 60) + 1
  canary_asg_capacity_deficit_window_seconds     = local.canary_asg_capacity_deficit_evaluation_periods * 60

  # Composite alarm rule: ANY constituent alarm in ALARM state triggers
  # rollback. NLB-keyed clauses are dropped when
  # `disable_nlb_health_checks = true` (frps path) — there's nothing
  # publishing NLB metrics for those alarms to evaluate against. The
  # ASG capacity-deficit alarm replaces them on the frps path so the
  # composite never collapses to CPU-only (which would miss stuck launch,
  # capacity, or EC2 health replacement failures that don't spike CPU).
  #
  # NLB-vs-ASG alarm subsumption posture (cr-flagged check):
  #   - NLB path:  unhealthy_hosts > 0       OR cpu OR low_healthy(<1)
  #   - ASG path:  DesiredCapacity - InServiceInstances > 0 OR cpu
  # The ASG path uses a capacity-deficit signal because frps has no NLB
  # target group. It catches sustained stuck launch, capacity, or EC2
  # health replacement failures. App-level registration/routing failures
  # remain covered by the canary Lambda health gate and the qurl-reverse-
  # tunnel-server empty-AZ watchdog.
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
    ? "Canary deployment health (${var.component}): triggers on high CPU OR sustained ASG capacity deficit. NLB-keyed health checks disabled."
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
