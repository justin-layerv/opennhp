# Canary Deployment Module - CloudWatch Alarms
# Health monitoring alarms for canary deployments with EventBridge auto-rollback.

# ==============================================================================
# CloudWatch Metric Alarms
# ==============================================================================

# Alarm: Unhealthy hosts detected in target group during canary deployment
resource "aws_cloudwatch_metric_alarm" "canary_unhealthy" {
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
resource "aws_cloudwatch_metric_alarm" "canary_low_healthy" {
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

# ==============================================================================
# Composite Alarm
# ==============================================================================

# Composite alarm: ANY canary health issue triggers rollback
resource "aws_cloudwatch_composite_alarm" "canary_health" {
  alarm_name        = "${var.name_prefix}-canary-${var.component}-health"
  alarm_description = "Canary deployment health (${var.component}): triggers on unhealthy hosts, high CPU, or no healthy hosts"

  alarm_rule = "ALARM(\"${aws_cloudwatch_metric_alarm.canary_unhealthy.alarm_name}\") OR ALARM(\"${aws_cloudwatch_metric_alarm.canary_high_cpu.alarm_name}\") OR ALARM(\"${aws_cloudwatch_metric_alarm.canary_low_healthy.alarm_name}\")"

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
