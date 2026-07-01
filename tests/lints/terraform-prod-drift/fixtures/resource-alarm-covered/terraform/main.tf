# Positive path: the full alarm family (metric + composite + dashboard)
# paired with an apply role that grants every action RESOURCE_ACTIONS
# requires. The lint must NOT flag (exit 0) — guards against a
# false-positive regression in the alarm-family map entries.

resource "aws_cloudwatch_metric_alarm" "example" {
  alarm_name          = "fixture-metric"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Fixture"
  namespace           = "Fixture"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
}

resource "aws_cloudwatch_composite_alarm" "example" {
  alarm_name = "fixture-composite"
  alarm_rule = "ALARM(${aws_cloudwatch_metric_alarm.example.alarm_name})"
}

resource "aws_cloudwatch_dashboard" "example" {
  dashboard_name = "fixture-dashboard"
  dashboard_body = "{}"
}
