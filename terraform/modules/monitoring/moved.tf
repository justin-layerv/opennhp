# State-address migrations for #2628 (take nhp-server private).
#
# These three public-NLB alarms gained `count = var.nlb_alarms_enabled ? 1 : 0`.
# Adding count to a previously un-indexed resource changes its state address
# (`x` -> `x[0]`); these `moved {}` blocks rename the existing state in place so the
# default (nlb_alarms_enabled = true, e.g. prod) shows NO diff — the alarms are not
# destroyed+recreated — while the private path (sandbox) cleanly destroys them.
# Permanent no-ops once applied; leave in place.

moved {
  from = aws_cloudwatch_metric_alarm.unhealthy_hosts
  to   = aws_cloudwatch_metric_alarm.unhealthy_hosts[0]
}

moved {
  from = aws_cloudwatch_metric_alarm.no_healthy_hosts
  to   = aws_cloudwatch_metric_alarm.no_healthy_hosts[0]
}

moved {
  from = aws_cloudwatch_metric_alarm.tcp_resets
  to   = aws_cloudwatch_metric_alarm.tcp_resets[0]
}
