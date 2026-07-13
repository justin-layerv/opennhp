# Historical #2628 state-address migrations retained for indexed alarms.
#
# These three public-NLB alarms previously gained conditional count. They now use
# constant `count = 1` because the assigned-cell public edge is invariant. The
# moved blocks retain indexed state addresses and avoid recreating the alarms.
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
