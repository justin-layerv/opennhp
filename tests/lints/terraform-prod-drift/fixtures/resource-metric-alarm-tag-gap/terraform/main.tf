# Regression fence for the default_tags correctness (cr round 2): this
# metric alarm has NO `tags` block, yet the apply role below is missing
# `cloudwatch:TagResource`, so the lint must STILL flag it (exit 1).
#
# Under the provider-level `default_tags` set in every real environment,
# every taggable resource is tagged at apply and has its tags read on
# refresh even when the HCL omits `tags` — so the tag trio is required
# unconditionally. A body-aware `if "tags" in body` map entry would wrongly
# pass this untagged alarm and re-open the green-at-PR / red-at-apply gap;
# this fixture fails if anyone reintroduces that conditional.

resource "aws_cloudwatch_metric_alarm" "untagged" {
  alarm_name          = "fixture-untagged-metric"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Fixture"
  namespace           = "Fixture"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
}
