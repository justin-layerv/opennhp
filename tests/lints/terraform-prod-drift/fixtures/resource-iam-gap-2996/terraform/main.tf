# Reproduces #2996: an `aws_cloudwatch_composite_alarm` was added, but the
# apply role grants `cloudwatch:PutMetricAlarm` (metric alarms) and NOT
# `cloudwatch:PutCompositeAlarm` (composite alarms — a DISTINCT action).
# `terraform plan` under the read-only PR role is green; the post-merge
# `terraform apply` hits `AccessDenied: PutCompositeAlarm`. The IAM-coverage
# lint must flag the resource's missing action at PR time (exit 1).

resource "aws_cloudwatch_composite_alarm" "revocation_aged_out" {
  alarm_name = "fixture-revocation-aged-out"
  alarm_rule = "ALARM(fixture-child)"
}
