# Console login without MFA — detection (#1138)
#
# A purple-team CloudTrail review found real ConsoleLogin events from human
# accounts (kevin 2026-04-15; vikram 2026-04-10 and 2026-04-08) that completed
# WITHOUT MFA, and no alarm existed to surface them. A password-only console
# login is trivially phishable, so every MFA-less login is latent credential-
# compromise risk that nobody was being told about.
#
# This adds the CIS-3.2 metric-filter + alarm on the CloudTrail -> CloudWatch
# Logs stream that already exists (aws_cloudwatch_log_group.cloudtrail), so an
# MFA-less ConsoleLogin pages the same channel as every other security alarm.
# The issue notes prod CloudTrail had ZERO metric filters; because the security
# module is a single root module parameterised by var.environment, this filter
# lands in every environment whose CloudTrail is enabled — prod included.
#
# Scope: detection only. Enforcement (deny API access without MFA) is the
# require_mfa policy in iam_mfa_enforcement.tf; the standing inventory check is
# the audit Lambda in iam_mfa_audit.tf.

locals {
  # The filter reads the CloudTrail log group, so it exists only when CloudTrail
  # does. The alarm additionally needs an alert destination; gate it on the
  # plan-time-known local.security_alerting_enabled (defined in main.tf, built
  # from var.* booleans, never an SNS ARN) so count stays valid. When alerting
  # is off we still create the filter so the metric accrues for a dashboard, and
  # skip the actionless alarm.
  create_console_login_mfa_filter = var.enable_cloudtrail && var.enable_console_login_mfa_alarm
  create_console_login_mfa_alarm  = local.create_console_login_mfa_filter && local.security_alerting_enabled
}

resource "aws_cloudwatch_log_metric_filter" "console_login_no_mfa" {
  count          = local.create_console_login_mfa_filter ? 1 : 0
  name           = "${var.name_prefix}-console-login-no-mfa"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name
  pattern        = var.console_login_mfa_filter_pattern

  metric_transformation {
    # No dimensions: AWS rejects static dimensions on metric filters
    # ("does not support dimensions" — they'd have to be extracted from log
    # fields), and prod/sandbox are separate accounts so there's no cross-env
    # metric collision to disambiguate. Matches the monitoring module's
    # server_panic filter shape.
    #
    # Namespace LayerV/NHP/Security keeps this #1138 feature's metrics together
    # with the IAM MFA audit Lambda and the stale-finding watchdog (the sibling
    # this module mirrors), rather than the LayerV/Security namespace the CIS
    # CloudTrail filters in cloudtrail_metric_filters.tf use — those are graded
    # CIS controls, this is the deliberately-separate CloudWatch.3 signal.
    name      = "ConsoleLoginWithoutMFA"
    namespace = "LayerV/NHP/Security"
    value     = "1"
    # Emit 0 for any period that has log events but no MFA-less-login match, so
    # the dashboard reads "clean" rather than "no data" and the alarm fires only
    # on a real match. Note CloudWatch publishes this default ONLY for periods in
    # which the log group received some events — a period with zero events
    # publishes nothing, so the actual no-false-page backstop is the alarm's
    # treat_missing_data = "notBreaching", not default_value alone. A prod
    # CloudTrail group effectively always has traffic, so this holds in practice.
    default_value = "0"
  }
}

# >= 1 MFA-less ConsoleLogin in a 5-minute window pages immediately. Threshold
# and window match the issue's recommendation. treat_missing_data is the
# opposite of the GuardDuty watchdog's "missing": here, no data means no login
# events at all (a quiet account off-hours), which is healthy — default_value
# keeps real windows populated, so "missing" would only ever mean a silent
# account, not a suppressed alert.
resource "aws_cloudwatch_metric_alarm" "console_login_no_mfa" {
  count = local.create_console_login_mfa_alarm ? 1 : 0

  alarm_name          = "${var.name_prefix}-console-login-no-mfa"
  alarm_description   = "A console login completed without MFA (#1138). Password-only console access is phishable — confirm the login was expected and ensure the principal has MFA enforced (require_mfa policy)."
  namespace           = aws_cloudwatch_log_metric_filter.console_login_no_mfa[0].metric_transformation[0].namespace
  metric_name         = aws_cloudwatch_log_metric_filter.console_login_no_mfa[0].metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.security_alert_destination_arns
  # No ok_actions: this is an event-style alarm (metric is 1 on a match, 0
  # otherwise via default_value), so it returns to OK ~5 min after a single
  # MFA-less login. An OK notification there is just noise — one page per login
  # is the signal. (The stateful weekly audit alarms keep ok_actions because
  # they self-clear meaningfully across runs.)

  tags = merge(var.tags, { Component = "security" })
}
