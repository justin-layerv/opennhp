# IAM MFA audit (#1138 Step 4)
#
# Standing inventory check: lists IAM users on a schedule and pages if any user
# has no MFA device. AWS Config's IAM_USER_MFA_ENABLED rule (main.tf) already
# *records* this compliance state, but Config does not page anyone — a
# non-compliant user sits silent on a dashboard. This Lambda turns the same
# fact into an active Slack/email alert, closing the "no one noticed" failure
# mode the same way the GuardDuty stale-finding watchdog (#1137) does for
# findings, and re-alerting each run until every user has MFA.
#
# Pure read + publish: iam:ListUsers + iam:ListMFADevices + sns:Publish +
# cloudwatch:PutMetricData. Never mutates IAM. Wiring mirrors
# stale_finding_watchdog.tf.

locals {
  # Same plan-time-known alerting gate as the console-login alarm
  # (local.security_alerting_enabled is defined in main.tf, built from var.*
  # booleans so it is safe in count). The audit only runs if there is somewhere
  # to publish: a Lambda that finds an un-MFA'd user but has nowhere to report
  # it is the same silent failure in a different shape.
  create_iam_mfa_audit = var.enable_iam_mfa_audit && local.security_alerting_enabled
}

# ---------------------------------------------------------------------------
# Lambda package
# ---------------------------------------------------------------------------

data "archive_file" "mfa_audit" {
  count       = local.create_iam_mfa_audit ? 1 : 0
  type        = "zip"
  source_file = "${path.module}/lambda/mfa_audit.py"
  output_path = "${path.module}/lambda/mfa_audit.zip"
}

# ---------------------------------------------------------------------------
# IAM role
# ---------------------------------------------------------------------------
# Least-privilege: list users and their MFA devices account-wide (both are
# account-scoped list APIs with no resource-level controls), publish to the
# known alert topics, and emit a single CloudWatch metric namespace.

resource "aws_iam_role" "mfa_audit" {
  count = local.create_iam_mfa_audit ? 1 : 0
  name  = "${var.name_prefix}-iam-mfa-audit"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = merge(var.tags, { Component = "security" })
}

resource "aws_iam_role_policy_attachment" "mfa_audit_basic" {
  count      = local.create_iam_mfa_audit ? 1 : 0
  role       = aws_iam_role.mfa_audit[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "mfa_audit" {
  count = local.create_iam_mfa_audit ? 1 : 0
  name  = "iam-mfa-audit"
  role  = aws_iam_role.mfa_audit[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          # ListUsers / GetLoginProfile / ListMFADevices are account-level
          # reads with no resource-level scoping, so Resource must be "*". All
          # read-only; the role can never mutate IAM. GetLoginProfile is how the
          # audit excludes programmatic-only users (no console password) from
          # the MFA check.
          Sid    = "IAMReadMFA"
          Effect = "Allow"
          Action = [
            "iam:ListUsers",
            "iam:GetLoginProfile",
            "iam:ListMFADevices",
          ]
          Resource = "*"
        },
        {
          Sid      = "CloudWatchMetric"
          Effect   = "Allow"
          Action   = ["cloudwatch:PutMetricData"]
          Resource = "*"
          Condition = {
            StringEquals = {
              "cloudwatch:namespace" = "LayerV/NHP/Security"
            }
          }
        },
      ],
      local.enable_guardduty_alerts ? [{
        Sid      = "SNSPublishSlack"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = var.alerts_sns_topic_arn
      }] : [],
      local.enable_guardduty_email_alerts ? [{
        Sid      = "SNSPublishEmail"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.guardduty_email[0].arn
      }] : [],
    )
  })
}

# ---------------------------------------------------------------------------
# Lambda function
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "mfa_audit" {
  count             = local.create_iam_mfa_audit ? 1 : 0
  name              = "/aws/lambda/${var.name_prefix}-iam-mfa-audit"
  retention_in_days = local.is_prod ? 90 : 30
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, { Component = "security" })
}

resource "aws_lambda_function" "mfa_audit" {
  count = local.create_iam_mfa_audit ? 1 : 0

  depends_on = [aws_cloudwatch_log_group.mfa_audit]

  function_name    = "${var.name_prefix}-iam-mfa-audit"
  filename         = data.archive_file.mfa_audit[0].output_path
  source_code_hash = data.archive_file.mfa_audit[0].output_base64sha256
  role             = aws_iam_role.mfa_audit[0].arn
  handler          = "mfa_audit.handler"
  runtime          = "python3.12"
  timeout          = 120
  memory_size      = 256

  environment {
    variables = {
      ENVIRONMENT          = var.environment
      ALERTS_SNS_TOPIC_ARN = local.enable_guardduty_alerts ? var.alerts_sns_topic_arn : ""
      EMAIL_SNS_TOPIC_ARN  = local.enable_guardduty_email_alerts ? aws_sns_topic.guardduty_email[0].arn : ""
    }
  }

  # No dead_letter_config, matching the stale-finding watchdog: the Errors
  # alarm below turns any failed run into a page on the same topic, so a
  # silent failure is not a new failure mode.

  tags = merge(var.tags, { Component = "security" })
}

# ---------------------------------------------------------------------------
# EventBridge schedule
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "mfa_audit" {
  count               = local.create_iam_mfa_audit ? 1 : 0
  name                = "${var.name_prefix}-iam-mfa-audit"
  description         = "Weekly audit for IAM users without an MFA device (#1138)"
  schedule_expression = var.iam_mfa_audit_schedule

  tags = merge(var.tags, { Component = "security" })
}

resource "aws_cloudwatch_event_target" "mfa_audit" {
  count     = local.create_iam_mfa_audit ? 1 : 0
  rule      = aws_cloudwatch_event_rule.mfa_audit[0].name
  target_id = "lambda"
  arn       = aws_lambda_function.mfa_audit[0].arn
}

resource "aws_lambda_permission" "mfa_audit" {
  count         = local.create_iam_mfa_audit ? 1 : 0
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.mfa_audit[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.mfa_audit[0].arn
}

# ---------------------------------------------------------------------------
# Alarms
# ---------------------------------------------------------------------------

# Fires whenever the audit reports >= 1 user without MFA. Distinct from the
# Lambda Errors alarm: this is the finding itself, kept alarmable between
# weekly runs. "missing" holds the alarm in its last state between runs so a
# standing violation stays visible in ALARM until a clean run proves green.
#
# DO NOT change treat_missing_data to "notBreaching": the Lambda publishes once
# a week but the alarm evaluates daily (period 86400), so 6 of every 7 days are
# legitimately missing. "missing" maintains state across that gap;
# "notBreaching" would silently clear the alarm to OK the day after it fires and
# reopen the #1138 detection gap. Same warning applies to the two alarms below.
resource "aws_cloudwatch_metric_alarm" "iam_users_without_mfa" {
  count = local.create_iam_mfa_audit ? 1 : 0

  alarm_name          = "${var.name_prefix}-iam-users-without-mfa"
  alarm_description   = "One or more console-enabled IAM users have no MFA device (#1138). Programmatic-only users are excluded. Enroll MFA or remove the user; attach the require_mfa policy to enforce."
  namespace           = "LayerV/NHP/Security"
  metric_name         = "IAMUsersWithoutMFA"
  dimensions          = { Environment = var.environment }
  statistic           = "Maximum"
  period              = 86400
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "missing"
  alarm_actions       = local.security_alert_destination_arns
  ok_actions          = local.security_alert_destination_arns

  tags = merge(var.tags, { Component = "security" })
}

# Closes the all-users-failed false-green: if every user's ListMFADevices call
# throws, IAMUsersWithoutMFA is published as 0 (dashboard looks clean) and the
# handler returns normally (per-user errors are caught), so neither the finding
# alarm above nor the Lambda Errors alarm below fires. This alarm trips on any
# non-zero per-user check-error count so the primary metric's zero isn't read as
# "clean." Mirrors the stale-finding watchdog's region-errors alarm.
resource "aws_cloudwatch_metric_alarm" "mfa_audit_check_errors" {
  count = local.create_iam_mfa_audit ? 1 : 0

  alarm_name          = "${var.name_prefix}-iam-mfa-audit-check-errors"
  alarm_description   = "IAM MFA audit hit a per-user check error (#1138); IAMUsersWithoutMFA may be a false zero. Inspect the Lambda logs."
  namespace           = "LayerV/NHP/Security"
  metric_name         = "IAMMfaAuditCheckErrors"
  dimensions          = { Environment = var.environment }
  statistic           = "Maximum"
  period              = 86400
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "missing"
  alarm_actions       = local.security_alert_destination_arns
  ok_actions          = local.security_alert_destination_arns

  tags = merge(var.tags, { Component = "security" })
}

# Closes the all-channels-failed dropped-alert gap: if a real finding exists but
# every SNS publish throws (e.g. an SNS regional event), the Lambda's per-channel
# excepts CATCH the failure, so the handler returns normally and the AWS/Lambda
# Errors alarm below never fires — the page is silently lost. The Lambda counts
# failed publishes into IAMMfaAuditPublishErrors (emitted every run, 0 when
# clean); this alarm trips on any non-zero count so a dropped page is never
# silent. Same "do not flip to notBreaching" warning as the alarms above applies.
resource "aws_cloudwatch_metric_alarm" "mfa_audit_publish_errors" {
  count = local.create_iam_mfa_audit ? 1 : 0

  alarm_name          = "${var.name_prefix}-iam-mfa-audit-publish-errors"
  alarm_description   = "IAM MFA audit failed to publish an alert to one or more channels (#1138); a no-MFA finding may not have paged. Inspect the Lambda logs."
  namespace           = "LayerV/NHP/Security"
  metric_name         = "IAMMfaAuditPublishErrors"
  dimensions          = { Environment = var.environment }
  statistic           = "Maximum"
  period              = 86400
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "missing"
  alarm_actions       = local.security_alert_destination_arns
  ok_actions          = local.security_alert_destination_arns

  tags = merge(var.tags, { Component = "security" })
}

# A failed invocation means "nobody checked for another week". Turn it into a
# page on the same topic so failures are no quieter than successes.
resource "aws_cloudwatch_metric_alarm" "mfa_audit_errors" {
  count = local.create_iam_mfa_audit ? 1 : 0

  alarm_name          = "${var.name_prefix}-iam-mfa-audit-errors"
  alarm_description   = "IAM MFA audit Lambda failed (#1138)"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.mfa_audit[0].function_name }
  statistic           = "Sum"
  period              = 86400
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "missing"
  alarm_actions       = local.security_alert_destination_arns
  ok_actions          = local.security_alert_destination_arns

  tags = merge(var.tags, { Component = "security" })
}
