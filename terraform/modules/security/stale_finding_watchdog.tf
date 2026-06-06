# GuardDuty stale-finding watchdog (#1137)
#
# A HIGH-severity GuardDuty finding sat Archived=false for ~2 months
# before anyone noticed. The initial EventBridge → SNS → Chatbot alert
# fires exactly once at finding creation; after that, an un-actioned
# finding goes silent. This watchdog re-alerts on any non-archived
# finding older than var.stale_finding_age_days, so "no one noticed" is
# no longer a silent failure mode.
#
# Scope: does not rotate credentials or mutate AWS state. It is a pure
# read/publish loop — list-findings + get-findings + sns:Publish +
# cloudwatch:PutMetricData. Archival remains a human decision.

locals {
  # Require at least one output channel so a stale finding is never
  # silently discovered but never reported — the whole point of the
  # watchdog is to eliminate "no one noticed" as a failure mode, and
  # a misconfigured deployment that creates the Lambda but has
  # nowhere to publish is the same failure in a different shape.
  #
  # Note: local.enable_guardduty_email_alerts is defined in main.tf
  # as (enable_guardduty_alerts && len(emails) > 0), so email
  # implies alerts. The `||` here is defensive — the email-only
  # branch below and the corresponding Python code path are
  # guardrails against a future refactor that breaks that coupling.
  enable_stale_finding_watchdog = (
    var.enable_guardduty
    && var.enable_stale_finding_watchdog
    && (local.enable_guardduty_alerts || local.enable_guardduty_email_alerts)
  )

  # Preferred destination for watchdog self-failures (Errors alarm):
  # Chatbot->Slack when available, otherwise the email topic. The
  # email-only fallback is guardrail defense — unreachable under
  # current module wiring but kept so a future wiring change that
  # decouples the two doesn't silently lose self-failure detection.
  stale_finding_watchdog_failure_arn = (
    local.enable_guardduty_alerts
    ? var.alerts_sns_topic_arn
    : (local.enable_guardduty_email_alerts ? aws_sns_topic.guardduty_email[0].arn : "")
  )
}

# ---------------------------------------------------------------------------
# Lambda package
# ---------------------------------------------------------------------------

data "archive_file" "stale_finding_watchdog" {
  count       = local.enable_stale_finding_watchdog ? 1 : 0
  type        = "zip"
  source_file = "${path.module}/lambda/stale_finding_watchdog.py"
  output_path = "${path.module}/lambda/stale_finding_watchdog.zip"
}

# ---------------------------------------------------------------------------
# IAM role
# ---------------------------------------------------------------------------
# Least-privilege: list/get findings from any detector in this account
# (GuardDuty resource ARNs are account-scoped), publish to the two
# known alert topics, and emit a single CloudWatch metric namespace.

resource "aws_iam_role" "stale_finding_watchdog" {
  count = local.enable_stale_finding_watchdog ? 1 : 0
  name  = "${var.name_prefix}-guardduty-stale-watchdog"

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

resource "aws_iam_role_policy_attachment" "stale_finding_watchdog_basic" {
  count      = local.enable_stale_finding_watchdog ? 1 : 0
  role       = aws_iam_role.stale_finding_watchdog[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "stale_finding_watchdog" {
  count = local.enable_stale_finding_watchdog ? 1 : 0
  name  = "stale-finding-watchdog"
  role  = aws_iam_role.stale_finding_watchdog[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          # List* operations don't target a specific resource so
          # aws:ResourceAccount is absent; StringEquals against an
          # absent key returns false and the whole statement would
          # deny. Split from the GetFindings condition below so the
          # watchdog can actually enumerate detectors.
          Sid    = "GuardDutyList"
          Effect = "Allow"
          Action = [
            "guardduty:ListDetectors",
            "guardduty:ListFindings",
          ]
          Resource = "*"
        },
        {
          # Per-finding reads carry a detector ARN that pins
          # aws:ResourceAccount, so the condition bounds the role to
          # same-account detectors and blocks a future cross-account
          # GD aggregation from widening GetFindings' blast radius.
          Sid      = "GuardDutyGetFindings"
          Effect   = "Allow"
          Action   = ["guardduty:GetFindings"]
          Resource = "*"
          Condition = {
            StringEquals = {
              "aws:ResourceAccount" = data.aws_caller_identity.current.account_id
            }
          }
        },
        {
          # Lambda enumerates opt-in regions to check GuardDuty
          # detectors fleet-wide; this API is global-read-only and
          # has no resource-level controls.
          Sid      = "EC2DescribeRegions"
          Effect   = "Allow"
          Action   = ["ec2:DescribeRegions"]
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

resource "aws_cloudwatch_log_group" "stale_finding_watchdog" {
  count             = local.enable_stale_finding_watchdog ? 1 : 0
  name              = "/aws/lambda/${var.name_prefix}-guardduty-stale-watchdog"
  retention_in_days = local.is_prod ? 90 : 30
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, { Component = "security" })
}

resource "aws_lambda_function" "stale_finding_watchdog" {
  count = local.enable_stale_finding_watchdog ? 1 : 0

  depends_on = [aws_cloudwatch_log_group.stale_finding_watchdog]

  function_name    = "${var.name_prefix}-guardduty-stale-watchdog"
  filename         = data.archive_file.stale_finding_watchdog[0].output_path
  source_code_hash = data.archive_file.stale_finding_watchdog[0].output_base64sha256
  role             = aws_iam_role.stale_finding_watchdog[0].arn
  handler          = "stale_finding_watchdog.handler"
  runtime          = "python3.12"
  timeout          = 120
  memory_size      = 256

  environment {
    variables = {
      ENVIRONMENT          = var.environment
      ALERTS_SNS_TOPIC_ARN = local.enable_guardduty_alerts ? var.alerts_sns_topic_arn : ""
      EMAIL_SNS_TOPIC_ARN  = local.enable_guardduty_email_alerts ? aws_sns_topic.guardduty_email[0].arn : ""
      SEVERITY_THRESHOLD   = tostring(var.guardduty_alert_severity_threshold)
      STALE_AGE_DAYS       = tostring(var.stale_finding_age_days)
      TRIAGE_RUNBOOK_URL   = local.guardduty_triage_runbook_url
    }
  }

  # No dead_letter_config: the DLQ payload is Lambda's raw async-
  # invocation failure record, not a Chatbot CustomNotification, so
  # Chatbot would render it as a generic fallback while the Errors
  # alarm on the same topic renders natively. Rely on the Errors
  # alarm below for failed runs; "invocation never happened"
  # (throttles, invoke-time IAM errors) at weekly cadence is caught
  # by the follow-up missing-data alarm in #1279.

  tags = merge(var.tags, { Component = "security" })
}

# ---------------------------------------------------------------------------
# EventBridge schedule
# ---------------------------------------------------------------------------
# Runs weekly (Monday 13:00 UTC by default) — matches the #1137 issue's
# recommended cadence and avoids alert-fatigue from daily re-pings on the
# same un-archived finding. With a 7-day staleness threshold, weekly
# re-alerts catch a newly-stale finding within 7–14 days, which is well
# inside the 2-month gap the watchdog is built to close.

resource "aws_cloudwatch_event_rule" "stale_finding_watchdog" {
  count               = local.enable_stale_finding_watchdog ? 1 : 0
  name                = "${var.name_prefix}-guardduty-stale-watchdog"
  description         = "Weekly watchdog for un-archived GuardDuty findings (#1137)"
  schedule_expression = var.stale_finding_watchdog_schedule

  tags = merge(var.tags, { Component = "security" })
}

resource "aws_cloudwatch_event_target" "stale_finding_watchdog" {
  count     = local.enable_stale_finding_watchdog ? 1 : 0
  rule      = aws_cloudwatch_event_rule.stale_finding_watchdog[0].name
  target_id = "lambda"
  arn       = aws_lambda_function.stale_finding_watchdog[0].arn
}

resource "aws_lambda_permission" "stale_finding_watchdog" {
  count         = local.enable_stale_finding_watchdog ? 1 : 0
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.stale_finding_watchdog[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.stale_finding_watchdog[0].arn
}

# ---------------------------------------------------------------------------
# Failure alarm
# ---------------------------------------------------------------------------
# EventBridge retries async Lambda invocations twice then drops on
# failure. For a weekly watchdog a dropped execution means "nobody
# checked for another week" — this alarm turns a Lambda-level failure
# into an immediate Slack/email ping via the same alerts topic the
# watchdog itself publishes to, so failures are no quieter than
# successes. Missing-data is treated as "missing" so a failed run
# stays in ALARM until the next successful run proves green.

resource "aws_cloudwatch_metric_alarm" "stale_finding_watchdog_errors" {
  count = local.enable_stale_finding_watchdog && local.stale_finding_watchdog_failure_arn != "" ? 1 : 0

  alarm_name          = "${var.name_prefix}-guardduty-stale-watchdog-errors"
  alarm_description   = "GuardDuty stale-finding watchdog Lambda failed (#1137)"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.stale_finding_watchdog[0].function_name }
  statistic           = "Sum"
  period              = 86400
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  # "missing" keeps the alarm in its prior state between weekly runs
  # — a failed run stays visible in ALARM until a successful run
  # proves green, rather than self-clearing after 24h of no data.
  treat_missing_data = "missing"
  alarm_actions      = [local.stale_finding_watchdog_failure_arn]
  ok_actions         = [local.stale_finding_watchdog_failure_arn]

  tags = merge(var.tags, { Component = "security" })
}

# Closes the all-regions-failed false-green: if every region throws,
# StaleGuardDutyFindings is published as 0 (dashboard looks healthy)
# while StaleGuardDutyFindingsRegionErrors ticks up. This alarm fires
# on any non-zero error count so the primary metric's zero isn't read
# as "clean."
resource "aws_cloudwatch_metric_alarm" "stale_finding_watchdog_region_errors" {
  count = local.enable_stale_finding_watchdog && local.stale_finding_watchdog_failure_arn != "" ? 1 : 0

  alarm_name          = "${var.name_prefix}-guardduty-stale-watchdog-region-errors"
  alarm_description   = "GuardDuty stale-finding watchdog hit a per-region error (#1137)"
  namespace           = "LayerV/NHP/Security"
  metric_name         = "StaleGuardDutyFindingsRegionErrors"
  dimensions          = { Environment = var.environment }
  statistic           = "Sum"
  period              = 86400
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  # "missing" keeps the alarm in its prior state between weekly runs
  # — a failed run stays visible in ALARM until a successful run
  # proves green, rather than self-clearing after 24h of no data.
  treat_missing_data = "missing"
  alarm_actions      = [local.stale_finding_watchdog_failure_arn]
  ok_actions         = [local.stale_finding_watchdog_failure_arn]

  tags = merge(var.tags, { Component = "security" })
}
