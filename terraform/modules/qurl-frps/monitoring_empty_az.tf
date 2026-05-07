# Per-AZ Cloud Map empty-registration watchdog (#1542).
#
# Hard dependency on PR #1539 (`feat/frps-multi-az`): this file references
# `aws_service_discovery_service.frps_per_az` (created in #1539's main.tf)
# and `var.frps_az_suffixes` (declared in #1539's variables.tf). Until
# #1539 merges and this branch rebases on main, `terraform validate`
# fails on the bare branch. See PR description for the full dependency
# / merge-order context.
#
# The (a=2, b=1, c=0) failure mode: PR #1539 makes qurl-reverse-tunnel-server run as a single
# ASG with desired = length(frps_az_suffixes). The ASG's AZ-balanced
# placement keeps the steady-state distribution at one instance per AZ —
# but a rebalance during instance refresh, or an EC2 launch failure in one
# AZ, can silently drift to (2, 1, 0). The existing
# `instance_status_check_failed` alarm fires on `GroupInServiceInstances < 1`,
# so a total count of 3 distributed across two AZs satisfies it. OwnerIDs
# that hash to the empty AZ then resolve NXDOMAIN.
#
# This file is the *detection layer*. PR #1549 ships the *structural fence*
# (one ASG per AZ, min=max=desired=1 each) which makes (1,1,1) invariant.
# This watchdog stays in place after #1549 as defense in depth — a Cloud
# Map deregistration race or out-of-band deregister still empties a service
# even with a one-ASG-per-AZ topology.
#
# Cost note: 1 EventBridge rule + 1 Lambda invocation every 5 min +
# length(frps_az_suffixes) custom metrics + N+2 alarms (N per-suffix +
# 1 self-failure + 1 EventBridge rule failure) ≈ ~$1.40/month at the
# default 3-AZ fanout (3 metrics × $0.30/mo + 5 alarms × $0.10/mo
# = $0.90 + $0.50; Lambda invocations stay within free tier;
# EventBridge schedule is free). Cheap, but not free.

locals {
  # Single conditional gate so the same expression scopes every resource
  # in this file. `var.deploy_frps` does not exist at the module level
  # (the module's count = var.deploy_frps in root main.tf already gates
  # creation), so the only knob here is `frps_empty_az_alarm_enabled`.
  enable_empty_az_watchdog = var.frps_empty_az_alarm_enabled && var.enable_cloudwatch_alarms
}

# ---------------------------------------------------------------------------
# Lambda package
# ---------------------------------------------------------------------------

data "archive_file" "empty_az_watchdog" {
  count       = local.enable_empty_az_watchdog ? 1 : 0
  type        = "zip"
  source_file = "${path.module}/lambda/empty_az_watchdog.py"
  output_path = "${path.module}/lambda/empty_az_watchdog.zip"
}

# ---------------------------------------------------------------------------
# IAM role
# ---------------------------------------------------------------------------
# Least-privilege:
#   - servicediscovery:DiscoverInstances on Resource="*". Per the AWS
#     IAM service-authorization reference, DiscoverInstances does not
#     support resource-level permissions — a per-service ARN list
#     would silently AccessDenied at runtime. Matches the pattern in
#     `terraform/modules/ac/main.tf` and `terraform/modules/compute/main.tf`.
#     The blast radius is bounded by what the Lambda code itself
#     enumerates (only `frps-${suffix}` services in `var.namespace_name`).
#   - cloudwatch:PutMetricData scoped to the QurlFRPS namespace via
#     the `cloudwatch:namespace` condition key (this API DOES support
#     condition-key-based scoping).
#   - AWSLambdaBasicExecutionRole for log group + stream creation.

resource "aws_iam_role" "empty_az_watchdog" {
  count = local.enable_empty_az_watchdog ? 1 : 0
  name  = "${var.name_prefix}-frps-empty-az-watchdog"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = merge(var.tags, { Component = "frps" })
}

resource "aws_iam_role_policy_attachment" "empty_az_watchdog_basic" {
  count      = local.enable_empty_az_watchdog ? 1 : 0
  role       = aws_iam_role.empty_az_watchdog[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "empty_az_watchdog" {
  count = local.enable_empty_az_watchdog ? 1 : 0
  name  = "frps-empty-az-watchdog"
  role  = aws_iam_role.empty_az_watchdog[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Resource = "*" because DiscoverInstances doesn't support
        # resource-level permissions per the AWS IAM
        # service-authorization reference. A per-ARN list would
        # silently AccessDenied at runtime. See header comment for
        # blast-radius reasoning. Matches `ac/main.tf` and
        # `compute/main.tf`.
        Sid      = "DiscoverInstances"
        Effect   = "Allow"
        Action   = ["servicediscovery:DiscoverInstances"]
        Resource = "*"
      },
      {
        # Namespace-scoped PutMetricData. The `cloudwatch:namespace`
        # condition key is the IAM-supported way to scope writes.
        Sid      = "PutMetricDataQurlFRPS"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "QurlFRPS"
          }
        }
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# Lambda function
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "empty_az_watchdog" {
  count             = local.enable_empty_az_watchdog ? 1 : 0
  name              = "/aws/lambda/${var.name_prefix}-frps-empty-az-watchdog"
  retention_in_days = var.environment == "prod" ? 90 : 30
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, { Component = "frps" })
}

resource "aws_lambda_function" "empty_az_watchdog" {
  count = local.enable_empty_az_watchdog ? 1 : 0

  depends_on = [aws_cloudwatch_log_group.empty_az_watchdog]

  function_name    = "${var.name_prefix}-frps-empty-az-watchdog"
  filename         = data.archive_file.empty_az_watchdog[0].output_path
  source_code_hash = data.archive_file.empty_az_watchdog[0].output_base64sha256
  role             = aws_iam_role.empty_az_watchdog[0].arn
  handler          = "empty_az_watchdog.handler"
  runtime          = "python3.12"
  # 60s is generous: the loop is length(frps_az_suffixes) DiscoverInstances
  # calls (~100ms each at the AWS API SLO) plus the same number of
  # PutMetricData calls. At the default 3-suffix fanout the happy path
  # completes well under 5 seconds; the headroom covers a single
  # per-AZ retry + clock skew.
  #
  # 256 MB is over-provisioned for the work (3 API calls < 5 s), but
  # the cost is rounding error and the extra CPU headroom keeps cold-
  # start latency low — matters for a 5-min cadence where every
  # invocation is effectively a cold start on the first run after a
  # warm-pool drain. Sized to comfortably absorb a future fanout
  # bump (4-5 AZs) without revisiting.
  timeout     = 60
  memory_size = 256

  # Cap concurrent invocations at 1 — defence in depth against an
  # EventBridge retry storm or a slow run that overlaps the next
  # schedule tick. Each cycle is independent (the metric publish is
  # idempotent at any granularity > the alarm period) so serialising
  # is correct; with rate(5 minutes) and a sub-5-second happy path,
  # this is purely a guardrail against pathological queueing.
  #
  # Trade-off: this consumes 1 from the account-wide unreserved
  # concurrency pool. AWS's default per-account ceiling is 1000, so
  # the cost in production-scale accounts is invisible. Worth
  # tracking centrally if the project ever runs many small reserved-
  # concurrency Lambdas in a single sandbox-quota'd account.
  #
  # Runbook note: when reserved concurrency throttles a queued
  # invocation (e.g., a slow run overlaps the next 5-min tick),
  # AWS publishes `Throttles` rather than `Errors`. The
  # `empty_az_watchdog_errors` alarm only watches `Errors`, so a
  # throttle won't fire it. Coverage is intact: EventBridge async
  # invocations retry on throttle, and once retries are exhausted
  # (default 2 retries over up to 6 hours) the failure surfaces in
  # `AWS/Events FailedInvocations`, which `empty_az_watchdog_event_failures`
  # below DOES alarm on. First-on-call should check both metrics.
  #
  # Async-retry implication: a single throttle could replay an old
  # payload up to 6 hours later, well after the 5-min schedule has
  # moved on. The metric publish is idempotent (each cycle's
  # PutMetricData overwrites the previous suffix value within the
  # alarm's evaluation window), so a delayed replay is safe in
  # practice — but it does mean the watchdog is NOT a real-time
  # signal under retry pressure, only an eventually-consistent one.
  reserved_concurrent_executions = 1

  environment {
    variables = {
      # `var.environment` is intentionally not passed — the Lambda
      # doesn't reference it (alarm names carry env via name_prefix,
      # and AZSuffix is the only metric dimension), so plumbing it as
      # an env var would be a cold-start KeyError waiting to happen
      # the first time `var.environment` got dropped from the
      # variables block. See empty_az_watchdog.py and cr round 9.
      NAMESPACE_NAME = var.namespace_name
      AZ_SUFFIXES    = join(",", var.frps_az_suffixes)
    }
  }

  tags = merge(var.tags, { Component = "frps" })
}

# ---------------------------------------------------------------------------
# EventBridge schedule (every 5 min)
# ---------------------------------------------------------------------------
# 5-min cadence pairs with the `< 1 for 2 evaluation periods` alarm
# (10-minute floor on alert latency). Tighter than 5 min runs into the
# Cloud Map registration latency: post-instance-launch, the new instance
# typically registers within 30-90s, so a sub-5-min watchdog cadence
# would page on every instance refresh. 5 min keeps the watchdog quiet
# during normal ASG churn while still catching the (2,1,0) sustained
# failure within ~10-15 min.

resource "aws_cloudwatch_event_rule" "empty_az_watchdog" {
  count               = local.enable_empty_az_watchdog ? 1 : 0
  name                = "${var.name_prefix}-frps-empty-az-watchdog"
  description         = "Per-AZ qurl-reverse-tunnel-server Cloud Map empty-registration watchdog (#1542)"
  schedule_expression = "rate(5 minutes)"

  tags = merge(var.tags, { Component = "frps" })
}

resource "aws_cloudwatch_event_target" "empty_az_watchdog" {
  count     = local.enable_empty_az_watchdog ? 1 : 0
  rule      = aws_cloudwatch_event_rule.empty_az_watchdog[0].name
  target_id = "lambda"
  arn       = aws_lambda_function.empty_az_watchdog[0].arn
  # No `input` / `input_transformer`: EventBridge delivers a
  # synthetic dataless trigger event. The Lambda's full-event INFO
  # log (empty_az_watchdog.py:handler) is safe under that
  # constraint. Adding a payload here, OR wiring a different
  # invocation source (manual `aws lambda invoke`, SQS, etc.),
  # makes that INFO log a potential data-leak vector — audit the
  # log level before wiring any payload.
}

resource "aws_lambda_permission" "empty_az_watchdog" {
  count         = local.enable_empty_az_watchdog ? 1 : 0
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.empty_az_watchdog[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.empty_az_watchdog[0].arn
}

# ---------------------------------------------------------------------------
# Per-AZ alarms
# ---------------------------------------------------------------------------
# One alarm per AZ suffix on `QurlFRPS/PerAZRegistrationCount` (the metric
# the Lambda emits). Alarm fires when Count < 1 for 2 consecutive 5-min
# datapoints — i.e., at least one full Lambda cycle has confirmed the
# empty state. PAGE severity: an empty AZ means ~1/N of OwnerIDs hashing
# to that suffix are getting NXDOMAIN, which is a customer-visible
# tunnel resolution failure.
#
# `treat_missing_data = "missing"` is intentional: a Lambda failure
# (DiscoverInstances throttle, IAM blip) leaves no datapoint for the
# affected suffix this cycle. "missing" tells CloudWatch to evaluate
# only present datapoints — combined with the self-failure Errors
# alarm (and the EventBridge rule's FailedInvocations alarm below),
# a watchdog outage pages via those alarms rather than auto-greening
# this one (which "notBreaching" would do, hiding a real outage
# during the watchdog's own incident). If every evaluation period is
# missing, the alarm transitions to INSUFFICIENT_DATA — paired with
# the self-failure alarms, that's the intended signal that the
# watchdog itself is the layer to investigate, not the AZ.
#
# `statistic = "Minimum"` is the right-direction choice for an empty-
# detection alarm: "Minimum < 1 over the window" means "the window
# saw at least one datapoint at 0," i.e., the AZ was empty at some
# point in the period. With `evaluation_periods = 2 × period 300s`
# already absorbing a single transient flap, "Minimum" wins over
# "Maximum" because Maximum < 1 silently false-greens when a debug
# `aws lambda invoke` (or schedule jitter) lands an extra datapoint
# in the bucket while the AZ briefly recovered: Maximum sees the
# non-zero datapoint and the alarm never fires even though the AZ
# was genuinely empty for the rest of the period. In steady state
# (rate(5 min) × period 300) you get one datapoint per window so
# Minimum and Maximum collapse to the same value; the asymmetric
# failure mode is what tips the choice.
resource "aws_cloudwatch_metric_alarm" "empty_az_per_suffix" {
  for_each = local.enable_empty_az_watchdog ? toset(var.frps_az_suffixes) : toset([])

  alarm_name          = "${var.name_prefix}-frps-empty-az-${each.key}"
  alarm_description   = "qurl-reverse-tunnel-server Cloud Map service frps-${each.key} has 0 registrations for 2 consecutive 5-min cycles. OwnerIDs hashing to AZ suffix '${each.key}' will resolve NXDOMAIN. (#1542)"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "PerAZRegistrationCount"
  namespace           = "QurlFRPS"
  period              = 300
  statistic           = "Minimum"
  threshold           = 1
  treat_missing_data  = "missing"

  dimensions = {
    AZSuffix = each.key
  }

  alarm_actions = local.sns_actions
  ok_actions    = local.sns_actions

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-frps-empty-az-${each.key}"
    Severity  = "page"
    Component = "frps"
  })
}

# ---------------------------------------------------------------------------
# Watchdog self-failure alarms
# ---------------------------------------------------------------------------
# Two alarms cover the two distinct ways the watchdog itself can fail
# silently:
#
#   1. Lambda invocations land but raise (IAM blip, code regression,
#      ServiceDiscovery throttle on every suffix). Caught by the
#      `Errors > 0` alarm below.
#   2. Lambda is never invoked at all (target ARN drift,
#      lambda:InvokeFunction permission revoked out-of-band, async
#      delivery 5xx). Lambda Errors stays at 0 (no invocation means
#      no error datapoint), so the Errors alarm cannot detect this.
#      EventBridge's `FailedInvocations` metric covers it.
#
# Both alarms unconditionally create — same convention as
# `monitoring.tf` (instance_status_check_failed, cpu_high, etc.):
# alarms exist regardless of SNS topic configuration so the alarm
# *state* is queryable from CloudWatch / dashboards even when no
# topic is wired. A misconfigured env (no alarm_sns_topic_arn) means
# silent state changes — the same trade-off the rest of the module
# already makes. Note: this also fixes the SNS-gating asymmetry from
# cr round 1 — the per-suffix alarm above creates unconditionally, so
# this self-failure alarm should too.

resource "aws_cloudwatch_metric_alarm" "empty_az_watchdog_errors" {
  count = local.enable_empty_az_watchdog ? 1 : 0

  alarm_name          = "${var.name_prefix}-frps-empty-az-watchdog-errors"
  alarm_description   = "qurl-reverse-tunnel-server empty-AZ watchdog Lambda errored >= 1 time in the last 15 min. The per-AZ alarms may be in INSUFFICIENT_DATA — investigate Lambda logs. (#1542)"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.empty_az_watchdog[0].function_name }
  statistic           = "Sum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.sns_actions
  ok_actions          = local.sns_actions

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-frps-empty-az-watchdog-errors"
    Severity  = "ticket"
    Component = "frps"
  })
}

# EventBridge `FailedInvocations` covers case (2) above: the rule
# tried to invoke the target but the invocation itself failed
# (lambda:InvokeFunction permission revoked, target Lambda deleted,
# Lambda concurrency limit / reserved-concurrency throttle, async
# delivery 5xx). At rate(5 minutes) a 15-min window is the same
# evaluation surface as the Errors alarm above, so the two raise on
# comparable timescales.
#
# This alarm does NOT cover "rule disabled or deleted" — a deleted
# rule emits no metric datapoints at all, so any threshold against
# `FailedInvocations` would sit in INSUFFICIENT_DATA. That failure
# mode is intentionally out of scope: rule deletion is a deliberate
# operator action, and the module's drift detection (terraform plan
# in CI) catches an out-of-band delete on the next plan cycle.
resource "aws_cloudwatch_metric_alarm" "empty_az_watchdog_event_failures" {
  count = local.enable_empty_az_watchdog ? 1 : 0

  alarm_name          = "${var.name_prefix}-frps-empty-az-watchdog-event-failures"
  alarm_description   = "qurl-reverse-tunnel-server empty-AZ watchdog EventBridge rule failed to invoke its target >= 1 time in the last 15 min. The Lambda may not be running on schedule — investigate EventBridge target / lambda:InvokeFunction permission. NOTE: this alarm does NOT fire if the rule itself is disabled or deleted (no datapoints emitted); rule-deletion is caught at next terraform plan. (#1542)"
  namespace           = "AWS/Events"
  metric_name         = "FailedInvocations"
  dimensions          = { RuleName = aws_cloudwatch_event_rule.empty_az_watchdog[0].name }
  statistic           = "Sum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.sns_actions
  ok_actions          = local.sns_actions

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-frps-empty-az-watchdog-event-failures"
    Severity  = "ticket"
    Component = "frps"
  })
}
