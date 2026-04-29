# =====================================================================
# ECR Cross-Account Replication Failure Detector (issue #1320)
# =====================================================================
#
# Steady-state alarm that closes the observability gap exposed by the
# 2026-04-24 prod release incident (see
# docs/incidents/2026-04-24-ecr-source-account-trap.md): a scheduled
# Lambda walks recent ECR pushes, calls describe-image-replication-status
# per digest, and emits a per-repo CloudWatch metric so an alarm can fire
# on any non-zero failed count. ECR has no native metric for replication
# status and no list-failed-replications API, which is why this is a
# probe rather than a metric subscription.
#
# Cadence: 15-minute schedule × 2 evaluation periods. Worst-case
# detection latency is up to ~15 min waiting for the next probe tick
# + 2 × 15-min eval = ~45 min total (the "~30 min" figure is the
# eval window only, assuming the failure aligns with a tick).
# Comfortably inside the 1-hour SLO from #1320 either way.
#
# Resources gated on `module.ecr.is_replication_source` (single
# source of truth from
# `terraform/modules/ecr/main.tf::local.is_replication_source`):
# log group, IAM role + 2 inline policies, Lambda function
# + event_invoke_config, EventBridge rule + target + Lambda permission,
# 1 per-repo failure alarm (for_each), errors alarm, throttles alarm,
# not-invoking alarm. Adding a new gated resource? Use the same gate
# and update this list.

locals {
  ecr_replication_check_period = 900 # 15 minutes

  # Lockstep between IAM `cloudwatch:namespace` Condition, the alarm's
  # `namespace`, and the Lambda's `METRIC_NAMESPACE` env. Rename here
  # propagates to all three.
  ecr_replication_check_metric_namespace = "LayerV/NHP"

  # Per-repo alarm-name suffix used in both the alarm_name and the
  # `Name` tag of `aws_cloudwatch_metric_alarm.ecr_replication_failure`.
  # `trimprefix` strips the canonical `layerv/` so the alarm name
  # doesn't double up with `local.name_prefix` (which already starts
  # with `layerv-nhp-`). `replace(/, -)` then translates any remaining
  # path separator into a dash, so a future non-`layerv/` namespace
  # gets graceful handling — `org-x/foo` becomes
  # `…-replication-failure-org-x-foo` rather than failing apply on
  # AWS's no-`/`-in-alarm-name rule.
  #
  # Gated on `is_replication_source` so secondary accounts don't
  # compute it for nothing (the alarms themselves are gated the same
  # way; this just keeps plan-time tidy on accounts where the local
  # would never be used).
  ecr_replication_alarm_suffix = module.ecr.is_replication_source ? {
    for name in module.ecr.repository_names :
    name => replace(trimprefix(name, "layerv/"), "/", "-")
  } : {}
}

data "archive_file" "ecr_replication_check" {
  count       = module.ecr.is_replication_source ? 1 : 0
  type        = "zip"
  source_file = "${path.module}/lambda/ecr_replication_check.py"
  output_path = "${path.module}/lambda/.build/ecr_replication_check.zip"
}

resource "aws_cloudwatch_log_group" "ecr_replication_check" {
  count = module.ecr.is_replication_source ? 1 : 0
  name  = "/aws/lambda/${local.name_prefix}-ecr-replication-check"
  # `is_replication_source` only flips true on sandbox today (prod is
  # the destination, not the source), so a prod-branch on retention
  # would be dead code per CLAUDE.md "don't design for hypothetical
  # future requirements." If prod ever becomes a replication source,
  # bump this conditionally then.
  retention_in_days = 14
  kms_key_id        = module.kms.logs_key_arn

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-ecr-replication-check-logs"
    Component = "ecr"
  })
}

resource "aws_iam_role" "ecr_replication_check" {
  count = module.ecr.is_replication_source ? 1 : 0
  name  = "${local.name_prefix}-ecr-replication-check"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-ecr-replication-check-role"
    Component = "ecr"
  })
}

resource "aws_iam_role_policy" "ecr_replication_check_logs" {
  count = module.ecr.is_replication_source ? 1 : 0
  name  = "logs"
  role  = aws_iam_role.ecr_replication_check[0].id

  # Tighter than the AWS-managed `AWSLambdaBasicExecutionRole`, which
  # grants `logs:CreateLogStream` / `logs:PutLogEvents` against
  # `arn:aws:logs:*:*:*`. Pin to the function's own log group so a
  # future role-confusion bug can't write to other log streams.
  # `CreateLogGroup` is omitted because the group is Terraform-managed.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ]
      Resource = "${aws_cloudwatch_log_group.ecr_replication_check[0].arn}:*"
    }]
  })
}

resource "aws_iam_role_policy" "ecr_replication_check" {
  count = module.ecr.is_replication_source ? 1 : 0
  name  = "ecr-and-cloudwatch"
  role  = aws_iam_role.ecr_replication_check[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DescribeECRImagesAndReplicationStatus"
        Effect = "Allow"
        # Both APIs are repo-scoped. Resources are pinned to the
        # ECR-module-managed repos rather than "*" so a future ECR repo
        # outside this module can't be probed by accident. Pulling ARNs
        # straight from the module output (rather than reconstructing
        # them from `primary_account_id`, which is empty by precondition
        # on the primary account where this Lambda runs) keeps the
        # source of truth in the resource itself.
        Action = [
          "ecr:DescribeImages",
          "ecr:DescribeImageReplicationStatus",
        ]
        Resource = module.ecr.repository_arns
      },
      {
        Sid    = "PublishMetrics"
        Effect = "Allow"
        # PutMetricData has no resource-level permissions. Restrict by
        # namespace via a Condition so the role can only emit under
        # the project's own namespace and can't pollute arbitrary
        # cells. Namespace string is in `local.ecr_replication_check_
        # metric_namespace` so the IAM condition, the alarm namespace,
        # and the Lambda's runtime publish all stay in lockstep.
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = local.ecr_replication_check_metric_namespace
          }
        }
      },
    ]
  })
}

resource "aws_lambda_function" "ecr_replication_check" {
  count = module.ecr.is_replication_source ? 1 : 0

  depends_on = [aws_cloudwatch_log_group.ecr_replication_check]

  filename         = data.archive_file.ecr_replication_check[0].output_path
  function_name    = "${local.name_prefix}-ecr-replication-check"
  role             = aws_iam_role.ecr_replication_check[0].arn
  handler          = "ecr_replication_check.handler"
  source_code_hash = data.archive_file.ecr_replication_check[0].output_base64sha256
  runtime          = "python3.12"
  # 120s vs the cloudfront_cidr_drift template's 30s — this Lambda
  # walks N repos × M recent images sequentially, so headroom against
  # ECR throttling matters more than cold-start savings. At today's
  # call rate (~40 calls/run × ~50 ms) this is ~10× the steady-state
  # work; bumping the headroom is free until invocation duration
  # actually rises. The 120s ceiling also stays well under the 900s
  # schedule period — if a future scale-up pushes runtime past 900s,
  # the next tick's invocation throttles silently against
  # reserved_concurrent_executions=1 and only the not-invoking alarm
  # (45-min eval window) catches it. Bump both timeout AND the
  # not-invoking alarm's evaluation_periods if/when that ratio tightens.
  timeout     = 120
  memory_size = 128
  # PAIRED INVARIANT with `maximum_retry_attempts = 0` below: together
  # they prevent EventBridge from queuing a retry against an already-
  # running successor. Touching either without the other re-opens
  # implicit-replay accumulation.
  reserved_concurrent_executions = 1

  environment {
    variables = {
      REPOSITORIES     = join(",", module.ecr.repository_names)
      ENVIRONMENT      = var.environment
      LOOKBACK_HOURS   = tostring(var.ecr_replication_check_lookback_hours)
      METRIC_NAMESPACE = local.ecr_replication_check_metric_namespace
      # AWS rejects `AWS_REGION` as a user-set key in
      # `environment.variables` (the Lambda runtime owns it); plumbing
      # the value through `EXPECTED_REGION` lets non-Lambda imports
      # (tests, ops scripts) read the same value Terraform deploys.
      EXPECTED_REGION = var.aws_region
    }
  }

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-ecr-replication-check"
    Component = "ecr"
  })

  # Plan-time enforcement of the lookback↔untagged-expiry cushion.
  # CONSERVATIVE BY DESIGN: under today's deploy model every digest
  # carries an immutable git-SHA tag, so the relevant lifecycle bound
  # is `tagged_expiry` (90d / 2160h), not `untagged_expiry` (7d /
  # 168h) — a probe-blind window only opens if the SHA-backbone is
  # ever violated (#1489 tracks the CI lint that prevents that).
  # The fence still uses `untagged_expiry` because (a) it's the
  # tighter bound and matches the worst-case scenario the runbook
  # documents under "Bonus failure mode: tag rotation", and (b) the
  # variable's own [1, 720] validation can't even reach the
  # `tagged_expiry` ceiling. Until #1489 lands, this fence is what
  # protects against a regression that introduces a no-SHA-backbone
  # push AND a long-lookback config in the same PR.
  lifecycle {
    precondition {
      condition     = var.ecr_replication_check_lookback_hours < module.ecr.untagged_expiry_hours
      error_message = "ecr_replication_check_lookback_hours (${var.ecr_replication_check_lookback_hours}h) must be strictly less than the untagged-image lifecycle expiry (${module.ecr.untagged_expiry_hours}h, sourced from `terraform/modules/ecr/main.tf::local.ecr_untagged_expiry_days`). The variable's own validation accepts up to 720h to leave headroom for #1489 — until that lands, this precondition is the actual ceiling. See docs/runbooks/ecr-replication-failure.md."
    }

    # Catches future repos like `layerv/foo/bar` and `layerv/foo-bar`
    # collapsing to the same alarm-name suffix at plan time rather
    # than apply (the `for_each` would otherwise fail with a
    # duplicate-key error).
    precondition {
      condition     = length(distinct(values(local.ecr_replication_alarm_suffix))) == length(local.ecr_replication_alarm_suffix)
      error_message = "ECR replication alarm suffixes collide: ${jsonencode(local.ecr_replication_alarm_suffix)}. Rename one repo or revise `local.ecr_replication_alarm_suffix`."
    }
  }
}

resource "aws_cloudwatch_event_rule" "ecr_replication_check" {
  count               = module.ecr.is_replication_source ? 1 : 0
  name                = "${local.name_prefix}-ecr-replication-check"
  description         = "Probe ECR cross-account replication status every 15 minutes"
  schedule_expression = "rate(15 minutes)"

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-ecr-replication-check-rule"
    Component = "ecr"
  })
}

resource "aws_cloudwatch_event_target" "ecr_replication_check" {
  count     = module.ecr.is_replication_source ? 1 : 0
  rule      = aws_cloudwatch_event_rule.ecr_replication_check[0].name
  target_id = "ecr-replication-check"
  arn       = aws_lambda_function.ecr_replication_check[0].arn

  # Belt-and-braces against EventBridge's own delivery retry (default
  # 24h / 185 attempts). Paired with `aws_lambda_function_event_invoke_
  # config { maximum_retry_attempts = 0 }` below, no failed delivery
  # can accumulate and land while the next 15-min tick is also running.
  # `maximum_event_age_in_seconds` would be a no-op alongside
  # `maximum_retry_attempts = 0` (no retries means no aging) so it's
  # omitted; the Lambda-side `event_invoke_config` carries the
  # corresponding 60s bound where it actually applies.
  retry_policy {
    maximum_retry_attempts = 0
  }
}

resource "aws_lambda_permission" "ecr_replication_check" {
  count         = module.ecr.is_replication_source ? 1 : 0
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ecr_replication_check[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ecr_replication_check[0].arn
}


# Disable Lambda's async-invoke retry. EventBridge invokes async, and
# AWS's default async retry policy retries throttled invocations for
# up to 6 hours — meaning a single throttled tick (e.g., the prior tick
# is still running and `reserved_concurrent_executions = 1` rejects
# the next one) gets implicitly replayed against an already-running
# successor. The not-invoking alarm catches the durable case; the
# explicit retry-disable just prevents implicit replay accumulation.
# Today's runtime is well under 15 minutes, so this is purely
# defensive.
resource "aws_lambda_function_event_invoke_config" "ecr_replication_check" {
  count         = module.ecr.is_replication_source ? 1 : 0
  function_name = aws_lambda_function.ecr_replication_check[0].function_name
  # `maximum_event_age_in_seconds` here is NOT a no-op (unlike on the
  # EventBridge target's `retry_policy` block, where it is). It bounds
  # how long an event can sit in Lambda's async-invoke queue before
  # the *initial* delivery is abandoned — relevant under
  # `reserved_concurrent_executions = 1` if a tick overlaps the prior
  # tick's runtime and queues the new event behind it.
  #
  # 300s caps the queue wait at ~33% of one schedule period, so an
  # event can't sit through more than one full skipped tick. Default
  # is 21600s (6h) — way too long for a 15-min-cadence probe.
  # Aged-out events are discarded silently (no metric) so the
  # not-invoking alarm is the durable signal; DLQ follow-up #1488
  # tracks surfacing age-outs faster than the 45-min not-invoking
  # window.
  #
  # Post-hoc forensics nuance: under sustained throttling (a stuck
  # tick exceeding the schedule period), each subsequent event sits
  # in the async queue for up to 300s before being aged out *silently*
  # — no metric, no log, no DLQ entry today. The Throttles alarm
  # fires immediately on the rejected attempt so coverage is intact,
  # but the post-mortem signal is "Invocations non-zero, Errors zero,
  # observed throughput dropped" which can mislead first responders.
  # #1488 (DLQ) is the right place to close this gap.
  maximum_retry_attempts       = 0
  maximum_event_age_in_seconds = 300
}

# Per-repository alarm. for_each over the repo set so the alarm name
# tells on-call exactly which repo is affected — the metric is
# dimensioned by Repository, but the alarm name is what shows up in
# the SNS message subject and Slack post. Suffix-translation lives
# in `local.ecr_replication_alarm_suffix` so alarm_name and the Name
# tag stay in lockstep.
#
# KEYS-STABILITY NOTE: `for_each = toset(...)` keys ARE the repo
# names themselves (a set is unordered, so list-order doesn't
# matter), so the alarm keys are stable as long as the repo names
# don't mutate. A refactor that changes the value shape — e.g.,
# adding a prefix/suffix or dropping `layerv/` from the canonical
# form — would tear-down + recreate every alarm (brief gap in
# coverage). Touch `module.ecr.repository_names`'s value pattern
# carefully; the format precondition there already fences this.
resource "aws_cloudwatch_metric_alarm" "ecr_replication_failure" {
  for_each = module.ecr.is_replication_source ? toset(module.ecr.repository_names) : toset([])

  alarm_name        = "${local.name_prefix}-ecr-replication-failure-${local.ecr_replication_alarm_suffix[each.value]}"
  alarm_description = "ECR cross-account replication is failing for ${each.value}. See docs/runbooks/ecr-replication-failure.md and the rationale in issue #1320."

  # `threshold = 0` + `Maximum` is the lockstep pair: the alarm fires
  # iff any datapoint in the evaluation window is non-zero. Changing
  # the threshold (e.g., to "more than N persistent failures") MUST
  # also re-evaluate `statistic` — `Maximum` and `Sum` would diverge
  # sharply for any threshold > 0, especially under a cadence bump.
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  period              = local.ecr_replication_check_period
  metric_name         = "ECRReplicationFailureCount"
  namespace           = local.ecr_replication_check_metric_namespace
  # Lockstep with the publisher's `Unit = "Count"`.
  unit = "Count"
  # `Maximum` (not `Sum`) is robust to a future schedule-cadence bump
  # that puts >1 sample per period — Sum would over-count.
  statistic          = "Maximum"
  treat_missing_data = "notBreaching"

  dimensions = {
    Environment = var.environment
    Repository  = each.value
  }

  alarm_actions = [module.monitoring.sns_topic_arn]
  ok_actions    = [module.monitoring.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-ecr-replication-failure-${local.ecr_replication_alarm_suffix[each.value]}-alarm"
    Component = "ecr"
  })

  # Belt-and-braces against a degenerate suffix — if a future repo
  # name like `"layerv/"` ever passed through `trimprefix(..., "layerv/")`
  # it would yield `""` and the alarm name would become
  # `…-replication-failure-` with a trailing dash. Today this is
  # impossible by ECR's own naming rules (`local.ecr_repos` are
  # non-empty path segments and the module's repository_names output
  # is `[for r in local.ecr_repos : "layerv/${r}"]`), but the
  # precondition fences a future change to that pattern.
  lifecycle {
    precondition {
      condition     = length(local.ecr_replication_alarm_suffix[each.value]) > 0
      error_message = "ECR replication alarm suffix is empty for '${each.value}' — check `module.ecr.repository_names` for a name that collapses to empty after `trimprefix(\"layerv/\")`."
    }
  }
}

# Lambda-error alarm: a silent Lambda crash would recreate the exact
# observability gap this whole change exists to close. Required, not
# optional.
#
# Sensitivity is intentionally tighter than the failure-count alarm
# above (period=300, eval=1 → first error pages on the next 5-minute
# bucket, vs the failure-count alarm's 2-of-2-period gating). The two
# alarms fence different signal classes: a transient FAILED → IN_PROGRESS
# resolution is plausible mid-replication and warrants the smoothing,
# but a Lambda exception means the steady-state probe is blind for
# that period and there is no benefit to waiting for a second
# datapoint to confirm. Mirrors the cloudfront_cidr_drift_errors
# pattern at terraform/main.tf around line 2330.
resource "aws_cloudwatch_metric_alarm" "ecr_replication_check_errors" {
  count = module.ecr.is_replication_source ? 1 : 0

  alarm_name        = "${local.name_prefix}-ecr-replication-check-errors"
  alarm_description = "ECR replication-check Lambda is failing. The replication-failure alarm cannot fire while this is broken. See docs/runbooks/ecr-replication-failure.md and issue #1320."

  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  period              = 300
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  statistic           = "Sum"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.ecr_replication_check[0].function_name
  }

  alarm_actions = [module.monitoring.sns_topic_arn]
  ok_actions    = [module.monitoring.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-ecr-replication-check-errors-alarm"
    Component = "ecr"
  })
}

# Throttles alarm. `reserved_concurrent_executions = 1` rejects
# overlapping invocations, and `maximum_retry_attempts = 0` drops them
# silently — no `Errors` metric, no log line. The not-invoking alarm
# catches sustained throttling at +45min, but a single throttled tick
# would otherwise be invisible. This alarm fires at the same +5min
# cadence as the errors alarm so on-call sees throttling immediately,
# closing the last silent-failure surface inside the alarm topology.
resource "aws_cloudwatch_metric_alarm" "ecr_replication_check_throttles" {
  count = module.ecr.is_replication_source ? 1 : 0

  alarm_name        = "${local.name_prefix}-ecr-replication-check-throttles"
  alarm_description = "ECR replication-check Lambda is being throttled. Most likely cause: a tick overlapped the previous one and `reserved_concurrent_executions = 1` rejected it. See docs/runbooks/ecr-replication-failure.md."

  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  period              = 300
  metric_name         = "Throttles"
  namespace           = "AWS/Lambda"
  statistic           = "Sum"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.ecr_replication_check[0].function_name
  }

  alarm_actions = [module.monitoring.sns_topic_arn]
  ok_actions    = [module.monitoring.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-ecr-replication-check-throttles-alarm"
    Component = "ecr"
  })
}

# Invocations alarm: closes the last layer of silent-failure surface.
# The failure-count and errors alarms above both treat_missing_data =
# notBreaching; if the Lambda never runs (EventBridge target broken,
# IAM revoked, account-wide concurrency throttle, the schedule itself
# gets disabled), no Errors metric is emitted and no failure-count
# datapoints land — the alarms stay green even though the probe is
# blind. This alarm goes the other way: missing data is breaching, so
# zero invocations over a 45-minute window pages on-call within ~30
# minutes of the next scheduled tick.
#
# The same pattern probably belongs on cloudfront_cidr_drift and any
# other scheduled probes; #1481 tracks the repo-wide mirror. Closing
# the gap on this Lambda inline because the whole PR exists to
# prevent silent-failure regimes, and leaving the probe vulnerable to
# schedule-layer disablement would re-open the very gap #1320 closes.
resource "aws_cloudwatch_metric_alarm" "ecr_replication_check_not_invoking" {
  count = module.ecr.is_replication_source ? 1 : 0

  alarm_name        = "${local.name_prefix}-ecr-replication-check-not-invoking"
  alarm_description = "ECR replication-check Lambda has not invoked in 45 minutes (~3 schedule cycles). The probe is blind — neither the replication-failure nor the errors alarm can fire while this is broken. NOTE: a transient ALARM during the first apply on a fresh environment is expected (see runbook for first-apply behavior — acknowledge and wait one schedule cycle). See docs/runbooks/ecr-replication-failure.md and issue #1320."

  comparison_operator = "LessThanThreshold"
  threshold           = 1
  # 3 × the 15-minute schedule = 45-minute window. One missed tick is
  # allowable (CloudWatch eventual consistency, AWS Lambda re-warmup);
  # three in a row is a real gap.
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  period              = local.ecr_replication_check_period
  metric_name         = "Invocations"
  namespace           = "AWS/Lambda"
  statistic           = "Sum"
  treat_missing_data  = "breaching"

  dimensions = {
    FunctionName = aws_lambda_function.ecr_replication_check[0].function_name
  }

  alarm_actions = [module.monitoring.sns_topic_arn]
  # No `ok_actions`: with `treat_missing_data = "breaching"`, the
  # bootstrap ALARM→OK transition (first apply, before the first
  # scheduled invocation lands) is a documented false alarm. Routing
  # that OK transition to Slack/email would noise on-call without
  # signal. The ALARM-side notification is enough — operators
  # acknowledge per the runbook and don't need a recovery ping.
  # The other 3 alarms keep `ok_actions` because their OK transitions
  # are real recovery signals.

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-ecr-replication-check-not-invoking-alarm"
    Component = "ecr"
  })
}
