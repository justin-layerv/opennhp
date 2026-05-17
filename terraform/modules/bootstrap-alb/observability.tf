# CloudWatch alarms + SNS topic for the bootstrap ALB.
#
# Alarms wired:
#   - alb-target-5xx           — qurl-service runtime errors
#   - alb-elb-5xx              — ALB-side 5xx (no healthy targets, etc.)
#   - alb-unhealthy-hosts      — target-health
#   - alb-tls-handshake-failures — TLS-handshake failures
#   - waf-blocked-requests-rate — WAF blocked-request rate (rate-limit rule)
#
# Alarm routing follows the producer-keeps-SNS pattern: alerts-infra
# (the org-wide AWS Chatbot home, per project memory) subscribes to
# this topic separately. This module does NOT create any chat-platform
# channel configuration resource.

# Centralized SNS topic for all alarms attached to this stack.
# AWS-managed KMS encryption (`alias/aws/sns`) — alarm payloads carry
# resource ARNs + threshold values (low sensitivity, baseline-compliance
# scanners flag unencrypted topics) and the managed alias carries no
# per-key cost.
resource "aws_sns_topic" "alerts" {
  name              = "${local.alb_name}-alerts"
  kms_master_key_id = "alias/aws/sns"

  tags = merge(local.tags, { Name = "${local.alb_name}-alerts" })
}

# SNS topic policy. Attaching `aws_sns_topic_policy` REPLACES the
# default implicit grants — so this policy MUST explicitly carry
# every statement the topic needs to keep working:
#
#   1. `AllowCloudWatchAlarms`: this stack's same-account alarms
#      publish via the CloudWatch service principal. Without this,
#      every alarm publishes silently fail and alarm payloads never
#      reach the topic.
#   2. `AllowAccountAccess`: account-root principal can administer
#      the topic (publish, subscribe, manage). Operator-side IAM
#      principals (e.g., reading the topic via console) fall through
#      this statement when their identity-based policies don't carry
#      the right grants.
#   3. `AllowCrossAccountSubscribe`: alerts-infra (the org-wide AWS
#      Chatbot home) subscribes to this stack's alerts topic from a
#      separate AWS account. Conditional on
#      `var.cross_account_subscriber_arns` being non-empty —
#      `aws_iam_policy_document` accepts a `dynamic "statement"`
#      block, but the simpler `count`-gated shape is more readable
#      and produces the same JSON.
#
# Pattern mirrors `terraform/modules/monitoring/main.tf` precedent.
# The topic policy is ALWAYS attached (not gated on the cross-account
# list) because the same-account grants must be present unconditionally.
data "aws_iam_policy_document" "alerts" {
  statement {
    sid    = "AllowCloudWatchAlarms"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # Account-root admin. Defense-in-depth: account principals
  # usually have identity-based-policy access to SNS already, so
  # this statement is redundant in the common case. But the moment
  # someone attaches a deny-based SCP or a deny statement to an
  # operator's IAM principal, an explicit resource-level Allow
  # for account-root is what keeps the topic administrable. Same
  # shape as `terraform/modules/monitoring/main.tf::AllowAccountAccess`.
  statement {
    sid    = "AllowAccountAccess"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions = [
      "sns:Publish",
      "sns:Subscribe",
      "sns:GetTopicAttributes",
      "sns:SetTopicAttributes",
      "sns:AddPermission",
      "sns:RemovePermission",
      "sns:DeleteTopic",
      "sns:ListSubscriptionsByTopic",
    ]
    resources = [aws_sns_topic.alerts.arn]
  }

  # Cross-account subscribe — conditional, emitted only when
  # `var.cross_account_subscriber_arns` is non-empty.
  dynamic "statement" {
    for_each = length(var.cross_account_subscriber_arns) > 0 ? [1] : []

    content {
      sid    = "AllowCrossAccountSubscribe"
      effect = "Allow"

      principals {
        type        = "AWS"
        identifiers = var.cross_account_subscriber_arns
      }

      # `sns:Subscribe` is the only action needed on the topic-policy
      # side. `sns:Receive` is evaluated against the publisher's
      # principal (this stack's CloudWatch alarms), not against the
      # cross-account subscriber — granting it here would be a no-op.
      actions   = ["sns:Subscribe"]
      resources = [aws_sns_topic.alerts.arn]

      # Restrict the cross-account subscriber to delivery protocols
      # alerts-infra actually uses. Defense-in-depth: if the
      # alerts-infra role were ever compromised, an attacker could
      # otherwise subscribe an HTTP endpoint and exfiltrate alarm
      # payloads (resource ARNs + threshold values — low sensitivity
      # but recon-useful). Restricting to `lambda` (Chatbot's
      # canonical delivery path) + `https` (alternate webhook
      # delivery) + `email` (operator email fallback) keeps the
      # legitimate alerts-infra integrations working while denying
      # the raw-HTTP-exfil shape.
      #
      # **Allowlist widening coupling**: AWS Chatbot today routes
      # primarily via the `lambda` protocol, but some Slack
      # integrations use SQS-mediated delivery. If alerts-infra
      # ever switches the bootstrap-alb topic to SQS-mediated
      # subscription, this list MUST be widened to include `sqs`
      # in the SAME PR — otherwise the subscribe call 403s with no
      # AuthorizationError surfacing on this stack's side (it's on
      # alerts-infra's apply graph). Keep the allowlist + the
      # alerts-infra delivery shape in lockstep.
      condition {
        test     = "StringEquals"
        variable = "sns:Protocol"
        values   = ["lambda", "https", "email"]
      }
    }
  }

  # Deny non-TLS API access. Parallel to the deny-non-TLS bucket
  # policies in `access_logs.tf` — SNS supports HTTPS endpoints
  # natively, so this statement breaks nothing in practice but
  # closes the gap for baseline-compliance scanners (AWS Config
  # `sns-topic-message-delivery-notification-enabled` and similar).
  # `Action = sns:*` mirrors the bucket-policy shape.
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["sns:*"]
    resources = [aws_sns_topic.alerts.arn]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts.json
}

resource "aws_sns_topic_subscription" "email" {
  for_each = toset(var.alarm_email_subscriptions)

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value

  # Explicit ordering: subscriptions are account-internal so they
  # don't strictly require the topic policy, but pinning the
  # dependency keeps the apply graph readable and removes the
  # class of fresh-apply edge cases where the subscribe call
  # races the policy attachment.
  depends_on = [aws_sns_topic_policy.alerts]
}

# ALB target 5xx — qurl-service backend returning 5xx. `treat_missing_data
# = notBreaching` keeps the alarm green when the ALB has no traffic
# at all (early-life sandbox, dark-launch window before sidecars start
# bootstrapping).
#
# Dim-set includes BOTH `LoadBalancer` and `TargetGroup`. AWS/ApplicationELB
# publishes `HTTPCode_Target_5XX_Count` with both dims; the
# LoadBalancer-only dim selects an aggregate across all target groups
# attached to the ALB. Today there's exactly one TG (qurl-service), so
# the two forms are functionally identical — but pinning the TG
# explicitly prevents a future second-TG attachment from silently
# cross-contaminating the qurl-service 5xx signal with another
# backend's errors.
#
# **No `Region` dim**: AWS/ApplicationELB metrics are region-implicit
# (the metric stream lives in the region where the ALB exists),
# so a `Region` dim doesn't apply. terraform/CLAUDE.md's "Metric / Alarm
# Dim-Set Rules" `{Component, Environment, Region}` precedent is
# specific to the AC publisher (which custom-emits via
# `IncrCounter` with that exact dim set); AWS-native namespaces
# carry their own publisher-specific dim shapes, which the WAF
# alarm below (`{WebACL, Region, Rule}`) and this ALB-side set
# both reflect.
#
# Note: CloudWatch treats `{LoadBalancer}` and `{LoadBalancer, TargetGroup}`
# as DIFFERENT metric streams. Changing this dim-set on a live env
# resets the alarm's history (state flips to INSUFFICIENT_DATA on
# next refresh). Safe today because the module is default-off; if
# ever changed under live traffic, flag in CHANGELOG.
resource "aws_cloudwatch_metric_alarm" "alb_target_5xx" {
  alarm_name          = "${local.alb_name}-alb-target-5xx"
  alarm_description   = "ALB target returned >${var.alb_5xx_threshold_per_minute} 5xx responses/min — likely qurl-service runtime error on POST /v1/agent/bootstrap"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  datapoints_to_alarm = 3
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = var.alb_5xx_threshold_per_minute
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = aws_lb.this.arn_suffix
    TargetGroup  = aws_lb_target_group.qurl_service.arn_suffix
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  tags = merge(local.tags, { Name = "${local.alb_name}-alb-target-5xx" })
}

# ALB-side (load-balancer-emitted) 5xx — distinct from the target-side
# alarm above. Fires on conditions the TG can't see: no healthy
# targets, listener-rule misconfig, ALB throttling. Lower threshold
# than the target-5xx alarm because ALB-side 5xx is more diagnostic.
#
# **Dark-launch interaction.** Between this stack's first apply and
# the paired qurl-service ECS-attach PR, the TG has zero registered
# targets and `/v1/agent/bootstrap` returns 503 at the listener.
# That counts as ELB-side 5xx — so any sidecar that bootstraps OR
# any scanner that probes the path during the window will trip
# this alarm. Two recommended postures during the dark-launch
# window:
#   1. Pass `bootstrap_alb_cross_account_subscriber_arns = []` in
#      the sandbox tfvars flip PR (defer alerts-infra routing
#      until the paired data-plane PR lands), OR
#   2. Acknowledge the alarm on alerts-infra's chat-platform side
#      for the duration of the window.
# The README's "Step 3 — verify dark-launch posture" calls this out
# explicitly so the operator isn't surprised by a 3am page.
resource "aws_cloudwatch_metric_alarm" "alb_elb_5xx" {
  alarm_name          = "${local.alb_name}-alb-elb-5xx"
  alarm_description   = "Bootstrap ALB itself returned >${var.alb_elb_5xx_threshold_per_minute} 5xx responses/min — no healthy qurl-service targets, listener-rule misconfig, or platform throttling"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  datapoints_to_alarm = 3
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = var.alb_elb_5xx_threshold_per_minute
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = aws_lb.this.arn_suffix
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  tags = merge(local.tags, { Name = "${local.alb_name}-alb-elb-5xx" })
}

# Unhealthy host count: 2-of-2 evaluation so a transient drain blip
# during a normal qurl-service rolling deploy doesn't page. Default
# threshold 0 (= 'page on any unhealthy host') — qurl-service is the
# only thing this ALB forwards to, so any unhealthy target IS the
# bootstrap outage.
#
# **Threshold + comparison-operator semantics.** `GreaterThanThreshold`
# + `threshold = 0` reads as "fire when count > 0", i.e. ≥ 1 unhealthy
# host. Threshold 0 does NOT silence the alarm. The variable's
# allowable range is `≥ 0` (see `variables.tf::alb_unhealthy_hosts_threshold`).
# Kept this shape over the more-obvious `GreaterThanOrEqualToThreshold`
# + `threshold = 1` to preserve the "tune up only if the qurl-service
# ECS service runs N+ tasks and partial outage tolerates N+ unhealthy"
# semantics — N is a count of how many unhealthy is acceptable, which
# reads more naturally as `> N` than as `≥ N+1`.
resource "aws_cloudwatch_metric_alarm" "alb_unhealthy_hosts" {
  alarm_name          = "${local.alb_name}-alb-unhealthy-hosts"
  alarm_description   = "qurl-service target group has had unhealthy targets across 2 consecutive 1-minute windows — bootstrap surface is degraded (wall-clock to ALARM ~2–3 min including CloudWatch evaluation latency)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Maximum"
  threshold           = var.alb_unhealthy_hosts_threshold
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = aws_lb.this.arn_suffix
    TargetGroup  = aws_lb_target_group.qurl_service.arn_suffix
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  tags = merge(local.tags, { Name = "${local.alb_name}-alb-unhealthy-hosts" })
}

# TLS handshake failures: signal of cert misconfiguration, an in-flight
# cert rotation that didn't propagate, or an attacker probing for
# downgrade. The metric is `ClientTLSNegotiationErrorCount`; a 0
# threshold would fire on every legacy TLS-1.0 client probe (which is
# benign internet noise). Default 10/min filters that while catching
# real cert/protocol misconfigurations.
#
# Worth watching specifically for the bootstrap surface because TLS-
# handshake failures pre-date any application-layer signal — a sidecar
# whose system clock is wrong (cert validity check fails) sees the
# handshake fail and never makes it to the bootstrap handler at all.
# qurl-service's audit-row writer can't see those calls; this alarm
# is the only signal.
resource "aws_cloudwatch_metric_alarm" "alb_tls_handshake_failures" {
  alarm_name          = "${local.alb_name}-alb-tls-handshake-failures"
  alarm_description   = "ALB observed >${var.alb_tls_handshake_failure_threshold}/min TLS handshake failures for ≥3min — cert misconfiguration, downgrade probing, or sidecar clock skew. NOTE: ALB access logs don't capture pre-handshake requests, so this alarm has no forensic payload source today; #1896 tracks enabling `aws_lb.connection_logs` (provider 5.20+) to close that gap."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  datapoints_to_alarm = 3
  metric_name         = "ClientTLSNegotiationErrorCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = var.alb_tls_handshake_failure_threshold
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = aws_lb.this.arn_suffix
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  tags = merge(local.tags, { Name = "${local.alb_name}-alb-tls-handshake-failures" })
}

# WAF rate-limit blocks. Scoped specifically to the
# `RateLimitPerSourceIP` rule: AWS/WAFV2 publishes BlockedRequests
# per-rule with no `Rule = "ALL"` aggregate value, so an alarm without
# the Rule dimension stays in INSUFFICIENT_DATA forever. Managed-rule
# blocks are routine internet noise (IP reputation hits, bot
# signatures); rate-limit hits indicate real probing or a misbehaving
# caller — that's the actionable signal.
#
# **Dim-set exact-match.** Per terraform/CLAUDE.md's "Metric / Alarm Dim-Set
# Rules" section, CloudWatch alarms select their metric stream by
# EXACT dimension match. AWS/WAFV2 publishes `BlockedRequests` with
# `{WebACL, Region, Rule}` — the alarm's `dimensions` map below
# lists those three exactly. Adding a fourth dim (`Action`,
# `RuleGroupId`, etc.) would silently select a non-existent stream
# and the alarm sits in INSUFFICIENT_DATA forever.
resource "aws_cloudwatch_metric_alarm" "waf_rate_limit_blocks" {
  alarm_name          = "${local.alb_name}-waf-rate-limit-blocks"
  alarm_description   = "WAF rate-limit rule blocked >${var.waf_blocked_threshold_per_5min} requests/5min for ≥10min — likely active probing of /v1/agent/bootstrap or a misbehaving caller"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 300
  statistic           = "Sum"
  threshold           = var.waf_blocked_threshold_per_5min
  treat_missing_data  = "notBreaching"

  dimensions = {
    WebACL = aws_wafv2_web_acl.this.name
    Region = data.aws_region.current.id
    Rule   = local.waf_rule_rate_limit
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  tags = merge(local.tags, { Name = "${local.alb_name}-waf-rate-limit-blocks" })
}
