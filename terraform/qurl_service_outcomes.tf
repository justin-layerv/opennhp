# =====================================================================
# qurl-service bootstrap outcomes — CloudWatch Logs metric filters + alarms
# =====================================================================
#
# Source: the `slog.InfoContext("agent_bootstrap_completed", ...)` line
# emitted by `internal/api/handlers/agent_bootstrap.go` in the qurl-service
# repo. The paired audit row + slog line lands on every
# POST /v1/agent/bootstrap; this file alarms on the slog half.
#
# Outcome vocabulary (frozen in qurl-service's classifyBootstrapOutcome):
#   success | unauthorized | forbidden | rate_limited | client_error |
#   server_error | unknown
#
# Of those, **unauthorized** and **rate_limited** are the two that warrant
# paging during the v1 customer ship — both indicate the customer-side
# install is wrong or being abused in a way the existing
# `alb_target_5xx` alarm (in `modules/bootstrap-alb/observability.tf`)
# doesn't surface (those are 5xx, not 4xx).
#
# **Complementarity, not replacement**: these 4xx-outcome alarms ARE
# complementary to the ALB-side 5xx alarms — together they cover the
# bootstrap path, but a full qurl-service outage (no logs landing at
# all) is the ALB-5xx alarm's job, not these. The metric filters here
# only emit on log activity (`default_value = 0` triggers on
# non-matching events in the period); a silent log group produces no
# samples and `treat_missing_data = notBreaching` keeps these quiet
# while the ALB-5xx alarm pages.
#
# Placement: this file lives at root (not inside `modules/bootstrap-alb`)
# because the filters read the **qurl-service** log group, not the
# bootstrap-ALB's. Putting them inside `modules/bootstrap-alb` would force
# the module to take `qurl_service_log_group_name` as input — which means
# wiring `module.qurl_service[0].log_group_name` into
# `module.bootstrap_alb`. That creates a TF dependency cycle because
# `module.qurl_service` already consumes `module.bootstrap_alb`'s
# `target_group_arn` and `alb_security_group_id` (see the structural
# check fence at the top of `main.tf` around the `bootstrap_alb` block).
# Root-level placement breaks the cycle: root depends on both modules,
# but neither module needs to know about the other for this surface.
# Precedent: `terraform/ecr_replication_check.tf` is the same shape —
# a root-level observability file that crosses module boundaries.
#
# Conditional on `deploy_qurl_service` only. Filters AND alarms land
# together — both source from the qurl-service log group, and the
# alarm fan-out target (`module.monitoring.sns_topic_arn`) is
# unconditional so there's no separate alarm-side gate. An env that
# opts out of `deploy_qurl_service` gets neither.

locals {
  # Single gate: the metric filters AND alarms land together when
  # `deploy_qurl_service` is set. The qurl-service log group is the
  # source for both surfaces, and the alarm fan-out target —
  # `module.monitoring.sns_topic_arn` — is unconditional (the
  # monitoring module has no `count`), so there's no separate
  # gate-arm to factor out.
  #
  # Routing through `module.monitoring.sns_topic_arn` matches every
  # other alarm in `terraform/main.tf` (~15 references) and the
  # AC + tunnel-server modules. Bootstrap-alb has its OWN SNS topic
  # (`module.bootstrap_alb[0].alerts_topic_arn`) carrying its L4-L7
  # alarms (5xx, TLS, WAF, etc.) — keeping the bootstrap-outcome
  # alarms on the shared monitoring topic instead means alerts-infra
  # only needs to subscribe to one topic for the qurl-service
  # surface, not two. The semantic association with bootstrap-alb is
  # preserved through the alarm-name prefix (see below), not through
  # SNS routing.
  bootstrap_outcomes_enabled = var.deploy_qurl_service

  # Name prefix mirrors the bootstrap-ALB module's own alarm names
  # (`bootstrap-alb-${var.environment}-*`, where `bootstrap-alb` comes
  # from `local.project` in modules/bootstrap-alb/main.tf) so all
  # bootstrap-path alarms cluster together in the CloudWatch console.
  # Renaming `local.project` in the module breaks this co-clustering
  # silently — the README in modules/bootstrap-alb already pins
  # `local.project = "bootstrap-alb"` as a stability invariant for
  # IAM tag-scoping reasons, and this file relies on the same pin.
  bootstrap_outcomes_name_prefix = "bootstrap-alb-${var.environment}"
}

# ── Metric filters ──

# Per-period count of 401 responses on POST /v1/agent/bootstrap.
# `agent_bootstrap_completed` is the structured slog line; the outcome
# classifier in qurl-service maps StatusUnauthorized → "unauthorized".
# `default_value = 0` emits a 0 sample whenever the log group receives
# a non-matching event in the period (qurl-service emits other request
# log lines continuously, so non-matching events are the steady-state
# shape). This keeps the metric series populated for the
# `notBreaching` arm of the alarm's `treat_missing_data`. Note: a fully
# silent log group (no events of any kind in the minute) still produces
# no samples — `treat_missing_data = notBreaching` handles that arm.
resource "aws_cloudwatch_log_metric_filter" "bootstrap_unauthorized" {
  count = local.bootstrap_outcomes_enabled ? 1 : 0

  name           = "${local.bootstrap_outcomes_name_prefix}-bootstrap-unauthorized"
  log_group_name = module.qurl_service[0].log_group_name

  # JSON pattern: match the slog `msg` field + the outcome dimension.
  # The slog JSON handler emits `msg` as a top-level field; CW Logs
  # pattern syntax addresses it as `$.msg`. The combination of `msg` +
  # `outcome` defends against unrelated future log lines that happen
  # to also include an `outcome` field — qurl-service's
  # `agent_keys_repo.go` already emits a separate `outcome=write_failed`
  # slog line, so pinning the event name first is load-bearing.
  #
  # **slog-format dependency**: this filter assumes qurl-service uses
  # the default `slog.JSONHandler` which writes `msg` as the top-level
  # key. The JSON-path pattern also requires the log line to parse as a
  # whole-line JSON object — a single non-JSON banner (e.g., process
  # startup output that bypasses slog) silently fails to match. slog
  # guarantees the JSON shape on every emit it controls today; the
  # tunnel-server FRP precedent uses bracketed-substring patterns
  # specifically because FRP emits non-JSON startup banners. A migration
  # to a custom `HandlerOptions.ReplaceAttr` that renames the message
  # key, a non-JSON handler, or a non-slog logger path would silently
  # break the filter. Test fence tracked in qurl-service#714.
  pattern = "{ $.msg = \"agent_bootstrap_completed\" && $.outcome = \"unauthorized\" }"

  metric_transformation {
    name          = "BootstrapUnauthorizedCount"
    namespace     = "LayerV/QurlService"
    value         = "1"
    default_value = 0
  }
}

# Per-period count of 429 responses on POST /v1/agent/bootstrap. The
# bootstrap rate-limiter is 10/hr per-API-key (AgentBootstrapRateLimit
# in qurl-service); any sustained 429 implies one of: a customer with a
# runaway sidecar restart loop, a leaked key being abused, or a
# deliberately probing client. All three are operator-actionable.
resource "aws_cloudwatch_log_metric_filter" "bootstrap_rate_limited" {
  count = local.bootstrap_outcomes_enabled ? 1 : 0

  name           = "${local.bootstrap_outcomes_name_prefix}-bootstrap-rate-limited"
  log_group_name = module.qurl_service[0].log_group_name

  pattern = "{ $.msg = \"agent_bootstrap_completed\" && $.outcome = \"rate_limited\" }"

  metric_transformation {
    name          = "BootstrapRateLimitedCount"
    namespace     = "LayerV/QurlService"
    value         = "1"
    default_value = 0
  }
}

# ── Alarms ──

# 401 spike. Fires on > threshold/min sustained 3-of-5 minutes — same
# shape as the existing `alb_target_5xx` alarm. Threshold default 3/min
# (env-tunable via `var.bootstrap_unauthorized_threshold_per_minute`).
# The evaluation_periods + datapoints_to_alarm pattern lets a single
# legitimate 401 (operator's first attempt during a key rotation) drop
# off without paging.
#
# **Customer-install symptom**: a freshly-installed customer container
# whose `QURL_API_KEY` env is wrong (resolved from the wrong GCP SM
# secret, copy-pasted with a leading space, etc.) crash-loops with 401
# until someone fixes the key.
resource "aws_cloudwatch_metric_alarm" "bootstrap_unauthorized_spike" {
  count = local.bootstrap_outcomes_enabled ? 1 : 0

  alarm_name          = "${local.bootstrap_outcomes_name_prefix}-bootstrap-unauthorized-spike"
  alarm_description   = "qurl-service returned >${var.bootstrap_unauthorized_threshold_per_minute} 401 responses/min on POST /v1/agent/bootstrap — likely a customer sidecar with a wrong/revoked QURL_API_KEY or a leaked-key probe. The strict handler treats any non-API-key auth as forbidden, so 401 here means RequireAPIKeyAuth saw an invalid bearer."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  datapoints_to_alarm = 3
  metric_name         = "BootstrapUnauthorizedCount"
  namespace           = "LayerV/QurlService"
  period              = 60
  statistic           = "Sum"
  threshold           = var.bootstrap_unauthorized_threshold_per_minute
  treat_missing_data  = "notBreaching"

  alarm_actions = [module.monitoring.sns_topic_arn]
  ok_actions    = [module.monitoring.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name      = "${local.bootstrap_outcomes_name_prefix}-bootstrap-unauthorized-spike"
    Component = "qurl-service"
    Severity  = "ticket"
  })
}

# 429 spike. Same shape as the 401 alarm above; see comment there for
# the evaluation rationale. Documented separately because the operator
# response is different: 429 is "rate-limit hit, investigate which
# api_key_id is hammering" (the audit row carries that field), whereas
# 401 is "key invalid, investigate the customer config or revocation
# state."
resource "aws_cloudwatch_metric_alarm" "bootstrap_rate_limited_spike" {
  count = local.bootstrap_outcomes_enabled ? 1 : 0

  alarm_name          = "${local.bootstrap_outcomes_name_prefix}-bootstrap-rate-limited-spike"
  alarm_description   = "qurl-service returned >${var.bootstrap_rate_limited_threshold_per_minute} 429 responses/min on POST /v1/agent/bootstrap — bootstrap rate limit (10/hr per API key) is being saturated by a single api_key_id. Query the qurl-audit-log table for the offending api_key_id in the last 10 minutes."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  datapoints_to_alarm = 3
  metric_name         = "BootstrapRateLimitedCount"
  namespace           = "LayerV/QurlService"
  period              = 60
  statistic           = "Sum"
  threshold           = var.bootstrap_rate_limited_threshold_per_minute
  treat_missing_data  = "notBreaching"

  alarm_actions = [module.monitoring.sns_topic_arn]
  ok_actions    = [module.monitoring.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name      = "${local.bootstrap_outcomes_name_prefix}-bootstrap-rate-limited-spike"
    Component = "qurl-service"
    Severity  = "ticket"
  })
}
