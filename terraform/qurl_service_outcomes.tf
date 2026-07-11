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

# =====================================================================
# Agent registration + email OTP outcomes (T1) — metric filters + alarms
# =====================================================================
#
# Source: the `agent_otp_completed` and `agent_register_completed` slog lines
# qurl-service emits on the agent email-OTP register path (internal/api/handlers).
# Each is a structured slog `msg` with an `outcome` field, exactly like
# `agent_bootstrap_completed` above — so these filters reuse the identical
# `{ $.msg = "…" && $.outcome = "…" }` JSON-path pattern, the same
# `default_value = 0` + `treat_missing_data = notBreaching` shape, and the same
# `module.monitoring.sns_topic_arn` fan-out.
#
# Frozen outcome vocabularies (from qurl-service's classifiers):
#   agent_otp_completed:      success | invalid_api_key | invalid_device_id |
#                             email_unavailable | rate_limited | send_failed |
#                             client_error | server_error
#   agent_register_completed: success | credential_invalid | credential_expired |
#                             attempts_exceeded | conflict | rate_limited |
#                             client_error | server_error
#
# GATING: the OTP-outcome alarms gate on `local.agent_otp_alarms_enabled`
# (agent_otp_enabled — the flow that emits agent_otp_completed) and the
# register-outcome alarms on `local.agent_register_alarms_enabled`
# (agent_registration_enabled — the flow that emits agent_register_completed).
# So PATH A (registration only) arms the register alarms; PATH B (OTP) additionally
# arms the OTP alarms. A fully dark env arms neither and provisions nothing. Both
# also implicitly require deploy_qurl_service (the log group source) — the root
# preconditions in main.tf enforce that chain, so no extra guard is needed here.
# The `[0]` index on module.qurl_service is safe under the same reasoning as the
# bootstrap filters above (these locals can only be true when the service deploys).
#
# The slog-format + JSON-pattern dependency notes on the bootstrap filters above
# apply verbatim (default slog.JSONHandler, whole-line JSON, msg pinned first to
# disambiguate unrelated outcome-bearing lines). Same test fence class.

locals {
  # OTP-path alarms need the flow that emits `agent_otp_completed` (PATH B) to be
  # on. agent_otp_enabled ⇒ agent_registration_enabled ⇒ deploy_qurl_service is
  # enforced by the main.tf preconditions, so this single flag is sufficient.
  agent_otp_alarms_enabled = var.agent_otp_enabled

  # Register-path alarms need the flow that emits `agent_register_completed`
  # (PATH A). agent_registration_enabled ⇒ deploy_qurl_service (via the bootstrap
  # chain, enforced in main.tf).
  agent_register_alarms_enabled = var.agent_registration_enabled

  # OTP-shed alarm gate. The OTPRejectRateLimited metric is emitted from the
  # SHARED OTP dispatch core in endpoints/server (dispatchReceivedMessage routes
  # a direct NHP_OTP straight to HandleOTPRequest → dispatchOTP, independent of
  # NHP_RLY), and the pre-plugin OTP limiter is initialized unconditionally on
  # every nhp-server (udpserver.go, no deploy_relay/enable gate). So the metric
  # IS published in prod even with the relay module undeployed — prod agent
  # registration uses the direct-UDP OTP path. Gating this alarm on deploy_relay
  # alone would leave it non-existent exactly when OTP is live-but-relay-dark
  # (prod launch: agent_otp_enabled=true, deploy_relay=false), so the shed would
  # go unpaged. Gate on OTP-enabled OR relay-deployed so the alarm exists whenever
  # the metric can be emitted. (The `relay`/`agent_relay_*` names are retained to
  # avoid a destroy/recreate churn on the alarm resource; the alarm now covers the
  # direct path too, not just the relay.)
  agent_relay_otp_alarms_enabled = local.agent_otp_alarms_enabled || var.deploy_relay

  # Shared name prefix for these alarms. Distinct from the bootstrap prefix
  # (`bootstrap-alb-…`) because these are the agent-registration surface, not the
  # bootstrap-ALB surface; `layerv-nhp-<env>-agent-…` clusters them under the
  # standard name_prefix in the CloudWatch console.
  agent_reg_outcomes_name_prefix = "${local.name_prefix}-agent"

  # NOTE: local.agent_otp_config_set_name (the SES config-set name the bounce
  # alarm's three metric_query dimension blocks key on) is the SINGLE SOURCE OF
  # TRUTH defined in agent_otp_ses.tf alongside the config set itself, so the
  # alarm dimension and the real config-set name can never drift. Referenced below.
}

# ── OTP send failures (LAUNCH-BLOCKING) ──
# outcome=send_failed means SES rejected the OTP email. This is the silent-wire-
# failure case: the user requests a code, qurl-service tries to send, SES refuses,
# and the user simply never receives anything (no error surfaced to them). During
# launch this is the single most important OTP alarm — a misconfigured SES sender
# (still in sandbox, unverified DKIM, throttled) manifests here first. Threshold
# defaults to 0 so the FIRST send failure pages; a healthy sender never emits it.
resource "aws_cloudwatch_log_metric_filter" "agent_otp_send_failed" {
  count = local.agent_otp_alarms_enabled ? 1 : 0

  name           = "${local.agent_reg_outcomes_name_prefix}-otp-send-failed"
  log_group_name = module.qurl_service[0].log_group_name

  pattern = "{ $.msg = \"agent_otp_completed\" && $.outcome = \"send_failed\" }"

  metric_transformation {
    name          = "AgentOTPSendFailedCount"
    namespace     = "LayerV/QurlService"
    value         = "1"
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "agent_otp_send_failed_spike" {
  count = local.agent_otp_alarms_enabled ? 1 : 0

  alarm_name          = "${local.agent_reg_outcomes_name_prefix}-otp-send-failed-spike"
  alarm_description   = "qurl-service logged >${var.agent_otp_send_failed_threshold_per_minute} agent_otp_completed outcome=send_failed events/min — SES is rejecting OTP emails and users are silently NOT receiving codes (LAUNCH-BLOCKING). Check: (1) SES is out of sandbox for the sender domain (agent_otp_ses.tf identity), (2) DKIM + MAIL FROM DNS verified, (3) SES sending is not paused/throttled (config set reputation_options), (4) the AWS/SES Bounce/Reject metrics for the ${local.name_prefix}-agent-otp configuration set."
  comparison_operator = "GreaterThanThreshold"
  # 1-of-1: page on the FIRST breaching minute. A healthy sender never emits
  # send_failed, so sporadic single failures must page immediately — with the
  # old 3-of-5 they never accumulated (isolated singles aged out of the window)
  # and the launch-blocking alarm stayed silent. threshold=0 (>0 ⇒ ≥1 failure).
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  metric_name         = "AgentOTPSendFailedCount"
  namespace           = "LayerV/QurlService"
  period              = 60
  statistic           = "Sum"
  threshold           = var.agent_otp_send_failed_threshold_per_minute
  treat_missing_data  = "notBreaching"

  # ok_actions posts the ALARM→OK transition to the same SNS topic so the alarm
  # auto-resolves (dashboards/incidents clear) rather than needing a manual reset.
  # It relies on the SNS→pager routing treating an OK notification as non-paging
  # (the standard PagerDuty/Opsgenie CloudWatch integration resolves on OK, it does
  # not page) — so a recovery does NOT wake on-call. Same pattern on every
  # launch-blocking alarm in this file. (Operational: confirm the pager's OK
  # handling at rollout; TF can't assert SNS-subscription behavior.)
  alarm_actions = [module.monitoring.sns_topic_arn]
  ok_actions    = [module.monitoring.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name      = "${local.agent_reg_outcomes_name_prefix}-otp-send-failed-spike"
    Component = "qurl-service"
    Severity  = "page"
  })
}

# ── OTP rate-limited ──
# outcome=rate_limited on the OTP send path — a client retry loop or an email-
# bombing / account-enumeration attempt against the register endpoint. Operator-
# actionable (which api_key_id / device is hammering); a single legitimate
# rate-limit during a smoke doesn't page.
resource "aws_cloudwatch_log_metric_filter" "agent_otp_rate_limited" {
  count = local.agent_otp_alarms_enabled ? 1 : 0

  name           = "${local.agent_reg_outcomes_name_prefix}-otp-rate-limited"
  log_group_name = module.qurl_service[0].log_group_name

  pattern = "{ $.msg = \"agent_otp_completed\" && $.outcome = \"rate_limited\" }"

  metric_transformation {
    name          = "AgentOTPRateLimitedCount"
    namespace     = "LayerV/QurlService"
    value         = "1"
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "agent_otp_rate_limited_spike" {
  count = local.agent_otp_alarms_enabled ? 1 : 0

  alarm_name          = "${local.agent_reg_outcomes_name_prefix}-otp-rate-limited-spike"
  alarm_description   = "qurl-service logged >${var.agent_otp_rate_limited_threshold_per_minute} agent_otp_completed outcome=rate_limited events/min on the agent email-OTP send path — likely a client retry loop or an email-bombing/enumeration attempt against the register endpoint. Identify the offending api_key_id/device from the qurl audit log and consider tightening the OTP rate limit or blocking the caller."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  datapoints_to_alarm = 3
  metric_name         = "AgentOTPRateLimitedCount"
  namespace           = "LayerV/QurlService"
  period              = 60
  statistic           = "Sum"
  threshold           = var.agent_otp_rate_limited_threshold_per_minute
  treat_missing_data  = "notBreaching"

  alarm_actions = [module.monitoring.sns_topic_arn]
  ok_actions    = [module.monitoring.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name      = "${local.agent_reg_outcomes_name_prefix}-otp-rate-limited-spike"
    Component = "qurl-service"
    Severity  = "ticket"
  })
}

# ── Register brute-force (attempts_exceeded) ──
# outcome=attempts_exceeded on the register (credential-exchange) path — a caller
# burned the per-credential attempt budget, i.e. an OTP/credential-guessing
# attack. Higher-signal than credential_invalid (below): reaching the budget is
# an affirmative brute-force indicator, not a one-off malformed credential.
resource "aws_cloudwatch_log_metric_filter" "agent_register_attempts_exceeded" {
  count = local.agent_register_alarms_enabled ? 1 : 0

  name           = "${local.agent_reg_outcomes_name_prefix}-register-attempts-exceeded"
  log_group_name = module.qurl_service[0].log_group_name

  pattern = "{ $.msg = \"agent_register_completed\" && $.outcome = \"attempts_exceeded\" }"

  metric_transformation {
    name          = "AgentRegisterAttemptsExceededCount"
    namespace     = "LayerV/QurlService"
    value         = "1"
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "agent_register_attempts_exceeded_spike" {
  count = local.agent_register_alarms_enabled ? 1 : 0

  alarm_name          = "${local.agent_reg_outcomes_name_prefix}-register-attempts-exceeded-spike"
  alarm_description   = "qurl-service logged >${var.agent_register_attempts_exceeded_threshold_per_minute} agent_register_completed outcome=attempts_exceeded events/min — a caller is burning the per-credential attempt budget on the agent-register path, i.e. an OTP/credential brute-force. Identify the source (api_key_id/device/IP) from the qurl audit log and block; consider tightening the attempt budget."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  datapoints_to_alarm = 3
  metric_name         = "AgentRegisterAttemptsExceededCount"
  namespace           = "LayerV/QurlService"
  period              = 60
  statistic           = "Sum"
  threshold           = var.agent_register_attempts_exceeded_threshold_per_minute
  treat_missing_data  = "notBreaching"

  alarm_actions = [module.monitoring.sns_topic_arn]
  ok_actions    = [module.monitoring.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name      = "${local.agent_reg_outcomes_name_prefix}-register-attempts-exceeded-spike"
    Component = "qurl-service"
    Severity  = "page"
  })
}

# ── Register credential-invalid (lower-priority brute-force companion) ──
# outcome=credential_invalid — a clustered burst can be an early brute-force probe
# (before the attempt budget trips attempts_exceeded) or a broken client sending
# malformed credentials. Deliberately a higher threshold + ticket (not page): it's
# the softer, secondary signal that gives lead time before attempts_exceeded fires.
resource "aws_cloudwatch_log_metric_filter" "agent_register_credential_invalid" {
  count = local.agent_register_alarms_enabled ? 1 : 0

  name           = "${local.agent_reg_outcomes_name_prefix}-register-credential-invalid"
  log_group_name = module.qurl_service[0].log_group_name

  pattern = "{ $.msg = \"agent_register_completed\" && $.outcome = \"credential_invalid\" }"

  metric_transformation {
    name          = "AgentRegisterCredentialInvalidCount"
    namespace     = "LayerV/QurlService"
    value         = "1"
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "agent_register_credential_invalid_spike" {
  count = local.agent_register_alarms_enabled ? 1 : 0

  alarm_name          = "${local.agent_reg_outcomes_name_prefix}-register-credential-invalid-spike"
  alarm_description   = "qurl-service logged >${var.agent_register_credential_invalid_threshold_per_minute} agent_register_completed outcome=credential_invalid events/min — an early brute-force probe (before attempts_exceeded trips) or a broken client sending malformed register credentials. Lower priority than attempts_exceeded; correlate the source and watch for a follow-on attempts-exceeded page."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  datapoints_to_alarm = 3
  metric_name         = "AgentRegisterCredentialInvalidCount"
  namespace           = "LayerV/QurlService"
  period              = 60
  statistic           = "Sum"
  threshold           = var.agent_register_credential_invalid_threshold_per_minute
  treat_missing_data  = "notBreaching"

  alarm_actions = [module.monitoring.sns_topic_arn]
  ok_actions    = [module.monitoring.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name      = "${local.agent_reg_outcomes_name_prefix}-register-credential-invalid-spike"
    Component = "qurl-service"
    Severity  = "ticket"
  })
}

# ── Register rate-limited ──
# outcome=rate_limited on the register path — a client retry loop or enumeration
# against the credential-exchange endpoint. Same shape/severity as the OTP
# rate-limited alarm.
resource "aws_cloudwatch_log_metric_filter" "agent_register_rate_limited" {
  count = local.agent_register_alarms_enabled ? 1 : 0

  name           = "${local.agent_reg_outcomes_name_prefix}-register-rate-limited"
  log_group_name = module.qurl_service[0].log_group_name

  pattern = "{ $.msg = \"agent_register_completed\" && $.outcome = \"rate_limited\" }"

  metric_transformation {
    name          = "AgentRegisterRateLimitedCount"
    namespace     = "LayerV/QurlService"
    value         = "1"
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "agent_register_rate_limited_spike" {
  count = local.agent_register_alarms_enabled ? 1 : 0

  alarm_name          = "${local.agent_reg_outcomes_name_prefix}-register-rate-limited-spike"
  alarm_description   = "qurl-service logged >${var.agent_register_rate_limited_threshold_per_minute} agent_register_completed outcome=rate_limited events/min on the agent-register path — likely a client retry loop or an enumeration attempt against the credential-exchange endpoint. Identify the offending caller from the qurl audit log."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  datapoints_to_alarm = 3
  metric_name         = "AgentRegisterRateLimitedCount"
  namespace           = "LayerV/QurlService"
  period              = 60
  statistic           = "Sum"
  threshold           = var.agent_register_rate_limited_threshold_per_minute
  treat_missing_data  = "notBreaching"

  alarm_actions = [module.monitoring.sns_topic_arn]
  ok_actions    = [module.monitoring.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name      = "${local.agent_reg_outcomes_name_prefix}-register-rate-limited-spike"
    Component = "qurl-service"
    Severity  = "ticket"
  })
}

# ── OTP shed (global-cap saturation) ──
# LEGACY NAME: the resource id / alarm name still say "relay" (kept to avoid a
# destroy/recreate churn), but this alarm now covers BOTH the direct-UDP and the
# relayed OTP paths — the metric it watches is emitted from the shared OTP dispatch
# core, not the relay alone (see the gate comment on agent_relay_otp_alarms_enabled).
#
# This alarm keys on the nhp metric `OTPRejectRateLimited`, NOT a slog
# line — the metrics publisher emits it via PutMetricData to namespace
# `LayerV/NHP` with the base dim set {Environment=<env>} (buildRelayMetricDimensions
# in endpoints/relay/relay.go), exactly like `RelayShed`. The metric is emitted
# from the shared OTP dispatch core (endpoints/server), so it is NOT relay-prefixed
# — it ticks for a direct-UDP OTP as well as a relayed one, and (crucially) is
# published in prod even with the relay module undeployed. So this is a plain
# `aws_cloudwatch_metric_alarm` (no metric filter), matching modules/relay's
# `relay_shedding` alarm shape. It lives here (root) rather than modules/relay only
# because it is thematically part of the agent-OTP surface this file owns and
# routes to the same `module.monitoring.sns_topic_arn`; it is gated so it EXISTS
# whenever OTP is enabled OR the relay is deployed (see the local), so the
# prod-launch case (OTP on, relay dark) is covered rather than silently unarmed.
#
# ── OTP GLOBAL-CAP SIZING ──
# The nhp-server enforces a GLOBAL ~30/min OTP cap across the ENTIRE fleet (not
# per-client), in the shared OTP dispatch limiter that bounds BOTH the direct-UDP
# and relayed paths (OTPRateLimiter's process-global bucket, endpoints/server):
# once ~30 OTP requests land in a rolling minute, further ones are rejected with
# OTPRejectRateLimited and legitimate sends are shed. That cap is the deliberate
# DoS/cost ceiling on outbound OTP email.
# Threshold rationale: a HEALTHY system stays UNDER 30/min (real registration
# volume at launch is a trickle), so ANY reject means the fleet-wide cap was hit —
# either an attack/retry storm or real demand outgrowing the 30/min ceiling.
# Default threshold 0 → page on the FIRST reject (GreaterThanThreshold → >0 = ≥1),
# same first-event posture as relay_shedding. If real OTP volume legitimately
# approaches 30/min, the FIX is to raise the relay's global cap (a code/config
# change in the relay), not to raise this threshold blindly — the threshold is a
# tunable var so an operator can widen it during a known burst, but the alarm
# firing is the signal that the 30/min cap needs revisiting.
resource "aws_cloudwatch_metric_alarm" "agent_relay_otp_reject_rate_limited" {
  count = local.agent_relay_otp_alarms_enabled ? 1 : 0

  alarm_name          = "${local.agent_reg_outcomes_name_prefix}-relay-otp-reject-rate-limited"
  alarm_description   = "The nhp-server rejected >${var.relay_otp_reject_rate_limited_threshold_per_minute} OTP requests/min (OTPRejectRateLimited) — the server's GLOBAL ~30/min OTP cap (fleet-wide, not per-client), enforced in the shared OTP dispatch core so it spans BOTH the direct-UDP and relayed paths, was saturated and legitimate OTP sends are being shed. Either an attack/retry storm or real registration demand outgrowing the 30/min ceiling. Check the nhp-server logs + the register-endpoint rate-limit alarms (in prod the relay is undeployed, so this is the direct-UDP path); if this is genuine demand, raise the server's global OTP cap (server code/config) rather than only widening this threshold."
  comparison_operator = "GreaterThanThreshold"
  # 1-of-1: page on the FIRST reject minute. A healthy fleet stays under the
  # relay's 30/min global OTP cap and never rejects, so any reject is either an
  # attack/retry storm or real demand outgrowing the cap — page immediately. The
  # old 3-of-5 let sporadic single rejects age out unpaged. threshold=0 (>0 ⇒ ≥1).
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  metric_name         = "OTPRejectRateLimited"
  namespace           = "LayerV/NHP"
  period              = 60
  statistic           = "Sum"
  threshold           = var.relay_otp_reject_rate_limited_threshold_per_minute
  treat_missing_data  = "notBreaching"

  # DIM SET — {Environment=<env>}, NO Cell/Region. This MUST match the
  # OTPRejectRateLimited series the nhp-server publishes. CAUTION: the nhp-server
  # metrics publisher's BASE dim set is [Environment, Cell]
  # (buildServerMetricDimensions), NOT [Environment] — so this {Environment}-only
  # alarm binds ONLY because the server DUAL-PUBLISHES an explicit [Environment]-only
  # BASE stream on the shed path (endpoints/server/msghandler.go dispatchOTP →
  # IncrCounterExplicitDims(..., buildServerEnvDimension()), the RelayShed pattern),
  # in ADDITION to the [Environment, Cell] breakdown. If that explicit base emit is
  # ever removed ("simplified" to a plain IncrCounter), this alarm silently stops
  # binding — it sits in INSUFFICIENT_DATA forever and treat_missing_data=notBreaching
  # keeps the launch-blocking page green. `terraform validate` cannot catch that;
  # correctness rests on the N2 dual-publish. Do NOT switch this to [Environment,
  # Cell] to "fix" a non-binding alarm — that loses the fleet-wide aggregate; the
  # fix is to restore the base emit. (The post-rollout canary ledger item fires a
  # test datapoint to confirm this alarm actually leaves INSUFFICIENT_DATA.)
  dimensions = {
    Environment = var.environment
  }

  alarm_actions = [module.monitoring.sns_topic_arn]
  ok_actions    = [module.monitoring.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name      = "${local.agent_reg_outcomes_name_prefix}-relay-otp-reject-rate-limited"
    Component = "nhp-relay"
    Severity  = "page"
  })
}

# ── SES bounce / complaint / reject (LAUNCH-BLOCKING deliverability) ──
# The send_failed alarm above catches SYNCHRONOUS SES rejections (qurl-service's
# SendEmail call returns an error → outcome=send_failed). It does NOT catch the
# ASYNCHRONOUS deliverability failures SES reports out-of-band on the config set:
# a message SES ACCEPTS at send time can still hard-BOUNCE (bad mailbox), draw a
# COMPLAINT (spam report), or be REJECTED by SES's own content/reputation filter.
# In all three the user never receives the OTP — the same silent-wire failure as
# send_failed, just surfaced on the SES side instead of the API call. This alarm
# closes that gap using the AWS/SES metrics the config set's CloudWatch event
# destination already publishes (agent_otp_ses.tf: BOUNCE/COMPLAINT/REJECT are in
# matching_event_types), dimensioned by ses:configuration-set.
#
# metric_query (math), unlike the single-metric alarms above: Bounce, Complaint,
# and Reject are three distinct AWS/SES metrics, and one alarm over their SUM is
# the minimal way to page on "any async deliverability failure" without standing
# up three near-identical alarms. threshold defaults to 0 → the FIRST bounce/
# complaint/reject pages (1-of-1), mirroring send_failed's first-event posture;
# a healthy verified sender emits none. Gated on agent_otp_alarms_enabled — the
# SES config set only exists when agent_otp_enabled, so the metrics only exist then.
resource "aws_cloudwatch_metric_alarm" "agent_otp_bounce" {
  count = local.agent_otp_alarms_enabled ? 1 : 0

  alarm_name          = "${local.agent_reg_outcomes_name_prefix}-otp-bounce"
  alarm_description   = "SES reported >${var.agent_otp_bounce_threshold_per_minute} async OTP delivery failures/min (Bounce + Complaint + Reject) on the ${local.name_prefix}-agent-otp configuration set — messages SES ACCEPTED at send time but could not deliver (hard bounce / spam complaint / filter reject), so the user silently never receives the code (LAUNCH-BLOCKING, complements agent-otp-send-failed-spike which only catches synchronous send errors). Check: (1) recipient-domain reputation / a bad address list, (2) SES account reputation + sending pause, (3) content tripping SES's reject filter. A sustained bounce/complaint rate also risks SES throttling the whole sender."
  comparison_operator = "GreaterThanThreshold"
  # 1-of-1: page on the FIRST breaching minute, same first-event posture as
  # send_failed — an async deliverability failure is as user-silent as a
  # synchronous one, so it must not wait for a 3-of-5 accumulation.
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = var.agent_otp_bounce_threshold_per_minute
  # No samples until the first send on this config set; a dark/idle OTP path
  # produces none, so notBreaching keeps it green (matches the other OTP alarms).
  treat_missing_data = "notBreaching"

  # SUM of the three AWS/SES async-failure metrics, each dimensioned by the
  # config set. RETURN the summed expression; the raw metrics are non-returned
  # inputs (Sum over a 60s period, matching the file's other OTP alarms).
  #
  # FILL(x, 0) IS LOAD-BEARING — do not drop it. CloudWatch metric-math
  # arithmetic only yields a result at timestamps where EVERY operand has a
  # datapoint; a missing series is NOT treated as zero. Bounce/Complaint/Reject
  # are SPARSE (published only when that event occurs) and rarely coincide in the
  # same 60s period, so a bare `bounce + complaint + reject` produces NO output
  # for the common case — a lone hard bounce with no complaint/reject that minute
  # — and the alarm would stay green on the very failure it exists to catch.
  # FILL substitutes 0 for the absent series so the sum is always defined.
  metric_query {
    id          = "failures"
    expression  = "FILL(bounce, 0) + FILL(complaint, 0) + FILL(reject, 0)"
    label       = "OTP async delivery failures (bounce+complaint+reject)"
    return_data = true
  }
  metric_query {
    id = "bounce"
    metric {
      metric_name = "Bounce"
      namespace   = "AWS/SES"
      period      = 60
      stat        = "Sum"
      dimensions = {
        "ses:configuration-set" = local.agent_otp_config_set_name
      }
    }
  }
  metric_query {
    id = "complaint"
    metric {
      metric_name = "Complaint"
      namespace   = "AWS/SES"
      period      = 60
      stat        = "Sum"
      dimensions = {
        "ses:configuration-set" = local.agent_otp_config_set_name
      }
    }
  }
  metric_query {
    id = "reject"
    metric {
      metric_name = "Reject"
      namespace   = "AWS/SES"
      period      = 60
      stat        = "Sum"
      dimensions = {
        "ses:configuration-set" = local.agent_otp_config_set_name
      }
    }
  }

  alarm_actions = [module.monitoring.sns_topic_arn]
  ok_actions    = [module.monitoring.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name      = "${local.agent_reg_outcomes_name_prefix}-otp-bounce"
    Component = "qurl-service"
    Severity  = "page"
  })
}
