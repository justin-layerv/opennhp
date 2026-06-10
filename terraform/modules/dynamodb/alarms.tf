# CloudWatch throttle alarms on the customer-facing DynamoDB tables, in two
# groups: the bootstrap/auth hot path (qurl-api-keys, qurl-agent-keys) via the
# standalone alarms below, and the resolve request path (qurl-resources,
# qurl-access-tokens, qurl-sessions, qurl-access-codes, qurl-domains) via the
# `qurl_resolve_throttle` for_each at the bottom of this file (#1912).
#
# Threshold posture: both alarms use `threshold = 0` (not env-tunable),
# deliberately diverging from the env-tunable
# `bootstrap_unauthorized_threshold_per_minute` /
# `bootstrap_rate_limited_threshold_per_minute` pattern on the
# qurl-service-outcome alarms. Rationale: 4xx-outcome counts vary with
# customer-install behaviour and need tuning headroom, but PAY_PER_REQUEST
# throttles are binary — any throttle on the bootstrap hot path is a
# customer-visible 5xx burst. There's no "noisy" tuning regime; the
# alarm should fire on a single throttle event.
#
# Severity posture: both alarms ship as `Severity = "page"` because a
# 2-minute sustained throttle on either table is a real customer-visible
# outage — every authenticated request (qurl-api-keys read) or every
# bootstrap (qurl-agent-keys Upsert) returns 5xx during that window. The
# evaluation_periods=2 + GreaterThanThreshold+threshold=0 combination
# means 2 consecutive 60s windows of throttling, not a single transient
# blip — adaptive-capacity catch-up under organic ramps typically
# completes within a single window. If burn-in shows otherwise (real
# 2-minute throttles that don't reach the customer), downgrade to
# `ticket` rather than raising the threshold; missing a real outage is
# worse than a noisy page in the v1 window.
#
# Scoped tables:
#
#   qurl-api-keys    — read on every authenticated request (CompositeAuth
#                      pulls the key hash; POST /v1/agent/bootstrap is
#                      the canonical first call from the customer
#                      sidecar). Throttle here = customer install
#                      stalls with 5xx.
#   qurl-agent-keys  — written by the bootstrap handler (Upsert on
#                      successful POST /v1/agent/bootstrap). Throttle
#                      here = bootstrap returns 5xx, customer install
#                      crash-loops.
#
# PAY_PER_REQUEST tables (both above) don't have provisioned-throughput
# throttles; they instead surface throttle events when DynamoDB's
# adaptive capacity scaler hasn't caught up to a burst. Either signal
# is operator-actionable: it means a real client is being told "service
# unavailable" right now.
#
# Async / config / write-audit tables (qurl-webhooks-*, qurl-audit-log,
# qurl-billing-audit, qurl-customers, qurl-idempotency-*) are still not in
# scope — they aren't on a customer-blocking request path. Add them to the
# `qurl_resolve_throttle` for_each below if a surface becomes customer-visible.
#
# Metric-name choice — `ReadThrottleEvents` + `WriteThrottleEvents`, NOT
# `ThrottledRequests`. AWS publishes `ThrottledRequests` with the
# `{TableName, Operation}` dimension set (see
# https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html#ThrottledRequests);
# an alarm dimensioned on `{TableName}` alone selects a non-existent
# metric stream and sits in INSUFFICIENT_DATA forever — the exact silent-
# alarm failure mode CLAUDE.md's "Metric / Alarm Dim-Set Rules" warns
# against. `Read/WriteThrottleEvents` are docs-confirmed retrievable
# with `{TableName}` alone (the docs page explicitly says "The TableName
# dimension returns the ReadThrottleEvents for the table"), so they're
# the correct primitive for table-level throttle detection. We combine
# them via metric math (`FILL(reads, 0) + FILL(writes, 0)`) so a
# throttle on either path pages once, not twice; FILL explicitly
# substitutes 0 for missing samples in either series (see the
# resource-level comment for the FILL rationale).
#
# Tag schema (`Component` / `Severity`) deliberately scoped to what
# the local module's existing-alarm precedent (none) and the parent
# `var.tags` cover. Cross-module standardisation of the Severity /
# Component / Project triple is tracked in #2112.
#
# Per-operation (`UserErrors`) alarms are deliberately NOT included.
# `UserErrors` is an account-region-aggregate metric with no
# `TableName` dimension (per the docs page) — alarming on it would
# either silently sit in INSUFFICIENT_DATA (with a `TableName` dim) or
# fire on errors from unrelated tables (without). Per-table 4xx
# observability requires either a custom metric-stream publisher or
# CloudWatch Logs Insights on the application's own logs; tracked in
# https://github.com/layervai/nhp/issues/2108.

locals {
  ddb_alarms_enabled = var.deploy_qurl_tables && var.alarm_sns_topic_arn != null
  ddb_alarm_actions  = local.ddb_alarms_enabled ? [var.alarm_sns_topic_arn] : []

  # Additional QURL tables on the customer *resolve* read path that warrant a
  # page-severity throttle alarm, beyond qurl-api-keys / qurl-agent-keys (the
  # auth + bootstrap hot path already covered by the standalone alarms above).
  # This set is INFERRED from table semantics / the resolve request flow, NOT
  # from measured qurl-service traffic — **qurl-service owner: confirm or
  # correct it in review** (#1912). Deliberately EXCLUDED as not on a customer-
  # blocking read path: qurl-audit-log + qurl-billing-audit (write-audit),
  # qurl-webhooks / qurl-webhook-deliveries / qurl-webhook-event-dedupe (async
  # delivery), qurl-customers (config), qurl-idempotency / qurl-apikey-
  # idempotency (write-path idempotency — promote if a mutation surface proves
  # hot). Flag any of these that should be paged.
  qurl_resolve_throttle_tables = local.ddb_alarms_enabled ? {
    "qurl-resources"     = aws_dynamodb_table.qurl_resources[0].name
    "qurl-access-tokens" = aws_dynamodb_table.qurl_access_tokens[0].name
    "qurl-sessions"      = aws_dynamodb_table.qurl_sessions[0].name
    "qurl-access-codes"  = aws_dynamodb_table.qurl_access_codes[0].name
    "qurl-domains"       = aws_dynamodb_table.qurl_domains[0].name
  } : {}
}

# ── qurl-api-keys ──

resource "aws_cloudwatch_metric_alarm" "qurl_api_keys_throttle" {
  count = local.ddb_alarms_enabled ? 1 : 0

  alarm_name = "${var.name_prefix}-${var.cell_id}-qurl-api-keys-throttle"
  # 2 consecutive 60s windows of throttling required before paging.
  # PAY_PER_REQUEST throttles are rare-and-real (adaptive capacity
  # catching up to a burst), and a single 60s blip during organic
  # traffic ramp doesn't always reach the customer — adaptive capacity
  # typically catches up within ~60-120s. evaluation_periods=2 reduces
  # OK-fan-out churn during ramps while still detecting a real outage
  # within 2 minutes (well under the alerting SLO).
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 0
  alarm_description   = "DynamoDB throttle on qurl-api-keys table sustained 2 consecutive minutes — every authenticated request hits this table for auth lookup, so a sustained throttle == customer-visible 5xx burst. Triage: AWS console → DynamoDB → qurl-api-keys → Metrics → Read/Write throttled events."
  treat_missing_data  = "notBreaching"

  # Metric math: read + write throttle events for the base table.
  # `FILL(reads, 0) + FILL(writes, 0)` explicitly substitutes 0 for
  # missing datapoints in either series. DDB only publishes
  # `Read/WriteThrottleEvents` when at least one throttle event lands
  # in the period — so a hot-partition burst on the read side produces
  # `reads=N, writes=<empty>`. AWS docs claim missing values are
  # treated as 0 in basic arithmetic, but the behavior differs when an
  # entire series is empty (no datapoints ever published vs sporadic
  # missing samples within an existing series). FILL removes the
  # ambiguity — explicit substitution rather than relying on the
  # implicit-zero-promise that AWS docs partially make.
  #
  # Per-GSI throttles (which publish at
  # `{TableName, GlobalSecondaryIndexName}`) are a separate alarm shape
  # tracked in #2116 — deferred until burn-in shows we hit a GSI-
  # specific throttle pattern. For v1 the base-table alarm is the
  # load-bearing one; `qurl-api-keys`' `owner-index` / `key-id-index`
  # GSIs are exposed independently and could hot-spot before the base
  # table does (especially if a single owner_id is concentrated).
  metric_query {
    id          = "throttles"
    expression  = "FILL(reads, 0) + FILL(writes, 0)"
    label       = "Throttle events"
    return_data = true
  }

  metric_query {
    id = "reads"
    metric {
      metric_name = "ReadThrottleEvents"
      namespace   = "AWS/DynamoDB"
      period      = 60
      stat        = "Sum"
      dimensions = {
        TableName = aws_dynamodb_table.qurl_api_keys[0].name
      }
    }
  }

  metric_query {
    id = "writes"
    metric {
      metric_name = "WriteThrottleEvents"
      namespace   = "AWS/DynamoDB"
      period      = 60
      stat        = "Sum"
      dimensions = {
        TableName = aws_dynamodb_table.qurl_api_keys[0].name
      }
    }
  }

  alarm_actions = local.ddb_alarm_actions
  ok_actions    = local.ddb_alarm_actions

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-api-keys-throttle"
    Component = "qurl-service"
    Severity  = "page"
  })
}

# ── qurl-agent-keys ──

resource "aws_cloudwatch_metric_alarm" "qurl_agent_keys_throttle" {
  count = local.ddb_alarms_enabled ? 1 : 0

  alarm_name          = "${var.name_prefix}-${var.cell_id}-qurl-agent-keys-throttle"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 0
  alarm_description   = "DynamoDB throttle on qurl-agent-keys table sustained 2 consecutive minutes — POST /v1/agent/bootstrap Upserts here, so a sustained throttle == customer install stalls with 5xx. Triage path same as qurl-api-keys-throttle."
  treat_missing_data  = "notBreaching"

  # See `qurl_api_keys_throttle` above for the FILL() rationale.
  metric_query {
    id          = "throttles"
    expression  = "FILL(reads, 0) + FILL(writes, 0)"
    label       = "Throttle events"
    return_data = true
  }

  metric_query {
    id = "reads"
    metric {
      metric_name = "ReadThrottleEvents"
      namespace   = "AWS/DynamoDB"
      period      = 60
      stat        = "Sum"
      dimensions = {
        TableName = aws_dynamodb_table.qurl_agent_keys[0].name
      }
    }
  }

  metric_query {
    id = "writes"
    metric {
      metric_name = "WriteThrottleEvents"
      namespace   = "AWS/DynamoDB"
      period      = 60
      stat        = "Sum"
      dimensions = {
        TableName = aws_dynamodb_table.qurl_agent_keys[0].name
      }
    }
  }

  alarm_actions = local.ddb_alarm_actions
  ok_actions    = local.ddb_alarm_actions

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-agent-keys-throttle"
    Component = "qurl-service"
    Severity  = "page"
  })
}

# ── Additional resolve-path QURL tables (#1912) ──
#
# Same correct primitive as the two standalone alarms above: ReadThrottleEvents
# + WriteThrottleEvents combined via FILL() metric-math, dimensioned {TableName},
# threshold=0, 2 consecutive 60s windows, Severity=page. Driven by for_each over
# local.qurl_resolve_throttle_tables rather than more hand-written blocks.
#
# The two existing standalone alarms (qurl-api-keys / qurl-agent-keys) are
# intentionally NOT folded into this for_each: they are live prod page-alarms,
# and a for_each migration would require `moved` blocks that — if mis-keyed —
# destroy+recreate them (a recreate gap on a customer-impacting page-alarm).
# New tables only; the DRY cost of two extra hand-shaped alarms isn't worth that
# risk. Per-GSI throttles remain out of scope here (tracked in #2116).
resource "aws_cloudwatch_metric_alarm" "qurl_resolve_throttle" {
  for_each = local.qurl_resolve_throttle_tables

  alarm_name          = "${var.name_prefix}-${var.cell_id}-${each.key}-throttle"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 0
  alarm_description   = "DynamoDB throttle on ${each.key} sustained 2 consecutive minutes — on the customer resolve path (read and/or write), so a sustained throttle == customer-visible resolve failures (link won't resolve / 5xx). Triage: AWS console → DynamoDB → ${each.key} → Metrics → Read/Write throttled events."
  treat_missing_data  = "notBreaching"

  # FILL(reads,0)+FILL(writes,0): see qurl_api_keys_throttle above for rationale.
  metric_query {
    id          = "throttles"
    expression  = "FILL(reads, 0) + FILL(writes, 0)"
    label       = "Throttle events"
    return_data = true
  }

  metric_query {
    id = "reads"
    metric {
      metric_name = "ReadThrottleEvents"
      namespace   = "AWS/DynamoDB"
      period      = 60
      stat        = "Sum"
      dimensions = {
        TableName = each.value
      }
    }
  }

  metric_query {
    id = "writes"
    metric {
      metric_name = "WriteThrottleEvents"
      namespace   = "AWS/DynamoDB"
      period      = 60
      stat        = "Sum"
      dimensions = {
        TableName = each.value
      }
    }
  }

  alarm_actions = local.ddb_alarm_actions
  ok_actions    = local.ddb_alarm_actions

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-${each.key}-throttle"
    Component = "qurl-service"
    Severity  = "page"
  })
}
