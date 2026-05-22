# ==============================================================================
# QURL Alerting — Grafana alert rules + AWS SNS contact point
# ==============================================================================
#
# Provisions Grafana Cloud alert rules for the qurl-api SLO and routes them
# through the existing CloudWatch SNS topic from the monitoring module so the
# new alerts land in the same Slack/email channels as every other prod alert.
#
# Why this exists: on 2026-03-24, every POST /v1/qurls in production returned
# HTTP 500 for over a week before any human noticed. The qurl-operations
# dashboard had 5xx and burn-rate panels labelled "page-level alert" and
# "ticket-level alert" — but no alert rules were ever created. This file
# closes that gap. See docs/slo.md and docs/runbooks/qurl-*.md for full
# context.
#
# Routing model:
#   Each rule sets `notification_settings.contact_point` directly to the
#   SNS contact point. This bypasses the global Grafana notification-policy
#   tree, which would otherwise be a stack-wide singleton this file should
#   not own. Severity-based routing (page vs ticket) lives in the alert
#   labels for downstream filtering by humans, not in Grafana's policy
#   tree, because the SNS topic currently fans out to a single set of
#   email + Slack subscribers regardless of severity.
#
# Soak protocol: rules ship with is_paused = true by default. After
# deployment, watch each rule's "would-have-fired" count in Grafana for 24h,
# tune thresholds if obvious noise is observed, then flip
# var.qurl_alerts_paused = false in a follow-up apply. Rules whose metric
# has zero healthy-state samples (e.g. qurl-webhook-suppressed-lookup-failed)
# need an additional pre-flip verification because no_data_state="OK" will
# silently pass a typo'd metric name: cold-check that the metric resolves
# in Grafana Explore (e.g. `qurl_webhook_connector_resources_suppressed_total`
# returns any series), then induce a hot-check increment in sandbox to
# confirm the increment lands. Full protocol per rule's runbook —
# see e.g. docs/runbooks/qurl-webhook-suppressed-lookup-failed.md.
#
# TODO(follow-up): the burn-rate PromQL is duplicated between this file and
# the qurl-operations.json dashboard. The right long-term fix is to extract
# the expressions into a `.tftpl` template consumed by both via
# templatefile() — see qurl-operations.json:610 and :663 for the source
# panels. Out of scope for this PR but worth a follow-up.

locals {
  # Single source of truth for whether the alerting stack is provisioned.
  # The precondition below fails the apply if a partially-configured state
  # is detected (var.qurl_alerts_enabled=true with empty SNS topic ARN).
  # Silent disablement was the failure mode this PR exists to prevent —
  # we fail loud here.
  qurl_alerts_enabled = var.qurl_alerts_enabled

  # Burn-rate denominator: see docs/slo.md. The PromQL expressions below
  # divide the observed error rate by (1 - SLO/100), producing a unitless
  # "burn rate" where 1.0 = spending budget at exactly the sustainable
  # rate. Threshold values below are scale-invariant in the SLO target.
  qurl_slo_error_budget = 1 - (var.qurl_alerts_slo_target_percent / 100)

  # Prometheus label selector shared across every rule. service_name and
  # deployment_environment narrow to qurl-api in the target environment;
  # cell_id is left unconstrained at the selector level because the rules
  # below aggregate per-cell so a single broken cell isn't masked by
  # healthy traffic in other cells.
  qurl_prom_selector = "service_name=\"qurl-api\", deployment_environment=\"${var.environment}\""

  # Common alert labels merged into every rule. severity is used for
  # downstream filtering by humans (alert subject lines, email rules,
  # Slack threads); it does NOT drive Grafana-side routing in this PR
  # because all rules go to the same SNS contact point.
  qurl_alert_labels_base = {
    service        = "qurl-api"
    component      = "qurl"
    deployment_env = var.environment
  }

  # Severity label values. Named here so the rule definitions reference a
  # symbol instead of a string literal — keeps the values aligned across
  # rules and any future automation that filters on them.
  qurl_severity = {
    page   = "page"
    ticket = "ticket"
  }

  # Alert thresholds. Hoisted to locals so the soak-and-tune protocol
  # documented in docs/slo.md has a single place to look. Values are
  # scale-invariant in var.qurl_alerts_slo_target_percent — see the
  # "burn rate" explanation in docs/slo.md.
  qurl_thresholds = {
    # 6h burn rate above 6× sustainable. Pages on-call. At 6× burn,
    # the 30d budget exhausts in ~5 days, so this alerts well before
    # the budget actually runs out.
    fast_burn = 6
    # 3d burn rate above 1× sustainable. Files a ticket for daytime
    # investigation. At 1× burn, budget exhausts in exactly 30 days
    # (the SLO window) — slow drain rather than acute incident.
    slow_burn = 1
    # Loki ERROR-level log lines per second. ~3 errors/min steady-state.
    # Tune after a week of soak; the right destination for genuinely
    # benign errors is changing the log level in code from ERROR to WARN,
    # not raising this threshold.
    error_log_rate = 0.05
    # Failed DynamoDB Query operations per second against qurl-resources.
    # Filtered to Query specifically (not PutItem/UpdateItem) because the
    # service intentionally generates ConditionalCheckFailedException via
    # attribute_not_exists checks in the create-resource path; Query
    # failures have no legitimate steady-state.
    dynamodb_query_failure_rate = 0.05
    # Webhook events the transit-resource gate dropped fail-CLOSED because
    # it couldn't load the resource to make a decision (DDB hiccup, IAM
    # blip). Per qurl-service `metrics.go::WebhookSuppressedReasonLookupFailed`
    # (https://github.com/layervai/qurl-service/blob/eaaf9deb82f1973f61c19632d860721279c6cfce/internal/observability/metrics.go
    # — grep the file for the symbol; deep-line anchor dropped because qurl-service
    # line numbers will drift independently of the pinned SHA)
    # the metric is "zero in normal operation; spikes during DDB hiccups
    # indicate webhooks are being dropped on the floor and the gate's
    # lookup path is the cause." 0.05/sec is a starting point pending
    # soak data — it borrows the shape of dynamodb_query_failure_rate
    # for consistency, but the semantics differ (each dropped event is
    # an irretrievable customer-visible missing webhook, vs DDB Query
    # failures which surface as 5xx already paged elsewhere). Soak may
    # justify tightening, loosening, or splitting page/ticket severities.
    webhook_connector_suppressed_lookup_failed_rate = 0.05
  }

  # PromQL / LogQL queries hoisted to locals to keep the rule definitions
  # readable. Each expression uses the shared qurl_prom_selector to ensure
  # consistent label matching across rules and the dashboard.
  #
  # Burn-rate computation:
  # The naive form `errors / total / budget` produces an empty result
  # vector when there are zero 5xx samples, which Grafana treats as
  # NoData (the burn-rate vector is missing because the LHS of the
  # division is empty). The `or vector(0)` shortcut the dashboard uses
  # discards the cell_id label and so cannot be combined with per-cell
  # aggregation. Instead we compute the error fraction as
  # `1 - (non_5xx_rate / total_rate)`, which is always defined whenever
  # there is any traffic and naturally returns 0 when traffic is healthy.
  #
  # Per-cell aggregation: every burn-rate query groups by cell_id and
  # then takes `max by (cell_id)` so an outage in one cell drives the
  # alert even if other cells are healthy. The dashboard's queries also
  # filter on cell_id (via the $cell_id template variable); the alert
  # has no template variable, so we evaluate every cell and let Grafana
  # generate one alert instance per cell.
  #
  # The `non_5xx_selector` and `total_selector` are split apart so the
  # PromQL is readable and so we don't repeat the long label set inline
  # in three different places.
  qurl_non_5xx_selector = "${local.qurl_prom_selector}, http_status_code!~\"5..\""
  qurl_total_selector   = local.qurl_prom_selector

  # 6h burn rate, per-cell, dashboard-equivalent.
  # Source: qurl-operations.json:610 (semantically equivalent; see comment above
  # for why we use `1 - non_5xx/total` rather than the dashboard's `errors/total`).
  qurl_query_fast_burn = "max by (cell_id) ((1 - (sum by (cell_id) (rate(http_server_request_duration_seconds_count{${local.qurl_non_5xx_selector}}[6h])) / sum by (cell_id) (rate(http_server_request_duration_seconds_count{${local.qurl_total_selector}}[6h])))) / ${local.qurl_slo_error_budget})"

  # 3d burn rate, per-cell. Source: qurl-operations.json:663.
  qurl_query_slow_burn = "max by (cell_id) ((1 - (sum by (cell_id) (rate(http_server_request_duration_seconds_count{${local.qurl_non_5xx_selector}}[3d])) / sum by (cell_id) (rate(http_server_request_duration_seconds_count{${local.qurl_total_selector}}[3d])))) / ${local.qurl_slo_error_budget})"

  # LogQL: ERROR-level log lines from qurl-api. The `|=` line filter runs
  # before `| json` so the parser only sees lines that already match the
  # ERROR level — Loki best-practice ordering, eliminates ~95% of lines
  # before the JSON parser cost. Aggregated across cells; per-cell
  # error-log alerting is overkill for v1 since most legitimate error log
  # spikes affect every cell simultaneously (deploy, dependency outage).
  qurl_query_error_log_rate = "sum(rate({service_name=\"qurl-api\", deployment_environment=\"${var.environment}\"} |= \"\\\"level\\\":\\\"ERROR\\\"\" | json | level=\"ERROR\" [5m]))"

  # PromQL: failed Query operations against qurl-resources, per-cell.
  #
  # CRITICAL: the label keys are `operation`, `table`, `success` —
  # NOT `aws_dynamodb_operation`, etc. The metric is `aws.dynamodb.operation.total`
  # under OTel naming, which the OTel→Prom translation converts to
  # `aws_dynamodb_operation_total`. The attribute keys (`operation`, `table`,
  # `success` per qurl-service `internal/observability/metrics.go:581-583`)
  # are translated as-is, NOT prefixed with the metric name. The dashboard's
  # working query at qurl-operations.json:1561 confirms this label set.
  # An earlier version of this rule used `aws_dynamodb_*` prefixes and
  # would have returned zero results forever — see the v2 review notes
  # in the PR for the discovery.
  #
  # Table selector is anchored at both ends to prevent accidentally
  # matching `foo-qurl-resources` or `qurl-resources-archive`. The leading
  # `.*` accommodates any environment prefix (layerv-nhp-sandbox-cell0,
  # layerv-nhp-prod-cell0, etc.).
  qurl_query_dynamodb_query_failures = "max by (cell_id) (sum by (cell_id) (rate(aws_dynamodb_operation_total{${local.qurl_prom_selector}, table=~\"^.*-qurl-resources$\", operation=\"Query\", success=\"false\"}[5m])))"

  # PromQL: webhook events suppressed fail-CLOSED because the gate's
  # resource lookup failed. The metric is
  # `qurl.webhook.connector_resources_suppressed.total` (OTel name) →
  # `qurl_webhook_connector_resources_suppressed_total` after the
  # OTel→Prom translation (dots → underscores, single `_total` suffix
  # preserved, NOT double-appended). The same translation rule is
  # already exercised by `qurl.webhook.delivery.total` →
  # `qurl_webhook_delivery_total`, which works in dashboards/qurl-
  # webhooks.json:120 — that's empirical proof the name shape is
  # correct, not a guess. Soak verification will still confirm a
  # real time series resolves before flipping is_paused=false.
  #
  # Attribute `reason` is filtered to `lookup_failed` so the alert
  # only fires on the silent-drop branch (the other reason,
  # `filtered`, is the legitimate in-band gate hit for transit-typed
  # resources and is high-volume by design).
  #
  # Per-cell aggregation matches the other qurl alerts so a single
  # broken cell drives the page even if other cells are healthy.
  qurl_query_webhook_connector_suppressed_lookup_failed = "max by (cell_id) (sum by (cell_id) (rate(qurl_webhook_connector_resources_suppressed_total{${local.qurl_prom_selector}, reason=\"lookup_failed\"}[5m])))"

  # Threshold-expression model bodies, one per rule. Each is a Grafana
  # server-side expression of type "threshold" comparing the upstream
  # query (refId "A") to a single numeric value. Built once here so the
  # rule definitions don't repeat the JSON shape.
  qurl_threshold_models = {
    for name, value in local.qurl_thresholds :
    name => jsonencode({
      refId      = "C"
      type       = "threshold"
      expression = "A"
      conditions = [{
        evaluator = { type = "gt", params = [value] }
        operator  = { type = "and" }
        query     = { params = ["A"] }
        reducer   = { type = "last" }
        type      = "query"
      }]
    })
  }
}

# ==============================================================================
# IAM role: Grafana Cloud → SNS publish
# ==============================================================================
#
# Grafana Cloud's SNS contact point publishes via STS AssumeRole into the
# prod account. The trust policy mirrors the pattern already used by
# aws_iam_role.grafana_cloudwatch in main.tf — same external ID, same
# Grafana Cloud account ID — but a separate role keeps the permission
# surface single-purpose (CloudWatch reads vs SNS publish).
#
# TODO(#1024): there are now three copies of this trust policy in the
# repo (grafana_cloudwatch in main.tf, grafana_athena in
# cost-analytics/main.tf, grafana_sns_publisher here). Extract a shared
# `modules/grafana-cloud-iam-role/` helper that takes a permission policy
# document and emits the role + policy with the standard trust policy.

resource "aws_iam_role" "grafana_sns_publisher" {
  count = local.qurl_alerts_enabled ? 1 : 0

  # Fail loud if alerting is enabled but prerequisites are missing.
  # Silent disablement is the failure mode this PR exists to prevent.
  lifecycle {
    precondition {
      condition     = var.qurl_alerts_sns_topic_arn != ""
      error_message = "qurl_alerts_enabled = true but qurl_alerts_sns_topic_arn is empty. Wire module.monitoring.sns_topic_arn through to module.grafana_dashboards.qurl_alerts_sns_topic_arn before enabling alerting."
    }
    precondition {
      condition     = var.create_dashboards
      error_message = "qurl_alerts_enabled = true requires create_dashboards = true because the alert rule group references grafana_folder.qurl[0].uid. Enable create_dashboards for this environment or disable qurl_alerts_enabled."
    }
    precondition {
      condition     = var.grafana_cloud_aws_account_id != ""
      error_message = "qurl_alerts_enabled = true requires var.grafana_cloud_aws_account_id to be set so the IAM trust policy can name Grafana Cloud's AWS account."
    }
  }

  name = "${var.name_prefix}-grafana-sns-publisher"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.grafana_cloud_aws_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = local.grafana_cloud_external_id != "" ? {
          StringEquals = {
            "sts:ExternalId" = local.grafana_cloud_external_id
          }
        } : {}
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-grafana-sns-publisher"
    Component = "grafana-dashboards"
    Purpose   = "qurl-alerts-routing"
  })
}

resource "aws_iam_role_policy" "grafana_sns_publisher" {
  count = local.qurl_alerts_enabled ? 1 : 0

  name = "${var.name_prefix}-grafana-sns-publisher-policy"
  role = aws_iam_role.grafana_sns_publisher[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PublishToQurlAlertsSNSTopic"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [var.qurl_alerts_sns_topic_arn]
      }
    ]
  })
}

# ==============================================================================
# Grafana SNS contact point
# ==============================================================================
#
# The contact point is the bridge from Grafana's alert manager to AWS SNS.
# Grafana assumes the role above and publishes to the topic ARN, which
# fans out to the existing email and Slack subscribers configured by the
# monitoring module — there is no parallel notification channel created
# by this PR.

resource "grafana_contact_point" "qurl_aws_sns" {
  count = local.qurl_alerts_enabled ? 1 : 0

  name = "qurl-aws-sns-${var.environment}"

  sns {
    topic           = var.qurl_alerts_sns_topic_arn
    assume_role_arn = aws_iam_role.grafana_sns_publisher[0].arn
    # external_id matches the trust policy condition above. Empty when
    # var.grafana_cloud_external_id is unset, in which case the trust
    # policy condition is also absent — no external ID is required.
    # Tightening tracked in #1462 (degraded-trust mode when external_id
    # is unset; surfaced by the #1319 audit).
    external_id    = local.grafana_cloud_external_id
    auth_provider  = "arn"
    message_format = "json"
    body           = "{{ template \"sns.default.message\" . }}"
    subject        = "[qurl-${var.environment}] {{ .CommonLabels.alertname }}"
  }
}

# ==============================================================================
# Alert rule group: qurl-api SLO + DynamoDB + webhook drops
# ==============================================================================
#
# All rules live in one group so they share an evaluation interval and
# fire from the same Grafana scheduler tick. Each rule's notification_settings
# block names the SNS contact point directly, bypassing the stack-wide
# notification policy tree (which is a Grafana singleton this PR should
# not own).
#
# no_data_state philosophy:
#   The 2026-03-24 incident's root pattern was a silent failure in the
#   observability layer (panels existed, alerts didn't). Rules where missing
#   data is suspicious (the metric should always exist for a service with
#   live customers) use no_data_state="NoData" so an instrumentation gap
#   pages on-call. Rules where missing data is healthy (no error logs = no
#   errors) use "OK". Each rule's setting is documented inline.

resource "grafana_rule_group" "qurl_alerts" {
  count = local.qurl_alerts_enabled ? 1 : 0

  name             = "qurl-api-${var.environment}"
  folder_uid       = grafana_folder.qurl[0].uid
  interval_seconds = 60

  # ----------------------------------------------------------------------
  # Rule 1: 5xx fast burn — pages on a 6-hour burn rate exceeding the
  # fast_burn threshold. At 6× burn, the 30d error budget exhausts in
  # ~5 days. Source PromQL: qurl-operations.json:610
  # ----------------------------------------------------------------------
  rule {
    name      = "qurl-5xx-fast-burn"
    condition = "C"
    for       = "5m"
    is_paused = var.qurl_alerts_paused

    # NoData = page: a service with live customers should always have
    # http_server_request_duration_seconds_count samples; missing samples
    # mean either a total traffic loss (which IS an outage) or a broken
    # observability pipeline (which IS the lesson of 2026-03-24).
    no_data_state  = "NoData"
    exec_err_state = "Error"

    annotations = {
      summary     = "qurl-api 5xx fast-burn rate exceeded ${local.qurl_thresholds.fast_burn}× sustainable"
      description = "Rolling 6h 5xx burn rate is above ${local.qurl_thresholds.fast_burn} for at least one cell, meaning the 30d error budget will be exhausted in ~5 days at this rate. Per-cell aggregation: the alert fires for the worst cell. Investigate the QURL Operations dashboard for the affected endpoint."
      runbook_url = "${var.qurl_alerts_runbook_base_url}/qurl-5xx.md"
      slo_window  = "6h"
      slo_target  = tostring(var.qurl_alerts_slo_target_percent)
    }

    labels = merge(local.qurl_alert_labels_base, {
      severity   = local.qurl_severity.page
      alert_type = "burn_rate"
      window     = "6h"
    })

    notification_settings {
      contact_point = grafana_contact_point.qurl_aws_sns[0].name
      group_by      = ["alertname", "service", "deployment_env"]
    }

    data {
      ref_id         = "A"
      datasource_uid = var.prometheus_datasource_uid
      relative_time_range {
        from = 21600 # 6h
        to   = 0
      }
      model = jsonencode({
        refId   = "A"
        expr    = local.qurl_query_fast_burn
        instant = true
        range   = false
      })
    }

    data {
      ref_id         = "C"
      datasource_uid = "__expr__"
      relative_time_range {
        from = 0
        to   = 0
      }
      model = local.qurl_threshold_models.fast_burn
    }
  }

  # ----------------------------------------------------------------------
  # Rule 2: 5xx slow burn — opens a ticket on a 3-day burn rate above the
  # slow_burn threshold. At 1× burn, budget exhausts in exactly 30 days.
  # Source PromQL: qurl-operations.json:663
  # ----------------------------------------------------------------------
  rule {
    name      = "qurl-5xx-slow-burn"
    condition = "C"
    for       = "1h"
    is_paused = var.qurl_alerts_paused

    # NoData = page (same reasoning as fast-burn). The 1h `for` window
    # makes spurious NoData transitions during quiet periods unlikely.
    no_data_state  = "NoData"
    exec_err_state = "Error"

    annotations = {
      summary     = "qurl-api 5xx slow-burn rate exceeded ${local.qurl_thresholds.slow_burn}× sustainable"
      description = "Rolling 3d 5xx burn rate is above ${local.qurl_thresholds.slow_burn} for at least one cell, meaning the 30d error budget will be exhausted within the month at this rate. Per-cell aggregation: the alert fires for the worst cell. Lower-priority than fast-burn but warrants investigation during business hours."
      runbook_url = "${var.qurl_alerts_runbook_base_url}/qurl-5xx.md"
      slo_window  = "3d"
      slo_target  = tostring(var.qurl_alerts_slo_target_percent)
    }

    labels = merge(local.qurl_alert_labels_base, {
      severity   = local.qurl_severity.ticket
      alert_type = "burn_rate"
      window     = "3d"
    })

    notification_settings {
      contact_point = grafana_contact_point.qurl_aws_sns[0].name
      group_by      = ["alertname", "service", "deployment_env"]
    }

    data {
      ref_id         = "A"
      datasource_uid = var.prometheus_datasource_uid
      relative_time_range {
        from = 259200 # 3d
        to   = 0
      }
      model = jsonencode({
        refId   = "A"
        expr    = local.qurl_query_slow_burn
        instant = true
        range   = false
      })
    }

    data {
      ref_id         = "C"
      datasource_uid = "__expr__"
      relative_time_range {
        from = 0
        to   = 0
      }
      model = local.qurl_threshold_models.slow_burn
    }
  }

  # ----------------------------------------------------------------------
  # Rule 3: error-log spike — pages when slog.Error lines exceed the
  # error_log_rate threshold. Catches application errors that may not
  # become HTTP 5xx (background workers, webhook delivery failures, etc.).
  # ----------------------------------------------------------------------
  rule {
    name      = "qurl-error-logs-spike"
    condition = "C"
    for       = "5m"
    is_paused = var.qurl_alerts_paused

    # NoData = OK: zero ERROR-level log lines is the healthy steady state
    # for a service that isn't experiencing problems. Loki rate queries
    # over a window with no matching lines return empty (NoData) rather
    # than 0, so we explicitly map that to OK here.
    no_data_state  = "OK"
    exec_err_state = "Error"

    annotations = {
      summary     = "qurl-api error log rate exceeded ${local.qurl_thresholds.error_log_rate}/sec"
      description = "Rate of slog.Error lines from qurl-api in ${var.environment} exceeded ${local.qurl_thresholds.error_log_rate}/sec for 5 minutes. Catches non-HTTP error paths the 5xx burn-rate alerts miss (background workers, webhook delivery failures, billing reconciliation)."
      runbook_url = "${var.qurl_alerts_runbook_base_url}/qurl-error-logs.md"
    }

    labels = merge(local.qurl_alert_labels_base, {
      severity   = local.qurl_severity.page
      alert_type = "log_rate"
    })

    notification_settings {
      contact_point = grafana_contact_point.qurl_aws_sns[0].name
      group_by      = ["alertname", "service", "deployment_env"]
    }

    data {
      ref_id         = "A"
      datasource_uid = var.qurl_alerts_loki_datasource_uid
      relative_time_range {
        from = 300 # 5m
        to   = 0
      }
      model = jsonencode({
        refId     = "A"
        expr      = local.qurl_query_error_log_rate
        queryType = "instant"
      })
    }

    data {
      ref_id         = "C"
      datasource_uid = "__expr__"
      relative_time_range {
        from = 0
        to   = 0
      }
      model = local.qurl_threshold_models.error_log_rate
    }
  }

  # ----------------------------------------------------------------------
  # Rule 4: qurl-resources DynamoDB Query failures — pages when the
  # qurl-service's own OpenTelemetry instrumentation reports sustained
  # Query failures against qurl-resources. Direct, narrow signal for
  # the 2026-03-24 incident class (missing GSI → ValidationException).
  # ----------------------------------------------------------------------
  rule {
    name      = "qurl-dynamodb-query-failures"
    condition = "C"
    for       = "5m"
    is_paused = var.qurl_alerts_paused

    # NoData = page: aws_dynamodb_operation_total{operation="Query", success="false"}
    # legitimately reads as 0 when there are no Query failures, BUT the metric
    # itself should always be present in the time series database because the
    # qurl-service emits it on every DynamoDB operation. Empty result vector =
    # the metric stopped being emitted = the qurl-service stopped serving
    # qurl-resources Query traffic, which is itself an outage worth paging on.
    no_data_state  = "NoData"
    exec_err_state = "Error"

    annotations = {
      summary     = "qurl-resources DynamoDB Query failures sustained > ${local.qurl_thresholds.dynamodb_query_failure_rate}/sec"
      description = "The qurl-service is reporting Query failures against the qurl-resources table at >${local.qurl_thresholds.dynamodb_query_failure_rate}/sec for 5 minutes for at least one cell. The most likely cause is a schema mismatch — a GSI was removed or renamed under a deployed binary that still queries it. This is the direct signal for the 2026-03-24 incident class. Per-cell aggregation: the alert fires for the worst cell."
      runbook_url = "${var.qurl_alerts_runbook_base_url}/qurl-dynamodb-query-failures.md"
    }

    labels = merge(local.qurl_alert_labels_base, {
      severity   = local.qurl_severity.page
      alert_type = "dynamodb_query_failure"
      table      = "qurl-resources"
    })

    notification_settings {
      contact_point = grafana_contact_point.qurl_aws_sns[0].name
      group_by      = ["alertname", "service", "deployment_env"]
    }

    data {
      ref_id         = "A"
      datasource_uid = var.prometheus_datasource_uid
      relative_time_range {
        from = 300 # 5m
        to   = 0
      }
      model = jsonencode({
        refId   = "A"
        expr    = local.qurl_query_dynamodb_query_failures
        instant = true
        range   = false
      })
    }

    data {
      ref_id         = "C"
      datasource_uid = "__expr__"
      relative_time_range {
        from = 0
        to   = 0
      }
      model = local.qurl_threshold_models.dynamodb_query_failure_rate
    }
  }

  # ----------------------------------------------------------------------
  # Rule 5: webhook events silently dropped by the transit-resource gate's
  # fail-CLOSED lookup-failure branch. This is the operator's only signal
  # for "we silently dropped events because the gate couldn't decide."
  # Customers never see these drops directly — they just see missing
  # webhook deliveries for some events. Without this alert the drop is
  # invisible.
  # ----------------------------------------------------------------------
  rule {
    name      = "qurl-webhook-suppressed-lookup-failed"
    condition = "C"
    # for=5m combined with rate([5m]) in the query intentionally
    # suppresses single isolated drops — see the "Structural blind
    # spot" section in qurl-webhook-suppressed-lookup-failed.md.
    # Do NOT "harmonize" the windows without rethinking what the
    # alert should fire on; the time-to-page (~10m sustained) is
    # the trade-off for the suppression behavior.
    for       = "5m"
    is_paused = var.qurl_alerts_paused

    # NoData = OK: the counter has zero samples in healthy operation
    # (it only increments on the rare fail-closed path). Empty result
    # vector is the normal steady state, NOT an instrumentation gap —
    # the metric is registered at startup but only emitted on the
    # suppression branch, so the time series legitimately doesn't
    # exist when the system is healthy.
    no_data_state  = "OK"
    exec_err_state = "Error"

    annotations = {
      summary     = "qurl-api silently dropping webhook events (fail-closed lookup failures) > ${local.qurl_thresholds.webhook_connector_suppressed_lookup_failed_rate}/sec"
      description = "The transit-resource webhook gate at qurl-service is dropping events because it cannot load the resource to decide whether to publish. Sustained rate > ${local.qurl_thresholds.webhook_connector_suppressed_lookup_failed_rate}/sec for 5 minutes for at least one cell. The most likely cause is a DDB hiccup or IAM permission lapse on the resource-read path. Per-cell aggregation: the alert fires for the worst cell. Customers experience missing webhook deliveries with no error visible on their side; this alert is the only operator signal."
      runbook_url = "${var.qurl_alerts_runbook_base_url}/qurl-webhook-suppressed-lookup-failed.md"
    }

    labels = merge(local.qurl_alert_labels_base, {
      severity   = local.qurl_severity.page
      alert_type = "webhook_drop"
      # reason is structurally redundant with the PromQL filter on
      # the same attribute (the alert can never fire with a different
      # value) but is set here as a stable downstream-filterable label
      # for SNS receiver routing rules and to keep the label shape
      # forward-compatible if a future rule splits per-reason.
      reason = "lookup_failed"
    })

    notification_settings {
      contact_point = grafana_contact_point.qurl_aws_sns[0].name
      # TODO(#2113): add cell_id once the whole rule group changes
      # together. Without it, simultaneous drops in multiple cells
      # collapse into a single SNS notification; the runbook's first
      # action is "confirm scope by cell" so operators currently have
      # to re-run a PromQL query to learn which cell paged.
      group_by = ["alertname", "service", "deployment_env"]
    }

    data {
      ref_id         = "A"
      datasource_uid = var.prometheus_datasource_uid
      relative_time_range {
        from = 300 # 5m
        to   = 0
      }
      model = jsonencode({
        refId   = "A"
        expr    = local.qurl_query_webhook_connector_suppressed_lookup_failed
        instant = true
        range   = false
      })
    }

    data {
      ref_id         = "C"
      datasource_uid = "__expr__"
      relative_time_range {
        from = 0
        to   = 0
      }
      model = local.qurl_threshold_models.webhook_connector_suppressed_lookup_failed_rate
    }
  }
}
