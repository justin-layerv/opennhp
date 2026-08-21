# =============================================================================
# Connector Authority runtime alarm set (NHP #3455)
#
# DIMENSION-SET CONTRACT (terraform/CLAUDE.md, "Metric / Alarm Dim-Set Rules").
# CloudWatch selects an alarm's metric stream by EXACT dimension match. A dim
# set that the publisher never emits selects a non-existent stream, and the
# alarm sits in INSUFFICIENT_DATA (or, with notBreaching, a permanently green
# OK) while the fault it names goes unpaged. Two publishers are involved here
# and each is matched exactly:
#
#   1. AWS/Lambda platform metrics. Every metric used below is published by AWS
#      at the {FunctionName} dim set — verified against live us-east-2
#      list-metrics output for this account, which reports {FunctionName},
#      {FunctionName,Resource}, and {ExecutedVersion,FunctionName,Resource} for
#      Errors/ConcurrentExecutions/AsyncEvents*. {FunctionName} alone is the
#      function-wide aggregate across both closed aliases, which is what every
#      invariant here is stated over. No metric name is invented: concepts AWS
#      does not publish are composed from published ones (see the
#      non-provisioned-initialization composite below) rather than guessed at.
#
#   2. The Authority handler's own EMF publisher, namespace
#      LayerV/ConnectorAuthority. Its dim list is built in
#      layervai/qurl-service internal/connectorauthorityruntime/telemetry.go
#      (authorityTelemetry.emitPoint): ALWAYS EnvironmentID and
#      AuthorityOperation, THEN CellID when and only when the operation is a
#      cell operation (config.go::isCellOperation), THEN the metric's own
#      dynamic dimensions in sorted key order. AuthorityOperation carries the
#      PascalCase qurl-conformance operation name — the same value this module
#      renders into CONNECTOR_AUTHORITY_OPERATION — NOT the snake_case
#      terraform operation key. local.authority_custom_metric_identity_dimensions
#      reproduces that prefix exactly from the same map the environment block
#      uses, so the alarm and the publisher cannot drift apart.
#
# WHY treat_missing_data = "notBreaching" EVERYWHERE. Every alarm here is a
# zero-baseline fault counter. AWS publishes Lambda platform metrics only for
# periods with invocations, and the EMF metrics exist only for periods in which
# the handler emitted them, so an idle minute has no datapoint and any other
# setting would either page continuously on a quiet path or hold a stale state.
# The cost is that a wrong dim set is indistinguishable from a healthy stream in
# the console. That is why the rollout gate for this set is a SANDBOX SYNTHETIC
# FAILURE with a recorded page receipt (issue #3455 acceptance criterion 3, and
# the ledger entry docs/runbooks/prod-rollout-ledger/2026-07-26-issue-3455-
# authority-operator-alerts.md) — alarm state alone proves nothing here.
# =============================================================================

locals {
  # Every alarm in this file routes to the reviewed operator destinations. The
  # module owns no topic: see the operator_alarm_topic_arns variable, and the
  # foundation_contract precondition that rejects an enabled runtime with an
  # empty destination list.
  authority_alarm_actions = var.operator_alarm_topic_arns

  # Sole source of truth for the Lambda request budget: the function resource
  # and the duration alarm both read it (authority_runtime.tf).
  authority_runtime_timeout_seconds = 10

  # 80% of the reviewed request budget, in exact integer milliseconds
  # (seconds x 1000 x 0.8 == seconds x 800). A request that reaches this point
  # is on the edge of being killed by the Lambda timeout, so the operator is
  # paged BEFORE the failure rather than by its Errors aftermath.
  #
  # This is a STRUCTURAL threshold derived from the configured budget, not an
  # empirical percentile: the graph has never carried traffic (no AWS/Lambda
  # Duration datapoint exists for any of the 13 functions yet). The POST-STEP-3
  # FLAG on the timeout/memory pair in authority_runtime.tf owns the empirical
  # recalibration; tightening the timeout there tightens this automatically.
  authority_duration_alarm_threshold_ms = local.authority_runtime_timeout_seconds * 800

  # ---------------------------------------------------------------------------
  # AWS/Lambda platform alarms, one set per Authority function.
  # ---------------------------------------------------------------------------
  # threshold == null means "resolved per function from the bound contract"
  # (concurrency exhaustion is the only such alarm today).
  authority_lambda_alarm_specs = {
    provisioned_concurrency_spillover = {
      suffix              = "provisioned-concurrency-spillover"
      metric_name         = "ProvisionedConcurrencySpilloverInvocations"
      statistic           = "Sum"
      extended_statistic  = null
      comparison_operator = "GreaterThanThreshold"
      threshold           = 0
      period              = 60
      evaluation_periods  = 1
      # Aggregate across both aliases deliberately: any active or standby
      # spillover violates the function-wide zero-spillover invariant.
      summary = "spilled to an on-demand execution environment; a nonzero value aborts the rollout"
    }
    errors = {
      suffix              = "errors"
      metric_name         = "Errors"
      statistic           = "Sum"
      extended_statistic  = null
      comparison_operator = "GreaterThanThreshold"
      threshold           = 0
      period              = 60
      evaluation_periods  = 1
      # Errors counts handler faults, unhandled panics, timeouts, AND the
      # fail-closed init rejection of a non-provisioned execution environment.
      # A clean protocol rejection is a successful invocation carrying an error
      # envelope, so it does NOT land here — the baseline is exactly zero.
      summary = "returned a function error, timed out, or failed initialization; the request-path baseline is exactly zero"
    }
    throttles = {
      suffix              = "throttles"
      metric_name         = "Throttles"
      statistic           = "Sum"
      extended_statistic  = null
      comparison_operator = "GreaterThanThreshold"
      threshold           = 0
      period              = 60
      evaluation_periods  = 1
      # A throttle is a caller-visible failure of assignment/registration, not
      # backpressure to absorb: the reserved envelope is sized from the bound
      # contract's caller capacity, so reaching it means the capacity model or
      # the caller's preinvoke limiter is wrong.
      summary = "was throttled against its reserved concurrency envelope; the caller saw a failed assignment or registration"
    }
    duration = {
      suffix              = "duration"
      metric_name         = "Duration"
      statistic           = null
      extended_statistic  = "p99"
      comparison_operator = "GreaterThanThreshold"
      threshold           = null # resolved to authority_duration_alarm_threshold_ms
      # 5-minute periods over 2 evaluations: the request path is fully
      # provisioned (no cold start), so a single slow dependency call must not
      # page, but a sustained p99 at the timeout edge must.
      period             = 300
      evaluation_periods = 2
      summary            = "p99 request duration reached 80% of the reviewed Lambda timeout budget"
    }
    concurrency_exhaustion = {
      suffix              = "concurrency-exhaustion"
      metric_name         = "ConcurrentExecutions"
      statistic           = "Maximum"
      extended_statistic  = null
      comparison_operator = "GreaterThanOrEqualToThreshold"
      threshold           = null # resolved to the contract's steady reserved envelope
      period              = 60
      evaluation_periods  = 1
      # The LEADING indicator for the throttle alarm above: AWS publishes
      # ConcurrentExecutions per function for functions carrying a reserved
      # limit, which all 13 do. Sitting AT the reserved ceiling means the very
      # next concurrent request is rejected.
      summary = "reached its full reserved concurrency ceiling; the next concurrent request throttles"
    }
    async_invocation = {
      suffix              = "async-invocation"
      metric_name         = "AsyncEventsReceived"
      statistic           = "Sum"
      extended_statistic  = null
      comparison_operator = "GreaterThanThreshold"
      threshold           = 0
      period              = 60
      evaluation_periods  = 1
      # Contract drift guard, not a failure counter. The Authority is invoked
      # RequestResponse only; an asynchronous invocation would put a security
      # decision on a retried, queued, caller-invisible path. Any datapoint at
      # all is the fault. Deliberately NOT a DeadLetterErrors alarm: no
      # Authority function has a dead_letter_config (asserted in the module
      # tests and the first-apply checker), and DeadLetterErrors is published by
      # no function in this account — an alarm on it could never select a real
      # stream, which is the exact anti-pattern the dim-set rule forbids.
      summary = "received an asynchronous invocation; the Authority is a RequestResponse-only contract"
    }
  }

  authority_lambda_alarms = merge([
    for function_name, fn in local.authority_runtime_functions : {
      for alarm_key, spec in local.authority_lambda_alarm_specs :
      "${function_name}:${alarm_key}" => {
        function_name       = function_name
        operation           = fn.operation
        alarm_name          = "${function_name}-${spec.suffix}"
        metric_name         = spec.metric_name
        statistic           = spec.statistic
        extended_statistic  = spec.extended_statistic
        comparison_operator = spec.comparison_operator
        period              = spec.period
        evaluation_periods  = spec.evaluation_periods
        summary             = spec.summary
        threshold = (
          spec.threshold != null ? spec.threshold :
          alarm_key == "duration" ? local.authority_duration_alarm_threshold_ms :
          fn.spec.steady_reserved_concurrency
        )
      }
    }
  ]...)

  # ---------------------------------------------------------------------------
  # Non-provisioned initialization (composite over published metrics).
  # ---------------------------------------------------------------------------
  # The handler rejects any execution environment whose
  # AWS_LAMBDA_INITIALIZATION_TYPE is not "provisioned-concurrency"
  # (connectorauthorityruntime/initialization.go). That rejection happens at
  # INIT, before the telemetry provider exists, so the handler emits NO custom
  # metric for it and there is nothing to alarm on directly.
  #
  # Rather than invent a metric name, compose the event from the two published
  # AWS/Lambda signals it necessarily produces in the same minute: the
  # invocation ran outside provisioned capacity (spillover) AND the environment
  # failed (Errors). The conjunction is the precise security event; each child
  # also pages on its own, so nothing is lost if the two datapoints straddle a
  # period boundary.
  authority_non_provisioned_init_alarms = local.authority_runtime_functions

  # ---------------------------------------------------------------------------
  # Custom LayerV/ConnectorAuthority (EMF) alarms.
  # ---------------------------------------------------------------------------
  authority_custom_metric_namespace = "LayerV/ConnectorAuthority"

  # The COMPLETE emitted-metric inventory of the deployed Authority handler,
  # transcribed from authorityMetricUnits in
  # layervai/qurl-service internal/connectorauthorityruntime/telemetry.go. Every
  # name must be classified below as alarmed or explicitly unalarmed; the
  # foundation_contract precondition rejects a partial or overlapping
  # classification, so a handler that starts emitting a new metric cannot land
  # unmonitored and unreviewed.
  authority_emitted_custom_metrics = toset([
    "qurl.connector_authority.invocation.total",
    "aws.dynamodb.operation.total",
    "aws.dynamodb.operation.duration",
    "qurl.connector_authority.hub_replay.decision.total",
    "qurl.connector_authority.hub_replay.phase.total",
    "qurl.connector_authority.hub_replay.future_skew",
    "qurl.connector_registration.activation.total",
    "qurl.connector_registration.otp_verification.total",
    "qurl.connector_registration.adapter_admission.total",
    "qurl.connector_registration.adapter_contract_violation.total",
    "qurl.connector_registration.adapter_late_result.total",
    "qurl.connector_registration.completion_identity_rejected.total",
  ])

  authority_alarmed_custom_metrics = toset([
    "qurl.connector_authority.invocation.total",
    "qurl.connector_registration.adapter_admission.total",
    "qurl.connector_registration.adapter_contract_violation.total",
    "qurl.connector_registration.adapter_late_result.total",
    "qurl.connector_registration.completion_identity_rejected.total",
  ])

  # Deliberately unalarmed, each with the reason it cannot become a fail-closed
  # operator page today. These stay available to dashboards and forensics.
  authority_unalarmed_custom_metrics = {
    "aws.dynamodb.operation.total"                       = "Dependency diagnostic. A failed DynamoDB call that matters to the caller already lands on the terminal invocation outcome alarm (unavailable/internal) or on AWS/Lambda Errors; alarming the raw counter would page on retried transient faults."
    "aws.dynamodb.operation.duration"                    = "The handler emits the histogram's arithmetic MEAN, not a percentile (telemetry.go emitMetric documents this explicitly and directs percentile alarms at the Lambda platform metrics). A mean-based latency page would be both noisy and wrong; the Duration p99 alarm owns request latency."
    "qurl.connector_authority.hub_replay.decision.total" = "The replay decision space is mostly legitimate (replay hits, conditional winners/losers, recoveries). Separating the genuinely bad outcomes needs a post-traffic baseline that does not exist yet; the terminal outcome alarm covers the operator-visible failures in the meantime."
    "qurl.connector_authority.hub_replay.phase.total"    = "Phase breakdown of the same decision counter above; dashboard dimension, not an independent fault signal."
    "qurl.connector_authority.hub_replay.future_skew"    = "Clock-skew gauge in seconds with no reviewed tolerance yet; a threshold guessed ahead of the first real distribution would page on normal skew or never fire."
    "qurl.connector_registration.activation.total"       = "Outcome breakdown whose rejected/quota/not-yet-valid outcomes are legitimate user-driven states; alarming it would page on end-user error."
    "qurl.connector_registration.otp_verification.total" = "Same: OTP mismatch, missing, and lockout are expected user-driven outcomes, not operator faults."
  }

  # The publisher's identity dimension prefix, reproduced exactly. Built from
  # local.authority_operation_conformance_name — the same map that renders
  # CONNECTOR_AUTHORITY_OPERATION into the function's environment — so the alarm
  # dimension and the value the handler reports are the same string by
  # construction. CellID is present if and only if the operation is a cell
  # operation, matching isCellOperation on the handler side.
  authority_custom_metric_identity_dimensions = {
    for function_name, fn in local.authority_runtime_functions :
    function_name => merge(
      {
        EnvironmentID      = var.environment
        AuthorityOperation = local.authority_operation_conformance_name[fn.operation]
      },
      fn.cell_id == "" ? {} : {
        CellID = fn.cell_id
      },
    )
  }

  # Terminal invocation outcome (every function). The two alarmed outcomes are
  # the ones no caller can provoke: "internal" is a handler fault or malformed
  # response envelope, "unavailable" is a dependency the Authority could not
  # reach. "success", "invalid_request", and "rejected" are caller-driven and
  # are deliberately left unalarmed.
  authority_terminal_alarm_outcomes = ["internal", "unavailable"]
  authority_terminal_alarms = merge([
    for function_name, fn in local.authority_runtime_functions : {
      for outcome in local.authority_terminal_alarm_outcomes :
      "${function_name}:${outcome}" => {
        function_name = function_name
        operation     = fn.operation
        outcome       = outcome
      }
    }
  ]...)

  # Registration-adapter metrics are emitted only by the admission-gated
  # operations (internal/connectorauthority/registration_adapter.go), which is
  # exactly local.authority_admission_operations. Keying the alarms off that
  # same list keeps the alarm set and the handler's emit sites in lockstep.
  authority_registration_adapter_functions = {
    for function_name, fn in local.authority_runtime_functions :
    function_name => fn
    if contains(local.authority_admission_operations, fn.operation)
  }

  # Admission rejection. "admitted" is the healthy outcome; "limited" means the
  # in-flight/rate gate rejected a registration, "unavailable" means the gate
  # itself could not decide. Both are fail-closed rejections of real customer
  # onboarding, which is precisely the silent-friction failure #3455 exists to
  # prevent.
  authority_admission_alarm_outcomes = ["limited", "unavailable"]
  authority_admission_alarms = merge([
    for function_name, fn in local.authority_registration_adapter_functions : {
      for outcome in local.authority_admission_alarm_outcomes :
      "${function_name}:${outcome}" => {
        function_name = function_name
        operation     = fn.operation
        outcome       = outcome
      }
    }
  ]...)

  # Completion identity rejection is emitted only from the CompleteRegistration
  # adapter path (registration_adapter.go). "authority_fence" is the Authority
  # refusing to complete a registration whose identity did not match — a
  # security decision that must reach an operator, never just a log line.
  authority_completion_identity_alarms = {
    for function_name, fn in local.authority_runtime_functions :
    function_name => fn
    if fn.operation == "complete_registration"
  }
  authority_completion_identity_alarm_cause = "authority_fence"
}

# -----------------------------------------------------------------------------
# AWS/Lambda platform alarms.
#
# The spillover member of this set keeps the resource name authority_spillover
# so the already-applied live alarms are the same Terraform addresses; it is now
# routed to the operator destination like every other alarm.
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "authority_spillover" {
  for_each = {
    for key, alarm in local.authority_lambda_alarms :
    alarm.function_name => alarm
    if endswith(key, ":provisioned_concurrency_spillover")
  }

  alarm_name          = each.value.alarm_name
  alarm_description   = "Connector Authority ${each.value.operation} (${each.value.function_name}) ${each.value.summary}."
  namespace           = "AWS/Lambda"
  metric_name         = each.value.metric_name
  statistic           = each.value.statistic
  comparison_operator = each.value.comparison_operator
  threshold           = each.value.threshold
  period              = each.value.period
  evaluation_periods  = each.value.evaluation_periods
  treat_missing_data  = "notBreaching"

  alarm_actions = local.authority_alarm_actions

  dimensions = {
    FunctionName = each.value.function_name
  }

  tags = merge(local.common_tags, {
    Name      = each.value.alarm_name
    Operation = each.value.operation
  })
}

resource "aws_cloudwatch_metric_alarm" "authority_runtime" {
  for_each = {
    for key, alarm in local.authority_lambda_alarms :
    key => alarm
    if !endswith(key, ":provisioned_concurrency_spillover")
  }

  alarm_name          = each.value.alarm_name
  alarm_description   = "Connector Authority ${each.value.operation} (${each.value.function_name}) ${each.value.summary}."
  namespace           = "AWS/Lambda"
  metric_name         = each.value.metric_name
  statistic           = each.value.statistic
  extended_statistic  = each.value.extended_statistic
  comparison_operator = each.value.comparison_operator
  threshold           = each.value.threshold
  period              = each.value.period
  evaluation_periods  = each.value.evaluation_periods
  treat_missing_data  = "notBreaching"

  alarm_actions = local.authority_alarm_actions

  # The exact published AWS/Lambda dim set: the function-wide aggregate across
  # every version and both closed aliases.
  dimensions = {
    FunctionName = each.value.function_name
  }

  tags = merge(local.common_tags, {
    Name      = each.value.alarm_name
    Operation = each.value.operation
  })
}

# -----------------------------------------------------------------------------
# Non-provisioned initialization: composed from published metrics, never
# invented. See the local above for why no direct metric can exist.
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_composite_alarm" "authority_non_provisioned_initialization" {
  for_each = local.authority_non_provisioned_init_alarms

  alarm_name        = "${each.key}-non-provisioned-initialization"
  alarm_description = "Connector Authority ${each.value.operation} (${each.key}) served an invocation from an execution environment that was not created by provisioned concurrency, and that environment failed closed at initialization. The startup graph cannot fit inside the request path, so this is a security event, not a capacity event."

  alarm_rule = join(" AND ", [
    "ALARM(\"${aws_cloudwatch_metric_alarm.authority_spillover[each.key].alarm_name}\")",
    "ALARM(\"${aws_cloudwatch_metric_alarm.authority_runtime["${each.key}:errors"].alarm_name}\")",
  ])

  alarm_actions = local.authority_alarm_actions

  tags = merge(local.common_tags, {
    Name      = "${each.key}-non-provisioned-initialization"
    Operation = each.value.operation
  })
}

# -----------------------------------------------------------------------------
# Custom LayerV/ConnectorAuthority (EMF) alarms.
#
# Each dimensions block is the publisher's identity prefix (EnvironmentID,
# AuthorityOperation, and CellID for cell operations) MERGED with that metric's
# own dynamic dimensions — the exact set emitPoint writes into the EMF
# _aws.CloudWatchMetrics[0].Dimensions list. A partial set here would select a
# stream that never exists.
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "authority_terminal_outcome" {
  for_each = local.authority_terminal_alarms

  alarm_name          = "${each.value.function_name}-terminal-outcome-${each.value.outcome}"
  alarm_description   = "Connector Authority ${each.value.operation} (${each.value.function_name}) returned the ${each.value.outcome} terminal outcome. No caller can provoke this outcome: it is a handler fault or an unreachable dependency."
  namespace           = local.authority_custom_metric_namespace
  metric_name         = "qurl.connector_authority.invocation.total"
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = local.authority_alarm_actions

  # terminalMetricDimensions contributes exactly {Outcome}.
  dimensions = merge(
    local.authority_custom_metric_identity_dimensions[each.value.function_name],
    { Outcome = each.value.outcome },
  )

  tags = merge(local.common_tags, {
    Name      = "${each.value.function_name}-terminal-outcome-${each.value.outcome}"
    Operation = each.value.operation
  })
}

resource "aws_cloudwatch_metric_alarm" "authority_admission_rejected" {
  for_each = local.authority_admission_alarms

  alarm_name          = "${each.value.function_name}-admission-${each.value.outcome}"
  alarm_description   = "Connector Authority ${each.value.operation} (${each.value.function_name}) rejected a registration at admission with outcome ${each.value.outcome}. Customer or agent onboarding is failing closed."
  namespace           = local.authority_custom_metric_namespace
  metric_name         = "qurl.connector_registration.adapter_admission.total"
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = local.authority_alarm_actions

  # registrationAdapterMetricDimensions contributes exactly {Outcome}; both
  # emitting operations are cell operations, so CellID is always present.
  dimensions = merge(
    local.authority_custom_metric_identity_dimensions[each.value.function_name],
    { Outcome = each.value.outcome },
  )

  tags = merge(local.common_tags, {
    Name      = "${each.value.function_name}-admission-${each.value.outcome}"
    Operation = each.value.operation
  })
}

resource "aws_cloudwatch_metric_alarm" "authority_adapter_contract_violation" {
  for_each = local.authority_registration_adapter_functions

  alarm_name          = "${each.key}-adapter-contract-violation"
  alarm_description   = "Connector Authority ${each.value.operation} (${each.key}) observed a registration adapter contract violation. The handler and its adapter disagree about the reviewed contract; treat as drift until proven otherwise."
  namespace           = local.authority_custom_metric_namespace
  metric_name         = "qurl.connector_registration.adapter_contract_violation.total"
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = local.authority_alarm_actions

  # This metric carries NO dynamic dimensions (the publisher returns an empty
  # map), so the identity prefix alone is the complete emitted set.
  dimensions = local.authority_custom_metric_identity_dimensions[each.key]

  tags = merge(local.common_tags, {
    Name      = "${each.key}-adapter-contract-violation"
    Operation = each.value.operation
  })
}

resource "aws_cloudwatch_metric_alarm" "authority_adapter_late_result" {
  for_each = local.authority_registration_adapter_functions

  alarm_name          = "${each.key}-adapter-late-result"
  alarm_description   = "Connector Authority ${each.value.operation} (${each.key}) produced a registration adapter result after its deadline had passed. The caller has already been answered, so the late result is unobservable to it."
  namespace           = local.authority_custom_metric_namespace
  metric_name         = "qurl.connector_registration.adapter_late_result.total"
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = local.authority_alarm_actions

  # No dynamic dimensions, exactly as for the contract-violation counter.
  dimensions = local.authority_custom_metric_identity_dimensions[each.key]

  tags = merge(local.common_tags, {
    Name      = "${each.key}-adapter-late-result"
    Operation = each.value.operation
  })
}

resource "aws_cloudwatch_metric_alarm" "authority_completion_identity_rejected" {
  for_each = local.authority_completion_identity_alarms

  alarm_name          = "${each.key}-completion-identity-${local.authority_completion_identity_alarm_cause}"
  alarm_description   = "Connector Authority ${each.value.operation} (${each.key}) refused to complete a registration at the Authority identity fence. This is a security refusal and must reach an operator, not only the log group."
  namespace           = local.authority_custom_metric_namespace
  metric_name         = "qurl.connector_registration.completion_identity_rejected.total"
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = local.authority_alarm_actions

  # registrationIdentityMetricDimensions contributes exactly {Cause}.
  dimensions = merge(
    local.authority_custom_metric_identity_dimensions[each.key],
    { Cause = local.authority_completion_identity_alarm_cause },
  )

  tags = merge(local.common_tags, {
    Name      = "${each.key}-completion-identity-${local.authority_completion_identity_alarm_cause}"
    Operation = each.value.operation
  })
}
