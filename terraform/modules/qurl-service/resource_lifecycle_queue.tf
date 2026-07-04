# Resource-lifecycle SQS queue — qurl-scanner fan-out to qurl-api consumer.
#
# Producer: the qurl-scanner Lambda (`scanner_lambda.tf`) emits one envelope
# per expired qURL (`qurl.expired`) and one per closed resource
# (`resource.closed`) to this queue when run with `--emit-mode=sqs`.
#
# Consumer: the qurl-api ECS task's webhook-event drainer goroutine
# (qurl-service PR #874, gated on `WEBHOOK_EVENTS_CONSUMER_ENABLED=true` +
# `WEBHOOK_EVENTS_SQS_QUEUE_URL` env vars). It de-duplicates via the
# `qurl-webhook-event-dedupe` DDB table (qurl-service PR #874 / nhp ledger
# 2026-06-09) and then fans out via the existing in-process
# `WebhookService` to registered subscribers (Discord bot, qurl-s3-connector).
#
# # Encryption
#
# The queue + DLQ are SSE-KMS-encrypted with the same `secrets` CMK that
# encrypts the qurl-service DDB tables (`var.secrets_kms_key_arn`,
# threaded from `module.kms.secrets_key_arn` at the root). Reusing the
# existing key keeps the IAM grant surface minimal: the producer and
# consumer roles already hold `kms:Decrypt` against this key for their
# DDB work, and the new IAM policies in `scanner_lambda.tf` /
# `main.tf` just add `kms:GenerateDataKey` (producer) and
# `kms:Decrypt` (consumer) statements scoped to the same key.
#
# # Gating
#
# `count = var.qurl_scanner_lambda_enabled ? 1 : 0` keys the queue's
# existence to the same flag as the producer Lambda. In an env where the
# scanner Lambda isn't deployed (today: prod), the queue + DLQ are
# absent — no orphan resources, no IAM grants on roles that wouldn't be
# able to reach the queue anyway.
#
# # Inert until activation
#
# This file ships the queue + DLQ + IAM grants on both producer and
# consumer roles. It does NOT set `EMIT_MODE=sqs` on the scanner Lambda
# and does NOT set `WEBHOOK_EVENTS_CONSUMER_ENABLED=true` on the qurl-api
# task. So:
#   - The scanner Lambda continues to default to `log-only` emit (slog
#     the would-be payload, skip pass 2). Nothing is published to the
#     queue.
#   - The qurl-api drainer goroutine stays dormant. Nothing reads from
#     the queue.
# The queue sits empty between this PR landing and the activation PR
# that flips both flags. That activation PR is gated on the sandbox
# smoke tests for the scanner Lambda (#2326 ledger entry) coming back
# clean.
#
# # FIFO vs standard
#
# Standard queue (not FIFO). qurl-service's `SqsEmitter` sends no FIFO
# parameters (no `MessageGroupId` / `MessageDeduplicationId`); the
# consumer's startup config hard-fails when the URL ends in `.fifo`.
# Both are documented in
# `qurl-service:docs/claude/env-vars.md::WEBHOOK_EVENTS_SQS_QUEUE_URL`.
#
# # ACTIVATION-PR NOTES
#
# Before flipping `EMIT_MODE=sqs` / `WEBHOOK_EVENTS_CONSUMER_ENABLED=true`:
#
#   1. The queue-resource `precondition` below is the SINGLE site that
#      guards `var.secrets_kms_key_arn != null` for the producer +
#      consumer IAM policies (which reference the var unguarded). Safe
#      today because all three share the `qurl_scanner_lambda_enabled`
#      gate and the precondition aborts plan before apply. FRAGILE if
#      the activation PR (or any future edit) moves either IAM policy
#      to a different gate — the null-guard silently vanishes, then
#      `Resource = [null]` returns an ambiguous `Invalid policy
#      document` at apply. cr #2461 round-3.
#
#   2. The DLQ's `kms_master_key_id = var.secrets_kms_key_arn` is
#      transitively safe (the main-queue precondition fails plan
#      before the DLQ can create) but not locally guarded — keep the
#      precondition on the main queue, OR add one to the DLQ too, when
#      refactoring this file.
#
#   3. The backlog alarm fires on `Sum > 1000 for 3 × 5min` of
#      `ApproximateNumberOfMessagesVisible`. The sandbox 10k mass-mint
#      load test (plan step 4, prod-gate per #2326's ledger) is
#      EXPECTED to push the queue well over 1000 for >15 min by
#      construction. Pre-ack the alarm for the load-test window (or
#      put the alarm in a maintenance-window suppression for the
#      duration) — the alarm during the load test is the test
#      working, not a regression.

resource "aws_sqs_queue" "resource_lifecycle_queue" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  name                       = "${var.name_prefix}-${var.cell_id}-qurl-resource-lifecycle"
  visibility_timeout_seconds = 90     # >= the qurl-api drainer's per-message ack budget (60s default per PR #874)
  message_retention_seconds  = 345600 # 4 days — long enough for an ops incident to investigate, short enough that any logical-bug leak evaporates
  receive_wait_time_seconds  = 20     # long polling
  kms_master_key_id          = var.secrets_kms_key_arn

  tags = merge(var.tags, local.scanner_lambda_common_tags, {
    Name = "${var.name_prefix}-${var.cell_id}-qurl-resource-lifecycle"
  })

  # KMS-NULL FAIL-LOUD: `var.secrets_kms_key_arn` is `default = null` at
  # the module level; the root always wires `module.kms.secrets_key_arn`
  # (non-null) and there's no caller path where the queue should exist
  # without it. Without this precondition, a null value would silently
  # fall back to SSE-SQS (AWS-owned key, on by default for queues
  # created since 2023) instead of the CMK this queue requires. The
  # queue would still be encrypted, but not under the secrets CMK the
  # regulated emit path is supposed to live under — which is exactly
  # the posture this queue exists for. A precondition surfaces a
  # copy-pasteable error at plan time instead — same fail-loud pattern
  # as the existing block at scanner_lambda.tf:473-489.
  #
  # The IAM grants in scanner_lambda.tf (`KMSEncryptSQS`) and main.tf
  # (`KMSDecryptResourceLifecycleSQS`) also reference
  # `var.secrets_kms_key_arn` unguarded; a null there would produce
  # `Resource = [null]` and fail apply with `Invalid policy document`,
  # but the failure would be ambiguous. This single precondition catches
  # the null at the producer-config layer and points the operator
  # directly at the missing wire.
  lifecycle {
    precondition {
      condition     = var.secrets_kms_key_arn != null && var.secrets_kms_key_arn != ""
      error_message = "qurl_scanner_lambda_enabled=true requires var.secrets_kms_key_arn to be non-empty. Wire `module.kms.secrets_key_arn` from the root into the qurl-service module (the same key the DDB tables and Stripe secret use). Without it the queue would be created unencrypted, breaching the regulated emit path; the dependent IAM policies would also fail with `Invalid policy document`."
    }
  }
}

# Dead-letter queue: receives envelopes that fail the consumer's processing
# loop 3 times in a row. The qurl-api consumer surfaces transient failures
# (DDB throttle, publish-side ctx-cancel) AND unknown-event-type envelopes
# (deploy-skew recovery between scanner and consumer image versions) by
# leaving them on the queue for redelivery — without the DLQ they would
# churn forever and starve real work. 14-day retention so an operator has
# time to inspect + replay during an incident.
resource "aws_sqs_queue" "resource_lifecycle_queue_dlq" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  name                      = "${var.name_prefix}-${var.cell_id}-qurl-resource-lifecycle-dlq"
  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = var.secrets_kms_key_arn

  tags = merge(var.tags, local.scanner_lambda_common_tags, {
    Name = "${var.name_prefix}-${var.cell_id}-qurl-resource-lifecycle-dlq"
  })
}

resource "aws_sqs_queue_redrive_policy" "resource_lifecycle_queue" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  queue_url = aws_sqs_queue.resource_lifecycle_queue[0].id
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.resource_lifecycle_queue_dlq[0].arn
    maxReceiveCount     = 3
  })
}

# ============================================================================
# Alarms
# ============================================================================
#
# Both alarms wire `alarm_actions` to `local.qurl_service_alarm_actions`,
# which the root module feeds from the cell-wide alerts topic
# (`module.monitoring.sns_topic_arn`) through the
# `var.qurl_service_alarm_sns_topic_arn` input —
# the topic every other alarm in the cell routes to (#2491). The module
# keeps the empty-string safe-degrade seam (empty ARN → alarm still fires
# + appears in CloudWatch, just no notification) so it stays reusable —
# the same `var.x != "" ? [x] : []` seam the AC alarms use
# (`modules/ac/monitoring.tf`), which `check-observability-parity.py`
# enforces. (Note: `modules/billing/sqs.tf`, cited below for the `Sum`
# statistic, takes the other tack — `default = null` + `count` gating —
# so it is not the seam precedent.)
#
# STATISTIC CHOICE — both alarms use `Sum` on
# `ApproximateNumberOfMessagesVisible`, a gauge. AWS's own SQS dashboards
# default to `Maximum` for gauges; `Sum` over a 5-min period can
# over-count if CloudWatch emits more than one datapoint per period
# (rare for SQS but possible). Kept as `Sum` here for consistency with
# the existing `modules/billing/sqs.tf` precedent (`usage_queue_backlog`
# + `dlq_messages`) — switching ONE pair of queue alarms in the repo to
# `Maximum` would create an inconsistency that's worse than the slight
# over-count risk. A future hygiene PR could flip both pairs together.

resource "aws_cloudwatch_metric_alarm" "resource_lifecycle_queue_backlog" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  alarm_name          = "${var.name_prefix}-${var.cell_id}-qurl-resource-lifecycle-queue-backlog"
  alarm_description   = "Resource-lifecycle SQS queue backlog growing — qurl-api consumer may be falling behind or wedged."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3 # 3 × 5-min periods to absorb a transient burst (first-sweep backfill, redeploy lag)
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 1000
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.resource_lifecycle_queue[0].name
  }

  alarm_actions = local.qurl_service_alarm_actions
  ok_actions    = local.qurl_service_alarm_actions

  tags = merge(var.tags, local.scanner_lambda_common_tags, {
    Name = "${var.name_prefix}-${var.cell_id}-qurl-resource-lifecycle-queue-backlog"
  })
}

# DLQ-depth alarm fires on any message: by the time the consumer has
# failed 3 redelivery attempts, the envelope is either a deploy-skew
# casualty (recoverable by operator replay after the consumer image
# catches up) or a hard payload bug (needs investigation + fix). Either
# way, ops needs to see it immediately.
resource "aws_cloudwatch_metric_alarm" "resource_lifecycle_queue_dlq_messages" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  alarm_name          = "${var.name_prefix}-${var.cell_id}-qurl-resource-lifecycle-dlq-messages"
  alarm_description   = "Messages in resource-lifecycle DLQ — qurl-api consumer failed 3 attempts (deploy-skew casualty or payload bug)."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.resource_lifecycle_queue_dlq[0].name
  }

  alarm_actions = local.qurl_service_alarm_actions
  ok_actions    = local.qurl_service_alarm_actions

  tags = merge(var.tags, local.scanner_lambda_common_tags, {
    Name = "${var.name_prefix}-${var.cell_id}-qurl-resource-lifecycle-dlq-messages"
  })
}
