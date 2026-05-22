# Runbook: qurl-api webhook events dropped (fail-CLOSED lookup failures)

## What fired

**`qurl-webhook-suppressed-lookup-failed`** — the qurl-service emitted a sustained rate of `qurl_webhook_connector_resources_suppressed_total{reason="lookup_failed"}` exceeding `0.05/s` over a 5-minute window for at least one cell.

## What it means

The transit-resource webhook gate at `internal/service/qurl_service.go::publishResourceWebhookEvent` (qurl-service) decides whether to publish a webhook by loading the resource and inspecting `Type`. When the load fails (DynamoDB hiccup, IAM permission lapse, network blip), the gate **fails CLOSED** — it drops the event rather than publishing with unknown classification. The metric increments once per dropped event with `reason="lookup_failed"`.

This is the operator's **only** signal for "we silently dropped webhooks." Customers never see these drops directly — their webhook endpoints simply don't receive the missing events. There is no HTTP error, no retry, no DLQ surface; the event is gone.

The metric and its companion `reason="filtered"` (in-band suppression for transit-typed resources, high-volume by design) are documented at qurl-service `internal/observability/metrics.go::WebhookSuppressedReasonLookupFailed`.

## First five minutes

1. **Confirm scope.** PromQL: `sum by (cell_id, event) (rate(qurl_webhook_connector_resources_suppressed_total{deployment_environment="prod", reason="lookup_failed"}[10m]))`. Tells you which cell(s) and which event type(s) are dropping.
2. **Check DynamoDB health** for the resources table in the affected cell — the `qurl-dynamodb-query-failures` alert may also be firing. If it is, treat this as a downstream symptom of that incident and start with [qurl-dynamodb-query-failures.md](qurl-dynamodb-query-failures.md).
3. **Search Loki for the load error**: `{service_name="qurl-api", deployment_environment="prod"} |= "webhook event suppressed" | json | level="WARN"`. The drop site (qurl-service `internal/service/qurl_service.go::publishResourceWebhookEvent`) emits `slog.WarnContext` with the literal message `"webhook event suppressed: transit gate could not load resource (fail-closed)"` and structured fields `owner_id`, `event_type`, `resource_id`, `error` — the `error` field is the wrapped DDB error and is the most diagnostic. If the search returns no lines despite the alert firing, the deployed binary may predate the log addition; cross-check the suppression metric increments against log absence to confirm.
4. **Check IAM**: a recent terraform apply may have narrowed the qurl-service task role's DynamoDB permissions. `gh run list -R layervai/nhp -w promote-to-prod.yml --limit 5` — anything recent with `terraform-apply: success` is worth diffing for `aws_iam_*` changes against the qurl-resources table.

## Mitigations

| Cause | Action |
|---|---|
| DynamoDB throttling / outage | Wait it out; the events are already lost (no DLQ exists). File an incident ticket recording the count of dropped events from the metric for customer follow-up. |
| IAM permission regression | Roll the relevant terraform change back. The qurl-service ECS task role lives in **this repo** at `terraform/modules/qurl-service/main.tf::aws_iam_role.task`, not the qurl-service application repo — search recent `nhp` PRs that touched `modules/qurl-service/` for the suspect change. Re-apply once policy is restored. |
| Wide-blast network issue (NAT / VPC endpoint) | Coordinate with infra; the AC-side alarms will also be firing. |

## Why there is no automated remediation

The gate's fail-CLOSED choice is intentional — publishing with unknown classification risks leaking transit-typed resources (connector-internal resources that must never appear in customer-facing webhook payloads) to customer endpoints. The right answer when the gate can't decide is to drop the event and page an operator, which is what this alert encodes.

**Full rationale (internal):** the qurl-service repo's `docs/claude/connector-redaction.md` documents which resource fields are connector-internal and the redaction model that this gate implements. Operators without qurl-service repo access: ping the #qurl team in chat for context.

If the drop rate ever becomes load-bearing for a customer integration, the long-term fix is in qurl-service: introduce a DLQ for `reason="lookup_failed"` events so they can be replayed after the DDB hiccup clears, rather than discarded outright. That's a behavioral change tracked separately — this runbook documents the current dropped-on-the-floor reality.

## Tuning notes

`0.05/s` matches the `dynamodb_query_failure_rate` precedent. The metric should sit at zero in healthy steady state; any sustained non-zero rate is suspicious. After soak, if benign short bursts during deploy churn produce spurious pages, consider raising the threshold or extending the `for` window — but **do not** silence this alert without a DLQ in place, because there is no other surface that catches the drop.

**Structural blind spot — single isolated drops.** PromQL `rate()` needs at least two samples to produce a value, so a single isolated drop after a long quiet period evaluates to an empty result vector, which `no_data_state = OK` correctly classifies as healthy. The alert is structurally incapable of catching one-off drops; it only fires on sustained or repeated drops within a 5m window. This is acceptable today because the dropped event is already lost (no DLQ), so the difference between "one drop missed by the alert" and "one drop caught but unrecoverable" is operationally identical. If a DLQ is ever introduced (the long-term direction), this blind spot becomes worth closing with a complementary `increase(...[10m]) > 0` rule.

## Soak verification before flipping is_paused=false

The metric is registered by qurl-service at startup but is zero-emitting until the fail-CLOSED branch fires, so a wrong metric name would be silently treated as "healthy zero" by `no_data_state = OK`. Before flipping `qurl_alerts_paused = false`, validate the metric name resolves end-to-end:

1. **Cold check — name-shape validation.** In Grafana Explore: `qurl_webhook_connector_resources_suppressed_total{deployment_environment="sandbox"}`.
   - The OTel→Prom name-shape correctness is anchored by the `qurl_webhook_delivery_total` precedent (same shape, same translation rules), so a *typo'd* metric name surfaces here.
   - **Caveat:** OTel SDKs do not universally emit zero-valued samples for registered-but-never-incremented counters. If the cold check returns no series for a correctly-named metric, that just means the counter hasn't incremented yet in sandbox — not a defect. Proceed directly to the hot check; do NOT conclude the rule is broken from a quiet cold check alone.

2. **Hot check — end-to-end materialization.** Required because the cold check can be inconclusive. Induce one drop in sandbox:
   - **Cleanest induction:** land a one-off sandbox-only debug knob in qurl-service that injects a `lookup_failed` increment on a guarded code path. Most surgical, no infrastructure side effects.
   - **Fallback induction:** force throttling on the `qurl-resources` table briefly (provisioned-capacity reduction if applicable, or a controlled load test that exceeds the on-demand burst floor). Avoid the IAM-revoke approach — the task role grants `GetItem` and `Query` in a single statement (`terraform/modules/qurl-service/main.tf::aws_iam_role_policy.task_dynamodb`), so removing `GetItem` would also strip `Query` and trip the sibling `qurl-dynamodb-query-failures` alert as a side effect.
   - Either way: watch the alert's PromQL panel for one increment with `reason="lookup_failed"`. Restore conditions immediately. **Coordinate first** — even non-IAM inductions can disrupt concurrent sandbox flows (other engineers' tests, scheduled smoke tests, CI). Post in the team channel and pick an off-hours window.

3. Only after the hot check increments cleanly, flip `qurl_alerts_paused = false`.

If both checks fail to produce any series, the most likely cause is the qurl-service binary in sandbox is older than the metric introduction — verify the deployed image tag is ≥ the qurl-service commit that introduced `WebhookSuppressedReasonLookupFailed`.
