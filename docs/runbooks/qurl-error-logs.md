# Runbook: qurl-api error log spike

## What fired

**`qurl-error-logs-spike`** — the rate of `slog.Error` log lines from `service_name="qurl-api"` in production exceeded `0.05 errors/sec` averaged over 5 minutes.

## What it means

The qurl-service is logging structured errors faster than the steady-state rate. This catches errors that may not become HTTP 5xx — examples: webhook delivery failures, billing reconciliation failures, background-worker panics that the recovery middleware caught and logged.

It overlaps with the [qurl-5xx](qurl-5xx.md) alert: most causes of a 5xx burn-rate alert will also produce error logs. If both alerts fire together, treat them as one incident and start with the 5xx runbook (which has the actionable diagnosis steps).

## When this fires alone (no 5xx)

Useful signals:
- **Webhook delivery failures**: search Loki for `{service_name="qurl-api"} |= "webhook delivery failed"`. Look for the customer's webhook URL — they may have rotated their endpoint and not updated the qurl webhook config.
- **Background reconciler errors**: search Loki for `{service_name="qurl-api"} |= "reconcile"`. The expiring-soon reconciliation worker logs errors when it can't write its gauge — usually a transient DynamoDB issue.
- **Audit log write failures**: search for `|= "audit"`. These are non-fatal (the audit log is best-effort) but a sustained spike means you're losing audit history, which is a compliance concern.

## First five minutes

1. Loki query: `{service_name="qurl-api", deployment_environment="prod"} | json | level="ERROR"` over the last 30 minutes. Look at the histogram of error counts to confirm the spike is real and ongoing.
2. Group by `msg`: `sum by (msg) (count_over_time({service_name="qurl-api", deployment_environment="prod"} | json | level="ERROR" [10m]))`. The top result tells you the dominant error.
3. Pick the dominant `msg` and read the structured fields — the qurl-service uses `slog.ErrorContext` which adds request_id, owner_id, resource_id where applicable. Trace the `request_id` in Tempo if you need the full request context.

## Mitigations

Same as [qurl-5xx](qurl-5xx.md). If the cause is a non-fatal background-worker error (e.g., webhook delivery), the mitigation may be "tell the customer to fix their webhook" rather than "roll back the deploy".

## Tuning notes

The threshold (`0.05/s`, ~3 errors/min) is a starting guess. Soak for a week; tighten if normal traffic produces a steady stream of expected errors (e.g., quota-exceeded warnings logged at ERROR when they should be WARN), or loosen if the rule fires on benign customer-input errors.

If a category of error log is genuinely benign and high-volume, the right fix is to **change the log level in the code from ERROR to WARN**, not to raise the alert threshold. Alert thresholds are downstream of code; code is the source of truth for severity.
