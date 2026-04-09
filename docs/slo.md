# Service Level Objectives — qurl-api

## Why this document exists

On 2026-03-24, every `POST /v1/qurls` in production returned HTTP 500 for over a week before any human noticed. The qurl-service had a fully built Grafana dashboard with `5xx Count`, `5xx Error Rate`, `Burn Rate (6h)` and `Burn Rate (3d)` panels — the panels were even labelled "page-level alert" and "ticket-level alert" in their descriptions — but **no Grafana alert rules existed behind them**. Burn-rate math is meaningless without a target. This document defines that target.

## Current SLO

| Service | Indicator | Objective | Window | Error budget |
|---|---|---|---|---|
| `qurl-api` | HTTP request availability — fraction of `http_server_request_duration_seconds_count` requests where `http_status_code` is not in 5xx | **99.99%** | 30 days | 4.32 minutes / 30 days |

### Scope

- **In:** the entire qurl-api HTTP surface — all routes under `service_name="qurl-api"`, `deployment_environment="prod"`. Aggregating across routes is intentional for the first iteration: it catches surges that affect any meaningful slice of traffic without per-route alert noise. Per-route SLOs can be layered on later.
- **Out:** intentional 4xx (validation failures, rate-limit responses, authentication failures). These are user errors, not service errors, and are not part of the availability budget.
- **Out for now:** latency. A latency SLO will be added in a follow-up. The dashboard already has p99 latency panels; the alert rules are HTTP-availability only for this iteration.

### Why 99.99%

The 2026-03-24 incident burned roughly 10,000× the entire 30-day budget for any reasonable target — the actual error rate was effectively 100% for the affected endpoint for >1 week. So the precise target value doesn't change whether that incident would page; any non-trivial SLO catches it. 99.99% is chosen because:

1. The dashboard's `slo_target` template variable already defaulted to `99.99` — adopting the same value keeps the dashboard panels and the alert rules in lockstep with no template-variable overrides.
2. Burn-rate math is scale-invariant in the ratios: a "page-level burn rate >6" alert fires at the same relative speed regardless of whether the SLO is 99.5% or 99.99%. The threshold ratios in `terraform/modules/grafana-dashboards/alerts.tf` work for any SLO.
3. 99.99% is industry-standard for highly-available infrastructure services and matches the bar customers paying for this product expect.

This is a starting target. We will revise it after a month of soak data and based on measured error budget consumption. If the budget is consistently exhausted by routine deploys / dependency hiccups, loosen the target. If the budget is consistently underused, tighten.

## Burn-rate alerting

Two alerts, both fired against the same SLO via the standard multi-window burn-rate pattern:

| Alert | Window | Threshold | Severity | Time to budget exhaustion at threshold |
|---|---|---|---|---|
| **5xx fast burn** | 6h | burn rate `> 6` | page | ~5 days at this rate |
| **5xx slow burn** | 3d | burn rate `> 1` | ticket | ~30 days at this rate |

Burn rate = `(error_rate_over_window) / (1 - SLO/100)`. A burn rate of 1 means we are spending exactly the budget over the measurement window. A burn rate of 6 means we are spending 6× faster — a 30-day budget will be exhausted in 5 days if the rate continues. The PromQL expressions live in `terraform/modules/grafana-dashboards/dashboards/qurl-operations.json` (lines 610 and 663) and are reused verbatim by the alert rules in `terraform/modules/grafana-dashboards/alerts.tf` so the dashboard and the alert can never drift.

Two additional, non-burn-rate rules supplement the burn-rate alerts:

- **Error log spike** — Loki rate of `slog.Error` lines from `service_name="qurl-api"` exceeding `0.05/s` for 5 minutes. Catches application-layer errors that may not become 5xx (background workers, webhook delivery failures).
- **DynamoDB query failures** — `aws_dynamodb_operation_total` failures filtered to `qurl-resources` Query operations. This is the specific signal that would have caught the 2026-03-24 GSI removal incident in under 5 minutes; it lives in this layer because the qurl-service's own DynamoDB instrumentation has tighter granularity than the AWS-side `UserErrors` CloudWatch metric (which is too noisy due to `ConditionalCheckFailedException` from normal `attribute_not_exists` checks).

## Runbooks

Each alert links to a runbook in `docs/runbooks/`:

- [qurl-5xx.md](runbooks/qurl-5xx.md) — fast and slow 5xx burn-rate alerts
- [qurl-error-logs.md](runbooks/qurl-error-logs.md) — `slog.Error` log spike alert
- [qurl-dynamodb-query-failures.md](runbooks/qurl-dynamodb-query-failures.md) — DynamoDB Query failure alert

No alert ships without a runbook URL in `annotations.runbook_url`.

## Soak protocol

New alert rules ship with `is_paused = true`. After deployment:

1. Watch the rule's "would-have-fired" count in Grafana for 24 hours.
2. Tune thresholds if obvious noise is observed.
3. Flip `var.qurl_alerts_paused = false` and re-apply terraform.

This prevents day-1 alert fatigue — the most common reason new alerting initiatives die.
