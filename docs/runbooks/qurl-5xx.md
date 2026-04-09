# Runbook: qurl-api 5xx burn rate

## What fired

One or both of:

- **`qurl-5xx-fast-burn`** — 6-hour error budget burn rate exceeded 6× sustainable. At this rate, 30 days of error budget are spent in ~5 days.
- **`qurl-5xx-slow-burn`** — 3-day error budget burn rate exceeded 1× sustainable. At this rate, 30 days of error budget are spent in ~30 days.

Both alerts publish to the same SNS topic the rest of prod alerts use, so you'll see them in the usual email/Slack channel.

## What it means

A meaningful fraction of `POST /v1/qurls`, `GET /v1/qurls/...`, `POST /v1/resolve`, or other qurl-api requests are returning 5xx. The aggregate alert does not tell you *which* endpoint — that's the first thing to check.

## First five minutes

1. Open the **QURL Operations** dashboard in Grafana Cloud. The "5xx by Endpoint" panel (around line 860 of the dashboard JSON) shows the top 10 routes by error rate. This identifies the affected endpoint immediately.
2. Open the **Tempo** trace explorer for `service_name="qurl-api", http.status_code=~"5.."` over the last 15 minutes. Pick a sample failing trace and follow it down to the actual error.
3. In Loki, query `{service_name="qurl-api", deployment_environment="prod"} | json | level="ERROR"` over the last 30 minutes. Look for repeated error messages — repetition is the signal.

## Common causes

| Pattern in logs | Likely cause | Action |
|---|---|---|
| `failed to query <some>-index` repeated | Missing/changed DynamoDB GSI (the 2026-03-24 incident class) | Check `terraform/modules/dynamodb/main.tf` git log for recent GSI changes; check the `qurl-schema-compat` workflow job log for the last promote-to-prod run; consider rolling back terraform |
| `dynamodb: throttled` or `ProvisionedThroughputExceededException` | DynamoDB capacity exhaustion | Check the `dynamodb_throttled_*` CloudWatch alarms (already wired); consider raising on-demand capacity or burst limits |
| `auth0: jwks fetch failed` | Auth0 JWKS endpoint outage or local cache eviction | Check Auth0 status page; check Auth0 outbound firewall from prod ECS task |
| `redis: connection refused` or `redis: i/o timeout` | Redis (idempotency cache) outage | Check ElastiCache cluster health |
| `geoip: lookup failed` and steady error rate | GeoIP database missing or corrupt | Check `/health/ready` for the geoip subcheck; the service should still serve requests but with degraded GeoIP enrichment |
| Errors only on `POST /v1/qurls` | Resource-creation path broken (like the 2026-03-24 incident) | Run `qurl-api schema-check --plan plan.json` against the most recent prod terraform plan if you have it; otherwise check for recent terraform applies via `gh run list -R layervai/nhp -w promote-to-prod.yml --limit 5` |

## Mitigations (in order of preference)

1. **Roll back the offending change.** If a deploy in the last hour correlates with the spike, rolling that deploy back is almost always faster than diagnosing the bug.
   - Code rollback: trigger `promote-to-prod.yml` with `rollback=true` and the previous qurl-service image tag.
   - Terraform rollback: identify the offending resource change in the most recent terraform plan and revert via a new PR (terraform doesn't have a one-click rollback).
2. **Scale up the ECS service** if the cause is capacity rather than bug.
3. **Disable the affected endpoint** at the ALB or via a feature flag if the bug is isolated. This is rarely the right call — usually rollback is faster.

## After the fact

- File a post-incident artifact in `docs/incidents/` (template TBD) with the timeline, the root cause, the customer impact, and any tooling/alerting gaps surfaced.
- If a tooling gap was surfaced — e.g., a new alert that should have fired earlier — open a follow-up issue and link it to the incident artifact.

## Why this alert is wired this way

The 2026-03-24 incident produced a steady 100% error rate on `POST /v1/qurls` for over a week and **nothing fired**. The Grafana dashboard had 5xx panels but no alert rules behind them. The fix in this PR is to add the rules. The rules ship paused for 24h to soak before going live; if you are reading this runbook because the rule actually fired, the soak protocol worked.
