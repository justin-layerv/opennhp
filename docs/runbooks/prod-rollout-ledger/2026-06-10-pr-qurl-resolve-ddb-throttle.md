# 2026-06-10 · QURL resolve-path DDB throttle alarms (#1912)

- **Owner:** prod rollout coordinator (**qurl-service owner must confirm the table set** — see below)
- **Source:** PR (this), [#1912](https://github.com/layervai/nhp/issues/1912)

Adds **5** page-severity DynamoDB throttle alarms (`ReadThrottleEvents`+`WriteThrottleEvents`
FILL metric-math, `{TableName}`) for the inferred customer-resolve-path QURL tables
(`qurl-resources`, `qurl-access-tokens`, `qurl-sessions`, `qurl-access-codes`,
`qurl-domains`), extending the existing `qurl-api-keys` / `qurl-agent-keys` alarms in
`modules/dynamodb/alarms.tf`. Plan: **5 to add, 0 change, 0 destroy** (the two existing
alarms are untouched).

- [ ] **Pre-merge (gating decision):** the alarmed table set is *inferred* from table semantics, not measured traffic. The qurl-service owner confirms/corrects it in PR review before merge (which resolve-path tables warrant a page; whether any excluded write/idempotency table should be added).
- [ ] Rollout: validate in sandbox first (applies on merge to main), then promote to prod with `run_terraform=true`.
- [ ] **Expected first-apply noise (not an incident):** the 5 fresh alarms transition `INSUFFICIENT_DATA → OK` and fire `ok_actions`, so the alarm SNS topic (Chatbot/Slack + email) gets ~5 OK notifications at once on the first apply per env. Expected — same as any new-alarm batch.
- [ ] Post-rollout: confirm the 5 `*-throttle` alarms settle in `OK` (no throttling at steady state) — `aws cloudwatch describe-alarms --alarm-name-prefix "layerv-nhp-prod-<cell>-qurl-" | grep throttle`.
- [ ] Rollback: revert the PR (removes the 5 alarms); no data impact, no migration.
