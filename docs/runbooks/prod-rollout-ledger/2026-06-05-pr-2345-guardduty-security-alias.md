# 2026-06-05 · PR #2345 · GuardDuty security alias + triage-runbook links

- **Owner:** prod rollout coordinator
- **Source:** [#2345](https://github.com/layervai/nhp/pull/2345) · [#2334](https://github.com/layervai/nhp/issues/2334)

Adds `security@layerv.ai` to `guardduty_alert_emails` and wires the triage-runbook link into alerts. Not yet in prod: applied via prod promote, then a manual SNS confirmation click.

- [ ] Rollout: prod apply adds an `email` subscription on `layerv-nhp-prod-guardduty-email` (starts `PendingConfirmation` — no blackout, existing subscribers + Slack keep delivering). Confirm via `aws sns list-subscriptions-by-topic ... --query "Subscriptions[?Endpoint=='security@layerv.ai'].SubscriptionArn"` (a `PendingConfirmation` value = link unclicked; click it from the alias inbox). The EventBridge input-transformer change + watchdog `TRIAGE_RUNBOOK_URL` need no manual step.
- [ ] Post-rollout: confirm the next real or synthetic GuardDuty alert (email + Slack) carries the link to `docs/runbooks/guardduty-finding-triage.md` (GuardDuty console → Settings → generate sample findings; archive the samples afterward so the stale-finding watchdog doesn't re-alert).
- [ ] Rollback: revert the PR (remove the alias + runbook-link additions) and re-apply — deletes the SNS subscription, no data migration; a leftover pending/confirmed subscription is harmless.
- [ ] Follow-ups: sandbox carries the same `security@layerv.ai` subscription on `layerv-nhp-sandbox-guardduty-email` (applied on merge) and also needs one confirmation click; [#2334](https://github.com/layervai/nhp/issues/2334) stays open for lower-priority items (severity-tiered SNS topics, dedicated security Slack channel; pager-escalation is won't-do — watchdog is the compensating control).
