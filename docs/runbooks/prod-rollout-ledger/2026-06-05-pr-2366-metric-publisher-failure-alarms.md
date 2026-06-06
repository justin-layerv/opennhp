# 2026-06-05 · PR #2366 · Metric publisher failure alarms

- **Owner:** prod rollout coordinator
- **Source:** [#2366](https://github.com/layervai/nhp/pull/2366) · [#1707](https://github.com/layervai/nhp/issues/1707)

Adds additive CloudWatch alarms on AC/server metric-publisher failures. Not yet in prod: applies through the normal promote pipeline.

- [ ] Post-rollout: after the apply creating `${name_prefix}-ac-publisher-failures` and `${name_prefix}-${cell_id}-server-publisher-failures`, confirm both settle in `OK` and NOT `INSUFFICIENT_DATA` (the latter = alarm dim set doesn't match the live publisher's emitted dims; audit `dimensions {}` against `acBaseDims` / `buildServerMetricDimensions`).
- [ ] Post-rollout (optional): temporarily revoke `cloudwatch:PutMetricData` on a sandbox AC/server and confirm `PublisherFailures` increments and the alarm transitions to `ALARM`.
- [ ] Rollback: alarms are purely additive — `terraform apply` of the revert removes them; the Go counter is inert when no batch fails.
