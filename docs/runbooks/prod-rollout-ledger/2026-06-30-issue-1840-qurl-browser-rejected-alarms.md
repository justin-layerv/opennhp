# 2026-06-30 · issue #1840 · qURL browser rejected timing alarms

- **Owner:** prod rollout coordinator
- **Source:** [#1840](https://github.com/layervai/nhp/issues/1840) · activation follow-up [#2924](https://github.com/layervai/nhp/issues/2924)

Adds two additive CloudWatch metric-math alarms for the nhp-server qURL browser
timing rejected counters:
`${name_prefix}-${cell_id}-qurl-browser-rejected-malformed-ratio` and
`${name_prefix}-${cell_id}-qurl-browser-rejected-out-of-range-ratio`. They key
on the server publisher's `{Environment, Cell}` dim set and start report-only
with `actions_enabled=false` while the rejected-fields-per-resolve-attempt
thresholds bake.

- [ ] Rollout: apply through the normal prod promote Terraform path. Verify the plan creates only the two `aws_cloudwatch_metric_alarm.qurl_browser_rejected_ratio` instances under `terraform/modules/monitoring`.
- [ ] Post-rollout: confirm both alarms exist, select `LayerV/NHP` with `{Environment, Cell}`, and show `ActionsEnabled=false` during the bake. Alarm descriptions must reference `endpoints/server/msghandler.go::QurlResolveBrowser*` and describe rejected fields per resolve attempt, not percent of requests.
- [ ] Post-rollout bake: after 7 days, compare each alarm's `ratio` expression against the 2026-06-30 baseline (sandbox max 5m ratio: malformed 0.154, out-of-range 0.231; prod max 0). Confirm the ratio still moves under an intentional forged-timing burst even when `QurlResolveFailValidate` traffic is present, evaluate whether low-traffic windows need a minimum `resolve_attempts` floor before paging, verify true zero-traffic windows remain empty/notBreaching, and confirm publisher liveness remains covered by `server_publisher_failures` / `server-cloudmap-register-refresh-heartbeat`. Record the CloudWatch per-referenced-metric alarm cost impact before enabling this across more cells, and note that each alarm already uses 8 of CloudWatch's 10 `MetricStat` slots plus 2 of its 10 `Expression` slots (10 of 20 total `MetricDataQuery` entries). Decide whether the currently wired `ok_actions` recovery notifications should stay enabled or be removed before flipping actions on. If no non-test traffic exceeds the 0.20 / 0.30 thresholds for three consecutive 5m periods and the minimum-denominator / OK-notification decisions are recorded, flip `qurl_browser_rejected_alarm_actions_enabled=true` in the [#2924](https://github.com/layervai/nhp/issues/2924) follow-up config PR and close that issue.
- [ ] Rollback: revert this PR or remove the two alarm resources. The Go-side rejected counters already exist and are safe to leave emitting while the alarms are removed.
