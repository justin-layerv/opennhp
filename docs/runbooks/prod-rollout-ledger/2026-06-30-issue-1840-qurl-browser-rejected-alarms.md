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

The #2924 activation review hardened the alarm before the bake: the ratio is now
gated on a minimum-volume floor
(`local.qurl_browser_rejected_min_resolve_attempts`, default 20) so a tiny
denominator cannot breach, and the `datapoints_to_alarm=3` false-negative and `ok_actions`
questions are decided in the resource comment (accept 3-of-3 sustained-only
paging; keep OK recovery notifications). The flip itself stays gated on the bake.

- [ ] Rollout: apply through the normal prod promote Terraform path. Verify the plan creates only the two `aws_cloudwatch_metric_alarm.qurl_browser_rejected_ratio` instances under `terraform/modules/monitoring`.
- [ ] Post-rollout: confirm both alarms exist, select `LayerV/NHP` with `{Environment, Cell}`, and show `ActionsEnabled=false` during the bake. Alarm descriptions must reference `endpoints/server/msghandler.go::QurlResolveBrowser*` and describe rejected fields per resolve attempt, not percent of requests. Confirm the applied `ratio` expression gates on `resolve_attempts >= local.qurl_browser_rejected_min_resolve_attempts` (currently 20, the min-volume floor), not the pre-#2924 `resolve_attempts > 0`.
- [ ] Post-rollout bake (after 7 days):
  - Compare each alarm's `ratio` against the 2026-06-30 baseline (sandbox max 5m ratio: malformed 0.154, out-of-range 0.231; prod max 0), and confirm the ratio still moves under an intentional forged-timing burst even when `QurlResolveFailValidate` traffic is present.
  - Verify true zero-traffic windows remain empty/notBreaching and publisher liveness stays covered by `server_publisher_failures` / `server-cloudmap-register-refresh-heartbeat`.
  - Validate the `local.qurl_browser_rejected_min_resolve_attempts` floor (default 20) against the per-cell 5-minute `resolve_attempts` distribution — capture percentiles (p50/p95), not just the max ratio, because the floor is only defensible if quiet cells routinely clear it. Raise it if sandbox routinely breaches on windows just above the floor; lower it if a real-traffic cell sits below the floor per 5m, since it then blinds a low-rate sustained forgery (each forged request adds up to six to the numerator but only +1 to the denominator, so at the default 20 a cell seeing e.g. 3 forged attempts per 5m reads 0 under the floor and never pages).
  - Record the CloudWatch per-referenced-metric alarm cost impact before enabling this across more cells; each alarm already uses 8 of CloudWatch's 10 `MetricStat` slots plus 2 of its 10 `Expression` slots (10 of 20 total `MetricDataQuery` entries).
  - The `datapoints_to_alarm=3` sustained-only false-negative and the `ok_actions` keep/remove questions are already decided in the resource comment (accept sustained-only paging; keep OK recovery notifications) — only re-open them if the bake contradicts those calls.
- [ ] Flip (in the [#2924](https://github.com/layervai/nhp/issues/2924) follow-up config PR):
  - **Hard gate (enforce per environment):** every real-traffic cell's p50 `resolve_attempts` must clear the floor in *each* environment — sandbox clearing it says nothing about prod, whose 2026-06-30 baseline had zero rejected datapoints and may run far fewer than 20 resolve attempts per 5m. Otherwise lower the floor or scope it per-cell, so the alarm is not silently disabled in a cell where forgery would matter.
  - Record the observed per-cell p50/p95 `resolve_attempts` in that PR so the "floor is defensible" decision is auditable rather than asserted. If a cell cannot clear the floor, per-cell scoping (or a raw-counter tripwire alarm for quiet cells) is the natural follow-up.
  - When no non-test traffic exceeds the 0.20 / 0.30 thresholds for three consecutive 5m periods and the hard gate holds, flip `qurl_browser_rejected_alarm_actions_enabled=true` and close #2924.
- [ ] Rollback: revert this PR or remove the two alarm resources. The Go-side rejected counters already exist and are safe to leave emitting while the alarms are removed.
