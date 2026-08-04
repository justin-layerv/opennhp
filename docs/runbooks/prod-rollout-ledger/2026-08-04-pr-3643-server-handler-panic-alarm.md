# 2026-08-04 · PR #3643 · Server handler-panic observability

- **Owner:** prod rollout coordinator
- **Source:** [PR #3643](https://github.com/layervai/nhp/pull/3643) · upstream OpenNHP `94a5ff67`
- **Related:** [issue #2679](https://github.com/layervai/nhp/issues/2679) / [PR #2673](https://github.com/layervai/nhp/pull/2673) — the `msgToPacketRoutine` sibling this mirrors

PR #3643 wraps each `dispatchHandler` goroutine in a `recover()`, so a panic in
a knock/register/list handler degrades to a dropped request instead of killing
the process. That **removes** this class from the existing stderr `"panic:"`
detector (`server_panic`) — there is no crash left to observe. The PR adds
`server_handler_panic` (metric filter + alarm on the structured server log
group) to replace the lost signal. Additive infra; no protocol path changes.

Until this applies, a recovered handler panic in a deployed cell is **silent**:
the code change ships with the app image, the detector ships with Terraform.

- [ ] Rollout: apply Terraform **before or with** the server image carrying the
      recover. An image-first rollout leaves a window where handler panics are
      recovered but unalarmed.
- [ ] Post-rollout: confirm `${name_prefix}-${cell_id}-server-handler-panic`
      exists, routes to the NHP server alerts SNS topic, and is fed by the
      `server-handler-panic` metric filter on the structured server log group
      (`/layerv/nhp/<env>/<cell>/server`).
- [ ] Post-sandbox rollout, **before prod promotion**: prove the filter actually
      matches. Alarm state is not evidence — `treat_missing_data =
      "notBreaching"` means a filter whose pattern never matches sits in a
      permanently green `OK`, indistinguishable from a healthy one. Drive a real
      or injected structured `dispatchHandler` recovery log event and confirm it
      increments `ServerHandlerPanic-<env>-<cell>`. The two AND-matched terms
      are `dispatchHandler` and `runtime panic encountered`; record the log
      event and the datapoint.
- [ ] Post-rollout: confirm the "Server Forward Safety" dashboard widget renders
      the new `Handler Panic Recovery` series alongside the existing two.
- [ ] Pre-rollout: **on-call acknowledgement of the paging profile.** The alarm
      sets `ok_actions`, matching both sibling panic alarms
      (`server_async_runtime_panic`, and the AC's `udp_handler_panic`), because
      the OK transition is what re-arms paging — without it a recurring panic
      latches ALARM and never pages again. The cost is that a *sustained*
      remote-triggerable panic flaps and pages on both edges, ~2 notifications
      per 5-minute cycle for as long as it continues. That is intended for a
      zero-baseline security signal, but on-call should know it before it
      happens, not during. If it ever needs damping, suppress at the
      notification layer — dropping `ok_actions` would stop the re-paging that
      makes a recurring panic visible.

      Log volume under the same sustained trigger is bounded by construction:
      the recovery emits the alarm-bearing line every time (so
      `ServerHandlerPanic` counts every occurrence) but carries a full
      `debug.Stack()` at most once per minute, with the suppressed count
      reported on the next stack-bearing line. Without that cap, a
      packet-rate attacker-reachable panic would write a multi-KB stack per
      packet and turn a correctness bug into unbounded ingestion cost. The
      one-minute interval is deliberately shorter than the alarm's 5-minute
      period, so every window that fires still has a stack to triage from.
- [ ] Rollback: alarm, metric filter, and dashboard series are purely additive;
      `terraform apply` of the revert removes them. Reverting the Terraform
      **without** reverting the server image re-opens the silent window above.
