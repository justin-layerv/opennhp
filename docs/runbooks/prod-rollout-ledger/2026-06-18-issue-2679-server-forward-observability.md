# 2026-06-18 · issue #2679 · Server forward-send observability

- **Owner:** prod rollout coordinator
- **Source:** [#2679](https://github.com/layervai/nhp/issues/2679) · [PR #2673](https://github.com/layervai/nhp/pull/2673) · [PR #2693](https://github.com/layervai/nhp/pull/2693)

Adds additive CloudWatch visibility for two zero-baseline NHP server signals:
`ServerForwardTargetDrop` and async `ErrRuntimePanic` recoveries from
`msgToPacketRoutine`. Applies through the normal promote pipeline; no protocol
path changes are included.

- [ ] Post-rollout: confirm `${name_prefix}-${cell_id}-server-forward-target-drop`
      exists, routes to the NHP server alerts SNS topic, and selects
      `LayerV/NHP` metric `ServerForwardTargetDrop` with dimensions
      `{Environment, Cell}`.
- [ ] Post-rollout: confirm `${name_prefix}-${cell_id}-server-async-runtime-panic`
      exists, routes to the NHP server alerts SNS topic, and is fed by the
      `server-async-runtime-panic` metric filter on the structured server log
      group (`/layerv/nhp/<env>/<cell>/server`).
- [ ] Post-sandbox rollout: before prod promotion, confirm a real or injected
      structured `msgToPacketRoutine` recovery log event increments
      `ServerAsyncRuntimePanic-<env>-<cell>`.
- [ ] Post-rollout: confirm the "Server Forward Safety"
      dashboard widget renders both zero-baseline signals for the prod cell.
- [ ] Rollback: alarms, metric filter, dashboard widget, and runbook are purely
      additive; `terraform apply` of the revert removes them.
