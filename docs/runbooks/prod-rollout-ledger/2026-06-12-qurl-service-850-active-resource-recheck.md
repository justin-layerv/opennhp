# 2026-06-12 · qurl-service #850 · Active-resource recheck scheduler

- **Owner:** prod rollout coordinator
- **Source:** [layervai/qurl-service#850](https://github.com/layervai/qurl-service/issues/850) · [#2486](https://github.com/layervai/nhp/issues/2486)

Adds the hourly qurl-scanner active-resource recheck Lambda, EventBridge rule,
IAM, and alarms. Apply only after qurl-service has published a scanner image
that supports `active-resource-recheck`.

- [ ] Pre-rollout: confirm the scanner image-tag SSM parameter points at a qurl-service SHA that includes `QURL_SCANNER_SCAN_MODE=active-resource-recheck`, root event `scan_mode` support, and the real-run guard requiring tombstone-write for active rechecks.
- [ ] Pre-rollout: confirm reserved-concurrency headroom before prod/non-trivial-cell enablement; the scanner pair reserves two Lambda concurrency slots per qurl-service cell once active recheck is enabled.
- [ ] Rollout: apply this NHP Terraform change in sandbox before prod with `qurl_scanner_tombstone_write_enabled=false` and `qurl_scanner_active_recheck_enabled=false`; the active-recheck scheduler must remain absent until SQS emit/consumer is active and the tombstone-write phase has burned in.
- [ ] Rollout: after SQS emit/consumer burn-in is healthy, flip `qurl_scanner_tombstone_write_enabled=true` while keeping `qurl_scanner_active_recheck_enabled=false`; this turns on tombstone writes for the existing per-minute expiry scanner without starting the broad status-index sweep.
- [ ] Rollout: after per-minute tombstone-write burn-in is healthy and qurl-service #919 hard gates show active count and `Duration` fit the cell, flip `qurl_scanner_active_recheck_enabled=true`. Confirm the new Lambda has independent reserved concurrency and the hourly EventBridge target input keeps `scan_mode` at the JSON root; expect the invocation-gap alarm to start in ALARM for up to 2 hours, so suppress or stage SNS wiring accordingly.
- [ ] Post-rollout: confirm the active-recheck invocation-gap and errors alarms are OK, and CloudWatch Logs show `active_resource_recheck.scanned` plus `close.sessions_active` / `close.closed` counters.
- [ ] Post-rollout: watch active-recheck `Duration`, memory, and qurl-resources read volume on the first sandbox runs; this pass shares the scanner memory setting but scans a different `status-index` workload.
- [ ] Rollback: revert/apply this PR or disable the active-recheck EventBridge rule while reverting; leave the per-minute expiry scanner enabled unless the broader scanner rollout itself is being rolled back.
