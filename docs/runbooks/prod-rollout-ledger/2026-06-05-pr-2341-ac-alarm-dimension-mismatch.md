# 2026-06-05 · PR #2341 · AC alarm dimension-mismatch fix

- **Owner:** prod rollout coordinator
- **Source:** [#2341](https://github.com/layervai/nhp/pull/2341) · [issue #968](https://github.com/layervai/nhp/issues/968)

Repoints three silently-non-functional AC alarms (`registration_failure`, `server_connection_failure`, `disk_usage_high`) at a base `{Component, Environment, Region}` metric stream and drops `InstanceId` from `disk-monitor.sh`. Not yet in prod: standard apply, verification is the whole point.

- [ ] Rollout: standard `terraform apply` recreates the three alarms with corrected dimension sets (no ordering). The `disk-monitor` SSM doc changes; the next scheduled association run (30-min cadence) first publishes `DiskUsagePercent` at `{Component=AC}` (no `InstanceId`).
- [ ] Post-rollout: confirm the Go base-dim publish exists in prod — `aws cloudwatch list-metrics --namespace LayerV/NHP --metric-name RegistrationSuccess` returns a stream with dims exactly `{Component=AC, Environment=prod, Region=<prod-region>}`; confirm `DiskUsagePercent` has a `{Component=AC}` stream and NO `InstanceId` stream after the disk-monitor association re-runs.
- [ ] Post-rollout: confirm the three alarms reach `OK`/`ALARM` (not historical permanent-`OK`-on-no-data) — Tier 1 smoke `TestACAlarms_DimensionsMatchPublisher` + `TestACAlarms_PublisherStreamsExistForAlarmDims` assert the contract in the promote-to-prod smoke leg.
- [ ] Post-rollout (calibration): `server_connection_failure` has no transport-drop exclusion — it feeds on timeouts during a server blue/green flip, AC instance refresh, and ~90s NLB re-registration. Confirm neither the first sandbox flip nor a fleet refresh pushes >10 `ServerConnectionFailure` across two 5-min windows; raise threshold/`evaluation_periods` if it cry-wolfs. Thresholds (5/10) are fleet-wide `Sum` (no `ACId`), so a capacity bump is a re-calibration trigger; all three are unvalidated.
- [ ] Post-rollout: day-1 option — coordinator MAY stage `server_connection_failure` (and optionally `registration_failure`) with SNS removed / a high initial threshold until the first sandbox flip, then dial in. Confirm the 10-min `registration_stale` window is acceptable as the sole all-timeout outage detector (timeout-classified registration errors now drop off `registration_failure`).
- [ ] Rollback: revert the PR and re-apply — alarms return to prior dimension sets; harmless (they were already non-functional, no monitoring lost vs the pre-PR baseline).
- [ ] Follow-up: [#946](https://github.com/layervai/nhp/issues/946) — separate `ServersHealthy` gauge work, out of scope.
