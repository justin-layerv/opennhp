# 2026-06-26 · PR #2808 · qURL v2 revocation-latency SLO + alarms

- **Owner:** prod rollout coordinator
- **Source:** [#2808](https://github.com/layervai/nhp/pull/2808) · gate [#2792](https://github.com/layervai/nhp/issues/2792) (+ [#2793](https://github.com/layervai/nhp/issues/2793))

Adds the `RevocationDeliveryLatency` histogram (NHP_REV emit -> AC NHP_RACK ack), a p99 < 15s SLO alarm, and a companion `RevocationAgedOut` non-delivery alarm. Both alarms key on `{Environment, Cell}` and are additive. Sample/ack data only exists once the revocation retry engine is armed.

- [ ] Rollout: applied by the normal prod promote terraform apply (additive — two new `aws_cloudwatch_metric_alarm` in `modules/monitoring`, no replacements/deletions). Verify the plan diff shows only `revocation_delivery_latency_high` + `revocation_aged_out` creations under the prod cell.
- [ ] Post-rollout: confirm both alarms exist and are `OK`/`INSUFFICIENT_DATA` (not erroneously `ALARM`): `<name_prefix>-<cell>-revocation-delivery-latency` and `<name_prefix>-<cell>-revocation-aged-out`. With the retry engine still OFF they should sit `INSUFFICIENT_DATA`/`OK` under `treat_missing_data="notBreaching"` (no samples yet) — that is expected, not a fault.
- [ ] Post-rollout (SLO DATA PRECONDITION): the histogram and aged-out signal are emitted **only** when `NHP_REVOCATION_RETRY_ENABLED=true` (the per-AC `firstSentAt` exists only with the engine armed). Until the fleet ships AC ack support (#2793) and the engine is flipped on, `RevocationDeliveryLatency` collects zero samples and the p99 alarm cannot fire. Arming the engine is gated separately — track there, not here; this entry only covers the alarms shipping inert-ready.
- [ ] Lockstep guard: the alarm threshold (15000 ms) mirrors `RevocationDeliveryLatencyP99SLO` (15s) in `endpoints/server/revocation_retry.go`. If either moves, move both in the same PR.
- [ ] Rollback: revert this PR (or remove the two alarm resources from `terraform/modules/monitoring/main.tf`) and apply — removes the alarms only; the Go-side metric recording is harmless to leave (no-op while the engine is OFF).
