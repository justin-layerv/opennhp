# 2026-06-06 · PR #2329 · Custom-domain renewal alarm aggregation

- **Owner:** prod rollout coordinator
- **Source:** [#2329](https://github.com/layervai/nhp/pull/2329)

Adds custom-domain cert renewal-scan + heartbeat alarms and smoke IAM/test wiring. Not yet in prod: promoted through the normal prod promote flow.

- [ ] Rollout: promote the custom-domain cert Lambda, renewal-scan alarms, heartbeat alarm, and smoke IAM/test wiring through the normal prod promote flow.
- [ ] Post-rollout: watch `layerv-nhp-prod-cert-renewal-scan-missing` — acknowledge a one-time first-deploy/replacement page if it fires before the first heartbeat datapoint; wait one scan interval; escalate if not cleared within an hour or it re-enters ALARM after OK.
- [ ] Post-rollout: confirm `RenewalScanRuns` publishes for `Environment=prod` + prod `CellID` and the three renewal count alarms move to OK (or an expected datapoint-backed ALARM). If the heartbeat alarm fires alongside Lambda Errors, treat it as a telemetry publish outage first — inspect cert Lambda logs before any customer DNS cleanup.
- [ ] Rollback: roll back the cert Lambda/alarm Terraform to the prior release if telemetry can't be stabilized (old scheduled-renewal failure signals return until recovered).
- [ ] Follow-up: [#2379](https://github.com/layervai/nhp/issues/2379) — scale the scheduled renewal scanner for thousands of certs.
