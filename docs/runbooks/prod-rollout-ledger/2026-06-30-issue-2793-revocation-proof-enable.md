# 2026-06-30 · Issue #2793 · arm qURL v2 revocation proof engine

- **Owner:** prod rollout coordinator
- **Source:** [#2793](https://github.com/layervai/nhp/issues/2793)

Arms the NHP server's qURL v2 revocation proof engine in Terraform-managed
sandbox/prod fleets by rendering `NHP_REVOCATION_RETRY_ENABLED=true`,
`NHP_REVOCATION_RETRY_INTERVAL_SECONDS=5`, and
`NHP_REVOCATION_RETRY_AGE_OUT_SECONDS=60` into the server env file. The Go
binary remains absent-env default-OFF for unmanaged/pre-ACK fleets, but managed
fleet revokes now retry `NHP_REV` until each targeted live AC slot sends
`NHP_RVA` or ages out to `RevocationAgedOut`.

Issue #2868's arm-time decision is alarm tuning, not pruning: the server keeps
pending proof entries through ordinary disconnects, UDP loss, and unknown AC
drops because it has no AC-side decommission proof that the exact targeted slot
can no longer host the revoked flow. The raw `revocation-aged-out` alarm stays
`Sum >= 1`; paging goes through `revocation-aged-out-page`, a composite that
requires raw age-out outside a recent roughly 10-minute `{Environment, Cell}`
`DeploymentWindow` emitted by server/AC deploy workflows and refreshed while
long ASG/canary rollout polls are still active. The no-action
`revocation-aged-out-suppressed` composite is an operator breadcrumb for raw
age-outs observed while the deploy suppressor is active.

- [ ] Pre-rollout: confirm the deployed AC image includes the `NHP_RVA` ack path (`RevocationAckSent` exists in AC metrics/logs, or the image tag is at/after this code) before refreshing servers. A pre-ACK AC fleet will correctly age out every revoke.
- [ ] Pre-rollout: confirm prod and sandbox have no blank/whitespace AC assignment ids and no recent empty-`ACId` registration logs. Blank AC ids are untrackable proof targets.
- [ ] Rollout: apply Terraform normally. Expect server launch-template user data to change and the server ASG refresh/deploy path to roll the fleet. The change is config-only; no new IAM/resource creation should be needed beyond launch-template/user-data churn.
- [ ] Rollout sequence: let the normal merge-time sandbox deploy arm first and soak before running the prod promote. Do not intentionally arm sandbox and prod simultaneously; a pre-ACK prod AC fleet will produce `RevocationAgedOut` for every targeted revoke until the AC image is corrected.
- [ ] Post-rollout: on one fresh server instance per environment, confirm `/opt/layerv/nhp-server/etc/env` contains the three `NHP_REVOCATION_RETRY_*` variables with `true`, `5`, and `60`.
- [ ] Post-rollout: trigger or observe a qURL v2 revoke and verify server logs show the retry engine enabled at boot plus either `RevocationAckReceived` / `RevocationDeliveryLatency` for delivered revokes or `RevocationAgedOut` for genuinely unproven slots.
- [ ] Post-rollout: confirm the revocation age-out alarm shape is armed as intended: `<name_prefix>-<cell>-revocation-aged-out` exists as the no-action raw detector, `<name_prefix>-<cell>-revocation-deploy-window` exists as the no-action deploy suppressor, `<name_prefix>-<cell>-revocation-aged-out-suppressed` exists as the no-action suppressed-event breadcrumb, and `<name_prefix>-<cell>-revocation-aged-out-page` is the SNS-backed paging alarm.
- [ ] Post-rollout: update any saved log searches or dashboards that grep the former revocation-ack display mnemonic to `NHP_RVA`. The `RevocationAck*` metric names and alarms are unchanged; this is only a log/display-string rename.
- [ ] Alarm triage: a nonzero raw `RevocationAgedOut` after this flip is not a cosmetic warning; it means a revoke target was not proven delivered. If it occurs during the recent deploy window after the latest deploy heartbeat, the deploy-window composite suppresses paging while keeping the raw signal visible for audit; `<name_prefix>-<cell>-revocation-aged-out-suppressed` records that raw+window overlap as a no-action breadcrumb. A transient deploy-window age-out is not queued for a later page unless the raw detector remains or repeats after the suppressor clears. `DeploymentWindow` is trust-on-emit in the shared `LayerV/NHP` namespace, so any principal with namespace-scoped `PutMetricData` access, including server instances that publish the raw revocation signal, can emit it; hardening that trust boundary is tracked in [#2974](https://github.com/layervai/nhp/issues/2974). If `<name_prefix>-<cell>-revocation-aged-out-page` fires, treat it as a non-deploy immediate-revocation delivery failure outside the deploy suppressor.
- [ ] Rollback: set `nhp_revocation_retry_enabled=false` in the affected env or revert this PR and re-apply/refresh servers. This restores fire-and-forget NHP_REV delivery and should block relying on immediate revocation in prod until re-enabled.
