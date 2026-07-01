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

- [ ] Pre-rollout: confirm the deployed AC image includes the `NHP_RVA` ack path (`RevocationAckSent` exists in AC metrics/logs, or the image tag is at/after this code) before refreshing servers. A pre-ACK AC fleet will correctly age out every revoke.
- [ ] Pre-rollout: confirm prod and sandbox have no blank/whitespace AC assignment ids and no recent empty-`ACId` registration logs. Blank AC ids are untrackable proof targets.
- [ ] Rollout: apply Terraform normally. Expect server launch-template user data to change and the server ASG refresh/deploy path to roll the fleet. The change is config-only; no new IAM/resource creation should be needed beyond launch-template/user-data churn.
- [ ] Rollout sequence: let the normal merge-time sandbox deploy arm first and soak before running the prod promote. Do not intentionally arm sandbox and prod simultaneously; a pre-ACK prod AC fleet will produce `RevocationAgedOut` for every targeted revoke until the AC image is corrected.
- [ ] Post-rollout: on one fresh server instance per environment, confirm `/opt/layerv/nhp-server/etc/env` contains the three `NHP_REVOCATION_RETRY_*` variables with `true`, `5`, and `60`.
- [ ] Post-rollout: trigger or observe a qURL v2 revoke and verify server logs show the retry engine enabled at boot plus either `RevocationAckReceived` / `RevocationDeliveryLatency` for delivered revokes or `RevocationAgedOut` for genuinely unproven slots.
- [ ] Post-rollout: update any saved log searches or dashboards that grep the former revocation-ack display mnemonic to `NHP_RVA`. The `RevocationAck*` metric names and alarms are unchanged; this is only a log/display-string rename.
- [ ] Alarm triage: a nonzero `RevocationAgedOut` after this flip is not a cosmetic warning; it means a revoke target was not proven delivered. Correlate blue/green drain overlap first, then treat non-deploy age-outs as immediate-revocation delivery failures.
- [ ] Rollback: set `nhp_revocation_retry_enabled=false` in the affected env or revert this PR and re-apply/refresh servers. This restores fire-and-forget NHP_REV delivery and should block relying on immediate revocation in prod until re-enabled.
