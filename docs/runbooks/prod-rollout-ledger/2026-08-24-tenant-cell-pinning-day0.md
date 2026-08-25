# 2026-08-24 · Tenant home-cell pinning — sandbox activation + prod day-0

- **Owner:** prod rollout coordinator
- **Source:** this PR · [qurl-service tenancy-pinning B6 ledger](https://github.com/layervai/qurl-service/blob/main/docs/runbooks/prod-rollout-ledger/2026-08-05-pr-1351-tenancy-pinning-b6.md) (its deferred step 3)

The pin store (`CONNECTOR_AUTHORITY_TENANT_PINNING_ENABLED`) already ships in
qurl-service; this PR gives it a Terraform lever and commits it on in both
Control roots. Sandbox activates on the next control deploy after merge; prod
carries `true` as the day-0 bootstrap value so tenants are pinned from the
first assignment ever issued and no backfill migration exists later. With one
assignable cell the pin is a no-op at placement time — the value it buys is
entirely at the moment a second cell becomes assignable.

- [ ] Post-merge (sandbox): after the control deploy applies, read the
      IssueAssignment function env and confirm
      `CONNECTOR_AUTHORITY_TENANT_PINNING_ENABLED=true` plus the
      `TenantCellPinRead`/`TenantCellPinWrite` statements on its exec role
      policy. Run one enrollment; confirm `assigned_cell_id` appears on that
      owner's Control customer row and a second assignment for the same owner
      returns the recorded cell. Alarm state is not evidence here — the pin
      emits no dedicated metric, so the row readback is the proof.
- [ ] Rollout (prod): nothing extra — the production Control bootstrap's
      runtime apply consumes the committed `true`. During post-bootstrap
      verification, include the same env + exec-role + customer-row readback
      as the sandbox check above.
- [ ] Rollback: set the root variable false and re-apply (env var and both
      grants disappear together). Recorded `assigned_cell_id` attributes stay
      on customer rows and are inert while the store is nil; do not bulk-strip
      them — they become authoritative again the moment pinning re-enables.
