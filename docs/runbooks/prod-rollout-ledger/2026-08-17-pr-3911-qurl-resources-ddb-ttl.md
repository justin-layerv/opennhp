# 2026-08-17 · PR #3911 · qurl-resources DDB TTL enablement

- **Owner:** prod rollout coordinator
- **Source:** [#3911](https://github.com/layervai/nhp/pull/3911) · [layervai/qurl-service#846](https://github.com/layervai/qurl-service/issues/846)

Enables DynamoDB TTL (attribute `ttl`) on `qurl_resources`. The service has
always written the attribute assuming enforcement; no environment ever enabled
it (sandbox cells + prod all `DISABLED` before this PR). Sandbox applies with
the normal main merge; prod picks it up at the next promote and DynamoDB then
begins background-deleting rows whose `ttl` has passed — long-expired rows the
service already treats as dead (851 such rows at the 2026-08-15 prod read-only
CRID dry run; recount at promote). CRID retirement sentinels are separate
no-TTL items and survive.

- [ ] Pre-rollout (prod, at promote time): re-run the near-future-`ttl` safety
      scan against `layerv-nhp-prod-cell0-qurl-resources` (rows with `ttl` in
      `(now, now+90d]`; expect 0 or examine each) so the safety evidence is
      fresh at the moment enforcement starts. Baseline 2026-08-17: **0** such
      rows out of 4,325 scanned items (sandbox cell0 had 18, all revoked with
      `ttl = expires_at + 7d`; sandbox cell1's table is empty and is managed
      by the lean cell1 root, so it enables on that root's next apply). Prod
      has no cell1 resources table.
- [ ] Rollout (prod): after the promote apply, confirm
      `aws dynamodb describe-time-to-live --table-name layerv-nhp-prod-cell0-qurl-resources`
      (name verified live 2026-08-17) reports `ENABLED` with attribute `ttl`.
- [ ] Post-rollout (prod): after the sweep settles (DynamoDB TTL deletes
      within ~days, not hours), re-run the read-only CRID backfill dry run
      (`cmd/qurl-crid-backfill`, no `--apply`) and confirm the passed-ttl
      cohort has drained toward 0 with all anomaly cohorts still 0. This
      feeds the CRID prod promote confirm-zero gate.
- [ ] Post-rollout (sandbox, no prod dependency): same re-verify against
      sandbox cell0 (`crid_backfill_remaining` was 4,335 — entirely passed-ttl
      rows — on 2026-08-17); expect it near 0 once the sweeper catches up.
      Closes the phase-2c ledger loop in qurl-service with post-sweeper
      evidence.
- [ ] Cross-repo follow-up: comment findings on qurl-service#846 (its premise
      — TTL already active on attribute `ttl` — was false at infra level until
      this PR; the `tombstone_ttl` rotation decision there stays open and
      remains possible).
- [ ] Rollback: revert the `ttl` block and re-apply (in-place config change;
      rows already deleted stay deleted — they were months past their
      service-stamped deletion time).
