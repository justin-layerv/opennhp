# 2026-06-06 · PR #2342 · Terraform state bucket KMS migration (#1128)

- **Owner:** prod rollout coordinator
- **Source:** [#2342](https://github.com/layervai/nhp/pull/2342) · [#1128](https://github.com/layervai/nhp/issues/1128) · cutover PR [#2347](https://github.com/layervai/nhp/pull/2347)

Migrate the TF state buckets from AES256 to SSE-KMS. The CMK + bucket-default are operator/admin out-of-band steps (CI is deliberately object-only on the state bucket); the only code change is the backend `kms_key_id` cutover (#2347). Full procedure + lockout analysis: [`tfstate-kms-migration.md`](../tfstate-kms-migration.md). **Phase A (CMK) is done in both accounts** — the cutover PR #2347 is ready.

- [x] Pre-rollout: `alias/terraform-state` CMK (rotation on) exists in **both** accounts (sandbox `…/289dbe35…`, prod `…/00a0e673…`), and `nhp-{sandbox,prod}-github-actions` both simulate `allowed` for `s3:PutObject/GetObject` + `kms:Decrypt/GenerateDataKey` on the state object + key (end-to-end SSE-KMS write/read confirmed on both real buckets). The mid-`promote-to-prod` `KMSAccessDeniedException` gate is cleared.
- [ ] Rollout: merge cutover PR #2347 (backend `kms_key_id` + `init -reconfigure`); sandbox applies via `build-and-push` first, then prod via `promote-to-prod`.
- [ ] Rollout (per account, operator out-of-band): Phase B — set the bucket default to `aws:kms` (runbook Phase B). **Required to close #1128**: it clears the `s3-default-encryption-kms` Config rule (which checks the bucket default); Phase C alone (state objects) leaves that finding red.
- [ ] Post-rollout: Phase D — `head-object` on `nhp/<env>/terraform.tfstate` reports `aws:kms` + the CMK ARN, and a CloudTrail `Decrypt` event references the CMK (the per-caller audit trail #1128 asks for).
- [ ] Rollback: revert #2347 + `terraform init -reconfigure` (next state write reverts to AES256; no data migration). **Never disable or schedule deletion of the CMK while any state version is encrypted with it** — that bricks state.
- [ ] Follow-ups: [#2359](https://github.com/layervai/nhp/issues/2359) (reconcile/remove orphaned `terraform/bootstrap`), [#2360](https://github.com/layervai/nhp/issues/2360) (CI guard so `kms_key_id` can't be silently dropped); on #1128 close, remove the `docs/SECURITY.md` state-bucket AES256 exception bullet.
