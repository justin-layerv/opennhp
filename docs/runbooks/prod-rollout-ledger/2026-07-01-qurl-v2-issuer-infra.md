# 2026-07-01 · qURL v2 issuer infra + NHP-server trust store (sandbox enablement)

- **Owner:** prod rollout coordinator
- **Scope:** nhp terraform (issuer KMS key, qurl-api v2 env + IAM, NHP-server
  `QURL_V2_ISSUER_TRUST_STORE` + `QURL_V2_ADMISSION_ENABLED`). Pairs with
  qurl-service PR [#1088](https://github.com/layervai/qurl-service/pull/1088)
  (admission-service wiring). Supersedes the wiring task in
  `2026-06-22-pr-2769-qurl-v2-admission.md` (issuer trust store is now
  Terraform-computed from the KMS key, not hand-written).

Provisions the ECDSA P-256 issuer signing key and threads all qURL v2 flags
through qurl-service + compute. **Ships with v2 minting + admission OFF.** Sandbox
sets `qurl_v2_issuer_key_enabled = true` (creates the key + validates qurl-api
issuer config); `resource_keys` / `issuance` / `admission` stay false. Prod sets
nothing (all default off).

- [ ] **Rollout (this PR apply, sandbox):** the apply creates the issuer KMS key,
  grants qurl-api `kms:Sign`/`GetPublicKey` on it, and sets `QURL_V2_ISSUER_KEY_*`
  env on qurl-api → **qurl-api ECS task rolls**. Confirm qurl-api boots healthy
  (`/health/ready` green; `QURL_V2_ISSUER_KEY_ENABLED` logged, issuance still off).
  The **NHP-server fleet does NOT roll**: its `QURL_V2_*` env is rendered only when
  `qurl_v2_admission_enabled` (off here), so its `user_data` is byte-unchanged.
- [ ] **Pre-rollout (HARD, before the enable flip):** qurl-service PR #1088 merged
  and deployed to sandbox (the `/internal/v2/qurl/admissions/*` routes must be
  mounted — they 404 without it, and every qv2 knock would deny at `prepare`).
- [ ] **Rollout (the enable, coordinated, sandbox) — prefer a TWO-apply sequence to
  avoid a cross-fleet race:**
  - **Apply 1:** `qurl_v2_admission_enabled` + `qurl_v2_resource_keys_enabled` (+
    `qurl_v2_issuer_key_enabled`, already true) = `true`, issuance still `false`. This
    rolls the NHP-server knock fleet (`admission_enabled` now renders the `QURL_V2_*`
    env) and provisions resource keys — but nothing mints v2 links yet. Wait for the
    server instance refresh to converge and the trust-store check below to pass.
  - **Apply 2:** `qurl_v2_issuance_enabled = true`. Minting begins only once every
    server can already admit, so there is no window where a freshly-minted v2 link
    hits a not-yet-refreshed server (trust store still `{}`) and denies.

  The plan-time preconditions permit Apply 1's `admission=true, issuance=false` (the
  harmless direction). A single-apply enable (all three flags at once) is also valid
  but has a transient window where links minted before the server refresh converges
  can fail. After Apply 2, verify end-to-end: mint a qURL, confirm the link is `qv2.`
  (not `qv1.`), and confirm a knock opens the resource.
- [ ] **Verify (at enable):** the NHP-server trust store round-trips. It is
  transported **base64-encoded** (`base64encode()` in the compute module; the qURL
  plugin's `LoadConfig` decodes it — resolves the earlier env-file quote-handling
  concern that was #2989). Confirm it loaded: SSM in after the server refresh and
  check the qURL plugin logged `qURL v2 admission ENABLED` with no trust-store parse
  error (`docker exec nhp-server … logs`).
- [ ] **Verify (at enable):** `kms:GetPublicKey` is available where it's now needed.
  The trust-store `data.aws_kms_public_key` read is gated on `admission_enabled`, so
  *this staging apply performs no `GetPublicKey`* — but the enable apply does. Confirm
  the **Terraform apply role** holds `kms:GetPublicKey` on the issuer key (its key
  policy is root-delegation only; the CI plan-read policy's KMS-metadata block grants
  `kms:Get*`, which includes `GetPublicKey`, so the enable-flip PR plan refreshes
  cleanly). Separately, qurl-api **boot** performs a synchronous `kms:GetPublicKey`
  when issuance is on (fatal on failure), so the key + policy must exist before the
  flag flips (already granted by the issuer key policy's service-role statement — no
  extra IAM).
- [ ] **Verify (at enable):** the `kid` in the sandbox trust store
  (`qurl_v2_issuer_kid`) matches what qurl-service signs under
  (`QURL_V2_ISSUER_KEY_KID`) — both driven by the same var, but confirm on the
  live task envs (a mismatch → `ErrUnknownKID` → every admission denies).
- [ ] **Verify (at enable):** qurl-api can create/reap per-resource KMS keys
  (tag-scoped IAM `purpose=qurl-v2-resource-key`) but nothing else — spot-check
  CloudTrail that resource-key creates succeed and no `kms:*` on the encryption
  CMKs is attempted/allowed.
- [ ] **Verify (at enable, HARD — resource-keys):** the resource-key destructive-KMS
  Deny is EXHAUSTIVE. `qurl_v2_resource_key_protected_kms_arns` lists only the
  ebs/efs/secrets/logs/rds CMKs + issuer key; the tfstate CMK (`alias/terraform-state`)
  and any other root-delegating account CMK are NOT covered, so a compromised qurl-api
  could tag + `ScheduleKeyDeletion` them. Before flipping `qurl_v2_resource_keys_enabled`,
  land the exhaustive fix (an SCP) tracked in #2990, or confirm the list covers every
  root-delegating CMK in the account.
- [ ] **Rollback:** set the three enable flags back to false and re-apply (v2
  path goes inert; createQurl returns to v1). The issuer key + `issuer_key_enabled`
  can stay (idle). Full teardown: set `qurl_v2_issuer_key_enabled = false` (key
  enters its deletion window; only after confirming no minted qv2 links depend on
  it).
- [ ] **Prod:** left dark (no tfvars). The compute `user_data` change does NOT roll the
  prod NHP-server fleet: the `QURL_V2_*` env renders only when `qurl_v2_admission_enabled`
  (unset in prod), so prod `user_data` is byte-unchanged.
