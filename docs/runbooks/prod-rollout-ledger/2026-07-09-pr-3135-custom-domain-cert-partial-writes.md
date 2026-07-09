# 2026-07-09 - PR #3135 - Custom-domain cert partial-write hardening

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3135

Deploys fail-loud cert/key preflight in the custom-domain cert-manager Lambda
and AC-side staging validation so a partial SSM write cannot poison the served
custom-domain certificate after a renewal.

- [ ] Pre-rollout: deploy to sandbox and trigger or wait for one custom-domain
      renewal scan; confirm a cert/key mismatch is rejected before any active
      domain's SSM `/key`, `/chain`, or `/meta` set is advanced.
- [ ] Pre-rollout: confirm an AC incremental sync for mismatched SSM material
      fails without replacing the live cert directory or `custom-domains.toml`
      block for that domain.
- [ ] Rollout: deploy the cert-manager Lambda and updated AC cert-sync SSM
      document together; AC instances must pick up the script with staged
      validation before the Lambda starts writing renewal material with the new
      rollback path.
- [ ] Post-rollout: run a read-only prod scan comparing each custom-domain SSM
      `/key` public key with its `/chain` leaf public key before forcing any
      healing sync; repair any existing mismatch from SSM history or a fresh
      issuance before invoking AC sync for that domain.
- [ ] Post-rollout: monitor `RenewalProcessingFailures`,
      `CertPairRollbackFailures`, `CertSyncFailures`, cert-manager Lambda errors,
      and SNI probes for domains renewed during the first scheduled scan after
      deploy. A domain preserved on last-known-good local cert material because
      SSM is invalid still increments `CertSyncFailures`; the `>0` per-6-hour
      alarm should keep paging until the SSM key/chain pair is repaired.
      Present-but-empty material during initial provisioning can also page;
      confirm it clears on the next issuance scan or repair the partial SSM
      state.
- [ ] Post-rollout: review Systems Manager Parameter Store usage after the
      first renewal window. Fullchains over 4 KiB are intentionally stored as
      Advanced SecureStrings; if this becomes common, check Advanced parameter
      count/cost against the account budget. The rollback snapshot also adds
      two `GetParameter(WithDecryption=True)` reads per cert store for the
      previous `/key` and `/chain`; confirm KMS decrypt volume remains expected.
      Re-validate the Advanced-to-Standard fallback's AWS `ValidationException`
      text match after AWS SDK or API behavior changes.
- [ ] Rollback: reverting this PR reopens the partial-write poisoning failure
      mode. Prefer a forward fix unless the rollback path itself blocks valid
      renewals, and inspect SSM key/chain pairs before running AC sync after any
      rollback.
