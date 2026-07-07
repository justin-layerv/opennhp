# 2026-07-07 · Custom-domain renewal failures preserve active state

- **Owner:** prod rollout coordinator
- **Source:** nhp PR #3124

Scheduled custom-domain renewals previously reused the first-time provisioning
failure path. A transient renewal processing failure, including Let's Encrypt
duplicate-certificate rate limiting, could move an otherwise-active domain to
`status=failed` while SSM still held a valid cert. qurl-service then correctly
failed closed to qurl.site, but the customer custom domain stopped being honored
before TLS expiry.

- [ ] Pre-rollout: deploy to sandbox and invoke or wait for the custom-domain cert renewal scan.
- [ ] Pre-rollout: confirm `dashboard.everhavencapital.com` recovers to `status=active` if SSM still has an unexpired cert and `_layerv-verify.dashboard.everhavencapital.com` still matches the sandbox `qurl-domains` row.
- [ ] Pre-rollout: confirm a forced renewal processing failure records `last_renewal_failed_at` / `last_renewal_failure_reason` without changing the domain's active status.
- [ ] Post-rollout: monitor `RenewalStatusRecovered`, `RenewalProcessingFailures`, and Lambda errors for the first scheduled scan in prod; a non-zero `RenewalStatusRecovered` page is self-healing evidence that the demotion failure mode happened and should clear on the next clean scan, while non-zero processing failures should leave active domains active unless DNS ownership re-verification fails.
- [ ] Rollback: reverting restores the old failure mode where renewal processing errors can demote active domains. Prefer forward-fix unless the recovery path itself incorrectly marks domains active without DNS ownership evidence.
