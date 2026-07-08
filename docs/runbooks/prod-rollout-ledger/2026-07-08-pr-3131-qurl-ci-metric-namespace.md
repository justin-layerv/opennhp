# 2026-07-08 · PR #3131 · qURL CI metric namespace

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3131, https://github.com/layervai/qurl-service/pull/1163

Before relying on qurl-service's sandbox live-environment lock metric for alerts,
apply this Terraform IAM change so the shared NHP GitHub Actions role can publish
`LayerV/QURLServiceCI/SandboxLiveEnvLockFailure` and delete successful
qurl-service PR image tags from only the qurl API ECR repository.

- [ ] Rollout: apply the Terraform plan from this PR and confirm the `nhp-<env>-github-actions` role's `CloudWatchPutMetricData` statement includes `LayerV/QURLServiceCI` without broadening beyond the explicit namespace allowlist.
- [ ] Rollout: confirm the same role's `QURLPrImageCleanup` statement grants `ecr:BatchDeleteImage` only on the `nhp-qurl` repository ARN, not on every repository in `local.ecr_repos`.
- [ ] Post-rollout: force or inspect a non-customer-path qurl-service sandbox lock metric emission and confirm `LayerV/QURLServiceCI/SandboxLiveEnvLockFailure` appears with `Reason` and `Action` dimensions.
- [ ] Post-rollout: re-run a successful qurl-service PR smoke or inspect the next one and confirm the `Delete PR image tag` step no longer reports ECR `AccessDenied`.
- [ ] Cross-repo: before closing qurl-service PR #1163's rollout dependency, verify its pre-merge qv2 smoke gate no longer reports CloudWatch `AccessDenied` warnings when the lock script emits a best-effort failure metric.
- [ ] Rollback: if the namespace grant is reverted, treat qurl-service lock metric publication as log-only until the allowlist is restored; if the ECR cleanup grant is reverted, expect successful qurl-service PR image tags to remain until lifecycle cleanup. The sandbox mutex still fails closed.
