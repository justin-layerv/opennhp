# 2026-06-18 · PR #2698 · qurl-scanner Lambda ECR policy

- **Owner:** prod rollout coordinator
- **Source:** [#2698](https://github.com/layervai/nhp/pull/2698) · [layervai/qurl-service#850](https://github.com/layervai/qurl-service/issues/850)

The qurl-scanner Lambda can enter `ImageAccessDenied` after going inactive if
the scanner ECR repository policy does not allow the Lambda service principal
to retrieve the image. Sandbox was hot-fixed manually; this PR makes Terraform
own the primary-account repo policy before scanner rollout depends on it. Prod
uses a replicated secondary-account repo, so [#2699](https://github.com/layervai/nhp/issues/2699)
tracks Terraform ownership there after this rollout check is no longer manual.

- [ ] Rollout: apply this Terraform change in sandbox and confirm the
      `layerv/qurl-scanner-lambda` ECR repository policy still contains both
      `AllowCrossAccountPull` and `LambdaECRImageRetrievalPolicy`.
- [ ] Post-rollout: let the sandbox scanner idle long enough to pass through an
      inactive/reactivation cycle, then confirm manual or scheduled invoke still
      succeeds and `layerv-nhp-sandbox-cell0-qurl-scanner-invocation-gap` stays
      OK.
- [ ] Pre-rollout (prod): confirm the replicated prod scanner Lambda ECR
      repository policy has the same Lambda retrieval statement before enabling
      `qurl_scanner_lambda_enabled = true` in prod. This remains a manual gate
      until #2699 lands.
- [ ] Rollback: if the repository policy blocks any expected ECR pull, restore
      the previous cross-account-only statement and refresh the affected
      scanner Lambda only after adding an equivalent out-of-band Lambda image
      retrieval permission.
