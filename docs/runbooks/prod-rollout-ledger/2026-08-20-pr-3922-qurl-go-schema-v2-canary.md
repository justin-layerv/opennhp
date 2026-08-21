# 2026-08-20 · qurl-go schema-v2 registration canary

- **Owner:** prod rollout coordinator
- **Source:** [NHP #3922](https://github.com/layervai/nhp/pull/3922) · [NHP #3921](https://github.com/layervai/nhp/pull/3921)

The sandbox mailbox role must admit qurl-go's protected `main` workflow before
the normal OTP registration writer can create the designated schema-v2 canary.
This remains blocked on the governed invalid-row reset and writer convergence;
it does not authorize an ad hoc credential or AWS mutation.

The exact GitHub OIDC `sub` is repository `main`-ref-wide: any qurl-go workflow
running on `refs/heads/main` can assume this role. AWS IAM cannot scope that
claim to one workflow, so rollout approval must explicitly accept the boundary
as branch protection plus the unchanged, mailbox-read-only role policy. No
Environment subject or wildcard is accepted.

- [ ] Pre-rollout: after the qurl-service reset-tool merge publishes its final
      Authority digest, replan this exact NHP head. Require the Control plan to
      bind that digest and pass its image-roll contract, and require the
      mailbox-role target plan to pass
      `check-qurl-go-otp-mailbox-gate-plan.py` at `0 add / 1 change / 0 destroy`.
      Generate its JSON with exact Terraform `1.14.3` and include both targets:
      `module.nhp.aws_iam_role.qurl_go_otp_mailbox_gate[0]` and
      `module.nhp.aws_iam_role_policy.qurl_go_otp_mailbox_gate[0]`; the latter
      must remain present and no-op so the checker can prove permissions did
      not expand.
- [ ] Rollout: let the main-push `Deploy Sandbox - Control` job converge and
      verify the final writer image before its dependent infrastructure job
      applies the trust update. Do not start the row reset until the complete
      NHP run is terminal green.
- [ ] Cross-repo: after the governed reset reports inventory PASS, run the
      protected qurl-go `main` OTP registration lane once and prove the
      designated registration is schema v2 before the NHP #3921 reader rollout.
- [ ] Rollback: remove only the exact qurl-go `refs/heads/main` trust subject;
      preserve the existing `pull_request` subject and mailbox-read policy.
