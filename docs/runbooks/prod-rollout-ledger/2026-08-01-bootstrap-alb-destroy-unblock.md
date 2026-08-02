# 2026-08-01 · Unblock the sandbox bootstrap-ALB destroy

- **Owner:** sandbox terraform coordinator
- **Source:** [NHP PR #3607](https://github.com/layervai/nhp/pull/3607) (retirement), this PR (unblock)

#3607 restored `lifecycle { prevent_destroy = true }` in the same revision that
removed sandbox's bootstrap-ALB module from configuration, so that revision
blocked its own destroy and the sandbox root stopped planning entirely —
failing every Terraform PR, not just bootstrap-ALB ones. This removes the block
so the pending destroy can apply.

Verified against live sandbox with a read-only targeted plan: on `main` the
plan fails with `Instance cannot be destroyed`; with this change it returns
`0 to add, 0 to change, 34 to destroy`. `force_destroy = true` is already
recorded in state from the earlier preparation revision, so the versioned
bucket empties cleanly.

**Production is unaffected while the guard is off.** Its module stays in
configuration, so no production plan calls for its access-log bucket to be
destroyed. But the guard genuinely is absent repo-wide, so the restore below is
required, not optional.

- [ ] Rollout: apply to sandbox. Expect exactly the bootstrap-ALB teardown —
      ALB, WAF, target group, listener, alarms, SNS topic, Athena workgroup,
      both S3 buckets, ACM cert, and the `bootstrap.layerv.xyz` alias. Nothing
      outside `module.nhp.module.bootstrap_alb` and its root-level companions
      (`terraform_data.bootstrap_alb_dns_preconditions`,
      `time_sleep.bootstrap_alb_iam_propagation`) should move.
- [ ] Rollout: the CI apply role's `s3:DeleteObjectVersion` grant for these
      buckets lands in the SAME apply as the destroy (both live in
      `terraform/main.tf`), so IAM propagation can race it. If the apply fails
      with `AccessDenied ... s3:DeleteObjectVersion` while emptying, simply
      re-run the sandbox deploy — the grant is already in place by then. Do not
      hand-empty the bucket to work around it.
- [ ] Post-rollout: confirm the sandbox root plans clean, then re-run the
      Terraform Plan check on any PR blocked by this (e.g.
      [#3649](https://github.com/layervai/nhp/pull/3649)).
- [ ] Post-rollout: sandbox runs `bootstrap_alb_provision_certificate = true`,
      so its ACM cert is destroyed with the module. No manual
      `aws acm delete-certificate` is needed — README "Teardown / cleanup"
      section 2 applies only to `provision_certificate = false` paths.
- [ ] Follow-up (required, do not leave pending): restore
      `lifecycle { prevent_destroy = true }` on the access-log bucket once
      sandbox's is gone, and confirm production's bucket reads back with the
      guard and `force_destroy = false`. Until that lands, production's
      access-log bucket has no destroy guard.
- [ ] Rollback: revert this PR only together with #3607's tfvars flip. Reverting
      this alone returns the root to the state that cannot plan.
