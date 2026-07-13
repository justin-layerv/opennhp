# 2026-07-13 · Issue #3232 · AC readiness dependency

- **Owner:** prod rollout coordinator
- **Source:** [#3232](https://github.com/layervai/nhp/issues/3232), [server-key validator PR #3230](https://github.com/layervai/nhp/pull/3230)

Remove the AC module-wide internal-ALB readiness dependency before applying
#3230. The broad edge makes stable public Route53 zone ids unknown and causes
unsafe apex/wildcard replacements in unrelated Terraform plans.

- [ ] Pre-rollout: merge this fix before #3230, then rerun #3230's exact-head hosted sandbox plan. The plan must contain zero replace/destroy actions for `module.nhp.module.ac[0].aws_route53_record.ac[0]` and `ac_wildcard[0]`; abort if either returns.
- [ ] Ordering proof: retain the root token's dependency on both internal-ALB certificate validation and private DNS alias, its disabled empty-token path, the module-local readiness resource, and the launch-template-only `depends_on`. The local resource intentionally remains inert with `input = ""` when disabled because the enabled first-apply token is unknown and cannot safely drive `count`; prove the disabled plan remains valid. Record the structural-test and Terraform-validation runs on the PR.
- [ ] Sandbox rollout: apply through the normal checked-plan path. Confirm the new `terraform_data.qurl_internal_alb_readiness` is added without an AC Route53 replacement/destruction and that any AC launch-template update occurs only after the internal certificate and alias are ready.
- [ ] Prod rollout: carry the same commit through the normal promote plan/apply. Require zero AC Route53 replacement/destruction and strict plan-time AC Lambda artifacts before approval.
- [ ] Cleanup: link the sandbox/prod plan and apply evidence from #3232, remove this entry only after both environments contain the targeted graph, and keep #3230 blocked until its own exact apply plan inherits the fix.
- [ ] Rollback: restore the prior code only after proving the rollback plan has zero AC Route53 replacements/destructions. Prefer keeping the narrow edge; the former module-wide dependency is the diagnosed hazard, not a safe fallback.
