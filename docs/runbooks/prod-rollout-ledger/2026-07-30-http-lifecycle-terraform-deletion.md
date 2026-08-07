# 2026-07-30 · HTTP lifecycle Terraform deletion

- **Owner:** sandbox UDP retirement operator
- **Source:** This PR · [preparation PR #3605](https://github.com/layervai/nhp/pull/3605) · [NHP #3597](https://github.com/layervai/nhp/pull/3597) · [qurl-service #1336](https://github.com/layervai/qurl-service/pull/1336)

Delete the exact Terraform resources governed by
`TERRAFORM_RETIREMENT_RESOURCES` and retain the successful saved-plan apply
receipt for the post-removal UDP proof.

- [ ] Pre-rollout: require #3605 merged and applied and its prepared qurl-service task definition active and healthy. ~~and the complete pre-removal UDP proof green.~~
      _Proof-aggregate gate withdrawn 2026-08-06 — the UDP proof controller has never produced a green run (100 dispatches, 0 success) and every failure is harness, not product. See `2026-07-29-http-lifecycle-retirement.md`._
- [ ] Pre-rollout: require NHP #3597 and qurl-service #1336 deployed, then update this same PR to pin the exact final qurl-go and Connector proof heads in `.github/workflows/udp-proof-controller.yml`; do not merge an intermediate pin because the receipt must be produced by the final NHP head.
- [ ] Rollout: review the saved sandbox plan and require every `TERRAFORM_RETIREMENT_RESOURCES` member to be a pure delete, with no deletion or replacement outside that logical set; verify the merged module source has restored production's `force_destroy=false` plus `prevent_destroy=true`, then apply that exact saved plan from trusted `main`.
- [ ] Post-rollout: retain the `udp-proof-terraform-apply-*` artifact and run the post-removal qurl-go and Connector UDP suites against the resulting NHP head.
- [ ] Rollback: stop before apply if the plan is not the exact governed deletion set. After apply, roll forward on native UDP; restoring the deleted ALB log bucket or qurl-service OTP pepper is not supported.
