# 2026-07-23 · NHP main deploy semantic invokes

- **Owner:** prod rollout coordinator
- **Source:** [NHP main deploy run 30047738154](https://github.com/layervai/nhp/actions/runs/30047738154) and [NHP #3405](https://github.com/layervai/nhp/pull/3405)

The sandbox deploy role lost its accidental broad Lambda-invoke fallback when
#3391 narrowed helper access. Restore only the qualified read-only relay-status
invoke before rerunning the failed deployment, and verify production has the
same exact grant before its next apply.

- [ ] Pre-rollout: add only `relay-status:$LATEST` to the sandbox `terraform-read` policy, then verify policy simulation permits that ARN and denies the unqualified target plus an Authority alias.
- [ ] Rollout: rerun current NHP `main` sandbox deployment and require Infrastructure, post-apply plan, validation, and smoke jobs to pass.
- [ ] Pre-production: verify the production deploy role has the same exact qualified grant before the next production Terraform plan; repair it first if absent.
- [ ] Post-rollout: record the successful sandbox run and production readback on the hotfix PR, then delete this ledger entry once both environments are complete.
