# 2026-08-01 · Restore the bootstrap-ALB access-log destroy guard

- **Owner:** sandbox terraform coordinator
- **Source:** [NHP PR #3607](https://github.com/layervai/nhp/pull/3607) (retirement), [#3651](https://github.com/layervai/nhp/pull/3651) (unblock), this PR (restore)

Third and final revision of the bootstrap-ALB retirement. Restores
`lifecycle { prevent_destroy = true }` on the access-log bucket for production,
the only surviving instance, closing the window #3651 opened.

**Do not merge or apply until sandbox's bootstrap-ALB destroy has actually
applied.** `prevent_destroy` is evaluated from configuration, not state, and
cannot be scoped to one environment. Restoring it while sandbox still has a
pending destroy re-creates #3607's failure exactly: the revision blocks its own
destroy and the whole sandbox root stops planning.

- [ ] Pre-rollout: confirm sandbox's bootstrap ALB is gone — a sandbox plan
      shows no pending `module.nhp.module.bootstrap_alb` destroy, and
      `terraform state list | grep bootstrap_alb` returns nothing. Merged is
      not sufficient; the destroy must be applied.
- [ ] Rollout: apply. This is a configuration-only guard restore; the plan
      should show no resource changes.
- [ ] Post-rollout: confirm production's
      `module.bootstrap_alb[0].aws_s3_bucket.alb_access_logs` reads back with
      `force_destroy = false` and its `prevent_destroy` guard in place. This is
      the step that closes #3651's window.
- [ ] Rollback: revert this PR. That returns the repo to the guard-absent state,
      which plans cleanly — a safe place to stop, but it re-opens the window, so
      only do it to unblock a genuinely stuck destroy.
