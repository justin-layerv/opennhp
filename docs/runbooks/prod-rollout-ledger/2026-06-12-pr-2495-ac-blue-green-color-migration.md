# 2026-06-12 · PR #2495 · AC cross-color assignment migration on blue/green switch

- **Owner:** prod rollout coordinator
- **Source:** [#2495](https://github.com/layervai/nhp/pull/2495)

Makes blue/green AC→server convergence deterministic for the steady-state
one-instance-per-AZ fleet (3 = `MaxServersPerAssignment`), so the post-switch
knock-readiness gate stops flaking; a new-active fleet larger than 3
(autoscaling past the AZ count, or a deploy stacked on a not-yet-scaled-down
color) still converges far faster but full coverage of the extras stays a
faster coupon-collector — a pre-existing `MaxServersPerAssignment` limit, not
closed here. Pure server-side logic change plus a new
`ACAssignmentColorMigration` counter; no config/secret/migration. Applies
through the normal promote pipeline.

- [ ] Post-rollout: on the first prod blue/green switch carrying this code, confirm `ACAssignmentColorMigration` spikes (~one-per-AC) during the switch and returns to ~zero, and that the `Validate` job's `[Server] Verify Post-Switch Knock Readiness` step converges (every new-color server reports `N AC peer(s) connected`) without a 5-minute timeout. Read the *sustained rate*, not single events: occasional isolated ticks outside the switch window are benign (e.g. a cache straddle reassigning an already-same-color AC to its own color, or a new-color server slow to propagate to Cloud Map being briefly self-evicted by ACs that land on it). Only a *sustained* non-zero rate indicates non-convergence (e.g. a server that never propagates and is repeatedly self-evicted).
- [ ] Rollback: pure code revert — `git revert` restores the prior `updateAssignmentWithSelf`-only path (reintroduces the slow-convergence flake). No data/assignment migration to undo; the `ACAssignmentColorMigration` counter is inert once reverted.
