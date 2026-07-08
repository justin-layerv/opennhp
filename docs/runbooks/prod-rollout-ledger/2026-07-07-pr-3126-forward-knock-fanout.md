# 2026-07-07 · PR #3126 · Forwarded knock fan-out

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3126, https://github.com/layervai/qurl-service/pull/1163, https://github.com/layervai/qurl-service/actions/runs/28883148806

Before promoting this NHP server behavior to production, prove the retry-less qURL v2 admission path no longer returns the 52003/52005 forwarded-AC denial that broke the qurl-service main smoke.

- [ ] Pre-rollout: after the NHP sandbox deploy, rerun qurl-service PR #1163's `Pre-merge qv2 Smoke (Sandbox)` check and confirm it passes against the fixed NHP server path.
- [ ] Pre-rollout: run or inspect a sandbox native forwarded-knock smoke that does not depend on qURL v2, proving the all-assigned-owner fan-out path works for plain NHP_FWD admission as well as the qURL v2 admission wrapper.
- [ ] Post-rollout: after production promotion, run the qURL smoke workflow for prod (including qv2 if prod trust config is published) and inspect NHP server logs/metrics for forwarded admission errors (`52003`, `52005`) before closing this entry.
- [ ] Post-rollout: confirm duplicate qURL v2 side effects stay at the AC-pinhole layer only: `authWithNHPClaims` performs qurl-service prepare/commit once on the origin before `ForwardKnock`, forwarded receivers do not call qurl-service prepare/commit, and qurl-service one-time-use / max-session counters show no >1 commit per first knock.
- [ ] Post-rollout: during the production burn-in window, inspect AC operation/AOP volume for all native forwarded knocks, not only qURL v2. Compare `KnockForwardPeerAttempt` against request volume and check `ServerForwardUnknownResult` for expected first-success loser responses; confirm the bounded fan-out does not produce sustained abnormal AC load.
- [ ] Rollback: if qURL v2 admission failures increase after promotion, roll back the NHP server image to the previous production task definition/AMI and rerun the qURL smoke workflow.
