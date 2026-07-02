# 2026-07-01 · PR #2999 · Phase 0 knock-failure attribution metrics

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/2999 · https://github.com/layervai/nhp/issues/3001 · https://github.com/layervai/qurl-service/issues/976

Additive-only observability: six new bounded-cardinality metrics (no behavior
change), emitted via the existing 60s-flush Publisher. Post-rollout, confirm
they actually land; the dashboard/histogram build-out is deferred to #3001.

- [ ] Post-rollout: after the next sandbox deploy of nhp-server + nhp-acd,
      confirm the six new series appear in CloudWatch namespace `LayerV/NHP` —
      `KnockFailReason` (base + `Reason`), `KnockForwardOutcome` (`Outcome`),
      `ACAssignmentSelectedPublicIP`, `ACAssignmentSelectedCriticallyLow`,
      `AllUnconnectedDurationMs`, `AllUnconnectedRecoveryMs`.
- [ ] Post-rollout (deferred → #3001): build the cause-histogram dashboard/query
      + the 0F Logs-Insights join, with the reading caveats recorded on #3001
      (RecoveryMs as a percentile not sum; per-forward `KnockForwardOutcome` vs
      per-knock `KnockFailReason` cardinality; `token_publish_failed` is
      post-admission). Leave this file until #3001 closes.
