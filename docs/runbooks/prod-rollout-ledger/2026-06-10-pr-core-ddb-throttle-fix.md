# 2026-06-10 · core DynamoDB throttle-alarm fix (#1912)

- **Owner:** prod rollout coordinator
- **Source:** PR (this), [#1912](https://github.com/layervai/nhp/issues/1912)

Fixes the core-table `dynamodb_throttled` alarm (was `ThrottledRequests` +
`{TableName}`, which matches no metric stream → silently `OK` forever) by
switching it to `ReadThrottleEvents` + `WriteThrottleEvents` metric-math at
`{TableName}`. Removes the identically-broken `dynamodb_system_errors` alarm
(#2445). Plan: **5 throttle alarms updated in-place, 5 system-errors alarms
destroyed**, nothing else.

- [ ] Rollout: validate in sandbox first (applies on merge to main), then promote to prod with `run_terraform=true`.
- [ ] **Behavior change to announce:** the 5 core-table throttle alarms were silently broken (never fired). After this they fire on a *real* sustained throttle (2 consecutive 60s windows). There is **no** alarm-state notification burst — in-place updates stay in their current state and the destroys are silent — but a genuine throttling incident that was previously invisible will now page. That is the intended fix, not a regression.
- [ ] Post-rollout: confirm the 5 `*-dynamodb-throttled-*` alarms apply cleanly and are now backed by the Read/Write throttle-events metric-math (`aws cloudwatch describe-alarms --alarm-name-prefix "layerv-nhp-prod-<cell>-dynamodb-throttled-"` → each has a `Metrics` array with `ReadThrottleEvents`/`WriteThrottleEvents`, not a flat `ThrottledRequests`). They should sit `OK` (no real throttling expected at steady state).
- [ ] Post-rollout: confirm the 5 `*-dynamodb-errors-*` (SystemErrors) alarms are gone. Coverage removal is intentional (they never fired); revisit path is #2445.
- [ ] Rollback: revert the PR — restores the prior (silent/broken) alarms; no data impact, no migration.
