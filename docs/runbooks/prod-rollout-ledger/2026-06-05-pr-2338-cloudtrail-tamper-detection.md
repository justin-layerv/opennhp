# 2026-06-05 · PR #2338 · CloudTrail tamper-detection alerting

- **Owner:** prod rollout coordinator
- **Source:** [#2338](https://github.com/layervai/nhp/pull/2338) · [issue #1143](https://github.com/layervai/nhp/issues/1143)

Adds an EventBridge rule paging Slack on CloudTrail tampering. Not yet in prod: default-on additive resources apply through the normal promote pipeline; the post-rollout Slack-page smoke is the only required task.

- [ ] Post-rollout (REQUIRED): run the Slack-page smoke in `docs/SECURITY.md` → "CloudTrail Tamper Detection" → Testing — trigger a benign `update-trail` on `layerv-nhp-prod-trail` and confirm the `:rotating_light: CloudTrail tampering` page reaches the on-call Slack channel; confirm the `Error code` field renders blank (not literal `null`).
- [ ] Post-rollout: exercise a `PutEventSelectors` event (re-apply current selectors — a no-op) and confirm the page renders the trail name, not `nullname`/`namenull` (proves the `<trailName><trailNameSel>` coalescing in the live transformer).
- [ ] Rollback: set `enable_cloudtrail_tamper_alerts = false` (or revert); additive and side-effect-free, no data/traffic impact.
- [ ] Follow-up: rule runs in us-east-2 covering the canonical `layerv-nhp-prod-trail`; the redundant us-east-1 `layerv-prod-trail` is uncovered until [#1143](https://github.com/layervai/nhp/issues/1143) Bucket B deletes it (tampering it alone blinds nothing).
