# 2026-06-03 · PR #2310 · Internal knock storage-resolved resources

- **Owner:** prod rollout coordinator
- **Source:** [#2310](https://github.com/layervai/nhp/pull/2310) · [issue #1209](https://github.com/layervai/nhp/issues/1209) · [layervai/qurl-service#821](https://github.com/layervai/qurl-service/pull/821)

NHP server resolves internal-knock resources from storage. Not yet in prod: deploy this NHP server change BEFORE qurl-service #821.

- [ ] Pre-rollout: confirm qurl-service #821 stays draft/blocked from prod until this NHP change deploys; confirm prod NHP servers already enforce strict `NHP_INTERNAL_AUTH_REQUIRE=true`; confirm prod qurl-service still sends request-level `resId` (`HTTPKnockRequest.ResourceID` from `NHPResourceID`).
- [ ] Rollout: deploy this NHP server change before qurl-service #821; once healthy, mark #821 ready and include it in a later qurl-service rollout.
- [ ] Post-rollout: before #821 deploys, verify prod NHP health reports this PR's merge-commit image tag. After #821 deploys, run a prod headless resolve smoke — confirm internal-knock success, no strict-auth failures, and the effective open window is the storage catalog cap (120s in prod, not qurl-service's default 300s).
- [ ] Rollback: if storage-resolved knocks fail before #821 deploys, roll back this NHP server image. If failures appear only after #821, roll back qurl-service first (restore body-supplied `resInfo`), then evaluate the NHP image.
- [ ] Follow-ups: [#1210](https://github.com/layervai/nhp/issues/1210) stays open for independent-trust-root SrcIp attestation; do not close it with a duplicate same-key request signature.
