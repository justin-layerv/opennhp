# 2026-07-26 · Cell0 qurl-service publisher foundation

- **Owner:** prod rollout coordinator
- **Source:** canonical UDP-only qURL Connector plan; qurl-service publisher PR

Create and prove the exact cell0 promotion boundary before the two-cell
qurl-service publisher or deployment-manifest producer runs.

- [ ] Pre-rollout: merge the governed qurl-service publisher, bring the sandbox root to a reviewed current-main no-op without targeting, and confirm the exact cell0 ECS family, service, roles, and 512/1024 task shape.
- [ ] Rollout: review and apply the sandbox saved plan; reject any mutation beyond the new parameter, role, policy, and outputs.
- [ ] Post-rollout: read back the exact main-ref trust, least-privilege policy, and `UNPUBLISHED` SSM sentinel; retain the saved-plan/apply evidence.
- [ ] Cross-repo: after the separate cell1 foundation exists, run the publisher's `publish_only` phase and require NHP's manifest producer to verify the resulting immutable contract.
- [ ] Rollback: before publication, remove only this foundation with a reviewed saved plan; after publication, preserve the contract as evidence until both cell runtimes leave the proof chain.
