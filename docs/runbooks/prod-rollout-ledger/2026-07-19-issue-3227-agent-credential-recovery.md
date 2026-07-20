# 2026-07-19 · Issue #3227 · Agent credential recovery activation

- **Owner:** prod rollout coordinator
- **Source:** [Hub tracker #3227](https://github.com/layervai/nhp/issues/3227), [cross-repo tracker qurl-connector #421](https://github.com/layervai/qurl-connector/issues/421)

Keep the additive UDP credential-recovery contract dark until every separately
permissioned producer, assigned-cell consumer, and SDK proof is complete. This
entry does not authorize an NHP listener, Lambda alias, IAM grant, or feature
flag change.

- [ ] Cross-repo: implement and review the qurl-service `IssueCredentialRecovery` and `CompleteCredentialRecovery` domain, durable replay/candidate storage, live recovery-credential revocation fence, exact 900-second grant, and immutable 90-day revoked-device-episode horizon against qurl-conformance v0.9.0. Keep #1291 retention and retirement gates satisfied before activation.
- [ ] Pre-rollout: add the assigned-cell strict completion codec/handler and the separately permissioned Hub/cell `:active` alias IAM/configuration in the owning NHP runtime/Terraform PRs. Do not configure either new alias against this contract-only source slice.
- [ ] Pre-rollout: configure and prove the Hub recovery admission gate emits the contract-frozen 60-second authenticated rate-limit delay. Any other configured delay must remain the fail-closed 52400 unavailable result, never a divergent 52404.
- [ ] Pre-rollout: publish the immutable qurl-go recovery consumer and prove that Hub issue plus assigned-cell completion use only authenticated NHP UDP, retain one sealed candidate across ambiguity, reject wrong cell/generation/key, and never call HTTP or relay.
- [ ] Sandbox rollout: on a real two-cell topology, record exact commits and prove successful recovery, exact Issue replay, exact committed Complete replay after grant expiry but before the horizon, changed-candidate conflict, revoked recovery-credential kill switch, exact horizon expiry, and no cross-cell probe/fallback before enabling any production recovery path.
- [ ] Prod rollout: deploy the reviewed Authority aliases and NHP runtime/configuration producer-first, keep Connector auth/recovery gated until health and negative-boundary checks pass, then enable the SDK consumer and record metrics/log evidence with no credential, grant, candidate, or private-key material.
- [ ] Rollback: disable the SDK recovery entry point first, remove the new Hub/cell alias configuration and IAM grants, and leave persisted recovery records inert. Ordinary enroll, refresh, and qURL resource CRUD must remain available and must never fall back through this recovery path.
