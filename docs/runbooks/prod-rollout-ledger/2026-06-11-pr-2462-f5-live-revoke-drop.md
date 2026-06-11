# 2026-06-11 · PR #2462 · F5 live revoke drop

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/2462 · https://github.com/layervai/nhp/issues/1535 · https://github.com/layervai/nhp/issues/1543

Deploys the strict-gated F5 live-drop sweeper and private internal sweep endpoint. This PR does not flip `NHP_AC_PUBKEY_REVOKE_VERIFY`; destructive drops remain gated on strict mode, DynamoDB storage, and a non-zero sweep interval.

- [ ] Post-rollout: after the server deploy, confirm startup logs report the `NHP_AC_PUBKEY_REVOKE_SWEEP_INTERVAL_SECONDS` parse result and whether the mid-session sweeper started or stayed disabled by permit mode.
- [ ] Post-rollout: smoke the private, signed internal sweep endpoint from the prod internal network; expect `409` while F5 strict mode is still off, or `200` with zero drops and no `truncated` field if strict mode is already on and no revoked live ACs match.
- [ ] Follow-up before any prod F5 strict flip: complete #1543 alarm coverage, now including `ACPubkeyRevokedConnDropped`.
- [ ] Rollback: revert this PR and redeploy the server if the sweeper or endpoint causes unexpected auth, storage, or connection-lifecycle regressions. As an immediate mitigation for only the background path, set `NHP_AC_PUBKEY_REVOKE_SWEEP_INTERVAL_SECONDS=0`.
