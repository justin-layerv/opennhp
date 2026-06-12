# 2026-06-12 · Issue #1157 · AC pubkey revocation mid-session sweep

- **Owner:** prod rollout coordinator
- **Source:** [issue #1157](https://github.com/layervai/nhp/issues/1157) · follow-up [#1535](https://github.com/layervai/nhp/issues/1535)

Adds strict-mode mid-session enforcement for `ACAssignment.RevokedPubKeys`: already-connected ACs with revoked pubkeys are removed from `acConnectionMap`, `remoteConnectionMap`, `acPeerMap`, closed, and counted via `ACPubkeyRevokedConnDropped`. The periodic sweep runs only when `NHP_AC_PUBKEY_REVOKE_VERIFY=true`; operators can also trigger the same logic with signed internal `POST /nhp/internal/ac/revocations/sweep`.

- [ ] Pre-rollout: confirm prod is ready for strict `NHP_AC_PUBKEY_REVOKE_VERIFY=true` per `docs/runbooks/f5-revoked-pubkey-paging.md`; do not treat this sweep as active while the gate is still permit-mode.
- [ ] Rollout: deploy NHP server normally. If changing the sweep cadence, set `NHP_AC_PUBKEY_REVOKE_SWEEP_INTERVAL_SECONDS` to a positive integer; unset defaults to 60 seconds and invalid values fail server startup.
- [ ] Post-rollout: confirm `ACPubkeyRevokedConnDropped` is zero during normal traffic. During a planned revocation drill, add one test AC pubkey to `RevokedPubKeys`, call the internal sweep endpoint with the configured `NHP_INTERNAL_AUTH_SECRET`, and confirm exactly one drop plus AC reconnect/reject behavior.
- [ ] Rollback: revert the server image. Removing the code stops mid-session drops; registration-time revocation remains governed by `NHP_AC_PUBKEY_REVOKE_VERIFY`.
- [ ] Follow-ups: codify a CloudWatch alarm on sustained non-zero `ACPubkeyRevokedConnDropped` if operators want revocation-drop pages distinct from the existing `ACPubkeyRevoked` registration signal.
