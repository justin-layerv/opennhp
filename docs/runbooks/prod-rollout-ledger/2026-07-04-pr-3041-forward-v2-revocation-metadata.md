# 2026-07-04 · PR #3041 · Native forward qURL v2 revocation metadata

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3041, https://github.com/layervai/nhp/issues/2774

Native `NHP_FWD` messages now carry a narrow qURL v2 admission revocation
sidecar. The wire change is backward-compatible, but targeted revoke coverage for
forwarded flows is complete only after the nhp-server fleet runs this commit or
later.

- [ ] Rollout: deploy nhp-server through the normal canary/prod sequence; mixed
      versions are allowed, but do not treat forwarded qURL-user/admission/session
      revocation coverage as complete until the fleet runs this commit or later.
- [ ] Post-rollout: confirm the deployed server version is active across server
      tasks and the forward path is healthy (`KnockForwardFailure` and
      `ServerForwardTargetDrop` not sustained above baseline).
- [ ] Mixed-version alarm triage: if targeted zero-match alarms fire while the
      fleet is rolling, first check for old native forward senders that cannot
      carry admission revocation metadata. Sustained alarms after the full fleet
      is on this version need normal targeted-revocation investigation.
- [ ] Hash-mismatch triage: the receiver intentionally keeps its catalog
      `resource_public_key_hash` authoritative when it differs from the origin
      admission-verified hash; per-user/session/admission revokes still use the
      forwarded sidecar tuple. Treat `ForwardAdmissionResourceHashMismatch`
      after fleet rollout as stale-catalog or bad-sidecar evidence, and wire
      dashboard/alarm coverage in follow-up #3045. The metric assumes the
      sidecar represents the single admitted resource key for the fan-out peer's
      resolved AC assignment; if future admission flows allow one fan-out to
      cover multiple distinct resource keys, revisit the metric's
      stale-catalog interpretation before alerting on it.
- [ ] Rollback: reverting this PR is safe for admission availability, but native
      forwarded v2 flows return to resource-key-only revoke matching until the
      fix is redeployed.
