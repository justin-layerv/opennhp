# 2026-06-10 · PR #2450 · Cross-server knock forwarding repaired (per-resource resId)

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/2450 · follow-up alarm https://github.com/layervai/nhp/issues/2449

Re-animates a server-to-server HTTP knock forward path that had **never
successfully executed in prod** (every forward 400'd "missing aspId or resId").
After deploy, servers will begin making cross-server forward calls for the first
time. Hop-attestation mode is **permit** (`NHP_INTERNAL_FORWARD_ATTEST_REQUIRE`
unset), so no flag flip is required and a mixed-version fleet keeps forwarding.

- [ ] Post-rollout: confirm forwarding now succeeds — `KnockForwardSuccess`
      (LayerV/NHP) climbs above zero and `KnockForwardFailure` does **not** show
      a sustained nonzero stream after the fleet is fully rolled.
- [ ] Post-rollout: confirm the user-visible symptom drops — `KnockNoAC` and
      `resolve` 500s with `ErrACConnectionNotFound (52003)` fall during/after a
      blue/green roll (this is the churn window the bug fired in).
- [ ] Post-rollout: confirm `ForwardHopAttestPermit` does not spike (a spike
      would mean the dual-registry pubkey invariant diverged now that real
      forwards carry attestations — see PR #2354 ledger / design doc).
- [ ] Rollback: revert PR #2450 — restores the prior (broken-but-masked)
      behavior. Safe: consumers (qurl-service) already retry, and resolves still
      land on local-AC servers most of the time. No data/migration impact.
- [ ] Follow-up (does not block this rollout): #2449 — add an alarm on
      `KnockForwardFailure` / sustained `KnockNoAC` so a future forward
      regression pages instead of hiding.
