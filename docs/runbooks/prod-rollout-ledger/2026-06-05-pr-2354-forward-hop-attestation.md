# 2026-06-05 · PR #2354 · Cross-server forward hop attestation (#1127)

- **Owner:** prod rollout coordinator
- **Source:** [#2354](https://github.com/layervai/nhp/pull/2354) · [#1127](https://github.com/layervai/nhp/issues/1127)

Binds each server-to-server `/nhp/internal/knock` forward to the forwarding
server's NHP identity via an ECDH per-pair MAC, gated by
`NHP_INTERNAL_FORWARD_ATTEST_REQUIRE` (permit default). Ships permit-mode; the
strict flip is a deliberate later step. Design:
[`docs/design/INTERNAL_FORWARD_HOP_ATTESTATION.md`](../../design/INTERNAL_FORWARD_HOP_ATTESTATION.md).

- [ ] Pre-rollout: deploy permit-mode fleet-wide first (a strict receiver rejects an un-attesting older sender). Confirm every server exposes `PUBLIC_KEY` in Cloud Map and that storage `ServerInfo.PubKey` == Cloud Map `PUBLIC_KEY` == device key (the dual-registry invariant — a divergence shows up only as `ForwardHopAttestPermit` that never drains).
- [ ] Rollout: flip `NHP_INTERNAL_FORWARD_ATTEST_REQUIRE=true` only after burn-in (below) AND after #2389 wires the env var through terraform — until then a flip is a manual env edit, not a reviewed tfvar change. Flip #1122 (`NHP_INTERNAL_AUTH_REQUIRE`) strict before trusting `ForwardHopCeilingReject` as a loop signal (its hop-range check runs pre-trust/MAC, so it's drivable while #1122 is permit). Under strict, sequence capacity changes so a freshly-joined target's pubkey propagates to forwarders before it receives forwarded knocks (else transient `knock_forward` 401s).
- [ ] Post-rollout: confirm `ForwardHopAttestPermit` holds at zero across a stable window while `ForwardHopAttestSuccess` is non-zero (corroborate against `KnockForwardSuccess`); `ForwardHopAttestReject` and `ForwardHopCeilingReject` stay zero.
- [ ] Rollback: set `NHP_INTERNAL_FORWARD_ATTEST_REQUIRE=false` (back to permit) without redeploying — the receiver then warns-and-allows.
- [ ] Follow-ups: [#2389](https://github.com/layervai/nhp/issues/2389) (terraform passthrough for the strict flip); [#1223](https://github.com/layervai/nhp/issues/1223) (internal-knock replay-cache, complements the residual). #1127 stays open — this "Addresses" (not "Fixes") it; the `Source="api"` origin-spoof residual is out of scope.
