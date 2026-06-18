# 2026-06-05 · PR #2354 · Cross-server forward hop attestation (#1127)

- **Owner:** prod rollout coordinator
- **Source:** [#2354](https://github.com/layervai/nhp/pull/2354) · [#1127](https://github.com/layervai/nhp/issues/1127)

Binds each server-to-server `/nhp/internal/knock` forward to the forwarding
server's NHP identity via an ECDH per-pair MAC, gated by
`NHP_INTERNAL_FORWARD_ATTEST_REQUIRE` (permit default). Ships permit-mode; the
strict flip is a deliberate later step. Design:
[`docs/design/INTERNAL_FORWARD_HOP_ATTESTATION.md`](../../design/INTERNAL_FORWARD_HOP_ATTESTATION.md).

- [x] Pre-rollout: deploy permit-mode fleet-wide first (a strict receiver rejects an un-attesting older sender). Confirm every server exposes `PUBLIC_KEY` in Cloud Map and that storage `ServerInfo.PubKey` == Cloud Map `PUBLIC_KEY` == device key (the dual-registry invariant — a divergence shows up only as `ForwardHopAttestPermit` that never drains). _Done/current 2026-06-18: prod Cloud Map service `server.nhp.prod.internal` advertises `PUBLIC_KEY=e4cvt8Il90hResvhyawFqhgXqbi2Qddlqa3Iy0vPniU=` for all three prod server instances, prod `layerv-nhp-prod-cell0-ac-assignments` stores the same pubkey for assigned servers, and the prod server Secrets Manager JSON (`layerv-nhp-prod-server`) exposes the same public half of the device key. Narrow prod SSM Run Command `210f90f7-a40d-44fd-931e-b8ab0c5ebee5` showed all three server instances still run permit mode (`NHP_INTERNAL_FORWARD_ATTEST_REQUIRE=UNSET_DEFAULT_PERMIT`) with `NHP_INTERNAL_AUTH_REQUIRE=true`; a prior log sweep (`5b5c12f2-d5d6-4a6d-9c7f-95c25b78f891`) showed peer advertisements carrying the same `serverPubKey`. Sandbox evidence matched the same invariant for its fleet (`PUBLIC_KEY` / assignment pubkey `9dVku2oF589tWz9/Hn01STtstgkum4MM4kgKEp7lCw8=`, SSM Run Command `def2b5e3-d0f0-4334-94c7-d45b92ebcdd3`, permit default)._
- [ ] Rollout: flip `NHP_INTERNAL_FORWARD_ATTEST_REQUIRE=true` only after burn-in (below) AND after #2389 wires the env var through terraform — until then a flip is a manual env edit, not a reviewed tfvar change. Flip #1122 (`NHP_INTERNAL_AUTH_REQUIRE`) strict before trusting `ForwardHopCeilingReject` as a loop signal (its hop-range check runs pre-trust/MAC, so it's drivable while #1122 is permit). Under strict, sequence capacity changes so a freshly-joined target's pubkey propagates to forwarders before it receives forwarded knocks (else transient `knock_forward` 401s).
- [ ] Post-rollout: confirm `ForwardHopAttestPermit` holds at zero across a stable window while `ForwardHopAttestSuccess` is non-zero (corroborate against `KnockForwardSuccess`); `ForwardHopAttestReject` and `ForwardHopCeilingReject` stay zero.
- [ ] Rollback: set `NHP_INTERNAL_FORWARD_ATTEST_REQUIRE=false` (back to permit) without redeploying — the receiver then warns-and-allows.
- [ ] Follow-ups: [#2389](https://github.com/layervai/nhp/issues/2389) (terraform passthrough for the strict flip); [#1223](https://github.com/layervai/nhp/issues/1223) (internal-knock replay-cache, complements the residual). #1127 stays open — this "Addresses" (not "Fixes") it; the `Source="api"` origin-spoof residual is out of scope.
