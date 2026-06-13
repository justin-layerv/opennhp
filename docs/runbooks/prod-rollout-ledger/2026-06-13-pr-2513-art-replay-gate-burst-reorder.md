# 2026-06-13 · PR #2513 · ART replay-gate burst-reorder validation

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/2513 (#1457)

#1457 subjects NHP_ART to the per-connection strict-less-than replay gate.
ART is drop-only (no connection block — `shouldEscalateReplay`), but a dropped
ART still fails its knock, and because ART send-times are stamped by the
concurrent `msgToPacketRoutine` workers, a knock burst can false-drop a
reordered ART with no network reorder. Get a load number behind the "rare"
assumption via `MetricARTReplayGateDrop` before relying on the strict gate.

- [ ] Pre-reliance: stand up a CloudWatch alarm (or at least a dashboard panel)
      on `ARTReplayGateDrop` (namespace `LayerV/NHP`) so a burst-reorder
      availability regression pages rather than requiring a manual metric read —
      tracked alongside the `ARTReplayDetected` security-parity alarm in #2512.
- [ ] Post-rollout: with that alarm/panel live, watch the `ARTReplayGateDrop`
      rate under a multi-knock burst through one AC; a near-zero rate confirms
      the strict gate is safe under real burst load. Note this counter only
      sees matched-transaction (live-knock-affecting) drops by design, so read
      it as the availability-affecting rate, not total gate-drops.
- [ ] Post-rollout: if the rate is non-trivial, loosen the ART replay gate from
      strict `<` to a small monotonic tolerance window (`nhp/core/responder.go`;
      the dedupe cache remains the real replay defense, so sub-window reorder can
      be tolerated without weakening security). Symmetric AOP case: #2518.
