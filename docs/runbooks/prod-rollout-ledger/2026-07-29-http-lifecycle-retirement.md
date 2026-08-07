# 2026-07-29 · HTTP lifecycle retirement

- **Owner:** prod rollout coordinator
- **Source:** this PR; `prancy-mapping-wilkinson` coordinated retirement;
  qurl-service #1336; qurl-go #115; qurl-python #121; qurl-typescript #206

Retire browser-relayed and qurl-service-HTTP Connector lifecycle handling once
the native-UDP replacement is covered.

## Proof-aggregate gate withdrawn (2026-08-06)

This entry required the `pre_removal` and `post_removal` UDP proof aggregates to
report 68/68 green. **That gate is withdrawn.** The aggregate is produced by
`udp-proof-controller.yml`, which has never produced a green run: 100 dispatches
since 2026-07-30, 82 failure / 18 cancelled / 0 success.

The withdrawal is not a decision to ship unproven. Every one of those failures
is in the proof scaffolding, upstream of any product assertion — the qurl-go
live proof dies on `aws: command not found` (exit 127; the AWS CLI is not
installed on the ephemeral JIT runner), and the controller dies on JIT
configuration bounds, ready-runner brokering, duplicate dispatch correlation,
and cleanup. The aggregate has never reached the point of evaluating whether
native UDP enrollment works.

The evidence relied on instead is the coverage that does run and does pass:

- nhp `endpoints/server/internal/{connectorcell,connectorhub,connectorauthority}`
  plus `server/hub` — 1482 assertions, green
- qurl-go `relayknock`, `relayknock/internal/nhpwire`, `relayknock/nativeudp` —
  green
- both sides pinned to `qurl-conformance v0.12.0`, so the wire contract is
  tested against shared vectors on both ends

What that coverage does not replace is a live round trip against the deployed
estate. The post-rollout smoke below is now the first such exercise, so treat it
as load-bearing rather than confirmatory.

- [ ] Rollout: merge and deploy this NHP cut with the coordinated qurl-service
      and SDK retirements inside the isolated window; confirm the relay still
      serves browser `KNK`/`RKN`/`EXT`, rejects lifecycle types before waiter or
      server dispatch, and native assigned-cell UDP registration remains
      healthy.
- [ ] Post-rollout (**now the first live round trip, not a confirmation**):
      exercise native assigned-cell UDP enrollment end to end against the
      deployed estate and retain the evidence. A failure here is a real
      regression signal, not a harness artifact.
- [ ] Rollback: if deployment health or post-removal proof fails, redeploy the
      preceding exact NHP and qurl-service images and revert the coordinated
      retirement as a unit; do not partially re-enable relay lifecycle
      forwarding.
- [ ] Cross-repo: do not merge qurl-go #93 or Connector #452 until the
      post-removal aggregate is green and the Connector is repinned to the
      immutable qurl-go release.
