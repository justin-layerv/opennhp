# 2026-07-29 · HTTP lifecycle retirement

- **Owner:** prod rollout coordinator
- **Source:** this PR; `prancy-mapping-wilkinson` coordinated retirement;
  qurl-service #1336; qurl-go #115; qurl-python #121; qurl-typescript #206

Retire browser-relayed and qurl-service-HTTP Connector lifecycle handling only
after the native-UDP replacement has passed the complete two-client proof.

- [ ] Pre-rollout: require the immutable `pre_removal` aggregate to report
      exactly 68/68 green rows against the reviewed Connector and qurl-go heads.
- [ ] Rollout: merge and deploy this NHP cut with the coordinated qurl-service
      and SDK retirements inside the isolated window; confirm the relay still
      serves browser `KNK`/`RKN`/`EXT`, rejects lifecycle types before waiter or
      server dispatch, and native assigned-cell UDP registration remains
      healthy.
- [ ] Post-rollout: repin affected proof heads and require the identical
      `post_removal` aggregate to report exactly 68/68 green rows before
      releasing qurl-go or qurl-connector.
- [ ] Rollback: if deployment health or post-removal proof fails, redeploy the
      preceding exact NHP and qurl-service images and revert the coordinated
      retirement as a unit; do not partially re-enable relay lifecycle
      forwarding.
- [ ] Cross-repo: do not merge qurl-go #93 or Connector #452 until the
      post-removal aggregate is green and the Connector is repinned to the
      immutable qurl-go release.
