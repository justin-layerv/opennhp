# 2026-08-03 · PR #3693 · NHP protocol 1.1 header binding

- **Owner:** prod rollout coordinator
- **Source:** layervai/nhp#3693, layervai/qurl-conformance#71, layervai/qurl-go#130

NHP 1.1 authenticates the packet header in the body AAD. It is a **hard cutover**:
1.0 and 1.1 cannot talk to each other **in either direction**, by decision, with no
compatibility mode.

- A 1.1 receiver **rejects** a 1.0 sender at the version gate
  (`ErrUnsupportedProtocolVersion`, 32022).
- A 1.0 receiver **cannot open** a 1.1 sender's packet — the body AAD does not
  match and the AEAD fails.

There is therefore **no deploy order that avoids breakage.** The moment the fleet
flips to 1.1, every 1.0 sender still in the field fails until it is upgraded. Do
not plan this rollout as if sequencing makes it safe; plan it to make the broken
window as short as possible and to know exactly who is in it.

**Who is in the broken window**

- **Cached qurl-link browser bundles** — self-healing. Users recover on the next
  fetch of `nhp-agent.min.js`. Bounded by cache TTL, so publish the new bundle
  immediately after the fleet, not hours later.
- **Customer-deployed qurl-go agents** — NOT self-healing. `github.com/layervai/qurl-go`
  is published on the Go proxy (v0.1.0, v0.1.1, v0.2.0). Those are compiled into
  customer binaries and only recover when the customer rebuilds against the 1.1
  SDK and redeploys. This outage is unbounded and ends on their schedule, not ours.

- [ ] Pre-rollout: confirm qurl-conformance >= v0.12.0 is released and
      `endpoints/go.mod` pins it.
- [ ] Pre-rollout: **measure the field before flipping.** Check which qurl-go SDK
      versions are actually knocking the fleet. If any customer is on <= v0.2.0,
      they go dark at cutover — decide deliberately whether to notify them first.
- [ ] Pre-rollout: the fleet is a long way behind main (last standalone prod
      canary was 2026-06-01; the scheduled-release pipeline was retired
      in PR #3864 — prod ships only via `trigger-prod-deploy.sh`). Get prod
      current on main and
      verify **before** adding a breaking protocol change, or 1.1 ships buried in
      a very large combined delta and any failure is unattributable.
- [ ] Rollout: deploy the server, relay and AC fleet, then publish the
      regenerated `terraform/modules/qurl-link/frontend/nhp-agent.min.js` and its
      SRI **immediately after**. Fleet marginally first so a freshly-fetched 1.1
      bundle always finds a 1.1 receiver; the gap between the two is the browser
      outage window, so keep it minutes, not hours.
- [ ] Post-rollout: watch `ErrUnsupportedProtocolVersion` (32022) in server logs.
      A decaying rate is cached 1.0 bundles draining as expected. A **flat,
      non-decaying** rate is a customer agent stuck on an old SDK — that will not
      resolve on its own and needs an outbound conversation.
- [ ] Rollback: roll back senders before receivers — bundle and SRI first, then
      the fleet. Rolling back the fleet alone strands every 1.1 sender already
      fetched.
- [ ] Cross-repo: layervai/qurl-go#130 must merge and release so customers have a
      1.1 SDK to rebuild against. Ship it as close to the fleet cutover as
      possible — until it exists, a broken customer has nothing to upgrade to.
