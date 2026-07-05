# PR #3048 — qURL AC-open on LOCAL_IP for hostname/arbitrary-URL targets

Fix ships an empty AOP `Addr.Ip` for qv2 (AC substitutes `LOCAL_IP`) so a
hostname/arbitrary-URL qURL target no longer fails the AC eBPF IP parser.

- [ ] Post-rollout: mint a fresh qURL whose target is a hostname / arbitrary URL
      (e.g. `abcnews.com`) and confirm it opens — the AC no longer logs
      `invalid IP address: <host>` / `HandleAccessControl failed`, and the server
      no longer logs `authWithNHPClaims: AC open failed AFTER commit` for it.
- [ ] Post-rollout: note for support — one-time-use links **burned** by the
      pre-fix AC-open failure stay consumed (admission commits before AC-open);
      affected users must re-mint a fresh link after deploy. No server action.
- [ ] Cross-repo contract (qurl-service): the fix keys the pinhole on
      `(LOCAL_IP, ac_routing.dest_port)` with a port-specific TCP rule, so
      `ac_routing.dest_port` MUST remain the AC-ingress / customer-facing port (the
      Traefik-on-AC listener, e.g. 443) — NOT the upstream resource port. A change to
      that field's semantics on the qurl-service side would silently break the pinhole
      match. Keep this invariant documented on the qurl-service `ac_routing` contract.

Delete this file once all three are confirmed post-deploy / acknowledged.
