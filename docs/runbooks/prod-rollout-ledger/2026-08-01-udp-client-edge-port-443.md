# 2026-08-01 · UDP client edge moves to port 443

- **Owner:** prod rollout coordinator
- **Source:** [qurl-go PR #124](https://github.com/layervai/qurl-go/pull/124)

Every public NHP UDP listener (cell0, cell1, prod cell, Connector Hub) moves
from UDP 62206 to UDP **443**, the port SDK clients dial. The server's own bind
stays 62206 — the NLB translates listener→target. Prod additionally requires the
qURL-resolve TLS listener to vacate 443 first, because an NLB permits exactly
one listener per port.

This is a hard cutover with no dual-listen window: a client pinned to 62206
stops working the moment the listener moves. qurl-go #124 pins the SDK to 443,
so the SDK release must be out before prod applies.

- [ ] Pre-rollout: confirm qurl-go #124 is merged and released, and that every
      SDK consumer in the fleet is on that release. Confirm no external
      integrator is still pinned to 62206.
- [ ] Pre-rollout (prod only): confirm `enable_resolve_cloudfront = true` is
      still set for prod. The compute module's precondition rejects
      `enable_qurl_resolve_endpoint` without CloudFront, because the resolve
      TLS listener now sits on 8443 and only CloudFront can be pointed at a
      custom origin port. If CloudFront is ever turned off for prod, this apply
      fails closed at plan time rather than silently breaking resolve.
- [ ] Rollout: the prod apply moves `aws_lb_listener.https` 443 → 8443 and
      `aws_lb_listener.udp` 62206 → 443 in one graph. `depends_on` orders the
      TLS listener off 443 first; if that ordering is ever lost the apply fails
      with `DuplicateListener` rather than corrupting the edge. Both are
      in-place `ModifyListener` calls, not replacements.
- [ ] Rollout: expect a bounded outage on the **legacy** `resolve.qurl.link`
      path. The NLB drops 443 immediately, but the CloudFront origin-port change
      takes roughly 5–15 minutes to propagate, so some CF edges will 502 until
      it does. This path is superseded by the browser js-agent (sandbox already
      runs `qurl_link_js_agent_enabled = true`). Native UDP SDK traffic and the
      knock path are not affected by this window.
- [ ] Post-rollout: read back exactly one public UDP listener per cell and on
      the Hub, on port 443, forwarding to the unchanged UDP 62206 target group
      with healthy targets. Confirm the NLB SG admits the proof-runner `/32`
      and the managed AC EIP pool on UDP **443**, while its egress to the server
      SG and the server SG's own rules remain on **62206**.
- [ ] Post-rollout: confirm AC registration reconverges. The AC dials the public
      NLB (`endpoints/ac.DefaultServerPort`), so a stale AC image still on 62206
      will fail registration until it is refreshed.
- [ ] Post-rollout: fetch `resolve.qurl.link` through CloudFront and confirm it
      serves from the 8443 origin.
- [ ] Rollback: revert the PR and re-apply. Both listener moves are in-place, so
      rollback is symmetric — but it re-opens the same CloudFront propagation
      window, and any client already migrated to 443 breaks until the revert
      lands everywhere.
