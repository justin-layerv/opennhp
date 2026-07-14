# 2026-06-10 · PR #2457 · Public status page rollout

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/2457

This release replaces the internal ops dashboard at status.layerv.ai with the
public customer-facing status page. Uptime history accumulates from first
deploy, so the bars start gray and fill in.

- [ ] Pre-rollout: confirm no external monitor or integration still polls the
      old direct API Gateway `/status` URL as its high-fanout path; direct
      compatibility API callers are intentionally throttled to 2 rps / burst 3
      and should migrate polling to the CloudFront/S3 `status.json` path. The
      Lambda reserved concurrency of 5 is sized as API burst 3 plus two async
      slots for a scheduled snapshot and incident publish; revisit the throttle
      and reserved pool together before supporting higher direct-API traffic.
- [ ] Pre-rollout: confirm prod Lambda account concurrency headroom before
      apply. The status aggregator reserves 5 executions, so the account must
      have enough unreserved concurrency after all existing reserved functions
      for other prod Lambdas to keep their expected burst capacity.
- [x] Pre-rollout: confirmed status-probe UA/WAF reachability on 2026-07-08
      with `User-Agent: LayerV-StatusPage/2.0`. Prod and sandbox `website`
      plus `qurl_link` returned HEAD and GET 200. Prod and sandbox `qurl_api`
      returned HEAD 404, then the Lambda's 4xx-HEAD fallback path returned
      ranged GET 200.
- [ ] Post-rollout: status.layerv.ai renders the new page (CloudFront TTL is
      60s) and `GET /status` returns only the public payload keys
      (environment, timestamp, overall, components with id/status/display_only,
      history, incidents).
- [ ] Post-rollout: confirm the public `qurl_link` tile is green and the live
      qURL Link `/index.html` shell answers the Lambda user agent with HEAD or
      ranged/plain GET 2xx/3xx so launch does not start with a permanently amber
      qURL Links component.
- [ ] Post-rollout: confirm the display-only `website` tile is green and
      `https://layerv.ai/` answers the `LayerV-StatusPage/2.0` Lambda user agent
      with HEAD or ranged/plain GET 2xx/3xx. This tile is excluded from the
      customer-facing overall rollup, but a sustained probe failure still pages
      the NHP on-call.
- [ ] Post-rollout: within ~15 minutes the EventBridge snapshot writes
      `history.json` into the status page bucket and today's uptime bars
      begin filling.
- [ ] Post-rollout: confirm the compatibility API access log group
      `/aws/apigateway/layerv-nhp-prod-status` exists and receives an entry
      after a direct `GET /status` smoke.
- [ ] Post-rollout: if prod is blue/green for server or AC, confirm the
      status aggregator reads the corresponding active-color SSM parameter and
      the public `nhp_server` / `nhp_ac` tiles reflect only the active public
      target group, not idle-color target health.
- [ ] Post-rollout: confirm the `layerv-nhp-prod-status-snapshot-*` alarms
      are OK after the first three scheduled snapshots land; the invocation-gap
      alarm treats missing data as breaching, so initial deploy-time ALARM state
      is expected until enough samples exist.
- [ ] Recovery note: if logs report malformed `history.json`, current status
      publication continues and the Lambda starts a fresh history window; inspect
      logs/backups if you need to recover prior uptime bars.
- [ ] Rollback: revert the PR and re-promote; the prior internal dashboard
      returns. `history.json` / `incidents.json` left in the bucket are
      harmless.
