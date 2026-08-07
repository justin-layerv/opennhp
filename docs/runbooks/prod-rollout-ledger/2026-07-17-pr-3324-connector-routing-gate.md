# 2026-07-17 · PR #3324 · Connector routing identity cutover gate

- **Owner:** prod rollout coordinator
- **Source:** [NHP #3739](https://github.com/layervai/nhp/pull/3739), [NHP #3275](https://github.com/layervai/nhp/issues/3275), [traefik-plugins #246](https://github.com/layervai/traefik-plugins/pull/246), [qurl-connector v0.7.1](https://github.com/layervai/qurl-connector/releases/tag/v0.7.1)

PR #3739 proves the current `connector_routing_id` contract in sandbox before production promotion. Keep ordinary `*.qurl.site` Connector admission closed until every producer and consumer uses that identity; the startup-only gate must never differ across an admitted Access Controller fleet.

- [ ] Pre-rollout: verify the current qurl-service producer is deployed on every API host, the selected qurl-connector release registers the exact producer-issued `connector_routing_id`, and traefik-plugins #246 is deployed on every Access Controller with the default-off `requireConnectorRoutingID` posture (the field is absent until enabled); record the exact deployed SHAs and largest `negativeCacheTtl`.
- [ ] Rollout: with Connector admission still closed, set `require_connector_routing_id=true`, apply the launch-template change, then perform the normal whole-fleet AC restart/rollout and verify the rendered `requireConnectorRoutingID=true` plus the expected plugin SHA on every AC before opening admission.
- [ ] Post-rollout: smoke a real ordinary `*.qurl.site` Connector route through every AC and prove the exact producer-issued routing identity is used for FRP Host and active-upstream routing without exposing that private routing identity downstream.
- [ ] Rollback: close Connector admission and qurl-service `CONNECTOR_AUTH_ENABLED`, stop `c-...`-registered Connector workloads, set `require_connector_routing_id=false`, and restart/verify the entire AC fleet to clear route and negative caches before rolling back the Connector, plugin/config, and qurl-reverse-tunnel-server; roll back qurl-service last.
- [ ] Cross-repo: keep custom-domain serving dark unless traefik-plugins #237 and its matching qurl-service producer have been separately deployed and proven; attach rollout and rollback evidence to the linked tracking issues before deleting this ledger entry.
