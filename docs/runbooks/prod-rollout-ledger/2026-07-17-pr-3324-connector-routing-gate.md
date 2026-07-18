# 2026-07-17 · PR #3324 · Connector routing identity cutover gate

- **Owner:** prod rollout coordinator
- **Source:** [NHP #3275](https://github.com/layervai/nhp/issues/3275), [traefik-plugins #246](https://github.com/layervai/traefik-plugins/pull/246), [qurl-connector #421](https://github.com/layervai/qurl-connector/issues/421)

Keep ordinary `*.qurl.site` Connector admission closed while the additive producer and default-off consumers deploy. The startup-only gate must never differ across an admitted Access Controller fleet.

- [ ] Pre-rollout: verify qurl-service #1225 is deployed on every API host, the native-UDP Connector tracked by qurl-connector #421 is staged with exact producer-issued `connector_routing_id`, and traefik-plugins #246 is deployed on every Access Controller with the default-off `requireConnectorRoutingID` posture (the field is absent until enabled); record the exact deployed SHAs and largest `negativeCacheTtl`.
- [ ] Rollout: with Connector admission still closed, set `require_connector_routing_id=true`, apply the launch-template change, then perform the normal whole-fleet AC restart/rollout and verify the rendered `requireConnectorRoutingID=true` plus the expected plugin SHA on every AC before opening admission.
- [ ] Post-rollout: smoke a real ordinary `*.qurl.site` Connector route through every AC and prove the exact producer-issued routing identity is used for FRP Host and active-upstream routing without exposing that private routing identity downstream.
- [ ] Rollback: close Connector admission and qurl-service `CONNECTOR_AUTH_ENABLED`, stop `c-...`-registered Connector workloads, set `require_connector_routing_id=false`, and restart/verify the entire AC fleet to clear route and negative caches before rolling back the Connector, plugin/config, and qurl-reverse-tunnel-server; roll back qurl-service last.
- [ ] Cross-repo: keep custom-domain serving dark unless traefik-plugins #237 and its matching qurl-service producer have been separately deployed and proven; attach rollout and rollback evidence to the linked tracking issues before deleting this ledger entry.
