# 2026-06-19 · PR #2746 · qv1 qURL bootstrap

- **Owner:** prod rollout coordinator
- **Source:** [nhp#2746](https://github.com/layervai/nhp/pull/2746), [qurl-service#991](https://github.com/layervai/qurl-service/pull/991), [qurl-service#990](https://github.com/layervai/qurl-service/issues/990)

This makes qurl.link understand `#qv1.<bundle>` fragments and wires the qurl-service task with `QURL_BROWSER_RELAY_BASE_URL` only when the JS-agent relay path is enabled. The qv1-capable frontend must be live before qurl-service starts minting qv1 links. Treat the qURL link as the bearer secret: possession of the fragment includes the access token and, for qv1 links, the qURL-scoped browser-agent private key.

- [ ] Pre-rollout: confirm this NHP release is deployed in the target environment before enabling qurl-service#991's `QURL_BROWSER_RELAY_BASE_URL`; confirm the rendered qurl.link CSP `connect-src` allows the same relay origin that qurl-service embeds in the bundle.
- [ ] Rollout: when flipping qurl.link JS-agent relay support, confirm the qurl-service task has `NHP_SERVER_PUBLIC_KEY_B64` and `QURL_BROWSER_RELAY_BASE_URL` together, and that the relay URL has no path, query, fragment, or userinfo.
- [ ] Post-rollout: mint a qURL and verify qurl.link clears `#qv1.` and legacy `#at_` fragments from history before verification, uses the bundled private key for the relay knock, rejects a bundle whose `server_public_key_b64` differs from the rendered static key, and maps qurl-service `agent_identity_conflict` to a terminal no-pinhole denial.
- [ ] Post-rollout: confirm the legacy direct-resolve path (`POST /plugins/qurl` with a bare `at_` token, the qurl-service `/internal/v1/resolve` endpoint — distinct from `/internal/v1/browser-relay/resolve`) still accepts a bare-token POST in qv1-enabled envs, so the smoke tests that extract the embedded `at_` token from a qv1 bundle (10/11/15/24) keep passing post-cutover.
- [ ] Capacity/attribution: update qurl-agent-keys capacity expectations for qurl-service#991's one durable key row per newly minted qURL in relay-enabled environments; track qurl-service#990 for any later lifecycle/cardinality decision.
- [ ] Rollback: disable `qurl_link_js_agent_enabled` or unset qurl-service `QURL_BROWSER_RELAY_BASE_URL` to stop minting new qv1 links; existing qv1 links require this qv1-capable frontend until revoked or expired.
