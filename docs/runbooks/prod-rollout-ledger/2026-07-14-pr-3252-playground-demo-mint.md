# 2026-07-14 · PR #3252 · Playground fixed-resource demo mint (hidden-app LiveDemo)

- **Owner:** prod rollout coordinator
- **Source:** [#3252](https://github.com/layervai/nhp/pull/3252) · full cross-repo activation sequence: [layervai/website#676](https://github.com/layervai/website/pull/676)

Ships dark (all `developer_portal_demo_*` variables default empty in every env). The connector host + page are website-side (layervai/website#672/#676); this entry covers only this repo's rollout tasks — the demo-mint Lambda + its tfvars.

- [ ] Rollout: after the website connector creates the `hidden-app` resource, set `developer_portal_demo_target_url = "https://hidden-app.layerv.ai"` (byte-for-byte the LiveDemo constant), `developer_portal_demo_resource_id = "<resource id>"`, `developer_portal_demo_qurl_site = "https://<resource id>.qurl.site"` in `terraform/environments/prod/terraform.tfvars` and apply. All three must be set together (plan-time precondition).
- [ ] Pre-flip proof: `POST /v1/qurls/{resource_id}/mint_link` with `{"expires_in":"30m","one_time_use":true}` (not an empty body) returns 201 with a `qurl_link` — verifies the prod image honors both fields and the M2M account owns the resource.
- [ ] Post-rollout: `POST https://devapi.layerv.ai/playground/qurl` with `{"target_url":"https://hidden-app.layerv.ai","expires_in":"30m","one_time_use":true}` returns a real `qurl_link` that renders the page; a second open shows "Access link invalid"; `DELETE /playground/qurl/<resource id>` returns 403.
- [ ] Post-rollout: confirm the `<name_prefix>-playground-demo-mint-failures` alarm exists and routes — the only signal that the live demo degraded to simulated links. Note: it covers the LiveDemo client path (`handle_demo_mint`) only; a demo-id mint via the sibling `POST /playground/qurl/{id}/mint` route is not counted, so don't repoint the demo at that route without adding coverage.
- [ ] Rollback: empty the three tfvars and re-apply — the demo path disables and the LiveDemo falls back to its client-side simulated links (today's behavior).
- [ ] Sandbox (optional, after the staging hidden-app connector exists — blocked on qurl-service#1225 routing-id chain): same three writes in `terraform/environments/sandbox/terraform.tfvars`.
