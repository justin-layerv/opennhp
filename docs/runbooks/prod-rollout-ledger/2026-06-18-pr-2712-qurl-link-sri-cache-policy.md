# 2026-06-18 · PR #2712 · qURL link SRI cache policy

- **Owner:** prod rollout coordinator
- **Source:** [PR #2712](https://github.com/layervai/nhp/pull/2712), [issue #2700](https://github.com/layervai/nhp/issues/2700), [issue #2680](https://github.com/layervai/nhp/issues/2680)

Adds the SRI-pinned qurl.link browser-agent path and replaces the qurl-link CloudFront cache policy with a module-owned policy whose `min_ttl = 0`. Prod keeps `qurl_link_js_agent_enabled = false`, but the next prod apply still performs an in-place qurl.link distribution cache-policy update, so verify that change explicitly.

- [ ] Rollout: during the next prod Terraform apply, confirm the qurl-link CloudFront distribution update is limited to the cache-policy replacement and does not flip `qurl_link_js_agent_enabled` or upload `/nhp-agent.min.js` in prod.
- [ ] Post-rollout: fetch `https://qurl.link/` and confirm prod remains dark: no JS-agent script tag, HTML still serves `Cache-Control: max-age=3600, must-revalidate`, and `/nhp-agent.min.js` is not served as JavaScript.
- [ ] Rollout: when a later prod cutover enables `qurl_link_js_agent_enabled`, confirm qurl.link HTML and `/nhp-agent.min.js` both serve `Cache-Control: no-cache` and the rendered script `integrity` value matches the live bundle SHA-384.
- [ ] Rollback: if the cache-policy replacement causes unexpected edge caching behavior, restore the prior managed cache policy or revert this PR's cache-policy change, invalidate the qurl-link paths, and keep `qurl_link_js_agent_enabled = false` until headers and fallback behavior are verified.
