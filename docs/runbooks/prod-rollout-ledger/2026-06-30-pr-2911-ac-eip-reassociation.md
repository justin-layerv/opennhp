# 2026-06-30 · PR #2911 · AC EIP reassociation guard

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/2911

Before this fix is considered fully rolled out in prod, verify the serving AC fleet is not already displaced onto EC2 auto-assigned public IPs from the old boot script.

- [ ] Pre-rollout: confirm every serving prod AC instance has a tagged managed EIP from the AC EIP pool.
- [ ] Rollout: if any serving prod AC lacks a managed EIP, refresh/replace that AC or attach an available pool EIP before marking prod healthy.
- [ ] Post-rollout: run the AC EIP smoke fence against prod and record the passing run on PR #2911.
