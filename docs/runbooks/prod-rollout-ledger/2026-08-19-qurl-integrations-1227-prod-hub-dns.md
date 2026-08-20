# 2026-08-19 · qurl-integrations #1227 · Publish explicit production Hub DNS

- **Owner:** prod rollout coordinator
- **Source:** [qurl-integrations#1227](https://github.com/layervai/qurl-integrations/pull/1227) · [NHP#3913](https://github.com/layervai/nhp/pull/3913)

The source-locked `prod-hub-dns` root stages the explicit Hub alias without
looking up the absent NLB or changing the management-account zone. Activate it
only after production Control's Hub edge is healthy.

- [ ] Pre-rollout: prove `layerv-nhp-prod-hub-edge` exists, is internet-facing,
      has healthy worker targets, and serves UDP 443 -> worker 62206. Record the
      current explicit-record absence and wildcard AC-NLB target as the unsafe
      baseline; wildcard resolution is not Hub proof.
- [ ] Rollout: remove the `hub_dns_enabled` validation source lock and set its
      tfvars value true together in a reviewed PR. From that merged main commit,
      dispatch `prod-hub-dns-update.yml` with `operation=plan-and-apply` and the
      exact `APPLY_PROD_HUB_DNS` confirmation. Review its rendered plan, then
      approve the production-environment apply of the byte-pinned saved plan;
      require one `hub.nhp.layerv.ai` A-alias create targeting only the
      discovered Hub NLB.
- [ ] Post-rollout: read back the explicit Route 53 alias and verify its target
      name/zone ID match the Hub NLB, its answers no longer equal the wildcard
      AC NLB, and a pinned native client reaches the Hub over UDP 443.
- [ ] Rollback: before a pinned CLI release, remove the explicit record with a
      reviewed saved plan. After release, preserve the Hub identity and recover
      the endpoint in place; wildcard fallback to the AC NLB is not a rollback.
