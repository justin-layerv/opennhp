# 2026-06-02 · PR #2306 · Resolve WAF IP-reputation count + logging

- **Owner:** prod rollout coordinator
- **Source:** [#2306](https://github.com/layervai/nhp/pull/2306)

Switches the resolve WebACL's `AWSManagedRulesAmazonIpReputationList` rule to `Count` (override) and adds WAF logging. Not yet in prod: applied via promote with `run_terraform=true`.

- [ ] Rollout: validate in sandbox first, then promote with `run_terraform=true`. WARNING: this applies the ENTIRE pending prod terraform diff (last-apply `c9db0f19` → HEAD, incl. auth0 + ACME/cert-lambda drift) — coordinate with the broader split-state recovery, not as an isolated WAF apply.
- [ ] Rollout: watch the first apply for a WAF→CloudWatch-Logs resource-policy size error on the new `aws-waf-logs-layerv-nhp-{prod,sandbox}-resolve` group (shared 5120-char AWS-managed policy); if hit, prune `aws-waf-logs-*` destinations or switch delivery to S3/Firehose.
- [ ] Post-rollout (authoritative config proof): `aws wafv2 get-web-acl` → confirm the IP-reputation rule `OverrideAction` is `Count`; `get-sampled-requests` on metric `<env>-resolve-ip-reputation` shows matches `action=COUNT`, request allowed.
- [ ] Post-rollout: re-run `QURL Smoke Tests (prod)` (`TestQURLEndToEndFlow`, `TestMultiInstance_*`, `TestCustomDomain_EndToEnd_ResolveAndProxy`) — supporting evidence only (IP-dependent, runner IPs are dynamic).
- [ ] Post-rollout: confirm WAF logging delivers to `aws-waf-logs-layerv-nhp-prod-resolve` (us-east-1) with the `token` query string redacted; review count labels to decide Block-vs-narrow ([#2308](https://github.com/layervai/nhp/issues/2308), owner + deadline before next release cut).
- [ ] Rollback: set `resolve_waf_ip_reputation_block = true` (or revert the PR) and apply; no data migration or refresh.
- [ ] Follow-ups: [#2308](https://github.com/layervai/nhp/issues/2308) (permanent count-vs-block fate), [#2307](https://github.com/layervai/nhp/issues/2307) (tfsec/checkov CI + justified us-east-1 KMS-omission suppression); optional us-east-1 CMK for the log group.
