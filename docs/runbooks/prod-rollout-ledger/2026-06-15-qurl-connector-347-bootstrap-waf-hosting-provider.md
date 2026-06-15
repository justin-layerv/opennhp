# 2026-06-15 · qurl-connector#347 · Bootstrap WAF: count-only HostingProviderIPList

- **Owner:** prod rollout coordinator
- **Source:** this PR (nhp); layervai/qurl-connector#347 (live-sandbox connector smoke)

The bootstrap ALB WAF's `AWSManagedRulesAnonymousIpList` → `HostingProviderIPList`
sub-rule blocks cloud/datacenter source IPs; this PR overrides it to `Count` so
cloud-deployed connectors (AWS Nitro / GCP Confidential Space sidecars) — and the
live-sandbox smoke — can reach `POST /v1/agent/bootstrap`.

- [ ] **Apply to sandbox** — unblocks the qurl-connector live-sandbox smoke
  (layervai/qurl-connector#347), which currently gets the bare `server: awselb/2.0`
  403 from the bootstrap ALB. Confirm the smoke's host + hardened-container
  round-trips go green after apply.
- [ ] **Prod ordering** — this override must be applied to prod **before**
  `bootstrap_alb_waf_count_only_rule_groups` drops `AWSManagedRulesAnonymousIpList`
  (the planned post-watch enforce flip), else `HostingProviderIPList` will 403 every
  cloud-deployed connector. No action needed if applied together: the override is a
  no-op while the group stays whole-group count-only.

Delete this file once both are confirmed.
