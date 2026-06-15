# 2026-06-15 · qurl-connector#347 · Bootstrap WAF: count-only AmazonIpReputationList

- **Owner:** prod rollout coordinator
- **Source:** this PR (nhp); layervai/qurl-connector#347 (live-sandbox connector smoke); precedent nhp #2306 (resolve-WAF IP-reputation count)

Count-only `AWSManagedRulesAmazonIpReputationList` on the bootstrap ALB WAF in both envs. Its IP-reputation sub-rules categorically false-positive on cloud / hosting / datacenter source IPs — both GitHub-hosted CI runners and real cloud-deployed connector sidecars (AWS Nitro / GCP Confidential Space) — 403'ing legitimate `/v1/agent/bootstrap` at the ALB with no qurl-service log entry. Same fix `qurl_resolve` already uses (#2306); load-bearing defenses (per-API-key 10/hr rate limit + per-source-IP WAF rate limit) still enforce.

- [ ] **Rollout (prod):** apply, then confirm a bootstrap from a cloud/datacenter source IP against `bootstrap.layerv.ai` is no longer ALB-403'd. (Sandbox applies automatically on merge and unblocks the qurl-connector#347 smoke — verify that smoke goes green.)
- [ ] **Cross-repo / future:** when #2238 flips `AnonymousIpList` + `CommonRuleSet` from count-only to enforce, **leave `AmazonIpReputationList` count-only** — it's a durable cloud-edge false-positive carve-out, not a watch-period entry (the prod tfvars comment states this; this entry is the reminder for the #2238 owner).

Delete this file once prod is applied and the #2238 owner is aware of the carve-out.
