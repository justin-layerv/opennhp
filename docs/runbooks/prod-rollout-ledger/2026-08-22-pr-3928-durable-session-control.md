# 2026-08-22 · PR #3928 · Durable session control

- **Owner:** prod rollout coordinator
- **Source:** [NHP #3928](https://github.com/layervai/nhp/pull/3928), [qurl-go #193](https://github.com/layervai/qurl-go/pull/193)

Production is one coordinated release, not a multi-day flag rollout. Terraform,
the real-flush AC fleet, the durable server authority, and the session-aware SDK
must advance as one attended change; the workflow orders AC before server.

- [ ] Pre-rollout: record the exact NHP and qurl-go release SHAs; confirm the sandbox real-flush session-close, direct knock, forwarded knock, restart recovery, and qurl Connector journeys are green with every L3/session-control alarm OK.
- [ ] Pre-rollout: review a refresh-enabled production Terraform plan showing `enable_l3_flush_on_expiry=true`, `l3_flush_dry_run=false`, `l3_flush_real_mode_acknowledged=true`, the session-control DynamoDB table/indexes/IAM, and no unrelated destroy or replacement outside the expected AC/server launch and canary graph.
- [ ] Pre-rollout: confirm both server colors remain at `max_capacity=10` (20 possible Cloud Map registrations, 80 entries below the non-pageable 100-result ceiling) and that the existing Cloud Map register-failure, refresh-failure, and refresh-heartbeat alarms are `OK`. The Terraform module rejects any future per-color maximum above 40.
- [ ] Rollout: dispatch one attended production promote with Terraform, AC, server, relay, and required qURL components selected. Confirm Terraform completes, Traefik plugins publish, every AC canary/fleet member reaches real-flush readiness, and only then the server canary/fleet advances.
- [ ] Post-rollout: run the production-safe direct, forwarded/fanout, exact-close, reconnect/recovery, and qurl Connector CLI journeys; confirm durable session work drains and L3 flush totals rise while errors, drops, breaker-open, wait-timeout, corruption, and stale-authority metrics remain zero.
- [ ] Rollback: stop new admission first, restore the prior server and AC images together, revert all three L3 values together, and apply/refresh the fleet. Do not leave a durable-session server serving against an AC fleet without a real flusher; retain the session-control table for forensic recovery until the rollback is verified.
- [ ] Cross-repo: publish and deploy the matching qurl-go/qurl Connector releases only with the coordinated backend release, then record their exact tags and smoke evidence on the source PRs before deleting this entry.
