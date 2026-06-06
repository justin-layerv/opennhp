# 2026-06-06 · PR #2336 · nhp-server container runs as non-root user

- **Owner:** prod rollout coordinator
- **Source:** [#2336](https://github.com/layervai/nhp/pull/2336) · [issue #1090](https://github.com/layervai/nhp/issues/1090)

Runs the nhp-server container as uid 10001. Not yet in prod: a launch-template bump rolled per env (sandbox first, then prod) via instance refresh.

- [ ] Pre-rollout: after the sandbox compute-ASG instance refresh (plan/apply doesn't exercise this runtime change), run PR #2336's sandbox functional validation. Highest-signal checks: `docker inspect nhp-server` shows process user `10001`; the server reads its 0600 `config.toml` from the `:ro` mount and binds 8888/TCP + 62206/UDP; knock round-trip succeeds; Docker HEALTHCHECK is `healthy`. Full list (config/log/secrets perms, etcd-path TLS) in the PR.
- [ ] Rollout: launch-template bump — roll the `nhp-server` ASG via instance refresh per env (sandbox first, then prod). No data migration, no cross-repo ordering.
- [ ] Post-rollout: confirm prod NHP server `/health` reports this PR's merge-commit image tag and the NLB target group stays healthy through the refresh.
- [ ] Rollback: revert the PR and instance-refresh the `nhp-server` ASG to the prior launch-template version (self-contained to compute `user_data`). AMI-collision failure mode: a base AMI shipping an account at uid/gid 10001 trips the fail-loud `FATAL ... exit 1` guard → crash-loop surfaced by `servers_healthy_low`/target-group alarms; fix by repinning `nhp_server_uid`/`nhp_server_gid` to a free id and re-baking.
- [ ] Follow-ups: PR 2 (Traefik non-root) and PR 3 (nhp-acd non-root) remain open under [#1090](https://github.com/layervai/nhp/issues/1090), each with its own ledger entry.
