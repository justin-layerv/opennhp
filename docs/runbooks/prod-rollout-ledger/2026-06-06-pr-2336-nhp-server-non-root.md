# 2026-06-06 · PR #2336 · nhp-server container runs as non-root user

- **Owner:** prod rollout coordinator
- **Source:** [#2336](https://github.com/layervai/nhp/pull/2336) · [issue #1090](https://github.com/layervai/nhp/issues/1090)

Runs the nhp-server container as uid 10001. Not yet in prod: a launch-template bump rolled per env (sandbox first, then prod) via instance refresh.

- [x] Pre-rollout: after the sandbox compute-ASG instance refresh (plan/apply doesn't exercise this runtime change), run PR #2336's read-only sandbox runtime validation. _Done/current 2026-06-18: SSM Run Command `e57b5000-f8f2-493d-ba62-813bbbc14b44` against the refreshed sandbox server fleet (3 blue + 1 green instance) showed `nhp-server` active, Docker `User=10001:10001`, Docker health `healthy`, `/nhp-server/etc` mounted read-only, `/opt/layerv/nhp-server/etc/config.toml` mode `600 nhp-server:nhp-server`, TCP 8888 + UDP 62206 bound by `nhp-serverd`, and the server target groups healthy._
- [x] Pre-rollout: run an operator-approved sandbox knock round-trip against refreshed server instances. _Done/current 2026-06-18: narrow sandbox smoke `go test -tags=smoke -v -count=1 -timeout 15m -run '^TestKnock_ReadyConsistentWithUserResolve$' ./...` passed from `tests/smoke`; it reported `knock-ready 200 AND resolve succeeded` for freshly minted qURL traffic through NHP (knock-ready req_id `3ce591a21f9a4440`, resolve req_id `faa2b42cc66f7985`)._
- [ ] Rollout: launch-template bump — roll the `nhp-server` ASG via instance refresh per env (sandbox first, then prod). No data migration, no cross-repo ordering.
- [ ] Post-rollout: confirm prod NHP server `/health` reports this PR's merge-commit image tag and the NLB target group stays healthy through the refresh.
- [ ] Rollback: revert the PR and instance-refresh the `nhp-server` ASG to the prior launch-template version (self-contained to compute `user_data`). AMI-collision failure mode: a base AMI shipping an account at uid/gid 10001 trips the fail-loud `FATAL ... exit 1` guard → crash-loop surfaced by `servers_healthy_low`/target-group alarms; fix by repinning `nhp_server_uid`/`nhp_server_gid` to a free id and re-baking.
- [ ] Follow-ups: PR 2 (Traefik non-root) and PR 3 (nhp-acd non-root) remain open under [#1090](https://github.com/layervai/nhp/issues/1090), each with its own ledger entry.
