# 2026-07-05 · PR #3050 · AC qURL readiness health check

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3050

Changes the public AC TLS/qURL target groups from Traefik `/ping` liveness to
`nhp-acd` admission readiness (`/nhp-ac/ready`) so the NLB only routes qURL
browser traffic to ACs with a recently confirmed assigned-server path. Requires
Terraform apply plus AC instance refresh because the target-group health-check
path and Traefik route are in Terraform/user data, while the readiness handler is
in the AC binary. The target-group `health_check.path` updates in place, so the
route must be present on AC instances before the public qURL target groups depend
on it.

The readiness signal is intentionally internal, not secret: anything allowed by
the VPC-only Traefik health-check security-group rule can observe a target's
server-connectivity state on port 8080. Public `:443` must keep returning the
constant hidden 404 for the same path.

Correctness depends on the current qURL fanout contract, not merely on target
health: `endpoints/server/httpserver.go::handleHttpOpenResource` uses
`HttpKnockForwarder.FanoutHttpKnock` to cover assigned peer servers,
`endpoints/server/udpserver.go::handleNhpOpenResource` does the same for the
native/relay path, and `processACOperationBroadcast` sends AOP to all local AC
connections before the origin ACK is released when knock fanout is enabled. If
that contract changes to targeted per-AC admission, `/nhp-ac/ready` is no longer
sufficient by itself.

- [ ] Pre-rollout (sandbox, REQUIRED): stage the AC build/user data before the
      target-group path cutover. Refresh/canary the AC instances (or the
      blue/green standby color before switch) until each candidate public target
      serves `GET /nhp-ac/ready` on port 8080 while the active qURL target group
      still has a healthy path. Do **not** run a full apply that flips the active
      `ac_tcp` path against old instances; old user data returns 404 for
      `/nhp-ac/ready`, and all active targets can go unhealthy after ~90s.
      Because the AC ASGs intentionally use EC2 health checks, instance refresh
      will not wait for `/nhp-ac/ready`; this readiness gate is a required
      operator check before cutover, not an ASG-enforced condition. Record the
      real ASG instance-refresh `min_healthy_percentage`, fleet size, and TG
      deregistration timing, and confirm they preserve at least one
      readiness-healthy public target throughout the refresh.
- [ ] Rollout (sandbox): after the readiness route is confirmed on the
      instances that will receive qURL traffic, apply/complete the target-group
      path cutover and confirm `ac_tcp` and `ac_tcp_green` health checks use
      `/nhp-ac/ready` on port 8080 while `ac_frps_control*` remain on `/ping`.
- [ ] Post-rollout (sandbox): explicitly probe the Traefik health-check
      entrypoint on port 8080. A healthy AC must return 200 with `ready`; an AC
      with no fresh assigned-server path must return 503 with
      `no healthy assigned server`. This confirms the path-only change from
      `/ping` to `/nhp-ac/ready` still traverses the existing Traefik entrypoint
      correctly and that the intended fail-closed transition is observable.
- [ ] Post-rollout (sandbox): verify every active public AC target is healthy,
      `ServersHealthy` is >=1 per target in steady state, and a freshly minted
      qv2 link completes qurl.link verification and commits the
      `r_*.qurl.site.layerv.xyz` navigation without SYN denies on the selected AC.
- [ ] Post-rollout (sandbox): from an admitted qURL client path, hit
      `https://r_*.qurl.site.layerv.xyz/nhp-ac/ready` on public `:443` and
      confirm it returns the hidden constant 404, while the NLB health check on
      port 8080 returns 200 only for ACs with a fresh assigned-server path. This
      proves the public route does not expose the readiness bit.
- [ ] Post-rollout (sandbox): confirm the active public target-group
      no-healthy-targets alarm (`*-ac-tg-no-healthy`) exists, uses the
      `HealthyHostCount` `Maximum < 1` predicate ("no enabled AZ has a healthy
      target"), treats missing data as breaching, routes to an actually paged
      SNS destination, and stays OK. When blue/green is enabled, this alarm uses
      `FILL(blue, 0) + FILL(green, 0)` metric math over blue+green target
      groups so an inactive cold/drained standby color contributes zero instead
      of a missing breaching datapoint while another color has healthy public AC
      capacity. Confirm this missing-standby-metric case in sandbox before prod
      by draining/scaling the standby color to zero, or by an equivalent
      CloudWatch `get-metric-data` evaluation against one healthy color plus one
      no-registered-target color. Also confirm the green target-group
      no-healthy alarm is desired-capacity-aware: it must stay OK when green
      desired capacity is zero, and it must alarm when green desired capacity is
      positive but the green target group has no healthy targets. The
      `Maximum < 1` health predicate intentionally will not page for a single-AZ
      green drain while another AZ still has healthy green targets; verify
      on-call accepts that sensitivity tradeoff before prod.
- [ ] Post-rollout (sandbox, REQUIRED before prod): during a normal server
      blue/green or registration flip, confirm the active AC fleet never reaches
      zero healthy assigned-server paths; the new target health deliberately
      removes ACs with no assigned-server path from public qURL rotation. This
      is the single most important prod gate for this PR because the readiness
      predicate's fresh-server window is 30s.
- [ ] Prod sign-off (REQUIRED): DE/on-call explicitly accepts the availability
      tradeoff before prod. This fail-closed gate can remove all public AC
      targets during a correlated server-registration/keepalive outage, and the
      NLB demotion window (`interval=30s`, `unhealthy_threshold=3`) mitigates
      sustained server-path loss rather than sub-90s blips. The
      `*-ac-tg-no-healthy` alarm uses `period=60s`, `evaluation_periods=2`, so
      page-worthy detection can lag complete target loss by about one additional
      minute after NLB demotion; record explicit acceptance of that detection
      lag, the signer, and the accepted rollback trigger in this ledger before
      prod cutover.
- [ ] Rollout (prod): promote with the same staged ordering after sandbox
      validation: AC build/user data first, then target-group path cutover, then
      qv2 public qURL ingress validation. Do not apply the health-check path
      cutover as a standalone full apply against old active AC instances.
- [ ] Post-rollout (prod): confirm AC TCP target groups are healthy on
      `/nhp-ac/ready`, `ac-servers-healthy-low` and `*-ac-tg-no-healthy` stay
      OK, and a prod-safe qv2 smoke reaches the qurl.site navigation path.
- [ ] Rollback: restore `/ping` target health before rolling instances back to a
      build/user data that lacks `nhp-ac-ready`; Traefik `/ping` remains present
      on the new build, so the path revert is the safe first step. Then
      roll back/refresh ACs to the prior build. This restores the old
      liveness-only posture and can re-admit AC targets without server
      connectivity, so pair rollback with qv2 smoke and deny-log checks.
