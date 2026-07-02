# 2026-07-02 · PR #3025 · AC EBPFXDP health-check port exemption

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3025 (fixes a live sandbox
  outage where all AC targets flapped unhealthy under FilterMode_EBPFXDP)

The AC XDP whitelist fails closed on the load-balancer health-check port
(:8080). This PR admits it at startup. Sandbox is already on
`ac_filter_mode=1`, so the fix must deploy there and be verified; prod is on
`ac_filter_mode=0`, so this is a hard prerequisite for any prod EBPFXDP flip
(it supersedes the "gate any prod EBPFXDP flip on this being live" note left by
PR #3019).

- [ ] Post-rollout (sandbox): after the AC build ships, confirm
      `aws_lb_target_group.ac_tcp` targets go `healthy` and the
      `layerv-nhp-sandbox-ac-servers-healthy-low` and
      `layerv-nhp-sandbox-ac-green-tg-no-healthy` alarms clear; probe a qurl
      link end-to-end.
- [ ] Post-rollout (sandbox): confirm the `ac_frps_control*` target groups
      (same :8080 `/ping`) also report healthy.
- [ ] Rollout gate (prod): do NOT flip prod `ac_filter_mode` 0→1 until this
      build is live in prod. In iptables mode the change is inert (the
      exemption is EBPFXDP-only), so the prerequisite is "deployed", not
      "flipped".
- [ ] Rollback: revert to the prior AC build. Safe — the exemption is additive
      and EBPFXDP-only; FilterMode_IPTABLES behavior is unchanged.
