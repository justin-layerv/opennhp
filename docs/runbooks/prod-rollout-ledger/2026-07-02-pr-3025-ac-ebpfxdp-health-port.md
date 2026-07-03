# 2026-07-02 · PR #3025 (+ marshal follow-up) · AC EBPFXDP health-check port exemption

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3025 (startup exemption) +
  the `protocol_port` value-marshal fix that makes it actually land (fixes a
  live sandbox outage where all AC targets flapped unhealthy under
  FilterMode_EBPFXDP)

The AC XDP whitelist fails closed on the load-balancer health-check port
(:8080). #3025 admits it at startup, but that write hit a latent bug: the
`protocol_port` map value is a `__packed` 9-byte C struct while the Go writer
emitted a 16-byte struct, so `Map.Update` failed and the rule never landed
(`protocol_port` stayed empty; targets still unhealthy on the #3025 deploy).
The follow-up writes the value as 9 packed bytes. **Interim:** the 3 sandbox
green ACs were manually seeded (`bpftool map update protocol_port key 1f 90 06
value 01 ff*8`) to restore service — that is EPHEMERAL and lost on the next
instance refresh, so the marshal fix must deploy to make it durable. Sandbox is
already on `ac_filter_mode=1`; prod is on `ac_filter_mode=0`, so this remains a
hard prerequisite for any prod EBPFXDP flip (supersedes the #3019 note).

- [ ] Post-rollout (sandbox): after the marshal-fix build ships, refresh the AC
      ASG and confirm `protocol_port` self-populates at startup (bpftool map
      dump shows the `{8080,tcp}` entry with NO manual seeding), targets go
      `healthy`, and the `layerv-nhp-sandbox-ac-servers-healthy-low` /
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
