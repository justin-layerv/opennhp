# 2026-07-02 · Issue #2849 · eBPF malformed-DENY telemetry sampling

- **Owner:** EBPFXDP FilterMode-flip (E5) coordinator
- **Source:** https://github.com/layervai/nhp/issues/2849

Before the E5 `FilterMode=EBPFXDP` prod flip, confirm the #2849 token-bucket
sampling metrics and alarms are present and flat under normal load. These checks
prove malformed-packet DENY floods are actively capped without silent telemetry
loss.

- [ ] Pre-rollout (HARD, before E5 FilterMode flip): confirm sandbox and prod
      Terraform have created the `*-ac-ebpf-perf-lost-samples` and
      `*-ac-ebpf-deny-telemetry-suppressed` CloudWatch alarms with SNS actions.
- [ ] At-flip (E5): verify `EbpfPerfLostSamples` `Sum` stays 0 after the AC
      eBPF datapath is live; any non-zero period blocks/rolls back the flip
      until telemetry completeness is restored.
- [ ] At-flip (E5): verify `EbpfDenyTelemetrySuppressed` is flat under normal
      traffic, then run or review a controlled malformed-packet canary and record
      that suppression is observable and returns to 0 after the canary stops.
- [ ] Rollback: if either metric alarms during normal post-flip traffic and the
      cause cannot be resolved immediately, roll affected ACs back to
      `FilterMode=IPTABLES` while investigating.
