# 2026-06-28 · Issue #2812 · AC eBPF object extraction smoke

- **Owner:** prod rollout coordinator
- **Source:** [#2812](https://github.com/layervai/nhp/issues/2812), [PR #2961](https://github.com/layervai/nhp/pull/2961)

Adds a Tier 1 smoke probe that is dormant while ACs run `FilterMode=0`, then becomes a hard deploy-time check once any active AC instance runs `FilterMode=EBPFXDP`.
PR #2961 makes the first sandbox flip explicit through `ac_filter_mode = 1`; applying it only updates the AC launch template, so the sandbox rollout must also cycle the AC ASG before treating eBPF as active.

- [ ] Pre-rollout (HARD, before E5 FilterMode flip): confirm the target env's Tier 1 smoke is invoked with `allow_ssm_probes=true`; otherwise the AC eBPF object extraction gate skips by policy and does not protect the flip.
- [ ] Pre-rollout (HARD, before E5 FilterMode flip): confirm Terraform/user-data renders the AC config as numeric TOML, canonically `FilterMode = 1`, matching `endpoints/ac/config.go`; string values such as `"EBPFXDP"` are not valid for the current AC config parser or smoke gate.
- [ ] Rollout: after flipping `FilterMode=EBPFXDP` in sandbox, refresh/roll the AC ASG so every active instance boots fresh user_data, then run Tier 1 smoke and confirm `TestACEBPFObjects_PresentInDeployedLayoutWhenFilterModeEBPFXDP` passes against every active AC instance before promoting the flip to prod.
- [ ] Post-rollout: after the prod flip, confirm the same Tier 1 smoke test passes and no AC emits eBPF object load failures on boot.
- [ ] Rollback: revert the FilterMode flip to iptables and refresh/roll the AC ASG; the smoke test will return to skip state once active AC instances report `FilterMode=0`.
