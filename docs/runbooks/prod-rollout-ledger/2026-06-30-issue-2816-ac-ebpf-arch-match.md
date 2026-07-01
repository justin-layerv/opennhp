# 2026-06-30 · Issue #2816 · AC eBPF architecture + min-kernel pre-flip gates

- **Owner:** EBPFXDP FilterMode-flip (E5) coordinator
- **Source:** https://github.com/layervai/nhp/issues/2816,
  https://github.com/layervai/nhp/issues/2865,
  https://github.com/layervai/nhp/issues/2945 (flip-time re-run tracking),
  https://github.com/layervai/nhp/issues/2869 (proof, closed),
  https://github.com/layervai/nhp/pull/2941 (proof PR)
- **Delete when:** the E5 prod `FilterMode=EBPFXDP` flip lands and every
  checklist item below is complete.

`build-and-push.yml` pins the AC image build to `linux/amd64`, and
`scripts/check-ac-ebpf-arch-lockstep.sh` keeps that build platform in lockstep
with Terraform's AC launch-template instance families. The remaining hard E5
gate is live confirmation that prod has not drifted out-of-band before the eBPF
objects become load-bearing.

Related E5 gates: issue #2812 AC eBPF object extraction smoke, issue #2852
CloudWatch bucketing + metric-filter verification, and issue #2861 eBPF
required check.

- [x] Current-state source check (2026-06-30): `bash
      scripts/check-ac-ebpf-arch-lockstep.sh` reports
      `build=linux/amd64; prod=c6i.xlarge; non-prod=t3.medium`; the paired
      fixture suite reports `PASSED: 17 checks`.

Pre-rollout (all **HARD**, immediately before the E5 prod
`FilterMode=EBPFXDP` flip). This entry also carries the #2945 min-kernel input
re-check so the E5 coordinator has one active arch/kernel-floor checklist after
the completed #2869 verifier-proof entry is deleted. Deleting #2869 here is a
consolidation, not discharge of its unchecked flip-time items: every live #2869
obligation is represented below and #2945 stays open as the tracking issue. Any
proof re-run must still cover the #2941/#2869 verifier inventory: direct IPv6 L4
lookup, extension-header walk/fail-closed behavior, AH/Routing/Mobility denies,
UDP, ICMPv6/NDP, and v6 telemetry. The #2869 proof recorded committed XDP object
hash `764ab9baae061725cc7a2742891ad8f028c5c0a1b4a4d2f42dd6d4ea0f929da8`;
the flip must record the promoted object's load-relevant hash too:

- [ ] Run `bash tests/scripts/check-ac-ebpf-arch-lockstep_test.sh` and
      `bash scripts/check-ac-ebpf-arch-lockstep.sh` from the exact commit being
      promoted, and record the output in the flip issue/PR.
- [ ] Re-check the #2945 min-kernel proof inputs before enabling v6 XDP. If the
      target AC AMI, active running kernel, AC instance architecture, eBPF
      source, or pinned eBPF toolchain changed after the 2026-07-01
      `6.17.0-1017-aws` / `x86_64` evidence, including any reboot or
      kernel-package activation that changes the active running kernel (not
      just the installed package), re-run `make test-ebpf` or an equivalent
      load + `BPF_PROG_TEST_RUN` proof on the new minimum floor before flipping
      v6 XDP.
- [ ] Rollback/hold for #2945: if the min-kernel proof rejects
      `resolve_ipv6_l4` / `xdp_white_prog_v6`, keep prod v6 XDP gated and leave
      prod on `FilterMode=IPTABLES` until the helper is adjusted and the proof
      passes.
- [ ] For the #2865 fragment-state work, verify the promoted AC binary loads and
      pins the XDP object before the sampler runs: `/sys/fs/bpf/frag_state_v6`
      must be pinned alongside `conn_track_v6`, `EbpfFragStateV6*` usage/reap
      metrics must publish under EBPFXDP, and
      `${name_prefix}-ac-ebpf-frag-state-v6-usage-high` must be present before
      relying on v6 XDP for fragmented-flow admission. Treat a new sampler
      against an old object with no `frag_state_v6` pin as a failed flip state,
      hold or roll back, and record the committed XDP object's load-relevant hash
      in the flip issue/PR.
- [ ] During the flip watch, tell on-call that later-fragment DENYs can be benign
      fail-closed reordering, and explicitly confirm no in-scope
      UDP-over-fragmented-IPv6 path depends on out-of-order fragment buffering.
- [ ] If an AC instance refresh, scale-out, or launch-template update occurs
      after this evidence is recorded and before the flip, re-run these
      pre-rollout checks before proceeding.
- [ ] With `AWS_PROFILE=layerv-prod`, resolve the prod AC ASG set from SSM. If
      `/prod/nhp/ac/active-color` exists, check both `/prod/nhp/ac/asg-name`
      (canonical blue; `/prod/nhp/ac/blue-asg-name` is the symmetric alias when
      present) and `/prod/nhp/ac/green-asg-name` (green), with the active color
      called out in the evidence; otherwise check `/prod/nhp/ac/asg-name`.
- [ ] For every resolved prod AC ASG, describe the ASG and confirm
      `MixedInstancesPolicy` is absent; if one exists, stop the flip until every
      override instance type is classified and tested.
- [ ] For every resolved prod AC ASG, describe the ASG launch-template version
      and active instances, then confirm every AC instance type maps to EC2
      architecture `x86_64` (`linux/amd64`) and matches the AC image platform.
      Useful probes: `aws autoscaling describe-auto-scaling-groups`,
      `aws ec2 describe-launch-template-versions`, and
      `aws ec2 describe-instance-types`.
- [ ] Rollback/hold: if the live prod AC ASG is arm64, mixed-arch, or otherwise
      does not match the `linux/amd64` AC image build, do not flip E5. Keep or
      revert prod to `FilterMode=IPTABLES`; the follow-up fix is per-arch AC
      image/object builds plus a real BPF object load test on the non-amd64
      kernel before relaxing this gate.
