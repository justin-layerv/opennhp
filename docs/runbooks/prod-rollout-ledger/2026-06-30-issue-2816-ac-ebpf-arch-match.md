# 2026-06-30 · Issue #2816 · AC eBPF build/runtime architecture lockstep

- **Owner:** EBPFXDP FilterMode-flip (E5) coordinator
- **Source:** https://github.com/layervai/nhp/issues/2816

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
`FilterMode=EBPFXDP` flip):

- [ ] Run `bash tests/scripts/check-ac-ebpf-arch-lockstep_test.sh` and
      `bash scripts/check-ac-ebpf-arch-lockstep.sh` from the exact commit being
      promoted, and record the output in the flip issue/PR.
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
