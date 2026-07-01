# 2026-07-01 · Issue #2869 · IPv6 XDP min-kernel verifier proof

- **Owner:** EBPFXDP FilterMode-flip (E5) coordinator
- **Source:** https://github.com/layervai/nhp/issues/2869,
  https://github.com/layervai/nhp/issues/2945,
  https://github.com/layervai/nhp/pull/2941
- **Delete when:** https://github.com/layervai/nhp/issues/2945 closes.

The E5 v6 XDP flip needs verifier and `BPF_PROG_TEST_RUN` proof on the lowest
AC kernel currently in the prod/sandbox blast radius, not only on the GitHub
Actions runner. Current live prod and sandbox ACs share the lowest observed
running kernel `6.17.0-1017-aws` on Ubuntu 24.04.4; a checked prod AC had
`linux-aws 6.17.0-1019.19~24.04.1` installed, but that package was not the
active running kernel on the host, so `6.17.0-1017-aws` remains the E5
running-kernel floor for this evidence. This closes #2869 for the current-floor
proof; #2945 owns the future flip-time revalidation/hold obligations.

- [x] Current-state kernel/AMI identification (2026-07-01): sandbox
      `/sandbox/nhp/ac/ami-id` and prod `/prod/nhp/ac/ami-id` both pointed at
      current Packer-built AC AMIs; active sandbox and prod ACs share the
      running-kernel floor `6.17.0-1017-aws`. Read-only SSM probes on
      representative live ACs confirmed `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`,
      `CONFIG_BPF_JIT=y`, and `CONFIG_XDP_SOCKETS=y`. The verifier and current
      AC build/runtime target are both `x86_64` / `linux/amd64` per the #2816
      arch-lockstep evidence.
- [x] Current-state verifier proof (2026-07-01): launched a temporary sandbox
      verifier AC from the current sandbox AC AMI as `t3.medium` and ran `sudo
      env CLANG=clang-18 NHP_REQUIRE_BPF_TESTS=1 make test-ebpf` from commit
      `ea930bd76461f79eed10a6ca634afc126c7ab04a` (same eBPF source as this
      docs-only PR) using the pinned eBPF toolchain
      (`clang-18=1:18.1.3-1ubuntu1`, `llvm-18=1:18.1.3-1ubuntu1`,
      `libbpf-dev=1:1.3.0-2build2`). The SSM run exited `0`; focused read-back
      returned `PASS` / `ok github.com/OpenNHP/opennhp/nhp/utils/ebpf` on
      `6.17.0-1017-aws`. Local source-equivalence check passed for the tested
      commit versus this PR head across the eBPF source/test/toolchain-install
      paths.
- [x] Covered cases from `make test-ebpf`: the #2869-required direct IPv6 L4,
      extension-header, fail-closed, AH/Routing/Mobility, UDP, ICMPv6/NDP, and
      v6 telemetry cases. The PR body carries the command IDs and full evidence
      breadcrumbs.
- [ ] Pre-rollout (HARD, before the E5 v6 XDP flip; tracked by #2945): re-check
      the target AC AMI and the active running kernel at flip time, including
      any reboot or kernel package activation since this proof. If the target
      AC AMI, running kernel, AC instance architecture, eBPF source, or pinned
      eBPF toolchain changes after the evidence above, re-run `make test-ebpf`
      or an equivalent load + `BPF_PROG_TEST_RUN` proof on the new floor before
      flipping v6 XDP. For the #2865 fragment-state work, also verify the new
      AC binary loads and pins the XDP object before the sampler runs:
      `/sys/fs/bpf/frag_state_v6` must be pinned alongside `conn_track_v6`, and
      the `EbpfFragStateV6*` usage/reap metrics must publish under EBPFXDP.
      A new sampler against an old object with no `frag_state_v6` pin is a
      failed flip state and should hold/roll back instead of being treated as a
      mixed-rollout success. Confirm
      `${name_prefix}-ac-ebpf-frag-state-v6-usage-high` is present before
      relying on v6 XDP for fragmented-flow admission, and record the committed
      XDP object's load-relevant hash (this PR regenerated
      `764ab9baae061725cc7a2742891ad8f028c5c0a1b4a4d2f42dd6d4ea0f929da8`).
      During flip watch, tell on-call that later-fragment DENYs can be benign
      fail-closed reordering and explicitly confirm no in-scope
      UDP-over-fragmented-IPv6 path depends on out-of-order fragment buffering.
- [ ] Rollback/hold (tracked by #2945): if the min-kernel proof rejects
      `resolve_ipv6_l4` / `xdp_white_prog_v6`, keep prod v6 XDP gated and leave
      prod on `FilterMode=IPTABLES` until the helper is adjusted and this proof
      passes.
