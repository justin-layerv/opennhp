# 2026-06-25 · PR #2797 · AC revocation IPv6 hard-fail signal (iptables mode) — #2794

- **Owner:** prod rollout coordinator
- **Source:** [#2797](https://github.com/layervai/nhp/pull/2797) · audit fix for [#2794](https://github.com/layervai/nhp/issues/2794) · gap closed by [#2165](https://github.com/layervai/nhp/issues/2165) (netlink) · related [#2778](https://github.com/layervai/nhp/issues/2778)

`(*UdpAC).flushEntryNow` now ticks `RevocationIPv6HardFail` for a v6 immediate
revoke in `FilterMode_IPTABLES` (previously only the eBPF path ticked it; iptables
v6 revoke silently no-op'd into the conflated `ConntrackFlusher` skip counter).
v6 immediate revoke is a **declared out-of-scope gap in BOTH filter modes** (flow
dies at kernel TTL) until #2165 lands the v6-capable netlink flusher — see the
"Filter-mode/IPv6 caveat" in `docs/design/QURL_V2_KEYED_IDENTITY.md`. This is
observability-only: no breaker trip, no fail-closed.

- [ ] Pre-rollout (before qURL v2 immediate revocation is relied on in prod):
  add a CloudWatch alarm on the AC `RevocationIPv6HardFail` metric — **ANY**
  nonzero value is a real "revoke could not be enforced" gap (a v6 established
  flow surviving to kernel TTL after a revoke), independent of filter mode.
  Confirm the prod AC filter mode (`FilterMode_IPTABLES` vs `EBPFXDP`) so the
  alarm's expected baseline is understood: in either mode the metric should be
  flat unless a customer actually has v6 admissions, which v2 admission does not
  emit today — so a nonzero value pre-#2165 is the signal that v6 admission has
  appeared and the gap is now live.
- [ ] Post-rollout: after the first prod revoke smoke (see #2789 ledger entry),
  confirm `RevocationIPv6HardFail = 0` on the prod AC (no unexpected v6
  admissions slipping past the v4-only teardown).
- [ ] Rollback: none required — the change only adds a metric tick + corrects
  comments; reverting is safe and leaves the prior (silently-conflated) behavior.
