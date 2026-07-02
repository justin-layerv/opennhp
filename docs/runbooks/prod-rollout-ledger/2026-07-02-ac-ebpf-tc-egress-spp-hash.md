# 2026-07-02 · AC eBPF crash-loop fix · tc_egress `spp` map type

- **Owner:** prod rollout coordinator
- **Source:** <this PR> · triggered by #2961 (sandbox AC eBPF filter-mode flip) exposing a latent #2163 miss

`tc_egress.c`'s `spp` map stayed `LRU_HASH` when #2163 flipped the shared XDP
`spp` to `HASH`; both pin `/sys/fs/bpf/spp`, so under `FilterMode=EBPFXDP` the
second `LoadAndAssign` fails and every AC crash-loops (~10s), taking `ACPeerCount`
to 0 fleet-wide and blocking all blue/green deploys at the knock-ready gate. This
PR sets tc's `spp` to `HASH` and adds a cross-object parity guard.

Because `HASH` no longer LRU-evicts, this PR also adds a periodic `spp`
expired-entry reaper (the datapath-fill GC for tc-written return-path pinholes)
into the existing conn_track lifecycle sampler. The reaper walk runs inside the
same timed window as the conn_track walk, so `SampleDurationSeconds` and the
`slowSample` warn threshold now cover **two** HASH map walks instead of one.

- [ ] Post-rollout: after this deploys, confirm sandbox ACs stop crash-looping —
      no `EbpfEngineLoad: Failed to load and assign tc eBPF objects` in
      `/layerv/nhp/sandbox/ac`, `ACPeerCount` returns > 0, and a blue/green deploy
      passes `[Server] Verify Knock Readiness`.
- [ ] Pre-rollout (prod EBPFXDP flip): this fix MUST be deployed before prod AC
      `FilterMode` is flipped to `EBPFXDP` (the prod analogue of #2961) — otherwise
      prod ACs hit the identical crash-loop. Gate the prod flip on this being live.
- [ ] Post-rollout (prod EBPFXDP flip): once `spp` actually carries datapath
      entries under real traffic, re-check the `spp allow-rule reap was partial`
      and `SampleDurationSeconds`/`slowSample` signals — the sampler now walks two
      HASH maps per pass. Re-tune `bpfConntrackSampleInterval` /
      `connTrackExpiredDeleteBudget` if the combined walk regularly trips the slow
      threshold. In sandbox today `spp` is near-empty so the second walk is ~free.
- [ ] Post-rollout (prod EBPFXDP flip): watch **`spp` occupancy and `-E2BIG`
      insertion-failure headroom directly**, not just walk timing — alarm on the
      `EbpfSppUsagePercent` gauge this PR adds (`EbpfSppEntries` /
      `EbpfSppMaxEntries` give the raw counts). The reaper
      bounds *steady-state* orphan accumulation (≤ `connTrackExpiredDeleteBudget`
      = 100k per ~60s pass ≈ ~1.7k reverse-tuples/s, and only entries already past
      the 180s TTL), but it does **not** cover a *within-TTL burst*: `tc_egress`
      writes a pinhole on every egress packet, so >1M distinct reverse-tuples
      inside any 180s window fills `spp` to `max_entries` before any entry is even
      reap-eligible → new admissions get `-E2BIG`. That burst mode shows up as
      `EbpfSppUsagePercent` near 100 / occupancy near 1M, **not** as a slow walk, so the
      re-tune item above won't catch it. (Inherent to the #2163 HASH decision, not
      introduced here — but this is the fill mode most likely to bite on a busy
      egress path at the flip.) If it materializes, the levers are the 180s TTL,
      `max_entries`, or an egress-pinhole rate control — not the reaper.
- [ ] Rollback: reverting this PR restores the crash-loop under EBPFXDP; the real
      rollback for an AC-eBPF problem is disabling the eBPF filter mode
      (`FilterMode` → IPTABLES via terraform), not reverting this map-type fix.
