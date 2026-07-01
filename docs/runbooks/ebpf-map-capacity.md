# eBPF Map Capacity Runbook

Use this runbook for AC eBPF/XDP map capacity alarms and supporting metrics:

- `EbpfMapFull`: allow-rule admission map is full and new admissions are being rejected fail-closed.
- `EbpfConntrackV4UsagePercent` / `EbpfConntrackV6UsagePercent`: established-flow conntrack cache is high after quiet-entry reaping.
- `EbpfConntrackV4MaxEntries` / `EbpfConntrackV6MaxEntries`: loaded conntrack map ceilings reported by pinned map metadata.
- `EbpfConntrackSampleErrors`: per-period conntrack stats/reaper sample failures.
- `EbpfConntrackPartialSamples`: per-period incomplete conntrack HASH walks caused by concurrent churn.

## First Checks

Confirm the alarm stream uses the AC publisher dimensions:

```bash
aws cloudwatch get-metric-statistics \
  --namespace LayerV/NHP \
  --metric-name EbpfMapFull \
  --dimensions Name=Component,Value=AC Name=Environment,Value=<env> Name=Region,Value=<region> \
  --statistics Sum \
  --period 300 \
  --start-time <iso-start> \
  --end-time <iso-end>
```

Check conntrack occupancy and reaper activity:

```bash
aws cloudwatch get-metric-statistics \
  --namespace LayerV/NHP \
  --metric-name EbpfConntrackV4UsagePercent \
  --dimensions Name=Component,Value=AC Name=Environment,Value=<env> Name=Region,Value=<region> \
  --statistics Maximum \
  --period 300 \
  --start-time <iso-start> \
  --end-time <iso-end>

aws cloudwatch get-metric-statistics \
  --namespace LayerV/NHP \
  --metric-name EbpfConntrackV4ExpiredReaped \
  --dimensions Name=Component,Value=AC Name=Environment,Value=<env> Name=Region,Value=<region> \
  --statistics Sum \
  --period 300 \
  --start-time <iso-start> \
  --end-time <iso-end>

aws cloudwatch get-metric-statistics \
  --namespace LayerV/NHP \
  --metric-name EbpfConntrackSampleSeconds \
  --dimensions Name=Component,Value=AC Name=Environment,Value=<env> Name=Region,Value=<region> \
  --statistics Maximum \
  --period 300 \
  --start-time <iso-start> \
  --end-time <iso-end>
```

On an affected AC, inspect pinned maps:

```bash
sudo bpftool map show pinned /sys/fs/bpf/spp
sudo bpftool map show pinned /sys/fs/bpf/conn_track
sudo bpftool map show pinned /sys/fs/bpf/conn_track_v6
sudo bpftool map dump pinned /sys/fs/bpf/conn_track | head
```

## If `EbpfMapFull` Fired

This is allow-rule capacity. The AC failed closed for new admissions whose rule insert hit `max_entries`; existing admitted sessions were not silently evicted.

Actions:

- Confirm whether admission failures are ongoing by checking `EbpfMapFull` `Sum` over the last 5 to 15 minutes.
- Reduce admission pressure if possible: stop the traffic source, pause the campaign, or scale the AC fleet before retrying.
- Confirm L3 flush-on-expiry is healthy: `L3FlushBreakerOpen` should be 0 and `L3FlushScheduleWaitTimeout` should be 0.
- If customers are blocked, roll the affected ACs back to `FilterMode=IPTABLES` or scale out while investigating.
- Do not raise `MAX_ENTRIES` ad hoc. BPF HASH maps preallocate unswappable kernel memory at load time; any increase must be paired with the AC instance RAM review in `docs/design/SESSION_ENFORCEMENT_ARCHITECTURE.md`.

## If Conntrack Usage Fired

This is established-flow cache pressure, not allow-rule admission failure. Correctness remains fail-closed: a full conntrack HASH cache makes new or uncached flows pay the allow-rule slow path; it does not fail open and does not evict an existing conntrack entry.

Actions:

- Check `EbpfConntrackV4ExpiredReaped` / `EbpfConntrackV6ExpiredReaped` with `Sum`. Non-zero periods mean the quiet-entry reaper is making progress; keep watching usage and oldest-age.
  This is a fleet-shared `{Component, Environment, Region}` counter stream; use AC logs for per-instance reaper progress.
- Check `EbpfConntrackV4MaxEntries` / `EbpfConntrackV6MaxEntries` to confirm which ceiling is actually loaded on the affected fleet.
- Check `EbpfConntrackV4OldestAgeSeconds` / `EbpfConntrackV6OldestAgeSeconds`. This is idle age since the last packet, not total entry lifetime; a rising value with low reaped counts means most entries may still be live.
  During an expiry backlog above the 100,000-entry delete budget, oldest-age can under-report because expired entries left for a later pass are excluded from the survivor-age calculation.
- Check `EbpfConntrackSampleSeconds` with `Maximum`. Values near the sampler interval mean full-map walks are making cached snapshots stale and quiet-entry reaping lag; keep this evidence with the #2928/#2930 flip-gate records.
- Check `EbpfConntrackSampleErrors` `Sum`. Any non-zero value in the current period means the sampler/reaper may be blind or stalled; inspect AC logs for `[BpfFlusher] conntrack stats/reaper sample failed`.
- Check `EbpfConntrackPartialSamples` `Sum`. Any non-zero value means the HASH walk aborted under concurrent churn; usage may be undercounting and the quiet reaper skipped deletes for that sample.
- If occupancy stays high after reaping, scale AC capacity or reduce long-lived flow creation.
- Only raise `MAX_ENTRIES` / `MAX_ENTRIES_V6` after re-running the kernel-memory math against the chosen AC instance type.

## If `EbpfConntrackSampleErrors` Fired

Actions:

- Confirm the XDP program loaded and pinned the expected maps.
- Check permissions and path shape for both `/sys/fs/bpf/conn_track` and `/sys/fs/bpf/conn_track_v6`; the sampler expects the V4 and V6 conntrack maps to be pinned together after the EBPFXDP flip.
- Verify the pinned map key/value sizes match the committed XDP object. A wrong map at the pin path is treated as a sample error by design.
- Restart or replace the affected AC if the maps are corrupt or pinned from an old process.

## If `EbpfConntrackPartialSamples` Fired

Partial samples mean the pinned HASH map changed enough during iteration that
cilium/ebpf aborted the walk. The AC preserves last-known higher occupancy and
oldest-age gauges for the affected family, skips quiet-entry deletes from that
incomplete pass, and emits this counter so high churn does not look silently
healthy. The alarm is calibrated for sustained telemetry degradation, not a
single churny walk: it fires only after more than 4 aborted family-map walks in
each of 3 consecutive five-minute windows.
Flip-time calibration of this threshold and the 85% usage thresholds is tracked
in nhp#2930.

Actions:

- Treat concurrent high `EbpfConntrackV4UsagePercent` / `EbpfConntrackV6UsagePercent` as real capacity pressure; a non-high value during
  partial samples is not proof of safety until complete samples resume.
- Check AC logs for `conntrack v4 stats/reaper sample was partial` or `conntrack v6 stats/reaper sample was partial` to identify the affected family.
- If partial samples persist with high usage, reduce new-flow churn or scale AC capacity before raising map ceilings.
- Treat nhp#2928's reaper/metrics decoupling decision as hard E5 EBPFXDP flip-gate evidence: the lifecycle sampler must stay independent of GaugeFunc publication, or sizing plus datapath GC need an explicit replacement decision.
- Treat the near-`max_entries` conntrack walk measurement as a hard E5 EBPFXDP flip gate: confirm it exercises the 100,000-delete path without making sampler snapshots too stale on the target AC instance type, and keep the result with the nhp#2928/#2930 evidence.

## Metric Meaning

`EbpfMapFull` is an admission failure signal. It means allow-rule map capacity was exhausted and new sessions are being denied.

`EbpfConntrack*UsagePercent` is a cache-pressure signal. It means established-flow conntrack occupancy is high after the userspace quiet-entry reaper ran.

The quiet-entry reaper runs from the BpfFlusher lifecycle sampler (60s today),
not from GaugeFunc collection. Each sample deletes at most 100,000 expired quiet
entries per conntrack family, up to ~200,000 across V4+V6. At today's cadence,
the designed reclaim ceiling is therefore roughly 100,000 entries/minute per
family, or ~200,000/minute across V4+V6; slower draining under a larger quiet
backlog is expected, not evidence that the reaper is stuck. Conntrack gauges are
cached snapshot reads; if a sample is slow, metrics may publish the previous
snapshot for one flush while the sampler continues outside the publisher path.
If sample errors or partial samples are firing, conntrack occupancy telemetry
and quiet-entry reclamation can both be stale or incomplete.

Do not use `EbpfMapFull` as a proxy for conntrack saturation, and do not use conntrack usage as proof that admissions are being denied.
