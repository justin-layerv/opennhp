# L3 Flush Scheduler — Scaling Design

This document captures the design rationale, capacity ceilings,
and operational tuning guidance for the L3 flush-on-expiry
scheduler at `endpoints/ac/expiry_scheduler.go`. It exists to
keep the design intent legible to future maintainers and to
document the gap between the original SLO commitment and the
realistic Go-runtime achievable.

For the high-level mechanism (what L3 flush is, why we need
it), see `SESSION_ENFORCEMENT_ARCHITECTURE.md`.

## TL;DR

| Concern | Today's design | Capacity ceiling |
|---|---|---|
| Concurrent scheduled entries | Hashed wheel + 256-shard index | ~10M (80 MB per 1M) |
| Insert throughput | Wheel insert is O(1), 64 workers | ~15M ops/sec (M1 Max baseline) |
| Cancel throughput | Index lookup + intrusive unlink | ~3M ops/sec |
| Fire latency p50 | Tick + dispatch + worker pickup | ~3-5 ms |
| Fire latency p99 | + GC + scheduler jitter | **~5-10 ms** |
| Fire latency max | + worst-case GC pause | ~30 ms |
| ConntrackFlusher throughput | exec(conntrack) per call | **~12k ops/sec** ← bottleneck |
| BpfFlusher throughput | LoadPinnedMap + Delete per call | ~150k ops/sec |

The 12k ops/sec ConntrackFlusher ceiling is the binding
throughput constraint today. See nhp#2165 for the netlink
replacement that lifts it to ~640k ops/sec.

## Architecture

```
                      HandleAccessControl
                              │
                  ipset.Add / EbpfRuleAdd
                              │
                              ▼
                     Scheduler.Schedule
                              │
            shard.mu → wheelMu → insertLocked
                              │
                              ▼
                  ┌────────────────────┐
                  │   Timer wheel      │
                  │   60000 buckets ×  │
                  │   10 ms tick =     │
                  │   10 min coverage  │
                  │   + overflow list  │
                  └─────────┬──────────┘
                            │ tick goroutine
                            │ every 10 ms:
                            │ drain current bucket
                            ▼
                  flushQueue (cap=32k)
                            │
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
        worker[0]       worker[1]   ...  worker[63]
            │               │               │
            ▼               ▼               ▼
                  FlowFlusher.Flush
                  (Conntrack | BPF | NoOp)
```

### Why hashed timer wheel (not `time.AfterFunc`)

Go's runtime timer heap breaks down past ~100k concurrent
timers — per-timer overhead is ~100-200 B of runtime state
plus the closure capture. At 1M entries that's 200 MB+ of pure
runtime overhead and meaningful CPU on every Add/Fire.

The hashed wheel (Kafka / Netty pattern) is the known-good
million-scale pattern. Insert is O(1), fire is O(K) where K is
the number of entries in the current bucket. The full wheel
costs `wheelSize × 8` bytes of bucket-head pointers regardless
of population.

### Why 256 shards for the index

The scheduler needs `Cancel(key)` and longest-wins Reschedule
to look up entries by key in O(1). A single mutex around a
million-entry map would serialize hot Schedule paths. 256
shards keyed by `xxhash(FlowKey) % 256` give ~4k entries per
shard at 1M total — small maps with rare lock contention.

256 is also large enough that the 64-worker pool can almost
always find an uncontended shard on Cancel + worker
deletion-on-fire.

### Why bounded backpressure (not unbounded)

Under the L3-only enforcement contract (post-L7 removal), a
silently-late flush represents unauthorized data flow past
session end. We commit to fail-loud rather than fail-soft:

1. Channel send to flushQueue is non-blocking.
2. On full queue, the entry is re-bucketed for next tick
   (counted as `metricFlushDeferred`).
3. After `maxConsecutiveDefers` (5) cycles, the entry is
   dropped and the breaker is forced open.
4. UdpAC reads `IsBreakerOpen()` at NHP-AOP admission and
   refuses new sessions until the breaker is manually reset.

The 5-cycle bound means worst-case 50 ms of late flush before
the breaker trips — well under the security contract's 100 ms
hard ceiling.

## Capacity ceilings (measured baselines)

All numbers are Apple M1 Max + Go 1.26.3 + the default
configuration (`defaultTickInterval=10 ms`,
`defaultWheelSize=60000`, `defaultWorkerCount=64`,
`defaultFlushQueueCap=32768`). Production AC instances (Linux
on AWS) should be expected to be in the same order of
magnitude, possibly faster.

| Metric | Bench | Result |
|---|---|---|
| 1M-entry seed + Reschedule | `BenchmarkScheduler_Insert_OneMillion` | ~15M ops/sec |
| Concurrent insert (10 producers) | `BenchmarkScheduler_Insert_Concurrent` | 66 ns/op = ~15M ops/sec aggregate |
| Cancel | `BenchmarkScheduler_Cancel` | 323 ns/op = ~3M ops/sec |
| Fire-latency p50 | `BenchmarkScheduler_FireLatency_p99` | ~3-5 ms |
| Fire-latency p99 | same | ~5-10 ms |
| Fire-latency max | same | ~6-30 ms (GC-dependent) |

Memory: at 1M entries, ~80 MB for the entry pool + ~64 MB for
the shard maps = ~150 MB total scheduler state. At 10M:
~1.5 GB — within instance memory budget for `c5.4xlarge` (32 GB),
but #2163's tokenStore line item (~5 GB at 10M) is the binding
constraint there.

## SLO gap and roadmap

The original design contract for the L3-only end-state
committed to **p99 fire-latency < 5 ms**. Realistic Go-runtime
ceiling is **5-10 ms** on a loaded host. The gap factors:

1. `time.NewTicker` slips by 1-5 ms when the runtime serves
   many goroutines on few logical CPUs.
2. GC pauses contribute 1-10 ms p99.9 spikes.
3. Channel-send to flushQueue has small but nonzero tail
   latency.

For the rollout phase (4+4 weeks L3+L7 side-by-side), the
5-10 ms p99 is operationally adequate — well under the 100 ms
hard ceiling. The 5 ms target becomes hard at L7 removal.

### Architectural path to 5 ms p99 (future work)

These changes will not land in PR #2164. They land in the
4+4-week side-by-side validation window, before L7 removal:

1. **`runtime.LockOSThread` on the tick goroutine** — pin to a
   dedicated OS thread so it isn't subject to the M:N
   scheduler. ~1-2 ms p99 reduction.
2. **Per-shard tickers** — instead of one tick goroutine
   walking the global wheel, each of the 256 shards runs its
   own tick. Smaller per-tick critical section, parallel
   drain. ~1 ms p99 reduction.
3. **Allocation-free hot path** — eliminate `time.Now()`
   allocations in `Schedule`, avoid `errors.New` in idempotent
   paths. Reduces GC pressure → tighter p99.9.
4. **GOGC tuning** — set to 50 from default 100 on AC processes
   for tighter GC cycles. Trade-off: 30% more CPU.

Each change is independently testable against the
`BenchmarkScheduler_FireLatency_p99` benchmark.

## Operational tuning

### Per-deployment knobs

The scheduler is constructed in `udpac.go` with options driven
by `Config`. Tunable today (live-reloadable via TOML):

- `EnableL3FlushOnExpiry` — master gate.
- `L3FlushDryRun` — log-only mode. Auto-defaulted to true the
  first reload after `EnableL3FlushOnExpiry` flips from false
  to true.
- `L3FlushErrorThreshold` / `L3FlushErrorWindowSec` — circuit
  breaker thresholds. Defaults 10/60.

Not yet wired to Config (held in scheduler-side / msghandler-side constants):

- `defaultTickInterval` (10 ms)
- `defaultWheelSize` (60000 buckets = 10 min coverage)
- `defaultWorkerCount` (64)
- `defaultFlushQueueCap` (32768)
- `flushSafetyMargin` (50 ms) — in `endpoints/ac/msghandler.go`;
  extends each flush deadline past the kernel allow-rule's
  natural expiry so the scheduler always sweeps an already-
  expired entry. Tuning down requires benchmarking ipset
  eviction latency under load (current value is comfortably
  above the per-call kernel-write latency, well under the
  10 ms tick resolution).

If the operator needs to tune these per-fleet (e.g., to drop
tick to 2 ms for tighter p99), thread them through Config in a
follow-up.

### Wheel-size sizing

Pick wheelSize × tickInterval to cover ~99% of expected TTLs.
With qURL's session_duration distribution (min 60 s, default
~300 s, max ~24 h):

- `wheelSize=600 × tick=10 ms = 6 s` covers <1% of entries —
  the rest land in overflow.
- `wheelSize=6000 × tick=10 ms = 60 s` covers ~5% of entries.
- `wheelSize=60000 × tick=10 ms = 10 min` covers ~80%
  (**production default** since 2026-05; sized for qURL's 60-300s
  modal session_duration).

Overflow walks are O(overflow_size) per wrap. At 1M entries
mostly in overflow with a 6 s wrap, that's ~170k ops/sec on
the tick goroutine. Tolerable but worth sizing wheel up if
overflow becomes a CPU hot spot in profiling.

### Worker-pool sizing

Default 64 workers. Each consumes ~10 KB of goroutine stack.
At default flusher latency (NoOpFlusher: ~0 µs; BpfFlusher:
~100 µs; ConntrackFlusher: ~10 ms), the throughput ceiling per
worker is `1 / per-call-latency`. Cumulative:

| Flusher | Per-call | 64-worker ceiling |
|---|---|---|
| NoOpFlusher | ~0 µs | (unbounded) |
| BpfFlusher | ~100 µs | ~640k ops/sec |
| ConntrackFlusher (exec) | ~10 ms | ~12k ops/sec ← bottleneck |
| ConntrackFlusher (netlink, #2165) | ~150 µs | ~640k ops/sec |

When the ConntrackFlusher swap to netlink lands, the worker
pool can stay at 64 — the throughput ceiling rises by a factor
of ~50.

### Deploy-time spike vs the ConntrackFlusher ceiling

Steady-state at 1M concurrent sessions / 5-min average TTL is
~3.3k flushes/sec — comfortably below the 12k ops/sec exec
ceiling. But a coordinated burst is possible: a deploy that
issues a large batch of /resolve calls in one minute lands a
correlated cohort of expirations at the same +session_duration
moment. With 200k sessions in a 1-min window, post-rollover
burst is ~3.3k/sec (fine); with 600k sessions in a 1-min window,
burst is ~10k/sec (approaching the ceiling). Two mitigations:

- **Operationally:** stagger large /resolve bursts across the
  cohort by ≥30 s. The defaultFlushQueueCap (32k) absorbs ~3 s
  worth of ceiling-rate output, so the queue tolerates one
  spike but a sustained over-ceiling rate trips the breaker via
  the defer→drop path.
- **Architecturally:** land #2165 (netlink batching) before any
  customer onboarding that would produce >300k correlated
  sessions/min. The netlink ceiling (~640k ops/sec) absorbs any
  realistic spike.

### Tempset (auxiliary-range) entries — scope decision

`HandleAccessControl`'s `/25` and `/121` tempset entries
(scan-tolerance for nearby IPs after a successful knock) are
added to ipset with `tempOpenTimeSec` but **deliberately not
scheduled for flush**. Rationale: these aren't session-tied
NHP-AOP entries; they exist to absorb scan traffic close to a
legitimate client's IP, and the scheduler's per-session scope
covers the actual session-tied (per-host) entry path.

Trade-off worth knowing at L7-removal time: a real customer
flow whose ipset hit lands on the auxiliary range (rare —
requires the source IP to fall in the /25 or /121 range
WITHOUT being the per-host entry) would survive `tempOpenTimeSec`
via the ESTABLISHED bypass under L3-only enforcement. This is
the same architectural gap the scheduler exists to close for the
per-host case, intentionally left open here because:

1. Tempset's purpose is scan tolerance, not session enforcement —
   any traffic on the auxiliary range was admitted on a scan-
   tolerance budget, not a session budget.
2. Scheduling tempset flushes at the /25 or /121 set-wide
   granularity would over-flush; per-tuple flushing would require
   ipset save+parse on every tempset add (already O(n) on save).

If at L7-removal time a real customer flow is observed on the
auxiliary range, revisit by either:
(a) scheduling per-tuple flushes for tempset entries (and
absorbing the ipset-save cost), or
(b) reducing `tempOpenTimeSec` to a value below the worst-case
session_duration so the bypass window is bounded.

(cr fence: round 13 finding 1.)

## L7-removal pre-flight checklist

Issues that MUST close before flipping the L3-only contract (i.e.,
removing the L7 admission backstop). The 4+4-week sandbox+prod
rollout window with L7 still active gives time to land these.
Re-validating this list is a release-gate item on the L7-removal
PR itself; tracking is informational here.

- **#2168 — processEntry / re-admission race.** Today: in-flight
  `Flush` against a re-admitted FlowKey self-heals on next packet
  (conntrack mode) or silently denies one admission (BPF mode).
  Under L3-only enforcement this race is no longer benign — the
  BPF silent-deny path becomes a customer-visible session denial.
- **#2172 — Cancel wiring.** `/refresh` that shortens a session
  and token-revoke must call `Scheduler.Cancel(key)` so a phantom
  flush doesn't race the next admission. Today the lingering
  phantom is ENOENT-no-op (harmless metric noise); under L3-only
  it can cause the same BPF silent-deny window as #2168.
- **#2169 — overflow promotion stall under `wheelMu`.** The
  default wheel size now covers the modal session distribution
  in-wheel, but operators running with a smaller wheel or longer
  session tails will hit O(N) promotion stalls. The per-shard
  ticker roadmap closes this; under L3-only the stall window is a
  customer-visible admission latency spike.

These three are the load-bearing follow-ups. The remaining issues
(#2165 netlink swap, #2170 L3FlushMode enum, #2171 dispatch race
fence, #2173 misc operability, #2179 conntrack-tools version pin)
are all operability / throughput / fences — none gate L7 removal.

## See also

- `endpoints/ac/expiry_scheduler.go` — implementation + godoc.
- `endpoints/ac/expiry_scheduler_test.go` — race fences for the
  7 bugs caught during design review.
- `endpoints/ac/expiry_scheduler_bench_test.go` — SLO benches.
- `SESSION_ENFORCEMENT_ARCHITECTURE.md` — overall enforcement
  model (three-clock framing, L3 vs L7 boundaries).
- nhp#2163 — capacity audit covering ipset / BPF / tokenStore
  ceilings beyond the scheduler itself.
- nhp#2165 — ConntrackFlusher netlink follow-up that lifts the
  throughput ceiling.
