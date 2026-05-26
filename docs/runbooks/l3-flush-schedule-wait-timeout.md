# Runbook: L3 flush scheduler — Schedule wait timeout

## What fired

One of:

- **AC log line `[ExpirySched] Schedule(<flowkey>): in-flight Flush exceeded <duration>; proceeding (kernel state may briefly flap)`** — Schedule's Phase 1 wait on an in-flight Flush exceeded `flushCallTimeout + scheduleWaitSlop` (default 5.1s).
- **Alert on `MetricL3FlushScheduleWaitTimeout` non-zero** — same condition surfaced via dashboard.

Implementation lives in `endpoints/ac/expiry_scheduler.go` (Schedule's Phase 1 wait + ScheduleWaitTimeout metric). PR #2185 / issue #2168 is the original context.

## Why the metric exists

Under the L3-only enforcement contract, a chronically-stuck flusher means re-admission of the same FlowKey could race the in-flight teardown (#2168). Schedule waits for the in-flight Flush to complete before proceeding. If the wait times out, the kernel state is briefly in an indeterminate post-timeout state and Schedule proceeds anyway (force-insert) to avoid orphaning the caller's new kernel rule. `ScheduleWaitTimeout` non-zero is the early-warning signal that fires BEFORE the breaker trips.

## First steps — distinguish "stuck flusher" from "slop too tight"

Look at three signals together over the same 5-minute window:

1. **`L3FlushScheduleWaitTimeout` rate** — the alert.
2. **`L3FlushErr` rate** — flush calls that returned non-canceled errors.
3. **`L3FlushBreakerOpen` (0/1)** — whether the breaker has tripped.

### Case A: WaitTimeout ticks WITH FlushErr ticks OR BreakerOpen = 1

**Real stuck flusher.** Jump to [`l3-flush-breaker-recovery.md`](l3-flush-breaker-recovery.md) and treat WaitTimeout as a leading-indicator confirmation.

### Case B: WaitTimeout ticks WITHOUT FlushErr or BreakerOpen

**`scheduleWaitSlop` is too tight for the host's GC tail.** Most likely cause: a stop-the-world pause on a hot AC approached the 100ms slop bound.

**Mitigation:** widen `scheduleWaitSlop` from 100ms to 250ms via a code change + AC restart. Auto-adaptive sizing (`max(100ms, flushCallTimeout/10)`) is tracked in #2189.

Other causes worth checking:
- High `shard.mu` contention from a million-session burst at the same shard → look at `L3FlushBucketMaxDepth` for hot-shard hot-bucket evidence.
- `flushCallTimeout` was tuned down (post-#2165) below the actual flusher latency → check the runtime tuning history.

## Verification after mitigation

After the mitigation lands (config change + AC restart, or breaker reset + flusher fix):

- `L3FlushScheduleWaitTimeout` should stop incrementing within one tick interval.
- New NHP-AOPs should not see the warning log line.

If the metric continues to tick after mitigation, escalate — there's a second factor not covered above.

## Why we proceed past the timeout (and not fail closed)

Forcing Schedule to fail when the wait times out would orphan the caller's new kernel rule of any flush hook — the rule would persist past intended deadline on every wait-timeout, which is the same security regression as the underlying #2168 bug. Better to flap briefly (microwindow drop in BPF mode, self-heal in iptables) than to leak authz. The breaker is the fail-closed mechanism for chronically-stuck flushers; this metric is the early-warning before the breaker trips.

## Related

- `l3-flush-breaker-recovery.md` — what to do when the breaker actually trips
- PR #2185 / issue #2168 — the race fix this metric supports
- #2189 — auto-adaptive slop sizing + dashboard alarm wiring
