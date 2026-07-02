# endpoints/ac — Local Guidance

## Prod Rollout Ledger

AC changes often create concrete prod rollout tasks such as L3/ipset checks,
Traefik plugin ordering, metric/alarm verification, deploy refreshes, or
qurl-router coordination. When they do, add a succinct entry file under
[`../../docs/runbooks/prod-rollout-ledger/`](../../docs/runbooks/prod-rollout-ledger/)
before merge (delete it once its tasks are done).

During review, confirm either the task ledger was updated or the PR has no
pre-rollout, rollout, or post-rollout tasks. Do not add entries just to
describe behavior changes.

## Lock Order

When acquiring multiple mutexes in `endpoints/ac/`, follow this order
to prevent deadlocks. New code that takes locks in a different order
must update this list and audit all existing call sites.

- **`r.mu` then `device.peerMapMutex`, never reversed.** `r.mu` is
  acquired in `handleRegistrationResponse`'s direct-AAK branch and in
  `Stop()`; both call into `device.RemovePeerByAddress` /
  `device.LookupPeer` (which acquire `peerMapMutex` internally) while
  still holding `r.mu`. `core.Device` methods do not call back into
  `ACRegistration`, so `peerMapMutex` is leaf-most for the AC; a
  future change that takes `r.mu` while holding `peerMapMutex` would
  deadlock against the direct-AAK reconcile path.
- **`reconcileDevicePeers` does not acquire `r.mu` itself.** Callers
  decide. `HandleRedispatch` releases `r.mu` after the
  `assignedServers` swap and calls reconcile lock-free (the orphan
  family it admits is documented + surfaced via
  `MetricReconcileOverlap`). `handleRegistrationResponse`'s
  direct-AAK branch holds `r.mu` across reconcile to close the
  orphan-until-restart hole on that path.
- **L3 flush scheduler locks are scheduler-internal.** The L3 flush
  scheduler (PR #2164) adds: 256 sharded `shard.mu` entries (the
  index-per-key mutex), `wheelMu` (single mutex protecting wheel
  buckets + overflow + hand), and `breakerErrMu` (ring buffer of
  error timestamps). Start/Shutdown sequencing uses `sync.Once`
  (`startOnce` / `stopOnce`) plus the `started atomic.Bool`, not
  named mutexes. The full lock-order discipline lives in the
  `expiry_scheduler.go` package godoc — `shard.mu` is taken BEFORE
  `wheelMu` across the entire Schedule/Cancel sequence, and the
  scheduler does NOT call back into `UdpAC` while holding any of
  these locks (so no inversion is possible from outside-in callers).
  When extending the scheduler, keep the lock discipline documented
  in the scheduler godoc rather than duplicating it here.
- **`BpfFlusher.statsMu` is leaf-most and internal.** The lifecycle sampler
  serializes eBPF conntrack walk/reap work in its own goroutine and briefly
  takes `statsMu` only to publish the cached snapshot. `ConntrackStats` takes
  only `statsMu`, so gauge reads return the last snapshot without waiting on a
  map walk. Neither path calls back into `UdpAC`, `ACRegistration`, metrics
  publisher locks, or scheduler/tokenstore locks. Keep `statsMu` leaf-most;
  future changes that invoke AC callbacks while holding it must audit this
  table first.
- **`BpfFlusher.conntrackSamplerMu` guards only sampler lifecycle state.**
  Start/stop paths take it to read or swap the sampler pointer; they do not
  hold it while walking eBPF maps or waiting for sampler shutdown. The sampler
  goroutine clears the pointer during teardown and then closes `done`, so
  callers that wait for shutdown must snapshot the pointer, release the mutex,
  and only then wait.
- **`revocationIndex.mu` is leaf-most and internal.** The revocation index
  protects its token sets plus per-key epoch watermarks with one mutex. Apply
  paths snapshot tokens and release the mutex before touching tokenStore,
  scheduler, flusher, metrics, or registration state; add/remove paths are
  called after tokenStore operations have returned. The watermark TTL sweep may
  scan the map while holding this mutex, but it does not call back into any AC
  subsystem. Future changes that hold `revocationIndex.mu` while invoking
  tokenStore, scheduler, flusher, metrics, or registration code must audit this
  table first.
- **ConntrackFlusher netlink locks are leaf-most and internal.** `ctConn.mu`
  serializes request/response use of one pooled ctnetlink socket and may be held
  across dump/delete syscalls; `ctEventIndex.mu` guards the #2908 event-fed
  origin index and is held only while applying multicast events, startup
  backfill replay, taking a lookup snapshot, or pruning successfully-deleted
  origins after the indexed delete path has released its pooled socket.
  the current event-index generation pointer is an `atomic.Pointer` so the
  #2908 hot Flush path does not take a flusher-level mutex; `eventIndexMu`
  guards the archived-counter snapshot boundary used by cumulative gauges
  (resync swaps in the candidate, then closes and archives the old event
  subscription under this mutex so those gauges stay monotonic);
  `netlinkIndexResyncMu` serializes resync and final teardown so shutdown cannot
  leak a freshly rebuilt generation. `netlinkIndexResyncLaunchMu` gates worker
  `WaitGroup` Add vs Close Wait; Close takes and releases it immediately after
  setting `closed=true`, before cancellation and `WaitGroup` wait. Close waits
  for scheduled resync workers before taking `netlinkIndexResyncMu`, so a worker
  launched just before shutdown can acquire the mutex, observe `closed`, and exit
  instead of blocking behind Close's wait.
  `netlinkIndexResyncCancelMu` protects only the active resync cancel function;
  resync may briefly take it while holding `netlinkIndexResyncMu`, while Close
  takes and releases it before waiting for workers and final teardown. The netlink
  backend intentionally avoids nesting `ctConn.mu` and `ctEventIndex.mu`; resync
  may take `netlinkIndexResyncMu` before pooled-socket work and before swapping
  `eventIndexMu`, and no path takes the reverse order. The event-index
  `onUnhealthy` callback fires only after `ctEventIndex.mu` is released. None of
  these locks call back into
  `UdpAC`, `ACRegistration`, metrics publisher locks, tokenstore, or scheduler
  locks. Keep them leaf-most; future changes that invoke AC callbacks while
  holding any of them must audit this table first.
- **`tokenStore.mu` is never held while scheduler `shard.mu` /
  `wheelMu` are acquired** (#2172). The
  `TokenStore.OnExpire` hook wired by `(*UdpAC).Start` calls
  `cancelAllScheduledFlows` → `Scheduler.Cancel`, which takes
  `shard.mu` then `wheelMu`. To prevent an inversion against
  `Schedule`/`Cancel` invocations made from other AC code paths,
  `TokenStore.CleanExpired` snapshots expired `(token, entry)` pairs
  under `tokenStore.mu`, releases the lock, then invokes the hook
  batch outside the critical section. Fenced from the tokenstore
  side by `TestTokenStore_OnExpire_RunsAfterLockReleased`. A future
  hook caller that moves the invocation back inside `tokenStore.mu`
  would re-introduce the inversion.
- **`AccessEntry.mu` is leaf-most** (#2201/#2205). It guards
  `scheduledKeys` only; never hold it while taking `tokenStore.mu`
  or any scheduler lock. `cancelAllScheduledFlows` drains the set
  under `e.mu` and walks the returned slice outside the lock — the
  `Scheduler.Cancel` calls in that walk take scheduler shard locks
  freely. `scheduleFlushIfEnabled` records the key on `e.mu` BEFORE
  `Scheduler.Schedule` (closes a cross-entry shared-FlowKey race
  window — see scheduleFlushIfEnabled godoc); both critical sections
  are outside scheduler locks. A future change that calls
  `Scheduler.{Schedule,Cancel}` while holding `e.mu`, or takes
  `tokenStore.mu` while holding `e.mu`, would break this order.
  Mutex correctness fenced by
  `TestAccessEntry_ScheduledKeys_NoRaceDetectorTrip` under `-race`;
  cross-entry shared-FlowKey race (sequential) fenced by
  `TestUdpAC_CancelAllScheduledFlows_MultiSessionRaceKeepsKeyAlive`
  (live peer → key kept alive) and its deleted-peer counterpart
  `TestUdpAC_CancelAllScheduledFlows_DeletedHolderNotCountedKeyCanceled`
  (revoked/deleted peer → key Cancelled, the #2784 under-flush
  behavioral fence). The end-to-end ApplyRevocation order fence is
  `TestApplyRevocation_DeleteBeforeFlushOrderPreventsSiblingPushBack`,
  which intentionally gates `flushEntryNow` on `e.mu` to observe the
  post-delete/pre-flush window.
