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
  behavioral fence).
