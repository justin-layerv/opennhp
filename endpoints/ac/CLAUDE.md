# endpoints/ac — Local Guidance

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
