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
