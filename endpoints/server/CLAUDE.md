# endpoints/server — Local Guidance

## Prod Rollout Task Ledger

Server changes often create concrete prod rollout tasks such as internal
endpoint smoke tests, HMAC secret checks, metric/alarm verification,
shutdown/drain coordination, qurl-service coordination, or
qurl-reverse-tunnel-server coordination. When they do, update
[`../../docs/runbooks/prod-rollout-task-ledger.md`](../../docs/runbooks/prod-rollout-task-ledger.md)
by adding an entry following its PR Update Rule before merge.

During review, confirm either the task ledger was updated or the PR has no
pre-rollout, rollout, or post-rollout tasks. Do not add entries just to
describe behavior changes.

## Lock Order

When acquiring multiple mutexes in `endpoints/server/`, follow this order
to prevent deadlocks. New code that takes locks in a different order
must update this list and audit all existing call sites.

- **Peer maps before peers**: `acPeerMapMutex` / `dbPeerMapMutex` /
  `agentPeerMapMutex` are acquired before any `peer.Lock()` (which
  `MatchesIP`, `RecvAddr`, `UpdateRecv`, `LastSendTime`, etc. take
  internally). Do not invert: `isKnownPeerIP` (`udpserver.go`) holds
  the map mutex while iterating peers, and a reverse-order site would
  deadlock against it.
- **`remoteConnectionMapMutex` is leaf-most for the conn lifecycle**:
  no other mutex is acquired while holding it. The connection
  routine's defer takes it briefly to remove the global-map entry.
- **`acConnectionMapMutex` then `remoteConnectionMapMutex`, never
  reversed AND never nested.** `HandleACOnline`'s stale-conn cleanup
  acquires `acConnectionMapMutex` first to find the stale entry,
  releases it, then acquires `remoteConnectionMapMutex` to remove
  the global-map entry. The two are never held simultaneously — even
  nested-in-order acquisition is forbidden because the connection
  routine's defer would invert against it (it removes from
  `acConnectionMap` first, then from `remoteConnectionMap` via
  `removeConnection`).
- **`authServiceMapMutex` is leaf-most; never held while taking
  `pluginHandlerMapMutex`.** `applyAspMapDelta` (`udpserver.go`)
  takes `authServiceMapMutex.Lock()`, performs the build-fresh-then-
  swap, releases it, then calls `ensurePluginLoaded` which acquires
  `pluginHandlerMapMutex.RLock()`/`Lock()`. The two are sequenced,
  never nested — a future change that holds `authServiceMapMutex`
  while taking `pluginHandlerMapMutex` would invert against
  `updateResources` (`config.go`), which performs the inverse
  sequence (pluginHandlerMap writes via `LoadPlugin` happen INSIDE
  the iteration over `aspMap` BEFORE the final
  `authServiceMapMutex.Lock()` swap, so no overlap exists today).
  Both call sites must keep authServiceMap leaf-most.
- **`agentPeerMapMutex` then `device.peerMapMutex`, never reversed.**
  `AddAgentPeer` (`udpserver.go`) holds `agentPeerMapMutex` across
  the `device.AddPeer` call so both maps reflect the new agent in a
  single critical section — closes a TOCTOU window where
  `agentPeerMap` had the pubkey but `device.peerMap` didn't yet, a
  blind spot for any future receive-path consumer that gates
  synchronously on `device.peerMap` (e.g. NHP_LST register/list).
  Safe because `core.Device` methods never call back into
  `UdpServer` and so cannot reach `agentPeerMapMutex` from inside
  `device.peerMapMutex`. A future change that takes
  `device.peerMapMutex` and then `agentPeerMapMutex` would deadlock
  against `AddAgentPeer`.

## Graceful Shutdown — Ordering Invariants

`UdpServer.Stop()` runs ~15 cleanup steps in sequence. The six
listed below are **load-bearing ordering invariants** — re-ordering
or skipping any of them regresses customer-visible behavior during
canary deploys. The remaining steps (etcd close, webrtc stop,
license stop, listener close, device stop, wg.Wait, storage close,
plugin close) MUST run, but their order relative to one another is
not currently a correctness invariant. Read `Stop()` end-to-end
before adding or moving any step.

> **One additional ordering rule:** `metrics.Stop()` must come AFTER
> `awaitTransactionDrain` (step 5). The drain calls `IncrCounter` on
> the timeout path; moving `metrics.Stop()` above the drain would
> turn that counter into a silent no-op. Pinned inline in `Stop()`.

1. **`httpServer.Stop()` first** — closes the HTTP listener (no new
   requests can land) and `Shutdown(ctx)` waits up to its budget for
   in-flight HTTP handlers to return. HTTP handlers that trigger
   NHP knocks finish their retry loop here. Must run before any
   downstream cleanup so the handler still has a working NHP path.
2. **`cleanupOwnedAssignments()` + Cloud Map deregister** before the
   drain — stops peer servers from forwarding new work to this
   instance before we tell our ACs to leave.
3. **`drainACConnections()`** before any teardown that would prevent
   new transactions from being added or completed — sends NHP_ARD to
   every connected AC redirecting them to NLB, so ACs start
   reconnecting to surviving servers. Safe to run before step 4
   because NHP_ARD is not a request-type transaction on the server
   side (see `nhp/core/transaction.go::IsTransactionRequest`), so the
   drain itself does not add to the local transaction map.
4. **`forwarder.Stop()` before the transaction-drain wait** — stops
   the cross-server forwarder so no new forwarded knocks can spawn
   fresh local transactions while we're waiting for existing ones to
   clear. `forwarder.Stop()` only halts the cleanup routine — it does
   not drain in-flight forwards — so it's safe to run pre-drain.
   `listenConn` is intentionally **kept open** through step 5; closing
   it pre-drain would cause every in-flight server→AC transaction
   (waiting for an AC response on listenConn) to time out at
   ServerLocalTransactionResponseTimeoutMs instead of completing
   normally — net worse than the race the drain solves.
5. **`awaitTransactionDrain(shutdownTransactionDrainTimeout)`** —
   waits for in-flight local NHP transactions (server→AC knocks,
   forwarded queries, etc.) to complete or time out. Without this
   step, the close in step 6 races every in-flight transaction and
   each one returns `ErrTransactionFailedByClosedConnection` to its
   caller (observed as `knock_failed` 500s on the qURL plugin during
   canary rolls). Bounded by `shutdownTransactionDrainTimeout`;
   `MetricShutdownTransactionDrainTimeout` fires if exhausted.
6. **`close(s.signals.stop)`** — terminates every per-connection
   goroutine, which closes each `ConnectionData.StopSignal`. Any
   transaction still selecting on that signal returns the closed-
   connection error. Must come **after** step 5 so the drain has
   already given those transactions a chance to finish cleanly.

A residual race remains: a UDP packet arriving on `listenConn`
between the drain's last `count == 0` observation and step 6 can
still spawn a fresh transaction that gets stranded. `Stop()` logs
a warning if it observes this. The durable fix is at the LB/ASG
layer (deregister the instance from the NLB target group BEFORE
SIGTERM reaches the process) — tracked as a separate PR.
