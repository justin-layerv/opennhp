# endpoints/server — Local Guidance

## Prod Rollout Ledger

Server changes often create concrete prod rollout tasks such as internal
endpoint smoke tests, HMAC secret checks, metric/alarm verification,
shutdown/drain coordination, qurl-service coordination, or
qurl-reverse-tunnel-server coordination. When they do, add a succinct entry file under
[`../../docs/runbooks/prod-rollout-ledger/`](../../docs/runbooks/prod-rollout-ledger/)
before merge (delete it once its tasks are done).

During review, confirm either the task ledger was updated or the PR has no
pre-rollout, rollout, or post-rollout tasks. Do not add entries just to
describe behavior changes.

## Lock Order

When acquiring multiple mutexes in `endpoints/server/`, follow this order
to prevent deadlocks. New code that takes locks in a different order
must update this list and audit all existing call sites.

> **Always release with `defer`, never a bare unlock on the happy path.**
> `dispatchHandler` recovers panics in message-handler goroutines (PR #3643,
> synced from upstream `94a5ff67`), so a panicking handler no longer takes the
> process down with it. A `defer mu.Unlock()` still runs during unwinding,
> before the recover — but a handler that unlocks only on the success path
> leaks the lock permanently, and every later request contending on it
> deadlocks. That is strictly worse than the crash the recover replaced: the
> crash was loud and self-healing via ASG restart, the leaked lock is a silent
> hang. The recovery emits a `Critical` line that pages via the
> `server_handler_panic` alarm; treat any occurrence as a bug to root-cause,
> not a steady state to absorb.
>
> **Audited at PR #3643. The safety property is NOT "no bare unlock is
> reachable" — several are. It is that every reachable one has a panic-free
> critical section.** An AST reachability pass over the pinned handler set
> (name-matched, so deliberately over-approximating) found bare unlocks on the
> handler goroutine in `resolveAgentPeerForKnock`, `applyAspMapDelta`,
> `loadPluginOnce`, `LoadPlugin`, `snapshotLiveACConns`, and
> `handleNhpOpenResource`. Every one of them holds the lock across a pure map
> read/write or an allocation (`slices.Clone`, `make`) and calls nothing that
> can fault on attacker input, so a panic cannot occur while the lock is held.
> `handleNhpOpenResource`'s is additionally a function-local mutex that cannot
> outlive the call.
>
> That is the invariant to preserve. **Adding a call that can panic inside any
> of those critical sections is the regression** — not the bare unlock itself.
> When in doubt, use `defer`. `TestAuditedCriticalSectionsStayPanicFree`
> enforces this: it fails if a call appears inside one of the audited sections.
>
> **Recovery is not transparent — it restores the lock, not the data.** A
> `defer mu.Unlock()` fires correctly during unwinding, so a handler that
> panics mid-critical-section releases its mutex — with the guarded structure
> left half-updated, visible to every later goroutine. The crash this replaced
> discarded that state wholesale on restart. This is an accepted trade, because
> the class being hardened against is parser panics that fault on
> attacker-controlled bytes *before* touching shared state; it is not a licence
> to treat recovery as free. A handler that mutates shared state in several
> steps should reach a consistent point before it can panic, or carry its own
> rollback.
>
> **The same applies to every happy-path-only cleanup, not just unlocks.**
> Mutexes get the tests above because they deadlock loudest, but a handler that
> removes its transaction-map entry, stops a timer, returns a pooled buffer, or
> decrements a counter *only on the success path* now leaks that resource on a
> recovered panic where the process used to die and reset it. Before the
> recover, "the process dies" was the cleanup of last resort for all of it. If
> a handler acquires anything that must be given back, give it back with
> `defer`.
>
> `connDataForOutboundAddr` is the named hazard and is **not** reachable today:
> it holds the central `remoteConnectionMapMutex` across three helper calls
> with bare unlocks on every branch, and a leak there deadlocks the whole
> connection layer. Reachability analysis reports a false edge into it via
> `forwardToTransaction -> SendMessage`; that `SendMessage` is
> `core.RemoteTransaction`'s channel send, not `(*UdpServer).SendMessage`. If a
> handler ever reaches it for real, convert it to `defer` first.
>
> The forwarder path (`FanoutKnock -> forwardToServer -> SendMessage ->
> connDataForOutboundAddr`) *is* called from `handleNhpOpenResource`, but from
> inside a nested `go func()`, so the recover does not cover it and those locks
> are not at risk from this change.
>
> **The recover's blast radius is one goroutine.** `recover()` catches only
> panics on its own stack, so a handler that spawns `go func()` is NOT
> protected inside those children — `handleNhpOpenResource`'s AC-open fan-out
> is the live example. `dispatchAsync` (NHP_AOL, NHP_FWD, NHP_FRT) has no
> recover at all. Both still crash the process on panic, which is why the
> stderr `server_panic` alarm remains load-bearing alongside
> `server_handler_panic`.

- **Peer maps before peers**: `acPeerMapMutex` / `dbPeerMapMutex` /
  `agentPeerMapMutex` are acquired before any `peer.Lock()` (which
  `MatchesIP`, `RecvAddr`, `UpdateRecv`, `LastSendTime`, etc. take
  internally). Do not invert: `isKnownPeerIP` (`udpserver.go`) holds
  the map mutex while iterating peers, and a reverse-order site would
  deadlock against it.
- **`remoteConnectionMapMutex` nests only `overloadMu` for connection
  pressure publication.** The connection routine's defer takes the map lock
  briefly to remove the global-map entry and may then call
  `setConnectionOverload`, which acquires `overloadMu`. No other mutex may be
  acquired while holding `remoteConnectionMapMutex`.
- **`overloadMu` is leaf-most.** It may be acquired while holding
  `remoteConnectionMapMutex`; while held, overload publication performs only
  atomic source reads/stores and `device.SetOverload` (an atomic store). Never
  acquire a map, peer, plugin, or publisher mutex while holding it.
- **`outboundConnStartMutex` is not nested with server data locks.**
  `connDataForOutboundAddr` takes it only after releasing
  `remoteConnectionMapMutex`; `Stop()` takes it alone as a barrier before
  `wg.Wait`. Do not hold it while acquiring map, peer, or plugin locks.
- **`acConnectionMapMutex` then `remoteConnectionMapMutex`, never
  reversed AND never nested.** `HandleACOnline`'s stale-conn cleanup
  acquires `acConnectionMapMutex` first to find the stale entry,
  releases it, then acquires `remoteConnectionMapMutex` to remove
  the global-map entry. The two are never held simultaneously — even
  nested-in-order acquisition is forbidden because the connection
  routine's defer would invert against it (it removes from
  `acConnectionMap` first, then from `remoteConnectionMap` via
  `removeConnection`).
- **Revoked-AC live-drop cleanup keeps the same sequencing.**
  `dropRevokedACPubkeyConnections` removes matching `ACConn` entries
  under `acConnectionMapMutex`, releases it, then touches
  `remoteConnectionMapMutex`, and only later holds
  `acConnectionMapMutex.RLock()` through the no-live-conn scan and
  `removeACPeer` (`device.peerMapMutex` then `acPeerMapMutex`). This
  serializes the remove decision with `ACConn` appends. Cloud-mode
  `HandleACOnline` publishes/re-publishes its peer after the `ACConn`
  append via `ensureACPeerForLiveConn`, which holds the same RLock
  while calling `AddACPeer`; if cleanup removes the peer before the
  append, the registration restores it after the conn is live, and if
  the append wins first cleanup observes the live conn and keeps the
  peer. Do not take `remoteConnectionMapMutex` in either nested
  section.
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
   ServerACOpenTransactionResponseTimeoutMs instead of completing
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
