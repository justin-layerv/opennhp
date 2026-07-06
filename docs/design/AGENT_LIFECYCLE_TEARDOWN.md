# NHP Agent Lifecycle & Teardown Model

Reference for the concurrency invariants that keep `endpoints/agent`'s
`Stop()` / `RestartAgent()` teardown race-free. The inline comments at each
site are the source of truth for the local mechanics; this doc is the map that
ties them together. Introduced by the #3084 port (OpenNHP PR #1552
adaptation); see `docs/UPSTREAM_SYNC.md`.

## The hazard

`RestartAgent()` runs the full `Stop()` teardown and then `Start()` on the same
`*UdpAgent`, while SDK calls, the knock/DHP loops, the DHP web-console handlers,
and a debounced config-watcher callback may still be in flight. Naively, that
races teardown into: send-on-closed-channel panics, `close`-of-closed double
closes, `wg.Wait()` deadlocks, and nil-derefs. Blast radius is a single agent
process.

## Invariants

1. **`sendMsgCh` and `knockTargetMapUpdated` are never closed.** Their consumers
   (`sendMessageRoutine`, `knockResourceRoutine`) return on `signals.stop`, so
   the close is redundant for shutdown — and unsafe: not every sender is
   `wg`-tracked, so `wg.Wait()` doesn't fence them. Crucially, a `select` **send
   case on an already-closed channel is still "ready"** and can be chosen (~50%),
   so select-on-stop *alone* only narrows the window; not closing the channel is
   what removes it. (Upstream `8e983f1d` gave `knockTargetMapUpdated` this
   treatment; the fork extends it to `sendMsgCh`.) Fenced by
   `TestStop_LeavesSendChannelOpen`.

2. **Every send to `sendMsgCh` goes through `sendOrStop`** — a `select` on the
   send vs `signals.stop`. It bails cleanly if the routine has exited rather than
   blocking forever on a full buffer. All 8 sites (request methods, knock/DHP,
   DHP DAR/DAV).

3. **Every blocking device receive goes through `awaitOrDeadline`** — a generic
   helper (`request.go`) doing a leading non-blocking receive (prefer an
   already-delivered value over a bail) then a `select` on the value vs
   `signals.stop` vs an optional deadline. Two call sites: `awaitTransactionResponse`
   (the transaction `ResponseMsgCh`, via the no-deadline wrapper `awaitOrStop` —
   the transaction layer carries its own `AgentLocalTransactionResponseTimeoutMs`)
   and `preAccessRequest` (the `EncryptedPktCh` from the encrypt pipeline, **with**
   a deadline). Both channels are **buffered size-1**, **closed on the receive
   path**, and **left open on the bail path**, so a late, blocking `device.wg`
   write lands in the buffer instead of deadlocking `device.Stop()`. The close is
   a deliberate fail-loud tripwire for a future second writer. `preAccessRequest`
   matters because it's reachable synchronously from the `a.wg`-tracked `Knock`,
   so a bare receive there would strand `wg.Wait()` when `SendMsgToPacket`
   discarded the message (non-blocking) or the device is mid-teardown — and,
   because it's a direct device encrypt rather than a transaction, it's the one
   receive without a transaction-layer timeout, so it carries its own deadline
   (`AgentLocalTransactionResponseTimeoutMs`) to also bound the discard-**while-
   running** case (a full `msgToPacketQueue` under load) rather than park until
   the next `Stop()`. **Operational note:** under *sustained* queue overload that
   caps a `wg`-tracked knock sub-routine's encrypt-await at ~5s (it then returns
   `ErrTransactionFailedByTimeout`; pre-access is best-effort — the caller only
   logs, so the knock still succeeds). A value left in the buffer by a bail is not `Destroy()`'d,
   so its pooled packet is reclaimed only on device teardown — a negligible
   tradeoff (bounded in-flight count vs a ~256Ki-slot pool) versus the hang it
   avoids.

4. **Single-writer channels (in `nhp/core`).** Invariant #3's close-on-receive is
   safe only because each channel gets exactly one write. Two channels rely on it:
   - `ResponseMsgCh` (pre-existing — the agent already did `serverPpd := <-ch;
     close(ch)`): four writers (`transaction.go` completion + error defers,
     `device.go` two pre-transaction error paths), mutually exclusive; the port
     *documents and fences* it — back-reference comments at all four sites +
     `TestResponseMsgChWrittenExactlyOnce` (the `device.go` pre-transaction leg)
     + `TestLocalTransactionResponseMsgChWrittenExactlyOnce` (the transaction-owned
     completion-vs-error-defer leg, driving a real completion; was #3104).
   - `EncryptedPktCh`: two `device.go` `msgToPacketRoutine` writers (success
     return + error defer), mutually exclusive on the same `err != nil` guard,
     fenced by `TestEncryptedPktChWrittenExactlyOnce`.

5. **`Stop()` ordering** (`udpagent.go`):
   `running.CompareAndSwap(true,false)` → `stopKnockLoop()` → `close(signals.stop)`
   → `StopConfigWatch()` → `a.wg.Wait()` → `a.device.Stop()`.
   - The **CAS** makes `Stop()` idempotent (a second/concurrent `Stop()` returns
     early instead of double-closing; a pre-`Start()` `Stop()` is a safe no-op).
   - **`lifecycleMu` serialization (#3103).** `Start()` reassigns `signals.stop` /
     `sendMsgCh` / `knockTargetStopOnce` and flips `running` under
     `lifecycleMu.Lock`; `Stop()` holds it across the CAS + `stopKnockLoop` +
     `close(signals.stop)` (released before `wg.Wait`). SDK ops read the
     reassigned fields only via a snapshot under `RLock` (`sendOrStop`,
     `stopSignal()`) and register their `a.wg.Add` via `beginTrackedOp` /
     `launchTrackedRoutine` (also `RLock`). This closes both the
     `Start()`-field-reassignment **data race** and the direct-SDK-`Knock` /
     `Stop()`-racing-`Start()` **"WaitGroup is reused before Wait" panic**: an
     `Add` either lands before `Stop()`'s CAS (so `wg.Wait` counts it) or sees
     `running=false` and bails, and `Stop()` now blocks on `Start()`'s `Lock` and
     stops the fully-started agent instead of CAS-failing mid-launch. The `RLock`
     is held only across the snapshot / `Add`, never a blocking send/receive
     (which would deadlock `Stop()`'s brief `Lock`).
   - **`wg.Wait()` before `device.Stop()`** avoids racing `sendMessageRoutine`'s
     feed into a closed `msgToPacketQueue` (`device.Stop()` closes it). The sole
     prerequisite is that **every `a.wg` routine returns on `signals.stop`
     without needing the device torn down** — which holds: `sendMessageRoutine`'s
     `device.SendMsgToPacket` is a **non-blocking** send (discard-on-full, with a
     reciprocal breadcrumb at that call site), so it can't stall `wg.Wait()`; and
     the `wg`-tracked knock paths bail on `signals.stop` at their response
     receives (invariant #3), the load-bearing guard. Note the device's *own*
     shutdown (`msgToPacketRoutine` draining `conn.SendQueue`, `ForwardOutboundPacket`'s
     `StopSignal` escape) is a `device.wg` concern that `device.Stop()` resolves
     **after** this `wg.Wait()` — it is *not* a prerequisite for the reorder,
     since those routines aren't in `a.wg`.

6. **`knockTargetStopOnce`** guards `close(knockTargetStop)` (closed by both
   `StopKnockLoop()` and `Stop()`), re-armed in `Start()` so `RestartAgent`
   reuse doesn't leave a spent `Once` (which would deadlock `wg.Wait()`).
   `StopKnockLoop`/`StartKnockLoop` are therefore **not** a standalone reusable
   pair — a fresh `Start()` is required to re-arm.

7. **Interruptible backoffs.** `Knock`'s ~4.9s error backoff and
   `dhpKnockResourceRoutine`'s 2s retry sleep both `select` on `signals.stop`, so
   these `wg`-tracked routines don't stall `wg.Wait()` per active target on
   teardown.

## Behavioral notes

- **Best-effort on a raced `Stop()`.** A response arriving at the same instant
  `signals.stop` closes may be dropped and reported as
  `ErrPacketToMessageRoutineStopped`. Advisory: external SDK consumers should
  treat that error as retriable (the request may have taken effect server-side).
  Not enforced in-tree; the in-tree knock loops already retry.
- **Teardown logs are `Debug`.** Logs that fire only when the agent is stopping
  (the `IsRunning()`-gated skips; the knock/DHP-loop stopped-error paths) are
  `Debug`, so a routine `RestartAgent` doesn't trip error-log alerting.
- **Nil-safe log identity.** `deviceKey()` avoids `%v`-reflecting `*UdpAgent`
  (which would walk unlocked maps → the unrecoverable "concurrent map iteration
  and map write" throw) and is nil-safe for pre-`Start()` log sites.

## Once-tracked follow-ups (all fixed in this PR)

The concurrency gaps this port surfaced were closed here rather than deferred:

- **#3103** — `Start()`'s lock-free field reassignment vs concurrent SDK reads,
  and the direct-`sdk.KnockResource` / `Stop()`-racing-`Start()` "WaitGroup
  reused" panic. Closed by `lifecycleMu` (invariant #5) for the reassigned
  channels — `signals.stop` / `sendMsgCh` / `knockTargetMapUpdated` are read via
  `RLock` snapshots (`stopSignal` / `sendOrStop` / `mapUpdatedSignal`) — and by
  taking `knockTargetMapMutex` / `serverPeerMutex` around the map re-init. Fenced
  by `TestBeginTrackedOp_ConcurrentStop_NoWaitGroupReusePanic`,
  `TestRestart_ConcurrentSendOrStop_NoFieldRace`,
  `TestRestart_ConcurrentMapDelete_NoMapRace`, and
  `TestRestart_ConcurrentMapUpdatedSignal_NoFieldRace`.
- **#3104** — executable fence for the transaction-owned `ResponseMsgCh`
  single-writer leg: `TestLocalTransactionResponseMsgChWrittenExactlyOnce`
  (invariant #4).
- **#3108** — `resolveServerAddr`'s misconfig logs demoted `Critical`→`Error`
  (they're a retriable return to the knock retry loop, not a process-integrity
  event).
- **#3112** — the while-running `EncryptedPktCh` discard hang (a full
  `msgToPacketQueue` dropping the packet with `signals.stop` open, parking
  `preAccessRequest` until the next `Stop()`). Closed by the `preAccessRequest`
  encrypt deadline (invariant #3).

The CAS-loser's early return (before the winner's `wg.Wait()`/`device.Stop()`) is
drain-safe for every in-tree caller: `sdk.Close` only nils the GC-live singleton,
and the web-console `restartAgent` handler + `main` return without reusing a
device-touched resource — no caller treats a `Stop()` return as "teardown fully
drained."

## Open follow-up

- **#3114** — `Start()` also reassigns **`a.device`** (and `a.config`) lock-free,
  raced by unsynchronized SDK reads: `AddServer` (`a.device.AddPeer`) and the
  request methods (`RequestOtp`/`RegisterPublicKey`/`ListResource` → `newMsgData`
  → `a.device.NextCounterIndex`, gated only by `IsRunning()` so no `wg` token pins
  `a.device`). Bounded to the agent field-publish — `nhp/core`'s `Device` is
  already thread-safe (`AddPeer` locks `peerMapMutex`; `Stop()` deliberately
  doesn't invalidate `peerMap`) — but spans ~15 heterogeneously-guarded sites plus
  `a.config`, so scoped to its own focused PR rather than the #3084 teardown fixes.
