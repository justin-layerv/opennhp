# 2026-07-04 · PR #3046 · qURL AC-open re-knock retry + DNS-fast timeout retune

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3046 · https://github.com/layervai/qurl-service/issues/976

> **Fix #1 (empty pinhole dst → AC `LOCAL_IP` for hostname/arbitrary-URL targets)
> shipped separately as #3048** and was adopted into this branch via merge — its
> rollout task lives in `2026-07-05-pr-3048-qurl-hostname-ac-open-localip.md`. This
> entry now covers only #3046's remaining, still-unmerged surface.

Two remaining changes on the qURL knock path, neither an infra change:

1. **Blue/green AC-reassignment re-knock retry** (`ac_open_reknock_retry.go`) plus
   additive-only observability: four bounded-cardinality counters on the existing
   60s-flush Publisher.
2. **DNS-fast timeout retune of the AC-open (knock) hot path.** The server→AC AOP
   transaction gets its own aggressive **1.5s** timeout
   (`ServerACOpenTransactionResponseTimeoutMs`), routed only to NHP_AOP and
   **decoupled** from the shared 4.7s `ServerLocalTransactionResponseTimeoutMs` that
   the DB-wrap (NHP_DWR) and forward (NHP_FWD) paths keep. Also: reknock backoff
   750ms→300ms, `HttpKnockProcessingBudget` 15s→5s, `DefaultBroadcastTimeout` 10s→3s,
   agent `FailureRetryInterval` 10s→2s (paired with qurl-service#1110, client timeout
   15s→7s). Worst-case AC-open drops ~10s→~3.3s; happy path is unchanged (ACK-speed).

   **Cross-repo lockstep (no build-time guard):** `HttpKnockProcessingBudget` (5s,
   nhp) must stay **<** qurl-service's `internal/nhp.defaultTimeout` (7s) so the server
   returns its authoritative answer before the client gives up. The coupling is
   comment-only on both sides (nhp `constants.go` ↔ qurl-service `knock_client.go`); a
   bump on either side is a coordinated two-repo change — verify the other side and
   this ledger before merging it.

- [ ] **Post-rollout (observability):** confirm the four new series appear in
      CloudWatch namespace `LayerV/NHP` — `KnockReknockRetry`,
      `KnockReknockRetrySuccess`, `KnockReknockNoFreshConns`,
      `KnockReknockDeadlineSkipped`. Steady-state all ~0. Read them as the four
      outcomes of the retry path (they fire at distinct points, so they do NOT
      overlap):
        - `KnockReknockRetry` WITH `KnockReknockRetrySuccess` tracking it = a
          flip/reassignment is being absorbed (fresh conns appeared, retry
          succeeded) — healthy.
        - `KnockReknockRetry` WITHOUT `KnockReknockRetrySuccess` = fresh conns
          appeared but the retry ALSO failed — ongoing thrash; investigate.
        - `KnockReknockNoFreshConns` rising = no fresh conn re-registered within the
          backoff (a stuck migration, or the surviving AC re-registered to a
          DIFFERENT server, which this local path does not forward in-flight) →
          escalate to the ops/forward fix, NOT this retry.
        - `KnockReknockDeadlineSkipped` rising = fresh conns existed but the caller's
          `HttpKnockProcessingBudget` was nearly spent (< one transaction timeout
          left), so the retry was skipped as un-winnable. A few are benign; a
          sustained rise means admission is eating the budget before AC-open → look
          upstream (slow prepare/authorize/commit), not at the AC.
      Note: a reknock-retried knock runs `processACOperationBroadcast` twice, so each
      retried knock adds a second `MetricBroadcastTotal` increment during a flip — the
      new `KnockReknock*` counters are the clean signal. Dashboard/alarm build-out can
      fold into the #976 Phase-0 observability epic (#3001).
- [ ] **Canary GATE (during rollout, not just a post-rollout dashboard):** the AOP
      timeout retune's one real risk degrades silently (the reknock hides the
      client-facing failure whenever a sibling conn exists), so gate the canary on it:
        - **Pre-req to validate:** prod keeps **`MaxACConnsPerID` > 1 per acId** in
          steady state. The entire sibling-conn retry recovery vector depends on it — a
          single-conn AC that false-times-out at 1.5s hits `NoFreshConns` → user-visible
          52005 with no server-side recovery. If single-conn ACs are common OUTSIDE
          migrations, that dominates the retry's benefit and the 1.5s is riskier than the
          watch below implies.
        - **Gate:** hold/roll back the canary on an elevated **AC connection teardown /
          re-registration** rate (watch it alongside `KnockReknockRetry` /
          `KnockReknockNoFreshConns`), not merely a post-hoc dashboard review — this is
          the failure mode most likely to surprise. A sustained rise = the 1.5s is too
          tight for the AC's real datapath-write latency under load → raise
          `ServerACOpenTransactionResponseTimeoutMs` (decoupled precisely to tune in
          isolation without touching DB/forward).
        - Watch **server goroutine count** too during a wide simultaneous flip: the
          UDP-direct reknock has no deadline (lifecycle ctx), so each timed-out knock
          holds a goroutine ~1.8s (backoff + one txn) with no shedding valve, unlike the
          HTTP path's `KnockReknockDeadlineSkipped` short-circuit. Bounded by the
          single-retry ceiling + idempotency, but a flip is a burst of held goroutines.
- [ ] **Post-rollout (timeout retune):** after the next canary, confirm the retune
      changed only the intended path's failure latency:
        - The 1.5s AOP timeout should fire (as reknock/timeout signal) only during real
          reassignment windows, not steady-state — watch the `KnockReknock*` rates.
        - Confirm the **DB-wrap (NHP_DWR) and forward (NHP_FWD)** paths are unaffected
          (they keep the shared 4.7s timeout; a rise in DHP data-access failures or
          forwarded-knock timeouts would mean the AOP decoupling regressed something).
        - Confirm no uptick in `MetricShutdownTransactionDrainTimeout` after a canary
          roll — the drain stays 15s (sized against the 4.7s DB-wrap), so it should be
          unchanged.
        - AC conn teardown / re-registration is the headline risk — but it's now the
          **canary GATE** above (why: the 1.5s AOP timeout covers the AC's pre-ACK
          ipset/eBPF datapath write, per the `ServerACOpenTransactionResponseTimeoutMs`
          godoc), so it's watched DURING rollout, not just reviewed after.
