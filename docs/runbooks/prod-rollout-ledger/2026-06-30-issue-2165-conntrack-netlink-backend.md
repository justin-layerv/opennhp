# 2026-06-30 · issue #2165 · AC ConntrackFlusher direct-netlink backend (opt-in)

- **Owner:** prod rollout coordinator
- **Source:** [#2165](https://github.com/layervai/nhp/issues/2165) · [#2908](https://github.com/layervai/nhp/issues/2908) · runtime resync [#2946](https://github.com/layervai/nhp/issues/2946)/[#2966](https://github.com/layervai/nhp/pull/2966) · capacity audit [#2163](https://github.com/layervai/nhp/issues/2163) · v6 gap [#2794](https://github.com/layervai/nhp/issues/2794)/[#2797](https://github.com/layervai/nhp/pull/2797) · exec-backend PR [#2164](https://github.com/layervai/nhp/issues/2164)

Adds `l3FlushConntrackBackend` to AC config. `"exec"` (default) keeps today's
fork+exec `conntrack -D`. `"netlink"` switches `FilterMode_IPTABLES` L3 flush to a
direct NFNL_SUBSYS_CTNETLINK datapath (no fork, no locale stderr-scrape, IPv4+IPv6).
The backend is built once at AC Start — **a change requires an AC restart**, not a
live config reload. Enabling netlink also closes the iptables-mode IPv6
immediate-revocation gap (#2794): the coarse flush becomes v6-capable, so
`RevocationIPv6HardFail` stops firing for iptables v6 revokes
(`coarseConntrackHandlesV6`).

Dependency note: `github.com/florianl/go-conntrack`,
`github.com/mdlayher/netlink`, `github.com/mdlayher/socket`, and
`github.com/josharian/native` were checked as MIT-licensed. The netlink backend
does not rely on go-conntrack `Config.ReadTimeout`/`WriteTimeout`; those are
deprecated/insufficient for this whole-Flush budget, so the code applies explicit
`SetReadDeadline` + `SetWriteDeadline` calls on `nfct.Con` before dump/delete.
Treat these as enforcement-path dependencies: do not flip prod while normal
Dependabot/CVE/image-scan gates have an open high/critical finding against this
module chain.

Also adds `l3FlushConntrackPoolSize` (default 16; ≤0 → default, clamped to 128) so
the socket-pool : worker ratio can be tuned during the soak without a code change.
The default is the conservative #2165 sketch ratio (16 single-flight netlink
sockets for the 64-worker scheduler), and the soak must explicitly accept or tune
that ratio because each socket holder owns its delete loop (or the safe O(table)
dump fallback if the #2908 event index is unhealthy) for the whole `Flush`. The
soak measures the channel-backed free-list pool routing model: acquired sockets
are absent until release, so contention signals should be interpreted after
availability-aware routing, not round-robin head-of-line blocking.

#2908 adds a conntrack NEW/UPDATE/DESTROY event index seeded by a one-time startup
dump. While that event stream is healthy, steady-state `Flush` is O(matches): look
up the full origin tuples for `{src,dst,dport,proto}` and delete those entries
without dumping the whole family table. If the event stream errors or is not
usable, the flusher falls back to the old dump/filter/delete path rather than
silently missing flows; the #2946/#2966 fix rebuilds a fresh subscription
generation at runtime so a transient multicast overrun does not pin the AC to
fallback until restart. If an immediate-revocation reschedule needs fresh kernel
ground truth, it intentionally uses the same dump/delete path and counts that
separately.
Netlink-only soak-readability metrics:
`L3FlushConntrackDeleted` (entries torn down), `L3FlushConntrackIndexedFlushes`
(event-index hot path used), `L3FlushConntrackIndexFallbackDumps` (safe O(table)
fallback used because the index was unavailable/unhealthy),
`L3FlushConntrackIndexAuthoritativeDumps` (intentional fresh-ground-truth dumps
for immediate revocation), `L3FlushConntrackIndexEventErrors` (event stream
disabled the index), `L3FlushConntrackIndexPendingOverflows` (startup replay
pressure tripped the pending cap), `L3FlushConntrackIndexResyncAttempts`,
`L3FlushConntrackIndexResyncSuccesses`, and
`L3FlushConntrackIndexResyncFailures` (runtime #2946 recovery),
`L3FlushConntrackIndexEvents` (event-stream liveness),
`L3FlushConntrackIndexOrigins` (resident userspace mirror cardinality),
`L3FlushConntrackDumpLatency` (per-Flush dump latency distribution in ms for
CloudWatch percentile reads; fallback/authoritative Flush dumps only, not
startup/resync backfill dumps), `L3FlushConntrackDumpLatencyDropped` (histogram
samples dropped from the AC-local buffer before publish; period-Sum delta),
`L3FlushConntrackDumpLatencyNegativeDurations` (impossible clock/instrumentation
anomalies ignored before histogram buffering; cumulative gauge),
`L3FlushConntrackSlowDumps`
(fallback/authoritative dumps over ~1ms),
and the existing breaker/`FlushErr` series. During populated-table characterization,
`IndexedFlushes` should rise with deletes, `IndexEvents` should advance when the
conntrack table churns, `IndexOrigins` should match the expected table
cardinality envelope while the index is healthy, and fallback/error/
resync-failure/slow-dump counters should stay flat after startup except for
intentional authoritative immediate-revocation dumps or an injected/real
event-loss episode; any unexplained fallback rate means the million-table
throughput claim is not established even though correctness is preserved. If the
event index disables itself, the resident mirror is reclaimed
and `IndexOrigins` is expected to drop to 0 while fallback/error counters explain
why the hot path is no longer active. Treat `IndexOrigins = 0` as a correlated
signal, not an alertable fact by itself: it also represents a healthy empty
table, so dashboards/sign-off must read it alongside `IndexEventErrors` and
`IndexFallbackDumps`.
The event monitor raises its netlink receive buffer but deliberately does **not**
enable `NETLINK_NO_ENOBUFS`: ENOBUFS must stay visible because it means multicast
events may have been dropped and the index is no longer complete. Today that
condition disables the current index, uses safe dump fallback while resync
rebuilds a fresh subscription generation, and surfaces recovery on the resync
metrics added for [#2946](https://github.com/layervai/nhp/issues/2946). Runtime
`EventErrors` are cumulative subscription-health evidence and remain non-zero
after a recovered blip; use resync attempts/successes/failures plus fallback
dumps for current recovery posture. Runtime resync attempts are rate-limited by
a minimum interval, so sustained event loss should show bounded
`ResyncAttempts`/`SlowDumps` rather than continuous rebuilds.

- [ ] Pre-rollout: on a **sandbox** iptables-mode AC, confirm the netlink datapath
      is available — `nf_conntrack_netlink` loadable + AC has `CAP_NET_ADMIN`
      and the rendered AC config carries the rollout-selected
      `L3FlushConntrackBackend = "netlink"` plus the accepted
      `L3FlushConntrackPoolSize` (0 means the AC default, currently 16). The
      issue #2940 config-gate PR adds Terraform passthrough for those two config
      keys; without that passthrough, #2940 could not be completed through the
      managed sandbox AC config because Terraform rendered only
      `EnableL3FlushOnExpiry` and `L3FlushDryRun`.
      The same config-gate PR also introduces benign prod launch-template
      user_data drift: prod continues to render `exec`/`0`, so behavior remains
      unchanged, but the two explicit config lines will land on the next prod AC
      instance refresh.
      As of 2026-07-04, the live sandbox blue and green AC instances render
      `FilterMode = 1`, `EnableL3FlushOnExpiry = false`, and
      `L3FlushDryRun = true`; the issue #2940 acceptance run still requires a
      deliberate iptables-mode sandbox/standby AC validation window rather than
      interpreting the active eBPF/XDP fleet as netlink evidence.
      (it already manages iptables/ipset/`conntrack -D`, so this should hold; the
      flusher fails Start loud if `conntrack.Open` fails). The #2908 event index
      also makes netlink event subscription and the startup backfill dump fatal
      for the opt-in netlink backend: a subscription failure or a 30s backfill
      timeout blocks AC start rather than silently running with an unproven
      snapshot. Event-stream loss during backfill is different and intentionally
      softer: the AC starts on safe fallback dumps, error/pending-overflow
      counters stay visible, `IndexOrigins` remains 0, and runtime resync
      restores the hot path once the stream is healthy. The #2908 throughput
      claim is not accepted until restart/backfill or runtime resync arms the
      index at target cardinality. Treat startup stream loss as an explicit
      throughput-only sign-off item: enforcement still uses safe dump fallback,
      but the hot path is absent until recovery. Confirm that fail-closed
      subscription/timeout posture and degraded-on-stream-loss posture are
      acceptable for the target instance before flipping the backend. Then run
      `NHP_CONNTRACK_NETLINK_BENCH_GATE=1 go test -bench=BenchmarkConntrackFlusher_Netlink -benchtime=2s ./endpoints/ac/`
      on that AC and confirm **≤200µs/op** (the #2165 acceptance gate). The env
      var intentionally turns the benchmark's warning into a hard failure for
      this acceptance run; ordinary ad hoc/CI `-bench` invocations may only log an
      unready-AC miss. The bench skips where netlink event subscription is
      unavailable, so a skip means the AC isn't ready.
      On the same AC, run a real-kernel idempotency probe before the flip: confirm
      a no-match netlink `Flush` returns nil (the #2168 schedule-then-write
      contract) and confirm a targeted absent-origin delete surfaces as ENOENT
      through `errors.Is(err, unix.ENOENT)` / `conntrackDeleteResult` maps it to
      nil. Also create one real TCP/UDP conntrack entry, run a netlink `Flush`
      for its FlowKey, and confirm the entry is gone from the kernel table so
      the manual gate proves a positive delete, not only no-match/idempotency.
      Also confirm the socket deadline seam (`SetReadDeadline` +
      `SetWriteDeadline` on `nfct.Con`) bounds a short-deadline dump/delete probe
      rather than parking a worker past `flushCallTimeout`.
      Also run a non-gated characterization against a representative populated
      conntrack table (or an artificially populated table at the target
      cardinality): compare exec vs netlink-index p50/p95/p99 flush latency at
      the target table size, record table cardinality,
      `L3FlushConntrackIndexedFlushes`, `L3FlushConntrackIndexFallbackDumps`,
      `L3FlushConntrackIndexAuthoritativeDumps`,
      `L3FlushConntrackIndexEventErrors`,
      `L3FlushConntrackIndexPendingOverflows`,
      `L3FlushConntrackIndexResyncAttempts`,
      `L3FlushConntrackIndexResyncSuccesses`,
      `L3FlushConntrackIndexResyncFailures`,
      `L3FlushConntrackIndexEvents`, `L3FlushConntrackIndexOrigins`,
      `L3FlushConntrackDumpLatency` p50/p95/p99/p999,
      `L3FlushConntrackDumpLatencyDropped`,
      `L3FlushConntrackDumpLatencyPublisherDropped`,
      `L3FlushConntrackDumpLatencyNegativeDurations`,
      `L3FlushConntrackSlowDumps`, `PublisherFailures`, AC process RSS/Go heap,
      and GC pause. Record
      the steady-state resident index cost at the target cardinality, not just
      transient dump allocation, because the #2908 index intentionally trades
      repeated O(table) dumps for a full userspace origin mirror.
      Record index arm-success across repeated AC restarts/backfills at the
      target cardinality; a startup that leaves `IndexOrigins = 0` with
      `L3FlushConntrackIndexPendingOverflows`/event errors means the hot path
      failed to arm and cannot support the #2908 throughput claim.
      `L3FlushConntrackDumpLatency` intentionally proves only steady-state
      fallback/authoritative `Flush` dump cost; startup/resync backfill dumps
      are excluded from that histogram and must be accepted or rejected from the
      backfill wall-time measurement here. A clean percentile envelope alone is
      not sufficient: failed/timed-out dumps do not sample the histogram, so
      `FlushErr`/breaker pressure must stay flat while the histogram is healthy.
      Treat a `L3FlushConntrackDumpLatency` gap during a window with
      `PublisherFailures > 0` as best-effort publish loss, not proof that no
      fallback/authoritative dumps occurred.
      Evaluate `L3FlushConntrackDumpLatencyDropped` and
      `L3FlushConntrackDumpLatencyPublisherDropped` as per-window deltas, and
      `L3FlushConntrackDumpLatencyNegativeDurations` as a cumulative value or
      increase; all three should remain zero.
      During the first populated-table soak window with more than 150 unique
      dump-latency values, sanity-check that CloudWatch p50/p95/p99 aggregate
      across the metric's multiple same-timestamp `Values`/`Counts` datums.
      Use p50/p95/p99/p999 for acceptance, not min/p0, because the histogram
      intentionally floors zero or sub-microsecond dumps at `0.001` ms.
      Record the startup backfill dump wall time against the 30s
      `defaultNetlinkIndexBackfillTimeout` budget so the soak distinguishes a
      steady-state throughput win from a startup-availability cliff. Startup
      fail-closed is intentional for the opt-in netlink backend: if the event
      subscription cannot arm or the seed backfill cannot complete inside that
      budget, the AC should fail visibly instead of silently starting in the old
      O(table)-per-Flush regime. Do not flip prod until the observed backfill
      wall time has clear headroom under representative cardinality/churn, or
      tune/escalate before enabling.
      Also run a low-frequency completeness reconcile during the characterization:
      compare a kernel dump snapshot against the event index's expected origin
      count/match set for sampled FlowKeys. Counter flatness proves the hot path
      is active and error-free; this reconcile is the gate that proves it is
      complete enough to trust for indexed no-match Flushes. Sign-off must record
      the observed NEW-event apply lag / reconcile skew bound, because an indexed
      no-match is not a fresh kernel-ground-truth dump; it means the healthy event
      mirror currently has no matching origin. Do not proceed unless that measured
      lag window is explicitly accepted for scheduled-expiry teardown semantics;
      immediate-revocation `RescheduleEarlier` flushes bypass the index and use a
      fresh dump so the revocation path does not rely on that async no-match.
      This is a **hard rollout gate**: do not proceed to the prod flip if
      `L3FlushConntrackIndexEventErrors` has a nonzero rate, if
      `L3FlushConntrackIndexFallbackDumps` has a nonzero rate, or if indexed
      netlink is worse in that regime. Record
      `L3FlushConntrackIndexAuthoritativeDumps` separately so immediate
      revocation dump cost is visible without masking event-index fallback
      health, and do not treat this populated-table check as a formality (CI
      does not populate a representative kernel
      conntrack table or prove event stream health). Attach the characterization
      output to rollout sign-off before flipping prod. Use
      the same pre/post table snapshot for the
      parity readout and treat any exec-vs-netlink teardown gap from port-less
      TCP/UDP entries as a signal to investigate, not noise, even though
      confirmed TCP/UDP entries are expected to carry ports. The accepted
      divergence is explicit: if the only observed gap is an incomplete
      port-less TCP/UDP entry that exec would have deleted and netlink skipped,
      record that acceptance in the rollout issue; any confirmed-flow gap blocks
      the flip. Record the `l3FlushConntrackPoolSize` used for this run and an
      explicit "default 16 accepted" or tuned value decision; if the 16-socket
      default shows
      pool-contention symptoms (`FlushErr`, breaker pressure, or schedule wait
      timeouts under burst), raise the pool size and restart the AC before
      proceeding.
- [ ] Rollout (sandbox): set `l3FlushConntrackBackend = "netlink"` in the sandbox
      AC config and restart the AC (instance refresh). Run a **7-day soak** with
      L3 flush in real (non-dry-run) mode against a representative-size
      conntrack table (or an artificially populated one) under
      representative/simulated burst load **driving real concurrency** and at
      least one large sibling fan-out tuple (many established flows sharing
      `{src,dst,dport,proto}` behind the same NAT) — not sandbox-idle, not just
      the single-threaded bench, and not broad one-flow-per-key bursts. Run this
      with `L3FlushDryRun=false`; dry-run may still suppress the
      v6 hard-fail while not deleting flows, so it is not valid evidence that the
      iptables v6 gap is closed. Watch: L3 flush breaker stays closed (no
      `BreakerOpen`), `FlushErr` flat, zero scheduler drops, `RevocationIPv6HardFail`
      drops to 0 for any iptables v6 revoke (gap closed), `L3FlushConntrackDeleted`
      climbs (path is actually tearing flows down), `L3FlushConntrackIndexedFlushes`
      climbs (event index is serving steady-state Flush),
      `L3FlushConntrackIndexEvents` climbs when the table churns,
      `L3FlushConntrackIndexOrigins` is recorded at target table cardinality
      with RSS/Go heap/GC pause, `L3FlushConntrackIndexAuthoritativeDumps`
      accounts for intentional immediate-revocation dumps, and
      `L3FlushConntrackIndexFallbackDumps`,
      `L3FlushConntrackIndexEventErrors`,
      `L3FlushConntrackIndexPendingOverflows`,
      `L3FlushConntrackIndexResyncFailures`, and post-startup
      `L3FlushConntrackSlowDumps` stay flat except for recorded authoritative
      dumps; `L3FlushConntrackDumpLatency` stays within the accepted percentile
      envelope, `L3FlushConntrackDumpLatencyDropped` remains zero,
      `L3FlushConntrackDumpLatencyPublisherDropped` remains zero,
      `L3FlushConntrackDumpLatencyNegativeDurations` remains zero, and
      `PublisherFailures` remains zero. Treat those histogram percentiles as
      accepted only when `FlushErr` and breaker pressure are also flat and the
      separate startup/resync backfill wall-time evidence remains within budget.
      Before accepting the prod flip, record the post-soak retention decision
      for `L3FlushConntrackDumpLatency` and its three guardrail signals
      (`...Dropped`, `...PublisherDropped`, `...NegativeDurations`): either keep
      them with named alarm/dashboard ownership, or file a labelled follow-up
      issue to retire the soak-only signals once the netlink backend is proven.
      If an event-index error is injected, expect
      `L3FlushConntrackIndexEventErrors` to move and verify
      `L3FlushConntrackIndexResyncAttempts` and
      `L3FlushConntrackIndexResyncSuccesses` advance, event-loss fallback dumps
      stop after the rebuilt generation is installed, and no teardown miss
      appears in the pre/post table snapshot. Under sustained injected event
      loss, verify error/resync-failure counters move together, resync attempts
      respect the minimum interval, and the AC does not create a continuous
      full-table dump loop; also watch socket-pool wait and `SlowDumps` because
      resync backfills share the pool with fallback dumps while the index is
      unhealthy. Treat `EventErrors` as cumulative subscription-health evidence,
      not a distinct incident count; use resync attempts/failures for recovery
      episode cadence. Recovery is trigger-driven: a degraded but quiescent AC
      may not advance `ResyncAttempts` until the next non-authoritative fallback
      Flush.
      During shutdown or restart, verify an in-flight resync is
      cancelled by Close (the active socket deadline is snapped forward) before
      the shared pool is torn down, rather than waiting for the full backfill
      budget. Treat any pending-overflow count above zero as startup replay
      pressure evidence that must be resolved or explicitly accepted before prod
      flip.
      Note: a transient netlink `ENOBUFS`/`EINTR`
      dump is retried once and is self-healing (the socket is reopened); a
      *persistent* dump failure trips `FlushErr` → breaker (intended fail-loud).
      The scheduler's `flushCallTimeout` is one whole-Flush budget shared by
      socket-pool wait and all indexed deletes (or by fallback dump + deletes if
      the index is unhealthy); if `FlushErr` ticks during the large fan-out tuple,
      correlate it with indexed/fallback counters, matched-flow count/fan-out
      size, breaker state, and pool size before accepting the flip. Any
      fallback dump rise is an event-index health warning; fallback dumps plus
      `FlushErr` block the flip until the event stream/pool/budget path is
      resolved. Authoritative dumps are expected only for immediate revocation,
      but authoritative dumps plus `FlushErr` still require pool/budget review
      before accepting the flip. For the
      large fan-out tuple,
      compare `L3FlushConntrackDeleted` deltas against the matched-flow count so a
      mid-list persistent delete error cannot silently strand the tail. Partial
      success still returns an error and spends breaker budget, so do not accept
      the flip until `L3FlushErrorThreshold`/window tuning is explicitly checked
      against large-fan-out partial-delete events. Explicitly confirm the default
      `flushCallTimeout` (5s) covers worst-case fan-out × per-delete latency at
      the target table size, or tune/escalate before accepting the flip. Include
      one NAT-ed temp-access flow in the soak and confirm netlink tears it down
      equivalently to exec (both use the ORIGINAL tuple / kernel-observed
      FlowKey). Capture before/after in the issue.
- [ ] Rollout (prod): after a clean sandbox soak, flip prod
      `l3FlushConntrackBackend = "netlink"` + AC restart. Monitor the same metrics
      across a full deploy cycle.
- [ ] Post-rollout: after 7+ days clean prod runtime on netlink, plan removal of
      the exec backend + its `isConntrackNoEntries` stderr-scrape and the
      conntrack-tools AMI dependency (the exec-removal acceptance item) — separate
      PR; update/close this entry then.
- [ ] Rollback: set `l3FlushConntrackBackend = "exec"` (or unset) + restart the AC
      → reverts to the v1 fork+exec datapath. Default is exec, so reverting this
      PR entirely is also safe. No data/schema migration (the flusher is stateless
      across the swap).
- [ ] Follow-up (not blocking, tracked — no action required for this rollout): a
      dump-latency histogram for finer fallback/backfill readability is **#2909**.
      Compact resident origin storage to reduce million-entry GC scan pressure is
      **#2973**.
      The surgical, sibling-preserving revoke teardown stays the **#2784**
      follow-up.

> Cross-link: the [#2797 ledger entry](2026-06-25-pr-2797-revocation-ipv6-hardfail-iptables.md)
> calls this the gap-closing change for iptables v6 — its
> `RevocationIPv6HardFail = 0` post-rollout check is satisfied for iptables ACs
> only once they run the netlink backend.
