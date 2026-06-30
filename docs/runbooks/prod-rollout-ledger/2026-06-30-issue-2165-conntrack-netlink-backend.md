# 2026-06-30 · issue #2165 · AC ConntrackFlusher direct-netlink backend (opt-in)

- **Owner:** prod rollout coordinator
- **Source:** [#2165](https://github.com/layervai/nhp/issues/2165) · capacity audit [#2163](https://github.com/layervai/nhp/issues/2163) · v6 gap [#2794](https://github.com/layervai/nhp/issues/2794)/[#2797](https://github.com/layervai/nhp/pull/2797) · exec-backend PR [#2164](https://github.com/layervai/nhp/issues/2164)

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
that ratio because each socket holder owns the O(table) dump and every matching
delete for the whole `Flush`. The soak measures the channel-backed free-list pool
routing model: acquired sockets are absent until release, so contention signals
should be interpreted after availability-aware routing, not round-robin
head-of-line blocking. Three soak-readability metrics are published only on the
netlink backend:
`L3FlushConntrackDeleted` (entries torn down), `L3FlushConntrackSlowDumps` (Flush
dumps over ~1ms — the table-size-knee early warning, #2908), and the existing
breaker/`FlushErr` series. Because each netlink `Dump` materializes the whole
family table before filtering, also watch AC process RSS/Go heap/GC pause during
the populated-table characterization; the O(table) knee can show up as allocation
pressure before it is obvious in dump latency.

- [ ] Pre-rollout: on a **sandbox** iptables-mode AC, confirm the netlink datapath
      is available — `nf_conntrack_netlink` loadable + AC has `CAP_NET_ADMIN`
      (it already manages iptables/ipset/`conntrack -D`, so this should hold; the
      flusher fails Start loud if `conntrack.Open` fails). Then run
      `NHP_CONNTRACK_NETLINK_BENCH_GATE=1 go test -bench=BenchmarkConntrackFlusher_Netlink -benchtime=2s ./endpoints/ac/`
      on that AC and confirm **≤200µs/op** (the #2165 acceptance gate). The env
      var intentionally turns the benchmark's warning into a hard failure for
      this acceptance run; ordinary ad hoc/CI `-bench` invocations may only log a
      populated-table miss. The bench skips where netlink is unavailable, so a
      skip means the AC isn't ready.
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
      cardinality): compare exec vs netlink p50/p95/p99 flush latency at the
      target table size, record table cardinality, `L3FlushConntrackSlowDumps`,
      the temporary alert threshold chosen for that counter, AC process RSS/Go
      heap, and GC pause.
      This is a **hard rollout gate**: do not proceed to the prod flip if
      netlink is worse in that regime without resolving/escalating the #2908
      table-size follow-up, and do not treat this populated-table check as a
      formality (the single-threaded small-table bench cannot surface O(table ×
      concurrent flushes) behavior, and CI does not populate a representative
      kernel conntrack table). Attach the characterization output to rollout
      sign-off before flipping prod. Use the same pre/post table snapshot for the
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
      climbs (path is actually tearing flows down), and `L3FlushConntrackSlowDumps`
      stays below the pre-recorded temporary alert threshold (no table-size-knee);
      AC process RSS/Go heap/GC pause should not rise with slow-dump spikes.
      Note: a transient netlink `ENOBUFS`/`EINTR`
      dump is retried once and is self-healing (the socket is reopened); a
      *persistent* dump failure trips `FlushErr` → breaker (intended fail-loud).
      The scheduler's `flushCallTimeout` is one whole-Flush budget shared by
      socket-pool wait, dump, and all matching deletes; if `FlushErr` ticks after
      a successful slow dump or during the large fan-out tuple, correlate it with
      `L3FlushConntrackSlowDumps`, matched-flow count/fan-out size, breaker state,
      and pool size before accepting the flip. A slow-dump rise without `FlushErr`
      is a table-size warning; slow dumps plus `FlushErr` block the flip until the
      budget/pool-size/#2908 path is resolved. For the large fan-out tuple,
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
- [ ] Follow-up (not blocking, tracked — no action required for this rollout): the
      per-`Flush` conntrack dump is O(table); true million-session 100k/sec headroom
      needs a kernel-side CTA_FILTER mass-delete or an AC-side conntrack-event
      source-port index — **#2908** (the `L3FlushConntrackSlowDumps` metric is its
      early-warning signal). A dump-latency histogram for finer soak readability is
      **#2909**. The surgical, sibling-preserving revoke teardown stays the **#2784**
      follow-up.

> Cross-link: the [#2797 ledger entry](2026-06-25-pr-2797-revocation-ipv6-hardfail-iptables.md)
> calls this the gap-closing change for iptables v6 — its
> `RevocationIPv6HardFail = 0` post-rollout check is satisfied for iptables ACs
> only once they run the netlink backend.
