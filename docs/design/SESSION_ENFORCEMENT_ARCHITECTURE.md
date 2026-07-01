# Session Enforcement Architecture

## Status: Implemented (2026-05)

**Author:** posey
**Related PRs:**
- `layervai/qurl-service#514` — resource authz endpoint + OpenTime ↔ session_duration coupling
- `layervai/traefik-plugins#146` — qurl-router consumes the new endpoint on `*.qurl.site`
- `layervai/nhp#1929` — sandbox tfvars + SSM-doc cleanup
- `layervai/traefik-plugins#147` — `hqdatamiddleware` plugin source deletion
- `layervai/nhp#1930` — dead `nhp_session_ttl` cookie removal

## TL;DR

For `*.qurl.site` and custom-domain traffic, **session enforcement is server-side**: the Traefik `qurl-router` plugin calls `GET /internal/v1/resource/:id/authorize?client_ip=X` (or the domain-keyed sibling) against `qurl-service` on every request, with a positive-only cache bounded by `min(15s, remaining_session_seconds)`.

We deliberately rejected a stateless-cookie approach (NHP signs an authz cookie at resolve time, qurl-router verifies it locally) even though it offers lower latency and lower load. The decision was driven by four feature requirements that don't compose with stateless cookies: **revocation**, **`one_time_use`**, **`max_sessions`**, and **audit/billing bookkeeping**.

This document captures the trade-off analysis so a future maintainer doesn't relitigate it cold — and so the conditions for revisiting are explicit.

## Background

A 1-second `session_duration` ([qurl-service#498](https://github.com/layervai/qurl-service/pull/498)) is the marketed floor for short-lived qURLs. In May 2026 we found this floor was structurally not enforced for `*.qurl.site` traffic. The investigation surfaced a longer-standing architectural drift that this document records.

### The legacy cookie-driven attempt

The deleted `hqdatamiddleware` plugin implemented a token-bootstrap reverse proxy:

1. User arrives at the protected resource with `?access_token=<JWT>` in the URL.
2. Plugin decrypts the JWT (AES-GCM), extracts `ServiceInfo` (target host/port/scheme), generates a `session_id` UUID, stores `session_id → ServiceInfo` in an in-process cache (`Apps`).
3. Sets a `session_id` cookie + strips the token from the URL.
4. Subsequent requests look up `session_id` in `Apps` → proxy to cached backend.
5. Cache miss = "Authorization Expired" denial page.

The architecture predates the current `qurl-service`-driven resolve flow. The current flow consumes the `at_*` token at the `qurl.link` step and redirects to `qurl.site` with only NHP cookies (no `?access_token` query). The bootstrap branch of `hqdatamiddleware` was therefore structurally unreachable — `nhp_session_ttl` was set, but no router middleware ever read it.

A three-PR fix chain ([qurl-service#498](https://github.com/layervai/qurl-service/pull/498) + [traefik-plugins#143](https://github.com/layervai/traefik-plugins/pull/143)) tried to fence the cookie path. Each PR was internally correct but bottomed out at unreachable code.

### The current architecture (post-supersession PRs)

```
                qurl-service authoritative
                       │
                       │ session row (DDB):
                       │   pk=resource_id, sk=session_id
                       │   src_ip, ttl, created_at
                       │
   ┌───────────────────┴───────────────────┐
   │                                       │
   │ resolve creates session               │ authz reads session
   │                                       │
   ▼                                       ▼
NHP server                            qurl-router (Traefik)
qurl plugin                           on AC instances
   │                                       ▲
   │ POST /internal/v1/resolve             │
   │ → returns OpenTime, SessionDuration   │ GET /internal/v1/resource/:id/authorize
   │                                       │ → 200 {remaining_seconds: N}
   │ NHP knock (OpenTime → iptables)       │ → 403 if no matching session
   │                                       │
   ▼                                       │
Browser ──redirect──> r_xxx.qurl.site ─────┘
```

Two enforcement layers, both coupled to per-qURL `session_duration`:

| Layer | Mechanism | Coupled how |
|---|---|---|
| L3 (kernel) | iptables/ipset pinhole, timeout = `OpenTime` on the NHP knock packet | `qurl-service` returns `OpenTime = min(defaultOpenTime, sessionDuration)` so the pinhole closes when the session expires. NHP AC has a `openTimeSec == CloseWindowOpenTimeSec` special-case (`endpoints/ac/msghandler.go:152-156`) that also collapses the temp-port window to the same 1s window. |
| L7 (HTTP) | `qurl-router` calls `qurl-service` resource authz on every cache-miss request | `qurl-service` filters sessions by TTL in Go (DDB TTL reaper lags up to 48h); positive-cache TTL = `min(15s, remaining_seconds)` |

End-to-end: after `session_duration` seconds, both L3 (no more bytes flowing) and L7 (HTTP denied) close together.

### Operator note: OpenTime=1 self-destruct sessions

The post-qurl-service#498 floor lets `session_duration` go as low as 1 second (Discord-bot self-destruct presets; the bot rounds 0.5s up to 1s). At `OpenTime=1`, the AC's `RemainingFirewallSeconds()` returns 0 essentially immediately after issue (truncate-toward-zero in the sub-second dead zone), so the AC's `/refresh` endpoint refuses extension at any point past `FirstKnockTime + 1µs`. The session simply expires naturally at `FirstKnockTime + 1s`.

This is intentional — a 1s self-destruct shouldn't be refreshable — but when triaging a "why isn't this refreshing?" report, the answer for `session_duration ≤ 2s` is the strict-firewall dead zone, not a regression. See `endpoints/ac/tokenstore_test.go::TestRemainingFirewallSeconds_OpenTimeOneBoundary` for the fence.

### The three-clock model (post-L3-flush)

After the L3 flush-on-expiry work in `endpoints/ac/expiry_scheduler.go` (nhp#2164), session enforcement runs three coupled clocks. Useful as a reading frame when triaging "why didn't this session terminate?" reports:

```
                         L7 session (qurl-service /authorize)
            ┌────────────────────────────────────────────┐
            │   ←─── reactive to /resolve ───→            │
  /resolve  │                              session expires
     t=0 ───┼──── image fetch ─────┐                     ─────►
            │                      │                     ▲
            │                  first-paint               │
            │                      │                     │
            │                      ◄─── self-destruct ───►
            │                      │                     │
            │                      └─ client blank fires ┘
            │
            └─── reactive to /resolve ─── L3 ipset closes (kernel TTL)
                                          └─ scheduler.Flush fires →
                                             conntrack/BPF deletes →
                                             existing TCP terminates
```

| Clock | Anchor | End condition | Source of truth |
|---|---|---|---|
| **Fileviewer blank** (client JS) | first-paint | first-paint + `viewer_ttl` | URL `expire_after` param (from connector) |
| **L7 session** (`/authorize` denial) | first /authorize | first-authorize + `session_duration` | qurl-service token storage (sessions table) |
| **L3 firewall close** (ipset/BPF entry expiry + active flush) | /resolve | `/resolve + OpenTime` | NHP-AOP from qurl-service; flush scheduled in AC |

**What L3 flush adds vs the prior architecture:** before the scheduler, the AC relied on the kernel's natural ipset/BPF TTL to remove allow-rules. Established TCP connections survived past that point (both filter modes have an ESTABLISHED bypass — see `expiry_scheduler.go` godoc). The scheduler closes that gap by actively flushing kernel conntrack / BPF map state at the deadline. **Active flows terminate within ~1 tick (10 ms default) of session end; quiet flows terminate at the next packet attempt (see `QUIET_STREAM_RESIDUAL.md` for the 25 s backend-keepalive recipe).**

For the rollout phase, the L3 flush runs *alongside* the L7 `/authorize` enforcement (defense-in-depth). After 4+4 weeks of side-by-side validation, the L7 layer can be removed and L3 flush becomes the sole enforcement boundary. The scheduler's fail-closed admission semantic (UdpAC refuses new NHP-AOPs when the scheduler's circuit breaker is open) is sized for that end-state — see `SCHEDULER_SCALING.md` for the SLO contract.

## eBPF/XDP map types and capacity (AC-side L3 enforcement)

This section is the source of truth for the BPF map declarations in
`nhp/ebpf/xdp/nhp_ebpf_xdp.c`, per the action item in
[nhp#2163](https://github.com/layervai/nhp/issues/2163) (BPF-map item).

> **Scope note.** These maps are the *eBPF/XDP* `FilterMode` of the AC. Under
> `FilterMode=0` (iptables/ipset — the production default at time of writing)
> they are never loaded, so the contents of this section are **inert in prod**
> until the eBPF FilterMode flip. The L7 `/authorize` layer (above) is
> orthogonal and unaffected.

### Map-type invariant: authoritative allow-rules MUST be `HASH`, never `LRU_HASH`

The XDP program (`xdp_white_prog`) decides admission by looking up
**allow-rule maps** — five on the non-ICMP fall-through path, plus
`icmpwhitelist` on the separate ICMP branch (six in total). A packet that
matches no conntrack entry falls through to these maps; an entry's presence
(with `allowed==1` and unexpired `expire_time`) **is** the kernel's
authorization decision. They are therefore *authoritative*, not a cache:

| Map | Key | Role |
|---|---|---|
| `spp` (whitelist) | src+dst+dport+proto | full 4-tuple allow-rule |
| `src_port` | src+dport | source + destination-port allow-rule |
| `sdwhitelist` | src+dst | source + destination allow-rule |
| `port_list` | src+port-range | source + port-range allow-rule |
| `protocol_port` | proto+dport | protocol + destination-port allow-rule |
| `icmpwhitelist` | src+dst | ICMP allow-rule |

All six are `BPF_MAP_TYPE_HASH`.

**Why not `LRU_HASH`:** an LRU map silently evicts the least-recently-used
entry when it reaches `max_entries`. For an authoritative allow-rule map that
means inserting the *N+1*-th admission silently **evicts an already-admitted
session's allow-rule** — its next packet finds no allow-rule and is dropped.
The symptom is "a random session was killed" (#2163), and the admitted set
becomes non-deterministic, so you can no longer reason about what is
authorized. That breaks the security model.

`HASH` instead returns `-E2BIG` from the kernel on an insert into a full map.
The AC's user-space insertion path (`nhp/utils/ebpf/ebpf.go`,
`EbpfRuleAdd` → `Add*Rule`) surfaces that as an explicit error, which the AC
admission path (`endpoints/ac/msghandler.go`) treats as a **fail-CLOSED**
event: it refuses to insert the *new* allow-rule (and emits a loud map-full
metric/log naming the full map, see below) rather than silently revoking an
*existing* one. Refreshing an *existing* allow-rule still succeeds on a full map
(an update needs no new slot), so session re-authorization is unaffected — only
genuinely-new rule insertions past capacity fail.

**What "fail-closed" guarantees here (precisely).** The load-bearing property is
*no silent eviction of an admitted session, and any allow-rule tuple that fails
to insert is fail-closed at the datapath* (an absent rule never admits → next
packet on that tuple `XDP_DROP`s). It is **not** "an admission is rejected as one
atomic unit," because the call sites have two shapes:

- **Single-rule sites** (e.g. `spp`/`sdwhitelist`/`protocol_port`) log the
  `-E2BIG` and **return**, so the whole admission is refused.
- **CIDR / port-range expansion sites** (the `src_port`/`port_list` temp-access
  handlers, and the later `icmpwhitelist` path in
  `endpoints/ac/msghandler.go`) log the per-tuple `-E2BIG` and **continue** the
  per-IP loop — deliberately, so the rest of the range still gets its rules. If
  the map fills mid-range the result is a **partial** allow-rule set: inserted
  tuples pass, un-inserted tuples drop. Still fail-closed (no tuple is silently
  admitted), just not all-or-nothing. Each per-tuple failure is individually
  metered (`MetricEbpfMapFull`) and logged.

Either way no *existing* admitted session is evicted — which is the whole point
of the `LRU_HASH`→`HASH` change.

**`conn_track` and `conn_track_v6` are also `HASH` (#2814).** They are
per-flow established-connection caches that the datapath populates (with
`BPF_ANY`) only *after* an allow-rule match; a conntrack hit short-circuits to
`XDP_PASS`. The old "they are only caches, so LRU eviction is benign" argument
is true only while the shared allow-rule still exists. It fails after a
surgical revoke:

- `endpoints/ac/revocation_index.go` `flushEntryNow` first does a **coarse**
  `Scheduler.RescheduleEarlier` on the shared allow-rule for the `FlowKey`
  ("COARSE first: bar re-open in every mode... additive, never gated by the
  surgical outcome"), with no `tokenStore` ref-count against other live
  admissions sharing that `FlowKey`.
- `surgicalFlushFlowKey` / `surgicalFlushFlowKeyV6` then delete only the revoked
  5-tuples and deliberately leave same-allow-tuple siblings alive (#2784).
- A spared sibling's established flow then survives solely via its conntrack
  entry. If the conntrack map were `LRU_HASH`, memory pressure could evict that
  typically idle/cold sibling entry; the next packet would miss conntrack, find
  the now-removed allow-rule absent, and `XDP_DROP`. That reopens the collateral
  over-flush #2784 fixed.

The decision is therefore **option 1 from
[nhp#2814](https://github.com/layervai/nhp/issues/2814)**: use
`BPF_MAP_TYPE_HASH` for both established-flow caches. At capacity a new/uncached
flow's cache insert returns `-E2BIG`; the XDP datapath has no user-space error
channel, and the `BPF_ANY` update result is intentionally not verdict-bearing.
Correctness still holds: if an allow-rule matches, the packet returns
`XDP_PASS`; it simply remains uncached and pays the full allow-rule scan on each
packet until a cache slot is made available. If no allow-rule matches, it still
`XDP_DROP`s. Dead quiet entries are reclaimed by the userspace conntrack
stats/reaper (`nhp/utils/ebpf/conntrack_stats_linux.go`), wired through the
BpfFlusher lifecycle sampler: once per sampler interval it applies the same
`timestamp + ttl_ns < now` predicate as `check_conn_expiry` and deletes expired
entries from `conn_track` / `conn_track_v6`, even when the flow will never send
the next packet that would trigger datapath GC. Reclamation cadence is therefore
the sampler cadence (60s today), while conntrack GaugeFuncs only read the cached
snapshot the sampler published. Each sample deletes at most 100,000 expired
quiet entries per conntrack family, up to ~200,000 across V4+V6; at today's
cadence that is roughly 100,000 entries/minute per family, so a mass-expiry
event cannot issue unbounded delete syscalls on the metrics publisher and may
drain gradually.
The reaper uses the package's existing kernel-time helper; on
non-suspending EC2 hosts it is equivalent to XDP's `bpf_ktime_get_ns`, and even
under clock-domain skew the worst case is premature cache reaping followed by
allow-rule slow-path repopulation, not fail-open or silent eviction. If sampler
errors occur, `EbpfConntrackSampleErrors` pages on-call because both occupancy
visibility and quiet-entry reclamation may be impaired. If concurrent HASH churn
aborts an iteration, `EbpfConntrackPartialSamples` pages separately because the
AC preserves conservative occupancy but deletes are skipped for that sample. The
real-kernel regression proof is
`TestConnTrackFullHashCacheMissFallsBackToAllowRule`, which shrinks
`conn_track`, fills it, and verifies exactly that full-cache slow-path behavior
without evicting an existing established entry.

This removes the E5 flip blocker in #2814. The remaining capacity concern is
operational sizing: a full conntrack HASH map is a performance cliff for
new/uncached flows, not a fail-open or collateral-kill condition. Sizing stays
coupled to `max_entries`, instance type, and the E5 flip readiness checks. A
near-`max_entries` conntrack walk measurement on the target AC instance type
remains hard E5 flip evidence: #2928 removes the full-walk publisher dependency,
but slow samples still make cached snapshots stale and delay quiet-entry reaping.

### Capacity / `max_entries` sizing and kernel-memory cost

`MAX_ENTRIES` is **1,000,000** (uniform across all maps) at time of writing.
#2163 targets 1M+ concurrent sessions and floats sizing each map at 2× the
8M ipset bump it proposed (i.e. 16M; that 8M premise is itself rejected — see
"ipset `maxelem`" below). **We deliberately do *not* adopt 16M**, and the
type fix above is independent of the eventual ceiling. The kernel-memory math
is why.

BPF `HASH` maps **preallocate** all element + bucket memory at map-creation
(load) time by default (no `BPF_F_NO_PREALLOC`), and that memory is
**unswappable kernel memory**. The model (per `kernel/bpf/hashtab.c`):
`bytes ≈ max_entries × (≈48 B htab_elem + round_up(key,8) + round_up(value,8) + ≈16 B bucket)`;
`LRU_HASH` adds ≈16 B/entry for the LRU list node.

| `MAX_ENTRIES` | Total across all 7 maps | Feasible on prod AC (`c6i.xlarge`, 8 GB)? |
|---|---|---|
| 1,000,000 (current) | **≈ 0.66 GB** | yes |
| 2,000,000 (2× headroom) | **≈ 1.31 GB** | yes, but tight alongside ipset + tokenStore |
| 16,000,000 (#2163's floated 2×-of-8M) | **≈ 10.5 GB** | **no — exceeds total instance RAM** |

(Per-map breakdown is reproducible from the struct sizes in
`nhp_ebpf_xdp.c`; the dominant maps are `conn_track` at ≈120 MB/1M entries and
`spp` at ≈96 MB/1M entries.)

**AC-instance-RAM implication.** Prod ACs are `c6i.xlarge` (8 GB);
sandbox ACs are `t3.medium` (4 GB) — see `terraform/modules/ac/main.tf`.
A 16M sizing (~10.5 GB) is physically impossible on either: the AC would fail
to load the `.o` at boot. Even 2M (~1.31 GB) is a meaningful fraction of an
8 GB box that *also* carries the ipset (a capped security backstop — ≤1M
entries by validation, default 10k; **not** the 8M item 1 originally floated —
see "ipset `maxelem`" below) and the in-memory `tokenStore` (~500 MB at 1M
sessions — a floor, since qURL v2 keyed-identity metadata and the L3-flush
`scheduledKeys` map were added to `AccessEntry` after that estimate; #2163
item 3) and the Go heap. The correct `max_entries` is therefore **coupled to
the AC instance-type decision (#2163 item 3)** — it cannot be chosen in
isolation.

**Decision for this slice:** keep `MAX_ENTRIES = 1,000,000`. The HASH map-type
security fix is correct and shippable at any size, and is inert in prod
(iptables FilterMode) until the eBPF flip. The `max_entries` bump is a
separate, flip-time concern that must be co-decided with the instance-type
review; the recommended target is **2M (not 16M)** unless instance RAM grows,
and any bump must re-run the memory math above against the chosen instance
type. This slice keeps the current value and makes the current ceiling
observable rather than changing the RAM envelope.

#### ipset `maxelem` (#2163 item 1): a capped security backstop, not a scale lever

[#2163](https://github.com/layervai/nhp/issues/2163) item 1 proposed bumping the
ipset `maxelem` to **8M** so the **iptables/ipset** datapath could admit 1M+
concurrent sessions. **We deliberately do not do this.** `ipset_max_elements`
(`terraform/modules/ac/variables.tf`) stays a **security backstop** — default
**10,000**, hard-validated ceiling **1,000,000** — set by #1160 T3-08 (landed in
#1506) to bound a population-flood DoS. Three reasons the 8M bump is the wrong
lever:

1. **It reintroduces the DoS surface #1506 closed.** The cap bounds
   kernel-memory growth from an attacker flooding the knock path; 8M removes that
   bound. The AC creates **6 sets** per instance (3 IPv4 + 3 IPv6), so the
   worst-case is `6 × maxelem`, not one set.
2. **The worst-case kernel-memory cost is infeasible.** ipset hash types grow
   *dynamically* (memory ∝ *actual* entries, capped at `maxelem` — unlike the BPF
   maps above, which preallocate at load), so at typical load the cap costs
   ~nothing. But the worst case 8M would unlock is ~640 MB/set × 6 ≈ **3.8 GB** of
   unswappable kernel memory, on top of the BPF maps and `tokenStore` on the same
   8 GB box. Even the 1M ceiling is ~80 MB/set worst-case. (That ~80 B/entry is a
   per-set-type blend — the `hash:ip,port,ip` sets (`defaultset`, `defaultset_down`)
   run larger than the `hash:net,port` `tempset` — so treat these as
   order-of-magnitude, not exact.)
3. **The 1M-session scale step rides the eBPF/XDP datapath, not ipset growth.**
   At scale, allow-rules live in the BPF `HASH` maps (sized under
   [nhp#2813](https://github.com/layervai/nhp/issues/2813); recommended 2M, *not*
   16M), reached only after the FilterMode flip. The ipset path is the pre-flip
   datapath, so its `maxelem` is sized to the **legitimate-traffic ceiling**
   (80 pps × 120 s ≈ 9.6k, rounded to 10k), not the 1M-session target.

If the ipset datapath ever had to carry production scale *before* the flip, that
is a paired **instance-type + security sign-off** decision (the same gate #2813
puts on the BPF bump) — never a unilateral `maxelem` bump. The `max_entries` and
`maxelem` levers are co-decided.

#### IPv6 maps: `MAX_ENTRIES_V6` (separate, right-sized ceiling)

The IPv6 allow-rule + conntrack + fragment-state maps (added across the E2 IPv6
slice — `spp_v6`, `src_port_v6`, `icmp_wl_v6`, `sdwhitelist_v6`,
`port_list_v6` as `HASH`, `conn_track_v6` as `HASH`, and `frag_state_v6` as
`HASH`) are sized by a
**separate** `MAX_ENTRIES_V6`, deliberately **not** reused from `MAX_ENTRIES`.
The production knock NLB is **IPv4-only**, so v6 enforcement scale is far smaller
than v4 today; sizing the v6 maps at the v4 1M ceiling would preallocate ~0.5 GB
of unswappable kernel memory for a near-empty workload. `MAX_ENTRIES_V6` is
**131072 (128K, a power of two)** — a comfortable near-term v6 ceiling.

Kernel-memory cost, using the same preallocation model as above (the
`htab_elem + round_up(key,8) + round_up(value,8) + bucket` formula, `LRU_HASH`
+≈16 B/entry). The v6 allow-rule keys (asserted packed sizes in
`nhp_ebpf_xdp.c`) all reuse the IP-agnostic 16 B `*_value` types
(`round_up(16,8)=16`); `conn_track_v6` reuses the 40 B `conn_value`;
`frag_state_v6` uses a 37 B packed key and 16 B value. (`MB` below is decimal,
10⁶ B; ≈102 MiB binary.)

| Map | Type | Key (packed → `round_up/8`) | B/entry | At 131072 |
|---|---|---|---|---|
| `spp_v6` | HASH | 35 → 40 | 120 | ≈ 15.7 MB |
| `src_port_v6` | HASH | 18 → 24 | 104 | ≈ 13.6 MB |
| `icmp_wl_v6` | HASH | 32 → 32 | 112 | ≈ 14.7 MB |
| `sdwhitelist_v6` | HASH | 32 → 32 | 112 | ≈ 14.7 MB |
| `port_list_v6` | HASH | 20 → 24 | 104 | ≈ 13.6 MB |
| **5 HASH allow-rule maps** | | | **552** | **≈ 72.3 MB** |
| `conn_track_v6` | HASH | 38 → 40 | 144 | ≈ 18.9 MB |
| `frag_state_v6` | HASH | 37 → 40 | 120 | ≈ 15.7 MB |
| **Total (7 v6 maps)** | | | | **≈ 107 MB** |

≈107 MB is trivial on an 8 GB `c6i.xlarge` (or even the 4 GB `t3.medium`
sandbox) AC. There is deliberately **no `protocol_port_v6` map**: the
`protocol_port` key (`{dst_port, protocol}`) carries no IP address, so a
proto+dst-port allow-rule is IP-family-agnostic — the existing v4
`protocol_port` map is reused for v6 (one entry admits the proto+port for both
families), saving a map and a duplicate write path. Like the v4 `MAX_ENTRIES`
bump, any `MAX_ENTRIES_V6` change is flip-time work that must re-run this math
against the chosen instance type, co-decided under
[nhp#2813](https://github.com/layervai/nhp/issues/2813).

> **C↔Go struct-size contract — enforced in CI.** The v4 and v6 key/tuple sizes
> are pinned with `_Static_assert`s in `nhp_ebpf_xdp.c`, which documents the
> packing rules and the shared size contract.
> `.github/workflows/ebpf-datapath-test.yml` compiles it via `make test-ebpf`
> whenever the eBPF source changes, so a wrong size (the `__packed`-no-op
> regression class behind #2818) fails CI rather than only a local `make ebpf`
> regen. The same job runs `scripts/check-ebpf-committed-object-drift.sh`, which
> recompiles the object and diffs load-relevant bytes against the committed
> `endpoints/ac/main/etc/nhp_ebpf_xdp.o`, so the native-AC load path cannot
> silently lag the source. (Wiring this enforcement was tracked by
> [nhp#2823](https://github.com/layervai/nhp/issues/2823).)

> **IPv6 extension-header policy.** `xdp_white_prog_v6` walks a bounded IPv6
> extension-header chain before admission: Hop-by-Hop Options, Routing,
> Destination Options, Mobility, and AH advance with per-header `data_end`
> checks, up to the fixed verifier-friendly cap in `nhp_ebpf_xdp.c`. If the
> resolved upper layer is `TCP`/`UDP`/`ICMPv6`, the packet enters the normal
> allow-rule cascade with the resolved protocol and L4 offset. Routing-header
> security policy (for example RH0 / `segments-left`) is deliberately delegated
> to the kernel stack after `XDP_PASS`; XDP only classifies through the header to
> preserve the admission decision.
>
> Fragment headers are TCP/UDP stateful: a first fragment must resolve the real
> L4 ports and pass the normal allow-rule cascade before it can create
> `frag_state_v6`; later fragments pass only on a matching, unexpired fragment
> state entry. First fragments on an already-established conntrack 5-tuple still
> seed fresh per-datagram fragment state before passing, so every fragment
> identification is authorized independently. TCP/UDP atomic fragments
> (`offset=0,M=0`) behave like complete packets and do not consume
> fragment-state capacity; ICMPv6 packets carrying a Fragment header still stay
> on the stricter TCP/UDP-only fragment policy below. State insertion is
> verdict-bearing for fragmented flows: a full `conn_track_v6` or
> `frag_state_v6` map fails the first fragment closed instead of allowing a flow
> whose later-fragment authority or established-flow cache could not be recorded.
> Non-fragmented packets keep the legacy slow-path fallback when conntrack is
> full, but first fragments take the conservative drop. If fragment-state
> insertion fails after the first fragment refreshes `conn_track_v6`, the denied
> fragmented datagram still drops with DENY telemetry; the retained conntrack
> entry may pass a later non-fragmented packet for the same
> allow-rule-authorized 5-tuple. Fragment state expires at the earlier of the
> associated admission deadline and the IPv6 reassembly window (60s), and the
> userspace sampler/reaper proactively deletes expired quiet entries. Fragmented
> ICMPv6 and malformed fragments remain fail-closed. Later-fragment ACCEPT
> telemetry is intentionally suppressed because those packets carry no L4 ports;
> the first admitted fragment on a new allow-rule match emits ACCEPT,
> conntrack-hit first fragments stay silent like established-flow packets, and
> later-fragment drops still emit DENY. A later fragment that arrives before its
> first fragment is therefore dropped before kernel reassembly can buffer it; TCP
> can recover through retransmission, while UDP treats that reordered datagram as
> loss. Flip owners should confirm no in-scope UDP-over-fragmented-IPv6 path
> depends on out-of-order fragment buffering.
>
> Later-fragment state keys on `{src, dst, fragment ID, next header}` because
> later fragments do not contain TCP/UDP ports. A non-conforming later fragment
> whose Fragment-header Next Header does not match the seeded first fragment
> misses state and drops fail-closed rather than aliasing another datagram. The
> accepted residual risk is the normal IPv6-fragmentation surface: a
> source-spoofing actor that can also guess or observe a 32-bit fragment ID for
> an in-flight admitted datagram may get spoofed later fragments to kernel
> reassembly, where the kernel remains responsible for RFC reassembly and
> overlap handling. XDP still fails closed on missing, expired, duplicate,
> malformed, or reserved-bit-set Fragment headers; the reserved-bit check is
> deliberately stricter than RFC 8200's instruction to ignore those bits on
> receipt. An allowed source that emits many distinct first fragments can
> saturate `frag_state_v6` until TTL/reaper drain, but saturation remains
> fail-closed and does not evict unrelated fragment state.
>
> The parser still fails closed for anything else it cannot safely classify:
> ESP, No Next Header, unknown protocols, truncated headers, malformed
> fragments, and chains longer than the cap all drop and emit a v6 DENY event
> with ports set to zero.
>
> Minimum-kernel verifier proof for the current E5 target floor was recorded
> while closing [nhp#2869](https://github.com/layervai/nhp/issues/2869) in
> [nhp#2941](https://github.com/layervai/nhp/pull/2941). Before the flip, re-run
> the proof if the target AC AMI, active running kernel, instance architecture,
> eBPF source, or pinned eBPF toolchain changes; if verifier acceptance
> regresses, keep v6 XDP gated. The flip-time revalidation/hold obligation is
> tracked in [nhp#2945](https://github.com/layervai/nhp/issues/2945), including
> validation that the loaded XDP object pins `frag_state_v6` with the conntrack
> maps before the new AC sampler runs and that the `EbpfFragStateV6*`
> gauges/counter are present before relying on EBPFXDP for IPv6 fragmented-flow
> admission.

### Fail-closed observability (`MetricEbpfMapFull`)

When an allow-rule map insert returns `-E2BIG`, the AC increments the
`EbpfMapFull` metric (`endpoints/ac/registration.go`) and logs a loud
fail-closed security event (`endpoints/ac/msghandler.go`,
`(*UdpAC).ebpfRuleAddFailClosed`). A non-zero rate means the AC is rejecting
*new* admissions because an allow-rule map is at capacity — i.e. the eBPF
capacity ceiling has been reached and admissions are being denied (fail-closed,
not silently evicting). The CloudWatch alarm in
`terraform/modules/ac/monitoring.tf` watches the AC publisher base dimensions
`{Component=AC, Environment, Region}` and points operators at
`docs/runbooks/ebpf-map-capacity.md`. This is inert in prod under iptables
FilterMode (the map is never loaded, so the metric never fires).

### Conntrack and fragment-state saturation observability

Conntrack cache and IPv6 fragment-state pressure are intentionally separate from
`EbpfMapFull`:

| Metric | Meaning |
|---|---|
| `EbpfConntrackV4Entries` / `EbpfConntrackV6Entries` | Current established-flow cache entries after quiet-entry reaping in this sample |
| `EbpfConntrackV4MaxEntries` / `EbpfConntrackV6MaxEntries` | Loaded map ceiling reported by the pinned map metadata |
| `EbpfConntrackV4UsagePercent` / `EbpfConntrackV6UsagePercent` | Post-reap occupancy vs the map's `max_entries` |
| `EbpfConntrackV4OldestAgeSeconds` / `EbpfConntrackV6OldestAgeSeconds` | Oldest surviving entry idle age observed in the sample; during an expiry backlog above the delete budget, this can under-report while expired survivors wait for a later pass |
| `EbpfConntrackV4ExpiredReaped` / `EbpfConntrackV6ExpiredReaped` | Per-period quiet expired entries deleted by the sampler/reaper |
| `EbpfFragStateV6Entries` / `EbpfFragStateV6MaxEntries` / `EbpfFragStateV6UsagePercent` | Post-reap occupancy for IPv6 later-fragment admission state, separate from established-flow `conn_track_v6` |
| `EbpfFragStateV6ExpiredReaped` | Per-period expired IPv6 fragment-state entries deleted by the sampler/reaper |
| `EbpfConntrackSampleSeconds` | Wall-clock duration of the most recent lifecycle sampler/reap attempt; use `Maximum` during flip validation to catch full-map walk latency |
| `EbpfConntrackSampleErrors` | Per-period failures to sample/reap the pinned conntrack maps |
| `EbpfConntrackPartialSamples` | Per-period incomplete HASH walks caused by concurrent churn; usage gauges may undercount for those samples. The alarm pages only on sustained partials, not isolated churny walks |

Terraform alarms page separately on high v4/v6 conntrack usage, high
`frag_state_v6` usage, and sampler errors or partial samples. A conntrack usage
alarm means new/uncached flows may lose the fast-path cache and fall back to the
allow-rule cascade; it does **not** mean admissions are being rejected. A
fragment-state usage alarm means new or established IPv6 fragmented first
packets are nearing the fail-closed `frag_state_v6` ceiling; because
established-flow first fragments must still record per-datagram state for later
fragments, saturation can temporarily degrade already-authorized fragmented
flows until entries expire or are reaped. Authorized fragment churn can also
raise `EbpfConntrackV6UsagePercent`, because the first fragment seeds or
refreshes conntrack before fragment-state insertion decides pass/drop.
`EbpfMapFull` is the
admission-fail-closed signal.

## Alternative considered: stateless signed cookie

**Shape:** NHP server mints a signed cookie `{resource_id, client_ip, session_id, expires_at}` with HMAC at resolve time. `qurl-router` verifies signature + expiry + client_ip locally on every request. No qurl-service call on the data path.

This is roughly the architecture `hqdatamiddleware` reached for, modernized as a signed cookie instead of a URL-bearing JWT.

### Where cookies win

1. **Latency**: cold-path saves ~10-40ms per request (no qurl-service round trip, no 2 DDB ops).
2. **Throughput**: no API call rate amplification. At 1s `session_duration` and 100 concurrent users on a busy page, the server-side authz path generates ~5,000 qurl-service calls/sec; cookies would generate zero data-path calls.
3. **Graceful degradation**: qurl-service can be down and `*.qurl.site` keeps serving (within cookie lifetime). Server-side authz fails closed after the 15s positive-cache window expires.
4. **Plugin simplicity**: qurl-router doesn't need an HTTP client for authz — pure verify + proxy.

### Where cookies lose (and why we rejected them)

#### 1. Revocation is broken

Current: `DELETE /v1/qurls/:id` or session-kill from compliance / incident-response *immediately* affects future requests. The next authz call hits qurl-service, finds no matching session, denies.

Cookies: the cookie remains valid until its baked-in `expires_at`. Mitigations all defeat the win:

- Server-side denylist → back to per-request API call (no longer "stateless")
- Very short cookie lifetime + refresh mechanism → more complexity, refresh interval *is* the revocation window
- Periodic re-check from qurl-router → just API calls at a lower rate (this is the hybrid option below)

#### 2. `one_time_use` becomes leaky

The current resolve handler atomically consumes the `at_*` token on first knock (`SET status='consumed' WHERE status='active'` — DDB conditional update). Subsequent visits to `qurl.link` with the same token fail.

But once a cookie is minted on that first resolve, the user can revisit the protected resource indefinitely within the cookie's lifetime. The cookie is held by the user; nothing on the qurl-router side knows the token was supposed to be one-shot. Defeats the marketed one-time-use guarantee.

#### 3. `max_sessions` becomes leaky

The DDB session row count is the source of truth for "this qURL has been activated by ≤ N distinct client_ips." A stolen or shared cookie can be replayed from anywhere within the cookie's lifetime — distributing the cookie circumvents the cap. Server-side authz checks the live session table; cookies trust the bearer.

#### 4. Audit & billing bookkeeping

`qurl-service` writes session records used for:
- Billing usage metrics (per-customer session counts)
- Audit log (who accessed what when, from where)
- Dashboards (active-sessions, expiring-soon)

Decoupling cookies from server-side session writes either drops this data or requires parallel bookkeeping (cookie-mint → write session, cookie-verify → write access event). At that point you're paying the DB writes anyway — the cookie just shifts them to a different point in the flow.

#### 5. Cross-resource scoping is touchy

Cookies scoped to `.qurl.site` at the parent-domain level can be sent to *any* subdomain. Per-resource cookies (name = `qurl_authz_r_xxx`) or `resource_id` in the signed payload (with reject-on-mismatch) both work but add complexity. Each qURL a user touches lands a new cookie; browser per-domain cookie count caps (~50) become a concern for power users.

The current design has none of this — there's no resource-scoped state in the browser.

#### 6. HMAC secret blast radius

`qurl-router` running in Traefik on each AC instance would need the same HMAC secret NHP uses to sign cookies. We already have `NHP_INTERNAL_AUTH_SECRET` for nhp-server ↔ qurl-service signing. Adding the AC Traefik plugin as a third consumer:

- Expands the principal set that can read the secret (AC instance role + secret rotation operators)
- A compromised AC instance can now forge authz cookies for any user (currently it can only deny — failure mode is loss of availability, not loss of confidentiality)

The current design needs no shared secret at the plugin layer: qurl-router has a service token for calling the internal API, but that token only lets it *ask* whether a client is authorized, not *assert* that they are.

#### 7. Cookie-theft amplification

A stolen authz cookie under the cookie design is a stolen session, period — the attacker has the credential. Under the server-side design, the attacker also needs to either (a) be on the same source IP (sessions are scoped by `src_ip`) or (b) be inside an iptables pinhole opened for the victim's IP. There's still a stolen-NHP-token problem (`nhp_token` / `nhp_refresh_token` are bearer credentials), but it's bounded by NHP's existing scoping.

## The case where cookies are clearly better: 1-second sessions

For `session_duration ≈ 1s`, the cookie design is both correct and faster:

- Cookie Max-Age = 1 → browser drops the cookie at 1s → next request has no cookie → denied. Zero qurl-service load.
- Server-side authz path: API call + 2 DDB ops per refresh (auth cache TTL clamped to 1s). At 100 concurrent users actively refreshing, ~5k calls/sec — a real load.

**This is the trigger for revisiting.** Today, 1-second sessions are a corner case (demos, security-sensitive one-time views). If the product roadmap moves them into the modal configuration (e.g., default for some pricing tier, or a UX-driven push-button "ephemeral access" feature), the server-side architecture stops being the right trade-off.

## Hybrid option (the right shape if perf becomes the constraint)

If 1-second sessions hit DDB scaling before the feature-compose issues bite:

```
Resolve mints cookie + writes session row
                │
                ▼
Browser → r_xxx.qurl.site
                │
                ▼
qurl-router:
  1. Verify cookie HMAC + expiry + client_ip (fast path)
  2. If cookie valid AND last-authz check < 60s ago: proxy
  3. Else: call qurl-service authz (revocation + audit refresh)
     → on 403: drop cached entry, deny
     → on 200: refresh cached "last-authz" timestamp
```

Trade: 1-2 orders of magnitude fewer API calls in steady state, at the cost of a ≤60s revocation-effective-time window. Whether 60s is acceptable depends on what revocation is for. Incident response usually tolerates it; compliance kills might not.

This is **not implemented today**. Don't build it preemptively — the current design's perf envelope is fine for typical workloads.

## Decision

**Server-side authz is correct for the current feature set.** Specifically:

- `qurl-router` calls `qurl-service` `/internal/v1/resource/:id/authorize` on the `*.qurl.site` branch
- `qurl-router` calls `qurl-service` `/internal/v1/domain/:domain/authorize` on the custom-domain branch
- Positive-only cache, bounded by `min(15s, remaining_seconds)` (the new `*.qurl.site` path) or `15s` (the older domain path)
- Fail-closed on any error
- L3 pinhole (`OpenTime`) coupled to per-qURL `session_duration` in qurl-service's resolve response

## When to revisit

Reopen this trade-off if **any** of the following becomes true:

1. **1-second `session_duration` becomes the modal configuration** (not a corner case). Watch for: tier-default short sessions, "ephemeral access" feature rollout, or repeated customer requests for sub-15s sessions.
2. **qurl-service authz throughput hits a hard wall.** Symptoms: sustained 5xx on `/internal/v1/resource/:id/authorize`, DDB throttled-read alarms on `qurl-resources` or `qurl-sessions`, ECS auto-scaling saturated.
3. **A new feature requires sub-15s revocation latency.** The current architecture's effective revocation window is bounded by the positive-auth cache (15s ceiling). If compliance / incident response needs sub-second revocation, server-side authz can deliver it (drop the cache TTL), but at amplified API call cost.
4. **`max_sessions` and `one_time_use` get reworked or removed.** Two of the four blocker features. If they're deprecated, the cookie option becomes meaningfully more viable.

If revisiting: the hybrid option is the most likely right answer, not pure cookies.

## Monitoring (post-rollout)

To detect when we're approaching the revisit thresholds:

| Metric | Source | Watch for |
|---|---|---|
| `/internal/v1/resource/:id/authorize` p99 latency | qurl-service ECS service | rising past ~30ms p99 |
| `/internal/v1/resource/:id/authorize` error rate | qurl-service ECS service | non-zero 5xx |
| `qurl-resources` + `qurl-sessions` throttled-read count | CloudWatch DDB metrics | any non-zero sustained value |
| qurl-router authz API call rate | (not currently emitted — add a metric if revisiting) | rate ÷ active users |
| Effective revocation latency | manual probe: revoke a qURL, observe time-to-deny | > 15s sustained |

## References

- `endpoints/server/staticplugins/qurl/main.go::AuthWithHttp` — the resolve handler that mints sessions
- `endpoints/ac/msghandler.go:152-156` — the `openTimeSec == CloseWindowOpenTimeSec` special-case on the AC (constant in `endpoints/ac/constants.go`)
- `qurl-service/internal/service/resolve_service.go::AuthorizeResourceAccess` — the authz service method
- `qurl-service/internal/service/resolve_service.go::buildResolveOutput` — OpenTime ↔ SessionDuration coupling
- `traefik-plugins/plugins-local/src/github.com/traefik/qurl-router/qurl_router.go::authorizeResourceAccess` — the consumer
- The deleted `hqdatamiddleware` plugin source (recover from git history at `layervai/traefik-plugins` pre-PR #147 if needed for archeology)
