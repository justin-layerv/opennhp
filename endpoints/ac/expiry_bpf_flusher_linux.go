//go:build linux

package ac

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/OpenNHP/opennhp/nhp/log"
	utilebpf "github.com/OpenNHP/opennhp/nhp/utils/ebpf"
)

// BpfFlusher tears down kernel BPF allow-rule entries matching a
// FlowKey. Used in FilterMode_EBPFXDP, where XDP's conn_track
// short-circuit otherwise lets established flows survive
// allow-rule expiry.
//
// # Why we don't iterate conn_track here
//
// The XDP program (nhp/ebpf/xdp/nhp_ebpf_xdp.c) sets each
// conn_track entry's `ttl_ns = expire_time - now_at_create`, so a
// conn_track entry inherits the REMAINING lifetime of the
// allow-rule at flow start. When `check_conn_expiry` fires at the
// next packet, the entry is deleted by the XDP program itself and
// the packet drops. We therefore do NOT need to iterate conn_track
// on flush — deleting the allow-rule alone is sufficient for:
//
//   - blocking new flows: allow-rule lookup fails → XDP_DROP
//   - terminating active flows: conn_track ttl_ns has expired at
//     the same wall-clock moment as the allow-rule (because they
//     were anchored to the same expire_time), so the next packet
//     triggers check_conn_expiry → bpf_map_delete_elem → XDP_DROP
//
// **Quiet-flow residual** (acknowledged in
// QUIET_STREAM_RESIDUAL.md): a connection with no traffic at the
// moment of allow-rule deletion will linger in conn_track until
// the next packet attempt — the user has signed up for the
// ~25-second backend-side TCP keepalive recipe as the mitigation.
//
// # Multi-map delete
//
// HandleAccessControl (msghandler.go) writes to *different* maps
// depending on the (proto, port) shape:
//   - TCP/UDP with explicit port → /sys/fs/bpf/spp (whitelistKey)
//   - "any" protocol, no port → /sys/fs/bpf/sdwhitelist
//   - ICMP → /sys/fs/bpf/icmpwhitelist (same key shape as sdwhitelist)
//
// Flush dispatches based on FlowKey.Protocol to the matching map.
// Port-list / src-port / protocol-port maps (mapTypes 4-6) carry
// auxiliary tempset entries that are NOT session-tied — we
// intentionally do not schedule flushes for those (see the
// scoping note in the scheduler godoc), so the flusher doesn't
// touch them either.
//
// # Idempotency
//
// Per-map Delete returns ebpf.ErrKeyNotExist on no-match; the
// nhp/utils/ebpf helpers translate that to nil. Kernel GC may
// race with us — that's fine.
//
// # Per-call open/close cost
//
// Each Flush opens the pinned map, calls Delete, closes. Matches
// the existing AddWhitelistRule pattern. Per-call cost ~100µs;
// at 100k flush/sec across 64 workers, that's ~1.5k ops/sec/worker
// ≈ 150ms/worker of CPU per second — well within the per-tick
// budget. A long-lived BpfFlusher holding the three map handles
// open across Flush calls would lift this ceiling; bundle that
// optimization with the ConntrackFlusher netlink swap tracked in
// #2165 (both lift the same throughput knee). A long-term
// optimization is to hold the map handles open for the flusher
// lifetime; deferred to a follow-up (the same one that swaps
// ConntrackFlusher to netlink batching).
type BpfFlusher struct {
	// metricSkipped counts wrong-address-family keys that reached the
	// wrong flusher and were silently no-op'd. Read via SkippedCount
	// for observability — see the Flush godoc; every increment is a
	// should-never-happen defensive path, so any non-zero reading
	// indicates an upstream regression.
	//
	// CONFLATION NOTE — two orthogonal axes share this one counter:
	//
	//   1. expiry vs revocation: Flush (scheduled-expiry path — a skip
	//      is a benign leak the kernel TTL closes) vs FlushConn /
	//      FlushConnV6 (revocation path — a skip is a FAILED REVOKE, the
	//      worse signal).
	//   2. flush DIRECTION / address family: FlushConn skips a v6 key
	//      that reached the IPv4-only flusher, while FlushConnV6 skips an
	//      IPv4-mapped key that reached the IPv6-only flusher. Both are
	//      "wrong-family key → wrong flusher" regressions; the cr for E2
	//      s5 flagged that a future E5 watch might want per-direction
	//      visibility.
	//
	// The counter alone cannot tell which axis/direction tripped, but
	// each increment is paired with a distinct, direction-specific
	// Warning log (the four call sites below each name their own flusher
	// and key), so an operator can always recover the direction from the
	// logs around a non-zero reading. Splitting the counter itself (per
	// expiry/revoke and per family) is deferred to the P4e follow-up
	// issue (#2778; P4e owns the revoke breaker/accounting that needs the
	// distinct signal, and the metrics publisher that consumes this lives
	// in registration.go, outside this slice's scope). Keeping it folded
	// here is acceptable because the path is should-never-happen
	// defensive in production — the upstream code routes v4 keys to the
	// IPv4 flushers and v6 keys to the IPv6 flusher.
	metricSkipped atomic.Uint64
}

// NewBpfFlusher constructs a BpfFlusher. Returns nil error
// unconditionally on Linux — the per-Flush LoadPinnedMap is the
// real failure point if the XDP program isn't loaded.
func NewBpfFlusher() (*BpfFlusher, error) {
	return &BpfFlusher{}, nil
}

// SkippedCount returns the number of non-IPv4 keys this flusher has
// silently no-op'd. A non-zero reading indicates an upstream
// regression scheduling v6 keys under EBPFXDP — the eBPF maps are
// IPv4-only by design. Exposed for the UdpAC metrics publisher
// rather than the Scheduler's FlushMetrics (this is a flusher-
// implementation concern, not a scheduler concern).
func (f *BpfFlusher) SkippedCount() uint64 {
	return f.metricSkipped.Load()
}

// Flush implements FlowFlusher. Deletes the allow-rule entry for
// the FlowKey from the appropriate BPF map.
//
// CONTRACT: Returns nil on success OR on missing-entry (idempotent
// ENOENT no-op via isEbpfNoEntry in nhp/utils/ebpf — wraps both
// ebpf.ErrKeyNotExist and syscall.ENOENT). msghandler.go's
// schedule-then-write reorder for #2168 relies on this — a
// scheduled flush against a never-written kernel entry (e.g., when
// the EbpfRuleAdd subsequently failed) MUST NOT bump FlushErr or
// trip the breaker.
//
// ctx-honoring: the cilium/ebpf
// LoadPinnedMap/Delete path doesn't take a context, so we honor
// the scheduler-supplied ctx only at entry. Per-call latency is
// sub-ms today, well within defaultFlushCallTimeout; if a future
// kernel issue stalls one of these calls the worker would be
// unbounded — the entry-check at least catches a context that
// canceled BEFORE this Flush started (Shutdown-mid-tick).
// Symmetric to ConntrackFlusher's exec.CommandContext-honoring
// behavior at the SLO contract level.
func (f *BpfFlusher) Flush(ctx context.Context, key FlowKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	srcIP := key.SrcIPString()
	dstIP := key.DstIPString()

	// Only IPv4 is supported by the eBPF maps today (parseIP in
	// nhp/utils/ebpf rejects non-IPv4). FlowKey carries both v4
	// and v6 in [16]byte form; surface the constraint early so the
	// breaker doesn't get pinged with map-load failures on v6.
	//
	// This branch should be unreachable in production — the upstream
	// code paths only schedule IPv4 keys under EBPFXDP. If it ever
	// fires, a regression upstream let a v6 key reach here and the
	// entry is being silently dropped from observability. Warning
	// (not Debug) + a metric increment makes that regression visible
	//
	if !isIPv4Mapped(key.SrcIP) || !isIPv4Mapped(key.DstIP) {
		f.metricSkipped.Add(1)
		log.Warning("[BpfFlusher] non-IPv4 key %s reached IPv4-only eBPF flusher — upstream regression? Schedule leaked (silently no-op'd; tracked in metricSkipped)", key)
		return nil
	}

	switch key.Protocol {
	case FlowProtoTCP, FlowProtoUDP:
		proto, _ := key.Protocol.ianaL4Proto() // ok by case guard
		return utilebpf.DelEbpfRuleForSrcDstPortProto(srcIP, dstIP, proto, key.DstPort)

	case FlowProtoICMP:
		return utilebpf.DelEbpfIcmpRuleForSrcDst(srcIP, dstIP)

	case FlowProtoAny:
		// "Any" maps to the srcDest (no-port-no-proto) shape.
		return utilebpf.DelEbpfRuleForSrcDst(srcIP, dstIP)

	default:
		return fmt.Errorf("BpfFlusher: unsupported protocol %s for %s", key.Protocol, key)
	}
}

// FlushConn surgically tears down a SINGLE established flow by its full
// conntrack 5-tuple (the allow-rule FlowKey plus the per-flow source
// port). This is the P4c immediate-revocation primitive: unlike Flush
// above (which deletes the coarse allow-rule entry shared by every
// admission on the same {src,dst,dport,proto} tuple), FlushConn deletes
// exactly the target admission's conntrack entry and leaves a sibling
// flow on the same tuple — but with a different source port — passing.
//
// It is ALSO what makes revocation immediate for an established flow.
// Flush (allow-rule delete) blocks only NEW flows; an already-established
// flow keeps passing the XDP conntrack short-circuit until the conntrack
// entry's ttl_ns — anchored to the allow-rule's ORIGINAL remaining
// lifetime at flow creation — elapses, i.e. up to the full session
// duration after a revoke. Deleting the conntrack entry here forces the
// next packet back through the allow-rule path; a revoke removes that too,
// so the flow drops immediately. P4e calls both (allow-rule Flush to bar
// re-open + FlushConn per live 5-tuple to kill established flows).
//
// CONTRACT (mirrors Flush): returns nil on success OR on missing-entry
// (idempotent ENOENT no-op). The kernel's own check_conn_expiry GC or a
// concurrent flush may have already removed the entry — that MUST NOT be
// treated as an error by a future revocation breaker.
//
// Only TCP and UDP create conntrack entries in the XDP program (the
// established-flow short-circuit is port-keyed); ICMP and "any" allow
// rules have no conntrack entry, so a non-TCP/UDP protocol here is a
// caller bug, surfaced as an error rather than a silent no-op.
//
// REVOCATION-SEMANTICS CAVEAT — a nil return does NOT prove the flow was
// torn down on the IPv6 branch. The conntrack map is IPv4-only (struct
// ipv4_ct_tuple uses __be32), so a v6 ConnFlowKey has no entry to delete:
// the no-op is the CORRECT outcome, but the nil return is indistinguishable
// from a real delete. For scheduled expiry a missed flush is a leak the
// kernel TTL eventually closes; for a REVOCATION primitive, a v6 qURL
// admission therefore has no immediate-teardown path here at all. The v6
// case is counted on metricSkipped (see SkippedCount), but the caller
// (P4e's revoke wiring) MUST NOT read this nil as "flow killed" — it must
// treat a v6 flow as an explicit hard-fail or coarse allow-rule fallback.
// Tracked for the revoke path in the P4e follow-up issue (#2778); until then this
// is a documented IPv6 immediate-revocation gap (see the gospel's
// "Filter-mode/IPv6 caveat" + DE Risk #6).
//
// ctx-honoring: symmetric to Flush — honored at entry only, since the
// cilium/ebpf LoadPinnedMap/Delete path takes no context. Per-call
// latency is sub-ms (single pinned-map open + Delete).
func (f *BpfFlusher) FlushConn(ctx context.Context, conn ConnFlowKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := conn.Flow

	// conntrack keys are IPv4-only (struct ipv4_ct_tuple uses __be32),
	// matching the allow-rule maps. FlowKey carries v4 and v6 in
	// [16]byte form; surface the constraint the same way Flush does so a
	// leaked v6 key is observable rather than a silent map-load failure.
	if !isIPv4Mapped(key.SrcIP) || !isIPv4Mapped(key.DstIP) {
		f.metricSkipped.Add(1)
		log.Warning("[BpfFlusher] non-IPv4 conn key %s reached IPv4-only eBPF conntrack flusher — upstream regression? (silently no-op'd; tracked in metricSkipped)", conn)
		return nil
	}

	proto, ok := key.Protocol.ianaL4Proto()
	if !ok {
		return fmt.Errorf("BpfFlusher.FlushConn: protocol %s for %s has no conntrack entry (only TCP/UDP do)", key.Protocol, conn)
	}

	return utilebpf.DelEbpfConnTrackEntry(key.SrcIPString(), key.DstIPString(), proto, conn.SrcPort, key.DstPort)
}

// FlushConnV6 is the IPv6 twin of FlushConn (E2 slice 5): it surgically deletes
// a single established v6 flow from the pinned conn_track_v6 map by its full
// 5-tuple. Bound to a.surgicalConnFlushV6 in the same EBPFXDP-on-Linux Start()
// block as FlushConn, it is what makes a v6 qURL revocation immediate instead of
// the documented IPv6 immediate-revocation gap (#2778). The gate is INVERTED vs
// FlushConn: this requires a real (non-IPv4-mapped) v6 key — a v4 key reaching
// here is the upstream-regression case, surfaced the same observable way.
func (f *BpfFlusher) FlushConnV6(ctx context.Context, conn ConnFlowKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := conn.Flow

	// Inverse of FlushConn's gate: the conn_track_v6 map keys on struct
	// ipv6_ct_tuple (in6_addr addrs), so this targets v6 flows only. An
	// IPv4-mapped key reaching here is an upstream regression (the caller routes
	// v4 to FlushConn); surface it the same observable way FlushConn surfaces a
	// leaked v6 key — count it and no-op rather than mis-key the v6 map.
	if isIPv4Mapped(key.SrcIP) || isIPv4Mapped(key.DstIP) {
		f.metricSkipped.Add(1)
		log.Warning("[BpfFlusher] IPv4-mapped conn key %s reached the IPv6-only eBPF conntrack flusher — upstream regression? (silently no-op'd; tracked in metricSkipped)", conn)
		return nil
	}

	proto, ok := key.Protocol.ianaL4Proto()
	if !ok {
		return fmt.Errorf("BpfFlusher.FlushConnV6: protocol %s for %s has no conntrack entry (only TCP/UDP do)", key.Protocol, conn)
	}

	return utilebpf.DelEbpfConnTrackEntryV6(key.SrcIPString(), key.DstIPString(), proto, conn.SrcPort, key.DstPort)
}

// isIPv4Mapped returns true if the [16]byte holds an IPv4-mapped
// IPv6 address (::ffff:a.b.c.d). FlowKey.MakeFlowKey always
// produces this form for IPv4 inputs.
func isIPv4Mapped(b [16]byte) bool {
	for i := 0; i < 10; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return b[10] == 0xff && b[11] == 0xff
}

// ensure interface satisfaction at compile time
var _ FlowFlusher = (*BpfFlusher)(nil)
