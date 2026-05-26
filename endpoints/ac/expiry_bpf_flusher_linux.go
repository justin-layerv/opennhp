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
	// metricSkipped counts non-IPv4 keys that reached this
	// (IPv4-only) flusher and were silently no-op'd. Read via
	// SkippedCount for observability — see the Flush godoc; this
	// branch should be unreachable in production, so any non-zero
	// reading indicates an upstream regression.
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
		proto := uint8(6) // TCP
		if key.Protocol == FlowProtoUDP {
			proto = 17
		}
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
