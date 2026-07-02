//go:build linux

package ac

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenNHP/opennhp/nhp/log"
	utilebpf "github.com/OpenNHP/opennhp/nhp/utils/ebpf"
)

// BpfFlusher tears down kernel BPF allow-rule entries matching a
// FlowKey. Used in FilterMode_EBPFXDP, where XDP's conn_track
// short-circuit otherwise lets established flows survive
// allow-rule expiry.
//
// # Why Flush doesn't iterate conn_track
//
// The XDP program (nhp/ebpf/xdp/nhp_ebpf_xdp.c) sets each
// conn_track entry's `ttl_ns = expire_time - now_at_create`, so a
// conn_track entry inherits the REMAINING lifetime of the
// allow-rule at flow start. When `check_conn_expiry` fires at the
// next packet, the entry is deleted by the XDP program itself and
// the packet drops. We therefore do NOT synchronously iterate
// conn_track from Flush — deleting the allow-rule alone is sufficient for:
//
//   - blocking new flows: allow-rule lookup fails → XDP_DROP
//   - terminating active flows: conn_track ttl_ns has expired at
//     the same wall-clock moment as the allow-rule (because they
//     were anchored to the same expire_time), so the next packet
//     triggers check_conn_expiry → bpf_map_delete_elem → XDP_DROP
//
// **Quiet-flow residual** (acknowledged in QUIET_STREAM_RESIDUAL.md): a
// connection with no traffic at the moment of allow-rule deletion will not
// trigger datapath GC on its own. StartConntrackSampler owns a lifecycle ticker
// that samples and reaps conn_track / conn_track_v6 once per sample interval, so
// dead quiet entries do not keep HASH maps saturated before the next packet
// attempt; Flush stays latency-bounded and per-key.
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
	// metricSkipped counts non-IPv4-mapped keys that reached this IPv4-only flusher
	// and were silently no-op'd. Read via SkippedCount for observability — see the
	// Flush godoc. What a non-zero reading means depends on the increment site:
	//
	//   - Flush (allow-rule): a v6 key here is a scheduled-EXPIRY skip — a benign
	//     leak the kernel TTL closes. The eBPF datapath is IPv4-only, so a v6 key
	//     is not expected under EBPFXDP in a correct (v4-only) deployment; if one
	//     appears, the no-op here is the right outcome and the flow self-closes at
	//     TTL. This is NOT a failed-revoke signal (see below).
	//   - FlushConn: a v6 conn key here is a wrong-family ROUTING regression — the
	//     revoke path routes v6 conn keys to FlushConnV6, not here.
	//   - FlushConnV6: an IPv4-mapped conn key here is the inverse wrong-family
	//     routing regression — the revoke path routes v4 conn keys to FlushConn.
	//
	// The Flush-path tick is NOT a failed-revoke signal: the revoke path's coarse
	// reschedule is IPv4-only, so a v6 revoke never drives a key into Flush (a real
	// failed v6 revoke is MetricRevocationIPv6HardFail; a normal one on a wired
	// EBPFXDP build is torn down by FlushConnV6). The full expiry-vs-revoke split —
	// incl. the deferred-tick residual (#2901) — lives in the flushEntryNow godoc
	// (revocation_index.go) and the QURL_V2_KEYED_IDENTITY.md Filter-mode/IPv6
	// caveat; this comment is intentionally local to avoid re-deriving it. (#2778)
	//
	// The folded axis that remains is flush DIRECTION / address family (FlushConn-v6
	// vs FlushConnV6-v4): each increment is paired with a distinct,
	// direction-specific Warning log (the call sites below each name their own
	// flusher and key), so an operator can recover the direction from the logs. A
	// dedicated per-direction counter is the lower-priority E5 follow-up the cr for
	// E2 s5 flagged (#2778).
	metricSkipped atomic.Uint64

	conntrackSamplerMu sync.Mutex
	conntrackSampler   *bpfConntrackSampler

	sampleConntrack func() (utilebpf.ConnTrackStats, error)

	statsMu sync.Mutex
	stats   BpfConntrackStats

	// Sampler-private cumulative counters. refreshConntrackStats is the only
	// reader/writer; it publishes their values into stats under statsMu for
	// cross-goroutine gauge reads.
	conntrackSampleErrors    uint64
	conntrackPartialSamples  uint64
	conntrackExpiredReapedV4 uint64
	conntrackExpiredReapedV6 uint64
	fragStateExpiredReapedV6 uint64
}

type bpfConntrackSampler struct {
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

const (
	// Matches endpoints/metrics.flushInterval (60s today) so the lifecycle
	// sampler preserves the previous map-walk cadence while GaugeFuncs remain
	// pure cache readers. The sampler free-runs from the publisher, so snapshots
	// can be up to one interval old; keep this equality intentional so publisher
	// cadence changes force an explicit sampler cost/freshness retune.
	bpfConntrackSampleInterval = 60 * time.Second

	bpfConntrackSampleSlowThreshold = 2 * time.Second
)

// NewBpfFlusher constructs a BpfFlusher. Returns nil error
// unconditionally on Linux — the per-Flush LoadPinnedMap is the
// real failure point if the XDP program isn't loaded.
func NewBpfFlusher() (*BpfFlusher, error) {
	return &BpfFlusher{}, nil
}

// SkippedCount returns the number of non-IPv4 keys this flusher has
// silently no-op'd — the expiry-skip / wrong-family count described on the
// metricSkipped godoc (NOT a failed-revoke signal; that is
// MetricRevocationIPv6HardFail). Exposed for the UdpAC metrics publisher
// rather than the Scheduler's FlushMetrics (a flusher-implementation concern).
func (f *BpfFlusher) SkippedCount() uint64 {
	return f.metricSkipped.Load()
}

// StartConntrackSampler starts the lifecycle-owned conntrack sample/reap loop.
// It is idempotent and its goroutine kicks one immediate refresh before
// entering the ticker so gauges get a fresh snapshot without making gauge
// collection perform the destructive map walk. Gauge reads racing a slow first
// sample return the existing cached snapshot until that async pass publishes.
func (f *BpfFlusher) StartConntrackSampler() {
	f.startConntrackSampler(bpfConntrackSampleInterval)
}

func (f *BpfFlusher) startConntrackSampler(interval time.Duration) {
	if f == nil {
		return
	}
	if interval <= 0 {
		interval = bpfConntrackSampleInterval
	}

	f.conntrackSamplerMu.Lock()
	if f.conntrackSampler != nil {
		f.conntrackSamplerMu.Unlock()
		return
	}
	sampler := &bpfConntrackSampler{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	f.conntrackSampler = sampler
	f.conntrackSamplerMu.Unlock()

	go f.runConntrackSampler(sampler, interval)
}

// StopConntrackSampler stops the lifecycle-owned conntrack sampler and waits
// for any in-flight map walk/delete pass to finish. If ctx expires, the sampler
// remains registered until that pass exits. A timeout does not leave AC-owned
// map handles dangling: SampleAndReapConnTrack opens and closes pinned eBPF map
// handles per pass, and the EBPFXDP path has no conntrackFlusher pool to close.
func (f *BpfFlusher) StopConntrackSampler(ctx context.Context) error {
	if f == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	f.conntrackSamplerMu.Lock()
	sampler := f.conntrackSampler
	f.conntrackSamplerMu.Unlock()
	if sampler == nil {
		return nil
	}

	sampler.stopSampler()
	select {
	case <-sampler.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *BpfFlusher) runConntrackSampler(sampler *bpfConntrackSampler, interval time.Duration) {
	defer func() {
		f.conntrackSamplerMu.Lock()
		if f.conntrackSampler == sampler {
			f.conntrackSampler = nil
		}
		f.conntrackSamplerMu.Unlock()
		close(sampler.done)
	}()

	select {
	case <-sampler.stop:
		return
	default:
	}
	f.refreshConntrackStats()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			f.refreshConntrackStats()
		case <-sampler.stop:
			return
		}
	}
}

func (s *bpfConntrackSampler) stopSampler() {
	s.stopOnce.Do(func() {
		close(s.stop)
	})
}

// ConntrackStats returns the cached cross-platform stats view for CloudWatch
// gauges. The lifecycle sampler owns map walking and quiet-entry reaping;
// GaugeFuncs are pure readers so metrics publication cannot trigger duplicate
// conntrack walks or block on a destructive maintenance burst.
func (f *BpfFlusher) ConntrackStats() BpfConntrackStats {
	if f == nil {
		return BpfConntrackStats{}
	}

	f.statsMu.Lock()
	defer f.statsMu.Unlock()
	return f.stats
}

func (f *BpfFlusher) refreshConntrackStats() {
	sampleStart := time.Now()
	raw, err := f.sampleAndReapConnTrack()
	sampleElapsed := time.Since(sampleStart)
	slowSample := sampleElapsed > bpfConntrackSampleSlowThreshold
	if slowSample {
		if err != nil {
			log.Warning("[BpfFlusher] conntrack sampler/reaper pass took %s (> %s) and failed: %v; full HASH map walks may lag quiet-entry reaping (see nhp#2928)",
				sampleElapsed, bpfConntrackSampleSlowThreshold, err)
		} else {
			log.Warning("[BpfFlusher] conntrack sampler/reaper pass took %s (> %s); full HASH map walks may lag quiet-entry reaping (v4=%d/%d v6=%d/%d, see nhp#2928)",
				sampleElapsed, bpfConntrackSampleSlowThreshold, raw.V4.Entries, raw.V4.MaxEntries, raw.V6.Entries, raw.V6.MaxEntries)
		}
	}
	if err != nil {
		// SampleErrors is per refresh attempt (a joined v4/v6 sample/reap
		// pass); PartialSamples below is per family because HASH iteration can
		// abort in one map while the other family returns a complete sample.
		f.conntrackSampleErrors++
		if !slowSample {
			log.Warning("[BpfFlusher] conntrack stats/reaper sample failed: %v", err)
		}
	}
	if raw.V4.PartialSample {
		f.conntrackPartialSamples++
		log.Warning("[BpfFlusher] conntrack v4 stats/reaper sample was partial; occupancy may undercount during high churn")
	}
	if raw.V6.PartialSample {
		f.conntrackPartialSamples++
		log.Warning("[BpfFlusher] conntrack v6 stats/reaper sample was partial; occupancy may undercount during high churn")
	}
	if raw.FragV6.PartialSample {
		f.conntrackPartialSamples++
		log.Warning("[BpfFlusher] IPv6 fragment-state stats/reaper sample was partial; occupancy may undercount during high churn")
	}
	f.conntrackExpiredReapedV4 += raw.V4.ExpiredDeleted
	f.conntrackExpiredReapedV6 += raw.V6.ExpiredDeleted
	f.fragStateExpiredReapedV6 += raw.FragV6.ExpiredDeleted

	nextStats := bpfConntrackStatsFromRaw(
		raw,
		f.conntrackSampleErrors,
		f.conntrackPartialSamples,
		f.conntrackExpiredReapedV4,
		f.conntrackExpiredReapedV6,
		f.fragStateExpiredReapedV6,
	)
	nextStats.SampleDurationSeconds = sampleElapsed.Seconds()

	// The lifecycle sampler goroutine is the sole writer of f.stats, so the
	// prior snapshot it merges against cannot change while this sample runs.
	f.statsMu.Lock()
	f.stats = bpfConntrackStatsPreserveConservativeOccupancy(nextStats, f.stats, raw, err)
	f.statsMu.Unlock()
}

func (f *BpfFlusher) sampleAndReapConnTrack() (utilebpf.ConnTrackStats, error) {
	if f.sampleConntrack != nil {
		return f.sampleConntrack()
	}
	return utilebpf.SampleAndReapConnTrack()
}

func bpfConntrackStatsFromRaw(raw utilebpf.ConnTrackStats, sampleErrors, partialSamples, expiredReapedV4, expiredReapedV6, fragExpiredReapedV6 uint64) BpfConntrackStats {
	v4Entries := bpfConntrackPostReapEntries(raw.V4)
	v6Entries := bpfConntrackPostReapEntries(raw.V6)
	fragV6Entries := bpfConntrackPostReapEntries(raw.FragV6)
	return BpfConntrackStats{
		V4Entries:           v4Entries,
		V4MaxEntries:        raw.V4.MaxEntries,
		V4UsagePercent:      bpfConntrackUsagePercent(v4Entries, raw.V4.MaxEntries),
		V4OldestAgeSeconds:  bpfConntrackAgeSeconds(raw.V4.OldestAgeNanos),
		V4ExpiredReaped:     expiredReapedV4,
		V6Entries:           v6Entries,
		V6MaxEntries:        raw.V6.MaxEntries,
		V6UsagePercent:      bpfConntrackUsagePercent(v6Entries, raw.V6.MaxEntries),
		V6OldestAgeSeconds:  bpfConntrackAgeSeconds(raw.V6.OldestAgeNanos),
		V6ExpiredReaped:     expiredReapedV6,
		V6FragEntries:       fragV6Entries,
		V6FragMaxEntries:    raw.FragV6.MaxEntries,
		V6FragUsagePercent:  bpfConntrackUsagePercent(fragV6Entries, raw.FragV6.MaxEntries),
		V6FragExpiredReaped: fragExpiredReapedV6,
		SampleErrors:        sampleErrors,
		PartialSamples:      partialSamples,
	}
}

func bpfConntrackStatsPreserveConservativeOccupancy(next, previous BpfConntrackStats, raw utilebpf.ConnTrackStats, sampleErr error) BpfConntrackStats {
	if sampleErr != nil && bpfConntrackMapStatsLacksUsableOccupancy(raw.V4) {
		next.V4Entries = previous.V4Entries
		next.V4MaxEntries = previous.V4MaxEntries
		next.V4UsagePercent = previous.V4UsagePercent
		next.V4OldestAgeSeconds = previous.V4OldestAgeSeconds
	}
	if sampleErr != nil && bpfConntrackMapStatsLacksUsableOccupancy(raw.V6) {
		next.V6Entries = previous.V6Entries
		next.V6MaxEntries = previous.V6MaxEntries
		next.V6UsagePercent = previous.V6UsagePercent
		next.V6OldestAgeSeconds = previous.V6OldestAgeSeconds
	}
	if sampleErr != nil && bpfConntrackMapStatsLacksUsableOccupancy(raw.FragV6) {
		next.V6FragEntries = previous.V6FragEntries
		next.V6FragMaxEntries = previous.V6FragMaxEntries
		next.V6FragUsagePercent = previous.V6FragUsagePercent
	}
	if raw.V4.PartialSample {
		next = bpfConntrackStatsPreservePartialV4(next, previous)
	}
	if raw.V6.PartialSample {
		next = bpfConntrackStatsPreservePartialV6(next, previous)
	}
	if raw.FragV6.PartialSample {
		next = bpfConntrackStatsPreservePartialFragV6(next, previous)
	}
	return next
}

func bpfConntrackStatsPreservePartialV4(next, previous BpfConntrackStats) BpfConntrackStats {
	if next.V4UsagePercent < previous.V4UsagePercent {
		next.V4Entries = previous.V4Entries
		next.V4MaxEntries = previous.V4MaxEntries
		next.V4UsagePercent = previous.V4UsagePercent
	}
	if next.V4OldestAgeSeconds < previous.V4OldestAgeSeconds {
		next.V4OldestAgeSeconds = previous.V4OldestAgeSeconds
	}
	return next
}

func bpfConntrackStatsPreservePartialV6(next, previous BpfConntrackStats) BpfConntrackStats {
	if next.V6UsagePercent < previous.V6UsagePercent {
		next.V6Entries = previous.V6Entries
		next.V6MaxEntries = previous.V6MaxEntries
		next.V6UsagePercent = previous.V6UsagePercent
	}
	if next.V6OldestAgeSeconds < previous.V6OldestAgeSeconds {
		next.V6OldestAgeSeconds = previous.V6OldestAgeSeconds
	}
	return next
}

func bpfConntrackStatsPreservePartialFragV6(next, previous BpfConntrackStats) BpfConntrackStats {
	if next.V6FragUsagePercent < previous.V6FragUsagePercent {
		next.V6FragEntries = previous.V6FragEntries
		next.V6FragMaxEntries = previous.V6FragMaxEntries
		next.V6FragUsagePercent = previous.V6FragUsagePercent
	}
	return next
}

func bpfConntrackMapStatsLacksUsableOccupancy(stats utilebpf.ConnTrackMapStats) bool {
	if stats.SampleError {
		// A wrong or mismatched pinned map can still report MaxEntries; do not
		// treat that alone as usable occupancy after a sample error.
		return stats.Entries == 0 && stats.OldestAgeNanos == 0 && stats.ExpiredDeleted == 0
	}
	return stats.Entries == 0 && stats.MaxEntries == 0 && stats.OldestAgeNanos == 0 && stats.ExpiredDeleted == 0
}

func bpfConntrackPostReapEntries(stats utilebpf.ConnTrackMapStats) uint64 {
	if stats.ExpiredDeleted >= stats.Entries {
		return 0
	}
	// ExpiredDeleted only includes successful map deletes; failed deletes stay
	// in this occupancy count so usage alarms remain conservative.
	return stats.Entries - stats.ExpiredDeleted
}

func bpfConntrackUsagePercent(entries, maxEntries uint64) float64 {
	if maxEntries == 0 {
		return 0
	}
	return 100 * float64(entries) / float64(maxEntries)
}

func bpfConntrackAgeSeconds(ageNanos uint64) float64 {
	return float64(ageNanos) / float64(time.Second)
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
// torn down on the IPv6 branch. The conn_track map is IPv4-only (struct
// ipv4_ct_tuple uses __be32), so a v6 ConnFlowKey has no entry to delete:
// the no-op is the CORRECT outcome, but the nil return is indistinguishable
// from a real delete. This is precisely why the revoke caller
// (surgicalFlushFlowKey) routes v6 conn keys to FlushConnV6 — the conn_track_v6
// twin, #2837 — and NEVER here: a v6 key reaching FlushConn is a wrong-family
// regression (counted on metricSkipped), not the normal v6 revoke path. The
// matching coarse allow-rule reschedule in flushEntryNow is likewise IPv4-only,
// so it never drives a v6 key into this flusher either (#2778 part 2). A v6 flow
// whose surgical teardown is unavailable (iptables mode, or a v4-only EBPFXDP
// build) is surfaced as the dedicated MetricRevocationIPv6HardFail — the
// documented IPv6 immediate-revocation gap (see the gospel's
// "Filter-mode/IPv6 caveat" + DE Risk #6), never a silent nil "killed".
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
	// FlushConnsV6 returns one error slot per input source port.
	return f.FlushConnsV6(ctx, conn.Flow, []uint16{conn.SrcPort})[0]
}

// FlushConnsV6 is the batched IPv6 twin of FlushConnV6 for one allow-rule
// revocation. It opens conn_track_v6 and frag_state_v6 once across all
// enumerated source-port siblings, while returning one error slot per input
// source port so revocation_index.go can preserve per-flow success and hard-fail
// accounting.
func (f *BpfFlusher) FlushConnsV6(ctx context.Context, key FlowKey, srcPorts []uint16) []error {
	errs := make([]error, len(srcPorts))
	if len(srcPorts) == 0 {
		return errs
	}
	if err := ctx.Err(); err != nil {
		return fillErrs(errs, err)
	}

	// Inverse of FlushConn's gate: the conn_track_v6 map keys on struct
	// ipv6_ct_tuple (in6_addr addrs), so this targets v6 flows only. An
	// IPv4-mapped key reaching here is an upstream regression (the caller routes
	// v4 to FlushConn); surface it the same observable way FlushConn surfaces a
	// leaked v6 key — count it and no-op rather than mis-key the v6 map.
	if isIPv4Mapped(key.SrcIP) || isIPv4Mapped(key.DstIP) {
		f.metricSkipped.Add(uint64(len(srcPorts)))
		log.Warning("[BpfFlusher] IPv4-mapped flow key %s reached the IPv6-only eBPF conntrack batch flusher with %d source ports — upstream regression? (silently no-op'd; tracked in metricSkipped)", key, len(srcPorts))
		return errs
	}

	proto, ok := key.Protocol.ianaL4Proto()
	if !ok {
		err := fmt.Errorf("BpfFlusher.FlushConnsV6: protocol %s for %s has no conntrack entry (only TCP/UDP do)", key.Protocol, key)
		return fillErrs(errs, err)
	}

	results := utilebpf.DelEbpfConnTrackEntriesV6(key.SrcIPString(), key.DstIPString(), proto, srcPorts, key.DstPort)
	if len(results) != len(srcPorts) {
		err := fmt.Errorf("BpfFlusher.FlushConnsV6: conn_track_v6 batch returned %d results for %d source ports", len(results), len(srcPorts))
		return fillErrs(errs, err)
	}
	for i, result := range results {
		errs[i] = result.Err
	}
	return errs
}

func fillErrs(errs []error, err error) []error {
	for i := range errs {
		errs[i] = err
	}
	return errs
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
