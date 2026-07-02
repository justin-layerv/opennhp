package ac

import (
	"context"
	"errors"
	"fmt"
	"testing"

	utilebpf "github.com/OpenNHP/opennhp/nhp/utils/ebpf"
)

// This file proves the E2-slice-5 IPv6 surgical-revocation WIRING: that
// flushEntryNow → surgicalFlushFlowKey → surgicalFlushFlowKeyV6 drives the v6
// surgical conntrack path correctly off the injected v6 seams
// (surgicalConnFlushBatchV6 / surgicalConnFlushV6 + enumerateConnSrcPortsV6).
// It is the v6 twin of
// revocation_surgical_test.go's v4 wiring proofs. Neither proves the live XDP
// datapath drops the next real v6 packet — that is the #2779 kernel-rig gate.
//
// The injected-seam design exists precisely so this runs cross-platform: the
// pinned conn_track_v6 map is absent in unit tests, so the production
// EnumerateConnTrackSrcPortsV6 would return ErrConnTrackMapNotPinned and the
// FlushConnsV6 batch drive could never be observed off a kernel rig.

// newSurgicalV6TestAC builds a UdpAC with BOTH the v4 and v6 surgical seams
// bound — mirroring the EBPFXDP-on-Linux Start() binding (which binds both pairs
// together) without a kernel. It delegates to newSurgicalTestAC for the
// scheduler + core fields + v4 seam (wired but inert here, with a no-port v4
// enumerator, so surgicalAvailable is true and the v6 branch is reached) and
// then layers on the v6 seam. enumerateV6 maps a v6 allow-rule tuple to the
// source ports the fake conn_track_v6 map "holds".
func newSurgicalV6TestAC(t *testing.T, enumerateV6 func(srcIP, dstIP string, proto uint8, dstPort uint16) ([]uint16, error)) (*UdpAC, *fakeSurgicalFlusher) {
	t.Helper()
	a, _ := newSurgicalTestAC(t, func(_, _ string, _ uint8, _ uint16) ([]uint16, error) { return nil, nil })
	v6 := &fakeSurgicalFlusher{}
	a.surgicalConnFlushBatchV6 = v6.flushConnBatch
	a.surgicalConnFlushV6 = v6.flushConn
	a.enumerateConnSrcPortsV6 = enumerateV6
	return a, v6
}

// TestFlushEntryNow_V6Surgical_BatchesAndKillsEachSibling is the core proof of the slice:
// for a v6 TCP entry with the v6 seam wired, flushEntryNow enumerates the live
// conn_track_v6 source ports on the allow-rule tuple and hands them to
// FlushConnsV6 in one batch — both the target admission and a same-allow-tuple
// sibling (different source port) are torn down individually by their full
// 5-tuple while reusing the pinned conn_track_v6 / frag_state_v6 handles for the
// revocation. This is the v6 equivalent of #2784's v4 resolution, closing the
// #2778 immediate-revocation gap on the eBPF/XDP path without the O(K * N)
// frag_state_v6 scan from issue #2977.
func TestFlushEntryNow_V6Surgical_BatchesAndKillsEachSibling(t *testing.T) {
	const (
		srcIP      = "2001:db8::7"
		dstIP      = "2001:db8::10"
		dport      = 443
		targetPort = uint16(43210)
		siblingPrt = uint16(43211)
	)
	enumerate := func(s, d string, proto uint8, dp uint16) ([]uint16, error) {
		if s == srcIP && d == dstIP && proto == 6 && dp == dport {
			return []uint16{targetPort, siblingPrt}, nil
		}
		return nil, nil
	}
	a, v6 := newSurgicalV6TestAC(t, enumerate)

	key, err := MakeFlowKey(srcIP, dstIP, dport, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey(v6): %v", err)
	}
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry)

	flushed := v6.snapshot()
	if len(flushed) != 2 {
		t.Fatalf("FlushConnsV6 recorded %d source-port flushes, want 2 (one per enumerated v6 source port): %+v", len(flushed), flushed)
	}
	if got := v6.batchCallCount(); got != 1 {
		t.Fatalf("FlushConnsV6 batch calls = %d, want 1 (all v6 source-port siblings for one allow-rule revoke must share one pinned-map batch)", got)
	}
	got := map[uint16]ConnFlowKey{}
	for _, c := range flushed {
		got[c.SrcPort] = c
	}
	for _, want := range []uint16{targetPort, siblingPrt} {
		c, ok := got[want]
		if !ok {
			t.Errorf("no FlushConnV6 for source port %d; the enumerated v6 5-tuple was not surgically torn down", want)
			continue
		}
		if c.Flow != key {
			t.Errorf("FlushConnV6 for sport %d carried Flow %s, want %s", want, c.Flow, key)
		}
	}
	if got := incrCounter(t, a, MetricRevocationSurgicalFlushedV6); got != 2 {
		t.Errorf("%s = %v, want 2", MetricRevocationSurgicalFlushedV6, got)
	}
	// The shared v4 counter must NOT move for a v6 flush — the split is the whole
	// point of the v6-specific counter (observable by address family for E5).
	if got := incrCounter(t, a, MetricRevocationSurgicalFlushed); got != 0 {
		t.Errorf("%s = %v, want 0 (v6 flushes tick the V6 counter, not the v4 one)", MetricRevocationSurgicalFlushed, got)
	}
	// v6 was surgically handled — NOT a hard-fail.
	if got := incrCounter(t, a, MetricRevocationIPv6HardFail); got != 0 {
		t.Errorf("%s = %v, want 0 (v6 was surgically flushed, not a gap)", MetricRevocationIPv6HardFail, got)
	}
	if got := incrCounter(t, a, MetricRevocationFlushScheduled); got != 1 {
		t.Errorf("%s = %v, want 1 (per-entry tick; surgical-v6 teardown, v6 coarse reschedule skipped)", MetricRevocationFlushScheduled, got)
	}
}

func TestFlushEntryNow_V6Surgical_SingleFlowFallbackStillFlushesSiblings(t *testing.T) {
	const (
		srcIP      = "2001:db8::7"
		dstIP      = "2001:db8::10"
		dport      = 443
		targetPort = uint16(43210)
		siblingPrt = uint16(43211)
	)
	enumerate := func(s, d string, proto uint8, dp uint16) ([]uint16, error) {
		if s == srcIP && d == dstIP && proto == 6 && dp == dport {
			return []uint16{targetPort, siblingPrt}, nil
		}
		return nil, nil
	}
	a, v6 := newSurgicalV6TestAC(t, enumerate)
	a.surgicalConnFlushBatchV6 = nil

	key, err := MakeFlowKey(srcIP, dstIP, dport, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey(v6): %v", err)
	}
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry)

	if got := v6.batchCallCount(); got != 0 {
		t.Fatalf("FlushConnsV6 batch calls = %d, want 0 when only the single-flow fallback seam is wired", got)
	}
	flushed := v6.snapshot()
	if len(flushed) != 2 {
		t.Fatalf("single-flow FlushConnV6 fallback recorded %d source-port flushes, want 2: %+v", len(flushed), flushed)
	}
	got := map[uint16]bool{}
	for _, c := range flushed {
		got[c.SrcPort] = true
	}
	if !got[targetPort] || !got[siblingPrt] {
		t.Fatalf("single-flow fallback flushes = %+v; want both source ports %d and %d", flushed, targetPort, siblingPrt)
	}
	if got := incrCounter(t, a, MetricRevocationSurgicalFlushedV6); got != 2 {
		t.Errorf("%s = %v, want 2", MetricRevocationSurgicalFlushedV6, got)
	}
	if got := incrCounter(t, a, MetricRevocationIPv6HardFail); got != 0 {
		t.Errorf("%s = %v, want 0 (single-flow fallback flushed both siblings)", MetricRevocationIPv6HardFail, got)
	}
}

func TestFlushEntryNow_V6Surgical_BatchResultLengthMismatchHardFailsAllPorts(t *testing.T) {
	const (
		srcIP      = "2001:db8::7"
		dstIP      = "2001:db8::10"
		dport      = 443
		targetPort = uint16(43210)
		siblingPrt = uint16(43211)
	)
	enumerate := func(s, d string, proto uint8, dp uint16) ([]uint16, error) {
		if s == srcIP && d == dstIP && proto == 6 && dp == dport {
			return []uint16{targetPort, siblingPrt}, nil
		}
		return nil, nil
	}
	a, v6 := newSurgicalV6TestAC(t, enumerate)
	a.surgicalConnFlushBatchV6 = func(context.Context, FlowKey, []uint16) []error {
		return []error{nil}
	}

	key, err := MakeFlowKey(srcIP, dstIP, dport, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey(v6): %v", err)
	}
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry)

	if flushed := v6.snapshot(); len(flushed) != 0 {
		t.Fatalf("single-flow fallback should not run after a malformed non-nil batch result; got flushes %+v", flushed)
	}
	if got := incrCounter(t, a, MetricRevocationIPv6HardFail); got != 2 {
		t.Errorf("%s = %v, want 2 (fail closed for every enumerated source port when batch result cardinality is malformed)", MetricRevocationIPv6HardFail, got)
	}
	if got := incrCounter(t, a, MetricRevocationSurgicalFlushedV6); got != 0 {
		t.Errorf("%s = %v, want 0", MetricRevocationSurgicalFlushedV6, got)
	}
}

// TestFlushEntryNow_V6_ICMP_NoSurgicalNoHardFail proves a v6 ICMP/"any" flow
// (no conn_track_v6 entry by design — the short-circuit is port-keyed) skips
// enumeration WITHOUT a hard-fail when the v6 seam is wired: the coarse
// allow-rule teardown suffices. Distinguishes "v6 with no surgical path" (TCP/UDP
// gap) from "v6 with no conntrack entry to begin with" (ICMP/any).
func TestFlushEntryNow_V6_ICMP_NoSurgicalNoHardFail(t *testing.T) {
	enumerateCalled := false
	enumerate := func(_, _ string, _ uint8, _ uint16) ([]uint16, error) {
		enumerateCalled = true
		return nil, nil
	}
	a, v6 := newSurgicalV6TestAC(t, enumerate)

	key, err := MakeFlowKey("2001:db8::7", "2001:db8::10", 0, FlowProtoICMP)
	if err != nil {
		t.Fatalf("MakeFlowKey(v6 icmp): %v", err)
	}
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry)

	if enumerateCalled {
		t.Error("enumerator called for a v6 ICMP flow — ICMP has no conn_track_v6 entry to enumerate")
	}
	if n := len(v6.snapshot()); n != 0 {
		t.Errorf("FlushConnV6 called %d times for a v6 ICMP flow, want 0", n)
	}
	if got := incrCounter(t, a, MetricRevocationIPv6HardFail); got != 0 {
		t.Errorf("%s = %v, want 0 (v6 ICMP/any is not a hard-fail; coarse teardown suffices)", MetricRevocationIPv6HardFail, got)
	}
	if got := incrCounter(t, a, MetricRevocationSurgicalFlushedV6); got != 0 {
		t.Errorf("%s = %v, want 0", MetricRevocationSurgicalFlushedV6, got)
	}
}

// TestFlushEntryNow_V6_NotPinned_SoftFallback proves the inert-feature path: when
// the v6 seam is wired but conn_track_v6 is not pinned (XDP not attached),
// enumeration returns ErrConnTrackMapNotPinned and surgicalFlushFlowKeyV6 treats
// it as a soft fallback — NO hard-fail metric (the coarse reschedule already
// ran), no FlushConnV6 calls.
func TestFlushEntryNow_V6_NotPinned_SoftFallback(t *testing.T) {
	// Wrap the sentinel with %w exactly as the production enumerator does, so the
	// errors.Is(err, ErrConnTrackMapNotPinned) branch in surgicalFlushFlowKeyV6
	// matches.
	enumerate := func(_, _ string, _ uint8, _ uint16) ([]uint16, error) {
		return nil, fmt.Errorf("%w: /sys/fs/bpf/conn_track_v6: no such file", utilebpf.ErrConnTrackMapNotPinned)
	}
	a, v6 := newSurgicalV6TestAC(t, enumerate)

	key, err := MakeFlowKey("2001:db8::7", "2001:db8::10", 443, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey(v6): %v", err)
	}
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry)

	if n := len(v6.snapshot()); n != 0 {
		t.Errorf("FlushConnV6 called %d times when conn_track_v6 not pinned, want 0", n)
	}
	if got := incrCounter(t, a, MetricRevocationIPv6HardFail); got != 0 {
		t.Errorf("%s = %v, want 0 (map-not-pinned is a soft fallback, not a hard-fail)", MetricRevocationIPv6HardFail, got)
	}
	if got := incrCounter(t, a, MetricRevocationSurgicalFlushedV6); got != 0 {
		t.Errorf("%s = %v, want 0", MetricRevocationSurgicalFlushedV6, got)
	}
}

// TestFlushEntryNow_V6_EnumerateError_HardFails proves the v6 asymmetry vs v4: a
// non-not-pinned enumeration error ticks MetricRevocationIPv6HardFail (v6 has no
// working coarse fallback, so an enumeration failure IS an immediate-revocation
// gap), unlike the v4 path which only logs.
func TestFlushEntryNow_V6_EnumerateError_HardFails(t *testing.T) {
	enumerate := func(_, _ string, _ uint8, _ uint16) ([]uint16, error) {
		return nil, errors.New("kernel iterate exploded")
	}
	a, v6 := newSurgicalV6TestAC(t, enumerate)

	key, err := MakeFlowKey("2001:db8::7", "2001:db8::10", 443, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey(v6): %v", err)
	}
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry)

	if n := len(v6.snapshot()); n != 0 {
		t.Errorf("FlushConnV6 called %d times on enumeration error, want 0", n)
	}
	if got := incrCounter(t, a, MetricRevocationIPv6HardFail); got != 1 {
		t.Errorf("%s = %v, want 1 (a v6 enumeration error has no coarse fallback — it IS an immediate-revocation gap, #2778)", MetricRevocationIPv6HardFail, got)
	}
	if got := incrCounter(t, a, MetricRevocationSurgicalFlushedV6); got != 0 {
		t.Errorf("%s = %v, want 0", MetricRevocationSurgicalFlushedV6, got)
	}
}

// TestFlushEntryNow_V6_SeamUnwired_StillHardFails proves the fallback is
// preserved: a v6 TCP key with the v6 seam NOT bound (the v4-only EBPFXDP case,
// or non-Linux) still hard-fails — surgicalFlushFlowKeyV6's nil-seam branch —
// rather than silently treating the v6 flow as killed. TCP is deliberate: it
// DOES have a conn_track_v6 entry, so an unwired seam is a genuine teardown gap.
// Contrast TestFlushEntryNow_V6_ICMP_SeamUnwired_NoHardFail, where the proto
// check short-circuits before the seam-nil branch. Uses the v4-seam-only
// constructor.
func TestFlushEntryNow_V6_SeamUnwired_StillHardFails(t *testing.T) {
	v4Enumerate := func(_, _ string, _ uint8, _ uint16) ([]uint16, error) { return nil, nil }
	a, _ := newSurgicalTestAC(t, v4Enumerate) // binds only the v4 seam; v6 fields nil

	key, err := MakeFlowKey("2001:db8::7", "2001:db8::10", 443, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey(v6): %v", err)
	}
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry)

	if got := incrCounter(t, a, MetricRevocationIPv6HardFail); got != 1 {
		t.Errorf("%s = %v, want 1 (v6 seam unwired → hard-fail fallback preserved)", MetricRevocationIPv6HardFail, got)
	}
	if got := incrCounter(t, a, MetricRevocationSurgicalFlushedV6); got != 0 {
		t.Errorf("%s = %v, want 0", MetricRevocationSurgicalFlushedV6, got)
	}
	if got := incrCounter(t, a, MetricRevocationSurgicalFlushed); got != 0 {
		t.Errorf("%s = %v, want 0", MetricRevocationSurgicalFlushed, got)
	}
}

// TestFlushEntryNow_V6_ICMP_SeamUnwired_NoHardFail is the regression proof for
// the proto-before-seam ordering in surgicalFlushFlowKeyV6: a v6 ICMP key with
// the v6 seam UNWIRED must NO-OP (no hard-fail), because ICMP never has a
// conn_track_v6 entry — a wired seam would no-op on it too, so an unwired seam is
// not an immediate-revocation gap. Before the reorder the nil-seam check ran
// first and over-counted MetricRevocationIPv6HardFail here, inflating the "gap"
// signal for a protocol that never had a conntrack entry to leak. The sibling
// TestFlushEntryNow_V6_SeamUnwired_StillHardFails proves a TCP key on the SAME
// unwired seam still hard-fails — so the no-op here is proto-driven, not a
// regression of the fallback. Uses the v4-seam-only constructor.
func TestFlushEntryNow_V6_ICMP_SeamUnwired_NoHardFail(t *testing.T) {
	v4Enumerate := func(_, _ string, _ uint8, _ uint16) ([]uint16, error) { return nil, nil }
	a, _ := newSurgicalTestAC(t, v4Enumerate) // binds only the v4 seam; v6 fields nil

	key, err := MakeFlowKey("2001:db8::7", "2001:db8::10", 0, FlowProtoICMP)
	if err != nil {
		t.Fatalf("MakeFlowKey(v6 icmp): %v", err)
	}
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry)

	if got := incrCounter(t, a, MetricRevocationIPv6HardFail); got != 0 {
		t.Errorf("%s = %v, want 0 (v6 ICMP has no conn_track_v6 entry; an unwired seam is not a gap — proto check must precede the seam-nil hard-fail)", MetricRevocationIPv6HardFail, got)
	}
	if got := incrCounter(t, a, MetricRevocationSurgicalFlushedV6); got != 0 {
		t.Errorf("%s = %v, want 0 (nothing to surgically flush for v6 ICMP)", MetricRevocationSurgicalFlushedV6, got)
	}
	// FlushScheduled ticks per processed entry; the v6 coarse reschedule is
	// skipped (#2778 part 2), and v6 ICMP has no conn_track_v6 entry to flush.
	if got := incrCounter(t, a, MetricRevocationFlushScheduled); got != 1 {
		t.Errorf("%s = %v, want 1 (per-entry tick even when nothing is torn down for v6 ICMP)", MetricRevocationFlushScheduled, got)
	}
}

// TestFlushEntryNow_V6_PerPortFlushError_HardFails proves the per-FLOW arm of the
// v6 asymmetry (the cr point this slice's fix closed): when enumeration SUCCEEDS
// but a single FlushConnV6 returns a real (non-ENOENT) error, that one 5-tuple
// has no coarse fallback to bar re-open — so it ticks MetricRevocationIPv6HardFail
// per failed flow — while the sibling on the same allow-rule tuple still flushes
// and ticks MetricRevocationSurgicalFlushedV6. Before the fix the per-port error
// branch was log-only, so a real v6 teardown failure leaked silently off the
// hard-fail alarm that the E5 FilterMode flip relies on.
func TestFlushEntryNow_V6_PerPortFlushError_HardFails(t *testing.T) {
	const (
		srcIP    = "2001:db8::7"
		dstIP    = "2001:db8::10"
		dport    = 443
		failPort = uint16(43210)
		okPort   = uint16(43211)
	)
	enumerate := func(s, d string, proto uint8, dp uint16) ([]uint16, error) {
		if s == srcIP && d == dstIP && proto == 6 && dp == dport {
			return []uint16{failPort, okPort}, nil
		}
		return nil, nil
	}
	a, v6 := newSurgicalV6TestAC(t, enumerate)
	// One port's delete genuinely fails (a real non-ENOENT Delete error); the
	// other succeeds. FlushConnV6 is idempotent on ENOENT, so this models the
	// ONLY way a non-nil error reaches the loop.
	v6.errFor = func(conn ConnFlowKey) error {
		if conn.SrcPort == failPort {
			return errors.New("conn_track_v6 Delete failed: EIO")
		}
		return nil
	}

	key, err := MakeFlowKey(srcIP, dstIP, dport, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey(v6): %v", err)
	}
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry)

	// Both 5-tuples were ATTEMPTED — one failed delete must not abort the
	// surviving sibling's flush.
	flushed := v6.snapshot()
	if got := v6.batchCallCount(); got != 1 {
		t.Fatalf("FlushConnsV6 batch calls = %d, want 1 (mixed per-flow results must be accounted through the batch path)", got)
	}
	got := map[uint16]bool{}
	for _, c := range flushed {
		got[c.SrcPort] = true
	}
	if !got[failPort] || !got[okPort] {
		t.Fatalf("FlushConnV6 attempts = %+v; want both ports %d and %d attempted (failed delete must not abort siblings)", flushed, failPort, okPort)
	}

	// The failed flow has no coarse fallback → it IS an immediate-revocation gap.
	if got := incrCounter(t, a, MetricRevocationIPv6HardFail); got != 1 {
		t.Errorf("%s = %v, want 1 (one per-port FlushConnV6 failed; a v6 flow with no coarse fallback is an immediate-revocation gap)", MetricRevocationIPv6HardFail, got)
	}
	// The surviving flow was torn down → the v6 success counter moves exactly once.
	if got := incrCounter(t, a, MetricRevocationSurgicalFlushedV6); got != 1 {
		t.Errorf("%s = %v, want 1 (the sibling whose delete succeeded)", MetricRevocationSurgicalFlushedV6, got)
	}
	// The shared v4 counter must never move for a v6 flush.
	if got := incrCounter(t, a, MetricRevocationSurgicalFlushed); got != 0 {
		t.Errorf("%s = %v, want 0 (v6 flushes tick the V6 counter, not the v4 one)", MetricRevocationSurgicalFlushed, got)
	}
}
