package ac

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
)

// This file proves the P4e-slice-5 surgical-revocation WIRING: that
// flushEntryNow drives the surgical conntrack path correctly off the injected
// seams (surgicalConnFlush + enumerateConnSrcPorts). It is the AC-level
// complement to nhp/utils/ebpf/conntrack_enumerate_linux_test.go, which proves
// the map-op primitive (enumerate + delete target exactly one flow). Neither
// proves the live XDP datapath drops the next real packet — that is the #2779
// kernel-rig gate.
//
// The injected-seam design exists precisely so this runs cross-platform: the
// pinned conn_track map is absent in unit tests, so the production
// EnumerateConnTrackSrcPorts would return ErrConnTrackMapNotPinned and the
// FlushConn-per-source-port drive could never be observed off a kernel rig.

// fakeSurgicalFlusher records the ConnFlowKeys passed to FlushConn so a test can
// assert which exact 5-tuples were surgically torn down. errFor, if set, lets a
// test make a specific 5-tuple's flush fail (modeling a real non-ENOENT Delete
// error) while the others succeed — the call is still recorded so the test can
// prove every sibling was attempted.
type fakeSurgicalFlusher struct {
	mu      sync.Mutex
	flushed []ConnFlowKey
	errFor  func(ConnFlowKey) error
}

func (f *fakeSurgicalFlusher) flushConn(_ context.Context, conn ConnFlowKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushed = append(f.flushed, conn)
	if f.errFor != nil {
		return f.errFor(conn)
	}
	return nil
}

func (f *fakeSurgicalFlusher) snapshot() []ConnFlowKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ConnFlowKey, len(f.flushed))
	copy(out, f.flushed)
	return out
}

// newSurgicalTestAC builds a UdpAC with a started scheduler, a real metrics
// publisher (so the revocation counters are observable), and the surgical seams
// bound to the supplied fakes — mirroring the EBPFXDP-on-Linux Start() binding
// without a kernel. enumerate maps an allow-rule tuple to the source ports the
// fake conntrack map "holds".
func newSurgicalTestAC(t *testing.T, enumerate func(srcIP, dstIP string, proto uint8, dstPort uint16) ([]uint16, error)) (*UdpAC, *fakeSurgicalFlusher) {
	t.Helper()
	sched := NewScheduler(newRecordingFlusher(), WithTickInterval(2*time.Millisecond), WithWheelSize(256))
	sched.Start()
	t.Cleanup(func() { shutdownOrFail(t, sched) })

	fsf := &fakeSurgicalFlusher{}
	a := &UdpAC{
		tokenStore:            common.NewTokenStore[*AccessEntry](),
		revIndex:              newRevocationIndex(),
		expirySched:           sched,
		registration:          &ACRegistration{metrics: metrics.NewPublisherForTest(t)},
		surgicalConnFlush:     fsf.flushConn,
		enumerateConnSrcPorts: enumerate,
	}
	return a, fsf
}

func counter(t *testing.T, a *UdpAC, name string) float64 {
	t.Helper()
	counters, _ := a.registration.metrics.CountersForTest(t)
	return counters[name]
}

// TestFlushEntryNow_Surgical_KillsEachSibling proves the core resolution of
// #2784: for a v4 TCP entry, flushEntryNow enumerates the live conntrack source
// ports on the allow-rule tuple and FlushConn's EXACTLY each one — both the
// "target" admission and a same-allow-tuple sibling (different source port) are
// torn down INDIVIDUALLY by their full 5-tuple. The coarse path alone (the old
// behavior) could only reschedule the shared allow-rule, killing the tuple
// wholesale; here each flow is addressed surgically, which is what lets a real
// revoke kill one admission and leave another behind one NAT alive.
func TestFlushEntryNow_Surgical_KillsEachSibling(t *testing.T) {
	const (
		srcIP      = "198.51.100.7"
		dstIP      = "203.0.113.10"
		dport      = 443
		targetPort = uint16(43210)
		siblingPrt = uint16(43211)
	)
	// Fake conntrack: two siblings on the target allow-rule tuple.
	enumerate := func(s, d string, proto uint8, dp uint16) ([]uint16, error) {
		if s == srcIP && d == dstIP && proto == 6 && dp == dport {
			return []uint16{targetPort, siblingPrt}, nil
		}
		return nil, nil
	}
	a, fsf := newSurgicalTestAC(t, enumerate)

	key, err := MakeFlowKey(srcIP, dstIP, dport, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey: %v", err)
	}
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry)

	flushed := fsf.snapshot()
	if len(flushed) != 2 {
		t.Fatalf("FlushConn called %d times, want 2 (one per enumerated source port): %+v", len(flushed), flushed)
	}
	got := map[uint16]ConnFlowKey{}
	for _, c := range flushed {
		got[c.SrcPort] = c
	}
	for _, want := range []uint16{targetPort, siblingPrt} {
		c, ok := got[want]
		if !ok {
			t.Errorf("no FlushConn for source port %d; the enumerated 5-tuple was not surgically torn down", want)
			continue
		}
		// The 5-tuple handed to FlushConn must carry the allow-rule key verbatim
		// plus the per-flow source port — a wrong tuple would delete the wrong
		// conntrack entry (or none).
		if c.Flow != key {
			t.Errorf("FlushConn for sport %d carried Flow %s, want %s", want, c.Flow, key)
		}
	}
	if got := counter(t, a, MetricRevocationSurgicalFlushed); got != 2 {
		t.Errorf("%s = %v, want 2", MetricRevocationSurgicalFlushed, got)
	}
	// Coarse path still fired (drain-once-feed-both): the entry had drained keys.
	if got := counter(t, a, MetricRevocationFlushScheduled); got != 1 {
		t.Errorf("%s = %v, want 1 (coarse reschedule must run alongside surgical)", MetricRevocationFlushScheduled, got)
	}
	// No v6 hard-fail on a v4 entry.
	if got := counter(t, a, MetricRevocationIPv6HardFail); got != 0 {
		t.Errorf("%s = %v, want 0 on a v4 flow", MetricRevocationIPv6HardFail, got)
	}
}

// TestFlushEntryNow_IPv6_HardFailNoSurgical proves the #2778 contract when only
// the v4 surgical seam is wired (newSurgicalTestAC leaves the v6 seam nil, as on
// a v4-only EBPFXDP build / non-Linux): a v6 FlowKey is NOT routed through the
// v4 enumerator, increments MetricRevocationIPv6HardFail, and is NOT silently
// treated as killed. The coarse path still runs (the only — futile, on v6 —
// thing available), observable via MetricRevocationFlushScheduled. (When the v6
// seam IS wired, surgicalFlushFlowKeyV6 instead surgically tears the v6 flow
// down — see revocation_surgical_v6_test.go.)
func TestFlushEntryNow_IPv6_HardFailNoSurgical(t *testing.T) {
	enumerateCalled := false
	enumerate := func(s, d string, proto uint8, dp uint16) ([]uint16, error) {
		enumerateCalled = true // the v4 enumerator must NOT be called for a v6 key
		return nil, nil
	}
	a, fsf := newSurgicalTestAC(t, enumerate)

	key, err := MakeFlowKey("2001:db8::1", "2001:db8::2", 443, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey(v6): %v", err)
	}
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry)

	if enumerateCalled {
		t.Error("v4 enumerator was called for an IPv6 flow — with the v6 seam unwired, a v6 key must hard-fail without touching the v4 conntrack path")
	}
	if n := len(fsf.snapshot()); n != 0 {
		t.Errorf("FlushConn called %d times for an IPv6 flow, want 0", n)
	}
	if got := counter(t, a, MetricRevocationIPv6HardFail); got != 1 {
		t.Errorf("%s = %v, want 1 (a v6 flow under EBPFXDP is an immediate-revocation gap, #2778)", MetricRevocationIPv6HardFail, got)
	}
	if got := counter(t, a, MetricRevocationSurgicalFlushed); got != 0 {
		t.Errorf("%s = %v, want 0 (no surgical teardown is possible for v6)", MetricRevocationSurgicalFlushed, got)
	}
	if got := counter(t, a, MetricRevocationSurgicalFlushedV6); got != 0 {
		t.Errorf("%s = %v, want 0 (v6 seam unwired → hard-fail, nothing flushed)", MetricRevocationSurgicalFlushedV6, got)
	}
	if got := counter(t, a, MetricRevocationFlushScheduled); got != 1 {
		t.Errorf("%s = %v, want 1 (coarse path still runs)", MetricRevocationFlushScheduled, got)
	}
}

// TestFlushEntryNow_ICMPandAny_NoSurgicalNoHardFail proves that v4 ICMP / "any"
// flows — which the XDP program creates NO conntrack entry for (the
// established-flow short-circuit is port-keyed) — skip the surgical path
// WITHOUT a v6-style hard-fail: the coarse allow-rule teardown suffices, so
// enumeration is never attempted and no hard-fail metric is ticked.
func TestFlushEntryNow_ICMPandAny_NoSurgicalNoHardFail(t *testing.T) {
	for _, proto := range []FlowProto{FlowProtoICMP, FlowProtoAny} {
		t.Run(proto.String(), func(t *testing.T) {
			enumerateCalled := false
			enumerate := func(s, d string, p uint8, dp uint16) ([]uint16, error) {
				enumerateCalled = true
				return nil, nil
			}
			a, fsf := newSurgicalTestAC(t, enumerate)

			key, err := MakeFlowKey("198.51.100.7", "203.0.113.10", 0, proto)
			if err != nil {
				t.Fatalf("MakeFlowKey(%s): %v", proto, err)
			}
			entry := &AccessEntry{OpenTime: 10}
			entry.recordScheduledKey(key)

			a.flushEntryNow(entry)

			if enumerateCalled {
				t.Errorf("%s: enumerator called, but ICMP/any have no conntrack entry to enumerate", proto)
			}
			if n := len(fsf.snapshot()); n != 0 {
				t.Errorf("%s: FlushConn called %d times, want 0", proto, n)
			}
			if got := counter(t, a, MetricRevocationIPv6HardFail); got != 0 {
				t.Errorf("%s: %s = %v, want 0 (ICMP/any v4 is not a hard-fail)", proto, MetricRevocationIPv6HardFail, got)
			}
			// Coarse path still runs to tear the allow-rule down.
			if got := counter(t, a, MetricRevocationFlushScheduled); got != 1 {
				t.Errorf("%s: %s = %v, want 1", proto, MetricRevocationFlushScheduled, got)
			}
		})
	}
}

// TestFlushEntryNow_CoarseOnlyWhenSurgicalUnwired proves the fallback for a v4
// key: when the surgical seam is NOT bound (non-Linux / L3 disabled in the real
// Start(); surgicalConnFlush == nil and config nil here), flushEntryNow runs the
// coarse allow-rule reschedule alone and ticks no surgical accounting. The v6
// hard-fail stays 0 because the key is v4 AND config is nil — NOT merely because
// the surgical seam is unwired: a v6 key under FilterMode_IPTABLES with the
// surgical seam unwired DOES hard-fail (#2794), which
// revocation_iptables_v6_test.go covers.
func TestFlushEntryNow_CoarseOnlyWhenSurgicalUnwired(t *testing.T) {
	a, _ := newTestACWithScheduler(t) // leaves surgicalConnFlush + registration nil
	a.registration = &ACRegistration{metrics: metrics.NewPublisherForTest(t)}

	key, err := MakeFlowKey("198.51.100.7", "203.0.113.10", 443, FlowProtoTCP)
	if err != nil {
		t.Fatalf("MakeFlowKey: %v", err)
	}
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)
	a.expirySched.Schedule(key, time.Now().Add(10*time.Second))

	a.flushEntryNow(entry)

	if got := counter(t, a, MetricRevocationSurgicalFlushed); got != 0 {
		t.Errorf("%s = %v, want 0 when surgical seam is unwired", MetricRevocationSurgicalFlushed, got)
	}
	if got := counter(t, a, MetricRevocationIPv6HardFail); got != 0 {
		t.Errorf("%s = %v, want 0 for a v4 key with nil config (no v6 gap, no iptables-mode attribution)", MetricRevocationIPv6HardFail, got)
	}
	if got := counter(t, a, MetricRevocationFlushScheduled); got != 1 {
		t.Errorf("%s = %v, want 1 (coarse path runs)", MetricRevocationFlushScheduled, got)
	}
}
