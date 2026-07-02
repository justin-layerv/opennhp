//go:build linux

package ac

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	utilebpf "github.com/OpenNHP/opennhp/nhp/utils/ebpf"
)

var errTestConntrackSample = errors.New("conntrack sample failed")

// TestIsIPv4Mapped fences the IPv4 detection used to short-circuit
// BpfFlusher on non-IPv4 keys (the eBPF maps are IPv4-only).
func TestIsIPv4Mapped(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"v4-via-string", "192.0.2.1", true},
		{"v4-mapped-explicit", "::ffff:192.0.2.1", true},
		{"v6-loopback", "::1", false},
		{"v6-doc-prefix", "2001:db8::1", false},
		{"v4-broadcast", "192.0.2.255", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, err := MakeFlowKey(c.in, "192.0.2.2", 443, FlowProtoTCP)
			if err != nil {
				t.Fatal(err)
			}
			got := isIPv4Mapped(k.SrcIP)
			if got != c.want {
				t.Errorf("isIPv4Mapped(%s) = %v want %v (bytes=%v)", c.in, got, c.want, k.SrcIP)
			}
		})
	}
}

// TestBpfFlusher_NonIPv4_NoOp fences the early return on non-IPv4
// keys — should NOT propagate to the underlying map (which would
// fail with an unhelpful error and ping the breaker).
//
// Cr round 4 finding 1 added the SkippedCount counter so a
// regression scheduling v6 keys under EBPFXDP becomes visible;
// this test also fences the counter increments alongside the
// no-op behavior.
func TestBpfFlusher_NonIPv4_NoOp(t *testing.T) {
	f := &BpfFlusher{}
	k, err := MakeFlowKey("2001:db8::1", "2001:db8::2", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	// On a v6 key the flusher should return nil without ever
	// attempting LoadPinnedMap (which would fail with EACCES /
	// ENOENT in test environments without the BPF program loaded).
	// context.Background() — never pass nil ctx even when the
	// short-circuit doesn't read it
	if err := f.Flush(context.Background(), k); err != nil {
		t.Errorf("BpfFlusher.Flush on v6 key: got err %v, want nil (should short-circuit)", err)
	}
	if got := f.SkippedCount(); got != 1 {
		t.Errorf("SkippedCount after 1 v6 Flush: got %d want 1", got)
	}
	// Second call increments.
	_ = f.Flush(context.Background(), k)
	if got := f.SkippedCount(); got != 2 {
		t.Errorf("SkippedCount after 2 v6 Flushes: got %d want 2", got)
	}
}

// TestBpfFlusher_FlushConn_NonIPv4_NoOp mirrors the allow-rule
// short-circuit for the P4c surgical conntrack path: a v6 ConnFlowKey must
// return nil and bump the skip counter WITHOUT attempting LoadPinnedMap
// (the conntrack map is IPv4-only, struct ipv4_ct_tuple). These assertions
// run on any Linux host because the guard returns before any kernel call.
func TestBpfFlusher_FlushConn_NonIPv4_NoOp(t *testing.T) {
	f := &BpfFlusher{}
	k, err := MakeFlowKey("2001:db8::1", "2001:db8::2", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	conn := ConnFlowKey{Flow: k, SrcPort: 43210}
	if err := f.FlushConn(context.Background(), conn); err != nil {
		t.Errorf("FlushConn on v6 key: got err %v, want nil (should short-circuit before LoadPinnedMap)", err)
	}
	if got := f.SkippedCount(); got != 1 {
		t.Errorf("SkippedCount after 1 v6 FlushConn: got %d want 1", got)
	}
}

// TestBpfFlusher_FlushConn_NonConnProto_Errors fences the protocol guard:
// ICMP and "any" allow-rules create NO conntrack entry in the XDP program
// (the established-flow short-circuit is port-keyed), so calling FlushConn
// for them is a caller bug and must surface an error rather than silently
// no-op. The guard runs before LoadPinnedMap, so this is host-independent.
func TestBpfFlusher_FlushConn_NonConnProto_Errors(t *testing.T) {
	f := &BpfFlusher{}
	for _, proto := range []FlowProto{FlowProtoICMP, FlowProtoAny} {
		k, err := MakeFlowKey("192.0.2.1", "192.0.2.2", 0, proto)
		if err != nil {
			t.Fatal(err)
		}
		conn := ConnFlowKey{Flow: k, SrcPort: 43210}
		if err := f.FlushConn(context.Background(), conn); err == nil {
			t.Errorf("FlushConn with protocol %s: got nil, want error (no conntrack entry exists for it)", proto)
		}
	}
	// A non-IPv4 key takes the skip branch BEFORE the protocol switch, so
	// the protocol-guard cases above (all IPv4) must NOT have bumped the
	// skip counter.
	if got := f.SkippedCount(); got != 0 {
		t.Errorf("SkippedCount after protocol-guard cases: got %d want 0 (these are IPv4 keys; the protocol error path must not touch the v6 skip counter)", got)
	}
}

// TestBpfFlusher_FlushConn_CanceledCtx fences the ctx-honoring contract:
// a canceled context short-circuits before any kernel call, symmetric to
// Flush. Without this, a Shutdown-mid-revoke could still issue a map op.
func TestBpfFlusher_FlushConn_CanceledCtx(t *testing.T) {
	f := &BpfFlusher{}
	k, err := MakeFlowKey("192.0.2.1", "192.0.2.2", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.FlushConn(ctx, ConnFlowKey{Flow: k, SrcPort: 43210}); err == nil {
		t.Error("FlushConn with canceled ctx: got nil, want ctx error (must short-circuit before LoadPinnedMap)")
	}
}

// TestBpfFlusher_FlushConnV6_V4Mapped_NoOp is the v6 twin of
// TestBpfFlusher_FlushConn_NonIPv4_NoOp, fencing FlushConnV6's INVERTED family
// gate — the load-bearing new logic of E2 s5. FlushConn skips a v6 key; FlushConnV6
// skips an IPv4-MAPPED key (the caller routes v4 to FlushConn). If this gate were
// ever written non-inverted (a copy-paste of FlushConn's `!isIPv4Mapped`), a real
// v6 key would be silently skipped and never torn down — a silent revocation
// failure that every AC-level wiring test would still pass, since they all inject a
// fake surgicalConnFlushV6 and never run this real gate. So a v4-mapped key must
// return nil and bump the skip counter WITHOUT attempting LoadPinnedMap. Runs on
// any Linux host because the guard returns before any kernel call.
func TestBpfFlusher_FlushConnV6_V4Mapped_NoOp(t *testing.T) {
	f := &BpfFlusher{}
	// An all-IPv4 key (rendered IPv4-mapped in [16]byte) reaching the v6-only
	// flusher is the inverted-gate skip case.
	k, err := MakeFlowKey("192.0.2.1", "192.0.2.2", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	conn := ConnFlowKey{Flow: k, SrcPort: 43210}
	if err := f.FlushConnV6(context.Background(), conn); err != nil {
		t.Errorf("FlushConnV6 on v4-mapped key: got err %v, want nil (should short-circuit before LoadPinnedMap)", err)
	}
	if got := f.SkippedCount(); got != 1 {
		t.Errorf("SkippedCount after 1 v4-mapped FlushConnV6: got %d want 1", got)
	}
	// Regression catch for a non-inverted gate: a genuine v6 key must NOT be
	// skipped — it must fall through the gate to the proto switch. Use a FRESH
	// flusher and assert the skip counter stays 0, so a non-inverted gate (which
	// would skip the v6 key) moves it 0→1 and trips this assertion. (Reusing the
	// flusher above would make the post-call count 1 under BOTH the correct gate
	// and the inverted gate — a dud assertion.) We assert only on the skip
	// counter, never the call's error, so this holds with or without a loaded
	// kernel map (the real v6 delete fails here, but that is not what we test).
	v6, err := MakeFlowKey("2001:db8::1", "2001:db8::2", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	fresh := &BpfFlusher{}
	_ = fresh.FlushConnV6(context.Background(), ConnFlowKey{Flow: v6, SrcPort: 43210})
	if got := fresh.SkippedCount(); got != 0 {
		t.Errorf("SkippedCount after a genuine v6 FlushConnV6: got %d want 0 (a v6 key must pass the gate, not be skipped — a non-inverted gate would skip it and read 1)", got)
	}
}

// TestBpfFlusher_FlushConnV6_NonConnProto_Errors is the v6 twin of
// TestBpfFlusher_FlushConn_NonConnProto_Errors: ICMP / "any" create no
// conn_track_v6 entry (the established-flow short-circuit is port-keyed), so
// FlushConnV6 for them is a caller bug and must surface an error, not silently
// no-op. The proto guard runs before LoadPinnedMap, so this is host-independent.
// Uses genuine v6 keys so the inverted family gate lets them through to the proto
// switch (a v4-mapped key would skip out before the proto check).
func TestBpfFlusher_FlushConnV6_NonConnProto_Errors(t *testing.T) {
	f := &BpfFlusher{}
	for _, proto := range []FlowProto{FlowProtoICMP, FlowProtoAny} {
		k, err := MakeFlowKey("2001:db8::1", "2001:db8::2", 0, proto)
		if err != nil {
			t.Fatal(err)
		}
		conn := ConnFlowKey{Flow: k, SrcPort: 43210}
		if err := f.FlushConnV6(context.Background(), conn); err == nil {
			t.Errorf("FlushConnV6 with protocol %s: got nil, want error (no conn_track_v6 entry exists for it)", proto)
		}
	}
	// These are genuine v6 keys taking the proto-error path, NOT the v4-mapped
	// skip branch, so the skip counter must stay 0.
	if got := f.SkippedCount(); got != 0 {
		t.Errorf("SkippedCount after v6 protocol-guard cases: got %d want 0 (these are v6 keys; the proto error path must not touch the skip counter)", got)
	}
}

// TestBpfFlusher_FlushConnV6_CanceledCtx is the v6 twin of
// TestBpfFlusher_FlushConn_CanceledCtx: a canceled context short-circuits before
// any kernel call, symmetric to FlushConn. Without this a Shutdown-mid-revoke
// could still issue a v6 map op.
func TestBpfFlusher_FlushConnV6_CanceledCtx(t *testing.T) {
	f := &BpfFlusher{}
	k, err := MakeFlowKey("2001:db8::1", "2001:db8::2", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.FlushConnV6(ctx, ConnFlowKey{Flow: k, SrcPort: 43210}); err == nil {
		t.Error("FlushConnV6 with canceled ctx: got nil, want ctx error (must short-circuit before LoadPinnedMap)")
	}
}

func TestBpfFlusher_FlushConnsV6_V4Mapped_NoOpPerPort(t *testing.T) {
	f := &BpfFlusher{}
	k, err := MakeFlowKey("192.0.2.1", "192.0.2.2", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	errs := f.FlushConnsV6(context.Background(), k, []uint16{43210, 43211})
	if len(errs) != 2 {
		t.Fatalf("FlushConnsV6 errors len = %d, want 2", len(errs))
	}
	for i, err := range errs {
		if err != nil {
			t.Errorf("FlushConnsV6 v4-mapped err[%d] = %v, want nil no-op", i, err)
		}
	}
	if got := f.SkippedCount(); got != 2 {
		t.Errorf("SkippedCount after 2 v4-mapped FlushConnsV6 ports: got %d want 2", got)
	}
}

func TestBpfFlusher_FlushConnsV6_NonConnProto_ErrorsPerPort(t *testing.T) {
	f := &BpfFlusher{}
	k, err := MakeFlowKey("2001:db8::1", "2001:db8::2", 0, FlowProtoICMP)
	if err != nil {
		t.Fatal(err)
	}
	errs := f.FlushConnsV6(context.Background(), k, []uint16{43210, 43211})
	if len(errs) != 2 {
		t.Fatalf("FlushConnsV6 errors len = %d, want 2", len(errs))
	}
	for i, err := range errs {
		if err == nil {
			t.Errorf("FlushConnsV6 ICMP err[%d] = nil, want protocol error", i)
		}
	}
	if got := f.SkippedCount(); got != 0 {
		t.Errorf("SkippedCount after v6 batch protocol-guard case: got %d want 0", got)
	}
}

func TestBpfFlusher_FlushConnsV6_CanceledCtxErrorsPerPort(t *testing.T) {
	f := &BpfFlusher{}
	k, err := MakeFlowKey("2001:db8::1", "2001:db8::2", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	errs := f.FlushConnsV6(ctx, k, []uint16{43210, 43211})
	if len(errs) != 2 {
		t.Fatalf("FlushConnsV6 errors len = %d, want 2", len(errs))
	}
	for i, err := range errs {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("FlushConnsV6 canceled err[%d] = %v, want context.Canceled", i, err)
		}
	}
}

func TestBpfConntrackSampleIntervalMatchesPublisherFlushInterval(t *testing.T) {
	flushInterval := metrics.FlushIntervalForTest(t)
	if bpfConntrackSampleInterval != flushInterval {
		t.Fatalf("bpfConntrackSampleInterval = %s, want metrics flush interval %s to preserve the previous conntrack map-walk cadence",
			bpfConntrackSampleInterval, flushInterval)
	}
}

func TestBpfConntrackStatsFromRaw_ZeroMaxEntriesUsesZeroUsagePercent(t *testing.T) {
	stats := bpfConntrackStatsFromRaw(utilebpf.ConnTrackStats{}, 0, 0, 0, 0, 0)
	if stats.V4MaxEntries != 0 || stats.V4UsagePercent != 0 {
		t.Fatalf("v4 zero snapshot = max %d usage %v, want max 0 usage 0", stats.V4MaxEntries, stats.V4UsagePercent)
	}
	if stats.V6MaxEntries != 0 || stats.V6UsagePercent != 0 {
		t.Fatalf("v6 zero snapshot = max %d usage %v, want max 0 usage 0", stats.V6MaxEntries, stats.V6UsagePercent)
	}
	if stats.V6FragMaxEntries != 0 || stats.V6FragUsagePercent != 0 {
		t.Fatalf("v6 fragment zero snapshot = max %d usage %v, want max 0 usage 0", stats.V6FragMaxEntries, stats.V6FragUsagePercent)
	}
}

func TestBpfFlusher_ConntrackStatsReturnsCachedSnapshotWithoutSampling(t *testing.T) {
	calls := 0
	want := BpfConntrackStats{V4Entries: 7, V6Entries: 3}
	f := &BpfFlusher{
		stats: want,
		sampleConntrack: func() (utilebpf.ConnTrackStats, error) {
			calls++
			return utilebpf.ConnTrackStats{}, nil
		},
	}

	got := f.ConntrackStats()

	if got != want {
		t.Fatalf("ConntrackStats = %+v, want cached snapshot %+v", got, want)
	}
	if calls != 0 {
		t.Fatalf("ConntrackStats invoked sampler %d time(s), want 0; gauges must not drive map walks", calls)
	}
}

func TestBpfFlusher_ConntrackSamplerSamplesEachInterval(t *testing.T) {
	samples := make(chan int32, 3)
	var calls atomic.Int32
	f := &BpfFlusher{
		sampleConntrack: func() (utilebpf.ConnTrackStats, error) {
			call := calls.Add(1)
			select {
			case samples <- call:
			default:
			}
			return utilebpf.ConnTrackStats{
				V4: utilebpf.ConnTrackMapStats{
					Entries:    uint64(call),
					MaxEntries: 10,
				},
			}, nil
		},
	}

	f.startConntrackSampler(10 * time.Millisecond)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := f.StopConntrackSampler(ctx); err != nil {
			t.Fatalf("StopConntrackSampler err = %v", err)
		}
	}()

	for want := int32(1); want <= 3; want++ {
		select {
		case got := <-samples:
			if got != want {
				t.Fatalf("sample call = %d, want %d", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for sample call %d", want)
		}
	}
}

func TestBpfFlusher_ConntrackSamplerNonPositiveIntervalFallsBackToDefault(t *testing.T) {
	sampled := make(chan struct{}, 1)
	f := &BpfFlusher{
		sampleConntrack: func() (utilebpf.ConnTrackStats, error) {
			select {
			case sampled <- struct{}{}:
			default:
			}
			return utilebpf.ConnTrackStats{}, nil
		},
	}

	f.startConntrackSampler(0)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := f.StopConntrackSampler(ctx); err != nil {
			t.Fatalf("StopConntrackSampler err = %v", err)
		}
	}()

	select {
	case <-sampled:
	case <-time.After(time.Second):
		t.Fatal("sampler did not run immediate sample with fallback interval")
	}
}

func TestBpfFlusher_ConntrackSamplerStartStopWaitsForInFlightSample(t *testing.T) {
	sampleStarted := make(chan struct{})
	releaseSample := make(chan struct{})
	var calls atomic.Int32
	f := &BpfFlusher{
		sampleConntrack: func() (utilebpf.ConnTrackStats, error) {
			if calls.Add(1) == 1 {
				close(sampleStarted)
			}
			<-releaseSample
			return utilebpf.ConnTrackStats{
				V4: utilebpf.ConnTrackMapStats{Entries: 1, MaxEntries: 10},
			}, nil
		},
	}

	f.startConntrackSampler(time.Hour)
	f.startConntrackSampler(time.Hour)

	select {
	case <-sampleStarted:
	case <-time.After(time.Second):
		t.Fatal("sampler did not start an immediate sample")
	}

	stopReturned := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		stopReturned <- f.StopConntrackSampler(ctx)
	}()

	select {
	case err := <-stopReturned:
		t.Fatalf("StopConntrackSampler returned before in-flight sample completed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	close(releaseSample)
	select {
	case err := <-stopReturned:
		if err != nil {
			t.Fatalf("StopConntrackSampler err = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("StopConntrackSampler did not return after in-flight sample completed")
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("sample calls after duplicate start + stop = %d, want 1", got)
	}
	if err := f.StopConntrackSampler(context.Background()); err != nil {
		t.Fatalf("second StopConntrackSampler err = %v, want nil", err)
	}
}

func TestBpfFlusher_ConntrackSamplerStopTimeoutLeavesSamplerRegistered(t *testing.T) {
	sampleStarted := make(chan struct{})
	releaseSample := make(chan struct{})
	f := &BpfFlusher{
		sampleConntrack: func() (utilebpf.ConnTrackStats, error) {
			select {
			case <-sampleStarted:
			default:
				close(sampleStarted)
			}
			<-releaseSample
			return utilebpf.ConnTrackStats{
				V4: utilebpf.ConnTrackMapStats{Entries: 1, MaxEntries: 10},
			}, nil
		},
	}

	f.startConntrackSampler(time.Hour)
	select {
	case <-sampleStarted:
	case <-time.After(time.Second):
		t.Fatal("sampler did not start an immediate sample")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.StopConntrackSampler(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("StopConntrackSampler err = %v, want context.Canceled", err)
	}

	f.conntrackSamplerMu.Lock()
	registered := f.conntrackSampler != nil
	f.conntrackSamplerMu.Unlock()
	if !registered {
		t.Fatal("sampler unregistered before the blocked sample exited")
	}

	close(releaseSample)
	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
	defer waitCancel()
	if err := f.StopConntrackSampler(waitCtx); err != nil {
		t.Fatalf("StopConntrackSampler after releasing sample err = %v, want nil", err)
	}
}

func TestBpfConntrackStatsFromRaw_PostReapOccupancyAndCumulativeCounters(t *testing.T) {
	raw := utilebpf.ConnTrackStats{
		V4: utilebpf.ConnTrackMapStats{
			Entries:        10,
			MaxEntries:     20,
			OldestAgeNanos: uint64(2 * time.Second),
			ExpiredDeleted: 3,
		},
		V6: utilebpf.ConnTrackMapStats{
			Entries:        5,
			MaxEntries:     10,
			OldestAgeNanos: uint64(1500 * time.Millisecond),
			ExpiredDeleted: 5,
			PartialSample:  true,
		},
		FragV6: utilebpf.ConnTrackMapStats{
			Entries:        8,
			MaxEntries:     16,
			ExpiredDeleted: 2,
		},
	}

	got := bpfConntrackStatsFromRaw(raw, 2, 1, 11, 7, 13)
	if got.V4Entries != 7 {
		t.Fatalf("V4Entries = %d, want post-reap 7", got.V4Entries)
	}
	if got.V4UsagePercent != 35 {
		t.Fatalf("V4UsagePercent = %v, want 35", got.V4UsagePercent)
	}
	if got.V4OldestAgeSeconds != 2 {
		t.Fatalf("V4OldestAgeSeconds = %v, want 2", got.V4OldestAgeSeconds)
	}
	if got.V4ExpiredReaped != 11 {
		t.Fatalf("V4ExpiredReaped = %d, want cumulative 11", got.V4ExpiredReaped)
	}
	if got.V6Entries != 0 {
		t.Fatalf("V6Entries = %d, want 0 after reaping every observed entry", got.V6Entries)
	}
	if got.V6UsagePercent != 0 {
		t.Fatalf("V6UsagePercent = %v, want 0", got.V6UsagePercent)
	}
	if got.V6OldestAgeSeconds != 1.5 {
		t.Fatalf("V6OldestAgeSeconds = %v, want 1.5", got.V6OldestAgeSeconds)
	}
	if got.V6ExpiredReaped != 7 {
		t.Fatalf("V6ExpiredReaped = %d, want cumulative 7", got.V6ExpiredReaped)
	}
	if got.V6FragEntries != 6 {
		t.Fatalf("V6FragEntries = %d, want post-reap 6", got.V6FragEntries)
	}
	if got.V6FragUsagePercent != 37.5 {
		t.Fatalf("V6FragUsagePercent = %v, want 37.5", got.V6FragUsagePercent)
	}
	if got.V6FragExpiredReaped != 13 {
		t.Fatalf("V6FragExpiredReaped = %d, want cumulative 13", got.V6FragExpiredReaped)
	}
	if got.SampleErrors != 2 {
		t.Fatalf("SampleErrors = %d, want 2", got.SampleErrors)
	}
	if got.PartialSamples != 1 {
		t.Fatalf("PartialSamples = %d, want 1", got.PartialSamples)
	}
}

func TestBpfConntrackStatsPreserveLastGoodOnHardSampleError(t *testing.T) {
	previous := BpfConntrackStats{
		V4Entries:          17,
		V4MaxEntries:       100,
		V4UsagePercent:     17,
		V4OldestAgeSeconds: 4,
		V4ExpiredReaped:    9,
		V6Entries:          33,
		V6MaxEntries:       100,
		V6UsagePercent:     33,
		V6OldestAgeSeconds: 8,
		V6ExpiredReaped:    3,
		V6FragEntries:      44,
		V6FragMaxEntries:   100,
		V6FragUsagePercent: 44,
	}
	raw := utilebpf.ConnTrackStats{
		V4: utilebpf.ConnTrackMapStats{
			SampleError:  true,
			MapNotPinned: true,
		},
		V6: utilebpf.ConnTrackMapStats{
			Entries:        10,
			MaxEntries:     20,
			ExpiredDeleted: 2,
			OldestAgeNanos: uint64(3 * time.Second),
		},
		FragV6: utilebpf.ConnTrackMapStats{
			SampleError: true,
		},
	}

	next := bpfConntrackStatsFromRaw(raw, 1, 0, 9, 5, 0)
	got := bpfConntrackStatsPreserveConservativeOccupancy(next, previous, raw, errTestConntrackSample)

	if got.V4Entries != previous.V4Entries || got.V4MaxEntries != previous.V4MaxEntries ||
		got.V4UsagePercent != previous.V4UsagePercent || got.V4OldestAgeSeconds != previous.V4OldestAgeSeconds {
		t.Fatalf("V4 occupancy = entries %d max %d usage %v age %v, want previous entries %d max %d usage %v age %v",
			got.V4Entries, got.V4MaxEntries, got.V4UsagePercent, got.V4OldestAgeSeconds,
			previous.V4Entries, previous.V4MaxEntries, previous.V4UsagePercent, previous.V4OldestAgeSeconds)
	}
	if got.V4ExpiredReaped != 9 {
		t.Fatalf("V4ExpiredReaped = %d, want current watermark 9", got.V4ExpiredReaped)
	}
	if got.V6Entries != 8 || got.V6MaxEntries != 20 || got.V6UsagePercent != 40 || got.V6OldestAgeSeconds != 3 {
		t.Fatalf("V6 occupancy = entries %d max %d usage %v age %v, want new sample entries 8 max 20 usage 40 age 3",
			got.V6Entries, got.V6MaxEntries, got.V6UsagePercent, got.V6OldestAgeSeconds)
	}
	if got.V6ExpiredReaped != 5 {
		t.Fatalf("V6ExpiredReaped = %d, want current watermark 5", got.V6ExpiredReaped)
	}
	if got.V6FragEntries != previous.V6FragEntries || got.V6FragMaxEntries != previous.V6FragMaxEntries ||
		got.V6FragUsagePercent != previous.V6FragUsagePercent {
		t.Fatalf("V6Frag occupancy = entries %d max %d usage %v, want previous entries %d max %d usage %v",
			got.V6FragEntries, got.V6FragMaxEntries, got.V6FragUsagePercent,
			previous.V6FragEntries, previous.V6FragMaxEntries, previous.V6FragUsagePercent)
	}
	if got.SampleErrors != 1 {
		t.Fatalf("SampleErrors = %d, want 1", got.SampleErrors)
	}
}

func TestBpfConntrackStatsPreserveConservativeOccupancyOnPartialSample(t *testing.T) {
	previous := BpfConntrackStats{
		V4Entries:          80,
		V4MaxEntries:       100,
		V4UsagePercent:     80,
		V4OldestAgeSeconds: 20,
		V6Entries:          10,
		V6MaxEntries:       100,
		V6UsagePercent:     10,
		V6OldestAgeSeconds: 4,
		V6FragEntries:      60,
		V6FragMaxEntries:   100,
		V6FragUsagePercent: 60,
	}
	raw := utilebpf.ConnTrackStats{
		V4: utilebpf.ConnTrackMapStats{
			Entries:        20,
			MaxEntries:     100,
			OldestAgeNanos: uint64(3 * time.Second),
			PartialSample:  true,
		},
		V6: utilebpf.ConnTrackMapStats{
			Entries:        70,
			MaxEntries:     100,
			OldestAgeNanos: uint64(9 * time.Second),
			PartialSample:  true,
		},
		FragV6: utilebpf.ConnTrackMapStats{
			Entries:       20,
			MaxEntries:    100,
			PartialSample: true,
		},
	}

	next := bpfConntrackStatsFromRaw(raw, 0, 3, 7, 11, 13)
	got := bpfConntrackStatsPreserveConservativeOccupancy(next, previous, raw, nil)

	if got.V4Entries != previous.V4Entries || got.V4MaxEntries != previous.V4MaxEntries ||
		got.V4UsagePercent != previous.V4UsagePercent || got.V4OldestAgeSeconds != previous.V4OldestAgeSeconds {
		t.Fatalf("V4 partial occupancy = entries %d max %d usage %v age %v, want previous entries %d max %d usage %v age %v",
			got.V4Entries, got.V4MaxEntries, got.V4UsagePercent, got.V4OldestAgeSeconds,
			previous.V4Entries, previous.V4MaxEntries, previous.V4UsagePercent, previous.V4OldestAgeSeconds)
	}
	if got.V6Entries != 70 || got.V6MaxEntries != 100 || got.V6UsagePercent != 70 || got.V6OldestAgeSeconds != 9 {
		t.Fatalf("V6 partial occupancy = entries %d max %d usage %v age %v, want higher partial sample entries 70 max 100 usage 70 age 9",
			got.V6Entries, got.V6MaxEntries, got.V6UsagePercent, got.V6OldestAgeSeconds)
	}
	if got.V6FragEntries != previous.V6FragEntries || got.V6FragMaxEntries != previous.V6FragMaxEntries ||
		got.V6FragUsagePercent != previous.V6FragUsagePercent {
		t.Fatalf("V6Frag partial occupancy = entries %d max %d usage %v, want previous entries %d max %d usage %v",
			got.V6FragEntries, got.V6FragMaxEntries, got.V6FragUsagePercent,
			previous.V6FragEntries, previous.V6FragMaxEntries, previous.V6FragUsagePercent)
	}
	if got.PartialSamples != 3 || got.V4ExpiredReaped != 7 || got.V6ExpiredReaped != 11 || got.V6FragExpiredReaped != 13 {
		t.Fatalf("watermarks = partial %d v4Reaped %d v6Reaped %d fragV6Reaped %d, want current 3/7/11/13",
			got.PartialSamples, got.V4ExpiredReaped, got.V6ExpiredReaped, got.V6FragExpiredReaped)
	}
}

// TestConnFlowKey_String fences the log rendering — a ConnFlowKey in logs
// must show the source-port discriminator (the thing that distinguishes
// it from the coarse allow-rule FlowKey), so a revoke-path log line is
// actionable when diagnosing whether the right flow was targeted.
func TestConnFlowKey_String(t *testing.T) {
	k, err := MakeFlowKey("198.51.100.7", "203.0.113.10", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	got := ConnFlowKey{Flow: k, SrcPort: 43210}.String()
	want := "198.51.100.7:43210→203.0.113.10:443/tcp"
	if got != want {
		t.Errorf("ConnFlowKey.String() = %q, want %q", got, want)
	}
}
