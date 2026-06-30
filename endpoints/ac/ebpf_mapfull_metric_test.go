package ac

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/utils/ebpf"
)

// These tests prove the LOUD half of the eBPF allow-rule fail-closed path
// (#2163, item 3: a full allow-rule map must FAIL the admission with a metric
// + log, not a swallowed error). They exercise (*UdpAC).recordEbpfInsertResult
// — the detect-and-record half of ebpfRuleAddFailClosed — with a SYNTHETIC
// error so the assertion needs no kernel and no pinned BPF maps (this package
// builds and these tests run on darwin). The synthetic error wraps
// syscall.E2BIG exactly the way cilium/ebpf wraps a real full-map insert
// ("key too big for map: %w" over unix.E2BIG, see wrapMapError), so the branch
// driven here is the same one a real kernel -E2BIG would drive.
//
// The behavioral proof that a full HASH map actually returns E2BIG (and that
// LRU_HASH would instead silently evict) lives in the kernel test
// nhp/utils/ebpf/maptype_eviction_linux_test.go.

func newMetricTestAC(t *testing.T) *UdpAC {
	t.Helper()
	return &UdpAC{
		registration: &ACRegistration{
			metrics: metrics.NewPublisherForTest(t),
		},
	}
}

// simulatedMapFullErr mirrors how cilium/ebpf surfaces a full-map insert:
// fmt.Errorf("update: %w", fmt.Errorf("key too big for map: %w", unix.E2BIG)).
// errors.Is must reach syscall.E2BIG through both wrappers.
func simulatedMapFullErr() error {
	return fmt.Errorf("update: %w", fmt.Errorf("key too big for map: %w", syscall.E2BIG))
}

// TestRecordEbpfInsertResult_MapFull_IncrementsMetricAndReturnsErr is the core
// proof: a map-full error bumps MetricEbpfMapFull exactly once AND is returned
// UNCHANGED (so the caller's fail-closed early-return still fires). A swallowed
// error here would be an admitted-but-not-enforced session — the security hole
// #2163 guards against.
func TestRecordEbpfInsertResult_MapFull_IncrementsMetricAndReturnsErr(t *testing.T) {
	a := newMetricTestAC(t)
	in := simulatedMapFullErr()

	out := a.recordEbpfInsertResult(in, ebpf.EbpfRuleParams{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}, 1)

	if !errors.Is(out, syscall.E2BIG) {
		t.Fatalf("map-full error must be returned unchanged (fail-closed); got %v", out)
	}
	counters, _ := a.registration.metrics.CountersForTest(t)
	if got := counters[MetricEbpfMapFull]; got != 1 {
		t.Fatalf("MetricEbpfMapFull = %v, want 1 — a full allow-rule map must raise a LOUD metric (#2163); an alarm at the eBPF FilterMode flip observes this counter", got)
	}
}

// TestRecordEbpfInsertResult_Success_NoMetric: a successful insert (nil error)
// must not bump the map-full counter and must return nil.
func TestRecordEbpfInsertResult_Success_NoMetric(t *testing.T) {
	a := newMetricTestAC(t)

	if out := a.recordEbpfInsertResult(nil, ebpf.EbpfRuleParams{SrcIP: "10.0.0.1"}, 1); out != nil {
		t.Fatalf("nil insert error must pass through as nil; got %v", out)
	}
	counters, _ := a.registration.metrics.CountersForTest(t)
	if got := counters[MetricEbpfMapFull]; got != 0 {
		t.Fatalf("MetricEbpfMapFull = %v, want 0 on success — the map-full counter must not fire for non-full inserts", got)
	}
}

// TestRecordEbpfInsertResult_OtherError_NoMetricButReturned: a non-map-full
// error (e.g. EPERM) must be returned unchanged (still fail-closed at the
// caller) but must NOT be miscounted as a capacity event — operators rely on
// MetricEbpfMapFull meaning "we hit the allow-rule ceiling", not "any insert
// error". This guards against the counter becoming a noisy catch-all.
func TestRecordEbpfInsertResult_OtherError_NoMetricButReturned(t *testing.T) {
	a := newMetricTestAC(t)
	in := fmt.Errorf("update: %w", syscall.EPERM)

	out := a.recordEbpfInsertResult(in, ebpf.EbpfRuleParams{SrcIP: "10.0.0.1"}, 1)

	if !errors.Is(out, syscall.EPERM) {
		t.Fatalf("non-map-full error must be returned unchanged; got %v", out)
	}
	counters, _ := a.registration.metrics.CountersForTest(t)
	if got := counters[MetricEbpfMapFull]; got != 0 {
		t.Fatalf("MetricEbpfMapFull = %v, want 0 for a non-E2BIG error — capacity counter must not be a catch-all", got)
	}
}

// TestRecordEbpfInsertResult_RepeatedMapFull_MonotonicCount: each rejected
// admission increments the counter (so a sustained capacity event is visible as
// a rate, not a single blip).
func TestRecordEbpfInsertResult_RepeatedMapFull_MonotonicCount(t *testing.T) {
	a := newMetricTestAC(t)
	const n = 5
	for i := 0; i < n; i++ {
		_ = a.recordEbpfInsertResult(simulatedMapFullErr(), ebpf.EbpfRuleParams{SrcIP: "10.0.0.1"}, 2)
	}
	counters, _ := a.registration.metrics.CountersForTest(t)
	if got := counters[MetricEbpfMapFull]; got != n {
		t.Fatalf("MetricEbpfMapFull = %v, want %d (every rejected admission must be counted)", got, n)
	}
}
