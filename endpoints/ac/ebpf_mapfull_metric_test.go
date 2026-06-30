package ac

import (
	"errors"
	"fmt"
	"strings"
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

func TestACRegistration_EbpfConntrackGauges_ReadWiredStats(t *testing.T) {
	want := BpfConntrackStats{
		V4Entries:             7,
		V4MaxEntries:          20,
		V4UsagePercent:        35,
		V4OldestAgeSeconds:    2.5,
		V4ExpiredReaped:       11,
		V6Entries:             3,
		V6MaxEntries:          10,
		V6UsagePercent:        30,
		V6OldestAgeSeconds:    1.5,
		V6ExpiredReaped:       5,
		SampleDurationSeconds: 1.25,
	}
	a := &UdpAC{
		bpfConntrackStats: func() BpfConntrackStats {
			return want
		},
	}
	reg := &ACRegistration{ac: a}

	if got := reg.ebpfConntrackV4EntriesGauge(); got != 7 {
		t.Fatalf("V4 entries gauge = %v, want 7", got)
	}
	if got := reg.ebpfConntrackV4MaxEntriesGauge(); got != 20 {
		t.Fatalf("V4 max entries gauge = %v, want 20", got)
	}
	if got := reg.ebpfConntrackV4UsagePercentGauge(); got != 35 {
		t.Fatalf("V4 usage gauge = %v, want 35", got)
	}
	if got := reg.ebpfConntrackV4OldestAgeSecondsGauge(); got != 2.5 {
		t.Fatalf("V4 oldest age gauge = %v, want 2.5", got)
	}
	if got := reg.ebpfConntrackV6EntriesGauge(); got != 3 {
		t.Fatalf("V6 entries gauge = %v, want 3", got)
	}
	if got := reg.ebpfConntrackV6MaxEntriesGauge(); got != 10 {
		t.Fatalf("V6 max entries gauge = %v, want 10", got)
	}
	if got := reg.ebpfConntrackV6UsagePercentGauge(); got != 30 {
		t.Fatalf("V6 usage gauge = %v, want 30", got)
	}
	if got := reg.ebpfConntrackV6OldestAgeSecondsGauge(); got != 1.5 {
		t.Fatalf("V6 oldest age gauge = %v, want 1.5", got)
	}
	if got := reg.ebpfConntrackSampleSecondsGauge(); got != 1.25 {
		t.Fatalf("sample seconds gauge = %v, want 1.25", got)
	}
}

func TestACRegistration_ConntrackGaugeCollectionDrivesStatsSampler(t *testing.T) {
	publisher := metrics.NewPublisherForTest(t)
	calls := 0
	a := &UdpAC{
		bpfConntrackStats: func() BpfConntrackStats {
			calls++
			return BpfConntrackStats{
				V4Entries:             42,
				V4ExpiredReaped:       11,
				V6ExpiredReaped:       5,
				SampleDurationSeconds: 1.25,
			}
		},
	}
	reg := &ACRegistration{ac: a, metrics: publisher}
	a.registration = reg
	reg.registerConntrackGaugeFuncs()

	gauges := publisher.GaugesForTest(t)

	if calls == 0 {
		t.Fatal("conntrack gauge collection did not call BpfConntrackStats; quiet-entry reaping depends on this side effect")
	}
	if got := gauges[MetricEbpfConntrackV4Entries]; got != 42 {
		t.Fatalf("%s gauge after collection = %v, want 42", MetricEbpfConntrackV4Entries, got)
	}
	if _, ok := gauges[MetricEbpfConntrackV6UsagePercent]; !ok {
		t.Fatalf("%s gauge was not registered; conntrack gauge block must stay in the collected gauge path", MetricEbpfConntrackV6UsagePercent)
	}
	if got := gauges[MetricEbpfConntrackSampleSeconds]; got != 1.25 {
		t.Fatalf("%s gauge after collection = %v, want 1.25", MetricEbpfConntrackSampleSeconds, got)
	}
	if got := conntrackCounterValueForTest(t, publisher, MetricEbpfConntrackV4ExpiredReaped); got != 11 {
		t.Fatalf("%s counter after collection = %v, want 11", MetricEbpfConntrackV4ExpiredReaped, got)
	}
	if got := conntrackCounterValueForTest(t, publisher, MetricEbpfConntrackV6ExpiredReaped); got != 5 {
		t.Fatalf("%s counter after collection = %v, want 5", MetricEbpfConntrackV6ExpiredReaped, got)
	}
}

func TestACRegistration_ConntrackGaugeRegistrationSkipsUnwired(t *testing.T) {
	publisher := metrics.NewPublisherForTest(t)
	reg := &ACRegistration{ac: &UdpAC{}, metrics: publisher}
	reg.registerConntrackGaugeFuncs()

	gauges := publisher.GaugesForTest(t)
	for _, name := range []string{
		MetricEbpfConntrackV4Entries,
		MetricEbpfConntrackV4MaxEntries,
		MetricEbpfConntrackV4UsagePercent,
		MetricEbpfConntrackV4OldestAgeSeconds,
		MetricEbpfConntrackV6Entries,
		MetricEbpfConntrackV6MaxEntries,
		MetricEbpfConntrackV6UsagePercent,
		MetricEbpfConntrackV6OldestAgeSeconds,
		MetricEbpfConntrackSampleSeconds,
	} {
		if _, ok := gauges[name]; ok {
			t.Fatalf("%s gauge registered without BpfFlusher stats wiring; pre-flip conntrack metrics should stay silent", name)
		}
	}
}

func TestACRegistration_EbpfConntrackGauges_ZeroWhenUnwired(t *testing.T) {
	reg := &ACRegistration{ac: &UdpAC{}}
	if got := reg.ebpfConntrackV4EntriesGauge(); got != 0 {
		t.Fatalf("V4 entries gauge = %v, want 0 without BpfFlusher wiring", got)
	}
	if got := reg.ebpfConntrackV6UsagePercentGauge(); got != 0 {
		t.Fatalf("V6 usage gauge = %v, want 0 without BpfFlusher wiring", got)
	}
	if got := reg.ebpfConntrackSampleSecondsGauge(); got != 0 {
		t.Fatalf("sample seconds gauge = %v, want 0 without BpfFlusher wiring", got)
	}
}

func TestUdpAC_BpfConntrackStats_RecordsCounterDeltas(t *testing.T) {
	publisher := metrics.NewPublisherForTest(t)
	samples := []BpfConntrackStats{
		{SampleErrors: 2, PartialSamples: 1, V4ExpiredReaped: 11, V6ExpiredReaped: 5},
		{SampleErrors: 2, PartialSamples: 1, V4ExpiredReaped: 11, V6ExpiredReaped: 5},
		{SampleErrors: 5, PartialSamples: 4, V4ExpiredReaped: 17, V6ExpiredReaped: 9},
	}
	idx := 0
	a := &UdpAC{
		registration: &ACRegistration{metrics: publisher},
		bpfConntrackStats: func() BpfConntrackStats {
			if idx >= len(samples) {
				return samples[len(samples)-1]
			}
			stats := samples[idx]
			idx++
			return stats
		},
	}

	if _, ok := a.BpfConntrackStats(); !ok {
		t.Fatal("BpfConntrackStats ok = false, want true")
	}
	sampleErrors := conntrackCounterValueForTest(t, publisher, MetricEbpfConntrackSampleErrors)
	if got := sampleErrors; got != 2 {
		t.Fatalf("sample error counter after first sample = %v, want 2", got)
	}
	partialSamples := conntrackCounterValueForTest(t, publisher, MetricEbpfConntrackPartialSamples)
	if got := partialSamples; got != 1 {
		t.Fatalf("partial sample counter after first sample = %v, want 1", got)
	}
	if got := conntrackCounterValueForTest(t, publisher, MetricEbpfConntrackV4ExpiredReaped); got != 11 {
		t.Fatalf("v4 expired-reaped counter after first sample = %v, want 11", got)
	}
	if got := conntrackCounterValueForTest(t, publisher, MetricEbpfConntrackV6ExpiredReaped); got != 5 {
		t.Fatalf("v6 expired-reaped counter after first sample = %v, want 5", got)
	}

	if _, ok := a.BpfConntrackStats(); !ok {
		t.Fatal("BpfConntrackStats ok = false on cached cumulative sample, want true")
	}
	sampleErrors = conntrackCounterValueForTest(t, publisher, MetricEbpfConntrackSampleErrors)
	if got := sampleErrors; got != 2 {
		t.Fatalf("sample error counter after repeated watermark = %v, want still 2", got)
	}
	partialSamples = conntrackCounterValueForTest(t, publisher, MetricEbpfConntrackPartialSamples)
	if got := partialSamples; got != 1 {
		t.Fatalf("partial sample counter after repeated watermark = %v, want still 1", got)
	}
	if got := conntrackCounterValueForTest(t, publisher, MetricEbpfConntrackV4ExpiredReaped); got != 11 {
		t.Fatalf("v4 expired-reaped counter after repeated watermark = %v, want still 11", got)
	}
	if got := conntrackCounterValueForTest(t, publisher, MetricEbpfConntrackV6ExpiredReaped); got != 5 {
		t.Fatalf("v6 expired-reaped counter after repeated watermark = %v, want still 5", got)
	}

	if _, ok := a.BpfConntrackStats(); !ok {
		t.Fatal("BpfConntrackStats ok = false on advanced cumulative sample, want true")
	}
	sampleErrors = conntrackCounterValueForTest(t, publisher, MetricEbpfConntrackSampleErrors)
	if got := sampleErrors; got != 5 {
		t.Fatalf("sample error counter after advanced watermark = %v, want 5", got)
	}
	partialSamples = conntrackCounterValueForTest(t, publisher, MetricEbpfConntrackPartialSamples)
	if got := partialSamples; got != 4 {
		t.Fatalf("partial sample counter after advanced watermark = %v, want 4", got)
	}
	if got := conntrackCounterValueForTest(t, publisher, MetricEbpfConntrackV4ExpiredReaped); got != 17 {
		t.Fatalf("v4 expired-reaped counter after advanced watermark = %v, want 17", got)
	}
	if got := conntrackCounterValueForTest(t, publisher, MetricEbpfConntrackV6ExpiredReaped); got != 9 {
		t.Fatalf("v6 expired-reaped counter after advanced watermark = %v, want 9", got)
	}
}

func TestUdpAC_BpfConntrackStats_DoesNotConsumeCounterDeltasWithoutPublisher(t *testing.T) {
	publisher := metrics.NewPublisherForTest(t)
	a := &UdpAC{
		bpfConntrackStats: func() BpfConntrackStats {
			return BpfConntrackStats{
				SampleErrors:    2,
				PartialSamples:  1,
				V4ExpiredReaped: 11,
				V6ExpiredReaped: 5,
			}
		},
	}

	if _, ok := a.BpfConntrackStats(); !ok {
		t.Fatal("BpfConntrackStats ok = false without publisher, want true because stats reader is wired")
	}
	if got := a.bpfConntrackSampleErrorsReported.Load(); got != 0 {
		t.Fatalf("sample-error watermark advanced without publisher: got %d, want 0", got)
	}
	if got := a.bpfConntrackExpiredReapedV4Reported.Load(); got != 0 {
		t.Fatalf("v4 expired-reaped watermark advanced without publisher: got %d, want 0", got)
	}

	a.registration = &ACRegistration{metrics: publisher}
	if _, ok := a.BpfConntrackStats(); !ok {
		t.Fatal("BpfConntrackStats ok = false with publisher, want true")
	}
	if got := conntrackCounterValueForTest(t, publisher, MetricEbpfConntrackSampleErrors); got != 2 {
		t.Fatalf("sample-error counter after publisher attach = %v, want 2", got)
	}
	if got := conntrackCounterValueForTest(t, publisher, MetricEbpfConntrackV4ExpiredReaped); got != 11 {
		t.Fatalf("v4 expired-reaped counter after publisher attach = %v, want 11", got)
	}
}

func conntrackCounterValueForTest(t *testing.T, publisher *metrics.Publisher, name string) float64 {
	t.Helper()

	counters, dimCounters := publisher.CountersForTest(t)
	total := counters[name] + dimCounters[name]
	anchored := name + "\x00"
	for k, v := range dimCounters {
		if strings.HasPrefix(k, anchored) {
			total += v
		}
	}
	return total
}
