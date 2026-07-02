package ac

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"

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

func TestUdpAC_EbpfTelemetryMetrics_RecordsCounterDeltas(t *testing.T) {
	publisher := metrics.NewPublisherForTest(t)
	var lostPerfSamples uint64
	var suppressedDeny uint64
	a := &UdpAC{
		registration: &ACRegistration{metrics: publisher},
		ebpfLostPerfSamples: func() uint64 {
			return lostPerfSamples
		},
		ebpfDenyTelemetrySuppressed: func() uint64 {
			return suppressedDeny
		},
	}

	lostPerfSamples = 3
	suppressedDeny = 2
	a.recordEbpfTelemetryMetricDeltas()
	if got := counterValueForTest(t, publisher, MetricEbpfPerfLostSamples); got != 3 {
		t.Fatalf("%s counter after first sample = %v, want 3", MetricEbpfPerfLostSamples, got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfDenyTelemetrySuppressed); got != 2 {
		t.Fatalf("%s counter after first sample = %v, want 2", MetricEbpfDenyTelemetrySuppressed, got)
	}

	a.recordEbpfTelemetryMetricDeltas()
	if got := counterValueForTest(t, publisher, MetricEbpfPerfLostSamples); got != 3 {
		t.Fatalf("%s counter after repeated watermark = %v, want still 3", MetricEbpfPerfLostSamples, got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfDenyTelemetrySuppressed); got != 2 {
		t.Fatalf("%s counter after repeated watermark = %v, want still 2", MetricEbpfDenyTelemetrySuppressed, got)
	}

	lostPerfSamples = 8
	suppressedDeny = 10
	a.recordEbpfTelemetryMetricDeltas()
	if got := counterValueForTest(t, publisher, MetricEbpfPerfLostSamples); got != 8 {
		t.Fatalf("%s counter after advanced watermark = %v, want 8", MetricEbpfPerfLostSamples, got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfDenyTelemetrySuppressed); got != 10 {
		t.Fatalf("%s counter after advanced watermark = %v, want 10", MetricEbpfDenyTelemetrySuppressed, got)
	}
}

func TestUdpAC_EbpfTelemetryMetrics_DoesNotConsumeCounterDeltasWithoutPublisher(t *testing.T) {
	publisher := metrics.NewPublisherForTest(t)
	a := &UdpAC{
		ebpfLostPerfSamples: func() uint64 {
			return 5
		},
		ebpfDenyTelemetrySuppressed: func() uint64 {
			return 4
		},
	}

	a.recordEbpfTelemetryMetricDeltas()
	if got := a.ebpfLostPerfSamplesReported.Load(); got != 0 {
		t.Fatalf("lost perf watermark advanced without publisher: got %d, want 0", got)
	}
	if got := a.ebpfDenyTelemetrySuppressedReported.Load(); got != 0 {
		t.Fatalf("suppressed-DENY watermark advanced without publisher: got %d, want 0", got)
	}

	a.registration = &ACRegistration{metrics: publisher}
	a.recordEbpfTelemetryMetricDeltas()
	if got := counterValueForTest(t, publisher, MetricEbpfPerfLostSamples); got != 5 {
		t.Fatalf("%s counter after publisher attach = %v, want 5", MetricEbpfPerfLostSamples, got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfDenyTelemetrySuppressed); got != 4 {
		t.Fatalf("%s counter after publisher attach = %v, want 4", MetricEbpfDenyTelemetrySuppressed, got)
	}
}

func TestUdpAC_EbpfTelemetryMetricPublisher_StartGating(t *testing.T) {
	tests := []struct {
		name              string
		filterMode        int
		registrationWired bool
		metricsWired      bool
		wantStarted       bool
	}{
		{
			name:              "ebpf with metrics starts",
			filterMode:        FilterMode_EBPFXDP,
			registrationWired: true,
			metricsWired:      true,
			wantStarted:       true,
		},
		{
			name:              "iptables with metrics does not start",
			filterMode:        FilterMode_IPTABLES,
			registrationWired: true,
			metricsWired:      true,
			wantStarted:       false,
		},
		{
			name:              "ebpf without registration does not start",
			filterMode:        FilterMode_EBPFXDP,
			registrationWired: false,
			metricsWired:      false,
			wantStarted:       false,
		},
		{
			name:              "ebpf without metrics does not start",
			filterMode:        FilterMode_EBPFXDP,
			registrationWired: true,
			metricsWired:      false,
			wantStarted:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var publisher *metrics.Publisher
			var registration *ACRegistration
			if tt.registrationWired {
				registration = &ACRegistration{}
				if tt.metricsWired {
					publisher = metrics.NewPublisherForTest(t)
					registration.metrics = publisher
				}
			}
			a := &UdpAC{
				config:       &Config{FilterMode: tt.filterMode},
				registration: registration,
				ebpfLostPerfSamples: func() uint64 {
					return 7
				},
				ebpfDenyTelemetrySuppressed: func() uint64 {
					return 9
				},
			}
			a.signals.stop = make(chan struct{})

			a.startEbpfTelemetryMetricPublisher()
			if gotStarted := a.ebpfTelemetryPublisherDone != nil; gotStarted != tt.wantStarted {
				t.Fatalf("publisher started = %t, want %t", gotStarted, tt.wantStarted)
			}
			firstDone := a.ebpfTelemetryPublisherDone
			a.startEbpfTelemetryMetricPublisher()
			if a.ebpfTelemetryPublisherDone != firstDone {
				t.Fatalf("second publisher start changed done channel: got %p, want %p", a.ebpfTelemetryPublisherDone, firstDone)
			}
			close(a.signals.stop)

			done := make(chan struct{})
			go func() {
				a.wg.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("telemetry metric publisher did not stop")
			}

			if publisher == nil {
				return
			}
			if got := counterValueForTest(t, publisher, MetricEbpfPerfLostSamples); got != 0 {
				t.Fatalf("%s counter after publisher stop = %v, want 0; Stop owns the final flush", MetricEbpfPerfLostSamples, got)
			}
			if got := counterValueForTest(t, publisher, MetricEbpfDenyTelemetrySuppressed); got != 0 {
				t.Fatalf("%s counter after publisher stop = %v, want 0; Stop owns the final flush", MetricEbpfDenyTelemetrySuppressed, got)
			}
		})
	}
}

func TestUdpAC_EbpfTelemetryMetricPublisher_StopFlushPublishesTrailingDelta(t *testing.T) {
	publisher := metrics.NewPublisherForTest(t)
	var lostPerfSamples uint64
	var suppressedDeny uint64
	a := &UdpAC{
		config:       &Config{FilterMode: FilterMode_EBPFXDP},
		registration: &ACRegistration{metrics: publisher},
		ebpfLostPerfSamples: func() uint64 {
			return lostPerfSamples
		},
		ebpfDenyTelemetrySuppressed: func() uint64 {
			return suppressedDeny
		},
	}
	a.signals.stop = make(chan struct{})

	a.startEbpfTelemetryMetricPublisher()
	if a.ebpfTelemetryPublisherDone == nil {
		t.Fatal("telemetry metric publisher did not start")
	}

	lostPerfSamples = 11
	suppressedDeny = 13
	close(a.signals.stop)
	a.flushEbpfTelemetryOnStop()
	select {
	case <-a.ebpfTelemetryPublisherDone:
	default:
		t.Fatal("telemetry metric publisher still running after stop flush")
	}
	if got := counterValueForTest(t, publisher, MetricEbpfPerfLostSamples); got != 11 {
		t.Fatalf("%s counter after stop flush = %v, want 11", MetricEbpfPerfLostSamples, got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfDenyTelemetrySuppressed); got != 13 {
		t.Fatalf("%s counter after stop flush = %v, want 13", MetricEbpfDenyTelemetrySuppressed, got)
	}

	a.flushEbpfTelemetryOnStop()
	if got := counterValueForTest(t, publisher, MetricEbpfPerfLostSamples); got != 11 {
		t.Fatalf("%s counter after repeated stop flush = %v, want still 11", MetricEbpfPerfLostSamples, got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfDenyTelemetrySuppressed); got != 13 {
		t.Fatalf("%s counter after repeated stop flush = %v, want still 13", MetricEbpfDenyTelemetrySuppressed, got)
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
		V6FragEntries:         4,
		V6FragMaxEntries:      16,
		V6FragUsagePercent:    25,
		V6FragExpiredReaped:   6,
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
	if got := reg.ebpfFragStateV6EntriesGauge(); got != 4 {
		t.Fatalf("V6 fragment entries gauge = %v, want 4", got)
	}
	if got := reg.ebpfFragStateV6MaxEntriesGauge(); got != 16 {
		t.Fatalf("V6 fragment max entries gauge = %v, want 16", got)
	}
	if got := reg.ebpfFragStateV6UsagePercentGauge(); got != 25 {
		t.Fatalf("V6 fragment usage gauge = %v, want 25", got)
	}
	if got := reg.ebpfConntrackSampleSecondsGauge(); got != 1.25 {
		t.Fatalf("sample seconds gauge = %v, want 1.25", got)
	}
}

func TestACRegistration_ConntrackGaugeCollectionReadsCachedStatsAndPublishesCounterDeltas(t *testing.T) {
	publisher := metrics.NewPublisherForTest(t)
	calls := 0
	a := &UdpAC{
		bpfConntrackStats: func() BpfConntrackStats {
			calls++
			return BpfConntrackStats{
				V4Entries:             42,
				V4ExpiredReaped:       11,
				V6ExpiredReaped:       5,
				V6FragEntries:         6,
				V6FragExpiredReaped:   7,
				SampleDurationSeconds: 1.25,
			}
		},
	}
	reg := &ACRegistration{ac: a, metrics: publisher}
	a.registration = reg
	reg.registerConntrackGaugeFuncs()

	gauges := publisher.GaugesForTest(t)

	if calls == 0 {
		t.Fatal("conntrack gauge collection did not read the cached BpfConntrackStats snapshot")
	}
	if got := gauges[MetricEbpfConntrackV4Entries]; got != 42 {
		t.Fatalf("%s gauge after collection = %v, want 42", MetricEbpfConntrackV4Entries, got)
	}
	if _, ok := gauges[MetricEbpfConntrackV6UsagePercent]; !ok {
		t.Fatalf("%s gauge was not registered; conntrack gauge block must stay in the collected gauge path", MetricEbpfConntrackV6UsagePercent)
	}
	if got := gauges[MetricEbpfFragStateV6Entries]; got != 6 {
		t.Fatalf("%s gauge after collection = %v, want 6", MetricEbpfFragStateV6Entries, got)
	}
	if got := gauges[MetricEbpfConntrackSampleSeconds]; got != 1.25 {
		t.Fatalf("%s gauge after collection = %v, want 1.25", MetricEbpfConntrackSampleSeconds, got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfConntrackV4ExpiredReaped); got != 11 {
		t.Fatalf("%s counter after collection = %v, want 11", MetricEbpfConntrackV4ExpiredReaped, got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfConntrackV6ExpiredReaped); got != 5 {
		t.Fatalf("%s counter after collection = %v, want 5", MetricEbpfConntrackV6ExpiredReaped, got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfFragStateV6ExpiredReaped); got != 7 {
		t.Fatalf("%s counter after collection = %v, want 7", MetricEbpfFragStateV6ExpiredReaped, got)
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
		MetricEbpfFragStateV6Entries,
		MetricEbpfFragStateV6MaxEntries,
		MetricEbpfFragStateV6UsagePercent,
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
	if got := reg.ebpfFragStateV6UsagePercentGauge(); got != 0 {
		t.Fatalf("V6 fragment usage gauge = %v, want 0 without BpfFlusher wiring", got)
	}
	if got := reg.ebpfConntrackSampleSecondsGauge(); got != 0 {
		t.Fatalf("sample seconds gauge = %v, want 0 without BpfFlusher wiring", got)
	}
}

func TestUdpAC_BpfConntrackStats_RecordsCounterDeltas(t *testing.T) {
	publisher := metrics.NewPublisherForTest(t)
	samples := []BpfConntrackStats{
		{SampleErrors: 2, PartialSamples: 1, V4ExpiredReaped: 11, V6ExpiredReaped: 5, V6FragExpiredReaped: 6},
		{SampleErrors: 2, PartialSamples: 1, V4ExpiredReaped: 11, V6ExpiredReaped: 5, V6FragExpiredReaped: 6},
		{SampleErrors: 5, PartialSamples: 4, V4ExpiredReaped: 17, V6ExpiredReaped: 9, V6FragExpiredReaped: 12},
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
	sampleErrors := counterValueForTest(t, publisher, MetricEbpfConntrackSampleErrors)
	if got := sampleErrors; got != 2 {
		t.Fatalf("sample error counter after first sample = %v, want 2", got)
	}
	partialSamples := counterValueForTest(t, publisher, MetricEbpfConntrackPartialSamples)
	if got := partialSamples; got != 1 {
		t.Fatalf("partial sample counter after first sample = %v, want 1", got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfConntrackV4ExpiredReaped); got != 11 {
		t.Fatalf("v4 expired-reaped counter after first sample = %v, want 11", got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfConntrackV6ExpiredReaped); got != 5 {
		t.Fatalf("v6 expired-reaped counter after first sample = %v, want 5", got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfFragStateV6ExpiredReaped); got != 6 {
		t.Fatalf("v6 fragment expired-reaped counter after first sample = %v, want 6", got)
	}

	if _, ok := a.BpfConntrackStats(); !ok {
		t.Fatal("BpfConntrackStats ok = false on cached cumulative sample, want true")
	}
	sampleErrors = counterValueForTest(t, publisher, MetricEbpfConntrackSampleErrors)
	if got := sampleErrors; got != 2 {
		t.Fatalf("sample error counter after repeated watermark = %v, want still 2", got)
	}
	partialSamples = counterValueForTest(t, publisher, MetricEbpfConntrackPartialSamples)
	if got := partialSamples; got != 1 {
		t.Fatalf("partial sample counter after repeated watermark = %v, want still 1", got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfConntrackV4ExpiredReaped); got != 11 {
		t.Fatalf("v4 expired-reaped counter after repeated watermark = %v, want still 11", got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfConntrackV6ExpiredReaped); got != 5 {
		t.Fatalf("v6 expired-reaped counter after repeated watermark = %v, want still 5", got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfFragStateV6ExpiredReaped); got != 6 {
		t.Fatalf("v6 fragment expired-reaped counter after repeated watermark = %v, want still 6", got)
	}

	if _, ok := a.BpfConntrackStats(); !ok {
		t.Fatal("BpfConntrackStats ok = false on advanced cumulative sample, want true")
	}
	sampleErrors = counterValueForTest(t, publisher, MetricEbpfConntrackSampleErrors)
	if got := sampleErrors; got != 5 {
		t.Fatalf("sample error counter after advanced watermark = %v, want 5", got)
	}
	partialSamples = counterValueForTest(t, publisher, MetricEbpfConntrackPartialSamples)
	if got := partialSamples; got != 4 {
		t.Fatalf("partial sample counter after advanced watermark = %v, want 4", got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfConntrackV4ExpiredReaped); got != 17 {
		t.Fatalf("v4 expired-reaped counter after advanced watermark = %v, want 17", got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfConntrackV6ExpiredReaped); got != 9 {
		t.Fatalf("v6 expired-reaped counter after advanced watermark = %v, want 9", got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfFragStateV6ExpiredReaped); got != 12 {
		t.Fatalf("v6 fragment expired-reaped counter after advanced watermark = %v, want 12", got)
	}
}

func TestUdpAC_BpfConntrackStats_DoesNotConsumeCounterDeltasWithoutPublisher(t *testing.T) {
	publisher := metrics.NewPublisherForTest(t)
	a := &UdpAC{
		bpfConntrackStats: func() BpfConntrackStats {
			return BpfConntrackStats{
				SampleErrors:        2,
				PartialSamples:      1,
				V4ExpiredReaped:     11,
				V6ExpiredReaped:     5,
				V6FragExpiredReaped: 6,
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
	if got := a.bpfFragStateExpiredReapedV6Reported.Load(); got != 0 {
		t.Fatalf("v6 fragment expired-reaped watermark advanced without publisher: got %d, want 0", got)
	}

	a.registration = &ACRegistration{metrics: publisher}
	if _, ok := a.BpfConntrackStats(); !ok {
		t.Fatal("BpfConntrackStats ok = false with publisher, want true")
	}
	if got := counterValueForTest(t, publisher, MetricEbpfConntrackSampleErrors); got != 2 {
		t.Fatalf("sample-error counter after publisher attach = %v, want 2", got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfConntrackV4ExpiredReaped); got != 11 {
		t.Fatalf("v4 expired-reaped counter after publisher attach = %v, want 11", got)
	}
	if got := counterValueForTest(t, publisher, MetricEbpfFragStateV6ExpiredReaped); got != 6 {
		t.Fatalf("v6 fragment expired-reaped counter after publisher attach = %v, want 6", got)
	}
}

func counterValueForTest(t *testing.T, publisher *metrics.Publisher, name string) float64 {
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
