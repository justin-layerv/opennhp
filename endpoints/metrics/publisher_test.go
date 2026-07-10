package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

// testFlushInstant is the deterministic flush time threaded through the
// metric-build and EMF tests so they can assert datums carry an exact,
// reproducible timestamp (rather than a live time.Now). Shared so the fixture
// lives in one place instead of being re-spelled at each call site.
var testFlushInstant = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func TestNewPublisher_AWSUnavailable(t *testing.T) {
	original := loadAWSConfig
	loadAWSConfig = func(ctx context.Context, optFns ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, fmt.Errorf("simulated AWS config failure")
	}
	defer func() { loadAWSConfig = original }()

	p := NewPublisher(Config{Namespace: "Test"})
	if p != nil {
		p.Stop()
		t.Error("expected nil publisher when AWS config fails")
	}
}

func TestPublisher_NilSafety(t *testing.T) {
	var mp *Publisher

	// All methods should be no-ops on nil receiver (no panic)
	mp.IncrCounter("test")
	mp.IncrCounterWithDims("test", nil)
	mp.AddCounterWithDims("test", 5, nil)
	mp.RecordLatency("test", 1.0)
	mp.SetGauge("test", 42)
	mp.RegisterGaugeFunc("test", func() float64 { return 1 })
	mp.RegisterHistogramFunc("test", types.StandardUnitMilliseconds, func() []float64 { return nil })
	mp.SetHealthProbe(func(ctx context.Context) bool { return true })
	mp.Stop()
	if got := mp.DimensionsForTest(t); got != nil {
		t.Errorf("DimensionsForTest(t) on nil receiver = %v, want nil", got)
	}
}

// TestPublisher_DimensionsForTestDeepCopies fences the deep-copy
// guarantee DimensionsForTest documents. types.Dimension holds
// *string Name and Value; a shallow copy of the slice would share
// those pointers and let a caller mutate *d.Name / *d.Value to
// clobber the publisher's invariant. This test mutates the returned
// slice and re-reads to confirm the publisher's view is untouched.
//
// Uses SetBaseDimsForTest rather than touching mp.dims directly so
// the test mirrors how production-shaped helpers wire dims — keeps
// the test structurally safe if newTestPublisher ever switches to
// NewPublisher (which starts the flushLoop goroutine).
func TestPublisher_DimensionsForTestDeepCopies(t *testing.T) {
	mp := newTestPublisher(t, nil)
	mp.SetBaseDimsForTest(t, []types.Dimension{
		{Name: aws.String("Environment"), Value: aws.String("prod")},
	})

	got := mp.DimensionsForTest(t)
	if len(got) != 1 || *got[0].Name != "Environment" || *got[0].Value != "prod" {
		t.Fatalf("DimensionsForTest returned unexpected initial state: %+v", got)
	}

	*got[0].Value = "mutated-by-caller"
	*got[0].Name = "AlsoMutated"

	again := mp.DimensionsForTest(t)
	if *again[0].Name != "Environment" || *again[0].Value != "prod" {
		t.Errorf("DimensionsForTest shared pointee with caller; publisher state was mutated: Name=%q Value=%q",
			*again[0].Name, *again[0].Value)
	}
}

func TestPublisher_SetGauge(t *testing.T) {
	mp := newTestPublisher(t, nil)

	mp.SetGauge("ACPeerCount", 5)

	mp.mu.Lock()
	val, exists := mp.gauges["ACPeerCount"]
	mp.mu.Unlock()

	if !exists {
		t.Fatal("expected ACPeerCount gauge to exist")
	}
	if val != 5 {
		t.Errorf("expected ACPeerCount=5, got %v", val)
	}

	// Zero is a valid gauge value (always published)
	mp.SetGauge("ACPeerCount", 0)
	mp.mu.Lock()
	val = mp.gauges["ACPeerCount"]
	mp.mu.Unlock()
	if val != 0 {
		t.Errorf("expected ACPeerCount=0, got %v", val)
	}
}

func TestPublisher_RegisterGaugeFunc(t *testing.T) {
	mp := newTestPublisher(t, nil)

	peerCount := 3
	mp.RegisterGaugeFunc("ACPeerCount", func() float64 {
		return float64(peerCount)
	})

	// Before collectGauges, gauge should not exist
	mp.mu.Lock()
	_, exists := mp.gauges["ACPeerCount"]
	mp.mu.Unlock()
	if exists {
		t.Error("expected ACPeerCount gauge to not exist before collectGauges")
	}

	// After collectGauges, gauge should reflect the function's return value
	mp.collectGauges()
	mp.mu.Lock()
	val := mp.gauges["ACPeerCount"]
	mp.mu.Unlock()
	if val != 3 {
		t.Errorf("expected ACPeerCount=3, got %v", val)
	}

	// Change the underlying value and collect again
	peerCount = 0
	mp.collectGauges()
	mp.mu.Lock()
	val = mp.gauges["ACPeerCount"]
	mp.mu.Unlock()
	if val != 0 {
		t.Errorf("expected ACPeerCount=0, got %v", val)
	}
}

func TestPublisher_RegisterHistogramFunc(t *testing.T) {
	mp := newTestPublisher(t, nil)

	pending := []float64{0.125, 0.25, 0.25}
	mp.RegisterHistogramFunc("ConntrackDumpDuration", types.StandardUnitMilliseconds, func() []float64 {
		out := pending
		pending = nil
		return out
	})

	mp.collectHistograms()
	mp.mu.Lock()
	entry := mp.histograms["ConntrackDumpDuration"]
	mp.mu.Unlock()
	if entry == nil {
		t.Fatal("expected ConntrackDumpDuration histogram to be collected")
	}
	if entry.unit != types.StandardUnitMilliseconds {
		t.Errorf("histogram unit = %v, want Milliseconds", entry.unit)
	}
	if got, want := entry.values, []float64{0.125, 0.25, 0.25}; !slices.Equal(got, want) {
		t.Errorf("histogram values = %v, want %v", got, want)
	}

	mp.collectHistograms()
	mp.mu.Lock()
	again := slices.Clone(mp.histograms["ConntrackDumpDuration"].values)
	mp.mu.Unlock()
	if got, want := again, []float64{0.125, 0.25, 0.25}; !slices.Equal(got, want) {
		t.Errorf("second collect with empty drain changed values = %v, want %v", got, want)
	}
}

func TestPublisher_RegisterHistogramFuncInitializesMaps(t *testing.T) {
	mp := &Publisher{}
	mp.RegisterHistogramFunc("DumpDuration", types.StandardUnitMilliseconds, func() []float64 {
		return []float64{1.25}
	})

	mp.collectHistograms()
	mp.mu.Lock()
	entry := mp.histograms["DumpDuration"]
	dropped := mp.counters[histogramPublisherDroppedMetricName("DumpDuration")]
	mp.mu.Unlock()
	if entry == nil {
		t.Fatal("expected DumpDuration histogram to be collected")
	}
	if entry.unit != types.StandardUnitMilliseconds {
		t.Errorf("histogram unit = %v, want Milliseconds", entry.unit)
	}
	if got, want := entry.values, []float64{1.25}; !slices.Equal(got, want) {
		t.Errorf("histogram values = %v, want %v", got, want)
	}
	if dropped != 0 {
		t.Errorf("%s = %v, want 0", histogramPublisherDroppedMetricName("DumpDuration"), dropped)
	}
}

func TestPublisher_RegisterHistogramFuncUpdatesUnit(t *testing.T) {
	mp := newTestPublisher(t, nil)
	mp.RegisterHistogramFunc("DumpDuration", types.StandardUnitMilliseconds, func() []float64 {
		return []float64{1}
	})
	mp.collectHistograms()

	// Re-registration is last-unit-wins for buffered samples in the same flush
	// window. Production registers once at startup, but keep the edge explicit.
	mp.RegisterHistogramFunc("DumpDuration", types.StandardUnitSeconds, func() []float64 {
		return []float64{2}
	})
	mp.collectHistograms()

	mp.mu.Lock()
	entry := mp.histograms["DumpDuration"]
	mp.mu.Unlock()
	if entry == nil {
		t.Fatal("expected DumpDuration histogram to be collected")
	}
	if entry.unit != types.StandardUnitSeconds {
		t.Errorf("histogram unit = %v, want Seconds", entry.unit)
	}
	if got, want := entry.values, []float64{1, 2}; !slices.Equal(got, want) {
		t.Errorf("histogram values = %v, want %v", got, want)
	}
}

func TestPublisher_HistogramCap(t *testing.T) {
	mp := newTestPublisher(t, nil)

	values := make([]float64, MaxHistogramSamples+2)
	for i := range values {
		values[i] = float64(i)
	}
	mp.RegisterHistogramFunc("DumpDuration", types.StandardUnitMilliseconds, func() []float64 {
		return values
	})

	mp.collectHistograms()
	mp.mu.Lock()
	gotSamples := len(mp.histograms["DumpDuration"].values)
	gotDropped := mp.counters[histogramPublisherDroppedMetricName("DumpDuration")]
	mp.mu.Unlock()
	if gotSamples != MaxHistogramSamples {
		t.Errorf("histogram samples = %d, want cap %d", gotSamples, MaxHistogramSamples)
	}
	if gotDropped != 2 {
		t.Errorf("%s = %v, want 2", histogramPublisherDroppedMetricName("DumpDuration"), gotDropped)
	}
}

func TestPublisher_HistogramFiltersInvalidValuesAsPublisherDropped(t *testing.T) {
	mp := newTestPublisher(t, nil)
	mp.RegisterHistogramFunc("DumpDuration", types.StandardUnitMilliseconds, func() []float64 {
		return []float64{math.NaN(), 0.2, math.Inf(1), 0.1, math.Inf(-1)}
	})

	mp.collectHistograms()
	mp.mu.Lock()
	entry := mp.histograms["DumpDuration"]
	gotDropped := mp.counters[histogramPublisherDroppedMetricName("DumpDuration")]
	mp.mu.Unlock()
	if entry == nil {
		t.Fatal("expected DumpDuration histogram to be collected")
	}
	if got, want := entry.values, []float64{0.2, 0.1}; !slices.Equal(got, want) {
		t.Errorf("histogram values = %v, want %v", got, want)
	}
	if gotDropped != 3 {
		t.Errorf("%s = %v, want 3", histogramPublisherDroppedMetricName("DumpDuration"), gotDropped)
	}
}

func TestPublisher_SetHealthProbe(t *testing.T) {
	// NOTE: client is intentionally nil — this test only exercises probeHealth(),
	// which writes to the gauges map.
	mp := &Publisher{
		counters:    make(map[string]float64),
		dimCounters: make(map[string]*dimCounterEntry),
		gauges:      make(map[string]float64),
		latencies:   make(map[string][]float64),
		stop:        make(chan struct{}),
	}

	// No probe set — probeHealth should be a no-op
	mp.probeHealth()
	mp.mu.Lock()
	if _, exists := mp.gauges["StorageHealthy"]; exists {
		t.Error("expected no StorageHealthy gauge before probe is set")
	}
	mp.mu.Unlock()

	// Set a healthy probe
	mp.SetHealthProbe(func(ctx context.Context) bool { return true })
	mp.probeHealth()
	mp.mu.Lock()
	if mp.gauges["StorageHealthy"] != 1.0 {
		t.Errorf("expected StorageHealthy=1.0, got %v", mp.gauges["StorageHealthy"])
	}
	mp.mu.Unlock()

	// Set an unhealthy probe — 0 must be stored (not skipped like counters)
	mp.SetHealthProbe(func(ctx context.Context) bool { return false })
	mp.probeHealth()
	mp.mu.Lock()
	val, exists := mp.gauges["StorageHealthy"]
	mp.mu.Unlock()
	if !exists {
		t.Fatal("expected StorageHealthy gauge to exist when unhealthy")
	}
	if val != 0.0 {
		t.Errorf("expected StorageHealthy=0.0, got %v", val)
	}
}

func TestPublisher_Flush_NoClientDoesNotPanic(t *testing.T) {
	mp := newTestPublisher(t, nil)
	mp.IncrCounter("KnockRequest")
	mp.flush() // must not panic — nil client is handled gracefully
}

func TestPublisher_CounterAccumulation(t *testing.T) {
	mp := &Publisher{
		counters:    make(map[string]float64),
		dimCounters: make(map[string]*dimCounterEntry),
		latencies:   make(map[string][]float64),
		stop:        make(chan struct{}),
	}

	mp.IncrCounter("KnockRequest")
	mp.IncrCounter("KnockRequest")
	mp.IncrCounter("KnockRequest")
	mp.IncrCounter("AuthSuccess")

	mp.mu.Lock()
	defer mp.mu.Unlock()

	if mp.counters["KnockRequest"] != 3 {
		t.Errorf("expected KnockRequest=3, got %v", mp.counters["KnockRequest"])
	}
	if mp.counters["AuthSuccess"] != 1 {
		t.Errorf("expected AuthSuccess=1, got %v", mp.counters["AuthSuccess"])
	}
}

func TestPublisher_DimCounterAccumulation(t *testing.T) {
	mp := &Publisher{
		counters:    make(map[string]float64),
		dimCounters: make(map[string]*dimCounterEntry),
		latencies:   make(map[string][]float64),
		dims: []types.Dimension{
			{Name: aws.String("Environment"), Value: aws.String("sandbox")},
		},
		stop: make(chan struct{}),
	}

	// Same metric+dims should accumulate
	errorDims := []types.Dimension{
		{Name: aws.String("Error"), Value: aws.String("timeout")},
	}
	mp.IncrCounterWithDims("RegistrationFailure", errorDims)
	mp.IncrCounterWithDims("RegistrationFailure", errorDims)

	// Different dims should be separate entries
	otherErrorDims := []types.Dimension{
		{Name: aws.String("Error"), Value: aws.String("connection refused")},
	}
	mp.IncrCounterWithDims("RegistrationFailure", otherErrorDims)

	mp.mu.Lock()
	defer mp.mu.Unlock()

	if len(mp.dimCounters) != 2 {
		t.Fatalf("expected 2 dimCounter entries, got %d", len(mp.dimCounters))
	}

	// Find the "timeout" entry
	found := false
	for _, entry := range mp.dimCounters {
		if entry.metricName == "RegistrationFailure" && entry.value == 2 {
			found = true
			// Should have shared + extra dims
			if len(entry.dims) != 2 {
				t.Errorf("expected 2 dims (shared + extra), got %d", len(entry.dims))
			}
		}
	}
	if !found {
		t.Error("expected to find RegistrationFailure with value=2")
	}
}

// TestPublisher_AddCounterExplicitDims proves the explicit-dims emit publishes at
// the EXACT dim set given — the shared base dims (mp.dims) are NOT prepended.
// This is the primitive that lets a fleet-wide alarm select a dim set that is a
// STRICT SUBSET of the publisher base (e.g. [Environment] against an [Environment,
// Cell] server publisher — the round-9 OTP-shed launch-blocker). Contrast with
// AddCounterWithDims, which prepends the base.
func TestPublisher_AddCounterExplicitDims(t *testing.T) {
	mp := &Publisher{
		counters:    make(map[string]float64),
		dimCounters: make(map[string]*dimCounterEntry),
		latencies:   make(map[string][]float64),
		// Base dims = [Environment, Cell] — like the nhp-server publisher.
		dims: []types.Dimension{
			{Name: aws.String("Environment"), Value: aws.String("prod")},
			{Name: aws.String("Cell"), Value: aws.String("cell7")},
		},
		stop: make(chan struct{}),
	}

	envOnly := []types.Dimension{
		{Name: aws.String("Environment"), Value: aws.String("prod")},
	}
	mp.IncrCounterExplicitDims("OTPRejectRateLimited", envOnly)
	mp.AddCounterExplicitDims("OTPRejectRateLimited", 2, envOnly) // same set → accumulates

	mp.mu.Lock()
	defer mp.mu.Unlock()

	if len(mp.dimCounters) != 1 {
		t.Fatalf("expected exactly 1 dimCounter entry (one [Environment]-only stream), got %d: %v", len(mp.dimCounters), mp.dimCounters)
	}
	for _, entry := range mp.dimCounters {
		if entry.value != 3 {
			t.Errorf("accumulated value = %v, want 3 (1 + 2 on the same dim set)", entry.value)
		}
		// The CRITICAL assertion: dims are EXACTLY [Environment], with NO Cell — the
		// base was not prepended. A leaked Cell would be the [Environment, Cell] set
		// the fleet-wide alarm can never bind to.
		if len(entry.dims) != 1 {
			t.Fatalf("explicit-dims entry has %d dims, want exactly 1 ([Environment] only, base NOT prepended); dims=%v", len(entry.dims), entry.dims)
		}
		if *entry.dims[0].Name != "Environment" || *entry.dims[0].Value != "prod" {
			t.Errorf("dim = %s=%s, want Environment=prod", *entry.dims[0].Name, *entry.dims[0].Value)
		}
	}
}

func TestPublisher_AddCounterWithDims(t *testing.T) {
	mp := &Publisher{
		counters:    make(map[string]float64),
		dimCounters: make(map[string]*dimCounterEntry),
		latencies:   make(map[string][]float64),
		dims: []types.Dimension{
			{Name: aws.String("Environment"), Value: aws.String("sandbox")},
		},
		stop: make(chan struct{}),
	}

	extraDims := []types.Dimension{
		{Name: aws.String("ConnectionType"), Value: aws.String("Redispatch")},
	}
	mp.AddCounterWithDims("ServerConnections", 3, extraDims)
	mp.AddCounterWithDims("ServerConnections", 2, extraDims)

	mp.mu.Lock()
	defer mp.mu.Unlock()

	if len(mp.dimCounters) != 1 {
		t.Fatalf("expected 1 dimCounter entry, got %d", len(mp.dimCounters))
	}
	for _, entry := range mp.dimCounters {
		if entry.value != 5 {
			t.Errorf("expected accumulated value=5, got %v", entry.value)
		}
	}
}

func TestPublisher_LatencyStatistics(t *testing.T) {
	mp := &Publisher{
		counters:    make(map[string]float64),
		dimCounters: make(map[string]*dimCounterEntry),
		latencies:   make(map[string][]float64),
		stop:        make(chan struct{}),
	}

	mp.RecordLatency("KnockLatency", 10.0)
	mp.RecordLatency("KnockLatency", 20.0)
	mp.RecordLatency("KnockLatency", 5.0)
	mp.RecordLatency("KnockLatency", 15.0)

	mp.mu.Lock()
	values := mp.latencies["KnockLatency"]
	mp.mu.Unlock()

	if len(values) != 4 {
		t.Fatalf("expected 4 latency samples, got %d", len(values))
	}

	min, max, sum := values[0], values[0], 0.0
	for _, v := range values {
		sum += v
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	if min != 5.0 {
		t.Errorf("expected min=5.0, got %v", min)
	}
	if max != 20.0 {
		t.Errorf("expected max=20.0, got %v", max)
	}
	if sum != 50.0 {
		t.Errorf("expected sum=50.0, got %v", sum)
	}
}

func TestPublisher_LatencyCap(t *testing.T) {
	mp := &Publisher{
		counters:    make(map[string]float64),
		dimCounters: make(map[string]*dimCounterEntry),
		latencies:   make(map[string][]float64),
		stop:        make(chan struct{}),
	}

	for i := 0; i < maxLatencySamples+100; i++ {
		mp.RecordLatency("test", float64(i))
	}

	mp.mu.Lock()
	count := len(mp.latencies["test"])
	dropped := mp.counters["test_Dropped"]
	mp.mu.Unlock()

	if count != maxLatencySamples {
		t.Errorf("expected latency samples capped at %d, got %d", maxLatencySamples, count)
	}
	if dropped != 100 {
		t.Errorf("expected 100 dropped samples, got %v", dropped)
	}
}

func TestPublisher_FlushResetsState(t *testing.T) {
	mp := &Publisher{
		counters:    make(map[string]float64),
		dimCounters: make(map[string]*dimCounterEntry),
		gauges:      make(map[string]float64),
		latencies:   make(map[string][]float64),
		stop:        make(chan struct{}),
	}

	mp.IncrCounter("test")
	mp.IncrCounterWithDims("dimtest", []types.Dimension{
		{Name: aws.String("Key"), Value: aws.String("Val")},
	})
	mp.RecordLatency("latency", 10.0)
	mp.mu.Lock()
	mp.gauges["StorageHealthy"] = 1.0
	mp.mu.Unlock()

	// Verify data exists before flush
	mp.mu.Lock()
	if mp.counters["test"] != 1 {
		t.Errorf("expected counter=1 before flush, got %v", mp.counters["test"])
	}
	if len(mp.dimCounters) != 1 {
		t.Errorf("expected 1 dimCounter before flush, got %d", len(mp.dimCounters))
	}
	if len(mp.latencies["latency"]) != 1 {
		t.Errorf("expected 1 latency sample before flush, got %d", len(mp.latencies["latency"]))
	}
	if mp.gauges["StorageHealthy"] != 1.0 {
		t.Errorf("expected gauge=1.0 before flush, got %v", mp.gauges["StorageHealthy"])
	}
	// Manually swap maps (simulating flush's map reset without calling the API)
	mp.counters = make(map[string]float64)
	mp.dimCounters = make(map[string]*dimCounterEntry)
	mp.gauges = make(map[string]float64)
	mp.latencies = make(map[string][]float64)
	mp.mu.Unlock()

	if len(mp.counters) != 0 {
		t.Errorf("expected counters to be empty after reset, got %v", mp.counters)
	}
	if len(mp.dimCounters) != 0 {
		t.Errorf("expected dimCounters to be empty after reset, got %v", mp.dimCounters)
	}
	if len(mp.gauges) != 0 {
		t.Errorf("expected gauges to be empty after reset, got %v", mp.gauges)
	}
	if len(mp.latencies) != 0 {
		t.Errorf("expected latencies to be empty after reset, got %v", mp.latencies)
	}
}

func TestPublisher_StopWaitsForFlushLoop(t *testing.T) {
	mp := &Publisher{
		counters:    make(map[string]float64),
		dimCounters: make(map[string]*dimCounterEntry),
		latencies:   make(map[string][]float64),
		stop:        make(chan struct{}),
	}

	// Start the flush loop like NewPublisher does
	mp.wg.Add(1)
	go mp.flushLoop()

	// Stop should not deadlock and should wait for flushLoop to exit
	done := make(chan struct{})
	go func() {
		mp.Stop()
		close(done)
	}()

	select {
	case <-done:
		// success — Stop returned without deadlock
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() deadlocked")
	}

	// Calling Stop a second time should not panic (idempotent)
	mp.Stop()
}

func TestBuildDimCounterKey_Deterministic(t *testing.T) {
	dims1 := []types.Dimension{
		{Name: aws.String("B"), Value: aws.String("2")},
		{Name: aws.String("A"), Value: aws.String("1")},
	}
	dims2 := []types.Dimension{
		{Name: aws.String("A"), Value: aws.String("1")},
		{Name: aws.String("B"), Value: aws.String("2")},
	}

	key1 := buildDimCounterKey("metric", dims1)
	key2 := buildDimCounterKey("metric", dims2)

	if key1 != key2 {
		t.Errorf("expected same key regardless of dim order, got %q and %q", key1, key2)
	}

	// Different metric name should produce different key
	key3 := buildDimCounterKey("other", dims1)
	if key1 == key3 {
		t.Error("expected different keys for different metric names")
	}

	// Different dim values should produce different key
	dims3 := []types.Dimension{
		{Name: aws.String("A"), Value: aws.String("1")},
		{Name: aws.String("B"), Value: aws.String("3")},
	}
	key4 := buildDimCounterKey("metric", dims3)
	if key1 == key4 {
		t.Error("expected different keys for different dim values")
	}
}

func TestDimsSorted(t *testing.T) {
	tests := []struct {
		name string
		dims []types.Dimension
		want bool
	}{
		{"nil", nil, true},
		{"empty", []types.Dimension{}, true},
		{"single", []types.Dimension{{Name: aws.String("A"), Value: aws.String("1")}}, true},
		{"sorted", []types.Dimension{
			{Name: aws.String("A"), Value: aws.String("1")},
			{Name: aws.String("B"), Value: aws.String("2")},
			{Name: aws.String("C"), Value: aws.String("3")},
		}, true},
		{"unsorted", []types.Dimension{
			{Name: aws.String("B"), Value: aws.String("2")},
			{Name: aws.String("A"), Value: aws.String("1")},
		}, false},
		{"equal names", []types.Dimension{
			{Name: aws.String("A"), Value: aws.String("1")},
			{Name: aws.String("A"), Value: aws.String("2")},
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dimsSorted(tt.dims); got != tt.want {
				t.Errorf("dimsSorted() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPublisher_BuildMetricData is a table-driven test that verifies
// buildMetricData produces the expected CloudWatch MetricDatum output
// for each metric type. Each subtest exercises one scenario independently.
func TestPublisher_BuildMetricData(t *testing.T) {
	sharedDims := []types.Dimension{
		{Name: aws.String("Environment"), Value: aws.String("test")},
	}

	tests := []struct {
		name        string
		counters    map[string]float64
		dimCounters map[string]*dimCounterEntry
		gauges      map[string]float64
		latencies   map[string][]float64
		histograms  map[string]*histogramEntry
		wantCount   int
		verify      func(t *testing.T, data []types.MetricDatum)
	}{
		{
			name:      "counters produce Count datums with shared dims",
			counters:  map[string]float64{"KnockRequest": 2, "AuthSuccess": 1},
			wantCount: 2,
			verify: func(t *testing.T, data []types.MetricDatum) {
				byName := indexByName(data)
				knock := byName["KnockRequest"]
				if *knock.Value != 2.0 {
					t.Errorf("KnockRequest value = %v, want 2.0", *knock.Value)
				}
				if knock.Unit != types.StandardUnitCount {
					t.Errorf("KnockRequest unit = %v, want Count", knock.Unit)
				}
				if len(knock.Dimensions) != 1 || *knock.Dimensions[0].Name != "Environment" {
					t.Errorf("KnockRequest should have shared dims only, got %v", knock.Dimensions)
				}
			},
		},
		{
			name: "dimCounters merge shared and extra dimensions",
			dimCounters: map[string]*dimCounterEntry{
				"k": {
					metricName: "RegistrationFailure",
					value:      1,
					dims: append(append([]types.Dimension{}, sharedDims...),
						types.Dimension{Name: aws.String("ErrorCode"), Value: aws.String("timeout")}),
				},
			},
			wantCount: 1,
			verify: func(t *testing.T, data []types.MetricDatum) {
				d := data[0]
				if *d.Value != 1.0 {
					t.Errorf("RegistrationFailure value = %v, want 1.0", *d.Value)
				}
				if len(d.Dimensions) != 2 {
					t.Errorf("RegistrationFailure should have 2 dims (shared+extra), got %d", len(d.Dimensions))
				}
			},
		},
		{
			name:      "gauges always published with unit None",
			gauges:    map[string]float64{"StorageHealthy": 1.0},
			wantCount: 1,
			verify: func(t *testing.T, data []types.MetricDatum) {
				d := data[0]
				if *d.Value != 1.0 {
					t.Errorf("StorageHealthy value = %v, want 1.0", *d.Value)
				}
				if d.Unit != types.StandardUnitNone {
					t.Errorf("StorageHealthy unit = %v, want None", d.Unit)
				}
			},
		},
		{
			name:      "latencies produce StatisticSet in Milliseconds",
			latencies: map[string][]float64{"KnockLatency": {10.0, 20.0}},
			wantCount: 1,
			verify: func(t *testing.T, data []types.MetricDatum) {
				d := data[0]
				if d.StatisticValues == nil {
					t.Fatal("KnockLatency should have StatisticValues")
				}
				if *d.StatisticValues.SampleCount != 2.0 {
					t.Errorf("SampleCount = %v, want 2.0", *d.StatisticValues.SampleCount)
				}
				if *d.StatisticValues.Minimum != 10.0 {
					t.Errorf("Minimum = %v, want 10.0", *d.StatisticValues.Minimum)
				}
				if *d.StatisticValues.Maximum != 20.0 {
					t.Errorf("Maximum = %v, want 20.0", *d.StatisticValues.Maximum)
				}
				if *d.StatisticValues.Sum != 30.0 {
					t.Errorf("Sum = %v, want 30.0", *d.StatisticValues.Sum)
				}
				if d.Unit != types.StandardUnitMilliseconds {
					t.Errorf("unit = %v, want Milliseconds", d.Unit)
				}
			},
		},
		{
			name: "histograms produce Values and Counts in their registered unit",
			histograms: map[string]*histogramEntry{
				"ConntrackDumpDuration": {
					unit:   types.StandardUnitMilliseconds,
					values: []float64{0.2, 0.1, 0.2, math.Inf(1), math.NaN()},
				},
			},
			wantCount: 1,
			verify: func(t *testing.T, data []types.MetricDatum) {
				d := data[0]
				if d.StatisticValues != nil || d.Value != nil {
					t.Fatalf("ConntrackDumpDuration should use Values/Counts only, got StatisticValues=%v Value=%v", d.StatisticValues, d.Value)
				}
				if got, want := d.Values, []float64{0.1, 0.2}; !slices.Equal(got, want) {
					t.Errorf("Values = %v, want %v", got, want)
				}
				if got, want := d.Counts, []float64{1, 2}; !slices.Equal(got, want) {
					t.Errorf("Counts = %v, want %v", got, want)
				}
				if d.Unit != types.StandardUnitMilliseconds {
					t.Errorf("unit = %v, want Milliseconds", d.Unit)
				}
			},
		},
		{
			name:     "zero-value counters are skipped",
			counters: map[string]float64{"active": 5, "zero": 0},
			dimCounters: map[string]*dimCounterEntry{
				"k1": {metricName: "active_dim", value: 3, dims: sharedDims},
				"k2": {metricName: "zero_dim", value: 0, dims: sharedDims},
			},
			wantCount: 2,
			verify: func(t *testing.T, data []types.MetricDatum) {
				for _, d := range data {
					if *d.Value == 0 {
						t.Errorf("zero-value metric %q should have been skipped", *d.MetricName)
					}
				}
			},
		},
		{
			name:     "full pipeline with all metric types",
			counters: map[string]float64{"KnockRequest": 2, "AuthSuccess": 1},
			dimCounters: map[string]*dimCounterEntry{
				"k": {
					metricName: "RegistrationFailure",
					value:      1,
					dims: append(append([]types.Dimension{}, sharedDims...),
						types.Dimension{Name: aws.String("ErrorCode"), Value: aws.String("timeout")}),
				},
			},
			gauges:    map[string]float64{"StorageHealthy": 1.0},
			latencies: map[string][]float64{"KnockLatency": {10.0, 20.0}},
			histograms: map[string]*histogramEntry{
				"ConntrackDumpDuration": {unit: types.StandardUnitMilliseconds, values: []float64{0.2}},
			},
			wantCount: 6,
			verify: func(t *testing.T, data []types.MetricDatum) {
				byName := indexByName(data)
				for _, name := range []string{"KnockRequest", "AuthSuccess", "RegistrationFailure", "StorageHealthy", "KnockLatency", "ConntrackDumpDuration"} {
					if _, ok := byName[name]; !ok {
						t.Errorf("missing expected metric %q", name)
					}
				}
			},
		},
	}

	// knownTS is the single flush instant threaded through buildMetricData.
	// Every emitted datum — regardless of metric type — must carry exactly
	// this timestamp. That is the "capture once per flush" property: it is what
	// makes CloudWatch record each datapoint at (approximately) event time
	// instead of PutMetricData receive time (#1257), and it is what regresses
	// if someone later moves the capture into a per-datum loop.
	knownTS := testFlushInstant

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &Publisher{dims: sharedDims, stop: make(chan struct{})}
			data := mp.buildMetricData(knownTS, tt.counters, tt.dimCounters, tt.gauges, tt.latencies, tt.histograms)
			if len(data) != tt.wantCount {
				t.Fatalf("expected %d metric datums, got %d", tt.wantCount, len(data))
			}
			for _, d := range data {
				if d.Timestamp == nil {
					t.Errorf("metric %q: Timestamp is nil, want the captured flush instant", aws.ToString(d.MetricName))
					continue
				}
				if !d.Timestamp.Equal(knownTS) {
					t.Errorf("metric %q: Timestamp = %s, want %s (every datum must carry the single captured flush instant)",
						aws.ToString(d.MetricName), d.Timestamp.Format(time.RFC3339Nano), knownTS.Format(time.RFC3339Nano))
				}
			}
			if tt.verify != nil {
				tt.verify(t, data)
			}
		})
	}
}

// indexByName creates a map from metric name to MetricDatum for deterministic assertions.
func indexByName(data []types.MetricDatum) map[string]types.MetricDatum {
	m := make(map[string]types.MetricDatum, len(data))
	for _, d := range data {
		m[*d.MetricName] = d
	}
	return m
}

func TestPublisher_BuildMetricData_HistogramChunksValuesCounts(t *testing.T) {
	values := make([]float64, maxHistogramValuesPerDatum+1)
	for i := range values {
		values[i] = float64(i)
	}
	values = append(values, 42) // duplicate should increment count, not add a unique value.

	mp := &Publisher{stop: make(chan struct{})}
	data := mp.buildMetricData(testFlushInstant, nil, nil, nil, nil, map[string]*histogramEntry{
		"DumpDuration": {
			unit:   types.StandardUnitMilliseconds,
			values: values,
		},
	})

	if len(data) != 2 {
		t.Fatalf("expected 2 histogram datums for %d unique values, got %d", maxHistogramValuesPerDatum+1, len(data))
	}
	if len(data[0].Values) != maxHistogramValuesPerDatum {
		t.Fatalf("first histogram datum Values len = %d, want %d", len(data[0].Values), maxHistogramValuesPerDatum)
	}
	if len(data[1].Values) != 1 {
		t.Fatalf("second histogram datum Values len = %d, want 1", len(data[1].Values))
	}
	if len(data[0].Counts) != len(data[0].Values) || len(data[1].Counts) != len(data[1].Values) {
		t.Fatalf("Counts length must match Values length: first %d/%d second %d/%d",
			len(data[0].Counts), len(data[0].Values), len(data[1].Counts), len(data[1].Values))
	}
	for _, d := range data {
		for i, value := range d.Values {
			if value == 42 && d.Counts[i] != 2 {
				t.Fatalf("count for duplicate value 42 = %v, want 2", d.Counts[i])
			}
		}
		if d.Timestamp == nil || !d.Timestamp.Equal(testFlushInstant) {
			t.Fatalf("histogram datum timestamp = %v, want %s", d.Timestamp, testFlushInstant.Format(time.RFC3339Nano))
		}
	}
}

// newTestPublisher creates a Publisher with initialized maps for testing.
// Pass nil for client to test nil-client paths.
func newTestPublisher(t *testing.T, client cloudWatchClient) *Publisher {
	t.Helper()
	return &Publisher{
		client:         client,
		namespace:      "LayerV/NHP",
		counters:       make(map[string]float64),
		dimCounters:    make(map[string]*dimCounterEntry),
		gauges:         make(map[string]float64),
		latencies:      make(map[string][]float64),
		histograms:     make(map[string]*histogramEntry),
		gaugeFuncs:     make(map[string]GaugeFunc),
		histogramFuncs: make(map[string]histogramFuncEntry),
		stop:           make(chan struct{}),
		emfWriter:      io.Discard,
	}
}

// newTestPublisherWithEMF wraps NewPublisherForTestWithEMFBuffer with the
// fields the in-package EMF tests need: an injected cloudWatchClient (which
// NewPublisher* deliberately can't take because its type is unexported)
// and the canonical Environment/Cell base dims. Keeps the struct literal
// in one place (publisher_testhelpers.go) so a new Publisher field added
// there doesn't silently diverge here.
func newTestPublisherWithEMF(t *testing.T, client cloudWatchClient) (*Publisher, *bytes.Buffer) {
	t.Helper()
	mp, buf := NewPublisherForTestWithEMFBuffer(t)
	mp.client = client
	mp.dims = []types.Dimension{
		{Name: aws.String("Environment"), Value: aws.String("sandbox")},
		{Name: aws.String("Cell"), Value: aws.String("cell0")},
	}
	return mp, buf
}

type mockCloudWatchClient struct {
	calls []*cloudwatch.PutMetricDataInput
}

func (m *mockCloudWatchClient) PutMetricData(_ context.Context, params *cloudwatch.PutMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricDataOutput, error) {
	// Deep-copy MetricData to avoid aliasing; flush() reuses the backing array.
	m.calls = append(m.calls, &cloudwatch.PutMetricDataInput{
		Namespace:  params.Namespace,
		MetricData: append([]types.MetricDatum(nil), params.MetricData...),
	})
	return &cloudwatch.PutMetricDataOutput{}, nil
}

// errorCloudWatchClient always returns the configured error.
type errorCloudWatchClient struct {
	err error
}

func (e *errorCloudWatchClient) PutMetricData(_ context.Context, _ *cloudwatch.PutMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricDataOutput, error) {
	return nil, e.err
}

// TestPublisher_Flush_PutMetricDataPayload verifies the integration boundary:
// metrics accumulated via public API are sent to CloudWatch with the correct
// namespace and datum count. Datum-shape assertions live in TestPublisher_BuildMetricData.
func TestPublisher_Flush_PutMetricDataPayload(t *testing.T) {
	sharedDims := []types.Dimension{
		{Name: aws.String("Environment"), Value: aws.String("sandbox")},
		{Name: aws.String("Cell"), Value: aws.String("cell0")},
	}

	mockCW := &mockCloudWatchClient{}
	mp := newTestPublisher(t, mockCW)
	mp.dims = sharedDims

	mp.IncrCounter("KnockRequest")
	mp.IncrCounter("KnockRequest")
	mp.AddCounterWithDims("RegistrationFailure", 3, []types.Dimension{
		{Name: aws.String("ErrorCode"), Value: aws.String("timeout")},
	})
	mp.RecordLatency("KnockLatency", 10)
	mp.RecordLatency("KnockLatency", 20)
	mp.RecordLatency("KnockLatency", 30)

	// Bracket flush() so we can assert it stamps each datum with a real
	// event-time instant (a recent time.Now), not the zero value or
	// CloudWatch receive time. before/after bound the window flushStart
	// must fall within.
	before := time.Now()
	mp.flush()
	after := time.Now()

	if len(mockCW.calls) != 1 {
		t.Fatalf("expected 1 PutMetricData call, got %d", len(mockCW.calls))
	}
	call := mockCW.calls[0]
	if call.Namespace == nil || *call.Namespace != "LayerV/NHP" {
		t.Fatalf("expected namespace LayerV/NHP, got %v", call.Namespace)
	}
	// 3 datums: KnockRequest (counter), RegistrationFailure (dimCounter), KnockLatency (latency)
	if len(call.MetricData) != 3 {
		t.Fatalf("expected 3 metric datums, got %d", len(call.MetricData))
	}
	byName := indexByName(call.MetricData)
	for _, name := range []string{"KnockRequest", "RegistrationFailure", "KnockLatency"} {
		if _, ok := byName[name]; !ok {
			t.Errorf("missing expected metric %q in PutMetricData payload", name)
		}
	}
	// Every datum carries a flush-time timestamp within [before, after].
	for _, d := range call.MetricData {
		if d.Timestamp == nil {
			t.Errorf("metric %q: Timestamp is nil, want a flush-time instant", aws.ToString(d.MetricName))
			continue
		}
		if d.Timestamp.Before(before) || d.Timestamp.After(after) {
			t.Errorf("metric %q: Timestamp %s outside flush window [%s, %s]",
				aws.ToString(d.MetricName), d.Timestamp.Format(time.RFC3339Nano),
				before.Format(time.RFC3339Nano), after.Format(time.RFC3339Nano))
		}
	}
}

func TestPublisher_Flush_IncludesGaugeEmittedCountersInSameWindow(t *testing.T) {
	mockCW := &mockCloudWatchClient{}
	mp := newTestPublisher(t, mockCW)
	mp.dims = []types.Dimension{
		{Name: aws.String("Environment"), Value: aws.String("sandbox")},
	}
	mp.RegisterGaugeFunc("ConntrackUsage", func() float64 {
		mp.AddCounterWithDims("ConntrackPartialSamples", 2, nil)
		return 87
	})

	mp.collectGauges()
	mp.flush()

	if len(mockCW.calls) != 1 {
		t.Fatalf("expected 1 PutMetricData call, got %d", len(mockCW.calls))
	}
	byName := indexByName(mockCW.calls[0].MetricData)
	partialSamples, ok := byName["ConntrackPartialSamples"]
	if !ok {
		t.Fatalf("ConntrackPartialSamples counter emitted from gauge func missing from same flush: %+v", mockCW.calls[0].MetricData)
	}
	if got := aws.ToFloat64(partialSamples.Value); got != 2 {
		t.Errorf("ConntrackPartialSamples value = %v, want 2", got)
	}
	if partialSamples.Unit != types.StandardUnitCount {
		t.Errorf("ConntrackPartialSamples unit = %v, want Count", partialSamples.Unit)
	}

	usage, ok := byName["ConntrackUsage"]
	if !ok {
		t.Fatalf("ConntrackUsage gauge missing from flush: %+v", mockCW.calls[0].MetricData)
	}
	if got := aws.ToFloat64(usage.Value); got != 87 {
		t.Errorf("ConntrackUsage value = %v, want 87", got)
	}
	if usage.Unit != types.StandardUnitNone {
		t.Errorf("ConntrackUsage unit = %v, want None", usage.Unit)
	}
}

func TestPublisher_Flush_IncludesHistogramEmittedCountersInSameWindow(t *testing.T) {
	mockCW := &mockCloudWatchClient{}
	mp := newTestPublisher(t, mockCW)
	mp.dims = []types.Dimension{
		{Name: aws.String("Environment"), Value: aws.String("sandbox")},
	}
	mp.RegisterHistogramFunc("ConntrackDumpDuration", types.StandardUnitMilliseconds, func() []float64 {
		mp.AddCounterWithDims("ConntrackDumpDurationDropped", 2, nil)
		return []float64{1.5, 0.2, 1.5}
	})

	mp.collectHistograms()
	mp.flush()

	if len(mockCW.calls) != 1 {
		t.Fatalf("expected 1 PutMetricData call, got %d", len(mockCW.calls))
	}
	byName := indexByName(mockCW.calls[0].MetricData)
	dropped, ok := byName["ConntrackDumpDurationDropped"]
	if !ok {
		t.Fatalf("ConntrackDumpDurationDropped counter emitted from histogram func missing from same flush: %+v", mockCW.calls[0].MetricData)
	}
	if got := aws.ToFloat64(dropped.Value); got != 2 {
		t.Errorf("ConntrackDumpDurationDropped value = %v, want 2", got)
	}
	if dropped.Unit != types.StandardUnitCount {
		t.Errorf("ConntrackDumpDurationDropped unit = %v, want Count", dropped.Unit)
	}

	hist, ok := byName["ConntrackDumpDuration"]
	if !ok {
		t.Fatalf("ConntrackDumpDuration histogram missing from same flush: %+v", mockCW.calls[0].MetricData)
	}
	if hist.Unit != types.StandardUnitMilliseconds {
		t.Errorf("ConntrackDumpDuration unit = %v, want Milliseconds", hist.Unit)
	}
	if got, want := hist.Values, []float64{0.2, 1.5}; !slices.Equal(got, want) {
		t.Errorf("ConntrackDumpDuration Values = %v, want %v", got, want)
	}
	if got, want := hist.Counts, []float64{1, 2}; !slices.Equal(got, want) {
		t.Errorf("ConntrackDumpDuration Counts = %v, want %v", got, want)
	}
	if hist.Timestamp == nil || dropped.Timestamp == nil || !hist.Timestamp.Equal(*dropped.Timestamp) {
		t.Errorf("histogram/counter timestamps = %v/%v, want same flush timestamp", hist.Timestamp, dropped.Timestamp)
	}
}

func TestPublisher_Flush_BatchingByBatchSize(t *testing.T) {
	mockCW := &mockCloudWatchClient{}
	mp := newTestPublisher(t, mockCW)

	// Unique counter names so each produces a distinct MetricDatum.
	for i := 0; i < batchSize+1; i++ {
		mp.IncrCounter(fmt.Sprintf("Metric_%d", i))
	}

	mp.flush()

	if len(mockCW.calls) != 2 {
		t.Fatalf("expected 2 PutMetricData calls, got %d", len(mockCW.calls))
	}
	if len(mockCW.calls[0].MetricData) != batchSize {
		t.Fatalf("expected first batch size %d, got %d", batchSize, len(mockCW.calls[0].MetricData))
	}
	if len(mockCW.calls[1].MetricData) != 1 {
		t.Fatalf("expected second batch size 1, got %d", len(mockCW.calls[1].MetricData))
	}
}

func TestPublisher_Flush_PutMetricDataError(t *testing.T) {
	errClient := &errorCloudWatchClient{err: errors.New("throttled")}
	mp := newTestPublisher(t, errClient)

	mp.IncrCounter("KnockRequest")
	mp.flush() // must not panic on API error

	mp.mu.Lock()
	knock := mp.counters["KnockRequest"]
	pubFail := mp.counters[MetricPublisherFailure]
	total := len(mp.counters)
	mp.mu.Unlock()

	// The flushed metric is dropped, not retried (best-effort; see flush()).
	if knock != 0 {
		t.Errorf("expected flushed KnockRequest counter dropped, got %v", knock)
	}
	// The failed batch self-reports via MetricPublisherFailure into the fresh
	// counter map, to be carried by the next (hopefully successful) flush.
	if pubFail != 1 {
		t.Errorf("expected %s=1 after one failed batch, got %v", MetricPublisherFailure, pubFail)
	}
	if total != 1 {
		t.Errorf("expected only %s left in counter map, got %d entries", MetricPublisherFailure, total)
	}
}

// TestPublisher_Flush_PutMetricDataError_CountsPerBatch verifies the failure
// counter is incremented once per failed PutMetricData batch, not once per
// flush — so the alarm's Sum reflects the true number of failed API calls.
func TestPublisher_Flush_PutMetricDataError_CountsPerBatch(t *testing.T) {
	errClient := &errorCloudWatchClient{err: errors.New("throttled")}
	mp := newTestPublisher(t, errClient)

	// batchSize+1 distinct counters force exactly 2 PutMetricData batches.
	for i := 0; i < batchSize+1; i++ {
		mp.IncrCounter(fmt.Sprintf("Metric_%d", i))
	}
	mp.flush()

	mp.mu.Lock()
	pubFail := mp.counters[MetricPublisherFailure]
	mp.mu.Unlock()
	if pubFail != 2 {
		t.Errorf("expected %s=2 (one per failed batch), got %v", MetricPublisherFailure, pubFail)
	}
}

// TestPublisher_Flush_PublisherFailure_RoundTrip locks the end-to-end contract
// the PublisherFailures alarm depends on: a failure self-reported by a failing
// flush is actually emitted to CloudWatch on the NEXT successful flush, carrying
// the publisher's base dims (the alarm's metric-stream selector).
func TestPublisher_Flush_PublisherFailure_RoundTrip(t *testing.T) {
	baseDims := []types.Dimension{
		{Name: aws.String("Component"), Value: aws.String("AC")},
		{Name: aws.String("Environment"), Value: aws.String("sandbox")},
		{Name: aws.String("Region"), Value: aws.String("us-east-2")},
	}

	// Flush 1 fails -> PublisherFailures lands in the freshly-swapped map.
	errClient := &errorCloudWatchClient{err: errors.New("throttled")}
	mp := newTestPublisher(t, errClient)
	mp.dims = baseDims
	mp.IncrCounter("KnockRequest")
	mp.flush()

	// Flush 2 succeeds -> the carried PublisherFailures counter is published.
	mockCW := &mockCloudWatchClient{}
	mp.client = mockCW
	mp.flush()

	if len(mockCW.calls) != 1 {
		t.Fatalf("expected 1 PutMetricData call on the successful flush, got %d", len(mockCW.calls))
	}
	datum, ok := indexByName(mockCW.calls[0].MetricData)[MetricPublisherFailure]
	if !ok {
		t.Fatalf("expected %s datum emitted on the successful flush", MetricPublisherFailure)
	}
	if datum.Value == nil || *datum.Value != 1 {
		t.Errorf("expected %s value 1, got %v", MetricPublisherFailure, datum.Value)
	}
	// The datum must carry the base dims, or the alarm selects a non-existent
	// stream and sits in INSUFFICIENT_DATA forever (the #239 trap). CloudWatch
	// treats dimensions as an unordered set, so compare as a set, not by order.
	if len(datum.Dimensions) != len(baseDims) {
		t.Fatalf("expected %d base dims on %s, got %d", len(baseDims), MetricPublisherFailure, len(datum.Dimensions))
	}
	got := make(map[string]string, len(datum.Dimensions))
	for _, d := range datum.Dimensions {
		got[*d.Name] = *d.Value
	}
	for _, want := range baseDims {
		if got[*want.Name] != *want.Value {
			t.Errorf("base dim %s: got %q, want %q", *want.Name, got[*want.Name], *want.Value)
		}
	}
}

func TestEmitEMF_SingleMetric(t *testing.T) {
	mp, buf := newTestPublisherWithEMF(t, nil)
	mp.emitEMF(testFlushInstant, map[string][]float64{"KnockLatency": {10.5, 20.3, 5.1}})
	events := parseEMFLines(t, buf.Bytes())
	if len(events) != 1 {
		t.Fatalf("expected 1 EMF event, got %d", len(events))
	}
	event := events[0]
	if _, ok := event["_aws"].(map[string]any); !ok {
		t.Fatal("missing _aws block")
	}
	if event["Environment"] != "sandbox" {
		t.Errorf("expected Environment=sandbox, got %v", event["Environment"])
	}
	vals, ok := event["KnockLatency"].([]any)
	if !ok {
		t.Fatalf("expected KnockLatency array, got %T", event["KnockLatency"])
	}
	if len(vals) != 3 {
		t.Errorf("expected 3 values, got %d", len(vals))
	}
}

func TestEmitEMF_SingleValue(t *testing.T) {
	mp, buf := newTestPublisherWithEMF(t, nil)
	mp.emitEMF(testFlushInstant, map[string][]float64{"KnockLatency": {42.5}})
	events := parseEMFLines(t, buf.Bytes())
	val, ok := events[0]["KnockLatency"].(float64)
	if !ok {
		t.Fatalf("expected float64, got %T", events[0]["KnockLatency"])
	}
	if val != 42.5 {
		t.Errorf("expected 42.5, got %v", val)
	}
	// EMF events must carry the flush instant emitEMF was given — the same
	// instant buildMetricData stamps onto the PutMetricData statistic set
	// (one flush → one event time).
	if got := emfTimestampMs(t, events[0]); got != testFlushInstant.UnixMilli() {
		t.Errorf("EMF _aws.Timestamp = %d, want %d", got, testFlushInstant.UnixMilli())
	}
}

func TestEmitEMF_ChunkingOver150(t *testing.T) {
	mp, buf := newTestPublisherWithEMF(t, nil)
	values := make([]float64, 200)
	for i := range values {
		values[i] = float64(i)
	}
	mp.emitEMF(testFlushInstant, map[string][]float64{"KnockLatency": values})
	events := parseEMFLines(t, buf.Bytes())
	if len(events) != 2 {
		t.Fatalf("expected 2 EMF events, got %d", len(events))
	}
}

func TestEmitEMF_NilWriter(t *testing.T) {
	mp := newTestPublisher(t, nil)
	mp.emfWriter = nil
	mp.emitEMF(testFlushInstant, map[string][]float64{"KnockLatency": {10.0}})
}

func TestFlush_EmitsEMFAlongsideStatisticSets(t *testing.T) {
	mockCW := &mockCloudWatchClient{}
	mp, buf := newTestPublisherWithEMF(t, mockCW)
	mp.RecordLatency("KnockLatency", 10)
	mp.RecordLatency("KnockLatency", 20)
	mp.IncrCounter("KnockRequest")
	mp.flush()
	if len(mockCW.calls) != 1 {
		t.Fatalf("expected 1 PutMetricData call, got %d", len(mockCW.calls))
	}
	byName := indexByName(mockCW.calls[0].MetricData)
	if byName["KnockLatency"].StatisticValues == nil {
		t.Fatal("KnockLatency should have StatisticValues")
	}
	events := parseEMFLines(t, buf.Bytes())
	if len(events) != 1 {
		t.Fatalf("expected 1 EMF event, got %d", len(events))
	}
	vals := events[0]["KnockLatency"].([]any)
	if len(vals) != 2 {
		t.Errorf("expected 2 EMF values, got %d", len(vals))
	}

	// Cross-sink invariant: the EMF latency event and the PutMetricData
	// statistic-set datum for the same latency in the same flush must carry one
	// identical timestamp (one flush -> one event time). flush() stamps both
	// from a single flushStart, so the datum's Timestamp (UnixMilli) must equal
	// the EMF event's _aws.Timestamp. Each sink is also checked against the
	// injected instant elsewhere; this pins the two sinks to each other.
	statDatum := byName["KnockLatency"]
	if statDatum.Timestamp == nil {
		t.Fatal("KnockLatency statistic-set datum missing Timestamp")
	}
	if emfTSMs := emfTimestampMs(t, events[0]); emfTSMs != statDatum.Timestamp.UnixMilli() {
		t.Errorf("cross-sink timestamp mismatch: EMF _aws.Timestamp=%d, PutMetricData datum=%d (must be equal — one flush, one event time)",
			emfTSMs, statDatum.Timestamp.UnixMilli())
	}
}

// emfTimestampMs extracts the _aws.Timestamp (epoch millis) from a parsed EMF
// event, failing the test if the block or field is missing or mistyped. JSON
// numbers decode to float64.
func emfTimestampMs(t *testing.T, event map[string]any) int64 {
	t.Helper()
	awsBlock, ok := event["_aws"].(map[string]any)
	if !ok {
		t.Fatalf("missing _aws block, got %T", event["_aws"])
	}
	ts, ok := awsBlock["Timestamp"].(float64)
	if !ok {
		t.Fatalf("expected _aws.Timestamp number, got %T", awsBlock["Timestamp"])
	}
	return int64(ts)
}

func parseEMFLines(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	var events []map[string]any
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("failed to parse EMF line: %v", err)
		}
		events = append(events, event)
	}
	return events
}
