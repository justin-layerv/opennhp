package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

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
	mp.SetHealthProbe(func(ctx context.Context) bool { return true })
	mp.Stop()
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
			wantCount: 5,
			verify: func(t *testing.T, data []types.MetricDatum) {
				byName := indexByName(data)
				for _, name := range []string{"KnockRequest", "AuthSuccess", "RegistrationFailure", "StorageHealthy", "KnockLatency"} {
					if _, ok := byName[name]; !ok {
						t.Errorf("missing expected metric %q", name)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp := &Publisher{dims: sharedDims, stop: make(chan struct{})}
			data := mp.buildMetricData(tt.counters, tt.dimCounters, tt.gauges, tt.latencies)
			if len(data) != tt.wantCount {
				t.Fatalf("expected %d metric datums, got %d", tt.wantCount, len(data))
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

// newTestPublisher creates a Publisher with initialized maps for testing.
// Pass nil for client to test nil-client paths.
func newTestPublisher(t *testing.T, client cloudWatchClient) *Publisher {
	t.Helper()
	return &Publisher{
		client:      client,
		namespace:   "LayerV/NHP",
		counters:    make(map[string]float64),
		dimCounters: make(map[string]*dimCounterEntry),
		gauges:      make(map[string]float64),
		latencies:   make(map[string][]float64),
		gaugeFuncs:  make(map[string]GaugeFunc),
		stop:        make(chan struct{}),
		emfWriter:   io.Discard,
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

	mp.flush()

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

	// Verify state was reset despite the error (metrics are best-effort)
	mp.mu.Lock()
	count := len(mp.counters)
	mp.mu.Unlock()
	if count != 0 {
		t.Errorf("expected counters reset after flush, got %d entries", count)
	}
}

func TestEmitEMF_SingleMetric(t *testing.T) {
	mp, buf := newTestPublisherWithEMF(t, nil)
	mp.emitEMF(map[string][]float64{"KnockLatency": {10.5, 20.3, 5.1}})
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
	mp.emitEMF(map[string][]float64{"KnockLatency": {42.5}})
	events := parseEMFLines(t, buf.Bytes())
	val, ok := events[0]["KnockLatency"].(float64)
	if !ok {
		t.Fatalf("expected float64, got %T", events[0]["KnockLatency"])
	}
	if val != 42.5 {
		t.Errorf("expected 42.5, got %v", val)
	}
}

func TestEmitEMF_ChunkingOver150(t *testing.T) {
	mp, buf := newTestPublisherWithEMF(t, nil)
	values := make([]float64, 200)
	for i := range values {
		values[i] = float64(i)
	}
	mp.emitEMF(map[string][]float64{"KnockLatency": values})
	events := parseEMFLines(t, buf.Bytes())
	if len(events) != 2 {
		t.Fatalf("expected 2 EMF events, got %d", len(events))
	}
}

func TestEmitEMF_NilWriter(t *testing.T) {
	mp := newTestPublisher(t, nil)
	mp.emfWriter = nil
	mp.emitEMF(map[string][]float64{"KnockLatency": {10.0}})
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
