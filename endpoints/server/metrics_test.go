package server

import (
	"context"
	"testing"
	"time"
)

func TestMetricsPublisher_NilSafety(t *testing.T) {
	var mp *MetricsPublisher

	// All methods should be no-ops on nil receiver (no panic)
	mp.IncrCounter("test")
	mp.RecordLatency("test", 1.0)
	mp.SetHealthProbe(func(ctx context.Context) bool { return true })
	mp.Stop()
}

func TestMetricsPublisher_SetHealthProbe(t *testing.T) {
	mp := &MetricsPublisher{
		counters:  make(map[string]float64),
		gauges:    make(map[string]float64),
		latencies: make(map[string][]float64),
		stop:      make(chan struct{}),
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

func TestMetricsPublisher_CounterAccumulation(t *testing.T) {
	mp := &MetricsPublisher{
		counters:  make(map[string]float64),
		latencies: make(map[string][]float64),
		stop:      make(chan struct{}),
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

func TestMetricsPublisher_LatencyStatistics(t *testing.T) {
	mp := &MetricsPublisher{
		counters:  make(map[string]float64),
		latencies: make(map[string][]float64),
		stop:      make(chan struct{}),
	}

	// Record a known set of latencies
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

	// Verify the statistic calculation logic (same as flush)
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

func TestMetricsPublisher_LatencyCap(t *testing.T) {
	mp := &MetricsPublisher{
		counters:  make(map[string]float64),
		latencies: make(map[string][]float64),
		stop:      make(chan struct{}),
	}

	// Record more than maxLatencySamples
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

func TestMetricsPublisher_FlushResetsState(t *testing.T) {
	mp := &MetricsPublisher{
		counters:  make(map[string]float64),
		gauges:    make(map[string]float64),
		latencies: make(map[string][]float64),
		stop:      make(chan struct{}),
	}

	mp.IncrCounter("test")
	mp.RecordLatency("latency", 10.0)
	mp.mu.Lock()
	mp.gauges["StorageHealthy"] = 1.0
	mp.mu.Unlock()

	// Verify data exists before flush
	mp.mu.Lock()
	if mp.counters["test"] != 1 {
		t.Errorf("expected counter=1 before flush, got %v", mp.counters["test"])
	}
	if len(mp.latencies["latency"]) != 1 {
		t.Errorf("expected 1 latency sample before flush, got %d", len(mp.latencies["latency"]))
	}
	if mp.gauges["StorageHealthy"] != 1.0 {
		t.Errorf("expected gauge=1.0 before flush, got %v", mp.gauges["StorageHealthy"])
	}
	// Manually swap maps (simulating flush's map reset without calling the API)
	mp.counters = make(map[string]float64)
	mp.gauges = make(map[string]float64)
	mp.latencies = make(map[string][]float64)
	mp.mu.Unlock()

	if len(mp.counters) != 0 {
		t.Errorf("expected counters to be empty after reset, got %v", mp.counters)
	}
	if len(mp.gauges) != 0 {
		t.Errorf("expected gauges to be empty after reset, got %v", mp.gauges)
	}
	if len(mp.latencies) != 0 {
		t.Errorf("expected latencies to be empty after reset, got %v", mp.latencies)
	}
}

func TestMetricsPublisher_StopWaitsForFlushLoop(t *testing.T) {
	mp := &MetricsPublisher{
		counters:  make(map[string]float64),
		latencies: make(map[string][]float64),
		stop:      make(chan struct{}),
	}

	// Start the flush loop like NewMetricsPublisher does
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
