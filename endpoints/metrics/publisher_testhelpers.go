package metrics

// This file contains helpers used exclusively by external-package tests that
// need to construct or inspect a Publisher without going through NewPublisher
// (which requires AWS configuration). Every function accepts a testing.TB
// parameter so that production code cannot call them without importing the
// testing package — a clear signal (and practical guardrail) that these are
// test-only APIs.

import (
	"bytes"
	"io"
	"testing"
)

// NewPublisherForTest constructs a Publisher with initialized in-memory maps
// and a discard EMF writer. It is safe to call from any package's tests when
// you need a real *Publisher to inject into code under test, but you do not
// want a CloudWatch client or a flushLoop goroutine.
//
// The returned Publisher has no dimensions and no client; calls to Stop are
// safe (the flushLoop never started).
func NewPublisherForTest(t testing.TB) *Publisher {
	t.Helper()
	return &Publisher{
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

// NewPublisherForTestWithEMFBuffer is like NewPublisherForTest but routes
// EMF output to the returned bytes.Buffer so tests can assert on EMF
// events emitted via EmitEMFCounterNow (or the flush-driven emitEMF
// path). Use this when the code under test emits metrics via EMF
// rather than IncrCounter / IncrCounterWithDims.
func NewPublisherForTestWithEMFBuffer(t testing.TB) (*Publisher, *bytes.Buffer) {
	t.Helper()
	mp := NewPublisherForTest(t)
	buf := &bytes.Buffer{}
	mp.emfWriter = buf
	return mp, buf
}

// CountersForTest returns snapshots of the in-memory counter state. It is
// intended only for external-package tests that need to assert which metrics
// were emitted by code under test. The returned maps are deep copies; the
// dimCounters map is keyed by `<metric>|<dim_name>=<dim_value>|...` for
// stable substring assertions.
func (mp *Publisher) CountersForTest(t testing.TB) (counters map[string]float64, dimCounters map[string]float64) {
	t.Helper()
	if mp == nil {
		return map[string]float64{}, map[string]float64{}
	}
	mp.mu.Lock()
	defer mp.mu.Unlock()

	counters = make(map[string]float64, len(mp.counters))
	for k, v := range mp.counters {
		counters[k] = v
	}

	dimCounters = make(map[string]float64, len(mp.dimCounters))
	for k, v := range mp.dimCounters {
		dimCounters[k] = v.value
	}
	return counters, dimCounters
}
