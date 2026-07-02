package metrics

// This file contains helpers used exclusively by external-package tests that
// need to construct or inspect a Publisher without going through NewPublisher
// (which requires AWS configuration). Every function accepts a testing.TB
// parameter so that production code cannot call them without importing the
// testing package — a clear signal (and practical guardrail) that these are
// test-only APIs.

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
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

// FlushIntervalForTest exposes the publisher flush cadence to external-package
// tests that need to fence cross-package timing invariants.
func FlushIntervalForTest(t testing.TB) time.Duration {
	t.Helper()
	return flushInterval
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

// SetBaseDimsForTest overrides the publisher's base dimensions so external-
// package tests can exercise EMF / counter emission with a realistic dim set
// (Environment, Cell) instead of the empty default that NewPublisherForTest
// returns. Must be called before the code under test emits.
//
// Holds mp.mu so a test that wires this against a Publisher constructed
// via NewPublisher (which starts flushLoop) is race-detector-safe;
// production write paths to mp.dims don't exist today but the lock
// keeps the helper structurally safe against a future refactor that
// makes mp.dims mutable.
func (mp *Publisher) SetBaseDimsForTest(t testing.TB, dims []types.Dimension) {
	t.Helper()
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.dims = dims
}

// DimensionsForTest returns a deep copy of the publisher's shared base
// dim set so external-package tests can fence the dims that were wired
// up at construction (e.g., that ac.NewACRegistration → resolveEnvironment
// flowed the right Environment value through into the Publisher). Deep
// copy because types.Dimension holds *string pointers — a shallow copy
// would share pointees and let a test caller mutate the publisher's
// invariant.
//
// Test-only by signature (testing.TB parameter) — production code that
// would import testing to call this has a bigger problem. Holds mp.mu
// for symmetry with SetBaseDimsForTest, so a test that uses both
// against a real-flushLoop Publisher is race-detector-safe.
//
// Fails the test (rather than panicking) if a dim has nil Name or
// Value — production code paths always populate both via aws.String,
// but a careless SetBaseDimsForTest caller passing types.Dimension{}
// with bare fields would otherwise crash here.
func (mp *Publisher) DimensionsForTest(t testing.TB) []types.Dimension {
	t.Helper()
	if mp == nil {
		return nil
	}
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	out := make([]types.Dimension, len(mp.dims))
	for i, d := range mp.dims {
		if d.Name == nil || d.Value == nil {
			t.Fatalf("DimensionsForTest: dim[%d] has nil Name (%v) or Value (%v); production paths always populate both via aws.String — likely a SetBaseDimsForTest caller passed types.Dimension{}", i, d.Name, d.Value)
		}
		out[i] = types.Dimension{
			Name:  aws.String(*d.Name),
			Value: aws.String(*d.Value),
		}
	}
	return out
}

// ParseEMFLinesForTest splits a newline-separated EMF stream (e.g., the
// bytes.Buffer returned by NewPublisherForTestWithEMFBuffer) into parsed
// events. Empty lines are skipped; a JSON decode failure fails the test
// immediately -- EMF lines that don't parse are a pipeline bug CloudWatch
// would also fail to extract, so there's no useful "soft failure" mode.
func ParseEMFLinesForTest(t testing.TB, data []byte) []map[string]any {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	events := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("invalid EMF JSON line: %v\nraw=%s", err, line)
		}
		events = append(events, ev)
	}
	return events
}

// CountersForTest returns snapshots of the in-memory counter state. It is
// intended only for external-package tests that need to assert which metrics
// were emitted by code under test. The returned maps are deep copies; the
// dimCounters map uses the same NUL-separated key format as buildDimCounterKey.
// With no dimensions, the key is the bare metric name.
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

// LatenciesForTest returns a deep copy of the in-memory latency observations
// (metric name → recorded millisecond samples), as accumulated by RecordLatency
// between flushes. Intended only for external-package tests that need to assert
// a specific latency value was recorded by code under test (e.g. the
// revocation-delivery-latency SLO histogram, #2792) without going through the
// EMF/statistic-set serialization. Mirrors CountersForTest / GaugesForTest.
func (mp *Publisher) LatenciesForTest(t testing.TB) map[string][]float64 {
	t.Helper()
	if mp == nil {
		return map[string][]float64{}
	}
	mp.mu.Lock()
	defer mp.mu.Unlock()
	out := make(map[string][]float64, len(mp.latencies))
	for k, v := range mp.latencies {
		out[k] = slices.Clone(v)
	}
	return out
}

// GaugesForTest collects registered gauge functions and returns a snapshot of
// the in-memory gauge state. Intended only for tests that need to assert state
// indicators registered via RegisterGaugeFunc.
func (mp *Publisher) GaugesForTest(t testing.TB) map[string]float64 {
	t.Helper()
	if mp == nil {
		return map[string]float64{}
	}
	mp.collectGauges()

	mp.mu.Lock()
	defer mp.mu.Unlock()
	gauges := make(map[string]float64, len(mp.gauges))
	for k, v := range mp.gauges {
		gauges[k] = v
	}
	return gauges
}
