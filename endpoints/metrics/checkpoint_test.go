package metrics

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

// checkpointPath returns the on-disk checkpoint file path for the given dir.
// Used by tests to stat / write fixtures directly. Production callers go
// through resolveCheckpointTarget so they can validate the directory.
func checkpointPath(dir string) string {
	return filepath.Join(dir, checkpointFileName)
}

func TestSaveAndLoadCheckpoint(t *testing.T) {
	dir := t.TempDir()

	cp := &checkpoint{
		Version:   checkpointSchemaVersion,
		Timestamp: time.Now(),
		Counters:  map[string]float64{"KnockRequest": 5, "AuthSuccess": 2},
		Gauges:    map[string]float64{"StorageHealthy": 1.0},
		Latencies: map[string][]float64{"KnockLatency": {10.0, 20.0, 30.0}},
		DimCounters: map[string]checkpointDimCounter{
			"key1": {
				MetricName: "RegistrationFailure",
				Dims: []checkpointDimension{
					{Name: "Environment", Value: "sandbox"},
					{Name: "Error", Value: "timeout"},
				},
				Value: 3,
			},
		},
	}

	if err := saveCheckpoint(dir, cp); err != nil {
		t.Fatalf("saveCheckpoint failed: %v", err)
	}

	if _, err := os.Stat(checkpointPath(dir)); err != nil {
		t.Fatalf("checkpoint file does not exist: %v", err)
	}

	loaded, err := loadCheckpoint(dir)
	if err != nil {
		t.Fatalf("loadCheckpoint failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil checkpoint")
	}

	if loaded.Counters["KnockRequest"] != 5 {
		t.Errorf("expected KnockRequest=5, got %v", loaded.Counters["KnockRequest"])
	}
	if loaded.Counters["AuthSuccess"] != 2 {
		t.Errorf("expected AuthSuccess=2, got %v", loaded.Counters["AuthSuccess"])
	}
	if loaded.Gauges["StorageHealthy"] != 1.0 {
		t.Errorf("expected StorageHealthy=1.0, got %v", loaded.Gauges["StorageHealthy"])
	}
	if len(loaded.Latencies["KnockLatency"]) != 3 {
		t.Errorf("expected 3 latency samples, got %d", len(loaded.Latencies["KnockLatency"]))
	}

	dc, ok := loaded.DimCounters["key1"]
	if !ok {
		t.Fatal("expected dimCounter key1 to exist")
	}
	if dc.MetricName != "RegistrationFailure" {
		t.Errorf("expected MetricName=RegistrationFailure, got %s", dc.MetricName)
	}
	if dc.Value != 3 {
		t.Errorf("expected Value=3, got %v", dc.Value)
	}

	// loadCheckpoint leaves the file in place on the happy path; the file
	// is removed by recoverFromCheckpoint after the merge succeeds (so that
	// a panic between load and merge does not silently lose data).
	if _, err := os.Stat(checkpointPath(dir)); err != nil {
		t.Errorf("expected checkpoint file to remain after loadCheckpoint, got: %v", err)
	}
}

func TestLoadCheckpoint_NoFile(t *testing.T) {
	dir := t.TempDir()
	cp, err := loadCheckpoint(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cp != nil {
		t.Error("expected nil checkpoint when no file exists")
	}
}

func TestLoadCheckpoint_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(checkpointPath(dir), []byte("{invalid json"), 0o600); err != nil {
		t.Fatalf("failed to write corrupt file: %v", err)
	}
	cp, err := loadCheckpoint(dir)
	if err == nil {
		t.Fatal("expected error for corrupt checkpoint")
	}
	if cp != nil {
		t.Error("expected nil checkpoint on error")
	}
	// File should be preserved on unmarshal failure so data is not lost
	if _, statErr := os.Stat(checkpointPath(dir)); os.IsNotExist(statErr) {
		t.Error("corrupt checkpoint file should be preserved for debugging")
	}
}

func TestLoadCheckpoint_WrongSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	// Write a checkpoint that parses as valid JSON but carries an
	// incompatible schema version (zero from an untagged file).
	raw := []byte(`{"timestamp":"2026-01-01T00:00:00Z","counters":{"X":1}}`)
	if err := os.WriteFile(checkpointPath(dir), raw, 0o600); err != nil {
		t.Fatalf("write test checkpoint: %v", err)
	}

	cp, err := loadCheckpoint(dir)
	if err != nil {
		t.Fatalf("loadCheckpoint returned error: %v", err)
	}
	if cp != nil {
		t.Error("expected nil checkpoint for wrong schema version")
	}
	// Incompatible files should be removed so they do not accumulate.
	if _, statErr := os.Stat(checkpointPath(dir)); !os.IsNotExist(statErr) {
		t.Error("expected incompatible checkpoint file to be removed")
	}
}

func TestSaveCheckpoint_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	cp := &checkpoint{Version: checkpointSchemaVersion, Timestamp: time.Now(), Counters: map[string]float64{"test": 1}}

	for i := 0; i < 5; i++ {
		cp.Counters["test"] = float64(i)
		if err := saveCheckpoint(dir, cp); err != nil {
			t.Fatalf("saveCheckpoint iteration %d failed: %v", i, err)
		}
	}

	// No temp files should be left behind
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != checkpointFileName {
			t.Errorf("unexpected file left behind: %s", e.Name())
		}
	}

	loaded, err := loadCheckpoint(dir)
	if err != nil {
		t.Fatalf("loadCheckpoint failed: %v", err)
	}
	if loaded.Counters["test"] != 4 {
		t.Errorf("expected test=4, got %v", loaded.Counters["test"])
	}
}

func TestRemoveCheckpoint(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(checkpointPath(dir), []byte("{}"), 0o600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	removeCheckpoint(dir)
	if _, err := os.Stat(checkpointPath(dir)); !os.IsNotExist(err) {
		t.Error("expected checkpoint file to be removed")
	}
	// Removing non-existent file should not panic
	removeCheckpoint(dir)
}

func TestPublisher_SnapshotToCheckpoint(t *testing.T) {
	mp := newTestPublisher(t, nil)
	mp.counters["KnockRequest"] = 3
	mp.dimCounters["key1"] = &dimCounterEntry{
		metricName: "Failure",
		dims:       []types.Dimension{{Name: aws.String("Env"), Value: aws.String("test")}},
		value:      2,
	}
	mp.gauges["Peers"] = 5
	mp.latencies["Latency"] = []float64{1.0, 2.0}

	cp := mp.snapshotToCheckpoint()

	if cp.Counters["KnockRequest"] != 3 {
		t.Errorf("expected counter=3, got %v", cp.Counters["KnockRequest"])
	}
	if cp.Gauges["Peers"] != 5 {
		t.Errorf("expected gauge=5, got %v", cp.Gauges["Peers"])
	}
	if len(cp.Latencies["Latency"]) != 2 {
		t.Errorf("expected 2 latency samples, got %d", len(cp.Latencies["Latency"]))
	}

	// Verify deep copy
	mp.counters["KnockRequest"] = 100
	if cp.Counters["KnockRequest"] != 3 {
		t.Error("snapshot should be a deep copy of counters")
	}
	mp.latencies["Latency"][0] = 999
	if cp.Latencies["Latency"][0] != 1.0 {
		t.Error("snapshot should be a deep copy of latencies")
	}
}

func TestPublisher_MergeCheckpoint(t *testing.T) {
	mp := newTestPublisher(t, nil)
	mp.counters["KnockRequest"] = 2
	mp.dimCounters["key1"] = &dimCounterEntry{
		metricName: "Failure",
		dims:       []types.Dimension{{Name: aws.String("Env"), Value: aws.String("test")}},
		value:      1,
	}
	mp.latencies["Latency"] = []float64{5.0}

	cp := &checkpoint{
		Version:  checkpointSchemaVersion,
		Counters: map[string]float64{"KnockRequest": 3, "AuthSuccess": 1},
		DimCounters: map[string]checkpointDimCounter{
			"key1": {MetricName: "Failure", Dims: []checkpointDimension{{Name: "Env", Value: "test"}}, Value: 2},
			"key2": {MetricName: "OtherFailure", Dims: []checkpointDimension{{Name: "Code", Value: "500"}}, Value: 5},
		},
		Gauges:    map[string]float64{"StorageHealthy": 1.0},
		Latencies: map[string][]float64{"Latency": {10.0, 20.0}},
	}

	mp.mergeCheckpoint(cp)

	if mp.counters["KnockRequest"] != 5 {
		t.Errorf("expected KnockRequest=5, got %v", mp.counters["KnockRequest"])
	}
	if mp.counters["AuthSuccess"] != 1 {
		t.Errorf("expected AuthSuccess=1, got %v", mp.counters["AuthSuccess"])
	}
	if mp.dimCounters["key1"].value != 3 {
		t.Errorf("expected dimCounter key1=3, got %v", mp.dimCounters["key1"].value)
	}
	if mp.dimCounters["key2"] == nil || mp.dimCounters["key2"].value != 5 {
		t.Errorf("expected dimCounter key2=5")
	}
	if mp.gauges["StorageHealthy"] != 1.0 {
		t.Errorf("expected StorageHealthy=1.0, got %v", mp.gauges["StorageHealthy"])
	}
	if len(mp.latencies["Latency"]) != 3 {
		t.Errorf("expected 3 latency samples, got %d", len(mp.latencies["Latency"]))
	}
}

func TestPublisher_MergeCheckpoint_GaugesPreserveLive(t *testing.T) {
	mp := newTestPublisher(t, nil)
	mp.gauges["StorageHealthy"] = 0.0

	cp := &checkpoint{Version: checkpointSchemaVersion, Gauges: map[string]float64{"StorageHealthy": 1.0, "NewGauge": 42}}
	mp.mergeCheckpoint(cp)

	if mp.gauges["StorageHealthy"] != 0.0 {
		t.Errorf("expected live gauge preserved, got %v", mp.gauges["StorageHealthy"])
	}
	if mp.gauges["NewGauge"] != 42 {
		t.Errorf("expected NewGauge=42, got %v", mp.gauges["NewGauge"])
	}
}

func TestPublisher_MergeCheckpoint_LatencyCap(t *testing.T) {
	mp := newTestPublisher(t, nil)
	mp.latencies["test"] = make([]float64, maxLatencySamples-2)

	cp := &checkpoint{Version: checkpointSchemaVersion, Latencies: map[string][]float64{"test": {100, 200, 300, 400, 500}}}
	mp.mergeCheckpoint(cp)

	if len(mp.latencies["test"]) != maxLatencySamples {
		t.Errorf("expected cap at %d, got %d", maxLatencySamples, len(mp.latencies["test"]))
	}
}

func TestPublisher_MergeCheckpoint_Nil(t *testing.T) {
	mp := newTestPublisher(t, nil)
	mp.counters["test"] = 1
	mp.mergeCheckpoint(nil)
	if mp.counters["test"] != 1 {
		t.Errorf("expected counter unchanged, got %v", mp.counters["test"])
	}
}

func TestPublisher_WriteCheckpoint(t *testing.T) {
	dir := t.TempDir()
	mp := newCheckpointTestPublisher(t, dir)
	mp.counters["KnockRequest"] = 7
	mp.gauges["Peers"] = 3

	mp.writeCheckpoint()

	if _, err := os.Stat(checkpointPath(dir)); err != nil {
		t.Fatalf("checkpoint file should exist: %v", err)
	}

	cp, err := loadCheckpoint(dir)
	if err != nil {
		t.Fatalf("loadCheckpoint failed: %v", err)
	}
	if cp.Counters["KnockRequest"] != 7 {
		t.Errorf("expected KnockRequest=7, got %v", cp.Counters["KnockRequest"])
	}
}

// TestWriteCheckpoint_FailureIncrementsMetric verifies that a failed
// saveCheckpoint call (here forced by pointing the publisher at a path
// that cannot be written -- a regular file masquerading as a directory)
// surfaces the failure as MetricCheckpointWriteFailure on the in-memory
// counter map. Operators rely on this counter to alarm on silent
// checkpointing outages, so the wiring is part of the contract.
func TestWriteCheckpoint_FailureIncrementsMetric(t *testing.T) {
	parent := t.TempDir()
	// Create a regular file where the checkpoint dir should be so that
	// saveCheckpoint cannot create checkpointTempFileName underneath it.
	bogusDir := filepath.Join(parent, "not-a-dir")
	if err := os.WriteFile(bogusDir, []byte("nope"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	mp := newTestPublisher(t, nil)
	mp.checkpointDir = bogusDir
	mp.counters["KnockRequest"] = 1

	mp.writeCheckpoint()

	if got := mp.counters[MetricCheckpointWriteFailure]; got != 1 {
		t.Errorf("MetricCheckpointWriteFailure = %v, want 1", got)
	}
}

// TestPublisher_FlushRemovesCheckpoint verifies flush() deletes the checkpoint
// file so a subsequent crash-recovery cannot replay metrics that were already
// published.
func TestPublisher_FlushRemovesCheckpoint(t *testing.T) {
	dir := t.TempDir()
	mp := newCheckpointTestPublisher(t, dir)
	mp.counters["KnockRequest"] = 3

	// Pre-create a checkpoint file on disk as if a previous tick had written one.
	mp.writeCheckpoint()
	if _, err := os.Stat(checkpointPath(dir)); err != nil {
		t.Fatalf("precondition: checkpoint file should exist before flush: %v", err)
	}

	mp.flush()

	if _, err := os.Stat(checkpointPath(dir)); !os.IsNotExist(err) {
		t.Errorf("flush should have removed the checkpoint file; stat err: %v", err)
	}
	if len(mp.counters) != 0 {
		t.Errorf("flush should have cleared counters; got %v", mp.counters)
	}
}

func TestCheckpointRoundTrip_DimCounters(t *testing.T) {
	dir := t.TempDir()
	mp := newCheckpointTestPublisher(t, dir)
	mp.dimCounters["k"] = &dimCounterEntry{
		metricName: "RegistrationFailure",
		dims: []types.Dimension{
			{Name: aws.String("Environment"), Value: aws.String("sandbox")},
			{Name: aws.String("Error"), Value: aws.String("timeout")},
		},
		value: 4,
	}
	mp.writeCheckpoint()

	// Create a SECOND, completely independent publisher (mp2) without a
	// checkpoint dir and merge the checkpoint that mp wrote. This models the
	// real cross-process recovery flow: a fresh process starts up with no
	// in-memory state and must reconstruct the dimCounters from disk. We
	// deliberately do NOT reuse mp here, otherwise the test would only prove
	// that a publisher round-trips its own state.
	mp2 := newTestPublisher(t, nil)
	cp, err := loadCheckpoint(dir)
	if err != nil {
		t.Fatalf("loadCheckpoint failed: %v", err)
	}
	mp2.mergeCheckpoint(cp)

	entry, ok := mp2.dimCounters["k"]
	if !ok {
		t.Fatal("expected dimCounter key 'k' to exist")
	}
	if entry.metricName != "RegistrationFailure" || entry.value != 4 {
		t.Errorf("unexpected dimCounter: %+v", entry)
	}
	if len(entry.dims) != 2 {
		t.Fatalf("expected 2 dims, got %d", len(entry.dims))
	}
}

func TestCheckpointPath(t *testing.T) {
	got := checkpointPath("/tmp")
	want := filepath.Join("/tmp", checkpointFileName)
	if got != want {
		t.Errorf("checkpointPath(/tmp) = %q, want %q", got, want)
	}
}

func TestRecoverFromCheckpoint_DropsStale(t *testing.T) {
	dir := t.TempDir()

	// Pre-seed a checkpoint with a timestamp well past 2*flushInterval.
	staleCP := &checkpoint{
		Version:   checkpointSchemaVersion,
		Timestamp: time.Now().Add(-3 * flushInterval),
		Counters:  map[string]float64{"StaleMetric": 99},
	}
	if err := saveCheckpoint(dir, staleCP); err != nil {
		t.Fatalf("saveCheckpoint failed: %v", err)
	}

	mp := newCheckpointTestPublisher(t, dir)
	mp.recoverFromCheckpoint()

	if got := mp.counters["StaleMetric"]; got != 0 {
		t.Errorf("expected stale checkpoint to be dropped, but counter merged: got %v", got)
	}
	if len(mp.counters) != 0 {
		t.Errorf("expected counters to be empty, got %v", mp.counters)
	}
	// Stale checkpoints must be deleted on the recovery path so the next
	// start does not log the same warning forever.
	if _, err := os.Stat(checkpointPath(dir)); !os.IsNotExist(err) {
		t.Error("expected stale checkpoint file to be removed by recoverFromCheckpoint")
	}
}

func TestRecoverFromCheckpoint_MergesFresh(t *testing.T) {
	dir := t.TempDir()

	freshCP := &checkpoint{
		Version:   checkpointSchemaVersion,
		Timestamp: time.Now(),
		Counters:  map[string]float64{"FreshMetric": 7},
	}
	if err := saveCheckpoint(dir, freshCP); err != nil {
		t.Fatalf("saveCheckpoint failed: %v", err)
	}

	mp := newCheckpointTestPublisher(t, dir)
	mp.recoverFromCheckpoint()

	if got := mp.counters["FreshMetric"]; got != 7 {
		t.Errorf("expected fresh checkpoint to be merged, got counter=%v", got)
	}
}

func TestRecoverFromCheckpoint_NoFile(t *testing.T) {
	dir := t.TempDir()
	mp := newCheckpointTestPublisher(t, dir)
	mp.counters["LiveMetric"] = 1

	mp.recoverFromCheckpoint() // no checkpoint on disk — must be a no-op

	if got := mp.counters["LiveMetric"]; got != 1 {
		t.Errorf("expected live counter untouched, got %v", got)
	}
}

func TestRecoverFromCheckpoint_Disabled(t *testing.T) {
	mp := newTestPublisher(t, nil) // checkpointDir == ""
	mp.counters["LiveMetric"] = 1

	mp.recoverFromCheckpoint() // checkpointing disabled — must be a no-op

	if got := mp.counters["LiveMetric"]; got != 1 {
		t.Errorf("expected live counter untouched, got %v", got)
	}
}

// TestCheckpointIntegration_RecoverAfterRestart exercises the full checkpoint
// lifecycle: record metrics → write a checkpoint → load it from a fresh
// publisher → confirm counters, latencies, and dimCounters round-trip.
func TestCheckpointIntegration_RecoverAfterRestart(t *testing.T) {
	dir := t.TempDir()

	// --- Phase 1: Create publisher, record metrics, write checkpoint ---

	mp1 := newCheckpointTestPublisher(t, dir)
	mp1.dims = []types.Dimension{{Name: aws.String("Env"), Value: aws.String("test")}}

	mp1.IncrCounter("KnockRequest")
	mp1.IncrCounter("KnockRequest")
	mp1.IncrCounter("KnockRequest")
	mp1.IncrCounter("AuthSuccess")
	mp1.RecordLatency("KnockLatency", 10.0)
	mp1.RecordLatency("KnockLatency", 25.0)
	mp1.IncrCounterWithDims("RegistrationFailure", []types.Dimension{
		{Name: aws.String("Error"), Value: aws.String("timeout")},
	})

	mp1.writeCheckpoint()

	cpPath := checkpointPath(dir)
	if _, err := os.Stat(cpPath); err != nil {
		t.Fatalf("checkpoint file should exist after writeCheckpoint: %v", err)
	}

	// --- Phase 2: New publisher loads checkpoint and recovers metrics ---

	mp2 := newCheckpointTestPublisher(t, dir)

	cp, err := loadCheckpoint(dir)
	if err != nil {
		t.Fatalf("loadCheckpoint failed: %v", err)
	}
	if cp == nil {
		t.Fatal("expected non-nil checkpoint from previous publisher")
	}

	// Checkpoint is fresh (just written), so it should not be discarded
	cpAge := time.Since(cp.Timestamp)
	stalenessThreshold := 2 * flushInterval
	if cpAge > stalenessThreshold {
		t.Fatalf("checkpoint should be fresh, but age=%s exceeds threshold=%s", cpAge, stalenessThreshold)
	}

	mp2.mergeCheckpoint(cp)

	// Verify counters were recovered
	if mp2.counters["KnockRequest"] != 3 {
		t.Errorf("expected KnockRequest=3 after recovery, got %v", mp2.counters["KnockRequest"])
	}
	if mp2.counters["AuthSuccess"] != 1 {
		t.Errorf("expected AuthSuccess=1 after recovery, got %v", mp2.counters["AuthSuccess"])
	}

	// Verify latencies were recovered
	latencies := mp2.latencies["KnockLatency"]
	if len(latencies) != 2 {
		t.Fatalf("expected 2 latency samples after recovery, got %d", len(latencies))
	}
	if latencies[0] != 10.0 || latencies[1] != 25.0 {
		t.Errorf("expected latencies [10.0, 25.0], got %v", latencies)
	}

	// Verify dim counters were recovered
	if len(mp2.dimCounters) != 1 {
		t.Fatalf("expected 1 dimCounter after recovery, got %d", len(mp2.dimCounters))
	}
	for _, entry := range mp2.dimCounters {
		if entry.metricName != "RegistrationFailure" {
			t.Errorf("expected RegistrationFailure, got %s", entry.metricName)
		}
		if entry.value != 1 {
			t.Errorf("expected dimCounter value=1, got %v", entry.value)
		}
	}

	// loadCheckpoint no longer removes the file on the happy path; the
	// file lives until recoverFromCheckpoint deletes it after a successful
	// merge. Verify both halves of the contract here.
	if _, err := os.Stat(cpPath); err != nil {
		t.Errorf("checkpoint file should still exist after loadCheckpoint, got: %v", err)
	}

	mp3 := newCheckpointTestPublisher(t, dir)
	mp3.recoverFromCheckpoint()
	if mp3.counters["KnockRequest"] != 3 {
		t.Errorf("expected KnockRequest=3 after recoverFromCheckpoint, got %v", mp3.counters["KnockRequest"])
	}
	if _, err := os.Stat(cpPath); !os.IsNotExist(err) {
		t.Error("checkpoint file should be removed after successful recoverFromCheckpoint")
	}
}

// newCheckpointTestPublisher wraps newTestPublisher with checkpointing
// pointed at a test-owned directory. checkpointInterval is intentionally
// left zero — none of the checkpoint tests start the flushLoop, so the
// ticker is never created and the field is never read.
func newCheckpointTestPublisher(t *testing.T, dir string) *Publisher {
	t.Helper()
	mp := newTestPublisher(t, nil)
	mp.checkpointDir = dir
	return mp
}
