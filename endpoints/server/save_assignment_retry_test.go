package server

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
)

// retryStorage is a test-only StorageBackend wrapper that programs
// the behavior of SaveACAssignment per attempt. The test injects a
// queue of errors (one per attempt); the wrapper returns each in
// order until exhausted, after which all calls succeed. GET calls
// pass through to the wrapped MemoryStorage so the retry loop's
// "re-read current version" path can exercise its real code.
//
// Why a wrapper rather than a method swap: the gate's retry helper
// drives the SaveACAssignment / GetACAssignment pair concurrently
// with non-conflict storage methods (license, resource lookups);
// stubbing one method on a struct while keeping the rest live
// keeps test setup small.
type retryStorage struct {
	*MemoryStorage

	mu          sync.Mutex
	saveErrs    []error // consumed left-to-right per Save call
	saveCalls   int
	getCalls    int
	getRespond  func(call int) (*ACAssignment, error) // optional GET override
	persistOnOK bool                                  // when true, the underlying MemoryStorage records the assignment after a returned-nil Save
}

func newRetryStorage(mem *MemoryStorage, saveErrs []error) *retryStorage {
	return &retryStorage{
		MemoryStorage: mem,
		saveErrs:      saveErrs,
		persistOnOK:   true,
	}
}

func (r *retryStorage) SaveACAssignment(ctx context.Context, a *ACAssignment) error {
	r.mu.Lock()
	idx := r.saveCalls
	r.saveCalls++
	if idx < len(r.saveErrs) {
		err := r.saveErrs[idx]
		r.mu.Unlock()
		if err != nil {
			return err
		}
	} else {
		r.mu.Unlock()
	}
	if r.persistOnOK {
		// Mimic real backend: record the assignment so subsequent
		// GET calls see the latest version. Use the underlying
		// MemoryStorage's PutACAssignment which is a non-versioned
		// write — version semantics are emulated by the test
		// setup, not enforced here.
		r.MemoryStorage.PutACAssignment(a)
	}
	return nil
}

func (r *retryStorage) GetACAssignment(ctx context.Context, acID string) (*ACAssignment, error) {
	r.mu.Lock()
	call := r.getCalls
	r.getCalls++
	override := r.getRespond
	r.mu.Unlock()
	if override != nil {
		return override(call)
	}
	return r.MemoryStorage.GetACAssignment(ctx, acID)
}

// retryStorageGetCalls / retryStorageSaveCalls are accessor helpers
// so tests can read the call counters under the mutex without
// reaching into struct internals.
func (r *retryStorage) retryStorageSaveCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.saveCalls
}

func (r *retryStorage) retryStorageGetCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.getCalls
}

func newRetryServer(t *testing.T, storage StorageBackend) *UdpServer {
	t.Helper()
	return &UdpServer{
		metrics:       metrics.NewPublisherForTest(t),
		storage:       storage,
		storageConfig: &StorageConfig{Backend: StorageBackendDynamoDB},
	}
}

// TestSaveAssignmentWithRetry_FirstAttemptSucceeds is the no-retry
// baseline: a clean Save returns nil and consumes one Save call.
func TestSaveAssignmentWithRetry_FirstAttemptSucceeds(t *testing.T) {
	mem := NewMemoryStorage()
	rs := newRetryStorage(mem, nil) // no errors programmed
	s := newRetryServer(t, rs)

	assignment := &ACAssignment{ACID: "ac-1", Version: 1, AssignedServers: []ServerInfo{{ID: "srv-1"}}}
	if err := s.saveAssignmentWithRetry("ac-1", 42, "10.0.0.1:62206", assignment); err != nil {
		t.Fatalf("clean save: err=%v, want nil", err)
	}
	if rs.retryStorageSaveCalls() != 1 {
		t.Errorf("save calls=%d, want 1 (no retry on success)", rs.retryStorageSaveCalls())
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACAssignmentVersionConflictRetry]; c != 0 {
		t.Errorf("clean save should not increment retry counter, got %v", c)
	}
}

// TestSaveAssignmentWithRetry_VersionConflictThenSucceeds fences the
// happy retry path: Save fails once with VersionConflict, the helper
// re-reads the latest version, retries, and succeeds.
func TestSaveAssignmentWithRetry_VersionConflictThenSucceeds(t *testing.T) {
	mem := NewMemoryStorage()
	// Pre-populate an existing assignment to simulate "another
	// server got there first." The retry-helper's re-read should
	// observe this and bump version to 2.
	mem.PutACAssignment(&ACAssignment{ACID: "ac-1", Version: 5})
	rs := newRetryStorage(mem, []error{
		NewVersionConflictError("first attempt loses race"),
		// Second attempt: success.
	})
	s := newRetryServer(t, rs)

	assignment := &ACAssignment{ACID: "ac-1", Version: 1, AssignedServers: []ServerInfo{{ID: "srv-2"}}}
	if err := s.saveAssignmentWithRetry("ac-1", 42, "10.0.0.1:62206", assignment); err != nil {
		t.Fatalf("retry-then-success: err=%v, want nil", err)
	}
	if rs.retryStorageSaveCalls() != 2 {
		t.Errorf("save calls=%d, want 2 (one retry)", rs.retryStorageSaveCalls())
	}
	if rs.retryStorageGetCalls() != 1 {
		t.Errorf("get calls=%d, want 1 (re-read on conflict)", rs.retryStorageGetCalls())
	}
	if assignment.Version != 6 {
		t.Errorf("assignment.Version=%d, want 6 (existing.Version=5 + 1)", assignment.Version)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACAssignmentVersionConflictRetry]; c != 1 {
		t.Errorf("retry counter=%v, want 1", c)
	}
	if c := counters[MetricACAssignmentVersionConflictExhausted]; c != 0 {
		t.Errorf("exhausted counter=%v, want 0 (we converged)", c)
	}
}

// TestSaveAssignmentWithRetry_VersionConflictExhausts fences the
// exhaustion path: 3 conflicts in a row → returns the last error
// AND fires the exhausted counter. Caller turns this into "accept
// directly" per the legacy availability contract.
func TestSaveAssignmentWithRetry_VersionConflictExhausts(t *testing.T) {
	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{ACID: "ac-1", Version: 5})
	rs := newRetryStorage(mem, []error{
		NewVersionConflictError("attempt 1"),
		NewVersionConflictError("attempt 2"),
		NewVersionConflictError("attempt 3"),
	})
	s := newRetryServer(t, rs)

	assignment := &ACAssignment{ACID: "ac-1", Version: 1}
	err := s.saveAssignmentWithRetry("ac-1", 42, "10.0.0.1:62206", assignment)
	if err == nil {
		t.Fatal("exhausted retries should return an error, got nil")
	}
	if !IsVersionConflictError(err) {
		t.Errorf("exhausted error type=%T, want VersionConflict", err)
	}
	if rs.retryStorageSaveCalls() != saveAssignmentMaxAttempts {
		t.Errorf("save calls=%d, want %d", rs.retryStorageSaveCalls(), saveAssignmentMaxAttempts)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACAssignmentVersionConflictRetry]; c != float64(saveAssignmentMaxAttempts-1) {
		t.Errorf("retry counter=%v, want %d (one increment per failed attempt except the last; last attempt is counted as exhaustion not retry)",
			c, saveAssignmentMaxAttempts-1)
	}
	if c := counters[MetricACAssignmentVersionConflictExhausted]; c != 1 {
		t.Errorf("exhausted counter=%v, want 1", c)
	}
}

// TestSaveAssignmentWithRetry_NonConflictErrorReturnsImmediately
// fences the availability fallback: a non-VersionConflict error
// (DDB unavailable, marshal failure) MUST NOT retry. The caller
// turns the error into "accept directly," and retrying would just
// double-charge a flaky storage outage with no chance of converging.
func TestSaveAssignmentWithRetry_NonConflictErrorReturnsImmediately(t *testing.T) {
	mem := NewMemoryStorage()
	customErr := errors.New("ddb: ProvisionedThroughputExceededException")
	rs := newRetryStorage(mem, []error{customErr})
	s := newRetryServer(t, rs)

	assignment := &ACAssignment{ACID: "ac-1", Version: 1}
	err := s.saveAssignmentWithRetry("ac-1", 42, "10.0.0.1:62206", assignment)
	if err == nil {
		t.Fatal("non-conflict error should propagate, got nil")
	}
	if !errors.Is(err, customErr) {
		t.Errorf("err=%v, want underlying customErr", err)
	}
	if rs.retryStorageSaveCalls() != 1 {
		t.Errorf("save calls=%d, want 1 (no retry on non-conflict error)", rs.retryStorageSaveCalls())
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACAssignmentVersionConflictRetry]; c != 0 {
		t.Errorf("non-conflict should not increment retry counter, got %v", c)
	}
	if c := counters[MetricACAssignmentVersionConflictExhausted]; c != 0 {
		t.Errorf("non-conflict should not increment exhausted counter, got %v", c)
	}
	if c := counters[MetricACAssignmentSaveError]; c != 1 {
		t.Errorf("non-conflict should increment save-error counter once, got %v", c)
	}
}

// TestSaveAssignmentWithRetry_ReReadNotFoundResetsToVersion1
// covers the edge case where a concurrent delete/TTL-expiry races
// the conflict — the assignment vanishes between Save attempts.
// The helper must treat this as "no assignment in storage" and try
// Version=1 on the next attempt.
func TestSaveAssignmentWithRetry_ReReadNotFoundResetsToVersion1(t *testing.T) {
	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{ACID: "ac-1", Version: 5})
	rs := newRetryStorage(mem, []error{
		NewVersionConflictError("first attempt loses race"),
		// Second attempt: success.
	})
	rs.getRespond = func(call int) (*ACAssignment, error) {
		// First (and only) GET call returns not-found.
		if call == 0 {
			return nil, &StorageError{Code: ErrCodeNotFound, Message: "ac-1 disappeared"}
		}
		return mem.GetACAssignment(context.Background(), "ac-1")
	}
	s := newRetryServer(t, rs)

	assignment := &ACAssignment{ACID: "ac-1", Version: 1}
	if err := s.saveAssignmentWithRetry("ac-1", 42, "10.0.0.1:62206", assignment); err != nil {
		t.Fatalf("not-found re-read: err=%v, want nil", err)
	}
	if assignment.Version != 1 {
		t.Errorf("after not-found, assignment.Version=%d, want 1 (concurrent delete reset)", assignment.Version)
	}
}

// TestSaveAssignmentWithRetry_TwoConflictsThenSucceeds fences the
// max-1 case: two retries then succeed. Verifies the loop iterates
// the right number of times and that the metric counter records
// each retry attempt.
func TestSaveAssignmentWithRetry_TwoConflictsThenSucceeds(t *testing.T) {
	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{ACID: "ac-1", Version: 5})
	rs := newRetryStorage(mem, []error{
		NewVersionConflictError("attempt 1"),
		NewVersionConflictError("attempt 2"),
		// attempt 3: success.
	})
	s := newRetryServer(t, rs)

	assignment := &ACAssignment{ACID: "ac-1", Version: 1}
	if err := s.saveAssignmentWithRetry("ac-1", 42, "10.0.0.1:62206", assignment); err != nil {
		t.Fatalf("two-retries-then-success: err=%v, want nil", err)
	}
	if rs.retryStorageSaveCalls() != 3 {
		t.Errorf("save calls=%d, want 3", rs.retryStorageSaveCalls())
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACAssignmentVersionConflictRetry]; c != 2 {
		t.Errorf("retry counter=%v, want 2", c)
	}
	if c := counters[MetricACAssignmentVersionConflictExhausted]; c != 0 {
		t.Errorf("exhausted counter=%v, want 0", c)
	}
}
