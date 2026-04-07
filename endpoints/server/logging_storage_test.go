package server

import (
	"context"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// LoggingStorage Tests
// ============================================================================

func TestLoggingStorage_GetACAssignment_Success(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutACAssignment(CreateTestACAssignment("ac-log-1", "srv-1", "srv-2"))

	ls := NewLoggingStorage(backend)
	ctx := context.Background()

	assignment, err := ls.GetACAssignment(ctx, "ac-log-1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if assignment.ACID != "ac-log-1" {
		t.Errorf("Expected ACID 'ac-log-1', got '%s'", assignment.ACID)
	}
	if len(assignment.AssignedServers) != 2 {
		t.Errorf("Expected 2 servers, got %d", len(assignment.AssignedServers))
	}
}

func TestLoggingStorage_GetACAssignment_NotFound(t *testing.T) {
	backend := NewMemoryStorage()
	ls := NewLoggingStorage(backend)
	ctx := context.Background()

	_, err := ls.GetACAssignment(ctx, "non-existent")
	if err == nil {
		t.Fatal("Expected error for non-existent AC")
	}
	if !IsNotFoundError(err) {
		t.Errorf("Expected NotFoundError, got %T: %v", err, err)
	}
}

func TestLoggingStorage_GetACAssignment_BackendError(t *testing.T) {
	backend := NewMemoryStorage()
	backend.SetServiceUnavailable("test outage")

	ls := NewLoggingStorage(backend)
	ctx := context.Background()

	_, err := ls.GetACAssignment(ctx, "ac-error")
	if err == nil {
		t.Fatal("Expected error from backend")
	}
}

func TestLoggingStorage_GetACsByServer(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutACAssignment(CreateTestACAssignment("ac-srv-1", "srv-target"))
	backend.PutACAssignment(CreateTestACAssignment("ac-srv-2", "srv-target"))
	backend.PutACAssignment(CreateTestACAssignment("ac-srv-3", "srv-other"))

	ls := NewLoggingStorage(backend)
	ctx := context.Background()

	assignments, err := ls.GetACsByServer(ctx, "srv-target")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(assignments) != 2 {
		t.Errorf("Expected 2 assignments, got %d", len(assignments))
	}
}

func TestLoggingStorage_GetLicense_Success(t *testing.T) {
	backend := NewMemoryStorage()
	license := CreateTestLicense("test-key-123")
	backend.PutLicenseWithKey(license, "test-key-123")

	ls := NewLoggingStorage(backend)
	ctx := context.Background()

	result, err := ls.GetLicense(ctx, "test-key-123")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if result.CustomerID != "test-customer" {
		t.Errorf("Expected customerID 'test-customer', got '%s'", result.CustomerID)
	}
}

func TestLoggingStorage_GetLicense_NotFound(t *testing.T) {
	backend := NewMemoryStorage()
	ls := NewLoggingStorage(backend)
	ctx := context.Background()

	_, err := ls.GetLicense(ctx, "missing-key")
	if err == nil {
		t.Fatal("Expected error for missing license")
	}
	if !IsNotFoundError(err) {
		t.Errorf("Expected NotFoundError, got %T: %v", err, err)
	}
}

func TestLoggingStorage_GetResource_Success(t *testing.T) {
	backend := NewMemoryStorage()
	resource := CreateTestResource("cust-1", "res-1", "ac-1")
	backend.PutResource(resource)

	ls := NewLoggingStorage(backend)
	ctx := context.Background()

	result, err := ls.GetResource(ctx, "cust-1", "res-1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if result.ResourceID != "res-1" {
		t.Errorf("Expected resourceID 'res-1', got '%s'", result.ResourceID)
	}
}

func TestLoggingStorage_GetResource_NotFound(t *testing.T) {
	backend := NewMemoryStorage()
	ls := NewLoggingStorage(backend)
	ctx := context.Background()

	_, err := ls.GetResource(ctx, "cust-1", "missing-res")
	if err == nil {
		t.Fatal("Expected error for missing resource")
	}
	if !IsNotFoundError(err) {
		t.Errorf("Expected NotFoundError, got %T: %v", err, err)
	}
}

func TestLoggingStorage_GetResourceByACID_Success(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutResource(CreateTestResource("cust-1", "res-1", "ac-lookup"))
	backend.PutResource(CreateTestResource("cust-1", "res-2", "ac-lookup"))

	ls := NewLoggingStorage(backend)
	ctx := context.Background()

	resources, err := ls.GetResourceByACID(ctx, "ac-lookup")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(resources) != 2 {
		t.Errorf("Expected 2 resources, got %d", len(resources))
	}
}

func TestLoggingStorage_SaveACAssignment_Success(t *testing.T) {
	backend := NewMemoryStorage()
	ls := NewLoggingStorage(backend)
	ctx := context.Background()

	assignment := CreateTestACAssignment("ac-save-1", "srv-1", "srv-2")
	err := ls.SaveACAssignment(ctx, assignment)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify it was actually saved
	saved, err := backend.GetACAssignment(ctx, "ac-save-1")
	if err != nil {
		t.Fatalf("Expected saved assignment, got error: %v", err)
	}
	if saved.ACID != "ac-save-1" {
		t.Errorf("Expected ACID 'ac-save-1', got '%s'", saved.ACID)
	}
}

func TestLoggingStorage_SaveACAssignment_Error(t *testing.T) {
	backend := NewMemoryStorage()
	backend.SetServiceUnavailable("write outage")

	ls := NewLoggingStorage(backend)
	ctx := context.Background()

	assignment := CreateTestACAssignment("ac-save-err", "srv-1")
	err := ls.SaveACAssignment(ctx, assignment)
	if err == nil {
		t.Fatal("Expected error from backend")
	}
}

func TestLoggingStorage_Name(t *testing.T) {
	backend := NewMemoryStorage()
	ls := NewLoggingStorage(backend)

	if ls.Name() != "memory (logged)" {
		t.Errorf("Expected name 'memory (logged)', got '%s'", ls.Name())
	}
}

func TestLoggingStorage_Backend(t *testing.T) {
	backend := NewMemoryStorage()
	ls := NewLoggingStorage(backend)

	if ls.Backend() != backend {
		t.Error("Backend() should return the underlying storage backend")
	}
}

func TestLoggingStorage_Close(t *testing.T) {
	backend := NewMemoryStorage()
	ls := NewLoggingStorage(backend)

	err := ls.Close()
	if err != nil {
		t.Errorf("Expected no error on close, got %v", err)
	}
}

func TestLoggingStorage_ContextCancellation(t *testing.T) {
	backend := NewMemoryStorage()
	// Add delay so context cancellation can take effect
	backend.SetDelayOnNextCall(2 * time.Second)

	ls := NewLoggingStorage(backend)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := ls.GetACAssignment(ctx, "ac-timeout")
	if err == nil {
		t.Fatal("Expected error from context cancellation")
	}
}

func TestLoggingStorage_ComposesWithCachedStorage(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutACAssignment(CreateTestACAssignment("ac-compose", "srv-1"))

	// Chain: backend -> logging -> cache
	logged := NewLoggingStorage(backend)
	cached := NewCachedStorage(logged, CacheConfig{
		MaxEntries: 100,
		DefaultTTL: 60,
	})

	ctx := context.Background()

	// First call: cache miss -> logging -> backend
	_, err := cached.GetACAssignment(ctx, "ac-compose")
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}

	// Second call: cache hit (no logging/backend call)
	_, err = cached.GetACAssignment(ctx, "ac-compose")
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}

	// Backend should only be called once (cache hit on second)
	if backend.GetCallCount("GetACAssignment") != 1 {
		t.Errorf("Expected 1 backend call, got %d", backend.GetCallCount("GetACAssignment"))
	}
}

func TestLoggingStorage_Ping_NonPinger(t *testing.T) {
	// MemoryStorage doesn't implement Pinger, so Ping should be a no-op
	backend := NewMemoryStorage()
	ls := NewLoggingStorage(backend)

	err := ls.Ping(context.Background())
	if err != nil {
		t.Errorf("Expected no error from Ping on non-Pinger backend, got %v", err)
	}
}

// pingableStorage embeds MemoryStorage and adds a Ping method to satisfy the Pinger interface.
type pingableStorage struct {
	*MemoryStorage
	pingErr error
}

func (p *pingableStorage) Ping(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return p.pingErr
}

func TestLoggingStorage_Ping_Success(t *testing.T) {
	backend := &pingableStorage{MemoryStorage: NewMemoryStorage()}
	ls := NewLoggingStorage(backend)

	err := ls.Ping(context.Background())
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestLoggingStorage_Ping_Error(t *testing.T) {
	backend := &pingableStorage{
		MemoryStorage: NewMemoryStorage(),
		pingErr:       NewServiceUnavailableError("db down", nil),
	}
	ls := NewLoggingStorage(backend)

	err := ls.Ping(context.Background())
	if err == nil {
		t.Fatal("Expected error from Ping")
	}
}

func TestLoggingStorage_GetACsByServer_Empty(t *testing.T) {
	backend := NewMemoryStorage()
	ls := NewLoggingStorage(backend)
	ctx := context.Background()

	assignments, err := ls.GetACsByServer(ctx, "nonexistent-server")
	if err != nil {
		t.Fatalf("Expected no error for empty results, got %v", err)
	}
	if len(assignments) != 0 {
		t.Errorf("Expected empty slice, got %d assignments", len(assignments))
	}
}

func TestLoggingStorage_SlowOperation(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutACAssignment(CreateTestACAssignment("ac-slow", "srv-1"))
	// Inject 600ms delay to exceed the 500ms slow threshold
	backend.SetDelayOnNextCallForMethod("GetACAssignment", 600*time.Millisecond)

	ls := NewLoggingStorage(backend)
	ctx := context.Background()

	// Should succeed but trigger the Warning log path internally
	assignment, err := ls.GetACAssignment(ctx, "ac-slow")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if assignment.ACID != "ac-slow" {
		t.Errorf("Expected ACID 'ac-slow', got '%s'", assignment.ACID)
	}
}

func TestLoggingStorage_InterfaceCompliance(t *testing.T) {
	// Verify LoggingStorage implements StorageBackend
	var _ StorageBackend = (*LoggingStorage)(nil)
}

func TestContextWithRequestID(t *testing.T) {
	ctx := context.Background()

	// No request ID — should return "-".
	if s := requestIDFromCtx(ctx); s != "-" {
		t.Errorf("expected %q, got %q", "-", s)
	}

	// With request ID — should return the ID.
	ctx = ContextWithRequestID(ctx, "req-abc-123")
	if s := requestIDFromCtx(ctx); s != "req-abc-123" {
		t.Errorf("expected %q, got %q", "req-abc-123", s)
	}
}

func TestLoggingStorage_RequestIDPropagated(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutACAssignment(CreateTestACAssignment("ac-rid", "srv-1"))

	ls := NewLoggingStorage(backend)

	// Storage call with request ID should not error (verifies the ctx flows through).
	ctx := ContextWithRequestID(context.Background(), "req-test-456")
	assignment, err := ls.GetACAssignment(ctx, "ac-rid")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if assignment.ACID != "ac-rid" {
		t.Errorf("Expected ACID 'ac-rid', got '%s'", assignment.ACID)
	}
}

// contextCapturingStorage wraps a StorageBackend and records the context
// passed to each method call, so tests can verify request ID propagation.
type contextCapturingStorage struct {
	StorageBackend
	mu           sync.Mutex
	capturedCtxs []context.Context
}

// Compile-time assertion that contextCapturingStorage satisfies StorageBackend.
// The embedded StorageBackend provides this automatically, but the explicit
// check makes the intent obvious and catches removal of the embedding.
var _ StorageBackend = (*contextCapturingStorage)(nil)

func (c *contextCapturingStorage) captureCtx(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.capturedCtxs = append(c.capturedCtxs, ctx)
}

func (c *contextCapturingStorage) lastCapturedCtx() context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.capturedCtxs) == 0 {
		return nil
	}
	return c.capturedCtxs[len(c.capturedCtxs)-1]
}

func (c *contextCapturingStorage) GetACAssignment(ctx context.Context, acID string) (*ACAssignment, error) {
	c.captureCtx(ctx)
	return c.StorageBackend.GetACAssignment(ctx, acID)
}

func (c *contextCapturingStorage) GetACsByServer(ctx context.Context, serverID string) ([]ACAssignment, error) {
	c.captureCtx(ctx)
	return c.StorageBackend.GetACsByServer(ctx, serverID)
}

func (c *contextCapturingStorage) GetLicense(ctx context.Context, licenseKey string) (*License, error) {
	c.captureCtx(ctx)
	return c.StorageBackend.GetLicense(ctx, licenseKey)
}

func (c *contextCapturingStorage) GetResource(ctx context.Context, customerID, resourceID string) (*Resource, error) {
	c.captureCtx(ctx)
	return c.StorageBackend.GetResource(ctx, customerID, resourceID)
}

func (c *contextCapturingStorage) GetResourceByACID(ctx context.Context, acID string) ([]Resource, error) {
	c.captureCtx(ctx)
	return c.StorageBackend.GetResourceByACID(ctx, acID)
}

func (c *contextCapturingStorage) SaveACAssignment(ctx context.Context, assignment *ACAssignment) error {
	c.captureCtx(ctx)
	return c.StorageBackend.SaveACAssignment(ctx, assignment)
}

// TestLoggingStorage_RequestIDFlowsThroughToBackend verifies that a request ID
// set via ContextWithRequestID is present in the context received by the
// underlying storage backend. This proves the full propagation path:
//
//	HTTP middleware -> ContextWithRequestID -> LoggingStorage -> backend
func TestLoggingStorage_RequestIDFlowsThroughToBackend(t *testing.T) {
	t.Parallel()

	mem := NewMemoryStorage()
	mem.PutACAssignment(CreateTestACAssignment("ac-flow", "srv-1"))
	mem.PutLicenseWithKey(CreateTestLicense("lic-flow"), "lic-flow")
	mem.PutResource(CreateTestResource("cust-flow", "res-flow", "ac-flow"))

	capturing := &contextCapturingStorage{StorageBackend: mem}
	ls := NewLoggingStorage(capturing)

	const expectedID = "req-flow-test-789"
	ctx := ContextWithRequestID(context.Background(), expectedID)

	// Exercise every storage method that accepts a context and verify the
	// request ID is preserved in the context the backend receives.

	tests := []struct {
		name string
		call func()
	}{
		{
			name: "GetACAssignment",
			call: func() { _, _ = ls.GetACAssignment(ctx, "ac-flow") },
		},
		{
			name: "GetACsByServer",
			call: func() { _, _ = ls.GetACsByServer(ctx, "srv-1") },
		},
		{
			name: "GetLicense",
			call: func() { _, _ = ls.GetLicense(ctx, "lic-flow") },
		},
		{
			name: "GetResource",
			call: func() { _, _ = ls.GetResource(ctx, "cust-flow", "res-flow") },
		},
		{
			name: "GetResourceByACID",
			call: func() { _, _ = ls.GetResourceByACID(ctx, "ac-flow") },
		},
		{
			name: "SaveACAssignment",
			call: func() { _ = ls.SaveACAssignment(ctx, CreateTestACAssignment("ac-save-flow", "srv-1")) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.call()

			capturedCtx := capturing.lastCapturedCtx()
			if capturedCtx == nil {
				t.Fatal("backend received no context")
			}

			got := requestIDFromCtx(capturedCtx)
			if got != expectedID {
				t.Errorf("request ID not propagated to backend: expected %q, got %q", expectedID, got)
			}
		})
	}
}

// TestLoggingStorage_NilContextRequestIDDefaultsToDash verifies that when no
// request ID is set in the context, requestIDFromCtx returns "-" (the default
// sentinel). This ensures log lines always have a parseable req_id field.
func TestLoggingStorage_NilContextRequestIDDefaultsToDash(t *testing.T) {
	t.Parallel()

	mem := NewMemoryStorage()
	mem.PutACAssignment(CreateTestACAssignment("ac-nil", "srv-1"))

	capturing := &contextCapturingStorage{StorageBackend: mem}
	ls := NewLoggingStorage(capturing)

	// Call with plain background context (no request ID).
	_, err := ls.GetACAssignment(context.Background(), "ac-nil")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	capturedCtx := capturing.lastCapturedCtx()
	if capturedCtx == nil {
		t.Fatal("backend received no context")
	}

	got := requestIDFromCtx(capturedCtx)
	if got != "-" {
		t.Errorf("expected default sentinel %q for missing request ID, got %q", "-", got)
	}
}
