package server

import (
	"context"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// MemoryStorage Basic Operations Tests
// ============================================================================

func TestMemoryStorage_Name(t *testing.T) {
	storage := NewMemoryStorage()
	if storage.Name() != "memory" {
		t.Errorf("Expected name 'memory', got '%s'", storage.Name())
	}
}

func TestMemoryStorage_ACAssignment_PutAndGet(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Put assignment
	assignment := CreateTestACAssignment("ac-1", "srv-a", "srv-b", "srv-c")
	storage.PutACAssignment(assignment)

	// Get assignment
	retrieved, err := storage.GetACAssignment(ctx, "ac-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify fields
	if retrieved.ACID != "ac-1" {
		t.Errorf("Expected ACID 'ac-1', got '%s'", retrieved.ACID)
	}
	if len(retrieved.AssignedServers) != 3 {
		t.Errorf("Expected 3 servers, got %d", len(retrieved.AssignedServers))
	}
	if retrieved.AssignedServers[0].ID != "srv-a" {
		t.Errorf("Expected first server 'srv-a', got '%s'", retrieved.AssignedServers[0].ID)
	}
}

func TestMemoryStorage_ACAssignment_NotFound(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	_, err := storage.GetACAssignment(ctx, "nonexistent")
	if err == nil {
		t.Fatal("Expected error for nonexistent AC")
	}
	if !IsNotFoundError(err) {
		t.Errorf("Expected NOT_FOUND error, got %v", err)
	}
}

func TestMemoryStorage_ACAssignment_Delete(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Put then delete
	storage.PutACAssignment(CreateTestACAssignment("ac-delete", "srv-1"))
	storage.DeleteACAssignment("ac-delete")

	// Verify deleted
	_, err := storage.GetACAssignment(ctx, "ac-delete")
	if !IsNotFoundError(err) {
		t.Error("Expected NOT_FOUND after delete")
	}
}

func TestMemoryStorage_ACAssignment_Mutation_Isolation(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Put assignment
	original := CreateTestACAssignment("ac-iso", "srv-1")
	storage.PutACAssignment(original)

	// Modify original
	original.CustomerID = "modified-customer"
	original.AssignedServers[0].ID = "modified-srv"

	// Get should return unmodified copy
	retrieved, _ := storage.GetACAssignment(ctx, "ac-iso")
	if retrieved.CustomerID == "modified-customer" {
		t.Error("Storage should not be affected by mutations to original")
	}
	if retrieved.AssignedServers[0].ID == "modified-srv" {
		t.Error("Storage should not be affected by mutations to original servers")
	}
}

func TestMemoryStorage_GetACsByServer(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Create assignments with overlapping servers
	storage.PutACAssignment(CreateTestACAssignment("ac-1", "srv-a", "srv-b", "srv-c"))
	storage.PutACAssignment(CreateTestACAssignment("ac-2", "srv-b", "srv-c", "srv-d"))
	storage.PutACAssignment(CreateTestACAssignment("ac-3", "srv-e", "srv-f", "srv-g"))

	// Query for srv-b (should return ac-1 and ac-2)
	results, err := storage.GetACsByServer(ctx, "srv-b")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("Expected 2 ACs for srv-b, got %d", len(results))
	}

	// Verify both ac-1 and ac-2 are in results
	foundAC1, foundAC2 := false, false
	for _, r := range results {
		if r.ACID == "ac-1" {
			foundAC1 = true
		}
		if r.ACID == "ac-2" {
			foundAC2 = true
		}
	}
	if !foundAC1 || !foundAC2 {
		t.Error("Expected both ac-1 and ac-2 in results")
	}

	// Query for srv-e (should return only ac-3)
	results, _ = storage.GetACsByServer(ctx, "srv-e")
	if len(results) != 1 || results[0].ACID != "ac-3" {
		t.Error("Expected only ac-3 for srv-e")
	}
}

func TestMemoryStorage_License_PutAndGet(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Put license
	license := CreateTestLicense("cust-1", "resource.nhp.test")
	storage.PutLicense(license)

	// Get license
	retrieved, err := storage.GetLicense(ctx, "cust-1", "resource.nhp.test")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if retrieved.CustomerID != "cust-1" {
		t.Errorf("Expected CustomerID 'cust-1', got '%s'", retrieved.CustomerID)
	}
	if retrieved.Tier != "pro" {
		t.Errorf("Expected Tier 'pro', got '%s'", retrieved.Tier)
	}
	if !retrieved.Active {
		t.Error("Expected Active to be true")
	}
}

func TestMemoryStorage_License_NotFound(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	_, err := storage.GetLicense(ctx, "nonexistent", "resource.nhp.test")
	if !IsNotFoundError(err) {
		t.Errorf("Expected NOT_FOUND error, got %v", err)
	}
}

func TestMemoryStorage_Resource_PutAndGet(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Put resource
	resource := CreateTestResource("cust-1", "res-1", "ac-1")
	storage.PutResource(resource)

	// Get resource
	retrieved, err := storage.GetResource(ctx, "cust-1", "res-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if retrieved.ResourceID != "res-1" {
		t.Errorf("Expected ResourceID 'res-1', got '%s'", retrieved.ResourceID)
	}
	if retrieved.ACID != "ac-1" {
		t.Errorf("Expected ACID 'ac-1', got '%s'", retrieved.ACID)
	}
}

func TestMemoryStorage_GetResourceByACID(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Put multiple resources for same AC
	storage.PutResource(CreateTestResource("cust-1", "res-1", "ac-1"))
	storage.PutResource(CreateTestResource("cust-1", "res-2", "ac-1"))
	storage.PutResource(CreateTestResource("cust-1", "res-3", "ac-2")) // Different AC

	// Get resources for ac-1
	resources, err := storage.GetResourceByACID(ctx, "ac-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(resources) != 2 {
		t.Fatalf("Expected 2 resources for ac-1, got %d", len(resources))
	}
}

func TestMemoryStorage_Close(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Add data
	storage.PutACAssignment(CreateTestACAssignment("ac-1", "srv-1"))
	storage.PutLicense(CreateTestLicense("cust-1", "res.nhp.test"))

	// Close
	err := storage.Close()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Data should be cleared
	_, err = storage.GetACAssignment(ctx, "ac-1")
	if !IsNotFoundError(err) {
		t.Error("Expected data to be cleared after Close")
	}
}

// ============================================================================
// Error Injection Tests
// ============================================================================

func TestMemoryStorage_ErrorInjection_NextCall(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Put data first
	storage.PutACAssignment(CreateTestACAssignment("ac-1", "srv-1"))

	// Set error for next call
	storage.SetErrorOnNextCall(ErrCodeServiceUnavail, "simulated outage")

	// First call should fail
	_, err := storage.GetACAssignment(ctx, "ac-1")
	if err == nil {
		t.Fatal("Expected error from injected error")
	}
	se, ok := err.(*StorageError)
	if !ok {
		t.Fatal("Expected StorageError")
	}
	if se.Code != ErrCodeServiceUnavail {
		t.Errorf("Expected SERVICE_UNAVAILABLE, got %s", se.Code)
	}

	// Second call should succeed (error was consumed)
	retrieved, err := storage.GetACAssignment(ctx, "ac-1")
	if err != nil {
		t.Fatalf("Expected success on second call, got: %v", err)
	}
	if retrieved.ACID != "ac-1" {
		t.Error("Expected correct data on second call")
	}
}

func TestMemoryStorage_ErrorInjection_SpecificMethod(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Put data
	storage.PutACAssignment(CreateTestACAssignment("ac-1", "srv-1"))
	storage.PutLicense(CreateTestLicense("cust-1", "res.nhp.test"))

	// Set error only for GetLicense
	storage.SetErrorOnNextCallForMethod("GetLicense", ErrCodeRateLimited, "rate limited")

	// GetACAssignment should succeed
	_, err := storage.GetACAssignment(ctx, "ac-1")
	if err != nil {
		t.Fatalf("GetACAssignment should not be affected: %v", err)
	}

	// GetLicense should fail
	_, err = storage.GetLicense(ctx, "cust-1", "res.nhp.test")
	if err == nil {
		t.Fatal("Expected GetLicense to fail")
	}
}

func TestMemoryStorage_ErrorInjection_ServiceUnavailable(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	storage.SetServiceUnavailable("DynamoDB is down")

	_, err := storage.GetACAssignment(ctx, "ac-1")
	if err == nil {
		t.Fatal("Expected SERVICE_UNAVAILABLE error")
	}

	se, ok := err.(*StorageError)
	if !ok || se.Code != ErrCodeServiceUnavail {
		t.Error("Expected SERVICE_UNAVAILABLE error code")
	}
}

func TestMemoryStorage_ErrorInjection_ClearError(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	storage.PutACAssignment(CreateTestACAssignment("ac-1", "srv-1"))

	// Set and clear error
	storage.SetErrorOnNextCall(ErrCodeServiceUnavail, "test")
	storage.ClearError()

	// Should succeed
	_, err := storage.GetACAssignment(ctx, "ac-1")
	if err != nil {
		t.Fatalf("Expected success after ClearError: %v", err)
	}
}

// ============================================================================
// Delay Injection Tests
// ============================================================================

func TestMemoryStorage_DelayInjection(t *testing.T) {
	storage := NewMemoryStorage()

	storage.PutACAssignment(CreateTestACAssignment("ac-1", "srv-1"))

	// Set short delay
	delay := 100 * time.Millisecond
	storage.SetDelayOnNextCall(delay)

	// Measure time
	ctx := context.Background()
	start := time.Now()
	_, err := storage.GetACAssignment(ctx, "ac-1")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if elapsed < delay {
		t.Errorf("Expected delay of at least %v, got %v", delay, elapsed)
	}
}

func TestMemoryStorage_DelayInjection_ContextCancellation(t *testing.T) {
	storage := NewMemoryStorage()

	storage.PutACAssignment(CreateTestACAssignment("ac-1", "srv-1"))

	// Set long delay
	storage.SetDelayOnNextCall(5 * time.Second)

	// Create context that cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Should be cancelled before delay completes
	_, err := storage.GetACAssignment(ctx, "ac-1")
	if err != context.DeadlineExceeded {
		t.Errorf("Expected context.DeadlineExceeded, got %v", err)
	}
}

func TestMemoryStorage_DelayInjection_SpecificMethod(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	storage.PutACAssignment(CreateTestACAssignment("ac-1", "srv-1"))
	storage.PutLicense(CreateTestLicense("cust-1", "res.nhp.test"))

	// Set delay only for GetLicense
	storage.SetDelayOnNextCallForMethod("GetLicense", 100*time.Millisecond)

	// GetACAssignment should be fast
	start := time.Now()
	storage.GetACAssignment(ctx, "ac-1")
	acElapsed := time.Since(start)

	// GetLicense should be slow
	start = time.Now()
	storage.GetLicense(ctx, "cust-1", "res.nhp.test")
	licElapsed := time.Since(start)

	if acElapsed > 50*time.Millisecond {
		t.Errorf("GetACAssignment should not be delayed: %v", acElapsed)
	}
	if licElapsed < 100*time.Millisecond {
		t.Errorf("GetLicense should be delayed: %v", licElapsed)
	}
}

// ============================================================================
// Call Metrics Tests
// ============================================================================

func TestMemoryStorage_CallCounts(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	storage.PutACAssignment(CreateTestACAssignment("ac-1", "srv-1"))

	// Make calls
	storage.GetACAssignment(ctx, "ac-1")
	storage.GetACAssignment(ctx, "ac-1")
	storage.GetACAssignment(ctx, "nonexistent") // Error case still counts
	storage.GetACsByServer(ctx, "srv-1")

	// Check counts
	if storage.GetCallCount("GetACAssignment") != 3 {
		t.Errorf("Expected 3 GetACAssignment calls, got %d", storage.GetCallCount("GetACAssignment"))
	}
	if storage.GetCallCount("GetACsByServer") != 1 {
		t.Errorf("Expected 1 GetACsByServer call, got %d", storage.GetCallCount("GetACsByServer"))
	}
	if storage.GetTotalCallCount() != 4 {
		t.Errorf("Expected 4 total calls, got %d", storage.GetTotalCallCount())
	}
}

func TestMemoryStorage_ResetCallCounts(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	storage.PutACAssignment(CreateTestACAssignment("ac-1", "srv-1"))
	storage.GetACAssignment(ctx, "ac-1")
	storage.GetACAssignment(ctx, "ac-1")

	if storage.GetCallCount("GetACAssignment") != 2 {
		t.Fatal("Expected 2 calls before reset")
	}

	storage.ResetCallCounts()

	if storage.GetCallCount("GetACAssignment") != 0 {
		t.Error("Expected 0 calls after reset")
	}
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestMemoryStorage_ConcurrentAccess(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	var wg sync.WaitGroup
	goroutines := 20
	iterations := 100

	// Pre-populate some data
	for i := 0; i < 10; i++ {
		storage.PutACAssignment(CreateTestACAssignment("ac-"+string(rune('A'+i)), "srv-1"))
	}

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				switch i % 5 {
				case 0:
					storage.PutACAssignment(CreateTestACAssignment("ac-concurrent-"+string(rune('A'+gid%10)), "srv-x"))
				case 1:
					storage.GetACAssignment(ctx, "ac-"+string(rune('A'+i%10)))
				case 2:
					storage.GetACsByServer(ctx, "srv-1")
				case 3:
					storage.DeleteACAssignment("ac-concurrent-" + string(rune('A'+(gid+1)%10)))
				case 4:
					storage.Clear()
				}
			}
		}(g)
	}

	wg.Wait()
	// If we get here without panic/race, the test passes
}

// ============================================================================
// Test Helper Tests
// ============================================================================

func TestCreateTestACAssignment(t *testing.T) {
	assignment := CreateTestACAssignment("my-ac", "srv-1", "srv-2")

	if assignment.ACID != "my-ac" {
		t.Errorf("Expected ACID 'my-ac', got '%s'", assignment.ACID)
	}
	if len(assignment.AssignedServers) != 2 {
		t.Fatalf("Expected 2 servers, got %d", len(assignment.AssignedServers))
	}
	if assignment.AssignedServers[0].ID != "srv-1" {
		t.Errorf("Expected first server 'srv-1', got '%s'", assignment.AssignedServers[0].ID)
	}
	if assignment.Version != 1 {
		t.Error("Expected version 1")
	}
}

func TestCreateTestLicense(t *testing.T) {
	license := CreateTestLicense("cust-123", "my.nhp.test")

	if license.CustomerID != "cust-123" {
		t.Errorf("Expected CustomerID 'cust-123', got '%s'", license.CustomerID)
	}
	if license.ResourceFQDN != "my.nhp.test" {
		t.Errorf("Expected ResourceFQDN 'my.nhp.test', got '%s'", license.ResourceFQDN)
	}
	if !license.Active {
		t.Error("Expected Active to be true")
	}
	if license.ExpiresAt <= time.Now().Unix() {
		t.Error("Expected ExpiresAt to be in the future")
	}
}

func TestCreateTestResource(t *testing.T) {
	resource := CreateTestResource("cust-1", "res-1", "ac-1")

	if resource.CustomerID != "cust-1" {
		t.Errorf("Expected CustomerID 'cust-1', got '%s'", resource.CustomerID)
	}
	if resource.ResourceID != "res-1" {
		t.Errorf("Expected ResourceID 'res-1', got '%s'", resource.ResourceID)
	}
	if resource.ACID != "ac-1" {
		t.Errorf("Expected ACID 'ac-1', got '%s'", resource.ACID)
	}
	if resource.DestPort != 443 {
		t.Errorf("Expected DestPort 443, got %d", resource.DestPort)
	}
}

// ============================================================================
// CachedStorage Error Handling Tests
// ============================================================================

func TestCachedStorage_BackendError_NotCached(t *testing.T) {
	backend := NewMemoryStorage()
	cached := NewCachedStorage(backend, CacheConfig{
		MaxEntries: 100,
		DefaultTTL: 60,
	})

	ctx := context.Background()

	// Inject error
	backend.SetErrorOnNextCall(ErrCodeServiceUnavail, "backend down")

	// First call should fail
	_, err := cached.GetACAssignment(ctx, "ac-1")
	if err == nil {
		t.Fatal("Expected error")
	}

	// Now add data
	backend.PutACAssignment(CreateTestACAssignment("ac-1", "srv-1"))

	// Second call should succeed (error was not cached)
	_, err = cached.GetACAssignment(ctx, "ac-1")
	if err != nil {
		t.Fatalf("Expected success: %v", err)
	}
}
