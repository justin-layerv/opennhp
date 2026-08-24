package server

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// ============================================================================
// AssignmentCache Tests
// ============================================================================

func TestAssignmentCache_BasicOperations(t *testing.T) {
	config := CacheConfig{
		MaxEntries:         100,
		DefaultTTL:         60,
		ReassignmentTTL:    5,
		ReassignmentWindow: 300,
	}
	cache := NewAssignmentCache(config)

	// Test Set and Get
	assignment := &ACAssignment{
		ACID:         "ac-test-1",
		ResourceFQDN: "test.nhp.example.com",
		CustomerID:   "cust-123",
		AssignedServers: []ServerInfo{
			{ID: "srv-1", IP: "10.0.0.1", Port: common.DefaultNHPPort},
		},
	}

	cache.Set("ac-test-1", assignment)

	retrieved := cache.Get("ac-test-1")
	if retrieved == nil {
		t.Fatal("Expected to retrieve cached assignment, got nil")
	}
	if retrieved.ACID != "ac-test-1" {
		t.Errorf("Expected ACID 'ac-test-1', got '%s'", retrieved.ACID)
	}

	// Test Get non-existent
	missing := cache.Get("non-existent")
	if missing != nil {
		t.Error("Expected nil for non-existent key")
	}

	// Test Delete
	cache.Delete("ac-test-1")
	deleted := cache.Get("ac-test-1")
	if deleted != nil {
		t.Error("Expected nil after delete")
	}
}

func TestAssignmentCache_TTLExpiration(t *testing.T) {
	config := CacheConfig{
		MaxEntries:         100,
		DefaultTTL:         1, // 1 second TTL for testing
		ReassignmentTTL:    1,
		ReassignmentWindow: 300,
	}
	cache := NewAssignmentCache(config)

	assignment := &ACAssignment{
		ACID: "ac-ttl-test",
	}

	cache.Set("ac-ttl-test", assignment)

	// Should be retrievable immediately
	if cache.Get("ac-ttl-test") == nil {
		t.Fatal("Expected to retrieve cached assignment immediately")
	}

	// Wait for TTL to expire
	time.Sleep(1100 * time.Millisecond)

	// Should be expired now
	if cache.Get("ac-ttl-test") != nil {
		t.Error("Expected nil after TTL expiration")
	}
}

func TestAssignmentCache_AdaptiveTTL(t *testing.T) {
	config := CacheConfig{
		MaxEntries:         100,
		DefaultTTL:         60,
		ReassignmentTTL:    1, // Short TTL during reassignment
		ReassignmentWindow: 300,
	}
	cache := NewAssignmentCache(config)

	// Assignment that was recently reassigned
	reassignedAt := time.Now().Unix()
	assignment := &ACAssignment{
		ACID:         "ac-reassigned",
		ReassignedAt: &reassignedAt,
	}

	cache.Set("ac-reassigned", assignment)

	// Should be retrievable immediately
	if cache.Get("ac-reassigned") == nil {
		t.Fatal("Expected to retrieve cached assignment immediately")
	}

	// Wait for short TTL to expire (ReassignmentTTL = 1 second)
	time.Sleep(1100 * time.Millisecond)

	// Should be expired due to short reassignment TTL
	if cache.Get("ac-reassigned") != nil {
		t.Error("Expected nil after reassignment TTL expiration")
	}
}

func TestAssignmentCache_ConcurrentAccess(t *testing.T) {
	config := CacheConfig{
		MaxEntries:         1000,
		DefaultTTL:         60,
		ReassignmentTTL:    5,
		ReassignmentWindow: 300,
	}
	cache := NewAssignmentCache(config)

	// Run concurrent reads and writes
	var wg sync.WaitGroup
	iterations := 100
	goroutines := 10

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				key := "ac-concurrent-" + string(rune('A'+gid))
				assignment := &ACAssignment{
					ACID:       key,
					CustomerID: "cust-" + string(rune('0'+i%10)),
				}

				// Mix of operations
				switch i % 4 {
				case 0:
					cache.Set(key, assignment)
				case 1:
					cache.Get(key)
				case 2:
					cache.Get("non-existent-" + string(rune('0'+i%10)))
				case 3:
					cache.Delete(key)
				}
			}
		}(g)
	}

	wg.Wait()
	// If we get here without panic/race, the test passes
}

func TestAssignmentCache_Eviction(t *testing.T) {
	config := CacheConfig{
		MaxEntries:         3, // Small capacity
		DefaultTTL:         60,
		ReassignmentTTL:    5,
		ReassignmentWindow: 300,
	}
	cache := NewAssignmentCache(config)

	// Fill cache beyond capacity
	for i := 0; i < 5; i++ {
		key := "ac-evict-" + string(rune('A'+i))
		cache.Set(key, &ACAssignment{ACID: key})
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	}

	// Cache should have at most MaxEntries
	count := 0
	for i := 0; i < 5; i++ {
		key := "ac-evict-" + string(rune('A'+i))
		if cache.Get(key) != nil {
			count++
		}
	}

	if count > config.MaxEntries {
		t.Errorf("Expected at most %d entries, got %d", config.MaxEntries, count)
	}
}

// ============================================================================
// CachedStorage Tests
// ============================================================================

// mockStorageBackend implements StorageBackend for testing
type mockStorageBackend struct {
	assignments map[string]*ACAssignment
	callCount   int
	mu          sync.Mutex

	// saveOverride, when non-nil, is called instead of the normal CAS save
	// path. Lets tests inject deterministic SaveACAssignment outcomes
	// (e.g., simulated VersionConflictError on the refresh path) without
	// racing two goroutines for timing.
	saveOverride func(*ACAssignment) error
}

func (*mockStorageBackend) acAssignmentCacheSafeLeaf() {}

func newMockStorageBackend() *mockStorageBackend {
	return &mockStorageBackend{
		assignments: make(map[string]*ACAssignment),
	}
}

func (m *mockStorageBackend) GetACAssignment(ctx context.Context, acID string) (*ACAssignment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++

	if assignment, ok := m.assignments[acID]; ok {
		return assignment, nil
	}
	return nil, NewNotFoundError("AC not found: " + acID)
}

func (m *mockStorageBackend) GetACsByServer(ctx context.Context, serverID string) ([]ACAssignment, error) {
	return nil, NewNotFoundError("not implemented")
}

func (m *mockStorageBackend) GetLicense(ctx context.Context, licenseKey string) (*License, error) {
	return nil, NewNotFoundError("not implemented")
}

func (m *mockStorageBackend) GetResource(ctx context.Context, customerID, resourceID string) (*Resource, error) {
	return nil, NewNotFoundError("not implemented")
}

func (m *mockStorageBackend) GetResourceByACID(ctx context.Context, acID string) ([]Resource, error) {
	return nil, NewNotFoundError("not implemented")
}

func (m *mockStorageBackend) SaveACAssignment(ctx context.Context, assignment *ACAssignment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveOverride != nil {
		return m.saveOverride(assignment)
	}
	// Mirror DynamoDBStorage's optimistic-locking conditional so tests
	// structurally fence the version-bump invariant: a Save with Version
	// not equal to existing.Version+1 (or != 1 for a brand-new row) is a
	// VersionConflictError. Without this, refreshAssignmentTTL's silent
	// Version-not-bumped no-op (the latent bug fixed in #1681) would
	// pass tests against this mock even though prod DDB rejected the
	// write.
	if existing, ok := m.assignments[assignment.ACID]; ok {
		if assignment.Version != existing.Version+1 {
			return NewVersionConflictError(fmt.Sprintf("expected version %d, got %d", existing.Version+1, assignment.Version))
		}
	}
	m.assignments[assignment.ACID] = assignment
	return nil
}

func (m *mockStorageBackend) Close() error {
	return nil
}

func (m *mockStorageBackend) Name() string {
	return "mock"
}

func TestCachedStorage_CacheHit(t *testing.T) {
	backend := newMockStorageBackend()
	backend.assignments["ac-cache-hit"] = &ACAssignment{
		ACID:       "ac-cache-hit",
		CustomerID: "cust-123",
	}

	config := CacheConfig{
		MaxEntries:         100,
		DefaultTTL:         60,
		ReassignmentTTL:    5,
		ReassignmentWindow: 300,
	}
	cached := NewCachedStorage(backend, config)

	ctx := context.Background()

	// First call - cache miss, should hit backend
	result1, err := cached.GetACAssignment(ctx, "ac-cache-hit")
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}
	if result1.ACID != "ac-cache-hit" {
		t.Errorf("Expected ACID 'ac-cache-hit', got '%s'", result1.ACID)
	}
	if backend.callCount != 1 {
		t.Errorf("Expected 1 backend call, got %d", backend.callCount)
	}

	// Second call - cache hit, should NOT hit backend
	result2, err := cached.GetACAssignment(ctx, "ac-cache-hit")
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}
	if result2.ACID != "ac-cache-hit" {
		t.Errorf("Expected ACID 'ac-cache-hit', got '%s'", result2.ACID)
	}
	if backend.callCount != 1 {
		t.Errorf("Expected still 1 backend call (cache hit), got %d", backend.callCount)
	}
}

func TestCachedStorage_CacheMiss(t *testing.T) {
	backend := newMockStorageBackend()

	config := CacheConfig{
		MaxEntries:         100,
		DefaultTTL:         60,
		ReassignmentTTL:    5,
		ReassignmentWindow: 300,
	}
	cached := NewCachedStorage(backend, config)

	ctx := context.Background()

	// Call for non-existent AC
	_, err := cached.GetACAssignment(ctx, "non-existent")
	if err == nil {
		t.Fatal("Expected error for non-existent AC")
	}
	if !IsNotFoundError(err) {
		t.Errorf("Expected NotFoundError, got %T: %v", err, err)
	}
}

func TestCachedStorage_InvalidateCache(t *testing.T) {
	backend := newMockStorageBackend()
	backend.assignments["ac-invalidate"] = &ACAssignment{
		ACID:       "ac-invalidate",
		CustomerID: "cust-123",
	}

	config := CacheConfig{
		MaxEntries:         100,
		DefaultTTL:         60,
		ReassignmentTTL:    5,
		ReassignmentWindow: 300,
	}
	cached := NewCachedStorage(backend, config)

	ctx := context.Background()

	// Prime the cache
	_, _ = cached.GetACAssignment(ctx, "ac-invalidate")
	if backend.callCount != 1 {
		t.Fatalf("Expected 1 backend call, got %d", backend.callCount)
	}

	// Invalidate
	cached.InvalidateACAssignment("ac-invalidate")

	// Next call should hit backend again
	_, _ = cached.GetACAssignment(ctx, "ac-invalidate")
	if backend.callCount != 2 {
		t.Errorf("Expected 2 backend calls after invalidation, got %d", backend.callCount)
	}
}

func TestCachedStorage_Name(t *testing.T) {
	backend := newMockStorageBackend()
	config := CacheConfig{MaxEntries: 100, DefaultTTL: 60}
	cached := NewCachedStorage(backend, config)

	name := cached.Name()
	if name != "mock (cached)" {
		t.Errorf("Expected 'mock (cached)', got '%s'", name)
	}
}

func TestCachedStorage_Backend(t *testing.T) {
	backend := newMockStorageBackend()
	config := CacheConfig{MaxEntries: 100, DefaultTTL: 60}
	cached := NewCachedStorage(backend, config)

	// Backend() should return the underlying storage backend
	if cached.Backend() != backend {
		t.Error("Backend() should return the underlying storage backend")
	}
}

// TestCachedStorage_SaveACAssignment_NormalizesEmptyRevokedPubKeys fences
// #1545: a caller that builds the empty case as []string{} (violating
// the nil construction contract on ACAssignment.RevokedPubKeys) and
// saves directly — without going through Clone — must still persist the
// field as an omitted attribute, not a DDB NULL. SaveACAssignment Clones
// at the boundary and Clone normalizes empty→nil, so the backend never
// sees a non-nil empty slice and the rule stops being load-bearing on
// every write caller remembering to Clone.
func TestCachedStorage_SaveACAssignment_NormalizesEmptyRevokedPubKeys(t *testing.T) {
	backend := newMockStorageBackend()
	cached := NewCachedStorage(backend, CacheConfig{MaxEntries: 100, DefaultTTL: 60})
	ctx := context.Background()

	if err := cached.SaveACAssignment(ctx, &ACAssignment{
		ACID:           "ac-1545",
		Version:        1,
		RevokedPubKeys: []string{},
	}); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	// What the backend actually received must be nil, not []string{}.
	saved := backend.assignments["ac-1545"]
	if saved == nil {
		t.Fatal("assignment not persisted to backend")
	}
	if saved.RevokedPubKeys != nil {
		t.Errorf("backend RevokedPubKeys = %#v, want nil (empty must normalize at the write boundary)", saved.RevokedPubKeys)
	}

	// A cache-served read must agree with a backend-served read.
	got, err := cached.GetACAssignment(ctx, "ac-1545")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if got.RevokedPubKeys != nil {
		t.Errorf("cached RevokedPubKeys = %#v, want nil", got.RevokedPubKeys)
	}
}

// TestCachedStorage_SaveACAssignment_PreservesNonEmptyRevokedPubKeys is
// the companion to the normalization fence: the empty→nil rule must NOT
// drop a real revocation list.
func TestCachedStorage_SaveACAssignment_PreservesNonEmptyRevokedPubKeys(t *testing.T) {
	backend := newMockStorageBackend()
	cached := NewCachedStorage(backend, CacheConfig{MaxEntries: 100, DefaultTTL: 60})
	ctx := context.Background()

	want := []string{"pk-a", "pk-b"}
	if err := cached.SaveACAssignment(ctx, &ACAssignment{
		ACID:           "ac-1545-nonempty",
		Version:        1,
		RevokedPubKeys: want,
	}); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	saved := backend.assignments["ac-1545-nonempty"]
	if saved == nil {
		t.Fatal("assignment not persisted to backend")
	}
	if len(saved.RevokedPubKeys) != 2 || saved.RevokedPubKeys[0] != "pk-a" || saved.RevokedPubKeys[1] != "pk-b" {
		t.Errorf("backend RevokedPubKeys = %#v, want %#v", saved.RevokedPubKeys, want)
	}
}

// TestCachedStorage_GetACAssignment_ReturnsOwnedCopy fences #1540:
// GetACAssignment must hand callers an exclusively-owned copy, never the
// cache's internal pointer, on BOTH the cache-miss and cache-hit paths.
// A caller mutating the result must not affect what a subsequent caller
// reads — otherwise a future in-place mutator races the F4/F5
// registration kernels reading the same cached entry on a concurrent
// AOL. The backend here is intentionally non-cloning (mockStorageBackend
// returns its stored pointer), so any surviving aliasing would be
// CachedStorage's own.
func TestCachedStorage_GetACAssignment_ReturnsOwnedCopy(t *testing.T) {
	backend := newMockStorageBackend()
	backend.assignments["ac-1540"] = &ACAssignment{
		ACID:            "ac-1540",
		RevokedPubKeys:  []string{"pk-orig"},
		AssignedServers: []ServerInfo{{ID: "srv-1", IP: "10.0.0.1"}},
	}
	cached := NewCachedStorage(backend, CacheConfig{MaxEntries: 100, DefaultTTL: 60})
	ctx := context.Background()

	// First call is a cache MISS (populates the cache from the backend).
	got1, err := cached.GetACAssignment(ctx, "ac-1540")
	if err != nil {
		t.Fatalf("get1 failed: %v", err)
	}
	// Tamper with every reference-typed field of the returned copy.
	got1.RevokedPubKeys[0] = "pk-TAMPERED"
	got1.RevokedPubKeys = append(got1.RevokedPubKeys, "pk-EXTRA")
	got1.AssignedServers[0].IP = "6.6.6.6"

	// Second call is a cache HIT — must be pristine, proving got1's
	// mutations did not reach the cached entry (miss-path clone).
	got2, err := cached.GetACAssignment(ctx, "ac-1540")
	if err != nil {
		t.Fatalf("get2 failed: %v", err)
	}
	if got2 == got1 {
		t.Error("GetACAssignment returned the same pointer twice; expected independent copies")
	}
	if len(got2.RevokedPubKeys) != 1 || got2.RevokedPubKeys[0] != "pk-orig" {
		t.Errorf("cached RevokedPubKeys corrupted by caller mutation: %#v", got2.RevokedPubKeys)
	}
	if got2.AssignedServers[0].IP != "10.0.0.1" {
		t.Errorf("cached AssignedServers corrupted by caller mutation: IP=%q", got2.AssignedServers[0].IP)
	}

	// Tamper with the HIT-path copy and confirm a third HIT is still
	// pristine (hit-path clone).
	got2.RevokedPubKeys[0] = "pk-TAMPERED-AGAIN"
	got3, err := cached.GetACAssignment(ctx, "ac-1540")
	if err != nil {
		t.Fatalf("get3 failed: %v", err)
	}
	if got3.RevokedPubKeys[0] != "pk-orig" {
		t.Errorf("cached RevokedPubKeys corrupted via hit-path copy: %#v", got3.RevokedPubKeys)
	}
}

// TestCachedStorage_GetACAssignment_BackendNilNilDoesNotPanic guards the
// owned-copy clone against a backend (nil, nil) contract violation. A
// compliant backend returns ErrNotFound, never (nil, nil), but the gate
// and msghandler explicitly defend against the contract violation — so
// the tail Clone in GetACAssignment must not nil-panic before those
// caller-side guards run. Returns (nil, nil) gracefully, as the
// pre-clone code did. (nilNilStorage is defined in
// ac_pubkey_revoke_gate_test.go.)
func TestCachedStorage_GetACAssignment_BackendNilNilDoesNotPanic(t *testing.T) {
	backend := &nilNilStorage{MemoryStorage: NewMemoryStorage()}
	cached := NewCachedStorage(backend, CacheConfig{MaxEntries: 100, DefaultTTL: 60})

	got, err := cached.GetACAssignment(context.Background(), "ac-nilnil")
	if err != nil {
		t.Fatalf("expected nil error for (nil, nil) backend return, got %v", err)
	}
	if got != nil {
		t.Errorf("expected (nil, nil) graceful return, got %#v", got)
	}
}

// ============================================================================
// StorageError Tests
// ============================================================================

func TestStorageError_Error(t *testing.T) {
	// Error without wrapped error
	err1 := &StorageError{Code: ErrCodeNotFound, Message: "not found"}
	if err1.Error() != "not found" {
		t.Errorf("Expected 'not found', got '%s'", err1.Error())
	}

	// Error with wrapped error
	wrapped := &StorageError{Code: ErrCodeServiceUnavail, Message: "service down", Err: context.DeadlineExceeded}
	expected := "service down: context deadline exceeded"
	if wrapped.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, wrapped.Error())
	}
}

func TestIsNotFoundError(t *testing.T) {
	notFoundErr := NewNotFoundError("test not found")
	if !IsNotFoundError(notFoundErr) {
		t.Error("Expected IsNotFoundError to return true for NotFoundError")
	}

	serviceErr := NewServiceUnavailableError("service down", nil)
	if IsNotFoundError(serviceErr) {
		t.Error("Expected IsNotFoundError to return false for ServiceUnavailableError")
	}

	genericErr := context.DeadlineExceeded
	if IsNotFoundError(genericErr) {
		t.Error("Expected IsNotFoundError to return false for generic error")
	}
}

// ============================================================================
// DefaultStorageConfig Tests
// ============================================================================

func TestDefaultStorageConfig(t *testing.T) {
	cfg := DefaultStorageConfig()

	if cfg.Backend != "dynamodb" {
		t.Errorf("Expected backend 'dynamodb', got '%s'", cfg.Backend)
	}
	if cfg.DynamoDB.Region != "us-east-2" {
		t.Errorf("Expected region 'us-east-2', got '%s'", cfg.DynamoDB.Region)
	}
	if cfg.DynamoDB.RelayKeysTable != "" {
		t.Errorf("Expected RelayKeysTable empty by default, got '%s'", cfg.DynamoDB.RelayKeysTable)
	}
	if cfg.Cache.MaxEntries != 10000 {
		t.Errorf("Expected MaxEntries 10000, got %d", cfg.Cache.MaxEntries)
	}
	if cfg.Cache.DefaultTTL != 60 {
		t.Errorf("Expected DefaultTTL 60, got %d", cfg.Cache.DefaultTTL)
	}
	if cfg.Cache.ReassignmentTTL != 5 {
		t.Errorf("Expected ReassignmentTTL 5, got %d", cfg.Cache.ReassignmentTTL)
	}

	// CloudMap defaults
	if cfg.CloudMap.Enabled != false {
		t.Errorf("Expected CloudMap.Enabled false, got %v", cfg.CloudMap.Enabled)
	}
	// CloudMap should have empty config by default (user must configure)
	if cfg.CloudMap.Region != "" {
		t.Errorf("Expected CloudMap.Region empty, got '%s'", cfg.CloudMap.Region)
	}
	if cfg.CloudMap.NamespaceName != "" {
		t.Errorf("Expected CloudMap.NamespaceName empty, got '%s'", cfg.CloudMap.NamespaceName)
	}
	if cfg.CloudMap.ServiceName != "" {
		t.Errorf("Expected CloudMap.ServiceName empty, got '%s'", cfg.CloudMap.ServiceName)
	}
	// Configurable TTL/timeout should use defaults when 0
	if cfg.CloudMap.CacheTTL != 0 {
		t.Errorf("Expected CloudMap.CacheTTL 0 (use default), got %d", cfg.CloudMap.CacheTTL)
	}
	if cfg.CloudMap.OperationTimeout != 0 {
		t.Errorf("Expected CloudMap.OperationTimeout 0 (use default), got %d", cfg.CloudMap.OperationTimeout)
	}
	// Verify GetCacheTTL/GetOperationTimeout return defaults
	if cfg.CloudMap.GetCacheTTL() != DefaultCloudMapCacheTTL {
		t.Errorf("Expected GetCacheTTL() %v, got %v", DefaultCloudMapCacheTTL, cfg.CloudMap.GetCacheTTL())
	}
	if cfg.CloudMap.GetOperationTimeout() != DefaultCloudMapOperationTimeout {
		t.Errorf("Expected GetOperationTimeout() %v, got %v", DefaultCloudMapOperationTimeout, cfg.CloudMap.GetOperationTimeout())
	}
}

// ============================================================================
// LRU Eviction Tests (moved from forward_test.go)
// ============================================================================

func TestAssignmentCache_LRUEviction_UnderLoad(t *testing.T) {
	// Create small cache
	cache := NewAssignmentCache(CacheConfig{
		MaxEntries: 10,
		DefaultTTL: 60,
	})

	// Add more entries than capacity
	for i := 0; i < 20; i++ {
		assignment := CreateTestACAssignment("ac-lru-"+string(rune('A'+i)), "srv-1")
		cache.Set(assignment.ACID, assignment)
	}

	// Cache should not exceed MaxEntries
	if cache.Len() > 10 {
		t.Errorf("Cache exceeded max entries: %d > 10", cache.Len())
	}

	// Most recent entries should still be present
	// (LRU evicts least recently used)
	recentHits := 0
	for i := 15; i < 20; i++ {
		if cache.Get("ac-lru-"+string(rune('A'+i))) != nil {
			recentHits++
		}
	}

	// At least some recent entries should be cached
	if recentHits < 3 {
		t.Errorf("Expected at least 3 recent entries cached, got %d", recentHits)
	}
}

func TestAssignmentCache_LRUEviction_AccessPattern(t *testing.T) {
	cache := NewAssignmentCache(CacheConfig{
		MaxEntries: 5,
		DefaultTTL: 60,
	})

	// Add 5 entries
	for i := 0; i < 5; i++ {
		assignment := CreateTestACAssignment("ac-access-"+string(rune('A'+i)), "srv-1")
		cache.Set(assignment.ACID, assignment)
	}

	// Access entry A multiple times (making it recently used)
	for i := 0; i < 10; i++ {
		cache.Get("ac-access-A")
	}

	// Add new entry - should evict least recently used (B, C, D, or E)
	cache.Set("ac-access-NEW", CreateTestACAssignment("ac-access-NEW", "srv-1"))

	// Entry A should still be present (recently accessed)
	if cache.Get("ac-access-A") == nil {
		t.Error("Recently accessed entry A should not be evicted")
	}

	// New entry should be present
	if cache.Get("ac-access-NEW") == nil {
		t.Error("New entry should be present")
	}
}

func TestAssignmentCache_ConcurrentEviction(t *testing.T) {
	cache := NewAssignmentCache(CacheConfig{
		MaxEntries: 100,
		DefaultTTL: 60,
	})

	var wg sync.WaitGroup
	goroutines := 20
	entriesPerGoroutine := 50

	// Concurrent writes causing evictions
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < entriesPerGoroutine; i++ {
				id := "ac-concurrent-" + string(rune('A'+gid)) + "-" + string(rune('0'+i%10))
				assignment := CreateTestACAssignment(id, "srv-1")
				cache.Set(id, assignment)

				// Also do some reads
				cache.Get(id)
			}
		}(g)
	}

	wg.Wait()

	// Should not exceed max entries
	if cache.Len() > 100 {
		t.Errorf("Cache exceeded max entries after concurrent access: %d > 100", cache.Len())
	}
}

// ============================================================================
// CachedStorage Integration Tests (moved from forward_test.go)
// ============================================================================

func TestCachedStorage_ReducesBackendCalls(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutACAssignment(CreateTestACAssignment("ac-cached", "srv-1", "srv-2"))

	cached := NewCachedStorage(backend, CacheConfig{
		MaxEntries: 100,
		DefaultTTL: 60,
	})

	ctx := context.Background()

	// Simulate 100 knock lookups for same AC
	for i := 0; i < 100; i++ {
		_, err := cached.GetACAssignment(ctx, "ac-cached")
		if err != nil {
			t.Fatalf("Lookup %d failed: %v", i, err)
		}
	}

	// Should only have 1 backend call (cache hit for remaining 99)
	if backend.GetCallCount("GetACAssignment") != 1 {
		t.Errorf("Expected 1 backend call (cached), got %d", backend.GetCallCount("GetACAssignment"))
	}
}

func TestAssignmentCache_AdaptiveTTL_Reassignment(t *testing.T) {
	backend := NewMemoryStorage()

	// Assignment with recent reassignment
	assignment := CreateTestACAssignment("ac-reassigned", "srv-new-1", "srv-new-2")
	now := time.Now().Unix()
	assignment.ReassignedAt = &now // Just reassigned

	backend.PutACAssignment(assignment)

	// Create cache with 60s default TTL, 5s reassignment TTL
	cache := NewAssignmentCache(CacheConfig{
		MaxEntries:         100,
		DefaultTTL:         60,
		ReassignmentTTL:    1, // 1 second for faster testing
		ReassignmentWindow: 60,
	})

	// Add to cache
	cache.Set("ac-reassigned", assignment)

	// Should be valid immediately
	if cache.Get("ac-reassigned") == nil {
		t.Fatal("Expected cache hit immediately after set")
	}

	// Wait for short TTL to expire
	time.Sleep(1500 * time.Millisecond)

	// Should be expired due to reassignment TTL (1s)
	if cache.Get("ac-reassigned") != nil {
		t.Error("Expected cache miss after reassignment TTL")
	}
}

func TestCachedStorage_ServesDuringOutage(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutACAssignment(CreateTestACAssignment("ac-cached-outage", "srv-1"))

	cached := NewCachedStorage(backend, CacheConfig{
		MaxEntries: 100,
		DefaultTTL: 60,
	})

	ctx := context.Background()

	// Warm the cache
	_, err := cached.GetACAssignment(ctx, "ac-cached-outage")
	if err != nil {
		t.Fatalf("Initial lookup failed: %v", err)
	}

	// Simulate storage outage
	backend.SetServiceUnavailable("outage")

	// Cache hit should still work during outage!
	assignment, err := cached.GetACAssignment(ctx, "ac-cached-outage")
	if err != nil {
		t.Fatalf("Cached lookup should succeed during outage: %v", err)
	}
	if assignment.ACID != "ac-cached-outage" {
		t.Error("Wrong cached assignment")
	}

	// But lookup for uncached item should fail
	_, err = cached.GetACAssignment(ctx, "ac-not-cached")
	if err == nil {
		t.Error("Expected error for uncached item during outage")
	}
}

func TestCachedStorage_InvalidationOnReassign(t *testing.T) {
	backend := NewMemoryStorage()

	// Initial assignment: servers A, B, C
	initialAssignment := CreateTestACAssignment("ac-reassign", "srv-a", "srv-b", "srv-c")
	backend.PutACAssignment(initialAssignment)

	cached := NewCachedStorage(backend, CacheConfig{
		MaxEntries:         100,
		DefaultTTL:         60,
		ReassignmentTTL:    1, // 1 second for faster testing
		ReassignmentWindow: 60,
	})

	ctx := context.Background()

	// Load into cache
	assignment1, _ := cached.GetACAssignment(ctx, "ac-reassign")
	if assignment1.AssignedServers[0].ID != "srv-a" {
		t.Fatal("Expected initial assignment")
	}

	// Simulate Console reassigning to new servers
	newAssignment := CreateTestACAssignment("ac-reassign", "srv-x", "srv-y", "srv-z")
	now := time.Now().Unix()
	newAssignment.ReassignedAt = &now // Mark as just reassigned
	backend.PutACAssignment(newAssignment)

	// Cache still has old assignment
	assignment2, _ := cached.GetACAssignment(ctx, "ac-reassign")
	if assignment2.AssignedServers[0].ID != "srv-a" {
		t.Log("Cache was invalidated immediately - this is acceptable")
	}

	// Invalidate cache (simulating what would happen when we detect staleness)
	cached.InvalidateACAssignment("ac-reassign")

	// Now should get new assignment with short TTL
	assignment3, _ := cached.GetACAssignment(ctx, "ac-reassign")
	if assignment3.AssignedServers[0].ID != "srv-x" {
		t.Errorf("Expected new assignment after invalidation, got %s", assignment3.AssignedServers[0].ID)
	}

	// Verify the new assignment has ReassignedAt set
	if assignment3.ReassignedAt == nil {
		t.Error("Expected ReassignedAt to be set on new assignment")
	}
}
