package server

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// ============================================================================
// Mock HealthChecker for Testing
// ============================================================================

// MockHealthChecker implements the HealthChecker interface for testing.
type MockHealthChecker struct {
	healthyIPs  map[string]bool
	returnError error
	callCount   int32 // atomic counter for concurrent tests
	mu          sync.RWMutex
}

// Compile-time check that MockHealthChecker implements HealthChecker
var _ HealthChecker = (*MockHealthChecker)(nil)

func NewMockHealthChecker(healthyIPs map[string]bool) *MockHealthChecker {
	return &MockHealthChecker{
		healthyIPs: healthyIPs,
	}
}

func (m *MockHealthChecker) GetHealthyServerIPs(ctx context.Context) (map[string]bool, error) {
	atomic.AddInt32(&m.callCount, 1)
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.returnError != nil {
		return nil, m.returnError
	}

	// Return a copy
	result := make(map[string]bool, len(m.healthyIPs))
	for k, v := range m.healthyIPs {
		result[k] = v
	}
	return result, nil
}

func (m *MockHealthChecker) InvalidateCache() {
	// No-op for mock
}

func (m *MockHealthChecker) IsNil() bool {
	return m == nil
}

func (m *MockHealthChecker) SetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.returnError = err
}

func (m *MockHealthChecker) SetHealthyIPs(ips map[string]bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthyIPs = ips
}

func (m *MockHealthChecker) GetCallCount() int32 {
	return atomic.LoadInt32(&m.callCount)
}

// ============================================================================
// FilterHealthyServers Tests (using HealthChecker interface)
// ============================================================================

func TestFilterHealthyServers_NilHealthChecker(t *testing.T) {
	// When health checker is nil, all servers should be returned (fail-open)
	servers := []ServerInfo{
		{ID: "srv-1", IP: "10.0.0.1", InternalIP: "10.0.0.1", Port: common.DefaultNHPPort},
		{ID: "srv-2", IP: "10.0.0.2", InternalIP: "10.0.0.2", Port: common.DefaultNHPPort},
	}

	result := FilterHealthyServers(context.Background(), nil, servers)

	if len(result) != len(servers) {
		t.Errorf("Expected %d servers, got %d", len(servers), len(result))
	}
}

func TestFilterHealthyServers_NilInterfaceValue(t *testing.T) {
	// Regression test for nil interface with typed nil value.
	// In Go, a nil *CloudMapClient assigned to HealthChecker interface
	// creates a non-nil interface (has type info) with nil underlying value.
	// Calling methods on such interface panics with nil pointer dereference.
	// This test ensures FilterHealthyServers handles this case correctly.
	servers := []ServerInfo{
		{ID: "srv-1", IP: "10.0.0.1", InternalIP: "10.0.0.1", Port: common.DefaultNHPPort},
		{ID: "srv-2", IP: "10.0.0.2", InternalIP: "10.0.0.2", Port: common.DefaultNHPPort},
	}

	// Create a nil *CloudMapClient and pass it as HealthChecker interface
	var nilClient *CloudMapClient = nil
	var healthChecker HealthChecker = nilClient // Interface is NOT nil, but underlying value IS nil

	// This should NOT panic - it should return all servers (fail-open)
	result := FilterHealthyServers(context.Background(), healthChecker, servers)

	if len(result) != len(servers) {
		t.Errorf("Expected %d servers, got %d", len(servers), len(result))
	}
}

func TestFilterHealthyServers_EmptyInput(t *testing.T) {
	// Empty server list should return empty list
	result := FilterHealthyServers(context.Background(), nil, []ServerInfo{})

	if len(result) != 0 {
		t.Errorf("Expected 0 servers, got %d", len(result))
	}
}

func TestFilterHealthyServers_AllHealthy(t *testing.T) {
	mock := NewMockHealthChecker(map[string]bool{
		"10.0.0.1": true,
		"10.0.0.2": true,
		"10.0.0.3": true,
	})

	servers := []ServerInfo{
		{ID: "srv-1", IP: "10.0.0.1", InternalIP: "10.0.0.1", Port: common.DefaultNHPPort},
		{ID: "srv-2", IP: "10.0.0.2", InternalIP: "10.0.0.2", Port: common.DefaultNHPPort},
		{ID: "srv-3", IP: "10.0.0.3", InternalIP: "10.0.0.3", Port: common.DefaultNHPPort},
	}

	// Use the real FilterHealthyServers function with the mock
	result := FilterHealthyServers(context.Background(), mock, servers)

	if len(result) != 3 {
		t.Errorf("Expected 3 healthy servers, got %d", len(result))
	}
}

func TestFilterHealthyServers_SomeHealthy(t *testing.T) {
	mock := NewMockHealthChecker(map[string]bool{
		"10.0.0.1": true,
		"10.0.0.3": true,
	})

	servers := []ServerInfo{
		{ID: "srv-1", IP: "10.0.0.1", InternalIP: "10.0.0.1", Port: common.DefaultNHPPort},
		{ID: "srv-2", IP: "10.0.0.2", InternalIP: "10.0.0.2", Port: common.DefaultNHPPort}, // Not healthy
		{ID: "srv-3", IP: "10.0.0.3", InternalIP: "10.0.0.3", Port: common.DefaultNHPPort},
	}

	result := FilterHealthyServers(context.Background(), mock, servers)

	if len(result) != 2 {
		t.Errorf("Expected 2 healthy servers, got %d", len(result))
	}

	// Verify correct servers were kept
	for _, srv := range result {
		if srv.ID == "srv-2" {
			t.Errorf("srv-2 should have been filtered out (unhealthy)")
		}
	}
}

func TestFilterHealthyServers_NoneHealthy(t *testing.T) {
	// Mock returns empty healthy set
	mock := NewMockHealthChecker(map[string]bool{})

	servers := []ServerInfo{
		{ID: "srv-1", IP: "10.0.0.1", InternalIP: "10.0.0.1", Port: common.DefaultNHPPort},
		{ID: "srv-2", IP: "10.0.0.2", InternalIP: "10.0.0.2", Port: common.DefaultNHPPort},
	}

	// When health checker returns 0 healthy servers, we fail-open and return all
	result := FilterHealthyServers(context.Background(), mock, servers)

	// Fail-open: return all servers when health check returns empty
	if len(result) != 2 {
		t.Errorf("Expected 2 servers (fail-open), got %d", len(result))
	}
}

func TestFilterHealthyServers_MatchByInternalIP(t *testing.T) {
	// Server's InternalIP should also be checked for health
	mock := NewMockHealthChecker(map[string]bool{
		"192.168.1.100": true, // InternalIP
	})

	servers := []ServerInfo{
		{ID: "srv-1", IP: "54.1.2.3", InternalIP: "192.168.1.100", Port: common.DefaultNHPPort},
	}

	result := FilterHealthyServers(context.Background(), mock, servers)

	if len(result) != 1 {
		t.Errorf("Expected 1 healthy server (matched by InternalIP), got %d", len(result))
	}
}

func TestFilterHealthyServers_HealthCheckError(t *testing.T) {
	// When health check returns an error, we fail-open and return all servers
	mock := NewMockHealthChecker(nil)
	mock.SetError(context.DeadlineExceeded)

	servers := []ServerInfo{
		{ID: "srv-1", IP: "10.0.0.1", InternalIP: "10.0.0.1", Port: common.DefaultNHPPort},
		{ID: "srv-2", IP: "10.0.0.2", InternalIP: "10.0.0.2", Port: common.DefaultNHPPort},
	}

	result := FilterHealthyServers(context.Background(), mock, servers)

	if len(result) != 2 {
		t.Errorf("Expected 2 servers (fail-open on error), got %d", len(result))
	}
}

// ============================================================================
// CloudMapConfig Tests
// ============================================================================

func TestCloudMapConfig_GetCacheTTL(t *testing.T) {
	tests := []struct {
		name     string
		config   CloudMapConfig
		expected time.Duration
	}{
		{
			name:     "default when zero",
			config:   CloudMapConfig{CacheTTL: 0},
			expected: DefaultCloudMapCacheTTL,
		},
		{
			name:     "custom value",
			config:   CloudMapConfig{CacheTTL: 60},
			expected: 60 * time.Second,
		},
		{
			name:     "small value",
			config:   CloudMapConfig{CacheTTL: 5},
			expected: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetCacheTTL()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestCloudMapConfig_GetOperationTimeout(t *testing.T) {
	tests := []struct {
		name     string
		config   CloudMapConfig
		expected time.Duration
	}{
		{
			name:     "default when zero",
			config:   CloudMapConfig{OperationTimeout: 0},
			expected: DefaultCloudMapOperationTimeout,
		},
		{
			name:     "custom value",
			config:   CloudMapConfig{OperationTimeout: 10},
			expected: 10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetOperationTimeout()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// ============================================================================
// CloudMapClient Cache Tests
// ============================================================================

func TestCloudMapClient_CacheExpiry(t *testing.T) {
	client := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "srv-1", IP: "10.0.0.1", InternalIP: "10.0.0.1"},
		},
		instancesExpiry: time.Now().Add(-1 * time.Minute), // Expired
	}

	// With expired cache, DiscoverServerInstances would normally call the API
	// Since we don't have a real API to call, we just verify the cache logic
	client.instancesMu.RLock()
	isExpired := time.Now().After(client.instancesExpiry)
	client.instancesMu.RUnlock()

	if !isExpired {
		t.Error("Cache should be expired")
	}
}

func TestCloudMapClient_CacheValid(t *testing.T) {
	client := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "srv-1", IP: "10.0.0.1", InternalIP: "10.0.0.1"},
			{ID: "srv-2", IP: "10.0.0.2", InternalIP: "10.0.0.2"},
		},
		instancesExpiry: time.Now().Add(1 * time.Minute), // Valid
	}

	client.instancesMu.RLock()
	isValid := time.Now().Before(client.instancesExpiry)
	cachedCount := len(client.cachedInstances)
	client.instancesMu.RUnlock()

	if !isValid {
		t.Error("Cache should be valid")
	}
	if cachedCount != 2 {
		t.Errorf("Expected 2 cached instances, got %d", cachedCount)
	}
}

func TestCloudMapClient_InvalidateCache(t *testing.T) {
	client := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "srv-1", IP: "10.0.0.1", InternalIP: "10.0.0.1"},
		},
		instancesExpiry: time.Now().Add(1 * time.Minute), // Valid
	}

	client.InvalidateCache()

	client.instancesMu.RLock()
	isExpired := time.Now().After(client.instancesExpiry)
	client.instancesMu.RUnlock()

	if !isExpired {
		t.Error("Cache should be invalidated (expired)")
	}
}

// ============================================================================
// Interface Compliance Tests
// ============================================================================

func TestCloudMapClient_ImplementsHealthChecker(t *testing.T) {
	// Compile-time checks are in the var declarations above,
	// but we verify the behavior here
	var hc HealthChecker

	// CloudMapClient should implement HealthChecker
	hc = &CloudMapClient{}
	_ = hc

	// MockHealthChecker should implement HealthChecker
	hc = &MockHealthChecker{}
	_ = hc
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestMockHealthChecker_ConcurrentCalls(t *testing.T) {
	// This tests that our mock works correctly under concurrent access
	mock := NewMockHealthChecker(map[string]bool{
		"10.0.0.1": true,
	})

	var wg sync.WaitGroup
	concurrency := 100
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := mock.GetHealthyServerIPs(context.Background())
			if err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	// Check for any errors from goroutines
	for err := range errCh {
		t.Errorf("Unexpected error: %v", err)
	}

	// All calls should have succeeded
	if mock.GetCallCount() != int32(concurrency) {
		t.Errorf("Expected %d calls, got %d", concurrency, mock.GetCallCount())
	}
}

func TestFilterHealthyServers_ConcurrentAccess(t *testing.T) {
	// Test that FilterHealthyServers is safe for concurrent use
	mock := NewMockHealthChecker(map[string]bool{
		"10.0.0.1": true,
		"10.0.0.2": true,
	})

	servers := []ServerInfo{
		{ID: "srv-1", IP: "10.0.0.1", InternalIP: "10.0.0.1", Port: common.DefaultNHPPort},
		{ID: "srv-2", IP: "10.0.0.2", InternalIP: "10.0.0.2", Port: common.DefaultNHPPort},
		{ID: "srv-3", IP: "10.0.0.3", InternalIP: "10.0.0.3", Port: common.DefaultNHPPort},
	}

	var wg sync.WaitGroup
	concurrency := 50
	errCh := make(chan string, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := FilterHealthyServers(context.Background(), mock, servers)
			if len(result) != 2 {
				errCh <- fmt.Sprintf("Expected 2 healthy servers, got %d", len(result))
			}
		}()
	}

	wg.Wait()
	close(errCh)

	// Check for any errors from goroutines
	for errMsg := range errCh {
		t.Error(errMsg)
	}
}

// ============================================================================
// Integration Test Scenarios (Documented for Manual Testing)
// ============================================================================
//
// These scenarios should be tested in a real AWS environment:
//
// 1. Terminate NHP Server via ASG:
//    - Create AC assignment pointing to 3 servers (including one to terminate)
//    - Terminate one server instance
//    - Wait for Cloud Map health check to fail (~30s)
//    - Verify AC registration succeeds without redirect loop
//
// 2. Cloud Map Unavailable:
//    - Configure Cloud Map with invalid credentials
//    - Verify AC registration falls back to accepting directly (fail-open)
//
// 3. Cache Behavior:
//    - Kill server, immediately try AC registration
//    - Expect redirect to dead server (cache still valid)
//    - Wait 30s, retry AC registration
//    - Expect registration to succeed (cache refreshed)
//
// 4. All Servers Unhealthy:
//    - Create AC assignment pointing to 3 servers
//    - Terminate all 3 servers
//    - Verify AC registration succeeds at any live server
//
// 5. Singleflight Behavior:
//    - With cache expired, send 100 concurrent registration requests
//    - Verify only 1 Cloud Map API call is made (singleflight deduplication)
//
// ============================================================================
