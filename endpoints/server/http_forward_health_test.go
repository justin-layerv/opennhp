package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// ============================================================================
// markFailed / failure tracking unit tests
// ============================================================================

func TestMarkFailed_RecordsFailure(t *testing.T) {
	f := NewHttpKnockForwarder(newMockStorageBackend(), nil, "10.0.0.1", 8888, nil)

	f.markFailed("10.0.0.2")

	f.failedMu.RLock()
	_, exists := f.failedServers["10.0.0.2"]
	f.failedMu.RUnlock()

	if !exists {
		t.Fatal("Expected 10.0.0.2 to be in failedServers")
	}
}

func TestMarkFailed_EvictsExpiredEntriesAboveThreshold(t *testing.T) {
	f := NewHttpKnockForwarder(newMockStorageBackend(), nil, "10.0.0.1", 8888, nil)

	// Fill the map above the eviction threshold with expired entries
	f.failedMu.Lock()
	for i := 0; i < failedServersEvictThreshold+5; i++ {
		f.failedServers["10.99.0."+strconv.Itoa(i)] = time.Now().Add(-httpForwardHealthDecay - time.Second)
	}
	f.failedMu.Unlock()

	// Mark a new failure — should trigger eviction since map exceeds threshold
	f.markFailed("10.0.0.2")

	f.failedMu.RLock()
	freshExists := false
	staleCount := 0
	for ip, ts := range f.failedServers {
		if ip == "10.0.0.2" {
			freshExists = true
		} else if time.Since(ts) >= httpForwardHealthDecay {
			staleCount++
		}
	}
	mapLen := len(f.failedServers)
	f.failedMu.RUnlock()

	if !freshExists {
		t.Error("Expected fresh entry 10.0.0.2 to exist")
	}
	if staleCount > 0 {
		t.Errorf("Expected 0 stale entries after eviction, got %d", staleCount)
	}
	if mapLen != 1 {
		t.Errorf("Expected map length 1 (only fresh entry), got %d", mapLen)
	}
}

func TestMarkFailed_SkipsEvictionBelowThreshold(t *testing.T) {
	f := NewHttpKnockForwarder(newMockStorageBackend(), nil, "10.0.0.1", 8888, nil)

	// Insert a few expired entries (below threshold)
	f.failedMu.Lock()
	f.failedServers["10.0.0.99"] = time.Now().Add(-httpForwardHealthDecay - time.Second)
	f.failedMu.Unlock()

	// Mark a new failure — should NOT trigger eviction (below threshold)
	f.markFailed("10.0.0.2")

	f.failedMu.RLock()
	_, staleExists := f.failedServers["10.0.0.99"]
	mapLen := len(f.failedServers)
	f.failedMu.RUnlock()

	// Stale entry should still be there (no eviction below threshold)
	if !staleExists {
		t.Error("Expected stale entry to remain below eviction threshold")
	}
	if mapLen != 2 {
		t.Errorf("Expected map length 2, got %d", mapLen)
	}
}

func TestMarkFailed_ConcurrentSafe(t *testing.T) {
	f := NewHttpKnockForwarder(newMockStorageBackend(), nil, "10.0.0.1", 8888, nil)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f.markFailed("10.0.0." + strconv.Itoa(i%10))
		}(i)
	}
	wg.Wait()

	f.failedMu.RLock()
	defer f.failedMu.RUnlock()
	if len(f.failedServers) > 10 {
		t.Errorf("Expected at most 10 entries, got %d", len(f.failedServers))
	}
}

// ============================================================================
// filterForwardTargets with failure tracking
// ============================================================================

func TestFilterForwardTargets_SkipsRecentlyFailed(t *testing.T) {
	f := NewHttpKnockForwarder(newMockStorageBackend(), nil, "10.0.0.1", 8888, nil)

	// Mark srv-2 as recently failed
	f.markFailed("10.0.0.2")

	servers := []ServerInfo{
		{ID: "srv-2", InternalIP: "10.0.0.2"},
		{ID: "srv-3", InternalIP: "10.0.0.3"},
	}

	result := f.filterForwardTargets(context.Background(), servers)

	if len(result) != 1 {
		t.Fatalf("Expected 1 server (srv-2 failed), got %d", len(result))
	}
	if result[0].ID != "srv-3" {
		t.Errorf("Expected srv-3, got %s", result[0].ID)
	}
}

func TestFilterForwardTargets_AllowsRecoveredServers(t *testing.T) {
	f := NewHttpKnockForwarder(newMockStorageBackend(), nil, "10.0.0.1", 8888, nil)

	// Mark srv-2 as failed long ago (beyond decay window)
	f.failedMu.Lock()
	f.failedServers["10.0.0.2"] = time.Now().Add(-httpForwardHealthDecay - time.Second)
	f.failedMu.Unlock()

	servers := []ServerInfo{
		{ID: "srv-2", InternalIP: "10.0.0.2"},
		{ID: "srv-3", InternalIP: "10.0.0.3"},
	}

	result := f.filterForwardTargets(context.Background(), servers)

	if len(result) != 2 {
		t.Fatalf("Expected 2 servers (srv-2 recovered), got %d", len(result))
	}
}

func TestFilterForwardTargets_FallbackWhenAllFailed(t *testing.T) {
	f := NewHttpKnockForwarder(newMockStorageBackend(), nil, "10.0.0.1", 8888, nil)

	// Mark ALL non-self servers as failed
	f.markFailed("10.0.0.2")
	f.markFailed("10.0.0.3")

	servers := []ServerInfo{
		{ID: "srv-1", InternalIP: "10.0.0.1"}, // self
		{ID: "srv-2", InternalIP: "10.0.0.2"}, // failed
		{ID: "srv-3", InternalIP: "10.0.0.3"}, // failed
	}

	result := f.filterForwardTargets(context.Background(), servers)

	// Should fall back to all non-self servers rather than returning empty
	if len(result) != 2 {
		t.Fatalf("Expected 2 servers (fallback to all non-self), got %d", len(result))
	}
}

func TestFilterForwardTargets_NoFallbackWhenOnlySelf(t *testing.T) {
	f := NewHttpKnockForwarder(newMockStorageBackend(), nil, "10.0.0.1", 8888, nil)

	servers := []ServerInfo{
		{ID: "srv-1", InternalIP: "10.0.0.1"}, // self only
	}

	result := f.filterForwardTargets(context.Background(), servers)

	// No fallback possible — only self in the list
	if len(result) != 0 {
		t.Fatalf("Expected 0 servers, got %d", len(result))
	}
}

func TestFilterForwardTargets_CombinesCloudMapAndFailureTracking(t *testing.T) {
	mock := NewMockHealthChecker(map[string]bool{
		"10.0.0.2": true,
		"10.0.0.3": true,
		// 10.0.0.4 is unhealthy in CloudMap
	})

	f := NewHttpKnockForwarder(newMockStorageBackend(), mock, "10.0.0.1", 8888, nil)

	// Mark srv-2 as failed (even though CloudMap says healthy)
	f.markFailed("10.0.0.2")

	servers := []ServerInfo{
		{ID: "srv-1", InternalIP: "10.0.0.1", IP: "10.0.0.1"}, // self
		{ID: "srv-2", InternalIP: "10.0.0.2", IP: "10.0.0.2"}, // CloudMap healthy, but recently failed
		{ID: "srv-3", InternalIP: "10.0.0.3", IP: "10.0.0.3"}, // CloudMap healthy, not failed
		{ID: "srv-4", InternalIP: "10.0.0.4", IP: "10.0.0.4"}, // CloudMap unhealthy
	}

	result := f.filterForwardTargets(context.Background(), servers)

	// srv-1: self (excluded)
	// srv-2: CloudMap healthy but recently failed (excluded)
	// srv-3: CloudMap healthy and not failed (included)
	// srv-4: CloudMap unhealthy (excluded by CloudMap)
	if len(result) != 1 {
		t.Fatalf("Expected 1 server (srv-3), got %d", len(result))
	}
	if result[0].ID != "srv-3" {
		t.Errorf("Expected srv-3, got %s", result[0].ID)
	}
}

// ============================================================================
// ForwardHttpKnock failure tracking integration
// ============================================================================

func TestForwardHttpKnock_MarksFailedServers(t *testing.T) {
	// Start a mock server that always returns an error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := HttpKnockForwardResponse{Error: "AC not connected"}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	_, portStr, _ := net.SplitHostPort(mockServer.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	storage := newMockStorageBackend()
	storage.assignments["ac-test"] = &ACAssignment{
		ACID: "ac-test",
		AssignedServers: []ServerInfo{
			{ID: "srv-2", InternalIP: "127.0.0.1"},
		},
	}

	f := NewHttpKnockForwarder(storage, nil, "10.0.0.99", port, nil)

	_, err := f.ForwardHttpKnock(context.Background(), "ac-test", &common.HttpKnockRequest{}, &common.ResourceData{})
	if err == nil {
		t.Fatal("Expected error")
	}

	// Verify server was marked as failed
	f.failedMu.RLock()
	_, failed := f.failedServers["127.0.0.1"]
	f.failedMu.RUnlock()

	if !failed {
		t.Error("Expected 127.0.0.1 to be marked as failed after forward error")
	}
}

func TestForwardHttpKnock_InvalidatesCacheOnTotalFailure(t *testing.T) {
	// Start a mock server that always fails
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := HttpKnockForwardResponse{Error: "AC not connected"}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	_, portStr, _ := net.SplitHostPort(mockServer.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	storage := newMockStorageBackend()
	storage.assignments["ac-test"] = &ACAssignment{
		ACID: "ac-test",
		AssignedServers: []ServerInfo{
			{ID: "srv-2", InternalIP: "127.0.0.1"},
		},
	}

	mock := NewMockHealthChecker(map[string]bool{"127.0.0.1": true})
	f := NewHttpKnockForwarder(storage, mock, "10.0.0.99", port, nil)

	_, _ = f.ForwardHttpKnock(context.Background(), "ac-test", &common.HttpKnockRequest{}, &common.ResourceData{})

	// Verify cache was invalidated
	if !mock.cacheInvalidated.Load() {
		t.Error("Expected CloudMap cache to be invalidated after total forward failure")
	}
}

func TestForwardHttpKnock_DoesNotInvalidateCacheOnPartialSuccess(t *testing.T) {
	// Two mock servers: first fails, second succeeds
	var callCount atomic.Int32
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n == 1 {
			// First call: return error
			resp := HttpKnockForwardResponse{Error: "AC not connected"}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		// Second call: success
		resp := HttpKnockForwardResponse{
			AckMsg: &common.ServerKnockAckMsg{ErrCode: common.ErrSuccess.ErrorCode()},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	_, portStr, _ := net.SplitHostPort(mockServer.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	storage := newMockStorageBackend()
	storage.assignments["ac-test"] = &ACAssignment{
		ACID: "ac-test",
		AssignedServers: []ServerInfo{
			// Both point to same mock server (different IDs to avoid self-exclusion)
			{ID: "srv-2", InternalIP: "127.0.0.1"},
			{ID: "srv-3", InternalIP: "127.0.0.1"},
		},
	}

	mock := NewMockHealthChecker(map[string]bool{"127.0.0.1": true})
	f := NewHttpKnockForwarder(storage, mock, "10.0.0.99", port, nil)

	ack, err := f.ForwardHttpKnock(context.Background(), "ac-test", &common.HttpKnockRequest{}, &common.ResourceData{})
	if err != nil {
		t.Fatalf("Expected success on second attempt, got error: %v", err)
	}
	if ack == nil {
		t.Fatal("Expected non-nil ack")
	}

	// Cache should NOT be invalidated since one attempt succeeded
	if mock.cacheInvalidated.Load() {
		t.Error("Cache should not be invalidated when forward partially succeeded")
	}
}

// ============================================================================
// ForwardHttpKnock stopped state
// ============================================================================

func TestForwardHttpKnock_RejectsWhenStopped(t *testing.T) {
	f := NewHttpKnockForwarder(newMockStorageBackend(), nil, "10.0.0.1", 8888, nil)
	f.Stop()

	_, err := f.ForwardHttpKnock(context.Background(), "ac-test", &common.HttpKnockRequest{}, &common.ResourceData{})
	if !errors.Is(err, errForwarderStopped) {
		t.Errorf("Expected errForwarderStopped, got %v", err)
	}
}

// ============================================================================
// ForwardHttpKnock context cancellation
// ============================================================================

func TestForwardHttpKnock_RespectsContextCancellation(t *testing.T) {
	// Start a slow server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer mockServer.Close()

	_, portStr, _ := net.SplitHostPort(mockServer.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	storage := newMockStorageBackend()
	storage.assignments["ac-test"] = &ACAssignment{
		ACID: "ac-test",
		AssignedServers: []ServerInfo{
			{ID: "srv-2", InternalIP: "127.0.0.1"},
		},
	}

	f := NewHttpKnockForwarder(storage, nil, "10.0.0.99", port, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := f.ForwardHttpKnock(ctx, "ac-test", &common.HttpKnockRequest{}, &common.ResourceData{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Expected error from context cancellation")
	}
	if elapsed > 1*time.Second {
		t.Errorf("Expected fast cancellation, took %v", elapsed)
	}
}

// ============================================================================
// Rolling deployment simulation (functional/integration test)
// ============================================================================

func TestForwardHttpKnock_RollingDeploySimulation(t *testing.T) {
	// Simulate 3 servers: A (being terminated), B (healthy), C (healthy)
	// Server D (new) tries to forward a knock

	// Server B: responds successfully
	serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := HttpKnockForwardResponse{
			AckMsg: &common.ServerKnockAckMsg{ErrCode: common.ErrSuccess.ErrorCode()},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer serverB.Close()

	_, portStr, _ := net.SplitHostPort(serverB.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// Server A (terminated): no listener — connection refused
	// We represent this by using a port that nothing is listening on
	deadPort := findFreePort(t)

	storage := newMockStorageBackend()
	storage.assignments["layerv-ac-tf"] = &ACAssignment{
		ACID: "layerv-ac-tf",
		AssignedServers: []ServerInfo{
			{ID: "srv-a", InternalIP: "127.0.0.1", Port: deadPort}, // terminated
			{ID: "srv-b", InternalIP: "127.0.0.1", Port: port},     // healthy
			{ID: "srv-c", InternalIP: "127.0.0.1", Port: port},     // healthy (same mock)
		},
	}

	// Server D (new, no AC connections) — this is us
	f := &HttpKnockForwarder{
		storage:  storage,
		localIP:  "10.0.0.4", // different from 127.0.0.1
		httpPort: port,       // default port for forwarding
		httpClient: &http.Client{
			Timeout: 2 * time.Second,
		},
		failedServers: make(map[string]time.Time),
	}

	// Forward should succeed by falling through dead server A to healthy server B
	ack, err := f.ForwardHttpKnock(context.Background(), "layerv-ac-tf", &common.HttpKnockRequest{}, &common.ResourceData{})
	if err != nil {
		t.Fatalf("Expected successful forward (should skip dead server A), got error: %v", err)
	}
	if ack == nil || ack.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Errorf("Expected success ack, got %+v", ack)
	}

}

func TestForwardHttpKnock_SecondRequestSkipsDeadServer(t *testing.T) {
	// Simulate: a previous request failed on a server, marking it as failed.
	// The next request should skip it via failure tracking and go directly
	// to a healthy server.

	var requestCount atomic.Int32
	healthyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		resp := HttpKnockForwardResponse{
			AckMsg: &common.ServerKnockAckMsg{ErrCode: common.ErrSuccess.ErrorCode()},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer healthyServer.Close()

	_, healthyPortStr, _ := net.SplitHostPort(healthyServer.Listener.Addr().String())
	healthyPort, _ := strconv.Atoi(healthyPortStr)

	storage := newMockStorageBackend()
	storage.assignments["ac-test"] = &ACAssignment{
		ACID: "ac-test",
		AssignedServers: []ServerInfo{
			{ID: "srv-dead", InternalIP: "10.0.0.2"},     // dead — marked failed below
			{ID: "srv-healthy", InternalIP: "127.0.0.1"}, // healthy — points to mock server
		},
	}

	f := NewHttpKnockForwarder(storage, nil, "10.0.0.99", healthyPort, nil)

	// Pre-mark the dead server as failed (simulating a previous failed forward)
	f.markFailed("10.0.0.2")

	// Forward should skip dead server and go directly to healthy
	ack, err := f.ForwardHttpKnock(context.Background(), "ac-test", &common.HttpKnockRequest{}, &common.ResourceData{})
	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}
	if ack == nil {
		t.Fatal("Expected non-nil ack")
	}

	// Only the healthy server should have been contacted
	if requestCount.Load() != 1 {
		t.Errorf("Expected exactly 1 request to healthy server, got %d", requestCount.Load())
	}
}

func TestForwardHttpKnock_NilCloudMapDoesNotPanic(t *testing.T) {
	// This tests the exact prod scenario: storage is available but CloudMap is nil.
	// The forwarder should work, just without health filtering.

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := HttpKnockForwardResponse{
			AckMsg: &common.ServerKnockAckMsg{ErrCode: common.ErrSuccess.ErrorCode()},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	_, portStr, _ := net.SplitHostPort(mockServer.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	storage := newMockStorageBackend()
	storage.assignments["ac-test"] = &ACAssignment{
		ACID: "ac-test",
		AssignedServers: []ServerInfo{
			{ID: "srv-2", InternalIP: "127.0.0.1"},
		},
	}

	// Explicitly pass nil CloudMap (the prod scenario)
	f := NewHttpKnockForwarder(storage, nil, "10.0.0.99", port, nil)

	ack, err := f.ForwardHttpKnock(context.Background(), "ac-test", &common.HttpKnockRequest{}, &common.ResourceData{})
	if err != nil {
		t.Fatalf("Expected success with nil CloudMap, got error: %v", err)
	}
	if ack == nil {
		t.Fatal("Expected non-nil ack")
	}
}

func TestForwardHttpKnock_AllFailedThenCacheInvalidatedThenRetrySucceeds(t *testing.T) {
	// Full lifecycle: all forwards fail → cache invalidated → new servers
	// appear → next forward succeeds

	var callCount atomic.Int32
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n <= 1 {
			resp := HttpKnockForwardResponse{Error: "AC not connected"}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		resp := HttpKnockForwardResponse{
			AckMsg: &common.ServerKnockAckMsg{ErrCode: common.ErrSuccess.ErrorCode()},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	_, portStr, _ := net.SplitHostPort(mockServer.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	storage := newMockStorageBackend()
	storage.assignments["ac-test"] = &ACAssignment{
		ACID: "ac-test",
		AssignedServers: []ServerInfo{
			{ID: "srv-2", InternalIP: "127.0.0.1"},
		},
	}

	mock := NewMockHealthChecker(map[string]bool{"127.0.0.1": true})
	f := NewHttpKnockForwarder(storage, mock, "10.0.0.99", port, nil)

	// First attempt: all fail → cache invalidated
	_, err := f.ForwardHttpKnock(context.Background(), "ac-test", &common.HttpKnockRequest{}, &common.ResourceData{})
	if err == nil {
		t.Fatal("Expected error on first attempt")
	}
	if !mock.cacheInvalidated.Load() {
		t.Error("Expected cache invalidation after total failure")
	}

	// Second attempt: server has recovered (mock returns success on call 2+)
	// Failed server should be in the fallback path since it's the only non-self server
	ack, err := f.ForwardHttpKnock(context.Background(), "ac-test", &common.HttpKnockRequest{}, &common.ResourceData{})
	if err != nil {
		t.Fatalf("Expected success on retry, got error: %v", err)
	}
	if ack == nil {
		t.Fatal("Expected non-nil ack on retry")
	}
}

// ============================================================================
// CloudMap DeregisterInstance tests
// ============================================================================

func TestCloudMapDeregisterInstance_RequiresServiceID(t *testing.T) {
	c := &CloudMapClient{
		serviceID: "", // not set
	}

	err := c.DeregisterInstance(context.Background(), "i-12345")
	if err == nil {
		t.Fatal("Expected error when serviceID is empty")
	}
}

// ============================================================================
// Helpers
// ============================================================================

func findFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
