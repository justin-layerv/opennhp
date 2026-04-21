package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================================
// Failure injection test helpers
//
// These tests simulate infrastructure failures (Docker container crash,
// storage backend failure, network partition, etc.) and verify that the
// health monitoring system detects them correctly.
//
// Addresses: https://github.com/layervai/nhp/issues/154
// ============================================================================

// failingChecker simulates a component that transitions between healthy and
// failed states, modeling scenarios like Docker container crashes or storage
// backend outages.
type failingChecker struct {
	name     string
	critical bool

	mu      sync.RWMutex
	healthy bool
	err     error
	delay   time.Duration
	panics  bool
	hangCh  chan struct{} // if set, Check blocks until this channel is closed
}

func newFailingChecker(name string, critical bool) *failingChecker {
	return &failingChecker{
		name:     name,
		critical: critical,
		healthy:  true,
	}
}

func (f *failingChecker) Name() string     { return f.name }
func (f *failingChecker) IsCritical() bool { return f.critical }

func (f *failingChecker) Check(ctx context.Context) *CheckResult {
	f.mu.RLock()
	healthy := f.healthy
	err := f.err
	delay := f.delay
	panics := f.panics
	hangCh := f.hangCh
	f.mu.RUnlock()

	start := time.Now()

	if panics {
		panic(fmt.Sprintf("simulated crash in %s", f.name))
	}

	// Simulate a hung process that blocks indefinitely until context cancels
	if hangCh != nil {
		select {
		case <-hangCh:
		case <-ctx.Done():
			result := &CheckResult{
				Name:      f.name,
				Status:    CheckStatusFail,
				Message:   fmt.Sprintf("%s health check timed out: %v", f.name, ctx.Err()),
				Timestamp: start,
				Critical:  f.critical,
			}
			result.SetDuration(time.Since(start))
			return result
		}
	}

	// Simulate slow checks (e.g., network latency to storage)
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			result := &CheckResult{
				Name:      f.name,
				Status:    CheckStatusFail,
				Message:   fmt.Sprintf("%s health check timed out: %v", f.name, ctx.Err()),
				Timestamp: start,
				Critical:  f.critical,
			}
			result.SetDuration(time.Since(start))
			return result
		}
	}

	result := &CheckResult{
		Name:      f.name,
		Timestamp: start,
		Critical:  f.critical,
	}

	if !healthy {
		result.Status = CheckStatusFail
		if err != nil {
			result.Message = err.Error()
		} else {
			result.Message = f.name + " is unhealthy"
		}
	} else {
		result.Status = CheckStatusPass
		result.Message = f.name + " is healthy"
	}

	result.SetDuration(time.Since(start))
	return result
}

// simulateCrash transitions the checker to a failed state,
// modeling a Docker container crash or process termination.
func (f *failingChecker) simulateCrash(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.healthy = false
	f.err = err
}

// simulateRecover transitions the checker back to healthy,
// modeling a container restart or service recovery.
func (f *failingChecker) simulateRecover() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.healthy = true
	f.err = nil
	f.panics = false
	f.hangCh = nil
	f.delay = 0
}

// simulateHang causes the checker to block until the returned cancel func
// is called, modeling a hung process (e.g., Docker exec kill -STOP 1).
// The returned function is safe to call multiple times.
func (f *failingChecker) simulateHang() func() {
	ch := make(chan struct{})
	f.mu.Lock()
	f.hangCh = ch
	f.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

// simulateSlow adds latency to the checker, modeling degraded network
// connectivity to a dependency.
func (f *failingChecker) simulateSlow(delay time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delay = delay
}

// simulatePanic causes the checker to panic, modeling an unexpected
// runtime error inside a health check.
func (f *failingChecker) simulatePanic() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.panics = true
}

// ============================================================================
// Test: Docker container crash detection
// ============================================================================

func TestFailureInjection_DockerContainerCrash(t *testing.T) {
	t.Parallel()

	// Simulate the NHP server's health monitoring stack:
	// - storage (DynamoDB/etcd) is critical
	// - the health manager detects when storage becomes unreachable
	storage := newFailingChecker("storage", true)

	m := NewManager(&ManagerConfig{
		Service: "nhp-server",
		Version: "test",
		Timeout: 5 * time.Second,
	})
	m.Register(storage)

	// Phase 1: Healthy state
	resp := m.CheckReadiness(context.Background())
	if resp.Status != StatusHealthy {
		t.Fatalf("expected healthy before crash, got %s", resp.Status)
	}

	// Phase 2: Simulate Docker container crash (storage becomes unreachable)
	storage.simulateCrash(errors.New("connection refused: container nhp-server is not running"))

	resp = m.CheckReadiness(context.Background())
	if resp.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy after container crash, got %s", resp.Status)
	}

	// Verify the check result has the failure details
	storageCheck, ok := resp.Checks["storage"]
	if !ok {
		t.Fatal("expected storage check in response")
	}
	if storageCheck.Status != CheckStatusFail {
		t.Errorf("expected storage check to fail, got %s", storageCheck.Status)
	}
	if storageCheck.Message == "" {
		t.Error("expected failure message to contain error details")
	}

	// Phase 3: Container restarts and storage recovers
	storage.simulateRecover()

	resp = m.CheckReadiness(context.Background())
	if resp.Status != StatusHealthy {
		t.Fatalf("expected healthy after recovery, got %s", resp.Status)
	}
}

// ============================================================================
// Test: Storage backend failure (DynamoDB unreachable)
// ============================================================================

func TestFailureInjection_StorageBackendFailure(t *testing.T) {
	t.Parallel()

	storage := newFailingChecker("dynamodb", true)
	acPeers := newFailingChecker("ac_peers", true)

	m := NewManager(&ManagerConfig{
		Service: "nhp-server",
		Version: "test",
		Timeout: 5 * time.Second,
	})
	m.Register(storage)
	m.Register(acPeers)

	// Initially healthy
	resp := m.CheckReadiness(context.Background())
	if resp.Status != StatusHealthy {
		t.Fatalf("expected healthy initially, got %s", resp.Status)
	}

	// DynamoDB goes down (e.g., network partition to AWS)
	storage.simulateCrash(errors.New("RequestError: send request failed: dial tcp: i/o timeout"))

	resp = m.CheckReadiness(context.Background())
	if resp.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy when DynamoDB is down, got %s", resp.Status)
	}

	// Verify DynamoDB check shows failure while AC peers are still healthy
	ddbCheck := resp.Checks["dynamodb"]
	if ddbCheck == nil || ddbCheck.Status != CheckStatusFail {
		t.Error("expected dynamodb check to fail")
	}
	acCheck := resp.Checks["ac_peers"]
	if acCheck == nil || acCheck.Status != CheckStatusPass {
		t.Error("expected ac_peers check to still pass")
	}
}

// ============================================================================
// Test: AC peer disconnection
// ============================================================================

func TestFailureInjection_ACPeerDisconnection(t *testing.T) {
	t.Parallel()

	// Use the real ACPeerChecker with a controllable counter.
	// GracePeriod=-1 disables the debounce window so this test exercises
	// the underlying counter-drives-status contract directly. The
	// with-grace behavior (transient zero is absorbed; sustained zero
	// fails) has its own dedicated tests in acpeer_test.go.
	counter := newCounterAt(3)
	acChecker := NewACPeerChecker(&ACPeerCheckerConfig{Counter: counter, GracePeriod: -1})

	m := NewManager(&ManagerConfig{
		Service: "nhp-server",
		Version: "test",
		Timeout: 5 * time.Second,
	})
	m.Register(acChecker)

	// Phase 1: 3 peers connected
	resp := m.CheckReadiness(context.Background())
	if resp.Status != StatusHealthy {
		t.Fatalf("expected healthy with 3 peers, got %s", resp.Status)
	}

	// Phase 2: All AC peers disconnect (simulates AC ASG termination)
	counter.set(0)

	resp = m.CheckReadiness(context.Background())
	if resp.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy with 0 peers, got %s", resp.Status)
	}

	acCheck := resp.Checks["ac_peers"]
	if acCheck == nil {
		t.Fatal("expected ac_peers check in response")
	}
	if acCheck.Status != CheckStatusFail {
		t.Errorf("expected ac_peers to fail, got %s", acCheck.Status)
	}
	if acCheck.Message != "no AC peers connected" {
		t.Errorf("unexpected message: %s", acCheck.Message)
	}

	// Phase 3: New AC peers connect
	counter.set(2)

	resp = m.CheckReadiness(context.Background())
	if resp.Status != StatusHealthy {
		t.Fatalf("expected healthy after AC peers reconnect, got %s", resp.Status)
	}
}

// ============================================================================
// Test: Multiple simultaneous failures (cascading failure)
// ============================================================================

func TestFailureInjection_CascadingFailure(t *testing.T) {
	t.Parallel()

	storage := newFailingChecker("dynamodb", true)
	etcd := newFailingChecker("etcd", true)
	cache := newFailingChecker("cache", false)

	m := NewManager(&ManagerConfig{
		Service: "nhp-server",
		Version: "test",
		Timeout: 5 * time.Second,
	})
	m.Register(storage)
	m.Register(etcd)
	m.Register(cache)

	// All healthy
	resp := m.CheckReadiness(context.Background())
	if resp.Status != StatusHealthy {
		t.Fatalf("expected healthy initially, got %s", resp.Status)
	}

	// Stage 1: Non-critical cache fails -> degraded
	cache.simulateCrash(errors.New("cache eviction storm"))

	resp = m.CheckReadiness(context.Background())
	if resp.Status != StatusDegraded {
		t.Fatalf("expected degraded with only cache failure, got %s", resp.Status)
	}

	// Stage 2: Critical storage also fails -> unhealthy
	storage.simulateCrash(errors.New("connection refused"))

	resp = m.CheckReadiness(context.Background())
	if resp.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy with critical + non-critical failure, got %s", resp.Status)
	}

	// Stage 3: Both critical backends fail
	etcd.simulateCrash(errors.New("etcd cluster unavailable"))

	resp = m.CheckReadiness(context.Background())
	if resp.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy with all backends down, got %s", resp.Status)
	}

	// Verify all checks are present and failed appropriately
	if len(resp.Checks) != 3 {
		t.Errorf("expected 3 checks, got %d", len(resp.Checks))
	}
	for name, check := range resp.Checks {
		if check.Status != CheckStatusFail {
			t.Errorf("expected %s to fail, got %s", name, check.Status)
		}
	}

	// Stage 4: Partial recovery (storage comes back, etcd still down)
	storage.simulateRecover()

	resp = m.CheckReadiness(context.Background())
	if resp.Status != StatusUnhealthy {
		t.Fatalf("expected still unhealthy with etcd down, got %s", resp.Status)
	}

	// Stage 5: Full recovery
	etcd.simulateRecover()
	cache.simulateRecover()

	resp = m.CheckReadiness(context.Background())
	if resp.Status != StatusHealthy {
		t.Fatalf("expected healthy after full recovery, got %s", resp.Status)
	}
}

// ============================================================================
// Test: Process hang simulation (Docker exec kill -STOP 1)
// ============================================================================

func TestFailureInjection_ProcessHang(t *testing.T) {
	t.Parallel()

	storage := newFailingChecker("storage", true)

	m := NewManager(&ManagerConfig{
		Service: "nhp-server",
		Version: "test",
		Timeout: 200 * time.Millisecond, // Short timeout to detect hangs quickly
	})
	m.Register(storage)

	// Initially healthy
	resp := m.CheckReadiness(context.Background())
	if resp.Status != StatusHealthy {
		t.Fatalf("expected healthy initially, got %s", resp.Status)
	}

	// Simulate process hang (kill -STOP 1 inside container)
	unfreeze := storage.simulateHang()
	defer unfreeze()

	// Health check should detect the hang via timeout
	resp = m.CheckReadiness(context.Background())
	if resp.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy when storage check hangs, got %s", resp.Status)
	}

	storageCheck := resp.Checks["storage"]
	if storageCheck == nil {
		t.Fatal("expected storage check in response")
	}
	if storageCheck.Status != CheckStatusFail {
		t.Errorf("expected storage check to fail due to timeout, got %s", storageCheck.Status)
	}

	// Unfreeze and verify recovery
	unfreeze()
	storage.simulateRecover()

	resp = m.CheckReadiness(context.Background())
	if resp.Status != StatusHealthy {
		t.Fatalf("expected healthy after unfreeze, got %s", resp.Status)
	}
}

// ============================================================================
// Test: Liveness vs readiness divergence (container runs but a critical
// dependency reports unready). Models the scenario where iptables drops UDP
// traffic to 62206 — the process is alive (liveness passes) but the
// readiness check that watches the port returns failure.
// ============================================================================

func TestFailureInjection_LivenessVsReadinessDivergence(t *testing.T) {
	t.Parallel()

	// Simulate the scenario where the container is running (liveness passes)
	// but the UDP port checker reports failure (readiness fails). This is an
	// abstract simulation: a real port-binding test would require an actual
	// UDP listener and OS-level firewall rules, which we cannot do in unit
	// tests. The point of this test is to verify that the manager correctly
	// distinguishes liveness from readiness when only one critical checker
	// is failing.
	udpPort := newFailingChecker("udp_port", true)
	container := newFailingChecker("container", true)

	m := NewManager(&ManagerConfig{
		Service: "nhp-server",
		Version: "test",
		Timeout: 5 * time.Second,
	})
	m.Register(container)
	m.Register(udpPort)

	// Both healthy initially
	resp := m.CheckReadiness(context.Background())
	if resp.Status != StatusHealthy {
		t.Fatalf("expected healthy initially, got %s", resp.Status)
	}

	// Simulate iptables DROP on UDP port 62206
	// Container is still running, but port check fails
	udpPort.simulateCrash(errors.New("UDP port 62206 not bound: iptables DROP rule active"))

	resp = m.CheckReadiness(context.Background())
	if resp.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy when port is blocked, got %s", resp.Status)
	}

	// Liveness should still pass (service process is alive)
	liveResp := m.CheckLiveness(context.Background())
	if liveResp.Status != StatusHealthy {
		t.Fatalf("expected liveness to pass even with port blocked, got %s", liveResp.Status)
	}

	// Container check should still pass
	containerCheck := resp.Checks["container"]
	if containerCheck == nil || containerCheck.Status != CheckStatusPass {
		t.Error("expected container check to pass (container is running)")
	}

	// UDP port check should fail
	portCheck := resp.Checks["udp_port"]
	if portCheck == nil || portCheck.Status != CheckStatusFail {
		t.Error("expected udp_port check to fail")
	}
}

// ============================================================================
// Test: Startup failure under component crash
// ============================================================================

func TestFailureInjection_StartupWithCrash(t *testing.T) {
	t.Parallel()

	storage := newFailingChecker("storage", true)
	// Start with storage crashed (simulating dependency not ready yet)
	storage.simulateCrash(errors.New("connection refused"))

	m := NewManager(&ManagerConfig{
		Service:        "nhp-server",
		Version:        "test",
		Timeout:        5 * time.Second,
		StartupTimeout: 60 * time.Second,
	})
	m.Register(storage)

	// Startup check should fail but not timeout (within startup window)
	resp := m.CheckStartup(context.Background())
	if resp.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy during startup with crashed storage, got %s", resp.Status)
	}
	if m.IsStartupComplete() {
		t.Fatal("startup should not be complete with crashed storage")
	}

	// Storage comes back (container restart completed)
	storage.simulateRecover()

	resp = m.CheckStartup(context.Background())
	if resp.Status != StatusHealthy {
		t.Fatalf("expected healthy after storage recovery, got %s", resp.Status)
	}
	if !m.IsStartupComplete() {
		t.Fatal("startup should be complete after successful check")
	}
}

// ============================================================================
// Test: Startup timeout when recovery never happens
// ============================================================================

func TestFailureInjection_StartupTimeoutExceeded(t *testing.T) {
	t.Parallel()

	storage := newFailingChecker("storage", true)
	storage.simulateCrash(errors.New("storage never comes back"))

	m := NewManager(&ManagerConfig{
		Service:        "nhp-server",
		Version:        "test",
		Timeout:        5 * time.Second,
		StartupTimeout: 1 * time.Nanosecond, // Already expired by the time CheckStartup runs
	})
	m.Register(storage)

	// No sleep needed: a 1ns startup window has already elapsed by the time
	// the next instruction executes — the check below will see startup as
	// timed out without any wall-clock waits.
	resp := m.CheckStartup(context.Background())
	if resp.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy after startup timeout, got %s", resp.Status)
	}

	// Should have a startup_timeout check, not the storage check
	if _, exists := resp.Checks["startup_timeout"]; !exists {
		t.Error("expected startup_timeout check when timeout exceeded")
	}
}

// ============================================================================
// Test: Checker panic recovery under failure injection
// ============================================================================

func TestFailureInjection_CheckerPanic(t *testing.T) {
	t.Parallel()

	storage := newFailingChecker("storage", true)
	normal := newFailingChecker("normal", false)

	m := NewManager(&ManagerConfig{
		Service: "nhp-server",
		Version: "test",
		Timeout: 5 * time.Second,
	})
	m.Register(storage)
	m.Register(normal)

	// Simulate a crash that causes a panic in the health checker
	storage.simulatePanic()

	// The manager should recover from the panic and report it as a failure
	resp := m.CheckReadiness(context.Background())
	if resp.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy after checker panic, got %s", resp.Status)
	}

	// Both checks should be present
	if len(resp.Checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(resp.Checks))
	}

	storageCheck := resp.Checks["storage"]
	if storageCheck == nil {
		t.Fatal("expected storage check in response after panic")
	}
	if storageCheck.Status != CheckStatusFail {
		t.Errorf("expected storage check to fail after panic, got %s", storageCheck.Status)
	}

	// Normal checker should still have run
	normalCheck := resp.Checks["normal"]
	if normalCheck == nil || normalCheck.Status != CheckStatusPass {
		t.Error("expected normal checker to still pass despite storage panic")
	}
}

// ============================================================================
// Test: Rapid failure/recovery cycling (flapping)
// ============================================================================

func TestFailureInjection_FlappingComponent(t *testing.T) {
	t.Parallel()

	storage := newFailingChecker("storage", true)

	m := NewManager(&ManagerConfig{
		Service: "nhp-server",
		Version: "test",
		Timeout: 5 * time.Second,
	})
	m.Register(storage)

	// Rapid cycling between healthy and unhealthy
	for i := 0; i < 10; i++ {
		// Crash
		storage.simulateCrash(fmt.Errorf("failure iteration %d", i))
		resp := m.CheckReadiness(context.Background())
		if resp.Status != StatusUnhealthy {
			t.Fatalf("iteration %d: expected unhealthy after crash, got %s", i, resp.Status)
		}

		// Recover
		storage.simulateRecover()
		resp = m.CheckReadiness(context.Background())
		if resp.Status != StatusHealthy {
			t.Fatalf("iteration %d: expected healthy after recovery, got %s", i, resp.Status)
		}
	}
}

// ============================================================================
// Test: Concurrent health checks during failure transition
// ============================================================================

func TestFailureInjection_ConcurrentChecksDuringFailure(t *testing.T) {
	t.Parallel()

	storage := newFailingChecker("storage", true)

	m := NewManager(&ManagerConfig{
		Service: "nhp-server",
		Version: "test",
		Timeout: 5 * time.Second,
	})
	m.Register(storage)

	const totalChecks = 50
	const crashAfter = 25

	var unhealthyCount atomic.Int32
	var healthyCount atomic.Int32

	// Phase 1: run `crashAfter` concurrent checks while the checker is healthy.
	// We wait for all of them to complete before mutating state, guaranteeing
	// they observe the healthy status and avoiding races between check
	// invocation and the crash injection. This is deterministic regardless of
	// goroutine scheduling on slow CI runners.
	var phase1 sync.WaitGroup
	for i := 0; i < crashAfter; i++ {
		phase1.Add(1)
		go func() {
			defer phase1.Done()
			resp := m.CheckReadiness(context.Background())
			switch resp.Status {
			case StatusUnhealthy:
				unhealthyCount.Add(1)
			case StatusHealthy:
				healthyCount.Add(1)
			}
		}()
	}
	phase1.Wait()

	// Inject the crash between phases. Because phase1 has fully drained, no
	// in-flight check can race with this mutation.
	storage.simulateCrash(errors.New("mid-flight crash"))

	// Phase 2: run the remaining concurrent checks against the crashed checker.
	var phase2 sync.WaitGroup
	for i := crashAfter; i < totalChecks; i++ {
		phase2.Add(1)
		go func() {
			defer phase2.Done()
			resp := m.CheckReadiness(context.Background())
			switch resp.Status {
			case StatusUnhealthy:
				unhealthyCount.Add(1)
			case StatusHealthy:
				healthyCount.Add(1)
			}
		}()
	}
	phase2.Wait()

	// We should see at least some unhealthy responses after the crash
	if unhealthyCount.Load() == 0 {
		t.Error("expected at least some unhealthy responses during crash transition")
	}
	// And some healthy ones before the crash
	if healthyCount.Load() == 0 {
		t.Error("expected at least some healthy responses before crash transition")
	}

	t.Logf("healthy=%d, unhealthy=%d (total %d)", healthyCount.Load(), unhealthyCount.Load(), totalChecks)
}

// ============================================================================
// Test: HTTP handler returns correct status codes during failures
// ============================================================================

func TestFailureInjection_HTTPHandlerStatusCodes(t *testing.T) {
	t.Parallel()

	storage := newFailingChecker("storage", true)
	cache := newFailingChecker("cache", false)

	mgr := NewManager(&ManagerConfig{
		Service: "nhp-server",
		Version: "test",
		Timeout: 5 * time.Second,
	})
	mgr.Register(storage)
	mgr.Register(cache)

	handler := NewHandler(mgr)
	router := gin.New()
	handler.RegisterRoutes(router)

	tests := []struct {
		name           string
		setup          func()
		endpoint       string
		wantStatus     int
		wantBodyStatus string
	}{
		{
			name:           "all healthy - readiness returns 200",
			setup:          func() { storage.simulateRecover(); cache.simulateRecover() },
			endpoint:       "/health/ready",
			wantStatus:     http.StatusOK,
			wantBodyStatus: "healthy",
		},
		{
			name:           "critical storage crash - readiness returns 503",
			setup:          func() { storage.simulateCrash(errors.New("container stopped")) },
			endpoint:       "/health/ready",
			wantStatus:     http.StatusServiceUnavailable,
			wantBodyStatus: "unhealthy",
		},
		{
			name:           "critical storage crash - liveness still returns 200",
			setup:          func() { storage.simulateCrash(errors.New("container stopped")) },
			endpoint:       "/health/live",
			wantStatus:     http.StatusOK,
			wantBodyStatus: "healthy",
		},
		{
			name: "non-critical cache crash - readiness returns 200 (degraded)",
			setup: func() {
				storage.simulateRecover()
				cache.simulateCrash(errors.New("cache OOM"))
			},
			endpoint:       "/health/ready",
			wantStatus:     http.StatusOK,
			wantBodyStatus: "degraded",
		},
		{
			name:           "recovery after crash - readiness returns 200",
			setup:          func() { storage.simulateRecover(); cache.simulateRecover() },
			endpoint:       "/health/ready",
			wantStatus:     http.StatusOK,
			wantBodyStatus: "healthy",
		},
	}

	for _, tt := range tests {
		// Subtests are NOT marked t.Parallel() because they share the same
		// `storage` and `cache` checkers and call setup() to mutate them.
		// Running them in parallel would let one subtest's setup race against
		// another's request handling. The outer test is parallel, which is
		// what we want.
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			req, _ := http.NewRequest("GET", tt.endpoint, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("expected HTTP %d, got %d", tt.wantStatus, w.Code)
			}

			var resp map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}
			if resp["status"] != tt.wantBodyStatus {
				t.Errorf("expected status %q, got %q", tt.wantBodyStatus, resp["status"])
			}
		})
	}
}

// ============================================================================
// Test: Knock readiness fails when AC peers disconnect
// ============================================================================

func TestFailureInjection_KnockReadinessDuringACFailure(t *testing.T) {
	t.Parallel()

	// GracePeriod=-1 disables the debounce window so this failure-
	// injection test exercises the immediate counter-drives-status path.
	// The with-grace behavior is covered in acpeer_test.go.
	counter := newCounterAt(3)
	acChecker := NewACPeerChecker(&ACPeerCheckerConfig{Counter: counter, GracePeriod: -1})

	storageChecker := newFailingChecker("dynamodb", true)

	// Standard readiness manager (storage only)
	readinessMgr := NewManager(&ManagerConfig{
		Service: "nhp-server",
		Version: "test",
		Timeout: 5 * time.Second,
	})
	readinessMgr.Register(storageChecker)

	// Knock readiness manager (storage + AC peers)
	knockMgr := NewManager(&ManagerConfig{
		Service: "nhp-server",
		Version: "test",
		Timeout: 5 * time.Second,
	})
	knockMgr.Register(storageChecker)
	knockMgr.Register(acChecker)

	handler := NewHandler(readinessMgr)
	handler.SetKnockManager(knockMgr)

	router := gin.New()
	handler.RegisterRoutes(router)

	// Phase 1: All healthy
	req, _ := http.NewRequest("GET", "/health/knock-ready", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with AC peers, got %d", w.Code)
	}

	// Phase 2: AC peers disconnect (but storage is fine)
	counter.set(0)

	req, _ = http.NewRequest("GET", "/health/knock-ready", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for knock-ready without AC peers, got %d", w.Code)
	}

	// Standard readiness should still pass (storage is healthy)
	req, _ = http.NewRequest("GET", "/health/ready", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for /health/ready (storage is healthy), got %d", w.Code)
	}

	// Phase 3: AC peers reconnect
	counter.set(1)

	req, _ = http.NewRequest("GET", "/health/knock-ready", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for knock-ready after AC reconnect, got %d", w.Code)
	}
}

// ============================================================================
// Test: Health check timeout under slow dependency
// ============================================================================

func TestFailureInjection_SlowDependencyTimeout(t *testing.T) {
	t.Parallel()

	storage := newFailingChecker("storage", true)
	// Simulate a slow storage backend (e.g., DynamoDB throttling)
	storage.simulateSlow(500 * time.Millisecond)

	m := NewManager(&ManagerConfig{
		Service: "nhp-server",
		Version: "test",
		Timeout: 100 * time.Millisecond, // Manager timeout is shorter than check delay
	})
	m.Register(storage)

	start := time.Now()
	resp := m.CheckReadiness(context.Background())
	elapsed := time.Since(start)

	// The check should fail due to the manager's context timeout
	if resp.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy due to timeout, got %s", resp.Status)
	}

	// The manager timeout is 100ms and the simulated dependency would block
	// for 500ms; the check must abort via the context well before the full
	// 500ms. We allow up to 400ms (4x the timeout) as headroom for slow CI
	// runners — anything beyond that is a sign timeout propagation broke.
	if elapsed > 400*time.Millisecond {
		t.Errorf("expected check to complete quickly due to timeout, took %v", elapsed)
	}
}

// ============================================================================
// Test: Failure detection preserves check metadata (timestamps, durations)
// ============================================================================

func TestFailureInjection_MetadataPreservation(t *testing.T) {
	t.Parallel()

	storage := newFailingChecker("storage", true)

	m := NewManager(&ManagerConfig{
		Service: "nhp-server",
		Version: "test",
		Timeout: 5 * time.Second,
	})
	m.Register(storage)

	// Check while healthy
	before := time.Now()
	resp := m.CheckReadiness(context.Background())
	after := time.Now()

	if resp.Timestamp.Before(before) || resp.Timestamp.After(after) {
		t.Errorf("response timestamp %v not between %v and %v", resp.Timestamp, before, after)
	}
	if resp.Service != "nhp-server" {
		t.Errorf("expected service nhp-server, got %s", resp.Service)
	}

	// Inject failure and verify metadata is still correct
	storage.simulateCrash(errors.New("disk failure"))

	before = time.Now()
	resp = m.CheckReadiness(context.Background())
	after = time.Now()

	if resp.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy, got %s", resp.Status)
	}
	if resp.Timestamp.Before(before) || resp.Timestamp.After(after) {
		t.Errorf("response timestamp %v not between %v and %v after failure", resp.Timestamp, before, after)
	}

	storageCheck := resp.Checks["storage"]
	if storageCheck == nil {
		t.Fatal("expected storage check")
	}
	if storageCheck.DurationMS < 0 {
		t.Errorf("expected non-negative duration, got %d", storageCheck.DurationMS)
	}
	if storageCheck.Timestamp.IsZero() {
		t.Error("expected non-zero check timestamp")
	}
}

// ============================================================================
// Test: IsHealthy reflects failure state correctly
// ============================================================================

func TestFailureInjection_IsHealthy(t *testing.T) {
	t.Parallel()

	storage := newFailingChecker("storage", true)
	cache := newFailingChecker("cache", false)

	m := NewManager(&ManagerConfig{
		Service: "nhp-server",
		Version: "test",
		Timeout: 5 * time.Second,
	})
	m.Register(storage)
	m.Register(cache)

	// Healthy
	if !m.IsHealthy(context.Background()) {
		t.Fatal("expected IsHealthy=true when all components are healthy")
	}

	// Non-critical failure (degraded) - still considered healthy for traffic
	cache.simulateCrash(errors.New("cache down"))
	if !m.IsHealthy(context.Background()) {
		t.Fatal("expected IsHealthy=true when only non-critical component fails (degraded)")
	}

	// Critical failure
	storage.simulateCrash(errors.New("storage down"))
	if m.IsHealthy(context.Background()) {
		t.Fatal("expected IsHealthy=false when critical component fails")
	}

	// Recovery
	storage.simulateRecover()
	cache.simulateRecover()
	if !m.IsHealthy(context.Background()) {
		t.Fatal("expected IsHealthy=true after recovery")
	}
}

// Note on coverage: per-checker failure modes for the DynamoDB and etcd
// checkers (success, error, timeout, nil-client) are already covered by
// TestDynamoDBChecker_Check_* in dynamodb_test.go and TestEtcdChecker_Check_*
// in etcd_test.go. Repeating those cases here as
// "TestFailureInjection_DynamoDBChecker" / "TestFailureInjection_EtcdChecker"
// added no new signal and was removed during review. The end-to-end manager
// behavior under those failure modes IS exercised below via the failingChecker
// helper (e.g. TestFailureInjection_StorageBackendFailure).

// ============================================================================
// Test: Full lifecycle - server boot, health checks, failure, ASG replacement
// ============================================================================

func TestFailureInjection_FullServerLifecycle(t *testing.T) {
	t.Parallel()

	// This test simulates the full lifecycle described in issue #154:
	// 1. Server boots, startup check passes
	// 2. Health checks pass, NLB routes traffic
	// 3. Component crashes, health checks fail
	// 4. ASG marks instance unhealthy
	// 5. New instance launches and passes startup

	storage := newFailingChecker("dynamodb", true)
	counter := newCounterAt(0)
	acChecker := NewACPeerChecker(&ACPeerCheckerConfig{Counter: counter})

	// Boot phase: create manager with startup checks
	m := NewManager(&ManagerConfig{
		Service:        "nhp-server",
		Version:        "test",
		Timeout:        5 * time.Second,
		StartupTimeout: 60 * time.Second,
	})
	m.Register(storage)
	m.Register(acChecker)

	handler := NewHandler(m)
	router := gin.New()
	handler.RegisterRoutes(router)

	// Step 1: Server boots - startup check fails (no AC peers yet)
	req, _ := http.NewRequest("GET", "/health/startup", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("step 1: expected 503 during startup (no AC peers), got %d", w.Code)
	}

	// Step 2: AC peers connect, startup succeeds
	counter.set(2)
	req, _ = http.NewRequest("GET", "/health/startup", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("step 2: expected 200 after startup (AC peers connected), got %d", w.Code)
	}

	// Step 3: Readiness passes, NLB would route traffic
	req, _ = http.NewRequest("GET", "/health/ready", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("step 3: expected 200 for readiness, got %d", w.Code)
	}

	// Step 4: Docker container crashes (storage goes down)
	storage.simulateCrash(errors.New("connection refused: container nhp-server is not running"))

	req, _ = http.NewRequest("GET", "/health/ready", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("step 4: expected 503 after crash, got %d", w.Code)
	}

	// Verify response body shows the failure
	var resp ReadinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.Status != string(StatusUnhealthy) {
		t.Errorf("expected unhealthy status in body, got %s", resp.Status)
	}

	// Liveness still passes (the health check process itself is alive)
	req, _ = http.NewRequest("GET", "/health/live", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("step 4: expected liveness to still pass, got %d", w.Code)
	}

	// Step 5: After ASG replacement, simulate new instance startup
	storage.simulateRecover()
	counter.set(3) // New AC peers connect

	// New manager simulates a fresh instance
	m2 := NewManager(&ManagerConfig{
		Service:        "nhp-server",
		Version:        "test",
		Timeout:        5 * time.Second,
		StartupTimeout: 60 * time.Second,
	})
	m2.Register(storage)
	m2.Register(NewACPeerChecker(&ACPeerCheckerConfig{Counter: counter}))

	handler2 := NewHandler(m2)
	router2 := gin.New()
	handler2.RegisterRoutes(router2)

	req, _ = http.NewRequest("GET", "/health/startup", nil)
	w = httptest.NewRecorder()
	router2.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("step 5: expected 200 for new instance startup, got %d", w.Code)
	}
}
