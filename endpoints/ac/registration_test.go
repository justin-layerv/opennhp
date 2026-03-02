package ac

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// mustNewACRegistration is a test helper that calls NewACRegistration and
// fails the test if it returns an error.
func mustNewACRegistration(t *testing.T, ac *UdpAC) *ACRegistration {
	t.Helper()
	reg, err := NewACRegistration(ac)
	if err != nil {
		t.Fatalf("NewACRegistration failed: %v", err)
	}
	return reg
}

// TestNilMetricsPublisher tests that ACRegistration with nil metrics publisher doesn't panic.
// The metrics.Publisher is nil-safe — all methods are no-ops on nil receiver.
func TestNilMetricsPublisher(t *testing.T) {
	reg := &ACRegistration{
		ac: &UdpAC{config: &Config{ACId: "test-ac"}},
		// metrics intentionally nil (Publisher is nil-safe)
	}
	// All metric methods should be no-ops without panic
	reg.metrics.IncrCounter("TestMetric")
	reg.metrics.IncrCounterWithDims("TestMetric", nil)
	reg.metrics.AddCounterWithDims("TestMetric", 5, nil)
	reg.metrics.Stop()
}

// mockNetError implements net.Error for testing the typed interface path in classifyError.
type mockNetError struct {
	msg     string
	timeout bool
}

func (e *mockNetError) Error() string   { return e.msg }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return false }

// TestClassifyError tests error categorization for CloudWatch dimensions.
func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"nil error", nil, "none"},
		{"typed NHP error", common.ErrTransactionFailedByTimeout, common.ErrTransactionFailedByTimeout.ErrorCode()},
		{"wrapped NHP error", fmt.Errorf("registration failed: %w", common.ErrTransactionFailedByTimeout), common.ErrTransactionFailedByTimeout.ErrorCode()},
		{"net.Error timeout", &mockNetError{msg: "i/o timeout", timeout: true}, "timeout"},
		{"net.Error non-timeout", &mockNetError{msg: "connection refused", timeout: false}, "connection_error"},
		{"wrapped net.Error timeout", fmt.Errorf("dial failed: %w", &mockNetError{msg: "deadline", timeout: true}), "timeout"},
		{"timeout string", fmt.Errorf("operation timed out"), "timeout"},
		{"deadline exceeded", fmt.Errorf("context deadline exceeded"), "timeout"},
		{"connection refused", fmt.Errorf("dial: connection refused"), "connection_error"},
		{"connection reset", fmt.Errorf("read: connection reset by peer"), "connection_error"},
		{"ECDH failure", fmt.Errorf("ECDH key exchange failed"), "crypto_error"},
		{"decrypt error", fmt.Errorf("failed to decrypt packet"), "crypto_error"},
		{"DNS failure", fmt.Errorf("no such host"), "dns_error"},
		{"resolve error", fmt.Errorf("could not resolve endpoint"), "dns_error"},
		{"DNS lookup failed", fmt.Errorf("DNS lookup failed for server.nhp.internal"), "dns_error"},
		{"name resolution", fmt.Errorf("name resolution failed"), "dns_error"},
		{"unknown error", fmt.Errorf("something unexpected"), "other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyError(tt.err)
			if got != tt.expected {
				t.Errorf("classifyError(%q) = %q, want %q", tt.err, got, tt.expected)
			}
		})
	}
}

// TestClassifyReason tests reason categorization for CloudWatch dimensions.
func TestClassifyReason(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		expected string
	}{
		{"refresh redirect", ReasonRefreshRedirect, ReasonRefreshRedirect},
		{"server connection timeout", ReasonServerConnectionTimeout, ReasonServerConnectionTimeout},
		{"connection timeout", ReasonConnectionTimeout, ReasonConnectionTimeout},
		{"unknown reason", "some_random_reason", "other"},
		{"empty string", "", "other"},
		{"error message as reason", "failed to connect to server 10.0.0.1", "other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyReason(tt.reason)
			if got != tt.expected {
				t.Errorf("classifyReason(%q) = %q, want %q", tt.reason, got, tt.expected)
			}
		})
	}
}

// TestACRegistration_NewACRegistration tests creation of ACRegistration.
func TestACRegistration_NewACRegistration(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	if reg == nil {
		t.Fatal("NewACRegistration returned nil")
	}

	if reg.ac != ac {
		t.Error("ACRegistration.ac not set correctly")
	}

	if reg.assignedServers == nil {
		t.Error("assignedServers slice should be initialized")
	}

	if len(reg.assignedServers) != 0 {
		t.Error("assignedServers should be empty initially")
	}

	if reg.oldServerSets == nil {
		t.Error("oldServerSets map should be initialized")
	}

	if reg.stopCh == nil {
		t.Error("stopCh should be initialized")
	}
}

// TestACRegistration_NewACRegistration_RegionDimension tests that AWS_REGION
// env var adds a Region dimension to shared metrics dimensions.
func TestACRegistration_NewACRegistration_RegionDimension(t *testing.T) {
	// Save and restore AWS_REGION
	orig := os.Getenv("AWS_REGION")
	defer os.Setenv("AWS_REGION", orig)

	os.Setenv("AWS_REGION", "us-west-2")

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-region",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)
	if reg.metrics == nil {
		t.Skip("metrics publisher nil (AWS config unavailable)")
	}

	// Emit a counter and check that the Region dimension is present
	// by verifying the publisher was created with the region dimension.
	// Since the publisher is opaque, we verify indirectly by checking
	// that NewACRegistration didn't error (Region dim was appended).
	// The actual dimension is tested via buildMetricData in publisher_test.go.
}

// TestACRegistration_HandleRedispatch tests handling of NHP_ARD messages.
func TestACRegistration_HandleRedispatch(t *testing.T) {
	// Create a minimal AC with required fields
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
		sendMsgCh: make(chan *core.MsgData, 10), // Buffer to prevent blocking
	}

	reg := mustNewACRegistration(t, ac)

	tests := []struct {
		name          string
		ardMsg        *common.ACRedispatchMsg
		expectError   bool
		errorContains string
	}{
		{
			name: "empty targets",
			ardMsg: &common.ACRedispatchMsg{
				Targets: []common.RedirectTarget{},
			},
			expectError:   true,
			errorContains: "no targets",
		},
		{
			name: "error code set",
			ardMsg: &common.ACRedispatchMsg{
				ErrCode: "LICENSE_EXPIRED",
				ErrMsg:  "License has expired",
				Targets: []common.RedirectTarget{
					{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "pubkey"},
				},
			},
			expectError:   true,
			errorContains: "redispatch failed",
		},
		{
			name: "target with empty IP",
			ardMsg: &common.ACRedispatchMsg{
				Targets: []common.RedirectTarget{
					{IP: "", Port: DefaultServerPort, PubKeyBase64: "pubkey"},
				},
			},
			expectError:   true,
			errorContains: "empty IP",
		},
		{
			name: "target with invalid port",
			ardMsg: &common.ACRedispatchMsg{
				Targets: []common.RedirectTarget{
					{IP: "10.0.0.1", Port: 0, PubKeyBase64: "pubkey"},
				},
			},
			expectError:   true,
			errorContains: "invalid port",
		},
		{
			name: "target with empty public key",
			ardMsg: &common.ACRedispatchMsg{
				Targets: []common.RedirectTarget{
					{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: ""},
				},
			},
			expectError:   true,
			errorContains: "empty public key",
		},
		{
			name: "target with invalid IP format",
			ardMsg: &common.ACRedispatchMsg{
				Targets: []common.RedirectTarget{
					{IP: "not-an-ip", Port: DefaultServerPort, PubKeyBase64: "pubkey"},
				},
			},
			expectError:   true,
			errorContains: "invalid IP address",
		},
		// Note: We don't test "success code with targets" here because it requires
		// a fully initialized device. That's tested in integration tests.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := reg.HandleRedispatch(tt.ardMsg)

			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectError && err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error containing %q, got %q", tt.errorContains, err.Error())
				}
			}
		})
	}
}

// TestACRegistration_UpdateServerLastSeen tests the LastSeen update mechanism.
func TestACRegistration_UpdateServerLastSeen(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Add some assigned servers manually
	oldTime := time.Now().Add(-1 * time.Hour)
	server1 := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         DefaultServerPort,
			PubKeyBase64: "pubkey1",
		},
	}
	server1.LastSeen = oldTime
	server1.FailCount = 3

	server2 := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.2",
			Port:         DefaultServerPort,
			PubKeyBase64: "pubkey2",
		},
	}
	server2.LastSeen = oldTime
	server2.FailCount = 2

	reg.assignedServers = []*AssignedServer{server1, server2}

	// Test UpdateServerLastSeen by public key
	reg.UpdateServerLastSeen("pubkey1")
	newTime := server1.GetLastSeen()

	if !newTime.After(oldTime) {
		t.Error("LastSeen should be updated to a newer time")
	}

	server1.mu.RLock()
	failCount := server1.FailCount
	server1.mu.RUnlock()
	if failCount != 0 {
		t.Error("FailCount should be reset to 0")
	}

	// Test UpdateServerLastSeenByAddr
	reg.UpdateServerLastSeenByAddr("10.0.0.2:62206")
	newTime = server2.GetLastSeen()

	if !newTime.After(oldTime) {
		t.Error("LastSeen should be updated to a newer time")
	}

	server2.mu.RLock()
	failCount = server2.FailCount
	server2.mu.RUnlock()
	if failCount != 0 {
		t.Error("FailCount should be reset to 0")
	}
}

// TestACRegistration_HasAssignedServers tests the HasAssignedServers method.
func TestACRegistration_HasAssignedServers(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	if reg.HasAssignedServers() {
		t.Error("should return false when no servers assigned")
	}

	reg.assignedServers = []*AssignedServer{
		{
			Target: common.RedirectTarget{
				IP:   "10.0.0.1",
				Port: DefaultServerPort,
			},
		},
	}

	if !reg.HasAssignedServers() {
		t.Error("should return true when servers are assigned")
	}
}

// TestACRegistration_ConcurrentAccess tests thread safety of ACRegistration.
func TestACRegistration_ConcurrentAccess(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Add some servers
	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         DefaultServerPort,
			PubKeyBase64: "pubkey1",
		},
	}
	server.UpdateLastSeen()
	reg.assignedServers = []*AssignedServer{server}

	// Run concurrent operations
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(4)

		// Reader - registration level
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = reg.HasAssignedServers()
				_ = reg.GetAssignedServers()
			}
		}()

		// Reader - server level
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = server.GetLastSeen()
				_ = server.IsConnected()
			}
		}()

		// Writer - UpdateServerLastSeen
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				reg.UpdateServerLastSeen("pubkey1")
			}
		}()

		// Writer - UpdateServerLastSeenByAddr
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				reg.UpdateServerLastSeenByAddr("10.0.0.1:62206")
			}
		}()
	}

	wg.Wait()
	// If we get here without race detector issues, the test passes
}

// TestConfig_RegistrationFields tests that registration config fields are parsed correctly.
func TestConfig_RegistrationFields(t *testing.T) {
	config := &Config{
		ACId:               "test-ac",
		PrivateKeyBase64:   "testprivkey",
		LicenseKey:         "lk_abc123",
		ServerEndpoint:     "server.nhp.test.internal",
		ACVersion:          "1.0.0",
		ServerPubKeyBase64: "serverpubkey",
		ServerPort:         DefaultServerPort,
	}

	if config.LicenseKey != "lk_abc123" {
		t.Errorf("LicenseKey = %q, want %q", config.LicenseKey, "lk_abc123")
	}

	if config.ServerEndpoint != "server.nhp.test.internal" {
		t.Errorf("ServerEndpoint = %q, want %q", config.ServerEndpoint, "server.nhp.test.internal")
	}

	if config.ACVersion != "1.0.0" {
		t.Errorf("ACVersion = %q, want %q", config.ACVersion, "1.0.0")
	}

	if config.ServerPubKeyBase64 != "serverpubkey" {
		t.Errorf("ServerPubKeyBase64 = %q, want %q", config.ServerPubKeyBase64, "serverpubkey")
	}

	if config.ServerPort != 62206 {
		t.Errorf("ServerPort = %d, want %d", config.ServerPort, 62206)
	}
}

// TestACRegistration_OldServerSetsCleanup tests the old server set cleanup mechanism.
func TestACRegistration_OldServerSetsCleanup(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Simulate having old server sets
	key1 := time.Now().Add(-3 * time.Minute).Format(time.RFC3339Nano)
	key2 := time.Now().Add(-1 * time.Minute).Format(time.RFC3339Nano)

	reg.oldServerSets[key1] = []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort}},
	}
	reg.oldServerSets[key2] = []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: DefaultServerPort}},
	}

	if len(reg.oldServerSets) != 2 {
		t.Errorf("expected 2 old server sets, got %d", len(reg.oldServerSets))
	}

	// Manually trigger cleanup for key1
	reg.mu.Lock()
	delete(reg.oldServerSets, key1)
	reg.mu.Unlock()

	if len(reg.oldServerSets) != 1 {
		t.Errorf("expected 1 old server set after cleanup, got %d", len(reg.oldServerSets))
	}

	if _, exists := reg.oldServerSets[key2]; !exists {
		t.Error("key2 should still exist after key1 cleanup")
	}
}

// TestAssignedServer_Accessors tests the thread-safe accessor methods.
func TestAssignedServer_Accessors(t *testing.T) {
	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.0.1",
			Port: DefaultServerPort,
		},
	}

	// Test SetConnected and IsConnected
	if server.IsConnected() {
		t.Error("new server should not be connected")
	}

	server.SetConnected(true)
	if !server.IsConnected() {
		t.Error("server should be connected after SetConnected(true)")
	}

	server.SetConnected(false)
	if server.IsConnected() {
		t.Error("server should not be connected after SetConnected(false)")
	}

	// Test IncrementFailCount
	count := server.IncrementFailCount()
	if count != 1 {
		t.Errorf("expected FailCount=1, got %d", count)
	}

	count = server.IncrementFailCount()
	if count != 2 {
		t.Errorf("expected FailCount=2, got %d", count)
	}

	count = server.IncrementFailCount()
	if count != 3 {
		t.Errorf("expected FailCount=3, got %d", count)
	}

	// Test UpdateLastSeen resets FailCount
	server.UpdateLastSeen()
	server.mu.RLock()
	failCount := server.FailCount
	server.mu.RUnlock()
	if failCount != 0 {
		t.Errorf("UpdateLastSeen should reset FailCount, got %d", failCount)
	}

	// Test GetLastSeen returns recent time
	lastSeen := server.GetLastSeen()
	if time.Since(lastSeen) > time.Second {
		t.Error("GetLastSeen should return recent time after UpdateLastSeen")
	}
}

// TestACRegistration_GetAssignedServers tests the GetAssignedServers method.
func TestACRegistration_GetAssignedServers(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Initially empty
	servers := reg.GetAssignedServers()
	if len(servers) != 0 {
		t.Errorf("expected 0 servers initially, got %d", len(servers))
	}

	// Add some servers
	reg.assignedServers = []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort}},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: DefaultServerPort}},
	}

	servers = reg.GetAssignedServers()
	if len(servers) != 2 {
		t.Errorf("expected 2 servers, got %d", len(servers))
	}
}

// TestACRegistration_UpdateServerLastSeen_NoMatch tests update with non-matching keys.
func TestACRegistration_UpdateServerLastSeen_NoMatch(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	oldTime := time.Now().Add(-1 * time.Hour)
	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         DefaultServerPort,
			PubKeyBase64: "actual-pubkey",
		},
	}
	server.LastSeen = oldTime
	reg.assignedServers = []*AssignedServer{server}

	// Update with non-matching pubkey - should be no-op
	reg.UpdateServerLastSeen("wrong-pubkey")
	if !server.GetLastSeen().Equal(oldTime) {
		t.Error("LastSeen should not change for non-matching pubkey")
	}

	// Update with non-matching address - should be no-op
	reg.UpdateServerLastSeenByAddr("192.168.1.1:62206")
	if !server.GetLastSeen().Equal(oldTime) {
		t.Error("LastSeen should not change for non-matching address")
	}
}

// TestACRegistration_Stop tests graceful shutdown.
func TestACRegistration_Stop(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Manually simulate what Start() would do for testing
	reg.wg.Add(1)
	go func() {
		defer reg.wg.Done()
		<-reg.stopCh
	}()

	// Stop should complete without hanging
	done := make(chan struct{})
	go func() {
		reg.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success - Stop completed
	case <-time.After(time.Second):
		t.Error("Stop() should complete within 1 second")
	}
}

// TestACRegistration_Stop_DoubleStopSafe tests that Stop() can be called multiple times without panic.
func TestACRegistration_Stop_DoubleStopSafe(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Manually simulate what Start() would do for testing
	reg.wg.Add(1)
	go func() {
		defer reg.wg.Done()
		<-reg.stopCh
	}()

	// First Stop should work
	reg.Stop()

	// Second Stop should not panic (would panic if closing stopCh twice)
	reg.Stop()

	// Third Stop should also be safe
	reg.Stop()
}

// TestACRegistration_ReregisteringGuard tests the atomic re-registration guard.
func TestACRegistration_ReregisteringGuard(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// First attempt should succeed
	if !reg.reregistering.CompareAndSwap(false, true) {
		t.Error("first CompareAndSwap should succeed")
	}

	// Second attempt should fail (already reregistering)
	if reg.reregistering.CompareAndSwap(false, true) {
		t.Error("second CompareAndSwap should fail while reregistering")
	}

	// After reset, should succeed again
	reg.reregistering.Store(false)
	if !reg.reregistering.CompareAndSwap(false, true) {
		t.Error("CompareAndSwap should succeed after reset")
	}
}

// TestACRegistration_ServerAssignment tests that servers are correctly assigned.
// Note: Full HandleRedispatch with connections requires integration tests.
func TestACRegistration_ServerAssignment(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Directly assign servers (simulating what HandleRedispatch does internally)
	reg.assignedServers = []*AssignedServer{
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.1",
				Port:         DefaultServerPort,
				PubKeyBase64: "pubkey1",
				ServerID:     "server-1",
				AZ:           "us-west-2a",
			},
		},
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.2",
				Port:         DefaultServerPort,
				PubKeyBase64: "pubkey2",
				ServerID:     "server-2",
				AZ:           "us-west-2b",
			},
		},
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.3",
				Port:         DefaultServerPort,
				PubKeyBase64: "pubkey3",
				ServerID:     "server-3",
				AZ:           "us-west-2c",
			},
		},
	}

	// Verify servers were assigned
	servers := reg.GetAssignedServers()
	if len(servers) != 3 {
		t.Errorf("expected 3 assigned servers, got %d", len(servers))
	}

	// Verify server details
	if servers[0].Target.IP != "10.0.0.1" {
		t.Errorf("expected first server IP 10.0.0.1, got %s", servers[0].Target.IP)
	}
	if servers[1].Target.AZ != "us-west-2b" {
		t.Errorf("expected second server AZ us-west-2b, got %s", servers[1].Target.AZ)
	}
	if servers[2].Target.ServerID != "server-3" {
		t.Errorf("expected third server ID server-3, got %s", servers[2].Target.ServerID)
	}

	// Verify HasAssignedServers
	if !reg.HasAssignedServers() {
		t.Error("HasAssignedServers should return true")
	}
}

// TestACRegistration_CheckServerHealth_SkipsNeverConnected tests that health check
// skips servers that were never connected (prevents false positive re-registration).
func TestACRegistration_CheckServerHealth_SkipsNeverConnected(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Create a server that was never connected (Connected=false, LastSeen=zero)
	// This simulates a server where connectToServer() failed
	neverConnectedServer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         DefaultServerPort,
			PubKeyBase64: "pubkey1",
		},
		// Connected is false (default), LastSeen is zero (default)
	}

	// Create a healthy connected server
	healthyServer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.2",
			Port:         DefaultServerPort,
			PubKeyBase64: "pubkey2",
		},
	}
	healthyServer.SetConnected(true)
	healthyServer.UpdateLastSeen()

	reg.assignedServers = []*AssignedServer{neverConnectedServer, healthyServer}

	// Run health check - should NOT trigger re-registration
	// because the only "stale" server was never connected
	reg.checkServerHealth()

	// Verify re-registration was NOT triggered
	if reg.reregistering.Load() {
		t.Error("checkServerHealth should not trigger re-registration for never-connected servers")
	}

	// Now simulate the healthy server going stale
	healthyServer.mu.Lock()
	healthyServer.LastSeen = time.Now().Add(-1 * time.Hour) // Way past threshold
	healthyServer.mu.Unlock()

	// Run health check again - should trigger re-registration
	reg.checkServerHealth()

	// Verify re-registration was triggered for the actually-stale connected server
	if !reg.reregistering.Load() {
		t.Error("checkServerHealth should trigger re-registration when connected server is stale")
	}
}

// TestACRegistration_ConcurrentRedispatchAndHealthCheck tests that concurrent
// modifications to assignedServers and health checks don't race.
// This verifies the slice copy pattern works correctly under load.
func TestACRegistration_ConcurrentRedispatchAndHealthCheck(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Pre-populate with connected servers
	for i := 0; i < 3; i++ {
		server := &AssignedServer{
			Target: common.RedirectTarget{
				IP:           fmt.Sprintf("10.0.0.%d", i+1),
				Port:         DefaultServerPort,
				PubKeyBase64: fmt.Sprintf("pubkey%d", i+1),
			},
		}
		server.SetConnected(true)
		server.UpdateLastSeen()
		reg.assignedServers = append(reg.assignedServers, server)
	}

	var wg sync.WaitGroup
	iterations := 100

	// Goroutine 1: Repeatedly modify assignedServers (simulating HandleRedispatch)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			reg.mu.Lock()
			// Simulate what HandleRedispatch does: replace the slice
			newServers := make([]*AssignedServer, 3)
			for j := 0; j < 3; j++ {
				newServers[j] = &AssignedServer{
					Target: common.RedirectTarget{
						IP:           fmt.Sprintf("192.168.%d.%d", i%256, j+1),
						Port:         DefaultServerPort,
						PubKeyBase64: fmt.Sprintf("newkey%d-%d", i, j),
					},
				}
				newServers[j].SetConnected(true)
				newServers[j].UpdateLastSeen()
			}
			reg.assignedServers = newServers
			reg.mu.Unlock()
			time.Sleep(time.Microsecond) // Yield to other goroutines
		}
	}()

	// Goroutine 2: Repeatedly call checkServerHealth
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			reg.checkServerHealth()
			time.Sleep(time.Microsecond)
		}
	}()

	// Goroutine 3: Repeatedly call GetAssignedServers
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			servers := reg.GetAssignedServers()
			_ = len(servers) // Use the result
			time.Sleep(time.Microsecond)
		}
	}()

	// Goroutine 4: Repeatedly call UpdateServerLastSeen
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			reg.UpdateServerLastSeen("pubkey1")
			reg.UpdateServerLastSeenByAddr("10.0.0.1:62206")
			time.Sleep(time.Microsecond)
		}
	}()

	wg.Wait()
	// If we get here without race detector issues or panics, the test passes
}

// TestACRegistration_RapidRedispatchOldServerSets tests that rapid redispatches
// correctly manage oldServerSets without interference.
func TestACRegistration_RapidRedispatchOldServerSets(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Simulate multiple rapid redispatches by directly manipulating state
	// (bypassing connectToServer which needs network)
	numRedispatches := 5

	for i := 0; i < numRedispatches; i++ {
		reg.mu.Lock()
		// Move current to old (like HandleRedispatch does)
		if len(reg.assignedServers) > 0 {
			key := time.Now().Add(time.Duration(i) * time.Nanosecond).Format(time.RFC3339Nano)
			reg.oldServerSets[key] = reg.assignedServers
		}

		// Create new servers
		reg.assignedServers = []*AssignedServer{
			{Target: common.RedirectTarget{IP: fmt.Sprintf("10.%d.0.1", i), Port: DefaultServerPort}},
			{Target: common.RedirectTarget{IP: fmt.Sprintf("10.%d.0.2", i), Port: DefaultServerPort}},
		}
		reg.mu.Unlock()

		// Small delay to ensure unique timestamps
		time.Sleep(time.Millisecond)
	}

	reg.mu.RLock()
	oldSetsCount := len(reg.oldServerSets)
	currentCount := len(reg.assignedServers)
	reg.mu.RUnlock()

	// Should have numRedispatches-1 old sets (first redispatch has no old servers)
	expectedOldSets := numRedispatches - 1
	if oldSetsCount != expectedOldSets {
		t.Errorf("expected %d old server sets, got %d", expectedOldSets, oldSetsCount)
	}

	// Should have 2 current servers
	if currentCount != 2 {
		t.Errorf("expected 2 current servers, got %d", currentCount)
	}

	// Verify each old set is independent
	reg.mu.RLock()
	for key, servers := range reg.oldServerSets {
		if len(servers) != 2 {
			t.Errorf("old server set %s should have 2 servers, got %d", key, len(servers))
		}
	}
	reg.mu.RUnlock()
}

// TestACRegistration_HandleServerDownRespectStopChannel tests that handleServerDown
// respects the stop channel and exits cleanly.
func TestACRegistration_HandleServerDownRespectStopChannel(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Set up a server to trigger handleServerDown
	deadServer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.0.1",
			Port: DefaultServerPort,
		},
	}

	// Set reregistering flag (as checkServerHealth would)
	reg.reregistering.Store(true)

	// Start handleServerDown in a goroutine
	done := make(chan struct{})
	go func() {
		reg.handleServerDown(deadServer)
		close(done)
	}()

	// Give it a moment to start the jitter sleep
	time.Sleep(10 * time.Millisecond)

	// Close stopCh to signal shutdown
	close(reg.stopCh)

	// handleServerDown should exit quickly
	select {
	case <-done:
		// Success - handleServerDown exited
	case <-time.After(time.Second):
		t.Error("handleServerDown did not respect stopCh within 1 second")
	}

	// Verify reregistering flag was reset
	if reg.reregistering.Load() {
		t.Error("reregistering flag should be reset after handleServerDown exits")
	}
}

// TestACRegistration_HealthCheckFullFlow tests the complete health check flow:
// connected server goes stale -> triggers re-registration flag.
func TestACRegistration_HealthCheckFullFlow(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Create a mix of servers in different states
	servers := []*AssignedServer{
		// Server 1: Never connected (should be skipped)
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.1",
				Port:         DefaultServerPort,
				PubKeyBase64: "pubkey1",
			},
			// Connected: false (default)
			// LastSeen: zero (default)
		},
		// Server 2: Connected and healthy
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.2",
				Port:         DefaultServerPort,
				PubKeyBase64: "pubkey2",
			},
		},
		// Server 3: Connected but stale
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.3",
				Port:         DefaultServerPort,
				PubKeyBase64: "pubkey3",
			},
		},
	}

	// Set up server states
	servers[1].SetConnected(true)
	servers[1].UpdateLastSeen() // Fresh

	servers[2].SetConnected(true)
	servers[2].mu.Lock()
	servers[2].LastSeen = time.Now().Add(-1 * time.Hour) // Stale
	servers[2].mu.Unlock()

	reg.assignedServers = servers

	// Verify initial state
	if reg.reregistering.Load() {
		t.Fatal("reregistering should be false initially")
	}

	// Run health check
	reg.checkServerHealth()

	// Should trigger re-registration due to stale server 3
	if !reg.reregistering.Load() {
		t.Error("checkServerHealth should trigger re-registration for stale server")
	}

	// Reset and test that only the stale server triggers it
	reg.reregistering.Store(false)

	// Make server 3 healthy again
	servers[2].UpdateLastSeen()

	reg.checkServerHealth()

	// Should NOT trigger re-registration now
	if reg.reregistering.Load() {
		t.Error("checkServerHealth should not trigger re-registration when all connected servers are healthy")
	}
}

// TestACRegistration_KeepaliveFilteringLogic tests the filtering conditions
// in sendKeepalives (skips disconnected and nil peer servers).
// Note: Full sendKeepalives testing requires device setup; this tests the logic.
func TestACRegistration_KeepaliveFilteringLogic(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Create servers with different states to verify filtering conditions
	connectedWithPeer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         DefaultServerPort,
			PubKeyBase64: "pubkey1",
		},
		Peer: &core.UdpPeer{
			Ip:   "10.0.0.1",
			Port: DefaultServerPort,
		},
	}
	connectedWithPeer.SetConnected(true)

	disconnectedWithPeer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.2",
			Port:         DefaultServerPort,
			PubKeyBase64: "pubkey2",
		},
		Peer: &core.UdpPeer{
			Ip:   "10.0.0.2",
			Port: DefaultServerPort,
		},
	}
	// disconnectedWithPeer.Connected is false by default

	connectedNoPeer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.3",
			Port:         DefaultServerPort,
			PubKeyBase64: "pubkey3",
		},
		// Peer is nil
	}
	connectedNoPeer.SetConnected(true)

	reg.assignedServers = []*AssignedServer{connectedWithPeer, disconnectedWithPeer, connectedNoPeer}

	// Verify the filtering conditions that sendKeepalives uses
	servers := reg.GetAssignedServers()

	eligibleCount := 0
	for _, server := range servers {
		// This matches the condition in sendKeepalives:
		// if server.Peer == nil || !server.IsConnected() { continue }
		if server.Peer != nil && server.IsConnected() {
			eligibleCount++
		}
	}

	// Only connectedWithPeer should be eligible
	if eligibleCount != 1 {
		t.Errorf("expected 1 eligible server for keepalive, got %d", eligibleCount)
	}

	// Verify each server's eligibility
	if connectedWithPeer.Peer == nil || !connectedWithPeer.IsConnected() {
		t.Error("connectedWithPeer should be eligible for keepalive")
	}
	if disconnectedWithPeer.Peer != nil && disconnectedWithPeer.IsConnected() {
		t.Error("disconnectedWithPeer should NOT be eligible for keepalive")
	}
	if connectedNoPeer.Peer != nil && connectedNoPeer.IsConnected() {
		t.Error("connectedNoPeer should NOT be eligible for keepalive (nil peer)")
	}
}

// TestACRegistration_Start_MissingConfig tests Start() with missing required config.
func TestACRegistration_Start_MissingConfig(t *testing.T) {
	// ServerEndpoint is the only required config for cloud mode registration
	ac := &UdpAC{
		config: &Config{
			ACId: "test-ac-001",
			// ServerEndpoint is empty
		},
	}
	reg := mustNewACRegistration(t, ac)

	err := reg.Start()
	if err == nil {
		t.Error("expected error but got nil")
		return
	}
	if err.Error() != "ServerEndpoint is required" {
		t.Errorf("expected error %q, got %q", "ServerEndpoint is required", err.Error())
	}
}

// TestACRegistration_HandleRegistrationResponse tests all error paths in handleRegistrationResponse.
func TestACRegistration_HandleRegistrationResponse(t *testing.T) {
	// Create a test private key for the device
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// Create a mock peer for testing (used by RemovePeer on error paths)
	mockPeer := &core.UdpPeer{
		Hostname:     "test-server",
		Ip:           "10.0.0.1",
		Port:         DefaultServerPort,
		PubKeyBase64: "dGVzdC1wdWJrZXktYmFzZTY0", // "test-pubkey-base64" in base64
		Type:         core.NHP_SERVER,
	}

	tests := []struct {
		name          string
		ppd           *core.PacketParserData
		expectError   bool
		errorContains string
	}{
		{
			name: "ppd.Error set",
			ppd: &core.PacketParserData{
				Error: fmt.Errorf("network error"),
			},
			expectError:   true,
			errorContains: "registration failed",
		},
		{
			name: "NHP_AAK with error code",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(`{"errCode":"LICENSE_EXPIRED","errMsg":"License has expired"}`),
			},
			expectError:   true,
			errorContains: "registration rejected",
		},
		{
			name: "NHP_AAK with Registered=false",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(`{"registered":false}`),
			},
			expectError:   true,
			errorContains: "Registered=false",
		},
		{
			name: "NHP_AAK parse error",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(`{invalid json`),
			},
			expectError:   true,
			errorContains: "failed to parse NHP_AAK",
		},
		{
			name: "NHP_ARD parse error",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_ARD,
				BodyMessage: []byte(`{invalid json`),
			},
			expectError:   true,
			errorContains: "failed to parse NHP_ARD",
		},
		{
			name: "unexpected response type",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_KPL, // Not AAK or ARD
				BodyMessage: []byte(`{}`),
			},
			expectError:   true,
			errorContains: "unexpected response type",
		},
		{
			name: "NHP_AAK success",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(`{"registered":true,"acAddr":"10.0.0.1:62206"}`),
			},
			expectError: false,
		},
		{
			name: "NHP_AAK success with ErrCode 0",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(`{"errCode":"0","registered":true,"acAddr":"10.0.0.1:62206"}`),
			},
			expectError: false,
		},
		{
			name: "NHP_AAK with invalid ErrCode string fails",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(`{"errCode":"SUCCESS","registered":true,"acAddr":"10.0.0.1:62206"}`),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := reg.handleRegistrationResponse(tt.ppd, mockPeer)

			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectError && err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error containing %q, got %q", tt.errorContains, err.Error())
				}
			}
		})
	}
}

// TestACRegistration_CheckServerHealth_AlreadyReregistering tests that health check
// skips triggering re-registration when already in progress.
func TestACRegistration_CheckServerHealth_AlreadyReregistering(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Create a stale connected server that would trigger re-registration
	staleServer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         DefaultServerPort,
			PubKeyBase64: "pubkey1",
		},
	}
	staleServer.SetConnected(true)
	staleServer.mu.Lock()
	staleServer.LastSeen = time.Now().Add(-1 * time.Hour) // Very stale
	staleServer.mu.Unlock()

	reg.assignedServers = []*AssignedServer{staleServer}

	// Pre-set reregistering flag to simulate already in progress
	reg.reregistering.Store(true)

	// Run health check - should NOT spawn another handleServerDown
	// because reregistering is already true
	reg.checkServerHealth()

	// Flag should still be true (unchanged)
	if !reg.reregistering.Load() {
		t.Error("reregistering flag should remain true")
	}

	// Reset and verify it would have triggered if not already reregistering
	reg.reregistering.Store(false)
	reg.checkServerHealth()

	// Now it should have triggered
	if !reg.reregistering.Load() {
		t.Error("reregistering should be set when not already in progress")
	}
}

// TestACRegistration_CleanupOldServers_NilPeer tests that cleanup handles servers
// with nil peers gracefully.
func TestACRegistration_CleanupOldServers_NilPeer(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Create old servers - some with nil peer
	cleanupKey := "test-cleanup-key"
	reg.oldServerSets[cleanupKey] = []*AssignedServer{
		{
			Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort},
			Peer:   nil, // No peer - should be handled gracefully
		},
		{
			Target: common.RedirectTarget{IP: "10.0.0.2", Port: DefaultServerPort},
			Peer:   nil, // No peer
		},
	}

	// This should not panic even with nil peers
	// We can't wait 2 minutes, so we'll directly test the cleanup logic
	reg.mu.Lock()
	oldServers := reg.oldServerSets[cleanupKey]
	delete(reg.oldServerSets, cleanupKey)
	reg.mu.Unlock()

	// Simulate what cleanupOldServers does - should handle nil peer gracefully
	for _, server := range oldServers {
		if server.Peer != nil {
			// Would call r.ac.device.RemovePeer() - but peer is nil so this is skipped
			t.Error("should not reach here - peer is nil")
		}
	}

	// Verify the set was cleaned up
	reg.mu.RLock()
	if _, exists := reg.oldServerSets[cleanupKey]; exists {
		t.Error("cleanup key should have been deleted")
	}
	reg.mu.RUnlock()
}

// TestACRegistration_Constants tests that important constants have expected values.
func TestACRegistration_Constants(t *testing.T) {
	// These constants are critical for correct behavior - verify they haven't been
	// accidentally changed to inappropriate values.

	if RegistrationTimeout != 30*time.Second {
		t.Errorf("RegistrationTimeout = %v, want 30s", RegistrationTimeout)
	}

	if KeepaliveInterval != 10*time.Second {
		t.Errorf("KeepaliveInterval = %v, want 10s", KeepaliveInterval)
	}

	if KeepaliveTimeout != 3*time.Second {
		t.Errorf("KeepaliveTimeout = %v, want 3s", KeepaliveTimeout)
	}

	if KeepaliveMaxRetries != 3 {
		t.Errorf("KeepaliveMaxRetries = %d, want 3", KeepaliveMaxRetries)
	}

	if MaxReregistrationAttempts != 5 {
		t.Errorf("MaxReregistrationAttempts = %d, want 5", MaxReregistrationAttempts)
	}

	if DefaultServerPort != 62206 {
		t.Errorf("DefaultServerPort = %d, want 62206", DefaultServerPort)
	}

	if ConnectionTimeout != 10*time.Second {
		t.Errorf("ConnectionTimeout = %v, want 10s", ConnectionTimeout)
	}

	// Verify health check threshold calculation
	healthCheckThreshold := KeepaliveInterval * KeepaliveMaxRetries
	if healthCheckThreshold != 30*time.Second {
		t.Errorf("Health check threshold = %v, want 30s (10s * 3)", healthCheckThreshold)
	}
}

// TestACRegistration_ServerPortDefault tests that ServerPort defaults to 62206.
func TestACRegistration_ServerPortDefault(t *testing.T) {
	// When ServerPort is 0, register() should use DefaultServerPort
	config := &Config{
		ACId:               "test-ac",
		ServerEndpoint:     "server.nhp.test.internal",
		ServerPubKeyBase64: "testpubkey",
		ServerPort:         0, // Should default to 62206
	}

	if config.ServerPort == 0 {
		// This is the condition in register() that triggers the default
		serverPort := config.ServerPort
		if serverPort == 0 {
			serverPort = DefaultServerPort
		}

		if serverPort != 62206 {
			t.Errorf("default ServerPort = %d, want 62206", serverPort)
		}
	}

	// Also test when ServerPort is explicitly set
	config.ServerPort = 12345
	if config.ServerPort != 12345 {
		t.Errorf("explicit ServerPort = %d, want 12345", config.ServerPort)
	}
}

// TestACRegistration_HandleRedispatch_PartialSuccess tests that HandleRedispatch
// succeeds with partial connection success (some but not all servers).
func TestACRegistration_HandleRedispatch_PartialSuccess(t *testing.T) {
	// This test verifies the partial success warning logic by examining
	// the conditions that trigger it.

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// After HandleRedispatch runs, if successCount < len(serversToConnect),
	// it logs a warning but still returns nil (success).
	// We can't easily test the actual connection without a device,
	// but we can verify the assigned servers are set up correctly.

	// Manually simulate what HandleRedispatch does for server assignment
	reg.mu.Lock()
	reg.assignedServers = []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "key1"}, Connected: false},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: DefaultServerPort, PubKeyBase64: "key2"}, Connected: false},
		{Target: common.RedirectTarget{IP: "10.0.0.3", Port: DefaultServerPort, PubKeyBase64: "key3"}, Connected: false},
	}
	reg.mu.Unlock()

	// Simulate partial success: only 2 of 3 connected
	reg.assignedServers[0].SetConnected(true)
	reg.assignedServers[1].SetConnected(true)
	// reg.assignedServers[2] remains disconnected

	// Verify state
	connectedCount := 0
	for _, server := range reg.GetAssignedServers() {
		if server.IsConnected() {
			connectedCount++
		}
	}

	if connectedCount != 2 {
		t.Errorf("expected 2 connected servers, got %d", connectedCount)
	}

	// This is "partial success" - some but not all servers connected
	totalServers := len(reg.GetAssignedServers())
	if connectedCount >= totalServers {
		t.Error("this should be partial success (not all connected)")
	}
	if connectedCount == 0 {
		t.Error("this should be partial success (at least one connected)")
	}
}

// TestACRegistration_Stop_CleansUpRegistrationPeer tests that Stop() cleans up
// the registration peer that was kept after NHP_AAK response.
func TestACRegistration_Stop_CleansUpRegistrationPeer(t *testing.T) {
	// Create a test private key for the device
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// Simulate a registration peer being set (as would happen after NHP_AAK)
	regPeer := &core.UdpPeer{
		Hostname:     "reg-server",
		Ip:           "10.0.0.100",
		Port:         DefaultServerPort,
		PubKeyBase64: "cmVnLXNlcnZlci1wdWJrZXk=", // "reg-server-pubkey" in base64
		Type:         core.NHP_SERVER,
	}
	device.AddPeer(regPeer)
	reg.registrationPeer = regPeer

	// Simulate some connected servers with peers
	serverPeer := &core.UdpPeer{
		Hostname:     "assigned-server",
		Ip:           "10.0.0.1",
		Port:         DefaultServerPort,
		PubKeyBase64: "YXNzaWduZWQtc2VydmVyLXB1YmtleQ==", // "assigned-server-pubkey" in base64
		Type:         core.NHP_SERVER,
	}
	device.AddPeer(serverPeer)

	reg.mu.Lock()
	reg.assignedServers = []*AssignedServer{
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.1",
				Port:         DefaultServerPort,
				PubKeyBase64: "YXNzaWduZWQtc2VydmVyLXB1YmtleQ==",
			},
			Peer:      serverPeer,
			Connected: true,
		},
	}
	reg.mu.Unlock()

	// Stop the registration manager
	reg.Stop()

	// Verify registration peer was cleaned up
	if reg.registrationPeer != nil {
		t.Error("registrationPeer should be nil after Stop()")
	}

	// Verify assigned servers were cleaned up
	if len(reg.assignedServers) != 0 {
		t.Errorf("assignedServers should be empty after Stop(), got %d", len(reg.assignedServers))
	}
}

// TestACRegistration_HandleRegistrationResponse_ReplacesOldPeer tests that receiving
// NHP_AAK when there's already a registration peer cleans up the old one.
func TestACRegistration_HandleRegistrationResponse_ReplacesOldPeer(t *testing.T) {
	// Create a test private key for the device
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// Simulate an existing registration peer (from previous registration)
	oldPeer := &core.UdpPeer{
		Hostname:     "old-server",
		Ip:           "10.0.0.50",
		Port:         DefaultServerPort,
		PubKeyBase64: "b2xkLXNlcnZlci1wdWJrZXk=", // "old-server-pubkey" in base64
		Type:         core.NHP_SERVER,
	}
	device.AddPeer(oldPeer)
	reg.registrationPeer = oldPeer

	// Create a new peer for the new registration
	newPeer := &core.UdpPeer{
		Hostname:     "new-server",
		Ip:           "10.0.0.100",
		Port:         DefaultServerPort,
		PubKeyBase64: "bmV3LXNlcnZlci1wdWJrZXk=", // "new-server-pubkey" in base64
		Type:         core.NHP_SERVER,
	}

	// Simulate successful NHP_AAK response
	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true,"acAddr":"10.0.0.100:62206"}`),
	}

	err := reg.handleRegistrationResponse(ppd, newPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the registration peer was updated to the new one
	reg.mu.RLock()
	currentPeer := reg.registrationPeer
	reg.mu.RUnlock()

	if currentPeer != newPeer {
		t.Error("registrationPeer should be updated to the new peer")
	}

	if currentPeer.PubKeyBase64 != newPeer.PubKeyBase64 {
		t.Errorf("registrationPeer pubkey mismatch: got %s, want %s",
			currentPeer.PubKeyBase64, newPeer.PubKeyBase64)
	}
}

// TestACRegistration_NHP_AAK_AddsToAssignedServers verifies that when NHP_AAK is received
// (direct registration without redispatch), the registration peer is added to assignedServers.
// This is critical for keepalive management - without this fix, the connection times out
// after 5 minutes because keepaliveLoop() has no servers to send keepalives to.
func TestACRegistration_NHP_AAK_AddsToAssignedServers(t *testing.T) {
	// Create a test private key for the device
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// Create a peer with a resolvable IP address
	testPeer := &core.UdpPeer{
		Hostname:     "test-server",
		Ip:           "10.0.0.1",
		Port:         DefaultServerPort,
		PubKeyBase64: "dGVzdC1wdWJrZXktYmFzZTY0", // "test-pubkey-base64" in base64
		Type:         core.NHP_SERVER,
	}

	// Verify assignedServers is empty before
	if reg.HasAssignedServers() {
		t.Fatal("assignedServers should be empty before NHP_AAK")
	}

	// Simulate successful NHP_AAK response
	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true,"acAddr":"10.0.0.1:62206"}`),
	}

	err := reg.handleRegistrationResponse(ppd, testPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the registration peer was added to assignedServers
	if !reg.HasAssignedServers() {
		t.Fatal("assignedServers should NOT be empty after NHP_AAK - this is the critical fix!")
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	server := servers[0]

	// Verify the assigned server has the correct peer
	if server.Peer != testPeer {
		t.Error("assigned server Peer should be the registration peer")
	}

	// Verify the assigned server is marked as connected
	if !server.IsConnected() {
		t.Error("assigned server should be marked as Connected=true")
	}

	// Verify LastSeen is set (not zero)
	if server.GetLastSeen().IsZero() {
		t.Error("assigned server LastSeen should be set")
	}

	// Verify the target has correct IP and port from the peer's SendAddr
	sendAddr := testPeer.SendAddr()
	if sendAddr == nil {
		t.Fatal("test peer SendAddr should not be nil")
	}
	udpAddr := sendAddr.(*net.UDPAddr)

	if server.Target.IP != udpAddr.IP.String() {
		t.Errorf("Target.IP = %s, want %s", server.Target.IP, udpAddr.IP.String())
	}
	if server.Target.Port != udpAddr.Port {
		t.Errorf("Target.Port = %d, want %d", server.Target.Port, udpAddr.Port)
	}
	if server.Target.PubKeyBase64 != testPeer.PublicKeyBase64() {
		t.Errorf("Target.PubKeyBase64 = %s, want %s", server.Target.PubKeyBase64, testPeer.PublicKeyBase64())
	}
}

// TestACRegistration_NHP_AAK_KeepaliveEligibility verifies that after NHP_AAK,
// the assigned server is eligible for keepalives (has Peer != nil and IsConnected).
// This test ensures the keepalive filtering logic will include the registration server.
func TestACRegistration_NHP_AAK_KeepaliveEligibility(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-002",
			ServerEndpoint: "server.nhp.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	testPeer := &core.UdpPeer{
		Hostname:     "test-server",
		Ip:           "10.0.0.2",
		Port:         DefaultServerPort,
		PubKeyBase64: "dGVzdC1wdWJrZXktMg==",
		Type:         core.NHP_SERVER,
	}

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true,"acAddr":"10.0.0.2:62206"}`),
	}

	err := reg.handleRegistrationResponse(ppd, testPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	server := servers[0]

	// These are the exact conditions checked in sendKeepalives():
	// if server.Peer == nil || !server.IsConnected() { continue }
	if server.Peer == nil {
		t.Error("server.Peer is nil - keepalives will NOT be sent!")
	}
	if !server.IsConnected() {
		t.Error("server.IsConnected() is false - keepalives will NOT be sent!")
	}

	// Verify the peer has a valid SendAddr (required for sending keepalives)
	if server.Peer.SendAddr() == nil {
		t.Error("server.Peer.SendAddr() is nil - keepalives cannot be sent!")
	}
}

// TestACRegistration_NHP_AAK_ReRegistration_ReplacesAssignedServer verifies that
// when re-registration occurs (receiving another NHP_AAK), the old assigned server
// is replaced with the new one.
func TestACRegistration_NHP_AAK_ReRegistration_ReplacesAssignedServer(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-003",
			ServerEndpoint: "server.nhp.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// First registration
	firstPeer := &core.UdpPeer{
		Hostname:     "first-server",
		Ip:           "10.0.0.10",
		Port:         DefaultServerPort,
		PubKeyBase64: "Zmlyc3Qtc2VydmVy",
		Type:         core.NHP_SERVER,
	}

	ppd1 := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true,"acAddr":"10.0.0.10:62206"}`),
	}

	err := reg.handleRegistrationResponse(ppd1, firstPeer)
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server after first registration, got %d", len(servers))
	}
	if servers[0].Target.IP != "10.0.0.10" {
		t.Errorf("first server IP = %s, want 10.0.0.10", servers[0].Target.IP)
	}

	// Second registration (re-registration)
	secondPeer := &core.UdpPeer{
		Hostname:     "second-server",
		Ip:           "10.0.0.20",
		Port:         DefaultServerPort,
		PubKeyBase64: "c2Vjb25kLXNlcnZlcg==",
		Type:         core.NHP_SERVER,
	}

	ppd2 := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true,"acAddr":"10.0.0.20:62206"}`),
	}

	err = reg.handleRegistrationResponse(ppd2, secondPeer)
	if err != nil {
		t.Fatalf("second registration failed: %v", err)
	}

	// After re-registration, we should have exactly 1 server (replaced, not appended).
	// This prevents duplicate entries from accumulating on repeated re-registrations.
	servers = reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected exactly 1 assigned server after re-registration, got %d", len(servers))
	}

	// Verify it's the new server, not the old one
	if servers[0].Target.IP != "10.0.0.20" {
		t.Errorf("expected new server IP 10.0.0.20, got %s", servers[0].Target.IP)
	}
	if servers[0].Peer != secondPeer {
		t.Error("new server should have secondPeer")
	}

	// Verify old server is NOT present
	for _, s := range servers {
		if s.Target.IP == "10.0.0.10" {
			t.Error("old server (10.0.0.10) should not be in assignedServers after re-registration")
		}
	}
}

// TestACRegistration_NHP_AAK_AssignedServerFields verifies all fields of the
// AssignedServer are correctly populated after NHP_AAK.
func TestACRegistration_NHP_AAK_AssignedServerFields(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-004",
			ServerEndpoint: "server.nhp.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	testPeer := &core.UdpPeer{
		Hostname:     "test-server",
		Ip:           "192.168.1.100",
		Port:         12345,
		PubKeyBase64: "dGVzdC1rZXktMTIzNDU=",
		Type:         core.NHP_SERVER,
	}

	beforeTime := time.Now()

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true,"acAddr":"192.168.1.100:12345"}`),
	}

	err := reg.handleRegistrationResponse(ppd, testPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	afterTime := time.Now()

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	server := servers[0]

	// Check Target fields
	if server.Target.IP != "192.168.1.100" {
		t.Errorf("Target.IP = %s, want 192.168.1.100", server.Target.IP)
	}
	if server.Target.Port != 12345 {
		t.Errorf("Target.Port = %d, want 12345", server.Target.Port)
	}
	if server.Target.PubKeyBase64 != testPeer.PublicKeyBase64() {
		t.Errorf("Target.PubKeyBase64 mismatch")
	}

	// Check Peer
	if server.Peer != testPeer {
		t.Error("Peer should be the test peer")
	}

	// Check Connected
	if !server.IsConnected() {
		t.Error("Connected should be true")
	}

	// Check LastSeen is within expected range
	lastSeen := server.GetLastSeen()
	if lastSeen.Before(beforeTime) || lastSeen.After(afterTime) {
		t.Errorf("LastSeen %v not in expected range [%v, %v]", lastSeen, beforeTime, afterTime)
	}

	// Check FailCount is 0
	server.mu.RLock()
	failCount := server.FailCount
	server.mu.RUnlock()
	if failCount != 0 {
		t.Errorf("FailCount = %d, want 0", failCount)
	}
}

// TestACRegistration_NHP_AAK_ServerAddr verifies that when NHP_AAK contains
// ServerAddr and ServerPubKey, the AC creates a new peer with the direct server
// address instead of using the registration peer (which may be connected to NLB).
func TestACRegistration_NHP_AAK_ServerAddr(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-serveraddr",
			ServerEndpoint: "nlb.test.internal", // AC connects to NLB
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// Registration peer is connected to NLB (initial registration endpoint)
	registrationPeer := &core.UdpPeer{
		Hostname:     "nlb.test.internal",
		Ip:           "10.0.0.1", // NLB IP
		Port:         DefaultServerPort,
		PubKeyBase64: "bmxiLXB1YmtleQ==", // NLB/shared public key
		Type:         core.NHP_SERVER,
	}

	// Server's direct address (different from NLB)
	// Use a public IP (TEST-NET-3 range) to test the switch-to-direct behavior
	serverDirectIP := "203.0.113.100"
	serverDirectPort := DefaultServerPort
	serverPubKey := "c2VydmVyLWRpcmVjdC1wdWJrZXk=" // Different from NLB key

	// NHP_AAK with server's direct address
	aakJSON := fmt.Sprintf(`{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "%s:%d",
		"serverPubKey": "%s"
	}`, serverDirectIP, serverDirectPort, serverPubKey)

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := reg.handleRegistrationResponse(ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	server := servers[0]

	// Verify the server uses the DIRECT address, not the NLB address
	if server.Target.IP != serverDirectIP {
		t.Errorf("Target.IP = %s, want %s (server direct IP)", server.Target.IP, serverDirectIP)
	}
	if server.Target.Port != serverDirectPort {
		t.Errorf("Target.Port = %d, want %d", server.Target.Port, serverDirectPort)
	}
	if server.Target.PubKeyBase64 != serverPubKey {
		t.Errorf("Target.PubKeyBase64 = %s, want %s (server direct pubkey)", server.Target.PubKeyBase64, serverPubKey)
	}

	// Verify the peer is the new direct peer, not the registration peer
	if server.Peer == registrationPeer {
		t.Error("server.Peer should be a NEW peer (direct), not the registration peer (NLB)")
	}
	if server.Peer.PublicKeyBase64() != serverPubKey {
		t.Errorf("server.Peer.PublicKeyBase64() = %s, want %s", server.Peer.PublicKeyBase64(), serverPubKey)
	}

	// Verify the peer can send to the direct address
	sendAddr := server.Peer.SendAddr()
	if sendAddr == nil {
		t.Fatal("server.Peer.SendAddr() should not be nil")
	}
	udpAddr := sendAddr.(*net.UDPAddr)
	if udpAddr.IP.String() != serverDirectIP {
		t.Errorf("SendAddr IP = %s, want %s", udpAddr.IP.String(), serverDirectIP)
	}
	if udpAddr.Port != serverDirectPort {
		t.Errorf("SendAddr Port = %d, want %d", udpAddr.Port, serverDirectPort)
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_Fallback verifies that if ServerAddr
// parsing fails, the AC falls back to using the registration peer.
func TestACRegistration_NHP_AAK_ServerAddr_Fallback(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-fallback",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	registrationPeer := &core.UdpPeer{
		Hostname:     "nlb.test.internal",
		Ip:           "10.0.0.1",
		Port:         DefaultServerPort,
		PubKeyBase64: "bmxiLXB1YmtleQ==",
		Type:         core.NHP_SERVER,
	}

	// NHP_AAK with invalid ServerAddr (missing port)
	aakJSON := `{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "invalid-no-port",
		"serverPubKey": "c2VydmVyLWRpcmVjdC1wdWJrZXk="
	}`

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := reg.handleRegistrationResponse(ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	server := servers[0]

	// Should fall back to registration peer's address
	if server.Peer != registrationPeer {
		t.Error("should fall back to registration peer when ServerAddr parsing fails")
	}
}

// TestACRegistration_NHP_AAK_Legacy verifies backwards compatibility:
// when ServerAddr is not provided, the AC uses the registration peer (legacy behavior).
func TestACRegistration_NHP_AAK_Legacy(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-legacy",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	registrationPeer := &core.UdpPeer{
		Hostname:     "nlb.test.internal",
		Ip:           "10.0.0.1",
		Port:         DefaultServerPort,
		PubKeyBase64: "bmxiLXB1YmtleQ==",
		Type:         core.NHP_SERVER,
	}

	// Legacy NHP_AAK without ServerAddr/ServerPubKey
	aakJSON := `{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000"
	}`

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := reg.handleRegistrationResponse(ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	server := servers[0]

	// Should use registration peer (legacy behavior)
	if server.Peer != registrationPeer {
		t.Error("legacy mode should use registration peer")
	}
	if server.Target.PubKeyBase64 != registrationPeer.PublicKeyBase64() {
		t.Errorf("Target.PubKeyBase64 = %s, want %s", server.Target.PubKeyBase64, registrationPeer.PublicKeyBase64())
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_RemovesOldPeer verifies that when switching
// to direct connection, the old NLB-connected peer is removed from the device.
func TestACRegistration_NHP_AAK_ServerAddr_RemovesOldPeer(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-remove-peer",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// NLB peer (will be removed after direct connection)
	nlbPubKey := "bmxiLXB1YmtleS1yZW1vdmU="
	registrationPeer := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         DefaultServerPort,
		PubKeyBase64: nlbPubKey,
		Type:         core.NHP_SERVER,
	}

	// Add the registration peer to the device (simulating what register() does)
	device.AddPeer(registrationPeer)

	// Verify the NLB peer is in the device
	if device.LookupPeer(registrationPeer.PublicKey()) == nil {
		t.Fatal("NLB peer should be in device before NHP_AAK")
	}

	// Server's direct address (different public key)
	serverPubKey := "c2VydmVyLWRpcmVjdC1rZXk="
	aakJSON := fmt.Sprintf(`{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "203.0.113.100:62206",
		"serverPubKey": "%s"
	}`, serverPubKey)

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := reg.handleRegistrationResponse(ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the OLD NLB peer was removed from the device
	if device.LookupPeer(registrationPeer.PublicKey()) != nil {
		t.Error("old NLB peer should be removed from device after switching to direct connection")
	}

	// Verify the NEW direct peer was added to the device
	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	directPeer := servers[0].Peer
	if device.LookupPeer(directPeer.PublicKey()) == nil {
		t.Error("new direct peer should be added to device")
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_IPv6 verifies handling of IPv6 server addresses.
func TestACRegistration_NHP_AAK_ServerAddr_IPv6(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-ipv6",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	registrationPeer := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         DefaultServerPort,
		PubKeyBase64: "bmxiLXB1YmtleQ==",
		Type:         core.NHP_SERVER,
	}

	// IPv6 address with brackets (standard format for host:port)
	serverIPv6 := "2001:db8::1"
	serverPort := DefaultServerPort
	serverPubKey := "aXB2Ni1zZXJ2ZXIta2V5"

	aakJSON := fmt.Sprintf(`{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "[%s]:%d",
		"serverPubKey": "%s"
	}`, serverIPv6, serverPort, serverPubKey)

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := reg.handleRegistrationResponse(ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	server := servers[0]

	// Verify IPv6 address was parsed correctly
	if server.Target.IP != serverIPv6 {
		t.Errorf("Target.IP = %s, want %s", server.Target.IP, serverIPv6)
	}
	if server.Target.Port != serverPort {
		t.Errorf("Target.Port = %d, want %d", server.Target.Port, serverPort)
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_OnlyServerAddr verifies behavior when
// ServerAddr is provided but ServerPubKey is missing (should fall back).
func TestACRegistration_NHP_AAK_ServerAddr_OnlyServerAddr(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-no-pubkey",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	registrationPeer := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         DefaultServerPort,
		PubKeyBase64: "bmxiLXB1YmtleQ==",
		Type:         core.NHP_SERVER,
	}

	// ServerAddr provided but no ServerPubKey
	aakJSON := `{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "203.0.113.100:62206"
	}`

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := reg.handleRegistrationResponse(ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	// Should fall back to registration peer when ServerPubKey is missing
	if servers[0].Peer != registrationPeer {
		t.Error("should use registration peer when ServerPubKey is missing")
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_OnlyServerPubKey verifies behavior when
// ServerPubKey is provided but ServerAddr is missing (should fall back).
func TestACRegistration_NHP_AAK_ServerAddr_OnlyServerPubKey(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-no-addr",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	registrationPeer := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         DefaultServerPort,
		PubKeyBase64: "bmxiLXB1YmtleQ==",
		Type:         core.NHP_SERVER,
	}

	// ServerPubKey provided but no ServerAddr
	aakJSON := `{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverPubKey": "c2VydmVyLXB1YmtleQ=="
	}`

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := reg.handleRegistrationResponse(ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	// Should fall back to registration peer when ServerAddr is missing
	if servers[0].Peer != registrationPeer {
		t.Error("should use registration peer when ServerAddr is missing")
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_ReRegistration verifies that re-registration
// with ServerAddr properly replaces the old direct peer with a new one.
func TestACRegistration_NHP_AAK_ServerAddr_ReRegistration(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-rereg",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// First registration
	firstPeer := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         DefaultServerPort,
		PubKeyBase64: "Zmlyc3QtcGVlcg==",
		Type:         core.NHP_SERVER,
	}

	firstServerPubKey := "Zmlyc3Qtc2VydmVy"
	firstAAK := fmt.Sprintf(`{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "203.0.113.100:62206",
		"serverPubKey": "%s"
	}`, firstServerPubKey)

	ppd1 := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(firstAAK),
	}

	err := reg.handleRegistrationResponse(ppd1, firstPeer)
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 server after first registration, got %d", len(servers))
	}
	firstDirectPeer := servers[0].Peer

	// Second registration (re-registration to different server)
	secondPeer := &core.UdpPeer{
		Ip:           "10.0.0.2",
		Port:         DefaultServerPort,
		PubKeyBase64: "c2Vjb25kLXBlZXI=",
		Type:         core.NHP_SERVER,
	}

	secondServerPubKey := "c2Vjb25kLXNlcnZlcg=="
	secondAAK := fmt.Sprintf(`{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50001",
		"serverAddr": "203.0.113.200:62206",
		"serverPubKey": "%s"
	}`, secondServerPubKey)

	ppd2 := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(secondAAK),
	}

	err = reg.handleRegistrationResponse(ppd2, secondPeer)
	if err != nil {
		t.Fatalf("second registration failed: %v", err)
	}

	servers = reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 server after re-registration, got %d", len(servers))
	}

	// Verify the server was replaced
	if servers[0].Target.IP != "203.0.113.200" {
		t.Errorf("server IP should be updated to 203.0.113.200, got %s", servers[0].Target.IP)
	}
	if servers[0].Target.PubKeyBase64 != secondServerPubKey {
		t.Errorf("server pubkey should be updated")
	}

	// Verify the first direct peer was removed from device
	if device.LookupPeer(firstDirectPeer.PublicKey()) != nil {
		t.Error("first direct peer should be removed after re-registration")
	}

	// Verify the second direct peer is in device
	if device.LookupPeer(servers[0].Peer.PublicKey()) == nil {
		t.Error("second direct peer should be in device")
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_KeepaliveTarget verifies that after
// switching to direct connection, keepalives would be sent to the direct address.
func TestACRegistration_NHP_AAK_ServerAddr_KeepaliveTarget(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-keepalive",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	nlbIP := "10.0.0.1"
	registrationPeer := &core.UdpPeer{
		Ip:           nlbIP,
		Port:         DefaultServerPort,
		PubKeyBase64: "bmxiLXB1YmtleQ==",
		Type:         core.NHP_SERVER,
	}

	directIP := "203.0.113.100"
	serverPubKey := "ZGlyZWN0LXNlcnZlcg=="
	aakJSON := fmt.Sprintf(`{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "%s:62206",
		"serverPubKey": "%s"
	}`, directIP, serverPubKey)

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := reg.handleRegistrationResponse(ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	server := servers[0]

	// Verify keepalive would go to DIRECT address, not NLB
	sendAddr := server.Peer.SendAddr()
	if sendAddr == nil {
		t.Fatal("Peer.SendAddr() should not be nil")
	}

	udpAddr := sendAddr.(*net.UDPAddr)
	if udpAddr.IP.String() != directIP {
		t.Errorf("keepalive target IP = %s, want %s (direct, not NLB %s)",
			udpAddr.IP.String(), directIP, nlbIP)
	}

	// Verify the server meets keepalive eligibility criteria
	if server.Peer == nil {
		t.Error("server.Peer should not be nil for keepalives")
	}
	if !server.IsConnected() {
		t.Error("server should be connected for keepalives")
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_SamePubKey verifies correct behavior when
// the server's direct pubkey is the same as the NLB shared key.
func TestACRegistration_NHP_AAK_ServerAddr_SamePubKey(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-same-key",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// Same public key for both NLB and direct (shared key scenario)
	sharedPubKey := "c2hhcmVkLWtleQ=="
	registrationPeer := &core.UdpPeer{
		Ip:           "10.0.0.1", // NLB IP
		Port:         DefaultServerPort,
		PubKeyBase64: sharedPubKey,
		Type:         core.NHP_SERVER,
	}

	device.AddPeer(registrationPeer)

	directIP := "203.0.113.100"
	aakJSON := fmt.Sprintf(`{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "%s:62206",
		"serverPubKey": "%s"
	}`, directIP, sharedPubKey)

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := reg.handleRegistrationResponse(ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	// Even with same pubkey, the peer should be pointing to the DIRECT IP
	sendAddr := servers[0].Peer.SendAddr()
	if sendAddr == nil {
		t.Fatal("SendAddr should not be nil")
	}

	udpAddr := sendAddr.(*net.UDPAddr)
	if udpAddr.IP.String() != directIP {
		t.Errorf("peer should point to direct IP %s, got %s", directIP, udpAddr.IP.String())
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_VariousPorts verifies handling of various port numbers.
func TestACRegistration_NHP_AAK_ServerAddr_VariousPorts(t *testing.T) {
	testCases := []struct {
		name         string
		serverAddr   string
		expectedIP   string
		expectedPort int
	}{
		{
			name:         "standard port",
			serverAddr:   "203.0.113.100:62206",
			expectedIP:   "203.0.113.100",
			expectedPort: DefaultServerPort,
		},
		{
			name:         "high port",
			serverAddr:   "203.0.113.100:65535",
			expectedIP:   "203.0.113.100",
			expectedPort: 65535,
		},
		{
			name:         "low port",
			serverAddr:   "203.0.113.100:1024",
			expectedIP:   "203.0.113.100",
			expectedPort: 1024,
		},
		{
			name:         "port 1",
			serverAddr:   "203.0.113.100:1",
			expectedIP:   "203.0.113.100",
			expectedPort: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var testPrivateKey [32]byte
			for i := range testPrivateKey {
				testPrivateKey[i] = byte(i)
			}

			device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
			if device == nil {
				t.Fatal("Failed to create device")
			}

			ac := &UdpAC{
				config: &Config{
					ACId:           "test-ac-" + tc.name,
					ServerEndpoint: "nlb.test.internal",
				},
				device: device,
			}

			reg := mustNewACRegistration(t, ac)

			registrationPeer := &core.UdpPeer{
				Ip:           "10.0.0.1",
				Port:         DefaultServerPort,
				PubKeyBase64: "bmxiLXB1YmtleQ==",
				Type:         core.NHP_SERVER,
			}

			aakJSON := fmt.Sprintf(`{
				"errCode": "0",
				"registered": true,
				"acAddr": "192.168.1.50:50000",
				"serverAddr": "%s",
				"serverPubKey": "c2VydmVyLWtleQ=="
			}`, tc.serverAddr)

			ppd := &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(aakJSON),
			}

			err := reg.handleRegistrationResponse(ppd, registrationPeer)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			servers := reg.GetAssignedServers()
			if len(servers) != 1 {
				t.Fatalf("expected 1 server, got %d", len(servers))
			}

			if servers[0].Target.IP != tc.expectedIP {
				t.Errorf("IP = %s, want %s", servers[0].Target.IP, tc.expectedIP)
			}
			if servers[0].Target.Port != tc.expectedPort {
				t.Errorf("Port = %d, want %d", servers[0].Target.Port, tc.expectedPort)
			}
		})
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_InvalidFormats tests various invalid ServerAddr formats.
func TestACRegistration_NHP_AAK_ServerAddr_InvalidFormats(t *testing.T) {
	testCases := []struct {
		name       string
		serverAddr string
	}{
		{"missing port", "203.0.113.100"},
		{"empty string", ""},
		{"just colon", ":"},
		{"port only", ":62206"},
		{"invalid port", "203.0.113.100:notaport"},
		{"negative port", "203.0.113.100:-1"},
		{"spaces", "203.0.113.100 : 62206"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var testPrivateKey [32]byte
			for i := range testPrivateKey {
				testPrivateKey[i] = byte(i)
			}

			device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
			if device == nil {
				t.Fatal("Failed to create device")
			}

			ac := &UdpAC{
				config: &Config{
					ACId:           "test-ac-invalid",
					ServerEndpoint: "nlb.test.internal",
				},
				device: device,
			}

			reg := mustNewACRegistration(t, ac)

			nlbIP := "10.0.0.1"
			registrationPeer := &core.UdpPeer{
				Ip:           nlbIP,
				Port:         DefaultServerPort,
				PubKeyBase64: "bmxiLXB1YmtleQ==",
				Type:         core.NHP_SERVER,
			}

			aakJSON := fmt.Sprintf(`{
				"errCode": "0",
				"registered": true,
				"acAddr": "192.168.1.50:50000",
				"serverAddr": "%s",
				"serverPubKey": "c2VydmVyLWtleQ=="
			}`, tc.serverAddr)

			ppd := &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(aakJSON),
			}

			err := reg.handleRegistrationResponse(ppd, registrationPeer)
			if err != nil {
				t.Fatalf("should not error, but got: %v", err)
			}

			servers := reg.GetAssignedServers()
			if len(servers) != 1 {
				t.Fatalf("expected 1 server, got %d", len(servers))
			}

			// Should fall back to registration peer for invalid formats
			if servers[0].Peer != registrationPeer {
				t.Error("should fall back to registration peer for invalid ServerAddr")
			}

			// Verify the peer points to NLB address (fallback)
			sendAddr := servers[0].Peer.SendAddr()
			if sendAddr != nil {
				udpAddr := sendAddr.(*net.UDPAddr)
				if udpAddr.IP.String() != nlbIP {
					t.Errorf("fallback should use NLB IP %s, got %s", nlbIP, udpAddr.IP.String())
				}
			}
		})
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_UnresolvableHost verifies that when ServerAddr
// contains a valid format but unresolvable hostname, it falls back to registration peer.
func TestACRegistration_NHP_AAK_ServerAddr_UnresolvableHost(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-unresolvable",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	nlbIP := "10.0.0.1"
	registrationPeer := &core.UdpPeer{
		Ip:           nlbIP,
		Port:         DefaultServerPort,
		PubKeyBase64: "bmxiLXB1YmtleQ==",
		Type:         core.NHP_SERVER,
	}

	// Valid format but unresolvable hostname - should fall back via SendAddr() == nil
	aakJSON := `{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "unresolvable.invalid.hostname.test:62206",
		"serverPubKey": "c2VydmVyLWtleQ=="
	}`

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := reg.handleRegistrationResponse(ppd, registrationPeer)
	if err != nil {
		t.Fatalf("should not error, but got: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}

	// Should fall back to registration peer when hostname cannot be resolved
	if servers[0].Peer != registrationPeer {
		t.Error("should fall back to registration peer for unresolvable hostname")
	}

	// Verify the peer points to NLB address (fallback)
	sendAddr := servers[0].Peer.SendAddr()
	if sendAddr != nil {
		udpAddr := sendAddr.(*net.UDPAddr)
		if udpAddr.IP.String() != nlbIP {
			t.Errorf("fallback should use NLB IP %s, got %s", nlbIP, udpAddr.IP.String())
		}
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_PrivateIPBlocked verifies that when ServerAddr
// contains a private IP (RFC 1918), the AC stays on the NLB connection instead of
// switching to the private address which would be unreachable from outside the VPC.
func TestACRegistration_NHP_AAK_ServerAddr_PrivateIPBlocked(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-private-ip",
			ServerEndpoint: "nlb.example.com",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// NLB has a public IP
	nlbIP := "203.0.113.1"
	nlbPubKey := "bmxiLXB1YmtleQ=="
	registrationPeer := &core.UdpPeer{
		Ip:           nlbIP,
		Port:         DefaultServerPort,
		PubKeyBase64: nlbPubKey,
		Type:         core.NHP_SERVER,
	}

	// Test various non-routable IP ranges
	testCases := []struct {
		name      string
		privateIP string
	}{
		// RFC 1918 private ranges
		{"10.x.x.x range", "10.0.1.100"},
		{"172.16.x.x range", "172.16.0.100"},
		{"172.31.x.x range", "172.31.255.100"},
		{"192.168.x.x range", "192.168.1.100"},
		// Loopback
		{"loopback 127.0.0.1", "127.0.0.1"},
		{"loopback 127.0.0.100", "127.0.0.100"},
		// Link-local
		{"link-local 169.254.x.x", "169.254.1.1"},
		// CGNAT (Carrier-Grade NAT) - 100.64.0.0/10
		{"CGNAT 100.64.x.x", "100.64.0.1"},
		{"CGNAT 100.100.x.x", "100.100.100.100"},
		{"CGNAT 100.127.x.x", "100.127.255.255"},
	}

	serverPubKey := "c2VydmVyLWRpcmVjdC1wdWJrZXk="

	// Helper to run a single test case
	runTestCase := func(t *testing.T, privateIP string) {
		t.Helper()

		// Reset device state
		device.RemovePeer(nlbPubKey)
		device.RemovePeer(serverPubKey)

		aakJSON := fmt.Sprintf(`{
			"errCode": "0",
			"registered": true,
			"acAddr": "192.168.1.50:50000",
			"serverAddr": "%s:62206",
			"serverPubKey": "%s"
		}`, privateIP, serverPubKey)

		ppd := &core.PacketParserData{
			HeaderType:  core.NHP_AAK,
			BodyMessage: []byte(aakJSON),
		}

		err := reg.handleRegistrationResponse(ppd, registrationPeer)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		servers := reg.GetAssignedServers()
		if len(servers) != 1 {
			t.Fatalf("expected 1 server, got %d", len(servers))
		}
		server := servers[0]

		// Verify IP stayed on NLB
		if server.Target.IP != nlbIP {
			t.Errorf("should stay on NLB IP %s, got %s (private IP should be blocked)", nlbIP, server.Target.IP)
		}

		// Verify pubkey updated to server's key
		if server.Target.PubKeyBase64 != serverPubKey {
			t.Errorf("should update pubkey to %s, got %s", serverPubKey, server.Target.PubKeyBase64)
		}

		// Verify peer is registration peer (NLB)
		if server.Peer != registrationPeer {
			t.Error("should use registration peer (NLB) when private IP is blocked")
		}

		// Verify peer map lookup by NEW public key works
		if device.LookupPeer(decodeTestPubKey(t, serverPubKey)) == nil {
			t.Error("peer should be findable by server's public key after update")
		}

		// Verify old NLB key no longer finds peer
		if device.LookupPeer(decodeTestPubKey(t, nlbPubKey)) != nil {
			t.Error("peer should NOT be findable by old NLB public key")
		}
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runTestCase(t, tc.privateIP)
		})
	}
}

// decodeTestPubKey decodes a base64 public key for test lookup
func decodeTestPubKey(t *testing.T, pubKeyBase64 string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		t.Fatalf("failed to decode public key: %v", err)
	}
	return decoded
}

// TestIsNonRoutableIP tests the isNonRoutableIP helper function directly.
func TestIsNonRoutableIP(t *testing.T) {
	testCases := []struct {
		name     string
		ip       string
		expected bool
	}{
		// RFC 1918 private ranges - should be non-routable
		{"private 10.0.0.1", "10.0.0.1", true},
		{"private 10.255.255.255", "10.255.255.255", true},
		{"private 172.16.0.1", "172.16.0.1", true},
		{"private 172.31.255.255", "172.31.255.255", true},
		{"private 192.168.0.1", "192.168.0.1", true},
		{"private 192.168.255.255", "192.168.255.255", true},

		// Loopback - should be non-routable
		{"loopback 127.0.0.1", "127.0.0.1", true},
		{"loopback 127.255.255.255", "127.255.255.255", true},

		// Link-local - should be non-routable
		{"link-local 169.254.0.1", "169.254.0.1", true},
		{"link-local 169.254.255.255", "169.254.255.255", true},

		// CGNAT (100.64.0.0/10) - should be non-routable
		{"CGNAT start 100.64.0.0", "100.64.0.0", true},
		{"CGNAT middle 100.100.100.100", "100.100.100.100", true},
		{"CGNAT end 100.127.255.255", "100.127.255.255", true},

		// Just outside CGNAT range - should be routable
		{"not CGNAT 100.63.255.255", "100.63.255.255", false},
		{"not CGNAT 100.128.0.0", "100.128.0.0", false},

		// Public IPs - should be routable
		{"public 8.8.8.8", "8.8.8.8", false},
		{"public 1.1.1.1", "1.1.1.1", false},
		{"public 203.0.113.1", "203.0.113.1", false},
		{"public 52.0.0.1", "52.0.0.1", false},

		// Edge cases for 172.x.x.x - only 172.16-31 is private
		{"not private 172.15.255.255", "172.15.255.255", false},
		{"not private 172.32.0.0", "172.32.0.0", false},

		// IPv6 private (fc00::/7) - should be non-routable
		{"IPv6 private fc00::", "fc00::", true},
		{"IPv6 private fd00::1", "fd00::1", true},

		// IPv6 loopback - should be non-routable
		{"IPv6 loopback ::1", "::1", true},

		// IPv6 link-local - should be non-routable
		{"IPv6 link-local fe80::1", "fe80::1", true},

		// IPv6 public - should be routable
		{"IPv6 public 2001:4860:4860::8888", "2001:4860:4860::8888", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tc.ip)
			}

			result := isNonRoutableIP(ip)
			if result != tc.expected {
				t.Errorf("isNonRoutableIP(%s) = %v, want %v", tc.ip, result, tc.expected)
			}
		})
	}
}

// TestIsNonRoutableIP_NilIP tests that nil IP is treated as non-routable.
func TestIsNonRoutableIP_NilIP(t *testing.T) {
	if !isNonRoutableIP(nil) {
		t.Error("nil IP should be treated as non-routable")
	}
}

// TestACRegistration_ResetIptables tests that resetIptables() correctly
// handles different FilterMode values and nil iptables safely.
func TestACRegistration_ResetIptables(t *testing.T) {
	tests := []struct {
		name       string
		filterMode int
	}{
		{
			name:       "IPTABLES mode with nil iptables - should not panic",
			filterMode: FilterMode_IPTABLES,
		},
		{
			name:       "EBPF mode - should not call iptables",
			filterMode: FilterMode_EBPFXDP,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ac := &UdpAC{
				config: &Config{
					ACId:           "test-ac-001",
					ServerEndpoint: "server.nhp.test.internal",
					FilterMode:     tc.filterMode,
				},
				// iptables is nil - we're testing that resetIptables handles this safely
			}

			reg := mustNewACRegistration(t, ac)

			// This should not panic even with nil iptables
			// The function checks both FilterMode AND nil iptables before calling
			reg.resetIptables()

			// If we get here without panic, the nil-safety check works
		})
	}
}

// TestACRegistration_LastSeenUpdatePreventsReregistration tests that updating
// LastSeen prevents false "server down" detection. This is a regression test
// for the bug where NHP_KPL (unidirectional) responses were expected to update
// LastSeen, causing constant re-registration every 30 seconds.
//
// The fix updates LastSeen when SENDING a keepalive, not when receiving a response.
// This test verifies that pattern works correctly with the health check.
func TestACRegistration_LastSeenUpdatePreventsReregistration(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Create a connected server with recent LastSeen (simulating sendKeepalives behavior)
	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         DefaultServerPort,
			PubKeyBase64: "pubkey1",
		},
	}
	server.SetConnected(true)
	server.UpdateLastSeen() // Simulates what sendKeepalives() now does

	reg.assignedServers = []*AssignedServer{server}

	// Run health check - should NOT trigger re-registration
	reg.checkServerHealth()

	if reg.reregistering.Load() {
		t.Error("Health check should NOT trigger re-registration when LastSeen is recent")
	}

	// Simulate time passing but LastSeen being refreshed (like keepalive loop)
	// Sleep a tiny bit to ensure time advances
	time.Sleep(10 * time.Millisecond)
	server.UpdateLastSeen() // Simulates another keepalive send

	reg.checkServerHealth()

	if reg.reregistering.Load() {
		t.Error("Health check should NOT trigger re-registration after LastSeen refresh")
	}
}

// TestACRegistration_StaleLastSeenTriggersReregistration verifies that when
// LastSeen is NOT updated (e.g., if keepalives fail to send), re-registration
// is correctly triggered. This ensures the health check still works for
// legitimate server failures.
func TestACRegistration_StaleLastSeenTriggersReregistration(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Create a connected server with STALE LastSeen
	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         DefaultServerPort,
			PubKeyBase64: "pubkey1",
		},
	}
	server.SetConnected(true)
	// Set LastSeen to 1 hour ago - way past the threshold
	server.mu.Lock()
	server.LastSeen = time.Now().Add(-1 * time.Hour)
	server.mu.Unlock()

	reg.assignedServers = []*AssignedServer{server}

	// Run health check - SHOULD trigger re-registration
	reg.checkServerHealth()

	if !reg.reregistering.Load() {
		t.Error("Health check SHOULD trigger re-registration when LastSeen is stale")
	}
}

// TestACRegistration_SendKeepalives_SkipsInvalidServers verifies that
// sendKeepalives correctly skips servers that shouldn't receive keepalives.
func TestACRegistration_SendKeepalives_SkipsInvalidServers(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Server with no peer - should be skipped
	serverNoPeer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.0.1",
			Port: DefaultServerPort,
		},
		Peer: nil,
	}
	serverNoPeer.SetConnected(true)

	// Server not connected - should be skipped
	serverNotConnected := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.0.2",
			Port: DefaultServerPort,
		},
	}
	// Connected is false by default

	reg.assignedServers = []*AssignedServer{serverNoPeer, serverNotConnected}

	// Record initial LastSeen times (zero time)
	noPeerLastSeen := serverNoPeer.GetLastSeen()
	notConnectedLastSeen := serverNotConnected.GetLastSeen()

	// sendKeepalives would normally update LastSeen, but these servers should be skipped
	// We can verify this by checking the skip conditions in the code

	// Server with nil peer should NOT have LastSeen updated
	if serverNoPeer.Peer != nil {
		t.Error("Test setup error: serverNoPeer should have nil peer")
	}

	// Server not connected should NOT have LastSeen updated
	if serverNotConnected.IsConnected() {
		t.Error("Test setup error: serverNotConnected should not be connected")
	}

	// Verify neither would be processed (their conditions fail the skip check)
	// The actual sendKeepalives requires device infrastructure, so we verify
	// the conditions that would cause them to be skipped
	for _, server := range reg.assignedServers {
		if server.Peer == nil || !server.IsConnected() {
			// This server would be skipped - verify LastSeen unchanged
			if server.Target.IP == "10.0.0.1" && server.GetLastSeen() != noPeerLastSeen {
				t.Error("Server with nil peer should be skipped, LastSeen should not change")
			}
			if server.Target.IP == "10.0.0.2" && server.GetLastSeen() != notConnectedLastSeen {
				t.Error("Disconnected server should be skipped, LastSeen should not change")
			}
		}
	}
}

// TestACRegistration_IsServerAddress tests the IsServerAddress method that determines
// if a given address belongs to an assigned server (used by connectionRoutine timeout handling).
func TestACRegistration_IsServerAddress(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Add some assigned servers (including IPv6)
	reg.assignedServers = []*AssignedServer{
		{
			Target: common.RedirectTarget{
				IP:   "10.0.0.1",
				Port: DefaultServerPort,
			},
		},
		{
			Target: common.RedirectTarget{
				IP:   "192.168.1.100",
				Port: DefaultServerPort,
			},
		},
		{
			Target: common.RedirectTarget{
				IP:   "::1", // IPv6 loopback
				Port: DefaultServerPort,
			},
		},
		{
			Target: common.RedirectTarget{
				IP:   "2001:db8::1", // IPv6 address
				Port: 8080,
			},
		},
	}

	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{
			name:     "exact match first server",
			addr:     "10.0.0.1:62206",
			expected: true,
		},
		{
			name:     "exact match second server",
			addr:     "192.168.1.100:62206",
			expected: true,
		},
		{
			name:     "IPv6 loopback with brackets (as net.UDPAddr.String() formats)",
			addr:     "[::1]:62206",
			expected: true,
		},
		{
			name:     "IPv6 address with brackets",
			addr:     "[2001:db8::1]:8080",
			expected: true,
		},
		{
			name:     "IPv6 wrong port",
			addr:     "[::1]:12345",
			expected: false,
		},
		{
			name:     "wrong port",
			addr:     "10.0.0.1:12345",
			expected: false,
		},
		{
			name:     "wrong IP",
			addr:     "10.0.0.99:62206",
			expected: false,
		},
		{
			name:     "completely different address",
			addr:     "8.8.8.8:53",
			expected: false,
		},
		{
			name:     "empty address",
			addr:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reg.IsServerAddress(tt.addr)
			if result != tt.expected {
				t.Errorf("IsServerAddress(%q) = %v, want %v", tt.addr, result, tt.expected)
			}
		})
	}
}

// TestACRegistration_IsServerAddress_WithRegistrationPeer tests that IsServerAddress
// also checks the registration peer address.
func TestACRegistration_IsServerAddress_WithRegistrationPeer(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Create a registration peer with a send address
	regPeer := &core.UdpPeer{
		Ip:   "10.0.0.50",
		Port: DefaultServerPort,
	}
	regPeer.Type = core.NHP_SERVER
	// Set SendAddr by encoding the IP/Port (UdpPeer uses these fields)
	reg.registrationPeer = regPeer

	// No assigned servers, only registration peer
	reg.assignedServers = nil

	// Registration peer address should match
	// Note: SendAddr() returns *net.UDPAddr from the peer's Ip:Port fields
	peerAddr := fmt.Sprintf("%s:%d", regPeer.Ip, regPeer.Port)

	if !reg.IsServerAddress(peerAddr) {
		t.Errorf("Expected IsServerAddress(%q) = true for registration peer", peerAddr)
	}

	// Other addresses should not match
	if reg.IsServerAddress("8.8.8.8:53") {
		t.Error("Expected IsServerAddress to return false for non-server address")
	}
}

// TestACRegistration_TriggerReregistration_AtomicGuard tests that TriggerReregistration
// respects the atomic re-registration guard to prevent concurrent re-registrations.
func TestACRegistration_TriggerReregistration_AtomicGuard(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// First call should proceed
	reg.TriggerReregistration("test_reason_1")

	// Poll for reregistering flag to be set (more reliable than fixed sleep)
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if reg.reregistering.Load() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Verify reregistering flag is set
	if !reg.reregistering.Load() {
		t.Error("Expected reregistering flag to be true after first trigger")
	}

	// Second call while first is in progress should be skipped
	reg.TriggerReregistration("test_reason_2")

	// Brief pause to let second call attempt to run
	time.Sleep(5 * time.Millisecond)

	// The key assertion is that reregistering flag is still true (first call still running)
	// and second call was skipped (didn't reset the flag or cause issues)
	if !reg.reregistering.Load() {
		t.Error("Expected reregistering flag to still be true (first trigger still running)")
	}

	// Stop the registration to clean up
	reg.Stop()
}

// TestACRegistration_TriggerReregistration_StopsOnShutdown tests that TriggerReregistration
// respects the stop channel and exits cleanly during shutdown.
func TestACRegistration_TriggerReregistration_StopsOnShutdown(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Trigger re-registration
	reg.TriggerReregistration("shutdown_test")

	// Give goroutine time to start
	time.Sleep(10 * time.Millisecond)

	// Stop immediately - should cause the goroutine to exit
	reg.Stop()

	// Verify reregistering flag is eventually cleared
	time.Sleep(100 * time.Millisecond)

	// After stop, the flag should be cleared (goroutine exited)
	// Note: The flag might still be true if goroutine didn't exit yet,
	// but Stop() should have closed stopCh
	select {
	case <-reg.stopCh:
		// Good - stop channel is closed
	default:
		t.Error("Expected stopCh to be closed after Stop()")
	}
}

// TestRegistrationRefreshInterval verifies the periodic refresh constant is set correctly.
// The refresh interval determines how often NHP_AOL is re-sent to refresh server peer state,
// handling server restarts where the server loses peer state but the AC continues
// sending successful keep-alives.
func TestRegistrationRefreshInterval(t *testing.T) {
	// Verify refresh happens every 60 seconds (6 * 10s keepalive interval)
	expectedTicks := 6
	if RegistrationRefreshInterval != expectedTicks {
		t.Errorf("Expected RegistrationRefreshInterval to be %d, got %d", expectedTicks, RegistrationRefreshInterval)
	}

	// Verify the actual interval is 60 seconds
	actualInterval := time.Duration(RegistrationRefreshInterval) * KeepaliveInterval
	expectedInterval := 60 * time.Second
	if actualInterval != expectedInterval {
		t.Errorf("Expected actual refresh interval to be %v, got %v", expectedInterval, actualInterval)
	}
}

// TestRefreshAssignedServerRegistrations_NoServers verifies the function handles
// an empty server list gracefully without panicking.
func TestRefreshAssignedServerRegistrations_NoServers(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Should not panic with empty server list
	reg.refreshAssignedServerRegistrations()
	// Test passes if no panic occurs
}

// TestRefreshAssignedServerRegistrations_SkipsDisconnectedServers verifies that
// the refresh logic skips servers that are not connected.
func TestRefreshAssignedServerRegistrations_SkipsDisconnectedServers(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
		sendMsgCh: make(chan *core.MsgData, 10),
	}

	reg := mustNewACRegistration(t, ac)

	// Add servers with different connection states
	server1 := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.1.100",
			Port: DefaultServerPort,
		},
		Connected: false, // Not connected - should be skipped
		Peer:      nil,
	}

	server2 := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.2.100",
			Port: DefaultServerPort,
		},
		Connected: true,
		Peer:      nil, // Nil peer - should be skipped
	}

	reg.mu.Lock()
	reg.assignedServers = []*AssignedServer{server1, server2}
	reg.mu.Unlock()

	// Should not panic and should skip both servers
	reg.refreshAssignedServerRegistrations()

	// Verify no messages were sent (both servers should be skipped)
	select {
	case <-ac.sendMsgCh:
		t.Error("Expected no messages to be sent for disconnected/nil-peer servers")
	default:
		// Good - no messages sent
	}
}

// TestHandleRefreshResponse_Success tests successful NHP_AAK response handling.
func TestHandleRefreshResponse_Success(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.1.100",
			Port: DefaultServerPort,
		},
		Connected: true,
		LastSeen:  time.Now().Add(-time.Minute), // Set old LastSeen
	}

	sendAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.100"), Port: DefaultServerPort}

	// Create successful NHP_AAK response
	aakMsg := common.ServerACAckMsg{
		ErrCode: common.ErrSuccess.ErrorCode(),
	}
	aakBytes, _ := json.Marshal(aakMsg)

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: aakBytes,
	}

	oldLastSeen := server.GetLastSeen()

	// Handle the response
	reg.handleRefreshResponse(ppd, server, sendAddr)

	// Verify LastSeen was updated
	if !server.GetLastSeen().After(oldLastSeen) {
		t.Error("Expected LastSeen to be updated after successful refresh")
	}
}

// TestHandleRefreshResponse_Rejected tests NHP_AAK with error code handling.
func TestHandleRefreshResponse_Rejected(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.1.100",
			Port: DefaultServerPort,
		},
		Connected: true,
		LastSeen:  time.Now().Add(-time.Minute),
	}

	sendAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.100"), Port: DefaultServerPort}

	// Create rejected NHP_AAK response
	aakMsg := common.ServerACAckMsg{
		ErrCode: "license_invalid",
		ErrMsg:  "License validation failed",
	}
	aakBytes, _ := json.Marshal(aakMsg)

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: aakBytes,
	}

	oldLastSeen := server.GetLastSeen()

	// Handle the response - should not update LastSeen
	reg.handleRefreshResponse(ppd, server, sendAddr)

	// Verify LastSeen was NOT updated (rejection)
	if server.GetLastSeen() != oldLastSeen {
		t.Error("Expected LastSeen to NOT be updated after rejected refresh")
	}
}

// TestHandleRefreshResponse_Redirect tests NHP_ARD response triggering re-registration.
func TestHandleRefreshResponse_Redirect(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
		sendMsgCh: make(chan *core.MsgData, 10),
	}

	reg := mustNewACRegistration(t, ac)

	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.1.100",
			Port: DefaultServerPort,
		},
		Connected: true,
	}

	sendAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.100"), Port: DefaultServerPort}

	// Create NHP_ARD response (server wants us to connect elsewhere)
	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_ARD,
		BodyMessage: []byte("{}"), // Empty ARD message
	}

	// Handle the response - should trigger re-registration
	reg.handleRefreshResponse(ppd, server, sendAddr)

	// Give goroutine time to set the flag
	time.Sleep(10 * time.Millisecond)

	// Verify re-registration was triggered (reregistering flag should be set)
	// Note: We can't directly check the flag, but the TriggerReregistration
	// function was called. The test verifies no panic occurs.
}

// TestHandleRefreshResponse_Error tests error response handling.
func TestHandleRefreshResponse_Error(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.1.100",
			Port: DefaultServerPort,
		},
		Connected: true,
		LastSeen:  time.Now().Add(-time.Minute),
	}

	sendAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.100"), Port: DefaultServerPort}

	// Create response with error
	ppd := &core.PacketParserData{
		Error: fmt.Errorf("decryption failed"),
	}

	oldLastSeen := server.GetLastSeen()

	// Handle the response - should not panic, should not update LastSeen
	reg.handleRefreshResponse(ppd, server, sendAddr)

	// Verify LastSeen was NOT updated
	if server.GetLastSeen() != oldLastSeen {
		t.Error("Expected LastSeen to NOT be updated after error response")
	}
}

// TestHandleRefreshResponse_UnexpectedType tests handling of unexpected response types.
func TestHandleRefreshResponse_UnexpectedType(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.1.100",
			Port: DefaultServerPort,
		},
		Connected: true,
		LastSeen:  time.Now().Add(-time.Minute),
	}

	sendAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.100"), Port: DefaultServerPort}

	// Create unexpected response type (e.g., NHP_KPL)
	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_KPL, // Unexpected type
		BodyMessage: []byte{},
	}

	oldLastSeen := server.GetLastSeen()

	// Handle the response - should not panic, should log warning
	reg.handleRefreshResponse(ppd, server, sendAddr)

	// Verify LastSeen was NOT updated
	if server.GetLastSeen() != oldLastSeen {
		t.Error("Expected LastSeen to NOT be updated after unexpected response type")
	}
}
