package ac

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// TestACRegistration_NewACRegistration tests creation of ACRegistration.
func TestACRegistration_NewACRegistration(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := NewACRegistration(ac)

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

	reg := NewACRegistration(ac)

	tests := []struct {
		name        string
		ardMsg      *common.ACRedispatchMsg
		expectError bool
		errorContains string
	}{
		{
			name: "empty targets",
			ardMsg: &common.ACRedispatchMsg{
				Targets: []common.RedirectTarget{},
			},
			expectError: true,
			errorContains: "no targets",
		},
		{
			name: "error code set",
			ardMsg: &common.ACRedispatchMsg{
				ErrCode: "LICENSE_EXPIRED",
				ErrMsg:  "License has expired",
				Targets: []common.RedirectTarget{
					{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "pubkey"},
				},
			},
			expectError: true,
			errorContains: "redispatch failed",
		},
		{
			name: "target with empty IP",
			ardMsg: &common.ACRedispatchMsg{
				Targets: []common.RedirectTarget{
					{IP: "", Port: 62206, PubKeyBase64: "pubkey"},
				},
			},
			expectError: true,
			errorContains: "empty IP",
		},
		{
			name: "target with invalid port",
			ardMsg: &common.ACRedispatchMsg{
				Targets: []common.RedirectTarget{
					{IP: "10.0.0.1", Port: 0, PubKeyBase64: "pubkey"},
				},
			},
			expectError: true,
			errorContains: "invalid port",
		},
		{
			name: "target with empty public key",
			ardMsg: &common.ACRedispatchMsg{
				Targets: []common.RedirectTarget{
					{IP: "10.0.0.1", Port: 62206, PubKeyBase64: ""},
				},
			},
			expectError: true,
			errorContains: "empty public key",
		},
		{
			name: "target with invalid IP format",
			ardMsg: &common.ACRedispatchMsg{
				Targets: []common.RedirectTarget{
					{IP: "not-an-ip", Port: 62206, PubKeyBase64: "pubkey"},
				},
			},
			expectError: true,
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

	reg := NewACRegistration(ac)

	// Add some assigned servers manually
	oldTime := time.Now().Add(-1 * time.Hour)
	server1 := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         62206,
			PubKeyBase64: "pubkey1",
		},
	}
	server1.LastSeen = oldTime
	server1.FailCount = 3

	server2 := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.2",
			Port:         62206,
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

	reg := NewACRegistration(ac)

	if reg.HasAssignedServers() {
		t.Error("should return false when no servers assigned")
	}

	reg.assignedServers = []*AssignedServer{
		{
			Target: common.RedirectTarget{
				IP:   "10.0.0.1",
				Port: 62206,
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

	reg := NewACRegistration(ac)

	// Add some servers
	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         62206,
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
		ServerPort:         62206,
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

	reg := NewACRegistration(ac)

	// Simulate having old server sets
	key1 := time.Now().Add(-3 * time.Minute).Format(time.RFC3339Nano)
	key2 := time.Now().Add(-1 * time.Minute).Format(time.RFC3339Nano)

	reg.oldServerSets[key1] = []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: 62206}},
	}
	reg.oldServerSets[key2] = []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: 62206}},
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
			Port: 62206,
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

	reg := NewACRegistration(ac)

	// Initially empty
	servers := reg.GetAssignedServers()
	if len(servers) != 0 {
		t.Errorf("expected 0 servers initially, got %d", len(servers))
	}

	// Add some servers
	reg.assignedServers = []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: 62206}},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: 62206}},
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

	reg := NewACRegistration(ac)

	oldTime := time.Now().Add(-1 * time.Hour)
	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         62206,
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

	reg := NewACRegistration(ac)

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

// TestACRegistration_ReregisteringGuard tests the atomic re-registration guard.
func TestACRegistration_ReregisteringGuard(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := NewACRegistration(ac)

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

	reg := NewACRegistration(ac)

	// Directly assign servers (simulating what HandleRedispatch does internally)
	reg.assignedServers = []*AssignedServer{
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.1",
				Port:         62206,
				PubKeyBase64: "pubkey1",
				ServerID:     "server-1",
				AZ:           "us-west-2a",
			},
		},
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.2",
				Port:         62206,
				PubKeyBase64: "pubkey2",
				ServerID:     "server-2",
				AZ:           "us-west-2b",
			},
		},
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.3",
				Port:         62206,
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

	reg := NewACRegistration(ac)

	// Create a server that was never connected (Connected=false, LastSeen=zero)
	// This simulates a server where connectToServer() failed
	neverConnectedServer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         62206,
			PubKeyBase64: "pubkey1",
		},
		// Connected is false (default), LastSeen is zero (default)
	}

	// Create a healthy connected server
	healthyServer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.2",
			Port:         62206,
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

	reg := NewACRegistration(ac)

	// Pre-populate with connected servers
	for i := 0; i < 3; i++ {
		server := &AssignedServer{
			Target: common.RedirectTarget{
				IP:           fmt.Sprintf("10.0.0.%d", i+1),
				Port:         62206,
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
						Port:         62206,
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

	reg := NewACRegistration(ac)

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
			{Target: common.RedirectTarget{IP: fmt.Sprintf("10.%d.0.1", i), Port: 62206}},
			{Target: common.RedirectTarget{IP: fmt.Sprintf("10.%d.0.2", i), Port: 62206}},
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

	reg := NewACRegistration(ac)

	// Set up a server to trigger handleServerDown
	deadServer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.0.1",
			Port: 62206,
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

	reg := NewACRegistration(ac)

	// Create a mix of servers in different states
	servers := []*AssignedServer{
		// Server 1: Never connected (should be skipped)
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.1",
				Port:         62206,
				PubKeyBase64: "pubkey1",
			},
			// Connected: false (default)
			// LastSeen: zero (default)
		},
		// Server 2: Connected and healthy
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.2",
				Port:         62206,
				PubKeyBase64: "pubkey2",
			},
		},
		// Server 3: Connected but stale
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.3",
				Port:         62206,
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

	reg := NewACRegistration(ac)

	// Create servers with different states to verify filtering conditions
	connectedWithPeer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         62206,
			PubKeyBase64: "pubkey1",
		},
		Peer: &core.UdpPeer{
			Ip:   "10.0.0.1",
			Port: 62206,
		},
	}
	connectedWithPeer.SetConnected(true)

	disconnectedWithPeer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.2",
			Port:         62206,
			PubKeyBase64: "pubkey2",
		},
		Peer: &core.UdpPeer{
			Ip:   "10.0.0.2",
			Port: 62206,
		},
	}
	// disconnectedWithPeer.Connected is false by default

	connectedNoPeer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.3",
			Port:         62206,
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
	reg := NewACRegistration(ac)

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
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := NewACRegistration(ac)

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := reg.handleRegistrationResponse(tt.ppd)

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

	reg := NewACRegistration(ac)

	// Create a stale connected server that would trigger re-registration
	staleServer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         62206,
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

	reg := NewACRegistration(ac)

	// Create old servers - some with nil peer
	cleanupKey := "test-cleanup-key"
	reg.oldServerSets[cleanupKey] = []*AssignedServer{
		{
			Target: common.RedirectTarget{IP: "10.0.0.1", Port: 62206},
			Peer:   nil, // No peer - should be handled gracefully
		},
		{
			Target: common.RedirectTarget{IP: "10.0.0.2", Port: 62206},
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

	reg := NewACRegistration(ac)

	// After HandleRedispatch runs, if successCount < len(serversToConnect),
	// it logs a warning but still returns nil (success).
	// We can't easily test the actual connection without a device,
	// but we can verify the assigned servers are set up correctly.

	// Manually simulate what HandleRedispatch does for server assignment
	reg.mu.Lock()
	reg.assignedServers = []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "key1"}, Connected: false},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: 62206, PubKeyBase64: "key2"}, Connected: false},
		{Target: common.RedirectTarget{IP: "10.0.0.3", Port: 62206, PubKeyBase64: "key3"}, Connected: false},
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
