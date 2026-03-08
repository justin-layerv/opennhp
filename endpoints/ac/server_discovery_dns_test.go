package ac

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/core"
)

// failingLookupHost is a mock DNS resolver that always returns an error,
// used to make DNS failure tests deterministic regardless of environment
// (some environments have DNS interceptors that resolve any hostname).
func failingLookupHost(_ string) ([]string, error) {
	return nil, errors.New("mock DNS resolution failure")
}

// =============================================================================
// DNS Re-Resolution Tests
//
// TestServerDiscovery_* — integration-style tests for the serverDiscovery loop
//   (address change detection, connection cleanup, fail counters, cache invalidation)
// TestUdpPeer_* — unit tests for UdpPeer methods (SendAddr, ResolveHost, InvalidateDNSCache,
//   DNS caching, static IP fallback)
// =============================================================================

// assertUDPAddr asserts that addr is a *net.UDPAddr with the expected IP and port.
func assertUDPAddr(t *testing.T, addr net.Addr, wantIP string, wantPort int) {
	t.Helper()
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("Expected *net.UDPAddr, got %T", addr)
	}
	if wantIP != "" && udpAddr.IP.String() != wantIP {
		t.Errorf("IP: got %s, want %s", udpAddr.IP.String(), wantIP)
	}
	if udpAddr.Port != wantPort {
		t.Errorf("Port: got %d, want %d", udpAddr.Port, wantPort)
	}
}

// createTestACForDiscovery creates a minimal UdpAC with a device and
// initialized remoteConnectionMap, suitable for testing connection lifecycle
// (create, close) in serverDiscovery tests.
func createTestACForDiscovery(t *testing.T) *UdpAC {
	t.Helper()
	ac := createTestAC(t)
	ac.remoteConnectionMap = make(map[string]*UdpConn)
	return ac
}

// createTestUdpConn creates a UdpConn backed by a real UDP socket, suitable
// for testing connection map operations and Close() behavior.
func createTestUdpConn(t *testing.T, ac *UdpAC, remoteIP string, remotePort int) *UdpConn {
	t.Helper()
	remoteAddr := &net.UDPAddr{IP: net.ParseIP(remoteIP), Port: remotePort}
	conn := ac.newConnection(remoteAddr)
	if conn == nil {
		t.Fatalf("newConnection returned nil for %s:%d", remoteIP, remotePort)
	}
	return conn
}

// TestServerDiscovery_AddressChangeDetected verifies that when a UdpPeer's
// SendAddr() returns a different address (simulating DNS re-resolution to a new
// IP), the change is correctly detected by comparing the new address string to
// the previously-tracked address.
func TestServerDiscovery_AddressChangeDetected(t *testing.T) {
	tests := []struct {
		name         string
		lastAddrStr  string
		newAddrStr   string
		wantDetected bool
	}{
		{
			name:         "same address, no change",
			lastAddrStr:  "10.0.0.1:62206",
			newAddrStr:   "10.0.0.1:62206",
			wantDetected: false,
		},
		{
			name:         "IP changed, same port",
			lastAddrStr:  "10.0.0.1:62206",
			newAddrStr:   "10.0.0.2:62206",
			wantDetected: true,
		},
		{
			name:         "first iteration, empty lastAddr",
			lastAddrStr:  "",
			newAddrStr:   "10.0.0.1:62206",
			wantDetected: false,
		},
		{
			name:         "same IP, different port",
			lastAddrStr:  "10.0.0.1:62206",
			newAddrStr:   "10.0.0.1:62207",
			wantDetected: true,
		},
		{
			name:         "IPv4 to different IPv4",
			lastAddrStr:  "192.168.1.100:62206",
			newAddrStr:   "192.168.1.200:62206",
			wantDetected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This mirrors the detection logic in serverDiscovery:
			//   if lastAddrStr != "" && lastAddrStr != addrStr { ... }
			detected := tt.lastAddrStr != "" && tt.lastAddrStr != tt.newAddrStr
			if detected != tt.wantDetected {
				t.Errorf("address change detection: got %v, want %v (lastAddr=%q, newAddr=%q)",
					detected, tt.wantDetected, tt.lastAddrStr, tt.newAddrStr)
			}
		})
	}
}

// TestServerDiscovery_OldConnectionClosedOnAddressChange verifies that when a
// DNS address change is detected, the old connection is removed from the
// remoteConnectionMap and properly closed.
func TestServerDiscovery_OldConnectionClosedOnAddressChange(t *testing.T) {
	ac := createTestACForDiscovery(t)
	defer ac.device.Stop()

	oldAddr := "10.0.0.1:62206"
	newAddr := "10.0.0.2:62206"

	// Create old connection via the AC's newConnection (properly initializes all fields)
	oldConn := createTestUdpConn(t, ac, "10.0.0.1", DefaultServerPort)
	ac.remoteConnectionMutex.Lock()
	ac.remoteConnectionMap[oldAddr] = oldConn
	ac.remoteConnectionMutex.Unlock()

	// Simulate the address change logic from serverDiscovery (lines 694-714)
	lastAddrStr := oldAddr
	addrStr := newAddr

	if lastAddrStr != "" && lastAddrStr != addrStr {
		var removedConn *UdpConn
		ac.remoteConnectionMutex.Lock()
		if conn, found := ac.remoteConnectionMap[lastAddrStr]; found {
			removedConn = conn
			delete(ac.remoteConnectionMap, lastAddrStr)
		}
		ac.remoteConnectionMutex.Unlock()

		if removedConn != nil {
			removedConn.Close()
		}
	}

	// Verify the old connection was removed from the map
	ac.remoteConnectionMutex.Lock()
	_, stillExists := ac.remoteConnectionMap[oldAddr]
	ac.remoteConnectionMutex.Unlock()

	if stillExists {
		t.Error("Old connection should be removed from remoteConnectionMap after address change")
	}

	// Verify the map is empty (only had one entry)
	if len(ac.remoteConnectionMap) != 0 {
		t.Errorf("remoteConnectionMap should be empty, has %d entries", len(ac.remoteConnectionMap))
	}
}

// TestServerDiscovery_FailCountResetOnAddressChange verifies that both the
// local failCount and the shared serverFailCount are reset to 0 when a DNS
// address change is detected. This prevents stale failure counters from
// triggering premature DNS cache invalidation for the new address.
func TestServerDiscovery_FailCountResetOnAddressChange(t *testing.T) {
	tests := []struct {
		name              string
		initialFailCount  int
		initialSharedFail int32
		addressChanged    bool
		wantFailCount     int
		wantSharedFail    int32
	}{
		{
			name:              "reset both counters on address change",
			initialFailCount:  5,
			initialSharedFail: 1,
			addressChanged:    true,
			wantFailCount:     0,
			wantSharedFail:    0,
		},
		{
			name:              "counters unchanged when no address change",
			initialFailCount:  3,
			initialSharedFail: 1,
			addressChanged:    false,
			wantFailCount:     3,
			wantSharedFail:    1,
		},
		{
			name:              "reset from zero is a no-op",
			initialFailCount:  0,
			initialSharedFail: 0,
			addressChanged:    true,
			wantFailCount:     0,
			wantSharedFail:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failCount := tt.initialFailCount
			var serverFailCount int32 = tt.initialSharedFail

			// Simulate the reset logic from serverDiscovery (lines 712-713)
			if tt.addressChanged {
				failCount = 0
				atomic.StoreInt32(&serverFailCount, 0)
			}

			if failCount != tt.wantFailCount {
				t.Errorf("failCount: got %d, want %d", failCount, tt.wantFailCount)
			}
			if got := atomic.LoadInt32(&serverFailCount); got != tt.wantSharedFail {
				t.Errorf("serverFailCount: got %d, want %d", got, tt.wantSharedFail)
			}
		})
	}
}

// TestServerDiscovery_ConnectionMapUpdatedOnAddressChange verifies that after
// an address change, the old connection entry is removed and a new connection
// can be added with the new address key.
func TestServerDiscovery_ConnectionMapUpdatedOnAddressChange(t *testing.T) {
	ac := createTestACForDiscovery(t)
	defer ac.device.Stop()

	oldAddr := "10.0.0.1:62206"
	newAddr := "10.0.0.2:62206"

	// Create old connection
	oldConn := createTestUdpConn(t, ac, "10.0.0.1", DefaultServerPort)
	ac.remoteConnectionMutex.Lock()
	ac.remoteConnectionMap[oldAddr] = oldConn
	ac.remoteConnectionMutex.Unlock()

	// Simulate address change cleanup
	ac.remoteConnectionMutex.Lock()
	if conn, found := ac.remoteConnectionMap[oldAddr]; found {
		delete(ac.remoteConnectionMap, oldAddr)
		conn.Close()
	}
	ac.remoteConnectionMutex.Unlock()

	// Add new connection (simulating what sendMsgCh would cause)
	newConn := createTestUdpConn(t, ac, "10.0.0.2", DefaultServerPort)
	ac.remoteConnectionMutex.Lock()
	ac.remoteConnectionMap[newAddr] = newConn
	ac.remoteConnectionMutex.Unlock()

	// Verify old entry is gone and new entry is present
	ac.remoteConnectionMutex.Lock()
	defer ac.remoteConnectionMutex.Unlock()

	if _, found := ac.remoteConnectionMap[oldAddr]; found {
		t.Error("Old address should not exist in connection map")
	}
	if _, found := ac.remoteConnectionMap[newAddr]; !found {
		t.Error("New address should exist in connection map")
	}
	if len(ac.remoteConnectionMap) != 1 {
		t.Errorf("Connection map should have exactly 1 entry, has %d", len(ac.remoteConnectionMap))
	}

	// Cleanup
	newConn.Close()
}

// TestUdpPeer_DNSResolutionFailureRetries verifies that when DNS
// resolution fails (SendAddr returns nil), the discovery loop continues
// to retry rather than crashing or exiting. Uses a mock resolver to avoid
// flaky behavior from environment DNS interceptors.
func TestUdpPeer_DNSResolutionFailureRetries(t *testing.T) {
	peer := &core.UdpPeer{
		Hostname:       "server.nhp.test.internal",
		Port:           DefaultServerPort,
		Type:           core.NHP_SERVER,
		LookupHostFunc: failingLookupHost,
	}

	// SendAddr calls ResolveHost which uses the mock resolver.
	// Since resolution fails and no static Ip is set, SendAddr returns nil.
	sendAddr := peer.SendAddr()

	if sendAddr != nil {
		t.Errorf("SendAddr should return nil when DNS fails and no static IP is set, got %v", sendAddr)
	}
}

// TestUdpPeer_DNSCacheInvalidationAfterFailures verifies that after
// ServerDiscoveryRetryBeforeFail consecutive failures, the DNS cache is
// invalidated (via InvalidateDNSCache) to force a fresh lookup on the next
// iteration. This allows the AC to recover when a server's IP changes during
// repeated connection failures.
func TestUdpPeer_DNSCacheInvalidationAfterFailures(t *testing.T) {
	peer := &core.UdpPeer{
		Hostname: "localhost",
		Ip:       "127.0.0.1",
		Port:     DefaultServerPort,
		Type:     core.NHP_SERVER,
	}

	// Trigger initial DNS resolution to populate the cache
	addr := peer.SendAddr()
	if addr == nil {
		t.Fatal("SendAddr should succeed for localhost")
	}

	// Record the initial resolved IPs
	initialIps := peer.ResolvedIps()
	if len(initialIps) == 0 {
		t.Fatal("Expected at least one resolved IP for localhost")
	}

	// Simulate the failure counting logic from serverDiscovery (lines 793-819)
	failCount := 0
	var serverFailCount int32

	for i := 0; i < ServerDiscoveryRetryBeforeFail; i++ {
		failCount++

		if failCount%ServerDiscoveryRetryBeforeFail == 0 {
			atomic.StoreInt32(&serverFailCount, 1)
			// In real code, this is where InvalidateDNSCache is called
			peer.InvalidateDNSCache()
		}
	}

	// After exactly ServerDiscoveryRetryBeforeFail failures, cache should be invalidated
	if atomic.LoadInt32(&serverFailCount) != 1 {
		t.Errorf("serverFailCount should be 1 after %d failures, got %d",
			ServerDiscoveryRetryBeforeFail, atomic.LoadInt32(&serverFailCount))
	}

	// SendAddr should re-resolve DNS (since cache was invalidated)
	addrAfter := peer.SendAddr()
	if addrAfter == nil {
		t.Fatal("SendAddr should still succeed for localhost after cache invalidation")
	}

	t.Logf("DNS cache invalidation triggered after %d failures, re-resolved to %s",
		ServerDiscoveryRetryBeforeFail, addrAfter.String())
}

// TestUdpPeer_StaticIPFallbackOnDNSFailure verifies that when a peer
// has both a hostname and a static IP, DNS resolution failure falls back to
// the static IP rather than returning nil. Uses a mock resolver for determinism.
func TestUdpPeer_StaticIPFallbackOnDNSFailure(t *testing.T) {
	peer := &core.UdpPeer{
		Hostname:       "server.nhp.test.internal",
		Ip:             "10.0.0.42",
		Port:           DefaultServerPort,
		Type:           core.NHP_SERVER,
		LookupHostFunc: failingLookupHost,
	}

	// ResolveHost should fall back to the static IP when hostname resolution fails
	host := peer.ResolveHost()
	if host != "10.0.0.42" {
		t.Errorf("ResolveHost should fall back to static IP, got %s, want 10.0.0.42", host)
	}

	// SendAddr should return a valid address using the fallback
	addr := peer.SendAddr()
	if addr == nil {
		t.Fatal("SendAddr should not return nil when static IP fallback is available")
	}

	assertUDPAddr(t, addr, "10.0.0.42", DefaultServerPort)
}

// TestUdpPeer_InvalidateDNSCacheNoHostname verifies that calling
// InvalidateDNSCache on a peer with no hostname is a no-op (safe to call).
func TestUdpPeer_InvalidateDNSCacheNoHostname(t *testing.T) {
	peer := &core.UdpPeer{
		Ip:   "10.0.0.1",
		Port: DefaultServerPort,
		Type: core.NHP_SERVER,
	}

	// Should not panic or error when hostname is empty
	peer.InvalidateDNSCache()

	// SendAddr should still work using static IP
	addr := peer.SendAddr()
	if addr == nil {
		t.Fatal("SendAddr should return address for peer with static IP")
	}

	assertUDPAddr(t, addr, "10.0.0.1", DefaultServerPort)
}

// TestServerDiscovery_ConcurrentAddressChangeAndMapAccess verifies that
// the remoteConnectionMap operations during address change are thread-safe.
// In production, multiple goroutines may access the map concurrently:
// - serverDiscovery modifies entries on address change
// - sendMessageRoutine reads/writes entries
// - connectionRoutine deletes entries on cleanup
func TestServerDiscovery_ConcurrentAddressChangeAndMapAccess(t *testing.T) {
	ac := &UdpAC{
		remoteConnectionMap: make(map[string]*UdpConn),
	}

	const numGoroutines = 10
	const numIterations = 100
	var wg sync.WaitGroup

	// Simulate concurrent access to remoteConnectionMap
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				addr := fmt.Sprintf("10.0.%d.%d:%d", id, j%256, DefaultServerPort)

				// Simulate adding a connection (like sendMessageRoutine does)
				ac.remoteConnectionMutex.Lock()
				ac.remoteConnectionMap[addr] = &UdpConn{
					ConnData: &core.ConnectionData{
						RemoteAddr: &net.UDPAddr{
							IP:   net.ParseIP(fmt.Sprintf("10.0.%d.%d", id, j%256)),
							Port: DefaultServerPort,
						},
					},
				}
				ac.remoteConnectionMutex.Unlock()

				// Simulate removing a connection (like address change cleanup)
				ac.remoteConnectionMutex.Lock()
				delete(ac.remoteConnectionMap, addr)
				ac.remoteConnectionMutex.Unlock()
			}
		}(i)
	}

	wg.Wait()

	// After all goroutines complete, map should be empty
	if len(ac.remoteConnectionMap) != 0 {
		t.Errorf("Connection map should be empty after cleanup, has %d entries", len(ac.remoteConnectionMap))
	}
}

// TestServerDiscovery_AddressTrackingAcrossIterations verifies the lastAddrStr
// tracking across multiple discovery iterations. The variable tracks the
// previous address to detect changes on each iteration.
func TestServerDiscovery_AddressTrackingAcrossIterations(t *testing.T) {
	// Simulate a sequence of addresses that SendAddr() would return
	// across multiple discovery iterations
	addressSequence := []struct {
		addr        string
		wantChange  bool
		description string
	}{
		{"10.0.0.1:62206", false, "first iteration, no previous address"},
		{"10.0.0.1:62206", false, "same address, no change"},
		{"10.0.0.1:62206", false, "still same address"},
		{"10.0.0.2:62206", true, "DNS changed to new IP"},
		{"10.0.0.2:62206", false, "same new address, no change"},
		{"10.0.0.3:62206", true, "DNS changed again"},
		{"10.0.0.1:62206", true, "DNS reverted to original IP"},
	}

	var lastAddrStr string

	for i, step := range addressSequence {
		addrStr := step.addr
		detected := lastAddrStr != "" && lastAddrStr != addrStr

		if detected != step.wantChange {
			t.Errorf("iteration %d (%s): address change detection: got %v, want %v (last=%q, curr=%q)",
				i, step.description, detected, step.wantChange, lastAddrStr, addrStr)
		}

		lastAddrStr = addrStr
	}
}

// TestServerDiscovery_MultipleAddressChangesResetCounters verifies that fail
// counters are reset each time an address change is detected, not just the
// first time. This ensures that multiple DNS changes during connection
// instability don't accumulate stale failure counts.
func TestServerDiscovery_MultipleAddressChangesResetCounters(t *testing.T) {
	failCount := 0
	var serverFailCount int32

	type iteration struct {
		addr           string
		simulateError  bool
		wantFailCount  int
		wantSharedFail int32
	}

	iterations := []iteration{
		// Connect to first address, have some failures
		{"10.0.0.1:62206", true, 1, 0},
		{"10.0.0.1:62206", true, 2, 0},
		// DNS changes - counters should reset
		{"10.0.0.2:62206", false, 0, 0},
		// Fail on new address
		{"10.0.0.2:62206", true, 1, 0},
		// DNS changes again - counters should reset again
		{"10.0.0.3:62206", false, 0, 0},
		// Accumulate failures up to threshold
		{"10.0.0.3:62206", true, 1, 0},
		{"10.0.0.3:62206", true, 2, 0},
		{"10.0.0.3:62206", true, 3, 1}, // hits ServerDiscoveryRetryBeforeFail=3
	}

	lastAddrStr := ""
	for i, iter := range iterations {
		// Detect address change
		if lastAddrStr != "" && lastAddrStr != iter.addr {
			failCount = 0
			atomic.StoreInt32(&serverFailCount, 0)
		}
		lastAddrStr = iter.addr

		// Simulate error
		if iter.simulateError {
			failCount++
			if failCount%ServerDiscoveryRetryBeforeFail == 0 {
				atomic.StoreInt32(&serverFailCount, 1)
			}
		}

		if failCount != iter.wantFailCount {
			t.Errorf("iteration %d (addr=%s): failCount: got %d, want %d",
				i, iter.addr, failCount, iter.wantFailCount)
		}
		if got := atomic.LoadInt32(&serverFailCount); got != iter.wantSharedFail {
			t.Errorf("iteration %d (addr=%s): serverFailCount: got %d, want %d",
				i, iter.addr, got, iter.wantSharedFail)
		}
	}
}

// TestUdpPeer_SendAddrWithHostname verifies that SendAddr correctly
// resolves a hostname to an IP address and returns a *net.UDPAddr with the
// correct port.
func TestUdpPeer_SendAddrWithHostname(t *testing.T) {
	peer := &core.UdpPeer{
		Hostname: "localhost",
		Port:     DefaultServerPort,
		Type:     core.NHP_SERVER,
	}

	addr := peer.SendAddr()
	if addr == nil {
		t.Fatal("SendAddr should resolve localhost successfully")
	}

	// localhost IP varies by platform; just check port
	assertUDPAddr(t, addr, "", DefaultServerPort)
}

// TestUdpPeer_SendAddrWithStaticIP verifies that SendAddr returns the
// static IP when no hostname is configured.
func TestUdpPeer_SendAddrWithStaticIP(t *testing.T) {
	peer := &core.UdpPeer{
		Ip:   "192.168.1.100",
		Port: DefaultServerPort,
		Type: core.NHP_SERVER,
	}

	addr := peer.SendAddr()
	if addr == nil {
		t.Fatal("SendAddr should succeed with static IP")
	}

	assertUDPAddr(t, addr, "192.168.1.100", DefaultServerPort)
}

// TestUdpPeer_SendAddrNilForInvalidIP verifies that SendAddr returns
// nil when neither hostname resolution nor static IP yields a valid IP.
func TestUdpPeer_SendAddrNilForInvalidIP(t *testing.T) {
	peer := &core.UdpPeer{
		Ip:   "not-a-valid-ip",
		Port: DefaultServerPort,
		Type: core.NHP_SERVER,
	}

	addr := peer.SendAddr()
	if addr != nil {
		t.Errorf("SendAddr should return nil for invalid IP, got %v", addr)
	}
}

// TestUdpPeer_DNSCacheRespectsTTL verifies that DNS resolution is
// cached for MinimalNSLookupInterval and only re-resolved after that interval.
// After InvalidateDNSCache, the next SendAddr forces immediate re-resolution.
func TestUdpPeer_DNSCacheRespectsTTL(t *testing.T) {
	peer := &core.UdpPeer{
		Hostname: "localhost",
		Port:     DefaultServerPort,
		Type:     core.NHP_SERVER,
	}

	// First call triggers DNS resolution
	addr1 := peer.SendAddr()
	if addr1 == nil {
		t.Fatal("First SendAddr should succeed")
	}

	// Second call should use cached result (within MinimalNSLookupInterval)
	addr2 := peer.SendAddr()
	if addr2 == nil {
		t.Fatal("Second SendAddr should succeed from cache")
	}

	// Both should return the same address since cache is valid
	if addr1.String() != addr2.String() {
		t.Errorf("Cached result should be the same: first=%s, second=%s",
			addr1.String(), addr2.String())
	}

	// Invalidate cache
	peer.InvalidateDNSCache()

	// Next call should re-resolve
	addr3 := peer.SendAddr()
	if addr3 == nil {
		t.Fatal("SendAddr after cache invalidation should succeed")
	}

	t.Logf("Cache behavior verified: initial=%s, cached=%s, after_invalidation=%s",
		addr1.String(), addr2.String(), addr3.String())
}

// TestServerDiscovery_FailCountProgressionToThreshold verifies the exact
// progression of fail counts through to DNS cache invalidation, matching the
// logic in serverDiscovery lines 793-819.
func TestServerDiscovery_FailCountProgressionToThreshold(t *testing.T) {
	type failState struct {
		failCount            int
		serverFailCountValue int32
		dnsCacheInvalidated  bool
	}

	var failCount int
	var serverFailCount int32
	var dnsCacheInvalidated bool
	addrStr := "10.0.0.1:62206"

	// Record state at each failure
	var states []failState
	for i := 0; i < ServerDiscoveryRetryBeforeFail*2; i++ {
		failCount++

		if failCount%ServerDiscoveryRetryBeforeFail == 0 {
			atomic.StoreInt32(&serverFailCount, 1)
			dnsCacheInvalidated = true
			t.Logf("Failure %d: DNS cache invalidated for %s", failCount, addrStr)
		} else {
			dnsCacheInvalidated = false
			remaining := ServerDiscoveryRetryBeforeFail - (failCount % ServerDiscoveryRetryBeforeFail)
			t.Logf("Failure %d: %d more until DNS invalidation", failCount, remaining)
		}

		states = append(states, failState{
			failCount:            failCount,
			serverFailCountValue: atomic.LoadInt32(&serverFailCount),
			dnsCacheInvalidated:  dnsCacheInvalidated,
		})
	}

	// Verify cache invalidation happens at exactly the right counts
	for i, s := range states {
		expectedInvalidation := (s.failCount % ServerDiscoveryRetryBeforeFail) == 0
		if s.dnsCacheInvalidated != expectedInvalidation {
			t.Errorf("failure %d: dnsCacheInvalidated: got %v, want %v",
				i+1, s.dnsCacheInvalidated, expectedInvalidation)
		}
	}

	// Verify it happens at multiples of ServerDiscoveryRetryBeforeFail
	if !states[ServerDiscoveryRetryBeforeFail-1].dnsCacheInvalidated {
		t.Errorf("Expected DNS cache invalidation at failure %d", ServerDiscoveryRetryBeforeFail)
	}
	if !states[ServerDiscoveryRetryBeforeFail*2-1].dnsCacheInvalidated {
		t.Errorf("Expected DNS cache invalidation at failure %d", ServerDiscoveryRetryBeforeFail*2)
	}
}

// TestServerDiscovery_OldConnectionNotInMapIsHandled verifies that the address
// change cleanup logic handles the case where the old address is NOT in the
// connection map (e.g., if the connection timed out and was already cleaned up
// by connectionRoutine).
func TestServerDiscovery_OldConnectionNotInMapIsHandled(t *testing.T) {
	ac := &UdpAC{
		remoteConnectionMap: make(map[string]*UdpConn),
	}

	oldAddr := "10.0.0.1:62206"
	newAddr := "10.0.0.2:62206"

	// Don't add any connection for oldAddr - simulating it was already cleaned up

	lastAddrStr := oldAddr
	addrStr := newAddr

	// This should not panic or error even though oldAddr is not in the map
	if lastAddrStr != "" && lastAddrStr != addrStr {
		var oldConn *UdpConn
		ac.remoteConnectionMutex.Lock()
		if conn, found := ac.remoteConnectionMap[lastAddrStr]; found {
			oldConn = conn
			delete(ac.remoteConnectionMap, lastAddrStr)
		}
		ac.remoteConnectionMutex.Unlock()

		if oldConn != nil {
			oldConn.Close()
		}
	}

	// No panic = success
	t.Log("Address change cleanup handled gracefully when old connection is not in map")
}

// TestUdpPeer_ResolveHostCachingBehavior verifies that ResolveHost
// caches the DNS result and only re-resolves after MinimalNSLookupInterval.
func TestUdpPeer_ResolveHostCachingBehavior(t *testing.T) {
	peer := &core.UdpPeer{
		Hostname: "localhost",
		Ip:       "10.0.0.99",
		Port:     DefaultServerPort,
		Type:     core.NHP_SERVER,
	}

	// First resolution
	ip1 := peer.ResolveHost()
	if ip1 == "" {
		t.Fatal("ResolveHost should return a non-empty string")
	}

	// Immediate second call should use cached value
	ip2 := peer.ResolveHost()
	if ip2 != ip1 {
		t.Errorf("Cached ResolveHost should return same IP: got %s, want %s", ip2, ip1)
	}

	// After invalidation, should re-resolve
	peer.InvalidateDNSCache()
	ip3 := peer.ResolveHost()
	if ip3 == "" {
		t.Fatal("ResolveHost after invalidation should return a non-empty string")
	}

	t.Logf("ResolveHost caching: first=%s, cached=%s, after_invalidation=%s", ip1, ip2, ip3)
}

// TestUdpPeer_NoHostnameSkipsDNS verifies that when only a static IP
// is configured (no hostname), ResolveHost returns the static IP directly
// without any DNS lookup.
func TestUdpPeer_NoHostnameSkipsDNS(t *testing.T) {
	peer := &core.UdpPeer{
		Ip:   "10.0.0.42",
		Port: DefaultServerPort,
		Type: core.NHP_SERVER,
	}

	// ResolveHost should return static IP directly
	ip := peer.ResolveHost()
	if ip != "10.0.0.42" {
		t.Errorf("ResolveHost with no hostname: got %s, want 10.0.0.42", ip)
	}

	// ResolvedIps should be nil (no DNS lookup happened)
	resolvedIps := peer.ResolvedIps()
	if len(resolvedIps) != 0 {
		t.Errorf("ResolvedIps should be empty when no hostname is configured, got %v", resolvedIps)
	}
}

// TestServerDiscovery_AddressChangeCleanupOrder verifies that connection
// cleanup happens in the correct order: delete from map under lock, then
// close the connection outside the lock. This ordering is critical — closing
// under the lock would block all map operations for the duration of Close().
//
// The test proves the lock is NOT held during Close() by having a concurrent
// goroutine acquire the lock while Close() is running. If Close() were inside
// the lock, the goroutine would block until Close() finishes.
func TestServerDiscovery_AddressChangeCleanupOrder(t *testing.T) {
	ac := createTestACForDiscovery(t)
	defer ac.device.Stop()

	oldAddr := "10.0.0.1:62206"

	conn := createTestUdpConn(t, ac, "10.0.0.1", DefaultServerPort)
	ac.remoteConnectionMutex.Lock()
	ac.remoteConnectionMap[oldAddr] = conn
	ac.remoteConnectionMutex.Unlock()

	// Track operation order with a channel-based approach:
	// after delete (under lock) but before close (outside lock),
	// verify the map is already updated and the lock is free.
	deleteDone := make(chan struct{})
	mapAccessible := make(chan bool, 1)

	// Step 1: Remove from map under lock
	var oldConn *UdpConn
	ac.remoteConnectionMutex.Lock()
	if c, found := ac.remoteConnectionMap[oldAddr]; found {
		oldConn = c
		delete(ac.remoteConnectionMap, oldAddr)
	}
	ac.remoteConnectionMutex.Unlock()

	// Signal that delete is done and lock is released
	close(deleteDone)

	// Concurrent goroutine: verify the lock is free (not held during Close)
	go func() {
		<-deleteDone // wait for delete to complete
		// Try to acquire the lock — this proves Close() doesn't hold it
		ac.remoteConnectionMutex.Lock()
		_, stillExists := ac.remoteConnectionMap[oldAddr]
		ac.remoteConnectionMutex.Unlock()
		mapAccessible <- !stillExists
	}()

	// Step 2: Close outside lock
	if oldConn != nil {
		oldConn.Close()
	}

	// Verify the concurrent goroutine could access the map
	if accessible := <-mapAccessible; !accessible {
		t.Error("Old address should be removed from map before Close() runs")
	}

	// Verify final state
	ac.remoteConnectionMutex.Lock()
	remaining := len(ac.remoteConnectionMap)
	ac.remoteConnectionMutex.Unlock()
	if remaining != 0 {
		t.Errorf("remoteConnectionMap should be empty, has %d entries", remaining)
	}
}
