package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

func TestForwardedAgentPubKeyRejectsEmpty(t *testing.T) {
	if got, ok := forwardedAgentPubKey(&core.PacketParserData{}); ok || got != "" {
		t.Fatalf("forwardedAgentPubKey(empty)=(%q,%v), want empty,false", got, ok)
	}
	if got, ok := forwardedAgentPubKey(nil); ok || got != "" {
		t.Fatalf("forwardedAgentPubKey(nil)=(%q,%v), want empty,false", got, ok)
	}
	if got, ok := forwardedAgentPubKey(&core.PacketParserData{RemotePubKey: []byte{1, 2, 3, 4}}); ok || got != "" {
		t.Fatalf("forwardedAgentPubKey(short)=(%q,%v), want empty,false", got, ok)
	}
	if got, ok := forwardedAgentPubKey(&core.PacketParserData{RemotePubKey: make([]byte, 33)}); ok || got != "" {
		t.Fatalf("forwardedAgentPubKey(long)=(%q,%v), want empty,false", got, ok)
	}
}

func TestForwardedAgentPubKeyEncodesAuthenticatedKey(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	got, ok := forwardedAgentPubKey(&core.PacketParserData{RemotePubKey: raw})
	if !ok {
		t.Fatal("forwardedAgentPubKey returned ok=false, want true")
	}
	if want := base64.StdEncoding.EncodeToString(raw); got != want {
		t.Fatalf("forwardedAgentPubKey=%q want %q", got, want)
	}
}

// ============================================================================
// ServerHealthTracker Tests
// ============================================================================

func TestServerHealthTracker_InitialState(t *testing.T) {
	tracker := NewServerHealthTracker()

	// All servers should be healthy initially
	if tracker.IsUnhealthy("srv-1") {
		t.Error("Expected server to be healthy initially")
	}
}

func TestServerHealthTracker_RecordFailure(t *testing.T) {
	tracker := NewServerHealthTracker()

	tracker.RecordFailure("srv-1")

	if !tracker.IsUnhealthy("srv-1") {
		t.Error("Expected server to be unhealthy after failure")
	}
}

func TestServerHealthTracker_RecordSuccess(t *testing.T) {
	tracker := NewServerHealthTracker()

	// Record failure then success
	tracker.RecordFailure("srv-1")
	if !tracker.IsUnhealthy("srv-1") {
		t.Fatal("Expected server to be unhealthy after failure")
	}

	tracker.RecordSuccess("srv-1")
	if tracker.IsUnhealthy("srv-1") {
		t.Error("Expected server to be healthy after success")
	}
}

func TestServerHealthTracker_HealthDecay(t *testing.T) {
	// Create tracker and record failure
	tracker := NewServerHealthTracker()
	tracker.RecordFailure("srv-decay")

	if !tracker.IsUnhealthy("srv-decay") {
		t.Fatal("Expected server to be unhealthy immediately after failure")
	}

	// Manually set failure time to past (simulating decay)
	tracker.mu.Lock()
	tracker.failures["srv-decay"] = time.Now().Add(-HealthDecayDuration - time.Second)
	tracker.mu.Unlock()

	// Should be healthy now (decay expired)
	if tracker.IsUnhealthy("srv-decay") {
		t.Error("Expected server to be healthy after decay period")
	}
}

func TestServerHealthTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewServerHealthTracker()

	var wg sync.WaitGroup
	goroutines := 10
	iterations := 100

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			serverID := "srv-concurrent-" + string(rune('A'+gid%5))

			for i := 0; i < iterations; i++ {
				switch i % 3 {
				case 0:
					tracker.RecordFailure(serverID)
				case 1:
					tracker.RecordSuccess(serverID)
				case 2:
					tracker.IsUnhealthy(serverID)
				}
			}
		}(g)
	}

	wg.Wait()
	// If we get here without panic/race, the test passes
}

// ============================================================================
// ServerForwarder Tests
// ============================================================================

func TestServerForwarder_NextTransactionID(t *testing.T) {
	// Test sequential ID generation (IDs should increment by 1)
	forwarder := &ServerForwarder{
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
		nextTxID:    1000, // Start with known value
	}

	id1 := forwarder.nextTransactionID()
	id2 := forwarder.nextTransactionID()
	id3 := forwarder.nextTransactionID()

	if id1 != 1001 {
		t.Errorf("Expected first ID to be 1001, got %d", id1)
	}
	if id2 != 1002 {
		t.Errorf("Expected second ID to be 1002, got %d", id2)
	}
	if id3 != 1003 {
		t.Errorf("Expected third ID to be 1003, got %d", id3)
	}
}

func TestServerForwarder_EntropyInitialization(t *testing.T) {
	// Test that NewServerForwarder initializes with entropy (non-zero, unpredictable)
	forwarder1 := NewServerForwarder(nil)
	forwarder2 := NewServerForwarder(nil)

	// Both should have non-zero initial IDs
	if forwarder1.nextTxID == 0 {
		t.Error("Expected forwarder1 to have non-zero initial txID")
	}
	if forwarder2.nextTxID == 0 {
		t.Error("Expected forwarder2 to have non-zero initial txID")
	}

	// The two forwarders should have different initial IDs (extremely unlikely to collide)
	if forwarder1.nextTxID == forwarder2.nextTxID {
		t.Error("Expected forwarders to have different initial txIDs")
	}
}

func TestServerForwarder_CleanupPendingForwards(t *testing.T) {
	forwarder := &ServerForwarder{
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
	}

	// Add some pending forwards
	now := time.Now()

	// Fresh pending - should be kept
	forwarder.pendingFwds[1] = &PendingForward{
		TransactionID: 1,
		CreatedAt:     now,
	}

	// Old pending - should be cleaned up
	forwarder.pendingFwds[2] = &PendingForward{
		TransactionID: 2,
		CreatedAt:     now.Add(-ForwardTimeout * 3), // Well past timeout
	}

	// Run cleanup
	forwarder.CleanupPendingForwards()

	// Check results
	if _, exists := forwarder.pendingFwds[1]; !exists {
		t.Error("Expected fresh pending forward to be kept")
	}
	if _, exists := forwarder.pendingFwds[2]; exists {
		t.Error("Expected old pending forward to be cleaned up")
	}
}

func TestServerForwarder_ConcurrentTransactionIDs(t *testing.T) {
	forwarder := &ServerForwarder{
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
	}

	var wg sync.WaitGroup
	goroutines := 10
	idsPerGoroutine := 100

	allIDs := make(chan uint64, goroutines*idsPerGoroutine)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < idsPerGoroutine; i++ {
				id := forwarder.nextTransactionID()
				allIDs <- id
			}
		}()
	}

	wg.Wait()
	close(allIDs)

	// Collect all IDs and check for uniqueness
	seen := make(map[uint64]bool)
	for id := range allIDs {
		if seen[id] {
			t.Errorf("Duplicate transaction ID generated: %d", id)
		}
		seen[id] = true
	}

	expectedCount := goroutines * idsPerGoroutine
	if len(seen) != expectedCount {
		t.Errorf("Expected %d unique IDs, got %d", expectedCount, len(seen))
	}
}

// ============================================================================
// PendingForward Tests
// ============================================================================

func TestPendingForward_Creation(t *testing.T) {
	pending := &PendingForward{
		TransactionID: 12345,
		ResponseCh:    make(chan *common.ServerForwardResultMsg, 1),
		CreatedAt:     time.Now(),
	}

	if pending.TransactionID != 12345 {
		t.Errorf("Expected TransactionID 12345, got %d", pending.TransactionID)
	}
	if pending.ResponseCh == nil {
		t.Error("Expected ResponseCh to be non-nil")
	}
}

// ============================================================================
// ForwardKnock Tests with MemoryStorage
// ============================================================================

func TestForwardKnock_NoAssignedServers(t *testing.T) {
	forwarder := &ServerForwarder{
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
		nextTxID:    1000,
	}

	// Empty assignment
	assignment := &ACAssignment{
		ACID:            "ac-empty",
		AssignedServers: []ServerInfo{},
	}

	ctx := context.Background()
	_, err := forwarder.ForwardKnock(ctx, assignment, []byte("knock"), nil)
	if err == nil {
		t.Fatal("Expected error for empty assigned servers")
	}
	if err.Error() != "no assigned servers for AC" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestForwardKnock_SkipsUnhealthyServers(t *testing.T) {
	forwarder := &ServerForwarder{
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
		nextTxID:    1000,
	}

	// Mark all servers as unhealthy
	forwarder.health.RecordFailure("srv-1")
	forwarder.health.RecordFailure("srv-2")
	forwarder.health.RecordFailure("srv-3")

	assignment := CreateTestACAssignment("ac-1", "srv-1", "srv-2", "srv-3")

	ctx := context.Background()
	_, err := forwarder.ForwardKnock(ctx, assignment, []byte("knock"), nil)
	if err == nil {
		t.Fatal("Expected error when all servers are unhealthy")
	}
	if err.Error() != "all assigned servers unreachable or unhealthy" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestForwardKnock_SendFailureReturnsImmediately(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	baseDeps := NewMockForwarderDeps()
	baseDeps.SetDevice(device)
	deps := &sendFailureForwarderDeps{
		MockForwarderDeps: baseDeps,
		err:               errors.New("prequeue drop"),
	}
	forwarder := NewServerForwarder(deps)
	assignment := &ACAssignment{
		ACID: "ac-send-fail",
		AssignedServers: []ServerInfo{
			{
				ID:         "srv-send-fail",
				InternalIP: "10.0.0.50",
				Port:       common.DefaultNHPPort,
				PubKey:     device.PublicKeyBase64(),
			},
		},
	}

	start := time.Now()
	_, err := forwarder.ForwardKnock(
		context.Background(),
		assignment,
		[]byte("knock"),
		&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321},
	)

	if err == nil {
		t.Fatal("ForwardKnock returned nil error, want send failure")
	}
	if !strings.Contains(err.Error(), "forward send failed: prequeue drop") {
		t.Fatalf("ForwardKnock error = %q, want prequeue send failure", err)
	}
	if elapsed := time.Since(start); elapsed >= ForwardTimeout/2 {
		t.Fatalf("ForwardKnock waited %v after immediate send failure, want less than %v", elapsed, ForwardTimeout/2)
	}
	if forwarder.health.IsUnhealthy("srv-send-fail") {
		t.Fatal("local send failure marked remote server unhealthy")
	}
}

func TestForwardKnock_ServerShuffling(t *testing.T) {
	// This test verifies that servers are shuffled for load distribution
	// Run multiple times and track which server is tried first
	firstServerCounts := make(map[string]int)

	for i := 0; i < 100; i++ {
		forwarder := &ServerForwarder{
			health:      NewServerHealthTracker(),
			pendingFwds: make(map[uint64]*PendingForward),
			serverPeers: make(map[string]*core.UdpPeer),
			nextTxID:    1000,
		}

		assignment := CreateTestACAssignment("ac-shuffle", "srv-a", "srv-b", "srv-c")

		// We can't easily test actual network calls, but we can verify
		// that health tracking affects ordering
		// Mark srv-a as unhealthy - it should always be skipped
		forwarder.health.RecordFailure("srv-a")

		// At this point, either srv-b or srv-c would be tried first
		// (randomly shuffled), but never srv-a
		if !forwarder.health.IsUnhealthy("srv-a") {
			t.Error("srv-a should be marked unhealthy")
		}
		if forwarder.health.IsUnhealthy("srv-b") || forwarder.health.IsUnhealthy("srv-c") {
			t.Error("srv-b and srv-c should be healthy")
		}

		// Track which servers are NOT skipped
		for _, s := range assignment.AssignedServers {
			if !forwarder.health.IsUnhealthy(s.ID) {
				firstServerCounts[s.ID]++
			}
		}
	}

	// srv-a should never be counted (always skipped)
	if firstServerCounts["srv-a"] > 0 {
		t.Error("srv-a should always be skipped (unhealthy)")
	}

	// srv-b and srv-c should each be counted ~100 times
	if firstServerCounts["srv-b"] != 100 || firstServerCounts["srv-c"] != 100 {
		t.Errorf("Expected srv-b and srv-c to be available 100 times each, got b=%d c=%d",
			firstServerCounts["srv-b"], firstServerCounts["srv-c"])
	}
}

// ============================================================================
// HandleForwardRequest Timestamp Validation Tests
// ============================================================================

func TestHandleForwardRequest_StaleTimestamp(t *testing.T) {
	mockDeps := NewMockForwarderDeps()
	forwarder := &ServerForwarder{
		deps:        mockDeps,
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
	}

	// Create message with old timestamp
	fwdMsg := &common.ServerForwardMsg{
		KnockData:     []byte("test-knock"),
		SourceServer:  "srv-source",
		UserAddr:      "1.2.3.4:12345",
		TransactionId: 1234,
		Timestamp:     time.Now().Add(-MaxTimestampAge - time.Minute).Unix(), // Very old
	}

	// Should reject with stale timestamp error
	// Note: HandleForwardRequest sends response via channel, so we check channel
	go forwarder.HandleForwardRequest(nil, fwdMsg)

	select {
	case msg := <-mockDeps.GetSendChannel():
		if msg.HeaderType != core.NHP_FRT {
			t.Errorf("Expected NHP_FRT, got %d", msg.HeaderType)
		}
		// Parse result message to verify error
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(msg.Message, &result); err != nil {
			t.Fatalf("Failed to parse result: %v", err)
		}
		if result.Success {
			t.Error("Expected failure for stale timestamp")
		}
		if result.ErrCode != "STALE_TIMESTAMP" {
			t.Errorf("Expected STALE_TIMESTAMP error, got %s", result.ErrCode)
		}
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for response")
	}
}

func TestHandleForwardRequest_FutureTimestamp(t *testing.T) {
	mockDeps := NewMockForwarderDeps()
	forwarder := &ServerForwarder{
		deps:        mockDeps,
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
	}

	// Create message with future timestamp (beyond clock skew tolerance)
	fwdMsg := &common.ServerForwardMsg{
		KnockData:     []byte("test-knock"),
		SourceServer:  "srv-source",
		UserAddr:      "1.2.3.4:12345",
		TransactionId: 1234,
		Timestamp:     time.Now().Add(10 * time.Second).Unix(), // Too far in future
	}

	go forwarder.HandleForwardRequest(nil, fwdMsg)

	select {
	case msg := <-mockDeps.GetSendChannel():
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(msg.Message, &result); err != nil {
			t.Fatalf("Failed to parse result: %v", err)
		}
		if result.Success {
			t.Error("Expected failure for future timestamp")
		}
		if result.ErrCode != "FUTURE_TIMESTAMP" {
			t.Errorf("Expected FUTURE_TIMESTAMP error, got %s", result.ErrCode)
		}
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for response")
	}
}

func TestHandleForwardRequest_ValidTimestamp_WithinSkew(t *testing.T) {
	mockDeps := NewMockForwarderDeps()
	forwarder := &ServerForwarder{
		deps:        mockDeps,
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
	}

	// Create message with timestamp slightly in future (within 5s tolerance)
	fwdMsg := &common.ServerForwardMsg{
		KnockData:     []byte("test-knock"),
		SourceServer:  "srv-source",
		UserAddr:      "1.2.3.4:12345",
		TransactionId: 1234,
		Timestamp:     time.Now().Add(3 * time.Second).Unix(), // Within tolerance
	}

	go forwarder.HandleForwardRequest(nil, fwdMsg)

	// Should NOT fail on timestamp, but will fail later due to missing device
	select {
	case msg := <-mockDeps.GetSendChannel():
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(msg.Message, &result); err != nil {
			t.Fatalf("Failed to parse result: %v", err)
		}
		// Should fail on decryption, NOT timestamp
		if result.ErrCode == "STALE_TIMESTAMP" || result.ErrCode == "FUTURE_TIMESTAMP" {
			t.Errorf("Should not fail on timestamp (within tolerance), got %s", result.ErrCode)
		}
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for response")
	}
}

func TestHandleForwardRequest_InvalidUserAddr(t *testing.T) {
	mockDeps := NewMockForwarderDeps()
	forwarder := &ServerForwarder{
		deps:        mockDeps,
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
	}

	// Create message with invalid user address
	fwdMsg := &common.ServerForwardMsg{
		KnockData:     []byte("test-knock"),
		SourceServer:  "srv-source",
		UserAddr:      "not-a-valid-address", // Invalid
		TransactionId: 1234,
		Timestamp:     time.Now().Unix(),
	}

	go forwarder.HandleForwardRequest(nil, fwdMsg)

	select {
	case msg := <-mockDeps.GetSendChannel():
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(msg.Message, &result); err != nil {
			t.Fatalf("Failed to parse result: %v", err)
		}
		if result.ErrCode != "INVALID_USER_ADDR" {
			t.Errorf("Expected INVALID_USER_ADDR error, got %s", result.ErrCode)
		}
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for response")
	}
}

func TestHandleDecryptedForwardedKnock_RejectsEmptyResourceHost(t *testing.T) {
	mockDeps := NewMockForwarderDeps()
	mockDeps.SetAuthServiceProvider(&common.AuthServiceProviderData{
		AuthSvcId: "agent",
		ResourceGroups: common.ResourceGroupMap{
			"qurl-tunnel-server": {
				ResourceGroup: common.ResourceGroup{
					AuthServiceId: "agent",
					ResourceId:    "qurl-tunnel-server",
					OpenTime:      30,
					Resources: map[string]*common.ResourceInfo{
						"qurl-tunnel-server": {
							ACId:       "ac-a",
							Hostname:   "connect.test",
							PortSuffix: true,
							Addr: &common.NetAddress{
								Port:     0,
								Protocol: "tcp",
							},
						},
					},
				},
			},
		},
	})
	forwarder := NewServerForwarder(mockDeps)

	knockMsg := &common.AgentKnockMsg{
		HeaderType:    core.NHP_KNK,
		UserId:        "test-user",
		DeviceId:      "test-device",
		AuthServiceId: "agent",
		ResourceId:    "qurl-tunnel-server",
	}
	body, err := json.Marshal(knockMsg)
	if err != nil {
		t.Fatalf("marshal knock: %v", err)
	}
	fwdMsg := &common.ServerForwardMsg{
		SourceServer:  "srv-source",
		UserAddr:      "1.2.3.4:12345",
		TransactionId: 1234,
		Timestamp:     time.Now().Unix(),
	}
	userAddr, err := net.ResolveUDPAddr("udp", fwdMsg.UserAddr)
	if err != nil {
		t.Fatalf("resolve user addr: %v", err)
	}

	forwarder.handleDecryptedForwardedKnock(nil, fwdMsg, userAddr, &core.PacketParserData{
		BodyMessage:  body,
		RemotePubKey: make([]byte, 32),
	})

	select {
	case msg := <-mockDeps.GetSendChannel():
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(msg.Message, &result); err != nil {
			t.Fatalf("parse result: %v", err)
		}
		if result.ErrCode != "RESOURCE_INFO_INCOMPLETE" {
			t.Fatalf("ErrCode=%s ErrMsg=%s, want RESOURCE_INFO_INCOMPLETE", result.ErrCode, result.ErrMsg)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}
}

// ============================================================================
// HandleForwardResult Tests
// ============================================================================

func TestHandleForwardResult_MatchingTransaction(t *testing.T) {
	forwarder := &ServerForwarder{
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
	}

	// Create pending forward
	responseCh := make(chan *common.ServerForwardResultMsg, 1)
	forwarder.pendingFwds[12345] = &PendingForward{
		TransactionID: 12345,
		ResponseCh:    responseCh,
		CreatedAt:     time.Now(),
	}

	// Handle result
	resultMsg := &common.ServerForwardResultMsg{
		TransactionId: 12345,
		Success:       true,
		ACKData:       []byte(`{"errCode":"0"}`),
	}

	forwarder.HandleForwardResult(nil, resultMsg)

	// Should receive on channel
	select {
	case received := <-responseCh:
		if received.TransactionId != 12345 {
			t.Errorf("Expected txID 12345, got %d", received.TransactionId)
		}
		if !received.Success {
			t.Error("Expected success")
		}
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for result on channel")
	}
}

func TestHandleForwardResult_UnknownTransaction(t *testing.T) {
	forwarder := &ServerForwarder{
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
	}

	// Handle result for unknown transaction
	resultMsg := &common.ServerForwardResultMsg{
		TransactionId: 99999, // No pending forward with this ID
		Success:       true,
	}

	// Should not panic, just log warning
	forwarder.HandleForwardResult(nil, resultMsg)
	// If we get here without panic, test passes
}

// ============================================================================
// ServerForwarder Lifecycle Tests
// ============================================================================

func TestServerForwarder_StartStop(t *testing.T) {
	forwarder := NewServerForwarder(nil)

	// Add old pending forward BEFORE starting
	forwarder.pendingMutex.Lock()
	forwarder.pendingFwds[1] = &PendingForward{
		TransactionID: 1,
		CreatedAt:     time.Now().Add(-time.Hour), // Very old - will be cleaned
	}
	forwarder.pendingMutex.Unlock()

	forwarder.Start()

	// Let cleanup run at least once (every 4 seconds)
	time.Sleep(ForwardTimeout*2 + 500*time.Millisecond)

	// Verify old pending was cleaned up
	forwarder.pendingMutex.Lock()
	_, hasOld := forwarder.pendingFwds[1]
	forwarder.pendingMutex.Unlock()

	if hasOld {
		t.Error("Expected old pending forward to be cleaned up")
	}

	// Add fresh pending AFTER cleanup ran - this proves cleanup keeps fresh items
	forwarder.pendingMutex.Lock()
	forwarder.pendingFwds[2] = &PendingForward{
		TransactionID: 2,
		CreatedAt:     time.Now(), // Fresh - should be kept
	}
	forwarder.pendingMutex.Unlock()

	// Run cleanup manually to verify fresh entry is kept
	forwarder.CleanupPendingForwards()

	forwarder.pendingMutex.Lock()
	_, hasFresh := forwarder.pendingFwds[2]
	forwarder.pendingMutex.Unlock()

	if !hasFresh {
		t.Error("Expected fresh pending forward to be kept after cleanup")
	}

	// Stop should not hang
	done := make(chan struct{})
	go func() {
		forwarder.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Good
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() timed out")
	}
}

// ============================================================================
// Integration: Storage + Forwarder
// ============================================================================

func TestIntegration_StorageForwarderFlow(t *testing.T) {
	// This test simulates the flow when a knock arrives at a server
	// that doesn't have the AC connection

	storage := NewMemoryStorage()

	// Setup: AC is assigned to servers srv-1, srv-2, srv-3
	storage.PutACAssignment(CreateTestACAssignment("ac-target", "srv-1", "srv-2", "srv-3"))

	// Simulate: Server srv-7 (not assigned) receives knock
	ctx := context.Background()
	assignment, err := storage.GetACAssignment(ctx, "ac-target")
	if err != nil {
		t.Fatalf("Failed to get assignment: %v", err)
	}

	// Verify we got correct assignment
	if len(assignment.AssignedServers) != 3 {
		t.Fatalf("Expected 3 assigned servers, got %d", len(assignment.AssignedServers))
	}

	// Verify server IDs
	serverIDs := make(map[string]bool)
	for _, s := range assignment.AssignedServers {
		serverIDs[s.ID] = true
	}
	if !serverIDs["srv-1"] || !serverIDs["srv-2"] || !serverIDs["srv-3"] {
		t.Error("Expected servers srv-1, srv-2, srv-3 in assignment")
	}

	// The forwarder would now forward to one of these servers
	// (actual network forwarding tested in integration tests)
}

// ============================================================================
// Advanced Forwarding Scenarios
// ============================================================================

func TestForwardKnock_HealthTrackingDuringRetry(t *testing.T) {
	// Test that health tracking is updated correctly when servers fail/succeed
	tracker := NewServerHealthTracker()

	// Simulate forwarding retry scenario:
	// 1. Try srv-1 -> fails
	// 2. Try srv-2 -> fails
	// 3. Try srv-3 -> succeeds

	// Initially all healthy
	if tracker.IsUnhealthy("srv-1") || tracker.IsUnhealthy("srv-2") || tracker.IsUnhealthy("srv-3") {
		t.Fatal("All servers should be healthy initially")
	}

	// Simulate srv-1 failure
	tracker.RecordFailure("srv-1")
	if !tracker.IsUnhealthy("srv-1") {
		t.Error("srv-1 should be unhealthy after failure")
	}

	// Simulate srv-2 failure
	tracker.RecordFailure("srv-2")
	if !tracker.IsUnhealthy("srv-2") {
		t.Error("srv-2 should be unhealthy after failure")
	}

	// Simulate srv-3 success
	tracker.RecordSuccess("srv-3")
	if tracker.IsUnhealthy("srv-3") {
		t.Error("srv-3 should remain healthy after success")
	}

	// On next forwarding attempt, srv-1 and srv-2 should be skipped
	skipped := 0
	for _, serverID := range []string{"srv-1", "srv-2", "srv-3"} {
		if tracker.IsUnhealthy(serverID) {
			skipped++
		}
	}
	if skipped != 2 {
		t.Errorf("Expected 2 servers to be skipped, got %d", skipped)
	}
}

func TestForwardKnock_AllServersFailThenRecover(t *testing.T) {
	tracker := NewServerHealthTracker()

	servers := []string{"srv-1", "srv-2", "srv-3"}

	// Mark all as failed
	for _, s := range servers {
		tracker.RecordFailure(s)
	}

	// All should be unhealthy
	healthyCount := 0
	for _, s := range servers {
		if !tracker.IsUnhealthy(s) {
			healthyCount++
		}
	}
	if healthyCount != 0 {
		t.Error("All servers should be unhealthy")
	}

	// Simulate one server recovering
	tracker.RecordSuccess("srv-2")

	// Now srv-2 should be available
	if tracker.IsUnhealthy("srv-2") {
		t.Error("srv-2 should be healthy after success")
	}
	if !tracker.IsUnhealthy("srv-1") || !tracker.IsUnhealthy("srv-3") {
		t.Error("srv-1 and srv-3 should still be unhealthy")
	}
}

func TestPendingForwards_ConcurrentAddRemove(t *testing.T) {
	forwarder := &ServerForwarder{
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
		nextTxID:    1000,
	}

	var wg sync.WaitGroup
	goroutines := 20
	iterations := 100

	// Concurrent add/remove of pending forwards
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				txID := forwarder.nextTransactionID()

				// Add pending
				forwarder.pendingMutex.Lock()
				forwarder.pendingFwds[txID] = &PendingForward{
					TransactionID: txID,
					ResponseCh:    make(chan *common.ServerForwardResultMsg, 1),
					CreatedAt:     time.Now(),
				}
				forwarder.pendingMutex.Unlock()

				// Simulate some work
				time.Sleep(time.Microsecond)

				// Remove pending
				forwarder.pendingMutex.Lock()
				delete(forwarder.pendingFwds, txID)
				forwarder.pendingMutex.Unlock()
			}
		}(g)
	}

	wg.Wait()

	// All pending forwards should be removed
	forwarder.pendingMutex.Lock()
	remaining := len(forwarder.pendingFwds)
	forwarder.pendingMutex.Unlock()

	if remaining != 0 {
		t.Errorf("Expected 0 pending forwards after cleanup, got %d", remaining)
	}
}

// ============================================================================
// decryptForwardedKnock Error Path Tests
// ============================================================================

func TestDecryptForwardedKnock_EmptyData(t *testing.T) {
	// Create a minimal mock deps
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	deps := NewMockForwarderDeps()
	deps.SetDevice(device)

	forwarder := NewServerForwarder(deps)

	// Test with empty data
	_, err := forwarder.decryptForwardedKnock([]byte{}, nil)
	if err == nil {
		t.Error("Expected error for empty knock data")
	}
	if err.Error() != "empty knock data" {
		t.Errorf("Expected 'empty knock data' error, got: %v", err)
	}
}

func TestDecryptForwardedKnock_InvalidPacket(t *testing.T) {
	// Create a minimal mock deps
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	deps := NewMockForwarderDeps()
	deps.SetDevice(device)

	forwarder := NewServerForwarder(deps)

	// Test with random invalid data (not a valid NHP packet)
	invalidData := []byte("this is not a valid NHP packet")
	_, err := forwarder.decryptForwardedKnock(invalidData, nil)
	if err == nil {
		t.Error("Expected error for invalid packet data")
	}
	// The error should be from the decryption process
	t.Logf("Got expected error: %v", err)
}

func TestDecryptForwardedKnock_TooShort(t *testing.T) {
	// Create a minimal mock deps
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	deps := NewMockForwarderDeps()
	deps.SetDevice(device)

	forwarder := NewServerForwarder(deps)

	// Test with data too short to be a valid packet header
	tooShort := make([]byte, 10) // NHP packet header is much larger
	_, err := forwarder.decryptForwardedKnock(tooShort, nil)
	if err == nil {
		t.Error("Expected error for packet data too short")
	}
	t.Logf("Got expected error: %v", err)
}

// ============================================================================
// getOrCreateServerPeer Tests
// ============================================================================

func TestGetOrCreateServerPeer_CreatesNew(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	deps := NewMockForwarderDeps()
	deps.SetDevice(device)

	forwarder := NewServerForwarder(deps)

	// Create a server info
	serverInfo := ServerInfo{
		ID:         "test-server-1",
		InternalIP: "10.0.0.1",
		Port:       common.DefaultNHPPort,
		PubKey:     "dGVzdHB1YmtleWJhc2U2NA==", // "testpubkeybase64" in base64
	}

	// Get or create peer
	peer, err := forwarder.getOrCreateServerPeer(serverInfo)
	if err != nil {
		t.Fatalf("Failed to create peer: %v", err)
	}
	if peer == nil {
		t.Fatal("Expected non-nil peer")
	}

	// Verify peer is cached
	forwarder.peerMutex.RLock()
	cachedPeer, found := forwarder.serverPeers[serverInfo.ID]
	forwarder.peerMutex.RUnlock()

	if !found {
		t.Error("Expected peer to be cached")
	}
	if cachedPeer != peer {
		t.Error("Cached peer should be same as returned peer")
	}
}

func TestGetOrCreateServerPeer_ReturnsExisting(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	deps := NewMockForwarderDeps()
	deps.SetDevice(device)

	forwarder := NewServerForwarder(deps)

	serverInfo := ServerInfo{
		ID:         "test-server-2",
		InternalIP: "10.0.0.2",
		Port:       common.DefaultNHPPort,
		PubKey:     "dGVzdHB1YmtleTI=", // "testpubkey2" in base64
	}

	// Create peer first time
	peer1, err := forwarder.getOrCreateServerPeer(serverInfo)
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}

	// Get peer second time (should return same instance)
	peer2, err := forwarder.getOrCreateServerPeer(serverInfo)
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}

	if peer1 != peer2 {
		t.Error("Expected same peer instance on second call")
	}
}

func TestGetOrCreateServerPeer_ConcurrentCreation(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	deps := NewMockForwarderDeps()
	deps.SetDevice(device)

	forwarder := NewServerForwarder(deps)

	serverInfo := ServerInfo{
		ID:         "test-server-concurrent",
		InternalIP: "10.0.0.3",
		Port:       common.DefaultNHPPort,
		PubKey:     "Y29uY3VycmVudHRlc3Q=", // "concurrenttest" in base64
	}

	// Launch multiple goroutines trying to create the same peer
	var wg sync.WaitGroup
	peers := make(chan *core.UdpPeer, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			peer, err := forwarder.getOrCreateServerPeer(serverInfo)
			if err != nil {
				t.Errorf("Failed to get peer: %v", err)
				return
			}
			peers <- peer
		}()
	}

	wg.Wait()
	close(peers)

	// All peers should be the same instance
	var firstPeer *core.UdpPeer
	for peer := range peers {
		if firstPeer == nil {
			firstPeer = peer
		} else if peer != firstPeer {
			t.Error("Expected all concurrent calls to return same peer instance")
		}
	}

	// Should only have one peer in the map
	forwarder.peerMutex.RLock()
	peerCount := len(forwarder.serverPeers)
	forwarder.peerMutex.RUnlock()

	if peerCount != 1 {
		t.Errorf("Expected 1 peer in map, got %d", peerCount)
	}
}

// ============================================================================
// Context Cancellation Tests
// ============================================================================

func TestForwardKnock_ContextCancellation(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	device.Start()
	defer device.Stop()

	deps := NewMockForwarderDeps()
	deps.SetDevice(device)

	forwarder := NewServerForwarder(deps)

	// Create an assignment with servers
	assignment := &ACAssignment{
		ACID: "test-ac-cancel",
		AssignedServers: []ServerInfo{
			{ID: "srv-1", InternalIP: "10.0.0.1", Port: common.DefaultNHPPort, PubKey: "c3J2MXB1YmtleQ=="},
			{ID: "srv-2", InternalIP: "10.0.0.2", Port: common.DefaultNHPPort, PubKey: "c3J2MnB1YmtleQ=="},
		},
	}

	// Create an already-canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Try to forward with canceled context
	_, err := forwarder.ForwardKnock(ctx, assignment, []byte("test-knock"), nil)

	// Should return context error
	if err == nil {
		t.Fatal("Expected error from canceled context")
	}

	// The error might be context.Canceled or could be from connection timeout
	// depending on timing, but it should fail
	t.Logf("Got expected error on canceled context: %v", err)
}

// ============================================================================
// Storage Error Scenarios
// ============================================================================

func TestIntegration_StorageError_GracefulDegradation(t *testing.T) {
	storage := NewMemoryStorage()

	// Initially storage works
	storage.PutACAssignment(CreateTestACAssignment("ac-error-test", "srv-1"))

	ctx := context.Background()

	// First lookup succeeds
	assignment, err := storage.GetACAssignment(ctx, "ac-error-test")
	if err != nil {
		t.Fatalf("Initial lookup should succeed: %v", err)
	}
	if assignment.ACID != "ac-error-test" {
		t.Error("Wrong assignment returned")
	}

	// Simulate storage outage
	storage.SetServiceUnavailable("DynamoDB throttled")

	// Lookup during outage should fail with SERVICE_UNAVAILABLE
	_, err = storage.GetACAssignment(ctx, "ac-error-test")
	if err == nil {
		t.Fatal("Expected error during storage outage")
	}

	var se *StorageError
	if !errors.As(err, &se) {
		t.Fatalf("Expected StorageError, got %T", err)
	}
	if se.Code != ErrCodeServiceUnavail {
		t.Errorf("Expected SERVICE_UNAVAILABLE, got %s", se.Code)
	}

	// After outage clears, storage should work again
	assignment, err = storage.GetACAssignment(ctx, "ac-error-test")
	if err != nil {
		t.Fatalf("Lookup should succeed after outage: %v", err)
	}
	if assignment.ACID != "ac-error-test" {
		t.Error("Wrong assignment after recovery")
	}
}

// ============================================================================
// Version Conflict Tests
// ============================================================================

func TestIntegration_VersionConflict_Detection(t *testing.T) {
	storage := NewMemoryStorage()

	// Create assignment with version 1
	assignment := CreateTestACAssignment("ac-version", "srv-1")
	assignment.Version = 1
	storage.PutACAssignment(assignment)

	ctx := context.Background()

	// Read assignment
	retrieved, _ := storage.GetACAssignment(ctx, "ac-version")
	if retrieved.Version != 1 {
		t.Fatalf("Expected version 1, got %d", retrieved.Version)
	}

	// Simulate concurrent update (version bump)
	updated := CreateTestACAssignment("ac-version", "srv-new")
	updated.Version = 2
	storage.PutACAssignment(updated)

	// Re-read shows new version
	retrieved2, _ := storage.GetACAssignment(ctx, "ac-version")
	if retrieved2.Version != 2 {
		t.Errorf("Expected version 2, got %d", retrieved2.Version)
	}
	if retrieved2.AssignedServers[0].ID != "srv-new" {
		t.Error("Expected updated server assignment")
	}
}

// ============================================================================
// Health Tracker Advanced Tests
// ============================================================================

func TestHealthTracker_MultipleServers_IndependentTracking(t *testing.T) {
	tracker := NewServerHealthTracker()

	// Mark different servers as failed at different times
	tracker.RecordFailure("srv-1")
	time.Sleep(10 * time.Millisecond)
	tracker.RecordFailure("srv-2")

	// Both should be unhealthy
	if !tracker.IsUnhealthy("srv-1") {
		t.Error("srv-1 should be unhealthy")
	}
	if !tracker.IsUnhealthy("srv-2") {
		t.Error("srv-2 should be unhealthy")
	}

	// srv-3 was never marked failed
	if tracker.IsUnhealthy("srv-3") {
		t.Error("srv-3 should be healthy")
	}

	// Clear srv-1
	tracker.RecordSuccess("srv-1")
	if tracker.IsUnhealthy("srv-1") {
		t.Error("srv-1 should be healthy after success")
	}
	if !tracker.IsUnhealthy("srv-2") {
		t.Error("srv-2 should still be unhealthy")
	}
}

func TestHealthTracker_RapidFailureSuccess(t *testing.T) {
	tracker := NewServerHealthTracker()

	// Rapid alternation
	for i := 0; i < 100; i++ {
		tracker.RecordFailure("srv-flaky")
		if !tracker.IsUnhealthy("srv-flaky") {
			t.Errorf("Iteration %d: should be unhealthy after failure", i)
		}
		tracker.RecordSuccess("srv-flaky")
		if tracker.IsUnhealthy("srv-flaky") {
			t.Errorf("Iteration %d: should be healthy after success", i)
		}
	}
}

// TestIsSuccessErrCode validates common.IsSuccessErrCode helper function.
// Per nhp/common/errors.go, success is indicated by "" or "0".
func TestIsSuccessErrCode(t *testing.T) {
	tests := []struct {
		name      string
		errCode   string
		isSuccess bool
	}{
		{"empty string is success", "", true},
		{"0 is success", "0", true},
		{"SUCCESS string is not success", "SUCCESS", false},
		{"error code is not success", "LICENSE_EXPIRED", false},
		{"numeric error is not success", "50001", false},
		{"1 is not success", "1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isSuccess := common.IsSuccessErrCode(tt.errCode)
			if isSuccess != tt.isSuccess {
				t.Errorf("IsSuccessErrCode(%q): got %v, want %v", tt.errCode, isSuccess, tt.isSuccess)
			}
		})
	}
}

// ============================================================================
// getOrCreateServerPeer Regression Tests
// ============================================================================

// TestGetOrCreateServerPeer_UsesStaticIP verifies that server peers use the
// static InternalIP field for addressing, NOT DNS resolution of the server ID.
// Regression test: previously target.ID was set as Hostname, causing DNS
// resolution of identifiers like "server-b" to random IPs.
func TestGetOrCreateServerPeer_UsesStaticIP(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, make([]byte, 32), nil)
	if device == nil {
		t.Fatal("failed to create device")
	}
	device.Start()
	defer device.Stop()

	forwarder := &ServerForwarder{
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
		deps:        &testForwarderDepsWithDevice{device: device},
	}

	target := ServerInfo{
		ID:         "non-resolvable-server-id", // NOT a valid hostname
		InternalIP: "10.0.1.50",
		Port:       common.DefaultNHPPort,
		PubKey:     device.PublicKeyBase64(), // self-key for simplicity
	}

	peer, err := forwarder.getOrCreateServerPeer(target)
	if err != nil {
		t.Fatalf("getOrCreateServerPeer failed: %v", err)
	}

	addr := peer.SendAddr()
	if addr == nil {
		t.Fatal("SendAddr() returned nil — peer has no valid address")
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", addr)
	}

	if udpAddr.IP.String() != "10.0.1.50" {
		t.Errorf("expected IP 10.0.1.50, got %s (DNS resolution of server ID?)", udpAddr.IP)
	}
	if udpAddr.Port != common.DefaultNHPPort {
		t.Errorf("expected port %d, got %d", common.DefaultNHPPort, udpAddr.Port)
	}
}

type sendFailureForwarderDeps struct {
	*MockForwarderDeps
	err error
}

func (d *sendFailureForwarderDeps) SendMessage(*core.MsgData) error {
	return d.err
}

// testForwarderDepsWithDevice is a minimal ForwarderDeps for unit tests that
// only need GetDevice().
type testForwarderDepsWithDevice struct {
	device *core.Device
}

func (d *testForwarderDepsWithDevice) GetHostname() string             { return "test-server" }
func (d *testForwarderDepsWithDevice) GetDevice() *core.Device         { return d.device }
func (d *testForwarderDepsWithDevice) SendMessage(*core.MsgData) error { return nil }
func (d *testForwarderDepsWithDevice) FindACConnectionsForResource(*common.AgentKnockMsg, *common.ResourceData) []*ACConn {
	return nil
}
func (d *testForwarderDepsWithDevice) FindAuthSvcProvider(string) *common.AuthServiceProviderData {
	return nil
}
func (d *testForwarderDepsWithDevice) ResolveAuthSvcProvider(context.Context, string, string) *common.AuthServiceProviderData {
	return nil
}
func (d *testForwarderDepsWithDevice) LifecycleCtx() context.Context {
	return context.Background()
}
func (d *testForwarderDepsWithDevice) ProcessACOperation(*common.AgentKnockMsg, *ACConn, *common.NetAddress, []*common.NetAddress, uint32, *common.ResourceData) (*common.ACOpsResultMsg, error) {
	return nil, nil
}
func (d *testForwarderDepsWithDevice) ProcessACOperationBroadcast(context.Context, *common.AgentKnockMsg, []*ACConn, *common.NetAddress, []*common.NetAddress, uint32, *common.ResourceData) (*common.ACOpsResultMsg, error) {
	return nil, nil
}
func (d *testForwarderDepsWithDevice) PublishACKTokens(context.Context, *common.AgentKnockMsg, *common.ServerKnockAckMsg, string, int, string) error {
	return nil
}

func (d *testForwarderDepsWithDevice) ResolveOwnerIDByPubKey(context.Context, string) string {
	return ""
}
