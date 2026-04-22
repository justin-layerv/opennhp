package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// ============================================================================
// isPrivateIP Tests
// ============================================================================

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// RFC 1918 private ranges
		{"10.x.x.x", "10.0.0.1", true},
		{"10.255.x.x", "10.255.255.255", true},
		{"172.16.x.x", "172.16.0.1", true},
		{"172.31.x.x", "172.31.255.255", true},
		{"192.168.x.x", "192.168.1.1", true},

		// Loopback
		{"loopback", "127.0.0.1", true},
		{"loopback other", "127.0.0.2", true},

		// Public IPs
		{"public 8.8.8.8", "8.8.8.8", false},
		{"public 1.1.1.1", "1.1.1.1", false},
		{"public 54.x", "54.1.2.3", false},

		// Edge cases
		{"empty string", "", false},
		{"invalid", "not-an-ip", false},
		{"172.15 (not private)", "172.15.255.255", false},
		{"172.32 (not private)", "172.32.0.1", false},

		// IPv6
		{"ipv6 loopback", "::1", true},
		{"ipv6 link-local", "fe80::1", false}, // link-local is not private
		{"ipv6 ULA", "fd00::1", true},         // unique local address is private
		{"ipv6 public", "2001:db8::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPrivateIP(tt.ip)
			if result != tt.expected {
				t.Errorf("isPrivateIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

// ============================================================================
// filterForwardTargets Tests
// ============================================================================

func TestFilterForwardTargets_ExcludesSelf(t *testing.T) {
	f := &HttpKnockForwarder{
		localIP: "10.0.0.1",
	}

	servers := []ServerInfo{
		{ID: "srv-1", InternalIP: "10.0.0.1"}, // self
		{ID: "srv-2", InternalIP: "10.0.0.2"},
		{ID: "srv-3", InternalIP: "10.0.0.3"},
	}

	result := f.filterForwardTargets(context.Background(), servers)

	if len(result) != 2 {
		t.Fatalf("Expected 2 servers (excluding self), got %d", len(result))
	}
	for _, srv := range result {
		if srv.InternalIP == "10.0.0.1" {
			t.Error("Self should have been excluded")
		}
	}
}

func TestFilterForwardTargets_WithHealthChecker(t *testing.T) {
	mock := NewMockHealthChecker(map[string]bool{
		"10.0.0.2": true,
		// 10.0.0.3 is unhealthy
	})

	f := &HttpKnockForwarder{
		localIP:  "10.0.0.1",
		cloudMap: mock,
	}

	servers := []ServerInfo{
		{ID: "srv-1", InternalIP: "10.0.0.1", IP: "10.0.0.1"}, // self
		{ID: "srv-2", InternalIP: "10.0.0.2", IP: "10.0.0.2"}, // healthy
		{ID: "srv-3", InternalIP: "10.0.0.3", IP: "10.0.0.3"}, // unhealthy
	}

	result := f.filterForwardTargets(context.Background(), servers)

	if len(result) != 1 {
		t.Fatalf("Expected 1 server (self excluded, srv-3 unhealthy), got %d", len(result))
	}
	if result[0].ID != "srv-2" {
		t.Errorf("Expected srv-2, got %s", result[0].ID)
	}
}

func TestFilterForwardTargets_NilHealthChecker(t *testing.T) {
	f := &HttpKnockForwarder{
		localIP: "10.0.0.1",
	}

	servers := []ServerInfo{
		{ID: "srv-2", InternalIP: "10.0.0.2"},
		{ID: "srv-3", InternalIP: "10.0.0.3"},
	}

	result := f.filterForwardTargets(context.Background(), servers)

	if len(result) != 2 {
		t.Fatalf("Expected 2 servers (no health filtering), got %d", len(result))
	}
}

func TestFilterForwardTargets_AllSelf(t *testing.T) {
	f := &HttpKnockForwarder{
		localIP: "10.0.0.1",
	}

	servers := []ServerInfo{
		{ID: "srv-1", InternalIP: "10.0.0.1"},
	}

	result := f.filterForwardTargets(context.Background(), servers)

	if len(result) != 0 {
		t.Fatalf("Expected 0 servers (all are self), got %d", len(result))
	}
}

// ============================================================================
// ForwardHttpKnock Tests
// ============================================================================

func TestForwardHttpKnock_NoStorage(t *testing.T) {
	f := &HttpKnockForwarder{}

	_, err := f.ForwardHttpKnock(context.Background(), "ac-1", &common.HttpKnockRequest{}, &common.ResourceData{})
	if err == nil {
		t.Fatal("Expected error when storage is nil")
	}
}

func TestForwardHttpKnock_AssignmentNotFound(t *testing.T) {
	storage := newMockStorageBackend()
	f := NewHttpKnockForwarder(storage, nil, "10.0.0.1", 8888, nil, nil)

	_, err := f.ForwardHttpKnock(context.Background(), "ac-not-found", &common.HttpKnockRequest{}, &common.ResourceData{})
	if err == nil {
		t.Fatal("Expected error when assignment not found")
	}
}

func TestForwardHttpKnock_AssignmentExpired(t *testing.T) {
	storage := newMockStorageBackend()
	expired := time.Now().Add(-1 * time.Hour).Unix()
	storage.assignments["ac-expired"] = &ACAssignment{
		ACID:            "ac-expired",
		AssignedServers: []ServerInfo{{ID: "srv-1", InternalIP: "10.0.0.2"}},
		TTL:             &expired,
	}
	f := NewHttpKnockForwarder(storage, nil, "10.0.0.1", 8888, nil, nil)

	_, err := f.ForwardHttpKnock(context.Background(), "ac-expired", &common.HttpKnockRequest{}, &common.ResourceData{})
	if err == nil {
		t.Fatal("Expected error for expired assignment")
	}
}

func TestForwardHttpKnock_NoAvailableServers(t *testing.T) {
	storage := newMockStorageBackend()
	storage.assignments["ac-self-only"] = &ACAssignment{
		ACID:            "ac-self-only",
		AssignedServers: []ServerInfo{{ID: "srv-1", InternalIP: "10.0.0.1"}}, // only self
	}
	f := NewHttpKnockForwarder(storage, nil, "10.0.0.1", 8888, nil, nil)

	_, err := f.ForwardHttpKnock(context.Background(), "ac-self-only", &common.HttpKnockRequest{}, &common.ResourceData{})
	if err == nil {
		t.Fatal("Expected error when only self is available")
	}
}

func TestForwardHttpKnock_SuccessfulForward(t *testing.T) {
	// Start a mock server that returns a successful knock response
	expectedAck := &common.ServerKnockAckMsg{
		ErrCode: common.ErrSuccess.ErrorCode(),
	}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nhp/internal/knock" {
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		resp := HttpKnockForwardResponse{AckMsg: expectedAck}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	// Extract host and port from the test server
	// The test server listens on 127.0.0.1 which is a loopback (private) IP
	storage := newMockStorageBackend()
	storage.assignments["ac-test"] = &ACAssignment{
		ACID: "ac-test",
		AssignedServers: []ServerInfo{
			{ID: "srv-2", InternalIP: "127.0.0.1"},
		},
	}

	// Parse port from test server address
	_, portStr, _ := net.SplitHostPort(mockServer.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	f := NewHttpKnockForwarder(storage, nil, "10.0.0.99", port, nil, nil) // different IP than 127.0.0.1

	ack, err := f.ForwardHttpKnock(context.Background(), "ac-test", &common.HttpKnockRequest{}, &common.ResourceData{})
	if err != nil {
		t.Fatalf("Expected successful forward, got error: %v", err)
	}
	if ack == nil {
		t.Fatal("Expected non-nil ack message")
	}
	if ack.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Errorf("Expected success error code, got %s", ack.ErrCode)
	}
}

func TestForwardHttpKnock_ServerReturnsError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := HttpKnockForwardResponse{Error: "AC not connected"}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	storage := newMockStorageBackend()
	storage.assignments["ac-err"] = &ACAssignment{
		ACID: "ac-err",
		AssignedServers: []ServerInfo{
			{ID: "srv-2", InternalIP: "127.0.0.1"},
		},
	}

	_, portStr, _ := net.SplitHostPort(mockServer.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	f := NewHttpKnockForwarder(storage, nil, "10.0.0.99", port, nil, nil)

	_, err := f.ForwardHttpKnock(context.Background(), "ac-err", &common.HttpKnockRequest{}, &common.ResourceData{})
	if err == nil {
		t.Fatal("Expected error when remote returns error")
	}
}

func TestForwardHttpKnock_RejectsPublicIP(t *testing.T) {
	storage := newMockStorageBackend()
	storage.assignments["ac-public"] = &ACAssignment{
		ACID: "ac-public",
		AssignedServers: []ServerInfo{
			{ID: "srv-2", InternalIP: "54.1.2.3"}, // public IP
		},
	}
	f := NewHttpKnockForwarder(storage, nil, "10.0.0.1", 8888, nil, nil)

	_, err := f.ForwardHttpKnock(context.Background(), "ac-public", &common.HttpKnockRequest{}, &common.ResourceData{})
	if err == nil {
		t.Fatal("Expected error for public IP target (SSRF prevention)")
	}
}

// ============================================================================
// selectServersForAssignment Tests
// ============================================================================

func TestSelectServersForAssignment_IncludesSelf(t *testing.T) {
	s := &UdpServer{instanceID: "srv-1"}

	allServers := []ServerInfo{
		{ID: "srv-1", InternalIP: "10.0.0.1", AZ: "us-east-2a"},
		{ID: "srv-2", InternalIP: "10.0.0.2", AZ: "us-east-2b"},
		{ID: "srv-3", InternalIP: "10.0.0.3", AZ: "us-east-2c"},
	}

	selected := s.selectServersForAssignment(allServers, MaxServersPerAssignment)

	if len(selected) != 3 {
		t.Fatalf("Expected 3 servers, got %d", len(selected))
	}

	// Self (srv-1) must be first
	if selected[0].ID != "srv-1" {
		t.Errorf("Expected self (srv-1) first, got %s", selected[0].ID)
	}
}

func TestSelectServersForAssignment_AZDistribution(t *testing.T) {
	s := &UdpServer{instanceID: "srv-1"}

	// 6 servers across 3 AZs
	allServers := []ServerInfo{
		{ID: "srv-1", InternalIP: "10.0.0.1", AZ: "us-east-2a"},
		{ID: "srv-2", InternalIP: "10.0.0.2", AZ: "us-east-2a"},
		{ID: "srv-3", InternalIP: "10.0.0.3", AZ: "us-east-2b"},
		{ID: "srv-4", InternalIP: "10.0.0.4", AZ: "us-east-2b"},
		{ID: "srv-5", InternalIP: "10.0.0.5", AZ: "us-east-2c"},
		{ID: "srv-6", InternalIP: "10.0.0.6", AZ: "us-east-2c"},
	}

	selected := s.selectServersForAssignment(allServers, MaxServersPerAssignment)

	if len(selected) != MaxServersPerAssignment {
		t.Fatalf("Expected %d servers, got %d", MaxServersPerAssignment, len(selected))
	}

	// Should have servers from different AZs
	azSet := make(map[string]bool)
	for _, srv := range selected {
		azSet[srv.AZ] = true
	}
	if len(azSet) < 2 {
		t.Errorf("Expected servers from at least 2 AZs, got %d: %v", len(azSet), azSet)
	}
}

func TestSelectServersForAssignment_DeterministicOrder(t *testing.T) {
	s := &UdpServer{instanceID: "srv-1"}

	allServers := []ServerInfo{
		{ID: "srv-1", InternalIP: "10.0.0.1", AZ: "us-east-2c"},
		{ID: "srv-2", InternalIP: "10.0.0.2", AZ: "us-east-2a"},
		{ID: "srv-3", InternalIP: "10.0.0.3", AZ: "us-east-2b"},
	}

	// Run multiple times — should produce the same result
	first := s.selectServersForAssignment(allServers, MaxServersPerAssignment)
	for i := 0; i < 10; i++ {
		result := s.selectServersForAssignment(allServers, MaxServersPerAssignment)
		if len(result) != len(first) {
			t.Fatalf("Iteration %d: length mismatch %d vs %d", i, len(result), len(first))
		}
		for j := range result {
			if result[j].ID != first[j].ID {
				t.Errorf("Iteration %d: server[%d] = %s, expected %s", i, j, result[j].ID, first[j].ID)
			}
		}
	}
}

func TestSelectServersForAssignment_FewerThanMax(t *testing.T) {
	s := &UdpServer{instanceID: "srv-1"}

	allServers := []ServerInfo{
		{ID: "srv-1", InternalIP: "10.0.0.1", AZ: "us-east-2a"},
		{ID: "srv-2", InternalIP: "10.0.0.2", AZ: "us-east-2b"},
	}

	selected := s.selectServersForAssignment(allServers, MaxServersPerAssignment)

	if len(selected) != 2 {
		t.Fatalf("Expected 2 servers (fewer than max), got %d", len(selected))
	}
}

func TestSelectServersForAssignment_SelfNotInList(t *testing.T) {
	s := &UdpServer{instanceID: "srv-unknown"}

	allServers := []ServerInfo{
		{ID: "srv-1", InternalIP: "10.0.0.1", AZ: "us-east-2a"},
		{ID: "srv-2", InternalIP: "10.0.0.2", AZ: "us-east-2b"},
		{ID: "srv-3", InternalIP: "10.0.0.3", AZ: "us-east-2c"},
	}

	selected := s.selectServersForAssignment(allServers, MaxServersPerAssignment)

	if len(selected) != MaxServersPerAssignment {
		t.Fatalf("Expected %d servers, got %d", MaxServersPerAssignment, len(selected))
	}
}

func TestSelectServersForAssignment_SingleServer(t *testing.T) {
	s := &UdpServer{instanceID: "srv-1"}

	allServers := []ServerInfo{
		{ID: "srv-1", InternalIP: "10.0.0.1", AZ: "us-east-2a"},
	}

	selected := s.selectServersForAssignment(allServers, MaxServersPerAssignment)

	if len(selected) != 1 {
		t.Fatalf("Expected 1 server, got %d", len(selected))
	}
	if selected[0].ID != "srv-1" {
		t.Errorf("Expected srv-1, got %s", selected[0].ID)
	}
}

// ============================================================================
// ACAssignment.Clone Tests
// ============================================================================

func TestACAssignment_Clone(t *testing.T) {
	ttl := int64(1234567890)
	reassigned := int64(1234567800)
	original := &ACAssignment{
		ACID:         "ac-test",
		ResourceFQDN: "test.example.com",
		CustomerID:   "cust-123",
		AssignedServers: []ServerInfo{
			{ID: "srv-1", IP: "10.0.0.1"},
		},
		Version:      3,
		ReassignedAt: &reassigned,
		CreatedAt:    1234567000,
		LastSeen:     1234567800,
		TTL:          &ttl,
	}

	clone := original.Clone()

	// Values should match
	if clone.ACID != original.ACID {
		t.Errorf("ACID mismatch: %s vs %s", clone.ACID, original.ACID)
	}
	if clone.Version != original.Version {
		t.Errorf("Version mismatch: %d vs %d", clone.Version, original.Version)
	}

	// Mutating clone should not affect original
	clone.Version = 99
	clone.LastSeen = 9999999
	if original.Version == 99 {
		t.Error("Mutating clone.Version affected original")
	}
	if original.LastSeen == 9999999 {
		t.Error("Mutating clone.LastSeen affected original")
	}

	// Clone is a different pointer
	if clone == original {
		t.Error("Clone should be a different pointer")
	}

	// TTL is deep-copied — mutating clone TTL should not affect original
	*clone.TTL = 9999
	if *original.TTL != 1234567890 {
		t.Errorf("Mutating clone.TTL affected original: got %d", *original.TTL)
	}

	// AssignedServers is deep-copied — mutating clone slice should not affect original
	clone.AssignedServers[0].ID = "srv-mutated"
	if original.AssignedServers[0].ID != "srv-1" {
		t.Errorf("Mutating clone.AssignedServers affected original: got %s", original.AssignedServers[0].ID)
	}
}

// ============================================================================
// maxForwardResponseSize Constant Test
// ============================================================================

func TestMaxForwardResponseSize(t *testing.T) {
	if maxForwardResponseSize != 64<<10 {
		t.Errorf("Expected maxForwardResponseSize to be 64 KiB (65536), got %d", maxForwardResponseSize)
	}
	if maxInternalKnockRequestSize != 64<<10 {
		t.Errorf("Expected maxInternalKnockRequestSize to be 64 KiB (65536), got %d", maxInternalKnockRequestSize)
	}
	// Pin that the two caps are equal TODAY. Declared separately on
	// purpose so a future tuning of one doesn't silently propagate;
	// if they diverge intentionally, update this assertion to match.
	if maxInternalKnockRequestSize != maxForwardResponseSize {
		t.Errorf("request/response caps drifted: request=%d response=%d — if intentional, update this test; if not, fix the const", maxInternalKnockRequestSize, maxForwardResponseSize)
	}
}
