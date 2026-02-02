package server

import (
	"net"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/core"
)

// testPrivateKey returns a valid 32-byte private key for testing.
func testPrivateKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

// TestAddACPeer_NilMap tests that AddACPeer initializes the map when nil.
// This is critical for cloud mode where ac.toml is not loaded and updateACPeers
// is never called, leaving acPeerMap nil.
func TestAddACPeer_NilMap(t *testing.T) {
	// Create a minimal UdpServer with nil acPeerMap (simulates cloud mode startup)
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device: device,
		// acPeerMap intentionally NOT initialized - this is the bug we're testing
	}

	// Create a mock AC peer
	acPeer := &core.UdpPeer{
		Ip:           "10.0.0.100",
		Port:         62206,
		PubKeyBase64: "dGVzdHB1YmtleQ==", // "testpubkey" base64
		ExpireTime:   1924991999,
	}
	acPeer.Type = core.NHP_AC

	// This should NOT panic - the fix initializes the map if nil
	s.AddACPeer(acPeer)

	// Verify the peer was added
	if s.acPeerMap == nil {
		t.Fatal("acPeerMap should be initialized after AddACPeer")
	}

	if len(s.acPeerMap) != 1 {
		t.Errorf("Expected 1 peer in acPeerMap, got %d", len(s.acPeerMap))
	}

	// Verify the peer is accessible by public key
	if _, exists := s.acPeerMap[acPeer.PublicKeyBase64()]; !exists {
		t.Error("Peer not found in acPeerMap by public key")
	}
}

// TestAddACPeer_ExistingMap tests that AddACPeer works correctly when map is already initialized.
func TestAddACPeer_ExistingMap(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:    device,
		acPeerMap: make(map[string]*core.UdpPeer),
	}

	// Add first peer
	peer1 := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         62206,
		PubKeyBase64: "cGVlcjE=", // "peer1"
		ExpireTime:   1924991999,
	}
	peer1.Type = core.NHP_AC
	s.AddACPeer(peer1)

	// Add second peer
	peer2 := &core.UdpPeer{
		Ip:           "10.0.0.2",
		Port:         62206,
		PubKeyBase64: "cGVlcjI=", // "peer2"
		ExpireTime:   1924991999,
	}
	peer2.Type = core.NHP_AC
	s.AddACPeer(peer2)

	// Verify both peers are in the map
	if len(s.acPeerMap) != 2 {
		t.Errorf("Expected 2 peers in acPeerMap, got %d", len(s.acPeerMap))
	}
}

// TestAddACPeer_NonACPeer tests that non-AC peers are not added to acPeerMap.
func TestAddACPeer_NonACPeer(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:    device,
		acPeerMap: make(map[string]*core.UdpPeer),
	}

	// Create a peer with wrong type (not NHP_AC)
	peer := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         62206,
		PubKeyBase64: "bm90YWM=", // "notac"
		ExpireTime:   1924991999,
	}
	peer.Type = core.NHP_AGENT // Not an AC

	s.AddACPeer(peer)

	// Verify peer was NOT added (wrong type)
	if len(s.acPeerMap) != 0 {
		t.Errorf("Expected 0 peers in acPeerMap for non-AC peer, got %d", len(s.acPeerMap))
	}
}

// TestCloudModePeer_RecvAddrInitialized tests that a peer created in cloud mode
// has its recvAddr properly initialized after UpdateRecv is called.
// This is critical because in cloud mode, peer validation is disabled
// (DisableACPeerValidation=true), so responder.go skips the UpdateRecv call.
// The fix in HandleACOnline must call UpdateRecv explicitly.
func TestCloudModePeer_RecvAddrInitialized(t *testing.T) {
	// Simulate cloud mode peer creation (as done in msghandler.go HandleACOnline)
	acPeer := &core.UdpPeer{
		Hostname:     "test-ac",
		Ip:           "10.0.0.100",
		Port:         62206,
		PubKeyBase64: "dGVzdHB1YmtleQ==",
		ExpireTime:   0,
	}
	acPeer.Type = core.NHP_AC

	// Before UpdateRecv, recvAddr.String() returns "<nil>" (the bug we're fixing)
	// Note: RecvAddr() returns net.Addr interface which is not nil even when
	// the underlying *net.UDPAddr is nil (Go interface semantics)
	if acPeer.RecvAddr().String() != "<nil>" {
		t.Errorf("Expected recvAddr.String() to be '<nil>' before UpdateRecv, got '%s'", acPeer.RecvAddr().String())
	}

	// Simulate the fix: call UpdateRecv with the connection address
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("10.0.0.100"),
		Port: 62206,
	}
	acPeer.UpdateRecv(time.Now().UnixNano(), remoteAddr)

	// After UpdateRecv, recvAddr should have valid address
	if acPeer.RecvAddr().String() == "<nil>" {
		t.Fatal("Expected recvAddr to be set after UpdateRecv, still got '<nil>'")
	}

	// Verify the address matches
	if acPeer.RecvAddr().String() != "10.0.0.100:62206" {
		t.Errorf("Expected recvAddr to be '10.0.0.100:62206', got '%s'", acPeer.RecvAddr().String())
	}
}

// TestCloudModePeer_RecvAddrUsedInACConn tests that an ACConn created with a
// properly initialized peer can be used in processACOperation without nil address.
func TestCloudModePeer_RecvAddrUsedInACConn(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	// Create peer as done in cloud mode
	acPeer := &core.UdpPeer{
		Hostname:     "test-ac",
		Ip:           "10.0.0.100",
		Port:         62206,
		PubKeyBase64: "dGVzdHB1YmtleQ==",
		ExpireTime:   0,
	}
	acPeer.Type = core.NHP_AC

	// Initialize recvAddr (the fix)
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("10.0.0.100"),
		Port: 62206,
	}
	acPeer.UpdateRecv(time.Now().UnixNano(), remoteAddr)

	// Create ACConn as done in HandleACOnline
	acConn := &ACConn{
		ACPeer: acPeer,
		ACId:   "test-ac",
	}

	// This is the line that failed with nil in processACOperation
	acAddrStr := acConn.ACPeer.RecvAddr().String()

	if acAddrStr == "<nil>" {
		t.Error("ACConn.ACPeer.RecvAddr() returned <nil>, processACOperation would fail")
	}

	if acAddrStr != "10.0.0.100:62206" {
		t.Errorf("Expected address '10.0.0.100:62206', got '%s'", acAddrStr)
	}
}
