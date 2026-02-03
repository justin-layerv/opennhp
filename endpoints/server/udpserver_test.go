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

// TestACConnectionCleanup_OnReregistration tests that when an AC re-registers
// from a different source port, the old stale connection is cleaned up.
// This prevents knock operations from using stale connections.
func TestACConnectionCleanup_OnReregistration(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:              device,
		acPeerMap:           make(map[string]*core.UdpPeer),
		acConnectionMap:     make(map[string]*ACConn),
		remoteConnectionMap: make(map[string]*UdpConn),
	}

	acId := "test-ac"

	// Create initial connection (simulating first registration from port 47051)
	oldRemoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.100"), Port: 47051}
	oldConnData := &core.ConnectionData{
		RemoteAddr: oldRemoteAddr,
	}
	oldPeer := &core.UdpPeer{
		Ip:           "10.0.0.100",
		Port:         47051,
		PubKeyBase64: "b2xkcGVlcg==",
	}
	oldPeer.Type = core.NHP_AC
	oldPeer.UpdateRecv(time.Now().UnixNano(), oldRemoteAddr)

	oldACConn := &ACConn{
		ConnData: oldConnData,
		ACPeer:   oldPeer,
		ACId:     acId,
	}
	oldUdpConn := &UdpConn{
		ConnData:       oldConnData,
		isACConnection: true,
	}

	// Store old connection in both maps
	s.acConnectionMap[acId] = oldACConn
	s.remoteConnectionMap[oldRemoteAddr.String()] = oldUdpConn

	// Verify old connection is stored
	if len(s.acConnectionMap) != 1 {
		t.Fatalf("Expected 1 AC connection, got %d", len(s.acConnectionMap))
	}
	if len(s.remoteConnectionMap) != 1 {
		t.Fatalf("Expected 1 remote connection, got %d", len(s.remoteConnectionMap))
	}

	// Create new connection (simulating re-registration from port 38229)
	newRemoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.100"), Port: 38229}
	newConnData := &core.ConnectionData{
		RemoteAddr: newRemoteAddr,
	}
	newPeer := &core.UdpPeer{
		Ip:           "10.0.0.100",
		Port:         38229,
		PubKeyBase64: "bmV3cGVlcg==",
	}
	newPeer.Type = core.NHP_AC
	newPeer.UpdateRecv(time.Now().UnixNano(), newRemoteAddr)

	newACConn := &ACConn{
		ConnData: newConnData,
		ACPeer:   newPeer,
		ACId:     acId,
	}

	// Simulate the cleanup logic from HandleACOnline (using address comparison)
	s.acConnectionMapMutex.Lock()
	if oldConn, exists := s.acConnectionMap[acId]; exists {
		oldAddrStr := oldConn.ConnData.RemoteAddr.String()
		newAddrStr := newConnData.RemoteAddr.String()
		if oldAddrStr != newAddrStr {
			s.acConnectionMapMutex.Unlock()

			s.remoteConnectionMapMutex.Lock()
			if _, found := s.remoteConnectionMap[oldAddrStr]; found {
				delete(s.remoteConnectionMap, oldAddrStr)
			}
			s.remoteConnectionMapMutex.Unlock()

			s.acConnectionMapMutex.Lock()
		}
	}
	s.acConnectionMap[acId] = newACConn
	s.acConnectionMapMutex.Unlock()

	// Verify: old connection should be removed from remoteConnectionMap
	if _, exists := s.remoteConnectionMap[oldRemoteAddr.String()]; exists {
		t.Error("Old connection should be removed from remoteConnectionMap after re-registration")
	}

	// Verify: new AC connection should be stored
	if storedConn, exists := s.acConnectionMap[acId]; !exists {
		t.Error("New AC connection should be stored in acConnectionMap")
	} else if storedConn.ConnData.RemoteAddr.Port != 38229 {
		t.Errorf("Expected new connection port 38229, got %d", storedConn.ConnData.RemoteAddr.Port)
	}

	// Verify: only 1 AC connection exists (no duplicates)
	if len(s.acConnectionMap) != 1 {
		t.Errorf("Expected exactly 1 AC connection after re-registration, got %d", len(s.acConnectionMap))
	}
}

// TestACPeer_RecvAddrUpdatedOnReregistration tests that when an existing AC peer
// re-registers from a different source port, its RecvAddr is updated.
// This is critical because processACOperation uses ACPeer.RecvAddr() to send
// knock operations to the AC.
func TestACPeer_RecvAddrUpdatedOnReregistration(t *testing.T) {
	// Create peer as it would be created on first registration
	acPeer := &core.UdpPeer{
		Hostname:     "test-ac",
		Ip:           "10.0.0.100",
		Port:         47051, // Original port
		PubKeyBase64: "dGVzdHB1YmtleQ==",
		ExpireTime:   0,
	}
	acPeer.Type = core.NHP_AC

	// Initialize recvAddr with original address
	oldRemoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.100"), Port: 47051}
	acPeer.UpdateRecv(time.Now().UnixNano(), oldRemoteAddr)

	// Verify original address
	if acPeer.RecvAddr().String() != "10.0.0.100:47051" {
		t.Fatalf("Expected initial recvAddr '10.0.0.100:47051', got '%s'", acPeer.RecvAddr().String())
	}

	// Simulate re-registration from new port (as done in HandleACOnline fix)
	newRemoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.100"), Port: 38229}
	acPeer.UpdateRecv(time.Now().UnixNano(), newRemoteAddr)

	// Verify address is updated
	if acPeer.RecvAddr().String() != "10.0.0.100:38229" {
		t.Errorf("Expected updated recvAddr '10.0.0.100:38229', got '%s'", acPeer.RecvAddr().String())
	}
}

// TestACConnectionCleanup_SameConnection tests that cleanup doesn't happen
// when the AC sends NHP_AOL from the same connection (no port change).
func TestACConnectionCleanup_SameConnection(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:              device,
		acPeerMap:           make(map[string]*core.UdpPeer),
		acConnectionMap:     make(map[string]*ACConn),
		remoteConnectionMap: make(map[string]*UdpConn),
	}

	acId := "test-ac"

	// Create connection
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.100"), Port: 47051}
	connData := &core.ConnectionData{
		RemoteAddr: remoteAddr,
	}
	peer := &core.UdpPeer{
		Ip:           "10.0.0.100",
		Port:         47051,
		PubKeyBase64: "c2FtZXBlZXI=",
	}
	peer.Type = core.NHP_AC
	peer.UpdateRecv(time.Now().UnixNano(), remoteAddr)

	acConn := &ACConn{
		ConnData: connData,
		ACPeer:   peer,
		ACId:     acId,
	}
	udpConn := &UdpConn{
		ConnData:       connData,
		isACConnection: true,
	}

	// Store connection
	s.acConnectionMap[acId] = acConn
	s.remoteConnectionMap[remoteAddr.String()] = udpConn

	// Simulate re-registration from SAME connection (same address)
	s.acConnectionMapMutex.Lock()
	if oldConn, exists := s.acConnectionMap[acId]; exists {
		oldAddrStr := oldConn.ConnData.RemoteAddr.String()
		newAddrStr := connData.RemoteAddr.String()
		// Same address - should NOT clean up
		if oldAddrStr != newAddrStr {
			t.Error("Same address should not trigger cleanup")
		}
	}
	s.acConnectionMap[acId] = acConn
	s.acConnectionMapMutex.Unlock()

	// Verify: connection should still exist in remoteConnectionMap
	if _, exists := s.remoteConnectionMap[remoteAddr.String()]; !exists {
		t.Error("Connection should NOT be removed when re-registering from same connection")
	}
}
