package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// TestBuildServerMetricDimensions tests that buildServerMetricDimensions returns
// correct CloudWatch dimensions based on environment variables, including the
// default fallback values ("unknown" and "cell0") when env vars are unset.
func TestBuildServerMetricDimensions(t *testing.T) {
	t.Run("defaults when env vars unset", func(t *testing.T) {
		// Use t.Setenv for automatic cleanup and parallel safety.
		// Setting to "" is equivalent to unset for our logic (Getenv returns "" for both).
		t.Setenv("NHP_ENVIRONMENT", "")
		t.Setenv("NHP_CELL_ID", "")

		dims := buildServerMetricDimensions()

		if len(dims) != 2 {
			t.Fatalf("Expected 2 dimensions, got %d", len(dims))
		}

		if *dims[0].Name != "Environment" || *dims[0].Value != "unknown" {
			t.Errorf("Expected Environment=unknown, got %s=%s", *dims[0].Name, *dims[0].Value)
		}
		if *dims[1].Name != "Cell" || *dims[1].Value != "cell0" {
			t.Errorf("Expected Cell=cell0, got %s=%s", *dims[1].Name, *dims[1].Value)
		}
	})

	t.Run("custom values from env vars", func(t *testing.T) {
		t.Setenv("NHP_ENVIRONMENT", "sandbox")
		t.Setenv("NHP_CELL_ID", "cell3")

		dims := buildServerMetricDimensions()

		if len(dims) != 2 {
			t.Fatalf("Expected 2 dimensions, got %d", len(dims))
		}

		if *dims[0].Name != "Environment" || *dims[0].Value != "sandbox" {
			t.Errorf("Expected Environment=sandbox, got %s=%s", *dims[0].Name, *dims[0].Value)
		}
		if *dims[1].Name != "Cell" || *dims[1].Value != "cell3" {
			t.Errorf("Expected Cell=cell3, got %s=%s", *dims[1].Name, *dims[1].Value)
		}
	})

	t.Run("partial env vars", func(t *testing.T) {
		t.Setenv("NHP_ENVIRONMENT", "production")
		t.Setenv("NHP_CELL_ID", "")

		dims := buildServerMetricDimensions()

		if *dims[0].Value != "production" {
			t.Errorf("Expected Environment=production, got %s", *dims[0].Value)
		}
		if *dims[1].Value != "cell0" {
			t.Errorf("Expected Cell=cell0 (default), got %s", *dims[1].Value)
		}
	})
}

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
		Port:         common.DefaultNHPPort,
		PubKeyBase64: "dGVzdHB1YmtleQ==", // "testpubkey" base64
		ExpireTime:   common.FarFutureExpiry,
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
		Port:         common.DefaultNHPPort,
		PubKeyBase64: "cGVlcjE=", // "peer1"
		ExpireTime:   common.FarFutureExpiry,
	}
	peer1.Type = core.NHP_AC
	s.AddACPeer(peer1)

	// Add second peer
	peer2 := &core.UdpPeer{
		Ip:           "10.0.0.2",
		Port:         common.DefaultNHPPort,
		PubKeyBase64: "cGVlcjI=", // "peer2"
		ExpireTime:   common.FarFutureExpiry,
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
		Port:         common.DefaultNHPPort,
		PubKeyBase64: "bm90YWM=", // "notac"
		ExpireTime:   common.FarFutureExpiry,
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
		Port:         common.DefaultNHPPort,
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
		Port: common.DefaultNHPPort,
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
		Port:         common.DefaultNHPPort,
		PubKeyBase64: "dGVzdHB1YmtleQ==",
		ExpireTime:   0,
	}
	acPeer.Type = core.NHP_AC

	// Initialize recvAddr (the fix)
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("10.0.0.100"),
		Port: common.DefaultNHPPort,
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
		acConnectionMap:     make(map[string][]*ACConn),
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
	s.acConnectionMap[acId] = []*ACConn{oldACConn}
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

	// Simulate the cleanup logic from HandleACOnline (same IP, different port → update in-place)
	s.acConnectionMapMutex.Lock()
	existingConns := s.acConnectionMap[acId]
	var staleConn *ACConn
	updated := false
	for i, existing := range existingConns {
		if existing.ConnData.RemoteAddr.IP.Equal(newConnData.RemoteAddr.IP) {
			oldAddr := existing.ConnData.RemoteAddr.String()
			newAddr := newConnData.RemoteAddr.String()
			if oldAddr != newAddr {
				staleConn = existing
			}
			existingConns[i] = newACConn
			updated = true
			break
		}
	}
	if !updated {
		existingConns = append(existingConns, newACConn)
	}
	s.acConnectionMap[acId] = existingConns
	s.acConnectionMapMutex.Unlock()

	// Clean up stale connection
	if staleConn != nil {
		oldAddrStr := staleConn.ConnData.RemoteAddr.String()
		s.remoteConnectionMapMutex.Lock()
		if _, found := s.remoteConnectionMap[oldAddrStr]; found {
			delete(s.remoteConnectionMap, oldAddrStr)
		}
		s.remoteConnectionMapMutex.Unlock()
	}

	// Verify: old connection should be removed from remoteConnectionMap
	if _, exists := s.remoteConnectionMap[oldRemoteAddr.String()]; exists {
		t.Error("Old connection should be removed from remoteConnectionMap after re-registration")
	}

	// Verify: new AC connection should be stored
	conns, exists := s.acConnectionMap[acId]
	if !exists || len(conns) == 0 {
		t.Error("New AC connection should be stored in acConnectionMap")
	} else if conns[0].ConnData.RemoteAddr.Port != 38229 {
		t.Errorf("Expected new connection port 38229, got %d", conns[0].ConnData.RemoteAddr.Port)
	}

	// Verify: only 1 AC connection exists for this ID (same IP = update in-place)
	if len(conns) != 1 {
		t.Errorf("Expected exactly 1 AC connection after re-registration from same IP, got %d", len(conns))
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
		acConnectionMap:     make(map[string][]*ACConn),
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
	s.acConnectionMap[acId] = []*ACConn{acConn}
	s.remoteConnectionMap[remoteAddr.String()] = udpConn

	// Simulate re-registration from SAME connection (same IP, same port → update in-place, no stale conn)
	s.acConnectionMapMutex.Lock()
	existingConns := s.acConnectionMap[acId]
	var staleConn *ACConn
	for i, existing := range existingConns {
		if existing.ConnData.RemoteAddr.IP.Equal(connData.RemoteAddr.IP) {
			oldAddr := existing.ConnData.RemoteAddr.String()
			newAddr := connData.RemoteAddr.String()
			if oldAddr != newAddr {
				staleConn = existing
			}
			existingConns[i] = acConn
			break
		}
	}
	s.acConnectionMap[acId] = existingConns
	s.acConnectionMapMutex.Unlock()

	// Same address → no stale connection to clean up
	if staleConn != nil {
		t.Error("Same address should not produce a stale connection")
	}

	// Verify: connection should still exist in remoteConnectionMap
	if _, exists := s.remoteConnectionMap[remoteAddr.String()]; !exists {
		t.Error("Connection should NOT be removed when re-registering from same connection")
	}
}

// TestMultiACRegistration tests that multiple ACs with the same AC ID but
// different IPs are stored as separate entries (blue/green deployment).
func TestMultiACRegistration(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:              device,
		acPeerMap:           make(map[string]*core.UdpPeer),
		acConnectionMap:     make(map[string][]*ACConn),
		remoteConnectionMap: make(map[string]*UdpConn),
	}

	acId := "test-ac"

	// Register first AC instance (blue) from IP 10.0.0.1
	blueAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 47051}
	blueConnData := &core.ConnectionData{RemoteAddr: blueAddr}
	bluePeer := &core.UdpPeer{Ip: "10.0.0.1", Port: 47051, PubKeyBase64: "Ymx1ZQ=="}
	bluePeer.Type = core.NHP_AC
	bluePeer.UpdateRecv(time.Now().UnixNano(), blueAddr)
	blueACConn := &ACConn{ConnData: blueConnData, ACPeer: bluePeer, ACId: acId}

	s.acConnectionMapMutex.Lock()
	s.acConnectionMap[acId] = append(s.acConnectionMap[acId], blueACConn)
	s.acConnectionMapMutex.Unlock()

	// Register second AC instance (green) from IP 10.0.0.2
	greenAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 47051}
	greenConnData := &core.ConnectionData{RemoteAddr: greenAddr}
	greenPeer := &core.UdpPeer{Ip: "10.0.0.2", Port: 47051, PubKeyBase64: "Z3JlZW4="}
	greenPeer.Type = core.NHP_AC
	greenPeer.UpdateRecv(time.Now().UnixNano(), greenAddr)
	greenACConn := &ACConn{ConnData: greenConnData, ACPeer: greenPeer, ACId: acId}

	// Simulate the new registration logic: different IP → append
	s.acConnectionMapMutex.Lock()
	existingConns := s.acConnectionMap[acId]
	found := false
	for _, existing := range existingConns {
		if existing.ConnData.RemoteAddr.IP.Equal(greenConnData.RemoteAddr.IP) {
			found = true
			break
		}
	}
	if !found {
		existingConns = append(existingConns, greenACConn)
	}
	s.acConnectionMap[acId] = existingConns
	s.acConnectionMapMutex.Unlock()

	// Verify both connections are stored
	conns := s.acConnectionMap[acId]
	if len(conns) != 2 {
		t.Fatalf("Expected 2 AC connections for same AC ID (blue/green), got %d", len(conns))
	}

	// Verify they have different IPs
	ip1 := conns[0].ConnData.RemoteAddr.IP.String()
	ip2 := conns[1].ConnData.RemoteAddr.IP.String()
	if ip1 == ip2 {
		t.Errorf("Expected different IPs for blue/green, both are %s", ip1)
	}

	t.Logf("Multi-AC registration: blue=%s, green=%s", ip1, ip2)
}

// TestMultiACConnectionTimeout tests that connection timeout cleanup removes
// only the matching entry from the slice, not the entire AC ID key.
func TestMultiACConnectionTimeout(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:              device,
		acPeerMap:           make(map[string]*core.UdpPeer),
		acConnectionMap:     make(map[string][]*ACConn),
		remoteConnectionMap: make(map[string]*UdpConn),
	}

	acId := "test-ac"

	// Create two AC connections (blue and green)
	blueAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 47051}
	blueConnData := &core.ConnectionData{RemoteAddr: blueAddr}
	blueACConn := &ACConn{ConnData: blueConnData, ACId: acId}

	greenAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 47051}
	greenConnData := &core.ConnectionData{RemoteAddr: greenAddr}
	greenACConn := &ACConn{ConnData: greenConnData, ACId: acId}

	s.acConnectionMap[acId] = []*ACConn{blueACConn, greenACConn}

	// Simulate blue connection timing out (connectionRoutine cleanup)
	blueUdpConn := &UdpConn{ConnData: blueConnData, isACConnection: true}

	s.acConnectionMapMutex.Lock()
	for acIdKey, conns := range s.acConnectionMap {
		for i, acConn := range conns {
			if acConn.ConnData.Equal(blueUdpConn.ConnData) {
				s.acConnectionMap[acIdKey] = append(conns[:i], conns[i+1:]...)
				if len(s.acConnectionMap[acIdKey]) == 0 {
					delete(s.acConnectionMap, acIdKey)
				}
				break
			}
		}
	}
	s.acConnectionMapMutex.Unlock()

	// Verify: green connection should still be there
	conns, exists := s.acConnectionMap[acId]
	if !exists {
		t.Fatal("AC ID key should still exist after removing one of two connections")
	}
	if len(conns) != 1 {
		t.Fatalf("Expected 1 remaining connection, got %d", len(conns))
	}
	if !conns[0].ConnData.RemoteAddr.IP.Equal(net.ParseIP("10.0.0.2")) {
		t.Errorf("Expected green connection (10.0.0.2) to remain, got %s", conns[0].ConnData.RemoteAddr.IP)
	}
}

// TestMaxACConnsPerID tests that the cap on connections per AC ID works correctly.
func TestMaxACConnsPerID(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:              device,
		acPeerMap:           make(map[string]*core.UdpPeer),
		acConnectionMap:     make(map[string][]*ACConn),
		remoteConnectionMap: make(map[string]*UdpConn),
	}

	acId := "test-ac"
	const maxConns = 10

	// Register maxConns AC instances
	for i := 0; i < maxConns; i++ {
		addr := &net.UDPAddr{IP: net.ParseIP(fmt.Sprintf("10.0.0.%d", i+1)), Port: 47051}
		connData := &core.ConnectionData{RemoteAddr: addr}
		acConn := &ACConn{ConnData: connData, ACId: acId}
		s.acConnectionMap[acId] = append(s.acConnectionMap[acId], acConn)
	}

	if len(s.acConnectionMap[acId]) != maxConns {
		t.Fatalf("Expected %d connections, got %d", maxConns, len(s.acConnectionMap[acId]))
	}

	// Register one more (should evict oldest)
	newAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.1"), Port: 47051}
	newConnData := &core.ConnectionData{RemoteAddr: newAddr}
	newACConn := &ACConn{ConnData: newConnData, ACId: acId}

	existingConns := s.acConnectionMap[acId]
	if len(existingConns) >= maxConns {
		existingConns = existingConns[1:] // evict oldest
	}
	existingConns = append(existingConns, newACConn)
	s.acConnectionMap[acId] = existingConns

	// Verify count stays at max
	if len(s.acConnectionMap[acId]) != maxConns {
		t.Errorf("Expected %d connections after cap eviction, got %d", maxConns, len(s.acConnectionMap[acId]))
	}

	// Verify newest is the last entry
	lastConn := s.acConnectionMap[acId][maxConns-1]
	if !lastConn.ConnData.RemoteAddr.IP.Equal(net.ParseIP("10.0.1.1")) {
		t.Errorf("Expected newest connection (10.0.1.1) as last entry, got %s", lastConn.ConnData.RemoteAddr.IP)
	}
}

// mockACResponder reads from sendMsgCh and sends mock AC responses.
// delay controls how long before responding; if nil error, sends a success ART response.
func mockACResponder(sendMsgCh <-chan *core.MsgData, delay time.Duration, respErr error) {
	go func() {
		for md := range sendMsgCh {
			go func(md *core.MsgData) {
				time.Sleep(delay)
				ppd := &core.PacketParserData{
					HeaderType: core.NHP_ART,
					Error:      respErr,
				}
				if respErr == nil {
					artMsg := &common.ACOpsResultMsg{
						ErrCode: common.ErrSuccess.ErrorCode(),
					}
					ppd.BodyMessage, _ = json.Marshal(artMsg)
				}
				md.ResponseMsgCh <- ppd
			}(md)
		}
	}()
}

// newTestServerForBroadcast creates a minimal UdpServer suitable for
// processACOperation and processACOperationBroadcast tests.
func newTestServerForBroadcast(t *testing.T) (*UdpServer, chan *core.MsgData) {
	t.Helper()
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	t.Cleanup(func() { device.Stop() })

	sendCh := make(chan *core.MsgData, core.SendQueueSize)

	s := &UdpServer{
		device:                 device,
		sendMsgCh:              sendCh,
		acPeerMap:              make(map[string]*core.UdpPeer),
		acConnectionMap:        make(map[string][]*ACConn),
		remoteConnectionMap:    make(map[string]*UdpConn),
		srcIpAssociatedAddrMap: make(map[string][]*common.NetAddress),
	}
	s.running.Store(true)

	return s, sendCh
}

// newTestACConn creates a mock ACConn with a valid peer for testing.
// device is optional; if provided, ConnectionData.Close() won't panic on flush.
func newTestACConn(t *testing.T, ip string, port int, acId string, device ...*core.Device) *ACConn {
	t.Helper()
	addr := &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
	peer := &core.UdpPeer{
		Ip:           ip,
		Port:         port,
		PubKeyBase64: "dGVzdHB1YmtleQ==", // "testpubkey" - not a valid curve point but valid base64
		ExpireTime:   common.FarFutureExpiry,
	}
	peer.Type = core.NHP_AC
	peer.UpdateRecv(time.Now().UnixNano(), addr)

	// Initialize all channels that ConnectionData.Close() needs to avoid nil-channel panics
	connData := &core.ConnectionData{
		RemoteAddr:       addr,
		StopSignal:       make(chan struct{}),
		SendQueue:        make(chan *core.Packet, 1),
		RecvQueue:        make(chan *core.Packet, 1),
		BlockSignal:      make(chan struct{}, 1),
		SetTimeoutSignal: make(chan struct{}, 1),
	}
	if len(device) > 0 && device[0] != nil {
		connData.Device = device[0]
	}

	return &ACConn{
		ConnData: connData,
		ACPeer:   peer,
		ACId:     acId,
	}
}

// TestBroadcast_ReturnsOnFirstSuccess verifies that the broadcast returns
// immediately on the first AC success (low latency) while remaining goroutines
// continue in the background so all ACs still get the ipset pinhole.
func TestBroadcast_ReturnsOnFirstSuccess(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)

	// Track how many AOP messages complete (one per goroutine)
	var aopCount atomic.Int32
	var allDone sync.WaitGroup
	allDone.Add(3)

	// Respond to all AOP messages with success, but at different speeds
	go func() {
		for md := range sendCh {
			go func(md *core.MsgData) {
				n := aopCount.Add(1)
				// Stagger responses: 0ms, 50ms, 100ms
				time.Sleep(time.Duration(n-1) * 50 * time.Millisecond)
				artMsg := &common.ACOpsResultMsg{ErrCode: common.ErrSuccess.ErrorCode()}
				body, _ := json.Marshal(artMsg)
				md.ResponseMsgCh <- &core.PacketParserData{
					HeaderType:  core.NHP_ART,
					BodyMessage: body,
				}
				allDone.Done()
			}(md)
		}
	}()

	conns := []*ACConn{
		newTestACConn(t, "10.0.0.1", 47051, "test-ac"),
		newTestACConn(t, "10.0.0.2", 47051, "test-ac"),
		newTestACConn(t, "10.0.0.3", 47051, "test-ac"),
	}

	knkMsg := &common.AgentKnockMsg{UserId: "test-user"}
	srcAddr := &common.NetAddress{Ip: "192.168.1.100", Port: 443}
	dstAddrs := []*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}}

	artMsg, err := s.processACOperationBroadcast(knkMsg, conns, srcAddr, dstAddrs, 60)

	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}
	if artMsg == nil {
		t.Fatal("Expected non-nil artMsg")
	}
	if artMsg.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Errorf("Expected success error code, got %s", artMsg.ErrCode)
	}

	// Wait for background goroutines to finish, then verify all 3 AOP messages completed
	allDone.Wait()
	if aopCount.Load() != 3 {
		t.Errorf("Expected all 3 AOP messages sent, got %d", aopCount.Load())
	}
}

// TestBroadcast_PartialFailureStillSucceeds verifies that when some ACs fail
// but at least one succeeds, the broadcast returns success and remaining
// goroutines complete in the background.
func TestBroadcast_PartialFailureStillSucceeds(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)

	var aopCount atomic.Int32
	var allDone sync.WaitGroup
	allDone.Add(3)

	go func() {
		for md := range sendCh {
			go func(md *core.MsgData) {
				n := aopCount.Add(1)
				if n == 2 {
					// Second AC succeeds
					artMsg := &common.ACOpsResultMsg{ErrCode: common.ErrSuccess.ErrorCode()}
					body, _ := json.Marshal(artMsg)
					md.ResponseMsgCh <- &core.PacketParserData{
						HeaderType:  core.NHP_ART,
						BodyMessage: body,
					}
				} else {
					// Others fail
					md.ResponseMsgCh <- &core.PacketParserData{
						HeaderType: core.NHP_ART,
						Error:      common.ErrServerACOpsFailed,
					}
				}
				allDone.Done()
			}(md)
		}
	}()

	conns := []*ACConn{
		newTestACConn(t, "10.0.0.1", 47051, "test-ac"),
		newTestACConn(t, "10.0.0.2", 47051, "test-ac"),
		newTestACConn(t, "10.0.0.3", 47051, "test-ac"),
	}

	knkMsg := &common.AgentKnockMsg{UserId: "test-user"}
	srcAddr := &common.NetAddress{Ip: "192.168.1.100", Port: 443}
	dstAddrs := []*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}}

	artMsg, err := s.processACOperationBroadcast(knkMsg, conns, srcAddr, dstAddrs, 60)

	if err != nil {
		t.Fatalf("Expected success (partial), got error: %v", err)
	}
	if artMsg == nil {
		t.Fatal("Expected non-nil artMsg")
	}
	// Wait for background goroutines, then verify all 3 were attempted
	allDone.Wait()
	if aopCount.Load() != 3 {
		t.Errorf("Expected all 3 AOP messages sent, got %d", aopCount.Load())
	}
}

// TestBroadcastCancellation_AllFail verifies that when all ACs fail,
// the broadcast returns the last error.
func TestBroadcastCancellation_AllFail(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)

	// All ACs respond with errors (use generic error, not timeout,
	// to avoid triggering conn.Close() which needs a fully initialized Device)
	go func() {
		for md := range sendCh {
			go func(md *core.MsgData) {
				md.ResponseMsgCh <- &core.PacketParserData{
					HeaderType: core.NHP_ART,
					Error:      common.ErrServerACOpsFailed,
				}
			}(md)
		}
	}()

	conns := []*ACConn{
		newTestACConn(t, "10.0.0.1", 47051, "test-ac"),
		newTestACConn(t, "10.0.0.2", 47051, "test-ac"),
	}

	knkMsg := &common.AgentKnockMsg{UserId: "test-user"}
	srcAddr := &common.NetAddress{Ip: "192.168.1.100", Port: 443}
	dstAddrs := []*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}}

	_, err := s.processACOperationBroadcast(knkMsg, conns, srcAddr, dstAddrs, 60)

	if err == nil {
		t.Fatal("Expected error when all ACs fail")
	}
}

// TestBroadcastCancellation_SingleConn verifies the single-connection
// optimization (no broadcast overhead).
func TestBroadcastCancellation_SingleConn(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)
	mockACResponder(sendCh, 0, nil)

	conns := []*ACConn{
		newTestACConn(t, "10.0.0.1", 47051, "test-ac"),
	}

	knkMsg := &common.AgentKnockMsg{UserId: "test-user"}
	srcAddr := &common.NetAddress{Ip: "192.168.1.100", Port: 443}
	dstAddrs := []*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}}

	artMsg, err := s.processACOperationBroadcast(knkMsg, conns, srcAddr, dstAddrs, 60)

	if err != nil {
		t.Fatalf("Expected success for single conn, got: %v", err)
	}
	if artMsg == nil {
		t.Fatal("Expected non-nil artMsg")
	}
}

// TestBroadcast_TimeoutReturnsFirstSuccess verifies that when some ACs hang
// beyond DefaultBroadcastTimeout, the broadcast still returns the first success
// and the background goroutine completes (does not leak).
func TestBroadcast_TimeoutReturnsFirstSuccess(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)

	var allDone sync.WaitGroup
	allDone.Add(3)

	// AC 1 responds fast (success), AC 2 responds fast (success),
	// AC 3 never responds — its per-goroutine context.WithTimeout will fire.
	var respondCount atomic.Int32
	go func() {
		for md := range sendCh {
			go func(md *core.MsgData) {
				n := respondCount.Add(1)
				defer allDone.Done()
				if n <= 2 {
					// Respond immediately with success
					artMsg := &common.ACOpsResultMsg{ErrCode: common.ErrSuccess.ErrorCode()}
					body, _ := json.Marshal(artMsg)
					md.ResponseMsgCh <- &core.PacketParserData{
						HeaderType:  core.NHP_ART,
						BodyMessage: body,
					}
				}
				// n == 3: never respond — the goroutine's context timeout will
				// cause processACOperation to return an error. We just need to
				// wait for the channel to be consumed or closed.
				// Since we can't block forever in a test, simulate the timeout
				// by responding with an error after a short delay.
				if n == 3 {
					time.Sleep(200 * time.Millisecond)
					md.ResponseMsgCh <- &core.PacketParserData{
						HeaderType: core.NHP_ART,
						Error:      fmt.Errorf("simulated timeout"),
					}
				}
			}(md)
		}
	}()

	conns := []*ACConn{
		newTestACConn(t, "10.0.0.1", 47051, "test-ac"),
		newTestACConn(t, "10.0.0.2", 47051, "test-ac"),
		newTestACConn(t, "10.0.0.3", 47051, "test-ac"),
	}

	knkMsg := &common.AgentKnockMsg{UserId: "test-user"}
	srcAddr := &common.NetAddress{Ip: "192.168.1.100", Port: 443}
	dstAddrs := []*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}}

	artMsg, err := s.processACOperationBroadcast(knkMsg, conns, srcAddr, dstAddrs, 60)

	if err != nil {
		t.Fatalf("Expected success (first AC responded), got error: %v", err)
	}
	if artMsg == nil {
		t.Fatal("Expected non-nil artMsg")
	}

	// Wait for all goroutines including the "timed out" one
	allDone.Wait()
	if respondCount.Load() != 3 {
		t.Errorf("Expected 3 responders, got %d", respondCount.Load())
	}
}

// TestProcessACOperation_ContextAlreadyCanceled verifies that
// processACOperation returns immediately when the context is already canceled.
func TestProcessACOperation_ContextAlreadyCanceled(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)

	// Slow responder — should not matter since context is already canceled
	go func() {
		for md := range sendCh {
			go func(md *core.MsgData) {
				time.Sleep(10 * time.Second)
				md.ResponseMsgCh <- &core.PacketParserData{
					HeaderType: core.NHP_ART,
				}
			}(md)
		}
	}()

	conn := newTestACConn(t, "10.0.0.1", 47051, "test-ac")
	knkMsg := &common.AgentKnockMsg{UserId: "test-user"}
	srcAddr := &common.NetAddress{Ip: "192.168.1.100", Port: 443}
	dstAddrs := []*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	start := time.Now()
	_, err := s.processACOperation(ctx, knkMsg, conn, srcAddr, dstAddrs, 60)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context.Canceled, got: %v", err)
	}

	if elapsed > 1*time.Second {
		t.Errorf("Should have returned immediately, took %v", elapsed)
	}
}

// TestDrainACConnections verifies that drainACConnections sends NHP_ARD to all
// connected ACs with the NLB hostname, and uses fire-and-forget (no ResponseMsgCh).
func TestDrainACConnections(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)

	// Set NLB config
	s.config = &Config{
		Hostname:   "test-nlb.example.com",
		ListenPort: 62206,
	}

	// Add two AC connections
	ac1 := newTestACConn(t, "10.0.0.1", 47051, "ac-1")
	ac2 := newTestACConn(t, "10.0.0.2", 47051, "ac-2")
	s.acConnectionMap["ac-1"] = []*ACConn{ac1}
	s.acConnectionMap["ac-2"] = []*ACConn{ac2}

	// Run drain in background (it sleeps 100ms at the end)
	go s.drainACConnections()

	// Collect sent messages
	var msgs []*core.MsgData
	timeout := time.After(2 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case md := <-sendCh:
			msgs = append(msgs, md)
		case <-timeout:
			t.Fatalf("expected 2 drain messages, got %d", len(msgs))
		}
	}

	for _, md := range msgs {
		if md.HeaderType != core.NHP_ARD {
			t.Errorf("expected NHP_ARD header type, got %d", md.HeaderType)
		}
		if md.ResponseMsgCh != nil {
			t.Error("drain should be fire-and-forget (nil ResponseMsgCh)")
		}

		var ardMsg common.ACRedispatchMsg
		if err := json.Unmarshal(md.Message, &ardMsg); err != nil {
			t.Fatalf("failed to unmarshal ARD: %v", err)
		}
		if len(ardMsg.Targets) != 1 {
			t.Fatalf("expected 1 target, got %d", len(ardMsg.Targets))
		}
		target := ardMsg.Targets[0]
		if target.Hostname != "test-nlb.example.com" {
			t.Errorf("expected hostname test-nlb.example.com, got %s", target.Hostname)
		}
		if target.IP != "" {
			t.Errorf("drain targets should use Hostname, not IP; got IP=%s", target.IP)
		}
		if target.Port != 62206 {
			t.Errorf("expected port 62206, got %d", target.Port)
		}
	}
}

// TestDrainACConnections_NoACs verifies that drainACConnections is a no-op
// when no ACs are connected.
func TestDrainACConnections_NoACs(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)
	s.config = &Config{
		Hostname:   "test-nlb.example.com",
		ListenPort: 62206,
	}

	// No ACs connected — drain should return immediately
	done := make(chan struct{})
	go func() {
		s.drainACConnections()
		close(done)
	}()

	select {
	case <-done:
		// good — returned quickly
	case <-time.After(1 * time.Second):
		t.Fatal("drainACConnections should return immediately with no ACs")
	}

	// Verify nothing was sent
	select {
	case md := <-sendCh:
		t.Fatalf("unexpected message sent: %+v", md)
	default:
		// good
	}
}

// TestDrainACConnections_NoHostname verifies that drainACConnections returns
// early when no Hostname is configured (e.g., local development).
func TestDrainACConnections_NoHostname(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)
	s.config = &Config{
		Hostname:   "", // no NLB hostname
		ListenPort: 62206,
	}

	// Add an AC so we can verify it's NOT drained
	ac1 := newTestACConn(t, "10.0.0.1", 47051, "ac-1")
	s.acConnectionMap["ac-1"] = []*ACConn{ac1}

	done := make(chan struct{})
	go func() {
		s.drainACConnections()
		close(done)
	}()

	select {
	case <-done:
		// good — returned quickly
	case <-time.After(1 * time.Second):
		t.Fatal("drainACConnections should return immediately without Hostname")
	}

	// Verify nothing was sent despite having an AC
	select {
	case md := <-sendCh:
		t.Fatalf("unexpected message sent: %+v", md)
	default:
		// good
	}
}
