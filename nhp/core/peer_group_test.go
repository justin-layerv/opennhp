package core

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

const testSharedKey = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="

func newTestUdpPeer(ip string, port int) *UdpPeer {
	return &UdpPeer{
		PubKeyBase64: testSharedKey,
		Ip:           ip,
		Port:         port,
		Type:         NHP_SERVER,
	}
}

func udpAddr(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

func TestPeerGroupCreation(t *testing.T) {
	p1 := newTestUdpPeer("10.0.1.5", 62206)
	p2 := newTestUdpPeer("10.0.2.8", 62206)
	pg := NewPeerGroup(p1, p2)

	if pg.Len() != 2 {
		t.Fatalf("expected 2 members, got %d", pg.Len())
	}
	if pg.PublicKeyBase64() != testSharedKey {
		t.Fatalf("expected key %s, got %s", testSharedKey, pg.PublicKeyBase64())
	}
}

func TestPeerGroupAddMember(t *testing.T) {
	p1 := newTestUdpPeer("10.0.1.5", 62206)
	p2 := newTestUdpPeer("10.0.2.8", 62206)
	pg := NewPeerGroup(p1, p2)

	p3 := newTestUdpPeer("10.0.3.12", 62206)
	if !pg.AddMember(p3) {
		t.Fatal("expected AddMember to return true for a unique address with room in the group")
	}

	if pg.Len() != 3 {
		t.Fatalf("expected 3 members, got %d", pg.Len())
	}
}

func TestPeerGroupAddMember_ReRegistration(t *testing.T) {
	p1 := newTestUdpPeer("10.0.1.5", 62206)
	p2 := newTestUdpPeer("10.0.2.8", 62206)
	pg := NewPeerGroup(p1, p2)

	// Re-register same address — should replace, not add, and return true.
	p1New := newTestUdpPeer("10.0.1.5", 62206)
	if !pg.AddMember(p1New) {
		t.Fatal("expected AddMember to return true for re-registration at an existing address (replace path)")
	}

	if pg.Len() != 2 {
		t.Fatalf("expected 2 members after re-registration, got %d", pg.Len())
	}
}

func TestPeerGroupAddMember_MaxSize(t *testing.T) {
	p1 := newTestUdpPeer("10.0.1.1", 62206)
	p2 := newTestUdpPeer("10.0.1.2", 62206)
	pg := NewPeerGroup(p1, p2)

	for i := 3; i <= MaxPeerGroupSize; i++ {
		if !pg.AddMember(newTestUdpPeer(fmt.Sprintf("10.0.1.%d", i), 62206)) {
			t.Fatalf("expected AddMember #%d (before cap) to return true", i)
		}
	}

	// One more with a unique address must be refused.
	refused := newTestUdpPeer("10.0.99.99", 62206)
	if pg.AddMember(refused) {
		t.Fatal("expected AddMember to return false when group is at MaxPeerGroupSize and the new address is unique")
	}
	if pg.Len() != MaxPeerGroupSize {
		t.Fatalf("expected %d members at max, got %d", MaxPeerGroupSize, pg.Len())
	}

	// The cap only blocks appends; re-registration at an existing
	// address must still succeed via the in-place replace branch.
	replaceExisting := newTestUdpPeer("10.0.1.1", 62206)
	if !pg.AddMember(replaceExisting) {
		t.Fatal("expected AddMember to return true for re-registration at an existing address even when the group is at MaxPeerGroupSize")
	}
	if pg.Len() != MaxPeerGroupSize {
		t.Fatalf("expected %d members after at-cap replace, got %d", MaxPeerGroupSize, pg.Len())
	}
}

func TestPeerGroupRemoveMember(t *testing.T) {
	p1 := newTestUdpPeer("10.0.1.5", 62206)
	p2 := newTestUdpPeer("10.0.2.8", 62206)
	p3 := newTestUdpPeer("10.0.3.12", 62206)
	pg := NewPeerGroup(p1, p2)
	pg.AddMember(p3)

	removed := pg.RemoveMember("10.0.2.8")
	if removed == nil {
		t.Fatal("expected removed member, got nil")
	}
	if pg.Len() != 2 {
		t.Fatalf("expected 2 members after remove, got %d", pg.Len())
	}

	// Remove non-existent
	removed = pg.RemoveMember("10.0.99.99")
	if removed != nil {
		t.Fatal("expected nil for non-existent remove")
	}
}

func TestPeerGroupCheckRecvAddress(t *testing.T) {
	p1 := newTestUdpPeer("10.0.1.5", 62206)
	p2 := newTestUdpPeer("10.0.2.8", 62206)
	p3 := newTestUdpPeer("10.0.3.12", 62206)
	pg := NewPeerGroup(p1, p2)
	pg.AddMember(p3)

	now := time.Now().UnixNano()

	// First recv from each — should all succeed (no previous recvAddr set, hold time expired)
	addr1 := udpAddr("10.0.1.5", 62206)
	addr2 := udpAddr("10.0.2.8", 62206)
	addr3 := udpAddr("10.0.3.12", 62206)

	if !pg.CheckRecvAddress(now, addr1) {
		t.Error("CheckRecvAddress should accept addr1")
	}
	pg.UpdateRecv(now, addr1)

	if !pg.CheckRecvAddress(now, addr2) {
		t.Error("CheckRecvAddress should accept addr2")
	}
	pg.UpdateRecv(now, addr2)

	if !pg.CheckRecvAddress(now, addr3) {
		t.Error("CheckRecvAddress should accept addr3")
	}
	pg.UpdateRecv(now, addr3)

	// Now within hold time, each member should still accept their own addr
	nowPlus1 := now + int64(time.Second)
	if !pg.CheckRecvAddress(nowPlus1, addr1) {
		t.Error("CheckRecvAddress should still accept addr1 within hold time")
	}
	if !pg.CheckRecvAddress(nowPlus1, addr2) {
		t.Error("CheckRecvAddress should still accept addr2 within hold time")
	}
	if !pg.CheckRecvAddress(nowPlus1, addr3) {
		t.Error("CheckRecvAddress should still accept addr3 within hold time")
	}
}

func TestPeerGroupCheckRecvAddress_UnknownAddr(t *testing.T) {
	p1 := newTestUdpPeer("10.0.1.5", 62206)
	p2 := newTestUdpPeer("10.0.2.8", 62206)
	pg := NewPeerGroup(p1, p2)

	now := time.Now().UnixNano()

	// Set recv addrs
	pg.UpdateRecv(now, udpAddr("10.0.1.5", 62206))
	pg.UpdateRecv(now, udpAddr("10.0.2.8", 62206))

	// Within hold time, unknown addr should be rejected
	nowPlus1 := now + int64(time.Second)
	unknown := udpAddr("10.0.99.99", 62206)
	if pg.CheckRecvAddress(nowPlus1, unknown) {
		t.Error("CheckRecvAddress should reject unknown addr within hold time")
	}
}

func TestPeerGroupUpdateRecv_RoutesToCorrectMember(t *testing.T) {
	p1 := newTestUdpPeer("10.0.1.5", 62206)
	p2 := newTestUdpPeer("10.0.2.8", 62206)
	pg := NewPeerGroup(p1, p2)

	now := time.Now().UnixNano()

	// Update with p1's address
	pg.UpdateRecv(now, udpAddr("10.0.1.5", 62206))

	// p1 should have recvAddr set
	if p1.RecvAddr() == nil {
		t.Error("p1 should have recvAddr set after UpdateRecv")
	}
	if p1.RecvAddr().String() != "10.0.1.5:62206" {
		t.Errorf("p1 recvAddr = %s, want 10.0.1.5:62206", p1.RecvAddr().String())
	}
}

func TestPeerGroupIsExpired(t *testing.T) {
	p1 := newTestUdpPeer("10.0.1.5", 62206)
	p2 := newTestUdpPeer("10.0.2.8", 62206)

	// No expiry set — neither expired
	pg := NewPeerGroup(p1, p2)
	if pg.IsExpired() {
		t.Error("group should not be expired when no ExpireTime set")
	}

	// Set both to past — group expired
	past := time.Now().Add(-time.Hour).Unix()
	p1.ExpireTime = past
	p2.ExpireTime = past
	if !pg.IsExpired() {
		t.Error("group should be expired when all members expired")
	}

	// Set one to future — group not expired
	p1.ExpireTime = time.Now().Add(time.Hour).Unix()
	if pg.IsExpired() {
		t.Error("group should not be expired when at least one member is valid")
	}
}

func TestPeerGroupPassthrough(t *testing.T) {
	p1 := newTestUdpPeer("10.0.1.5", 62206)
	p2 := newTestUdpPeer("10.0.2.8", 62206)
	pg := NewPeerGroup(p1, p2)

	if pg.DeviceType() != NHP_SERVER {
		t.Errorf("DeviceType = %d, want %d", pg.DeviceType(), NHP_SERVER)
	}
	if pg.PublicKeyBase64() != testSharedKey {
		t.Errorf("PublicKeyBase64 = %s, want %s", pg.PublicKeyBase64(), testSharedKey)
	}
	if pg.Host() != "10.0.1.5:62206" {
		t.Errorf("Host = %s, want 10.0.1.5:62206", pg.Host())
	}
}

func TestPeerGroupName(t *testing.T) {
	p1 := newTestUdpPeer("10.0.1.5", 62206)
	p2 := newTestUdpPeer("10.0.2.8", 62206)
	pg := NewPeerGroup(p1, p2)

	name := pg.Name()
	if name == "" {
		t.Fatal("Name should not be empty")
	}
	// Should end with "(group)"
	if name[len(name)-7:] != "(group)" {
		t.Errorf("Name = %s, should end with (group)", name)
	}
}

func TestPeerGroupAddMember_HostnameReRegistration(t *testing.T) {
	p1 := &UdpPeer{PubKeyBase64: testSharedKey, Hostname: "nlb-a.example.com", Port: 62206, Type: NHP_SERVER}
	p2 := &UdpPeer{PubKeyBase64: testSharedKey, Hostname: "nlb-b.example.com", Port: 62206, Type: NHP_SERVER}
	pg := NewPeerGroup(p1, p2)

	// Re-register same hostname — should replace, not add
	p1New := &UdpPeer{PubKeyBase64: testSharedKey, Hostname: "nlb-a.example.com", Port: 62206, Type: NHP_SERVER}
	pg.AddMember(p1New)
	if pg.Len() != 2 {
		t.Fatalf("expected 2 members after hostname re-registration, got %d", pg.Len())
	}

	// Different hostname — should add
	p3 := &UdpPeer{PubKeyBase64: testSharedKey, Hostname: "nlb-c.example.com", Port: 62206, Type: NHP_SERVER}
	pg.AddMember(p3)
	if pg.Len() != 3 {
		t.Fatalf("expected 3 members after adding different hostname, got %d", pg.Len())
	}
}

func TestDeviceAddPeer_HostnameOnlyDifferentHostnames(t *testing.T) {
	d := &Device{peerMap: make(map[string]Peer)}
	p1 := &UdpPeer{PubKeyBase64: testSharedKey, Hostname: "nlb-a.example.com", Port: 62206, Type: NHP_SERVER}
	p2 := &UdpPeer{PubKeyBase64: testSharedKey, Hostname: "nlb-b.example.com", Port: 62206, Type: NHP_SERVER}

	d.AddPeer(p1)
	d.AddPeer(p2)

	got := d.LookupPeer(p1.PublicKey())
	group, isGroup := got.(*PeerGroup)
	if !isGroup {
		t.Fatal("different hostnames with same key should create PeerGroup")
	}
	if group.Len() != 2 {
		t.Fatalf("expected 2 members, got %d", group.Len())
	}
}

// --- Device.AddPeer integration tests ---

func TestDeviceAddPeer_SinglePeerUnchanged(t *testing.T) {
	d := &Device{
		peerMap: make(map[string]Peer),
	}
	p := newTestUdpPeer("10.0.1.5", 62206)
	d.AddPeer(p)

	got := d.LookupPeer(p.PublicKey())
	if got == nil {
		t.Fatal("LookupPeer returned nil")
	}
	if _, isGroup := got.(*PeerGroup); isGroup {
		t.Fatal("single peer should not be a PeerGroup")
	}
}

func TestDeviceAddPeer_SameAddressOverwrites(t *testing.T) {
	d := &Device{
		peerMap: make(map[string]Peer),
	}
	p1 := newTestUdpPeer("10.0.1.5", 62206)
	p2 := newTestUdpPeer("10.0.1.5", 62206)

	d.AddPeer(p1)
	d.AddPeer(p2)

	got := d.LookupPeer(p1.PublicKey())
	if _, isGroup := got.(*PeerGroup); isGroup {
		t.Fatal("same address re-registration should not create PeerGroup")
	}
	if got != p2 {
		t.Fatal("same address re-registration should overwrite with new peer")
	}
}

func TestDeviceAddPeer_DifferentAddressCreatesGroup(t *testing.T) {
	d := &Device{
		peerMap: make(map[string]Peer),
	}
	p1 := newTestUdpPeer("10.0.1.5", 62206)
	p2 := newTestUdpPeer("10.0.2.8", 62206)

	d.AddPeer(p1)
	d.AddPeer(p2)

	got := d.LookupPeer(p1.PublicKey())
	group, isGroup := got.(*PeerGroup)
	if !isGroup {
		t.Fatal("different addresses with same key should create PeerGroup")
	}
	if group.Len() != 2 {
		t.Fatalf("expected 2 members, got %d", group.Len())
	}
}

func TestDeviceAddPeer_ThirdMemberAddsToGroup(t *testing.T) {
	d := &Device{
		peerMap: make(map[string]Peer),
	}
	p1 := newTestUdpPeer("10.0.1.5", 62206)
	p2 := newTestUdpPeer("10.0.2.8", 62206)
	p3 := newTestUdpPeer("10.0.3.12", 62206)

	d.AddPeer(p1)
	d.AddPeer(p2)
	d.AddPeer(p3)

	got := d.LookupPeer(p1.PublicKey())
	group, isGroup := got.(*PeerGroup)
	if !isGroup {
		t.Fatal("expected PeerGroup")
	}
	if group.Len() != 3 {
		t.Fatalf("expected 3 members, got %d", group.Len())
	}
}

// TestDeviceAddPeer_AtMaxSize_DoesNotAdd locks in the upper-layer
// behavior of the diagnostic-gap fix: when AddMember refuses, Device.AddPeer
// must not grow the group beyond MaxPeerGroupSize. Asserting at the
// PeerGroup layer only (via the AddMember return value) leaves room for a
// future Device.AddPeer refactor to break this invariant while the unit
// tests still pass.
func TestDeviceAddPeer_AtMaxSize_DoesNotAdd(t *testing.T) {
	d := &Device{
		peerMap: make(map[string]Peer),
	}
	for i := 1; i <= MaxPeerGroupSize; i++ {
		d.AddPeer(newTestUdpPeer(fmt.Sprintf("10.0.1.%d", i), 62206))
	}

	got := d.LookupPeer(newTestUdpPeer("10.0.1.1", 62206).PublicKey())
	group, isGroup := got.(*PeerGroup)
	if !isGroup {
		t.Fatalf("expected PeerGroup after %d AddPeer calls, got %T", MaxPeerGroupSize, got)
	}
	if group.Len() != MaxPeerGroupSize {
		t.Fatalf("expected group at cap (size %d), got %d", MaxPeerGroupSize, group.Len())
	}

	// One more AddPeer with a unique address must not grow the group.
	d.AddPeer(newTestUdpPeer("10.0.99.99", 62206))

	if group.Len() != MaxPeerGroupSize {
		t.Fatalf("Device.AddPeer must not grow PeerGroup beyond MaxPeerGroupSize=%d; got %d", MaxPeerGroupSize, group.Len())
	}

	// The refused address must not be reachable via the device pool.
	for _, m := range group.Members() {
		if m.Ip == "10.0.99.99" {
			t.Fatal("refused address must not be present in PeerGroup membership")
		}
	}
}

func TestDeviceRemovePeerByAddress(t *testing.T) {
	d := &Device{
		peerMap: make(map[string]Peer),
	}
	p1 := newTestUdpPeer("10.0.1.5", 62206)
	p2 := newTestUdpPeer("10.0.2.8", 62206)
	p3 := newTestUdpPeer("10.0.3.12", 62206)

	d.AddPeer(p1)
	d.AddPeer(p2)
	d.AddPeer(p3)

	// Remove one — group shrinks to 2
	d.RemovePeerByAddress(testSharedKey, "10.0.2.8")
	got := d.LookupPeer(p1.PublicKey())
	group, isGroup := got.(*PeerGroup)
	if !isGroup {
		t.Fatal("expected PeerGroup with 2 members")
	}
	if group.Len() != 2 {
		t.Fatalf("expected 2 members, got %d", group.Len())
	}

	// Remove another — demotes to single peer
	d.RemovePeerByAddress(testSharedKey, "10.0.3.12")
	got = d.LookupPeer(p1.PublicKey())
	if _, isGroup := got.(*PeerGroup); isGroup {
		t.Fatal("expected single peer after removing down to 1 member")
	}
	udp, ok := got.(*UdpPeer)
	if !ok {
		t.Fatal("expected UdpPeer")
	}
	if udp.Ip != "10.0.1.5" {
		t.Fatalf("expected remaining peer 10.0.1.5, got %s", udp.Ip)
	}

	// Remove last — entry deleted
	d.RemovePeerByAddress(testSharedKey, "10.0.1.5")
	got = d.LookupPeer(p1.PublicKey())
	if got != nil {
		t.Fatal("expected nil after removing all members")
	}
}

func TestDeviceRemovePeer_RemovesEntireGroup(t *testing.T) {
	d := &Device{
		peerMap: make(map[string]Peer),
	}
	p1 := newTestUdpPeer("10.0.1.5", 62206)
	p2 := newTestUdpPeer("10.0.2.8", 62206)

	d.AddPeer(p1)
	d.AddPeer(p2)

	d.RemovePeer(testSharedKey)
	got := d.LookupPeer(p1.PublicKey())
	if got != nil {
		t.Fatal("RemovePeer should remove entire group")
	}
}

// TestEndToEnd_SharedKeyMultiServer simulates the real scenario: AC connects
// to 3 servers sharing the same key, then receives packets from all 3.
func TestEndToEnd_SharedKeyMultiServer(t *testing.T) {
	d := &Device{
		peerMap: make(map[string]Peer),
	}

	// AC connects to 3 assigned servers (HandleRedispatch → connectToServer → AddPeer)
	s1 := newTestUdpPeer("10.0.1.5", 62206)
	s2 := newTestUdpPeer("10.0.2.8", 62206)
	s3 := newTestUdpPeer("10.0.3.12", 62206)
	d.AddPeer(s1)
	d.AddPeer(s2)
	d.AddPeer(s3)

	// Lookup the peer (as validatePeer does)
	peer := d.LookupPeer(s1.PublicKey())
	if peer == nil {
		t.Fatal("LookupPeer should return the peer group")
	}

	now := time.Now().UnixNano()

	// Receive NHP_AOP from server-1
	addr1 := udpAddr("10.0.1.5", 62206)
	if !peer.CheckRecvAddress(now, addr1) {
		t.Fatal("should accept packet from server-1")
	}
	peer.UpdateRecv(now, addr1)

	// Receive NHP_AOP from server-2 (this was the failing case before PeerGroup)
	addr2 := udpAddr("10.0.2.8", 62206)
	if !peer.CheckRecvAddress(now, addr2) {
		t.Fatal("should accept packet from server-2")
	}
	peer.UpdateRecv(now, addr2)

	// Receive NHP_AOP from server-3
	addr3 := udpAddr("10.0.3.12", 62206)
	if !peer.CheckRecvAddress(now, addr3) {
		t.Fatal("should accept packet from server-3")
	}
	peer.UpdateRecv(now, addr3)

	// Within hold time, all three should still work
	nowPlus1 := now + int64(time.Second)
	if !peer.CheckRecvAddress(nowPlus1, addr1) {
		t.Fatal("should accept server-1 within hold time")
	}
	if !peer.CheckRecvAddress(nowPlus1, addr2) {
		t.Fatal("should accept server-2 within hold time")
	}
	if !peer.CheckRecvAddress(nowPlus1, addr3) {
		t.Fatal("should accept server-3 within hold time")
	}
}

// --- Concurrent access tests ---

// TestPeerGroupConcurrent_CheckAndUpdate verifies no data races when multiple
// goroutines call CheckRecvAddress and UpdateRecv simultaneously, simulating
// the real scenario where NHP_AOP packets arrive from multiple servers
// concurrently on different packetToMsgRoutine workers.
func TestPeerGroupConcurrent_CheckAndUpdate(t *testing.T) {
	d := &Device{peerMap: make(map[string]Peer)}

	s1 := newTestUdpPeer("10.0.1.5", 62206)
	s2 := newTestUdpPeer("10.0.2.8", 62206)
	s3 := newTestUdpPeer("10.0.3.12", 62206)
	d.AddPeer(s1)
	d.AddPeer(s2)
	d.AddPeer(s3)

	peer := d.LookupPeer(s1.PublicKey())

	addrs := []*net.UDPAddr{
		udpAddr("10.0.1.5", 62206),
		udpAddr("10.0.2.8", 62206),
		udpAddr("10.0.3.12", 62206),
	}

	var wg sync.WaitGroup
	const iterations = 1000

	// Spawn 3 goroutines simulating concurrent packet processing from 3 servers
	for _, addr := range addrs {
		wg.Add(1)
		go func(a *net.UDPAddr) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				now := time.Now().UnixNano()
				peer.CheckRecvAddress(now, a)
				peer.UpdateRecv(now, a)
			}
		}(addr)
	}

	wg.Wait()
}

// TestPeerGroupConcurrent_AddAndCheck verifies no data races when AddPeer
// runs concurrently with CheckRecvAddress, simulating AC reconnection
// (HandleRedispatch) while packets are still being validated.
func TestPeerGroupConcurrent_AddAndCheck(t *testing.T) {
	d := &Device{peerMap: make(map[string]Peer)}

	s1 := newTestUdpPeer("10.0.1.5", 62206)
	s2 := newTestUdpPeer("10.0.2.8", 62206)
	d.AddPeer(s1)
	d.AddPeer(s2)

	peer := d.LookupPeer(s1.PublicKey())

	var wg sync.WaitGroup
	const iterations = 1000

	// Goroutine 1: continuously check/update recv addresses
	wg.Add(1)
	go func() {
		defer wg.Done()
		addr := udpAddr("10.0.1.5", 62206)
		for i := 0; i < iterations; i++ {
			now := time.Now().UnixNano()
			peer.CheckRecvAddress(now, addr)
			peer.UpdateRecv(now, addr)
		}
	}()

	// Goroutine 2: add new members to the group via Device.AddPeer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			p := newTestUdpPeer(fmt.Sprintf("10.0.%d.%d", i/256, i%256), 62206)
			d.AddPeer(p)
		}
	}()

	// Goroutine 3: read-side operations (Name, IsExpired, PublicKey)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			peer.Name()
			peer.IsExpired()
			peer.PublicKeyBase64()
			peer.LastRecvTime()
			peer.RecvAddr()
		}
	}()

	wg.Wait()
}
