package server

import (
	"container/list"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// Per-IP UdpConn cap tests for admitNewConnection / removeConnection.
// Run against a minimal UdpServer; the connection routine is not started,
// so cleanup-defer side effects (e.g. evicted conns leaving the global
// map) are not observed here.

func newTestUdpServer(t *testing.T) *UdpServer {
	t.Helper()
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("core.NewDevice returned nil")
	}
	t.Cleanup(func() { device.Stop() })
	return &UdpServer{
		device:              device,
		remoteConnectionMap: make(map[string]*UdpConn),
		connectionsByIP:     make(map[string]*list.List),
		metrics:             metrics.NewPublisherForTest(t),
	}
}

type connKind int

const (
	kindAgent connKind = iota
	kindAC
	kindDB
)

func makeConn(ip string, port int, kind connKind) *UdpConn {
	c := &UdpConn{
		ConnData:    &core.ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP(ip), Port: port}},
		evictSignal: make(chan struct{}),
	}
	switch kind {
	case kindAC:
		c.isACConnection = true
	case kindDB:
		c.isDBConnection = true
	}
	return c
}

// 50 source ports from one IP must allocate at most MaxAgentConnsPerIP.
func TestAdmitNewConnection_AgentCapEnforced(t *testing.T) {
	s := newTestUdpServer(t)
	const ip = "10.0.0.5"
	conns := make([]*UdpConn, 0, 50)
	for port := 30000; port < 30050; port++ {
		c := makeConn(ip, port, kindAgent)
		conns = append(conns, c)
		s.admitNewConnection(c, c.ConnData.RemoteAddr.String())
	}

	bucket := s.connectionsByIP[ip]
	if bucket == nil {
		t.Fatalf("connectionsByIP[%q] missing", ip)
	}
	if got := bucket.Len(); got != MaxAgentConnsPerIP {
		t.Errorf("bucket size: got %d, want %d", got, MaxAgentConnsPerIP)
	}

	wantStart := 50 - MaxAgentConnsPerIP
	i := 0
	for e := bucket.Front(); e != nil; e = e.Next() {
		want := conns[wantStart+i]
		if got := e.Value.(*UdpConn); got != want {
			t.Errorf("bucket[%d]: got port %d, want %d",
				i, got.ConnData.RemoteAddr.Port, want.ConnData.RemoteAddr.Port)
		}
		i++
	}
}

func TestAdmitNewConnection_EvictsOldestFirst(t *testing.T) {
	s := newTestUdpServer(t)
	const ip = "10.0.0.6"
	first := makeConn(ip, 40000, kindAgent)
	s.admitNewConnection(first, first.ConnData.RemoteAddr.String())

	for port := 40001; port < 40000+MaxAgentConnsPerIP; port++ {
		c := makeConn(ip, port, kindAgent)
		s.admitNewConnection(c, c.ConnData.RemoteAddr.String())
	}

	overflow := makeConn(ip, 40000+MaxAgentConnsPerIP, kindAgent)
	s.admitNewConnection(overflow, overflow.ConnData.RemoteAddr.String())

	select {
	case <-first.evictSignal:
	default:
		t.Errorf("evictSignal not closed on oldest conn")
	}
	if first.perIPElem != nil {
		t.Errorf("perIPElem on evicted conn not cleared (would leak a list element)")
	}

	// The other conns survive — pin that we evicted *only* the head.
	for port := 40001; port < 40000+MaxAgentConnsPerIP; port++ {
		_, present := s.remoteConnectionMap[(&net.UDPAddr{IP: net.ParseIP(ip), Port: port}).String()]
		if !present {
			t.Errorf("non-oldest conn at port %d was removed unexpectedly", port)
		}
	}
}

func TestAdmitNewConnection_ACBypassesCap(t *testing.T) {
	s := newTestUdpServer(t)
	const ip = "10.0.0.7"
	for i := 0; i < MaxAgentConnsPerIP+5; i++ {
		c := makeConn(ip, 50000+i, kindAC)
		s.admitNewConnection(c, c.ConnData.RemoteAddr.String())
	}
	if _, present := s.connectionsByIP[ip]; present {
		t.Errorf("AC conns leaked into connectionsByIP")
	}
	if got := len(s.remoteConnectionMap); got != MaxAgentConnsPerIP+5 {
		t.Errorf("remoteConnectionMap size: got %d, want %d", got, MaxAgentConnsPerIP+5)
	}
}

func TestAdmitNewConnection_DBBypassesCap(t *testing.T) {
	s := newTestUdpServer(t)
	const ip = "10.0.0.8"
	for i := 0; i < MaxAgentConnsPerIP+5; i++ {
		c := makeConn(ip, 60000+i, kindDB)
		s.admitNewConnection(c, c.ConnData.RemoteAddr.String())
	}
	if _, present := s.connectionsByIP[ip]; present {
		t.Errorf("DB conns leaked into connectionsByIP")
	}
}

// 32 conns from 2 IPs (16 each) admit cleanly: cap is per-IP, not global.
func TestAdmitNewConnection_DistinctIPsIndependent(t *testing.T) {
	s := newTestUdpServer(t)
	for _, ip := range []string{"10.0.0.10", "10.0.0.11"} {
		for i := 0; i < MaxAgentConnsPerIP; i++ {
			c := makeConn(ip, 30000+i, kindAgent)
			s.admitNewConnection(c, c.ConnData.RemoteAddr.String())
		}
	}
	for _, ip := range []string{"10.0.0.10", "10.0.0.11"} {
		bucket := s.connectionsByIP[ip]
		if bucket == nil {
			t.Errorf("missing bucket for %s", ip)
			continue
		}
		// All survive: nothing was evicted.
		for e := bucket.Front(); e != nil; e = e.Next() {
			c := e.Value.(*UdpConn)
			select {
			case <-c.evictSignal:
				t.Errorf("conn %s evicted but should not have been", c.ConnData.RemoteAddr)
			default:
			}
		}
	}
}

func TestRemoveConnection_DropsBucketWhenEmpty(t *testing.T) {
	s := newTestUdpServer(t)
	const ip = "10.0.0.12"
	c := makeConn(ip, 30000, kindAgent)
	addrStr := c.ConnData.RemoteAddr.String()
	s.admitNewConnection(c, addrStr)
	if _, present := s.connectionsByIP[ip]; !present {
		t.Fatalf("bucket should exist after admit")
	}

	s.removeConnection(c, addrStr)

	if _, present := s.connectionsByIP[ip]; present {
		t.Errorf("bucket should be dropped after last conn removed")
	}
	if _, present := s.remoteConnectionMap[addrStr]; present {
		t.Errorf("remoteConnectionMap entry should be cleared")
	}
	if c.perIPElem != nil {
		t.Errorf("perIPElem should be nil after removal")
	}
}

// removeConnection on a conn the eviction path already pulled must be
// safe — pinned because admit clears perIPElem, then the cleanup defer
// runs and would double-pop without the nil guard.
func TestRemoveConnection_AfterEvictionIsNoOpForBucket(t *testing.T) {
	s := newTestUdpServer(t)
	const ip = "10.0.0.13"
	first := makeConn(ip, 30000, kindAgent)
	s.admitNewConnection(first, first.ConnData.RemoteAddr.String())
	for port := 30001; port < 30000+MaxAgentConnsPerIP; port++ {
		c := makeConn(ip, port, kindAgent)
		s.admitNewConnection(c, c.ConnData.RemoteAddr.String())
	}
	overflow := makeConn(ip, 30000+MaxAgentConnsPerIP, kindAgent)
	s.admitNewConnection(overflow, overflow.ConnData.RemoteAddr.String())

	if first.perIPElem != nil {
		t.Errorf("evictee perIPElem not cleared by admit path")
	}

	bucketLenBefore := s.connectionsByIP[ip].Len()
	s.removeConnection(first, first.ConnData.RemoteAddr.String())
	if got := s.connectionsByIP[ip].Len(); got != bucketLenBefore {
		t.Errorf("bucket length after removeConnection on evictee: got %d, want %d (no-op)",
			got, bucketLenBefore)
	}
	if _, present := s.remoteConnectionMap[first.ConnData.RemoteAddr.String()]; present {
		t.Errorf("evictee not removed from remoteConnectionMap")
	}
}

// Two clients behind one NAT keep their own (IP, port) reply tuples
// after eviction — pins option-A reply-path correctness against any
// future drift back toward IP-only keying.
func TestAdmitNewConnection_ReplyAddrPreservedAfterEviction(t *testing.T) {
	s := newTestUdpServer(t)
	const ip = "10.0.0.14"
	a := makeConn(ip, 30000, kindAgent)
	b := makeConn(ip, 30001, kindAgent)
	s.admitNewConnection(a, a.ConnData.RemoteAddr.String())
	s.admitNewConnection(b, b.ConnData.RemoteAddr.String())

	for i := 0; i < MaxAgentConnsPerIP-2; i++ {
		c := makeConn(ip, 31000+i, kindAgent)
		s.admitNewConnection(c, c.ConnData.RemoteAddr.String())
	}
	push := makeConn(ip, 32000, kindAgent)
	s.admitNewConnection(push, push.ConnData.RemoteAddr.String())

	select {
	case <-a.evictSignal:
	default:
		t.Fatalf("oldest (A) should have been evicted")
	}

	if b.ConnData.RemoteAddr.Port != 30001 {
		t.Errorf("B's reply port mutated: got %d, want 30001", b.ConnData.RemoteAddr.Port)
	}
	if push.ConnData.RemoteAddr.Port != 32000 {
		t.Errorf("pusher's reply port mutated: got %d, want 32000", push.ConnData.RemoteAddr.Port)
	}
	if got := s.remoteConnectionMap[b.ConnData.RemoteAddr.String()]; got != b {
		t.Errorf("remoteConnectionMap[B] no longer resolves to B (cross-talk)")
	}
}

// AC admission from an IP that's already at the agent cap must not
// trigger eviction — AC bypasses the bucket entirely.
func TestAdmitNewConnection_ACAdmittedWhenAgentBucketFull(t *testing.T) {
	s := newTestUdpServer(t)
	const ip = "10.0.0.15"
	for i := 0; i < MaxAgentConnsPerIP; i++ {
		c := makeConn(ip, 30000+i, kindAgent)
		s.admitNewConnection(c, c.ConnData.RemoteAddr.String())
	}
	ac := makeConn(ip, 40000, kindAC)
	s.admitNewConnection(ac, ac.ConnData.RemoteAddr.String())

	if _, present := s.remoteConnectionMap[ac.ConnData.RemoteAddr.String()]; !present {
		t.Errorf("AC conn missing from remoteConnectionMap")
	}
	// No agent conn should have been evicted.
	for i := 0; i < MaxAgentConnsPerIP; i++ {
		port := 30000 + i
		addr := (&net.UDPAddr{IP: net.ParseIP(ip), Port: port}).String()
		if _, present := s.remoteConnectionMap[addr]; !present {
			t.Errorf("agent conn at port %d evicted by AC admission", port)
		}
	}
}

// Concurrent admits from one IP must converge on a bucket of size
// MaxAgentConnsPerIP without panic or double-close, and exactly
// total - cap evictSignals must be closed.
func TestAdmitNewConnection_ConcurrentSameIP(t *testing.T) {
	s := newTestUdpServer(t)
	const ip = "10.0.0.16"
	const total = 200

	conns := make([]*UdpConn, total)
	for i := range conns {
		conns[i] = makeConn(ip, 30000+i, kindAgent)
	}

	var wg sync.WaitGroup
	wg.Add(total)
	for i := range conns {
		go func(i int) {
			defer wg.Done()
			s.admitNewConnection(conns[i], conns[i].ConnData.RemoteAddr.String())
		}(i)
	}
	wg.Wait()

	if got := s.connectionsByIP[ip].Len(); got != MaxAgentConnsPerIP {
		t.Errorf("bucket size: got %d, want %d", got, MaxAgentConnsPerIP)
	}

	// The non-blocking select-after-Wait is deterministic only because
	// eviction happens synchronously under remoteConnectionMapMutex
	// inside admitNewConnection (the close(evictSignal) call is on the
	// same goroutine and the same mutex acquisition as the bucket
	// pop). If admit ever moves to async eviction, this assertion
	// will undercount and the test must be reshaped.
	closed := 0
	for _, c := range conns {
		select {
		case <-c.evictSignal:
			closed++
		default:
		}
	}
	if want := total - MaxAgentConnsPerIP; closed != want {
		t.Errorf("closed evictSignals: got %d, want %d", closed, want)
	}
}

// Defensive-coverage test for removeConnection's pointer-equality
// guard. The current production receive loop's addrStr lookup
// (recvPacketRoutine) happens before the admit decision, so a real
// inbound packet at an evictee's addrStr is forwarded to the still-
// live evictee — the new-admit-at-same-addrStr path the guard
// protects against doesn't fire from recvPacketRoutine today. This
// test directly drives the race so a future code path that creates
// an admit at a reused addrStr (or a refactor that changes the
// lookup-then-admit ordering) won't silently orphan the new conn.
//
// The eviction is driven through admitNewConnection (cap overflow)
// rather than poking internals so the test stays meaningful if admit's
// bookkeeping changes.
func TestRemoveConnection_AddrStrReuseDoesNotOrphanNewConn(t *testing.T) {
	s := newTestUdpServer(t)
	const ip = "10.0.0.50"
	const port = 30000
	addrStr := (&net.UDPAddr{IP: net.ParseIP(ip), Port: port}).String()

	// Admit `old` first so it's the FIFO head, then fill the bucket
	// with conns at distinct ports. A subsequent admit at any new
	// port from the same IP will evict `old` (oldest by admit time).
	old := makeConn(ip, port, kindAgent)
	s.admitNewConnection(old, addrStr)
	for i := 1; i < MaxAgentConnsPerIP; i++ {
		c := makeConn(ip, port+i, kindAgent)
		s.admitNewConnection(c, c.ConnData.RemoteAddr.String())
	}
	overflow := makeConn(ip, port+MaxAgentConnsPerIP, kindAgent)
	s.admitNewConnection(overflow, overflow.ConnData.RemoteAddr.String())

	select {
	case <-old.evictSignal:
	default:
		t.Fatalf("old conn should have been evicted")
	}

	// `old`'s cleanup defer hasn't run yet (we're not running its
	// routine). A fresh conn appears at the same IP:port (CGNAT
	// reuse) and is admitted, replacing old's remoteConnectionMap
	// entry.
	fresh := makeConn(ip, port, kindAgent)
	s.admitNewConnection(fresh, addrStr)

	// Now `old`'s cleanup defer fires.
	s.removeConnection(old, addrStr)

	got := s.remoteConnectionMap[addrStr]
	if got != fresh {
		t.Errorf("remoteConnectionMap[%s] = %v, want %v (new conn was orphaned)",
			addrStr, got, fresh)
	}
}

// Spoofed AC/DB header from an IP that doesn't match any configured
// AC/DB peer must NOT bypass the per-IP cap. Without the IP gate, an
// attacker setting NHP_AOL/NHP_DOL on rotated-port packets would
// inherit the AC/DB cleanup behavior and cap bypass — defeating the
// fix.
func TestIsKnownPeerIP_GatesACDBClassification(t *testing.T) {
	s := newTestUdpServer(t)
	s.acPeerMap = make(map[string]*core.UdpPeer)
	s.dbPeerMap = make(map[string]*core.UdpPeer)

	staticACPeer := &core.UdpPeer{
		Ip:           "10.0.0.30",
		Port:         62206,
		PubKeyBase64: "YWN0ZXN0",
		ExpireTime:   2147483647,
	}
	staticACPeer.Type = core.NHP_AC
	s.acPeerMap[staticACPeer.PubKeyBase64] = staticACPeer

	// Hostname-configured AC peer whose recv address has been observed
	// (covers the post-bootstrap recovery path: cap gate sees the AC
	// once recvAddr populates even if Ip is empty).
	recvSeenACPeer := &core.UdpPeer{
		PubKeyBase64: "YWN0ZXN0Mg==",
		Hostname:     "ac.example.com",
		Port:         62206,
		ExpireTime:   2147483647,
	}
	recvSeenACPeer.Type = core.NHP_AC
	recvSeenACPeer.UpdateRecv(0, &net.UDPAddr{IP: net.ParseIP("10.0.0.31"), Port: 50001})
	s.acPeerMap[recvSeenACPeer.PubKeyBase64] = recvSeenACPeer

	// Hostname-configured AC peer whose Hostname has been resolved
	// (covers the gate's primaryResolvedIp branch — DNS resolved before
	// any recv arrived).
	resolvedACPeer := &core.UdpPeer{
		PubKeyBase64: "YWN0ZXN0Mw==",
		Hostname:     "ac2.example.com",
		Port:         62206,
		ExpireTime:   2147483647,
		LookupHostFunc: func(host string) ([]string, error) {
			return []string{"10.0.0.32"}, nil
		},
	}
	resolvedACPeer.Type = core.NHP_AC
	_ = resolvedACPeer.ResolveHost()
	s.acPeerMap[resolvedACPeer.PubKeyBase64] = resolvedACPeer

	staticDBPeer := &core.UdpPeer{
		Ip:           "10.0.0.40",
		Port:         62206,
		PubKeyBase64: "ZGJ0ZXN0",
		ExpireTime:   2147483647,
	}
	staticDBPeer.Type = core.NHP_DB
	s.dbPeerMap[staticDBPeer.PubKeyBase64] = staticDBPeer

	tests := []struct {
		name string
		fn   func(string) bool
		ip   string
		want bool
	}{
		{"AC peer matched on static Ip", s.isKnownACPeerIP, "10.0.0.30", true},
		{"AC peer matched on recvAddr.IP", s.isKnownACPeerIP, "10.0.0.31", true},
		{"AC peer matched on primaryResolvedIp", s.isKnownACPeerIP, "10.0.0.32", true},
		{"AC peer not matched (random IP)", s.isKnownACPeerIP, "10.0.0.99", false},
		{"DB peer matched on static Ip", s.isKnownDBPeerIP, "10.0.0.40", true},
		{"DB peer not matched (AC IP)", s.isKnownDBPeerIP, "10.0.0.30", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fn(tt.ip); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}

	// Empty-map case (no peers registered): both helpers return false
	// for any IP. Done as a separate fixture-construction so we don't
	// pollute the populated server's maps.
	t.Run("empty AC map returns false", func(t *testing.T) {
		s2 := newTestUdpServer(t)
		s2.acPeerMap = map[string]*core.UdpPeer{}
		if s2.isKnownACPeerIP("10.0.0.30") {
			t.Errorf("expected false for empty acPeerMap")
		}
	})
}

// Integration test: spin up the connection routine and verify that
// closing evictSignal causes it to exit AND its defer removes the
// global-map entry. Pins the end-to-end teardown chain that the unit
// tests above stub out.
func TestConnectionRoutine_ExitsOnEvictSignal(t *testing.T) {
	s := newTestUdpServer(t)
	s.signals.stop = make(chan struct{})
	s.acConnectionMap = make(map[string][]*ACConn)
	s.dbConnectionMap = make(map[string]*DBConn)

	const ip = "10.0.0.20"
	conn := makeConn(ip, 30000, kindAgent)
	conn.ConnData.InitTime = time.Now().UnixNano()
	conn.ConnData.LastLocalRecvTime = conn.ConnData.InitTime
	conn.ConnData.Device = s.device
	conn.ConnData.LocalAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	conn.ConnData.CookieStore = &core.CookieStore{}
	conn.ConnData.RemoteTransactionMap = make(map[uint64]*core.RemoteTransaction)
	conn.ConnData.TimeoutMs = DefaultAgentConnectionTimeoutMs
	conn.ConnData.SendQueue = make(chan *core.Packet, PacketQueueSizePerConnection)
	conn.ConnData.RecvQueue = make(chan *core.Packet, PacketQueueSizePerConnection)
	conn.ConnData.BlockSignal = make(chan struct{})
	conn.ConnData.SetTimeoutSignal = make(chan struct{})
	conn.ConnData.StopSignal = make(chan struct{})

	addrStr := conn.ConnData.RemoteAddr.String()
	s.admitNewConnection(conn, addrStr)

	s.wg.Add(1)
	go s.connectionRoutine(conn)

	// Force eviction by admitting MaxAgentConnsPerIP more conns from
	// the same IP — the first overflowing admit closes conn.evictSignal.
	for i := 1; i <= MaxAgentConnsPerIP; i++ {
		c := makeConn(ip, 30000+i, kindAgent)
		s.admitNewConnection(c, c.ConnData.RemoteAddr.String())
	}

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("connection routine did not exit within 2s after eviction")
	}

	s.remoteConnectionMapMutex.Lock()
	_, present := s.remoteConnectionMap[addrStr]
	s.remoteConnectionMapMutex.Unlock()
	if present {
		t.Errorf("evicted conn not removed from remoteConnectionMap by cleanup defer")
	}
}

// admitNewConnection must panic when evictSignal is nil — silent
// disablement of eviction (select on nil never fires) would leak
// conns out of the per-IP cap. Pinned because future UdpConn literals
// might forget the field.
func TestAdmitNewConnection_PanicsOnNilEvictSignal(t *testing.T) {
	s := newTestUdpServer(t)
	conn := &UdpConn{
		ConnData: &core.ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.60"), Port: 30000}},
		// evictSignal intentionally nil
	}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic on nil evictSignal, got none")
		}
	}()
	s.admitNewConnection(conn, conn.ConnData.RemoteAddr.String())
}

// admitNewConnection dereferences conn.ConnData.RemoteAddr.IP; a nil
// here would be a programming-bug class same as nil evictSignal.
// Both should fail loudly at admit rather than later.
func TestAdmitNewConnection_PanicsOnNilRemoteAddr(t *testing.T) {
	s := newTestUdpServer(t)
	conn := &UdpConn{
		ConnData:    &core.ConnectionData{}, // RemoteAddr nil
		evictSignal: make(chan struct{}),
	}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic on nil RemoteAddr, got none")
		}
	}()
	s.admitNewConnection(conn, "10.0.0.0:0")
}

// connectionsByIP must not grow unboundedly across long admit/evict/
// remove churn cycles. Pin because the bucket-empty-delete branch in
// removeConnection is the only thing keeping distinct-IP keys from
// accumulating.
func TestConnectionsByIP_NoLeakUnderChurn(t *testing.T) {
	s := newTestUdpServer(t)
	for cycle := 0; cycle < 100; cycle++ {
		ip := fmt.Sprintf("10.1.%d.%d", cycle/256, cycle%256)
		c := makeConn(ip, 30000, kindAgent)
		addrStr := c.ConnData.RemoteAddr.String()
		s.admitNewConnection(c, addrStr)
		s.removeConnection(c, addrStr)
	}
	if got := len(s.connectionsByIP); got != 0 {
		t.Errorf("connectionsByIP leaked %d buckets across 100 churn cycles", got)
	}
	if got := len(s.remoteConnectionMap); got != 0 {
		t.Errorf("remoteConnectionMap leaked %d entries", got)
	}
}

func TestAdmitNewConnection_EmitsEvictionMetric(t *testing.T) {
	s := newTestUdpServer(t)
	const ip = "10.0.0.17"
	for i := 0; i < MaxAgentConnsPerIP; i++ {
		c := makeConn(ip, 30000+i, kindAgent)
		s.admitNewConnection(c, c.ConnData.RemoteAddr.String())
	}
	s.admitNewConnection(makeConn(ip, 40000, kindAgent), (&net.UDPAddr{IP: net.ParseIP(ip), Port: 40000}).String())

	counters, _ := s.metrics.CountersForTest(t)
	if counters[MetricAgentConnPerIPEvictions] != 1 {
		t.Errorf("MetricAgentConnPerIPEvictions: got %v, want 1",
			counters[MetricAgentConnPerIPEvictions])
	}
}
