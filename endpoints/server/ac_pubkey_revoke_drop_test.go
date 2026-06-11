package server

import (
	"container/list"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/core"
)

func newRevokeDropTestServer(t *testing.T) *UdpServer {
	t.Helper()
	return &UdpServer{
		metrics:             metrics.NewPublisherForTest(t),
		device:              core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil),
		acPeerMap:           map[string]*core.UdpPeer{},
		acConnectionMap:     map[string][]*ACConn{},
		remoteConnectionMap: map[string]*UdpConn{},
		connectionsByIP:     map[string]*list.List{},
	}
}

func putRevokeDropConn(s *UdpServer, acID string, seed byte, addr *net.UDPAddr) (*ACConn, *UdpConn) {
	pubkey := testPubkeyB64(seed)
	connData := newClosableConnData(addr)
	acPeer := &core.UdpPeer{
		Hostname:     acID,
		PubKeyBase64: pubkey,
		Type:         core.NHP_AC,
	}
	acConn := &ACConn{
		ConnData: connData,
		ACPeer:   acPeer,
		ACId:     acID,
	}
	udpConn := &UdpConn{
		ConnData:       connData,
		isACConnection: true,
		evictSignal:    make(chan struct{}),
	}
	s.acPeerMap[pubkey] = acPeer
	s.acConnectionMap[acID] = append(s.acConnectionMap[acID], acConn)
	s.remoteConnectionMap[addr.String()] = udpConn
	return acConn, udpConn
}

func TestDropRevokedACPubkeyConnections_DropsOnlyRevokedAndCleansMaps(t *testing.T) {
	const acID = "ac-1535-drop"
	s := newRevokeDropTestServer(t)

	revoked, revokedUDP := putRevokeDropConn(s, acID, 0xA1, &net.UDPAddr{IP: net.ParseIP("10.0.0.11"), Port: 47011})
	legit, legitUDP := putRevokeDropConn(s, acID, 0xB2, &net.UDPAddr{IP: net.ParseIP("10.0.0.12"), Port: 47012})

	// Simulate the cloud-mode dynamic-AC corner where the first AOL
	// was admitted before AC classification and therefore owns a
	// per-IP bucket element. removeConnection must clear it.
	bucket := list.New()
	revokedUDP.perIPElem = bucket.PushBack(revokedUDP)
	s.connectionsByIP[revoked.ConnData.RemoteAddr.IP.String()] = bucket

	dropped := s.dropRevokedACPubkeyConnections(acID, []string{revoked.ACPeer.PubKeyBase64}, "test")
	if dropped != 1 {
		t.Fatalf("dropRevokedACPubkeyConnections dropped %d conns, want 1", dropped)
	}

	conns := s.acConnectionMap[acID]
	if len(conns) != 1 || conns[0] != legit {
		t.Fatalf("acConnectionMap[%s] = %#v, want only legit conn", acID, conns)
	}
	if _, found := s.remoteConnectionMap[revoked.ConnData.RemoteAddr.String()]; found {
		t.Errorf("revoked conn still present in remoteConnectionMap")
	}
	if got := s.remoteConnectionMap[legit.ConnData.RemoteAddr.String()]; got != legitUDP {
		t.Errorf("legit conn remote map entry changed: got %v want %v", got, legitUDP)
	}
	if revokedUDP.perIPElem != nil {
		t.Errorf("revoked conn perIPElem not cleared")
	}
	if _, found := s.connectionsByIP[revoked.ConnData.RemoteAddr.IP.String()]; found {
		t.Errorf("revoked conn IP bucket still present")
	}
	if _, found := s.acPeerMap[revoked.ACPeer.PubKeyBase64]; found {
		t.Errorf("revoked pubkey still present in acPeerMap")
	}
	if _, found := s.acPeerMap[legit.ACPeer.PubKeyBase64]; !found {
		t.Errorf("legit pubkey removed from acPeerMap")
	}
	if !waitForClosed(revoked.ConnData, closeWaitTimeout) {
		t.Fatalf("revoked conn did not close within %s", closeWaitTimeout)
	}
	if legit.ConnData.IsClosed() {
		t.Fatal("legit conn was closed")
	}

	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokedConnDropped]; c != 1 {
		t.Errorf("%s counter=%v, want 1", MetricACPubkeyRevokedConnDropped, c)
	}
}

func TestDropRevokedACPubkeyConnections_Idempotent(t *testing.T) {
	const acID = "ac-1535-idempotent"
	s := newRevokeDropTestServer(t)

	revoked, _ := putRevokeDropConn(s, acID, 0xA3, &net.UDPAddr{IP: net.ParseIP("10.0.0.13"), Port: 47013})
	revokedPubkey := revoked.ACPeer.PubKeyBase64

	if dropped := s.dropRevokedACPubkeyConnections(acID, []string{revokedPubkey}, "test"); dropped != 1 {
		t.Fatalf("first drop count = %d, want 1", dropped)
	}
	if dropped := s.dropRevokedACPubkeyConnections(acID, []string{revokedPubkey}, "test"); dropped != 0 {
		t.Fatalf("second drop count = %d, want 0", dropped)
	}

	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokedConnDropped]; c != 1 {
		t.Errorf("%s counter=%v, want 1 after idempotent rerun", MetricACPubkeyRevokedConnDropped, c)
	}
}

func TestDropRevokedACPubkeyConnections_KeepsPeerWhenSamePubkeyStillLive(t *testing.T) {
	const (
		revokedACID = "ac-1535-shared-a"
		otherACID   = "ac-1535-shared-b"
	)
	s := newRevokeDropTestServer(t)

	revoked, _ := putRevokeDropConn(s, revokedACID, 0xA6, &net.UDPAddr{IP: net.ParseIP("10.0.0.16"), Port: 47016})
	sharedPubkey := revoked.ACPeer.PubKeyBase64
	otherConnData := newClosableConnData(&net.UDPAddr{IP: net.ParseIP("10.0.0.17"), Port: 47017})
	otherPeer := &core.UdpPeer{
		Hostname:     otherACID,
		PubKeyBase64: sharedPubkey,
		Type:         core.NHP_AC,
	}
	otherConn := &ACConn{
		ConnData: otherConnData,
		ACPeer:   otherPeer,
		ACId:     otherACID,
	}
	otherUDP := &UdpConn{
		ConnData:       otherConnData,
		isACConnection: true,
		evictSignal:    make(chan struct{}),
	}
	s.acConnectionMap[otherACID] = []*ACConn{otherConn}
	s.remoteConnectionMap[otherConnData.RemoteAddr.String()] = otherUDP

	if dropped := s.dropRevokedACPubkeyConnections(revokedACID, []string{sharedPubkey}, "test"); dropped != 1 {
		t.Fatalf("dropRevokedACPubkeyConnections dropped %d conns, want 1", dropped)
	}
	if _, found := s.acPeerMap[sharedPubkey]; !found {
		t.Fatalf("shared pubkey was removed from acPeerMap despite another live conn")
	}
	if got := s.remoteConnectionMap[otherConnData.RemoteAddr.String()]; got != otherUDP {
		t.Fatalf("other live conn remote map entry changed: got %v want %v", got, otherUDP)
	}
	if otherConnData.IsClosed() {
		t.Fatal("other live conn sharing pubkey was closed")
	}
}

func TestEnsureACPeerForLiveConn_ReaddsAfterDropWinsBeforeAppend(t *testing.T) {
	const (
		revokedACID = "ac-1535-readd-a"
		otherACID   = "ac-1535-readd-b"
	)
	s := newRevokeDropTestServer(t)

	revoked, _ := putRevokeDropConn(s, revokedACID, 0xAA, &net.UDPAddr{IP: net.ParseIP("10.0.0.31"), Port: 47031})
	sharedPubkey := revoked.ACPeer.PubKeyBase64
	pendingConnData := newClosableConnData(&net.UDPAddr{IP: net.ParseIP("10.0.0.32"), Port: 47032})
	pendingPeer := &core.UdpPeer{
		Hostname:     otherACID,
		PubKeyBase64: sharedPubkey,
		Type:         core.NHP_AC,
	}
	pendingConn := &ACConn{
		ConnData: pendingConnData,
		ACPeer:   pendingPeer,
		ACId:     otherACID,
	}

	if dropped := s.dropRevokedACPubkeyConnections(revokedACID, []string{sharedPubkey}, "test"); dropped != 1 {
		t.Fatalf("dropRevokedACPubkeyConnections dropped %d conns, want 1", dropped)
	}
	if _, found := s.acPeerMap[sharedPubkey]; found {
		t.Fatalf("shared pubkey still present before pending registration append")
	}

	s.acConnectionMapMutex.Lock()
	s.acConnectionMap[otherACID] = []*ACConn{pendingConn}
	s.acConnectionMapMutex.Unlock()

	if !s.ensureACPeerForLiveConn(otherACID, pendingConn) {
		t.Fatal("ensureACPeerForLiveConn returned false for live pending conn")
	}
	if got := s.acPeerMap[sharedPubkey]; got != pendingPeer {
		t.Fatalf("shared pubkey peer = %v, want pending peer %v", got, pendingPeer)
	}
	if pendingConnData.IsClosed() {
		t.Fatal("pending conn was closed")
	}
}

func TestEnsureACPeerForLiveConn_SkipsRemovedConn(t *testing.T) {
	const acID = "ac-1535-readd-removed"
	s := newRevokeDropTestServer(t)
	revoked, _ := putRevokeDropConn(s, acID, 0xAB, &net.UDPAddr{IP: net.ParseIP("10.0.0.33"), Port: 47033})
	removedConn := &ACConn{
		ConnData: newClosableConnData(&net.UDPAddr{IP: net.ParseIP("10.0.0.34"), Port: 47034}),
		ACPeer: &core.UdpPeer{
			Hostname:     acID,
			PubKeyBase64: revoked.ACPeer.PubKeyBase64,
			Type:         core.NHP_AC,
		},
		ACId: acID,
	}

	if dropped := s.dropRevokedACPubkeyConnections(acID, []string{revoked.ACPeer.PubKeyBase64}, "test"); dropped != 1 {
		t.Fatalf("dropRevokedACPubkeyConnections dropped %d conns, want 1", dropped)
	}
	if s.ensureACPeerForLiveConn(acID, removedConn) {
		t.Fatal("ensureACPeerForLiveConn returned true for conn absent from acConnectionMap")
	}
	if _, found := s.acPeerMap[revoked.ACPeer.PubKeyBase64]; found {
		t.Fatalf("removed conn pubkey was re-added to acPeerMap")
	}
}

func TestSweepRevokedACPubkeyConnections_StrictCloudModeDropsLiveConn(t *testing.T) {
	const acID = "ac-1535-sweep"
	s := newRevokeDropTestServer(t)
	revoked, _ := putRevokeDropConn(s, acID, 0xA4, &net.UDPAddr{IP: net.ParseIP("10.0.0.14"), Port: 47014})

	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{
		ACID:           acID,
		Version:        1,
		RevokedPubKeys: []string{revoked.ACPeer.PubKeyBase64},
	})
	s.storage = mem
	s.storageConfig = &StorageConfig{Backend: StorageBackendDynamoDB}
	s.acPubkeyRevokeVerifyRequire = true

	stats := s.sweepRevokedACPubkeyConnections(context.Background(), nil, acPubkeyRevokedConnDropSourceSweep)
	if stats.Skipped {
		t.Fatal("sweep unexpectedly skipped")
	}
	if stats.CheckedACIDs != 1 {
		t.Errorf("CheckedACIDs=%d, want 1", stats.CheckedACIDs)
	}
	if stats.DroppedConns != 1 {
		t.Errorf("DroppedConns=%d, want 1", stats.DroppedConns)
	}
	if stats.AffectedACIDs != 1 {
		t.Errorf("AffectedACIDs=%d, want 1", stats.AffectedACIDs)
	}
	if got := mem.GetCallCount("GetACAssignment"); got != 1 {
		t.Errorf("GetACAssignment call count=%d, want 1", got)
	}
}

func TestSweepRevokedACPubkeyConnections_StorageErrorIncrementsLookupErr(t *testing.T) {
	const acID = "ac-1535-storage-error"
	s := newRevokeDropTestServer(t)
	putRevokeDropConn(s, acID, 0xA7, &net.UDPAddr{IP: net.ParseIP("10.0.0.18"), Port: 47018})

	s.storage = &errStorageACAssignment{
		MemoryStorage: NewMemoryStorage(),
		err:           errors.New("ddb: ProvisionedThroughputExceededException"),
	}
	s.storageConfig = &StorageConfig{Backend: StorageBackendDynamoDB}
	s.acPubkeyRevokeVerifyRequire = true

	stats := s.sweepRevokedACPubkeyConnections(context.Background(), nil, acPubkeyRevokedConnDropSourceSweep)
	if stats.LookupErrors != 1 {
		t.Errorf("LookupErrors=%d, want 1", stats.LookupErrors)
	}
	if stats.DroppedConns != 0 {
		t.Errorf("DroppedConns=%d, want 0 on storage error", stats.DroppedConns)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokedLookupErr]; c != 1 {
		t.Errorf("%s counter=%v, want 1", MetricACPubkeyRevokedLookupErr, c)
	}
}

func TestSweepRevokedACPubkeyConnections_CanceledContextDoesNotEmitLookupErr(t *testing.T) {
	const acID = "ac-1535-canceled"
	s := newRevokeDropTestServer(t)
	putRevokeDropConn(s, acID, 0xA8, &net.UDPAddr{IP: net.ParseIP("10.0.0.19"), Port: 47019})

	s.storage = NewMemoryStorage()
	s.storageConfig = &StorageConfig{Backend: StorageBackendDynamoDB}
	s.acPubkeyRevokeVerifyRequire = true

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stats := s.sweepRevokedACPubkeyConnections(ctx, nil, acPubkeyRevokedConnDropSourceOnDemand)
	if stats.LookupErrors != 0 {
		t.Errorf("LookupErrors=%d, want 0 for caller-canceled sweep", stats.LookupErrors)
	}
	if !stats.Truncated {
		t.Errorf("Truncated=false, want true for caller-canceled sweep")
	}
	if stats.CheckedACIDs != 0 {
		t.Errorf("CheckedACIDs=%d, want 0 when context is canceled before lookup", stats.CheckedACIDs)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokedLookupErr]; c != 0 {
		t.Errorf("%s counter=%v, want 0 for caller cancellation", MetricACPubkeyRevokedLookupErr, c)
	}
}

func TestACPubkeyRevokeSweepRoutine_TickDropsAndStops(t *testing.T) {
	const acID = "ac-1535-routine"
	s := newRevokeDropTestServer(t)
	revoked, _ := putRevokeDropConn(s, acID, 0xA9, &net.UDPAddr{IP: net.ParseIP("10.0.0.20"), Port: 47020})

	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{
		ACID:           acID,
		Version:        1,
		RevokedPubKeys: []string{revoked.ACPeer.PubKeyBase64},
	})
	s.storage = mem
	s.storageConfig = &StorageConfig{Backend: StorageBackendDynamoDB}
	s.acPubkeyRevokeVerifyRequire = true
	s.acPubkeyRevokeSweepInterval = 5 * time.Millisecond
	s.signals.stop = make(chan struct{})

	s.wg.Add(1)
	done := make(chan struct{})
	go func() {
		s.acPubkeyRevokeSweepRoutine()
		close(done)
	}()
	connCount := func() int {
		s.acConnectionMapMutex.RLock()
		defer s.acConnectionMapMutex.RUnlock()
		return len(s.acConnectionMap[acID])
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if connCount() == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if connCount() != 0 {
		t.Fatal("sweep routine did not drop revoked live conn before deadline")
	}

	close(s.signals.stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("acPubkeyRevokeSweepRoutine did not exit within 1s after stop closed")
	}
	s.wg.Wait()
}

func TestSweepRevokedACPubkeyConnections_PermitModeSkipsDestructiveDrop(t *testing.T) {
	const acID = "ac-1535-permit"
	s := newRevokeDropTestServer(t)
	revoked, _ := putRevokeDropConn(s, acID, 0xA5, &net.UDPAddr{IP: net.ParseIP("10.0.0.15"), Port: 47015})

	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{
		ACID:           acID,
		Version:        1,
		RevokedPubKeys: []string{revoked.ACPeer.PubKeyBase64},
	})
	s.storage = mem
	s.storageConfig = &StorageConfig{Backend: StorageBackendDynamoDB}
	s.acPubkeyRevokeVerifyRequire = false

	stats := s.sweepRevokedACPubkeyConnections(context.Background(), nil, acPubkeyRevokedConnDropSourceSweep)
	if !stats.Skipped {
		t.Fatal("permit-mode sweep did not mark itself skipped")
	}
	if len(s.acConnectionMap[acID]) != 1 {
		t.Fatalf("permit-mode sweep removed a conn; len=%d want 1", len(s.acConnectionMap[acID]))
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokedConnDropped]; c != 0 {
		t.Errorf("%s counter=%v, want 0 in permit mode", MetricACPubkeyRevokedConnDropped, c)
	}
}

func TestParseACPubkeyRevokeSweepInterval(t *testing.T) {
	tests := []struct {
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{"", defaultACPubkeyRevokeSweepInterval, false},
		{"0", 0, false},
		{"5", 5 * time.Second, false},
		{"60", time.Minute, false},
		{"4", 0, true},
		{"-1", 0, true},
		{"bogus", 0, true},
	}

	for _, tt := range tests {
		got, err := parseACPubkeyRevokeSweepInterval(tt.raw)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseACPubkeyRevokeSweepInterval(%q) err=nil, want error", tt.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseACPubkeyRevokeSweepInterval(%q) err=%v", tt.raw, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseACPubkeyRevokeSweepInterval(%q)=%s, want %s", tt.raw, got, tt.want)
		}
	}
}
