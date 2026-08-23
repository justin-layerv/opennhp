package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

func TestHandleACOnlineTargetPersistenceFailureDoesNotMutateLivePeer(t *testing.T) {
	const (
		acID   = "ac-session-control-stage"
		bootID = "00112233445566778899aabbccddeeff"
	)
	pubkey := testPubkey(0x61)
	pubkeyB64 := testPubkeyB64(0x61)
	oldAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.10"), Port: 41000}
	newAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.11"), Port: 42000}

	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{ACID: acID, Version: 1})
	storageErr := errors.New("session-control target write failed")
	s := newF5TestServer(t, mem, true)
	s.device = core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	s.listenAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 62206}
	s.localIp = "127.0.0.1"
	s.sessionControlCellID = testSessionControlCellID
	s.sessionControlStore = newAdmissionSessionControlStore(time.Now())
	s.sessionControlStore.(*admissionSessionControlStore).prepareErr = storageErr

	livePeer := &core.UdpPeer{
		Hostname:     acID,
		Ip:           oldAddr.IP.String(),
		Port:         oldAddr.Port,
		PubKeyBase64: pubkeyB64,
		ExpireTime:   0,
		Type:         core.NHP_AC,
	}
	livePeer.UpdateRecv(100, oldAddr)
	liveConn := &ACConn{
		ACPeer:          livePeer,
		ConnData:        &core.ConnectionData{RemoteAddr: oldAddr},
		ACId:            acID,
		BootID:          bootID,
		FlushGeneration: 1,
	}
	testMarkACSessionControlReady(t, liveConn)
	s.acPeerMap[pubkeyB64] = livePeer
	s.acConnectionMap[acID] = []*ACConn{liveConn}

	body, err := json.Marshal(common.ACOnlineMsg{
		ACId:                   acID,
		BootID:                 bootID,
		SessionFlushGeneration: 2,
		SessionFlushComplete:   true,
	})
	if err != nil {
		t.Fatalf("marshal AOL: %v", err)
	}
	ppd := &core.PacketParserData{
		HeaderType:    core.NHP_AOL,
		BodyMessage:   body,
		SenderTrxId:   7,
		LocalInitTime: 200,
		RemotePubKey:  pubkey,
		ConnData:      &core.ConnectionData{RemoteAddr: newAddr},
	}

	if err := s.HandleACOnline(ppd); !errors.Is(err, common.ErrACSessionControlNotReady) {
		t.Fatalf("HandleACOnline() error = %v, want ErrACSessionControlNotReady", err)
	}
	if got := livePeer.RecvAddr(); got == nil || got.String() != oldAddr.String() {
		t.Fatalf("live peer address mutated after rejected AOL: got %v, want %s", got, oldAddr)
	}
	s.acPeerMapMutex.Lock()
	gotPeer := s.acPeerMap[pubkeyB64]
	s.acPeerMapMutex.Unlock()
	if gotPeer != livePeer {
		t.Fatal("rejected AOL replaced the published peer pointer")
	}
	s.acConnectionMapMutex.Lock()
	gotConns := append([]*ACConn(nil), s.acConnectionMap[acID]...)
	s.acConnectionMapMutex.Unlock()
	if len(gotConns) != 1 || gotConns[0] != liveConn || gotConns[0].ACPeer != livePeer {
		t.Fatalf("rejected AOL mutated acConnectionMap: %#v", gotConns)
	}
	if !liveConn.sessionControlAuthorityReady.Load() {
		t.Fatal("PrepareTarget failure revoked the existing ready connection")
	}
}

func TestHandleACOnlineDelayedLowerGenerationDoesNotFenceNewerReadyTarget(t *testing.T) {
	const acID = "ac-session-control-stale"
	pubkey := testPubkey(0x63)
	pubkeyB64 := testPubkeyB64(0x63)
	addr := &net.UDPAddr{IP: net.ParseIP("10.0.3.10"), Port: 45000}
	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{ACID: acID, Version: 1})
	s := newF5TestServer(t, mem, true)
	s.device = core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	s.listenAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 62206}
	s.localIp = "127.0.0.1"
	s.sessionControlCellID = testSessionControlCellID
	s.sessionControlStore = newAdmissionSessionControlStore(time.Now())
	peer := &core.UdpPeer{Hostname: acID, PubKeyBase64: pubkeyB64, Type: core.NHP_AC}
	peer.UpdateRecv(time.Now().UnixNano(), addr)
	current := &ACConn{
		ConnData: &core.ConnectionData{RemoteAddr: addr, LastLocalRecvTime: time.Now().UnixNano()},
		ACPeer:   peer, ACId: acID, BootID: "63636363636363636363636363636363", FlushGeneration: 3,
	}
	if _, err := s.activateACSessionControlTarget(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	testMarkACSessionControlReady(t, current)
	s.acPeerMap[pubkeyB64] = peer
	s.acConnectionMap[acID] = []*ACConn{current}
	body, err := json.Marshal(common.ACOnlineMsg{
		ACId: acID, BootID: "62626262626262626262626262626262", SessionFlushGeneration: 2, SessionFlushComplete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ppd := &core.PacketParserData{
		HeaderType: core.NHP_AOL, BodyMessage: body, SenderTrxId: 9, LocalInitTime: time.Now().UnixNano(),
		RemotePubKey: pubkey, ConnData: &core.ConnectionData{RemoteAddr: addr},
	}
	if err := s.HandleACOnline(ppd); !errors.Is(err, common.ErrACSessionControlNotReady) {
		t.Fatalf("delayed AOL error = %v, want authority reject", err)
	}
	if !current.sessionControlAuthorityReady.Load() || !s.hasLiveACConn(acID) {
		t.Fatalf("delayed lower-generation AOL fenced newer target: ready/live=%t/%t", current.sessionControlAuthorityReady.Load(), s.hasLiveACConn(acID))
	}
}

func TestHandleACOnlinePublishesStagedPeerOnlyAfterAuthorityAdmission(t *testing.T) {
	const (
		acID   = "ac-session-control-stage-success"
		bootID = "102132435465768798a9bacbdcedfe0f"
	)
	pubkey := testPubkey(0x62)
	pubkeyB64 := testPubkeyB64(0x62)
	oldAddr := &net.UDPAddr{IP: net.ParseIP("10.0.2.10"), Port: 43000}
	newAddr := &net.UDPAddr{IP: net.ParseIP("10.0.2.11"), Port: 44000}

	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{ACID: acID, Version: 1})
	s := newF5TestServer(t, mem, true)
	s.device = core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	s.listenAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 62206}
	s.localIp = "127.0.0.1"
	s.sessionControlCellID = testSessionControlCellID
	s.sessionControlStore = newAdmissionSessionControlStore(time.Now())

	livePeer := &core.UdpPeer{
		Hostname:     acID,
		Ip:           oldAddr.IP.String(),
		Port:         oldAddr.Port,
		PubKeyBase64: pubkeyB64,
		ExpireTime:   0,
		Type:         core.NHP_AC,
	}
	livePeer.UpdateRecv(100, oldAddr)
	s.acPeerMap[pubkeyB64] = livePeer

	body, err := json.Marshal(common.ACOnlineMsg{
		ACId:                   acID,
		BootID:                 bootID,
		SessionFlushGeneration: 2,
		SessionFlushComplete:   true,
	})
	if err != nil {
		t.Fatalf("marshal AOL: %v", err)
	}
	ppd := &core.PacketParserData{
		HeaderType:    core.NHP_AOL,
		BodyMessage:   body,
		SenderTrxId:   8,
		LocalInitTime: 200,
		RemotePubKey:  pubkey,
		ConnData:      &core.ConnectionData{RemoteAddr: newAddr},
	}

	if err := s.HandleACOnline(ppd); !errors.Is(err, common.ErrTransactionIdNotFound) {
		t.Fatalf("HandleACOnline() error = %v, want terminal ErrTransactionIdNotFound", err)
	}
	s.acPeerMapMutex.Lock()
	gotPeer := s.acPeerMap[pubkeyB64]
	s.acPeerMapMutex.Unlock()
	if gotPeer == nil || gotPeer == livePeer {
		t.Fatal("successful AOL did not replace the published peer with the staged pointer")
	}
	if got := gotPeer.RecvAddr(); got == nil || got.String() != newAddr.String() {
		t.Fatalf("published staged peer address = %v, want %s", got, newAddr)
	}
	if got := livePeer.RecvAddr(); got == nil || got.String() != oldAddr.String() {
		t.Fatalf("old peer pointer mutated during successful replacement: got %v, want %s", got, oldAddr)
	}
	s.acConnectionMapMutex.Lock()
	gotConns := append([]*ACConn(nil), s.acConnectionMap[acID]...)
	s.acConnectionMapMutex.Unlock()
	if len(gotConns) != 1 || gotConns[0].ACPeer != gotPeer {
		t.Fatalf("admitted ACConn did not carry staged peer: %#v", gotConns)
	}
}
