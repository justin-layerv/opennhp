package core

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPacketToMsgRoutine_InvokesRecvReplayDedupe is the wiring fence for
// the #1457 chokepoint. The cache (endpoints/server/art_replay_cache_test.go)
// and the server hook logic (art_dedupe_test.go) are fenced in isolation;
// this proves the receive pipeline actually CALLS the hook — after
// validatePeer (so the hook sees the AEAD-authenticated RemotePubKey /
// RemoteSendTime and the SenderTrxId) and before the body decrypt — and
// that a hook error drops the packet via the standard error-delivery
// path. A refactor that disconnects the hook from packetToMsgRoutine
// leaves the isolated tests green but fails here.
func TestPacketToMsgRoutine_InvokesRecvReplayDedupe(t *testing.T) {
	silenceGlobalLogger(t)

	acDevice := NewDevice(NHP_AC, validatePeerPrivateKey(1), nil)
	serverDevice := NewDevice(NHP_SERVER, validatePeerPrivateKey(33), nil)
	if acDevice == nil || serverDevice == nil {
		t.Fatal("failed to create AC/server devices")
	}
	acPeer := &UdpPeer{PubKeyBase64: acDevice.PublicKeyBase64(), Ip: "127.0.0.1", Port: 12345, Type: NHP_AC}
	serverPeer := &UdpPeer{PubKeyBase64: serverDevice.PublicKeyBase64(), Ip: "127.0.0.1", Port: 12346, Type: NHP_SERVER}
	serverDevice.AddPeer(acPeer)
	acDevice.AddPeer(serverPeer)

	type seen struct {
		pubkey   []byte
		txid     uint64
		sendTime int64
	}
	var mu sync.Mutex
	var calls []seen
	dropErr := errors.New("dedupe drop sentinel")
	var drop atomic.Bool
	serverDevice.SetRecvReplayDedupe(func(ppd *PacketParserData) error {
		mu.Lock()
		calls = append(calls, seen{append([]byte(nil), ppd.RemotePubKey...), ppd.SenderTrxId, ppd.RemoteSendTime})
		mu.Unlock()
		if drop.Load() {
			return dropErr
		}
		return nil
	})

	serverDevice.Start()
	defer serverDevice.Stop()

	const txid uint64 = 7
	// Build one real ART packet AC → server; replay the same bytes twice.
	acConn := validatePeerConnectionData(acDevice, 12345, 12346)
	mad, err := acDevice.MsgToPacket(&MsgData{ConnData: acConn, PeerPk: serverPeer.PublicKey(), HeaderType: NHP_ART, TransactionId: txid})
	if err != nil {
		t.Fatalf("MsgToPacket failed: %v", err)
	}
	content := append([]byte(nil), mad.BasePacket.Content...)

	// deliver drives one copy of the ART through the async pipeline on a
	// FRESH connection (LastRemoteSendTime == 0, so the per-connection
	// replay gate never trips) and returns the delivered ppd. Isolating
	// the connection makes the hook — not the responder gate — the thing
	// that processes both copies.
	deliver := func() *PacketParserData {
		t.Helper()
		pkt := &Packet{Content: append([]byte(nil), content...), HeaderType: NHP_ART}
		ch := make(chan *PacketParserData, 1)
		serverDevice.RecvPacketToMsg(&PacketData{
			BasePacket:     pkt,
			ConnData:       validatePeerConnectionData(serverDevice, 12346, 12345),
			InitTime:       time.Now().UnixNano(),
			DecryptedMsgCh: ch,
		})
		select {
		case ppd := <-ch:
			return ppd
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for packetToMsgRoutine result")
			return nil
		}
	}

	// First copy: hook returns nil → packet validates, decrypts, and is
	// delivered with no error.
	if ppd := deliver(); ppd.Error != nil {
		t.Fatalf("first ART: unexpected delivery error %v (validatePeer setup wrong?)", ppd.Error)
	}

	// Second copy: hook drops → packet delivered with the sentinel error,
	// proving the hook runs and its error short-circuits delivery.
	drop.Store(true)
	if ppd := deliver(); !errors.Is(ppd.Error, dropErr) {
		t.Fatalf("dropped ART: got %v, want sentinel drop error", ppd.Error)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("hook must be invoked once per delivery; got %d calls", len(calls))
	}
	for i, c := range calls {
		if !bytes.Equal(c.pubkey, acPeer.PublicKey()) {
			t.Errorf("call %d: hook saw RemotePubKey %x, want AC pubkey %x — hook must run AFTER validatePeer populates it", i, c.pubkey, acPeer.PublicKey())
		}
		if c.txid != txid {
			t.Errorf("call %d: hook saw SenderTrxId %d, want %d", i, c.txid, txid)
		}
		if c.sendTime == 0 {
			t.Errorf("call %d: hook saw RemoteSendTime 0 — must be populated by validatePeer before the hook", i)
		}
	}
}

// TestSetRecvReplayDedupe_NilHookSkipped confirms the default (no hook
// installed) leaves the receive path unchanged: a device that never
// calls SetRecvReplayDedupe delivers a valid packet normally. This is
// the contract that keeps agent/db/AC devices — which dedupe elsewhere
// or not at all — unaffected by the #1457 chokepoint.
func TestSetRecvReplayDedupe_NilHookSkipped(t *testing.T) {
	silenceGlobalLogger(t)

	acDevice := NewDevice(NHP_AC, validatePeerPrivateKey(1), nil)
	serverDevice := NewDevice(NHP_SERVER, validatePeerPrivateKey(33), nil)
	if acDevice == nil || serverDevice == nil {
		t.Fatal("failed to create AC/server devices")
	}
	acPeer := &UdpPeer{PubKeyBase64: acDevice.PublicKeyBase64(), Ip: "127.0.0.1", Port: 12345, Type: NHP_AC}
	serverPeer := &UdpPeer{PubKeyBase64: serverDevice.PublicKeyBase64(), Ip: "127.0.0.1", Port: 12346, Type: NHP_SERVER}
	serverDevice.AddPeer(acPeer)
	acDevice.AddPeer(serverPeer)

	// No SetRecvReplayDedupe call — recvReplayDedupeFn stays nil.
	serverDevice.Start()
	defer serverDevice.Stop()

	acConn := validatePeerConnectionData(acDevice, 12345, 12346)
	mad, err := acDevice.MsgToPacket(&MsgData{ConnData: acConn, PeerPk: serverPeer.PublicKey(), HeaderType: NHP_ART, TransactionId: 9})
	if err != nil {
		t.Fatalf("MsgToPacket failed: %v", err)
	}

	ch := make(chan *PacketParserData, 1)
	serverDevice.RecvPacketToMsg(&PacketData{
		BasePacket:     &Packet{Content: append([]byte(nil), mad.BasePacket.Content...), HeaderType: NHP_ART},
		ConnData:       validatePeerConnectionData(serverDevice, 12346, 12345),
		InitTime:       time.Now().UnixNano(),
		DecryptedMsgCh: ch,
	})
	select {
	case ppd := <-ch:
		if ppd.Error != nil {
			t.Fatalf("nil-hook device: ART delivery error %v, want clean delivery", ppd.Error)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for packetToMsgRoutine result")
	}
}
