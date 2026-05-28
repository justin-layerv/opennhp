package core

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// TestShouldCheckRecvAttack_AOPNoLongerExempt is the regression
// fence for issue #1123. The previous implementation skipped the
// per-connection LastRemoteSendTime monotonic check for NHP_AOP,
// which made the responder a no-op replay-protector for AC-side
// AOP processing within an open connection. The fix removes that
// exemption so AOP rides the same gate as every other AC-bound
// message; the cross-connection cousin lives in
// endpoints/ac/aop_replay_cache.go.
func TestShouldCheckRecvAttack_AOPNoLongerExempt(t *testing.T) {
	if !shouldCheckRecvAttack(NHP_AC, NHP_SERVER, NHP_AOP) {
		t.Fatal("NHP_AOP on AC must be subject to the LastRemoteSendTime gate (#1123)")
	}
}

// TestShouldCheckRecvAttack_ARTStillExempt pins the remaining
// exemption: NHP_ART (AC → server response) skips the gate because
// the server-side transaction layer already correlates by
// TransactionId and the AC→server hop occasionally exceeds the
// flood-gate threshold (MinimalRecvIntervalMs in constants.go).
// Tracked for follow-up dedupe in #1457.
func TestShouldCheckRecvAttack_ARTStillExempt(t *testing.T) {
	if shouldCheckRecvAttack(NHP_SERVER, NHP_AC, NHP_ART) {
		t.Fatal("NHP_ART on server must remain exempt from the LastRemoteSendTime gate")
	}
}

// TestShouldCheckRecvAttack_DefaultEnforced sanity-checks that an
// unrelated message type still enforces the gate, so a future
// refactor of shouldCheckRecvAttack cannot silently widen the
// exemption set.
func TestShouldCheckRecvAttack_DefaultEnforced(t *testing.T) {
	if !shouldCheckRecvAttack(NHP_SERVER, NHP_AGENT, NHP_KNK) {
		t.Fatal("non-exempt (deviceType, peerType, msgType) must enforce the gate")
	}
}

// TestShouldCheckFlood_AOPExempt fences the round-7 cr finding for
// issue #1123. The flood gate (`MinimalRecvIntervalMs = 20 ms`)
// must NOT apply to NHP_AOP on AC: the server legitimately emits
// AOPs in tight succession during knock bursts, and applying the
// 20 ms floor would false-flood-block a connection past
// `ThreatCountBeforeBlock`. Replay protection is preserved via
// shouldCheckRecvAttack (still enforced on AOP) plus the
// cross-connection cache in endpoints/ac/aop_replay_cache.go.
func TestShouldCheckFlood_AOPExempt(t *testing.T) {
	if shouldCheckFlood(NHP_AC, NHP_SERVER, NHP_AOP) {
		t.Fatal("NHP_AOP on AC must be exempt from the 20 ms flood gate (#1123 round-7)")
	}
}

// TestShouldCheckFlood_ARTExempt mirrors the existing replay-gate
// exemption on the flood gate so the AC→server hop's legitimate
// latency does not flood-block a connection.
func TestShouldCheckFlood_ARTExempt(t *testing.T) {
	if shouldCheckFlood(NHP_SERVER, NHP_AC, NHP_ART) {
		t.Fatal("NHP_ART on server must remain exempt from the 20 ms flood gate")
	}
}

// TestShouldCheckFlood_DefaultEnforced asserts the flood gate is
// otherwise enforced, so a future refactor of shouldCheckFlood
// cannot silently widen the exemption set.
func TestShouldCheckFlood_DefaultEnforced(t *testing.T) {
	if !shouldCheckFlood(NHP_SERVER, NHP_AGENT, NHP_KNK) {
		t.Fatal("non-exempt (deviceType, peerType, msgType) must enforce the flood gate")
	}
}

type validatePeerFixture struct {
	acPeer        *UdpPeer
	server        *Device
	serverConn    *ConnectionData
	packetContent []byte
	initTime      int64
}

func TestValidatePeerPopulatesRemotePubKey(t *testing.T) {
	fixture := newValidatePeerFixture(t)
	ppd := fixture.parseAndValidate(t)
	defer ppd.Destroy()

	if !bytes.Equal(ppd.RemotePubKey, fixture.acPeer.PublicKey()) {
		t.Fatalf("RemotePubKey mismatch\ngot:  %x\nwant: %x", ppd.RemotePubKey, fixture.acPeer.PublicKey())
	}
}

func TestValidatePeerRemotePubKeySurvivesDestroy(t *testing.T) {
	fixture := newValidatePeerFixture(t)
	ppd := fixture.parseAndValidate(t)
	want := append([]byte(nil), fixture.acPeer.PublicKey()...)

	ppd.Destroy()

	if !bytes.Equal(ppd.RemotePubKey, want) {
		t.Fatalf("RemotePubKey after Destroy mismatch\ngot:  %x\nwant: %x", ppd.RemotePubKey, want)
	}
}

// BenchmarkValidatePeer uses ART so one encrypted packet can be replayed through
// validatePeer without tripping the server-side replay/flood gates.
func BenchmarkValidatePeer(b *testing.B) {
	fixture := newValidatePeerFixture(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ppd := fixture.parseAndValidate(b)
		ppd.Destroy()
	}
}

func newValidatePeerFixture(tb testing.TB) validatePeerFixture {
	tb.Helper()
	silenceGlobalLogger(tb)

	acPrivKey := validatePeerPrivateKey(1)
	serverPrivKey := validatePeerPrivateKey(33)
	acDevice := NewDevice(NHP_AC, acPrivKey, nil)
	if acDevice == nil {
		tb.Fatal("failed to create AC device")
	}
	serverDevice := NewDevice(NHP_SERVER, serverPrivKey, nil)
	if serverDevice == nil {
		tb.Fatal("failed to create server device")
	}

	acPeer := &UdpPeer{
		PubKeyBase64: acDevice.PublicKeyBase64(),
		Ip:           "127.0.0.1",
		Port:         12345,
		Type:         NHP_AC,
	}
	serverPeer := &UdpPeer{
		PubKeyBase64: serverDevice.PublicKeyBase64(),
		Ip:           "127.0.0.1",
		Port:         12346,
		Type:         NHP_SERVER,
	}
	serverDevice.AddPeer(acPeer)
	acDevice.AddPeer(serverPeer)

	acConn := validatePeerConnectionData(acDevice, 12345, 12346)
	mad, err := acDevice.MsgToPacket(&MsgData{
		ConnData:      acConn,
		PeerPk:        serverPeer.PublicKey(),
		HeaderType:    NHP_ART,
		TransactionId: 1,
	})
	if err != nil {
		tb.Fatalf("MsgToPacket failed: %v", err)
	}

	return validatePeerFixture{
		acPeer:        acPeer,
		server:        serverDevice,
		serverConn:    validatePeerConnectionData(serverDevice, 12346, 12345),
		packetContent: append([]byte(nil), mad.BasePacket.Content...),
		initTime:      time.Now().UnixNano(),
	}
}

func (f validatePeerFixture) parseAndValidate(tb testing.TB) *PacketParserData {
	tb.Helper()

	pkt := Packet{
		Content:    f.packetContent,
		HeaderType: NHP_ART,
	}
	pd := PacketData{
		BasePacket: &pkt,
		ConnData:   f.serverConn,
		InitTime:   f.initTime,
	}

	ppd, err := f.server.createPacketParserData(&pd)
	if err != nil {
		tb.Fatalf("createPacketParserData failed: %v", err)
	}
	if err := ppd.validatePeer(); err != nil {
		tb.Fatalf("validatePeer failed: %v", err)
	}

	return ppd
}

func validatePeerPrivateKey(start byte) []byte {
	key := make([]byte, PrivateKeySize)
	for i := range key {
		key[i] = start + byte(i)
	}
	return key
}

func validatePeerConnectionData(device *Device, localPort int, remotePort int) *ConnectionData {
	return &ConnectionData{
		Device:           device,
		LocalAddr:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort},
		RemoteAddr:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
		InitTime:         time.Now().UnixNano(),
		CookieStore:      &CookieStore{},
		SendQueue:        make(chan *Packet, 1),
		RecvQueue:        make(chan *Packet, 1),
		BlockSignal:      make(chan struct{}, 1),
		SetTimeoutSignal: make(chan struct{}, 1),
		StopSignal:       make(chan struct{}),
	}
}
