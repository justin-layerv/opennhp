package server

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// TestRelayAckRoundTrip_AgentDecryptsAckFromSyntheticDecrypt is the
// architecture spike for the NHP_RLY handler (#2208, P3b). It proves the one
// load-bearing assumption the relay reply mechanism rests on:
//
//	An NHP_ACK built from a *synthetically* decrypted inner knock (the
//	forward.go decryptForwardedKnock pattern) — encrypted via the
//	EncryptedPktCh divert rather than forwardToTransaction — is decryptable by
//	the agent's *original* knock transaction, with the inner counter matching.
//
// This is what lets the server reply to a relay-forwarded knock with an ACK
// that is (a) end-to-end encrypted for the agent [from the inner cipher
// state], (b) correlated to the inner knock counter, yet (c) transported to
// the relay's address (here: captured bytes we hand back to the agent). The
// existing forward_e2e_test.go path replies via NHP_FRT to another *server*,
// so it never exercises an agent-decryptable ACK from a synthetic decrypt —
// this spike does.
//
// If this ever regresses, the NHP_RLY handler's reply path is broken at the
// crypto layer; fix here before touching the handler.
func TestRelayAckRoundTrip_AgentDecryptsAckFromSyntheticDecrypt(t *testing.T) {
	agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)
	// Server mirrors cloud-mode: agent-peer validation disabled, so the inner
	// knock decrypts on the agent's learned pubkey without a pre-registered
	// agent peer — exactly how the relay path will decrypt forwarded knocks.
	serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x22, &core.DeviceOptions{DisableAgentPeerValidation: true})

	serverPk := decodeBase64PubKey(serverDev.PublicKeyBase64())
	agentPk := decodeBase64PubKey(agentDev.PublicKeyBase64())
	serverAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62206}
	// The real browser client IP the relay reports as SourceAddr. Distinct
	// from both the server and any relay address so a leak of the wrong
	// address into the ACK or the (future) pinhole is visible.
	clientSrcAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 44444}

	// Agent must hold the server pubkey to encrypt the knock to it.
	agentDev.AddPeer(&core.UdpPeer{
		PubKeyBase64: serverDev.PublicKeyBase64(),
		Ip:           serverAddr.IP.String(),
		Port:         serverAddr.Port,
		Type:         core.NHP_SERVER,
	})

	// --- 1. Agent encrypts an NHP_KNK as a real transaction, capturing bytes.
	const innerTrxID = uint64(424242)
	respCh := make(chan *core.PacketParserData, 1)
	agentConn := newSpikeConn(agentDev, serverAddr)
	knockBytes, err := json.Marshal(&common.AgentKnockMsg{
		HeaderType:    core.NHP_KNK,
		UserId:        "spike-user",
		AuthServiceId: "spike-asp",
		ResourceId:    "spike-resource",
	})
	if err != nil {
		t.Fatalf("marshal knock: %v", err)
	}
	agentDev.SendMsgToPacket(&core.MsgData{
		ConnData:      agentConn,
		PeerPk:        serverPk,
		HeaderType:    core.NHP_KNK,
		TransactionId: innerTrxID,
		Message:       knockBytes,
		ResponseMsgCh: respCh, // transaction delivers the decrypted ACK here
	})
	encryptedKnock := drainEncryptedPacket(t, agentConn) // the bytes a relay would forward as InnerPacket

	// --- 2. Server synthetic-decrypts the inner knock (forward.go pattern),
	//        stamping ConnData.RemoteAddr with the relay-reported client IP.
	innerPpd := syntheticDecryptKnock(t, serverDev, encryptedKnock, clientSrcAddr)
	if got := base64.StdEncoding.EncodeToString(innerPpd.RemotePubKey); got != base64.StdEncoding.EncodeToString(agentPk) {
		t.Fatalf("inner decrypt RemotePubKey=%s want agent %s", got, base64.StdEncoding.EncodeToString(agentPk))
	}
	if innerPpd.SenderTrxId != innerTrxID {
		t.Fatalf("inner decrypt SenderTrxId=%d want %d", innerPpd.SenderTrxId, innerTrxID)
	}

	// --- 3. Server builds the ACK from innerPpd and diverts the encrypted
	//        bytes via EncryptedPktCh instead of forwardToTransaction.
	ackBytes, err := json.Marshal(&common.ServerKnockAckMsg{
		ErrCode:   common.ErrSuccess.ErrorCode(),
		AgentAddr: clientSrcAddr.String(),
	})
	if err != nil {
		t.Fatalf("marshal ack: %v", err)
	}
	ackMd := makeMsgData(innerPpd, core.NHP_ACK, ackBytes)
	encCh := make(chan *core.MsgAssemblerData, 1)
	ackMd.EncryptedPktCh = encCh
	serverDev.SendMsgToPacket(ackMd)

	var encryptedAck []byte
	select {
	case mad := <-encCh:
		if mad.Error != nil {
			t.Fatalf("server ACK encryption failed: %v", mad.Error)
		}
		encryptedAck = slices.Clone(mad.BasePacket.Content)
		mad.Destroy()
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server ACK encryption")
	}

	// --- 4. Agent routes the ACK bytes (as if returned via the relay) into
	//        its original knock transaction for decryption.
	routeResponseToTransaction(t, agentDev, encryptedAck)

	// --- 5. The agent transaction must decrypt the ACK with matching counter.
	select {
	case serverPpd := <-respCh:
		if serverPpd.Error != nil {
			t.Fatalf("agent failed to decrypt relay ACK: %v", serverPpd.Error)
		}
		if serverPpd.HeaderType != core.NHP_ACK {
			t.Fatalf("agent decrypted header=%d want NHP_ACK", serverPpd.HeaderType)
		}
		if serverPpd.SenderTrxId != innerTrxID {
			t.Fatalf("ACK counter=%d want inner knock counter %d", serverPpd.SenderTrxId, innerTrxID)
		}
		var got common.ServerKnockAckMsg
		if err := json.Unmarshal(serverPpd.BodyMessage, &got); err != nil {
			t.Fatalf("unmarshal decrypted ACK: %v", err)
		}
		if got.AgentAddr != clientSrcAddr.String() {
			t.Fatalf("decrypted ACK AgentAddr=%q want %q", got.AgentAddr, clientSrcAddr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent never received the decrypted relay ACK on its transaction")
	}
}

// newSpikeDevice builds a started core.Device with a deterministic key.
func newSpikeDevice(t *testing.T, deviceType int, keySeed byte, opt *core.DeviceOptions) *core.Device {
	t.Helper()
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i) + keySeed
	}
	dev := core.NewDevice(deviceType, priv, opt)
	if dev == nil {
		t.Fatalf("NewDevice(type=%d) returned nil", deviceType)
	}
	dev.Start()
	t.Cleanup(dev.Stop)
	return dev
}

// newSpikeConn builds a ConnectionData whose SendQueue is drained manually
// (no send loop), mirroring captureEncryptedPacket in forward_e2e_test.go.
func newSpikeConn(dev *core.Device, remote *net.UDPAddr) *core.ConnectionData {
	return &core.ConnectionData{
		Device:           dev,
		LocalAddr:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		RemoteAddr:       remote,
		InitTime:         time.Now().UnixNano(),
		SendQueue:        make(chan *core.Packet, 64),
		RecvQueue:        make(chan *core.Packet, 64),
		BlockSignal:      make(chan struct{}, 1),
		SetTimeoutSignal: make(chan struct{}, 1),
		StopSignal:       make(chan struct{}),
	}
}

// drainEncryptedPacket pulls the freshly-encrypted packet off a capture conn's
// SendQueue and returns a copy of its bytes. The packet is kept (transaction
// requests set KeepAfterSend), so it is not released here.
func drainEncryptedPacket(t *testing.T, conn *core.ConnectionData) []byte {
	t.Helper()
	select {
	case pkt := <-conn.SendQueue:
		if pkt == nil || pkt.Content == nil {
			t.Fatal("drained nil/empty packet")
		}
		return slices.Clone(pkt.Content)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout draining encrypted packet")
		return nil
	}
}

// syntheticDecryptKnock decrypts a captured knock against the server device
// using a synthetic ConnectionData, exactly as forward.go decryptForwardedKnock
// does — the relay-reported source address becomes ConnData.RemoteAddr.
func syntheticDecryptKnock(t *testing.T, dev *core.Device, knock []byte, srcAddr *net.UDPAddr) *core.PacketParserData {
	t.Helper()
	pkt := &core.Packet{Content: knock}
	pd := &core.PacketData{
		BasePacket: pkt,
		ConnData: &core.ConnectionData{
			Device:     dev,
			RemoteAddr: srcAddr,
			InitTime:   time.Now().UnixNano(),
		},
		InitTime: time.Now().UnixNano(),
	}
	ppd, err := dev.PacketToMsg(pd)
	if err != nil {
		t.Fatalf("synthetic decrypt failed: %v", err)
	}
	if ppd == nil || ppd.Error != nil {
		t.Fatalf("synthetic decrypt returned error ppd: %+v", ppd)
	}
	return ppd
}

// routeResponseToTransaction feeds an encrypted transaction-response packet
// into the device's matching local transaction, mirroring the recv routing in
// forward_e2e_test.go's processReceivedPacket.
func routeResponseToTransaction(t *testing.T, dev *core.Device, data []byte) {
	t.Helper()
	pkt := dev.AllocatePoolPacket()
	copy(pkt.Buf[:len(data)], data)
	pkt.Content = pkt.Buf[:len(data)]

	headerType, _, err := dev.RecvPrecheck(pkt)
	if err != nil {
		dev.ReleasePoolPacket(pkt)
		t.Fatalf("RecvPrecheck on relay ACK: %v", err)
	}
	if !dev.IsTransactionResponse(headerType) {
		dev.ReleasePoolPacket(pkt)
		t.Fatalf("relay ACK header=%d is not a transaction response", headerType)
	}
	txID := pkt.Counter()
	tx := dev.FindLocalTransaction(txID)
	if tx == nil {
		dev.ReleasePoolPacket(pkt)
		t.Fatalf("no local transaction for relay ACK counter %d", txID)
	}
	if err := tx.SendPacket(pkt); err != nil {
		t.Fatalf("delivering relay ACK to transaction %d: %v", txID, err)
	}
}
