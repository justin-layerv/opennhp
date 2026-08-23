package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

const testRelayRequestID = "AQEBAQEBAQEBAQEBAQEBAQ"

func TestRelayContextHelpersRejectPreCanceledBeforeWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	socket := &recordingUDPWriteSocket{writeN: -1}
	s := &UdpServer{udpWriteSocket: socket}

	if _, err := s.buildRelayInnerReplyContext(ctx, nil, core.NHP_ACK, []byte(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("buildRelayInnerReplyContext error = %v, want context canceled", err)
	}
	if err := s.sendRelayReturnContext(ctx, nil, testRelayRequestID, []byte("inner")); !errors.Is(err, context.Canceled) {
		t.Fatalf("sendRelayReturnContext error = %v, want context canceled", err)
	}
	_, writes := socket.snapshot()
	if writes != 0 {
		t.Fatalf("pre-canceled relay response performed %d physical writes", writes)
	}
}

func TestSendRelayReturnContextClassifiesEncodeFailure(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("create server device")
	}
	s := &UdpServer{device: device, udpWriteSocket: &recordingUDPWriteSocket{writeN: -1}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := s.sendRelayReturnContext(ctx, &core.PacketParserData{}, testRelayRequestID, []byte("inner"))
	if !errors.Is(err, errRelayReturnEncode) {
		t.Fatalf("sendRelayReturnContext error = %v, want encode classification", err)
	}
	_, writes := s.udpWriteSocket.(*recordingUDPWriteSocket).snapshot()
	if writes != 0 {
		t.Fatalf("encode failure performed %d physical writes", writes)
	}
}

func TestConsumeEncryptedPacketDestroysErrorResult(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, bytes.Repeat([]byte{0x44}, 32), nil)
	device.Start()
	t.Cleanup(device.Stop)
	encCh := make(chan *core.MsgAssemblerData, 1)
	device.SendMsgToPacket(&core.MsgData{
		HeaderType:     core.NHP_ACK,
		PeerPk:         []byte{1},
		Message:        []byte(`{}`),
		ExternalPacket: device.AllocateRelayPacket(),
		EncryptedPktCh: encCh,
	})
	var mad *core.MsgAssemblerData
	select {
	case mad = <-encCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for forced encryption error")
	}
	if mad == nil || mad.Error == nil {
		t.Fatalf("forced encryption result = %#v, want non-nil MAD error", mad)
	}
	if _, err := core.ConsumeEncryptedPacket(mad); err == nil {
		t.Fatal("ConsumeEncryptedPacket accepted a forced encryption error")
	}
	if mad.BasePacket.Content != nil {
		t.Fatal("error MAD retained its pooled relay packet after consumption")
	}
}

// ============================================================================
// Pure validation helpers — the relay's security boundary
// ============================================================================

// TestValidateRelaySourceAddrSyntactic fences the SHAPE-only validator applied to
// every forwarded inner type (the synthetic decrypt address must be well-formed
// before the inner type is known). It deliberately does NOT assert routable/public:
// a private/loopback/CGNAT source is syntactically VALID here and must be ACCEPTED
// — the registration path (OTP/REG) relies on that (same-host dev/smoke relays),
// and the stricter routable-public gate is applied only in the knock dispatch arm
// (inline isRoutablePublicIP, covered by TestIsRoutablePublicIP + the end-to-end
// TestHandleRelayForward_PrivateSource_* cases). So the non-routable rows below
// EXPECT acceptance, not rejection.
func TestValidateRelaySourceAddrSyntactic(t *testing.T) {
	cases := []struct {
		name    string
		addr    *common.NetAddress
		wantErr string // substring; "" means accept
	}{
		{"nil", nil, "missing source address"},
		{"zero port", &common.NetAddress{Ip: "203.0.113.7", Port: 0}, "invalid source port"},
		{"negative port", &common.NetAddress{Ip: "203.0.113.7", Port: -1}, "invalid source port"},
		{"port too high", &common.NetAddress{Ip: "203.0.113.7", Port: 70000}, "invalid source port"},
		{"unparseable ip", &common.NetAddress{Ip: "not-an-ip", Port: 443}, "unparseable source ip"},
		// Non-routable but syntactically valid → ACCEPTED (syntactic check does not
		// judge routability; the knock arm does that separately).
		{"private ip accepted (syntactic only)", &common.NetAddress{Ip: "192.168.1.10", Port: 443}, ""},
		{"loopback accepted (syntactic only)", &common.NetAddress{Ip: "127.0.0.1", Port: 443}, ""},
		{"cgnat accepted (syntactic only)", &common.NetAddress{Ip: "100.64.0.1", Port: 443}, ""},
		{"public v4", &common.NetAddress{Ip: "203.0.113.7", Port: 44444}, ""},
		{"public v6", &common.NetAddress{Ip: "2606:4700:4700::1111", Port: 443}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateRelaySourceAddrSyntactic(tc.addr)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got == nil || got.IP == nil {
					t.Fatalf("accepted addr but got nil UDPAddr")
				}
				if got.Port != tc.addr.Port {
					t.Errorf("port = %d, want %d", got.Port, tc.addr.Port)
				}
				if got.IP.String() != net.ParseIP(tc.addr.Ip).String() {
					t.Errorf("ip = %s, want %s", got.IP, tc.addr.Ip)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil (addr accepted as %v)", tc.wantErr, got)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestIsRoutablePublicIP(t *testing.T) {
	public := []string{"203.0.113.7", "8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.1", "2606:4700:4700::1111"}
	nonRoutable := []string{
		"0.0.0.0", "127.0.0.1", "::1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
		"169.254.1.1", "224.0.0.1", "ff02::1", "fe80::1", "fc00::1",
		"100.64.0.1", "100.100.50.50", "100.127.255.255",
	}
	for _, ipStr := range public {
		if ip := net.ParseIP(ipStr); !isRoutablePublicIP(ip) {
			t.Errorf("isRoutablePublicIP(%s) = false, want true (public)", ipStr)
		}
	}
	for _, ipStr := range nonRoutable {
		if ip := net.ParseIP(ipStr); isRoutablePublicIP(ip) {
			t.Errorf("isRoutablePublicIP(%s) = true, want false (non-routable)", ipStr)
		}
	}
	if isRoutablePublicIP(nil) {
		t.Error("isRoutablePublicIP(nil) = true, want false")
	}
}

func TestDecodeRelayInnerPacket(t *testing.T) {
	validInner := base64.StdEncoding.EncodeToString(make([]byte, 64)) // 64 >= min, <= max

	cases := []struct {
		name    string
		in      string
		wantErr string
	}{
		{"empty", "", "empty inner packet"},
		{"oversize base64", strings.Repeat("A", relayInnerMaxBase64Len+4), "base64 too large"},
		{"invalid base64", "!!!! not base64 !!!!", "base64 decode"},
		{"too short", base64.StdEncoding.EncodeToString(make([]byte, 8)), "too short"},
		{"valid", validInner, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeRelayInnerPacket(tc.in)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(got) != 64 {
					t.Errorf("decoded len = %d, want 64", len(got))
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// ============================================================================
// decryptRelayInnerKnock — the inner knock is attributed to the relay-reported
// client IP, never the relay
// ============================================================================

func TestDecryptRelayInnerKnock_StampsClientSourceAddr(t *testing.T) {
	serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x22, &core.DeviceOptions{DisableAgentPeerValidation: true})
	agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)
	serverPk := decodeBase64PubKey(serverDev.PublicKeyBase64())
	agentPk := agentDev.PublicKeyBase64()

	innerKnock := encryptInnerForRelay(t, agentDev, serverPk, core.NHP_KNK, 1234, &common.AgentKnockMsg{
		HeaderType: core.NHP_KNK, UserId: "u", AuthServiceId: "asp", ResourceId: "res",
	})

	clientAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 44444}
	s := &UdpServer{device: serverDev}

	receivedAtNanos := time.Now().UnixNano()
	innerPpd, cookie, conn, err := s.decryptRelayInnerKnock(innerKnock, clientAddr, receivedAtNanos)
	if conn != nil {
		defer conn.Close()
	}
	if err != nil {
		t.Fatalf("decryptRelayInnerKnock: %v", err)
	}
	if len(cookie) != 0 {
		t.Fatal("normal knock unexpectedly produced overload cookie")
	}
	if innerPpd.ConnData.RemoteAddr.String() != clientAddr.String() {
		t.Errorf("inner ConnData.RemoteAddr = %s, want client %s (the AC pinhole source must be the relay-reported client, never the relay)",
			innerPpd.ConnData.RemoteAddr, clientAddr)
	}
	if got := base64.StdEncoding.EncodeToString(innerPpd.RemotePubKey); got != agentPk {
		t.Errorf("inner RemotePubKey = %s, want agent %s", got, agentPk)
	}
	if innerPpd.SenderTrxId != 1234 {
		t.Errorf("inner SenderTrxId = %d, want 1234", innerPpd.SenderTrxId)
	}
	if innerPpd.LocalInitTime != receivedAtNanos {
		t.Errorf("inner receipt = %d, want inherited outer receipt %d", innerPpd.LocalInitTime, receivedAtNanos)
	}
}

// ============================================================================
// HandleRelayForward — reject paths (pre-auth drops, no ack sent)
// ============================================================================

func TestHandleRelayForward_Rejects(t *testing.T) {
	serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x22, &core.DeviceOptions{DisableAgentPeerValidation: true})
	agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)
	serverPk := decodeBase64PubKey(serverDev.PublicKeyBase64())

	relayPub := relayTestPubKey()
	relayPubB64 := base64.StdEncoding.EncodeToString(relayPub)
	otherPub := make([]byte, 32)
	for i := range otherPub {
		otherPub[i] = 0x99
	}

	// A real inner knock and a real non-knock inner packet, both forwardable.
	goodKnock := encryptInnerForRelay(t, agentDev, serverPk, core.NHP_KNK, 1, &common.AgentKnockMsg{
		HeaderType: core.NHP_KNK, UserId: "u", AuthServiceId: "asp", ResourceId: "res",
	})
	nonRelayable := encryptInnerForRelay(t, agentDev, serverPk, core.NHP_DAR, 2, map[string]any{})

	pubSource := &common.NetAddress{Ip: "203.0.113.7", Port: 44444}

	cases := []struct {
		name      string
		senderPub []byte
		rlyMsg    *common.RelayForwardMsg
	}{
		{
			name:      "unregistered relay peer",
			senderPub: otherPub, // not in relayPeerMap
			rlyMsg:    &common.RelayForwardMsg{SourceAddr: pubSource, InnerPacket: base64.StdEncoding.EncodeToString(goodKnock), RequestID: testRelayRequestID},
		},
		{
			name:      "private source address",
			senderPub: relayPub,
			rlyMsg:    &common.RelayForwardMsg{SourceAddr: &common.NetAddress{Ip: "192.168.1.5", Port: 443}, InnerPacket: base64.StdEncoding.EncodeToString(goodKnock), RequestID: testRelayRequestID},
		},
		{
			name:      "nil source address",
			senderPub: relayPub,
			rlyMsg:    &common.RelayForwardMsg{SourceAddr: nil, InnerPacket: base64.StdEncoding.EncodeToString(goodKnock), RequestID: testRelayRequestID},
		},
		{
			name:      "malformed inner packet",
			senderPub: relayPub,
			rlyMsg:    &common.RelayForwardMsg{SourceAddr: pubSource, InnerPacket: "!!!not-base64!!!", RequestID: testRelayRequestID},
		},
		{
			name:      "non-relayable inner type",
			senderPub: relayPub,
			rlyMsg:    &common.RelayForwardMsg{SourceAddr: pubSource, InnerPacket: base64.StdEncoding.EncodeToString(nonRelayable), RequestID: testRelayRequestID},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			listen := mustUDPListener(t)
			mp := metrics.NewPublisherForTest(t)
			s := &UdpServer{
				device:       serverDev,
				metrics:      mp,
				relayPeerMap: map[string]*core.UdpPeer{relayPubB64: {PubKeyBase64: relayPubB64, Type: core.NHP_RELAY}},
				listenConn:   listen,
			}
			body, err := json.Marshal(tc.rlyMsg)
			if err != nil {
				t.Fatalf("marshal RelayForwardMsg: %v", err)
			}
			outerPpd := &core.PacketParserData{
				HeaderType:    core.NHP_RLY,
				RemotePubKey:  tc.senderPub,
				ConnData:      &core.ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6000}},
				BodyMessage:   body,
				LocalInitTime: time.Now().UnixNano(),
			}

			s.HandleRelayForward(outerPpd)

			counters, _ := mp.CountersForTest(t)
			if got := counters[MetricRelayForwardReject]; got != 1 {
				t.Errorf("MetricRelayForwardReject = %v, want 1", got)
			}
		})
	}
}

// ============================================================================
// HandleRelayForward — full round-trip: a relay-forwarded knock that
// buildKnockAck rejects (header-type mismatch) still produces an agent-
// decryptable NHP_ACK delivered to the RELAY's address.
// ============================================================================

func TestHandleRelayForward_RoundTripDeliversAgentAckToRelay(t *testing.T) {
	serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x22, &core.DeviceOptions{DisableAgentPeerValidation: true})
	agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)
	serverPk := decodeBase64PubKey(serverDev.PublicKeyBase64())

	serverListen := mustUDPListener(t) // server writes the ack from here
	relayListen := mustUDPListener(t)  // stands in for the relay; receives the ack
	relayAddr := relayListen.LocalAddr().(*net.UDPAddr)

	// The agent must hold the server peer to decrypt the ACK's response leg
	// (validatePeer looks the responder's static key up in the agent's pool).
	agentToServerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62206}
	agentDev.AddPeer(&core.UdpPeer{
		PubKeyBase64: serverDev.PublicKeyBase64(),
		Ip:           agentToServerAddr.IP.String(),
		Port:         agentToServerAddr.Port,
		Type:         core.NHP_SERVER,
	})

	// Inner knock: wire NHP_KNK with a mismatched body header type (NHP_RKN) so
	// the strict #1154 gate inside buildKnockAck rejects it — exercising the
	// full relay round-trip without needing plugin/ASP wiring. Sent as a real
	// agent transaction so the agent can decrypt the returned ack.
	const innerTrx = uint64(424242)
	respCh := make(chan *core.PacketParserData, 1)
	agentConn := newSpikeConn(agentDev, agentToServerAddr)
	knockBody, err := json.Marshal(&common.AgentKnockMsg{
		HeaderType: core.NHP_RKN, UserId: "relay-user", AuthServiceId: "asp", ResourceId: "res",
	})
	if err != nil {
		t.Fatalf("marshal knock body: %v", err)
	}
	agentDev.SendMsgToPacket(&core.MsgData{
		ConnData:      agentConn,
		PeerPk:        serverPk,
		HeaderType:    core.NHP_KNK,
		TransactionId: innerTrx,
		Message:       knockBody,
		ResponseMsgCh: respCh,
	})
	innerKnock := drainEncryptedPacket(t, agentConn)

	rlyBytes, err := json.Marshal(&common.RelayForwardMsg{
		SourceAddr:  &common.NetAddress{Ip: "203.0.113.7", Port: 44444},
		InnerPacket: base64.StdEncoding.EncodeToString(innerKnock),
		RequestID:   testRelayRequestID,
	})
	if err != nil {
		t.Fatalf("marshal RelayForwardMsg: %v", err)
	}
	outerPpd, relayDev, relayConn := realOuterRelayRequest(t, serverDev, serverListen.LocalAddr().(*net.UDPAddr), relayAddr, rlyBytes)
	relayPubB64 := base64.StdEncoding.EncodeToString(outerPpd.RemotePubKey)
	mp := metrics.NewPublisherForTest(t)
	s := &UdpServer{
		device:                       serverDev,
		metrics:                      mp,
		relayPeerMap:                 map[string]*core.UdpPeer{relayPubB64: {PubKeyBase64: relayPubB64, Type: core.NHP_RELAY}},
		knockHeaderTypeVerifyRequire: true,
		listenConn:                   serverListen,
	}

	s.HandleRelayForward(outerPpd)

	// The ack must arrive at the RELAY's address (not the client's).
	outerReturnBytes := readUDPWithTimeout(t, relayListen, 5*time.Second)
	returned := decryptRelayReturnForTest(t, relayDev, relayConn, outerReturnBytes)
	if returned.RequestID != testRelayRequestID {
		t.Fatalf("return request ID = %q, want %q", returned.RequestID, testRelayRequestID)
	}
	ackBytes, err := base64.StdEncoding.DecodeString(returned.InnerPacket)
	if err != nil {
		t.Fatalf("decode returned inner ACK: %v", err)
	}

	// And the AGENT must be able to decrypt it via its original knock transaction.
	routeResponseToTransaction(t, agentDev, ackBytes)
	select {
	case serverPpd := <-respCh:
		if serverPpd.Error != nil {
			t.Fatalf("agent failed to decrypt relayed ack: %v", serverPpd.Error)
		}
		if serverPpd.HeaderType != core.NHP_ACK {
			t.Fatalf("agent decrypted header = %d, want NHP_ACK", serverPpd.HeaderType)
		}
		if serverPpd.SenderTrxId != innerTrx {
			t.Errorf("ack counter = %d, want inner knock counter %d", serverPpd.SenderTrxId, innerTrx)
		}
		var ack common.ServerKnockAckMsg
		if err := json.Unmarshal(serverPpd.BodyMessage, &ack); err != nil {
			t.Fatalf("unmarshal decrypted ack: %v", err)
		}
		if ack.ErrCode != common.ErrKnockHeaderTypeMismatch.ErrorCode() {
			t.Errorf("ack.ErrCode = %q, want header-type-mismatch reject %q", ack.ErrCode, common.ErrKnockHeaderTypeMismatch.ErrorCode())
		}
		// AgentAddr is echoed from ppd.ConnData.RemoteAddr — the SAME field
		// buildKnockAck threads into authReq.SrcAddr (the AC pinhole source, set
		// three lines apart in nhpauth.go). Asserting it equals the relay-
		// reported client (not the relay) is the end-to-end proof that the
		// pinhole opens for the real client; the upstream half — the synthetic
		// decrypt stamping that field — is fenced directly by
		// TestDecryptRelayInnerKnock_StampsClientSourceAddr. Together they cover
		// the relay's central security property without plugin/ASP wiring.
		if ack.AgentAddr != "203.0.113.7:44444" {
			t.Errorf("ack.AgentAddr = %q, want relay-reported client 203.0.113.7:44444 (pinhole must open for the client, never the relay)", ack.AgentAddr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent never received the decrypted relayed ack")
	}

	counters, _ := mp.CountersForTest(t)
	if got := counters[MetricRelayForward]; got != 1 {
		t.Errorf("MetricRelayForward = %v, want 1", got)
	}
	if got := counters[MetricRelayForwardReject]; got != 0 {
		t.Errorf("MetricRelayForwardReject = %v, want 0 (auth reject is delivered as an ack, not a pre-auth drop)", got)
	}
}

func TestHandleRelayForward_ExactSessionRetirementReturnsDurableReceipt(t *testing.T) {
	serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x22, &core.DeviceOptions{DisableAgentPeerValidation: true})
	agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)
	serverPk := decodeBase64PubKey(serverDev.PublicKeyBase64())

	serverListen := mustUDPListener(t)
	relayListen := mustUDPListener(t)
	relayAddr := relayListen.LocalAddr().(*net.UDPAddr)
	agentToServerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62206}
	agentDev.AddPeer(&core.UdpPeer{
		PubKeyBase64: serverDev.PublicKeyBase64(), Ip: agentToServerAddr.IP.String(),
		Port: agentToServerAddr.Port, Type: core.NHP_SERVER,
	})

	candidate := sessionControlSessionCandidate{
		CellID: "cell-01", AgentPublicKey: agentDev.PublicKeyBase64(), SessionID: 902,
		IssuedAtMillis: 1_800_000_000_000, ReservationDeadlineMillis: 1_800_000_030_000,
		RunID: "0123456789abcdef", RunAttempt: 3,
	}
	current, err := planSessionControlReservation(candidate, testSessionControlSessionSnapshot(7))
	if err != nil {
		t.Fatal(err)
	}
	current.RetainUntilMillis = candidate.ReservationDeadlineMillis + time.Minute.Milliseconds()
	store := &exactRetirementTestStore{
		memorySessionControlStore: newMemorySessionControlStore(time.UnixMilli(candidate.IssuedAtMillis)),
		current:                   current,
	}

	const innerTrx = uint64(424244)
	response := make(chan *core.PacketParserData, 1)
	agentConn := newSpikeConn(agentDev, agentToServerAddr)
	closeBody, err := json.Marshal(&common.AgentExactSessionCloseMsg{
		HeaderType: core.NHP_EXT, AuthServiceID: common.RegisteredAgentAuthServiceID,
		CellID: candidate.CellID, SessionID: candidate.SessionID,
		SessionIssuedAtMillis: candidate.IssuedAtMillis, RunID: candidate.RunID, RunAttempt: candidate.RunAttempt,
	})
	if err != nil {
		t.Fatal(err)
	}
	agentDev.SendMsgToPacket(&core.MsgData{
		ConnData: agentConn, PeerPk: serverPk, HeaderType: core.NHP_EXT,
		TransactionId: innerTrx, Message: closeBody, ResponseMsgCh: response,
	})
	innerClose := drainEncryptedPacket(t, agentConn)
	rlyBytes, err := json.Marshal(&common.RelayForwardMsg{
		SourceAddr:  &common.NetAddress{Ip: "203.0.113.7", Port: 44444},
		InnerPacket: base64.StdEncoding.EncodeToString(innerClose), RequestID: testRelayRequestID,
	})
	if err != nil {
		t.Fatal(err)
	}
	outerPpd, relayDev, relayConn := realOuterRelayRequest(
		t, serverDev, serverListen.LocalAddr().(*net.UDPAddr), relayAddr, rlyBytes,
	)
	relayPubB64 := base64.StdEncoding.EncodeToString(outerPpd.RemotePubKey)
	s := &UdpServer{
		device: serverDev, metrics: metrics.NewPublisherForTest(t), listenConn: serverListen,
		sessionControlCellID: candidate.CellID, sessionControlStore: store,
		relayPeerMap: map[string]*core.UdpPeer{
			relayPubB64: {PubKeyBase64: relayPubB64, Type: core.NHP_RELAY},
		},
	}

	s.HandleRelayForward(outerPpd)
	outerReturnBytes := readUDPWithTimeout(t, relayListen, 5*time.Second)
	returned := decryptRelayReturnForTest(t, relayDev, relayConn, outerReturnBytes)
	ackPacket, err := base64.StdEncoding.DecodeString(returned.InnerPacket)
	if err != nil {
		t.Fatal(err)
	}
	routeResponseToTransaction(t, agentDev, ackPacket)
	select {
	case serverPpd := <-response:
		if serverPpd.Error != nil || serverPpd.HeaderType != core.NHP_ACK || serverPpd.SenderTrxId != innerTrx {
			t.Fatalf("relayed exact-close ACK packet = %#v", serverPpd)
		}
		var ack common.ServerExactSessionCloseAckMsg
		if err := json.Unmarshal(serverPpd.BodyMessage, &ack); err != nil {
			t.Fatal(err)
		}
		if !common.IsSuccessErrCode(ack.ErrCode) || ack.CellID != candidate.CellID ||
			ack.SessionID != candidate.SessionID || ack.SessionIssuedAtMillis != candidate.IssuedAtMillis ||
			ack.RunID != candidate.RunID || ack.RunAttempt != candidate.RunAttempt ||
			ack.CloseEventID != sessionControlExactCloseEventID(candidate) || ack.State != sessionControlSessionStateClosing {
			t.Fatalf("relayed exact-close ACK = %#v", ack)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent never received the relayed exact-close ACK")
	}
	if store.resolveCalls != 1 || store.closeCalls != 1 {
		t.Fatalf("relayed exact-close store calls = resolve %d close %d, want 1/1", store.resolveCalls, store.closeCalls)
	}
}

func TestHandleRelayForward_BodylessExitIsRejectedOnCurrentEnvelope(t *testing.T) {
	serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x22, &core.DeviceOptions{DisableAgentPeerValidation: true})
	agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)
	serverPk := decodeBase64PubKey(serverDev.PublicKeyBase64())
	innerExit := encryptRawInnerForRelay(t, agentDev, serverPk, core.NHP_EXT, 424243, nil)

	serverListen := mustUDPListener(t)
	relayListen := mustUDPListener(t)
	relayAddr := relayListen.LocalAddr().(*net.UDPAddr)
	body, err := json.Marshal(&common.RelayForwardMsg{
		SourceAddr:  &common.NetAddress{Ip: "203.0.113.7", Port: 44444},
		InnerPacket: base64.StdEncoding.EncodeToString(innerExit),
		RequestID:   testRelayRequestID,
	})
	if err != nil {
		t.Fatalf("marshal RelayForwardMsg: %v", err)
	}
	outerPpd, _, _ := realOuterRelayRequest(t, serverDev, serverListen.LocalAddr().(*net.UDPAddr), relayAddr, body)
	relayPubB64 := base64.StdEncoding.EncodeToString(outerPpd.RemotePubKey)
	mp := metrics.NewPublisherForTest(t)
	s := &UdpServer{
		device:       serverDev,
		metrics:      mp,
		relayPeerMap: map[string]*core.UdpPeer{relayPubB64: {PubKeyBase64: relayPubB64, Type: core.NHP_RELAY}},
		listenConn:   serverListen,
	}
	s.running.Store(true)

	s.HandleRelayForward(outerPpd)
	s.agentSessionCloseWorkerWG.Wait()
	counters, _ := mp.CountersForTest(t)
	if got := counters[MetricAgentSessionCloseRequest]; got != 0 {
		t.Fatalf("AgentSessionCloseRequest = %v, want 0 for rejected bodyless close", got)
	}
	if got := counters[MetricRelayForwardReject]; got != 1 {
		t.Fatalf("MetricRelayForwardReject = %v, want 1", got)
	}
	if err := relayListen.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, core.RelayPacketBufferSize)
	if n, _, readErr := relayListen.ReadFromUDP(buf); readErr == nil {
		t.Fatalf("bodyless EXT produced an unexpected %d-byte NHP response", n)
	} else if !errors.Is(readErr, os.ErrDeadlineExceeded) {
		t.Fatalf("waiting for absent EXT response: %v", readErr)
	}
}

func TestSendRelayReturnCarriesMaximumInnerPacket(t *testing.T) {
	serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x22, &core.DeviceOptions{DisableRelayPeerValidation: true})
	serverListen := mustUDPListener(t)
	relayListen := mustUDPListener(t)
	relayAddr := relayListen.LocalAddr().(*net.UDPAddr)
	body, err := json.Marshal(&common.RelayForwardMsg{
		SourceAddr:  &common.NetAddress{Ip: "203.0.113.7", Port: 44444},
		InnerPacket: base64.StdEncoding.EncodeToString([]byte("request")),
		RequestID:   testRelayRequestID,
	})
	if err != nil {
		t.Fatal(err)
	}
	outerPpd, relayDev, relayConn := realOuterRelayRequest(
		t, serverDev, serverListen.LocalAddr().(*net.UDPAddr), relayAddr, body,
	)
	s := &UdpServer{device: serverDev, listenConn: serverListen}
	inner := make([]byte, core.PacketBufferSize)
	for i := range inner {
		inner[i] = byte(i)
	}
	if err := s.sendRelayReturn(outerPpd, testRelayRequestID, inner); err != nil {
		t.Fatalf("send maximum relay return: %v", err)
	}
	outerBytes := readUDPWithTimeout(t, relayListen, 5*time.Second)
	if len(outerBytes) != 5772 {
		t.Fatalf("maximum relay return = %d bytes, want 5772", len(outerBytes))
	}
	returned := decryptRelayReturnForTest(t, relayDev, relayConn, outerBytes)
	decoded, err := base64.StdEncoding.DecodeString(returned.InnerPacket)
	if err != nil {
		t.Fatalf("decode maximum returned inner packet: %v", err)
	}
	if !bytes.Equal(decoded, inner) {
		t.Fatal("maximum inner packet changed in server relay return")
	}

	writeFailure := errors.New("injected relay write failure")
	failingSocket := &recordingUDPWriteSocket{writeN: 0, writeErr: writeFailure}
	s.udpWriteSocket = failingSocket
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = s.sendRelayReturnContext(ctx, outerPpd, testRelayRequestID, inner)
	if !errors.Is(err, errRelayReturnWrite) || !errors.Is(err, writeFailure) {
		t.Fatalf("relay write error = %v, want stage and underlying write classifications", err)
	}
}

// An overloaded server must admit the authenticated outer NHP_RLY envelope,
// issue the normal end-to-end encrypted COK for its inner KNK, and return that
// opaque packet in a request-correlated RelayReturnMsg. This is the production
// handler path, not a hand-built return envelope.
func TestHandleRelayForward_OverloadCookieRoundTrip(t *testing.T) {
	serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x22, &core.DeviceOptions{DisableAgentPeerValidation: true})
	agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)
	serverPk := decodeBase64PubKey(serverDev.PublicKeyBase64())

	serverListen := mustUDPListener(t)
	relayListen := mustUDPListener(t)
	relayAddr := relayListen.LocalAddr().(*net.UDPAddr)
	agentToServerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62206}
	agentDev.AddPeer(&core.UdpPeer{
		PubKeyBase64: serverDev.PublicKeyBase64(),
		Ip:           agentToServerAddr.IP.String(),
		Port:         agentToServerAddr.Port,
		Type:         core.NHP_SERVER,
	})

	const innerTrx = uint64(515151)
	agentConn := newSpikeConn(agentDev, agentToServerAddr)
	knockBody, err := json.Marshal(&common.AgentKnockMsg{
		HeaderType: core.NHP_KNK, UserId: "overload-user", AuthServiceId: "asp", ResourceId: "res",
	})
	if err != nil {
		t.Fatalf("marshal knock body: %v", err)
	}
	agentDev.SendMsgToPacket(&core.MsgData{
		ConnData:      agentConn,
		PeerPk:        serverPk,
		HeaderType:    core.NHP_KNK,
		TransactionId: innerTrx,
		Message:       knockBody,
	})
	innerKnock := drainEncryptedPacket(t, agentConn)

	rlyBytes, err := json.Marshal(&common.RelayForwardMsg{
		SourceAddr:  &common.NetAddress{Ip: "203.0.113.7", Port: 44444},
		InnerPacket: base64.StdEncoding.EncodeToString(innerKnock),
		RequestID:   testRelayRequestID,
	})
	if err != nil {
		t.Fatalf("marshal RelayForwardMsg: %v", err)
	}

	// Decrypt the real outer envelope first, exactly as the UDP receive loop
	// does before dispatch. The core allowlist assertion separately fences that
	// NHP_RLY reaches this point when overload is already active.
	outerPpd, relayDev, relayConn := realOuterRelayRequest(t, serverDev, serverListen.LocalAddr().(*net.UDPAddr), relayAddr, rlyBytes)
	relayPubB64 := base64.StdEncoding.EncodeToString(outerPpd.RemotePubKey)
	mp := metrics.NewPublisherForTest(t)
	s := &UdpServer{
		device:       serverDev,
		metrics:      mp,
		relayPeerMap: map[string]*core.UdpPeer{relayPubB64: {PubKeyBase64: relayPubB64, Type: core.NHP_RELAY}},
		listenConn:   serverListen,
	}

	serverDev.SetOverload(true)
	defer serverDev.SetOverload(false)
	s.HandleRelayForward(outerPpd)

	outerReturnBytes := readUDPWithTimeout(t, relayListen, 5*time.Second)
	returned := decryptRelayReturnForTest(t, relayDev, relayConn, outerReturnBytes)
	if returned.RequestID != testRelayRequestID {
		t.Fatalf("return request ID = %q, want %q", returned.RequestID, testRelayRequestID)
	}
	cokBytes, err := base64.StdEncoding.DecodeString(returned.InnerPacket)
	if err != nil {
		t.Fatalf("decode returned inner COK: %v", err)
	}
	agentPpd, err := agentDev.PacketToMsg(&core.PacketData{
		BasePacket: &core.Packet{Content: cokBytes},
		ConnData:   agentConn,
		InitTime:   time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatalf("agent failed to decrypt relayed COK: %v", err)
	}
	if agentPpd == nil || agentPpd.HeaderType != core.NHP_COK {
		t.Fatalf("agent decrypted packet = %#v, want NHP_COK", agentPpd)
	}
	if agentPpd.SenderTrxId != innerTrx {
		t.Errorf("COK counter = %d, want inner knock counter %d", agentPpd.SenderTrxId, innerTrx)
	}
	var cok common.ServerCookieMsg
	if err := json.Unmarshal(agentPpd.BodyMessage, &cok); err != nil {
		t.Fatalf("unmarshal decrypted COK: %v", err)
	}
	if cok.TransactionId != innerTrx {
		t.Errorf("COK payload transaction ID = %d, want %d", cok.TransactionId, innerTrx)
	}
	rawCookie, err := base64.StdEncoding.DecodeString(cok.Cookie)
	if err != nil {
		t.Fatalf("decode COK cookie: %v", err)
	}
	if len(rawCookie) != core.CookieSize {
		t.Errorf("cookie length = %d, want %d", len(rawCookie), core.CookieSize)
	}

	counters, _ := mp.CountersForTest(t)
	if got := counters[MetricRelayForward]; got != 1 {
		t.Errorf("MetricRelayForward = %v, want 1", got)
	}
	if got := counters[MetricRelayForwardReject]; got != 0 {
		t.Errorf("MetricRelayForwardReject = %v, want 0", got)
	}
	if got := counters[MetricRelayOverloadCookieReturn]; got != 1 {
		t.Errorf("MetricRelayOverloadCookieReturn = %v, want 1", got)
	}
}

// ============================================================================
// test helpers
// ============================================================================

func realOuterRelayRequest(t *testing.T, serverDev *core.Device, serverAddr, relayAddr *net.UDPAddr, body []byte) (*core.PacketParserData, *core.Device, *core.ConnectionData) {
	t.Helper()
	relayDev := newSpikeDevice(t, core.NHP_RELAY, 0x55, &core.DeviceOptions{DisableServerPeerValidation: false})
	relayPub := decodeBase64PubKey(relayDev.PublicKeyBase64())
	serverPub := decodeBase64PubKey(serverDev.PublicKeyBase64())

	serverDev.AddPeer(&core.UdpPeer{PubKeyBase64: relayDev.PublicKeyBase64(), Ip: relayAddr.IP.String(), Port: relayAddr.Port, Type: core.NHP_RELAY})
	relayDev.AddPeer(&core.UdpPeer{PubKeyBase64: serverDev.PublicKeyBase64(), Ip: serverAddr.IP.String(), Port: serverAddr.Port, Type: core.NHP_SERVER})

	relayConn := newSpikeConn(relayDev, serverAddr)
	relayDev.SendMsgToPacket(&core.MsgData{
		ConnData:      relayConn,
		PeerPk:        serverPub,
		HeaderType:    core.NHP_RLY,
		TransactionId: 991122,
		Message:       body,
	})
	outerBytes := drainEncryptedPacket(t, relayConn)
	serverConn := newSpikeConn(serverDev, relayAddr)
	outerPpd, err := serverDev.PacketToMsg(&core.PacketData{
		BasePacket: &core.Packet{Content: outerBytes},
		ConnData:   serverConn,
		InitTime:   time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatalf("decrypt real outer NHP_RLY: %v", err)
	}
	if outerPpd == nil || outerPpd.HeaderType != core.NHP_RLY {
		t.Fatalf("real outer packet = %#v, want NHP_RLY", outerPpd)
	}
	if got := base64.StdEncoding.EncodeToString(outerPpd.RemotePubKey); got != base64.StdEncoding.EncodeToString(relayPub) {
		t.Fatalf("outer relay pubkey = %q, want %q", got, relayDev.PublicKeyBase64())
	}
	return outerPpd, relayDev, relayConn
}

func decryptRelayReturnForTest(t *testing.T, relayDev *core.Device, relayConn *core.ConnectionData, outerBytes []byte) common.RelayReturnMsg {
	t.Helper()
	ppd, err := relayDev.PacketToMsg(&core.PacketData{
		BasePacket: &core.Packet{Content: outerBytes},
		ConnData:   relayConn,
		InitTime:   time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatalf("relay failed to decrypt outer return: %v", err)
	}
	if ppd == nil || ppd.Error != nil {
		t.Fatalf("relay outer return parser data = %#v", ppd)
	}
	if ppd.HeaderType != core.NHP_ACK {
		t.Fatalf("outer return type = %s, want NHP-ACK", core.HeaderTypeToString(ppd.HeaderType))
	}
	var returned common.RelayReturnMsg
	if err := json.Unmarshal(ppd.BodyMessage, &returned); err != nil {
		t.Fatalf("unmarshal RelayReturnMsg: %v", err)
	}
	return returned
}

// relayTestPubKey returns a deterministic 32-byte relay public key.
func relayTestPubKey() []byte {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = 0x55
	}
	return pub
}

// encryptInnerForRelay produces the raw encrypted bytes of an inner NHP packet
// of the given wire type, as an agent would emit it to the server — the bytes a
// relay forwards in RelayForwardMsg.InnerPacket.
func encryptInnerForRelay(t *testing.T, agentDev *core.Device, serverPk []byte, wireType int, trxID uint64, msg any) []byte {
	t.Helper()
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal inner message: %v", err)
	}
	return encryptRawInnerForRelay(t, agentDev, serverPk, wireType, trxID, body)
}

// encryptRawInnerForRelay preserves an already-serialized body byte-for-byte.
// It is used when a test needs to fence duplicate fields, unknown fields,
// ordering, or whitespace across the full relay decrypt path.
func encryptRawInnerForRelay(t *testing.T, agentDev *core.Device, serverPk []byte, wireType int, trxID uint64, body []byte) []byte {
	t.Helper()
	conn := newSpikeConn(agentDev, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62206})
	agentDev.SendMsgToPacket(&core.MsgData{
		ConnData:      conn,
		PeerPk:        serverPk,
		HeaderType:    wireType,
		TransactionId: trxID,
		Message:       body,
	})
	return drainEncryptedPacket(t, conn)
}

// mustUDPListener binds a localhost UDP socket and closes it at test end.
func mustUDPListener(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// readUDPWithTimeout reads a single datagram or fails the test on timeout.
func readUDPWithTimeout(t *testing.T, conn *net.UDPConn, timeout time.Duration) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 65536)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected a datagram within %s, got: %v", timeout, err)
	}
	return buf[:n]
}
