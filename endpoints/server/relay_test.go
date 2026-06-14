package server

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// ============================================================================
// Pure validation helpers — the relay's security boundary
// ============================================================================

func TestValidateRelaySourceAddr(t *testing.T) {
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
		{"private ip", &common.NetAddress{Ip: "192.168.1.10", Port: 443}, "non-routable"},
		{"loopback", &common.NetAddress{Ip: "127.0.0.1", Port: 443}, "non-routable"},
		{"cgnat", &common.NetAddress{Ip: "100.64.0.1", Port: 443}, "non-routable"},
		{"public v4", &common.NetAddress{Ip: "203.0.113.7", Port: 44444}, ""},
		{"public v6", &common.NetAddress{Ip: "2606:4700:4700::1111", Port: 443}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateRelaySourceAddr(tc.addr)
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

	innerPpd, err := s.decryptRelayInnerKnock(innerKnock, clientAddr)
	if err != nil {
		t.Fatalf("decryptRelayInnerKnock: %v", err)
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
	nonKnock := encryptInnerForRelay(t, agentDev, serverPk, core.NHP_LST, 2, &common.AgentListMsg{})

	pubSource := &common.NetAddress{Ip: "203.0.113.7", Port: 44444}

	cases := []struct {
		name      string
		senderPub []byte
		rlyMsg    *common.RelayForwardMsg
	}{
		{
			name:      "unregistered relay peer",
			senderPub: otherPub, // not in relayPeerMap
			rlyMsg:    &common.RelayForwardMsg{SourceAddr: pubSource, InnerPacket: base64.StdEncoding.EncodeToString(goodKnock)},
		},
		{
			name:      "private source address",
			senderPub: relayPub,
			rlyMsg:    &common.RelayForwardMsg{SourceAddr: &common.NetAddress{Ip: "192.168.1.5", Port: 443}, InnerPacket: base64.StdEncoding.EncodeToString(goodKnock)},
		},
		{
			name:      "nil source address",
			senderPub: relayPub,
			rlyMsg:    &common.RelayForwardMsg{SourceAddr: nil, InnerPacket: base64.StdEncoding.EncodeToString(goodKnock)},
		},
		{
			name:      "malformed inner packet",
			senderPub: relayPub,
			rlyMsg:    &common.RelayForwardMsg{SourceAddr: pubSource, InnerPacket: "!!!not-base64!!!"},
		},
		{
			name:      "non-knock inner type",
			senderPub: relayPub,
			rlyMsg:    &common.RelayForwardMsg{SourceAddr: pubSource, InnerPacket: base64.StdEncoding.EncodeToString(nonKnock)},
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
				HeaderType:   core.NHP_RLY,
				RemotePubKey: tc.senderPub,
				ConnData:     &core.ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6000}},
				BodyMessage:  body,
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

	// Inner knock: wire NHP_KNK with a mismatched body header type (NHP_EXT) so
	// the strict #1154 gate inside buildKnockAck rejects it — exercising the
	// full relay round-trip without needing plugin/ASP wiring. Sent as a real
	// agent transaction so the agent can decrypt the returned ack.
	const innerTrx = uint64(424242)
	respCh := make(chan *core.PacketParserData, 1)
	agentConn := newSpikeConn(agentDev, agentToServerAddr)
	knockBody, err := json.Marshal(&common.AgentKnockMsg{
		HeaderType: core.NHP_EXT, UserId: "relay-user", AuthServiceId: "asp", ResourceId: "res",
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

	relayPub := relayTestPubKey()
	relayPubB64 := base64.StdEncoding.EncodeToString(relayPub)
	mp := metrics.NewPublisherForTest(t)
	s := &UdpServer{
		device:                       serverDev,
		metrics:                      mp,
		relayPeerMap:                 map[string]*core.UdpPeer{relayPubB64: {PubKeyBase64: relayPubB64, Type: core.NHP_RELAY}},
		knockHeaderTypeVerifyRequire: true, // strict gate -> the mismatch is rejected
		listenConn:                   serverListen,
	}

	rlyBytes, err := json.Marshal(&common.RelayForwardMsg{
		SourceAddr:  &common.NetAddress{Ip: "203.0.113.7", Port: 44444},
		InnerPacket: base64.StdEncoding.EncodeToString(innerKnock),
	})
	if err != nil {
		t.Fatalf("marshal RelayForwardMsg: %v", err)
	}
	outerPpd := &core.PacketParserData{
		HeaderType:   core.NHP_RLY,
		RemotePubKey: relayPub,
		ConnData:     &core.ConnectionData{RemoteAddr: relayAddr},
		BodyMessage:  rlyBytes,
	}

	s.HandleRelayForward(outerPpd)

	// The ack must arrive at the RELAY's address (not the client's).
	ackBytes := readUDPWithTimeout(t, relayListen, 5*time.Second)

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

// ============================================================================
// test helpers
// ============================================================================

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
