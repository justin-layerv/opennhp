package core

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"
)

var connectorHubAdmissionBody = []byte(`{"usrId":"","devId":"agent-01","aspId":"agent","usrData":{"query":"cell_assignment","version":1,"mode":"refresh"}}`)

type connectorHubAdmissionFixture struct {
	sender       *Device
	receiver     *Device
	receiverConn *ConnectionData
	headerType   int
	packet       []byte
	sendTime     int64
}

func newConnectorHubAdmissionFixture(tb testing.TB, receiverType, headerType int, options DeviceOptions) connectorHubAdmissionFixture {
	tb.Helper()
	silenceGlobalLogger(tb)

	senderType := NHP_AGENT
	// The DHP sender supports the DHP_KNK negative fence below; it must remain
	// outside the NHP_AGENT admission branch.
	if HeaderTypeToDeviceType(headerType) == DHP_AGENT {
		senderType = DHP_AGENT
	}
	sender := NewDevice(senderType, validatePeerPrivateKey(70), nil)
	if sender == nil {
		tb.Fatal("create sender device")
	}
	receiver := NewDevice(receiverType, validatePeerPrivateKey(33), &options)
	if receiver == nil {
		tb.Fatal("create receiver device")
	}
	receiverConn := validatePeerConnectionData(receiver, 12346, 12345)

	var cookie *[CookieSize]byte
	if headerType == NHP_RKN {
		cookie = &[CookieSize]byte{}
		for i := range cookie {
			cookie[i] = byte(i + 1)
		}
		receiverConn.CookieStore.CurrCookie = *cookie
		receiver.SetOverload(true)
	}

	mad, err := sender.MsgToPacket(&MsgData{
		ConnData:       validatePeerConnectionData(sender, 12345, 12346),
		PeerPk:         receiver.staticEcdh.PublicKey(),
		HeaderType:     headerType,
		TransactionId:  1,
		Message:        connectorHubAdmissionBody,
		ExternalCookie: cookie,
	})
	if err != nil {
		tb.Fatalf("encrypt %s: %v", HeaderTypeToString(headerType), err)
	}

	return connectorHubAdmissionFixture{
		sender:       sender,
		receiver:     receiver,
		receiverConn: receiverConn,
		headerType:   headerType,
		packet:       bytes.Clone(mad.BasePacket.Content),
		sendTime:     mad.LocalInitTime,
	}
}

func (f connectorHubAdmissionFixture) parse(tb testing.TB, packet []byte, initTime int64) (*PacketParserData, error) {
	tb.Helper()
	pkt := &Packet{Content: bytes.Clone(packet), HeaderType: f.headerType}
	if _, _, err := f.receiver.RecvPrecheck(pkt); err != nil {
		return nil, err
	}
	ppd, err := f.receiver.createPacketParserData(&PacketData{
		BasePacket: pkt,
		ConnData:   f.receiverConn,
		InitTime:   initTime,
	})
	if err != nil {
		return ppd, err
	}
	return ppd, ppd.validatePeer()
}

func assertConnectorHubDropOnlyState(tb testing.TB, conn *ConnectionData, wantLastRemoteSendTime int64) {
	tb.Helper()
	if got := atomic.LoadInt64(&conn.LastRemoteSendTime); got != wantLastRemoteSendTime {
		tb.Fatalf("LastRemoteSendTime = %d, want %d", got, wantLastRemoteSendTime)
	}
	if got := atomic.LoadInt32(&conn.RecvThreatCount); got != 0 {
		tb.Fatalf("RecvThreatCount = %d, want 0", got)
	}
	if got := len(conn.BlockSignal); got != 0 {
		tb.Fatalf("BlockSignal length = %d, want 0", got)
	}
}

func TestAllowUnregisteredAgentLSTDefaultStillRejectsUnknownPeer(t *testing.T) {
	fixture := newConnectorHubAdmissionFixture(t, NHP_SERVER, NHP_LST, DeviceOptions{})
	ppd, err := fixture.parse(t, fixture.packet, time.Now().UnixNano())
	if ppd != nil {
		defer ppd.Destroy()
	}
	assertNHPError(t, err, ErrPeerNotFound)
}

func TestAllowUnregisteredAgentLSTAuthenticatesAndDecryptsExactRequest(t *testing.T) {
	fixture := newConnectorHubAdmissionFixture(t, NHP_SERVER, NHP_LST, DeviceOptions{AllowUnregisteredAgentLST: true})
	ppd, err := fixture.parse(t, fixture.packet, time.Now().UnixNano())
	if ppd == nil {
		t.Fatal("parse returned nil PacketParserData")
	}
	defer ppd.Destroy()
	if err != nil {
		t.Fatalf("validate unregistered LST: %v", err)
	}
	if err := ppd.decryptBody(); err != nil {
		t.Fatalf("decrypt unregistered LST body: %v", err)
	}
	if !bytes.Equal(ppd.RemotePubKey, fixture.sender.staticEcdh.PublicKey()) {
		t.Fatalf("authenticated peer = %x, want %x", ppd.RemotePubKey, fixture.sender.staticEcdh.PublicKey())
	}
	if !bytes.Equal(ppd.BodyMessage, connectorHubAdmissionBody) {
		t.Fatalf("decrypted body = %q, want %q", ppd.BodyMessage, connectorHubAdmissionBody)
	}
	if ppd.RemoteSendTime == 0 {
		t.Fatal("authenticated send timestamp was not preserved")
	}
}

func TestAllowUnregisteredAgentLSTDoesNotAdmitOtherAgentHeaders(t *testing.T) {
	for _, headerType := range []int{NHP_KNK, NHP_RKN, NHP_OTP, NHP_REG, NHP_EXT, DHP_KNK, NHP_DAR, NHP_DAV} {
		t.Run(HeaderTypeToString(headerType), func(t *testing.T) {
			fixture := newConnectorHubAdmissionFixture(t, NHP_SERVER, headerType, DeviceOptions{AllowUnregisteredAgentLST: true})
			ppd, err := fixture.parse(t, fixture.packet, time.Now().UnixNano())
			if ppd != nil {
				defer ppd.Destroy()
			}
			assertNHPError(t, err, ErrPeerNotFound)
		})
	}

	// NHP_ACC is agent-origin traffic too, but NHP_SERVER rejects it at the
	// direction gate before peer validation. The new option must not widen that
	// earlier allowlist.
	fixture := newConnectorHubAdmissionFixture(t, NHP_SERVER, NHP_ACC, DeviceOptions{AllowUnregisteredAgentLST: true})
	pkt := &Packet{Content: bytes.Clone(fixture.packet), HeaderType: NHP_ACC}
	if _, _, err := fixture.receiver.RecvPrecheck(pkt); err == nil {
		t.Fatal("NHP_SERVER RecvPrecheck admitted NHP_ACC")
	}
}

func TestDisableAgentPeerValidationBroadBehaviorIsUnchanged(t *testing.T) {
	for _, headerType := range []int{NHP_LST, NHP_KNK, NHP_RKN, NHP_OTP, NHP_REG, NHP_EXT, DHP_KNK, NHP_DAR, NHP_DAV} {
		t.Run(HeaderTypeToString(headerType), func(t *testing.T) {
			fixture := newConnectorHubAdmissionFixture(t, NHP_SERVER, headerType, DeviceOptions{DisableAgentPeerValidation: true})
			ppd, err := fixture.parse(t, fixture.packet, time.Now().UnixNano())
			if ppd == nil {
				t.Fatal("parse returned nil PacketParserData")
			}
			defer ppd.Destroy()
			if err != nil {
				t.Fatalf("broad peer-validation option rejected %s: %v", HeaderTypeToString(headerType), err)
			}
		})
	}

	fixture := newConnectorHubAdmissionFixture(t, NHP_SERVER, NHP_ACC, DeviceOptions{DisableAgentPeerValidation: true})
	pkt := &Packet{Content: bytes.Clone(fixture.packet), HeaderType: NHP_ACC}
	if _, _, err := fixture.receiver.RecvPrecheck(pkt); err == nil {
		t.Fatal("DisableAgentPeerValidation unexpectedly widened the NHP_SERVER direction gate to NHP_ACC")
	}
}

func TestAllowUnregisteredAgentLSTIsIgnoredByNonServerReceiver(t *testing.T) {
	relay := newConnectorHubAdmissionFixture(t, NHP_RELAY, NHP_LST, DeviceOptions{AllowUnregisteredAgentLST: true})
	relayPPD, err := relay.parse(t, relay.packet, time.Now().UnixNano())
	if relayPPD != nil {
		defer relayPPD.Destroy()
	}
	assertNHPError(t, err, ErrPeerNotFound)

	fixture := newConnectorHubAdmissionFixture(t, NHP_AC, NHP_LST, DeviceOptions{AllowUnregisteredAgentLST: true})
	pkt := &Packet{Content: bytes.Clone(fixture.packet), HeaderType: NHP_LST}
	if _, _, err := fixture.receiver.RecvPrecheck(pkt); err == nil {
		t.Fatal("NHP_AC RecvPrecheck admitted NHP_LST")
	}

	// Exercise the low-level guard directly too: even if a caller bypasses the
	// direction precheck, the option is inert unless the receiver is NHP_SERVER.
	ppd, err := fixture.receiver.createPacketParserData(&PacketData{
		BasePacket: pkt,
		ConnData:   fixture.receiverConn,
		InitTime:   time.Now().UnixNano(),
	})
	if ppd != nil {
		defer ppd.Destroy()
	}
	if err == nil {
		err = ppd.validatePeer()
	}
	assertNHPError(t, err, ErrPeerNotFound)
}

func TestAllowUnregisteredAgentLSTStillRejectsTamperedHandshakeAndBody(t *testing.T) {
	t.Run("static_key_ciphertext", func(t *testing.T) {
		fixture := newConnectorHubAdmissionFixture(t, NHP_SERVER, NHP_LST, DeviceOptions{AllowUnregisteredAgentLST: true})
		packet := bytes.Clone(fixture.packet)
		pkt := &Packet{Content: packet, HeaderType: NHP_LST}
		pkt.Header().StaticBytes()[0] ^= 0x80

		ppd, err := fixture.parse(t, packet, time.Now().UnixNano())
		if ppd != nil {
			defer ppd.Destroy()
		}
		if err == nil {
			t.Fatal("tampered initiator static-key ciphertext was accepted")
		}
	})

	t.Run("body_ciphertext", func(t *testing.T) {
		fixture := newConnectorHubAdmissionFixture(t, NHP_SERVER, NHP_LST, DeviceOptions{AllowUnregisteredAgentLST: true})
		packet := bytes.Clone(fixture.packet)
		packet[len(packet)-1] ^= 0x80

		ppd, err := fixture.parse(t, packet, time.Now().UnixNano())
		if ppd == nil {
			t.Fatal("parse returned nil PacketParserData")
		}
		defer ppd.Destroy()
		if err != nil {
			t.Fatalf("handshake validation failed before body test: %v", err)
		}
		if err := ppd.decryptBody(); err == nil {
			t.Fatal("tampered LST body ciphertext was accepted")
		}
		if len(ppd.BodyMessage) != 0 {
			t.Fatalf("tampered LST exposed plaintext body %q", ppd.BodyMessage)
		}
	})
}

func TestAllowUnregisteredAgentLSTPreservesStalenessAndReplayGates(t *testing.T) {
	t.Run("stale", func(t *testing.T) {
		fixture := newConnectorHubAdmissionFixture(t, NHP_SERVER, NHP_LST, DeviceOptions{AllowUnregisteredAgentLST: true})
		initTime := fixture.sendTime + int64((DefaultRecvStalenessFloorSeconds+1)*time.Second)
		for attempt := 0; attempt < 2; attempt++ {
			ppd, err := fixture.parse(t, fixture.packet, initTime)
			assertNHPError(t, err, ErrStalePacketReceived)
			if ppd != nil {
				ppd.Destroy()
			}
		}
		assertConnectorHubDropOnlyState(t, fixture.receiverConn, 0)
	})

	t.Run("timestamp_regression", func(t *testing.T) {
		older := newConnectorHubAdmissionFixture(t, NHP_SERVER, NHP_LST, DeviceOptions{AllowUnregisteredAgentLST: true})
		var newerMad *MsgAssemblerData
		for attempt := 0; attempt < 100; attempt++ {
			var err error
			newerMad, err = older.sender.MsgToPacket(&MsgData{
				ConnData:      validatePeerConnectionData(older.sender, 12345, 12346),
				PeerPk:        older.receiver.staticEcdh.PublicKey(),
				HeaderType:    NHP_LST,
				TransactionId: 2,
				Message:       connectorHubAdmissionBody,
			})
			if err != nil {
				t.Fatalf("encrypt newer LST: %v", err)
			}
			if newerMad.LocalInitTime > older.sendTime {
				break
			}
		}
		if newerMad == nil || newerMad.LocalInitTime <= older.sendTime {
			t.Fatal("could not construct a later authenticated timestamp")
		}
		newerPacket := bytes.Clone(newerMad.BasePacket.Content)

		newerPPD, err := older.parse(t, newerPacket, time.Now().UnixNano())
		if newerPPD == nil {
			t.Fatal("newer parse returned nil PacketParserData")
		}
		if err != nil {
			t.Fatalf("validate newer LST: %v", err)
		}
		newerPPD.Destroy()

		for attempt := 0; attempt < 2; attempt++ {
			olderPPD, err := older.parse(t, older.packet, time.Now().UnixNano())
			assertNHPError(t, err, ErrReplayPacketReceived)
			if olderPPD != nil {
				olderPPD.Destroy()
			}
		}
		assertConnectorHubDropOnlyState(t, older.receiverConn, newerMad.LocalInitTime)
	})

	t.Run("same_timestamp_replay", func(t *testing.T) {
		fixture := newConnectorHubAdmissionFixture(t, NHP_SERVER, NHP_LST, DeviceOptions{AllowUnregisteredAgentLST: true})
		initialPPD, err := fixture.parse(t, fixture.packet, time.Now().UnixNano())
		if initialPPD == nil {
			t.Fatal("initial parse returned nil PacketParserData")
		}
		if err != nil {
			initialPPD.Destroy()
			t.Fatalf("validate initial LST: %v", err)
		}
		initialPPD.Destroy()

		for attempt := 0; attempt < 2; attempt++ {
			replayPPD, err := fixture.parse(t, fixture.packet, time.Now().UnixNano())
			assertNHPError(t, err, ErrReplayPacketReceived)
			if replayPPD != nil {
				replayPPD.Destroy()
			}
		}
		assertConnectorHubDropOnlyState(t, fixture.receiverConn, fixture.sendTime)
	})
}

func TestAllowUnregisteredAgentLSTDoesNotChangeExistingSourceEscalation(t *testing.T) {
	tests := []struct {
		name         string
		options      DeviceOptions
		registerPeer bool
	}{
		{name: "registered_default", registerPeer: true},
		{
			name: "legacy_broad_disable",
			options: DeviceOptions{
				DisableAgentPeerValidation: true,
				AllowUnregisteredAgentLST:  true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newConnectorHubAdmissionFixture(t, NHP_SERVER, NHP_LST, test.options)
			if test.registerPeer {
				fixture.receiver.AddPeer(&UdpPeer{
					PubKeyBase64: fixture.sender.PublicKeyBase64(),
					Ip:           "127.0.0.1",
					Port:         12345,
					Type:         NHP_AGENT,
				})
			}

			initTime := fixture.sendTime + int64((DefaultRecvStalenessFloorSeconds+1)*time.Second)
			for attempt := 0; attempt < 2; attempt++ {
				ppd, err := fixture.parse(t, fixture.packet, initTime)
				assertNHPError(t, err, ErrStalePacketReceived)
				if ppd != nil {
					ppd.Destroy()
				}
			}

			if got := atomic.LoadInt32(&fixture.receiverConn.RecvThreatCount); got != ThreatCountBeforeBlock {
				t.Fatalf("RecvThreatCount = %d, want %d", got, ThreatCountBeforeBlock)
			}
			if got := len(fixture.receiverConn.BlockSignal); got != 1 {
				t.Fatalf("BlockSignal length = %d, want 1", got)
			}
		})
	}
}

func TestAllowUnregisteredAgentLSTBoundsFutureTimestampSkew(t *testing.T) {
	const expectedFutureSkewLimit = 30 * time.Second
	if unregisteredLSTFutureSkewLimit != expectedFutureSkewLimit {
		t.Fatalf("future skew limit = %s, want %s", unregisteredLSTFutureSkewLimit, expectedFutureSkewLimit)
	}

	t.Run("exact_boundary_allowed", func(t *testing.T) {
		fixture := newConnectorHubAdmissionFixture(t, NHP_SERVER, NHP_LST, DeviceOptions{AllowUnregisteredAgentLST: true})
		ppd, err := fixture.parse(t, fixture.packet, fixture.sendTime-int64(expectedFutureSkewLimit))
		if ppd == nil {
			t.Fatal("parse returned nil PacketParserData")
		}
		defer ppd.Destroy()
		if err != nil {
			t.Fatalf("exact future-skew boundary rejected: %v", err)
		}
		if err := ppd.decryptBody(); err != nil {
			t.Fatalf("decrypt exact-boundary LST body: %v", err)
		}
	})

	t.Run("one_nanosecond_over_boundary_rejected", func(t *testing.T) {
		fixture := newConnectorHubAdmissionFixture(t, NHP_SERVER, NHP_LST, DeviceOptions{AllowUnregisteredAgentLST: true})
		ppd, err := fixture.parse(t, fixture.packet, fixture.sendTime-int64(expectedFutureSkewLimit)-1)
		if ppd != nil {
			defer ppd.Destroy()
			if ppd.RemoteSendTime != 0 {
				t.Fatalf("rejected future timestamp surfaced RemoteSendTime %d", ppd.RemoteSendTime)
			}
		}
		assertNHPError(t, err, ErrStalePacketReceived)
		assertConnectorHubDropOnlyState(t, fixture.receiverConn, 0)
	})

	t.Run("registered_path_unchanged", func(t *testing.T) {
		fixture := newConnectorHubAdmissionFixture(t, NHP_SERVER, NHP_LST, DeviceOptions{})
		fixture.receiver.AddPeer(&UdpPeer{
			PubKeyBase64: fixture.sender.PublicKeyBase64(),
			Ip:           "127.0.0.1",
			Port:         12345,
			Type:         NHP_AGENT,
		})
		ppd, err := fixture.parse(t, fixture.packet, fixture.sendTime-int64(expectedFutureSkewLimit)-1)
		if ppd == nil {
			t.Fatal("parse returned nil PacketParserData")
		}
		defer ppd.Destroy()
		if err != nil {
			t.Fatalf("narrow future-skew bound changed registered LST: %v", err)
		}
		if err := ppd.decryptBody(); err != nil {
			t.Fatalf("decrypt registered LST body: %v", err)
		}
	})
}
