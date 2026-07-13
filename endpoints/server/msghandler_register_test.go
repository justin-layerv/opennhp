package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// newRegisterUnitServer builds a minimal UdpServer for the buildRegisterAck unit
// tests: a real device (NewNhpServerHelper reads device.PublicKeyBase64()) plus
// the supplied plugin map. No otpRateLimiter (nil = unbounded) and no listenConn
// (buildRegisterAck does not touch the wire — the relay path does, separately).
func newRegisterUnitServer(t *testing.T, handlers map[string]plugins.PluginHandler) *UdpServer {
	t.Helper()
	dev := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if dev == nil {
		t.Fatal("NewDevice returned nil")
	}
	t.Cleanup(dev.Stop)
	return &UdpServer{device: dev, pluginHandlerMap: handlers}
}

// buildRegisterPpd builds a decrypted-NHP_REG ppd the way the responder hands one
// to the register handler: a parsed AgentRegisterMsg body plus the
// Noise-authenticated RemotePubKey.
func buildRegisterPpd(t *testing.T, aspID string, pubKey []byte) *core.PacketParserData {
	t.Helper()
	body, err := json.Marshal(&common.AgentRegisterMsg{UserId: "u", DeviceId: "d", AuthServiceId: aspID, OTP: "123456"})
	if err != nil {
		t.Fatalf("marshal AgentRegisterMsg: %v", err)
	}
	return &core.PacketParserData{
		ConnData:     &core.ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 55555}},
		SenderTrxId:  99,
		HeaderType:   core.NHP_REG,
		BodyMessage:  body,
		RemotePubKey: pubKey,
	}
}

func buildListPpd(t *testing.T, aspID string, pubKey []byte) *core.PacketParserData {
	t.Helper()
	body, err := json.Marshal(&common.AgentListMsg{
		UserId: "u", DeviceId: "d", AuthServiceId: aspID,
	})
	if err != nil {
		t.Fatalf("marshal AgentListMsg: %v", err)
	}
	return &core.PacketParserData{
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 55555},
			StopSignal: make(chan struct{}),
		},
		SenderTrxId:  100,
		HeaderType:   core.NHP_LST,
		BodyMessage:  body,
		RemotePubKey: pubKey,
	}
}

func TestBuildListResult_PluginFailuresProduceFailClosedLRT(t *testing.T) {
	const aspID = "asp-list-unit"
	tests := []struct {
		name    string
		plugin  plugins.PluginHandler
		wantErr error
	}{
		{
			name: "bare plugin error",
			plugin: &recordingRegOTPPlugin{
				listErr: plugins.ErrPluginNotRegistered,
			},
			wantErr: plugins.ErrPluginNotRegistered,
		},
		{
			name:    "nil result without error",
			plugin:  &mockPluginHandler{},
			wantErr: errors.New("list plugin returned nil result"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newRegisterUnitServer(
				t, map[string]plugins.PluginHandler{aspID: tc.plugin},
			)
			lrtBytes, _, err := s.buildListResult(
				buildListPpd(t, aspID, testPubkey(0xC5)),
			)
			if err == nil || err.Error() != tc.wantErr.Error() {
				t.Fatalf("buildListResult error = %v, want %v", err, tc.wantErr)
			}
			if string(lrtBytes) == "null" {
				t.Fatal("buildListResult marshaled nil plugin result as JSON null")
			}
			var got common.ServerListResultMsg
			if err := json.Unmarshal(lrtBytes, &got); err != nil {
				t.Fatalf("unmarshal LRT bytes: %v", err)
			}
			if got.ErrCode != common.ErrAuthHandlerNotFound.ErrorCode() {
				t.Errorf(
					"LRT.ErrCode = %q, want fail-closed %q",
					got.ErrCode, common.ErrAuthHandlerNotFound.ErrorCode(),
				)
			}
			if common.IsSuccessErrCode(got.ErrCode) {
				t.Error("plugin failure produced a successful LRT")
			}
		})
	}
}

func TestHandleListRequest_DeliveredErrorLRTDoesNotReturnLogicalError(t *testing.T) {
	const aspID = "asp-list-direct-error"
	s := newRegisterUnitServer(t, map[string]plugins.PluginHandler{
		aspID: &recordingRegOTPPlugin{listErr: plugins.ErrPluginNotRegistered},
	})
	ppd := buildListPpd(t, aspID, testPubkey(0xC6))
	msgCh := make(chan *core.MsgData, 1)
	ppd.ConnData.RemoteTransactionMap = map[uint64]*core.RemoteTransaction{
		ppd.SenderTrxId: core.NewRemoteTransactionForTest(ppd.SenderTrxId, msgCh),
	}

	if err := s.HandleListRequest(ppd); err != nil {
		t.Fatalf("HandleListRequest returned delivered logical error: %v", err)
	}

	select {
	case md := <-msgCh:
		if md.HeaderType != core.NHP_LRT {
			t.Fatalf("delivered header type = %s, want NHP_LRT", core.HeaderTypeToString(md.HeaderType))
		}
		var got common.ServerListResultMsg
		if err := json.Unmarshal(md.Message, &got); err != nil {
			t.Fatalf("unmarshal delivered LRT: %v", err)
		}
		if common.IsSuccessErrCode(got.ErrCode) {
			t.Fatalf("delivered LRT unexpectedly succeeded: %+v", got)
		}
	default:
		t.Fatal("HandleListRequest did not deliver its fail-closed LRT")
	}
}

func TestHandleListRequest_UndeliveredErrorLRTReturnsTransportError(t *testing.T) {
	const aspID = "asp-list-direct-undeliverable"
	s := newRegisterUnitServer(t, map[string]plugins.PluginHandler{
		aspID: &recordingRegOTPPlugin{listErr: plugins.ErrPluginNotRegistered},
	})
	ppd := buildListPpd(t, aspID, testPubkey(0xC7))
	// No remote transaction is registered. The logical plugin failure still
	// becomes fail-closed LRT bytes, but because those bytes cannot be delivered,
	// HandleListRequest must surface the transport failure to dispatchHandler.
	if err := s.HandleListRequest(ppd); !errors.Is(err, common.ErrTransactionIdNotFound) {
		t.Fatalf("HandleListRequest error = %v, want ErrTransactionIdNotFound", err)
	}
}

// TestBuildRegisterAck_ScriptedAckAndPubKey fences buildRegisterAck's core: it
// hands the plugin an NhpRegisterRequest carrying the authenticated pubkey, and
// returns the marshaled bytes of whatever ack the plugin returns.
func TestBuildRegisterAck_ScriptedAckAndPubKey(t *testing.T) {
	const aspID = "asp-reg-unit"
	pubKey := testPubkey(0xC1)
	wantPubB64 := base64.StdEncoding.EncodeToString(pubKey)

	scripted := &common.ServerRegisterAckMsg{ErrCode: common.ErrSuccess.ErrorCode(), AuthServiceId: aspID}
	plugin := &recordingRegOTPPlugin{regAck: scripted}
	s := newRegisterUnitServer(t, map[string]plugins.PluginHandler{aspID: plugin})

	rakBytes, err := s.buildRegisterAck(buildRegisterPpd(t, aspID, pubKey))
	if err != nil {
		t.Fatalf("buildRegisterAck returned error: %v", err)
	}
	// The plugin must have received the authenticated pubkey (bind target).
	if plugin.regGot == nil || plugin.regGot.PublicKey != wantPubB64 {
		t.Fatalf("plugin NhpRegisterRequest.PublicKey = %q, want %q (std-base64 of ppd.RemotePubKey)", func() string {
			if plugin.regGot == nil {
				return "<nil>"
			}
			return plugin.regGot.PublicKey
		}(), wantPubB64)
	}
	// The returned bytes must be the scripted ack.
	var got common.ServerRegisterAckMsg
	if err := json.Unmarshal(rakBytes, &got); err != nil {
		t.Fatalf("unmarshal RAK bytes: %v", err)
	}
	if got.ErrCode != common.ErrSuccess.ErrorCode() || got.AuthServiceId != aspID {
		t.Errorf("RAK = %+v, want the scripted success ack", got)
	}
}

// TestBuildRegisterAck_NoHandlerFailsClosed proves that when no plugin is
// registered for the aspId, buildRegisterAck returns (non-nil bytes, nil error)
// carrying ErrAuthHandlerNotFound — a fail-closed RAK, never a nil/`null` body.
func TestBuildRegisterAck_NoHandlerFailsClosed(t *testing.T) {
	// Empty plugin map AND an aspId that has no static registration, so
	// loadPluginOnce("no-such-asp", "") cannot load one either.
	s := newRegisterUnitServer(t, map[string]plugins.PluginHandler{})
	rakBytes, err := s.buildRegisterAck(buildRegisterPpd(t, "no-such-asp", testPubkey(0xC2)))
	if err != nil {
		t.Fatalf("buildRegisterAck returned error: %v (a no-handler case must be a fail-closed ack, not a returned error)", err)
	}
	var got common.ServerRegisterAckMsg
	if err := json.Unmarshal(rakBytes, &got); err != nil {
		t.Fatalf("unmarshal RAK bytes: %v", err)
	}
	if got.ErrCode != common.ErrAuthHandlerNotFound.ErrorCode() {
		t.Errorf("RAK.ErrCode = %q, want ErrAuthHandlerNotFound %q", got.ErrCode, common.ErrAuthHandlerNotFound.ErrorCode())
	}
}

// TestBuildRegisterAck_PluginErrorFailsClosed proves a plugin that returns
// (nil, ErrPluginNotRegistered) — the N3-pending stub shape — still yields a RAK
// with the mapped fail-closed errCode rather than a nil ack marshaled to `null`.
func TestBuildRegisterAck_PluginErrorFailsClosed(t *testing.T) {
	const aspID = "agent"
	s := newRegisterUnitServer(t, map[string]plugins.PluginHandler{aspID: &stubbedAgentPlugin{}})
	rakBytes, err := s.buildRegisterAck(buildRegisterPpd(t, aspID, testPubkey(0xC3)))
	if err != nil {
		t.Fatalf("buildRegisterAck returned error: %v (a plugin error must ride in the RAK, not be returned)", err)
	}
	if string(rakBytes) == "null" {
		t.Fatal("buildRegisterAck marshaled a nil ack to `null`; the RAK must always be a populated object")
	}
	var got common.ServerRegisterAckMsg
	if err := json.Unmarshal(rakBytes, &got); err != nil {
		t.Fatalf("unmarshal RAK bytes: %v", err)
	}
	if got.ErrCode != common.ErrRegistrationDisabled.ErrorCode() {
		t.Errorf("RAK.ErrCode = %q, want ErrRegistrationDisabled %q (bare ErrPluginNotRegistered maps to a concrete code)", got.ErrCode, common.ErrRegistrationDisabled.ErrorCode())
	}
}

// pluginErrAckKept returns a populated ack ALONGSIDE an error, modeling an N3
// plugin that sets its own reject code (e.g. bad OTP) and also returns an error.
type pluginErrAckKept struct {
	mockPluginHandler
}

func (*pluginErrAckKept) RegisterAgent(req *common.NhpRegisterRequest, _ *plugins.NhpServerPluginHelper) (*common.ServerRegisterAckMsg, error) {
	req.Ack.ErrCode = common.ErrRegistrationCredentialInvalid.ErrorCode()
	req.Ack.ErrMsg = "bad otp"
	return req.Ack, common.ErrRegistrationCredentialInvalid
}

// TestBuildRegisterAck_PluginProvidedRejectCodePreserved proves that when the
// plugin returns a populated ack with its OWN reject code alongside an error,
// buildRegisterAck preserves that code rather than overwriting it with the
// fallback — the plugin's specific verdict wins.
func TestBuildRegisterAck_PluginProvidedRejectCodePreserved(t *testing.T) {
	const aspID = "asp-reg-reject"
	s := newRegisterUnitServer(t, map[string]plugins.PluginHandler{aspID: &pluginErrAckKept{}})
	rakBytes, err := s.buildRegisterAck(buildRegisterPpd(t, aspID, testPubkey(0xC4)))
	if err != nil {
		t.Fatalf("buildRegisterAck returned error: %v", err)
	}
	var got common.ServerRegisterAckMsg
	if err := json.Unmarshal(rakBytes, &got); err != nil {
		t.Fatalf("unmarshal RAK bytes: %v", err)
	}
	if got.ErrCode != common.ErrRegistrationCredentialInvalid.ErrorCode() {
		t.Errorf("RAK.ErrCode = %q, want the plugin-provided ErrRegistrationCredentialInvalid %q (plugin verdict must not be overwritten)",
			got.ErrCode, common.ErrRegistrationCredentialInvalid.ErrorCode())
	}
}

// TestBuildRelayInnerReply_HeaderTypeParameterized proves buildRelayInnerReply
// stamps the caller-chosen header type onto the encrypted reply and the agent
// decrypts it under that type. Runs the same synthetic-decrypt → divert →
// agent-decrypt round-trip as the spike test, once per (NHP_ACK, NHP_RAK), so
// the type parameter is exercised for both reply kinds the relay return path
// serves.
func TestBuildRelayInnerReply_HeaderTypeParameterized(t *testing.T) {
	cases := []struct {
		name       string
		headerType int
	}{
		{"NHP_ACK", core.NHP_ACK},
		{"NHP_RAK", core.NHP_RAK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)
			serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x22, &core.DeviceOptions{DisableAgentPeerValidation: true})
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

			// Agent sends a REG as a real transaction so it can decrypt the reply.
			const innerTrx = uint64(20202)
			respCh := make(chan *core.PacketParserData, 1)
			agentConn := newSpikeConn(agentDev, agentToServerAddr)
			regBody, err := json.Marshal(&common.AgentRegisterMsg{UserId: "u", AuthServiceId: "asp"})
			if err != nil {
				t.Fatalf("marshal reg body: %v", err)
			}
			agentDev.SendMsgToPacket(&core.MsgData{
				ConnData:      agentConn,
				PeerPk:        serverPk,
				HeaderType:    core.NHP_REG,
				TransactionId: innerTrx,
				Message:       regBody,
				ResponseMsgCh: respCh,
			})
			innerREG := drainEncryptedPacket(t, agentConn)

			// Server synthetic-decrypts and diverts a reply of tc.headerType.
			s := &UdpServer{device: serverDev, listenConn: serverListen}
			innerPpd, cookie, innerConn, err := s.decryptRelayInnerKnock(innerREG, &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 44444})
			if err != nil {
				t.Fatalf("decryptRelayInnerKnock: %v", err)
			}
			if innerConn != nil {
				defer innerConn.Close()
			}
			if len(cookie) != 0 {
				t.Fatalf("decryptRelayInnerKnock returned unexpected overload cookie")
			}
			replyBody, err := json.Marshal(&common.ServerRegisterAckMsg{ErrCode: common.ErrSuccess.ErrorCode()})
			if err != nil {
				t.Fatalf("marshal reply body: %v", err)
			}
			replyPacket, err := s.buildRelayInnerReply(innerPpd, tc.headerType, replyBody)
			if err != nil {
				t.Fatalf("buildRelayInnerReply(%s): %v", tc.name, err)
			}
			if _, err := serverListen.WriteToUDP(replyPacket, relayAddr); err != nil {
				t.Fatalf("write inner reply(%s): %v", tc.name, err)
			}

			replyBytes := readUDPWithTimeout(t, relayListen, 5*time.Second)
			routeResponseToTransaction(t, agentDev, replyBytes)
			select {
			case serverPpd := <-respCh:
				if serverPpd.Error != nil {
					t.Fatalf("agent failed to decrypt %s reply: %v", tc.name, serverPpd.Error)
				}
				if serverPpd.HeaderType != tc.headerType {
					t.Errorf("agent decrypted header = %d, want %s (%d) — buildRelayInnerReply must stamp the caller's type",
						serverPpd.HeaderType, tc.name, tc.headerType)
				}
				if serverPpd.SenderTrxId != innerTrx {
					t.Errorf("reply counter = %d, want inner counter %d", serverPpd.SenderTrxId, innerTrx)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("agent never received the %s reply", tc.name)
			}
		})
	}
}
