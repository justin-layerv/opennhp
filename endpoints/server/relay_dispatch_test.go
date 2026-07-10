package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	agentplugin "github.com/OpenNHP/opennhp/endpoints/server/staticplugins/agent"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// ============================================================================
// Mock plugins for the OTP/REG dispatch arms (agent-registration N2).
//
// These record whether the plugin was reached and let a test script the
// RegisterAgent result, so the dispatch behavior (reached? reply? fail-closed
// shape?) can be asserted without the real (N3-pending) agent plugin.
// ============================================================================

// recordingRegOTPPlugin embeds mockPluginHandler (httpauth_test.go) and records
// OTP/Register calls. RegisterAgent's return is scripted by regAck/regErr.
type recordingRegOTPPlugin struct {
	mockPluginHandler
	otpCalls int
	otpGot   *common.NhpOTPRequest
	regCalls int
	regGot   *common.NhpRegisterRequest
	regAck   *common.ServerRegisterAckMsg
	regErr   error
}

func (p *recordingRegOTPPlugin) RequestOTP(req *common.NhpOTPRequest, _ *plugins.NhpServerPluginHelper) error {
	p.otpCalls++
	p.otpGot = req
	return nil
}

func (p *recordingRegOTPPlugin) RegisterAgent(req *common.NhpRegisterRequest, _ *plugins.NhpServerPluginHelper) (*common.ServerRegisterAckMsg, error) {
	p.regCalls++
	p.regGot = req
	return p.regAck, p.regErr
}

// stubbedAgentPlugin models the N3-pending agent plugin: RequestOTP and
// RegisterAgent both return plugins.ErrPluginNotRegistered (a bare errors.New
// with NO errCode), exactly like staticplugins/agent/plugin.go today. Used to
// prove the fail-closed RAK shape while N3 is unimplemented.
type stubbedAgentPlugin struct {
	mockPluginHandler
	otpCalls int
}

func (p *stubbedAgentPlugin) RequestOTP(*common.NhpOTPRequest, *plugins.NhpServerPluginHelper) error {
	p.otpCalls++
	return plugins.ErrPluginNotRegistered
}

func (p *stubbedAgentPlugin) RegisterAgent(*common.NhpRegisterRequest, *plugins.NhpServerPluginHelper) (*common.ServerRegisterAckMsg, error) {
	return nil, plugins.ErrPluginNotRegistered
}

// buildRelayForwardOuterPpd wraps an inner packet in an NHP_RLY outerPpd the way
// the responder hands one to HandleRelayForward, with the relay authenticated as
// a registered NHP_RELAY peer.
func buildRelayForwardOuterPpd(t *testing.T, relayPub []byte, relayAddr *net.UDPAddr, innerPacket []byte) *core.PacketParserData {
	t.Helper()
	rlyBytes, err := json.Marshal(&common.RelayForwardMsg{
		SourceAddr:  &common.NetAddress{Ip: "203.0.113.7", Port: 44444},
		InnerPacket: base64.StdEncoding.EncodeToString(innerPacket),
	})
	if err != nil {
		t.Fatalf("marshal RelayForwardMsg: %v", err)
	}
	return &core.PacketParserData{
		HeaderType:   core.NHP_RLY,
		RemotePubKey: relayPub,
		ConnData:     &core.ConnectionData{RemoteAddr: relayAddr},
		BodyMessage:  rlyBytes,
	}
}

// ============================================================================
// Inner NHP_OTP: fire-and-forget — plugin reached, NOTHING sent on the divert.
// ============================================================================

func TestHandleRelayForward_InnerOTP_DispatchesPluginNoReply(t *testing.T) {
	const aspID = "asp-otp-relay"
	serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x22, &core.DeviceOptions{DisableAgentPeerValidation: true})
	agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)
	serverPk := decodeBase64PubKey(serverDev.PublicKeyBase64())
	agentPkB64 := agentDev.PublicKeyBase64()

	serverListen := mustUDPListener(t) // any reply would be written from here
	relayListen := mustUDPListener(t)  // stands in for the relay; a reply would land here
	relayAddr := relayListen.LocalAddr().(*net.UDPAddr)

	innerOTP := encryptInnerForRelay(t, agentDev, serverPk, core.NHP_OTP, 9001, &common.AgentOTPMsg{
		UserId: "u", DeviceId: "d", AuthServiceId: aspID,
	})

	relayPub := relayTestPubKey()
	relayPubB64 := base64.StdEncoding.EncodeToString(relayPub)
	plugin := &recordingRegOTPPlugin{}
	mp := metrics.NewPublisherForTest(t)
	s := &UdpServer{
		device:           serverDev,
		metrics:          mp,
		relayPeerMap:     map[string]*core.UdpPeer{relayPubB64: {PubKeyBase64: relayPubB64, Type: core.NHP_RELAY}},
		listenConn:       serverListen,
		pluginHandlerMap: map[string]plugins.PluginHandler{aspID: plugin},
	}

	s.HandleRelayForward(buildRelayForwardOuterPpd(t, relayPub, relayAddr, innerOTP))

	// The plugin's RequestOTP must have been reached with the authenticated key.
	if plugin.otpCalls != 1 {
		t.Fatalf("plugin RequestOTP called %d times, want 1 (relayed OTP must reach the OTP dispatch)", plugin.otpCalls)
	}
	if plugin.otpGot == nil || plugin.otpGot.PublicKey != agentPkB64 {
		t.Errorf("OTP request PublicKey = %q, want authenticated agent key %q", func() string {
			if plugin.otpGot == nil {
				return "<nil>"
			}
			return plugin.otpGot.PublicKey
		}(), agentPkB64)
	}

	// FIRE-AND-FORGET: absolutely nothing may be written back toward the relay.
	if err := relayListen.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 4096)
	if n, _, err := relayListen.ReadFromUDP(buf); err == nil {
		t.Fatalf("relayed OTP produced a %d-byte reply; OTP is fire-and-forget and must send NOTHING", n)
	} else if !isTimeout(err) {
		t.Fatalf("unexpected read error waiting to prove no OTP reply: %v", err)
	}

	counters, _ := mp.CountersForTest(t)
	if got := counters[MetricRelayOTP]; got != 1 {
		t.Errorf("MetricRelayOTP = %v, want 1", got)
	}
	if got := counters[MetricRelayForwardReject]; got != 0 {
		t.Errorf("MetricRelayForwardReject = %v, want 0 (OTP is admitted, not rejected)", got)
	}
}

// TestHandleRelayForward_InnerOTP_RateLimitedDropsSilently proves the pre-plugin
// OTP rate limiter shed drops with NO reply and NO plugin call, and ticks the
// rate-limited metric. The limiter is pre-drained for the agent's key so the
// very first relayed OTP is shed.
func TestHandleRelayForward_InnerOTP_RateLimitedDropsSilently(t *testing.T) {
	const aspID = "asp-otp-rl"
	serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x22, &core.DeviceOptions{DisableAgentPeerValidation: true})
	agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)
	serverPk := decodeBase64PubKey(serverDev.PublicKeyBase64())
	agentPkB64 := agentDev.PublicKeyBase64()

	serverListen := mustUDPListener(t)
	relayListen := mustUDPListener(t)
	relayAddr := relayListen.LocalAddr().(*net.UDPAddr)

	innerOTP := encryptInnerForRelay(t, agentDev, serverPk, core.NHP_OTP, 9002, &common.AgentOTPMsg{
		UserId: "u", AuthServiceId: aspID,
	})

	relayPub := relayTestPubKey()
	relayPubB64 := base64.StdEncoding.EncodeToString(relayPub)
	plugin := &recordingRegOTPPlugin{}
	mp := metrics.NewPublisherForTest(t)

	// Capacity-1 limiter, then drain the agent key so the request under test is shed.
	otpRL := NewOTPRateLimiter(OTPRateLimiterConfig{Capacity: 1, RefillInterval: time.Hour, GlobalCapacity: 100, GlobalRate: 1, IdleTTL: time.Minute, MaxKeys: 16})
	if !otpRL.Allow(agentPkB64) {
		t.Fatal("precondition: first Allow should pass to drain the single token")
	}

	s := &UdpServer{
		device:           serverDev,
		metrics:          mp,
		relayPeerMap:     map[string]*core.UdpPeer{relayPubB64: {PubKeyBase64: relayPubB64, Type: core.NHP_RELAY}},
		listenConn:       serverListen,
		pluginHandlerMap: map[string]plugins.PluginHandler{aspID: plugin},
		otpRateLimiter:   otpRL,
	}

	s.HandleRelayForward(buildRelayForwardOuterPpd(t, relayPub, relayAddr, innerOTP))

	if plugin.otpCalls != 0 {
		t.Errorf("plugin RequestOTP called %d times, want 0 (rate limiter must shed BEFORE the plugin)", plugin.otpCalls)
	}
	if err := relayListen.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 4096)
	if n, _, err := relayListen.ReadFromUDP(buf); err == nil {
		t.Fatalf("rate-limited OTP produced a %d-byte reply; a shed OTP must send nothing", n)
	} else if !isTimeout(err) {
		t.Fatalf("unexpected read error: %v", err)
	}

	counters, _ := mp.CountersForTest(t)
	if got := counters[MetricOTPRejectRateLimited]; got != 1 {
		t.Errorf("MetricOTPRejectRateLimited = %v, want 1", got)
	}
	// The OTP still passed the inner-type gate (counted) before being shed at the limiter.
	if got := counters[MetricRelayOTP]; got != 1 {
		t.Errorf("MetricRelayOTP = %v, want 1 (the gate admits it; the limiter sheds it afterwards)", got)
	}
}

// ============================================================================
// Inner NHP_REG: produces a counter-correlated NHP_RAK, agent-decryptable.
// A scripted mock returns a success ack; the RAK must ride the inner cipher
// state back to the RELAY address and decrypt on the agent's transaction.
// ============================================================================

func TestHandleRelayForward_InnerREG_DeliversCounterCorrelatedRAK(t *testing.T) {
	const aspID = "asp-reg-relay"
	serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x22, &core.DeviceOptions{DisableAgentPeerValidation: true})
	agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)
	serverPk := decodeBase64PubKey(serverDev.PublicKeyBase64())

	serverListen := mustUDPListener(t)
	relayListen := mustUDPListener(t)
	relayAddr := relayListen.LocalAddr().(*net.UDPAddr)

	// The agent must hold the server peer to decrypt the RAK response leg.
	agentToServerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62206}
	agentDev.AddPeer(&core.UdpPeer{
		PubKeyBase64: serverDev.PublicKeyBase64(),
		Ip:           agentToServerAddr.IP.String(),
		Port:         agentToServerAddr.Port,
		Type:         core.NHP_SERVER,
	})

	// Send NHP_REG as a real agent transaction so the agent can decrypt the RAK.
	const innerTrx = uint64(131313)
	respCh := make(chan *core.PacketParserData, 1)
	agentConn := newSpikeConn(agentDev, agentToServerAddr)
	regBody, err := json.Marshal(&common.AgentRegisterMsg{UserId: "reg-user", AuthServiceId: aspID, OTP: "123456"})
	if err != nil {
		t.Fatalf("marshal register body: %v", err)
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

	relayPub := relayTestPubKey()
	relayPubB64 := base64.StdEncoding.EncodeToString(relayPub)
	scriptedAck := &common.ServerRegisterAckMsg{ErrCode: common.ErrSuccess.ErrorCode(), AuthServiceId: aspID}
	plugin := &recordingRegOTPPlugin{regAck: scriptedAck}
	mp := metrics.NewPublisherForTest(t)
	s := &UdpServer{
		device:           serverDev,
		metrics:          mp,
		relayPeerMap:     map[string]*core.UdpPeer{relayPubB64: {PubKeyBase64: relayPubB64, Type: core.NHP_RELAY}},
		listenConn:       serverListen,
		pluginHandlerMap: map[string]plugins.PluginHandler{aspID: plugin},
	}

	s.HandleRelayForward(buildRelayForwardOuterPpd(t, relayPub, relayAddr, innerREG))

	if plugin.regCalls != 1 {
		t.Fatalf("plugin RegisterAgent called %d times, want 1", plugin.regCalls)
	}

	// The RAK must arrive at the RELAY's address and decrypt on the agent's txn.
	rakBytes := readUDPWithTimeout(t, relayListen, 5*time.Second)
	routeResponseToTransaction(t, agentDev, rakBytes)
	select {
	case serverPpd := <-respCh:
		if serverPpd.Error != nil {
			t.Fatalf("agent failed to decrypt relayed RAK: %v", serverPpd.Error)
		}
		if serverPpd.HeaderType != core.NHP_RAK {
			t.Fatalf("agent decrypted header = %d, want NHP_RAK", serverPpd.HeaderType)
		}
		if serverPpd.SenderTrxId != innerTrx {
			t.Errorf("RAK counter = %d, want inner REG counter %d", serverPpd.SenderTrxId, innerTrx)
		}
		var rak common.ServerRegisterAckMsg
		if err := json.Unmarshal(serverPpd.BodyMessage, &rak); err != nil {
			t.Fatalf("unmarshal decrypted RAK: %v", err)
		}
		if rak.ErrCode != common.ErrSuccess.ErrorCode() {
			t.Errorf("RAK.ErrCode = %q, want success %q (scripted ack)", rak.ErrCode, common.ErrSuccess.ErrorCode())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent never received the decrypted relayed RAK")
	}

	counters, _ := mp.CountersForTest(t)
	if got := counters[MetricRelayRegister]; got != 1 {
		t.Errorf("MetricRelayRegister = %v, want 1", got)
	}
}

// TestHandleRelayForward_InnerREG_StubbedPluginFailsClosed proves the inertness
// N2 relies on: with the agent plugin still stubbed (RegisterAgent returns the
// bare plugins.ErrPluginNotRegistered, exactly like staticplugins/agent today),
// the relayed REG still produces a decryptable RAK — carrying the mapped
// fail-closed errCode (ErrRegistrationDisabled), NOT a silent drop and NOT a
// success. This is the "reaches dispatch, returns a fail-closed RAK" contract.
func TestHandleRelayForward_InnerREG_StubbedPluginFailsClosed(t *testing.T) {
	const aspID = "agent"
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

	const innerTrx = uint64(141414)
	respCh := make(chan *core.PacketParserData, 1)
	agentConn := newSpikeConn(agentDev, agentToServerAddr)
	regBody, err := json.Marshal(&common.AgentRegisterMsg{UserId: "reg-user", AuthServiceId: aspID})
	if err != nil {
		t.Fatalf("marshal register body: %v", err)
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

	relayPub := relayTestPubKey()
	relayPubB64 := base64.StdEncoding.EncodeToString(relayPub)
	mp := metrics.NewPublisherForTest(t)
	s := &UdpServer{
		device:           serverDev,
		metrics:          mp,
		relayPeerMap:     map[string]*core.UdpPeer{relayPubB64: {PubKeyBase64: relayPubB64, Type: core.NHP_RELAY}},
		listenConn:       serverListen,
		pluginHandlerMap: map[string]plugins.PluginHandler{aspID: &stubbedAgentPlugin{}},
	}

	s.HandleRelayForward(buildRelayForwardOuterPpd(t, relayPub, relayAddr, innerREG))

	rakBytes := readUDPWithTimeout(t, relayListen, 5*time.Second)
	routeResponseToTransaction(t, agentDev, rakBytes)
	select {
	case serverPpd := <-respCh:
		if serverPpd.Error != nil {
			t.Fatalf("agent failed to decrypt fail-closed RAK: %v", serverPpd.Error)
		}
		if serverPpd.HeaderType != core.NHP_RAK {
			t.Fatalf("agent decrypted header = %d, want NHP_RAK", serverPpd.HeaderType)
		}
		var rak common.ServerRegisterAckMsg
		if err := json.Unmarshal(serverPpd.BodyMessage, &rak); err != nil {
			t.Fatalf("unmarshal decrypted RAK: %v", err)
		}
		if rak.ErrCode != common.ErrRegistrationDisabled.ErrorCode() {
			t.Errorf("fail-closed RAK.ErrCode = %q, want ErrRegistrationDisabled %q (a bare ErrPluginNotRegistered must map to a concrete registration errCode)",
				rak.ErrCode, common.ErrRegistrationDisabled.ErrorCode())
		}
		if common.IsSuccessErrCode(rak.ErrCode) {
			t.Error("fail-closed RAK reported success; the stubbed plugin must fail CLOSED")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent never received the fail-closed RAK (N3-pending REG must still reply, not drop)")
	}
}

// ============================================================================
// N3 END-TO-END: the REAL agent plugin (staticplugins/agent), flag ON, wired to
// a FAKE qurl-service, driven through the real relay dispatch. Proves the whole
// N2→N3 seam: a relayed NHP_REG reaches the agent plugin's RegisterAgent, which
// calls qurl-service /internal/v1/agent/register, and the mapped verdict rides a
// counter-correlated NHP_RAK back to the agent's transaction. Unlike the
// mock-plugin tests above, this exercises registrar.go + plugin.go + the errCode
// mapping for real.
//
// A SINGLE fake qurl-service (with a swappable handler) backs every sub-case.
// The real agent plugin's registrar is injected via InstallRegistrarForTest,
// which bypasses agent.Init's process-wide sync.Once — so this test does not
// race any other server test that may load the "agent" plugin (and consume that
// Once) with a disabled config.
// ============================================================================

// agentE2EHandler is a mutable qurl-service fake: the current sub-case swaps in
// the response it wants behind the one stable URL agent.Init captured.
type agentE2EHandler struct {
	mu sync.Mutex
	fn http.HandlerFunc
}

func (h *agentE2EHandler) set(fn http.HandlerFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fn = fn
}

func (h *agentE2EHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	fn := h.fn
	h.mu.Unlock()
	if fn == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	fn(w, r)
}

func TestHandleRelayForward_InnerREG_RealAgentPluginE2E(t *testing.T) {
	const aspID = "agent"

	// One fake qurl-service for the whole test; sub-cases swap the handler.
	handler := &agentE2EHandler{}
	qurl := httptest.NewServer(handler)
	t.Cleanup(qurl.Close)

	// Enable the real agent plugin against the fake by injecting its registrar
	// directly (bypasses the global Init Once — see the section header).
	agentplugin.InstallRegistrarForTest(t, qurl.URL, "e2e-service-token")
	// The real handler; RegisterAgent populates the RAK via the injected registrar.
	realAgent := agentplugin.New()

	// Drive one relayed NHP_REG through HandleRelayForward and return the RAK the
	// agent decrypts on its own transaction.
	driveREG := func(t *testing.T, innerTrx uint64) common.ServerRegisterAckMsg {
		t.Helper()
		serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x22, &core.DeviceOptions{DisableAgentPeerValidation: true})
		agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)
		serverPk := decodeBase64PubKey(serverDev.PublicKeyBase64())

		serverListen := mustUDPListener(t)
		relayListen := mustUDPListener(t)
		relayAddr := relayListen.LocalAddr().(*net.UDPAddr)

		agentToServerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62210}
		agentDev.AddPeer(&core.UdpPeer{
			PubKeyBase64: serverDev.PublicKeyBase64(),
			Ip:           agentToServerAddr.IP.String(),
			Port:         agentToServerAddr.Port,
			Type:         core.NHP_SERVER,
		})

		respCh := make(chan *core.PacketParserData, 1)
		agentConn := newSpikeConn(agentDev, agentToServerAddr)
		regBody, err := json.Marshal(&common.AgentRegisterMsg{
			UserId: "ak_e2e", DeviceId: "dev_e2e", AuthServiceId: aspID, OTP: "OTP-E2E",
			UserData: map[string]any{"hostname": "e2e-host", "takeover": false},
		})
		if err != nil {
			t.Fatalf("marshal register body: %v", err)
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

		relayPub := relayTestPubKey()
		relayPubB64 := base64.StdEncoding.EncodeToString(relayPub)
		s := &UdpServer{
			device:           serverDev,
			metrics:          metrics.NewPublisherForTest(t),
			relayPeerMap:     map[string]*core.UdpPeer{relayPubB64: {PubKeyBase64: relayPubB64, Type: core.NHP_RELAY}},
			listenConn:       serverListen,
			pluginHandlerMap: map[string]plugins.PluginHandler{aspID: realAgent},
		}

		s.HandleRelayForward(buildRelayForwardOuterPpd(t, relayPub, relayAddr, innerREG))

		rakBytes := readUDPWithTimeout(t, relayListen, 5*time.Second)
		routeResponseToTransaction(t, agentDev, rakBytes)
		select {
		case serverPpd := <-respCh:
			if serverPpd.Error != nil {
				t.Fatalf("agent failed to decrypt relayed RAK: %v", serverPpd.Error)
			}
			if serverPpd.HeaderType != core.NHP_RAK {
				t.Fatalf("agent decrypted header = %d, want NHP_RAK", serverPpd.HeaderType)
			}
			if serverPpd.SenderTrxId != innerTrx {
				t.Errorf("RAK counter = %d, want inner REG counter %d", serverPpd.SenderTrxId, innerTrx)
			}
			var rak common.ServerRegisterAckMsg
			if err := json.Unmarshal(serverPpd.BodyMessage, &rak); err != nil {
				t.Fatalf("unmarshal decrypted RAK: %v", err)
			}
			return rak
		case <-time.After(5 * time.Second):
			t.Fatal("agent never received the decrypted relayed RAK")
		}
		return common.ServerRegisterAckMsg{}
	}

	t.Run("qurl-service success → RAK ErrCode 0", func(t *testing.T) {
		var gotPath, gotToken string
		handler.set(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotToken = r.Header.Get("X-Service-Token")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":true,"data":{"agent_id":"agt_e2e"}}`))
		})

		rak := driveREG(t, 202020)

		if gotPath != "/internal/v1/agent/register" {
			t.Errorf("qurl-service path = %q, want /internal/v1/agent/register", gotPath)
		}
		if gotToken != "e2e-service-token" {
			t.Errorf("X-Service-Token = %q, want e2e-service-token", gotToken)
		}
		if rak.ErrCode != common.ErrSuccess.ErrorCode() {
			t.Errorf("RAK.ErrCode = %q, want success %q", rak.ErrCode, common.ErrSuccess.ErrorCode())
		}
		if rak.AuthServiceId != aspID {
			t.Errorf("RAK.aspId = %q, want %q", rak.AuthServiceId, aspID)
		}
	})

	t.Run("qurl-service credential_invalid → RAK 52100", func(t *testing.T) {
		handler.set(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"error":{"code":"credential_invalid","message":"bad otp"}}`))
		})

		rak := driveREG(t, 212121)

		if rak.ErrCode != common.ErrRegistrationCredentialInvalid.ErrorCode() {
			t.Errorf("RAK.ErrCode = %q, want ErrRegistrationCredentialInvalid %q (mapped end-to-end)",
				rak.ErrCode, common.ErrRegistrationCredentialInvalid.ErrorCode())
		}
		if common.IsSuccessErrCode(rak.ErrCode) {
			t.Error("credential_invalid produced a success RAK; must fail closed")
		}
	})

	t.Run("qurl-service rate_limited → RAK 52104", func(t *testing.T) {
		handler.set(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"success":false,"error":{"code":"rate_limited"}}`))
		})

		rak := driveREG(t, 222222)

		if rak.ErrCode != common.ErrRegistrationRateLimited.ErrorCode() {
			t.Errorf("RAK.ErrCode = %q, want ErrRegistrationRateLimited %q", rak.ErrCode, common.ErrRegistrationRateLimited.ErrorCode())
		}
	})
}

// ============================================================================
// TYPE-DEPENDENT SOURCE-ADDRESS GATE: OTP/REG accept a private/loopback relay
// source (they open no AC pinhole; SourceAddr is only informational), while KNK
// from the SAME private source is still rejected by the routable-public gate.
// This pins the split introduced for the registration path — a same-host smoke
// test / dev relay must not silently drop a registration.
// ============================================================================

// buildRelayForwardOuterPpdSrc is buildRelayForwardOuterPpd with a caller-chosen
// SourceAddr (so a test can supply a private/loopback source).
func buildRelayForwardOuterPpdSrc(t *testing.T, relayPub []byte, relayAddr *net.UDPAddr, innerPacket []byte, src *common.NetAddress) *core.PacketParserData {
	t.Helper()
	rlyBytes, err := json.Marshal(&common.RelayForwardMsg{SourceAddr: src, InnerPacket: base64.StdEncoding.EncodeToString(innerPacket)})
	if err != nil {
		t.Fatalf("marshal RelayForwardMsg: %v", err)
	}
	return &core.PacketParserData{
		HeaderType:   core.NHP_RLY,
		RemotePubKey: relayPub,
		ConnData:     &core.ConnectionData{RemoteAddr: relayAddr},
		BodyMessage:  rlyBytes,
	}
}

func TestHandleRelayForward_PrivateSource_RegistrationAcceptedKnockRejected(t *testing.T) {
	const aspID = "asp-src-split"
	// A loopback source — the same-host dev/smoke relay case that MUST work for
	// registration but MUST NOT open an AC pinhole via a knock.
	privateSrc := &common.NetAddress{Ip: "127.0.0.1", Port: 40000}

	newServer := func(t *testing.T, plugin plugins.PluginHandler) (*UdpServer, *core.Device, []byte, *net.UDPConn, *net.UDPAddr, *metrics.Publisher) {
		serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x22, &core.DeviceOptions{DisableAgentPeerValidation: true})
		serverPk := decodeBase64PubKey(serverDev.PublicKeyBase64())
		serverListen := mustUDPListener(t)
		relayListen := mustUDPListener(t)
		relayPub := relayTestPubKey()
		relayPubB64 := base64.StdEncoding.EncodeToString(relayPub)
		mp := metrics.NewPublisherForTest(t)
		s := &UdpServer{
			device:           serverDev,
			metrics:          mp,
			relayPeerMap:     map[string]*core.UdpPeer{relayPubB64: {PubKeyBase64: relayPubB64, Type: core.NHP_RELAY}},
			listenConn:       serverListen,
			pluginHandlerMap: map[string]plugins.PluginHandler{aspID: plugin},
		}
		_ = serverPk
		return s, serverDev, relayPub, relayListen, relayListen.LocalAddr().(*net.UDPAddr), mp
	}

	t.Run("OTP from private source is accepted (forwarded, no reply)", func(t *testing.T) {
		plugin := &recordingRegOTPPlugin{}
		s, serverDev, relayPub, _, relayAddr, mp := newServer(t, plugin)
		serverPk := decodeBase64PubKey(serverDev.PublicKeyBase64())
		agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)
		innerOTP := encryptInnerForRelay(t, agentDev, serverPk, core.NHP_OTP, 5001, &common.AgentOTPMsg{UserId: "u", AuthServiceId: aspID})

		s.HandleRelayForward(buildRelayForwardOuterPpdSrc(t, relayPub, relayAddr, innerOTP, privateSrc))

		if plugin.otpCalls != 1 {
			t.Fatalf("OTP from a private source: RequestOTP called %d times, want 1 (registration opens no pinhole; a private source must be accepted)", plugin.otpCalls)
		}
		counters, _ := mp.CountersForTest(t)
		if got := counters[MetricRelayForwardReject]; got != 0 {
			t.Errorf("MetricRelayForwardReject = %v, want 0 (a private source must NOT be rejected on the OTP path)", got)
		}
	})

	t.Run("REG from private source is accepted (RAK produced)", func(t *testing.T) {
		plugin := &recordingRegOTPPlugin{regAck: &common.ServerRegisterAckMsg{ErrCode: common.ErrSuccess.ErrorCode(), AuthServiceId: aspID}}
		s, serverDev, relayPub, relayListen, relayAddr, mp := newServer(t, plugin)
		serverPk := decodeBase64PubKey(serverDev.PublicKeyBase64())
		agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)
		innerREG := encryptInnerForRelay(t, agentDev, serverPk, core.NHP_REG, 5002, &common.AgentRegisterMsg{UserId: "u", AuthServiceId: aspID})

		s.HandleRelayForward(buildRelayForwardOuterPpdSrc(t, relayPub, relayAddr, innerREG, privateSrc))

		if plugin.regCalls != 1 {
			t.Fatalf("REG from a private source: RegisterAgent called %d times, want 1 (a private source must be accepted on the REG path)", plugin.regCalls)
		}
		// A RAK must have been written toward the relay (registration replies);
		// readUDPWithTimeout fails the test itself if nothing arrives.
		_ = readUDPWithTimeout(t, relayListen, 3*time.Second)
		counters, _ := mp.CountersForTest(t)
		if got := counters[MetricRelayForwardReject]; got != 0 {
			t.Errorf("MetricRelayForwardReject = %v, want 0 (a private source must NOT be rejected on the REG path)", got)
		}
	})

	t.Run("KNK from the same private source is still rejected", func(t *testing.T) {
		plugin := &recordingRegOTPPlugin{}
		s, serverDev, relayPub, relayListen, relayAddr, mp := newServer(t, plugin)
		serverPk := decodeBase64PubKey(serverDev.PublicKeyBase64())
		agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)
		innerKNK := encryptInnerForRelay(t, agentDev, serverPk, core.NHP_KNK, 5003, &common.AgentKnockMsg{
			HeaderType: core.NHP_KNK, UserId: "u", AuthServiceId: aspID, ResourceId: "res",
		})

		s.HandleRelayForward(buildRelayForwardOuterPpdSrc(t, relayPub, relayAddr, innerKNK, privateSrc))

		counters, _ := mp.CountersForTest(t)
		if got := counters[MetricRelayForwardReject]; got != 1 {
			t.Errorf("MetricRelayForwardReject = %v, want 1 (a private source on the KNK path opens an AC pinhole and MUST be rejected)", got)
		}
		// No reply may have been written for the rejected knock.
		if err := relayListen.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		buf := make([]byte, 4096)
		if n, _, err := relayListen.ReadFromUDP(buf); err == nil {
			t.Fatalf("rejected private-source KNK produced a %d-byte reply; a pre-auth drop must send nothing", n)
		} else if !isTimeout(err) {
			t.Fatalf("unexpected read error: %v", err)
		}
	})
}

// TestRegisterErrToCode covers the plugin-error → RAK errCode mapping directly.
func TestRegisterErrToCode(t *testing.T) {
	// A bare error (the ErrPluginNotRegistered shape) maps to ErrRegistrationDisabled.
	if got := registerErrToCode(plugins.ErrPluginNotRegistered); got != common.ErrRegistrationDisabled {
		t.Errorf("registerErrToCode(ErrPluginNotRegistered) = %v, want ErrRegistrationDisabled", got.ErrorCode())
	}
	if got := registerErrToCode(errors.New("some transient failure")); got != common.ErrRegistrationDisabled {
		t.Errorf("registerErrToCode(bare error) = %v, want ErrRegistrationDisabled", got.ErrorCode())
	}
	// A *common.Error is used verbatim (its own code survives).
	if got := registerErrToCode(common.ErrRegistrationRateLimited); got != common.ErrRegistrationRateLimited {
		t.Errorf("registerErrToCode(*common.Error) = %v, want the same error verbatim", got.ErrorCode())
	}
}

// isTimeout reports whether err is a net i/o timeout (read deadline elapsed).
func isTimeout(err error) bool {
	var nerr net.Error
	return errors.As(err, &nerr) && nerr.Timeout()
}

// TestHandleOTPRequest_DirectRateLimited proves the pre-plugin OTP limiter also
// gates the DIRECT (agent→server UDP) OTP path, not just the relayed one: a
// drained limiter sheds the request BEFORE the plugin, returns nil (fire-and-
// forget, no error surfaced to the dispatcher), and ticks the rate-limited
// metric. Shares dispatchOTP with the relay path, so this pins the direct arm.
func TestHandleOTPRequest_DirectRateLimited(t *testing.T) {
	const aspID = "asp-otp-direct-rl"
	pubKey := testPubkey(0xD5)
	pubB64 := base64.StdEncoding.EncodeToString(pubKey)

	plugin := &recordingRegOTPPlugin{}
	// Source Environment + Cell from the env exactly as production does — both the
	// publisher base dims (buildServerMetricDimensions) and the explicit
	// [Environment]-only shed emit (buildServerEnvDimension) read NHP_ENVIRONMENT,
	// so t.Setenv keeps them consistent (and proves the shed emits the fleet-wide
	// base stream the launch-blocking T1 alarm binds to, not just the per-Cell one).
	t.Setenv("NHP_ENVIRONMENT", "prod")
	t.Setenv("NHP_CELL_ID", "cell7")
	mp := metrics.NewPublisherForTest(t)
	mp.SetBaseDimsForTest(t, buildServerMetricDimensions()) // [Environment=prod, Cell=cell7]
	otpRL := NewOTPRateLimiter(OTPRateLimiterConfig{Capacity: 1, RefillInterval: time.Hour, GlobalCapacity: 100, GlobalRate: 1, IdleTTL: time.Minute, MaxKeys: 16})
	if !otpRL.Allow(pubB64) {
		t.Fatal("precondition: first Allow should drain the single token")
	}
	s := &UdpServer{
		device:           core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil),
		metrics:          mp,
		pluginHandlerMap: map[string]plugins.PluginHandler{aspID: plugin},
		otpRateLimiter:   otpRL,
	}
	t.Cleanup(s.device.Stop)

	body, err := json.Marshal(&common.AgentOTPMsg{UserId: "u", AuthServiceId: aspID})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ppd := &core.PacketParserData{
		ConnData:     &core.ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40000}},
		HeaderType:   core.NHP_OTP,
		BodyMessage:  body,
		RemotePubKey: pubKey,
	}
	if err := s.HandleOTPRequest(ppd); err != nil {
		t.Fatalf("HandleOTPRequest returned error on a rate-limited drop: %v (a shed OTP is fire-and-forget, no error)", err)
	}
	if plugin.otpCalls != 0 {
		t.Errorf("plugin RequestOTP called %d times, want 0 (the limiter must shed before the plugin)", plugin.otpCalls)
	}
	counters, dimCounters := mp.CountersForTest(t)
	if got := counters[MetricOTPRejectRateLimited]; got != 1 {
		t.Errorf("MetricOTPRejectRateLimited = %v, want 1", got)
	}
	// DUAL-PUBLISH: the shed must ALSO emit an explicit [Environment]-only stream —
	// the exact dim set the launch-blocking T1 alarm selects on. Without it, the
	// metric lands only at the publisher base [Environment, Cell] and the
	// {Environment} alarm never binds (INSUFFICIENT_DATA → silently green). Key
	// format mirrors buildDimCounterKey (name\x00Dim=Val), like the RelayShed test.
	const envBaseKey = MetricOTPRejectRateLimited + "\x00Environment=prod"
	if got := dimCounters[envBaseKey]; got != 1 {
		t.Errorf("[Environment]-only base stream %q = %v, want 1 (the launch-blocking OTP-shed alarm binds to this exact dim set; a plain IncrCounter at [Environment, Cell] would leave it unarmed); got dimCounters=%v", envBaseKey, got, dimCounters)
	}
	// And it must NOT have leaked a Cell into the base stream (that would be the
	// [Environment, Cell] breakdown, not the fleet-wide base the alarm needs).
	if _, hasCell := dimCounters[MetricOTPRejectRateLimited+"\x00Cell=cell7\x00Environment=prod"]; hasCell {
		t.Errorf("base stream unexpectedly carried a Cell dim; the explicit base emit must be [Environment]-only. dimCounters=%v", dimCounters)
	}
}

// TestDispatchOTP_LazyLoadsPluginViaLoadPluginOnce fences Scope item 5: unlike
// the knock path (which warms the plugin via the DDB resolve bridge on knock),
// the OTP/REG dispatch calls FindPluginHandler DIRECTLY — a plain map read with
// no lazy load — so dispatchOTP/buildRegisterAck must call loadPluginOnce first.
// Here the plugin is registered in the STATIC REGISTRY but the server's
// pluginHandlerMap starts EMPTY (as it would before any knock warmed it); a
// single dispatchOTP must lazily load it and reach RequestOTP. Without the
// explicit loadPluginOnce this would find no handler and return
// ErrAuthHandlerNotFound.
func TestDispatchOTP_LazyLoadsPluginViaLoadPluginOnce(t *testing.T) {
	// A registry aspId unique to this test; register a factory that returns a
	// recording plugin and clean it out afterwards so no other test sees it.
	const aspID = "asp-lazyload-otp"
	rec := &recordingRegOTPPlugin{}
	plugins.RegisterPlugin(aspID, func() plugins.PluginHandler { return rec })

	s := newLoadableTestServer(t)

	// Precondition: the handler is NOT in the map yet (no knock warmed it).
	if s.FindPluginHandler(aspID) != nil {
		t.Fatal("precondition: pluginHandlerMap must start without the aspId")
	}

	body, err := json.Marshal(&common.AgentOTPMsg{UserId: "u", AuthServiceId: aspID})
	if err != nil {
		t.Fatalf("marshal AgentOTPMsg: %v", err)
	}
	ppd := &core.PacketParserData{
		ConnData:     &core.ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40000}},
		SenderTrxId:  7,
		HeaderType:   core.NHP_OTP,
		BodyMessage:  body,
		RemotePubKey: testPubkey(0xD0),
	}

	if err := s.dispatchOTP(ppd); err != nil {
		t.Fatalf("dispatchOTP returned error: %v (the plugin should have been lazily loaded and RequestOTP reached)", err)
	}
	if rec.otpCalls != 1 {
		t.Fatalf("RequestOTP called %d times, want 1 (dispatchOTP must loadPluginOnce before FindPluginHandler)", rec.otpCalls)
	}
	// The plugin must now be resident in the map (loadPluginOnce installed it).
	if s.FindPluginHandler(aspID) == nil {
		t.Error("after dispatchOTP, FindPluginHandler still nil — loadPluginOnce did not install the handler")
	}
}

// newLoadableTestServer builds a UdpServer whose plugin-load path is fully
// exercisable: a real device, an empty pluginHandlerMap, a test metrics
// publisher, and — critically — a real logger + config so LoadPlugin's h.Init
// (which reads s.log/s.config) does not nil-deref. Logs go to a temp dir.
func newLoadableTestServer(t *testing.T) *UdpServer {
	t.Helper()
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("core.NewDevice returned nil")
	}
	t.Cleanup(device.Stop)
	lg := log.NewLogger("test-server", log.LogLevelError, t.TempDir(), "server")
	t.Cleanup(lg.Close)
	return &UdpServer{
		device:           device,
		metrics:          metrics.NewPublisherForTest(t),
		pluginHandlerMap: map[string]plugins.PluginHandler{},
		log:              lg,
		config:           &Config{Hostname: "test-host"},
	}
}
