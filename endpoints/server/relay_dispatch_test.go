package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

type recordingRegOTPPlugin struct {
	mockPluginHandler
	otpCalls  int
	otpGot    *common.NhpOTPRequest
	regCalls  int
	regGot    *common.NhpRegisterRequest
	regAck    *common.ServerRegisterAckMsg
	regErr    error
	listCalls int
	listGot   *common.NhpListRequest
	listAck   *common.ServerListResultMsg
	listErr   error
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

func (p *recordingRegOTPPlugin) ListService(req *common.NhpListRequest, _ *plugins.NhpServerPluginHelper) (*common.ServerListResultMsg, error) {
	p.listCalls++
	p.listGot = req
	return p.listAck, p.listErr
}

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

func buildRealRelayForwardOuterPpd(t *testing.T, s *UdpServer, relayAddr *net.UDPAddr, innerPacket []byte, src *common.NetAddress) (*core.PacketParserData, *core.Device, *core.ConnectionData) {
	t.Helper()
	if src == nil {
		src = &common.NetAddress{Ip: "203.0.113.7", Port: 44444}
	}
	rlyBytes, err := json.Marshal(&common.RelayForwardMsg{
		SourceAddr:  src,
		InnerPacket: base64.StdEncoding.EncodeToString(innerPacket),
		RequestID:   testRelayRequestID,
	})
	if err != nil {
		t.Fatalf("marshal RelayForwardMsg: %v", err)
	}
	serverAddr := s.listenConn.LocalAddr().(*net.UDPAddr)
	outerPpd, relayDev, relayConn := realOuterRelayRequest(t, s.device, serverAddr, relayAddr, rlyBytes)
	relayPubB64 := base64.StdEncoding.EncodeToString(outerPpd.RemotePubKey)
	s.relayPeerMap[relayPubB64] = &core.UdpPeer{PubKeyBase64: relayPubB64, Type: core.NHP_RELAY}
	return outerPpd, relayDev, relayConn
}

func readRealRelayInnerReturn(t *testing.T, relayListen *net.UDPConn, relayDev *core.Device, relayConn *core.ConnectionData, timeout time.Duration) []byte {
	t.Helper()
	outerBytes := readUDPWithTimeout(t, relayListen, timeout)
	returned := decryptRelayReturnForTest(t, relayDev, relayConn, outerBytes)
	if returned.RequestID != testRelayRequestID {
		t.Fatalf("RelayReturn request ID = %q, want %q", returned.RequestID, testRelayRequestID)
	}
	inner, err := base64.StdEncoding.DecodeString(returned.InnerPacket)
	if err != nil {
		t.Fatalf("decode RelayReturn inner packet: %v", err)
	}
	return inner
}

func TestHandleRelayForward_LifecycleTypesFailClosedBeforePluginDispatch(t *testing.T) {
	for _, tc := range []struct {
		name          string
		headerType    int
		wantBodyClear bool
	}{
		{name: "otp", headerType: core.NHP_OTP, wantBodyClear: true},
		{name: "register", headerType: core.NHP_REG, wantBodyClear: true},
		{name: "list", headerType: core.NHP_LST, wantBodyClear: true},
		{name: "register ack", headerType: core.NHP_RAK},
		{name: "list result", headerType: core.NHP_LRT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, vectors, _, _, _, _ := connectorRegistrationFixture(t)
			serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x82, &core.DeviceOptions{DisableAgentPeerValidation: true})
			agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x81, nil)
			serverListen := mustUDPListener(t)
			relayListen := mustUDPListener(t)
			plugin := &recordingRegOTPPlugin{}
			server := connectorRegistrationServer(t, newCapturingRegistrationAuthority(vectors), plugin)
			server.device = serverDev
			server.listenConn = serverListen
			server.relayPeerMap = make(map[string]*core.UdpPeer)
			server.pluginHandlerMap["other"] = plugin
			bodyCleared := false
			server.observeRelayRejectedBodyCleared = func(body []byte) {
				bodyCleared = allZero(body)
			}

			body := []byte(`{"usrId":"u","devId":"d","aspId":"other","pass":"secret"}`)
			inner := encryptRawInnerForRelay(
				t,
				agentDev,
				decodeBase64PubKey(serverDev.PublicKeyBase64()),
				tc.headerType,
				611,
				body,
			)
			outer, _, _ := buildRealRelayForwardOuterPpd(t, server, relayListen.LocalAddr().(*net.UDPAddr), inner, nil)
			server.HandleRelayForward(outer)

			if got := plugin.otpCalls + plugin.regCalls + plugin.listCalls; got != 0 {
				t.Fatalf("plugin lifecycle calls = %d, want 0", got)
			}
			if tc.wantBodyClear && !bodyCleared {
				t.Fatal("rejected relay lifecycle body was not cleared")
			}
			counters, _ := server.metrics.CountersForTest(t)
			if got := counters[MetricRelayForwardReject]; got != 1 {
				t.Fatalf("MetricRelayForwardReject = %v, want 1", got)
			}
			if err := relayListen.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			if n, _, err := relayListen.ReadFromUDP(make([]byte, 2048)); err == nil {
				t.Fatalf("retired lifecycle type emitted %d response bytes", n)
			} else if !isTimeout(err) {
				t.Fatalf("relay read: %v", err)
			}
		})
	}
}

func TestHandleRelayForward_InnerDHPKnock_ReturnsAuthenticatedACK(t *testing.T) {
	const innerTrx = uint64(171717)
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

	respCh := make(chan *core.PacketParserData, 1)
	agentConn := newSpikeConn(agentDev, agentToServerAddr)
	body, err := json.Marshal(&common.DHPKnockMsg{
		UserId: "dhp-user", DeviceId: "dev", Evidence: "not-valid-evidence",
	})
	if err != nil {
		t.Fatal(err)
	}
	agentDev.SendMsgToPacket(&core.MsgData{
		ConnData: agentConn, PeerPk: serverPk, HeaderType: core.DHP_KNK,
		TransactionId: innerTrx, Message: body, ResponseMsgCh: respCh,
	})
	innerDHP := drainEncryptedPacket(t, agentConn)

	relayPub := relayTestPubKey()
	relayPubB64 := base64.StdEncoding.EncodeToString(relayPub)
	s := &UdpServer{
		device: serverDev, metrics: metrics.NewPublisherForTest(t), listenConn: serverListen,
		relayPeerMap: map[string]*core.UdpPeer{
			relayPubB64: {PubKeyBase64: relayPubB64, Type: core.NHP_RELAY},
		},
	}
	privateSrc := &common.NetAddress{Ip: "127.0.0.1", Port: 44444}
	outerPpd, relayDev, relayConn := buildRealRelayForwardOuterPpd(t, s, relayAddr, innerDHP, privateSrc)
	s.HandleRelayForward(outerPpd)
	innerACK := readRealRelayInnerReturn(t, relayListen, relayDev, relayConn, 5*time.Second)
	routeResponseToTransaction(t, agentDev, innerACK)

	select {
	case ppd := <-respCh:
		if ppd.Error != nil {
			t.Fatalf("agent failed to decrypt relayed DHP ACK: %v", ppd.Error)
		}
		if ppd.HeaderType != core.NHP_ACK || ppd.SenderTrxId != innerTrx {
			t.Fatalf("DHP ACK header/counter = %s/%d, want NHP-ACK/%d", core.HeaderTypeToString(ppd.HeaderType), ppd.SenderTrxId, innerTrx)
		}
		var ack common.ServerDHPKnockAckMsg
		if err := json.Unmarshal(ppd.BodyMessage, &ack); err != nil {
			t.Fatal(err)
		}
		if ack.ErrCode != common.ErrEvidenceAppraisalFailed.ErrorCode() {
			t.Fatalf("DHP ACK ErrCode = %q, want %q", ack.ErrCode, common.ErrEvidenceAppraisalFailed.ErrorCode())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent never received relayed DHP ACK")
	}
}

func TestRegisterErrToCode(t *testing.T) {
	if got := registerErrToCode(plugins.ErrPluginNotRegistered); got != common.ErrRegistrationDisabled {
		t.Errorf("registerErrToCode(ErrPluginNotRegistered) = %v, want ErrRegistrationDisabled", got.ErrorCode())
	}
	if got := registerErrToCode(errors.New("some transient failure")); got != common.ErrRegistrationDisabled {
		t.Errorf("registerErrToCode(bare error) = %v, want ErrRegistrationDisabled", got.ErrorCode())
	}
	if got := registerErrToCode(common.ErrRegistrationRateLimited); got != common.ErrRegistrationRateLimited {
		t.Errorf("registerErrToCode(*common.Error) = %v, want the same error verbatim", got.ErrorCode())
	}
}

func TestListErrToCode(t *testing.T) {
	if got := listErrToCode(plugins.ErrPluginNotRegistered); got != common.ErrAuthHandlerNotFound {
		t.Errorf("listErrToCode(ErrPluginNotRegistered) = %v, want ErrAuthHandlerNotFound", got.ErrorCode())
	}
	if got := listErrToCode(common.ErrInvalidInput); got != common.ErrInvalidInput {
		t.Errorf("listErrToCode(*common.Error) = %v, want the same error verbatim", got.ErrorCode())
	}
}

func isTimeout(err error) bool {
	var nerr net.Error
	return errors.As(err, &nerr) && nerr.Timeout()
}

func TestHandleOTPRequest_DirectRateLimited(t *testing.T) {
	const aspID = "asp-otp-direct-rl"
	pubKey := testPubkey(0xD5)
	pubB64 := base64.StdEncoding.EncodeToString(pubKey)

	plugin := &recordingRegOTPPlugin{}
	t.Setenv("NHP_ENVIRONMENT", "prod")
	t.Setenv("NHP_CELL_ID", "cell7")
	mp := metrics.NewPublisherForTest(t)
	mp.SetBaseDimsForTest(t, buildServerMetricDimensions())
	otpRL := NewOTPRateLimiter(OTPRateLimiterConfig{
		Capacity: 1, RefillInterval: time.Hour,
		GlobalCapacity: 100, GlobalRate: 1,
		IdleTTL: time.Minute, MaxKeys: 16,
	})
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
		t.Fatalf("HandleOTPRequest rate-limited drop: %v", err)
	}
	if plugin.otpCalls != 0 {
		t.Errorf("plugin RequestOTP called %d times, want 0", plugin.otpCalls)
	}
	counters, dimCounters := mp.CountersForTest(t)
	if got := counters[MetricOTPRejectRateLimited]; got != 1 {
		t.Errorf("MetricOTPRejectRateLimited = %v, want 1", got)
	}
	const envBaseKey = MetricOTPRejectRateLimited + "\x00Environment=prod"
	if got := dimCounters[envBaseKey]; got != 1 {
		t.Errorf("[Environment]-only stream = %v, want 1; counters=%v", got, dimCounters)
	}
}

func TestDispatchOTP_LazyLoadsPluginViaLoadPluginOnce(t *testing.T) {
	const aspID = "asp-lazyload-otp"
	rec := &recordingRegOTPPlugin{}
	plugins.RegisterPlugin(aspID, func() plugins.PluginHandler { return rec })

	s := newLoadableTestServer(t)
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
		t.Fatalf("dispatchOTP: %v", err)
	}
	if rec.otpCalls != 1 {
		t.Fatalf("RequestOTP called %d times, want 1", rec.otpCalls)
	}
	if s.FindPluginHandler(aspID) == nil {
		t.Error("plugin was not installed by loadPluginOnce")
	}
}

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
