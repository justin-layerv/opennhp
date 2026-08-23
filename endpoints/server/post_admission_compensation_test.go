package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

type postAdmissionFailingACKTokenStore struct{}

func (postAdmissionFailingACKTokenStore) StoreACToken(context.Context, string, *ACTokenEntry) error {
	return errors.New("shared-store write failed (test)")
}

func (postAdmissionFailingACKTokenStore) LoadACToken(context.Context, string) (*ACTokenEntry, bool, error) {
	return nil, false, nil
}

type successfulRemoteAdmissionPlugin struct {
	fakePluginHandler
	onAdmitted func(*common.NhpAuthRequest)
}

type forwardedAdmissionJourneyPlugin struct {
	fakePluginHandler
	resource *common.ResourceData
}

func (p forwardedAdmissionJourneyPlugin) AuthWithNHP(req *common.NhpAuthRequest, helper *plugins.NhpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if helper == nil || helper.AuthWithNhpCallbackFunc == nil || p.resource == nil {
		return nil, errors.New("forwarded admission journey plugin is not wired")
	}
	return helper.AuthWithNhpCallbackFunc(req, p.resource)
}

// forwardedAdmissionJourneyOriginDeps keeps the NHP_FWD outer transport
// deterministic while executing the real ServerForwarder sender and receiver
// logic. The forwarded message still carries the original encrypted NHP_KNK;
// each receiver decrypts it through its own core.Device before AC admission.
type forwardedAdmissionJourneyOriginDeps struct {
	*MockForwarderDeps

	mu        sync.RWMutex
	receivers map[string]*ServerForwarder
	sent      atomic.Int32
}

func (d *forwardedAdmissionJourneyOriginDeps) addReceiver(addr *net.UDPAddr, receiver *ServerForwarder) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.receivers[addr.String()] = receiver
}

func (d *forwardedAdmissionJourneyOriginDeps) SendMessage(md *core.MsgData) error {
	if md == nil || md.HeaderType != core.NHP_FWD || md.RemoteAddr == nil {
		return fmt.Errorf("unexpected forwarded journey message: %+v", md)
	}
	var msg common.ServerForwardMsg
	if err := json.Unmarshal(md.Message, &msg); err != nil {
		return fmt.Errorf("decode forwarded journey message: %w", err)
	}
	d.mu.RLock()
	receiver := d.receivers[md.RemoteAddr.String()]
	d.mu.RUnlock()
	if receiver == nil {
		return fmt.Errorf("no forwarded journey receiver for %s", md.RemoteAddr)
	}
	d.sent.Add(1)
	go receiver.HandleForwardRequest(&core.PacketParserData{SenderTrxId: msg.TransactionId}, &msg)
	return nil
}

type forwardedAdmissionJourneyReceiverDeps struct {
	*MockForwarderDeps

	origin     *ServerForwarder
	acID       string
	admissions atomic.Int32
	sendErr    error
}

func (d *forwardedAdmissionJourneyReceiverDeps) SendMessage(md *core.MsgData) error {
	if md == nil || md.HeaderType != core.NHP_FRT {
		return fmt.Errorf("unexpected receiver journey message: %+v", md)
	}
	if d.sendErr != nil {
		return d.sendErr
	}
	if d.origin == nil {
		return errors.New("forwarded journey origin is missing")
	}
	var result common.ServerForwardResultMsg
	if err := json.Unmarshal(md.Message, &result); err != nil {
		return fmt.Errorf("decode receiver journey result: %w", err)
	}
	d.origin.HandleForwardResult(nil, &result)
	return nil
}

func TestHandleForwardRequestSuccessResultEnqueueFailureCompensatesExactSession(t *testing.T) {
	const (
		resourceID = "forward-send-failure-resource"
		acID       = "forward-send-failure-ac"
		sessionID  = uint64(906)
	)
	base := NewMockForwarderDeps()
	base.SetAuthServiceProvider(&common.AuthServiceProviderData{
		AuthSvcId: "generic",
		ResourceGroups: common.ResourceGroupMap{
			resourceID: {ResourceGroup: common.ResourceGroup{
				AuthServiceId: "generic", ResourceId: resourceID, OpenTime: 60,
				Resources: map[string]*common.ResourceInfo{
					resourceID: {ACId: acID, Hostname: "forward.internal", Addr: &common.NetAddress{Ip: "10.0.0.30", Port: 443}},
				},
			}},
		},
	})
	base.SetACConnection(&ACConn{ACId: acID})
	deps := &forwardedAdmissionJourneyReceiverDeps{
		MockForwarderDeps: base,
		acID:              acID,
		sendErr:           errors.New("immediate NHP_FRT enqueue failure"),
	}
	forwarder := NewServerForwarder(deps)
	agentKey := bytes.Repeat([]byte{0x63}, core.PublicKeySize)
	issuedAt := time.Now()
	body, err := json.Marshal(&common.AgentKnockMsg{HeaderType: core.NHP_KNK, UserId: "u", AuthServiceId: "generic", ResourceId: resourceID})
	if err != nil {
		t.Fatal(err)
	}
	forwarder.handleDecryptedForwardedKnock(
		&core.PacketParserData{},
		&common.ServerForwardMsg{SessionId: sessionID, SessionIssuedAtNanos: issuedAt.UnixNano(), TransactionId: 77},
		&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 44000},
		&core.PacketParserData{BodyMessage: body, RemotePubKey: agentKey},
	)
	if got := deps.admissions.Load(); got != 1 {
		t.Fatalf("forward receiver AC admissions = %d, want 1", got)
	}
	if testRegistryHasSession(base.forwardedSessions, sessionID) {
		t.Fatal("immediate successful NHP_FRT enqueue failure retained admitted exact session")
	}
}

func (d *forwardedAdmissionJourneyReceiverDeps) ProcessACOperationBroadcast(
	_ context.Context,
	knk *common.AgentKnockMsg,
	_ []*ACConn,
	_ *common.NetAddress,
	_ []*common.NetAddress,
	openTime uint32,
	_ *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	registry := d.forwardedSessions
	if registry == nil {
		return nil, errors.New("forwarded journey session registry is missing")
	}
	if err := registry.beginOpen(knk.NHPSessionId, knk.NHPSessionIssuedAt); err != nil {
		return nil, fmt.Errorf("begin forwarded journey AC admission: %w", err)
	}
	sessionExpiresAt := knk.NHPSessionIssuedAt.Add(time.Duration(openTime) * time.Second)
	if err := registry.finishOpen(
		knk.NHPSessionId,
		knk.NHPSessionIssuedAt,
		sessionExpiresAt,
		sessionExpiresAt.Add(time.Duration(ACOpenCompensationTime)*time.Second),
		d.acID,
		true,
	); err != nil {
		return nil, fmt.Errorf("finish forwarded journey AC admission: %w", err)
	}
	d.admissions.Add(1)
	return &common.ACOpsResultMsg{
		SessionId: knk.NHPSessionId,
		ErrCode:   common.ErrSuccess.ErrorCode(),
		ACToken:   "forwarded-journey-token",
		OpenTime:  openTime,
	}, nil
}

func (p successfulRemoteAdmissionPlugin) AuthWithNHP(req *common.NhpAuthRequest, _ *plugins.NhpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if p.onAdmitted != nil {
		p.onAdmitted(req)
	}
	return &common.ServerKnockAckMsg{ErrCode: common.ErrSuccess.ErrorCode(), OpenTime: 60}, nil
}

func TestHandleNhpOpenResourceTokenFailureClosesExactLocalSession(t *testing.T) {
	const sessionID = uint64(901)
	const acID = "ac-native-compensation"
	s, _ := newTestServerForBroadcast(t)
	s.ackTokenStore = postAdmissionFailingACKTokenStore{}
	s.tokenStore = common.NewTokenStore[*ACTokenEntry]()
	addLiveTestAC(t, s, acID, "10.0.0.20", 62206)
	agentKey := make([]byte, core.PublicKeySize)
	for i := range agentKey {
		agentKey[i] = byte(i + 1)
	}
	issuedAt := time.Now()
	if err := s.sessionRegistry().reserveExact(agentKey, sessionID, issuedAt, issuedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	s.processACOperationBroadcastFn = func(_ context.Context, knk *common.AgentKnockMsg, _ []*ACConn, _ *common.NetAddress, _ []*common.NetAddress, openTime uint32, _ *common.ResourceData) (*common.ACOpsResultMsg, error) {
		if err := s.sessionRegistry().beginOpen(knk.NHPSessionId, knk.NHPSessionIssuedAt); err != nil {
			t.Fatal(err)
		}
		expiresAt := knk.NHPSessionIssuedAt.Add(time.Duration(openTime) * time.Second)
		if err := s.sessionRegistry().finishOpen(knk.NHPSessionId, knk.NHPSessionIssuedAt, expiresAt, expiresAt.Add(time.Duration(ACOpenCompensationTime)*time.Second), acID, true); err != nil {
			t.Fatal(err)
		}
		return &common.ACOpsResultMsg{ErrCode: common.ErrSuccess.ErrorCode(), ACToken: "token-native", OpenTime: openTime}, nil
	}
	var closeCalls atomic.Int32
	s.processACSessionCloseFn = func(_ context.Context, gotSession uint64, _ *ACConn) error {
		if gotSession != sessionID {
			t.Errorf("closed session = %d, want %d", gotSession, sessionID)
		}
		closeCalls.Add(1)
		return nil
	}
	knock := &common.AgentKnockMsg{UserId: "u", AuthServiceId: "generic", ResourceId: "catalog-r", NHPSessionId: sessionID, NHPSessionIssuedAt: issuedAt}
	ack := &common.ServerKnockAckMsg{SessionId: sessionID, OpenTime: 60}
	req := &common.NhpAuthRequest{
		Msg: knock, Ack: ack, PublicKey: base64.StdEncoding.EncodeToString(agentKey),
		SrcAddr: &common.NetAddress{Ip: "198.51.100.9", Port: 1234}, SessionId: sessionID, SessionIssuedAt: issuedAt,
	}
	res := &common.ResourceData{ResourceGroup: common.ResourceGroup{ResourceId: "catalog-r", OpenTime: 60, Resources: map[string]*common.ResourceInfo{
		"catalog-r": {ACId: acID, Addr: &common.NetAddress{Ip: "10.0.0.30", Port: 443}},
	}}}
	if _, err := s.handleNhpOpenResource(req, res); err == nil {
		t.Fatal("token publication failure returned nil error")
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("exact local close calls = %d, want 1", got)
	}
	if testRegistryHasSession(s.sessionRegistry(), sessionID) {
		t.Fatal("failed native admission retained exact local session after successful compensation")
	}
}

func TestCompensateForwardedNHPSessionClosesExactLocalSession(t *testing.T) {
	const sessionID = uint64(903)
	const acID = "ac-forward-compensation"
	s, _ := newTestServerForBroadcast(t)
	addLiveTestAC(t, s, acID, "10.0.0.22", 62206)
	agentKey := make([]byte, core.PublicKeySize)
	for i := range agentKey {
		agentKey[i] = byte(0x80 + i)
	}
	issuedAt := time.Now()
	activateTestAgentSession(t, s, agentKey, sessionID, issuedAt, issuedAt.Add(time.Minute), acID)
	var closeCalls atomic.Int32
	s.processACSessionCloseFn = func(context.Context, uint64, *ACConn) error {
		closeCalls.Add(1)
		return nil
	}
	if !s.CompensateForwardedNHPSession(base64.StdEncoding.EncodeToString(agentKey), sessionID, issuedAt) {
		t.Fatal("forwarded exact-session compensation failed")
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("forwarded exact close calls = %d, want 1", got)
	}
	if testRegistryHasSession(s.sessionRegistry(), sessionID) {
		t.Fatal("forwarded exact session remained after compensation")
	}
}

func TestHandleKnockRequestSendFailureCompensatesRemoteAdmissions(t *testing.T) {
	for _, test := range []struct {
		name          string
		peerCount     int
		fanoutEnabled bool
	}{
		{name: "no-local ForwardKnock", peerCount: 1},
		{name: "multi-peer FanoutKnock", peerCount: 2, fanoutEnabled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			const (
				authServiceID = "forwarded-journey"
				resourceID    = "forwarded-journey-resource"
				acID          = "forwarded-journey-ac"
			)

			signer := newFleetCloseTestSigner(t)
			type peerHarness struct {
				id         string
				server     *UdpServer
				http       *httptest.Server
				host       string
				port       int
				nhpNode    *E2ETestNode
				nhpAddr    *net.UDPAddr
				receiver   *ServerForwarder
				deps       *forwardedAdmissionJourneyReceiverDeps
				closeCalls *atomic.Int32
			}

			sharedServerKey := bytes.Repeat([]byte{0x4d}, core.PrivateKeySize)
			clientNode := newE2ETestNodeWithType(t, "forwarded-journey-agent", core.NHP_AGENT)
			clientNode.Start()
			defer clientNode.Stop()

			origin, _ := newTestServerForBroadcast(t)
			originNode := newE2ETestNodeFull(t, "forwarded-journey-origin", core.NHP_SERVER, sharedServerKey, nil)
			originNode.Start()
			defer originNode.Stop()
			originNode.AddPeer(clientNode)
			origin.device = originNode.device
			origin.fleetCloseSigner = signer
			configureFleetCloseTestOrigin(origin, "i-origin", "127.0.0.1", 8888)
			origin.tokenStore = common.NewTokenStore[*ACTokenEntry]()
			origin.authServiceMap = common.AuthSvcProviderMap{
				authServiceID: {AuthSvcId: authServiceID},
			}
			resource := &common.ResourceData{ResourceGroup: common.ResourceGroup{
				AuthServiceId: authServiceID,
				ResourceId:    resourceID,
				OpenTime:      60,
				Resources: map[string]*common.ResourceInfo{
					resourceID: {
						ACId:     acID,
						Hostname: "forwarded-journey.internal",
						Addr:     &common.NetAddress{Ip: "10.0.0.30", Port: 443},
					},
				},
			}}
			origin.pluginHandlerMap = map[string]plugins.PluginHandler{
				authServiceID: forwardedAdmissionJourneyPlugin{resource: resource},
			}

			originDeps := &forwardedAdmissionJourneyOriginDeps{
				MockForwarderDeps: NewMockForwarderDeps(),
				receivers:         make(map[string]*ServerForwarder),
			}
			originDeps.SetDevice(origin.device)
			originForwarder := NewServerForwarder(originDeps)
			origin.forwarder = originForwarder

			peers := make([]peerHarness, 0, test.peerCount)
			for i := 0; i < test.peerCount; i++ {
				peerID := "i-peer-" + strconv.Itoa(i)
				peer, _ := newTestServerForBroadcast(t)
				peer.fleetCloseSigner = signer
				peer.cloudMap = &CloudMapClient{
					cachedInstances: []ServerInfo{{ID: "i-origin", InternalIP: origin.localIp, HTTPPort: 8888}},
					instancesExpiry: time.Now().Add(time.Minute),
					discoverFreshFn: func(context.Context) ([]ServerInfo, error) {
						return []ServerInfo{{ID: "i-origin", InternalIP: origin.localIp, HTTPPort: 8888}}, nil
					},
				}
				addLiveTestAC(t, peer, acID, "10.0.0."+strconv.Itoa(40+i), 62206)
				peerCloseCalls := &atomic.Int32{}
				peer.processACSessionCloseFn = func(context.Context, uint64, *ACConn) error {
					peerCloseCalls.Add(1)
					return nil
				}

				hs := &HttpServer{udpServer: peer}
				gin.SetMode(gin.TestMode)
				router := gin.New()
				router.Use(func(ctx *gin.Context) {
					ctx.Request.RemoteAddr = net.JoinHostPort(origin.localIp, "43123")
					ctx.Next()
				})
				router.POST(exactSessionCloseFleetPath, hs.handleInternalExactSessionClose)
				peerHTTP := httptest.NewServer(router)
				parsed, err := url.Parse(peerHTTP.URL)
				if err != nil {
					t.Fatal(err)
				}
				port, err := strconv.Atoi(parsed.Port())
				if err != nil {
					t.Fatal(err)
				}

				nhpNode := newE2ETestNodeFull(t, peerID, core.NHP_SERVER, sharedServerKey, nil)
				nhpNode.Start()
				nhpNode.AddPeer(clientNode)
				deps := &forwardedAdmissionJourneyReceiverDeps{
					MockForwarderDeps: NewMockForwarderDeps(),
					origin:            originForwarder,
					acID:              acID,
				}
				deps.SetDevice(nhpNode.device)
				deps.SetAuthServiceProvider(&common.AuthServiceProviderData{
					AuthSvcId: authServiceID,
					ResourceGroups: common.ResourceGroupMap{
						resourceID: resource,
					},
				})
				deps.SetACConnection(&ACConn{ACId: acID})
				deps.forwardedSessions = peer.sessionRegistry()
				receiver := NewServerForwarder(deps)
				nhpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0." + strconv.Itoa(i+2)), Port: nhpNode.addr.Port}
				originDeps.addReceiver(nhpAddr, receiver)
				peers = append(peers, peerHarness{
					id: peerID, server: peer, http: peerHTTP, host: parsed.Hostname(), port: port,
					nhpNode: nhpNode, nhpAddr: nhpAddr, receiver: receiver, deps: deps, closeCalls: peerCloseCalls,
				})
			}
			defer func() {
				for _, peer := range peers {
					peer.http.Close()
					peer.nhpNode.Stop()
				}
			}()

			origin.fleetCloseHTTPClient = peers[0].http.Client()
			targets := []ServerInfo{{ID: "i-origin", InternalIP: origin.localIp, HTTPPort: 8888}}
			for _, peer := range peers {
				targets = append(targets, ServerInfo{ID: peer.id, InternalIP: peer.host, HTTPPort: peer.port})
			}
			origin.cloudMap = &CloudMapClient{discoverFreshFn: func(context.Context) ([]ServerInfo, error) { return targets, nil }}

			assignment := &ACAssignment{ACID: acID, AssignedServers: make([]ServerInfo, 0, len(peers)+1)}
			if test.fanoutEnabled {
				assignment.AssignedServers = append(assignment.AssignedServers, ServerInfo{
					ID: "i-origin", InternalIP: origin.localIp, Port: 62206, AZ: "test-a", PubKey: origin.device.PublicKeyBase64(),
				})
			}
			for i, peer := range peers {
				assignment.AssignedServers = append(assignment.AssignedServers, ServerInfo{
					ID: peer.id, InternalIP: peer.nhpAddr.IP.String(), Port: peer.nhpAddr.Port,
					AZ: "test-" + string(rune('b'+i)), PubKey: peer.nhpNode.publicKey,
				})
			}
			storage := NewMemoryStorage()
			if err := storage.SaveACAssignment(context.Background(), assignment); err != nil {
				t.Fatal(err)
			}
			origin.storage = storage

			var localAdmissions, localCloseCalls atomic.Int32
			if test.fanoutEnabled {
				origin.config = &Config{EnableKnockACFanout: true}
				addLiveTestAC(t, origin, acID, "10.0.0.10", 62206)
				origin.processACOperationBroadcastFn = func(_ context.Context, knk *common.AgentKnockMsg, _ []*ACConn, _ *common.NetAddress, _ []*common.NetAddress, openTime uint32, _ *common.ResourceData) (*common.ACOpsResultMsg, error) {
					if err := origin.sessionRegistry().beginOpen(knk.NHPSessionId, knk.NHPSessionIssuedAt); err != nil {
						return nil, err
					}
					sessionExpiresAt := knk.NHPSessionIssuedAt.Add(time.Duration(openTime) * time.Second)
					if err := origin.sessionRegistry().finishOpen(knk.NHPSessionId, knk.NHPSessionIssuedAt, sessionExpiresAt, sessionExpiresAt.Add(time.Duration(ACOpenCompensationTime)*time.Second), acID, true); err != nil {
						return nil, err
					}
					localAdmissions.Add(1)
					return &common.ACOpsResultMsg{SessionId: knk.NHPSessionId, ErrCode: common.ErrSuccess.ErrorCode(), ACToken: "origin-token", OpenTime: openTime}, nil
				}
				origin.processACSessionCloseFn = func(context.Context, uint64, *ACConn) error {
					localCloseCalls.Add(1)
					return nil
				}
			}

			knock := &common.AgentKnockMsg{HeaderType: core.NHP_KNK, UserId: "u", AuthServiceId: authServiceID, ResourceId: resourceID}
			body, err := json.Marshal(knock)
			if err != nil {
				t.Fatal(err)
			}
			encryptedKnock, err := captureEncryptedPacket(clientNode, peers[0].nhpNode, core.NHP_KNK, body)
			if err != nil {
				t.Fatal(err)
			}
			remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.20"), Port: 44000}
			conn := &core.ConnectionData{
				Device:               origin.device,
				RemoteAddr:           remoteAddr,
				RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
				StopSignal:           make(chan struct{}),
			}
			ppd, err := origin.device.PacketToMsg(&core.PacketData{
				BasePacket: &core.Packet{Content: slices.Clone(encryptedKnock)},
				ConnData:   conn,
				InitTime:   time.Now().UnixNano(),
			})
			if err != nil {
				t.Fatalf("decrypt origin journey knock: %v", err)
			}
			ppd.ConnData.RemoteTransactionMap = make(map[uint64]*core.RemoteTransaction)
			if err := origin.HandleKnockRequest(ppd); err == nil {
				t.Fatal("missing response transaction did not surface ACK send failure")
			}
			origin.agentSessionCloseWorkerWG.Wait()

			if got := originDeps.sent.Load(); got != int32(test.peerCount) {
				t.Fatalf("actual NHP_FWD messages = %d, want %d", got, test.peerCount)
			}
			if test.fanoutEnabled && localAdmissions.Load() != 1 {
				t.Fatalf("origin local AC admissions = %d, want 1 alongside FanoutKnock", localAdmissions.Load())
			}
			if !test.fanoutEnabled && localAdmissions.Load() != 0 {
				t.Fatalf("origin local AC admissions = %d, want 0 on no-local ForwardKnock", localAdmissions.Load())
			}
			wantLocalClose := int32(0)
			if test.fanoutEnabled {
				wantLocalClose = 1
			}
			if got := localCloseCalls.Load(); got != wantLocalClose {
				t.Fatalf("origin exact AC close calls = %d, want %d", got, wantLocalClose)
			}
			for i, peer := range peers {
				peer.server.agentSessionCloseWorkerWG.Wait()
				if got := peer.deps.admissions.Load(); got != 1 {
					t.Fatalf("peer %d HandleForwardRequest AC admissions = %d, want 1", i, got)
				}
				if got := peer.closeCalls.Load(); got != 1 {
					t.Fatalf("peer %d exact AC close calls = %d, want 1", i, got)
				}
				peer.server.sessionRegistry().mu.Lock()
				remaining := len(peer.server.sessionRegistry().sessions)
				peer.server.sessionRegistry().mu.Unlock()
				if remaining != 0 {
					t.Fatalf("peer %d retained %d exact session(s) after ACK send failure", i, remaining)
				}
			}
		})
	}
}
