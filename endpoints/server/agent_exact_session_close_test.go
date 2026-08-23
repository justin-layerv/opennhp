package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

type exactRetirementTestStore struct {
	*memorySessionControlStore
	current      sessionControlSessionAuthority
	resolveErr   error
	closeErr     error
	resolveCalls int
	closeCalls   int
}

func (s *exactRetirementTestStore) ResolveExactSessionForClose(_ context.Context,
	selector sessionControlExactRetirementSelector,
) (*sessionControlSessionAuthority, error) {
	s.resolveCalls++
	if s.resolveErr != nil {
		return nil, s.resolveErr
	}
	if !sessionControlExactRetirementSelectorMatchesCandidate(selector, s.current.Candidate) {
		return nil, errSessionControlSessionNotFound
	}
	copy := s.current
	return &copy, nil
}

func (s *exactRetirementTestStore) EnsureExactSessionClose(_ context.Context,
	candidate sessionControlSessionCandidate, retainUntilMillis int64,
) (*sessionControlExactClosePreparation, error) {
	s.closeCalls++
	if s.closeErr != nil {
		return nil, s.closeErr
	}
	if candidate != s.current.Candidate || retainUntilMillis != s.current.RetainUntilMillis {
		return nil, errSessionControlSessionConflict
	}
	closing := s.current
	closing.State = sessionControlSessionStateClosing
	closing.CloseEventID = sessionControlExactCloseEventID(candidate)
	return &sessionControlExactClosePreparation{EventID: closing.CloseEventID, Session: closing}, nil
}

func exactRetirementTestPacket(t *testing.T, candidate sessionControlSessionCandidate, agentKey []byte) *core.PacketParserData {
	t.Helper()
	body, err := json.Marshal(common.AgentExactSessionCloseMsg{
		HeaderType: core.NHP_EXT, AuthServiceID: common.RegisteredAgentAuthServiceID,
		CellID: candidate.CellID, SessionID: candidate.SessionID,
		SessionIssuedAtMillis: candidate.IssuedAtMillis, RunID: candidate.RunID, RunAttempt: candidate.RunAttempt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &core.PacketParserData{
		HeaderType: core.NHP_EXT, BodyMessage: body, RemotePubKey: bytes.Clone(agentKey),
		ConnData: &core.ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 49152}},
	}
}

func newExactRetirementHandlerFixture(t *testing.T) (*UdpServer, *exactRetirementTestStore,
	sessionControlSessionCandidate, []byte,
) {
	t.Helper()
	agentKey := bytes.Repeat([]byte{0x91}, core.PublicKeySize)
	candidate := sessionControlSessionCandidate{
		CellID: "cell-01", AgentPublicKey: base64.StdEncoding.EncodeToString(agentKey), SessionID: 901,
		IssuedAtMillis: 1_800_000_000_000, ReservationDeadlineMillis: 1_800_000_030_000,
		RunID: "0123456789abcdef", RunAttempt: 2,
	}
	current, err := planSessionControlReservation(candidate, testSessionControlSessionSnapshot(1))
	if err != nil {
		t.Fatal(err)
	}
	current.RetainUntilMillis = candidate.ReservationDeadlineMillis + time.Minute.Milliseconds()
	store := &exactRetirementTestStore{memorySessionControlStore: newMemorySessionControlStore(time.UnixMilli(candidate.IssuedAtMillis)), current: current}
	server := &UdpServer{
		sessionControlStore: store, sessionControlCellID: candidate.CellID,
		metrics: metrics.NewPublisherForTest(t),
	}
	return server, store, candidate, agentKey
}

func TestBuildAgentExactSessionCloseAckPreparesOnlyTheReceiptSession(t *testing.T) {
	server, store, candidate, agentKey := newExactRetirementHandlerFixture(t)
	ackBytes, userID, admission, err := server.buildKnockAckWithAdmission(exactRetirementTestPacket(t, candidate, agentKey))
	if err != nil || userID != "" || admission != nil {
		t.Fatalf("exact close result = user %q admission %#v err %v", userID, admission, err)
	}
	var ack common.ServerExactSessionCloseAckMsg
	if err := json.Unmarshal(ackBytes, &ack); err != nil {
		t.Fatal(err)
	}
	wantEvent := sessionControlExactCloseEventID(candidate)
	if !common.IsSuccessErrCode(ack.ErrCode) || ack.SessionID != candidate.SessionID ||
		ack.CellID != candidate.CellID || ack.SessionIssuedAtMillis != candidate.IssuedAtMillis ||
		ack.RunID != candidate.RunID || ack.RunAttempt != candidate.RunAttempt ||
		ack.CloseEventID != wantEvent || ack.State != sessionControlSessionStateClosing {
		t.Fatalf("exact close ACK = %#v", ack)
	}
	if store.resolveCalls != 1 || store.closeCalls != 1 {
		t.Fatalf("exact close calls = resolve %d close %d, want 1/1", store.resolveCalls, store.closeCalls)
	}
}

func TestBuildAgentExactSessionCloseAckReplaysTerminalSession(t *testing.T) {
	server, store, candidate, agentKey := newExactRetirementHandlerFixture(t)
	store.current.State = sessionControlSessionStateClosed
	store.current.CloseEventID = sessionControlExactCloseEventID(candidate)
	ackBytes, _, admission, err := server.buildKnockAckWithAdmission(exactRetirementTestPacket(t, candidate, agentKey))
	if err != nil || admission != nil {
		t.Fatalf("terminal replay = admission %#v err %v", admission, err)
	}
	var ack common.ServerExactSessionCloseAckMsg
	if err := json.Unmarshal(ackBytes, &ack); err != nil {
		t.Fatal(err)
	}
	if !common.IsSuccessErrCode(ack.ErrCode) || ack.State != sessionControlSessionStateClosed ||
		ack.CloseEventID != store.current.CloseEventID || store.closeCalls != 0 {
		t.Fatalf("terminal exact close ACK/calls = %#v/%d", ack, store.closeCalls)
	}
}

func TestBuildAgentExactSessionCloseAckRejectsNonDeterministicTerminalEvent(t *testing.T) {
	server, store, candidate, agentKey := newExactRetirementHandlerFixture(t)
	store.current.State = sessionControlSessionStateClosed
	store.current.CloseEventID = "0123456789abcdef0123456789abcdef"
	if store.current.CloseEventID == sessionControlExactCloseEventID(candidate) {
		t.Fatal("test event unexpectedly equals the deterministic event")
	}
	ackBytes, _, admission, err := server.buildKnockAckWithAdmission(exactRetirementTestPacket(t, candidate, agentKey))
	if err != nil || admission != nil {
		t.Fatalf("non-deterministic terminal replay = admission %#v err %v", admission, err)
	}
	var ack common.ServerExactSessionCloseAckMsg
	if err := json.Unmarshal(ackBytes, &ack); err != nil {
		t.Fatal(err)
	}
	if common.IsSuccessErrCode(ack.ErrCode) || ack.CloseEventID != "" || store.closeCalls != 0 {
		t.Fatalf("non-deterministic terminal ACK/calls = %#v/%d", ack, store.closeCalls)
	}
}

func TestBuildAgentExactSessionCloseAckRejectsReceiptDriftAndStoreFailure(t *testing.T) {
	for name, mutate := range map[string]func(*common.AgentExactSessionCloseMsg){
		"cell":     func(request *common.AgentExactSessionCloseMsg) { request.CellID = "cell-02" },
		"session":  func(request *common.AgentExactSessionCloseMsg) { request.SessionID++ },
		"issuance": func(request *common.AgentExactSessionCloseMsg) { request.SessionIssuedAtMillis++ },
		"run":      func(request *common.AgentExactSessionCloseMsg) { request.RunID = "fedcba9876543210" },
		"attempt":  func(request *common.AgentExactSessionCloseMsg) { request.RunAttempt++ },
	} {
		t.Run(name, func(t *testing.T) {
			server, store, candidate, agentKey := newExactRetirementHandlerFixture(t)
			packet := exactRetirementTestPacket(t, candidate, agentKey)
			var request common.AgentExactSessionCloseMsg
			if err := json.Unmarshal(packet.BodyMessage, &request); err != nil {
				t.Fatal(err)
			}
			mutate(&request)
			packet.BodyMessage, _ = json.Marshal(request)
			ackBytes, _, admission, err := server.buildKnockAckWithAdmission(packet)
			if err != nil || admission != nil {
				t.Fatalf("drift result = admission %#v err %v", admission, err)
			}
			var ack common.ServerExactSessionCloseAckMsg
			if err := json.Unmarshal(ackBytes, &ack); err != nil {
				t.Fatal(err)
			}
			if common.IsSuccessErrCode(ack.ErrCode) || ack.SessionID != 0 || store.closeCalls != 0 {
				t.Fatalf("drift ACK/calls = %#v/%d", ack, store.closeCalls)
			}
		})
	}

	t.Run("authenticated agent", func(t *testing.T) {
		server, store, candidate, _ := newExactRetirementHandlerFixture(t)
		wrongKey := bytes.Repeat([]byte{0x92}, core.PublicKeySize)
		ackBytes, _, _, err := server.buildKnockAckWithAdmission(exactRetirementTestPacket(t, candidate, wrongKey))
		if err != nil {
			t.Fatal(err)
		}
		var ack common.ServerExactSessionCloseAckMsg
		_ = json.Unmarshal(ackBytes, &ack)
		if common.IsSuccessErrCode(ack.ErrCode) || ack.SessionID != 0 || store.closeCalls != 0 {
			t.Fatalf("wrong-agent ACK/calls = %#v/%d", ack, store.closeCalls)
		}
	})

	t.Run("store failure", func(t *testing.T) {
		server, store, candidate, agentKey := newExactRetirementHandlerFixture(t)
		store.closeErr = errors.New("write unavailable")
		ackBytes, _, _, err := server.buildKnockAckWithAdmission(exactRetirementTestPacket(t, candidate, agentKey))
		if err != nil {
			t.Fatal(err)
		}
		var ack common.ServerExactSessionCloseAckMsg
		_ = json.Unmarshal(ackBytes, &ack)
		if common.IsSuccessErrCode(ack.ErrCode) || ack.SessionID != 0 || store.closeCalls != 1 {
			t.Fatalf("store-failure ACK/calls = %#v/%d", ack, store.closeCalls)
		}
	})
}

func TestBuildAgentExactSessionCloseAckRejectsLegacyResourceEXTBeforeAdmission(t *testing.T) {
	server, store, _, agentKey := newExactRetirementHandlerFixture(t)
	legacyBody := []byte(`{"headerType":3,"usrId":"agent","devId":"agent","aspId":"agent","resId":"resource","runId":"0123456789abcdef","runAttempt":1}`)
	ackBytes, _, admission, err := server.buildKnockAckWithAdmission(&core.PacketParserData{
		HeaderType: core.NHP_EXT, BodyMessage: legacyBody, RemotePubKey: agentKey,
		ConnData: &core.ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 49152}},
	})
	if err != nil || admission != nil {
		t.Fatalf("legacy EXT = admission %#v err %v", admission, err)
	}
	var ack common.ServerExactSessionCloseAckMsg
	if err := json.Unmarshal(ackBytes, &ack); err != nil {
		t.Fatal(err)
	}
	if common.IsSuccessErrCode(ack.ErrCode) || ack.SessionID != 0 || store.resolveCalls != 0 || store.closeCalls != 0 {
		t.Fatalf("legacy EXT ACK/store calls = %#v/%d/%d", ack, store.resolveCalls, store.closeCalls)
	}
}

func directExactRetirementRequest(t *testing.T) (*UdpServer, *exactRetirementTestStore,
	sessionControlSessionCandidate, *core.Device, *core.PacketParserData, <-chan *core.PacketParserData,
	*core.RemoteTransaction,
) {
	t.Helper()
	serverDevice := newSpikeDevice(t, core.NHP_SERVER, 0xa2, &core.DeviceOptions{DisableAgentPeerValidation: true})
	agentDevice := newSpikeDevice(t, core.NHP_AGENT, 0xa1, nil)
	serverListener := mustUDPListener(t)
	agentListener := mustUDPListener(t)
	candidate := sessionControlSessionCandidate{
		CellID: "cell-01", AgentPublicKey: agentDevice.PublicKeyBase64(), SessionID: 903,
		IssuedAtMillis: 1_800_000_000_000, ReservationDeadlineMillis: 1_800_000_030_000,
		RunID: "0123456789abcdef", RunAttempt: 4,
	}
	current, err := planSessionControlReservation(candidate, testSessionControlSessionSnapshot(1))
	if err != nil {
		t.Fatal(err)
	}
	current.RetainUntilMillis = candidate.ReservationDeadlineMillis + time.Minute.Milliseconds()
	store := &exactRetirementTestStore{
		memorySessionControlStore: newMemorySessionControlStore(time.UnixMilli(candidate.IssuedAtMillis)),
		current:                   current,
	}
	server := &UdpServer{
		device: serverDevice, listenConn: serverListener, metrics: metrics.NewPublisherForTest(t),
		sessionControlCellID: candidate.CellID, sessionControlStore: store,
	}
	body, err := json.Marshal(common.AgentExactSessionCloseMsg{
		HeaderType: core.NHP_EXT, AuthServiceID: common.RegisteredAgentAuthServiceID,
		CellID: candidate.CellID, SessionID: candidate.SessionID,
		SessionIssuedAtMillis: candidate.IssuedAtMillis,
		RunID:                 candidate.RunID, RunAttempt: candidate.RunAttempt,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, responses, transaction := realDirectRegistrationRequest(
		t, server, agentDevice, agentListener, core.NHP_EXT, 104, body, time.Now(),
	)
	return server, store, candidate, agentDevice, request, responses, transaction
}

func TestHandleKnockRequest_DirectExactSessionRetirementRoundTrip(t *testing.T) {
	server, store, candidate, agentDevice, request, responses, transaction := directExactRetirementRequest(t)
	if err := server.HandleKnockRequest(request); err != nil {
		t.Fatalf("HandleKnockRequest exact retirement: %v", err)
	}
	wire := drainEncryptedPacket(t, request.ConnData)
	routeResponseToTransaction(t, agentDevice, wire)
	select {
	case response := <-responses:
		if response == nil || response.Error != nil || response.HeaderType != core.NHP_ACK {
			t.Fatalf("direct exact-retirement response = %#v", response)
		}
		var ack common.ServerExactSessionCloseAckMsg
		if err := common.DecodeServerExactSessionCloseAckMsg(response.BodyMessage, &ack); err != nil {
			t.Fatalf("decode direct exact-retirement ACK: %v", err)
		}
		if err := common.ValidateServerExactSessionCloseAck(ack, common.AgentSessionReceipt{
			CellID: candidate.CellID, SessionID: candidate.SessionID,
			SessionIssuedAtMillis: candidate.IssuedAtMillis,
			RunID:                 candidate.RunID, RunAttempt: candidate.RunAttempt,
		}); err != nil {
			t.Fatalf("direct exact-retirement ACK authority: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not receive the direct exact-retirement ACK")
	}
	select {
	case <-transaction.Done():
	case <-time.After(time.Second):
		t.Fatal("direct exact-retirement transaction did not retire")
	}
	if store.resolveCalls != 1 || store.closeCalls != 1 {
		t.Fatalf("direct exact-retirement calls = resolve %d close %d, want 1/1", store.resolveCalls, store.closeCalls)
	}
}

func TestHandleKnockRequest_ExactRetirementSendFailureKeepsDurableClose(t *testing.T) {
	server, store, _, _, request, _, transaction := directExactRetirementRequest(t)
	request.ConnData.RemoteTransactionMutex.Lock()
	delete(request.ConnData.RemoteTransactionMap, request.SenderTrxId)
	request.ConnData.RemoteTransactionMutex.Unlock()
	if err := server.HandleKnockRequest(request); err == nil {
		t.Fatal("exact retirement with a missing response transaction succeeded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := transaction.CompleteContext(ctx); err != nil {
		t.Fatalf("retire detached response transaction: %v", err)
	}
	select {
	case <-transaction.Done():
	case <-time.After(time.Second):
		t.Fatal("detached exact-retirement transaction did not retire")
	}
	if store.resolveCalls != 1 || store.closeCalls != 1 {
		t.Fatalf("send failure changed durable close calls = resolve %d close %d, want 1/1", store.resolveCalls, store.closeCalls)
	}
}
