package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

type requestRuntimeFaultStore struct {
	*admissionSessionControlStore
	mu               sync.Mutex
	reserveErrors    []error
	reserveCalls     int
	markConflictLeft int
	markCalls        int
}

type requestRuntimeDueStore struct {
	*requestRuntimeFaultStore
	dueSession sessionControlSessionAuthority
	dueCalls   int
	closeCalls int
}

type forwardedStaleVerifyStore struct {
	*admissionSessionControlStore
}

func (s *forwardedStaleVerifyStore) VerifySession(ctx context.Context,
	candidate sessionControlSessionCandidate, snapshot sessionControlFenceSnapshot,
) (*sessionControlSessionAuthority, error) {
	// Deliberately skip admissionSessionControlStore's fixture-only setSnapshot:
	// the request model below already represents a newer strong directory than
	// the snapshot UdpServer just read, exactly reproducing a real stale read.
	return s.requestModel.VerifySession(ctx, candidate, snapshot)
}

type registeredAgentSuccessACKPlugin struct {
	fakePluginHandler
	resourceID   string
	resourceHost string
	acToken      string
}

func (p registeredAgentSuccessACKPlugin) AuthWithNHP(*common.NhpAuthRequest,
	*plugins.NhpServerPluginHelper,
) (*common.ServerKnockAckMsg, error) {
	return &common.ServerKnockAckMsg{
		ErrCode: common.ErrSuccess.ErrorCode(), OpenTime: 60,
		AgentAddr:    "203.0.113.12:51003",
		ResourceHost: map[string]string{p.resourceID: p.resourceHost},
		ACTokens:     map[string]string{p.resourceID: p.acToken},
	}, nil
}

func (s *requestRuntimeDueStore) ListDueReservedSessionsPage(_ context.Context, cellID string,
	shard uint64, _ int64, _ *sessionControlDueSessionCursor, _ int32,
) (*sessionControlDueSessionPage, error) {
	s.dueCalls++
	page := &sessionControlDueSessionPage{}
	if s.dueSession.Candidate.CellID == cellID &&
		s.dueSession.Candidate.SessionID%sessionControlSessionDueShardCount == shard {
		page.Sessions = []sessionControlSessionAuthority{s.dueSession}
	}
	return page, nil
}

func (s *requestRuntimeDueStore) ListDueClosingSessionsPage(context.Context, string, uint64, int64,
	*sessionControlDueSessionCursor, int32,
) (*sessionControlDueSessionPage, error) {
	return &sessionControlDueSessionPage{}, nil
}

func (s *requestRuntimeDueStore) EnsureExactSessionClose(ctx context.Context,
	candidate sessionControlSessionCandidate, retainUntilMillis int64,
) (*sessionControlExactClosePreparation, error) {
	s.closeCalls++
	return s.requestRuntimeFaultStore.admissionSessionControlStore.EnsureExactSessionClose(ctx, candidate, retainUntilMillis)
}

func (s *requestRuntimeFaultStore) ReserveSession(ctx context.Context,
	candidate sessionControlSessionCandidate, snapshot sessionControlFenceSnapshot,
) (*sessionControlSessionAuthority, error) {
	s.mu.Lock()
	index := s.reserveCalls
	s.reserveCalls++
	var injected error
	if index < len(s.reserveErrors) {
		injected = s.reserveErrors[index]
	}
	s.mu.Unlock()
	if injected != nil {
		return nil, injected
	}
	return s.admissionSessionControlStore.ReserveSession(ctx, candidate, snapshot)
}

func (s *requestRuntimeFaultStore) MarkSessionAckEnqueued(ctx context.Context,
	candidate sessionControlSessionCandidate, snapshot sessionControlFenceSnapshot,
) (*sessionControlSessionAuthority, error) {
	s.mu.Lock()
	s.markCalls++
	if s.markConflictLeft > 0 {
		s.markConflictLeft--
		s.mu.Unlock()
		return nil, errSessionControlSessionConflict
	}
	s.mu.Unlock()
	return s.admissionSessionControlStore.MarkSessionAckEnqueued(ctx, candidate, snapshot)
}

func TestSessionControlRuntimeRetentionUsesOriginIssuanceUnderClockSkew(t *testing.T) {
	candidate := testSessionControlSessionCandidate(0x91, 901)
	behind := time.UnixMilli(candidate.IssuedAtMillis - 5_000)
	got, err := sessionControlRetainUntilMillis(candidate, 65, behind)
	if err != nil {
		t.Fatal(err)
	}
	want := candidate.IssuedAtMillis + 65*time.Second.Milliseconds()
	if got != want {
		t.Fatalf("retain until = %d, want origin issuance + compensated lifetime = %d", got, want)
	}
}

func TestSessionControlRuntimeReserveRetriesFreshFenceSnapshot(t *testing.T) {
	candidate := testSessionControlSessionCandidate(0x92, 902)
	base := newAdmissionSessionControlStore(time.UnixMilli(candidate.IssuedAtMillis + 1_000))
	store := &requestRuntimeFaultStore{
		admissionSessionControlStore: base,
		reserveErrors: []error{
			errSessionControlSessionFenceStale,
			errSessionControlSessionFenceStale,
			errSessionControlSessionFenceStale,
		},
	}
	s := &UdpServer{sessionControlStore: store, sessionControlCellID: candidate.CellID}
	if err := s.reserveDurableSession(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if store.reserveCalls != sessionControlRuntimeSnapshotAttempts {
		t.Fatalf("ReserveSession calls = %d, want %d", store.reserveCalls, sessionControlRuntimeSnapshotAttempts)
	}
}

func TestSessionControlRuntimeMarkWaitsForAllFanoutCASWinners(t *testing.T) {
	candidate := testSessionControlSessionCandidate(0x93, 903)
	base := newAdmissionSessionControlStore(time.UnixMilli(candidate.IssuedAtMillis + 1_000))
	store := &requestRuntimeFaultStore{
		admissionSessionControlStore: base,
		markConflictLeft:             MaxACConnsPerID,
	}
	snapshot, err := store.SnapshotActiveFences(context.Background(), candidate.CellID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveSession(context.Background(), candidate, *snapshot); err != nil {
		t.Fatal(err)
	}
	target := testSessionControlSessionTarget(0x94)
	if _, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, target,
		candidate.IssuedAtMillis+60*time.Second.Milliseconds(),
		candidate.IssuedAtMillis+65*time.Second.Milliseconds(), *snapshot); err != nil {
		t.Fatal(err)
	}
	s := &UdpServer{sessionControlStore: store, sessionControlCellID: candidate.CellID}
	if err := s.markDurableSessionAckEnqueued(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if store.markCalls != sessionControlSessionFanoutAttempts {
		t.Fatalf("MarkSessionAckEnqueued calls = %d, want %d", store.markCalls, sessionControlSessionFanoutAttempts)
	}
}

func TestVerifyForwardedDurableNHPSessionUsesExactStoredAuthority(t *testing.T) {
	newFixture := func(t *testing.T) (*UdpServer, *admissionSessionControlStore,
		sessionControlSessionCandidate, *common.AgentKnockMsg) {
		t.Helper()
		candidate := testSessionControlSessionCandidate(0x51, 0x905)
		store := newAdmissionSessionControlStore(time.UnixMilli(candidate.IssuedAtMillis + 1))
		snapshot, err := store.SnapshotActiveFences(context.Background(), candidate.CellID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.ReserveSession(context.Background(), candidate, *snapshot); err != nil {
			t.Fatal(err)
		}
		knock := &common.AgentKnockMsg{
			AuthServiceId: common.RegisteredAgentAuthServiceID,
			NHPSessionId:  candidate.SessionID, NHPSessionIssuedAt: time.UnixMilli(candidate.IssuedAtMillis),
			NHPAgentPublicKey: candidate.AgentPublicKey,
			RunID:             candidate.RunID, RunAttempt: candidate.RunAttempt,
		}
		return &UdpServer{sessionControlCellID: candidate.CellID, sessionControlStore: store}, store, candidate, knock
	}

	server, _, candidate, knock := newFixture(t)
	receipt, err := server.VerifyForwardedDurableNHPSession(context.Background(), knock)
	if err != nil {
		t.Fatal(err)
	}
	if receipt != (common.AgentSessionReceipt{
		CellID: candidate.CellID, SessionID: candidate.SessionID,
		SessionIssuedAtMillis: candidate.IssuedAtMillis,
		RunID:                 candidate.RunID, RunAttempt: candidate.RunAttempt,
	}) {
		t.Fatalf("verified forwarded receipt = %#v, want stored candidate %#v", receipt, candidate)
	}

	for name, mutate := range map[string]func(*admissionSessionControlStore, sessionControlSessionCandidate, *common.AgentKnockMsg){
		"missing": func(store *admissionSessionControlStore, candidate sessionControlSessionCandidate, _ *common.AgentKnockMsg) {
			store.requestModel.mu.Lock()
			delete(store.requestModel.sessions, candidate.SessionID)
			store.requestModel.mu.Unlock()
		},
		"drift": func(_ *admissionSessionControlStore, _ sessionControlSessionCandidate, knock *common.AgentKnockMsg) {
			knock.RunAttempt++
		},
		"non-reserved": func(store *admissionSessionControlStore, candidate sessionControlSessionCandidate, _ *common.AgentKnockMsg) {
			store.requestModel.mu.Lock()
			current := store.requestModel.sessions[candidate.SessionID]
			current.State = sessionControlSessionStateAckEnqueued
			store.requestModel.sessions[candidate.SessionID] = current
			store.requestModel.mu.Unlock()
		},
	} {
		t.Run(name, func(t *testing.T) {
			server, store, candidate, knock := newFixture(t)
			mutate(store, candidate, knock)
			if receipt, err := server.VerifyForwardedDurableNHPSession(context.Background(), knock); err == nil {
				t.Fatalf("invalid forwarded authority verified as %#v", receipt)
			}
		})
	}
	server, store, _, knock := newFixture(t)
	store.requestModel.setSnapshot(testSessionControlSessionSnapshot(2))
	server.sessionControlStore = &forwardedStaleVerifyStore{admissionSessionControlStore: store}
	if receipt, err := server.VerifyForwardedDurableNHPSession(context.Background(), knock); !errors.Is(err, errSessionControlSessionFenceStale) {
		t.Fatalf("stale forwarded authority = %#v, %v; want fence stale", receipt, err)
	}
}

func TestBuildKnockAckRegeneratesFleetWideNumericSessionCollision(t *testing.T) {
	now := time.Now()
	base := newAdmissionSessionControlStore(now)
	store := &requestRuntimeFaultStore{
		admissionSessionControlStore: base,
		reserveErrors:                []error{errSessionControlSessionCollision},
	}
	plugin := &mutatingSessionKnockPlugin{}
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("NewDevice returned nil")
	}
	t.Cleanup(device.Stop)
	s := &UdpServer{
		device: device, metrics: metrics.NewPublisherForTest(t),
		sessionControlCellID: testSessionControlCellID, sessionControlStore: store,
		authServiceMap:   common.AuthSvcProviderMap{"test": {AuthSvcId: "test"}},
		pluginHandlerMap: map[string]plugins.PluginHandler{"test": plugin},
	}
	registry := s.sessionRegistry()
	ids := []uint64{0x901, 0x902}
	registry.newID = func() uint64 {
		id := ids[0]
		ids = ids[1:]
		return id
	}
	body, err := json.Marshal(&common.AgentKnockMsg{
		HeaderType: core.NHP_KNK, UserId: "collision-user",
		AuthServiceId: "test", ResourceId: "test-resource",
	})
	if err != nil {
		t.Fatal(err)
	}
	agentKey := bytes.Repeat([]byte{0x52}, core.PublicKeySize)
	ackBytes, _, admission, err := s.buildKnockAckWithAdmission(&core.PacketParserData{
		HeaderType: core.NHP_KNK, SenderTrxId: 10, RemotePubKey: agentKey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 12), Port: 51003},
			StopSignal: make(chan struct{}),
		},
		BodyMessage: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	var ack common.ServerKnockAckMsg
	if err := json.Unmarshal(ackBytes, &ack); err != nil {
		t.Fatal(err)
	}
	if admission == nil || admission.Candidate.SessionID != 0x902 || ack.SessionId != 0x902 || store.reserveCalls != 2 {
		t.Fatalf("collision retry admission/ACK/calls = %#v/%d/%d, want session 0x902 in 2 calls", admission, ack.SessionId, store.reserveCalls)
	}
	if ack.CellId != admission.Candidate.CellID ||
		ack.SessionIssuedAtMillis != admission.Candidate.IssuedAtMillis ||
		ack.RunID != admission.Candidate.RunID || ack.RunAttempt != admission.Candidate.RunAttempt {
		t.Fatalf("durable session receipt = %#v, want candidate %#v", ack, admission.Candidate)
	}
	registry.mu.Lock()
	_, firstPresent := registry.sessions[0x901]
	_, secondPresent := registry.sessions[0x902]
	registry.mu.Unlock()
	if firstPresent || !secondPresent {
		t.Fatalf("local collision retry sessions first/second = %t/%t, want false/true", firstPresent, secondPresent)
	}
	registry.release(agentKey, admission.SessionID, admission.SessionIssuedAt)
	if err := s.compensateDurableAdmission(admission); err != nil && !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatal(err)
	}
}

func TestBuildKnockAckRegisteredAgentSuccessUsesStrictReceiptEncoder(t *testing.T) {
	const (
		runID      = "0123456789abcdef"
		resourceID = "connector-knock-1"
		sessionID  = uint64(0x903)
	)
	base := newAdmissionSessionControlStore(time.Now())
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("NewDevice returned nil")
	}
	t.Cleanup(device.Stop)
	s := &UdpServer{
		device: device, metrics: metrics.NewPublisherForTest(t),
		sessionControlCellID: testSessionControlCellID, sessionControlStore: base,
		authServiceMap: common.AuthSvcProviderMap{
			common.RegisteredAgentAuthServiceID: {AuthSvcId: common.RegisteredAgentAuthServiceID},
		},
		pluginHandlerMap: map[string]plugins.PluginHandler{
			common.RegisteredAgentAuthServiceID: registeredAgentSuccessACKPlugin{
				resourceID: resourceID, resourceHost: "127.0.0.1:443", acToken: "token",
			},
		},
	}
	s.sessionRegistry().newID = func() uint64 { return sessionID }
	body, err := json.Marshal(&common.AgentKnockMsg{
		HeaderType: core.NHP_KNK, UserId: "registered-user",
		AuthServiceId: common.RegisteredAgentAuthServiceID, ResourceId: resourceID,
		RunID: runID, RunAttempt: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	agentKey := bytes.Repeat([]byte{0x53}, core.PublicKeySize)
	ackBytes, _, admission, err := s.buildKnockAckWithAdmission(&core.PacketParserData{
		HeaderType: core.NHP_KNK, SenderTrxId: 11, RemotePubKey: agentKey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 12), Port: 51003},
			StopSignal: make(chan struct{}),
		},
		BodyMessage: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	if admission == nil {
		t.Fatal("registered-agent success returned no durable admission receipt")
	}
	var ack common.ServerKnockAckMsg
	if err := common.DecodeRegisteredAgentKnockAckMsg(ackBytes, &ack, runID, 1, resourceID); err != nil {
		t.Fatalf("strict decode direct producer ACK: %v", err)
	}
	if ack.SessionId != sessionID || ack.CellId != admission.Candidate.CellID ||
		ack.SessionIssuedAtMillis != admission.Candidate.IssuedAtMillis ||
		ack.RunID != admission.Candidate.RunID || ack.RunAttempt != admission.Candidate.RunAttempt {
		t.Fatalf("direct producer receipt = %#v, want durable candidate %#v", ack, admission.Candidate)
	}
}

func TestBuildKnockAckRegisteredAgentInvalidResourceAuthorityCompensates(t *testing.T) {
	const (
		runID      = "0123456789abcdef"
		resourceID = "connector-knock-1"
	)
	for name, plugin := range map[string]registeredAgentSuccessACKPlugin{
		"whitespace host": {resourceID: resourceID, resourceHost: "   ", acToken: "token"},
		"padded token":    {resourceID: resourceID, resourceHost: "127.0.0.1:443", acToken: " token "},
	} {
		t.Run(name, func(t *testing.T) {
			const sessionID = uint64(0x904)
			base := newAdmissionSessionControlStore(time.Now())
			device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
			if device == nil {
				t.Fatal("NewDevice returned nil")
			}
			t.Cleanup(device.Stop)
			s := &UdpServer{
				device: device, metrics: metrics.NewPublisherForTest(t),
				sessionControlCellID: testSessionControlCellID, sessionControlStore: base,
				authServiceMap: common.AuthSvcProviderMap{
					common.RegisteredAgentAuthServiceID: {AuthSvcId: common.RegisteredAgentAuthServiceID},
				},
				pluginHandlerMap: map[string]plugins.PluginHandler{
					common.RegisteredAgentAuthServiceID: plugin,
				},
			}
			s.sessionRegistry().newID = func() uint64 { return sessionID }
			body, err := json.Marshal(&common.AgentKnockMsg{
				HeaderType: core.NHP_KNK, UserId: "registered-user",
				AuthServiceId: common.RegisteredAgentAuthServiceID, ResourceId: resourceID,
				RunID: runID, RunAttempt: 1,
			})
			if err != nil {
				t.Fatal(err)
			}
			agentKey := bytes.Repeat([]byte{0x54}, core.PublicKeySize)
			ackBytes, _, admission, err := s.buildKnockAckWithAdmission(&core.PacketParserData{
				HeaderType: core.NHP_KNK, SenderTrxId: 12, RemotePubKey: agentKey,
				ConnData: &core.ConnectionData{
					RemoteAddr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 12), Port: 51003},
					StopSignal: make(chan struct{}),
				},
				BodyMessage: body,
			})
			if err == nil || ackBytes != nil || admission != nil {
				t.Fatalf("invalid authority result = ack %s admission %#v err %v", ackBytes, admission, err)
			}
			registry := s.sessionRegistry()
			registry.mu.Lock()
			_, localPresent := registry.sessions[sessionID]
			registry.mu.Unlock()
			if localPresent {
				t.Fatal("invalid registered-agent ACK left its local session reserved")
			}
			base.requestModel.mu.Lock()
			closed := base.requestModel.sessions[sessionID]
			base.requestModel.mu.Unlock()
			if closed.State != sessionControlSessionStateClosing || closed.CloseEventID == "" {
				t.Fatalf("invalid registered-agent ACK durable compensation = %#v", closed)
			}
		})
	}
}

func TestSessionControlRecoveryClosesReservedCrashGapAfterAckEnqueue(t *testing.T) {
	candidate := testSessionControlSessionCandidate(0x95, 905)
	base := newAdmissionSessionControlStore(time.UnixMilli(candidate.ReservationDeadlineMillis + 1))
	faults := &requestRuntimeFaultStore{admissionSessionControlStore: base}
	store := &requestRuntimeDueStore{requestRuntimeFaultStore: faults}
	snapshot, err := store.SnapshotActiveFences(context.Background(), candidate.CellID)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := store.ReserveSession(context.Background(), candidate, *snapshot)
	if err != nil {
		t.Fatal(err)
	}
	store.dueSession = *reserved
	s := &UdpServer{sessionControlStore: store, sessionControlCellID: candidate.CellID}
	s.recoverDueReservedSessions(context.Background(), store, candidate.ReservationDeadlineMillis)
	if store.dueCalls != int(sessionControlSessionDueShardCount) || store.closeCalls != 1 {
		t.Fatalf("recovery due/close calls = %d/%d, want %d/1", store.dueCalls, store.closeCalls, sessionControlSessionDueShardCount)
	}
	base.requestModel.mu.Lock()
	closed := base.requestModel.sessions[candidate.SessionID]
	base.requestModel.mu.Unlock()
	if closed.State != sessionControlSessionStateClosing || closed.CloseEventID != sessionControlExactCloseEventID(candidate) {
		t.Fatalf("recovered crash-gap session = %#v", closed)
	}
}
