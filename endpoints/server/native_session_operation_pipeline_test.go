package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

type orderedNativeOperationStore struct {
	*admissionSessionControlStore
	mu                    sync.Mutex
	events                []string
	deadlines             []time.Time
	reserveError          error
	cancelAuthority       *sessionControlNativeOperationAuthority
	cancelError           error
	resolveAuthority      *sessionControlNativeOperationAuthority
	resolveError          error
	exactAuthority        *sessionControlSessionAuthority
	exactError            error
	exactClosePreparation *sessionControlExactClosePreparation
	exactCloseError       error
}

func (s *orderedNativeOperationStore) record(event string) {
	s.mu.Lock()
	s.events = append(s.events, event)
	s.mu.Unlock()
}

func (s *orderedNativeOperationStore) recordContext(event string, ctx context.Context) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Time{}
	}
	s.mu.Lock()
	s.events = append(s.events, event)
	s.deadlines = append(s.deadlines, deadline)
	s.mu.Unlock()
}

func (s *orderedNativeOperationStore) ReserveNativeSessionOperation(context.Context,
	sessionControlSessionCandidate, sessionControlNativeOperation, sessionControlFenceSnapshot, time.Time,
) (*sessionControlSessionAuthority, error) {
	s.record("origin-six-item-transaction")
	return nil, s.reserveError
}

func (*orderedNativeOperationStore) VerifyMappedNativeSessionOperation(context.Context,
	sessionControlSessionCandidate, sessionControlNativeOperation,
) (*sessionControlSessionAuthority, *sessionControlFenceDirectory, error) {
	return nil, nil, errors.New("unexpected forwarded verifier")
}

func (s *orderedNativeOperationStore) CancelAbsentNativeSessionOperation(ctx context.Context,
	op sessionControlNativeOperation, _ time.Time,
) (*sessionControlNativeOperationAuthority, error) {
	s.recordContext("recovery-three-item-transaction", ctx)
	if s.cancelAuthority != nil && s.cancelAuthority.Operation != op {
		return nil, errSessionControlNativeOperationConflict
	}
	return s.cancelAuthority, s.cancelError
}

func (s *orderedNativeOperationStore) ResolveNativeSessionOperation(ctx context.Context,
	operationID string,
) (*sessionControlNativeOperationAuthority, error) {
	s.recordContext("resolve-operation", ctx)
	if s.resolveAuthority != nil && s.resolveAuthority.Operation.Binding.OperationID != operationID {
		return nil, errSessionControlNativeOperationConflict
	}
	return s.resolveAuthority, s.resolveError
}

func (s *orderedNativeOperationStore) ResolveExactSessionForClose(ctx context.Context,
	selector sessionControlExactRetirementSelector,
) (*sessionControlSessionAuthority, error) {
	s.recordContext("resolve-exact-session", ctx)
	if s.exactAuthority != nil &&
		!sessionControlExactRetirementSelectorMatchesCandidate(selector, s.exactAuthority.Candidate) {
		return nil, errSessionControlSessionCorrupt
	}
	return s.exactAuthority, s.exactError
}

func (s *orderedNativeOperationStore) EnsureExactSessionClose(ctx context.Context,
	candidate sessionControlSessionCandidate, _ int64,
) (*sessionControlExactClosePreparation, error) {
	s.recordContext("close-exact-session", ctx)
	if s.exactClosePreparation != nil && s.exactClosePreparation.Session.Candidate != candidate {
		return nil, errSessionControlSessionCorrupt
	}
	return s.exactClosePreparation, s.exactCloseError
}

type orderedNativeOperationPlugin struct {
	fakePluginHandler
	store *orderedNativeOperationStore
}

type orderedNativeForwardDeps struct {
	*MockForwarderDeps
	mu     sync.Mutex
	events []string
}

func (d *orderedNativeForwardDeps) VerifyForwardedDurableNHPSession(ctx context.Context,
	_ *common.AgentKnockMsg,
) (common.AgentSessionReceipt, error) {
	d.mu.Lock()
	d.events = append(d.events, "four-item-transactional-read")
	d.mu.Unlock()
	deadline, ok := ctx.Deadline()
	remaining := time.Until(deadline)
	if !ok || remaining > sessionControlNativeOperationReadTimeout+time.Millisecond ||
		remaining < sessionControlNativeOperationReadTimeout-25*time.Millisecond {
		return common.AgentSessionReceipt{}, errors.New("forward verifier budget drifted")
	}
	return common.AgentSessionReceipt{}, errSessionControlNativeOperationConflict
}

func (d *orderedNativeForwardDeps) ResolveAuthSvcProvider(context.Context, string, string) *common.AuthServiceProviderData {
	d.mu.Lock()
	d.events = append(d.events, "catalog")
	d.mu.Unlock()
	return &common.AuthServiceProviderData{}
}

func (p orderedNativeOperationPlugin) AuthWithNHP(*common.NhpAuthRequest,
	*plugins.NhpServerPluginHelper,
) (*common.ServerKnockAckMsg, error) {
	p.store.record("plugin")
	return nil, errors.New("test plugin stop")
}

func TestNativeSessionOperationOriginRejectsBeforeIdentityLookupPluginOrAOP(t *testing.T) {
	t.Setenv("NHP_ENVIRONMENT", "sandbox")
	now := time.Now().UTC()
	base := newAdmissionSessionControlStore(now)
	store := &orderedNativeOperationStore{
		admissionSessionControlStore: base,
		reserveError:                 common.ErrNativeSessionOperationRecoveryRequired,
	}
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("NewDevice returned nil")
	}
	t.Cleanup(device.Stop)
	querier := newFakeAgentKeysQuerier()
	serverBinding := common.NativeSessionOperationServerBinding{
		AWSAccountID: "111122223333", AWSRegion: "us-east-2", CellID: testSessionControlCellID,
		SessionControlTable: storeTableNameForTest, AgentKeysTable: "control-qurl-agent-keys",
		AgentKeySchema:   common.NativeSessionOperationAgentKeySchema,
		CredentialKind:   common.NativeSessionOperationCredentialKind,
		ConnectorIDClaim: common.NativeSessionOperationConnectorIDClaim,
	}
	server := &UdpServer{
		device: device, metrics: metrics.NewPublisherForTest(t), sessionControlCellID: testSessionControlCellID,
		sessionControlStore: store,
		storageConfig: &StorageConfig{Backend: StorageBackendDynamoDB, DynamoDB: DynamoDBConfig{
			AccountID: serverBinding.AWSAccountID, Region: serverBinding.AWSRegion,
			SessionControlTable: serverBinding.SessionControlTable, AgentKeysTable: serverBinding.AgentKeysTable,
			NativeSessionOperations: true,
		}},
		nativeSessionOperationFences: &sessionControlNativeOperationFenceCache{},
		authServiceMap: common.AuthSvcProviderMap{
			common.RegisteredAgentAuthServiceID: {AuthSvcId: common.RegisteredAgentAuthServiceID},
		},
		agentPeerLookup: newTestLookup(t, querier),
	}
	server.pluginHandlerMap = map[string]plugins.PluginHandler{
		common.RegisteredAgentAuthServiceID: orderedNativeOperationPlugin{store: store},
	}
	snapshot, err := base.SnapshotActiveFences(context.Background(), testSessionControlCellID)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.nativeSessionOperationFences.store(*snapshot, testSessionControlCellID); err != nil {
		t.Fatal(err)
	}
	server.sessionRegistry().newID = func() uint64 { return 0x991 }
	agentKey := bytes.Repeat([]byte{0x62}, core.PublicKeySize)
	agentPublicKey := base64.StdEncoding.EncodeToString(agentKey)
	knock := common.AgentKnockMsg{
		HeaderType: core.NHP_KNK, UserId: "fixed-agent-a", DeviceId: "fixed-agent-a",
		AuthServiceId: common.RegisteredAgentAuthServiceID, ResourceId: "fixed-resource-a",
		RunID: "0123456789abcdef", RunAttempt: 1,
		NativeSessionOperationOwnerID:   "auth0|fixed-owner",
		NativeSessionOperationPrepared:  now.Add(-time.Second).UnixMilli(),
		NativeSessionOperationExpiresAt: now.Add(20 * time.Minute).UnixMilli(),
	}
	knock.NativeSessionOperationID, err = common.NativeSessionOperationID(agentPublicKey, knock.RunID, knock.RunAttempt)
	if err != nil {
		t.Fatal(err)
	}
	knock.NativeSessionOperationBinding, err = common.NativeSessionOperationBindingSHA256(knock, agentPublicKey, serverBinding)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(knock)
	if err != nil {
		t.Fatal(err)
	}
	ackBytes, _, admission, err := server.buildKnockAckWithAdmission(&core.PacketParserData{
		HeaderType: core.NHP_KNK, SenderTrxId: 41, RemotePubKey: agentKey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 41), Port: 51003},
			StopSignal: make(chan struct{}),
		},
		BodyMessage: body,
	})
	if err != nil || admission != nil {
		t.Fatalf("rejected native admission = ack %s admission %#v err %v", ackBytes, admission, err)
	}
	var ack common.ServerKnockAckMsg
	if err := json.Unmarshal(ackBytes, &ack); err != nil ||
		ack.ErrCode != common.ErrNativeSessionOperationRecoveryRequired.ErrorCode() ||
		ack.ErrMsg != common.ErrNativeSessionOperationRecoveryRequired.Error() {
		t.Fatalf("reject ACK = %#v, %v", ack, err)
	}
	store.mu.Lock()
	events := append([]string(nil), store.events...)
	store.mu.Unlock()
	if len(events) != 1 || events[0] != "origin-six-item-transaction" || querier.callCount() != 0 ||
		querier.getCallCount() != 0 {
		t.Fatalf("pre-transaction side effects: events=%v query=%d get=%d", events, querier.callCount(),
			querier.getCallCount())
	}
}

func TestNativeSessionOperationForwardRejectsBeforeCatalogPlacementOrACWork(t *testing.T) {
	deps := &orderedNativeForwardDeps{MockForwarderDeps: NewMockForwarderDeps()}
	forwarder := NewServerForwarder(deps)
	publicKey := bytes.Repeat([]byte{0x63}, core.PublicKeySize)
	now := time.Now().UTC()
	knock := common.AgentKnockMsg{
		HeaderType: core.NHP_KNK, UserId: "fixed-agent-a", DeviceId: "fixed-agent-a",
		AuthServiceId: common.RegisteredAgentAuthServiceID, ResourceId: "fixed-resource-a",
		RunID: "0123456789abcdef", RunAttempt: 1,
		NativeSessionOperationID: strings.Repeat("a", 64), NativeSessionOperationBinding: strings.Repeat("b", 64),
		NativeSessionOperationOwnerID:   "auth0|fixed-owner",
		NativeSessionOperationPrepared:  now.Add(-time.Second).UnixMilli(),
		NativeSessionOperationExpiresAt: now.Add(20 * time.Minute).UnixMilli(),
	}
	body, err := json.Marshal(knock)
	if err != nil {
		t.Fatal(err)
	}
	forwarder.handleDecryptedForwardedKnock(
		&core.PacketParserData{HeaderType: core.NHP_FWD},
		&common.ServerForwardMsg{
			TransactionId: 71, SessionId: 0x771, SessionIssuedAtNanos: now.UnixNano(),
		},
		&net.UDPAddr{IP: net.IPv4(203, 0, 113, 71), Port: 51003},
		&core.PacketParserData{HeaderType: core.NHP_KNK, RemotePubKey: publicKey, BodyMessage: body},
	)
	deps.mu.Lock()
	events := append([]string(nil), deps.events...)
	deps.mu.Unlock()
	if len(events) != 1 || events[0] != "four-item-transactional-read" || deps.LastResolveCtx() != nil ||
		deps.MetricCount(MetricForwardResolvedResourceFallback) != 0 {
		t.Fatalf("forward pre-verifier side effects: events=%v resolve=%v fallback=%d", events,
			deps.LastResolveCtx(), deps.MetricCount(MetricForwardResolvedResourceFallback))
	}
}

func TestNativeSessionOperationRecoveryCanceledReceiptUsesNoPluginOrLookup(t *testing.T) {
	now := time.Now().UTC()
	store := &orderedNativeOperationStore{admissionSessionControlStore: newAdmissionSessionControlStore(now)}
	serverBinding := common.NativeSessionOperationServerBinding{
		AWSAccountID: "111122223333", AWSRegion: "us-east-2", CellID: testSessionControlCellID,
		SessionControlTable: storeTableNameForTest, AgentKeysTable: "control-qurl-agent-keys",
		AgentKeySchema:   common.NativeSessionOperationAgentKeySchema,
		CredentialKind:   common.NativeSessionOperationCredentialKind,
		ConnectorIDClaim: common.NativeSessionOperationConnectorIDClaim,
	}
	publicKeyBytes := bytes.Repeat([]byte{0x64}, core.PublicKeySize)
	publicKey := base64.StdEncoding.EncodeToString(publicKeyBytes)
	request := common.AgentNativeSessionOperationRecoveryMsg{
		HeaderType: core.NHP_EXT, UserID: "fixed-agent-a", DeviceID: "fixed-agent-a",
		AuthServiceID: common.RegisteredAgentAuthServiceID, ResourceID: "fixed-resource-a",
		RunID: "0123456789abcdef", RunAttempt: 1, OwnerID: "auth0|fixed-owner",
		PreparedAtMS: now.Add(-time.Second).UnixMilli(), ExpiresAtMS: now.Add(20 * time.Minute).UnixMilli(),
	}
	var err error
	request.OperationID, err = common.NativeSessionOperationID(publicKey, request.RunID, request.RunAttempt)
	if err != nil {
		t.Fatal(err)
	}
	projection := request.KnockProjection()
	projection.NHPAgentPublicKey = publicKey
	request.BindingSHA256, err = common.NativeSessionOperationBindingSHA256(projection, publicKey, serverBinding)
	if err != nil {
		t.Fatal(err)
	}
	projection = request.KnockProjection()
	op, err := sessionControlNativeOperationForKnock(&projection, publicKey, serverBinding)
	if err != nil {
		t.Fatal(err)
	}
	store.cancelAuthority = &sessionControlNativeOperationAuthority{
		Operation: op, State: sessionControlNativeOperationStateCanceled,
		TerminalAtMillis: now.UnixMilli(), TTL: now.Add(25 * time.Hour).Unix(),
	}
	server := &UdpServer{
		sessionControlCellID: testSessionControlCellID, sessionControlStore: store,
		storageConfig: &StorageConfig{Backend: StorageBackendDynamoDB, DynamoDB: DynamoDBConfig{
			AccountID: serverBinding.AWSAccountID, Region: serverBinding.AWSRegion,
			SessionControlTable: serverBinding.SessionControlTable, AgentKeysTable: serverBinding.AgentKeysTable,
			NativeSessionOperations: true,
		}},
	}
	body, userID, err := server.buildAgentNativeSessionOperationRecoveryAck(&core.PacketParserData{
		HeaderType: core.NHP_EXT, RemotePubKey: publicKeyBytes,
	}, request)
	if err != nil || userID != "" {
		t.Fatalf("recovery ACK = %s user=%q err=%v", body, userID, err)
	}
	var ack common.ServerNativeSessionOperationRecoveryAckMsg
	if err := json.Unmarshal(body, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.ErrCode != common.ErrSuccess.ErrorCode() || ack.OperationID != request.OperationID ||
		ack.BindingSHA256 != request.BindingSHA256 || ack.State != sessionControlNativeOperationStateCanceled ||
		ack.SessionID != 0 || ack.CloseEventID != "" {
		t.Fatalf("canceled recovery ACK = %#v", ack)
	}
	store.mu.Lock()
	events := append([]string(nil), store.events...)
	store.mu.Unlock()
	if len(events) != 1 || events[0] != "recovery-three-item-transaction" {
		t.Fatalf("recovery side effects = %v", events)
	}
}

func newNativeOperationRecoveryHandlerFixture(t *testing.T) (*UdpServer, *orderedNativeOperationStore,
	common.AgentNativeSessionOperationRecoveryMsg, sessionControlNativeOperation,
	sessionControlSessionCandidate, []byte,
) {
	t.Helper()
	now := time.Now().UTC()
	store := &orderedNativeOperationStore{admissionSessionControlStore: newAdmissionSessionControlStore(now)}
	serverBinding := common.NativeSessionOperationServerBinding{
		AWSAccountID: "111122223333", AWSRegion: "us-east-2", CellID: testSessionControlCellID,
		SessionControlTable: storeTableNameForTest, AgentKeysTable: "control-qurl-agent-keys",
		AgentKeySchema:   common.NativeSessionOperationAgentKeySchema,
		CredentialKind:   common.NativeSessionOperationCredentialKind,
		ConnectorIDClaim: common.NativeSessionOperationConnectorIDClaim,
	}
	publicKeyBytes := bytes.Repeat([]byte{0x65}, core.PublicKeySize)
	publicKey := base64.StdEncoding.EncodeToString(publicKeyBytes)
	request := common.AgentNativeSessionOperationRecoveryMsg{
		HeaderType: core.NHP_EXT, UserID: "fixed-agent-a", DeviceID: "fixed-agent-a",
		AuthServiceID: common.RegisteredAgentAuthServiceID, ResourceID: "fixed-resource-a",
		RunID: "0123456789abcdef", RunAttempt: 1, OwnerID: "auth0|fixed-owner",
		PreparedAtMS: now.Add(-time.Second).UnixMilli(), ExpiresAtMS: now.Add(20 * time.Minute).UnixMilli(),
	}
	var err error
	request.OperationID, err = common.NativeSessionOperationID(publicKey, request.RunID, request.RunAttempt)
	if err != nil {
		t.Fatal(err)
	}
	projection := request.KnockProjection()
	projection.NHPAgentPublicKey = publicKey
	request.BindingSHA256, err = common.NativeSessionOperationBindingSHA256(projection, publicKey, serverBinding)
	if err != nil {
		t.Fatal(err)
	}
	projection = request.KnockProjection()
	op, err := sessionControlNativeOperationForKnock(&projection, publicKey, serverBinding)
	if err != nil {
		t.Fatal(err)
	}
	candidate := testSessionControlSessionCandidate(0x65, 0x965)
	candidate.AgentPublicKey = publicKey
	candidate.RunID = request.RunID
	candidate.RunAttempt = request.RunAttempt
	candidate.NativeOperation = op.Binding
	server := &UdpServer{
		sessionControlCellID: testSessionControlCellID, sessionControlStore: store,
		storageConfig: &StorageConfig{Backend: StorageBackendDynamoDB, DynamoDB: DynamoDBConfig{
			AccountID: serverBinding.AWSAccountID, Region: serverBinding.AWSRegion,
			SessionControlTable: serverBinding.SessionControlTable, AgentKeysTable: serverBinding.AgentKeysTable,
			NativeSessionOperations: true,
		}},
	}
	return server, store, request, op, candidate, publicKeyBytes
}

func assertNativeOperationRecoveryDeadlines(t *testing.T, started time.Time,
	store *orderedNativeOperationStore, expectedEvents []string,
) {
	t.Helper()
	store.mu.Lock()
	events := append([]string(nil), store.events...)
	deadlines := append([]time.Time(nil), store.deadlines...)
	store.mu.Unlock()
	if strings.Join(events, ",") != strings.Join(expectedEvents, ",") || len(deadlines) != len(expectedEvents) {
		t.Fatalf("recovery calls = events %v deadlines %v, want %v", events, deadlines, expectedEvents)
	}
	if sessionControlNativeOperationAggregateTimeout >= time.Second ||
		sessionControlNativeOperationAggregateTimeout != sessionControlNativeOperationWriteTimeout+
			sessionControlNativeOperationReadTimeout {
		t.Fatalf("recovery aggregate timeout = %s", sessionControlNativeOperationAggregateTimeout)
	}
	for index, deadline := range deadlines {
		remainingAtStart := deadline.Sub(started)
		if deadline.IsZero() || remainingAtStart > sessionControlNativeOperationAggregateTimeout+25*time.Millisecond ||
			remainingAtStart < sessionControlNativeOperationAggregateTimeout-75*time.Millisecond {
			t.Fatalf("recovery deadline[%d] = %v (%s from start), want aggregate %s", index, deadline,
				remainingAtStart, sessionControlNativeOperationAggregateTimeout)
		}
		if index > 0 && !deadline.Equal(deadlines[0]) {
			t.Fatalf("recovery deadline[%d] = %v, want inherited aggregate %v", index, deadline, deadlines[0])
		}
	}
}

func TestNativeSessionOperationRecoveryUsesOneSubsecondAggregateDeadline(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(*orderedNativeOperationStore, sessionControlNativeOperation, sessionControlSessionCandidate)
		wantState  string
		wantCode   string
		wantEvents []string
	}{
		{
			name: "absent canceled",
			configure: func(store *orderedNativeOperationStore, op sessionControlNativeOperation,
				_ sessionControlSessionCandidate,
			) {
				store.cancelAuthority = &sessionControlNativeOperationAuthority{
					Operation: op, State: sessionControlNativeOperationStateCanceled,
					TerminalAtMillis: time.Now().UnixMilli(), TTL: time.Now().Add(25 * time.Hour).Unix(),
				}
			},
			wantState: sessionControlNativeOperationStateCanceled,
			wantCode:  common.ErrSuccess.ErrorCode(),
			wantEvents: []string{
				"recovery-three-item-transaction",
			},
		},
		{
			name: "mapped closes and resolves",
			configure: func(store *orderedNativeOperationStore, op sessionControlNativeOperation,
				candidate sessionControlSessionCandidate,
			) {
				mapped := &sessionControlNativeOperationAuthority{
					Operation: op, State: sessionControlNativeOperationStateMapped, Candidate: &candidate,
				}
				closing := *mapped
				closing.State = sessionControlNativeOperationStateClosing
				store.cancelAuthority = mapped
				store.resolveAuthority = &closing
				store.exactAuthority = &sessionControlSessionAuthority{
					Candidate: candidate, State: sessionControlSessionStateAckEnqueued,
					RetainUntilMillis: candidate.ReservationDeadlineMillis,
				}
				store.exactClosePreparation = &sessionControlExactClosePreparation{
					EventID: sessionControlExactCloseEventID(candidate),
					Session: sessionControlSessionAuthority{
						Candidate: candidate, State: sessionControlSessionStateClosing,
						CloseEventID: sessionControlExactCloseEventID(candidate),
					},
				}
			},
			wantState: sessionControlNativeOperationStateClosing,
			wantCode:  common.ErrSuccess.ErrorCode(),
			wantEvents: []string{
				"recovery-three-item-transaction", "resolve-exact-session", "close-exact-session", "resolve-operation",
			},
		},
		{
			name: "lost response fails closed",
			configure: func(store *orderedNativeOperationStore, _ sessionControlNativeOperation,
				_ sessionControlSessionCandidate,
			) {
				store.cancelError = context.DeadlineExceeded
			},
			wantCode: common.ErrServerACOpsFailed.ErrorCode(),
			wantEvents: []string{
				"recovery-three-item-transaction",
			},
		},
		{
			name: "closed terminal replay",
			configure: func(store *orderedNativeOperationStore, op sessionControlNativeOperation,
				candidate sessionControlSessionCandidate,
			) {
				store.cancelAuthority = &sessionControlNativeOperationAuthority{
					Operation: op, State: sessionControlNativeOperationStateClosed, Candidate: &candidate,
					TerminalAtMillis: time.Now().UnixMilli(), TTL: time.Now().Add(25 * time.Hour).Unix(),
				}
			},
			wantState: sessionControlNativeOperationStateClosed,
			wantCode:  common.ErrSuccess.ErrorCode(),
			wantEvents: []string{
				"recovery-three-item-transaction",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, store, request, op, candidate, publicKey := newNativeOperationRecoveryHandlerFixture(t)
			test.configure(store, op, candidate)
			started := time.Now()
			body, userID, err := server.buildAgentNativeSessionOperationRecoveryAck(&core.PacketParserData{
				HeaderType: core.NHP_EXT, RemotePubKey: publicKey,
			}, request)
			if err != nil || userID != "" {
				t.Fatalf("recovery ACK = %s user=%q err=%v", body, userID, err)
			}
			var ack common.ServerNativeSessionOperationRecoveryAckMsg
			if err := json.Unmarshal(body, &ack); err != nil {
				t.Fatal(err)
			}
			if ack.ErrCode != test.wantCode || ack.State != test.wantState {
				t.Fatalf("recovery ACK = %#v, want code=%s state=%s", ack, test.wantCode, test.wantState)
			}
			assertNativeOperationRecoveryDeadlines(t, started, store, test.wantEvents)
		})
	}
}
