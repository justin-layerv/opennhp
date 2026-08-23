package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/endpoints/server/health"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

type admissionSessionControlStore struct {
	*memorySessionControlStore
	requestModel   *memorySessionControlSessionModel
	controlMu      sync.Mutex
	snapshots      []*sessionControlFenceSnapshot
	snapshotCalls  int
	activateErrors []error
	activateCalls  int
	mutateActivate func(*sessionControlTargetAuthority)
	finalizeCalls  int
	beforeFinalize func(sessionControlTargetReadiness)
	mutateFinalize func(*sessionControlTargetAuthority)
	cancelCalls    int
	cancelCtxErr   error
	prepareErr     error
}

func (s *admissionSessionControlStore) ReserveSession(ctx context.Context, candidate sessionControlSessionCandidate,
	snapshot sessionControlFenceSnapshot) (*sessionControlSessionAuthority, error) {
	s.requestModel.setSnapshot(snapshot)
	return s.requestModel.ReserveSession(ctx, candidate, snapshot)
}

func (s *admissionSessionControlStore) VerifySession(ctx context.Context, candidate sessionControlSessionCandidate,
	snapshot sessionControlFenceSnapshot) (*sessionControlSessionAuthority, error) {
	s.requestModel.setSnapshot(snapshot)
	return s.requestModel.VerifySession(ctx, candidate, snapshot)
}

func (s *admissionSessionControlStore) PrepareSessionIntentCurrent(ctx context.Context,
	candidate sessionControlSessionCandidate, target sessionControlTargetAuthority,
	sessionExpiresAtMillis, retainUntilMillis int64, snapshot sessionControlFenceSnapshot,
) (*sessionControlSessionIntentPreparation, error) {
	s.requestModel.setSnapshot(snapshot)
	s.requestModel.setTarget(target)
	return s.requestModel.PrepareSessionIntentCurrent(ctx, candidate, target,
		sessionExpiresAtMillis, retainUntilMillis, snapshot)
}

func (s *admissionSessionControlStore) MarkSessionAckEnqueued(ctx context.Context,
	candidate sessionControlSessionCandidate, snapshot sessionControlFenceSnapshot,
) (*sessionControlSessionAuthority, error) {
	s.requestModel.setSnapshot(snapshot)
	return s.requestModel.MarkSessionAckEnqueued(ctx, candidate, snapshot)
}

func (s *admissionSessionControlStore) EnsureExactSessionClose(ctx context.Context,
	candidate sessionControlSessionCandidate, retainUntilMillis int64,
) (*sessionControlExactClosePreparation, error) {
	return s.requestModel.EnsureExactSessionClose(ctx, candidate, retainUntilMillis)
}

func (s *admissionSessionControlStore) PrepareTarget(ctx context.Context, candidate sessionControlTargetCandidate) (*sessionControlTargetPreparation, error) {
	s.controlMu.Lock()
	injected := s.prepareErr
	s.controlMu.Unlock()
	if injected != nil {
		return nil, injected
	}
	return s.memorySessionControlStore.PrepareTarget(ctx, candidate)
}

func (s *admissionSessionControlStore) SnapshotActiveFences(ctx context.Context, cellID string) (*sessionControlFenceSnapshot, error) {
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	if len(s.snapshots) == 0 {
		return s.memorySessionControlStore.SnapshotActiveFences(ctx, cellID)
	}
	index := s.snapshotCalls
	if index >= len(s.snapshots) {
		index = len(s.snapshots) - 1
	}
	s.snapshotCalls++
	copy := *s.snapshots[index]
	copy.Fences = append([]sessionControlFenceAuthority(nil), copy.Fences...)
	return &copy, nil
}

func (s *admissionSessionControlStore) ActivateTarget(ctx context.Context, activation sessionControlTargetActivation) (*sessionControlTargetAuthority, error) {
	s.controlMu.Lock()
	index := s.activateCalls
	s.activateCalls++
	var injected error
	if index < len(s.activateErrors) {
		injected = s.activateErrors[index]
	}
	s.controlMu.Unlock()
	if injected != nil {
		return nil, injected
	}
	result, err := s.memorySessionControlStore.ActivateTarget(ctx, activation)
	if err == nil && result != nil && s.mutateActivate != nil {
		copy := *result
		s.mutateActivate(&copy)
		result = &copy
	}
	return result, err
}

func (s *admissionSessionControlStore) CancelTargetPreparation(ctx context.Context, fence sessionControlTargetFence) (*sessionControlTargetAuthority, error) {
	s.controlMu.Lock()
	s.cancelCalls++
	s.cancelCtxErr = ctx.Err()
	s.controlMu.Unlock()
	return s.memorySessionControlStore.CancelTargetPreparation(ctx, fence)
}

func (s *admissionSessionControlStore) FinalizeTargetReady(ctx context.Context,
	readiness sessionControlTargetReadiness) (*sessionControlTargetAuthority, error) {
	s.controlMu.Lock()
	s.finalizeCalls++
	before := s.beforeFinalize
	s.controlMu.Unlock()
	if before != nil {
		before(readiness)
	}
	result, err := s.memorySessionControlStore.FinalizeTargetReady(ctx, readiness)
	if err == nil && result != nil && s.mutateFinalize != nil {
		copy := *result
		s.mutateFinalize(&copy)
		result = &copy
	}
	return result, err
}

// AOL fixtures without durable close work still implement the narrow delivery
// capability so production HandleACOnline can exercise its mandatory empty
// owner snapshot instead of bypassing the seam.
func (s *admissionSessionControlStore) SnapshotOwnerExactCloseTasks(ctx context.Context,
	cellID, acID, publicKey string,
) (*sessionControlOwnerTaskSnapshot, error) {
	target, err := s.GetTarget(ctx, sessionControlTargetKey{ACID: acID, PublicKey: publicKey})
	if err != nil {
		return nil, err
	}
	if target.ControlCellID != cellID {
		return nil, errSessionControlOwnerConflict
	}
	phase := sessionControlOwnerActiveUnready
	if target.State == sessionControlTargetPreparing {
		phase = sessionControlOwnerPreparing
	} else if target.ready() {
		phase = sessionControlOwnerReady
	}
	owner, err := sessionControlOwnerFromTarget(*target, nil, phase)
	if err != nil {
		return nil, err
	}
	return &sessionControlOwnerTaskSnapshot{Owner: owner, Tasks: []sessionControlOwnerTaskDeliveryAuthority{}}, nil
}

func (*admissionSessionControlStore) ListDueExactCloseTasksPage(context.Context, string, uint64, int64,
	*sessionControlCloseTaskDueCursor, int32,
) (*sessionControlCloseTaskDuePage, error) {
	return &sessionControlCloseTaskDuePage{Tasks: []sessionControlCloseTask{}}, nil
}

func (*admissionSessionControlStore) ClaimExactCloseTaskForDelivery(context.Context,
	sessionControlCloseTaskLeaseRequest,
) (*sessionControlExactCloseTaskAuthority, error) {
	return nil, errSessionControlCloseTaskNotFound
}

func (*admissionSessionControlStore) ReleaseExactCloseTask(context.Context,
	sessionControlCloseTaskLeaseRequest,
) (*sessionControlCloseTask, error) {
	return nil, errSessionControlCloseTaskNotFound
}

func (*admissionSessionControlStore) RebindExactCloseTask(context.Context,
	sessionControlCloseTaskRebindRequest,
) (*sessionControlCloseTask, error) {
	return nil, errSessionControlCloseTaskNotFound
}

func (*admissionSessionControlStore) AckExactCloseTask(context.Context,
	sessionControlCloseTaskAckRequest,
) (*sessionControlCloseTask, error) {
	return nil, errSessionControlCloseTaskNotFound
}

func newAdmissionSessionControlStore(now time.Time) *admissionSessionControlStore {
	base := newMemorySessionControlStore(now)
	snapshot, err := base.SnapshotActiveFences(context.Background(), testSessionControlCellID)
	if err != nil {
		panic(err)
	}
	requestModel := newMemorySessionControlSessionModel(*snapshot)
	requestModel.nowMillis = now.UnixMilli()
	return &admissionSessionControlStore{memorySessionControlStore: base, requestModel: requestModel}
}

func testAdmissionACConn(acID string, seed byte, bootID string, generation uint64) *ACConn {
	peer := &core.UdpPeer{PubKeyBase64: testPubkeyB64(seed), Type: core.NHP_AC}
	return &ACConn{
		ConnData:        &core.ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 42000 + int(seed)}},
		ACPeer:          peer,
		ACId:            acID,
		BootID:          bootID,
		FlushGeneration: generation,
	}
}

func testMarkACSessionControlReady(t *testing.T, conn *ACConn) {
	t.Helper()
	if conn == nil || conn.ACPeer == nil {
		t.Fatal("cannot mark incomplete AC connection ready")
	}
	target := &sessionControlTargetAuthority{
		ACID: conn.ACId, PublicKey: conn.ACPeer.PubKeyBase64, BootID: conn.BootID,
		FlushGeneration: conn.FlushGeneration, State: sessionControlTargetActive,
		Version: 2, AuthorityVersion: 2, CountedActiveSlot: true,
		ControlCellID: testSessionControlCellID, ActivatedControlVersion: 1, ReadyControlVersion: 1,
		AAKEnqueuedAtMillis: 1, AAKTransactionID: 1,
		CreatedAtMillis: 1, PreparedAtMillis: 1, UpdatedAtMillis: 1,
	}
	conn.sessionControlTarget.Store(target)
	conn.sessionControlAuthorityReady.Store(true)
}

func testAdmissionFenceSnapshot(t *testing.T, candidates ...sessionControlFenceCandidate) *sessionControlFenceSnapshot {
	t.Helper()
	store := newMemorySessionControlFenceStore(time.Unix(1_800_001_000, 0).UTC())
	for _, candidate := range candidates {
		if _, err := store.PrepareFence(context.Background(), candidate); err != nil {
			t.Fatalf("PrepareFence() error = %v", err)
		}
	}
	snapshot, err := store.SnapshotActiveFences(context.Background(), testSessionControlCellID)
	if err != nil {
		t.Fatalf("SnapshotActiveFences() error = %v", err)
	}
	return snapshot
}

func TestCloudSessionControlCellIdentityFailsClosedBeforeListener(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		value   string
		present bool
	}{
		{name: "missing"},
		{name: "uppercase", value: "Cell-01", present: true},
		{name: "whitespace", value: "cell-01 ", present: true},
		{name: "separator", value: "cell--01", present: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			s := &UdpServer{}
			err := s.configureSessionControlCellID(func(string) (string, bool) { return test.value, test.present })
			if err == nil || s.sessionControlCellID != "" || s.listenConn != nil {
				t.Fatalf("cell configuration = %q, %v, listener=%v; want fail before listener", s.sessionControlCellID, err, s.listenConn)
			}
		})
	}
	s := &UdpServer{}
	if err := s.configureSessionControlCellID(func(name string) (string, bool) {
		if name != "NHP_CELL_ID" {
			t.Fatalf("lookup name = %q", name)
		}
		return "cell-01", true
	}); err != nil || s.sessionControlCellID != "cell-01" {
		t.Fatalf("canonical cell configuration = %q, %v", s.sessionControlCellID, err)
	}
	startSource, err := os.ReadFile("udpserver.go")
	if err != nil {
		t.Fatal(err)
	}
	configureAt := strings.Index(string(startSource), "configureCloudSessionControlCellID()")
	listenAt := strings.Index(string(startSource), "net.ListenUDP(")
	if configureAt < 0 || listenAt < 0 || configureAt >= listenAt {
		t.Fatalf("cloud cell validation/listener order = %d/%d, want validation first", configureAt, listenAt)
	}
}

func TestACSessionControlAdmissionEmptyVersionOneHappyPath(t *testing.T) {
	store := newAdmissionSessionControlStore(time.Unix(1_800_001_100, 0).UTC())
	conn := testAdmissionACConn("ac-admission-empty", 0x71, "11111111111111111111111111111111", 1)
	s := &UdpServer{sessionControlStore: store, sessionControlCellID: testSessionControlCellID}
	var sends atomic.Int32
	s.sendACSessionControlFenceFn = func(context.Context, *ACConn, sessionControlFenceAuthority) error {
		sends.Add(1)
		return nil
	}

	active, err := s.activateACSessionControlTarget(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	if active.State != sessionControlTargetActive || active.ActivatedControlVersion != 1 || sends.Load() != 0 {
		t.Fatalf("active target = %#v, sends=%d", active, sends.Load())
	}
	if store.cancelCalls != 0 {
		t.Fatalf("cancel calls = %d, want 0", store.cancelCalls)
	}
}

func TestACSessionControlFenceExchangeRequiresExactAuthenticatedRVA(t *testing.T) {
	fence := testAdmissionFenceSnapshot(t,
		testSessionControlFenceCandidate("70707070707070707070707070707070", testSessionControlExactFenceSelector(0x70)),
	).Fences[0]
	for _, test := range []struct {
		name   string
		mutate func(*core.PacketParserData, *common.ACSessionCloseAckMsg)
		ok     bool
	}{
		{name: "exact", ok: true},
		{name: "other_connection", mutate: func(response *core.PacketParserData, _ *common.ACSessionCloseAckMsg) {
			response.ConnData = &core.ConnectionData{}
		}},
		{name: "other_authenticated_key", mutate: func(response *core.PacketParserData, _ *common.ACSessionCloseAckMsg) {
			response.RemotePubKey = testPubkey(0x7f)
		}},
		{name: "mutated_selector", mutate: func(_ *core.PacketParserData, ack *common.ACSessionCloseAckMsg) {
			ack.SessionID++
		}},
		{name: "mutated_event", mutate: func(_ *core.PacketParserData, ack *common.ACSessionCloseAckMsg) {
			ack.EventID = "71717171717171717171717171717171"
		}},
		{name: "mutated_boot", mutate: func(_ *core.PacketParserData, ack *common.ACSessionCloseAckMsg) {
			ack.BootID = "11111111111111111111111111111111"
		}},
		{name: "mutated_generation", mutate: func(_ *core.PacketParserData, ack *common.ACSessionCloseAckMsg) {
			ack.FlushGeneration++
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := testAdmissionACConn("ac-rva-exact", 0x70, "10101010101010101010101010101010", 10)
			s := &UdpServer{
				device:    core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil),
				sendMsgCh: make(chan *core.MsgData, 1),
			}
			s.signals.stop = make(chan struct{})
			s.running.Store(true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- s.sendACSessionControlFence(ctx, conn, fence) }()
			md := <-s.sendMsgCh
			if md.HeaderType != core.NHP_REV || md.ResponseMsgCh != nil || len(s.acConnectionMap) != 0 {
				t.Fatalf("catch-up send type/transaction/map = %d/%v/%#v", md.HeaderType, md.ResponseMsgCh, s.acConnectionMap)
			}
			var message common.ACSessionCloseMsg
			if err := common.DecodeACSessionCloseMsg(md.Message, &message); err != nil {
				t.Fatalf("strict REV decode: %v", err)
			}
			ack := common.ACSessionCloseAckMsg{
				Kind: message.Kind, Scope: message.Scope, EventID: message.EventID, AgentPublicKey: message.AgentPublicKey,
				SessionID: message.SessionID, SessionIssuedAtMillis: message.SessionIssuedAtMillis,
				BootID: conn.BootID, FlushGeneration: conn.FlushGeneration,
			}
			response := &core.PacketParserData{
				HeaderType: core.NHP_RVA, ConnData: conn.ConnData, RemotePubKey: conn.ACPeer.PublicKey(),
			}
			if test.mutate != nil {
				test.mutate(response, &ack)
			}
			response.BodyMessage, _ = json.Marshal(ack)
			handleErr := s.HandleRevocationAck(response)
			if !test.ok {
				cancel()
			}
			err := <-done
			if test.ok && err != nil {
				t.Fatalf("exact RVA error = %v", err)
			}
			if !test.ok && (handleErr == nil || !errors.Is(err, context.Canceled)) {
				t.Fatalf("non-exact RVA handler/send errors = %v/%v, want reject and blocked waiter", handleErr, err)
			}
		})
	}
}

func TestACSessionControlFenceExchangeUsesRealDevicePushDispatch(t *testing.T) {
	serverDevice := newSpikeDevice(t, core.NHP_SERVER, 0x31, nil)
	acDevice := newSpikeDevice(t, core.NHP_AC, 0x32, nil)
	serverAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62206}
	acAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62207}
	serverDevice.AddPeer(&core.UdpPeer{PubKeyBase64: acDevice.PublicKeyBase64(), Ip: acAddr.IP.String(), Port: acAddr.Port, Type: core.NHP_AC})
	acDevice.AddPeer(&core.UdpPeer{PubKeyBase64: serverDevice.PublicKeyBase64(), Ip: serverAddr.IP.String(), Port: serverAddr.Port, Type: core.NHP_SERVER})
	serverConn := newSpikeConn(serverDevice, acAddr)
	acConnData := newSpikeConn(acDevice, serverAddr)
	conn := &ACConn{
		ConnData:       serverConn,
		ACPeer:         &core.UdpPeer{PubKeyBase64: acDevice.PublicKeyBase64(), Type: core.NHP_AC},
		ACCipherScheme: common.CIPHER_SCHEME_CURVE,
		ACId:           "ac-real-rva", BootID: "12121212121212121212121212121212", FlushGeneration: 12,
	}
	fence := testAdmissionFenceSnapshot(t,
		testSessionControlFenceCandidate("70707070707070707070707070707070", testSessionControlExactFenceSelector(0x70)),
	).Fences[0]
	s := &UdpServer{device: serverDevice, sendMsgCh: make(chan *core.MsgData, 1)}
	s.signals.stop = make(chan struct{})
	s.running.Store(true)
	done := make(chan error, 1)
	go func() { done <- s.sendACSessionControlFence(context.Background(), conn, fence) }()

	md := <-s.sendMsgCh
	if md.ResponseMsgCh != nil || serverDevice.LocalTransactionCount() != 0 {
		t.Fatalf("NHP_REV response channel/transactions = %v/%d, want push with no core transaction", md.ResponseMsgCh, serverDevice.LocalTransactionCount())
	}
	serverDevice.SendMsgToPacket(md)
	revWire := drainEncryptedPacket(t, serverConn)
	revPPD, err := acDevice.PacketToMsg(&core.PacketData{
		BasePacket: &core.Packet{Content: revWire}, ConnData: acConnData, InitTime: time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatalf("AC decrypt NHP_REV: %v", err)
	}
	var closeMsg common.ACSessionCloseMsg
	if err := common.DecodeACSessionCloseMsg(revPPD.BodyMessage, &closeMsg); err != nil {
		t.Fatalf("strict AC NHP_REV decode: %v", err)
	}
	ackBody, err := json.Marshal(common.ACSessionCloseAckMsg{
		Kind: closeMsg.Kind, Scope: closeMsg.Scope, EventID: closeMsg.EventID, AgentPublicKey: closeMsg.AgentPublicKey,
		SessionID: closeMsg.SessionID, SessionIssuedAtMillis: closeMsg.SessionIssuedAtMillis,
		BootID: conn.BootID, FlushGeneration: conn.FlushGeneration, Closed: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	acDevice.SendMsgToPacket(&core.MsgData{
		ConnData: acConnData, HeaderType: core.NHP_RVA, CipherScheme: revPPD.CipherScheme,
		TransactionId: acDevice.NextCounterIndex(), Compress: true,
		PeerPk: decodeBase64PubKey(serverDevice.PublicKeyBase64()), Message: ackBody,
	})
	rvaWire := drainEncryptedPacket(t, acConnData)
	rvaPPD, err := serverDevice.PacketToMsg(&core.PacketData{
		BasePacket: &core.Packet{Content: rvaWire}, ConnData: serverConn, InitTime: time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatalf("server decrypt NHP_RVA: %v", err)
	}
	s.dispatchReceivedMessage(rvaPPD)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("real push/dispatch catch-up = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("real NHP_RVA dispatch did not unblock exact waiter")
	}
	s.wg.Wait()
	if serverDevice.LocalTransactionCount() != 0 || len(s.acSessionControlFenceWaiters) != 0 {
		t.Fatalf("post-dispatch transactions/waiters = %d/%d", serverDevice.LocalTransactionCount(), len(s.acSessionControlFenceWaiters))
	}
}

func TestACSessionControlFenceExchangeRetransmitsWithOneContinuousWaiter(t *testing.T) {
	conn := testAdmissionACConn("ac-rva-retry", 0x6f, "13131313131313131313131313131313", 13)
	fence := testAdmissionFenceSnapshot(t,
		testSessionControlFenceCandidate("6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f", testSessionControlExactFenceSelector(0x6f)),
	).Fences[0]
	s := &UdpServer{device: core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil), sendMsgCh: make(chan *core.MsgData, 2)}
	s.signals.stop = make(chan struct{})
	s.running.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.sendACSessionControlFence(ctx, conn, fence) }()

	first := <-s.sendMsgCh // Simulate a lost REV or its lost RVA.
	if first.ResponseMsgCh != nil || len(s.acSessionControlFenceWaiters) != 1 {
		t.Fatalf("first push response channel/waiters = %v/%d", first.ResponseMsgCh, len(s.acSessionControlFenceWaiters))
	}
	var second *core.MsgData
	select {
	case second = <-s.sendMsgCh:
	case <-time.After(2 * acSessionControlFenceRetryInterval):
		t.Fatal("session-control catch-up was not retransmitted")
	}
	if second.ResponseMsgCh != nil || second.TransactionId == first.TransactionId || !bytes.Equal(second.Message, first.Message) || len(s.acSessionControlFenceWaiters) != 1 {
		t.Fatalf("second push response/counter/body/waiters = %v/%d/%t/%d", second.ResponseMsgCh, second.TransactionId, bytes.Equal(second.Message, first.Message), len(s.acSessionControlFenceWaiters))
	}
	var message common.ACSessionCloseMsg
	if err := common.DecodeACSessionCloseMsg(second.Message, &message); err != nil {
		t.Fatal(err)
	}
	ackBody, err := json.Marshal(common.ACSessionCloseAckMsg{
		Kind: message.Kind, Scope: message.Scope, EventID: message.EventID, AgentPublicKey: message.AgentPublicKey,
		SessionID: message.SessionID, SessionIssuedAtMillis: message.SessionIssuedAtMillis,
		BootID: conn.BootID, FlushGeneration: conn.FlushGeneration, Closed: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.HandleRevocationAck(&core.PacketParserData{
		HeaderType: core.NHP_RVA, ConnData: conn.ConnData, RemotePubKey: conn.ACPeer.PublicKey(), BodyMessage: ackBody,
	}); err != nil {
		t.Fatalf("second-attempt strict RVA: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("retransmitted catch-up = %v", err)
	}
	if len(s.acSessionControlFenceWaiters) != 0 {
		t.Fatalf("continuous waiter leaked after ACK: %#v", s.acSessionControlFenceWaiters)
	}
}

func TestACSessionControlAdmissionContentionRejectsPromptlyWithoutLeak(t *testing.T) {
	s := &UdpServer{}
	release, err := s.acquireACSessionControlAdmission(context.Background(), "ac-busy")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	secondRelease, err := s.acquireACSessionControlAdmission(context.Background(), "ac-busy")
	if !errors.Is(err, errACSessionControlAdmissionBusy) || secondRelease != nil || time.Since(started) > 100*time.Millisecond {
		t.Fatalf("contended acquire release-present/error after elapsed = %t/%v after %v, want prompt busy", secondRelease != nil, err, time.Since(started))
	}
	release()
	if len(s.acSessionControlAdmissions) != 0 {
		t.Fatalf("admission entries leaked after contention: %#v", s.acSessionControlAdmissions)
	}
}

func TestACSessionControlAuthorityGateLinearizesAOPEnqueueBeforeAOLWrite(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	s.sessionControlCellID = testSessionControlCellID
	store := newAdmissionSessionControlStore(time.Now())
	s.sessionControlStore = store
	s.sendMsgCh = make(chan *core.MsgData)
	conn := newTestACConn(t, "10.0.0.9", 47051, "ac-authority-linearize")
	conn.ACPeer.PubKeyBase64 = testPubkeyB64(0x59)
	conn.BootID = "59595959595959595959595959595959"
	conn.FlushGeneration = 1
	testMarkACSessionControlReady(t, conn)
	knock := &common.AgentKnockMsg{
		UserId: "test-user", NHPAgentPublicKey: testPubkeyB64(0x58),
		NHPSessionId: 901, NHPSessionIssuedAt: time.Now(),
	}
	reserveTestNHPSession(t, s, knock, 60)
	candidate, err := sessionControlCandidateForKnock(testSessionControlCellID, knock)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.SnapshotActiveFences(context.Background(), testSessionControlCellID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveSession(context.Background(), candidate, *snapshot); err != nil {
		t.Fatal(err)
	}
	target := conn.sessionControlTarget.Load()
	if target == nil || !conn.sessionControlReady(true) {
		t.Fatal("test connection is not backed by ready target authority")
	}
	retainUntil, err := sessionControlRetainUntilMillis(candidate, 60+ACOpenCompensationTime, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, *target,
		knock.NHPSessionIssuedAt.Add(60*time.Second).UnixMilli(), retainUntil, *snapshot); err != nil {
		t.Fatalf("prepare durable test intent: %v", err)
	}
	aopDone := make(chan error, 1)
	go func() {
		_, err := s.processACOperation(context.Background(), knock, conn,
			&common.NetAddress{Ip: "192.0.2.9", Port: 443},
			[]*common.NetAddress{{Ip: "10.0.0.9", Port: 8080}}, 60, nil)
		aopDone <- err
	}()

	deadline := time.Now().Add(time.Second)
	for {
		s.acSessionControlAuthorityGatesMu.Lock()
		refs := uint64(0)
		for _, entry := range s.acSessionControlAuthorityGates {
			refs += entry.refs
		}
		s.acSessionControlAuthorityGatesMu.Unlock()
		if refs == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("AOP did not acquire authority read ownership")
		}
		runtime.Gosched()
	}
	writerCtx, writerCancel := context.WithTimeout(context.Background(), time.Second)
	defer writerCancel()
	writerAcquired := make(chan func(), 1)
	go func() {
		release, err := s.acquireACSessionControlAuthorityWrite(writerCtx, conn)
		if err != nil {
			writerAcquired <- nil
			return
		}
		writerAcquired <- release
	}()
	select {
	case <-writerAcquired:
		select {
		case aopErr := <-aopDone:
			t.Fatalf("AOL write ownership passed AOP before its send enqueue; AOP result = %v", aopErr)
		default:
			t.Fatal("AOL write ownership passed AOP before its send enqueue")
		}
	case <-time.After(25 * time.Millisecond):
	}

	md := <-s.sendMsgCh
	var releaseWriter func()
	select {
	case releaseWriter = <-writerAcquired:
		if releaseWriter == nil {
			t.Fatal("AOL write ownership timed out after AOP enqueue")
		}
	case <-time.After(time.Second):
		t.Fatal("AOL write ownership did not follow AOP enqueue")
	}
	conn.sessionControlAuthorityReady.Store(false)
	releaseWriter()
	body, err := successARTBodyForAOP(md, 0)
	md.ResponseMsgCh <- &core.PacketParserData{HeaderType: core.NHP_ART, BodyMessage: body, Error: err}
	if err := <-aopDone; err != nil {
		t.Fatalf("linearized AOP result = %v", err)
	}
	if len(s.acSessionControlAuthorityGates) != 0 {
		t.Fatalf("authority gate entries leaked: %#v", s.acSessionControlAuthorityGates)
	}
}

func TestACSessionControlStalePreparePreservesNewerReadyConnection(t *testing.T) {
	store := newAdmissionSessionControlStore(time.Unix(1_800_001_650, 0).UTC())
	s := &UdpServer{sessionControlStore: store, sessionControlCellID: testSessionControlCellID}
	s.sendACSessionControlFenceFn = func(context.Context, *ACConn, sessionControlFenceAuthority) error { return nil }
	current := testAdmissionACConn("ac-stale-aol", 0x75, "75757575757575757575757575757575", 5)
	if _, err := s.activateACSessionControlTarget(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	testMarkACSessionControlReady(t, current)
	current.ConnData.LastLocalRecvTime = time.Now().UnixNano()
	s.acConnectionMap = map[string][]*ACConn{current.ACId: {current}}
	delayed := testAdmissionACConn(current.ACId, 0x75, "74747474747474747474747474747474", 4)
	prepared := false
	_, err := s.activateACSessionControlTargetAfterPrepare(context.Background(), delayed, func(sessionControlTargetPreparation) {
		prepared = true
		s.markACSessionControlConnectionNotReady(current.ACId, current.ACPeer.PubKeyBase64)
	})
	if !errors.Is(err, errSessionControlTargetStale) {
		t.Fatalf("delayed lower-generation AOL = %v, want stale", err)
	}
	if prepared || !current.sessionControlAuthorityReady.Load() || !s.hasLiveACConn(current.ACId) {
		t.Fatalf("stale AOL prepared/ready/live = %t/%t/%t", prepared, current.sessionControlAuthorityReady.Load(), s.hasLiveACConn(current.ACId))
	}
}

func TestACPeerHealthUsesLiveAuthorityReadyDistinctIDs(t *testing.T) {
	now := time.Now()
	readyA := testAdmissionACConn("ac-health-a", 0x51, "51515151515151515151515151515151", 1)
	readyASibling := testAdmissionACConn("ac-health-a", 0x52, "52525252525252525252525252525252", 1)
	readyB := testAdmissionACConn("ac-health-b", 0x53, "53535353535353535353535353535353", 1)
	for _, conn := range []*ACConn{readyA, readyASibling, readyB} {
		conn.ConnData.LastLocalRecvTime = now.UnixNano()
		testMarkACSessionControlReady(t, conn)
	}
	s := &UdpServer{
		sessionControlCellID: testSessionControlCellID,
		acConnectionMap: map[string][]*ACConn{
			readyA.ACId: {readyA, readyASibling},
			readyB.ACId: {readyB},
		},
	}
	checker := health.NewACPeerChecker(&health.ACPeerCheckerConfig{Counter: s, GracePeriod: -1})
	if got := s.ACPeerCount(); got != 2 || checker.Check(context.Background()).Status != health.CheckStatusPass {
		t.Fatalf("initial authority health count/status = %d/%s", got, checker.Check(context.Background()).Status)
	}
	readyA.sessionControlAuthorityReady.Store(false)
	readyASibling.sessionControlAuthorityReady.Store(false)
	if got := s.ACPeerCount(); got != 1 || s.hasLiveACConn(readyA.ACId) {
		t.Fatalf("preparing A count/live = %d/%t", got, s.hasLiveACConn(readyA.ACId))
	}
	readyB.sessionControlAuthorityReady.Store(false)
	if got := s.ACPeerCount(); got != 0 || checker.Check(context.Background()).Status != health.CheckStatusFail {
		t.Fatalf("failed catch-up health count/status = %d/%s", got, checker.Check(context.Background()).Status)
	}
	testMarkACSessionControlReady(t, readyASibling)
	if got := s.ACPeerCount(); got != 1 || !s.hasLiveACConn(readyA.ACId) || checker.Check(context.Background()).Status != health.CheckStatusPass {
		t.Fatalf("recovered health count/live/status = %d/%t/%s", got, s.hasLiveACConn(readyA.ACId), checker.Check(context.Background()).Status)
	}
}

func TestACSessionControlAdmissionCatchupFailureCancelsUncountedPreparation(t *testing.T) {
	store := newAdmissionSessionControlStore(time.Unix(1_800_001_200, 0).UTC())
	store.snapshots = []*sessionControlFenceSnapshot{testAdmissionFenceSnapshot(t,
		testSessionControlFenceCandidate("71717171717171717171717171717171", testSessionControlExactFenceSelector(0x72)),
	)}
	conn := testAdmissionACConn("ac-admission-cancel", 0x72, "22222222222222222222222222222222", 2)
	s := &UdpServer{sessionControlStore: store, sessionControlCellID: testSessionControlCellID}
	s.sendACSessionControlFenceFn = func(context.Context, *ACConn, sessionControlFenceAuthority) error {
		return errors.New("RVA unavailable")
	}

	if _, err := s.activateACSessionControlTarget(context.Background(), conn); err == nil {
		t.Fatal("catch-up failure returned nil")
	}
	if store.cancelCalls != 1 {
		t.Fatalf("cancel calls = %d, want exact one", store.cancelCalls)
	}
	target, err := store.GetTarget(context.Background(), sessionControlTargetKey{ACID: conn.ACId, PublicKey: conn.ACPeer.PubKeyBase64})
	if err != nil || target.State != sessionControlTargetCanceled || target.CountedActiveSlot {
		t.Fatalf("canceled target = %#v, %v", target, err)
	}
}

func TestACSessionControlCountedReconnectFailurePreservesButFencesOldConnection(t *testing.T) {
	store := newAdmissionSessionControlStore(time.Unix(1_800_001_300, 0).UTC())
	acID := "ac-admission-counted"
	old := testAdmissionACConn(acID, 0x73, "33333333333333333333333333333333", 3)
	prepared, err := store.PrepareTarget(context.Background(), sessionControlTargetCandidate{
		ACID: acID, PublicKey: old.ACPeer.PubKeyBase64, BootID: old.BootID, FlushGeneration: old.FlushGeneration, ControlCellID: testSessionControlCellID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActivateTarget(context.Background(), prepared.Target.fence().activation(1)); err != nil {
		t.Fatal(err)
	}
	testMarkACSessionControlReady(t, old)
	old.ConnData.LastLocalRecvTime = time.Now().UnixNano()
	store.snapshots = []*sessionControlFenceSnapshot{testAdmissionFenceSnapshot(t,
		testSessionControlFenceCandidate("73737373737373737373737373737373", testSessionControlExactFenceSelector(0x73)),
	)}
	s := &UdpServer{
		sessionControlStore: store, sessionControlCellID: testSessionControlCellID,
		acConnectionMap: map[string][]*ACConn{acID: {old}}, metrics: metrics.NewPublisherForTest(t),
	}
	if got := s.ACPeerCount(); got != 1 {
		t.Fatalf("ready target health count = %d, want 1", got)
	}
	s.sendACSessionControlFenceFn = func(context.Context, *ACConn, sessionControlFenceAuthority) error {
		return errors.New("catch-up failed")
	}
	newConn := testAdmissionACConn(acID, 0x73, "44444444444444444444444444444444", 4)

	release, err := s.acquireACSessionControlAdmission(context.Background(), acID)
	if err != nil {
		t.Fatal(err)
	}
	s.markACSessionControlConnectionNotReady(acID, old.ACPeer.PubKeyBase64)
	_, admissionErr := s.activateACSessionControlTarget(context.Background(), newConn)
	release()
	if admissionErr == nil {
		t.Fatal("counted reconnect catch-up failure returned nil")
	}
	if store.cancelCalls != 0 {
		t.Fatalf("counted preparation cancel calls = %d, want 0", store.cancelCalls)
	}
	target, err := store.GetTarget(context.Background(), prepared.Target.key())
	if err != nil || target.State != sessionControlTargetPreparing || !target.CountedActiveSlot {
		t.Fatalf("counted preparing target = %#v, %v", target, err)
	}
	if conns, _ := s.snapshotLiveACConns(acID); len(conns) != 0 {
		t.Fatalf("authority-unready old conn remained AOP eligible: %#v", conns)
	}
	if _, err := s.processACOperation(context.Background(), &common.AgentKnockMsg{}, old, nil, nil, 0, nil); !errors.Is(err, common.ErrACSessionControlNotReady) {
		t.Fatalf("authority-unready direct AOP error = %v, want session-control not ready", err)
	}
	if got := s.acConnectionMap[acID]; len(got) != 1 || got[0] != old {
		t.Fatalf("old control-recovery conn was replaced: %#v", got)
	}
	if got := s.ACPeerCount(); got != 0 {
		t.Fatalf("failed PREPARING catch-up health count = %d, want 0", got)
	}
	store.snapshots = nil
	s.sendACSessionControlFenceFn = func(context.Context, *ACConn, sessionControlFenceAuthority) error { return nil }
	if _, err := s.activateACSessionControlTarget(context.Background(), newConn); err != nil {
		t.Fatalf("recovery activation = %v", err)
	}
	newConn.ConnData.LastLocalRecvTime = time.Now().UnixNano()
	testMarkACSessionControlReady(t, newConn)
	s.acConnectionMap[acID] = []*ACConn{newConn}
	if got := s.ACPeerCount(); got != 1 || !s.hasLiveACConn(acID) {
		t.Fatalf("recovered ACTIVE target health count/live = %d/%t", got, s.hasLiveACConn(acID))
	}
}

func TestACSessionControlAdmissionRecatchesAfterEventFirstControlStale(t *testing.T) {
	store := newAdmissionSessionControlStore(time.Unix(1_800_001_400, 0).UTC())
	first := testSessionControlFenceCandidate("74747474747474747474747474747474", testSessionControlExactFenceSelector(0x74))
	second := testSessionControlFenceCandidate("75757575757575757575757575757575", testSessionControlExactFenceSelector(0x75))
	store.snapshots = []*sessionControlFenceSnapshot{
		testAdmissionFenceSnapshot(t, first),
		testAdmissionFenceSnapshot(t, first, second),
	}
	store.activateErrors = []error{errSessionControlTargetControlStale}
	store.memorySessionControlStore.mu.Lock()
	store.controlDirectories[testSessionControlCellID] = sessionControlFenceDirectory{
		CellID: testSessionControlCellID, Version: 3, ActiveFenceCount: 2,
		CreatedAtMillis: 1_800_001_400_000, UpdatedAtMillis: 1_800_001_400_000,
	}
	store.memorySessionControlStore.mu.Unlock()
	conn := testAdmissionACConn("ac-admission-recatch", 0x74, "55555555555555555555555555555555", 5)
	s := &UdpServer{sessionControlStore: store, sessionControlCellID: testSessionControlCellID}
	var events []string
	s.sendACSessionControlFenceFn = func(_ context.Context, _ *ACConn, fence sessionControlFenceAuthority) error {
		events = append(events, fence.EventID)
		return nil
	}

	active, err := s.activateACSessionControlTarget(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	if active.ActivatedControlVersion != 3 || store.activateCalls != 2 || store.snapshotCalls != 2 {
		t.Fatalf("recatch result = %#v, activate=%d snapshot=%d", active, store.activateCalls, store.snapshotCalls)
	}
	want := []string{first.EventID, first.EventID, second.EventID}
	if len(events) != len(want) {
		t.Fatalf("catch-up events = %#v, want %#v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("catch-up events = %#v, want %#v", events, want)
		}
	}
}

func TestACSessionControlManyFenceCatchupUsesOneAggregateDeadline(t *testing.T) {
	store := newAdmissionSessionControlStore(time.Unix(1_800_001_500, 0).UTC())
	fences := make([]sessionControlFenceAuthority, 256)
	base := testAdmissionFenceSnapshot(t,
		testSessionControlFenceCandidate("76767676767676767676767676767676", testSessionControlExactFenceSelector(0x76)),
	).Fences[0]
	for i := range fences {
		fences[i] = base
		fences[i].EventID = strings.Repeat(string("0123456789abcdef"[i%16]), 32)
	}
	store.snapshots = []*sessionControlFenceSnapshot{{
		CellID: testSessionControlCellID, DirectoryVersion: 2, ActiveFenceCount: uint64(len(fences)), Fences: fences,
	}}
	conn := testAdmissionACConn("ac-admission-deadline", 0x76, "66666666666666666666666666666666", 6)
	s := &UdpServer{sessionControlStore: store, sessionControlCellID: testSessionControlCellID}
	var calls atomic.Int32
	s.sendACSessionControlFenceFn = func(ctx context.Context, _ *ACConn, _ sessionControlFenceAuthority) error {
		calls.Add(1)
		<-ctx.Done()
		return ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := s.activateACSessionControlTarget(ctx, conn)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatalf("bounded catch-up error/elapsed = %v/%v", err, time.Since(started))
	}
	if calls.Load() != 1 || store.cancelCalls != 1 {
		t.Fatalf("send/cancel calls = %d/%d, want one blocked send and exact cancel", calls.Load(), store.cancelCalls)
	}
	if store.cancelCtxErr != nil {
		t.Fatalf("compensating cancel inherited expired aggregate context: %v", store.cancelCtxErr)
	}
}

func TestACSessionControlConcurrentAdmissionEnforcesDurableCap(t *testing.T) {
	store := newAdmissionSessionControlStore(time.Unix(1_800_001_600, 0).UTC())
	s := &UdpServer{sessionControlStore: store, sessionControlCellID: testSessionControlCellID}
	const attempts = MaxACConnsPerID + 1
	var successes atomic.Int32
	var capacity atomic.Int32
	var wg sync.WaitGroup
	for i := range attempts {
		wg.Add(1)
		go func(seed byte) {
			defer wg.Done()
			acID := "ac-admission-cap"
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var release func()
			var err error
			for {
				release, err = s.acquireACSessionControlAdmission(ctx, acID)
				if !errors.Is(err, errACSessionControlAdmissionBusy) {
					break
				}
				runtime.Gosched()
			}
			if err != nil {
				t.Errorf("acquire admission: %v", err)
				return
			}
			defer release()
			conn := testAdmissionACConn(acID, seed, "77777777777777777777777777777777", uint64(seed)+1)
			if _, err = s.activateACSessionControlTarget(context.Background(), conn); err == nil {
				successes.Add(1)
			} else if errors.Is(err, errSessionControlTargetCapacity) {
				capacity.Add(1)
			} else {
				t.Errorf("admission error = %v", err)
			}
		}(byte(i + 1))
	}
	wg.Wait()
	if successes.Load() != MaxACConnsPerID || capacity.Load() != 1 {
		t.Fatalf("success/capacity = %d/%d", successes.Load(), capacity.Load())
	}
	if got := store.authorities["ac-admission-cap"].ActiveTargetCount; got != MaxACConnsPerID {
		t.Fatalf("durable active target count = %d", got)
	}
	if len(s.acSessionControlAdmissions) != 0 {
		t.Fatalf("admission lock entries leaked: %#v", s.acSessionControlAdmissions)
	}
}

func TestHandleACOnlineAAKFailureLeavesActiveTargetForIdempotentRetry(t *testing.T) {
	const (
		acID   = "ac-admission-aak-retry"
		bootID = "88888888888888888888888888888888"
	)
	pubkey := testPubkey(0x78)
	pubkeyB64 := testPubkeyB64(0x78)
	storage := NewMemoryStorage()
	storage.PutACAssignment(&ACAssignment{ACID: acID, Version: 1})
	store := newAdmissionSessionControlStore(time.Unix(1_800_001_700, 0).UTC())
	s := &UdpServer{
		metrics: metrics.NewPublisherForTest(t), storage: storage,
		storageConfig:       &StorageConfig{Backend: StorageBackendDynamoDB},
		sessionControlStore: store, sessionControlCellID: testSessionControlCellID,
		device:     core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil),
		listenAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 62206}, localIp: "127.0.0.1",
		acPeerMap: map[string]*core.UdpPeer{}, acConnectionMap: map[string][]*ACConn{},
	}
	peer := &core.UdpPeer{Hostname: acID, PubKeyBase64: pubkeyB64, Type: core.NHP_AC}
	peer.UpdateRecv(time.Now().UnixNano(), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 45000})
	s.acPeerMap[pubkeyB64] = peer
	body, err := json.Marshal(common.ACOnlineMsg{
		ACId: acID, BootID: bootID, SessionFlushGeneration: 8, SessionFlushComplete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ppd := &core.PacketParserData{
		HeaderType: core.NHP_AOL, BodyMessage: body, SenderTrxId: 88, LocalInitTime: time.Now().UnixNano(), RemotePubKey: pubkey,
		ConnData: &core.ConnectionData{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 45000}, RemoteTransactionMap: map[uint64]*core.RemoteTransaction{}},
	}
	ppd.ConnData.LastLocalRecvTime = time.Now().UnixNano()
	if err := s.HandleACOnline(ppd); !errors.Is(err, common.ErrTransactionIdNotFound) {
		t.Fatalf("first AOL error = %v, want AAK transaction miss", err)
	}
	target, err := store.GetTarget(context.Background(), sessionControlTargetKey{ACID: acID, PublicKey: pubkeyB64})
	if err != nil || target.State != sessionControlTargetActive {
		t.Fatalf("post-AAK-failure target = %#v, %v", target, err)
	}
	s.acConnectionMapMutex.RLock()
	failedConns := append([]*ACConn(nil), s.acConnectionMap[acID]...)
	s.acConnectionMapMutex.RUnlock()
	if len(failedConns) != 1 || failedConns[0].sessionControlAuthorityReady.Load() || s.hasLiveACConn(acID) || s.ACPeerCount() != 0 {
		t.Fatalf("post-AAK-failure conns/ready/live/health = %d/%t/%t/%d", len(failedConns), len(failedConns) == 1 && failedConns[0].sessionControlAuthorityReady.Load(), s.hasLiveACConn(acID), s.ACPeerCount())
	}
	counters, _ := s.metrics.CountersForTest(t)
	if counters[MetricACRegistrationSuccess] != 0 {
		t.Fatalf("success metric after AAK failure = %v", counters[MetricACRegistrationSuccess])
	}

	aakMessages := make(chan *core.MsgData, 1)
	ppd.ConnData.RemoteTransactionMap[ppd.SenderTrxId] = core.NewRemoteTransactionForTest(ppd.SenderTrxId, aakMessages)
	store.beforeFinalize = func(readiness sessionControlTargetReadiness) {
		if len(aakMessages) != 1 {
			t.Errorf("FinalizeTargetReady ran before AAK enqueue: buffered=%d", len(aakMessages))
		}
		if readiness.AAKTransactionID != ppd.SenderTrxId {
			t.Errorf("FinalizeTargetReady transaction = %d, want %d", readiness.AAKTransactionID, ppd.SenderTrxId)
		}
	}
	if err := s.HandleACOnline(ppd); err != nil {
		t.Fatalf("idempotent AOL retry error = %v", err)
	}
	select {
	case md := <-aakMessages:
		if md.HeaderType != core.NHP_AAK {
			t.Fatalf("retry response type = %d", md.HeaderType)
		}
	default:
		t.Fatal("retry did not enqueue AAK")
	}
	target, err = store.GetTarget(context.Background(), target.key())
	if err != nil || !target.ready() {
		t.Fatalf("retried target = %#v, %v", target, err)
	}
	s.acConnectionMapMutex.RLock()
	readyConns := append([]*ACConn(nil), s.acConnectionMap[acID]...)
	s.acConnectionMapMutex.RUnlock()
	if len(readyConns) != 1 || readyConns[0].sessionControlTarget.Load() == nil ||
		*readyConns[0].sessionControlTarget.Load() != *target || store.finalizeCalls != 1 {
		t.Fatalf("published durable readiness conns/finalize = %#v/%d", readyConns, store.finalizeCalls)
	}
	if !s.hasLiveACConn(acID) || s.ACPeerCount() != 1 {
		t.Fatalf("retry did not publish authority-ready health: live=%t count=%d", s.hasLiveACConn(acID), s.ACPeerCount())
	}
	counters, _ = s.metrics.CountersForTest(t)
	if counters[MetricACRegistrationSuccess] != 1 {
		t.Fatalf("success metric after AAK enqueue = %v", counters[MetricACRegistrationSuccess])
	}
}

func TestHandleACOnlineDirectoryAdvanceAfterAAKKeepsDurableTargetUnready(t *testing.T) {
	const (
		acID   = "ac-admission-finalize-stale"
		bootID = "98989898989898989898989898989898"
	)
	pubkey := testPubkey(0x79)
	pubkeyB64 := testPubkeyB64(0x79)
	storage := NewMemoryStorage()
	storage.PutACAssignment(&ACAssignment{ACID: acID, Version: 1})
	store := newAdmissionSessionControlStore(time.Unix(1_800_001_800, 0).UTC())
	s := &UdpServer{
		metrics: metrics.NewPublisherForTest(t), storage: storage,
		storageConfig:       &StorageConfig{Backend: StorageBackendDynamoDB},
		sessionControlStore: store, sessionControlCellID: testSessionControlCellID,
		device:     core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil),
		listenAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 62206}, localIp: "127.0.0.1",
		acPeerMap: map[string]*core.UdpPeer{}, acConnectionMap: map[string][]*ACConn{},
	}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 45001}
	peer := &core.UdpPeer{Hostname: acID, PubKeyBase64: pubkeyB64, Type: core.NHP_AC}
	peer.UpdateRecv(time.Now().UnixNano(), addr)
	s.acPeerMap[pubkeyB64] = peer
	body, err := json.Marshal(common.ACOnlineMsg{
		ACId: acID, BootID: bootID, SessionFlushGeneration: 9, SessionFlushComplete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	aakMessages := make(chan *core.MsgData, 1)
	connData := newClosableConnData(addr)
	connData.RemoteTransactionMap = map[uint64]*core.RemoteTransaction{}
	connData.RemoteTransactionMap[99] = core.NewRemoteTransactionForTest(99, aakMessages)
	udpConn := &UdpConn{ConnData: connData}
	s.remoteConnectionMap = map[string]*UdpConn{addr.String(): udpConn}
	ppd := &core.PacketParserData{HeaderType: core.NHP_AOL, BodyMessage: body, SenderTrxId: 99,
		LocalInitTime: time.Now().UnixNano(), RemotePubKey: pubkey, ConnData: connData}
	store.beforeFinalize = func(sessionControlTargetReadiness) {
		store.memorySessionControlStore.mu.Lock()
		directory := store.memorySessionControlStore.controlDirectories[testSessionControlCellID]
		directory.Version++
		directory.UpdatedAtMillis++
		store.memorySessionControlStore.controlDirectories[testSessionControlCellID] = directory
		store.memorySessionControlStore.mu.Unlock()
	}
	if err := s.HandleACOnline(ppd); !errors.Is(err, common.ErrACSessionControlNotReady) {
		t.Fatalf("HandleACOnline() = %v, want post-AAK durable readiness rejection", err)
	}
	select {
	case md := <-aakMessages:
		if md.HeaderType != core.NHP_AAK {
			t.Fatalf("enqueued response type = %d", md.HeaderType)
		}
	default:
		t.Fatal("success AAK was not enqueued before directory race")
	}
	target, err := store.GetTarget(context.Background(), sessionControlTargetKey{ACID: acID, PublicKey: pubkeyB64})
	if err != nil || target.ready() {
		t.Fatalf("post-race target = %#v, %v; want durable ACTIVE_UNREADY", target, err)
	}
	s.acConnectionMapMutex.RLock()
	conns := append([]*ACConn(nil), s.acConnectionMap[acID]...)
	s.acConnectionMapMutex.RUnlock()
	if len(conns) != 0 || s.hasLiveACConn(acID) || s.ACPeerCount() != 0 {
		t.Fatalf("post-race local authority conns/live/count = %#v/%t/%d", conns, s.hasLiveACConn(acID), s.ACPeerCount())
	}
	s.acPeerMapMutex.Lock()
	_, peerPublished := s.acPeerMap[pubkeyB64]
	s.acPeerMapMutex.Unlock()
	if peerPublished {
		t.Fatal("post-race staged peer remained published after durable finalization failed")
	}
	if got := s.device.LookupPeer(pubkey); got != nil {
		t.Fatalf("post-race staged peer remained in device registry: %#v", got)
	}
	deadline := time.Now().Add(time.Second)
	for !connData.IsClosed() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !connData.IsClosed() {
		t.Fatal("post-race exact UDP connection was not closed")
	}
	s.remoteConnectionMapMutex.Lock()
	_, udpPublished := s.remoteConnectionMap[addr.String()]
	s.remoteConnectionMapMutex.Unlock()
	if udpPublished {
		t.Fatal("post-race exact UDP connection remained published")
	}
	counters, _ := s.metrics.CountersForTest(t)
	if counters[MetricACRegistrationSuccess] != 0 {
		t.Fatalf("success metric after failed durable finalization = %v", counters[MetricACRegistrationSuccess])
	}
}

func TestHandleACOnlineFinalizesWithFreshBudgetAfterCatchUpContextExpires(t *testing.T) {
	const (
		acID   = "ac-admission-finalize-fresh-budget"
		bootID = "a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9"
	)
	pubkey := testPubkey(0x7a)
	pubkeyB64 := testPubkeyB64(0x7a)
	storage := NewMemoryStorage()
	storage.PutACAssignment(&ACAssignment{ACID: acID, Version: 1})
	store := newAdmissionSessionControlStore(time.Unix(1_800_001_900, 0).UTC())
	s := &UdpServer{
		metrics: metrics.NewPublisherForTest(t), storage: storage,
		storageConfig:       &StorageConfig{Backend: StorageBackendDynamoDB},
		sessionControlStore: store, sessionControlCellID: testSessionControlCellID,
		sessionControlAOLBudget: 100 * time.Millisecond,
		device:                  core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil),
		listenAddr:              &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 62206}, localIp: "127.0.0.1",
		acPeerMap: map[string]*core.UdpPeer{}, acConnectionMap: map[string][]*ACConn{},
	}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 45002}
	peer := &core.UdpPeer{Hostname: acID, PubKeyBase64: pubkeyB64, Type: core.NHP_AC}
	peer.UpdateRecv(time.Now().UnixNano(), addr)
	s.acPeerMap[pubkeyB64] = peer
	body, err := json.Marshal(common.ACOnlineMsg{
		ACId: acID, BootID: bootID, SessionFlushGeneration: 10, SessionFlushComplete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	aakMessages := make(chan *core.MsgData)
	connData := &core.ConnectionData{RemoteAddr: addr, RemoteTransactionMap: map[uint64]*core.RemoteTransaction{}}
	connData.LastLocalRecvTime = time.Now().UnixNano()
	connData.RemoteTransactionMap[100] = core.NewRemoteTransactionForTest(100, aakMessages)
	ppd := &core.PacketParserData{HeaderType: core.NHP_AOL, BodyMessage: body, SenderTrxId: 100,
		LocalInitTime: time.Now().UnixNano(), RemotePubKey: pubkey, ConnData: connData}
	received := make(chan *core.MsgData, 1)
	go func() {
		time.Sleep(150 * time.Millisecond)
		received <- <-aakMessages
	}()
	if err := s.HandleACOnline(ppd); err != nil {
		t.Fatalf("HandleACOnline() with expired catch-up budget = %v (finalize calls=%d)", err, store.finalizeCalls)
	}
	select {
	case md := <-received:
		if md == nil || md.HeaderType != core.NHP_AAK {
			t.Fatalf("response = %#v, want AAK", md)
		}
	case <-time.After(time.Second):
		t.Fatal("AAK was not delivered")
	}
	target, err := store.GetTarget(context.Background(), sessionControlTargetKey{ACID: acID, PublicKey: pubkeyB64})
	if err != nil || target == nil || !target.ready() || store.finalizeCalls != 1 {
		t.Fatalf("fresh-budget finalized target/calls = %#v/%d, %v", target, store.finalizeCalls, err)
	}
	if !s.hasLiveACConn(acID) {
		t.Fatal("fresh-budget finalization did not publish a ready connection")
	}
}

func TestACSessionControlRejectsMismatchedActivatedAuthority(t *testing.T) {
	store := newAdmissionSessionControlStore(time.Unix(1_800_002_000, 0).UTC())
	store.mutateActivate = func(target *sessionControlTargetAuthority) {
		target.BootID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		target.Version++
	}
	s := &UdpServer{sessionControlStore: store, sessionControlCellID: testSessionControlCellID}
	conn := testAdmissionACConn("ac-activation-result-exact", 0x7b,
		"abababababababababababababababab", 1)
	if _, err := s.activateACSessionControlTarget(context.Background(), conn); !errors.Is(err, errSessionControlTargetCorrupt) {
		t.Fatalf("mismatched ActivateTarget result error = %v, want corrupt", err)
	}
}

func TestHandleACOnlineRejectsMismatchedFinalizedAudit(t *testing.T) {
	const (
		acID   = "ac-finalize-result-exact"
		bootID = "acacacacacacacacacacacacacacacac"
	)
	pubkey := testPubkey(0x7c)
	pubkeyB64 := testPubkeyB64(0x7c)
	storage := NewMemoryStorage()
	storage.PutACAssignment(&ACAssignment{ACID: acID, Version: 1})
	store := newAdmissionSessionControlStore(time.Unix(1_800_002_100, 0).UTC())
	store.mutateFinalize = func(target *sessionControlTargetAuthority) {
		// This remains superficially ready; only the exact readiness audit binds
		// it to the AAK just enqueued by this AOL transaction.
		target.AAKTransactionID++
	}
	s := &UdpServer{
		metrics: metrics.NewPublisherForTest(t), storage: storage,
		storageConfig:       &StorageConfig{Backend: StorageBackendDynamoDB},
		sessionControlStore: store, sessionControlCellID: testSessionControlCellID,
		device:     core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil),
		listenAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 62206}, localIp: "127.0.0.1",
		acPeerMap: map[string]*core.UdpPeer{}, acConnectionMap: map[string][]*ACConn{},
	}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 45003}
	peer := &core.UdpPeer{Hostname: acID, PubKeyBase64: pubkeyB64, Type: core.NHP_AC}
	peer.UpdateRecv(time.Now().UnixNano(), addr)
	s.acPeerMap[pubkeyB64] = peer
	body, err := json.Marshal(common.ACOnlineMsg{
		ACId: acID, BootID: bootID, SessionFlushGeneration: 11, SessionFlushComplete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	aakMessages := make(chan *core.MsgData, 1)
	connData := &core.ConnectionData{RemoteAddr: addr, RemoteTransactionMap: map[uint64]*core.RemoteTransaction{}}
	connData.RemoteTransactionMap[101] = core.NewRemoteTransactionForTest(101, aakMessages)
	ppd := &core.PacketParserData{HeaderType: core.NHP_AOL, BodyMessage: body, SenderTrxId: 101,
		LocalInitTime: time.Now().UnixNano(), RemotePubKey: pubkey, ConnData: connData}
	if err := s.HandleACOnline(ppd); !errors.Is(err, common.ErrACSessionControlNotReady) {
		t.Fatalf("HandleACOnline() mismatched finalized audit = %v, want not ready", err)
	}
	if len(aakMessages) != 1 {
		t.Fatalf("AAK enqueue count = %d, want 1 before malformed result", len(aakMessages))
	}
	s.acConnectionMapMutex.RLock()
	remaining := len(s.acConnectionMap[acID])
	s.acConnectionMapMutex.RUnlock()
	if remaining != 0 || s.hasLiveACConn(acID) {
		t.Fatalf("mismatched finalized result remained published: conns=%d live=%t", remaining, s.hasLiveACConn(acID))
	}

	// A contradictory retirement audit must also fail the runtime interface
	// boundary even when every ordinary readiness field matches exactly.
	store.mutateFinalize = func(target *sessionControlTargetAuthority) {
		target.RetiredAtMillis = target.UpdatedAtMillis
	}
	// The first malformed-finalize path deliberately removes the staged peer
	// along with the exact published connection. Restore the pre-existing peer
	// so this retry reaches the same durable finalize boundary instead of the
	// unrelated first-registration license gate.
	peer.UpdateRecv(time.Now().UnixNano(), addr)
	s.acPeerMapMutex.Lock()
	s.acPeerMap[pubkeyB64] = peer
	s.acPeerMapMutex.Unlock()
	retiredAAK := make(chan *core.MsgData, 1)
	ppd.SenderTrxId = 103
	connData.RemoteTransactionMap[103] = core.NewRemoteTransactionForTest(103, retiredAAK)
	if err := s.HandleACOnline(ppd); !errors.Is(err, common.ErrACSessionControlNotReady) {
		t.Fatalf("HandleACOnline() contradictory retired audit = %v, want not ready", err)
	}
	if len(retiredAAK) != 1 || s.hasLiveACConn(acID) {
		t.Fatalf("contradictory retired audit publication: aak=%d live=%t", len(retiredAAK), s.hasLiveACConn(acID))
	}
}

func TestHandleACOnlineCellGateBlocksCloseThroughFinalize(t *testing.T) {
	const (
		acID   = "ac-finalize-cell-gate"
		bootID = "adadadadadadadadadadadadadadadad"
	)
	pubkey := testPubkey(0x7e)
	pubkeyB64 := testPubkeyB64(0x7e)
	storage := NewMemoryStorage()
	storage.PutACAssignment(&ACAssignment{ACID: acID, Version: 1})
	store := newAdmissionSessionControlStore(time.Unix(1_800_002_200, 0).UTC())
	s := &UdpServer{
		metrics: metrics.NewPublisherForTest(t), storage: storage,
		storageConfig:       &StorageConfig{Backend: StorageBackendDynamoDB},
		sessionControlStore: store, sessionControlCellID: testSessionControlCellID,
		device:     core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil),
		listenAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 62206}, localIp: "127.0.0.1",
		acPeerMap: map[string]*core.UdpPeer{}, acConnectionMap: map[string][]*ACConn{},
	}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 45005}
	peer := &core.UdpPeer{Hostname: acID, PubKeyBase64: pubkeyB64, Type: core.NHP_AC}
	peer.UpdateRecv(time.Now().UnixNano(), addr)
	s.acPeerMap[pubkeyB64] = peer
	body, err := json.Marshal(common.ACOnlineMsg{
		ACId: acID, BootID: bootID, SessionFlushGeneration: 12, SessionFlushComplete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	aakMessages := make(chan *core.MsgData, 1)
	connData := &core.ConnectionData{RemoteAddr: addr, RemoteTransactionMap: map[uint64]*core.RemoteTransaction{}}
	connData.LastLocalRecvTime = time.Now().UnixNano()
	connData.RemoteTransactionMap[102] = core.NewRemoteTransactionForTest(102, aakMessages)
	ppd := &core.PacketParserData{HeaderType: core.NHP_AOL, BodyMessage: body, SenderTrxId: 102,
		LocalInitTime: time.Now().UnixNano(), RemotePubKey: pubkey, ConnData: connData}
	finalizeEntered := make(chan struct{})
	allowFinalize := make(chan struct{})
	store.beforeFinalize = func(sessionControlTargetReadiness) {
		close(finalizeEntered)
		<-allowFinalize
	}
	handleDone := make(chan error, 1)
	go func() { handleDone <- s.HandleACOnline(ppd) }()
	select {
	case <-finalizeEntered:
	case <-time.After(time.Second):
		t.Fatal("AOL did not reach durable finalization")
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, closeErr := s.acquireSessionControlCellWrite(closeCtx)
	closeCancel()
	if !errors.Is(closeErr, context.DeadlineExceeded) {
		t.Fatalf("cell writer during AOL finalization = %v, want deadline", closeErr)
	}
	close(allowFinalize)
	select {
	case err := <-handleDone:
		if err != nil {
			t.Fatalf("HandleACOnline() after releasing finalization = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("AOL did not finish after finalization release")
	}
	releaseWrite, err := s.acquireSessionControlCellWrite(context.Background())
	if err != nil {
		t.Fatalf("cell writer after AOL = %v", err)
	}
	releaseWrite()
}

func TestFinalizeFailureAfterConcurrentConnectionCleanupStillRemovesPeer(t *testing.T) {
	pubkey := testPubkey(0x7d)
	pubkeyB64 := testPubkeyB64(0x7d)
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	peer := &core.UdpPeer{Hostname: "ac-finalize-cleanup-race", PubKeyBase64: pubkeyB64, Type: core.NHP_AC}
	target := &ACConn{ACId: peer.Hostname, ACPeer: peer, ConnData: &core.ConnectionData{
		RemoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 45004},
	}}
	s := &UdpServer{device: device, acPeerMap: map[string]*core.UdpPeer{pubkeyB64: peer},
		acConnectionMap: map[string][]*ACConn{}}
	device.AddPeer(peer)
	// Simulate connectionRoutine winning exact ACConn removal immediately before
	// the finalize-failure cleanup runs.
	if s.removePublishedACSessionControlConnection(target.ACId, target) {
		t.Fatal("cleanup reported removing an ACConn already removed by connectionRoutine")
	}
	s.acPeerMapMutex.Lock()
	_, peerPublished := s.acPeerMap[pubkeyB64]
	s.acPeerMapMutex.Unlock()
	if peerPublished || device.LookupPeer(pubkey) != nil {
		t.Fatalf("peer survived concurrent connection cleanup: map=%t device=%#v", peerPublished, device.LookupPeer(pubkey))
	}
}

func TestAOLDurableAuthorityDoesNotCallLegacyAssignmentTargetWriter(t *testing.T) {
	for _, path := range []string{"msghandler.go", "ac_session_control_admission.go"} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"registerACSessionControlTarget("} {
			if strings.Contains(string(body), forbidden) {
				t.Fatalf("%s still contains legacy target write %q", path, forbidden)
			}
		}
	}
}
