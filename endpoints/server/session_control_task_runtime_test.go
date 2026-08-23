package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

type sessionControlTaskRuntimeStore struct {
	sessionControlOwnerTaskDeliveryStore
	claim func(context.Context, sessionControlCloseTaskLeaseRequest) (*sessionControlExactCloseTaskAuthority, error)
	ack   func(context.Context, sessionControlCloseTaskAckRequest) (*sessionControlCloseTask, error)
}

func (s sessionControlTaskRuntimeStore) ClaimExactCloseTaskForDelivery(ctx context.Context,
	request sessionControlCloseTaskLeaseRequest,
) (*sessionControlExactCloseTaskAuthority, error) {
	if s.claim != nil {
		return s.claim(ctx, request)
	}
	return s.sessionControlOwnerTaskDeliveryStore.ClaimExactCloseTaskForDelivery(ctx, request)
}

func (s sessionControlTaskRuntimeStore) AckExactCloseTask(ctx context.Context,
	request sessionControlCloseTaskAckRequest,
) (*sessionControlCloseTask, error) {
	if s.ack != nil {
		return s.ack(ctx, request)
	}
	return s.sessionControlOwnerTaskDeliveryStore.AckExactCloseTask(ctx, request)
}

func sessionControlTaskRuntimeAck(authority sessionControlExactCloseTaskAuthority) common.ACSessionCloseAckMsg {
	selector := authority.Work.Selector
	return common.ACSessionCloseAckMsg{Kind: common.ACSessionCloseKind,
		Scope: common.ACSessionCloseScopeExact, EventID: authority.Task.EventID,
		AgentPublicKey: selector.AgentPublicKey, SessionID: selector.SessionID,
		SessionIssuedAtMillis: selector.SessionIssuedMillis, BootID: authority.Task.BoundBootID,
		FlushGeneration: authority.Task.BoundFlushGeneration, Closed: 1}
}

func sessionControlTaskRuntimeServer(t *testing.T,
	fixture *sessionControlOwnerSnapshotFixture,
) (*UdpServer, *ACConn, sessionControlCloseTask) {
	t.Helper()
	task, err := fixture.store.getCloseTask(context.Background(), fixture.ownerPK, fixture.eventIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	conn := testAdmissionACConn(task.ACID, 0xd1, task.BoundBootID, task.BoundFlushGeneration)
	conn.ACPeer.PubKeyBase64 = task.PublicKey
	target := task.CreationTarget
	conn.sessionControlTarget.Store(&target)
	conn.sessionControlAuthorityReady.Store(true)
	s := &UdpServer{sessionControlCellID: task.CellID,
		device:          core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil),
		acConnectionMap: map[string][]*ACConn{task.ACID: {conn}}}
	return s, conn, *task
}

func TestSessionControlTaskRuntimeClaimsSendsStrictAckAndRestoresReady(t *testing.T) {
	fixture := newSessionControlOwnerSnapshotFixture(t, 1)
	s, conn, task := sessionControlTaskRuntimeServer(t, &fixture)
	s.sendACSessionControlTaskFn = func(_ context.Context, gotConn *ACConn,
		authority sessionControlExactCloseTaskAuthority,
	) (common.ACSessionCloseAckMsg, error) {
		if gotConn != conn || authority.Task.State != sessionControlCloseTaskStateLeased ||
			authority.Task.EventID != task.EventID || authority.Work.Selector.Scope != sessionControlFenceSelectorExact {
			t.Fatalf("strict delivery authority = %#v conn=%p", authority, gotConn)
		}
		return sessionControlTaskRuntimeAck(authority), nil
	}
	if err := s.deliverDueExactCloseTask(context.Background(), fixture.store, task); err != nil {
		t.Fatal(err)
	}
	stored, err := fixture.store.getCloseTask(context.Background(), task.OwnerPK, task.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != sessionControlCloseTaskStateAcked || stored.AckClosed != 1 ||
		stored.CurrentOwnerPendingCount != 0 || !conn.sessionControlReady(true) {
		t.Fatalf("delivered task/conn = %#v ready=%t", stored, conn.sessionControlReady(true))
	}
}

func TestSessionControlAOLDrainsSameProcessTaskBeforePrepare(t *testing.T) {
	fixture := newSessionControlOwnerSnapshotFixture(t, 1)
	s, conn, task := sessionControlTaskRuntimeServer(t, &fixture)
	s.sessionControlStore = fixture.store
	s.sendACSessionControlTaskFn = func(_ context.Context, gotConn *ACConn,
		authority sessionControlExactCloseTaskAuthority,
	) (common.ACSessionCloseAckMsg, error) {
		if gotConn != conn || authority.Task.EventID != task.EventID ||
			authority.Task.BoundFlushGeneration != fixture.target.FlushGeneration {
			t.Fatalf("same-process delivery authority = %#v conn=%p", authority, gotConn)
		}
		return sessionControlTaskRuntimeAck(authority), nil
	}
	if err := s.drainACSessionControlTasksForTarget(context.Background(), conn, fixture.target, false); err != nil {
		t.Fatal(err)
	}
	stored, err := fixture.store.getCloseTask(context.Background(), fixture.ownerPK, task.EventID)
	if err != nil || stored.State != sessionControlCloseTaskStateAcked ||
		stored.BoundFlushGeneration != fixture.target.FlushGeneration {
		t.Fatalf("same-process drained task = %#v, %v", stored, err)
	}
}

func TestSessionControlAOLRebindsAndDrainsTaskOnNewProcess(t *testing.T) {
	fixture := newSessionControlOwnerSnapshotFixture(t, 1)
	oldOwner, err := fixture.store.getOwner(context.Background(), fixture.target.ControlCellID,
		fixture.target.ACID, fixture.target.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	next := fixture.target
	next.BootID = "fedcbafedcbafedcbafedcbafedcbafe"
	next.FlushGeneration++
	next.Version++
	next.ActivatedControlVersion++
	next.ReadyControlVersion = 0
	next.AAKEnqueuedAtMillis, next.AAKTransactionID, next.RetiredAtMillis = 0, 0, 0
	next.PreparedAtMillis = max(next.UpdatedAtMillis, time.Now().UnixMilli())
	next.UpdatedAtMillis = next.PreparedAtMillis
	nextOwner, err := sessionControlOwnerFromTarget(next, oldOwner, sessionControlOwnerActiveUnready)
	if err != nil {
		t.Fatal(err)
	}
	targetRow, err := sessionControlTargetToRow(next)
	if err != nil {
		t.Fatal(err)
	}
	fixture.fake.setItem(marshalSessionControlSessionTestRow(t, targetRow))
	seedSessionControlTaskOwner(t, fixture.fake, nextOwner)

	conn := testAdmissionACConn(next.ACID, 0xd2, next.BootID, next.FlushGeneration)
	conn.ACPeer.PubKeyBase64 = next.PublicKey
	s := &UdpServer{sessionControlCellID: next.ControlCellID, sessionControlStore: fixture.store}
	s.sendACSessionControlTaskFn = func(_ context.Context, gotConn *ACConn,
		authority sessionControlExactCloseTaskAuthority,
	) (common.ACSessionCloseAckMsg, error) {
		if gotConn != conn || authority.Task.BoundBootID != next.BootID ||
			authority.Task.BoundFlushGeneration != next.FlushGeneration ||
			authority.Task.BoundTargetVersion != next.Version {
			t.Fatalf("rebound delivery authority = %#v conn=%p", authority, gotConn)
		}
		return sessionControlTaskRuntimeAck(authority), nil
	}
	if err = s.drainACSessionControlTasksForTarget(context.Background(), conn, next, true); err != nil {
		t.Fatal(err)
	}
	stored, err := fixture.store.getCloseTask(context.Background(), fixture.ownerPK, fixture.eventIDs[0])
	if err != nil || stored.State != sessionControlCloseTaskStateAcked || stored.BoundBootID != next.BootID ||
		stored.BoundFlushGeneration != next.FlushGeneration || stored.CurrentOwnerPendingCount != 0 {
		t.Fatalf("rebound drained task = %#v, %v", stored, err)
	}
	after, err := fixture.store.SnapshotOwnerExactCloseTasks(context.Background(), next.ControlCellID,
		next.ACID, next.PublicKey)
	if err != nil || after.Owner.PendingCount != 0 || after.Owner.Phase != sessionControlOwnerActiveUnready {
		t.Fatalf("post-rebind owner = %#v, %v", after, err)
	}
}

func TestSessionControlAOLActivatesAndDrainsTaskMaterializedWhilePreparing(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, 10*time.Second)
	installSessionControlMaterializationQuery(t, fake)
	fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		applySessionControlMaterializationTransaction(fake, input)
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}

	sourceTarget := testSessionControlSessionTarget(0xd3)
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0xd4, 4_300)
	reserved, err := planSessionControlReservation(candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	expires := candidate.IssuedAtMillis + time.Hour.Milliseconds()
	intent, err := planSessionControlIntent(reserved.fence(), sourceTarget, expires,
		expires+time.Hour.Milliseconds(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionControlReservation(t, fake, intent.Session)
	seedSessionControlIntent(t, fake, intent.Intent)

	preparing := sourceTarget
	preparing.BootID = "d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3"
	preparing.FlushGeneration++
	preparing.State = sessionControlTargetPreparing
	preparing.Version++
	preparing.ActivatedControlVersion, preparing.ReadyControlVersion = 0, 0
	preparing.AAKEnqueuedAtMillis, preparing.AAKTransactionID = 0, 0
	preparing.PreparedAtMillis++
	preparing.UpdatedAtMillis = preparing.PreparedAtMillis
	seedSessionControlTarget(t, fake, preparing)

	directory := sessionControlCloseTestDirectory(snapshot, store.nowUTC().UnixMilli()-1_000)
	close := expectedSessionControlExactClose(t, intent.Session, directory, store.nowUTC().UnixMilli(),
		intent.Session.RetainUntilMillis)
	seedCommittedSessionControlExactClose(t, fake, directory, close)
	if _, err = store.MaterializeNormalExactClose(context.Background(), candidate, close.EventID); err != nil {
		t.Fatal(err)
	}
	ownerPK := sessionControlOwnerPK(preparing.ControlCellID, preparing.ACID, preparing.PublicKey)
	task, err := store.getCloseTask(context.Background(), ownerPK, close.EventID)
	if err != nil || task.CreationTarget != preparing || task.BoundFlushGeneration != preparing.FlushGeneration {
		t.Fatalf("PREPARING-bound materialized task = %#v, %v", task, err)
	}

	active, err := store.ActivateTarget(context.Background(), preparing.fence().activation(close.Work.PreparedDirectoryVersion))
	if err != nil || active == nil || active.State != sessionControlTargetActive || active.ReadyControlVersion != 0 {
		t.Fatalf("ActivateTarget() = %#v, %v", active, err)
	}
	if !sessionControlCloseTaskCanFollowPreparingActivation(*task, *active) {
		t.Fatalf("materialized task cannot follow exact activation: task=%#v active=%#v", task, active)
	}
	mutations := []struct {
		name   string
		mutate func(*sessionControlTargetAuthority)
	}{
		{name: "version plus two", mutate: func(target *sessionControlTargetAuthority) { target.Version++ }},
		{name: "ready", mutate: func(target *sessionControlTargetAuthority) {
			target.ReadyControlVersion = target.ActivatedControlVersion
			target.AAKEnqueuedAtMillis = target.PreparedAtMillis
			target.AAKTransactionID = 1
		}},
		{name: "boot", mutate: func(target *sessionControlTargetAuthority) { target.BootID = sourceTarget.BootID }},
		{name: "generation", mutate: func(target *sessionControlTargetAuthority) { target.FlushGeneration++ }},
		{name: "authority", mutate: func(target *sessionControlTargetAuthority) { target.AuthorityVersion++ }},
		{name: "prepared timestamp", mutate: func(target *sessionControlTargetAuthority) { target.PreparedAtMillis++ }},
	}
	for _, mutation := range mutations {
		mutated := *active
		mutation.mutate(&mutated)
		if sessionControlCloseTaskCanFollowPreparingActivation(*task, mutated) {
			t.Fatalf("same-generation activation accepted %s mutation: %#v", mutation.name, mutated)
		}
	}
	activeRow, err := sessionControlTargetToRow(*active)
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, activeRow))
	installSessionControlOwnerTaskQuery(fake)
	preDrain, err := store.SnapshotOwnerExactCloseTasks(context.Background(), active.ControlCellID,
		active.ACID, active.PublicKey)
	if err != nil || preDrain.Owner.PendingCount != 1 || len(preDrain.Tasks) != 1 {
		t.Fatalf("post-activation pending snapshot = %#v, %v", preDrain, err)
	}

	conn := testAdmissionACConn(active.ACID, 0xd3, active.BootID, active.FlushGeneration)
	conn.ACPeer.PubKeyBase64 = active.PublicKey
	s := &UdpServer{sessionControlCellID: active.ControlCellID, sessionControlStore: store}
	s.sendACSessionControlTaskFn = func(_ context.Context, gotConn *ACConn,
		authority sessionControlExactCloseTaskAuthority,
	) (common.ACSessionCloseAckMsg, error) {
		if gotConn != conn || authority.Task.BoundBootID != active.BootID ||
			authority.Task.BoundFlushGeneration != active.FlushGeneration ||
			authority.Task.BoundTargetVersion != active.Version || authority.Task.TaskVersion < 2 {
			t.Fatalf("same-generation activation rebind = %#v conn=%p", authority, gotConn)
		}
		return sessionControlTaskRuntimeAck(authority), nil
	}
	if err = s.drainACSessionControlTasksForTarget(context.Background(), conn, *active, true); err != nil {
		t.Fatal(err)
	}
	stored, err := store.getCloseTask(context.Background(), ownerPK, close.EventID)
	if err != nil || stored.State != sessionControlCloseTaskStateAcked ||
		stored.BoundTargetVersion != active.Version || stored.BoundFlushGeneration != active.FlushGeneration ||
		stored.CurrentOwnerPendingCount != 0 {
		t.Fatalf("post-activation drained task = %#v, %v", stored, err)
	}
}

func TestSessionControlTaskRuntimeRejectsWrongLocalTargetBeforeClaim(t *testing.T) {
	fixture := newSessionControlOwnerSnapshotFixture(t, 1)
	s, conn, task := sessionControlTaskRuntimeServer(t, &fixture)
	target := *conn.sessionControlTarget.Load()
	target.Version++
	conn.sessionControlTarget.Store(&target)
	if err := s.deliverDueExactCloseTask(context.Background(), fixture.store, task); !errors.Is(err, common.ErrACSessionControlNotReady) {
		t.Fatalf("wrong target delivery error = %v", err)
	}
	stored, err := fixture.store.getCloseTask(context.Background(), task.OwnerPK, task.EventID)
	if err != nil || stored.State != sessionControlCloseTaskStatePending {
		t.Fatalf("wrong target mutated task = %#v, %v", stored, err)
	}
}

func TestSessionControlTaskRuntimeNoAckRespectsCallerDeadlineAndReleasesOwnerGate(t *testing.T) {
	fixture := newSessionControlOwnerSnapshotFixture(t, 1)
	s, conn, task := sessionControlTaskRuntimeServer(t, &fixture)
	s.sendACSessionControlTaskFn = func(ctx context.Context, _ *ACConn,
		_ sessionControlExactCloseTaskAuthority,
	) (common.ACSessionCloseAckMsg, error) {
		<-ctx.Done()
		return common.ACSessionCloseAckMsg{}, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := s.deliverDueExactCloseTask(ctx, fixture.store, task); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline delivery error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("deadline delivery held owner gate for %v", elapsed)
	}
	gateCtx, gateCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer gateCancel()
	release, err := s.acquireACSessionControlAuthorityWrite(gateCtx, conn)
	if err != nil {
		t.Fatalf("owner gate remained held: %v", err)
	}
	release()
}

func TestSessionControlTaskRuntimeCommitsExactAckWithFreshContextAfterCallerExpires(t *testing.T) {
	fixture := newSessionControlOwnerSnapshotFixture(t, 1)
	s, _, task := sessionControlTaskRuntimeServer(t, &fixture)
	s.sendACSessionControlTaskFn = func(ctx context.Context, _ *ACConn,
		authority sessionControlExactCloseTaskAuthority,
	) (common.ACSessionCloseAckMsg, error) {
		<-ctx.Done()
		// Model an exact authenticated RVA racing the caller deadline. Once the
		// immutable ACK exists, the durable ACK CAS must use its fresh result
		// budget rather than discard it with the expired delivery context.
		return sessionControlTaskRuntimeAck(authority), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := s.deliverDueExactCloseTask(ctx, fixture.store, task); err != nil {
		t.Fatal(err)
	}
	stored, err := fixture.store.getCloseTask(context.Background(), task.OwnerPK, task.EventID)
	if err != nil || stored.State != sessionControlCloseTaskStateAcked || stored.AckClosed != 1 {
		t.Fatalf("fresh-context ACK = %#v, %v", stored, err)
	}
}

func TestSessionControlTaskRuntimeRejectsMutatedWorkBeforeWireSend(t *testing.T) {
	fixture := newSessionControlOwnerSnapshotFixture(t, 1)
	s, _, task := sessionControlTaskRuntimeServer(t, &fixture)
	sent := false
	s.sendACSessionControlTaskFn = func(context.Context, *ACConn,
		sessionControlExactCloseTaskAuthority,
	) (common.ACSessionCloseAckMsg, error) {
		sent = true
		return common.ACSessionCloseAckMsg{}, nil
	}
	store := sessionControlTaskRuntimeStore{sessionControlOwnerTaskDeliveryStore: fixture.store}
	store.claim = func(ctx context.Context,
		request sessionControlCloseTaskLeaseRequest,
	) (*sessionControlExactCloseTaskAuthority, error) {
		claimed, err := fixture.store.ClaimExactCloseTaskForDelivery(ctx, request)
		if err == nil {
			claimed.Work.Selector.SessionID++ // stale selector digest must not authorize the wire
		}
		return claimed, err
	}
	if err := s.deliverDueExactCloseTask(context.Background(), store, task); !errors.Is(err, errSessionControlCloseTaskConflict) || sent {
		t.Fatalf("mutated work delivery = %v, sent=%t", err, sent)
	}
}

func TestSessionControlTaskRuntimeDropsConnectionWhenAckResultCannotBeClassified(t *testing.T) {
	fixture := newSessionControlOwnerSnapshotFixture(t, 1)
	s, conn, task := sessionControlTaskRuntimeServer(t, &fixture)
	s.sessionControlStore = fixture.store
	s.sendACSessionControlTaskFn = func(_ context.Context, _ *ACConn,
		authority sessionControlExactCloseTaskAuthority,
	) (common.ACSessionCloseAckMsg, error) {
		return sessionControlTaskRuntimeAck(authority), nil
	}
	resultLost := errors.New("ACK committed but result classification transport failed")
	store := sessionControlTaskRuntimeStore{sessionControlOwnerTaskDeliveryStore: fixture.store}
	store.ack = func(ctx context.Context, request sessionControlCloseTaskAckRequest) (*sessionControlCloseTask, error) {
		if _, err := fixture.store.AckExactCloseTask(ctx, request); err != nil {
			return nil, err
		}
		return nil, resultLost
	}
	if err := s.deliverDueExactCloseTask(context.Background(), store, task); !errors.Is(err, resultLost) {
		t.Fatalf("lost ACK result error = %v", err)
	}
	stored, err := fixture.store.getCloseTask(context.Background(), task.OwnerPK, task.EventID)
	if err != nil || stored.State != sessionControlCloseTaskStateAcked || stored.DueAtMillis != 0 {
		t.Fatalf("lost ACK result task = %#v, %v", stored, err)
	}
	if s.findSessionControlTaskConnection(task) != nil || conn.sessionControlReady(true) {
		t.Fatalf("lost ACK result left connection published/ready")
	}
}
