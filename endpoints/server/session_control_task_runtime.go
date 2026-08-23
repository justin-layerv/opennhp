package server

import (
	"context"
	"errors"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// sessionControlOwnerTaskDeliveryStore is intentionally narrower than the AOL
// authority surface. Recovery owns only strong task discovery, exact leasing,
// authenticated delivery, and the rebind/ACK transitions needed by an AOL
// reconnect; production startup asserts this capability on the same concrete
// Dynamo store.
type sessionControlOwnerTaskDeliveryStore interface {
	ListDueExactCloseTasksPage(context.Context, string, uint64, int64,
		*sessionControlCloseTaskDueCursor, int32) (*sessionControlCloseTaskDuePage, error)
	SnapshotOwnerExactCloseTasks(context.Context, string, string, string) (*sessionControlOwnerTaskSnapshot, error)
	ClaimExactCloseTaskForDelivery(context.Context,
		sessionControlCloseTaskLeaseRequest) (*sessionControlExactCloseTaskAuthority, error)
	ReleaseExactCloseTask(context.Context, sessionControlCloseTaskLeaseRequest) (*sessionControlCloseTask, error)
	RebindExactCloseTask(context.Context, sessionControlCloseTaskRebindRequest) (*sessionControlCloseTask, error)
	AckExactCloseTask(context.Context, sessionControlCloseTaskAckRequest) (*sessionControlCloseTask, error)
}

var _ sessionControlOwnerTaskDeliveryStore = (*dynamoSessionControlStore)(nil)

func sessionControlRecoveryTaskKey(task sessionControlCloseTask) string {
	return task.OwnerPK + "#" + task.EventID
}

func sessionControlTaskMatchesConnectionIdentity(task sessionControlCloseTask, conn *ACConn) bool {
	if conn == nil || conn.ACPeer == nil || conn.ConnData == nil || task.ACID != conn.ACId ||
		task.PublicKey != conn.ACPeer.PubKeyBase64 || task.BoundBootID != conn.BootID ||
		task.BoundFlushGeneration != conn.FlushGeneration {
		return false
	}
	target := conn.sessionControlTarget.Load()
	return target != nil && validateSessionControlTargetAuthority(*target) == nil &&
		target.State == sessionControlTargetActive && target.CountedActiveSlot &&
		target.ActivatedControlVersion > 0 && target.RetiredAtMillis == 0 &&
		target.ControlCellID == task.CellID && target.ACID == task.ACID && target.PublicKey == task.PublicKey &&
		target.BootID == task.BoundBootID && target.FlushGeneration == task.BoundFlushGeneration &&
		target.Version == task.BoundTargetVersion && target.AuthorityVersion == task.BoundAuthorityVersion &&
		target.ActivatedControlVersion == task.BoundActivatedCursor &&
		target.ReadyControlVersion == task.BoundReadyCursor
}

func (s *UdpServer) findSessionControlTaskConnection(task sessionControlCloseTask) *ACConn {
	if s == nil {
		return nil
	}
	s.acConnectionMapMutex.RLock()
	defer s.acConnectionMapMutex.RUnlock()
	for _, conn := range s.acConnectionMap[task.ACID] {
		if sessionControlTaskMatchesConnectionIdentity(task, conn) {
			return conn
		}
	}
	return nil
}

func (s *UdpServer) restoreSessionControlConnectionAfterTaskAck(ctx context.Context,
	store sessionControlOwnerTaskDeliveryStore, conn *ACConn, task sessionControlCloseTask,
) error {
	if conn == nil || task.State != sessionControlCloseTaskStateAcked ||
		task.CurrentOwnerPendingCount != 0 || task.BoundReadyCursor == 0 {
		return nil
	}
	snapshot, err := store.SnapshotOwnerExactCloseTasks(ctx, task.CellID, task.ACID, task.PublicKey)
	if err != nil {
		return err
	}
	target := conn.sessionControlTarget.Load()
	if target == nil || snapshot.Owner.PendingCount != 0 ||
		!snapshot.Owner.exactTarget(*target, sessionControlOwnerReady) ||
		!sessionControlTaskMatchesConnectionIdentity(task, conn) ||
		s.findSessionControlTaskConnection(task) != conn {
		return common.ErrACSessionControlNotReady
	}
	conn.sessionControlAuthorityReady.Store(true)
	return nil
}

// deliverDueExactCloseTask owns one durable lease attempt. It takes the same
// per-owner write gate as AOL, validates the full post-claim task/session/owner
// authority against the exact local AC connection, disables local serving,
// sends the strict REV, and commits the authenticated RVA under that lease.
// Failures leave the lease to expire; retrying immediately would create a hot
// loop against a disconnected AC and is unnecessary for correctness.
func (s *UdpServer) deliverDueExactCloseTask(ctx context.Context,
	store sessionControlOwnerTaskDeliveryStore, discovered sessionControlCloseTask,
) error {
	if s == nil || store == nil || ctx == nil || validateSessionControlCloseTask(discovered) != nil ||
		discovered.State == sessionControlCloseTaskStateAcked {
		return common.ErrInvalidInput
	}
	conn := s.findSessionControlTaskConnection(discovered)
	if conn == nil {
		return common.ErrACSessionControlNotReady
	}
	releaseOwner, err := s.acquireACSessionControlAuthorityWrite(ctx, conn)
	if err != nil {
		return err
	}
	defer releaseOwner()
	if !sessionControlTaskMatchesConnectionIdentity(discovered, conn) ||
		s.findSessionControlTaskConnection(discovered) != conn {
		return common.ErrACSessionControlNotReady
	}
	return s.deliverExactCloseTaskOnConnection(ctx, store, conn, discovered, true)
}

func (s *UdpServer) deliverExactCloseTaskOnConnection(ctx context.Context,
	store sessionControlOwnerTaskDeliveryStore, conn *ACConn, discovered sessionControlCloseTask,
	restoreReady bool,
) error {
	if !sessionControlTaskMatchesConnectionIdentity(discovered, conn) {
		return common.ErrACSessionControlNotReady
	}
	operationID, err := newAgentSessionCloseEventID()
	if err != nil {
		return err
	}
	leaseID, err := newAgentSessionCloseEventID()
	if err != nil {
		return err
	}
	leaseOwner, err := s.sessionOwnerID()
	if err != nil {
		return err
	}
	lease := sessionControlCloseTaskLeaseRequest{CellID: discovered.CellID, EventID: discovered.EventID,
		OwnerPK: discovered.OwnerPK, OperationID: operationID, LeaseID: leaseID, LeaseOwner: leaseOwner}
	claimed, err := store.ClaimExactCloseTaskForDelivery(ctx, lease)
	if err != nil {
		return err
	}
	if claimed == nil || !sessionControlExactCloseTaskMatchesConnection(*claimed, conn) ||
		claimed.Task.State != sessionControlCloseTaskStateLeased || claimed.Task.LeaseID != lease.LeaseID ||
		claimed.Task.LeaseOwner != lease.LeaseOwner {
		return errSessionControlCloseTaskConflict
	}
	// The durable OWNER is already unready while pending work exists. Clear the
	// process-local optimization before any network delivery so health/routing
	// converge promptly on this process too.
	conn.sessionControlAuthorityReady.Store(false)
	leaseDeadline := time.UnixMilli(claimed.Task.LeaseExpiresAtMillis).Add(-time.Second)
	if !leaseDeadline.After(time.Now()) {
		return errSessionControlCloseTaskConflict
	}
	sendCtx, sendCancel := context.WithDeadline(ctx, leaseDeadline)
	ack, err := s.sendACSessionControlTask(sendCtx, conn, *claimed)
	sendCancel()
	if err != nil {
		return err
	}
	// Once an exact authenticated RVA exists, its immutable diagnostic must win
	// even if the caller or send budget expires. The store already classifies a
	// lost response against this exact lease/ACK, so use one fresh bounded commit
	// context and never release the lease after this point.
	ackCtx, ackCancel := context.WithTimeout(context.WithoutCancel(ctx), DynamoDBOperationTimeout)
	acked, err := store.AckExactCloseTask(ackCtx, sessionControlCloseTaskAckRequest{
		Lease: lease, AuthenticatedPublicKey: conn.ACPeer.PubKeyBase64, Ack: ack,
	})
	ackCancel()
	if err != nil {
		if restoreReady {
			// The ACK transaction may have committed even when its fresh result
			// classification also lost transport. An ACKED row has no due index,
			// so force exact AOL recovery rather than strand this local conn false.
			s.removePublishedACSessionControlConnection(conn.ACId, conn)
		}
		return err
	}
	if acked == nil || acked.EventID != claimed.Task.EventID || acked.OwnerPK != claimed.Task.OwnerPK ||
		acked.State != sessionControlCloseTaskStateAcked {
		return errSessionControlCloseTaskConflict
	}
	if restoreReady {
		readyCtx, readyCancel := context.WithTimeout(context.WithoutCancel(ctx), DynamoDBOperationTimeout)
		readyErr := s.restoreSessionControlConnectionAfterTaskAck(readyCtx, store, conn, *acked)
		readyCancel()
		if readyErr != nil {
			// ACKED tasks have no due keys, so there is no durable rediscovery
			// event that can repair a failed local-ready projection. Drop the
			// exact publication and force the AC through the AOL strong snapshot
			// path instead of stranding a silent, permanently unready socket.
			s.removePublishedACSessionControlConnection(conn.ACId, conn)
		}
	}
	return nil
}

func sessionControlTaskDeliveryIgnorable(err error) bool {
	return errors.Is(err, common.ErrACSessionControlNotReady) ||
		errors.Is(err, errSessionControlCloseTaskBusy) ||
		errors.Is(err, errSessionControlCloseTaskConflict) ||
		errors.Is(err, errSessionControlCloseTaskNotFound)
}

// drainACSessionControlTasksForTarget runs while HandleACOnline owns the exact
// per-owner write gate. For an exact same-process retry it drains tasks before
// Prepare can version the target. For a strictly newer process it runs after
// catch-up/Activate, rebinds every older task to the new ACTIVE_UNREADY target,
// and proves pending_count reached zero before AAK/final readiness.
func (s *UdpServer) drainACSessionControlTasksForTarget(ctx context.Context, conn *ACConn,
	target sessionControlTargetAuthority, allowRebind bool,
) error {
	store, ok := s.sessionControlStore.(sessionControlOwnerTaskDeliveryStore)
	if !ok {
		return errors.New("session-control task-delivery capability is unavailable")
	}
	if conn == nil || conn.ACPeer == nil || target.ControlCellID != s.sessionControlCellID ||
		target.ACID != conn.ACId || target.PublicKey != conn.ACPeer.PubKeyBase64 ||
		target.BootID != conn.BootID || target.FlushGeneration != conn.FlushGeneration ||
		target.State != sessionControlTargetActive || !target.CountedActiveSlot ||
		target.ActivatedControlVersion == 0 || target.RetiredAtMillis != 0 {
		return common.ErrACSessionControlNotReady
	}
	snapshot, err := store.SnapshotOwnerExactCloseTasks(ctx, target.ControlCellID, target.ACID, target.PublicKey)
	if err != nil {
		return err
	}
	if snapshot.Owner.PendingCount == 0 {
		return nil
	}
	if !snapshot.Owner.exactTarget(target, snapshot.Owner.Phase) {
		return errSessionControlOwnerConflict
	}
	targetCopy := target
	conn.sessionControlTarget.Store(&targetCopy)
	conn.sessionControlAuthorityReady.Store(false)
	for _, entry := range snapshot.Tasks {
		task := entry.Task
		if task.State == sessionControlCloseTaskStateAcked {
			continue
		}
		if !sessionControlCloseTaskBoundToTarget(task, target) {
			if !allowRebind || target.FlushGeneration <= task.BoundFlushGeneration {
				return errSessionControlCloseTaskConflict
			}
			operationID, idErr := newAgentSessionCloseEventID()
			if idErr != nil {
				return idErr
			}
			rebound, rebindErr := store.RebindExactCloseTask(ctx, sessionControlCloseTaskRebindRequest{
				CellID: target.ControlCellID, EventID: task.EventID, OwnerPK: task.OwnerPK,
				OperationID: operationID, Target: target,
			})
			if rebindErr != nil {
				return rebindErr
			}
			task = *rebound
		}
		if err = s.deliverExactCloseTaskOnConnection(ctx, store, conn, task, false); err != nil {
			return err
		}
	}
	after, err := store.SnapshotOwnerExactCloseTasks(ctx, target.ControlCellID, target.ACID, target.PublicKey)
	if err != nil {
		return err
	}
	if after.Owner.PendingCount != 0 || !after.Owner.exactTarget(target, after.Owner.Phase) {
		return errSessionControlOwnerConflict
	}
	return nil
}
