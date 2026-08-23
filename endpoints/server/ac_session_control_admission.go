package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

const (
	maxACSessionControlAdmissionAttempts = 4
	acSessionControlFenceRetryInterval   = time.Second
	acSessionControlAuthorityGateWeight  = int64(1 << 30)
)

type acSessionControlAdmissionLock struct {
	mu   sync.Mutex
	refs uint64
}

type acSessionControlAuthorityGateKey struct {
	acID      string
	publicKey string
}

type acSessionControlAuthorityGate struct {
	semaphore *semaphore.Weighted
	refs      uint64
}

var errACSessionControlAdmissionBusy = errors.New("AC session-control admission is busy")

type acSessionControlFenceWaiterKey struct {
	connData        *core.ConnectionData
	acPublicKey     string
	eventID         string
	selectorDigest  string
	bootID          string
	flushGeneration uint64
}

type acSessionControlFenceWaiter struct {
	// Preserve the exact authenticated acknowledgement instead of reducing it
	// to a wake-up bit. Active-fence catch-up currently needs only completion,
	// while durable task delivery must commit the AC's exact Closed diagnostic,
	// boot identity, and flush generation after the same strict waiter match.
	ack chan common.ACSessionCloseAckMsg
}

func newACSessionControlAdmissionLock() *acSessionControlAdmissionLock {
	return &acSessionControlAdmissionLock{}
}

func sessionControlAuthorityGateKeyForConn(conn *ACConn) (acSessionControlAuthorityGateKey, error) {
	if conn == nil || !canonicalSessionControlACID(conn.ACId) || conn.ACPeer == nil ||
		!common.ValidNHPAgentPublicKey(conn.ACPeer.PubKeyBase64) {
		return acSessionControlAuthorityGateKey{}, errors.New("invalid AC session-control authority gate identity")
	}
	return acSessionControlAuthorityGateKey{acID: conn.ACId, publicKey: conn.ACPeer.PubKeyBase64}, nil
}

func (s *UdpServer) acquireACSessionControlAuthority(ctx context.Context, key acSessionControlAuthorityGateKey, weight int64) (func(), error) {
	if s == nil || ctx == nil || !canonicalSessionControlACID(key.acID) || key.publicKey == "" ||
		(weight != 1 && weight != acSessionControlAuthorityGateWeight) {
		return nil, errors.New("invalid AC session-control authority acquisition")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.acSessionControlAuthorityGatesMu.Lock()
	if s.acSessionControlAuthorityGates == nil {
		s.acSessionControlAuthorityGates = make(map[acSessionControlAuthorityGateKey]*acSessionControlAuthorityGate)
	}
	entry := s.acSessionControlAuthorityGates[key]
	if entry == nil {
		entry = &acSessionControlAuthorityGate{semaphore: semaphore.NewWeighted(acSessionControlAuthorityGateWeight)}
		s.acSessionControlAuthorityGates[key] = entry
	}
	entry.refs++
	s.acSessionControlAuthorityGatesMu.Unlock()

	if err := entry.semaphore.Acquire(ctx, weight); err != nil {
		s.acSessionControlAuthorityGatesMu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(s.acSessionControlAuthorityGates, key)
		}
		s.acSessionControlAuthorityGatesMu.Unlock()
		return nil, err
	}
	return func() {
		entry.semaphore.Release(weight)
		s.acSessionControlAuthorityGatesMu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(s.acSessionControlAuthorityGates, key)
		}
		s.acSessionControlAuthorityGatesMu.Unlock()
	}, nil
}

func (s *UdpServer) acquireACSessionControlAuthorityRead(ctx context.Context, conn *ACConn) (func(), error) {
	key, err := sessionControlAuthorityGateKeyForConn(conn)
	if err != nil {
		return nil, err
	}
	return s.acquireACSessionControlAuthority(ctx, key, 1)
}

func (s *UdpServer) acquireACSessionControlAuthorityWrite(ctx context.Context, conn *ACConn) (func(), error) {
	key, err := sessionControlAuthorityGateKeyForConn(conn)
	if err != nil {
		return nil, err
	}
	return s.acquireACSessionControlAuthority(ctx, key, acSessionControlAuthorityGateWeight)
}

// acquireACSessionControlAdmission serializes one AC's durable admission. It
// never queues a goroutine behind an in-flight AOL: callers receive a bounded
// busy rejection and the AC retries AOL. The bookkeeping mutex is not held
// while the keyed lock or caller's store/network work is in progress. The
// release closure must be deferred immediately.
func (s *UdpServer) acquireACSessionControlAdmission(ctx context.Context, acID string) (func(), error) {
	if s == nil || ctx == nil || !canonicalSessionControlACID(acID) {
		return nil, errors.New("invalid AC session-control admission identity")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.acSessionControlAdmissionMu.Lock()
	if s.acSessionControlAdmissions == nil {
		s.acSessionControlAdmissions = make(map[string]*acSessionControlAdmissionLock)
	}
	entry := s.acSessionControlAdmissions[acID]
	if entry == nil {
		entry = newACSessionControlAdmissionLock()
		s.acSessionControlAdmissions[acID] = entry
	}
	entry.refs++
	s.acSessionControlAdmissionMu.Unlock()

	if !entry.mu.TryLock() {
		s.acSessionControlAdmissionMu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(s.acSessionControlAdmissions, acID)
		}
		s.acSessionControlAdmissionMu.Unlock()
		return nil, errACSessionControlAdmissionBusy
	}
	return func() {
		entry.mu.Unlock()
		s.acSessionControlAdmissionMu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(s.acSessionControlAdmissions, acID)
		}
		s.acSessionControlAdmissionMu.Unlock()
	}, nil
}

func sessionControlFenceSelectorFromAck(ack common.ACSessionCloseAckMsg) (sessionControlFenceSelector, error) {
	selector := sessionControlFenceSelector{AgentPublicKey: ack.AgentPublicKey}
	switch ack.Scope {
	case common.ACSessionCloseScopeExact:
		selector.Scope = sessionControlFenceSelectorExact
		selector.SessionID = ack.SessionID
		selector.SessionIssuedMillis = ack.SessionIssuedAtMillis
	case common.ACSessionCloseScopeAgent:
		selector.Scope = sessionControlFenceSelectorAgent
		selector.IssuedThroughMillis = ack.IssuedThroughMillis
	case common.ACSessionCloseScopeRun:
		selector.Scope = sessionControlFenceSelectorRun
		selector.RunID = ack.RunID
		selector.RunAttempt = ack.RunAttempt
	default:
		return sessionControlFenceSelector{}, errors.New("unsupported session-control acknowledgement scope")
	}
	if err := validateSessionControlFenceSelector(selector); err != nil {
		return sessionControlFenceSelector{}, err
	}
	return selector, nil
}

func sessionControlFenceWaiterKeyForSend(conn *ACConn, fence sessionControlFenceAuthority) (acSessionControlFenceWaiterKey, error) {
	if err := validateSessionControlFenceAuthority(fence); err != nil || fence.State == sessionControlFenceRetired {
		return acSessionControlFenceWaiterKey{}, errors.New("invalid active session-control fence")
	}
	return sessionControlFenceWaiterKeyForSelectorSend(conn, fence.EventID, fence.Selector)
}

func sessionControlFenceWaiterKeyForSelectorSend(conn *ACConn, eventID string,
	selector sessionControlFenceSelector,
) (acSessionControlFenceWaiterKey, error) {
	if conn == nil || conn.ConnData == nil || conn.ACPeer == nil ||
		!common.ValidNHPACBootID(conn.BootID) || conn.FlushGeneration == 0 ||
		!validSessionControlFenceEventID(eventID) || validateSessionControlFenceSelector(selector) != nil {
		return acSessionControlFenceWaiterKey{}, errors.New("invalid AC session-control catch-up connection")
	}
	acPublicKey := conn.ACPeer.PublicKey()
	if len(acPublicKey) != core.PublicKeySize || base64.StdEncoding.EncodeToString(acPublicKey) != conn.ACPeer.PubKeyBase64 {
		return acSessionControlFenceWaiterKey{}, errors.New("invalid AC session-control catch-up public key")
	}
	digest, err := sessionControlFenceSelectorDigest(selector)
	if err != nil {
		return acSessionControlFenceWaiterKey{}, err
	}
	return acSessionControlFenceWaiterKey{
		connData: conn.ConnData, acPublicKey: conn.ACPeer.PubKeyBase64,
		eventID: eventID, selectorDigest: digest,
		bootID: conn.BootID, flushGeneration: conn.FlushGeneration,
	}, nil
}

func sessionControlFenceWaiterKeyForAck(ppd *core.PacketParserData, ack common.ACSessionCloseAckMsg) (acSessionControlFenceWaiterKey, error) {
	if ppd == nil || ppd.HeaderType != core.NHP_RVA || ppd.ConnData == nil || len(ppd.RemotePubKey) != core.PublicKeySize {
		return acSessionControlFenceWaiterKey{}, errors.New("invalid session-control acknowledgement envelope")
	}
	selector, err := sessionControlFenceSelectorFromAck(ack)
	if err != nil {
		return acSessionControlFenceWaiterKey{}, err
	}
	digest, err := sessionControlFenceSelectorDigest(selector)
	if err != nil {
		return acSessionControlFenceWaiterKey{}, err
	}
	return acSessionControlFenceWaiterKey{
		connData: ppd.ConnData, acPublicKey: base64.StdEncoding.EncodeToString(ppd.RemotePubKey),
		eventID: ack.EventID, selectorDigest: digest,
		bootID: ack.BootID, flushGeneration: ack.FlushGeneration,
	}, nil
}

func (s *UdpServer) registerACSessionControlFenceWaiter(key acSessionControlFenceWaiterKey) (*acSessionControlFenceWaiter, func(), error) {
	if s == nil || key.connData == nil || key.acPublicKey == "" || key.eventID == "" || key.selectorDigest == "" || key.bootID == "" || key.flushGeneration == 0 {
		return nil, nil, errors.New("invalid AC session-control acknowledgement waiter")
	}
	waiter := &acSessionControlFenceWaiter{ack: make(chan common.ACSessionCloseAckMsg, 1)}
	s.acSessionControlFenceWaitersMu.Lock()
	if s.acSessionControlFenceWaiters == nil {
		s.acSessionControlFenceWaiters = make(map[acSessionControlFenceWaiterKey]*acSessionControlFenceWaiter)
	}
	if s.acSessionControlFenceWaiters[key] != nil {
		s.acSessionControlFenceWaitersMu.Unlock()
		return nil, nil, errors.New("duplicate AC session-control acknowledgement waiter")
	}
	s.acSessionControlFenceWaiters[key] = waiter
	s.acSessionControlFenceWaitersMu.Unlock()
	return waiter, func() {
		s.acSessionControlFenceWaitersMu.Lock()
		if s.acSessionControlFenceWaiters[key] == waiter {
			delete(s.acSessionControlFenceWaiters, key)
		}
		s.acSessionControlFenceWaitersMu.Unlock()
	}, nil
}

// handleACSessionControlFenceAck strictly routes kind-bearing NHP_RVA packets
// to a waiter registered before the corresponding NHP_REV was enqueued. It
// does not consult acConnectionMap because catch-up precedes connection
// publication. Authentication is bound by RemotePubKey and exact ConnData.
func (s *UdpServer) handleACSessionControlFenceAck(ppd *core.PacketParserData) (bool, error) {
	if s == nil || ppd == nil {
		return false, common.ErrInvalidInput
	}
	present, err := common.ACSessionCloseKindPresent(ppd.BodyMessage)
	if err != nil || !present {
		return present, err
	}
	var ack common.ACSessionCloseAckMsg
	if err := common.DecodeACSessionCloseAckMsg(ppd.BodyMessage, &ack); err != nil {
		return true, fmt.Errorf("decode AC session-control catch-up acknowledgement: %w", err)
	}
	key, err := sessionControlFenceWaiterKeyForAck(ppd, ack)
	if err != nil {
		return true, err
	}
	s.acSessionControlFenceWaitersMu.Lock()
	waiter := s.acSessionControlFenceWaiters[key]
	if waiter != nil {
		delete(s.acSessionControlFenceWaiters, key)
	}
	s.acSessionControlFenceWaitersMu.Unlock()
	if waiter == nil {
		return true, common.ErrACOperationFailed
	}
	waiter.ack <- ack
	return true, nil
}

func (s *UdpServer) configureSessionControlCellID(lookupEnv func(string) (string, bool)) error {
	if s == nil || lookupEnv == nil {
		return errors.New("session-control cell identity resolver is unavailable")
	}
	cellID, present := lookupEnv("NHP_CELL_ID")
	if !present || !validSessionControlCellID(cellID) {
		return errors.New("cloud session-control authority requires canonical NHP_CELL_ID")
	}
	s.sessionControlCellID = cellID
	return nil
}

func (s *UdpServer) configureCloudSessionControlCellID() error {
	return s.configureSessionControlCellID(os.LookupEnv)
}

func (s *UdpServer) successfulACOnlineAckMsgData(
	ppd *core.PacketParserData,
	aolMsg *common.ACOnlineMsg,
	assignedPeers []common.RedirectTarget,
) (*core.MsgData, error) {
	if s == nil || ppd == nil || ppd.ConnData == nil || ppd.ConnData.RemoteAddr == nil ||
		aolMsg == nil || s.listenAddr == nil || s.device == nil {
		return nil, errors.New("AC online success response dependencies are unavailable")
	}
	ack := &common.ServerACAckMsg{
		ErrCode:                common.ErrSuccess.ErrorCode(),
		ACAddr:                 ppd.ConnData.RemoteAddr.String(),
		Registered:             true,
		ServerAddr:             fmt.Sprintf("%s:%d", s.localIp, s.listenAddr.Port),
		ServerPubKey:           s.device.PublicKeyBase64(),
		Peers:                  assignedPeers,
		BootID:                 aolMsg.BootID,
		SessionFlushGeneration: aolMsg.SessionFlushGeneration,
		AOLTransactionID:       ppd.SenderTrxId,
	}
	body, err := json.Marshal(ack)
	if err != nil {
		return nil, fmt.Errorf("marshal AC online success acknowledgement: %w", err)
	}
	return makeMsgData(ppd, core.NHP_AAK, body), nil
}

func (s *UdpServer) sessionControlAuthorityRequired() bool {
	return s != nil && s.sessionControlCellID != ""
}

func (c *ACConn) sessionControlReady(required bool) bool {
	if c == nil {
		return false
	}
	if !required {
		return true
	}
	target := c.sessionControlTarget.Load()
	return c.sessionControlAuthorityReady.Load() && target != nil && target.ready() && c.ACPeer != nil &&
		target.ACID == c.ACId && target.PublicKey == c.ACPeer.PubKeyBase64 && target.BootID == c.BootID &&
		target.FlushGeneration == c.FlushGeneration
}

func (s *UdpServer) markACSessionControlConnectionNotReady(acID, publicKey string) {
	if s == nil {
		return
	}
	s.acConnectionMapMutex.Lock()
	defer s.acConnectionMapMutex.Unlock()
	for _, conn := range s.acConnectionMap[acID] {
		if conn == nil || conn.ACPeer == nil || conn.ACPeer.PubKeyBase64 != publicKey {
			continue
		}
		conn.sessionControlAuthorityReady.Store(false)
		conn.sessionControlTarget.Store(nil)
	}
}

// removePublishedACSessionControlConnection removes exactly the connection
// staged by one AOL attempt when its success AAK cannot be enqueued. Durable
// readiness authorization already succeeded, so the target deliberately
// remains READY for the AC's next exact attachment AOL; only the unpublished
// process-local projection and its UDP connection are removed.
func (s *UdpServer) removePublishedACSessionControlConnection(acID string, target *ACConn) bool {
	if s == nil || target == nil {
		return false
	}
	publicKey, _ := acConnPubkey(target)
	addr := ""
	if target.ConnData != nil && target.ConnData.RemoteAddr != nil {
		addr = target.ConnData.RemoteAddr.String()
	}

	s.acConnectionMapMutex.Lock()
	conns := s.acConnectionMap[acID]
	kept := make([]*ACConn, 0, len(conns))
	removed := false
	for _, conn := range conns {
		if conn == target {
			removed = true
			continue
		}
		kept = append(kept, conn)
	}
	if removed {
		if len(kept) == 0 {
			delete(s.acConnectionMap, acID)
		} else {
			s.acConnectionMap[acID] = kept
		}
	}
	s.acConnectionMapMutex.Unlock()
	if removed {
		if udpConn := s.lookupRemoteConnForDrop(addr, target.ConnData); udpConn != nil {
			s.removeConnection(udpConn, addr)
			go udpConn.Close()
		}
	}
	// The connection routine can win the map removal race immediately before
	// this cleanup. It does not own AC peer removal, so always reconcile the peer
	// after the exact-pointer attempt; the live-connection scan preserves any
	// sibling publication.
	s.removeACPeerIfNoLiveConn(publicKey)
	return removed
}

func sessionControlCloseMessage(fence sessionControlFenceAuthority) (common.ACSessionCloseMsg, error) {
	if err := validateSessionControlFenceAuthority(fence); err != nil || fence.State == sessionControlFenceRetired {
		return common.ACSessionCloseMsg{}, errors.New("invalid active session-control fence")
	}
	return sessionControlCloseMessageForSelector(fence.EventID, fence.Selector)
}

func sessionControlCloseMessageForSelector(eventID string,
	selector sessionControlFenceSelector,
) (common.ACSessionCloseMsg, error) {
	if !validSessionControlFenceEventID(eventID) || validateSessionControlFenceSelector(selector) != nil {
		return common.ACSessionCloseMsg{}, errors.New("invalid session-control close selector")
	}
	message := common.ACSessionCloseMsg{
		Kind:           common.ACSessionCloseKind,
		EventID:        eventID,
		AgentPublicKey: selector.AgentPublicKey,
	}
	switch selector.Scope {
	case sessionControlFenceSelectorExact:
		message.Scope = common.ACSessionCloseScopeExact
		message.SessionID = selector.SessionID
		message.SessionIssuedAtMillis = selector.SessionIssuedMillis
	case sessionControlFenceSelectorAgent:
		message.Scope = common.ACSessionCloseScopeAgent
		message.IssuedThroughMillis = selector.IssuedThroughMillis
	case sessionControlFenceSelectorRun:
		message.Scope = common.ACSessionCloseScopeRun
		message.RunID = selector.RunID
		message.RunAttempt = selector.RunAttempt
	default:
		return common.ACSessionCloseMsg{}, errors.New("unsupported session-control fence selector")
	}
	return message, nil
}

func (s *UdpServer) sendACSessionControlFence(ctx context.Context, conn *ACConn, fence sessionControlFenceAuthority) error {
	if s == nil {
		return common.ErrInvalidInput
	}
	if s.sendACSessionControlFenceFn != nil {
		return s.sendACSessionControlFenceFn(ctx, conn, fence)
	}
	_, err := s.sendACSessionControlSelector(ctx, conn, fence.EventID, fence.Selector)
	return err
}

func sessionControlExactCloseTaskMatchesConnection(authority sessionControlExactCloseTaskAuthority,
	conn *ACConn,
) bool {
	if conn == nil || conn.ACPeer == nil || conn.ConnData == nil ||
		!sessionControlExactCloseTaskAuthorityValid(authority) ||
		!sessionControlCloseTaskMatchesOwner(authority.Task, authority.Owner) ||
		authority.Task.ACID != conn.ACId || authority.Task.PublicKey != conn.ACPeer.PubKeyBase64 ||
		authority.Task.BoundBootID != conn.BootID ||
		authority.Task.BoundFlushGeneration != conn.FlushGeneration {
		return false
	}
	target := conn.sessionControlTarget.Load()
	return target != nil && validateSessionControlTargetAuthority(*target) == nil &&
		target.State == sessionControlTargetActive && target.CountedActiveSlot &&
		target.ActivatedControlVersion > 0 && target.RetiredAtMillis == 0 &&
		target.ControlCellID == authority.Task.CellID && target.ACID == authority.Task.ACID &&
		target.PublicKey == authority.Task.PublicKey && target.BootID == authority.Task.BoundBootID &&
		target.FlushGeneration == authority.Task.BoundFlushGeneration &&
		target.Version == authority.Task.BoundTargetVersion &&
		target.AuthorityVersion == authority.Task.BoundAuthorityVersion &&
		target.ActivatedControlVersion == authority.Task.BoundActivatedCursor &&
		target.ReadyControlVersion == authority.Task.BoundReadyCursor
}

func (s *UdpServer) sendACSessionControlTask(ctx context.Context, conn *ACConn,
	authority sessionControlExactCloseTaskAuthority,
) (common.ACSessionCloseAckMsg, error) {
	if s == nil || !sessionControlExactCloseTaskMatchesConnection(authority, conn) ||
		authority.Work.EventID != authority.Task.EventID ||
		authority.Work.SelectorDigest != authority.Task.SelectorDigest {
		return common.ACSessionCloseAckMsg{}, common.ErrACSessionControlNotReady
	}
	if s.sendACSessionControlTaskFn != nil {
		return s.sendACSessionControlTaskFn(ctx, conn, authority)
	}
	return s.sendACSessionControlSelector(ctx, conn, authority.Task.EventID, authority.Work.Selector)
}

func (s *UdpServer) sendACSessionControlSelector(ctx context.Context, conn *ACConn, eventID string,
	selector sessionControlFenceSelector,
) (common.ACSessionCloseAckMsg, error) {
	if s == nil {
		return common.ACSessionCloseAckMsg{}, common.ErrInvalidInput
	}
	if ctx == nil || conn == nil || conn.ConnData == nil || conn.ACPeer == nil || s.device == nil || s.sendMsgCh == nil {
		return common.ACSessionCloseAckMsg{}, common.ErrInvalidInput
	}
	message, err := sessionControlCloseMessageForSelector(eventID, selector)
	if err != nil {
		return common.ACSessionCloseAckMsg{}, err
	}
	body, err := json.Marshal(message)
	if err != nil {
		return common.ACSessionCloseAckMsg{}, fmt.Errorf("marshal AC session-control catch-up: %w", err)
	}
	waiterKey, err := sessionControlFenceWaiterKeyForSelectorSend(conn, eventID, selector)
	if err != nil {
		return common.ACSessionCloseAckMsg{}, err
	}
	waiter, unregister, err := s.registerACSessionControlFenceWaiter(waiterKey)
	if err != nil {
		return common.ACSessionCloseAckMsg{}, err
	}
	defer unregister()
	if !s.IsRunning() {
		return common.ACSessionCloseAckMsg{}, common.ErrPacketToMessageRoutineStopped
	}
	ticker := time.NewTicker(acSessionControlFenceRetryInterval)
	defer ticker.Stop()
	for {
		// Each retransmission uses a fresh NHP counter while preserving the exact
		// immutable event and body. The waiter remains installed continuously, so
		// an acknowledgement racing the retry cannot be lost between attempts.
		md := &core.MsgData{
			ConnData: conn.ConnData, HeaderType: core.NHP_REV, CipherScheme: conn.ACCipherScheme,
			TransactionId: s.device.NextCounterIndex(), Compress: true,
			PeerPk: conn.ACPeer.PublicKey(), Message: body,
		}
		select {
		case s.sendMsgCh <- md:
		case ack := <-waiter.ack:
			return ack, nil
		case <-ctx.Done():
			return common.ACSessionCloseAckMsg{}, ctx.Err()
		case <-s.signals.stop:
			return common.ACSessionCloseAckMsg{}, common.ErrPacketToMessageRoutineStopped
		}
		select {
		case ack := <-waiter.ack:
			return ack, nil
		case <-ticker.C:
			continue
		case <-ctx.Done():
			return common.ACSessionCloseAckMsg{}, ctx.Err()
		case <-s.signals.stop:
			return common.ACSessionCloseAckMsg{}, common.ErrPacketToMessageRoutineStopped
		}
	}
}

type acSessionControlTargetActivationResult struct {
	Target         sessionControlTargetAuthority
	Snapshot       sessionControlFenceSnapshot
	ExistingActive bool
	AlreadyReady   bool
}

func (s *UdpServer) catchUpReadyACSessionControlTarget(ctx context.Context, conn *ACConn,
	target sessionControlTargetAuthority,
) (*sessionControlTargetAttachment, error) {
	snapshot, candidate, err := s.catchUpExistingACSessionControlTarget(ctx, conn, target)
	if err != nil {
		return nil, err
	}
	if !target.ready() {
		return nil, errSessionControlTargetConflict
	}
	attachment := &sessionControlTargetAttachment{Candidate: candidate, Target: target, Snapshot: *snapshot}
	if !validSessionControlTargetAttachment(*attachment) {
		return nil, errSessionControlTargetCorrupt
	}
	return attachment, nil
}

func (s *UdpServer) catchUpExistingACSessionControlTarget(ctx context.Context, conn *ACConn,
	target sessionControlTargetAuthority,
) (*sessionControlFenceSnapshot, sessionControlTargetCandidate, error) {
	snapshot, candidate, err := s.snapshotExistingACSessionControlTarget(ctx, conn, target)
	if err != nil {
		return nil, sessionControlTargetCandidate{}, err
	}
	for _, activeFence := range snapshot.Fences {
		if err := s.sendACSessionControlFence(ctx, conn, activeFence); err != nil {
			return nil, sessionControlTargetCandidate{}, err
		}
	}
	return snapshot, candidate, nil
}

// snapshotExistingACSessionControlTarget validates one exact durable target and
// obtains the current CONTROL authority without sending any fence. Callers must
// compare the cursor before choosing the one catch-up path they will execute;
// an advanced ACTIVE_UNREADY target is deliberately re-prepared and must not
// spend the aggregate AOL deadline sending the same (up to 1024) fences twice.
func (s *UdpServer) snapshotExistingACSessionControlTarget(ctx context.Context, conn *ACConn,
	target sessionControlTargetAuthority,
) (*sessionControlFenceSnapshot, sessionControlTargetCandidate, error) {
	if s == nil || ctx == nil || s.sessionControlStore == nil || conn == nil || conn.ACPeer == nil {
		return nil, sessionControlTargetCandidate{}, errors.New("session-control attachment is unavailable")
	}
	candidate := sessionControlTargetCandidate{
		ACID: conn.ACId, PublicKey: conn.ACPeer.PubKeyBase64,
		BootID: conn.BootID, FlushGeneration: conn.FlushGeneration,
		ControlCellID: s.sessionControlCellID,
	}
	if validateSessionControlTargetAuthority(target) != nil || !target.exactCandidate(candidate) ||
		target.State != sessionControlTargetActive || !target.CountedActiveSlot ||
		target.ActivatedControlVersion == 0 || target.RetiredAtMillis != 0 {
		return nil, sessionControlTargetCandidate{}, errSessionControlTargetConflict
	}
	snapshot, err := s.sessionControlStore.SnapshotActiveFences(ctx, s.sessionControlCellID)
	if err != nil {
		return nil, sessionControlTargetCandidate{}, err
	}
	if snapshot == nil || validateSessionControlFenceSnapshot(*snapshot, s.sessionControlCellID) != nil ||
		snapshot.AdmissionBlocked {
		return nil, sessionControlTargetCandidate{}, errSessionControlFenceCorrupt
	}
	return snapshot, candidate, nil
}

func (s *UdpServer) verifyConcurrentReadyACSessionControlTarget(ctx context.Context, conn *ACConn,
	snapshot sessionControlFenceSnapshot,
) (*sessionControlTargetAuthority, error) {
	if s == nil || ctx == nil || conn == nil || conn.ACPeer == nil {
		return nil, common.ErrACSessionControlNotReady
	}
	candidate := sessionControlTargetCandidate{
		ACID: conn.ACId, PublicKey: conn.ACPeer.PubKeyBase64,
		BootID: conn.BootID, FlushGeneration: conn.FlushGeneration,
		ControlCellID: s.sessionControlCellID,
	}
	target, err := s.sessionControlStore.GetTarget(ctx, sessionControlTargetKey{
		ACID: candidate.ACID, PublicKey: candidate.PublicKey,
	})
	if err != nil {
		return nil, err
	}
	attachment := sessionControlTargetAttachment{Candidate: candidate, Target: *target, Snapshot: snapshot}
	if !validSessionControlTargetAttachment(attachment) {
		return nil, errSessionControlTargetConflict
	}
	return s.sessionControlStore.VerifyReadyTargetAttachment(ctx, attachment)
}

func (s *UdpServer) activateACSessionControlTarget(ctx context.Context, conn *ACConn) (result *sessionControlTargetAuthority, err error) {
	activation, err := s.activateACSessionControlTargetWithSnapshotAfterPrepare(ctx, conn, nil)
	if err != nil {
		return nil, err
	}
	return &activation.Target, nil
}

func (s *UdpServer) activateACSessionControlTargetAfterPrepare(
	ctx context.Context,
	conn *ACConn,
	afterPrepare func(sessionControlTargetPreparation),
) (result *sessionControlTargetAuthority, err error) {
	activation, err := s.activateACSessionControlTargetWithSnapshotAfterPrepare(ctx, conn, afterPrepare)
	if err != nil {
		return nil, err
	}
	return &activation.Target, nil
}

func (s *UdpServer) activateACSessionControlTargetWithSnapshotAfterPrepare(
	ctx context.Context,
	conn *ACConn,
	afterPrepare func(sessionControlTargetPreparation),
) (result *acSessionControlTargetActivationResult, err error) {
	if s == nil || ctx == nil || s.sessionControlStore == nil || !validSessionControlCellID(s.sessionControlCellID) ||
		conn == nil || conn.ACPeer == nil {
		return nil, errors.New("session-control admission is unavailable")
	}
	preparation, err := s.sessionControlStore.PrepareTarget(ctx, sessionControlTargetCandidate{
		ACID:            conn.ACId,
		PublicKey:       conn.ACPeer.PubKeyBase64,
		BootID:          conn.BootID,
		FlushGeneration: conn.FlushGeneration,
		ControlCellID:   s.sessionControlCellID,
	})
	if err != nil {
		return nil, err
	}
	if preparation == nil {
		return nil, errSessionControlTargetCorrupt
	}
	if !preparation.RequiresActivation {
		target := preparation.Target
		snapshot, _, snapshotErr := s.snapshotExistingACSessionControlTarget(ctx, conn, target)
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		if !target.ready() && snapshot.DirectoryVersion != target.ActivatedControlVersion {
			preparation, err = s.sessionControlStore.ReprepareTargetForControlAdvance(ctx,
				sessionControlTargetControlAdvance{Target: target, ObservedControlVersion: snapshot.DirectoryVersion})
			if err != nil {
				return nil, err
			}
			if preparation == nil || !preparation.RequiresActivation {
				return nil, errSessionControlTargetCorrupt
			}
		} else {
			for _, activeFence := range snapshot.Fences {
				if sendErr := s.sendACSessionControlFence(ctx, conn, activeFence); sendErr != nil {
					return nil, sendErr
				}
			}
			return &acSessionControlTargetActivationResult{
				Target: target, Snapshot: *snapshot, ExistingActive: true, AlreadyReady: target.ready(),
			}, nil
		}
	}
	if afterPrepare != nil {
		afterPrepare(*preparation)
	}
	fence := preparation.Target.fence()
	activated := false
	defer func() {
		if activated || fence.CountedActiveSlot || err == nil {
			return
		}
		// Catch-up commonly fails because the aggregate AOL context expired. An
		// exact uncounted preparation must still be compensated; use one fresh,
		// bounded cleanup budget rather than passing an already-canceled context
		// that would deterministically leak PREPARING authority.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), DynamoDBOperationTimeout)
		defer cleanupCancel()
		if _, cancelErr := s.sessionControlStore.CancelTargetPreparation(cleanupCtx, fence); cancelErr != nil {
			err = errors.Join(err, fmt.Errorf("cancel rejected session-control preparation: %w", cancelErr))
		}
	}()

	for range maxACSessionControlAdmissionAttempts {
		snapshot, snapshotErr := s.sessionControlStore.SnapshotActiveFences(ctx, s.sessionControlCellID)
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		if snapshot == nil || snapshot.CellID != s.sessionControlCellID || snapshot.DirectoryVersion == 0 ||
			uint64(len(snapshot.Fences)) != snapshot.ActiveFenceCount {
			return nil, errSessionControlFenceCorrupt
		}
		for _, activeFence := range snapshot.Fences {
			if sendErr := s.sendACSessionControlFence(ctx, conn, activeFence); sendErr != nil {
				return nil, sendErr
			}
		}
		activationRequest := fence.activation(snapshot.DirectoryVersion)
		active, activateErr := s.sessionControlStore.ActivateTarget(ctx, activationRequest)
		if errors.Is(activateErr, errSessionControlTargetControlStale) {
			continue
		}
		if activateErr != nil {
			return nil, activateErr
		}
		expectedActive := sessionControlExpectedActivatedTarget(activationRequest)
		if active == nil || *active != expectedActive {
			return nil, errSessionControlTargetCorrupt
		}
		activated = true
		return &acSessionControlTargetActivationResult{Target: *active, Snapshot: *snapshot}, nil
	}
	return nil, errSessionControlTargetControlStale
}
