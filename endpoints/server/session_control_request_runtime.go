package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

const (
	sessionControlRuntimeSnapshotAttempts  = 4
	sessionControlRuntimeSessionIDAttempts = 4
)

var _ sessionControlRequestStore = (*dynamoSessionControlStore)(nil)
var _ sessionControlExactRetirementStore = (*dynamoSessionControlStore)(nil)

// sessionControlRequestStore is the narrow request-path portion of the durable
// authority. Keeping it separate from sessionControlStore avoids forcing task
// worker methods into every AOL-only test double while production's one Dynamo
// store implements both interfaces.
type sessionControlRequestStore interface {
	ReserveSession(context.Context, sessionControlSessionCandidate, sessionControlFenceSnapshot) (*sessionControlSessionAuthority, error)
	VerifySession(context.Context, sessionControlSessionCandidate, sessionControlFenceSnapshot) (*sessionControlSessionAuthority, error)
	PrepareSessionIntentCurrent(context.Context, sessionControlSessionCandidate, sessionControlTargetAuthority, int64, int64, sessionControlFenceSnapshot) (*sessionControlSessionIntentPreparation, error)
	MarkSessionAckEnqueued(context.Context, sessionControlSessionCandidate, sessionControlFenceSnapshot) (*sessionControlSessionAuthority, error)
	EnsureExactSessionClose(context.Context, sessionControlSessionCandidate, int64) (*sessionControlExactClosePreparation, error)
}

type sessionControlNativeOperationRequestStore interface {
	ReserveNativeSessionOperation(context.Context, sessionControlSessionCandidate, sessionControlNativeOperation,
		sessionControlFenceSnapshot, time.Time) (*sessionControlSessionAuthority, error)
	VerifyMappedNativeSessionOperation(context.Context, sessionControlSessionCandidate,
		sessionControlNativeOperation) (*sessionControlSessionAuthority, *sessionControlFenceDirectory, error)
	CancelAbsentNativeSessionOperation(context.Context, sessionControlNativeOperation,
		time.Time) (*sessionControlNativeOperationAuthority, error)
	ResolveNativeSessionOperation(context.Context, string) (*sessionControlNativeOperationAuthority, error)
}

// sessionControlExactRetirementStore is the authenticated client-close seam.
// Session IDs are globally non-reused durable keys; the strong resolver also
// binds the authenticated agent and assigned cell before the existing exact
// close transition can run.
type sessionControlExactRetirementStore interface {
	ResolveExactSessionForClose(context.Context, sessionControlExactRetirementSelector) (*sessionControlSessionAuthority, error)
	EnsureExactSessionClose(context.Context, sessionControlSessionCandidate, int64) (*sessionControlExactClosePreparation, error)
}

// sessionControlExactRetirementSelector is the complete public receipt. The
// reservation deadline is intentionally excluded: it is server policy stored
// in the canonical SESSION row and must not be reconstructed from today's TTL.
type sessionControlExactRetirementSelector struct {
	CellID         string
	AgentPublicKey string
	SessionID      uint64
	IssuedAtMillis int64
	RunID          string
	RunAttempt     uint64
}

func sessionControlExactRetirementSelectorForCandidate(candidate sessionControlSessionCandidate) sessionControlExactRetirementSelector {
	return sessionControlExactRetirementSelector{
		CellID: candidate.CellID, AgentPublicKey: candidate.AgentPublicKey, SessionID: candidate.SessionID,
		IssuedAtMillis: candidate.IssuedAtMillis, RunID: candidate.RunID, RunAttempt: candidate.RunAttempt,
	}
}

func validSessionControlExactRetirementSelector(selector sessionControlExactRetirementSelector) bool {
	return validSessionControlCellID(selector.CellID) && common.ValidNHPAgentPublicKey(selector.AgentPublicKey) &&
		selector.SessionID > 0 && selector.IssuedAtMillis > 0 && common.ValidateAgentKnockRunID(selector.RunID) == nil &&
		selector.RunAttempt > 0
}

func sessionControlExactRetirementSelectorMatchesCandidate(selector sessionControlExactRetirementSelector,
	candidate sessionControlSessionCandidate,
) bool {
	return selector.CellID == candidate.CellID && selector.AgentPublicKey == candidate.AgentPublicKey &&
		selector.SessionID == candidate.SessionID && selector.IssuedAtMillis == candidate.IssuedAtMillis &&
		selector.RunID == candidate.RunID && selector.RunAttempt == candidate.RunAttempt
}

type sessionControlExactRetirementResult struct {
	Candidate    sessionControlSessionCandidate
	CloseEventID string
	State        string
}

type sessionControlAdmissionReceipt struct {
	Candidate       sessionControlSessionCandidate
	SessionID       uint64
	SessionIssuedAt time.Time
	OpenTime        uint32
}

func (s *UdpServer) requestSessionControlStore() (sessionControlRequestStore, error) {
	if s == nil || s.sessionControlStore == nil {
		return nil, errors.New("session-control request authority is unavailable")
	}
	store, ok := s.sessionControlStore.(sessionControlRequestStore)
	if !ok {
		return nil, errors.New("session-control request authority is incomplete")
	}
	return store, nil
}

func (s *UdpServer) exactRetirementSessionControlStore() (sessionControlExactRetirementStore, error) {
	if s == nil || s.sessionControlStore == nil {
		return nil, errors.New("session-control exact retirement authority is unavailable")
	}
	store, ok := s.sessionControlStore.(sessionControlExactRetirementStore)
	if !ok {
		return nil, errors.New("session-control exact retirement authority is incomplete")
	}
	return store, nil
}

func (s *UdpServer) validateSessionControlExactRetirementCapabilities() error {
	_, err := s.exactRetirementSessionControlStore()
	return err
}

func (s *UdpServer) ensureAuthenticatedExactSessionClose(ctx context.Context,
	selector sessionControlExactRetirementSelector,
) (*sessionControlExactRetirementResult, error) {
	store, err := s.exactRetirementSessionControlStore()
	if err != nil {
		return nil, err
	}
	if !validSessionControlExactRetirementSelector(selector) {
		return nil, errors.New("invalid authenticated exact session receipt")
	}
	releaseCell, err := s.acquireSessionControlCellWrite(ctx)
	if err != nil {
		return nil, err
	}
	defer releaseCell()
	current, err := store.ResolveExactSessionForClose(ctx, selector)
	if err != nil {
		return nil, err
	}
	if current == nil || !sessionControlExactRetirementSelectorMatchesCandidate(selector, current.Candidate) {
		return nil, errSessionControlSessionCorrupt
	}
	expectedEventID := sessionControlExactCloseEventID(current.Candidate)
	if current.State == sessionControlSessionStateClosed {
		if current.CloseEventID != expectedEventID {
			return nil, errSessionControlSessionCorrupt
		}
		return &sessionControlExactRetirementResult{
			Candidate: current.Candidate, CloseEventID: current.CloseEventID, State: sessionControlSessionStateClosed,
		}, nil
	}
	closed, closeErr := store.EnsureExactSessionClose(ctx, current.Candidate, current.RetainUntilMillis)
	if closeErr == nil {
		if closed == nil || closed.Session.Candidate != current.Candidate ||
			closed.Session.State != sessionControlSessionStateClosing ||
			closed.EventID != expectedEventID || closed.Session.CloseEventID != expectedEventID {
			return nil, fmt.Errorf("%w: authenticated exact close result", errSessionControlCloseCorrupt)
		}
		return &sessionControlExactRetirementResult{
			Candidate: current.Candidate, CloseEventID: closed.EventID, State: sessionControlSessionStateClosing,
		}, nil
	}
	// A terminal worker may retire the exact session between the resolver and
	// the close CAS. Accept only the same authenticated durable row in CLOSED;
	// every other conflict or operational error remains fail-closed.
	if ctx.Err() != nil {
		return nil, closeErr
	}
	latest, resultErr := store.ResolveExactSessionForClose(ctx, selector)
	if resultErr == nil && latest != nil && latest.Candidate == current.Candidate &&
		latest.State == sessionControlSessionStateClosed && latest.CloseEventID == expectedEventID {
		return &sessionControlExactRetirementResult{
			Candidate: latest.Candidate, CloseEventID: latest.CloseEventID, State: sessionControlSessionStateClosed,
		}, nil
	}
	return nil, closeErr
}

func sessionControlCandidateForKnock(cellID string, knkMsg *common.AgentKnockMsg) (sessionControlSessionCandidate, error) {
	if knkMsg == nil || knkMsg.NHPSessionIssuedAt.IsZero() {
		return sessionControlSessionCandidate{}, errors.New("missing NHP session authority")
	}
	issuedMillis := knkMsg.NHPSessionIssuedAt.UnixMilli()
	deadlineDelta := pendingSessionReservationTTL.Milliseconds()
	if issuedMillis <= 0 || issuedMillis > math.MaxInt64-deadlineDelta {
		return sessionControlSessionCandidate{}, errors.New("invalid NHP session issuance")
	}
	candidate := sessionControlSessionCandidate{
		CellID:                    cellID,
		AgentPublicKey:            knkMsg.NHPAgentPublicKey,
		SessionID:                 knkMsg.NHPSessionId,
		IssuedAtMillis:            issuedMillis,
		ReservationDeadlineMillis: issuedMillis + deadlineDelta,
		RunID:                     knkMsg.RunID,
		RunAttempt:                knkMsg.RunAttempt,
	}
	if !validSessionControlSessionCandidate(candidate) {
		return sessionControlSessionCandidate{}, errors.New("invalid NHP session authority")
	}
	return candidate, nil
}

func (s *UdpServer) nativeSessionOperationEnabled() bool {
	return s != nil && s.storageConfig != nil && s.storageConfig.Backend == StorageBackendDynamoDB &&
		s.storageConfig.DynamoDB.NativeSessionOperations
}

func (s *UdpServer) nativeSessionOperationServerBinding() (common.NativeSessionOperationServerBinding, error) {
	if !s.nativeSessionOperationEnabled() {
		return common.NativeSessionOperationServerBinding{}, errors.New("native session operations are disabled")
	}
	binding := common.NativeSessionOperationServerBinding{
		AWSAccountID: s.storageConfig.DynamoDB.AccountID, AWSRegion: s.storageConfig.DynamoDB.Region,
		CellID: s.sessionControlCellID, SessionControlTable: s.storageConfig.DynamoDB.SessionControlTable,
		AgentKeysTable:   s.storageConfig.DynamoDB.AgentKeysTable,
		AgentKeySchema:   common.NativeSessionOperationAgentKeySchema,
		CredentialKind:   common.NativeSessionOperationCredentialKind,
		ConnectorIDClaim: common.NativeSessionOperationConnectorIDClaim,
	}
	if err := validateNativeSessionOperationServerBindingConfig(binding); err != nil {
		return common.NativeSessionOperationServerBinding{}, err
	}
	return binding, nil
}

func (s *UdpServer) nativeSessionOperationStore() (sessionControlNativeOperationRequestStore, error) {
	if !s.nativeSessionOperationEnabled() || s.sessionControlStore == nil {
		return nil, errors.New("native session operation store is unavailable")
	}
	store, ok := s.sessionControlStore.(sessionControlNativeOperationRequestStore)
	if !ok {
		return nil, errors.New("native session operation store capability is incomplete")
	}
	return store, nil
}

func (s *UdpServer) reserveNativeDurableSession(ctx context.Context, candidate sessionControlSessionCandidate,
	op sessionControlNativeOperation, now time.Time,
) error {
	store, err := s.nativeSessionOperationStore()
	if err != nil {
		return err
	}
	if s.nativeSessionOperationFences == nil {
		return errors.New("native session operation fence cache is unavailable")
	}
	snapshot, err := s.nativeSessionOperationFences.allowSnapshot()
	if err != nil {
		s.nativeSessionOperationFences.refreshAsync(s)
		return err
	}
	reserved, err := store.ReserveNativeSessionOperation(ctx, candidate, op, snapshot, now)
	if err != nil {
		if errors.Is(err, errSessionControlNativeOperationConflict) || errors.Is(err, errSessionControlSessionFenceStale) {
			s.nativeSessionOperationFences.refreshAsync(s)
		}
		return err
	}
	if reserved == nil || reserved.Candidate != candidate || reserved.State != sessionControlSessionStateReserved ||
		reserved.Version != 1 || reserved.TargetCount != 0 {
		return errSessionControlNativeOperationCorrupt
	}
	return nil
}

func sessionControlRetainUntilMillis(candidate sessionControlSessionCandidate, openTime uint32, deliveryDeadline time.Time) (int64, error) {
	baseMillis := time.Now().UnixMilli()
	if deliveryDeadline.UnixMilli() > baseMillis {
		baseMillis = deliveryDeadline.UnixMilli()
	}
	// The forwarding receiver's wall clock can legitimately trail the origin's
	// issued-at timestamp within the accepted skew.  Retention must still cover
	// the full compensated serving lifetime measured from that authority.
	if candidate.IssuedAtMillis > baseMillis {
		baseMillis = candidate.IssuedAtMillis
	}
	openMillis := int64(openTime) * time.Second.Milliseconds()
	if baseMillis > math.MaxInt64-openMillis {
		return 0, errors.New("session-control retention overflow")
	}
	retainUntil := baseMillis + openMillis
	if retainUntil < candidate.ReservationDeadlineMillis {
		retainUntil = candidate.ReservationDeadlineMillis
	}
	return retainUntil, nil
}

func (s *UdpServer) reserveDurableSession(ctx context.Context, candidate sessionControlSessionCandidate) error {
	store, err := s.requestSessionControlStore()
	if err != nil {
		return err
	}
	for range sessionControlRuntimeSnapshotAttempts {
		releaseCell, acquireErr := s.acquireSessionControlCellRead(ctx)
		if acquireErr != nil {
			return acquireErr
		}
		snapshot, snapshotErr := s.sessionControlStore.SnapshotActiveFences(ctx, candidate.CellID)
		if snapshotErr != nil {
			releaseCell()
			return snapshotErr
		}
		if snapshot == nil {
			releaseCell()
			return errSessionControlFenceCorrupt
		}
		reserved, reserveErr := store.ReserveSession(ctx, candidate, *snapshot)
		releaseCell()
		if reserveErr == nil {
			if reserved == nil || reserved.Candidate != candidate || reserved.State != sessionControlSessionStateReserved ||
				reserved.Version != 1 || reserved.TargetCount != 0 {
				return errSessionControlSessionCorrupt
			}
			return nil
		}
		if !errors.Is(reserveErr, errSessionControlSessionFenceStale) {
			return reserveErr
		}
	}
	return errSessionControlSessionFenceStale
}

// VerifyForwardedDurableNHPSession proves that an authenticated forwarding
// origin reserved this exact fleet-wide session before the receiver performs
// any local reservation or AOP work.
func (s *UdpServer) VerifyForwardedDurableNHPSession(ctx context.Context,
	knkMsg *common.AgentKnockMsg,
) (common.AgentSessionReceipt, error) {
	if !s.sessionControlAuthorityRequired() {
		return common.AgentSessionReceipt{}, nil
	}
	candidate, err := sessionControlCandidateForKnock(s.sessionControlCellID, knkMsg)
	if err != nil {
		return common.AgentSessionReceipt{}, err
	}
	if common.NativeSessionOperationPresent(*knkMsg) {
		binding, bindingErr := s.nativeSessionOperationServerBinding()
		if bindingErr != nil {
			return common.AgentSessionReceipt{}, bindingErr
		}
		op, operationErr := sessionControlNativeOperationForKnock(knkMsg, knkMsg.NHPAgentPublicKey, binding)
		if operationErr != nil {
			return common.AgentSessionReceipt{}, operationErr
		}
		candidate.NativeOperation = op.Binding
		store, storeErr := s.nativeSessionOperationStore()
		if storeErr != nil {
			return common.AgentSessionReceipt{}, storeErr
		}
		verified, _, verifyErr := store.VerifyMappedNativeSessionOperation(ctx, candidate, op)
		if verifyErr != nil {
			return common.AgentSessionReceipt{}, verifyErr
		}
		if verified == nil || verified.Candidate != candidate || verified.State != sessionControlSessionStateReserved {
			return common.AgentSessionReceipt{}, errSessionControlNativeOperationCorrupt
		}
		knkMsg.NHPAgentOwnerID = op.OwnerID
		return common.AgentSessionReceipt{
			CellID: candidate.CellID, SessionID: candidate.SessionID,
			SessionIssuedAtMillis: candidate.IssuedAtMillis,
			RunID:                 candidate.RunID, RunAttempt: candidate.RunAttempt,
		}, nil
	}
	store, err := s.requestSessionControlStore()
	if err != nil {
		return common.AgentSessionReceipt{}, err
	}
	releaseCell, err := s.acquireSessionControlCellRead(ctx)
	if err != nil {
		return common.AgentSessionReceipt{}, err
	}
	defer releaseCell()
	snapshot, err := s.sessionControlStore.SnapshotActiveFences(ctx, candidate.CellID)
	if err != nil {
		return common.AgentSessionReceipt{}, err
	}
	if snapshot == nil {
		return common.AgentSessionReceipt{}, errSessionControlFenceCorrupt
	}
	verified, err := store.VerifySession(ctx, candidate, *snapshot)
	if err != nil {
		return common.AgentSessionReceipt{}, err
	}
	if verified == nil || verified.Candidate != candidate || verified.State != sessionControlSessionStateReserved {
		return common.AgentSessionReceipt{}, errSessionControlSessionCorrupt
	}
	receipt := common.AgentSessionReceipt{
		CellID: candidate.CellID, SessionID: candidate.SessionID,
		SessionIssuedAtMillis: candidate.IssuedAtMillis,
		RunID:                 candidate.RunID, RunAttempt: candidate.RunAttempt,
	}
	if knkMsg.AuthServiceId == common.RegisteredAgentAuthServiceID {
		if err := common.ValidateAgentSessionReceipt(receipt); err != nil {
			return common.AgentSessionReceipt{}, errSessionControlSessionCorrupt
		}
	}
	return receipt, nil
}

func (s *UdpServer) prepareDurableSessionIntent(ctx context.Context, candidate sessionControlSessionCandidate,
	target sessionControlTargetAuthority, sessionExpiresAtMillis, retainUntilMillis int64) (*sessionControlSessionIntentPreparation, error) {
	store, err := s.requestSessionControlStore()
	if err != nil {
		return nil, err
	}
	snapshot, err := s.sessionControlStore.SnapshotActiveFences(ctx, candidate.CellID)
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		return nil, errSessionControlFenceCorrupt
	}
	prepared, err := store.PrepareSessionIntentCurrent(ctx, candidate, target,
		sessionExpiresAtMillis, retainUntilMillis, *snapshot)
	if err != nil {
		return nil, err
	}
	if prepared == nil || prepared.Session.Candidate != candidate || prepared.Intent.Session != candidate ||
		prepared.Intent.Target != target || prepared.Session.State != sessionControlSessionStateReserved {
		return nil, errSessionControlSessionCorrupt
	}
	verified, err := store.VerifySession(ctx, candidate, *snapshot)
	if err != nil {
		return nil, err
	}
	if verified == nil || verified.Candidate != candidate || verified.State != sessionControlSessionStateReserved ||
		verified.Version < prepared.Session.Version || verified.TargetCount < prepared.Session.TargetCount ||
		verified.SessionExpiresAtMillis != sessionExpiresAtMillis || verified.RetainUntilMillis < retainUntilMillis {
		return nil, errSessionControlSessionCorrupt
	}
	return prepared, nil
}

func (s *UdpServer) markDurableSessionAckEnqueued(ctx context.Context, candidate sessionControlSessionCandidate) error {
	store, err := s.requestSessionControlStore()
	if err != nil {
		return err
	}
	// Up to MaxACConnsPerID sibling intents may win their session CAS before the
	// final ACK transition.  Treat those conflicts like the intent writer does
	// and leave one final attempt after all possible sibling winners.
	for range sessionControlSessionFanoutAttempts {
		releaseCell, acquireErr := s.acquireSessionControlCellRead(ctx)
		if acquireErr != nil {
			return acquireErr
		}
		snapshot, snapshotErr := s.sessionControlStore.SnapshotActiveFences(ctx, candidate.CellID)
		if snapshotErr != nil {
			releaseCell()
			return snapshotErr
		}
		if snapshot == nil {
			releaseCell()
			return errSessionControlFenceCorrupt
		}
		marked, markErr := store.MarkSessionAckEnqueued(ctx, candidate, *snapshot)
		releaseCell()
		if markErr == nil {
			if marked == nil || marked.Candidate != candidate || marked.State != sessionControlSessionStateAckEnqueued {
				return errSessionControlSessionCorrupt
			}
			return nil
		}
		if !errors.Is(markErr, errSessionControlSessionFenceStale) &&
			!errors.Is(markErr, errSessionControlSessionConflict) {
			return markErr
		}
	}
	return errSessionControlSessionConflict
}

func (s *UdpServer) ensureDurableExactSessionClose(ctx context.Context, candidate sessionControlSessionCandidate,
	retainUntilMillis int64) error {
	store, err := s.requestSessionControlStore()
	if err != nil {
		return err
	}
	releaseCell, err := s.acquireSessionControlCellWrite(ctx)
	if err != nil {
		return err
	}
	closed, closeErr := store.EnsureExactSessionClose(ctx, candidate, retainUntilMillis)
	releaseCell()
	if closeErr != nil {
		return closeErr
	}
	if closed == nil || closed.Session.Candidate != candidate || closed.Session.State != sessionControlSessionStateClosing {
		return fmt.Errorf("%w: exact close result", errSessionControlCloseCorrupt)
	}
	return nil
}
