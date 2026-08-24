package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	sessionControlCloseWorkKind           = "close_work"
	sessionControlOverflowCloseKind       = "overflow_close"
	sessionControlCloseWorkSK             = "WORK"
	sessionControlOverflowCloseSKPrefix   = "EVENT#"
	sessionControlCloseWorkStatePending   = "pending"
	sessionControlCloseWorkStateCompleted = "completed"
	sessionControlCloseWorkModeNormal     = "active_fence"
	sessionControlCloseWorkModeOverflow   = "overflow"
	sessionControlCloseWorkSchema         = uint64(1)
	sessionControlCloseDueShardCount      = uint64(16)
	sessionControlOverflowCloseQueryLimit = int32(100)
	sessionControlExactCloseAttempts      = MaxACConnsPerID + 2
)

var (
	errSessionControlCloseConflict = errors.New("session-control close changed concurrently")
	errSessionControlCloseCorrupt  = errors.New("session-control close authority is malformed")
)

// sessionControlCloseWork is immutable discovery authority. The due GSI is
// liveness-only; recovery must strongly read these base keys before acting.
// Selector retains the full generic union so agent/run overflow producers can
// reuse this row shape without inventing a second close directory.
type sessionControlCloseWork struct {
	CellID                   string
	EventID                  string
	Selector                 sessionControlFenceSelector
	SelectorDigest           string
	Mode                     string
	State                    string
	PreparedDirectoryVersion uint64
	SessionVersion           uint64
	ExpectedTargetCount      uint64
	CreatedAtMillis          int64
	UpdatedAtMillis          int64
	DueAtMillis              int64
	CompletedAtMillis        int64
}

type sessionControlCloseWorkRow struct {
	PK                       string `dynamodbav:"pk"`
	SK                       string `dynamodbav:"sk"`
	Kind                     string `dynamodbav:"kind"`
	SchemaVersion            uint64 `dynamodbav:"schema_version"`
	CellID                   string `dynamodbav:"cell_id"`
	EventID                  string `dynamodbav:"event_id"`
	SelectorScope            string `dynamodbav:"selector_scope"`
	AgentPublicKey           string `dynamodbav:"agent_public_key"`
	SessionID                uint64 `dynamodbav:"session_id,omitempty"`
	SessionIssuedMillis      int64  `dynamodbav:"session_issued_ms,omitempty"`
	IssuedThroughMillis      int64  `dynamodbav:"issued_through_ms,omitempty"`
	RunID                    string `dynamodbav:"run_id,omitempty"`
	RunAttempt               uint64 `dynamodbav:"run_attempt,omitempty"`
	SelectorDigest           string `dynamodbav:"selector_digest"`
	Mode                     string `dynamodbav:"mode"`
	State                    string `dynamodbav:"state"`
	PreparedDirectoryVersion uint64 `dynamodbav:"prepared_directory_version"`
	SessionVersion           uint64 `dynamodbav:"session_version"`
	ExpectedTargetCount      uint64 `dynamodbav:"expected_target_count"`
	CreatedAtMillis          int64  `dynamodbav:"created_at_ms"`
	UpdatedAtMillis          int64  `dynamodbav:"updated_at_ms"`
	DueAtMillis              int64  `dynamodbav:"due_at_ms,omitempty"`
	DueShard                 string `dynamodbav:"due_shard,omitempty"`
	DueSort                  string `dynamodbav:"due_sort,omitempty"`
	CompletedAtMillis        int64  `dynamodbav:"completed_at_ms,omitempty"`
}

type sessionControlExactClosePreparation struct {
	EventID  string
	Session  sessionControlSessionAuthority
	Fence    *sessionControlFenceAuthority
	Work     sessionControlCloseWork
	Overflow bool
	// Complete is non-nil only for an exact historical close that has already
	// crossed the delivery/ACK boundary. Callers must not rematerialize Work in
	// this state; the zero Work value is intentional.
	Complete *sessionControlCloseComplete
}

type sessionControlOverflowCloseSnapshot struct {
	Directory sessionControlFenceDirectory
	Work      []sessionControlCloseWork
}

func sessionControlExactCloseEventID(candidate sessionControlSessionCandidate) string {
	canonical := fmt.Sprintf("v1\x00exact\x00%s\x00%s\x00%d\x00%d\x00%d\x00%s\x00%d",
		candidate.CellID, candidate.AgentPublicKey, candidate.SessionID, candidate.IssuedAtMillis,
		candidate.ReservationDeadlineMillis, candidate.RunID, candidate.RunAttempt)
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:16])
}

func sessionControlOverflowClosePK(cellID string) string {
	return "OVERFLOW#" + sessionControlFenceHash(cellID)
}

func sessionControlOverflowCloseSK(eventID string) string {
	return sessionControlOverflowCloseSKPrefix + eventID
}

func sessionControlCloseDueShard(work sessionControlCloseWork) string {
	digest := sha256.Sum256([]byte(work.EventID))
	return fmt.Sprintf("CLOSE#%s#%02d", work.CellID, uint64(digest[0])%sessionControlCloseDueShardCount)
}

func sessionControlCloseDueSort(work sessionControlCloseWork) string {
	return sessionControlSessionIssuedText(work.DueAtMillis) + "#" + work.EventID
}

func sessionControlCloseWorkKey(eventID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlFenceMetaPK(eventID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlCloseWorkSK},
	}
}

func sessionControlOverflowCloseKey(cellID, eventID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlOverflowClosePK(cellID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlOverflowCloseSK(eventID)},
	}
}

func validateSessionControlCloseWork(work sessionControlCloseWork) error {
	if !validSessionControlCellID(work.CellID) || !validSessionControlFenceEventID(work.EventID) ||
		validateSessionControlFenceSelector(work.Selector) != nil ||
		work.SelectorDigest == "" ||
		(work.State != sessionControlCloseWorkStatePending && work.State != sessionControlCloseWorkStateCompleted) ||
		(work.Mode != sessionControlCloseWorkModeNormal && work.Mode != sessionControlCloseWorkModeOverflow) ||
		work.PreparedDirectoryVersion == 0 || work.PreparedDirectoryVersion >= ^uint64(0)-1 ||
		work.SessionVersion == 0 || work.SessionVersion >= ^uint64(0)-1 ||
		work.ExpectedTargetCount > sessionControlSessionMaxTargets || work.ExpectedTargetCount >= work.SessionVersion ||
		(work.SessionVersion == 1 && work.ExpectedTargetCount != 0) ||
		(work.SessionVersion > 1 && work.ExpectedTargetCount == 0) ||
		work.CreatedAtMillis <= 0 || work.UpdatedAtMillis < work.CreatedAtMillis {
		return errSessionControlCloseCorrupt
	}
	switch work.State {
	case sessionControlCloseWorkStatePending:
		if work.UpdatedAtMillis != work.CreatedAtMillis || work.DueAtMillis != work.CreatedAtMillis ||
			work.CompletedAtMillis != 0 {
			return errSessionControlCloseCorrupt
		}
	case sessionControlCloseWorkStateCompleted:
		if work.Mode != sessionControlCloseWorkModeNormal || work.DueAtMillis != 0 ||
			work.CompletedAtMillis != work.UpdatedAtMillis || work.CompletedAtMillis < work.CreatedAtMillis {
			return errSessionControlCloseCorrupt
		}
	}
	digest, err := sessionControlFenceSelectorDigest(work.Selector)
	if err != nil || digest != work.SelectorDigest {
		return errSessionControlCloseCorrupt
	}
	return nil
}

func sessionControlCloseWorkToRow(work sessionControlCloseWork) (sessionControlCloseWorkRow, error) {
	if err := validateSessionControlCloseWork(work); err != nil {
		return sessionControlCloseWorkRow{}, err
	}
	row := sessionControlCloseWorkRow{
		Kind: sessionControlCloseWorkKind, SchemaVersion: sessionControlCloseWorkSchema,
		CellID: work.CellID, EventID: work.EventID, SelectorScope: work.Selector.Scope,
		AgentPublicKey: work.Selector.AgentPublicKey, SessionID: work.Selector.SessionID,
		SessionIssuedMillis: work.Selector.SessionIssuedMillis,
		IssuedThroughMillis: work.Selector.IssuedThroughMillis, RunID: work.Selector.RunID,
		RunAttempt: work.Selector.RunAttempt, SelectorDigest: work.SelectorDigest,
		Mode: work.Mode, State: work.State, PreparedDirectoryVersion: work.PreparedDirectoryVersion,
		SessionVersion: work.SessionVersion, ExpectedTargetCount: work.ExpectedTargetCount,
		CreatedAtMillis: work.CreatedAtMillis, UpdatedAtMillis: work.UpdatedAtMillis,
		DueAtMillis: work.DueAtMillis, CompletedAtMillis: work.CompletedAtMillis,
	}
	if work.State == sessionControlCloseWorkStatePending {
		row.DueShard = sessionControlCloseDueShard(work)
		row.DueSort = sessionControlCloseDueSort(work)
	}
	if work.Mode == sessionControlCloseWorkModeNormal {
		row.PK = sessionControlFenceMetaPK(work.EventID)
		row.SK = sessionControlCloseWorkSK
	} else {
		row.PK = sessionControlOverflowClosePK(work.CellID)
		row.SK = sessionControlOverflowCloseSK(work.EventID)
		row.Kind = sessionControlOverflowCloseKind
	}
	return row, nil
}

func sessionControlCloseWorkFromRow(row sessionControlCloseWorkRow, overflow bool, expectedCellID, expectedEventID string) (sessionControlCloseWork, error) {
	work := sessionControlCloseWork{
		CellID: row.CellID, EventID: row.EventID,
		Selector: sessionControlFenceSelector{
			Scope: row.SelectorScope, AgentPublicKey: row.AgentPublicKey,
			SessionID: row.SessionID, SessionIssuedMillis: row.SessionIssuedMillis,
			IssuedThroughMillis: row.IssuedThroughMillis, RunID: row.RunID, RunAttempt: row.RunAttempt,
		},
		SelectorDigest: row.SelectorDigest, Mode: row.Mode, State: row.State,
		PreparedDirectoryVersion: row.PreparedDirectoryVersion,
		SessionVersion:           row.SessionVersion, ExpectedTargetCount: row.ExpectedTargetCount,
		CreatedAtMillis: row.CreatedAtMillis, UpdatedAtMillis: row.UpdatedAtMillis,
		DueAtMillis: row.DueAtMillis, CompletedAtMillis: row.CompletedAtMillis,
	}
	expectedKind := sessionControlCloseWorkKind
	expectedPK := sessionControlFenceMetaPK(row.EventID)
	expectedSK := sessionControlCloseWorkSK
	expectedMode := sessionControlCloseWorkModeNormal
	if overflow {
		expectedKind = sessionControlOverflowCloseKind
		expectedPK = sessionControlOverflowClosePK(row.CellID)
		expectedSK = sessionControlOverflowCloseSK(row.EventID)
		expectedMode = sessionControlCloseWorkModeOverflow
	}
	if row.Kind != expectedKind || row.SchemaVersion != sessionControlCloseWorkSchema ||
		row.PK != expectedPK || row.SK != expectedSK || row.CellID != expectedCellID ||
		row.EventID != expectedEventID || row.Mode != expectedMode ||
		validateSessionControlCloseWork(work) != nil {
		return sessionControlCloseWork{}, errSessionControlCloseCorrupt
	}
	if (work.State == sessionControlCloseWorkStatePending &&
		(row.DueShard != sessionControlCloseDueShard(work) || row.DueSort != sessionControlCloseDueSort(work))) ||
		(work.State == sessionControlCloseWorkStateCompleted && (row.DueShard != "" || row.DueSort != "")) {
		return sessionControlCloseWork{}, errSessionControlCloseCorrupt
	}
	return work, nil
}

func sessionControlCloseWorkFromItem(item map[string]types.AttributeValue, overflow bool, expectedCellID, expectedEventID string) (sessionControlCloseWork, error) {
	if _, ok := item["expected_target_count"].(*types.AttributeValueMemberN); !ok {
		return sessionControlCloseWork{}, fmt.Errorf("%w: missing or invalid expected_target_count", errSessionControlCloseCorrupt)
	}
	if _, hasTTL := item["ttl"]; hasTTL {
		return sessionControlCloseWork{}, errSessionControlCloseCorrupt
	}
	state, stateOK := item["state"].(*types.AttributeValueMemberS)
	if !stateOK {
		return sessionControlCloseWork{}, errSessionControlCloseCorrupt
	}
	if state.Value == sessionControlCloseWorkStatePending {
		for _, name := range []string{"due_at_ms", "due_shard", "due_sort"} {
			if _, ok := item[name]; !ok {
				return sessionControlCloseWork{}, errSessionControlCloseCorrupt
			}
		}
		if _, ok := item["completed_at_ms"]; ok {
			return sessionControlCloseWork{}, errSessionControlCloseCorrupt
		}
	} else if state.Value == sessionControlCloseWorkStateCompleted {
		if _, ok := item["completed_at_ms"].(*types.AttributeValueMemberN); !ok {
			return sessionControlCloseWork{}, errSessionControlCloseCorrupt
		}
		for _, name := range []string{"due_at_ms", "due_shard", "due_sort"} {
			if _, ok := item[name]; ok {
				return sessionControlCloseWork{}, errSessionControlCloseCorrupt
			}
		}
	} else {
		return sessionControlCloseWork{}, errSessionControlCloseCorrupt
	}
	var row sessionControlCloseWorkRow
	if err := attributevalue.UnmarshalMap(item, &row); err != nil {
		return sessionControlCloseWork{}, fmt.Errorf("%w: decode close work", errSessionControlCloseCorrupt)
	}
	return sessionControlCloseWorkFromRow(row, overflow, expectedCellID, expectedEventID)
}

func (s *dynamoSessionControlStore) getCloseWork(ctx context.Context, cellID, eventID string, overflow bool) (*sessionControlCloseWork, error) {
	key := sessionControlCloseWorkKey(eventID)
	if overflow {
		key = sessionControlOverflowCloseKey(cellID, eventID)
	}
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true), Key: key,
	})
	if err != nil {
		return nil, fmt.Errorf("session-control close work strong read: %w", err)
	}
	if len(result.Item) == 0 {
		return nil, errSessionControlSessionNotFound
	}
	work, err := sessionControlCloseWorkFromItem(result.Item, overflow, cellID, eventID)
	if err != nil {
		return nil, err
	}
	return &work, nil
}

type sessionControlExactCloseStableState struct {
	Directory sessionControlFenceDirectory
	Session   *sessionControlSessionAuthority
	Meta      *sessionControlFenceAuthority
	Active    *sessionControlFenceAuthority
	Work      *sessionControlCloseWork
	Overflow  *sessionControlCloseWork
}

func (s *dynamoSessionControlStore) readStableExactCloseState(ctx context.Context, candidate sessionControlSessionCandidate, eventID string) (*sessionControlExactCloseStableState, error) {
	readCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	for range sessionControlSessionReadAttempts {
		before, err := s.getFenceDirectory(readCtx, candidate.CellID)
		if err != nil {
			return nil, err
		}
		session, sessionErr := s.classifyReservation(readCtx, candidate)
		if sessionErr != nil && !errors.Is(sessionErr, errSessionControlSessionNotFound) {
			return nil, sessionErr
		}
		meta, metaErr := s.getFence(readCtx, candidate.CellID, eventID, false)
		if metaErr != nil && !errors.Is(metaErr, errSessionControlFenceNotFound) {
			return nil, metaErr
		}
		active, activeErr := s.getFence(readCtx, candidate.CellID, eventID, true)
		if activeErr != nil && !errors.Is(activeErr, errSessionControlFenceNotFound) {
			return nil, activeErr
		}
		work, workErr := s.getCloseWork(readCtx, candidate.CellID, eventID, false)
		if workErr != nil && !errors.Is(workErr, errSessionControlSessionNotFound) {
			return nil, workErr
		}
		overflow, overflowErr := s.getCloseWork(readCtx, candidate.CellID, eventID, true)
		if overflowErr != nil && !errors.Is(overflowErr, errSessionControlSessionNotFound) {
			return nil, overflowErr
		}
		after, err := s.getFenceDirectory(readCtx, candidate.CellID)
		if err != nil {
			return nil, err
		}
		if *before != *after {
			continue
		}
		if sessionErr != nil {
			if meta != nil || active != nil || work != nil || overflow != nil {
				return nil, errSessionControlCloseCorrupt
			}
			return &sessionControlExactCloseStableState{Directory: *after}, nil
		}
		return &sessionControlExactCloseStableState{
			Directory: *after, Session: session, Meta: meta, Active: active, Work: work, Overflow: overflow,
		}, nil
	}
	return nil, errSessionControlCloseConflict
}

func sessionControlExactCloseSelector(candidate sessionControlSessionCandidate) sessionControlFenceSelector {
	return sessionControlFenceSelector{
		Scope: sessionControlFenceSelectorExact, AgentPublicKey: candidate.AgentPublicKey,
		SessionID: candidate.SessionID, SessionIssuedMillis: candidate.IssuedAtMillis,
	}
}

func classifySessionControlExactClose(candidate sessionControlSessionCandidate, eventID string, stable *sessionControlExactCloseStableState) (*sessionControlExactClosePreparation, error) {
	if stable == nil || stable.Session == nil {
		return nil, errSessionControlSessionNotFound
	}
	session := stable.Session
	if session.State != sessionControlSessionStateClosing {
		if stable.Meta != nil || stable.Active != nil || stable.Work != nil || stable.Overflow != nil {
			return nil, errSessionControlCloseCorrupt
		}
		return nil, errSessionControlSessionNotFound
	}
	if session.CloseEventID != eventID || session.ClosePreparedDirectory == 0 ||
		session.ClosePreparedDirectory > stable.Directory.Version || session.ClosePreparedAtMillis <= 0 {
		return nil, errSessionControlCloseConflict
	}
	selector := sessionControlExactCloseSelector(candidate)
	digest, _ := sessionControlFenceSelectorDigest(selector)
	if stable.Overflow != nil {
		if stable.Meta != nil || stable.Active != nil || stable.Work != nil ||
			!stable.Directory.AdmissionBlocked || stable.Directory.OverflowCloseCount == 0 ||
			stable.Overflow.EventID != eventID || stable.Overflow.Selector != selector ||
			stable.Overflow.SelectorDigest != digest ||
			stable.Overflow.PreparedDirectoryVersion != session.ClosePreparedDirectory ||
			stable.Overflow.SessionVersion != session.Version ||
			stable.Overflow.ExpectedTargetCount != session.TargetCount ||
			stable.Overflow.CreatedAtMillis != session.ClosePreparedAtMillis {
			return nil, errSessionControlCloseCorrupt
		}
		return &sessionControlExactClosePreparation{
			EventID: eventID, Session: *session, Work: *stable.Overflow, Overflow: true,
		}, nil
	}
	if stable.Meta == nil || stable.Active == nil || stable.Work == nil ||
		stable.Directory.ActiveFenceCount == 0 ||
		*stable.Meta != *stable.Active ||
		(stable.Meta.State != sessionControlFencePreparing && stable.Meta.State != sessionControlFenceConverged) ||
		stable.Meta.EventID != eventID || stable.Meta.Selector != selector || stable.Meta.SelectorDigest != digest ||
		stable.Meta.PreparedDirectoryVersion != session.ClosePreparedDirectory ||
		stable.Work.EventID != eventID || stable.Work.Selector != selector || stable.Work.SelectorDigest != digest ||
		stable.Work.PreparedDirectoryVersion != session.ClosePreparedDirectory ||
		stable.Work.SessionVersion != session.Version || stable.Work.ExpectedTargetCount != session.TargetCount ||
		stable.Work.CreatedAtMillis != stable.Meta.CreatedAtMillis ||
		stable.Work.CreatedAtMillis != stable.Meta.PreparedAtMillis ||
		stable.Work.CreatedAtMillis != session.ClosePreparedAtMillis {
		return nil, errSessionControlCloseCorrupt
	}
	fence := *stable.Meta
	return &sessionControlExactClosePreparation{
		EventID: eventID, Session: *session, Fence: &fence, Work: *stable.Work,
	}, nil
}

func (s *dynamoSessionControlStore) classifyPromotedOverflowExactClose(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string,
	stable *sessionControlExactCloseStableState) (*sessionControlExactClosePreparation, error) {
	if stable == nil || stable.Session == nil || stable.Session.State != sessionControlSessionStateClosing ||
		stable.Meta == nil || stable.Active == nil || stable.Work != nil || stable.Overflow != nil ||
		*stable.Meta != *stable.Active || stable.Meta.State != sessionControlFenceConverged ||
		stable.Directory.ActiveFenceCount == 0 {
		return nil, errSessionControlCloseCorrupt
	}
	complete, err := s.getCloseComplete(ctx, eventID)
	if err != nil {
		return nil, err
	}
	session := *stable.Session
	fence := *stable.Meta
	if complete.WorkMode != sessionControlCloseWorkModeOverflow ||
		!sessionControlCloseCompleteMatchesCandidate(*complete, candidate, eventID) ||
		complete.SessionVersion != session.Version || complete.ExpectedTargetCount != session.TargetCount ||
		complete.PreparedDirectoryVersion != session.ClosePreparedDirectory ||
		complete.SelectorDigest != fence.SelectorDigest || fence.CellID != candidate.CellID ||
		fence.EventID != eventID || fence.PreparedDirectoryVersion != session.ClosePreparedDirectory ||
		fence.Version != complete.FenceVersion || fence.CreatedAtMillis != session.ClosePreparedAtMillis ||
		fence.PreparedAtMillis != session.ClosePreparedAtMillis ||
		fence.ConvergedAtMillis != complete.CompletedAtMillis ||
		fence.ReplayNotBeforeMillis != complete.FenceReplayNotBeforeMillis ||
		complete.CompletedDirectoryVersion > stable.Directory.Version ||
		complete.RetainUntilMillis < session.RetainUntilMillis {
		return nil, errSessionControlCloseCorrupt
	}
	// A retention-extension transaction writes COMPLETE and SESSION atomically.
	// If this read bracket straddled that commit, observing the stronger COMPLETE
	// proves the matching SESSION update committed too.
	session.RetainUntilMillis = complete.RetainUntilMillis
	return &sessionControlExactClosePreparation{EventID: eventID, Session: session, Fence: &fence,
		Overflow: true, Complete: complete}, nil
}

func (s *dynamoSessionControlStore) classifyExistingExactClose(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string,
	stable *sessionControlExactCloseStableState) (*sessionControlExactClosePreparation, error) {
	classified, err := classifySessionControlExactClose(candidate, eventID, stable)
	if err != nil && stable != nil && stable.Meta != nil && stable.Active != nil &&
		stable.Work == nil && stable.Overflow == nil {
		return s.classifyPromotedOverflowExactClose(ctx, candidate, eventID, stable)
	}
	return classified, err
}

func planSessionControlExactClose(current sessionControlSessionAuthority, eventID string, preparedDirectoryVersion uint64,
	preparedAtMillis, retainUntilMillis int64) (sessionControlSessionAuthority, error) {
	if (current.State != sessionControlSessionStateReserved && current.State != sessionControlSessionStateAckEnqueued) ||
		!validSessionControlFenceEventID(eventID) || preparedDirectoryVersion <= current.ReservedDirectoryVersion ||
		preparedDirectoryVersion >= ^uint64(0)-1 || preparedAtMillis < current.Candidate.IssuedAtMillis ||
		preparedAtMillis > retainUntilMillis || retainUntilMillis < current.Candidate.ReservationDeadlineMillis {
		return sessionControlSessionAuthority{}, errSessionControlCloseConflict
	}
	planned := current
	planned.State = sessionControlSessionStateClosing
	planned.CloseEventID = eventID
	planned.ClosePreparedDirectory = preparedDirectoryVersion
	planned.ClosePreparedAtMillis = preparedAtMillis
	if retainUntilMillis > planned.RetainUntilMillis {
		planned.RetainUntilMillis = retainUntilMillis
	}
	if err := validateSessionControlSessionAuthority(planned); err != nil {
		return sessionControlSessionAuthority{}, err
	}
	return planned, nil
}

func sessionControlSessionCloseUpdate(current, planned sessionControlSessionAuthority) types.TransactWriteItem {
	candidate := current.Candidate
	condition := "kind = :kind AND schema_version = :schema AND cell_id = :cell_id AND agent_public_key = :agent_public_key AND session_id = :session_id AND issued_at_ms = :issued_at AND reservation_deadline_ms = :reservation_deadline AND run_id = :run_id AND run_attempt = :run_attempt AND #state = :state AND #version = :version AND target_count = :count AND retain_until_ms = :retain AND reserved_directory_version = :reserved_version AND reserved_active_fence_count = :reserved_count AND attribute_not_exists(close_event_id) AND attribute_not_exists(close_prepared_directory_version) AND attribute_not_exists(close_prepared_at_ms) AND attribute_not_exists(#ttl)"
	values := map[string]types.AttributeValue{
		":kind":                   &types.AttributeValueMemberS{Value: sessionControlSessionMetaKind},
		":schema":                 &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlSessionSchemaForCandidate(candidate))},
		":cell_id":                &types.AttributeValueMemberS{Value: candidate.CellID},
		":agent_public_key":       &types.AttributeValueMemberS{Value: candidate.AgentPublicKey},
		":session_id":             &types.AttributeValueMemberN{Value: fmt.Sprint(candidate.SessionID)},
		":issued_at":              &types.AttributeValueMemberN{Value: fmt.Sprint(candidate.IssuedAtMillis)},
		":reservation_deadline":   &types.AttributeValueMemberN{Value: fmt.Sprint(candidate.ReservationDeadlineMillis)},
		":run_id":                 &types.AttributeValueMemberS{Value: candidate.RunID},
		":run_attempt":            &types.AttributeValueMemberN{Value: fmt.Sprint(candidate.RunAttempt)},
		":state":                  &types.AttributeValueMemberS{Value: current.State},
		":next_state":             &types.AttributeValueMemberS{Value: sessionControlSessionStateClosing},
		":version":                &types.AttributeValueMemberN{Value: fmt.Sprint(current.Version)},
		":count":                  &types.AttributeValueMemberN{Value: fmt.Sprint(current.TargetCount)},
		":retain":                 &types.AttributeValueMemberN{Value: fmt.Sprint(current.RetainUntilMillis)},
		":next_retain":            &types.AttributeValueMemberN{Value: fmt.Sprint(planned.RetainUntilMillis)},
		":reserved_version":       &types.AttributeValueMemberN{Value: fmt.Sprint(current.ReservedDirectoryVersion)},
		":reserved_count":         &types.AttributeValueMemberN{Value: fmt.Sprint(current.ReservedActiveFenceCount)},
		":close_event_id":         &types.AttributeValueMemberS{Value: planned.CloseEventID},
		":close_prepared_version": &types.AttributeValueMemberN{Value: fmt.Sprint(planned.ClosePreparedDirectory)},
		":close_prepared_at":      &types.AttributeValueMemberN{Value: fmt.Sprint(planned.ClosePreparedAtMillis)},
		":next_due_shard":         &types.AttributeValueMemberS{Value: sessionControlClosingSessionDueShard(candidate)},
		":next_due_sort":          &types.AttributeValueMemberS{Value: sessionControlClosingSessionDueSort(planned)},
	}
	if current.TargetCount == 0 {
		condition += " AND attribute_not_exists(session_expires_at_ms)"
	} else {
		condition += " AND session_expires_at_ms = :session_expires_at"
		values[":session_expires_at"] = &types.AttributeValueMemberN{Value: fmt.Sprint(current.SessionExpiresAtMillis)}
	}
	if current.State == sessionControlSessionStateReserved {
		condition += " AND attribute_not_exists(ack_enqueued_at_ms) AND due_shard = :current_due_shard AND due_sort = :current_due_sort"
		values[":current_due_shard"] = &types.AttributeValueMemberS{Value: sessionControlSessionDueShard(candidate)}
		values[":current_due_sort"] = &types.AttributeValueMemberS{Value: sessionControlSessionDueSort(candidate)}
	} else {
		condition += " AND ack_enqueued_at_ms = :ack_enqueued_at AND attribute_not_exists(due_shard) AND attribute_not_exists(due_sort)"
		values[":ack_enqueued_at"] = &types.AttributeValueMemberN{Value: fmt.Sprint(current.AckEnqueuedAtMillis)}
	}
	condition = sessionControlAppendNativeOperationCondition(condition, values, candidate)
	return types.TransactWriteItem{Update: &types.Update{
		Key:                       sessionControlSessionDynamoKey(candidate.SessionID),
		UpdateExpression:          aws.String("SET #state = :next_state, retain_until_ms = :next_retain, close_event_id = :close_event_id, close_prepared_directory_version = :close_prepared_version, close_prepared_at_ms = :close_prepared_at, due_shard = :next_due_shard, due_sort = :next_due_sort"),
		ConditionExpression:       aws.String(condition),
		ExpressionAttributeNames:  map[string]string{"#state": "state", "#version": "version", "#ttl": "ttl"},
		ExpressionAttributeValues: values,
	}}
}

func sessionControlSessionCloseRetentionUpdate(current sessionControlSessionAuthority, nextRetainUntilMillis int64) types.TransactWriteItem {
	candidate := current.Candidate
	condition := "kind = :kind AND schema_version = :schema AND cell_id = :cell_id AND agent_public_key = :agent_public_key AND session_id = :session_id AND issued_at_ms = :issued_at AND reservation_deadline_ms = :reservation_deadline AND run_id = :run_id AND run_attempt = :run_attempt AND #state = :state AND #version = :version AND target_count = :count AND retain_until_ms = :retain AND reserved_directory_version = :reserved_version AND reserved_active_fence_count = :reserved_count AND close_event_id = :close_event_id AND close_prepared_directory_version = :close_prepared_version AND close_prepared_at_ms = :close_prepared_at AND due_shard = :due_shard AND due_sort = :due_sort AND attribute_not_exists(#ttl)"
	values := map[string]types.AttributeValue{
		":kind":                   &types.AttributeValueMemberS{Value: sessionControlSessionMetaKind},
		":schema":                 &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlSessionSchemaForCandidate(candidate))},
		":cell_id":                &types.AttributeValueMemberS{Value: candidate.CellID},
		":agent_public_key":       &types.AttributeValueMemberS{Value: candidate.AgentPublicKey},
		":session_id":             &types.AttributeValueMemberN{Value: fmt.Sprint(candidate.SessionID)},
		":issued_at":              &types.AttributeValueMemberN{Value: fmt.Sprint(candidate.IssuedAtMillis)},
		":reservation_deadline":   &types.AttributeValueMemberN{Value: fmt.Sprint(candidate.ReservationDeadlineMillis)},
		":run_id":                 &types.AttributeValueMemberS{Value: candidate.RunID},
		":run_attempt":            &types.AttributeValueMemberN{Value: fmt.Sprint(candidate.RunAttempt)},
		":state":                  &types.AttributeValueMemberS{Value: sessionControlSessionStateClosing},
		":version":                &types.AttributeValueMemberN{Value: fmt.Sprint(current.Version)},
		":count":                  &types.AttributeValueMemberN{Value: fmt.Sprint(current.TargetCount)},
		":retain":                 &types.AttributeValueMemberN{Value: fmt.Sprint(current.RetainUntilMillis)},
		":next_retain":            &types.AttributeValueMemberN{Value: fmt.Sprint(nextRetainUntilMillis)},
		":reserved_version":       &types.AttributeValueMemberN{Value: fmt.Sprint(current.ReservedDirectoryVersion)},
		":reserved_count":         &types.AttributeValueMemberN{Value: fmt.Sprint(current.ReservedActiveFenceCount)},
		":close_event_id":         &types.AttributeValueMemberS{Value: current.CloseEventID},
		":close_prepared_version": &types.AttributeValueMemberN{Value: fmt.Sprint(current.ClosePreparedDirectory)},
		":close_prepared_at":      &types.AttributeValueMemberN{Value: fmt.Sprint(current.ClosePreparedAtMillis)},
		":due_shard":              &types.AttributeValueMemberS{Value: sessionControlClosingSessionDueShard(candidate)},
		":due_sort":               &types.AttributeValueMemberS{Value: sessionControlClosingSessionDueSort(current)},
	}
	if current.TargetCount == 0 {
		condition += " AND attribute_not_exists(session_expires_at_ms)"
	} else {
		condition += " AND session_expires_at_ms = :session_expires_at"
		values[":session_expires_at"] = &types.AttributeValueMemberN{Value: fmt.Sprint(current.SessionExpiresAtMillis)}
	}
	if current.AckEnqueuedAtMillis == 0 {
		condition += " AND attribute_not_exists(ack_enqueued_at_ms)"
	} else {
		condition += " AND ack_enqueued_at_ms = :ack_enqueued_at"
		values[":ack_enqueued_at"] = &types.AttributeValueMemberN{Value: fmt.Sprint(current.AckEnqueuedAtMillis)}
	}
	condition = sessionControlAppendNativeOperationCondition(condition, values, candidate)
	return types.TransactWriteItem{Update: &types.Update{
		Key:                       sessionControlSessionDynamoKey(candidate.SessionID),
		UpdateExpression:          aws.String("SET retain_until_ms = :next_retain"),
		ConditionExpression:       aws.String(condition),
		ExpressionAttributeNames:  map[string]string{"#state": "state", "#version": "version", "#ttl": "ttl"},
		ExpressionAttributeValues: values,
	}}
}

func sessionControlClosePut(tableName string, row sessionControlCloseWorkRow) (types.TransactWriteItem, error) {
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, fmt.Errorf("marshal session-control close work: %w", err)
	}
	return types.TransactWriteItem{Put: &types.Put{
		TableName: aws.String(tableName), Item: item,
		ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)"),
	}}, nil
}

func (s *dynamoSessionControlStore) EnsureExactSessionClose(ctx context.Context, candidate sessionControlSessionCandidate, retainUntilMillis int64) (*sessionControlExactClosePreparation, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlSessionCandidate(candidate) || retainUntilMillis < candidate.ReservationDeadlineMillis {
		return nil, errors.New("invalid exact session-control close")
	}
	eventID := sessionControlExactCloseEventID(candidate)
	baseNow, err := s.now()
	if err != nil {
		return nil, err
	}
	closeCtx, closeCancel := context.WithTimeout(ctx, s.timeout())
	defer closeCancel()
	for range sessionControlExactCloseAttempts {
		stable, err := s.readStableExactCloseState(closeCtx, candidate, eventID)
		if err != nil {
			return nil, err
		}
		if stable.Session == nil {
			return nil, errSessionControlSessionNotFound
		}
		nativeAuthority, err := s.nativeOperationForSession(closeCtx, candidate, "")
		if err != nil {
			return nil, err
		}
		if stable.Session.State == sessionControlSessionStateClosing {
			if nativeAuthority != nil && nativeAuthority.State != sessionControlNativeOperationStateClosing {
				return nil, errSessionControlNativeOperationConflict
			}
			classified, classifyErr := s.classifyExistingExactClose(closeCtx, candidate, eventID, stable)
			if classifyErr != nil {
				return nil, classifyErr
			}
			if classified.Overflow && classified.Complete == nil {
				if _, orderErr := s.getOverflowOrder(closeCtx, classified.Work); orderErr != nil {
					return nil, orderErr
				}
			}
			replayMillis := sessionControlFenceReplayHorizon.Milliseconds()
			if classified.Session.ClosePreparedAtMillis > math.MaxInt64-replayMillis {
				return nil, errSessionControlCloseCorrupt
			}
			requiredRetainUntilMillis := classified.Session.ClosePreparedAtMillis + replayMillis
			if retainUntilMillis > requiredRetainUntilMillis {
				requiredRetainUntilMillis = retainUntilMillis
			}
			if classified.Session.RetainUntilMillis >= requiredRetainUntilMillis {
				return classified, nil
			}
			if classified.Complete != nil {
				extended, extendErr := s.extendCloseCompleteRetention(ctx, candidate, *classified.Complete,
					requiredRetainUntilMillis)
				if extendErr != nil {
					return nil, extendErr
				}
				classified.Complete = extended
				classified.Session.RetainUntilMillis = extended.RetainUntilMillis
				return classified, nil
			}
			directoryCheck := sessionControlDirectoryCondition(sessionControlFenceSnapshot{
				CellID: classified.Session.Candidate.CellID, DirectoryVersion: stable.Directory.Version,
				ActiveFenceCount: stable.Directory.ActiveFenceCount, AdmissionBlocked: stable.Directory.AdmissionBlocked,
				OverflowCloseCount:                     stable.Directory.OverflowCloseCount,
				OverflowLeaderEventID:                  stable.Directory.OverflowLeaderEventID,
				OverflowLeaderPreparedDirectoryVersion: stable.Directory.OverflowLeaderPreparedDirectoryVersion,
				OverflowLeaderSelectedDirectoryVersion: stable.Directory.OverflowLeaderSelectedDirectoryVersion,
			})
			directoryCheck.ConditionCheck.TableName = aws.String(s.tableName)
			sessionWrite := sessionControlSessionCloseRetentionUpdate(classified.Session, requiredRetainUntilMillis)
			sessionWrite.Update.TableName = aws.String(s.tableName)
			token := sessionControlSessionToken("xe", eventID, classified.Session.State,
				classified.Session.Version, classified.Session.TargetCount, classified.Session.SessionExpiresAtMillis,
				classified.Session.RetainUntilMillis, classified.Session.ReservedDirectoryVersion,
				classified.Session.ReservedActiveFenceCount, classified.Session.AckEnqueuedAtMillis,
				classified.Session.ClosePreparedDirectory, classified.Session.ClosePreparedAtMillis,
				requiredRetainUntilMillis, stable.Directory.Version, stable.Directory.ActiveFenceCount,
				stable.Directory.AdmissionBlocked, stable.Directory.OverflowCloseCount,
				stable.Directory.OverflowLeaderEventID, stable.Directory.OverflowLeaderPreparedDirectoryVersion,
				stable.Directory.OverflowLeaderSelectedDirectoryVersion)
			_, writeErr := s.client.TransactWriteItems(closeCtx, &dynamodb.TransactWriteItemsInput{
				ClientRequestToken: token, TransactItems: []types.TransactWriteItem{directoryCheck, sessionWrite},
			})
			if writeErr == nil {
				classified.Session.RetainUntilMillis = requiredRetainUntilMillis
				return classified, nil
			}
			var canceled *types.TransactionCanceledException
			if errors.As(writeErr, &canceled) {
				if closeCtx.Err() != nil {
					return nil, fmt.Errorf("extend exact session-control close retention: %w", closeCtx.Err())
				}
				continue
			}
			resultCtx, resultCancel := s.exactCloseResultContext(ctx, candidate)
			latest, latestErr := s.readStableExactCloseState(resultCtx, candidate, eventID)
			if latestErr == nil {
				latestClose, exactErr := s.classifyExistingExactClose(resultCtx, candidate, eventID, latest)
				if exactErr == nil && latestClose.Overflow && latestClose.Complete == nil {
					_, exactErr = s.getOverflowOrder(resultCtx, latestClose.Work)
				}
				if exactErr == nil && candidate.NativeOperation.present() {
					_, exactErr = s.nativeOperationForSession(resultCtx, candidate,
						sessionControlNativeOperationStateClosing)
				}
				resultCancel()
				if exactErr == nil && latestClose.Session.RetainUntilMillis >= requiredRetainUntilMillis {
					return latestClose, nil
				}
				if exactErr != nil {
					return nil, exactErr
				}
			} else {
				resultCancel()
			}
			return nil, fmt.Errorf("extend exact session-control close retention: %w", writeErr)
		}
		if stable.Meta != nil || stable.Active != nil || stable.Work != nil || stable.Overflow != nil {
			return nil, errSessionControlCloseCorrupt
		}
		if nativeAuthority != nil && nativeAuthority.State != sessionControlNativeOperationStateMapped {
			return nil, errSessionControlNativeOperationConflict
		}
		directory := stable.Directory
		if directory.Version >= ^uint64(0)-2 {
			return nil, errSessionControlCloseCorrupt
		}
		transactionMillis := baseNow.UnixMilli()
		if transactionMillis < directory.UpdatedAtMillis {
			transactionMillis = directory.UpdatedAtMillis
		}
		if transactionMillis < candidate.IssuedAtMillis {
			transactionMillis = candidate.IssuedAtMillis
		}
		replayMillis := sessionControlFenceReplayHorizon.Milliseconds()
		if transactionMillis > math.MaxInt64-replayMillis {
			return nil, errSessionControlCloseCorrupt
		}
		minimumRetainUntilMillis := transactionMillis + replayMillis
		if retainUntilMillis < minimumRetainUntilMillis {
			retainUntilMillis = minimumRetainUntilMillis
		}
		preparedVersion := directory.Version + 1
		plannedSession, err := planSessionControlExactClose(*stable.Session, eventID, preparedVersion,
			transactionMillis, retainUntilMillis)
		if err != nil {
			return nil, err
		}
		selector := sessionControlExactCloseSelector(candidate)
		digest, _ := sessionControlFenceSelectorDigest(selector)
		overflow := directory.AdmissionBlocked || directory.ActiveFenceCount >= sessionControlFenceActiveLimit
		work := sessionControlCloseWork{
			CellID: candidate.CellID, EventID: eventID, Selector: selector, SelectorDigest: digest,
			Mode: sessionControlCloseWorkModeNormal, State: sessionControlCloseWorkStatePending,
			PreparedDirectoryVersion: preparedVersion, SessionVersion: stable.Session.Version,
			ExpectedTargetCount: stable.Session.TargetCount, CreatedAtMillis: transactionMillis,
			UpdatedAtMillis: transactionMillis, DueAtMillis: transactionMillis,
		}
		if overflow {
			work.Mode = sessionControlCloseWorkModeOverflow
		}
		workRow, err := sessionControlCloseWorkToRow(work)
		if err != nil {
			return nil, err
		}
		workWrite, err := sessionControlClosePut(s.tableName, workRow)
		if err != nil {
			return nil, err
		}
		directoryValues := sessionControlFenceDirectoryConditionValues(directory)
		directoryValues[":updated_at"] = &types.AttributeValueMemberN{Value: fmt.Sprint(transactionMillis)}
		directoryWrite := types.TransactWriteItem{Update: &types.Update{
			TableName: aws.String(s.tableName), Key: sessionControlFenceDirectoryKey(candidate.CellID),
			ExpressionAttributeNames:  map[string]string{"#version": "version", "#ttl": "ttl"},
			ExpressionAttributeValues: directoryValues,
		}}
		sessionWrite := sessionControlSessionCloseUpdate(*stable.Session, plannedSession)
		sessionWrite.Update.TableName = aws.String(s.tableName)
		transaction := &dynamodb.TransactWriteItemsInput{}
		var fence *sessionControlFenceAuthority
		if overflow {
			if directory.OverflowCloseCount >= ^uint64(0)-2 {
				return nil, errSessionControlCloseCorrupt
			}
			directoryValues[":next_overflow_count"] = &types.AttributeValueMemberN{Value: fmt.Sprint(directory.OverflowCloseCount + 1)}
			directoryValues[":blocked"] = &types.AttributeValueMemberBOOL{Value: true}
			directoryWrite.Update.UpdateExpression = aws.String("SET #version = :next_version, admission_blocked = :blocked, overflow_close_count = :next_overflow_count, updated_at_ms = :updated_at")
			directoryWrite.Update.ConditionExpression = aws.String(sessionControlFenceDirectoryCondition())
			orderWrite, orderErr := sessionControlOverflowOrderPut(s.tableName, work)
			if orderErr != nil {
				return nil, orderErr
			}
			transaction.ClientRequestToken = sessionControlSessionToken("xo", eventID, candidate.CellID,
				stable.Session.State, stable.Session.Version, stable.Session.TargetCount,
				stable.Session.SessionExpiresAtMillis, stable.Session.RetainUntilMillis,
				stable.Session.ReservedDirectoryVersion, stable.Session.ReservedActiveFenceCount,
				stable.Session.AckEnqueuedAtMillis,
				directory.Version, directory.ActiveFenceCount, directory.OverflowCloseCount,
				plannedSession.RetainUntilMillis, transactionMillis, sessionControlOverflowOrderSK(work))
			transaction.TransactItems = []types.TransactWriteItem{directoryWrite, sessionWrite, workWrite, orderWrite}
		} else {
			prepared := sessionControlFenceAuthority{
				CellID: candidate.CellID, EventID: eventID, Selector: selector, SelectorDigest: digest,
				PreparedDirectoryVersion: preparedVersion, State: sessionControlFencePreparing, Version: 1,
				CreatedAtMillis: transactionMillis, PreparedAtMillis: transactionMillis, UpdatedAtMillis: transactionMillis,
			}
			metaRow, rowErr := sessionControlFenceToRow(prepared, false)
			if rowErr != nil {
				return nil, rowErr
			}
			activeRow, rowErr := sessionControlFenceToRow(prepared, true)
			if rowErr != nil {
				return nil, rowErr
			}
			metaItem, marshalErr := attributevalue.MarshalMap(metaRow)
			if marshalErr != nil {
				return nil, marshalErr
			}
			activeItem, marshalErr := attributevalue.MarshalMap(activeRow)
			if marshalErr != nil {
				return nil, marshalErr
			}
			directoryValues[":next_count"] = &types.AttributeValueMemberN{Value: fmt.Sprint(directory.ActiveFenceCount + 1)}
			directoryValues[":capacity"] = &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlFenceActiveLimit)}
			directoryWrite.Update.UpdateExpression = aws.String("SET #version = :next_version, active_fence_count = :next_count, updated_at_ms = :updated_at")
			directoryWrite.Update.ConditionExpression = aws.String(sessionControlFenceDirectoryCondition() + " AND admission_blocked = :unblocked AND active_fence_count < :capacity")
			directoryValues[":unblocked"] = &types.AttributeValueMemberBOOL{Value: false}
			transaction.ClientRequestToken = sessionControlSessionToken("xn", eventID, candidate.CellID,
				stable.Session.State, stable.Session.Version, stable.Session.TargetCount,
				stable.Session.SessionExpiresAtMillis, stable.Session.RetainUntilMillis,
				stable.Session.ReservedDirectoryVersion, stable.Session.ReservedActiveFenceCount,
				stable.Session.AckEnqueuedAtMillis,
				directory.Version, directory.ActiveFenceCount, plannedSession.RetainUntilMillis, transactionMillis)
			transaction.TransactItems = []types.TransactWriteItem{
				directoryWrite,
				{Put: &types.Put{TableName: aws.String(s.tableName), Item: metaItem, ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}},
				{Put: &types.Put{TableName: aws.String(s.tableName), Item: activeItem, ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}},
				sessionWrite, workWrite,
			}
			fence = &prepared
		}
		if nativeAuthority != nil {
			closingAuthority, transitionErr := sessionControlNativeOperationPlanClosing(*nativeAuthority)
			if transitionErr != nil {
				return nil, transitionErr
			}
			operationWrite, transitionErr := sessionControlNativeOperationExactTransition(s.tableName,
				*nativeAuthority, closingAuthority)
			if transitionErr != nil {
				return nil, transitionErr
			}
			transaction.TransactItems = append(transaction.TransactItems, operationWrite)
		}
		_, writeErr := s.client.TransactWriteItems(closeCtx, transaction)
		if writeErr == nil {
			return &sessionControlExactClosePreparation{
				EventID: eventID, Session: plannedSession, Fence: fence, Work: work, Overflow: overflow,
			}, nil
		}
		var canceled *types.TransactionCanceledException
		if errors.As(writeErr, &canceled) {
			if closeCtx.Err() != nil {
				return nil, fmt.Errorf("ensure exact session-control close: %w", closeCtx.Err())
			}
			continue
		}
		resultCtx, resultCancel := s.exactCloseResultContext(ctx, candidate)
		latest, classifyErr := s.readStableExactCloseState(resultCtx, candidate, eventID)
		if classifyErr == nil && latest.Session != nil && latest.Session.State == sessionControlSessionStateClosing {
			classified, exactErr := s.classifyExistingExactClose(resultCtx, candidate, eventID, latest)
			if exactErr == nil && classified.Overflow && classified.Complete == nil {
				_, exactErr = s.getOverflowOrder(resultCtx, classified.Work)
			}
			if exactErr == nil && candidate.NativeOperation.present() {
				_, exactErr = s.nativeOperationForSession(resultCtx, candidate,
					sessionControlNativeOperationStateClosing)
			}
			resultCancel()
			if exactErr == nil && classified.Session.RetainUntilMillis >= plannedSession.RetainUntilMillis {
				return classified, nil
			}
			if exactErr != nil {
				return nil, exactErr
			}
			if exactErr == nil && closeCtx.Err() == nil {
				// Another caller may have committed the deterministic close with a
				// weaker retention horizon while this write's result was ambiguous.
				// Re-enter through the CLOSING branch and monotonically extend it;
				// never report the stronger request as satisfied by the weaker row.
				continue
			}
		} else {
			resultCancel()
		}
		return nil, fmt.Errorf("ensure exact session-control close: %w", writeErr)
	}
	return nil, errSessionControlCloseConflict
}

func (s *dynamoSessionControlStore) SnapshotOverflowCloseWork(ctx context.Context, cellID string) (*sessionControlOverflowCloseSnapshot, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlCellID(cellID) {
		return nil, errors.New("invalid session-control overflow cell id")
	}
	readCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	for range sessionControlFenceAttempts {
		before, err := s.getFenceDirectory(readCtx, cellID)
		if err != nil {
			return nil, err
		}
		var (
			work     []sessionControlCloseWork
			lastKey  map[string]types.AttributeValue
			physical uint64
		)
		for {
			result, queryErr := s.client.Query(readCtx, &dynamodb.QueryInput{
				TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true),
				KeyConditionExpression: aws.String("pk = :pk"),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":pk": &types.AttributeValueMemberS{Value: sessionControlOverflowClosePK(cellID)},
				},
				ExclusiveStartKey: lastKey, Limit: aws.Int32(sessionControlOverflowCloseQueryLimit),
			})
			if queryErr != nil {
				return nil, fmt.Errorf("session-control overflow close strong query: %w", queryErr)
			}
			if uint64(len(result.Items)) > ^uint64(0)-physical {
				return nil, errSessionControlCloseCorrupt
			}
			physical += uint64(len(result.Items))
			for _, item := range result.Items {
				rowEventID, ok := item["event_id"].(*types.AttributeValueMemberS)
				if !ok || rowEventID.Value == "" {
					return nil, errSessionControlCloseCorrupt
				}
				decoded, err := sessionControlCloseWorkFromItem(item, true, cellID, rowEventID.Value)
				if err != nil {
					return nil, err
				}
				work = append(work, decoded)
			}
			if len(result.LastEvaluatedKey) == 0 {
				break
			}
			lastKey = result.LastEvaluatedKey
		}
		after, err := s.getFenceDirectory(readCtx, cellID)
		if err != nil {
			return nil, err
		}
		if *before != *after {
			continue
		}
		if physical != after.OverflowCloseCount || after.AdmissionBlocked != (physical > 0) {
			return nil, errSessionControlCloseCorrupt
		}
		return &sessionControlOverflowCloseSnapshot{Directory: *after, Work: work}, nil
	}
	return nil, errSessionControlCloseConflict
}
