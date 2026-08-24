package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/OpenNHP/opennhp/nhp/common"
)

const (
	sessionControlSessionMetaKind            = "session_meta"
	sessionControlAgentSessionKind           = "agent_session"
	sessionControlSessionIntentKind          = "session_target_intent"
	sessionControlTargetSessionKind          = "target_session"
	sessionControlSessionMetaSK              = "META"
	sessionControlSessionTargetPrefix        = "TARGET#"
	sessionControlSessionSchema              = uint64(3)
	sessionControlSessionStateReserved       = "reserved"
	sessionControlSessionStateAckEnqueued    = "ack_enqueued"
	sessionControlSessionStateClosing        = "closing"
	sessionControlSessionStateClosed         = "closed"
	sessionControlSessionIntentMayBeAdmitted = "may_be_admitted"
	sessionControlSessionReadAttempts        = 4
	// A session can fan out to every live AC connection for one AC ID. Each
	// concurrent winner can advance the session CAS once before a loser retries,
	// so cover every peer plus one final attempt at the resulting authority.
	sessionControlSessionFanoutAttempts = MaxACConnsPerID + 1
	// Recovery scans a fixed set of liveness-only GSI partitions, then verifies
	// every discovered session with a strongly consistent base-table read.
	sessionControlSessionDueShardCount = uint64(16)
	// One base NHP session may fan out to several ACs, but an unbounded intent
	// partition would turn recovery into an unbounded correctness read. This is
	// deliberately much larger than the current AC fanout while remaining finite.
	sessionControlSessionMaxTargets = uint64(1_024)
)

var (
	errSessionControlSessionNotFound       = errors.New("session-control session not found")
	errSessionControlSessionConflict       = errors.New("session-control session changed concurrently")
	errSessionControlSessionCollision      = errors.New("session-control numeric session id collision")
	errSessionControlSessionFenceStale     = errors.New("session-control session fence snapshot is stale")
	errSessionControlSessionFenceDenied    = errors.New("session-control session is denied by an active fence")
	errSessionControlSessionTargetConflict = errors.New("session-control session target changed concurrently")
	errSessionControlSessionCorrupt        = errors.New("session-control session authority is malformed")
	errSessionControlSessionCapacity       = errors.New("session-control session target capacity is exhausted")
)

// sessionControlSessionCandidate is chosen before plugin/open-time resolution.
// ReservationDeadlineMillis is only a provisional liveness deadline; unresolved
// rows intentionally have no DynamoDB TTL and cannot be deleted on its passage.
type sessionControlSessionCandidate struct {
	CellID                    string
	AgentPublicKey            string
	SessionID                 uint64
	IssuedAtMillis            int64
	ReservationDeadlineMillis int64
	RunID                     string
	RunAttempt                uint64
}

type sessionControlSessionFence struct {
	Candidate                sessionControlSessionCandidate
	Version                  uint64
	TargetCount              uint64
	SessionExpiresAtMillis   int64
	RetainUntilMillis        int64
	ReservedDirectoryVersion uint64
	ReservedActiveFenceCount uint64
}

// sessionControlSessionAuthority has two monotonic CAS dimensions: Version
// counts intent-authority changes only, while State advances independently
// from reserved to ack_enqueued or closing and never moves backward.
type sessionControlSessionAuthority struct {
	Candidate                sessionControlSessionCandidate
	State                    string
	Version                  uint64
	TargetCount              uint64
	SessionExpiresAtMillis   int64
	RetainUntilMillis        int64
	ReservedDirectoryVersion uint64
	ReservedActiveFenceCount uint64
	AckEnqueuedAtMillis      int64
	CloseEventID             string
	ClosePreparedDirectory   uint64
	ClosePreparedAtMillis    int64
}

func (authority sessionControlSessionAuthority) fence() sessionControlSessionFence {
	return sessionControlSessionFence{
		Candidate:                authority.Candidate,
		Version:                  authority.Version,
		TargetCount:              authority.TargetCount,
		SessionExpiresAtMillis:   authority.SessionExpiresAtMillis,
		RetainUntilMillis:        authority.RetainUntilMillis,
		ReservedDirectoryVersion: authority.ReservedDirectoryVersion,
		ReservedActiveFenceCount: authority.ReservedActiveFenceCount,
	}
}

type sessionControlSessionIntent struct {
	Session                  sessionControlSessionCandidate
	Target                   sessionControlTargetAuthority
	Owner                    sessionControlOwnerAuthority
	State                    string
	SessionVersion           uint64
	SessionExpiresAtMillis   int64
	RetainUntilMillis        int64
	PreparedDirectoryVersion uint64
	PreparedActiveFenceCount uint64
}

type sessionControlSessionIntentPreparation struct {
	Session sessionControlSessionAuthority
	Intent  sessionControlSessionIntent
}

type sessionControlSessionRow struct {
	PK                        string `dynamodbav:"pk"`
	SK                        string `dynamodbav:"sk"`
	Kind                      string `dynamodbav:"kind"`
	SchemaVersion             uint64 `dynamodbav:"schema_version"`
	CellID                    string `dynamodbav:"cell_id"`
	AgentPublicKey            string `dynamodbav:"agent_public_key"`
	SessionID                 uint64 `dynamodbav:"session_id"`
	IssuedAtMillis            int64  `dynamodbav:"issued_at_ms"`
	ReservationDeadlineMillis int64  `dynamodbav:"reservation_deadline_ms"`
	RunID                     string `dynamodbav:"run_id"`
	RunAttempt                uint64 `dynamodbav:"run_attempt"`
	State                     string `dynamodbav:"state"`
	Version                   uint64 `dynamodbav:"version"`
	TargetCount               uint64 `dynamodbav:"target_count"`
	SessionExpiresAtMillis    int64  `dynamodbav:"session_expires_at_ms,omitempty"`
	RetainUntilMillis         int64  `dynamodbav:"retain_until_ms"`
	ReservedDirectoryVersion  uint64 `dynamodbav:"reserved_directory_version"`
	ReservedActiveFenceCount  uint64 `dynamodbav:"reserved_active_fence_count"`
	AckEnqueuedAtMillis       int64  `dynamodbav:"ack_enqueued_at_ms,omitempty"`
	CloseEventID              string `dynamodbav:"close_event_id,omitempty"`
	ClosePreparedDirectory    uint64 `dynamodbav:"close_prepared_directory_version,omitempty"`
	ClosePreparedAtMillis     int64  `dynamodbav:"close_prepared_at_ms,omitempty"`
	DueShard                  string `dynamodbav:"due_shard,omitempty"`
	DueSort                   string `dynamodbav:"due_sort,omitempty"`
}

type sessionControlSessionMembershipRow struct {
	PK                        string `dynamodbav:"pk"`
	SK                        string `dynamodbav:"sk"`
	Kind                      string `dynamodbav:"kind"`
	SchemaVersion             uint64 `dynamodbav:"schema_version"`
	CellID                    string `dynamodbav:"cell_id"`
	AgentPublicKey            string `dynamodbav:"agent_public_key"`
	SessionID                 uint64 `dynamodbav:"session_id"`
	IssuedAtMillis            int64  `dynamodbav:"issued_at_ms"`
	ReservationDeadlineMillis int64  `dynamodbav:"reservation_deadline_ms"`
	RunID                     string `dynamodbav:"run_id"`
	RunAttempt                uint64 `dynamodbav:"run_attempt"`
}

func sessionControlSessionRowAbsentAttributes(row sessionControlSessionRow) []string {
	absent := []string{"ttl"}
	if row.SessionExpiresAtMillis == 0 {
		absent = append(absent, "session_expires_at_ms")
	}
	if row.AckEnqueuedAtMillis == 0 {
		absent = append(absent, "ack_enqueued_at_ms")
	}
	if row.CloseEventID == "" {
		absent = append(absent, "close_event_id")
	}
	if row.ClosePreparedDirectory == 0 {
		absent = append(absent, "close_prepared_directory_version")
	}
	if row.ClosePreparedAtMillis == 0 {
		absent = append(absent, "close_prepared_at_ms")
	}
	if row.DueShard == "" {
		absent = append(absent, "due_shard")
	}
	if row.DueSort == "" {
		absent = append(absent, "due_sort")
	}
	return absent
}

type sessionControlSessionIntentRow struct {
	PK                        string `dynamodbav:"pk"`
	SK                        string `dynamodbav:"sk"`
	Kind                      string `dynamodbav:"kind"`
	SchemaVersion             uint64 `dynamodbav:"schema_version"`
	CellID                    string `dynamodbav:"cell_id"`
	AgentPublicKey            string `dynamodbav:"agent_public_key"`
	SessionID                 uint64 `dynamodbav:"session_id"`
	IssuedAtMillis            int64  `dynamodbav:"issued_at_ms"`
	ReservationDeadlineMillis int64  `dynamodbav:"reservation_deadline_ms"`
	RunID                     string `dynamodbav:"run_id"`
	RunAttempt                uint64 `dynamodbav:"run_attempt"`
	TargetACID                string `dynamodbav:"target_ac_id"`
	TargetPublicKey           string `dynamodbav:"target_public_key"`
	TargetBootID              string `dynamodbav:"target_boot_id"`
	TargetFlushGeneration     uint64 `dynamodbav:"target_flush_generation"`
	TargetVersion             uint64 `dynamodbav:"target_version"`
	TargetAuthorityVersion    uint64 `dynamodbav:"target_authority_version"`
	TargetCountedActiveSlot   bool   `dynamodbav:"target_counted_active_slot"`
	TargetControlCellID       string `dynamodbav:"target_control_cell_id"`
	TargetActivatedCursor     uint64 `dynamodbav:"target_activated_cursor"`
	TargetReadyCursor         uint64 `dynamodbav:"target_ready_cursor"`
	TargetAAKEnqueuedAtMillis int64  `dynamodbav:"target_aak_enqueued_at_ms"`
	TargetAAKTransactionID    uint64 `dynamodbav:"target_aak_transaction_id"`
	TargetCreatedAtMillis     int64  `dynamodbav:"target_created_at_ms"`
	TargetPreparedAtMillis    int64  `dynamodbav:"target_prepared_at_ms"`
	TargetUpdatedAtMillis     int64  `dynamodbav:"target_updated_at_ms"`
	TargetRetiredAtMillis     int64  `dynamodbav:"target_retired_at_ms,omitempty"`
	OwnerLifecycleVersion     uint64 `dynamodbav:"owner_lifecycle_version"`
	OwnerWorkVersion          uint64 `dynamodbav:"owner_work_version"`
	OwnerTaskCount            uint64 `dynamodbav:"owner_task_count"`
	OwnerPendingCount         uint64 `dynamodbav:"owner_pending_count"`
	State                     string `dynamodbav:"state"`
	SessionVersion            uint64 `dynamodbav:"session_version"`
	SessionExpiresAtMillis    int64  `dynamodbav:"session_expires_at_ms"`
	RetainUntilMillis         int64  `dynamodbav:"retain_until_ms"`
	PreparedDirectoryVersion  uint64 `dynamodbav:"prepared_directory_version"`
	PreparedActiveFenceCount  uint64 `dynamodbav:"prepared_active_fence_count"`
}

func sessionControlIntentTargetReadinessAttributesPresent(item map[string]types.AttributeValue) bool {
	for _, name := range []string{"target_ready_cursor", "target_aak_enqueued_at_ms", "target_aak_transaction_id",
		"owner_lifecycle_version", "owner_work_version", "owner_task_count", "owner_pending_count"} {
		if _, ok := item[name].(*types.AttributeValueMemberN); !ok {
			return false
		}
	}
	return true
}

func validSessionControlSessionCandidate(candidate sessionControlSessionCandidate) bool {
	runBindingValid := (candidate.RunID == "" && candidate.RunAttempt == 0) ||
		(common.ValidateAgentKnockRunID(candidate.RunID) == nil && candidate.RunAttempt > 0)
	return validSessionControlCellID(candidate.CellID) && common.ValidNHPAgentPublicKey(candidate.AgentPublicKey) &&
		candidate.SessionID > 0 && candidate.IssuedAtMillis > 0 &&
		candidate.ReservationDeadlineMillis > candidate.IssuedAtMillis &&
		candidate.ReservationDeadlineMillis-candidate.IssuedAtMillis == pendingSessionReservationTTL.Milliseconds() &&
		runBindingValid
}

func validateSessionControlFenceSnapshot(snapshot sessionControlFenceSnapshot, cellID string) error {
	if !validSessionControlCellID(cellID) || snapshot.CellID != cellID ||
		snapshot.DirectoryVersion == 0 || snapshot.DirectoryVersion >= ^uint64(0)-1 ||
		snapshot.ActiveFenceCount > sessionControlFenceActiveLimit ||
		snapshot.OverflowCloseCount >= ^uint64(0)-1 ||
		snapshot.AdmissionBlocked != (snapshot.OverflowCloseCount > 0) ||
		uint64(len(snapshot.Fences)) != snapshot.ActiveFenceCount ||
		validateSessionControlFenceDirectory(sessionControlFenceDirectory{
			CellID: snapshot.CellID, Version: snapshot.DirectoryVersion,
			ActiveFenceCount: snapshot.ActiveFenceCount, AdmissionBlocked: snapshot.AdmissionBlocked,
			OverflowCloseCount: snapshot.OverflowCloseCount, OverflowLeaderEventID: snapshot.OverflowLeaderEventID,
			OverflowLeaderPreparedDirectoryVersion: snapshot.OverflowLeaderPreparedDirectoryVersion,
			OverflowLeaderSelectedDirectoryVersion: snapshot.OverflowLeaderSelectedDirectoryVersion,
			CreatedAtMillis:                        1, UpdatedAtMillis: 1,
		}) != nil {
		return errSessionControlSessionCorrupt
	}
	seen := make(map[string]struct{}, len(snapshot.Fences))
	for _, fence := range snapshot.Fences {
		if validateSessionControlFenceAuthority(fence) != nil || fence.CellID != cellID ||
			fence.State == sessionControlFenceRetired || fence.PreparedDirectoryVersion > snapshot.DirectoryVersion {
			return errSessionControlSessionCorrupt
		}
		if _, duplicate := seen[fence.EventID]; duplicate {
			return errSessionControlSessionCorrupt
		}
		seen[fence.EventID] = struct{}{}
	}
	return nil
}

func evaluateSessionControlFences(candidate sessionControlSessionCandidate, snapshot sessionControlFenceSnapshot) error {
	if !validSessionControlSessionCandidate(candidate) {
		return errors.New("invalid session-control session candidate")
	}
	if err := validateSessionControlFenceSnapshot(snapshot, candidate.CellID); err != nil {
		return err
	}
	if snapshot.AdmissionBlocked {
		return errSessionControlAdmissionBlocked
	}
	for _, fence := range snapshot.Fences {
		selector := fence.Selector
		if selector.AgentPublicKey != candidate.AgentPublicKey {
			continue
		}
		switch selector.Scope {
		case sessionControlFenceSelectorExact:
			if selector.SessionID == candidate.SessionID && selector.SessionIssuedMillis == candidate.IssuedAtMillis {
				return errSessionControlSessionFenceDenied
			}
		case sessionControlFenceSelectorAgent:
			if fence.State == sessionControlFencePreparing || candidate.IssuedAtMillis <= selector.IssuedThroughMillis {
				return errSessionControlSessionFenceDenied
			}
		case sessionControlFenceSelectorRun:
			if selector.RunID == candidate.RunID &&
				(fence.State == sessionControlFencePreparing || selector.RunAttempt != candidate.RunAttempt) {
				return errSessionControlSessionFenceDenied
			}
		default:
			return errSessionControlSessionCorrupt
		}
	}
	return nil
}

func validateSessionControlSessionAuthority(authority sessionControlSessionAuthority) error {
	if !validSessionControlSessionCandidate(authority.Candidate) ||
		authority.Version == 0 || authority.Version >= ^uint64(0)-1 ||
		authority.TargetCount > sessionControlSessionMaxTargets || authority.TargetCount >= authority.Version ||
		(authority.Version == 1 && authority.TargetCount != 0) ||
		(authority.Version > 1 && authority.TargetCount == 0) ||
		(authority.TargetCount == 0 && authority.SessionExpiresAtMillis != 0) ||
		(authority.TargetCount > 0 && (authority.SessionExpiresAtMillis <= authority.Candidate.IssuedAtMillis ||
			authority.SessionExpiresAtMillis > authority.RetainUntilMillis)) ||
		authority.RetainUntilMillis < authority.Candidate.ReservationDeadlineMillis ||
		authority.ReservedDirectoryVersion == 0 || authority.ReservedDirectoryVersion >= ^uint64(0)-1 ||
		authority.ReservedActiveFenceCount > sessionControlFenceActiveLimit {
		return errSessionControlSessionCorrupt
	}
	switch authority.State {
	case sessionControlSessionStateReserved:
		if authority.AckEnqueuedAtMillis != 0 || authority.CloseEventID != "" || authority.ClosePreparedDirectory != 0 ||
			authority.ClosePreparedAtMillis != 0 {
			return errSessionControlSessionCorrupt
		}
	case sessionControlSessionStateAckEnqueued:
		if authority.TargetCount == 0 || authority.AckEnqueuedAtMillis < authority.Candidate.IssuedAtMillis ||
			authority.AckEnqueuedAtMillis >= authority.SessionExpiresAtMillis ||
			authority.CloseEventID != "" || authority.ClosePreparedDirectory != 0 || authority.ClosePreparedAtMillis != 0 {
			return errSessionControlSessionCorrupt
		}
	case sessionControlSessionStateClosing, sessionControlSessionStateClosed:
		if (authority.AckEnqueuedAtMillis != 0 && authority.AckEnqueuedAtMillis < authority.Candidate.IssuedAtMillis) ||
			(authority.AckEnqueuedAtMillis != 0 && authority.AckEnqueuedAtMillis >= authority.SessionExpiresAtMillis) ||
			!validSessionControlFenceEventID(authority.CloseEventID) ||
			authority.ClosePreparedDirectory <= authority.ReservedDirectoryVersion ||
			authority.ClosePreparedAtMillis < authority.Candidate.IssuedAtMillis ||
			authority.ClosePreparedAtMillis > authority.RetainUntilMillis {
			return errSessionControlSessionCorrupt
		}
	default:
		return errSessionControlSessionCorrupt
	}
	return nil
}

func validSessionControlSessionFence(fence sessionControlSessionFence) bool {
	authority := sessionControlSessionAuthority{
		Candidate: fence.Candidate, State: sessionControlSessionStateReserved,
		Version: fence.Version, TargetCount: fence.TargetCount, RetainUntilMillis: fence.RetainUntilMillis,
		SessionExpiresAtMillis:   fence.SessionExpiresAtMillis,
		ReservedDirectoryVersion: fence.ReservedDirectoryVersion,
		ReservedActiveFenceCount: fence.ReservedActiveFenceCount,
	}
	return validateSessionControlSessionAuthority(authority) == nil && fence.Version < ^uint64(0)-1
}

func validateSessionControlSnapshotAfterReservation(fence sessionControlSessionFence, snapshot sessionControlFenceSnapshot) error {
	if snapshot.DirectoryVersion < fence.ReservedDirectoryVersion {
		return errSessionControlSessionFenceStale
	}
	if snapshot.DirectoryVersion == fence.ReservedDirectoryVersion &&
		snapshot.ActiveFenceCount != fence.ReservedActiveFenceCount {
		return errSessionControlSessionCorrupt
	}
	return nil
}

func validateSessionControlSessionIntent(intent sessionControlSessionIntent) error {
	if !validSessionControlSessionCandidate(intent.Session) ||
		validateSessionControlTargetAuthority(intent.Target) != nil || !intent.Target.ready() ||
		intent.Target.ControlCellID != intent.Session.CellID || intent.Target.Version >= ^uint64(0)-1 ||
		intent.Target.AuthorityVersion >= ^uint64(0)-1 ||
		intent.State != sessionControlSessionIntentMayBeAdmitted || intent.SessionVersion < 2 ||
		intent.SessionVersion >= ^uint64(0)-1 ||
		intent.SessionExpiresAtMillis <= intent.Session.IssuedAtMillis ||
		intent.RetainUntilMillis < intent.SessionExpiresAtMillis ||
		intent.PreparedDirectoryVersion == 0 || intent.PreparedDirectoryVersion >= ^uint64(0)-1 ||
		intent.PreparedDirectoryVersion < intent.Target.ActivatedControlVersion ||
		intent.PreparedActiveFenceCount > sessionControlFenceActiveLimit ||
		validateSessionControlOwnerAuthority(intent.Owner) != nil || intent.Owner.Phase != sessionControlOwnerReady ||
		intent.Owner.PendingCount != 0 || !intent.Owner.exactTarget(intent.Target, sessionControlOwnerReady) {
		return errSessionControlSessionCorrupt
	}
	return nil
}

func sessionControlSessionHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func sessionControlSessionIDText(sessionID uint64) string {
	return fmt.Sprintf("%020d", sessionID)
}

func sessionControlSessionIssuedText(issuedAtMillis int64) string {
	return fmt.Sprintf("%019d", issuedAtMillis)
}

func sessionControlSessionDueShard(candidate sessionControlSessionCandidate) string {
	return sessionControlSessionDueShardForState(candidate, sessionControlSessionStateReserved)
}

func sessionControlClosingSessionDueShard(candidate sessionControlSessionCandidate) string {
	return sessionControlSessionDueShardForState(candidate, sessionControlSessionStateClosing)
}

func sessionControlSessionDueShardForState(candidate sessionControlSessionCandidate, state string) string {
	return fmt.Sprintf("SESSION#%s#%s#%02d", state, candidate.CellID,
		candidate.SessionID%sessionControlSessionDueShardCount)
}

func sessionControlSessionAuthorityDueShard(authority sessionControlSessionAuthority) string {
	return sessionControlSessionDueShardForState(authority.Candidate, authority.State)
}

func sessionControlSessionDueSort(candidate sessionControlSessionCandidate) string {
	return sessionControlSessionIssuedText(candidate.ReservationDeadlineMillis) + "#" +
		sessionControlSessionIDText(candidate.SessionID)
}

func sessionControlClosingSessionDueSort(authority sessionControlSessionAuthority) string {
	return sessionControlSessionIssuedText(authority.ClosePreparedAtMillis) + "#" +
		sessionControlSessionIDText(authority.Candidate.SessionID)
}

func sessionControlSessionAuthorityDueSort(authority sessionControlSessionAuthority) string {
	if authority.State == sessionControlSessionStateClosing {
		return sessionControlClosingSessionDueSort(authority)
	}
	return sessionControlSessionDueSort(authority.Candidate)
}

func sessionControlSessionAuthorityDueAt(authority sessionControlSessionAuthority) int64 {
	if authority.State == sessionControlSessionStateClosing {
		return authority.ClosePreparedAtMillis
	}
	return authority.Candidate.ReservationDeadlineMillis
}

func sessionControlSessionPK(sessionID uint64) string {
	return "SESSION#" + sessionControlSessionIDText(sessionID)
}

func sessionControlAgentSessionPK(agentPublicKey string) string {
	return "AGENT#" + sessionControlSessionHash(agentPublicKey)
}

func sessionControlSessionMembershipSK(issuedAtMillis int64, sessionID uint64) string {
	return "SESSION#" + sessionControlSessionIssuedText(issuedAtMillis) + "#" + sessionControlSessionIDText(sessionID)
}

func sessionControlIntentTargetDigest(target sessionControlTargetAuthority) string {
	canonical := fmt.Sprintf("v1\x00%s\x00%s\x00%s\x00%s\x00%d",
		target.ControlCellID, target.ACID, target.PublicKey, target.BootID, target.FlushGeneration)
	return sessionControlSessionHash(canonical)
}

func sessionControlSessionIntentSK(target sessionControlTargetAuthority) string {
	return sessionControlSessionTargetPrefix + sessionControlIntentTargetDigest(target)
}

func sessionControlTargetSessionPK(target sessionControlTargetAuthority) string {
	return "TARGET#" + sessionControlIntentTargetDigest(target)
}

func sessionControlSessionDynamoKey(sessionID uint64) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlSessionPK(sessionID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlSessionMetaSK},
	}
}

func sessionControlAgentSessionDynamoKey(candidate sessionControlSessionCandidate) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlAgentSessionPK(candidate.AgentPublicKey)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlSessionMembershipSK(candidate.IssuedAtMillis, candidate.SessionID)},
	}
}

func sessionControlSessionIntentDynamoKey(sessionID uint64, target sessionControlTargetAuthority) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlSessionPK(sessionID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlSessionIntentSK(target)},
	}
}

func sessionControlTargetSessionDynamoKey(candidate sessionControlSessionCandidate, target sessionControlTargetAuthority) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlTargetSessionPK(target)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlSessionMembershipSK(candidate.IssuedAtMillis, candidate.SessionID)},
	}
}

func sessionControlSessionToRow(authority sessionControlSessionAuthority) (sessionControlSessionRow, error) {
	if err := validateSessionControlSessionAuthority(authority); err != nil {
		return sessionControlSessionRow{}, err
	}
	candidate := authority.Candidate
	row := sessionControlSessionRow{
		PK: sessionControlSessionPK(candidate.SessionID), SK: sessionControlSessionMetaSK,
		Kind: sessionControlSessionMetaKind, SchemaVersion: sessionControlSessionSchema,
		CellID: candidate.CellID, AgentPublicKey: candidate.AgentPublicKey, SessionID: candidate.SessionID,
		IssuedAtMillis: candidate.IssuedAtMillis, ReservationDeadlineMillis: candidate.ReservationDeadlineMillis,
		RunID: candidate.RunID, RunAttempt: candidate.RunAttempt, State: authority.State,
		Version: authority.Version, TargetCount: authority.TargetCount,
		SessionExpiresAtMillis: authority.SessionExpiresAtMillis, RetainUntilMillis: authority.RetainUntilMillis,
		ReservedDirectoryVersion: authority.ReservedDirectoryVersion,
		ReservedActiveFenceCount: authority.ReservedActiveFenceCount,
		AckEnqueuedAtMillis:      authority.AckEnqueuedAtMillis,
		CloseEventID:             authority.CloseEventID, ClosePreparedDirectory: authority.ClosePreparedDirectory,
		ClosePreparedAtMillis: authority.ClosePreparedAtMillis,
	}
	if authority.State == sessionControlSessionStateReserved || authority.State == sessionControlSessionStateClosing {
		row.DueShard = sessionControlSessionAuthorityDueShard(authority)
		row.DueSort = sessionControlSessionAuthorityDueSort(authority)
	}
	return row, nil
}

func sessionControlSessionFromRow(row sessionControlSessionRow, expectedSessionID uint64) (sessionControlSessionAuthority, error) {
	authority := sessionControlSessionAuthority{
		Candidate: sessionControlSessionCandidate{
			CellID: row.CellID, AgentPublicKey: row.AgentPublicKey, SessionID: row.SessionID,
			IssuedAtMillis: row.IssuedAtMillis, ReservationDeadlineMillis: row.ReservationDeadlineMillis,
			RunID: row.RunID, RunAttempt: row.RunAttempt,
		},
		State: row.State, Version: row.Version, TargetCount: row.TargetCount,
		SessionExpiresAtMillis: row.SessionExpiresAtMillis, RetainUntilMillis: row.RetainUntilMillis,
		ReservedDirectoryVersion: row.ReservedDirectoryVersion,
		ReservedActiveFenceCount: row.ReservedActiveFenceCount,
		AckEnqueuedAtMillis:      row.AckEnqueuedAtMillis,
		CloseEventID:             row.CloseEventID, ClosePreparedDirectory: row.ClosePreparedDirectory,
		ClosePreparedAtMillis: row.ClosePreparedAtMillis,
	}
	if row.Kind != sessionControlSessionMetaKind || row.SchemaVersion != sessionControlSessionSchema ||
		row.PK != sessionControlSessionPK(row.SessionID) || row.SK != sessionControlSessionMetaSK || row.SessionID != expectedSessionID ||
		validateSessionControlSessionAuthority(authority) != nil {
		return sessionControlSessionAuthority{}, errSessionControlSessionCorrupt
	}
	if authority.State == sessionControlSessionStateReserved || authority.State == sessionControlSessionStateClosing {
		if row.DueShard != sessionControlSessionAuthorityDueShard(authority) ||
			row.DueSort != sessionControlSessionAuthorityDueSort(authority) {
			return sessionControlSessionAuthority{}, errSessionControlSessionCorrupt
		}
	} else if row.DueShard != "" || row.DueSort != "" {
		return sessionControlSessionAuthority{}, errSessionControlSessionCorrupt
	}
	return authority, nil
}

func sessionControlSessionMembershipToRow(candidate sessionControlSessionCandidate) (sessionControlSessionMembershipRow, error) {
	if !validSessionControlSessionCandidate(candidate) {
		return sessionControlSessionMembershipRow{}, errSessionControlSessionCorrupt
	}
	return sessionControlSessionMembershipRow{
		PK:   sessionControlAgentSessionPK(candidate.AgentPublicKey),
		SK:   sessionControlSessionMembershipSK(candidate.IssuedAtMillis, candidate.SessionID),
		Kind: sessionControlAgentSessionKind, SchemaVersion: sessionControlSessionSchema,
		CellID: candidate.CellID, AgentPublicKey: candidate.AgentPublicKey, SessionID: candidate.SessionID,
		IssuedAtMillis: candidate.IssuedAtMillis, ReservationDeadlineMillis: candidate.ReservationDeadlineMillis,
		RunID: candidate.RunID, RunAttempt: candidate.RunAttempt,
	}, nil
}

func sessionControlSessionMembershipFromRow(row sessionControlSessionMembershipRow, expected sessionControlSessionCandidate) (sessionControlSessionCandidate, error) {
	candidate := sessionControlSessionCandidate{
		CellID: row.CellID, AgentPublicKey: row.AgentPublicKey, SessionID: row.SessionID,
		IssuedAtMillis: row.IssuedAtMillis, ReservationDeadlineMillis: row.ReservationDeadlineMillis,
		RunID: row.RunID, RunAttempt: row.RunAttempt,
	}
	if row.Kind != sessionControlAgentSessionKind || row.SchemaVersion != sessionControlSessionSchema ||
		row.PK != sessionControlAgentSessionPK(row.AgentPublicKey) ||
		row.SK != sessionControlSessionMembershipSK(row.IssuedAtMillis, row.SessionID) ||
		!validSessionControlSessionCandidate(candidate) || candidate != expected {
		return sessionControlSessionCandidate{}, errSessionControlSessionCorrupt
	}
	return candidate, nil
}

func sessionControlIntentToRow(intent sessionControlSessionIntent, reverse bool) (sessionControlSessionIntentRow, error) {
	if err := validateSessionControlSessionIntent(intent); err != nil {
		return sessionControlSessionIntentRow{}, err
	}
	row := sessionControlSessionIntentRow{
		Kind: sessionControlSessionIntentKind, SchemaVersion: sessionControlSessionSchema,
		CellID: intent.Session.CellID, AgentPublicKey: intent.Session.AgentPublicKey,
		SessionID: intent.Session.SessionID, IssuedAtMillis: intent.Session.IssuedAtMillis,
		ReservationDeadlineMillis: intent.Session.ReservationDeadlineMillis,
		RunID:                     intent.Session.RunID, RunAttempt: intent.Session.RunAttempt,
		TargetACID: intent.Target.ACID, TargetPublicKey: intent.Target.PublicKey,
		TargetBootID: intent.Target.BootID, TargetFlushGeneration: intent.Target.FlushGeneration,
		TargetVersion: intent.Target.Version, TargetAuthorityVersion: intent.Target.AuthorityVersion,
		TargetCountedActiveSlot: intent.Target.CountedActiveSlot, TargetControlCellID: intent.Target.ControlCellID,
		TargetActivatedCursor:     intent.Target.ActivatedControlVersion,
		TargetReadyCursor:         intent.Target.ReadyControlVersion,
		TargetAAKEnqueuedAtMillis: intent.Target.AAKEnqueuedAtMillis,
		TargetAAKTransactionID:    intent.Target.AAKTransactionID,
		TargetCreatedAtMillis:     intent.Target.CreatedAtMillis, TargetPreparedAtMillis: intent.Target.PreparedAtMillis,
		TargetUpdatedAtMillis: intent.Target.UpdatedAtMillis, TargetRetiredAtMillis: intent.Target.RetiredAtMillis,
		OwnerLifecycleVersion: intent.Owner.LifecycleVersion, OwnerWorkVersion: intent.Owner.WorkVersion,
		OwnerTaskCount: intent.Owner.TaskCount, OwnerPendingCount: intent.Owner.PendingCount,
		State: intent.State, SessionVersion: intent.SessionVersion,
		SessionExpiresAtMillis: intent.SessionExpiresAtMillis, RetainUntilMillis: intent.RetainUntilMillis,
		PreparedDirectoryVersion: intent.PreparedDirectoryVersion,
		PreparedActiveFenceCount: intent.PreparedActiveFenceCount,
	}
	if reverse {
		row.PK = sessionControlTargetSessionPK(intent.Target)
		row.SK = sessionControlSessionMembershipSK(intent.Session.IssuedAtMillis, intent.Session.SessionID)
		row.Kind = sessionControlTargetSessionKind
	} else {
		row.PK = sessionControlSessionPK(intent.Session.SessionID)
		row.SK = sessionControlSessionIntentSK(intent.Target)
	}
	return row, nil
}

func sessionControlIntentFromRow(row sessionControlSessionIntentRow, reverse bool) (sessionControlSessionIntent, error) {
	intent := sessionControlSessionIntent{
		Session: sessionControlSessionCandidate{
			CellID: row.CellID, AgentPublicKey: row.AgentPublicKey, SessionID: row.SessionID,
			IssuedAtMillis: row.IssuedAtMillis, ReservationDeadlineMillis: row.ReservationDeadlineMillis,
			RunID: row.RunID, RunAttempt: row.RunAttempt,
		},
		Target: sessionControlTargetAuthority{
			ACID: row.TargetACID, PublicKey: row.TargetPublicKey, BootID: row.TargetBootID,
			FlushGeneration: row.TargetFlushGeneration, State: sessionControlTargetActive,
			Version: row.TargetVersion, AuthorityVersion: row.TargetAuthorityVersion,
			CountedActiveSlot: row.TargetCountedActiveSlot, ControlCellID: row.TargetControlCellID,
			ActivatedControlVersion: row.TargetActivatedCursor,
			ReadyControlVersion:     row.TargetReadyCursor,
			AAKEnqueuedAtMillis:     row.TargetAAKEnqueuedAtMillis,
			AAKTransactionID:        row.TargetAAKTransactionID,
			CreatedAtMillis:         row.TargetCreatedAtMillis, PreparedAtMillis: row.TargetPreparedAtMillis,
			UpdatedAtMillis: row.TargetUpdatedAtMillis, RetiredAtMillis: row.TargetRetiredAtMillis,
		},
		Owner: sessionControlOwnerAuthority{
			CellID: row.TargetControlCellID, ACID: row.TargetACID, PublicKey: row.TargetPublicKey,
			LifecycleVersion: row.OwnerLifecycleVersion, WorkVersion: row.OwnerWorkVersion,
			TaskCount: row.OwnerTaskCount, PendingCount: row.OwnerPendingCount,
			Phase: sessionControlOwnerReady, BootID: row.TargetBootID, FlushGeneration: row.TargetFlushGeneration,
			TargetVersion: row.TargetVersion, TargetAuthorityVersion: row.TargetAuthorityVersion,
			TargetCountedActiveSlot: row.TargetCountedActiveSlot,
			ActivatedControlVersion: row.TargetActivatedCursor, ReadyControlVersion: row.TargetReadyCursor,
			TargetCreatedAtMillis: row.TargetCreatedAtMillis, TargetPreparedAtMillis: row.TargetPreparedAtMillis,
			TargetUpdatedAtMillis: row.TargetUpdatedAtMillis, AAKEnqueuedAtMillis: row.TargetAAKEnqueuedAtMillis,
			AAKTransactionID: row.TargetAAKTransactionID, CreatedAtMillis: row.TargetCreatedAtMillis,
			UpdatedAtMillis: row.TargetUpdatedAtMillis,
		},
		State: row.State, SessionVersion: row.SessionVersion,
		SessionExpiresAtMillis: row.SessionExpiresAtMillis, RetainUntilMillis: row.RetainUntilMillis,
		PreparedDirectoryVersion: row.PreparedDirectoryVersion,
		PreparedActiveFenceCount: row.PreparedActiveFenceCount,
	}
	expectedKind := sessionControlSessionIntentKind
	expectedPK := sessionControlSessionPK(row.SessionID)
	expectedSK := sessionControlSessionIntentSK(intent.Target)
	if reverse {
		expectedKind = sessionControlTargetSessionKind
		expectedPK = sessionControlTargetSessionPK(intent.Target)
		expectedSK = sessionControlSessionMembershipSK(row.IssuedAtMillis, row.SessionID)
	}
	if row.Kind != expectedKind || row.SchemaVersion != sessionControlSessionSchema || row.PK != expectedPK || row.SK != expectedSK ||
		validateSessionControlSessionIntent(intent) != nil {
		return sessionControlSessionIntent{}, errSessionControlSessionCorrupt
	}
	return intent, nil
}

func sessionControlSessionCandidateEqual(left, right sessionControlSessionCandidate) bool {
	return left == right
}

func sessionControlIntentExact(left, right sessionControlSessionIntent) bool {
	return left == right
}

func sessionControlIntentSameAuthority(left, right sessionControlSessionIntent) bool {
	return left.Session == right.Session && left.Target == right.Target && left.Owner == right.Owner && left.State == right.State
}

func sessionControlTargetSameProcess(left, right sessionControlTargetAuthority) bool {
	return left.ControlCellID == right.ControlCellID && left.ACID == right.ACID &&
		left.PublicKey == right.PublicKey && left.BootID == right.BootID &&
		left.FlushGeneration == right.FlushGeneration
}

func sessionControlIntentSameProcess(left, right sessionControlSessionIntent) bool {
	return left.Session == right.Session && sessionControlTargetSameProcess(left.Target, right.Target) &&
		left.State == right.State
}

func sessionControlTargetCanExtend(current, next sessionControlTargetAuthority) bool {
	if !sessionControlTargetSameProcess(current, next) ||
		current.State != sessionControlTargetActive || next.State != sessionControlTargetActive ||
		next.Version < current.Version || next.AuthorityVersion < current.AuthorityVersion ||
		next.ActivatedControlVersion < current.ActivatedControlVersion ||
		next.ReadyControlVersion < current.ReadyControlVersion ||
		next.AAKEnqueuedAtMillis < current.AAKEnqueuedAtMillis ||
		next.CreatedAtMillis != current.CreatedAtMillis || next.PreparedAtMillis < current.UpdatedAtMillis ||
		next.UpdatedAtMillis < current.UpdatedAtMillis {
		return false
	}
	return next.Version > current.Version || next == current
}

func sessionControlIntentSatisfies(intent, requested sessionControlSessionIntent) bool {
	return sessionControlIntentSameAuthority(intent, requested) &&
		intent.SessionExpiresAtMillis == requested.SessionExpiresAtMillis &&
		intent.RetainUntilMillis >= requested.RetainUntilMillis &&
		intent.PreparedDirectoryVersion == requested.PreparedDirectoryVersion &&
		intent.PreparedActiveFenceCount == requested.PreparedActiveFenceCount
}

func planSessionControlReservation(candidate sessionControlSessionCandidate, snapshot sessionControlFenceSnapshot) (sessionControlSessionAuthority, error) {
	if err := evaluateSessionControlFences(candidate, snapshot); err != nil {
		return sessionControlSessionAuthority{}, err
	}
	return sessionControlSessionAuthority{
		Candidate: candidate, State: sessionControlSessionStateReserved, Version: 1,
		RetainUntilMillis:        candidate.ReservationDeadlineMillis,
		ReservedDirectoryVersion: snapshot.DirectoryVersion,
		ReservedActiveFenceCount: snapshot.ActiveFenceCount,
	}, nil
}

func planSessionControlIntent(fence sessionControlSessionFence, target sessionControlTargetAuthority,
	sessionExpiresAtMillis, retainUntilMillis int64, snapshot sessionControlFenceSnapshot) (sessionControlSessionIntentPreparation, error) {
	if !validSessionControlSessionFence(fence) || validateSessionControlTargetAuthority(target) != nil ||
		!target.ready() || target.ControlCellID != fence.Candidate.CellID ||
		sessionExpiresAtMillis <= fence.Candidate.IssuedAtMillis || retainUntilMillis < sessionExpiresAtMillis {
		return sessionControlSessionIntentPreparation{}, errors.New("invalid session-control session intent")
	}
	if (fence.TargetCount == 0 && fence.SessionExpiresAtMillis != 0) ||
		(fence.TargetCount > 0 && fence.SessionExpiresAtMillis != sessionExpiresAtMillis) {
		return sessionControlSessionIntentPreparation{}, errSessionControlSessionConflict
	}
	if target.Version >= ^uint64(0)-1 || target.AuthorityVersion >= ^uint64(0)-1 {
		return sessionControlSessionIntentPreparation{}, errSessionControlSessionCorrupt
	}
	if err := evaluateSessionControlFences(fence.Candidate, snapshot); err != nil {
		return sessionControlSessionIntentPreparation{}, err
	}
	if err := validateSessionControlSnapshotAfterReservation(fence, snapshot); err != nil {
		return sessionControlSessionIntentPreparation{}, err
	}
	if snapshot.DirectoryVersion < target.ActivatedControlVersion {
		return sessionControlSessionIntentPreparation{}, errSessionControlSessionFenceStale
	}
	if fence.TargetCount >= sessionControlSessionMaxTargets {
		return sessionControlSessionIntentPreparation{}, errSessionControlSessionCapacity
	}
	nextRetain := fence.RetainUntilMillis
	if retainUntilMillis > nextRetain {
		nextRetain = retainUntilMillis
	}
	next := sessionControlSessionAuthority{
		Candidate: fence.Candidate, State: sessionControlSessionStateReserved,
		Version: fence.Version + 1, TargetCount: fence.TargetCount + 1,
		SessionExpiresAtMillis: sessionExpiresAtMillis, RetainUntilMillis: nextRetain,
		ReservedDirectoryVersion: fence.ReservedDirectoryVersion,
		ReservedActiveFenceCount: fence.ReservedActiveFenceCount,
	}
	owner, ownerErr := sessionControlOwnerFromTarget(target, nil, sessionControlOwnerReady)
	if ownerErr != nil {
		return sessionControlSessionIntentPreparation{}, errSessionControlSessionCorrupt
	}
	intent := sessionControlSessionIntent{
		Session: fence.Candidate, Target: target, Owner: owner, State: sessionControlSessionIntentMayBeAdmitted,
		SessionVersion: next.Version, SessionExpiresAtMillis: sessionExpiresAtMillis, RetainUntilMillis: retainUntilMillis,
		PreparedDirectoryVersion: snapshot.DirectoryVersion,
		PreparedActiveFenceCount: snapshot.ActiveFenceCount,
	}
	if validateSessionControlSessionAuthority(next) != nil || validateSessionControlSessionIntent(intent) != nil {
		return sessionControlSessionIntentPreparation{}, errSessionControlSessionCorrupt
	}
	return sessionControlSessionIntentPreparation{Session: next, Intent: intent}, nil
}

func planSessionControlIntentExtension(current sessionControlSessionAuthority, fence sessionControlSessionFence,
	existing sessionControlSessionIntent, target sessionControlTargetAuthority, sessionExpiresAtMillis, retainUntilMillis int64,
	snapshot sessionControlFenceSnapshot) (sessionControlSessionIntentPreparation, error) {
	if current.fence() != fence || existing.Session != fence.Candidate ||
		existing.State != sessionControlSessionIntentMayBeAdmitted ||
		validateSessionControlTargetAuthority(target) != nil || !sessionControlTargetCanExtend(existing.Target, target) ||
		sessionExpiresAtMillis != fence.SessionExpiresAtMillis ||
		existing.SessionExpiresAtMillis != fence.SessionExpiresAtMillis || retainUntilMillis < sessionExpiresAtMillis {
		return sessionControlSessionIntentPreparation{}, errSessionControlSessionConflict
	}
	if err := evaluateSessionControlFences(fence.Candidate, snapshot); err != nil {
		return sessionControlSessionIntentPreparation{}, err
	}
	if err := validateSessionControlSnapshotAfterReservation(fence, snapshot); err != nil {
		return sessionControlSessionIntentPreparation{}, err
	}
	if snapshot.DirectoryVersion < existing.PreparedDirectoryVersion ||
		snapshot.DirectoryVersion < target.ActivatedControlVersion {
		return sessionControlSessionIntentPreparation{}, errSessionControlSessionFenceStale
	}
	if fence.Version >= ^uint64(0)-1 {
		return sessionControlSessionIntentPreparation{}, errSessionControlSessionCorrupt
	}
	nextSession := current
	nextSession.Version++
	if retainUntilMillis > nextSession.RetainUntilMillis {
		nextSession.RetainUntilMillis = retainUntilMillis
	}
	nextIntent := existing
	nextIntent.Target = target
	owner, ownerErr := sessionControlOwnerFromTarget(target, nil, sessionControlOwnerReady)
	if ownerErr != nil {
		return sessionControlSessionIntentPreparation{}, errSessionControlSessionCorrupt
	}
	nextIntent.Owner = owner
	nextIntent.SessionVersion = nextSession.Version
	if retainUntilMillis > nextIntent.RetainUntilMillis {
		nextIntent.RetainUntilMillis = retainUntilMillis
	}
	nextIntent.PreparedDirectoryVersion = snapshot.DirectoryVersion
	nextIntent.PreparedActiveFenceCount = snapshot.ActiveFenceCount
	if validateSessionControlSessionAuthority(nextSession) != nil || validateSessionControlSessionIntent(nextIntent) != nil {
		return sessionControlSessionIntentPreparation{}, errSessionControlSessionCorrupt
	}
	return sessionControlSessionIntentPreparation{Session: nextSession, Intent: nextIntent}, nil
}

func sessionControlSessionToken(action string, parts ...any) *string {
	hasher := sha256.New()
	_, _ = fmt.Fprintf(hasher, "v1\x00%s", action)
	for _, part := range parts {
		_, _ = fmt.Fprintf(hasher, "\x00%v", part)
	}
	token := "ss-" + action + "-" + hex.EncodeToString(hasher.Sum(nil)[:12])
	return aws.String(token)
}

func sessionControlReservationToken(candidate sessionControlSessionCandidate, snapshot sessionControlFenceSnapshot) *string {
	return sessionControlSessionToken("reserve", candidate.CellID, candidate.AgentPublicKey, candidate.SessionID,
		candidate.IssuedAtMillis, candidate.ReservationDeadlineMillis, candidate.RunID, candidate.RunAttempt,
		snapshot.CellID, snapshot.DirectoryVersion, snapshot.ActiveFenceCount)
}

func sessionControlIntentTokenWithOwner(fence sessionControlSessionFence, target sessionControlTargetAuthority,
	owner sessionControlOwnerAuthority, sessionExpiresAtMillis, retainUntilMillis int64,
	snapshot sessionControlFenceSnapshot) *string {
	return sessionControlSessionToken("intent", fence.Candidate.CellID, fence.Candidate.AgentPublicKey,
		fence.Candidate.SessionID, fence.Candidate.IssuedAtMillis, fence.Candidate.ReservationDeadlineMillis,
		fence.Candidate.RunID, fence.Candidate.RunAttempt, fence.Version, fence.TargetCount,
		fence.SessionExpiresAtMillis, fence.RetainUntilMillis,
		fence.ReservedDirectoryVersion, fence.ReservedActiveFenceCount,
		target.ACID, target.PublicKey, target.BootID, target.FlushGeneration, target.Version,
		target.AuthorityVersion, target.CountedActiveSlot, target.ActivatedControlVersion, target.ControlCellID,
		target.ReadyControlVersion, target.AAKEnqueuedAtMillis, target.AAKTransactionID,
		target.CreatedAtMillis, target.PreparedAtMillis, target.UpdatedAtMillis, target.RetiredAtMillis, target.State,
		owner.LifecycleVersion, owner.WorkVersion, owner.TaskCount, owner.PendingCount, owner.Phase,
		sessionExpiresAtMillis, retainUntilMillis, snapshot.CellID, snapshot.DirectoryVersion, snapshot.ActiveFenceCount)
}

func sessionControlIntentToken(fence sessionControlSessionFence, target sessionControlTargetAuthority,
	sessionExpiresAtMillis, retainUntilMillis int64, snapshot sessionControlFenceSnapshot) *string {
	owner, _ := sessionControlOwnerFromTarget(target, nil, sessionControlOwnerReady)
	return sessionControlIntentTokenWithOwner(fence, target, owner, sessionExpiresAtMillis, retainUntilMillis, snapshot)
}

func sessionControlDirectoryCondition(snapshot sessionControlFenceSnapshot) types.TransactWriteItem {
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		Key:                      sessionControlFenceDirectoryKey(snapshot.CellID),
		ConditionExpression:      aws.String("kind = :kind AND schema_version = :schema AND cell_id = :cell_id AND #version = :version AND active_fence_count = :count AND admission_blocked = :admission_blocked AND overflow_close_count = :overflow_close_count AND overflow_leader_event_id = :leader_event_id AND overflow_leader_prepared_directory_version = :leader_prepared_version AND overflow_leader_selected_directory_version = :leader_selected_version AND attribute_not_exists(#ttl)"),
		ExpressionAttributeNames: map[string]string{"#version": "version", "#ttl": "ttl"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":kind":                    &types.AttributeValueMemberS{Value: sessionControlFenceDirectoryKind},
			":schema":                  &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlFenceSchema)},
			":cell_id":                 &types.AttributeValueMemberS{Value: snapshot.CellID},
			":version":                 &types.AttributeValueMemberN{Value: fmt.Sprint(snapshot.DirectoryVersion)},
			":count":                   &types.AttributeValueMemberN{Value: fmt.Sprint(snapshot.ActiveFenceCount)},
			":admission_blocked":       &types.AttributeValueMemberBOOL{Value: snapshot.AdmissionBlocked},
			":overflow_close_count":    &types.AttributeValueMemberN{Value: fmt.Sprint(snapshot.OverflowCloseCount)},
			":leader_event_id":         &types.AttributeValueMemberS{Value: snapshot.OverflowLeaderEventID},
			":leader_prepared_version": &types.AttributeValueMemberN{Value: fmt.Sprint(snapshot.OverflowLeaderPreparedDirectoryVersion)},
			":leader_selected_version": &types.AttributeValueMemberN{Value: fmt.Sprint(snapshot.OverflowLeaderSelectedDirectoryVersion)},
		},
	}}
}

func requireSessionControlAdmissionDirectory(directory sessionControlFenceDirectory, snapshot sessionControlFenceSnapshot) error {
	if directory.AdmissionBlocked {
		return errSessionControlAdmissionBlocked
	}
	if directory.Version != snapshot.DirectoryVersion ||
		directory.ActiveFenceCount != snapshot.ActiveFenceCount ||
		directory.AdmissionBlocked != snapshot.AdmissionBlocked ||
		directory.OverflowCloseCount != snapshot.OverflowCloseCount ||
		directory.OverflowLeaderEventID != snapshot.OverflowLeaderEventID ||
		directory.OverflowLeaderPreparedDirectoryVersion != snapshot.OverflowLeaderPreparedDirectoryVersion ||
		directory.OverflowLeaderSelectedDirectoryVersion != snapshot.OverflowLeaderSelectedDirectoryVersion {
		return errSessionControlSessionFenceStale
	}
	return nil
}

func (s *dynamoSessionControlStore) getSessionItem(ctx context.Context, sessionID uint64) (*sessionControlSessionAuthority, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true), Key: sessionControlSessionDynamoKey(sessionID),
	})
	if err != nil {
		return nil, fmt.Errorf("session-control session strong read: %w", err)
	}
	if len(result.Item) == 0 {
		return nil, errSessionControlSessionNotFound
	}
	if _, hasTTL := result.Item["ttl"]; hasTTL {
		return nil, errSessionControlSessionCorrupt
	}
	var row sessionControlSessionRow
	if err := attributevalue.UnmarshalMap(result.Item, &row); err != nil {
		return nil, fmt.Errorf("%w: decode session row", errSessionControlSessionCorrupt)
	}
	authority, err := sessionControlSessionFromRow(row, sessionID)
	if err != nil {
		return nil, err
	}
	canonicalRow, err := sessionControlSessionToRow(authority)
	if err != nil {
		return nil, errSessionControlSessionCorrupt
	}
	canonicalItem, err := attributevalue.MarshalMap(canonicalRow)
	if err != nil || !reflect.DeepEqual(canonicalItem, result.Item) {
		return nil, errSessionControlSessionCorrupt
	}
	return &authority, nil
}

func (s *dynamoSessionControlStore) getAgentSessionMembership(ctx context.Context, candidate sessionControlSessionCandidate) (*sessionControlSessionCandidate, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true), Key: sessionControlAgentSessionDynamoKey(candidate),
	})
	if err != nil {
		return nil, fmt.Errorf("session-control agent membership strong read: %w", err)
	}
	if len(result.Item) == 0 {
		return nil, errSessionControlSessionNotFound
	}
	if _, hasTTL := result.Item["ttl"]; hasTTL {
		return nil, errSessionControlSessionCorrupt
	}
	var row sessionControlSessionMembershipRow
	if err := attributevalue.UnmarshalMap(result.Item, &row); err != nil {
		return nil, fmt.Errorf("%w: decode agent membership", errSessionControlSessionCorrupt)
	}
	decoded, err := sessionControlSessionMembershipFromRow(row, candidate)
	if err != nil {
		return nil, err
	}
	return &decoded, nil
}

// ResolveExactSessionForClose strongly binds a public, server-assigned session
// ID to the authenticated agent and assigned cell. The immutable membership is
// required alongside the canonical SESSION row so a torn or forged base row
// can never become client-close authority.
func (s *dynamoSessionControlStore) ResolveExactSessionForClose(ctx context.Context,
	selector sessionControlExactRetirementSelector,
) (*sessionControlSessionAuthority, error) {
	if !validSessionControlExactRetirementSelector(selector) {
		return nil, errors.New("invalid exact session close selector")
	}
	current, err := s.getSessionItem(ctx, selector.SessionID)
	if err != nil {
		return nil, err
	}
	if current == nil || !sessionControlExactRetirementSelectorMatchesCandidate(selector, current.Candidate) {
		return nil, errSessionControlSessionNotFound
	}
	membership, err := s.getAgentSessionMembership(ctx, current.Candidate)
	if err != nil {
		if errors.Is(err, errSessionControlSessionNotFound) {
			return nil, errSessionControlSessionCorrupt
		}
		return nil, err
	}
	if membership == nil || *membership != current.Candidate {
		return nil, errSessionControlSessionCorrupt
	}
	if current.State == sessionControlSessionStateClosed {
		expectedEventID := sessionControlExactCloseEventID(current.Candidate)
		if current.CloseEventID != expectedEventID {
			return nil, errSessionControlSessionCorrupt
		}
		closed, closedErr := s.getCloseClosed(ctx, expectedEventID)
		if closedErr != nil {
			if errors.Is(closedErr, errSessionControlTerminalNotFound) {
				return nil, errSessionControlSessionCorrupt
			}
			return nil, closedErr
		}
		if closed == nil || closed.SessionAfter != *current ||
			!sessionControlCloseClosedMatchesCandidate(*closed, current.Candidate, expectedEventID) {
			return nil, errSessionControlSessionCorrupt
		}
	}
	copy := *current
	return &copy, nil
}

func (s *dynamoSessionControlStore) classifyReservation(ctx context.Context, candidate sessionControlSessionCandidate) (*sessionControlSessionAuthority, error) {
	for range sessionControlSessionReadAttempts {
		before, beforeErr := s.getSessionItem(ctx, candidate.SessionID)
		if beforeErr != nil && !errors.Is(beforeErr, errSessionControlSessionNotFound) {
			return nil, beforeErr
		}
		membership, membershipErr := s.getAgentSessionMembership(ctx, candidate)
		if membershipErr != nil && !errors.Is(membershipErr, errSessionControlSessionNotFound) {
			return nil, membershipErr
		}
		after, afterErr := s.getSessionItem(ctx, candidate.SessionID)
		if afterErr != nil && !errors.Is(afterErr, errSessionControlSessionNotFound) {
			return nil, afterErr
		}

		beforeFound := beforeErr == nil
		afterFound := afterErr == nil
		if beforeFound != afterFound || (beforeFound && *before != *after) {
			continue
		}
		if !afterFound {
			if membershipErr == nil {
				return nil, errSessionControlSessionCorrupt
			}
			return nil, errSessionControlSessionNotFound
		}
		if !sessionControlSessionCandidateEqual(after.Candidate, candidate) {
			return nil, errSessionControlSessionCollision
		}
		if membershipErr != nil || membership == nil || *membership != candidate {
			return nil, errSessionControlSessionCorrupt
		}
		return after, nil
	}
	return nil, errSessionControlSessionConflict
}

func (s *dynamoSessionControlStore) readSessionDirectory(ctx context.Context, cellID string) (*sessionControlFenceDirectory, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true), Key: sessionControlFenceDirectoryKey(cellID),
	})
	if err != nil {
		return nil, fmt.Errorf("session-control directory strong read: %w", err)
	}
	if len(result.Item) == 0 {
		return nil, errSessionControlSessionFenceStale
	}
	directory, err := sessionControlFenceDirectoryFromItem(result.Item, cellID)
	if err != nil {
		return nil, errSessionControlSessionCorrupt
	}
	return &directory, nil
}

// DynamoDB may commit a transaction even when its response loses the race with
// the operation deadline. Result classification therefore gets a fresh,
// bounded context that deliberately does not inherit caller cancellation.
func (s *dynamoSessionControlStore) sessionResultContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), s.timeout())
}

// ReserveSession atomically orders a caller-chosen numeric session ID against
// the exact active-fence directory cursor. The immutable agent membership is a
// base-table row; no GSI or TTL participates in correctness.
func (s *dynamoSessionControlStore) ReserveSession(ctx context.Context, candidate sessionControlSessionCandidate,
	snapshot sessionControlFenceSnapshot) (*sessionControlSessionAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlSessionCandidate(candidate) {
		return nil, errors.New("invalid session-control session candidate")
	}
	if err := validateSessionControlFenceSnapshot(snapshot, candidate.CellID); err != nil {
		return nil, err
	}
	if err := evaluateSessionControlFences(candidate, snapshot); err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	if current, err := s.classifyReservation(opCtx, candidate); err == nil {
		directory, readErr := s.readSessionDirectory(opCtx, candidate.CellID)
		if readErr != nil {
			return nil, readErr
		}
		if readErr = requireSessionControlAdmissionDirectory(*directory, snapshot); readErr != nil {
			return nil, readErr
		}
		if current.State == sessionControlSessionStateClosing || current.State == sessionControlSessionStateClosed {
			return nil, errSessionControlSessionFenceDenied
		}
		return current, nil
	} else if !errors.Is(err, errSessionControlSessionNotFound) {
		return nil, err
	}
	planned, err := planSessionControlReservation(candidate, snapshot)
	if err != nil {
		return nil, err
	}
	sessionRow, _ := sessionControlSessionToRow(planned)
	membershipRow, _ := sessionControlSessionMembershipToRow(candidate)
	sessionItem, err := attributevalue.MarshalMap(sessionRow)
	if err != nil {
		return nil, fmt.Errorf("marshal session-control session: %w", err)
	}
	membershipItem, err := attributevalue.MarshalMap(membershipRow)
	if err != nil {
		return nil, fmt.Errorf("marshal session-control membership: %w", err)
	}
	directoryWrite := sessionControlDirectoryCondition(snapshot)
	directoryWrite.ConditionCheck.TableName = aws.String(s.tableName)
	_, writeErr := s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: sessionControlReservationToken(candidate, snapshot),
		TransactItems: []types.TransactWriteItem{
			directoryWrite,
			{Put: &types.Put{TableName: aws.String(s.tableName), Item: sessionItem, ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}},
			{Put: &types.Put{TableName: aws.String(s.tableName), Item: membershipItem, ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}},
		},
	})
	if writeErr == nil {
		return &planned, nil
	}
	operationErr := opCtx.Err()
	resultCtx, resultCancel := s.sessionResultContext(ctx)
	defer resultCancel()
	if current, classifyErr := s.classifyReservation(resultCtx, candidate); classifyErr == nil {
		directory, readErr := s.readSessionDirectory(resultCtx, candidate.CellID)
		if readErr != nil {
			return nil, readErr
		}
		if readErr = requireSessionControlAdmissionDirectory(*directory, snapshot); readErr != nil {
			return nil, readErr
		}
		if current.State == sessionControlSessionStateClosing || current.State == sessionControlSessionStateClosed {
			return nil, errSessionControlSessionFenceDenied
		}
		return current, nil
	} else if !errors.Is(classifyErr, errSessionControlSessionNotFound) {
		return nil, classifyErr
	}
	directory, directoryErr := s.readSessionDirectory(resultCtx, candidate.CellID)
	if directoryErr != nil {
		return nil, directoryErr
	}
	if err := requireSessionControlAdmissionDirectory(*directory, snapshot); err != nil {
		return nil, err
	}
	var canceled *types.TransactionCanceledException
	if errors.As(writeErr, &canceled) {
		return nil, errSessionControlSessionConflict
	}
	if operationErr != nil {
		return nil, fmt.Errorf("reserve session-control session: %w", operationErr)
	}
	return nil, fmt.Errorf("reserve session-control session: %w", writeErr)
}

func (s *dynamoSessionControlStore) getIntentItem(ctx context.Context, candidate sessionControlSessionCandidate,
	target sessionControlTargetAuthority, reverse bool) (*sessionControlSessionIntent, error) {
	key := sessionControlSessionIntentDynamoKey(candidate.SessionID, target)
	if reverse {
		key = sessionControlTargetSessionDynamoKey(candidate, target)
	}
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true), Key: key,
	})
	if err != nil {
		return nil, fmt.Errorf("session-control intent strong read: %w", err)
	}
	if len(result.Item) == 0 {
		return nil, errSessionControlSessionNotFound
	}
	if _, hasTTL := result.Item["ttl"]; hasTTL {
		return nil, errSessionControlSessionCorrupt
	}
	if !sessionControlIntentTargetReadinessAttributesPresent(result.Item) {
		return nil, errSessionControlSessionCorrupt
	}
	var row sessionControlSessionIntentRow
	if err := attributevalue.UnmarshalMap(result.Item, &row); err != nil {
		return nil, errSessionControlSessionCorrupt
	}
	intent, err := sessionControlIntentFromRow(row, reverse)
	if err != nil {
		return nil, err
	}
	return &intent, nil
}

func (s *dynamoSessionControlStore) inspectIntent(ctx context.Context, request sessionControlSessionIntent,
	fence sessionControlSessionFence) (*sessionControlSessionAuthority, *sessionControlSessionIntent, error) {
	for range sessionControlSessionReadAttempts {
		before, beforeErr := s.classifyReservation(ctx, fence.Candidate)
		if beforeErr != nil && !errors.Is(beforeErr, errSessionControlSessionNotFound) {
			return nil, nil, beforeErr
		}
		forward, forwardErr := s.getIntentItem(ctx, fence.Candidate, request.Target, false)
		reverse, reverseErr := s.getIntentItem(ctx, fence.Candidate, request.Target, true)
		if forwardErr != nil && !errors.Is(forwardErr, errSessionControlSessionNotFound) {
			return nil, nil, forwardErr
		}
		if reverseErr != nil && !errors.Is(reverseErr, errSessionControlSessionNotFound) {
			return nil, nil, reverseErr
		}
		after, afterErr := s.classifyReservation(ctx, fence.Candidate)
		if afterErr != nil && !errors.Is(afterErr, errSessionControlSessionNotFound) {
			return nil, nil, afterErr
		}

		beforeFound := beforeErr == nil
		afterFound := afterErr == nil
		if beforeFound != afterFound || (beforeFound && *before != *after) {
			continue
		}
		forwardFound := forwardErr == nil
		reverseFound := reverseErr == nil
		if !beforeFound {
			if forwardFound || reverseFound {
				return nil, nil, errSessionControlSessionCorrupt
			}
			return nil, nil, errSessionControlSessionNotFound
		}
		if forwardFound != reverseFound {
			return nil, nil, errSessionControlSessionCorrupt
		}
		if !forwardFound {
			return after, nil, nil
		}
		if !sessionControlIntentExact(*forward, *reverse) ||
			forward.SessionVersion > after.Version || after.TargetCount == 0 ||
			forward.SessionExpiresAtMillis != after.SessionExpiresAtMillis ||
			forward.RetainUntilMillis > after.RetainUntilMillis ||
			forward.PreparedDirectoryVersion < after.ReservedDirectoryVersion ||
			(forward.PreparedDirectoryVersion == after.ReservedDirectoryVersion &&
				forward.PreparedActiveFenceCount != after.ReservedActiveFenceCount) {
			return nil, nil, errSessionControlSessionCorrupt
		}
		if !sessionControlIntentSameProcess(*forward, request) {
			return nil, nil, errSessionControlSessionConflict
		}
		return after, forward, nil
	}
	return nil, nil, errSessionControlSessionConflict
}

func sessionControlActiveTargetCondition(target sessionControlTargetAuthority) types.TransactWriteItem {
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		Key:                      sessionControlTargetDynamoKey(target.key()),
		ConditionExpression:      aws.String("kind = :kind AND schema_version = :schema AND ac_id = :ac_id AND public_key = :public_key AND boot_id = :boot_id AND flush_generation = :flush_generation AND control_cell_id = :cell_id AND #state = :state AND #version = :version AND authority_version = :authority_version AND counted_active_slot = :counted AND activated_control_version = :cursor AND ready_control_version = :ready_cursor AND aak_enqueued_at_ms = :aak_enqueued_at AND aak_transaction_id = :aak_transaction_id AND created_at_ms = :created_at AND prepared_at_ms = :prepared_at AND updated_at_ms = :updated_at AND attribute_not_exists(retired_at_ms) AND attribute_not_exists(#ttl)"),
		ExpressionAttributeNames: map[string]string{"#state": "state", "#version": "version", "#ttl": "ttl"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":kind":               &types.AttributeValueMemberS{Value: sessionControlTargetKind},
			":schema":             &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlTargetSchema)},
			":ac_id":              &types.AttributeValueMemberS{Value: target.ACID},
			":public_key":         &types.AttributeValueMemberS{Value: target.PublicKey},
			":boot_id":            &types.AttributeValueMemberS{Value: target.BootID},
			":flush_generation":   &types.AttributeValueMemberN{Value: fmt.Sprint(target.FlushGeneration)},
			":cell_id":            &types.AttributeValueMemberS{Value: target.ControlCellID},
			":state":              &types.AttributeValueMemberS{Value: string(sessionControlTargetActive)},
			":version":            &types.AttributeValueMemberN{Value: fmt.Sprint(target.Version)},
			":authority_version":  &types.AttributeValueMemberN{Value: fmt.Sprint(target.AuthorityVersion)},
			":counted":            &types.AttributeValueMemberBOOL{Value: true},
			":cursor":             &types.AttributeValueMemberN{Value: fmt.Sprint(target.ActivatedControlVersion)},
			":ready_cursor":       &types.AttributeValueMemberN{Value: fmt.Sprint(target.ReadyControlVersion)},
			":aak_enqueued_at":    &types.AttributeValueMemberN{Value: fmt.Sprint(target.AAKEnqueuedAtMillis)},
			":aak_transaction_id": &types.AttributeValueMemberN{Value: fmt.Sprint(target.AAKTransactionID)},
			":created_at":         &types.AttributeValueMemberN{Value: fmt.Sprint(target.CreatedAtMillis)},
			":prepared_at":        &types.AttributeValueMemberN{Value: fmt.Sprint(target.PreparedAtMillis)},
			":updated_at":         &types.AttributeValueMemberN{Value: fmt.Sprint(target.UpdatedAtMillis)},
		},
	}}
}

func sessionControlSessionUpdate(fence sessionControlSessionFence, planned sessionControlSessionAuthority, enforceCapacity bool) types.TransactWriteItem {
	candidate := fence.Candidate
	condition := "kind = :kind AND schema_version = :schema AND cell_id = :cell_id AND agent_public_key = :agent_public_key AND session_id = :session_id AND issued_at_ms = :issued_at AND reservation_deadline_ms = :reservation_deadline AND run_id = :run_id AND run_attempt = :run_attempt AND #state = :state AND #version = :version AND target_count = :count AND retain_until_ms = :retain AND reserved_directory_version = :reserved_version AND reserved_active_fence_count = :reserved_count AND due_shard = :due_shard AND due_sort = :due_sort AND attribute_not_exists(ack_enqueued_at_ms) AND attribute_not_exists(close_event_id) AND attribute_not_exists(close_prepared_directory_version) AND attribute_not_exists(#ttl)"
	if fence.TargetCount == 0 {
		condition += " AND attribute_not_exists(session_expires_at_ms)"
	} else {
		condition += " AND session_expires_at_ms = :session_expires_at"
	}
	if enforceCapacity {
		condition += " AND target_count < :capacity"
	}
	write := types.TransactWriteItem{Update: &types.Update{
		Key:                      sessionControlSessionDynamoKey(candidate.SessionID),
		UpdateExpression:         aws.String("SET #version = :next_version, target_count = :next_count, session_expires_at_ms = :next_session_expires_at, retain_until_ms = :next_retain"),
		ConditionExpression:      aws.String(condition),
		ExpressionAttributeNames: map[string]string{"#state": "state", "#version": "version", "#ttl": "ttl"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":kind":                    &types.AttributeValueMemberS{Value: sessionControlSessionMetaKind},
			":schema":                  &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlSessionSchema)},
			":cell_id":                 &types.AttributeValueMemberS{Value: candidate.CellID},
			":agent_public_key":        &types.AttributeValueMemberS{Value: candidate.AgentPublicKey},
			":session_id":              &types.AttributeValueMemberN{Value: fmt.Sprint(candidate.SessionID)},
			":issued_at":               &types.AttributeValueMemberN{Value: fmt.Sprint(candidate.IssuedAtMillis)},
			":reservation_deadline":    &types.AttributeValueMemberN{Value: fmt.Sprint(candidate.ReservationDeadlineMillis)},
			":run_id":                  &types.AttributeValueMemberS{Value: candidate.RunID},
			":run_attempt":             &types.AttributeValueMemberN{Value: fmt.Sprint(candidate.RunAttempt)},
			":state":                   &types.AttributeValueMemberS{Value: sessionControlSessionStateReserved},
			":version":                 &types.AttributeValueMemberN{Value: fmt.Sprint(fence.Version)},
			":count":                   &types.AttributeValueMemberN{Value: fmt.Sprint(fence.TargetCount)},
			":retain":                  &types.AttributeValueMemberN{Value: fmt.Sprint(fence.RetainUntilMillis)},
			":reserved_version":        &types.AttributeValueMemberN{Value: fmt.Sprint(fence.ReservedDirectoryVersion)},
			":reserved_count":          &types.AttributeValueMemberN{Value: fmt.Sprint(fence.ReservedActiveFenceCount)},
			":due_shard":               &types.AttributeValueMemberS{Value: sessionControlSessionDueShard(candidate)},
			":due_sort":                &types.AttributeValueMemberS{Value: sessionControlSessionDueSort(candidate)},
			":capacity":                &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlSessionMaxTargets)},
			":next_version":            &types.AttributeValueMemberN{Value: fmt.Sprint(planned.Version)},
			":next_count":              &types.AttributeValueMemberN{Value: fmt.Sprint(planned.TargetCount)},
			":next_session_expires_at": &types.AttributeValueMemberN{Value: fmt.Sprint(planned.SessionExpiresAtMillis)},
			":next_retain":             &types.AttributeValueMemberN{Value: fmt.Sprint(planned.RetainUntilMillis)},
		},
	}}
	if fence.TargetCount > 0 {
		write.Update.ExpressionAttributeValues[":session_expires_at"] = &types.AttributeValueMemberN{Value: fmt.Sprint(fence.SessionExpiresAtMillis)}
	}
	if !enforceCapacity {
		delete(write.Update.ExpressionAttributeValues, ":capacity")
	}
	return write
}

func sessionControlIntentCASPut(tableName string, current, next sessionControlSessionIntent, reverse bool) (types.TransactWriteItem, error) {
	currentRow, err := sessionControlIntentToRow(current, reverse)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	nextRow, err := sessionControlIntentToRow(next, reverse)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(nextRow)
	if err != nil {
		return types.TransactWriteItem{}, fmt.Errorf("marshal extended session-control intent: %w", err)
	}
	values := map[string]types.AttributeValue{
		":kind":                       &types.AttributeValueMemberS{Value: currentRow.Kind},
		":schema":                     &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.SchemaVersion)},
		":cell_id":                    &types.AttributeValueMemberS{Value: currentRow.CellID},
		":agent_public_key":           &types.AttributeValueMemberS{Value: currentRow.AgentPublicKey},
		":session_id":                 &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.SessionID)},
		":issued_at":                  &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.IssuedAtMillis)},
		":reservation_deadline":       &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.ReservationDeadlineMillis)},
		":run_id":                     &types.AttributeValueMemberS{Value: currentRow.RunID},
		":run_attempt":                &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.RunAttempt)},
		":target_ac_id":               &types.AttributeValueMemberS{Value: currentRow.TargetACID},
		":target_public_key":          &types.AttributeValueMemberS{Value: currentRow.TargetPublicKey},
		":target_boot_id":             &types.AttributeValueMemberS{Value: currentRow.TargetBootID},
		":target_flush_generation":    &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.TargetFlushGeneration)},
		":target_version":             &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.TargetVersion)},
		":target_authority_version":   &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.TargetAuthorityVersion)},
		":target_counted":             &types.AttributeValueMemberBOOL{Value: currentRow.TargetCountedActiveSlot},
		":target_cell_id":             &types.AttributeValueMemberS{Value: currentRow.TargetControlCellID},
		":target_cursor":              &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.TargetActivatedCursor)},
		":target_ready_cursor":        &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.TargetReadyCursor)},
		":target_aak_enqueued_at":     &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.TargetAAKEnqueuedAtMillis)},
		":target_aak_transaction_id":  &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.TargetAAKTransactionID)},
		":target_created_at":          &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.TargetCreatedAtMillis)},
		":target_prepared_at":         &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.TargetPreparedAtMillis)},
		":target_updated_at":          &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.TargetUpdatedAtMillis)},
		":state":                      &types.AttributeValueMemberS{Value: currentRow.State},
		":session_version":            &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.SessionVersion)},
		":session_expires_at":         &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.SessionExpiresAtMillis)},
		":retain_until":               &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.RetainUntilMillis)},
		":prepared_directory_version": &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.PreparedDirectoryVersion)},
		":prepared_active_count":      &types.AttributeValueMemberN{Value: fmt.Sprint(currentRow.PreparedActiveFenceCount)},
	}
	condition := "kind = :kind AND schema_version = :schema AND cell_id = :cell_id AND agent_public_key = :agent_public_key AND session_id = :session_id AND issued_at_ms = :issued_at AND reservation_deadline_ms = :reservation_deadline AND run_id = :run_id AND run_attempt = :run_attempt AND target_ac_id = :target_ac_id AND target_public_key = :target_public_key AND target_boot_id = :target_boot_id AND target_flush_generation = :target_flush_generation AND target_version = :target_version AND target_authority_version = :target_authority_version AND target_counted_active_slot = :target_counted AND target_control_cell_id = :target_cell_id AND target_activated_cursor = :target_cursor AND target_ready_cursor = :target_ready_cursor AND target_aak_enqueued_at_ms = :target_aak_enqueued_at AND target_aak_transaction_id = :target_aak_transaction_id AND target_created_at_ms = :target_created_at AND target_prepared_at_ms = :target_prepared_at AND target_updated_at_ms = :target_updated_at AND attribute_not_exists(target_retired_at_ms) AND #state = :state AND session_version = :session_version AND session_expires_at_ms = :session_expires_at AND retain_until_ms = :retain_until AND prepared_directory_version = :prepared_directory_version AND prepared_active_fence_count = :prepared_active_count AND attribute_not_exists(#ttl)"
	return types.TransactWriteItem{Put: &types.Put{
		TableName: aws.String(tableName), Item: item, ConditionExpression: aws.String(condition),
		ExpressionAttributeNames: map[string]string{"#state": "state", "#ttl": "ttl"}, ExpressionAttributeValues: values,
	}}, nil
}

// PrepareSessionIntent durably records that one exact authority-ready ACTIVE
// target may have admitted the session before any network send. Denial, timeout, or an
// ambiguous response never deletes this intent; recovery must close it.
func (s *dynamoSessionControlStore) PrepareSessionIntent(ctx context.Context, fence sessionControlSessionFence,
	target sessionControlTargetAuthority, sessionExpiresAtMillis, retainUntilMillis int64,
	snapshot sessionControlFenceSnapshot) (*sessionControlSessionIntentPreparation, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlSessionFence(fence) || validateSessionControlTargetAuthority(target) != nil ||
		!target.ready() || target.ControlCellID != fence.Candidate.CellID ||
		sessionExpiresAtMillis <= fence.Candidate.IssuedAtMillis || retainUntilMillis < sessionExpiresAtMillis {
		return nil, errors.New("invalid session-control session intent")
	}
	if target.Version >= ^uint64(0)-1 || target.AuthorityVersion >= ^uint64(0)-1 {
		return nil, errSessionControlSessionCorrupt
	}
	if err := validateSessionControlFenceSnapshot(snapshot, fence.Candidate.CellID); err != nil {
		return nil, err
	}
	if err := evaluateSessionControlFences(fence.Candidate, snapshot); err != nil {
		return nil, err
	}
	if err := validateSessionControlSnapshotAfterReservation(fence, snapshot); err != nil {
		return nil, err
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	if now.UnixMilli() >= sessionExpiresAtMillis {
		return nil, errSessionControlSessionFenceDenied
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	owner, ownerErr := s.getOwner(opCtx, target.ControlCellID, target.ACID, target.PublicKey)
	if ownerErr != nil {
		return nil, ownerErr
	}
	if owner.Phase != sessionControlOwnerReady || owner.PendingCount != 0 ||
		!owner.exactTarget(target, sessionControlOwnerReady) {
		return nil, errSessionControlSessionTargetConflict
	}
	admittedOwner, err := planSessionControlOwnerAdmission(*owner, now.UnixMilli())
	if err != nil {
		return nil, errSessionControlSessionTargetConflict
	}
	request := sessionControlSessionIntent{
		Session: fence.Candidate, Target: target, Owner: *owner, State: sessionControlSessionIntentMayBeAdmitted,
		SessionVersion: fence.Version + 1, SessionExpiresAtMillis: sessionExpiresAtMillis,
		RetainUntilMillis: retainUntilMillis, PreparedDirectoryVersion: snapshot.DirectoryVersion,
		PreparedActiveFenceCount: snapshot.ActiveFenceCount,
	}
	currentSession, existingIntent, inspectErr := s.inspectIntent(opCtx, request, fence)
	if inspectErr != nil {
		return nil, inspectErr
	}
	if currentSession.State != sessionControlSessionStateReserved {
		if currentSession.State == sessionControlSessionStateClosing {
			return nil, errSessionControlSessionFenceDenied
		}
		return nil, errSessionControlSessionConflict
	}
	if currentSession.fence() != fence {
		if currentSession.TargetCount >= sessionControlSessionMaxTargets && existingIntent == nil {
			return nil, errSessionControlSessionCapacity
		}
		return nil, errSessionControlSessionConflict
	}
	currentTarget, err := s.getTarget(opCtx, target.key())
	if err != nil {
		if errors.Is(err, errSessionControlTargetNotFound) {
			return nil, errSessionControlSessionTargetConflict
		}
		if errors.Is(err, errSessionControlTargetCorrupt) {
			return nil, errSessionControlSessionCorrupt
		}
		return nil, err
	}
	if *currentTarget != target || currentTarget.State != sessionControlTargetActive {
		return nil, errSessionControlSessionTargetConflict
	}
	var (
		planned   sessionControlSessionIntentPreparation
		extension bool
	)
	if existingIntent == nil {
		planned, err = planSessionControlIntent(fence, target, sessionExpiresAtMillis, retainUntilMillis, snapshot)
	} else {
		extension = true
		planned, err = planSessionControlIntentExtension(*currentSession, fence, *existingIntent, target,
			sessionExpiresAtMillis, retainUntilMillis, snapshot)
	}
	if err != nil {
		return nil, err
	}
	planned.Intent.Owner = *owner
	if validateSessionControlSessionIntent(planned.Intent) != nil {
		return nil, errSessionControlSessionCorrupt
	}

	directoryWrite := sessionControlDirectoryCondition(snapshot)
	directoryWrite.ConditionCheck.TableName = aws.String(s.tableName)
	targetWrite := sessionControlActiveTargetCondition(target)
	targetWrite.ConditionCheck.TableName = aws.String(s.tableName)
	ownerWrite, err := sessionControlOwnerReplace(s.tableName, *owner, admittedOwner)
	if err != nil {
		return nil, err
	}
	sessionWrite := sessionControlSessionUpdate(fence, planned.Session, !extension)
	sessionWrite.Update.TableName = aws.String(s.tableName)
	var forwardWrite, reverseWrite types.TransactWriteItem
	if extension {
		forwardWrite, err = sessionControlIntentCASPut(s.tableName, *existingIntent, planned.Intent, false)
		if err == nil {
			reverseWrite, err = sessionControlIntentCASPut(s.tableName, *existingIntent, planned.Intent, true)
		}
	} else {
		forwardRow, rowErr := sessionControlIntentToRow(planned.Intent, false)
		if rowErr != nil {
			return nil, rowErr
		}
		reverseRow, rowErr := sessionControlIntentToRow(planned.Intent, true)
		if rowErr != nil {
			return nil, rowErr
		}
		forwardItem, marshalErr := attributevalue.MarshalMap(forwardRow)
		if marshalErr != nil {
			return nil, fmt.Errorf("marshal session-control intent: %w", marshalErr)
		}
		reverseItem, marshalErr := attributevalue.MarshalMap(reverseRow)
		if marshalErr != nil {
			return nil, fmt.Errorf("marshal session-control reverse intent: %w", marshalErr)
		}
		forwardWrite = types.TransactWriteItem{Put: &types.Put{TableName: aws.String(s.tableName), Item: forwardItem, ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}}
		reverseWrite = types.TransactWriteItem{Put: &types.Put{TableName: aws.String(s.tableName), Item: reverseItem, ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}}
	}
	if err != nil {
		return nil, err
	}
	_, writeErr := s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: sessionControlIntentTokenWithOwner(fence, target, *owner, sessionExpiresAtMillis, retainUntilMillis, snapshot),
		TransactItems: []types.TransactWriteItem{
			directoryWrite, targetWrite, ownerWrite, sessionWrite,
			forwardWrite, reverseWrite,
		},
	})
	if writeErr == nil {
		return &planned, nil
	}
	operationErr := opCtx.Err()
	resultCtx, resultCancel := s.sessionResultContext(ctx)
	defer resultCancel()
	currentSession, existingIntent, inspectErr = s.inspectIntent(resultCtx, request, fence)
	if inspectErr != nil {
		return nil, inspectErr
	}
	directory, directoryErr := s.readSessionDirectory(resultCtx, fence.Candidate.CellID)
	if directoryErr != nil {
		return nil, directoryErr
	}
	if err := requireSessionControlAdmissionDirectory(*directory, snapshot); err != nil {
		return nil, err
	}
	currentTarget, targetErr := s.getTarget(resultCtx, target.key())
	if targetErr != nil {
		if errors.Is(targetErr, errSessionControlTargetNotFound) {
			return nil, errSessionControlSessionTargetConflict
		}
		if errors.Is(targetErr, errSessionControlTargetCorrupt) {
			return nil, errSessionControlSessionCorrupt
		}
		return nil, targetErr
	}
	if *currentTarget != target || currentTarget.State != sessionControlTargetActive {
		return nil, errSessionControlSessionTargetConflict
	}
	currentOwner, ownerErr := s.getOwner(resultCtx, target.ControlCellID, target.ACID, target.PublicKey)
	if ownerErr != nil {
		return nil, ownerErr
	}
	if *currentOwner != admittedOwner {
		if currentOwner.Phase == sessionControlOwnerReady && currentOwner.PendingCount == 0 &&
			currentOwner.exactTarget(target, sessionControlOwnerReady) {
			if *currentOwner == *owner && operationErr != nil {
				return nil, fmt.Errorf("prepare session-control intent: %w", operationErr)
			}
			return nil, errSessionControlSessionConflict
		}
		return nil, errSessionControlSessionTargetConflict
	}
	if currentSession.State != sessionControlSessionStateReserved {
		if currentSession.State == sessionControlSessionStateClosing {
			return nil, errSessionControlSessionFenceDenied
		}
		return nil, errSessionControlSessionConflict
	}
	if existingIntent != nil && existingIntent.SessionVersion > fence.Version &&
		sessionControlIntentSatisfies(*existingIntent, request) {
		return &sessionControlSessionIntentPreparation{Session: *currentSession, Intent: *existingIntent}, nil
	}
	if !extension && currentSession.TargetCount >= sessionControlSessionMaxTargets {
		return nil, errSessionControlSessionCapacity
	}
	if operationErr != nil {
		return nil, fmt.Errorf("prepare session-control intent: %w", operationErr)
	}
	return nil, errSessionControlSessionConflict
}

// PrepareSessionIntentCurrent derives the intent CAS fence from durable state
// instead of trusting a caller-held session version. One aggregate deadline
// covers bounded retries when concurrent fanout advances the session header.
func (s *dynamoSessionControlStore) PrepareSessionIntentCurrent(ctx context.Context,
	candidate sessionControlSessionCandidate, target sessionControlTargetAuthority,
	sessionExpiresAtMillis, retainUntilMillis int64,
	snapshot sessionControlFenceSnapshot) (*sessionControlSessionIntentPreparation, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlSessionCandidate(candidate) {
		return nil, errors.New("invalid session-control session candidate")
	}
	if validateSessionControlTargetAuthority(target) != nil || !target.ready() ||
		target.ControlCellID != candidate.CellID {
		return nil, errors.New("invalid session-control session intent target")
	}
	if err := evaluateSessionControlFences(candidate, snapshot); err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	for range sessionControlSessionFanoutAttempts {
		current, err := s.classifyReservation(opCtx, candidate)
		if err != nil {
			return nil, err
		}
		if current.State == sessionControlSessionStateClosing {
			return nil, errSessionControlSessionFenceDenied
		}
		if current.State != sessionControlSessionStateReserved {
			return nil, errSessionControlSessionConflict
		}
		if current.TargetCount > 0 && current.SessionExpiresAtMillis != sessionExpiresAtMillis {
			return nil, errSessionControlSessionConflict
		}
		now, err := s.now()
		if err != nil {
			return nil, err
		}
		if now.UnixMilli() >= sessionExpiresAtMillis {
			return nil, errSessionControlSessionFenceDenied
		}
		prepared, err := s.PrepareSessionIntent(opCtx, current.fence(), target,
			sessionExpiresAtMillis, retainUntilMillis, snapshot)
		if err == nil {
			return prepared, nil
		}
		if !errors.Is(err, errSessionControlSessionConflict) {
			return nil, err
		}
		if opCtx.Err() != nil {
			return nil, fmt.Errorf("prepare current session-control intent: %w", opCtx.Err())
		}
	}
	return nil, errSessionControlSessionConflict
}

// VerifySession returns the exact current RESERVED authority for a forwarded
// receiver's audit/diagnostic boundary. It does not mint a caller-held write
// fence: PrepareSessionIntentCurrent independently reloads and linearizes the
// later AOP mutation. ACK_ENQUEUED and CLOSING are both terminal here.
func (s *dynamoSessionControlStore) VerifySession(ctx context.Context, candidate sessionControlSessionCandidate,
	snapshot sessionControlFenceSnapshot) (*sessionControlSessionAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if err := evaluateSessionControlFences(candidate, snapshot); err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	current, err := s.classifyReservation(opCtx, candidate)
	if err != nil {
		return nil, err
	}
	if current.State == sessionControlSessionStateClosing {
		return nil, errSessionControlSessionFenceDenied
	}
	if current.State != sessionControlSessionStateReserved {
		return nil, errSessionControlSessionFenceDenied
	}
	if err := validateSessionControlSnapshotAfterReservation(current.fence(), snapshot); err != nil {
		return nil, err
	}
	directory, err := s.readSessionDirectory(opCtx, candidate.CellID)
	if err != nil {
		return nil, err
	}
	if err := requireSessionControlAdmissionDirectory(*directory, snapshot); err != nil {
		return nil, err
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	deadlineMillis := current.SessionExpiresAtMillis
	if current.TargetCount == 0 {
		deadlineMillis = current.Candidate.ReservationDeadlineMillis
	}
	if now.UnixMilli() >= deadlineMillis {
		return nil, errSessionControlSessionFenceDenied
	}
	return current, nil
}

func sessionControlSessionAckUpdate(current sessionControlSessionAuthority, ackEnqueuedAtMillis int64) types.TransactWriteItem {
	candidate := current.Candidate
	return types.TransactWriteItem{Update: &types.Update{
		Key:                 sessionControlSessionDynamoKey(candidate.SessionID),
		UpdateExpression:    aws.String("SET #state = :next_state, ack_enqueued_at_ms = :ack_enqueued_at REMOVE due_shard, due_sort"),
		ConditionExpression: aws.String("kind = :kind AND schema_version = :schema AND cell_id = :cell_id AND agent_public_key = :agent_public_key AND session_id = :session_id AND issued_at_ms = :issued_at AND reservation_deadline_ms = :reservation_deadline AND run_id = :run_id AND run_attempt = :run_attempt AND #state = :state AND #version = :version AND target_count = :count AND session_expires_at_ms = :session_expires_at AND retain_until_ms = :retain AND reserved_directory_version = :reserved_version AND reserved_active_fence_count = :reserved_count AND due_shard = :due_shard AND due_sort = :due_sort AND attribute_not_exists(ack_enqueued_at_ms) AND attribute_not_exists(close_event_id) AND attribute_not_exists(close_prepared_directory_version) AND attribute_not_exists(#ttl)"),
		ExpressionAttributeNames: map[string]string{
			"#state": "state", "#version": "version", "#ttl": "ttl",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":kind":                 &types.AttributeValueMemberS{Value: sessionControlSessionMetaKind},
			":schema":               &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlSessionSchema)},
			":cell_id":              &types.AttributeValueMemberS{Value: candidate.CellID},
			":agent_public_key":     &types.AttributeValueMemberS{Value: candidate.AgentPublicKey},
			":session_id":           &types.AttributeValueMemberN{Value: fmt.Sprint(candidate.SessionID)},
			":issued_at":            &types.AttributeValueMemberN{Value: fmt.Sprint(candidate.IssuedAtMillis)},
			":reservation_deadline": &types.AttributeValueMemberN{Value: fmt.Sprint(candidate.ReservationDeadlineMillis)},
			":run_id":               &types.AttributeValueMemberS{Value: candidate.RunID},
			":run_attempt":          &types.AttributeValueMemberN{Value: fmt.Sprint(candidate.RunAttempt)},
			":state":                &types.AttributeValueMemberS{Value: sessionControlSessionStateReserved},
			":next_state":           &types.AttributeValueMemberS{Value: sessionControlSessionStateAckEnqueued},
			":ack_enqueued_at":      &types.AttributeValueMemberN{Value: fmt.Sprint(ackEnqueuedAtMillis)},
			":version":              &types.AttributeValueMemberN{Value: fmt.Sprint(current.Version)},
			":count":                &types.AttributeValueMemberN{Value: fmt.Sprint(current.TargetCount)},
			":session_expires_at":   &types.AttributeValueMemberN{Value: fmt.Sprint(current.SessionExpiresAtMillis)},
			":retain":               &types.AttributeValueMemberN{Value: fmt.Sprint(current.RetainUntilMillis)},
			":reserved_version":     &types.AttributeValueMemberN{Value: fmt.Sprint(current.ReservedDirectoryVersion)},
			":reserved_count":       &types.AttributeValueMemberN{Value: fmt.Sprint(current.ReservedActiveFenceCount)},
			":due_shard":            &types.AttributeValueMemberS{Value: sessionControlSessionDueShard(candidate)},
			":due_sort":             &types.AttributeValueMemberS{Value: sessionControlSessionDueSort(candidate)},
		},
	}}
}

func sessionControlSessionAckSatisfies(latest, reserved sessionControlSessionAuthority) bool {
	return latest.State == sessionControlSessionStateAckEnqueued &&
		latest.Candidate == reserved.Candidate && latest.Version == reserved.Version &&
		latest.TargetCount == reserved.TargetCount &&
		latest.SessionExpiresAtMillis == reserved.SessionExpiresAtMillis &&
		latest.RetainUntilMillis == reserved.RetainUntilMillis &&
		latest.ReservedDirectoryVersion == reserved.ReservedDirectoryVersion &&
		latest.ReservedActiveFenceCount == reserved.ReservedActiveFenceCount
}

// MarkSessionAckEnqueued records the durable ACK publication boundary. Session
// version remains the intent/count CAS; the monotonic state CAS is an
// independent fence and deliberately does not increment version.
func (s *dynamoSessionControlStore) MarkSessionAckEnqueued(ctx context.Context,
	candidate sessionControlSessionCandidate, snapshot sessionControlFenceSnapshot) (*sessionControlSessionAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if err := evaluateSessionControlFences(candidate, snapshot); err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	current, err := s.classifyReservation(opCtx, candidate)
	if err != nil {
		return nil, err
	}
	if err := validateSessionControlSnapshotAfterReservation(current.fence(), snapshot); err != nil {
		return nil, err
	}
	if current.State == sessionControlSessionStateClosing {
		return nil, errSessionControlSessionFenceDenied
	}
	if current.State == sessionControlSessionStateAckEnqueued {
		directory, readErr := s.readSessionDirectory(opCtx, candidate.CellID)
		if readErr != nil {
			return nil, readErr
		}
		if err := requireSessionControlAdmissionDirectory(*directory, snapshot); err != nil {
			return nil, err
		}
		return current, nil
	}
	if current.State != sessionControlSessionStateReserved || current.TargetCount == 0 {
		return nil, errSessionControlSessionConflict
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	if now.UnixMilli() >= current.SessionExpiresAtMillis {
		return nil, errSessionControlSessionFenceDenied
	}
	ackEnqueuedAtMillis := now.UnixMilli()
	if ackEnqueuedAtMillis < current.Candidate.IssuedAtMillis {
		ackEnqueuedAtMillis = current.Candidate.IssuedAtMillis
	}
	planned := *current
	planned.State = sessionControlSessionStateAckEnqueued
	planned.AckEnqueuedAtMillis = ackEnqueuedAtMillis
	if err := validateSessionControlSessionAuthority(planned); err != nil {
		return nil, err
	}
	directoryWrite := sessionControlDirectoryCondition(snapshot)
	directoryWrite.ConditionCheck.TableName = aws.String(s.tableName)
	sessionWrite := sessionControlSessionAckUpdate(*current, ackEnqueuedAtMillis)
	sessionWrite.Update.TableName = aws.String(s.tableName)
	_, writeErr := s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: sessionControlSessionToken("ack", candidate.CellID, candidate.AgentPublicKey,
			candidate.SessionID, candidate.IssuedAtMillis, current.Version, current.TargetCount,
			current.SessionExpiresAtMillis, current.RetainUntilMillis, ackEnqueuedAtMillis,
			snapshot.DirectoryVersion, snapshot.ActiveFenceCount),
		TransactItems: []types.TransactWriteItem{directoryWrite, sessionWrite},
	})
	if writeErr == nil {
		return &planned, nil
	}
	operationErr := opCtx.Err()
	resultCtx, resultCancel := s.sessionResultContext(ctx)
	defer resultCancel()
	directory, directoryErr := s.readSessionDirectory(resultCtx, candidate.CellID)
	if directoryErr != nil {
		return nil, directoryErr
	}
	if err := requireSessionControlAdmissionDirectory(*directory, snapshot); err != nil {
		return nil, err
	}
	latest, classifyErr := s.classifyReservation(resultCtx, candidate)
	if classifyErr != nil {
		return nil, classifyErr
	}
	if sessionControlSessionAckSatisfies(*latest, *current) {
		return latest, nil
	}
	if latest.State == sessionControlSessionStateClosing {
		return nil, errSessionControlSessionFenceDenied
	}
	if operationErr != nil {
		return nil, fmt.Errorf("mark session-control ACK enqueued: %w", operationErr)
	}
	return nil, errSessionControlSessionConflict
}
