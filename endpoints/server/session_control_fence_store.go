package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/OpenNHP/opennhp/nhp/common"
)

const (
	sessionControlFenceDirectoryKind  = "fence_directory"
	sessionControlFenceMetaKind       = "fence_meta"
	sessionControlFenceActiveKind     = "active_fence"
	sessionControlFenceDirectorySK    = "DIRECTORY"
	sessionControlFenceMetaSK         = "META"
	sessionControlFenceActiveSKPrefix = "FENCE#"
	sessionControlFenceSchema         = uint64(2)
	sessionControlFenceAttempts       = 4
	sessionControlFenceQueryLimit     = int32(100)
	sessionControlFenceActiveLimit    = 1_024
	sessionControlFenceReplayHorizon  = 125 * time.Second
	sessionControlFenceIdempotencyTTL = 24 * time.Hour
	sessionControlFenceSelectorExact  = "exact"
	sessionControlFenceSelectorAgent  = "agent"
	sessionControlFenceSelectorRun    = "run"
)

var (
	errSessionControlFenceNotFound      = errors.New("session-control fence not found")
	errSessionControlFenceConflict      = errors.New("session-control fence changed concurrently")
	errSessionControlFenceRetired       = errors.New("session-control fence is retired")
	errSessionControlFenceCorrupt       = errors.New("session-control fence authority is malformed")
	errSessionControlFenceCapacity      = errors.New("session-control fence directory capacity is exhausted")
	errSessionControlFenceReplayHorizon = errors.New("session-control fence replay horizon has not elapsed")
	errSessionControlAdmissionBlocked   = errors.New("session-control admission is blocked by pending close work")
)

type sessionControlFenceSelector struct {
	Scope               string
	AgentPublicKey      string
	SessionID           uint64
	SessionIssuedMillis int64
	IssuedThroughMillis int64
	RunID               string
	RunAttempt          uint64
}

type sessionControlFenceCandidate struct {
	CellID   string
	EventID  string
	Selector sessionControlFenceSelector
}

type sessionControlFenceState string

const (
	sessionControlFencePreparing sessionControlFenceState = "preparing"
	sessionControlFenceConverged sessionControlFenceState = "converged"
	sessionControlFenceRetired   sessionControlFenceState = "retired"
)

type sessionControlFenceAuthority struct {
	CellID                   string
	EventID                  string
	Selector                 sessionControlFenceSelector
	SelectorDigest           string
	PreparedDirectoryVersion uint64
	State                    sessionControlFenceState
	Version                  uint64
	CreatedAtMillis          int64
	PreparedAtMillis         int64
	ConvergedAtMillis        int64
	ReplayNotBeforeMillis    int64
	UpdatedAtMillis          int64
	RetiredAtMillis          int64
	ExpiresAt                int64
}

type sessionControlFenceDirectory struct {
	CellID                                 string
	Version                                uint64
	ActiveFenceCount                       uint64
	AdmissionBlocked                       bool
	OverflowCloseCount                     uint64
	OverflowLeaderEventID                  string
	OverflowLeaderPreparedDirectoryVersion uint64
	OverflowLeaderSelectedDirectoryVersion uint64
	CreatedAtMillis                        int64
	UpdatedAtMillis                        int64
}

type sessionControlFenceSnapshot struct {
	CellID                                 string
	DirectoryVersion                       uint64
	ActiveFenceCount                       uint64
	AdmissionBlocked                       bool
	OverflowCloseCount                     uint64
	OverflowLeaderEventID                  string
	OverflowLeaderPreparedDirectoryVersion uint64
	OverflowLeaderSelectedDirectoryVersion uint64
	Fences                                 []sessionControlFenceAuthority
}

// sessionControlActiveFenceStore is intentionally isolated from the
// UdpServer-facing sessionControlStore until AOL admission is wired in a later
// change. Retirement is omitted because permanent authority removal belongs to
// a separately reviewed lower-level path.
type sessionControlActiveFenceStore interface {
	PrepareFence(context.Context, sessionControlFenceCandidate) (*sessionControlFenceAuthority, error)
	MarkFenceConverged(context.Context, sessionControlFenceAuthority) (*sessionControlFenceAuthority, error)
	SnapshotActiveFences(context.Context, string) (*sessionControlFenceSnapshot, error)
}

type sessionControlFenceDirectoryRow struct {
	PK                                     string `dynamodbav:"pk"`
	SK                                     string `dynamodbav:"sk"`
	Kind                                   string `dynamodbav:"kind"`
	SchemaVersion                          uint64 `dynamodbav:"schema_version"`
	CellID                                 string `dynamodbav:"cell_id"`
	Version                                uint64 `dynamodbav:"version"`
	ActiveFenceCount                       uint64 `dynamodbav:"active_fence_count"`
	AdmissionBlocked                       bool   `dynamodbav:"admission_blocked"`
	OverflowCloseCount                     uint64 `dynamodbav:"overflow_close_count"`
	OverflowLeaderEventID                  string `dynamodbav:"overflow_leader_event_id"`
	OverflowLeaderPreparedDirectoryVersion uint64 `dynamodbav:"overflow_leader_prepared_directory_version"`
	OverflowLeaderSelectedDirectoryVersion uint64 `dynamodbav:"overflow_leader_selected_directory_version"`
	CreatedAtMillis                        int64  `dynamodbav:"created_at_ms"`
	UpdatedAtMillis                        int64  `dynamodbav:"updated_at_ms"`
}

type sessionControlFenceRow struct {
	PK                       string                   `dynamodbav:"pk"`
	SK                       string                   `dynamodbav:"sk"`
	Kind                     string                   `dynamodbav:"kind"`
	SchemaVersion            uint64                   `dynamodbav:"schema_version"`
	CellID                   string                   `dynamodbav:"cell_id"`
	EventID                  string                   `dynamodbav:"event_id"`
	SelectorScope            string                   `dynamodbav:"selector_scope"`
	AgentPublicKey           string                   `dynamodbav:"agent_public_key"`
	SessionID                uint64                   `dynamodbav:"session_id,omitempty"`
	SessionIssuedMillis      int64                    `dynamodbav:"session_issued_ms,omitempty"`
	IssuedThroughMillis      int64                    `dynamodbav:"issued_through_ms,omitempty"`
	RunID                    string                   `dynamodbav:"run_id,omitempty"`
	RunAttempt               uint64                   `dynamodbav:"run_attempt,omitempty"`
	SelectorDigest           string                   `dynamodbav:"selector_digest"`
	PreparedDirectoryVersion uint64                   `dynamodbav:"prepared_directory_version"`
	State                    sessionControlFenceState `dynamodbav:"state"`
	Version                  uint64                   `dynamodbav:"version"`
	CreatedAtMillis          int64                    `dynamodbav:"created_at_ms"`
	PreparedAtMillis         int64                    `dynamodbav:"prepared_at_ms"`
	ConvergedAtMillis        int64                    `dynamodbav:"converged_at_ms,omitempty"`
	ReplayNotBeforeMillis    int64                    `dynamodbav:"replay_not_before_ms,omitempty"`
	UpdatedAtMillis          int64                    `dynamodbav:"updated_at_ms"`
	RetiredAtMillis          int64                    `dynamodbav:"retired_at_ms,omitempty"`
	ExpiresAt                int64                    `dynamodbav:"expires_at,omitempty"`
}

func validSessionControlCellID(cellID string) bool {
	if len(cellID) == 0 || len(cellID) > 32 || cellID[0] == '-' || cellID[len(cellID)-1] == '-' {
		return false
	}
	previousDash := false
	for i := range len(cellID) {
		character := cellID[i]
		isDash := character == '-'
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && !isDash {
			return false
		}
		if isDash && previousDash {
			return false
		}
		previousDash = isDash
	}
	return true
}

func validSessionControlFenceEventID(eventID string) bool {
	return common.ValidNHPACBootID(eventID)
}

func validateSessionControlFenceSelector(selector sessionControlFenceSelector) error {
	if !common.ValidNHPAgentPublicKey(selector.AgentPublicKey) {
		return errors.New("invalid session-control fence agent public key")
	}
	switch selector.Scope {
	case sessionControlFenceSelectorExact:
		if selector.SessionID == 0 || selector.SessionIssuedMillis <= 0 || selector.IssuedThroughMillis != 0 ||
			selector.RunID != "" || selector.RunAttempt != 0 {
			return errors.New("invalid exact session-control fence selector")
		}
	case sessionControlFenceSelectorAgent:
		if selector.IssuedThroughMillis <= 0 || selector.SessionID != 0 || selector.SessionIssuedMillis != 0 ||
			selector.RunID != "" || selector.RunAttempt != 0 {
			return errors.New("invalid agent session-control fence selector")
		}
	case sessionControlFenceSelectorRun:
		if common.ValidateAgentKnockRunID(selector.RunID) != nil || selector.RunAttempt == 0 ||
			selector.SessionID != 0 || selector.SessionIssuedMillis != 0 || selector.IssuedThroughMillis != 0 {
			return errors.New("invalid run session-control fence selector")
		}
	default:
		return errors.New("invalid session-control fence selector scope")
	}
	return nil
}

func sessionControlFenceSelectorDigest(selector sessionControlFenceSelector) (string, error) {
	if err := validateSessionControlFenceSelector(selector); err != nil {
		return "", err
	}
	canonical := fmt.Sprintf("v1\x00%s\x00%s\x00%d\x00%d\x00%d\x00%s\x00%d",
		selector.Scope, selector.AgentPublicKey, selector.SessionID, selector.SessionIssuedMillis,
		selector.IssuedThroughMillis, selector.RunID, selector.RunAttempt)
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:]), nil
}

func validSessionControlFenceCandidate(candidate sessionControlFenceCandidate) bool {
	if !validSessionControlCellID(candidate.CellID) || !validSessionControlFenceEventID(candidate.EventID) {
		return false
	}
	return validateSessionControlFenceSelector(candidate.Selector) == nil
}

func validateSessionControlFenceAuthority(fence sessionControlFenceAuthority) error {
	if !validSessionControlFenceCandidate(sessionControlFenceCandidate{CellID: fence.CellID, EventID: fence.EventID, Selector: fence.Selector}) ||
		fence.Version == 0 || fence.Version == ^uint64(0) || fence.PreparedDirectoryVersion == 0 ||
		fence.CreatedAtMillis <= 0 || fence.PreparedAtMillis != fence.CreatedAtMillis ||
		fence.UpdatedAtMillis < fence.PreparedAtMillis {
		return errSessionControlFenceCorrupt
	}
	digest, err := sessionControlFenceSelectorDigest(fence.Selector)
	if err != nil || digest != fence.SelectorDigest {
		return errSessionControlFenceCorrupt
	}
	switch fence.State {
	case sessionControlFencePreparing:
		if fence.ConvergedAtMillis != 0 || fence.ReplayNotBeforeMillis != 0 || fence.RetiredAtMillis != 0 || fence.ExpiresAt != 0 {
			return errSessionControlFenceCorrupt
		}
	case sessionControlFenceConverged:
		if fence.ConvergedAtMillis < fence.PreparedAtMillis || fence.ReplayNotBeforeMillis < fence.ConvergedAtMillis+sessionControlFenceReplayHorizon.Milliseconds() ||
			fence.RetiredAtMillis != 0 || fence.ExpiresAt != 0 {
			return errSessionControlFenceCorrupt
		}
	case sessionControlFenceRetired:
		if fence.ConvergedAtMillis < fence.PreparedAtMillis || fence.ReplayNotBeforeMillis < fence.ConvergedAtMillis+sessionControlFenceReplayHorizon.Milliseconds() ||
			fence.RetiredAtMillis < fence.ReplayNotBeforeMillis ||
			fence.ExpiresAt != fence.RetiredAtMillis/1_000+int64(sessionControlFenceIdempotencyTTL/time.Second) {
			return errSessionControlFenceCorrupt
		}
	default:
		return errSessionControlFenceCorrupt
	}
	return nil
}

func validateSessionControlFenceDirectory(directory sessionControlFenceDirectory) error {
	if !validSessionControlCellID(directory.CellID) || directory.Version == 0 || directory.Version == ^uint64(0) ||
		directory.ActiveFenceCount > sessionControlFenceActiveLimit ||
		directory.OverflowCloseCount >= ^uint64(0)-1 || directory.AdmissionBlocked != (directory.OverflowCloseCount > 0) ||
		directory.CreatedAtMillis <= 0 || directory.UpdatedAtMillis < directory.CreatedAtMillis {
		return errSessionControlFenceCorrupt
	}
	if directory.OverflowLeaderEventID == "" {
		if directory.OverflowLeaderPreparedDirectoryVersion != 0 || directory.OverflowLeaderSelectedDirectoryVersion != 0 {
			return errSessionControlFenceCorrupt
		}
	} else if !validSessionControlFenceEventID(directory.OverflowLeaderEventID) || !directory.AdmissionBlocked ||
		directory.OverflowCloseCount == 0 || directory.OverflowLeaderPreparedDirectoryVersion == 0 ||
		directory.OverflowLeaderSelectedDirectoryVersion <= directory.OverflowLeaderPreparedDirectoryVersion ||
		directory.OverflowLeaderSelectedDirectoryVersion > directory.Version {
		return errSessionControlFenceCorrupt
	}
	return nil
}

func sessionControlFenceHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func sessionControlFenceDirectoryPK(cellID string) string {
	return "CONTROL#" + sessionControlFenceHash(cellID)
}
func sessionControlFenceActivePK(cellID string) string {
	return "ACTIVE#" + sessionControlFenceHash(cellID)
}
func sessionControlFenceMetaPK(eventID string) string {
	return "EVENT#" + sessionControlFenceHash(eventID)
}
func sessionControlFenceActiveSK(eventID string) string {
	return sessionControlFenceActiveSKPrefix + eventID
}

func sessionControlFenceDirectoryKey(cellID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlFenceDirectoryPK(cellID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlFenceDirectorySK},
	}
}

func sessionControlFenceMetaKey(eventID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlFenceMetaPK(eventID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlFenceMetaSK},
	}
}

func sessionControlFenceActiveKey(cellID, eventID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlFenceActivePK(cellID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlFenceActiveSK(eventID)},
	}
}

func sessionControlFenceDirectoryToRow(directory sessionControlFenceDirectory) (sessionControlFenceDirectoryRow, error) {
	if err := validateSessionControlFenceDirectory(directory); err != nil {
		return sessionControlFenceDirectoryRow{}, err
	}
	return sessionControlFenceDirectoryRow{
		PK:                                     sessionControlFenceDirectoryPK(directory.CellID),
		SK:                                     sessionControlFenceDirectorySK,
		Kind:                                   sessionControlFenceDirectoryKind,
		SchemaVersion:                          sessionControlFenceSchema,
		CellID:                                 directory.CellID,
		Version:                                directory.Version,
		ActiveFenceCount:                       directory.ActiveFenceCount,
		AdmissionBlocked:                       directory.AdmissionBlocked,
		OverflowCloseCount:                     directory.OverflowCloseCount,
		OverflowLeaderEventID:                  directory.OverflowLeaderEventID,
		OverflowLeaderPreparedDirectoryVersion: directory.OverflowLeaderPreparedDirectoryVersion,
		OverflowLeaderSelectedDirectoryVersion: directory.OverflowLeaderSelectedDirectoryVersion,
		CreatedAtMillis:                        directory.CreatedAtMillis,
		UpdatedAtMillis:                        directory.UpdatedAtMillis,
	}, nil
}

func sessionControlFenceDirectoryFromRow(row sessionControlFenceDirectoryRow, expectedCellID string) (sessionControlFenceDirectory, error) {
	directory := sessionControlFenceDirectory{
		CellID:                                 row.CellID,
		Version:                                row.Version,
		ActiveFenceCount:                       row.ActiveFenceCount,
		AdmissionBlocked:                       row.AdmissionBlocked,
		OverflowCloseCount:                     row.OverflowCloseCount,
		OverflowLeaderEventID:                  row.OverflowLeaderEventID,
		OverflowLeaderPreparedDirectoryVersion: row.OverflowLeaderPreparedDirectoryVersion,
		OverflowLeaderSelectedDirectoryVersion: row.OverflowLeaderSelectedDirectoryVersion,
		CreatedAtMillis:                        row.CreatedAtMillis,
		UpdatedAtMillis:                        row.UpdatedAtMillis,
	}
	if row.Kind != sessionControlFenceDirectoryKind || row.SchemaVersion != sessionControlFenceSchema ||
		row.PK != sessionControlFenceDirectoryPK(row.CellID) || row.SK != sessionControlFenceDirectorySK || row.CellID != expectedCellID {
		return sessionControlFenceDirectory{}, errSessionControlFenceCorrupt
	}
	if err := validateSessionControlFenceDirectory(directory); err != nil {
		return sessionControlFenceDirectory{}, err
	}
	return directory, nil
}

// sessionControlFenceDirectoryFromItem is the single fail-closed decoder for
// the CONTROL/DIRECTORY authority. All count and latch attributes are required
// even when their canonical value is zero; otherwise an incomplete row could
// silently decode as an open, empty directory.
func sessionControlFenceDirectoryFromItem(item map[string]types.AttributeValue, expectedCellID string) (sessionControlFenceDirectory, error) {
	if _, ok := item["active_fence_count"].(*types.AttributeValueMemberN); !ok {
		return sessionControlFenceDirectory{}, fmt.Errorf("%w: missing or invalid active_fence_count", errSessionControlFenceCorrupt)
	}
	if _, ok := item["admission_blocked"].(*types.AttributeValueMemberBOOL); !ok {
		return sessionControlFenceDirectory{}, fmt.Errorf("%w: missing or invalid admission_blocked", errSessionControlFenceCorrupt)
	}
	if _, ok := item["overflow_close_count"].(*types.AttributeValueMemberN); !ok {
		return sessionControlFenceDirectory{}, fmt.Errorf("%w: missing or invalid overflow_close_count", errSessionControlFenceCorrupt)
	}
	if _, ok := item["overflow_leader_event_id"].(*types.AttributeValueMemberS); !ok {
		return sessionControlFenceDirectory{}, fmt.Errorf("%w: missing or invalid overflow_leader_event_id", errSessionControlFenceCorrupt)
	}
	for _, name := range []string{"overflow_leader_prepared_directory_version", "overflow_leader_selected_directory_version"} {
		if _, ok := item[name].(*types.AttributeValueMemberN); !ok {
			return sessionControlFenceDirectory{}, fmt.Errorf("%w: missing or invalid %s", errSessionControlFenceCorrupt, name)
		}
	}
	if _, hasTTL := item["ttl"]; hasTTL {
		return sessionControlFenceDirectory{}, fmt.Errorf("%w: directory has TTL", errSessionControlFenceCorrupt)
	}
	var row sessionControlFenceDirectoryRow
	if err := attributevalue.UnmarshalMap(item, &row); err != nil {
		return sessionControlFenceDirectory{}, fmt.Errorf("%w: decode directory", errSessionControlFenceCorrupt)
	}
	return sessionControlFenceDirectoryFromRow(row, expectedCellID)
}

func sessionControlFenceToRow(fence sessionControlFenceAuthority, active bool) (sessionControlFenceRow, error) {
	if err := validateSessionControlFenceAuthority(fence); err != nil {
		return sessionControlFenceRow{}, err
	}
	if active && fence.State == sessionControlFenceRetired {
		return sessionControlFenceRow{}, errSessionControlFenceCorrupt
	}
	row := sessionControlFenceRow{
		Kind:                     sessionControlFenceMetaKind,
		SchemaVersion:            sessionControlFenceSchema,
		CellID:                   fence.CellID,
		EventID:                  fence.EventID,
		SelectorScope:            fence.Selector.Scope,
		AgentPublicKey:           fence.Selector.AgentPublicKey,
		SessionID:                fence.Selector.SessionID,
		SessionIssuedMillis:      fence.Selector.SessionIssuedMillis,
		IssuedThroughMillis:      fence.Selector.IssuedThroughMillis,
		RunID:                    fence.Selector.RunID,
		RunAttempt:               fence.Selector.RunAttempt,
		SelectorDigest:           fence.SelectorDigest,
		PreparedDirectoryVersion: fence.PreparedDirectoryVersion,
		State:                    fence.State,
		Version:                  fence.Version,
		CreatedAtMillis:          fence.CreatedAtMillis,
		PreparedAtMillis:         fence.PreparedAtMillis,
		ConvergedAtMillis:        fence.ConvergedAtMillis,
		ReplayNotBeforeMillis:    fence.ReplayNotBeforeMillis,
		UpdatedAtMillis:          fence.UpdatedAtMillis,
		RetiredAtMillis:          fence.RetiredAtMillis,
		ExpiresAt:                fence.ExpiresAt,
	}
	if active {
		row.PK = sessionControlFenceActivePK(fence.CellID)
		row.SK = sessionControlFenceActiveSK(fence.EventID)
		row.Kind = sessionControlFenceActiveKind
	} else {
		row.PK = sessionControlFenceMetaPK(fence.EventID)
		row.SK = sessionControlFenceMetaSK
	}
	return row, nil
}

func sessionControlFenceFromRow(row sessionControlFenceRow, active bool, expectedCellID, expectedEventID string) (sessionControlFenceAuthority, error) {
	fence := sessionControlFenceAuthority{
		CellID:  row.CellID,
		EventID: row.EventID,
		Selector: sessionControlFenceSelector{
			Scope:               row.SelectorScope,
			AgentPublicKey:      row.AgentPublicKey,
			SessionID:           row.SessionID,
			SessionIssuedMillis: row.SessionIssuedMillis,
			IssuedThroughMillis: row.IssuedThroughMillis,
			RunID:               row.RunID,
			RunAttempt:          row.RunAttempt,
		},
		SelectorDigest:           row.SelectorDigest,
		PreparedDirectoryVersion: row.PreparedDirectoryVersion,
		State:                    row.State,
		Version:                  row.Version,
		CreatedAtMillis:          row.CreatedAtMillis,
		PreparedAtMillis:         row.PreparedAtMillis,
		ConvergedAtMillis:        row.ConvergedAtMillis,
		ReplayNotBeforeMillis:    row.ReplayNotBeforeMillis,
		UpdatedAtMillis:          row.UpdatedAtMillis,
		RetiredAtMillis:          row.RetiredAtMillis,
		ExpiresAt:                row.ExpiresAt,
	}
	expectedKind := sessionControlFenceMetaKind
	expectedPK := sessionControlFenceMetaPK(row.EventID)
	expectedSK := sessionControlFenceMetaSK
	if active {
		expectedKind = sessionControlFenceActiveKind
		expectedPK = sessionControlFenceActivePK(row.CellID)
		expectedSK = sessionControlFenceActiveSK(row.EventID)
	}
	if row.Kind != expectedKind || row.SchemaVersion != sessionControlFenceSchema || row.PK != expectedPK || row.SK != expectedSK ||
		row.CellID != expectedCellID || row.EventID != expectedEventID {
		return sessionControlFenceAuthority{}, errSessionControlFenceCorrupt
	}
	if err := validateSessionControlFenceAuthority(fence); err != nil || (active && fence.State == sessionControlFenceRetired) {
		return sessionControlFenceAuthority{}, errSessionControlFenceCorrupt
	}
	return fence, nil
}

func sessionControlFenceSameIdentity(left, right sessionControlFenceAuthority) bool {
	return left.CellID == right.CellID && left.EventID == right.EventID &&
		left.Selector == right.Selector && left.SelectorDigest == right.SelectorDigest &&
		left.PreparedDirectoryVersion == right.PreparedDirectoryVersion &&
		left.CreatedAtMillis == right.CreatedAtMillis && left.PreparedAtMillis == right.PreparedAtMillis
}

func sessionControlFenceTransactionToken(action string, parts ...any) *string {
	hasher := sha256.New()
	_, _ = fmt.Fprintf(hasher, "v1\x00%s", action)
	for _, part := range parts {
		_, _ = fmt.Fprintf(hasher, "\x00%v", part)
	}
	digest := hasher.Sum(nil)
	token := "sf-" + action + "-" + hex.EncodeToString(digest[:12])
	return aws.String(token)
}

func sessionControlFenceTransitionCondition(fence sessionControlFenceAuthority) string {
	base := "kind = :kind AND schema_version = :schema AND cell_id = :cell_id AND event_id = :event_id AND selector_digest = :selector_digest AND prepared_directory_version = :prepared_directory_version AND created_at_ms = :created_at AND prepared_at_ms = :prepared_at AND selector_scope = :selector_scope AND agent_public_key = :agent_public_key AND #state = :state AND #version = :version"
	switch fence.Selector.Scope {
	case sessionControlFenceSelectorExact:
		return base + " AND session_id = :session_id AND session_issued_ms = :session_issued_ms AND attribute_not_exists(issued_through_ms) AND attribute_not_exists(run_id) AND attribute_not_exists(run_attempt)"
	case sessionControlFenceSelectorAgent:
		return base + " AND issued_through_ms = :issued_through_ms AND attribute_not_exists(session_id) AND attribute_not_exists(session_issued_ms) AND attribute_not_exists(run_id) AND attribute_not_exists(run_attempt)"
	case sessionControlFenceSelectorRun:
		return base + " AND run_id = :run_id AND run_attempt = :run_attempt AND attribute_not_exists(session_id) AND attribute_not_exists(session_issued_ms) AND attribute_not_exists(issued_through_ms)"
	default:
		return base + " AND attribute_exists(__invalid_selector_scope__)"
	}
}

func sessionControlFenceTransitionValues(fence sessionControlFenceAuthority, kind string) map[string]types.AttributeValue {
	values := map[string]types.AttributeValue{
		":kind":                       &types.AttributeValueMemberS{Value: kind},
		":schema":                     &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlFenceSchema)},
		":cell_id":                    &types.AttributeValueMemberS{Value: fence.CellID},
		":event_id":                   &types.AttributeValueMemberS{Value: fence.EventID},
		":selector_digest":            &types.AttributeValueMemberS{Value: fence.SelectorDigest},
		":prepared_directory_version": &types.AttributeValueMemberN{Value: fmt.Sprint(fence.PreparedDirectoryVersion)},
		":created_at":                 &types.AttributeValueMemberN{Value: fmt.Sprint(fence.CreatedAtMillis)},
		":prepared_at":                &types.AttributeValueMemberN{Value: fmt.Sprint(fence.PreparedAtMillis)},
		":selector_scope":             &types.AttributeValueMemberS{Value: fence.Selector.Scope},
		":agent_public_key":           &types.AttributeValueMemberS{Value: fence.Selector.AgentPublicKey},
		":state":                      &types.AttributeValueMemberS{Value: string(fence.State)},
		":version":                    &types.AttributeValueMemberN{Value: fmt.Sprint(fence.Version)},
	}
	switch fence.Selector.Scope {
	case sessionControlFenceSelectorExact:
		values[":session_id"] = &types.AttributeValueMemberN{Value: fmt.Sprint(fence.Selector.SessionID)}
		values[":session_issued_ms"] = &types.AttributeValueMemberN{Value: fmt.Sprint(fence.Selector.SessionIssuedMillis)}
	case sessionControlFenceSelectorAgent:
		values[":issued_through_ms"] = &types.AttributeValueMemberN{Value: fmt.Sprint(fence.Selector.IssuedThroughMillis)}
	case sessionControlFenceSelectorRun:
		values[":run_id"] = &types.AttributeValueMemberS{Value: fence.Selector.RunID}
		values[":run_attempt"] = &types.AttributeValueMemberN{Value: fmt.Sprint(fence.Selector.RunAttempt)}
	}
	return values
}

func sessionControlFenceDirectoryConditionValues(directory sessionControlFenceDirectory) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		":kind":                             &types.AttributeValueMemberS{Value: sessionControlFenceDirectoryKind},
		":schema":                           &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlFenceSchema)},
		":cell_id":                          &types.AttributeValueMemberS{Value: directory.CellID},
		":version":                          &types.AttributeValueMemberN{Value: fmt.Sprint(directory.Version)},
		":count":                            &types.AttributeValueMemberN{Value: fmt.Sprint(directory.ActiveFenceCount)},
		":admission_blocked":                &types.AttributeValueMemberBOOL{Value: directory.AdmissionBlocked},
		":overflow_close_count":             &types.AttributeValueMemberN{Value: fmt.Sprint(directory.OverflowCloseCount)},
		":overflow_leader_event_id":         &types.AttributeValueMemberS{Value: directory.OverflowLeaderEventID},
		":overflow_leader_prepared_version": &types.AttributeValueMemberN{Value: fmt.Sprint(directory.OverflowLeaderPreparedDirectoryVersion)},
		":overflow_leader_selected_version": &types.AttributeValueMemberN{Value: fmt.Sprint(directory.OverflowLeaderSelectedDirectoryVersion)},
		":next_version":                     &types.AttributeValueMemberN{Value: fmt.Sprint(directory.Version + 1)},
	}
}

func sessionControlFenceDirectoryCondition() string {
	return "kind = :kind AND schema_version = :schema AND cell_id = :cell_id AND #version = :version AND active_fence_count = :count AND admission_blocked = :admission_blocked AND overflow_close_count = :overflow_close_count AND overflow_leader_event_id = :overflow_leader_event_id AND overflow_leader_prepared_directory_version = :overflow_leader_prepared_version AND overflow_leader_selected_directory_version = :overflow_leader_selected_version AND attribute_not_exists(#ttl)"
}

func (s *dynamoSessionControlStore) getFenceDirectory(ctx context.Context, cellID string) (*sessionControlFenceDirectory, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlCellID(cellID) {
		return nil, errors.New("invalid session-control fence cell id")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	result, err := s.client.GetItem(opCtx, &dynamodb.GetItemInput{
		TableName:      aws.String(s.tableName),
		ConsistentRead: aws.Bool(true),
		Key:            sessionControlFenceDirectoryKey(cellID),
	})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("session-control fence directory strong read: %w", err)
	}
	if len(result.Item) == 0 {
		return nil, errSessionControlFenceNotFound
	}
	directory, err := sessionControlFenceDirectoryFromItem(result.Item, cellID)
	if err != nil {
		return nil, err
	}
	return &directory, nil
}

func (s *dynamoSessionControlStore) ensureFenceDirectory(ctx context.Context, cellID string, now time.Time) (*sessionControlFenceDirectory, error) {
	for range sessionControlFenceAttempts {
		directory, err := s.getFenceDirectory(ctx, cellID)
		if err == nil {
			return directory, nil
		}
		if !errors.Is(err, errSessionControlFenceNotFound) {
			return nil, err
		}
		created := sessionControlFenceDirectory{
			CellID: cellID, Version: 1, CreatedAtMillis: now.UnixMilli(), UpdatedAtMillis: now.UnixMilli(),
		}
		row, rowErr := sessionControlFenceDirectoryToRow(created)
		if rowErr != nil {
			return nil, rowErr
		}
		item, marshalErr := attributevalue.MarshalMap(row)
		if marshalErr != nil {
			return nil, fmt.Errorf("marshal session-control fence directory: %w", marshalErr)
		}
		opCtx, cancel := context.WithTimeout(ctx, s.timeout())
		_, putErr := s.client.PutItem(opCtx, &dynamodb.PutItemInput{
			TableName: aws.String(s.tableName), Item: item,
			ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)"),
		})
		cancel()
		if putErr == nil {
			return &created, nil
		}
		var conditional *types.ConditionalCheckFailedException
		if !errors.As(putErr, &conditional) {
			return nil, fmt.Errorf("persist session-control fence directory: %w", putErr)
		}
	}
	return nil, errSessionControlFenceConflict
}

func (s *dynamoSessionControlStore) getFence(ctx context.Context, cellID, eventID string, active bool) (*sessionControlFenceAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlCellID(cellID) || !validSessionControlFenceEventID(eventID) {
		return nil, errors.New("invalid session-control fence identity")
	}
	key := sessionControlFenceMetaKey(eventID)
	if active {
		key = sessionControlFenceActiveKey(cellID, eventID)
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	result, err := s.client.GetItem(opCtx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true), Key: key,
	})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("session-control fence strong read: %w", err)
	}
	if len(result.Item) == 0 {
		return nil, errSessionControlFenceNotFound
	}
	var row sessionControlFenceRow
	if err := attributevalue.UnmarshalMap(result.Item, &row); err != nil {
		return nil, fmt.Errorf("%w: decode fence row", errSessionControlFenceCorrupt)
	}
	fence, err := sessionControlFenceFromRow(row, active, cellID, eventID)
	if err != nil {
		return nil, err
	}
	return &fence, nil
}

type sessionControlFenceStableState struct {
	Directory sessionControlFenceDirectory
	Meta      *sessionControlFenceAuthority
	Active    *sessionControlFenceAuthority
}

// readStableFenceState uses the directory version as a seqlock around the two
// item reads. Mark/retire always bump that version in the same transaction as
// their row changes, so a mixed pre/post-transaction view is retried rather
// than misclassified as durable corruption.
func (s *dynamoSessionControlStore) readStableFenceState(ctx context.Context, cellID, eventID string) (*sessionControlFenceStableState, error) {
	// One aggregate budget covers every read in every bracket attempt. The
	// individual strong-read helpers inherit this shorter parent deadline.
	readCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	for range sessionControlFenceAttempts {
		before, err := s.getFenceDirectory(readCtx, cellID)
		if err != nil {
			return nil, err
		}
		meta, metaErr := s.getFence(readCtx, cellID, eventID, false)
		if metaErr != nil && !errors.Is(metaErr, errSessionControlFenceNotFound) {
			return nil, metaErr
		}
		active, activeErr := s.getFence(readCtx, cellID, eventID, true)
		if activeErr != nil && !errors.Is(activeErr, errSessionControlFenceNotFound) {
			return nil, activeErr
		}
		after, err := s.getFenceDirectory(readCtx, cellID)
		if err != nil {
			return nil, err
		}
		if *before != *after {
			continue
		}
		if meta == nil {
			if active != nil {
				return nil, errSessionControlFenceCorrupt
			}
			return &sessionControlFenceStableState{Directory: *after}, nil
		}
		if meta.PreparedDirectoryVersion > after.Version {
			return nil, errSessionControlFenceCorrupt
		}
		if meta.State == sessionControlFenceRetired {
			if active != nil {
				return nil, errSessionControlFenceCorrupt
			}
			return &sessionControlFenceStableState{Directory: *after, Meta: meta}, nil
		}
		if active == nil || *active != *meta {
			return nil, errSessionControlFenceCorrupt
		}
		return &sessionControlFenceStableState{Directory: *after, Meta: meta, Active: active}, nil
	}
	return nil, errSessionControlFenceConflict
}

func (s *dynamoSessionControlStore) classifyPreparedFence(ctx context.Context, candidate sessionControlFenceCandidate) (*sessionControlFenceAuthority, error) {
	stable, err := s.readStableFenceState(ctx, candidate.CellID, candidate.EventID)
	if err != nil {
		return nil, err
	}
	meta := stable.Meta
	if meta == nil {
		return nil, errSessionControlFenceNotFound
	}
	digest, _ := sessionControlFenceSelectorDigest(candidate.Selector)
	if meta.CellID != candidate.CellID || meta.EventID != candidate.EventID || meta.Selector != candidate.Selector || meta.SelectorDigest != digest {
		return nil, errSessionControlFenceConflict
	}
	if meta.State == sessionControlFenceRetired {
		return nil, errSessionControlFenceRetired
	}
	if stable.Directory.ActiveFenceCount == 0 {
		return nil, errSessionControlFenceCorrupt
	}
	return meta, nil
}

func (s *dynamoSessionControlStore) PrepareFence(ctx context.Context, candidate sessionControlFenceCandidate) (*sessionControlFenceAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlFenceCandidate(candidate) {
		return nil, errors.New("invalid session-control fence candidate")
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	digest, err := sessionControlFenceSelectorDigest(candidate.Selector)
	if err != nil {
		return nil, err
	}
	prepared := sessionControlFenceAuthority{
		CellID: candidate.CellID, EventID: candidate.EventID, Selector: candidate.Selector,
		SelectorDigest: digest, State: sessionControlFencePreparing, Version: 1,
		CreatedAtMillis: now.UnixMilli(), PreparedAtMillis: now.UnixMilli(), UpdatedAtMillis: now.UnixMilli(),
	}

	for range sessionControlFenceAttempts {
		directory, directoryErr := s.ensureFenceDirectory(ctx, candidate.CellID, now)
		if directoryErr != nil {
			return nil, directoryErr
		}
		if directory.Version > ^uint64(0)-4 {
			return nil, errSessionControlFenceCorrupt
		}
		_, existingErr := s.getFence(ctx, candidate.CellID, candidate.EventID, false)
		if existingErr == nil {
			return s.classifyPreparedFence(ctx, candidate)
		}
		if !errors.Is(existingErr, errSessionControlFenceNotFound) {
			return nil, existingErr
		}
		if directory.ActiveFenceCount >= sessionControlFenceActiveLimit {
			return nil, errSessionControlFenceCapacity
		}
		prepared.PreparedDirectoryVersion = directory.Version + 1
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
			return nil, fmt.Errorf("marshal prepared session-control fence meta: %w", marshalErr)
		}
		activeItem, marshalErr := attributevalue.MarshalMap(activeRow)
		if marshalErr != nil {
			return nil, fmt.Errorf("marshal prepared session-control active fence: %w", marshalErr)
		}

		directoryValues := sessionControlFenceDirectoryConditionValues(*directory)
		directoryValues[":next_count"] = &types.AttributeValueMemberN{Value: fmt.Sprint(directory.ActiveFenceCount + 1)}
		directoryValues[":capacity"] = &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlFenceActiveLimit)}
		directoryValues[":updated_at"] = &types.AttributeValueMemberN{Value: fmt.Sprint(now.UnixMilli())}
		transaction := &dynamodb.TransactWriteItemsInput{
			ClientRequestToken: sessionControlFenceTransactionToken("prepare", candidate.CellID, candidate.EventID, digest, prepared.PreparedDirectoryVersion, now.UnixMilli()),
			TransactItems: []types.TransactWriteItem{
				{Update: &types.Update{
					TableName: aws.String(s.tableName), Key: sessionControlFenceDirectoryKey(candidate.CellID),
					UpdateExpression:         aws.String("SET #version = :next_version, active_fence_count = :next_count, updated_at_ms = :updated_at"),
					ConditionExpression:      aws.String(sessionControlFenceDirectoryCondition() + " AND active_fence_count < :capacity"),
					ExpressionAttributeNames: map[string]string{"#version": "version", "#ttl": "ttl"}, ExpressionAttributeValues: directoryValues,
				}},
				{Put: &types.Put{TableName: aws.String(s.tableName), Item: metaItem,
					ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}},
				{Put: &types.Put{TableName: aws.String(s.tableName), Item: activeItem,
					ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}},
			},
		}
		opCtx, cancel := context.WithTimeout(ctx, s.timeout())
		_, writeErr := s.client.TransactWriteItems(opCtx, transaction)
		cancel()
		if writeErr == nil {
			return &prepared, nil
		}
		var canceled *types.TransactionCanceledException
		if !errors.As(writeErr, &canceled) {
			return nil, fmt.Errorf("prepare session-control fence: %w", writeErr)
		}
		classified, classifyErr := s.classifyPreparedFence(ctx, candidate)
		if classifyErr == nil {
			return classified, nil
		}
		if !errors.Is(classifyErr, errSessionControlFenceNotFound) {
			return nil, classifyErr
		}
	}
	return nil, errSessionControlFenceConflict
}

func (s *dynamoSessionControlStore) MarkFenceConverged(ctx context.Context, fence sessionControlFenceAuthority) (*sessionControlFenceAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if err := validateSessionControlFenceAuthority(fence); err != nil || fence.State != sessionControlFencePreparing {
		return nil, errors.New("invalid preparing session-control fence")
	}
	if fence.Version >= ^uint64(0)-1 {
		return nil, errSessionControlFenceCorrupt
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	converged := fence
	converged.State = sessionControlFenceConverged
	converged.Version++
	converged.ConvergedAtMillis = now.UnixMilli()
	converged.ReplayNotBeforeMillis = now.Add(sessionControlFenceReplayHorizon).UnixMilli()
	converged.UpdatedAtMillis = now.UnixMilli()
	metaRow, err := sessionControlFenceToRow(converged, false)
	if err != nil {
		return nil, err
	}
	activeRow, err := sessionControlFenceToRow(converged, true)
	if err != nil {
		return nil, err
	}
	metaItem, err := attributevalue.MarshalMap(metaRow)
	if err != nil {
		return nil, fmt.Errorf("marshal converged session-control fence meta: %w", err)
	}
	activeItem, err := attributevalue.MarshalMap(activeRow)
	if err != nil {
		return nil, fmt.Errorf("marshal converged session-control active fence: %w", err)
	}

	for range sessionControlFenceAttempts {
		stable, currentErr := s.readStableFenceState(ctx, fence.CellID, fence.EventID)
		if currentErr != nil {
			return nil, currentErr
		}
		current := stable.Meta
		if current == nil {
			return nil, errSessionControlFenceNotFound
		}
		if current.State == sessionControlFenceRetired {
			return nil, errSessionControlFenceRetired
		}
		if current.State == sessionControlFenceConverged {
			if sessionControlFenceSameIdentity(*current, fence) && current.Version == fence.Version+1 {
				return current, nil
			}
			return nil, errSessionControlFenceConflict
		}
		if *current != fence {
			return nil, errSessionControlFenceConflict
		}
		directory := &stable.Directory
		if directory.ActiveFenceCount == 0 || directory.Version > ^uint64(0)-3 {
			return nil, errSessionControlFenceCorrupt
		}
		directoryValues := sessionControlFenceDirectoryConditionValues(*directory)
		directoryValues[":updated_at"] = &types.AttributeValueMemberN{Value: fmt.Sprint(now.UnixMilli())}
		transaction := &dynamodb.TransactWriteItemsInput{
			ClientRequestToken: sessionControlFenceTransactionToken("mark", fence.CellID, fence.EventID, fence.SelectorDigest, fence.PreparedDirectoryVersion, fence.Version, directory.Version, converged.ReplayNotBeforeMillis),
			TransactItems: []types.TransactWriteItem{
				{Update: &types.Update{
					TableName: aws.String(s.tableName), Key: sessionControlFenceDirectoryKey(fence.CellID),
					UpdateExpression:         aws.String("SET #version = :next_version, updated_at_ms = :updated_at"),
					ConditionExpression:      aws.String(sessionControlFenceDirectoryCondition()),
					ExpressionAttributeNames: map[string]string{"#version": "version", "#ttl": "ttl"}, ExpressionAttributeValues: directoryValues,
				}},
				{Put: &types.Put{
					TableName: aws.String(s.tableName), Item: metaItem,
					ConditionExpression:       aws.String(sessionControlFenceTransitionCondition(fence)),
					ExpressionAttributeNames:  map[string]string{"#state": "state", "#version": "version"},
					ExpressionAttributeValues: sessionControlFenceTransitionValues(fence, sessionControlFenceMetaKind),
				}},
				{Put: &types.Put{
					TableName: aws.String(s.tableName), Item: activeItem,
					ConditionExpression:       aws.String(sessionControlFenceTransitionCondition(fence)),
					ExpressionAttributeNames:  map[string]string{"#state": "state", "#version": "version"},
					ExpressionAttributeValues: sessionControlFenceTransitionValues(fence, sessionControlFenceActiveKind),
				}},
			},
		}
		opCtx, cancel := context.WithTimeout(ctx, s.timeout())
		_, writeErr := s.client.TransactWriteItems(opCtx, transaction)
		cancel()
		if writeErr == nil {
			return &converged, nil
		}
		var canceled *types.TransactionCanceledException
		if !errors.As(writeErr, &canceled) {
			return nil, fmt.Errorf("mark session-control fence converged: %w", writeErr)
		}
		latestState, latestErr := s.readStableFenceState(ctx, fence.CellID, fence.EventID)
		if latestErr != nil {
			return nil, latestErr
		}
		latest := latestState.Meta
		if latest == nil {
			return nil, errSessionControlFenceNotFound
		}
		if latest.State == sessionControlFenceConverged &&
			sessionControlFenceSameIdentity(*latest, fence) && latest.Version == fence.Version+1 {
			return latest, nil
		}
		if latest.State == sessionControlFenceRetired {
			return nil, errSessionControlFenceRetired
		}
	}
	return nil, errSessionControlFenceConflict
}

func (s *dynamoSessionControlStore) SnapshotActiveFences(ctx context.Context, cellID string) (*sessionControlFenceSnapshot, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlCellID(cellID) {
		return nil, errors.New("invalid session-control fence cell id")
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	// Missing is an explicit empty-cell initialization, never an implicit
	// version-zero snapshot. The subsequent double read remains authoritative.
	if _, err := s.ensureFenceDirectory(ctx, cellID, now); err != nil {
		return nil, err
	}
	// One shared five-second budget covers both directory fence reads and every
	// paginated ACTIVE query. A large or throttled partition cannot multiply the
	// operation timeout by its page count.
	snapshotCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	first, err := s.getFenceDirectory(snapshotCtx, cellID)
	if err != nil {
		return nil, err
	}
	var (
		fences   []sessionControlFenceAuthority
		lastKey  map[string]types.AttributeValue
		physical int
	)
	for {
		result, queryErr := s.client.Query(snapshotCtx, &dynamodb.QueryInput{
			TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true),
			KeyConditionExpression: aws.String("pk = :pk AND begins_with(sk, :fence_prefix)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk":           &types.AttributeValueMemberS{Value: sessionControlFenceActivePK(cellID)},
				":fence_prefix": &types.AttributeValueMemberS{Value: sessionControlFenceActiveSKPrefix},
			},
			ExclusiveStartKey: lastKey, Limit: aws.Int32(sessionControlFenceQueryLimit),
		})
		if queryErr != nil {
			return nil, fmt.Errorf("session-control active-fence strong query: %w", queryErr)
		}
		physical += len(result.Items)
		if physical > sessionControlFenceActiveLimit || (physical == sessionControlFenceActiveLimit && len(result.LastEvaluatedKey) != 0) {
			return nil, fmt.Errorf("%w: active-fence partition exceeds bounded read", errSessionControlFenceCorrupt)
		}
		for _, item := range result.Items {
			var row sessionControlFenceRow
			if err := attributevalue.UnmarshalMap(item, &row); err != nil {
				return nil, fmt.Errorf("%w: decode active fence", errSessionControlFenceCorrupt)
			}
			fence, err := sessionControlFenceFromRow(row, true, cellID, row.EventID)
			if err != nil {
				return nil, err
			}
			if fence.PreparedDirectoryVersion > first.Version {
				return nil, errSessionControlFenceCorrupt
			}
			fences = append(fences, fence)
		}
		if len(result.LastEvaluatedKey) == 0 {
			break
		}
		lastKey = result.LastEvaluatedKey
	}
	second, err := s.getFenceDirectory(snapshotCtx, cellID)
	if err != nil {
		return nil, err
	}
	if *first != *second || uint64(len(fences)) != first.ActiveFenceCount {
		return nil, fmt.Errorf("%w: unstable directory or active-fence count mismatch", errSessionControlFenceCorrupt)
	}
	return &sessionControlFenceSnapshot{
		CellID: cellID, DirectoryVersion: first.Version, ActiveFenceCount: first.ActiveFenceCount,
		AdmissionBlocked: first.AdmissionBlocked, OverflowCloseCount: first.OverflowCloseCount, Fences: fences,
		OverflowLeaderEventID:                  first.OverflowLeaderEventID,
		OverflowLeaderPreparedDirectoryVersion: first.OverflowLeaderPreparedDirectoryVersion,
		OverflowLeaderSelectedDirectoryVersion: first.OverflowLeaderSelectedDirectoryVersion,
	}, nil
}

// retireFence is deliberately not part of sessionControlActiveFenceStore.
// Future IAM must authorize the transaction's Delete only for this cell's
// ACTIVE partition via dynamodb:LeadingKeys; no broad table DeleteItem grant is
// justified by this lower-level primitive.
func (s *dynamoSessionControlStore) retireFence(ctx context.Context, fence sessionControlFenceAuthority) (*sessionControlFenceAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if err := validateSessionControlFenceAuthority(fence); err != nil || fence.State != sessionControlFenceConverged {
		return nil, errors.New("invalid converged session-control fence")
	}
	if fence.Version >= ^uint64(0)-1 {
		return nil, errSessionControlFenceCorrupt
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	retired := fence
	retired.State = sessionControlFenceRetired
	retired.Version++
	retired.UpdatedAtMillis = now.UnixMilli()
	retired.RetiredAtMillis = now.UnixMilli()
	retired.ExpiresAt = now.Unix() + int64(sessionControlFenceIdempotencyTTL/time.Second)
	metaRow, err := sessionControlFenceToRow(retired, false)
	if err != nil {
		return nil, err
	}
	metaItem, err := attributevalue.MarshalMap(metaRow)
	if err != nil {
		return nil, fmt.Errorf("marshal retired session-control fence meta: %w", err)
	}

	for range sessionControlFenceAttempts {
		stable, stableErr := s.readStableFenceState(ctx, fence.CellID, fence.EventID)
		if stableErr != nil {
			return nil, stableErr
		}
		meta := stable.Meta
		if meta == nil {
			return nil, errSessionControlFenceNotFound
		}
		if meta.State == sessionControlFenceRetired {
			if sessionControlFenceSameIdentity(*meta, fence) && meta.Version == fence.Version+1 {
				return meta, nil
			}
			return nil, errSessionControlFenceRetired
		}
		if *meta != fence {
			return nil, errSessionControlFenceConflict
		}
		if now.UnixMilli() < fence.ReplayNotBeforeMillis {
			return nil, errSessionControlFenceReplayHorizon
		}
		directory := &stable.Directory
		if directory.ActiveFenceCount == 0 || directory.Version > ^uint64(0)-2 ||
			fence.PreparedDirectoryVersion > directory.Version {
			return nil, errSessionControlFenceCorrupt
		}
		directoryValues := sessionControlFenceDirectoryConditionValues(*directory)
		directoryValues[":next_count"] = &types.AttributeValueMemberN{Value: fmt.Sprint(directory.ActiveFenceCount - 1)}
		directoryValues[":updated_at"] = &types.AttributeValueMemberN{Value: fmt.Sprint(now.UnixMilli())}
		transitionNames := map[string]string{"#state": "state", "#version": "version"}
		transaction := &dynamodb.TransactWriteItemsInput{
			ClientRequestToken: sessionControlFenceTransactionToken("retire", fence.CellID, fence.EventID, fence.SelectorDigest, fence.PreparedDirectoryVersion, fence.Version, directory.Version, retired.RetiredAtMillis),
			TransactItems: []types.TransactWriteItem{
				{Update: &types.Update{
					TableName: aws.String(s.tableName), Key: sessionControlFenceDirectoryKey(fence.CellID),
					UpdateExpression:         aws.String("SET #version = :next_version, active_fence_count = :next_count, updated_at_ms = :updated_at"),
					ConditionExpression:      aws.String(sessionControlFenceDirectoryCondition() + " AND active_fence_count > :next_count"),
					ExpressionAttributeNames: map[string]string{"#version": "version", "#ttl": "ttl"}, ExpressionAttributeValues: directoryValues,
				}},
				{Put: &types.Put{
					TableName: aws.String(s.tableName), Item: metaItem,
					ConditionExpression:       aws.String(sessionControlFenceTransitionCondition(fence)),
					ExpressionAttributeNames:  transitionNames,
					ExpressionAttributeValues: sessionControlFenceTransitionValues(fence, sessionControlFenceMetaKind),
				}},
				{Delete: &types.Delete{
					TableName: aws.String(s.tableName), Key: sessionControlFenceActiveKey(fence.CellID, fence.EventID),
					ConditionExpression:       aws.String(sessionControlFenceTransitionCondition(fence)),
					ExpressionAttributeNames:  transitionNames,
					ExpressionAttributeValues: sessionControlFenceTransitionValues(fence, sessionControlFenceActiveKind),
				}},
			},
		}
		opCtx, cancel := context.WithTimeout(ctx, s.timeout())
		_, writeErr := s.client.TransactWriteItems(opCtx, transaction)
		cancel()
		if writeErr == nil {
			return &retired, nil
		}
		var canceled *types.TransactionCanceledException
		if !errors.As(writeErr, &canceled) {
			return nil, fmt.Errorf("retire session-control fence: %w", writeErr)
		}
		latestState, latestErr := s.readStableFenceState(ctx, fence.CellID, fence.EventID)
		if latestErr != nil {
			return nil, latestErr
		}
		latest := latestState.Meta
		if latest == nil {
			return nil, errSessionControlFenceNotFound
		}
		if latest.State == sessionControlFenceRetired &&
			sessionControlFenceSameIdentity(*latest, fence) && latest.Version == fence.Version+1 {
			return latest, nil
		}
	}
	return nil, errSessionControlFenceConflict
}

var _ sessionControlActiveFenceStore = (*dynamoSessionControlStore)(nil)
