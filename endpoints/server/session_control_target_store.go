package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/OpenNHP/opennhp/nhp/common"
)

const (
	sessionControlTargetKind       = "target"
	sessionControlAuthorityKind    = "authority"
	sessionControlAuthoritySK      = "AUTHORITY"
	sessionControlTargetPrefix     = "TARGET#"
	sessionControlTargetSchema     = uint64(2)
	sessionControlAuthoritySchema  = uint64(1)
	sessionControlPrepareAttempts  = 4
	sessionControlTargetQueryLimit = int32(100)
	// Retired rows are permanent, so a corrupted or runaway target partition must
	// fail closed at a finite bound instead of monopolizing a request goroutine.
	sessionControlTargetReadLimit = 1_024
)

type sessionControlTargetState string

const (
	sessionControlTargetPreparing sessionControlTargetState = "preparing"
	sessionControlTargetActive    sessionControlTargetState = "active"
	sessionControlTargetCanceled  sessionControlTargetState = "canceled"
	sessionControlTargetRetired   sessionControlTargetState = "retired"
)

var (
	errSessionControlTargetNotFound     = errors.New("session-control target not found")
	errSessionControlTargetConflict     = errors.New("session-control target changed concurrently")
	errSessionControlTargetRetired      = errors.New("session-control target public key is permanently retired")
	errSessionControlTargetStale        = errors.New("session-control target generation is stale")
	errSessionControlTargetPendingWork  = errors.New("session-control target has pending close work")
	errSessionControlTargetCorrupt      = errors.New("session-control target authority is malformed")
	errSessionControlTargetCapacity     = errors.New("session-control active-target capacity is exhausted")
	errSessionControlTargetControlStale = errors.New("session-control target catch-up cursor is stale")
)

type sessionControlTargetKey struct {
	ACID      string
	PublicKey string
}

type sessionControlTargetCandidate struct {
	ACID            string
	PublicKey       string
	BootID          string
	FlushGeneration uint64
	ControlCellID   string
}

type sessionControlTargetFence struct {
	ACID                    string
	PublicKey               string
	BootID                  string
	FlushGeneration         uint64
	Version                 uint64
	AuthorityVersion        uint64
	CountedActiveSlot       bool
	ControlCellID           string
	ActivatedControlVersion uint64
	ReadyControlVersion     uint64
	AAKEnqueuedAtMillis     int64
	AAKTransactionID        uint64
	CreatedAtMillis         int64
	PreparedAtMillis        int64
}

type sessionControlTargetActivation struct {
	Fence                  sessionControlTargetFence
	ControlCellID          string
	CaughtUpControlVersion uint64
}

// sessionControlTargetDirectoryFence names the exact CONTROL directory cursor
// consumed by one target transition. Keeping it distinct from the target fence
// leaves an unambiguous slot for an owner-directory cursor when that authority
// is added later.
type sessionControlTargetDirectoryFence struct {
	CellID                                 string
	DirectoryVersion                       uint64
	ActiveFenceCount                       uint64
	AdmissionBlocked                       bool
	OverflowCloseCount                     uint64
	OverflowLeaderEventID                  string
	OverflowLeaderPreparedDirectoryVersion uint64
	OverflowLeaderSelectedDirectoryVersion uint64
}

type sessionControlTargetReadiness struct {
	Fence               sessionControlTargetFence
	ControlDirectory    sessionControlTargetDirectoryFence
	AAKEnqueuedAtMillis int64
	AAKTransactionID    uint64
}

type sessionControlTargetAuthority struct {
	ACID                    string
	PublicKey               string
	BootID                  string
	FlushGeneration         uint64
	State                   sessionControlTargetState
	Version                 uint64
	AuthorityVersion        uint64
	CountedActiveSlot       bool
	ControlCellID           string
	ActivatedControlVersion uint64
	ReadyControlVersion     uint64
	AAKEnqueuedAtMillis     int64
	AAKTransactionID        uint64
	CreatedAtMillis         int64
	PreparedAtMillis        int64
	UpdatedAtMillis         int64
	RetiredAtMillis         int64
}

type sessionControlTargetPreparation struct {
	Target             sessionControlTargetAuthority
	RequiresActivation bool
}

func (fence sessionControlTargetFence) key() sessionControlTargetKey {
	return sessionControlTargetKey{ACID: fence.ACID, PublicKey: fence.PublicKey}
}

type sessionControlTargetRow struct {
	PK                      string                    `dynamodbav:"pk"`
	SK                      string                    `dynamodbav:"sk"`
	Kind                    string                    `dynamodbav:"kind"`
	SchemaVersion           uint64                    `dynamodbav:"schema_version"`
	ACID                    string                    `dynamodbav:"ac_id"`
	PublicKey               string                    `dynamodbav:"public_key"`
	BootID                  string                    `dynamodbav:"boot_id"`
	FlushGeneration         uint64                    `dynamodbav:"flush_generation"`
	State                   sessionControlTargetState `dynamodbav:"state"`
	Version                 uint64                    `dynamodbav:"version"`
	AuthorityVersion        uint64                    `dynamodbav:"authority_version"`
	CountedActiveSlot       bool                      `dynamodbav:"counted_active_slot"`
	ControlCellID           string                    `dynamodbav:"control_cell_id"`
	ActivatedControlVersion uint64                    `dynamodbav:"activated_control_version"`
	ReadyControlVersion     uint64                    `dynamodbav:"ready_control_version"`
	AAKEnqueuedAtMillis     int64                     `dynamodbav:"aak_enqueued_at_ms"`
	AAKTransactionID        uint64                    `dynamodbav:"aak_transaction_id"`
	CreatedAtMillis         int64                     `dynamodbav:"created_at_ms"`
	PreparedAtMillis        int64                     `dynamodbav:"prepared_at_ms"`
	UpdatedAtMillis         int64                     `dynamodbav:"updated_at_ms"`
	RetiredAtMillis         int64                     `dynamodbav:"retired_at_ms,omitempty"`
}

func sessionControlTargetReadinessAttributesPresent(item map[string]types.AttributeValue) bool {
	for _, name := range []string{"ready_control_version", "aak_enqueued_at_ms", "aak_transaction_id"} {
		if _, ok := item[name].(*types.AttributeValueMemberN); !ok {
			return false
		}
	}
	return true
}

type sessionControlAuthority struct {
	ACID              string
	ControlCellID     string
	Version           uint64
	ActiveTargetCount uint64
	CreatedAtMillis   int64
	UpdatedAtMillis   int64
}

type sessionControlAuthorityRow struct {
	PK                string `dynamodbav:"pk"`
	SK                string `dynamodbav:"sk"`
	Kind              string `dynamodbav:"kind"`
	SchemaVersion     uint64 `dynamodbav:"schema_version"`
	ACID              string `dynamodbav:"ac_id"`
	ControlCellID     string `dynamodbav:"control_cell_id,omitempty"`
	Version           uint64 `dynamodbav:"version"`
	ActiveTargetCount uint64 `dynamodbav:"active_target_count"`
	CreatedAtMillis   int64  `dynamodbav:"created_at_ms"`
	UpdatedAtMillis   int64  `dynamodbav:"updated_at_ms"`
}

func sessionControlHealthRead(tableName string) *dynamodb.GetItemInput {
	return &dynamodb.GetItemInput{
		TableName:      aws.String(tableName),
		ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{
			"pk": &types.AttributeValueMemberS{Value: sessionControlHealthPK},
			"sk": &types.AttributeValueMemberS{Value: "META"},
		},
	}
}

func canonicalSessionControlACID(acID string) bool {
	if !utf8.ValidString(acID) || strings.TrimSpace(acID) == "" || strings.TrimSpace(acID) != acID {
		return false
	}
	for _, r := range acID {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validSessionControlTargetKey(key sessionControlTargetKey) bool {
	return canonicalSessionControlACID(key.ACID) && common.ValidNHPAgentPublicKey(key.PublicKey)
}

func validSessionControlTargetCandidate(candidate sessionControlTargetCandidate) bool {
	return validSessionControlTargetKey(sessionControlTargetKey{ACID: candidate.ACID, PublicKey: candidate.PublicKey}) &&
		common.ValidNHPACBootID(candidate.BootID) && candidate.FlushGeneration > 0 &&
		validSessionControlCellID(candidate.ControlCellID)
}

func validSessionControlTargetFence(fence sessionControlTargetFence) bool {
	return validSessionControlTargetCandidate(sessionControlTargetCandidate{
		ACID:            fence.ACID,
		PublicKey:       fence.PublicKey,
		BootID:          fence.BootID,
		FlushGeneration: fence.FlushGeneration,
		ControlCellID:   fence.ControlCellID,
	}) && fence.Version > 0 && fence.Version != ^uint64(0) && fence.AuthorityVersion > 0 &&
		fence.ActivatedControlVersion < ^uint64(0)-1 && fence.ReadyControlVersion < ^uint64(0)-1 &&
		validSessionControlTargetReadyAudit(fence.ActivatedControlVersion, fence.ReadyControlVersion,
			fence.AAKEnqueuedAtMillis, fence.AAKTransactionID, fence.PreparedAtMillis) &&
		fence.CreatedAtMillis > 0 && fence.PreparedAtMillis >= fence.CreatedAtMillis
}

func validSessionControlTargetActivation(activation sessionControlTargetActivation) bool {
	return validSessionControlTargetFence(activation.Fence) &&
		activation.Fence.ActivatedControlVersion == 0 && activation.Fence.ReadyControlVersion == 0 &&
		activation.ControlCellID == activation.Fence.ControlCellID &&
		validSessionControlCellID(activation.ControlCellID) &&
		activation.CaughtUpControlVersion > 0 && activation.CaughtUpControlVersion < ^uint64(0)-1
}

func validSessionControlTargetDirectoryFence(fence sessionControlTargetDirectoryFence) bool {
	return validSessionControlCellID(fence.CellID) && fence.DirectoryVersion > 0 &&
		fence.DirectoryVersion != ^uint64(0) && fence.ActiveFenceCount <= sessionControlFenceActiveLimit &&
		fence.OverflowCloseCount < ^uint64(0)-1 && fence.AdmissionBlocked == (fence.OverflowCloseCount > 0) &&
		validateSessionControlFenceDirectory(sessionControlFenceDirectory{
			CellID: fence.CellID, Version: fence.DirectoryVersion, ActiveFenceCount: fence.ActiveFenceCount,
			AdmissionBlocked: fence.AdmissionBlocked, OverflowCloseCount: fence.OverflowCloseCount,
			OverflowLeaderEventID:                  fence.OverflowLeaderEventID,
			OverflowLeaderPreparedDirectoryVersion: fence.OverflowLeaderPreparedDirectoryVersion,
			OverflowLeaderSelectedDirectoryVersion: fence.OverflowLeaderSelectedDirectoryVersion,
			CreatedAtMillis:                        1, UpdatedAtMillis: 1,
		}) == nil
}

func validSessionControlTargetReadiness(readiness sessionControlTargetReadiness) bool {
	fence := readiness.Fence
	directory := readiness.ControlDirectory
	return validSessionControlTargetFence(fence) && fence.ActivatedControlVersion > 0 &&
		fence.CountedActiveSlot && fence.ReadyControlVersion == 0 &&
		fence.AAKEnqueuedAtMillis == 0 && fence.AAKTransactionID == 0 &&
		fence.Version < ^uint64(0)-1 && directory.CellID == fence.ControlCellID &&
		directory.DirectoryVersion == fence.ActivatedControlVersion &&
		validSessionControlTargetDirectoryFence(directory) && !directory.AdmissionBlocked &&
		readiness.AAKEnqueuedAtMillis >= fence.PreparedAtMillis && readiness.AAKTransactionID > 0
}

func validSessionControlTargetReadyAudit(activated, ready uint64, enqueuedAtMillis int64, transactionID uint64,
	preparedAtMillis int64) bool {
	if ready == 0 {
		return enqueuedAtMillis == 0 && transactionID == 0
	}
	return activated > 0 && ready == activated && enqueuedAtMillis >= preparedAtMillis && transactionID > 0
}

func validSessionControlTargetState(state sessionControlTargetState) bool {
	switch state {
	case sessionControlTargetPreparing, sessionControlTargetActive, sessionControlTargetCanceled, sessionControlTargetRetired:
		return true
	default:
		return false
	}
}

func (target sessionControlTargetAuthority) key() sessionControlTargetKey {
	return sessionControlTargetKey{ACID: target.ACID, PublicKey: target.PublicKey}
}

func (target sessionControlTargetAuthority) fence() sessionControlTargetFence {
	return sessionControlTargetFence{
		ACID:                    target.ACID,
		PublicKey:               target.PublicKey,
		BootID:                  target.BootID,
		FlushGeneration:         target.FlushGeneration,
		Version:                 target.Version,
		AuthorityVersion:        target.AuthorityVersion,
		CountedActiveSlot:       target.CountedActiveSlot,
		ControlCellID:           target.ControlCellID,
		ActivatedControlVersion: target.ActivatedControlVersion,
		ReadyControlVersion:     target.ReadyControlVersion,
		AAKEnqueuedAtMillis:     target.AAKEnqueuedAtMillis,
		AAKTransactionID:        target.AAKTransactionID,
		CreatedAtMillis:         target.CreatedAtMillis,
		PreparedAtMillis:        target.PreparedAtMillis,
	}
}

func (fence sessionControlTargetFence) readiness(snapshot sessionControlFenceSnapshot,
	aakEnqueuedAtMillis int64, aakTransactionID uint64) sessionControlTargetReadiness {
	return sessionControlTargetReadiness{
		Fence: fence,
		ControlDirectory: sessionControlTargetDirectoryFence{
			CellID: snapshot.CellID, DirectoryVersion: snapshot.DirectoryVersion,
			ActiveFenceCount: snapshot.ActiveFenceCount, AdmissionBlocked: snapshot.AdmissionBlocked,
			OverflowCloseCount:                     snapshot.OverflowCloseCount,
			OverflowLeaderEventID:                  snapshot.OverflowLeaderEventID,
			OverflowLeaderPreparedDirectoryVersion: snapshot.OverflowLeaderPreparedDirectoryVersion,
			OverflowLeaderSelectedDirectoryVersion: snapshot.OverflowLeaderSelectedDirectoryVersion,
		},
		AAKEnqueuedAtMillis: aakEnqueuedAtMillis,
		AAKTransactionID:    aakTransactionID,
	}
}

func (fence sessionControlTargetFence) activation(controlVersion uint64) sessionControlTargetActivation {
	return sessionControlTargetActivation{
		Fence: fence, ControlCellID: fence.ControlCellID, CaughtUpControlVersion: controlVersion,
	}
}

func (target sessionControlTargetAuthority) exactCandidate(candidate sessionControlTargetCandidate) bool {
	return target.ACID == candidate.ACID && target.PublicKey == candidate.PublicKey &&
		target.BootID == candidate.BootID && target.FlushGeneration == candidate.FlushGeneration &&
		target.ControlCellID == candidate.ControlCellID
}

func sessionControlTargetReconnectHasPendingWork(current sessionControlTargetAuthority,
	candidate sessionControlTargetCandidate, owner sessionControlOwnerAuthority) (bool, error) {
	if !current.exactCandidate(candidate) {
		return false, nil
	}
	switch current.State {
	case sessionControlTargetPreparing:
		if !owner.exactTarget(current, sessionControlOwnerPreparing) {
			return false, errSessionControlOwnerCorrupt
		}
	case sessionControlTargetActive:
		if !sessionControlCloseOwnerTargetMatch(owner, current) {
			return false, errSessionControlOwnerCorrupt
		}
	default:
		return false, nil
	}
	return owner.PendingCount > 0, nil
}

func (target sessionControlTargetAuthority) exactFence(fence sessionControlTargetFence) bool {
	return target.ACID == fence.ACID && target.PublicKey == fence.PublicKey &&
		target.BootID == fence.BootID && target.FlushGeneration == fence.FlushGeneration &&
		target.ControlCellID == fence.ControlCellID && target.CreatedAtMillis == fence.CreatedAtMillis &&
		target.PreparedAtMillis == fence.PreparedAtMillis
}

func (target sessionControlTargetAuthority) required() bool {
	return target.State == sessionControlTargetActive ||
		(target.State == sessionControlTargetPreparing && target.CountedActiveSlot)
}

func (target sessionControlTargetAuthority) ready() bool {
	return target.State == sessionControlTargetActive && target.CountedActiveSlot &&
		target.ActivatedControlVersion > 0 && target.ReadyControlVersion == target.ActivatedControlVersion &&
		target.AAKEnqueuedAtMillis >= target.PreparedAtMillis && target.AAKTransactionID > 0
}

func validateSessionControlTargetAuthority(target sessionControlTargetAuthority) error {
	if !validSessionControlTargetCandidate(sessionControlTargetCandidate{
		ACID:            target.ACID,
		PublicKey:       target.PublicKey,
		BootID:          target.BootID,
		FlushGeneration: target.FlushGeneration,
		ControlCellID:   target.ControlCellID,
	}) || !validSessionControlTargetState(target.State) || target.Version == 0 || target.Version == ^uint64(0) ||
		target.AuthorityVersion == 0 || target.CreatedAtMillis <= 0 ||
		target.PreparedAtMillis < target.CreatedAtMillis || target.UpdatedAtMillis < target.PreparedAtMillis ||
		target.ActivatedControlVersion >= ^uint64(0)-1 || target.ReadyControlVersion >= ^uint64(0)-1 ||
		!validSessionControlTargetReadyAudit(target.ActivatedControlVersion, target.ReadyControlVersion,
			target.AAKEnqueuedAtMillis, target.AAKTransactionID, target.PreparedAtMillis) {
		return errSessionControlTargetCorrupt
	}
	if target.State == sessionControlTargetRetired {
		if target.RetiredAtMillis != target.UpdatedAtMillis || target.CountedActiveSlot {
			return errSessionControlTargetCorrupt
		}
	} else if target.RetiredAtMillis != 0 {
		return errSessionControlTargetCorrupt
	}
	if target.State == sessionControlTargetActive && (!target.CountedActiveSlot || target.ActivatedControlVersion == 0) {
		return errSessionControlTargetCorrupt
	}
	if target.State == sessionControlTargetPreparing && (target.ActivatedControlVersion != 0 || target.ReadyControlVersion != 0) {
		return errSessionControlTargetCorrupt
	}
	if target.State == sessionControlTargetCanceled && (target.CountedActiveSlot || target.ActivatedControlVersion != 0 || target.ReadyControlVersion != 0) {
		return errSessionControlTargetCorrupt
	}
	return nil
}

func sessionControlTargetPK(acID string) string {
	digest := sha256.Sum256([]byte(acID))
	return "AC#" + hex.EncodeToString(digest[:])
}

func sessionControlTargetSK(publicKey string) string {
	digest := sha256.Sum256([]byte(publicKey))
	return sessionControlTargetPrefix + hex.EncodeToString(digest[:])
}

func sessionControlTargetDynamoKey(key sessionControlTargetKey) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlTargetPK(key.ACID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlTargetSK(key.PublicKey)},
	}
}

func sessionControlTargetFromRow(row sessionControlTargetRow, expectedACID string) (sessionControlTargetAuthority, error) {
	target := sessionControlTargetAuthority{
		ACID:                    row.ACID,
		PublicKey:               row.PublicKey,
		BootID:                  row.BootID,
		FlushGeneration:         row.FlushGeneration,
		State:                   row.State,
		Version:                 row.Version,
		AuthorityVersion:        row.AuthorityVersion,
		CountedActiveSlot:       row.CountedActiveSlot,
		ControlCellID:           row.ControlCellID,
		ActivatedControlVersion: row.ActivatedControlVersion,
		ReadyControlVersion:     row.ReadyControlVersion,
		AAKEnqueuedAtMillis:     row.AAKEnqueuedAtMillis,
		AAKTransactionID:        row.AAKTransactionID,
		CreatedAtMillis:         row.CreatedAtMillis,
		PreparedAtMillis:        row.PreparedAtMillis,
		UpdatedAtMillis:         row.UpdatedAtMillis,
		RetiredAtMillis:         row.RetiredAtMillis,
	}
	if row.Kind != sessionControlTargetKind || row.SchemaVersion != sessionControlTargetSchema ||
		row.PK != sessionControlTargetPK(row.ACID) || row.SK != sessionControlTargetSK(row.PublicKey) ||
		row.ACID != expectedACID {
		return sessionControlTargetAuthority{}, errSessionControlTargetCorrupt
	}
	if err := validateSessionControlTargetAuthority(target); err != nil {
		return sessionControlTargetAuthority{}, err
	}
	return target, nil
}

func sessionControlTargetToRow(target sessionControlTargetAuthority) (sessionControlTargetRow, error) {
	if err := validateSessionControlTargetAuthority(target); err != nil {
		return sessionControlTargetRow{}, err
	}
	return sessionControlTargetRow{
		PK:                      sessionControlTargetPK(target.ACID),
		SK:                      sessionControlTargetSK(target.PublicKey),
		Kind:                    sessionControlTargetKind,
		SchemaVersion:           sessionControlTargetSchema,
		ACID:                    target.ACID,
		PublicKey:               target.PublicKey,
		BootID:                  target.BootID,
		FlushGeneration:         target.FlushGeneration,
		State:                   target.State,
		Version:                 target.Version,
		AuthorityVersion:        target.AuthorityVersion,
		CountedActiveSlot:       target.CountedActiveSlot,
		ControlCellID:           target.ControlCellID,
		ActivatedControlVersion: target.ActivatedControlVersion,
		ReadyControlVersion:     target.ReadyControlVersion,
		AAKEnqueuedAtMillis:     target.AAKEnqueuedAtMillis,
		AAKTransactionID:        target.AAKTransactionID,
		CreatedAtMillis:         target.CreatedAtMillis,
		PreparedAtMillis:        target.PreparedAtMillis,
		UpdatedAtMillis:         target.UpdatedAtMillis,
		RetiredAtMillis:         target.RetiredAtMillis,
	}, nil
}

func sessionControlAuthorityDynamoKey(acID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlTargetPK(acID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlAuthoritySK},
	}
}

func validateSessionControlAuthority(authority sessionControlAuthority) error {
	if !canonicalSessionControlACID(authority.ACID) || authority.Version == 0 || authority.Version == ^uint64(0) ||
		authority.ActiveTargetCount > uint64(MaxACConnsPerID) || authority.CreatedAtMillis <= 0 || authority.UpdatedAtMillis < authority.CreatedAtMillis {
		return errSessionControlTargetCorrupt
	}
	if authority.ControlCellID == "" {
		if authority.ActiveTargetCount != 0 {
			return errSessionControlTargetCorrupt
		}
	} else if !validSessionControlCellID(authority.ControlCellID) {
		return errSessionControlTargetCorrupt
	}
	return nil
}

func sessionControlAuthorityToRow(authority sessionControlAuthority) (sessionControlAuthorityRow, error) {
	if err := validateSessionControlAuthority(authority); err != nil {
		return sessionControlAuthorityRow{}, err
	}
	return sessionControlAuthorityRow{
		PK:                sessionControlTargetPK(authority.ACID),
		SK:                sessionControlAuthoritySK,
		Kind:              sessionControlAuthorityKind,
		SchemaVersion:     sessionControlAuthoritySchema,
		ACID:              authority.ACID,
		ControlCellID:     authority.ControlCellID,
		Version:           authority.Version,
		ActiveTargetCount: authority.ActiveTargetCount,
		CreatedAtMillis:   authority.CreatedAtMillis,
		UpdatedAtMillis:   authority.UpdatedAtMillis,
	}, nil
}

func sessionControlAuthorityFromRow(row sessionControlAuthorityRow, expectedACID string) (sessionControlAuthority, error) {
	authority := sessionControlAuthority{
		ACID:              row.ACID,
		ControlCellID:     row.ControlCellID,
		Version:           row.Version,
		ActiveTargetCount: row.ActiveTargetCount,
		CreatedAtMillis:   row.CreatedAtMillis,
		UpdatedAtMillis:   row.UpdatedAtMillis,
	}
	if row.Kind != sessionControlAuthorityKind || row.SchemaVersion != sessionControlAuthoritySchema ||
		row.PK != sessionControlTargetPK(row.ACID) || row.SK != sessionControlAuthoritySK || row.ACID != expectedACID {
		return sessionControlAuthority{}, errSessionControlTargetCorrupt
	}
	if err := validateSessionControlAuthority(authority); err != nil {
		return sessionControlAuthority{}, err
	}
	return authority, nil
}

func planSessionControlTargetPreparation(current *sessionControlTargetAuthority, candidate sessionControlTargetCandidate, authority sessionControlAuthority, now time.Time) (sessionControlTargetPreparation, bool, error) {
	if !validSessionControlTargetCandidate(candidate) || validateSessionControlAuthority(authority) != nil ||
		authority.ACID != candidate.ACID || now.IsZero() || now.UnixMilli() <= 0 {
		return sessionControlTargetPreparation{}, false, errors.New("invalid session-control target preparation")
	}
	if authority.ControlCellID != "" && authority.ControlCellID != candidate.ControlCellID {
		return sessionControlTargetPreparation{}, false, errSessionControlTargetConflict
	}
	nowMillis := now.UTC().UnixMilli()
	if current == nil {
		target := sessionControlTargetAuthority{
			ACID:             candidate.ACID,
			PublicKey:        candidate.PublicKey,
			BootID:           candidate.BootID,
			FlushGeneration:  candidate.FlushGeneration,
			ControlCellID:    candidate.ControlCellID,
			State:            sessionControlTargetPreparing,
			Version:          1,
			AuthorityVersion: authority.Version,
			CreatedAtMillis:  nowMillis,
			PreparedAtMillis: nowMillis,
			UpdatedAtMillis:  nowMillis,
		}
		return sessionControlTargetPreparation{Target: target, RequiresActivation: true}, true, nil
	}
	if err := validateSessionControlTargetAuthority(*current); err != nil || current.ACID != candidate.ACID || current.PublicKey != candidate.PublicKey {
		return sessionControlTargetPreparation{}, false, errSessionControlTargetCorrupt
	}
	if current.CountedActiveSlot && (authority.ControlCellID != current.ControlCellID || authority.ActiveTargetCount == 0) {
		return sessionControlTargetPreparation{}, false, errSessionControlTargetCorrupt
	}
	if current.ControlCellID != candidate.ControlCellID {
		return sessionControlTargetPreparation{}, false, errSessionControlTargetConflict
	}
	if current.State == sessionControlTargetRetired {
		return sessionControlTargetPreparation{}, false, errSessionControlTargetRetired
	}
	if current.exactCandidate(candidate) {
		switch current.State {
		case sessionControlTargetPreparing:
			if current.AuthorityVersion == authority.Version {
				return sessionControlTargetPreparation{Target: *current, RequiresActivation: true}, false, nil
			}
		case sessionControlTargetActive:
			// Every reconnect, including the same boot/generation tuple after an
			// ambiguous AAK loss, must re-enter catch-up. Returning the active row
			// would skip durable operations created while its control was absent.
		case sessionControlTargetCanceled:
			// A rejected late gate is retryable. Incrementing the fence prevents
			// any delayed activation from the canceled attempt from winning.
		default:
			return sessionControlTargetPreparation{}, false, errSessionControlTargetCorrupt
		}
	} else if candidate.FlushGeneration <= current.FlushGeneration {
		return sessionControlTargetPreparation{}, false, errSessionControlTargetStale
	}

	next := *current
	// Preparation itself consumes one version and must leave two further values
	// for activation and readiness finalization (or one for cancellation). Do not
	// persist an attempt that can never become authority-ready.
	if next.Version >= ^uint64(0)-3 {
		return sessionControlTargetPreparation{}, false, errSessionControlTargetCorrupt
	}
	if nowMillis < current.UpdatedAtMillis {
		nowMillis = current.UpdatedAtMillis
	}
	next.BootID = candidate.BootID
	next.FlushGeneration = candidate.FlushGeneration
	next.State = sessionControlTargetPreparing
	next.Version++
	next.AuthorityVersion = authority.Version
	next.ActivatedControlVersion = 0
	next.ReadyControlVersion = 0
	next.AAKEnqueuedAtMillis = 0
	next.AAKTransactionID = 0
	next.PreparedAtMillis = nowMillis
	next.UpdatedAtMillis = nowMillis
	next.RetiredAtMillis = 0
	return sessionControlTargetPreparation{Target: next, RequiresActivation: true}, true, nil
}

func (s *dynamoSessionControlStore) now() (time.Time, error) {
	if s == nil || s.nowUTC == nil {
		return time.Time{}, errors.New("session-control store clock is unavailable")
	}
	now := s.nowUTC().UTC()
	if now.IsZero() || now.UnixMilli() <= 0 {
		return time.Time{}, errors.New("session-control store clock is invalid")
	}
	return now, nil
}

func (s *dynamoSessionControlStore) validate() error {
	if s == nil || s.client == nil || s.tableName == "" {
		return errors.New("session-control store is unavailable")
	}
	return nil
}

func (s *dynamoSessionControlStore) getAuthority(ctx context.Context, acID string) (*sessionControlAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !canonicalSessionControlACID(acID) {
		return nil, errors.New("invalid session-control AC id")
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(s.tableName),
		ConsistentRead: aws.Bool(true),
		Key:            sessionControlAuthorityDynamoKey(acID),
	})
	if err != nil {
		return nil, fmt.Errorf("session-control authority strong read: %w", err)
	}
	if len(result.Item) == 0 {
		return nil, errSessionControlTargetNotFound
	}
	var row sessionControlAuthorityRow
	if err := attributevalue.UnmarshalMap(result.Item, &row); err != nil {
		return nil, fmt.Errorf("%w: decode authority row", errSessionControlTargetCorrupt)
	}
	authority, err := sessionControlAuthorityFromRow(row, acID)
	if err != nil {
		return nil, err
	}
	return &authority, nil
}

func (s *dynamoSessionControlStore) ensureAuthority(ctx context.Context, acID string, now time.Time) (*sessionControlAuthority, error) {
	for attempt := 0; attempt < sessionControlPrepareAttempts; attempt++ {
		authority, err := s.getAuthority(ctx, acID)
		if err == nil {
			return authority, nil
		}
		if !errors.Is(err, errSessionControlTargetNotFound) {
			return nil, err
		}
		nowMillis := now.UTC().UnixMilli()
		created := sessionControlAuthority{
			ACID:            acID,
			Version:         1,
			CreatedAtMillis: nowMillis,
			UpdatedAtMillis: nowMillis,
		}
		row, rowErr := sessionControlAuthorityToRow(created)
		if rowErr != nil {
			return nil, rowErr
		}
		item, marshalErr := attributevalue.MarshalMap(row)
		if marshalErr != nil {
			return nil, fmt.Errorf("marshal session-control authority: %w", marshalErr)
		}
		operationCtx, cancel := context.WithTimeout(ctx, s.timeout())
		_, putErr := s.client.PutItem(operationCtx, &dynamodb.PutItemInput{
			TableName:           aws.String(s.tableName),
			Item:                item,
			ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)"),
		})
		cancel()
		if putErr == nil {
			return &created, nil
		}
		var conditional *types.ConditionalCheckFailedException
		if !errors.As(putErr, &conditional) {
			return nil, fmt.Errorf("persist session-control authority: %w", putErr)
		}
	}
	return nil, errSessionControlTargetConflict
}

func (s *dynamoSessionControlStore) getTarget(ctx context.Context, key sessionControlTargetKey) (*sessionControlTargetAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlTargetKey(key) {
		return nil, errors.New("invalid session-control target key")
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(s.tableName),
		ConsistentRead: aws.Bool(true),
		Key:            sessionControlTargetDynamoKey(key),
	})
	if err != nil {
		return nil, fmt.Errorf("session-control target strong read: %w", err)
	}
	if len(result.Item) == 0 {
		return nil, errSessionControlTargetNotFound
	}
	if !sessionControlTargetReadinessAttributesPresent(result.Item) {
		return nil, fmt.Errorf("%w: target readiness audit attributes are missing", errSessionControlTargetCorrupt)
	}
	var row sessionControlTargetRow
	if err := attributevalue.UnmarshalMap(result.Item, &row); err != nil {
		return nil, fmt.Errorf("%w: decode target row", errSessionControlTargetCorrupt)
	}
	target, err := sessionControlTargetFromRow(row, key.ACID)
	if err != nil || target.PublicKey != key.PublicKey {
		return nil, errSessionControlTargetCorrupt
	}
	return &target, nil
}

func (s *dynamoSessionControlStore) GetTarget(ctx context.Context, key sessionControlTargetKey) (*sessionControlTargetAuthority, error) {
	return s.getTarget(ctx, key)
}

func (s *dynamoSessionControlStore) ListRequiredTargets(ctx context.Context, acID, controlCellID string) ([]sessionControlTargetAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !canonicalSessionControlACID(acID) || !validSessionControlCellID(controlCellID) {
		return nil, errors.New("invalid session-control authority identity")
	}
	// One aggregate deadline covers every authority bracket and paginated query
	// retry. Activation and retirement update the target plus authority header in
	// one transaction, so the monotonic header version is the list seqlock.
	listCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	for range sessionControlPrepareAttempts {
		before, err := s.getAuthority(listCtx, acID)
		if err != nil {
			return nil, err
		}
		var (
			out          []sessionControlTargetAuthority
			lastKey      map[string]types.AttributeValue
			physical     int
			cellMismatch bool
		)
		for {
			result, queryErr := s.client.Query(listCtx, &dynamodb.QueryInput{
				TableName:              aws.String(s.tableName),
				ConsistentRead:         aws.Bool(true),
				KeyConditionExpression: aws.String("pk = :pk AND begins_with(sk, :target_prefix)"),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":pk":            &types.AttributeValueMemberS{Value: sessionControlTargetPK(acID)},
					":target_prefix": &types.AttributeValueMemberS{Value: sessionControlTargetPrefix},
				},
				ExclusiveStartKey: lastKey,
				Limit:             aws.Int32(sessionControlTargetQueryLimit),
			})
			if queryErr != nil {
				return nil, fmt.Errorf("session-control required-target strong query: %w", queryErr)
			}
			physical += len(result.Items)
			if physical > sessionControlTargetReadLimit {
				return nil, fmt.Errorf("%w: target partition exceeds bounded read", errSessionControlTargetCorrupt)
			}
			for _, item := range result.Items {
				if !sessionControlTargetReadinessAttributesPresent(item) {
					return nil, fmt.Errorf("%w: required-target readiness audit attributes are missing (%T/%T/%T)",
						errSessionControlTargetCorrupt, item["ready_control_version"], item["aak_enqueued_at_ms"], item["aak_transaction_id"])
				}
				var row sessionControlTargetRow
				if err := attributevalue.UnmarshalMap(item, &row); err != nil {
					return nil, fmt.Errorf("%w: decode required-target row", errSessionControlTargetCorrupt)
				}
				target, rowErr := sessionControlTargetFromRow(row, acID)
				if rowErr != nil {
					return nil, rowErr
				}
				if target.required() {
					cellMismatch = cellMismatch || target.ControlCellID != controlCellID
					out = append(out, target)
				}
			}
			if len(result.LastEvaluatedKey) == 0 {
				break
			}
			lastKey = result.LastEvaluatedKey
		}
		after, err := s.getAuthority(listCtx, acID)
		if err != nil {
			return nil, err
		}
		if *before != *after {
			continue
		}
		if after.ControlCellID != "" && after.ControlCellID != controlCellID {
			return nil, errSessionControlTargetConflict
		}
		if cellMismatch || len(out) > MaxACConnsPerID || uint64(len(out)) != after.ActiveTargetCount {
			return nil, fmt.Errorf("%w: authority count=%d required rows=%d", errSessionControlTargetCorrupt, after.ActiveTargetCount, len(out))
		}
		return out, nil
	}
	return nil, errSessionControlTargetConflict
}

func (s *dynamoSessionControlStore) PrepareTarget(ctx context.Context, candidate sessionControlTargetCandidate) (*sessionControlTargetPreparation, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlTargetCandidate(candidate) {
		return nil, errors.New("invalid session-control target candidate")
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	key := sessionControlTargetKey{ACID: candidate.ACID, PublicKey: candidate.PublicKey}
	for attempt := 0; attempt < sessionControlPrepareAttempts; attempt++ {
		authority, authorityErr := s.ensureAuthority(ctx, candidate.ACID, now)
		if authorityErr != nil {
			return nil, authorityErr
		}
		current, getErr := s.getTarget(ctx, key)
		if getErr != nil && !errors.Is(getErr, errSessionControlTargetNotFound) {
			return nil, getErr
		}
		planned, write, planErr := planSessionControlTargetPreparation(current, candidate, *authority, now)
		if planErr != nil {
			return nil, planErr
		}
		if !write {
			owner, ownerErr := s.getOwner(ctx, candidate.ControlCellID, candidate.ACID, candidate.PublicKey)
			if ownerErr != nil {
				return nil, ownerErr
			}
			stable, stableErr := s.getTarget(ctx, key)
			if stableErr != nil {
				return nil, stableErr
			}
			if current == nil || *stable != *current {
				continue
			}
			if owner.TargetVersion != planned.Target.Version || owner.TargetAuthorityVersion != planned.Target.AuthorityVersion ||
				owner.BootID != planned.Target.BootID || owner.FlushGeneration != planned.Target.FlushGeneration ||
				owner.Phase != sessionControlOwnerPreparing {
				return nil, errSessionControlOwnerCorrupt
			}
			pending, pendingErr := sessionControlTargetReconnectHasPendingWork(*current, candidate, *owner)
			if pendingErr != nil {
				return nil, pendingErr
			}
			if pending {
				return nil, errSessionControlTargetPendingWork
			}
			return &planned, nil
		}
		var currentOwner *sessionControlOwnerAuthority
		if current != nil {
			currentOwner, getErr = s.getOwner(ctx, candidate.ControlCellID, candidate.ACID, candidate.PublicKey)
			if getErr != nil {
				return nil, getErr
			}
			stable, stableErr := s.getTarget(ctx, key)
			if stableErr != nil {
				return nil, stableErr
			}
			if *stable != *current {
				continue
			}
			pending, pendingErr := sessionControlTargetReconnectHasPendingWork(*current, candidate, *currentOwner)
			if pendingErr != nil {
				return nil, pendingErr
			}
			if pending {
				return nil, errSessionControlTargetPendingWork
			}
		}
		nextOwner, ownerErr := sessionControlOwnerFromTarget(planned.Target, currentOwner, sessionControlOwnerPreparing)
		if ownerErr != nil {
			return nil, ownerErr
		}
		if current == nil {
			if err := s.putNewTarget(ctx, planned.Target, nextOwner); err == nil {
				return &planned, nil
			} else if !errors.Is(err, errSessionControlTargetConflict) {
				return nil, err
			}
			continue
		}
		if err := s.replacePreparedTarget(ctx, *current, planned.Target, *currentOwner, nextOwner); err == nil {
			return &planned, nil
		} else if !errors.Is(err, errSessionControlTargetConflict) {
			return nil, err
		}
	}
	return nil, errSessionControlTargetConflict
}

func (s *dynamoSessionControlStore) putNewTarget(ctx context.Context, target sessionControlTargetAuthority,
	owner sessionControlOwnerAuthority) error {
	row, err := sessionControlTargetToRow(target)
	if err != nil {
		return err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return fmt.Errorf("marshal session-control target: %w", err)
	}
	ownerWrite, err := sessionControlOwnerPut(s.tableName, owner, true)
	if err != nil {
		return err
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	_, err = s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: sessionControlOwnerTransitionToken("prepare-new", nil, owner),
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{TableName: aws.String(s.tableName), Item: item,
				ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}},
			ownerWrite,
		},
	})
	if err == nil {
		return nil
	}
	var canceled *types.TransactionCanceledException
	if errors.As(err, &canceled) {
		return errSessionControlTargetConflict
	}
	return fmt.Errorf("persist new session-control target: %w", err)
}

func (s *dynamoSessionControlStore) replacePreparedTarget(ctx context.Context, current, next sessionControlTargetAuthority,
	currentOwner, nextOwner sessionControlOwnerAuthority) error {
	ownerWrite, err := sessionControlOwnerReplace(s.tableName, currentOwner, nextOwner)
	if err != nil {
		return err
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	_, err = s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: sessionControlOwnerTransitionToken("prepare", &currentOwner, nextOwner),
		TransactItems: []types.TransactWriteItem{{Update: &types.Update{
			TableName:           aws.String(s.tableName),
			Key:                 sessionControlTargetDynamoKey(current.key()),
			UpdateExpression:    aws.String("SET boot_id = :next_boot, flush_generation = :next_generation, #state = :preparing, #version = :next_version, authority_version = :next_authority_version, activated_control_version = :cleared_control_version, ready_control_version = :cleared_control_version, aak_enqueued_at_ms = :zero_time, aak_transaction_id = :zero_transaction, prepared_at_ms = :prepared_at, updated_at_ms = :updated_at REMOVE retired_at_ms"),
			ConditionExpression: aws.String("ac_id = :ac_id AND public_key = :public_key AND boot_id = :current_boot AND flush_generation = :current_generation AND control_cell_id = :control_cell_id AND activated_control_version = :activated_control_version AND ready_control_version = :ready_control_version AND aak_enqueued_at_ms = :aak_enqueued_at AND aak_transaction_id = :aak_transaction_id AND created_at_ms = :created_at AND prepared_at_ms = :current_prepared_at AND #state = :current_state AND #version = :current_version AND authority_version = :current_authority_version AND counted_active_slot = :counted_active_slot"),
			ExpressionAttributeNames: map[string]string{
				"#state":   "state",
				"#version": "version",
			},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":ac_id":                     &types.AttributeValueMemberS{Value: current.ACID},
				":public_key":                &types.AttributeValueMemberS{Value: current.PublicKey},
				":current_boot":              &types.AttributeValueMemberS{Value: current.BootID},
				":current_generation":        &types.AttributeValueMemberN{Value: fmt.Sprint(current.FlushGeneration)},
				":control_cell_id":           &types.AttributeValueMemberS{Value: current.ControlCellID},
				":activated_control_version": &types.AttributeValueMemberN{Value: fmt.Sprint(current.ActivatedControlVersion)},
				":ready_control_version":     &types.AttributeValueMemberN{Value: fmt.Sprint(current.ReadyControlVersion)},
				":aak_enqueued_at":           &types.AttributeValueMemberN{Value: fmt.Sprint(current.AAKEnqueuedAtMillis)},
				":aak_transaction_id":        &types.AttributeValueMemberN{Value: fmt.Sprint(current.AAKTransactionID)},
				":created_at":                &types.AttributeValueMemberN{Value: fmt.Sprint(current.CreatedAtMillis)},
				":current_prepared_at":       &types.AttributeValueMemberN{Value: fmt.Sprint(current.PreparedAtMillis)},
				":current_state":             &types.AttributeValueMemberS{Value: string(current.State)},
				":current_version":           &types.AttributeValueMemberN{Value: fmt.Sprint(current.Version)},
				":current_authority_version": &types.AttributeValueMemberN{Value: fmt.Sprint(current.AuthorityVersion)},
				":counted_active_slot":       &types.AttributeValueMemberBOOL{Value: current.CountedActiveSlot},
				":cleared_control_version":   &types.AttributeValueMemberN{Value: "0"},
				":zero_time":                 &types.AttributeValueMemberN{Value: "0"},
				":zero_transaction":          &types.AttributeValueMemberN{Value: "0"},
				":next_boot":                 &types.AttributeValueMemberS{Value: next.BootID},
				":next_generation":           &types.AttributeValueMemberN{Value: fmt.Sprint(next.FlushGeneration)},
				":preparing":                 &types.AttributeValueMemberS{Value: string(sessionControlTargetPreparing)},
				":next_version":              &types.AttributeValueMemberN{Value: fmt.Sprint(next.Version)},
				":next_authority_version":    &types.AttributeValueMemberN{Value: fmt.Sprint(next.AuthorityVersion)},
				":prepared_at":               &types.AttributeValueMemberN{Value: fmt.Sprint(next.PreparedAtMillis)},
				":updated_at":                &types.AttributeValueMemberN{Value: fmt.Sprint(next.UpdatedAtMillis)},
			},
		}}, ownerWrite},
	})
	if err == nil {
		return nil
	}
	var canceled *types.TransactionCanceledException
	if errors.As(err, &canceled) {
		return errSessionControlTargetConflict
	}
	return fmt.Errorf("replace prepared session-control target: %w", err)
}

func (s *dynamoSessionControlStore) cancelPreparedTarget(ctx context.Context, fence sessionControlTargetFence) (*sessionControlTargetAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlTargetFence(fence) {
		return nil, errors.New("invalid session-control target fence")
	}
	if fence.Version >= ^uint64(0)-1 {
		return nil, errSessionControlTargetCorrupt
	}
	if fence.CountedActiveSlot {
		return nil, errSessionControlTargetConflict
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	nowMillis := now.UnixMilli()
	if nowMillis < fence.PreparedAtMillis {
		nowMillis = fence.PreparedAtMillis
	}
	values := map[string]types.AttributeValue{
		":ac_id":                     &types.AttributeValueMemberS{Value: fence.ACID},
		":public_key":                &types.AttributeValueMemberS{Value: fence.PublicKey},
		":boot_id":                   &types.AttributeValueMemberS{Value: fence.BootID},
		":flush_generation":          &types.AttributeValueMemberN{Value: fmt.Sprint(fence.FlushGeneration)},
		":control_cell_id":           &types.AttributeValueMemberS{Value: fence.ControlCellID},
		":activated_control_version": &types.AttributeValueMemberN{Value: fmt.Sprint(fence.ActivatedControlVersion)},
		":ready_control_version":     &types.AttributeValueMemberN{Value: fmt.Sprint(fence.ReadyControlVersion)},
		":aak_enqueued_at":           &types.AttributeValueMemberN{Value: fmt.Sprint(fence.AAKEnqueuedAtMillis)},
		":aak_transaction_id":        &types.AttributeValueMemberN{Value: fmt.Sprint(fence.AAKTransactionID)},
		":created_at":                &types.AttributeValueMemberN{Value: fmt.Sprint(fence.CreatedAtMillis)},
		":prepared_at":               &types.AttributeValueMemberN{Value: fmt.Sprint(fence.PreparedAtMillis)},
		":current_state":             &types.AttributeValueMemberS{Value: string(sessionControlTargetPreparing)},
		":current_version":           &types.AttributeValueMemberN{Value: fmt.Sprint(fence.Version)},
		":current_authority_version": &types.AttributeValueMemberN{Value: fmt.Sprint(fence.AuthorityVersion)},
		":counted_active_slot":       &types.AttributeValueMemberBOOL{Value: fence.CountedActiveSlot},
		":next_state":                &types.AttributeValueMemberS{Value: string(sessionControlTargetCanceled)},
		":next_version":              &types.AttributeValueMemberN{Value: fmt.Sprint(fence.Version + 1)},
		":updated_at":                &types.AttributeValueMemberN{Value: fmt.Sprint(nowMillis)},
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	result, err := s.client.UpdateItem(opCtx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.tableName),
		Key:                 sessionControlTargetDynamoKey(sessionControlTargetKey{ACID: fence.ACID, PublicKey: fence.PublicKey}),
		UpdateExpression:    aws.String("SET #state = :next_state, #version = :next_version, updated_at_ms = :updated_at"),
		ConditionExpression: aws.String("ac_id = :ac_id AND public_key = :public_key AND boot_id = :boot_id AND flush_generation = :flush_generation AND control_cell_id = :control_cell_id AND activated_control_version = :activated_control_version AND ready_control_version = :ready_control_version AND aak_enqueued_at_ms = :aak_enqueued_at AND aak_transaction_id = :aak_transaction_id AND created_at_ms = :created_at AND prepared_at_ms = :prepared_at AND #state = :current_state AND #version = :current_version AND authority_version = :current_authority_version AND counted_active_slot = :counted_active_slot"),
		ExpressionAttributeNames: map[string]string{
			"#state":   "state",
			"#version": "version",
		},
		ExpressionAttributeValues: values,
		ReturnValues:              types.ReturnValueAllNew,
	})
	cancel()
	if err != nil {
		var conditional *types.ConditionalCheckFailedException
		if errors.As(err, &conditional) {
			return s.classifyTransitionConflict(ctx, fence, sessionControlTargetCanceled)
		}
		return nil, fmt.Errorf("cancel prepared session-control target: %w", err)
	}
	var row sessionControlTargetRow
	if err := attributevalue.UnmarshalMap(result.Attributes, &row); err != nil {
		return nil, fmt.Errorf("%w: decode transition result", errSessionControlTargetCorrupt)
	}
	target, err := sessionControlTargetFromRow(row, fence.ACID)
	if err != nil || target.PublicKey != fence.PublicKey || target.State != sessionControlTargetCanceled || target.Version != fence.Version+1 {
		return nil, errSessionControlTargetCorrupt
	}
	return &target, nil
}

func sessionControlTargetTransactionCondition() string {
	return "kind = :target_kind AND schema_version = :target_schema AND ac_id = :ac_id AND public_key = :public_key AND boot_id = :boot_id AND flush_generation = :flush_generation AND control_cell_id = :control_cell_id AND activated_control_version = :activated_control_version AND ready_control_version = :ready_control_version AND aak_enqueued_at_ms = :aak_enqueued_at AND aak_transaction_id = :aak_transaction_id AND created_at_ms = :created_at AND prepared_at_ms = :prepared_at AND #state = :current_state AND #version = :current_version AND authority_version = :current_authority_version AND counted_active_slot = :counted_active_slot"
}

func sessionControlTransactionToken(action string, activation sessionControlTargetActivation) *string {
	fence := activation.Fence
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%d\x00%t\x00%d\x00%d\x00%d\x00%d\x00%d\x00%d\x00%s\x00%d",
		action, fence.ACID, fence.PublicKey, fence.BootID, fence.FlushGeneration, fence.Version,
		fence.AuthorityVersion, fence.CountedActiveSlot, fence.CreatedAtMillis, fence.PreparedAtMillis,
		fence.ActivatedControlVersion, fence.ReadyControlVersion, fence.AAKEnqueuedAtMillis, fence.AAKTransactionID,
		activation.ControlCellID, activation.CaughtUpControlVersion)))
	token := "sc-" + action + "-" + hex.EncodeToString(digest[:12])
	return aws.String(token)
}

func sessionControlTargetTransactionValues(fence sessionControlTargetFence) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		":target_kind":               &types.AttributeValueMemberS{Value: sessionControlTargetKind},
		":target_schema":             &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlTargetSchema)},
		":ac_id":                     &types.AttributeValueMemberS{Value: fence.ACID},
		":public_key":                &types.AttributeValueMemberS{Value: fence.PublicKey},
		":boot_id":                   &types.AttributeValueMemberS{Value: fence.BootID},
		":flush_generation":          &types.AttributeValueMemberN{Value: fmt.Sprint(fence.FlushGeneration)},
		":control_cell_id":           &types.AttributeValueMemberS{Value: fence.ControlCellID},
		":activated_control_version": &types.AttributeValueMemberN{Value: fmt.Sprint(fence.ActivatedControlVersion)},
		":ready_control_version":     &types.AttributeValueMemberN{Value: fmt.Sprint(fence.ReadyControlVersion)},
		":aak_enqueued_at":           &types.AttributeValueMemberN{Value: fmt.Sprint(fence.AAKEnqueuedAtMillis)},
		":aak_transaction_id":        &types.AttributeValueMemberN{Value: fmt.Sprint(fence.AAKTransactionID)},
		":created_at":                &types.AttributeValueMemberN{Value: fmt.Sprint(fence.CreatedAtMillis)},
		":prepared_at":               &types.AttributeValueMemberN{Value: fmt.Sprint(fence.PreparedAtMillis)},
		":current_state":             &types.AttributeValueMemberS{Value: string(sessionControlTargetPreparing)},
		":current_version":           &types.AttributeValueMemberN{Value: fmt.Sprint(fence.Version)},
		":current_authority_version": &types.AttributeValueMemberN{Value: fmt.Sprint(fence.AuthorityVersion)},
		":counted_active_slot":       &types.AttributeValueMemberBOOL{Value: fence.CountedActiveSlot},
	}
}

func sessionControlExpectedActivatedTarget(activation sessionControlTargetActivation) sessionControlTargetAuthority {
	fence := activation.Fence
	authorityVersion := fence.AuthorityVersion
	if !fence.CountedActiveSlot {
		authorityVersion++
	}
	return sessionControlTargetAuthority{
		ACID: fence.ACID, PublicKey: fence.PublicKey, BootID: fence.BootID,
		FlushGeneration: fence.FlushGeneration, State: sessionControlTargetActive,
		Version: fence.Version + 1, AuthorityVersion: authorityVersion, CountedActiveSlot: true,
		ControlCellID: fence.ControlCellID, ActivatedControlVersion: activation.CaughtUpControlVersion,
		ReadyControlVersion: 0, AAKEnqueuedAtMillis: 0, AAKTransactionID: 0,
		CreatedAtMillis: fence.CreatedAtMillis, PreparedAtMillis: fence.PreparedAtMillis,
		UpdatedAtMillis: fence.PreparedAtMillis,
	}
}

// ActivateTarget commits target membership and the exact catch-up cursor, but
// deliberately leaves the target authority-unready until its success AAK has
// been enqueued and FinalizeTargetReady commits that audit boundary.
func (s *dynamoSessionControlStore) ActivateTarget(ctx context.Context, activation sessionControlTargetActivation) (*sessionControlTargetAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlTargetActivation(activation) {
		return nil, errors.New("invalid session-control target activation")
	}
	fence := activation.Fence
	if fence.Version >= ^uint64(0)-2 {
		return nil, errSessionControlTargetCorrupt
	}
	if !fence.CountedActiveSlot && fence.AuthorityVersion >= ^uint64(0)-1 {
		return nil, errSessionControlTargetCorrupt
	}
	currentOwner, err := s.getOwner(ctx, fence.ControlCellID, fence.ACID, fence.PublicKey)
	if err != nil {
		return nil, err
	}
	if currentOwner.Phase == sessionControlOwnerActiveUnready {
		current, currentErr := s.getTarget(ctx, fence.key())
		if currentErr != nil {
			return nil, currentErr
		}
		expected := sessionControlExpectedActivatedTarget(activation)
		if *current == expected && currentOwner.exactTarget(*current, sessionControlOwnerActiveUnready) {
			return current, nil
		}
		return nil, errSessionControlOwnerConflict
	}
	preparingTarget := sessionControlTargetAuthority{
		ACID: fence.ACID, PublicKey: fence.PublicKey, BootID: fence.BootID,
		FlushGeneration: fence.FlushGeneration, State: sessionControlTargetPreparing,
		Version: fence.Version, AuthorityVersion: fence.AuthorityVersion,
		CountedActiveSlot: fence.CountedActiveSlot, ControlCellID: fence.ControlCellID,
		ActivatedControlVersion: fence.ActivatedControlVersion, ReadyControlVersion: fence.ReadyControlVersion,
		AAKEnqueuedAtMillis: fence.AAKEnqueuedAtMillis, AAKTransactionID: fence.AAKTransactionID,
		CreatedAtMillis: fence.CreatedAtMillis, PreparedAtMillis: fence.PreparedAtMillis,
		UpdatedAtMillis: fence.PreparedAtMillis,
	}
	if !currentOwner.exactTarget(preparingTarget, sessionControlOwnerPreparing) {
		return nil, errSessionControlOwnerConflict
	}
	// The activation request must be byte-for-byte stable for DynamoDB's
	// ClientRequestToken idempotency window. PreparedAtMillis is the immutable
	// start of this catch-up attempt and is therefore also its stable update
	// timestamp; a retry cannot accidentally change the transaction parameters.
	nowMillis := fence.PreparedAtMillis
	nextAuthorityVersion := fence.AuthorityVersion
	values := sessionControlTargetTransactionValues(fence)
	values[":next_state"] = &types.AttributeValueMemberS{Value: string(sessionControlTargetActive)}
	values[":next_version"] = &types.AttributeValueMemberN{Value: fmt.Sprint(fence.Version + 1)}
	values[":counted"] = &types.AttributeValueMemberBOOL{Value: true}
	values[":updated_at"] = &types.AttributeValueMemberN{Value: fmt.Sprint(nowMillis)}
	values[":caught_up_control_version"] = &types.AttributeValueMemberN{Value: fmt.Sprint(activation.CaughtUpControlVersion)}
	values[":zero_control_version"] = &types.AttributeValueMemberN{Value: "0"}
	values[":zero_time"] = &types.AttributeValueMemberN{Value: "0"}
	values[":zero_transaction"] = &types.AttributeValueMemberN{Value: "0"}

	authorityValues := map[string]types.AttributeValue{
		":authority_kind":    &types.AttributeValueMemberS{Value: sessionControlAuthorityKind},
		":authority_schema":  &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlAuthoritySchema)},
		":ac_id":             &types.AttributeValueMemberS{Value: fence.ACID},
		":authority_version": &types.AttributeValueMemberN{Value: fmt.Sprint(fence.AuthorityVersion)},
		":control_cell_id":   &types.AttributeValueMemberS{Value: activation.ControlCellID},
	}
	authorityCondition := "kind = :authority_kind AND schema_version = :authority_schema AND ac_id = :ac_id AND #version = :authority_version"
	var authorityWrite types.TransactWriteItem
	if fence.CountedActiveSlot {
		authorityWrite.ConditionCheck = &types.ConditionCheck{
			TableName:                 aws.String(s.tableName),
			Key:                       sessionControlAuthorityDynamoKey(fence.ACID),
			ConditionExpression:       aws.String(authorityCondition + " AND control_cell_id = :control_cell_id"),
			ExpressionAttributeNames:  map[string]string{"#version": "version"},
			ExpressionAttributeValues: authorityValues,
		}
	} else {
		nextAuthorityVersion++
		values[":next_authority_version"] = &types.AttributeValueMemberN{Value: fmt.Sprint(nextAuthorityVersion)}
		authorityValues[":next_authority_version"] = &types.AttributeValueMemberN{Value: fmt.Sprint(nextAuthorityVersion)}
		authorityValues[":capacity"] = &types.AttributeValueMemberN{Value: fmt.Sprint(MaxACConnsPerID)}
		authorityValues[":next_count"] = &types.AttributeValueMemberN{Value: "1"}
		authorityValues[":updated_at"] = &types.AttributeValueMemberN{Value: fmt.Sprint(nowMillis)}
		authorityValues[":zero"] = &types.AttributeValueMemberN{Value: "0"}
		authorityWrite.Update = &types.Update{
			TableName:                 aws.String(s.tableName),
			Key:                       sessionControlAuthorityDynamoKey(fence.ACID),
			UpdateExpression:          aws.String("SET #version = :next_authority_version, control_cell_id = :control_cell_id, active_target_count = active_target_count + :next_count, updated_at_ms = :updated_at"),
			ConditionExpression:       aws.String(authorityCondition + " AND active_target_count < :capacity AND ((attribute_not_exists(control_cell_id) AND active_target_count = :zero) OR control_cell_id = :control_cell_id)"),
			ExpressionAttributeNames:  map[string]string{"#version": "version"},
			ExpressionAttributeValues: authorityValues,
		}
	}
	values[":next_authority_version"] = &types.AttributeValueMemberN{Value: fmt.Sprint(nextAuthorityVersion)}
	nextTarget := preparingTarget
	nextTarget.State = sessionControlTargetActive
	nextTarget.Version = fence.Version + 1
	nextTarget.AuthorityVersion = nextAuthorityVersion
	nextTarget.CountedActiveSlot = true
	nextTarget.ActivatedControlVersion = activation.CaughtUpControlVersion
	nextTarget.UpdatedAtMillis = nowMillis
	nextOwner, ownerErr := sessionControlOwnerFromTarget(nextTarget, currentOwner, sessionControlOwnerActiveUnready)
	if ownerErr != nil {
		return nil, ownerErr
	}
	ownerWrite, ownerErr := sessionControlOwnerReplace(s.tableName, *currentOwner, nextOwner)
	if ownerErr != nil {
		return nil, ownerErr
	}
	targetWrite := types.TransactWriteItem{Update: &types.Update{
		TableName:                 aws.String(s.tableName),
		Key:                       sessionControlTargetDynamoKey(sessionControlTargetKey{ACID: fence.ACID, PublicKey: fence.PublicKey}),
		UpdateExpression:          aws.String("SET #state = :next_state, #version = :next_version, authority_version = :next_authority_version, counted_active_slot = :counted, activated_control_version = :caught_up_control_version, ready_control_version = :zero_control_version, aak_enqueued_at_ms = :zero_time, aak_transaction_id = :zero_transaction, updated_at_ms = :updated_at"),
		ConditionExpression:       aws.String(sessionControlTargetTransactionCondition()),
		ExpressionAttributeNames:  map[string]string{"#state": "state", "#version": "version"},
		ExpressionAttributeValues: values,
	}}
	controlWrite := types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName:           aws.String(s.tableName),
		Key:                 sessionControlFenceDirectoryKey(activation.ControlCellID),
		ConditionExpression: aws.String("kind = :control_kind AND schema_version = :control_schema AND cell_id = :control_cell_id AND #control_version = :caught_up_control_version AND admission_blocked = :admission_blocked AND overflow_close_count = :overflow_close_count AND overflow_leader_event_id = :leader_event_id AND overflow_leader_prepared_directory_version = :leader_prepared_version AND overflow_leader_selected_directory_version = :leader_selected_version AND attribute_not_exists(#ttl)"),
		ExpressionAttributeNames: map[string]string{
			"#control_version": "version", "#ttl": "ttl",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":control_kind":              &types.AttributeValueMemberS{Value: sessionControlFenceDirectoryKind},
			":control_schema":            &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlFenceSchema)},
			":control_cell_id":           &types.AttributeValueMemberS{Value: activation.ControlCellID},
			":caught_up_control_version": &types.AttributeValueMemberN{Value: fmt.Sprint(activation.CaughtUpControlVersion)},
			":admission_blocked":         &types.AttributeValueMemberBOOL{Value: false},
			":overflow_close_count":      &types.AttributeValueMemberN{Value: "0"},
			":leader_event_id":           &types.AttributeValueMemberS{Value: ""},
			":leader_prepared_version":   &types.AttributeValueMemberN{Value: "0"},
			":leader_selected_version":   &types.AttributeValueMemberN{Value: "0"},
		},
	}}

	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	_, err = s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: sessionControlOwnerTransitionToken("activate", currentOwner, nextOwner),
		TransactItems:      []types.TransactWriteItem{targetWrite, authorityWrite, controlWrite, ownerWrite},
	})
	cancel()
	if err != nil {
		resultCtx, resultCancel := s.sessionResultContext(ctx)
		classified, classifyErr := s.classifyActivationConflict(resultCtx, activation)
		resultCancel()
		if classifyErr == nil {
			return classified, nil
		}
		var canceled *types.TransactionCanceledException
		if errors.As(err, &canceled) {
			return nil, classifyErr
		}
		return nil, fmt.Errorf("activate session-control target: %w", err)
	}
	return &nextTarget, nil
}

func (s *dynamoSessionControlStore) classifyActivationConflict(ctx context.Context, activation sessionControlTargetActivation) (*sessionControlTargetAuthority, error) {
	fence := activation.Fence
	current, err := s.getTarget(ctx, sessionControlTargetKey{ACID: fence.ACID, PublicKey: fence.PublicKey})
	if err != nil {
		return nil, err
	}
	expected := sessionControlExpectedActivatedTarget(activation)
	if *current == expected {
		owner, ownerErr := s.getOwner(ctx, fence.ControlCellID, fence.ACID, fence.PublicKey)
		if ownerErr != nil {
			return nil, ownerErr
		}
		if !owner.exactTarget(*current, sessionControlOwnerActiveUnready) {
			return nil, errSessionControlOwnerCorrupt
		}
		return current, nil
	}
	directory, directoryErr := s.getFenceDirectory(ctx, activation.ControlCellID)
	if directoryErr != nil {
		if errors.Is(directoryErr, errSessionControlFenceNotFound) {
			return nil, errSessionControlTargetControlStale
		}
		return nil, directoryErr
	}
	if directory.AdmissionBlocked {
		return nil, errSessionControlAdmissionBlocked
	}
	if directory.Version != activation.CaughtUpControlVersion {
		return nil, errSessionControlTargetControlStale
	}
	if current.State == sessionControlTargetRetired {
		return nil, errSessionControlTargetRetired
	}
	authority, err := s.getAuthority(ctx, fence.ACID)
	if err != nil {
		return nil, err
	}
	if authority.ControlCellID != "" && authority.ControlCellID != activation.ControlCellID {
		return nil, errSessionControlTargetConflict
	}
	if !fence.CountedActiveSlot && authority.Version == fence.AuthorityVersion && authority.ActiveTargetCount >= uint64(MaxACConnsPerID) {
		return nil, errSessionControlTargetCapacity
	}
	return nil, errSessionControlTargetConflict
}

func sessionControlReadinessToken(readiness sessionControlTargetReadiness) *string {
	fence := readiness.Fence
	directory := readiness.ControlDirectory
	hasher := sha256.New()
	for _, part := range []any{
		"v1", fence.ACID, fence.PublicKey, fence.BootID, fence.FlushGeneration, fence.Version,
		fence.AuthorityVersion, fence.CountedActiveSlot, fence.ControlCellID,
		fence.ActivatedControlVersion, fence.ReadyControlVersion, fence.AAKEnqueuedAtMillis,
		fence.AAKTransactionID, fence.CreatedAtMillis, fence.PreparedAtMillis,
		readiness.AAKEnqueuedAtMillis, readiness.AAKTransactionID,
		directory.CellID, directory.DirectoryVersion, directory.ActiveFenceCount,
		directory.AdmissionBlocked, directory.OverflowCloseCount,
		directory.OverflowLeaderEventID, directory.OverflowLeaderPreparedDirectoryVersion,
		directory.OverflowLeaderSelectedDirectoryVersion,
	} {
		_, _ = fmt.Fprintf(hasher, "\x00%v", part)
	}
	token := "sc-ready-" + hex.EncodeToString(hasher.Sum(nil)[:12])
	return aws.String(token)
}

func sessionControlTargetDirectoryCondition(fence sessionControlTargetDirectoryFence) types.TransactWriteItem {
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		Key:                      sessionControlFenceDirectoryKey(fence.CellID),
		ConditionExpression:      aws.String("kind = :kind AND schema_version = :schema AND cell_id = :cell_id AND #version = :version AND active_fence_count = :count AND admission_blocked = :admission_blocked AND overflow_close_count = :overflow_close_count AND overflow_leader_event_id = :leader_event_id AND overflow_leader_prepared_directory_version = :leader_prepared_version AND overflow_leader_selected_directory_version = :leader_selected_version AND attribute_not_exists(#ttl)"),
		ExpressionAttributeNames: map[string]string{"#version": "version", "#ttl": "ttl"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":kind":                    &types.AttributeValueMemberS{Value: sessionControlFenceDirectoryKind},
			":schema":                  &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlFenceSchema)},
			":cell_id":                 &types.AttributeValueMemberS{Value: fence.CellID},
			":version":                 &types.AttributeValueMemberN{Value: fmt.Sprint(fence.DirectoryVersion)},
			":count":                   &types.AttributeValueMemberN{Value: fmt.Sprint(fence.ActiveFenceCount)},
			":admission_blocked":       &types.AttributeValueMemberBOOL{Value: fence.AdmissionBlocked},
			":overflow_close_count":    &types.AttributeValueMemberN{Value: fmt.Sprint(fence.OverflowCloseCount)},
			":leader_event_id":         &types.AttributeValueMemberS{Value: fence.OverflowLeaderEventID},
			":leader_prepared_version": &types.AttributeValueMemberN{Value: fmt.Sprint(fence.OverflowLeaderPreparedDirectoryVersion)},
			":leader_selected_version": &types.AttributeValueMemberN{Value: fmt.Sprint(fence.OverflowLeaderSelectedDirectoryVersion)},
		},
	}}
}

func sessionControlTargetFinalizedExact(current sessionControlTargetAuthority,
	readiness sessionControlTargetReadiness) bool {
	fence := readiness.Fence
	return current.exactFence(fence) && current.State == sessionControlTargetActive &&
		current.Version == fence.Version+1 && current.AuthorityVersion == fence.AuthorityVersion &&
		current.CountedActiveSlot == fence.CountedActiveSlot &&
		current.ActivatedControlVersion == fence.ActivatedControlVersion &&
		current.ReadyControlVersion == fence.ActivatedControlVersion &&
		current.AAKEnqueuedAtMillis == readiness.AAKEnqueuedAtMillis &&
		current.AAKTransactionID == readiness.AAKTransactionID &&
		current.UpdatedAtMillis == readiness.AAKEnqueuedAtMillis &&
		current.RetiredAtMillis == 0
}

func sessionControlOwnerMatchesFinalizedTarget(owner sessionControlOwnerAuthority,
	target sessionControlTargetAuthority) bool {
	if owner.LifecycleVersion < 2 {
		return false
	}
	if owner.exactTarget(target, sessionControlOwnerReady) {
		return true
	}
	return owner.PendingCount > 0 && owner.exactTarget(target, sessionControlOwnerActiveUnready)
}

// FinalizeTargetReady is the only transition that makes an ACTIVE target
// eligible for new AOP intent materialization. It orders the AAK enqueue audit
// against the exact CONTROL directory observed by catch-up.
func (s *dynamoSessionControlStore) FinalizeTargetReady(ctx context.Context,
	readiness sessionControlTargetReadiness) (*sessionControlTargetAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlTargetReadiness(readiness) {
		return nil, errors.New("invalid session-control target readiness")
	}
	fence := readiness.Fence
	activeTarget := sessionControlTargetAuthority{
		ACID: fence.ACID, PublicKey: fence.PublicKey, BootID: fence.BootID,
		FlushGeneration: fence.FlushGeneration, State: sessionControlTargetActive,
		Version: fence.Version, AuthorityVersion: fence.AuthorityVersion,
		CountedActiveSlot: fence.CountedActiveSlot, ControlCellID: fence.ControlCellID,
		ActivatedControlVersion: fence.ActivatedControlVersion, ReadyControlVersion: fence.ReadyControlVersion,
		AAKEnqueuedAtMillis: fence.AAKEnqueuedAtMillis, AAKTransactionID: fence.AAKTransactionID,
		CreatedAtMillis: fence.CreatedAtMillis, PreparedAtMillis: fence.PreparedAtMillis,
		UpdatedAtMillis: fence.PreparedAtMillis,
	}
	currentOwner, ownerErr := s.getOwner(ctx, fence.ControlCellID, fence.ACID, fence.PublicKey)
	if ownerErr != nil {
		return nil, ownerErr
	}
	if currentOwner.Phase == sessionControlOwnerReady ||
		(currentOwner.Phase == sessionControlOwnerActiveUnready && currentOwner.ReadyControlVersion > 0) {
		current, getErr := s.getTarget(ctx, fence.key())
		if getErr != nil {
			return nil, getErr
		}
		if !sessionControlTargetFinalizedExact(*current, readiness) ||
			!sessionControlOwnerMatchesFinalizedTarget(*currentOwner, *current) {
			return nil, errSessionControlOwnerConflict
		}
		return current, nil
	}
	if !currentOwner.exactTarget(activeTarget, sessionControlOwnerActiveUnready) || currentOwner.PendingCount != 0 {
		return nil, errSessionControlOwnerConflict
	}
	nextTarget := activeTarget
	nextTarget.Version++
	nextTarget.ReadyControlVersion = fence.ActivatedControlVersion
	nextTarget.AAKEnqueuedAtMillis = readiness.AAKEnqueuedAtMillis
	nextTarget.AAKTransactionID = readiness.AAKTransactionID
	nextTarget.UpdatedAtMillis = readiness.AAKEnqueuedAtMillis
	nextOwner, ownerErr := sessionControlOwnerFromTarget(nextTarget, currentOwner, sessionControlOwnerReady)
	if ownerErr != nil {
		return nil, ownerErr
	}
	ownerWrite, ownerErr := sessionControlOwnerReplace(s.tableName, *currentOwner, nextOwner)
	if ownerErr != nil {
		return nil, ownerErr
	}
	values := sessionControlTargetTransactionValues(fence)
	values[":current_state"] = &types.AttributeValueMemberS{Value: string(sessionControlTargetActive)}
	values[":next_version"] = &types.AttributeValueMemberN{Value: fmt.Sprint(fence.Version + 1)}
	values[":next_ready_control_version"] = &types.AttributeValueMemberN{Value: fmt.Sprint(fence.ActivatedControlVersion)}
	values[":next_aak_enqueued_at"] = &types.AttributeValueMemberN{Value: fmt.Sprint(readiness.AAKEnqueuedAtMillis)}
	values[":next_aak_transaction_id"] = &types.AttributeValueMemberN{Value: fmt.Sprint(readiness.AAKTransactionID)}
	targetWrite := types.TransactWriteItem{Update: &types.Update{
		TableName:                 aws.String(s.tableName),
		Key:                       sessionControlTargetDynamoKey(fence.key()),
		UpdateExpression:          aws.String("SET #version = :next_version, ready_control_version = :next_ready_control_version, aak_enqueued_at_ms = :next_aak_enqueued_at, aak_transaction_id = :next_aak_transaction_id, updated_at_ms = :next_aak_enqueued_at"),
		ConditionExpression:       aws.String(sessionControlTargetTransactionCondition() + " AND attribute_not_exists(retired_at_ms) AND attribute_not_exists(#ttl)"),
		ExpressionAttributeNames:  map[string]string{"#state": "state", "#version": "version", "#ttl": "ttl"},
		ExpressionAttributeValues: values,
	}}
	directoryWrite := sessionControlTargetDirectoryCondition(readiness.ControlDirectory)
	directoryWrite.ConditionCheck.TableName = aws.String(s.tableName)
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	_, writeErr := s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: sessionControlOwnerTransitionToken("ready", currentOwner, nextOwner),
		TransactItems:      []types.TransactWriteItem{targetWrite, directoryWrite, ownerWrite},
	})
	operationErr := opCtx.Err()
	cancel()
	if writeErr == nil {
		return &nextTarget, nil
	}
	resultCtx, resultCancel := s.sessionResultContext(ctx)
	defer resultCancel()
	current, err := s.getTarget(resultCtx, fence.key())
	if err != nil {
		return nil, err
	}
	// DynamoDB may have committed before a timeout or lost response. The exact
	// immutable target result is authoritative even if a later event advanced the
	// CONTROL directory after this finalize transaction committed.
	if sessionControlTargetFinalizedExact(*current, readiness) {
		owner, ownerErr := s.getOwner(resultCtx, fence.ControlCellID, fence.ACID, fence.PublicKey)
		if ownerErr != nil {
			return nil, ownerErr
		}
		if !sessionControlOwnerMatchesFinalizedTarget(*owner, *current) {
			return nil, errSessionControlOwnerCorrupt
		}
		return current, nil
	}
	directory, err := s.getFenceDirectory(resultCtx, readiness.ControlDirectory.CellID)
	if err != nil {
		if errors.Is(err, errSessionControlFenceNotFound) {
			return nil, errSessionControlTargetControlStale
		}
		return nil, err
	}
	expected := readiness.ControlDirectory
	if directory.AdmissionBlocked {
		return nil, errSessionControlAdmissionBlocked
	}
	if directory.CellID != expected.CellID || directory.Version != expected.DirectoryVersion ||
		directory.ActiveFenceCount != expected.ActiveFenceCount ||
		directory.AdmissionBlocked != expected.AdmissionBlocked ||
		directory.OverflowCloseCount != expected.OverflowCloseCount ||
		directory.OverflowLeaderEventID != expected.OverflowLeaderEventID ||
		directory.OverflowLeaderPreparedDirectoryVersion != expected.OverflowLeaderPreparedDirectoryVersion ||
		directory.OverflowLeaderSelectedDirectoryVersion != expected.OverflowLeaderSelectedDirectoryVersion {
		return nil, errSessionControlTargetControlStale
	}
	if current.State == sessionControlTargetRetired {
		return nil, errSessionControlTargetRetired
	}
	if operationErr != nil {
		return nil, fmt.Errorf("finalize session-control target readiness: %w", operationErr)
	}
	return nil, errSessionControlTargetConflict
}

func (s *dynamoSessionControlStore) classifyTransitionConflict(ctx context.Context, fence sessionControlTargetFence, intended sessionControlTargetState) (*sessionControlTargetAuthority, error) {
	current, err := s.getTarget(ctx, sessionControlTargetKey{ACID: fence.ACID, PublicKey: fence.PublicKey})
	if err != nil {
		return nil, err
	}
	if current.State == sessionControlTargetRetired {
		if intended == sessionControlTargetRetired && current.exactFence(fence) && current.Version == fence.Version+1 &&
			current.ActivatedControlVersion == fence.ActivatedControlVersion &&
			current.ReadyControlVersion == fence.ReadyControlVersion &&
			current.AAKEnqueuedAtMillis == fence.AAKEnqueuedAtMillis && current.AAKTransactionID == fence.AAKTransactionID {
			return current, nil
		}
		return nil, errSessionControlTargetRetired
	}
	if current.exactFence(fence) && current.State == intended && current.Version == fence.Version+1 &&
		current.AuthorityVersion == fence.AuthorityVersion && current.CountedActiveSlot == fence.CountedActiveSlot &&
		current.ActivatedControlVersion == fence.ActivatedControlVersion &&
		current.ReadyControlVersion == fence.ReadyControlVersion &&
		current.AAKEnqueuedAtMillis == fence.AAKEnqueuedAtMillis && current.AAKTransactionID == fence.AAKTransactionID {
		return current, nil
	}
	return nil, errSessionControlTargetConflict
}

func sessionControlRetiredTargetMatchesFence(target sessionControlTargetAuthority, fence sessionControlTargetFence) bool {
	expectedAuthorityVersion := fence.AuthorityVersion
	if fence.CountedActiveSlot {
		if expectedAuthorityVersion >= ^uint64(0)-1 {
			return false
		}
		expectedAuthorityVersion++
	}
	return target.State == sessionControlTargetRetired && target.exactFence(fence) &&
		target.Version == fence.Version+1 && target.AuthorityVersion == expectedAuthorityVersion &&
		!target.CountedActiveSlot &&
		target.ActivatedControlVersion == fence.ActivatedControlVersion &&
		target.ReadyControlVersion == fence.ReadyControlVersion &&
		target.AAKEnqueuedAtMillis == fence.AAKEnqueuedAtMillis &&
		target.AAKTransactionID == fence.AAKTransactionID &&
		target.UpdatedAtMillis >= fence.PreparedAtMillis && target.RetiredAtMillis == target.UpdatedAtMillis
}

func (s *dynamoSessionControlStore) classifyRetiredTarget(ctx context.Context,
	fence sessionControlTargetFence) (*sessionControlTargetAuthority, error) {
	current, err := s.getTarget(ctx, fence.key())
	if err != nil {
		return nil, err
	}
	if !sessionControlRetiredTargetMatchesFence(*current, fence) {
		if current.State == sessionControlTargetRetired {
			return nil, errSessionControlTargetRetired
		}
		return nil, errSessionControlTargetConflict
	}
	owner, err := s.getOwner(ctx, current.ControlCellID, current.ACID, current.PublicKey)
	if err != nil {
		return nil, err
	}
	if owner.TaskCount != 0 || owner.PendingCount != 0 || !owner.exactTarget(*current, sessionControlOwnerRetired) {
		return nil, errSessionControlOwnerCorrupt
	}
	return current, nil
}

func (s *dynamoSessionControlStore) CancelTargetPreparation(ctx context.Context, fence sessionControlTargetFence) (*sessionControlTargetAuthority, error) {
	return s.cancelPreparedTarget(ctx, fence)
}

// retireTarget is intentionally below the UdpServer-facing sessionControlStore
// interface. Permanent key retirement requires a separately authenticated and
// audited operator path; ordinary AOL/runtime code must not acquire that power.
func (s *dynamoSessionControlStore) retireTarget(ctx context.Context, fence sessionControlTargetFence) (*sessionControlTargetAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlTargetFence(fence) {
		return nil, errors.New("invalid session-control target fence")
	}
	if fence.Version >= ^uint64(0)-1 {
		return nil, errSessionControlTargetCorrupt
	}
	current, err := s.getTarget(ctx, sessionControlTargetKey{ACID: fence.ACID, PublicKey: fence.PublicKey})
	if err != nil {
		return nil, err
	}
	if current.State == sessionControlTargetRetired {
		return s.classifyRetiredTarget(ctx, fence)
	}
	if !current.exactFence(fence) || current.Version != fence.Version ||
		current.AuthorityVersion != fence.AuthorityVersion || current.CountedActiveSlot != fence.CountedActiveSlot ||
		current.ActivatedControlVersion != fence.ActivatedControlVersion ||
		current.ReadyControlVersion != fence.ReadyControlVersion ||
		current.AAKEnqueuedAtMillis != fence.AAKEnqueuedAtMillis || current.AAKTransactionID != fence.AAKTransactionID {
		return nil, errSessionControlTargetConflict
	}
	currentOwner, ownerErr := s.getOwner(ctx, current.ControlCellID, current.ACID, current.PublicKey)
	if ownerErr != nil {
		return nil, ownerErr
	}
	expectedOwnerPhase := sessionControlOwnerPreparing
	if current.ready() {
		expectedOwnerPhase = sessionControlOwnerReady
	} else if current.State == sessionControlTargetActive {
		expectedOwnerPhase = sessionControlOwnerActiveUnready
	}
	if !currentOwner.exactTarget(*current, expectedOwnerPhase) {
		return nil, errSessionControlOwnerCorrupt
	}
	if currentOwner.PendingCount != 0 {
		return nil, errSessionControlOwnerConflict
	}
	authority, err := s.getAuthority(ctx, fence.ACID)
	if err != nil {
		return nil, err
	}
	if current.CountedActiveSlot && authority.ActiveTargetCount == 0 {
		return nil, errSessionControlTargetCorrupt
	}
	if current.CountedActiveSlot && authority.Version >= ^uint64(0)-1 {
		return nil, errSessionControlTargetCorrupt
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	nowMillis := now.UnixMilli()
	if nowMillis < current.UpdatedAtMillis {
		nowMillis = current.UpdatedAtMillis
	}
	nextHeaderVersion := authority.Version
	if current.CountedActiveSlot {
		nextHeaderVersion++
	}
	nextTargetAuthorityVersion := current.AuthorityVersion
	if current.CountedActiveSlot {
		nextTargetAuthorityVersion++
	}
	targetValues := map[string]types.AttributeValue{
		":target_kind":               &types.AttributeValueMemberS{Value: sessionControlTargetKind},
		":target_schema":             &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlTargetSchema)},
		":ac_id":                     &types.AttributeValueMemberS{Value: current.ACID},
		":public_key":                &types.AttributeValueMemberS{Value: current.PublicKey},
		":boot_id":                   &types.AttributeValueMemberS{Value: current.BootID},
		":flush_generation":          &types.AttributeValueMemberN{Value: fmt.Sprint(current.FlushGeneration)},
		":control_cell_id":           &types.AttributeValueMemberS{Value: current.ControlCellID},
		":activated_control_version": &types.AttributeValueMemberN{Value: fmt.Sprint(current.ActivatedControlVersion)},
		":ready_control_version":     &types.AttributeValueMemberN{Value: fmt.Sprint(current.ReadyControlVersion)},
		":aak_enqueued_at":           &types.AttributeValueMemberN{Value: fmt.Sprint(current.AAKEnqueuedAtMillis)},
		":aak_transaction_id":        &types.AttributeValueMemberN{Value: fmt.Sprint(current.AAKTransactionID)},
		":created_at":                &types.AttributeValueMemberN{Value: fmt.Sprint(current.CreatedAtMillis)},
		":prepared_at":               &types.AttributeValueMemberN{Value: fmt.Sprint(current.PreparedAtMillis)},
		":current_state":             &types.AttributeValueMemberS{Value: string(current.State)},
		":current_version":           &types.AttributeValueMemberN{Value: fmt.Sprint(current.Version)},
		":current_authority_version": &types.AttributeValueMemberN{Value: fmt.Sprint(current.AuthorityVersion)},
		":counted_active_slot":       &types.AttributeValueMemberBOOL{Value: current.CountedActiveSlot},
		":retired":                   &types.AttributeValueMemberS{Value: string(sessionControlTargetRetired)},
		":next_version":              &types.AttributeValueMemberN{Value: fmt.Sprint(current.Version + 1)},
		":next_authority_version":    &types.AttributeValueMemberN{Value: fmt.Sprint(nextTargetAuthorityVersion)},
		":not_counted":               &types.AttributeValueMemberBOOL{Value: false},
		":updated_at":                &types.AttributeValueMemberN{Value: fmt.Sprint(nowMillis)},
		":retired_at":                &types.AttributeValueMemberN{Value: fmt.Sprint(nowMillis)},
	}
	targetWrite := types.TransactWriteItem{Update: &types.Update{
		TableName:                 aws.String(s.tableName),
		Key:                       sessionControlTargetDynamoKey(current.key()),
		UpdateExpression:          aws.String("SET #state = :retired, #version = :next_version, authority_version = :next_authority_version, counted_active_slot = :not_counted, updated_at_ms = :updated_at, retired_at_ms = :retired_at"),
		ConditionExpression:       aws.String(sessionControlTargetTransactionCondition()),
		ExpressionAttributeNames:  map[string]string{"#state": "state", "#version": "version"},
		ExpressionAttributeValues: targetValues,
	}}
	retiredTarget := *current
	retiredTarget.State = sessionControlTargetRetired
	retiredTarget.Version++
	retiredTarget.AuthorityVersion = nextTargetAuthorityVersion
	retiredTarget.CountedActiveSlot = false
	retiredTarget.UpdatedAtMillis = nowMillis
	retiredTarget.RetiredAtMillis = nowMillis
	retiredOwner, ownerErr := sessionControlOwnerFromTarget(retiredTarget, currentOwner, sessionControlOwnerRetired)
	if ownerErr != nil {
		return nil, ownerErr
	}
	ownerWrite, ownerErr := sessionControlOwnerReplace(s.tableName, *currentOwner, retiredOwner)
	if ownerErr != nil {
		return nil, ownerErr
	}
	authorityValues := map[string]types.AttributeValue{
		":authority_kind":    &types.AttributeValueMemberS{Value: sessionControlAuthorityKind},
		":authority_schema":  &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlAuthoritySchema)},
		":ac_id":             &types.AttributeValueMemberS{Value: fence.ACID},
		":authority_version": &types.AttributeValueMemberN{Value: fmt.Sprint(authority.Version)},
		":control_cell_id":   &types.AttributeValueMemberS{Value: current.ControlCellID},
	}
	authorityCondition := "kind = :authority_kind AND schema_version = :authority_schema AND ac_id = :ac_id AND #version = :authority_version"
	var authorityWrite types.TransactWriteItem
	if current.CountedActiveSlot {
		authorityCondition += " AND control_cell_id = :control_cell_id"
		authorityValues[":next_authority_version"] = &types.AttributeValueMemberN{Value: fmt.Sprint(nextHeaderVersion)}
		authorityValues[":one"] = &types.AttributeValueMemberN{Value: "1"}
		authorityValues[":updated_at"] = &types.AttributeValueMemberN{Value: fmt.Sprint(nowMillis)}
		authorityWrite.Update = &types.Update{
			TableName:                 aws.String(s.tableName),
			Key:                       sessionControlAuthorityDynamoKey(fence.ACID),
			UpdateExpression:          aws.String("SET #version = :next_authority_version, active_target_count = active_target_count - :one, updated_at_ms = :updated_at"),
			ConditionExpression:       aws.String(authorityCondition + " AND active_target_count >= :one"),
			ExpressionAttributeNames:  map[string]string{"#version": "version"},
			ExpressionAttributeValues: authorityValues,
		}
	} else {
		authorityCondition += " AND (attribute_not_exists(control_cell_id) OR control_cell_id = :control_cell_id)"
		authorityWrite.ConditionCheck = &types.ConditionCheck{
			TableName:                 aws.String(s.tableName),
			Key:                       sessionControlAuthorityDynamoKey(fence.ACID),
			ConditionExpression:       aws.String(authorityCondition),
			ExpressionAttributeNames:  map[string]string{"#version": "version"},
			ExpressionAttributeValues: authorityValues,
		}
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	_, err = s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: sessionControlOwnerTransitionToken("retire", currentOwner, retiredOwner),
		TransactItems:      []types.TransactWriteItem{targetWrite, authorityWrite, ownerWrite},
	})
	cancel()
	if err != nil {
		resultCtx, resultCancel := s.sessionResultContext(ctx)
		classified, classifyErr := s.classifyRetiredTarget(resultCtx, fence)
		resultCancel()
		if classifyErr == nil {
			return classified, nil
		}
		var canceled *types.TransactionCanceledException
		if errors.As(err, &canceled) {
			return nil, classifyErr
		}
		return nil, fmt.Errorf("retire session-control target: %w", err)
	}
	return &retiredTarget, nil
}
