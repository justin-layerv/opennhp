package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/OpenNHP/opennhp/nhp/common"
)

const (
	sessionControlCloseManifestKind              = "close_manifest"
	sessionControlCloseManifestSchema            = uint64(1)
	sessionControlCloseManifestSKPrefix          = "MANIFEST#"
	sessionControlCloseTaskKind                  = "close_task"
	sessionControlCloseTaskSchema                = uint64(1)
	sessionControlCloseTaskSKPrefix              = "TASK#"
	sessionControlCloseTaskSetKind               = "close_taskset"
	sessionControlCloseTaskSetSchema             = uint64(1)
	sessionControlCloseTaskSetSK                 = "TASKSET"
	sessionControlCloseTaskStatePending          = "pending"
	sessionControlCloseTaskStateLeased           = "leased"
	sessionControlCloseTaskOperationMaterialized = "materialized"
	sessionControlCloseTaskOperationClaimed      = "claimed"
	sessionControlCloseTaskOperationReleased     = "released"
	sessionControlCloseTaskOperationRebound      = "rebound"
	sessionControlCloseTaskOperationAcked        = "acked"
	sessionControlCloseTaskStateAcked            = "acked"
	sessionControlCloseManifestOwnerLimit        = 48
	sessionControlOverflowManifestOwnerLimit     = 47
	sessionControlCloseManifestLimit             = 22
	sessionControlCloseQueryLimit                = int32(100)
	sessionControlCloseReadAttempts              = 4
	// Normal materialization reserves the 1025th owner slot for overflow close
	// work. The generic owner schema deliberately retains its 1025-row ceiling.
	sessionControlNormalCloseTaskLimit = sessionControlFenceActiveLimit
)

func validSessionControlExactCloseWorkMode(mode string) bool {
	return mode == sessionControlCloseWorkModeNormal || mode == sessionControlCloseWorkModeOverflow
}

func sessionControlCloseOwnerLimitForMode(mode string) int {
	if mode == sessionControlCloseWorkModeOverflow {
		return sessionControlOverflowManifestOwnerLimit
	}
	return sessionControlCloseManifestOwnerLimit
}

var (
	errSessionControlMaterializationConflict = errors.New("session-control close materialization changed concurrently")
	errSessionControlMaterializationCorrupt  = errors.New("session-control close materialization is malformed")
	errSessionControlMaterializationCapacity = errors.New("session-control close materialization capacity is exhausted")
)

// A task row has immutable creation identity/audit and a mutable delivery
// suffix. Initial materialization writes version one in pending state without a
// lease. A manifest authenticates the immutable creation digest, so later
// delivery mutations never invalidate an already committed TASKSET result.
type sessionControlCloseTask struct {
	CellID                    string
	EventID                   string
	SelectorDigest            string
	SessionVersion            uint64
	ExpectedTargetCount       uint64
	PreparedDirectoryVersion  uint64
	ManifestIndex             uint64
	WorkMode                  string
	OwnerPK                   string
	ACID                      string
	PublicKey                 string
	SourceDigest              string
	SourceCount               uint64
	SourceBootID              string
	SourceFlushGeneration     uint64
	CreationTarget            sessionControlTargetAuthority
	OwnerBefore               sessionControlOwnerAuthority
	OwnerAfter                sessionControlOwnerAuthority
	CreationDigest            string
	TaskVersion               uint64
	State                     string
	BoundBootID               string
	BoundFlushGeneration      uint64
	BoundTargetVersion        uint64
	BoundAuthorityVersion     uint64
	BoundOwnerLifecycle       uint64
	BoundActivatedCursor      uint64
	BoundReadyCursor          uint64
	CurrentOwnerWorkVersion   uint64
	CurrentOwnerTaskCount     uint64
	CurrentOwnerPendingCount  uint64
	DueAtMillis               int64
	DueShard                  string
	DueSort                   string
	LeaseID                   string
	LeaseOwner                string
	LeaseExpiresAtMillis      int64
	LastOperationKind         string
	LastOperationID           string
	LastOperationInputDigest  string
	AckAuthenticatedPublicKey string
	AckSelectorDigest         string
	AckBootID                 string
	AckFlushGeneration        uint64
	AckClosed                 uint64
	AckLeaseID                string
	AckLeaseOwner             string
	AckedAtMillis             int64
	CreatedAtMillis           int64
	UpdatedAtMillis           int64
}

type sessionControlCloseTaskRef struct {
	OwnerPK        string `dynamodbav:"owner_pk" json:"owner_pk"`
	CreationDigest string `dynamodbav:"creation_digest" json:"creation_digest"`
	SourceDigest   string `dynamodbav:"source_digest" json:"source_digest"`
	SourceCount    uint64 `dynamodbav:"source_count" json:"source_count"`
}

type sessionControlCloseManifest struct {
	CellID                   string
	EventID                  string
	SelectorDigest           string
	SessionVersion           uint64
	ExpectedTargetCount      uint64
	PreparedDirectoryVersion uint64
	WorkMode                 string
	ManifestIndex            uint64
	Refs                     []sessionControlCloseTaskRef
	ManifestDigest           string
	CreatedAtMillis          int64
}

type sessionControlCloseTaskSet struct {
	CellID                   string
	EventID                  string
	SelectorDigest           string
	SessionVersion           uint64
	ExpectedTargetCount      uint64
	PreparedDirectoryVersion uint64
	WorkMode                 string
	SourceCount              uint64
	OwnerCount               uint64
	ManifestDigests          []string
	ManifestSourceCounts     []uint64
	ManifestOwnerCounts      []uint64
	TaskSetDigest            string
	CreatedAtMillis          int64
}

type sessionControlCloseTaskRow struct {
	PK                        string                  `dynamodbav:"pk"`
	SK                        string                  `dynamodbav:"sk"`
	Kind                      string                  `dynamodbav:"kind"`
	SchemaVersion             uint64                  `dynamodbav:"schema_version"`
	CellID                    string                  `dynamodbav:"cell_id"`
	EventID                   string                  `dynamodbav:"event_id"`
	SelectorDigest            string                  `dynamodbav:"selector_digest"`
	SessionVersion            uint64                  `dynamodbav:"session_version"`
	ExpectedTargetCount       uint64                  `dynamodbav:"expected_target_count"`
	PreparedDirectoryVersion  uint64                  `dynamodbav:"prepared_directory_version"`
	ManifestIndex             uint64                  `dynamodbav:"manifest_index"`
	WorkMode                  string                  `dynamodbav:"work_mode"`
	OwnerPK                   string                  `dynamodbav:"owner_pk"`
	ACID                      string                  `dynamodbav:"ac_id"`
	PublicKey                 string                  `dynamodbav:"public_key"`
	SourceDigest              string                  `dynamodbav:"source_digest"`
	SourceCount               uint64                  `dynamodbav:"source_count"`
	SourceBootID              string                  `dynamodbav:"source_boot_id"`
	SourceFlushGeneration     uint64                  `dynamodbav:"source_flush_generation"`
	CreationTarget            sessionControlTargetRow `dynamodbav:"creation_target"`
	OwnerBefore               sessionControlOwnerRow  `dynamodbav:"owner_before"`
	OwnerAfter                sessionControlOwnerRow  `dynamodbav:"owner_after"`
	CreationDigest            string                  `dynamodbav:"creation_digest"`
	TaskVersion               uint64                  `dynamodbav:"task_version"`
	State                     string                  `dynamodbav:"state"`
	BoundBootID               string                  `dynamodbav:"bound_boot_id"`
	BoundFlushGeneration      uint64                  `dynamodbav:"bound_flush_generation"`
	BoundTargetVersion        uint64                  `dynamodbav:"bound_target_version"`
	BoundAuthorityVersion     uint64                  `dynamodbav:"bound_authority_version"`
	BoundOwnerLifecycle       uint64                  `dynamodbav:"bound_owner_lifecycle_version"`
	BoundActivatedCursor      uint64                  `dynamodbav:"bound_activated_cursor"`
	BoundReadyCursor          uint64                  `dynamodbav:"bound_ready_cursor"`
	CurrentOwnerWorkVersion   uint64                  `dynamodbav:"current_owner_work_version"`
	CurrentOwnerTaskCount     uint64                  `dynamodbav:"current_owner_task_count"`
	CurrentOwnerPendingCount  uint64                  `dynamodbav:"current_owner_pending_count"`
	DueAtMillis               int64                   `dynamodbav:"due_at_ms,omitempty"`
	DueShard                  string                  `dynamodbav:"due_shard,omitempty"`
	DueSort                   string                  `dynamodbav:"due_sort,omitempty"`
	LeaseID                   string                  `dynamodbav:"lease_id,omitempty"`
	LeaseOwner                string                  `dynamodbav:"lease_owner,omitempty"`
	LeaseExpiresAtMillis      int64                   `dynamodbav:"lease_expires_at_ms,omitempty"`
	LastOperationKind         string                  `dynamodbav:"last_operation_kind"`
	LastOperationID           string                  `dynamodbav:"last_operation_id"`
	LastOperationInputDigest  string                  `dynamodbav:"last_operation_input_digest"`
	AckAuthenticatedPublicKey string                  `dynamodbav:"ack_authenticated_public_key,omitempty"`
	AckSelectorDigest         string                  `dynamodbav:"ack_selector_digest,omitempty"`
	AckBootID                 string                  `dynamodbav:"ack_boot_id,omitempty"`
	AckFlushGeneration        uint64                  `dynamodbav:"ack_flush_generation,omitempty"`
	AckClosed                 *uint64                 `dynamodbav:"ack_closed,omitempty"`
	AckLeaseID                string                  `dynamodbav:"ack_lease_id,omitempty"`
	AckLeaseOwner             string                  `dynamodbav:"ack_lease_owner,omitempty"`
	AckedAtMillis             int64                   `dynamodbav:"acked_at_ms,omitempty"`
	CreatedAtMillis           int64                   `dynamodbav:"created_at_ms"`
	UpdatedAtMillis           int64                   `dynamodbav:"updated_at_ms"`
}

type sessionControlCloseManifestRow struct {
	PK                       string                       `dynamodbav:"pk"`
	SK                       string                       `dynamodbav:"sk"`
	Kind                     string                       `dynamodbav:"kind"`
	SchemaVersion            uint64                       `dynamodbav:"schema_version"`
	CellID                   string                       `dynamodbav:"cell_id"`
	EventID                  string                       `dynamodbav:"event_id"`
	SelectorDigest           string                       `dynamodbav:"selector_digest"`
	SessionVersion           uint64                       `dynamodbav:"session_version"`
	ExpectedTargetCount      uint64                       `dynamodbav:"expected_target_count"`
	PreparedDirectoryVersion uint64                       `dynamodbav:"prepared_directory_version"`
	WorkMode                 string                       `dynamodbav:"work_mode"`
	ManifestIndex            uint64                       `dynamodbav:"manifest_index"`
	Refs                     []sessionControlCloseTaskRef `dynamodbav:"task_refs"`
	ManifestDigest           string                       `dynamodbav:"manifest_digest"`
	CreatedAtMillis          int64                        `dynamodbav:"created_at_ms"`
}

type sessionControlCloseTaskSetRow struct {
	PK                       string   `dynamodbav:"pk"`
	SK                       string   `dynamodbav:"sk"`
	Kind                     string   `dynamodbav:"kind"`
	SchemaVersion            uint64   `dynamodbav:"schema_version"`
	CellID                   string   `dynamodbav:"cell_id"`
	EventID                  string   `dynamodbav:"event_id"`
	SelectorDigest           string   `dynamodbav:"selector_digest"`
	SessionVersion           uint64   `dynamodbav:"session_version"`
	ExpectedTargetCount      uint64   `dynamodbav:"expected_target_count"`
	PreparedDirectoryVersion uint64   `dynamodbav:"prepared_directory_version"`
	WorkMode                 string   `dynamodbav:"work_mode"`
	SourceCount              uint64   `dynamodbav:"source_count"`
	OwnerCount               uint64   `dynamodbav:"owner_count"`
	ManifestDigests          []string `dynamodbav:"manifest_digests"`
	ManifestSourceCounts     []uint64 `dynamodbav:"manifest_source_counts"`
	ManifestOwnerCounts      []uint64 `dynamodbav:"manifest_owner_counts"`
	TaskSetDigest            string   `dynamodbav:"taskset_digest"`
	CreatedAtMillis          int64    `dynamodbav:"created_at_ms"`
}

type sessionControlCloseSourceGroup struct {
	OwnerPK               string
	CellID                string
	ACID                  string
	PublicKey             string
	Intents               []sessionControlSessionIntent
	SourceDigest          string
	SourceBootID          string
	SourceFlushGeneration uint64
}

func sessionControlCloseManifestSK(index uint64) string {
	return fmt.Sprintf("%s%02d", sessionControlCloseManifestSKPrefix, index)
}

func sessionControlCloseTaskSK(eventID string) string {
	return sessionControlCloseTaskSKPrefix + eventID
}

func sessionControlCloseManifestKey(eventID string, index uint64) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlFenceMetaPK(eventID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlCloseManifestSK(index)},
	}
}

func sessionControlCloseTaskKey(ownerPK, eventID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: ownerPK},
		"sk": &types.AttributeValueMemberS{Value: sessionControlCloseTaskSK(eventID)},
	}
}

func sessionControlCloseTaskSetKey(eventID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlFenceMetaPK(eventID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlCloseTaskSetSK},
	}
}

func sessionControlCloseTaskDueShard(task sessionControlCloseTask) string {
	digest := sha256.Sum256([]byte(task.EventID + "\x00" + task.OwnerPK))
	return fmt.Sprintf("CLOSETASK#%s#%02d", task.CellID, uint64(digest[0])%sessionControlCloseDueShardCount)
}

func sessionControlCloseTaskDueSort(task sessionControlCloseTask) string {
	return sessionControlSessionIssuedText(task.DueAtMillis) + "#" + task.EventID + "#" + task.OwnerPK
}

func sessionControlMaterializationDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode session-control materialization digest: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func sessionControlCloseSourceDigest(intents []sessionControlSessionIntent) (string, error) {
	// The source rows are the durable authority consumed by materialization.
	// Hash the complete decoded rows, not a hand-selected projection, so state,
	// both fence cursors, session expiry/retention, and all target/owner audit
	// fields participate automatically.
	return sessionControlMaterializationDigest(struct {
		Version uint64                        `json:"version"`
		Intents []sessionControlSessionIntent `json:"intents"`
	}{Version: 1, Intents: intents})
}

func sessionControlCloseTaskCreationDigest(task sessionControlCloseTask) (string, error) {
	return sessionControlMaterializationDigest(struct {
		Version                  uint64
		CellID                   string
		EventID                  string
		SelectorDigest           string
		SessionVersion           uint64
		ExpectedTargetCount      uint64
		PreparedDirectoryVersion uint64
		ManifestIndex            uint64
		WorkMode                 string
		OwnerPK                  string
		ACID                     string
		PublicKey                string
		SourceDigest             string
		SourceCount              uint64
		SourceBootID             string
		SourceFlushGeneration    uint64
		CreationTarget           sessionControlTargetAuthority
		OwnerBefore              sessionControlOwnerAuthority
		OwnerAfter               sessionControlOwnerAuthority
		CreatedAtMillis          int64
	}{1, task.CellID, task.EventID, task.SelectorDigest, task.SessionVersion, task.ExpectedTargetCount,
		task.PreparedDirectoryVersion, task.ManifestIndex, task.WorkMode, task.OwnerPK, task.ACID, task.PublicKey,
		task.SourceDigest, task.SourceCount, task.SourceBootID, task.SourceFlushGeneration,
		task.CreationTarget, task.OwnerBefore, task.OwnerAfter, task.CreatedAtMillis})
}

func validSessionControlMaterializationWorkTuple(sessionVersion, expectedTargetCount,
	preparedDirectoryVersion uint64) bool {
	return sessionVersion > 0 && sessionVersion < ^uint64(0)-1 &&
		expectedTargetCount <= sessionControlSessionMaxTargets && expectedTargetCount < sessionVersion &&
		(sessionVersion == 1) == (expectedTargetCount == 0) &&
		preparedDirectoryVersion > 0 && preparedDirectoryVersion < ^uint64(0)-1
}

func validateSessionControlCloseTask(task sessionControlCloseTask) error {
	if !validSessionControlCellID(task.CellID) || !validSessionControlFenceEventID(task.EventID) ||
		task.SelectorDigest == "" || task.ExpectedTargetCount == 0 ||
		!validSessionControlMaterializationWorkTuple(task.SessionVersion, task.ExpectedTargetCount, task.PreparedDirectoryVersion) ||
		task.ManifestIndex >= sessionControlCloseManifestLimit || !validSessionControlExactCloseWorkMode(task.WorkMode) ||
		task.OwnerPK != sessionControlOwnerPK(task.CellID, task.ACID, task.PublicKey) ||
		task.SourceDigest == "" || task.SourceCount == 0 || task.SourceCount > task.ExpectedTargetCount ||
		task.SourceBootID == "" || task.SourceFlushGeneration == 0 ||
		validateSessionControlTargetAuthority(task.CreationTarget) != nil ||
		validateSessionControlOwnerAuthority(task.OwnerBefore) != nil || validateSessionControlOwnerAuthority(task.OwnerAfter) != nil ||
		task.TaskVersion == 0 || task.TaskVersion >= ^uint64(0)-1 || !task.CreationTarget.required() ||
		!task.CreationTarget.CountedActiveSlot || !sessionControlCloseOwnerTargetMatch(task.OwnerBefore, task.CreationTarget) ||
		!common.ValidNHPACBootID(task.BoundBootID) || task.BoundFlushGeneration == 0 ||
		task.BoundTargetVersion == 0 || task.BoundTargetVersion == ^uint64(0) ||
		task.BoundAuthorityVersion == 0 || task.BoundOwnerLifecycle == 0 || task.BoundOwnerLifecycle == ^uint64(0) ||
		(task.BoundReadyCursor > 0 && task.BoundReadyCursor != task.BoundActivatedCursor) ||
		task.CurrentOwnerPendingCount > task.CurrentOwnerTaskCount ||
		task.CurrentOwnerTaskCount > sessionControlOwnerTaskLimit ||
		task.CurrentOwnerWorkVersion < task.OwnerAfter.WorkVersion ||
		task.LastOperationID == "" || task.CreatedAtMillis <= 0 || task.UpdatedAtMillis < task.CreatedAtMillis ||
		task.OwnerBefore.CellID != task.CellID || task.OwnerBefore.ACID != task.ACID || task.OwnerBefore.PublicKey != task.PublicKey ||
		task.OwnerAfter.CellID != task.CellID || task.OwnerAfter.ACID != task.ACID || task.OwnerAfter.PublicKey != task.PublicKey {
		return errSessionControlMaterializationCorrupt
	}
	expectedAfter, planErr := planSessionControlOwnerTaskInsert(task.OwnerBefore, task.CreatedAtMillis)
	if planErr != nil || expectedAfter != task.OwnerAfter {
		return errSessionControlMaterializationCorrupt
	}
	minimumWorkVersion := task.OwnerAfter.WorkVersion
	if task.TaskVersion-1 > ^uint64(0)-minimumWorkVersion {
		return errSessionControlMaterializationCorrupt
	}
	minimumWorkVersion += task.TaskVersion - 1
	if task.CurrentOwnerWorkVersion < minimumWorkVersion {
		return errSessionControlMaterializationCorrupt
	}
	switch task.State {
	case sessionControlCloseTaskStatePending:
		if task.CurrentOwnerPendingCount == 0 || task.LeaseID != "" || task.LeaseOwner != "" ||
			task.LeaseExpiresAtMillis != 0 || task.DueAtMillis < task.UpdatedAtMillis ||
			task.DueShard != sessionControlCloseTaskDueShard(task) || task.DueSort != sessionControlCloseTaskDueSort(task) ||
			sessionControlCloseTaskHasAckAudit(task) {
			return errSessionControlMaterializationCorrupt
		}
		if task.TaskVersion == 1 {
			if task.CurrentOwnerWorkVersion != task.OwnerAfter.WorkVersion ||
				task.CurrentOwnerTaskCount != task.OwnerAfter.TaskCount ||
				task.CurrentOwnerPendingCount != task.OwnerAfter.PendingCount ||
				task.LastOperationKind != sessionControlCloseTaskOperationMaterialized ||
				task.LastOperationID != task.CreationDigest || task.LastOperationInputDigest != task.CreationDigest ||
				task.BoundBootID != task.CreationTarget.BootID ||
				task.BoundFlushGeneration != task.CreationTarget.FlushGeneration ||
				task.BoundTargetVersion != task.CreationTarget.Version ||
				task.BoundAuthorityVersion != task.CreationTarget.AuthorityVersion ||
				task.BoundOwnerLifecycle != task.OwnerAfter.LifecycleVersion ||
				task.BoundActivatedCursor != task.CreationTarget.ActivatedControlVersion ||
				task.BoundReadyCursor != task.CreationTarget.ReadyControlVersion ||
				task.UpdatedAtMillis != task.CreatedAtMillis ||
				task.DueAtMillis != task.CreatedAtMillis {
				return errSessionControlMaterializationCorrupt
			}
		} else if (task.LastOperationKind != sessionControlCloseTaskOperationReleased &&
			task.LastOperationKind != sessionControlCloseTaskOperationRebound) ||
			!validSessionControlTaskOperationID(task.LastOperationID) ||
			!validSessionControlTaskInputDigest(task.LastOperationInputDigest) ||
			task.DueAtMillis != task.UpdatedAtMillis {
			return errSessionControlMaterializationCorrupt
		}
	case sessionControlCloseTaskStateLeased:
		claimDigest, claimDigestErr := sessionControlCloseTaskOperationInputDigest("claim", sessionControlCloseTaskLeaseRequest{
			CellID: task.CellID, EventID: task.EventID, OwnerPK: task.OwnerPK,
			OperationID: task.LastOperationID, LeaseID: task.LeaseID, LeaseOwner: task.LeaseOwner,
		})
		if task.TaskVersion == 1 || !validSessionControlTaskLeaseID(task.LeaseID) ||
			!validSessionControlTaskLeaseOwner(task.LeaseOwner) ||
			task.UpdatedAtMillis > math.MaxInt64-sessionControlCloseTaskLeaseDuration.Milliseconds() ||
			task.LeaseExpiresAtMillis != task.UpdatedAtMillis+sessionControlCloseTaskLeaseDuration.Milliseconds() ||
			task.DueAtMillis != task.LeaseExpiresAtMillis ||
			task.DueShard != sessionControlCloseTaskDueShard(task) || task.DueSort != sessionControlCloseTaskDueSort(task) ||
			task.CurrentOwnerPendingCount == 0 || sessionControlCloseTaskHasAckAudit(task) ||
			task.LastOperationKind != sessionControlCloseTaskOperationClaimed ||
			!validSessionControlTaskOperationID(task.LastOperationID) ||
			!validSessionControlTaskInputDigest(task.LastOperationInputDigest) || claimDigestErr != nil ||
			task.LastOperationInputDigest != claimDigest {
			return errSessionControlMaterializationCorrupt
		}
	case sessionControlCloseTaskStateAcked:
		if task.TaskVersion == 1 || task.LeaseID != "" || task.LeaseOwner != "" || task.LeaseExpiresAtMillis != 0 ||
			task.DueAtMillis != 0 || task.DueShard != "" || task.DueSort != "" ||
			task.LastOperationKind != sessionControlCloseTaskOperationAcked ||
			!validSessionControlTaskOperationID(task.LastOperationID) ||
			!validSessionControlTaskInputDigest(task.LastOperationInputDigest) ||
			task.AckAuthenticatedPublicKey != task.PublicKey || task.AckSelectorDigest != task.SelectorDigest ||
			task.AckBootID != task.BoundBootID || task.AckFlushGeneration != task.BoundFlushGeneration ||
			!validSessionControlTaskLeaseID(task.AckLeaseID) || !validSessionControlTaskLeaseOwner(task.AckLeaseOwner) ||
			task.AckedAtMillis != task.UpdatedAtMillis || task.AckedAtMillis < task.CreatedAtMillis {
			return errSessionControlMaterializationCorrupt
		}
	default:
		return errSessionControlMaterializationCorrupt
	}
	digest, err := sessionControlCloseTaskCreationDigest(task)
	if err != nil || digest != task.CreationDigest {
		return errSessionControlMaterializationCorrupt
	}
	return nil
}

func sessionControlCloseTaskHasAckAudit(task sessionControlCloseTask) bool {
	return task.AckAuthenticatedPublicKey != "" || task.AckSelectorDigest != "" || task.AckBootID != "" ||
		task.AckFlushGeneration != 0 || task.AckClosed != 0 || task.AckLeaseID != "" || task.AckLeaseOwner != "" ||
		task.AckedAtMillis != 0
}

func validSessionControlOwnerPK(ownerPK string) bool {
	if !strings.HasPrefix(ownerPK, sessionControlOwnerPKPrefix) || len(ownerPK) != len(sessionControlOwnerPKPrefix)+64 {
		return false
	}
	digest := strings.TrimPrefix(ownerPK, sessionControlOwnerPKPrefix)
	if digest != strings.ToLower(digest) {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == 32
}

func sessionControlCloseManifestDigest(manifest sessionControlCloseManifest) (string, error) {
	return sessionControlMaterializationDigest(struct {
		Version                  uint64
		CellID                   string
		EventID                  string
		SelectorDigest           string
		SessionVersion           uint64
		ExpectedTargetCount      uint64
		PreparedDirectoryVersion uint64
		WorkMode                 string
		ManifestIndex            uint64
		Refs                     []sessionControlCloseTaskRef
		CreatedAtMillis          int64
	}{1, manifest.CellID, manifest.EventID, manifest.SelectorDigest, manifest.SessionVersion,
		manifest.ExpectedTargetCount, manifest.PreparedDirectoryVersion, manifest.WorkMode,
		manifest.ManifestIndex, manifest.Refs, manifest.CreatedAtMillis})
}

func sessionControlCloseTaskSetDigest(taskSet sessionControlCloseTaskSet) (string, error) {
	return sessionControlMaterializationDigest(struct {
		Version                  uint64
		CellID                   string
		EventID                  string
		SelectorDigest           string
		SessionVersion           uint64
		ExpectedTargetCount      uint64
		PreparedDirectoryVersion uint64
		WorkMode                 string
		SourceCount              uint64
		OwnerCount               uint64
		ManifestDigests          []string
		ManifestSourceCounts     []uint64
		ManifestOwnerCounts      []uint64
		CreatedAtMillis          int64
	}{1, taskSet.CellID, taskSet.EventID, taskSet.SelectorDigest, taskSet.SessionVersion,
		taskSet.ExpectedTargetCount, taskSet.PreparedDirectoryVersion, taskSet.WorkMode, taskSet.SourceCount,
		taskSet.OwnerCount, taskSet.ManifestDigests, taskSet.ManifestSourceCounts,
		taskSet.ManifestOwnerCounts, taskSet.CreatedAtMillis})
}

func validateSessionControlCloseManifest(manifest sessionControlCloseManifest) error {
	if !validSessionControlCellID(manifest.CellID) || !validSessionControlFenceEventID(manifest.EventID) ||
		manifest.SelectorDigest == "" || manifest.ExpectedTargetCount == 0 ||
		!validSessionControlMaterializationWorkTuple(manifest.SessionVersion, manifest.ExpectedTargetCount, manifest.PreparedDirectoryVersion) ||
		!validSessionControlExactCloseWorkMode(manifest.WorkMode) ||
		manifest.ManifestIndex >= sessionControlCloseManifestLimit || len(manifest.Refs) == 0 ||
		len(manifest.Refs) > sessionControlCloseOwnerLimitForMode(manifest.WorkMode) || manifest.CreatedAtMillis <= 0 {
		return errSessionControlMaterializationCorrupt
	}
	var sourceSum uint64
	for index, ref := range manifest.Refs {
		if !validSessionControlOwnerPK(ref.OwnerPK) || ref.CreationDigest == "" ||
			ref.SourceDigest == "" || ref.SourceCount == 0 || (index > 0 && manifest.Refs[index-1].OwnerPK >= ref.OwnerPK) {
			return errSessionControlMaterializationCorrupt
		}
		if ref.SourceCount > manifest.ExpectedTargetCount || sourceSum > manifest.ExpectedTargetCount-ref.SourceCount {
			return errSessionControlMaterializationCorrupt
		}
		sourceSum += ref.SourceCount
	}
	if sourceSum < uint64(len(manifest.Refs)) || sourceSum > manifest.ExpectedTargetCount {
		return errSessionControlMaterializationCorrupt
	}
	expected, err := sessionControlCloseManifestDigest(manifest)
	if err != nil || expected != manifest.ManifestDigest {
		return errSessionControlMaterializationCorrupt
	}
	return nil
}

func validateSessionControlCloseTaskSet(taskSet sessionControlCloseTaskSet) error {
	if !validSessionControlCellID(taskSet.CellID) || !validSessionControlFenceEventID(taskSet.EventID) ||
		taskSet.SelectorDigest == "" ||
		!validSessionControlMaterializationWorkTuple(taskSet.SessionVersion, taskSet.ExpectedTargetCount, taskSet.PreparedDirectoryVersion) ||
		!validSessionControlExactCloseWorkMode(taskSet.WorkMode) ||
		taskSet.SourceCount != taskSet.ExpectedTargetCount ||
		taskSet.OwnerCount > sessionControlSessionMaxTargets || len(taskSet.ManifestDigests) > sessionControlCloseManifestLimit ||
		taskSet.CreatedAtMillis <= 0 || (taskSet.OwnerCount == 0) != (len(taskSet.ManifestDigests) == 0) ||
		len(taskSet.ManifestDigests) != len(taskSet.ManifestSourceCounts) ||
		len(taskSet.ManifestDigests) != len(taskSet.ManifestOwnerCounts) {
		return errSessionControlMaterializationCorrupt
	}
	ownerLimit := sessionControlCloseOwnerLimitForMode(taskSet.WorkMode)
	if taskSet.OwnerCount > taskSet.SourceCount ||
		(taskSet.SourceCount == 0 && (taskSet.OwnerCount != 0 || len(taskSet.ManifestDigests) != 0)) ||
		(taskSet.SourceCount > 0 && (taskSet.OwnerCount == 0 ||
			len(taskSet.ManifestDigests) != (int(taskSet.OwnerCount)+ownerLimit-1)/ownerLimit)) {
		return errSessionControlMaterializationCorrupt
	}
	var sourceSum, ownerSum uint64
	for index, digest := range taskSet.ManifestDigests {
		manifestSources, manifestOwners := taskSet.ManifestSourceCounts[index], taskSet.ManifestOwnerCounts[index]
		if digest == "" || manifestOwners == 0 || manifestOwners > uint64(ownerLimit) ||
			manifestSources < manifestOwners || manifestSources > taskSet.ExpectedTargetCount ||
			(index < len(taskSet.ManifestDigests)-1 && manifestOwners != uint64(ownerLimit)) {
			return errSessionControlMaterializationCorrupt
		}
		if manifestOwners > taskSet.OwnerCount || sourceSum > taskSet.ExpectedTargetCount-manifestSources ||
			ownerSum > taskSet.OwnerCount-manifestOwners {
			return errSessionControlMaterializationCorrupt
		}
		sourceSum += manifestSources
		ownerSum += manifestOwners
	}
	if sourceSum != taskSet.SourceCount || ownerSum != taskSet.OwnerCount {
		return errSessionControlMaterializationCorrupt
	}
	expected, err := sessionControlCloseTaskSetDigest(taskSet)
	if err != nil || expected != taskSet.TaskSetDigest {
		return errSessionControlMaterializationCorrupt
	}
	return nil
}

func sessionControlCloseTaskToRow(task sessionControlCloseTask) (sessionControlCloseTaskRow, error) {
	if err := validateSessionControlCloseTask(task); err != nil {
		return sessionControlCloseTaskRow{}, err
	}
	target, err := sessionControlTargetToRow(task.CreationTarget)
	if err != nil {
		return sessionControlCloseTaskRow{}, err
	}
	before, err := sessionControlOwnerToRow(task.OwnerBefore)
	if err != nil {
		return sessionControlCloseTaskRow{}, err
	}
	after, err := sessionControlOwnerToRow(task.OwnerAfter)
	if err != nil {
		return sessionControlCloseTaskRow{}, err
	}
	var ackClosed *uint64
	if task.State == sessionControlCloseTaskStateAcked {
		value := task.AckClosed
		ackClosed = &value
	}
	return sessionControlCloseTaskRow{
		PK: task.OwnerPK, SK: sessionControlCloseTaskSK(task.EventID), Kind: sessionControlCloseTaskKind,
		SchemaVersion: sessionControlCloseTaskSchema, CellID: task.CellID, EventID: task.EventID,
		SelectorDigest: task.SelectorDigest, SessionVersion: task.SessionVersion,
		ExpectedTargetCount: task.ExpectedTargetCount, PreparedDirectoryVersion: task.PreparedDirectoryVersion,
		ManifestIndex: task.ManifestIndex, WorkMode: task.WorkMode,
		OwnerPK: task.OwnerPK, ACID: task.ACID, PublicKey: task.PublicKey,
		SourceDigest: task.SourceDigest, SourceCount: task.SourceCount, SourceBootID: task.SourceBootID,
		SourceFlushGeneration: task.SourceFlushGeneration, CreationTarget: target, OwnerBefore: before,
		OwnerAfter: after, CreationDigest: task.CreationDigest, TaskVersion: task.TaskVersion, State: task.State,
		BoundBootID: task.BoundBootID, BoundFlushGeneration: task.BoundFlushGeneration,
		BoundTargetVersion: task.BoundTargetVersion, BoundAuthorityVersion: task.BoundAuthorityVersion,
		BoundOwnerLifecycle: task.BoundOwnerLifecycle, BoundActivatedCursor: task.BoundActivatedCursor,
		BoundReadyCursor: task.BoundReadyCursor, CurrentOwnerWorkVersion: task.CurrentOwnerWorkVersion,
		CurrentOwnerTaskCount: task.CurrentOwnerTaskCount, CurrentOwnerPendingCount: task.CurrentOwnerPendingCount,
		DueAtMillis: task.DueAtMillis, DueShard: task.DueShard,
		DueSort: task.DueSort, LeaseID: task.LeaseID, LeaseOwner: task.LeaseOwner,
		LeaseExpiresAtMillis: task.LeaseExpiresAtMillis, LastOperationKind: task.LastOperationKind,
		LastOperationID: task.LastOperationID, LastOperationInputDigest: task.LastOperationInputDigest,
		AckAuthenticatedPublicKey: task.AckAuthenticatedPublicKey, AckSelectorDigest: task.AckSelectorDigest,
		AckBootID: task.AckBootID, AckFlushGeneration: task.AckFlushGeneration, AckClosed: ackClosed,
		AckLeaseID: task.AckLeaseID, AckLeaseOwner: task.AckLeaseOwner, AckedAtMillis: task.AckedAtMillis,
		CreatedAtMillis: task.CreatedAtMillis,
		UpdatedAtMillis: task.UpdatedAtMillis,
	}, nil
}

func sessionControlCloseTaskFromItem(item map[string]types.AttributeValue, ownerPK, eventID string) (sessionControlCloseTask, error) {
	if len(item) == 0 {
		return sessionControlCloseTask{}, errSessionControlSessionNotFound
	}
	if _, hasTTL := item["ttl"]; hasTTL {
		return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
	}
	for _, name := range []string{"session_version", "expected_target_count", "prepared_directory_version", "manifest_index",
		"source_count", "source_flush_generation", "task_version", "bound_flush_generation",
		"bound_target_version", "bound_authority_version", "bound_owner_lifecycle_version", "bound_activated_cursor",
		"bound_ready_cursor", "current_owner_work_version", "current_owner_task_count", "current_owner_pending_count",
		"created_at_ms", "updated_at_ms"} {
		if _, ok := item[name].(*types.AttributeValueMemberN); !ok {
			return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
		}
	}
	for _, name := range []string{"work_mode", "last_operation_kind", "last_operation_id", "last_operation_input_digest"} {
		if _, ok := item[name].(*types.AttributeValueMemberS); !ok {
			return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
		}
	}
	for _, name := range []string{"lease_id", "lease_owner"} {
		if value, exists := item[name]; exists {
			if _, ok := value.(*types.AttributeValueMemberS); !ok {
				return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
			}
		}
	}
	if value, exists := item["lease_expires_at_ms"]; exists {
		if _, ok := value.(*types.AttributeValueMemberN); !ok {
			return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
		}
	}
	stateValue, stateOK := item["state"].(*types.AttributeValueMemberS)
	if !stateOK {
		return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
	}
	if stateValue.Value == sessionControlCloseTaskStateAcked {
		for _, name := range []string{"due_at_ms", "due_shard", "due_sort", "lease_id", "lease_owner", "lease_expires_at_ms"} {
			if _, exists := item[name]; exists {
				return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
			}
		}
		for _, name := range []string{"ack_authenticated_public_key", "ack_selector_digest", "ack_boot_id",
			"ack_lease_id", "ack_lease_owner"} {
			if _, ok := item[name].(*types.AttributeValueMemberS); !ok {
				return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
			}
		}
		for _, name := range []string{"ack_flush_generation", "ack_closed", "acked_at_ms"} {
			if _, ok := item[name].(*types.AttributeValueMemberN); !ok {
				return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
			}
		}
	} else {
		if _, ok := item["due_at_ms"].(*types.AttributeValueMemberN); !ok {
			return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
		}
		for _, name := range []string{"due_shard", "due_sort"} {
			if _, ok := item[name].(*types.AttributeValueMemberS); !ok {
				return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
			}
		}
		for _, name := range []string{"ack_authenticated_public_key", "ack_selector_digest", "ack_boot_id",
			"ack_flush_generation", "ack_closed", "ack_lease_id", "ack_lease_owner", "acked_at_ms"} {
			if _, exists := item[name]; exists {
				return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
			}
		}
	}
	var row sessionControlCloseTaskRow
	if err := attributevalue.UnmarshalMap(item, &row); err != nil {
		return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
	}
	target, err := sessionControlTargetFromRow(row.CreationTarget, row.ACID)
	if err != nil {
		return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
	}
	beforeItem, _ := attributevalue.MarshalMap(row.OwnerBefore)
	afterItem, _ := attributevalue.MarshalMap(row.OwnerAfter)
	before, err := sessionControlOwnerFromItem(beforeItem, row.CellID, row.ACID, row.PublicKey)
	if err != nil {
		return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
	}
	after, err := sessionControlOwnerFromItem(afterItem, row.CellID, row.ACID, row.PublicKey)
	if err != nil {
		return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
	}
	var ackClosed uint64
	if row.AckClosed != nil {
		ackClosed = *row.AckClosed
	}
	task := sessionControlCloseTask{
		CellID: row.CellID, EventID: row.EventID, SelectorDigest: row.SelectorDigest,
		SessionVersion: row.SessionVersion, ExpectedTargetCount: row.ExpectedTargetCount,
		PreparedDirectoryVersion: row.PreparedDirectoryVersion, ManifestIndex: row.ManifestIndex,
		WorkMode: row.WorkMode, OwnerPK: row.OwnerPK,
		ACID: row.ACID, PublicKey: row.PublicKey, SourceDigest: row.SourceDigest, SourceCount: row.SourceCount,
		SourceBootID: row.SourceBootID, SourceFlushGeneration: row.SourceFlushGeneration,
		CreationTarget: target, OwnerBefore: before, OwnerAfter: after, CreationDigest: row.CreationDigest,
		TaskVersion: row.TaskVersion, State: row.State, BoundBootID: row.BoundBootID,
		BoundFlushGeneration: row.BoundFlushGeneration, BoundTargetVersion: row.BoundTargetVersion,
		BoundAuthorityVersion: row.BoundAuthorityVersion, BoundOwnerLifecycle: row.BoundOwnerLifecycle,
		BoundActivatedCursor: row.BoundActivatedCursor, BoundReadyCursor: row.BoundReadyCursor,
		CurrentOwnerWorkVersion: row.CurrentOwnerWorkVersion, CurrentOwnerTaskCount: row.CurrentOwnerTaskCount,
		CurrentOwnerPendingCount: row.CurrentOwnerPendingCount,
		DueAtMillis:              row.DueAtMillis, DueShard: row.DueShard, DueSort: row.DueSort, LeaseID: row.LeaseID,
		LeaseOwner: row.LeaseOwner, LeaseExpiresAtMillis: row.LeaseExpiresAtMillis,
		LastOperationKind: row.LastOperationKind, LastOperationID: row.LastOperationID,
		LastOperationInputDigest:  row.LastOperationInputDigest,
		AckAuthenticatedPublicKey: row.AckAuthenticatedPublicKey, AckSelectorDigest: row.AckSelectorDigest,
		AckBootID: row.AckBootID, AckFlushGeneration: row.AckFlushGeneration, AckClosed: ackClosed,
		AckLeaseID: row.AckLeaseID, AckLeaseOwner: row.AckLeaseOwner, AckedAtMillis: row.AckedAtMillis,
		CreatedAtMillis: row.CreatedAtMillis, UpdatedAtMillis: row.UpdatedAtMillis,
	}
	if row.PK != ownerPK || row.SK != sessionControlCloseTaskSK(eventID) || row.Kind != sessionControlCloseTaskKind ||
		row.SchemaVersion != sessionControlCloseTaskSchema || row.OwnerPK != ownerPK || row.EventID != eventID ||
		validateSessionControlCloseTask(task) != nil {
		return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
	}
	return task, nil
}

func sessionControlCloseManifestToRow(manifest sessionControlCloseManifest) (sessionControlCloseManifestRow, error) {
	if err := validateSessionControlCloseManifest(manifest); err != nil {
		return sessionControlCloseManifestRow{}, err
	}
	return sessionControlCloseManifestRow{
		PK: sessionControlFenceMetaPK(manifest.EventID), SK: sessionControlCloseManifestSK(manifest.ManifestIndex),
		Kind: sessionControlCloseManifestKind, SchemaVersion: sessionControlCloseManifestSchema,
		CellID: manifest.CellID, EventID: manifest.EventID, SelectorDigest: manifest.SelectorDigest,
		SessionVersion: manifest.SessionVersion, ExpectedTargetCount: manifest.ExpectedTargetCount,
		PreparedDirectoryVersion: manifest.PreparedDirectoryVersion, WorkMode: manifest.WorkMode,
		ManifestIndex: manifest.ManifestIndex,
		Refs:          manifest.Refs, ManifestDigest: manifest.ManifestDigest, CreatedAtMillis: manifest.CreatedAtMillis,
	}, nil
}

func sessionControlCloseManifestFromItem(item map[string]types.AttributeValue, eventID string, index uint64) (sessionControlCloseManifest, error) {
	if len(item) == 0 {
		return sessionControlCloseManifest{}, errSessionControlSessionNotFound
	}
	if _, hasTTL := item["ttl"]; hasTTL {
		return sessionControlCloseManifest{}, errSessionControlMaterializationCorrupt
	}
	if _, ok := item["work_mode"].(*types.AttributeValueMemberS); !ok {
		return sessionControlCloseManifest{}, errSessionControlMaterializationCorrupt
	}
	for _, name := range []string{"schema_version", "session_version", "expected_target_count",
		"prepared_directory_version", "manifest_index", "created_at_ms"} {
		if _, ok := item[name].(*types.AttributeValueMemberN); !ok {
			return sessionControlCloseManifest{}, errSessionControlMaterializationCorrupt
		}
	}
	refs, ok := item["task_refs"].(*types.AttributeValueMemberL)
	if !ok {
		return sessionControlCloseManifest{}, errSessionControlMaterializationCorrupt
	}
	for _, value := range refs.Value {
		ref, mapOK := value.(*types.AttributeValueMemberM)
		if !mapOK {
			return sessionControlCloseManifest{}, errSessionControlMaterializationCorrupt
		}
		if _, ok := ref.Value["owner_pk"].(*types.AttributeValueMemberS); !ok {
			return sessionControlCloseManifest{}, errSessionControlMaterializationCorrupt
		}
		if _, ok := ref.Value["creation_digest"].(*types.AttributeValueMemberS); !ok {
			return sessionControlCloseManifest{}, errSessionControlMaterializationCorrupt
		}
		if _, ok := ref.Value["source_digest"].(*types.AttributeValueMemberS); !ok {
			return sessionControlCloseManifest{}, errSessionControlMaterializationCorrupt
		}
		if _, ok := ref.Value["source_count"].(*types.AttributeValueMemberN); !ok {
			return sessionControlCloseManifest{}, errSessionControlMaterializationCorrupt
		}
	}
	var row sessionControlCloseManifestRow
	if err := attributevalue.UnmarshalMap(item, &row); err != nil {
		return sessionControlCloseManifest{}, errSessionControlMaterializationCorrupt
	}
	manifest := sessionControlCloseManifest{CellID: row.CellID, EventID: row.EventID, SelectorDigest: row.SelectorDigest,
		SessionVersion: row.SessionVersion, ExpectedTargetCount: row.ExpectedTargetCount,
		PreparedDirectoryVersion: row.PreparedDirectoryVersion, WorkMode: row.WorkMode,
		ManifestIndex: row.ManifestIndex, Refs: row.Refs,
		ManifestDigest: row.ManifestDigest, CreatedAtMillis: row.CreatedAtMillis}
	if row.PK != sessionControlFenceMetaPK(eventID) || row.SK != sessionControlCloseManifestSK(index) ||
		row.Kind != sessionControlCloseManifestKind || row.SchemaVersion != sessionControlCloseManifestSchema ||
		row.EventID != eventID || row.ManifestIndex != index || validateSessionControlCloseManifest(manifest) != nil {
		return sessionControlCloseManifest{}, errSessionControlMaterializationCorrupt
	}
	return manifest, nil
}

func sessionControlCloseTaskSetToRow(taskSet sessionControlCloseTaskSet) (sessionControlCloseTaskSetRow, error) {
	if err := validateSessionControlCloseTaskSet(taskSet); err != nil {
		return sessionControlCloseTaskSetRow{}, err
	}
	return sessionControlCloseTaskSetRow{PK: sessionControlFenceMetaPK(taskSet.EventID), SK: sessionControlCloseTaskSetSK,
		Kind: sessionControlCloseTaskSetKind, SchemaVersion: sessionControlCloseTaskSetSchema, CellID: taskSet.CellID,
		EventID: taskSet.EventID, SelectorDigest: taskSet.SelectorDigest, SessionVersion: taskSet.SessionVersion,
		ExpectedTargetCount: taskSet.ExpectedTargetCount, PreparedDirectoryVersion: taskSet.PreparedDirectoryVersion,
		WorkMode:    taskSet.WorkMode,
		SourceCount: taskSet.SourceCount, OwnerCount: taskSet.OwnerCount, ManifestDigests: taskSet.ManifestDigests,
		ManifestSourceCounts: taskSet.ManifestSourceCounts, ManifestOwnerCounts: taskSet.ManifestOwnerCounts,
		TaskSetDigest: taskSet.TaskSetDigest, CreatedAtMillis: taskSet.CreatedAtMillis}, nil
}

func sessionControlCloseTaskSetFromItem(item map[string]types.AttributeValue, eventID string) (sessionControlCloseTaskSet, error) {
	if len(item) == 0 {
		return sessionControlCloseTaskSet{}, errSessionControlSessionNotFound
	}
	if _, hasTTL := item["ttl"]; hasTTL {
		return sessionControlCloseTaskSet{}, errSessionControlMaterializationCorrupt
	}
	if _, ok := item["work_mode"].(*types.AttributeValueMemberS); !ok {
		return sessionControlCloseTaskSet{}, errSessionControlMaterializationCorrupt
	}
	for _, name := range []string{"schema_version", "session_version", "expected_target_count",
		"prepared_directory_version", "source_count", "owner_count", "created_at_ms"} {
		if _, ok := item[name].(*types.AttributeValueMemberN); !ok {
			return sessionControlCloseTaskSet{}, errSessionControlMaterializationCorrupt
		}
	}
	for _, name := range []string{"manifest_digests", "manifest_source_counts", "manifest_owner_counts"} {
		list, ok := item[name].(*types.AttributeValueMemberL)
		if !ok {
			return sessionControlCloseTaskSet{}, errSessionControlMaterializationCorrupt
		}
		for _, value := range list.Value {
			if name == "manifest_digests" {
				if _, ok := value.(*types.AttributeValueMemberS); !ok {
					return sessionControlCloseTaskSet{}, errSessionControlMaterializationCorrupt
				}
			} else if _, ok := value.(*types.AttributeValueMemberN); !ok {
				return sessionControlCloseTaskSet{}, errSessionControlMaterializationCorrupt
			}
		}
	}
	var row sessionControlCloseTaskSetRow
	if err := attributevalue.UnmarshalMap(item, &row); err != nil {
		return sessionControlCloseTaskSet{}, errSessionControlMaterializationCorrupt
	}
	taskSet := sessionControlCloseTaskSet{CellID: row.CellID, EventID: row.EventID, SelectorDigest: row.SelectorDigest,
		SessionVersion: row.SessionVersion, ExpectedTargetCount: row.ExpectedTargetCount,
		PreparedDirectoryVersion: row.PreparedDirectoryVersion, WorkMode: row.WorkMode,
		SourceCount: row.SourceCount, OwnerCount: row.OwnerCount,
		ManifestDigests: row.ManifestDigests, ManifestSourceCounts: row.ManifestSourceCounts,
		ManifestOwnerCounts: row.ManifestOwnerCounts, TaskSetDigest: row.TaskSetDigest, CreatedAtMillis: row.CreatedAtMillis}
	if row.PK != sessionControlFenceMetaPK(eventID) || row.SK != sessionControlCloseTaskSetSK ||
		row.Kind != sessionControlCloseTaskSetKind || row.SchemaVersion != sessionControlCloseTaskSetSchema ||
		row.EventID != eventID || validateSessionControlCloseTaskSet(taskSet) != nil {
		return sessionControlCloseTaskSet{}, errSessionControlMaterializationCorrupt
	}
	return taskSet, nil
}

func (s *dynamoSessionControlStore) getCloseManifest(ctx context.Context, eventID string, index uint64) (*sessionControlCloseManifest, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true),
		Key: sessionControlCloseManifestKey(eventID, index)})
	if err != nil {
		return nil, fmt.Errorf("session-control close manifest strong read: %w", err)
	}
	manifest, err := sessionControlCloseManifestFromItem(result.Item, eventID, index)
	if err != nil {
		return nil, err
	}
	return &manifest, nil
}

func (s *dynamoSessionControlStore) getCloseTaskSet(ctx context.Context, eventID string) (*sessionControlCloseTaskSet, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true),
		Key: sessionControlCloseTaskSetKey(eventID)})
	if err != nil {
		return nil, fmt.Errorf("session-control close taskset strong read: %w", err)
	}
	taskSet, err := sessionControlCloseTaskSetFromItem(result.Item, eventID)
	if err != nil {
		return nil, err
	}
	return &taskSet, nil
}

func sessionControlCloseIntentOrderKey(intent sessionControlSessionIntent) string {
	encoded, _ := json.Marshal(intent)
	return sessionControlOwnerPK(intent.Target.ControlCellID, intent.Target.ACID, intent.Target.PublicKey) + "\x00" + string(encoded)
}

func sessionControlCloseSessionRetainCompatible(base, current sessionControlSessionAuthority) bool {
	if current.RetainUntilMillis < base.RetainUntilMillis {
		return false
	}
	current.RetainUntilMillis = base.RetainUntilMillis
	return current == base
}

// listStableCloseSourceIntents uses one aggregate store deadline. The session
// header brackets the strongly consistent, paginated forward-intent query; an
// exact physical count match against both SESSION and WORK is required before
// the rows can become materialization input.
func (s *dynamoSessionControlStore) listStableCloseSourceIntents(ctx context.Context,
	close *sessionControlExactClosePreparation) ([]sessionControlSessionIntent, error) {
	if close == nil {
		return nil, errSessionControlMaterializationCorrupt
	}
	readCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	for range sessionControlCloseReadAttempts {
		before, err := s.classifyReservation(readCtx, close.Session.Candidate)
		if err != nil {
			return nil, err
		}
		var intents []sessionControlSessionIntent
		var lastKey map[string]types.AttributeValue
		physical := 0
		for {
			result, queryErr := s.client.Query(readCtx, &dynamodb.QueryInput{
				TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true),
				KeyConditionExpression: aws.String("pk = :pk AND begins_with(sk, :prefix)"),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":pk":     &types.AttributeValueMemberS{Value: sessionControlSessionPK(close.Session.Candidate.SessionID)},
					":prefix": &types.AttributeValueMemberS{Value: sessionControlSessionTargetPrefix},
				},
				ExclusiveStartKey: lastKey, Limit: aws.Int32(sessionControlCloseQueryLimit),
			})
			if queryErr != nil {
				return nil, fmt.Errorf("session-control close source strong query: %w", queryErr)
			}
			physical += len(result.Items)
			if physical > int(sessionControlSessionMaxTargets) {
				return nil, errSessionControlMaterializationCapacity
			}
			for _, item := range result.Items {
				if _, hasTTL := item["ttl"]; hasTTL || !sessionControlIntentTargetReadinessAttributesPresent(item) {
					return nil, errSessionControlMaterializationCorrupt
				}
				var row sessionControlSessionIntentRow
				if unmarshalErr := attributevalue.UnmarshalMap(item, &row); unmarshalErr != nil {
					return nil, errSessionControlMaterializationCorrupt
				}
				intent, decodeErr := sessionControlIntentFromRow(row, false)
				if decodeErr != nil || intent.Session != close.Session.Candidate {
					return nil, errSessionControlMaterializationCorrupt
				}
				intents = append(intents, intent)
			}
			if len(result.LastEvaluatedKey) == 0 {
				break
			}
			lastKey = result.LastEvaluatedKey
		}
		after, err := s.classifyReservation(readCtx, close.Session.Candidate)
		if err != nil {
			return nil, err
		}
		overflow := close.Work.Mode == sessionControlCloseWorkModeOverflow
		work, err := s.getCloseWork(readCtx, close.Session.Candidate.CellID, close.EventID, overflow)
		if err != nil {
			return nil, err
		}
		if !sessionControlCloseSessionRetainCompatible(*before, *after) ||
			!sessionControlCloseSessionRetainCompatible(close.Session, *after) {
			return nil, errSessionControlMaterializationCorrupt
		}
		if *work != close.Work || after.State != sessionControlSessionStateClosing ||
			uint64(physical) != after.TargetCount || uint64(physical) != work.ExpectedTargetCount {
			return nil, errSessionControlMaterializationCorrupt
		}
		close.Session = *after
		sort.Slice(intents, func(i, j int) bool {
			return sessionControlCloseIntentOrderKey(intents[i]) < sessionControlCloseIntentOrderKey(intents[j])
		})
		return intents, nil
	}
	return nil, errSessionControlMaterializationConflict
}

func sessionControlCloseSourceGroups(intents []sessionControlSessionIntent) ([]sessionControlCloseSourceGroup, error) {
	byOwner := make(map[string][]sessionControlSessionIntent)
	for _, intent := range intents {
		if validateSessionControlSessionIntent(intent) != nil {
			return nil, errSessionControlMaterializationCorrupt
		}
		ownerPK := sessionControlOwnerPK(intent.Target.ControlCellID, intent.Target.ACID, intent.Target.PublicKey)
		byOwner[ownerPK] = append(byOwner[ownerPK], intent)
	}
	ownerPKs := make([]string, 0, len(byOwner))
	for ownerPK := range byOwner {
		ownerPKs = append(ownerPKs, ownerPK)
	}
	sort.Strings(ownerPKs)
	groups := make([]sessionControlCloseSourceGroup, 0, len(ownerPKs))
	for _, ownerPK := range ownerPKs {
		groupIntents := byOwner[ownerPK]
		sort.Slice(groupIntents, func(i, j int) bool {
			return sessionControlCloseIntentOrderKey(groupIntents[i]) < sessionControlCloseIntentOrderKey(groupIntents[j])
		})
		digest, err := sessionControlCloseSourceDigest(groupIntents)
		if err != nil {
			return nil, err
		}
		selected := groupIntents[0].Target
		generationBoot := make(map[uint64]string, len(groupIntents))
		for _, intent := range groupIntents {
			target := intent.Target
			if boot, exists := generationBoot[target.FlushGeneration]; exists && boot != target.BootID {
				return nil, errSessionControlMaterializationCorrupt
			}
			generationBoot[target.FlushGeneration] = target.BootID
			if target.FlushGeneration > selected.FlushGeneration {
				selected = target
				continue
			}
		}
		groups = append(groups, sessionControlCloseSourceGroup{OwnerPK: ownerPK, CellID: selected.ControlCellID,
			ACID: selected.ACID, PublicKey: selected.PublicKey, Intents: groupIntents, SourceDigest: digest,
			SourceBootID: selected.BootID, SourceFlushGeneration: selected.FlushGeneration})
	}
	return groups, nil
}

func sessionControlCloseOwnerTargetMatch(owner sessionControlOwnerAuthority, target sessionControlTargetAuthority) bool {
	if !target.required() {
		return false
	}
	switch target.State {
	case sessionControlTargetPreparing:
		return target.CountedActiveSlot && owner.exactTarget(target, sessionControlOwnerPreparing)
	case sessionControlTargetActive:
		if target.ready() && owner.PendingCount == 0 {
			return owner.exactTarget(target, sessionControlOwnerReady)
		}
		return owner.exactTarget(target, sessionControlOwnerActiveUnready) &&
			(!target.ready() || owner.PendingCount > 0)
	default:
		return false
	}
}

func (s *dynamoSessionControlStore) readStableCloseOwnerTarget(ctx context.Context,
	group sessionControlCloseSourceGroup, taskLimit uint64) (sessionControlOwnerAuthority, sessionControlTargetAuthority, error) {
	if taskLimit == 0 || taskLimit > sessionControlOwnerTaskLimit {
		return sessionControlOwnerAuthority{}, sessionControlTargetAuthority{}, errSessionControlMaterializationCorrupt
	}
	for range sessionControlCloseReadAttempts {
		before, err := s.getOwner(ctx, group.CellID, group.ACID, group.PublicKey)
		if err != nil {
			return sessionControlOwnerAuthority{}, sessionControlTargetAuthority{}, err
		}
		target, err := s.getTarget(ctx, sessionControlTargetKey{ACID: group.ACID, PublicKey: group.PublicKey})
		if err != nil {
			return sessionControlOwnerAuthority{}, sessionControlTargetAuthority{}, err
		}
		after, err := s.getOwner(ctx, group.CellID, group.ACID, group.PublicKey)
		if err != nil {
			return sessionControlOwnerAuthority{}, sessionControlTargetAuthority{}, err
		}
		if *before != *after {
			continue
		}
		if !sessionControlCloseOwnerTargetMatch(*after, *target) {
			return sessionControlOwnerAuthority{}, sessionControlTargetAuthority{}, errSessionControlMaterializationCorrupt
		}
		if target.FlushGeneration < group.SourceFlushGeneration {
			return sessionControlOwnerAuthority{}, sessionControlTargetAuthority{}, errSessionControlMaterializationConflict
		}
		if target.FlushGeneration == group.SourceFlushGeneration && target.BootID != group.SourceBootID {
			return sessionControlOwnerAuthority{}, sessionControlTargetAuthority{}, errSessionControlMaterializationConflict
		}
		if after.TaskCount >= taskLimit {
			return sessionControlOwnerAuthority{}, sessionControlTargetAuthority{}, errSessionControlMaterializationCapacity
		}
		return *after, *target, nil
	}
	return sessionControlOwnerAuthority{}, sessionControlTargetAuthority{}, errSessionControlMaterializationConflict
}

func sessionControlCloseManifestMatchesSources(manifest sessionControlCloseManifest,
	close *sessionControlExactClosePreparation, groups []sessionControlCloseSourceGroup, index uint64) bool {
	if close == nil || manifest.CellID != close.Session.Candidate.CellID || manifest.EventID != close.EventID ||
		manifest.SelectorDigest != close.Work.SelectorDigest || manifest.SessionVersion != close.Session.Version ||
		manifest.ExpectedTargetCount != close.Work.ExpectedTargetCount ||
		manifest.PreparedDirectoryVersion != close.Work.PreparedDirectoryVersion ||
		manifest.WorkMode != close.Work.Mode ||
		manifest.ManifestIndex != index || manifest.CreatedAtMillis != close.Work.CreatedAtMillis || len(manifest.Refs) != len(groups) {
		return false
	}
	for i, group := range groups {
		ref := manifest.Refs[i]
		if ref.OwnerPK != group.OwnerPK || ref.SourceDigest != group.SourceDigest || ref.SourceCount != uint64(len(group.Intents)) || ref.CreationDigest == "" {
			return false
		}
	}
	return true
}

func sessionControlCloseBuildTask(close *sessionControlExactClosePreparation, manifestIndex uint64, group sessionControlCloseSourceGroup,
	owner sessionControlOwnerAuthority, target sessionControlTargetAuthority) (sessionControlCloseTask, error) {
	next, err := planSessionControlOwnerTaskInsert(owner, close.Work.CreatedAtMillis)
	if err != nil {
		return sessionControlCloseTask{}, err
	}
	task := sessionControlCloseTask{CellID: close.Session.Candidate.CellID, EventID: close.EventID,
		SelectorDigest: close.Work.SelectorDigest, SessionVersion: close.Work.SessionVersion,
		ExpectedTargetCount:      close.Work.ExpectedTargetCount,
		PreparedDirectoryVersion: close.Work.PreparedDirectoryVersion,
		ManifestIndex:            manifestIndex, WorkMode: close.Work.Mode,
		OwnerPK: group.OwnerPK, ACID: group.ACID, PublicKey: group.PublicKey,
		SourceDigest: group.SourceDigest, SourceCount: uint64(len(group.Intents)), SourceBootID: group.SourceBootID,
		SourceFlushGeneration: group.SourceFlushGeneration, CreationTarget: target, OwnerBefore: owner, OwnerAfter: next,
		TaskVersion: 1, State: sessionControlCloseTaskStatePending, BoundBootID: target.BootID,
		BoundFlushGeneration: target.FlushGeneration, BoundTargetVersion: target.Version,
		BoundAuthorityVersion: target.AuthorityVersion, BoundOwnerLifecycle: next.LifecycleVersion,
		BoundActivatedCursor: target.ActivatedControlVersion, BoundReadyCursor: target.ReadyControlVersion,
		CurrentOwnerWorkVersion: next.WorkVersion, CurrentOwnerTaskCount: next.TaskCount,
		CurrentOwnerPendingCount: next.PendingCount,
		DueAtMillis:              close.Work.CreatedAtMillis, CreatedAtMillis: close.Work.CreatedAtMillis,
		UpdatedAtMillis: close.Work.CreatedAtMillis}
	task.DueShard = sessionControlCloseTaskDueShard(task)
	task.DueSort = sessionControlCloseTaskDueSort(task)
	task.CreationDigest, err = sessionControlCloseTaskCreationDigest(task)
	task.LastOperationKind = sessionControlCloseTaskOperationMaterialized
	task.LastOperationID = task.CreationDigest
	task.LastOperationInputDigest = task.CreationDigest
	if err != nil || validateSessionControlCloseTask(task) != nil {
		return sessionControlCloseTask{}, errSessionControlMaterializationCorrupt
	}
	return task, nil
}

func sessionControlExactItemCondition(item map[string]types.AttributeValue, absent ...string) (string, map[string]string, map[string]types.AttributeValue) {
	keys := make([]string, 0, len(item))
	for key := range item {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys)+len(absent)+1)
	names := make(map[string]string, len(keys)+len(absent))
	values := make(map[string]types.AttributeValue, len(keys))
	for index, key := range keys {
		name, value := fmt.Sprintf("#exact_%d", index), fmt.Sprintf(":exact_%d", index)
		names[name] = key
		values[value] = item[key]
		parts = append(parts, name+" = "+value)
	}
	seenAbsent := map[string]struct{}{"ttl": {}}
	absent = append(absent, "ttl")
	for _, key := range absent {
		if _, exists := item[key]; exists {
			continue
		}
		if _, duplicate := seenAbsent[key]; duplicate && key != "ttl" {
			continue
		}
		seenAbsent[key] = struct{}{}
		name := fmt.Sprintf("#exact_absent_%d", len(names))
		names[name] = key
		parts = append(parts, "attribute_not_exists("+name+")")
	}
	return strings.Join(parts, " AND "), names, values
}

func sessionControlCloseSessionCondition(tableName string, session sessionControlSessionAuthority) (types.TransactWriteItem, error) {
	row, err := sessionControlSessionToRow(session)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, fmt.Errorf("marshal close materialization session condition: %w", err)
	}
	delete(item, "retain_until_ms")
	condition, names, values := sessionControlExactItemCondition(item, "session_expires_at_ms", "ack_enqueued_at_ms", "due_shard", "due_sort")
	names["#exact_retain"] = "retain_until_ms"
	values[":exact_min_retain"] = &types.AttributeValueMemberN{Value: fmt.Sprint(session.RetainUntilMillis)}
	condition += " AND #exact_retain >= :exact_min_retain"
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{TableName: aws.String(tableName),
		Key: sessionControlSessionDynamoKey(session.Candidate.SessionID), ConditionExpression: aws.String(condition),
		ExpressionAttributeNames: names, ExpressionAttributeValues: values}}, nil
}

func sessionControlCloseWorkCondition(tableName string, work sessionControlCloseWork) (types.TransactWriteItem, error) {
	row, err := sessionControlCloseWorkToRow(work)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, fmt.Errorf("marshal close materialization work condition: %w", err)
	}
	condition, names, values := sessionControlExactItemCondition(item, "session_id", "session_issued_ms",
		"issued_through_ms", "run_id", "run_attempt")
	key := sessionControlCloseWorkKey(work.EventID)
	if work.Mode == sessionControlCloseWorkModeOverflow {
		key = sessionControlOverflowCloseKey(work.CellID, work.EventID)
	}
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{TableName: aws.String(tableName),
		Key: key, ConditionExpression: aws.String(condition),
		ExpressionAttributeNames: names, ExpressionAttributeValues: values}}, nil
}

func sessionControlCloseManifestCondition(tableName string, manifest sessionControlCloseManifest) (types.TransactWriteItem, error) {
	row, err := sessionControlCloseManifestToRow(manifest)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	condition, names, values := sessionControlExactItemCondition(item)
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{TableName: aws.String(tableName),
		Key:                 sessionControlCloseManifestKey(manifest.EventID, manifest.ManifestIndex),
		ConditionExpression: aws.String(condition), ExpressionAttributeNames: names,
		ExpressionAttributeValues: values}}, nil
}

func sessionControlCloseTaskPut(tableName string, task sessionControlCloseTask) (types.TransactWriteItem, error) {
	row, err := sessionControlCloseTaskToRow(task)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, fmt.Errorf("marshal close materialization task: %w", err)
	}
	return types.TransactWriteItem{Put: &types.Put{TableName: aws.String(tableName), Item: item,
		ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}}, nil
}

func sessionControlCloseManifestPut(tableName string, manifest sessionControlCloseManifest) (types.TransactWriteItem, error) {
	row, err := sessionControlCloseManifestToRow(manifest)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, fmt.Errorf("marshal close materialization manifest: %w", err)
	}
	return types.TransactWriteItem{Put: &types.Put{TableName: aws.String(tableName), Item: item,
		ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}}, nil
}

func sessionControlCloseTaskSetPut(tableName string, taskSet sessionControlCloseTaskSet) (types.TransactWriteItem, error) {
	row, err := sessionControlCloseTaskSetToRow(taskSet)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, fmt.Errorf("marshal close materialization taskset: %w", err)
	}
	return types.TransactWriteItem{Put: &types.Put{TableName: aws.String(tableName), Item: item,
		ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}}, nil
}

func sessionControlCloseMaterializationToken(prefix string, value any) (*string, error) {
	digest, err := sessionControlMaterializationDigest(value)
	if err != nil {
		return nil, err
	}
	token := prefix + digest[:24]
	if len(token) > 36 {
		return nil, errSessionControlMaterializationCorrupt
	}
	return aws.String(token), nil
}

func sessionControlCloseBuildManifest(close *sessionControlExactClosePreparation, index uint64,
	tasks []sessionControlCloseTask) (sessionControlCloseManifest, error) {
	refs := make([]sessionControlCloseTaskRef, len(tasks))
	for i, task := range tasks {
		if task.ManifestIndex != index || task.WorkMode != close.Work.Mode {
			return sessionControlCloseManifest{}, errSessionControlMaterializationCorrupt
		}
		refs[i] = sessionControlCloseTaskRef{OwnerPK: task.OwnerPK,
			CreationDigest: task.CreationDigest, SourceDigest: task.SourceDigest, SourceCount: task.SourceCount}
	}
	manifest := sessionControlCloseManifest{CellID: close.Session.Candidate.CellID, EventID: close.EventID,
		SelectorDigest: close.Work.SelectorDigest, SessionVersion: close.Work.SessionVersion,
		ExpectedTargetCount:      close.Work.ExpectedTargetCount,
		PreparedDirectoryVersion: close.Work.PreparedDirectoryVersion,
		WorkMode:                 close.Work.Mode,
		ManifestIndex:            index, Refs: refs, CreatedAtMillis: close.Work.CreatedAtMillis}
	digest, err := sessionControlCloseManifestDigest(manifest)
	if err != nil {
		return sessionControlCloseManifest{}, err
	}
	manifest.ManifestDigest = digest
	if validateSessionControlCloseManifest(manifest) != nil {
		return sessionControlCloseManifest{}, errSessionControlMaterializationCorrupt
	}
	return manifest, nil
}

func sessionControlCloseTaskSetMatchesCandidate(taskSet sessionControlCloseTaskSet,
	candidate sessionControlSessionCandidate, eventID, mode string) bool {
	digest, err := sessionControlFenceSelectorDigest(sessionControlExactCloseSelector(candidate))
	return err == nil && taskSet.CellID == candidate.CellID && taskSet.EventID == eventID &&
		taskSet.SelectorDigest == digest && taskSet.WorkMode == mode &&
		eventID == sessionControlExactCloseEventID(candidate)
}

func sessionControlCloseTaskSetMatchesPreparation(taskSet sessionControlCloseTaskSet,
	close *sessionControlExactClosePreparation) bool {
	return close != nil && taskSet.CellID == close.Work.CellID && taskSet.EventID == close.EventID &&
		taskSet.SelectorDigest == close.Work.SelectorDigest && taskSet.SessionVersion == close.Work.SessionVersion &&
		taskSet.ExpectedTargetCount == close.Work.ExpectedTargetCount &&
		taskSet.PreparedDirectoryVersion == close.Work.PreparedDirectoryVersion &&
		taskSet.WorkMode == close.Work.Mode && taskSet.CreatedAtMillis == close.Work.CreatedAtMillis
}

func sessionControlCloseTaskSetMatchesClose(taskSet sessionControlCloseTaskSet,
	close *sessionControlExactClosePreparation, sourceCount, ownerCount uint64, manifests []sessionControlCloseManifest) bool {
	if close == nil || taskSet.CellID != close.Session.Candidate.CellID || taskSet.EventID != close.EventID ||
		taskSet.SelectorDigest != close.Work.SelectorDigest || taskSet.SessionVersion != close.Work.SessionVersion ||
		taskSet.ExpectedTargetCount != close.Work.ExpectedTargetCount ||
		taskSet.PreparedDirectoryVersion != close.Work.PreparedDirectoryVersion ||
		taskSet.WorkMode != close.Work.Mode ||
		taskSet.SourceCount != sourceCount || taskSet.OwnerCount != ownerCount || len(taskSet.ManifestDigests) != len(manifests) ||
		taskSet.CreatedAtMillis != close.Work.CreatedAtMillis {
		return false
	}
	for index, manifest := range manifests {
		var sourceSum uint64
		for _, ref := range manifest.Refs {
			sourceSum += ref.SourceCount
		}
		if taskSet.ManifestDigests[index] != manifest.ManifestDigest ||
			taskSet.ManifestSourceCounts[index] != sourceSum ||
			taskSet.ManifestOwnerCounts[index] != uint64(len(manifest.Refs)) {
			return false
		}
	}
	return true
}

func sessionControlOverflowLeaderMatchesWork(directory sessionControlFenceDirectory,
	work sessionControlCloseWork) bool {
	return work.Mode == sessionControlCloseWorkModeOverflow && directory.CellID == work.CellID &&
		directory.AdmissionBlocked && directory.OverflowCloseCount > 0 &&
		directory.OverflowLeaderEventID == work.EventID &&
		directory.OverflowLeaderPreparedDirectoryVersion == work.PreparedDirectoryVersion &&
		directory.OverflowLeaderSelectedDirectoryVersion > work.PreparedDirectoryVersion &&
		directory.OverflowLeaderSelectedDirectoryVersion <= directory.Version
}

func sessionControlOverflowLeaderMatchesClose(directory sessionControlFenceDirectory,
	close *sessionControlExactClosePreparation) bool {
	return close != nil && close.Overflow && directory.CellID == close.Session.Candidate.CellID &&
		sessionControlOverflowLeaderMatchesWork(directory, close.Work)
}

func sessionControlCloseDirectorySnapshot(directory sessionControlFenceDirectory) sessionControlFenceSnapshot {
	return sessionControlFenceSnapshot{CellID: directory.CellID, DirectoryVersion: directory.Version,
		ActiveFenceCount: directory.ActiveFenceCount, AdmissionBlocked: directory.AdmissionBlocked,
		OverflowCloseCount: directory.OverflowCloseCount, OverflowLeaderEventID: directory.OverflowLeaderEventID,
		OverflowLeaderPreparedDirectoryVersion: directory.OverflowLeaderPreparedDirectoryVersion,
		OverflowLeaderSelectedDirectoryVersion: directory.OverflowLeaderSelectedDirectoryVersion}
}

func sessionControlCloseDirectoryCursor(directory sessionControlFenceDirectory) sessionControlTargetDirectoryFence {
	return sessionControlTargetDirectoryFence{CellID: directory.CellID, DirectoryVersion: directory.Version,
		ActiveFenceCount: directory.ActiveFenceCount, AdmissionBlocked: directory.AdmissionBlocked,
		OverflowCloseCount: directory.OverflowCloseCount, OverflowLeaderEventID: directory.OverflowLeaderEventID,
		OverflowLeaderPreparedDirectoryVersion: directory.OverflowLeaderPreparedDirectoryVersion,
		OverflowLeaderSelectedDirectoryVersion: directory.OverflowLeaderSelectedDirectoryVersion}
}

func (s *dynamoSessionControlStore) materializeCloseManifest(ctx context.Context,
	close *sessionControlExactClosePreparation, index uint64,
	groups []sessionControlCloseSourceGroup, leader *sessionControlFenceDirectory) (sessionControlCloseManifest, error) {
	if existing, err := s.getCloseManifest(ctx, close.EventID, index); err == nil {
		if !sessionControlCloseManifestMatchesSources(*existing, close, groups, index) {
			return sessionControlCloseManifest{}, errSessionControlMaterializationCorrupt
		}
		return *existing, nil
	} else if !errors.Is(err, errSessionControlSessionNotFound) {
		return sessionControlCloseManifest{}, err
	}

	for range sessionControlCloseReadAttempts {
		tasks := make([]sessionControlCloseTask, 0, len(groups))
		taskLimit := uint64(sessionControlNormalCloseTaskLimit)
		if close.Work.Mode == sessionControlCloseWorkModeOverflow {
			if leader == nil || !sessionControlOverflowLeaderMatchesClose(*leader, close) {
				return sessionControlCloseManifest{}, errSessionControlMaterializationConflict
			}
			taskLimit = sessionControlOwnerTaskLimit
		}
		for _, group := range groups {
			owner, target, err := s.readStableCloseOwnerTarget(ctx, group, taskLimit)
			if err != nil {
				return sessionControlCloseManifest{}, err
			}
			task, err := sessionControlCloseBuildTask(close, index, group, owner, target)
			if err != nil {
				return sessionControlCloseManifest{}, err
			}
			tasks = append(tasks, task)
		}
		manifest, err := sessionControlCloseBuildManifest(close, index, tasks)
		if err != nil {
			return sessionControlCloseManifest{}, err
		}
		sessionCondition, err := sessionControlCloseSessionCondition(s.tableName, close.Session)
		if err != nil {
			return sessionControlCloseManifest{}, err
		}
		workCondition, err := sessionControlCloseWorkCondition(s.tableName, close.Work)
		if err != nil {
			return sessionControlCloseManifest{}, err
		}
		manifestPut, err := sessionControlCloseManifestPut(s.tableName, manifest)
		if err != nil {
			return sessionControlCloseManifest{}, err
		}
		items := make([]types.TransactWriteItem, 0, 3+2*len(tasks))
		items = append(items, sessionCondition, workCondition, manifestPut)
		if leader != nil {
			directoryCondition := sessionControlDirectoryCondition(sessionControlCloseDirectorySnapshot(*leader))
			directoryCondition.ConditionCheck.TableName = aws.String(s.tableName)
			items = append(items, directoryCondition)
		}
		for _, task := range tasks {
			ownerReplace, replaceErr := sessionControlOwnerReplace(s.tableName, task.OwnerBefore, task.OwnerAfter)
			if replaceErr != nil {
				return sessionControlCloseManifest{}, replaceErr
			}
			taskPut, putErr := sessionControlCloseTaskPut(s.tableName, task)
			if putErr != nil {
				return sessionControlCloseManifest{}, putErr
			}
			items = append(items, ownerReplace, taskPut)
		}
		if len(items) > 99 {
			return sessionControlCloseManifest{}, errSessionControlMaterializationCorrupt
		}
		token, err := sessionControlCloseMaterializationToken("scm-m-", struct {
			Version  uint64
			Session  sessionControlSessionAuthority
			Work     sessionControlCloseWork
			Leader   *sessionControlFenceDirectory
			Manifest sessionControlCloseManifest
			Tasks    []sessionControlCloseTask
		}{1, close.Session, close.Work, leader, manifest, tasks})
		if err != nil {
			return sessionControlCloseManifest{}, err
		}
		_, writeErr := s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{ClientRequestToken: token, TransactItems: items})
		if writeErr == nil {
			return manifest, nil
		}

		resultCtx, cancel := s.sessionResultContext(ctx)
		existing, classifyErr := s.getCloseManifest(resultCtx, close.EventID, index)
		cancel()
		if classifyErr == nil {
			if !sessionControlCloseManifestMatchesSources(*existing, close, groups, index) {
				return sessionControlCloseManifest{}, errSessionControlMaterializationCorrupt
			}
			return *existing, nil
		}
		if !errors.Is(classifyErr, errSessionControlSessionNotFound) {
			return sessionControlCloseManifest{}, classifyErr
		}
		var canceled *types.TransactionCanceledException
		if errors.As(writeErr, &canceled) {
			continue
		}
		return sessionControlCloseManifest{}, fmt.Errorf("materialize session-control close manifest: %w", writeErr)
	}
	return sessionControlCloseManifest{}, errSessionControlMaterializationConflict
}

func sessionControlCloseBuildTaskSet(close *sessionControlExactClosePreparation, sourceCount, ownerCount uint64,
	manifests []sessionControlCloseManifest) (sessionControlCloseTaskSet, error) {
	taskSet := sessionControlCloseTaskSet{CellID: close.Session.Candidate.CellID, EventID: close.EventID,
		SelectorDigest: close.Work.SelectorDigest, SessionVersion: close.Work.SessionVersion,
		ExpectedTargetCount:      close.Work.ExpectedTargetCount,
		PreparedDirectoryVersion: close.Work.PreparedDirectoryVersion,
		WorkMode:                 close.Work.Mode,
		SourceCount:              sourceCount, OwnerCount: ownerCount, CreatedAtMillis: close.Work.CreatedAtMillis,
		ManifestDigests: make([]string, len(manifests)), ManifestSourceCounts: make([]uint64, len(manifests)),
		ManifestOwnerCounts: make([]uint64, len(manifests))}
	for index, manifest := range manifests {
		taskSet.ManifestDigests[index] = manifest.ManifestDigest
		taskSet.ManifestOwnerCounts[index] = uint64(len(manifest.Refs))
		for _, ref := range manifest.Refs {
			taskSet.ManifestSourceCounts[index] += ref.SourceCount
		}
	}
	digest, err := sessionControlCloseTaskSetDigest(taskSet)
	if err != nil {
		return sessionControlCloseTaskSet{}, err
	}
	taskSet.TaskSetDigest = digest
	if validateSessionControlCloseTaskSet(taskSet) != nil {
		return sessionControlCloseTaskSet{}, errSessionControlMaterializationCorrupt
	}
	return taskSet, nil
}

func (s *dynamoSessionControlStore) commitCloseTaskSet(ctx context.Context,
	close *sessionControlExactClosePreparation, sourceCount, ownerCount uint64,
	manifests []sessionControlCloseManifest, leader *sessionControlFenceDirectory) (*sessionControlCloseTaskSet, error) {
	taskSet, err := sessionControlCloseBuildTaskSet(close, sourceCount, ownerCount, manifests)
	if err != nil {
		return nil, err
	}
	if existing, readErr := s.getCloseTaskSet(ctx, close.EventID); readErr == nil {
		if !sessionControlCloseTaskSetMatchesClose(*existing, close, sourceCount, ownerCount, manifests) {
			return nil, errSessionControlMaterializationCorrupt
		}
		return existing, nil
	} else if !errors.Is(readErr, errSessionControlSessionNotFound) {
		return nil, readErr
	}

	workCondition, err := sessionControlCloseWorkCondition(s.tableName, close.Work)
	if err != nil {
		return nil, err
	}
	items := make([]types.TransactWriteItem, 0, 3+len(manifests))
	if leader == nil {
		sessionCondition, conditionErr := sessionControlCloseSessionCondition(s.tableName, close.Session)
		if conditionErr != nil {
			return nil, conditionErr
		}
		items = append(items, sessionCondition, workCondition)
	} else {
		if !sessionControlOverflowLeaderMatchesClose(*leader, close) {
			return nil, errSessionControlMaterializationConflict
		}
		directoryCondition := sessionControlDirectoryCondition(sessionControlCloseDirectorySnapshot(*leader))
		directoryCondition.ConditionCheck.TableName = aws.String(s.tableName)
		items = append(items, directoryCondition, workCondition)
		// With no manifest transaction, the zero-target TASKSET is the first
		// materialization write and must itself bind the CLOSING session.
		if len(manifests) == 0 {
			sessionCondition, conditionErr := sessionControlCloseSessionCondition(s.tableName, close.Session)
			if conditionErr != nil {
				return nil, conditionErr
			}
			items = append(items, sessionCondition)
		}
	}
	for _, manifest := range manifests {
		condition, conditionErr := sessionControlCloseManifestCondition(s.tableName, manifest)
		if conditionErr != nil {
			return nil, conditionErr
		}
		items = append(items, condition)
	}
	put, err := sessionControlCloseTaskSetPut(s.tableName, taskSet)
	if err != nil {
		return nil, err
	}
	items = append(items, put)
	if len(items) > 25 {
		return nil, errSessionControlMaterializationCorrupt
	}
	token, err := sessionControlCloseMaterializationToken("scm-s-", struct {
		Version   uint64
		Session   sessionControlSessionAuthority
		Work      sessionControlCloseWork
		Leader    *sessionControlFenceDirectory
		Manifests []sessionControlCloseManifest
		TaskSet   sessionControlCloseTaskSet
	}{1, close.Session, close.Work, leader, manifests, taskSet})
	if err != nil {
		return nil, err
	}
	_, writeErr := s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{ClientRequestToken: token, TransactItems: items})
	if writeErr == nil {
		return &taskSet, nil
	}
	resultCtx, cancel := s.sessionResultContext(ctx)
	defer cancel()
	existing, classifyErr := s.getCloseTaskSet(resultCtx, close.EventID)
	if classifyErr == nil {
		if !sessionControlCloseTaskSetMatchesClose(*existing, close, sourceCount, ownerCount, manifests) {
			return nil, errSessionControlMaterializationCorrupt
		}
		return existing, nil
	}
	if !errors.Is(classifyErr, errSessionControlSessionNotFound) {
		return nil, classifyErr
	}
	var canceled *types.TransactionCanceledException
	if errors.As(writeErr, &canceled) {
		return nil, errSessionControlMaterializationConflict
	}
	return nil, fmt.Errorf("commit session-control close taskset: %w", writeErr)
}

// MaterializeNormalExactClose converts a frozen exact-close source inventory
// into immutable creation manifests and a single TASKSET commit marker. A task
// row is not actionable until that TASKSET exists. Exact TASKSET replay is the
// operation result and intentionally does not inspect later mutable task state.
func (s *dynamoSessionControlStore) MaterializeNormalExactClose(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string) (*sessionControlCloseTaskSet, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlSessionCandidate(candidate) || eventID != sessionControlExactCloseEventID(candidate) {
		return nil, errors.New("invalid session-control exact close materialization identity")
	}
	materializeCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	if existing, err := s.getCloseTaskSet(materializeCtx, eventID); err == nil {
		if !sessionControlCloseTaskSetMatchesCandidate(*existing, candidate, eventID,
			sessionControlCloseWorkModeNormal) {
			return nil, errSessionControlMaterializationCorrupt
		}
		return existing, nil
	} else if !errors.Is(err, errSessionControlSessionNotFound) {
		return nil, err
	}

	stable, err := s.readStableExactCloseState(materializeCtx, candidate, eventID)
	if err != nil {
		return nil, err
	}
	close, err := classifySessionControlExactClose(candidate, eventID, stable)
	if err != nil {
		return nil, err
	}
	if close.Overflow {
		return nil, errSessionControlMaterializationCapacity
	}
	if close.Work.Mode != sessionControlCloseWorkModeNormal || close.Fence == nil {
		return nil, errSessionControlMaterializationCorrupt
	}
	intents, err := s.listStableCloseSourceIntents(materializeCtx, close)
	if err != nil {
		return nil, err
	}
	groups, err := sessionControlCloseSourceGroups(intents)
	if err != nil {
		return nil, err
	}
	if uint64(len(intents)) != close.Work.ExpectedTargetCount || uint64(len(groups)) > sessionControlSessionMaxTargets {
		return nil, errSessionControlMaterializationCorrupt
	}
	manifestCount := (len(groups) + sessionControlCloseManifestOwnerLimit - 1) / sessionControlCloseManifestOwnerLimit
	if manifestCount > sessionControlCloseManifestLimit {
		return nil, errSessionControlMaterializationCapacity
	}
	manifests := make([]sessionControlCloseManifest, 0, manifestCount)
	for index := 0; index < manifestCount; index++ {
		first := index * sessionControlCloseManifestOwnerLimit
		last := min(first+sessionControlCloseManifestOwnerLimit, len(groups))
		manifest, materializeErr := s.materializeCloseManifest(materializeCtx, close, uint64(index), groups[first:last], nil)
		if materializeErr != nil {
			return nil, materializeErr
		}
		manifests = append(manifests, manifest)
	}
	return s.commitCloseTaskSet(materializeCtx, close, uint64(len(intents)), uint64(len(groups)), manifests, nil)
}

// MaterializeSelectedOverflowExactClose materializes only the one exact
// overflow event selected by the durable CONTROL directory. The directory is
// conditioned in every manifest/task write and in TASKSET commit, so a later
// leader or any concurrent directory mutation cannot inherit partially
// materialized authority. Overflow uses the owner's reserved 1025th physical
// slot; normal materialization remains capped at 1024.
func (s *dynamoSessionControlStore) MaterializeSelectedOverflowExactClose(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string) (*sessionControlCloseTaskSet, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlSessionCandidate(candidate) || eventID != sessionControlExactCloseEventID(candidate) {
		return nil, errors.New("invalid selected overflow exact close materialization identity")
	}
	materializeCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	stable, err := s.readStableExactCloseState(materializeCtx, candidate, eventID)
	if err != nil {
		return nil, err
	}
	close, err := classifySessionControlExactClose(candidate, eventID, stable)
	if err != nil {
		return nil, err
	}
	if !sessionControlOverflowLeaderMatchesClose(stable.Directory, close) ||
		close.Work.State != sessionControlCloseWorkStatePending {
		return nil, errSessionControlMaterializationConflict
	}
	if existing, readErr := s.getCloseTaskSet(materializeCtx, eventID); readErr == nil {
		if !sessionControlCloseTaskSetMatchesPreparation(*existing, close) {
			return nil, errSessionControlMaterializationCorrupt
		}
		after, directoryErr := s.getFenceDirectory(materializeCtx, candidate.CellID)
		if directoryErr != nil {
			return nil, directoryErr
		}
		if *after != stable.Directory || !sessionControlOverflowLeaderMatchesClose(*after, close) {
			return nil, errSessionControlMaterializationConflict
		}
		return existing, nil
	} else if !errors.Is(readErr, errSessionControlSessionNotFound) {
		return nil, readErr
	}
	intents, err := s.listStableCloseSourceIntents(materializeCtx, close)
	if err != nil {
		return nil, err
	}
	groups, err := sessionControlCloseSourceGroups(intents)
	if err != nil {
		return nil, err
	}
	if uint64(len(intents)) != close.Work.ExpectedTargetCount ||
		uint64(len(groups)) > sessionControlSessionMaxTargets {
		return nil, errSessionControlMaterializationCorrupt
	}
	ownerLimit := sessionControlOverflowManifestOwnerLimit
	manifestCount := (len(groups) + ownerLimit - 1) / ownerLimit
	if manifestCount > sessionControlCloseManifestLimit {
		return nil, errSessionControlMaterializationCapacity
	}
	leader := stable.Directory
	manifests := make([]sessionControlCloseManifest, 0, manifestCount)
	for index := 0; index < manifestCount; index++ {
		first := index * ownerLimit
		last := min(first+ownerLimit, len(groups))
		manifest, materializeErr := s.materializeCloseManifest(materializeCtx, close, uint64(index),
			groups[first:last], &leader)
		if materializeErr != nil {
			return nil, materializeErr
		}
		manifests = append(manifests, manifest)
	}
	return s.commitCloseTaskSet(materializeCtx, close, uint64(len(intents)), uint64(len(groups)),
		manifests, &leader)
}
