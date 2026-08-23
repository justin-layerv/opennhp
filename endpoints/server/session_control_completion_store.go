package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/OpenNHP/opennhp/nhp/common"
)

const (
	sessionControlCloseAckChunkKind       = "close_ack_chunk"
	sessionControlCloseAckChunkSchema     = uint64(1)
	sessionControlCloseAckChunkSKPrefix   = "ACKCHUNK#"
	sessionControlCloseCompleteKind       = "close_complete"
	sessionControlCloseCompleteSchema     = uint64(1)
	sessionControlCloseCompleteSK         = "COMPLETE"
	sessionControlCloseCompletionAttempts = 4
)

var (
	errSessionControlCompletionNotFound = errors.New("session-control close completion authority not found")
	errSessionControlCompletionConflict = errors.New("session-control close completion changed concurrently")
	errSessionControlCompletionCorrupt  = errors.New("session-control close completion authority is malformed")
)

// sessionControlCloseAckRef is the compact immutable ACK audit copied from one
// terminal TASK. The manifest retains creation identity while this row retains
// the authenticated result, so completion never depends on mutable owner state.
type sessionControlCloseAckRef struct {
	OwnerPK                   string `dynamodbav:"owner_pk" json:"owner_pk"`
	CreationDigest            string `dynamodbav:"creation_digest" json:"creation_digest"`
	SourceDigest              string `dynamodbav:"source_digest" json:"source_digest"`
	SourceCount               uint64 `dynamodbav:"source_count" json:"source_count"`
	TaskVersion               uint64 `dynamodbav:"task_version" json:"task_version"`
	AckAuthenticatedPublicKey string `dynamodbav:"ack_authenticated_public_key" json:"ack_authenticated_public_key"`
	AckSelectorDigest         string `dynamodbav:"ack_selector_digest" json:"ack_selector_digest"`
	AckBootID                 string `dynamodbav:"ack_boot_id" json:"ack_boot_id"`
	AckFlushGeneration        uint64 `dynamodbav:"ack_flush_generation" json:"ack_flush_generation"`
	AckClosed                 uint64 `dynamodbav:"ack_closed" json:"ack_closed"`
	AckLeaseID                string `dynamodbav:"ack_lease_id" json:"ack_lease_id"`
	AckLeaseOwner             string `dynamodbav:"ack_lease_owner" json:"ack_lease_owner"`
	AckedAtMillis             int64  `dynamodbav:"acked_at_ms" json:"acked_at_ms"`
	AckOperationID            string `dynamodbav:"ack_operation_id" json:"ack_operation_id"`
	AckOperationInputDigest   string `dynamodbav:"ack_operation_input_digest" json:"ack_operation_input_digest"`
}

type sessionControlCloseAckChunk struct {
	CellID                   string
	EventID                  string
	SelectorDigest           string
	SessionVersion           uint64
	ExpectedTargetCount      uint64
	PreparedDirectoryVersion uint64
	WorkMode                 string
	TaskSetDigest            string
	ManifestIndex            uint64
	ManifestDigest           string
	SourceCount              uint64
	OwnerCount               uint64
	AckClosedTotal           uint64
	Refs                     []sessionControlCloseAckRef
	ChunkDigest              string
	CreatedAtMillis          int64
}

type sessionControlCloseAckChunkRow struct {
	PK                       string                      `dynamodbav:"pk"`
	SK                       string                      `dynamodbav:"sk"`
	Kind                     string                      `dynamodbav:"kind"`
	SchemaVersion            uint64                      `dynamodbav:"schema_version"`
	CellID                   string                      `dynamodbav:"cell_id"`
	EventID                  string                      `dynamodbav:"event_id"`
	SelectorDigest           string                      `dynamodbav:"selector_digest"`
	SessionVersion           uint64                      `dynamodbav:"session_version"`
	ExpectedTargetCount      uint64                      `dynamodbav:"expected_target_count"`
	PreparedDirectoryVersion uint64                      `dynamodbav:"prepared_directory_version"`
	WorkMode                 string                      `dynamodbav:"work_mode"`
	TaskSetDigest            string                      `dynamodbav:"taskset_digest"`
	ManifestIndex            uint64                      `dynamodbav:"manifest_index"`
	ManifestDigest           string                      `dynamodbav:"manifest_digest"`
	SourceCount              uint64                      `dynamodbav:"source_count"`
	OwnerCount               uint64                      `dynamodbav:"owner_count"`
	AckClosedTotal           uint64                      `dynamodbav:"ack_closed_total"`
	Refs                     []sessionControlCloseAckRef `dynamodbav:"ack_refs"`
	ChunkDigest              string                      `dynamodbav:"chunk_digest"`
	CreatedAtMillis          int64                       `dynamodbav:"created_at_ms"`
}

type sessionControlCloseComplete struct {
	CellID                     string
	EventID                    string
	SelectorDigest             string
	AgentPublicKey             string
	SessionID                  uint64
	SessionIssuedMillis        int64
	SessionVersion             uint64
	ExpectedTargetCount        uint64
	PreparedDirectoryVersion   uint64
	WorkMode                   string
	TaskSetDigest              string
	SourceCount                uint64
	OwnerCount                 uint64
	AckClosedTotal             uint64
	ManifestDigests            []string
	ChunkDigests               []string
	ChunkSourceCounts          []uint64
	ChunkOwnerCounts           []uint64
	FenceVersion               uint64
	CompletedDirectoryVersion  uint64
	FenceReplayNotBeforeMillis int64
	CompletedAtMillis          int64
	RetainUntilMillis          int64
	CompleteDigest             string
}

type sessionControlCloseCompleteRow struct {
	PK                         string   `dynamodbav:"pk"`
	SK                         string   `dynamodbav:"sk"`
	Kind                       string   `dynamodbav:"kind"`
	SchemaVersion              uint64   `dynamodbav:"schema_version"`
	CellID                     string   `dynamodbav:"cell_id"`
	EventID                    string   `dynamodbav:"event_id"`
	SelectorDigest             string   `dynamodbav:"selector_digest"`
	AgentPublicKey             string   `dynamodbav:"agent_public_key"`
	SessionID                  uint64   `dynamodbav:"session_id"`
	SessionIssuedMillis        int64    `dynamodbav:"session_issued_ms"`
	SessionVersion             uint64   `dynamodbav:"session_version"`
	ExpectedTargetCount        uint64   `dynamodbav:"expected_target_count"`
	PreparedDirectoryVersion   uint64   `dynamodbav:"prepared_directory_version"`
	WorkMode                   string   `dynamodbav:"work_mode"`
	TaskSetDigest              string   `dynamodbav:"taskset_digest"`
	SourceCount                uint64   `dynamodbav:"source_count"`
	OwnerCount                 uint64   `dynamodbav:"owner_count"`
	AckClosedTotal             uint64   `dynamodbav:"ack_closed_total"`
	ManifestDigests            []string `dynamodbav:"manifest_digests"`
	ChunkDigests               []string `dynamodbav:"chunk_digests"`
	ChunkSourceCounts          []uint64 `dynamodbav:"chunk_source_counts"`
	ChunkOwnerCounts           []uint64 `dynamodbav:"chunk_owner_counts"`
	FenceVersion               uint64   `dynamodbav:"fence_version"`
	CompletedDirectoryVersion  uint64   `dynamodbav:"completed_directory_version"`
	FenceReplayNotBeforeMillis int64    `dynamodbav:"fence_replay_not_before_ms"`
	CompletedAtMillis          int64    `dynamodbav:"completed_at_ms"`
	RetainUntilMillis          int64    `dynamodbav:"retain_until_ms"`
	CompleteDigest             string   `dynamodbav:"complete_digest"`
}

func sessionControlCloseAckChunkSK(index uint64) string {
	return fmt.Sprintf("%s%020d", sessionControlCloseAckChunkSKPrefix, index)
}

func sessionControlCloseAckChunkKey(eventID string, index uint64) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlFenceMetaPK(eventID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlCloseAckChunkSK(index)},
	}
}

func sessionControlCloseCompleteKey(eventID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlFenceMetaPK(eventID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlCloseCompleteSK},
	}
}

func sessionControlCloseAckRefFromTask(task sessionControlCloseTask) sessionControlCloseAckRef {
	return sessionControlCloseAckRef{
		OwnerPK: task.OwnerPK, CreationDigest: task.CreationDigest, SourceDigest: task.SourceDigest,
		SourceCount: task.SourceCount, TaskVersion: task.TaskVersion,
		AckAuthenticatedPublicKey: task.AckAuthenticatedPublicKey, AckSelectorDigest: task.AckSelectorDigest,
		AckBootID: task.AckBootID, AckFlushGeneration: task.AckFlushGeneration, AckClosed: task.AckClosed,
		AckLeaseID: task.AckLeaseID, AckLeaseOwner: task.AckLeaseOwner, AckedAtMillis: task.AckedAtMillis,
		AckOperationID: task.LastOperationID, AckOperationInputDigest: task.LastOperationInputDigest,
	}
}

func sessionControlCloseAckChunkDigest(chunk sessionControlCloseAckChunk) (string, error) {
	chunk.ChunkDigest = ""
	return sessionControlMaterializationDigest(struct {
		Version uint64
		Chunk   sessionControlCloseAckChunk
	}{1, chunk})
}

func validateSessionControlCloseAckChunk(chunk sessionControlCloseAckChunk) error {
	if !validSessionControlCellID(chunk.CellID) || !validSessionControlFenceEventID(chunk.EventID) ||
		!validSessionControlTaskInputDigest(chunk.SelectorDigest) ||
		!validSessionControlMaterializationWorkTuple(chunk.SessionVersion, chunk.ExpectedTargetCount,
			chunk.PreparedDirectoryVersion) || !validSessionControlExactCloseWorkMode(chunk.WorkMode) ||
		!validSessionControlTaskInputDigest(chunk.TaskSetDigest) ||
		chunk.ManifestIndex >= sessionControlCloseManifestLimit || !validSessionControlTaskInputDigest(chunk.ManifestDigest) ||
		chunk.OwnerCount == 0 || chunk.OwnerCount > uint64(sessionControlCloseOwnerLimitForMode(chunk.WorkMode)) ||
		uint64(len(chunk.Refs)) != chunk.OwnerCount || chunk.SourceCount < chunk.OwnerCount ||
		chunk.SourceCount > chunk.ExpectedTargetCount || chunk.CreatedAtMillis <= 0 {
		return errSessionControlCompletionCorrupt
	}
	var sourceTotal, closedTotal uint64
	for index, ref := range chunk.Refs {
		if !validSessionControlOwnerPK(ref.OwnerPK) || !validSessionControlTaskInputDigest(ref.CreationDigest) ||
			!validSessionControlTaskInputDigest(ref.SourceDigest) || ref.SourceCount == 0 ||
			ref.TaskVersion <= 1 || ref.TaskVersion >= math.MaxUint64-1 ||
			ref.AckSelectorDigest != chunk.SelectorDigest ||
			!validSessionControlTaskInputDigest(ref.AckSelectorDigest) ||
			!commonValidCloseAckPublicKey(ref.AckAuthenticatedPublicKey) ||
			!common.ValidNHPACBootID(ref.AckBootID) ||
			!validSessionControlTaskOperationID(ref.AckOperationID) ||
			!validSessionControlTaskInputDigest(ref.AckOperationInputDigest) ||
			!validSessionControlTaskLeaseID(ref.AckLeaseID) || !validSessionControlTaskLeaseOwner(ref.AckLeaseOwner) ||
			ref.AckFlushGeneration == 0 || ref.AckedAtMillis <= 0 ||
			(index > 0 && chunk.Refs[index-1].OwnerPK >= ref.OwnerPK) ||
			ref.SourceCount > chunk.ExpectedTargetCount-sourceTotal || ref.AckClosed > math.MaxUint64-closedTotal {
			return errSessionControlCompletionCorrupt
		}
		sourceTotal += ref.SourceCount
		closedTotal += ref.AckClosed
		if ref.AckedAtMillis > chunk.CreatedAtMillis {
			return errSessionControlCompletionCorrupt
		}
	}
	if sourceTotal != chunk.SourceCount || closedTotal != chunk.AckClosedTotal {
		return errSessionControlCompletionCorrupt
	}
	digest, err := sessionControlCloseAckChunkDigest(chunk)
	if err != nil || digest != chunk.ChunkDigest {
		return errSessionControlCompletionCorrupt
	}
	return nil
}

func commonValidCloseAckPublicKey(value string) bool {
	// Task validation already uses the canonical NHP public-key validator; this
	// wrapper keeps completion validation independent of an API request shape.
	return common.ValidNHPAgentPublicKey(value)
}

func sessionControlCloseAckChunkToRow(chunk sessionControlCloseAckChunk) (sessionControlCloseAckChunkRow, error) {
	if err := validateSessionControlCloseAckChunk(chunk); err != nil {
		return sessionControlCloseAckChunkRow{}, err
	}
	return sessionControlCloseAckChunkRow{
		PK: sessionControlFenceMetaPK(chunk.EventID), SK: sessionControlCloseAckChunkSK(chunk.ManifestIndex),
		Kind: sessionControlCloseAckChunkKind, SchemaVersion: sessionControlCloseAckChunkSchema,
		CellID: chunk.CellID, EventID: chunk.EventID, SelectorDigest: chunk.SelectorDigest,
		SessionVersion: chunk.SessionVersion, ExpectedTargetCount: chunk.ExpectedTargetCount,
		PreparedDirectoryVersion: chunk.PreparedDirectoryVersion, WorkMode: chunk.WorkMode,
		TaskSetDigest: chunk.TaskSetDigest, ManifestIndex: chunk.ManifestIndex, ManifestDigest: chunk.ManifestDigest,
		SourceCount: chunk.SourceCount, OwnerCount: chunk.OwnerCount, AckClosedTotal: chunk.AckClosedTotal,
		Refs: chunk.Refs, ChunkDigest: chunk.ChunkDigest, CreatedAtMillis: chunk.CreatedAtMillis,
	}, nil
}

func sessionControlCloseAckChunkFromItem(item map[string]types.AttributeValue, eventID string,
	index uint64) (sessionControlCloseAckChunk, error) {
	if len(item) == 0 {
		return sessionControlCloseAckChunk{}, errSessionControlCompletionNotFound
	}
	for _, name := range []string{"manifest_index", "source_count", "owner_count", "ack_closed_total", "created_at_ms"} {
		if _, ok := item[name].(*types.AttributeValueMemberN); !ok {
			return sessionControlCloseAckChunk{}, errSessionControlCompletionCorrupt
		}
	}
	if _, hasTTL := item["ttl"]; hasTTL {
		return sessionControlCloseAckChunk{}, errSessionControlCompletionCorrupt
	}
	refs, refsOK := item["ack_refs"].(*types.AttributeValueMemberL)
	if !refsOK || len(refs.Value) == 0 {
		return sessionControlCloseAckChunk{}, errSessionControlCompletionCorrupt
	}
	for _, entry := range refs.Value {
		member, ok := entry.(*types.AttributeValueMemberM)
		if !ok {
			return sessionControlCloseAckChunk{}, errSessionControlCompletionCorrupt
		}
		for _, name := range []string{"owner_pk", "creation_digest", "source_digest", "ack_authenticated_public_key",
			"ack_selector_digest", "ack_boot_id", "ack_lease_id", "ack_lease_owner", "ack_operation_id",
			"ack_operation_input_digest"} {
			if _, ok := member.Value[name].(*types.AttributeValueMemberS); !ok {
				return sessionControlCloseAckChunk{}, errSessionControlCompletionCorrupt
			}
		}
		for _, name := range []string{"source_count", "task_version", "ack_flush_generation", "ack_closed", "acked_at_ms"} {
			if _, ok := member.Value[name].(*types.AttributeValueMemberN); !ok {
				return sessionControlCloseAckChunk{}, errSessionControlCompletionCorrupt
			}
		}
	}
	var row sessionControlCloseAckChunkRow
	if err := attributevalue.UnmarshalMap(item, &row); err != nil {
		return sessionControlCloseAckChunk{}, fmt.Errorf("%w: decode ACK chunk", errSessionControlCompletionCorrupt)
	}
	chunk := sessionControlCloseAckChunk{
		CellID: row.CellID, EventID: row.EventID, SelectorDigest: row.SelectorDigest,
		SessionVersion: row.SessionVersion, ExpectedTargetCount: row.ExpectedTargetCount,
		PreparedDirectoryVersion: row.PreparedDirectoryVersion, WorkMode: row.WorkMode,
		TaskSetDigest: row.TaskSetDigest, ManifestIndex: row.ManifestIndex, ManifestDigest: row.ManifestDigest,
		SourceCount: row.SourceCount, OwnerCount: row.OwnerCount, AckClosedTotal: row.AckClosedTotal,
		Refs: row.Refs, ChunkDigest: row.ChunkDigest, CreatedAtMillis: row.CreatedAtMillis,
	}
	if row.PK != sessionControlFenceMetaPK(eventID) || row.SK != sessionControlCloseAckChunkSK(index) ||
		row.Kind != sessionControlCloseAckChunkKind || row.SchemaVersion != sessionControlCloseAckChunkSchema ||
		row.EventID != eventID || row.ManifestIndex != index || validateSessionControlCloseAckChunk(chunk) != nil {
		return sessionControlCloseAckChunk{}, errSessionControlCompletionCorrupt
	}
	return chunk, nil
}

func (s *dynamoSessionControlStore) getCloseAckChunk(ctx context.Context, eventID string,
	index uint64) (*sessionControlCloseAckChunk, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.tableName),
		ConsistentRead: aws.Bool(true), Key: sessionControlCloseAckChunkKey(eventID, index)})
	if err != nil {
		return nil, fmt.Errorf("session-control close ACK chunk strong read: %w", err)
	}
	chunk, err := sessionControlCloseAckChunkFromItem(result.Item, eventID, index)
	if err != nil {
		return nil, err
	}
	return &chunk, nil
}

func sessionControlCloseCompleteDigest(complete sessionControlCloseComplete) (string, error) {
	complete.CompleteDigest = ""
	return sessionControlMaterializationDigest(struct {
		Version  uint64
		Complete sessionControlCloseComplete
	}{1, complete})
}

func validateSessionControlCloseComplete(complete sessionControlCloseComplete) error {
	if !validSessionControlCellID(complete.CellID) || !validSessionControlFenceEventID(complete.EventID) ||
		!validSessionControlTaskInputDigest(complete.SelectorDigest) ||
		!commonValidCloseAckPublicKey(complete.AgentPublicKey) || complete.SessionID == 0 ||
		complete.SessionIssuedMillis <= 0 ||
		!validSessionControlMaterializationWorkTuple(complete.SessionVersion, complete.ExpectedTargetCount,
			complete.PreparedDirectoryVersion) || !validSessionControlExactCloseWorkMode(complete.WorkMode) ||
		!validSessionControlTaskInputDigest(complete.TaskSetDigest) || complete.SourceCount != complete.ExpectedTargetCount ||
		complete.OwnerCount > complete.SourceCount || complete.OwnerCount > sessionControlSessionMaxTargets ||
		complete.ManifestDigests == nil || complete.ChunkDigests == nil ||
		complete.ChunkSourceCounts == nil || complete.ChunkOwnerCounts == nil ||
		len(complete.ManifestDigests) != len(complete.ChunkDigests) ||
		len(complete.ManifestDigests) != len(complete.ChunkSourceCounts) ||
		len(complete.ManifestDigests) != len(complete.ChunkOwnerCounts) ||
		len(complete.ManifestDigests) > sessionControlCloseManifestLimit ||
		(complete.OwnerCount == 0) != (len(complete.ManifestDigests) == 0) || complete.FenceVersion < 2 ||
		complete.CompletedDirectoryVersion <= complete.PreparedDirectoryVersion || complete.FenceReplayNotBeforeMillis <= 0 ||
		complete.CompletedAtMillis <= 0 || complete.RetainUntilMillis < complete.CompletedAtMillis ||
		complete.RetainUntilMillis < complete.FenceReplayNotBeforeMillis {
		return errSessionControlCompletionCorrupt
	}
	selector := sessionControlFenceSelector{Scope: sessionControlFenceSelectorExact,
		AgentPublicKey: complete.AgentPublicKey, SessionID: complete.SessionID,
		SessionIssuedMillis: complete.SessionIssuedMillis}
	selectorDigest, selectorErr := sessionControlFenceSelectorDigest(selector)
	if selectorErr != nil || selectorDigest != complete.SelectorDigest {
		return errSessionControlCompletionCorrupt
	}
	if complete.CompletedAtMillis > math.MaxInt64-sessionControlFenceReplayHorizon.Milliseconds() ||
		complete.RetainUntilMillis < complete.CompletedAtMillis+sessionControlFenceReplayHorizon.Milliseconds() {
		return errSessionControlCompletionCorrupt
	}
	var sourceTotal, ownerTotal uint64
	for index := range complete.ManifestDigests {
		if !validSessionControlTaskInputDigest(complete.ManifestDigests[index]) ||
			!validSessionControlTaskInputDigest(complete.ChunkDigests[index]) ||
			complete.ChunkOwnerCounts[index] == 0 ||
			complete.ChunkOwnerCounts[index] > uint64(sessionControlCloseOwnerLimitForMode(complete.WorkMode)) ||
			complete.ChunkSourceCounts[index] < complete.ChunkOwnerCounts[index] ||
			complete.ChunkSourceCounts[index] > complete.SourceCount-sourceTotal ||
			complete.ChunkOwnerCounts[index] > complete.OwnerCount-ownerTotal {
			return errSessionControlCompletionCorrupt
		}
		sourceTotal += complete.ChunkSourceCounts[index]
		ownerTotal += complete.ChunkOwnerCounts[index]
	}
	if sourceTotal != complete.SourceCount || ownerTotal != complete.OwnerCount {
		return errSessionControlCompletionCorrupt
	}
	digest, err := sessionControlCloseCompleteDigest(complete)
	if err != nil || digest != complete.CompleteDigest {
		return errSessionControlCompletionCorrupt
	}
	return nil
}

func sessionControlCloseCompleteToRow(complete sessionControlCloseComplete) (sessionControlCloseCompleteRow, error) {
	if err := validateSessionControlCloseComplete(complete); err != nil {
		return sessionControlCloseCompleteRow{}, err
	}
	return sessionControlCloseCompleteRow{
		PK: sessionControlFenceMetaPK(complete.EventID), SK: sessionControlCloseCompleteSK,
		Kind: sessionControlCloseCompleteKind, SchemaVersion: sessionControlCloseCompleteSchema,
		CellID: complete.CellID, EventID: complete.EventID, SelectorDigest: complete.SelectorDigest,
		AgentPublicKey: complete.AgentPublicKey, SessionID: complete.SessionID,
		SessionIssuedMillis: complete.SessionIssuedMillis, SessionVersion: complete.SessionVersion,
		ExpectedTargetCount: complete.ExpectedTargetCount, PreparedDirectoryVersion: complete.PreparedDirectoryVersion,
		WorkMode: complete.WorkMode, TaskSetDigest: complete.TaskSetDigest, SourceCount: complete.SourceCount,
		OwnerCount: complete.OwnerCount, AckClosedTotal: complete.AckClosedTotal,
		ManifestDigests: complete.ManifestDigests, ChunkDigests: complete.ChunkDigests,
		ChunkSourceCounts: complete.ChunkSourceCounts, ChunkOwnerCounts: complete.ChunkOwnerCounts,
		FenceVersion: complete.FenceVersion, CompletedDirectoryVersion: complete.CompletedDirectoryVersion,
		FenceReplayNotBeforeMillis: complete.FenceReplayNotBeforeMillis,
		CompletedAtMillis:          complete.CompletedAtMillis, RetainUntilMillis: complete.RetainUntilMillis,
		CompleteDigest: complete.CompleteDigest,
	}, nil
}

func sessionControlCloseCompleteFromItem(item map[string]types.AttributeValue,
	eventID string) (sessionControlCloseComplete, error) {
	if len(item) == 0 {
		return sessionControlCloseComplete{}, errSessionControlCompletionNotFound
	}
	for _, name := range []string{"session_id", "session_issued_ms", "session_version", "expected_target_count",
		"prepared_directory_version", "source_count", "owner_count", "ack_closed_total", "fence_version",
		"completed_directory_version", "fence_replay_not_before_ms", "completed_at_ms", "retain_until_ms"} {
		if _, ok := item[name].(*types.AttributeValueMemberN); !ok {
			return sessionControlCloseComplete{}, errSessionControlCompletionCorrupt
		}
	}
	if _, hasTTL := item["ttl"]; hasTTL {
		return sessionControlCloseComplete{}, errSessionControlCompletionCorrupt
	}
	for _, name := range []string{"manifest_digests", "chunk_digests", "chunk_source_counts", "chunk_owner_counts"} {
		if _, ok := item[name].(*types.AttributeValueMemberL); !ok {
			return sessionControlCloseComplete{}, errSessionControlCompletionCorrupt
		}
	}
	var row sessionControlCloseCompleteRow
	if err := attributevalue.UnmarshalMap(item, &row); err != nil {
		return sessionControlCloseComplete{}, fmt.Errorf("%w: decode COMPLETE", errSessionControlCompletionCorrupt)
	}
	complete := sessionControlCloseComplete{
		CellID: row.CellID, EventID: row.EventID, SelectorDigest: row.SelectorDigest,
		AgentPublicKey: row.AgentPublicKey, SessionID: row.SessionID, SessionIssuedMillis: row.SessionIssuedMillis,
		SessionVersion: row.SessionVersion, ExpectedTargetCount: row.ExpectedTargetCount,
		PreparedDirectoryVersion: row.PreparedDirectoryVersion, WorkMode: row.WorkMode,
		TaskSetDigest: row.TaskSetDigest, SourceCount: row.SourceCount, OwnerCount: row.OwnerCount,
		AckClosedTotal: row.AckClosedTotal, ManifestDigests: row.ManifestDigests, ChunkDigests: row.ChunkDigests,
		ChunkSourceCounts: row.ChunkSourceCounts, ChunkOwnerCounts: row.ChunkOwnerCounts,
		FenceVersion: row.FenceVersion, CompletedDirectoryVersion: row.CompletedDirectoryVersion,
		FenceReplayNotBeforeMillis: row.FenceReplayNotBeforeMillis,
		CompletedAtMillis:          row.CompletedAtMillis, RetainUntilMillis: row.RetainUntilMillis,
		CompleteDigest: row.CompleteDigest,
	}
	if row.PK != sessionControlFenceMetaPK(eventID) || row.SK != sessionControlCloseCompleteSK ||
		row.Kind != sessionControlCloseCompleteKind || row.SchemaVersion != sessionControlCloseCompleteSchema ||
		row.EventID != eventID || validateSessionControlCloseComplete(complete) != nil {
		return sessionControlCloseComplete{}, errSessionControlCompletionCorrupt
	}
	return complete, nil
}

func (s *dynamoSessionControlStore) getCloseComplete(ctx context.Context,
	eventID string) (*sessionControlCloseComplete, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.tableName),
		ConsistentRead: aws.Bool(true), Key: sessionControlCloseCompleteKey(eventID)})
	if err != nil {
		return nil, fmt.Errorf("session-control close COMPLETE strong read: %w", err)
	}
	complete, err := sessionControlCloseCompleteFromItem(result.Item, eventID)
	if err != nil {
		return nil, err
	}
	return &complete, nil
}

func sessionControlCloseAckChunkMatchesCandidate(chunk sessionControlCloseAckChunk,
	candidate sessionControlSessionCandidate, eventID string, index uint64) bool {
	selector := sessionControlExactCloseSelector(candidate)
	digest, err := sessionControlFenceSelectorDigest(selector)
	return err == nil && chunk.CellID == candidate.CellID && chunk.EventID == eventID &&
		chunk.SelectorDigest == digest && chunk.ManifestIndex == index
}

func sessionControlCloseCompleteMatchesCandidate(complete sessionControlCloseComplete,
	candidate sessionControlSessionCandidate, eventID string) bool {
	selector := sessionControlExactCloseSelector(candidate)
	digest, err := sessionControlFenceSelectorDigest(selector)
	return err == nil && complete.CellID == candidate.CellID && complete.EventID == eventID &&
		complete.SelectorDigest == digest && complete.AgentPublicKey == candidate.AgentPublicKey &&
		complete.SessionID == candidate.SessionID && complete.SessionIssuedMillis == candidate.IssuedAtMillis
}

func sessionControlCloseAckChunkPut(tableName string, chunk sessionControlCloseAckChunk) (types.TransactWriteItem, error) {
	row, err := sessionControlCloseAckChunkToRow(chunk)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	return types.TransactWriteItem{Put: &types.Put{TableName: aws.String(tableName), Item: item,
		ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}}, nil
}

func sessionControlCloseAckChunkCondition(tableName string,
	chunk sessionControlCloseAckChunk) (types.TransactWriteItem, error) {
	row, err := sessionControlCloseAckChunkToRow(chunk)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	condition, names, values := sessionControlExactItemCondition(item)
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{TableName: aws.String(tableName),
		Key:                 sessionControlCloseAckChunkKey(chunk.EventID, chunk.ManifestIndex),
		ConditionExpression: aws.String(condition), ExpressionAttributeNames: names,
		ExpressionAttributeValues: values}}, nil
}

func sessionControlCloseTaskAckCondition(tableName string, task sessionControlCloseTask) (types.TransactWriteItem, error) {
	row, err := sessionControlCloseTaskToRow(task)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	condition, names, values := sessionControlExactItemCondition(item, "due_at_ms", "due_shard", "due_sort",
		"lease_id", "lease_owner", "lease_expires_at_ms")
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{TableName: aws.String(tableName),
		Key: sessionControlCloseTaskKey(task.OwnerPK, task.EventID), ConditionExpression: aws.String(condition),
		ExpressionAttributeNames: names, ExpressionAttributeValues: values}}, nil
}

func sessionControlCloseExactCondition(tableName string, key map[string]types.AttributeValue,
	row any, absent ...string) (types.TransactWriteItem, error) {
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	condition, names, values := sessionControlExactItemCondition(item, absent...)
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{TableName: aws.String(tableName), Key: key,
		ConditionExpression: aws.String(condition), ExpressionAttributeNames: names,
		ExpressionAttributeValues: values}}, nil
}

func sessionControlCloseAckChunkToken(tableName string, session sessionControlSessionAuthority,
	work sessionControlCloseWork, taskSet sessionControlCloseTaskSet, manifest sessionControlCloseManifest,
	tasks []sessionControlCloseTask, directory *sessionControlFenceDirectory,
	chunk sessionControlCloseAckChunk) (*string, error) {
	digest, err := sessionControlMaterializationDigest(struct {
		Version   uint64
		Table     string
		Session   sessionControlSessionAuthority
		Work      sessionControlCloseWork
		TaskSet   sessionControlCloseTaskSet
		Manifest  sessionControlCloseManifest
		Tasks     []sessionControlCloseTask
		Directory *sessionControlFenceDirectory
		Chunk     sessionControlCloseAckChunk
	}{1, tableName, session, work, taskSet, manifest, tasks, directory, chunk})
	if err != nil {
		return nil, err
	}
	return aws.String("sc-ac-" + digest[:24]), nil
}

func sessionControlCloseAckChunkMatchesAuthority(chunk sessionControlCloseAckChunk,
	session sessionControlSessionAuthority, work sessionControlCloseWork, taskSet sessionControlCloseTaskSet,
	manifest sessionControlCloseManifest) bool {
	return session.State == sessionControlSessionStateClosing && session.CloseEventID == chunk.EventID &&
		chunk.CellID == session.Candidate.CellID && chunk.SelectorDigest == work.SelectorDigest &&
		chunk.SessionVersion == session.Version && chunk.ExpectedTargetCount == session.TargetCount &&
		chunk.PreparedDirectoryVersion == session.ClosePreparedDirectory && chunk.WorkMode == work.Mode &&
		chunk.TaskSetDigest == taskSet.TaskSetDigest && chunk.ManifestIndex == manifest.ManifestIndex &&
		chunk.ManifestDigest == manifest.ManifestDigest
}

// PrepareExactCloseAckChunk snapshots one fully ACKed manifest into one
// immutable recovery row. All reads and the write share one aggregate budget;
// only an ambiguous transport result gets one fresh bounded result read.
func (s *dynamoSessionControlStore) PrepareExactCloseAckChunk(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string, manifestIndex uint64) (*sessionControlCloseAckChunk, error) {
	return s.prepareExactCloseAckChunk(ctx, candidate, eventID, manifestIndex, "")
}

func (s *dynamoSessionControlStore) prepareExactCloseAckChunk(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string, manifestIndex uint64,
	expectedMode string) (*sessionControlCloseAckChunk, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlSessionCandidate(candidate) || !validSessionControlFenceEventID(eventID) ||
		eventID != sessionControlExactCloseEventID(candidate) ||
		manifestIndex >= sessionControlCloseManifestLimit {
		return nil, errors.New("invalid session-control close ACK chunk request")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	if existing, err := s.getCloseAckChunk(opCtx, eventID, manifestIndex); err == nil {
		if !sessionControlCloseAckChunkMatchesCandidate(*existing, candidate, eventID, manifestIndex) ||
			(expectedMode != "" && existing.WorkMode != expectedMode) {
			return nil, errSessionControlCompletionConflict
		}
		return existing, nil
	} else if !errors.Is(err, errSessionControlCompletionNotFound) {
		return nil, err
	}
	session, err := s.classifyReservation(opCtx, candidate)
	if err != nil {
		return nil, err
	}
	if session.State != sessionControlSessionStateClosing || session.CloseEventID != eventID {
		return nil, errSessionControlCompletionConflict
	}
	taskSet, err := s.getCloseTaskSet(opCtx, eventID)
	if err != nil {
		return nil, err
	}
	if !validSessionControlExactCloseWorkMode(taskSet.WorkMode) ||
		(expectedMode != "" && taskSet.WorkMode != expectedMode) {
		return nil, errSessionControlCompletionConflict
	}
	overflow := taskSet.WorkMode == sessionControlCloseWorkModeOverflow
	work, err := s.getCloseWork(opCtx, candidate.CellID, eventID, overflow)
	if err != nil {
		return nil, err
	}
	var directory *sessionControlFenceDirectory
	if overflow {
		directory, err = s.getFenceDirectory(opCtx, candidate.CellID)
		if err != nil {
			return nil, err
		}
		if !sessionControlOverflowLeaderMatchesWork(*directory, *work) {
			return nil, errSessionControlCompletionConflict
		}
	}
	if manifestIndex >= uint64(len(taskSet.ManifestDigests)) {
		return nil, errSessionControlCompletionConflict
	}
	manifest, err := s.getCloseManifest(opCtx, eventID, manifestIndex)
	if err != nil {
		return nil, err
	}
	base := sessionControlCloseAckChunk{CellID: candidate.CellID, EventID: eventID,
		SelectorDigest: work.SelectorDigest, SessionVersion: session.Version,
		ExpectedTargetCount: session.TargetCount, PreparedDirectoryVersion: session.ClosePreparedDirectory,
		WorkMode: work.Mode, TaskSetDigest: taskSet.TaskSetDigest, ManifestIndex: manifestIndex,
		ManifestDigest: manifest.ManifestDigest}
	if work.State != sessionControlCloseWorkStatePending || work.Mode != taskSet.WorkMode ||
		manifest.WorkMode != taskSet.WorkMode ||
		!sessionControlCloseAckChunkMatchesAuthority(base, *session, *work, *taskSet, *manifest) ||
		taskSet.ManifestDigests[manifestIndex] != manifest.ManifestDigest ||
		uint64(len(manifest.Refs)) != taskSet.ManifestOwnerCounts[manifestIndex] {
		return nil, errSessionControlCompletionCorrupt
	}
	tasks := make([]sessionControlCloseTask, 0, len(manifest.Refs))
	refs := make([]sessionControlCloseAckRef, 0, len(manifest.Refs))
	var sourceTotal, closedTotal uint64
	createdAt := int64(0)
	for _, manifestRef := range manifest.Refs {
		task, taskErr := s.getCloseTask(opCtx, manifestRef.OwnerPK, eventID)
		if taskErr != nil {
			return nil, taskErr
		}
		if task.State != sessionControlCloseTaskStateAcked || task.ManifestIndex != manifestIndex ||
			task.CreationDigest != manifestRef.CreationDigest || task.SourceDigest != manifestRef.SourceDigest ||
			task.SourceCount != manifestRef.SourceCount || task.WorkMode != taskSet.WorkMode ||
			task.SelectorDigest != work.SelectorDigest || sessionControlCloseTaskHasAckAudit(*task) == false ||
			task.SourceCount > taskSet.SourceCount-sourceTotal || task.AckClosed > math.MaxUint64-closedTotal {
			return nil, errSessionControlCompletionConflict
		}
		sourceTotal += task.SourceCount
		closedTotal += task.AckClosed
		if task.AckedAtMillis > createdAt {
			createdAt = task.AckedAtMillis
		}
		tasks = append(tasks, *task)
		refs = append(refs, sessionControlCloseAckRefFromTask(*task))
	}
	if sourceTotal != taskSet.ManifestSourceCounts[manifestIndex] {
		return nil, errSessionControlCompletionCorrupt
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	if now.UnixMilli() > createdAt {
		createdAt = now.UnixMilli()
	}
	chunk := base
	chunk.SourceCount, chunk.OwnerCount, chunk.AckClosedTotal = sourceTotal, uint64(len(refs)), closedTotal
	chunk.Refs, chunk.CreatedAtMillis = refs, createdAt
	chunk.ChunkDigest, err = sessionControlCloseAckChunkDigest(chunk)
	if err != nil || validateSessionControlCloseAckChunk(chunk) != nil {
		return nil, errSessionControlCompletionCorrupt
	}
	sessionCheck, err := sessionControlCloseSessionCondition(s.tableName, *session)
	if err != nil {
		return nil, err
	}
	workCheck, err := sessionControlCloseWorkCondition(s.tableName, *work)
	if err != nil {
		return nil, err
	}
	taskSetCheck, err := sessionControlCloseTaskSetCondition(s.tableName, *taskSet)
	if err != nil {
		return nil, err
	}
	manifestCheck, err := sessionControlCloseManifestCondition(s.tableName, *manifest)
	if err != nil {
		return nil, err
	}
	transaction := []types.TransactWriteItem{sessionCheck, workCheck, taskSetCheck, manifestCheck}
	if directory != nil {
		directoryCheck := sessionControlDirectoryCondition(sessionControlCloseDirectorySnapshot(*directory))
		directoryCheck.ConditionCheck.TableName = aws.String(s.tableName)
		transaction = append(transaction, directoryCheck)
	}
	for _, task := range tasks {
		check, checkErr := sessionControlCloseTaskAckCondition(s.tableName, task)
		if checkErr != nil {
			return nil, checkErr
		}
		transaction = append(transaction, check)
	}
	put, err := sessionControlCloseAckChunkPut(s.tableName, chunk)
	if err != nil {
		return nil, err
	}
	transaction = append(transaction, put)
	token, err := sessionControlCloseAckChunkToken(s.tableName, *session, *work, *taskSet, *manifest, tasks,
		directory, chunk)
	if err != nil {
		return nil, err
	}
	_, writeErr := s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: token, TransactItems: transaction})
	if writeErr == nil {
		return &chunk, nil
	}
	classify := func(classifyCtx context.Context) (*sessionControlCloseAckChunk, error) {
		current, classifyErr := s.getCloseAckChunk(classifyCtx, eventID, manifestIndex)
		if classifyErr == nil && reflect.DeepEqual(*current, chunk) {
			return current, nil
		}
		return nil, errSessionControlCompletionConflict
	}
	var canceled *types.TransactionCanceledException
	if errors.As(writeErr, &canceled) {
		if current, classifyErr := classify(opCtx); classifyErr == nil {
			return current, nil
		}
		return nil, errSessionControlCompletionConflict
	}
	resultCtx, resultCancel := s.sessionResultContext(ctx)
	defer resultCancel()
	if current, classifyErr := classify(resultCtx); classifyErr == nil {
		return current, nil
	}
	return nil, fmt.Errorf("prepare session-control close ACK chunk: %w", writeErr)
}

func (s *dynamoSessionControlStore) PrepareNormalExactCloseAckChunk(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string,
	manifestIndex uint64) (*sessionControlCloseAckChunk, error) {
	return s.prepareExactCloseAckChunk(ctx, candidate, eventID, manifestIndex,
		sessionControlCloseWorkModeNormal)
}

func sessionControlCloseCompletePut(tableName string, complete sessionControlCloseComplete,
	current *sessionControlCloseComplete) (types.TransactWriteItem, error) {
	row, err := sessionControlCloseCompleteToRow(complete)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	put := &types.Put{TableName: aws.String(tableName), Item: item}
	if current == nil {
		put.ConditionExpression = aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")
	} else {
		currentRow, rowErr := sessionControlCloseCompleteToRow(*current)
		if rowErr != nil {
			return types.TransactWriteItem{}, rowErr
		}
		currentItem, marshalErr := attributevalue.MarshalMap(currentRow)
		if marshalErr != nil {
			return types.TransactWriteItem{}, marshalErr
		}
		condition, names, values := sessionControlExactItemCondition(currentItem)
		put.ConditionExpression, put.ExpressionAttributeNames, put.ExpressionAttributeValues = aws.String(condition), names, values
	}
	return types.TransactWriteItem{Put: put}, nil
}

func sessionControlCloseWorkReplace(tableName string, current,
	next sessionControlCloseWork) (types.TransactWriteItem, error) {
	currentRow, err := sessionControlCloseWorkToRow(current)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	nextRow, err := sessionControlCloseWorkToRow(next)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	currentItem, err := attributevalue.MarshalMap(currentRow)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	nextItem, err := attributevalue.MarshalMap(nextRow)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	condition, names, values := sessionControlExactItemCondition(currentItem, "completed_at_ms")
	return types.TransactWriteItem{Put: &types.Put{TableName: aws.String(tableName), Item: nextItem,
		ConditionExpression: aws.String(condition), ExpressionAttributeNames: names,
		ExpressionAttributeValues: values}}, nil
}

func sessionControlCloseCompletionToken(tableName, action string, values ...any) (*string, error) {
	digest, err := sessionControlMaterializationDigest(struct {
		Version uint64
		Table   string
		Action  string
		Values  []any
	}{1, tableName, action, values})
	if err != nil {
		return nil, err
	}
	return aws.String("sc-co-" + digest[:24]), nil
}

func sessionControlCloseCompleteRetention(completeAt, sessionRetain, fenceReplay, minimum int64) (int64, error) {
	if completeAt <= 0 || completeAt > math.MaxInt64-sessionControlFenceReplayHorizon.Milliseconds() || minimum < 0 {
		return 0, errSessionControlCompletionCorrupt
	}
	retain := completeAt + sessionControlFenceReplayHorizon.Milliseconds()
	for _, candidate := range []int64{sessionRetain, fenceReplay, minimum} {
		if candidate > retain {
			retain = candidate
		}
	}
	return retain, nil
}

func sessionControlCloseCompleteMatchesAuthority(complete sessionControlCloseComplete,
	session sessionControlSessionAuthority, work sessionControlCloseWork, taskSet sessionControlCloseTaskSet) bool {
	return complete.CellID == session.Candidate.CellID && complete.EventID == session.CloseEventID &&
		complete.AgentPublicKey == session.Candidate.AgentPublicKey && complete.SessionID == session.Candidate.SessionID &&
		complete.SessionIssuedMillis == session.Candidate.IssuedAtMillis && complete.SessionVersion == session.Version &&
		complete.ExpectedTargetCount == session.TargetCount &&
		complete.PreparedDirectoryVersion == session.ClosePreparedDirectory && complete.SelectorDigest == work.SelectorDigest &&
		complete.WorkMode == work.Mode && complete.TaskSetDigest == taskSet.TaskSetDigest &&
		complete.SourceCount == taskSet.SourceCount && complete.OwnerCount == taskSet.OwnerCount
}

func (s *dynamoSessionControlStore) classifyCloseComplete(ctx context.Context, eventID string,
	desired sessionControlCloseComplete) (*sessionControlCloseComplete, error) {
	current, err := s.getCloseComplete(ctx, eventID)
	if err != nil {
		return nil, err
	}
	// Completion timestamps can differ when two initial completers clamp against
	// different local clocks, and retention can only grow afterward. Every
	// authority field remains exact; a compatible winner is sufficient only
	// when it retained the result for at least as long as this caller requires.
	normalized := *current
	normalized.CompletedAtMillis = desired.CompletedAtMillis
	normalized.RetainUntilMillis = desired.RetainUntilMillis
	normalized.CompleteDigest = desired.CompleteDigest
	if current.RetainUntilMillis < desired.RetainUntilMillis || !reflect.DeepEqual(normalized, desired) {
		return nil, errSessionControlCompletionConflict
	}
	return current, nil
}

func (s *dynamoSessionControlStore) extendCloseCompleteRetention(ctx context.Context,
	candidate sessionControlSessionCandidate, current sessionControlCloseComplete,
	minimumRetainUntilMillis int64) (*sessionControlCloseComplete, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	session, err := s.classifyReservation(opCtx, candidate)
	if err != nil {
		return nil, err
	}
	if session.State != sessionControlSessionStateClosing || session.CloseEventID != current.EventID ||
		session.Version != current.SessionVersion || session.TargetCount != current.ExpectedTargetCount ||
		session.ClosePreparedDirectory != current.PreparedDirectoryVersion {
		return nil, errSessionControlCompletionConflict
	}
	desiredRetain := current.RetainUntilMillis
	if session.RetainUntilMillis > desiredRetain {
		desiredRetain = session.RetainUntilMillis
	}
	if minimumRetainUntilMillis > desiredRetain {
		desiredRetain = minimumRetainUntilMillis
	}
	if desiredRetain <= current.RetainUntilMillis {
		return &current, nil
	}
	next := current
	next.RetainUntilMillis = desiredRetain
	next.CompleteDigest, err = sessionControlCloseCompleteDigest(next)
	if err != nil || validateSessionControlCloseComplete(next) != nil {
		return nil, errSessionControlCompletionCorrupt
	}
	completePut, err := sessionControlCloseCompletePut(s.tableName, next, &current)
	if err != nil {
		return nil, err
	}
	sessionWrite := sessionControlSessionCloseRetentionUpdate(*session, desiredRetain)
	sessionWrite.Update.TableName = aws.String(s.tableName)
	token, err := sessionControlCloseCompletionToken(s.tableName, "retain", current, next, *session)
	if err != nil {
		return nil, err
	}
	_, writeErr := s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{ClientRequestToken: token,
		TransactItems: []types.TransactWriteItem{completePut, sessionWrite}})
	if writeErr == nil {
		return &next, nil
	}
	var canceled *types.TransactionCanceledException
	if errors.As(writeErr, &canceled) {
		if classified, classifyErr := s.classifyCloseComplete(opCtx, current.EventID, next); classifyErr == nil {
			return classified, nil
		}
		return nil, errSessionControlCompletionConflict
	}
	resultCtx, resultCancel := s.sessionResultContext(ctx)
	defer resultCancel()
	if classified, classifyErr := s.classifyCloseComplete(resultCtx, current.EventID, next); classifyErr == nil {
		return classified, nil
	}
	return nil, fmt.Errorf("extend session-control close COMPLETE retention: %w", writeErr)
}

// CompleteNormalExactClose commits normal close completion only after every
// immutable ACK chunk exists and the exact active fence is converged. An exact
// historical COMPLETE is returned before consulting mutable directory/fence
// state; a stronger explicit retention request uses a two-item monotonic CAS.
func (s *dynamoSessionControlStore) CompleteNormalExactClose(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string,
	minimumRetainUntilMillis int64) (*sessionControlCloseComplete, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlSessionCandidate(candidate) || !validSessionControlFenceEventID(eventID) ||
		eventID != sessionControlExactCloseEventID(candidate) ||
		minimumRetainUntilMillis < 0 {
		return nil, errors.New("invalid session-control close COMPLETE request")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	if existing, err := s.getCloseComplete(opCtx, eventID); err == nil {
		if existing.WorkMode != sessionControlCloseWorkModeNormal ||
			!sessionControlCloseCompleteMatchesCandidate(*existing, candidate, eventID) {
			return nil, errSessionControlCompletionConflict
		}
		if minimumRetainUntilMillis <= existing.RetainUntilMillis {
			return existing, nil
		}
		cancel()
		return s.extendCloseCompleteRetention(ctx, candidate, *existing, minimumRetainUntilMillis)
	} else if !errors.Is(err, errSessionControlCompletionNotFound) {
		return nil, err
	}
	stable, err := s.readStableExactCloseState(opCtx, candidate, eventID)
	if err != nil {
		return nil, err
	}
	classified, err := classifySessionControlExactClose(candidate, eventID, stable)
	if err != nil {
		return nil, err
	}
	if classified.Overflow || classified.Fence == nil || classified.Fence.State != sessionControlFenceConverged ||
		stable.Meta == nil || stable.Active == nil || *stable.Meta != *stable.Active ||
		classified.Work.State != sessionControlCloseWorkStatePending ||
		classified.Work.Mode != sessionControlCloseWorkModeNormal {
		return nil, errSessionControlCompletionConflict
	}
	taskSet, err := s.getCloseTaskSet(opCtx, eventID)
	if err != nil {
		return nil, err
	}
	if taskSet.CellID != candidate.CellID || taskSet.SelectorDigest != classified.Work.SelectorDigest ||
		taskSet.SessionVersion != classified.Session.Version ||
		taskSet.ExpectedTargetCount != classified.Session.TargetCount ||
		taskSet.PreparedDirectoryVersion != classified.Session.ClosePreparedDirectory ||
		taskSet.WorkMode != sessionControlCloseWorkModeNormal {
		return nil, errSessionControlCompletionCorrupt
	}
	chunks := make([]sessionControlCloseAckChunk, 0, len(taskSet.ManifestDigests))
	var sourceTotal, ownerTotal, closedTotal uint64
	for index := range taskSet.ManifestDigests {
		chunk, chunkErr := s.getCloseAckChunk(opCtx, eventID, uint64(index))
		if chunkErr != nil {
			return nil, chunkErr
		}
		if chunk.CellID != classified.Session.Candidate.CellID || chunk.EventID != eventID ||
			chunk.SelectorDigest != classified.Work.SelectorDigest ||
			chunk.SessionVersion != classified.Session.Version ||
			chunk.ExpectedTargetCount != classified.Session.TargetCount ||
			chunk.PreparedDirectoryVersion != classified.Session.ClosePreparedDirectory ||
			chunk.WorkMode != classified.Work.Mode || chunk.TaskSetDigest != taskSet.TaskSetDigest ||
			chunk.ManifestIndex != uint64(index) ||
			chunk.ManifestDigest != taskSet.ManifestDigests[index] ||
			chunk.SourceCount != taskSet.ManifestSourceCounts[index] ||
			chunk.OwnerCount != taskSet.ManifestOwnerCounts[index] ||
			chunk.SourceCount > taskSet.SourceCount-sourceTotal || chunk.OwnerCount > taskSet.OwnerCount-ownerTotal ||
			chunk.AckClosedTotal > math.MaxUint64-closedTotal {
			return nil, errSessionControlCompletionCorrupt
		}
		sourceTotal += chunk.SourceCount
		ownerTotal += chunk.OwnerCount
		closedTotal += chunk.AckClosedTotal
		chunks = append(chunks, *chunk)
	}
	if sourceTotal != taskSet.SourceCount || ownerTotal != taskSet.OwnerCount ||
		(taskSet.OwnerCount == 0 && len(chunks) != 0) {
		return nil, errSessionControlCompletionCorrupt
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	completedAt := now.UnixMilli()
	for _, candidateMillis := range []int64{classified.Work.UpdatedAtMillis, classified.Fence.UpdatedAtMillis,
		classified.Session.ClosePreparedAtMillis} {
		if candidateMillis > completedAt {
			completedAt = candidateMillis
		}
	}
	for _, chunk := range chunks {
		if chunk.CreatedAtMillis > completedAt {
			completedAt = chunk.CreatedAtMillis
		}
	}
	retain, err := sessionControlCloseCompleteRetention(completedAt, classified.Session.RetainUntilMillis,
		classified.Fence.ReplayNotBeforeMillis, minimumRetainUntilMillis)
	if err != nil {
		return nil, err
	}
	complete := sessionControlCloseComplete{
		CellID: candidate.CellID, EventID: eventID, SelectorDigest: classified.Work.SelectorDigest,
		AgentPublicKey: candidate.AgentPublicKey, SessionID: candidate.SessionID,
		SessionIssuedMillis: candidate.IssuedAtMillis, SessionVersion: classified.Session.Version,
		ExpectedTargetCount:      classified.Session.TargetCount,
		PreparedDirectoryVersion: classified.Session.ClosePreparedDirectory,
		WorkMode:                 classified.Work.Mode, TaskSetDigest: taskSet.TaskSetDigest,
		SourceCount: taskSet.SourceCount, OwnerCount: taskSet.OwnerCount, AckClosedTotal: closedTotal,
		ManifestDigests: append(make([]string, 0, len(taskSet.ManifestDigests)), taskSet.ManifestDigests...),
		ChunkDigests:    make([]string, 0, len(chunks)), ChunkSourceCounts: make([]uint64, 0, len(chunks)),
		ChunkOwnerCounts: make([]uint64, 0, len(chunks)),
		FenceVersion:     classified.Fence.Version, CompletedDirectoryVersion: stable.Directory.Version,
		FenceReplayNotBeforeMillis: classified.Fence.ReplayNotBeforeMillis,
		CompletedAtMillis:          completedAt, RetainUntilMillis: retain,
	}
	for _, chunk := range chunks {
		complete.ChunkDigests = append(complete.ChunkDigests, chunk.ChunkDigest)
		complete.ChunkSourceCounts = append(complete.ChunkSourceCounts, chunk.SourceCount)
		complete.ChunkOwnerCounts = append(complete.ChunkOwnerCounts, chunk.OwnerCount)
	}
	complete.CompleteDigest, err = sessionControlCloseCompleteDigest(complete)
	if err != nil || validateSessionControlCloseComplete(complete) != nil ||
		!sessionControlCloseCompleteMatchesAuthority(complete, classified.Session, classified.Work, *taskSet) {
		return nil, errSessionControlCompletionCorrupt
	}
	nextWork := classified.Work
	nextWork.State = sessionControlCloseWorkStateCompleted
	nextWork.UpdatedAtMillis = completedAt
	nextWork.DueAtMillis = 0
	nextWork.CompletedAtMillis = completedAt
	directoryRow, err := sessionControlFenceDirectoryToRow(stable.Directory)
	if err != nil {
		return nil, err
	}
	directoryCheck, err := sessionControlCloseExactCondition(s.tableName,
		sessionControlFenceDirectoryKey(candidate.CellID), directoryRow)
	if err != nil {
		return nil, err
	}
	metaRow, err := sessionControlFenceToRow(*classified.Fence, false)
	if err != nil {
		return nil, err
	}
	metaCheck, err := sessionControlCloseExactCondition(s.tableName, sessionControlFenceMetaKey(eventID), metaRow,
		"retired_at_ms", "expires_at")
	if err != nil {
		return nil, err
	}
	activeRow, err := sessionControlFenceToRow(*classified.Fence, true)
	if err != nil {
		return nil, err
	}
	activeCheck, err := sessionControlCloseExactCondition(s.tableName,
		sessionControlFenceActiveKey(candidate.CellID, eventID), activeRow, "retired_at_ms", "expires_at")
	if err != nil {
		return nil, err
	}
	sessionWrite := sessionControlSessionCloseRetentionUpdate(classified.Session, retain)
	sessionWrite.Update.TableName = aws.String(s.tableName)
	workWrite, err := sessionControlCloseWorkReplace(s.tableName, classified.Work, nextWork)
	if err != nil {
		return nil, err
	}
	taskSetCheck, err := sessionControlCloseTaskSetCondition(s.tableName, *taskSet)
	if err != nil {
		return nil, err
	}
	transaction := []types.TransactWriteItem{directoryCheck, metaCheck, activeCheck, sessionWrite, workWrite, taskSetCheck}
	for _, chunk := range chunks {
		check, checkErr := sessionControlCloseAckChunkCondition(s.tableName, chunk)
		if checkErr != nil {
			return nil, checkErr
		}
		transaction = append(transaction, check)
	}
	completePut, err := sessionControlCloseCompletePut(s.tableName, complete, nil)
	if err != nil {
		return nil, err
	}
	transaction = append(transaction, completePut)
	token, err := sessionControlCloseCompletionToken(s.tableName, "complete", stable.Directory,
		classified.Session, classified.Work, nextWork, *classified.Fence, *taskSet, chunks, complete)
	if err != nil {
		return nil, err
	}
	_, writeErr := s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{ClientRequestToken: token,
		TransactItems: transaction})
	if writeErr == nil {
		return &complete, nil
	}
	var canceled *types.TransactionCanceledException
	if errors.As(writeErr, &canceled) {
		if current, classifyErr := s.classifyCloseComplete(opCtx, eventID, complete); classifyErr == nil {
			return current, nil
		}
		return nil, errSessionControlCompletionConflict
	}
	resultCtx, resultCancel := s.sessionResultContext(ctx)
	defer resultCancel()
	if current, classifyErr := s.classifyCloseComplete(resultCtx, eventID, complete); classifyErr == nil {
		return current, nil
	}
	return nil, fmt.Errorf("complete normal session-control exact close: %w", writeErr)
}
