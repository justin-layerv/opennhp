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
)

const (
	sessionControlCloseCleanChunkKind     = "close_clean_chunk"
	sessionControlCloseCleanChunkSchema   = uint64(1)
	sessionControlCloseCleanChunkSKPrefix = "CLEANCHUNK#"
	sessionControlCloseClosedKind         = "close_closed"
	sessionControlCloseClosedSchema       = uint64(2)
	sessionControlCloseClosedSK           = "CLOSED"
)

var (
	errSessionControlTerminalNotFound = errors.New("session-control terminal authority not found")
	errSessionControlTerminalConflict = errors.New("session-control terminal authority changed concurrently")
	errSessionControlTerminalCorrupt  = errors.New("session-control terminal authority is malformed")
)

type sessionControlCloseCleanRef struct {
	OwnerPK     string
	AuditDigest string
	SourceCount uint64
}

// sessionControlCloseCleanChunk is the immutable proof that every task in one
// manifest has a corresponding TASKAUDIT and that no live TASK remained at the
// transaction linearization point. Complete may be an older compatible
// retention revision; every consumer must compare it with the current COMPLETE
// using sessionControlCloseCompleteCanExtend.
type sessionControlCloseCleanChunk struct {
	CellID          string
	EventID         string
	ManifestIndex   uint64
	Complete        sessionControlCloseComplete
	TaskSet         sessionControlCloseTaskSet
	Manifest        sessionControlCloseManifest
	AckChunk        sessionControlCloseAckChunk
	Refs            []sessionControlCloseCleanRef
	SourceCount     uint64
	OwnerCount      uint64
	CreatedAtMillis int64
	ChunkDigest     string
}

type sessionControlCloseCleanRefRow struct {
	OwnerPK     string `dynamodbav:"owner_pk"`
	AuditDigest string `dynamodbav:"audit_digest"`
	SourceCount uint64 `dynamodbav:"source_count"`
}

type sessionControlCloseCleanChunkRow struct {
	PK              string                           `dynamodbav:"pk"`
	SK              string                           `dynamodbav:"sk"`
	Kind            string                           `dynamodbav:"kind"`
	SchemaVersion   uint64                           `dynamodbav:"schema_version"`
	CellID          string                           `dynamodbav:"cell_id"`
	EventID         string                           `dynamodbav:"event_id"`
	ManifestIndex   uint64                           `dynamodbav:"manifest_index"`
	Complete        sessionControlCloseCompleteRow   `dynamodbav:"complete"`
	TaskSet         sessionControlCloseTaskSetRow    `dynamodbav:"taskset"`
	Manifest        sessionControlCloseManifestRow   `dynamodbav:"manifest"`
	AckChunk        sessionControlCloseAckChunkRow   `dynamodbav:"ack_chunk"`
	Refs            []sessionControlCloseCleanRefRow `dynamodbav:"refs"`
	SourceCount     uint64                           `dynamodbav:"source_count"`
	OwnerCount      uint64                           `dynamodbav:"owner_count"`
	CreatedAtMillis int64                            `dynamodbav:"created_at_ms"`
	ChunkDigest     string                           `dynamodbav:"chunk_digest"`
}

type sessionControlCloseClosedAudit struct {
	CellID          string
	EventID         string
	DirectoryBefore sessionControlFenceDirectory
	DirectoryAfter  sessionControlFenceDirectory
	FenceBefore     sessionControlFenceAuthority
	FenceAfter      sessionControlFenceAuthority
	SessionBefore   sessionControlSessionAuthority
	SessionAfter    sessionControlSessionAuthority
	// WorkBefore is present only for normal active-fence closes. Promoted
	// overflow closes already deleted their HEADER/ORDER pair atomically and
	// use COMPLETE as the durable completion marker.
	WorkBefore                *sessionControlCloseWork
	Complete                  sessionControlCloseComplete
	TaskSet                   sessionControlCloseTaskSet
	CleanChunkDigests         []string
	CleanChunkCreatedAtMillis []int64
	ClosedAtMillis            int64
	ClosedDigest              string
}

type sessionControlCloseClosedRow struct {
	PK                        string                          `dynamodbav:"pk"`
	SK                        string                          `dynamodbav:"sk"`
	Kind                      string                          `dynamodbav:"kind"`
	SchemaVersion             uint64                          `dynamodbav:"schema_version"`
	CellID                    string                          `dynamodbav:"cell_id"`
	EventID                   string                          `dynamodbav:"event_id"`
	DirectoryBefore           sessionControlFenceDirectoryRow `dynamodbav:"directory_before"`
	DirectoryAfter            sessionControlFenceDirectoryRow `dynamodbav:"directory_after"`
	FenceBefore               sessionControlFenceRow          `dynamodbav:"fence_before"`
	FenceAfter                sessionControlFenceRow          `dynamodbav:"fence_after"`
	SessionBefore             sessionControlSessionRow        `dynamodbav:"session_before"`
	SessionAfter              sessionControlSessionRow        `dynamodbav:"session_after"`
	WorkBefore                *sessionControlCloseWorkRow     `dynamodbav:"work_before,omitempty"`
	Complete                  sessionControlCloseCompleteRow  `dynamodbav:"complete"`
	TaskSet                   sessionControlCloseTaskSetRow   `dynamodbav:"taskset"`
	CleanChunkDigests         []string                        `dynamodbav:"clean_chunk_digests"`
	CleanChunkCreatedAtMillis []int64                         `dynamodbav:"clean_chunk_created_at_ms"`
	ClosedAtMillis            int64                           `dynamodbav:"closed_at_ms"`
	ClosedDigest              string                          `dynamodbav:"closed_digest"`
}

func sessionControlCloseCleanChunkSK(index uint64) string {
	return fmt.Sprintf("%s%02d", sessionControlCloseCleanChunkSKPrefix, index)
}

func sessionControlCloseCleanChunkKey(eventID string, index uint64) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlFenceMetaPK(eventID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlCloseCleanChunkSK(index)},
	}
}

func sessionControlCloseClosedKey(eventID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlFenceMetaPK(eventID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlCloseClosedSK},
	}
}

func sessionControlCloseCleanChunkDigest(chunk sessionControlCloseCleanChunk) (string, error) {
	chunk.ChunkDigest = ""
	return sessionControlMaterializationDigest(struct {
		Version uint64
		Chunk   sessionControlCloseCleanChunk
	}{1, chunk})
}

func sessionControlCloseClosedDigest(closed sessionControlCloseClosedAudit) (string, error) {
	closed.ClosedDigest = ""
	return sessionControlMaterializationDigest(struct {
		Version uint64
		Closed  sessionControlCloseClosedAudit
	}{1, closed})
}

func sessionControlCloseManifestMatchesTaskSet(manifest sessionControlCloseManifest,
	taskSet sessionControlCloseTaskSet) bool {
	index := manifest.ManifestIndex
	if index >= uint64(len(taskSet.ManifestDigests)) {
		return false
	}
	var sourceCount uint64
	for _, ref := range manifest.Refs {
		if ref.SourceCount > math.MaxUint64-sourceCount {
			return false
		}
		sourceCount += ref.SourceCount
	}
	return manifest.CellID == taskSet.CellID && manifest.EventID == taskSet.EventID &&
		manifest.SelectorDigest == taskSet.SelectorDigest && manifest.SessionVersion == taskSet.SessionVersion &&
		manifest.ExpectedTargetCount == taskSet.ExpectedTargetCount &&
		manifest.PreparedDirectoryVersion == taskSet.PreparedDirectoryVersion && manifest.WorkMode == taskSet.WorkMode &&
		taskSet.ManifestDigests[index] == manifest.ManifestDigest &&
		taskSet.ManifestSourceCounts[index] == sourceCount &&
		taskSet.ManifestOwnerCounts[index] == uint64(len(manifest.Refs))
}

func sessionControlCloseAckChunkMatchesManifest(chunk sessionControlCloseAckChunk,
	complete sessionControlCloseComplete, taskSet sessionControlCloseTaskSet,
	manifest sessionControlCloseManifest) bool {
	index := manifest.ManifestIndex
	return index < uint64(len(complete.ChunkDigests)) &&
		chunk.CellID == complete.CellID && chunk.EventID == complete.EventID &&
		chunk.SelectorDigest == complete.SelectorDigest && chunk.SessionVersion == complete.SessionVersion &&
		chunk.ExpectedTargetCount == complete.ExpectedTargetCount &&
		chunk.PreparedDirectoryVersion == complete.PreparedDirectoryVersion && chunk.WorkMode == complete.WorkMode &&
		chunk.TaskSetDigest == taskSet.TaskSetDigest && chunk.ManifestIndex == index &&
		chunk.ManifestDigest == manifest.ManifestDigest && complete.ChunkDigests[index] == chunk.ChunkDigest &&
		complete.ChunkSourceCounts[index] == chunk.SourceCount && complete.ChunkOwnerCounts[index] == chunk.OwnerCount
}

func validateSessionControlCloseCleanChunk(chunk sessionControlCloseCleanChunk) error {
	if !validSessionControlCellID(chunk.CellID) || !validSessionControlFenceEventID(chunk.EventID) ||
		chunk.ManifestIndex >= sessionControlCloseManifestLimit || validateSessionControlCloseComplete(chunk.Complete) != nil ||
		validateSessionControlCloseTaskSet(chunk.TaskSet) != nil || validateSessionControlCloseManifest(chunk.Manifest) != nil ||
		validateSessionControlCloseAckChunk(chunk.AckChunk) != nil || !sessionControlCloseTaskSetMatchesComplete(chunk.TaskSet, chunk.Complete) ||
		!sessionControlCloseManifestMatchesTaskSet(chunk.Manifest, chunk.TaskSet) ||
		!sessionControlCloseAckChunkMatchesManifest(chunk.AckChunk, chunk.Complete, chunk.TaskSet, chunk.Manifest) ||
		chunk.CellID != chunk.Complete.CellID || chunk.EventID != chunk.Complete.EventID ||
		chunk.ManifestIndex != chunk.Manifest.ManifestIndex || chunk.OwnerCount == 0 ||
		chunk.OwnerCount != uint64(len(chunk.Refs)) || chunk.SourceCount != chunk.AckChunk.SourceCount ||
		chunk.OwnerCount != chunk.AckChunk.OwnerCount || chunk.CreatedAtMillis < chunk.Complete.CompletedAtMillis ||
		chunk.CreatedAtMillis < chunk.AckChunk.CreatedAtMillis {
		return errSessionControlTerminalCorrupt
	}
	var sourceCount uint64
	for index, ref := range chunk.Refs {
		manifestRef := chunk.Manifest.Refs[index]
		if !validSessionControlOwnerPK(ref.OwnerPK) || !validSessionControlTaskInputDigest(ref.AuditDigest) ||
			ref.OwnerPK != manifestRef.OwnerPK || ref.SourceCount != manifestRef.SourceCount || ref.SourceCount == 0 ||
			(index > 0 && chunk.Refs[index-1].OwnerPK >= ref.OwnerPK) ||
			ref.SourceCount > chunk.SourceCount-sourceCount {
			return errSessionControlTerminalCorrupt
		}
		sourceCount += ref.SourceCount
	}
	if sourceCount != chunk.SourceCount {
		return errSessionControlTerminalCorrupt
	}
	digest, err := sessionControlCloseCleanChunkDigest(chunk)
	if err != nil || digest != chunk.ChunkDigest {
		return errSessionControlTerminalCorrupt
	}
	return nil
}

func sessionControlCloseCleanChunkToRow(chunk sessionControlCloseCleanChunk) (sessionControlCloseCleanChunkRow, error) {
	if err := validateSessionControlCloseCleanChunk(chunk); err != nil {
		return sessionControlCloseCleanChunkRow{}, err
	}
	complete, err := sessionControlCloseCompleteToRow(chunk.Complete)
	if err != nil {
		return sessionControlCloseCleanChunkRow{}, err
	}
	taskSet, err := sessionControlCloseTaskSetToRow(chunk.TaskSet)
	if err != nil {
		return sessionControlCloseCleanChunkRow{}, err
	}
	manifest, err := sessionControlCloseManifestToRow(chunk.Manifest)
	if err != nil {
		return sessionControlCloseCleanChunkRow{}, err
	}
	ackChunk, err := sessionControlCloseAckChunkToRow(chunk.AckChunk)
	if err != nil {
		return sessionControlCloseCleanChunkRow{}, err
	}
	refs := make([]sessionControlCloseCleanRefRow, len(chunk.Refs))
	for index, ref := range chunk.Refs {
		refs[index] = sessionControlCloseCleanRefRow(ref)
	}
	return sessionControlCloseCleanChunkRow{
		PK: sessionControlFenceMetaPK(chunk.EventID), SK: sessionControlCloseCleanChunkSK(chunk.ManifestIndex),
		Kind: sessionControlCloseCleanChunkKind, SchemaVersion: sessionControlCloseCleanChunkSchema,
		CellID: chunk.CellID, EventID: chunk.EventID, ManifestIndex: chunk.ManifestIndex,
		Complete: complete, TaskSet: taskSet, Manifest: manifest, AckChunk: ackChunk, Refs: refs,
		SourceCount: chunk.SourceCount, OwnerCount: chunk.OwnerCount,
		CreatedAtMillis: chunk.CreatedAtMillis, ChunkDigest: chunk.ChunkDigest,
	}, nil
}

func sessionControlCloseCleanChunkFromItem(item map[string]types.AttributeValue,
	eventID string, index uint64) (sessionControlCloseCleanChunk, error) {
	for _, name := range []string{"schema_version", "manifest_index", "source_count", "owner_count", "created_at_ms"} {
		if _, ok := item[name].(*types.AttributeValueMemberN); !ok {
			return sessionControlCloseCleanChunk{}, errSessionControlTerminalCorrupt
		}
	}
	for _, name := range []string{"complete", "taskset", "manifest", "ack_chunk"} {
		if _, ok := item[name].(*types.AttributeValueMemberM); !ok {
			return sessionControlCloseCleanChunk{}, errSessionControlTerminalCorrupt
		}
	}
	if _, ok := item["refs"].(*types.AttributeValueMemberL); !ok {
		return sessionControlCloseCleanChunk{}, errSessionControlTerminalCorrupt
	}
	if _, hasTTL := item["ttl"]; hasTTL {
		return sessionControlCloseCleanChunk{}, errSessionControlTerminalCorrupt
	}
	var row sessionControlCloseCleanChunkRow
	if err := attributevalue.UnmarshalMap(item, &row); err != nil {
		return sessionControlCloseCleanChunk{}, errSessionControlTerminalCorrupt
	}
	complete, err := sessionControlCloseCompleteFromItem(item["complete"].(*types.AttributeValueMemberM).Value, eventID)
	if err != nil {
		return sessionControlCloseCleanChunk{}, errSessionControlTerminalCorrupt
	}
	taskSet, err := sessionControlCloseTaskSetFromItem(item["taskset"].(*types.AttributeValueMemberM).Value, eventID)
	if err != nil {
		return sessionControlCloseCleanChunk{}, errSessionControlTerminalCorrupt
	}
	manifest, err := sessionControlCloseManifestFromItem(item["manifest"].(*types.AttributeValueMemberM).Value, eventID, index)
	if err != nil {
		return sessionControlCloseCleanChunk{}, errSessionControlTerminalCorrupt
	}
	ackChunk, err := sessionControlCloseAckChunkFromItem(item["ack_chunk"].(*types.AttributeValueMemberM).Value, eventID, index)
	if err != nil {
		return sessionControlCloseCleanChunk{}, errSessionControlTerminalCorrupt
	}
	refs := make([]sessionControlCloseCleanRef, len(row.Refs))
	for refIndex, ref := range row.Refs {
		refs[refIndex] = sessionControlCloseCleanRef(ref)
	}
	chunk := sessionControlCloseCleanChunk{CellID: row.CellID, EventID: row.EventID, ManifestIndex: row.ManifestIndex,
		Complete: complete, TaskSet: taskSet, Manifest: manifest, AckChunk: ackChunk, Refs: refs,
		SourceCount: row.SourceCount, OwnerCount: row.OwnerCount, CreatedAtMillis: row.CreatedAtMillis,
		ChunkDigest: row.ChunkDigest}
	if row.PK != sessionControlFenceMetaPK(eventID) || row.SK != sessionControlCloseCleanChunkSK(index) ||
		row.Kind != sessionControlCloseCleanChunkKind || row.SchemaVersion != sessionControlCloseCleanChunkSchema ||
		row.EventID != eventID || row.ManifestIndex != index || validateSessionControlCloseCleanChunk(chunk) != nil {
		return sessionControlCloseCleanChunk{}, errSessionControlTerminalCorrupt
	}
	canonicalRow, err := sessionControlCloseCleanChunkToRow(chunk)
	if err != nil {
		return sessionControlCloseCleanChunk{}, errSessionControlTerminalCorrupt
	}
	canonicalItem, err := attributevalue.MarshalMap(canonicalRow)
	if err != nil || !reflect.DeepEqual(canonicalItem, item) {
		return sessionControlCloseCleanChunk{}, errSessionControlTerminalCorrupt
	}
	return chunk, nil
}

func (s *dynamoSessionControlStore) getCloseCleanChunk(ctx context.Context, eventID string,
	index uint64) (*sessionControlCloseCleanChunk, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.tableName),
		ConsistentRead: aws.Bool(true), Key: sessionControlCloseCleanChunkKey(eventID, index)})
	if err != nil {
		return nil, fmt.Errorf("session-control CLEANCHUNK strong read: %w", err)
	}
	if len(result.Item) == 0 {
		return nil, errSessionControlTerminalNotFound
	}
	chunk, err := sessionControlCloseCleanChunkFromItem(result.Item, eventID, index)
	if err != nil {
		return nil, err
	}
	return &chunk, nil
}

func sessionControlCloseCleanChunkPut(tableName string, chunk sessionControlCloseCleanChunk) (types.TransactWriteItem, error) {
	row, err := sessionControlCloseCleanChunkToRow(chunk)
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

func sessionControlCloseCleanChunkCondition(tableName string, chunk sessionControlCloseCleanChunk) (types.TransactWriteItem, error) {
	row, err := sessionControlCloseCleanChunkToRow(chunk)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	return sessionControlCloseExactCondition(tableName, sessionControlCloseCleanChunkKey(chunk.EventID, chunk.ManifestIndex), row)
}

func sessionControlCloseTaskAuditCondition(tableName string, audit sessionControlCloseTaskAudit) (types.TransactWriteItem, error) {
	row, err := sessionControlCloseTaskAuditToRow(audit)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	return sessionControlCloseExactCondition(tableName, sessionControlCloseTaskAuditKey(audit.OwnerPK, audit.EventID), row)
}

func sessionControlCloseTaskAbsentCondition(tableName, ownerPK, eventID string) types.TransactWriteItem {
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{TableName: aws.String(tableName),
		Key:                 sessionControlCloseTaskKey(ownerPK, eventID),
		ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}}
}

func sessionControlTerminalToken(tableName, action string, values ...any) (*string, error) {
	digest, err := sessionControlMaterializationDigest(struct {
		Version uint64
		Table   string
		Action  string
		Values  []any
	}{1, tableName, action, values})
	if err != nil {
		return nil, err
	}
	return aws.String("sc-te-" + digest[:24]), nil
}

func sessionControlCloseCleanChunkMatchesDesired(current, desired sessionControlCloseCleanChunk) bool {
	if !sessionControlCloseCompleteCanExtend(current.Complete, desired.Complete) &&
		!sessionControlCloseCompleteCanExtend(desired.Complete, current.Complete) {
		return false
	}
	current.Complete = desired.Complete
	current.ChunkDigest = desired.ChunkDigest
	return reflect.DeepEqual(current, desired)
}

func (s *dynamoSessionControlStore) classifyCloseCleanChunk(ctx context.Context,
	desired sessionControlCloseCleanChunk) (*sessionControlCloseCleanChunk, error) {
	current, err := s.getCloseCleanChunk(ctx, desired.EventID, desired.ManifestIndex)
	if err != nil {
		return nil, err
	}
	if !sessionControlCloseCleanChunkMatchesDesired(*current, desired) {
		return nil, errSessionControlTerminalConflict
	}
	return current, nil
}

// prepareExactCloseCleanChunk atomically proves that all TASK rows in a
// manifest are gone and that their immutable TASKAUDIT rows match the exact
// current COMPLETE/TASKSET authority. The largest transaction is 99 items.
func (s *dynamoSessionControlStore) prepareExactCloseCleanChunk(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string, manifestIndex uint64,
	expectedMode string) (*sessionControlCloseCleanChunk, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlSessionCandidate(candidate) || !validSessionControlFenceEventID(eventID) ||
		eventID != sessionControlExactCloseEventID(candidate) || manifestIndex >= sessionControlCloseManifestLimit {
		return nil, errors.New("invalid session-control CLEANCHUNK request")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	complete, err := s.getCloseComplete(opCtx, eventID)
	if err != nil {
		return nil, err
	}
	if !sessionControlCloseCompleteMatchesCandidate(*complete, candidate, eventID) ||
		!validSessionControlExactCloseWorkMode(complete.WorkMode) ||
		(expectedMode != "" && complete.WorkMode != expectedMode) ||
		manifestIndex >= uint64(len(complete.ManifestDigests)) {
		return nil, errSessionControlTerminalCorrupt
	}
	taskSet, err := s.getCloseTaskSet(opCtx, eventID)
	if err != nil {
		return nil, err
	}
	manifest, err := s.getCloseManifest(opCtx, eventID, manifestIndex)
	if err != nil {
		return nil, err
	}
	ackChunk, err := s.getCloseAckChunk(opCtx, eventID, manifestIndex)
	if err != nil {
		return nil, err
	}
	if !sessionControlCloseTaskSetMatchesComplete(*taskSet, *complete) ||
		!sessionControlCloseManifestMatchesTaskSet(*manifest, *taskSet) ||
		!sessionControlCloseAckChunkMatchesManifest(*ackChunk, *complete, *taskSet, *manifest) {
		return nil, errSessionControlTerminalCorrupt
	}
	refs := make([]sessionControlCloseCleanRef, 0, len(manifest.Refs))
	audits := make([]sessionControlCloseTaskAudit, 0, len(manifest.Refs))
	createdAt := complete.CompletedAtMillis
	var sourceCount uint64
	for _, ref := range manifest.Refs {
		completed, readErr := s.readCompletedCloseTaskRef(opCtx, *complete, *taskSet, *manifest, *ackChunk, ref)
		if readErr != nil {
			return nil, readErr
		}
		if completed.Task != nil || completed.Audit == nil ||
			!sessionControlCloseCompleteCanExtend(*complete, completed.Audit.Complete) ||
			!sessionControlCloseTaskMatchesCompletedRef(completed.Audit.AckedTask, completed.Audit.Complete,
				*taskSet, *manifest, *ackChunk, ref) {
			return nil, errSessionControlTerminalCorrupt
		}
		if ref.SourceCount > math.MaxUint64-sourceCount {
			return nil, errSessionControlTerminalCorrupt
		}
		sourceCount += ref.SourceCount
		if completed.Audit.CleanedAtMillis > createdAt {
			createdAt = completed.Audit.CleanedAtMillis
		}
		refs = append(refs, sessionControlCloseCleanRef{OwnerPK: ref.OwnerPK,
			AuditDigest: completed.Audit.AuditDigest, SourceCount: ref.SourceCount})
		audits = append(audits, *completed.Audit)
	}
	desired := sessionControlCloseCleanChunk{CellID: candidate.CellID, EventID: eventID,
		ManifestIndex: manifestIndex, Complete: *complete, TaskSet: *taskSet, Manifest: *manifest,
		AckChunk: *ackChunk, Refs: refs, SourceCount: sourceCount,
		OwnerCount: uint64(len(refs)), CreatedAtMillis: createdAt}
	desired.ChunkDigest, err = sessionControlCloseCleanChunkDigest(desired)
	if err != nil || validateSessionControlCloseCleanChunk(desired) != nil {
		return nil, errSessionControlTerminalCorrupt
	}
	completeCondition, err := sessionControlCloseCompleteCondition(s.tableName, *complete)
	if err != nil {
		return nil, err
	}
	taskSetCondition, err := sessionControlCloseTaskSetCondition(s.tableName, *taskSet)
	if err != nil {
		return nil, err
	}
	transaction := make([]types.TransactWriteItem, 0, 3+2*len(audits))
	transaction = append(transaction, completeCondition, taskSetCondition)
	for _, audit := range audits {
		auditCondition, conditionErr := sessionControlCloseTaskAuditCondition(s.tableName, audit)
		if conditionErr != nil {
			return nil, conditionErr
		}
		transaction = append(transaction, auditCondition,
			sessionControlCloseTaskAbsentCondition(s.tableName, audit.OwnerPK, eventID))
	}
	chunkPut, err := sessionControlCloseCleanChunkPut(s.tableName, desired)
	if err != nil {
		return nil, err
	}
	transaction = append(transaction, chunkPut)
	if len(transaction) > 99 {
		return nil, errSessionControlTerminalCorrupt
	}
	token, err := sessionControlTerminalToken(s.tableName, "clean", desired)
	if err != nil {
		return nil, err
	}
	_, writeErr := s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: token, TransactItems: transaction})
	if writeErr == nil {
		return &desired, nil
	}
	var canceled *types.TransactionCanceledException
	if errors.As(writeErr, &canceled) {
		classified, classifyErr := s.classifyCloseCleanChunk(opCtx, desired)
		if classifyErr == nil {
			return classified, nil
		}
		return nil, errSessionControlTerminalConflict
	}
	resultCtx, resultCancel := s.sessionResultContext(ctx)
	defer resultCancel()
	classified, classifyErr := s.classifyCloseCleanChunk(resultCtx, desired)
	if classifyErr == nil {
		return classified, nil
	}
	return nil, fmt.Errorf("prepare session-control CLEANCHUNK: %w", writeErr)
}

func (s *dynamoSessionControlStore) PrepareExactCloseCleanChunk(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string,
	manifestIndex uint64) (*sessionControlCloseCleanChunk, error) {
	return s.prepareExactCloseCleanChunk(ctx, candidate, eventID, manifestIndex, "")
}

// GetExactCloseCleanChunk strongly reads the immutable cleanup progress marker
// for one manifest. Recovery uses this marker as its durable cursor: a restart
// skips manifests whose complete TASKAUDIT set has already been proven instead
// of replaying every earlier task/audit pair under one bounded worker context.
func (s *dynamoSessionControlStore) GetExactCloseCleanChunk(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string,
	manifestIndex uint64) (*sessionControlCloseCleanChunk, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlSessionCandidate(candidate) || !validSessionControlFenceEventID(eventID) ||
		eventID != sessionControlExactCloseEventID(candidate) || manifestIndex >= sessionControlCloseManifestLimit {
		return nil, errors.New("invalid session-control CLEANCHUNK read request")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	chunk, err := s.getCloseCleanChunk(opCtx, eventID, manifestIndex)
	if err != nil {
		return nil, err
	}
	if chunk.ManifestIndex != manifestIndex || chunk.CellID != candidate.CellID ||
		!sessionControlCloseCompleteMatchesCandidate(chunk.Complete, candidate, eventID) {
		return nil, errSessionControlTerminalCorrupt
	}
	return chunk, nil
}

func (s *dynamoSessionControlStore) PrepareNormalExactCloseCleanChunk(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string,
	manifestIndex uint64) (*sessionControlCloseCleanChunk, error) {
	return s.prepareExactCloseCleanChunk(ctx, candidate, eventID, manifestIndex,
		sessionControlCloseWorkModeNormal)
}

func sessionControlDirectoryTerminalTransition(before, after sessionControlFenceDirectory,
	closedAtMillis int64) bool {
	if before.ActiveFenceCount == 0 || before.Version >= math.MaxUint64-1 ||
		after.Version != before.Version+1 || after.ActiveFenceCount+1 != before.ActiveFenceCount ||
		after.CellID != before.CellID || after.AdmissionBlocked != before.AdmissionBlocked ||
		after.OverflowCloseCount != before.OverflowCloseCount ||
		after.OverflowLeaderEventID != before.OverflowLeaderEventID ||
		after.OverflowLeaderPreparedDirectoryVersion != before.OverflowLeaderPreparedDirectoryVersion ||
		after.OverflowLeaderSelectedDirectoryVersion != before.OverflowLeaderSelectedDirectoryVersion ||
		after.CreatedAtMillis != before.CreatedAtMillis || after.UpdatedAtMillis != closedAtMillis {
		return false
	}
	return validateSessionControlFenceDirectory(before) == nil && validateSessionControlFenceDirectory(after) == nil
}

func sessionControlFenceTerminalTransition(before, after sessionControlFenceAuthority,
	closedAtMillis int64) bool {
	if before.State != sessionControlFenceConverged || before.Version >= math.MaxUint64-1 ||
		after.State != sessionControlFenceRetired || after.Version != before.Version+1 ||
		!sessionControlFenceSameIdentity(before, after) ||
		after.ConvergedAtMillis != before.ConvergedAtMillis ||
		after.ReplayNotBeforeMillis != before.ReplayNotBeforeMillis ||
		after.UpdatedAtMillis != closedAtMillis || after.RetiredAtMillis != closedAtMillis ||
		after.ExpiresAt != closedAtMillis/1_000+int64(sessionControlFenceIdempotencyTTL.Seconds()) {
		return false
	}
	return validateSessionControlFenceAuthority(before) == nil && validateSessionControlFenceAuthority(after) == nil
}

func sessionControlSessionTerminalTransition(before, after sessionControlSessionAuthority) bool {
	if before.State != sessionControlSessionStateClosing || after.State != sessionControlSessionStateClosed {
		return false
	}
	after.State = sessionControlSessionStateClosing
	return before == after && validateSessionControlSessionAuthority(before) == nil
}

func sessionControlCloseWorkMatchesComplete(work sessionControlCloseWork,
	complete sessionControlCloseComplete) bool {
	return work.Mode == sessionControlCloseWorkModeNormal && work.State == sessionControlCloseWorkStateCompleted &&
		work.CellID == complete.CellID && work.EventID == complete.EventID &&
		work.SelectorDigest == complete.SelectorDigest && work.SessionVersion == complete.SessionVersion &&
		work.ExpectedTargetCount == complete.ExpectedTargetCount &&
		work.PreparedDirectoryVersion == complete.PreparedDirectoryVersion &&
		work.CompletedAtMillis == complete.CompletedAtMillis
}

func sessionControlCloseCompleteMatchesSessionTaskSet(complete sessionControlCloseComplete,
	session sessionControlSessionAuthority, taskSet sessionControlCloseTaskSet) bool {
	return complete.CellID == session.Candidate.CellID && complete.EventID == session.CloseEventID &&
		complete.AgentPublicKey == session.Candidate.AgentPublicKey && complete.SessionID == session.Candidate.SessionID &&
		complete.SessionIssuedMillis == session.Candidate.IssuedAtMillis && complete.SessionVersion == session.Version &&
		complete.ExpectedTargetCount == session.TargetCount &&
		complete.PreparedDirectoryVersion == session.ClosePreparedDirectory &&
		complete.TaskSetDigest == taskSet.TaskSetDigest && complete.SourceCount == taskSet.SourceCount &&
		complete.OwnerCount == taskSet.OwnerCount && complete.WorkMode == taskSet.WorkMode
}

func validateSessionControlCloseClosedAudit(closed sessionControlCloseClosedAudit) error {
	if !validSessionControlCellID(closed.CellID) || !validSessionControlFenceEventID(closed.EventID) ||
		closed.ClosedAtMillis <= 0 || validateSessionControlCloseComplete(closed.Complete) != nil ||
		validateSessionControlCloseTaskSet(closed.TaskSet) != nil ||
		!sessionControlCloseTaskSetMatchesComplete(closed.TaskSet, closed.Complete) ||
		closed.CellID != closed.Complete.CellID || closed.EventID != closed.Complete.EventID ||
		closed.CleanChunkDigests == nil || closed.CleanChunkCreatedAtMillis == nil ||
		len(closed.CleanChunkDigests) != len(closed.Complete.ManifestDigests) ||
		len(closed.CleanChunkCreatedAtMillis) != len(closed.CleanChunkDigests) ||
		!sessionControlDirectoryTerminalTransition(closed.DirectoryBefore, closed.DirectoryAfter, closed.ClosedAtMillis) ||
		!sessionControlFenceTerminalTransition(closed.FenceBefore, closed.FenceAfter, closed.ClosedAtMillis) ||
		!sessionControlSessionTerminalTransition(closed.SessionBefore, closed.SessionAfter) ||
		closed.FenceBefore.CellID != closed.CellID || closed.FenceBefore.EventID != closed.EventID ||
		closed.FenceBefore.SelectorDigest != closed.Complete.SelectorDigest ||
		closed.FenceBefore.Version != closed.Complete.FenceVersion ||
		closed.DirectoryBefore.CellID != closed.CellID ||
		closed.DirectoryBefore.Version < closed.Complete.CompletedDirectoryVersion ||
		closed.SessionBefore.Candidate.CellID != closed.CellID ||
		closed.SessionBefore.CloseEventID != closed.EventID ||
		closed.SessionBefore.RetainUntilMillis != closed.Complete.RetainUntilMillis ||
		!sessionControlCloseCompleteMatchesSessionTaskSet(closed.Complete, closed.SessionBefore, closed.TaskSet) ||
		closed.ClosedAtMillis < closed.Complete.CompletedAtMillis ||
		closed.ClosedAtMillis < closed.Complete.FenceReplayNotBeforeMillis ||
		closed.FenceBefore.ReplayNotBeforeMillis != closed.Complete.FenceReplayNotBeforeMillis {
		return errSessionControlTerminalCorrupt
	}
	switch closed.Complete.WorkMode {
	case sessionControlCloseWorkModeNormal:
		if closed.WorkBefore == nil || validateSessionControlCloseWork(*closed.WorkBefore) != nil ||
			!sessionControlCloseWorkMatchesComplete(*closed.WorkBefore, closed.Complete) ||
			!sessionControlCloseCompleteMatchesAuthority(closed.Complete, closed.SessionBefore,
				*closed.WorkBefore, closed.TaskSet) {
			return errSessionControlTerminalCorrupt
		}
	case sessionControlCloseWorkModeOverflow:
		if closed.WorkBefore != nil {
			return errSessionControlTerminalCorrupt
		}
	default:
		return errSessionControlTerminalCorrupt
	}
	for index, digest := range closed.CleanChunkDigests {
		if !validSessionControlTaskInputDigest(digest) ||
			closed.CleanChunkCreatedAtMillis[index] <= 0 ||
			closed.CleanChunkCreatedAtMillis[index] > closed.ClosedAtMillis {
			return errSessionControlTerminalCorrupt
		}
	}
	digest, err := sessionControlCloseClosedDigest(closed)
	if err != nil || digest != closed.ClosedDigest {
		return errSessionControlTerminalCorrupt
	}
	return nil
}

func sessionControlCloseClosedToRow(closed sessionControlCloseClosedAudit) (sessionControlCloseClosedRow, error) {
	if err := validateSessionControlCloseClosedAudit(closed); err != nil {
		return sessionControlCloseClosedRow{}, err
	}
	directoryBefore, err := sessionControlFenceDirectoryToRow(closed.DirectoryBefore)
	if err != nil {
		return sessionControlCloseClosedRow{}, err
	}
	directoryAfter, err := sessionControlFenceDirectoryToRow(closed.DirectoryAfter)
	if err != nil {
		return sessionControlCloseClosedRow{}, err
	}
	fenceBefore, err := sessionControlFenceToRow(closed.FenceBefore, false)
	if err != nil {
		return sessionControlCloseClosedRow{}, err
	}
	fenceAfter, err := sessionControlFenceToRow(closed.FenceAfter, false)
	if err != nil {
		return sessionControlCloseClosedRow{}, err
	}
	sessionBefore, err := sessionControlSessionToRow(closed.SessionBefore)
	if err != nil {
		return sessionControlCloseClosedRow{}, err
	}
	sessionAfter, err := sessionControlSessionToRow(closed.SessionAfter)
	if err != nil {
		return sessionControlCloseClosedRow{}, err
	}
	var workBefore *sessionControlCloseWorkRow
	if closed.WorkBefore != nil {
		row, workErr := sessionControlCloseWorkToRow(*closed.WorkBefore)
		if workErr != nil {
			return sessionControlCloseClosedRow{}, workErr
		}
		workBefore = &row
	}
	complete, err := sessionControlCloseCompleteToRow(closed.Complete)
	if err != nil {
		return sessionControlCloseClosedRow{}, err
	}
	taskSet, err := sessionControlCloseTaskSetToRow(closed.TaskSet)
	if err != nil {
		return sessionControlCloseClosedRow{}, err
	}
	cleanChunkDigests := make([]string, len(closed.CleanChunkDigests))
	copy(cleanChunkDigests, closed.CleanChunkDigests)
	cleanChunkCreatedAtMillis := make([]int64, len(closed.CleanChunkCreatedAtMillis))
	copy(cleanChunkCreatedAtMillis, closed.CleanChunkCreatedAtMillis)
	return sessionControlCloseClosedRow{
		PK: sessionControlFenceMetaPK(closed.EventID), SK: sessionControlCloseClosedSK,
		Kind: sessionControlCloseClosedKind, SchemaVersion: sessionControlCloseClosedSchema,
		CellID: closed.CellID, EventID: closed.EventID,
		DirectoryBefore: directoryBefore, DirectoryAfter: directoryAfter,
		FenceBefore: fenceBefore, FenceAfter: fenceAfter, SessionBefore: sessionBefore, SessionAfter: sessionAfter,
		WorkBefore: workBefore, Complete: complete, TaskSet: taskSet,
		CleanChunkDigests:         cleanChunkDigests,
		CleanChunkCreatedAtMillis: cleanChunkCreatedAtMillis,
		ClosedAtMillis:            closed.ClosedAtMillis, ClosedDigest: closed.ClosedDigest,
	}, nil
}

func sessionControlCloseClosedFromItem(item map[string]types.AttributeValue,
	eventID string) (sessionControlCloseClosedAudit, error) {
	for _, name := range []string{"schema_version", "closed_at_ms"} {
		if _, ok := item[name].(*types.AttributeValueMemberN); !ok {
			return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
		}
	}
	for _, name := range []string{"directory_before", "directory_after", "fence_before", "fence_after",
		"session_before", "session_after", "complete", "taskset"} {
		if _, ok := item[name].(*types.AttributeValueMemberM); !ok {
			return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
		}
	}
	for _, name := range []string{"clean_chunk_digests", "clean_chunk_created_at_ms"} {
		if _, ok := item[name].(*types.AttributeValueMemberL); !ok {
			return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
		}
	}
	if _, hasTTL := item["ttl"]; hasTTL {
		return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
	}
	var row sessionControlCloseClosedRow
	if err := attributevalue.UnmarshalMap(item, &row); err != nil {
		return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
	}
	directoryBefore, err := sessionControlFenceDirectoryFromItem(
		item["directory_before"].(*types.AttributeValueMemberM).Value, row.CellID)
	if err != nil {
		return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
	}
	directoryAfter, err := sessionControlFenceDirectoryFromItem(
		item["directory_after"].(*types.AttributeValueMemberM).Value, row.CellID)
	if err != nil {
		return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
	}
	fenceBefore, err := sessionControlFenceFromRow(row.FenceBefore, false, row.CellID, eventID)
	if err != nil {
		return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
	}
	fenceAfter, err := sessionControlFenceFromRow(row.FenceAfter, false, row.CellID, eventID)
	if err != nil {
		return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
	}
	sessionBefore, err := sessionControlSessionFromRow(row.SessionBefore, row.SessionBefore.SessionID)
	if err != nil {
		return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
	}
	sessionAfter, err := sessionControlSessionFromRow(row.SessionAfter, row.SessionAfter.SessionID)
	if err != nil {
		return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
	}
	complete, err := sessionControlCloseCompleteFromItem(item["complete"].(*types.AttributeValueMemberM).Value, eventID)
	if err != nil {
		return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
	}
	taskSet, err := sessionControlCloseTaskSetFromItem(item["taskset"].(*types.AttributeValueMemberM).Value, eventID)
	if err != nil {
		return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
	}
	var workBefore *sessionControlCloseWork
	switch complete.WorkMode {
	case sessionControlCloseWorkModeNormal:
		if _, ok := item["work_before"].(*types.AttributeValueMemberM); !ok || row.WorkBefore == nil {
			return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
		}
		work, workErr := sessionControlCloseWorkFromRow(*row.WorkBefore, false, row.CellID, eventID)
		if workErr != nil {
			return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
		}
		workBefore = &work
	case sessionControlCloseWorkModeOverflow:
		if _, present := item["work_before"]; present || row.WorkBefore != nil {
			return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
		}
	default:
		return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
	}
	closed := sessionControlCloseClosedAudit{
		CellID: row.CellID, EventID: row.EventID, DirectoryBefore: directoryBefore, DirectoryAfter: directoryAfter,
		FenceBefore: fenceBefore, FenceAfter: fenceAfter, SessionBefore: sessionBefore, SessionAfter: sessionAfter,
		WorkBefore: workBefore, Complete: complete, TaskSet: taskSet,
		CleanChunkDigests:         row.CleanChunkDigests,
		CleanChunkCreatedAtMillis: row.CleanChunkCreatedAtMillis,
		ClosedAtMillis:            row.ClosedAtMillis, ClosedDigest: row.ClosedDigest,
	}
	if row.PK != sessionControlFenceMetaPK(eventID) || row.SK != sessionControlCloseClosedSK ||
		row.Kind != sessionControlCloseClosedKind || row.SchemaVersion != sessionControlCloseClosedSchema ||
		row.EventID != eventID || validateSessionControlCloseClosedAudit(closed) != nil {
		return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
	}
	canonicalRow, err := sessionControlCloseClosedToRow(closed)
	if err != nil {
		return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
	}
	canonicalItem, err := attributevalue.MarshalMap(canonicalRow)
	if err != nil || !reflect.DeepEqual(canonicalItem, item) {
		return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
	}
	return closed, nil
}

func (s *dynamoSessionControlStore) getCloseClosed(ctx context.Context,
	eventID string) (*sessionControlCloseClosedAudit, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.tableName),
		ConsistentRead: aws.Bool(true), Key: sessionControlCloseClosedKey(eventID)})
	if err != nil {
		return nil, fmt.Errorf("session-control CLOSED strong read: %w", err)
	}
	if len(result.Item) == 0 {
		return nil, errSessionControlTerminalNotFound
	}
	closed, err := sessionControlCloseClosedFromItem(result.Item, eventID)
	if err != nil {
		return nil, err
	}
	return &closed, nil
}

func sessionControlCloseExactReplace(tableName string, key map[string]types.AttributeValue,
	currentRow, nextRow any, absent ...string) (types.TransactWriteItem, error) {
	current, err := attributevalue.MarshalMap(currentRow)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	next, err := attributevalue.MarshalMap(nextRow)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	condition, names, values := sessionControlExactItemCondition(current, absent...)
	return types.TransactWriteItem{Put: &types.Put{TableName: aws.String(tableName), Item: next,
		ConditionExpression: aws.String(condition), ExpressionAttributeNames: names,
		ExpressionAttributeValues: values}}, nil
}

func sessionControlCloseExactDelete(tableName string, key map[string]types.AttributeValue,
	currentRow any, absent ...string) (types.TransactWriteItem, error) {
	current, err := attributevalue.MarshalMap(currentRow)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	condition, names, values := sessionControlExactItemCondition(current, absent...)
	return types.TransactWriteItem{Delete: &types.Delete{TableName: aws.String(tableName), Key: key,
		ConditionExpression: aws.String(condition), ExpressionAttributeNames: names,
		ExpressionAttributeValues: values}}, nil
}

func sessionControlCloseClosedPut(tableName string, closed sessionControlCloseClosedAudit) (types.TransactWriteItem, error) {
	row, err := sessionControlCloseClosedToRow(closed)
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

func sessionControlCloseClosedMatchesCandidate(closed sessionControlCloseClosedAudit,
	candidate sessionControlSessionCandidate, eventID string) bool {
	return closed.CellID == candidate.CellID && closed.EventID == eventID &&
		sessionControlCloseCompleteMatchesCandidate(closed.Complete, candidate, eventID) &&
		closed.SessionBefore.Candidate == candidate && closed.SessionAfter.Candidate == candidate
}

func sessionControlDirectoryAtOrAfterTerminal(current sessionControlFenceDirectory,
	closed sessionControlCloseClosedAudit) bool {
	if validateSessionControlFenceDirectory(current) != nil || current.CellID != closed.CellID ||
		current.Version < closed.DirectoryAfter.Version {
		return false
	}
	return current.Version != closed.DirectoryAfter.Version || current == closed.DirectoryAfter
}

func (s *dynamoSessionControlStore) classifyTerminalExactClose(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string) (*sessionControlCloseClosedAudit, error) {
	closed, err := s.getCloseClosed(ctx, eventID)
	if err != nil {
		return nil, err
	}
	if !sessionControlCloseClosedMatchesCandidate(*closed, candidate, eventID) {
		return nil, errSessionControlTerminalConflict
	}
	directory, err := s.getFenceDirectory(ctx, candidate.CellID)
	if err != nil {
		return nil, err
	}
	if !sessionControlDirectoryAtOrAfterTerminal(*directory, *closed) {
		return nil, errSessionControlTerminalConflict
	}
	session, err := s.classifyReservation(ctx, candidate)
	if err != nil {
		return nil, err
	}
	meta, metaErr := s.getFence(ctx, candidate.CellID, eventID, false)
	_, activeErr := s.getFence(ctx, candidate.CellID, eventID, true)
	_, workErr := s.getCloseWork(ctx, candidate.CellID, eventID, false)
	_, overflowErr := s.getCloseWork(ctx, candidate.CellID, eventID, true)
	complete, completeErr := s.getCloseComplete(ctx, eventID)
	taskSet, taskSetErr := s.getCloseTaskSet(ctx, eventID)
	if metaErr != nil {
		if errors.Is(metaErr, errSessionControlFenceNotFound) {
			return nil, errSessionControlTerminalConflict
		}
		return nil, metaErr
	}
	if activeErr == nil {
		return nil, errSessionControlTerminalConflict
	}
	if !errors.Is(activeErr, errSessionControlFenceNotFound) {
		return nil, activeErr
	}
	if workErr == nil {
		return nil, errSessionControlTerminalConflict
	}
	if !errors.Is(workErr, errSessionControlSessionNotFound) {
		return nil, workErr
	}
	if overflowErr == nil {
		return nil, errSessionControlTerminalConflict
	}
	if !errors.Is(overflowErr, errSessionControlSessionNotFound) {
		return nil, overflowErr
	}
	if completeErr != nil {
		if errors.Is(completeErr, errSessionControlCompletionNotFound) {
			return nil, errSessionControlTerminalConflict
		}
		return nil, completeErr
	}
	if taskSetErr != nil {
		if errors.Is(taskSetErr, errSessionControlSessionNotFound) {
			return nil, errSessionControlTerminalConflict
		}
		return nil, taskSetErr
	}
	if *session != closed.SessionAfter || *meta != closed.FenceAfter ||
		!reflect.DeepEqual(*complete, closed.Complete) || !reflect.DeepEqual(*taskSet, closed.TaskSet) {
		return nil, errSessionControlTerminalConflict
	}
	for index := range closed.CleanChunkDigests {
		chunk, chunkErr := s.getCloseCleanChunk(ctx, eventID, uint64(index))
		if chunkErr != nil {
			if errors.Is(chunkErr, errSessionControlTerminalNotFound) {
				return nil, errSessionControlTerminalConflict
			}
			return nil, chunkErr
		}
		if chunk.ChunkDigest != closed.CleanChunkDigests[index] ||
			chunk.CreatedAtMillis != closed.CleanChunkCreatedAtMillis[index] {
			return nil, errSessionControlTerminalConflict
		}
	}
	return closed, nil
}

func planSessionControlTerminalExactClose(directory sessionControlFenceDirectory,
	fence sessionControlFenceAuthority, session sessionControlSessionAuthority,
	work *sessionControlCloseWork, complete sessionControlCloseComplete,
	taskSet sessionControlCloseTaskSet, chunks []sessionControlCloseCleanChunk,
	closedAtMillis int64) (sessionControlCloseClosedAudit, error) {
	if directory.ActiveFenceCount == 0 || directory.Version >= math.MaxUint64-1 ||
		fence.Version >= math.MaxUint64-1 || closedAtMillis < fence.ReplayNotBeforeMillis {
		return sessionControlCloseClosedAudit{}, errSessionControlFenceReplayHorizon
	}
	nextDirectory := directory
	nextDirectory.Version++
	nextDirectory.ActiveFenceCount--
	nextDirectory.UpdatedAtMillis = closedAtMillis
	nextFence := fence
	nextFence.State = sessionControlFenceRetired
	nextFence.Version++
	nextFence.UpdatedAtMillis = closedAtMillis
	nextFence.RetiredAtMillis = closedAtMillis
	nextFence.ExpiresAt = closedAtMillis/1_000 + int64(sessionControlFenceIdempotencyTTL.Seconds())
	nextSession := session
	nextSession.State = sessionControlSessionStateClosed
	closed := sessionControlCloseClosedAudit{
		CellID: session.Candidate.CellID, EventID: session.CloseEventID,
		DirectoryBefore: directory, DirectoryAfter: nextDirectory,
		FenceBefore: fence, FenceAfter: nextFence, SessionBefore: session, SessionAfter: nextSession,
		WorkBefore: work, Complete: complete, TaskSet: taskSet,
		CleanChunkDigests:         make([]string, 0, len(chunks)),
		CleanChunkCreatedAtMillis: make([]int64, 0, len(chunks)), ClosedAtMillis: closedAtMillis,
	}
	for _, chunk := range chunks {
		closed.CleanChunkDigests = append(closed.CleanChunkDigests, chunk.ChunkDigest)
		closed.CleanChunkCreatedAtMillis = append(closed.CleanChunkCreatedAtMillis, chunk.CreatedAtMillis)
	}
	var err error
	closed.ClosedDigest, err = sessionControlCloseClosedDigest(closed)
	if err != nil || validateSessionControlCloseClosedAudit(closed) != nil {
		return sessionControlCloseClosedAudit{}, errSessionControlTerminalCorrupt
	}
	return closed, nil
}

// FinalizeTerminalExactClose releases one ACTIVE slot only after every
// manifest has an immutable CLEANCHUNK and the exact replay horizon has
// elapsed. The immutable CLOSED marker is the sole ambiguity proof.
func (s *dynamoSessionControlStore) FinalizeTerminalExactClose(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string) (*sessionControlCloseClosedAudit, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlSessionCandidate(candidate) || !validSessionControlFenceEventID(eventID) ||
		eventID != sessionControlExactCloseEventID(candidate) {
		return nil, errors.New("invalid session-control terminal close request")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	if _, err := s.getCloseClosed(opCtx, eventID); err == nil {
		return s.classifyTerminalExactClose(opCtx, candidate, eventID)
	} else if !errors.Is(err, errSessionControlTerminalNotFound) {
		return nil, err
	}
	stable, err := s.readStableExactCloseState(opCtx, candidate, eventID)
	if err != nil {
		return nil, err
	}
	if stable.Session == nil || stable.Meta == nil || stable.Active == nil || stable.Overflow != nil ||
		*stable.Meta != *stable.Active || stable.Meta.State != sessionControlFenceConverged ||
		stable.Session.State != sessionControlSessionStateClosing {
		return nil, errSessionControlTerminalConflict
	}
	complete, err := s.getCloseComplete(opCtx, eventID)
	if err != nil {
		return nil, err
	}
	taskSet, err := s.getCloseTaskSet(opCtx, eventID)
	if err != nil {
		return nil, err
	}
	var work *sessionControlCloseWork
	switch complete.WorkMode {
	case sessionControlCloseWorkModeNormal:
		if stable.Work == nil || stable.Work.Mode != sessionControlCloseWorkModeNormal ||
			stable.Work.State != sessionControlCloseWorkStateCompleted {
			return nil, errSessionControlTerminalConflict
		}
		copy := *stable.Work
		work = &copy
	case sessionControlCloseWorkModeOverflow:
		if stable.Work != nil {
			return nil, errSessionControlTerminalConflict
		}
	default:
		return nil, errSessionControlTerminalCorrupt
	}
	if !sessionControlCloseCompleteMatchesCandidate(*complete, candidate, eventID) ||
		!sessionControlCloseCompleteMatchesSessionTaskSet(*complete, *stable.Session, *taskSet) ||
		complete.SelectorDigest != stable.Meta.SelectorDigest ||
		(work != nil && !sessionControlCloseCompleteMatchesAuthority(*complete, *stable.Session, *work, *taskSet)) ||
		!sessionControlCloseTaskSetMatchesComplete(*taskSet, *complete) ||
		complete.FenceVersion != stable.Meta.Version || complete.CompletedDirectoryVersion > stable.Directory.Version ||
		stable.Session.RetainUntilMillis != complete.RetainUntilMillis {
		return nil, errSessionControlTerminalCorrupt
	}
	chunks := make([]sessionControlCloseCleanChunk, 0, len(complete.ManifestDigests))
	var sourceTotal, ownerTotal uint64
	for index := range complete.ManifestDigests {
		chunk, chunkErr := s.getCloseCleanChunk(opCtx, eventID, uint64(index))
		if chunkErr != nil {
			return nil, chunkErr
		}
		if !sessionControlCloseCompleteCanExtend(*complete, chunk.Complete) ||
			chunk.TaskSet.TaskSetDigest != taskSet.TaskSetDigest || chunk.ManifestIndex != uint64(index) ||
			chunk.Manifest.ManifestDigest != complete.ManifestDigests[index] ||
			chunk.AckChunk.ChunkDigest != complete.ChunkDigests[index] ||
			chunk.SourceCount != complete.ChunkSourceCounts[index] ||
			chunk.OwnerCount != complete.ChunkOwnerCounts[index] ||
			chunk.SourceCount > complete.SourceCount-sourceTotal || chunk.OwnerCount > complete.OwnerCount-ownerTotal {
			return nil, errSessionControlTerminalCorrupt
		}
		sourceTotal += chunk.SourceCount
		ownerTotal += chunk.OwnerCount
		chunks = append(chunks, *chunk)
	}
	if sourceTotal != complete.SourceCount || ownerTotal != complete.OwnerCount ||
		(len(chunks) == 0) != (complete.OwnerCount == 0) {
		return nil, errSessionControlTerminalCorrupt
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	closedAt := now.UnixMilli()
	if closedAt < stable.Meta.ReplayNotBeforeMillis {
		return nil, errSessionControlFenceReplayHorizon
	}
	for _, candidateMillis := range []int64{stable.Directory.UpdatedAtMillis, stable.Meta.UpdatedAtMillis,
		stable.Session.ClosePreparedAtMillis, complete.CompletedAtMillis,
		stable.Meta.ReplayNotBeforeMillis} {
		if candidateMillis > closedAt {
			closedAt = candidateMillis
		}
	}
	if work != nil && work.UpdatedAtMillis > closedAt {
		closedAt = work.UpdatedAtMillis
	}
	for _, chunk := range chunks {
		if chunk.CreatedAtMillis > closedAt {
			closedAt = chunk.CreatedAtMillis
		}
	}
	closed, err := planSessionControlTerminalExactClose(stable.Directory, *stable.Meta, *stable.Session,
		work, *complete, *taskSet, chunks, closedAt)
	if err != nil {
		return nil, err
	}
	directoryBeforeRow, _ := sessionControlFenceDirectoryToRow(closed.DirectoryBefore)
	directoryAfterRow, _ := sessionControlFenceDirectoryToRow(closed.DirectoryAfter)
	directoryReplace, err := sessionControlCloseExactReplace(s.tableName,
		sessionControlFenceDirectoryKey(candidate.CellID), directoryBeforeRow, directoryAfterRow)
	if err != nil {
		return nil, err
	}
	fenceBeforeRow, _ := sessionControlFenceToRow(closed.FenceBefore, false)
	fenceAfterRow, _ := sessionControlFenceToRow(closed.FenceAfter, false)
	metaReplace, err := sessionControlCloseExactReplace(s.tableName, sessionControlFenceMetaKey(eventID),
		fenceBeforeRow, fenceAfterRow, "retired_at_ms", "expires_at")
	if err != nil {
		return nil, err
	}
	activeBeforeRow, _ := sessionControlFenceToRow(closed.FenceBefore, true)
	activeDelete, err := sessionControlCloseExactDelete(s.tableName,
		sessionControlFenceActiveKey(candidate.CellID, eventID), activeBeforeRow, "retired_at_ms", "expires_at")
	if err != nil {
		return nil, err
	}
	sessionBeforeRow, _ := sessionControlSessionToRow(closed.SessionBefore)
	sessionAfterRow, _ := sessionControlSessionToRow(closed.SessionAfter)
	sessionReplace, err := sessionControlCloseExactReplace(s.tableName,
		sessionControlSessionDynamoKey(candidate.SessionID), sessionBeforeRow, sessionAfterRow,
		sessionControlSessionRowAbsentAttributes(sessionBeforeRow)...)
	if err != nil {
		return nil, err
	}
	closedPut, err := sessionControlCloseClosedPut(s.tableName, closed)
	if err != nil {
		return nil, err
	}
	completeCondition, err := sessionControlCloseCompleteCondition(s.tableName, *complete)
	if err != nil {
		return nil, err
	}
	taskSetCondition, err := sessionControlCloseTaskSetCondition(s.tableName, *taskSet)
	if err != nil {
		return nil, err
	}
	transaction := []types.TransactWriteItem{directoryReplace, metaReplace, activeDelete, sessionReplace}
	if closed.WorkBefore != nil {
		workBeforeRow, rowErr := sessionControlCloseWorkToRow(*closed.WorkBefore)
		if rowErr != nil {
			return nil, rowErr
		}
		workDelete, deleteErr := sessionControlCloseExactDelete(s.tableName, sessionControlCloseWorkKey(eventID),
			workBeforeRow, "due_at_ms", "due_shard", "due_sort")
		if deleteErr != nil {
			return nil, deleteErr
		}
		transaction = append(transaction, workDelete)
	}
	transaction = append(transaction, closedPut, completeCondition, taskSetCondition)
	for _, chunk := range chunks {
		condition, conditionErr := sessionControlCloseCleanChunkCondition(s.tableName, chunk)
		if conditionErr != nil {
			return nil, conditionErr
		}
		transaction = append(transaction, condition)
	}
	if len(transaction) > 30 {
		return nil, errSessionControlTerminalCorrupt
	}
	token, err := sessionControlTerminalToken(s.tableName, "close", closed)
	if err != nil {
		return nil, err
	}
	_, writeErr := s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: token, TransactItems: transaction})
	if writeErr == nil {
		return &closed, nil
	}
	var canceled *types.TransactionCanceledException
	if errors.As(writeErr, &canceled) {
		classified, classifyErr := s.classifyTerminalExactClose(opCtx, candidate, eventID)
		if classifyErr == nil {
			return classified, nil
		}
		return nil, errSessionControlTerminalConflict
	}
	resultCtx, resultCancel := s.sessionResultContext(ctx)
	defer resultCancel()
	classified, classifyErr := s.classifyTerminalExactClose(resultCtx, candidate, eventID)
	if classifyErr == nil {
		return classified, nil
	}
	return nil, fmt.Errorf("finalize terminal session-control exact close: %w", writeErr)
}

func (s *dynamoSessionControlStore) FinalizeTerminalNormalExactClose(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string) (*sessionControlCloseClosedAudit, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlSessionCandidate(candidate) || !validSessionControlFenceEventID(eventID) ||
		eventID != sessionControlExactCloseEventID(candidate) {
		return nil, errors.New("invalid session-control terminal close request")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	if closed, err := s.getCloseClosed(opCtx, eventID); err == nil {
		cancel()
		if closed.Complete.WorkMode != sessionControlCloseWorkModeNormal {
			return nil, errSessionControlTerminalConflict
		}
		return s.FinalizeTerminalExactClose(ctx, candidate, eventID)
	} else if !errors.Is(err, errSessionControlTerminalNotFound) {
		cancel()
		return nil, err
	}
	complete, err := s.getCloseComplete(opCtx, eventID)
	cancel()
	if err != nil {
		return nil, err
	}
	if complete.WorkMode != sessionControlCloseWorkModeNormal {
		return nil, errSessionControlTerminalConflict
	}
	return s.FinalizeTerminalExactClose(ctx, candidate, eventID)
}
