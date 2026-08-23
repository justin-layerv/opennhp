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
	sessionControlCloseTaskAuditKind     = "close_task_audit"
	sessionControlCloseTaskAuditSchema   = uint64(1)
	sessionControlCloseTaskAuditSKPrefix = "TASKAUDIT#"
	sessionControlCloseCleanupPageLimit  = int32(100)
)

var (
	errSessionControlCleanupNotFound = errors.New("session-control close cleanup authority not found")
	errSessionControlCleanupConflict = errors.New("session-control close cleanup changed concurrently")
	errSessionControlCleanupCorrupt  = errors.New("session-control close cleanup authority is malformed")
)

type sessionControlCloseTaskCleanupRequest struct {
	CellID      string
	EventID     string
	OwnerPK     string
	OperationID string
}

// sessionControlCloseTaskAudit is the durable result of the only operation
// that physically removes a completed task. It intentionally retains the full
// first ACK and both owner cursors: an ACK or cleanup response may be lost
// after the transaction commits, and neither caller may infer success from a
// missing task alone.
type sessionControlCloseTaskAudit struct {
	CellID               string
	EventID              string
	OwnerPK              string
	ManifestIndex        uint64
	Complete             sessionControlCloseComplete
	AckedTask            sessionControlCloseTask
	OwnerBefore          sessionControlOwnerAuthority
	OwnerAfter           sessionControlOwnerAuthority
	OperationID          string
	OperationInputDigest string
	CleanedAtMillis      int64
	RetainUntilMillis    int64
	AuditDigest          string
}

type sessionControlCloseTaskAuditRow struct {
	PK                   string                         `dynamodbav:"pk"`
	SK                   string                         `dynamodbav:"sk"`
	Kind                 string                         `dynamodbav:"kind"`
	SchemaVersion        uint64                         `dynamodbav:"schema_version"`
	CellID               string                         `dynamodbav:"cell_id"`
	EventID              string                         `dynamodbav:"event_id"`
	OwnerPK              string                         `dynamodbav:"owner_pk"`
	ManifestIndex        uint64                         `dynamodbav:"manifest_index"`
	Complete             sessionControlCloseCompleteRow `dynamodbav:"complete"`
	AckedTask            sessionControlCloseTaskRow     `dynamodbav:"acked_task"`
	OwnerBefore          sessionControlOwnerRow         `dynamodbav:"owner_before"`
	OwnerAfter           sessionControlOwnerRow         `dynamodbav:"owner_after"`
	OperationID          string                         `dynamodbav:"operation_id"`
	OperationInputDigest string                         `dynamodbav:"operation_input_digest"`
	CleanedAtMillis      int64                          `dynamodbav:"cleaned_at_ms"`
	RetainUntilMillis    int64                          `dynamodbav:"retain_until_ms"`
	AuditDigest          string                         `dynamodbav:"audit_digest"`
}

type sessionControlCompletedCloseTaskCursor struct {
	CellID         string
	EventID        string
	CompleteDigest string
	ManifestIndex  uint64
	RefIndex       uint64
	SeenOwners     uint64
	SeenSources    uint64
}

type sessionControlCompletedCloseTaskItem struct {
	OwnerPK string
	Task    *sessionControlCloseTask
	Audit   *sessionControlCloseTaskAudit
}

type sessionControlCompletedCloseTaskPage struct {
	Items []sessionControlCompletedCloseTaskItem
	Next  *sessionControlCompletedCloseTaskCursor
}

func sessionControlCloseTaskAuditSK(eventID string) string {
	return sessionControlCloseTaskAuditSKPrefix + eventID
}

func sessionControlCloseTaskAuditKey(ownerPK, eventID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: ownerPK},
		"sk": &types.AttributeValueMemberS{Value: sessionControlCloseTaskAuditSK(eventID)},
	}
}

func sessionControlCloseTaskCleanupInputDigest(request sessionControlCloseTaskCleanupRequest) (string, error) {
	return sessionControlMaterializationDigest(struct {
		Version     uint64
		CellID      string
		EventID     string
		OwnerPK     string
		OperationID string
	}{1, request.CellID, request.EventID, request.OwnerPK, request.OperationID})
}

func validSessionControlCloseTaskCleanupRequest(request sessionControlCloseTaskCleanupRequest) bool {
	return validSessionControlCellID(request.CellID) && validSessionControlFenceEventID(request.EventID) &&
		validSessionControlOwnerPK(request.OwnerPK) && validSessionControlTaskOperationID(request.OperationID)
}

func sessionControlCloseTaskAuditDigest(audit sessionControlCloseTaskAudit) (string, error) {
	audit.AuditDigest = ""
	return sessionControlMaterializationDigest(struct {
		Version uint64
		Audit   sessionControlCloseTaskAudit
	}{1, audit})
}

func sessionControlCloseCompleteCanExtend(current, recorded sessionControlCloseComplete) bool {
	if current.RetainUntilMillis < recorded.RetainUntilMillis {
		return false
	}
	current.RetainUntilMillis = recorded.RetainUntilMillis
	current.CompleteDigest = recorded.CompleteDigest
	return reflect.DeepEqual(current, recorded)
}

func sessionControlCloseTaskMatchesComplete(task sessionControlCloseTask,
	complete sessionControlCloseComplete) bool {
	return task.State == sessionControlCloseTaskStateAcked && validSessionControlExactCloseWorkMode(task.WorkMode) &&
		task.WorkMode == complete.WorkMode &&
		task.CellID == complete.CellID && task.EventID == complete.EventID &&
		task.SelectorDigest == complete.SelectorDigest && task.SessionVersion == complete.SessionVersion &&
		task.ExpectedTargetCount == complete.ExpectedTargetCount &&
		task.PreparedDirectoryVersion == complete.PreparedDirectoryVersion &&
		task.ManifestIndex < uint64(len(complete.ManifestDigests))
}

// Cleanup consumes physical inventory, not delivery authority. A reconnect
// may legitimately replace the target lifecycle after an ACK without
// rewriting the terminal task. The current owner is therefore allowed to be a
// later lifecycle descendant, while its stable identity and work/count cursor
// remain exact enough for a one-row decrement CAS.
func sessionControlCloseTaskMatchesCleanupOwner(task sessionControlCloseTask,
	owner sessionControlOwnerAuthority) bool {
	if task.State != sessionControlCloseTaskStateAcked || validateSessionControlOwnerAuthority(owner) != nil ||
		owner.CellID != task.CellID || owner.ACID != task.ACID || owner.PublicKey != task.PublicKey ||
		owner.Phase == sessionControlOwnerRetired || owner.TaskCount == 0 ||
		owner.WorkVersion < task.CurrentOwnerWorkVersion {
		return false
	}
	return owner.WorkVersion != task.CurrentOwnerWorkVersion ||
		(owner.TaskCount == task.CurrentOwnerTaskCount && owner.PendingCount == task.CurrentOwnerPendingCount)
}

func validateSessionControlCloseTaskAudit(audit sessionControlCloseTaskAudit) error {
	if !validSessionControlCellID(audit.CellID) || !validSessionControlFenceEventID(audit.EventID) ||
		!validSessionControlOwnerPK(audit.OwnerPK) || audit.ManifestIndex >= sessionControlCloseManifestLimit ||
		validateSessionControlCloseComplete(audit.Complete) != nil ||
		validateSessionControlCloseTask(audit.AckedTask) != nil ||
		!sessionControlCloseTaskMatchesComplete(audit.AckedTask, audit.Complete) ||
		audit.AckedTask.OwnerPK != audit.OwnerPK || audit.AckedTask.ManifestIndex != audit.ManifestIndex ||
		validateSessionControlOwnerAuthority(audit.OwnerBefore) != nil ||
		validateSessionControlOwnerAuthority(audit.OwnerAfter) != nil ||
		audit.OwnerBefore.CellID != audit.CellID || audit.OwnerBefore.ACID != audit.AckedTask.ACID ||
		audit.OwnerBefore.PublicKey != audit.AckedTask.PublicKey ||
		!sessionControlCloseTaskMatchesCleanupOwner(audit.AckedTask, audit.OwnerBefore) ||
		!validSessionControlTaskOperationID(audit.OperationID) ||
		!validSessionControlTaskInputDigest(audit.OperationInputDigest) || audit.CleanedAtMillis <= 0 ||
		audit.CleanedAtMillis < audit.Complete.CompletedAtMillis ||
		audit.CleanedAtMillis > math.MaxInt64-sessionControlFenceReplayHorizon.Milliseconds() ||
		audit.RetainUntilMillis < audit.Complete.RetainUntilMillis ||
		audit.RetainUntilMillis < audit.CleanedAtMillis+sessionControlFenceReplayHorizon.Milliseconds() {
		return errSessionControlCleanupCorrupt
	}
	inputDigest, err := sessionControlCloseTaskCleanupInputDigest(sessionControlCloseTaskCleanupRequest{
		CellID: audit.CellID, EventID: audit.EventID, OwnerPK: audit.OwnerPK, OperationID: audit.OperationID,
	})
	if err != nil || inputDigest != audit.OperationInputDigest {
		return errSessionControlCleanupCorrupt
	}
	next, err := planSessionControlOwnerTaskCleanup(audit.OwnerBefore, audit.CleanedAtMillis)
	if err != nil || next != audit.OwnerAfter {
		return errSessionControlCleanupCorrupt
	}
	digest, err := sessionControlCloseTaskAuditDigest(audit)
	if err != nil || digest != audit.AuditDigest {
		return errSessionControlCleanupCorrupt
	}
	return nil
}

func sessionControlCloseTaskAuditToRow(audit sessionControlCloseTaskAudit) (sessionControlCloseTaskAuditRow, error) {
	if err := validateSessionControlCloseTaskAudit(audit); err != nil {
		return sessionControlCloseTaskAuditRow{}, err
	}
	complete, err := sessionControlCloseCompleteToRow(audit.Complete)
	if err != nil {
		return sessionControlCloseTaskAuditRow{}, err
	}
	task, err := sessionControlCloseTaskToRow(audit.AckedTask)
	if err != nil {
		return sessionControlCloseTaskAuditRow{}, err
	}
	before, err := sessionControlOwnerToRow(audit.OwnerBefore)
	if err != nil {
		return sessionControlCloseTaskAuditRow{}, err
	}
	after, err := sessionControlOwnerToRow(audit.OwnerAfter)
	if err != nil {
		return sessionControlCloseTaskAuditRow{}, err
	}
	return sessionControlCloseTaskAuditRow{
		PK: audit.OwnerPK, SK: sessionControlCloseTaskAuditSK(audit.EventID), Kind: sessionControlCloseTaskAuditKind,
		SchemaVersion: sessionControlCloseTaskAuditSchema, CellID: audit.CellID, EventID: audit.EventID,
		OwnerPK: audit.OwnerPK, ManifestIndex: audit.ManifestIndex, Complete: complete, AckedTask: task,
		OwnerBefore: before, OwnerAfter: after, OperationID: audit.OperationID,
		OperationInputDigest: audit.OperationInputDigest, CleanedAtMillis: audit.CleanedAtMillis,
		RetainUntilMillis: audit.RetainUntilMillis, AuditDigest: audit.AuditDigest,
	}, nil
}

func sessionControlCloseTaskAuditFromItem(item map[string]types.AttributeValue,
	ownerPK, eventID string) (sessionControlCloseTaskAudit, error) {
	if len(item) == 0 {
		return sessionControlCloseTaskAudit{}, errSessionControlCleanupNotFound
	}
	if _, hasTTL := item["ttl"]; hasTTL {
		return sessionControlCloseTaskAudit{}, errSessionControlCleanupCorrupt
	}
	for _, name := range []string{"schema_version", "manifest_index", "cleaned_at_ms", "retain_until_ms"} {
		if _, ok := item[name].(*types.AttributeValueMemberN); !ok {
			return sessionControlCloseTaskAudit{}, errSessionControlCleanupCorrupt
		}
	}
	for _, name := range []string{"complete", "acked_task", "owner_before", "owner_after"} {
		if _, ok := item[name].(*types.AttributeValueMemberM); !ok {
			return sessionControlCloseTaskAudit{}, errSessionControlCleanupCorrupt
		}
	}
	var row sessionControlCloseTaskAuditRow
	if err := attributevalue.UnmarshalMap(item, &row); err != nil {
		return sessionControlCloseTaskAudit{}, fmt.Errorf("%w: decode TASKAUDIT", errSessionControlCleanupCorrupt)
	}
	completeItem := item["complete"].(*types.AttributeValueMemberM).Value
	complete, err := sessionControlCloseCompleteFromItem(completeItem, row.EventID)
	if err != nil {
		return sessionControlCloseTaskAudit{}, errSessionControlCleanupCorrupt
	}
	taskItem := item["acked_task"].(*types.AttributeValueMemberM).Value
	task, err := sessionControlCloseTaskFromItem(taskItem, row.OwnerPK, row.EventID)
	if err != nil {
		return sessionControlCloseTaskAudit{}, errSessionControlCleanupCorrupt
	}
	beforeItem := item["owner_before"].(*types.AttributeValueMemberM).Value
	before, err := sessionControlOwnerFromItem(beforeItem, row.CellID, task.ACID, task.PublicKey)
	if err != nil {
		return sessionControlCloseTaskAudit{}, errSessionControlCleanupCorrupt
	}
	afterItem := item["owner_after"].(*types.AttributeValueMemberM).Value
	after, err := sessionControlOwnerFromItem(afterItem, row.CellID, task.ACID, task.PublicKey)
	if err != nil {
		return sessionControlCloseTaskAudit{}, errSessionControlCleanupCorrupt
	}
	audit := sessionControlCloseTaskAudit{CellID: row.CellID, EventID: row.EventID, OwnerPK: row.OwnerPK,
		ManifestIndex: row.ManifestIndex, Complete: complete, AckedTask: task, OwnerBefore: before,
		OwnerAfter: after, OperationID: row.OperationID, OperationInputDigest: row.OperationInputDigest,
		CleanedAtMillis: row.CleanedAtMillis, RetainUntilMillis: row.RetainUntilMillis,
		AuditDigest: row.AuditDigest}
	if row.PK != ownerPK || row.SK != sessionControlCloseTaskAuditSK(eventID) ||
		row.Kind != sessionControlCloseTaskAuditKind || row.SchemaVersion != sessionControlCloseTaskAuditSchema ||
		row.OwnerPK != ownerPK || row.EventID != eventID || validateSessionControlCloseTaskAudit(audit) != nil {
		return sessionControlCloseTaskAudit{}, errSessionControlCleanupCorrupt
	}
	return audit, nil
}

func (s *dynamoSessionControlStore) getCloseTaskAudit(ctx context.Context,
	ownerPK, eventID string) (*sessionControlCloseTaskAudit, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.tableName),
		ConsistentRead: aws.Bool(true), Key: sessionControlCloseTaskAuditKey(ownerPK, eventID)})
	if err != nil {
		return nil, fmt.Errorf("session-control TASKAUDIT strong read: %w", err)
	}
	audit, err := sessionControlCloseTaskAuditFromItem(result.Item, ownerPK, eventID)
	if err != nil {
		return nil, err
	}
	return &audit, nil
}

func sessionControlCloseTaskAuditMatchesRequest(audit sessionControlCloseTaskAudit,
	request sessionControlCloseTaskCleanupRequest, complete sessionControlCloseComplete) bool {
	digest, err := sessionControlCloseTaskCleanupInputDigest(request)
	return err == nil && audit.CellID == request.CellID && audit.EventID == request.EventID &&
		audit.OwnerPK == request.OwnerPK && audit.OperationID == request.OperationID &&
		audit.OperationInputDigest == digest && sessionControlCloseCompleteCanExtend(complete, audit.Complete)
}

func sessionControlCloseTaskMatchesRef(task sessionControlCloseTask,
	manifest sessionControlCloseManifest, ref sessionControlCloseTaskRef) bool {
	return task.ManifestIndex == manifest.ManifestIndex && task.OwnerPK == ref.OwnerPK &&
		task.CreationDigest == ref.CreationDigest && task.SourceDigest == ref.SourceDigest &&
		task.SourceCount == ref.SourceCount
}

func sessionControlCloseAckChunkContainsTask(chunk sessionControlCloseAckChunk,
	task sessionControlCloseTask) bool {
	expected := sessionControlCloseAckRefFromTask(task)
	for _, ref := range chunk.Refs {
		if ref.OwnerPK == task.OwnerPK {
			return ref == expected
		}
	}
	return false
}

func sessionControlCloseCompleteMatchesTaskAuthority(complete sessionControlCloseComplete,
	taskSet sessionControlCloseTaskSet, manifest sessionControlCloseManifest,
	chunk sessionControlCloseAckChunk, task sessionControlCloseTask) bool {
	index := task.ManifestIndex
	return sessionControlCloseTaskMatchesComplete(task, complete) &&
		complete.TaskSetDigest == taskSet.TaskSetDigest && complete.SourceCount == taskSet.SourceCount &&
		complete.OwnerCount == taskSet.OwnerCount && complete.ManifestDigests[index] == manifest.ManifestDigest &&
		complete.ChunkDigests[index] == chunk.ChunkDigest &&
		complete.ChunkSourceCounts[index] == chunk.SourceCount &&
		complete.ChunkOwnerCounts[index] == chunk.OwnerCount &&
		chunk.CellID == complete.CellID && chunk.EventID == complete.EventID &&
		chunk.SelectorDigest == complete.SelectorDigest && chunk.SessionVersion == complete.SessionVersion &&
		chunk.ExpectedTargetCount == complete.ExpectedTargetCount &&
		chunk.PreparedDirectoryVersion == complete.PreparedDirectoryVersion &&
		chunk.WorkMode == complete.WorkMode && chunk.TaskSetDigest == complete.TaskSetDigest &&
		chunk.ManifestIndex == index && chunk.ManifestDigest == manifest.ManifestDigest &&
		sessionControlCloseAckChunkContainsTask(chunk, task)
}

func (s *dynamoSessionControlStore) readCloseTaskCompletionAuthority(ctx context.Context,
	complete sessionControlCloseComplete, task sessionControlCloseTask) (*sessionControlCloseTaskSet,
	*sessionControlCloseManifest, *sessionControlCloseAckChunk, error) {
	taskSet, err := s.getCloseTaskSet(ctx, complete.EventID)
	if err != nil {
		if errors.Is(err, errSessionControlSessionNotFound) || errors.Is(err, errSessionControlMaterializationCorrupt) {
			return nil, nil, nil, errSessionControlCleanupCorrupt
		}
		return nil, nil, nil, err
	}
	if task.ManifestIndex >= uint64(len(taskSet.ManifestDigests)) {
		return nil, nil, nil, errSessionControlCleanupCorrupt
	}
	manifest, err := s.getCloseManifest(ctx, complete.EventID, task.ManifestIndex)
	if err != nil {
		if errors.Is(err, errSessionControlSessionNotFound) || errors.Is(err, errSessionControlMaterializationCorrupt) {
			return nil, nil, nil, errSessionControlCleanupCorrupt
		}
		return nil, nil, nil, err
	}
	chunk, err := s.getCloseAckChunk(ctx, complete.EventID, task.ManifestIndex)
	if err != nil {
		if errors.Is(err, errSessionControlCompletionNotFound) || errors.Is(err, errSessionControlCompletionCorrupt) {
			return nil, nil, nil, errSessionControlCleanupCorrupt
		}
		return nil, nil, nil, err
	}
	if !sessionControlCloseCompleteMatchesTaskAuthority(complete, *taskSet, *manifest, *chunk, task) {
		return nil, nil, nil, errSessionControlCleanupCorrupt
	}
	return taskSet, manifest, chunk, nil
}

func sessionControlCloseCompleteCondition(tableName string,
	complete sessionControlCloseComplete) (types.TransactWriteItem, error) {
	row, err := sessionControlCloseCompleteToRow(complete)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	condition, names, values := sessionControlExactItemCondition(item)
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{TableName: aws.String(tableName),
		Key: sessionControlCloseCompleteKey(complete.EventID), ConditionExpression: aws.String(condition),
		ExpressionAttributeNames: names, ExpressionAttributeValues: values}}, nil
}

func sessionControlCloseTaskDelete(tableName string,
	task sessionControlCloseTask) (types.TransactWriteItem, error) {
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
	return types.TransactWriteItem{Delete: &types.Delete{TableName: aws.String(tableName),
		Key: sessionControlCloseTaskKey(task.OwnerPK, task.EventID), ConditionExpression: aws.String(condition),
		ExpressionAttributeNames: names, ExpressionAttributeValues: values}}, nil
}

func sessionControlCloseTaskAuditPut(tableName string,
	audit sessionControlCloseTaskAudit) (types.TransactWriteItem, error) {
	row, err := sessionControlCloseTaskAuditToRow(audit)
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

func sessionControlCloseTaskCleanupToken(tableName string, complete sessionControlCloseComplete,
	task sessionControlCloseTask, current, next sessionControlOwnerAuthority,
	audit sessionControlCloseTaskAudit) (*string, error) {
	digest, err := sessionControlMaterializationDigest(struct {
		Version  uint64
		Table    string
		Complete sessionControlCloseComplete
		Task     sessionControlCloseTask
		Current  sessionControlOwnerAuthority
		Next     sessionControlOwnerAuthority
		Audit    sessionControlCloseTaskAudit
	}{1, tableName, complete, task, current, next, audit})
	if err != nil {
		return nil, err
	}
	return aws.String("sc-cl-" + digest[:24]), nil
}

func (s *dynamoSessionControlStore) classifyCloseTaskCleanup(ctx context.Context,
	request sessionControlCloseTaskCleanupRequest,
	requiredComplete sessionControlCloseComplete) (*sessionControlCloseTaskAudit, error) {
	complete, err := s.getCloseComplete(ctx, request.EventID)
	if err != nil {
		return nil, err
	}
	if !sessionControlCloseCompleteCanExtend(*complete, requiredComplete) {
		return nil, errSessionControlCleanupConflict
	}
	audit, err := s.getCloseTaskAudit(ctx, request.OwnerPK, request.EventID)
	if err != nil {
		return nil, err
	}
	if !sessionControlCloseTaskAuditMatchesRequest(*audit, request, *complete) {
		return nil, errSessionControlCleanupConflict
	}
	if _, _, _, err = s.readCloseTaskCompletionAuthority(ctx, *complete, audit.AckedTask); err != nil {
		return nil, err
	}
	if _, err = s.getCloseTask(ctx, request.OwnerPK, request.EventID); !errors.Is(err, errSessionControlCloseTaskNotFound) {
		if err == nil {
			return nil, errSessionControlCleanupCorrupt
		}
		return nil, err
	}
	return audit, nil
}

func (s *dynamoSessionControlStore) classifyAckedCloseTaskAudit(ctx context.Context,
	request sessionControlCloseTaskAckRequest) (*sessionControlCloseTask, error) {
	audit, err := s.getCloseTaskAudit(ctx, request.Lease.OwnerPK, request.Lease.EventID)
	if errors.Is(err, errSessionControlCleanupNotFound) {
		return nil, errSessionControlCloseTaskNotFound
	}
	if err != nil {
		return nil, err
	}
	classified, err := s.classifyCloseTaskCleanup(ctx, sessionControlCloseTaskCleanupRequest{
		CellID: audit.CellID, EventID: audit.EventID, OwnerPK: audit.OwnerPK, OperationID: audit.OperationID,
	}, audit.Complete)
	if err != nil {
		return nil, err
	}
	if !sessionControlCloseTaskAckMatches(classified.AckedTask, request, true) {
		return nil, errSessionControlCloseTaskConflict
	}
	task := classified.AckedTask
	return &task, nil
}

func (s *dynamoSessionControlStore) classifyCompletedCloseTaskAck(ctx context.Context,
	request sessionControlCloseTaskAckRequest) (*sessionControlCloseTask, error) {
	task, err := s.getCloseTask(ctx, request.Lease.OwnerPK, request.Lease.EventID)
	if err != nil {
		return nil, err
	}
	complete, err := s.getCloseComplete(ctx, request.Lease.EventID)
	if err != nil {
		return nil, err
	}
	if !sessionControlCloseTaskAckMatches(*task, request, true) ||
		!sessionControlCloseTaskMatchesComplete(*task, *complete) {
		return nil, errSessionControlCloseTaskConflict
	}
	if _, _, _, err = s.readCloseTaskCompletionAuthority(ctx, *complete, *task); err != nil {
		return nil, err
	}
	return task, nil
}

// CleanupAckedNormalExactCloseTask replaces one exact ACKED TASK with an
// immutable TASKAUDIT while decrementing its stable owner's physical task
// count. COMPLETE, MANIFEST, and ACKCHUNK are immutable recovery authority;
// the transaction therefore needs only the exact COMPLETE condition in
// addition to OWNER, TASK, and TASKAUDIT.
func (s *dynamoSessionControlStore) CleanupAckedExactCloseTask(ctx context.Context,
	request sessionControlCloseTaskCleanupRequest) (*sessionControlCloseTaskAudit, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlCloseTaskCleanupRequest(request) {
		return nil, errors.New("invalid session-control close task cleanup")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	complete, err := s.getCloseComplete(opCtx, request.EventID)
	if err != nil {
		return nil, err
	}
	if complete.CellID != request.CellID || !validSessionControlExactCloseWorkMode(complete.WorkMode) {
		return nil, errSessionControlCleanupConflict
	}
	if audit, auditErr := s.getCloseTaskAudit(opCtx, request.OwnerPK, request.EventID); auditErr == nil {
		if !sessionControlCloseTaskAuditMatchesRequest(*audit, request, *complete) {
			return nil, errSessionControlCleanupConflict
		}
		return s.classifyCloseTaskCleanup(opCtx, request, *complete)
	} else if !errors.Is(auditErr, errSessionControlCleanupNotFound) {
		return nil, auditErr
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	task, err := s.getCloseTask(opCtx, request.OwnerPK, request.EventID)
	if err != nil {
		return nil, err
	}
	state := sessionControlCommittedTaskState{Task: *task}
	owner, err := s.getOwner(opCtx, state.Task.CellID, state.Task.ACID, state.Task.PublicKey)
	if err != nil {
		return nil, err
	}
	if !sessionControlCloseTaskMatchesCleanupOwner(state.Task, *owner) {
		return nil, errSessionControlCleanupConflict
	}
	state.Owner = *owner
	if state.Task.State != sessionControlCloseTaskStateAcked || state.Task.CellID != request.CellID ||
		!sessionControlCloseTaskMatchesComplete(state.Task, *complete) {
		return nil, errSessionControlCleanupConflict
	}
	if _, _, _, err = s.readCloseTaskCompletionAuthority(opCtx, *complete, state.Task); err != nil {
		return nil, err
	}
	cleanedAt := now.UnixMilli()
	for _, candidate := range []int64{complete.CompletedAtMillis, state.Task.UpdatedAtMillis, state.Owner.UpdatedAtMillis} {
		if cleanedAt < candidate {
			cleanedAt = candidate
		}
	}
	if cleanedAt <= 0 || cleanedAt > math.MaxInt64-sessionControlFenceReplayHorizon.Milliseconds() {
		return nil, errSessionControlCleanupCorrupt
	}
	nextOwner, err := planSessionControlOwnerTaskCleanup(state.Owner, cleanedAt)
	if err != nil {
		return nil, errSessionControlCleanupCorrupt
	}
	retainUntil := cleanedAt + sessionControlFenceReplayHorizon.Milliseconds()
	if retainUntil < complete.RetainUntilMillis {
		retainUntil = complete.RetainUntilMillis
	}
	inputDigest, err := sessionControlCloseTaskCleanupInputDigest(request)
	if err != nil {
		return nil, err
	}
	audit := sessionControlCloseTaskAudit{CellID: request.CellID, EventID: request.EventID,
		OwnerPK: request.OwnerPK, ManifestIndex: state.Task.ManifestIndex, Complete: *complete,
		AckedTask: state.Task, OwnerBefore: state.Owner, OwnerAfter: nextOwner, OperationID: request.OperationID,
		OperationInputDigest: inputDigest, CleanedAtMillis: cleanedAt, RetainUntilMillis: retainUntil}
	audit.AuditDigest, err = sessionControlCloseTaskAuditDigest(audit)
	if err != nil || validateSessionControlCloseTaskAudit(audit) != nil {
		return nil, errSessionControlCleanupCorrupt
	}
	completeCondition, err := sessionControlCloseCompleteCondition(s.tableName, *complete)
	if err != nil {
		return nil, err
	}
	ownerReplace, err := sessionControlOwnerReplace(s.tableName, state.Owner, nextOwner)
	if err != nil {
		return nil, err
	}
	taskDelete, err := sessionControlCloseTaskDelete(s.tableName, state.Task)
	if err != nil {
		return nil, err
	}
	auditPut, err := sessionControlCloseTaskAuditPut(s.tableName, audit)
	if err != nil {
		return nil, err
	}
	token, err := sessionControlCloseTaskCleanupToken(s.tableName, *complete, state.Task, state.Owner, nextOwner, audit)
	if err != nil {
		return nil, err
	}
	_, writeErr := s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{ClientRequestToken: token,
		TransactItems: []types.TransactWriteItem{completeCondition, ownerReplace, taskDelete, auditPut}})
	if writeErr == nil {
		return &audit, nil
	}
	var canceled *types.TransactionCanceledException
	if errors.As(writeErr, &canceled) {
		classified, classifyErr := s.classifyCloseTaskCleanup(opCtx, request, *complete)
		if classifyErr == nil {
			return classified, nil
		}
		return nil, errSessionControlCleanupConflict
	}
	resultCtx, resultCancel := s.sessionResultContext(ctx)
	defer resultCancel()
	classified, classifyErr := s.classifyCloseTaskCleanup(resultCtx, request, *complete)
	if classifyErr == nil {
		return classified, nil
	}
	return nil, fmt.Errorf("cleanup session-control close task: %w", writeErr)
}

func (s *dynamoSessionControlStore) CleanupAckedNormalExactCloseTask(ctx context.Context,
	request sessionControlCloseTaskCleanupRequest) (*sessionControlCloseTaskAudit, error) {
	complete, err := s.getCloseComplete(ctx, request.EventID)
	if err != nil {
		return nil, err
	}
	if complete.WorkMode != sessionControlCloseWorkModeNormal {
		return nil, errSessionControlCleanupConflict
	}
	return s.CleanupAckedExactCloseTask(ctx, request)
}

func sessionControlCloseTaskSetMatchesComplete(taskSet sessionControlCloseTaskSet,
	complete sessionControlCloseComplete) bool {
	return taskSet.CellID == complete.CellID && taskSet.EventID == complete.EventID &&
		taskSet.SelectorDigest == complete.SelectorDigest && taskSet.SessionVersion == complete.SessionVersion &&
		taskSet.ExpectedTargetCount == complete.ExpectedTargetCount &&
		taskSet.PreparedDirectoryVersion == complete.PreparedDirectoryVersion &&
		taskSet.WorkMode == complete.WorkMode && taskSet.TaskSetDigest == complete.TaskSetDigest &&
		taskSet.SourceCount == complete.SourceCount && taskSet.OwnerCount == complete.OwnerCount &&
		sessionControlCleanupEqualStrings(taskSet.ManifestDigests, complete.ManifestDigests) &&
		sessionControlCleanupEqualUint64s(taskSet.ManifestSourceCounts, complete.ChunkSourceCounts) &&
		sessionControlCleanupEqualUint64s(taskSet.ManifestOwnerCounts, complete.ChunkOwnerCounts)
}

func sessionControlCleanupEqualStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sessionControlCleanupEqualUint64s(left, right []uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sessionControlCloseTaskMatchesCompletedRef(task sessionControlCloseTask,
	complete sessionControlCloseComplete, taskSet sessionControlCloseTaskSet,
	manifest sessionControlCloseManifest, chunk sessionControlCloseAckChunk,
	ref sessionControlCloseTaskRef) bool {
	return sessionControlCloseTaskMatchesRef(task, manifest, ref) &&
		sessionControlCloseCompleteMatchesTaskAuthority(complete, taskSet, manifest, chunk, task)
}

func (s *dynamoSessionControlStore) readCompletedCloseTaskRef(ctx context.Context,
	complete sessionControlCloseComplete, taskSet sessionControlCloseTaskSet,
	manifest sessionControlCloseManifest, chunk sessionControlCloseAckChunk,
	ref sessionControlCloseTaskRef) (sessionControlCompletedCloseTaskItem, error) {
	first, firstErr := s.getCloseTask(ctx, ref.OwnerPK, complete.EventID)
	if firstErr != nil && !errors.Is(firstErr, errSessionControlCloseTaskNotFound) {
		return sessionControlCompletedCloseTaskItem{}, firstErr
	}
	audit, auditErr := s.getCloseTaskAudit(ctx, ref.OwnerPK, complete.EventID)
	if auditErr != nil && !errors.Is(auditErr, errSessionControlCleanupNotFound) {
		return sessionControlCompletedCloseTaskItem{}, auditErr
	}
	second, secondErr := s.getCloseTask(ctx, ref.OwnerPK, complete.EventID)
	if secondErr != nil && !errors.Is(secondErr, errSessionControlCloseTaskNotFound) {
		return sessionControlCompletedCloseTaskItem{}, secondErr
	}
	firstExists, secondExists := firstErr == nil, secondErr == nil
	auditExists := auditErr == nil
	if firstExists && secondExists {
		if *first != *second || auditExists ||
			!sessionControlCloseTaskMatchesCompletedRef(*second, complete, taskSet, manifest, chunk, ref) {
			return sessionControlCompletedCloseTaskItem{}, errSessionControlCleanupCorrupt
		}
		return sessionControlCompletedCloseTaskItem{OwnerPK: ref.OwnerPK, Task: second}, nil
	}
	// Cleanup atomically deletes TASK and creates TASKAUDIT. A transition
	// between the two TASK reads is valid only when the intervening audit is
	// the exact committed replacement.
	if firstExists && secondExists != firstExists && !auditExists {
		return sessionControlCompletedCloseTaskItem{}, errSessionControlCleanupConflict
	}
	if secondExists || !auditExists ||
		!sessionControlCloseTaskAuditMatchesRequest(*audit, sessionControlCloseTaskCleanupRequest{
			CellID: audit.CellID, EventID: audit.EventID, OwnerPK: audit.OwnerPK, OperationID: audit.OperationID,
		}, complete) ||
		!sessionControlCloseTaskMatchesCompletedRef(audit.AckedTask, complete, taskSet, manifest, chunk, ref) {
		return sessionControlCompletedCloseTaskItem{}, errSessionControlCleanupCorrupt
	}
	return sessionControlCompletedCloseTaskItem{OwnerPK: ref.OwnerPK, Audit: audit}, nil
}

func clampSessionControlCloseCleanupPageLimit(limit int32) int32 {
	if limit <= 0 || limit > sessionControlCloseCleanupPageLimit {
		return sessionControlCloseCleanupPageLimit
	}
	return limit
}

func (s *dynamoSessionControlStore) validateCompletedCloseTaskCursor(ctx context.Context,
	taskSet sessionControlCloseTaskSet, complete sessionControlCloseComplete,
	cursor *sessionControlCompletedCloseTaskCursor) error {
	if cursor == nil {
		return nil
	}
	if cursor.CellID != complete.CellID || cursor.EventID != complete.EventID ||
		cursor.CompleteDigest != complete.CompleteDigest || len(complete.ManifestDigests) == 0 ||
		cursor.ManifestIndex >= uint64(len(complete.ManifestDigests)) {
		return errors.New("invalid completed session-control close task cursor")
	}
	var expectedOwners, expectedSources uint64
	for index := uint64(0); index < cursor.ManifestIndex; index++ {
		owners, sources := taskSet.ManifestOwnerCounts[index], taskSet.ManifestSourceCounts[index]
		if expectedOwners > math.MaxUint64-owners || expectedSources > math.MaxUint64-sources {
			return errSessionControlCleanupCorrupt
		}
		expectedOwners += owners
		expectedSources += sources
	}
	manifest, err := s.getCloseManifest(ctx, complete.EventID, cursor.ManifestIndex)
	if err != nil {
		if errors.Is(err, errSessionControlSessionNotFound) || errors.Is(err, errSessionControlMaterializationCorrupt) {
			return errSessionControlCleanupCorrupt
		}
		return err
	}
	if manifest.ManifestDigest != complete.ManifestDigests[cursor.ManifestIndex] ||
		cursor.RefIndex >= uint64(len(manifest.Refs)) {
		return errors.New("invalid completed session-control close task cursor")
	}
	for _, ref := range manifest.Refs[:cursor.RefIndex] {
		if expectedOwners == math.MaxUint64 || expectedSources > math.MaxUint64-ref.SourceCount {
			return errSessionControlCleanupCorrupt
		}
		expectedOwners++
		expectedSources += ref.SourceCount
	}
	if cursor.SeenOwners != expectedOwners || cursor.SeenSources != expectedSources {
		return errors.New("invalid completed session-control close task cursor")
	}
	return nil
}

// ListCompletedNormalExactCloseTasksPage walks the immutable TASKSET manifest
// inventory. Each committed reference must resolve, under strong reads, to
// exactly one terminal TASK or its immutable TASKAUDIT replacement. The
// cursor carries exact COMPLETE identity and cumulative parity so a terminal
// page cannot silently omit committed authority.
func (s *dynamoSessionControlStore) ListCompletedExactCloseTasksPage(ctx context.Context,
	cellID, eventID string, cursor *sessionControlCompletedCloseTaskCursor,
	limit int32) (*sessionControlCompletedCloseTaskPage, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlCellID(cellID) || !validSessionControlFenceEventID(eventID) {
		return nil, errors.New("invalid completed session-control close task page request")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	complete, err := s.getCloseComplete(opCtx, eventID)
	if err != nil {
		return nil, err
	}
	if complete.CellID != cellID || !validSessionControlExactCloseWorkMode(complete.WorkMode) {
		return nil, errSessionControlCleanupConflict
	}
	taskSet, err := s.getCloseTaskSet(opCtx, eventID)
	if err != nil {
		if errors.Is(err, errSessionControlSessionNotFound) || errors.Is(err, errSessionControlMaterializationCorrupt) {
			return nil, errSessionControlCleanupCorrupt
		}
		return nil, err
	}
	if !sessionControlCloseTaskSetMatchesComplete(*taskSet, *complete) {
		return nil, errSessionControlCleanupCorrupt
	}
	manifestIndex, refIndex, seenOwners, seenSources := uint64(0), uint64(0), uint64(0), uint64(0)
	if cursor != nil {
		if err = s.validateCompletedCloseTaskCursor(opCtx, *taskSet, *complete, cursor); err != nil {
			return nil, err
		}
		manifestIndex, refIndex = cursor.ManifestIndex, cursor.RefIndex
		seenOwners, seenSources = cursor.SeenOwners, cursor.SeenSources
	}
	page := &sessionControlCompletedCloseTaskPage{}
	pageLimit := int(clampSessionControlCloseCleanupPageLimit(limit))
	for manifestIndex < uint64(len(complete.ManifestDigests)) {
		manifest, readErr := s.getCloseManifest(opCtx, eventID, manifestIndex)
		if readErr != nil {
			if errors.Is(readErr, errSessionControlSessionNotFound) ||
				errors.Is(readErr, errSessionControlMaterializationCorrupt) {
				return nil, errSessionControlCleanupCorrupt
			}
			return nil, readErr
		}
		if manifest.ManifestDigest != complete.ManifestDigests[manifestIndex] {
			return nil, errSessionControlCleanupCorrupt
		}
		chunk, readErr := s.getCloseAckChunk(opCtx, eventID, manifestIndex)
		if readErr != nil {
			if errors.Is(readErr, errSessionControlCompletionNotFound) ||
				errors.Is(readErr, errSessionControlCompletionCorrupt) {
				return nil, errSessionControlCleanupCorrupt
			}
			return nil, readErr
		}
		if chunk.ChunkDigest != complete.ChunkDigests[manifestIndex] ||
			chunk.ManifestDigest != manifest.ManifestDigest ||
			uint64(len(manifest.Refs)) != complete.ChunkOwnerCounts[manifestIndex] {
			return nil, errSessionControlCleanupCorrupt
		}
		if refIndex >= uint64(len(manifest.Refs)) {
			return nil, errors.New("invalid completed session-control close task cursor")
		}
		for refIndex < uint64(len(manifest.Refs)) {
			ref := manifest.Refs[refIndex]
			if seenOwners >= complete.OwnerCount || seenSources > complete.SourceCount-ref.SourceCount {
				return nil, errSessionControlCleanupCorrupt
			}
			item, readErr := s.readCompletedCloseTaskRef(opCtx, *complete, *taskSet, *manifest, *chunk, ref)
			if readErr != nil {
				return nil, readErr
			}
			page.Items = append(page.Items, item)
			seenOwners++
			seenSources += ref.SourceCount
			refIndex++
			if len(page.Items) == pageLimit {
				if refIndex == uint64(len(manifest.Refs)) {
					manifestIndex++
					refIndex = 0
				}
				if manifestIndex < uint64(len(complete.ManifestDigests)) {
					page.Next = &sessionControlCompletedCloseTaskCursor{CellID: cellID, EventID: eventID,
						CompleteDigest: complete.CompleteDigest, ManifestIndex: manifestIndex, RefIndex: refIndex,
						SeenOwners: seenOwners, SeenSources: seenSources}
				} else if seenOwners != complete.OwnerCount || seenSources != complete.SourceCount {
					return nil, errSessionControlCleanupCorrupt
				}
				return page, nil
			}
		}
		manifestIndex++
		refIndex = 0
	}
	if seenOwners != complete.OwnerCount || seenSources != complete.SourceCount {
		return nil, errSessionControlCleanupCorrupt
	}
	return page, nil
}

func (s *dynamoSessionControlStore) ListCompletedNormalExactCloseTasksPage(ctx context.Context,
	cellID, eventID string, cursor *sessionControlCompletedCloseTaskCursor,
	limit int32) (*sessionControlCompletedCloseTaskPage, error) {
	complete, err := s.getCloseComplete(ctx, eventID)
	if err != nil {
		return nil, err
	}
	if complete.WorkMode != sessionControlCloseWorkModeNormal {
		return nil, errSessionControlCleanupConflict
	}
	return s.ListCompletedExactCloseTasksPage(ctx, cellID, eventID, cursor, limit)
}
