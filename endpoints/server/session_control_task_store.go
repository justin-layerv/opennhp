package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/OpenNHP/opennhp/nhp/common"
)

const (
	sessionControlCloseTaskLeaseDuration = 30 * time.Second
	sessionControlCloseTaskPageLimit     = int32(100)
)

var (
	errSessionControlCloseTaskNotFound = errors.New("session-control close task not found")
	errSessionControlCloseTaskConflict = errors.New("session-control close task changed concurrently")
	errSessionControlCloseTaskCorrupt  = errors.New("session-control close task authority is malformed")
	errSessionControlCloseTaskBusy     = errors.New("session-control close task lease is active")
)

type sessionControlCloseTaskDueCursor struct {
	CellID           string
	Shard            uint64
	DueThroughMillis int64
	LastKey          map[string]types.AttributeValue
}

type sessionControlCloseTaskDuePage struct {
	Tasks []sessionControlCloseTask
	Next  *sessionControlCloseTaskDueCursor
}

type sessionControlCommittedCloseTaskCursor struct {
	CellID        string
	EventID       string
	WorkMode      string
	TaskSetDigest string
	ManifestIndex uint64
	RefIndex      uint64
	Directory     sessionControlTargetDirectoryFence
}

type sessionControlCommittedCloseTaskPage struct {
	Tasks     []sessionControlCloseTask
	Directory *sessionControlTargetDirectoryFence
	Next      *sessionControlCommittedCloseTaskCursor
}

type sessionControlCloseTaskLeaseRequest struct {
	CellID      string
	EventID     string
	OwnerPK     string
	OperationID string
	LeaseID     string
	LeaseOwner  string
}

type sessionControlCloseTaskRebindRequest struct {
	CellID      string
	EventID     string
	OwnerPK     string
	OperationID string
	Target      sessionControlTargetAuthority
}

type sessionControlCloseTaskAckRequest struct {
	Lease                  sessionControlCloseTaskLeaseRequest
	AuthenticatedPublicKey string
	Ack                    common.ACSessionCloseAckMsg
}

type sessionControlCommittedTaskState struct {
	Task      sessionControlCloseTask
	TaskSet   sessionControlCloseTaskSet
	Manifest  sessionControlCloseManifest
	Work      sessionControlCloseWork
	Owner     sessionControlOwnerAuthority
	Directory *sessionControlFenceDirectory
}

func validSessionControlTaskCanonicalID(value string) bool {
	return validSessionControlFenceEventID(value)
}

func validSessionControlTaskOperationID(value string) bool {
	return validSessionControlTaskCanonicalID(value)
}

func validSessionControlTaskLeaseID(value string) bool {
	return validSessionControlTaskCanonicalID(value)
}

func validSessionControlTaskLeaseOwner(value string) bool {
	return validSessionControlTaskCanonicalID(value)
}

func validSessionControlTaskInputDigest(value string) bool {
	return len(value) == 64 && value == strings.ToLower(value) && func() bool {
		for _, c := range value {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
		return true
	}()
}

func sessionControlCloseTaskOperationInputDigest(action string,
	request sessionControlCloseTaskLeaseRequest) (string, error) {
	return sessionControlMaterializationDigest(struct {
		Version     uint64
		Action      string
		CellID      string
		EventID     string
		OwnerPK     string
		OperationID string
		LeaseID     string
		LeaseOwner  string
	}{1, action, request.CellID, request.EventID, request.OwnerPK,
		request.OperationID, request.LeaseID, request.LeaseOwner})
}

func validSessionControlCloseTaskLeaseRequest(request sessionControlCloseTaskLeaseRequest) bool {
	return validSessionControlCellID(request.CellID) && validSessionControlFenceEventID(request.EventID) &&
		validSessionControlOwnerPK(request.OwnerPK) && validSessionControlTaskOperationID(request.OperationID) &&
		validSessionControlTaskLeaseID(request.LeaseID) && validSessionControlTaskLeaseOwner(request.LeaseOwner)
}

func sessionControlCloseTaskShardForCell(cellID string, shard uint64) (string, error) {
	if !validSessionControlCellID(cellID) || shard >= sessionControlCloseDueShardCount {
		return "", errors.New("invalid session-control close task shard")
	}
	return fmt.Sprintf("CLOSETASK#%s#%02d", cellID, shard), nil
}

func clampSessionControlCloseTaskPageLimit(limit int32) int32 {
	if limit <= 0 || limit > sessionControlCloseTaskPageLimit {
		return sessionControlCloseTaskPageLimit
	}
	return limit
}

func sessionControlCloseTaskDueCursorPosition(key map[string]types.AttributeValue, cellID string,
	shard uint64, dueThroughMillis int64,
) (string, bool) {
	pk, pkOK := key["pk"].(*types.AttributeValueMemberS)
	sk, skOK := key["sk"].(*types.AttributeValueMemberS)
	dueShard, shardOK := key["due_shard"].(*types.AttributeValueMemberS)
	dueSort, sortOK := key["due_sort"].(*types.AttributeValueMemberS)
	wantShard, err := sessionControlCloseTaskShardForCell(cellID, shard)
	if err != nil || !pkOK || !skOK || !shardOK || !sortOK || dueShard.Value != wantShard ||
		!validSessionControlOwnerPK(pk.Value) || !strings.HasPrefix(sk.Value, sessionControlCloseTaskSKPrefix) ||
		len(dueSort.Value) < 19+1+32+1 || dueSort.Value[19] != '#' {
		return "", false
	}
	eventID := strings.TrimPrefix(sk.Value, sessionControlCloseTaskSKPrefix)
	deadline, err := strconv.ParseInt(dueSort.Value[:19], 10, 64)
	if err != nil || deadline <= 0 || deadline > dueThroughMillis || !validSessionControlFenceEventID(eventID) ||
		dueSort.Value != sessionControlSessionIssuedText(deadline)+"#"+eventID+"#"+pk.Value {
		return "", false
	}
	probe := sessionControlCloseTask{CellID: cellID, EventID: eventID, OwnerPK: pk.Value}
	if sessionControlCloseTaskDueShard(probe) != wantShard {
		return "", false
	}
	return dueSort.Value + "#" + pk.Value + "#" + sk.Value, true
}

func (s *dynamoSessionControlStore) getCloseTask(ctx context.Context, ownerPK, eventID string) (*sessionControlCloseTask, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true),
		Key: sessionControlCloseTaskKey(ownerPK, eventID),
	})
	if err != nil {
		return nil, fmt.Errorf("session-control close task strong read: %w", err)
	}
	task, err := sessionControlCloseTaskFromItem(result.Item, ownerPK, eventID)
	if errors.Is(err, errSessionControlSessionNotFound) {
		return nil, errSessionControlCloseTaskNotFound
	}
	if err != nil {
		if errors.Is(err, errSessionControlMaterializationCorrupt) {
			return nil, errSessionControlCloseTaskCorrupt
		}
		return nil, err
	}
	return &task, nil
}

func sessionControlCloseTaskMatchesCommit(task sessionControlCloseTask, taskSet sessionControlCloseTaskSet,
	manifest sessionControlCloseManifest, work sessionControlCloseWork) bool {
	if !validSessionControlExactCloseWorkMode(task.WorkMode) || taskSet.WorkMode != task.WorkMode ||
		manifest.WorkMode != task.WorkMode || work.Mode != task.WorkMode ||
		task.CellID != taskSet.CellID || task.CellID != manifest.CellID || task.CellID != work.CellID ||
		task.EventID != taskSet.EventID || task.EventID != manifest.EventID || task.EventID != work.EventID ||
		task.SelectorDigest != taskSet.SelectorDigest || task.SelectorDigest != manifest.SelectorDigest ||
		task.SelectorDigest != work.SelectorDigest || task.SessionVersion != taskSet.SessionVersion ||
		task.SessionVersion != manifest.SessionVersion || task.SessionVersion != work.SessionVersion ||
		task.ExpectedTargetCount != taskSet.ExpectedTargetCount ||
		task.ExpectedTargetCount != manifest.ExpectedTargetCount ||
		task.ExpectedTargetCount != work.ExpectedTargetCount ||
		task.PreparedDirectoryVersion != taskSet.PreparedDirectoryVersion ||
		task.PreparedDirectoryVersion != manifest.PreparedDirectoryVersion ||
		task.PreparedDirectoryVersion != work.PreparedDirectoryVersion ||
		task.ManifestIndex != manifest.ManifestIndex || task.ManifestIndex >= uint64(len(taskSet.ManifestDigests)) ||
		taskSet.ManifestDigests[task.ManifestIndex] != manifest.ManifestDigest ||
		taskSet.ManifestOwnerCounts[task.ManifestIndex] != uint64(len(manifest.Refs)) {
		return false
	}
	var sourceCount uint64
	found := false
	for _, ref := range manifest.Refs {
		if sourceCount > math.MaxUint64-ref.SourceCount {
			return false
		}
		sourceCount += ref.SourceCount
		if ref.OwnerPK == task.OwnerPK {
			if found || ref.CreationDigest != task.CreationDigest || ref.SourceDigest != task.SourceDigest ||
				ref.SourceCount != task.SourceCount {
				return false
			}
			found = true
		}
	}
	return found && sourceCount == taskSet.ManifestSourceCounts[task.ManifestIndex]
}

func sessionControlCloseTaskMatchesOwner(task sessionControlCloseTask, owner sessionControlOwnerAuthority) bool {
	if owner.CellID != task.CellID || owner.ACID != task.ACID || owner.PublicKey != task.PublicKey ||
		owner.WorkVersion < task.CurrentOwnerWorkVersion || owner.Phase == sessionControlOwnerRetired ||
		owner.TaskCount == 0 || (task.State != sessionControlCloseTaskStateAcked && owner.PendingCount == 0) ||
		owner.BootID != task.BoundBootID || owner.FlushGeneration != task.BoundFlushGeneration ||
		owner.TargetVersion != task.BoundTargetVersion || owner.TargetAuthorityVersion != task.BoundAuthorityVersion ||
		owner.LifecycleVersion != task.BoundOwnerLifecycle ||
		owner.ActivatedControlVersion != task.BoundActivatedCursor || owner.ReadyControlVersion != task.BoundReadyCursor {
		return false
	}
	if owner.WorkVersion == task.CurrentOwnerWorkVersion &&
		(owner.TaskCount != task.CurrentOwnerTaskCount || owner.PendingCount != task.CurrentOwnerPendingCount) {
		return false
	}
	return true
}

func (s *dynamoSessionControlStore) readCommittedCloseTask(ctx context.Context,
	ownerPK, eventID string) (*sessionControlCommittedTaskState, error) {
	task, err := s.getCloseTask(ctx, ownerPK, eventID)
	if err != nil {
		return nil, err
	}
	taskSet, err := s.getCloseTaskSet(ctx, eventID)
	if errors.Is(err, errSessionControlSessionNotFound) {
		return nil, errSessionControlCloseTaskNotFound
	}
	if err != nil {
		if errors.Is(err, errSessionControlMaterializationCorrupt) {
			return nil, errSessionControlCloseTaskCorrupt
		}
		return nil, err
	}
	if task.ManifestIndex >= uint64(len(taskSet.ManifestDigests)) {
		return nil, errSessionControlCloseTaskCorrupt
	}
	manifest, err := s.getCloseManifest(ctx, eventID, task.ManifestIndex)
	if err != nil {
		if errors.Is(err, errSessionControlSessionNotFound) || errors.Is(err, errSessionControlMaterializationCorrupt) {
			return nil, errSessionControlCloseTaskCorrupt
		}
		return nil, err
	}
	overflow := task.WorkMode == sessionControlCloseWorkModeOverflow
	work, err := s.getCloseWork(ctx, task.CellID, eventID, overflow)
	if err != nil {
		if errors.Is(err, errSessionControlSessionNotFound) || errors.Is(err, errSessionControlCloseCorrupt) {
			return nil, errSessionControlCloseTaskCorrupt
		}
		return nil, err
	}
	if !sessionControlCloseTaskMatchesCommit(*task, *taskSet, *manifest, *work) {
		return nil, errSessionControlCloseTaskCorrupt
	}
	state := &sessionControlCommittedTaskState{Task: *task, TaskSet: *taskSet, Manifest: *manifest, Work: *work}
	if overflow {
		directory, directoryErr := s.getFenceDirectory(ctx, task.CellID)
		if directoryErr != nil {
			return nil, directoryErr
		}
		if !sessionControlOverflowLeaderMatchesWork(*directory, *work) {
			return nil, errSessionControlCloseTaskConflict
		}
		state.Directory = directory
	}
	return state, nil
}

func (s *dynamoSessionControlStore) bindCommittedCloseTaskOwner(ctx context.Context,
	state *sessionControlCommittedTaskState) error {
	owner, err := s.getOwner(ctx, state.Task.CellID, state.Task.ACID, state.Task.PublicKey)
	if err != nil {
		if errors.Is(err, errSessionControlOwnerNotFound) {
			return errSessionControlCloseTaskConflict
		}
		return err
	}
	if !sessionControlCloseTaskMatchesOwner(state.Task, *owner) {
		return errSessionControlCloseTaskConflict
	}
	state.Owner = *owner
	return nil
}

// ListDueExactCloseTasksPage uses the eventual due index only for bounded
// discovery. Every hit is strong-read and admitted only through its committed
// TASKSET, indexed MANIFEST, exact immutable ref, mode-aware WORK, selected
// overflow leader when applicable, and current
// owner. Missing base rows and pre-TASKSET rows are harmless stale discovery;
// every existing malformed authority fails closed.
func (s *dynamoSessionControlStore) ListDueExactCloseTasksPage(ctx context.Context, cellID string,
	shard uint64, dueThroughMillis int64, cursor *sessionControlCloseTaskDueCursor,
	limit int32) (*sessionControlCloseTaskDuePage, error) {
	return s.listDueExactCloseTasksPage(ctx, cellID, shard, dueThroughMillis, cursor, limit, "")
}

func (s *dynamoSessionControlStore) listDueExactCloseTasksPage(ctx context.Context, cellID string,
	shard uint64, dueThroughMillis int64, cursor *sessionControlCloseTaskDueCursor,
	limit int32, expectedMode string) (*sessionControlCloseTaskDuePage, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	dueShard, err := sessionControlCloseTaskShardForCell(cellID, shard)
	if err != nil || dueThroughMillis <= 0 ||
		(expectedMode != "" && !validSessionControlExactCloseWorkMode(expectedMode)) {
		return nil, errors.New("invalid session-control close task due scan")
	}
	var lastKey map[string]types.AttributeValue
	lastPosition := ""
	if cursor != nil {
		if cursor.CellID != cellID || cursor.Shard != shard || cursor.DueThroughMillis != dueThroughMillis ||
			len(cursor.LastKey) == 0 {
			return nil, errors.New("invalid session-control close task due cursor")
		}
		var valid bool
		lastPosition, valid = sessionControlCloseTaskDueCursorPosition(cursor.LastKey, cellID, shard, dueThroughMillis)
		if !valid {
			return nil, errors.New("invalid session-control close task due cursor")
		}
		lastKey = cursor.LastKey
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	result, err := s.client.Query(opCtx, &dynamodb.QueryInput{
		TableName: aws.String(s.tableName), IndexName: aws.String(sessionControlDueIndexName),
		KeyConditionExpression: aws.String("due_shard = :shard AND due_sort <= :through"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":shard":   &types.AttributeValueMemberS{Value: dueShard},
			":through": &types.AttributeValueMemberS{Value: sessionControlSessionIssuedText(dueThroughMillis) + "#\uffff"},
		},
		ExclusiveStartKey: lastKey, Limit: aws.Int32(clampSessionControlCloseTaskPageLimit(limit)),
	})
	if err != nil {
		return nil, fmt.Errorf("session-control close task due discovery: %w", err)
	}
	page := &sessionControlCloseTaskDuePage{Tasks: make([]sessionControlCloseTask, 0, len(result.Items))}
	for _, projected := range result.Items {
		pk, pkOK := projected["pk"].(*types.AttributeValueMemberS)
		sk, skOK := projected["sk"].(*types.AttributeValueMemberS)
		if !pkOK || !skOK || !validSessionControlOwnerPK(pk.Value) ||
			!strings.HasPrefix(sk.Value, sessionControlCloseTaskSKPrefix) {
			return nil, errSessionControlCloseTaskCorrupt
		}
		eventID := strings.TrimPrefix(sk.Value, sessionControlCloseTaskSKPrefix)
		if !validSessionControlFenceEventID(eventID) {
			return nil, errSessionControlCloseTaskCorrupt
		}
		committed, readErr := s.readCommittedCloseTask(opCtx, pk.Value, eventID)
		if errors.Is(readErr, errSessionControlCloseTaskNotFound) {
			continue
		}
		if readErr != nil {
			return nil, readErr
		}
		if (expectedMode == "" || committed.Task.WorkMode == expectedMode) &&
			committed.Task.CellID == cellID && committed.Task.DueAtMillis <= dueThroughMillis &&
			committed.Task.DueShard == dueShard {
			page.Tasks = append(page.Tasks, committed.Task)
		}
	}
	if len(result.LastEvaluatedKey) != 0 {
		nextPosition, valid := sessionControlCloseTaskDueCursorPosition(result.LastEvaluatedKey, cellID, shard,
			dueThroughMillis)
		if !valid || (lastPosition != "" && nextPosition <= lastPosition) {
			return nil, errSessionControlCloseTaskCorrupt
		}
		page.Next = &sessionControlCloseTaskDueCursor{CellID: cellID, Shard: shard,
			DueThroughMillis: dueThroughMillis, LastKey: result.LastEvaluatedKey}
	}
	return page, nil
}

func (s *dynamoSessionControlStore) ListDueNormalExactCloseTasksPage(ctx context.Context, cellID string,
	shard uint64, dueThroughMillis int64, cursor *sessionControlCloseTaskDueCursor,
	limit int32) (*sessionControlCloseTaskDuePage, error) {
	return s.listDueExactCloseTasksPage(ctx, cellID, shard, dueThroughMillis, cursor, limit,
		sessionControlCloseWorkModeNormal)
}

// ListCommittedExactCloseTasksPage is the base-table recovery path for a
// due-index omission. TASKSET and MANIFEST rows enumerate every committed task;
// a missing referenced task is corruption because TASKSET is the commit point.
// Overflow pages additionally bracket and bind the exact selected leader so a
// cursor cannot resume under a different CONTROL authority.
func (s *dynamoSessionControlStore) ListCommittedExactCloseTasksPage(ctx context.Context, cellID, eventID string,
	cursor *sessionControlCommittedCloseTaskCursor, limit int32) (*sessionControlCommittedCloseTaskPage, error) {
	return s.listCommittedExactCloseTasksPage(ctx, cellID, eventID, "", cursor, limit)
}

func (s *dynamoSessionControlStore) listCommittedExactCloseTasksPage(ctx context.Context, cellID, eventID,
	expectedMode string, cursor *sessionControlCommittedCloseTaskCursor,
	limit int32) (*sessionControlCommittedCloseTaskPage, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlCellID(cellID) || !validSessionControlFenceEventID(eventID) ||
		(expectedMode != "" && !validSessionControlExactCloseWorkMode(expectedMode)) {
		return nil, errors.New("invalid committed session-control close task scan")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	taskSet, err := s.getCloseTaskSet(opCtx, eventID)
	if errors.Is(err, errSessionControlSessionNotFound) {
		return &sessionControlCommittedCloseTaskPage{Tasks: []sessionControlCloseTask{}}, nil
	}
	if err != nil {
		if errors.Is(err, errSessionControlMaterializationCorrupt) {
			return nil, errSessionControlCloseTaskCorrupt
		}
		return nil, err
	}
	if taskSet.CellID != cellID || !validSessionControlExactCloseWorkMode(taskSet.WorkMode) ||
		(expectedMode != "" && taskSet.WorkMode != expectedMode) {
		return nil, errSessionControlCloseTaskCorrupt
	}
	overflow := taskSet.WorkMode == sessionControlCloseWorkModeOverflow
	work, err := s.getCloseWork(opCtx, cellID, eventID, overflow)
	if err != nil {
		if errors.Is(err, errSessionControlSessionNotFound) || errors.Is(err, errSessionControlCloseCorrupt) {
			return nil, errSessionControlCloseTaskCorrupt
		}
		return nil, err
	}
	if work.Mode != taskSet.WorkMode || work.SelectorDigest != taskSet.SelectorDigest ||
		work.SessionVersion != taskSet.SessionVersion || work.ExpectedTargetCount != taskSet.ExpectedTargetCount ||
		work.PreparedDirectoryVersion != taskSet.PreparedDirectoryVersion {
		return nil, errSessionControlCloseTaskCorrupt
	}
	var directorySnapshot *sessionControlTargetDirectoryFence
	if overflow {
		directory, directoryErr := s.getFenceDirectory(opCtx, cellID)
		if directoryErr != nil {
			return nil, directoryErr
		}
		if !sessionControlOverflowLeaderMatchesWork(*directory, *work) {
			return nil, errSessionControlCloseTaskConflict
		}
		snapshot := sessionControlCloseDirectoryCursor(*directory)
		directorySnapshot = &snapshot
	}
	manifestIndex, refIndex := uint64(0), uint64(0)
	if cursor != nil {
		if cursor.CellID != cellID || cursor.EventID != eventID || cursor.WorkMode != taskSet.WorkMode ||
			cursor.TaskSetDigest != taskSet.TaskSetDigest ||
			cursor.ManifestIndex >= uint64(len(taskSet.ManifestDigests)) ||
			(overflow && (directorySnapshot == nil || cursor.Directory != *directorySnapshot)) ||
			(!overflow && cursor.Directory != (sessionControlTargetDirectoryFence{})) {
			return nil, errSessionControlCloseTaskConflict
		}
		manifestIndex, refIndex = cursor.ManifestIndex, cursor.RefIndex
	}
	page := &sessionControlCommittedCloseTaskPage{Tasks: make([]sessionControlCloseTask, 0, clampSessionControlCloseTaskPageLimit(limit)),
		Directory: directorySnapshot}
	want := int(clampSessionControlCloseTaskPageLimit(limit))
	for manifestIndex < uint64(len(taskSet.ManifestDigests)) && len(page.Tasks) < want {
		manifest, manifestErr := s.getCloseManifest(opCtx, eventID, manifestIndex)
		if manifestErr != nil {
			if errors.Is(manifestErr, errSessionControlSessionNotFound) ||
				errors.Is(manifestErr, errSessionControlMaterializationCorrupt) {
				return nil, errSessionControlCloseTaskCorrupt
			}
			return nil, manifestErr
		}
		if manifest.ManifestDigest != taskSet.ManifestDigests[manifestIndex] ||
			uint64(len(manifest.Refs)) != taskSet.ManifestOwnerCounts[manifestIndex] || refIndex > uint64(len(manifest.Refs)) {
			return nil, errSessionControlCloseTaskCorrupt
		}
		for refIndex < uint64(len(manifest.Refs)) && len(page.Tasks) < want {
			ref := manifest.Refs[refIndex]
			committed, readErr := s.readCommittedCloseTask(opCtx, ref.OwnerPK, eventID)
			if readErr != nil {
				if errors.Is(readErr, errSessionControlCloseTaskNotFound) {
					return nil, errSessionControlCloseTaskCorrupt
				}
				return nil, readErr
			}
			if committed.Task.ManifestIndex != manifestIndex || committed.Task.CreationDigest != ref.CreationDigest ||
				committed.Task.SourceDigest != ref.SourceDigest || committed.Task.SourceCount != ref.SourceCount ||
				committed.Task.WorkMode != taskSet.WorkMode ||
				(overflow && (committed.Directory == nil || directorySnapshot == nil ||
					sessionControlCloseDirectoryCursor(*committed.Directory) != *directorySnapshot)) {
				return nil, errSessionControlCloseTaskCorrupt
			}
			page.Tasks = append(page.Tasks, committed.Task)
			refIndex++
		}
		if refIndex == uint64(len(manifest.Refs)) {
			manifestIndex++
			refIndex = 0
		}
	}
	if overflow {
		after, afterErr := s.getFenceDirectory(opCtx, cellID)
		if afterErr != nil {
			return nil, afterErr
		}
		if directorySnapshot == nil || sessionControlCloseDirectoryCursor(*after) != *directorySnapshot ||
			!sessionControlOverflowLeaderMatchesWork(*after, *work) {
			return nil, errSessionControlCloseTaskConflict
		}
	}
	if manifestIndex < uint64(len(taskSet.ManifestDigests)) {
		page.Next = &sessionControlCommittedCloseTaskCursor{CellID: cellID, EventID: eventID,
			WorkMode: taskSet.WorkMode, TaskSetDigest: taskSet.TaskSetDigest,
			ManifestIndex: manifestIndex, RefIndex: refIndex}
		if directorySnapshot != nil {
			page.Next.Directory = *directorySnapshot
		}
	}
	return page, nil
}

func (s *dynamoSessionControlStore) ListCommittedNormalExactCloseTasksPage(ctx context.Context, cellID, eventID string,
	cursor *sessionControlCommittedCloseTaskCursor, limit int32) (*sessionControlCommittedCloseTaskPage, error) {
	return s.listCommittedExactCloseTasksPage(ctx, cellID, eventID, sessionControlCloseWorkModeNormal, cursor, limit)
}

func planSessionControlOwnerTaskLeaseTransition(current sessionControlOwnerAuthority,
	updatedAtMillis int64) (sessionControlOwnerAuthority, error) {
	if validateSessionControlOwnerAuthority(current) != nil || current.Phase == sessionControlOwnerRetired ||
		current.TaskCount == 0 || current.PendingCount == 0 || current.WorkVersion >= math.MaxUint64-1 {
		return sessionControlOwnerAuthority{}, errSessionControlCloseTaskCorrupt
	}
	next := current
	next.WorkVersion++
	if updatedAtMillis > next.UpdatedAtMillis {
		next.UpdatedAtMillis = updatedAtMillis
	}
	if validateSessionControlOwnerAuthority(next) != nil {
		return sessionControlOwnerAuthority{}, errSessionControlCloseTaskCorrupt
	}
	return next, nil
}

func sessionControlCloseTaskReplace(tableName string, current, next sessionControlCloseTask) (types.TransactWriteItem, error) {
	currentRow, err := sessionControlCloseTaskToRow(current)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	nextRow, err := sessionControlCloseTaskToRow(next)
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
	condition, names, values := sessionControlExactItemCondition(currentItem, "lease_id", "lease_owner", "lease_expires_at_ms")
	return types.TransactWriteItem{Put: &types.Put{TableName: aws.String(tableName), Item: nextItem,
		ConditionExpression: aws.String(condition), ExpressionAttributeNames: names,
		ExpressionAttributeValues: values}}, nil
}

func sessionControlCloseTaskSetCondition(tableName string, taskSet sessionControlCloseTaskSet) (types.TransactWriteItem, error) {
	row, err := sessionControlCloseTaskSetToRow(taskSet)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	condition, names, values := sessionControlExactItemCondition(item)
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{TableName: aws.String(tableName),
		Key: sessionControlCloseTaskSetKey(taskSet.EventID), ConditionExpression: aws.String(condition),
		ExpressionAttributeNames: names, ExpressionAttributeValues: values}}, nil
}

func sessionControlCloseTaskTransitionToken(tableName, action string, state sessionControlCommittedTaskState,
	nextTask sessionControlCloseTask, nextOwner sessionControlOwnerAuthority) (*string, error) {
	digest, err := sessionControlMaterializationDigest(struct {
		Version   uint64
		TableName string
		Action    string
		Current   sessionControlCloseTask
		Next      sessionControlCloseTask
		Owner     sessionControlOwnerAuthority
		NextOwner sessionControlOwnerAuthority
		TaskSet   sessionControlCloseTaskSet
		Manifest  sessionControlCloseManifest
		Work      sessionControlCloseWork
		Directory *sessionControlFenceDirectory
	}{1, tableName, action, state.Task, nextTask, state.Owner, nextOwner, state.TaskSet, state.Manifest,
		state.Work, state.Directory})
	if err != nil {
		return nil, err
	}
	return aws.String("sc-ct-" + digest[:24]), nil
}

func (s *dynamoSessionControlStore) writeCloseTaskTransition(ctx context.Context, action string,
	state sessionControlCommittedTaskState, nextTask sessionControlCloseTask,
	nextOwner sessionControlOwnerAuthority) error {
	taskSetCheck, err := sessionControlCloseTaskSetCondition(s.tableName, state.TaskSet)
	if err != nil {
		return err
	}
	manifestCheck, err := sessionControlCloseManifestCondition(s.tableName, state.Manifest)
	if err != nil {
		return err
	}
	workCheck, err := sessionControlCloseWorkCondition(s.tableName, state.Work)
	if err != nil {
		return err
	}
	ownerWrite, err := sessionControlOwnerReplace(s.tableName, state.Owner, nextOwner)
	if err != nil {
		return err
	}
	taskWrite, err := sessionControlCloseTaskReplace(s.tableName, state.Task, nextTask)
	if err != nil {
		return err
	}
	token, err := sessionControlCloseTaskTransitionToken(s.tableName, action, state, nextTask, nextOwner)
	if err != nil {
		return err
	}
	items := []types.TransactWriteItem{taskSetCheck, manifestCheck, workCheck, ownerWrite, taskWrite}
	if state.Work.Mode == sessionControlCloseWorkModeOverflow {
		if state.Directory == nil {
			return errSessionControlCloseTaskCorrupt
		}
		directoryCheck := sessionControlDirectoryCondition(sessionControlCloseDirectorySnapshot(*state.Directory))
		directoryCheck.ConditionCheck.TableName = aws.String(s.tableName)
		items = append(items, directoryCheck)
	}
	_, err = s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{ClientRequestToken: token,
		TransactItems: items})
	return err
}

func sessionControlCloseTaskClaimReplay(task sessionControlCloseTask, request sessionControlCloseTaskLeaseRequest) bool {
	digest, err := sessionControlCloseTaskOperationInputDigest("claim", request)
	return task.State == sessionControlCloseTaskStateLeased &&
		task.LastOperationKind == sessionControlCloseTaskOperationClaimed && task.LastOperationID == request.OperationID &&
		task.LeaseID == request.LeaseID && task.LeaseOwner == request.LeaseOwner && err == nil &&
		task.LastOperationInputDigest == digest
}

func sessionControlCloseTaskReleaseReplay(task sessionControlCloseTask, request sessionControlCloseTaskLeaseRequest) bool {
	digest, err := sessionControlCloseTaskOperationInputDigest("release", request)
	return task.State == sessionControlCloseTaskStatePending && task.TaskVersion > 1 &&
		task.LastOperationKind == sessionControlCloseTaskOperationReleased && task.LastOperationID == request.OperationID &&
		task.LeaseID == "" && task.LeaseOwner == "" && task.LeaseExpiresAtMillis == 0 && err == nil &&
		task.LastOperationInputDigest == digest
}

func validSessionControlCloseTaskRebindRequest(request sessionControlCloseTaskRebindRequest) bool {
	return validSessionControlCellID(request.CellID) && validSessionControlFenceEventID(request.EventID) &&
		validSessionControlOwnerPK(request.OwnerPK) && validSessionControlTaskOperationID(request.OperationID) &&
		validateSessionControlTargetAuthority(request.Target) == nil && request.Target.required() &&
		request.Target.CountedActiveSlot && request.Target.ControlCellID == request.CellID &&
		request.OwnerPK == sessionControlOwnerPK(request.CellID, request.Target.ACID, request.Target.PublicKey)
}

func sessionControlCloseTaskRebindInputDigest(request sessionControlCloseTaskRebindRequest) (string, error) {
	return sessionControlMaterializationDigest(struct {
		Version uint64
		Request sessionControlCloseTaskRebindRequest
	}{1, request})
}

func validSessionControlCloseTaskAckRequest(request sessionControlCloseTaskAckRequest) bool {
	if !validSessionControlCloseTaskLeaseRequest(request.Lease) || request.AuthenticatedPublicKey == "" ||
		request.Ack.Kind != common.ACSessionCloseKind || request.Ack.Scope != common.ACSessionCloseScopeExact ||
		request.Ack.EventID != request.Lease.EventID || !common.ValidNHPAgentPublicKey(request.AuthenticatedPublicKey) ||
		!common.ValidNHPACBootID(request.Ack.BootID) || request.Ack.FlushGeneration == 0 {
		return false
	}
	_, err := sessionControlFenceSelectorFromAck(request.Ack)
	return err == nil
}

func sessionControlCloseTaskAckInputDigest(request sessionControlCloseTaskAckRequest) (string, error) {
	return sessionControlMaterializationDigest(struct {
		Version uint64
		Request sessionControlCloseTaskAckRequest
	}{1, request})
}

func sessionControlCloseTaskBoundToTarget(task sessionControlCloseTask,
	target sessionControlTargetAuthority) bool {
	return task.CellID == target.ControlCellID && task.ACID == target.ACID && task.PublicKey == target.PublicKey &&
		task.BoundBootID == target.BootID && task.BoundFlushGeneration == target.FlushGeneration &&
		task.BoundTargetVersion == target.Version && task.BoundAuthorityVersion == target.AuthorityVersion &&
		task.BoundActivatedCursor == target.ActivatedControlVersion && task.BoundReadyCursor == target.ReadyControlVersion
}

func sessionControlCloseTaskOwnerTargetsCurrent(owner sessionControlOwnerAuthority,
	target sessionControlTargetAuthority) bool {
	if !target.required() || !target.CountedActiveSlot || owner.CellID != target.ControlCellID ||
		owner.ACID != target.ACID || owner.PublicKey != target.PublicKey || owner.TaskCount == 0 || owner.PendingCount == 0 ||
		!owner.exactTarget(target, owner.Phase) {
		return false
	}
	switch target.State {
	case sessionControlTargetPreparing:
		return owner.Phase == sessionControlOwnerPreparing
	case sessionControlTargetActive:
		return owner.Phase == sessionControlOwnerActiveUnready
	default:
		return false
	}
}

func sessionControlCloseTaskOwnerCursorDescends(task sessionControlCloseTask,
	owner sessionControlOwnerAuthority) bool {
	if owner.WorkVersion < task.CurrentOwnerWorkVersion {
		return false
	}
	return owner.WorkVersion != task.CurrentOwnerWorkVersion ||
		(owner.TaskCount == task.CurrentOwnerTaskCount && owner.PendingCount == task.CurrentOwnerPendingCount)
}

// readCurrentCloseTaskOwnerTarget brackets the target read with two strong
// owner reads. Every target lifecycle mutation updates OWNER atomically, so a
// stable exact OWNER is the transaction-ready fence for the TARGET snapshot.
func (s *dynamoSessionControlStore) readCurrentCloseTaskOwnerTarget(ctx context.Context,
	task sessionControlCloseTask, requested sessionControlTargetAuthority) (*sessionControlOwnerAuthority,
	*sessionControlTargetAuthority, error) {
	for range sessionControlSessionReadAttempts {
		before, err := s.getOwner(ctx, task.CellID, task.ACID, task.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		target, err := s.getTarget(ctx, task.CreationTarget.key())
		if err != nil {
			return nil, nil, err
		}
		after, err := s.getOwner(ctx, task.CellID, task.ACID, task.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		if *before != *after {
			continue
		}
		if *target != requested || !sessionControlCloseTaskOwnerTargetsCurrent(*after, *target) ||
			!sessionControlCloseTaskOwnerCursorDescends(task, *after) {
			return nil, nil, errSessionControlCloseTaskConflict
		}
		return after, target, nil
	}
	return nil, nil, errSessionControlCloseTaskConflict
}

func sessionControlCloseTaskRebindReplay(task sessionControlCloseTask,
	request sessionControlCloseTaskRebindRequest) bool {
	digest, err := sessionControlCloseTaskRebindInputDigest(request)
	return task.State == sessionControlCloseTaskStatePending && task.TaskVersion > 1 &&
		task.LastOperationKind == sessionControlCloseTaskOperationRebound &&
		task.LastOperationID == request.OperationID && task.LastOperationInputDigest == digest && err == nil &&
		sessionControlCloseTaskBoundToTarget(task, request.Target)
}

func sessionControlCloseTaskAckMatches(task sessionControlCloseTask,
	request sessionControlCloseTaskAckRequest, allowClosedDifference bool) bool {
	selector, err := sessionControlFenceSelectorFromAck(request.Ack)
	if err != nil {
		return false
	}
	digest, err := sessionControlFenceSelectorDigest(selector)
	if err != nil || digest != task.SelectorDigest || request.Lease.CellID != task.CellID ||
		request.Lease.EventID != task.EventID || request.Lease.OwnerPK != task.OwnerPK ||
		request.AuthenticatedPublicKey != task.PublicKey || request.Ack.EventID != task.EventID ||
		request.Ack.BootID != task.BoundBootID || request.Ack.FlushGeneration != task.BoundFlushGeneration {
		return false
	}
	if !allowClosedDifference {
		return true
	}
	normalized := request
	normalized.Ack.Closed = task.AckClosed
	inputDigest, digestErr := sessionControlCloseTaskAckInputDigest(normalized)
	return task.State == sessionControlCloseTaskStateAcked && task.LastOperationKind == sessionControlCloseTaskOperationAcked &&
		task.LastOperationID == request.Lease.OperationID && task.LastOperationInputDigest == inputDigest && digestErr == nil &&
		task.AckAuthenticatedPublicKey == request.AuthenticatedPublicKey && task.AckSelectorDigest == digest &&
		task.AckBootID == request.Ack.BootID && task.AckFlushGeneration == request.Ack.FlushGeneration &&
		task.AckLeaseID == request.Lease.LeaseID && task.AckLeaseOwner == request.Lease.LeaseOwner
}

func (s *dynamoSessionControlStore) classifyCloseTaskTransition(ctx context.Context,
	request sessionControlCloseTaskLeaseRequest, desired sessionControlCloseTask) (*sessionControlCloseTask, error) {
	state, err := s.readCommittedCloseTask(ctx, request.OwnerPK, request.EventID)
	if err != nil {
		return nil, err
	}
	if state.Task != desired {
		return nil, errSessionControlCloseTaskConflict
	}
	if err = s.bindCommittedCloseTaskOwner(ctx, state); err != nil {
		return nil, err
	}
	return &state.Task, nil
}

// ClaimExactCloseTask acquires one committed exact-close task for exactly thirty
// seconds. A different live lease is busy; an expired lease may be taken over.
func (s *dynamoSessionControlStore) ClaimExactCloseTask(ctx context.Context,
	request sessionControlCloseTaskLeaseRequest) (*sessionControlCloseTask, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlCloseTaskLeaseRequest(request) {
		return nil, errors.New("invalid session-control close task claim")
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	state, err := s.readCommittedCloseTask(opCtx, request.OwnerPK, request.EventID)
	if err != nil {
		return nil, err
	}
	if err = s.bindCommittedCloseTaskOwner(opCtx, state); err != nil {
		return nil, err
	}
	if state.Task.CellID != request.CellID {
		return nil, errSessionControlCloseTaskConflict
	}
	if sessionControlCloseTaskClaimReplay(state.Task, request) {
		return &state.Task, nil
	}
	if state.Task.State == sessionControlCloseTaskStateAcked {
		return nil, errSessionControlCloseTaskConflict
	}
	if state.Task.State == sessionControlCloseTaskStateLeased && state.Task.LeaseExpiresAtMillis > now.UnixMilli() {
		return nil, errSessionControlCloseTaskBusy
	}
	if state.Task.TaskVersion >= math.MaxUint64-1 {
		return nil, errSessionControlCloseTaskCorrupt
	}
	updatedAt := now.UnixMilli()
	if updatedAt < state.Task.UpdatedAtMillis {
		updatedAt = state.Task.UpdatedAtMillis
	}
	if updatedAt < state.Owner.UpdatedAtMillis {
		updatedAt = state.Owner.UpdatedAtMillis
	}
	if updatedAt > math.MaxInt64-sessionControlCloseTaskLeaseDuration.Milliseconds() {
		return nil, errSessionControlCloseTaskCorrupt
	}
	nextOwner, err := planSessionControlOwnerTaskLeaseTransition(state.Owner, updatedAt)
	if err != nil {
		return nil, err
	}
	next := state.Task
	next.TaskVersion++
	next.State = sessionControlCloseTaskStateLeased
	next.LeaseID, next.LeaseOwner = request.LeaseID, request.LeaseOwner
	next.LeaseExpiresAtMillis = updatedAt + sessionControlCloseTaskLeaseDuration.Milliseconds()
	next.DueAtMillis = next.LeaseExpiresAtMillis
	next.DueSort = sessionControlCloseTaskDueSort(next)
	next.LastOperationKind, next.LastOperationID = sessionControlCloseTaskOperationClaimed, request.OperationID
	next.LastOperationInputDigest, err = sessionControlCloseTaskOperationInputDigest("claim", request)
	if err != nil {
		return nil, err
	}
	next.CurrentOwnerWorkVersion = nextOwner.WorkVersion
	next.CurrentOwnerTaskCount = nextOwner.TaskCount
	next.CurrentOwnerPendingCount = nextOwner.PendingCount
	next.UpdatedAtMillis = updatedAt
	if validateSessionControlCloseTask(next) != nil {
		return nil, errSessionControlCloseTaskCorrupt
	}
	writeErr := s.writeCloseTaskTransition(opCtx, "claim", *state, next, nextOwner)
	if writeErr == nil {
		return &next, nil
	}
	var canceled *types.TransactionCanceledException
	if errors.As(writeErr, &canceled) {
		classified, classifyErr := s.classifyCloseTaskTransition(opCtx, request, next)
		if classifyErr == nil {
			return classified, nil
		}
		return nil, errSessionControlCloseTaskConflict
	}
	resultCtx, resultCancel := s.sessionResultContext(ctx)
	defer resultCancel()
	classified, classifyErr := s.classifyCloseTaskTransition(resultCtx, request, next)
	if classifyErr == nil {
		return classified, nil
	}
	return nil, fmt.Errorf("claim session-control close task: %w", writeErr)
}

// ReleaseExactCloseTask releases only the caller's exact live lease and makes
// the task immediately due. Counts do not change; OWNER WorkVersion and TASK
// TaskVersion provide the cross-process transition fence.
func (s *dynamoSessionControlStore) ReleaseExactCloseTask(ctx context.Context,
	request sessionControlCloseTaskLeaseRequest) (*sessionControlCloseTask, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlCloseTaskLeaseRequest(request) {
		return nil, errors.New("invalid session-control close task release")
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	state, err := s.readCommittedCloseTask(opCtx, request.OwnerPK, request.EventID)
	if err != nil {
		return nil, err
	}
	if err = s.bindCommittedCloseTaskOwner(opCtx, state); err != nil {
		return nil, err
	}
	if state.Task.CellID != request.CellID {
		return nil, errSessionControlCloseTaskConflict
	}
	if sessionControlCloseTaskReleaseReplay(state.Task, request) {
		return &state.Task, nil
	}
	if state.Task.State != sessionControlCloseTaskStateLeased || state.Task.LeaseID != request.LeaseID ||
		state.Task.LeaseOwner != request.LeaseOwner || state.Task.TaskVersion >= math.MaxUint64-1 {
		return nil, errSessionControlCloseTaskConflict
	}
	updatedAt := now.UnixMilli()
	if updatedAt < state.Task.UpdatedAtMillis {
		updatedAt = state.Task.UpdatedAtMillis
	}
	if updatedAt < state.Owner.UpdatedAtMillis {
		updatedAt = state.Owner.UpdatedAtMillis
	}
	nextOwner, err := planSessionControlOwnerTaskLeaseTransition(state.Owner, updatedAt)
	if err != nil {
		return nil, err
	}
	next := state.Task
	next.TaskVersion++
	next.State = sessionControlCloseTaskStatePending
	next.LeaseID, next.LeaseOwner, next.LeaseExpiresAtMillis = "", "", 0
	next.DueAtMillis = updatedAt
	next.DueSort = sessionControlCloseTaskDueSort(next)
	next.LastOperationKind, next.LastOperationID = sessionControlCloseTaskOperationReleased, request.OperationID
	next.LastOperationInputDigest, err = sessionControlCloseTaskOperationInputDigest("release", request)
	if err != nil {
		return nil, err
	}
	next.CurrentOwnerWorkVersion = nextOwner.WorkVersion
	next.CurrentOwnerTaskCount = nextOwner.TaskCount
	next.CurrentOwnerPendingCount = nextOwner.PendingCount
	next.UpdatedAtMillis = updatedAt
	if validateSessionControlCloseTask(next) != nil {
		return nil, errSessionControlCloseTaskCorrupt
	}
	writeErr := s.writeCloseTaskTransition(opCtx, "release", *state, next, nextOwner)
	if writeErr == nil {
		return &next, nil
	}
	var canceled *types.TransactionCanceledException
	if errors.As(writeErr, &canceled) {
		classified, classifyErr := s.classifyCloseTaskTransition(opCtx, request, next)
		if classifyErr == nil {
			return classified, nil
		}
		return nil, errSessionControlCloseTaskConflict
	}
	resultCtx, resultCancel := s.sessionResultContext(ctx)
	defer resultCancel()
	classified, classifyErr := s.classifyCloseTaskTransition(resultCtx, request, next)
	if classifyErr == nil {
		return classified, nil
	}
	return nil, fmt.Errorf("release session-control close task: %w", writeErr)
}

// RebindExactCloseTask moves one committed task to the exact current durable
// target generation. OWNER-before/TARGET/OWNER-after is one bounded strong-read
// bracket; the transaction's exact OWNER replacement closes the later write
// window without adding a sixth transaction member.
func (s *dynamoSessionControlStore) RebindExactCloseTask(ctx context.Context,
	request sessionControlCloseTaskRebindRequest) (*sessionControlCloseTask, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlCloseTaskRebindRequest(request) {
		return nil, errors.New("invalid session-control close task rebind")
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	state, err := s.readCommittedCloseTask(opCtx, request.OwnerPK, request.EventID)
	if err != nil {
		return nil, err
	}
	owner, target, err := s.readCurrentCloseTaskOwnerTarget(opCtx, state.Task, request.Target)
	if err != nil {
		return nil, err
	}
	state.Owner = *owner
	if sessionControlCloseTaskRebindReplay(state.Task, request) {
		return &state.Task, nil
	}
	if state.Task.State == sessionControlCloseTaskStateAcked ||
		target.FlushGeneration <= state.Task.BoundFlushGeneration || state.Task.TaskVersion >= math.MaxUint64-1 {
		return nil, errSessionControlCloseTaskConflict
	}
	updatedAt := now.UnixMilli()
	if updatedAt < state.Task.UpdatedAtMillis {
		updatedAt = state.Task.UpdatedAtMillis
	}
	if updatedAt < state.Owner.UpdatedAtMillis {
		updatedAt = state.Owner.UpdatedAtMillis
	}
	nextOwner, err := planSessionControlOwnerTaskLeaseTransition(state.Owner, updatedAt)
	if err != nil {
		return nil, err
	}
	next := state.Task
	next.TaskVersion++
	next.State = sessionControlCloseTaskStatePending
	next.BoundBootID = target.BootID
	next.BoundFlushGeneration = target.FlushGeneration
	next.BoundTargetVersion = target.Version
	next.BoundAuthorityVersion = target.AuthorityVersion
	next.BoundOwnerLifecycle = nextOwner.LifecycleVersion
	next.BoundActivatedCursor = target.ActivatedControlVersion
	next.BoundReadyCursor = target.ReadyControlVersion
	next.CurrentOwnerWorkVersion = nextOwner.WorkVersion
	next.CurrentOwnerTaskCount = nextOwner.TaskCount
	next.CurrentOwnerPendingCount = nextOwner.PendingCount
	next.LeaseID, next.LeaseOwner, next.LeaseExpiresAtMillis = "", "", 0
	next.DueAtMillis = updatedAt
	next.DueSort = sessionControlCloseTaskDueSort(next)
	next.LastOperationKind, next.LastOperationID = sessionControlCloseTaskOperationRebound, request.OperationID
	next.LastOperationInputDigest, err = sessionControlCloseTaskRebindInputDigest(request)
	if err != nil {
		return nil, err
	}
	next.UpdatedAtMillis = updatedAt
	if validateSessionControlCloseTask(next) != nil {
		return nil, errSessionControlCloseTaskCorrupt
	}
	writeErr := s.writeCloseTaskTransition(opCtx, "rebind", *state, next, nextOwner)
	if writeErr == nil {
		return &next, nil
	}
	var canceled *types.TransactionCanceledException
	if errors.As(writeErr, &canceled) {
		classified, classifyErr := s.classifyCloseTaskTransition(opCtx,
			sessionControlCloseTaskLeaseRequest{CellID: request.CellID, EventID: request.EventID, OwnerPK: request.OwnerPK}, next)
		if classifyErr == nil {
			return classified, nil
		}
		return nil, errSessionControlCloseTaskConflict
	}
	resultCtx, resultCancel := s.sessionResultContext(ctx)
	defer resultCancel()
	classified, classifyErr := s.classifyCloseTaskTransition(resultCtx,
		sessionControlCloseTaskLeaseRequest{CellID: request.CellID, EventID: request.EventID, OwnerPK: request.OwnerPK}, next)
	if classifyErr == nil {
		return classified, nil
	}
	return nil, fmt.Errorf("rebind session-control close task: %w", writeErr)
}

// AckExactCloseTask commits the first authenticated exact NHP_RVA result. Lease
// expiry does not invalidate an ACK while the same lease remains stored; a
// release, takeover, or rebind changes TASK and makes the old RVA terminally
// stale. Replays return the first stored Closed diagnostic.
func (s *dynamoSessionControlStore) AckExactCloseTask(ctx context.Context,
	request sessionControlCloseTaskAckRequest) (*sessionControlCloseTask, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlCloseTaskAckRequest(request) {
		return nil, errors.New("invalid session-control close task acknowledgement")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	state, err := s.readCommittedCloseTask(opCtx, request.Lease.OwnerPK, request.Lease.EventID)
	if err != nil {
		if completed, completedErr := s.classifyCompletedCloseTaskAck(opCtx, request); completedErr == nil {
			return completed, nil
		} else if !errors.Is(completedErr, errSessionControlCompletionNotFound) &&
			!errors.Is(completedErr, errSessionControlCloseTaskNotFound) {
			return nil, completedErr
		}
		if errors.Is(err, errSessionControlCloseTaskNotFound) {
			if audited, auditErr := s.classifyAckedCloseTaskAudit(opCtx, request); auditErr == nil {
				return audited, nil
			} else if !errors.Is(auditErr, errSessionControlCloseTaskNotFound) {
				return nil, auditErr
			}
		}
		return nil, err
	}
	if err = s.bindCommittedCloseTaskOwner(opCtx, state); err != nil {
		return nil, err
	}
	if sessionControlCloseTaskAckMatches(state.Task, request, true) {
		return &state.Task, nil
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	if state.Task.State != sessionControlCloseTaskStateLeased ||
		state.Task.LeaseID != request.Lease.LeaseID || state.Task.LeaseOwner != request.Lease.LeaseOwner ||
		state.Task.TaskVersion >= math.MaxUint64-1 || !sessionControlCloseTaskAckMatches(state.Task, request, false) {
		return nil, errSessionControlCloseTaskConflict
	}
	updatedAt := now.UnixMilli()
	if updatedAt < state.Task.UpdatedAtMillis {
		updatedAt = state.Task.UpdatedAtMillis
	}
	if updatedAt < state.Owner.UpdatedAtMillis {
		updatedAt = state.Owner.UpdatedAtMillis
	}
	nextOwner, err := planSessionControlOwnerTaskAck(state.Owner, updatedAt)
	if err != nil {
		return nil, errSessionControlCloseTaskCorrupt
	}
	next := state.Task
	next.TaskVersion++
	next.State = sessionControlCloseTaskStateAcked
	next.CurrentOwnerWorkVersion = nextOwner.WorkVersion
	next.CurrentOwnerTaskCount = nextOwner.TaskCount
	next.CurrentOwnerPendingCount = nextOwner.PendingCount
	next.LeaseID, next.LeaseOwner, next.LeaseExpiresAtMillis = "", "", 0
	next.DueAtMillis, next.DueShard, next.DueSort = 0, "", ""
	next.LastOperationKind, next.LastOperationID = sessionControlCloseTaskOperationAcked, request.Lease.OperationID
	next.LastOperationInputDigest, err = sessionControlCloseTaskAckInputDigest(request)
	if err != nil {
		return nil, err
	}
	selector, err := sessionControlFenceSelectorFromAck(request.Ack)
	if err != nil {
		return nil, err
	}
	next.AckSelectorDigest, err = sessionControlFenceSelectorDigest(selector)
	if err != nil {
		return nil, err
	}
	next.AckAuthenticatedPublicKey = request.AuthenticatedPublicKey
	next.AckBootID = request.Ack.BootID
	next.AckFlushGeneration = request.Ack.FlushGeneration
	next.AckClosed = request.Ack.Closed
	next.AckLeaseID = request.Lease.LeaseID
	next.AckLeaseOwner = request.Lease.LeaseOwner
	next.AckedAtMillis = updatedAt
	next.UpdatedAtMillis = updatedAt
	if validateSessionControlCloseTask(next) != nil {
		return nil, errSessionControlCloseTaskCorrupt
	}
	writeErr := s.writeCloseTaskTransition(opCtx, "ack", *state, next, nextOwner)
	if writeErr == nil {
		return &next, nil
	}
	var canceled *types.TransactionCanceledException
	if errors.As(writeErr, &canceled) {
		classified, classifyErr := s.classifyCloseTaskTransition(opCtx, request.Lease, next)
		if classifyErr == nil {
			return classified, nil
		}
		if errors.Is(classifyErr, errSessionControlCloseTaskNotFound) {
			if completed, completedErr := s.classifyCompletedCloseTaskAck(opCtx, request); completedErr == nil {
				return completed, nil
			} else if !errors.Is(completedErr, errSessionControlCompletionNotFound) &&
				!errors.Is(completedErr, errSessionControlCloseTaskNotFound) {
				return nil, completedErr
			}
			if audited, auditErr := s.classifyAckedCloseTaskAudit(opCtx, request); auditErr == nil {
				return audited, nil
			} else if !errors.Is(auditErr, errSessionControlCloseTaskNotFound) {
				return nil, auditErr
			}
		}
		return nil, errSessionControlCloseTaskConflict
	}
	resultCtx, resultCancel := s.sessionResultContext(ctx)
	defer resultCancel()
	classified, classifyErr := s.classifyCloseTaskTransition(resultCtx, request.Lease, next)
	if classifyErr == nil {
		return classified, nil
	}
	if errors.Is(classifyErr, errSessionControlCloseTaskNotFound) {
		if completed, completedErr := s.classifyCompletedCloseTaskAck(resultCtx, request); completedErr == nil {
			return completed, nil
		} else if !errors.Is(completedErr, errSessionControlCompletionNotFound) &&
			!errors.Is(completedErr, errSessionControlCloseTaskNotFound) {
			return nil, completedErr
		}
		if audited, auditErr := s.classifyAckedCloseTaskAudit(resultCtx, request); auditErr == nil {
			return audited, nil
		} else if !errors.Is(auditErr, errSessionControlCloseTaskNotFound) {
			return nil, auditErr
		}
	}
	return nil, fmt.Errorf("ack session-control close task: %w", writeErr)
}
