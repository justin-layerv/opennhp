package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// sessionControlOwnerTaskDeliveryAuthority is the bounded owner inventory
// result. OwnerPK and EventID are sufficient to load or claim the exact task;
// Task and Work retain the committed delivery identity and selector so callers
// never derive control messages from an eventual index projection.
type sessionControlOwnerTaskDeliveryAuthority struct {
	OwnerPK string
	EventID string
	Task    sessionControlCloseTask
	Work    sessionControlCloseWork
}

type sessionControlOwnerTaskSnapshot struct {
	Owner sessionControlOwnerAuthority
	Tasks []sessionControlOwnerTaskDeliveryAuthority
}

// sessionControlExactCloseTaskAuthority is the complete strong-read authority
// needed to deliver one exact close. Directory is present only for overflow
// work, whose selected-leader identity is part of the committed proof.
type sessionControlExactCloseTaskAuthority struct {
	Session   sessionControlSessionAuthority
	Task      sessionControlCloseTask
	TaskSet   sessionControlCloseTaskSet
	Manifest  sessionControlCloseManifest
	Work      sessionControlCloseWork
	Owner     sessionControlOwnerAuthority
	Directory *sessionControlFenceDirectory
}

// sessionControlExactCloseTaskAuthorityValid is the final fail-closed boundary
// before runtime code composes a REV from store-returned authority. It repeats
// the immutable session/work/task/commit binding so a malformed fake, alternate
// backend, or corrupted decoded value cannot redirect a valid task to a sibling
// exact session merely by copying stale digest strings.
func sessionControlExactCloseTaskAuthorityValid(authority sessionControlExactCloseTaskAuthority) bool {
	if validateSessionControlSessionAuthority(authority.Session) != nil ||
		authority.Session.State != sessionControlSessionStateClosing ||
		validateSessionControlCloseTask(authority.Task) != nil ||
		validateSessionControlCloseWork(authority.Work) != nil ||
		validateSessionControlCloseTaskSet(authority.TaskSet) != nil ||
		validateSessionControlCloseManifest(authority.Manifest) != nil ||
		validateSessionControlOwnerAuthority(authority.Owner) != nil ||
		!sessionControlCloseTaskMatchesCommit(authority.Task, authority.TaskSet, authority.Manifest, authority.Work) ||
		authority.Session.CloseEventID != authority.Task.EventID ||
		authority.Session.Candidate.CellID != authority.Task.CellID ||
		authority.Session.Candidate.AgentPublicKey != authority.Work.Selector.AgentPublicKey ||
		authority.Session.Candidate.SessionID != authority.Work.Selector.SessionID ||
		authority.Session.Candidate.IssuedAtMillis != authority.Work.Selector.SessionIssuedMillis ||
		authority.Session.Version != authority.Work.SessionVersion ||
		authority.Session.TargetCount != authority.Work.ExpectedTargetCount ||
		authority.Session.ClosePreparedDirectory != authority.Work.PreparedDirectoryVersion ||
		authority.Work.Selector.Scope != sessionControlFenceSelectorExact {
		return false
	}
	if authority.Work.Mode == sessionControlCloseWorkModeOverflow {
		return authority.Directory != nil &&
			validateSessionControlFenceDirectory(*authority.Directory) == nil &&
			sessionControlOverflowLeaderMatchesWork(*authority.Directory, authority.Work)
	}
	return authority.Work.Mode == sessionControlCloseWorkModeNormal && authority.Directory == nil
}

func sessionControlCommittedTaskStateEqual(left, right *sessionControlCommittedTaskState) bool {
	if left == nil || right == nil || left.Task != right.Task || left.TaskSet.TaskSetDigest != right.TaskSet.TaskSetDigest ||
		left.Manifest.ManifestDigest != right.Manifest.ManifestDigest || left.Work != right.Work || left.Owner != right.Owner {
		return false
	}
	if left.Directory == nil || right.Directory == nil {
		return left.Directory == nil && right.Directory == nil
	}
	return *left.Directory == *right.Directory
}

// sessionControlCloseTaskIsOwnerDescendant is deliberately weaker than the
// transition-time exact owner predicate. A strictly newer AC process may own
// the same required target while durable tasks still carry their older binding;
// the snapshot must enumerate those rows so RebindExactCloseTask can advance
// them. Equal-generation drift remains corrupt, and monotonic versions/counts
// are still bounded by the stable physical partition parity below.
func sessionControlCloseTaskIsOwnerDescendant(task sessionControlCloseTask,
	owner sessionControlOwnerAuthority,
) bool {
	if validateSessionControlOwnerAuthority(owner) != nil || owner.CellID != task.CellID ||
		owner.ACID != task.ACID || owner.PublicKey != task.PublicKey || owner.Phase == sessionControlOwnerRetired ||
		owner.WorkVersion < task.CurrentOwnerWorkVersion || owner.TaskCount == 0 ||
		(task.State != sessionControlCloseTaskStateAcked && owner.PendingCount == 0) {
		return false
	}
	if owner.WorkVersion == task.CurrentOwnerWorkVersion &&
		(owner.TaskCount != task.CurrentOwnerTaskCount || owner.PendingCount != task.CurrentOwnerPendingCount) {
		return false
	}
	if owner.FlushGeneration < task.BoundFlushGeneration {
		return false
	}
	if owner.FlushGeneration == task.BoundFlushGeneration {
		if owner.BootID == task.BoundBootID && owner.TargetVersion == task.BoundTargetVersion &&
			owner.TargetAuthorityVersion == task.BoundAuthorityVersion &&
			owner.LifecycleVersion == task.BoundOwnerLifecycle &&
			owner.ActivatedControlVersion == task.BoundActivatedCursor &&
			owner.ReadyControlVersion == task.BoundReadyCursor {
			return true
		}
		creation, validCreation := sessionControlCloseTaskPreparingActivationCreation(task)
		return validCreation &&
			owner.Phase == sessionControlOwnerActiveUnready && owner.BootID == creation.BootID &&
			owner.FlushGeneration == creation.FlushGeneration &&
			owner.TargetVersion == creation.Version+1 && owner.TargetAuthorityVersion == creation.AuthorityVersion &&
			owner.TargetCountedActiveSlot && owner.LifecycleVersion > task.BoundOwnerLifecycle &&
			owner.ActivatedControlVersion > 0 && owner.ReadyControlVersion == 0 &&
			owner.TargetCreatedAtMillis == creation.CreatedAtMillis &&
			owner.TargetPreparedAtMillis == creation.PreparedAtMillis &&
			owner.TargetUpdatedAtMillis == creation.PreparedAtMillis &&
			owner.AAKEnqueuedAtMillis == 0 && owner.AAKTransactionID == 0
	}
	return owner.TargetVersion > task.BoundTargetVersion &&
		owner.TargetAuthorityVersion >= task.BoundAuthorityVersion &&
		owner.LifecycleVersion > task.BoundOwnerLifecycle
}

func sessionControlExactTaskMatchesSession(state *sessionControlCommittedTaskState,
	session sessionControlSessionAuthority) bool {
	if state == nil || state.Work.Selector.Scope != sessionControlFenceSelectorExact ||
		session.State != sessionControlSessionStateClosing || session.CloseEventID != state.Task.EventID ||
		state.Task.EventID != sessionControlExactCloseEventID(session.Candidate) ||
		state.Work.CellID != session.Candidate.CellID ||
		state.Work.Selector.AgentPublicKey != session.Candidate.AgentPublicKey ||
		state.Work.Selector.SessionID != session.Candidate.SessionID ||
		state.Work.Selector.SessionIssuedMillis != session.Candidate.IssuedAtMillis ||
		state.Work.Selector.IssuedThroughMillis != 0 || state.Work.Selector.RunID != "" ||
		state.Work.Selector.RunAttempt != 0 || state.Work.SessionVersion != session.Version ||
		state.Work.ExpectedTargetCount != session.TargetCount ||
		state.Work.PreparedDirectoryVersion != session.ClosePreparedDirectory {
		return false
	}
	digest, err := sessionControlFenceSelectorDigest(state.Work.Selector)
	return err == nil && digest == state.Work.SelectorDigest && digest == state.Task.SelectorDigest
}

func sessionControlOwnerTaskQueryCursor(last map[string]types.AttributeValue, ownerPK string) (string, bool) {
	pk, pkOK := last["pk"].(*types.AttributeValueMemberS)
	sk, skOK := last["sk"].(*types.AttributeValueMemberS)
	eventID := ""
	if sk != nil {
		eventID = strings.TrimPrefix(sk.Value, sessionControlCloseTaskSKPrefix)
	}
	return func() string {
			if sk == nil {
				return ""
			}
			return sk.Value
		}(), pkOK && skOK && pk.Value == ownerPK && strings.HasPrefix(sk.Value, sessionControlCloseTaskSKPrefix) &&
			validSessionControlFenceEventID(eventID)
}

func (s *dynamoSessionControlStore) readOwnerCommittedTasks(ctx context.Context,
	ownerPK string) ([]sessionControlOwnerTaskDeliveryAuthority, bool, error) {
	tasks := make([]sessionControlOwnerTaskDeliveryAuthority, 0)
	seen := make(map[string]struct{})
	var lastKey map[string]types.AttributeValue
	lastCursor := ""
	incomplete := false
	physicalCount := 0
	for {
		result, err := s.client.Query(ctx, &dynamodb.QueryInput{
			TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true),
			KeyConditionExpression: aws.String("pk = :pk AND begins_with(sk, :task_prefix)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk":          &types.AttributeValueMemberS{Value: ownerPK},
				":task_prefix": &types.AttributeValueMemberS{Value: sessionControlCloseTaskSKPrefix},
			},
			ExclusiveStartKey: lastKey, Limit: aws.Int32(sessionControlOwnerQueryLimit),
		})
		if err != nil {
			return nil, false, fmt.Errorf("session-control owner task strong query: %w", err)
		}
		if len(result.Items) > int(sessionControlOwnerTaskLimit)-physicalCount {
			return nil, false, errSessionControlOwnerCapacity
		}
		physicalCount += len(result.Items)
		for _, item := range result.Items {
			pk, pkOK := item["pk"].(*types.AttributeValueMemberS)
			sk, skOK := item["sk"].(*types.AttributeValueMemberS)
			if !pkOK || !skOK || pk.Value != ownerPK || !strings.HasPrefix(sk.Value, sessionControlCloseTaskSKPrefix) {
				return nil, false, errSessionControlOwnerCorrupt
			}
			eventID := strings.TrimPrefix(sk.Value, sessionControlCloseTaskSKPrefix)
			if !validSessionControlFenceEventID(eventID) {
				return nil, false, errSessionControlOwnerCorrupt
			}
			if _, duplicate := seen[eventID]; duplicate {
				return nil, false, errSessionControlOwnerCorrupt
			}
			seen[eventID] = struct{}{}
			task, decodeErr := sessionControlCloseTaskFromItem(item, ownerPK, eventID)
			if decodeErr != nil {
				return nil, false, errSessionControlCloseTaskCorrupt
			}
			committed, readErr := s.readCommittedCloseTask(ctx, ownerPK, eventID)
			if errors.Is(readErr, errSessionControlCloseTaskNotFound) {
				incomplete = true
				continue
			}
			if readErr != nil {
				return nil, false, readErr
			}
			if committed.Task != task {
				incomplete = true
				continue
			}
			tasks = append(tasks, sessionControlOwnerTaskDeliveryAuthority{
				OwnerPK: ownerPK, EventID: eventID, Task: task, Work: committed.Work,
			})
		}
		if len(result.LastEvaluatedKey) == 0 {
			break
		}
		if len(result.Items) == 0 {
			return nil, false, errSessionControlOwnerCorrupt
		}
		cursor, valid := sessionControlOwnerTaskQueryCursor(result.LastEvaluatedKey, ownerPK)
		if !valid || cursor <= lastCursor {
			return nil, false, errSessionControlOwnerCorrupt
		}
		lastCursor = cursor
		lastKey = result.LastEvaluatedKey
	}
	return tasks, incomplete, nil
}

// SnapshotOwnerExactCloseTasks returns a stable, strong, physically bounded
// inventory for one exact target owner. OWNER brackets the paginated TASK
// partition; both physical and pending counts must match the durable directory.
func (s *dynamoSessionControlStore) SnapshotOwnerExactCloseTasks(ctx context.Context,
	cellID, acID, publicKey string) (*sessionControlOwnerTaskSnapshot, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlCellID(cellID) ||
		!validSessionControlTargetKey(sessionControlTargetKey{ACID: acID, PublicKey: publicKey}) {
		return nil, errors.New("invalid session-control owner task snapshot")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	ownerPK := sessionControlOwnerPK(cellID, acID, publicKey)
	for range sessionControlSessionReadAttempts {
		before, err := s.getOwner(opCtx, cellID, acID, publicKey)
		if err != nil {
			return nil, err
		}
		tasks, incomplete, err := s.readOwnerCommittedTasks(opCtx, ownerPK)
		if err != nil {
			return nil, err
		}
		after, err := s.getOwner(opCtx, cellID, acID, publicKey)
		if err != nil {
			return nil, err
		}
		if *before != *after || incomplete {
			continue
		}
		var pending uint64
		for _, entry := range tasks {
			if !sessionControlCloseTaskIsOwnerDescendant(entry.Task, *after) {
				return nil, errSessionControlOwnerCorrupt
			}
			if entry.Task.State != sessionControlCloseTaskStateAcked {
				pending++
			}
		}
		if uint64(len(tasks)) != after.TaskCount || pending != after.PendingCount {
			return nil, errSessionControlOwnerCorrupt
		}
		return &sessionControlOwnerTaskSnapshot{Owner: *after, Tasks: tasks}, nil
	}
	return nil, errSessionControlOwnerConflict
}

// LoadExactCloseTaskAuthority strongly brackets the committed task and its
// session/membership row. The selector is never reconstructed from TASK-only
// fields, and a retained session may extend its retention without invalidating
// the immutable close identity.
func (s *dynamoSessionControlStore) LoadExactCloseTaskAuthority(ctx context.Context,
	ownerPK, eventID string) (*sessionControlExactCloseTaskAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlOwnerPK(ownerPK) || !validSessionControlFenceEventID(eventID) {
		return nil, errors.New("invalid session-control exact close task authority")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	for range sessionControlSessionReadAttempts {
		before, err := s.readCommittedCloseTask(opCtx, ownerPK, eventID)
		if err != nil {
			return nil, err
		}
		if err = s.bindCommittedCloseTaskOwner(opCtx, before); err != nil {
			return nil, err
		}
		if before.Work.Selector.Scope != sessionControlFenceSelectorExact {
			return nil, errSessionControlCloseTaskCorrupt
		}
		session, err := s.getSessionItem(opCtx, before.Work.Selector.SessionID)
		if err != nil {
			if errors.Is(err, errSessionControlSessionNotFound) {
				return nil, errSessionControlCloseTaskCorrupt
			}
			return nil, err
		}
		session, err = s.classifyReservation(opCtx, session.Candidate)
		if err != nil {
			if errors.Is(err, errSessionControlSessionNotFound) || errors.Is(err, errSessionControlSessionCollision) ||
				errors.Is(err, errSessionControlSessionCorrupt) {
				return nil, errSessionControlCloseTaskCorrupt
			}
			return nil, err
		}
		after, err := s.readCommittedCloseTask(opCtx, ownerPK, eventID)
		if err != nil {
			return nil, err
		}
		if err = s.bindCommittedCloseTaskOwner(opCtx, after); err != nil {
			return nil, err
		}
		if !sessionControlCommittedTaskStateEqual(before, after) {
			continue
		}
		if !sessionControlExactTaskMatchesSession(after, *session) {
			return nil, errSessionControlCloseTaskCorrupt
		}
		return &sessionControlExactCloseTaskAuthority{
			Session: *session, Task: after.Task, TaskSet: after.TaskSet, Manifest: after.Manifest,
			Work: after.Work, Owner: after.Owner, Directory: after.Directory,
		}, nil
	}
	return nil, errSessionControlCloseTaskConflict
}

// ClaimExactCloseTaskForDelivery returns the exact authority that survived the
// lease CAS. A caller never sends from the pre-claim task or a partial row.
func (s *dynamoSessionControlStore) ClaimExactCloseTaskForDelivery(ctx context.Context,
	request sessionControlCloseTaskLeaseRequest) (*sessionControlExactCloseTaskAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	claimed, err := s.ClaimExactCloseTask(opCtx, request)
	if err != nil {
		return nil, err
	}
	authority, err := s.LoadExactCloseTaskAuthority(opCtx, request.OwnerPK, request.EventID)
	if err != nil {
		return nil, err
	}
	if authority.Task != *claimed {
		return nil, errSessionControlCloseTaskConflict
	}
	return authority, nil
}
