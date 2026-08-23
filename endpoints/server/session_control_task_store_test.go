package server

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/OpenNHP/opennhp/nhp/common"
)

type sessionControlTaskFixture struct {
	sessionControlMaterializationFixture
	taskSet sessionControlCloseTaskSet
	ownerPK string
	task    sessionControlCloseTask
}

func sessionControlTaskTestID(value uint64) string {
	return fmt.Sprintf("%032x", value)
}

func newSessionControlTaskFixture(t *testing.T, count int) sessionControlTaskFixture {
	t.Helper()
	materialization := newSessionControlMaterializationFixture(t, count)
	taskSet, err := materialization.store.MaterializeNormalExactClose(context.Background(), materialization.candidate,
		materialization.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	fixture := sessionControlTaskFixture{sessionControlMaterializationFixture: materialization, taskSet: *taskSet}
	if count > 0 {
		intent := materialization.intents[0]
		fixture.ownerPK = sessionControlOwnerPK(intent.Target.ControlCellID, intent.Target.ACID, intent.Target.PublicKey)
		task, readErr := fixture.store.getCloseTask(context.Background(), fixture.ownerPK, fixture.close.EventID)
		if readErr != nil {
			t.Fatal(readErr)
		}
		fixture.task = *task
	}
	return fixture
}

func sessionControlTaskClaimRequest(fixture sessionControlTaskFixture, seed uint64) sessionControlCloseTaskLeaseRequest {
	return sessionControlCloseTaskLeaseRequest{CellID: fixture.task.CellID, EventID: fixture.task.EventID,
		OwnerPK: fixture.ownerPK, OperationID: sessionControlTaskTestID(seed),
		LeaseID: sessionControlTaskTestID(seed + 1), LeaseOwner: sessionControlTaskTestID(seed + 2)}
}

func seedSessionControlTaskOwner(t *testing.T, fake *sessionControlSessionDynamoFake,
	owner sessionControlOwnerAuthority) {
	t.Helper()
	row, err := sessionControlOwnerToRow(owner)
	if err != nil {
		t.Fatal(err)
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(item)
}

func installSessionControlTaskTargetGeneration(t *testing.T, fixture *sessionControlTaskFixture,
	generation uint64, bootID string) sessionControlTargetAuthority {
	t.Helper()
	currentTarget, err := fixture.store.getTarget(context.Background(), fixture.task.CreationTarget.key())
	if err != nil {
		t.Fatal(err)
	}
	currentOwner, err := fixture.store.getOwner(context.Background(), fixture.task.CellID, fixture.task.ACID, fixture.task.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	next := *currentTarget
	next.BootID = bootID
	next.FlushGeneration = generation
	next.State = sessionControlTargetPreparing
	next.Version++
	next.ActivatedControlVersion = 0
	next.ReadyControlVersion = 0
	next.AAKEnqueuedAtMillis = 0
	next.AAKTransactionID = 0
	next.PreparedAtMillis = fixture.store.nowUTC().UnixMilli()
	if next.PreparedAtMillis < next.UpdatedAtMillis {
		next.PreparedAtMillis = next.UpdatedAtMillis
	}
	next.UpdatedAtMillis = next.PreparedAtMillis
	owner, err := sessionControlOwnerFromTarget(next, currentOwner, sessionControlOwnerPreparing)
	if err != nil {
		t.Fatal(err)
	}
	targetRow, err := sessionControlTargetToRow(next)
	if err != nil {
		t.Fatal(err)
	}
	fixture.fake.setItem(marshalSessionControlSessionTestRow(t, targetRow))
	seedSessionControlTaskOwner(t, fixture.fake, owner)
	return next
}

func activateSessionControlTaskTargetUnready(t *testing.T, fixture *sessionControlTaskFixture,
	preparing sessionControlTargetAuthority) sessionControlTargetAuthority {
	t.Helper()
	currentOwner, err := fixture.store.getOwner(context.Background(), preparing.ControlCellID,
		preparing.ACID, preparing.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	active := preparing
	active.State = sessionControlTargetActive
	active.Version++
	active.ActivatedControlVersion = fixture.task.BoundActivatedCursor
	if fixture.close.Fence != nil {
		active.ActivatedControlVersion = fixture.close.Fence.PreparedDirectoryVersion
	}
	active.ReadyControlVersion = 0
	active.AAKEnqueuedAtMillis = 0
	active.AAKTransactionID = 0
	active.UpdatedAtMillis++
	owner, err := sessionControlOwnerFromTarget(active, currentOwner, sessionControlOwnerActiveUnready)
	if err != nil {
		t.Fatal(err)
	}
	targetRow, err := sessionControlTargetToRow(active)
	if err != nil {
		t.Fatal(err)
	}
	fixture.fake.setItem(marshalSessionControlSessionTestRow(t, targetRow))
	seedSessionControlTaskOwner(t, fixture.fake, owner)
	return active
}

func sessionControlTaskRebindRequest(fixture sessionControlTaskFixture,
	target sessionControlTargetAuthority, seed uint64) sessionControlCloseTaskRebindRequest {
	return sessionControlCloseTaskRebindRequest{CellID: fixture.task.CellID, EventID: fixture.task.EventID,
		OwnerPK: fixture.ownerPK, OperationID: sessionControlTaskTestID(seed), Target: target}
}

func sessionControlTaskAckRequest(fixture sessionControlTaskFixture, task sessionControlCloseTask,
	lease sessionControlCloseTaskLeaseRequest, closed uint64) sessionControlCloseTaskAckRequest {
	selector := fixture.close.Work.Selector
	return sessionControlCloseTaskAckRequest{Lease: lease, AuthenticatedPublicKey: task.PublicKey,
		Ack: common.ACSessionCloseAckMsg{Kind: common.ACSessionCloseKind, Scope: common.ACSessionCloseScopeExact,
			EventID: task.EventID, AgentPublicKey: selector.AgentPublicKey, SessionID: selector.SessionID,
			SessionIssuedAtMillis: selector.SessionIssuedMillis, BootID: task.BoundBootID,
			FlushGeneration: task.BoundFlushGeneration, Closed: closed}}
}

func installSessionControlTaskDueQuery(fake *sessionControlSessionDynamoFake, omit bool) {
	fake.queryHook = func(ctx context.Context, input *dynamodb.QueryInput, _ int) (*dynamodb.QueryOutput, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if aws.ToString(input.IndexName) != sessionControlDueIndexName || aws.ToBool(input.ConsistentRead) {
			return nil, errors.New("malformed close-task due query")
		}
		if omit {
			return &dynamodb.QueryOutput{}, nil
		}
		shard, _ := input.ExpressionAttributeValues[":shard"].(*types.AttributeValueMemberS)
		through, _ := input.ExpressionAttributeValues[":through"].(*types.AttributeValueMemberS)
		if shard == nil || through == nil {
			return nil, errors.New("missing due query values")
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		keys := make([]string, 0)
		for key, item := range fake.items {
			itemShard, _ := item["due_shard"].(*types.AttributeValueMemberS)
			itemSort, _ := item["due_sort"].(*types.AttributeValueMemberS)
			if itemShard != nil && itemSort != nil && itemShard.Value == shard.Value && itemSort.Value <= through.Value {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		start := 0
		if len(input.ExclusiveStartKey) != 0 {
			after := sessionControlSessionDynamoMapKey(input.ExclusiveStartKey)
			start = sort.SearchStrings(keys, after)
			for start < len(keys) && keys[start] <= after {
				start++
			}
		}
		limit := len(keys) - start
		if input.Limit != nil && int(*input.Limit) < limit {
			limit = int(*input.Limit)
		}
		items := make([]map[string]types.AttributeValue, 0, limit)
		for _, key := range keys[start : start+limit] {
			item := fake.items[key]
			items = append(items, map[string]types.AttributeValue{"pk": item["pk"], "sk": item["sk"]})
		}
		var last map[string]types.AttributeValue
		if start+limit < len(keys) && limit > 0 {
			item := fake.items[keys[start+limit-1]]
			last = map[string]types.AttributeValue{"pk": item["pk"], "sk": item["sk"]}
		}
		return &dynamodb.QueryOutput{Items: items, LastEvaluatedKey: last}, nil
	}
}

func TestDynamoSessionControlCloseTaskClaimReleaseAndExactReplay(t *testing.T) {
	fixture := newSessionControlTaskFixture(t, 1)
	transactionsBefore := len(fixture.fake.transactions)
	request := sessionControlTaskClaimRequest(fixture, 0x101)
	claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	wantExpiry := fixture.store.nowUTC().UnixMilli() + sessionControlCloseTaskLeaseDuration.Milliseconds()
	if claimed.State != sessionControlCloseTaskStateLeased || claimed.TaskVersion != 2 ||
		claimed.LeaseExpiresAtMillis != wantExpiry || claimed.DueAtMillis != wantExpiry ||
		claimed.LastOperationInputDigest == "" || claimed.CurrentOwnerWorkVersion != claimed.OwnerAfter.WorkVersion+1 {
		t.Fatalf("claimed task = %#v", claimed)
	}
	txn := fixture.fake.transactions[transactionsBefore]
	if len(txn.TransactItems) != 5 || len(aws.ToString(txn.ClientRequestToken)) > 36 ||
		txn.TransactItems[0].ConditionCheck == nil || txn.TransactItems[1].ConditionCheck == nil ||
		txn.TransactItems[2].ConditionCheck == nil || txn.TransactItems[3].Put == nil || txn.TransactItems[4].Put == nil {
		t.Fatalf("claim transaction = %#v", txn)
	}
	transactionCount := len(fixture.fake.transactions)
	replayed, err := fixture.store.ClaimExactCloseTask(context.Background(), request)
	if err != nil || *replayed != *claimed || len(fixture.fake.transactions) != transactionCount {
		t.Fatalf("claim replay = %#v/%v txns=%d", replayed, err, len(fixture.fake.transactions))
	}

	release := request
	release.OperationID = sessionControlTaskTestID(0x201)
	released, err := fixture.store.ReleaseExactCloseTask(context.Background(), release)
	if err != nil {
		t.Fatal(err)
	}
	if released.State != sessionControlCloseTaskStatePending || released.TaskVersion != 3 ||
		released.LeaseID != "" || released.LeaseOwner != "" || released.LeaseExpiresAtMillis != 0 ||
		released.DueAtMillis != released.UpdatedAtMillis || released.CurrentOwnerWorkVersion != claimed.CurrentOwnerWorkVersion+1 {
		t.Fatalf("released task = %#v", released)
	}
	transactionCount = len(fixture.fake.transactions)
	replayed, err = fixture.store.ReleaseExactCloseTask(context.Background(), release)
	if err != nil || *replayed != *released || len(fixture.fake.transactions) != transactionCount {
		t.Fatalf("release replay = %#v/%v txns=%d", replayed, err, len(fixture.fake.transactions))
	}
	mutated := release
	mutated.LeaseID = sessionControlTaskTestID(0x999)
	if _, err = fixture.store.ReleaseExactCloseTask(context.Background(), mutated); !errors.Is(err, errSessionControlCloseTaskConflict) {
		t.Fatalf("mutated cleared-lease replay error = %v", err)
	}
}

func TestDynamoSessionControlCloseTaskLeaseBusyAndExpiredTakeover(t *testing.T) {
	fixture := newSessionControlTaskFixture(t, 1)
	first := sessionControlTaskClaimRequest(fixture, 0x301)
	claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	second := sessionControlTaskClaimRequest(fixture, 0x401)
	if _, err = fixture.store.ClaimExactCloseTask(context.Background(), second); !errors.Is(err, errSessionControlCloseTaskBusy) {
		t.Fatalf("live takeover error = %v", err)
	}
	fixture.store.nowUTC = func() time.Time { return time.UnixMilli(claimed.LeaseExpiresAtMillis).UTC() }
	taken, err := fixture.store.ClaimExactCloseTask(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if taken.LeaseID != second.LeaseID || taken.TaskVersion != claimed.TaskVersion+1 ||
		taken.LeaseExpiresAtMillis != claimed.LeaseExpiresAtMillis+sessionControlCloseTaskLeaseDuration.Milliseconds() {
		t.Fatalf("taken task = %#v", taken)
	}
}

func TestDynamoSessionControlCloseTaskOwnerCursorFences(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*sessionControlOwnerAuthority)
		wantError error
	}{
		{name: "lower", mutate: func(owner *sessionControlOwnerAuthority) { owner.WorkVersion-- }, wantError: errSessionControlCloseTaskConflict},
		{name: "equal_count_mismatch", mutate: func(owner *sessionControlOwnerAuthority) { owner.TaskCount++ }, wantError: errSessionControlCloseTaskConflict},
		{name: "higher_descendant", mutate: func(owner *sessionControlOwnerAuthority) {
			owner.WorkVersion++
			owner.TaskCount++
			owner.PendingCount++
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newSessionControlTaskFixture(t, 1)
			owner, err := fixture.store.getOwner(context.Background(), fixture.task.CellID, fixture.task.ACID, fixture.task.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			tt.mutate(owner)
			seedSessionControlTaskOwner(t, fixture.fake, *owner)
			claimed, claimErr := fixture.store.ClaimExactCloseTask(context.Background(), sessionControlTaskClaimRequest(fixture, 0x501))
			if tt.wantError != nil {
				if !errors.Is(claimErr, tt.wantError) {
					t.Fatalf("claim error = %v, want %v", claimErr, tt.wantError)
				}
				return
			}
			if claimErr != nil || claimed.CurrentOwnerTaskCount != owner.TaskCount ||
				claimed.CurrentOwnerPendingCount != owner.PendingCount || claimed.CurrentOwnerWorkVersion != owner.WorkVersion+1 {
				t.Fatalf("descendant claim = %#v/%v", claimed, claimErr)
			}
		})
	}
}

func TestDynamoSessionControlCloseTaskTransitionAmbiguityAndCancellationBudget(t *testing.T) {
	t.Run("transport_committed", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		fixture.fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			applySessionControlMaterializationTransaction(fixture.fake, input)
			owner, ownerErr := fixture.store.getOwner(context.Background(), fixture.task.CellID, fixture.task.ACID, fixture.task.PublicKey)
			if ownerErr != nil {
				t.Fatal(ownerErr)
			}
			owner.WorkVersion++
			seedSessionControlTaskOwner(t, fixture.fake, *owner)
			return nil, errors.New("response lost")
		}
		claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), sessionControlTaskClaimRequest(fixture, 0x601))
		if err != nil || claimed.State != sessionControlCloseTaskStateLeased {
			t.Fatalf("transport classification = %#v/%v", claimed, err)
		}
	})
	t.Run("cancel_uses_aggregate_budget", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		fixture.store.operationTimeout = 30 * time.Millisecond
		fixture.fake.transactHook = func(ctx context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			<-ctx.Done()
			return nil, &types.TransactionCanceledException{}
		}
		started := time.Now()
		_, err := fixture.store.ClaimExactCloseTask(context.Background(), sessionControlTaskClaimRequest(fixture, 0x701))
		if !errors.Is(err, errSessionControlCloseTaskConflict) || time.Since(started) > 100*time.Millisecond {
			t.Fatalf("cancel result = %v after %v", err, time.Since(started))
		}
	})
}

func TestDynamoSessionControlCloseTaskAmbiguityRequiresOwnerAuthority(t *testing.T) {
	tests := []struct {
		name        string
		mutateOwner func(*sessionControlTaskFixture, sessionControlCloseTask)
		wantSuccess bool
	}{
		{name: "missing_owner", mutateOwner: func(fixture *sessionControlTaskFixture, _ sessionControlCloseTask) {
			fixture.fake.mu.Lock()
			delete(fixture.fake.items, sessionControlSessionDynamoMapKey(sessionControlOwnerKey(
				fixture.task.CellID, fixture.task.ACID, fixture.task.PublicKey)))
			fixture.fake.mu.Unlock()
		}},
		{name: "lower_cursor", mutateOwner: func(fixture *sessionControlTaskFixture, desired sessionControlCloseTask) {
			owner, err := fixture.store.getOwner(context.Background(), desired.CellID, desired.ACID, desired.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			owner.WorkVersion = desired.CurrentOwnerWorkVersion - 1
			seedSessionControlTaskOwner(t, fixture.fake, *owner)
		}},
		{name: "equal_count_mismatch", mutateOwner: func(fixture *sessionControlTaskFixture, desired sessionControlCloseTask) {
			owner, err := fixture.store.getOwner(context.Background(), desired.CellID, desired.ACID, desired.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			owner.TaskCount++
			seedSessionControlTaskOwner(t, fixture.fake, *owner)
		}},
		{name: "higher_descendant", wantSuccess: true, mutateOwner: func(fixture *sessionControlTaskFixture, desired sessionControlCloseTask) {
			owner, err := fixture.store.getOwner(context.Background(), desired.CellID, desired.ACID, desired.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			owner.WorkVersion++
			owner.TaskCount++
			owner.PendingCount++
			seedSessionControlTaskOwner(t, fixture.fake, *owner)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newSessionControlTaskFixture(t, 1)
			fixture.fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
				applySessionControlMaterializationTransaction(fixture.fake, input)
				row := input.TransactItems[len(input.TransactItems)-1].Put.Item
				desired, decodeErr := sessionControlCloseTaskFromItem(row, fixture.ownerPK, fixture.task.EventID)
				if decodeErr != nil {
					t.Fatal(decodeErr)
				}
				tt.mutateOwner(&fixture, desired)
				return nil, errors.New("response lost")
			}
			claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), sessionControlTaskClaimRequest(fixture, 0xa01))
			if tt.wantSuccess {
				if err != nil || claimed == nil || claimed.State != sessionControlCloseTaskStateLeased {
					t.Fatalf("classification = %#v/%v", claimed, err)
				}
			} else if err == nil {
				t.Fatalf("classification unexpectedly succeeded: %#v", claimed)
			}
		})
	}
}

func TestDynamoSessionControlDueCloseTaskDiscoveryAndCommittedRepair(t *testing.T) {
	fixture := newSessionControlTaskFixture(t, 1)
	shardText := strings.TrimPrefix(fixture.task.DueShard, fmt.Sprintf("CLOSETASK#%s#", fixture.task.CellID))
	var shard uint64
	if _, err := fmt.Sscanf(shardText, "%d", &shard); err != nil {
		t.Fatal(err)
	}
	installSessionControlTaskDueQuery(fixture.fake, false)
	page, err := fixture.store.ListDueNormalExactCloseTasksPage(context.Background(), fixture.task.CellID,
		shard, fixture.task.DueAtMillis, nil, 200)
	if err != nil || len(page.Tasks) != 1 || len(fixture.fake.queries) == 0 ||
		aws.ToInt32(fixture.fake.queries[len(fixture.fake.queries)-1].Limit) != sessionControlCloseTaskPageLimit {
		t.Fatalf("due page = %#v/%v", page, err)
	}

	installSessionControlTaskDueQuery(fixture.fake, true)
	omitted, err := fixture.store.ListDueNormalExactCloseTasksPage(context.Background(), fixture.task.CellID,
		shard, fixture.task.DueAtMillis, nil, 10)
	if err != nil || len(omitted.Tasks) != 0 {
		t.Fatalf("omitted GSI page = %#v/%v", omitted, err)
	}
	repaired, err := fixture.store.ListCommittedNormalExactCloseTasksPage(context.Background(), fixture.task.CellID,
		fixture.task.EventID, nil, 10)
	if err != nil || len(repaired.Tasks) != 1 || repaired.Tasks[0].CreationDigest != fixture.task.CreationDigest {
		t.Fatalf("committed repair page = %#v/%v", repaired, err)
	}
}

func TestDynamoSessionControlDueCloseTaskSkipsMissingAndPreTaskSetButRejectsMalformed(t *testing.T) {
	t.Run("pre_taskset", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		installSessionControlTaskDueQuery(fixture.fake, false)
		fixture.fake.mu.Lock()
		delete(fixture.fake.items, sessionControlSessionDynamoMapKey(sessionControlCloseTaskSetKey(fixture.task.EventID)))
		fixture.fake.mu.Unlock()
		shard := uint64(0)
		_, _ = fmt.Sscanf(strings.TrimPrefix(fixture.task.DueShard, fmt.Sprintf("CLOSETASK#%s#", fixture.task.CellID)), "%d", &shard)
		page, err := fixture.store.ListDueNormalExactCloseTasksPage(context.Background(), fixture.task.CellID,
			shard, fixture.task.DueAtMillis, nil, 10)
		if err != nil || len(page.Tasks) != 0 {
			t.Fatalf("pre-taskset page = %#v/%v", page, err)
		}
	})
	t.Run("missing_base", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		projected := map[string]types.AttributeValue{"pk": &types.AttributeValueMemberS{Value: fixture.ownerPK},
			"sk": &types.AttributeValueMemberS{Value: sessionControlCloseTaskSK(fixture.task.EventID)}}
		fixture.fake.queryHook = func(context.Context, *dynamodb.QueryInput, int) (*dynamodb.QueryOutput, error) {
			return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{projected}}, nil
		}
		fixture.fake.mu.Lock()
		delete(fixture.fake.items, sessionControlSessionDynamoMapKey(sessionControlCloseTaskKey(fixture.ownerPK, fixture.task.EventID)))
		fixture.fake.mu.Unlock()
		shard := uint64(0)
		_, _ = fmt.Sscanf(strings.TrimPrefix(fixture.task.DueShard, fmt.Sprintf("CLOSETASK#%s#", fixture.task.CellID)), "%d", &shard)
		page, err := fixture.store.ListDueNormalExactCloseTasksPage(context.Background(), fixture.task.CellID,
			shard, fixture.task.DueAtMillis, nil, 10)
		if err != nil || len(page.Tasks) != 0 {
			t.Fatalf("missing base page = %#v/%v", page, err)
		}
	})
	t.Run("malformed_existing", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		installSessionControlTaskDueQuery(fixture.fake, false)
		fixture.fake.mu.Lock()
		item := fixture.fake.items[sessionControlSessionDynamoMapKey(sessionControlCloseTaskKey(fixture.ownerPK, fixture.task.EventID))]
		item["lease_expires_at_ms"] = &types.AttributeValueMemberS{Value: "bad"}
		fixture.fake.mu.Unlock()
		shard := uint64(0)
		_, _ = fmt.Sscanf(strings.TrimPrefix(fixture.task.DueShard, fmt.Sprintf("CLOSETASK#%s#", fixture.task.CellID)), "%d", &shard)
		if _, err := fixture.store.ListDueNormalExactCloseTasksPage(context.Background(), fixture.task.CellID,
			shard, fixture.task.DueAtMillis, nil, 10); !errors.Is(err, errSessionControlCloseTaskCorrupt) {
			t.Fatalf("malformed existing error = %v", err)
		}
	})
}

func TestDynamoSessionControlCommittedCloseTaskTraversalPaginationAndMissingReference(t *testing.T) {
	fixture := newSessionControlTaskFixture(t, 49)
	var cursor *sessionControlCommittedCloseTaskCursor
	seen := 0
	for {
		page, err := fixture.store.ListCommittedNormalExactCloseTasksPage(context.Background(), fixture.close.Session.Candidate.CellID,
			fixture.close.EventID, cursor, 17)
		if err != nil {
			t.Fatal(err)
		}
		seen += len(page.Tasks)
		cursor = page.Next
		if cursor == nil {
			break
		}
	}
	if seen != 49 {
		t.Fatalf("committed traversal count = %d", seen)
	}
	fixture.fake.mu.Lock()
	delete(fixture.fake.items, sessionControlSessionDynamoMapKey(sessionControlCloseTaskKey(fixture.ownerPK, fixture.close.EventID)))
	fixture.fake.mu.Unlock()
	if _, err := fixture.store.ListCommittedNormalExactCloseTasksPage(context.Background(), fixture.close.Session.Candidate.CellID,
		fixture.close.EventID, nil, 100); !errors.Is(err, errSessionControlCloseTaskCorrupt) {
		t.Fatalf("missing committed reference error = %v", err)
	}
}

func TestDynamoSessionControlCommittedCloseTaskTraversalPreservesStrongReadTransportErrors(t *testing.T) {
	sentinel := errors.New("injected strong-read transport failure")
	tests := []struct {
		name string
		key  func(sessionControlTaskFixture) map[string]types.AttributeValue
	}{
		{name: "taskset", key: func(fixture sessionControlTaskFixture) map[string]types.AttributeValue {
			return sessionControlCloseTaskSetKey(fixture.close.EventID)
		}},
		{name: "work", key: func(fixture sessionControlTaskFixture) map[string]types.AttributeValue {
			return sessionControlCloseWorkKey(fixture.close.EventID)
		}},
		{name: "manifest", key: func(fixture sessionControlTaskFixture) map[string]types.AttributeValue {
			return sessionControlCloseManifestKey(fixture.close.EventID, 0)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newSessionControlTaskFixture(t, 1)
			failureKey := sessionControlSessionDynamoMapKey(tt.key(fixture))
			fixture.fake.getHook = func(ctx context.Context, input *dynamodb.GetItemInput, _ int) (*dynamodb.GetItemOutput, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if sessionControlSessionDynamoMapKey(input.Key) == failureKey {
					return nil, sentinel
				}
				fixture.fake.mu.Lock()
				defer fixture.fake.mu.Unlock()
				return &dynamodb.GetItemOutput{Item: fixture.fake.items[sessionControlSessionDynamoMapKey(input.Key)]}, nil
			}
			_, err := fixture.store.ListCommittedNormalExactCloseTasksPage(context.Background(),
				fixture.task.CellID, fixture.task.EventID, nil, 10)
			if !errors.Is(err, sentinel) || errors.Is(err, errSessionControlCloseTaskCorrupt) {
				t.Fatalf("traversal error = %v, want preserved transport failure", err)
			}
		})
	}
}

func TestSessionControlCloseTaskMutableStateValidationAndTokenBinding(t *testing.T) {
	fixture := newSessionControlTaskFixture(t, 1)
	request := sessionControlTaskClaimRequest(fixture, 0x801)
	claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*sessionControlCloseTask){
		func(task *sessionControlCloseTask) { task.LeaseExpiresAtMillis++ },
		func(task *sessionControlCloseTask) { task.LastOperationInputDigest = strings.Repeat("0", 64) },
		func(task *sessionControlCloseTask) { task.CurrentOwnerWorkVersion = task.OwnerAfter.WorkVersion },
		func(task *sessionControlCloseTask) { task.CurrentOwnerPendingCount = 0 },
	}
	for index, mutate := range mutations {
		copy := *claimed
		mutate(&copy)
		if validateSessionControlCloseTask(copy) == nil {
			t.Fatalf("mutation %d accepted", index)
		}
	}
	state, err := fixture.store.readCommittedCloseTask(context.Background(), fixture.ownerPK, fixture.task.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if err = fixture.store.bindCommittedCloseTaskOwner(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	nextOwner, err := planSessionControlOwnerTaskLeaseTransition(state.Owner, state.Task.UpdatedAtMillis)
	if err != nil {
		t.Fatal(err)
	}
	token, err := sessionControlCloseTaskTransitionToken(fixture.store.tableName, "claim", *state, state.Task, nextOwner)
	if err != nil {
		t.Fatal(err)
	}
	mutatedState := *state
	mutatedState.Task.LastOperationInputDigest = strings.Repeat("f", 64)
	mutated, err := sessionControlCloseTaskTransitionToken(fixture.store.tableName, "claim", mutatedState, state.Task, nextOwner)
	if err != nil || aws.ToString(token) == aws.ToString(mutated) || len(aws.ToString(mutated)) > 36 {
		t.Fatalf("tokens = %q/%q err=%v", aws.ToString(token), aws.ToString(mutated), err)
	}
}

func TestSessionControlCloseTaskOperationInputDigestBindsAddressedTask(t *testing.T) {
	fixture := newSessionControlTaskFixture(t, 1)
	request := sessionControlTaskClaimRequest(fixture, 0x901)
	base, err := sessionControlCloseTaskOperationInputDigest("release", request)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*sessionControlCloseTaskLeaseRequest){
		func(value *sessionControlCloseTaskLeaseRequest) { value.CellID = "other-cell" },
		func(value *sessionControlCloseTaskLeaseRequest) { value.EventID = sessionControlTaskTestID(0x902) },
		func(value *sessionControlCloseTaskLeaseRequest) {
			value.OwnerPK = sessionControlOwnerPK(value.CellID, "ac-other", fixture.task.PublicKey)
		},
	}
	for index, mutate := range mutations {
		copy := request
		mutate(&copy)
		digest, digestErr := sessionControlCloseTaskOperationInputDigest("release", copy)
		if digestErr != nil || digest == base {
			t.Fatalf("identity mutation %d digest = %q/%v", index, digest, digestErr)
		}
	}
}

func TestSessionControlCloseTaskTransactionTokenBindsEveryAuthorityMember(t *testing.T) {
	fixture := newSessionControlTaskFixture(t, 1)
	state, err := fixture.store.readCommittedCloseTask(context.Background(), fixture.ownerPK, fixture.task.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if err = fixture.store.bindCommittedCloseTaskOwner(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	nextOwner, err := planSessionControlOwnerTaskLeaseTransition(state.Owner, state.Owner.UpdatedAtMillis)
	if err != nil {
		t.Fatal(err)
	}
	nextTask := state.Task
	base, err := sessionControlCloseTaskTransitionToken(fixture.store.tableName, "claim", *state, nextTask, nextOwner)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func(*string, *string, *sessionControlCommittedTaskState, *sessionControlCloseTask, *sessionControlOwnerAuthority)
	}{
		{name: "table", mutate: func(table, _ *string, _ *sessionControlCommittedTaskState, _ *sessionControlCloseTask, _ *sessionControlOwnerAuthority) {
			*table += "-other"
		}},
		{name: "action", mutate: func(_, action *string, _ *sessionControlCommittedTaskState, _ *sessionControlCloseTask, _ *sessionControlOwnerAuthority) {
			*action = "release"
		}},
		{name: "task", mutate: func(_, _ *string, state *sessionControlCommittedTaskState, _ *sessionControlCloseTask, _ *sessionControlOwnerAuthority) {
			state.Task.UpdatedAtMillis++
		}},
		{name: "next_task", mutate: func(_, _ *string, _ *sessionControlCommittedTaskState, task *sessionControlCloseTask, _ *sessionControlOwnerAuthority) {
			task.UpdatedAtMillis++
		}},
		{name: "owner", mutate: func(_, _ *string, state *sessionControlCommittedTaskState, _ *sessionControlCloseTask, _ *sessionControlOwnerAuthority) {
			state.Owner.WorkVersion++
		}},
		{name: "next_owner", mutate: func(_, _ *string, _ *sessionControlCommittedTaskState, _ *sessionControlCloseTask, owner *sessionControlOwnerAuthority) {
			owner.WorkVersion++
		}},
		{name: "taskset", mutate: func(_, _ *string, state *sessionControlCommittedTaskState, _ *sessionControlCloseTask, _ *sessionControlOwnerAuthority) {
			state.TaskSet.CreatedAtMillis++
		}},
		{name: "manifest", mutate: func(_, _ *string, state *sessionControlCommittedTaskState, _ *sessionControlCloseTask, _ *sessionControlOwnerAuthority) {
			state.Manifest.CreatedAtMillis++
		}},
		{name: "work", mutate: func(_, _ *string, state *sessionControlCommittedTaskState, _ *sessionControlCloseTask, _ *sessionControlOwnerAuthority) {
			state.Work.CreatedAtMillis++
		}},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			table, action := fixture.store.tableName, "claim"
			stateCopy, taskCopy, ownerCopy := *state, nextTask, nextOwner
			tt.mutate(&table, &action, &stateCopy, &taskCopy, &ownerCopy)
			token, tokenErr := sessionControlCloseTaskTransitionToken(table, action, stateCopy, taskCopy, ownerCopy)
			if tokenErr != nil || aws.ToString(token) == aws.ToString(base) || len(aws.ToString(token)) > 36 {
				t.Fatalf("token = %q, base %q, err %v", aws.ToString(token), aws.ToString(base), tokenErr)
			}
		})
	}
}

func TestDynamoSessionControlRebindExactCloseTaskHigherGenerationAndReplay(t *testing.T) {
	for _, differentBoot := range []bool{false, true} {
		t.Run(fmt.Sprintf("different_boot_%t", differentBoot), func(t *testing.T) {
			fixture := newSessionControlTaskFixture(t, 1)
			lease := sessionControlTaskClaimRequest(fixture, 0xb01)
			claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), lease)
			if err != nil {
				t.Fatal(err)
			}
			bootID := claimed.BoundBootID
			if differentBoot {
				bootID = "fedcba9876543210fedcba9876543210"
			}
			target := installSessionControlTaskTargetGeneration(t, &fixture, claimed.BoundFlushGeneration+1, bootID)
			request := sessionControlTaskRebindRequest(fixture, target, 0xb11)
			before := len(fixture.fake.transactions)
			rebound, err := fixture.store.RebindExactCloseTask(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if rebound.State != sessionControlCloseTaskStatePending || rebound.TaskVersion != claimed.TaskVersion+1 ||
				rebound.BoundBootID != target.BootID || rebound.BoundFlushGeneration != target.FlushGeneration ||
				rebound.BoundTargetVersion != target.Version || rebound.BoundAuthorityVersion != target.AuthorityVersion ||
				rebound.BoundOwnerLifecycle == claimed.BoundOwnerLifecycle ||
				rebound.BoundActivatedCursor != target.ActivatedControlVersion ||
				rebound.BoundReadyCursor != target.ReadyControlVersion || rebound.LeaseID != "" ||
				rebound.DueAtMillis != rebound.UpdatedAtMillis || rebound.LastOperationInputDigest == "" ||
				rebound.CurrentOwnerTaskCount != claimed.CurrentOwnerTaskCount ||
				rebound.CurrentOwnerPendingCount != claimed.CurrentOwnerPendingCount {
				t.Fatalf("rebound task = %#v", rebound)
			}
			txn := fixture.fake.transactions[before]
			if len(txn.TransactItems) != 5 || len(aws.ToString(txn.ClientRequestToken)) > 36 ||
				txn.TransactItems[0].ConditionCheck == nil || txn.TransactItems[1].ConditionCheck == nil ||
				txn.TransactItems[2].ConditionCheck == nil || txn.TransactItems[3].Put == nil || txn.TransactItems[4].Put == nil {
				t.Fatalf("rebind transaction = %#v", txn)
			}
			transactionCount := len(fixture.fake.transactions)
			replay, err := fixture.store.RebindExactCloseTask(context.Background(), request)
			if err != nil || *replay != *rebound || len(fixture.fake.transactions) != transactionCount {
				t.Fatalf("rebind replay = %#v/%v txns=%d", replay, err, len(fixture.fake.transactions))
			}
		})
	}
}

func TestDynamoSessionControlRebindExactCloseTaskRejectsEqualLowerAndTornAuthority(t *testing.T) {
	t.Run("equal", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		target, err := fixture.store.getTarget(context.Background(), fixture.task.CreationTarget.key())
		if err != nil {
			t.Fatal(err)
		}
		_, err = fixture.store.RebindExactCloseTask(context.Background(), sessionControlTaskRebindRequest(fixture, *target, 0xc01))
		if !errors.Is(err, errSessionControlCloseTaskConflict) {
			t.Fatalf("equal-generation error = %v", err)
		}
	})
	t.Run("lower", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		target := installSessionControlTaskTargetGeneration(t, &fixture, fixture.task.BoundFlushGeneration-1,
			fixture.task.BoundBootID)
		_, err := fixture.store.RebindExactCloseTask(context.Background(), sessionControlTaskRebindRequest(fixture, target, 0xc11))
		if !errors.Is(err, errSessionControlCloseTaskConflict) {
			t.Fatalf("lower-generation error = %v", err)
		}
	})
	t.Run("equal_generation_different_boot", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		target := installSessionControlTaskTargetGeneration(t, &fixture, fixture.task.BoundFlushGeneration,
			"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
		_, err := fixture.store.RebindExactCloseTask(context.Background(), sessionControlTaskRebindRequest(fixture, target, 0xc19))
		if !errors.Is(err, errSessionControlCloseTaskConflict) {
			t.Fatalf("equal-generation/different-boot error = %v", err)
		}
	})
	t.Run("uncounted_target", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		target := installSessionControlTaskTargetGeneration(t, &fixture, fixture.task.BoundFlushGeneration+1,
			fixture.task.BoundBootID)
		target.State = sessionControlTargetCanceled
		target.CountedActiveSlot = false
		_, err := fixture.store.RebindExactCloseTask(context.Background(),
			sessionControlTaskRebindRequest(fixture, target, 0xc1d))
		if err == nil {
			t.Fatal("uncounted target was accepted")
		}
	})
	t.Run("torn_owner_target_retries", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		oldOwner, err := fixture.store.getOwner(context.Background(), fixture.task.CellID, fixture.task.ACID, fixture.task.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		target := installSessionControlTaskTargetGeneration(t, &fixture, fixture.task.BoundFlushGeneration+1,
			"0123456789abcdef0123456789abcdef")
		newOwner, err := fixture.store.getOwner(context.Background(), fixture.task.CellID, fixture.task.ACID, fixture.task.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		ownerKey := sessionControlSessionDynamoMapKey(sessionControlOwnerKey(fixture.task.CellID, fixture.task.ACID, fixture.task.PublicKey))
		oldRow, _ := sessionControlOwnerToRow(*oldOwner)
		newRow, _ := sessionControlOwnerToRow(*newOwner)
		oldItem := marshalSessionControlSessionTestRow(t, oldRow)
		newItem := marshalSessionControlSessionTestRow(t, newRow)
		ownerReads := 0
		fixture.fake.getHook = func(ctx context.Context, input *dynamodb.GetItemInput, _ int) (*dynamodb.GetItemOutput, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			key := sessionControlSessionDynamoMapKey(input.Key)
			if key == ownerKey {
				ownerReads++
				if ownerReads == 1 {
					return &dynamodb.GetItemOutput{Item: oldItem}, nil
				}
				return &dynamodb.GetItemOutput{Item: newItem}, nil
			}
			fixture.fake.mu.Lock()
			defer fixture.fake.mu.Unlock()
			return &dynamodb.GetItemOutput{Item: fixture.fake.items[key]}, nil
		}
		rebound, err := fixture.store.RebindExactCloseTask(context.Background(), sessionControlTaskRebindRequest(fixture, target, 0xc21))
		if err != nil || rebound.BoundFlushGeneration != target.FlushGeneration || ownerReads < 4 {
			t.Fatalf("torn rebind = %#v/%v ownerReads=%d", rebound, err, ownerReads)
		}
	})
}

func TestDynamoSessionControlAckExactCloseTaskStoresFirstResultAndReturnsReady(t *testing.T) {
	fixture := newSessionControlTaskFixture(t, 1)
	lease := sessionControlTaskClaimRequest(fixture, 0xd01)
	claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	ackRequest := sessionControlTaskAckRequest(fixture, *claimed, lease, 0)
	before := len(fixture.fake.transactions)
	acked, err := fixture.store.AckExactCloseTask(context.Background(), ackRequest)
	if err != nil {
		t.Fatal(err)
	}
	if acked.State != sessionControlCloseTaskStateAcked || acked.AckClosed != 0 || acked.TaskVersion != claimed.TaskVersion+1 ||
		acked.LeaseID != "" || acked.DueAtMillis != 0 || acked.DueShard != "" || acked.DueSort != "" ||
		acked.AckAuthenticatedPublicKey != claimed.PublicKey || acked.AckSelectorDigest != claimed.SelectorDigest ||
		acked.AckBootID != claimed.BoundBootID || acked.AckFlushGeneration != claimed.BoundFlushGeneration ||
		acked.AckLeaseID != lease.LeaseID || acked.AckLeaseOwner != lease.LeaseOwner ||
		acked.CurrentOwnerPendingCount != 0 {
		t.Fatalf("acked task = %#v", acked)
	}
	owner, err := fixture.store.getOwner(context.Background(), acked.CellID, acked.ACID, acked.PublicKey)
	if err != nil || owner.Phase != sessionControlOwnerReady || owner.PendingCount != 0 {
		t.Fatalf("ready owner = %#v/%v", owner, err)
	}
	txn := fixture.fake.transactions[before]
	if len(txn.TransactItems) != 5 || len(aws.ToString(txn.ClientRequestToken)) > 36 ||
		txn.TransactItems[0].ConditionCheck == nil || txn.TransactItems[1].ConditionCheck == nil ||
		txn.TransactItems[2].ConditionCheck == nil || txn.TransactItems[3].Put == nil || txn.TransactItems[4].Put == nil {
		t.Fatalf("ack transaction = %#v", txn)
	}
	transactionCount := len(fixture.fake.transactions)
	ackRequest.Ack.Closed = 99
	replay, err := fixture.store.AckExactCloseTask(context.Background(), ackRequest)
	if err != nil || *replay != *acked || replay.AckClosed != 0 || len(fixture.fake.transactions) != transactionCount {
		t.Fatalf("different-diagnostic replay = %#v/%v txns=%d", replay, err, len(fixture.fake.transactions))
	}
}

func TestDynamoSessionControlAckExactCloseTaskAcceptsExpiredExactLease(t *testing.T) {
	fixture := newSessionControlTaskFixture(t, 1)
	lease := sessionControlTaskClaimRequest(fixture, 0xd11)
	claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	fixture.store.nowUTC = func() time.Time {
		return time.UnixMilli(claimed.LeaseExpiresAtMillis + time.Minute.Milliseconds()).UTC()
	}
	acked, err := fixture.store.AckExactCloseTask(context.Background(), sessionControlTaskAckRequest(fixture, *claimed, lease, 7))
	if err != nil || acked.AckClosed != 7 || acked.AckedAtMillis <= claimed.LeaseExpiresAtMillis {
		t.Fatalf("expired exact lease ACK = %#v/%v", acked, err)
	}
}

func TestDynamoSessionControlAckExactCloseTaskRejectsEveryIdentityMutation(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*sessionControlCloseTaskAckRequest)
	}{
		{name: "cell", mutate: func(value *sessionControlCloseTaskAckRequest) { value.Lease.CellID = "other-cell" }},
		{name: "event", mutate: func(value *sessionControlCloseTaskAckRequest) { value.Ack.EventID = sessionControlTaskTestID(0xe01) }},
		{name: "owner", mutate: func(value *sessionControlCloseTaskAckRequest) {
			value.Lease.OwnerPK = sessionControlOwnerPK(value.Lease.CellID, "other-ac", value.AuthenticatedPublicKey)
		}},
		{name: "lease", mutate: func(value *sessionControlCloseTaskAckRequest) { value.Lease.LeaseID = sessionControlTaskTestID(0xe02) }},
		{name: "lease_owner", mutate: func(value *sessionControlCloseTaskAckRequest) {
			value.Lease.LeaseOwner = sessionControlTaskTestID(0xe03)
		}},
		{name: "authenticated_public_key", mutate: func(value *sessionControlCloseTaskAckRequest) {
			value.AuthenticatedPublicKey = testSessionControlTargetCandidate(0xee, "00112233445566778899aabbccddeeff", 1).PublicKey
		}},
		{name: "selector_agent", mutate: func(value *sessionControlCloseTaskAckRequest) {
			value.Ack.AgentPublicKey = testSessionControlSessionCandidate(0xef, 1902).AgentPublicKey
		}},
		{name: "selector_session", mutate: func(value *sessionControlCloseTaskAckRequest) { value.Ack.SessionID++ }},
		{name: "selector_issued", mutate: func(value *sessionControlCloseTaskAckRequest) { value.Ack.SessionIssuedAtMillis++ }},
		{name: "boot", mutate: func(value *sessionControlCloseTaskAckRequest) { value.Ack.BootID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }},
		{name: "generation", mutate: func(value *sessionControlCloseTaskAckRequest) { value.Ack.FlushGeneration++ }},
		{name: "kind", mutate: func(value *sessionControlCloseTaskAckRequest) { value.Ack.Kind = "other" }},
		{name: "scope", mutate: func(value *sessionControlCloseTaskAckRequest) { value.Ack.Scope = common.ACSessionCloseScopeAgent }},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newSessionControlTaskFixture(t, 1)
			lease := sessionControlTaskClaimRequest(fixture, 0xe11)
			claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), lease)
			if err != nil {
				t.Fatal(err)
			}
			request := sessionControlTaskAckRequest(fixture, *claimed, lease, 1)
			tt.mutate(&request)
			if _, err = fixture.store.AckExactCloseTask(context.Background(), request); err == nil {
				t.Fatal("mutated ACK was accepted")
			}
		})
	}
}

func TestDynamoSessionControlAckExactCloseTaskRejectsStolenReleasedAndReboundLease(t *testing.T) {
	t.Run("stolen", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		oldLease := sessionControlTaskClaimRequest(fixture, 0xf01)
		oldTask, err := fixture.store.ClaimExactCloseTask(context.Background(), oldLease)
		if err != nil {
			t.Fatal(err)
		}
		fixture.store.nowUTC = func() time.Time { return time.UnixMilli(oldTask.LeaseExpiresAtMillis).UTC() }
		if _, err = fixture.store.ClaimExactCloseTask(context.Background(), sessionControlTaskClaimRequest(fixture, 0xf11)); err != nil {
			t.Fatal(err)
		}
		if _, err = fixture.store.AckExactCloseTask(context.Background(), sessionControlTaskAckRequest(fixture, *oldTask, oldLease, 1)); !errors.Is(err, errSessionControlCloseTaskConflict) {
			t.Fatalf("stolen ACK error = %v", err)
		}
	})
	t.Run("released", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		lease := sessionControlTaskClaimRequest(fixture, 0xf21)
		claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), lease)
		if err != nil {
			t.Fatal(err)
		}
		release := lease
		release.OperationID = sessionControlTaskTestID(0xf22)
		if _, err = fixture.store.ReleaseExactCloseTask(context.Background(), release); err != nil {
			t.Fatal(err)
		}
		if _, err = fixture.store.AckExactCloseTask(context.Background(), sessionControlTaskAckRequest(fixture, *claimed, lease, 1)); !errors.Is(err, errSessionControlCloseTaskConflict) {
			t.Fatalf("released ACK error = %v", err)
		}
	})
	t.Run("rebound", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		lease := sessionControlTaskClaimRequest(fixture, 0xf31)
		claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), lease)
		if err != nil {
			t.Fatal(err)
		}
		target := installSessionControlTaskTargetGeneration(t, &fixture, claimed.BoundFlushGeneration+1,
			"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		if _, err = fixture.store.RebindExactCloseTask(context.Background(), sessionControlTaskRebindRequest(fixture, target, 0xf32)); err != nil {
			t.Fatal(err)
		}
		if _, err = fixture.store.AckExactCloseTask(context.Background(), sessionControlTaskAckRequest(fixture, *claimed, lease, 1)); !errors.Is(err, errSessionControlCloseTaskConflict) {
			t.Fatalf("rebound ACK error = %v", err)
		}
	})
}

func TestDynamoSessionControlAckExactCloseTaskKeepsActiveUnreadyWithSiblingPending(t *testing.T) {
	fixture := newSessionControlTaskFixture(t, 1)
	lease := sessionControlTaskClaimRequest(fixture, 0x1011)
	claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := fixture.store.getOwner(context.Background(), claimed.CellID, claimed.ACID, claimed.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	owner.WorkVersion++
	owner.TaskCount++
	owner.PendingCount++
	seedSessionControlTaskOwner(t, fixture.fake, *owner)
	acked, err := fixture.store.AckExactCloseTask(context.Background(), sessionControlTaskAckRequest(fixture, *claimed, lease, 2))
	if err != nil {
		t.Fatal(err)
	}
	currentOwner, err := fixture.store.getOwner(context.Background(), claimed.CellID, claimed.ACID, claimed.PublicKey)
	if err != nil || currentOwner.Phase != sessionControlOwnerActiveUnready || currentOwner.PendingCount != 1 ||
		acked.CurrentOwnerPendingCount != 1 || acked.CurrentOwnerTaskCount != 2 {
		t.Fatalf("sibling owner/task = %#v/%#v/%v", currentOwner, acked, err)
	}
}

func TestDynamoSessionControlAckExactCloseTaskPreservesRequiredCatchUpPhase(t *testing.T) {
	tests := []struct {
		name      string
		activate  bool
		wantPhase sessionControlOwnerPhase
	}{
		{name: "preparing", wantPhase: sessionControlOwnerPreparing},
		{name: "active_unready", activate: true, wantPhase: sessionControlOwnerActiveUnready},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newSessionControlTaskFixture(t, 1)
			oldLease := sessionControlTaskClaimRequest(fixture, 0x1051)
			claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), oldLease)
			if err != nil {
				t.Fatal(err)
			}
			target := installSessionControlTaskTargetGeneration(t, &fixture,
				claimed.BoundFlushGeneration+1, "abcdefabcdefabcdefabcdefabcdefab")
			if tt.activate {
				target = activateSessionControlTaskTargetUnready(t, &fixture, target)
			}
			rebound, err := fixture.store.RebindExactCloseTask(context.Background(),
				sessionControlTaskRebindRequest(fixture, target, 0x1061))
			if err != nil {
				t.Fatal(err)
			}
			lease := sessionControlTaskClaimRequest(fixture, 0x1071)
			leased, err := fixture.store.ClaimExactCloseTask(context.Background(), lease)
			if err != nil {
				t.Fatal(err)
			}
			acked, err := fixture.store.AckExactCloseTask(context.Background(),
				sessionControlTaskAckRequest(fixture, *leased, lease, 0))
			if err != nil {
				t.Fatal(err)
			}
			owner, err := fixture.store.getOwner(context.Background(), acked.CellID, acked.ACID, acked.PublicKey)
			if err != nil || owner.Phase != tt.wantPhase || owner.PendingCount != 0 ||
				owner.ReadyControlVersion != 0 || acked.BoundFlushGeneration != target.FlushGeneration ||
				rebound.BoundOwnerLifecycle != owner.LifecycleVersion {
				t.Fatalf("catch-up ACK = task %#v owner %#v err %v", acked, owner, err)
			}
		})
	}
}

func TestDynamoSessionControlRebindAndAckAmbiguityClassification(t *testing.T) {
	t.Run("rebind_transport_committed", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		target := installSessionControlTaskTargetGeneration(t, &fixture, fixture.task.BoundFlushGeneration+1,
			"cccccccccccccccccccccccccccccccc")
		fixture.fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			applySessionControlMaterializationTransaction(fixture.fake, input)
			owner, ownerErr := fixture.store.getOwner(context.Background(), fixture.task.CellID, fixture.task.ACID, fixture.task.PublicKey)
			if ownerErr != nil {
				t.Fatal(ownerErr)
			}
			owner.WorkVersion++
			seedSessionControlTaskOwner(t, fixture.fake, *owner)
			return nil, errors.New("response lost")
		}
		rebound, err := fixture.store.RebindExactCloseTask(context.Background(), sessionControlTaskRebindRequest(fixture, target, 0x1111))
		if err != nil || rebound.BoundFlushGeneration != target.FlushGeneration {
			t.Fatalf("rebind transport classification = %#v/%v", rebound, err)
		}
	})
	t.Run("rebind_cancel_aggregate", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		target := installSessionControlTaskTargetGeneration(t, &fixture, fixture.task.BoundFlushGeneration+1,
			"dddddddddddddddddddddddddddddddd")
		fixture.store.operationTimeout = 30 * time.Millisecond
		fixture.fake.transactHook = func(ctx context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			<-ctx.Done()
			return nil, &types.TransactionCanceledException{}
		}
		started := time.Now()
		_, err := fixture.store.RebindExactCloseTask(context.Background(), sessionControlTaskRebindRequest(fixture, target, 0x1121))
		if !errors.Is(err, errSessionControlCloseTaskConflict) || time.Since(started) > 100*time.Millisecond {
			t.Fatalf("rebind cancel = %v after %v", err, time.Since(started))
		}
	})
	t.Run("ack_transport_committed_with_sibling_descendant", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		lease := sessionControlTaskClaimRequest(fixture, 0x1131)
		claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), lease)
		if err != nil {
			t.Fatal(err)
		}
		fixture.fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			applySessionControlMaterializationTransaction(fixture.fake, input)
			owner, ownerErr := fixture.store.getOwner(context.Background(), claimed.CellID, claimed.ACID, claimed.PublicKey)
			if ownerErr != nil {
				t.Fatal(ownerErr)
			}
			owner.WorkVersion++
			owner.TaskCount++
			seedSessionControlTaskOwner(t, fixture.fake, *owner)
			return nil, errors.New("response lost")
		}
		acked, err := fixture.store.AckExactCloseTask(context.Background(), sessionControlTaskAckRequest(fixture, *claimed, lease, 3))
		if err != nil || acked.State != sessionControlCloseTaskStateAcked {
			t.Fatalf("ack transport classification = %#v/%v", acked, err)
		}
	})
	t.Run("ack_cancel_aggregate", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		lease := sessionControlTaskClaimRequest(fixture, 0x1141)
		claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), lease)
		if err != nil {
			t.Fatal(err)
		}
		fixture.store.operationTimeout = 30 * time.Millisecond
		fixture.fake.transactHook = func(ctx context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			<-ctx.Done()
			return nil, &types.TransactionCanceledException{}
		}
		started := time.Now()
		_, err = fixture.store.AckExactCloseTask(context.Background(), sessionControlTaskAckRequest(fixture, *claimed, lease, 4))
		if !errors.Is(err, errSessionControlCloseTaskConflict) || time.Since(started) > 100*time.Millisecond {
			t.Fatalf("ack cancel = %v after %v", err, time.Since(started))
		}
	})
	t.Run("ack_retries_after_concurrent_sibling_wins_owner_cas", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		lease := sessionControlTaskClaimRequest(fixture, 0x1151)
		claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), lease)
		if err != nil {
			t.Fatal(err)
		}
		fixture.fake.transactHook = func(_ context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			owner, ownerErr := fixture.store.getOwner(context.Background(), claimed.CellID, claimed.ACID, claimed.PublicKey)
			if ownerErr != nil {
				t.Fatal(ownerErr)
			}
			owner.WorkVersion++
			owner.TaskCount++
			owner.PendingCount++
			seedSessionControlTaskOwner(t, fixture.fake, *owner)
			return nil, &types.TransactionCanceledException{}
		}
		request := sessionControlTaskAckRequest(fixture, *claimed, lease, 5)
		if _, err = fixture.store.AckExactCloseTask(context.Background(), request); !errors.Is(err, errSessionControlCloseTaskConflict) {
			t.Fatalf("concurrent sibling CAS error = %v", err)
		}
		fixture.fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			applySessionControlMaterializationTransaction(fixture.fake, input)
			return &dynamodb.TransactWriteItemsOutput{}, nil
		}
		acked, err := fixture.store.AckExactCloseTask(context.Background(), request)
		if err != nil || acked.State != sessionControlCloseTaskStateAcked ||
			acked.CurrentOwnerTaskCount != 2 || acked.CurrentOwnerPendingCount != 1 {
			t.Fatalf("concurrent sibling retry = %#v/%v", acked, err)
		}
		owner, err := fixture.store.getOwner(context.Background(), claimed.CellID, claimed.ACID, claimed.PublicKey)
		if err != nil || owner.Phase != sessionControlOwnerActiveUnready || owner.PendingCount != 1 {
			t.Fatalf("concurrent sibling owner = %#v/%v", owner, err)
		}
	})
}

func TestSessionControlCloseTaskAckedRowStrictPresenceAndStateValidation(t *testing.T) {
	fixture := newSessionControlTaskFixture(t, 1)
	lease := sessionControlTaskClaimRequest(fixture, 0x1211)
	claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	acked, err := fixture.store.AckExactCloseTask(context.Background(), sessionControlTaskAckRequest(fixture, *claimed, lease, 0))
	if err != nil {
		t.Fatal(err)
	}
	row, err := sessionControlCloseTaskToRow(*acked)
	if err != nil {
		t.Fatal(err)
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		t.Fatal(err)
	}
	closed, ok := item["ack_closed"].(*types.AttributeValueMemberN)
	if !ok || closed.Value != "0" {
		t.Fatalf("zero closed attribute = %#v", item["ack_closed"])
	}
	for _, name := range []string{"due_at_ms", "due_shard", "due_sort", "lease_id", "lease_owner", "lease_expires_at_ms"} {
		if _, present := item[name]; present {
			t.Fatalf("ACKed row retained %s: %#v", name, item[name])
		}
	}
	for _, name := range []string{"ack_authenticated_public_key", "ack_selector_digest", "ack_boot_id",
		"ack_flush_generation", "ack_closed", "ack_lease_id", "ack_lease_owner", "acked_at_ms"} {
		copy := make(map[string]types.AttributeValue, len(item))
		for key, value := range item {
			copy[key] = value
		}
		delete(copy, name)
		if _, decodeErr := sessionControlCloseTaskFromItem(copy, acked.OwnerPK, acked.EventID); !errors.Is(decodeErr, errSessionControlMaterializationCorrupt) {
			t.Fatalf("missing %s error = %v", name, decodeErr)
		}
	}
	for _, name := range []string{"due_at_ms", "due_shard", "due_sort", "lease_id", "lease_owner", "lease_expires_at_ms"} {
		copy := make(map[string]types.AttributeValue, len(item)+1)
		for key, value := range item {
			copy[key] = value
		}
		copy[name] = &types.AttributeValueMemberS{Value: "unexpected"}
		if _, decodeErr := sessionControlCloseTaskFromItem(copy, acked.OwnerPK, acked.EventID); !errors.Is(decodeErr, errSessionControlMaterializationCorrupt) {
			t.Fatalf("unexpected %s error = %v", name, decodeErr)
		}
	}
	mutations := []func(*sessionControlCloseTask){
		func(task *sessionControlCloseTask) {
			task.AckAuthenticatedPublicKey = fixture.close.Session.Candidate.AgentPublicKey
		},
		func(task *sessionControlCloseTask) { task.AckSelectorDigest = strings.Repeat("0", 64) },
		func(task *sessionControlCloseTask) { task.AckBootID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
		func(task *sessionControlCloseTask) { task.AckedAtMillis-- },
		func(task *sessionControlCloseTask) { task.DueAtMillis = task.UpdatedAtMillis },
	}
	for index, mutate := range mutations {
		copy := *acked
		mutate(&copy)
		if validateSessionControlCloseTask(copy) == nil {
			t.Fatalf("acked state mutation %d accepted", index)
		}
	}
}
