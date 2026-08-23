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
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/OpenNHP/opennhp/nhp/common"
)

type sessionControlOwnerSnapshotFixture struct {
	fake     *sessionControlSessionDynamoFake
	store    *dynamoSessionControlStore
	target   sessionControlTargetAuthority
	ownerPK  string
	eventIDs []string
}

func installSessionControlOwnerTaskQuery(fake *sessionControlSessionDynamoFake) {
	installSessionControlOwnerTaskQueryPageLimit(fake, 0)
}

func installSessionControlOwnerTaskQueryPageLimit(fake *sessionControlSessionDynamoFake, forcedPageLimit int) {
	fake.queryHook = func(ctx context.Context, input *dynamodb.QueryInput, _ int) (*dynamodb.QueryOutput, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pk, _ := input.ExpressionAttributeValues[":pk"].(*types.AttributeValueMemberS)
		prefix, _ := input.ExpressionAttributeValues[":task_prefix"].(*types.AttributeValueMemberS)
		if pk == nil || prefix == nil || prefix.Value != sessionControlCloseTaskSKPrefix ||
			!aws.ToBool(input.ConsistentRead) || input.IndexName != nil ||
			aws.ToString(input.KeyConditionExpression) != "pk = :pk AND begins_with(sk, :task_prefix)" {
			return nil, errors.New("malformed owner-task query")
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		keys := make([]string, 0)
		for key, item := range fake.items {
			itemPK, _ := item["pk"].(*types.AttributeValueMemberS)
			itemSK, _ := item["sk"].(*types.AttributeValueMemberS)
			if itemPK != nil && itemSK != nil && itemPK.Value == pk.Value && strings.HasPrefix(itemSK.Value, prefix.Value) {
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
		if forcedPageLimit > 0 && forcedPageLimit < limit {
			limit = forcedPageLimit
		}
		items := make([]map[string]types.AttributeValue, 0, limit)
		for _, key := range keys[start : start+limit] {
			items = append(items, fake.items[key])
		}
		var last map[string]types.AttributeValue
		if start+limit < len(keys) && limit > 0 {
			item := fake.items[keys[start+limit-1]]
			last = map[string]types.AttributeValue{"pk": item["pk"], "sk": item["sk"]}
		}
		return &dynamodb.QueryOutput{Items: items, LastEvaluatedKey: last}, nil
	}
}

func newSessionControlOwnerSnapshotFixture(t *testing.T, taskCount int) sessionControlOwnerSnapshotFixture {
	t.Helper()
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, 10*time.Second)
	installSessionControlMaterializationQuery(t, fake)
	fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		applySessionControlMaterializationTransaction(fake, input)
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}
	target := testSessionControlSessionTarget(0x81)
	seedSessionControlTarget(t, fake, target)
	fixture := sessionControlOwnerSnapshotFixture{fake: fake, store: store, target: target,
		ownerPK: sessionControlOwnerPK(target.ControlCellID, target.ACID, target.PublicKey)}
	snapshot := testSessionControlSessionSnapshot(target.ActivatedControlVersion)
	candidates := make([]sessionControlSessionCandidate, 0, taskCount)
	intents := make([]sessionControlSessionIntentPreparation, 0, taskCount)
	for index := 0; index < taskCount; index++ {
		candidate := testSessionControlSessionCandidate(byte(0x91+index), uint64(4_100+index))
		reserved, err := planSessionControlReservation(candidate, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		expires := candidate.IssuedAtMillis + time.Hour.Milliseconds()
		intent, err := planSessionControlIntent(reserved.fence(), target, expires, expires+time.Hour.Milliseconds(), snapshot)
		if err != nil {
			t.Fatal(err)
		}
		seedSessionControlReservation(t, fake, intent.Session)
		seedSessionControlIntent(t, fake, intent.Intent)
		candidates = append(candidates, candidate)
		intents = append(intents, intent)
	}
	directory := sessionControlCloseTestDirectory(snapshot, store.nowUTC().UnixMilli()-1_000)
	for index, intent := range intents {
		close := expectedSessionControlExactClose(t, intent.Session, directory, store.nowUTC().UnixMilli(),
			intent.Session.RetainUntilMillis)
		seedCommittedSessionControlExactClose(t, fake, directory, close)
		if _, err := store.MaterializeNormalExactClose(context.Background(), candidates[index], close.EventID); err != nil {
			t.Fatalf("materialize task %d: %v", index, err)
		}
		fixture.eventIDs = append(fixture.eventIDs, close.EventID)
		directory.Version++
		directory.ActiveFenceCount++
		directory.UpdatedAtMillis = close.Work.CreatedAtMillis
	}
	installSessionControlOwnerTaskQuery(fake)
	return fixture
}

func ackSessionControlOwnerSnapshotTask(t *testing.T, fixture *sessionControlOwnerSnapshotFixture, index int) {
	t.Helper()
	eventID := fixture.eventIDs[index]
	task, err := fixture.store.getCloseTask(context.Background(), fixture.ownerPK, eventID)
	if err != nil {
		t.Fatal(err)
	}
	lease := sessionControlCloseTaskLeaseRequest{CellID: task.CellID, EventID: eventID, OwnerPK: fixture.ownerPK,
		OperationID: sessionControlTaskTestID(0x800 + uint64(index)*10),
		LeaseID:     sessionControlTaskTestID(0x801 + uint64(index)*10),
		LeaseOwner:  sessionControlTaskTestID(0x802 + uint64(index)*10)}
	claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	work, err := fixture.store.getCloseWork(context.Background(), task.CellID, eventID, false)
	if err != nil {
		t.Fatal(err)
	}
	request := sessionControlCloseTaskAckRequest{Lease: lease, AuthenticatedPublicKey: claimed.PublicKey,
		Ack: common.ACSessionCloseAckMsg{Kind: common.ACSessionCloseKind, Scope: common.ACSessionCloseScopeExact,
			EventID: eventID, AgentPublicKey: work.Selector.AgentPublicKey, SessionID: work.Selector.SessionID,
			SessionIssuedAtMillis: work.Selector.SessionIssuedMillis, BootID: claimed.BoundBootID,
			FlushGeneration: claimed.BoundFlushGeneration, Closed: 1}}
	if _, err = fixture.store.AckExactCloseTask(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}

func TestDynamoSessionControlOwnerTaskSnapshotEmptyAndPendingAckedParity(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		fixture := newSessionControlOwnerSnapshotFixture(t, 0)
		snapshot, err := fixture.store.SnapshotOwnerExactCloseTasks(context.Background(), fixture.target.ControlCellID,
			fixture.target.ACID, fixture.target.PublicKey)
		if err != nil || len(snapshot.Tasks) != 0 || snapshot.Owner.TaskCount != 0 || snapshot.Owner.PendingCount != 0 {
			t.Fatalf("empty snapshot = %#v, %v", snapshot, err)
		}
		if len(fixture.fake.queries) != 1 || !aws.ToBool(fixture.fake.queries[0].ConsistentRead) {
			t.Fatalf("queries = %#v", fixture.fake.queries)
		}
	})
	t.Run("pending_and_acked", func(t *testing.T) {
		fixture := newSessionControlOwnerSnapshotFixture(t, 2)
		ackSessionControlOwnerSnapshotTask(t, &fixture, 0)
		installSessionControlOwnerTaskQueryPageLimit(fixture.fake, 1)
		fixture.fake.queries = nil
		snapshot, err := fixture.store.SnapshotOwnerExactCloseTasks(context.Background(), fixture.target.ControlCellID,
			fixture.target.ACID, fixture.target.PublicKey)
		if err != nil || len(snapshot.Tasks) != 2 || snapshot.Owner.TaskCount != 2 || snapshot.Owner.PendingCount != 1 {
			t.Fatalf("mixed snapshot = %#v, %v", snapshot, err)
		}
		states := map[string]int{}
		for _, entry := range snapshot.Tasks {
			states[entry.Task.State]++
			if entry.OwnerPK != fixture.ownerPK || entry.EventID != entry.Task.EventID ||
				entry.Work.EventID != entry.EventID || entry.Work.Selector.Scope != sessionControlFenceSelectorExact {
				t.Fatalf("delivery entry = %#v", entry)
			}
		}
		if states[sessionControlCloseTaskStatePending] != 1 || states[sessionControlCloseTaskStateAcked] != 1 {
			t.Fatalf("task states = %#v", states)
		}
		if len(fixture.fake.queries) != 2 {
			t.Fatalf("paginated query count = %d, want 2", len(fixture.fake.queries))
		}
	})
}

func TestDynamoSessionControlOwnerTaskSnapshotRetriesTornBracket(t *testing.T) {
	fixture := newSessionControlOwnerSnapshotFixture(t, 1)
	owner, err := fixture.store.getOwner(context.Background(), fixture.target.ControlCellID,
		fixture.target.ACID, fixture.target.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	transient := *owner
	transient.WorkVersion++
	transientRow, err := sessionControlOwnerToRow(transient)
	if err != nil {
		t.Fatal(err)
	}
	transientItem := marshalSessionControlSessionTestRow(t, transientRow)
	ownerKey := sessionControlSessionDynamoMapKey(sessionControlOwnerKey(owner.CellID, owner.ACID, owner.PublicKey))
	ownerReads := 0
	fixture.fake.getHook = func(ctx context.Context, input *dynamodb.GetItemInput, _ int) (*dynamodb.GetItemOutput, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := sessionControlSessionDynamoMapKey(input.Key)
		if key == ownerKey {
			ownerReads++
			if ownerReads == 2 {
				return &dynamodb.GetItemOutput{Item: transientItem}, nil
			}
		}
		fixture.fake.mu.Lock()
		item := fixture.fake.items[key]
		fixture.fake.mu.Unlock()
		return &dynamodb.GetItemOutput{Item: item}, nil
	}
	queriesBefore := len(fixture.fake.queries)
	snapshot, err := fixture.store.SnapshotOwnerExactCloseTasks(context.Background(), owner.CellID, owner.ACID, owner.PublicKey)
	if err != nil || len(snapshot.Tasks) != 1 || len(fixture.fake.queries)-queriesBefore != 2 {
		t.Fatalf("retried snapshot = %#v, %v; owner queries=%d", snapshot, err,
			len(fixture.fake.queries)-queriesBefore)
	}
}

func TestDynamoSessionControlOwnerTaskSnapshotEnumeratesOlderBindingForRebind(t *testing.T) {
	fixture := newSessionControlOwnerSnapshotFixture(t, 1)
	currentTarget, err := fixture.store.getTarget(context.Background(), fixture.target.key())
	if err != nil {
		t.Fatal(err)
	}
	currentOwner, err := fixture.store.getOwner(context.Background(), fixture.target.ControlCellID,
		fixture.target.ACID, fixture.target.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	next := *currentTarget
	next.BootID = "abcdefabcdefabcdefabcdefabcdefab"
	next.FlushGeneration++
	next.State = sessionControlTargetPreparing
	next.Version++
	next.ActivatedControlVersion, next.ReadyControlVersion = 0, 0
	next.AAKEnqueuedAtMillis, next.AAKTransactionID, next.RetiredAtMillis = 0, 0, 0
	next.PreparedAtMillis = max(next.UpdatedAtMillis, fixture.store.nowUTC().UnixMilli())
	next.UpdatedAtMillis = next.PreparedAtMillis
	nextOwner, err := sessionControlOwnerFromTarget(next, currentOwner, sessionControlOwnerPreparing)
	if err != nil {
		t.Fatal(err)
	}
	targetRow, err := sessionControlTargetToRow(next)
	if err != nil {
		t.Fatal(err)
	}
	fixture.fake.setItem(marshalSessionControlSessionTestRow(t, targetRow))
	seedSessionControlTaskOwner(t, fixture.fake, nextOwner)

	snapshot, err := fixture.store.SnapshotOwnerExactCloseTasks(context.Background(), next.ControlCellID,
		next.ACID, next.PublicKey)
	if err != nil || len(snapshot.Tasks) != 1 || snapshot.Tasks[0].Task.BoundFlushGeneration >= next.FlushGeneration {
		t.Fatalf("new-generation snapshot = %#v, %v", snapshot, err)
	}
	rebound, err := fixture.store.RebindExactCloseTask(context.Background(), sessionControlCloseTaskRebindRequest{
		CellID: next.ControlCellID, EventID: fixture.eventIDs[0], OwnerPK: fixture.ownerPK,
		OperationID: sessionControlTaskTestID(0x8f1), Target: next,
	})
	if err != nil || rebound.BoundBootID != next.BootID || rebound.BoundFlushGeneration != next.FlushGeneration ||
		rebound.State != sessionControlCloseTaskStatePending {
		t.Fatalf("rebound task = %#v, %v", rebound, err)
	}
}

func TestDynamoSessionControlOwnerTaskSnapshotBoundsStrictRowsAndOperationalErrors(t *testing.T) {
	t.Run("physical_cap", func(t *testing.T) {
		fixture := newSessionControlOwnerSnapshotFixture(t, 0)
		fixture.fake.queryHook = func(context.Context, *dynamodb.QueryInput, int) (*dynamodb.QueryOutput, error) {
			return &dynamodb.QueryOutput{Items: make([]map[string]types.AttributeValue, sessionControlOwnerTaskLimit+1)}, nil
		}
		_, err := fixture.store.SnapshotOwnerExactCloseTasks(context.Background(), fixture.target.ControlCellID,
			fixture.target.ACID, fixture.target.PublicKey)
		if !errors.Is(err, errSessionControlOwnerCapacity) {
			t.Fatalf("cap error = %v", err)
		}
	})
	t.Run("malformed_task", func(t *testing.T) {
		fixture := newSessionControlOwnerSnapshotFixture(t, 1)
		fixture.fake.mu.Lock()
		item := fixture.fake.items[sessionControlSessionDynamoMapKey(sessionControlCloseTaskKey(fixture.ownerPK, fixture.eventIDs[0]))]
		delete(item, "manifest_index")
		fixture.fake.mu.Unlock()
		_, err := fixture.store.SnapshotOwnerExactCloseTasks(context.Background(), fixture.target.ControlCellID,
			fixture.target.ACID, fixture.target.PublicKey)
		if !errors.Is(err, errSessionControlCloseTaskCorrupt) {
			t.Fatalf("malformed error = %v", err)
		}
	})
	t.Run("pre_taskset_is_not_delivery_authority", func(t *testing.T) {
		fixture := newSessionControlOwnerSnapshotFixture(t, 1)
		fixture.fake.mu.Lock()
		delete(fixture.fake.items, sessionControlSessionDynamoMapKey(sessionControlCloseTaskSetKey(fixture.eventIDs[0])))
		fixture.fake.queries = nil
		fixture.fake.mu.Unlock()
		_, err := fixture.store.SnapshotOwnerExactCloseTasks(context.Background(), fixture.target.ControlCellID,
			fixture.target.ACID, fixture.target.PublicKey)
		if !errors.Is(err, errSessionControlOwnerConflict) || len(fixture.fake.queries) != sessionControlSessionReadAttempts {
			t.Fatalf("pre-taskset error = %v; queries=%d", err, len(fixture.fake.queries))
		}
	})
	t.Run("counter_mismatch", func(t *testing.T) {
		fixture := newSessionControlOwnerSnapshotFixture(t, 1)
		owner, err := fixture.store.getOwner(context.Background(), fixture.target.ControlCellID,
			fixture.target.ACID, fixture.target.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		owner.PendingCount = 0
		owner.Phase = sessionControlOwnerReady
		seedSessionControlTaskOwner(t, fixture.fake, *owner)
		_, err = fixture.store.SnapshotOwnerExactCloseTasks(context.Background(), owner.CellID, owner.ACID, owner.PublicKey)
		if !errors.Is(err, errSessionControlOwnerCorrupt) {
			t.Fatalf("counter mismatch error = %v", err)
		}
	})
	t.Run("query_error", func(t *testing.T) {
		fixture := newSessionControlOwnerSnapshotFixture(t, 0)
		operational := errors.New("query transport")
		fixture.fake.queryHook = func(context.Context, *dynamodb.QueryInput, int) (*dynamodb.QueryOutput, error) {
			return nil, operational
		}
		_, err := fixture.store.SnapshotOwnerExactCloseTasks(context.Background(), fixture.target.ControlCellID,
			fixture.target.ACID, fixture.target.PublicKey)
		if !errors.Is(err, operational) {
			t.Fatalf("query error = %v", err)
		}
	})
}

func TestDynamoSessionControlLoadAndClaimExactCloseTaskAuthority(t *testing.T) {
	fixture := newSessionControlOwnerSnapshotFixture(t, 1)
	authority, err := fixture.store.LoadExactCloseTaskAuthority(context.Background(), fixture.ownerPK, fixture.eventIDs[0])
	if err != nil || authority.Session.State != sessionControlSessionStateClosing ||
		authority.Work.Selector.Scope != sessionControlFenceSelectorExact || authority.Task.EventID != fixture.eventIDs[0] ||
		authority.Owner.PendingCount != 1 || authority.Directory != nil {
		t.Fatalf("authority = %#v, %v", authority, err)
	}
	// Retention is monotonic session state, not immutable TASK/WORK identity.
	extended := authority.Session
	extended.RetainUntilMillis++
	seedSessionControlReservation(t, fixture.fake, extended)
	if _, err = fixture.store.LoadExactCloseTaskAuthority(context.Background(), fixture.ownerPK, fixture.eventIDs[0]); err != nil {
		t.Fatalf("retention extension rejected: %v", err)
	}

	request := sessionControlCloseTaskLeaseRequest{CellID: authority.Task.CellID, EventID: authority.Task.EventID,
		OwnerPK: fixture.ownerPK, OperationID: sessionControlTaskTestID(0x901),
		LeaseID: sessionControlTaskTestID(0x902), LeaseOwner: sessionControlTaskTestID(0x903)}
	claimed, err := fixture.store.ClaimExactCloseTaskForDelivery(context.Background(), request)
	if err != nil || claimed.Task.State != sessionControlCloseTaskStateLeased || claimed.Task.LeaseID != request.LeaseID ||
		claimed.Session.RetainUntilMillis != extended.RetainUntilMillis {
		t.Fatalf("claimed authority = %#v, %v", claimed, err)
	}
}

func TestDynamoSessionControlLoadExactCloseTaskAuthorityRejectsSessionDrift(t *testing.T) {
	fixture := newSessionControlOwnerSnapshotFixture(t, 1)
	task, err := fixture.store.getCloseTask(context.Background(), fixture.ownerPK, fixture.eventIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	work, err := fixture.store.getCloseWork(context.Background(), task.CellID, task.EventID, false)
	if err != nil {
		t.Fatal(err)
	}
	current, err := fixture.store.getSessionItem(context.Background(), work.Selector.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	current.ClosePreparedDirectory++
	seedSessionControlReservation(t, fixture.fake, *current)
	_, err = fixture.store.LoadExactCloseTaskAuthority(context.Background(), fixture.ownerPK, fixture.eventIDs[0])
	if !errors.Is(err, errSessionControlCloseTaskCorrupt) {
		t.Fatalf("session drift error = %v", err)
	}
}

func TestSessionControlTargetReconnectPendingWorkState(t *testing.T) {
	candidate := testSessionControlTargetCandidate(0xa1, "00112233445566778899aabbccddeeff", 11)
	target := testSessionControlTargetAuthority(candidate, sessionControlTargetActive, 2)
	target.ReadyControlVersion = target.ActivatedControlVersion
	target.AAKEnqueuedAtMillis = target.PreparedAtMillis
	target.AAKTransactionID = 99
	owner, err := sessionControlOwnerFromTarget(target, nil, sessionControlOwnerReady)
	if err != nil {
		t.Fatal(err)
	}
	owner, err = planSessionControlOwnerTaskInsert(owner, owner.UpdatedAtMillis)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := sessionControlTargetReconnectHasPendingWork(target, candidate, owner)
	if err != nil || !pending {
		t.Fatalf("pending state = %t, %v", pending, err)
	}
	different := candidate
	different.FlushGeneration++
	if pending, err = sessionControlTargetReconnectHasPendingWork(target, different, owner); err != nil || pending {
		t.Fatalf("different generation pending state = %t, %v", pending, err)
	}
}

func seedSessionControlSnapshotAuthority(t *testing.T, fake *sessionControlSessionDynamoFake,
	authority sessionControlAuthority) {
	t.Helper()
	row, err := sessionControlAuthorityToRow(authority)
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, row))
}

func TestDynamoSessionControlPrepareTargetRefusesPendingSameTupleAndFencesInsertionRace(t *testing.T) {
	newFixture := func(t *testing.T) (*sessionControlSessionDynamoFake, *dynamoSessionControlStore,
		sessionControlTargetCandidate, sessionControlTargetAuthority, sessionControlOwnerAuthority) {
		t.Helper()
		fake := newSessionControlSessionDynamoFake()
		store := newSessionControlSessionDynamoStore(fake, time.Second)
		candidate := testSessionControlTargetCandidate(0xa2, "00112233445566778899aabbccddeeff", 12)
		target := testSessionControlTargetAuthority(candidate, sessionControlTargetActive, 3)
		target.ReadyControlVersion = target.ActivatedControlVersion
		target.AAKEnqueuedAtMillis = target.PreparedAtMillis
		target.AAKTransactionID = 101
		owner := seedSessionControlTarget(t, fake, target)
		seedSessionControlSnapshotAuthority(t, fake, sessionControlAuthority{ACID: candidate.ACID,
			ControlCellID: candidate.ControlCellID, Version: target.AuthorityVersion, ActiveTargetCount: 1,
			CreatedAtMillis: target.CreatedAtMillis, UpdatedAtMillis: target.UpdatedAtMillis})
		return fake, store, candidate, target, owner
	}
	t.Run("already_pending", func(t *testing.T) {
		fake, store, candidate, target, owner := newFixture(t)
		pending, err := planSessionControlOwnerTaskInsert(owner, owner.UpdatedAtMillis)
		if err != nil {
			t.Fatal(err)
		}
		seedSessionControlTaskOwner(t, fake, pending)
		beforeTarget := target
		if _, err = store.PrepareTarget(context.Background(), candidate); !errors.Is(err, errSessionControlTargetPendingWork) {
			t.Fatalf("PrepareTarget() error = %v", err)
		}
		got, err := store.getTarget(context.Background(), target.key())
		if err != nil || *got != beforeTarget || len(fake.transactions) != 0 {
			t.Fatalf("target changed = %#v, %v; transactions=%d", got, err, len(fake.transactions))
		}
	})
	t.Run("insert_wins_owner_cas", func(t *testing.T) {
		fake, store, candidate, target, owner := newFixture(t)
		pending, err := planSessionControlOwnerTaskInsert(owner, owner.UpdatedAtMillis)
		if err != nil {
			t.Fatal(err)
		}
		fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			var pendingValue *types.AttributeValueMemberN
			if len(input.TransactItems) == 2 && input.TransactItems[1].Put != nil {
				pendingValue, _ = input.TransactItems[1].Put.ExpressionAttributeValues[":owner_pending_count"].(*types.AttributeValueMemberN)
			}
			if len(input.TransactItems) != 2 || input.TransactItems[1].Put == nil ||
				!strings.Contains(aws.ToString(input.TransactItems[1].Put.ConditionExpression), "pending_count = :owner_pending_count") ||
				pendingValue == nil || pendingValue.Value != "0" {
				t.Fatalf("prepare owner CAS = %#v", input.TransactItems)
			}
			seedSessionControlTaskOwner(t, fake, pending)
			return nil, &types.TransactionCanceledException{Message: aws.String("owner changed")}
		}
		if _, err = store.PrepareTarget(context.Background(), candidate); !errors.Is(err, errSessionControlTargetPendingWork) {
			t.Fatalf("raced PrepareTarget() error = %v", err)
		}
		gotTarget, targetErr := store.getTarget(context.Background(), target.key())
		gotOwner, ownerErr := store.getOwner(context.Background(), owner.CellID, owner.ACID, owner.PublicKey)
		if targetErr != nil || ownerErr != nil || *gotTarget != target || *gotOwner != pending || len(fake.transactions) != 1 {
			t.Fatalf("race state target=%#v/%v owner=%#v/%v transactions=%d", gotTarget, targetErr,
				gotOwner, ownerErr, len(fake.transactions))
		}
	})
}

func TestSessionControlOwnerTaskSnapshotIdentityValidation(t *testing.T) {
	fixture := newSessionControlOwnerSnapshotFixture(t, 0)
	for _, input := range [][3]string{{"bad cell", fixture.target.ACID, fixture.target.PublicKey},
		{fixture.target.ControlCellID, "", fixture.target.PublicKey},
		{fixture.target.ControlCellID, fixture.target.ACID, fmt.Sprintf("%064x", 0)}} {
		if _, err := fixture.store.SnapshotOwnerExactCloseTasks(context.Background(), input[0], input[1], input[2]); err == nil {
			t.Fatalf("invalid identity accepted: %#v", input)
		}
	}
}
