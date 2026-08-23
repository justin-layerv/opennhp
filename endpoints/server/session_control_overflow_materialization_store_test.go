package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type sessionControlOverflowMaterializationFixture struct {
	sessionControlMaterializationFixture
	leader sessionControlOverflowLeader
}

func newSessionControlOverflowMaterializationFixture(t *testing.T, count int) sessionControlOverflowMaterializationFixture {
	t.Helper()
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, 10*time.Second)
	installSessionControlMaterializationQuery(t, fake)
	fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		applySessionControlMaterializationTransaction(fake, input)
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}
	candidate := testSessionControlSessionCandidate(0xe1, 2901)
	snapshot := testSessionControlSessionSnapshot(1)
	current, err := planSessionControlReservation(candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	expires := store.nowUTC().UnixMilli() + time.Hour.Milliseconds()
	retain := expires + time.Hour.Milliseconds()
	intents := make([]sessionControlSessionIntent, 0, count)
	for index := 0; index < count; index++ {
		target := testSessionControlSessionTarget(byte(index%240 + 1))
		target.ACID = fmt.Sprintf("ac-overflow-materialize-%04d", index)
		planned, planErr := planSessionControlIntent(current.fence(), target, expires, retain, snapshot)
		if planErr != nil {
			t.Fatalf("plan intent %d: %v", index, planErr)
		}
		current = planned.Session
		intents = append(intents, planned.Intent)
		seedSessionControlTarget(t, fake, target)
		seedSessionControlIntent(t, fake, planned.Intent)
	}
	directory := sessionControlCloseTestDirectory(snapshot, store.nowUTC().UnixMilli()-1_000)
	directory.ActiveFenceCount = sessionControlFenceActiveLimit
	close := expectedSessionControlExactClose(t, current, directory, store.nowUTC().UnixMilli(), retain)
	if !close.Overflow || close.Work.Mode != sessionControlCloseWorkModeOverflow {
		t.Fatalf("overflow close fixture = %#v", close)
	}
	seedCommittedSessionControlExactClose(t, fake, directory, close)
	committedDirectory := directory
	committedDirectory.Version++
	committedDirectory.UpdatedAtMillis = close.Work.CreatedAtMillis
	committedDirectory.AdmissionBlocked = true
	committedDirectory.OverflowCloseCount++
	leader, err := store.SelectOldestOverflowCloseLeader(context.Background(), candidate.CellID)
	if err != nil {
		t.Fatal(err)
	}
	if leader.Directory.Version != committedDirectory.Version+1 {
		t.Fatalf("leader version = %d, want %d", leader.Directory.Version, committedDirectory.Version+1)
	}
	seedSessionControlCloseDirectory(t, fake, leader.Directory)
	fake.mu.Lock()
	fake.transactions = nil
	fake.mu.Unlock()
	return sessionControlOverflowMaterializationFixture{
		sessionControlMaterializationFixture: sessionControlMaterializationFixture{
			fake: fake, store: store, candidate: candidate, close: close, intents: intents,
		},
		leader: *leader,
	}
}

func assertOverflowLeaderCondition(t *testing.T, item types.TransactWriteItem,
	leader sessionControlFenceDirectory) {
	t.Helper()
	if item.ConditionCheck == nil ||
		sessionControlSessionDynamoMapKey(item.ConditionCheck.Key) != sessionControlSessionDynamoMapKey(sessionControlFenceDirectoryKey(leader.CellID)) {
		t.Fatalf("missing CONTROL leader condition: %#v", item)
	}
	condition := aws.ToString(item.ConditionCheck.ConditionExpression)
	for _, fragment := range []string{"overflow_leader_event_id", "overflow_leader_prepared_directory_version",
		"overflow_leader_selected_directory_version", "admission_blocked", "overflow_close_count", "attribute_not_exists(#ttl)"} {
		if !strings.Contains(condition, fragment) {
			t.Fatalf("leader condition lacks %q: %s", fragment, condition)
		}
	}
	if item.ConditionCheck.ExpressionAttributeNames["#ttl"] != "ttl" {
		t.Fatalf("leader ttl alias = %#v", item.ConditionCheck.ExpressionAttributeNames)
	}
}

func TestDynamoSessionControlMaterializeSelectedOverflowTransactionArithmetic(t *testing.T) {
	tests := []struct {
		count            int
		transactionSizes []int
	}{
		{count: 0, transactionSizes: []int{4}},
		{count: 47, transactionSizes: []int{98, 4}},
		{count: 48, transactionSizes: []int{98, 6, 5}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.count), func(t *testing.T) {
			fixture := newSessionControlOverflowMaterializationFixture(t, tt.count)
			result, err := fixture.store.MaterializeSelectedOverflowExactClose(context.Background(), fixture.candidate,
				fixture.close.EventID)
			if err != nil {
				t.Fatal(err)
			}
			if result.WorkMode != sessionControlCloseWorkModeOverflow || result.SourceCount != uint64(tt.count) ||
				result.OwnerCount != uint64(tt.count) || len(fixture.fake.transactions) != len(tt.transactionSizes) {
				t.Fatalf("result/transactions = %#v/%d", result, len(fixture.fake.transactions))
			}
			for index, want := range tt.transactionSizes {
				txn := fixture.fake.transactions[index]
				if len(txn.TransactItems) != want || len(aws.ToString(txn.ClientRequestToken)) > 36 {
					t.Fatalf("transaction %d = %d/%q, want %d", index, len(txn.TransactItems),
						aws.ToString(txn.ClientRequestToken), want)
				}
				leaderIndex := 3
				if index == len(tt.transactionSizes)-1 {
					leaderIndex = 0
				}
				assertOverflowLeaderCondition(t, txn.TransactItems[leaderIndex], fixture.leader.Directory)
				for _, member := range txn.TransactItems {
					if member.Put != nil && member.Put.Item["ttl"] != nil {
						t.Fatalf("pending overflow transaction %d wrote TTL: %#v", index, member.Put.Item)
					}
				}
			}
		})
	}
}

func TestDynamoSessionControlMaterializeSelectedOverflowTwentyTwoChunksAt1024(t *testing.T) {
	fixture := newSessionControlOverflowMaterializationFixture(t, int(sessionControlSessionMaxTargets))
	result, err := fixture.store.MaterializeSelectedOverflowExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ManifestDigests) != sessionControlCloseManifestLimit ||
		len(fixture.fake.transactions) != sessionControlCloseManifestLimit+1 {
		t.Fatalf("manifests/transactions = %d/%d", len(result.ManifestDigests), len(fixture.fake.transactions))
	}
	for index, txn := range fixture.fake.transactions[:sessionControlCloseManifestLimit] {
		want := 98
		if index == sessionControlCloseManifestLimit-1 {
			want = 78
		}
		if len(txn.TransactItems) != want {
			t.Fatalf("manifest transaction %d = %d, want %d", index, len(txn.TransactItems), want)
		}
		assertOverflowLeaderCondition(t, txn.TransactItems[3], fixture.leader.Directory)
	}
	last := fixture.fake.transactions[len(fixture.fake.transactions)-1]
	if len(last.TransactItems) != 25 {
		t.Fatalf("taskset transaction = %d, want 25", len(last.TransactItems))
	}
	assertOverflowLeaderCondition(t, last.TransactItems[0], fixture.leader.Directory)

	normal := newSessionControlMaterializationFixture(t, 48)
	if _, err := normal.store.MaterializeNormalExactClose(context.Background(), normal.candidate, normal.close.EventID); err != nil {
		t.Fatal(err)
	}
	if got := len(normal.fake.transactions[0].TransactItems); got != 99 {
		t.Fatalf("normal 48-owner manifest transaction = %d, want 99", got)
	}
}

func setSessionControlMaterializationOwnerTaskCount(t *testing.T, fixture sessionControlMaterializationFixture,
	count uint64) {
	t.Helper()
	intent := fixture.intents[0]
	owner, err := fixture.store.getOwner(context.Background(), intent.Target.ControlCellID, intent.Target.ACID,
		intent.Target.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	owner.TaskCount = count
	owner.PendingCount = 0
	owner.WorkVersion = count + 1
	seedSessionControlTaskOwner(t, fixture.fake, *owner)
}

func TestDynamoSessionControlMaterializeSelectedOverflowUsesOnlyReservedOwnerSlot(t *testing.T) {
	normal := newSessionControlMaterializationFixture(t, 1)
	setSessionControlMaterializationOwnerTaskCount(t, normal, sessionControlFenceActiveLimit)
	if _, err := normal.store.MaterializeNormalExactClose(context.Background(), normal.candidate,
		normal.close.EventID); !errors.Is(err, errSessionControlMaterializationCapacity) {
		t.Fatalf("normal at 1024 error = %v", err)
	}

	overflow := newSessionControlOverflowMaterializationFixture(t, 1)
	setSessionControlMaterializationOwnerTaskCount(t, overflow.sessionControlMaterializationFixture,
		sessionControlFenceActiveLimit)
	_, err := overflow.store.MaterializeSelectedOverflowExactClose(context.Background(), overflow.candidate,
		overflow.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	ownerPK := resultOwnerPK(t, overflow.intents[0])
	task, err := overflow.store.getCloseTask(context.Background(), ownerPK, overflow.close.EventID)
	if err != nil || task.OwnerAfter.TaskCount != sessionControlOwnerTaskLimit {
		t.Fatalf("overflow reserved slot task = %#v/%v", task, err)
	}

	full := newSessionControlOverflowMaterializationFixture(t, 1)
	setSessionControlMaterializationOwnerTaskCount(t, full.sessionControlMaterializationFixture,
		sessionControlOwnerTaskLimit)
	if _, err := full.store.MaterializeSelectedOverflowExactClose(context.Background(), full.candidate,
		full.close.EventID); !errors.Is(err, errSessionControlMaterializationCapacity) {
		t.Fatalf("overflow at 1025 error = %v", err)
	}
}

func resultOwnerPK(t *testing.T, intent sessionControlSessionIntent) string {
	t.Helper()
	return sessionControlOwnerPK(intent.Target.ControlCellID, intent.Target.ACID, intent.Target.PublicKey)
}

func TestDynamoSessionControlMaterializeSelectedOverflowLeaderAndHeaderFences(t *testing.T) {
	t.Run("nonleader", func(t *testing.T) {
		fixture := newSessionControlOverflowMaterializationFixture(t, 1)
		directory := fixture.leader.Directory
		directory.OverflowLeaderEventID = strings.Repeat("f", 32)
		seedSessionControlCloseDirectory(t, fixture.fake, directory)
		if _, err := fixture.store.MaterializeSelectedOverflowExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID); !errors.Is(err, errSessionControlMaterializationConflict) {
			t.Fatalf("nonleader error = %v", err)
		}
	})
	t.Run("leader_drifts_during_manifest", func(t *testing.T) {
		fixture := newSessionControlOverflowMaterializationFixture(t, 1)
		fixture.fake.transactHook = func(_ context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			directory := fixture.leader.Directory
			directory.Version++
			directory.UpdatedAtMillis++
			seedSessionControlCloseDirectory(t, fixture.fake, directory)
			return nil, &types.TransactionCanceledException{}
		}
		if _, err := fixture.store.MaterializeSelectedOverflowExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID); !errors.Is(err, errSessionControlMaterializationConflict) {
			t.Fatalf("leader drift error = %v", err)
		}
	})
	t.Run("header_drift", func(t *testing.T) {
		fixture := newSessionControlOverflowMaterializationFixture(t, 1)
		fixture.fake.mu.Lock()
		workKey := sessionControlSessionDynamoMapKey(sessionControlOverflowCloseKey(fixture.candidate.CellID,
			fixture.close.EventID))
		fixture.fake.items[workKey]["selector_digest"] = &types.AttributeValueMemberS{Value: strings.Repeat("f", 64)}
		fixture.fake.mu.Unlock()
		if _, err := fixture.store.MaterializeSelectedOverflowExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID); err == nil {
			t.Fatal("mutated overflow header was accepted")
		}
	})
}

func TestDynamoSessionControlMaterializeSelectedOverflowCrashResume(t *testing.T) {
	fixture := newSessionControlOverflowMaterializationFixture(t, 48)
	calls := 0
	fixture.fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("transport failed before commit")
		}
		applySessionControlMaterializationTransaction(fixture.fake, input)
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}
	if _, err := fixture.store.MaterializeSelectedOverflowExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID); err == nil {
		t.Fatal("missing interrupted overflow materialization error")
	}
	firstToken := aws.ToString(fixture.fake.transactions[0].ClientRequestToken)
	if _, err := fixture.store.MaterializeSelectedOverflowExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID); err != nil {
		t.Fatal(err)
	}
	for _, txn := range fixture.fake.transactions[2:] {
		if aws.ToString(txn.ClientRequestToken) == firstToken {
			t.Fatal("committed overflow manifest was emitted again")
		}
	}
}

func TestDynamoSessionControlMaterializeSelectedOverflowCrashBeforeTaskSet(t *testing.T) {
	fixture := newSessionControlOverflowMaterializationFixture(t, 47)
	calls := 0
	fixture.fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("taskset response unavailable before commit")
		}
		applySessionControlMaterializationTransaction(fixture.fake, input)
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}
	if _, err := fixture.store.MaterializeSelectedOverflowExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID); err == nil {
		t.Fatal("missing pre-taskset interruption")
	}
	manifestToken := aws.ToString(fixture.fake.transactions[0].ClientRequestToken)
	result, err := fixture.store.MaterializeSelectedOverflowExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID)
	if err != nil || result.WorkMode != sessionControlCloseWorkModeOverflow {
		t.Fatalf("resumed taskset = %#v/%v", result, err)
	}
	for _, txn := range fixture.fake.transactions[2:] {
		if aws.ToString(txn.ClientRequestToken) == manifestToken {
			t.Fatal("pre-taskset resume rewrote committed manifest")
		}
	}
}

func TestDynamoSessionControlMaterializeSelectedOverflowPreservesOperationalErrors(t *testing.T) {
	fixture := newSessionControlOverflowMaterializationFixture(t, 1)
	sentinel := errors.New("injected overflow source query failure")
	fixture.fake.queryHook = func(context.Context, *dynamodb.QueryInput, int) (*dynamodb.QueryOutput, error) {
		return nil, sentinel
	}
	if _, err := fixture.store.MaterializeSelectedOverflowExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID); !errors.Is(err, sentinel) {
		t.Fatalf("source query error = %v", err)
	}
}

func newSessionControlOverflowTaskFixture(t *testing.T) sessionControlTaskFixture {
	t.Helper()
	materialization := newSessionControlOverflowMaterializationFixture(t, 1)
	taskSet, err := materialization.store.MaterializeSelectedOverflowExactClose(context.Background(),
		materialization.candidate, materialization.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	base := sessionControlMaterializationFixture{fake: materialization.fake, store: materialization.store,
		candidate: materialization.candidate, close: materialization.close, intents: materialization.intents}
	fixture := sessionControlTaskFixture{sessionControlMaterializationFixture: base, taskSet: *taskSet}
	fixture.ownerPK = resultOwnerPK(t, fixture.intents[0])
	task, err := fixture.store.getCloseTask(context.Background(), fixture.ownerPK, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	fixture.task = *task
	return fixture
}

func TestDynamoSessionControlOverflowTaskDiscoveryClaimReleaseRebindAndAck(t *testing.T) {
	fixture := newSessionControlOverflowTaskFixture(t)
	shard := uint64(0)
	_, _ = fmt.Sscanf(strings.TrimPrefix(fixture.task.DueShard,
		fmt.Sprintf("CLOSETASK#%s#", fixture.task.CellID)), "%d", &shard)
	installSessionControlTaskDueQuery(fixture.fake, false)
	due, err := fixture.store.ListDueExactCloseTasksPage(context.Background(), fixture.task.CellID, shard,
		fixture.task.DueAtMillis, nil, 10)
	if err != nil || len(due.Tasks) != 1 || due.Tasks[0].WorkMode != sessionControlCloseWorkModeOverflow {
		t.Fatalf("overflow due page = %#v/%v", due, err)
	}
	installSessionControlTaskDueQuery(fixture.fake, true)
	if omitted, err := fixture.store.ListDueExactCloseTasksPage(context.Background(), fixture.task.CellID, shard,
		fixture.task.DueAtMillis, nil, 10); err != nil || len(omitted.Tasks) != 0 {
		t.Fatalf("omitted overflow due = %#v/%v", omitted, err)
	}
	committed, err := fixture.store.ListCommittedExactCloseTasksPage(context.Background(), fixture.task.CellID,
		fixture.task.EventID, nil, 10)
	if err != nil || len(committed.Tasks) != 1 || committed.Directory == nil ||
		committed.Tasks[0].WorkMode != sessionControlCloseWorkModeOverflow {
		t.Fatalf("overflow committed page = %#v/%v", committed, err)
	}

	before := len(fixture.fake.transactions)
	lease := sessionControlTaskClaimRequest(fixture, 0x2101)
	claimed, err := fixture.store.ClaimExactCloseTask(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	release := lease
	release.OperationID = sessionControlTaskTestID(0x2111)
	if _, err := fixture.store.ReleaseExactCloseTask(context.Background(), release); err != nil {
		t.Fatal(err)
	}
	target := installSessionControlTaskTargetGeneration(t, &fixture, claimed.BoundFlushGeneration+1,
		"cccccccccccccccccccccccccccccccc")
	if _, err := fixture.store.RebindExactCloseTask(context.Background(),
		sessionControlTaskRebindRequest(fixture, target, 0x2121)); err != nil {
		t.Fatal(err)
	}
	finalLease := sessionControlTaskClaimRequest(fixture, 0x2131)
	finalClaim, err := fixture.store.ClaimExactCloseTask(context.Background(), finalLease)
	if err != nil {
		t.Fatal(err)
	}
	acked, err := fixture.store.AckExactCloseTask(context.Background(),
		sessionControlTaskAckRequest(fixture, *finalClaim, finalLease, 1))
	if err != nil || acked.State != sessionControlCloseTaskStateAcked || acked.WorkMode != sessionControlCloseWorkModeOverflow {
		t.Fatalf("overflow ACK = %#v/%v", acked, err)
	}
	for index, txn := range fixture.fake.transactions[before:] {
		if len(txn.TransactItems) != 6 || len(aws.ToString(txn.ClientRequestToken)) > 36 {
			t.Fatalf("overflow lifecycle transaction %d = %d/%q", index, len(txn.TransactItems),
				aws.ToString(txn.ClientRequestToken))
		}
		assertOverflowLeaderCondition(t, txn.TransactItems[5], fixture.leaderDirectory(t))
	}
}

func (fixture sessionControlTaskFixture) leaderDirectory(t *testing.T) sessionControlFenceDirectory {
	t.Helper()
	directory, err := fixture.store.getFenceDirectory(context.Background(), fixture.task.CellID)
	if err != nil {
		t.Fatal(err)
	}
	return *directory
}

func TestDynamoSessionControlOverflowCommittedCursorRejectsLeaderDrift(t *testing.T) {
	fixture := newSessionControlOverflowMaterializationFixture(t, 48)
	if _, err := fixture.store.MaterializeSelectedOverflowExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID); err != nil {
		t.Fatal(err)
	}
	first, err := fixture.store.ListCommittedExactCloseTasksPage(context.Background(), fixture.candidate.CellID,
		fixture.close.EventID, nil, 1)
	if err != nil || first.Next == nil || first.Directory == nil {
		t.Fatalf("first committed overflow page = %#v/%v", first, err)
	}
	directory := fixture.leader.Directory
	directory.Version++
	directory.UpdatedAtMillis++
	seedSessionControlCloseDirectory(t, fixture.fake, directory)
	if _, err := fixture.store.ListCommittedExactCloseTasksPage(context.Background(), fixture.candidate.CellID,
		fixture.close.EventID, first.Next, 1); !errors.Is(err, errSessionControlCloseTaskConflict) {
		t.Fatalf("leader-drift cursor error = %v", err)
	}
}

func TestDynamoSessionControlOverflowTaskLifecycleRejectsLeaderReplacement(t *testing.T) {
	fixture := newSessionControlOverflowTaskFixture(t)
	directory := fixture.leaderDirectory(t)
	directory.OverflowLeaderEventID = strings.Repeat("e", 32)
	seedSessionControlCloseDirectory(t, fixture.fake, directory)
	if _, err := fixture.store.ClaimExactCloseTask(context.Background(),
		sessionControlTaskClaimRequest(fixture, 0x2201)); !errors.Is(err, errSessionControlCloseTaskConflict) {
		t.Fatalf("claim under replaced overflow leader error = %v", err)
	}
}

func TestDynamoSessionControlOverflowCommittedRecoveryPreservesDirectoryReadError(t *testing.T) {
	fixture := newSessionControlOverflowTaskFixture(t)
	sentinel := errors.New("injected CONTROL strong-read failure")
	directoryKey := sessionControlSessionDynamoMapKey(sessionControlFenceDirectoryKey(fixture.task.CellID))
	fixture.fake.getHook = func(ctx context.Context, input *dynamodb.GetItemInput, _ int) (*dynamodb.GetItemOutput, error) {
		if sessionControlSessionDynamoMapKey(input.Key) == directoryKey {
			return nil, sentinel
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fixture.fake.mu.Lock()
		defer fixture.fake.mu.Unlock()
		return &dynamodb.GetItemOutput{Item: fixture.fake.items[sessionControlSessionDynamoMapKey(input.Key)]}, nil
	}
	if _, err := fixture.store.ListCommittedExactCloseTasksPage(context.Background(), fixture.task.CellID,
		fixture.task.EventID, nil, 10); !errors.Is(err, sentinel) {
		t.Fatalf("CONTROL read error = %v", err)
	}
}
