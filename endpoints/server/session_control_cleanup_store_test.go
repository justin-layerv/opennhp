package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type sessionControlCleanupFixture struct {
	sessionControlCompletionFixture
	complete sessionControlCloseComplete
}

func applySessionControlCleanupTransaction(fake *sessionControlSessionDynamoFake,
	input *dynamodb.TransactWriteItemsInput) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, member := range input.TransactItems {
		switch {
		case member.Put != nil:
			fake.items[sessionControlSessionDynamoMapKey(member.Put.Item)] = member.Put.Item
		case member.Delete != nil:
			delete(fake.items, sessionControlSessionDynamoMapKey(member.Delete.Key))
		}
	}
}

func installSessionControlCleanupTransactionFake(fake *sessionControlSessionDynamoFake) {
	fake.transactHook = func(ctx context.Context,
		input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		applySessionControlCleanupTransaction(fake, input)
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}
}

func newSessionControlCleanupFixture(t *testing.T, count int) sessionControlCleanupFixture {
	t.Helper()
	fixture := sessionControlCleanupFixture{sessionControlCompletionFixture: newSessionControlCompletionFixture(t,
		count, true, true)}
	complete, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	fixture.complete = *complete
	installSessionControlCleanupTransactionFake(fixture.fake)
	return fixture
}

func sessionControlCleanupRequest(fixture sessionControlCleanupFixture,
	ownerPK string, seed uint64) sessionControlCloseTaskCleanupRequest {
	return sessionControlCloseTaskCleanupRequest{CellID: fixture.candidate.CellID,
		EventID: fixture.close.EventID, OwnerPK: ownerPK, OperationID: sessionControlTaskTestID(seed)}
}

func TestDynamoSessionControlCleanupAckedNormalExactCloseTask(t *testing.T) {
	fixture := newSessionControlCleanupFixture(t, 1)
	task, err := fixture.store.getCloseTask(context.Background(), fixture.ownerPK, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := fixture.store.getOwner(context.Background(), task.CellID, task.ACID, task.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	request := sessionControlCleanupRequest(fixture, task.OwnerPK, 0xc100)
	before := len(fixture.fake.transactions)
	audit, err := fixture.store.CleanupAckedNormalExactCloseTask(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if audit.AckedTask != *task || audit.OwnerBefore != *owner || audit.OwnerAfter.TaskCount+1 != owner.TaskCount ||
		audit.OwnerAfter.PendingCount != owner.PendingCount || audit.Complete.CompleteDigest != fixture.complete.CompleteDigest {
		t.Fatalf("cleanup audit = %#v", audit)
	}
	txn := fixture.fake.transactions[before]
	if len(txn.TransactItems) != 4 || len(aws.ToString(txn.ClientRequestToken)) > 36 ||
		txn.TransactItems[0].ConditionCheck == nil || txn.TransactItems[1].Put == nil ||
		txn.TransactItems[2].Delete == nil || txn.TransactItems[3].Put == nil {
		t.Fatalf("cleanup transaction = %#v", txn)
	}
	for _, member := range txn.TransactItems {
		if member.Put != nil {
			if _, hasTTL := member.Put.Item["ttl"]; hasTTL {
				t.Fatal("cleanup authority unexpectedly has TTL")
			}
		}
	}
	if _, err = fixture.store.getCloseTask(context.Background(), task.OwnerPK, task.EventID); !errors.Is(err, errSessionControlCloseTaskNotFound) {
		t.Fatalf("deleted task read = %v", err)
	}
	stored, err := fixture.store.getCloseTaskAudit(context.Background(), task.OwnerPK, task.EventID)
	if err != nil || stored.AuditDigest != audit.AuditDigest {
		t.Fatalf("stored audit = %#v, %v", stored, err)
	}
	transactions := len(fixture.fake.transactions)
	replayed, err := fixture.store.CleanupAckedNormalExactCloseTask(context.Background(), request)
	if err != nil || replayed.AuditDigest != audit.AuditDigest || len(fixture.fake.transactions) != transactions {
		t.Fatalf("cleanup replay = %#v, %v, transactions=%d", replayed, err, len(fixture.fake.transactions))
	}
	page, err := fixture.store.ListCompletedNormalExactCloseTasksPage(context.Background(), fixture.candidate.CellID,
		fixture.close.EventID, nil, 10)
	if err != nil || len(page.Items) != 1 || page.Items[0].Audit == nil || page.Items[0].Task != nil || page.Next != nil {
		t.Fatalf("completed page = %#v, %v", page, err)
	}
	lease := sessionControlCloseTaskLeaseRequest{CellID: task.CellID, EventID: task.EventID, OwnerPK: task.OwnerPK,
		OperationID: task.LastOperationID, LeaseID: task.AckLeaseID, LeaseOwner: task.AckLeaseOwner}
	ackRequest := sessionControlTaskAckRequest(fixture.sessionControlTaskFixture, *task, lease, task.AckClosed+99)
	late, err := fixture.store.AckExactCloseTask(context.Background(), ackRequest)
	if err != nil || late.AckClosed != task.AckClosed || late.AckedAtMillis != task.AckedAtMillis {
		t.Fatalf("late ACK = %#v, %v", late, err)
	}
}

func TestDynamoSessionControlCleanupRequiresCommittedAckReference(t *testing.T) {
	fixture := newSessionControlCleanupFixture(t, 1)
	task, err := fixture.store.getCloseTask(context.Background(), fixture.ownerPK, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	chunk, err := fixture.store.getCloseAckChunk(context.Background(), fixture.close.EventID, task.ManifestIndex)
	if err != nil {
		t.Fatal(err)
	}
	chunk.Refs[0].AckClosed++
	chunk.AckClosedTotal++
	chunk.ChunkDigest, err = sessionControlCloseAckChunkDigest(*chunk)
	if err != nil {
		t.Fatal(err)
	}
	row, err := sessionControlCloseAckChunkToRow(*chunk)
	if err != nil {
		t.Fatal(err)
	}
	fixture.fake.setItem(marshalSessionControlSessionTestRow(t, row))
	_, err = fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
		sessionControlCleanupRequest(fixture, task.OwnerPK, 0xc200))
	if !errors.Is(err, errSessionControlCleanupCorrupt) {
		t.Fatalf("mutated ACK ref cleanup = %v", err)
	}
}

func TestDynamoSessionControlCleanupAllowsReconnectDescendant(t *testing.T) {
	fixture := newSessionControlCleanupFixture(t, 1)
	task, err := fixture.store.getCloseTask(context.Background(), fixture.ownerPK, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	preparing := installSessionControlTaskTargetGeneration(t, &fixture.sessionControlTaskFixture,
		task.BoundFlushGeneration+1, sessionControlTaskTestID(0xc301))
	owner, err := fixture.store.getOwner(context.Background(), preparing.ControlCellID, preparing.ACID, preparing.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if owner.LifecycleVersion <= task.BoundOwnerLifecycle || owner.WorkVersion != task.CurrentOwnerWorkVersion {
		t.Fatalf("reconnected owner = %#v", owner)
	}
	audit, err := fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
		sessionControlCleanupRequest(fixture, task.OwnerPK, 0xc302))
	if err != nil || audit.OwnerBefore != *owner || audit.OwnerAfter.TaskCount+1 != owner.TaskCount {
		t.Fatalf("reconnect cleanup = %#v, %v", audit, err)
	}
}

func TestDynamoSessionControlCompletedTaskPagerBoundaries(t *testing.T) {
	for _, count := range []int{0, 1, 48, 49, 1024} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			fixture := newSessionControlCleanupFixture(t, count)
			var cursor *sessionControlCompletedCloseTaskCursor
			seen := 0
			for {
				page, err := fixture.store.ListCompletedNormalExactCloseTasksPage(context.Background(), fixture.candidate.CellID,
					fixture.close.EventID, cursor, 37)
				if err != nil {
					if count == 0 {
						storedTaskSet, _ := fixture.store.getCloseTaskSet(context.Background(), fixture.close.EventID)
						storedComplete, _ := fixture.store.getCloseComplete(context.Background(), fixture.close.EventID)
						t.Fatalf("%v\nTASKSET=%#v\nCOMPLETE=%#v\nMATCH=%t", err, storedTaskSet, storedComplete,
							storedTaskSet != nil && storedComplete != nil &&
								sessionControlCloseTaskSetMatchesComplete(*storedTaskSet, *storedComplete))
					}
					t.Fatal(err)
				}
				for _, item := range page.Items {
					if item.Task == nil || item.Audit != nil {
						t.Fatalf("pager item = %#v", item)
					}
				}
				seen += len(page.Items)
				if page.Next == nil {
					break
				}
				cursor = page.Next
			}
			if seen != count {
				t.Fatalf("pager saw %d tasks", seen)
			}
		})
	}
}

func TestDynamoSessionControlZeroTargetCompleteRoundTripUsesPhysicalEmptyLists(t *testing.T) {
	fixture := newSessionControlCleanupFixture(t, 0)
	stored, err := fixture.store.getCloseComplete(context.Background(), fixture.close.EventID)
	if err != nil || stored.CompleteDigest != fixture.complete.CompleteDigest ||
		stored.ManifestDigests == nil || stored.ChunkDigests == nil ||
		stored.ChunkSourceCounts == nil || stored.ChunkOwnerCounts == nil {
		t.Fatalf("zero-target COMPLETE round trip = %#v, %v", stored, err)
	}
	fixture.fake.mu.Lock()
	item := fixture.fake.items[sessionControlSessionDynamoMapKey(sessionControlCloseCompleteKey(fixture.close.EventID))]
	fixture.fake.mu.Unlock()
	for _, field := range []string{"manifest_digests", "chunk_digests", "chunk_source_counts", "chunk_owner_counts"} {
		list, ok := item[field].(*types.AttributeValueMemberL)
		if !ok || len(list.Value) != 0 {
			t.Fatalf("zero-target COMPLETE %s = %#v", field, item[field])
		}
	}
	invalid := fixture.complete
	invalid.ManifestDigests = nil
	if validateSessionControlCloseComplete(invalid) == nil {
		t.Fatal("nil zero-target COMPLETE manifest list accepted")
	}
}

func TestDynamoSessionControlCompletedTaskPagerMixedTaskAuditAcrossManifest(t *testing.T) {
	fixture := newSessionControlCleanupFixture(t, 49)
	first, err := fixture.store.getCloseManifest(context.Background(), fixture.close.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.store.getCloseManifest(context.Background(), fixture.close.EventID, 1)
	if err != nil {
		t.Fatal(err)
	}
	for index, ownerPK := range []string{first.Refs[len(first.Refs)-1].OwnerPK, second.Refs[0].OwnerPK} {
		if _, err = fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
			sessionControlCleanupRequest(fixture, ownerPK, uint64(0xc700+index))); err != nil {
			t.Fatal(err)
		}
	}
	var cursor *sessionControlCompletedCloseTaskCursor
	tasks, audits := 0, 0
	for {
		page, pageErr := fixture.store.ListCompletedNormalExactCloseTasksPage(context.Background(), fixture.candidate.CellID,
			fixture.close.EventID, cursor, 11)
		if pageErr != nil {
			t.Fatal(pageErr)
		}
		for _, item := range page.Items {
			if item.Task != nil {
				tasks++
			} else if item.Audit != nil {
				audits++
			} else {
				t.Fatalf("empty recovery item = %#v", item)
			}
		}
		if page.Next == nil {
			break
		}
		cursor = page.Next
	}
	if tasks != 47 || audits != 2 {
		t.Fatalf("mixed recovery = tasks %d audits %d", tasks, audits)
	}
}

func TestDynamoSessionControlCompletedTaskPagerRejectsForgedPrefix(t *testing.T) {
	fixture := newSessionControlCleanupFixture(t, 49)
	page, err := fixture.store.ListCompletedNormalExactCloseTasksPage(context.Background(), fixture.candidate.CellID,
		fixture.close.EventID, nil, 7)
	if err != nil || page.Next == nil {
		t.Fatalf("first page = %#v, %v", page, err)
	}
	for _, mutate := range []func(*sessionControlCompletedCloseTaskCursor){
		func(cursor *sessionControlCompletedCloseTaskCursor) { cursor.SeenOwners++ },
		func(cursor *sessionControlCompletedCloseTaskCursor) { cursor.SeenSources++ },
		func(cursor *sessionControlCompletedCloseTaskCursor) {
			cursor.ManifestIndex, cursor.RefIndex = 1, 0
		},
	} {
		forged := *page.Next
		mutate(&forged)
		if _, err = fixture.store.ListCompletedNormalExactCloseTasksPage(context.Background(), fixture.candidate.CellID,
			fixture.close.EventID, &forged, 7); err == nil {
			t.Fatalf("forged cursor accepted: %#v", forged)
		}
	}
	zero := newSessionControlCleanupFixture(t, 0)
	forged := &sessionControlCompletedCloseTaskCursor{CellID: zero.candidate.CellID, EventID: zero.close.EventID,
		CompleteDigest: zero.complete.CompleteDigest}
	if _, err = zero.store.ListCompletedNormalExactCloseTasksPage(context.Background(), zero.candidate.CellID,
		zero.close.EventID, forged, 7); err == nil {
		t.Fatal("zero-target cursor accepted")
	}
}

func TestDynamoSessionControlCompletedTaskPagerRequiresExactTaskXorAudit(t *testing.T) {
	for _, tt := range []struct {
		name       string
		mutateRows func(*testing.T, *sessionControlCleanupFixture, sessionControlCloseTask)
	}{
		{name: "both present", mutateRows: func(t *testing.T, fixture *sessionControlCleanupFixture,
			task sessionControlCloseTask) {
			if _, err := fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
				sessionControlCleanupRequest(*fixture, task.OwnerPK, 0xc800)); err != nil {
				t.Fatal(err)
			}
			row, err := sessionControlCloseTaskToRow(task)
			if err != nil {
				t.Fatal(err)
			}
			fixture.fake.setItem(marshalSessionControlSessionTestRow(t, row))
		}},
		{name: "neither present", mutateRows: func(t *testing.T, fixture *sessionControlCleanupFixture,
			task sessionControlCloseTask) {
			fixture.fake.mu.Lock()
			delete(fixture.fake.items, sessionControlSessionDynamoMapKey(sessionControlCloseTaskKey(task.OwnerPK, task.EventID)))
			fixture.fake.mu.Unlock()
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newSessionControlCleanupFixture(t, 1)
			task, err := fixture.store.getCloseTask(context.Background(), fixture.ownerPK, fixture.close.EventID)
			if err != nil {
				t.Fatal(err)
			}
			tt.mutateRows(t, &fixture, *task)
			_, err = fixture.store.ListCompletedNormalExactCloseTasksPage(context.Background(), fixture.candidate.CellID,
				fixture.close.EventID, nil, 10)
			if !errors.Is(err, errSessionControlCleanupCorrupt) {
				t.Fatalf("TASK xor AUDIT violation = %v", err)
			}
		})
	}
}

func TestDynamoSessionControlCompletedTaskPagerRejectsMutatedAuditAndParity(t *testing.T) {
	fixture := newSessionControlCleanupFixture(t, 1)
	audit, err := fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
		sessionControlCleanupRequest(fixture, fixture.ownerPK, 0xc900))
	if err != nil {
		t.Fatal(err)
	}
	row, err := sessionControlCloseTaskAuditToRow(*audit)
	if err != nil {
		t.Fatal(err)
	}
	mutatedClosed := aws.ToUint64(row.AckedTask.AckClosed) + 1
	row.AckedTask.AckClosed = &mutatedClosed
	fixture.fake.setItem(marshalSessionControlSessionTestRow(t, row))
	_, err = fixture.store.ListCompletedNormalExactCloseTasksPage(context.Background(), fixture.candidate.CellID,
		fixture.close.EventID, nil, 10)
	if !errors.Is(err, errSessionControlCleanupCorrupt) {
		t.Fatalf("mutated audit page = %v", err)
	}

	fixture = newSessionControlCleanupFixture(t, 1)
	taskSet := fixture.taskSet
	taskSet.SessionVersion++
	taskSet.ExpectedTargetCount++
	taskSet.SourceCount++
	taskSet.ManifestSourceCounts[0]++
	redigestSessionControlCloseTaskSet(t, &taskSet)
	taskSetRow, err := sessionControlCloseTaskSetToRow(taskSet)
	if err != nil {
		t.Fatalf("build self-consistent mismatched TASKSET: %v", err)
	}
	fixture.fake.setItem(marshalSessionControlSessionTestRow(t, taskSetRow))
	_, err = fixture.store.ListCompletedNormalExactCloseTasksPage(context.Background(), fixture.candidate.CellID,
		fixture.close.EventID, nil, 10)
	if !errors.Is(err, errSessionControlCleanupCorrupt) {
		t.Fatalf("terminal source/count mismatch = %v", err)
	}
}

func TestDynamoSessionControlCleanupAmbiguousCommitClassification(t *testing.T) {
	fixture := newSessionControlCleanupFixture(t, 1)
	request := sessionControlCleanupRequest(fixture, fixture.ownerPK, 0xc400)
	injected := errors.New("ambiguous cleanup response")
	fixture.fake.transactHook = func(_ context.Context,
		input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		applySessionControlCleanupTransaction(fixture.fake, input)
		return nil, injected
	}
	audit, err := fixture.store.CleanupAckedNormalExactCloseTask(context.Background(), request)
	if err != nil || audit == nil {
		t.Fatalf("ambiguous committed cleanup = %#v, %v", audit, err)
	}
	fixture = newSessionControlCleanupFixture(t, 1)
	fixture.fake.transactHook = func(context.Context,
		*dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		return nil, injected
	}
	_, err = fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
		sessionControlCleanupRequest(fixture, fixture.ownerPK, 0xc401))
	if !errors.Is(err, injected) {
		t.Fatalf("uncommitted ambiguous cleanup = %v", err)
	}
}

func TestDynamoSessionControlLateAckAuditRejectsIdentityMutations(t *testing.T) {
	fixture := newSessionControlCleanupFixture(t, 1)
	audit, err := fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
		sessionControlCleanupRequest(fixture, fixture.ownerPK, 0xca00))
	if err != nil {
		t.Fatal(err)
	}
	task := audit.AckedTask
	lease := sessionControlCloseTaskLeaseRequest{CellID: task.CellID, EventID: task.EventID, OwnerPK: task.OwnerPK,
		OperationID: task.LastOperationID, LeaseID: task.AckLeaseID, LeaseOwner: task.AckLeaseOwner}
	base := sessionControlTaskAckRequest(fixture.sessionControlTaskFixture, task, lease, task.AckClosed+1)
	otherKey := testSessionControlSessionTarget(0xef).PublicKey
	otherID := sessionControlTaskTestID(0xca01)
	mutations := []struct {
		name   string
		mutate func(*sessionControlCloseTaskAckRequest)
	}{
		{name: "authenticated public key", mutate: func(request *sessionControlCloseTaskAckRequest) {
			request.AuthenticatedPublicKey = otherKey
		}},
		{name: "selector public key", mutate: func(request *sessionControlCloseTaskAckRequest) {
			request.Ack.AgentPublicKey = otherKey
		}},
		{name: "selector session id", mutate: func(request *sessionControlCloseTaskAckRequest) {
			request.Ack.SessionID++
		}},
		{name: "selector issued", mutate: func(request *sessionControlCloseTaskAckRequest) {
			request.Ack.SessionIssuedAtMillis++
		}},
		{name: "event", mutate: func(request *sessionControlCloseTaskAckRequest) { request.Ack.EventID = otherID }},
		{name: "boot", mutate: func(request *sessionControlCloseTaskAckRequest) { request.Ack.BootID = otherID }},
		{name: "generation", mutate: func(request *sessionControlCloseTaskAckRequest) {
			request.Ack.FlushGeneration++
		}},
		{name: "lease id", mutate: func(request *sessionControlCloseTaskAckRequest) { request.Lease.LeaseID = otherID }},
		{name: "lease owner", mutate: func(request *sessionControlCloseTaskAckRequest) {
			request.Lease.LeaseOwner = otherID
		}},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			request := base
			tt.mutate(&request)
			if _, err := fixture.store.AckExactCloseTask(context.Background(), request); err == nil {
				t.Fatal("mutated late ACK accepted")
			}
		})
	}
	stored, err := fixture.store.AckExactCloseTask(context.Background(), base)
	if err != nil || stored.AckClosed != task.AckClosed {
		t.Fatalf("stored first Closed = %#v, %v", stored, err)
	}
}

func TestDynamoSessionControlConcurrentCleanupDecrementsOnce(t *testing.T) {
	fixture := newSessionControlCleanupFixture(t, 1)
	request := sessionControlCleanupRequest(fixture, fixture.ownerPK, 0xcb00)
	var mu sync.Mutex
	arrivals := 0
	ready := make(chan struct{})
	committed := make(chan struct{})
	fixture.fake.transactHook = func(_ context.Context,
		input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		mu.Lock()
		arrivals++
		arrival := arrivals
		if arrivals == 2 {
			close(ready)
		}
		mu.Unlock()
		<-ready
		if arrival == 1 {
			applySessionControlCleanupTransaction(fixture.fake, input)
			close(committed)
			return &dynamodb.TransactWriteItemsOutput{}, nil
		}
		<-committed
		return nil, &types.TransactionCanceledException{}
	}
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, cleanupErr := fixture.store.CleanupAckedNormalExactCloseTask(context.Background(), request)
			results <- cleanupErr
		}()
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("concurrent cleanup = %v", err)
		}
	}
	owner, err := fixture.store.getOwner(context.Background(), fixture.task.CellID,
		fixture.task.ACID, fixture.task.PublicKey)
	if err != nil || owner.TaskCount != 0 || owner.PendingCount != 0 {
		t.Fatalf("owner after concurrent cleanup = %#v, %v", owner, err)
	}
	if _, err = fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
		sessionControlCleanupRequest(fixture, fixture.ownerPK, 0xcb01)); !errors.Is(err, errSessionControlCleanupConflict) {
		t.Fatalf("different-operation cleanup replay = %v", err)
	}
}

func TestDynamoSessionControlCleanupRejectsWrongOwnerAuthority(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*sessionControlOwnerAuthority)
	}{
		{name: "stable identity", mutate: func(owner *sessionControlOwnerAuthority) { owner.ACID += "-other" }},
		{name: "work cursor", mutate: func(owner *sessionControlOwnerAuthority) { owner.WorkVersion-- }},
		{name: "physical count", mutate: func(owner *sessionControlOwnerAuthority) { owner.TaskCount++ }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newSessionControlCleanupFixture(t, 1)
			task, err := fixture.store.getCloseTask(context.Background(), fixture.ownerPK, fixture.close.EventID)
			if err != nil {
				t.Fatal(err)
			}
			owner, err := fixture.store.getOwner(context.Background(), task.CellID, task.ACID, task.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			tt.mutate(owner)
			row, err := sessionControlOwnerToRow(*owner)
			if err != nil {
				t.Fatal(err)
			}
			// Retain the original physical key so the strong read observes the
			// self-consistent but wrong stable identity row.
			row.PK = task.OwnerPK
			fixture.fake.setItem(marshalSessionControlSessionTestRow(t, row))
			_, err = fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
				sessionControlCleanupRequest(fixture, task.OwnerPK, 0xcc00))
			if err == nil {
				t.Fatal("wrong owner authority accepted")
			}
		})
	}
}

func TestSessionControlCloseTaskAuditNestedRowsArePresenceStrict(t *testing.T) {
	fixture := newSessionControlCleanupFixture(t, 1)
	audit, err := fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
		sessionControlCleanupRequest(fixture, fixture.ownerPK, 0xc500))
	if err != nil {
		t.Fatal(err)
	}
	row, err := sessionControlCloseTaskAuditToRow(*audit)
	if err != nil {
		t.Fatal(err)
	}
	item := marshalSessionControlSessionTestRow(t, row)
	for _, tt := range []struct {
		name   string
		field  string
		nested string
	}{
		{name: "complete zero count", field: "complete", nested: "expected_target_count"},
		{name: "task manifest index", field: "acked_task", nested: "manifest_index"},
		{name: "owner pending count", field: "owner_before", nested: "pending_count"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			copy := make(map[string]types.AttributeValue, len(item))
			for key, value := range item {
				copy[key] = value
			}
			member := copy[tt.field].(*types.AttributeValueMemberM)
			nested := make(map[string]types.AttributeValue, len(member.Value))
			for key, value := range member.Value {
				nested[key] = value
			}
			delete(nested, tt.nested)
			copy[tt.field] = &types.AttributeValueMemberM{Value: nested}
			if _, decodeErr := sessionControlCloseTaskAuditFromItem(copy, audit.OwnerPK, audit.EventID); !errors.Is(decodeErr, errSessionControlCleanupCorrupt) {
				t.Fatalf("missing %s.%s = %v", tt.field, tt.nested, decodeErr)
			}
		})
	}
}

func TestSessionControlCloseTaskAuditRejectsImpossibleRedigestedRows(t *testing.T) {
	fixture := newSessionControlCleanupFixture(t, 1)
	audit, err := fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
		sessionControlCleanupRequest(fixture, fixture.ownerPK, 0xcd00))
	if err != nil {
		t.Fatal(err)
	}
	impossible := *audit
	impossible.OwnerAfter.WorkVersion++
	impossible.AuditDigest, err = sessionControlCloseTaskAuditDigest(impossible)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := sessionControlCloseCompleteToRow(impossible.Complete)
	if err != nil {
		t.Fatal(err)
	}
	task, err := sessionControlCloseTaskToRow(impossible.AckedTask)
	if err != nil {
		t.Fatal(err)
	}
	before, err := sessionControlOwnerToRow(impossible.OwnerBefore)
	if err != nil {
		t.Fatal(err)
	}
	after, err := sessionControlOwnerToRow(impossible.OwnerAfter)
	if err != nil {
		t.Fatal(err)
	}
	row := sessionControlCloseTaskAuditRow{PK: impossible.OwnerPK,
		SK: sessionControlCloseTaskAuditSK(impossible.EventID), Kind: sessionControlCloseTaskAuditKind,
		SchemaVersion: sessionControlCloseTaskAuditSchema, CellID: impossible.CellID, EventID: impossible.EventID,
		OwnerPK: impossible.OwnerPK, ManifestIndex: impossible.ManifestIndex, Complete: complete, AckedTask: task,
		OwnerBefore: before, OwnerAfter: after, OperationID: impossible.OperationID,
		OperationInputDigest: impossible.OperationInputDigest, CleanedAtMillis: impossible.CleanedAtMillis,
		RetainUntilMillis: impossible.RetainUntilMillis, AuditDigest: impossible.AuditDigest}
	item := marshalSessionControlSessionTestRow(t, row)
	if _, err = sessionControlCloseTaskAuditFromItem(item, impossible.OwnerPK, impossible.EventID); !errors.Is(err, errSessionControlCleanupCorrupt) {
		t.Fatalf("redigested impossible audit = %v", err)
	}
	validRow, err := sessionControlCloseTaskAuditToRow(*audit)
	if err != nil {
		t.Fatal(err)
	}
	validItem := marshalSessionControlSessionTestRow(t, validRow)
	for _, field := range []string{"manifest_index", "cleaned_at_ms", "retain_until_ms"} {
		copy := make(map[string]types.AttributeValue, len(validItem))
		for key, value := range validItem {
			copy[key] = value
		}
		delete(copy, field)
		if _, decodeErr := sessionControlCloseTaskAuditFromItem(copy, audit.OwnerPK, audit.EventID); !errors.Is(decodeErr, errSessionControlCleanupCorrupt) {
			t.Fatalf("missing %s = %v", field, decodeErr)
		}
	}
	validItem["ttl"] = &types.AttributeValueMemberN{Value: "1"}
	if _, err = sessionControlCloseTaskAuditFromItem(validItem, audit.OwnerPK, audit.EventID); !errors.Is(err, errSessionControlCleanupCorrupt) {
		t.Fatalf("TTL-bearing audit = %v", err)
	}
}

func TestSessionControlCloseTaskCleanupTokenBindsEveryPayload(t *testing.T) {
	fixture := newSessionControlCleanupFixture(t, 1)
	audit, err := fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
		sessionControlCleanupRequest(fixture, fixture.ownerPK, 0xce00))
	if err != nil {
		t.Fatal(err)
	}
	base, err := sessionControlCloseTaskCleanupToken(fixture.store.tableName, audit.Complete,
		audit.AckedTask, audit.OwnerBefore, audit.OwnerAfter, *audit)
	if err != nil || len(aws.ToString(base)) > 36 {
		t.Fatalf("base token = %q, %v", aws.ToString(base), err)
	}
	replay, err := sessionControlCloseTaskCleanupToken(fixture.store.tableName, audit.Complete,
		audit.AckedTask, audit.OwnerBefore, audit.OwnerAfter, *audit)
	if err != nil || aws.ToString(replay) != aws.ToString(base) {
		t.Fatalf("replay token = %q, %v", aws.ToString(replay), err)
	}
	tests := []struct {
		name     string
		complete sessionControlCloseComplete
		task     sessionControlCloseTask
		before   sessionControlOwnerAuthority
		after    sessionControlOwnerAuthority
		audit    sessionControlCloseTaskAudit
	}{
		{name: "complete", complete: func() sessionControlCloseComplete {
			value := audit.Complete
			value.RetainUntilMillis++
			return value
		}(), task: audit.AckedTask, before: audit.OwnerBefore, after: audit.OwnerAfter, audit: *audit},
		{name: "task", complete: audit.Complete, task: func() sessionControlCloseTask {
			value := audit.AckedTask
			value.AckClosed++
			return value
		}(), before: audit.OwnerBefore, after: audit.OwnerAfter, audit: *audit},
		{name: "owner before", complete: audit.Complete, task: audit.AckedTask,
			before: func() sessionControlOwnerAuthority { value := audit.OwnerBefore; value.WorkVersion++; return value }(),
			after:  audit.OwnerAfter, audit: *audit},
		{name: "owner after", complete: audit.Complete, task: audit.AckedTask, before: audit.OwnerBefore,
			after: func() sessionControlOwnerAuthority { value := audit.OwnerAfter; value.WorkVersion++; return value }(),
			audit: *audit},
		{name: "audit", complete: audit.Complete, task: audit.AckedTask, before: audit.OwnerBefore,
			after: audit.OwnerAfter, audit: func() sessionControlCloseTaskAudit {
				value := *audit
				value.RetainUntilMillis++
				return value
			}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, tokenErr := sessionControlCloseTaskCleanupToken(fixture.store.tableName,
				tt.complete, tt.task, tt.before, tt.after, tt.audit)
			if tokenErr != nil || aws.ToString(token) == aws.ToString(base) {
				t.Fatalf("mutated token = %q, %v", aws.ToString(token), tokenErr)
			}
		})
	}
}

func TestDynamoSessionControlCleanupStrongReadFailuresAreOperational(t *testing.T) {
	for _, failSK := range []string{sessionControlCloseCompleteSK, sessionControlCloseTaskSetSK,
		sessionControlCloseManifestSK(0), sessionControlCloseAckChunkSK(0),
		sessionControlCloseTaskSK("placeholder"), sessionControlCloseTaskAuditSK("placeholder")} {
		t.Run(fmt.Sprintf("%q", failSK), func(t *testing.T) {
			fixture := newSessionControlCleanupFixture(t, 1)
			injected := errors.New("injected strong read failure")
			if failSK == sessionControlCloseTaskSK("placeholder") {
				failSK = sessionControlCloseTaskSK(fixture.close.EventID)
			}
			if failSK == sessionControlCloseTaskAuditSK("placeholder") {
				failSK = sessionControlCloseTaskAuditSK(fixture.close.EventID)
			}
			fixture.fake.getHook = func(ctx context.Context, input *dynamodb.GetItemInput,
				_ int) (*dynamodb.GetItemOutput, error) {
				sk, _ := input.Key["sk"].(*types.AttributeValueMemberS)
				if sk != nil && sk.Value == failSK {
					return nil, injected
				}
				fixture.fake.mu.Lock()
				defer fixture.fake.mu.Unlock()
				return &dynamodb.GetItemOutput{Item: fixture.fake.items[sessionControlSessionDynamoMapKey(input.Key)]}, nil
			}
			_, err := fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
				sessionControlCleanupRequest(fixture, fixture.ownerPK, 0xc600))
			if !errors.Is(err, injected) {
				t.Fatalf("strong read failure = %v", err)
			}
		})
	}
}

func TestDynamoSessionControlCleanupAmbiguousTaskAbsenceReadFailurePreservesWriteError(t *testing.T) {
	fixture := newSessionControlCleanupFixture(t, 1)
	writeErr := errors.New("ambiguous cleanup transport")
	readErr := errors.New("task absence strong read failed")
	fixture.fake.transactHook = func(_ context.Context,
		input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		applySessionControlCleanupTransaction(fixture.fake, input)
		return nil, writeErr
	}
	fixture.fake.getHook = func(ctx context.Context, input *dynamodb.GetItemInput,
		_ int) (*dynamodb.GetItemOutput, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fixture.fake.mu.Lock()
		defer fixture.fake.mu.Unlock()
		item := fixture.fake.items[sessionControlSessionDynamoMapKey(input.Key)]
		sk, _ := input.Key["sk"].(*types.AttributeValueMemberS)
		if sk != nil && sk.Value == sessionControlCloseTaskSK(fixture.close.EventID) && len(item) == 0 {
			return nil, readErr
		}
		return &dynamodb.GetItemOutput{Item: item}, nil
	}
	_, err := fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
		sessionControlCleanupRequest(fixture, fixture.ownerPK, 0xcf00))
	if !errors.Is(err, writeErr) || errors.Is(err, readErr) {
		t.Fatalf("ambiguous cleanup classification = %v", err)
	}
}
