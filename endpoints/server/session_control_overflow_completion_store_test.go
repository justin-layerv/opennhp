package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type sessionControlOverflowCompletionFixture struct {
	sessionControlCompletionFixture
	leader          sessionControlOverflowLeader
	ackTransactions []*dynamodb.TransactWriteItemsInput
}

func newSessionControlOverflowCompletionFixture(t *testing.T, count int) sessionControlOverflowCompletionFixture {
	t.Helper()
	overflow := newSessionControlOverflowMaterializationFixture(t, count)
	taskSet, err := overflow.store.MaterializeSelectedOverflowExactClose(context.Background(), overflow.candidate,
		overflow.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	taskFixture := sessionControlTaskFixture{sessionControlMaterializationFixture: overflow.sessionControlMaterializationFixture,
		taskSet: *taskSet}
	if count > 0 {
		taskFixture.ownerPK = resultOwnerPK(t, overflow.intents[0])
		task, readErr := overflow.store.getCloseTask(context.Background(), taskFixture.ownerPK, overflow.close.EventID)
		if readErr != nil {
			t.Fatal(readErr)
		}
		taskFixture.task = *task
	}
	fixture := sessionControlOverflowCompletionFixture{sessionControlCompletionFixture: sessionControlCompletionFixture{
		sessionControlTaskFixture: taskFixture}, leader: overflow.leader}
	installSessionControlCompletionTransactionFake(fixture.fake)
	seedSessionControlCompletionAckedTasks(t, &fixture.sessionControlCompletionFixture)
	fixture.fake.mu.Lock()
	fixture.fake.transactions = nil
	fixture.fake.mu.Unlock()
	for index := range taskSet.ManifestDigests {
		chunk, chunkErr := fixture.store.PrepareExactCloseAckChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, uint64(index))
		if chunkErr != nil {
			t.Fatalf("prepare overflow ACK chunk %d: %v", index, chunkErr)
		}
		fixture.chunks = append(fixture.chunks, *chunk)
	}
	fixture.fake.mu.Lock()
	fixture.ackTransactions = append(fixture.ackTransactions, fixture.fake.transactions...)
	fixture.fake.transactions = nil
	fixture.fake.mu.Unlock()
	return fixture
}

func TestDynamoSessionControlOverflowAckChunkBindsModeWorkAndLeader(t *testing.T) {
	fixture := newSessionControlOverflowCompletionFixture(t, 1)
	if len(fixture.ackTransactions) != 1 {
		t.Fatalf("ACK chunk transactions = %d", len(fixture.ackTransactions))
	}
	txn := fixture.ackTransactions[0]
	if len(txn.TransactItems) != 7 || len(aws.ToString(txn.ClientRequestToken)) > 36 ||
		txn.TransactItems[4].ConditionCheck == nil || txn.TransactItems[6].Put == nil {
		t.Fatalf("overflow ACK chunk transaction = %#v", txn)
	}
	directoryCheck := txn.TransactItems[4].ConditionCheck
	if sessionControlSessionDynamoMapKey(directoryCheck.Key) !=
		sessionControlSessionDynamoMapKey(sessionControlFenceDirectoryKey(fixture.candidate.CellID)) ||
		!strings.Contains(aws.ToString(directoryCheck.ConditionExpression), "overflow_leader_event_id") {
		t.Fatalf("overflow ACK chunk leader condition = %#v", directoryCheck)
	}
	chunk, err := sessionControlCloseAckChunkFromItem(txn.TransactItems[6].Put.Item,
		fixture.close.EventID, 0)
	if err != nil || chunk.WorkMode != sessionControlCloseWorkModeOverflow {
		t.Fatalf("overflow ACK chunk row = %#v, %v", chunk, err)
	}
}

func applySessionControlOverflowPromotionTransaction(fake *sessionControlSessionDynamoFake,
	input *dynamodb.TransactWriteItemsInput) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, member := range input.TransactItems {
		switch {
		case member.Put != nil:
			fake.items[sessionControlSessionDynamoMapKey(member.Put.Item)] = member.Put.Item
		case member.Delete != nil:
			delete(fake.items, sessionControlSessionDynamoMapKey(member.Delete.Key))
		case member.Update != nil:
			key := sessionControlSessionDynamoMapKey(member.Update.Key)
			item := fake.items[key]
			if item == nil {
				continue
			}
			copy := make(map[string]types.AttributeValue, len(item))
			for name, value := range item {
				copy[name] = value
			}
			if retain := member.Update.ExpressionAttributeValues[":next_retain"]; retain != nil {
				copy["retain_until_ms"] = retain
			}
			fake.items[key] = copy
		}
	}
}

func installSessionControlOverflowPromotionTransactionFake(fake *sessionControlSessionDynamoFake) {
	fake.transactHook = func(ctx context.Context,
		input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		applySessionControlOverflowPromotionTransaction(fake, input)
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}
}

func makeOverflowPromotionEligible(t *testing.T, fixture *sessionControlOverflowCompletionFixture,
	active uint64) sessionControlFenceDirectory {
	t.Helper()
	directory := fixture.leader.Directory
	directory.ActiveFenceCount = active
	seedSessionControlCloseDirectory(t, fixture.fake, directory)
	installSessionControlOverflowPromotionTransactionFake(fixture.fake)
	return directory
}

func TestDynamoSessionControlPromoteOverflowTransactionArithmeticAndReplay(t *testing.T) {
	for _, count := range []int{0, 47, 48, int(sessionControlSessionMaxTargets)} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			fixture := newSessionControlOverflowCompletionFixture(t, count)
			before := makeOverflowPromotionEligible(t, &fixture, sessionControlFenceActiveLimit-1)
			hasNext := count == int(sessionControlSessionMaxTargets)
			var next sessionControlCloseWork
			if hasNext {
				next = makeOverflowCloseWork(t, before.CellID, 102, fixture.close.Work.PreparedDirectoryVersion+1)
				next.CreatedAtMillis = fixture.close.Work.CreatedAtMillis + 1
				next.UpdatedAtMillis, next.DueAtMillis = next.CreatedAtMillis, next.CreatedAtMillis
				seedSessionControlCloseWork(t, fixture.fake, next)
				before.OverflowCloseCount = 2
				seedSessionControlCloseDirectory(t, fixture.fake, before)
			}
			complete, err := fixture.store.PromoteCompletedOverflowExactClose(context.Background(), fixture.candidate,
				fixture.close.EventID, 0)
			if err != nil {
				t.Fatal(err)
			}
			wantItems := 8 + len(fixture.chunks)
			if hasNext {
				wantItems += 2
			}
			if len(fixture.fake.transactions) != 1 ||
				len(fixture.fake.transactions[0].TransactItems) != wantItems ||
				len(aws.ToString(fixture.fake.transactions[0].ClientRequestToken)) > 36 ||
				complete.WorkMode != sessionControlCloseWorkModeOverflow {
				t.Fatalf("promotion transaction/result = %d/%#v", len(fixture.fake.transactions[0].TransactItems), complete)
			}
			txn := fixture.fake.transactions[0]
			if txn.TransactItems[0].Put == nil || txn.TransactItems[1].Delete == nil ||
				txn.TransactItems[2].Delete == nil || txn.TransactItems[3].Put == nil ||
				txn.TransactItems[4].Put == nil || txn.TransactItems[5].Update == nil ||
				txn.TransactItems[6].ConditionCheck == nil {
				t.Fatalf("promotion base members = %#v", txn.TransactItems[:7])
			}
			for _, member := range txn.TransactItems {
				if member.Put != nil && member.Put.Item["ttl"] != nil {
					t.Fatalf("promotion wrote TTL-bearing correctness row: %#v", member.Put.Item)
				}
			}
			after, readErr := fixture.store.getFenceDirectory(context.Background(), fixture.candidate.CellID)
			wantOverflowCount := uint64(0)
			if hasNext {
				wantOverflowCount = 1
			}
			if readErr != nil || after.Version != before.Version+1 ||
				after.ActiveFenceCount != sessionControlFenceActiveLimit ||
				after.AdmissionBlocked != hasNext || after.OverflowCloseCount != wantOverflowCount ||
				(hasNext && after.OverflowLeaderEventID != next.EventID) || (!hasNext && after.OverflowLeaderEventID != "") {
				t.Fatalf("promoted directory = %#v, %v", after, readErr)
			}
			if _, readErr = fixture.store.getCloseWork(context.Background(), fixture.candidate.CellID,
				fixture.close.EventID, true); !errors.Is(readErr, errSessionControlSessionNotFound) {
				t.Fatalf("overflow header after promotion = %v", readErr)
			}
			if _, readErr = fixture.store.getOverflowOrder(context.Background(), fixture.close.Work); !errors.Is(readErr, errSessionControlCloseConflict) {
				t.Fatalf("overflow order after promotion = %v", readErr)
			}
			replayed, replayErr := fixture.store.EnsureExactSessionClose(context.Background(), fixture.candidate,
				complete.RetainUntilMillis)
			if replayErr != nil || replayed.Complete == nil || replayed.Work != (sessionControlCloseWork{}) ||
				replayed.Complete.CompleteDigest != complete.CompleteDigest {
				t.Fatalf("post-promotion close replay = %#v, %v", replayed, replayErr)
			}
			stronger := complete.RetainUntilMillis + 1
			extended, extendErr := fixture.store.EnsureExactSessionClose(context.Background(), fixture.candidate, stronger)
			if extendErr != nil || extended.Complete == nil || extended.Session.RetainUntilMillis != stronger ||
				extended.Complete.RetainUntilMillis != stronger {
				t.Fatalf("post-promotion retention extension = %#v, %v", extended, extendErr)
			}
			if _, normalErr := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
				fixture.close.EventID, 0); !errors.Is(normalErr, errSessionControlCompletionConflict) {
				t.Fatalf("normal wrapper accepted overflow COMPLETE: %v", normalErr)
			}
		})
	}
}

func TestDynamoSessionControlPromoteOverflowCapacityAndNextOrderFence(t *testing.T) {
	t.Run("capacity", func(t *testing.T) {
		fixture := newSessionControlOverflowCompletionFixture(t, 0)
		installSessionControlOverflowPromotionTransactionFake(fixture.fake)
		if _, err := fixture.store.PromoteCompletedOverflowExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID, 0); !errors.Is(err, errSessionControlCompletionConflict) {
			t.Fatalf("promotion at active cap error = %v", err)
		}
	})
	t.Run("next_order_condition", func(t *testing.T) {
		fixture := newSessionControlOverflowCompletionFixture(t, 0)
		directory := fixture.leader.Directory
		directory.ActiveFenceCount = sessionControlFenceActiveLimit - 1
		directory.OverflowCloseCount = 2
		next := makeOverflowCloseWork(t, directory.CellID, 99, fixture.close.Work.PreparedDirectoryVersion+1)
		next.CreatedAtMillis = fixture.close.Work.CreatedAtMillis + 1
		next.UpdatedAtMillis, next.DueAtMillis = next.CreatedAtMillis, next.CreatedAtMillis
		seedSessionControlCloseWork(t, fixture.fake, next)
		seedSessionControlCloseDirectory(t, fixture.fake, directory)
		installSessionControlOverflowPromotionTransactionFake(fixture.fake)
		_, err := fixture.store.PromoteCompletedOverflowExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID, 0)
		if err != nil {
			t.Fatal(err)
		}
		txn := fixture.fake.transactions[0]
		if len(txn.TransactItems) != 10 || txn.TransactItems[len(txn.TransactItems)-2].ConditionCheck == nil ||
			txn.TransactItems[len(txn.TransactItems)-1].ConditionCheck == nil {
			t.Fatalf("next header/order conditions = %#v", txn.TransactItems)
		}
		last := txn.TransactItems[len(txn.TransactItems)-1].ConditionCheck
		if got := sessionControlSessionDynamoMapKey(last.Key); got != sessionControlSessionDynamoMapKey(sessionControlOverflowOrderKey(next)) {
			t.Fatalf("next order condition key = %q", got)
		}
	})
	t.Run("next_order_deleted_after_read", func(t *testing.T) {
		fixture := newSessionControlOverflowCompletionFixture(t, 0)
		directory := fixture.leader.Directory
		directory.ActiveFenceCount = sessionControlFenceActiveLimit - 1
		directory.OverflowCloseCount = 2
		next := makeOverflowCloseWork(t, directory.CellID, 100, fixture.close.Work.PreparedDirectoryVersion+1)
		next.CreatedAtMillis = fixture.close.Work.CreatedAtMillis + 1
		next.UpdatedAtMillis, next.DueAtMillis = next.CreatedAtMillis, next.CreatedAtMillis
		seedSessionControlCloseWork(t, fixture.fake, next)
		seedSessionControlCloseDirectory(t, fixture.fake, directory)
		fixture.fake.transactHook = func(_ context.Context,
			_ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			fixture.fake.mu.Lock()
			delete(fixture.fake.items, sessionControlSessionDynamoMapKey(sessionControlOverflowOrderKey(next)))
			fixture.fake.mu.Unlock()
			return nil, &types.TransactionCanceledException{}
		}
		if _, err := fixture.store.PromoteCompletedOverflowExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID, 0); err == nil {
			t.Fatal("promotion accepted deleted next ORDER")
		}
		if _, err := fixture.store.getCloseComplete(context.Background(), fixture.close.EventID); !errors.Is(err, errSessionControlCompletionNotFound) {
			t.Fatalf("unexpected COMPLETE after next-order race: %v", err)
		}
	})
	t.Run("concurrent_create_prevents_clear", func(t *testing.T) {
		fixture := newSessionControlOverflowCompletionFixture(t, 0)
		directory := fixture.leader.Directory
		directory.ActiveFenceCount = sessionControlFenceActiveLimit - 1
		seedSessionControlCloseDirectory(t, fixture.fake, directory)
		next := makeOverflowCloseWork(t, directory.CellID, 101, fixture.close.Work.PreparedDirectoryVersion+1)
		next.CreatedAtMillis = fixture.close.Work.CreatedAtMillis + 1
		next.UpdatedAtMillis, next.DueAtMillis = next.CreatedAtMillis, next.CreatedAtMillis
		calls := 0
		fixture.fake.transactHook = func(_ context.Context,
			input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			if calls == 0 {
				calls++
				seedSessionControlCloseWork(t, fixture.fake, next)
				concurrent := directory
				concurrent.Version++
				concurrent.OverflowCloseCount++
				concurrent.UpdatedAtMillis++
				seedSessionControlCloseDirectory(t, fixture.fake, concurrent)
				return nil, &types.TransactionCanceledException{}
			}
			applySessionControlOverflowPromotionTransaction(fixture.fake, input)
			return &dynamodb.TransactWriteItemsOutput{}, nil
		}
		if _, err := fixture.store.PromoteCompletedOverflowExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID, 0); err != nil {
			t.Fatal(err)
		}
		after, err := fixture.store.getFenceDirectory(context.Background(), fixture.candidate.CellID)
		if err != nil || !after.AdmissionBlocked || after.OverflowCloseCount != 1 ||
			after.OverflowLeaderEventID != next.EventID {
			t.Fatalf("directory cleared across concurrent create = %#v, %v", after, err)
		}
	})
}

func TestDynamoSessionControlPromoteOverflowAcceptsCompatibleClockWinner(t *testing.T) {
	fixture := newSessionControlOverflowCompletionFixture(t, 0)
	makeOverflowPromotionEligible(t, &fixture, sessionControlFenceActiveLimit-1)
	fixture.fake.transactHook = func(_ context.Context,
		input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		for _, member := range input.TransactItems {
			if member.Put == nil {
				continue
			}
			complete, decodeErr := sessionControlCloseCompleteFromItem(member.Put.Item, fixture.close.EventID)
			if decodeErr != nil {
				continue
			}
			complete.CompletedAtMillis++
			complete.FenceReplayNotBeforeMillis++
			if complete.RetainUntilMillis < complete.FenceReplayNotBeforeMillis {
				complete.RetainUntilMillis = complete.FenceReplayNotBeforeMillis
			}
			complete.CompleteDigest, decodeErr = sessionControlCloseCompleteDigest(complete)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			row, rowErr := sessionControlCloseCompleteToRow(complete)
			if rowErr != nil {
				t.Fatal(rowErr)
			}
			fixture.fake.setItem(marshalSessionControlSessionTestRow(t, row))
			return nil, &types.TransactionCanceledException{}
		}
		return nil, errors.New("missing COMPLETE put")
	}
	complete, err := fixture.store.PromoteCompletedOverflowExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID, 0)
	if err != nil || complete.CompletedAtMillis <= fixture.close.Work.CreatedAtMillis {
		t.Fatalf("compatible promoter winner = %#v, %v", complete, err)
	}
}

func TestDynamoSessionControlPromoteOverflowClassifiesLostResponseCountOnce(t *testing.T) {
	fixture := newSessionControlOverflowCompletionFixture(t, 0)
	makeOverflowPromotionEligible(t, &fixture, sessionControlFenceActiveLimit-1)
	fixture.fake.transactHook = func(_ context.Context,
		input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		applySessionControlOverflowPromotionTransaction(fixture.fake, input)
		return nil, errors.New("lost promotion response")
	}
	complete, err := fixture.store.PromoteCompletedOverflowExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID, 0)
	if err != nil || complete.WorkMode != sessionControlCloseWorkModeOverflow {
		t.Fatalf("lost promotion response = %#v, %v", complete, err)
	}
	directory, err := fixture.store.getFenceDirectory(context.Background(), fixture.candidate.CellID)
	if err != nil || directory.OverflowCloseCount != 0 || directory.ActiveFenceCount != sessionControlFenceActiveLimit {
		t.Fatalf("lost-response directory = %#v, %v", directory, err)
	}
	replayed, err := fixture.store.PromoteCompletedOverflowExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID, 0)
	if err != nil || replayed.CompleteDigest != complete.CompleteDigest || len(fixture.fake.transactions) != 1 {
		t.Fatalf("promotion replay = %#v, %v; transactions=%d", replayed, err, len(fixture.fake.transactions))
	}
}

func TestDynamoSessionControlOverflowCompletionRejectsRedigestedChunkAuthorityMutation(t *testing.T) {
	fixture := newSessionControlOverflowCompletionFixture(t, 1)
	makeOverflowPromotionEligible(t, &fixture, sessionControlFenceActiveLimit-1)
	chunk := fixture.chunks[0]
	chunk.SessionVersion++
	chunk.ChunkDigest = ""
	var err error
	chunk.ChunkDigest, err = sessionControlCloseAckChunkDigest(chunk)
	if err != nil {
		t.Fatal(err)
	}
	row, err := sessionControlCloseAckChunkToRow(chunk)
	if err != nil {
		t.Fatal(err)
	}
	fixture.fake.setItem(marshalSessionControlSessionTestRow(t, row))
	if _, err = fixture.store.PromoteCompletedOverflowExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID, 0); !errors.Is(err, errSessionControlCompletionCorrupt) {
		t.Fatalf("mutated overflow chunk error = %v", err)
	}
}

func TestDynamoSessionControlOverflowCompleteSupportsLateAckAndCleanup(t *testing.T) {
	fixture := newSessionControlOverflowCompletionFixture(t, 1)
	makeOverflowPromotionEligible(t, &fixture, sessionControlFenceActiveLimit-1)
	complete, err := fixture.store.PromoteCompletedOverflowExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	task, err := fixture.store.getCloseTask(context.Background(), fixture.ownerPK, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	lease := sessionControlCloseTaskLeaseRequest{CellID: task.CellID, EventID: task.EventID, OwnerPK: task.OwnerPK,
		OperationID: task.LastOperationID, LeaseID: task.AckLeaseID, LeaseOwner: task.AckLeaseOwner}
	request := sessionControlTaskAckRequest(fixture.sessionControlTaskFixture, *task, lease, task.AckClosed+1)
	late, err := fixture.store.AckExactCloseTask(context.Background(), request)
	if err != nil || late.AckClosed != task.AckClosed {
		t.Fatalf("late overflow ACK = %#v, %v", late, err)
	}
	installSessionControlCleanupTransactionFake(fixture.fake)
	cleanup := sessionControlCloseTaskCleanupRequest{
		CellID: fixture.candidate.CellID, EventID: fixture.close.EventID, OwnerPK: task.OwnerPK,
		OperationID: sessionControlTaskTestID(0xfa01)}
	if _, normalErr := fixture.store.CleanupAckedNormalExactCloseTask(context.Background(), cleanup); !errors.Is(normalErr, errSessionControlCleanupConflict) {
		t.Fatalf("normal cleanup wrapper accepted overflow COMPLETE: %v", normalErr)
	}
	if _, normalErr := fixture.store.ListCompletedNormalExactCloseTasksPage(context.Background(),
		fixture.candidate.CellID, fixture.close.EventID, nil, 1); !errors.Is(normalErr, errSessionControlCleanupConflict) {
		t.Fatalf("normal cleanup pager accepted overflow COMPLETE: %v", normalErr)
	}
	audit, err := fixture.store.CleanupAckedExactCloseTask(context.Background(), cleanup)
	if err != nil || audit.Complete.CompleteDigest != complete.CompleteDigest ||
		audit.Complete.WorkMode != sessionControlCloseWorkModeOverflow {
		t.Fatalf("overflow cleanup = %#v, %v", audit, err)
	}
}

func TestSessionControlOverflowOrderCanonicalKeyAndStrictNestedWork(t *testing.T) {
	base := makeOverflowCloseWork(t, "cell-01", 7, 9)
	laterVersion := base
	laterVersion.PreparedDirectoryVersion++
	laterVersion.EventID = strings.Repeat("0", 32)
	laterTime := base
	laterTime.CreatedAtMillis++
	laterTime.UpdatedAtMillis, laterTime.DueAtMillis = laterTime.CreatedAtMillis, laterTime.CreatedAtMillis
	if !(sessionControlOverflowOrderSK(base) < sessionControlOverflowOrderSK(laterTime) &&
		sessionControlOverflowOrderSK(laterTime) < sessionControlOverflowOrderSK(laterVersion)) {
		t.Fatalf("overflow order keys are not canonical: %q %q %q", sessionControlOverflowOrderSK(base),
			sessionControlOverflowOrderSK(laterTime), sessionControlOverflowOrderSK(laterVersion))
	}
	digest, err := sessionControlOverflowOrderDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	row, err := sessionControlOverflowOrderToRow(sessionControlOverflowOrder{Work: base, WorkDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		t.Fatal(err)
	}
	workMap := item["work"].(*types.AttributeValueMemberM)
	delete(workMap.Value, "expected_target_count")
	if _, err = sessionControlOverflowOrderFromItem(item, base.CellID); !errors.Is(err, errSessionControlCloseCorrupt) {
		t.Fatalf("missing nested zero-capable field error = %v", err)
	}
	item, err = attributevalue.MarshalMap(row)
	if err != nil {
		t.Fatal(err)
	}
	item["ttl"] = &types.AttributeValueMemberN{Value: "1"}
	if _, err = sessionControlOverflowOrderFromItem(item, base.CellID); !errors.Is(err, errSessionControlCloseCorrupt) {
		t.Fatalf("TTL-bearing ORDER error = %v", err)
	}
}
