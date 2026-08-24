package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func sessionControlCloseTestDirectory(snapshot sessionControlFenceSnapshot, createdAtMillis int64) sessionControlFenceDirectory {
	return sessionControlFenceDirectory{
		CellID: snapshot.CellID, Version: snapshot.DirectoryVersion, ActiveFenceCount: snapshot.ActiveFenceCount,
		AdmissionBlocked: snapshot.AdmissionBlocked, OverflowCloseCount: snapshot.OverflowCloseCount,
		CreatedAtMillis: createdAtMillis, UpdatedAtMillis: createdAtMillis,
	}
}

func seedSessionControlCloseDirectory(t *testing.T, fake *sessionControlSessionDynamoFake, directory sessionControlFenceDirectory) {
	t.Helper()
	row, err := sessionControlFenceDirectoryToRow(directory)
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, row))
}

func seedSessionControlCloseFence(t *testing.T, fake *sessionControlSessionDynamoFake, fence sessionControlFenceAuthority) {
	t.Helper()
	for _, active := range []bool{false, true} {
		row, err := sessionControlFenceToRow(fence, active)
		if err != nil {
			t.Fatal(err)
		}
		fake.setItem(marshalSessionControlSessionTestRow(t, row))
	}
}

func seedSessionControlCloseWork(t *testing.T, fake *sessionControlSessionDynamoFake, work sessionControlCloseWork) {
	t.Helper()
	row, err := sessionControlCloseWorkToRow(work)
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, row))
	if work.Mode == sessionControlCloseWorkModeOverflow {
		orderPut, err := sessionControlOverflowOrderPut("session-control-test", work)
		if err != nil {
			t.Fatal(err)
		}
		fake.setItem(orderPut.Put.Item)
	}
}

func expectedSessionControlExactClose(t *testing.T, current sessionControlSessionAuthority,
	directory sessionControlFenceDirectory, transactionMillis, retainUntilMillis int64) sessionControlExactClosePreparation {
	t.Helper()
	eventID := sessionControlExactCloseEventID(current.Candidate)
	minimumRetain := transactionMillis + sessionControlFenceReplayHorizon.Milliseconds()
	if retainUntilMillis < minimumRetain {
		retainUntilMillis = minimumRetain
	}
	planned, err := planSessionControlExactClose(current, eventID, directory.Version+1, transactionMillis, retainUntilMillis)
	if err != nil {
		t.Fatal(err)
	}
	selector := sessionControlExactCloseSelector(current.Candidate)
	digest, err := sessionControlFenceSelectorDigest(selector)
	if err != nil {
		t.Fatal(err)
	}
	overflow := directory.AdmissionBlocked || directory.ActiveFenceCount >= sessionControlFenceActiveLimit
	work := sessionControlCloseWork{
		CellID: current.Candidate.CellID, EventID: eventID, Selector: selector, SelectorDigest: digest,
		Mode: sessionControlCloseWorkModeNormal, State: sessionControlCloseWorkStatePending,
		PreparedDirectoryVersion: directory.Version + 1, SessionVersion: current.Version,
		ExpectedTargetCount: current.TargetCount, CreatedAtMillis: transactionMillis,
		UpdatedAtMillis: transactionMillis, DueAtMillis: transactionMillis,
	}
	preparation := sessionControlExactClosePreparation{EventID: eventID, Session: planned, Work: work, Overflow: overflow}
	if overflow {
		preparation.Work.Mode = sessionControlCloseWorkModeOverflow
		return preparation
	}
	fence := sessionControlFenceAuthority{
		CellID: current.Candidate.CellID, EventID: eventID, Selector: selector, SelectorDigest: digest,
		PreparedDirectoryVersion: directory.Version + 1, State: sessionControlFencePreparing, Version: 1,
		CreatedAtMillis: transactionMillis, PreparedAtMillis: transactionMillis, UpdatedAtMillis: transactionMillis,
	}
	preparation.Fence = &fence
	return preparation
}

func seedCommittedSessionControlExactClose(t *testing.T, fake *sessionControlSessionDynamoFake,
	directory sessionControlFenceDirectory, preparation sessionControlExactClosePreparation) {
	t.Helper()
	directory.Version++
	directory.UpdatedAtMillis = preparation.Work.CreatedAtMillis
	if preparation.Overflow {
		directory.AdmissionBlocked = true
		directory.OverflowCloseCount++
	} else {
		directory.ActiveFenceCount++
		seedSessionControlCloseFence(t, fake, *preparation.Fence)
	}
	seedSessionControlCloseDirectory(t, fake, directory)
	seedSessionControlReservation(t, fake, preparation.Session)
	seedSessionControlCloseWork(t, fake, preparation.Work)
}

func seedPromotedSessionControlOverflowClose(t *testing.T, fake *sessionControlSessionDynamoFake,
	preparation sessionControlExactClosePreparation, directory sessionControlFenceDirectory,
	retainUntilMillis int64) sessionControlCloseComplete {
	t.Helper()
	completedAt := preparation.Work.CreatedAtMillis + 1
	replay := completedAt + sessionControlFenceReplayHorizon.Milliseconds()
	if retainUntilMillis < replay {
		retainUntilMillis = replay
	}
	session := preparation.Session
	session.RetainUntilMillis = retainUntilMillis
	fence := sessionControlFenceAuthority{CellID: session.Candidate.CellID, EventID: preparation.EventID,
		Selector: preparation.Work.Selector, SelectorDigest: preparation.Work.SelectorDigest,
		PreparedDirectoryVersion: preparation.Work.PreparedDirectoryVersion,
		State:                    sessionControlFenceConverged, Version: 2, CreatedAtMillis: preparation.Work.CreatedAtMillis,
		PreparedAtMillis: preparation.Work.CreatedAtMillis, ConvergedAtMillis: completedAt,
		ReplayNotBeforeMillis: replay, UpdatedAtMillis: completedAt}
	directory.Version = preparation.Work.PreparedDirectoryVersion + 2
	directory.AdmissionBlocked = false
	directory.OverflowCloseCount = 0
	directory.OverflowLeaderEventID = ""
	directory.OverflowLeaderPreparedDirectoryVersion = 0
	directory.OverflowLeaderSelectedDirectoryVersion = 0
	directory.UpdatedAtMillis = completedAt
	complete := sessionControlCloseComplete{CellID: session.Candidate.CellID, EventID: preparation.EventID,
		SelectorDigest: preparation.Work.SelectorDigest, AgentPublicKey: session.Candidate.AgentPublicKey,
		SessionID: session.Candidate.SessionID, SessionIssuedMillis: session.Candidate.IssuedAtMillis,
		SessionVersion: session.Version, ExpectedTargetCount: session.TargetCount,
		PreparedDirectoryVersion: session.ClosePreparedDirectory, WorkMode: sessionControlCloseWorkModeOverflow,
		TaskSetDigest: strings.Repeat("a", 64), ManifestDigests: make([]string, 0), ChunkDigests: make([]string, 0),
		ChunkSourceCounts: make([]uint64, 0), ChunkOwnerCounts: make([]uint64, 0), FenceVersion: fence.Version,
		CompletedDirectoryVersion: directory.Version, FenceReplayNotBeforeMillis: replay,
		CompletedAtMillis: completedAt, RetainUntilMillis: retainUntilMillis}
	var err error
	complete.CompleteDigest, err = sessionControlCloseCompleteDigest(complete)
	if err != nil || validateSessionControlCloseComplete(complete) != nil {
		t.Fatalf("promoted overflow COMPLETE: %#v, %v", complete, err)
	}
	seedSessionControlReservation(t, fake, session)
	seedSessionControlCloseFence(t, fake, fence)
	seedSessionControlCloseDirectory(t, fake, directory)
	seedSessionControlCloseComplete(t, fake, complete)
	delete(fake.items, sessionControlSessionDynamoMapKey(sessionControlOverflowCloseKey(session.Candidate.CellID,
		preparation.EventID)))
	delete(fake.items, sessionControlSessionDynamoMapKey(sessionControlOverflowOrderKey(preparation.Work)))
	return complete
}

func newSessionControlExactCloseFixture(t *testing.T, directory sessionControlFenceDirectory) (*sessionControlSessionDynamoFake,
	*dynamoSessionControlStore, sessionControlSessionAuthority) {
	t.Helper()
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	candidate := testSessionControlSessionCandidate(0x91, 901)
	reserved, err := planSessionControlReservation(candidate, testSessionControlSessionSnapshot(1))
	if err != nil {
		t.Fatal(err)
	}
	seedSessionControlReservation(t, fake, reserved)
	seedSessionControlCloseDirectory(t, fake, directory)
	return fake, store, reserved
}

func TestDynamoSessionControlEnsureExactCloseNormalFiveItemWire(t *testing.T) {
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(7), 1_800_000_000_000)
	fake, store, reserved := newSessionControlExactCloseFixture(t, directory)
	got, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, reserved.RetainUntilMillis)
	if err != nil {
		t.Fatal(err)
	}
	wantRetain := store.nowUTC().UnixMilli() + sessionControlFenceReplayHorizon.Milliseconds()
	if got.Overflow || got.Fence == nil || got.Session.State != sessionControlSessionStateClosing ||
		got.Session.Version != reserved.Version || got.Session.TargetCount != reserved.TargetCount ||
		got.Session.RetainUntilMillis != wantRetain || got.Session.ClosePreparedAtMillis != store.nowUTC().UnixMilli() ||
		got.Work.SessionVersion != reserved.Version || got.Work.ExpectedTargetCount != 0 {
		t.Fatalf("normal close = %#v", got)
	}
	if len(fake.transactions) != 1 {
		t.Fatalf("transactions = %d, want 1", len(fake.transactions))
	}
	txn := fake.transactions[0]
	if len(txn.TransactItems) != 5 || len(aws.ToString(txn.ClientRequestToken)) > 36 {
		t.Fatalf("normal transaction/token = %d/%q", len(txn.TransactItems), aws.ToString(txn.ClientRequestToken))
	}
	if txn.TransactItems[0].Update == nil || txn.TransactItems[1].Put == nil || txn.TransactItems[2].Put == nil ||
		txn.TransactItems[3].Update == nil || txn.TransactItems[4].Put == nil {
		t.Fatalf("normal five members = %#v", txn.TransactItems)
	}
	directoryCondition := aws.ToString(txn.TransactItems[0].Update.ConditionExpression)
	if !strings.Contains(directoryCondition, "admission_blocked = :admission_blocked") ||
		!strings.Contains(directoryCondition, "overflow_close_count = :overflow_close_count") ||
		!strings.Contains(directoryCondition, "attribute_not_exists(#ttl)") || txn.TransactItems[0].Update.ExpressionAttributeNames["#ttl"] != "ttl" {
		t.Fatalf("directory condition = %q", directoryCondition)
	}
	sessionUpdate := txn.TransactItems[3].Update
	if strings.Contains(aws.ToString(sessionUpdate.UpdateExpression), "#version") ||
		!strings.Contains(aws.ToString(sessionUpdate.UpdateExpression), "close_prepared_at_ms") ||
		!strings.Contains(aws.ToString(sessionUpdate.UpdateExpression), "due_shard = :next_due_shard") ||
		!strings.Contains(aws.ToString(sessionUpdate.UpdateExpression), "due_sort = :next_due_sort") ||
		!strings.Contains(aws.ToString(sessionUpdate.ConditionExpression), "due_shard = :current_due_shard") ||
		!strings.Contains(aws.ToString(sessionUpdate.ConditionExpression), "due_sort = :current_due_sort") {
		t.Fatalf("session close update = %#v", sessionUpdate)
	}
	currentShard, currentShardOK := sessionUpdate.ExpressionAttributeValues[":current_due_shard"].(*types.AttributeValueMemberS)
	nextShard, nextShardOK := sessionUpdate.ExpressionAttributeValues[":next_due_shard"].(*types.AttributeValueMemberS)
	currentDue, currentDueOK := sessionUpdate.ExpressionAttributeValues[":current_due_sort"].(*types.AttributeValueMemberS)
	nextDue, nextDueOK := sessionUpdate.ExpressionAttributeValues[":next_due_sort"].(*types.AttributeValueMemberS)
	if !currentShardOK || !nextShardOK || currentShard.Value != sessionControlSessionDueShard(reserved.Candidate) ||
		nextShard.Value != sessionControlClosingSessionDueShard(reserved.Candidate) || currentShard.Value == nextShard.Value ||
		!currentDueOK || !nextDueOK || currentDue.Value != sessionControlSessionDueSort(reserved.Candidate) ||
		nextDue.Value != sessionControlClosingSessionDueSort(got.Session) || currentDue.Value == nextDue.Value {
		t.Fatalf("session close due transition shard=%#v/%#v sort=%#v/%#v", currentShard, nextShard,
			currentDue, nextDue)
	}
	reservedRow, err := sessionControlSessionToRow(reserved)
	if err != nil {
		t.Fatal(err)
	}
	applied := marshalSessionControlSessionTestRow(t, reservedRow)
	for field, placeholder := range map[string]string{
		"state":                            ":next_state",
		"retain_until_ms":                  ":next_retain",
		"close_event_id":                   ":close_event_id",
		"close_prepared_directory_version": ":close_prepared_version",
		"close_prepared_at_ms":             ":close_prepared_at",
		"due_shard":                        ":next_due_shard",
		"due_sort":                         ":next_due_sort",
	} {
		applied[field] = sessionUpdate.ExpressionAttributeValues[placeholder]
	}
	var appliedRow sessionControlSessionRow
	if err = attributevalue.UnmarshalMap(applied, &appliedRow); err != nil {
		t.Fatal(err)
	}
	appliedAuthority, err := sessionControlSessionFromRow(appliedRow, reserved.Candidate.SessionID)
	if err != nil || appliedAuthority != got.Session {
		t.Fatalf("applied close session = %#v, %v; want %#v", appliedAuthority, err, got.Session)
	}
	workItem := txn.TransactItems[4].Put.Item
	if _, ok := workItem["expected_target_count"].(*types.AttributeValueMemberN); !ok || workItem["ttl"] != nil {
		t.Fatalf("normal work item = %#v", workItem)
	}
	var workRow sessionControlCloseWorkRow
	if err := attributevalue.UnmarshalMap(workItem, &workRow); err != nil {
		t.Fatal(err)
	}
	work, err := sessionControlCloseWorkFromRow(workRow, false, reserved.Candidate.CellID, got.EventID)
	if err != nil || work != got.Work || work.CreatedAtMillis != got.Fence.CreatedAtMillis {
		t.Fatalf("normal work = %#v, %v", work, err)
	}
}

func TestDynamoSessionControlEnsureExactCloseOverflowFourItemWire(t *testing.T) {
	tests := []struct {
		name      string
		directory sessionControlFenceDirectory
		wantCount uint64
	}{
		{name: "hard active cap", directory: sessionControlCloseTestDirectory(sessionControlFenceSnapshot{
			CellID: "cell-01", DirectoryVersion: 8, ActiveFenceCount: sessionControlFenceActiveLimit,
		}, 1_800_000_000_000), wantCount: 1},
		{name: "already blocked", directory: sessionControlCloseTestDirectory(sessionControlFenceSnapshot{
			CellID: "cell-01", DirectoryVersion: 9, AdmissionBlocked: true, OverflowCloseCount: 3,
		}, 1_800_000_000_000), wantCount: 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake, store, reserved := newSessionControlExactCloseFixture(t, tt.directory)
			got, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, reserved.RetainUntilMillis)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Overflow || got.Fence != nil || got.Work.Mode != sessionControlCloseWorkModeOverflow {
				t.Fatalf("overflow close = %#v", got)
			}
			txn := fake.transactions[0]
			if len(txn.TransactItems) != 4 || len(aws.ToString(txn.ClientRequestToken)) > 36 ||
				txn.TransactItems[0].Update == nil || txn.TransactItems[1].Update == nil ||
				txn.TransactItems[2].Put == nil || txn.TransactItems[3].Put == nil {
				t.Fatalf("overflow transaction = %#v", txn)
			}
			values := txn.TransactItems[0].Update.ExpressionAttributeValues
			count, _ := values[":next_overflow_count"].(*types.AttributeValueMemberN)
			if count == nil || count.Value != fmt.Sprint(tt.wantCount) {
				t.Fatalf("next overflow count = %#v", count)
			}
			workItem := txn.TransactItems[2].Put.Item
			if _, ok := workItem["expected_target_count"].(*types.AttributeValueMemberN); !ok || workItem["ttl"] != nil {
				t.Fatalf("overflow work item = %#v", workItem)
			}
			orderItem := txn.TransactItems[3].Put.Item
			if _, ok := orderItem["work"].(*types.AttributeValueMemberM); !ok || orderItem["ttl"] != nil {
				t.Fatalf("overflow order item = %#v", orderItem)
			}
		})
	}
}

func TestDynamoSessionControlEnsureExactCloseLostResponseAndDuplicateCountOnce(t *testing.T) {
	directory := sessionControlCloseTestDirectory(sessionControlFenceSnapshot{
		CellID: "cell-01", DirectoryVersion: 11, AdmissionBlocked: true, OverflowCloseCount: 2,
	}, 1_800_000_000_000)
	fake, store, reserved := newSessionControlExactCloseFixture(t, directory)
	expected := expectedSessionControlExactClose(t, reserved, directory, store.nowUTC().UnixMilli(), reserved.RetainUntilMillis)
	fake.transactHook = func(ctx context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		<-ctx.Done()
		seedCommittedSessionControlExactClose(t, fake, directory, expected)
		return nil, ctx.Err()
	}
	got, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, reserved.RetainUntilMillis)
	if err != nil || *got != expected {
		t.Fatalf("ambiguous close = %#v, %v; want %#v", got, err, expected)
	}
	fake.transactHook = nil
	before := len(fake.transactions)
	again, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, reserved.RetainUntilMillis)
	if err != nil || *again != expected || len(fake.transactions) != before {
		t.Fatalf("duplicate close = %#v, %v, txns=%d/%d", again, err, len(fake.transactions), before)
	}
}

func TestDynamoSessionControlEnsureExactCloseFreshResultRecognizesOverflowPromotion(t *testing.T) {
	t.Run("initial close response lost after promotion", func(t *testing.T) {
		directory := sessionControlCloseTestDirectory(sessionControlFenceSnapshot{CellID: "cell-01",
			DirectoryVersion: 40, ActiveFenceCount: sessionControlFenceActiveLimit}, 1_800_000_000_000)
		fake, store, reserved := newSessionControlExactCloseFixture(t, directory)
		now := reserved.Candidate.IssuedAtMillis + 20_000
		store.nowUTC = func() time.Time { return time.UnixMilli(now).UTC() }
		transactionMillis := now
		if transactionMillis < directory.UpdatedAtMillis {
			transactionMillis = directory.UpdatedAtMillis
		}
		planned := expectedSessionControlExactClose(t, reserved, directory, transactionMillis,
			reserved.RetainUntilMillis)
		fake.transactHook = func(_ context.Context,
			_ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			seedPromotedSessionControlOverflowClose(t, fake, planned, directory, planned.Session.RetainUntilMillis)
			return nil, errors.New("lost close response")
		}
		got, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate,
			reserved.RetainUntilMillis)
		if err != nil || got.Complete == nil || got.Work != (sessionControlCloseWork{}) ||
			got.Complete.WorkMode != sessionControlCloseWorkModeOverflow {
			t.Fatalf("initial promoted result = %#v, %v", got, err)
		}
	})
	t.Run("retention response lost after promotion", func(t *testing.T) {
		directory := sessionControlCloseTestDirectory(sessionControlFenceSnapshot{CellID: "cell-01",
			DirectoryVersion: 41, ActiveFenceCount: sessionControlFenceActiveLimit}, 1_800_000_000_000)
		fake, store, reserved := newSessionControlExactCloseFixture(t, directory)
		now := reserved.Candidate.IssuedAtMillis + 20_000
		store.nowUTC = func() time.Time { return time.UnixMilli(now).UTC() }
		transactionMillis := now
		if transactionMillis < directory.UpdatedAtMillis {
			transactionMillis = directory.UpdatedAtMillis
		}
		committed := expectedSessionControlExactClose(t, reserved, directory, transactionMillis,
			reserved.RetainUntilMillis)
		seedCommittedSessionControlExactClose(t, fake, directory, committed)
		stronger := committed.Session.RetainUntilMillis + 10_000
		fake.transactHook = func(_ context.Context,
			_ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			seedPromotedSessionControlOverflowClose(t, fake, committed, directory, stronger)
			return nil, errors.New("lost retention response")
		}
		got, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, stronger)
		if err != nil || got.Complete == nil || got.Session.RetainUntilMillis < stronger {
			t.Fatalf("retention promoted result = %#v, %v", got, err)
		}
	})
}

func TestDynamoSessionControlEnsureExactCloseNormalLostResponse(t *testing.T) {
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(10), 1_800_000_000_000)
	fake, store, reserved := newSessionControlExactCloseFixture(t, directory)
	store.operationTimeout = 250 * time.Millisecond
	expected := expectedSessionControlExactClose(t, reserved, directory, store.nowUTC().UnixMilli(), reserved.RetainUntilMillis)
	fake.transactHook = func(ctx context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		<-ctx.Done()
		seedCommittedSessionControlExactClose(t, fake, directory, expected)
		return nil, ctx.Err()
	}
	got, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, reserved.RetainUntilMillis)
	if err != nil || got.EventID != expected.EventID || got.Session != expected.Session || got.Work != expected.Work ||
		got.Fence == nil || expected.Fence == nil || *got.Fence != *expected.Fence || got.Overflow != expected.Overflow {
		t.Fatalf("ambiguous normal close = %#v, %v; want %#v", got, err, expected)
	}
}

func TestDynamoSessionControlEnsureExactCloseAmbiguousCreationExtendsConcurrentLowerRetention(t *testing.T) {
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(10), 1_800_000_000_000)
	fake, store, reserved := newSessionControlExactCloseFixture(t, directory)
	lower := expectedSessionControlExactClose(t, reserved, directory, store.nowUTC().UnixMilli(), reserved.RetainUntilMillis)
	higher := lower.Session.RetainUntilMillis + 20_000
	calls := 0
	fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		calls++
		if calls == 1 {
			seedCommittedSessionControlExactClose(t, fake, directory, lower)
			return nil, context.DeadlineExceeded
		}
		extended := lower.Session
		extended.RetainUntilMillis = higher
		seedSessionControlReservation(t, fake, extended)
		return nil, context.DeadlineExceeded
	}
	got, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, higher)
	if err != nil || got.Session.RetainUntilMillis != higher || calls != 2 || len(fake.transactions) != 2 {
		t.Fatalf("higher-retain ambiguous creation = %#v, %v; calls=%d txns=%d", got, err, calls, len(fake.transactions))
	}
	if len(fake.transactions[1].TransactItems) != 2 {
		t.Fatalf("retention retry transaction = %#v", fake.transactions[1])
	}
}

func TestDynamoSessionControlEnsureExactCloseExtendsRetentionIdempotently(t *testing.T) {
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(4), 1_800_000_000_000)
	fake, store, reserved := newSessionControlExactCloseFixture(t, directory)
	committed := expectedSessionControlExactClose(t, reserved, directory, store.nowUTC().UnixMilli(), reserved.RetainUntilMillis)
	seedCommittedSessionControlExactClose(t, fake, directory, committed)
	higher := committed.Session.RetainUntilMillis + 10_000
	got, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, higher)
	if err != nil {
		t.Fatal(err)
	}
	if got.Session.RetainUntilMillis != higher || len(fake.transactions) != 1 || len(fake.transactions[0].TransactItems) != 2 {
		t.Fatalf("retention extension = %#v, txns=%#v", got, fake.transactions)
	}
	if len(aws.ToString(fake.transactions[0].ClientRequestToken)) > 36 {
		t.Fatalf("extension token too long: %q", aws.ToString(fake.transactions[0].ClientRequestToken))
	}
	// The fake does not apply writes; seed the committed extension and prove a
	// lower/equal replay performs no transaction and preserves the higher value.
	committed.Session.RetainUntilMillis = higher
	seedSessionControlReservation(t, fake, committed.Session)
	fake.transactions = nil
	for _, requested := range []int64{higher - 1, higher} {
		replayed, replayErr := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, requested)
		if replayErr != nil || replayed.Session.RetainUntilMillis != higher || len(fake.transactions) != 0 {
			t.Fatalf("retention replay(%d) = %#v, %v, txns=%d", requested, replayed, replayErr, len(fake.transactions))
		}
	}
}

func TestDynamoSessionControlEnsureExactCloseRetentionExtensionAmbiguousCommit(t *testing.T) {
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(4), 1_800_000_000_000)
	fake, store, reserved := newSessionControlExactCloseFixture(t, directory)
	store.operationTimeout = 250 * time.Millisecond
	committed := expectedSessionControlExactClose(t, reserved, directory, store.nowUTC().UnixMilli(), reserved.RetainUntilMillis)
	seedCommittedSessionControlExactClose(t, fake, directory, committed)
	higher := committed.Session.RetainUntilMillis + 20_000
	fake.transactHook = func(ctx context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		<-ctx.Done()
		committed.Session.RetainUntilMillis = higher
		seedSessionControlReservation(t, fake, committed.Session)
		return nil, ctx.Err()
	}
	got, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, higher)
	if err != nil || got.Session.RetainUntilMillis != higher {
		t.Fatalf("ambiguous retention extension = %#v, %v", got, err)
	}
}

func TestDynamoSessionControlExactCloseTokenBindsStateDependentSessionCAS(t *testing.T) {
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(6), 1_800_000_000_000)
	candidate := testSessionControlSessionCandidate(0x92, 902)
	reserved, err := planSessionControlReservation(candidate, testSessionControlSessionSnapshot(1))
	if err != nil {
		t.Fatal(err)
	}
	reserved.Version = 2
	reserved.TargetCount = 1
	reserved.SessionExpiresAtMillis = candidate.IssuedAtMillis + 120_000
	reserved.RetainUntilMillis = candidate.IssuedAtMillis + 150_000
	if err := validateSessionControlSessionAuthority(reserved); err != nil {
		t.Fatal(err)
	}
	acked := reserved
	acked.State = sessionControlSessionStateAckEnqueued
	acked.AckEnqueuedAtMillis = candidate.IssuedAtMillis + 1
	if err := validateSessionControlSessionAuthority(acked); err != nil {
		t.Fatal(err)
	}
	tokenFor := func(authority sessionControlSessionAuthority) string {
		fake := newSessionControlSessionDynamoFake()
		store := newSessionControlSessionDynamoStore(fake, time.Second)
		seedSessionControlReservation(t, fake, authority)
		seedSessionControlCloseDirectory(t, fake, directory)
		if _, err := store.EnsureExactSessionClose(context.Background(), candidate, authority.RetainUntilMillis); err != nil {
			t.Fatal(err)
		}
		return aws.ToString(fake.transactions[0].ClientRequestToken)
	}
	reservedToken := tokenFor(reserved)
	ackedToken := tokenFor(acked)
	if reservedToken == ackedToken || len(reservedToken) > 36 || len(ackedToken) > 36 {
		t.Fatalf("state-dependent tokens = %q / %q", reservedToken, ackedToken)
	}
}

func TestDynamoSessionControlExactCloseRetriesTenIntentCASWinnersAndAck(t *testing.T) {
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(3), 1_800_000_000_000)
	fake, store, current := newSessionControlExactCloseFixture(t, directory)
	current.SessionExpiresAtMillis = current.Candidate.IssuedAtMillis + 120_000
	current.RetainUntilMillis = current.Candidate.IssuedAtMillis + 150_000
	var calls int
	fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		calls++
		switch {
		case calls <= MaxACConnsPerID:
			current.Version++
			current.TargetCount++
			seedSessionControlReservation(t, fake, current)
			return nil, &types.TransactionCanceledException{}
		case calls == MaxACConnsPerID+1:
			current.State = sessionControlSessionStateAckEnqueued
			current.AckEnqueuedAtMillis = current.Candidate.IssuedAtMillis + 1
			seedSessionControlReservation(t, fake, current)
			return nil, &types.TransactionCanceledException{}
		default:
			return &dynamodb.TransactWriteItemsOutput{}, nil
		}
	}
	got, err := store.EnsureExactSessionClose(context.Background(), current.Candidate, current.RetainUntilMillis)
	if err != nil || got.Session.Version != uint64(MaxACConnsPerID+1) || got.Session.TargetCount != uint64(MaxACConnsPerID) ||
		got.Session.AckEnqueuedAtMillis == 0 || calls != sessionControlExactCloseAttempts {
		t.Fatalf("fanout+ACK close = %#v, %v; calls=%d", got, err, calls)
	}
}

func TestDynamoSessionControlExactCloseUsesOneAggregateDeadline(t *testing.T) {
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(3), 1_800_000_000_000)
	fake, store, reserved := newSessionControlExactCloseFixture(t, directory)
	store.operationTimeout = 12 * time.Millisecond
	fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		timer := time.NewTimer(3 * time.Millisecond)
		defer timer.Stop()
		<-timer.C
		return nil, &types.TransactionCanceledException{}
	}
	started := time.Now()
	_, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, reserved.RetainUntilMillis)
	elapsed := time.Since(started)
	if err == nil || len(fake.transactions) >= sessionControlExactCloseAttempts || elapsed > 100*time.Millisecond {
		t.Fatalf("aggregate close = %v; calls=%d elapsed=%v", err, len(fake.transactions), elapsed)
	}
}

func TestSessionControlCloseWorkRequiredFieldsAndTimestampBinding(t *testing.T) {
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(3), 1_800_000_000_000)
	fake, store, reserved := newSessionControlExactCloseFixture(t, directory)
	committed := expectedSessionControlExactClose(t, reserved, directory, store.nowUTC().UnixMilli(), reserved.RetainUntilMillis)
	seedCommittedSessionControlExactClose(t, fake, directory, committed)
	key := sessionControlSessionDynamoMapKey(sessionControlCloseWorkKey(committed.EventID))
	delete(fake.items[key], "expected_target_count")
	if _, err := store.getCloseWork(context.Background(), reserved.Candidate.CellID, committed.EventID, false); !errors.Is(err, errSessionControlCloseCorrupt) {
		t.Fatalf("missing expected_target_count error = %v", err)
	}
	seedSessionControlCloseWork(t, fake, committed.Work)
	mutated := committed.Work
	mutated.CreatedAtMillis++
	mutated.UpdatedAtMillis++
	mutated.DueAtMillis++
	seedSessionControlCloseWork(t, fake, mutated)
	stable, err := store.readStableExactCloseState(context.Background(), reserved.Candidate, committed.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := classifySessionControlExactClose(reserved.Candidate, committed.EventID, stable); !errors.Is(err, errSessionControlCloseCorrupt) {
		t.Fatalf("mutated timestamp classification = %v", err)
	}
}

func TestSessionControlDirectoryDecodeRequiresZeroCapableAuthorityFields(t *testing.T) {
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(1), 1_800_000_000_000)
	row, err := sessionControlFenceDirectoryToRow(directory)
	if err != nil {
		t.Fatal(err)
	}
	valid := marshalSessionControlSessionTestRow(t, row)
	tests := map[string]func(map[string]types.AttributeValue){
		"missing active count":   func(item map[string]types.AttributeValue) { delete(item, "active_fence_count") },
		"missing latch":          func(item map[string]types.AttributeValue) { delete(item, "admission_blocked") },
		"missing overflow count": func(item map[string]types.AttributeValue) { delete(item, "overflow_close_count") },
		"missing leader event":   func(item map[string]types.AttributeValue) { delete(item, "overflow_leader_event_id") },
		"missing leader prepared": func(item map[string]types.AttributeValue) {
			delete(item, "overflow_leader_prepared_directory_version")
		},
		"missing leader selected": func(item map[string]types.AttributeValue) {
			delete(item, "overflow_leader_selected_directory_version")
		},
		"wrong active count type": func(item map[string]types.AttributeValue) {
			item["active_fence_count"] = &types.AttributeValueMemberS{Value: "0"}
		},
		"wrong latch type": func(item map[string]types.AttributeValue) {
			item["admission_blocked"] = &types.AttributeValueMemberN{Value: "0"}
		},
		"wrong overflow count type": func(item map[string]types.AttributeValue) {
			item["overflow_close_count"] = &types.AttributeValueMemberS{Value: "0"}
		},
		"wrong leader event type": func(item map[string]types.AttributeValue) {
			item["overflow_leader_event_id"] = &types.AttributeValueMemberN{Value: "0"}
		},
		"wrong leader prepared type": func(item map[string]types.AttributeValue) {
			item["overflow_leader_prepared_directory_version"] = &types.AttributeValueMemberS{Value: "0"}
		},
		"wrong leader selected type": func(item map[string]types.AttributeValue) {
			item["overflow_leader_selected_directory_version"] = &types.AttributeValueMemberS{Value: "0"}
		},
		"TTL": func(item map[string]types.AttributeValue) { item["ttl"] = &types.AttributeValueMemberN{Value: "1"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			item := make(map[string]types.AttributeValue, len(valid)+1)
			for key, value := range valid {
				item[key] = value
			}
			mutate(item)
			if _, err := sessionControlFenceDirectoryFromItem(item, directory.CellID); !errors.Is(err, errSessionControlFenceCorrupt) {
				t.Fatalf("directory decode error = %v", err)
			}
			fake := newSessionControlSessionDynamoFake()
			fake.setItem(item)
			store := newSessionControlSessionDynamoStore(fake, time.Second)
			if _, err := store.readSessionDirectory(context.Background(), directory.CellID); !errors.Is(err, errSessionControlSessionCorrupt) {
				t.Fatalf("session directory decode error = %v", err)
			}
		})
	}
}

func TestSessionControlClosingRowRequiresPreparationTimestamp(t *testing.T) {
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(2), 1_800_000_000_000)
	fake, store, reserved := newSessionControlExactCloseFixture(t, directory)
	committed := expectedSessionControlExactClose(t, reserved, directory, store.nowUTC().UnixMilli(), reserved.RetainUntilMillis)
	row, err := sessionControlSessionToRow(committed.Session)
	if err != nil {
		t.Fatal(err)
	}
	item := marshalSessionControlSessionTestRow(t, row)
	delete(item, "close_prepared_at_ms")
	fake.setItem(item)
	if _, err := store.classifyReservation(context.Background(), reserved.Candidate); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("missing close preparation timestamp error = %v", err)
	}
}

func TestSessionControlNormalCloseClassificationRequiresCountedActiveFence(t *testing.T) {
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(2), 1_800_000_000_000)
	_, store, reserved := newSessionControlExactCloseFixture(t, directory)
	committed := expectedSessionControlExactClose(t, reserved, directory, store.nowUTC().UnixMilli(), reserved.RetainUntilMillis)
	stable := &sessionControlExactCloseStableState{
		Directory: directory, Session: &committed.Session, Meta: committed.Fence, Active: committed.Fence, Work: &committed.Work,
	}
	stable.Directory.Version++
	if _, err := classifySessionControlExactClose(reserved.Candidate, committed.EventID, stable); !errors.Is(err, errSessionControlCloseCorrupt) {
		t.Fatalf("zero-count normal close classification = %v", err)
	}
}

func TestDynamoSessionControlReserveNeverReopensClosingSessionAfterFenceRetirement(t *testing.T) {
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(4), 1_800_000_000_000)
	fake, store, reserved := newSessionControlExactCloseFixture(t, directory)
	committed := expectedSessionControlExactClose(t, reserved, directory, store.nowUTC().UnixMilli(), reserved.RetainUntilMillis)
	seedSessionControlReservation(t, fake, committed.Session)
	// Model the post-retirement directory: no active exact fence and admission
	// is open. The durable CLOSING state still forbids reservation replay.
	directory.Version = committed.Session.ClosePreparedDirectory + 2
	directory.ActiveFenceCount = 0
	seedSessionControlCloseDirectory(t, fake, directory)
	snapshot := sessionControlFenceSnapshot{CellID: directory.CellID, DirectoryVersion: directory.Version}
	if _, err := store.ReserveSession(context.Background(), reserved.Candidate, snapshot); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("post-retirement closing reserve error = %v", err)
	}
}

func TestDynamoSessionControlExactCloseConvergedReplayAndRetiredFailClosed(t *testing.T) {
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(5), 1_800_000_000_000)
	fake, store, reserved := newSessionControlExactCloseFixture(t, directory)
	committed := expectedSessionControlExactClose(t, reserved, directory, store.nowUTC().UnixMilli(), reserved.RetainUntilMillis)
	seedCommittedSessionControlExactClose(t, fake, directory, committed)
	converged := *committed.Fence
	converged.State = sessionControlFenceConverged
	converged.Version++
	converged.ConvergedAtMillis = converged.PreparedAtMillis + 1
	converged.ReplayNotBeforeMillis = converged.ConvergedAtMillis + sessionControlFenceReplayHorizon.Milliseconds()
	converged.UpdatedAtMillis = converged.ConvergedAtMillis
	seedSessionControlCloseFence(t, fake, converged)
	advanced := directory
	advanced.Version += 2
	advanced.ActiveFenceCount++
	advanced.UpdatedAtMillis = converged.UpdatedAtMillis
	seedSessionControlCloseDirectory(t, fake, advanced)
	got, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, committed.Session.RetainUntilMillis)
	if err != nil || got.Fence == nil || got.Fence.State != sessionControlFenceConverged {
		t.Fatalf("converged replay = %#v, %v", got, err)
	}
	delete(fake.items, sessionControlSessionDynamoMapKey(sessionControlFenceActiveKey(reserved.Candidate.CellID, committed.EventID)))
	if _, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, committed.Session.RetainUntilMillis); !errors.Is(err, errSessionControlCloseCorrupt) {
		t.Fatalf("retired/partial replay error = %v", err)
	}
}

func makeOverflowCloseWork(t *testing.T, cellID string, index int, preparedDirectoryVersion uint64) sessionControlCloseWork {
	t.Helper()
	candidate := testSessionControlSessionCandidate(byte(0xa0+index%16), uint64(index+1))
	candidate.CellID = cellID
	selector := sessionControlExactCloseSelector(candidate)
	digest, err := sessionControlFenceSelectorDigest(selector)
	if err != nil {
		t.Fatal(err)
	}
	created := int64(1_800_000_000_000 + index)
	return sessionControlCloseWork{
		CellID: cellID, EventID: fmt.Sprintf("%032x", index+1), Selector: selector, SelectorDigest: digest,
		Mode: sessionControlCloseWorkModeOverflow, State: sessionControlCloseWorkStatePending,
		PreparedDirectoryVersion: preparedDirectoryVersion, SessionVersion: 1, ExpectedTargetCount: 0,
		CreatedAtMillis: created, UpdatedAtMillis: created, DueAtMillis: created,
	}
}

func TestDynamoSessionControlSnapshotOverflowCloseWorkStrongWholePartitionAndPagination(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	const count = 101
	directory := sessionControlFenceDirectory{
		CellID: "cell-01", Version: 200, AdmissionBlocked: true, OverflowCloseCount: count,
		CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_500,
	}
	seedSessionControlCloseDirectory(t, fake, directory)
	for index := 0; index < count; index++ {
		seedSessionControlCloseWork(t, fake, makeOverflowCloseWork(t, directory.CellID, index, uint64(index+2)))
	}
	snapshot, err := store.SnapshotOverflowCloseWork(context.Background(), directory.CellID)
	if err != nil || len(snapshot.Work) != count || len(fake.queries) != 2 {
		t.Fatalf("overflow snapshot = %#v, %v; queries=%d", snapshot, err, len(fake.queries))
	}
	for _, query := range fake.queries {
		if !aws.ToBool(query.ConsistentRead) || aws.ToString(query.KeyConditionExpression) != "pk = :pk" {
			t.Fatalf("overflow query = %#v", query)
		}
	}
	junk := map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlOverflowClosePK(directory.CellID)},
		"sk": &types.AttributeValueMemberS{Value: "JUNK"},
	}
	fake.setItem(junk)
	if _, err := store.SnapshotOverflowCloseWork(context.Background(), directory.CellID); !errors.Is(err, errSessionControlCloseCorrupt) {
		t.Fatalf("junk partition row error = %v", err)
	}
}

func TestDynamoSessionControlSnapshotOverflowRetriesConcurrentCreateThenChecksParity(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	directory := sessionControlFenceDirectory{
		CellID: "cell-01", Version: 3, AdmissionBlocked: true, OverflowCloseCount: 1,
		CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_000,
	}
	first := makeOverflowCloseWork(t, directory.CellID, 0, 2)
	second := makeOverflowCloseWork(t, directory.CellID, 1, 4)
	seedSessionControlCloseDirectory(t, fake, directory)
	seedSessionControlCloseWork(t, fake, first)
	var once sync.Once
	fake.queryHook = func(context.Context, *dynamodb.QueryInput, int) (*dynamodb.QueryOutput, error) {
		once.Do(func() {
			seedSessionControlCloseWork(t, fake, second)
			directory.Version++
			directory.OverflowCloseCount++
			directory.UpdatedAtMillis++
			seedSessionControlCloseDirectory(t, fake, directory)
		})
		return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{
			marshalSessionControlSessionTestRow(t, mustSessionControlCloseRow(t, first)),
			marshalSessionControlSessionTestRow(t, mustSessionControlCloseRow(t, second)),
		}}, nil
	}
	snapshot, err := store.SnapshotOverflowCloseWork(context.Background(), directory.CellID)
	if err != nil || len(snapshot.Work) != 2 || len(fake.queries) < 2 {
		t.Fatalf("interleaved overflow snapshot = %#v, %v; queries=%d", snapshot, err, len(fake.queries))
	}
	directory.OverflowCloseCount++
	seedSessionControlCloseDirectory(t, fake, directory)
	if _, err := store.SnapshotOverflowCloseWork(context.Background(), directory.CellID); !errors.Is(err, errSessionControlCloseCorrupt) {
		t.Fatalf("physical/count mismatch error = %v", err)
	}
}

func TestDynamoSessionControlSnapshotOverflowRetriesConcurrentDelete(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	directory := sessionControlFenceDirectory{
		CellID: "cell-01", Version: 5, AdmissionBlocked: true, OverflowCloseCount: 2,
		CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_000,
	}
	first := makeOverflowCloseWork(t, directory.CellID, 0, 2)
	second := makeOverflowCloseWork(t, directory.CellID, 1, 4)
	seedSessionControlCloseDirectory(t, fake, directory)
	seedSessionControlCloseWork(t, fake, first)
	seedSessionControlCloseWork(t, fake, second)
	var once sync.Once
	fake.queryHook = func(context.Context, *dynamodb.QueryInput, int) (*dynamodb.QueryOutput, error) {
		once.Do(func() {
			fake.mu.Lock()
			delete(fake.items, sessionControlSessionDynamoMapKey(sessionControlOverflowCloseKey(directory.CellID, second.EventID)))
			fake.mu.Unlock()
			directory.Version++
			directory.OverflowCloseCount--
			directory.UpdatedAtMillis++
			seedSessionControlCloseDirectory(t, fake, directory)
		})
		return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{
			marshalSessionControlSessionTestRow(t, mustSessionControlCloseRow(t, first)),
		}}, nil
	}
	snapshot, err := store.SnapshotOverflowCloseWork(context.Background(), directory.CellID)
	if err != nil || len(snapshot.Work) != 1 || snapshot.Work[0] != first || len(fake.queries) < 2 {
		t.Fatalf("delete-interleaved overflow snapshot = %#v, %v; queries=%d", snapshot, err, len(fake.queries))
	}
}

func TestDynamoSessionControlSnapshotOverflowRejectsTTLAndMissingRequiredCount(t *testing.T) {
	for _, field := range []string{"ttl", "expected_target_count"} {
		t.Run(field, func(t *testing.T) {
			fake := newSessionControlSessionDynamoFake()
			store := newSessionControlSessionDynamoStore(fake, time.Second)
			directory := sessionControlFenceDirectory{
				CellID: "cell-01", Version: 3, AdmissionBlocked: true, OverflowCloseCount: 1,
				CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_000,
			}
			seedSessionControlCloseDirectory(t, fake, directory)
			row := mustSessionControlCloseRow(t, makeOverflowCloseWork(t, directory.CellID, 0, 2))
			item := marshalSessionControlSessionTestRow(t, row)
			if field == "ttl" {
				item["ttl"] = &types.AttributeValueMemberN{Value: "1"}
			} else {
				delete(item, field)
			}
			fake.setItem(item)
			if _, err := store.SnapshotOverflowCloseWork(context.Background(), directory.CellID); !errors.Is(err, errSessionControlCloseCorrupt) {
				t.Fatalf("%s row error = %v", field, err)
			}
		})
	}
}

func mustSessionControlCloseRow(t *testing.T, work sessionControlCloseWork) sessionControlCloseWorkRow {
	t.Helper()
	row, err := sessionControlCloseWorkToRow(work)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func TestDynamoSessionControlCloseCeilingsAndBehindClockClamp(t *testing.T) {
	t.Run("directory version ceiling", func(t *testing.T) {
		directory := sessionControlFenceDirectory{
			CellID: "cell-01", Version: math.MaxUint64 - 2,
			CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_000,
		}
		_, store, reserved := newSessionControlExactCloseFixture(t, directory)
		if _, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, reserved.RetainUntilMillis); !errors.Is(err, errSessionControlCloseCorrupt) {
			t.Fatalf("version ceiling error = %v", err)
		}
	})
	t.Run("overflow count ceiling", func(t *testing.T) {
		directory := sessionControlFenceDirectory{
			CellID: "cell-01", Version: 8, AdmissionBlocked: true, OverflowCloseCount: math.MaxUint64 - 2,
			CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_000,
		}
		_, store, reserved := newSessionControlExactCloseFixture(t, directory)
		if _, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, reserved.RetainUntilMillis); !errors.Is(err, errSessionControlCloseCorrupt) {
			t.Fatalf("overflow ceiling error = %v", err)
		}
	})
	t.Run("behind close clock clamps to issued", func(t *testing.T) {
		directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(2), 1_799_999_999_000)
		_, store, reserved := newSessionControlExactCloseFixture(t, directory)
		store.nowUTC = func() time.Time { return time.UnixMilli(reserved.Candidate.IssuedAtMillis - 1).UTC() }
		got, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, reserved.RetainUntilMillis)
		if err != nil || got.Session.ClosePreparedAtMillis != reserved.Candidate.IssuedAtMillis ||
			got.Session.RetainUntilMillis != reserved.Candidate.IssuedAtMillis+sessionControlFenceReplayHorizon.Milliseconds() {
			t.Fatalf("behind-clock close = %#v, %v", got, err)
		}
	})
}

func (s *memorySessionControlSessionModel) EnsureExactSessionClose(_ context.Context,
	candidate sessionControlSessionCandidate, retainUntilMillis int64) (*sessionControlExactClosePreparation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.sessions[candidate.SessionID]
	if !ok {
		return nil, errSessionControlSessionNotFound
	}
	if current.Candidate != candidate {
		return nil, errSessionControlSessionCollision
	}
	eventID := sessionControlExactCloseEventID(candidate)
	if current.State == sessionControlSessionStateClosing {
		preparation, ok := s.closePreparations[eventID]
		if !ok || preparation.Session != current {
			return nil, errSessionControlCloseCorrupt
		}
		minimum := current.ClosePreparedAtMillis + sessionControlFenceReplayHorizon.Milliseconds()
		if retainUntilMillis > minimum {
			minimum = retainUntilMillis
		}
		if current.RetainUntilMillis < minimum {
			current.RetainUntilMillis = minimum
			preparation.Session = current
			s.sessions[candidate.SessionID] = current
			s.closePreparations[eventID] = preparation
		}
		copy := preparation
		return &copy, nil
	}
	transactionMillis := s.nowMillis
	if transactionMillis < candidate.IssuedAtMillis {
		transactionMillis = candidate.IssuedAtMillis
	}
	minimum := transactionMillis + sessionControlFenceReplayHorizon.Milliseconds()
	if retainUntilMillis < minimum {
		retainUntilMillis = minimum
	}
	preparedVersion := s.snapshot.DirectoryVersion + 1
	planned, err := planSessionControlExactClose(current, eventID, preparedVersion, transactionMillis, retainUntilMillis)
	if err != nil {
		return nil, err
	}
	directory := memorySessionControlFenceDirectory(s.snapshot)
	preparation := expectedSessionControlExactCloseForMemory(current, directory, transactionMillis, retainUntilMillis)
	preparation.Session = planned
	s.snapshot.DirectoryVersion++
	if preparation.Overflow {
		s.snapshot.AdmissionBlocked = true
		s.snapshot.OverflowCloseCount++
	} else {
		s.snapshot.ActiveFenceCount++
		s.snapshot.Fences = append(s.snapshot.Fences, *preparation.Fence)
	}
	s.sessions[candidate.SessionID] = planned
	s.closePreparations[eventID] = preparation
	copy := preparation
	return &copy, nil
}

func expectedSessionControlExactCloseForMemory(current sessionControlSessionAuthority, directory sessionControlFenceDirectory,
	transactionMillis, retainUntilMillis int64) sessionControlExactClosePreparation {
	eventID := sessionControlExactCloseEventID(current.Candidate)
	selector := sessionControlExactCloseSelector(current.Candidate)
	digest, _ := sessionControlFenceSelectorDigest(selector)
	work := sessionControlCloseWork{
		CellID: current.Candidate.CellID, EventID: eventID, Selector: selector, SelectorDigest: digest,
		Mode: sessionControlCloseWorkModeNormal, State: sessionControlCloseWorkStatePending,
		PreparedDirectoryVersion: directory.Version + 1, SessionVersion: current.Version,
		ExpectedTargetCount: current.TargetCount, CreatedAtMillis: transactionMillis,
		UpdatedAtMillis: transactionMillis, DueAtMillis: transactionMillis,
	}
	preparation := sessionControlExactClosePreparation{EventID: eventID, Work: work}
	if directory.AdmissionBlocked || directory.ActiveFenceCount >= sessionControlFenceActiveLimit {
		preparation.Overflow = true
		preparation.Work.Mode = sessionControlCloseWorkModeOverflow
		return preparation
	}
	fence := sessionControlFenceAuthority{
		CellID: current.Candidate.CellID, EventID: eventID, Selector: selector, SelectorDigest: digest,
		PreparedDirectoryVersion: directory.Version + 1, State: sessionControlFencePreparing, Version: 1,
		CreatedAtMillis: transactionMillis, PreparedAtMillis: transactionMillis, UpdatedAtMillis: transactionMillis,
	}
	preparation.Fence = &fence
	return preparation
}

func TestMemorySessionControlExactCloseDuplicateAndAdmissionOrdering(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	store := newMemorySessionControlSessionModel(snapshot)
	candidate := testSessionControlSessionCandidate(0xb1, 1001)
	if _, err := store.ReserveSession(context.Background(), candidate, snapshot); err != nil {
		t.Fatal(err)
	}
	const workers = 24
	var wait sync.WaitGroup
	results := make(chan *sessionControlExactClosePreparation, workers)
	errs := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			got, err := store.EnsureExactSessionClose(context.Background(), candidate, candidate.ReservationDeadlineMillis)
			results <- got
			errs <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first *sessionControlExactClosePreparation
	for got := range results {
		if first == nil {
			first = got
		} else if *got != *first {
			t.Fatalf("duplicate close mismatch = %#v / %#v", got, first)
		}
	}
	if store.snapshot.DirectoryVersion != 2 || store.snapshot.ActiveFenceCount != 1 || len(store.closePreparations) != 1 {
		t.Fatalf("duplicate directory/preparations = %#v/%d", store.snapshot, len(store.closePreparations))
	}
	blocked := store.snapshot
	blocked.AdmissionBlocked = true
	blocked.OverflowCloseCount = 1
	store.setSnapshot(blocked)
	sibling := testSessionControlSessionCandidate(0xb2, 1002)
	if _, err := store.ReserveSession(context.Background(), sibling, blocked); !errors.Is(err, errSessionControlAdmissionBlocked) {
		t.Fatalf("blocked sibling reservation error = %v", err)
	}
	if _, err := store.EnsureExactSessionClose(context.Background(), candidate, first.Session.RetainUntilMillis); err != nil {
		t.Fatalf("exact close replay under latch = %v", err)
	}
}

func newMemorySessionControlAdmittedSession(t *testing.T, seed byte, sessionID uint64) (*memorySessionControlSessionModel,
	sessionControlSessionCandidate, sessionControlFenceSnapshot) {
	t.Helper()
	snapshot := testSessionControlSessionSnapshot(1)
	store := newMemorySessionControlSessionModel(snapshot)
	candidate := testSessionControlSessionCandidate(seed, sessionID)
	reserved, err := store.ReserveSession(context.Background(), candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	target := testSessionControlSessionTarget(seed + 1)
	store.setTarget(target)
	if _, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
		candidate.IssuedAtMillis+120_000, candidate.IssuedAtMillis+150_000, snapshot); err != nil {
		t.Fatal(err)
	}
	return store, candidate, snapshot
}

func TestMemorySessionControlExactCloseOrdersAgainstAckAndIntent(t *testing.T) {
	t.Run("ACK then close", func(t *testing.T) {
		store, candidate, snapshot := newMemorySessionControlAdmittedSession(t, 0xc1, 1101)
		acked, err := store.MarkSessionAckEnqueued(context.Background(), candidate, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		closed, err := store.EnsureExactSessionClose(context.Background(), candidate, acked.RetainUntilMillis)
		if err != nil || closed.Session.State != sessionControlSessionStateClosing ||
			closed.Session.AckEnqueuedAtMillis != acked.AckEnqueuedAtMillis {
			t.Fatalf("ACK-then-close = %#v, %v", closed, err)
		}
	})
	t.Run("close then ACK", func(t *testing.T) {
		store, candidate, snapshot := newMemorySessionControlAdmittedSession(t, 0xc3, 1102)
		if _, err := store.EnsureExactSessionClose(context.Background(), candidate, candidate.ReservationDeadlineMillis); err != nil {
			t.Fatal(err)
		}
		if _, err := store.MarkSessionAckEnqueued(context.Background(), candidate, snapshot); err == nil {
			t.Fatal("close-first ACK unexpectedly succeeded")
		}
	})
	t.Run("intent then close preserves intent authority", func(t *testing.T) {
		store, candidate, _ := newMemorySessionControlAdmittedSession(t, 0xc5, 1103)
		before := store.sessions[candidate.SessionID]
		closed, err := store.EnsureExactSessionClose(context.Background(), candidate, before.RetainUntilMillis)
		if err != nil || closed.Session.Version != before.Version || closed.Session.TargetCount != before.TargetCount ||
			len(store.intents) != 1 || len(store.reverse) != 1 {
			t.Fatalf("intent-then-close = %#v, %v; pairs=%d/%d", closed, err, len(store.intents), len(store.reverse))
		}
	})
	t.Run("close then intent", func(t *testing.T) {
		snapshot := testSessionControlSessionSnapshot(1)
		store := newMemorySessionControlSessionModel(snapshot)
		candidate := testSessionControlSessionCandidate(0xc7, 1104)
		if _, err := store.ReserveSession(context.Background(), candidate, snapshot); err != nil {
			t.Fatal(err)
		}
		target := testSessionControlSessionTarget(0xc8)
		store.setTarget(target)
		if _, err := store.EnsureExactSessionClose(context.Background(), candidate, candidate.ReservationDeadlineMillis); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, target,
			candidate.IssuedAtMillis+120_000, candidate.IssuedAtMillis+150_000, snapshot); err == nil {
			t.Fatal("close-first intent unexpectedly succeeded")
		}
	})
}

func TestMemorySessionControlAdmissionOperationsRejectOverflowLatchIncludingReplays(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	store := newMemorySessionControlSessionModel(snapshot)
	candidate := testSessionControlSessionCandidate(0xd1, 1201)
	reserved, err := store.ReserveSession(context.Background(), candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	target := testSessionControlSessionTarget(0xd2)
	store.setTarget(target)
	prepared, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
		candidate.IssuedAtMillis+120_000, candidate.IssuedAtMillis+150_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	blocked := snapshot
	blocked.AdmissionBlocked = true
	blocked.OverflowCloseCount = 1
	store.setSnapshot(blocked)
	operations := map[string]func() error{
		"reserve replay": func() error { _, err := store.ReserveSession(context.Background(), candidate, blocked); return err },
		"verify":         func() error { _, err := store.VerifySession(context.Background(), candidate, blocked); return err },
		"intent replay": func() error {
			_, err := store.PrepareSessionIntent(context.Background(), prepared.Session.fence(), target,
				candidate.IssuedAtMillis+120_000, candidate.IssuedAtMillis+150_000, blocked)
			return err
		},
		"current intent": func() error {
			_, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, target,
				candidate.IssuedAtMillis+120_000, candidate.IssuedAtMillis+150_000, blocked)
			return err
		},
		"ACK": func() error {
			_, err := store.MarkSessionAckEnqueued(context.Background(), candidate, blocked)
			return err
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			if err := operation(); !errors.Is(err, errSessionControlAdmissionBlocked) {
				t.Fatalf("operation error = %v", err)
			}
		})
	}
}

func TestMemorySessionControlTargetActivationRejectsOverflowLatchForCountedUncountedAndReplay(t *testing.T) {
	for _, counted := range []bool{false, true} {
		t.Run(fmt.Sprintf("counted=%v", counted), func(t *testing.T) {
			store := newMemorySessionControlStore(time.UnixMilli(1_800_000_000_000))
			candidate := testSessionControlTargetCandidate(byte(0xe1), "00112233445566778899aabbccddeeff", 7)
			preparing := testSessionControlTargetAuthority(candidate, sessionControlTargetPreparing, 3)
			preparing.CountedActiveSlot = counted
			if counted {
				preparing.AuthorityVersion = 2
			}
			store.targets[preparing.key()] = preparing
			store.authorities[preparing.ACID] = sessionControlAuthority{
				ACID: preparing.ACID, Version: preparing.AuthorityVersion, ActiveTargetCount: 1,
				ControlCellID: "cell-01", CreatedAtMillis: preparing.CreatedAtMillis, UpdatedAtMillis: preparing.UpdatedAtMillis,
			}
			store.controlDirectories["cell-01"] = sessionControlFenceDirectory{
				CellID: "cell-01", Version: 1, AdmissionBlocked: true, OverflowCloseCount: 1,
				CreatedAtMillis: preparing.CreatedAtMillis, UpdatedAtMillis: preparing.UpdatedAtMillis,
			}
			if _, err := store.ActivateTarget(context.Background(), preparing.fence().activation(1)); !errors.Is(err, errSessionControlAdmissionBlocked) {
				t.Fatalf("activation error = %v", err)
			}
			active := preparing
			active.State = sessionControlTargetActive
			active.Version++
			if !counted {
				active.AuthorityVersion++
			}
			active.CountedActiveSlot = true
			active.ActivatedControlVersion = 1
			store.targets[active.key()] = active
			if _, err := store.ActivateTarget(context.Background(), preparing.fence().activation(1)); !errors.Is(err, errSessionControlAdmissionBlocked) {
				t.Fatalf("activation replay error = %v", err)
			}
		})
	}
}

func TestMemorySessionControlFenceSafetyTransitionsPreserveOverflowLatch(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000)
	store := newMemorySessionControlFenceStore(now)
	store.directories["cell-01"] = sessionControlFenceDirectory{
		CellID: "cell-01", Version: 5, AdmissionBlocked: true, OverflowCloseCount: 2,
		CreatedAtMillis: now.UnixMilli(), UpdatedAtMillis: now.UnixMilli(),
	}
	candidate := testSessionControlFenceCandidate("f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1", sessionControlFenceSelector{
		Scope: sessionControlFenceSelectorAgent, AgentPublicKey: testACSessionControlPublicKey(0xf1),
		IssuedThroughMillis: now.UnixMilli(),
	})
	prepared, err := store.PrepareFence(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	assertLatch := func(stage string) {
		t.Helper()
		directory := store.directories[candidate.CellID]
		if !directory.AdmissionBlocked || directory.OverflowCloseCount != 2 {
			t.Fatalf("%s directory = %#v", stage, directory)
		}
	}
	assertLatch("prepare")
	store.setNow(now.Add(time.Second))
	converged, err := store.MarkFenceConverged(context.Background(), *prepared)
	if err != nil {
		t.Fatal(err)
	}
	assertLatch("converge")
	store.setNow(time.UnixMilli(converged.ReplayNotBeforeMillis))
	if _, err := store.retireFence(context.Background(), *converged); err != nil {
		t.Fatal(err)
	}
	assertLatch("retire")
}
