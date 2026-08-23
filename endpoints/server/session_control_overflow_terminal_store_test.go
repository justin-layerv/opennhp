package server

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type sessionControlOverflowTerminalFixture struct {
	sessionControlOverflowCompletionFixture
	complete          sessionControlCloseComplete
	directory         sessionControlFenceDirectory
	fence             sessionControlFenceAuthority
	cleanChunks       []sessionControlCloseCleanChunk
	cleanTransactions []*dynamodb.TransactWriteItemsInput
}

func newSessionControlOverflowTerminalFixture(t *testing.T, count int) sessionControlOverflowTerminalFixture {
	t.Helper()
	fixture := sessionControlOverflowTerminalFixture{sessionControlOverflowCompletionFixture: newSessionControlOverflowCompletionFixture(t, count)}
	makeOverflowPromotionEligible(t, &fixture.sessionControlOverflowCompletionFixture,
		sessionControlFenceActiveLimit-1)
	complete, err := fixture.store.PromoteCompletedOverflowExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	fixture.complete = *complete
	installSessionControlTerminalTransactionFake(fixture.fake)
	for manifestIndex := range fixture.taskSet.ManifestDigests {
		manifest, readErr := fixture.store.getCloseManifest(context.Background(), fixture.close.EventID,
			uint64(manifestIndex))
		if readErr != nil {
			t.Fatal(readErr)
		}
		for refIndex, ref := range manifest.Refs {
			_, cleanupErr := fixture.store.CleanupAckedExactCloseTask(context.Background(),
				sessionControlCloseTaskCleanupRequest{CellID: fixture.candidate.CellID,
					EventID: fixture.close.EventID, OwnerPK: ref.OwnerPK,
					OperationID: sessionControlTaskTestID(uint64(0xfb00 + manifestIndex*48 + refIndex))})
			if cleanupErr != nil {
				t.Fatalf("overflow cleanup manifest %d ref %d: %v", manifestIndex, refIndex, cleanupErr)
			}
		}
		chunk, chunkErr := fixture.store.PrepareExactCloseCleanChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, uint64(manifestIndex))
		if chunkErr != nil {
			t.Fatalf("overflow CLEANCHUNK %d: %v", manifestIndex, chunkErr)
		}
		fixture.cleanChunks = append(fixture.cleanChunks, *chunk)
		fixture.cleanTransactions = append(fixture.cleanTransactions,
			fixture.fake.transactions[len(fixture.fake.transactions)-1])
	}
	directory, err := fixture.store.getFenceDirectory(context.Background(), fixture.candidate.CellID)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := fixture.store.getFence(context.Background(), fixture.candidate.CellID, fixture.close.EventID, false)
	if err != nil {
		t.Fatal(err)
	}
	fixture.directory, fixture.fence = *directory, *fence
	fixture.store.nowUTC = func() time.Time { return time.UnixMilli(fence.ReplayNotBeforeMillis).UTC() }
	return fixture
}

func TestDynamoSessionControlOverflowTerminalArithmeticReplayAndModeIsolation(t *testing.T) {
	for _, count := range []int{0, 47, 48, int(sessionControlSessionMaxTargets)} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			fixture := newSessionControlOverflowTerminalFixture(t, count)
			for index, chunk := range fixture.cleanChunks {
				txn := fixture.cleanTransactions[index]
				if got, want := len(txn.TransactItems), 3+2*int(chunk.OwnerCount); got != want || got > 97 ||
					len(aws.ToString(txn.ClientRequestToken)) > 36 {
					t.Fatalf("overflow CLEANCHUNK %d transaction = %d, want %d", index, got, want)
				}
				if chunk.Complete.WorkMode != sessionControlCloseWorkModeOverflow ||
					chunk.TaskSet.WorkMode != sessionControlCloseWorkModeOverflow ||
					chunk.Manifest.WorkMode != sessionControlCloseWorkModeOverflow ||
					chunk.AckChunk.WorkMode != sessionControlCloseWorkModeOverflow {
					t.Fatalf("overflow CLEANCHUNK mode = %#v", chunk)
				}
				assertSessionControlTerminalUniqueTransactionKeys(t, txn.TransactItems)
			}
			if len(fixture.cleanChunks) > 0 {
				if _, err := fixture.store.PrepareNormalExactCloseCleanChunk(context.Background(), fixture.candidate,
					fixture.close.EventID, 0); !errors.Is(err, errSessionControlTerminalCorrupt) {
					t.Fatalf("normal CLEANCHUNK wrapper accepted overflow = %v", err)
				}
			}
			if _, err := fixture.store.FinalizeTerminalNormalExactClose(context.Background(), fixture.candidate,
				fixture.close.EventID); !errors.Is(err, errSessionControlTerminalConflict) {
				t.Fatalf("normal terminal wrapper accepted overflow = %v", err)
			}
			before := len(fixture.fake.transactions)
			closed, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
				fixture.close.EventID)
			if err != nil {
				t.Fatal(err)
			}
			txn := fixture.fake.transactions[before]
			if got, want := len(txn.TransactItems), 7+len(fixture.cleanChunks); got != want || got > 29 ||
				len(aws.ToString(txn.ClientRequestToken)) > 36 {
				t.Fatalf("overflow terminal transaction = %d/%q, want %d", got,
					aws.ToString(txn.ClientRequestToken), want)
			}
			if closed.WorkBefore != nil || closed.Complete.WorkMode != sessionControlCloseWorkModeOverflow ||
				closed.DirectoryAfter.ActiveFenceCount+1 != closed.DirectoryBefore.ActiveFenceCount ||
				closed.SessionAfter.State != sessionControlSessionStateClosed ||
				closed.FenceAfter.State != sessionControlFenceRetired {
				t.Fatalf("overflow CLOSED = %#v", closed)
			}
			for _, member := range txn.TransactItems {
				if member.Delete != nil && sessionControlSessionDynamoMapKey(member.Delete.Key) ==
					sessionControlSessionDynamoMapKey(sessionControlCloseWorkKey(fixture.close.EventID)) {
					t.Fatal("overflow terminal deleted synthetic common WORK")
				}
			}
			closedItem := txn.TransactItems[4].Put.Item
			if _, present := closedItem["work_before"]; present || closedItem["ttl"] != nil {
				t.Fatalf("overflow CLOSED physical shape = %#v", closedItem)
			}
			assertSessionControlTerminalUniqueTransactionKeys(t, txn.TransactItems)
			transactions := len(fixture.fake.transactions)
			replayed, replayErr := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
				fixture.close.EventID)
			if replayErr != nil || replayed.ClosedDigest != closed.ClosedDigest ||
				len(fixture.fake.transactions) != transactions {
				t.Fatalf("overflow terminal replay = %#v, %v", replayed, replayErr)
			}
		})
	}
}

func TestDynamoSessionControlOverflowTerminalPreservesLatchAndLeader(t *testing.T) {
	fixture := newSessionControlOverflowTerminalFixture(t, 0)
	directory := fixture.directory
	directory.Version++
	directory.AdmissionBlocked = true
	directory.OverflowCloseCount = 1
	directory.OverflowLeaderEventID = sessionControlTaskTestID(0xfc01)
	directory.OverflowLeaderPreparedDirectoryVersion = directory.Version - 1
	directory.OverflowLeaderSelectedDirectoryVersion = directory.Version
	directory.UpdatedAtMillis++
	seedSessionControlCloseDirectory(t, fixture.fake, directory)
	fixture.store.nowUTC = func() time.Time {
		return time.UnixMilli(max(fixture.fence.ReplayNotBeforeMillis, directory.UpdatedAtMillis)).UTC()
	}
	closed, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if closed.DirectoryAfter.AdmissionBlocked != directory.AdmissionBlocked ||
		closed.DirectoryAfter.OverflowCloseCount != directory.OverflowCloseCount ||
		closed.DirectoryAfter.OverflowLeaderEventID != directory.OverflowLeaderEventID ||
		closed.DirectoryAfter.OverflowLeaderPreparedDirectoryVersion != directory.OverflowLeaderPreparedDirectoryVersion ||
		closed.DirectoryAfter.OverflowLeaderSelectedDirectoryVersion != directory.OverflowLeaderSelectedDirectoryVersion {
		t.Fatalf("overflow terminal changed latch/leader: before=%#v after=%#v", directory, closed.DirectoryAfter)
	}
}

func TestDynamoSessionControlOverflowTerminalFreesSlotForNextLeaderPromotion(t *testing.T) {
	first := newSessionControlOverflowCompletionFixture(t, 0)
	directory := first.leader.Directory
	directory.ActiveFenceCount = sessionControlFenceActiveLimit - 1

	candidate := testSessionControlSessionCandidate(0xee, 9_901)
	candidate.CellID = first.candidate.CellID
	reserved, err := planSessionControlReservation(candidate, sessionControlFenceSnapshot{
		CellID: candidate.CellID, DirectoryVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	nextBase := directory
	nextBase.Version = first.close.Work.PreparedDirectoryVersion + 1
	nextClose := expectedSessionControlExactClose(t, reserved, nextBase,
		first.close.Work.CreatedAtMillis+1, reserved.RetainUntilMillis)
	if !nextClose.Overflow || nextClose.Work.PreparedDirectoryVersion <= first.close.Work.PreparedDirectoryVersion {
		t.Fatalf("next overflow close = %#v", nextClose)
	}
	seedSessionControlReservation(t, first.fake, nextClose.Session)
	seedSessionControlCloseWork(t, first.fake, nextClose.Work)
	nextTaskSet, err := sessionControlCloseBuildTaskSet(&nextClose, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	nextTaskSetRow, err := sessionControlCloseTaskSetToRow(nextTaskSet)
	if err != nil {
		t.Fatal(err)
	}
	first.fake.setItem(marshalSessionControlSessionTestRow(t, nextTaskSetRow))
	directory.Version = nextClose.Work.PreparedDirectoryVersion
	directory.OverflowCloseCount = 2
	directory.UpdatedAtMillis = nextClose.Work.CreatedAtMillis
	seedSessionControlCloseDirectory(t, first.fake, directory)
	installSessionControlOverflowPromotionTransactionFake(first.fake)
	firstComplete, err := first.store.PromoteCompletedOverflowExactClose(context.Background(), first.candidate,
		first.close.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	between, err := first.store.getFenceDirectory(context.Background(), first.candidate.CellID)
	if err != nil || !between.AdmissionBlocked || between.ActiveFenceCount != sessionControlFenceActiveLimit ||
		between.OverflowCloseCount != 1 || between.OverflowLeaderEventID != nextClose.EventID {
		t.Fatalf("first promotion did not install next leader = %#v, %v", between, err)
	}
	fence, err := first.store.getFence(context.Background(), first.candidate.CellID, first.close.EventID, false)
	if err != nil {
		t.Fatal(err)
	}
	first.store.nowUTC = func() time.Time { return time.UnixMilli(fence.ReplayNotBeforeMillis).UTC() }
	installSessionControlTerminalTransactionFake(first.fake)
	closed, err := first.store.FinalizeTerminalExactClose(context.Background(), first.candidate, first.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if closed.Complete.CompleteDigest != firstComplete.CompleteDigest ||
		closed.DirectoryAfter.ActiveFenceCount != sessionControlFenceActiveLimit-1 ||
		closed.DirectoryAfter.OverflowLeaderEventID != nextClose.EventID {
		t.Fatalf("terminal did not free slot/preserve leader = %#v", closed)
	}
	installSessionControlOverflowPromotionTransactionFake(first.fake)
	nextComplete, err := first.store.PromoteCompletedOverflowExactClose(context.Background(), candidate,
		nextClose.EventID, 0)
	if err != nil || nextComplete.WorkMode != sessionControlCloseWorkModeOverflow {
		t.Fatalf("next leader promotion = %#v, %v", nextComplete, err)
	}
	finalDirectory, err := first.store.getFenceDirectory(context.Background(), candidate.CellID)
	if err != nil || finalDirectory.ActiveFenceCount != sessionControlFenceActiveLimit ||
		finalDirectory.AdmissionBlocked || finalDirectory.OverflowCloseCount != 0 {
		t.Fatalf("directory after next promotion = %#v, %v", finalDirectory, err)
	}
}

func TestDynamoSessionControlOverflowTerminalHorizonAndLostResponse(t *testing.T) {
	t.Run("horizon", func(t *testing.T) {
		fixture := newSessionControlOverflowTerminalFixture(t, 0)
		fixture.store.nowUTC = func() time.Time {
			return time.UnixMilli(fixture.fence.ReplayNotBeforeMillis - 1).UTC()
		}
		if _, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID); !errors.Is(err, errSessionControlFenceReplayHorizon) {
			t.Fatalf("overflow horizon -1 = %v", err)
		}
		fixture.store.nowUTC = func() time.Time {
			return time.UnixMilli(fixture.fence.ReplayNotBeforeMillis).UTC()
		}
		if _, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID); err != nil {
			t.Fatalf("overflow exact horizon = %v", err)
		}
	})
	t.Run("lost_response", func(t *testing.T) {
		fixture := newSessionControlOverflowTerminalFixture(t, 0)
		fixture.fake.transactHook = func(_ context.Context,
			input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			applySessionControlTerminalTransaction(fixture.fake, input)
			return nil, errors.New("lost overflow terminal response")
		}
		closed, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID)
		if err != nil || closed.Complete.WorkMode != sessionControlCloseWorkModeOverflow {
			t.Fatalf("lost overflow terminal response = %#v, %v", closed, err)
		}
	})
}

func TestSessionControlClosedStrictModeUnion(t *testing.T) {
	normal := newSessionControlTerminalFixture(t, 0)
	normalClosed, err := normal.store.FinalizeTerminalExactClose(context.Background(), normal.candidate,
		normal.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	normalRow, err := sessionControlCloseClosedToRow(*normalClosed)
	if err != nil {
		t.Fatal(err)
	}
	normalItem := marshalSessionControlSessionTestRow(t, normalRow)
	delete(normalItem, "work_before")
	if _, err = sessionControlCloseClosedFromItem(normalItem, normalClosed.EventID); !errors.Is(err, errSessionControlTerminalCorrupt) {
		t.Fatalf("normal CLOSED without work_before = %v", err)
	}

	overflow := newSessionControlOverflowTerminalFixture(t, 0)
	overflowClosed, err := overflow.store.FinalizeTerminalExactClose(context.Background(), overflow.candidate,
		overflow.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	overflowRow, err := sessionControlCloseClosedToRow(*overflowClosed)
	if err != nil {
		t.Fatal(err)
	}
	base := marshalSessionControlSessionTestRow(t, overflowRow)
	for _, value := range []types.AttributeValue{
		&types.AttributeValueMemberNULL{Value: true},
		&types.AttributeValueMemberM{Value: map[string]types.AttributeValue{}},
	} {
		item := make(map[string]types.AttributeValue, len(base)+1)
		for name, attribute := range base {
			item[name] = attribute
		}
		item["work_before"] = value
		if _, err = sessionControlCloseClosedFromItem(item, overflowClosed.EventID); !errors.Is(err, errSessionControlTerminalCorrupt) {
			t.Fatalf("overflow CLOSED with work_before %T = %v", value, err)
		}
	}
}

func TestDynamoSessionControlOverflowTerminalRejectsUnexpectedWorkAndHalfState(t *testing.T) {
	t.Run("unexpected_work", func(t *testing.T) {
		fixture := newSessionControlOverflowTerminalFixture(t, 0)
		work := fixture.close.Work
		work.Mode = sessionControlCloseWorkModeNormal
		work.State = sessionControlCloseWorkStateCompleted
		work.DueAtMillis = 0
		work.CompletedAtMillis = fixture.complete.CompletedAtMillis
		work.UpdatedAtMillis = fixture.complete.CompletedAtMillis
		seedSessionControlCloseWork(t, fixture.fake, work)
		if _, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID); !errors.Is(err, errSessionControlTerminalConflict) {
			t.Fatalf("overflow terminal with synthetic WORK = %v", err)
		}
	})
	t.Run("generic_retire_without_closed", func(t *testing.T) {
		fixture := newSessionControlOverflowTerminalFixture(t, 0)
		closed, err := planSessionControlTerminalExactClose(fixture.directory, fixture.fence,
			fixture.close.Session, nil, fixture.complete, fixture.taskSet, fixture.cleanChunks,
			fixture.fence.ReplayNotBeforeMillis)
		if err != nil {
			t.Fatal(err)
		}
		seedSessionControlCloseDirectory(t, fixture.fake, closed.DirectoryAfter)
		row, err := sessionControlFenceToRow(closed.FenceAfter, false)
		if err != nil {
			t.Fatal(err)
		}
		fixture.fake.setItem(marshalSessionControlSessionTestRow(t, row))
		fixture.fake.mu.Lock()
		delete(fixture.fake.items, sessionControlSessionDynamoMapKey(
			sessionControlFenceActiveKey(fixture.candidate.CellID, fixture.close.EventID)))
		fixture.fake.mu.Unlock()
		if _, err = fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID); err == nil {
			t.Fatal("generic overflow retire accepted without CLOSED")
		}
	})
	t.Run("marker_without_transition", func(t *testing.T) {
		fixture := newSessionControlOverflowTerminalFixture(t, 0)
		closed, err := planSessionControlTerminalExactClose(fixture.directory, fixture.fence,
			fixture.close.Session, nil, fixture.complete, fixture.taskSet, fixture.cleanChunks,
			fixture.fence.ReplayNotBeforeMillis)
		if err != nil {
			t.Fatal(err)
		}
		row, err := sessionControlCloseClosedToRow(closed)
		if err != nil {
			t.Fatal(err)
		}
		fixture.fake.setItem(marshalSessionControlSessionTestRow(t, row))
		if _, err = fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID); err == nil {
			t.Fatal("orphan overflow CLOSED marker accepted")
		}
	})
}

func TestDynamoSessionControlOverflowCleanChunkCompatibleReplay(t *testing.T) {
	fixture := newSessionControlOverflowTerminalFixture(t, 47)
	stored := fixture.cleanChunks[0]
	fixture.fake.transactHook = func(context.Context,
		*dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		return nil, &types.TransactionCanceledException{}
	}
	replayed, err := fixture.store.PrepareExactCloseCleanChunk(context.Background(), fixture.candidate,
		fixture.close.EventID, 0)
	if err != nil || replayed.ChunkDigest != stored.ChunkDigest || replayed.OwnerCount != 47 {
		t.Fatalf("overflow CLEANCHUNK replay = %#v, %v", replayed, err)
	}
}
