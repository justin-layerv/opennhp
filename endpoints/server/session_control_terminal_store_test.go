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
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type sessionControlTerminalFixture struct {
	sessionControlCleanupFixture
	cleanChunks       []sessionControlCloseCleanChunk
	cleanTransactions []*dynamodb.TransactWriteItemsInput
}

func applySessionControlTerminalTransaction(fake *sessionControlSessionDynamoFake,
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

func installSessionControlTerminalTransactionFake(fake *sessionControlSessionDynamoFake) {
	fake.transactHook = func(ctx context.Context,
		input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		applySessionControlTerminalTransaction(fake, input)
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}
}

func assertSessionControlTerminalUniqueTransactionKeys(t *testing.T, transaction []types.TransactWriteItem) {
	t.Helper()
	seen := make(map[string]struct{}, len(transaction))
	for index, member := range transaction {
		var key map[string]types.AttributeValue
		switch {
		case member.ConditionCheck != nil:
			key = member.ConditionCheck.Key
		case member.Put != nil:
			key = member.Put.Item
		case member.Delete != nil:
			key = member.Delete.Key
		case member.Update != nil:
			key = member.Update.Key
		default:
			t.Fatalf("transaction item %d has no operation", index)
		}
		canonical := sessionControlSessionDynamoMapKey(key)
		if canonical == "" {
			t.Fatalf("transaction item %d has no canonical key", index)
		}
		if _, duplicate := seen[canonical]; duplicate {
			t.Fatalf("transaction item %d duplicates key %q", index, canonical)
		}
		seen[canonical] = struct{}{}
	}
}

func newSessionControlTerminalFixture(t *testing.T, count int) sessionControlTerminalFixture {
	t.Helper()
	fixture := sessionControlTerminalFixture{sessionControlCleanupFixture: newSessionControlCleanupFixture(t, count)}
	installSessionControlTerminalTransactionFake(fixture.fake)
	for manifestIndex := range fixture.taskSet.ManifestDigests {
		manifest, err := fixture.store.getCloseManifest(context.Background(), fixture.close.EventID,
			uint64(manifestIndex))
		if err != nil {
			t.Fatal(err)
		}
		for refIndex, ref := range manifest.Refs {
			_, err = fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
				sessionControlCleanupRequest(fixture.sessionControlCleanupFixture, ref.OwnerPK,
					uint64(0xd000+manifestIndex*sessionControlCloseManifestOwnerLimit+refIndex)))
			if err != nil {
				t.Fatalf("cleanup manifest %d ref %d: %v", manifestIndex, refIndex, err)
			}
		}
		chunk, err := fixture.store.PrepareNormalExactCloseCleanChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, uint64(manifestIndex))
		if err != nil {
			t.Fatalf("prepare clean chunk %d: %v", manifestIndex, err)
		}
		fixture.cleanChunks = append(fixture.cleanChunks, *chunk)
		fixture.cleanTransactions = append(fixture.cleanTransactions,
			fixture.fake.transactions[len(fixture.fake.transactions)-1])
	}
	fixture.store.nowUTC = func() time.Time {
		return time.UnixMilli(fixture.fence.ReplayNotBeforeMillis).UTC()
	}
	return fixture
}

func TestDynamoSessionControlTerminalTransactionArithmeticAndReplay(t *testing.T) {
	for _, count := range []int{0, 1, 48, 49, 1024} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			fixture := newSessionControlTerminalFixture(t, count)
			for index, chunk := range fixture.cleanChunks {
				txn := fixture.cleanTransactions[index]
				if got, want := len(txn.TransactItems), 3+2*int(chunk.OwnerCount); got != want || got > 99 ||
					len(aws.ToString(txn.ClientRequestToken)) > 36 {
					t.Fatalf("CLEANCHUNK %d transaction = %d, want %d", index, got, want)
				}
				if txn.TransactItems[0].ConditionCheck == nil || txn.TransactItems[1].ConditionCheck == nil ||
					txn.TransactItems[len(txn.TransactItems)-1].Put == nil {
					t.Fatalf("CLEANCHUNK %d shape = %#v", index, txn.TransactItems)
				}
				for pair := 0; pair < int(chunk.OwnerCount); pair++ {
					if txn.TransactItems[2+pair*2].ConditionCheck == nil ||
						txn.TransactItems[3+pair*2].ConditionCheck == nil {
						t.Fatalf("CLEANCHUNK %d proof pair %d malformed", index, pair)
					}
				}
				if _, hasTTL := txn.TransactItems[len(txn.TransactItems)-1].Put.Item["ttl"]; hasTTL {
					t.Fatal("CLEANCHUNK unexpectedly has TTL")
				}
				assertSessionControlTerminalUniqueTransactionKeys(t, txn.TransactItems)
			}

			before := len(fixture.fake.transactions)
			closed, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
				fixture.close.EventID)
			if err != nil {
				t.Fatal(err)
			}
			txn := fixture.fake.transactions[before]
			if got, want := len(txn.TransactItems), 8+len(fixture.cleanChunks); got != want || got > 30 ||
				len(aws.ToString(txn.ClientRequestToken)) > 36 {
				t.Fatalf("terminal transaction = %d/%q, want %d", got,
					aws.ToString(txn.ClientRequestToken), want)
			}
			if txn.TransactItems[0].Put == nil || txn.TransactItems[1].Put == nil ||
				txn.TransactItems[2].Delete == nil || txn.TransactItems[3].Put == nil ||
				txn.TransactItems[4].Delete == nil || txn.TransactItems[5].Put == nil ||
				txn.TransactItems[6].ConditionCheck == nil || txn.TransactItems[7].ConditionCheck == nil {
				t.Fatalf("terminal transaction shape = %#v", txn.TransactItems[:8])
			}
			for index := 8; index < len(txn.TransactItems); index++ {
				if txn.TransactItems[index].ConditionCheck == nil {
					t.Fatalf("terminal clean condition %d = %#v", index, txn.TransactItems[index])
				}
			}
			if closed.SessionAfter.State != sessionControlSessionStateClosed ||
				closed.DirectoryAfter.ActiveFenceCount+1 != closed.DirectoryBefore.ActiveFenceCount ||
				closed.DirectoryAfter.Version != closed.DirectoryBefore.Version+1 ||
				closed.FenceAfter.State != sessionControlFenceRetired ||
				closed.ClosedAtMillis != fixture.fence.ReplayNotBeforeMillis {
				t.Fatalf("CLOSED = %#v", closed)
			}
			if _, hasTTL := txn.TransactItems[5].Put.Item["ttl"]; hasTTL {
				t.Fatal("CLOSED unexpectedly has TTL")
			}
			assertSessionControlTerminalUniqueTransactionKeys(t, txn.TransactItems)
			transactions := len(fixture.fake.transactions)
			replayed, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
				fixture.close.EventID)
			if err != nil || replayed.ClosedDigest != closed.ClosedDigest || len(fixture.fake.transactions) != transactions {
				fixture.fake.mu.Lock()
				marker := fixture.fake.items[sessionControlSessionDynamoMapKey(sessionControlCloseClosedKey(fixture.close.EventID))]
				fixture.fake.mu.Unlock()
				t.Fatalf("terminal replay = %#v, %v, transactions=%d marker=%#v", replayed, err,
					len(fixture.fake.transactions), marker)
			}
		})
	}
}

func TestDynamoSessionControlTerminalPreservesOverflowLatchBytes(t *testing.T) {
	fixture := newSessionControlTerminalFixture(t, 1)
	directory, err := fixture.store.getFenceDirectory(context.Background(), fixture.candidate.CellID)
	if err != nil {
		t.Fatal(err)
	}
	directory.Version++
	directory.AdmissionBlocked = true
	directory.OverflowCloseCount = 2
	directory.OverflowLeaderEventID = sessionControlTaskTestID(0xd101)
	directory.OverflowLeaderPreparedDirectoryVersion = directory.Version - 1
	directory.OverflowLeaderSelectedDirectoryVersion = directory.Version
	directory.UpdatedAtMillis++
	seedSessionControlCloseDirectory(t, fixture.fake, *directory)
	fixture.store.nowUTC = func() time.Time {
		return time.UnixMilli(max(fixture.fence.ReplayNotBeforeMillis, directory.UpdatedAtMillis)).UTC()
	}
	closed, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	before, after := closed.DirectoryBefore, closed.DirectoryAfter
	if !before.AdmissionBlocked || after.AdmissionBlocked != before.AdmissionBlocked ||
		after.OverflowCloseCount != before.OverflowCloseCount ||
		after.OverflowLeaderEventID != before.OverflowLeaderEventID ||
		after.OverflowLeaderPreparedDirectoryVersion != before.OverflowLeaderPreparedDirectoryVersion ||
		after.OverflowLeaderSelectedDirectoryVersion != before.OverflowLeaderSelectedDirectoryVersion {
		t.Fatalf("latch drift: before=%#v after=%#v", before, after)
	}
}

func TestDynamoSessionControlTerminalExactReplayHorizon(t *testing.T) {
	fixture := newSessionControlTerminalFixture(t, 1)
	fixture.store.nowUTC = func() time.Time {
		return time.UnixMilli(fixture.fence.ReplayNotBeforeMillis - 1).UTC()
	}
	before := len(fixture.fake.transactions)
	if _, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID); !errors.Is(err, errSessionControlFenceReplayHorizon) {
		t.Fatalf("horizon -1 = %v", err)
	}
	if len(fixture.fake.transactions) != before {
		t.Fatal("horizon -1 wrote a transaction")
	}
	fixture.store.nowUTC = func() time.Time {
		return time.UnixMilli(fixture.fence.ReplayNotBeforeMillis).UTC()
	}
	closed, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID)
	if err != nil || closed.ClosedAtMillis != fixture.fence.ReplayNotBeforeMillis {
		t.Fatalf("exact horizon = %#v, %v", closed, err)
	}
}

func TestDynamoSessionControlTerminalRejectsGenericRetireAndMarkerHalfStates(t *testing.T) {
	t.Run("generic_retire_without_closed", func(t *testing.T) {
		fixture := newSessionControlTerminalFixture(t, 1)
		closed, err := planSessionControlTerminalExactClose(fixture.directory, fixture.fence,
			fixture.close.Session, mustSessionControlTerminalWork(t, fixture), fixture.complete,
			fixture.taskSet, fixture.cleanChunks, fixture.fence.ReplayNotBeforeMillis)
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
			t.Fatal("generic retire was accepted as terminal completion")
		}
	})

	t.Run("closed_marker_without_state_transition", func(t *testing.T) {
		fixture := newSessionControlTerminalFixture(t, 1)
		closed, err := planSessionControlTerminalExactClose(fixture.directory, fixture.fence,
			fixture.close.Session, mustSessionControlTerminalWork(t, fixture), fixture.complete,
			fixture.taskSet, fixture.cleanChunks, fixture.fence.ReplayNotBeforeMillis)
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
			t.Fatal("orphan CLOSED marker was accepted")
		}
	})
}

func mustSessionControlTerminalWork(t *testing.T, fixture sessionControlTerminalFixture) *sessionControlCloseWork {
	t.Helper()
	work, err := fixture.store.getCloseWork(context.Background(), fixture.candidate.CellID,
		fixture.close.EventID, false)
	if err != nil {
		t.Fatal(err)
	}
	return work
}

func TestDynamoSessionControlTerminalAcceptsOlderCleanChunkAfterRetentionExtension(t *testing.T) {
	fixture := newSessionControlTerminalFixture(t, 1)
	oldChunk := fixture.cleanChunks[0]
	minimum := fixture.complete.RetainUntilMillis + time.Hour.Milliseconds()
	extended, err := fixture.store.extendCloseCompleteRetention(context.Background(), fixture.candidate,
		fixture.complete, minimum)
	if err != nil {
		t.Fatal(err)
	}
	fixture.complete = *extended
	fixture.store.nowUTC = func() time.Time { return time.UnixMilli(fixture.fence.ReplayNotBeforeMillis).UTC() }
	closed, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if closed.Complete.RetainUntilMillis != minimum || oldChunk.Complete.RetainUntilMillis >= minimum {
		t.Fatalf("retention extension not observed: chunk=%d closed=%d", oldChunk.Complete.RetainUntilMillis,
			closed.Complete.RetainUntilMillis)
	}
}

func TestDynamoSessionControlCleanChunkCompatibleReplayAfterRetentionExtension(t *testing.T) {
	fixture := newSessionControlTerminalFixture(t, 1)
	stored := fixture.cleanChunks[0]
	minimum := fixture.complete.RetainUntilMillis + time.Hour.Milliseconds()
	extended, err := fixture.store.extendCloseCompleteRetention(context.Background(), fixture.candidate,
		fixture.complete, minimum)
	if err != nil {
		t.Fatal(err)
	}
	fixture.complete = *extended
	fixture.fake.transactHook = func(context.Context,
		*dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		return nil, &types.TransactionCanceledException{}
	}
	replayed, err := fixture.store.PrepareNormalExactCloseCleanChunk(context.Background(), fixture.candidate,
		fixture.close.EventID, 0)
	if err != nil || replayed.ChunkDigest != stored.ChunkDigest ||
		replayed.Complete.RetainUntilMillis != stored.Complete.RetainUntilMillis {
		t.Fatalf("compatible CLEANCHUNK replay = %#v, %v", replayed, err)
	}
}

func sessionControlTerminalSnapshot(directory sessionControlFenceDirectory) sessionControlFenceSnapshot {
	return sessionControlFenceSnapshot{CellID: directory.CellID, DirectoryVersion: directory.Version,
		ActiveFenceCount: directory.ActiveFenceCount, AdmissionBlocked: directory.AdmissionBlocked,
		OverflowCloseCount:                     directory.OverflowCloseCount,
		OverflowLeaderEventID:                  directory.OverflowLeaderEventID,
		OverflowLeaderPreparedDirectoryVersion: directory.OverflowLeaderPreparedDirectoryVersion,
		OverflowLeaderSelectedDirectoryVersion: directory.OverflowLeaderSelectedDirectoryVersion,
		Fences:                                 []sessionControlFenceAuthority{}}
}

func TestDynamoSessionControlReserveRejectsClosedExistingAndPostWriteClassification(t *testing.T) {
	for _, postWrite := range []bool{false, true} {
		t.Run(fmt.Sprintf("post_write_%t", postWrite), func(t *testing.T) {
			fixture := newSessionControlTerminalFixture(t, 1)
			if _, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
				fixture.close.EventID); err != nil {
				t.Fatal(err)
			}
			directory, err := fixture.store.getFenceDirectory(context.Background(), fixture.candidate.CellID)
			if err != nil {
				t.Fatal(err)
			}
			if postWrite {
				hide := 3
				fixture.fake.getHook = func(ctx context.Context, input *dynamodb.GetItemInput,
					_ int) (*dynamodb.GetItemOutput, error) {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					key := sessionControlSessionDynamoMapKey(input.Key)
					sessionKey := sessionControlSessionDynamoMapKey(sessionControlSessionDynamoKey(fixture.candidate.SessionID))
					membershipKey := sessionControlSessionDynamoMapKey(sessionControlAgentSessionDynamoKey(fixture.candidate))
					if hide > 0 && (key == sessionKey || key == membershipKey) {
						hide--
						return &dynamodb.GetItemOutput{}, nil
					}
					fixture.fake.mu.Lock()
					item := fixture.fake.items[key]
					fixture.fake.mu.Unlock()
					return &dynamodb.GetItemOutput{Item: item}, nil
				}
				fixture.fake.transactHook = func(context.Context,
					*dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
					return nil, &types.TransactionCanceledException{}
				}
			}
			if _, err = fixture.store.ReserveSession(context.Background(), fixture.candidate,
				sessionControlTerminalSnapshot(*directory)); !errors.Is(err, errSessionControlSessionFenceDenied) {
				t.Fatalf("ReserveSession CLOSED = %v", err)
			}
		})
	}
}

func TestDynamoSessionControlTerminalClassifierPreservesReadErrors(t *testing.T) {
	tests := []struct {
		name string
		key  func(sessionControlTerminalFixture) map[string]types.AttributeValue
	}{
		{"meta", func(f sessionControlTerminalFixture) map[string]types.AttributeValue {
			return sessionControlFenceMetaKey(f.close.EventID)
		}},
		{"active", func(f sessionControlTerminalFixture) map[string]types.AttributeValue {
			return sessionControlFenceActiveKey(f.candidate.CellID, f.close.EventID)
		}},
		{"work", func(f sessionControlTerminalFixture) map[string]types.AttributeValue {
			return sessionControlCloseWorkKey(f.close.EventID)
		}},
		{"complete", func(f sessionControlTerminalFixture) map[string]types.AttributeValue {
			return sessionControlCloseCompleteKey(f.close.EventID)
		}},
		{"taskset", func(f sessionControlTerminalFixture) map[string]types.AttributeValue {
			return sessionControlCloseTaskSetKey(f.close.EventID)
		}},
		{"cleanchunk", func(f sessionControlTerminalFixture) map[string]types.AttributeValue {
			return sessionControlCloseCleanChunkKey(f.close.EventID, 0)
		}},
	}
	for _, tt := range tests {
		for _, failure := range []string{"transport", "cancel"} {
			t.Run(tt.name+"_"+failure, func(t *testing.T) {
				fixture := newSessionControlTerminalFixture(t, 1)
				if _, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
					fixture.close.EventID); err != nil {
					t.Fatal(err)
				}
				target := sessionControlSessionDynamoMapKey(tt.key(fixture))
				var sentinel error = fmt.Errorf("%s transport", tt.name)
				if failure == "cancel" {
					sentinel = context.Canceled
				}
				fixture.fake.getHook = func(ctx context.Context, input *dynamodb.GetItemInput,
					_ int) (*dynamodb.GetItemOutput, error) {
					if sessionControlSessionDynamoMapKey(input.Key) == target {
						return nil, sentinel
					}
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					fixture.fake.mu.Lock()
					item := fixture.fake.items[sessionControlSessionDynamoMapKey(input.Key)]
					fixture.fake.mu.Unlock()
					return &dynamodb.GetItemOutput{Item: item}, nil
				}
				_, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
					fixture.close.EventID)
				if !errors.Is(err, sentinel) {
					t.Fatalf("classifier %s/%s error = %v", tt.name, failure, err)
				}
			})
		}
	}
}

func TestDynamoSessionControlTerminalLostResponseAndConcurrentWinner(t *testing.T) {
	fixture := newSessionControlTerminalFixture(t, 1)
	var once sync.Once
	fixture.fake.transactHook = func(ctx context.Context,
		input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		committed := false
		once.Do(func() {
			applySessionControlTerminalTransaction(fixture.fake, input)
			committed = true
		})
		if committed {
			return nil, errors.New("ambiguous transport")
		}
		return nil, &types.TransactionCanceledException{}
	}
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
				fixture.close.EventID)
			results <- err
		}()
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("ambiguous concurrent finalizer = %v", err)
		}
	}
	directory, err := fixture.store.getFenceDirectory(context.Background(), fixture.candidate.CellID)
	if err != nil || directory.ActiveFenceCount != 0 {
		t.Fatalf("directory after concurrent finalize = %#v, %v", directory, err)
	}
}

func TestDynamoSessionControlCleanChunkRejectsMissingBothAndReappearingTask(t *testing.T) {
	for _, mode := range []string{"missing", "both", "reappears_at_cas"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newSessionControlCleanupFixture(t, 1)
			installSessionControlTerminalTransactionFake(fixture.fake)
			manifest, err := fixture.store.getCloseManifest(context.Background(), fixture.close.EventID, 0)
			if err != nil {
				t.Fatal(err)
			}
			ownerPK := manifest.Refs[0].OwnerPK
			task, err := fixture.store.getCloseTask(context.Background(), ownerPK, fixture.close.EventID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
				sessionControlCleanupRequest(fixture, ownerPK, 0xd301)); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing":
				fixture.fake.mu.Lock()
				delete(fixture.fake.items, sessionControlSessionDynamoMapKey(
					sessionControlCloseTaskAuditKey(ownerPK, fixture.close.EventID)))
				fixture.fake.mu.Unlock()
			case "both":
				row, rowErr := sessionControlCloseTaskToRow(*task)
				if rowErr != nil {
					t.Fatal(rowErr)
				}
				fixture.fake.setItem(marshalSessionControlSessionTestRow(t, row))
			case "reappears_at_cas":
				fixture.fake.transactHook = func(context.Context,
					*dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
					row, rowErr := sessionControlCloseTaskToRow(*task)
					if rowErr != nil {
						return nil, rowErr
					}
					fixture.fake.setItem(marshalSessionControlSessionTestRow(t, row))
					return nil, &types.TransactionCanceledException{}
				}
			}
			_, err = fixture.store.PrepareNormalExactCloseCleanChunk(context.Background(), fixture.candidate,
				fixture.close.EventID, 0)
			if mode == "reappears_at_cas" {
				if !errors.Is(err, errSessionControlTerminalConflict) {
					t.Fatalf("reappearing TASK = %v", err)
				}
			} else if err == nil {
				t.Fatalf("%s TASK/AUDIT state was accepted", mode)
			}
		})
	}
}

func TestDynamoSessionControlCleanChunkFortyEightRefCancelAndLostResponse(t *testing.T) {
	makeReady := func(t *testing.T) (sessionControlCleanupFixture, sessionControlCloseManifest) {
		t.Helper()
		fixture := newSessionControlCleanupFixture(t, 48)
		installSessionControlTerminalTransactionFake(fixture.fake)
		manifest, err := fixture.store.getCloseManifest(context.Background(), fixture.close.EventID, 0)
		if err != nil {
			t.Fatal(err)
		}
		for index, ref := range manifest.Refs {
			if _, err = fixture.store.CleanupAckedNormalExactCloseTask(context.Background(),
				sessionControlCleanupRequest(fixture, ref.OwnerPK, uint64(0xd400+index))); err != nil {
				t.Fatal(err)
			}
		}
		return fixture, *manifest
	}
	t.Run("cancel", func(t *testing.T) {
		fixture, _ := makeReady(t)
		fixture.fake.transactHook = func(context.Context,
			*dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			return nil, &types.TransactionCanceledException{}
		}
		if _, err := fixture.store.PrepareNormalExactCloseCleanChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, 0); !errors.Is(err, errSessionControlTerminalConflict) {
			t.Fatalf("48-ref canceled CLEANCHUNK = %v", err)
		}
	})
	t.Run("lost_response", func(t *testing.T) {
		fixture, _ := makeReady(t)
		fixture.fake.transactHook = func(_ context.Context,
			input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			applySessionControlTerminalTransaction(fixture.fake, input)
			return nil, errors.New("lost CLEANCHUNK response")
		}
		chunk, err := fixture.store.PrepareNormalExactCloseCleanChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, 0)
		if err != nil || chunk.OwnerCount != 48 {
			t.Fatalf("48-ref lost response = %#v, %v", chunk, err)
		}
	})
}

func TestDynamoSessionControlTerminalRejectsNoncanonicalSessionAndConditionsAbsentFields(t *testing.T) {
	for _, name := range []string{"missing-zero", "unknown"} {
		t.Run(name, func(t *testing.T) {
			fixture := newSessionControlTerminalFixture(t, 0)
			key := sessionControlSessionDynamoMapKey(sessionControlSessionDynamoKey(fixture.candidate.SessionID))
			fixture.fake.mu.Lock()
			item := fixture.fake.items[key]
			if name == "missing-zero" {
				delete(item, "target_count")
			} else {
				item["unexpected_authority"] = &types.AttributeValueMemberS{Value: "unsafe"}
			}
			fixture.fake.mu.Unlock()
			if _, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
				fixture.close.EventID); !errors.Is(err, errSessionControlSessionCorrupt) {
				t.Fatalf("terminal noncanonical SESSION = %v", err)
			}
		})
	}

	fixture := newSessionControlTerminalFixture(t, 0)
	before := len(fixture.fake.transactions)
	if _, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID); err != nil {
		t.Fatal(err)
	}
	sessionPut := fixture.fake.transactions[before].TransactItems[3].Put
	condition := aws.ToString(sessionPut.ConditionExpression)
	for _, absent := range []string{"ack_enqueued_at_ms", "session_expires_at_ms", "ttl"} {
		if !strings.Contains(condition, "attribute_not_exists") {
			t.Fatalf("terminal session condition lacks absence fencing for %s: %q", absent, condition)
		}
		found := false
		for placeholder, name := range sessionPut.ExpressionAttributeNames {
			if name == absent && strings.Contains(condition, "attribute_not_exists("+placeholder+")") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("terminal session condition lacks %s absence: %q names=%#v", absent, condition,
				sessionPut.ExpressionAttributeNames)
		}
	}
}

func TestDynamoSessionControlTerminalClampsFutureCleanChunk(t *testing.T) {
	fixture := newSessionControlTerminalFixture(t, 1)
	future := fixture.fence.ReplayNotBeforeMillis + 5_000
	chunk := fixture.cleanChunks[0]
	chunk.CreatedAtMillis = future
	chunk.ChunkDigest, _ = sessionControlCloseCleanChunkDigest(chunk)
	row, err := sessionControlCloseCleanChunkToRow(chunk)
	if err != nil {
		t.Fatal(err)
	}
	fixture.fake.setItem(marshalSessionControlSessionTestRow(t, row))
	closed, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID)
	if err != nil || closed.ClosedAtMillis != future {
		t.Fatalf("future CLEANCHUNK clamp = %#v, %v", closed, err)
	}
}

func TestDynamoSessionControlTerminalRequiresEveryOneOfTwentyTwoCleanChunks(t *testing.T) {
	for _, mode := range []string{"missing", "mutated"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newSessionControlTerminalFixture(t, 1024)
			last := fixture.cleanChunks[len(fixture.cleanChunks)-1]
			key := sessionControlSessionDynamoMapKey(sessionControlCloseCleanChunkKey(last.EventID, last.ManifestIndex))
			fixture.fake.mu.Lock()
			if mode == "missing" {
				delete(fixture.fake.items, key)
			} else {
				item := fixture.fake.items[key]
				copy := make(map[string]types.AttributeValue, len(item))
				for name, value := range item {
					copy[name] = value
				}
				copy["source_count"] = &types.AttributeValueMemberN{Value: fmt.Sprint(last.SourceCount + 1)}
				fixture.fake.items[key] = copy
			}
			fixture.fake.mu.Unlock()
			if _, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
				fixture.close.EventID); err == nil {
				t.Fatalf("%s CLEANCHUNK was accepted", mode)
			}
		})
	}
}

func TestSessionControlTerminalTokensBindFullInput(t *testing.T) {
	fixture := newSessionControlTerminalFixture(t, 1)
	clean := fixture.cleanChunks[0]
	base, err := sessionControlTerminalToken(fixture.store.tableName, "clean", clean)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []sessionControlCloseCleanChunk{clean, clean, clean}
	mutations[0].CreatedAtMillis++
	mutations[1].Complete.RetainUntilMillis++
	mutations[2].Refs = append([]sessionControlCloseCleanRef(nil), clean.Refs...)
	mutations[2].Refs[0].AuditDigest = fmt.Sprintf("%064x", 0xd501)
	for index, mutation := range mutations {
		token, tokenErr := sessionControlTerminalToken(fixture.store.tableName, "clean", mutation)
		if tokenErr != nil || aws.ToString(token) == aws.ToString(base) || len(aws.ToString(token)) > 36 {
			t.Fatalf("clean token mutation %d = %q, %v", index, aws.ToString(token), tokenErr)
		}
	}
	closed, err := planSessionControlTerminalExactClose(fixture.directory, fixture.fence,
		fixture.close.Session, mustSessionControlTerminalWork(t, fixture), fixture.complete,
		fixture.taskSet, fixture.cleanChunks, fixture.fence.ReplayNotBeforeMillis)
	if err != nil {
		t.Fatal(err)
	}
	closedBase, err := sessionControlTerminalToken(fixture.store.tableName, "close", closed)
	if err != nil {
		t.Fatal(err)
	}
	closedMutations := []sessionControlCloseClosedAudit{closed, closed, closed}
	closedMutations[0].DirectoryAfter.AdmissionBlocked = !closed.DirectoryAfter.AdmissionBlocked
	closedMutations[1].SessionAfter.RetainUntilMillis++
	closedMutations[2].CleanChunkDigests = append([]string(nil), closed.CleanChunkDigests...)
	closedMutations[2].CleanChunkDigests[0] = fmt.Sprintf("%064x", 0xd502)
	for index, mutation := range closedMutations {
		token, tokenErr := sessionControlTerminalToken(fixture.store.tableName, "close", mutation)
		if tokenErr != nil || aws.ToString(token) == aws.ToString(closedBase) || len(aws.ToString(token)) > 36 {
			t.Fatalf("closed token mutation %d = %q, %v", index, aws.ToString(token), tokenErr)
		}
	}
}

func TestSessionControlTerminalStrictRowsAndCeilings(t *testing.T) {
	fixture := newSessionControlTerminalFixture(t, 1)
	chunk := fixture.cleanChunks[0]
	row, err := sessionControlCloseCleanChunkToRow(chunk)
	if err != nil {
		t.Fatal(err)
	}
	item := marshalSessionControlSessionTestRow(t, row)
	delete(item, "refs")
	if _, err = sessionControlCloseCleanChunkFromItem(item, chunk.EventID, chunk.ManifestIndex); !errors.Is(err, errSessionControlTerminalCorrupt) {
		t.Fatalf("missing refs = %v", err)
	}
	item = marshalSessionControlSessionTestRow(t, row)
	item["ttl"] = &types.AttributeValueMemberN{Value: "1"}
	if _, err = sessionControlCloseCleanChunkFromItem(item, chunk.EventID, chunk.ManifestIndex); !errors.Is(err, errSessionControlTerminalCorrupt) {
		t.Fatalf("CLEANCHUNK TTL = %v", err)
	}
	for _, field := range []string{"schema_version", "manifest_index", "source_count", "owner_count", "created_at_ms"} {
		item = marshalSessionControlSessionTestRow(t, row)
		delete(item, field)
		if _, err = sessionControlCloseCleanChunkFromItem(item, chunk.EventID, chunk.ManifestIndex); !errors.Is(err, errSessionControlTerminalCorrupt) {
			t.Fatalf("missing CLEANCHUNK %s = %v", field, err)
		}
	}
	overflow := chunk
	overflow.Refs = append([]sessionControlCloseCleanRef(nil), chunk.Refs...)
	overflow.SourceCount = math.MaxUint64
	overflow.Refs[0].SourceCount = math.MaxUint64
	overflow.ChunkDigest, _ = sessionControlCloseCleanChunkDigest(overflow)
	if validateSessionControlCloseCleanChunk(overflow) == nil {
		t.Fatal("wrapping CLEANCHUNK source total accepted")
	}

	directory := fixture.directory
	directory.Version = math.MaxUint64 - 1
	if _, err = planSessionControlTerminalExactClose(directory, fixture.fence, fixture.close.Session,
		mustSessionControlTerminalWork(t, fixture), fixture.complete, fixture.taskSet, fixture.cleanChunks,
		fixture.fence.ReplayNotBeforeMillis); err == nil {
		t.Fatal("directory version ceiling accepted")
	}
	fence := fixture.fence
	fence.Version = math.MaxUint64 - 1
	if _, err = planSessionControlTerminalExactClose(fixture.directory, fence, fixture.close.Session,
		mustSessionControlTerminalWork(t, fixture), fixture.complete, fixture.taskSet, fixture.cleanChunks,
		fixture.fence.ReplayNotBeforeMillis); err == nil {
		t.Fatal("fence version ceiling accepted")
	}
}

func TestSessionControlTerminalZeroTargetNestedRowsRequireCanonicalZeroFields(t *testing.T) {
	fixture := newSessionControlTerminalFixture(t, 0)
	closed, err := fixture.store.FinalizeTerminalExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	row, err := sessionControlCloseClosedToRow(*closed)
	if err != nil {
		t.Fatal(err)
	}
	base := marshalSessionControlSessionTestRow(t, row)
	for _, tt := range []struct{ nested, field string }{
		{"session_before", "target_count"}, {"session_after", "target_count"},
		{"work_before", "expected_target_count"},
	} {
		item := make(map[string]types.AttributeValue, len(base))
		for name, value := range base {
			item[name] = value
		}
		nested := item[tt.nested].(*types.AttributeValueMemberM)
		nestedCopy := make(map[string]types.AttributeValue, len(nested.Value))
		for name, value := range nested.Value {
			nestedCopy[name] = value
		}
		delete(nestedCopy, tt.field)
		item[tt.nested] = &types.AttributeValueMemberM{Value: nestedCopy}
		// The logical zero-valued authority and therefore closed_digest are
		// unchanged; this specifically proves physical presence is enforced.
		if _, err = sessionControlCloseClosedFromItem(item, closed.EventID); !errors.Is(err, errSessionControlTerminalCorrupt) {
			t.Fatalf("missing %s.%s = %v", tt.nested, tt.field, err)
		}
	}
}
