package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type sessionControlCompletionFixture struct {
	sessionControlTaskFixture
	directory sessionControlFenceDirectory
	fence     sessionControlFenceAuthority
	chunks    []sessionControlCloseAckChunk
}

func applySessionControlCompletionTransaction(fake *sessionControlSessionDynamoFake,
	input *dynamodb.TransactWriteItemsInput) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, member := range input.TransactItems {
		if member.Put != nil {
			fake.items[sessionControlSessionDynamoMapKey(member.Put.Item)] = member.Put.Item
			continue
		}
		if member.Update == nil {
			continue
		}
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

func seedSessionControlCloseComplete(t *testing.T, fake *sessionControlSessionDynamoFake,
	complete sessionControlCloseComplete) {
	t.Helper()
	row, err := sessionControlCloseCompleteToRow(complete)
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, row))
}

func installSessionControlCompletionTransactionFake(fake *sessionControlSessionDynamoFake) {
	fake.transactHook = func(ctx context.Context,
		input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		applySessionControlCompletionTransaction(fake, input)
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}
}

func seedSessionControlCompletionAckedTasks(t *testing.T, fixture *sessionControlCompletionFixture) {
	t.Helper()
	for manifestIndex := range fixture.taskSet.ManifestDigests {
		manifest, err := fixture.store.getCloseManifest(context.Background(), fixture.close.EventID, uint64(manifestIndex))
		if err != nil {
			t.Fatal(err)
		}
		for refIndex, ref := range manifest.Refs {
			task, err := fixture.store.getCloseTask(context.Background(), ref.OwnerPK, fixture.close.EventID)
			if err != nil {
				t.Fatal(err)
			}
			owner, err := fixture.store.getOwner(context.Background(), task.CellID, task.ACID, task.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			ackedAt := fixture.store.nowUTC().UnixMilli() + int64(manifestIndex*sessionControlCloseManifestOwnerLimit+refIndex)
			leasedOwner, err := planSessionControlOwnerTaskLeaseTransition(*owner, ackedAt)
			if err != nil {
				t.Fatal(err)
			}
			nextOwner, err := planSessionControlOwnerTaskAck(leasedOwner, ackedAt)
			if err != nil {
				t.Fatal(err)
			}
			lease := sessionControlCloseTaskLeaseRequest{CellID: task.CellID, EventID: task.EventID,
				OwnerPK: task.OwnerPK, OperationID: sessionControlTaskTestID(uint64(0x2000 + manifestIndex*100 + refIndex)),
				LeaseID:    sessionControlTaskTestID(uint64(0x3000 + manifestIndex*100 + refIndex)),
				LeaseOwner: sessionControlTaskTestID(uint64(0x4000 + manifestIndex*100 + refIndex))}
			request := sessionControlTaskAckRequest(fixture.sessionControlTaskFixture, *task, lease, uint64(refIndex+1))
			task.TaskVersion = 3
			task.State = sessionControlCloseTaskStateAcked
			task.CurrentOwnerWorkVersion = nextOwner.WorkVersion
			task.CurrentOwnerTaskCount = nextOwner.TaskCount
			task.CurrentOwnerPendingCount = nextOwner.PendingCount
			task.DueAtMillis, task.DueShard, task.DueSort = 0, "", ""
			task.LeaseID, task.LeaseOwner, task.LeaseExpiresAtMillis = "", "", 0
			task.LastOperationKind = sessionControlCloseTaskOperationAcked
			task.LastOperationID = lease.OperationID
			task.LastOperationInputDigest, err = sessionControlCloseTaskAckInputDigest(request)
			if err != nil {
				t.Fatal(err)
			}
			task.AckAuthenticatedPublicKey = request.AuthenticatedPublicKey
			task.AckSelectorDigest = task.SelectorDigest
			task.AckBootID = request.Ack.BootID
			task.AckFlushGeneration = request.Ack.FlushGeneration
			task.AckClosed = request.Ack.Closed
			task.AckLeaseID, task.AckLeaseOwner = lease.LeaseID, lease.LeaseOwner
			task.AckedAtMillis, task.UpdatedAtMillis = ackedAt, ackedAt
			if validateSessionControlCloseTask(*task) != nil {
				t.Fatalf("invalid seeded ACKed task: %#v", task)
			}
			row, err := sessionControlCloseTaskToRow(*task)
			if err != nil {
				t.Fatal(err)
			}
			fixture.fake.setItem(marshalSessionControlSessionTestRow(t, row))
			seedSessionControlTaskOwner(t, fixture.fake, nextOwner)
		}
	}
}

func convergeSessionControlCompletionFence(t *testing.T, fixture *sessionControlCompletionFixture) {
	t.Helper()
	directory, err := fixture.store.getFenceDirectory(context.Background(), fixture.close.Session.Candidate.CellID)
	if err != nil {
		t.Fatal(err)
	}
	fence := *fixture.close.Fence
	convergedAt := fixture.store.nowUTC().UnixMilli() + 10_000
	fence.State = sessionControlFenceConverged
	fence.Version++
	fence.ConvergedAtMillis = convergedAt
	fence.ReplayNotBeforeMillis = convergedAt + sessionControlFenceReplayHorizon.Milliseconds()
	fence.UpdatedAtMillis = convergedAt
	directory.Version++
	directory.UpdatedAtMillis = convergedAt
	seedSessionControlCloseFence(t, fixture.fake, fence)
	seedSessionControlCloseDirectory(t, fixture.fake, *directory)
	fixture.directory, fixture.fence = *directory, fence
}

func newSessionControlCompletionFixture(t *testing.T, count int, prepareChunks, converge bool) sessionControlCompletionFixture {
	t.Helper()
	taskFixture := newSessionControlTaskFixture(t, count)
	fixture := sessionControlCompletionFixture{sessionControlTaskFixture: taskFixture}
	installSessionControlCompletionTransactionFake(fixture.fake)
	seedSessionControlCompletionAckedTasks(t, &fixture)
	if prepareChunks {
		for index := range fixture.taskSet.ManifestDigests {
			chunk, err := fixture.store.PrepareNormalExactCloseAckChunk(context.Background(), fixture.candidate,
				fixture.close.EventID, uint64(index))
			if err != nil {
				t.Fatalf("prepare chunk %d: %v", index, err)
			}
			fixture.chunks = append(fixture.chunks, *chunk)
		}
	}
	if converge {
		convergeSessionControlCompletionFence(t, &fixture)
	}
	return fixture
}

func TestDynamoSessionControlPrepareAckChunksAndCompleteTransactionArithmetic(t *testing.T) {
	tests := []struct {
		count int
	}{
		{count: 0}, {count: 1}, {count: 48}, {count: 49}, {count: 1024},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.count), func(t *testing.T) {
			fixture := newSessionControlCompletionFixture(t, tt.count, false, false)
			beforeChunks := len(fixture.fake.transactions)
			for index, owners := range fixture.taskSet.ManifestOwnerCounts {
				chunk, err := fixture.store.PrepareNormalExactCloseAckChunk(context.Background(), fixture.candidate,
					fixture.close.EventID, uint64(index))
				if err != nil {
					t.Fatal(err)
				}
				fixture.chunks = append(fixture.chunks, *chunk)
				txn := fixture.fake.transactions[beforeChunks+index]
				if len(txn.TransactItems) != int(owners)+5 || len(txn.TransactItems) > 53 ||
					len(aws.ToString(txn.ClientRequestToken)) > 36 || txn.TransactItems[len(txn.TransactItems)-1].Put == nil {
					t.Fatalf("chunk transaction %d = %d/%q", index, len(txn.TransactItems), aws.ToString(txn.ClientRequestToken))
				}
				for _, member := range txn.TransactItems[:len(txn.TransactItems)-1] {
					if member.ConditionCheck == nil {
						t.Fatalf("chunk transaction member = %#v", member)
					}
				}
				if _, hasTTL := txn.TransactItems[len(txn.TransactItems)-1].Put.Item["ttl"]; hasTTL {
					t.Fatal("ACK chunk unexpectedly has TTL")
				}
			}
			convergeSessionControlCompletionFence(t, &fixture)
			beforeComplete := len(fixture.fake.transactions)
			complete, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
				fixture.close.EventID, 0)
			if err != nil {
				t.Fatal(err)
			}
			if complete.SourceCount != uint64(tt.count) || complete.OwnerCount != uint64(tt.count) ||
				len(complete.ChunkDigests) != len(fixture.taskSet.ManifestDigests) {
				t.Fatalf("COMPLETE = %#v", complete)
			}
			txn := fixture.fake.transactions[beforeComplete]
			if len(txn.TransactItems) != len(fixture.taskSet.ManifestDigests)+7 || len(txn.TransactItems) > 29 ||
				len(aws.ToString(txn.ClientRequestToken)) > 36 || txn.TransactItems[len(txn.TransactItems)-1].Put == nil {
				t.Fatalf("COMPLETE transaction = %d/%q", len(txn.TransactItems), aws.ToString(txn.ClientRequestToken))
			}
			for index := 0; index < 3; index++ {
				if txn.TransactItems[index].ConditionCheck == nil {
					t.Fatalf("COMPLETE authority member %d = %#v", index, txn.TransactItems[index])
				}
			}
			if txn.TransactItems[3].Update == nil || txn.TransactItems[4].Put == nil ||
				txn.TransactItems[5].ConditionCheck == nil {
				t.Fatalf("COMPLETE core members = %#v", txn.TransactItems[3:6])
			}
			for index := 6; index < len(txn.TransactItems)-1; index++ {
				if txn.TransactItems[index].ConditionCheck == nil {
					t.Fatalf("COMPLETE chunk member %d = %#v", index, txn.TransactItems[index])
				}
			}
			if _, hasDue := txn.TransactItems[4].Put.Item["due_at_ms"]; hasDue {
				t.Fatal("completed WORK unexpectedly remains due")
			}
			if _, hasCompleted := txn.TransactItems[4].Put.Item["completed_at_ms"]; !hasCompleted {
				t.Fatal("completed WORK lacks completion timestamp")
			}
			if _, hasTTL := txn.TransactItems[len(txn.TransactItems)-1].Put.Item["ttl"]; hasTTL {
				t.Fatal("COMPLETE unexpectedly has TTL")
			}
			work, err := fixture.store.getCloseWork(context.Background(), fixture.candidate.CellID,
				fixture.close.EventID, false)
			if err != nil || work.State != sessionControlCloseWorkStateCompleted || work.DueAtMillis != 0 {
				t.Fatalf("completed WORK = %#v/%v", work, err)
			}
		})
	}
}

func TestDynamoSessionControlNormalCompletionRejectsRedigestedChunkAuthorityMutation(t *testing.T) {
	fixture := newSessionControlCompletionFixture(t, 1, true, true)
	chunk := fixture.chunks[0]
	chunk.PreparedDirectoryVersion++
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
	if _, err = fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID, 0); !errors.Is(err, errSessionControlCompletionCorrupt) {
		t.Fatalf("mutated normal chunk error = %v", err)
	}
}

func TestDynamoSessionControlPrepareAckChunkRejectsNonterminalAndCorruptAudit(t *testing.T) {
	t.Run("event_identity", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		other := sessionControlTaskTestID(0x5001)
		if _, err := fixture.store.PrepareNormalExactCloseAckChunk(context.Background(), fixture.candidate, other, 0); err == nil {
			t.Fatal("mismatched ACK chunk event was accepted")
		}
		if _, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate, other, 0); err == nil {
			t.Fatal("mismatched COMPLETE event was accepted")
		}
	})
	t.Run("pending", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		installSessionControlCompletionTransactionFake(fixture.fake)
		if _, err := fixture.store.PrepareNormalExactCloseAckChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, 0); !errors.Is(err, errSessionControlCompletionConflict) {
			t.Fatalf("pending task error = %v", err)
		}
	})
	t.Run("leased", func(t *testing.T) {
		fixture := newSessionControlTaskFixture(t, 1)
		installSessionControlCompletionTransactionFake(fixture.fake)
		if _, err := fixture.store.ClaimExactCloseTask(context.Background(), sessionControlTaskClaimRequest(fixture, 0x5011)); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.PrepareNormalExactCloseAckChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, 0); !errors.Is(err, errSessionControlCompletionConflict) {
			t.Fatalf("leased task error = %v", err)
		}
	})
	t.Run("audit_mutation", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 1, false, false)
		key := sessionControlSessionDynamoMapKey(sessionControlCloseTaskKey(fixture.ownerPK, fixture.close.EventID))
		fixture.fake.mu.Lock()
		fixture.fake.items[key]["ack_selector_digest"] = &types.AttributeValueMemberS{Value: strings.Repeat("0", 64)}
		fixture.fake.mu.Unlock()
		if _, err := fixture.store.PrepareNormalExactCloseAckChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, 0); err == nil {
			t.Fatal("corrupt ACK audit was accepted")
		}
	})
	t.Run("manifest_ref_mutation", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 1, false, false)
		manifest, err := fixture.store.getCloseManifest(context.Background(), fixture.close.EventID, 0)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Refs = append([]sessionControlCloseTaskRef(nil), manifest.Refs...)
		manifest.Refs[0].CreationDigest = strings.Repeat("0", 64)
		redigestSessionControlCloseManifest(t, manifest)
		manifestRow, err := sessionControlCloseManifestToRow(*manifest)
		if err != nil {
			t.Fatal(err)
		}
		fixture.fake.setItem(marshalSessionControlSessionTestRow(t, manifestRow))
		taskSet := fixture.taskSet
		taskSet.ManifestDigests = append([]string(nil), taskSet.ManifestDigests...)
		taskSet.ManifestDigests[0] = manifest.ManifestDigest
		redigestSessionControlCloseTaskSet(t, &taskSet)
		taskSetRow, err := sessionControlCloseTaskSetToRow(taskSet)
		if err != nil {
			t.Fatal(err)
		}
		fixture.fake.setItem(marshalSessionControlSessionTestRow(t, taskSetRow))
		if _, err := fixture.store.PrepareNormalExactCloseAckChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, 0); !errors.Is(err, errSessionControlCompletionConflict) {
			t.Fatalf("mutated manifest ref error = %v", err)
		}
	})
}

func TestDynamoSessionControlPrepareAckChunkReplayAmbiguityAndAckRace(t *testing.T) {
	t.Run("exact_replay", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 1, false, false)
		chunk, err := fixture.store.PrepareNormalExactCloseAckChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, 0)
		if err != nil {
			t.Fatal(err)
		}
		transactions := len(fixture.fake.transactions)
		replay, err := fixture.store.PrepareNormalExactCloseAckChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, 0)
		if err != nil || !reflect.DeepEqual(*replay, *chunk) || len(fixture.fake.transactions) != transactions {
			t.Fatalf("chunk replay = %#v/%v txns=%d", replay, err, len(fixture.fake.transactions))
		}
	})
	t.Run("transport_committed", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 1, false, false)
		fixture.fake.transactHook = func(_ context.Context,
			input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			applySessionControlCompletionTransaction(fixture.fake, input)
			return nil, errors.New("response lost")
		}
		chunk, err := fixture.store.PrepareNormalExactCloseAckChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, 0)
		if err != nil || chunk.OwnerCount != 1 {
			t.Fatalf("chunk ambiguity = %#v/%v", chunk, err)
		}
	})
	t.Run("ack_changes_before_commit", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 1, false, false)
		fixture.fake.transactHook = func(_ context.Context,
			_ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			return nil, &types.TransactionCanceledException{}
		}
		if _, err := fixture.store.PrepareNormalExactCloseAckChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, 0); !errors.Is(err, errSessionControlCompletionConflict) {
			t.Fatalf("ACK race error = %v", err)
		}
	})
	t.Run("cancellation_uses_aggregate_budget", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 1, false, false)
		fixture.store.operationTimeout = 30 * time.Millisecond
		fixture.fake.transactHook = func(ctx context.Context,
			_ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			<-ctx.Done()
			return nil, &types.TransactionCanceledException{}
		}
		started := time.Now()
		_, err := fixture.store.PrepareNormalExactCloseAckChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, 0)
		if !errors.Is(err, errSessionControlCompletionConflict) || time.Since(started) > 100*time.Millisecond {
			t.Fatalf("chunk cancellation = %v after %v", err, time.Since(started))
		}
	})
}

func TestDynamoSessionControlCompleteRequiresEveryExactChunkAndConvergedFence(t *testing.T) {
	t.Run("missing_chunk", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 49, true, true)
		fixture.fake.mu.Lock()
		delete(fixture.fake.items, sessionControlSessionDynamoMapKey(sessionControlCloseAckChunkKey(fixture.close.EventID, 1)))
		fixture.fake.mu.Unlock()
		if _, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID, 0); !errors.Is(err, errSessionControlCompletionNotFound) {
			t.Fatalf("missing chunk error = %v", err)
		}
	})
	t.Run("mutated_chunk", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 1, true, true)
		key := sessionControlSessionDynamoMapKey(sessionControlCloseAckChunkKey(fixture.close.EventID, 0))
		fixture.fake.mu.Lock()
		fixture.fake.items[key]["source_count"] = &types.AttributeValueMemberN{Value: "2"}
		fixture.fake.mu.Unlock()
		if _, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID, 0); err == nil {
			t.Fatal("mutated chunk was accepted")
		}
	})
	t.Run("preparing_fence", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 1, true, false)
		if _, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID, 0); !errors.Is(err, errSessionControlCompletionConflict) {
			t.Fatalf("preparing fence error = %v", err)
		}
	})
}

func TestDynamoSessionControlCompleteRetentionReplayAndHistoricalFenceDrift(t *testing.T) {
	fixture := newSessionControlCompletionFixture(t, 1, true, true)
	complete, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID, fixture.fence.ReplayNotBeforeMillis-1)
	if err != nil {
		t.Fatal(err)
	}
	if complete.RetainUntilMillis < complete.CompletedAtMillis+sessionControlFenceReplayHorizon.Milliseconds() ||
		complete.RetainUntilMillis < fixture.fence.ReplayNotBeforeMillis {
		t.Fatalf("completion retention = %#v", complete)
	}
	// Exact historical replay is independent of later directory/fence state.
	fixture.fake.mu.Lock()
	directoryKey := sessionControlSessionDynamoMapKey(sessionControlFenceDirectoryKey(fixture.candidate.CellID))
	fixture.fake.items[directoryKey]["version"] = &types.AttributeValueMemberN{Value: fmt.Sprint(fixture.directory.Version + 100)}
	fixture.fake.mu.Unlock()
	replay, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID, complete.RetainUntilMillis)
	if err != nil || !reflect.DeepEqual(*replay, *complete) {
		t.Fatalf("historical replay = %#v/%v", replay, err)
	}
	stronger := complete.RetainUntilMillis + 60_000
	extended, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID, stronger)
	if err != nil || extended.RetainUntilMillis != stronger || extended.CompleteDigest == complete.CompleteDigest {
		t.Fatalf("retention extension = %#v/%v", extended, err)
	}
	txn := fixture.fake.transactions[len(fixture.fake.transactions)-1]
	if len(txn.TransactItems) != 2 || txn.TransactItems[0].Put == nil || txn.TransactItems[1].Update == nil ||
		len(aws.ToString(txn.ClientRequestToken)) > 36 {
		t.Fatalf("retention transaction = %#v", txn)
	}
}

func TestDynamoSessionControlCompleteAmbiguityCancellationAndFenceCAS(t *testing.T) {
	t.Run("transport_committed", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 1, true, true)
		fixture.fake.transactHook = func(_ context.Context,
			input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			applySessionControlCompletionTransaction(fixture.fake, input)
			return nil, errors.New("response lost")
		}
		complete, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID, 0)
		if err != nil || complete.OwnerCount != 1 {
			t.Fatalf("COMPLETE ambiguity = %#v/%v", complete, err)
		}
	})
	t.Run("transport_committed_then_retention_extended", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 1, true, true)
		fixture.fake.transactHook = func(_ context.Context,
			input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			applySessionControlCompletionTransaction(fixture.fake, input)
			last := input.TransactItems[len(input.TransactItems)-1]
			committed, decodeErr := sessionControlCloseCompleteFromItem(last.Put.Item, fixture.close.EventID)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			committed.RetainUntilMillis += 60_000
			committed.CompleteDigest, decodeErr = sessionControlCloseCompleteDigest(committed)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			seedSessionControlCloseComplete(t, fixture.fake, committed)
			return nil, errors.New("response lost after concurrent retention extension")
		}
		complete, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID, 0)
		if err != nil || complete.OwnerCount != 1 {
			t.Fatalf("COMPLETE extended ambiguity = %#v/%v", complete, err)
		}
	})
	t.Run("concurrent_initial_compatible_winner", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 1, true, true)
		var winnerAt int64
		fixture.fake.transactHook = func(_ context.Context,
			input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			last := input.TransactItems[len(input.TransactItems)-1]
			winner, decodeErr := sessionControlCloseCompleteFromItem(last.Put.Item, fixture.close.EventID)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			winner.CompletedAtMillis++
			winner.RetainUntilMillis++
			winnerAt = winner.CompletedAtMillis
			winner.CompleteDigest, decodeErr = sessionControlCloseCompleteDigest(winner)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			seedSessionControlCloseComplete(t, fixture.fake, winner)
			return nil, &types.TransactionCanceledException{}
		}
		complete, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID, 0)
		if err != nil || complete.CompletedAtMillis != winnerAt {
			t.Fatalf("compatible concurrent COMPLETE = %#v/%v", complete, err)
		}
		replay, replayErr := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID, complete.RetainUntilMillis)
		if replayErr != nil || !reflect.DeepEqual(*replay, *complete) {
			t.Fatalf("compatible historical replay = %#v/%v", replay, replayErr)
		}
	})
	t.Run("retention_extension_response_lost_then_extended_again", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 1, true, true)
		complete, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID, 0)
		if err != nil {
			t.Fatal(err)
		}
		requested := complete.RetainUntilMillis + 60_000
		var winnerRetain int64
		fixture.fake.transactHook = func(_ context.Context,
			input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			applySessionControlCompletionTransaction(fixture.fake, input)
			next, decodeErr := sessionControlCloseCompleteFromItem(input.TransactItems[0].Put.Item,
				fixture.close.EventID)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			next.RetainUntilMillis += 60_000
			winnerRetain = next.RetainUntilMillis
			next.CompleteDigest, decodeErr = sessionControlCloseCompleteDigest(next)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			seedSessionControlCloseComplete(t, fixture.fake, next)
			return nil, errors.New("extension response lost after later extension")
		}
		extended, extendErr := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID, requested)
		if extendErr != nil || extended.RetainUntilMillis != winnerRetain || winnerRetain <= requested {
			t.Fatalf("monotonic extension ambiguity = %#v/%v", extended, extendErr)
		}
	})
	t.Run("cancellation_uses_aggregate_budget", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 1, true, true)
		fixture.store.operationTimeout = 30 * time.Millisecond
		fixture.fake.transactHook = func(ctx context.Context,
			_ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			<-ctx.Done()
			return nil, &types.TransactionCanceledException{}
		}
		started := time.Now()
		_, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID, 0)
		if !errors.Is(err, errSessionControlCompletionConflict) || time.Since(started) > 100*time.Millisecond {
			t.Fatalf("COMPLETE cancellation = %v after %v", err, time.Since(started))
		}
	})
	t.Run("directory_changes_before_commit", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 1, true, true)
		fixture.fake.transactHook = func(_ context.Context,
			_ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			fixture.fake.mu.Lock()
			key := sessionControlSessionDynamoMapKey(sessionControlFenceDirectoryKey(fixture.candidate.CellID))
			fixture.fake.items[key]["version"] = &types.AttributeValueMemberN{Value: fmt.Sprint(fixture.directory.Version + 1)}
			fixture.fake.mu.Unlock()
			return nil, &types.TransactionCanceledException{}
		}
		if _, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID, 0); !errors.Is(err, errSessionControlCompletionConflict) {
			t.Fatalf("directory CAS error = %v", err)
		}
	})
}

func TestDynamoSessionControlCompleteClassifierPreservesImmutableAuthority(t *testing.T) {
	fixture := newSessionControlCompletionFixture(t, 1, true, true)
	desired, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*sessionControlCloseComplete)
	}{
		{name: "selector", mutate: func(v *sessionControlCloseComplete) { v.SelectorDigest = strings.Repeat("0", 64) }},
		{name: "session", mutate: func(v *sessionControlCloseComplete) { v.SessionVersion++ }},
		{name: "taskset", mutate: func(v *sessionControlCloseComplete) { v.TaskSetDigest = strings.Repeat("0", 64) }},
		{name: "fence", mutate: func(v *sessionControlCloseComplete) { v.FenceVersion++ }},
		{name: "completion", mutate: func(v *sessionControlCloseComplete) { v.AckClosedTotal++ }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			current := *desired
			current.ManifestDigests = append([]string(nil), desired.ManifestDigests...)
			current.ChunkDigests = append([]string(nil), desired.ChunkDigests...)
			current.ChunkSourceCounts = append([]uint64(nil), desired.ChunkSourceCounts...)
			current.ChunkOwnerCounts = append([]uint64(nil), desired.ChunkOwnerCounts...)
			tt.mutate(&current)
			current.CompleteDigest, err = sessionControlCloseCompleteDigest(current)
			if err != nil {
				t.Fatal(err)
			}
			// Some authority mutations are impossible rows; classify must fail
			// closed whether decoding or semantic comparison rejects them.
			row, rowErr := sessionControlCloseCompleteToRow(current)
			if rowErr == nil {
				fixture.fake.setItem(marshalSessionControlSessionTestRow(t, row))
			} else {
				item, marshalErr := attributevalue.MarshalMap(sessionControlCloseCompleteRow{
					PK: sessionControlFenceMetaPK(current.EventID), SK: sessionControlCloseCompleteSK,
					Kind: sessionControlCloseCompleteKind, SchemaVersion: sessionControlCloseCompleteSchema,
					CellID: current.CellID, EventID: current.EventID, SelectorDigest: current.SelectorDigest,
					AgentPublicKey: current.AgentPublicKey, SessionID: current.SessionID,
					SessionIssuedMillis: current.SessionIssuedMillis, SessionVersion: current.SessionVersion,
					ExpectedTargetCount:      current.ExpectedTargetCount,
					PreparedDirectoryVersion: current.PreparedDirectoryVersion, WorkMode: current.WorkMode,
					TaskSetDigest: current.TaskSetDigest, SourceCount: current.SourceCount, OwnerCount: current.OwnerCount,
					AckClosedTotal: current.AckClosedTotal, ManifestDigests: current.ManifestDigests,
					ChunkDigests: current.ChunkDigests, ChunkSourceCounts: current.ChunkSourceCounts,
					ChunkOwnerCounts: current.ChunkOwnerCounts, FenceVersion: current.FenceVersion,
					CompletedDirectoryVersion:  current.CompletedDirectoryVersion,
					FenceReplayNotBeforeMillis: current.FenceReplayNotBeforeMillis,
					CompletedAtMillis:          current.CompletedAtMillis, RetainUntilMillis: current.RetainUntilMillis,
					CompleteDigest: current.CompleteDigest,
				})
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				fixture.fake.setItem(item)
			}
			if _, classifyErr := fixture.store.classifyCloseComplete(context.Background(), fixture.close.EventID,
				*desired); classifyErr == nil {
				t.Fatal("authority drift was accepted")
			}
		})
	}
}

func TestSessionControlCompletionRowsStrictPresenceDigestParityAndNoTTL(t *testing.T) {
	fixture := newSessionControlCompletionFixture(t, 1, true, true)
	chunk := fixture.chunks[0]
	row, err := sessionControlCloseAckChunkToRow(chunk)
	if err != nil {
		t.Fatal(err)
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest_index", "source_count", "owner_count", "ack_closed_total", "created_at_ms"} {
		copy := cloneSessionControlCompletionItem(item)
		delete(copy, name)
		if _, decodeErr := sessionControlCloseAckChunkFromItem(copy, chunk.EventID, chunk.ManifestIndex); !errors.Is(decodeErr, errSessionControlCompletionCorrupt) {
			t.Fatalf("missing chunk %s error = %v", name, decodeErr)
		}
	}
	mutated := chunk
	mutated.Refs = append([]sessionControlCloseAckRef(nil), chunk.Refs...)
	mutated.AckClosedTotal++
	mutated.ChunkDigest, err = sessionControlCloseAckChunkDigest(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if validateSessionControlCloseAckChunk(mutated) == nil {
		t.Fatal("chunk sum mutation accepted")
	}
	wrongSelector := chunk
	wrongSelector.Refs = append([]sessionControlCloseAckRef(nil), chunk.Refs...)
	wrongSelector.Refs[0].AckSelectorDigest = strings.Repeat("0", 64)
	wrongSelector.ChunkDigest, err = sessionControlCloseAckChunkDigest(wrongSelector)
	if err != nil || validateSessionControlCloseAckChunk(wrongSelector) == nil {
		t.Fatalf("redigested ACK selector mismatch accepted: %v", err)
	}
	ceilingTask := chunk
	ceilingTask.Refs = append([]sessionControlCloseAckRef(nil), chunk.Refs...)
	ceilingTask.Refs[0].TaskVersion = math.MaxUint64 - 1
	ceilingTask.ChunkDigest, err = sessionControlCloseAckChunkDigest(ceilingTask)
	if err != nil || validateSessionControlCloseAckChunk(ceilingTask) == nil {
		t.Fatalf("redigested ACK task-version ceiling accepted: %v", err)
	}
	item["ttl"] = &types.AttributeValueMemberN{Value: "1"}
	if _, decodeErr := sessionControlCloseAckChunkFromItem(item, chunk.EventID, chunk.ManifestIndex); !errors.Is(decodeErr, errSessionControlCompletionCorrupt) {
		t.Fatalf("chunk TTL error = %v", decodeErr)
	}
	zeroClosed := chunk
	zeroClosed.Refs = append([]sessionControlCloseAckRef(nil), chunk.Refs...)
	zeroClosed.AckClosedTotal -= zeroClosed.Refs[0].AckClosed
	zeroClosed.Refs[0].AckClosed = 0
	zeroClosed.ChunkDigest, err = sessionControlCloseAckChunkDigest(zeroClosed)
	if err != nil || validateSessionControlCloseAckChunk(zeroClosed) != nil {
		t.Fatalf("zero-closed chunk = %#v/%v", zeroClosed, err)
	}
	zeroRow, err := sessionControlCloseAckChunkToRow(zeroClosed)
	if err != nil {
		t.Fatal(err)
	}
	zeroItem, err := attributevalue.MarshalMap(zeroRow)
	if err != nil {
		t.Fatal(err)
	}
	list := zeroItem["ack_refs"].(*types.AttributeValueMemberL)
	delete(list.Value[0].(*types.AttributeValueMemberM).Value, "ack_closed")
	if _, decodeErr := sessionControlCloseAckChunkFromItem(zeroItem, zeroClosed.EventID, zeroClosed.ManifestIndex); !errors.Is(decodeErr, errSessionControlCompletionCorrupt) {
		t.Fatalf("missing nested zero ack_closed error = %v", decodeErr)
	}

	complete, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	completeRow, err := sessionControlCloseCompleteToRow(*complete)
	if err != nil {
		t.Fatal(err)
	}
	completeItem, err := attributevalue.MarshalMap(completeRow)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"expected_target_count", "source_count", "owner_count", "ack_closed_total",
		"completed_directory_version", "completed_at_ms", "retain_until_ms"} {
		copy := cloneSessionControlCompletionItem(completeItem)
		delete(copy, name)
		if _, decodeErr := sessionControlCloseCompleteFromItem(copy, complete.EventID); !errors.Is(decodeErr, errSessionControlCompletionCorrupt) {
			t.Fatalf("missing COMPLETE %s error = %v", name, decodeErr)
		}
	}
	completeMutation := *complete
	completeMutation.ChunkSourceCounts = append([]uint64(nil), complete.ChunkSourceCounts...)
	completeMutation.ChunkSourceCounts[0]++
	completeMutation.CompleteDigest, err = sessionControlCloseCompleteDigest(completeMutation)
	if err != nil {
		t.Fatal(err)
	}
	if validateSessionControlCloseComplete(completeMutation) == nil {
		t.Fatal("COMPLETE sum mutation accepted")
	}

	zeroFixture := newSessionControlCompletionFixture(t, 0, true, true)
	zeroComplete, err := zeroFixture.store.CompleteNormalExactClose(context.Background(), zeroFixture.candidate,
		zeroFixture.close.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	zeroCompleteRow, err := sessionControlCloseCompleteToRow(*zeroComplete)
	if err != nil {
		t.Fatal(err)
	}
	zeroCompleteItem, err := attributevalue.MarshalMap(zeroCompleteRow)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest_digests", "chunk_digests", "chunk_source_counts", "chunk_owner_counts"} {
		copy := cloneSessionControlCompletionItem(zeroCompleteItem)
		delete(copy, name)
		if _, decodeErr := sessionControlCloseCompleteFromItem(copy, zeroComplete.EventID); !errors.Is(decodeErr, errSessionControlCompletionCorrupt) {
			t.Fatalf("missing zero-target COMPLETE %s error = %v", name, decodeErr)
		}
	}
}

func cloneSessionControlCompletionItem(item map[string]types.AttributeValue) map[string]types.AttributeValue {
	copy := make(map[string]types.AttributeValue, len(item))
	for key, value := range item {
		copy[key] = value
	}
	return copy
}

func TestSessionControlCloseCompleteRetentionCeiling(t *testing.T) {
	if _, err := sessionControlCloseCompleteRetention(math.MaxInt64-sessionControlFenceReplayHorizon.Milliseconds()+1,
		0, 0, 0); !errors.Is(err, errSessionControlCompletionCorrupt) {
		t.Fatalf("retention ceiling error = %v", err)
	}
}

func TestDynamoSessionControlCompleteClampsChronologyToLatestAckChunk(t *testing.T) {
	fixture := newSessionControlCompletionFixture(t, 1, true, true)
	chunk := fixture.chunks[0]
	chunk.CreatedAtMillis = fixture.fence.UpdatedAtMillis + 10_000
	chunk.ChunkDigest, _ = sessionControlCloseAckChunkDigest(chunk)
	row, err := sessionControlCloseAckChunkToRow(chunk)
	if err != nil {
		t.Fatal(err)
	}
	fixture.fake.setItem(marshalSessionControlSessionTestRow(t, row))
	complete, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
		fixture.close.EventID, 0)
	if err != nil || complete.CompletedAtMillis != chunk.CreatedAtMillis ||
		complete.RetainUntilMillis < chunk.CreatedAtMillis+sessionControlFenceReplayHorizon.Milliseconds() {
		t.Fatalf("chunk chronology completion = %#v/%v", complete, err)
	}
}

func TestSessionControlCompletionTransactionTokensBindEveryAuthorityInput(t *testing.T) {
	t.Run("ack_chunk", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 1, false, false)
		chunk, err := fixture.store.PrepareNormalExactCloseAckChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, 0)
		if err != nil {
			t.Fatal(err)
		}
		session, err := fixture.store.classifyReservation(context.Background(), fixture.candidate)
		if err != nil {
			t.Fatal(err)
		}
		work, err := fixture.store.getCloseWork(context.Background(), fixture.candidate.CellID, fixture.close.EventID, false)
		if err != nil {
			t.Fatal(err)
		}
		taskSet, err := fixture.store.getCloseTaskSet(context.Background(), fixture.close.EventID)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := fixture.store.getCloseManifest(context.Background(), fixture.close.EventID, 0)
		if err != nil {
			t.Fatal(err)
		}
		task, err := fixture.store.getCloseTask(context.Background(), manifest.Refs[0].OwnerPK, fixture.close.EventID)
		if err != nil {
			t.Fatal(err)
		}
		base, err := sessionControlCloseAckChunkToken(fixture.store.tableName, *session, *work, *taskSet,
			*manifest, []sessionControlCloseTask{*task}, nil, *chunk)
		if err != nil || aws.ToString(base) != aws.ToString(fixture.fake.transactions[len(fixture.fake.transactions)-1].ClientRequestToken) {
			t.Fatalf("ACK chunk token = %q/%v", aws.ToString(base), err)
		}
		mutatedSession := *session
		mutatedSession.Version++
		mutatedWork := *work
		mutatedWork.UpdatedAtMillis++
		mutatedTaskSet := *taskSet
		mutatedTaskSet.TaskSetDigest = strings.Repeat("0", 64)
		mutatedManifest := *manifest
		mutatedManifest.ManifestDigest = strings.Repeat("0", 64)
		mutatedTask := *task
		mutatedTask.TaskVersion++
		mutatedChunk := *chunk
		mutatedChunk.ChunkDigest = strings.Repeat("0", 64)
		cases := []struct {
			name     string
			table    string
			session  sessionControlSessionAuthority
			work     sessionControlCloseWork
			taskSet  sessionControlCloseTaskSet
			manifest sessionControlCloseManifest
			tasks    []sessionControlCloseTask
			chunk    sessionControlCloseAckChunk
		}{
			{name: "table", table: fixture.store.tableName + "-other", session: *session, work: *work, taskSet: *taskSet, manifest: *manifest, tasks: []sessionControlCloseTask{*task}, chunk: *chunk},
			{name: "session", table: fixture.store.tableName, session: mutatedSession, work: *work, taskSet: *taskSet, manifest: *manifest, tasks: []sessionControlCloseTask{*task}, chunk: *chunk},
			{name: "work", table: fixture.store.tableName, session: *session, work: mutatedWork, taskSet: *taskSet, manifest: *manifest, tasks: []sessionControlCloseTask{*task}, chunk: *chunk},
			{name: "taskset", table: fixture.store.tableName, session: *session, work: *work, taskSet: mutatedTaskSet, manifest: *manifest, tasks: []sessionControlCloseTask{*task}, chunk: *chunk},
			{name: "manifest", table: fixture.store.tableName, session: *session, work: *work, taskSet: *taskSet, manifest: mutatedManifest, tasks: []sessionControlCloseTask{*task}, chunk: *chunk},
			{name: "task", table: fixture.store.tableName, session: *session, work: *work, taskSet: *taskSet, manifest: *manifest, tasks: []sessionControlCloseTask{mutatedTask}, chunk: *chunk},
			{name: "chunk", table: fixture.store.tableName, session: *session, work: *work, taskSet: *taskSet, manifest: *manifest, tasks: []sessionControlCloseTask{*task}, chunk: mutatedChunk},
		}
		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				token, tokenErr := sessionControlCloseAckChunkToken(tt.table, tt.session, tt.work, tt.taskSet,
					tt.manifest, tt.tasks, nil, tt.chunk)
				if tokenErr != nil || aws.ToString(token) == aws.ToString(base) || len(aws.ToString(token)) > 36 {
					t.Fatalf("mutated token = %q/%v", aws.ToString(token), tokenErr)
				}
			})
		}
	})

	t.Run("complete", func(t *testing.T) {
		fixture := newSessionControlCompletionFixture(t, 1, true, true)
		complete, err := fixture.store.CompleteNormalExactClose(context.Background(), fixture.candidate,
			fixture.close.EventID, 0)
		if err != nil {
			t.Fatal(err)
		}
		nextWork := fixture.close.Work
		nextWork.State = sessionControlCloseWorkStateCompleted
		nextWork.UpdatedAtMillis = complete.CompletedAtMillis
		nextWork.DueAtMillis = 0
		nextWork.CompletedAtMillis = complete.CompletedAtMillis
		values := []any{fixture.directory, fixture.close.Session, fixture.close.Work, nextWork, fixture.fence,
			fixture.taskSet, fixture.chunks, *complete}
		base, err := sessionControlCloseCompletionToken(fixture.store.tableName, "complete", values...)
		if err != nil || aws.ToString(base) != aws.ToString(fixture.fake.transactions[len(fixture.fake.transactions)-1].ClientRequestToken) {
			t.Fatalf("COMPLETE token = %q/%v", aws.ToString(base), err)
		}
		for index := range values {
			t.Run(fmt.Sprintf("authority_%d", index), func(t *testing.T) {
				mutated := append([]any(nil), values...)
				mutated[index] = struct {
					Index uint64
					Value any
				}{uint64(index), values[index]}
				token, tokenErr := sessionControlCloseCompletionToken(fixture.store.tableName, "complete", mutated...)
				if tokenErr != nil || aws.ToString(token) == aws.ToString(base) || len(aws.ToString(token)) > 36 {
					t.Fatalf("mutated token = %q/%v", aws.ToString(token), tokenErr)
				}
			})
		}
		for _, tt := range []struct {
			name, table, action string
		}{
			{name: "table", table: fixture.store.tableName + "-other", action: "complete"},
			{name: "action", table: fixture.store.tableName, action: "retain"},
		} {
			t.Run(tt.name, func(t *testing.T) {
				token, tokenErr := sessionControlCloseCompletionToken(tt.table, tt.action, values...)
				if tokenErr != nil || aws.ToString(token) == aws.ToString(base) || len(aws.ToString(token)) > 36 {
					t.Fatalf("mutated token = %q/%v", aws.ToString(token), tokenErr)
				}
			})
		}
	})
}
