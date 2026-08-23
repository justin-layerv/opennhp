package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestDynamoSessionControlDueReservedSessionDiscoveryUsesStrongBaseAuthority(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0xa1, 1001)
	reserved, err := planSessionControlReservation(candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionControlReservation(t, fake, reserved)
	fake.queryHook = func(_ context.Context, input *dynamodb.QueryInput, _ int) (*dynamodb.QueryOutput, error) {
		if aws.ToString(input.IndexName) != sessionControlDueIndexName || aws.ToBool(input.ConsistentRead) ||
			aws.ToString(input.KeyConditionExpression) != "due_shard = :shard AND due_sort <= :through" {
			t.Fatalf("due session query = %#v", input)
		}
		return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{{
			"pk": &types.AttributeValueMemberS{Value: sessionControlSessionPK(candidate.SessionID)},
			"sk": &types.AttributeValueMemberS{Value: sessionControlSessionMetaSK},
		}}}, nil
	}
	page, err := store.ListDueReservedSessionsPage(context.Background(), candidate.CellID,
		candidate.SessionID%sessionControlSessionDueShardCount, candidate.ReservationDeadlineMillis, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Sessions) != 1 || page.Sessions[0] != reserved || page.Next != nil {
		t.Fatalf("due session page = %#v", page)
	}
	// One base read plus the SESSION/membership/SESSION classification bracket
	// proves the GSI projection was never accepted as authority.
	if len(fake.gets) != 4 {
		t.Fatalf("strong due-session reads = %d, want 4", len(fake.gets))
	}
}

func TestDynamoSessionControlDueReservedSessionDiscoveryIgnoresStaleTransitionProjection(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	candidate := testSessionControlSessionCandidate(0xa2, 1002)
	authority, err := planSessionControlReservation(candidate, testSessionControlSessionSnapshot(1))
	if err != nil {
		t.Fatal(err)
	}
	authority.TargetCount = 1
	authority.Version = 2
	authority.SessionExpiresAtMillis = candidate.IssuedAtMillis + 60_000
	authority.RetainUntilMillis = candidate.IssuedAtMillis + 65_000
	authority.State = sessionControlSessionStateAckEnqueued
	authority.AckEnqueuedAtMillis = candidate.IssuedAtMillis + 1_000
	seedSessionControlReservation(t, fake, authority)
	fake.queryHook = func(context.Context, *dynamodb.QueryInput, int) (*dynamodb.QueryOutput, error) {
		return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{{
			"pk": &types.AttributeValueMemberS{Value: sessionControlSessionPK(candidate.SessionID)},
			"sk": &types.AttributeValueMemberS{Value: sessionControlSessionMetaSK},
		}}}, nil
	}
	page, err := store.ListDueReservedSessionsPage(context.Background(), candidate.CellID,
		candidate.SessionID%sessionControlSessionDueShardCount, candidate.ReservationDeadlineMillis, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Sessions) != 0 {
		t.Fatalf("stale transitioned GSI hit returned sessions: %#v", page.Sessions)
	}
}

func TestDynamoSessionControlDueReservedSessionDiscoveryPreservesOperationalErrors(t *testing.T) {
	sentinel := errors.New("due index unavailable")
	fake := newSessionControlSessionDynamoFake()
	fake.queryHook = func(context.Context, *dynamodb.QueryInput, int) (*dynamodb.QueryOutput, error) {
		return nil, sentinel
	}
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	_, err := store.ListDueReservedSessionsPage(context.Background(), testSessionControlCellID, 0,
		time.Now().UnixMilli(), nil, 100)
	if !errors.Is(err, sentinel) || errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("due discovery transport error = %v", err)
	}
}

func TestDynamoSessionControlDueClosingSessionDiscoverySurvivesEveryClosePhase(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	candidate := testSessionControlSessionCandidate(0xa4, 1004)
	reserved, err := planSessionControlReservation(candidate, testSessionControlSessionSnapshot(2))
	if err != nil {
		t.Fatal(err)
	}
	directory := sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(3),
		candidate.ReservationDeadlineMillis)
	closing := expectedSessionControlExactClose(t, reserved, directory,
		candidate.ReservationDeadlineMillis+1, reserved.RetainUntilMillis).Session
	seedSessionControlReservation(t, fake, closing)
	var queriedShards []string
	fake.queryHook = func(_ context.Context, input *dynamodb.QueryInput, _ int) (*dynamodb.QueryOutput, error) {
		queriedShards = append(queriedShards,
			input.ExpressionAttributeValues[":shard"].(*types.AttributeValueMemberS).Value)
		return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{{
			"pk": &types.AttributeValueMemberS{Value: sessionControlSessionPK(candidate.SessionID)},
			"sk": &types.AttributeValueMemberS{Value: sessionControlSessionMetaSK},
		}}}, nil
	}
	page, err := store.ListDueClosingSessionsPage(context.Background(), candidate.CellID,
		candidate.SessionID%sessionControlSessionDueShardCount, closing.ClosePreparedAtMillis, nil, 100)
	if err != nil || len(page.Sessions) != 1 || page.Sessions[0] != closing {
		t.Fatalf("closing due page = %#v, %v", page, err)
	}
	reservedPage, err := store.ListDueReservedSessionsPage(context.Background(), candidate.CellID,
		candidate.SessionID%sessionControlSessionDueShardCount, closing.ClosePreparedAtMillis, nil, 100)
	if err != nil || len(reservedPage.Sessions) != 0 {
		t.Fatalf("closing row leaked into reserved page = %#v, %v", reservedPage, err)
	}
	if len(queriedShards) != 2 || queriedShards[0] != sessionControlClosingSessionDueShard(candidate) ||
		queriedShards[1] != sessionControlSessionDueShard(candidate) || queriedShards[0] == queriedShards[1] {
		t.Fatalf("state-separated due shards = %#v", queriedShards)
	}
}

func TestDynamoSessionControlClosingSessionRequiresCanonicalDueAuthority(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	candidate := testSessionControlSessionCandidate(0xa5, 1005)
	reserved, err := planSessionControlReservation(candidate, testSessionControlSessionSnapshot(2))
	if err != nil {
		t.Fatal(err)
	}
	closing := expectedSessionControlExactClose(t, reserved,
		sessionControlCloseTestDirectory(testSessionControlSessionSnapshot(3), candidate.ReservationDeadlineMillis),
		candidate.ReservationDeadlineMillis+1, reserved.RetainUntilMillis).Session
	row, err := sessionControlSessionToRow(closing)
	if err != nil {
		t.Fatal(err)
	}
	item := marshalSessionControlSessionTestRow(t, row)
	delete(item, "due_sort")
	fake.setItem(item)
	if _, err = store.getSessionItem(context.Background(), candidate.SessionID); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("closing row without due authority error = %v", err)
	}
}

func TestDynamoSessionControlDueReservedSessionCursorIsCanonicalAndAdvances(t *testing.T) {
	candidate := testSessionControlSessionCandidate(0xa3, 1003)
	shard := candidate.SessionID % sessionControlSessionDueShardCount
	dueShard := sessionControlSessionDueShard(candidate)
	canonical := map[string]types.AttributeValue{
		"pk":        &types.AttributeValueMemberS{Value: sessionControlSessionPK(candidate.SessionID)},
		"sk":        &types.AttributeValueMemberS{Value: sessionControlSessionMetaSK},
		"due_shard": &types.AttributeValueMemberS{Value: dueShard},
		"due_sort":  &types.AttributeValueMemberS{Value: sessionControlSessionDueSort(candidate)},
	}

	t.Run("malformed-input", func(t *testing.T) {
		store := newSessionControlSessionDynamoStore(newSessionControlSessionDynamoFake(), time.Second)
		bad := map[string]types.AttributeValue{}
		for key, value := range canonical {
			bad[key] = value
		}
		delete(bad, "due_sort")
		_, err := store.ListDueReservedSessionsPage(context.Background(), candidate.CellID, shard,
			candidate.ReservationDeadlineMillis, &sessionControlDueSessionCursor{CellID: candidate.CellID,
				Shard: shard, DueThroughMillis: candidate.ReservationDeadlineMillis,
				State: sessionControlSessionStateReserved, LastEvaluatedKey: bad}, 1)
		if err == nil {
			t.Fatal("malformed due cursor was accepted")
		}
	})

	t.Run("repeated-output", func(t *testing.T) {
		fake := newSessionControlSessionDynamoFake()
		fake.queryHook = func(context.Context, *dynamodb.QueryInput, int) (*dynamodb.QueryOutput, error) {
			return &dynamodb.QueryOutput{LastEvaluatedKey: canonical}, nil
		}
		store := newSessionControlSessionDynamoStore(fake, time.Second)
		_, err := store.ListDueReservedSessionsPage(context.Background(), candidate.CellID, shard,
			candidate.ReservationDeadlineMillis, &sessionControlDueSessionCursor{CellID: candidate.CellID,
				Shard: shard, DueThroughMillis: candidate.ReservationDeadlineMillis,
				State: sessionControlSessionStateReserved, LastEvaluatedKey: canonical}, 1)
		if !errors.Is(err, errSessionControlSessionCorrupt) {
			t.Fatalf("repeated due cursor error = %v, want corrupt", err)
		}
	})
}
