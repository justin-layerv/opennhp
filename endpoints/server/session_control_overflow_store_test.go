package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestDynamoSessionControlOverflowLeaderSelectionIsStableAndCapacityIndependent(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	directory := sessionControlFenceDirectory{
		CellID: "cell-01", Version: 20, ActiveFenceCount: sessionControlFenceActiveLimit,
		AdmissionBlocked: true, OverflowCloseCount: 2,
		CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_100,
	}
	first := makeOverflowCloseWork(t, directory.CellID, 9, 19)
	smaller := makeOverflowCloseWork(t, directory.CellID, 0, 18)
	seedSessionControlCloseDirectory(t, fake, directory)
	seedSessionControlCloseWork(t, fake, first)
	seedSessionControlCloseWork(t, fake, smaller)

	selected, err := store.SelectOldestOverflowCloseLeader(context.Background(), directory.CellID)
	if err != nil {
		t.Fatal(err)
	}
	if selected.Directory.Version != directory.Version+1 ||
		selected.Directory.OverflowLeaderEventID != smaller.EventID || selected.Work != smaller ||
		selected.Directory.OverflowLeaderPreparedDirectoryVersion != smaller.PreparedDirectoryVersion ||
		selected.Directory.OverflowLeaderSelectedDirectoryVersion != selected.Directory.Version {
		t.Fatalf("selected leader = %#v", selected)
	}
	if len(fake.transactions) != 1 || len(fake.transactions[0].TransactItems) != 3 ||
		len(aws.ToString(fake.transactions[0].ClientRequestToken)) > 36 {
		t.Fatalf("leader transaction = %#v", fake.transactions)
	}
	update := fake.transactions[0].TransactItems[0].Update
	order := fake.transactions[0].TransactItems[1].ConditionCheck
	header := fake.transactions[0].TransactItems[2].ConditionCheck
	if update == nil || order == nil || header == nil || strings.Contains(aws.ToString(update.ConditionExpression), "active_fence_count <") ||
		!strings.Contains(aws.ToString(update.ConditionExpression), "overflow_leader_event_id = :overflow_leader_event_id") ||
		!strings.Contains(aws.ToString(header.ConditionExpression), "attribute_not_exists(#ttl)") || header.ExpressionAttributeNames["#ttl"] != "ttl" {
		t.Fatalf("leader members = %#v", fake.transactions[0].TransactItems)
	}

	seedSessionControlCloseDirectory(t, fake, selected.Directory)
	replayed, err := store.SelectOldestOverflowCloseLeader(context.Background(), directory.CellID)
	if err != nil || replayed.Directory != selected.Directory || replayed.Work != smaller || len(fake.transactions) != 1 {
		t.Fatalf("leader replay = %#v, %v; transactions=%d", replayed, err, len(fake.transactions))
	}

	// A later close can have a lexically smaller event ID, but its strictly
	// higher prepared-directory cursor keeps it behind the durable leader.
	newer := makeOverflowCloseWork(t, directory.CellID, 15, selected.Directory.Version+1)
	newer.EventID = strings.Repeat("0", 32)
	newer.CreatedAtMillis = smaller.CreatedAtMillis - 1
	newer.UpdatedAtMillis, newer.DueAtMillis = newer.CreatedAtMillis, newer.CreatedAtMillis
	seedSessionControlCloseWork(t, fake, newer)
	advanced := selected.Directory
	advanced.Version++
	advanced.OverflowCloseCount++
	advanced.UpdatedAtMillis++
	seedSessionControlCloseDirectory(t, fake, advanced)
	replayed, err = store.SelectOldestOverflowCloseLeader(context.Background(), directory.CellID)
	if err != nil || replayed.Directory != advanced || replayed.Work != smaller || len(fake.transactions) != 1 {
		t.Fatalf("later smaller event preempted leader = %#v, %v; transactions=%d", replayed, err,
			len(fake.transactions))
	}
}

func TestDynamoSessionControlOverflowLeaderPreservesStrongQueryError(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	directory := sessionControlFenceDirectory{CellID: "cell-01", Version: 20, AdmissionBlocked: true,
		OverflowCloseCount: 1, CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_100}
	seedSessionControlCloseDirectory(t, fake, directory)
	sentinel := errors.New("overflow ORDER query unavailable")
	fake.queryHook = func(context.Context, *dynamodb.QueryInput, int) (*dynamodb.QueryOutput, error) {
		return nil, sentinel
	}
	if _, err := store.SelectOldestOverflowCloseLeader(context.Background(), directory.CellID); !errors.Is(err, sentinel) {
		t.Fatalf("leader query error = %v", err)
	}
}

func TestSessionControlDirectoryMutationsBindOverflowLeader(t *testing.T) {
	directory := sessionControlFenceDirectory{
		CellID: "cell-01", Version: 21, ActiveFenceCount: 2, AdmissionBlocked: true, OverflowCloseCount: 1,
		OverflowLeaderEventID:                  "00000000000000000000000000000001",
		OverflowLeaderPreparedDirectoryVersion: 19, OverflowLeaderSelectedDirectoryVersion: 20,
		CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_100,
	}
	if err := validateSessionControlFenceDirectory(directory); err != nil {
		t.Fatal(err)
	}
	condition := sessionControlFenceDirectoryCondition()
	for _, fragment := range []string{
		"overflow_leader_event_id = :overflow_leader_event_id",
		"overflow_leader_prepared_directory_version = :overflow_leader_prepared_version",
		"overflow_leader_selected_directory_version = :overflow_leader_selected_version",
		"attribute_not_exists(#ttl)",
	} {
		if !strings.Contains(condition, fragment) {
			t.Fatalf("directory condition lacks %q: %s", fragment, condition)
		}
	}
	values := sessionControlFenceDirectoryConditionValues(directory)
	if got := values[":overflow_leader_event_id"].(*types.AttributeValueMemberS).Value; got != directory.OverflowLeaderEventID {
		t.Fatalf("leader condition value = %q", got)
	}
	snapshot := sessionControlFenceSnapshot{
		CellID: directory.CellID, DirectoryVersion: directory.Version,
		ActiveFenceCount: directory.ActiveFenceCount, AdmissionBlocked: directory.AdmissionBlocked,
		OverflowCloseCount: directory.OverflowCloseCount, OverflowLeaderEventID: directory.OverflowLeaderEventID,
		OverflowLeaderPreparedDirectoryVersion: directory.OverflowLeaderPreparedDirectoryVersion,
		OverflowLeaderSelectedDirectoryVersion: directory.OverflowLeaderSelectedDirectoryVersion,
	}
	if snapshot.OverflowLeaderEventID != directory.OverflowLeaderEventID ||
		snapshot.OverflowLeaderPreparedDirectoryVersion != directory.OverflowLeaderPreparedDirectoryVersion ||
		snapshot.OverflowLeaderSelectedDirectoryVersion != directory.OverflowLeaderSelectedDirectoryVersion {
		t.Fatalf("snapshot dropped leader = %#v", snapshot)
	}
}

func TestDynamoSessionControlClosePreservesSelectedOverflowLeader(t *testing.T) {
	directory := sessionControlFenceDirectory{
		CellID: "cell-01", Version: 21, ActiveFenceCount: 2, AdmissionBlocked: true, OverflowCloseCount: 1,
		OverflowLeaderEventID:                  "00000000000000000000000000000001",
		OverflowLeaderPreparedDirectoryVersion: 19, OverflowLeaderSelectedDirectoryVersion: 20,
		CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_100,
	}
	fake, store, reserved := newSessionControlExactCloseFixture(t, directory)
	got, err := store.EnsureExactSessionClose(context.Background(), reserved.Candidate, reserved.RetainUntilMillis)
	if err != nil || !got.Overflow || len(fake.transactions) != 1 {
		t.Fatalf("overflow close with leader = %#v, %v", got, err)
	}
	update := fake.transactions[0].TransactItems[0].Update
	if update == nil || strings.Contains(aws.ToString(update.UpdateExpression), "overflow_leader_") {
		t.Fatalf("close rewrote leader authority = %#v", update)
	}
	values := update.ExpressionAttributeValues
	if values[":overflow_leader_event_id"].(*types.AttributeValueMemberS).Value != directory.OverflowLeaderEventID ||
		values[":overflow_leader_prepared_version"].(*types.AttributeValueMemberN).Value != "19" ||
		values[":overflow_leader_selected_version"].(*types.AttributeValueMemberN).Value != "20" {
		t.Fatalf("close did not bind leader authority = %#v", values)
	}
}

func TestDynamoSessionControlOverflowPage101AndTornDirectory(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	const count = 101
	directory := sessionControlFenceDirectory{
		CellID: "cell-01", Version: 300, AdmissionBlocked: true, OverflowCloseCount: count,
		CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_001_000,
	}
	seedSessionControlCloseDirectory(t, fake, directory)
	for index := 0; index < count; index++ {
		seedSessionControlCloseWork(t, fake, makeOverflowCloseWork(t, directory.CellID, index, uint64(index+2)))
	}
	first, err := store.ListOverflowCloseWorkPage(context.Background(), directory.CellID, nil, 100)
	if err != nil || len(first.Work) != 100 || first.Next == nil || first.Next.Seen != 100 {
		t.Fatalf("first overflow page = %#v, %v", first, err)
	}
	last, err := store.ListOverflowCloseWorkPage(context.Background(), directory.CellID, first.Next, 100)
	if err != nil || len(last.Work) != 1 || last.Next != nil || last.Directory != directory {
		t.Fatalf("last overflow page = %#v, %v", last, err)
	}
	for _, query := range fake.queries {
		if !aws.ToBool(query.ConsistentRead) || query.IndexName != nil || aws.ToInt32(query.Limit) > 100 {
			t.Fatalf("overflow query = %#v", query)
		}
	}

	torn := directory
	torn.Version++
	torn.UpdatedAtMillis++
	beforeItem := fake.items[sessionControlSessionDynamoMapKey(sessionControlFenceDirectoryKey(directory.CellID))]
	tornRow, err := sessionControlFenceDirectoryToRow(torn)
	if err != nil {
		t.Fatal(err)
	}
	tornItem := marshalSessionControlSessionTestRow(t, tornRow)
	fake.gets = nil
	fake.getHook = func(_ context.Context, input *dynamodb.GetItemInput, call int) (*dynamodb.GetItemOutput, error) {
		if sessionControlSessionDynamoMapKey(input.Key) != sessionControlSessionDynamoMapKey(sessionControlFenceDirectoryKey(directory.CellID)) {
			return &dynamodb.GetItemOutput{}, nil
		}
		if call == 0 {
			return &dynamodb.GetItemOutput{Item: beforeItem}, nil
		}
		return &dynamodb.GetItemOutput{Item: tornItem}, nil
	}
	if _, err := store.ListOverflowCloseWorkPage(context.Background(), directory.CellID, nil, 1); !errors.Is(err, errSessionControlCloseConflict) {
		t.Fatalf("torn overflow page error = %v, want conflict", err)
	}
}

func TestDynamoSessionControlDueDiscoveryStronglyVerifiesBaseRows(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	work := makeOverflowCloseWork(t, "cell-01", 3, 7)
	seedSessionControlCloseWork(t, fake, work)
	row, err := sessionControlCloseWorkToRow(work)
	if err != nil {
		t.Fatal(err)
	}
	item := marshalSessionControlSessionTestRow(t, row)
	projection := map[string]types.AttributeValue{"pk": item["pk"], "sk": item["sk"]}
	fake.queryHook = func(context.Context, *dynamodb.QueryInput, int) (*dynamodb.QueryOutput, error) {
		return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{projection}}, nil
	}
	shard := uint64(0)
	for candidate := uint64(0); candidate < sessionControlCloseDueShardCount; candidate++ {
		name, _ := sessionControlCloseDueShardForCell(work.CellID, candidate)
		if name == sessionControlCloseDueShard(work) {
			shard = candidate
			break
		}
	}
	page, err := store.ListDueCloseWorkPage(context.Background(), work.CellID, shard, work.DueAtMillis, nil, 10)
	if err != nil || len(page.Work) != 1 || page.Work[0] != work || len(fake.gets) != 1 || !aws.ToBool(fake.gets[0].ConsistentRead) {
		t.Fatalf("due page = %#v, %v; gets=%#v", page, err, fake.gets)
	}
	if len(fake.queries) != 1 || aws.ToBool(fake.queries[0].ConsistentRead) || aws.ToString(fake.queries[0].IndexName) != sessionControlDueIndexName {
		t.Fatalf("due query = %#v", fake.queries)
	}

	delete(fake.items, sessionControlSessionDynamoMapKey(item))
	page, err = store.ListDueCloseWorkPage(context.Background(), work.CellID, shard, work.DueAtMillis, nil, 10)
	if err != nil || len(page.Work) != 0 {
		t.Fatalf("deleted-base stale hit = %#v, %v", page, err)
	}

	malformed := make(map[string]types.AttributeValue, len(item))
	for key, value := range item {
		malformed[key] = value
	}
	delete(malformed, "expected_target_count")
	fake.setItem(malformed)
	if _, err := store.ListDueCloseWorkPage(context.Background(), work.CellID, shard, work.DueAtMillis, nil, 10); !errors.Is(err, errSessionControlCloseCorrupt) {
		t.Fatalf("malformed pending base error = %v, want corrupt", err)
	}

	fake.queryHook = func(context.Context, *dynamodb.QueryInput, int) (*dynamodb.QueryOutput, error) {
		return &dynamodb.QueryOutput{}, nil
	}
	page, err = store.ListDueCloseWorkPage(context.Background(), work.CellID, shard, work.DueAtMillis, nil, 10)
	if err != nil || len(page.Work) != 0 {
		t.Fatalf("omitted eventual-GSI hit = %#v, %v", page, err)
	}
}
