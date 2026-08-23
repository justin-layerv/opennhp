package server

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// The fake transaction deliberately consumes its operation budget before the
// store performs a fresh ambiguity-classification bracket. One millisecond is
// scheduler-sensitive under the full package race run and tests timing rather
// than the detached result-context contract.
const sessionControlDynamoAmbiguityTestTimeout = 100 * time.Millisecond

type sessionControlSessionDynamoFake struct {
	mu           sync.Mutex
	items        map[string]map[string]types.AttributeValue
	gets         []*dynamodb.GetItemInput
	transactions []*dynamodb.TransactWriteItemsInput
	queries      []*dynamodb.QueryInput
	updates      []*dynamodb.UpdateItemInput
	getHook      func(context.Context, *dynamodb.GetItemInput, int) (*dynamodb.GetItemOutput, error)
	transactHook func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error)
	queryHook    func(context.Context, *dynamodb.QueryInput, int) (*dynamodb.QueryOutput, error)
	updateHook   func(context.Context, *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error)
}

func newSessionControlSessionDynamoFake() *sessionControlSessionDynamoFake {
	return &sessionControlSessionDynamoFake{items: make(map[string]map[string]types.AttributeValue)}
}

func sessionControlSessionDynamoMapKey(key map[string]types.AttributeValue) string {
	pk, _ := key["pk"].(*types.AttributeValueMemberS)
	sk, _ := key["sk"].(*types.AttributeValueMemberS)
	if pk == nil || sk == nil {
		return ""
	}
	return pk.Value + "\x00" + sk.Value
}

func (f *sessionControlSessionDynamoFake) setItem(item map[string]types.AttributeValue) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[sessionControlSessionDynamoMapKey(item)] = item
}

func (f *sessionControlSessionDynamoFake) GetItem(ctx context.Context, input *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.mu.Lock()
	call := len(f.gets)
	f.gets = append(f.gets, input)
	hook := f.getHook
	f.mu.Unlock()
	if hook != nil {
		return hook(ctx, input, call)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return &dynamodb.GetItemOutput{Item: f.items[sessionControlSessionDynamoMapKey(input.Key)]}, nil
}

func (f *sessionControlSessionDynamoFake) TransactWriteItems(ctx context.Context, input *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	f.mu.Lock()
	f.transactions = append(f.transactions, input)
	hook := f.transactHook
	f.mu.Unlock()
	if hook != nil {
		return hook(ctx, input)
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

func (*sessionControlSessionDynamoFake) PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	return nil, errors.New("unexpected PutItem")
}

func (f *sessionControlSessionDynamoFake) Query(ctx context.Context, input *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	f.mu.Lock()
	call := len(f.queries)
	f.queries = append(f.queries, input)
	hook := f.queryHook
	f.mu.Unlock()
	if hook != nil {
		return hook(ctx, input, call)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pk, _ := input.ExpressionAttributeValues[":pk"].(*types.AttributeValueMemberS)
	if pk == nil {
		return nil, errors.New("query missing pk")
	}
	f.mu.Lock()
	keys := make([]string, 0)
	for key, item := range f.items {
		itemPK, _ := item["pk"].(*types.AttributeValueMemberS)
		if itemPK != nil && itemPK.Value == pk.Value {
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
	out := make([]map[string]types.AttributeValue, 0, limit)
	for _, key := range keys[start : start+limit] {
		out = append(out, f.items[key])
	}
	var last map[string]types.AttributeValue
	if start+limit < len(keys) && limit > 0 {
		item := f.items[keys[start+limit-1]]
		last = map[string]types.AttributeValue{"pk": item["pk"], "sk": item["sk"]}
	}
	f.mu.Unlock()
	return &dynamodb.QueryOutput{Items: out, LastEvaluatedKey: last}, nil
}

func (f *sessionControlSessionDynamoFake) UpdateItem(ctx context.Context, input *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	f.mu.Lock()
	f.updates = append(f.updates, input)
	hook := f.updateHook
	f.mu.Unlock()
	if hook != nil {
		return hook(ctx, input)
	}
	return &dynamodb.UpdateItemOutput{}, nil
}

func newSessionControlSessionDynamoStore(fake *sessionControlSessionDynamoFake, timeout time.Duration) *dynamoSessionControlStore {
	return &dynamoSessionControlStore{
		client: fake, tableName: storeTableNameForTest, operationTimeout: timeout,
		nowUTC: func() time.Time { return time.UnixMilli(1_800_000_010_000).UTC() },
	}
}

func marshalSessionControlSessionTestRow(t *testing.T, row any) map[string]types.AttributeValue {
	t.Helper()
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func seedSessionControlReservation(t *testing.T, fake *sessionControlSessionDynamoFake, authority sessionControlSessionAuthority) {
	t.Helper()
	sessionRow, err := sessionControlSessionToRow(authority)
	if err != nil {
		t.Fatal(err)
	}
	membershipRow, err := sessionControlSessionMembershipToRow(authority.Candidate)
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, sessionRow))
	fake.setItem(marshalSessionControlSessionTestRow(t, membershipRow))
}

func seedSessionControlDirectory(t *testing.T, fake *sessionControlSessionDynamoFake, snapshot sessionControlFenceSnapshot) {
	t.Helper()
	row, err := sessionControlFenceDirectoryToRow(sessionControlFenceDirectory{
		CellID: snapshot.CellID, Version: snapshot.DirectoryVersion, ActiveFenceCount: snapshot.ActiveFenceCount,
		AdmissionBlocked: snapshot.AdmissionBlocked, OverflowCloseCount: snapshot.OverflowCloseCount,
		OverflowLeaderEventID:                  snapshot.OverflowLeaderEventID,
		OverflowLeaderPreparedDirectoryVersion: snapshot.OverflowLeaderPreparedDirectoryVersion,
		OverflowLeaderSelectedDirectoryVersion: snapshot.OverflowLeaderSelectedDirectoryVersion,
		CreatedAtMillis:                        1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, row))
}

func seedSessionControlTarget(t *testing.T, fake *sessionControlSessionDynamoFake, target sessionControlTargetAuthority) sessionControlOwnerAuthority {
	t.Helper()
	row, err := sessionControlTargetToRow(target)
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, row))
	return seedSessionControlOwner(t, fake, target)
}

func seedSessionControlOwner(t *testing.T, fake *sessionControlSessionDynamoFake, target sessionControlTargetAuthority) sessionControlOwnerAuthority {
	t.Helper()
	phase := sessionControlOwnerPreparing
	if target.State == sessionControlTargetActive {
		phase = sessionControlOwnerActiveUnready
		if target.ready() {
			phase = sessionControlOwnerReady
		}
	} else if target.State == sessionControlTargetRetired {
		phase = sessionControlOwnerRetired
	}
	owner, err := sessionControlOwnerFromTarget(target, nil, phase)
	if err != nil {
		t.Fatal(err)
	}
	row, err := sessionControlOwnerToRow(owner)
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, row))
	return owner
}

func seedSessionControlIntent(t *testing.T, fake *sessionControlSessionDynamoFake, intent sessionControlSessionIntent) {
	t.Helper()
	for _, reverse := range []bool{false, true} {
		row, err := sessionControlIntentToRow(intent, reverse)
		if err != nil {
			t.Fatal(err)
		}
		fake.setItem(marshalSessionControlSessionTestRow(t, row))
	}
}

func TestDynamoSessionControlReserveSessionExactWire(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	candidate := testSessionControlSessionCandidate(0x51, 201)
	candidate.RunID = ""
	candidate.RunAttempt = 0
	snapshot := testSessionControlSessionSnapshot(7)

	reserved, err := store.ReserveSession(context.Background(), candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Version != 1 || reserved.TargetCount != 0 || reserved.RetainUntilMillis != candidate.ReservationDeadlineMillis {
		t.Fatalf("reserved authority = %#v", reserved)
	}
	if len(fake.gets) != 3 {
		t.Fatalf("strong reservation reads = %d, want 3", len(fake.gets))
	}
	for _, input := range fake.gets {
		if !aws.ToBool(input.ConsistentRead) || aws.ToString(input.TableName) != storeTableNameForTest {
			t.Fatalf("reservation read = %#v", input)
		}
	}
	if len(fake.transactions) != 1 {
		t.Fatalf("reservation transactions = %d, want 1", len(fake.transactions))
	}
	txn := fake.transactions[0]
	if aws.ToString(txn.ClientRequestToken) != aws.ToString(sessionControlReservationToken(candidate, snapshot)) ||
		len(aws.ToString(txn.ClientRequestToken)) > 36 || len(txn.TransactItems) != 3 {
		t.Fatalf("reservation transaction = %#v", txn)
	}
	directory := txn.TransactItems[0].ConditionCheck
	if directory == nil || !strings.Contains(aws.ToString(directory.ConditionExpression), "kind = :kind") ||
		!strings.Contains(aws.ToString(directory.ConditionExpression), "#version = :version") ||
		!strings.Contains(aws.ToString(directory.ConditionExpression), "active_fence_count = :count") ||
		!strings.Contains(aws.ToString(directory.ConditionExpression), "attribute_not_exists(#ttl)") || directory.ExpressionAttributeNames["#ttl"] != "ttl" {
		t.Fatalf("directory condition = %#v", directory)
	}
	var sessionRow sessionControlSessionRow
	var membershipRow sessionControlSessionMembershipRow
	if txn.TransactItems[1].Put == nil || txn.TransactItems[2].Put == nil ||
		attributevalue.UnmarshalMap(txn.TransactItems[1].Put.Item, &sessionRow) != nil ||
		attributevalue.UnmarshalMap(txn.TransactItems[2].Put.Item, &membershipRow) != nil {
		t.Fatalf("reservation puts = %#v", txn.TransactItems)
	}
	decoded, err := sessionControlSessionFromRow(sessionRow, candidate.SessionID)
	if err != nil || *reserved != decoded {
		t.Fatalf("session row = %#v, %v", sessionRow, err)
	}
	if _, err := sessionControlSessionMembershipFromRow(membershipRow, candidate); err != nil {
		t.Fatal(err)
	}
	if sessionRow.DueShard != sessionControlSessionDueShard(candidate) ||
		sessionRow.DueSort != sessionControlSessionDueSort(candidate) {
		t.Fatalf("reservation due index = %q/%q", sessionRow.DueShard, sessionRow.DueSort)
	}
	if sessionRow.SessionExpiresAtMillis != 0 {
		t.Fatalf("reservation serving expiry = %d, want unresolved zero", sessionRow.SessionExpiresAtMillis)
	}
	if _, exists := txn.TransactItems[1].Put.Item["session_expires_at_ms"]; exists {
		t.Fatal("unresolved reservation persisted a serving expiry")
	}
	for _, put := range []*types.Put{txn.TransactItems[1].Put, txn.TransactItems[2].Put} {
		if _, hasTTL := put.Item["ttl"]; hasTTL || aws.ToString(put.ConditionExpression) != "attribute_not_exists(pk) AND attribute_not_exists(sk)" {
			t.Fatalf("reservation put = %#v", put)
		}
	}
}

func TestDynamoSessionControlPrepareIntentExactWireAndExtensionCountOnce(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(3)
	candidate := testSessionControlSessionCandidate(0x52, 202)
	reserved, err := planSessionControlReservation(candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	target := testSessionControlSessionTarget(0x53)
	target.ActivatedControlVersion = 2
	target.ReadyControlVersion = 2
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlReservation(t, fake, reserved)
	owner := seedSessionControlTarget(t, fake, target)
	seedSessionControlDirectory(t, fake, snapshot)
	store := newSessionControlSessionDynamoStore(fake, time.Second)

	prepared, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.transactions) != 1 || len(fake.transactions[0].TransactItems) != 6 {
		t.Fatalf("intent transactions = %#v", fake.transactions)
	}
	if len(fake.gets) != 10 {
		t.Fatalf("intent strong reads = %d, want 10", len(fake.gets))
	}
	for _, input := range fake.gets {
		if !aws.ToBool(input.ConsistentRead) || aws.ToString(input.TableName) != storeTableNameForTest {
			t.Fatalf("intent read = %#v", input)
		}
	}
	txn := fake.transactions[0]
	if aws.ToString(txn.ClientRequestToken) != aws.ToString(sessionControlIntentTokenWithOwner(reserved.fence(), target, owner,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)) || len(aws.ToString(txn.ClientRequestToken)) > 36 {
		t.Fatalf("intent token = %q", aws.ToString(txn.ClientRequestToken))
	}
	baseIntentToken := aws.ToString(txn.ClientRequestToken)
	for name, mutate := range map[string]func(*sessionControlTargetAuthority){
		"ready cursor":       func(value *sessionControlTargetAuthority) { value.ReadyControlVersion++ },
		"AAK enqueue time":   func(value *sessionControlTargetAuthority) { value.AAKEnqueuedAtMillis++ },
		"AAK transaction id": func(value *sessionControlTargetAuthority) { value.AAKTransactionID++ },
	} {
		t.Run("intent token binds "+name, func(t *testing.T) {
			changed := target
			mutate(&changed)
			if token := aws.ToString(sessionControlIntentToken(reserved.fence(), changed,
				candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)); token == baseIntentToken || len(token) > 36 {
				t.Fatalf("changed intent token = %q, base = %q", token, baseIntentToken)
			}
		})
	}
	targetCheck := txn.TransactItems[1].ConditionCheck
	for _, fragment := range []string{"boot_id = :boot_id", "flush_generation = :flush_generation", "#version = :version", "authority_version = :authority_version", "activated_control_version = :cursor", "ready_control_version = :ready_cursor", "aak_enqueued_at_ms = :aak_enqueued_at", "aak_transaction_id = :aak_transaction_id", "attribute_not_exists(retired_at_ms)", "attribute_not_exists(#ttl)"} {
		if targetCheck == nil || !strings.Contains(aws.ToString(targetCheck.ConditionExpression), fragment) {
			t.Fatalf("target condition %q lacks %q", aws.ToString(targetCheck.ConditionExpression), fragment)
		}
	}
	ownerCheck := txn.TransactItems[2].ConditionCheck
	if ownerCheck == nil || !strings.Contains(aws.ToString(ownerCheck.ConditionExpression), "work_version = :owner_work_version") ||
		!strings.Contains(aws.ToString(ownerCheck.ConditionExpression), "pending_count = :owner_pending_count") ||
		!strings.Contains(aws.ToString(ownerCheck.ConditionExpression), "attribute_not_exists(#ttl)") || ownerCheck.ExpressionAttributeNames["#ttl"] != "ttl" {
		t.Fatalf("owner condition = %#v", ownerCheck)
	}
	update := txn.TransactItems[3].Update
	if update == nil || !strings.Contains(aws.ToString(update.ConditionExpression), "target_count < :capacity") ||
		!strings.Contains(aws.ToString(update.ConditionExpression), "attribute_not_exists(session_expires_at_ms)") ||
		!strings.Contains(aws.ToString(update.ConditionExpression), "due_shard = :due_shard") ||
		!strings.Contains(aws.ToString(update.ConditionExpression), "due_sort = :due_sort") ||
		sessionControlWireString(t, sessionControlAttributeWireMap(t, update.ExpressionAttributeValues), ":next_count", "N") != "1" ||
		sessionControlWireString(t, sessionControlAttributeWireMap(t, update.ExpressionAttributeValues), ":due_shard", "S") != sessionControlSessionDueShard(candidate) ||
		sessionControlWireString(t, sessionControlAttributeWireMap(t, update.ExpressionAttributeValues), ":due_sort", "S") != sessionControlSessionDueSort(candidate) ||
		sessionControlWireString(t, sessionControlAttributeWireMap(t, update.ExpressionAttributeValues), ":next_version", "N") != "2" {
		t.Fatalf("new intent session CAS = %#v", update)
	}
	if !strings.Contains(aws.ToString(update.UpdateExpression), "session_expires_at_ms = :next_session_expires_at") ||
		sessionControlWireString(t, sessionControlAttributeWireMap(t, update.ExpressionAttributeValues), ":next_session_expires_at", "N") != fmt.Sprint(candidate.IssuedAtMillis+60_000) {
		t.Fatalf("new intent serving expiry update = %#v", update)
	}
	for index, reverse := range []bool{false, true} {
		put := txn.TransactItems[4+index].Put
		if put == nil || aws.ToString(put.ConditionExpression) != "attribute_not_exists(pk) AND attribute_not_exists(sk)" {
			t.Fatalf("intent put %d = %#v", index, put)
		}
		var row sessionControlSessionIntentRow
		if err := attributevalue.UnmarshalMap(put.Item, &row); err != nil {
			t.Fatal(err)
		}
		decoded, err := sessionControlIntentFromRow(row, reverse)
		if err != nil || decoded != prepared.Intent {
			t.Fatalf("intent row %d = %#v, %v; want %#v", index, decoded, err, prepared.Intent)
		}
		if row.TargetReadyCursor != target.ReadyControlVersion ||
			row.TargetAAKEnqueuedAtMillis != target.AAKEnqueuedAtMillis ||
			row.TargetAAKTransactionID != target.AAKTransactionID {
			t.Fatalf("intent target readiness audit %d = %#v", index, row)
		}
		if _, hasTTL := put.Item["ttl"]; hasTTL {
			t.Fatalf("intent row %d has TTL", index)
		}
	}

	// Seed the committed state, then simulate a same-process reconnect and issue
	// another AOP through its newer ACTIVE authority.
	fake.transactions = nil
	seedSessionControlReservation(t, fake, prepared.Session)
	seedSessionControlIntent(t, fake, prepared.Intent)
	reactivated := target
	reactivated.Version += 2
	reactivated.AuthorityVersion += 2
	reactivated.ActivatedControlVersion++
	reactivated.ReadyControlVersion++
	reactivated.PreparedAtMillis += 1_000
	reactivated.UpdatedAtMillis += 1_000
	reactivated.AAKEnqueuedAtMillis = reactivated.UpdatedAtMillis
	reactivated.AAKTransactionID++
	seedSessionControlTarget(t, fake, reactivated)
	extended, err := store.PrepareSessionIntent(context.Background(), prepared.Session.fence(), reactivated,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+150_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if extended.Session.TargetCount != 1 || extended.Session.Version != 3 || extended.Intent.Target != reactivated ||
		extended.Intent.SessionExpiresAtMillis != candidate.IssuedAtMillis+60_000 ||
		extended.Intent.RetainUntilMillis != candidate.IssuedAtMillis+150_000 {
		t.Fatalf("extended preparation = %#v", extended)
	}
	extension := fake.transactions[0]
	update = extension.TransactItems[3].Update
	if strings.Contains(aws.ToString(update.ConditionExpression), ":capacity") ||
		!strings.Contains(aws.ToString(update.ConditionExpression), "session_expires_at_ms = :session_expires_at") ||
		sessionControlWireString(t, sessionControlAttributeWireMap(t, update.ExpressionAttributeValues), ":session_expires_at", "N") != fmt.Sprint(candidate.IssuedAtMillis+60_000) ||
		sessionControlWireString(t, sessionControlAttributeWireMap(t, update.ExpressionAttributeValues), ":next_session_expires_at", "N") != fmt.Sprint(candidate.IssuedAtMillis+60_000) ||
		sessionControlWireString(t, sessionControlAttributeWireMap(t, update.ExpressionAttributeValues), ":next_count", "N") != "1" {
		t.Fatalf("extension session CAS = %#v", update)
	}
	for _, index := range []int{4, 5} {
		put := extension.TransactItems[index].Put
		if put == nil || strings.Contains(aws.ToString(put.ConditionExpression), "attribute_not_exists(pk)") ||
			!strings.Contains(aws.ToString(put.ConditionExpression), "session_version = :session_version") ||
			!strings.Contains(aws.ToString(put.ConditionExpression), "prepared_directory_version = :prepared_directory_version") {
			t.Fatalf("extension intent CAS %d = %#v", index, put)
		}
		values := sessionControlAttributeWireMap(t, put.ExpressionAttributeValues)
		if sessionControlWireString(t, values, ":target_version", "N") != fmt.Sprint(target.Version) ||
			sessionControlWireString(t, values, ":target_authority_version", "N") != fmt.Sprint(target.AuthorityVersion) ||
			sessionControlWireString(t, values, ":target_cursor", "N") != fmt.Sprint(target.ActivatedControlVersion) ||
			sessionControlWireString(t, values, ":target_ready_cursor", "N") != fmt.Sprint(target.ReadyControlVersion) ||
			sessionControlWireString(t, values, ":target_aak_transaction_id", "N") != fmt.Sprint(target.AAKTransactionID) {
			t.Fatalf("extension old-target CAS %d = %#v", index, put.ExpressionAttributeValues)
		}
		var row sessionControlSessionIntentRow
		if err := attributevalue.UnmarshalMap(put.Item, &row); err != nil {
			t.Fatal(err)
		}
		decoded, err := sessionControlIntentFromRow(row, index == 5)
		if err != nil || decoded.Target != reactivated {
			t.Fatalf("extension new-target row %d = %#v, %v", index, decoded, err)
		}
	}
}

func TestDynamoSessionControlPrepareIntentRejectsOwnerInventoryRace(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x6e, 260)
	reserved, err := planSessionControlReservation(candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	target := testSessionControlSessionTarget(0x6f)
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlReservation(t, fake, reserved)
	owner := seedSessionControlTarget(t, fake, target)
	seedSessionControlDirectory(t, fake, snapshot)
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		inserted, err := planSessionControlOwnerTaskInsert(owner, owner.UpdatedAtMillis+1)
		if err != nil {
			t.Fatal(err)
		}
		row, err := sessionControlOwnerToRow(inserted)
		if err != nil {
			t.Fatal(err)
		}
		fake.setItem(marshalSessionControlSessionTestRow(t, row))
		return nil, &types.TransactionCanceledException{}
	}
	if _, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot); !errors.Is(err, errSessionControlSessionTargetConflict) {
		t.Fatalf("PrepareSessionIntent() owner inventory race error = %v, want conflict", err)
	}
}

func TestDynamoSessionControlIntentRejectsMissingTargetReadinessAudit(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x5e, 240)
	reserved, err := planSessionControlReservation(candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	target := testSessionControlSessionTarget(0x5f)
	planned, err := planSessionControlIntent(reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	row, err := sessionControlIntentToRow(planned.Intent, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"target_ready_cursor", "target_aak_enqueued_at_ms", "target_aak_transaction_id"} {
		t.Run(field, func(t *testing.T) {
			fake := newSessionControlSessionDynamoFake()
			store := newSessionControlSessionDynamoStore(fake, time.Second)
			item := marshalSessionControlSessionTestRow(t, row)
			delete(item, field)
			fake.setItem(item)
			if _, err := store.getIntentItem(context.Background(), candidate, target, false); !errors.Is(err, errSessionControlSessionCorrupt) {
				t.Fatalf("missing %s error = %v, want corrupt", field, err)
			}
		})
	}
}

func TestSessionControlIntentTargetIdentityBindsStableProcess(t *testing.T) {
	base := testSessionControlSessionTarget(0x54)
	seen := map[string]string{sessionControlIntentTargetDigest(base): "base"}
	processMutations := map[string]func(*sessionControlTargetAuthority){
		"ac id":            func(target *sessionControlTargetAuthority) { target.ACID += "-next" },
		"public key":       func(target *sessionControlTargetAuthority) { target.PublicKey = testACSessionControlPublicKey(0x55) },
		"boot":             func(target *sessionControlTargetAuthority) { target.BootID = "ffeeddccbbaa99887766554433221100" },
		"flush generation": func(target *sessionControlTargetAuthority) { target.FlushGeneration++ },
		"control cell":     func(target *sessionControlTargetAuthority) { target.ControlCellID = "cell-02" },
	}
	for name, mutate := range processMutations {
		target := base
		mutate(&target)
		digest := sessionControlIntentTargetDigest(target)
		if previous, duplicate := seen[digest]; duplicate {
			t.Fatalf("%s target digest collides with %s", name, previous)
		}
		seen[digest] = name
	}
	mutableAuthority := base
	mutableAuthority.Version++
	mutableAuthority.AuthorityVersion++
	mutableAuthority.ActivatedControlVersion++
	mutableAuthority.ReadyControlVersion++
	mutableAuthority.PreparedAtMillis++
	mutableAuthority.UpdatedAtMillis++
	mutableAuthority.AAKEnqueuedAtMillis++
	mutableAuthority.AAKTransactionID++
	if got, want := sessionControlIntentTargetDigest(mutableAuthority), sessionControlIntentTargetDigest(base); got != want {
		t.Fatalf("mutable authority changed process digest: %q != %q", got, want)
	}
}

func TestDynamoSessionControlReserveClassifiesCommitAfterOperationTimeout(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, sessionControlDynamoAmbiguityTestTimeout)
	candidate := testSessionControlSessionCandidate(0x56, 203)
	snapshot := testSessionControlSessionSnapshot(1)
	planned, err := planSessionControlReservation(candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionControlDirectory(t, fake, snapshot)
	fake.transactHook = func(ctx context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		<-ctx.Done()
		seedSessionControlReservation(t, fake, planned)
		return nil, ctx.Err()
	}
	got, err := store.ReserveSession(context.Background(), candidate, snapshot)
	if err != nil || *got != planned {
		t.Fatalf("ReserveSession() = %#v, %v; want committed %#v", got, err, planned)
	}
	for _, input := range fake.gets[3:] {
		if !aws.ToBool(input.ConsistentRead) {
			t.Fatalf("classification read was not strong: %#v", input)
		}
	}
}

func TestDynamoSessionControlReserveDetectsConcurrentNumericCollision(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	wanted := testSessionControlSessionCandidate(0x61, 210)
	winner := testSessionControlSessionCandidate(0x62, wanted.SessionID)
	winnerAuthority, _ := planSessionControlReservation(winner, snapshot)
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	seedSessionControlDirectory(t, fake, snapshot)
	fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		seedSessionControlReservation(t, fake, winnerAuthority)
		return nil, &types.TransactionCanceledException{}
	}
	_, err := store.ReserveSession(context.Background(), wanted, snapshot)
	if !errors.Is(err, errSessionControlSessionCollision) {
		t.Fatalf("ReserveSession() error = %v, want numeric collision", err)
	}
}

func TestDynamoSessionControlReserveReadBracketRetriesConcurrentCommit(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x63, 211)
	planned, _ := planSessionControlReservation(candidate, snapshot)
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlDirectory(t, fake, snapshot)
	membershipKey := sessionControlSessionDynamoMapKey(sessionControlAgentSessionDynamoKey(candidate))
	var once sync.Once
	fake.getHook = func(ctx context.Context, input *dynamodb.GetItemInput, _ int) (*dynamodb.GetItemOutput, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if sessionControlSessionDynamoMapKey(input.Key) == membershipKey {
			once.Do(func() { seedSessionControlReservation(t, fake, planned) })
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return &dynamodb.GetItemOutput{Item: fake.items[sessionControlSessionDynamoMapKey(input.Key)]}, nil
	}
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	got, err := store.ReserveSession(context.Background(), candidate, snapshot)
	if err != nil || *got != planned {
		t.Fatalf("ReserveSession() = %#v, %v; want concurrent commit %#v", got, err, planned)
	}
	if len(fake.transactions) != 0 {
		t.Fatalf("idempotent concurrent commit reached transaction: %d", len(fake.transactions))
	}
}

func TestDynamoSessionControlPrepareClassifiesCommitAfterOperationTimeout(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x57, 204)
	reserved, _ := planSessionControlReservation(candidate, snapshot)
	target := testSessionControlSessionTarget(0x58)
	planned, err := planSessionControlIntent(reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlReservation(t, fake, reserved)
	seedSessionControlDirectory(t, fake, snapshot)
	seedSessionControlTarget(t, fake, target)
	store := newSessionControlSessionDynamoStore(fake, sessionControlDynamoAmbiguityTestTimeout)
	fake.transactHook = func(ctx context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		<-ctx.Done()
		seedSessionControlReservation(t, fake, planned.Session)
		seedSessionControlIntent(t, fake, planned.Intent)
		return nil, ctx.Err()
	}
	got, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	if err != nil || *got != planned {
		t.Fatalf("PrepareSessionIntent() = %#v, %v; want committed %#v", got, err, planned)
	}
}

func TestDynamoSessionControlPrepareAmbiguityRequiresUnchangedDirectory(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x59, 205)
	reserved, _ := planSessionControlReservation(candidate, snapshot)
	target := testSessionControlSessionTarget(0x5a)
	planned, _ := planSessionControlIntent(reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlReservation(t, fake, reserved)
	seedSessionControlTarget(t, fake, target)
	store := newSessionControlSessionDynamoStore(fake, sessionControlDynamoAmbiguityTestTimeout)
	fake.transactHook = func(ctx context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		<-ctx.Done()
		seedSessionControlReservation(t, fake, planned.Session)
		seedSessionControlIntent(t, fake, planned.Intent)
		seedSessionControlDirectory(t, fake, testSessionControlSessionSnapshot(2))
		return nil, ctx.Err()
	}
	_, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	if !errors.Is(err, errSessionControlSessionFenceStale) {
		t.Fatalf("PrepareSessionIntent() error = %v, want fence stale", err)
	}
}

func TestDynamoSessionControlPrepareAmbiguityDoesNotAcceptOldProcessAuthority(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x64, 212)
	reserved, _ := planSessionControlReservation(candidate, snapshot)
	target := testSessionControlSessionTarget(0x65)
	first, _ := planSessionControlIntent(reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	reactivated := target
	reactivated.Version += 2
	reactivated.AuthorityVersion += 2
	reactivated.PreparedAtMillis++
	reactivated.UpdatedAtMillis++
	reactivated.AAKEnqueuedAtMillis = reactivated.UpdatedAtMillis
	reactivated.AAKTransactionID++
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlReservation(t, fake, first.Session)
	seedSessionControlIntent(t, fake, first.Intent)
	seedSessionControlDirectory(t, fake, snapshot)
	seedSessionControlTarget(t, fake, reactivated)
	store := newSessionControlSessionDynamoStore(fake, time.Millisecond)
	fake.transactHook = func(ctx context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	_, err := store.PrepareSessionIntent(context.Background(), first.Session.fence(), reactivated,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+150_000, snapshot)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("PrepareSessionIntent() error = %v, want ambiguous timeout rather than old-target success", err)
	}
}

func TestDynamoSessionControlPrepareClassifiesExactReconnectedTargetCommit(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x6b, 217)
	reserved, _ := planSessionControlReservation(candidate, snapshot)
	target := testSessionControlSessionTarget(0x6c)
	first, _ := planSessionControlIntent(reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	reactivated := target
	reactivated.Version += 2
	reactivated.AuthorityVersion += 2
	reactivated.PreparedAtMillis++
	reactivated.UpdatedAtMillis++
	reactivated.AAKEnqueuedAtMillis = reactivated.UpdatedAtMillis
	reactivated.AAKTransactionID++
	planned, err := planSessionControlIntentExtension(first.Session, first.Session.fence(), first.Intent, reactivated,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+150_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlReservation(t, fake, first.Session)
	seedSessionControlIntent(t, fake, first.Intent)
	seedSessionControlDirectory(t, fake, snapshot)
	seedSessionControlTarget(t, fake, reactivated)
	store := newSessionControlSessionDynamoStore(fake, sessionControlDynamoAmbiguityTestTimeout)
	fake.transactHook = func(ctx context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		<-ctx.Done()
		seedSessionControlReservation(t, fake, planned.Session)
		seedSessionControlIntent(t, fake, planned.Intent)
		return nil, ctx.Err()
	}
	got, err := store.PrepareSessionIntent(context.Background(), first.Session.fence(), reactivated,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+150_000, snapshot)
	if err != nil || *got != planned {
		t.Fatalf("PrepareSessionIntent() = %#v, %v; want exact reconnected commit %#v", got, err, planned)
	}
}

func TestDynamoSessionControlReserveCancellationWithoutCommit(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x5b, 206)
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlDirectory(t, fake, snapshot)
	store := newSessionControlSessionDynamoStore(fake, time.Millisecond)
	fake.transactHook = func(ctx context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	_, err := store.ReserveSession(context.Background(), candidate, snapshot)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReserveSession() error = %v, want deadline exceeded", err)
	}
}

func TestDynamoSessionControlPrepareCancellationWithoutCommit(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x5e, 208)
	reserved, _ := planSessionControlReservation(candidate, snapshot)
	target := testSessionControlSessionTarget(0x5f)
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlReservation(t, fake, reserved)
	seedSessionControlDirectory(t, fake, snapshot)
	seedSessionControlTarget(t, fake, target)
	store := newSessionControlSessionDynamoStore(fake, time.Millisecond)
	fake.transactHook = func(ctx context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	_, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("PrepareSessionIntent() error = %v, want deadline exceeded", err)
	}
}

func TestSessionControlSessionRejectsVersionOverflowAndTTLRows(t *testing.T) {
	candidate := testSessionControlSessionCandidate(0x60, 209)
	snapshot := testSessionControlSessionSnapshot(1)
	reserved, _ := planSessionControlReservation(candidate, snapshot)
	invalidSession := reserved
	invalidSession.TargetCount = 1
	if err := validateSessionControlSessionAuthority(invalidSession); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("version-1 session with target error = %v, want corrupt", err)
	}
	invalidSession = reserved
	invalidSession.Version = 2
	if err := validateSessionControlSessionAuthority(invalidSession); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("advanced session without target error = %v, want corrupt", err)
	}
	invalidSession = reserved
	invalidSession.SessionExpiresAtMillis = candidate.IssuedAtMillis + 60_000
	if err := validateSessionControlSessionAuthority(invalidSession); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("targetless session with serving expiry error = %v, want corrupt", err)
	}
	target := testSessionControlSessionTarget(0x66)
	prepared, _ := planSessionControlIntent(reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	invalidSession = prepared.Session
	invalidSession.SessionExpiresAtMillis = 0
	if err := validateSessionControlSessionAuthority(invalidSession); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("targetful session without serving expiry error = %v, want corrupt", err)
	}
	invalidIntent := prepared.Intent
	invalidIntent.SessionVersion = ^uint64(0)
	if err := validateSessionControlSessionIntent(invalidIntent); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("overflowing intent version error = %v, want corrupt", err)
	}
	unsafeFence := reserved.fence()
	unsafeFence.Version = ^uint64(0) - 1
	if validSessionControlSessionFence(unsafeFence) {
		t.Fatal("overflowing session fence accepted")
	}
	unsafeSnapshot := snapshot
	unsafeSnapshot.DirectoryVersion = ^uint64(0) - 1
	if err := validateSessionControlFenceSnapshot(unsafeSnapshot, candidate.CellID); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("overflowing directory error = %v, want corrupt", err)
	}
	invalidAck := prepared.Session
	invalidAck.State = sessionControlSessionStateAckEnqueued
	if err := validateSessionControlSessionAuthority(invalidAck); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("ACK without audit timestamp error = %v, want corrupt", err)
	}
	invalidAck.AckEnqueuedAtMillis = invalidAck.SessionExpiresAtMillis
	if err := validateSessionControlSessionAuthority(invalidAck); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("ACK at serving expiry error = %v, want corrupt", err)
	}
	validAck := invalidAck
	validAck.AckEnqueuedAtMillis = candidate.IssuedAtMillis + 10_000
	ackRow, err := sessionControlSessionToRow(validAck)
	if err != nil {
		t.Fatal(err)
	}
	if ackRow.DueShard != "" || ackRow.DueSort != "" {
		t.Fatalf("ACK row retained due index = %q/%q", ackRow.DueShard, ackRow.DueSort)
	}
	ackRow.DueShard = sessionControlSessionDueShard(candidate)
	ackRow.DueSort = sessionControlSessionDueSort(candidate)
	if _, err := sessionControlSessionFromRow(ackRow, candidate.SessionID); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("ACK row with due index error = %v, want corrupt", err)
	}

	fake := newSessionControlSessionDynamoFake()
	row, err := sessionControlSessionToRow(reserved)
	if err != nil {
		t.Fatal(err)
	}
	missingDue := row
	missingDue.DueSort = ""
	if _, err := sessionControlSessionFromRow(missingDue, candidate.SessionID); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("reserved row without due sort error = %v, want corrupt", err)
	}
	wrongDue := row
	wrongDue.DueShard = "SESSION#other-cell#00"
	if _, err := sessionControlSessionFromRow(wrongDue, candidate.SessionID); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("reserved row with wrong due shard error = %v, want corrupt", err)
	}
	item := marshalSessionControlSessionTestRow(t, row)
	item["ttl"] = &types.AttributeValueMemberN{Value: "1800000030"}
	fake.setItem(item)
	membership, err := sessionControlSessionMembershipToRow(candidate)
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, membership))
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	if _, err := store.ReserveSession(context.Background(), candidate, snapshot); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("TTL-bearing pending row error = %v, want corrupt", err)
	}
}

func TestDynamoSessionControlIntentRejectsImpossibleSessionPair(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*sessionControlSessionAuthority, *sessionControlSessionIntent)
	}{
		{
			name: "intent predates reservation cursor",
			mutate: func(session *sessionControlSessionAuthority, _ *sessionControlSessionIntent) {
				session.ReservedDirectoryVersion = 2
			},
		},
		{
			name: "same cursor has different active count",
			mutate: func(_ *sessionControlSessionAuthority, intent *sessionControlSessionIntent) {
				intent.PreparedActiveFenceCount = 1
			},
		},
		{
			name: "intent serving expiry differs from session",
			mutate: func(_ *sessionControlSessionAuthority, intent *sessionControlSessionIntent) {
				intent.SessionExpiresAtMillis++
			},
		},
	}
	for index, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseSnapshot := testSessionControlSessionSnapshot(1)
			candidate := testSessionControlSessionCandidate(byte(0x67+index), uint64(213+index))
			reserved, _ := planSessionControlReservation(candidate, baseSnapshot)
			target := testSessionControlSessionTarget(byte(0x69 + index))
			prepared, _ := planSessionControlIntent(reserved.fence(), target,
				candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, baseSnapshot)
			tt.mutate(&prepared.Session, &prepared.Intent)
			fake := newSessionControlSessionDynamoFake()
			seedSessionControlReservation(t, fake, prepared.Session)
			seedSessionControlIntent(t, fake, prepared.Intent)
			seedSessionControlTarget(t, fake, target)
			store := newSessionControlSessionDynamoStore(fake, time.Second)
			snapshot := testSessionControlSessionSnapshot(2)
			_, err := store.PrepareSessionIntent(context.Background(), prepared.Session.fence(), target,
				candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+150_000, snapshot)
			if !errors.Is(err, errSessionControlSessionCorrupt) {
				t.Fatalf("PrepareSessionIntent() error = %v, want corrupt", err)
			}
			if len(fake.transactions) != 0 {
				t.Fatalf("corrupt pair reached transaction: %d", len(fake.transactions))
			}
		})
	}
}

func TestDynamoSessionControlSessionStrongReadRequiresCanonicalPhysicalRow(t *testing.T) {
	candidate := testSessionControlSessionCandidate(0x87, 87)
	reserved, err := planSessionControlReservation(candidate, testSessionControlSessionSnapshot(1))
	if err != nil {
		t.Fatal(err)
	}
	row, err := sessionControlSessionToRow(reserved)
	if err != nil {
		t.Fatal(err)
	}
	canonical := marshalSessionControlSessionTestRow(t, row)
	tests := map[string]func(map[string]types.AttributeValue){
		"missing target_count": func(item map[string]types.AttributeValue) { delete(item, "target_count") },
		"missing reserved_active_fence_count": func(item map[string]types.AttributeValue) {
			delete(item, "reserved_active_fence_count")
		},
		"present zero optional": func(item map[string]types.AttributeValue) {
			item["ack_enqueued_at_ms"] = &types.AttributeValueMemberN{Value: "0"}
		},
		"unknown attribute": func(item map[string]types.AttributeValue) {
			item["unexpected_authority"] = &types.AttributeValueMemberS{Value: "unsafe"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			item := make(map[string]types.AttributeValue, len(canonical)+1)
			for key, value := range canonical {
				item[key] = value
			}
			mutate(item)
			fake := newSessionControlSessionDynamoFake()
			fake.setItem(item)
			store := newSessionControlSessionDynamoStore(fake, time.Second)
			if _, readErr := store.getSessionItem(context.Background(), candidate.SessionID); !errors.Is(readErr, errSessionControlSessionCorrupt) {
				t.Fatalf("noncanonical SESSION read = %v", readErr)
			}
		})
	}
}

func TestDynamoSessionControlIntentReadBracketRejectsTornHeader(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x5c, 207)
	reserved, _ := planSessionControlReservation(candidate, snapshot)
	target := testSessionControlSessionTarget(0x5d)
	planned, _ := planSessionControlIntent(reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlReservation(t, fake, reserved)
	seedSessionControlTarget(t, fake, target)
	forwardKey := sessionControlSessionDynamoMapKey(sessionControlSessionIntentDynamoKey(candidate.SessionID, target))
	var once sync.Once
	fake.getHook = func(ctx context.Context, input *dynamodb.GetItemInput, _ int) (*dynamodb.GetItemOutput, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if sessionControlSessionDynamoMapKey(input.Key) == forwardKey {
			once.Do(func() {
				seedSessionControlReservation(t, fake, planned.Session)
				seedSessionControlIntent(t, fake, planned.Intent)
			})
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return &dynamodb.GetItemOutput{Item: fake.items[sessionControlSessionDynamoMapKey(input.Key)]}, nil
	}
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	_, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	if !errors.Is(err, errSessionControlSessionConflict) {
		t.Fatalf("PrepareSessionIntent() error = %v, want stale-fence conflict", err)
	}
	if len(fake.transactions) != 0 {
		t.Fatalf("torn header reached transaction: %d", len(fake.transactions))
	}
}

func TestDynamoSessionControlIntentReadBracketRetriesTornProcessExtension(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x6d, 218)
	reserved, _ := planSessionControlReservation(candidate, snapshot)
	target := testSessionControlSessionTarget(0x6e)
	first, _ := planSessionControlIntent(reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	reactivated := target
	reactivated.Version += 2
	reactivated.AuthorityVersion += 2
	reactivated.PreparedAtMillis++
	reactivated.UpdatedAtMillis++
	reactivated.AAKEnqueuedAtMillis = reactivated.UpdatedAtMillis
	reactivated.AAKTransactionID++
	planned, err := planSessionControlIntentExtension(first.Session, first.Session.fence(), first.Intent, reactivated,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+150_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlReservation(t, fake, first.Session)
	seedSessionControlIntent(t, fake, first.Intent)
	seedSessionControlTarget(t, fake, reactivated)
	forwardKey := sessionControlSessionDynamoMapKey(sessionControlSessionIntentDynamoKey(candidate.SessionID, reactivated))
	var once sync.Once
	fake.getHook = func(ctx context.Context, input *dynamodb.GetItemInput, _ int) (*dynamodb.GetItemOutput, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if sessionControlSessionDynamoMapKey(input.Key) == forwardKey {
			once.Do(func() {
				seedSessionControlReservation(t, fake, planned.Session)
				seedSessionControlIntent(t, fake, planned.Intent)
			})
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return &dynamodb.GetItemOutput{Item: fake.items[sessionControlSessionDynamoMapKey(input.Key)]}, nil
	}
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	_, err = store.PrepareSessionIntent(context.Background(), first.Session.fence(), reactivated,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+150_000, snapshot)
	if !errors.Is(err, errSessionControlSessionConflict) {
		t.Fatalf("PrepareSessionIntent() error = %v, want refreshed-fence conflict", err)
	}
	if len(fake.transactions) != 0 {
		t.Fatalf("torn process extension reached transaction: %d", len(fake.transactions))
	}
	forward, err := store.getIntentItem(context.Background(), candidate, reactivated, false)
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := store.getIntentItem(context.Background(), candidate, reactivated, true)
	if err != nil || *forward != *reverse || *forward != planned.Intent {
		t.Fatalf("stable process pair = %#v/%#v, %v; want %#v", forward, reverse, err, planned.Intent)
	}
}

func TestDynamoSessionControlPrepareCurrentRetriesConcurrentFanoutCAS(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x70, 220)
	reserved, _ := planSessionControlReservation(candidate, snapshot)
	requestedTarget := testSessionControlSessionTarget(0x71)
	concurrentTarget := testSessionControlSessionTarget(0x72)
	concurrent, _ := planSessionControlIntent(reserved.fence(), concurrentTarget,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlReservation(t, fake, reserved)
	seedSessionControlDirectory(t, fake, snapshot)
	seedSessionControlTarget(t, fake, requestedTarget)
	seedSessionControlTarget(t, fake, concurrentTarget)
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	var calls int
	fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		calls++
		if calls == 1 {
			seedSessionControlReservation(t, fake, concurrent.Session)
			seedSessionControlIntent(t, fake, concurrent.Intent)
			return nil, &types.TransactionCanceledException{}
		}
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}
	prepared, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, requestedTarget,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+150_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || prepared.Session.Version != 3 || prepared.Session.TargetCount != 2 ||
		prepared.Intent.Target != requestedTarget {
		t.Fatalf("current-fence retry = %#v calls=%d", prepared, calls)
	}
}

func TestDynamoSessionControlPrepareCurrentUsesFullFanoutRetryBudget(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x78, 224)
	current, _ := planSessionControlReservation(candidate, snapshot)
	requestedTarget := testSessionControlSessionTarget(0x79)
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlReservation(t, fake, current)
	seedSessionControlDirectory(t, fake, snapshot)
	seedSessionControlTarget(t, fake, requestedTarget)
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	var calls int
	fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		calls++
		if calls <= MaxACConnsPerID {
			competitor := testSessionControlSessionTarget(byte(0x80 + calls))
			competing, err := planSessionControlIntent(current.fence(), competitor,
				candidate.IssuedAtMillis+120_000, candidate.IssuedAtMillis+150_000+int64(calls), snapshot)
			if err != nil {
				t.Fatal(err)
			}
			current = competing.Session
			seedSessionControlReservation(t, fake, competing.Session)
			seedSessionControlIntent(t, fake, competing.Intent)
			return nil, &types.TransactionCanceledException{}
		}
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}
	prepared, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, requestedTarget,
		candidate.IssuedAtMillis+120_000, candidate.IssuedAtMillis+150_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if calls != sessionControlSessionFanoutAttempts || prepared.Session.Version != current.Version+1 ||
		prepared.Session.TargetCount != current.TargetCount+1 {
		t.Fatalf("fanout retry budget result = %#v calls=%d, want %d", prepared, calls, sessionControlSessionFanoutAttempts)
	}
}

func TestDynamoSessionControlPrepareCurrentStopsAfterFanoutRetryBudget(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x7a, 225)
	current, _ := planSessionControlReservation(candidate, snapshot)
	requestedTarget := testSessionControlSessionTarget(0x7b)
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlReservation(t, fake, current)
	seedSessionControlDirectory(t, fake, snapshot)
	seedSessionControlTarget(t, fake, requestedTarget)
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	var calls int
	fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		calls++
		competitor := testSessionControlSessionTarget(byte(0xa0 + calls))
		competing, err := planSessionControlIntent(current.fence(), competitor,
			candidate.IssuedAtMillis+120_000, candidate.IssuedAtMillis+150_000+int64(calls), snapshot)
		if err != nil {
			t.Fatal(err)
		}
		current = competing.Session
		seedSessionControlReservation(t, fake, competing.Session)
		seedSessionControlIntent(t, fake, competing.Intent)
		return nil, &types.TransactionCanceledException{}
	}
	_, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, requestedTarget,
		candidate.IssuedAtMillis+120_000, candidate.IssuedAtMillis+150_000, snapshot)
	if !errors.Is(err, errSessionControlSessionConflict) {
		t.Fatalf("PrepareSessionIntentCurrent() error = %v, want retry exhaustion conflict", err)
	}
	if calls != sessionControlSessionFanoutAttempts {
		t.Fatalf("fanout retry attempts = %d, want %d", calls, sessionControlSessionFanoutAttempts)
	}
}

func TestDynamoSessionControlVerifySessionUsesStrongExactDirectoryRead(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x73, 221)
	reserved, _ := planSessionControlReservation(candidate, snapshot)
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlReservation(t, fake, reserved)
	seedSessionControlDirectory(t, fake, snapshot)
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	verified, err := store.VerifySession(context.Background(), candidate, snapshot)
	if err != nil || *verified != reserved {
		t.Fatalf("VerifySession() = %#v, %v; want %#v", verified, err, reserved)
	}
	if len(fake.gets) != 4 || len(fake.transactions) != 0 {
		t.Fatalf("VerifySession reads/transactions = %d/%d, want 4/0", len(fake.gets), len(fake.transactions))
	}
	for _, input := range fake.gets {
		if !aws.ToBool(input.ConsistentRead) {
			t.Fatalf("VerifySession read was not strong: %#v", input)
		}
	}
	store.nowUTC = func() time.Time { return time.UnixMilli(candidate.ReservationDeadlineMillis - 1).UTC() }
	if _, err := store.VerifySession(context.Background(), candidate, snapshot); err != nil {
		t.Fatalf("VerifySession before provisional deadline: %v", err)
	}
	store.nowUTC = func() time.Time { return time.UnixMilli(candidate.ReservationDeadlineMillis).UTC() }
	if _, err := store.VerifySession(context.Background(), candidate, snapshot); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("VerifySession at provisional deadline error = %v, want denied", err)
	}
	acked := reserved
	acked.State = sessionControlSessionStateAckEnqueued
	acked.Version = 2
	acked.TargetCount = 1
	acked.SessionExpiresAtMillis = candidate.IssuedAtMillis + 60_000
	acked.RetainUntilMillis = candidate.IssuedAtMillis + 90_000
	acked.AckEnqueuedAtMillis = candidate.IssuedAtMillis + 10_000
	seedSessionControlReservation(t, fake, acked)
	if _, err := store.VerifySession(context.Background(), candidate, snapshot); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("VerifySession ACK state error = %v, want denied", err)
	}
}

func TestDynamoSessionControlMarkAckEnqueuedExactWire(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x74, 222)
	reserved, _ := planSessionControlReservation(candidate, snapshot)
	target := testSessionControlSessionTarget(0x75)
	prepared, _ := planSessionControlIntent(reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlReservation(t, fake, prepared.Session)
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	acked, err := store.MarkSessionAckEnqueued(context.Background(), candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if acked.State != sessionControlSessionStateAckEnqueued || acked.Version != prepared.Session.Version ||
		acked.TargetCount != prepared.Session.TargetCount || acked.AckEnqueuedAtMillis != 1_800_000_010_000 {
		t.Fatalf("ACK authority = %#v", acked)
	}
	if len(fake.transactions) != 1 || len(fake.transactions[0].TransactItems) != 2 {
		t.Fatalf("ACK transaction = %#v", fake.transactions)
	}
	txn := fake.transactions[0]
	if aws.ToString(txn.ClientRequestToken) == "" || len(aws.ToString(txn.ClientRequestToken)) > 36 ||
		txn.TransactItems[0].ConditionCheck == nil || txn.TransactItems[1].Update == nil {
		t.Fatalf("ACK transaction shape = %#v", txn)
	}
	directory := txn.TransactItems[0].ConditionCheck
	if !strings.Contains(aws.ToString(directory.ConditionExpression), "#version = :version") ||
		!strings.Contains(aws.ToString(directory.ConditionExpression), "active_fence_count = :count") {
		t.Fatalf("ACK directory condition = %#v", directory)
	}
	update := txn.TransactItems[1].Update
	values := sessionControlAttributeWireMap(t, update.ExpressionAttributeValues)
	if aws.ToString(update.UpdateExpression) != "SET #state = :next_state, ack_enqueued_at_ms = :ack_enqueued_at REMOVE due_shard, due_sort" ||
		sessionControlWireString(t, values, ":state", "S") != sessionControlSessionStateReserved ||
		sessionControlWireString(t, values, ":next_state", "S") != sessionControlSessionStateAckEnqueued ||
		sessionControlWireString(t, values, ":ack_enqueued_at", "N") != "1800000010000" ||
		sessionControlWireString(t, values, ":due_shard", "S") != sessionControlSessionDueShard(candidate) ||
		sessionControlWireString(t, values, ":due_sort", "S") != sessionControlSessionDueSort(candidate) ||
		sessionControlWireString(t, values, ":version", "N") != fmt.Sprint(prepared.Session.Version) ||
		sessionControlWireString(t, values, ":session_expires_at", "N") != fmt.Sprint(prepared.Session.SessionExpiresAtMillis) ||
		!strings.Contains(aws.ToString(update.ConditionExpression), "session_expires_at_ms = :session_expires_at") ||
		!strings.Contains(aws.ToString(update.ConditionExpression), "due_shard = :due_shard") ||
		!strings.Contains(aws.ToString(update.ConditionExpression), "attribute_not_exists(ack_enqueued_at_ms)") ||
		!strings.Contains(aws.ToString(update.ConditionExpression), "attribute_not_exists(close_event_id)") ||
		!strings.Contains(aws.ToString(update.ConditionExpression), "attribute_not_exists(#ttl)") || update.ExpressionAttributeNames["#ttl"] != "ttl" {
		t.Fatalf("ACK session CAS = %#v", update)
	}
}

func TestDynamoSessionControlServingExpiryBoundaries(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x7c, 226)
	reserved, _ := planSessionControlReservation(candidate, snapshot)
	target := testSessionControlSessionTarget(0x7d)
	expiresAt := candidate.IssuedAtMillis + 60_000
	fake := newSessionControlSessionDynamoFake()
	seedSessionControlReservation(t, fake, reserved)
	seedSessionControlDirectory(t, fake, snapshot)
	seedSessionControlTarget(t, fake, target)
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	store.nowUTC = func() time.Time { return time.UnixMilli(expiresAt).UTC() }
	if _, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
		expiresAt, candidate.IssuedAtMillis+90_000, snapshot); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("first intent at serving expiry error = %v, want denied", err)
	}
	if len(fake.transactions) != 0 {
		t.Fatalf("expired first intent wrote %d transactions", len(fake.transactions))
	}
	prepared, err := planSessionControlIntent(reserved.fence(), target,
		expiresAt, candidate.IssuedAtMillis+90_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionControlReservation(t, fake, prepared.Session)
	store.nowUTC = func() time.Time { return time.UnixMilli(expiresAt - 1).UTC() }
	if got, err := store.VerifySession(context.Background(), candidate, snapshot); err != nil || *got != prepared.Session {
		t.Fatalf("VerifySession before serving expiry = %#v, %v; want %#v", got, err, prepared.Session)
	}
	store.nowUTC = func() time.Time { return time.UnixMilli(expiresAt).UTC() }
	if _, err := store.VerifySession(context.Background(), candidate, snapshot); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("VerifySession at serving expiry error = %v, want denied", err)
	}
	if _, err := store.MarkSessionAckEnqueued(context.Background(), candidate, snapshot); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("first ACK at serving expiry error = %v, want denied", err)
	}
	if len(fake.transactions) != 0 {
		t.Fatalf("expired first ACK wrote %d transactions", len(fake.transactions))
	}
	acked := prepared.Session
	acked.State = sessionControlSessionStateAckEnqueued
	acked.AckEnqueuedAtMillis = expiresAt - 1
	seedSessionControlReservation(t, fake, acked)
	store.nowUTC = func() time.Time { return time.UnixMilli(expiresAt + 1).UTC() }
	got, err := store.MarkSessionAckEnqueued(context.Background(), candidate, snapshot)
	if err != nil || *got != acked {
		t.Fatalf("post-expiry ACK replay = %#v, %v; want %#v", got, err, acked)
	}
}

func TestDynamoSessionControlRejectsServingExpiryChangeAcrossFanout(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	candidate := testSessionControlSessionCandidate(0x7e, 227)
	reserved, _ := planSessionControlReservation(candidate, snapshot)
	firstTarget := testSessionControlSessionTarget(0x7f)
	first, err := planSessionControlIntent(reserved.fence(), firstTarget,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		target sessionControlTargetAuthority
	}{
		{name: "same target extension", target: firstTarget},
		{name: "later target", target: testSessionControlSessionTarget(0x80)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := newSessionControlSessionDynamoFake()
			seedSessionControlReservation(t, fake, first.Session)
			seedSessionControlIntent(t, fake, first.Intent)
			seedSessionControlDirectory(t, fake, snapshot)
			seedSessionControlTarget(t, fake, tt.target)
			store := newSessionControlSessionDynamoStore(fake, time.Second)
			_, err := store.PrepareSessionIntent(context.Background(), first.Session.fence(), tt.target,
				candidate.IssuedAtMillis+60_001, candidate.IssuedAtMillis+90_001, snapshot)
			if !errors.Is(err, errSessionControlSessionConflict) {
				t.Fatalf("PrepareSessionIntent() error = %v, want immutable-expiry conflict", err)
			}
			if len(fake.transactions) != 0 {
				t.Fatalf("changed serving expiry wrote %d transactions", len(fake.transactions))
			}
		})
	}
}

func TestDynamoSessionControlMarkAckClassifiesAmbiguousCommitAndCloseWinner(t *testing.T) {
	newFixture := func(t *testing.T) (*sessionControlSessionDynamoFake, *dynamoSessionControlStore,
		sessionControlSessionCandidate, sessionControlSessionAuthority, sessionControlFenceSnapshot) {
		t.Helper()
		snapshot := testSessionControlSessionSnapshot(1)
		candidate := testSessionControlSessionCandidate(0x76, 223)
		reserved, _ := planSessionControlReservation(candidate, snapshot)
		target := testSessionControlSessionTarget(0x77)
		prepared, _ := planSessionControlIntent(reserved.fence(), target,
			candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
		fake := newSessionControlSessionDynamoFake()
		seedSessionControlReservation(t, fake, prepared.Session)
		seedSessionControlDirectory(t, fake, snapshot)
		return fake, newSessionControlSessionDynamoStore(fake, time.Millisecond), candidate, prepared.Session, snapshot
	}
	t.Run("idempotent ACK preserves first timestamp", func(t *testing.T) {
		fake, store, candidate, admitted, snapshot := newFixture(t)
		first := admitted
		first.State = sessionControlSessionStateAckEnqueued
		first.AckEnqueuedAtMillis = candidate.IssuedAtMillis + 7_000
		seedSessionControlReservation(t, fake, first)
		store.nowUTC = func() time.Time { return time.UnixMilli(candidate.IssuedAtMillis + 20_000).UTC() }
		got, err := store.MarkSessionAckEnqueued(context.Background(), candidate, snapshot)
		if err != nil || *got != first {
			t.Fatalf("MarkSessionAckEnqueued() = %#v, %v; want %#v", got, err, first)
		}
		if len(fake.transactions) != 0 {
			t.Fatalf("idempotent ACK wrote %d transactions", len(fake.transactions))
		}
	})
	t.Run("ambiguous ACK commit", func(t *testing.T) {
		fake, store, candidate, admitted, snapshot := newFixture(t)
		planned := admitted
		planned.State = sessionControlSessionStateAckEnqueued
		planned.AckEnqueuedAtMillis = 1_800_000_010_000
		fake.transactHook = func(ctx context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			<-ctx.Done()
			seedSessionControlReservation(t, fake, planned)
			return nil, ctx.Err()
		}
		got, err := store.MarkSessionAckEnqueued(context.Background(), candidate, snapshot)
		if err != nil || *got != planned {
			t.Fatalf("MarkSessionAckEnqueued() = %#v, %v; want %#v", got, err, planned)
		}
	})
	t.Run("concurrent ACK keeps winning timestamp", func(t *testing.T) {
		fake, store, candidate, admitted, snapshot := newFixture(t)
		winner := admitted
		winner.State = sessionControlSessionStateAckEnqueued
		winner.AckEnqueuedAtMillis = candidate.IssuedAtMillis + 5_000
		store.nowUTC = func() time.Time { return time.UnixMilli(candidate.IssuedAtMillis + 10_000).UTC() }
		fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			seedSessionControlReservation(t, fake, winner)
			return nil, &types.TransactionCanceledException{}
		}
		got, err := store.MarkSessionAckEnqueued(context.Background(), candidate, snapshot)
		if err != nil || *got != winner {
			t.Fatalf("MarkSessionAckEnqueued() = %#v, %v; want winner %#v", got, err, winner)
		}
	})
	t.Run("close wins", func(t *testing.T) {
		fake, store, candidate, admitted, snapshot := newFixture(t)
		closing := admitted
		closing.State = sessionControlSessionStateClosing
		closing.CloseEventID = "76767676767676767676767676767676"
		closing.ClosePreparedDirectory = 2
		closing.ClosePreparedAtMillis = closing.Candidate.IssuedAtMillis + 1
		fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			seedSessionControlReservation(t, fake, closing)
			seedSessionControlDirectory(t, fake, testSessionControlSessionSnapshot(2))
			return nil, &types.TransactionCanceledException{}
		}
		_, err := store.MarkSessionAckEnqueued(context.Background(), candidate, snapshot)
		if !errors.Is(err, errSessionControlSessionFenceStale) {
			t.Fatalf("MarkSessionAckEnqueued() error = %v, want close-winner stale fence", err)
		}
	})
}

func TestSessionControlSessionFixedWidthKeysPreserveNumericOrder(t *testing.T) {
	if got, want := sessionControlSessionIDText(9), "00000000000000000009"; got != want {
		t.Fatalf("session id key = %q, want %q", got, want)
	}
	if !(sessionControlSessionMembershipSK(99, 10) < sessionControlSessionMembershipSK(100, 1)) {
		t.Fatalf("issued membership keys are not numerically ordered: %q >= %q",
			sessionControlSessionMembershipSK(99, 10), sessionControlSessionMembershipSK(100, 1))
	}
	if got := len(aws.ToString(sessionControlSessionToken("intent", fmt.Sprint(^uint64(0))))); got > 36 {
		t.Fatalf("client token length = %d, want <= 36", got)
	}
	candidate := testSessionControlSessionCandidate(0x81, 9)
	if got, want := sessionControlSessionDueShard(candidate), "SESSION#reserved#cell-01#09"; got != want {
		t.Fatalf("session due shard = %q, want %q", got, want)
	}
	if got, want := sessionControlClosingSessionDueShard(candidate), "SESSION#closing#cell-01#09"; got != want {
		t.Fatalf("closing session due shard = %q, want %q", got, want)
	}
	otherCell := candidate
	otherCell.CellID = "cell-02"
	if sessionControlSessionDueShard(otherCell) == sessionControlSessionDueShard(candidate) {
		t.Fatal("session due shard did not bind the cell")
	}
	if got, want := sessionControlSessionDueSort(candidate), "0000001800000030000#00000000000000000009"; got != want {
		t.Fatalf("session due sort = %q, want %q", got, want)
	}
}
