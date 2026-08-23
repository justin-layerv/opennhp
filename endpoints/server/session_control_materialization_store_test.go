package server

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type sessionControlMaterializationFixture struct {
	fake      *sessionControlSessionDynamoFake
	store     *dynamoSessionControlStore
	candidate sessionControlSessionCandidate
	close     sessionControlExactClosePreparation
	intents   []sessionControlSessionIntent
}

func redigestSessionControlCloseTask(t *testing.T, task *sessionControlCloseTask) {
	t.Helper()
	digest, err := sessionControlCloseTaskCreationDigest(*task)
	if err != nil {
		t.Fatal(err)
	}
	task.CreationDigest = digest
	task.LastOperationID = digest
}

func redigestSessionControlCloseManifest(t *testing.T, manifest *sessionControlCloseManifest) {
	t.Helper()
	digest, err := sessionControlCloseManifestDigest(*manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ManifestDigest = digest
}

func redigestSessionControlCloseTaskSet(t *testing.T, taskSet *sessionControlCloseTaskSet) {
	t.Helper()
	digest, err := sessionControlCloseTaskSetDigest(*taskSet)
	if err != nil {
		t.Fatal(err)
	}
	taskSet.TaskSetDigest = digest
}

func installSessionControlMaterializationQuery(t *testing.T, fake *sessionControlSessionDynamoFake) {
	t.Helper()
	fake.queryHook = func(ctx context.Context, input *dynamodb.QueryInput, _ int) (*dynamodb.QueryOutput, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pk, _ := input.ExpressionAttributeValues[":pk"].(*types.AttributeValueMemberS)
		prefix, _ := input.ExpressionAttributeValues[":prefix"].(*types.AttributeValueMemberS)
		if pk == nil || prefix == nil || !aws.ToBool(input.ConsistentRead) {
			return nil, errors.New("malformed materialization query")
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		keys := make([]string, 0)
		for key, item := range fake.items {
			itemPK, _ := item["pk"].(*types.AttributeValueMemberS)
			itemSK, _ := item["sk"].(*types.AttributeValueMemberS)
			if itemPK != nil && itemSK != nil && itemPK.Value == pk.Value && strings.HasPrefix(itemSK.Value, prefix.Value) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		start := 0
		if len(input.ExclusiveStartKey) > 0 {
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
		items := make([]map[string]types.AttributeValue, 0, limit)
		for _, key := range keys[start : start+limit] {
			items = append(items, fake.items[key])
		}
		var last map[string]types.AttributeValue
		if start+limit < len(keys) && limit > 0 {
			item := fake.items[keys[start+limit-1]]
			last = map[string]types.AttributeValue{"pk": item["pk"], "sk": item["sk"]}
		}
		return &dynamodb.QueryOutput{Items: items, LastEvaluatedKey: last}, nil
	}
}

func applySessionControlMaterializationTransaction(fake *sessionControlSessionDynamoFake,
	input *dynamodb.TransactWriteItemsInput) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, member := range input.TransactItems {
		if member.Put != nil {
			fake.items[sessionControlSessionDynamoMapKey(member.Put.Item)] = member.Put.Item
		}
	}
}

func newSessionControlMaterializationFixture(t *testing.T, count int) sessionControlMaterializationFixture {
	t.Helper()
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, 10*time.Second)
	installSessionControlMaterializationQuery(t, fake)
	fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		applySessionControlMaterializationTransaction(fake, input)
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}
	candidate := testSessionControlSessionCandidate(0xd1, 1901)
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
		target.ACID = fmt.Sprintf("ac-materialize-%04d", index)
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
	close := expectedSessionControlExactClose(t, current, directory, store.nowUTC().UnixMilli(), retain)
	seedCommittedSessionControlExactClose(t, fake, directory, close)
	return sessionControlMaterializationFixture{fake: fake, store: store, candidate: candidate, close: close, intents: intents}
}

func TestDynamoSessionControlMaterializeNormalExactCloseTransactionArithmetic(t *testing.T) {
	tests := []struct {
		count            int
		transactionSizes []int
	}{
		{count: 0, transactionSizes: []int{3}},
		{count: 1, transactionSizes: []int{5, 4}},
		{count: 48, transactionSizes: []int{99, 4}},
		{count: 49, transactionSizes: []int{99, 5, 5}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.count), func(t *testing.T) {
			fixture := newSessionControlMaterializationFixture(t, tt.count)
			result, err := fixture.store.MaterializeNormalExactClose(context.Background(), fixture.candidate, fixture.close.EventID)
			if err != nil {
				t.Fatal(err)
			}
			if result.SourceCount != uint64(tt.count) || result.ExpectedTargetCount != uint64(tt.count) ||
				result.OwnerCount != uint64(tt.count) || len(fixture.fake.transactions) != len(tt.transactionSizes) {
				t.Fatalf("result/transactions = %#v/%d", result, len(fixture.fake.transactions))
			}
			for index, size := range tt.transactionSizes {
				txn := fixture.fake.transactions[index]
				if len(txn.TransactItems) != size || len(aws.ToString(txn.ClientRequestToken)) > 36 {
					t.Fatalf("transaction %d = %d/%q", index, len(txn.TransactItems), aws.ToString(txn.ClientRequestToken))
				}
			}
		})
	}
}

func TestDynamoSessionControlMaterializeNormalExactCloseTwentyTwoChunksAt1024(t *testing.T) {
	fixture := newSessionControlMaterializationFixture(t, int(sessionControlSessionMaxTargets))
	result, err := fixture.store.MaterializeNormalExactClose(context.Background(), fixture.candidate, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ManifestDigests) != sessionControlCloseManifestLimit || len(fixture.fake.transactions) != sessionControlCloseManifestLimit+1 {
		t.Fatalf("manifests/txns = %d/%d", len(result.ManifestDigests), len(fixture.fake.transactions))
	}
	for index, txn := range fixture.fake.transactions[:sessionControlCloseManifestLimit] {
		want := 99
		if index == sessionControlCloseManifestLimit-1 {
			want = 35
		}
		if len(txn.TransactItems) != want {
			t.Fatalf("manifest transaction %d = %d, want %d", index, len(txn.TransactItems), want)
		}
	}
	if got := len(fixture.fake.transactions[len(fixture.fake.transactions)-1].TransactItems); got != 25 {
		t.Fatalf("taskset transaction = %d", got)
	}
}

func TestDynamoSessionControlMaterializeNormalExactCloseReplayIgnoresMutableTaskProgress(t *testing.T) {
	fixture := newSessionControlMaterializationFixture(t, 1)
	first, err := fixture.store.MaterializeNormalExactClose(context.Background(), fixture.candidate, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	transactions := len(fixture.fake.transactions)
	ownerPK := sessionControlOwnerPK(fixture.intents[0].Target.ControlCellID, fixture.intents[0].Target.ACID, fixture.intents[0].Target.PublicKey)
	key := ownerPK + "\x00" + sessionControlCloseTaskSK(fixture.close.EventID)
	fixture.fake.mu.Lock()
	fixture.fake.items[key]["task_version"] = &types.AttributeValueMemberN{Value: "2"}
	fixture.fake.items[key]["state"] = &types.AttributeValueMemberS{Value: "leased"}
	fixture.fake.mu.Unlock()
	second, err := fixture.store.MaterializeNormalExactClose(context.Background(), fixture.candidate, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if first.TaskSetDigest != second.TaskSetDigest || len(fixture.fake.transactions) != transactions {
		t.Fatalf("replay = %#v/%#v txns=%d", first, second, len(fixture.fake.transactions))
	}
}

func TestDynamoSessionControlMaterializeNormalExactCloseResumesAfterFirstChunk(t *testing.T) {
	fixture := newSessionControlMaterializationFixture(t, 49)
	calls := 0
	fixture.fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("transport failed before commit")
		}
		applySessionControlMaterializationTransaction(fixture.fake, input)
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}
	if _, err := fixture.store.MaterializeNormalExactClose(context.Background(), fixture.candidate, fixture.close.EventID); err == nil {
		t.Fatal("missing interrupted materialization error")
	}
	firstManifestToken := aws.ToString(fixture.fake.transactions[0].ClientRequestToken)
	if _, err := fixture.store.MaterializeNormalExactClose(context.Background(), fixture.candidate, fixture.close.EventID); err != nil {
		t.Fatal(err)
	}
	for _, txn := range fixture.fake.transactions[2:] {
		if aws.ToString(txn.ClientRequestToken) == firstManifestToken {
			t.Fatal("committed first manifest was emitted again")
		}
	}
}

func TestDynamoSessionControlMaterializeAcceptsCloseRetentionExtensionBeforeSourceRead(t *testing.T) {
	fixture := newSessionControlMaterializationFixture(t, 1)
	extended := fixture.close.Session
	extended.RetainUntilMillis += time.Minute.Milliseconds()
	seedSessionControlReservation(t, fixture.fake, extended)
	if _, err := fixture.store.MaterializeNormalExactClose(context.Background(), fixture.candidate, fixture.close.EventID); err != nil {
		t.Fatal(err)
	}
}

func TestDynamoSessionControlMaterializeSessionCASAllowsRetentionExtensionBetweenReadAndWrite(t *testing.T) {
	fixture := newSessionControlMaterializationFixture(t, 1)
	extended := fixture.close.Session
	extended.RetainUntilMillis += time.Minute.Milliseconds()
	fixture.fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		if len(fixture.fake.transactions) == 1 {
			seedSessionControlReservation(t, fixture.fake, extended)
			condition := input.TransactItems[0].ConditionCheck
			if condition == nil || !strings.Contains(aws.ToString(condition.ConditionExpression), "#exact_retain >= :exact_min_retain") {
				t.Fatalf("session condition = %#v", condition)
			}
		}
		applySessionControlMaterializationTransaction(fixture.fake, input)
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}
	if _, err := fixture.store.MaterializeNormalExactClose(context.Background(), fixture.candidate, fixture.close.EventID); err != nil {
		t.Fatal(err)
	}
}

func TestSessionControlCloseSourceGroupsRejectEqualGenerationDifferentBootAtLowerGeneration(t *testing.T) {
	fixture := newSessionControlMaterializationFixture(t, 1)
	base := fixture.intents[0]
	intents := []sessionControlSessionIntent{base, base, base}
	intents[0].Target.FlushGeneration, intents[0].Target.BootID = 1, "11111111111111111111111111111111"
	intents[1].Target.FlushGeneration, intents[1].Target.BootID = 2, "22222222222222222222222222222222"
	intents[2].Target.FlushGeneration, intents[2].Target.BootID = 1, "33333333333333333333333333333333"
	for index := range intents {
		owner, err := sessionControlOwnerFromTarget(intents[index].Target, nil, sessionControlOwnerReady)
		if err != nil {
			t.Fatal(err)
		}
		intents[index].Owner = owner
	}
	if _, err := sessionControlCloseSourceGroups(intents); !errors.Is(err, errSessionControlMaterializationCorrupt) {
		t.Fatalf("error = %v", err)
	}
}

func TestSessionControlCloseSourceDigestBindsEveryIntentField(t *testing.T) {
	fixture := newSessionControlMaterializationFixture(t, 1)
	base := fixture.intents
	want, err := sessionControlCloseSourceDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*sessionControlSessionIntent){
		func(v *sessionControlSessionIntent) { v.State = "changed" },
		func(v *sessionControlSessionIntent) { v.SessionVersion++ },
		func(v *sessionControlSessionIntent) { v.SessionExpiresAtMillis++ },
		func(v *sessionControlSessionIntent) { v.RetainUntilMillis++ },
		func(v *sessionControlSessionIntent) { v.PreparedDirectoryVersion++ },
		func(v *sessionControlSessionIntent) { v.PreparedActiveFenceCount++ },
		func(v *sessionControlSessionIntent) { v.Target.Version++ },
		func(v *sessionControlSessionIntent) { v.Owner.WorkVersion++ },
	}
	for index, mutate := range mutations {
		copyIntent := append([]sessionControlSessionIntent(nil), base...)
		mutate(&copyIntent[0])
		got, digestErr := sessionControlCloseSourceDigest(copyIntent)
		if digestErr != nil || got == want {
			t.Fatalf("mutation %d digest = %q/%v", index, got, digestErr)
		}
	}
}

func TestDynamoSessionControlMaterializeLostResponsesClassifyCommittedManifestAndTaskSet(t *testing.T) {
	fixture := newSessionControlMaterializationFixture(t, 1)
	fixture.fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		applySessionControlMaterializationTransaction(fixture.fake, input)
		return nil, errors.New("response lost after commit")
	}
	result, err := fixture.store.MaterializeNormalExactClose(context.Background(), fixture.candidate, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if result.SourceCount != 1 || len(fixture.fake.transactions) != 2 {
		t.Fatalf("result/transactions = %#v/%d", result, len(fixture.fake.transactions))
	}
}

func TestDynamoSessionControlMaterializeDetectsTornSourceCount(t *testing.T) {
	for _, mutation := range []string{"missing", "extra"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := newSessionControlMaterializationFixture(t, 1)
			if mutation == "missing" {
				key := sessionControlSessionDynamoMapKey(sessionControlSessionIntentDynamoKey(fixture.candidate.SessionID, fixture.intents[0].Target))
				fixture.fake.mu.Lock()
				delete(fixture.fake.items, key)
				fixture.fake.mu.Unlock()
			} else {
				extra := fixture.intents[0]
				extra.Target.ACID = "ac-materialize-extra"
				owner, err := sessionControlOwnerFromTarget(extra.Target, nil, sessionControlOwnerReady)
				if err != nil {
					t.Fatal(err)
				}
				extra.Owner = owner
				seedSessionControlIntent(t, fixture.fake, extra)
			}
			if _, err := fixture.store.MaterializeNormalExactClose(context.Background(), fixture.candidate, fixture.close.EventID); !errors.Is(err, errSessionControlMaterializationCorrupt) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestDynamoSessionControlMaterializeUsesStrictlyHigherCurrentTarget(t *testing.T) {
	fixture := newSessionControlMaterializationFixture(t, 1)
	current := fixture.intents[0].Target
	current.BootID = "44444444444444444444444444444444"
	current.FlushGeneration++
	current.Version++
	current.AuthorityVersion++
	current.PreparedAtMillis = current.UpdatedAtMillis + 1
	current.UpdatedAtMillis = current.PreparedAtMillis
	current.AAKEnqueuedAtMillis = current.PreparedAtMillis + 1
	current.UpdatedAtMillis = current.AAKEnqueuedAtMillis
	seedSessionControlTarget(t, fixture.fake, current)
	if _, err := fixture.store.MaterializeNormalExactClose(context.Background(), fixture.candidate, fixture.close.EventID); err != nil {
		t.Fatal(err)
	}
	ownerPK := sessionControlOwnerPK(current.ControlCellID, current.ACID, current.PublicKey)
	fixture.fake.mu.Lock()
	item := fixture.fake.items[ownerPK+"\x00"+sessionControlCloseTaskSK(fixture.close.EventID)]
	fixture.fake.mu.Unlock()
	task, err := sessionControlCloseTaskFromItem(item, ownerPK, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if task.SourceFlushGeneration != fixture.intents[0].Target.FlushGeneration || task.BoundFlushGeneration != current.FlushGeneration {
		t.Fatalf("task source/binding = %#v", task)
	}
}

func TestDynamoSessionControlMaterializeRejectsCurrentTargetGenerationAndCapacityConflicts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*sessionControlTargetAuthority, *sessionControlOwnerAuthority)
		want   error
	}{
		{name: "equal generation different boot", mutate: func(target *sessionControlTargetAuthority, owner *sessionControlOwnerAuthority) {
			target.BootID = "55555555555555555555555555555555"
			owner.BootID = target.BootID
		}},
		{name: "current generation lower", mutate: func(target *sessionControlTargetAuthority, owner *sessionControlOwnerAuthority) {
			target.FlushGeneration--
			owner.FlushGeneration = target.FlushGeneration
		}},
		{name: "normal slot 1024 reserved", mutate: func(_ *sessionControlTargetAuthority, owner *sessionControlOwnerAuthority) {
			owner.Phase = sessionControlOwnerActiveUnready
			owner.TaskCount = sessionControlNormalCloseTaskLimit
			owner.PendingCount = 1
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newSessionControlMaterializationFixture(t, 1)
			target := fixture.intents[0].Target
			owner, err := sessionControlOwnerFromTarget(target, nil, sessionControlOwnerReady)
			if err != nil {
				t.Fatal(err)
			}
			tt.mutate(&target, &owner)
			if validateSessionControlTargetAuthority(target) != nil || validateSessionControlOwnerAuthority(owner) != nil || !owner.exactTarget(target, owner.Phase) {
				t.Fatalf("bad fixture target/owner = %#v/%#v", target, owner)
			}
			targetRow, _ := sessionControlTargetToRow(target)
			ownerRow, _ := sessionControlOwnerToRow(owner)
			fixture.fake.setItem(marshalSessionControlSessionTestRow(t, targetRow))
			fixture.fake.setItem(marshalSessionControlSessionTestRow(t, ownerRow))
			_, got := fixture.store.MaterializeNormalExactClose(context.Background(), fixture.candidate, fixture.close.EventID)
			if got == nil {
				t.Fatal("materialization accepted conflict")
			}
		})
	}
}

func TestSessionControlMaterializationStrictRowPresenceAndCountBounds(t *testing.T) {
	fixture := newSessionControlMaterializationFixture(t, 1)
	result, err := fixture.store.MaterializeNormalExactClose(context.Background(), fixture.candidate, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	fixture.fake.mu.Lock()
	manifestItem := fixture.fake.items[sessionControlFenceMetaPK(fixture.close.EventID)+"\x00"+sessionControlCloseManifestSK(0)]
	taskSetItem := fixture.fake.items[sessionControlFenceMetaPK(fixture.close.EventID)+"\x00"+sessionControlCloseTaskSetSK]
	fixture.fake.mu.Unlock()
	for _, name := range []string{"session_version", "expected_target_count", "prepared_directory_version", "manifest_index", "created_at_ms"} {
		copyItem := make(map[string]types.AttributeValue, len(manifestItem))
		for key, value := range manifestItem {
			copyItem[key] = value
		}
		delete(copyItem, name)
		if _, err := sessionControlCloseManifestFromItem(copyItem, fixture.close.EventID, 0); !errors.Is(err, errSessionControlMaterializationCorrupt) {
			t.Fatalf("manifest missing %s = %v", name, err)
		}
	}
	for _, name := range []string{"session_version", "expected_target_count", "prepared_directory_version", "work_mode", "source_count", "owner_count", "created_at_ms", "manifest_digests", "manifest_source_counts", "manifest_owner_counts"} {
		copyItem := make(map[string]types.AttributeValue, len(taskSetItem))
		for key, value := range taskSetItem {
			copyItem[key] = value
		}
		delete(copyItem, name)
		if _, err := sessionControlCloseTaskSetFromItem(copyItem, fixture.close.EventID); !errors.Is(err, errSessionControlMaterializationCorrupt) {
			t.Fatalf("taskset missing %s = %v", name, err)
		}
	}
	mutated := *result
	mutated.ManifestSourceCounts = append([]uint64(nil), result.ManifestSourceCounts...)
	mutated.ManifestSourceCounts[0] = ^uint64(0)
	redigestSessionControlCloseTaskSet(t, &mutated)
	if validateSessionControlCloseTaskSet(mutated) == nil {
		t.Fatal("wrapped manifest source count accepted")
	}
	mutated = *result
	mutated.OwnerCount = mutated.SourceCount + 1
	redigestSessionControlCloseTaskSet(t, &mutated)
	if validateSessionControlCloseTaskSet(mutated) == nil {
		t.Fatal("owner count above source count accepted")
	}
	mutated = *result
	mutated.SessionVersion = 1
	redigestSessionControlCloseTaskSet(t, &mutated)
	if validateSessionControlCloseTaskSet(mutated) == nil {
		t.Fatal("nonzero taskset accepted session version one")
	}
	zeroFixture := newSessionControlMaterializationFixture(t, 0)
	zero, err := zeroFixture.store.MaterializeNormalExactClose(context.Background(), zeroFixture.candidate, zeroFixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	zero.SessionVersion = 2
	redigestSessionControlCloseTaskSet(t, zero)
	if validateSessionControlCloseTaskSet(*zero) == nil {
		t.Fatal("zero-target taskset accepted session version two")
	}
	zeroFixture.fake.mu.Lock()
	zeroTaskSetItem := zeroFixture.fake.items[sessionControlFenceMetaPK(zeroFixture.close.EventID)+"\x00"+sessionControlCloseTaskSetSK]
	zeroFixture.fake.mu.Unlock()
	for _, name := range []string{"expected_target_count", "source_count", "owner_count", "work_mode", "manifest_digests", "manifest_source_counts", "manifest_owner_counts"} {
		copyItem := make(map[string]types.AttributeValue, len(zeroTaskSetItem))
		for key, value := range zeroTaskSetItem {
			copyItem[key] = value
		}
		delete(copyItem, name)
		if _, err := sessionControlCloseTaskSetFromItem(copyItem, zeroFixture.close.EventID); !errors.Is(err, errSessionControlMaterializationCorrupt) {
			t.Fatalf("zero taskset missing %s = %v", name, err)
		}
	}
	manifest, err := sessionControlCloseManifestFromItem(manifestItem, fixture.close.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	manifest.SessionVersion = 1
	redigestSessionControlCloseManifest(t, &manifest)
	if validateSessionControlCloseManifest(manifest) == nil {
		t.Fatal("nonzero manifest accepted session version one")
	}
	manifest, err = sessionControlCloseManifestFromItem(manifestItem, fixture.close.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Refs = append([]sessionControlCloseTaskRef(nil), manifest.Refs...)
	manifest.Refs[0].SourceCount = ^uint64(0)
	redigestSessionControlCloseManifest(t, &manifest)
	if validateSessionControlCloseManifest(manifest) == nil {
		t.Fatal("manifest source-count overflow accepted")
	}
	ownerPK := sessionControlOwnerPK(fixture.intents[0].Target.ControlCellID, fixture.intents[0].Target.ACID, fixture.intents[0].Target.PublicKey)
	fixture.fake.mu.Lock()
	taskItem := fixture.fake.items[ownerPK+"\x00"+sessionControlCloseTaskSK(fixture.close.EventID)]
	fixture.fake.mu.Unlock()
	task, err := sessionControlCloseTaskFromItem(taskItem, ownerPK, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	task.SessionVersion = 1
	redigestSessionControlCloseTask(t, &task)
	if validateSessionControlCloseTask(task) == nil {
		t.Fatal("nonzero task accepted session version one")
	}
	task, err = sessionControlCloseTaskFromItem(taskItem, ownerPK, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	task.SourceCount = task.ExpectedTargetCount + 1
	redigestSessionControlCloseTask(t, &task)
	if validateSessionControlCloseTask(task) == nil {
		t.Fatal("task source count above expected accepted")
	}
	chunkFixture := newSessionControlMaterializationFixture(t, 49)
	chunkSet, err := chunkFixture.store.MaterializeNormalExactClose(context.Background(), chunkFixture.candidate, chunkFixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	chunkSet.ManifestOwnerCounts = append([]uint64(nil), chunkSet.ManifestOwnerCounts...)
	chunkSet.ManifestSourceCounts = append([]uint64(nil), chunkSet.ManifestSourceCounts...)
	chunkSet.ManifestOwnerCounts[0], chunkSet.ManifestOwnerCounts[1] = 47, 2
	chunkSet.ManifestSourceCounts[0], chunkSet.ManifestSourceCounts[1] = 47, 2
	redigestSessionControlCloseTaskSet(t, chunkSet)
	if validateSessionControlCloseTaskSet(*chunkSet) == nil {
		t.Fatal("nondeterministic manifest chunk counts accepted")
	}
}

func TestSessionControlMaterializationRetentionCompatibilityRejectsRegressionAndOtherMutation(t *testing.T) {
	fixture := newSessionControlMaterializationFixture(t, 1)
	base := fixture.close.Session
	lower := base
	lower.RetainUntilMillis--
	if sessionControlCloseSessionRetainCompatible(base, lower) {
		t.Fatal("lower retention accepted")
	}
	mutated := base
	mutated.Version++
	if sessionControlCloseSessionRetainCompatible(base, mutated) {
		t.Fatal("non-retention session mutation accepted")
	}
}

func TestSessionControlMaterializationCanonicalOwnerPK(t *testing.T) {
	valid := sessionControlOwnerPK("cell-01", "ac-owner", testACSessionControlPublicKey(0x88))
	if !validSessionControlOwnerPK(valid) {
		t.Fatalf("valid owner pk rejected: %q", valid)
	}
	for _, malformed := range []string{sessionControlOwnerPKPrefix + "ab", sessionControlOwnerPKPrefix + strings.Repeat("g", 64), strings.ToUpper(valid)} {
		if validSessionControlOwnerPK(malformed) {
			t.Fatalf("malformed owner pk accepted: %q", malformed)
		}
	}
}

func TestSessionControlMaterializationInitialTaskSchemaAndMutations(t *testing.T) {
	fixture := newSessionControlMaterializationFixture(t, 1)
	if _, err := fixture.store.MaterializeNormalExactClose(context.Background(), fixture.candidate, fixture.close.EventID); err != nil {
		t.Fatal(err)
	}
	ownerPK := sessionControlOwnerPK(fixture.intents[0].Target.ControlCellID, fixture.intents[0].Target.ACID, fixture.intents[0].Target.PublicKey)
	fixture.fake.mu.Lock()
	item := fixture.fake.items[ownerPK+"\x00"+sessionControlCloseTaskSK(fixture.close.EventID)]
	fixture.fake.mu.Unlock()
	task, err := sessionControlCloseTaskFromItem(item, ownerPK, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if task.ManifestIndex != 0 || task.WorkMode != sessionControlCloseWorkModeNormal ||
		task.CurrentOwnerWorkVersion != task.OwnerAfter.WorkVersion || task.CurrentOwnerTaskCount != task.OwnerAfter.TaskCount ||
		task.CurrentOwnerPendingCount != task.OwnerAfter.PendingCount ||
		task.LastOperationKind != sessionControlCloseTaskOperationMaterialized || task.LastOperationID != task.CreationDigest {
		t.Fatalf("initial task audit = %#v", task)
	}
	for _, name := range []string{"manifest_index", "work_mode", "current_owner_work_version", "current_owner_task_count",
		"current_owner_pending_count", "last_operation_kind", "last_operation_id"} {
		copyItem := make(map[string]types.AttributeValue, len(item))
		for key, value := range item {
			copyItem[key] = value
		}
		delete(copyItem, name)
		if _, err := sessionControlCloseTaskFromItem(copyItem, ownerPK, fixture.close.EventID); !errors.Is(err, errSessionControlMaterializationCorrupt) {
			t.Fatalf("task missing %s = %v", name, err)
		}
	}
	mutations := []func(*sessionControlCloseTask){
		func(v *sessionControlCloseTask) {
			v.WorkMode = sessionControlCloseWorkModeOverflow
			redigestSessionControlCloseTask(t, v)
		},
		func(v *sessionControlCloseTask) { v.CurrentOwnerWorkVersion++ },
		func(v *sessionControlCloseTask) { v.CurrentOwnerTaskCount++ },
		func(v *sessionControlCloseTask) { v.CurrentOwnerPendingCount++ },
		func(v *sessionControlCloseTask) { v.LastOperationKind = "claim" },
		func(v *sessionControlCloseTask) { v.LastOperationID = strings.Repeat("0", 64) },
	}
	for index, mutate := range mutations {
		changed := task
		mutate(&changed)
		if validateSessionControlCloseTask(changed) == nil {
			t.Fatalf("task mutation %d accepted", index)
		}
	}
	changedIndex := task
	changedIndex.ManifestIndex = 1
	redigestSessionControlCloseTask(t, &changedIndex)
	if _, err := sessionControlCloseBuildManifest(&fixture.close, 0, []sessionControlCloseTask{changedIndex}); !errors.Is(err, errSessionControlMaterializationCorrupt) {
		t.Fatalf("manifest accepted task from another manifest: %v", err)
	}
}

func TestSessionControlMaterializationWorkModeStrictAcrossRows(t *testing.T) {
	fixture := newSessionControlMaterializationFixture(t, 1)
	result, err := fixture.store.MaterializeNormalExactClose(context.Background(), fixture.candidate, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	fixture.fake.mu.Lock()
	manifestItem := fixture.fake.items[sessionControlFenceMetaPK(fixture.close.EventID)+"\x00"+sessionControlCloseManifestSK(0)]
	fixture.fake.mu.Unlock()
	manifest, err := sessionControlCloseManifestFromItem(manifestItem, fixture.close.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	manifest.WorkMode = "future_mode"
	redigestSessionControlCloseManifest(t, &manifest)
	if validateSessionControlCloseManifest(manifest) == nil {
		t.Fatal("unknown work mode accepted on manifest")
	}
	result.WorkMode = "future_mode"
	redigestSessionControlCloseTaskSet(t, result)
	if validateSessionControlCloseTaskSet(*result) == nil {
		t.Fatal("unknown work mode accepted on taskset")
	}
	copyManifest := make(map[string]types.AttributeValue, len(manifestItem))
	for key, value := range manifestItem {
		copyManifest[key] = value
	}
	delete(copyManifest, "work_mode")
	if _, err := sessionControlCloseManifestFromItem(copyManifest, fixture.close.EventID, 0); !errors.Is(err, errSessionControlMaterializationCorrupt) {
		t.Fatalf("manifest missing work_mode = %v", err)
	}
}

func TestSessionControlMaterializationNewSchemaFieldsBindDigestsAndTokens(t *testing.T) {
	fixture := newSessionControlMaterializationFixture(t, 1)
	result, err := fixture.store.MaterializeNormalExactClose(context.Background(), fixture.candidate, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	ownerPK := sessionControlOwnerPK(fixture.intents[0].Target.ControlCellID, fixture.intents[0].Target.ACID, fixture.intents[0].Target.PublicKey)
	fixture.fake.mu.Lock()
	taskItem := fixture.fake.items[ownerPK+"\x00"+sessionControlCloseTaskSK(fixture.close.EventID)]
	manifestItem := fixture.fake.items[sessionControlFenceMetaPK(fixture.close.EventID)+"\x00"+sessionControlCloseManifestSK(0)]
	fixture.fake.mu.Unlock()
	task, err := sessionControlCloseTaskFromItem(taskItem, ownerPK, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	baseCreation := task.CreationDigest
	changed := task
	changed.ManifestIndex++
	redigestSessionControlCloseTask(t, &changed)
	if changed.CreationDigest == baseCreation {
		t.Fatal("manifest index did not change task creation digest")
	}
	changed = task
	changed.WorkMode = sessionControlCloseWorkModeOverflow
	redigestSessionControlCloseTask(t, &changed)
	if changed.CreationDigest == baseCreation {
		t.Fatal("work mode did not change task creation digest")
	}
	baseToken, err := sessionControlCloseMaterializationToken("scm-m-", task)
	if err != nil {
		t.Fatal(err)
	}
	changed = task
	changed.CurrentOwnerWorkVersion++
	changedToken, err := sessionControlCloseMaterializationToken("scm-m-", changed)
	if err != nil || aws.ToString(baseToken) == aws.ToString(changedToken) {
		t.Fatalf("current-owner token = %q/%q/%v", aws.ToString(baseToken), aws.ToString(changedToken), err)
	}
	changed = task
	changed.LastOperationID = strings.Repeat("f", 64)
	changedToken, err = sessionControlCloseMaterializationToken("scm-m-", changed)
	if err != nil || aws.ToString(baseToken) == aws.ToString(changedToken) {
		t.Fatalf("last-operation token = %q/%q/%v", aws.ToString(baseToken), aws.ToString(changedToken), err)
	}
	manifest, err := sessionControlCloseManifestFromItem(manifestItem, fixture.close.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	baseManifest := manifest.ManifestDigest
	manifest.WorkMode = sessionControlCloseWorkModeOverflow
	redigestSessionControlCloseManifest(t, &manifest)
	if manifest.ManifestDigest == baseManifest {
		t.Fatal("work mode did not change manifest digest")
	}
	baseTaskSet := result.TaskSetDigest
	result.WorkMode = sessionControlCloseWorkModeOverflow
	redigestSessionControlCloseTaskSet(t, result)
	if result.TaskSetDigest == baseTaskSet {
		t.Fatal("work mode did not change taskset digest")
	}
}
