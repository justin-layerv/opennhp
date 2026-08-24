package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type sandboxActiveReadyFixture struct {
	Fake      *sessionControlSessionDynamoFake
	Targets   []sessionControlTargetAuthority
	Owners    []sessionControlOwnerAuthority
	Authority sessionControlAuthority
	Directory sessionControlFenceDirectory
}

func sandboxActiveReadyAuthorities(t *testing.T, count int) ([]sessionControlTargetAuthority,
	[]sessionControlOwnerAuthority,
) {
	t.Helper()
	targets := make([]sessionControlTargetAuthority, count)
	owners := make([]sessionControlOwnerAuthority, count)
	for index := 0; index < count; index++ {
		candidate := testSessionControlTargetCandidate(byte(0xb0+index), fmt.Sprintf("%032x", index+1), uint64(index+1))
		candidate.ACID = sandboxStaleTargetRetirementACID
		candidate.ControlCellID = sandboxStaleTargetRetirementCellID
		target := testSessionControlTargetAuthority(candidate, sessionControlTargetActive, uint64(40+index))
		target.AuthorityVersion = 7
		target.ActivatedControlVersion = sandboxActiveReadyDirectoryVersion
		target.ReadyControlVersion = sandboxActiveReadyDirectoryVersion
		target.AAKEnqueuedAtMillis = target.PreparedAtMillis + int64(index+1)
		target.AAKTransactionID = uint64(100 + index)
		target.UpdatedAtMillis = target.AAKEnqueuedAtMillis
		if err := validateSessionControlTargetAuthority(target); err != nil {
			t.Fatal(err)
		}
		owner, err := sessionControlOwnerFromTarget(target, nil, sessionControlOwnerReady)
		if err != nil {
			t.Fatal(err)
		}
		targets[index] = target
		owners[index] = owner
	}
	return targets, owners
}

func seedSandboxActiveReadyFixture(t *testing.T) *sandboxActiveReadyFixture {
	t.Helper()
	targets, owners := sandboxActiveReadyAuthorities(t, sandboxActiveReadyPredecessorCount)
	fixture := &sandboxActiveReadyFixture{
		Fake: newSessionControlSessionDynamoFake(), Targets: targets, Owners: owners,
		Authority: sessionControlAuthority{
			ACID: sandboxStaleTargetRetirementACID, ControlCellID: sandboxStaleTargetRetirementCellID,
			Version: 7, ActiveTargetCount: sandboxActiveReadyPredecessorCount,
			CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_250,
		},
		Directory: sessionControlFenceDirectory{
			CellID: sandboxStaleTargetRetirementCellID, Version: sandboxActiveReadyDirectoryVersion,
			CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_250,
		},
	}
	for index := range fixture.Targets {
		fixture.setTarget(t, fixture.Targets[index])
		seedSessionControlOwnerAuthority(t, fixture.Fake, fixture.Owners[index])
	}
	fixture.setAuthority(t, fixture.Authority)
	fixture.setDirectory(t, fixture.Directory)
	fixture.installQueryModel()
	return fixture
}

func (f *sandboxActiveReadyFixture) setTarget(t *testing.T, target sessionControlTargetAuthority) {
	t.Helper()
	row, err := sessionControlTargetToRow(target)
	if err != nil {
		t.Fatal(err)
	}
	f.Fake.setItem(marshalSessionControlSessionTestRow(t, row))
}

func (f *sandboxActiveReadyFixture) setAuthority(t *testing.T, authority sessionControlAuthority) {
	t.Helper()
	row, err := sessionControlAuthorityToRow(authority)
	if err != nil {
		t.Fatal(err)
	}
	f.Fake.setItem(marshalSessionControlSessionTestRow(t, row))
}

func (f *sandboxActiveReadyFixture) setDirectory(t *testing.T, directory sessionControlFenceDirectory) {
	t.Helper()
	row, err := sessionControlFenceDirectoryToRow(directory)
	if err != nil {
		t.Fatal(err)
	}
	f.Fake.setItem(marshalSessionControlSessionTestRow(t, row))
}

func (f *sandboxActiveReadyFixture) installQueryModel() {
	f.Fake.queryHook = func(ctx context.Context, input *dynamodb.QueryInput, _ int) (*dynamodb.QueryOutput, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pk, _ := input.ExpressionAttributeValues[":pk"].(*types.AttributeValueMemberS)
		if pk == nil {
			return nil, errors.New("query lacks its exact partition")
		}
		prefix := ""
		for _, name := range []string{":target_prefix", ":task_prefix"} {
			if value, ok := input.ExpressionAttributeValues[name].(*types.AttributeValueMemberS); ok {
				prefix = value.Value
			}
		}
		f.Fake.mu.Lock()
		keys := make([]string, 0)
		for key, item := range f.Fake.items {
			itemPK, _ := item["pk"].(*types.AttributeValueMemberS)
			itemSK, _ := item["sk"].(*types.AttributeValueMemberS)
			if itemPK != nil && itemSK != nil && itemPK.Value == pk.Value && strings.HasPrefix(itemSK.Value, prefix) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		items := make([]map[string]types.AttributeValue, 0, len(keys))
		for _, key := range keys {
			items = append(items, f.Fake.items[key])
		}
		f.Fake.mu.Unlock()
		return &dynamodb.QueryOutput{Count: int32(len(items)), Items: items}, nil
	}
}

func TestSandboxActiveReadySnapshotRequiresExactStableHomogeneousTrio(t *testing.T) {
	fixture := seedSandboxActiveReadyFixture(t)
	plan, err := snapshotSandboxActiveReadyPredecessors(context.Background(), fixture.Fake,
		SandboxStaleTargetRetirementTable)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Schema != SandboxActiveReadyPredecessorPlanSchema || len(plan.Targets) != 3 {
		t.Fatalf("ACTIVE/READY plan = %#v", plan)
	}
	for index, planned := range plan.Targets {
		owner := fixture.Owners[index]
		if planned.ID != fmt.Sprintf("active-ready-predecessor-%d", index+1) || planned.Owner == nil ||
			planned.FenceSHA256 != sandboxStaleTargetFenceDigest(fixture.Targets[index].fence()) ||
			planned.OwnerSHA256 != sandboxStaleTargetOwnerDigest(owner) {
			t.Fatalf("ACTIVE/READY target %d = %#v", index, planned)
		}
	}
}

func TestSandboxActiveReadySnapshotRejectsEveryAuthorityDrift(t *testing.T) {
	tests := map[string]func(*testing.T, *sandboxActiveReadyFixture){
		"missing target": func(_ *testing.T, f *sandboxActiveReadyFixture) {
			delete(f.Fake.items, sessionControlSessionDynamoMapKey(sessionControlTargetDynamoKey(f.Targets[2].key())))
		},
		"extra target": func(t *testing.T, f *sandboxActiveReadyFixture) {
			targets, owners := sandboxActiveReadyAuthorities(t, 4)
			f.setTarget(t, targets[3])
			seedSessionControlOwnerAuthority(t, f.Fake, owners[3])
			f.Authority.ActiveTargetCount = 4
			f.setAuthority(t, f.Authority)
		},
		"mixed PREPARING target": func(t *testing.T, f *sandboxActiveReadyFixture) {
			target := f.Targets[1]
			target.State = sessionControlTargetPreparing
			target.ActivatedControlVersion = 0
			target.ReadyControlVersion = 0
			target.AAKEnqueuedAtMillis = 0
			target.AAKTransactionID = 0
			f.setTarget(t, target)
			owner, err := sessionControlOwnerFromTarget(target, nil, sessionControlOwnerPreparing)
			if err != nil {
				t.Fatal(err)
			}
			seedSessionControlOwnerAuthority(t, f.Fake, owner)
		},
		"malformed target": func(_ *testing.T, f *sandboxActiveReadyFixture) {
			key := sessionControlSessionDynamoMapKey(sessionControlTargetDynamoKey(f.Targets[0].key()))
			delete(f.Fake.items[key], "ready_control_version")
		},
		"authority version": func(t *testing.T, f *sandboxActiveReadyFixture) {
			f.Authority.Version++
			f.setAuthority(t, f.Authority)
		},
		"authority count": func(t *testing.T, f *sandboxActiveReadyFixture) {
			f.Authority.ActiveTargetCount--
			f.setAuthority(t, f.Authority)
		},
		"authority cell": func(t *testing.T, f *sandboxActiveReadyFixture) {
			f.Authority.ControlCellID = "cell1"
			f.setAuthority(t, f.Authority)
		},
		"directory version": func(t *testing.T, f *sandboxActiveReadyFixture) {
			f.Directory.Version--
			f.setDirectory(t, f.Directory)
		},
		"directory count": func(t *testing.T, f *sandboxActiveReadyFixture) {
			f.Directory.ActiveFenceCount = 1
			f.setDirectory(t, f.Directory)
		},
		"directory blocked": func(t *testing.T, f *sandboxActiveReadyFixture) {
			key := sessionControlSessionDynamoMapKey(sessionControlFenceDirectoryKey(f.Directory.CellID))
			f.Fake.items[key]["admission_blocked"] = &types.AttributeValueMemberBOOL{Value: true}
		},
		"directory overflow": func(t *testing.T, f *sandboxActiveReadyFixture) {
			key := sessionControlSessionDynamoMapKey(sessionControlFenceDirectoryKey(f.Directory.CellID))
			f.Fake.items[key]["overflow_close_count"] = &types.AttributeValueMemberN{Value: "1"}
		},
		"owner identity": func(t *testing.T, f *sandboxActiveReadyFixture) {
			owner := f.Owners[0]
			owner.TargetUpdatedAtMillis++
			seedSessionControlOwnerAuthority(t, f.Fake, owner)
		},
		"owner retained task": func(t *testing.T, f *sandboxActiveReadyFixture) {
			owner := f.Owners[0]
			owner.TaskCount = 1
			seedSessionControlOwnerAuthority(t, f.Fake, owner)
		},
		"physical owner task": func(_ *testing.T, f *sandboxActiveReadyFixture) {
			f.Fake.setItem(map[string]types.AttributeValue{
				"pk": &types.AttributeValueMemberS{Value: sessionControlOwnerPK(f.Owners[0].CellID, f.Owners[0].ACID, f.Owners[0].PublicKey)},
				"sk": &types.AttributeValueMemberS{Value: sessionControlCloseTaskSKPrefix + strings.Repeat("a", 64)},
			})
		},
		"reverse target session": func(_ *testing.T, f *sandboxActiveReadyFixture) {
			f.Fake.setItem(map[string]types.AttributeValue{
				"pk": &types.AttributeValueMemberS{Value: sessionControlTargetSessionPK(f.Targets[0])},
				"sk": &types.AttributeValueMemberS{Value: "SESSION#1"},
			})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := seedSandboxActiveReadyFixture(t)
			mutate(t, fixture)
			if _, err := snapshotSandboxActiveReadyPredecessors(context.Background(), fixture.Fake,
				SandboxStaleTargetRetirementTable); err == nil {
				t.Fatal("mutated ACTIVE/READY snapshot was accepted")
			}
			if len(fixture.Fake.transactions) != 0 {
				t.Fatal("snapshot drift reached a write")
			}
		})
	}
}

func TestSandboxActiveReadySnapshotRejectsTornDoubleRead(t *testing.T) {
	fixture := seedSandboxActiveReadyFixture(t)
	baseHook := fixture.Fake.queryHook
	var targetQueries int
	fixture.Fake.queryHook = func(ctx context.Context, input *dynamodb.QueryInput, call int) (*dynamodb.QueryOutput, error) {
		if _, ok := input.ExpressionAttributeValues[":target_prefix"]; ok {
			targetQueries++
			if targetQueries == 2 {
				target := fixture.Targets[0]
				target.Version++
				target.UpdatedAtMillis++
				fixture.setTarget(t, target)
				owner, err := sessionControlOwnerFromTarget(target, &fixture.Owners[0], sessionControlOwnerReady)
				if err != nil {
					t.Fatal(err)
				}
				seedSessionControlOwnerAuthority(t, fixture.Fake, owner)
			}
		}
		return baseHook(ctx, input, call)
	}
	if _, err := snapshotSandboxActiveReadyPredecessors(context.Background(), fixture.Fake,
		SandboxStaleTargetRetirementTable); err == nil {
		t.Fatal("torn ACTIVE/READY double read was accepted")
	}
}

func commitSandboxActiveReadyOwnerPut(t *testing.T, fake *sessionControlSessionDynamoFake,
	input *dynamodb.TransactWriteItemsInput,
) sessionControlOwnerAuthority {
	t.Helper()
	var put *types.Put
	for _, item := range input.TransactItems {
		kind, _ := func() (*types.AttributeValueMemberS, bool) {
			if item.Put == nil {
				return nil, false
			}
			value, ok := item.Put.Item["kind"].(*types.AttributeValueMemberS)
			return value, ok
		}()
		if kind != nil && kind.Value == sessionControlOwnerKind {
			put = item.Put
			break
		}
	}
	if put == nil {
		t.Fatalf("transaction lacks an OWNER Put: %#v", input)
	}
	var row sessionControlOwnerRow
	if err := attributevalue.UnmarshalMap(put.Item, &row); err != nil {
		t.Fatal(err)
	}
	owner, err := sessionControlOwnerFromItem(put.Item, row.CellID, row.ACID, row.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionControlOwnerAuthority(t, fake, owner)
	return owner
}

func TestSandboxActiveReadyAdmissionAndLatchSerializeInBothOrders(t *testing.T) {
	t.Run("admission wins", func(t *testing.T) {
		fixture := seedSandboxActiveReadyFixture(t)
		target, readyOwner := fixture.Targets[0], fixture.Owners[0]
		snapshot := sessionControlFenceSnapshot{CellID: sandboxStaleTargetRetirementCellID,
			DirectoryVersion: sandboxActiveReadyDirectoryVersion}
		candidate := testSessionControlSessionCandidate(0xc0, 800)
		candidate.CellID = sandboxStaleTargetRetirementCellID
		reserved, err := planSessionControlReservation(candidate, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		seedSessionControlReservation(t, fixture.Fake, reserved)
		fixture.Fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			commitSandboxActiveReadyOwnerPut(t, fixture.Fake, input)
			return &dynamodb.TransactWriteItemsOutput{}, nil
		}
		store := &dynamoSessionControlStore{client: fixture.Fake, tableName: SandboxStaleTargetRetirementTable,
			operationTimeout: time.Second, nowUTC: func() time.Time { return time.UnixMilli(1_800_000_010_000).UTC() }}
		if _, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
			candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot); err != nil {
			t.Fatal(err)
		}
		fixture.Fake.transactions = nil
		fixture.Fake.transactHook = nil
		if _, err := beginSandboxActiveReadyDecommissionWithClient(context.Background(), fixture.Fake,
			"active-ready-predecessor-1", target.fence(), readyOwner,
			sandboxFenceDirectoryReceipt(fixture.Directory)); err == nil {
			t.Fatal("latch accepted an owner generation consumed by admission")
		}
		if len(fixture.Fake.transactions) != 0 {
			t.Fatal("admission-first latch reached its transaction")
		}
	})

	t.Run("latch wins", func(t *testing.T) {
		fixture := seedSandboxActiveReadyFixture(t)
		target, readyOwner := fixture.Targets[0], fixture.Owners[0]
		fixture.Fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			commitSandboxActiveReadyOwnerPut(t, fixture.Fake, input)
			return &dynamodb.TransactWriteItemsOutput{}, nil
		}
		if _, err := beginSandboxActiveReadyDecommissionWithClient(context.Background(), fixture.Fake,
			"active-ready-predecessor-1", target.fence(), readyOwner,
			sandboxFenceDirectoryReceipt(fixture.Directory)); err != nil {
			t.Fatal(err)
		}
		fixture.Fake.transactions = nil
		candidate := testSessionControlSessionCandidate(0xc1, 801)
		candidate.CellID = sandboxStaleTargetRetirementCellID
		snapshot := sessionControlFenceSnapshot{CellID: sandboxStaleTargetRetirementCellID,
			DirectoryVersion: sandboxActiveReadyDirectoryVersion}
		reserved, err := planSessionControlReservation(candidate, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		seedSessionControlReservation(t, fixture.Fake, reserved)
		store := &dynamoSessionControlStore{client: fixture.Fake, tableName: SandboxStaleTargetRetirementTable,
			operationTimeout: time.Second, nowUTC: func() time.Time { return time.UnixMilli(1_800_000_010_000).UTC() }}
		if _, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
			candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot); !errors.Is(err, errSessionControlSessionTargetConflict) {
			t.Fatalf("post-latch admission error = %v", err)
		}
		if len(fixture.Fake.transactions) != 0 {
			t.Fatal("latch-first admission reached its transaction")
		}
	})
}

func TestSandboxActiveReadyTaskInsertAndLatchSerializeInBothOrders(t *testing.T) {
	fixture := seedSandboxActiveReadyFixture(t)
	ready := fixture.Owners[0]
	taskWinner, err := planSessionControlOwnerTaskInsert(ready, ready.UpdatedAtMillis+1)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionControlOwnerAuthority(t, fixture.Fake, taskWinner)
	if _, err := beginSandboxActiveReadyDecommissionWithClient(context.Background(), fixture.Fake,
		"active-ready-predecessor-1", fixture.Targets[0].fence(), ready,
		sandboxFenceDirectoryReceipt(fixture.Directory)); err == nil || len(fixture.Fake.transactions) != 0 {
		t.Fatalf("task-first latch = %v; transactions=%d", err, len(fixture.Fake.transactions))
	}
	latchWinner, err := planSessionControlOwnerDecommission(ready)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := planSessionControlOwnerTaskInsert(latchWinner, latchWinner.UpdatedAtMillis+1); err == nil {
		t.Fatal("latch-first owner admitted a task")
	}
}

func TestSandboxActiveReadyLatchRejectsSameBootAdmissionAndAttachment(t *testing.T) {
	fixture := seedSandboxActiveReadyFixture(t)
	target, ready := fixture.Targets[0], fixture.Owners[0]
	decommissioning, err := planSessionControlOwnerDecommission(ready)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionControlOwnerAuthority(t, fixture.Fake, decommissioning)
	if _, err := planSessionControlOwnerAdmission(decommissioning, decommissioning.UpdatedAtMillis+1); err == nil {
		t.Fatal("DECOMMISSIONING owner admitted a session intent")
	}
	attachment := sessionControlTargetAttachment{
		Candidate: sessionControlTargetCandidate{ACID: target.ACID, PublicKey: target.PublicKey, BootID: target.BootID,
			FlushGeneration: target.FlushGeneration, ControlCellID: target.ControlCellID},
		Target: target, Snapshot: sessionControlFenceSnapshot{CellID: target.ControlCellID,
			DirectoryVersion: sandboxActiveReadyDirectoryVersion},
	}
	store := &dynamoSessionControlStore{client: fixture.Fake, tableName: SandboxStaleTargetRetirementTable,
		operationTimeout: time.Second, nowUTC: time.Now}
	if _, err := store.VerifyReadyTargetAttachment(context.Background(), attachment); !errors.Is(err, errSessionControlTargetConflict) {
		t.Fatalf("post-latch same-boot attachment error = %v", err)
	}
	if len(fixture.Fake.transactions) != 0 {
		t.Fatal("post-latch same-boot attachment reached its transaction")
	}
}

func TestSandboxActiveReadyLatchClassifiesLostResponseAndReplays(t *testing.T) {
	fixture := seedSandboxActiveReadyFixture(t)
	target, ready := fixture.Targets[0], fixture.Owners[0]
	fixture.Fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		commitSandboxActiveReadyOwnerPut(t, fixture.Fake, input)
		return nil, context.DeadlineExceeded
	}
	receipt, err := beginSandboxActiveReadyDecommissionWithClient(context.Background(), fixture.Fake,
		"active-ready-predecessor-1", target.fence(), ready, sandboxFenceDirectoryReceipt(fixture.Directory))
	if err != nil || receipt.Owner.Phase != string(sessionControlOwnerDecommissioning) || len(fixture.Fake.transactions) != 1 {
		t.Fatalf("lost-response latch = %#v, %v; transactions=%d", receipt, err, len(fixture.Fake.transactions))
	}
	fixture.Fake.transactHook = nil
	replayed, err := beginSandboxActiveReadyDecommissionWithClient(context.Background(), fixture.Fake,
		"active-ready-predecessor-1", target.fence(), ready, sandboxFenceDirectoryReceipt(fixture.Directory))
	if err != nil || *replayed != *receipt || len(fixture.Fake.transactions) != 1 {
		t.Fatalf("latch replay = %#v, %v; transactions=%d", replayed, err, len(fixture.Fake.transactions))
	}
}

func TestSandboxActiveReadyLatchRejectsTargetOwnerAuthorityAndDirectoryDrift(t *testing.T) {
	tests := map[string]func(*testing.T, *sandboxActiveReadyFixture){
		"target": func(t *testing.T, fixture *sandboxActiveReadyFixture) {
			target := fixture.Targets[0]
			target.UpdatedAtMillis++
			fixture.setTarget(t, target)
		},
		"owner": func(t *testing.T, fixture *sandboxActiveReadyFixture) {
			owner, err := planSessionControlOwnerAdmission(fixture.Owners[0], fixture.Owners[0].UpdatedAtMillis+1)
			if err != nil {
				t.Fatal(err)
			}
			seedSessionControlOwnerAuthority(t, fixture.Fake, owner)
		},
		"authority": func(t *testing.T, fixture *sandboxActiveReadyFixture) {
			fixture.Authority.Version++
			fixture.setAuthority(t, fixture.Authority)
		},
		"directory": func(t *testing.T, fixture *sandboxActiveReadyFixture) {
			fixture.Directory.Version++
			fixture.Directory.UpdatedAtMillis++
			fixture.setDirectory(t, fixture.Directory)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := seedSandboxActiveReadyFixture(t)
			originalDirectory := sandboxFenceDirectoryReceipt(fixture.Directory)
			mutate(t, fixture)
			fixture.Fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
				return nil, &types.TransactionCanceledException{}
			}
			if _, err := beginSandboxActiveReadyDecommissionWithClient(context.Background(), fixture.Fake,
				"active-ready-predecessor-1", fixture.Targets[0].fence(), fixture.Owners[0], originalDirectory); err == nil {
				t.Fatal("latch accepted live authority drift")
			}
			if name != "directory" && len(fixture.Fake.transactions) != 0 {
				t.Fatalf("%s drift reached latch transaction", name)
			}
			if name == "directory" && len(fixture.Fake.transactions) != 1 {
				t.Fatalf("directory drift did not exercise its exact transaction condition: %d", len(fixture.Fake.transactions))
			}
		})
	}
}

func TestSandboxActiveReadyQuiescenceUsesStablePhysicalBracket(t *testing.T) {
	fixture := seedSandboxActiveReadyFixture(t)
	target, ready := fixture.Targets[0], fixture.Owners[0]
	decommissioning, _ := planSessionControlOwnerDecommission(ready)
	seedSessionControlOwnerAuthority(t, fixture.Fake, decommissioning)
	receipt, err := verifySandboxActiveReadyQuiescenceWithClient(context.Background(), fixture.Fake,
		"active-ready-predecessor-1", target.fence(), decommissioning, sandboxFenceDirectoryReceipt(fixture.Directory))
	if err != nil || receipt.OwnerTaskCount != "0" || receipt.TargetSessionCount != "0" {
		t.Fatalf("quiescence = %#v, %v", receipt, err)
	}

	fixture = seedSandboxActiveReadyFixture(t)
	target, ready = fixture.Targets[0], fixture.Owners[0]
	decommissioning, _ = planSessionControlOwnerDecommission(ready)
	seedSessionControlOwnerAuthority(t, fixture.Fake, decommissioning)
	baseHook := fixture.Fake.queryHook
	fixture.Fake.queryHook = func(ctx context.Context, input *dynamodb.QueryInput, call int) (*dynamodb.QueryOutput, error) {
		out, queryErr := baseHook(ctx, input, call)
		pk, _ := input.ExpressionAttributeValues[":pk"].(*types.AttributeValueMemberS)
		if queryErr == nil && pk != nil && pk.Value == sessionControlTargetSessionPK(target) {
			drift := target
			drift.UpdatedAtMillis++
			fixture.setTarget(t, drift)
		}
		return out, queryErr
	}
	if _, err := verifySandboxActiveReadyQuiescenceWithClient(context.Background(), fixture.Fake,
		"active-ready-predecessor-1", target.fence(), decommissioning,
		sandboxFenceDirectoryReceipt(fixture.Directory)); err == nil {
		t.Fatal("quiescence accepted a target change across its physical bracket")
	}
}

func TestSandboxActiveReadyQuiescenceRejectsPhysicalTaskAndReverseSessionRows(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "owner task"
		if reverse {
			name = "reverse session"
		}
		t.Run(name, func(t *testing.T) {
			fixture := seedSandboxActiveReadyFixture(t)
			target, ready := fixture.Targets[0], fixture.Owners[0]
			decommissioning, _ := planSessionControlOwnerDecommission(ready)
			seedSessionControlOwnerAuthority(t, fixture.Fake, decommissioning)
			pk := sessionControlOwnerPK(ready.CellID, ready.ACID, ready.PublicKey)
			sk := sessionControlCloseTaskSKPrefix + strings.Repeat("a", 64)
			if reverse {
				pk = sessionControlTargetSessionPK(target)
				sk = "SESSION#1"
			}
			fixture.Fake.setItem(map[string]types.AttributeValue{
				"pk": &types.AttributeValueMemberS{Value: pk}, "sk": &types.AttributeValueMemberS{Value: sk},
			})
			if _, err := verifySandboxActiveReadyQuiescenceWithClient(context.Background(), fixture.Fake,
				"active-ready-predecessor-1", target.fence(), decommissioning,
				sandboxFenceDirectoryReceipt(fixture.Directory)); err == nil {
				t.Fatal("quiescence accepted physical inventory")
			}
		})
	}
}

func TestSessionControlAdmissionGenerationPreservesCompletedTaskInventory(t *testing.T) {
	_, owners := sandboxActiveReadyAuthorities(t, 1)
	ready := owners[0]
	ready.TaskCount = 1
	ready.WorkVersion = 9
	next, err := planSessionControlOwnerAdmission(ready, ready.UpdatedAtMillis+1)
	if err != nil || next.WorkVersion != 10 || next.TaskCount != 1 || next.PendingCount != 0 ||
		next.Phase != sessionControlOwnerReady {
		t.Fatalf("READY retained-task admission owner = %#v, %v", next, err)
	}
	task := sessionControlCloseTask{CurrentOwnerWorkVersion: 9, CurrentOwnerTaskCount: 1,
		CurrentOwnerPendingCount: 0}
	if next.WorkVersion <= task.CurrentOwnerWorkVersion || next.TaskCount != task.CurrentOwnerTaskCount ||
		next.PendingCount != task.CurrentOwnerPendingCount {
		t.Fatalf("admission generation broke task descendant counters: next=%#v task=%#v", next, task)
	}
}

func sandboxActiveReadyJSONValue(t *testing.T, value any) any {
	t.Helper()
	encoded := canonicalSandboxRecoveryJSON(t, value)
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.UseNumber()
	var out any
	if err := decoder.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func sandboxActiveReadyTestPlan(t *testing.T) (SandboxStaleTargetRetirementPlan,
	[]sessionControlTargetFence, []sessionControlOwnerAuthority,
) {
	t.Helper()
	targets, owners := sandboxActiveReadyAuthorities(t, sandboxActiveReadyPredecessorCount)
	type pair struct {
		target sessionControlTargetAuthority
		owner  sessionControlOwnerAuthority
	}
	pairs := make([]pair, len(targets))
	for index := range targets {
		pairs[index] = pair{target: targets[index], owner: owners[index]}
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].target.PublicKey < pairs[j].target.PublicKey })
	plan := SandboxStaleTargetRetirementPlan{
		Schema: SandboxActiveReadyPredecessorPlanSchema, Table: SandboxStaleTargetRetirementTable,
		Region: SandboxStaleTargetRetirementRegion, ACID: sandboxStaleTargetRetirementACID,
		ControlCellID: sandboxStaleTargetRetirementCellID,
	}
	fences := make([]sessionControlTargetFence, len(pairs))
	sortedOwners := make([]sessionControlOwnerAuthority, len(pairs))
	for index, pair := range pairs {
		fence := pair.target.fence()
		publicOwner := sandboxStaleTargetPublicOwner(pair.owner)
		plan.Targets = append(plan.Targets, SandboxStaleTargetRetirementPlanTarget{
			ID: fmt.Sprintf("active-ready-predecessor-%d", index+1), Fence: sandboxStaleTargetPublicFence(fence),
			FenceSHA256: sandboxStaleTargetFenceDigest(fence), Owner: &publicOwner,
			OwnerSHA256: sandboxStaleTargetOwnerDigest(pair.owner),
		})
		fences[index] = fence
		sortedOwners[index] = pair.owner
	}
	return plan, fences, sortedOwners
}

func sandboxActiveReadyTestLedger(t *testing.T, plan SandboxStaleTargetRetirementPlan,
	fences []sessionControlTargetFence, owners []sessionControlOwnerAuthority, statuses []string,
	directory SandboxFenceDirectoryRecoveryReceipt,
) []sandboxActiveReadyJournalTarget {
	t.Helper()
	if len(statuses) != len(plan.Targets) {
		t.Fatal("ACTIVE/READY ledger fixture length differs from its plan")
	}
	ledger := make([]sandboxActiveReadyJournalTarget, len(statuses))
	for index, status := range statuses {
		decommissioning, err := planSessionControlOwnerDecommission(owners[index])
		if err != nil {
			t.Fatal(err)
		}
		target := sandboxActiveReadyJournalTarget{ID: plan.Targets[index].ID,
			FenceSHA256: plan.Targets[index].FenceSHA256, Status: status}
		if status == "latched" || status == "quiescent" || status == "retired" {
			target.LatchReceipt = sandboxLatchReceipt(target.ID, fences[index], decommissioning, directory)
		}
		if status == "quiescent" || status == "retired" {
			target.QuiescenceReceipt = &SandboxActiveReadyQuiescenceReceipt{
				Schema: sandboxActiveReadyQuiescenceReceiptSchema, TargetID: target.ID,
				FenceSHA256: target.FenceSHA256, OwnerSHA256: sandboxStaleTargetOwnerDigest(decommissioning),
				OwnerTaskCount: "0", OwnerPendingCount: "0",
				TargetSessionPK:    sessionControlTargetSessionPK(sandboxTargetFromFenceAndOwner(fences[index], decommissioning)),
				TargetSessionCount: "0", DirectorySHA256: directory.DirectorySHA256,
			}
		}
		if status == "retired" {
			target.Receipt = sandboxRecoveryRetirementReceipt(target.ID, fences[index])
		}
		ledger[index] = target
	}
	return ledger
}

func sandboxActiveReadyJournalFixture(t *testing.T, statuses []string, journalStatus string) (
	SandboxRecoveryParameterSnapshot, SandboxRecoveryParameterSnapshot, SandboxRecoveryParameterSnapshot,
	SandboxRecoveryParameterSnapshot, SandboxRecoveryParameterSnapshot,
	SandboxStaleTargetRetirementPlan, []sessionControlTargetFence, []sessionControlOwnerAuthority,
) {
	t.Helper()
	state, _, historical, _ := sandboxRecoveryJournalAuthority(t, "retired", "complete")
	plan, fences, owners := sandboxActiveReadyTestPlan(t)
	directory := sandboxFenceDirectoryReceipt(sessionControlFenceDirectory{
		CellID: sandboxStaleTargetRetirementCellID, Version: sandboxActiveReadyDirectoryVersion,
		CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_250,
	})
	ledger := sandboxActiveReadyTestLedger(t, plan, fences, owners, statuses, directory)
	planValue := canonicalSandboxRecoveryJSON(t, plan)
	readyStatus := "latching"
	quiescenceDigest := ""
	if journalStatus == "ready_predecessor_retiring" {
		readyStatus = "quiescent"
		quiescenceDigest, _ = sandboxActiveReadyQuiescentLedgerDigest(ledger)
	}
	readyJournal := sandboxActiveReadyRecoveryJournal{
		Schema: sandboxActiveReadyJournalSchema, Status: readyStatus,
		SourceStateVersion:         30,
		SourceStateSHA256:          "4268c108fe2685c5a475d05f2ec98d5d58c54618dc3934289b97bc0da855dca6",
		SourceMainJournalParameter: SandboxStaleTargetRecoveryJournalParameter,
		SourceMainJournalVersion:   8,
		SourceMainJournalSHA256:    "49a0da6ea26c551ed99f51ad1e1a4608aa89ab7d1f97a40f22c2c12ce99b1a5c",
		OrchestratorSHA:            "abcdefabcdefabcdefabcdefabcdefabcdefabcd",
		FenceDrainSHA256:           directory.DirectorySHA256,
		Plan:                       plan,
		PlanSHA256:                 sandboxCanonicalDigest(planValue),
		QuiescenceSHA256:           quiescenceDigest,
		Targets:                    ledger,
	}
	readyHistorical := SandboxRecoveryParameterSnapshot{
		Value: sandboxActiveReadySizeEnvelope(t, sandboxActiveReadyJournalEnvelopeSchema, readyJournal), Version: 20,
	}
	readyRef := sandboxStaleTargetJournalRef{Parameter: SandboxActiveReadyRecoveryJournalParameter,
		Version: readyHistorical.Version, SHA256: sandboxCanonicalDigest(readyHistorical.Value)}
	historical = mutateSandboxRecoveryJournal(t, historical, func(value map[string]any) {
		value["status"] = journalStatus
		runtime := value["runtime"].(map[string]any)
		runtime["fence_drain"] = sandboxActiveReadyJSONValue(t, directory)
		runtime["predecessor_plan"] = nil
		runtime["predecessor_plan_sha256"] = ""
		runtime["predecessor_targets"] = []any{}
		runtime["ready_predecessor_ref"] = sandboxActiveReadyJSONValue(t, readyRef)
	})
	historical.Version = 30
	state.Value = mutateSandboxRecoveryJSON(t, state.Value, func(value map[string]any) {
		ref := value["repair"].(map[string]any)["stale_target_retirement_ref"].(map[string]any)
		ref["version"] = json.Number("30")
		ref["sha256"] = sandboxCanonicalDigest(historical.Value)
	})
	return state, historical, historical, readyHistorical, readyHistorical, plan, fences, owners
}

func sandboxActiveReadyJournalSuccessor(t *testing.T, historical SandboxRecoveryParameterSnapshot,
	index int, target sandboxActiveReadyJournalTarget,
) SandboxRecoveryParameterSnapshot {
	t.Helper()
	journal, _, err := sandboxDecodeActiveReadyJournal(historical)
	if err != nil {
		t.Fatal(err)
	}
	journal.Targets[index] = target
	switch target.Status {
	case "latched":
		journal.Status = "latching"
	case "quiescent":
		allQuiescent := true
		for _, candidate := range journal.Targets {
			allQuiescent = allQuiescent && candidate.Status == "quiescent"
		}
		if allQuiescent {
			journal.Status = "quiescent"
			journal.QuiescenceSHA256, _ = sandboxActiveReadyQuiescentLedgerDigest(journal.Targets)
		}
	case "retired":
		journal.Status = "retiring"
		allRetired := true
		for _, candidate := range journal.Targets {
			allRetired = allRetired && candidate.Status == "retired"
		}
		if allRetired {
			journal.Status = "complete"
		}
	}
	successor := historical
	successor.Value = sandboxActiveReadySizeEnvelope(t, sandboxActiveReadyJournalEnvelopeSchema, journal)
	successor.Version++
	return successor
}

func mutateSandboxActiveReadyJournal(t *testing.T, snapshot SandboxRecoveryParameterSnapshot,
	mutate func(*sandboxActiveReadyRecoveryJournal),
) SandboxRecoveryParameterSnapshot {
	t.Helper()
	journal, _, err := sandboxDecodeActiveReadyJournal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&journal)
	snapshot.Value = sandboxActiveReadySizeEnvelope(t, sandboxActiveReadyJournalEnvelopeSchema, journal)
	return snapshot
}

func sandboxActiveReadyReceiptFromRetired(targetID string,
	retired sessionControlTargetAuthority,
) *SandboxStaleTargetRetirementReceipt {
	return &SandboxStaleTargetRetirementReceipt{
		Schema: SandboxStaleTargetRetirementReceiptSchema, TargetID: targetID, PublicKey: retired.PublicKey,
		Version: decimal(retired.Version), AuthorityVersion: decimal(retired.AuthorityVersion),
		CountedActiveSlot: retired.CountedActiveSlot, RetiredAtMillis: decimalMillis(retired.RetiredAtMillis),
		RetiredTargetSHA256: sandboxRetiredTargetDigest(retired),
	}
}

func TestSandboxActiveReadyJournalAcceptsOnlyTypedOrderedSingleSuccessors(t *testing.T) {
	tests := []struct {
		name        string
		statuses    []string
		status      string
		operation   sandboxActiveReadyOperation
		successor   string
		targetID    string
		targetIndex int
	}{
		{name: "pending to latched", statuses: []string{"pending", "pending", "pending"},
			status: "ready_predecessor_latching", operation: sandboxActiveReadyLatch,
			successor: "latched", targetID: "active-ready-predecessor-1"},
		{name: "latched to quiescent", statuses: []string{"latched", "pending", "pending"},
			status: "ready_predecessor_latching", operation: sandboxActiveReadyQuiescence,
			successor: "quiescent", targetID: "active-ready-predecessor-1"},
		{name: "quiescent to retired", statuses: []string{"quiescent", "quiescent", "quiescent"},
			status: "ready_predecessor_retiring", operation: sandboxActiveReadyRetire,
			successor: "retired", targetID: "active-ready-predecessor-1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, currentMain, historicalMain, currentReady, historicalReady, plan, fences, owners := sandboxActiveReadyJournalFixture(t,
				test.statuses, test.status)
			authority, err := sandboxResolveJournaledActiveReadyAuthority(state, currentMain, historicalMain,
				currentReady, historicalReady,
				test.targetID, test.operation)
			if err != nil || authority.Fence != fences[test.targetIndex] || authority.CurrentIsSuccessor {
				t.Fatalf("referenced operation = %#v, %v", authority, err)
			}
			directory := sandboxFenceDirectoryReceipt(sessionControlFenceDirectory{
				CellID: sandboxStaleTargetRetirementCellID, Version: sandboxActiveReadyDirectoryVersion,
				CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_250,
			})
			ledger := sandboxActiveReadyTestLedger(t, plan, fences, owners, []string{test.successor,
				test.statuses[1], test.statuses[2]}, directory)
			successor := sandboxActiveReadyJournalSuccessor(t, historicalReady, test.targetIndex, ledger[test.targetIndex])
			authority, err = sandboxResolveJournaledActiveReadyAuthority(state, currentMain, historicalMain,
				successor, historicalReady,
				test.targetID, test.operation)
			if err != nil || !authority.CurrentIsSuccessor {
				t.Fatalf("single successor = %#v, %v", authority, err)
			}
		})
	}
}

func TestSandboxActiveReadyJournalRejectsWrongOrderTargetAndEveryNonExactSuccessor(t *testing.T) {
	state, currentMain, historicalMain, _, historicalReady, plan, fences, owners := sandboxActiveReadyJournalFixture(t,
		[]string{"pending", "pending", "pending"}, "ready_predecessor_latching")
	if _, err := sandboxResolveJournaledActiveReadyAuthority(state, currentMain, historicalMain,
		historicalReady, historicalReady,
		"active-ready-predecessor-2", sandboxActiveReadyLatch); err == nil {
		t.Fatal("out-of-order target was accepted")
	}
	if _, err := sandboxResolveJournaledActiveReadyAuthority(state, currentMain, historicalMain,
		historicalReady, historicalReady,
		"not-in-plan", sandboxActiveReadyLatch); err == nil {
		t.Fatal("non-plan target was accepted")
	}
	directory := sandboxFenceDirectoryReceipt(sessionControlFenceDirectory{
		CellID: sandboxStaleTargetRetirementCellID, Version: sandboxActiveReadyDirectoryVersion,
		CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_250,
	})
	latched := sandboxActiveReadyTestLedger(t, plan, fences, owners, []string{"latched", "pending", "pending"}, directory)
	valid := sandboxActiveReadyJournalSuccessor(t, historicalReady, 0, latched[0])

	wrongTarget := sandboxActiveReadyJournalSuccessor(t, historicalReady, 1, latched[0])
	extraField := valid
	extraField.Value = mutateSandboxRecoveryJSON(t, valid.Value, func(value map[string]any) { value["extra"] = true })
	nPlusTwo := valid
	nPlusTwo.Version++
	wrongReceipt := mutateSandboxActiveReadyJournal(t, valid, func(journal *sandboxActiveReadyRecoveryJournal) {
		journal.Targets[0].LatchReceipt.OwnerSHA256 = strings.Repeat("f", 64)
	})
	for name, current := range map[string]SandboxRecoveryParameterSnapshot{
		"wrong target": wrongTarget, "extra field": extraField, "N+2": nPlusTwo, "wrong receipt": wrongReceipt,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := sandboxResolveJournaledActiveReadyAuthority(state, currentMain, historicalMain,
				current, historicalReady,
				"active-ready-predecessor-1", sandboxActiveReadyLatch); err == nil {
				t.Fatal("non-exact journal successor was accepted")
			}
		})
	}
}

func TestSandboxJournaledActiveReadyLatchUsesNAndClassifiesNPlusOneWithoutWrite(t *testing.T) {
	state, currentMain, historicalMain, _, historicalReady, plan, fences, owners := sandboxActiveReadyJournalFixture(t,
		[]string{"pending", "pending", "pending"}, "ready_predecessor_latching")
	directory := sandboxFenceDirectoryReceipt(seedSandboxActiveReadyFixture(t).Directory)
	latched := sandboxActiveReadyTestLedger(t, plan, fences, owners,
		[]string{"latched", "pending", "pending"}, directory)
	successor := sandboxActiveReadyJournalSuccessor(t, historicalReady, 0, latched[0])

	t.Run("N mutates once", func(t *testing.T) {
		fixture := seedSandboxActiveReadyFixture(t)
		fixture.Fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			commitSandboxActiveReadyOwnerPut(t, fixture.Fake, input)
			return nil, context.DeadlineExceeded
		}
		receipt, err := latchSandboxJournaledActiveReadyWithClient(context.Background(), fixture.Fake,
			"active-ready-predecessor-1", state, currentMain, historicalMain, historicalReady, historicalReady)
		if err != nil || receipt == nil || receipt.Owner.Phase != string(sessionControlOwnerDecommissioning) ||
			len(fixture.Fake.transactions) != 1 {
			t.Fatalf("journal N latch = %#v, %v; transactions=%d", receipt, err, len(fixture.Fake.transactions))
		}
	})

	t.Run("N plus one classifies exact decommissioning", func(t *testing.T) {
		fixture := seedSandboxActiveReadyFixture(t)
		decommissioning, err := planSessionControlOwnerDecommission(fixture.Owners[0])
		if err != nil {
			t.Fatal(err)
		}
		seedSessionControlOwnerAuthority(t, fixture.Fake, decommissioning)
		receipt, err := latchSandboxJournaledActiveReadyWithClient(context.Background(), fixture.Fake,
			"active-ready-predecessor-1", state, currentMain, historicalMain, successor, historicalReady)
		if err != nil || receipt == nil || *receipt != *latched[0].LatchReceipt || len(fixture.Fake.transactions) != 0 {
			t.Fatalf("journal N+1 latch replay = %#v, %v; transactions=%d",
				receipt, err, len(fixture.Fake.transactions))
		}
	})

	t.Run("N plus one READY rejects without write", func(t *testing.T) {
		fixture := seedSandboxActiveReadyFixture(t)
		if _, err := latchSandboxJournaledActiveReadyWithClient(context.Background(), fixture.Fake,
			"active-ready-predecessor-1", state, currentMain, historicalMain, successor, historicalReady); err == nil ||
			len(fixture.Fake.transactions) != 0 {
			t.Fatalf("journal-ahead READY latch = %v; transactions=%d", err, len(fixture.Fake.transactions))
		}
	})

	for name, mutate := range map[string]func(*testing.T, *sandboxActiveReadyFixture){
		"target drift": func(t *testing.T, fixture *sandboxActiveReadyFixture) {
			target := fixture.Targets[0]
			target.UpdatedAtMillis++
			fixture.setTarget(t, target)
		},
		"owner drift": func(t *testing.T, fixture *sandboxActiveReadyFixture) {
			owner, err := planSessionControlOwnerDecommission(fixture.Owners[0])
			if err != nil {
				t.Fatal(err)
			}
			owner.WorkVersion++
			seedSessionControlOwnerAuthority(t, fixture.Fake, owner)
		},
		"authority drift": func(t *testing.T, fixture *sandboxActiveReadyFixture) {
			fixture.Authority.Version++
			fixture.setAuthority(t, fixture.Authority)
		},
		"directory drift": func(t *testing.T, fixture *sandboxActiveReadyFixture) {
			fixture.Directory.Version++
			fixture.Directory.UpdatedAtMillis++
			fixture.setDirectory(t, fixture.Directory)
		},
	} {
		t.Run("N plus one "+name+" rejects without write", func(t *testing.T) {
			fixture := seedSandboxActiveReadyFixture(t)
			decommissioning, err := planSessionControlOwnerDecommission(fixture.Owners[0])
			if err != nil {
				t.Fatal(err)
			}
			seedSessionControlOwnerAuthority(t, fixture.Fake, decommissioning)
			mutate(t, fixture)
			if _, err := latchSandboxJournaledActiveReadyWithClient(context.Background(), fixture.Fake,
				"active-ready-predecessor-1", state, currentMain, historicalMain, successor, historicalReady); err == nil ||
				len(fixture.Fake.transactions) != 0 {
				t.Fatalf("journal-ahead %s latch = %v; transactions=%d", name, err, len(fixture.Fake.transactions))
			}
		})
	}
}

func commitSandboxActiveReadyRetirement(t *testing.T, fixture *sandboxActiveReadyFixture,
	index int, owner sessionControlOwnerAuthority, retiredAt int64,
) sessionControlTargetAuthority {
	t.Helper()
	current := fixture.Targets[index]
	retired := current
	retired.State = sessionControlTargetRetired
	retired.Version++
	retired.AuthorityVersion++
	retired.CountedActiveSlot = false
	retired.UpdatedAtMillis = retiredAt
	retired.RetiredAtMillis = retiredAt
	fixture.setTarget(t, retired)
	retiredOwner, err := sessionControlOwnerFromTarget(retired, &owner, sessionControlOwnerRetired)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionControlOwnerAuthority(t, fixture.Fake, retiredOwner)
	fixture.Authority.Version++
	fixture.Authority.ActiveTargetCount--
	fixture.Authority.UpdatedAtMillis = retiredAt
	fixture.setAuthority(t, fixture.Authority)
	return retired
}

func TestSandboxJournaledActiveReadyRetireClassifiesCommittedNAndNPlusOneBeforePreState(t *testing.T) {
	state, currentMain, historicalMain, _, historicalReady, plan, fences, owners := sandboxActiveReadyJournalFixture(t,
		[]string{"quiescent", "quiescent", "quiescent"}, "ready_predecessor_retiring")
	directory := sandboxFenceDirectoryReceipt(seedSandboxActiveReadyFixture(t).Directory)

	seedCommitted := func(t *testing.T) (*sandboxActiveReadyFixture, sessionControlTargetAuthority,
		sessionControlOwnerAuthority,
	) {
		t.Helper()
		fixture := seedSandboxActiveReadyFixture(t)
		decommissioning, err := planSessionControlOwnerDecommission(fixture.Owners[0])
		if err != nil {
			t.Fatal(err)
		}
		seedSessionControlOwnerAuthority(t, fixture.Fake, decommissioning)
		retired := commitSandboxActiveReadyRetirement(t, fixture, 0, decommissioning, 1_800_000_020_000)
		return fixture, retired, decommissioning
	}

	t.Run("journal N classifies committed retirement", func(t *testing.T) {
		fixture, retired, _ := seedCommitted(t)
		receipt, err := retireSandboxJournaledActiveReadyWithClient(context.Background(), fixture.Fake,
			"active-ready-predecessor-1", state, currentMain, historicalMain, historicalReady, historicalReady,
			func() time.Time { return time.UnixMilli(1_800_000_020_000).UTC() })
		if err != nil || receipt == nil || *receipt != *sandboxActiveReadyReceiptFromRetired(
			"active-ready-predecessor-1", retired) || len(fixture.Fake.transactions) != 0 {
			t.Fatalf("journal N committed retirement = %#v, %v; transactions=%d",
				receipt, err, len(fixture.Fake.transactions))
		}
	})

	t.Run("journal N plus one classifies exact committed retirement", func(t *testing.T) {
		fixture, retired, _ := seedCommitted(t)
		ledger := sandboxActiveReadyTestLedger(t, plan, fences, owners,
			[]string{"retired", "quiescent", "quiescent"}, directory)
		ledger[0].Receipt = sandboxActiveReadyReceiptFromRetired(ledger[0].ID, retired)
		successor := sandboxActiveReadyJournalSuccessor(t, historicalReady, 0, ledger[0])
		receipt, err := retireSandboxJournaledActiveReadyWithClient(context.Background(), fixture.Fake,
			"active-ready-predecessor-1", state, currentMain, historicalMain, successor, historicalReady,
			func() time.Time { return time.UnixMilli(1_800_000_020_000).UTC() })
		if err != nil || receipt == nil || *receipt != *ledger[0].Receipt || len(fixture.Fake.transactions) != 0 {
			t.Fatalf("journal N+1 committed retirement = %#v, %v; transactions=%d",
				receipt, err, len(fixture.Fake.transactions))
		}
	})

	t.Run("journal N plus one ACTIVE rejects without write", func(t *testing.T) {
		fixture := seedSandboxActiveReadyFixture(t)
		decommissioning, err := planSessionControlOwnerDecommission(fixture.Owners[0])
		if err != nil {
			t.Fatal(err)
		}
		seedSessionControlOwnerAuthority(t, fixture.Fake, decommissioning)
		ledger := sandboxActiveReadyTestLedger(t, plan, fences, owners,
			[]string{"retired", "quiescent", "quiescent"}, directory)
		ledger[0].Receipt = sandboxRecoveryRetirementReceipt(ledger[0].ID, fences[0])
		successor := sandboxActiveReadyJournalSuccessor(t, historicalReady, 0, ledger[0])
		if _, err := retireSandboxJournaledActiveReadyWithClient(context.Background(), fixture.Fake,
			"active-ready-predecessor-1", state, currentMain, historicalMain, successor, historicalReady,
			func() time.Time { return time.UnixMilli(1_800_000_020_000).UTC() }); err == nil ||
			len(fixture.Fake.transactions) != 0 {
			t.Fatalf("journal-ahead ACTIVE retirement = %v; transactions=%d", err, len(fixture.Fake.transactions))
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *sandboxActiveReadyFixture, sessionControlTargetAuthority, sessionControlOwnerAuthority)
	}{
		{name: "wrong retired target", mutate: func(t *testing.T, fixture *sandboxActiveReadyFixture,
			retired sessionControlTargetAuthority, _ sessionControlOwnerAuthority,
		) {
			retired.RetiredAtMillis++
			retired.UpdatedAtMillis++
			fixture.setTarget(t, retired)
		}},
		{name: "wrong retired owner", mutate: func(t *testing.T, fixture *sandboxActiveReadyFixture,
			retired sessionControlTargetAuthority, owner sessionControlOwnerAuthority,
		) {
			retiredOwner, err := sessionControlOwnerFromTarget(retired, &owner, sessionControlOwnerRetired)
			if err != nil {
				t.Fatal(err)
			}
			retiredOwner.WorkVersion++
			seedSessionControlOwnerAuthority(t, fixture.Fake, retiredOwner)
		}},
		{name: "wrong retired authority", mutate: func(t *testing.T, fixture *sandboxActiveReadyFixture,
			_ sessionControlTargetAuthority, _ sessionControlOwnerAuthority,
		) {
			fixture.Authority.Version++
			fixture.setAuthority(t, fixture.Authority)
		}},
	} {
		for _, mode := range []string{"journal N", "journal N plus one"} {
			t.Run(test.name+" "+mode, func(t *testing.T) {
				fixture, retired, owner := seedCommitted(t)
				current := historicalReady
				if mode == "journal N plus one" {
					ledger := sandboxActiveReadyTestLedger(t, plan, fences, owners,
						[]string{"retired", "quiescent", "quiescent"}, directory)
					ledger[0].Receipt = sandboxActiveReadyReceiptFromRetired(ledger[0].ID, retired)
					current = sandboxActiveReadyJournalSuccessor(t, historicalReady, 0, ledger[0])
				}
				test.mutate(t, fixture, retired, owner)
				if _, err := retireSandboxJournaledActiveReadyWithClient(context.Background(), fixture.Fake,
					"active-ready-predecessor-1", state, currentMain, historicalMain, current, historicalReady,
					func() time.Time { return time.UnixMilli(1_800_000_020_000).UTC() }); err == nil ||
					len(fixture.Fake.transactions) != 0 {
					t.Fatalf("%s %s = %v; transactions=%d", test.name, mode, err, len(fixture.Fake.transactions))
				}
			})
		}
	}
}

func TestSandboxActiveReadyFinalRetireRequiresDecommissioningDirectoryAndDecrementsOnce(t *testing.T) {
	fixture := seedSandboxActiveReadyFixture(t)
	target, ready := fixture.Targets[0], fixture.Owners[0]
	directory := fixture.Directory
	store := &dynamoSessionControlStore{client: fixture.Fake, tableName: SandboxStaleTargetRetirementTable,
		operationTimeout: time.Second, nowUTC: func() time.Time { return time.UnixMilli(1_800_000_020_000).UTC() }}
	if _, err := store.retireDecommissioningTarget(context.Background(), target.fence(), directory); err == nil {
		t.Fatal("READY owner was retired without the DECOMMISSIONING latch")
	}
	if len(fixture.Fake.transactions) != 0 {
		t.Fatal("READY owner reached final retirement transaction")
	}
	decommissioning, _ := planSessionControlOwnerDecommission(ready)
	seedSessionControlOwnerAuthority(t, fixture.Fake, decommissioning)
	wrongDirectory := directory
	wrongDirectory.Version--
	fixture.Fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		return nil, &types.TransactionCanceledException{}
	}
	if _, err := store.retireDecommissioningTarget(context.Background(), target.fence(), wrongDirectory); err == nil {
		t.Fatal("retirement accepted a non-journal directory")
	}
	fixture.Fake.transactions = nil
	const retiredAt = int64(1_800_000_020_000)
	fixture.Fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		if len(input.TransactItems) != 4 || input.TransactItems[3].ConditionCheck == nil ||
			sessionControlSessionDynamoMapKey(input.TransactItems[3].ConditionCheck.Key) !=
				sessionControlSessionDynamoMapKey(sessionControlFenceDirectoryKey(directory.CellID)) {
			t.Fatalf("final retirement transaction = %#v", input)
		}
		commitSandboxActiveReadyRetirement(t, fixture, 0, decommissioning, retiredAt)
		return nil, context.DeadlineExceeded
	}
	retired, err := store.retireDecommissioningTarget(context.Background(), target.fence(), directory)
	if err != nil || retired.State != sessionControlTargetRetired || fixture.Authority.ActiveTargetCount != 2 ||
		fixture.Authority.Version != 8 {
		t.Fatalf("final retirement = %#v, %v; authority=%#v", retired, err, fixture.Authority)
	}
	fixture.Fake.transactHook = nil
	replayed, err := store.retireDecommissioningTarget(context.Background(), target.fence(), directory)
	if err != nil || *replayed != *retired || len(fixture.Fake.transactions) != 1 ||
		fixture.Authority.ActiveTargetCount != 2 || fixture.Authority.Version != 8 {
		t.Fatalf("final retirement replay = %#v, %v; transactions=%d authority=%#v",
			replayed, err, len(fixture.Fake.transactions), fixture.Authority)
	}
}

func TestDynamoSessionControlPrepareCurrentRetriesOwnerGenerationContentionWithoutSleep(t *testing.T) {
	for seed := byte(0xd0); seed < 0xd2; seed++ {
		t.Run(fmt.Sprintf("session-%x", seed), func(t *testing.T) {
			snapshot := testSessionControlSessionSnapshot(1)
			candidate := testSessionControlSessionCandidate(seed, uint64(900)+uint64(seed))
			reserved, err := planSessionControlReservation(candidate, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			target := testSessionControlSessionTarget(seed + 1)
			fake := newSessionControlSessionDynamoFake()
			seedSessionControlReservation(t, fake, reserved)
			seedSessionControlDirectory(t, fake, snapshot)
			owner := seedSessionControlTarget(t, fake, target)
			store := newSessionControlSessionDynamoStore(fake, time.Second)
			var calls int
			fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
				calls++
				if calls == 1 {
					winner, ownerErr := planSessionControlOwnerAdmission(owner, 1_800_000_010_000)
					if ownerErr != nil {
						t.Fatal(ownerErr)
					}
					seedSessionControlOwnerAuthority(t, fake, winner)
					return nil, &types.TransactionCanceledException{}
				}
				commitSandboxActiveReadyOwnerPut(t, fake, input)
				return &dynamodb.TransactWriteItemsOutput{}, nil
			}
			prepared, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, target,
				candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
			if err != nil || prepared == nil || calls != 2 {
				t.Fatalf("owner-generation retry = %#v, %v; calls=%d", prepared, err, calls)
			}
		})
	}
}
