package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func newDynamoSessionControlTestStore(t *testing.T, handler http.HandlerFunc) *dynamoSessionControlStore {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	cfg := aws.Config{
		Region:      "us-east-2",
		Credentials: credentials.NewStaticCredentialsProvider("test-access-key", "test-secret-key", ""),
		EndpointResolverWithOptions: aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...any) (aws.Endpoint, error) {
				return aws.Endpoint{URL: server.URL, SigningRegion: region}, nil
			},
		),
		HTTPClient: server.Client(),
	}
	return &dynamoSessionControlStore{
		client:    dynamodb.NewFromConfig(cfg),
		tableName: "nhp-session-control-test",
		nowUTC:    func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
	}
}

func sessionControlWireItem(t *testing.T, target sessionControlTargetAuthority) map[string]any {
	t.Helper()
	row, err := sessionControlTargetToRow(target)
	if err != nil {
		t.Fatalf("sessionControlTargetToRow() error = %v", err)
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		t.Fatalf("MarshalMap() error = %v", err)
	}
	if !sessionControlTargetReadinessAttributesPresent(item) {
		t.Fatalf("MarshalMap() omitted required target readiness attributes: %#v", item)
	}
	wire := make(map[string]any, len(item))
	for name, value := range item {
		switch typed := value.(type) {
		case *types.AttributeValueMemberS:
			wire[name] = map[string]any{"S": typed.Value}
		case *types.AttributeValueMemberN:
			wire[name] = map[string]any{"N": typed.Value}
		case *types.AttributeValueMemberBOOL:
			wire[name] = map[string]any{"BOOL": typed.Value}
		default:
			t.Fatalf("unsupported attribute %q type %T", name, value)
		}
	}
	return wire
}

func sessionControlOwnerWireItem(t *testing.T, owner sessionControlOwnerAuthority) map[string]any {
	t.Helper()
	row, err := sessionControlOwnerToRow(owner)
	if err != nil {
		t.Fatal(err)
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		t.Fatal(err)
	}
	wire := make(map[string]any, len(item))
	for name, value := range item {
		switch typed := value.(type) {
		case *types.AttributeValueMemberS:
			wire[name] = map[string]any{"S": typed.Value}
		case *types.AttributeValueMemberN:
			wire[name] = map[string]any{"N": typed.Value}
		case *types.AttributeValueMemberBOOL:
			wire[name] = map[string]any{"BOOL": typed.Value}
		default:
			t.Fatalf("unsupported owner attribute %q type %T", name, value)
		}
	}
	return wire
}

func sessionControlAuthorityWireItem(t *testing.T, authority sessionControlAuthority) map[string]any {
	t.Helper()
	row, err := sessionControlAuthorityToRow(authority)
	if err != nil {
		t.Fatalf("sessionControlAuthorityToRow() error = %v", err)
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		t.Fatalf("MarshalMap() error = %v", err)
	}
	wire := make(map[string]any, len(item))
	for name, value := range item {
		switch typed := value.(type) {
		case *types.AttributeValueMemberS:
			wire[name] = map[string]any{"S": typed.Value}
		case *types.AttributeValueMemberN:
			wire[name] = map[string]any{"N": typed.Value}
		default:
			t.Fatalf("unsupported authority attribute %q type %T", name, value)
		}
	}
	return wire
}

func sessionControlWireString(t *testing.T, item map[string]any, name, kind string) string {
	t.Helper()
	attribute, ok := item[name].(map[string]any)
	if !ok {
		t.Fatalf("attribute %q = %#v, want map", name, item[name])
	}
	value, ok := attribute[kind].(string)
	if !ok {
		t.Fatalf("attribute %q/%q = %#v, want string", name, kind, attribute[kind])
	}
	return value
}

func sessionControlWireBool(t *testing.T, item map[string]any, name string) bool {
	t.Helper()
	attribute, ok := item[name].(map[string]any)
	if !ok {
		t.Fatalf("attribute %q = %#v, want map", name, item[name])
	}
	value, ok := attribute["BOOL"].(bool)
	if !ok {
		t.Fatalf("attribute %q/BOOL = %#v, want bool", name, attribute["BOOL"])
	}
	return value
}

func writeSessionControlDynamoJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encode DynamoDB response: %v", err)
	}
}

func decodeSessionControlDynamoRequest(t *testing.T, r *http.Request, out any) {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read DynamoDB request: %v", err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatalf("decode DynamoDB request: %v body=%s", err, body)
	}
}

func testSessionControlTargetAuthority(candidate sessionControlTargetCandidate, state sessionControlTargetState, version uint64) sessionControlTargetAuthority {
	target := sessionControlTargetAuthority{
		ACID:             candidate.ACID,
		PublicKey:        candidate.PublicKey,
		BootID:           candidate.BootID,
		FlushGeneration:  candidate.FlushGeneration,
		ControlCellID:    candidate.ControlCellID,
		State:            state,
		Version:          version,
		AuthorityVersion: 1,
		CreatedAtMillis:  1_800_000_000_000,
		PreparedAtMillis: 1_800_000_000_000,
		UpdatedAtMillis:  1_800_000_000_000,
	}
	if state == sessionControlTargetActive {
		target.AuthorityVersion = 2
		target.CountedActiveSlot = true
		target.ActivatedControlVersion = 1
	}
	return target
}

func TestDynamoSessionControlFinalizeTargetReadyExactWireAndOrdering(t *testing.T) {
	t.Run("exact wire", func(t *testing.T) {
		fake := newSessionControlSessionDynamoFake()
		store := newSessionControlSessionDynamoStore(fake, time.Second)
		candidate := testSessionControlTargetCandidate(0x62, "00112233445566778899aabbccddeeff", 4)
		active := testSessionControlTargetAuthority(candidate, sessionControlTargetActive, 2)
		currentOwner := seedSessionControlOwner(t, fake, active)
		snapshot := sessionControlFenceSnapshot{CellID: candidate.ControlCellID, DirectoryVersion: 1, ActiveFenceCount: 3}
		readiness := active.fence().readiness(snapshot, active.PreparedAtMillis+25, 901)
		got, err := store.FinalizeTargetReady(context.Background(), readiness)
		if err != nil || !got.ready() || got.Version != 3 {
			t.Fatalf("FinalizeTargetReady() = %#v, %v", got, err)
		}
		if len(fake.transactions) != 1 || len(fake.transactions[0].TransactItems) != 3 {
			t.Fatalf("transactions = %#v", fake.transactions)
		}
		txn := fake.transactions[0]
		nextOwner, ownerErr := sessionControlOwnerFromTarget(*got, &currentOwner, sessionControlOwnerReady)
		if ownerErr != nil {
			t.Fatal(ownerErr)
		}
		if token := aws.ToString(txn.ClientRequestToken); token != aws.ToString(sessionControlOwnerTransitionToken("ready", &currentOwner, nextOwner)) || len(token) > 36 {
			t.Fatalf("readiness token = %q", token)
		}
		targetWrite := txn.TransactItems[0].Update
		if targetWrite == nil || !strings.Contains(aws.ToString(targetWrite.UpdateExpression), "ready_control_version = :next_ready_control_version") ||
			!strings.Contains(aws.ToString(targetWrite.UpdateExpression), "aak_enqueued_at_ms = :next_aak_enqueued_at") ||
			!strings.Contains(aws.ToString(targetWrite.UpdateExpression), "aak_transaction_id = :next_aak_transaction_id") {
			t.Fatalf("target readiness update = %#v", targetWrite)
		}
		for _, fragment := range []string{
			"activated_control_version = :activated_control_version", "ready_control_version = :ready_control_version",
			"aak_enqueued_at_ms = :aak_enqueued_at", "aak_transaction_id = :aak_transaction_id",
			"attribute_not_exists(retired_at_ms)", "attribute_not_exists(#ttl)",
		} {
			if !strings.Contains(aws.ToString(targetWrite.ConditionExpression), fragment) {
				t.Fatalf("target condition missing %q: %s", fragment, aws.ToString(targetWrite.ConditionExpression))
			}
		}
		values := targetWrite.ExpressionAttributeValues
		if current, ok := values[":ready_control_version"].(*types.AttributeValueMemberN); !ok || current.Value != "0" {
			t.Fatalf("current readiness cursor = %#v, want zero", values[":ready_control_version"])
		}
		if next, ok := values[":next_ready_control_version"].(*types.AttributeValueMemberN); !ok || next.Value != "1" {
			t.Fatalf("next readiness cursor = %#v, want one", values[":next_ready_control_version"])
		}
		control := txn.TransactItems[1].ConditionCheck
		for _, fragment := range []string{"#version = :version", "active_fence_count = :count", "admission_blocked = :admission_blocked", "overflow_close_count = :overflow_close_count", "attribute_not_exists(#ttl)"} {
			if control == nil || !strings.Contains(aws.ToString(control.ConditionExpression), fragment) {
				t.Fatalf("CONTROL condition missing %q: %#v", fragment, control)
			}
		}
		if value, ok := control.ExpressionAttributeValues[":count"].(*types.AttributeValueMemberN); !ok || value.Value != "3" {
			t.Fatalf("CONTROL active count = %#v", control.ExpressionAttributeValues[":count"])
		}
		ownerWrite := txn.TransactItems[2].Put
		if ownerWrite == nil || !strings.Contains(aws.ToString(ownerWrite.ConditionExpression), "pending_count = :owner_pending_count") ||
			sessionControlWireString(t, sessionControlAttributeWireMap(t, ownerWrite.Item), "phase", "S") != string(sessionControlOwnerReady) {
			t.Fatalf("owner readiness update = %#v", ownerWrite)
		}
	})

	t.Run("event before finalize is stale", func(t *testing.T) {
		fake := newSessionControlSessionDynamoFake()
		store := newSessionControlSessionDynamoStore(fake, time.Second)
		candidate := testSessionControlTargetCandidate(0x63, "00112233445566778899aabbccddeeff", 5)
		active := testSessionControlTargetAuthority(candidate, sessionControlTargetActive, 2)
		seedSessionControlTarget(t, fake, active)
		seedSessionControlDirectory(t, fake, sessionControlFenceSnapshot{CellID: candidate.ControlCellID, DirectoryVersion: 2, ActiveFenceCount: 1})
		fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			return nil, &types.TransactionCanceledException{}
		}
		readiness := active.fence().readiness(sessionControlFenceSnapshot{CellID: candidate.ControlCellID, DirectoryVersion: 1}, active.PreparedAtMillis+1, 902)
		if _, err := store.FinalizeTargetReady(context.Background(), readiness); !errors.Is(err, errSessionControlTargetControlStale) {
			t.Fatalf("event-first finalize error = %v", err)
		}
	})

	t.Run("exact committed result wins after later event", func(t *testing.T) {
		fake := newSessionControlSessionDynamoFake()
		store := newSessionControlSessionDynamoStore(fake, time.Second)
		candidate := testSessionControlTargetCandidate(0x64, "00112233445566778899aabbccddeeff", 6)
		active := testSessionControlTargetAuthority(candidate, sessionControlTargetActive, 2)
		readiness := active.fence().readiness(sessionControlFenceSnapshot{CellID: candidate.ControlCellID, DirectoryVersion: 1}, active.PreparedAtMillis+1, 903)
		finalized := active
		finalized.Version++
		finalized.ReadyControlVersion = finalized.ActivatedControlVersion
		finalized.AAKEnqueuedAtMillis = readiness.AAKEnqueuedAtMillis
		finalized.AAKTransactionID = readiness.AAKTransactionID
		finalized.UpdatedAtMillis = readiness.AAKEnqueuedAtMillis
		currentOwner, err := sessionControlOwnerFromTarget(active, nil, sessionControlOwnerActiveUnready)
		if err != nil {
			t.Fatal(err)
		}
		finalOwner, err := sessionControlOwnerFromTarget(finalized, &currentOwner, sessionControlOwnerReady)
		if err != nil {
			t.Fatal(err)
		}
		targetRow, err := sessionControlTargetToRow(finalized)
		if err != nil {
			t.Fatal(err)
		}
		ownerRow, err := sessionControlOwnerToRow(finalOwner)
		if err != nil {
			t.Fatal(err)
		}
		fake.setItem(marshalSessionControlSessionTestRow(t, targetRow))
		fake.setItem(marshalSessionControlSessionTestRow(t, ownerRow))
		seedSessionControlDirectory(t, fake, sessionControlFenceSnapshot{
			CellID: candidate.ControlCellID, DirectoryVersion: 9, ActiveFenceCount: 8,
			AdmissionBlocked: true, OverflowCloseCount: 1,
			OverflowLeaderEventID:                  "00000000000000000000000000000001",
			OverflowLeaderPreparedDirectoryVersion: 8, OverflowLeaderSelectedDirectoryVersion: 9,
		})
		fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			return nil, context.DeadlineExceeded
		}
		got, err := store.FinalizeTargetReady(context.Background(), readiness)
		if err != nil || *got != finalized {
			t.Fatalf("ambiguous finalize = %#v, %v; want %#v", got, err, finalized)
		}
		if len(fake.gets) != 2 {
			t.Fatalf("classification reads = %d, want exact owner and target", len(fake.gets))
		}
	})

	t.Run("exact committed result wins after later owner task", func(t *testing.T) {
		fake := newSessionControlSessionDynamoFake()
		store := newSessionControlSessionDynamoStore(fake, time.Second)
		candidate := testSessionControlTargetCandidate(0x6d, "00112233445566778899aabbccddeeff", 13)
		active := testSessionControlTargetAuthority(candidate, sessionControlTargetActive, 2)
		readiness := active.fence().readiness(sessionControlFenceSnapshot{
			CellID: candidate.ControlCellID, DirectoryVersion: 1,
		}, active.PreparedAtMillis+1, 904)
		finalized := active
		finalized.Version++
		finalized.ReadyControlVersion = finalized.ActivatedControlVersion
		finalized.AAKEnqueuedAtMillis = readiness.AAKEnqueuedAtMillis
		finalized.AAKTransactionID = readiness.AAKTransactionID
		finalized.UpdatedAtMillis = readiness.AAKEnqueuedAtMillis
		activeOwner, err := sessionControlOwnerFromTarget(active, nil, sessionControlOwnerActiveUnready)
		if err != nil {
			t.Fatal(err)
		}
		readyOwner, err := sessionControlOwnerFromTarget(finalized, &activeOwner, sessionControlOwnerReady)
		if err != nil {
			t.Fatal(err)
		}
		pendingOwner, err := planSessionControlOwnerTaskInsert(readyOwner, readyOwner.UpdatedAtMillis+1)
		if err != nil {
			t.Fatal(err)
		}
		targetRow, _ := sessionControlTargetToRow(finalized)
		ownerRow, _ := sessionControlOwnerToRow(pendingOwner)
		fake.setItem(marshalSessionControlSessionTestRow(t, targetRow))
		fake.setItem(marshalSessionControlSessionTestRow(t, ownerRow))
		got, err := store.FinalizeTargetReady(context.Background(), readiness)
		if err != nil || *got != finalized || len(fake.transactions) != 0 {
			t.Fatalf("finalize retry after task = %#v, %v; transactions=%d", got, err, len(fake.transactions))
		}
	})
}

func TestDynamoSessionControlFinalizeTargetReadyLosesToPendingOwnerTask(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	candidate := testSessionControlTargetCandidate(0x6f, "00112233445566778899aabbccddeeff", 19)
	active := testSessionControlTargetAuthority(candidate, sessionControlTargetActive, 2)
	owner := seedSessionControlTarget(t, fake, active)
	directory := sessionControlFenceDirectory{
		CellID: candidate.ControlCellID, Version: active.ActivatedControlVersion, ActiveFenceCount: 1,
		CreatedAtMillis: active.CreatedAtMillis, UpdatedAtMillis: active.UpdatedAtMillis,
	}
	seedSessionControlCloseDirectory(t, fake, directory)
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
	readiness := active.fence().readiness(sessionControlFenceSnapshot{
		CellID: candidate.ControlCellID, DirectoryVersion: directory.Version, ActiveFenceCount: directory.ActiveFenceCount,
	}, active.PreparedAtMillis+1, 77)
	if _, err := store.FinalizeTargetReady(context.Background(), readiness); !errors.Is(err, errSessionControlTargetConflict) {
		t.Fatalf("FinalizeTargetReady() pending-task race error = %v, want conflict", err)
	}
}

func TestDynamoSessionControlTargetRejectsMissingReadinessAttributes(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	target := testSessionControlTargetAuthority(
		testSessionControlTargetCandidate(0x65, "00112233445566778899aabbccddeeff", 7),
		sessionControlTargetActive, 2)
	row, err := sessionControlTargetToRow(target)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"ready_control_version", "aak_enqueued_at_ms", "aak_transaction_id"} {
		t.Run(field, func(t *testing.T) {
			item, err := attributevalue.MarshalMap(row)
			if err != nil {
				t.Fatal(err)
			}
			delete(item, field)
			fake.items = map[string]map[string]types.AttributeValue{sessionControlSessionDynamoMapKey(item): item}
			if _, err := store.GetTarget(context.Background(), target.key()); !errors.Is(err, errSessionControlTargetCorrupt) {
				t.Fatalf("missing %s error = %v, want corrupt", field, err)
			}
		})
	}
}

func TestDynamoSessionControlExactActivePrepareIsNoWrite(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	candidate := testSessionControlTargetCandidate(0x66, "00112233445566778899aabbccddeeff", 8)
	current := testSessionControlTargetAuthority(candidate, sessionControlTargetActive, 3)
	current.AuthorityVersion = 2
	current.ReadyControlVersion = current.ActivatedControlVersion
	current.AAKEnqueuedAtMillis = current.PreparedAtMillis
	current.AAKTransactionID = 1001
	seedSessionControlTarget(t, fake, current)
	authorityRow, err := sessionControlAuthorityToRow(sessionControlAuthority{
		ACID: candidate.ACID, ControlCellID: candidate.ControlCellID, Version: 2, ActiveTargetCount: 1,
		CreatedAtMillis: current.CreatedAtMillis, UpdatedAtMillis: current.UpdatedAtMillis,
	})
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, authorityRow))
	prepared, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.RequiresActivation || prepared.Target != current || len(fake.transactions) != 0 {
		t.Fatalf("exact ACTIVE prepare = %#v; transactions=%d, want no-write", prepared, len(fake.transactions))
	}
}

func TestDynamoSessionControlReprepareForControlAdvanceExactWireAndAmbiguity(t *testing.T) {
	for _, lostResponse := range []bool{false, true} {
		t.Run(fmt.Sprintf("lost_response_%t", lostResponse), func(t *testing.T) {
			fake := newSessionControlSessionDynamoFake()
			store := newSessionControlSessionDynamoStore(fake, time.Second)
			candidate := testSessionControlTargetCandidate(0x65, "00112233445566778899aabbccddeeff", 8)
			current := testSessionControlTargetAuthority(candidate, sessionControlTargetActive, 3)
			owner := seedSessionControlTarget(t, fake, current)
			authority := sessionControlAuthority{
				ACID: candidate.ACID, ControlCellID: candidate.ControlCellID, Version: current.AuthorityVersion,
				ActiveTargetCount: 1, CreatedAtMillis: current.CreatedAtMillis, UpdatedAtMillis: current.UpdatedAtMillis,
			}
			authorityRow, err := sessionControlAuthorityToRow(authority)
			if err != nil {
				t.Fatal(err)
			}
			fake.setItem(marshalSessionControlSessionTestRow(t, authorityRow))
			planned, err := sessionControlTargetAdvancedPreparation(current, authority, store.nowUTC())
			if err != nil {
				t.Fatal(err)
			}
			nextOwner, err := sessionControlOwnerFromTarget(planned.Target, &owner, sessionControlOwnerPreparing)
			if err != nil {
				t.Fatal(err)
			}
			if lostResponse {
				fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
					targetRow, _ := sessionControlTargetToRow(planned.Target)
					ownerRow, _ := sessionControlOwnerToRow(nextOwner)
					fake.setItem(marshalSessionControlSessionTestRow(t, targetRow))
					fake.setItem(marshalSessionControlSessionTestRow(t, ownerRow))
					return nil, errors.New("lost reprepare response")
				}
			}
			got, err := store.ReprepareTargetForControlAdvance(context.Background(), sessionControlTargetControlAdvance{
				Target: current, ObservedControlVersion: current.ActivatedControlVersion + 1,
			})
			if err != nil || got == nil || got.Target != planned.Target || !got.RequiresActivation {
				t.Fatalf("ReprepareTargetForControlAdvance() = %#v, %v", got, err)
			}
			if len(fake.transactions) != 1 || len(fake.transactions[0].TransactItems) != 2 ||
				fake.transactions[0].TransactItems[0].Update == nil || fake.transactions[0].TransactItems[1].Put == nil ||
				aws.ToString(fake.transactions[0].ClientRequestToken) == "" ||
				len(aws.ToString(fake.transactions[0].ClientRequestToken)) > 36 {
				t.Fatalf("reprepare transaction = %#v", fake.transactions)
			}
		})
	}
}

func TestSessionControlReprepareForControlAdvanceRejectsEqualOrLowerCursor(t *testing.T) {
	current := testSessionControlTargetAuthority(
		testSessionControlTargetCandidate(0x64, "00112233445566778899aabbccddeeff", 7),
		sessionControlTargetActive, 3)
	for _, observed := range []uint64{current.ActivatedControlVersion, current.ActivatedControlVersion - 1} {
		fake := newSessionControlSessionDynamoFake()
		store := newSessionControlSessionDynamoStore(fake, time.Second)
		if _, err := store.ReprepareTargetForControlAdvance(context.Background(), sessionControlTargetControlAdvance{
			Target: current, ObservedControlVersion: observed,
		}); err == nil || len(fake.transactions) != 0 {
			t.Fatalf("observed cursor %d reached write: err=%v transactions=%d", observed, err, len(fake.transactions))
		}
	}
}

func TestDynamoSessionControlPrepareRetriesTornTargetOwnerReconnect(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	oldCandidate := testSessionControlTargetCandidate(0x67, "00112233445566778899aabbccddeeff", 8)
	current := testSessionControlTargetAuthority(oldCandidate, sessionControlTargetActive, 3)
	current.ReadyControlVersion = current.ActivatedControlVersion
	current.AAKEnqueuedAtMillis = current.UpdatedAtMillis
	current.AAKTransactionID = 88
	oldOwner := seedSessionControlTarget(t, fake, current)
	authority := sessionControlAuthority{
		ACID: oldCandidate.ACID, ControlCellID: oldCandidate.ControlCellID, Version: 2, ActiveTargetCount: 1,
		CreatedAtMillis: current.CreatedAtMillis, UpdatedAtMillis: current.UpdatedAtMillis,
	}
	authorityRow, err := sessionControlAuthorityToRow(authority)
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, authorityRow))
	candidate := oldCandidate
	candidate.BootID = "11112222333344445555666677778888"
	candidate.FlushGeneration++
	planned, write, err := planSessionControlTargetPreparation(&current, candidate, authority, store.nowUTC())
	if err != nil || !write {
		t.Fatalf("planned reconnect = %#v, %v, write=%t", planned, err, write)
	}
	nextOwner, err := sessionControlOwnerFromTarget(planned.Target, &oldOwner, sessionControlOwnerPreparing)
	if err != nil {
		t.Fatal(err)
	}
	nextTargetRow, _ := sessionControlTargetToRow(planned.Target)
	nextOwnerRow, _ := sessionControlOwnerToRow(nextOwner)
	nextTargetItem := marshalSessionControlSessionTestRow(t, nextTargetRow)
	nextOwnerItem := marshalSessionControlSessionTestRow(t, nextOwnerRow)
	targetKey := sessionControlSessionDynamoMapKey(sessionControlTargetDynamoKey(current.key()))
	ownerKey := sessionControlSessionDynamoMapKey(sessionControlOwnerKey(current.ControlCellID, current.ACID, current.PublicKey))
	targetReads := 0
	fake.getHook = func(_ context.Context, input *dynamodb.GetItemInput, _ int) (*dynamodb.GetItemOutput, error) {
		key := sessionControlSessionDynamoMapKey(input.Key)
		if key == targetKey {
			targetReads++
			if targetReads == 2 {
				fake.setItem(nextTargetItem)
				fake.setItem(nextOwnerItem)
			}
		}
		fake.mu.Lock()
		item := fake.items[key]
		fake.mu.Unlock()
		return &dynamodb.GetItemOutput{Item: item}, nil
	}
	got, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil || got.Target != planned.Target || got.RequiresActivation != planned.RequiresActivation || len(fake.transactions) != 0 {
		t.Fatalf("PrepareTarget() torn reconnect = %#v, %v; transactions=%d owner-key=%s", got, err, len(fake.transactions), ownerKey)
	}
}

func TestDynamoSessionControlFinalizeTargetReadyRejectsCeilingsBeforeWrite(t *testing.T) {
	for name, mutate := range map[string]func(*sessionControlTargetReadiness){
		"target version": func(readiness *sessionControlTargetReadiness) {
			readiness.Fence.Version = ^uint64(0) - 1
		},
		"active fence count": func(readiness *sessionControlTargetReadiness) {
			readiness.ControlDirectory.ActiveFenceCount = sessionControlFenceActiveLimit + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newSessionControlSessionDynamoFake()
			store := newSessionControlSessionDynamoStore(fake, time.Second)
			target := testSessionControlTargetAuthority(
				testSessionControlTargetCandidate(0x67, "00112233445566778899aabbccddeeff", 9),
				sessionControlTargetActive, 2)
			readiness := target.fence().readiness(sessionControlFenceSnapshot{
				CellID: target.ControlCellID, DirectoryVersion: target.ActivatedControlVersion,
			}, target.PreparedAtMillis+1, 1002)
			mutate(&readiness)
			if _, err := store.FinalizeTargetReady(context.Background(), readiness); err == nil {
				t.Fatal("invalid readiness ceiling reached DynamoDB")
			}
			if len(fake.transactions) != 0 {
				t.Fatalf("invalid readiness wrote %d transactions", len(fake.transactions))
			}
		})
	}
}

func TestDynamoSessionControlTargetAuthorityReadsAreStrongAndStateFiltered(t *testing.T) {
	activeCandidate := testSessionControlTargetCandidate(0x41, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 3)
	preparingCandidate := testSessionControlTargetCandidate(0x42, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 4)
	countedPreparingCandidate := testSessionControlTargetCandidate(0x46, "abababababababababababababababab", 5)
	active := testSessionControlTargetAuthority(activeCandidate, sessionControlTargetActive, 2)
	preparing := testSessionControlTargetAuthority(preparingCandidate, sessionControlTargetPreparing, 1)
	countedPreparing := testSessionControlTargetAuthority(countedPreparingCandidate, sessionControlTargetPreparing, 3)
	countedPreparing.AuthorityVersion = 2
	countedPreparing.CountedActiveSlot = true
	authority := sessionControlAuthority{
		ACID:              active.ACID,
		ControlCellID:     active.ControlCellID,
		Version:           2,
		ActiveTargetCount: 2,
		CreatedAtMillis:   1_800_000_000_000,
		UpdatedAtMillis:   1_800_000_000_000,
	}
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-Amz-Target") {
		case "DynamoDB_20120810.GetItem":
			var req struct {
				TableName      string                       `json:"TableName"`
				ConsistentRead bool                         `json:"ConsistentRead"`
				Key            map[string]map[string]string `json:"Key"`
			}
			decodeSessionControlDynamoRequest(t, r, &req)
			if req.TableName != storeTableNameForTest || !req.ConsistentRead {
				t.Fatalf("GetItem table/consistent = %q/%t", req.TableName, req.ConsistentRead)
			}
			if req.Key["pk"]["S"] != sessionControlTargetPK(active.ACID) {
				t.Fatalf("GetItem key = %#v", req.Key)
			}
			calls.Add(1)
			switch req.Key["sk"]["S"] {
			case sessionControlTargetSK(active.PublicKey):
				writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlWireItem(t, active)})
			case sessionControlAuthoritySK:
				writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlAuthorityWireItem(t, authority)})
			default:
				t.Fatalf("GetItem SK = %#v", req.Key)
			}
		case "DynamoDB_20120810.Query":
			var req struct {
				TableName                 string                       `json:"TableName"`
				ConsistentRead            bool                         `json:"ConsistentRead"`
				KeyConditionExpression    string                       `json:"KeyConditionExpression"`
				ExpressionAttributeValues map[string]map[string]string `json:"ExpressionAttributeValues"`
			}
			decodeSessionControlDynamoRequest(t, r, &req)
			if req.TableName != storeTableNameForTest || !req.ConsistentRead {
				t.Fatalf("Query table/consistent = %q/%t", req.TableName, req.ConsistentRead)
			}
			if req.KeyConditionExpression != "pk = :pk AND begins_with(sk, :target_prefix)" ||
				req.ExpressionAttributeValues[":pk"]["S"] != sessionControlTargetPK(active.ACID) ||
				req.ExpressionAttributeValues[":target_prefix"]["S"] != sessionControlTargetPrefix {
				t.Fatalf("Query authority scope = %#v", req)
			}
			calls.Add(1)
			writeSessionControlDynamoJSON(t, w, map[string]any{
				"Items":        []any{sessionControlWireItem(t, preparing), sessionControlWireItem(t, countedPreparing), sessionControlWireItem(t, active)},
				"Count":        3,
				"ScannedCount": 3,
			})
		default:
			t.Fatalf("unexpected DynamoDB operation %q", r.Header.Get("X-Amz-Target"))
		}
	})

	got, err := store.GetTarget(context.Background(), active.key())
	if err != nil || *got != active {
		t.Fatalf("GetTarget() = %#v, %v; want %#v", got, err, active)
	}
	required, err := store.ListRequiredTargets(context.Background(), active.ACID, active.ControlCellID)
	if err != nil {
		t.Fatalf("ListRequiredTargets() error = %v", err)
	}
	if len(required) != 2 || required[0] != countedPreparing || required[1] != active {
		t.Fatalf("required targets = %#v, want counted preparing plus active", required)
	}
	if calls.Load() != 4 {
		t.Fatalf("DynamoDB calls = %d, want target GetItem + bracketed authority GetItems around Query", calls.Load())
	}
}

const storeTableNameForTest = "nhp-session-control-test"

type sessionControlCancelClassificationClient struct {
	target       map[string]types.AttributeValue
	updateCtxErr error
	getCtxErr    error
}

func (c *sessionControlCancelClassificationClient) GetItem(ctx context.Context, _ *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	c.getCtxErr = ctx.Err()
	if c.getCtxErr != nil {
		return nil, c.getCtxErr
	}
	return &dynamodb.GetItemOutput{Item: c.target}, nil
}

func (c *sessionControlCancelClassificationClient) UpdateItem(ctx context.Context, _ *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	<-ctx.Done()
	c.updateCtxErr = ctx.Err()
	return nil, &types.ConditionalCheckFailedException{}
}

func (*sessionControlCancelClassificationClient) PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	return nil, errors.New("unexpected PutItem")
}

func (*sessionControlCancelClassificationClient) Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	return nil, errors.New("unexpected Query")
}

func (*sessionControlCancelClassificationClient) TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	return nil, errors.New("unexpected TransactWriteItems")
}

func TestDynamoSessionControlCancelClassifiesWithParentContextAfterOperationDeadline(t *testing.T) {
	candidate := testSessionControlTargetCandidate(0x47, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", 8)
	preparing := testSessionControlTargetAuthority(candidate, sessionControlTargetPreparing, 9)
	canceled := preparing
	canceled.State = sessionControlTargetCanceled
	canceled.Version++
	row, err := sessionControlTargetToRow(canceled)
	if err != nil {
		t.Fatal(err)
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		t.Fatal(err)
	}
	client := &sessionControlCancelClassificationClient{target: item}
	store := &dynamoSessionControlStore{
		client:           client,
		tableName:        storeTableNameForTest,
		nowUTC:           func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
		operationTimeout: time.Millisecond,
	}
	got, err := store.CancelTargetPreparation(context.Background(), preparing.fence())
	if err != nil || *got != canceled {
		t.Fatalf("CancelTargetPreparation() = %#v, %v; want idempotent %#v", got, err, canceled)
	}
	if !errors.Is(client.updateCtxErr, context.DeadlineExceeded) {
		t.Fatalf("UpdateItem context error = %v, want deadline exceeded", client.updateCtxErr)
	}
	if client.getCtxErr != nil {
		t.Fatalf("classification GetItem inherited spent operation context: %v", client.getCtxErr)
	}
}

func TestDynamoSessionControlPrepareUsesStrongReadAndConditionalCreate(t *testing.T) {
	candidate := testSessionControlTargetCandidate(0x43, "cccccccccccccccccccccccccccccccc", 5)
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			if got := r.Header.Get("X-Amz-Target"); got != "DynamoDB_20120810.GetItem" {
				t.Fatalf("first DynamoDB operation = %q, want GetItem", got)
			}
			var req struct {
				ConsistentRead bool `json:"ConsistentRead"`
			}
			decodeSessionControlDynamoRequest(t, r, &req)
			if !req.ConsistentRead {
				t.Fatal("preparation read was not strongly consistent")
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		case 2:
			if got := r.Header.Get("X-Amz-Target"); got != "DynamoDB_20120810.PutItem" {
				t.Fatalf("second DynamoDB operation = %q, want PutItem", got)
			}
			var req struct {
				TableName           string         `json:"TableName"`
				ConditionExpression string         `json:"ConditionExpression"`
				Item                map[string]any `json:"Item"`
			}
			decodeSessionControlDynamoRequest(t, r, &req)
			if req.TableName != storeTableNameForTest || req.ConditionExpression != "attribute_not_exists(pk) AND attribute_not_exists(sk)" {
				t.Fatalf("conditional create = %#v", req)
			}
			if sessionControlWireString(t, req.Item, "kind", "S") != sessionControlAuthorityKind ||
				sessionControlWireString(t, req.Item, "version", "N") != "1" ||
				sessionControlWireString(t, req.Item, "active_target_count", "N") != "0" {
				t.Fatalf("authority row = %#v", req.Item)
			}
			if _, present := req.Item["control_cell_id"]; present {
				t.Fatalf("unbound authority persisted a control cell: %#v", req.Item)
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		case 3:
			if got := r.Header.Get("X-Amz-Target"); got != "DynamoDB_20120810.GetItem" {
				t.Fatalf("third DynamoDB operation = %q, want target GetItem", got)
			}
			var req struct {
				ConsistentRead bool `json:"ConsistentRead"`
			}
			decodeSessionControlDynamoRequest(t, r, &req)
			if !req.ConsistentRead {
				t.Fatal("target preparation read was not strongly consistent")
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		case 4:
			if got := r.Header.Get("X-Amz-Target"); got != "DynamoDB_20120810.TransactWriteItems" {
				t.Fatalf("fourth DynamoDB operation = %q, want target+owner transaction", got)
			}
			var req struct {
				ClientRequestToken string `json:"ClientRequestToken"`
				TransactItems      []struct {
					Put *struct {
						TableName           string         `json:"TableName"`
						ConditionExpression string         `json:"ConditionExpression"`
						Item                map[string]any `json:"Item"`
					} `json:"Put"`
				} `json:"TransactItems"`
			}
			decodeSessionControlDynamoRequest(t, r, &req)
			if len(req.TransactItems) != 2 || len(req.ClientRequestToken) > 36 {
				t.Fatalf("target+owner create = %#v", req)
			}
			for index, member := range req.TransactItems {
				if member.Put == nil || member.Put.TableName != storeTableNameForTest ||
					member.Put.ConditionExpression != "attribute_not_exists(pk) AND attribute_not_exists(sk)" {
					t.Fatalf("conditional target+owner create %d = %#v", index, member.Put)
				}
			}
			targetItem := req.TransactItems[0].Put.Item
			if sessionControlWireString(t, targetItem, "state", "S") != string(sessionControlTargetPreparing) ||
				sessionControlWireString(t, targetItem, "version", "N") != "1" ||
				sessionControlWireString(t, targetItem, "authority_version", "N") != "1" ||
				sessionControlWireString(t, targetItem, "control_cell_id", "S") != candidate.ControlCellID ||
				sessionControlWireString(t, targetItem, "activated_control_version", "N") != "0" ||
				sessionControlWireBool(t, targetItem, "counted_active_slot") {
				t.Fatalf("prepared target row = %#v", targetItem)
			}
			ownerItem := req.TransactItems[1].Put.Item
			if sessionControlWireString(t, ownerItem, "kind", "S") != sessionControlOwnerKind ||
				sessionControlWireString(t, ownerItem, "phase", "S") != string(sessionControlOwnerPreparing) ||
				sessionControlWireString(t, ownerItem, "task_count", "N") != "0" ||
				sessionControlWireString(t, ownerItem, "pending_count", "N") != "0" {
				t.Fatalf("prepared owner row = %#v", ownerItem)
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		default:
			t.Fatalf("unexpected extra DynamoDB call")
		}
	})

	prepared, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil {
		t.Fatalf("PrepareTarget() error = %v", err)
	}
	if prepared.Target.State != sessionControlTargetPreparing || prepared.Target.Version != 1 || !prepared.RequiresActivation {
		t.Fatalf("preparation = %#v", prepared)
	}
}

func TestDynamoSessionControlActivateUsesExactVersionCAS(t *testing.T) {
	candidate := testSessionControlTargetCandidate(0x44, "dddddddddddddddddddddddddddddddd", 6)
	preparing := testSessionControlTargetAuthority(candidate, sessionControlTargetPreparing, 9)
	active := preparing
	active.State = sessionControlTargetActive
	active.Version++
	active.AuthorityVersion++
	active.CountedActiveSlot = true
	active.ActivatedControlVersion = 1
	preparingOwner, err := sessionControlOwnerFromTarget(preparing, nil, sessionControlOwnerPreparing)
	if err != nil {
		t.Fatal(err)
	}
	activeOwner, err := sessionControlOwnerFromTarget(active, &preparingOwner, sessionControlOwnerActiveUnready)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			if got := r.Header.Get("X-Amz-Target"); got != "DynamoDB_20120810.GetItem" {
				t.Fatalf("first DynamoDB operation = %q, want owner GetItem", got)
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlOwnerWireItem(t, preparingOwner)})
			return
		}
		if got := r.Header.Get("X-Amz-Target"); got != "DynamoDB_20120810.TransactWriteItems" {
			t.Fatalf("DynamoDB operation = %q, want TransactWriteItems", got)
		}
		var req struct {
			ClientRequestToken string `json:"ClientRequestToken"`
			TransactItems      []struct {
				Update *struct {
					TableName                 string            `json:"TableName"`
					Key                       map[string]any    `json:"Key"`
					ConditionExpression       string            `json:"ConditionExpression"`
					UpdateExpression          string            `json:"UpdateExpression"`
					ExpressionAttributeNames  map[string]string `json:"ExpressionAttributeNames"`
					ExpressionAttributeValues map[string]any    `json:"ExpressionAttributeValues"`
				} `json:"Update"`
				ConditionCheck *struct {
					Key                       map[string]any `json:"Key"`
					ConditionExpression       string         `json:"ConditionExpression"`
					ExpressionAttributeValues map[string]any `json:"ExpressionAttributeValues"`
				} `json:"ConditionCheck"`
				Put *struct {
					ConditionExpression string         `json:"ConditionExpression"`
					Item                map[string]any `json:"Item"`
				} `json:"Put"`
			} `json:"TransactItems"`
		}
		decodeSessionControlDynamoRequest(t, r, &req)
		if req.ClientRequestToken != aws.ToString(sessionControlOwnerTransitionToken("activate", &preparingOwner, activeOwner)) || len(req.ClientRequestToken) > 36 {
			t.Fatalf("activation client request token = %q", req.ClientRequestToken)
		}
		if len(req.TransactItems) != 4 || req.TransactItems[0].Update == nil || req.TransactItems[1].Update == nil || req.TransactItems[2].ConditionCheck == nil || req.TransactItems[3].Put == nil {
			t.Fatalf("activation transaction = %#v", req.TransactItems)
		}
		targetUpdate := req.TransactItems[0].Update
		authorityUpdate := req.TransactItems[1].Update
		for _, fragment := range []string{"ac_id = :ac_id", "public_key = :public_key", "boot_id = :boot_id", "flush_generation = :flush_generation", "control_cell_id = :control_cell_id", "activated_control_version = :activated_control_version", "ready_control_version = :ready_control_version", "aak_enqueued_at_ms = :aak_enqueued_at", "aak_transaction_id = :aak_transaction_id", "created_at_ms = :created_at", "prepared_at_ms = :prepared_at", "#state = :current_state", "#version = :current_version"} {
			if !strings.Contains(targetUpdate.ConditionExpression, fragment) {
				t.Fatalf("activation condition %q lacks %q", targetUpdate.ConditionExpression, fragment)
			}
		}
		if targetUpdate.ExpressionAttributeNames["#state"] != "state" || targetUpdate.ExpressionAttributeNames["#version"] != "version" ||
			!strings.Contains(targetUpdate.UpdateExpression, "activated_control_version = :caught_up_control_version") ||
			!strings.Contains(targetUpdate.UpdateExpression, "ready_control_version = :zero_control_version") ||
			!strings.Contains(targetUpdate.UpdateExpression, "aak_enqueued_at_ms = :zero_time") ||
			!strings.Contains(targetUpdate.UpdateExpression, "aak_transaction_id = :zero_transaction") ||
			sessionControlWireString(t, targetUpdate.ExpressionAttributeValues, ":current_state", "S") != string(sessionControlTargetPreparing) ||
			sessionControlWireString(t, targetUpdate.ExpressionAttributeValues, ":current_version", "N") != "9" ||
			sessionControlWireString(t, targetUpdate.ExpressionAttributeValues, ":current_authority_version", "N") != "1" ||
			sessionControlWireString(t, targetUpdate.ExpressionAttributeValues, ":next_state", "S") != string(sessionControlTargetActive) ||
			sessionControlWireString(t, targetUpdate.ExpressionAttributeValues, ":next_version", "N") != "10" ||
			sessionControlWireString(t, targetUpdate.ExpressionAttributeValues, ":next_authority_version", "N") != "2" ||
			sessionControlWireString(t, targetUpdate.ExpressionAttributeValues, ":caught_up_control_version", "N") != "1" ||
			sessionControlWireString(t, targetUpdate.ExpressionAttributeValues, ":zero_control_version", "N") != "0" ||
			!sessionControlWireBool(t, targetUpdate.ExpressionAttributeValues, ":counted") {
			t.Fatalf("activation target CAS = %#v", targetUpdate)
		}
		if authorityUpdate.TableName != storeTableNameForTest ||
			!strings.Contains(authorityUpdate.ConditionExpression, "attribute_not_exists(control_cell_id)") ||
			!strings.Contains(authorityUpdate.ConditionExpression, "active_target_count = :zero") ||
			!strings.Contains(authorityUpdate.UpdateExpression, "control_cell_id = :control_cell_id") ||
			!strings.Contains(authorityUpdate.ConditionExpression, "active_target_count < :capacity") ||
			!strings.Contains(authorityUpdate.UpdateExpression, "active_target_count = active_target_count + :next_count") ||
			sessionControlWireString(t, authorityUpdate.ExpressionAttributeValues, ":authority_version", "N") != "1" ||
			sessionControlWireString(t, authorityUpdate.ExpressionAttributeValues, ":next_authority_version", "N") != "2" ||
			sessionControlWireString(t, authorityUpdate.ExpressionAttributeValues, ":capacity", "N") != "10" {
			t.Fatalf("activation authority CAS = %#v", authorityUpdate)
		}
		controlCheck := req.TransactItems[2].ConditionCheck
		if !strings.Contains(controlCheck.ConditionExpression, "#control_version = :caught_up_control_version") ||
			sessionControlWireString(t, controlCheck.ExpressionAttributeValues, ":control_cell_id", "S") != preparing.ControlCellID ||
			sessionControlWireString(t, controlCheck.ExpressionAttributeValues, ":caught_up_control_version", "N") != "1" ||
			sessionControlWireString(t, controlCheck.Key, "pk", "S") != sessionControlFenceDirectoryPK(preparing.ControlCellID) {
			t.Fatalf("control directory ConditionCheck = %#v", controlCheck)
		}
		writeSessionControlDynamoJSON(t, w, map[string]any{})
	})

	got, err := store.ActivateTarget(context.Background(), preparing.fence().activation(1))
	if err != nil || *got != active {
		t.Fatalf("ActivateTarget() = %#v, %v; want %#v", got, err, active)
	}
}

func TestDynamoSessionControlCountedReconnectActivationChecksHeaderWithoutIncrement(t *testing.T) {
	candidate := testSessionControlTargetCandidate(0x48, "dededededededededededededededede", 9)
	preparing := testSessionControlTargetAuthority(candidate, sessionControlTargetPreparing, 4)
	preparing.AuthorityVersion = 7
	preparing.CountedActiveSlot = true
	active := preparing
	active.State = sessionControlTargetActive
	active.Version++
	active.ActivatedControlVersion = 1
	preparingOwner, err := sessionControlOwnerFromTarget(preparing, nil, sessionControlOwnerPreparing)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlOwnerWireItem(t, preparingOwner)})
			return
		}
		var req struct {
			TransactItems []struct {
				Update *struct {
					ExpressionAttributeValues map[string]any `json:"ExpressionAttributeValues"`
				} `json:"Update"`
				ConditionCheck *struct {
					ConditionExpression       string         `json:"ConditionExpression"`
					ExpressionAttributeValues map[string]any `json:"ExpressionAttributeValues"`
				} `json:"ConditionCheck"`
				Put *struct{} `json:"Put"`
			} `json:"TransactItems"`
		}
		decodeSessionControlDynamoRequest(t, r, &req)
		if len(req.TransactItems) != 4 || req.TransactItems[0].Update == nil || req.TransactItems[1].ConditionCheck == nil ||
			req.TransactItems[1].Update != nil || req.TransactItems[2].ConditionCheck == nil || req.TransactItems[3].Put == nil {
			t.Fatalf("counted activation transaction = %#v", req.TransactItems)
		}
		if got := sessionControlWireString(t, req.TransactItems[0].Update.ExpressionAttributeValues, ":next_authority_version", "N"); got != "7" {
			t.Fatalf("target authority version = %q, want unchanged 7", got)
		}
		check := req.TransactItems[1].ConditionCheck
		if !strings.Contains(check.ConditionExpression, "#version = :authority_version") ||
			!strings.Contains(check.ConditionExpression, "control_cell_id = :control_cell_id") ||
			sessionControlWireString(t, check.ExpressionAttributeValues, ":authority_version", "N") != "7" {
			t.Fatalf("authority ConditionCheck = %#v", check)
		}
		writeSessionControlDynamoJSON(t, w, map[string]any{})
	})
	got, err := store.ActivateTarget(context.Background(), preparing.fence().activation(1))
	if err != nil || *got != active {
		t.Fatalf("ActivateTarget(counted) = %#v, %v; want %#v", got, err, active)
	}
}

func TestDynamoSessionControlActivationRejectsStaleControlDirectoryBeforeCapacity(t *testing.T) {
	candidate := testSessionControlTargetCandidate(0x76, "12121212121212121212121212121212", 22)
	preparing := testSessionControlTargetAuthority(candidate, sessionControlTargetPreparing, 3)
	directory := sessionControlFenceDirectory{
		CellID: candidate.ControlCellID, Version: 2, CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_001,
	}
	preparingOwner, err := sessionControlOwnerFromTarget(preparing, nil, sessionControlOwnerPreparing)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlOwnerWireItem(t, preparingOwner)})
		case 2:
			if r.Header.Get("X-Amz-Target") != "DynamoDB_20120810.TransactWriteItems" {
				t.Fatalf("second operation = %q, want activation transaction", r.Header.Get("X-Amz-Target"))
			}
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"com.amazonaws.dynamodb.v20120810#TransactionCanceledException","message":"stale control"}`))
		case 3:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlWireItem(t, preparing)})
		case 4:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceDirectoryWireItem(t, directory)})
		default:
			t.Fatal("stale control classification reached capacity/authority read")
		}
	})
	if _, err := store.ActivateTarget(context.Background(), preparing.fence().activation(1)); !errors.Is(err, errSessionControlTargetControlStale) {
		t.Fatalf("ActivateTarget() stale control error = %v, want stale catch-up", err)
	}
}

func TestDynamoSessionControlActivationReplayAcceptsExactCommittedAuthority(t *testing.T) {
	candidate := testSessionControlTargetCandidate(0x77, "34343434343434343434343434343434", 23)
	preparing := testSessionControlTargetAuthority(candidate, sessionControlTargetPreparing, 3)
	active := preparing
	active.State = sessionControlTargetActive
	active.Version++
	active.AuthorityVersion++
	active.CountedActiveSlot = true
	active.ActivatedControlVersion = 1
	preparingOwner, err := sessionControlOwnerFromTarget(preparing, nil, sessionControlOwnerPreparing)
	if err != nil {
		t.Fatal(err)
	}
	activeOwner, err := sessionControlOwnerFromTarget(active, &preparingOwner, sessionControlOwnerActiveUnready)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, _ *http.Request) {
		switch calls.Add(1) {
		case 1:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlOwnerWireItem(t, preparingOwner)})
		case 2:
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"com.amazonaws.dynamodb.v20120810#TransactionCanceledException","message":"ambiguous"}`))
		case 3:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlWireItem(t, active)})
		case 4:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlOwnerWireItem(t, activeOwner)})
		default:
			t.Fatal("idempotent activation replay read past current directory")
		}
	})
	got, err := store.ActivateTarget(context.Background(), preparing.fence().activation(1))
	if err != nil || *got != active {
		t.Fatalf("ActivateTarget() replay = %#v, %v; want %#v", got, err, active)
	}
}

func TestDynamoSessionControlActivationLostResponseThenExactSecondCall(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	candidate := testSessionControlTargetCandidate(0x78, "45454545454545454545454545454545", 24)
	preparing := testSessionControlTargetAuthority(candidate, sessionControlTargetPreparing, 3)
	activation := preparing.fence().activation(1)
	active := sessionControlExpectedActivatedTarget(activation)
	preparingOwner, err := sessionControlOwnerFromTarget(preparing, nil, sessionControlOwnerPreparing)
	if err != nil {
		t.Fatal(err)
	}
	activeOwner, err := sessionControlOwnerFromTarget(active, &preparingOwner, sessionControlOwnerActiveUnready)
	if err != nil {
		t.Fatal(err)
	}
	preparingRow, _ := sessionControlOwnerToRow(preparingOwner)
	fake.setItem(marshalSessionControlSessionTestRow(t, preparingRow))
	fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		targetRow, _ := sessionControlTargetToRow(active)
		ownerRow, _ := sessionControlOwnerToRow(activeOwner)
		fake.setItem(marshalSessionControlSessionTestRow(t, targetRow))
		fake.setItem(marshalSessionControlSessionTestRow(t, ownerRow))
		return nil, errors.New("lost activation response")
	}
	fake.getHook = func(ctx context.Context, input *dynamodb.GetItemInput, call int) (*dynamodb.GetItemOutput, error) {
		if call == 1 {
			return nil, errors.New("classification unavailable")
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fake.mu.Lock()
		item := fake.items[sessionControlSessionDynamoMapKey(input.Key)]
		fake.mu.Unlock()
		return &dynamodb.GetItemOutput{Item: item}, nil
	}
	if _, err := store.ActivateTarget(context.Background(), activation); err == nil || !strings.Contains(err.Error(), "lost activation response") {
		t.Fatalf("first ActivateTarget() error = %v, want original lost response", err)
	}
	got, err := store.ActivateTarget(context.Background(), activation)
	if err != nil || *got != active || len(fake.transactions) != 1 {
		t.Fatalf("second ActivateTarget() = %#v, %v; transactions=%d", got, err, len(fake.transactions))
	}
}

func TestDynamoSessionControlPrepareNoWriteBracketsOwnerOnlyTaskInsertion(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	candidate := testSessionControlTargetCandidate(0x7d, "61616161616161616161616161616161", 29)
	active := testSessionControlTargetAuthority(candidate, sessionControlTargetActive, 3)
	active.ReadyControlVersion = active.ActivatedControlVersion
	active.AAKEnqueuedAtMillis = active.PreparedAtMillis
	active.AAKTransactionID = 700
	owner := seedSessionControlTarget(t, fake, active)
	seedSessionControlSnapshotAuthority(t, fake, sessionControlAuthority{
		ACID: candidate.ACID, ControlCellID: candidate.ControlCellID,
		Version: active.AuthorityVersion, ActiveTargetCount: 1,
		CreatedAtMillis: active.CreatedAtMillis, UpdatedAtMillis: active.UpdatedAtMillis,
	})
	pendingOwner, err := planSessionControlOwnerTaskInsert(owner, owner.UpdatedAtMillis+1)
	if err != nil {
		t.Fatal(err)
	}
	fake.getHook = func(ctx context.Context, input *dynamodb.GetItemInput, call int) (*dynamodb.GetItemOutput, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// authority, TARGET-before, OWNER-before, TARGET-after, OWNER-after.
		// Insert one task after the final TARGET read so only the OWNER bracket
		// can observe the authority change.
		if call == 3 {
			row, rowErr := sessionControlOwnerToRow(pendingOwner)
			if rowErr != nil {
				t.Fatal(rowErr)
			}
			fake.setItem(marshalSessionControlSessionTestRow(t, row))
		}
		fake.mu.Lock()
		item := fake.items[sessionControlSessionDynamoMapKey(input.Key)]
		fake.mu.Unlock()
		return &dynamodb.GetItemOutput{Item: item}, nil
	}
	if _, err = store.PrepareTarget(context.Background(), candidate); !errors.Is(err, errSessionControlTargetPendingWork) {
		t.Fatalf("PrepareTarget() owner-only insertion error = %v, want pending work", err)
	}
	if len(fake.transactions) != 0 {
		t.Fatalf("no-write prepare emitted %d transactions", len(fake.transactions))
	}
	if len(fake.gets) < 10 {
		t.Fatalf("no-write authority did not retry full TARGET/OWNER bracket: gets=%d", len(fake.gets))
	}
}

func TestDynamoSessionControlPreparePendingActivationRetriesOwnerCASAndPreservesWork(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	candidate := testSessionControlTargetCandidate(0x7e, "62626262626262626262626262626262", 30)
	preparing := testSessionControlTargetAuthority(candidate, sessionControlTargetPreparing, 3)
	preparing.CountedActiveSlot = true
	preparing.AuthorityVersion = 2
	owner := seedSessionControlTarget(t, fake, preparing)
	seedSessionControlSnapshotAuthority(t, fake, sessionControlAuthority{
		ACID: candidate.ACID, ControlCellID: candidate.ControlCellID,
		Version: preparing.AuthorityVersion, ActiveTargetCount: 1,
		CreatedAtMillis: preparing.CreatedAtMillis, UpdatedAtMillis: preparing.UpdatedAtMillis,
	})
	seedSessionControlDirectory(t, fake, sessionControlFenceSnapshot{
		CellID: candidate.ControlCellID, DirectoryVersion: 1,
	})
	preparation, err := store.PrepareTarget(context.Background(), candidate)
	if err != nil || preparation == nil || !preparation.RequiresActivation || preparation.Target != preparing {
		t.Fatalf("persisted PREPARING retry = %#v, %v", preparation, err)
	}
	pendingOwner, err := planSessionControlOwnerTaskInsert(owner, owner.UpdatedAtMillis+1)
	if err != nil {
		t.Fatal(err)
	}
	transactionCalls := 0
	fake.transactHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		transactionCalls++
		if transactionCalls == 1 {
			// Materialization wins after Activate read OWNER but before its exact
			// replacement. The transaction loses definitively and must retry.
			row, rowErr := sessionControlOwnerToRow(pendingOwner)
			if rowErr != nil {
				t.Fatal(rowErr)
			}
			fake.setItem(marshalSessionControlSessionTestRow(t, row))
			return nil, &types.TransactionCanceledException{Message: aws.String("owner changed")}
		}
		if len(input.TransactItems) != 4 || input.TransactItems[3].Put == nil {
			t.Fatalf("activation retry transaction = %#v", input.TransactItems)
		}
		wire := sessionControlAttributeWireMap(t, input.TransactItems[3].Put.Item)
		if got := sessionControlWireString(t, wire, "phase", "S"); got != string(sessionControlOwnerActiveUnready) {
			t.Fatalf("activation owner phase = %q", got)
		}
		if got := sessionControlWireString(t, wire, "task_count", "N"); got != "1" {
			t.Fatalf("activation owner task count = %q", got)
		}
		if got := sessionControlWireString(t, wire, "pending_count", "N"); got != "1" {
			t.Fatalf("activation owner pending count = %q", got)
		}
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}
	active, err := store.ActivateTarget(context.Background(), preparation.Target.fence().activation(1))
	if err != nil || active == nil || active.State != sessionControlTargetActive || active.ReadyControlVersion != 0 {
		t.Fatalf("ActivateTarget() raced task = %#v, %v", active, err)
	}
	if transactionCalls != 2 || len(fake.transactions) != 2 {
		t.Fatalf("activation attempts = %d/%d, want 2", transactionCalls, len(fake.transactions))
	}
	if aws.ToString(fake.transactions[0].ClientRequestToken) == aws.ToString(fake.transactions[1].ClientRequestToken) {
		t.Fatal("owner-changing activation retry reused its prior transaction token")
	}
}

func TestDynamoSessionControlActivationTransportTimeoutClassifiesCommittedState(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	candidate := testSessionControlTargetCandidate(0x79, "56565656565656565656565656565656", 25)
	preparing := testSessionControlTargetAuthority(candidate, sessionControlTargetPreparing, 3)
	activation := preparing.fence().activation(1)
	active := sessionControlExpectedActivatedTarget(activation)
	preparingOwner, _ := sessionControlOwnerFromTarget(preparing, nil, sessionControlOwnerPreparing)
	activeOwner, _ := sessionControlOwnerFromTarget(active, &preparingOwner, sessionControlOwnerActiveUnready)
	preparingRow, _ := sessionControlOwnerToRow(preparingOwner)
	fake.setItem(marshalSessionControlSessionTestRow(t, preparingRow))
	fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		targetRow, _ := sessionControlTargetToRow(active)
		ownerRow, _ := sessionControlOwnerToRow(activeOwner)
		fake.setItem(marshalSessionControlSessionTestRow(t, targetRow))
		fake.setItem(marshalSessionControlSessionTestRow(t, ownerRow))
		return nil, context.DeadlineExceeded
	}
	got, err := store.ActivateTarget(context.Background(), activation)
	if err != nil || *got != active {
		t.Fatalf("ActivateTarget() timeout classification = %#v, %v", got, err)
	}
}

func TestSessionControlActivationTokenIsStableAndFenceSpecific(t *testing.T) {
	candidate := testSessionControlTargetCandidate(0x49, "efefefefefefefefefefefefefefefef", 10)
	preparing := testSessionControlTargetAuthority(candidate, sessionControlTargetPreparing, 5)
	base := aws.ToString(sessionControlTransactionToken("activate", preparing.fence().activation(1)))
	if base == "" || len(base) > 36 || base != aws.ToString(sessionControlTransactionToken("activate", preparing.fence().activation(1))) {
		t.Fatalf("activation token is not stable/canonical: %q", base)
	}
	mutations := []sessionControlTargetFence{
		preparing.fence(),
		preparing.fence(),
		preparing.fence(),
		preparing.fence(),
		preparing.fence(),
	}
	mutations[0].Version++
	mutations[1].AuthorityVersion++
	mutations[2].PreparedAtMillis++
	mutations[3].CountedActiveSlot = true
	mutations[4].CreatedAtMillis++
	for i, mutated := range mutations {
		if got := aws.ToString(sessionControlTransactionToken("activate", mutated.activation(1))); got == base {
			t.Fatalf("mutation %d reused activation token %q", i, got)
		}
	}
	cellMutation := preparing.fence().activation(1)
	cellMutation.ControlCellID = "cell-02"
	if got := aws.ToString(sessionControlTransactionToken("activate", cellMutation)); got == base {
		t.Fatalf("cell mutation reused activation token %q", got)
	}
	cursorMutation := preparing.fence().activation(2)
	if got := aws.ToString(sessionControlTransactionToken("activate", cursorMutation)); got == base {
		t.Fatalf("cursor mutation reused activation token %q", got)
	}
}

func TestDynamoSessionControlVersionCeilingFailsBeforeWrite(t *testing.T) {
	store := newDynamoSessionControlTestStore(t, func(http.ResponseWriter, *http.Request) {
		t.Fatal("version-ceiling transition reached DynamoDB")
	})
	candidate := testSessionControlTargetCandidate(0x4a, "fafafafafafafafafafafafafafafafa", 11)
	target := testSessionControlTargetAuthority(candidate, sessionControlTargetPreparing, ^uint64(0)-1)
	for name, transition := range map[string]func() error{
		"activate": func() error {
			_, err := store.ActivateTarget(context.Background(), target.fence().activation(1))
			return err
		},
		"cancel": func() error {
			_, err := store.CancelTargetPreparation(context.Background(), target.fence())
			return err
		},
		"retire": func() error {
			_, err := store.retireTarget(context.Background(), target.fence())
			return err
		},
	} {
		if err := transition(); !errors.Is(err, errSessionControlTargetCorrupt) {
			t.Fatalf("%s ceiling error = %v, want corrupt", name, err)
		}
	}
}

func TestDynamoSessionControlRequiredListFailsClosedOnHeaderCountMismatch(t *testing.T) {
	candidate := testSessionControlTargetCandidate(0x4b, "acacacacacacacacacacacacacacacac", 12)
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-Amz-Target") {
		case "DynamoDB_20120810.GetItem":
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlAuthorityWireItem(t, sessionControlAuthority{
				ACID:              candidate.ACID,
				ControlCellID:     candidate.ControlCellID,
				Version:           1,
				ActiveTargetCount: 1,
				CreatedAtMillis:   1_800_000_000_000,
				UpdatedAtMillis:   1_800_000_000_000,
			})})
		case "DynamoDB_20120810.Query":
			writeSessionControlDynamoJSON(t, w, map[string]any{"Items": []any{}, "Count": 0, "ScannedCount": 0})
		default:
			t.Fatalf("unexpected operation %q", r.Header.Get("X-Amz-Target"))
		}
	})
	if _, err := store.ListRequiredTargets(context.Background(), candidate.ACID, candidate.ControlCellID); !errors.Is(err, errSessionControlTargetCorrupt) {
		t.Fatalf("ListRequiredTargets() mismatch error = %v, want corrupt", err)
	}
}

func TestDynamoSessionControlRequiredListAllowsUnboundEmptyAuthority(t *testing.T) {
	const acID = "ac-unbound-dynamo"
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-Amz-Target") {
		case "DynamoDB_20120810.GetItem":
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlAuthorityWireItem(t, sessionControlAuthority{
				ACID: acID, Version: 1, CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_000,
			})})
		case "DynamoDB_20120810.Query":
			writeSessionControlDynamoJSON(t, w, map[string]any{"Items": []any{}, "Count": 0, "ScannedCount": 0})
		default:
			t.Fatalf("unexpected operation %q", r.Header.Get("X-Amz-Target"))
		}
	})
	targets, err := store.ListRequiredTargets(context.Background(), acID, testSessionControlCellID)
	if err != nil || len(targets) != 0 {
		t.Fatalf("unbound empty required list = %#v, %v; want empty", targets, err)
	}
}

func TestDynamoSessionControlRequiredListRetriesActivationInterleaving(t *testing.T) {
	candidate := testSessionControlTargetCandidate(0x78, "56565656565656565656565656565656", 24)
	active := testSessionControlTargetAuthority(candidate, sessionControlTargetActive, 2)
	beforeActivation := sessionControlAuthority{
		ACID: candidate.ACID, Version: 1, CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_000,
	}
	afterActivation := sessionControlAuthority{
		ACID:              candidate.ACID,
		ControlCellID:     candidate.ControlCellID,
		Version:           2,
		ActiveTargetCount: 1,
		CreatedAtMillis:   1_800_000_000_000,
		UpdatedAtMillis:   1_800_000_000_000,
	}
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		wantOperation := "DynamoDB_20120810.GetItem"
		if call == 2 || call == 5 {
			wantOperation = "DynamoDB_20120810.Query"
		}
		if got := r.Header.Get("X-Amz-Target"); got != wantOperation {
			t.Fatalf("call %d operation = %q, want %q", call, got, wantOperation)
		}
		switch call {
		case 1:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlAuthorityWireItem(t, beforeActivation)})
		case 2, 5:
			writeSessionControlDynamoJSON(t, w, map[string]any{
				"Items": []any{sessionControlWireItem(t, active)}, "Count": 1, "ScannedCount": 1,
			})
		case 3, 4, 6:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlAuthorityWireItem(t, afterActivation)})
		default:
			t.Fatal("unexpected extra DynamoDB required-list call")
		}
	})

	targets, err := store.ListRequiredTargets(context.Background(), candidate.ACID, candidate.ControlCellID)
	if err != nil || len(targets) != 1 || targets[0] != active {
		t.Fatalf("activation-interleaved required list = %#v, %v; want active target", targets, err)
	}
	if calls.Load() != 6 {
		t.Fatalf("DynamoDB calls = %d, want two authority-query-authority brackets", calls.Load())
	}
}

func TestDynamoSessionControlRequiredListRetriesRetirementInterleaving(t *testing.T) {
	candidate := testSessionControlTargetCandidate(0x79, "78787878787878787878787878787878", 25)
	beforeRetirement := sessionControlAuthority{
		ACID:              candidate.ACID,
		ControlCellID:     candidate.ControlCellID,
		Version:           2,
		ActiveTargetCount: 1,
		CreatedAtMillis:   1_800_000_000_000,
		UpdatedAtMillis:   1_800_000_000_000,
	}
	afterRetirement := beforeRetirement
	afterRetirement.Version++
	afterRetirement.ActiveTargetCount = 0
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		wantOperation := "DynamoDB_20120810.GetItem"
		if call == 2 || call == 5 {
			wantOperation = "DynamoDB_20120810.Query"
		}
		if got := r.Header.Get("X-Amz-Target"); got != wantOperation {
			t.Fatalf("call %d operation = %q, want %q", call, got, wantOperation)
		}
		switch call {
		case 1:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlAuthorityWireItem(t, beforeRetirement)})
		case 2, 5:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Items": []any{}, "Count": 0, "ScannedCount": 0})
		case 3, 4, 6:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlAuthorityWireItem(t, afterRetirement)})
		default:
			t.Fatal("unexpected extra DynamoDB required-list call")
		}
	})

	targets, err := store.ListRequiredTargets(context.Background(), candidate.ACID, candidate.ControlCellID)
	if err != nil || len(targets) != 0 {
		t.Fatalf("retirement-interleaved required list = %#v, %v; want empty", targets, err)
	}
	if calls.Load() != 6 {
		t.Fatalf("DynamoDB calls = %d, want two authority-query-authority brackets", calls.Load())
	}
}

func TestDynamoSessionControlRetirementAtomicallyReleasesCountedSlot(t *testing.T) {
	candidate := testSessionControlTargetCandidate(0x4c, "bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", 13)
	active := testSessionControlTargetAuthority(candidate, sessionControlTargetActive, 2)
	retired := active
	retired.State = sessionControlTargetRetired
	retired.Version++
	retired.AuthorityVersion++
	retired.CountedActiveSlot = false
	retired.RetiredAtMillis = 1_800_000_000_000
	activeOwner, err := sessionControlOwnerFromTarget(active, nil, sessionControlOwnerActiveUnready)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			if got := r.Header.Get("X-Amz-Target"); got != "DynamoDB_20120810.GetItem" {
				t.Fatalf("retirement first operation = %q, want target GetItem", got)
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlWireItem(t, active)})
		case 2:
			if got := r.Header.Get("X-Amz-Target"); got != "DynamoDB_20120810.GetItem" {
				t.Fatalf("retirement second operation = %q, want owner GetItem", got)
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlOwnerWireItem(t, activeOwner)})
		case 3:
			if got := r.Header.Get("X-Amz-Target"); got != "DynamoDB_20120810.GetItem" {
				t.Fatalf("retirement third operation = %q, want authority GetItem", got)
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlAuthorityWireItem(t, sessionControlAuthority{
				ACID:              candidate.ACID,
				ControlCellID:     candidate.ControlCellID,
				Version:           2,
				ActiveTargetCount: 1,
				CreatedAtMillis:   1_800_000_000_000,
				UpdatedAtMillis:   1_800_000_000_000,
			})})
		case 4:
			if got := r.Header.Get("X-Amz-Target"); got != "DynamoDB_20120810.TransactWriteItems" {
				t.Fatalf("retirement fourth operation = %q, want transaction", got)
			}
			var req struct {
				TransactItems []struct {
					Update *struct {
						UpdateExpression          string         `json:"UpdateExpression"`
						ConditionExpression       string         `json:"ConditionExpression"`
						ExpressionAttributeValues map[string]any `json:"ExpressionAttributeValues"`
					} `json:"Update"`
					Put *struct{} `json:"Put"`
				} `json:"TransactItems"`
			}
			decodeSessionControlDynamoRequest(t, r, &req)
			if len(req.TransactItems) != 3 || req.TransactItems[0].Update == nil || req.TransactItems[1].Update == nil || req.TransactItems[2].Put == nil {
				t.Fatalf("retirement transaction = %#v", req.TransactItems)
			}
			targetUpdate := req.TransactItems[0].Update
			authorityUpdate := req.TransactItems[1].Update
			if sessionControlWireString(t, targetUpdate.ExpressionAttributeValues, ":retired", "S") != string(sessionControlTargetRetired) ||
				sessionControlWireBool(t, targetUpdate.ExpressionAttributeValues, ":not_counted") ||
				sessionControlWireString(t, targetUpdate.ExpressionAttributeValues, ":next_authority_version", "N") != "3" {
				t.Fatalf("retirement target update = %#v", targetUpdate)
			}
			if !strings.Contains(authorityUpdate.UpdateExpression, "active_target_count = active_target_count - :one") ||
				!strings.Contains(authorityUpdate.ConditionExpression, "active_target_count >= :one") ||
				sessionControlWireString(t, authorityUpdate.ExpressionAttributeValues, ":next_authority_version", "N") != "3" {
				t.Fatalf("retirement authority update = %#v", authorityUpdate)
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		default:
			t.Fatal("unexpected extra DynamoDB retirement call")
		}
	})
	got, err := store.retireTarget(context.Background(), active.fence())
	if err != nil || *got != retired {
		t.Fatalf("retireTarget() = %#v, %v; want %#v", got, err, retired)
	}
}

func TestDynamoSessionControlRetirementReplayRequiresExactEmptyOwner(t *testing.T) {
	candidate := testSessionControlTargetCandidate(0x7a, "67676767676767676767676767676767", 26)
	active := testSessionControlTargetAuthority(candidate, sessionControlTargetActive, 2)
	activeOwner, err := sessionControlOwnerFromTarget(active, nil, sessionControlOwnerActiveUnready)
	if err != nil {
		t.Fatal(err)
	}
	retired := active
	retired.State = sessionControlTargetRetired
	retired.Version++
	retired.AuthorityVersion++
	retired.CountedActiveSlot = false
	retired.RetiredAtMillis = retired.UpdatedAtMillis
	retiredOwner, err := sessionControlOwnerFromTarget(retired, &activeOwner, sessionControlOwnerRetired)
	if err != nil {
		t.Fatal(err)
	}
	seed := func(t *testing.T, ownerItem map[string]types.AttributeValue) (*sessionControlSessionDynamoFake, *dynamoSessionControlStore) {
		t.Helper()
		fake := newSessionControlSessionDynamoFake()
		targetRow, _ := sessionControlTargetToRow(retired)
		fake.setItem(marshalSessionControlSessionTestRow(t, targetRow))
		if ownerItem != nil {
			fake.setItem(ownerItem)
		}
		return fake, newSessionControlSessionDynamoStore(fake, time.Second)
	}
	ownerRow, _ := sessionControlOwnerToRow(retiredOwner)
	ownerItem := marshalSessionControlSessionTestRow(t, ownerRow)

	t.Run("exact replay", func(t *testing.T) {
		fake, store := seed(t, ownerItem)
		got, err := store.retireTarget(context.Background(), active.fence())
		if err != nil || *got != retired || len(fake.transactions) != 0 {
			t.Fatalf("retire replay = %#v, %v; transactions=%d", got, err, len(fake.transactions))
		}
	})
	t.Run("missing owner", func(t *testing.T) {
		_, store := seed(t, nil)
		if _, err := store.retireTarget(context.Background(), active.fence()); !errors.Is(err, errSessionControlOwnerNotFound) {
			t.Fatalf("missing retired owner error = %v", err)
		}
	})
	t.Run("mutated owner target", func(t *testing.T) {
		mutated := make(map[string]types.AttributeValue, len(ownerItem))
		for key, value := range ownerItem {
			mutated[key] = value
		}
		mutated["target_version"] = &types.AttributeValueMemberN{Value: "99"}
		_, store := seed(t, mutated)
		if _, err := store.retireTarget(context.Background(), active.fence()); !errors.Is(err, errSessionControlOwnerCorrupt) {
			t.Fatalf("mutated retired owner error = %v", err)
		}
	})
	t.Run("residual owner task", func(t *testing.T) {
		mutated := make(map[string]types.AttributeValue, len(ownerItem))
		for key, value := range ownerItem {
			mutated[key] = value
		}
		mutated["task_count"] = &types.AttributeValueMemberN{Value: "1"}
		_, store := seed(t, mutated)
		if _, err := store.retireTarget(context.Background(), active.fence()); !errors.Is(err, errSessionControlOwnerCorrupt) {
			t.Fatalf("residual retired task error = %v", err)
		}
	})
	t.Run("paired wrong authority version", func(t *testing.T) {
		wrongTarget := retired
		wrongTarget.AuthorityVersion++
		wrongOwner := retiredOwner
		wrongOwner.TargetAuthorityVersion = wrongTarget.AuthorityVersion
		fake := newSessionControlSessionDynamoFake()
		targetRow, _ := sessionControlTargetToRow(wrongTarget)
		ownerRow, _ := sessionControlOwnerToRow(wrongOwner)
		fake.setItem(marshalSessionControlSessionTestRow(t, targetRow))
		fake.setItem(marshalSessionControlSessionTestRow(t, ownerRow))
		store := newSessionControlSessionDynamoStore(fake, time.Second)
		if _, err := store.retireTarget(context.Background(), active.fence()); err == nil {
			t.Fatal("paired wrong retired authority version was accepted")
		}
	})
}

func TestDynamoSessionControlRetirementTransportTimeoutClassifiesCommittedPair(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	store := newSessionControlSessionDynamoStore(fake, time.Second)
	candidate := testSessionControlTargetCandidate(0x7b, "78787878787878787878787878787878", 27)
	active := testSessionControlTargetAuthority(candidate, sessionControlTargetActive, 2)
	activeOwner := seedSessionControlTarget(t, fake, active)
	authority := sessionControlAuthority{
		ACID: candidate.ACID, ControlCellID: candidate.ControlCellID, Version: active.AuthorityVersion,
		ActiveTargetCount: 1, CreatedAtMillis: active.CreatedAtMillis, UpdatedAtMillis: active.UpdatedAtMillis,
	}
	authorityRow, _ := sessionControlAuthorityToRow(authority)
	fake.setItem(marshalSessionControlSessionTestRow(t, authorityRow))
	retired := active
	retired.State = sessionControlTargetRetired
	retired.Version++
	retired.AuthorityVersion++
	retired.CountedActiveSlot = false
	retired.RetiredAtMillis = retired.UpdatedAtMillis
	retiredOwner, err := sessionControlOwnerFromTarget(retired, &activeOwner, sessionControlOwnerRetired)
	if err != nil {
		t.Fatal(err)
	}
	fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		targetRow, _ := sessionControlTargetToRow(retired)
		ownerRow, _ := sessionControlOwnerToRow(retiredOwner)
		fake.setItem(marshalSessionControlSessionTestRow(t, targetRow))
		fake.setItem(marshalSessionControlSessionTestRow(t, ownerRow))
		return nil, context.DeadlineExceeded
	}
	got, err := store.retireTarget(context.Background(), active.fence())
	if err != nil || *got != retired {
		t.Fatalf("retire timeout classification = %#v, %v", got, err)
	}
}

func TestDynamoSessionControlRequiredReadFailsClosedOnMalformedState(t *testing.T) {
	candidate := testSessionControlTargetCandidate(0x45, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", 7)
	malformed := testSessionControlTargetAuthority(candidate, sessionControlTargetState("mystery"), 1)
	// Construct the wire row directly because the production marshal boundary
	// correctly refuses the malformed state.
	wire := map[string]any{
		"pk":                        map[string]any{"S": sessionControlTargetPK(candidate.ACID)},
		"sk":                        map[string]any{"S": sessionControlTargetSK(candidate.PublicKey)},
		"kind":                      map[string]any{"S": sessionControlTargetKind},
		"schema_version":            map[string]any{"N": "1"},
		"ac_id":                     map[string]any{"S": candidate.ACID},
		"public_key":                map[string]any{"S": candidate.PublicKey},
		"boot_id":                   map[string]any{"S": candidate.BootID},
		"flush_generation":          map[string]any{"N": "7"},
		"state":                     map[string]any{"S": string(malformed.State)},
		"version":                   map[string]any{"N": "1"},
		"authority_version":         map[string]any{"N": "1"},
		"counted_active_slot":       map[string]any{"BOOL": false},
		"control_cell_id":           map[string]any{"S": candidate.ControlCellID},
		"activated_control_version": map[string]any{"N": "0"},
		"created_at_ms":             map[string]any{"N": "1800000000000"},
		"prepared_at_ms":            map[string]any{"N": "1800000000000"},
		"updated_at_ms":             map[string]any{"N": "1800000000000"},
	}
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-Amz-Target") {
		case "DynamoDB_20120810.GetItem":
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlAuthorityWireItem(t, sessionControlAuthority{
				ACID:              candidate.ACID,
				ControlCellID:     candidate.ControlCellID,
				Version:           1,
				ActiveTargetCount: 1,
				CreatedAtMillis:   1_800_000_000_000,
				UpdatedAtMillis:   1_800_000_000_000,
			})})
		case "DynamoDB_20120810.Query":
			writeSessionControlDynamoJSON(t, w, map[string]any{"Items": []any{wire}, "Count": 1, "ScannedCount": 1})
		default:
			t.Fatalf("unexpected operation %q", r.Header.Get("X-Amz-Target"))
		}
	})
	if _, err := store.ListRequiredTargets(context.Background(), candidate.ACID, candidate.ControlCellID); !errors.Is(err, errSessionControlTargetCorrupt) {
		t.Fatalf("malformed required-target read error = %v, want corrupt", err)
	}
}
