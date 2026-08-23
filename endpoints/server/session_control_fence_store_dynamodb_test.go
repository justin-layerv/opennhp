package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func testPreparedSessionControlFence(t *testing.T, eventID string, seed byte, preparedDirectoryVersion uint64, preparedAt time.Time) sessionControlFenceAuthority {
	t.Helper()
	selector := testSessionControlExactFenceSelector(seed)
	digest, err := sessionControlFenceSelectorDigest(selector)
	if err != nil {
		t.Fatal(err)
	}
	return sessionControlFenceAuthority{
		CellID: "cell-01", EventID: eventID, Selector: selector, SelectorDigest: digest,
		PreparedDirectoryVersion: preparedDirectoryVersion,
		State:                    sessionControlFencePreparing, Version: 1,
		CreatedAtMillis: preparedAt.UnixMilli(), PreparedAtMillis: preparedAt.UnixMilli(), UpdatedAtMillis: preparedAt.UnixMilli(),
	}
}

func sessionControlFenceWireItem(t *testing.T, fence sessionControlFenceAuthority, active bool) map[string]any {
	t.Helper()
	row, err := sessionControlFenceToRow(fence, active)
	if err != nil {
		t.Fatal(err)
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		t.Fatal(err)
	}
	return sessionControlAttributeWireMap(t, item)
}

func sessionControlFenceDirectoryWireItem(t *testing.T, directory sessionControlFenceDirectory) map[string]any {
	t.Helper()
	row, err := sessionControlFenceDirectoryToRow(directory)
	if err != nil {
		t.Fatal(err)
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		t.Fatal(err)
	}
	return sessionControlAttributeWireMap(t, item)
}

func sessionControlAttributeWireMap(t *testing.T, item map[string]types.AttributeValue) map[string]any {
	t.Helper()
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

func TestDynamoSessionControlPrepareFencePublishesDirectoryMetaAndActiveAtomically(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	candidate := testSessionControlFenceCandidate("44444444444444444444444444444444", testSessionControlExactFenceSelector(0x66))
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			var req struct {
				ConsistentRead bool `json:"ConsistentRead"`
			}
			decodeSessionControlDynamoRequest(t, r, &req)
			if r.Header.Get("X-Amz-Target") != "DynamoDB_20120810.GetItem" || !req.ConsistentRead {
				t.Fatalf("directory read = %#v target=%q", req, r.Header.Get("X-Amz-Target"))
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		case 2:
			if r.Header.Get("X-Amz-Target") != "DynamoDB_20120810.PutItem" {
				t.Fatalf("directory create target = %q", r.Header.Get("X-Amz-Target"))
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		case 3:
			var req struct {
				ConsistentRead bool `json:"ConsistentRead"`
			}
			decodeSessionControlDynamoRequest(t, r, &req)
			if r.Header.Get("X-Amz-Target") != "DynamoDB_20120810.GetItem" || !req.ConsistentRead {
				t.Fatalf("meta read = %#v target=%q", req, r.Header.Get("X-Amz-Target"))
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		case 4:
			if r.Header.Get("X-Amz-Target") != "DynamoDB_20120810.TransactWriteItems" {
				t.Fatalf("prepare target = %q", r.Header.Get("X-Amz-Target"))
			}
			var req struct {
				ClientRequestToken string `json:"ClientRequestToken"`
				TransactItems      []struct {
					Update *struct {
						ConditionExpression       string         `json:"ConditionExpression"`
						ExpressionAttributeValues map[string]any `json:"ExpressionAttributeValues"`
					} `json:"Update"`
					Put *struct {
						ConditionExpression string         `json:"ConditionExpression"`
						Item                map[string]any `json:"Item"`
					} `json:"Put"`
				} `json:"TransactItems"`
			}
			decodeSessionControlDynamoRequest(t, r, &req)
			if req.ClientRequestToken == "" || len(req.ClientRequestToken) > 36 || len(req.TransactItems) != 3 ||
				req.TransactItems[0].Update == nil || req.TransactItems[1].Put == nil || req.TransactItems[2].Put == nil {
				t.Fatalf("prepare transaction = %#v", req)
			}
			if !strings.Contains(req.TransactItems[0].Update.ConditionExpression, "active_fence_count < :capacity") ||
				sessionControlWireString(t, req.TransactItems[0].Update.ExpressionAttributeValues, ":next_count", "N") != "1" {
				t.Fatalf("prepare directory update = %#v", req.TransactItems[0].Update)
			}
			for index, kind := range []string{sessionControlFenceMetaKind, sessionControlFenceActiveKind} {
				put := req.TransactItems[index+1].Put
				if put.ConditionExpression != "attribute_not_exists(pk) AND attribute_not_exists(sk)" ||
					sessionControlWireString(t, put.Item, "kind", "S") != kind ||
					sessionControlWireString(t, put.Item, "prepared_directory_version", "N") != "2" ||
					sessionControlWireString(t, put.Item, "state", "S") != string(sessionControlFencePreparing) {
					t.Fatalf("prepare put %d = %#v", index, put)
				}
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		default:
			t.Fatal("unexpected prepare DynamoDB call")
		}
	})
	store.nowUTC = func() time.Time { return now }
	prepared, err := store.PrepareFence(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.PreparedDirectoryVersion != 2 || prepared.State != sessionControlFencePreparing || prepared.Version != 1 {
		t.Fatalf("prepared fence = %#v", prepared)
	}
}

func TestDynamoSessionControlMarkConvergedRetainsActiveWithExactImmutableCAS(t *testing.T) {
	preparedAt := time.Unix(1_800_000_000, 0).UTC()
	now := preparedAt.Add(10 * time.Second)
	prepared := testPreparedSessionControlFence(t, "55555555555555555555555555555555", 0x67, 2, preparedAt)
	directory := sessionControlFenceDirectory{CellID: prepared.CellID, Version: 2, ActiveFenceCount: 1, CreatedAtMillis: preparedAt.UnixMilli(), UpdatedAtMillis: preparedAt.UnixMilli()}
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1, 4:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceDirectoryWireItem(t, directory)})
		case 2:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, prepared, false)})
		case 3:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, prepared, true)})
		case 5:
			var req struct {
				TransactItems []struct {
					Update *struct{} `json:"Update"`
					Put    *struct {
						ConditionExpression       string         `json:"ConditionExpression"`
						ExpressionAttributeValues map[string]any `json:"ExpressionAttributeValues"`
						Item                      map[string]any `json:"Item"`
					} `json:"Put"`
				} `json:"TransactItems"`
			}
			decodeSessionControlDynamoRequest(t, r, &req)
			if len(req.TransactItems) != 3 || req.TransactItems[1].Put == nil || req.TransactItems[2].Put == nil {
				t.Fatalf("mark transaction = %#v", req.TransactItems)
			}
			for _, item := range req.TransactItems[1:] {
				put := item.Put
				for _, immutable := range []string{"prepared_directory_version = :prepared_directory_version", "created_at_ms = :created_at", "prepared_at_ms = :prepared_at"} {
					if !strings.Contains(put.ConditionExpression, immutable) {
						t.Fatalf("mark condition %q lacks %q", put.ConditionExpression, immutable)
					}
				}
				if sessionControlWireString(t, put.Item, "state", "S") != string(sessionControlFenceConverged) ||
					sessionControlWireString(t, put.Item, "replay_not_before_ms", "N") != "1800000135000" {
					t.Fatalf("converged item = %#v", put.Item)
				}
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		default:
			t.Fatal("unexpected mark DynamoDB call")
		}
	})
	store.nowUTC = func() time.Time { return now }
	converged, err := store.MarkFenceConverged(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	if converged.State != sessionControlFenceConverged || converged.ReplayNotBeforeMillis != now.Add(sessionControlFenceReplayHorizon).UnixMilli() {
		t.Fatalf("converged fence = %#v", converged)
	}
}

func TestDynamoSessionControlFenceSnapshotUsesStrongDoubleDirectoryFence(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	preparing := testPreparedSessionControlFence(t, "66666666666666666666666666666666", 0x68, 2, now)
	converged := testPreparedSessionControlFence(t, "77777777777777777777777777777777", 0x69, 3, now)
	converged.State = sessionControlFenceConverged
	converged.Version = 2
	converged.ConvergedAtMillis = now.UnixMilli()
	converged.ReplayNotBeforeMillis = now.Add(sessionControlFenceReplayHorizon).UnixMilli()
	directory := sessionControlFenceDirectory{CellID: preparing.CellID, Version: 4, ActiveFenceCount: 2, CreatedAtMillis: now.UnixMilli(), UpdatedAtMillis: now.UnixMilli()}
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1, 2, 4:
			var req struct {
				ConsistentRead bool `json:"ConsistentRead"`
			}
			decodeSessionControlDynamoRequest(t, r, &req)
			if !req.ConsistentRead {
				t.Fatal("directory snapshot read was not strong")
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceDirectoryWireItem(t, directory)})
		case 3:
			var req struct {
				ConsistentRead         bool   `json:"ConsistentRead"`
				KeyConditionExpression string `json:"KeyConditionExpression"`
			}
			decodeSessionControlDynamoRequest(t, r, &req)
			if !req.ConsistentRead || req.KeyConditionExpression != "pk = :pk AND begins_with(sk, :fence_prefix)" {
				t.Fatalf("active query = %#v", req)
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{
				"Items": []any{sessionControlFenceWireItem(t, preparing, true), sessionControlFenceWireItem(t, converged, true)},
				"Count": 2, "ScannedCount": 2,
			})
		default:
			t.Fatal("unexpected snapshot DynamoDB call")
		}
	})
	snapshot, err := store.SnapshotActiveFences(context.Background(), preparing.CellID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DirectoryVersion != 4 || snapshot.ActiveFenceCount != 2 || len(snapshot.Fences) != 2 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestDynamoSessionControlFenceEmptySnapshotCreatesVersionOneBeforeBracket(t *testing.T) {
	now := time.Unix(1_800_000_500, 0).UTC()
	directory := sessionControlFenceDirectory{
		CellID: "cell-02", Version: 1, CreatedAtMillis: now.UnixMilli(), UpdatedAtMillis: now.UnixMilli(),
	}
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		case 2:
			var req struct {
				ConditionExpression string         `json:"ConditionExpression"`
				Item                map[string]any `json:"Item"`
			}
			decodeSessionControlDynamoRequest(t, r, &req)
			if r.Header.Get("X-Amz-Target") != "DynamoDB_20120810.PutItem" ||
				req.ConditionExpression != "attribute_not_exists(pk) AND attribute_not_exists(sk)" ||
				sessionControlWireString(t, req.Item, "version", "N") != "1" ||
				sessionControlWireString(t, req.Item, "active_fence_count", "N") != "0" {
				t.Fatalf("empty directory initialization = %#v target=%q", req, r.Header.Get("X-Amz-Target"))
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		case 3, 5:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceDirectoryWireItem(t, directory)})
		case 4:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Items": []any{}, "Count": 0, "ScannedCount": 0})
		default:
			t.Fatal("unexpected empty snapshot DynamoDB call")
		}
	})
	store.nowUTC = func() time.Time { return now }
	snapshot, err := store.SnapshotActiveFences(context.Background(), directory.CellID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DirectoryVersion != 1 || snapshot.ActiveFenceCount != 0 || len(snapshot.Fences) != 0 {
		t.Fatalf("empty snapshot = %#v", snapshot)
	}
}

func TestDynamoSessionControlPrepareFenceClassifiesAmbiguousCommittedTransaction(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	candidate := testSessionControlFenceCandidate("88888888888888888888888888888888", testSessionControlExactFenceSelector(0x6a))
	digest, _ := sessionControlFenceSelectorDigest(candidate.Selector)
	prepared := sessionControlFenceAuthority{
		CellID: candidate.CellID, EventID: candidate.EventID, Selector: candidate.Selector, SelectorDigest: digest,
		PreparedDirectoryVersion: 2, State: sessionControlFencePreparing, Version: 1,
		CreatedAtMillis: now.UnixMilli(), PreparedAtMillis: now.UnixMilli(), UpdatedAtMillis: now.UnixMilli(),
	}
	before := sessionControlFenceDirectory{CellID: candidate.CellID, Version: 1, CreatedAtMillis: now.UnixMilli(), UpdatedAtMillis: now.UnixMilli()}
	after := before
	after.Version = 2
	after.ActiveFenceCount = 1
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceDirectoryWireItem(t, before)})
		case 2:
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		case 3:
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"com.amazonaws.dynamodb.v20120810#TransactionCanceledException","message":"ambiguous"}`))
		case 4, 7:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceDirectoryWireItem(t, after)})
		case 5:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, prepared, false)})
		case 6:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, prepared, true)})
		default:
			t.Fatal("unexpected ambiguous retry DynamoDB call")
		}
	})
	store.nowUTC = func() time.Time { return now }
	got, err := store.PrepareFence(context.Background(), candidate)
	if err != nil || *got != prepared {
		t.Fatalf("PrepareFence() = %#v, %v; want committed %#v", got, err, prepared)
	}
}

func TestDynamoSessionControlRetireFenceDeletesOnlyExactActiveMembership(t *testing.T) {
	preparedAt := time.Unix(1_800_000_000, 0).UTC()
	now := preparedAt.Add(200 * time.Second)
	converged := testPreparedSessionControlFence(t, "99999999999999999999999999999999", 0x6b, 2, preparedAt)
	converged.State = sessionControlFenceConverged
	converged.Version = 2
	converged.ConvergedAtMillis = preparedAt.UnixMilli()
	converged.ReplayNotBeforeMillis = preparedAt.Add(sessionControlFenceReplayHorizon).UnixMilli()
	directory := sessionControlFenceDirectory{CellID: converged.CellID, Version: 3, ActiveFenceCount: 1, CreatedAtMillis: preparedAt.UnixMilli(), UpdatedAtMillis: preparedAt.UnixMilli()}
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1, 4:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceDirectoryWireItem(t, directory)})
		case 2:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, converged, false)})
		case 3:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, converged, true)})
		case 5:
			var req struct {
				TransactItems []struct {
					Update *struct{} `json:"Update"`
					Put    *struct {
						Item map[string]any `json:"Item"`
					} `json:"Put"`
					Delete *struct {
						ConditionExpression string         `json:"ConditionExpression"`
						Key                 map[string]any `json:"Key"`
					} `json:"Delete"`
				} `json:"TransactItems"`
			}
			decodeSessionControlDynamoRequest(t, r, &req)
			if len(req.TransactItems) != 3 || req.TransactItems[1].Put == nil || req.TransactItems[2].Delete == nil {
				t.Fatalf("retire transaction = %#v", req.TransactItems)
			}
			if sessionControlWireString(t, req.TransactItems[1].Put.Item, "state", "S") != string(sessionControlFenceRetired) ||
				sessionControlWireString(t, req.TransactItems[1].Put.Item, "expires_at", "N") != "1800086600" {
				t.Fatalf("retired meta = %#v", req.TransactItems[1].Put.Item)
			}
			if !strings.Contains(req.TransactItems[2].Delete.ConditionExpression, "prepared_directory_version = :prepared_directory_version") ||
				sessionControlWireString(t, req.TransactItems[2].Delete.Key, "pk", "S") != sessionControlFenceActivePK(converged.CellID) {
				t.Fatalf("active delete = %#v", req.TransactItems[2].Delete)
			}
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		default:
			t.Fatal("unexpected retire DynamoDB call")
		}
	})
	store.nowUTC = func() time.Time { return now }
	retired, err := store.retireFence(context.Background(), converged)
	if err != nil {
		t.Fatal(err)
	}
	if retired.State != sessionControlFenceRetired || retired.ExpiresAt != now.Unix()+int64(sessionControlFenceIdempotencyTTL/time.Second) {
		t.Fatalf("retired fence = %#v", retired)
	}
}

func TestDynamoSessionControlRetiredFenceReplayRejectsLingeringActiveRow(t *testing.T) {
	preparedAt := time.Unix(1_800_000_000, 0).UTC()
	now := preparedAt.Add(200 * time.Second)
	converged := testPreparedSessionControlFence(t, "abababababababababababababababab", 0x6e, 2, preparedAt)
	converged.State = sessionControlFenceConverged
	converged.Version = 2
	converged.ConvergedAtMillis = preparedAt.UnixMilli()
	converged.ReplayNotBeforeMillis = preparedAt.Add(sessionControlFenceReplayHorizon).UnixMilli()
	retired := converged
	retired.State = sessionControlFenceRetired
	retired.Version++
	retired.UpdatedAtMillis = now.UnixMilli()
	retired.RetiredAtMillis = now.UnixMilli()
	retired.ExpiresAt = now.Unix() + int64(sessionControlFenceIdempotencyTTL/time.Second)
	directory := sessionControlFenceDirectory{CellID: converged.CellID, Version: 4, ActiveFenceCount: 0, CreatedAtMillis: preparedAt.UnixMilli(), UpdatedAtMillis: now.UnixMilli()}
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, _ *http.Request) {
		switch calls.Add(1) {
		case 1, 4:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceDirectoryWireItem(t, directory)})
		case 2:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, retired, false)})
		case 3:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, converged, true)})
		default:
			t.Fatal("unexpected retired replay DynamoDB call")
		}
	})
	store.nowUTC = func() time.Time { return now }
	if _, err := store.retireFence(context.Background(), converged); !errors.Is(err, errSessionControlFenceCorrupt) {
		t.Fatalf("retireFence() lingering ACTIVE error = %v, want corrupt", err)
	}
}

func TestDynamoSessionControlRetireFenceClassifiesAmbiguousSuccessOnlyAfterActiveAbsence(t *testing.T) {
	preparedAt := time.Unix(1_800_000_000, 0).UTC()
	now := preparedAt.Add(200 * time.Second)
	converged := testPreparedSessionControlFence(t, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", 0x6f, 2, preparedAt)
	converged.State = sessionControlFenceConverged
	converged.Version = 2
	converged.ConvergedAtMillis = preparedAt.UnixMilli()
	converged.ReplayNotBeforeMillis = preparedAt.Add(sessionControlFenceReplayHorizon).UnixMilli()
	retired := converged
	retired.State = sessionControlFenceRetired
	retired.Version++
	retired.UpdatedAtMillis = now.UnixMilli()
	retired.RetiredAtMillis = now.UnixMilli()
	retired.ExpiresAt = now.Unix() + int64(sessionControlFenceIdempotencyTTL/time.Second)
	directory := sessionControlFenceDirectory{CellID: converged.CellID, Version: 3, ActiveFenceCount: 1, CreatedAtMillis: preparedAt.UnixMilli(), UpdatedAtMillis: preparedAt.UnixMilli()}
	retiredDirectory := directory
	retiredDirectory.Version++
	retiredDirectory.ActiveFenceCount = 0
	retiredDirectory.UpdatedAtMillis = now.UnixMilli()
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, _ *http.Request) {
		switch calls.Add(1) {
		case 1, 4:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceDirectoryWireItem(t, directory)})
		case 2:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, converged, false)})
		case 3:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, converged, true)})
		case 5:
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"com.amazonaws.dynamodb.v20120810#TransactionCanceledException","message":"ambiguous"}`))
		case 6, 9:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceDirectoryWireItem(t, retiredDirectory)})
		case 7:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, retired, false)})
		case 8:
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		default:
			t.Fatal("unexpected ambiguous retire DynamoDB call")
		}
	})
	store.nowUTC = func() time.Time { return now }
	got, err := store.retireFence(context.Background(), converged)
	if err != nil || *got != retired {
		t.Fatalf("retireFence() = %#v, %v; want committed %#v", got, err, retired)
	}
}

func TestDynamoSessionControlMarkFenceConvergedRetriesMixedAtomicTransitionView(t *testing.T) {
	preparedAt := time.Unix(1_800_001_000, 0).UTC()
	convergedAt := preparedAt.Add(10 * time.Second)
	prepared := testPreparedSessionControlFence(t, "dededededededededededededededede", 0x70, 2, preparedAt)
	converged := prepared
	converged.State = sessionControlFenceConverged
	converged.Version++
	converged.ConvergedAtMillis = convergedAt.UnixMilli()
	converged.ReplayNotBeforeMillis = convergedAt.Add(sessionControlFenceReplayHorizon).UnixMilli()
	converged.UpdatedAtMillis = convergedAt.UnixMilli()
	before := sessionControlFenceDirectory{CellID: prepared.CellID, Version: 2, ActiveFenceCount: 1, CreatedAtMillis: preparedAt.UnixMilli(), UpdatedAtMillis: preparedAt.UnixMilli()}
	after := before
	after.Version++
	after.UpdatedAtMillis = convergedAt.UnixMilli()
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, _ *http.Request) {
		switch calls.Add(1) {
		case 1:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceDirectoryWireItem(t, before)})
		case 2:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, prepared, false)})
		case 3:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, converged, true)})
		case 4, 5, 8:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceDirectoryWireItem(t, after)})
		case 6:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, converged, false)})
		case 7:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, converged, true)})
		default:
			t.Fatal("unexpected converged interleaving DynamoDB call")
		}
	})
	store.nowUTC = func() time.Time { return convergedAt }
	got, err := store.MarkFenceConverged(context.Background(), prepared)
	if err != nil || *got != converged {
		t.Fatalf("MarkFenceConverged() = %#v, %v; want committed %#v", got, err, converged)
	}
	if calls.Load() != 8 {
		t.Fatalf("DynamoDB calls = %d, want one retried four-read bracket", calls.Load())
	}
}

func TestDynamoSessionControlRetireFenceRetriesMixedAtomicTransitionView(t *testing.T) {
	preparedAt := time.Unix(1_800_002_000, 0).UTC()
	convergedAt := preparedAt.Add(10 * time.Second)
	retiredAt := convergedAt.Add(sessionControlFenceReplayHorizon)
	converged := testPreparedSessionControlFence(t, "efefefefefefefefefefefefefefefef", 0x71, 2, preparedAt)
	converged.State = sessionControlFenceConverged
	converged.Version++
	converged.ConvergedAtMillis = convergedAt.UnixMilli()
	converged.ReplayNotBeforeMillis = retiredAt.UnixMilli()
	converged.UpdatedAtMillis = convergedAt.UnixMilli()
	retired := converged
	retired.State = sessionControlFenceRetired
	retired.Version++
	retired.UpdatedAtMillis = retiredAt.UnixMilli()
	retired.RetiredAtMillis = retiredAt.UnixMilli()
	retired.ExpiresAt = retiredAt.Unix() + int64(sessionControlFenceIdempotencyTTL/time.Second)
	before := sessionControlFenceDirectory{CellID: converged.CellID, Version: 3, ActiveFenceCount: 1, CreatedAtMillis: preparedAt.UnixMilli(), UpdatedAtMillis: convergedAt.UnixMilli()}
	after := before
	after.Version++
	after.ActiveFenceCount = 0
	after.UpdatedAtMillis = retiredAt.UnixMilli()
	var calls atomic.Int32
	store := newDynamoSessionControlTestStore(t, func(w http.ResponseWriter, _ *http.Request) {
		switch calls.Add(1) {
		case 1:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceDirectoryWireItem(t, before)})
		case 2:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, converged, false)})
		case 3:
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		case 4, 5, 8:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceDirectoryWireItem(t, after)})
		case 6:
			writeSessionControlDynamoJSON(t, w, map[string]any{"Item": sessionControlFenceWireItem(t, retired, false)})
		case 7:
			writeSessionControlDynamoJSON(t, w, map[string]any{})
		default:
			t.Fatal("unexpected retired interleaving DynamoDB call")
		}
	})
	store.nowUTC = func() time.Time { return retiredAt }
	got, err := store.retireFence(context.Background(), converged)
	if err != nil || *got != retired {
		t.Fatalf("retireFence() = %#v, %v; want committed %#v", got, err, retired)
	}
	if calls.Load() != 8 {
		t.Fatalf("DynamoDB calls = %d, want one retried four-read bracket", calls.Load())
	}
}

func TestSessionControlFenceTransitionTokensAreStableAndSpecific(t *testing.T) {
	base := aws.ToString(sessionControlFenceTransactionToken("prepare", "cell-01", "event", "digest", uint64(2), int64(3)))
	if base == "" || len(base) > 36 || base != aws.ToString(sessionControlFenceTransactionToken("prepare", "cell-01", "event", "digest", uint64(2), int64(3))) {
		t.Fatalf("unstable fence token %q", base)
	}
	for _, mutated := range []*string{
		sessionControlFenceTransactionToken("prepare", "cell-02", "event", "digest", uint64(2), int64(3)),
		sessionControlFenceTransactionToken("prepare", "cell-01", "event-2", "digest", uint64(2), int64(3)),
		sessionControlFenceTransactionToken("mark", "cell-01", "event", "digest", uint64(2), int64(3)),
	} {
		if aws.ToString(mutated) == base {
			t.Fatalf("distinct transition reused token %q", base)
		}
	}
}
