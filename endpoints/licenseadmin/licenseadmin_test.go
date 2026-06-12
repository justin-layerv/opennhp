package licenseadmin

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// TestLicenseUnmarshalToleratesStringSet locks the read tolerance the runbook
// documents: a bound_pubkeys attribute stored as a DynamoDB String Set (SS) —
// e.g. written by some other path — must still unmarshal into []string, exactly
// as the gate's reader (attributevalue.UnmarshalMap into server.License) does.
// This tool only ever writes a List (L), so the tolerance is otherwise only
// exercised by prose + the integration test's L path.
func TestLicenseUnmarshalToleratesStringSet(t *testing.T) {
	k1, k2 := testPubkeyB64(1), testPubkeyB64(2)
	item := map[string]types.AttributeValue{
		"license_key_sha256": &types.AttributeValueMemberS{Value: "abc"},
		"bound_pubkeys":      &types.AttributeValueMemberSS{Value: []string{k1, k2}},
	}
	var lic License
	if err := attributevalue.UnmarshalMap(item, &lic); err != nil {
		t.Fatalf("unmarshal SS: %v", err)
	}
	if len(lic.BoundPubKeys) != 2 {
		t.Fatalf("got %v, want 2 entries", lic.BoundPubKeys)
	}
	// A String Set is unordered, so assert membership rather than position.
	seen := map[string]bool{lic.BoundPubKeys[0]: true, lic.BoundPubKeys[1]: true}
	if !seen[k1] || !seen[k2] {
		t.Fatalf("got %v, want {%s, %s}", lic.BoundPubKeys, k1, k2)
	}
}

// testPubkeyB64 returns the canonical base64 of a deterministic 32-byte key.
func testPubkeyB64(seed byte) string {
	k := make([]byte, BoundPubKeyRawLen)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(k)
}

type fakeAssignmentDDB struct {
	updateErr error
	updateOut *dynamodb.UpdateItemOutput
	getOut    *dynamodb.GetItemOutput
	getErr    error

	updateCalls int
	getCalls    int
	lastGetKey  map[string]types.AttributeValue
}

func (f *fakeAssignmentDDB) UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	f.updateCalls++
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	return f.updateOut, nil
}

func (f *fakeAssignmentDDB) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.getCalls++
	f.lastGetKey = in.Key
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.getOut, nil
}

func TestCanonicalizeBoundPubKey(t *testing.T) {
	valid := testPubkeyB64(1)

	// A 32-byte all-0xFF key encodes to standard base64 containing '/' (good)
	// and URL-safe base64 containing '_' (must be rejected).
	ff := bytes.Repeat([]byte{0xff}, BoundPubKeyRawLen)
	stdFF := base64.StdEncoding.EncodeToString(ff)
	urlFF := base64.URLEncoding.EncodeToString(ff)
	unpadded := strings.TrimRight(stdFF, "=")
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, BoundPubKeyRawLen-1))
	allZero := base64.StdEncoding.EncodeToString(make([]byte, BoundPubKeyRawLen))

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"valid canonical", valid, valid, false},
		{"surrounding whitespace trimmed", "  " + valid + "\n", valid, false},
		{"all-FF standard base64 ok", stdFF, stdFF, false},
		{"url-safe rejected", urlFF, "", true},
		{"unpadded rejected", unpadded, "", true},
		{"wrong length rejected", short, "", true},
		{"all-zero point rejected", allZero, "", true},
		{"garbage rejected", "not base64!!", "", true},
		{"empty rejected", "", "", true},
		{"whitespace only rejected", "   ", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalizeBoundPubKey(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result %q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("canonical = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAppendBoundPubKeys(t *testing.T) {
	k1, k2, k3 := testPubkeyB64(1), testPubkeyB64(2), testPubkeyB64(3)

	res, added, err := AppendBoundPubKeys(nil, []string{k1, k2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 2 || len(added) != 2 {
		t.Fatalf("append to empty: res=%v added=%v", res, added)
	}

	// Dedup against an existing entry presented with surrounding whitespace.
	res, added, err = AppendBoundPubKeys([]string{k1}, []string{"  " + k1 + " ", k3})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(added) != 1 || added[0] != k3 {
		t.Fatalf("expected only k3 added, got %v", added)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 entries, got %v", res)
	}

	if _, _, err := AppendBoundPubKeys([]string{k1}, []string{"bad!!"}); err == nil {
		t.Fatal("expected error for invalid addition")
	}
}

func TestRemoveBoundPubKey(t *testing.T) {
	k1, k2 := testPubkeyB64(1), testPubkeyB64(2)

	res, removed, err := RemoveBoundPubKey([]string{k1, k2}, "  "+k1+"\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !removed {
		t.Fatal("expected removed=true")
	}
	if len(res) != 1 || res[0] != k2 {
		t.Fatalf("expected [k2], got %v", res)
	}

	res, removed, err = RemoveBoundPubKey([]string{k2}, k1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if removed {
		t.Fatal("expected removed=false")
	}
	if len(res) != 1 || res[0] != k2 {
		t.Fatalf("expected [k2] unchanged, got %v", res)
	}

	if _, _, err := RemoveBoundPubKey([]string{k1}, "bad!!"); err == nil {
		t.Fatal("expected error for invalid target")
	}
}

func TestBuildBoundPubKeysUpdateSet(t *testing.T) {
	k1, k2 := testPubkeyB64(1), testPubkeyB64(2)
	in, err := buildBoundPubKeysUpdate("nhp-licenses", "abc123", []string{k1, k2}, 1000, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if got := aws.ToString(in.TableName); got != "nhp-licenses" {
		t.Errorf("table = %q", got)
	}
	if got := aws.ToString(in.ConditionExpression); got != "attribute_exists(license_key_sha256) AND updated_at = :expected" {
		t.Errorf("condition = %q", got)
	}
	if got := aws.ToString(in.UpdateExpression); got != "SET bound_pubkeys = :bpk, updated_at = :now" {
		t.Errorf("update = %q", got)
	}
	if keyAV, ok := in.Key["license_key_sha256"].(*types.AttributeValueMemberS); !ok || keyAV.Value != "abc123" {
		t.Errorf("key = %#v", in.Key)
	}
	assertN(t, in.ExpressionAttributeValues, ":expected", "1000")
	assertN(t, in.ExpressionAttributeValues, ":now", "2000")

	bpk, ok := in.ExpressionAttributeValues[":bpk"].(*types.AttributeValueMemberL)
	if !ok {
		t.Fatalf(":bpk is not a List: %T", in.ExpressionAttributeValues[":bpk"])
	}
	if len(bpk.Value) != 2 {
		t.Fatalf(":bpk has %d entries, want 2", len(bpk.Value))
	}
	for i, want := range []string{k1, k2} {
		s, ok := bpk.Value[i].(*types.AttributeValueMemberS)
		if !ok || s.Value != want {
			t.Errorf(":bpk[%d] = %#v, want S(%q)", i, bpk.Value[i], want)
		}
	}
}

func TestBuildBoundPubKeysUpdateRemove(t *testing.T) {
	in, err := buildBoundPubKeysUpdate("nhp-licenses", "abc123", nil, 1000, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if got := aws.ToString(in.UpdateExpression); got != "SET updated_at = :now REMOVE bound_pubkeys" {
		t.Errorf("update = %q", got)
	}
	if _, present := in.ExpressionAttributeValues[":bpk"]; present {
		t.Error(":bpk must be absent on REMOVE")
	}
	assertN(t, in.ExpressionAttributeValues, ":expected", "1000")
	assertN(t, in.ExpressionAttributeValues, ":now", "2000")
}

func TestNextVersion(t *testing.T) {
	tests := []struct {
		now, expected, want int64
	}{
		{2000, 1000, 2000}, // normal: clock ahead of the read token
		{1000, 1000, 1001}, // same wall-clock second → must bump so the token changes
		{5, 1000, 1001},    // clock behind a future-bumped token → strictly above it
		{2000, 0, 2000},    // legacy expected 0
		{0, 0, 1},          // both zero → bump to 1
	}
	for _, tc := range tests {
		if got := nextVersion(tc.now, tc.expected); got != tc.want {
			t.Errorf("nextVersion(%d,%d) = %d, want %d", tc.now, tc.expected, got, tc.want)
		}
		// Invariant: the written token always differs from what was read.
		if got := nextVersion(tc.now, tc.expected); got == tc.expected {
			t.Errorf("nextVersion(%d,%d) returned expected value %d (not a sound lock token)", tc.now, tc.expected, got)
		}
	}
}

func TestBuildBoundPubKeysUpdateOptimisticLock(t *testing.T) {
	k1 := testPubkeyB64(1)

	// expected == 0 models a legacy/externally-minted row with no updated_at
	// attribute (UnmarshalMap yields 0). The condition must tolerate the absent
	// attribute, otherwise the write can never succeed and the caller aborts
	// with a misleading "concurrent modification".
	in, err := buildBoundPubKeysUpdate("nhp-licenses", "abc123", []string{k1}, 0, 2000)
	if err != nil {
		t.Fatal(err)
	}
	wantZero := "attribute_exists(license_key_sha256) AND (attribute_not_exists(updated_at) OR updated_at = :expected)"
	if got := aws.ToString(in.ConditionExpression); got != wantZero {
		t.Errorf("condition (expected=0) = %q, want %q", got, wantZero)
	}

	// A non-zero expectation keeps the strict equality lock (no relaxation).
	in2, err := buildBoundPubKeysUpdate("nhp-licenses", "abc123", []string{k1}, 5, 2000)
	if err != nil {
		t.Fatal(err)
	}
	wantStrict := "attribute_exists(license_key_sha256) AND updated_at = :expected"
	if got := aws.ToString(in2.ConditionExpression); got != wantStrict {
		t.Errorf("condition (expected=5) = %q, want %q", got, wantStrict)
	}
}

func TestACAssignmentUnmarshalToleratesStringSet(t *testing.T) {
	k1, k2 := testPubkeyB64(1), testPubkeyB64(2)
	item := map[string]types.AttributeValue{
		"ac_id":           &types.AttributeValueMemberS{Value: "ac-1"},
		"version":         &types.AttributeValueMemberN{Value: "7"},
		"revoked_pubkeys": &types.AttributeValueMemberSS{Value: []string{k1, k2}},
	}
	var assignment ACAssignment
	if err := attributevalue.UnmarshalMap(item, &assignment); err != nil {
		t.Fatalf("unmarshal SS: %v", err)
	}
	if assignment.ACID != "ac-1" || assignment.Version != 7 {
		t.Fatalf("assignment = %+v", assignment)
	}
	seen := map[string]bool{assignment.RevokedPubKeys[0]: true, assignment.RevokedPubKeys[1]: true}
	if !seen[k1] || !seen[k2] {
		t.Fatalf("got %v, want {%s, %s}", assignment.RevokedPubKeys, k1, k2)
	}
}

func TestGetACAssignmentNotFound(t *testing.T) {
	ddb := &fakeAssignmentDDB{getOut: &dynamodb.GetItemOutput{}}
	client := &AssignmentClient{ddb: ddb, table: "nhp-ac-assignments", region: "us-west-2"}

	got, err := client.GetACAssignment(context.Background(), " ac-1 ")
	if !errors.Is(err, ErrACAssignmentNotFound) {
		t.Fatalf("err = %v, want wrapping %v", err, ErrACAssignmentNotFound)
	}
	if !strings.Contains(err.Error(), `region="us-west-2" table="nhp-ac-assignments"`) {
		t.Fatalf("err = %v, want region/table context", err)
	}
	if got != nil {
		t.Fatalf("assignment = %#v, want nil", got)
	}
	if ddb.getCalls != 1 || ddb.updateCalls != 0 {
		t.Fatalf("calls get=%d update=%d, want 1/0", ddb.getCalls, ddb.updateCalls)
	}
	assertS(t, ddb.lastGetKey, "ac_id", "ac-1")
}

func TestGetACAssignmentUnmarshalError(t *testing.T) {
	ddb := &fakeAssignmentDDB{
		getOut: &dynamodb.GetItemOutput{Item: map[string]types.AttributeValue{
			"ac_id":   &types.AttributeValueMemberS{Value: "ac-1"},
			"version": &types.AttributeValueMemberS{Value: "not-a-number"},
		}},
	}
	client := &AssignmentClient{ddb: ddb, table: "nhp-ac-assignments"}

	got, err := client.GetACAssignment(context.Background(), "ac-1")
	if err == nil || !strings.Contains(err.Error(), "unmarshal AC assignment ac-1") {
		t.Fatalf("err = %v, want unmarshal AC assignment context", err)
	}
	if got != nil {
		t.Fatalf("assignment = %#v, want nil", got)
	}
	if ddb.getCalls != 1 || ddb.updateCalls != 0 {
		t.Fatalf("calls get=%d update=%d, want 1/0", ddb.getCalls, ddb.updateCalls)
	}
}

func TestBuildRevokedPubKeyUpdateAdd(t *testing.T) {
	k1 := testPubkeyB64(1)
	in, canon, err := buildRevokedPubKeyUpdate("nhp-ac-assignments", " ac-1 ", k1, revokedPubKeyAdd)
	if err != nil {
		t.Fatal(err)
	}
	if canon != k1 {
		t.Fatalf("canonical pubkey = %q, want %q", canon, k1)
	}
	if got := aws.ToString(in.TableName); got != "nhp-ac-assignments" {
		t.Errorf("table = %q", got)
	}
	wantCondition := "attribute_exists(ac_id) AND (attribute_not_exists(revoked_pubkeys) OR NOT contains(revoked_pubkeys, :pk))"
	if got := aws.ToString(in.ConditionExpression); got != wantCondition {
		t.Errorf("condition = %q, want %q", got, wantCondition)
	}
	wantUpdate := "SET version = if_not_exists(version, :zero) + :one ADD revoked_pubkeys :pk_set"
	if got := aws.ToString(in.UpdateExpression); got != wantUpdate {
		t.Errorf("update = %q, want %q", got, wantUpdate)
	}
	if got := in.ReturnValues; got != types.ReturnValueAllNew {
		t.Errorf("return values = %q, want %q", got, types.ReturnValueAllNew)
	}
	if got := in.ReturnValuesOnConditionCheckFailure; got != types.ReturnValuesOnConditionCheckFailureAllOld {
		t.Errorf("return values on condition failure = %q, want %q", got, types.ReturnValuesOnConditionCheckFailureAllOld)
	}
	if keyAV, ok := in.Key["ac_id"].(*types.AttributeValueMemberS); !ok || keyAV.Value != "ac-1" {
		t.Errorf("key = %#v", in.Key)
	}
	assertS(t, in.ExpressionAttributeValues, ":pk", k1)
	assertSS(t, in.ExpressionAttributeValues, ":pk_set", []string{k1})
	assertN(t, in.ExpressionAttributeValues, ":zero", "0")
	assertN(t, in.ExpressionAttributeValues, ":one", "1")
}

func TestBuildRevokedPubKeyUpdateDelete(t *testing.T) {
	k1 := testPubkeyB64(1)
	in, canon, err := buildRevokedPubKeyUpdate("nhp-ac-assignments", "ac-1", k1, revokedPubKeyDelete)
	if err != nil {
		t.Fatal(err)
	}
	if canon != k1 {
		t.Fatalf("canonical pubkey = %q, want %q", canon, k1)
	}
	wantCondition := "attribute_exists(ac_id) AND contains(revoked_pubkeys, :pk)"
	if got := aws.ToString(in.ConditionExpression); got != wantCondition {
		t.Errorf("condition = %q, want %q", got, wantCondition)
	}
	wantUpdate := "SET version = if_not_exists(version, :zero) + :one DELETE revoked_pubkeys :pk_set"
	if got := aws.ToString(in.UpdateExpression); got != wantUpdate {
		t.Errorf("update = %q, want %q", got, wantUpdate)
	}
	assertS(t, in.ExpressionAttributeValues, ":pk", k1)
	assertSS(t, in.ExpressionAttributeValues, ":pk_set", []string{k1})
}

func TestBuildRevokedPubKeyUpdateRejectsInvalidInput(t *testing.T) {
	if _, _, err := buildRevokedPubKeyUpdate("", "ac-1", testPubkeyB64(1), revokedPubKeyAdd); err == nil {
		t.Fatal("expected empty table error")
	}
	if _, _, err := buildRevokedPubKeyUpdate("t", " ", testPubkeyB64(1), revokedPubKeyAdd); err == nil {
		t.Fatal("expected empty ac_id error")
	}
	if _, _, err := buildRevokedPubKeyUpdate("t", "ac-1", "bad!!", revokedPubKeyAdd); err == nil {
		t.Fatal("expected invalid pubkey error")
	}
	if _, _, err := buildRevokedPubKeyUpdate("t", "ac-1", testPubkeyB64(1), revokedPubKeyAction("bogus")); err == nil {
		t.Fatal("expected unknown action error")
	}
}

func TestClassifyRevokedPubKeyState(t *testing.T) {
	k1, k2 := testPubkeyB64(1), testPubkeyB64(2)

	tests := []struct {
		name        string
		keys        []string
		action      revokedPubKeyAction
		pubkey      string
		wantChanged bool
		wantErr     error
	}{
		{
			name:        "add no-op when pubkey already present",
			action:      revokedPubKeyAdd,
			pubkey:      k1,
			wantChanged: false,
		},
		{
			name:    "add conflict when pubkey still absent",
			action:  revokedPubKeyAdd,
			pubkey:  k2,
			wantErr: ErrConcurrentModification,
		},
		{
			name:    "delete legacy whitespace entry is terminal",
			action:  revokedPubKeyDelete,
			pubkey:  k1,
			wantErr: ErrLegacyRevokedPubKeyWhitespace,
		},
		{
			name:    "delete conflict when exact pubkey still present",
			keys:    []string{k1},
			action:  revokedPubKeyDelete,
			pubkey:  k1,
			wantErr: ErrConcurrentModification,
		},
		{
			name:        "delete no-op when pubkey absent",
			action:      revokedPubKeyDelete,
			pubkey:      k2,
			wantChanged: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keys := []string{"  " + k1 + "\n"}
			if tc.keys != nil {
				keys = tc.keys
			}
			assignment := &ACAssignment{ACID: "ac-1", Version: 9, RevokedPubKeys: keys}
			got, changed, err := classifyRevokedPubKeyState(assignment, "ac-1", tc.pubkey, tc.action)
			if tc.wantErr != nil {
				if err == nil || !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want wrapping %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != assignment || changed != tc.wantChanged {
				t.Fatalf("got assignment=%p changed=%t, want assignment=%p changed=%t", got, changed, assignment, tc.wantChanged)
			}
		})
	}
}

func TestRevokedPubKeyClientSuccessUnmarshalsUpdatedAssignment(t *testing.T) {
	k1, k2 := testPubkeyB64(1), testPubkeyB64(2)

	tests := []struct {
		name       string
		updateItem ACAssignment
		call       func(context.Context, *AssignmentClient) (*ACAssignment, string, bool, error)
		wantCanon  string
		wantKeys   []string
	}{
		{
			name: "add",
			updateItem: ACAssignment{
				ACID:           "ac-1",
				Version:        8,
				RevokedPubKeys: []string{k1, k2},
			},
			call: func(ctx context.Context, client *AssignmentClient) (*ACAssignment, string, bool, error) {
				return client.AddRevokedPubKey(ctx, " ac-1 ", k2)
			},
			wantCanon: k2,
			wantKeys:  []string{k1, k2},
		},
		{
			name: "remove",
			updateItem: ACAssignment{
				ACID:    "ac-1",
				Version: 8,
			},
			call: func(ctx context.Context, client *AssignmentClient) (*ACAssignment, string, bool, error) {
				return client.RemoveRevokedPubKey(ctx, " ac-1 ", k1)
			},
			wantCanon: k1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ddb := &fakeAssignmentDDB{
				updateOut: &dynamodb.UpdateItemOutput{Attributes: mustAssignmentItem(t, tc.updateItem)},
			}
			client := &AssignmentClient{ddb: ddb, table: "nhp-ac-assignments"}

			got, canon, changed, err := tc.call(context.Background(), client)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !changed {
				t.Fatal("expected changed=true after successful conditional update")
			}
			if got == nil || got.ACID != "ac-1" || got.Version != 8 || !slices.Equal(got.RevokedPubKeys, tc.wantKeys) {
				t.Fatalf("assignment = %#v, want ac-1 version 8 keys %v", got, tc.wantKeys)
			}
			if canon != tc.wantCanon {
				t.Fatalf("canonical pubkey = %q, want %q", canon, tc.wantCanon)
			}
			if ddb.updateCalls != 1 || ddb.getCalls != 0 {
				t.Fatalf("calls update=%d get=%d, want 1/0", ddb.updateCalls, ddb.getCalls)
			}
		})
	}
}

func TestAddRevokedPubKeyClassifiesConditionalFailureWithReturnedItem(t *testing.T) {
	k1 := testPubkeyB64(1)
	ddb := &fakeAssignmentDDB{
		updateErr: &types.ConditionalCheckFailedException{Item: mustAssignmentItem(t, ACAssignment{
			ACID:           "ac-1",
			Version:        7,
			RevokedPubKeys: []string{k1},
		})},
	}
	client := &AssignmentClient{ddb: ddb, table: "nhp-ac-assignments"}

	got, canon, changed, err := client.AddRevokedPubKey(context.Background(), " ac-1 ", k1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if canon != k1 {
		t.Fatalf("canonical pubkey = %q, want %q", canon, k1)
	}
	if changed {
		t.Fatal("expected changed=false after returned item confirms add no-op")
	}
	if got == nil || got.Version != 7 || got.ACID != "ac-1" {
		t.Fatalf("assignment = %#v, want returned ac-1 version 7", got)
	}
	if ddb.updateCalls != 1 || ddb.getCalls != 0 {
		t.Fatalf("calls update=%d get=%d, want 1/0", ddb.updateCalls, ddb.getCalls)
	}
}

func TestAddRevokedPubKeyClassifiesConditionalFailureWithFallbackRead(t *testing.T) {
	k1 := testPubkeyB64(1)
	ddb := &fakeAssignmentDDB{
		updateErr: &types.ConditionalCheckFailedException{},
		getOut: &dynamodb.GetItemOutput{Item: mustAssignmentItem(t, ACAssignment{
			ACID:           "ac-1",
			Version:        7,
			RevokedPubKeys: []string{k1},
		})},
	}
	client := &AssignmentClient{ddb: ddb, table: "nhp-ac-assignments"}

	got, canon, changed, err := client.AddRevokedPubKey(context.Background(), " ac-1 ", k1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if canon != k1 {
		t.Fatalf("canonical pubkey = %q, want %q", canon, k1)
	}
	if changed {
		t.Fatal("expected changed=false after fallback read confirms add no-op")
	}
	if got == nil || got.Version != 7 || got.ACID != "ac-1" {
		t.Fatalf("assignment = %#v, want fallback-read ac-1 version 7", got)
	}
	if ddb.updateCalls != 1 || ddb.getCalls != 1 {
		t.Fatalf("calls update=%d get=%d, want 1/1", ddb.updateCalls, ddb.getCalls)
	}
	assertS(t, ddb.lastGetKey, "ac_id", "ac-1")
}

func TestAddRevokedPubKeyConditionalFailureMissingAssignment(t *testing.T) {
	k1 := testPubkeyB64(1)
	ddb := &fakeAssignmentDDB{
		updateErr: &types.ConditionalCheckFailedException{},
		getOut:    &dynamodb.GetItemOutput{},
	}
	client := &AssignmentClient{ddb: ddb, region: "us-east-2", table: "nhp-ac-assignments"}

	assignment, canon, changed, err := client.AddRevokedPubKey(context.Background(), " ac-missing ", k1)
	if !errors.Is(err, ErrACAssignmentNotFound) {
		t.Fatalf("err = %v, want ErrACAssignmentNotFound", err)
	}
	if assignment != nil || changed {
		t.Fatalf("assignment=%#v changed=%t, want nil/false", assignment, changed)
	}
	if canon != k1 {
		t.Fatalf("canonical pubkey = %q, want %q", canon, k1)
	}
	if !strings.Contains(err.Error(), `region="us-east-2" table="nhp-ac-assignments"`) {
		t.Fatalf("not-found error lacks lookup context: %v", err)
	}
	if ddb.updateCalls != 1 || ddb.getCalls != 1 {
		t.Fatalf("calls update=%d get=%d, want 1/1", ddb.updateCalls, ddb.getCalls)
	}
	assertS(t, ddb.lastGetKey, "ac_id", "ac-missing")
}

func TestRemoveRevokedPubKeyClassifiesLegacyWhitespaceAfterConditionalFailure(t *testing.T) {
	k1 := testPubkeyB64(1)
	ddb := &fakeAssignmentDDB{
		updateErr: &types.ConditionalCheckFailedException{Item: mustAssignmentItem(t, ACAssignment{
			ACID:           "ac-1",
			Version:        7,
			RevokedPubKeys: []string{"  " + k1 + "\n"},
		})},
	}
	client := &AssignmentClient{ddb: ddb, table: "nhp-ac-assignments"}

	_, canon, changed, err := client.RemoveRevokedPubKey(context.Background(), "ac-1", k1)
	if !errors.Is(err, ErrLegacyRevokedPubKeyWhitespace) {
		t.Fatalf("err = %v, want wrapping %v", err, ErrLegacyRevokedPubKeyWhitespace)
	}
	if canon != k1 {
		t.Fatalf("canonical pubkey = %q, want %q", canon, k1)
	}
	if changed {
		t.Fatal("expected changed=false on terminal legacy-whitespace classification")
	}
	if ddb.updateCalls != 1 || ddb.getCalls != 0 {
		t.Fatalf("calls update=%d get=%d, want 1/0", ddb.updateCalls, ddb.getCalls)
	}
}

func TestRevokedPubKeyPresentTrimsWhitespaceOnly(t *testing.T) {
	k1 := testPubkeyB64(1)
	if !revokedPubKeyPresent([]string{"  " + k1 + "\n"}, k1) {
		t.Fatal("expected whitespace-trimmed match")
	}
	if revokedPubKeyPresent([]string{"AB+/"}, "AB-_") {
		t.Fatal("URL-safe/std-base64 variants must not be normalized together")
	}
}

func mustAssignmentItem(t *testing.T, assignment ACAssignment) map[string]types.AttributeValue {
	t.Helper()
	item, err := attributevalue.MarshalMap(assignment)
	if err != nil {
		t.Fatalf("marshal AC assignment: %v", err)
	}
	return item
}

func assertN(t *testing.T, m map[string]types.AttributeValue, key, want string) {
	t.Helper()
	v, ok := m[key].(*types.AttributeValueMemberN)
	if !ok {
		t.Fatalf("%s is not a Number: %T", key, m[key])
	}
	if v.Value != want {
		t.Errorf("%s = %q, want %q", key, v.Value, want)
	}
}

func assertS(t *testing.T, m map[string]types.AttributeValue, key, want string) {
	t.Helper()
	v, ok := m[key].(*types.AttributeValueMemberS)
	if !ok {
		t.Fatalf("%s is not a String: %T", key, m[key])
	}
	if v.Value != want {
		t.Errorf("%s = %q, want %q", key, v.Value, want)
	}
}

func assertSS(t *testing.T, m map[string]types.AttributeValue, key string, want []string) {
	t.Helper()
	v, ok := m[key].(*types.AttributeValueMemberSS)
	if !ok {
		t.Fatalf("%s is not a String Set: %T", key, m[key])
	}
	got := slices.Clone(v.Value)
	want = slices.Clone(want)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("%s = %v, want %v", key, v.Value, want)
	}
}

func TestLicenseKeySHA256(t *testing.T) {
	// Known vector: SHA256("abc").
	got := LicenseKeySHA256("abc")
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Fatalf("LicenseKeySHA256(\"abc\") = %s, want %s", got, want)
	}
}
