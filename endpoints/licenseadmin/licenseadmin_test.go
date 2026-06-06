package licenseadmin

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
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

func TestLicenseKeySHA256(t *testing.T) {
	// Known vector: SHA256("abc").
	got := LicenseKeySHA256("abc")
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Fatalf("LicenseKeySHA256(\"abc\") = %s, want %s", got, want)
	}
}
