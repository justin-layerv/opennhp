package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/endpoints/licenseadmin"
)

// testKey returns the canonical base64 of a deterministic non-zero 32-byte key.
func testKey(seed byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// fakeStore is an in-memory licenseStore for unit-testing the command cores.
type fakeStore struct {
	lic       *licenseadmin.License
	getErr    error
	updateErr error
	updates   int
	lastKeys  []string
}

func (f *fakeStore) GetLicense(ctx context.Context, sha string) (*licenseadmin.License, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.lic, nil
}

func (f *fakeStore) UpdateBoundPubKeys(ctx context.Context, sha string, keys []string, expected int64) (int64, error) {
	f.updates++
	f.lastKeys = keys
	if f.updateErr != nil {
		return 0, f.updateErr
	}
	return expected + 1, nil
}

func TestRunUnbindGuardsLastKey(t *testing.T) {
	k1, k2 := testKey(1), testKey(2)
	ctx := context.Background()

	// Removing the last key without --yes is refused and does NOT write.
	fs := &fakeStore{lic: &licenseadmin.License{BoundPubKeys: []string{k1}}}
	if err := runUnbind(ctx, fs, io.Discard, "", "op", "sha", k1, false); err == nil {
		t.Fatal("expected refusal removing the last key without --yes")
	}
	if fs.updates != 0 {
		t.Fatalf("must not write on refusal; updates=%d", fs.updates)
	}

	// With --yes it writes the empty list (REMOVE).
	fs = &fakeStore{lic: &licenseadmin.License{BoundPubKeys: []string{k1}}}
	if err := runUnbind(ctx, fs, io.Discard, "", "op", "sha", k1, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fs.updates != 1 || len(fs.lastKeys) != 0 {
		t.Fatalf("expected one write of empty list; updates=%d keys=%v", fs.updates, fs.lastKeys)
	}

	// Removing a non-last key writes the remaining list, no --yes needed.
	fs = &fakeStore{lic: &licenseadmin.License{BoundPubKeys: []string{k1, k2}}}
	if err := runUnbind(ctx, fs, io.Discard, "", "op", "sha", k1, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fs.updates != 1 || len(fs.lastKeys) != 1 || fs.lastKeys[0] != k2 {
		t.Fatalf("expected write of [k2]; updates=%d keys=%v", fs.updates, fs.lastKeys)
	}

	// Removing a key that isn't present is a no-op (no write, "no change").
	fs = &fakeStore{lic: &licenseadmin.License{BoundPubKeys: []string{k2}}}
	var out bytes.Buffer
	if err := runUnbind(ctx, fs, &out, "", "op", "sha", k1, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fs.updates != 0 {
		t.Fatalf("no-op must not write; updates=%d", fs.updates)
	}
	if !strings.Contains(out.String(), "no change") {
		t.Fatalf("expected 'no change', got %q", out.String())
	}
}

func TestRunBindAndResetNoOps(t *testing.T) {
	k1 := testKey(1)
	ctx := context.Background()

	// bind of an already-bound key: no write, "no change".
	fs := &fakeStore{lic: &licenseadmin.License{BoundPubKeys: []string{k1}}}
	var out bytes.Buffer
	if err := runBind(ctx, fs, &out, "", "op", "sha", []string{k1}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fs.updates != 0 || !strings.Contains(out.String(), "no change") {
		t.Fatalf("bind no-op: updates=%d out=%q", fs.updates, out.String())
	}

	// bind of a new key: writes.
	fs = &fakeStore{lic: &licenseadmin.License{}}
	if err := runBind(ctx, fs, io.Discard, "", "op", "sha", []string{k1}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fs.updates != 1 || len(fs.lastKeys) != 1 {
		t.Fatalf("bind write: updates=%d keys=%v", fs.updates, fs.lastKeys)
	}

	// reset of an already-unbound license: no write.
	fs = &fakeStore{lic: &licenseadmin.License{}}
	out.Reset()
	if err := runReset(ctx, fs, &out, "", "op", "sha"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fs.updates != 0 || !strings.Contains(out.String(), "already unbound") {
		t.Fatalf("reset no-op: updates=%d out=%q", fs.updates, out.String())
	}

	// reset of a bound license: writes nil (REMOVE).
	fs = &fakeStore{lic: &licenseadmin.License{BoundPubKeys: []string{k1}}}
	if err := runReset(ctx, fs, io.Discard, "", "op", "sha"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fs.updates != 1 || fs.lastKeys != nil {
		t.Fatalf("reset write: updates=%d keys=%v", fs.updates, fs.lastKeys)
	}

	// GetLicense error propagates without writing.
	fs = &fakeStore{getErr: licenseadmin.ErrLicenseNotFound}
	if err := runReset(ctx, fs, io.Discard, "", "op", "sha"); !errors.Is(err, licenseadmin.ErrLicenseNotFound) {
		t.Fatalf("expected ErrLicenseNotFound, got %v", err)
	}
	if fs.updates != 0 {
		t.Fatalf("must not write when GetLicense fails; updates=%d", fs.updates)
	}
}

func TestBuildAuditRecord(t *testing.T) {
	rec := buildAuditRecord("bind", "alice", "abc123", nil, []string{"k1"}, nil, "2026-06-06T00:00:00Z")
	if rec.Audit != "nhp-license-admin" || rec.Action != "bind" || rec.Operator != "alice" || rec.License != "abc123" || rec.TS != "2026-06-06T00:00:00Z" {
		t.Fatalf("unexpected record: %+v", rec)
	}
	// nil slices must be normalized so the JSON renders [] not null.
	if rec.Before == nil || rec.Changed == nil {
		t.Fatal("nil before/changed must be normalized to non-nil")
	}

	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"audit", "action", "operator", "license_key_sha256", "before", "after", "changed", "ts"} {
		if _, ok := m[k]; !ok {
			t.Errorf("audit JSON missing key %q", k)
		}
	}
	// before/changed must serialize as arrays, never null.
	if _, ok := m["before"].([]any); !ok {
		t.Errorf("before should be a JSON array, got %T", m["before"])
	}
	if _, ok := m["changed"].([]any); !ok {
		t.Errorf("changed should be a JSON array, got %T", m["changed"])
	}
}

func TestResolveLicenseSHA256(t *testing.T) {
	validSHA := strings.Repeat("a", 64)
	tests := []struct {
		name, sha, key, env, want string
		wantErr                   bool
	}{
		{"sha only", validSHA, "", "", validSHA, false},
		{"sha lower-cased and trimmed", "  " + strings.ToUpper(validSHA) + "\n", "", "", validSHA, false},
		{"key flag only is hashed", "", "my-license-key", "", licenseadmin.LicenseKeySHA256("my-license-key"), false},
		{"key flag trimmed before hashing", "", "  my-license-key\n", "", licenseadmin.LicenseKeySHA256("my-license-key"), false},
		{"env key only is hashed", "", "", "env-key", licenseadmin.LicenseKeySHA256("env-key"), false},
		{"env key trimmed before hashing", "", "", "  env-key\n", licenseadmin.LicenseKeySHA256("env-key"), false},
		{"whitespace-only key is no selector", "", "   ", "", "", true},
		{"whitespace-only key doesn't conflict with sha", validSHA, "   ", "", validSHA, false},
		{"sha wins over env key (no collision)", validSHA, "", "env-key", validSHA, false},
		{"explicit key flag wins over env key", "", "flag-key", "env-key", licenseadmin.LicenseKeySHA256("flag-key"), false},
		{"both explicit selector flags rejected", validSHA, "k", "", "", true},
		{"both explicit flags rejected even with env", validSHA, "k", "env-key", "", true},
		{"no selector at all rejected", "", "", "", "", true},
		{"sha wrong length rejected", "abc", "", "", "", true},
		{"sha non-hex rejected", strings.Repeat("g", 64), "", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveLicenseSHA256(tc.sha, tc.key, tc.env)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsHex64(t *testing.T) {
	if !isHex64(strings.Repeat("0", 64)) {
		t.Error("64 zeros should be valid")
	}
	if !isHex64("0123456789abcdef" + strings.Repeat("0", 48)) {
		t.Error("valid lowercase hex rejected")
	}
	if isHex64(strings.Repeat("0", 63)) {
		t.Error("63 chars must be rejected")
	}
	if isHex64(strings.Repeat("0", 65)) {
		t.Error("65 chars must be rejected")
	}
	if isHex64(strings.Repeat("A", 64)) {
		t.Error("uppercase hex must be rejected (callers lower-case first)")
	}
	if isHex64(strings.Repeat("z", 64)) {
		t.Error("non-hex char must be rejected")
	}
}

func TestReadPubkeysFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "keys.txt")
	content := "# a comment\n\n  K1==  \nK2==\n   # indented comment\nK3==\n\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readPubkeysFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"K1==", "K2==", "K3=="}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}

	if _, err := readPubkeysFile(filepath.Join(dir, "does-not-exist.txt")); err == nil {
		t.Error("expected error for a missing file")
	}
}

func TestGatherCanonicalPubkeys(t *testing.T) {
	// Two valid 32-byte keys in canonical std-base64.
	k1 := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	k2 := base64.StdEncoding.EncodeToString([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"))

	// inline only
	got, err := gatherCanonicalPubkeys([]string{k1}, "")
	if err != nil || len(got) != 1 || got[0] != k1 {
		t.Fatalf("inline only: got %v err %v", got, err)
	}

	// inline + file merged
	dir := t.TempDir()
	p := filepath.Join(dir, "keys.txt")
	if err := os.WriteFile(p, []byte("# comment\n"+k2+"\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = gatherCanonicalPubkeys([]string{k1}, p)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(got) != 2 || got[0] != k1 || got[1] != k2 {
		t.Fatalf("merge: got %v", got)
	}

	// duplicate inline keys are deduped (count reflects distinct keys)
	got, err = gatherCanonicalPubkeys([]string{k1, k1, k2}, "")
	if err != nil {
		t.Fatalf("dedup: %v", err)
	}
	if len(got) != 2 || got[0] != k1 || got[1] != k2 {
		t.Fatalf("dedup: got %v, want [k1 k2]", got)
	}

	// empty (no inline, no file) → error
	if _, err := gatherCanonicalPubkeys(nil, ""); err == nil {
		t.Error("expected error for no inputs")
	}

	// a malformed key anywhere → error
	if _, err := gatherCanonicalPubkeys([]string{k1, "bad!!"}, ""); err == nil {
		t.Error("expected error for a malformed inline key")
	}

	// missing file → error
	if _, err := gatherCanonicalPubkeys([]string{k1}, filepath.Join(dir, "nope.txt")); err == nil {
		t.Error("expected error for a missing file")
	}
}

func TestWithRetry(t *testing.T) {
	// Succeeds on the first try.
	calls := 0
	if err := withRetry(context.Background(), func() error { calls++; return nil }); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}

	// A non-conflict error aborts immediately (no retry).
	calls = 0
	if err := withRetry(context.Background(), func() error { calls++; return errors.New("boom") }); err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (must not retry a non-conflict error)", calls)
	}

	// A conflict that clears on the second attempt succeeds.
	calls = 0
	err := withRetry(context.Background(), func() error {
		calls++
		if calls < 2 {
			return fmt.Errorf("wrapped: %w", licenseadmin.ErrConcurrentModification)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}

	// A persistent conflict exhausts maxAttempts and aborts.
	calls = 0
	if err := withRetry(context.Background(), func() error { calls++; return licenseadmin.ErrConcurrentModification }); err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if calls != 4 {
		t.Fatalf("calls = %d, want 4 (maxAttempts)", calls)
	}
}
