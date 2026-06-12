package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urfave/cli/v2"

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

type fakeAssignmentStore struct {
	assignment  *licenseadmin.ACAssignment
	getErr      error
	addErr      error
	removeErr   error
	addChanged  bool
	remChanged  bool
	gets        int
	adds        int
	removes     int
	lastGetACID string
	lastAddACID string
	lastRemACID string
	lastAddKey  string
	lastRemKey  string
}

func (f *fakeAssignmentStore) GetACAssignment(ctx context.Context, acID string) (*licenseadmin.ACAssignment, error) {
	f.gets++
	f.lastGetACID = acID
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.assignment, nil
}

func (f *fakeAssignmentStore) AddRevokedPubKey(ctx context.Context, acID, pubkey string) (*licenseadmin.ACAssignment, string, bool, error) {
	f.adds++
	f.lastAddACID = acID
	f.lastAddKey = pubkey
	if f.addErr != nil {
		return nil, "", false, f.addErr
	}
	return f.assignment, pubkey, f.addChanged, nil
}

func (f *fakeAssignmentStore) RemoveRevokedPubKey(ctx context.Context, acID, pubkey string) (*licenseadmin.ACAssignment, string, bool, error) {
	f.removes++
	f.lastRemACID = acID
	f.lastRemKey = pubkey
	if f.removeErr != nil {
		return nil, "", false, f.removeErr
	}
	return f.assignment, pubkey, f.remChanged, nil
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

func TestRunRevokeAndUnrevoke(t *testing.T) {
	k1 := testKey(1)
	ctx := context.Background()

	fs := &fakeAssignmentStore{
		assignment: &licenseadmin.ACAssignment{ACID: "ac-1", Version: 3, RevokedPubKeys: []string{k1}},
		addChanged: true,
	}
	var out bytes.Buffer
	mutatedRevokeAuditPath := filepath.Join(t.TempDir(), "revoke-mutated-audit.jsonl")
	if err := runRevoke(ctx, fs, &out, mutatedRevokeAuditPath, "op", "ac-1", k1); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if fs.adds != 1 || fs.removes != 0 {
		t.Fatalf("unexpected calls: adds=%d removes=%d", fs.adds, fs.removes)
	}
	if !strings.Contains(out.String(), "revoked pubkey for AC ac-1") || !strings.Contains(out.String(), "normally <=60s") {
		t.Fatalf("revoke output missing success/propagation text: %q", out.String())
	}
	rec := readACAuditRecord(t, mutatedRevokeAuditPath)
	if rec.Action != "revoke" || !rec.Changed || rec.Result != "mutated" || rec.PubKey != k1 || rec.Version != 3 || !slices.Equal(rec.RevokedPubKeys, []string{k1}) {
		t.Fatalf("unexpected mutated revoke audit: %+v", rec)
	}

	fs = &fakeAssignmentStore{
		assignment: &licenseadmin.ACAssignment{ACID: "ac-1", Version: 6, RevokedPubKeys: []string{" " + k1 + "\n", k1}},
		addChanged: true,
	}
	out.Reset()
	if err := runRevoke(ctx, fs, &out, "", "op", "ac-1", k1); err != nil {
		t.Fatalf("revoke with legacy duplicate: %v", err)
	}
	if !strings.Contains(out.String(), "legacy non-canonical revoked_pubkeys entry already matched") {
		t.Fatalf("revoke legacy duplicate output missing normalization note: %q", out.String())
	}
	if strings.Contains(out.String(), "reject the next registration") {
		t.Fatalf("revoke legacy duplicate output must not present the gate reject as newly pending: %q", out.String())
	}

	fs = &fakeAssignmentStore{
		assignment: &licenseadmin.ACAssignment{ACID: "ac-1", Version: 3, RevokedPubKeys: []string{k1}},
		addChanged: false,
	}
	revokeAuditPath := filepath.Join(t.TempDir(), "revoke-audit.jsonl")
	out.Reset()
	if err := runRevoke(ctx, fs, &out, revokeAuditPath, "op", "ac-1", k1); err != nil {
		t.Fatalf("revoke no-op: %v", err)
	}
	if !strings.Contains(out.String(), "no change") || !strings.Contains(out.String(), "version unchanged") {
		t.Fatalf("revoke no-op output = %q", out.String())
	}
	rec = readACAuditRecord(t, revokeAuditPath)
	if rec.Action != "revoke" || rec.Changed || rec.PubKey != k1 || rec.Version != 3 {
		t.Fatalf("unexpected no-op revoke audit: %+v", rec)
	}

	fs = &fakeAssignmentStore{
		assignment: &licenseadmin.ACAssignment{ACID: "ac-1", Version: 7, RevokedPubKeys: []string{" " + k1 + "\n", k1}},
		addChanged: false,
	}
	out.Reset()
	if err := runRevoke(ctx, fs, &out, "", "op", "ac-1", k1); err != nil {
		t.Fatalf("revoke no-op with legacy duplicate: %v", err)
	}
	if !strings.Contains(out.String(), "legacy non-canonical revoked_pubkeys entry also matches") {
		t.Fatalf("revoke no-op legacy duplicate output missing cleanup note: %q", out.String())
	}

	fs = &fakeAssignmentStore{
		assignment: &licenseadmin.ACAssignment{ACID: "ac-1", Version: 4},
		remChanged: true,
	}
	out.Reset()
	if err := runUnrevoke(ctx, fs, &out, "", "op", "ac-1", k1); err != nil {
		t.Fatalf("unrevoke: %v", err)
	}
	if fs.removes != 1 || fs.adds != 0 {
		t.Fatalf("unexpected calls: adds=%d removes=%d", fs.adds, fs.removes)
	}
	if !strings.Contains(out.String(), "unrevoked pubkey for AC ac-1") || !strings.Contains(out.String(), "normally <=60s") {
		t.Fatalf("unrevoke output missing success/propagation text: %q", out.String())
	}

	fs = &fakeAssignmentStore{
		assignment: &licenseadmin.ACAssignment{ACID: "ac-1", Version: 5, RevokedPubKeys: []string{" " + k1 + "\n"}},
		remChanged: true,
	}
	out.Reset()
	if err := runUnrevoke(ctx, fs, &out, "", "op", "ac-1", k1); err != nil {
		t.Fatalf("unrevoke with legacy residual: %v", err)
	}
	if !strings.Contains(out.String(), "non-canonical revoked_pubkeys entry still matches") {
		t.Fatalf("unrevoke residual output missing cleanup warning: %q", out.String())
	}
	if strings.Contains(out.String(), "stop rejecting") {
		t.Fatalf("unrevoke residual output must not promise stop rejecting: %q", out.String())
	}

	fs = &fakeAssignmentStore{
		assignment: &licenseadmin.ACAssignment{ACID: "ac-1", Version: 4},
		remChanged: false,
	}
	unrevokeAuditPath := filepath.Join(t.TempDir(), "unrevoke-audit.jsonl")
	out.Reset()
	if err := runUnrevoke(ctx, fs, &out, unrevokeAuditPath, "op", "ac-1", k1); err != nil {
		t.Fatalf("unrevoke no-op: %v", err)
	}
	if !strings.Contains(out.String(), "no change") || !strings.Contains(out.String(), "version unchanged") {
		t.Fatalf("unrevoke no-op output = %q", out.String())
	}
	rec = readACAuditRecord(t, unrevokeAuditPath)
	if rec.Action != "unrevoke" || rec.Changed || rec.PubKey != k1 || rec.Version != 4 {
		t.Fatalf("unexpected no-op unrevoke audit: %+v", rec)
	}
}

func TestRunRevokePropagatesStoreError(t *testing.T) {
	k1 := testKey(1)
	auditPath := filepath.Join(t.TempDir(), "revoke-error-audit.jsonl")
	fs := &fakeAssignmentStore{addErr: licenseadmin.ErrACAssignmentNotFound}
	if err := runRevoke(context.Background(), fs, io.Discard, auditPath, "op", "ac-missing", k1); !errors.Is(err, licenseadmin.ErrACAssignmentNotFound) {
		t.Fatalf("got %v, want ErrACAssignmentNotFound", err)
	}
	rec := readACAuditRecord(t, auditPath)
	if rec.Action != "revoke" || rec.ACID != "ac-missing" || rec.PubKey != k1 || rec.Changed || rec.Version != 0 || rec.Error == "" {
		t.Fatalf("unexpected error audit: %+v", rec)
	}
}

func TestRunRevokeSkipsAuditForRetryableConflict(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "revoke-conflict-audit.jsonl")
	fs := &fakeAssignmentStore{addErr: licenseadmin.ErrConcurrentModification}
	if err := runRevoke(context.Background(), fs, io.Discard, auditPath, "op", "ac-1", testKey(1)); !errors.Is(err, licenseadmin.ErrConcurrentModification) {
		t.Fatalf("got %v, want ErrConcurrentModification", err)
	}
	if _, err := os.Stat(auditPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retryable conflict should not emit a terminal-failure audit record; stat err=%v", err)
	}
}

func TestRunRevokeAuditsRetryExhaustion(t *testing.T) {
	k1 := testKey(1)
	auditPath := filepath.Join(t.TempDir(), "revoke-retry-exhausted-audit.jsonl")
	fs := &fakeAssignmentStore{addErr: licenseadmin.ErrConcurrentModification}
	err := withRetryOnExhaust(context.Background(), func() error {
		return runRevoke(context.Background(), fs, io.Discard, auditPath, "op", "ac-1", k1)
	}, func(err error) {
		emitACErrorAudit(auditPath, "revoke", "op", "ac-1", k1, err)
	})
	if err == nil {
		t.Fatal("expected retry exhaustion")
	}
	if fs.adds != 4 {
		t.Fatalf("adds = %d, want 4", fs.adds)
	}
	rec := readACAuditRecord(t, auditPath)
	if rec.Action != "revoke" || rec.PubKey != k1 || rec.Changed || !strings.Contains(rec.Error, "aborted after 4 retries") {
		t.Fatalf("unexpected retry-exhaustion audit: %+v", rec)
	}
}

func TestAssignmentMutationCommandsAuditRetryExhaustion(t *testing.T) {
	k1 := testKey(1)
	tests := []struct {
		name        string
		command     func(func(*cli.Context) (assignmentStore, error), io.Writer) *cli.Command
		store       *fakeAssignmentStore
		wantAdds    int
		wantRemoves int
	}{
		{
			name:        "revoke",
			command:     revokeCommandWithDeps,
			store:       &fakeAssignmentStore{addErr: licenseadmin.ErrConcurrentModification},
			wantAdds:    4,
			wantRemoves: 0,
		},
		{
			name:        "unrevoke",
			command:     unrevokeCommandWithDeps,
			store:       &fakeAssignmentStore{removeErr: licenseadmin.ErrConcurrentModification},
			wantAdds:    0,
			wantRemoves: 4,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			auditPath := filepath.Join(t.TempDir(), tc.name+"-retry-exhausted-audit.jsonl")
			var out bytes.Buffer
			cmd := tc.command(func(c *cli.Context) (assignmentStore, error) {
				if got := c.String("region"); got != "us-west-2" {
					t.Fatalf("region flag = %q, want us-west-2", got)
				}
				if got := c.String("ac-assignments-table"); got != "table" {
					t.Fatalf("table flag = %q, want table", got)
				}
				return tc.store, nil
			}, &out)
			app := cli.NewApp()
			app.Writer = io.Discard
			app.ErrWriter = io.Discard
			app.ExitErrHandler = func(*cli.Context, error) {}
			app.Commands = []*cli.Command{cmd}

			err := app.Run([]string{
				"nhp-license-admin",
				tc.name,
				"--operator", "op",
				"--audit-file", auditPath,
				"--ac-id", " ac-1 ",
				"--pubkey", k1,
				"--region", "us-west-2",
				"--ac-assignments-table", "table",
			})
			if err == nil {
				t.Fatal("expected retry exhaustion")
			}
			if tc.store.adds != tc.wantAdds || tc.store.removes != tc.wantRemoves {
				t.Fatalf("calls add=%d remove=%d, want add=%d remove=%d", tc.store.adds, tc.store.removes, tc.wantAdds, tc.wantRemoves)
			}
			if tc.name == "revoke" {
				if tc.store.lastAddACID != "ac-1" || tc.store.lastAddKey != k1 {
					t.Fatalf("revoke args ac_id=%q key=%q, want ac-1/%s", tc.store.lastAddACID, tc.store.lastAddKey, k1)
				}
			} else if tc.store.lastRemACID != "ac-1" || tc.store.lastRemKey != k1 {
				t.Fatalf("unrevoke args ac_id=%q key=%q, want ac-1/%s", tc.store.lastRemACID, tc.store.lastRemKey, k1)
			}
			if out.Len() != 0 {
				t.Fatalf("retry exhaustion should not print success output, got %q", out.String())
			}
			rec := readACAuditRecord(t, auditPath)
			if rec.Action != tc.name || rec.Operator != "op" || rec.ACID != "ac-1" || rec.PubKey != k1 || rec.Changed || rec.Version != 0 || !strings.Contains(rec.Error, "aborted after 4 retries") {
				t.Fatalf("unexpected retry-exhaustion audit: %+v", rec)
			}
		})
	}
}

func TestAssignmentPubKeyMutationSetupAuditsClientOpenFailure(t *testing.T) {
	k1 := testKey(1)
	auditPath := filepath.Join(t.TempDir(), "setup-error-audit.jsonl")
	flags := flag.NewFlagSet("revoke", flag.ContinueOnError)
	flags.String("operator", "op", "")
	flags.String("audit-file", auditPath, "")
	flags.String("ac-id", "ac-1", "")
	flags.String("pubkey", k1, "")
	flags.String("region", "us-east-2", "")
	flags.String("endpoint", "", "")
	flags.String("ac-assignments-table", "", "")
	if err := flags.Parse(nil); err != nil {
		t.Fatal(err)
	}
	c := cli.NewContext(cli.NewApp(), flags, nil)

	_, _, _, _, err := assignmentPubKeyMutationSetupWithDeps(c, "revoke", openAssignmentStore)
	if err == nil {
		t.Fatal("expected setup error")
	}
	rec := readACAuditRecord(t, auditPath)
	if rec.Action != "revoke" || rec.Operator != "op" || rec.ACID != "ac-1" || rec.PubKey != k1 || rec.Changed || rec.Version != 0 || rec.Error == "" {
		t.Fatalf("unexpected setup error audit: %+v", rec)
	}
}

func TestAssignmentPubKeyMutationInputsAuditsMissingACID(t *testing.T) {
	k1 := testKey(1)
	auditPath := filepath.Join(t.TempDir(), "missing-ac-id-audit.jsonl")
	flags := flag.NewFlagSet("revoke", flag.ContinueOnError)
	flags.String("operator", "op", "")
	flags.String("audit-file", auditPath, "")
	flags.String("ac-id", "   ", "")
	flags.String("pubkey", k1, "")
	if err := flags.Parse(nil); err != nil {
		t.Fatal(err)
	}
	c := cli.NewContext(cli.NewApp(), flags, nil)

	_, _, _, err := assignmentPubKeyMutationInputs(c, "revoke")
	if err == nil || !strings.Contains(err.Error(), "--ac-id is required") {
		t.Fatalf("got %v, want missing ac-id error", err)
	}
	rec := readACAuditRecord(t, auditPath)
	if rec.Action != "revoke" || rec.Operator != "op" || rec.ACID != "" || rec.PubKey != k1 || rec.Changed || rec.Version != 0 || rec.Error == "" {
		t.Fatalf("unexpected missing ac-id audit: %+v", rec)
	}
}

func TestListRevokedCommandAction(t *testing.T) {
	k1, k2 := testKey(1), testKey(2)
	fs := &fakeAssignmentStore{
		assignment: &licenseadmin.ACAssignment{
			ACID:           "ac-1",
			Version:        9,
			RevokedPubKeys: []string{k2, k1},
		},
	}
	var out bytes.Buffer
	cmd := listRevokedCommandWithDeps(func(c *cli.Context) (assignmentReader, error) {
		if got := c.String("region"); got != "us-west-2" {
			t.Fatalf("region flag = %q, want us-west-2", got)
		}
		if got := c.String("ac-assignments-table"); got != "table" {
			t.Fatalf("table flag = %q, want table", got)
		}
		return fs, nil
	}, &out)
	app := cli.NewApp()
	app.Writer = io.Discard
	app.ErrWriter = io.Discard
	app.Commands = []*cli.Command{cmd}

	err := app.Run([]string{"nhp-license-admin", "list-revoked", "--ac-id", " ac-1 ", "--region", "us-west-2", "--ac-assignments-table", "table"})
	if err != nil {
		t.Fatalf("list-revoked action: %v", err)
	}
	if fs.gets != 1 || fs.lastGetACID != " ac-1 " || fs.adds != 0 || fs.removes != 0 {
		t.Fatalf("calls get=%d ac_id=%q add=%d remove=%d, want one read only", fs.gets, fs.lastGetACID, fs.adds, fs.removes)
	}
	got := out.String()
	if !strings.Contains(got, "ac_id: ac-1") || !strings.Contains(got, "version: 9") {
		t.Fatalf("output missing assignment header: %q", got)
	}
	i1 := strings.Index(got, k1)
	i2 := strings.Index(got, k2)
	if i1 < 0 || i2 < 0 || i1 > i2 {
		t.Fatalf("revoked_pubkeys should print in sorted order; output=%q", got)
	}

	fs = &fakeAssignmentStore{getErr: fmt.Errorf("%w: ac-missing", licenseadmin.ErrACAssignmentNotFound)}
	err = runListRevoked(context.Background(), fs, io.Discard, " ac-missing ")
	if !errors.Is(err, licenseadmin.ErrACAssignmentNotFound) {
		t.Fatalf("list missing assignment error = %v, want ErrACAssignmentNotFound", err)
	}
	if !strings.Contains(err.Error(), "assigned ACs with an empty denylist print revoked_pubkeys: none") {
		t.Fatalf("list missing assignment error lacks empty-denylist hint: %v", err)
	}
}

func TestPrintRevokedAssignmentSortsPubkeys(t *testing.T) {
	k1 := testKey(1)
	k2 := testKey(2)
	var out bytes.Buffer
	printRevokedAssignment(&out, &licenseadmin.ACAssignment{ACID: "ac-1", Version: 4, RevokedPubKeys: []string{k2, k1}})
	got := out.String()
	i1 := strings.Index(got, k1)
	i2 := strings.Index(got, k2)
	if i1 < 0 || i2 < 0 || i1 > i2 {
		t.Fatalf("pubkeys should print in sorted order; output=%q", got)
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

func TestBuildACAuditRecord(t *testing.T) {
	k1 := testKey(1)
	k2 := testKey(2)
	rec := buildACAuditRecord("revoke", "alice", "ac-1", k1, true, 4, []string{k2, k1}, "2026-06-06T00:00:00Z")
	if rec.Audit != "nhp-license-admin" || rec.Action != "revoke" || rec.Operator != "alice" || rec.ACID != "ac-1" || rec.PubKey != k1 || !rec.Changed || rec.Result != "mutated" || rec.Version != 4 || rec.TS != "2026-06-06T00:00:00Z" {
		t.Fatalf("unexpected record: %+v", rec)
	}
	if len(rec.RevokedPubKeys) != 2 || rec.RevokedPubKeys[0] != k1 || rec.RevokedPubKeys[1] != k2 {
		t.Fatalf("revoked_pubkeys should be sorted in audit record: %+v", rec.RevokedPubKeys)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"audit", "action", "operator", "ac_id", "pubkey", "changed", "result", "version", "revoked_pubkeys", "ts"} {
		if _, ok := m[k]; !ok {
			t.Errorf("AC audit JSON missing key %q", k)
		}
	}

	noopRec := buildACAuditRecord("unrevoke", "alice", "ac-1", k1, false, 4, []string{k1}, "2026-06-06T00:00:00Z")
	if noopRec.Result != "noop" {
		t.Fatalf("noop result = %q, want noop", noopRec.Result)
	}

	errRec := buildACErrorAuditRecord("revoke", "alice", "ac-1", " "+k1+" ", errors.New("missing row"), "2026-06-06T00:00:00Z")
	if errRec.PubKey != k1 || errRec.Changed || errRec.Result != "error" || errRec.Version != 0 || errRec.Error != "missing row" || len(errRec.RevokedPubKeys) != 0 {
		t.Fatalf("unexpected AC error audit record: %+v", errRec)
	}

	invalidRec := buildACErrorAuditRecord("revoke", "alice", "ac-1", " \nnot-a-key\n ", errors.New("bad key"), "2026-06-06T00:00:00Z")
	if !strings.HasPrefix(invalidRec.PubKey, "<invalid pubkey len=9 sha256=") || strings.Contains(invalidRec.PubKey, "not-a-key") {
		t.Fatalf("invalid pubkey audit should persist a bounded fingerprint, got %q", invalidRec.PubKey)
	}
}

func TestACAssignmentPropagationTTLTextMatchesServerDefaults(t *testing.T) {
	serverConfigPath := filepath.Join("..", "..", "server", "config.go")
	// Intentional fail-closed tripwire: if server defaults move to named
	// constants or expressions, update acAssignmentDefaultCacheTTL /
	// acAssignmentReassignmentCacheTTL and this parser together.
	if got := serverConfigIntAssignment(t, serverConfigPath, "cfg.Cache.DefaultTTL"); got != 60 {
		t.Fatalf("server default assignment cache TTL = %d, want 60; update acAssignmentDefaultCacheTTL and operator text", got)
	}
	if got := serverConfigIntAssignment(t, serverConfigPath, "cfg.Cache.ReassignmentTTL"); got != 5 {
		t.Fatalf("server reassignment cache TTL = %d, want 5; update acAssignmentReassignmentCacheTTL and operator text", got)
	}
	if acAssignmentDefaultCacheTTL != "60s" || acAssignmentReassignmentCacheTTL != "5s" {
		t.Fatalf("CLI TTL text = %s/%s, want 60s/5s", acAssignmentDefaultCacheTTL, acAssignmentReassignmentCacheTTL)
	}
}

func TestAdminEnvVarsPrecedeLegacyAliases(t *testing.T) {
	opFlag, ok := operatorFlag().(*cli.StringFlag)
	if !ok {
		t.Fatalf("operatorFlag type = %T, want *cli.StringFlag", operatorFlag())
	}
	if got, want := opFlag.EnvVars, []string{"NHP_ADMIN_OPERATOR", "NHP_LICENSE_ADMIN_OPERATOR"}; !slices.Equal(got, want) {
		t.Fatalf("operator env precedence = %v, want %v", got, want)
	}

	auditFlag, ok := auditFileFlag().(*cli.StringFlag)
	if !ok {
		t.Fatalf("auditFileFlag type = %T, want *cli.StringFlag", auditFileFlag())
	}
	if got, want := auditFlag.EnvVars, []string{"NHP_ADMIN_AUDIT_FILE", "NHP_LICENSE_ADMIN_AUDIT_FILE"}; !slices.Equal(got, want) {
		t.Fatalf("audit-file env precedence = %v, want %v", got, want)
	}
}

func TestRequireOperatorRejectsOversizedLabel(t *testing.T) {
	flags := flag.NewFlagSet("revoke", flag.ContinueOnError)
	flags.String("operator", " "+strings.Repeat("a", maxOperatorLabelBytes)+" ", "")
	c := cli.NewContext(cli.NewApp(), flags, nil)
	op, err := requireOperator(c)
	if err != nil {
		t.Fatalf("max-sized operator label should be accepted: %v", err)
	}
	if len(op) != maxOperatorLabelBytes {
		t.Fatalf("operator length after trim = %d, want %d", len(op), maxOperatorLabelBytes)
	}

	flags = flag.NewFlagSet("revoke", flag.ContinueOnError)
	flags.String("operator", strings.Repeat("a", maxOperatorLabelBytes+1), "")
	c = cli.NewContext(cli.NewApp(), flags, nil)
	if _, err := requireOperator(c); err == nil || !strings.Contains(err.Error(), "at most 256 bytes") {
		t.Fatalf("oversized operator error = %v, want max-size rejection", err)
	}
}

func TestConnectionFlagRegionUsage(t *testing.T) {
	licenseRegion, ok := connectionFlags()[0].(*cli.StringFlag)
	if !ok {
		t.Fatalf("license region flag type = %T, want *cli.StringFlag", connectionFlags()[0])
	}
	if strings.Contains(licenseRegion.Usage, "incident profile") {
		t.Fatalf("license region usage should not carry assignment incident hint: %q", licenseRegion.Usage)
	}

	assignmentRegion, ok := assignmentConnectionFlags()[0].(*cli.StringFlag)
	if !ok {
		t.Fatalf("assignment region flag type = %T, want *cli.StringFlag", assignmentConnectionFlags()[0])
	}
	if !strings.Contains(assignmentRegion.Usage, "incident profile") {
		t.Fatalf("assignment region usage missing incident profile hint: %q", assignmentRegion.Usage)
	}
}

func serverConfigIntAssignment(t *testing.T, path, target string) int {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var (
		got   int
		found bool
	)
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		if len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			if selectorPath(lhs) != target {
				continue
			}
			lit, ok := assign.Rhs[i].(*ast.BasicLit)
			if !ok || lit.Kind != token.INT {
				t.Fatalf("%s is not assigned an integer literal", target)
			}
			value, err := strconv.Atoi(lit.Value)
			if err != nil {
				t.Fatalf("parse %s: %v", target, err)
			}
			got = value
			found = true
			return false
		}
		return true
	})
	if !found {
		t.Fatalf("server config assignment %s not found", target)
	}
	return got
}

func selectorPath(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		prefix := selectorPath(e.X)
		if prefix == "" {
			return e.Sel.Name
		}
		return prefix + "." + e.Sel.Name
	default:
		return ""
	}
}

func readACAuditRecord(t *testing.T, path string) acAuditRecord {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one audit line, got %d: %q", len(lines), string(b))
	}
	var rec acAuditRecord
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
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

	calls = 0
	var exhausted error
	if err := withRetryOnExhaust(context.Background(), func() error {
		calls++
		return licenseadmin.ErrConcurrentModification
	}, func(err error) {
		exhausted = err
	}); err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if calls != 4 {
		t.Fatalf("calls = %d, want 4 (maxAttempts)", calls)
	}
	if exhausted == nil || !strings.Contains(exhausted.Error(), "aborted after 4 retries") {
		t.Fatalf("onExhaust saw %v, want retry exhaustion", exhausted)
	}

	calls = 0
	exhausted = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := withRetryOnExhaust(ctx, func() error {
		calls++
		return licenseadmin.ErrConcurrentModification
	}, func(err error) {
		exhausted = err
	}); err == nil {
		t.Fatal("expected error after interrupted retry backoff")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 before interrupted backoff", calls)
	}
	if exhausted == nil || !strings.Contains(exhausted.Error(), "interrupted during retry backoff") {
		t.Fatalf("onExhaust saw %v, want interrupted backoff", exhausted)
	}
}

func TestRetryBackoffAddsBoundedJitter(t *testing.T) {
	for attempt := 1; attempt <= 3; attempt++ {
		got := retryBackoff(attempt)
		min := time.Duration(attempt) * 50 * time.Millisecond
		max := min + 25*time.Millisecond
		if got < min || got >= max {
			t.Fatalf("retryBackoff(%d) = %s, want in [%s, %s)", attempt, got, min, max)
		}
	}
}
