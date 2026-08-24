package server

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// ========================================================================
// Policy kernel tests (verifyACPubkeyRevoked) — no UdpServer dependency.
// ========================================================================

// TestVerifyACPubkeyRevoked_Kernel pins the kernel's verdict table.
// The kernel is the authoritative reference for "what counts as a
// revocation hit." Reviewers should read this table BEFORE reading
// the implementation.
func TestVerifyACPubkeyRevoked_Kernel(t *testing.T) {
	pkA := testPubkeyB64(0x01)
	pkB := testPubkeyB64(0x02)
	pkC := testPubkeyB64(0x03)

	tests := []struct {
		name      string
		presented string
		revoked   []string
		want      acPubkeyRevokeVerdict
	}{
		{"empty-revoked-ok", pkA, nil, verdictACPubkeyRevokeOK},
		{"empty-slice-revoked-ok", pkA, []string{}, verdictACPubkeyRevokeOK},
		{"single-revoked-no-match-ok", pkB, []string{pkA}, verdictACPubkeyRevokeOK},
		{"single-revoked-match-revoked", pkA, []string{pkA}, verdictACPubkeyRevokeRevoked},
		// Multi-entry list: hit at any position rejects, miss accepts.
		// First-, middle-, and last-position hits all return the same
		// verdict — pin all three so a future "early-exit" or "skip
		// last entry" refactor surfaces here, not in the wild.
		{"multi-revoked-first-match-revoked", pkA, []string{pkA, pkB, pkC}, verdictACPubkeyRevokeRevoked},
		{"multi-revoked-middle-match-revoked", pkB, []string{pkA, pkB, pkC}, verdictACPubkeyRevokeRevoked},
		{"multi-revoked-last-match-revoked", pkC, []string{pkA, pkB, pkC}, verdictACPubkeyRevokeRevoked},
		{"multi-revoked-no-match-ok", "zzzz-not-on-list", []string{pkA, pkB, pkC}, verdictACPubkeyRevokeOK},
		// Defense-in-depth: an empty presented pubkey against any
		// non-empty revocation list must be OK (the empty string is
		// not a revoked entry — operators can't accidentally type ""
		// into RevokedPubKeys via legitimate tooling, but an attacker
		// who can present a zero-byte pubkey shouldn't be auto-
		// blackholed by an unrelated revocation entry). The
		// validateACLicense / responder pipeline upstream rejects
		// zero-length pubkeys before this kernel runs; this is a
		// belt-and-suspenders kernel-side guard.
		{"empty-presented-with-list-ok", "", []string{pkA, pkB}, verdictACPubkeyRevokeOK},
		// Empty-string entry in the revocation list: must NOT match a
		// presented pubkey of any non-empty value. Today's tooling
		// won't write empty strings, but a future console bug or hand-
		// edited DDB row could; the kernel must not turn that into a
		// fleet-wide blackhole.
		{"empty-entry-in-list-no-match-ok", pkA, []string{""}, verdictACPubkeyRevokeOK},
		// Both empty: still OK (empty-presented short-circuits the
		// scan above, but pin this so the order-of-checks doesn't
		// matter).
		{"both-empty-ok", "", []string{""}, verdictACPubkeyRevokeOK},
		// Empty presented + nil revoked list: hits the empty-presented
		// short-circuit BEFORE the empty-list check. Different code
		// path from "both-empty-ok" (nil vs []string{""}) — pinning
		// both fences the order-of-checks documented in the kernel.
		{"empty-presented-nil-list-ok", "", nil, verdictACPubkeyRevokeOK},
		{"empty-presented-empty-slice-ok", "", []string{}, verdictACPubkeyRevokeOK},
		// Whitespace-tolerance: a trailing newline or leading space
		// on either side must NOT prevent the match. The kernel's
		// TrimSpace on both sides is documented as defense-in-depth
		// against operators pasting pubkeys from a terminal / Slack.
		// Mirrors the same property pinned by
		// TestVerifyLicensePubkey_TrimWhitespace in license_pubkey_gate_test.go.
		{"trailing-newline-on-list-entry-revoked", pkA, []string{pkA + "\n"}, verdictACPubkeyRevokeRevoked},
		{"leading-space-on-presented-revoked", " " + pkA, []string{pkA}, verdictACPubkeyRevokeRevoked},
		{"trailing-tab-both-sides-revoked", pkA + "\t", []string{pkA + "\t"}, verdictACPubkeyRevokeRevoked},
		// Trim does NOT normalize URL-safe base64 to std base64 —
		// that's a real format divergence the admin tooling must catch.
		// This test pins the boundary: a URL-safe encoded pubkey is a
		// MISS even if the underlying bytes would decode to the same
		// key. Surfaces a future PR that "improves" the kernel by
		// decoding/re-encoding, which would hide bugs in the
		// provisioning pipeline rather than catch them.
		{"url-safe-encoding-not-normalized-ok", "AB-_", []string{"AB+/"}, verdictACPubkeyRevokeOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifyACPubkeyRevoked(tt.presented, tt.revoked)
			if got != tt.want {
				t.Errorf("verifyACPubkeyRevoked(%q, %v) = %v, want %v", tt.presented, tt.revoked, got, tt.want)
			}
		})
	}
}

// ========================================================================
// Side-effect wrapper tests (applyACPubkeyRevokeVerdict).
// ========================================================================

func TestApplyACPubkeyRevokeVerdict_PermitMode(t *testing.T) {
	pk := testPubkeyB64(0x01)
	tests := []struct {
		name       string
		verdict    acPubkeyRevokeVerdict
		wantMetric string // empty = no metric expected
	}{
		{"ok-no-metric", verdictACPubkeyRevokeOK, ""},
		{"revoked-metric", verdictACPubkeyRevokeRevoked, MetricACPubkeyRevoked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServerForGate(t)
			// Permit mode: acPubkeyRevokeVerifyRequire stays false.
			proceed, err := s.applyACPubkeyRevokeVerdict(tt.verdict, "ac-1", pk, 1, "10.0.0.1:62206")
			if !proceed {
				t.Errorf("permit mode: proceed=false for verdict=%v, want true", tt.verdict)
			}
			if err != nil {
				t.Errorf("permit mode: err=%v for verdict=%v, want nil", err, tt.verdict)
			}
			counters, _ := s.metrics.CountersForTest(t)
			if tt.wantMetric == "" {
				if c := counters[MetricACPubkeyRevoked]; c != 0 {
					t.Errorf("no-metric case: revoked counter=%v, want 0", c)
				}
			} else if c := counters[tt.wantMetric]; c != 1 {
				t.Errorf("%s counter=%v, want 1", tt.wantMetric, c)
			}
		})
	}
}

// TestApplyACPubkeyRevokeVerdict_StrictMode_FencesTheFix is THE
// attack-break test: a registration with a revoked pubkey under
// strict mode must be rejected with ErrACPubkeyRevoked.
func TestApplyACPubkeyRevokeVerdict_StrictMode_FencesTheFix(t *testing.T) {
	pk := testPubkeyB64(0x01)
	s := newTestServerForGate(t)
	s.acPubkeyRevokeVerifyRequire = true

	proceed, err := s.applyACPubkeyRevokeVerdict(verdictACPubkeyRevokeRevoked, "ac-1", pk, 1, "10.0.0.1:62206")
	if proceed {
		t.Error("strict mode: proceed=true for revoked verdict; #1507 attack break violated")
	}
	if !errors.Is(err, common.ErrACPubkeyRevoked) {
		t.Errorf("strict mode: err=%v, want ErrACPubkeyRevoked (52019)", err)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevoked]; c != 1 {
		t.Errorf("revoked counter=%v, want 1", c)
	}
}

func TestApplyACPubkeyRevokeVerdict_StrictMode_OK(t *testing.T) {
	pk := testPubkeyB64(0x01)
	s := newTestServerForGate(t)
	s.acPubkeyRevokeVerifyRequire = true

	proceed, err := s.applyACPubkeyRevokeVerdict(verdictACPubkeyRevokeOK, "ac-1", pk, 1, "10.0.0.1:62206")
	if !proceed {
		t.Errorf("OK verdict: proceed=false, want true")
	}
	if err != nil {
		t.Errorf("OK verdict: err=%v, want nil", err)
	}
}

// TestApplyACPubkeyRevokeVerdict_UnknownVerdict_FailsClosed fences
// the structural fail-closed property. Mirrors the same test in
// ac_pubkey_cap_gate_test.go / license_pubkey_gate_test.go. Also
// pins MetricACPubkeyRevokeGateBug — the paging signal that
// distinguishes a server-side dispatch-table bug from a real
// revocation reject (both return 52020 vs 52019, but only this
// metric surfaces the bug class for alarming).
func TestApplyACPubkeyRevokeVerdict_UnknownVerdict_FailsClosed(t *testing.T) {
	s := newTestServerForGate(t)
	var zero acPubkeyRevokeVerdict
	proceed, err := s.applyACPubkeyRevokeVerdict(zero, "ac-1", testPubkeyB64(0x01), 1, "10.0.0.1:62206")
	if proceed {
		t.Error("uninitialized verdict proceeded; fail-closed violated")
	}
	if !errors.Is(err, common.ErrACPubkeyRevokedInternal) {
		t.Errorf("uninitialized verdict err=%v, want ErrACPubkeyRevokedInternal (52020)", err)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokeGateBug]; c != 1 {
		t.Errorf("MetricACPubkeyRevokeGateBug counter=%v, want 1 (must fire on fail-closed default to give operators a paging signal)", c)
	}
}

func TestApplyACPubkeyRevokeVerdict_UnknownVerdict_ExtremeValue(t *testing.T) {
	s := newTestServerForGate(t)
	unregistered := acPubkeyRevokeVerdict(99)
	proceed, err := s.applyACPubkeyRevokeVerdict(unregistered, "ac-1", testPubkeyB64(0x01), 1, "10.0.0.1:62206")
	if proceed {
		t.Error("unregistered verdict proceeded; fail-closed violated")
	}
	if !errors.Is(err, common.ErrACPubkeyRevokedInternal) {
		t.Errorf("unregistered verdict err=%v, want ErrACPubkeyRevokedInternal", err)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokeGateBug]; c != 1 {
		t.Errorf("MetricACPubkeyRevokeGateBug counter=%v, want 1", c)
	}
}

// TestApplyACPubkeyRevokeVerdict_LogPrefixIncluded smoke-tests that
// the strict-mode reject path runs to completion and emits the
// metric. We don't capture log output (same rationale as the other
// gate tests) but ensures the code path doesn't panic on a long
// pubkey string.
func TestApplyACPubkeyRevokeVerdict_LogPrefixIncluded(t *testing.T) {
	s := newTestServerForGate(t)
	s.acPubkeyRevokeVerifyRequire = true
	longPk := strings.Repeat("A", 100) // longer than typical pubkey b64 (44 chars)
	proceed, err := s.applyACPubkeyRevokeVerdict(verdictACPubkeyRevokeRevoked, "ac-1", longPk, 1, "10.0.0.1:62206")
	if proceed {
		t.Error("strict mode: proceed=true for revoked; want false")
	}
	if !errors.Is(err, common.ErrACPubkeyRevoked) {
		t.Errorf("strict mode: err=%v, want ErrACPubkeyRevoked", err)
	}
}

// TestParseACPubkeyRevokeVerify_DelegatesToShared fences that the
// gate's thin env-parser wrapper uses the shared parsePermitStrictEnv
// grammar (typo rejection, accepted token set). Same shape as the
// matching test in ac_pubkey_cap_gate_test.go.
func TestParseACPubkeyRevokeVerify_DelegatesToShared(t *testing.T) {
	tests := []struct {
		raw     string
		wantOK  bool
		wantErr bool
	}{
		{"", false, false},
		{"true", true, false},
		{"false", false, false},
		{"1", true, false},
		{"0", false, false},
		{"yes", true, false},
		{"on", true, false},
		{"off", false, false},
		// Fail-closed on typo (operator typo regression). Same
		// rationale as the other gates' env parsers.
		{"enabled", false, true},
		{"enforce", false, true},
		{"strict", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := parseACPubkeyRevokeVerify(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("err=%v, wantErr=%v", err, tt.wantErr)
			}
			if got != tt.wantOK {
				t.Errorf("got=%v, want=%v", got, tt.wantOK)
			}
		})
	}
}

// ========================================================================
// Storage-error policy tests (evaluateACPubkeyRevokeVerdict).
//
// Storage transient errors must NOT escalate to a strict-mode reject.
// The lookup-err counter is the operator's only signal — these tests
// fence both the verdict outcome and the metric. Mirrors the F4
// storage-error policy tests in license_customer_gate_test.go and
// reuses the errStorageACAssignment mock from that file (same shape
// — both gates fail on a transient GetACAssignment error).
// ========================================================================

func TestEvaluateACPubkeyRevokeVerdict_StorageErrorReturnsOK(t *testing.T) {
	mem := NewMemoryStorage()
	storage := &errStorageACAssignment{
		MemoryStorage: mem,
		err:           errors.New("ddb: ProvisionedThroughputExceededException"),
	}
	s := newTestServerForLicenseGate(t, mem)
	s.storage = storage

	verdict := s.evaluateACPubkeyRevokeVerdict(context.Background(), "ac-1", testPubkeyB64(0x01), 1, "10.0.0.1:62206")
	if verdict != verdictACPubkeyRevokeOK {
		t.Errorf("storage error verdict=%v, want OK (skip-the-gate)", verdict)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokedLookupErr]; c != 1 {
		t.Errorf("lookup-err counter=%v, want 1", c)
	}
}

func TestEvaluateACPubkeyRevokeVerdict_CandidateAuthorityErrorRejects(t *testing.T) {
	mem := NewMemoryStorage()
	storage := &errStorageACAssignment{
		MemoryStorage: mem,
		err:           NewACAssignmentAuthorityError(errors.New("active authority unavailable")),
	}
	s := newTestServerForLicenseGate(t, mem)
	s.storage = storage

	verdict := s.evaluateACPubkeyRevokeVerdict(context.Background(), "ac-1", testPubkeyB64(0x01), 1, "10.0.0.1:62206")
	if verdict != verdictACPubkeyRevokeAuthorityUnavailable {
		t.Fatalf("candidate authority error verdict=%v, want fail-closed authority verdict", verdict)
	}
	proceed, rejectErr := s.applyACPubkeyRevokeVerdict(verdict, "ac-1", testPubkeyB64(0x01), 1, "10.0.0.1:62206")
	if proceed || !errors.Is(rejectErr, common.ErrServerACOpsFailed) {
		t.Fatalf("apply candidate authority verdict=(%v,%v), want rejection %v", proceed, rejectErr, common.ErrServerACOpsFailed)
	}
}

func TestEvaluateACPubkeyRevokeVerdict_NotFoundReturnsOK(t *testing.T) {
	mem := NewMemoryStorage()
	s := newTestServerForLicenseGate(t, mem)

	// No assignment exists → not-found path.
	verdict := s.evaluateACPubkeyRevokeVerdict(context.Background(), "ac-never-seen", testPubkeyB64(0x01), 1, "10.0.0.1:62206")
	if verdict != verdictACPubkeyRevokeOK {
		t.Errorf("not-found verdict=%v, want OK (TOFU first-registration)", verdict)
	}
	// Not-found is the legitimate first-registration path; must NOT
	// trip lookup-err counter (that's reserved for true storage flaps).
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokedLookupErr]; c != 0 {
		t.Errorf("not-found should not increment lookup-err counter, got %v", c)
	}
}

func TestEvaluateACPubkeyRevokeVerdict_AssignmentWithoutRevokedPubKeysReturnsOK(t *testing.T) {
	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{
		ACID:       "ac-1",
		CustomerID: "cust-A",
		Version:    1,
		// RevokedPubKeys deliberately nil — most common steady-state.
	})
	s := newTestServerForLicenseGate(t, mem)

	verdict := s.evaluateACPubkeyRevokeVerdict(context.Background(), "ac-1", testPubkeyB64(0x01), 1, "10.0.0.1:62206")
	if verdict != verdictACPubkeyRevokeOK {
		t.Errorf("no-revoked-list verdict=%v, want OK", verdict)
	}
}

// TestEvaluateACPubkeyRevokeVerdict_RevokedPubkeyHitFencesTheFix is
// THE end-to-end attack break test: a registration whose presented
// pubkey is on the revocation list must verdict Revoked.
func TestEvaluateACPubkeyRevokeVerdict_RevokedPubkeyHitFencesTheFix(t *testing.T) {
	pkRevoked := testPubkeyB64(0xAA)
	pkLegitimate := testPubkeyB64(0xBB)
	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{
		ACID:           "ac-1",
		CustomerID:     "cust-A",
		Version:        1,
		RevokedPubKeys: []string{pkRevoked},
	})
	s := newTestServerForLicenseGate(t, mem)

	// Revoked pubkey: the hit. Must verdict Revoked.
	verdict := s.evaluateACPubkeyRevokeVerdict(context.Background(), "ac-1", pkRevoked, 1, "10.0.0.1:62206")
	if verdict != verdictACPubkeyRevokeRevoked {
		t.Errorf("revoked pubkey verdict=%v, want Revoked — F5 attack break violated", verdict)
	}

	// Same acId, different pubkey: must NOT be falsely revoked.
	// Tests the "yank one AC instance, leave others alone" property —
	// the acceptance criterion in #1507 reads "a registration with a
	// non-revoked pubkey on the same acId is accepted."
	verdict2 := s.evaluateACPubkeyRevokeVerdict(context.Background(), "ac-1", pkLegitimate, 1, "10.0.0.1:62206")
	if verdict2 != verdictACPubkeyRevokeOK {
		t.Errorf("non-revoked pubkey on same acId verdict=%v, want OK — false-positive lockout", verdict2)
	}
}

// nilNilStorage is a MemoryStorage subclass that returns the
// contract-violating (nil, nil) tuple for GetACAssignment. The
// StorageBackend contract is "non-nil + nil err" or "nil + ErrNotFound,"
// so this branch is unreachable for compliant backends — kept as
// belt-and-suspenders defense-in-depth so a future backend bug
// surfaces as a benign skip-the-gate rather than a nil-deref panic
// on assignment.RevokedPubKeys.
type nilNilStorage struct {
	*MemoryStorage
}

func (e *nilNilStorage) GetACAssignment(ctx context.Context, acID string) (*ACAssignment, error) {
	return nil, nil
}

// TestEvaluateACPubkeyRevokeVerdict_BackendReturnsNilNilDegradesToOK
// pins the defense-in-depth branch at evaluateACPubkeyRevokeVerdict's
// `assignment == nil` guard. A compliant backend can never produce
// (nil, nil), but a future backend bug now trips a benign skip-the-
// gate instead of a nil-deref panic on assignment.RevokedPubKeys.
func TestEvaluateACPubkeyRevokeVerdict_BackendReturnsNilNilDegradesToOK(t *testing.T) {
	mem := NewMemoryStorage()
	storage := &nilNilStorage{MemoryStorage: mem}
	s := newTestServerForLicenseGate(t, mem)
	s.storage = storage

	verdict := s.evaluateACPubkeyRevokeVerdict(context.Background(), "ac-1", testPubkeyB64(0x01), 1, "10.0.0.1:62206")
	if verdict != verdictACPubkeyRevokeOK {
		t.Errorf("(nil, nil) verdict=%v, want OK (defense-in-depth)", verdict)
	}
	// (nil, nil) is NOT a storage error — it's a contract violation
	// — so the lookup-err counter should NOT fire. Pin separately so
	// a future refactor that decides to count contract violations as
	// lookup errors makes the trade-off visible.
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokedLookupErr]; c != 0 {
		t.Errorf("(nil, nil) emitted lookup-err counter %v, want 0 (contract violation, not storage flap)", c)
	}
}

// TestEvaluateACPubkeyRevokeVerdict_NoStorageReturnsOK covers the
// non-cloud (etcd / static) deployment path: s.storage is nil, the
// gate is bypassed.
func TestEvaluateACPubkeyRevokeVerdict_NoStorageReturnsOK(t *testing.T) {
	s := newTestServerForGate(t)
	verdict := s.evaluateACPubkeyRevokeVerdict(context.Background(), "ac-1", testPubkeyB64(0x01), 1, "10.0.0.1:62206")
	if verdict != verdictACPubkeyRevokeOK {
		t.Errorf("no-storage verdict=%v, want OK", verdict)
	}
}

// TestEvaluateACPubkeyRevokeVerdict_LongListEmitsOversizeMetric pins
// the runaway-admin-tool sanity signal: when an ACAssignment's
// RevokedPubKeys list crosses acPubkeyRevokeListLengthWarn,
// MetricACPubkeyRevokeListOversize fires once per evaluation and
// the firstLongRevokeListLog sync.Once anchor fires once per
// process. Without this fence, a metric-name typo would silently
// disable the only standing dashboard signal for "operator's CLI is
// appending without dedupe" / "F5 is being misused as a license-
// wide kill switch."
func TestEvaluateACPubkeyRevokeVerdict_LongListEmitsOversizeMetric(t *testing.T) {
	const acId = "ac-1547-oversize"
	mem := NewMemoryStorage()
	revoked := make([]string, acPubkeyRevokeListLengthWarn)
	for i := range revoked {
		revoked[i] = testPubkeyB64(byte(i + 1))
	}
	mem.PutACAssignment(&ACAssignment{
		ACID:           acId,
		Version:        1,
		RevokedPubKeys: revoked,
	})
	s := newTestServerForLicenseGate(t, mem)

	// First evaluation fires the counter and consumes the once-per-
	// process log anchor. Verdict is OK because the presented pubkey
	// (0xFF) is NOT in the list (entries are 0x01..0x32).
	verdict := s.evaluateACPubkeyRevokeVerdict(context.Background(), acId, testPubkeyB64(0xFF), 1, "10.0.0.1:62206")
	if verdict != verdictACPubkeyRevokeOK {
		t.Errorf("first call: verdict=%v, want OK (presented not in list)", verdict)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokeListOversize]; c != 1 {
		t.Errorf("after one long-list evaluation: %s=%v, want 1", MetricACPubkeyRevokeListOversize, c)
	}

	// Second evaluation aggregates the counter. The log anchor stays
	// at first-fire (sync.Once is global to the test binary; if a
	// previous test already consumed it, that's still the documented
	// shared-testability behavior — we only assert the counter side
	// here because that's the operator-grade invariant).
	verdict = s.evaluateACPubkeyRevokeVerdict(context.Background(), acId, testPubkeyB64(0xFE), 2, "10.0.0.1:62206")
	if verdict != verdictACPubkeyRevokeOK {
		t.Errorf("second call: verdict=%v, want OK", verdict)
	}
	counters, _ = s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokeListOversize]; c != 2 {
		t.Errorf("after two long-list evaluations: %s=%v, want 2 (counter must aggregate)", MetricACPubkeyRevokeListOversize, c)
	}
}

// TestEvaluateACPubkeyRevokeVerdict_BelowWarnDoesNotEmitOversize
// pins the boundary: a list one below acPubkeyRevokeListLengthWarn
// must not fire the oversize signal. Without this, an off-by-one
// regression on the threshold would either silence the metric in
// production or spam it in steady state.
func TestEvaluateACPubkeyRevokeVerdict_BelowWarnDoesNotEmitOversize(t *testing.T) {
	const acId = "ac-1547-below-warn"
	mem := NewMemoryStorage()
	revoked := make([]string, acPubkeyRevokeListLengthWarn-1)
	for i := range revoked {
		revoked[i] = testPubkeyB64(byte(i + 1))
	}
	mem.PutACAssignment(&ACAssignment{ACID: acId, Version: 1, RevokedPubKeys: revoked})
	s := newTestServerForLicenseGate(t, mem)

	_ = s.evaluateACPubkeyRevokeVerdict(context.Background(), acId, testPubkeyB64(0xFF), 1, "10.0.0.1:62206")
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokeListOversize]; c != 0 {
		t.Errorf("below-warn list (len=%d, threshold=%d): %s=%v, want 0",
			len(revoked), acPubkeyRevokeListLengthWarn, MetricACPubkeyRevokeListOversize, c)
	}
}

// revokedListWithHead returns a RevokedPubKeys list of length n whose
// first entry is head and whose remaining entries are distinct filler
// base64 pubkeys (none equal to head). Used by the #1547 hard-cap tests
// to build lists longer than 255 entries without the byte-wrap
// collisions a testPubkeyB64(byte(i)) loop would hit.
func revokedListWithHead(head string, n int) []string {
	out := make([]string, 0, n)
	out = append(out, head)
	// 3-byte fillers can never equal head (the base64 of a 32-byte
	// testPubkey), and (byte(i), byte(i>>8)) is unique for i in 1..n.
	for i := 1; i < n; i++ {
		out = append(out, base64.StdEncoding.EncodeToString([]byte{byte(i), byte(i >> 8), 0xEE}))
	}
	return out
}

// TestEvaluateACPubkeyRevokeVerdict_OverCapSkipsScanAndAccepts is THE
// availability-first trade-off fence for the #1547 hard cap. A list
// past acPubkeyRevokeListLengthMax skips the linear scan and ACCEPTS
// the registration — even when the presented pubkey is on the list. A
// reviewer changing the cap policy to fail-closed (reject) must update
// this test and consciously accept that a single runaway acId can wedge
// its own registrations shut.
func TestEvaluateACPubkeyRevokeVerdict_OverCapSkipsScanAndAccepts(t *testing.T) {
	const acId = "ac-1547-over-cap"
	pkRevoked := testPubkeyB64(0xAA)
	// Head entry is the revoked pubkey, so without the cap this would
	// verdict Revoked. Length is one past the cap.
	revoked := revokedListWithHead(pkRevoked, acPubkeyRevokeListLengthMax+1)
	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{ACID: acId, Version: 1, RevokedPubKeys: revoked})
	s := newTestServerForLicenseGate(t, mem)

	verdict := s.evaluateACPubkeyRevokeVerdict(context.Background(), acId, pkRevoked, 1, "10.0.0.1:62206")
	if verdict != verdictACPubkeyRevokeOK {
		t.Errorf("over-cap list (len=%d, cap=%d), presented pubkey ON the list: verdict=%v, want OK (scan skipped, availability-first)",
			len(revoked), acPubkeyRevokeListLengthMax, verdict)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokeListCapped]; c != 1 {
		t.Errorf("%s=%v, want 1 (cap exceeded)", MetricACPubkeyRevokeListCapped, c)
	}
	// A capped list is also oversize, so the pre-existing dashboard
	// alarm must still fire — the cap escalation does not silence it.
	if c := counters[MetricACPubkeyRevokeListOversize]; c != 1 {
		t.Errorf("%s=%v, want 1 (capped list must still trip the oversize alarm)", MetricACPubkeyRevokeListOversize, c)
	}
}

// TestEvaluateACPubkeyRevokeVerdict_AtCapStillEnforces pins the boundary:
// a list of exactly acPubkeyRevokeListLengthMax entries is still scanned
// and enforced. Together with the over-cap test this fences the off-by-
// one: 256 enforces, 257 skips.
func TestEvaluateACPubkeyRevokeVerdict_AtCapStillEnforces(t *testing.T) {
	const acId = "ac-1547-at-cap"
	pkRevoked := testPubkeyB64(0xAA)
	revoked := revokedListWithHead(pkRevoked, acPubkeyRevokeListLengthMax)
	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{ACID: acId, Version: 1, RevokedPubKeys: revoked})
	s := newTestServerForLicenseGate(t, mem)

	verdict := s.evaluateACPubkeyRevokeVerdict(context.Background(), acId, pkRevoked, 1, "10.0.0.1:62206")
	if verdict != verdictACPubkeyRevokeRevoked {
		t.Errorf("at-cap list (len=%d == cap): verdict=%v, want Revoked (still enforced at the boundary)", len(revoked), verdict)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokeListCapped]; c != 0 {
		t.Errorf("%s=%v, want 0 (at the cap, not past it)", MetricACPubkeyRevokeListCapped, c)
	}
	if c := counters[MetricACPubkeyRevokeListOversize]; c != 1 {
		t.Errorf("%s=%v, want 1 (at-cap list is oversize)", MetricACPubkeyRevokeListOversize, c)
	}
}

// ========================================================================
// Storage encoding tests (DDB round-trip).
//
// The dynamodbav `,stringset` tag on RevokedPubKeys is load-bearing:
// the operator runbook in #1507's PR description writes the field as
// String Set (SS) using `ADD revoked_pubkeys :pk` update expressions.
// If a future refactor drops `,stringset`, the field marshals as List
// (L) on writes from Go but the runbook keeps producing SS rows —
// the read path then fails to unmarshal a SS row into the L-typed
// field, and an operator who revoked a pubkey via the runbook would
// see a silent UnmarshalTypeError on every subsequent registration.
//
// Cheap to fence at unit-test level via attributevalue.MarshalMap +
// type assertion. Mirrors TestLicenseStructDynamoDBAV_RoundTripsBoundPubKeys
// in license_pubkey_gate_test.go.
// ========================================================================

func TestACAssignment_RevokedPubKeys_RoundTripsAsStringSet(t *testing.T) {
	pk1 := testPubkeyB64(0x01)
	pk2 := testPubkeyB64(0x02)
	original := ACAssignment{
		ACID:           "ac-1",
		CustomerID:     "cust-A",
		Version:        1,
		RevokedPubKeys: []string{pk1, pk2},
	}
	item, err := attributevalue.MarshalMap(&original)
	if err != nil {
		t.Fatalf("MarshalMap: %v", err)
	}

	// THE INVARIANT: on-wire encoding is SS, not L. Operator runbooks
	// using `ADD revoked_pubkeys :pk` with `:pk` typed `SS` round-trip
	// cleanly only when the Go side also marshals as SS.
	attr, ok := item["revoked_pubkeys"]
	if !ok {
		t.Fatalf("revoked_pubkeys missing from DDB item, keys: %v", item)
	}
	ss, ok := attr.(*types.AttributeValueMemberSS)
	if !ok {
		t.Fatalf("revoked_pubkeys encoded as %T, want *AttributeValueMemberSS (the ,stringset tag must produce SS, not L)", attr)
	}
	wantSet := map[string]bool{pk1: true, pk2: true}
	if len(ss.Value) != len(wantSet) {
		t.Errorf("revoked_pubkeys SS size=%d, want %d", len(ss.Value), len(wantSet))
	}
	for _, v := range ss.Value {
		if !wantSet[v] {
			t.Errorf("revoked_pubkeys SS contains unexpected value %q", v)
		}
	}

	// Read-back must unmarshal cleanly into the same field type AND
	// preserve the exact pubkey values. SS is unordered so we
	// compare as a set.
	var roundtrip ACAssignment
	if err := attributevalue.UnmarshalMap(item, &roundtrip); err != nil {
		t.Fatalf("UnmarshalMap: %v", err)
	}
	if len(roundtrip.RevokedPubKeys) != len(wantSet) {
		t.Errorf("roundtrip RevokedPubKeys size=%d, want %d", len(roundtrip.RevokedPubKeys), len(wantSet))
	}
	got := make(map[string]bool, len(roundtrip.RevokedPubKeys))
	for _, v := range roundtrip.RevokedPubKeys {
		got[v] = true
	}
	for want := range wantSet {
		if !got[want] {
			t.Errorf("roundtrip RevokedPubKeys missing %q (got: %v)", want, roundtrip.RevokedPubKeys)
		}
	}

	// Empty-shape behavior. DDB rejects empty SS attributes
	// (`Value: []string{}` would fail the write), so the SDK's
	// `,stringset,omitempty` encodes the two empty shapes
	// differently — verified empirically against
	// aws-sdk-go-v2/feature/dynamodb/attributevalue v1.15.24:
	//
	//   - nil slice         → attribute OMITTED entirely.
	//   - non-nil []string{} → attribute PRESENT as NULL (not empty SS).
	//
	// Both are DDB-accepted on write. The asymmetry isn't load-
	// bearing for production code (autoAssignAC constructs
	// ACAssignment with an unset RevokedPubKeys field, i.e. nil),
	// but pin both shapes so a future SDK upgrade or tag-edit that
	// silently flips an empty slice to `&AttributeValueMemberSS{Value: []string{}}`
	// (which DDB rejects) trips here at build time instead of at
	// the next operator-driven SaveACAssignment.
	t.Run("nil slice omits attribute", func(t *testing.T) {
		empty := ACAssignment{ACID: "ac-2", Version: 1}
		emptyItem, err := attributevalue.MarshalMap(&empty)
		if err != nil {
			t.Fatalf("MarshalMap: %v", err)
		}
		if _, ok := emptyItem["revoked_pubkeys"]; ok {
			t.Errorf("omitempty violated: nil slice serialized into DDB item")
		}
	})
	t.Run("non-nil empty slice encoded as NULL", func(t *testing.T) {
		empty := ACAssignment{ACID: "ac-3", Version: 1, RevokedPubKeys: []string{}}
		emptyItem, err := attributevalue.MarshalMap(&empty)
		if err != nil {
			t.Fatalf("MarshalMap: %v", err)
		}
		attr, ok := emptyItem["revoked_pubkeys"]
		if !ok {
			t.Fatal("expected revoked_pubkeys present (as NULL) for non-nil empty slice")
		}
		if _, isNull := attr.(*types.AttributeValueMemberNULL); !isNull {
			// If this fires as *AttributeValueMemberSS{Value: []string{}},
			// the DDB write would FAIL — the SDK's empty-slice
			// handling has regressed and we need to either switch to
			// `,nullempty` or normalize empty-to-nil before save.
			t.Errorf("empty slice encoded as %T, want *AttributeValueMemberNULL (an empty SS would fail DDB write)", attr)
		}
	})
}

// TestACAssignment_Clone_NormalizesEmptyRevokedPubKeysToNil pins
// the construction-contract normalization in Clone(): an input
// with []string{} (which the SDK would encode as NULL on write)
// must Clone to nil so the field doc's "callers MUST use nil for
// the empty case" holds across cache reads and defensive copies.
func TestACAssignment_Clone_NormalizesEmptyRevokedPubKeysToNil(t *testing.T) {
	original := &ACAssignment{
		ACID:           "ac-1",
		Version:        1,
		RevokedPubKeys: []string{},
	}
	clone := original.Clone()
	if clone.RevokedPubKeys != nil {
		t.Errorf("Clone of empty []string{} produced %#v, want nil", clone.RevokedPubKeys)
	}
}
