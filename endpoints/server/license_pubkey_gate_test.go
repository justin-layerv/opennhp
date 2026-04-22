package server

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// newTestServerForLicenseGate wires an UdpServer with metrics +
// storage + cloud-mode storageConfig. Use ONLY for integration
// tests that call validateACLicense (which reads storage via
// GetLicense). For side-effect tests that call
// applyLicensePubkeyVerdict directly (no storage dependency), use
// the lighter newTestServerForGate from knock_headertype_gate_test.go.
func newTestServerForLicenseGate(t *testing.T, storage *MemoryStorage) *UdpServer {
	t.Helper()
	return &UdpServer{
		metrics:       metrics.NewPublisherForTest(t),
		storage:       storage,
		storageConfig: &StorageConfig{Backend: StorageBackendDynamoDB},
	}
}

// testPubkey returns a deterministic 32-byte pubkey labeled by seed.
// The noise responder feeds ppd.RemotePubKey with the raw 32-byte
// curve25519 pubkey; validateACLicense base64-encodes it before
// passing to the gate. Tests that need the base64 form use
// testPubkeyB64 directly to avoid reproducing the encoding logic.
func testPubkey(seed byte) []byte {
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = seed
	}
	return pk
}

func testPubkeyB64(seed byte) string {
	return base64.StdEncoding.EncodeToString(testPubkey(seed))
}

// ========================================================================
// Policy kernel tests (verifyLicensePubkey) — no UdpServer dependency.
// ========================================================================

// TestVerifyLicensePubkey_Kernel pins the kernel's verdict table. The
// strict flag is NOT an input here because the kernel doesn't consult
// it — that's applyLicensePubkeyVerdict's job. Keeping the kernel
// input-small makes this table the authoritative policy reference for
// future readers.
func TestVerifyLicensePubkey_Kernel(t *testing.T) {
	pkA := testPubkeyB64(0x01)
	pkB := testPubkeyB64(0x02)
	pkC := testPubkeyB64(0x03)

	tests := []struct {
		name      string
		presented string
		allow     []string
		want      licensePubkeyVerdict
	}{
		{"empty-allowlist-unbound", pkA, nil, verdictLicenseUnbound},
		{"empty-slice-allowlist-unbound", pkA, []string{}, verdictLicenseUnbound},
		{"single-pubkey-match-ok", pkA, []string{pkA}, verdictLicenseOK},
		{"single-pubkey-miss-mismatch", pkB, []string{pkA}, verdictLicenseMismatch},
		{"multi-pubkey-first-match-ok", pkA, []string{pkA, pkB, pkC}, verdictLicenseOK},
		{"multi-pubkey-middle-match-ok", pkB, []string{pkA, pkB, pkC}, verdictLicenseOK},
		{"multi-pubkey-last-match-ok", pkC, []string{pkA, pkB, pkC}, verdictLicenseOK},
		{"multi-pubkey-miss-mismatch", "zzzz-not-in-list", []string{pkA, pkB, pkC}, verdictLicenseMismatch},
		// Defense-in-depth: empty presented pubkey with a non-empty
		// allowlist must be mismatch (never OK), even though
		// validateACLicense's caller always populates ppd.RemotePubKey.
		{"empty-presented-with-allowlist-mismatch", "", []string{pkA}, verdictLicenseMismatch},
		// Canonical-encoding normalization (#1261 cr round 3 #1):
		// an operator pasting a pubkey from a terminal or Slack
		// can easily trail a \n or leading space. TrimSpace on
		// both sides prevents silent lockout of a legitimate AC
		// indistinguishable from an attack.
		{"trailing-newline-in-allowlist-still-matches", pkA, []string{pkA + "\n"}, verdictLicenseOK},
		{"leading-space-in-allowlist-still-matches", pkA, []string{" " + pkA}, verdictLicenseOK},
		{"trailing-crlf-in-allowlist-still-matches", pkA, []string{pkA + "\r\n"}, verdictLicenseOK},
		{"trailing-newline-in-presented-still-matches", pkA + "\n", []string{pkA}, verdictLicenseOK},
		// Presented-empty case after trim: whitespace-only presented
		// must NOT match an allowlist entry that is also whitespace —
		// the post-trim empty-vs-anything check fires.
		{"whitespace-only-presented-mismatch", "   ", []string{pkA}, verdictLicenseMismatch},
		// NOT normalized: URL-safe vs std base64, padded vs unpadded.
		// These are genuine format divergences — the docstring on
		// License.BoundPubKeys + admin tooling in #1262 are
		// responsible for rejecting them at write-time, not the
		// kernel at read-time. Using testPubkeyB64(0xFB) here
		// because a byte of 0xFB encodes to +/v7 (contains both +
		// and /), so URL-safe conversion actually produces a
		// different string.
		{
			"urlsafe-base64-mismatch-intentionally",
			strings.ReplaceAll(strings.ReplaceAll(testPubkeyB64(0xFB), "+", "-"), "/", "_"),
			[]string{testPubkeyB64(0xFB)},
			verdictLicenseMismatch,
		},
		// Provisioning-bug edge case (#1261 cr round 7 #4): an admin
		// accidentally stores a whitespace-only entry. len(allow)!=0
		// skips the Unbound shortcut, then the entry trims to "",
		// which fails to match the non-empty presented. Safer than
		// OK — a whitespace-only entry is a provisioning bug and
		// the mismatch signal surfaces it via
		// MetricLicensePubkeyMismatch. Admin tooling in #1262
		// should reject whitespace-only entries at write-time.
		{"whitespace-only-allowlist-entry-mismatch", pkA, []string{"   "}, verdictLicenseMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifyLicensePubkey(tt.presented, tt.allow)
			if got != tt.want {
				t.Errorf("verifyLicensePubkey(%q, %v) = %v, want %v", tt.presented, tt.allow, got, tt.want)
			}
		})
	}
}

// ========================================================================
// Side-effect wrapper tests (applyLicensePubkeyVerdict) — assert
// proceed+error choice and metric emission. Log output is not asserted
// (see #1154 gate test file for rationale — separate capture framework
// is follow-up scope).
// ========================================================================

// TestApplyLicensePubkeyVerdict_PermitMode fences that permit mode
// accepts all non-OK verdicts (that's the whole point of permit mode)
// while still emitting the right metric for each.
func TestApplyLicensePubkeyVerdict_PermitMode(t *testing.T) {
	pk := testPubkeyB64(0x01)
	tests := []struct {
		name       string
		verdict    licensePubkeyVerdict
		wantMetric string // empty = no metric expected
	}{
		{"ok-no-metric", verdictLicenseOK, ""},
		{"unbound-metric", verdictLicenseUnbound, MetricLicensePubkeyUnbound},
		{"mismatch-metric", verdictLicenseMismatch, MetricLicensePubkeyMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// applyLicensePubkeyVerdict has no storage dependency —
			// reuse the #1154 gate's lightweight helper rather than
			// building a cloud-mode-shaped UdpServer for a side-effect
			// test that never reads storage.
			s := newTestServerForGate(t)
			// Permit mode: licensePubkeyVerifyRequire stays false.
			proceed, err := s.applyLicensePubkeyVerdict(tt.verdict, "ac-1", pk, 1, "10.0.0.1:62206", "keypref")
			if !proceed {
				t.Errorf("permit mode: proceed=false for verdict=%v, want proceed=true", tt.verdict)
			}
			if err != nil {
				t.Errorf("permit mode: rejectErr=%v for verdict=%v, want nil", err, tt.verdict)
			}
			counters, _ := s.metrics.CountersForTest(t)
			if tt.wantMetric == "" {
				if c := counters[MetricLicensePubkeyUnbound]; c != 0 {
					t.Errorf("no-metric case: unbound counter=%v, want 0", c)
				}
				if c := counters[MetricLicensePubkeyMismatch]; c != 0 {
					t.Errorf("no-metric case: mismatch counter=%v, want 0", c)
				}
			} else if c := counters[tt.wantMetric]; c != 1 {
				t.Errorf("%s counter=%v, want 1", tt.wantMetric, c)
			}
		})
	}
}

// TestApplyLicensePubkeyVerdict_StrictMode fences that strict mode
// maps each non-OK verdict to its distinct reject error and refuses
// to proceed. The distinct-error property is important because it
// lets operators diagnose an incident from the agent log alone
// without grepping the server metrics.
func TestApplyLicensePubkeyVerdict_StrictMode(t *testing.T) {
	pk := testPubkeyB64(0x01)
	tests := []struct {
		name       string
		verdict    licensePubkeyVerdict
		wantErr    *common.Error
		wantMetric string
	}{
		{"ok-proceeds", verdictLicenseOK, nil, ""},
		{"unbound-rejects-52013", verdictLicenseUnbound, common.ErrLicensePubkeyUnbound, MetricLicensePubkeyUnbound},
		{"mismatch-rejects-52012", verdictLicenseMismatch, common.ErrLicensePubkeyMismatch, MetricLicensePubkeyMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServerForGate(t)
			s.licensePubkeyVerifyRequire = true
			proceed, err := s.applyLicensePubkeyVerdict(tt.verdict, "ac-1", pk, 1, "10.0.0.1:62206", "keypref")
			if tt.wantErr == nil {
				if !proceed {
					t.Errorf("OK verdict: proceed=false, want true")
				}
				if err != nil {
					t.Errorf("OK verdict: err=%v, want nil", err)
				}
			} else {
				if proceed {
					t.Errorf("strict: proceed=true for verdict=%v, want false", tt.verdict)
				}
				if err != tt.wantErr {
					t.Errorf("strict: err=%v, want %v", err, tt.wantErr)
				}
			}
			if tt.wantMetric != "" {
				counters, _ := s.metrics.CountersForTest(t)
				if c := counters[tt.wantMetric]; c != 1 {
					t.Errorf("%s counter=%v, want 1", tt.wantMetric, c)
				}
			}
		})
	}
}

// TestApplyLicensePubkeyVerdict_UnknownVerdict_FailsClosed fences the
// structural fail-closed property: an uninitialized verdict (Go
// zero value, underscored in the const block) MUST reject with
// ErrLicensePubkeyInternal rather than silently accept. Mirrors the
// #1154 gate's zero-value test.
func TestApplyLicensePubkeyVerdict_UnknownVerdict_FailsClosed(t *testing.T) {
	s := newTestServerForGate(t)
	var zero licensePubkeyVerdict // Go zero value, unnamed in the iota block
	proceed, err := s.applyLicensePubkeyVerdict(zero, "ac-1", testPubkeyB64(0x01), 1, "10.0.0.1:62206", "keypref")
	if proceed {
		t.Error("uninitialized verdict proceeded; fail-closed violated")
	}
	if err != common.ErrLicensePubkeyInternal {
		t.Errorf("uninitialized verdict err=%v, want ErrLicensePubkeyInternal (52014)", err)
	}
}

// TestApplyLicensePubkeyVerdict_UnknownVerdict_ExtremeValue fences
// the same fail-closed property for a positive-but-undefined
// verdict value (e.g., a future PR adds verdictLicenseX as iota+4
// but forgets to register it in the switch). The structural
// protection from the zero-value test doesn't cover this case;
// this test does.
func TestApplyLicensePubkeyVerdict_UnknownVerdict_ExtremeValue(t *testing.T) {
	s := newTestServerForGate(t)
	unregistered := licensePubkeyVerdict(99)
	proceed, err := s.applyLicensePubkeyVerdict(unregistered, "ac-1", testPubkeyB64(0x01), 1, "10.0.0.1:62206", "keypref")
	if proceed {
		t.Error("unregistered verdict proceeded; fail-closed violated")
	}
	if err != common.ErrLicensePubkeyInternal {
		t.Errorf("unregistered verdict err=%v, want ErrLicensePubkeyInternal", err)
	}
}

// ========================================================================
// Env-var parser tests — shared parsePermitStrictEnv grammar. Covered
// more exhaustively in permit_strict_env_test.go; this one just fences
// that the gate's thin wrapper is wired up.
// ========================================================================

func TestParseLicensePubkeyVerify_DelegatesToShared(t *testing.T) {
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
		{"no", false, false},
		{"on", true, false},
		{"off", false, false},
		// Typos fail-closed: the shared parser rejects anything
		// outside the accepted grammar. This is the property that
		// prevents a deployment typo from silently leaving the gate
		// in permit mode forever.
		{"enabled", false, true},
		{"enforce", false, true},
		{"strict", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := parseLicensePubkeyVerify(tt.raw)
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
// Integration tests via validateACLicense — the public surface of the
// gate. Covers the real attack scenarios end-to-end.
// ========================================================================

// makeLicenseFixture stores a test license and returns the key to
// present. The bcrypt hash is computed inside so tests don't have to
// call generateBcryptHash themselves.
func makeLicenseFixture(t *testing.T, storage *MemoryStorage, bound []string) string {
	t.Helper()
	licenseKey := "test-license-" + t.Name()
	license := &License{
		CustomerID:     "cust-1",
		ResourceID:     "console",
		Active:         true,
		Tier:           "pro",
		ExpiresAt:      time.Now().Add(24 * time.Hour).Unix(),
		LicenseKeyHash: generateBcryptHash(licenseKey),
		BoundPubKeys:   bound,
	}
	storage.PutLicenseWithKey(license, licenseKey)
	return licenseKey
}

// ppdWithPubkey builds a minimal PacketParserData carrying the given
// raw pubkey. validateACLicense reads ppd.RemotePubKey and base64-
// encodes it before passing to the gate — mirrors the production
// path where the noise responder writes the raw 32-byte key.
func ppdWithPubkey(pk []byte) *core.PacketParserData {
	return &core.PacketParserData{RemotePubKey: pk}
}

// TestValidateACLicense_PubkeyBound_Match: legitimate AC presents a
// pubkey that IS on the license's BoundPubKeys allowlist. Must
// succeed under both permit and strict mode — this is the golden
// path for a post-provisioning deployment.
func TestValidateACLicense_PubkeyBound_Match(t *testing.T) {
	for _, strict := range []bool{false, true} {
		name := "permit"
		if strict {
			name = "strict"
		}
		t.Run(name, func(t *testing.T) {
			storage := NewMemoryStorage()
			s := newTestServerForLicenseGate(t, storage)
			s.licensePubkeyVerifyRequire = strict
			licenseKey := makeLicenseFixture(t, storage, []string{testPubkeyB64(0x01)})
			aolMsg := &common.ACOnlineMsg{ACId: "ac-1", LicenseKey: licenseKey}
			err := s.validateACLicense(ppdWithPubkey(testPubkey(0x01)), aolMsg, 1, "10.0.0.1:62206", testPubkeyB64(0x01))
			if err != nil {
				t.Fatalf("%s mode: matching bound pubkey rejected: %v", name, err)
			}
		})
	}
}

// TestValidateACLicense_PubkeyBound_Mismatch_PermitAccepts: stolen
// license with attacker-chosen pubkey. In permit mode the registration
// is accepted (pre-fix behavior) but the mismatch metric fires so
// operators can see the attack. This is the key rollout-safety
// property: strict OFF does NOT break existing deployments even if
// an attack is in flight.
func TestValidateACLicense_PubkeyBound_Mismatch_PermitAccepts(t *testing.T) {
	storage := NewMemoryStorage()
	s := newTestServerForLicenseGate(t, storage)
	// Permit mode (licensePubkeyVerifyRequire stays false).
	licenseKey := makeLicenseFixture(t, storage, []string{testPubkeyB64(0x01)})

	aolMsg := &common.ACOnlineMsg{ACId: "ac-1", LicenseKey: licenseKey}
	err := s.validateACLicense(ppdWithPubkey(testPubkey(0x99)), aolMsg, 1, "10.0.0.1:62206", testPubkeyB64(0x99))
	if err != nil {
		t.Fatalf("permit mode must accept mismatch to preserve rollout compat; got %v", err)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricLicensePubkeyMismatch]; c != 1 {
		t.Errorf("MetricLicensePubkeyMismatch=%v, want 1", c)
	}
}

// TestValidateACLicense_PubkeyBound_Mismatch_StrictRejects: strict
// mode rejects the attacker's keypair with the #1155 error code.
// THIS IS THE TEST THAT FENCES THE FIX. A regression that silently
// accepts the attacker's registration would break this assertion.
func TestValidateACLicense_PubkeyBound_Mismatch_StrictRejects(t *testing.T) {
	storage := NewMemoryStorage()
	s := newTestServerForLicenseGate(t, storage)
	s.licensePubkeyVerifyRequire = true
	licenseKey := makeLicenseFixture(t, storage, []string{testPubkeyB64(0x01)})

	aolMsg := &common.ACOnlineMsg{ACId: "ac-1", LicenseKey: licenseKey}
	err := s.validateACLicense(ppdWithPubkey(testPubkey(0x99)), aolMsg, 1, "10.0.0.1:62206", testPubkeyB64(0x99))
	if err == nil {
		t.Fatal("strict mode must reject mismatched pubkey")
	}
	if err != common.ErrLicensePubkeyMismatch {
		t.Errorf("err=%v, want ErrLicensePubkeyMismatch (52012)", err)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricLicensePubkeyMismatch]; c != 1 {
		t.Errorf("MetricLicensePubkeyMismatch=%v, want 1", c)
	}
}

// TestValidateACLicense_PubkeyUnbound_PermitAccepts: a legacy license
// with empty BoundPubKeys is the expected state during rollout. Permit
// mode must keep accepting so existing deployments don't break at the
// gate's deploy boundary.
func TestValidateACLicense_PubkeyUnbound_PermitAccepts(t *testing.T) {
	storage := NewMemoryStorage()
	s := newTestServerForLicenseGate(t, storage)
	licenseKey := makeLicenseFixture(t, storage, nil) // no allowlist

	aolMsg := &common.ACOnlineMsg{ACId: "ac-1", LicenseKey: licenseKey}
	err := s.validateACLicense(ppdWithPubkey(testPubkey(0x01)), aolMsg, 1, "10.0.0.1:62206", testPubkeyB64(0x01))
	if err != nil {
		t.Fatalf("permit mode must accept unbound license during rollout; got %v", err)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricLicensePubkeyUnbound]; c != 1 {
		t.Errorf("MetricLicensePubkeyUnbound=%v, want 1", c)
	}
}

// TestValidateACLicense_PubkeyUnbound_StrictRejects: strict mode
// rejects unbound licenses with a distinct error code so operators
// can diagnose "need to provision BoundPubKeys" from the agent log
// alone, without cross-referencing server metrics.
func TestValidateACLicense_PubkeyUnbound_StrictRejects(t *testing.T) {
	storage := NewMemoryStorage()
	s := newTestServerForLicenseGate(t, storage)
	s.licensePubkeyVerifyRequire = true
	licenseKey := makeLicenseFixture(t, storage, nil)

	aolMsg := &common.ACOnlineMsg{ACId: "ac-1", LicenseKey: licenseKey}
	err := s.validateACLicense(ppdWithPubkey(testPubkey(0x01)), aolMsg, 1, "10.0.0.1:62206", testPubkeyB64(0x01))
	if err != common.ErrLicensePubkeyUnbound {
		t.Errorf("err=%v, want ErrLicensePubkeyUnbound (52013)", err)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricLicensePubkeyUnbound]; c != 1 {
		t.Errorf("MetricLicensePubkeyUnbound=%v, want 1", c)
	}
}

// TestValidateACLicense_GateDoesNotFireOnPriorFailure: if the license
// check fails at an earlier stage (e.g., bcrypt mismatch), the gate
// must NOT run — otherwise we'd double-count a single failed
// registration. Specifically, an attacker presenting a wrong license
// key should get ErrServerACOpsFailed from the bcrypt path, not
// ErrLicensePubkeyMismatch from the gate (the latter would leak
// "the license exists but pubkey is wrong," a license-enumeration
// side-channel).
func TestValidateACLicense_GateDoesNotFireOnPriorFailure(t *testing.T) {
	storage := NewMemoryStorage()
	s := newTestServerForLicenseGate(t, storage)
	s.licensePubkeyVerifyRequire = true

	// Store license with key "correct-key" — attacker presents
	// "wrong-key". bcrypt fails, so the gate never runs.
	license := &License{
		CustomerID:     "cust-1",
		ResourceID:     "console",
		Active:         true,
		Tier:           "pro",
		ExpiresAt:      time.Now().Add(24 * time.Hour).Unix(),
		LicenseKeyHash: generateBcryptHash("correct-key"),
		BoundPubKeys:   []string{testPubkeyB64(0x01)},
	}
	storage.PutLicenseWithKey(license, "correct-key")

	aolMsg := &common.ACOnlineMsg{ACId: "ac-1", LicenseKey: "wrong-key"}
	err := s.validateACLicense(ppdWithPubkey(testPubkey(0x99)), aolMsg, 1, "10.0.0.1:62206", testPubkeyB64(0x99))
	if err == nil {
		t.Fatal("wrong license key must fail validation")
	}
	// The error must be the generic license-failure code, NOT the
	// pubkey gate's code — otherwise we'd be leaking "license
	// exists" to the attacker.
	if err == common.ErrLicensePubkeyMismatch || err == common.ErrLicensePubkeyUnbound {
		t.Errorf("gate ran after bcrypt failure; err=%v (enumeration side-channel)", err)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricLicensePubkeyMismatch]; c != 0 {
		t.Errorf("gate fired after bcrypt failure: MetricLicensePubkeyMismatch=%v, want 0", c)
	}
	if c := counters[MetricLicensePubkeyUnbound]; c != 0 {
		t.Errorf("gate fired after bcrypt failure: MetricLicensePubkeyUnbound=%v, want 0", c)
	}
}

// TestLicenseStructDynamoDBAV_RoundTripsBoundPubKeys fences the
// dynamodbav tag on License.BoundPubKeys. JSON and DDB serialization
// are independent codepaths — a future refactor that keeps the JSON
// tag but drops `dynamodbav:"bound_pubkeys,omitempty"` would pass
// the JSON test and silently break DDB storage (the only production
// storage backend in cloud mode). cr round 1 on #1261 flagged this
// gap explicitly.
//
// Exercises MarshalMap + UnmarshalMap so we're testing the real DDB
// codepath, not just tag parsing. Empty-list case asserts omitempty
// so on-wire DDB records don't bloat for unprovisioned licenses.
func TestLicenseStructDynamoDBAV_RoundTripsBoundPubKeys(t *testing.T) {
	original := License{
		CustomerID:   "cust-1",
		BoundPubKeys: []string{"pkA", "pkB"},
	}
	item, err := attributevalue.MarshalMap(&original)
	if err != nil {
		t.Fatalf("MarshalMap: %v", err)
	}
	// Attribute name pins the DDB wire format — must match JSON tag
	// because this is the on-storage name operators will see when
	// they run `aws dynamodb get-item`.
	if _, ok := item["bound_pubkeys"]; !ok {
		t.Errorf("expected bound_pubkeys attribute in DDB item, got keys: %v", item)
	}
	var roundtrip License
	if err := attributevalue.UnmarshalMap(item, &roundtrip); err != nil {
		t.Fatalf("UnmarshalMap: %v", err)
	}
	if len(roundtrip.BoundPubKeys) != 2 || roundtrip.BoundPubKeys[0] != "pkA" || roundtrip.BoundPubKeys[1] != "pkB" {
		t.Errorf("roundtrip BoundPubKeys=%v, want [pkA pkB]", roundtrip.BoundPubKeys)
	}

	// Empty list omits the attribute (omitempty). DDB records for
	// unprovisioned licenses stay small.
	empty := License{CustomerID: "cust-2"}
	emptyItem, err := attributevalue.MarshalMap(&empty)
	if err != nil {
		t.Fatalf("empty MarshalMap: %v", err)
	}
	if _, ok := emptyItem["bound_pubkeys"]; ok {
		t.Errorf("omitempty violated: empty list serialized into DDB item")
	}
}

// TestLicenseStructJSON_RoundTripsBoundPubKeys fences the JSON/dynamodbav
// tags on the License struct. If a future refactor accidentally renames
// or drops the bound_pubkeys field, existing serialized records would
// lose their allowlist silently — this test catches that.
func TestLicenseStructJSON_RoundTripsBoundPubKeys(t *testing.T) {
	original := License{
		CustomerID:   "cust-1",
		BoundPubKeys: []string{"pkA", "pkB"},
	}
	raw, err := json.Marshal(&original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Field name pins the JSON wire format (DynamoDB + etcd serialize
	// through the same tag).
	if !strings.Contains(string(raw), `"bound_pubkeys":["pkA","pkB"]`) {
		t.Errorf("expected bound_pubkeys in JSON, got: %s", raw)
	}
	var roundtrip License
	if err := json.Unmarshal(raw, &roundtrip); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(roundtrip.BoundPubKeys) != 2 || roundtrip.BoundPubKeys[0] != "pkA" || roundtrip.BoundPubKeys[1] != "pkB" {
		t.Errorf("roundtrip BoundPubKeys=%v, want [pkA pkB]", roundtrip.BoundPubKeys)
	}

	// Empty list omits the field (omitempty tag). This matters for
	// DynamoDB storage: empty list in the record vs missing attribute
	// should both deserialize to empty, and marshal of an empty list
	// should not bloat the on-wire record.
	empty := License{CustomerID: "cust-2"}
	emptyRaw, err := json.Marshal(&empty)
	if err != nil {
		t.Fatalf("empty marshal: %v", err)
	}
	if strings.Contains(string(emptyRaw), "bound_pubkeys") {
		t.Errorf("omitempty violated: %s", emptyRaw)
	}
}

// TestPubkeyLogPrefix_TruncationAndEmpty fences the ops-UX helper.
// Full pubkeys are public (wire material), so truncation is just for
// log readability — but "<empty>" vs "" matters because grep-friendly
// scans shouldn't silently match non-log lines.
func TestPubkeyLogPrefix_TruncationAndEmpty(t *testing.T) {
	if got := pubkeyLogPrefix(""); got != "<empty>" {
		t.Errorf("empty: got %q, want <empty>", got)
	}
	short := "abc"
	if got := pubkeyLogPrefix(short); got != short {
		t.Errorf("short: got %q, want %q", got, short)
	}
	long := "abcdefghijklmnopqr"
	got := pubkeyLogPrefix(long)
	if got != long[:12] {
		t.Errorf("long: got %q, want %q", got, long[:12])
	}
}
