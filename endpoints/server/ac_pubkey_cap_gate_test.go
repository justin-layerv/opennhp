package server

import (
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// ========================================================================
// Policy kernel tests (verifyACPubkeyCap) — no UdpServer dependency.
// ========================================================================

// TestVerifyACPubkeyCap_Kernel pins the kernel's verdict table. The
// kernel is the authoritative reference for "what counts as a slot"
// and "what counts as a re-registration." Reviewers should read this
// table BEFORE reading the implementation.
func TestVerifyACPubkeyCap_Kernel(t *testing.T) {
	pkA := testPubkeyB64(0x01)
	pkB := testPubkeyB64(0x02)
	pkC := testPubkeyB64(0x03)
	pkD := testPubkeyB64(0x04)

	tests := []struct {
		name      string
		presented string
		existing  []string
		capLimit  int
		want      acPubkeyCapVerdict
	}{
		{"empty-existing-ok", pkA, nil, 10, verdictACPubkeyCapOK},
		{"empty-slice-existing-ok", pkA, []string{}, 10, verdictACPubkeyCapOK},
		{"single-existing-different-pubkey-ok", pkB, []string{pkA}, 10, verdictACPubkeyCapOK},
		// In-place re-registration: same pubkey already present,
		// regardless of how many distinct pubkeys exist or how close
		// to the cap. Must NEVER consume a slot or trip the gate.
		{"reregister-same-pubkey-at-cap-ok", pkA, []string{pkA, pkB, pkC, pkD}, 4, verdictACPubkeyCapOK},
		{"reregister-same-pubkey-over-cap-ok", pkA, []string{pkA, pkA, pkA, pkB}, 2, verdictACPubkeyCapOK},
		// Cap enforcement: distinct count >= cap and presented is
		// new → exceeded. The "==" boundary is the reject case
		// because adding the new pubkey would make distinct count
		// = cap+1.
		{"distinct-count-equals-cap-exceeded", pkD, []string{pkA, pkB, pkC, pkA}, 3, verdictACPubkeyCapExceeded},
		{"distinct-count-below-cap-ok", pkD, []string{pkA, pkB, pkC}, 4, verdictACPubkeyCapOK},
		// Duplicates in existing don't count toward distinct: the
		// kernel dedupes before comparing to cap.
		{"duplicate-existing-deduped-ok", pkB, []string{pkA, pkA, pkA, pkA}, 2, verdictACPubkeyCapOK},
		{"duplicate-existing-exceeds-after-distinct-cap", pkB, []string{pkA, pkA, pkC, pkD}, 3, verdictACPubkeyCapExceeded},
		// Cap=0 edge: a future operator override that sets the cap
		// to zero should reject every new pubkey. Same-pubkey
		// re-registration still passes (the loop matches before
		// the count check).
		{"cap-zero-new-pubkey-exceeded", pkA, nil, 0, verdictACPubkeyCapExceeded},
		{"cap-zero-reregister-ok", pkA, []string{pkA}, 0, verdictACPubkeyCapOK},
		// Cap=1 (single-slot AC): only the registered pubkey can
		// re-register, anything else trips.
		{"cap-one-new-pubkey-exceeded", pkB, []string{pkA}, 1, verdictACPubkeyCapExceeded},
		// MaxACConnsPerID==10 default: 10 distinct → 11th rejected.
		{
			"production-cap-10-attack-rejected",
			testPubkeyB64(0x0B),
			[]string{
				testPubkeyB64(0x01), testPubkeyB64(0x02), testPubkeyB64(0x03),
				testPubkeyB64(0x04), testPubkeyB64(0x05), testPubkeyB64(0x06),
				testPubkeyB64(0x07), testPubkeyB64(0x08), testPubkeyB64(0x09),
				testPubkeyB64(0x0A),
			},
			10,
			verdictACPubkeyCapExceeded,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, distinctCount := verifyACPubkeyCap(tt.presented, tt.existing, tt.capLimit)
			if got != tt.want {
				t.Errorf("verifyACPubkeyCap(%q, %v, %d) = %v, want %v", tt.presented, tt.existing, tt.capLimit, got, tt.want)
			}
			// distinctCount must always reflect the deduped size of
			// existingPubkeys regardless of verdict — applyACPubkeyCapVerdict
			// uses it to log the observed cap fraction, so a verdict that
			// flips OK→Exceeded must not silently zero the count.
			expectDistinct := uniqueCount(tt.existing)
			if distinctCount != expectDistinct {
				t.Errorf("distinctCount = %d, want %d (deduped size of existing)", distinctCount, expectDistinct)
			}
		})
	}
}

// uniqueCount mirrors the kernel's distinct dedup so the test checks
// the kernel against an independent counter rather than reusing the
// kernel's own arithmetic.
func uniqueCount(s []string) int {
	seen := make(map[string]struct{}, len(s))
	for _, x := range s {
		seen[x] = struct{}{}
	}
	return len(seen)
}

// ========================================================================
// Side-effect wrapper tests (applyACPubkeyCapVerdict).
// ========================================================================

func TestApplyACPubkeyCapVerdict_PermitMode(t *testing.T) {
	pk := testPubkeyB64(0x01)
	tests := []struct {
		name       string
		verdict    acPubkeyCapVerdict
		wantMetric string // empty = no metric expected
	}{
		{"ok-no-metric", verdictACPubkeyCapOK, ""},
		{"exceeded-metric", verdictACPubkeyCapExceeded, MetricACPubkeyCapExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServerForGate(t)
			// Permit mode: acPubkeyCapVerifyRequire stays false.
			proceed, err := s.applyACPubkeyCapVerdict(tt.verdict, "ac-1", pk, 5, 1, "10.0.0.1:62206")
			if !proceed {
				t.Errorf("permit mode: proceed=false for verdict=%v, want true", tt.verdict)
			}
			if err != nil {
				t.Errorf("permit mode: err=%v for verdict=%v, want nil", err, tt.verdict)
			}
			counters, _ := s.metrics.CountersForTest(t)
			if tt.wantMetric == "" {
				if c := counters[MetricACPubkeyCapExceeded]; c != 0 {
					t.Errorf("no-metric case: exceeded counter=%v, want 0", c)
				}
			} else if c := counters[tt.wantMetric]; c != 1 {
				t.Errorf("%s counter=%v, want 1", tt.wantMetric, c)
			}
		})
	}
}

// TestApplyACPubkeyCapVerdict_StrictMode_FencesTheFix is THE attack-
// break test: an attacker presenting an 11th pubkey under one acId
// in strict mode must be rejected with ErrACPubkeyCapExceeded.
func TestApplyACPubkeyCapVerdict_StrictMode_FencesTheFix(t *testing.T) {
	pk := testPubkeyB64(0x01)
	s := newTestServerForGate(t)
	s.acPubkeyCapVerifyRequire = true

	proceed, err := s.applyACPubkeyCapVerdict(verdictACPubkeyCapExceeded, "ac-1", pk, MaxACConnsPerID, 1, "10.0.0.1:62206")
	if proceed {
		t.Error("strict mode: proceed=true for exceeded verdict; #1157 F3 attack break violated")
	}
	if err != common.ErrACPubkeyCapExceeded {
		t.Errorf("strict mode: err=%v, want ErrACPubkeyCapExceeded (52015)", err)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyCapExceeded]; c != 1 {
		t.Errorf("exceeded counter=%v, want 1", c)
	}
}

func TestApplyACPubkeyCapVerdict_StrictMode_OK(t *testing.T) {
	pk := testPubkeyB64(0x01)
	s := newTestServerForGate(t)
	s.acPubkeyCapVerifyRequire = true

	proceed, err := s.applyACPubkeyCapVerdict(verdictACPubkeyCapOK, "ac-1", pk, 0, 1, "10.0.0.1:62206")
	if !proceed {
		t.Errorf("OK verdict: proceed=false, want true")
	}
	if err != nil {
		t.Errorf("OK verdict: err=%v, want nil", err)
	}
}

// TestApplyACPubkeyCapVerdict_UnknownVerdict_FailsClosed fences the
// structural fail-closed property. Mirrors the same test in
// license_pubkey_gate_test.go.
func TestApplyACPubkeyCapVerdict_UnknownVerdict_FailsClosed(t *testing.T) {
	s := newTestServerForGate(t)
	var zero acPubkeyCapVerdict
	proceed, err := s.applyACPubkeyCapVerdict(zero, "ac-1", testPubkeyB64(0x01), 0, 1, "10.0.0.1:62206")
	if proceed {
		t.Error("uninitialized verdict proceeded; fail-closed violated")
	}
	if err != common.ErrACPubkeyCapInternal {
		t.Errorf("uninitialized verdict err=%v, want ErrACPubkeyCapInternal (52016)", err)
	}
}

func TestApplyACPubkeyCapVerdict_UnknownVerdict_ExtremeValue(t *testing.T) {
	s := newTestServerForGate(t)
	unregistered := acPubkeyCapVerdict(99)
	proceed, err := s.applyACPubkeyCapVerdict(unregistered, "ac-1", testPubkeyB64(0x01), 0, 1, "10.0.0.1:62206")
	if proceed {
		t.Error("unregistered verdict proceeded; fail-closed violated")
	}
	if err != common.ErrACPubkeyCapInternal {
		t.Errorf("unregistered verdict err=%v, want ErrACPubkeyCapInternal", err)
	}
}

// TestParseACPubkeyCapVerify_DelegatesToShared fences that the gate's
// thin env-parser wrapper uses the shared parsePermitStrictEnv
// grammar (typo rejection, accepted token set). Same shape as the
// matching test in license_pubkey_gate_test.go.
func TestParseACPubkeyCapVerify_DelegatesToShared(t *testing.T) {
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
		// Fail-closed on typo is the property the operator typo
		// regression is built on — see the corresponding test in
		// license_pubkey_gate_test.go for the rationale.
		{"enabled", false, true},
		{"enforce", false, true},
		{"strict", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := parseACPubkeyCapVerify(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("err=%v, wantErr=%v", err, tt.wantErr)
			}
			if got != tt.wantOK {
				t.Errorf("got=%v, want=%v", got, tt.wantOK)
			}
		})
	}
}

// TestVerifyACPubkeyCap_Symmetric_F3_AttackVsLegit fences the dual
// property of the fix:
//   - 11 attacker pubkeys → exceeded (attack break)
//   - 1 legitimate pubkey re-registering 11 times → OK (no
//     false-positive rejection)
//
// This is the structural difference between F3-pre-fix (FIFO eviction
// regardless of pubkey) and F3-post-fix (distinct-pubkey count). A
// reviewer reading just this test should see both properties.
func TestVerifyACPubkeyCap_Symmetric_F3_AttackVsLegit(t *testing.T) {
	capLimit := MaxACConnsPerID

	t.Run("attacker-with-N+1-pubkeys-exceeded", func(t *testing.T) {
		// Build N existing pubkeys, present a NEW (N+1)th.
		existing := make([]string, 0, capLimit)
		for i := 0; i < capLimit; i++ {
			existing = append(existing, testPubkeyB64(byte(i+1)))
		}
		got, _ := verifyACPubkeyCap(testPubkeyB64(byte(capLimit+1)), existing, capLimit)
		if got != verdictACPubkeyCapExceeded {
			t.Errorf("attacker N+1 pubkey verdict=%v, want exceeded — F3 attack break violated", got)
		}
	})

	t.Run("same-pubkey-re-registering-N+1-times-ok", func(t *testing.T) {
		pk := testPubkeyB64(0x01)
		// Saturate existing with the same pubkey N times.
		existing := make([]string, capLimit)
		for i := range existing {
			existing[i] = pk
		}
		// Re-registration of the same pubkey: must be OK regardless
		// of how many existing slots it already occupies. The code
		// today never appends a duplicate (in-place update), but
		// the kernel must be defensive against duplicates seeping
		// in via a future code path.
		got, _ := verifyACPubkeyCap(pk, existing, capLimit)
		if got != verdictACPubkeyCapOK {
			t.Errorf("same-pubkey re-registration verdict=%v, want OK — false-positive lockout", got)
		}
	})
}

// TestVerifyACPubkeyCap_SameIPKeyRotation_UnderSaturation_Exceeded
// pins the documented constraint that a same-IP key rotation under
// saturated-distinct state trips the gate as Exceeded. This is a
// known false-positive in strict mode (the msghandler's same-IP
// replacement loop would have replaced the existing slot rather than
// appending), but the kernel is connection-blind and cannot
// distinguish "presented pubkey will replace an existing slot at the
// same RemoteAddr" from "presented pubkey is a new entry against a
// saturated distinct-pubkey set."
//
// Documented in ac_pubkey_cap_gate.go's verifyACPubkeyCap doc comment
// as a known operational constraint with the workaround "drain old
// pubkeys before rotating into a saturated state."
//
// This test is the structural fence: if a future PR loosens the
// kernel to allow same-IP rotation under saturation, this test
// trips and the trade-off discussion happens at PR time (the
// connection-blind kernel design vs the false-positive surface).
func TestVerifyACPubkeyCap_SameIPKeyRotation_UnderSaturation_Exceeded(t *testing.T) {
	capLimit := MaxACConnsPerID
	// Saturate with cap distinct pubkeys.
	existing := make([]string, 0, capLimit)
	for i := 0; i < capLimit; i++ {
		existing = append(existing, testPubkeyB64(byte(i+1)))
	}
	// Present a NEW pubkey (key rotation: the AC at IP_X used to use
	// existing[0]; now it presents a fresh pkA_new). Kernel cannot
	// know IP_X's slot would be replaced rather than appended — sees
	// the presented as net-new and verdicts Exceeded.
	pkRotated := testPubkeyB64(0xCD)
	got, distinct := verifyACPubkeyCap(pkRotated, existing, capLimit)
	if got != verdictACPubkeyCapExceeded {
		t.Errorf("same-IP key rotation under saturation verdict=%v, want Exceeded (documented constraint — see kernel doc)", got)
	}
	if distinct != capLimit {
		t.Errorf("distinctCount=%d, want %d — sanity check on the saturation fixture", distinct, capLimit)
	}
}

// TestVerifyACPubkeyCap_BlueGreenSamePubkey fences that legitimate
// blue/green deployments — same AC pubkey, multiple source IPs —
// are not rejected. Pre-#1157, blue/green relied on the FIFO cap to
// hold up to MaxACs slots regardless of pubkey; post-#1157, distinct
// pubkeys is the cap and same-pubkey is unbounded.
func TestVerifyACPubkeyCap_BlueGreenSamePubkey(t *testing.T) {
	pk := testPubkeyB64(0x01)
	// Simulate a blue/green stretch with 5 in-flight ACConns from
	// 5 different source IPs but the SAME static pubkey.
	existing := []string{pk, pk, pk, pk, pk}
	got, distinct := verifyACPubkeyCap(pk, existing, MaxACConnsPerID)
	if got != verdictACPubkeyCapOK {
		t.Errorf("blue/green same-pubkey verdict=%v, want OK", got)
	}
	if distinct != 1 {
		t.Errorf("blue/green same-pubkey distinct=%d, want 1 (kernel must dedupe)", distinct)
	}
}

// TestApplyACPubkeyCapVerdict_LogPrefixIncluded is a smoke test that
// the strict-mode reject path runs to completion and emits the
// metric. We don't capture log output (same rationale as the
// license_pubkey_gate tests) but the test ensures the code path
// doesn't panic on a long pubkey string.
func TestApplyACPubkeyCapVerdict_LogPrefixIncluded(t *testing.T) {
	s := newTestServerForGate(t)
	s.acPubkeyCapVerifyRequire = true
	longPk := strings.Repeat("A", 100) // longer than typical pubkey b64 (44 chars)
	proceed, err := s.applyACPubkeyCapVerdict(verdictACPubkeyCapExceeded, "ac-1", longPk, MaxACConnsPerID, 1, "10.0.0.1:62206")
	if proceed {
		t.Error("strict mode: proceed=true for exceeded; want false")
	}
	if err != common.ErrACPubkeyCapExceeded {
		t.Errorf("strict mode: err=%v, want ErrACPubkeyCapExceeded", err)
	}
}
