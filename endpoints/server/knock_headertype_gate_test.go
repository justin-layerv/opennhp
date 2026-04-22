package server

import (
	"encoding/json"
	"testing"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// newTestServerForGate wires a minimal UdpServer with an in-memory
// metrics publisher so the gate's side effects (counter emission)
// can be asserted without standing up a full NHP server. No listener,
// no logger, no storage — the policy kernel doesn't need any of those.
//
// If a future refactor makes applyKnockHeaderTypeVerdict consult any
// other UdpServer field, expand this helper rather than stubbing the
// field inline at the call site — otherwise tests will panic in a
// way that's hard to diagnose, and the diagnosis is "we need to
// widen the test fixture."
func newTestServerForGate(t *testing.T) *UdpServer {
	t.Helper()
	return &UdpServer{metrics: metrics.NewPublisherForTest(t)}
}

// TestShouldSamplePermitLog_Modulus pins the deterministic 1/N
// sampling decision. Covers the boundary (100 → sampled, 99 → not),
// a mid-range multiple (1000 → sampled), and the trxId=0 edge case
// that NextCounterIndex guarantees cannot happen in production
// but the helper handles as a benign overstate. Note: the
// divide-by-zero guard that used to live in shouldSamplePermitLog
// was removed (dead code against a compile-time const — if
// someone edits permitModeLogSampleMod to 0, this test would
// panic with integer divide-by-zero rather than fail cleanly, and
// that's the right signal per the helper's docstring).
func TestShouldSamplePermitLog_Modulus(t *testing.T) {
	tests := []struct {
		trxId    uint64
		expected bool
	}{
		{0, true},        // N | 0
		{1, false},       // below first multiple
		{99, false},      // just below N
		{100, true},      // first real multiple (trxIds start at 1)
		{101, false},     // one past
		{999, false},     // just below 10×N
		{1000, true},     // 10×N
		{100_000, true},  // 1000×N
		{100_001, false}, // arbitrary far-field negative case
	}
	for _, tt := range tests {
		got := shouldSamplePermitLog(tt.trxId)
		if got != tt.expected {
			t.Errorf("shouldSamplePermitLog(%d) = %v, want %v", tt.trxId, got, tt.expected)
		}
	}
}

// TestLegacyAgentRoundTrip_LandsInVerdictLegacy closes the loop
// from the agent's actual emission back into the gate: a pre-#1154
// agent marshals AgentKnockMsg{} without setting HeaderType, which
// produces `"headerType": 0` in the JSON wire. Re-parsing that JSON
// into AgentKnockMsg{} on the server side gives bodyType=0, and
// verifyKnockHeaderType must classify that as verdictLegacy (not
// OK, even if the wire side happens to also be 0 — policy is
// ordering-safe per the kernel docstring). This fences "what a
// real legacy agent emits → what the gate sees" as a mechanical
// property, not a review-time argument.
func TestLegacyAgentRoundTrip_LandsInVerdictLegacy(t *testing.T) {
	// Legacy agent marshal: no HeaderType set.
	legacyMsg := &common.AgentKnockMsg{
		UserId:        "legacy-user",
		DeviceId:      "legacy-device",
		AuthServiceId: "some-asp",
		ResourceId:    "some-resource",
	}
	raw, err := json.Marshal(legacyMsg)
	if err != nil {
		t.Fatalf("marshal legacy AgentKnockMsg: %v", err)
	}

	var parsed common.AgentKnockMsg
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal legacy emission: %v", err)
	}
	if parsed.HeaderType != 0 {
		t.Fatalf("legacy emission HeaderType = %d; want 0 (legacy signal)", parsed.HeaderType)
	}

	// Gate verdict on the round-tripped body against every realistic
	// wire type. All should land in verdictLegacy because the body
	// is zero. The verdict classification doesn't depend on the
	// strict flag (the body-zero check fires before the equality
	// check), but we exercise both modes anyway to pin the
	// invariant symmetrically — a future refactor that made
	// strict-mode diverge would fail loudly here.
	wireTypes := []int{core.NHP_KNK, core.NHP_RKN, core.NHP_EXT}
	for _, strict := range []bool{false, true} {
		modeName := "permit"
		if strict {
			modeName = "strict"
		}
		for _, wireType := range wireTypes {
			t.Run(modeName+"/"+core.HeaderTypeToString(wireType), func(t *testing.T) {
				_, verdict := verifyKnockHeaderType(parsed.HeaderType, wireType, strict)
				if verdict != verdictLegacy {
					t.Errorf("legacy body vs wire=%s (strict=%v): verdict=%v, want verdictLegacy",
						core.HeaderTypeToString(wireType), strict, verdict)
				}
			})
		}
	}
}

// TestDHPKnockMsg_UnmarshalAsAgentKnockMsg_SelfLimits pins the
// safety property that the gate docstring claims for DHP→NHP wire-
// flip attacks: a DHPKnockMsg JSON payload decoded as
// AgentKnockMsg produces HeaderType=0 and AuthServiceId="", which
// the gate lands in verdictLegacy and FindAuthSvcProvider("")
// rejects downstream. If DHPKnockMsg ever grows a field with a
// JSON tag that overlaps AgentKnockMsg's populated fields, this
// test surfaces it immediately — the "revisit if DHPKnockMsg ever
// grows an overlapping field" clause in the gate docstring is no
// longer a review-time check, it's a mechanical one.
func TestDHPKnockMsg_UnmarshalAsAgentKnockMsg_SelfLimits(t *testing.T) {
	// Synthetic DHP knock body — fields DHPKnockMsg actually
	// populates today (see DHPKnockMsg in nhp/common/nhpmsg.go).
	// If new fields appear with AgentKnockMsg-compatible JSON
	// tags, add them here to fence the overlap.
	dhpMsg := &common.DHPKnockMsg{
		UserId:         "dhp-user",
		DeviceId:       "dhp-device",
		OrganizationId: "dhp-org",
		Evidence:       "synthetic-evidence",
	}
	raw, err := json.Marshal(dhpMsg)
	if err != nil {
		t.Fatalf("marshal DHPKnockMsg: %v", err)
	}

	var asAgent common.AgentKnockMsg
	if err := json.Unmarshal(raw, &asAgent); err != nil {
		t.Fatalf("unmarshal DHPKnockMsg into AgentKnockMsg: %v", err)
	}

	if asAgent.HeaderType != 0 {
		t.Errorf("AgentKnockMsg.HeaderType = %d after DHP decode; want 0 (legacy-signal)", asAgent.HeaderType)
	}
	if asAgent.AuthServiceId != "" {
		t.Errorf("AgentKnockMsg.AuthServiceId = %q after DHP decode; want empty (FindAuthSvcProvider rejects)", asAgent.AuthServiceId)
	}
	if asAgent.ResourceId != "" {
		t.Errorf("AgentKnockMsg.ResourceId = %q after DHP decode; want empty", asAgent.ResourceId)
	}
}

// TestVerifyKnockHeaderType_OK_ReturnsBodyValue pins the happy path:
// body and wire agree on a real knock type; the gate returns the
// body value (it's the authenticated one) and verdictOK so the
// caller skips all metric/log emission.
func TestVerifyKnockHeaderType_OK_ReturnsBodyValue(t *testing.T) {
	use, verdict := verifyKnockHeaderType(core.NHP_KNK, core.NHP_KNK, false)
	if verdict != verdictOK {
		t.Fatalf("body==wire==KNK: verdict=%v, want verdictOK", verdict)
	}
	if use != core.NHP_KNK {
		t.Fatalf("use=%d, want NHP_KNK (%d)", use, core.NHP_KNK)
	}

	// Same contract under strict mode.
	use, verdict = verifyKnockHeaderType(core.NHP_EXT, core.NHP_EXT, true)
	if verdict != verdictOK {
		t.Fatalf("strict body==wire==EXT: verdict=%v, want verdictOK", verdict)
	}
	if use != core.NHP_EXT {
		t.Fatalf("strict use=%d, want NHP_EXT (%d)", use, core.NHP_EXT)
	}
}

// TestVerifyKnockHeaderType_Legacy_PermitFallsBackToWire fences the
// rollout ergonomics: a legacy agent sends body.HeaderType=0 and
// the gate in permit mode falls back to the wire value so the
// server processes the knock using the pre-#1154 behavior. Emits
// the legacy metric (side-effect tested separately) so operators
// can watch the rollout.
func TestVerifyKnockHeaderType_Legacy_PermitFallsBackToWire(t *testing.T) {
	use, verdict := verifyKnockHeaderType(0, core.NHP_KNK, false)
	if verdict != verdictLegacy {
		t.Fatalf("body=0: verdict=%v, want verdictLegacy", verdict)
	}
	if use != core.NHP_KNK {
		t.Fatalf("legacy permit use=%d, want NHP_KNK (%d) fallback", use, core.NHP_KNK)
	}
}

// TestVerifyKnockHeaderType_Legacy_StrictRejects fences the
// post-rollout posture: once operators flip strict, a legacy
// (zero-body) knock must be rejected. The caller turns a
// verdictLegacy-in-strict into the 52009 error response.
func TestVerifyKnockHeaderType_Legacy_StrictRejects(t *testing.T) {
	_, verdict := verifyKnockHeaderType(0, core.NHP_KNK, true)
	if verdict != verdictLegacy {
		t.Fatalf("strict body=0: verdict=%v, want verdictLegacy", verdict)
	}
}

// TestVerifyKnockHeaderType_Mismatch_PermitFallsBackToWire fences
// the load-bearing security observation from #1154: a MitM
// flipping the wire byte from NHP_KNK to NHP_EXT (body still says
// NHP_KNK because it's inside the AEAD) shows up as a mismatch.
// Permit mode preserves the pre-fix behavior (use wire value) so
// the rollout doesn't break anything; the metric is what operators
// watch. Once the permit-metric stays at zero, they flip strict.
func TestVerifyKnockHeaderType_Mismatch_PermitFallsBackToWire(t *testing.T) {
	use, verdict := verifyKnockHeaderType(core.NHP_KNK, core.NHP_EXT, false)
	if verdict != verdictMismatch {
		t.Fatalf("body=KNK wire=EXT: verdict=%v, want verdictMismatch", verdict)
	}
	if use != core.NHP_EXT {
		t.Fatalf("permit mismatch use=%d, want NHP_EXT (%d) pre-fix behavior", use, core.NHP_EXT)
	}
}

// TestVerifyKnockHeaderType_Mismatch_StrictRejects is the contract
// test that closes #1154: strict mode rejects the type-flip attack.
// The caller turns verdictMismatch-in-strict into 52009, so the
// MitM cannot flip openTime=1 on the victim.
func TestVerifyKnockHeaderType_Mismatch_StrictRejects(t *testing.T) {
	_, verdict := verifyKnockHeaderType(core.NHP_KNK, core.NHP_EXT, true)
	if verdict != verdictMismatch {
		t.Fatalf("strict body=KNK wire=EXT: verdict=%v, want verdictMismatch", verdict)
	}
}

// TestVerifyKnockHeaderType_ReverseFlip fences the other direction:
// an attacker flipping NHP_EXT → NHP_KNK is also detected. Less
// severe than the forward direction (the victim tried to close,
// stays open) but the gate must catch it too — same mismatch path.
func TestVerifyKnockHeaderType_ReverseFlip(t *testing.T) {
	_, verdict := verifyKnockHeaderType(core.NHP_EXT, core.NHP_KNK, true)
	if verdict != verdictMismatch {
		t.Fatalf("strict body=EXT wire=KNK: verdict=%v, want verdictMismatch", verdict)
	}
}

// TestVerifyKnockHeaderType_KPLWire_TreatedAsMismatch pins the
// boundary case that shouldn't happen in practice: the wire
// HeaderType dispatcher rejects raw NHP_KPL (keepalive) packets
// before they reach HandleKnockRequest. But if that upstream gate
// were ever loosened, a real agent (non-zero body) against a
// synthetic NHP_KPL wire byte still lands in the mismatch branch
// — the gate doesn't special-case the wire side, only the body
// zero-value. This keeps the policy uniform.
func TestVerifyKnockHeaderType_KPLWire_TreatedAsMismatch(t *testing.T) {
	_, verdict := verifyKnockHeaderType(core.NHP_KNK, core.NHP_KPL, true)
	if verdict != verdictMismatch {
		t.Fatalf("strict body=KNK wire=KPL: verdict=%v, want verdictMismatch", verdict)
	}
}

// TestVerifyKnockHeaderType_RKN_MismatchesKNK is a policy pin:
// NHP_RKN (re-knock) and NHP_KNK are distinct header types. A
// re-knock must carry body.HeaderType=NHP_RKN. If a MitM flips
// the wire NHP_KNK → NHP_RKN, the body will still say NHP_KNK,
// and the gate will flag it. Pins "any distinct-type mismatch
// counts," not just the specific KNK↔EXT pair the issue described.
func TestVerifyKnockHeaderType_RKN_MismatchesKNK(t *testing.T) {
	_, verdict := verifyKnockHeaderType(core.NHP_KNK, core.NHP_RKN, true)
	if verdict != verdictMismatch {
		t.Fatalf("strict body=KNK wire=RKN: verdict=%v, want verdictMismatch", verdict)
	}
}

// TestParseKnockHeaderTypeVerify_Tokens pins the truthy / falsy
// token set. The gate shares its token parser with
// parseInternalAuthRequire so operators configuring multiple gates
// via Terraform don't get surprised by asymmetric acceptance.
// Unrecognized values fail loud so an operator typo (e.g., "enable")
// cannot silently leave the gate in permit mode.
func TestParseKnockHeaderTypeVerify_Tokens(t *testing.T) {
	tests := []struct {
		in       string
		want     bool
		wantErr  bool
		wantWhat string
	}{
		{"", false, false, "unset → permit"},
		{"false", false, false, "false → permit"},
		{"0", false, false, "0 → permit"},
		{"no", false, false, "no → permit"},
		{"off", false, false, "off → permit"},
		{"true", true, false, "true → strict"},
		{"1", true, false, "1 → strict"},
		{"yes", true, false, "yes → strict"},
		{"on", true, false, "on → strict"},
		{"TRUE", true, false, "case-insensitive"},
		{"  true  ", true, false, "trimmed"},
		{"enable", false, true, "typo fails loud"},
		{"2", false, true, "non-boolean integer fails loud"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseKnockHeaderTypeVerify(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("%s: err=%v wantErr=%v", tt.wantWhat, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("%s: got=%v want=%v", tt.wantWhat, got, tt.want)
			}
		})
	}
}

// TestApplyKnockHeaderTypeVerdict_OK_NoMetric fences the side-effect
// contract: verdictOK must NOT emit any metric. The metric stream
// is the signal operators alarm on, so emitting on the happy path
// would destroy signal-to-noise under normal traffic.
//
// Asserts on the `counters` map (IncrCounter's target), not the
// dimCounters map which the gate never writes to. An earlier
// version of this test checked the wrong map and silently passed
// regardless of emit behavior — the ONLY assertion that fences a
// regression that accidentally adds an IncrCounter on the OK path
// is a zero-check on the real counter.
func TestApplyKnockHeaderTypeVerdict_OK_NoMetric(t *testing.T) {
	s := newTestServerForGate(t)
	proceed, rejectErr := s.applyKnockHeaderTypeVerdict(verdictOK, core.NHP_KNK, core.NHP_KNK, 1, "test-addr")
	if !proceed {
		t.Fatal("verdictOK should proceed")
	}
	if rejectErr != nil {
		t.Errorf("verdictOK rejectErr must be nil, got %v", rejectErr)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if counters[MetricKnockHeaderTypeMismatch] != 0 || counters[MetricKnockHeaderTypeLegacy] != 0 {
		t.Errorf("verdictOK must not emit gate metrics; mismatch=%v legacy=%v",
			counters[MetricKnockHeaderTypeMismatch], counters[MetricKnockHeaderTypeLegacy])
	}
}

// TestApplyKnockHeaderTypeVerdict_LegacyPermit_EmitsLegacyMetric
// fences the burn-in signal: in permit mode, a legacy verdict
// increments the legacy counter so operators know how many
// old-agent knocks are still being accepted. Must stay at zero
// before flipping strict.
func TestApplyKnockHeaderTypeVerdict_LegacyPermit_EmitsLegacyMetric(t *testing.T) {
	s := newTestServerForGate(t)
	s.knockHeaderTypeVerifyRequire = false
	proceed, rejectErr := s.applyKnockHeaderTypeVerdict(verdictLegacy, 0, core.NHP_KNK, 1, "test-addr")
	if !proceed {
		t.Fatal("permit mode must accept legacy")
	}
	if rejectErr != nil {
		t.Errorf("permit legacy rejectErr must be nil, got %v", rejectErr)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if counters[MetricKnockHeaderTypeLegacy] != 1 {
		t.Errorf("permit legacy: MetricKnockHeaderTypeLegacy=%v, want 1", counters[MetricKnockHeaderTypeLegacy])
	}
}

// TestApplyKnockHeaderTypeVerdict_LegacyStrict_Rejects fences the
// strict-mode behavior: once the permit counter is flat and the
// operator flips strict, a legacy knock is rejected at the gate
// with the 52009 error surfaced to the agent.
func TestApplyKnockHeaderTypeVerdict_LegacyStrict_Rejects(t *testing.T) {
	s := newTestServerForGate(t)
	s.knockHeaderTypeVerifyRequire = true
	proceed, rejectErr := s.applyKnockHeaderTypeVerdict(verdictLegacy, 0, core.NHP_KNK, 1, "test-addr")
	if proceed {
		t.Fatal("strict mode must reject legacy")
	}
	if rejectErr != common.ErrKnockHeaderTypeLegacy {
		t.Errorf("strict legacy rejectErr must be ErrKnockHeaderTypeLegacy (52010), got %v", rejectErr)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if counters[MetricKnockHeaderTypeLegacy] != 1 {
		t.Errorf("strict legacy: MetricKnockHeaderTypeLegacy=%v, want 1", counters[MetricKnockHeaderTypeLegacy])
	}
}

// TestApplyKnockHeaderTypeVerdict_MismatchPermit_EmitsMismatchMetric
// fences the attack-detection signal: even in permit mode (where
// the rollout preserves the pre-fix behavior), the mismatch metric
// must fire so operators know the attack is in flight. This counter
// is page-worthy in strict and investigate-worthy in permit.
func TestApplyKnockHeaderTypeVerdict_MismatchPermit_EmitsMismatchMetric(t *testing.T) {
	s := newTestServerForGate(t)
	s.knockHeaderTypeVerifyRequire = false
	proceed, rejectErr := s.applyKnockHeaderTypeVerdict(verdictMismatch, core.NHP_KNK, core.NHP_EXT, 1, "test-addr")
	if !proceed {
		t.Fatal("permit mode must accept mismatch (pre-fix behavior)")
	}
	if rejectErr != nil {
		t.Errorf("permit mismatch rejectErr must be nil, got %v", rejectErr)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if counters[MetricKnockHeaderTypeMismatch] != 1 {
		t.Errorf("permit mismatch: MetricKnockHeaderTypeMismatch=%v, want 1", counters[MetricKnockHeaderTypeMismatch])
	}
}

// TestApplyKnockHeaderTypeVerdict_ZeroValueVerdict_FailsClosed
// pins the fail-closed-by-construction property: the zero value
// of knockHeaderTypeVerdict is NOT verdictOK (iota=0 is unnamed),
// so an uninitialized verdict field or channel-default read
// lands in the switch default and rejects with
// ErrKnockHeaderTypeInternal. Without this test, a PR that
// re-orders the iota (putting verdictOK at 0) would silently
// regress the fail-closed-on-uninitialized property.
func TestApplyKnockHeaderTypeVerdict_ZeroValueVerdict_FailsClosed(t *testing.T) {
	s := newTestServerForGate(t)
	var zero knockHeaderTypeVerdict // Go zero value
	proceed, rejectErr := s.applyKnockHeaderTypeVerdict(zero, core.NHP_KNK, core.NHP_KNK, 1, "test-addr")
	if proceed {
		t.Fatal("zero-value verdict must reject (fail-closed by construction)")
	}
	if rejectErr != common.ErrKnockHeaderTypeInternal {
		t.Errorf("zero-value verdict rejectErr must be ErrKnockHeaderTypeInternal (52011), got %v", rejectErr)
	}
}

// TestApplyKnockHeaderTypeVerdict_UnknownVerdict_FailsClosed
// fences the belt-and-suspenders guard: if a future PR adds a new
// knockHeaderTypeVerdict constant and forgets to register a case
// in the switch, the default branch must reject (fail-closed) and
// log.Error, not silently accept. Without this test, the guard is
// review-dependent — which is exactly the failure mode it's
// designed to catch.
func TestApplyKnockHeaderTypeVerdict_UnknownVerdict_FailsClosed(t *testing.T) {
	s := newTestServerForGate(t)
	// A synthetic out-of-range verdict that will never match a
	// real switch case. Must be chosen outside the defined iota
	// range (verdictOK=0, verdictLegacy=1, verdictMismatch=2).
	bogus := knockHeaderTypeVerdict(99)
	proceed, rejectErr := s.applyKnockHeaderTypeVerdict(bogus, core.NHP_KNK, core.NHP_KNK, 1, "test-addr")
	if proceed {
		t.Fatal("unknown verdict must reject (fail-closed)")
	}
	if rejectErr != common.ErrKnockHeaderTypeInternal {
		t.Errorf("unknown verdict rejectErr must be ErrKnockHeaderTypeInternal (52011), got %v", rejectErr)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if counters[MetricKnockHeaderTypeMismatch] != 0 || counters[MetricKnockHeaderTypeLegacy] != 0 {
		t.Errorf("unknown verdict must not emit gate metrics; got mismatch=%v legacy=%v",
			counters[MetricKnockHeaderTypeMismatch], counters[MetricKnockHeaderTypeLegacy])
	}
}

// TestApplyKnockHeaderTypeVerdict_MismatchStrict_Rejects is the
// end-to-end contract that closes #1154: strict + mismatch →
// reject. A MitM flipping NHP_KNK → NHP_EXT is turned into a
// 52009 error on the ack path and NEVER reaches
// processACOperationBroadcast with openTime=1.
func TestApplyKnockHeaderTypeVerdict_MismatchStrict_Rejects(t *testing.T) {
	s := newTestServerForGate(t)
	s.knockHeaderTypeVerifyRequire = true
	proceed, rejectErr := s.applyKnockHeaderTypeVerdict(verdictMismatch, core.NHP_KNK, core.NHP_EXT, 1, "test-addr")
	if proceed {
		t.Fatal("strict mode must reject mismatch")
	}
	if rejectErr != common.ErrKnockHeaderTypeMismatch {
		t.Errorf("strict mismatch rejectErr must be ErrKnockHeaderTypeMismatch (52009), got %v", rejectErr)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if counters[MetricKnockHeaderTypeMismatch] != 1 {
		t.Errorf("strict mismatch: MetricKnockHeaderTypeMismatch=%v, want 1", counters[MetricKnockHeaderTypeMismatch])
	}
}
