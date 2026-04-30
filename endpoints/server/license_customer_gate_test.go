package server

import (
	"context"
	"errors"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// ========================================================================
// Policy kernel tests (verifyACIDCustomer) — no UdpServer dependency.
// ========================================================================

// TestVerifyACIDCustomer_Kernel pins the kernel's verdict table.
func TestVerifyACIDCustomer_Kernel(t *testing.T) {
	tests := []struct {
		name              string
		existingCustomer  string
		licenseCustomerID string
		want              licenseACIDCustomerVerdict
	}{
		{"both-empty-unbound", "", "", verdictACIDCustomerUnbound},
		{"existing-empty-license-set-unbound", "", "cust-A", verdictACIDCustomerUnbound},
		{"match-ok", "cust-A", "cust-A", verdictACIDCustomerOK},
		{"mismatch", "cust-A", "cust-B", verdictACIDCustomerMismatch},
		// License-side empty with a populated existing customer is
		// a defense-in-depth Mismatch: a misconfigured License with
		// no CustomerID must NOT silently sidestep a populated
		// assignment binding.
		{"existing-set-license-empty-mismatch", "cust-A", "", verdictACIDCustomerMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifyACIDCustomer(tt.existingCustomer, tt.licenseCustomerID)
			if got != tt.want {
				t.Errorf("verifyACIDCustomer(%q, %q) = %v, want %v", tt.existingCustomer, tt.licenseCustomerID, got, tt.want)
			}
		})
	}
}

// ========================================================================
// Side-effect wrapper tests (applyACIDCustomerVerdict).
// ========================================================================

func TestApplyACIDCustomerVerdict_PermitMode(t *testing.T) {
	tests := []struct {
		name       string
		verdict    licenseACIDCustomerVerdict
		wantMetric string
	}{
		{"ok-no-metric", verdictACIDCustomerOK, ""},
		{"unbound-no-metric", verdictACIDCustomerUnbound, ""},
		{"mismatch-metric", verdictACIDCustomerMismatch, MetricLicenseCustomerMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServerForGate(t)
			// Permit mode: licenseACIDCustomerVerifyRequire stays false.
			proceed, err := s.applyACIDCustomerVerdict(tt.verdict, "ac-1", "cust-A", "cust-B", 1, "10.0.0.1:62206", "keypref")
			if !proceed {
				t.Errorf("permit: proceed=false for verdict=%v, want true", tt.verdict)
			}
			if err != nil {
				t.Errorf("permit: err=%v for verdict=%v, want nil", err, tt.verdict)
			}
			counters, _ := s.metrics.CountersForTest(t)
			if tt.wantMetric == "" {
				if c := counters[MetricLicenseCustomerMismatch]; c != 0 {
					t.Errorf("no-metric case: mismatch counter=%v, want 0", c)
				}
			} else if c := counters[tt.wantMetric]; c != 1 {
				t.Errorf("%s counter=%v, want 1", tt.wantMetric, c)
			}
		})
	}
}

// TestApplyACIDCustomerVerdict_StrictMode_FencesTheFix is THE attack-
// break test: a license issued to customer A presented under an acId
// bound to customer B in strict mode must be rejected.
func TestApplyACIDCustomerVerdict_StrictMode_FencesTheFix(t *testing.T) {
	s := newTestServerForGate(t)
	s.licenseACIDCustomerVerifyRequire = true

	proceed, err := s.applyACIDCustomerVerdict(verdictACIDCustomerMismatch, "ac-of-customer-B", "cust-A", "cust-B", 1, "10.0.0.1:62206", "keypref")
	if proceed {
		t.Error("strict: proceed=true for mismatch; #1157 F4 attack break violated")
	}
	if err != common.ErrLicenseCustomerMismatch {
		t.Errorf("strict: err=%v, want ErrLicenseCustomerMismatch (52017)", err)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricLicenseCustomerMismatch]; c != 1 {
		t.Errorf("mismatch counter=%v, want 1", c)
	}
}

// TestApplyACIDCustomerVerdict_StrictMode_UnboundProceeds fences that
// strict mode treats Unbound as accept (first-time TOFU registration
// path). Rejecting Unbound under strict would lock out every brand-
// new AC, which is by design a non-attack flow — Mismatch is the
// reject signal.
func TestApplyACIDCustomerVerdict_StrictMode_UnboundProceeds(t *testing.T) {
	s := newTestServerForGate(t)
	s.licenseACIDCustomerVerifyRequire = true

	proceed, err := s.applyACIDCustomerVerdict(verdictACIDCustomerUnbound, "ac-new", "cust-A", "", 1, "10.0.0.1:62206", "keypref")
	if !proceed {
		t.Error("strict: Unbound rejected; expected accept (TOFU first-registration)")
	}
	if err != nil {
		t.Errorf("strict: Unbound err=%v, want nil", err)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricLicenseCustomerMismatch]; c != 0 {
		t.Errorf("Unbound should not increment Mismatch counter, got %v", c)
	}
}

func TestApplyACIDCustomerVerdict_UnknownVerdict_FailsClosed(t *testing.T) {
	s := newTestServerForGate(t)
	var zero licenseACIDCustomerVerdict
	proceed, err := s.applyACIDCustomerVerdict(zero, "ac-1", "cust-A", "cust-A", 1, "10.0.0.1:62206", "keypref")
	if proceed {
		t.Error("uninitialized verdict proceeded; fail-closed violated")
	}
	if err != common.ErrLicenseCustomerInternal {
		t.Errorf("uninitialized verdict err=%v, want ErrLicenseCustomerInternal (52018)", err)
	}
}

func TestApplyACIDCustomerVerdict_UnknownVerdict_ExtremeValue(t *testing.T) {
	s := newTestServerForGate(t)
	unregistered := licenseACIDCustomerVerdict(99)
	proceed, err := s.applyACIDCustomerVerdict(unregistered, "ac-1", "cust-A", "cust-A", 1, "10.0.0.1:62206", "keypref")
	if proceed {
		t.Error("unregistered verdict proceeded; fail-closed violated")
	}
	if err != common.ErrLicenseCustomerInternal {
		t.Errorf("unregistered verdict err=%v, want ErrLicenseCustomerInternal", err)
	}
}

func TestParseLicenseACIDCustomerVerify_DelegatesToShared(t *testing.T) {
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
		// Typos fail-closed (operator-typo regression). Same
		// rationale as the matching test in
		// license_pubkey_gate_test.go.
		{"enabled", false, true},
		{"enforce", false, true},
		{"strict", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := parseLicenseACIDCustomerVerify(tt.raw)
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
// Storage-error policy tests (evaluateACIDCustomerVerdict).
//
// Storage transient errors must NOT escalate to a strict-mode reject.
// The lookup-err counter is the operator's only signal — these tests
// fence both the verdict outcome and the metric.
// ========================================================================

// errStorage is a MemoryStorage subclass that returns a transient
// error on GetACAssignment. Used to verify the gate degrades
// gracefully under storage flap. Wraps the real MemoryStorage so we
// can mix transient errors with successful operations on other
// methods.
type errStorageACAssignment struct {
	*MemoryStorage
	err error
}

func (e *errStorageACAssignment) GetACAssignment(ctx context.Context, acID string) (*ACAssignment, error) {
	if e.err != nil {
		return nil, e.err
	}
	return e.MemoryStorage.GetACAssignment(ctx, acID)
}

func TestEvaluateACIDCustomerVerdict_StorageErrorReturnsUnbound(t *testing.T) {
	mem := NewMemoryStorage()
	storage := &errStorageACAssignment{
		MemoryStorage: mem,
		err:           errors.New("ddb: ProvisionedThroughputExceededException"),
	}
	s := newTestServerForLicenseGate(t, mem)
	s.storage = storage

	verdict, existing := s.evaluateACIDCustomerVerdict(context.Background(), "ac-1", "cust-A", 1, "10.0.0.1:62206")
	if verdict != verdictACIDCustomerUnbound {
		t.Errorf("storage error verdict=%v, want Unbound (skip-the-cross-check)", verdict)
	}
	if existing != "" {
		t.Errorf("storage error existing customer=%q, want empty", existing)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricLicenseCustomerLookupErr]; c != 1 {
		t.Errorf("lookup-err counter=%v, want 1", c)
	}
}

func TestEvaluateACIDCustomerVerdict_NotFoundReturnsUnbound(t *testing.T) {
	mem := NewMemoryStorage()
	s := newTestServerForLicenseGate(t, mem)

	// No assignment exists → not-found path.
	verdict, existing := s.evaluateACIDCustomerVerdict(context.Background(), "ac-never-seen", "cust-A", 1, "10.0.0.1:62206")
	if verdict != verdictACIDCustomerUnbound {
		t.Errorf("not-found verdict=%v, want Unbound (TOFU first-registration)", verdict)
	}
	if existing != "" {
		t.Errorf("not-found existing customer=%q, want empty", existing)
	}
	// Not-found is the legitimate first-registration path; must NOT
	// trip lookup-err counter (that's reserved for true storage flaps).
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricLicenseCustomerLookupErr]; c != 0 {
		t.Errorf("not-found should not increment lookup-err counter, got %v", c)
	}
}

func TestEvaluateACIDCustomerVerdict_BoundCustomerMatchesOK(t *testing.T) {
	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{
		ACID:       "ac-1",
		CustomerID: "cust-A",
		Version:    1,
	})
	s := newTestServerForLicenseGate(t, mem)

	verdict, existing := s.evaluateACIDCustomerVerdict(context.Background(), "ac-1", "cust-A", 1, "10.0.0.1:62206")
	if verdict != verdictACIDCustomerOK {
		t.Errorf("matching customers verdict=%v, want OK", verdict)
	}
	if existing != "cust-A" {
		t.Errorf("existing customer=%q, want cust-A", existing)
	}
}

// TestEvaluateACIDCustomerVerdict_BoundCustomerMismatchFencesTheFix
// is THE end-to-end attack break test. Customer A's license tries
// to register under customer B's bound acId. The kernel must return
// Mismatch.
func TestEvaluateACIDCustomerVerdict_BoundCustomerMismatchFencesTheFix(t *testing.T) {
	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{
		ACID:       "ac-of-customer-B",
		CustomerID: "cust-B",
		Version:    1,
	})
	s := newTestServerForLicenseGate(t, mem)

	verdict, existing := s.evaluateACIDCustomerVerdict(context.Background(), "ac-of-customer-B", "cust-A", 1, "10.0.0.1:62206")
	if verdict != verdictACIDCustomerMismatch {
		t.Errorf("cross-customer attempt verdict=%v, want Mismatch — F4 attack break violated", verdict)
	}
	if existing != "cust-B" {
		t.Errorf("existing customer=%q, want cust-B", existing)
	}
}

func TestEvaluateACIDCustomerVerdict_AssignmentWithoutCustomerIDReturnsUnbound(t *testing.T) {
	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{
		ACID:       "ac-1",
		CustomerID: "", // unbound assignment
		Version:    1,
	})
	s := newTestServerForLicenseGate(t, mem)

	verdict, existing := s.evaluateACIDCustomerVerdict(context.Background(), "ac-1", "cust-A", 1, "10.0.0.1:62206")
	if verdict != verdictACIDCustomerUnbound {
		t.Errorf("unbound assignment verdict=%v, want Unbound", verdict)
	}
	if existing != "" {
		t.Errorf("existing customer=%q, want empty", existing)
	}
}

// TestEvaluateACIDCustomerVerdict_NoStorageReturnsUnbound covers the
// non-cloud (etcd / static) deployment path: s.storage is nil, the
// gate is bypassed.
func TestEvaluateACIDCustomerVerdict_NoStorageReturnsUnbound(t *testing.T) {
	s := newTestServerForGate(t)
	verdict, existing := s.evaluateACIDCustomerVerdict(context.Background(), "ac-1", "cust-A", 1, "10.0.0.1:62206")
	if verdict != verdictACIDCustomerUnbound {
		t.Errorf("no-storage verdict=%v, want Unbound", verdict)
	}
	if existing != "" {
		t.Errorf("no-storage existing=%q, want empty", existing)
	}
}
