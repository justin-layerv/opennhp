package ac

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// newTestReg builds an ACRegistration with a publisher whose base dims are the
// canonical [Component, Environment, Region] set, keyed by acID so each test's
// breakdown streams are distinguishable. Shared by the failure-metric fences
// below.
func newTestReg(t *testing.T, acID string) *ACRegistration {
	t.Helper()
	ac := &UdpAC{
		config: &Config{
			ACId:           acID,
			ServerEndpoint: "server.nhp.test.internal",
		},
	}
	return mustNewACRegistration(t, ac)
}

// TestRecordRegistrationFailure_EmitsBothBaseAndTypedCounters verifies that
// recordRegistrationFailure (the alarmable path — server-side rejections) emits
// BOTH the unbreakdown base counter (no extra dims — what the
// registration_failure alarm watches) AND the ErrorCode/ACId breakdown counter
// (kept for dashboards).
//
// Regression fence for issue #968. The registration_failure alarm in
// terraform/modules/ac/monitoring.tf keys on the publisher base dim set
// [Component, Environment, Region]. Before #968 the failure paths only emitted
// the breakdown stream (ACId + ErrorCode appended), so the alarm watched a
// {Component, Environment, Region} stream that was never published and sat in
// permanent OK (treat_missing_data=notBreaching) even while registrations were
// failing fleet-wide.
//
// If a future refactor drops the base IncrCounter in recordRegistrationFailure,
// this test goes red — that is exactly the silent-re-break this fence exists for.
func TestRecordRegistrationFailure_EmitsBothBaseAndTypedCounters(t *testing.T) {
	reg := newTestReg(t, "test-ac-001")

	reg.recordRegistrationFailure(aws.String("rejected"))
	reg.recordRegistrationFailure(aws.String("registered_false"))
	reg.recordRegistrationFailure(aws.String("rejected"))

	counters, dimCounters := reg.metrics.CountersForTest(t)

	// Base counter: 3 failures total, no extra dims. This is the stream the
	// alarm evaluates.
	if got := counters[MetricRegistrationFailure]; got != 3 {
		t.Errorf("base RegistrationFailure counter: want 3, got %v", got)
	}

	// Breakdown counters: 2 for rejected, 1 for registered_false, each carrying
	// the ACId dimension.
	var rejectedCount, regFalseCount float64
	for key, v := range dimCounters {
		if !strings.Contains(key, MetricRegistrationFailure) {
			continue
		}
		if !strings.Contains(key, "ACId=test-ac-001") {
			t.Errorf("breakdown RegistrationFailure stream missing ACId dim: key=%q", key)
		}
		if strings.Contains(key, "ErrorCode=rejected") {
			rejectedCount += v
		}
		if strings.Contains(key, "ErrorCode=registered_false") {
			regFalseCount += v
		}
	}
	if rejectedCount != 2 {
		t.Errorf("rejected breakdown counter: want 2, got %v", rejectedCount)
	}
	if regFalseCount != 1 {
		t.Errorf("registered_false breakdown counter: want 1, got %v", regFalseCount)
	}
}

// TestRecordRegistrationDrop_EmitsBreakdownOnly verifies that lifecycle/transport
// drops (canceled, timeout, stopped) land ONLY on the ErrorCode/ACId breakdown
// stream and do NOT bump the base counter. This keeps the registration_failure
// alarm out of the path of the failure bursts that occur during every AC
// teardown / blue/green flip — routing them into the alarmable base counter
// (Sum>5 over one 5-min window) would guarantee false pages on fleet refresh
// (#968).
func TestRecordRegistrationDrop_EmitsBreakdownOnly(t *testing.T) {
	reg := newTestReg(t, "test-ac-003")

	reg.recordRegistrationDrop(aws.String("canceled"))
	reg.recordRegistrationDrop(aws.String("timeout"))
	reg.recordRegistrationDrop(aws.String("canceled"))

	counters, dimCounters := reg.metrics.CountersForTest(t)

	// Base counter must stay zero — drops are NOT alarmable.
	if got := counters[MetricRegistrationFailure]; got != 0 {
		t.Errorf("base RegistrationFailure counter after drops: want 0 (drops are breakdown-only), got %v", got)
	}

	// Breakdown stream still records them with ACId for accounting/dashboards.
	var canceledCount, timeoutCount float64
	for key, v := range dimCounters {
		if !strings.Contains(key, MetricRegistrationFailure) {
			continue
		}
		if !strings.Contains(key, "ACId=test-ac-003") {
			t.Errorf("breakdown RegistrationFailure drop stream missing ACId dim: key=%q", key)
		}
		if strings.Contains(key, "ErrorCode=canceled") {
			canceledCount += v
		}
		if strings.Contains(key, "ErrorCode=timeout") {
			timeoutCount += v
		}
	}
	if canceledCount != 2 {
		t.Errorf("canceled breakdown counter: want 2, got %v", canceledCount)
	}
	if timeoutCount != 1 {
		t.Errorf("timeout breakdown counter: want 1, got %v", timeoutCount)
	}
}

// TestRecordRegistrationOutcomeByCode_FailSafeDefault fences the routing rule
// that keeps #968 from silently regressing: every code in
// teardownRegistrationDropCodes is breakdown-only (base counter stays 0), and
// every OTHER code — including a hypothetical new one — is alarmable (base
// counter bumps). If a future change adds a page-worthy code to
// classifyResponseError/classifyError, this asserts it defaults to alarmable
// rather than silently dropping out of the registration_failure alarm.
func TestRecordRegistrationOutcomeByCode_FailSafeDefault(t *testing.T) {
	// All known teardown drops must NOT bump the alarmable base counter.
	for code := range teardownRegistrationDropCodes {
		reg := newTestReg(t, "test-ac-004")

		reg.recordRegistrationOutcomeByCode(code)

		counters, _ := reg.metrics.CountersForTest(t)
		if got := counters[MetricRegistrationFailure]; got != 0 {
			t.Errorf("teardown code %q: base RegistrationFailure counter want 0 (breakdown-only), got %v", code, got)
		}
	}

	// An unknown / non-teardown code MUST be alarmable (fail-safe default).
	for _, code := range []string{"rejected", "crypto_error", "some_future_code"} {
		reg := newTestReg(t, "test-ac-005")

		reg.recordRegistrationOutcomeByCode(code)

		counters, _ := reg.metrics.CountersForTest(t)
		if got := counters[MetricRegistrationFailure]; got != 1 {
			t.Errorf("non-teardown code %q: base RegistrationFailure counter want 1 (alarmable by default), got %v", code, got)
		}
	}
}

// TestRecordResponseError_TimeoutDropsRealErrorAlarms fences the ppd.Error
// routing — the subtle path cr round 4 surfaced. A transaction-layer timeout
// (common.ErrTransactionFailedByTimeout) is the dominant blue/green-flip
// transient and arrives on ResponseMsgCh as a fabricated error PPD (no response
// received), so it MUST be a breakdown-only drop, NOT feed the alarmable base
// counter. Any other (genuine server-returned) error MUST be alarmable —
// including one that merely classifies as "timeout" (hence the errors.Is check
// rather than a string match).
func TestRecordResponseError_TimeoutDropsRealErrorAlarms(t *testing.T) {
	// Transaction timeout → drop (base counter stays 0).
	t.Run("transaction_timeout_drops", func(t *testing.T) {
		reg := newTestReg(t, "test-ac-006")
		reg.recordResponseError(common.ErrTransactionFailedByTimeout)
		// Also exercise a wrapped form to confirm errors.Is unwraps.
		reg.recordResponseError(fmt.Errorf("registration round-trip: %w", common.ErrTransactionFailedByTimeout))

		counters, dimCounters := reg.metrics.CountersForTest(t)
		if got := counters[MetricRegistrationFailure]; got != 0 {
			t.Errorf("base RegistrationFailure after transaction timeouts: want 0 (drop), got %v", got)
		}
		// They still land on the breakdown stream for accounting.
		var seen int
		for key := range dimCounters {
			if strings.Contains(key, MetricRegistrationFailure) && strings.Contains(key, "ErrorCode=timeout") {
				seen++
			}
		}
		if seen == 0 {
			t.Errorf("transaction timeout not recorded on the breakdown stream at all")
		}
	})

	// Genuine server-returned error → alarmable (base counter bumps).
	t.Run("genuine_error_alarms", func(t *testing.T) {
		reg := newTestReg(t, "test-ac-007")
		reg.recordResponseError(errors.New("server returned ECDH/decrypt failure"))
		counters, _ := reg.metrics.CountersForTest(t)
		if got := counters[MetricRegistrationFailure]; got != 1 {
			t.Errorf("base RegistrationFailure after genuine error: want 1 (alarmable), got %v", got)
		}
	})
}

// TestRecordServerConnectionFailure_EmitsBothBaseAndTypedCounters mirrors the
// alarmable registration test for the server_connection_failure alarm (#968):
// the base counter is the stream the alarm watches; the breakdown stream carries
// ErrorCode + ACId. All server-connection failures are alarmable (a failure to
// connect to an assigned server is a genuine fault), so there is no drop variant.
func TestRecordServerConnectionFailure_EmitsBothBaseAndTypedCounters(t *testing.T) {
	reg := newTestReg(t, "test-ac-002")

	reg.recordServerConnectionFailure(aws.String("timeout"))
	reg.recordServerConnectionFailure(aws.String("refused"))

	counters, dimCounters := reg.metrics.CountersForTest(t)

	if got := counters[MetricServerConnectionFailure]; got != 2 {
		t.Errorf("base ServerConnectionFailure counter: want 2, got %v", got)
	}

	// Two distinct ErrorCode values -> two breakdown streams, each tagged ACId.
	var breakdownStreams int
	for key := range dimCounters {
		if !strings.Contains(key, MetricServerConnectionFailure) {
			continue
		}
		if !strings.Contains(key, "ACId=test-ac-002") {
			t.Errorf("breakdown ServerConnectionFailure stream missing ACId dim: key=%q", key)
		}
		breakdownStreams++
	}
	if breakdownStreams != 2 {
		t.Errorf("ServerConnectionFailure breakdown streams: want 2, got %d", breakdownStreams)
	}
}
