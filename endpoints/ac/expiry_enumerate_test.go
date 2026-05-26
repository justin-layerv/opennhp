package ac

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestEnumerateAndScheduleFlushes_NoOpWhenFeatureOff fences the
// disabled-feature short-circuit: if no scheduler is constructed
// (a.expirySched == nil), enumeration must return nil without
// touching kernel state. Without this, every AC that runs with
// EnableL3FlushOnExpiry=false would still try to enumerate ipset
// at boot — a regression that breaks the no-op-when-off contract.
func TestEnumerateAndScheduleFlushes_NoOpWhenFeatureOff(t *testing.T) {
	a := &UdpAC{expirySched: nil}
	if err := a.enumerateAndScheduleFlushes(); err != nil {
		t.Errorf("expected nil error with scheduler off; got %v", err)
	}
}

// TestEnumerateAndScheduleFlushes_FailClosed_OnEnumeratorError
// fences the synchronous-fail-closed-boot contract: if the
// underlying enumerator returns an error, the wrapper must
// propagate it (wrapped with elapsed-time context). UdpAC.Start()
// surfaces this error and refuses to admit traffic — the safety
// primitive that prevents the AC from admitting sessions whose
// kernel state we cannot guarantee to tear down.
//
// Exercised via the enumerateFn injection hook so the contract is
// fenced on EVERY platform CI runs on, not just non-Linux (an
// earlier version of this test runtime-skipped on Linux, which
// silently masked the gating signal — caught by the silent-failure
// pattern fence in my own feedback memory). Regression fence for
// cr round 2.
func TestEnumerateAndScheduleFlushes_FailClosed_OnEnumeratorError(t *testing.T) {
	a := &UdpAC{}
	sched := NewScheduler(&NoOpFlusher{})
	sched.Start()
	defer func() { _ = sched.Shutdown(context.Background()) }()
	a.expirySched = sched

	sentinel := errors.New("injected enumerator failure")
	a.enumerateFn = func() (int, error) { return 0, sentinel }

	err := a.enumerateAndScheduleFlushes()
	if err == nil {
		t.Fatal("expected fail-closed error from injected enumerator; got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel error; got %v", err)
	}
	if !strings.Contains(err.Error(), "L3 flush boot enumeration failed") {
		t.Errorf("expected wrapped error to start with 'L3 flush boot enumeration failed'; got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "after") {
		t.Errorf("expected wrapped error to include elapsed-time context ('after ...'); got %q", err.Error())
	}
}

// TestEnumerateAndScheduleFlushes_PropagatesCount fences the
// success-path observable: a successful enumeration must log the
// count (we don't intercept the log here; verifying the wrapper
// doesn't error and the injected enumerator is called is the fence
// that catches a refactor breaking the dispatch).
func TestEnumerateAndScheduleFlushes_PropagatesCount(t *testing.T) {
	a := &UdpAC{}
	sched := NewScheduler(&NoOpFlusher{})
	sched.Start()
	defer func() { _ = sched.Shutdown(context.Background()) }()
	a.expirySched = sched

	called := 0
	a.enumerateFn = func() (int, error) {
		called++
		return 42, nil
	}
	if err := a.enumerateAndScheduleFlushes(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if called != 1 {
		t.Errorf("enumerateFn called %d times; want 1", called)
	}
}

// TestEnumerateAndScheduleFlushes_PartialEnumeration fences the
// case where the enumerator returns (positive count, nil error) —
// e.g., the iptables path successfully enumerated V4 but the V6
// set didn't exist (errIpsetSetNotFound swallowed by the V6
// fallback in enumerateKernelAllowRules). The wrapper must
// propagate the count and treat partial-success as success
func TestEnumerateAndScheduleFlushes_PartialEnumeration(t *testing.T) {
	a := &UdpAC{}
	sched := NewScheduler(&NoOpFlusher{})
	sched.Start()
	defer func() { _ = sched.Shutdown(context.Background()) }()
	a.expirySched = sched

	// Simulate V4 enumerated 1000 entries; V6 absent (swallowed).
	a.enumerateFn = func() (int, error) { return 1000, nil }

	if err := a.enumerateAndScheduleFlushes(); err != nil {
		t.Errorf("partial enumeration (V4 ok, V6 absent → swallowed) should not error; got %v", err)
	}
}
