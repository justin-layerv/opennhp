package ac

// These tests fence the recoverUDPHandler function itself — the
// interface seam the goroutines in recvMessageRoutine rely on. They
// do NOT drive recvMessageRoutine end-to-end with a fault-injected
// handler, so if a future refactor inlines the goroutine body or
// changes the spawn shape so that `defer a.recoverUDPHandler` is no
// longer at the goroutine entry, every test in this file will keep
// passing while the production seam is silently bypassed. Catching
// that regression requires a smoke-suite test against the deployed
// binary (tracked in #1656) or a handler-level test that drives
// recvMessageRoutine — both intentionally out of scope here, since
// the alternative (fault-inject hooks in HandleUdpACOperations) would
// couple every handler refactor to this test file.
//
// Production spawn sites the recover discipline lives at:
//   - udpac.go::recvMessageRoutine, NHP_AOP arm — grep for
//     `defer a.recoverUDPHandler(core.NHP_AOP)`
//   - udpac.go::recvMessageRoutine, NHP_ARD arm — grep for
//     `defer a.recoverUDPHandler(core.NHP_ARD)`
//
// TestRecoverUDPHandler_NilMetricsPublisherSafe relies on
// metrics.Publisher.IncrCounter's nil-receiver guard — see
// endpoints/metrics/publisher.go (search for `if mp == nil { return }`
// inside IncrCounter). If that guard is ever moved or removed, this
// test transitions from "fences nil-safety" to "panics in CI"; the
// link between the two is documented but not enforced.

import (
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// TestRecoverUDPHandler_AbsorbsPanicAndIncrementsMetric is the regression
// fence for nhp#1423: a panic in any per-packet UDP message-handler
// goroutine must NOT crash nhp-acd. Before the fix, every call site on
// the AC's UDP path (HandleUdpACOperations → HandleAccessControl →
// IssueACTokenIfSuccess → common.GenerateOpaqueToken, plus the NHP_ARD
// path) was unguarded, so a single panic on any per-request goroutine
// would tear down all in-flight knock transactions on the instance and
// trigger an ASG instance refresh.
//
// recoverUDPHandler is the interface seam the issue calls for: invoking
// it via `defer` from a goroutine that panics is a faithful proxy for
// the production path, with the additional benefit that we don't need
// to reach into the deeper handlers to inject a fault. The seam itself
// is what guarantees the goroutine returns gracefully.
//
// Two assertions:
//  1. The panicking goroutine returns normally — the test's local
//     wg.Wait()-after-Done proves the panic did not propagate past
//     the recover seam. The companion test
//     TestRecoverUDPHandler_PanicReleasesUdpACWaitGroup exercises
//     production UdpAC.wg accounting end-to-end (Add → goroutine
//     panic → recover → Done → Wait returns).
//  2. The MetricUDPHandlerPanic counter incremented by exactly 1 —
//     the signal the CloudWatch alarm in
//     terraform/modules/ac/monitoring.tf observes.
func TestRecoverUDPHandler_AbsorbsPanicAndIncrementsMetric(t *testing.T) {
	a := &UdpAC{
		config: &Config{ACId: "test-ac"},
		registration: &ACRegistration{
			metrics: metrics.NewPublisherForTest(t),
		},
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer a.recoverUDPHandler(core.NHP_AOP)
		panic("synthetic UDP-handler fault")
	}()

	// If recoverUDPHandler ever stops eating the panic, the test process
	// terminates here instead of returning from wg.Wait — making the
	// regression visible as an outright test crash, not a soft assertion
	// failure.
	wg.Wait()

	counters, _ := a.registration.metrics.CountersForTest(t)
	if got := counters[MetricUDPHandlerPanic]; got != 1 {
		t.Fatalf("MetricUDPHandlerPanic = %v, want 1 — the alarm in monitoring.tf observes this counter", got)
	}
}

// TestRecoverUDPHandler_PanicReleasesUdpACWaitGroup pins the
// production wg-accounting contract: Stop() blocks on UdpAC.wg.Wait()
// after closing signals.stop, so a goroutine that panics and is
// recovered by recoverUDPHandler MUST still decrement UdpAC.wg or
// Stop() deadlocks forever. The actual invariant is that BOTH
// `defer a.wg.Done()` and `defer a.recoverUDPHandler(...)` are at
// the goroutine entry — not nested inside the handler. Whichever
// order they're declared, Go's defer LIFO runs every deferred
// function on the way out, so wg.Done fires regardless; the
// production order (wg.Done first → recover second, so LIFO runs
// recover first) is convention, not correctness. This test mirrors
// that exact shape and asserts wg.Wait() returns within a tight
// deadline.
func TestRecoverUDPHandler_PanicReleasesUdpACWaitGroup(t *testing.T) {
	a := &UdpAC{
		config: &Config{ACId: "test-ac"},
		registration: &ACRegistration{
			metrics: metrics.NewPublisherForTest(t),
		},
	}

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer a.recoverUDPHandler(core.NHP_AOP)
		panic("synthetic UDP-handler fault inside wg-tracked goroutine")
	}()

	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// wg.Wait returned, contract upheld
	case <-time.After(2 * time.Second):
		t.Fatal("UdpAC.wg.Wait() did not return after a recovered panic — Stop() would deadlock in production")
	}
}

// TestRecoverUDPHandler_RepeatedPanicsIncrementMonotonically pins
// the in-process contract that the panic counter accumulates across
// successive recover invocations on a single Publisher instance —
// not just records the first panic. The test calls 5 times and
// asserts counter == 5; it does NOT exercise CloudWatch's flush
// window (publishers reset between flushes by design, and that's
// the right behavior for `Sum`-statistic alarms). The regression
// being fenced is "the recover handler resets the counter between
// invocations," which would silently break a sustained-panic alarm
// even though the metric appears in CloudWatch each window.
func TestRecoverUDPHandler_RepeatedPanicsIncrementMonotonically(t *testing.T) {
	a := &UdpAC{
		config: &Config{ACId: "test-ac"},
		registration: &ACRegistration{
			metrics: metrics.NewPublisherForTest(t),
		},
	}

	const panics = 5
	for i := 0; i < panics; i++ {
		func() {
			defer a.recoverUDPHandler(core.NHP_AOP)
			panic("synthetic UDP-handler fault (repeated)")
		}()
	}

	counters, _ := a.registration.metrics.CountersForTest(t)
	if got := counters[MetricUDPHandlerPanic]; got != panics {
		t.Fatalf("MetricUDPHandlerPanic = %v, want %d (counter must monotonically track every recovered panic)", got, panics)
	}
}

// TestRecoverUDPHandler_ConcurrentPanicsAreThreadSafe pins the
// correctness contract that every concurrent panic increments the
// counter: in production multiple per-packet goroutines can panic
// and recover simultaneously, so a regression that loses increments
// under contention (e.g. a non-atomic counter, or any read-modify-
// write that drops samples) must fail this test even if it produces
// no data race. N goroutines each panic-and-recover, the counter
// must equal exactly N.
//
// Under `go test -race` this also catches a stricter regression: a
// future refactor that swapped Publisher.IncrCounter's mutex for a
// PLAIN (non-atomic, non-locking) counter would surface as a race
// report on the counter map's writes. `atomic.Uint64` is race-free
// by construction and would NOT trip -race — only the unconditional
// "every increment is observed" assertion catches that path.
func TestRecoverUDPHandler_ConcurrentPanicsAreThreadSafe(t *testing.T) {
	a := &UdpAC{
		config: &Config{ACId: "test-ac"},
		registration: &ACRegistration{
			metrics: metrics.NewPublisherForTest(t),
		},
	}

	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			defer a.recoverUDPHandler(core.NHP_AOP)
			panic("synthetic UDP-handler fault (concurrent)")
		}()
	}
	wg.Wait()

	counters, _ := a.registration.metrics.CountersForTest(t)
	if got := counters[MetricUDPHandlerPanic]; got != goroutines {
		t.Fatalf("MetricUDPHandlerPanic = %v, want %d (every concurrent panic must be counted)", got, goroutines)
	}
}

// TestRecoverUDPHandler_NoPanicIsNoOp pins the contract that
// recoverUDPHandler does not record a phantom panic on the happy path.
// A flaky alarm here would page operators after every benign UDP packet
// — the opposite of the signal we want.
func TestRecoverUDPHandler_NoPanicIsNoOp(t *testing.T) {
	a := &UdpAC{
		config: &Config{ACId: "test-ac"},
		registration: &ACRegistration{
			metrics: metrics.NewPublisherForTest(t),
		},
	}

	// Mirror the production spawn shape (defer from inside a goroutine
	// wrapper) even on the no-panic path. The function body is small
	// today and `recover()` returns nil whether called via defer or
	// not, but if a future refactor adds non-recover work to the
	// function that depends on being in a defer context, this test
	// would catch it instead of silently regressing.
	func() {
		defer a.recoverUDPHandler(core.NHP_AOP)
	}()

	counters, _ := a.registration.metrics.CountersForTest(t)
	if _, ok := counters[MetricUDPHandlerPanic]; ok {
		// Stricter than `got != 0` — fail if the metric was
		// emitted at all on the happy path. A future regression
		// that incremented by 0 (or any phantom write) would
		// otherwise sneak past the previous comparison.
		t.Fatalf("MetricUDPHandlerPanic was emitted on the happy path; counters=%v", counters)
	}
}

// TestRecoverUDPHandler_NilRegistrationSafe pins the defense-in-depth
// nil-safety contract for the recover seam. In production a.registration
// is set in Start() before recvMessageRoutine is spawned (see udpac.go
// `a.registration = ...` at the top of Start before `go a.recvMessageRoutine()`),
// so the field is non-nil for every per-packet goroutine. This test
// fences the recover handler's behavior under the test-fixture / future-
// refactor case where that ordering invariant is broken: the recover
// must still absorb the panic — losing the metric increment is the
// lesser evil compared to crashing the AC.
func TestRecoverUDPHandler_NilRegistrationSafe(t *testing.T) {
	a := &UdpAC{
		config: &Config{ACId: "test-ac"},
		// registration intentionally nil
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("recoverUDPHandler must absorb panic when registration is nil; got propagated panic: %v", r)
		}
	}()

	func() {
		defer a.recoverUDPHandler(core.NHP_ARD)
		panic("synthetic fault during early startup")
	}()
}

// TestRecoverUDPHandler_NilMetricsPublisherSafe pins the second
// nil-safety contract: a non-nil ACRegistration with a nil metrics
// publisher (a state that briefly exists during Stop, and that the
// metrics package guarantees is safe to call into via `Publisher.IncrCounter`'s
// nil-receiver check) must not turn the panic-recover into a
// secondary panic. Together with the registration-nil case above,
// this fences both ways the metric increment can be a no-op without
// the recover itself becoming a fault site.
func TestRecoverUDPHandler_NilMetricsPublisherSafe(t *testing.T) {
	a := &UdpAC{
		config:       &Config{ACId: "test-ac"},
		registration: &ACRegistration{
			// metrics intentionally nil — Publisher.IncrCounter is
			// nil-safe on the receiver, so the recover handler's
			// only job is to not deref it.
		},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("recoverUDPHandler must absorb panic when metrics publisher is nil; got propagated panic: %v", r)
		}
	}()

	func() {
		defer a.recoverUDPHandler(core.NHP_AOP)
		panic("synthetic fault while metrics publisher is nil")
	}()
}

// TestRecoverUDPHandler_NilConfigSafe pins the third nil-safety
// contract: the recover handler reads a.config.ACId for the log
// breadcrumb, and a panic inside this deferred handler is itself
// unrecovered and would kill the process — exactly what this PR
// exists to prevent. In production a.config is set during AC startup
// and never nilled, but the asymmetric value of being defensive at
// this seam means the wrapper falls back to a sentinel ACId rather
// than dereferencing a nil pointer.
func TestRecoverUDPHandler_NilConfigSafe(t *testing.T) {
	a := &UdpAC{
		// config intentionally nil
		registration: &ACRegistration{
			metrics: metrics.NewPublisherForTest(t),
		},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("recoverUDPHandler must absorb panic when config is nil; got propagated panic: %v", r)
		}
	}()

	func() {
		defer a.recoverUDPHandler(core.NHP_AOP)
		panic("synthetic fault while config is nil")
	}()

	counters, _ := a.registration.metrics.CountersForTest(t)
	if got := counters[MetricUDPHandlerPanic]; got != 1 {
		t.Fatalf("MetricUDPHandlerPanic = %v, want 1 (the metric must still increment when config is nil)", got)
	}
}
