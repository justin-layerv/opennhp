package server

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// Tests for the MaxConcurrentHandlers bound on dispatchReceivedMessage
// (#3086 / upstream OpenNHP bc499d7c H2). They double as the load-test
// evidence the issue asks for: TestDispatchHandler_CapsInFlightAndSheds
// drives a flood far exceeding the budget through the real dispatch
// chokepoint and asserts (a) concurrent handlers never exceed the cap,
// (b) the excess is shed rather than blocking the caller (the #1163
// non-blocking property), and (c) every shed ticks
// MetricHandlerBudgetExhausted. The wiring tests fence which arms are
// bounded (agent-facing) vs. deliberately unbounded (IP-gated infra).

// waitFor polls cond until it holds or timeout elapses. Used instead of
// a fixed sleep so the tests track goroutine scheduling without flaking
// on slow CI. (time.Now/Sleep are ordinary Go — the workflow-engine ban
// on Date.now does not apply here.)
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("condition %q not met within %s", what, timeout)
}

// newTestServerWithHandlerBudget builds a minimal UdpServer whose
// handler budget is `budget`. Only the fields dispatchHandler touches
// are wired (metrics + handlerSem); no device, listener, or maps.
func newTestServerWithHandlerBudget(t *testing.T, budget int) *UdpServer {
	t.Helper()
	return &UdpServer{
		metrics:    metrics.NewPublisherForTest(t),
		handlerSem: make(chan struct{}, budget),
	}
}

func newTestServerWithPartitionedHandlerBudget(t *testing.T, general, protected int) *UdpServer {
	t.Helper()
	return &UdpServer{
		metrics:             metrics.NewPublisherForTest(t),
		handlerSem:          make(chan struct{}, general),
		protectedHandlerSem: make(chan struct{}, protected),
	}
}

// TestDispatchHandler_CapsInFlightAndSheds is the core load-test fence.
// A flood of `flood` dispatches, each running a handler that parks until
// released, must (1) never block the dispatch loop, (2) run exactly
// `budget` handlers concurrently, (3) shed the remaining flood-budget
// synchronously with a matching MetricHandlerBudgetExhausted count, and
// (4) free slots on completion so a later dispatch acquires again.
func TestDispatchHandler_CapsInFlightAndSheds(t *testing.T) {
	const budget = 8
	const flood = 500 // far exceeds the budget: the flood we're bounding
	s := newTestServerWithHandlerBudget(t, budget)

	release := make(chan struct{})
	var inFlight atomic.Int64
	blockingFn := func(_ *core.PacketParserData) error {
		inFlight.Add(1)
		<-release
		inFlight.Add(-1)
		return nil
	}

	ppd := newDispatchPPD(core.NHP_KNK, `{}`)

	// (1) Non-blocking: a blocking acquire would deadlock this loop,
	// since nothing releases until close(release) below. Run it under a
	// deadline so a #1163 regression trips cleanly instead of hanging.
	loopDone := make(chan struct{})
	go func() {
		for i := 0; i < flood; i++ {
			s.dispatchHandler(ppd, blockingFn)
		}
		close(loopDone)
	}()
	select {
	case <-loopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatchHandler blocked under flood — acquire is not non-blocking (#1163 regression)")
	}

	// (3) Sheds are synchronous in the dispatch loop, so the count is
	// exact the instant the loop returns: everything past the budget.
	wantShed := int64(flood - budget)
	if got := s.handlerShedCount.Load(); got != wantShed {
		t.Fatalf("handlerShedCount = %d, want %d", got, wantShed)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if got := counters[MetricHandlerBudgetExhausted]; got != float64(wantShed) {
		t.Fatalf("MetricHandlerBudgetExhausted = %v, want %d", got, wantShed)
	}

	// (2) Exactly `budget` handlers are concurrently in-flight — the cap
	// is fully utilized and never exceeded (only `budget` goroutines were
	// ever spawned).
	waitFor(t, 2*time.Second, "all budget handlers in-flight",
		func() bool { return inFlight.Load() == budget })

	// (4) Release; slots drain back to empty, then a fresh dispatch
	// acquires a freed slot and runs. Wait on the semaphore length (not a
	// handler-side counter) so we observe the deferred slot release, not
	// just handler return.
	close(release)
	waitFor(t, 2*time.Second, "handler slots freed",
		func() bool { return len(s.handlerSem) == 0 })

	ran := make(chan struct{})
	s.dispatchHandler(ppd, func(_ *core.PacketParserData) error { close(ran); return nil })
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch after release did not run — slot was not freed on completion")
	}
	if got := s.handlerShedCount.Load(); got != wantShed {
		t.Fatalf("handlerShedCount changed after a slot was freed: got %d, want %d", got, wantShed)
	}
}

func TestDispatchHandler_ProtectedReservePreservesRKNProgress(t *testing.T) {
	const general = 4
	s := newTestServerWithPartitionedHandlerBudget(t, general, 2)
	generalRelease := make(chan struct{})
	generalEntered := make(chan struct{}, general)
	for i := 0; i < general; i++ {
		s.dispatchHandler(newDispatchPPD(core.NHP_KNK, `{}`), func(*core.PacketParserData) error {
			generalEntered <- struct{}{}
			<-generalRelease
			return nil
		})
	}
	for i := 0; i < general; i++ {
		select {
		case <-generalEntered:
		case <-time.After(2 * time.Second):
			t.Fatal("general handler did not enter")
		}
	}
	if !s.handlerOverload.Load() {
		t.Fatal("full general partition did not enable overload-cookie mode")
	}

	// An ordinary KNK cannot consume the reserve.
	s.dispatchHandler(newDispatchPPD(core.NHP_KNK, `{}`), func(*core.PacketParserData) error {
		t.Error("unproven KNK ran from protected reserve")
		return nil
	})
	if got := s.handlerShedCount.Load(); got != 1 {
		t.Fatalf("unproven KNK sheds = %d, want 1", got)
	}

	// A core-verified RKN can still make progress through the reserve.
	rknRan := make(chan struct{})
	s.dispatchHandler(newDispatchPPD(core.NHP_RKN, `{}`), func(*core.PacketParserData) error {
		close(rknRan)
		return nil
	})
	select {
	case <-rknRan:
	case <-time.After(2 * time.Second):
		t.Fatal("cookie-proven RKN did not run from protected reserve")
	}
	waitFor(t, 2*time.Second, "protected RKN slot released", func() bool {
		return len(s.protectedHandlerSem) == 0
	})

	// An authenticated exact-session EXT is the teardown path for an existing
	// admission. It must retain progress under the same saturated general
	// partition; its protected body is strictly mirrored to the outer type by
	// HandleKnockRequest before any close authority is used.
	extRan := make(chan struct{})
	s.dispatchHandler(newDispatchPPD(core.NHP_EXT, `{}`), func(*core.PacketParserData) error {
		close(extRan)
		return nil
	})
	select {
	case <-extRan:
	case <-time.After(2 * time.Second):
		t.Fatal("exact-session EXT did not run from protected reserve")
	}
	waitFor(t, 2*time.Second, "protected EXT slot released", func() bool {
		return len(s.protectedHandlerSem) == 0
	})

	close(generalRelease)
	waitFor(t, 2*time.Second, "handler pressure recovered", func() bool {
		return !s.handlerOverload.Load() && len(s.handlerSem) == 0
	})
}

func TestDispatchHandler_ProtectedReserveExhaustionIsDistinct(t *testing.T) {
	s := newTestServerWithPartitionedHandlerBudget(t, 1, 1)
	release := make(chan struct{})
	entered := make(chan struct{}, 2)
	block := func(*core.PacketParserData) error {
		entered <- struct{}{}
		<-release
		return nil
	}
	s.dispatchHandler(newDispatchPPD(core.NHP_KNK, `{}`), block)
	<-entered
	s.dispatchHandler(newDispatchPPD(core.NHP_RKN, `{}`), block)
	<-entered

	s.dispatchHandler(newDispatchPPD(core.NHP_RKN, `{}`), func(*core.PacketParserData) error {
		t.Error("RKN ran after both handler partitions were full")
		return nil
	})
	counters, _ := s.metrics.CountersForTest(t)
	if got := counters[MetricHandlerBudgetExhausted]; got != 1 {
		t.Fatalf("%s = %v, want 1", MetricHandlerBudgetExhausted, got)
	}
	if got := counters[MetricHandlerProtectedReserveExhausted]; got != 1 {
		t.Fatalf("%s = %v, want 1", MetricHandlerProtectedReserveExhausted, got)
	}
	close(release)
	waitFor(t, 2*time.Second, "partitioned handlers released", func() bool {
		return len(s.handlerSem)+len(s.protectedHandlerSem) == 0
	})
}

func TestProtectedHandlerTypes(t *testing.T) {
	for _, headerType := range []int{core.NHP_RKN, core.NHP_RLY, core.NHP_EXT} {
		if !isProtectedHandlerType(headerType) {
			t.Errorf("%s must be protected", core.HeaderTypeToString(headerType))
		}
	}
	for _, headerType := range []int{core.NHP_KNK, core.DHP_KNK, core.NHP_OTP} {
		if isProtectedHandlerType(headerType) {
			t.Errorf("%s must not consume protected capacity", core.HeaderTypeToString(headerType))
		}
	}
}

// TestDispatchHandler_NilSemUnbounded fences the test-only affordance:
// a nil handlerSem spawns every handler (no bound, no shed). Guards the
// many bare &UdpServer{} literals in the suite against a nil-channel
// deadlock.
func TestDispatchHandler_NilSemUnbounded(t *testing.T) {
	s := &UdpServer{metrics: metrics.NewPublisherForTest(t)} // nil handlerSem
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	var ran atomic.Int64
	ppd := newDispatchPPD(core.NHP_KNK, `{}`)
	for i := 0; i < n; i++ {
		s.dispatchHandler(ppd, func(_ *core.PacketParserData) error {
			ran.Add(1)
			wg.Done()
			return nil
		})
	}
	waitWG(t, &wg, 2*time.Second)
	if ran.Load() != n {
		t.Fatalf("nil-sem dispatch ran %d handlers, want %d (unbounded fallback)", ran.Load(), n)
	}
	if got := s.handlerShedCount.Load(); got != 0 {
		t.Fatalf("nil-sem dispatch shed %d, want 0 (no budget to exhaust)", got)
	}
}

func TestDispatchHandler_RegistersShutdownOwnershipBeforeLaunch(t *testing.T) {
	s := newTestServerWithHandlerBudget(t, 1)
	entered := make(chan struct{})
	release := make(chan struct{})
	s.dispatchHandler(newDispatchPPD(core.NHP_RLY, `{}`), func(_ *core.PacketParserData) error {
		close(entered)
		<-release
		return nil
	})
	<-entered
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("shutdown barrier returned while the dispatched relay handler was blocked")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown barrier did not observe the dispatched relay handler exit")
	}
}

func TestDispatchAsync_RegistersShutdownOwnershipBeforeLaunch(t *testing.T) {
	s := &UdpServer{}
	entered := make(chan struct{})
	release := make(chan struct{})
	s.dispatchAsync(func() {
		close(entered)
		<-release
	})
	<-entered
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("shutdown barrier returned while the trusted-peer handler was blocked")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown barrier did not observe the trusted-peer handler exit")
	}
}

// TestDispatchHandler_ReleasesSlotOnError fences that a bounded handler
// whose fn returns a non-nil error still frees its budget slot. The
// release rides a defer so it's structurally covered, but without this a
// handler that always errors would leak the whole budget into a
// permanent shed. Budget of 1 makes it deterministic: the second
// dispatch can only run if the first (erroring) handler freed its slot.
func TestDispatchHandler_ReleasesSlotOnError(t *testing.T) {
	s := newTestServerWithHandlerBudget(t, 1)
	ppd := newDispatchPPD(core.NHP_KNK, `{}`)

	// First dispatch takes the only slot and its handler errors.
	s.dispatchHandler(ppd, func(_ *core.PacketParserData) error { return errors.New("boom") })
	waitFor(t, 2*time.Second, "slot freed after error-returning handler",
		func() bool { return len(s.handlerSem) == 0 })

	// The freed slot must be reacquirable — a second dispatch runs, not sheds.
	ran := make(chan struct{})
	s.dispatchHandler(ppd, func(_ *core.PacketParserData) error { close(ran); return nil })
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("second dispatch did not run — the error-returning handler leaked its slot")
	}
	if got := s.handlerShedCount.Load(); got != 0 {
		t.Fatalf("shed %d — slot not freed on the error path", got)
	}
}

// TestDispatchReceivedMessage_AgentArmsRouteThroughBudget fences that
// every agent-facing arm consults the handler budget. With the budget
// pre-saturated, dispatching each type must shed. The deterministic,
// LOCALIZED failure signal is handlerShedCount==1: an arm that regressed
// to a bare `go` spawn would leave shed==0 and fail this assertion right
// here. (Such a regression would also spawn the real handler, which
// panics on the bare server's nil fields — a secondary, non-localized
// signal we deliberately don't rely on; the shed-count check trips first.)
func TestDispatchReceivedMessage_AgentArmsRouteThroughBudget(t *testing.T) {
	agentArms := []int{
		core.NHP_KNK, core.NHP_RKN, core.NHP_EXT, core.DHP_KNK,
		core.NHP_OTP, core.NHP_REG, core.NHP_LST,
		core.NHP_DAR, core.NHP_DRG, core.NHP_DAV,
		core.NHP_RLY,
	}
	for _, ht := range agentArms {
		ht := ht
		t.Run(core.HeaderTypeToString(ht), func(t *testing.T) {
			const budget = 4
			s := newTestServerWithHandlerBudget(t, budget)
			for i := 0; i < budget; i++ {
				s.handlerSem <- struct{}{} // saturate
			}
			s.dispatchReceivedMessage(newDispatchPPD(ht, `{}`))

			if got := s.handlerShedCount.Load(); got != 1 {
				t.Fatalf("%s with full budget: handlerShedCount = %d, want 1 (arm must route through dispatchHandler)",
					core.HeaderTypeToString(ht), got)
			}
			counters, _ := s.metrics.CountersForTest(t)
			if got := counters[MetricHandlerBudgetExhausted]; got != 1 {
				t.Fatalf("%s shed metric = %v, want 1", core.HeaderTypeToString(ht), got)
			}
		})
	}
}

// TestDispatchReceivedMessage_InfraArmsBypassBudget fences that infra
// arms are NOT gated by the budget: with the budget saturated they still
// spawn (bare `go`, never dispatchHandler) and never shed. Covers all
// five infra arms. AOL/DOL park on a held map mutex (the async_dispatch
// idiom) so the spawned handler can't race into nil UdpServer fields;
// FWD/FRT/RVA each json.Unmarshal their body first, so an invalid body
// makes the spawned handler early-return without touching server state.
// FWD in particular is the expensive unbounded arm (same buildKnockAck +
// AC-open pipeline as a direct knock), so a wiring assertion that it does
// NOT consume a handler slot is load-bearing.
func TestDispatchReceivedMessage_InfraArmsBypassBudget(t *testing.T) {
	// saturateBudget gives s a budget of 1 and fills it, so any arm that
	// routed through dispatchHandler would shed (bumping handlerShedCount).
	saturateBudget := func(s *UdpServer) {
		s.handlerSem = make(chan struct{}, 1)
		s.handlerSem <- struct{}{}
	}

	// AOL/DOL: park the spawned handler on its first mutex.
	t.Run("AOL", func(t *testing.T) {
		s := newTestServerForDispatch(t)
		saturateBudget(s)
		s.acPeerMapMutex.Lock()
		assertDispatchReturnsPromptly(t, s, newDispatchPPD(core.NHP_AOL, `{"acId":"x"}`), dispatchAssertDeadline)
		if got := s.handlerShedCount.Load(); got != 0 {
			t.Fatalf("NHP_AOL shed %d with a full budget — infra arm must bypass the budget", got)
		}
	})
	t.Run("DOL", func(t *testing.T) {
		s := newTestServerForDispatch(t)
		saturateBudget(s)
		s.dbPeerMapMutex.Lock()
		assertDispatchReturnsPromptly(t, s, newDispatchPPD(core.NHP_DOL, `{"dbId":"x"}`), dispatchAssertDeadline)
		if got := s.handlerShedCount.Load(); got != 0 {
			t.Fatalf("NHP_DOL shed %d with a full budget — infra arm must bypass the budget", got)
		}
	})

	// FWD/FRT/RVA: invalid body → handler early-returns at json.Unmarshal.
	// The shed accounting is synchronous in dispatchReceivedMessage, so the
	// handlerShedCount==0 assertion holds regardless of the spawned
	// goroutine's progress.
	for _, ht := range []int{core.NHP_FWD, core.NHP_FRT, core.NHP_RVA} {
		ht := ht
		t.Run(core.HeaderTypeToString(ht), func(t *testing.T) {
			s := newTestServerForDispatch(t)
			saturateBudget(s)
			s.dispatchReceivedMessage(newDispatchPPD(ht, `not-json`))
			if got := s.handlerShedCount.Load(); got != 0 {
				t.Fatalf("%s shed %d with a full budget — infra arm must bypass the budget",
					core.HeaderTypeToString(ht), got)
			}
		})
	}
}

// waitWG waits for wg with a deadline so a stuck handler trips a clean
// failure instead of hanging until go test's global timeout.
func waitWG(t *testing.T, wg *sync.WaitGroup, timeout time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatalf("waitgroup not done within %s", timeout)
	}
}
