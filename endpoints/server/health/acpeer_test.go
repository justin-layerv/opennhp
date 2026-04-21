package health

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockACPeerCounter is a test double for ACPeerCounter. Backing store
// is an atomic.Int32 so concurrent tests can flip the count between
// Check invocations without locks, and the in-range write is safe
// across the -race detector. Shared across acpeer_test.go and
// failure_injection_test.go — there is no mutex-based variant.
type mockACPeerCounter struct {
	count atomic.Int32
}

func (m *mockACPeerCounter) ACPeerCount() int {
	return int(m.count.Load())
}

// set overrides the current count. Kept as a method so failure-injection
// tests that mid-test flip the counter read as test state changes, not
// as direct atomic pokes.
func (m *mockACPeerCounter) set(n int) {
	m.count.Store(int32(n))
}

func newCounterAt(n int32) *mockACPeerCounter {
	c := &mockACPeerCounter{}
	c.count.Store(n)
	return c
}

// fakeClock returns the current value of an atomic.Int64 nanos.
type fakeClock struct{ nanos atomic.Int64 }

func (c *fakeClock) Now() time.Time { return time.Unix(0, c.nanos.Load()) }
func (c *fakeClock) Advance(d time.Duration) {
	c.nanos.Add(int64(d))
}

// fakeClockEpoch seeds fake-clock tests. Must be non-zero: the
// checker treats lastNonZeroAt == 0 as "never set", so a Unix-0
// seed would make first-seen timestamps indistinguishable from
// "never" and break the grace-window tests.
var fakeClockEpoch = time.Unix(1, 0)

// newCheckerWithFakeClock wires a checker to a fake clock seeded at a
// fixed time so the debounce-window tests don't depend on time.Now.
// Pass GracePeriod=-1 to disable debouncing; pass 0 to use the default.
func newCheckerWithFakeClock(t *testing.T, counter ACPeerCounter, gp time.Duration) (*ACPeerChecker, *fakeClock) {
	t.Helper()
	clk := &fakeClock{}
	clk.nanos.Store(fakeClockEpoch.UnixNano())
	c := NewACPeerChecker(&ACPeerCheckerConfig{
		Counter:     counter,
		GracePeriod: gp,
		now:         clk.Now,
	})
	return c, clk
}

func TestNewACPeerChecker(t *testing.T) {
	t.Parallel()

	c := NewACPeerChecker(&ACPeerCheckerConfig{
		Counter: newCounterAt(3),
	})
	if c.counter == nil {
		t.Error("counter should not be nil")
	}
	if c.gracePeriod != DefaultACPeerGracePeriod {
		t.Errorf("gracePeriod = %v, want default %v", c.gracePeriod, DefaultACPeerGracePeriod)
	}
}

func TestACPeerChecker_Name(t *testing.T) {
	t.Parallel()

	c := NewACPeerChecker(&ACPeerCheckerConfig{Counter: newCounterAt(0)})
	if c.Name() != "ac_peers" {
		t.Errorf("Name() = %q, want %q", c.Name(), "ac_peers")
	}
}

func TestACPeerChecker_IsCritical(t *testing.T) {
	t.Parallel()

	c := NewACPeerChecker(&ACPeerCheckerConfig{Counter: newCounterAt(0)})
	if !c.IsCritical() {
		t.Error("AC peer checker should be critical")
	}
}

func TestACPeerChecker_Check_NoCounter(t *testing.T) {
	t.Parallel()

	// Fake clock here is cosmetic — the skip path short-circuits
	// before touching either atomic or the grace window — but keeps
	// clock-injection discipline uniform across every test in this
	// file (per /simplify feedback).
	c, _ := newCheckerWithFakeClock(t, nil, 0)
	result := c.Check(context.Background())

	if result.Status != CheckStatusSkip {
		t.Errorf("status = %q, want %q", result.Status, CheckStatusSkip)
	}
	if result.Message != "AC peer counter not configured" {
		t.Errorf("message = %q, want 'AC peer counter not configured'", result.Message)
	}
}

func TestACPeerChecker_Check_HasPeers(t *testing.T) {
	t.Parallel()

	c := NewACPeerChecker(&ACPeerCheckerConfig{
		Counter: newCounterAt(5),
	})
	result := c.Check(context.Background())

	if result.Status != CheckStatusPass {
		t.Errorf("status = %q, want %q", result.Status, CheckStatusPass)
	}
	if result.Message != "5 AC peer(s) connected" {
		t.Errorf("message = %q, want '5 AC peer(s) connected'", result.Message)
	}
	if result.DurationMS < 0 {
		t.Errorf("DurationMS = %d, should be >= 0", result.DurationMS)
	}
}

func TestACPeerChecker_Check_OnePeer(t *testing.T) {
	t.Parallel()

	c := NewACPeerChecker(&ACPeerCheckerConfig{
		Counter: newCounterAt(1),
	})
	result := c.Check(context.Background())

	if result.Status != CheckStatusPass {
		t.Errorf("status = %q, want %q", result.Status, CheckStatusPass)
	}
	if result.Message != "1 AC peer(s) connected" {
		t.Errorf("message = %q, want '1 AC peer(s) connected'", result.Message)
	}
}

// TestACPeerChecker_Check_ZeroPeers_NoPriorState fences the cold-boot
// path: a server that has never seen a non-zero count must fail
// immediately on zero, not pretend to be in a grace window.
func TestACPeerChecker_Check_ZeroPeers_NoPriorState(t *testing.T) {
	t.Parallel()

	c, _ := newCheckerWithFakeClock(t, newCounterAt(0), 0)
	result := c.Check(context.Background())

	if result.Status != CheckStatusFail {
		t.Errorf("status = %q, want %q (no prior non-zero, no grace)", result.Status, CheckStatusFail)
	}
	if result.Message != "no AC peers connected" {
		t.Errorf("message = %q, want 'no AC peers connected'", result.Message)
	}
}

// TestACPeerChecker_Check_ZeroPeers_GraceDisabled fences the
// negative-GracePeriod escape hatch: legacy callers / tests can set it
// to skip debouncing entirely.
func TestACPeerChecker_Check_ZeroPeers_GraceDisabled(t *testing.T) {
	t.Parallel()

	counter := newCounterAt(3)
	c, clk := newCheckerWithFakeClock(t, counter, -1)

	// Establish prior non-zero so we know it isn't the no-prior path.
	if got := c.Check(context.Background()); got.Status != CheckStatusPass {
		t.Fatalf("setup: want pass on count=3, got %q", got.Status)
	}
	counter.set(0)
	clk.Advance(1 * time.Second)

	result := c.Check(context.Background())
	if result.Status != CheckStatusFail {
		t.Errorf("status = %q, want %q (grace disabled, must fail immediately)", result.Status, CheckStatusFail)
	}
}

// TestACPeerChecker_Check_GraceWindow_AbsorbsTransient is the lock
// for the actual sandbox failure: 1→0→1 over a single keepalive cycle
// must NOT flip /health/knock-ready to fail. The cached count appears
// in the message so the smoke regex (TestKnock_ReadyPerInstance...)
// keeps parsing m[1]="N" with N>0.
func TestACPeerChecker_Check_GraceWindow_AbsorbsTransient(t *testing.T) {
	t.Parallel()

	counter := newCounterAt(2)
	c, clk := newCheckerWithFakeClock(t, counter, 30*time.Second)

	if got := c.Check(context.Background()); got.Status != CheckStatusPass {
		t.Fatalf("setup: want pass on count=2, got %q (msg=%q)", got.Status, got.Message)
	}

	// Live count flips to 0; advance well within the grace window.
	counter.set(0)
	clk.Advance(15 * time.Second)

	result := c.Check(context.Background())
	if result.Status != CheckStatusPass {
		t.Fatalf("status = %q, want %q (count=0 within grace)", result.Status, CheckStatusPass)
	}
	if !strings.HasPrefix(result.Message, "2 AC peer(s) connected") {
		t.Errorf("message = %q, must start with cached count for smoke regex compatibility", result.Message)
	}
	if !strings.Contains(result.Message, "live=0") || !strings.Contains(result.Message, "grace") {
		t.Errorf("message = %q, must disclose live=0 + grace state for operators", result.Message)
	}
}

// TestACPeerChecker_Check_GraceWindow_FiresOnGraceAbsorbedCallback
// pins the MetricACGraceAbsorbed contract: the onGraceAbsorbed
// callback fires exactly when the grace-window branch returns pass,
// never on a real pass (live count > 0) or a real fail (grace
// expired). This is the hook CloudWatch monitoring uses to tell
// "debounce is absorbing flickers" apart from "AC cluster is broken
// and grace is hiding it"; a regression here makes the metric
// unreliable.
func TestACPeerChecker_Check_GraceWindow_FiresOnGraceAbsorbedCallback(t *testing.T) {
	t.Parallel()

	var absorbedCalls atomic.Int32
	counter := newCounterAt(2)
	clk := &fakeClock{}
	clk.nanos.Store(fakeClockEpoch.UnixNano())
	c := NewACPeerChecker(&ACPeerCheckerConfig{
		Counter:         counter,
		GracePeriod:     30 * time.Second,
		OnGraceAbsorbed: func() { absorbedCalls.Add(1) },
		now:             clk.Now,
	})

	// Seed lastNonZeroAt via a regular pass. Must NOT fire the callback
	// (callback is for grace-window path only).
	c.Check(context.Background())
	if got := absorbedCalls.Load(); got != 0 {
		t.Errorf("non-zero pass fired callback %d times, want 0", got)
	}

	// Grace-window pass. MUST fire the callback.
	counter.set(0)
	clk.Advance(15 * time.Second)
	c.Check(context.Background())
	if got := absorbedCalls.Load(); got != 1 {
		t.Errorf("grace-window pass fired callback %d times, want 1", got)
	}

	// Grace expired → fail. MUST NOT fire (live-zero past grace is
	// not an "absorbed transient").
	clk.Advance(30 * time.Second)
	c.Check(context.Background())
	if got := absorbedCalls.Load(); got != 1 {
		t.Errorf("grace-expired fail fired callback %d times (cumulative), want still 1", got)
	}
}

// TestACPeerChecker_Check_GraceWindow_NilCallbackIsSafe verifies the
// callback is optional — unit tests and any future caller without a
// metrics surface should be able to instantiate the checker without
// OnGraceAbsorbed and not panic on the grace path.
func TestACPeerChecker_Check_GraceWindow_NilCallbackIsSafe(t *testing.T) {
	t.Parallel()

	counter := newCounterAt(1)
	c, clk := newCheckerWithFakeClock(t, counter, 30*time.Second)
	// newCheckerWithFakeClock wires no OnGraceAbsorbed.
	c.Check(context.Background())
	counter.set(0)
	clk.Advance(10 * time.Second)

	// Must not panic even though callback is nil.
	if got := c.Check(context.Background()); got.Status != CheckStatusPass {
		t.Fatalf("grace-window pass with nil callback: got %q, want pass", got.Status)
	}
}

// TestACPeerChecker_Check_GraceWindow_BoundaryIsInclusive fences the
// `<=` choice at acpeer.go's grace-window comparison. Exactly
// gracePeriod must still pass; gracePeriod + 1ns must fail. Without
// this test the inclusive/exclusive choice would be incidental
// (the 15s/31s points in the other tests land nowhere near the
// boundary), and a future refactor to `<` would silently narrow the
// debounce window by up to one probe interval on the exact case
// the invariant tries to absorb (a flicker whose recovery lands
// right at the boundary).
func TestACPeerChecker_Check_GraceWindow_BoundaryIsInclusive(t *testing.T) {
	t.Parallel()

	const grace = 30 * time.Second

	counter := newCounterAt(1)
	c, clk := newCheckerWithFakeClock(t, counter, grace)
	c.Check(context.Background()) // seed lastNonZeroAt
	counter.set(0)

	// Exactly at the boundary — must pass.
	clk.Advance(grace)
	if got := c.Check(context.Background()); got.Status != CheckStatusPass {
		t.Fatalf("boundary (age == gracePeriod): got status=%q msg=%q, want pass — <=/< choice regressed",
			got.Status, got.Message)
	}

	// One nanosecond past — must fail.
	clk.Advance(time.Nanosecond)
	if got := c.Check(context.Background()); got.Status != CheckStatusFail {
		t.Fatalf("boundary + 1ns: got status=%q msg=%q, want fail",
			got.Status, got.Message)
	}
}

// TestACPeerChecker_Check_GraceWindow_FailsAfterExpiry fences the
// other side: a sustained zero past the grace window flips to fail
// honestly, so NLB and operators see the real state.
func TestACPeerChecker_Check_GraceWindow_FailsAfterExpiry(t *testing.T) {
	t.Parallel()

	counter := newCounterAt(1)
	c, clk := newCheckerWithFakeClock(t, counter, 30*time.Second)
	c.Check(context.Background()) // seed lastNonZeroAt

	counter.set(0)
	clk.Advance(31 * time.Second)

	result := c.Check(context.Background())
	if result.Status != CheckStatusFail {
		t.Errorf("status = %q, want %q (count=0 past grace)", result.Status, CheckStatusFail)
	}
	if result.Message != "no AC peers connected" {
		t.Errorf("message = %q, want 'no AC peers connected' once grace expires", result.Message)
	}
}

// TestACPeerChecker_Check_GraceWindow_RecoveryResetsClock fences that
// a transient blip-and-recover doesn't carry a "punishment" timer:
// after recovering to a non-zero count, the next blip gets a full
// fresh grace window.
func TestACPeerChecker_Check_GraceWindow_RecoveryResetsClock(t *testing.T) {
	t.Parallel()

	counter := newCounterAt(1)
	c, clk := newCheckerWithFakeClock(t, counter, 30*time.Second)
	c.Check(context.Background())

	// Blip 1: count=0 for 20s → still in grace (pass).
	counter.set(0)
	clk.Advance(20 * time.Second)
	if got := c.Check(context.Background()); got.Status != CheckStatusPass {
		t.Fatalf("blip 1 within grace: want pass, got %q", got.Status)
	}

	// Recover: count back to 1, advances lastNonZeroAt.
	counter.set(1)
	clk.Advance(1 * time.Second)
	if got := c.Check(context.Background()); got.Status != CheckStatusPass {
		t.Fatalf("recovery: want pass, got %q", got.Status)
	}

	// Blip 2: count=0 for 25s — must still be in grace because the
	// recovery reset the clock; without reset, total elapsed since
	// blip 1 (46s) would have failed this.
	counter.set(0)
	clk.Advance(25 * time.Second)
	if got := c.Check(context.Background()); got.Status != CheckStatusPass {
		t.Errorf("blip 2 within fresh grace: want pass, got %q (msg=%q)", got.Status, got.Message)
	}
}

// TestACPeerChecker_Check_GraceWindow_NegativeAgeClampsToZero fences
// the wall-clock-backward-jump edge case: if the wall clock steps
// backward (NTP adjustment, VM suspend/resume) between the non-zero
// write and a zero read, the raw age can be negative. We must clamp
// to zero so the rendered message stays a valid match for the smoke
// regex's \d+[^,]+ suffix — otherwise age.Round(time.Second) would
// emit "-Xs" and the suffix wouldn't parse.
func TestACPeerChecker_Check_GraceWindow_NegativeAgeClampsToZero(t *testing.T) {
	t.Parallel()

	counter := newCounterAt(3)
	c, clk := newCheckerWithFakeClock(t, counter, 30*time.Second)
	c.Check(context.Background()) // seed lastNonZeroAt

	// Simulate wall-clock step backward (e.g., NTP correction).
	counter.set(0)
	clk.Advance(-5 * time.Second)

	result := c.Check(context.Background())
	if result.Status != CheckStatusPass {
		t.Fatalf("status = %q, want %q (clamped-negative age is still within grace)",
			result.Status, CheckStatusPass)
	}
	// The specific assertion — no negative sign in the rendered age
	// component — fences the regex compatibility directly.
	if strings.Contains(result.Message, "-") {
		t.Errorf("message = %q, must not contain '-' (clamp should render age as 0s, not a negative)",
			result.Message)
	}
	if !strings.Contains(result.Message, "live=0 for 0s") {
		t.Errorf("message = %q, want clamped-age rendering 'live=0 for 0s'", result.Message)
	}
}

// TestACPeerChecker_Check_DefaultGraceApplied fences the default
// resolution: GracePeriod=0 in the config must produce
// DefaultACPeerGracePeriod, not "grace disabled".
func TestACPeerChecker_Check_DefaultGraceApplied(t *testing.T) {
	t.Parallel()

	c := NewACPeerChecker(&ACPeerCheckerConfig{Counter: newCounterAt(1)})
	if c.GracePeriod() != DefaultACPeerGracePeriod {
		t.Errorf("GracePeriod() = %v, want %v (zero config must default, not disable)",
			c.GracePeriod(), DefaultACPeerGracePeriod)
	}
}

// TestACPeerChecker_GracePeriodResolution fences the tri-valued
// config mapping in NewACPeerChecker: 0 → default, negative → disabled
// (internally 0), positive → as-is. Clamping against
// [MinACPeerGracePeriod, MaxACPeerGracePeriod] is the caller's
// responsibility (see server.acPeerGracePeriodFromConfig) so that the
// health package stays logger-free; the tests for that clamp live in
// httpserver_test.go.
func TestACPeerChecker_GracePeriodResolution(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		input     time.Duration
		wantGrace time.Duration
	}{
		{"zero → default", 0, DefaultACPeerGracePeriod},
		{"negative → disabled (0)", -time.Second, 0},
		{"positive → as-is (no clamp in this layer)", 2 * time.Second, 2 * time.Second},
		{"positive above Max → as-is (clamp is caller's job)", 10 * time.Minute, 10 * time.Minute},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewACPeerChecker(&ACPeerCheckerConfig{
				Counter:     newCounterAt(1),
				GracePeriod: tc.input,
			})
			if got := c.GracePeriod(); got != tc.wantGrace {
				t.Errorf("GracePeriod() = %v, want %v", got, tc.wantGrace)
			}
		})
	}
}

// TestACPeerChecker_DefaultTracksACKeepaliveWindow pins
// DefaultACPeerGracePeriod to the AC-side keepalive × retries window
// it was designed to track. If the AC side changes KeepaliveInterval
// or KeepaliveMaxRetries, this test fails — forcing the next
// contributor to decide whether the NHP-server default should move
// with it. Duplicating the constants here is cheaper than an import
// cycle (health -> ac).
func TestACPeerChecker_DefaultTracksACKeepaliveWindow(t *testing.T) {
	t.Parallel()

	// These mirror endpoints/ac/registration.go KeepaliveInterval (10s)
	// and KeepaliveMaxRetries (3). Package-internal constants so we
	// don't import the ac package. Cross-referenced by comment on
	// DefaultACPeerGracePeriod.
	const (
		acKeepaliveInterval   = 10 * time.Second
		acKeepaliveMaxRetries = 3
	)
	want := acKeepaliveInterval * acKeepaliveMaxRetries
	if DefaultACPeerGracePeriod != want {
		t.Errorf("DefaultACPeerGracePeriod = %v, want %v (AC-side %v × %d). "+
			"If the AC-side constants changed, decide whether the server-side grace "+
			"default should track them too.",
			DefaultACPeerGracePeriod, want, acKeepaliveInterval, acKeepaliveMaxRetries)
	}
}

func TestACPeerChecker_Interface(t *testing.T) {
	t.Parallel()

	// Verify ACPeerChecker implements Checker interface
	var _ Checker = (*ACPeerChecker)(nil)
}

// TestACPeerChecker_Check_ConcurrentRacesAgainstZeroTransition exercises
// the atomic-ordering invariant under real concurrency: 0 → N → 0 → N
// transitions flipped by one goroutine while many readers call Check
// from another. Run under -race; also asserts that no reader ever
// observes the message "0 AC peer(s) connected (cached, ...)" (the
// exact bug the write-order invariant prevents). -race catches the
// generic class implicitly, but this test pins the specific contract
// so a future contributor who reverses the Store order gets a fail
// with a clear diagnostic instead of a flaky unrelated race warning.
//
// Bounded by transition COUNT (not wall time) so the test doesn't
// silently pass on a starved CI runner that only managed to flip a
// handful of times in the budget. The flipper signals done after
// transitionCount full 0→N→0 cycles, then readers are stopped.
func TestACPeerChecker_Check_ConcurrentRacesAgainstZeroTransition(t *testing.T) {
	t.Parallel()

	const (
		readers         = 8
		transitionCount = 2000 // ~2000 0→N→0 cycles; fast even under -race
	)

	counter := newCounterAt(0)
	c, clk := newCheckerWithFakeClock(t, counter, 30*time.Second)

	stop := make(chan struct{})
	flipDone := make(chan struct{})
	var readersDone sync.WaitGroup
	readersDone.Add(readers)

	// One goroutine flips the count 0 → 1 → 0 → 2 → 0 ... for a fixed
	// number of cycles, advancing the fake clock a fraction of the
	// grace window each step so the zero/grace path is consistently
	// exercised. When the loop completes we close flipDone; readers
	// stop on stop, which is closed AFTER flipDone fires.
	go func() {
		defer close(flipDone)
		next := int32(1)
		for i := 0; i < transitionCount; i++ {
			counter.set(int(next))
			clk.Advance(50 * time.Microsecond)
			counter.set(0)
			clk.Advance(50 * time.Microsecond)
			next++
			if next > 5 {
				next = 1
			}
		}
	}()

	// N reader goroutines hammer Check(). We care about two invariants:
	//   - no panic / no -race report (the Go runtime catches these)
	//   - no cached-count message ever renders with m[1] == "0" — that
	//     would mean the writer published lastNonZeroAt before
	//     lastNonZeroCount and a reader sandwiched in between observed
	//     the initial zero count.
	for i := 0; i < readers; i++ {
		go func() {
			defer readersDone.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r := c.Check(context.Background())
				if r.Status == CheckStatusPass && strings.HasPrefix(r.Message, "0 AC peer(s) connected (cached") {
					t.Errorf("reader observed cached-zero: %q — write-order invariant violated", r.Message)
					return
				}
			}
		}()
	}

	<-flipDone
	close(stop)
	readersDone.Wait()
}
