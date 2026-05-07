package ac

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// pkgFileBytes reads `relPath` resolved against the directory of this
// test source file (via runtime.Caller), so the lookup is robust to
// `t.Chdir` or non-package-directory test invocations. Used by source-
// grep fences that cross-reference production files or smoke tests.
func pkgFileBytes(t *testing.T, relPath string) []byte {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot resolve test file path")
	}
	pkgDir := filepath.Dir(thisFile)
	full := filepath.Join(pkgDir, relPath)
	src, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("read %s: %v", full, err)
	}
	return src
}

// stopRegLater closes the registration's stopCh on test cleanup so that
// any goroutine spawned by TriggerReregistration is released, even when
// the test fails before reaching its own close() call.
func stopRegLater(t *testing.T, reg *ACRegistration) {
	t.Helper()
	t.Cleanup(func() {
		select {
		case <-reg.stopCh:
		default:
			close(reg.stopCh)
		}
	})
}

// newResilienceAC builds a minimal UdpAC suitable for the resilience
// unit tests. The sendMsgCh buffer is generous so the goroutines
// TriggerReregistration spawns can dispatch the registration message
// without ever blocking the test.
func newResilienceAC(acID string) *UdpAC {
	return &UdpAC{
		config: &Config{
			ACId:           acID,
			ServerEndpoint: "server.nhp.test.internal",
			// Provide a non-empty private key so the per-AC jitter
			// derivation has a stable input. The string is bogus —
			// the resilience layer never decodes it.
			PrivateKeyBase64: "test-private-key-" + acID,
		},
		sendMsgCh: make(chan *core.MsgData, 10),
	}
}

// TestCheckAllUnconnected_NoServersResetsCounter — when there are no
// assigned servers (initial bootstrap, post-stop), the detector must
// reset its counter rather than carry stale state across registration
// cycles.
func TestCheckAllUnconnected_NoServersResetsCounter(t *testing.T) {
	reg := mustNewACRegistration(t, newResilienceAC("no-servers"))
	stopRegLater(t, reg)

	reg.allUnconnectedTicks.Store(5)
	reg.assignedServers = []*AssignedServer{}

	reg.checkAllUnconnected()

	if got := reg.allUnconnectedTicks.Load(); got != 0 {
		t.Errorf("allUnconnectedTicks = %d, want 0 (counter must reset when there are no servers)", got)
	}
	if reg.reregistering.Load() {
		t.Error("re-registration must not trigger when there are no assigned servers")
	}
}

// TestCheckAllUnconnected_OneConnectedServerResetsCounter — a single
// connected server is enough evidence the AC has a working path; the
// detector must NOT trip just because some other entries are still
// unconnected.
func TestCheckAllUnconnected_OneConnectedServerResetsCounter(t *testing.T) {
	reg := mustNewACRegistration(t, newResilienceAC("partial-conn"))
	stopRegLater(t, reg)

	connected := &AssignedServer{
		Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "k1"},
	}
	connected.SetConnected(true)
	connected.UpdateLastSeen()

	dead := &AssignedServer{
		Target: common.RedirectTarget{IP: "10.0.0.2", Port: DefaultServerPort, PubKeyBase64: "k2"},
	}

	reg.assignedServers = []*AssignedServer{connected, dead}
	reg.allUnconnectedTicks.Store(7)

	reg.checkAllUnconnected()

	if got := reg.allUnconnectedTicks.Load(); got != 0 {
		t.Errorf("allUnconnectedTicks = %d, want 0 after observing a connected server", got)
	}
	if reg.reregistering.Load() {
		t.Error("re-registration must not trigger when at least one server is connected")
	}
}

// TestCheckAllUnconnected_TriggersExactlyOnceAtThreshold — the detector
// must trip a re-registration on the tick that crosses the configured
// threshold, must reset the counter, and must NOT clear the
// assignedServers slice. The "do not clear" assertion is the regression
// guard against the original PR #867 patch-6 issue: if checkAllUnconnected
// nullifies the slice itself, a HandleRedispatch that just installed
// fresh servers between the snapshot and the cleanup loses them.
func TestCheckAllUnconnected_TriggersExactlyOnceAtThreshold(t *testing.T) {
	reg := mustNewACRegistration(t, newResilienceAC("threshold"))
	stopRegLater(t, reg)

	// Force a deterministic threshold so the test isn't dependent on
	// the per-AC jitter that NewACRegistration computed.
	reg.allUnconnectedThreshold = 3

	srv := &AssignedServer{
		Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "k1"},
	}
	reg.assignedServers = []*AssignedServer{srv}

	// First two ticks should accumulate but not trigger.
	reg.checkAllUnconnected()
	if got := reg.allUnconnectedTicks.Load(); got != 1 {
		t.Errorf("after tick 1: allUnconnectedTicks = %d, want 1", got)
	}
	if reg.reregistering.Load() {
		t.Fatal("re-registration triggered too early (tick 1)")
	}

	reg.checkAllUnconnected()
	if got := reg.allUnconnectedTicks.Load(); got != 2 {
		t.Errorf("after tick 2: allUnconnectedTicks = %d, want 2", got)
	}
	if reg.reregistering.Load() {
		t.Fatal("re-registration triggered too early (tick 2)")
	}

	// Third tick crosses the threshold and trips re-registration.
	reg.checkAllUnconnected()

	if got := reg.allUnconnectedTicks.Load(); got != 0 {
		t.Errorf("after threshold trip: allUnconnectedTicks = %d, want 0 (counter must reset)", got)
	}
	if !reg.reregistering.Load() {
		t.Error("re-registration must be triggered after threshold reached")
	}

	// CRUCIAL: assignedServers must NOT be cleared by the detector.
	// Recovery is the re-registration path's job, not ours, and
	// clearing here races with HandleRedispatch.
	reg.mu.RLock()
	count := len(reg.assignedServers)
	reg.mu.RUnlock()
	if count != 1 {
		t.Errorf("assignedServers length = %d, want 1 (detector must NOT clear the slice)", count)
	}
}

// TestCheckAllUnconnected_DoesNotClobberConcurrentHandleRedispatch is
// the regression test for the patch-6 race in PR #867: a concurrent
// HandleRedispatch installing a fresh set of valid servers must not be
// silently overwritten by checkAllUnconnected. We simulate the scenario
// by having the detector trip while a goroutine concurrently replaces
// assignedServers, and assert the freshly-installed servers survive.
func TestCheckAllUnconnected_DoesNotClobberConcurrentHandleRedispatch(t *testing.T) {
	reg := mustNewACRegistration(t, newResilienceAC("clobber"))
	stopRegLater(t, reg)
	reg.allUnconnectedThreshold = 1 // trip on the very first tick

	// Initial: one unconnected server. The detector will see this set
	// and (under the buggy patch-6 implementation) try to nuke it.
	reg.assignedServers = []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "stale"}},
	}

	// Fresh servers a concurrent HandleRedispatch would install.
	fresh := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.1.1", Port: DefaultServerPort, PubKeyBase64: "fresh-1"}},
		{Target: common.RedirectTarget{IP: "10.0.1.2", Port: DefaultServerPort, PubKeyBase64: "fresh-2"}},
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine A: the resilience detector running on the keepalive
	// loop's tick. It snapshots the slice, sees all-unconnected,
	// triggers re-registration.
	go func() {
		defer wg.Done()
		reg.checkAllUnconnected()
	}()

	// Goroutine B: a concurrent HandleRedispatch (or any other path
	// that calls into the registration manager) atomically installing
	// a brand-new server set under the write lock.
	go func() {
		defer wg.Done()
		reg.mu.Lock()
		reg.assignedServers = fresh
		reg.mu.Unlock()
	}()

	wg.Wait()

	reg.mu.RLock()
	got := reg.assignedServers
	reg.mu.RUnlock()

	if len(got) != 2 {
		t.Fatalf("len(assignedServers) = %d, want 2 (the fresh set must survive the concurrent detector)", len(got))
	}
	for i, want := range []string{"fresh-1", "fresh-2"} {
		if got[i].Target.PubKeyBase64 != want {
			t.Errorf("assignedServers[%d].Target.PubKeyBase64 = %q, want %q (the detector must not clobber a concurrent HandleRedispatch)",
				i, got[i].Target.PubKeyBase64, want)
		}
	}
}

// TestCheckPeriodicNLBReregistration_DoesNotTriggerWithinInterval — the
// safety net must wait at least one interval before firing.
func TestCheckPeriodicNLBReregistration_DoesNotTriggerWithinInterval(t *testing.T) {
	reg := mustNewACRegistration(t, newResilienceAC("periodic-recent"))
	stopRegLater(t, reg)
	reg.nlbReregistrationInterval = 30 * time.Minute
	reg.lastNLBRegistrationNano.Store(time.Now().UnixNano())
	reg.assignedServers = []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "k1"}},
	}

	reg.checkPeriodicNLBReregistration()

	if reg.reregistering.Load() {
		t.Error("periodic NLB re-registration must not fire within the interval")
	}
}

// TestCheckPeriodicNLBReregistration_DoesNotTriggerWithoutAssignedServers
// — without any assigned servers, the bootstrap registrationLoop is
// still running. We must not race with it.
func TestCheckPeriodicNLBReregistration_DoesNotTriggerWithoutAssignedServers(t *testing.T) {
	reg := mustNewACRegistration(t, newResilienceAC("periodic-empty"))
	stopRegLater(t, reg)
	reg.nlbReregistrationInterval = 30 * time.Minute
	// Pretend the last registration was a long time ago.
	reg.lastNLBRegistrationNano.Store(time.Now().Add(-2 * time.Hour).UnixNano())
	reg.assignedServers = []*AssignedServer{}

	reg.checkPeriodicNLBReregistration()

	if reg.reregistering.Load() {
		t.Error("periodic NLB re-registration must not fire while assignedServers is empty (initial bootstrap is still running)")
	}
}

// TestCheckPeriodicNLBReregistration_TriggersAfterInterval — once the
// configured interval has elapsed and there are servers to reach, the
// safety net trips a re-registration.
func TestCheckPeriodicNLBReregistration_TriggersAfterInterval(t *testing.T) {
	reg := mustNewACRegistration(t, newResilienceAC("periodic-due"))
	stopRegLater(t, reg)
	reg.nlbReregistrationInterval = 30 * time.Minute
	reg.lastNLBRegistrationNano.Store(time.Now().Add(-2 * time.Hour).UnixNano())
	reg.assignedServers = []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "k1"}},
	}

	reg.checkPeriodicNLBReregistration()

	if !reg.reregistering.Load() {
		t.Error("periodic NLB re-registration must trip after the interval has elapsed")
	}
}

// TestResilienceJitterFactor_StableForSameInputs — the per-AC jitter
// must be deterministic so a restart of the same AC picks the same
// interval as before. Otherwise the whole point of fleet jitter is
// defeated: a coordinated restart would re-randomize every AC's
// schedule.
func TestResilienceJitterFactor_StableForSameInputs(t *testing.T) {
	a := resilienceJitterFactor("ac-001", "private-key-aaa")
	b := resilienceJitterFactor("ac-001", "private-key-aaa")
	if a != b {
		t.Errorf("resilienceJitterFactor not deterministic: got %v then %v", a, b)
	}
}

// TestResilienceJitterFactor_DifferentInputsProduceDifferentJitter
// — two ACs with different identities must end up at different points
// in the jitter range. The factor only has to differ; we do not
// constrain by how much (a strict bound would just be a tautology of
// SHA-256's output distribution).
func TestResilienceJitterFactor_DifferentInputsProduceDifferentJitter(t *testing.T) {
	cases := []struct {
		acID, key string
	}{
		{"ac-001", "key-a"},
		{"ac-002", "key-a"},
		{"ac-001", "key-b"},
		{"ac-009", "key-z"},
	}
	seen := make(map[float64]string, len(cases))
	for _, c := range cases {
		f := resilienceJitterFactor(c.acID, c.key)
		if f < -1.0 || f > 1.0 {
			t.Errorf("resilienceJitterFactor(%q,%q) = %v, want value in [-1, +1]", c.acID, c.key, f)
		}
		if prev, ok := seen[f]; ok {
			t.Errorf("resilienceJitterFactor collision: (%q,%q) and %s both produced %v",
				c.acID, c.key, prev, f)
		}
		seen[f] = c.acID + "/" + c.key
	}
}

// TestComputeNLBReregistrationInterval_BoundsAndJitter — the helper
// must respect the configured override, never collapse below the
// minimum even with worst-case negative jitter, and apply the per-AC
// jitter inside the configured fraction.
func TestComputeNLBReregistrationInterval_BoundsAndJitter(t *testing.T) {
	t.Run("uses default when configSeconds is zero", func(t *testing.T) {
		got := computeNLBReregistrationInterval(0, 0)
		if got != DefaultNLBReregistrationInterval {
			t.Errorf("got %v, want %v", got, DefaultNLBReregistrationInterval)
		}
	})

	t.Run("clamps tiny config values up to minimum", func(t *testing.T) {
		// Use a base well below MinNLBReregistrationInterval so the
		// clamp is actually exercised, regardless of how the floor is
		// retuned over time. Worst-case negative jitter would otherwise
		// produce a value far below the floor.
		got := computeNLBReregistrationInterval(5, -1.0)
		if got < MinNLBReregistrationInterval {
			t.Errorf("got %v, want >= %v (lower bound must be enforced after jitter)",
				got, MinNLBReregistrationInterval)
		}
	})

	t.Run("max negative jitter never collapses to a tiny value", func(t *testing.T) {
		// Even with worst-case negative jitter against the default,
		// the result must be at least MinNLBReregistrationInterval.
		got := computeNLBReregistrationInterval(0, -1.0)
		if got < MinNLBReregistrationInterval {
			t.Errorf("got %v, want >= %v", got, MinNLBReregistrationInterval)
		}
	})

	t.Run("max positive jitter stays within configured fraction", func(t *testing.T) {
		base := DefaultNLBReregistrationInterval
		got := computeNLBReregistrationInterval(0, 1.0)
		// The hard upper bound is base * (1 + fraction).
		upper := time.Duration(float64(base) * (1.0 + NLBReregistrationJitterFraction))
		if got > upper {
			t.Errorf("got %v, want <= %v (jitter must be bounded by configured fraction)",
				got, upper)
		}
	})

	t.Run("zero jitter returns the configured base", func(t *testing.T) {
		base := 45 * time.Minute
		got := computeNLBReregistrationInterval(int(base/time.Second), 0)
		if got != base {
			t.Errorf("got %v, want %v", got, base)
		}
	})

	t.Run("config in previously-clamped band is now active", func(t *testing.T) {
		// PR #1726 lowered MinNLBReregistrationInterval from 5min to
		// 30s. Operator configs in the [60s, 300s) band that were
		// previously silently clamped up to 300s now take effect
		// verbatim. Lock that contract change in: a future floor bump
		// that re-shadows this band would silently revert the change
		// without firing this test.
		const configSeconds = 120
		got := computeNLBReregistrationInterval(configSeconds, 0)
		want := time.Duration(configSeconds) * time.Second
		if got != want {
			t.Errorf("got %v, want %v — operator configs in the previously-clamped "+
				"60-300s band must take effect verbatim post-PR #1726", got, want)
		}
	})
}

// TestComputeAllUnconnectedThreshold_BoundsAndJitter — same as the
// interval helper but in tick units. The detector must never round
// down below MinAllUnconnectedThreshold and must spread the fleet
// across the configured ticks ± jitter range.
func TestComputeAllUnconnectedThreshold_BoundsAndJitter(t *testing.T) {
	t.Run("uses default when configTicks is zero", func(t *testing.T) {
		got := computeAllUnconnectedThreshold(0, 0)
		if got != uint32(DefaultAllUnconnectedThreshold) {
			t.Errorf("got %d, want %d", got, DefaultAllUnconnectedThreshold)
		}
	})

	t.Run("max negative jitter never collapses below minimum", func(t *testing.T) {
		got := computeAllUnconnectedThreshold(0, -1.0)
		if got < uint32(MinAllUnconnectedThreshold) {
			t.Errorf("got %d, want >= %d", got, MinAllUnconnectedThreshold)
		}
	})

	t.Run("clamps below-minimum config values up to minimum", func(t *testing.T) {
		got := computeAllUnconnectedThreshold(1, 0)
		if got < uint32(MinAllUnconnectedThreshold) {
			t.Errorf("got %d, want >= %d", got, MinAllUnconnectedThreshold)
		}
	})

	t.Run("max positive jitter stays within configured fraction", func(t *testing.T) {
		base := 10
		got := computeAllUnconnectedThreshold(base, 1.0)
		// Upper bound is rounded(base * (1 + fraction)).
		upper := uint32(math.Round(float64(base) * (1.0 + NLBReregistrationJitterFraction)))
		if got > upper {
			t.Errorf("got %d, want <= %d", got, upper)
		}
	})
}

// TestNewACRegistration_PopulatesResilienceFields — the constructor
// must wire the jittered values into the struct so the keepalive loop
// uses them. Without this, a config override would be silently dropped.
func TestNewACRegistration_PopulatesResilienceFields(t *testing.T) {
	ac := newResilienceAC("populate")
	ac.config.NLBReregistrationIntervalSeconds = 600 // 10 minutes
	ac.config.AllUnconnectedThresholdTicks = 5

	reg := mustNewACRegistration(t, ac)
	stopRegLater(t, reg)

	if reg.nlbReregistrationInterval == 0 {
		t.Error("nlbReregistrationInterval must be set on construction")
	}
	if reg.nlbReregistrationInterval < MinNLBReregistrationInterval {
		t.Errorf("nlbReregistrationInterval = %v, must be >= %v",
			reg.nlbReregistrationInterval, MinNLBReregistrationInterval)
	}
	if reg.allUnconnectedThreshold == 0 {
		t.Error("allUnconnectedThreshold must be set on construction")
	}
	if reg.allUnconnectedThreshold < uint32(MinAllUnconnectedThreshold) {
		t.Errorf("allUnconnectedThreshold = %d, must be >= %d",
			reg.allUnconnectedThreshold, MinAllUnconnectedThreshold)
	}
}

// TestClassifyReason_NewResilienceReasons — the new reason constants
// must be passed through classifyReason rather than collapsing to
// "other", which would erase the dimension distinction in CloudWatch.
func TestClassifyReason_NewResilienceReasons(t *testing.T) {
	for _, r := range []string{ReasonAllServersUnconnected, ReasonPeriodicNLBRefresh} {
		if got := classifyReason(r); got != r {
			t.Errorf("classifyReason(%q) = %q, want pass-through", r, got)
		}
	}
}

// blueGreenDeployGateWindow mirrors the *default* of
// post_switch_knock_ready_timeout_minutes — declared in
// .github/workflows/blue-green-deploy.yml and consumed by
// .github/scripts/verify-knock-ready.sh as KNOCK_READY_TIMEOUT_MINUTES
// (the script itself takes the value as a required positional and
// has no built-in default). There is no compile-time link to the
// workflow value — keep in sync by hand; this test catches drift
// against the default.
const blueGreenDeployGateWindow = 5 * time.Minute

// blueGreenDeployGateMinimum is the workflow's lower bound on
// post_switch_knock_ready_timeout_minutes (input bounds check in
// .github/workflows/blue-green-deploy.yml). 3 min is the minimum
// that fits the AC NLB safety net's worst-case fire interval
// (112.5 s default + 25% jitter) plus the gate's own convergence
// cost (~12-20 s) inside the budget — see PR #1726. Fences the
// override regime so a future PR that bumps the workflow's lower
// bound below this value, or that retunes the safety-net default
// past it, fails before shipping.
const blueGreenDeployGateMinimum = 3 * time.Minute

// blueGreenGateConvergenceCost is the cost the gate adds *after* the
// safety net fires: 2 consecutive all-ready iterations with ~10 s
// inter-iteration sleep + handshake RTT — empirically ~12-20 s.
// Subtracted from the budget in
// `worst_case_fire_plus_convergence_fits_workflow_minimum_gate`.
const blueGreenGateConvergenceCost = 20 * time.Second

// TestNLBReregistration_BoundedByDeployGate — fences the relationship
// between the periodic NLB re-registration safety net and the
// blue/green deploy gate window. The worst-case interval must be
// strictly less than the gate so a stale-color latch heals before
// the gate times out. A future PR that retunes either constant past
// the gate fails this test before it ships.
//
// Split into subtests so a CI failure points at the specific
// invariant rather than requiring the reader to walk the stack frame.
//
// Regression fence for PR #1726.
func TestNLBReregistration_BoundedByDeployGate(t *testing.T) {
	// Anchor against the production helper so a future refactor of
	// the jitter formula is fenced here too, not just in
	// TestComputeNLBReregistrationInterval_BoundsAndJitter.
	// Computed once here and reused across subtests intentionally —
	// `computeNLBReregistrationInterval` is a pure function of its
	// inputs (the worst-case-jitter knob is fixed at +1.0), so a
	// captured value cannot stale during this test's execution. If
	// any future subtest mutates package-level state that affects
	// the helper (e.g., a hypothetical config-reload test), recompute
	// inside that subtest.
	worstCase := computeNLBReregistrationInterval(0, 1.0)
	worstCaseNegJitter := time.Duration(float64(DefaultNLBReregistrationInterval) *
		(1.0 - NLBReregistrationJitterFraction))

	t.Run("worst_case_fits_default_gate", func(t *testing.T) {
		if worstCase >= blueGreenDeployGateWindow {
			t.Fatalf("worst-case NLB re-registration interval = %v (default %v + %.0f%% jitter), "+
				"must be < blue/green deploy gate %v — see "+
				".github/scripts/verify-knock-ready.sh and DefaultNLBReregistrationInterval",
				worstCase, DefaultNLBReregistrationInterval,
				NLBReregistrationJitterFraction*100, blueGreenDeployGateWindow)
		}
	})

	t.Run("worst_case_fire_plus_convergence_fits_workflow_minimum_gate", func(t *testing.T) {
		// Fence the override regime: the worst-case fire interval *plus*
		// the gate's own 2-iteration convergence cost (2 × ~10 s sleep
		// + handshake RTT, empirically ~12-20 s) must fit inside the
		// workflow's lower bound. Otherwise an operator dispatching at
		// the workflow minimum is outside the safety net's coverage.
		// PR #1726 raised the workflow lower bound from 2 to 3 min so
		// this assertion is load-bearing today; before the bump it was
		// t.Skip'd because 132.5s > 120s.
		fullConvergenceBudget := worstCase + blueGreenGateConvergenceCost
		if fullConvergenceBudget >= blueGreenDeployGateMinimum {
			deficit := fullConvergenceBudget - blueGreenDeployGateMinimum
			t.Fatalf("worst-case fire interval + gate convergence cost = %v + %v = %v >= "+
				"workflow gate minimum %v (deficit: %v over budget) — operator dispatches "+
				"at the workflow lower bound would be unprotected for full convergence. "+
				"Levers: lower DefaultNLBReregistrationInterval, lower "+
				"NLBReregistrationJitterFraction, lower blueGreenGateConvergenceCost "+
				"(after a verify-knock-ready.sh refactor), or raise the workflow's "+
				"lower bound.",
				worstCase, blueGreenGateConvergenceCost, fullConvergenceBudget,
				blueGreenDeployGateMinimum, deficit)
		}
	})

	t.Run("floor_does_not_shadow_negative_jitter_range", func(t *testing.T) {
		// worstCaseNegJitter is computed by hand (not via
		// computeNLBReregistrationInterval(0, -1.0)) deliberately:
		// the helper applies the post-jitter floor, which would
		// trivially satisfy `Min > worstCaseNegJitter` (both equal
		// the floor) and break this assertion's "would the floor
		// shadow the default's negative-jitter range?" semantics.
		// The hand-computed PRE-floor expression catches the case
		// where Min crawls above Default×(1−JitterFraction).
		//
		// The floor must not exceed the default after worst-case
		// negative jitter — otherwise an unconfigured AC's
		// negatively-jittered default gets clamped UP to the floor,
		// defeating the "floor catches operator misconfig, default
		// is the normal operating point" intent.
		if MinNLBReregistrationInterval > worstCaseNegJitter {
			t.Fatalf("MinNLBReregistrationInterval %v > worst-case negatively-jittered default %v — "+
				"the floor would override the default for ACs with negative jitter",
				MinNLBReregistrationInterval, worstCaseNegJitter)
		}
	})

	t.Run("floor_fits_workflow_minimum_gate", func(t *testing.T) {
		// The floor must also be strictly less than the workflow
		// minimum so operator overrides clamped to the floor still
		// satisfy the most aggressive gate dispatch.
		if MinNLBReregistrationInterval >= blueGreenDeployGateMinimum {
			t.Fatalf("MinNLBReregistrationInterval %v >= workflow gate minimum %v",
				MinNLBReregistrationInterval, blueGreenDeployGateMinimum)
		}
	})

	t.Run("floor_does_not_collapse_below_keepalive", func(t *testing.T) {
		// MinNLBReregistrationInterval's docstring warns that going
		// below ~3 × KeepaliveInterval risks dogpiling under network
		// blips even with the single-flight CAS in TriggerReregistration.
		// Lock that documented multiplier at compile time — a future
		// PR that pushes the floor below 3 × keepalive re-introduces
		// the dogpile class the floor was added to prevent.
		minMultiplier := 3 * KeepaliveInterval
		if MinNLBReregistrationInterval < minMultiplier {
			t.Fatalf("MinNLBReregistrationInterval %v < 3 × KeepaliveInterval (%v) — floor "+
				"below the documented dogpile-prevention multiplier; the periodic loop "+
				"would race the keepalive loop's per-server reconnect under network blips. "+
				"See MinNLBReregistrationInterval's docstring; either bump the floor or "+
				"relax the docstring claim in the same PR.",
				MinNLBReregistrationInterval, minMultiplier)
		}
	})
}

// methodBody parses the named Go source file and returns the body
// (between the opening `{` and the matching closing `}`, exclusive of
// the braces) of the method `(*recvType).methodName`. Uses go/parser
// + ast.Inspect rather than a brace-depth scanner so string literals
// and comments containing `{` or `}` cannot shift the bounds, and so
// the test does not impose any literal-content constraints on the
// production code.
func methodBody(t *testing.T, src []byte, recvType, methodName string) string {
	t.Helper()
	fset := token.NewFileSet()
	// SkipObjectResolution is a perf hint, not a correctness requirement —
	// we only need positions, not symbol resolution, so skip the
	// identifier-binding pass.
	file, err := parser.ParseFile(fset, "registration.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse registration.go: %v", err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name.Name != methodName {
			continue
		}
		if !methodHasReceiver(fn, recvType) {
			continue
		}
		start := fset.Position(fn.Body.Lbrace).Offset + 1 // skip past the opening `{`
		end := fset.Position(fn.Body.Rbrace).Offset       // up to but not including `}`
		return string(src[start:end])
	}
	t.Fatalf("could not locate (*%s).%s in registration.go — function renamed? "+
		"the smoke fence in tests/smoke/01_ac_nlb_reregistration_cadence_test.go "+
		"depends on the log line emitted from this function",
		recvType, methodName)
	panic("unreachable") // t.Fatalf calls runtime.Goexit; this satisfies the compiler.
}

// methodHasReceiver reports whether fn's receiver is `*recvType`.
// (Both `(r *ACRegistration)` and `(*ACRegistration)` parse to the
// same shape: a single field whose Type is a `*ast.StarExpr` whose
// X is an `*ast.Ident` with name `recvType`.)
func methodHasReceiver(fn *ast.FuncDecl, recvType string) bool {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return false
	}
	star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	ident, ok := star.X.(*ast.Ident)
	return ok && ident.Name == recvType
}

// TestCheckPeriodicNLBReregistration_LogFormatStable fences the log
// substring the smoke fence in
// tests/smoke/01_ac_nlb_reregistration_cadence_test.go depends on.
// A reword or removal of the log line in
// checkPeriodicNLBReregistration would silently degrade the smoke
// fence to a 0-match-always pass during burn-in; this unit test
// turns that into a loud failure on the same PR.
//
// Source-level grep rather than runtime stdout-capture: the
// production logger writes through AsyncLogWriter (a goroutine that
// reads os.Stdout), so redirecting stdout in a test races with
// that goroutine under -race. A source-file grep is race-free,
// catches the rename / removal cases the reviewer flagged, and is
// faster than a runtime fence. Function-body bounding uses
// go/parser + ast.Inspect so string literals or comments containing
// `{`/`}` inside the function cannot shift the search window — and
// so the production code carries no literal-content constraint just
// to satisfy this test.
//
// Anchored against periodicNLBRefreshLogSubstring (production
// constant) rather than a duplicated literal: a refactor that
// reformats the log line must update the constant, which lights up
// both this fence and (via the smoke test's matching regex) the
// runtime fence in lockstep.
//
// Regression fence for PR #1726 (paired with the smoke test of the
// same regression class).
func TestCheckPeriodicNLBReregistration_LogFormatStable(t *testing.T) {
	src := pkgFileBytes(t, "registration.go")
	fnBody := methodBody(t, src, "ACRegistration", "checkPeriodicNLBReregistration")

	// The log line is constructed by concatenation against
	// periodicNLBRefreshLogSubstring, so the function body should
	// reference the const symbol. Asserting on the symbol (not the
	// literal value) is what couples this fence to the production
	// constant: a refactor that drops the symbol from this function
	// loses the smoke-fence emission and the unit test catches it.
	const refMarker = "periodicNLBRefreshLogSubstring"
	if !strings.Contains(fnBody, refMarker) {
		t.Fatalf("checkPeriodicNLBReregistration body does not reference %s — the smoke fence in "+
			"tests/smoke/01_ac_nlb_reregistration_cadence_test.go matches on the constant's value; "+
			"reword in lockstep or land #1714's structured tag first",
			refMarker)
	}

	// Also assert the constant's value matches what the smoke test
	// regex looks for. A constant rename without a smoke regex
	// update would otherwise pass this fence and silently degrade
	// the smoke fence.
	const wantValue = "periodic NLB re-registration triggered"
	if periodicNLBRefreshLogSubstring != wantValue {
		t.Fatalf("periodicNLBRefreshLogSubstring = %q, smoke fence expects %q — "+
			"update tests/smoke/01_ac_nlb_reregistration_cadence_test.go's regex in lockstep",
			periodicNLBRefreshLogSubstring, wantValue)
	}

	// Two-way coupling: also assert the smoke test's CWLogs Insights
	// regex literal matches the production constant. Without this, a
	// future PR that updates the production constant + this unit test
	// in lockstep but forgets to update the smoke regex would silently
	// degrade the smoke fence to 0-match-always. The structural fix
	// (#1714) replaces the duplicated literal with a structured-tag
	// scan; this is the bridge.
	const smokeRel = "../../tests/smoke/01_ac_nlb_reregistration_cadence_test.go"
	smokeSrc := pkgFileBytes(t, smokeRel)
	if !strings.Contains(string(smokeSrc), wantValue) {
		t.Fatalf("smoke test %s does not contain expected literal %q — production constant "+
			"and smoke regex have drifted; update both in lockstep or land #1714's "+
			"structured-tag work to retire the duplication",
			smokeRel, wantValue)
	}
}
