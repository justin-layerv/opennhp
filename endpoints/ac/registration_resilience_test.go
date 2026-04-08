package ac

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

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
		got := computeNLBReregistrationInterval(60, -1.0) // 1 minute base, max negative jitter
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
