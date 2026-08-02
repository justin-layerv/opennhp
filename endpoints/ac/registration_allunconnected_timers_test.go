package ac

import (
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
)

// The Phase 0D all-unconnected timer state machine — the episode timer
// (allUnconnectedSinceNano) vs the per-window timer (allUnconnectedWindowStartNano),
// and the DurationMs/RecoveryMs emissions — churned across several #2999 review
// rounds fixing real bugs: episode-age over-reporting on a re-trip (fixed by the
// per-window timer), an episode-timer leak across the empty-assignment branch,
// and RecoveryMs only firing on the next healthy tick (fixed by calling
// markAllUnconnectedRecovered at the re-reg success sites). These tests pin that
// machine directly so it can't regress silently. They assert timer set/clear and
// latency emission rather than absolute durations, so they're time-robust.

// unconnectedAssignedServer returns an assigned server that reports
// IsConnected()==false (no SetConnected/UpdateLastSeen), so a set of them drives
// checkAllUnconnected toward the threshold.
func unconnectedAssignedServer(ip, key string) *AssignedServer {
	return &AssignedServer{
		Target: common.RedirectTarget{IP: ip, Port: testServerListenPort, PubKeyBase64: key},
	}
}

// TestCheckAllUnconnected_SetsTimersAndEmitsDurationMs — the 0->1 edge opens the
// episode (both timers set, detector counter fires once, no latency yet); the
// threshold edge emits DurationMs once, resets the tick counter, trips
// re-registration, and leaves the episode timer open (recovery owns closing it).
func TestCheckAllUnconnected_SetsTimersAndEmitsDurationMs(t *testing.T) {
	reg := mustNewACRegistration(t, newResilienceAC("timers-duration"))
	stopRegLater(t, reg)
	reg.metrics = metrics.NewPublisherForTest(t)
	reg.allUnconnectedThreshold = 2
	reg.assignedServers = []*AssignedServer{unconnectedAssignedServer("10.0.0.1", "k1")}

	// Tick 0->1 opens the episode.
	reg.checkAllUnconnected()
	if got := reg.allUnconnectedTicks.Load(); got != 1 {
		t.Fatalf("ticks after 0->1 = %d, want 1", got)
	}
	since := reg.allUnconnectedSinceNano.Load()
	window := reg.allUnconnectedWindowStartNano.Load()
	if since == 0 || window == 0 {
		t.Fatalf("episode/window timers must be set on 0->1: since=%d window=%d", since, window)
	}
	if since != window {
		t.Errorf("on 0->1 both timers should start at the same instant: since=%d window=%d", since, window)
	}
	if _, total := countDimCountersWithPrefix(t, reg, MetricAllUnconnectedDetected); total != 1 {
		t.Errorf("AllUnconnectedDetected emissions = %v on 0->1, want 1", total)
	}
	if lat := reg.metrics.LatenciesForTest(t); len(lat[MetricAllUnconnectedDurationMs]) != 0 || len(lat[MetricAllUnconnectedRecoveryMs]) != 0 {
		t.Errorf("no latency should be emitted before threshold: %v", lat)
	}

	// Tick 1->2 crosses the threshold.
	reg.checkAllUnconnected()
	if got := reg.allUnconnectedTicks.Load(); got != 0 {
		t.Errorf("ticks after threshold = %d, want 0 (counter must reset)", got)
	}
	if !reg.reregistering.Load() {
		t.Error("re-registration must trip at threshold")
	}
	lat := reg.metrics.LatenciesForTest(t)
	if n := len(lat[MetricAllUnconnectedDurationMs]); n != 1 {
		t.Errorf("DurationMs samples = %d, want 1 at threshold", n)
	}
	if n := len(lat[MetricAllUnconnectedRecoveryMs]); n != 0 {
		t.Errorf("RecoveryMs samples = %d, want 0 (no recovery yet)", n)
	}
	if reg.allUnconnectedSinceNano.Load() == 0 {
		t.Error("episode timer must persist past threshold (only recovery clears it)")
	}
	if _, total := countDimCountersWithPrefix(t, reg, MetricAllUnconnectedDetected); total != 1 {
		t.Errorf("AllUnconnectedDetected emissions = %v after threshold, want 1 (fires only on the 0->1 edge)", total)
	}
}

// TestCheckAllUnconnected_EpisodePersistsWindowRefreshesOnRetrip — a fresh 0->1
// after a threshold trip must REFRESH the window timer (unconditional Store) but
// leave the episode timer untouched (CAS(0,now) fails because it isn't 0). This
// is the fix for episode-age over-reporting: the next window's DurationMs
// measures that window, not the whole (still-open) episode. Sentinel values make
// it deterministic — no reliance on sub-nanosecond timing.
func TestCheckAllUnconnected_EpisodePersistsWindowRefreshesOnRetrip(t *testing.T) {
	reg := mustNewACRegistration(t, newResilienceAC("retrip"))
	stopRegLater(t, reg)
	reg.metrics = metrics.NewPublisherForTest(t)
	reg.allUnconnectedThreshold = 5 // high, so a single tick won't trip
	reg.assignedServers = []*AssignedServer{unconnectedAssignedServer("10.0.0.1", "k1")}

	// Simulate an episode already open from a PRIOR window: both timers hold an
	// ancient sentinel and ticks are back at 0 (a threshold trip reset them).
	const oldNano = int64(1_000)
	reg.allUnconnectedSinceNano.Store(oldNano)
	reg.allUnconnectedWindowStartNano.Store(oldNano)
	reg.allUnconnectedTicks.Store(0)

	reg.checkAllUnconnected() // 0->1 again

	if got := reg.allUnconnectedSinceNano.Load(); got != oldNano {
		t.Errorf("episode timer = %d, want %d (must persist across a re-trip)", got, oldNano)
	}
	if got := reg.allUnconnectedWindowStartNano.Load(); got <= oldNano {
		t.Errorf("window timer = %d, want a fresh (much larger) instant than the sentinel %d", got, oldNano)
	}
}

// TestCheckAllUnconnected_RecoveryEmitsRecoveryMsOnceAndClears — an observed
// reconnect closes the episode: RecoveryMs is emitted once, both timers and the
// tick counter clear, and a second recovery call does NOT double-emit (the
// Swap(0) guard), so a healthy tick right after recovery can't re-count the
// outage.
func TestCheckAllUnconnected_RecoveryEmitsRecoveryMsOnceAndClears(t *testing.T) {
	reg := mustNewACRegistration(t, newResilienceAC("recovery"))
	stopRegLater(t, reg)
	reg.metrics = metrics.NewPublisherForTest(t)

	openedAt := time.Now().Add(-50 * time.Millisecond).UnixNano()
	reg.allUnconnectedSinceNano.Store(openedAt)
	reg.allUnconnectedWindowStartNano.Store(openedAt)
	reg.allUnconnectedTicks.Store(3)

	connected := unconnectedAssignedServer("10.0.0.1", "k1")
	connected.SetConnected(true)
	connected.UpdateLastSeen()
	reg.assignedServers = []*AssignedServer{connected}

	reg.checkAllUnconnected()

	if got := reg.allUnconnectedTicks.Load(); got != 0 {
		t.Errorf("ticks after recovery = %d, want 0", got)
	}
	if s, w := reg.allUnconnectedSinceNano.Load(), reg.allUnconnectedWindowStartNano.Load(); s != 0 || w != 0 {
		t.Errorf("timers after recovery: since=%d window=%d, want both 0", s, w)
	}
	if n := len(reg.metrics.LatenciesForTest(t)[MetricAllUnconnectedRecoveryMs]); n != 1 {
		t.Fatalf("RecoveryMs samples = %d, want exactly 1", n)
	}

	// Idempotent: a second close must not emit again.
	reg.markAllUnconnectedRecovered()
	if n := len(reg.metrics.LatenciesForTest(t)[MetricAllUnconnectedRecoveryMs]); n != 1 {
		t.Errorf("RecoveryMs samples after a second recovery call = %d, want still 1 (Swap guard)", n)
	}
}

// TestCheckAllUnconnected_EmptySetClearsTimersWithoutRecoveryMs — an empty
// assigned set is a teardown / redispatch, NOT a reconnect: both timers must
// clear WITHOUT emitting RecoveryMs, or a teardown would masquerade as a fast
// recovery and skew the MTTR gauge.
func TestCheckAllUnconnected_EmptySetClearsTimersWithoutRecoveryMs(t *testing.T) {
	reg := mustNewACRegistration(t, newResilienceAC("teardown"))
	stopRegLater(t, reg)
	reg.metrics = metrics.NewPublisherForTest(t)

	openedAt := time.Now().Add(-20 * time.Millisecond).UnixNano()
	reg.allUnconnectedSinceNano.Store(openedAt)
	reg.allUnconnectedWindowStartNano.Store(openedAt)
	reg.allUnconnectedTicks.Store(4)
	reg.assignedServers = []*AssignedServer{}

	reg.checkAllUnconnected()

	if got := reg.allUnconnectedTicks.Load(); got != 0 {
		t.Errorf("ticks after empty-set = %d, want 0", got)
	}
	if s, w := reg.allUnconnectedSinceNano.Load(), reg.allUnconnectedWindowStartNano.Load(); s != 0 || w != 0 {
		t.Errorf("timers after empty-set: since=%d window=%d, want both 0 (episode must not leak)", s, w)
	}
	if n := len(reg.metrics.LatenciesForTest(t)[MetricAllUnconnectedRecoveryMs]); n != 0 {
		t.Errorf("RecoveryMs samples after empty-set teardown = %d, want 0 (teardown != reconnect)", n)
	}
}
