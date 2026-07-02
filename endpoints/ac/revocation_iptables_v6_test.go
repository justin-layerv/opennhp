package ac

import (
	"testing"
	"time"
)

// These tests pin the #2794 fix and its #2165 gap-closing follow-up. In
// FilterMode_IPTABLES with the EXEC backend an IPv6 immediate revoke has NO real
// teardown (the ConntrackFlusher shells `conntrack -D`, which is IPv4-only — no
// `-f ipv6`), so the revoke must raise the revocation-specific
// MetricRevocationIPv6HardFail rather than only ticking the flusher's CONFLATED
// metricSkipped ("benign expiry leak"). With the NETLINK backend (#2165,
// coarseConntrackHandlesV6) the coarse Flush is v6-capable and tears the flow
// down, so the hard-fail must NOT fire — fenced by the
// NetlinkBackend_NoHardFail test below. Before #2794, flushEntryNow ticked NO
// revocation-specific failure metric in iptables mode — the gap was a silent
// no-op behind a false comment claiming the iptables flusher "uses netlink."
//
// The load-bearing, platform-independent assertion for the exec backend is the
// hard-fail counter. In that mode the coarse RescheduleEarlier is IPv4-only, so a
// revoked v6 key is NOT rescheduled into the flusher at all — its expiry-skip
// counter (metricSkipped, a //go:build linux type) stays clean, and the v6 revoke
// is surfaced ONLY on the dedicated MetricRevocationIPv6HardFail. The netlink
// backend test flips only the coarseConntrackHandlesV6 gate and proves the v6 key
// does reach the flusher without raising the hard-fail.

// newIPTablesTestAC builds a UdpAC in FilterMode_IPTABLES with a real metrics
// publisher and a started scheduler, leaving the eBPF surgical seam unwired
// (surgicalConnFlush == nil) — exactly the production iptables-mode shape for
// the revocation apply path. Mirrors newTestACWithScheduler but pins the filter
// mode. Returns the recording flusher too, so a
// test that needs to assert which FlowKeys actually reached the flusher (not just
// revocation counters) can use it; counter-only tests discard it with `_`.
func newIPTablesTestAC(t *testing.T) (*UdpAC, *recordingFlusher) {
	t.Helper()
	a, f := newTestACWithScheduler(t) // surgicalConnFlush left nil → coarse-only
	a.config = &Config{FilterMode: FilterMode_IPTABLES}
	return a, f
}

// TestApplyRevocation_IPTablesV6_HardFail drives the REAL revoke path
// (ApplyRevocation → flushEntryNow) for a v6 admission under iptables mode and
// proves the revocation-specific hard-fail metric is raised — the non-vacuous
// proof for #2794. Pre-fix this metric stayed 0 in iptables mode (it was only
// ticked on the eBPF surgical path), so a v6 revoke that tore nothing down was
// indistinguishable from a benign expiry skip.
func TestApplyRevocation_IPTablesV6_HardFail(t *testing.T) {
	a, _ := newIPTablesTestAC(t)

	// Admit a qURL v2 entry whose tracked flow key is IPv6, mirroring what the
	// admission path does via scheduleFlushIfEnabled.
	entry := qurlV2Entry("qhashV6", "rhashV6", "", "admV6")
	token := a.GenerateAccessToken(entry) // stores + indexes
	key := mustKey(t, "2001:db8::1", "2001:db8::2", 443, FlowProtoTCP)
	entry.recordScheduledKey(key)
	a.expirySched.Schedule(key, time.Now().Add(10*time.Second)) // far-future normal expiry

	// Pre-condition: nothing ticked yet.
	if got := incrCounter(t, a, MetricRevocationIPv6HardFail); got != 0 {
		t.Fatalf("precondition: %s = %v, want 0 before revoke", MetricRevocationIPv6HardFail, got)
	}

	n := a.ApplyRevocation(scopeQurl, "qhashV6", 1)
	if n != 1 {
		t.Fatalf("ApplyRevocation flushed %d, want 1", n)
	}

	// THE assertion: a v6 revoke under iptables raises the dedicated hard-fail,
	// so the revoke breaker/observability can tell "v6 revoke not torn down"
	// apart from a benign expiry skip.
	if got := incrCounter(t, a, MetricRevocationIPv6HardFail); got != 1 {
		t.Fatalf("%s = %v, want 1 (a v6 revoke under iptables is an immediate-revocation gap, #2794)", MetricRevocationIPv6HardFail, got)
	}
	// No eBPF surgical teardown is possible/attempted in iptables mode.
	if got := incrCounter(t, a, MetricRevocationSurgicalFlushed); got != 0 {
		t.Errorf("%s = %v, want 0 (no surgical path in iptables mode)", MetricRevocationSurgicalFlushed, got)
	}
	if got := incrCounter(t, a, MetricRevocationSurgicalFlushedV6); got != 0 {
		t.Errorf("%s = %v, want 0 (no v6 surgical path in iptables mode)", MetricRevocationSurgicalFlushedV6, got)
	}
	// FlushScheduled ticks once per processed entry (the v6 coarse reschedule is
	// skipped now — #2778 part 2 — but the per-entry counter still fires), and the
	// entry was torn out of tokenStore so a re-knock cannot extend it.
	if got := incrCounter(t, a, MetricRevocationFlushScheduled); got != 1 {
		t.Errorf("%s = %v, want 1 (per-entry tick even when the v6 key hard-fails)", MetricRevocationFlushScheduled, got)
	}
	if _, found := a.tokenStore.Load(token); found {
		t.Errorf("revoked v6 entry still in tokenStore; re-knock could extend it")
	}
}

// TestFlushEntryNow_IPTablesV6_HardFail isolates the choke point: a v6 FlowKey in
// FilterMode_IPTABLES with the surgical seam unwired ticks
// MetricRevocationIPv6HardFail exactly once (the coarse reschedule is skipped for
// v6 — #2778 part 2), with no eBPF surgical accounting.
func TestFlushEntryNow_IPTablesV6_HardFail(t *testing.T) {
	a, _ := newIPTablesTestAC(t)

	key := mustKey(t, "2001:db8::a", "2001:db8::b", 443, FlowProtoTCP)
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry)

	if got := incrCounter(t, a, MetricRevocationIPv6HardFail); got != 1 {
		t.Errorf("%s = %v, want 1 (v6 under iptables has no immediate conntrack teardown, #2794)", MetricRevocationIPv6HardFail, got)
	}
	if got := incrCounter(t, a, MetricRevocationSurgicalFlushed); got != 0 {
		t.Errorf("%s = %v, want 0 (surgical seam unwired in iptables mode)", MetricRevocationSurgicalFlushed, got)
	}
	if got := incrCounter(t, a, MetricRevocationSurgicalFlushedV6); got != 0 {
		t.Errorf("%s = %v, want 0 (v6 surgical seam unwired in iptables mode)", MetricRevocationSurgicalFlushedV6, got)
	}
	if got := incrCounter(t, a, MetricRevocationFlushScheduled); got != 1 {
		t.Errorf("%s = %v, want 1 (per-entry tick; v6 coarse reschedule skipped)", MetricRevocationFlushScheduled, got)
	}
}

// TestFlushEntryNow_IPTablesV6_NetlinkBackend_NoHardFail proves the #2165
// gap-closing path: when the netlink backend is active
// (coarseConntrackHandlesV6 == true) the coarse RescheduleEarlier→Flush tears
// down v6 conntrack entries too, so a v6 revoke under iptables does NOT raise the
// hard-fail. This is the inverse of TestFlushEntryNow_IPTablesV6_HardFail (exec
// backend), and the only difference between the two ACs is the backend-capability
// flag — proving the gate is exactly coarseConntrackHandlesV6.
func TestFlushEntryNow_IPTablesV6_NetlinkBackend_NoHardFail(t *testing.T) {
	a, flusher := newIPTablesTestAC(t)
	a.coarseConntrackHandlesV6.Store(true) // netlink backend: coarse Flush is v6-capable

	key := mustKey(t, "2001:db8::a", "2001:db8::b", 443, FlowProtoTCP)
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)
	a.expirySched.Schedule(key, time.Now().Add(time.Hour))

	a.flushEntryNow(entry)

	if !flusher.waitFor(1, 2*time.Second) {
		t.Fatal("v6 key never reached the flusher; netlink-capable iptables revoke did not reschedule")
	}
	keys := flusher.snapshotKeys()
	if len(keys) != 1 || keys[0] != key {
		t.Errorf("flusher saw %v; want exactly [%v] (netlink-capable iptables v6 revoke should flush the v6 key)", keys, key)
	}
	if got := incrCounter(t, a, MetricRevocationIPv6HardFail); got != 0 {
		t.Errorf("%s = %v, want 0 (netlink backend coarse Flush is v6-capable; gap closed, #2165)", MetricRevocationIPv6HardFail, got)
	}
	if got := incrCounter(t, a, MetricRevocationFlushScheduled); got != 1 {
		t.Errorf("%s = %v, want 1 (coarse path still runs)", MetricRevocationFlushScheduled, got)
	}
}

// TestFlushEntryNow_IPTablesV4_NoHardFail proves the iptables hard-fail branch is
// v6-SPECIFIC: a v4 key under iptables mode tears down via the (v4-capable)
// `conntrack -D` coarse path and must NOT tick the hard-fail. A blanket
// iptables-mode hard-fail would be wrong — only v6 is the declared gap.
func TestFlushEntryNow_IPTablesV4_NoHardFail(t *testing.T) {
	a, _ := newIPTablesTestAC(t)

	key := mustKey(t, "198.51.100.7", "203.0.113.10", 443, FlowProtoTCP)
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry)

	if got := incrCounter(t, a, MetricRevocationIPv6HardFail); got != 0 {
		t.Errorf("%s = %v, want 0 for a v4 key under iptables (v4 tears down via conntrack -D; only v6 is the declared gap)", MetricRevocationIPv6HardFail, got)
	}
	if got := incrCounter(t, a, MetricRevocationFlushScheduled); got != 1 {
		t.Errorf("%s = %v, want 1 (coarse path runs)", MetricRevocationFlushScheduled, got)
	}
}

// TestFlushEntryNow_NilConfigV6_NoHardFail pins the nil-config guard: the
// surgical-seam unit helpers (and any AC built without a Config) must not
// nil-panic and must not raise a hard-fail off the iptables branch when the
// filter mode is unknown. This is the safety net for the explicit
// `a.config != nil` guard in flushEntryNow.
func TestFlushEntryNow_NilConfigV6_NoHardFail(t *testing.T) {
	a, _ := newTestACWithScheduler(t) // config + surgicalConnFlush both nil

	key := mustKey(t, "2001:db8::1", "2001:db8::2", 443, FlowProtoTCP)
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry) // must not panic

	if got := incrCounter(t, a, MetricRevocationIPv6HardFail); got != 0 {
		t.Errorf("%s = %v, want 0 with nil config (filter mode unknown — no hard-fail attribution)", MetricRevocationIPv6HardFail, got)
	}
	if got := incrCounter(t, a, MetricRevocationFlushScheduled); got != 1 {
		t.Errorf("%s = %v, want 1 (per-entry tick; the v6 coarse reschedule is skipped)", MetricRevocationFlushScheduled, got)
	}
}

// TestFlushEntryNow_IPTablesV6_NotRescheduledIntoFlusher is the concrete,
// deterministic proof for #2778 part 2: a v6 immediate revoke must NOT drive its
// key through the coarse RescheduleEarlier into the IPv4-only flusher. That flush
// is a guaranteed no-op (the flusher's teardown is IPv4-only in both modes) whose
// ONLY effect would be ticking the flusher's expiry-skip counter (metricSkipped →
// MetricL3FlushBpfSkipped), conflating a benign scheduled-expiry leak with a
// failed v6 revoke. With the coarse reschedule gated to IPv4, a v4 sibling on the
// same entry IS pulled to fire now (observed at the recording flusher) while the
// v6 key is left at its far-future deadline and never reaches the flusher; the v6
// revoke is surfaced ONLY on the dedicated MetricRevocationIPv6HardFail.
//
// The recording flusher stands in for the real //go:build linux
// BpfFlusher/ConntrackFlusher, so "the v6 key never reached the flusher" is
// exactly "the revoke did not pollute the expiry-skip counter" — asserted
// cross-platform without a kernel.
func TestFlushEntryNow_IPTablesV6_NotRescheduledIntoFlusher(t *testing.T) {
	// iptables mode (surgicalConnFlush nil → coarse-only, the production iptables
	// shape) with the recording flusher kept so we can assert which keys reach it.
	a, flusher := newIPTablesTestAC(t)

	v4 := mustKey(t, "198.51.100.7", "203.0.113.10", 443, FlowProtoTCP)
	v6 := mustKey(t, "2001:db8::1", "2001:db8::2", 443, FlowProtoTCP)
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(v4)
	entry.recordScheduledKey(v6)
	// Both parked far in the future; only a revoke-driven RescheduleEarlier(now)
	// could pull either earlier. 1h ≫ test lifetime, so a key left unrescheduled
	// can never fire here.
	far := time.Now().Add(time.Hour)
	a.expirySched.Schedule(v4, far)
	a.expirySched.Schedule(v6, far)

	a.flushEntryNow(entry)

	// The v4 sibling WAS rescheduled to fire now — the worker flushes it. This also
	// proves the worker is alive and processing now-due keys.
	if !flusher.waitFor(1, 2*time.Second) {
		t.Fatal("v4 sibling never reached the flusher; the coarse IPv4 reschedule regressed")
	}
	// The v6 key must NOT have been rescheduled: it stays at +1h, so no SECOND
	// flush ever arrives. This bounded wait is a sound negative because the
	// waitFor(1) above already proved the worker fired the v4 sibling's tick — a
	// regression that co-scheduled v6 to now would be due in that SAME window and
	// the worker would drain it within a few 2ms ticks, far inside 250ms. (The
	// only fully timing-free alternative is to peek scheduler-wheel internals,
	// which would add concurrency-sensitive test-only API for no real gain.)
	if flusher.waitFor(2, 250*time.Millisecond) {
		t.Errorf("a second key reached the flusher — the v6 key was rescheduled into the IPv4-only flusher, polluting the expiry-skip counter (#2778 part 2)")
	}
	keys := flusher.snapshotKeys()
	if len(keys) != 1 || keys[0] != v4 {
		t.Errorf("flusher saw %v; want exactly [%v] (only the v4 key is rescheduled; the v6 key must never reach the v4-only flusher)", keys, v4)
	}
	// The v6 revoke is surfaced on the dedicated hard-fail, NOT the expiry-skip path.
	if got := incrCounter(t, a, MetricRevocationIPv6HardFail); got != 1 {
		t.Errorf("%s = %v, want 1 (v6 revoke surfaced on the dedicated hard-fail metric)", MetricRevocationIPv6HardFail, got)
	}
}
