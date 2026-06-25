package ac

import (
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
)

// These tests pin the #2794 fix: in FilterMode_IPTABLES an IPv6 immediate revoke
// has NO real teardown (the ConntrackFlusher shells `conntrack -D`, which is
// IPv4-only — no `-f ipv6`; the v6-capable netlink flusher is the UNbuilt #2165),
// so the revoke must raise the revocation-specific MetricRevocationIPv6HardFail
// rather than only ticking the flusher's CONFLATED metricSkipped ("benign expiry
// leak"). Before the fix, flushEntryNow ticked NO revocation-specific failure
// metric in iptables mode — the gap was a silent no-op behind a false comment
// claiming the iptables flusher "uses netlink, which IS v6-capable."
//
// The load-bearing, platform-independent assertion is the hard-fail counter:
// metricSkipped lives on a //go:build linux type, and on Linux a v6 revoke would
// ALSO tick it asynchronously when the coarse-rescheduled key reaches the
// flusher — so "not metricSkipped" means "the revoke now emits the dedicated
// hard-fail signal," which these tests assert directly.

// newIPTablesTestAC builds a UdpAC in FilterMode_IPTABLES with a real metrics
// publisher and a started scheduler, leaving the eBPF surgical seam unwired
// (surgicalConnFlush == nil) — exactly the production iptables-mode shape for
// the revocation apply path. Mirrors newTestACWithScheduler but pins the filter
// mode + an observable metrics publisher. These tests assert on revocation
// counters, not flushed FlowKeys, so the recording flusher is not returned.
func newIPTablesTestAC(t *testing.T) *UdpAC {
	t.Helper()
	a, _ := newTestACWithScheduler(t) // surgicalConnFlush left nil → coarse-only
	a.registration = &ACRegistration{metrics: metrics.NewPublisherForTest(t)}
	a.config = &Config{FilterMode: FilterMode_IPTABLES}
	return a
}

// TestApplyRevocation_IPTablesV6_HardFail drives the REAL revoke path
// (ApplyRevocation → flushEntryNow) for a v6 admission under iptables mode and
// proves the revocation-specific hard-fail metric is raised — the non-vacuous
// proof for #2794. Pre-fix this metric stayed 0 in iptables mode (it was only
// ticked on the eBPF surgical path), so a v6 revoke that tore nothing down was
// indistinguishable from a benign expiry skip.
func TestApplyRevocation_IPTablesV6_HardFail(t *testing.T) {
	a := newIPTablesTestAC(t)

	// Admit a qURL v2 entry whose tracked flow key is IPv6, mirroring what the
	// admission path does via scheduleFlushIfEnabled.
	entry := qurlV2Entry("qhashV6", "rhashV6", "", "admV6")
	token := a.GenerateAccessToken(entry) // stores + indexes
	key := mustKey(t, "2001:db8::1", "2001:db8::2", 443, FlowProtoTCP)
	entry.recordScheduledKey(key)
	a.expirySched.Schedule(key, time.Now().Add(10*time.Second)) // far-future normal expiry

	// Pre-condition: nothing ticked yet.
	if got := counter(t, a, MetricRevocationIPv6HardFail); got != 0 {
		t.Fatalf("precondition: %s = %v, want 0 before revoke", MetricRevocationIPv6HardFail, got)
	}

	n := a.ApplyRevocation(scopeQurl, "qhashV6", 1)
	if n != 1 {
		t.Fatalf("ApplyRevocation flushed %d, want 1", n)
	}

	// THE assertion: a v6 revoke under iptables raises the dedicated hard-fail,
	// so the revoke breaker/observability can tell "v6 revoke not torn down"
	// apart from a benign expiry skip.
	if got := counter(t, a, MetricRevocationIPv6HardFail); got != 1 {
		t.Fatalf("%s = %v, want 1 (a v6 revoke under iptables is an immediate-revocation gap, #2794)", MetricRevocationIPv6HardFail, got)
	}
	// No eBPF surgical teardown is possible/attempted in iptables mode.
	if got := counter(t, a, MetricRevocationSurgicalFlushed); got != 0 {
		t.Errorf("%s = %v, want 0 (no surgical path in iptables mode)", MetricRevocationSurgicalFlushed, got)
	}
	// The coarse reschedule still ran (drain-once-feed-both), and the entry was
	// torn out of tokenStore so a re-knock cannot extend it.
	if got := counter(t, a, MetricRevocationFlushScheduled); got != 1 {
		t.Errorf("%s = %v, want 1 (coarse path runs even when v6 hard-fails)", MetricRevocationFlushScheduled, got)
	}
	if _, found := a.tokenStore.Load(token); found {
		t.Errorf("revoked v6 entry still in tokenStore; re-knock could extend it")
	}
}

// TestFlushEntryNow_IPTablesV6_HardFail isolates the choke point: a v6 FlowKey in
// FilterMode_IPTABLES with the surgical seam unwired ticks
// MetricRevocationIPv6HardFail exactly once and runs the coarse path, with no
// eBPF surgical accounting.
func TestFlushEntryNow_IPTablesV6_HardFail(t *testing.T) {
	a := newIPTablesTestAC(t)

	key := mustKey(t, "2001:db8::a", "2001:db8::b", 443, FlowProtoTCP)
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry)

	if got := counter(t, a, MetricRevocationIPv6HardFail); got != 1 {
		t.Errorf("%s = %v, want 1 (v6 under iptables has no immediate conntrack teardown, #2794)", MetricRevocationIPv6HardFail, got)
	}
	if got := counter(t, a, MetricRevocationSurgicalFlushed); got != 0 {
		t.Errorf("%s = %v, want 0 (surgical seam unwired in iptables mode)", MetricRevocationSurgicalFlushed, got)
	}
	if got := counter(t, a, MetricRevocationFlushScheduled); got != 1 {
		t.Errorf("%s = %v, want 1 (coarse path runs)", MetricRevocationFlushScheduled, got)
	}
}

// TestFlushEntryNow_IPTablesV4_NoHardFail proves the iptables hard-fail branch is
// v6-SPECIFIC: a v4 key under iptables mode tears down via the (v4-capable)
// `conntrack -D` coarse path and must NOT tick the hard-fail. A blanket
// iptables-mode hard-fail would be wrong — only v6 is the declared gap.
func TestFlushEntryNow_IPTablesV4_NoHardFail(t *testing.T) {
	a := newIPTablesTestAC(t)

	key := mustKey(t, "198.51.100.7", "203.0.113.10", 443, FlowProtoTCP)
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry)

	if got := counter(t, a, MetricRevocationIPv6HardFail); got != 0 {
		t.Errorf("%s = %v, want 0 for a v4 key under iptables (v4 tears down via conntrack -D; only v6 is the declared gap)", MetricRevocationIPv6HardFail, got)
	}
	if got := counter(t, a, MetricRevocationFlushScheduled); got != 1 {
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
	a.registration = &ACRegistration{metrics: metrics.NewPublisherForTest(t)}

	key := mustKey(t, "2001:db8::1", "2001:db8::2", 443, FlowProtoTCP)
	entry := &AccessEntry{OpenTime: 10}
	entry.recordScheduledKey(key)

	a.flushEntryNow(entry) // must not panic

	if got := counter(t, a, MetricRevocationIPv6HardFail); got != 0 {
		t.Errorf("%s = %v, want 0 with nil config (filter mode unknown — no hard-fail attribution)", MetricRevocationIPv6HardFail, got)
	}
	if got := counter(t, a, MetricRevocationFlushScheduled); got != 1 {
		t.Errorf("%s = %v, want 1 (coarse path still runs)", MetricRevocationFlushScheduled, got)
	}
}
