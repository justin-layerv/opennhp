package server

import (
	"fmt"
	"math"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
)

// Precheck-threat cache tests cover the three invariants that make
// the cache a memory-DoS fix for #1158:
//
//  1. IP keying — a port-rotating attacker on one IP occupies one
//     slot, not 65_535.
//  2. Bounded size — under a spoofed-IP flood the cache cannot
//     grow past the configured cap; excess entries are evicted
//     and the eviction callback fires.
//  3. Clear-on-success — a legitimate packet from the same IP
//     resets the counter (collapses scanner state back to zero so
//     legitimate retransmits aren't eventually blocked).
//
// Tests wire newPreCheckThreatCache with short TTLs where needed
// so the TTL-eviction path is exercised through the real wrapper
// (not the library directly). This keeps coverage aligned with
// what production will actually run.

// newTestThreatCache builds a cache sized/TTLed for cache-internal
// unit tests. Capacity matches production (PreCheckThreatCacheSize)
// so the cap-eviction regression fence tests the real number; TTL
// is set far enough ahead that tests don't race against it.
func newTestThreatCache(onEvict func()) *preCheckThreatCache {
	return newPreCheckThreatCache(PreCheckThreatCacheSize, 10*time.Second, onEvict)
}

// TestPreCheckThreatCache_IncrementAccumulatesPerIP asserts the
// counter behaves like the old map[string]int32 for the common
// case: repeated increments on the same key return a monotonic
// sequence and Len() stays at 1.
func TestPreCheckThreatCache_IncrementAccumulatesPerIP(t *testing.T) {
	c := newTestThreatCache(nil)
	ip := "192.0.2.10"

	for i := int32(1); i <= 5; i++ {
		if got := c.Increment(ip); got != i {
			t.Fatalf("Increment #%d = %d, want %d", i, got, i)
		}
	}
	if c.Len() != 1 {
		t.Errorf("Len()=%d, want 1 — per-IP keying should keep one slot", c.Len())
	}
}

// TestPreCheckThreatCache_PortRotationStaysSingleSlot is the
// regression fence for PR #1273 (#1158 memory-DoS primitive). Under
// the old IP:port keying, 65_535 distinct ports on one source IP
// produced 65_535 counter slots. Under IP-only keying that must
// collapse to 1.
func TestPreCheckThreatCache_PortRotationStaysSingleSlot(t *testing.T) {
	c := newTestThreatCache(nil)
	ip := "192.0.2.77"

	// 1000 synthetic "packets" from rotating ports — the cache sees
	// only ip, so port rotation is invisible here (by design).
	for i := 0; i < 1000; i++ {
		c.Increment(ip)
	}
	if got := c.Len(); got != 1 {
		t.Errorf("Len()=%d after 1000 increments on one IP, want 1 — port-rotation amplification regressed", got)
	}
}

// TestPreCheckThreatCache_ClearDropsCounter pins the success-path
// semantics: on success the caller calls Clear and the next
// Increment starts from zero.
func TestPreCheckThreatCache_ClearDropsCounter(t *testing.T) {
	c := newTestThreatCache(nil)
	ip := "198.51.100.5"

	c.Increment(ip)
	c.Increment(ip)
	c.Clear(ip)

	if c.Len() != 0 {
		t.Errorf("Len()=%d after Clear, want 0", c.Len())
	}
	if got := c.Increment(ip); got != 1 {
		t.Errorf("Increment after Clear = %d, want 1 (counter should restart)", got)
	}
}

// TestPreCheckThreatCache_ClearUnknownIsNoop guards against panics
// if Clear runs for an IP that was never Incremented (e.g., a
// legitimate first-packet from a new source).
func TestPreCheckThreatCache_ClearUnknownIsNoop(t *testing.T) {
	c := newTestThreatCache(nil)
	c.Clear("203.0.113.1") // must not panic
	if c.Len() != 0 {
		t.Errorf("Len()=%d after Clear on empty cache, want 0", c.Len())
	}
}

// TestPreCheckThreatCache_CapEvictsAndFiresCallback is the
// memory-DoS regression fence for PR #1273 (#1158). With the cache
// at capacity, one more distinct IP evicts the LRU-oldest and the
// eviction callback fires exactly once per eviction.
func TestPreCheckThreatCache_CapEvictsAndFiresCallback(t *testing.T) {
	var evictions atomic.Int64
	c := newTestThreatCache(func() { evictions.Add(1) })

	// Fill the cache exactly to capacity.
	for i := 0; i < PreCheckThreatCacheSize; i++ {
		c.Increment(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
	if c.Len() != PreCheckThreatCacheSize {
		t.Fatalf("Len()=%d, want %d after filling to cap", c.Len(), PreCheckThreatCacheSize)
	}
	if got := evictions.Load(); got != 0 {
		t.Fatalf("evictions=%d before overflow, want 0", got)
	}

	// One more distinct IP forces exactly one eviction.
	c.Increment("172.16.0.1")
	if c.Len() != PreCheckThreatCacheSize {
		t.Errorf("Len()=%d after overflow, want %d (cap must hold)", c.Len(), PreCheckThreatCacheSize)
	}
	if got := evictions.Load(); got != 1 {
		t.Errorf("evictions=%d after one overflow, want 1", got)
	}
}

// TestPreCheckThreatCache_TTLExpiresEntry covers the TTL path
// through the real wrapper. A short TTL keeps the test fast; an
// atomic counter is required because expirable.LRU runs a
// background sweep goroutine that fires the eviction callback
// concurrently with the test.
func TestPreCheckThreatCache_TTLExpiresEntry(t *testing.T) {
	var evictions atomic.Int64
	c := newPreCheckThreatCache(PreCheckThreatCacheSize, 20*time.Millisecond, func() {
		evictions.Add(1)
	})
	c.Increment("203.0.113.7")
	if c.Len() != 1 {
		t.Fatalf("Len()=%d before TTL, want 1", c.Len())
	}

	// Wait past TTL. expirable.LRU evicts lazily on access or via
	// its internal sweep goroutine; either path drains the entry
	// and fires the callback. 2s deadline gives CI runners margin
	// — the happy path returns as soon as both conditions hold,
	// so the extra headroom costs nothing on a healthy run.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.Len() == 0 && evictions.Load() > 0 {
			return // success: TTL expired and callback fired
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("TTL-expired entry never evicted: Len()=%d evictions=%d", c.Len(), evictions.Load())
}

// TestPreCheckThreatCache_NilCallbackSafe pins the optional-cb
// contract: callers that don't wire a metric publisher must not
// crash when eviction happens (e.g., future CLI tools or tests).
// The explicit assertion is that Increment past cap doesn't panic;
// the Len() check is a sanity-check that the cap logic still runs.
func TestPreCheckThreatCache_NilCallbackSafe(t *testing.T) {
	c := newTestThreatCache(nil)
	for i := 0; i < PreCheckThreatCacheSize+1; i++ {
		c.Increment(fmt.Sprintf("10.1.%d.%d", i/256, i%256))
	}
	if c.Len() != PreCheckThreatCacheSize {
		t.Errorf("Len()=%d, want %d", c.Len(), PreCheckThreatCacheSize)
	}
}

// TestPreCheckThreatCache_IncrementSaturatesAtMaxInt32 pins the
// overflow guard: a sustained attack that drives a single IP's
// counter past math.MaxInt32 must not wrap negative. If the
// counter wrapped, the subsequent `count > threshold` comparison
// in recordPreCheckThreat would become false and the source would
// stop getting blocked. Saturating at MaxInt32 makes the threshold
// comparison monotonically correct.
func TestPreCheckThreatCache_IncrementSaturatesAtMaxInt32(t *testing.T) {
	c := newTestThreatCache(nil)
	ip := "192.0.2.200"

	// Seed the LRU with the max-value directly via the wrapper: one
	// Increment + manual Add through a helper would be cleaner, but
	// the wrapper doesn't expose Add. Instead: Increment once (value
	// = 1), then drive up to MaxInt32 via the escape hatch — Add
	// through the underlying LRU. This test is the only caller that
	// reaches past int32's positive range, so breaking encapsulation
	// for this one test is acceptable.
	c.lru.Add(ip, math.MaxInt32)

	if got := c.Increment(ip); got != math.MaxInt32 {
		t.Errorf("Increment at MaxInt32 = %d, want %d (should saturate, not wrap)", got, int32(math.MaxInt32))
	}
	// Run it a few more times to confirm saturation is sticky.
	for i := 0; i < 100; i++ {
		if got := c.Increment(ip); got != math.MaxInt32 {
			t.Fatalf("Increment iter=%d = %d, want %d", i, got, int32(math.MaxInt32))
		}
	}
}

// TestPreCheckThreatCache_EvictionIncrementsRealMetric fences the
// whole wire-to-metric chain: when the wrapper's callback fires on
// eviction, metrics.Publisher.IncrCounter actually records under
// MetricPreCheckThreatEviction. Catches a typo in the metric name
// constant or a Publisher regression that the atomic-lambda tests
// miss (they stop at the callback boundary and don't touch the
// real Publisher path).
func TestPreCheckThreatCache_EvictionIncrementsRealMetric(t *testing.T) {
	pub := metrics.NewPublisherForTest(t)

	// Small cap so eviction is easy to force; short TTL unused here
	// (we evict via capacity, not time).
	const cap = 4
	c := newPreCheckThreatCache(cap, time.Hour, func() {
		pub.IncrCounter(MetricPreCheckThreatEviction)
	})

	// Fill to cap + 2 to force exactly 2 evictions.
	for i := 0; i < cap+2; i++ {
		c.Increment(fmt.Sprintf("10.0.0.%d", i))
	}

	counters, _ := pub.CountersForTest(t)
	if got := counters[MetricPreCheckThreatEviction]; got != 2 {
		t.Errorf("MetricPreCheckThreatEviction=%v, want 2 (two overflow evictions fired)", got)
	}
}

// TestPreCheckThreatCache_IPv4MappedIPv6CollapsesToOneSlot fences
// the dual-stack loophole: IPv4 and its IPv4-mapped IPv6 form
// (`::ffff:a.b.c.d`) must occupy one cache slot, not two. This
// relies on stdlib net.IP.String()'s internal To4() check — the
// test pins that behavior from this package so a future Go
// stdlib change couldn't silently double an attacker's slot
// allowance on a dual-stack deployment.
func TestPreCheckThreatCache_IPv4MappedIPv6CollapsesToOneSlot(t *testing.T) {
	c := newTestThreatCache(nil)

	c.Increment(net.ParseIP("198.51.100.5").String())
	c.Increment(net.ParseIP("::ffff:198.51.100.5").String())

	if got := c.Len(); got != 1 {
		t.Errorf("Len()=%d after IPv4 and IPv4-mapped IPv6 of one source, want 1 — stdlib or cache keying regressed", got)
	}
}

// newTestServerForPreCheck wires the minimal UdpServer fields that
// recordPreCheckThreat touches — metrics publisher (for eviction
// cb) and blockAddrMap (target of addBlockedIP). Mirrors
// newTestServerForGate's style.
func newTestServerForPreCheck(t *testing.T) *UdpServer {
	t.Helper()
	return &UdpServer{
		metrics:      metrics.NewPublisherForTest(t),
		blockAddrMap: make(map[string]*BlockAddr),
	}
}

// TestRecordPreCheckThreat_BlocksOnFailureAfterThreshold fences
// the integration between recvPacketRoutine and the cache: the
// PreCheckThreatCountBeforeBlock value is the *last tolerated
// count*, not the first blocked count. The block fires when
// Increment returns something *strictly greater than* threshold —
// i.e., the (threshold+1)th failure. Failure here means someone
// swapped Increment/Clear, flipped the operator from > to >=, or
// passed the wrong key.
func TestRecordPreCheckThreat_BlocksOnFailureAfterThreshold(t *testing.T) {
	s := newTestServerForPreCheck(t)
	cache := newTestThreatCache(nil)
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.42"), Port: 12345}

	for i := 0; i < PreCheckThreatCountBeforeBlock; i++ {
		s.recordPreCheckThreat(cache, addr.IP.String())
	}
	if s.IsBlockAddr(addr) {
		t.Fatalf("blocked at or below threshold (%d failures) — should only block when count > threshold", PreCheckThreatCountBeforeBlock)
	}

	s.recordPreCheckThreat(cache, addr.IP.String())
	if !s.IsBlockAddr(addr) {
		t.Fatalf("not blocked after %d failures (threshold is %d)", PreCheckThreatCountBeforeBlock+1, PreCheckThreatCountBeforeBlock)
	}
}

// TestRecordPreCheckThreat_PortRotationSharesIPCounter is the
// regression fence for PR #1273 (#1158 port-rotation
// amplification): a scanner bouncing across ports on one IP must
// see its failures counted against the IP, not scattered across
// per-port slots. Under IP-only keying (#1273 for the threat
// counter, #1160 T3-12 for the block map), the 6th distinct port
// trips the block on the IP — and the block applies to all
// previously-seen ports too.
func TestRecordPreCheckThreat_PortRotationSharesIPCounter(t *testing.T) {
	s := newTestServerForPreCheck(t)
	cache := newTestThreatCache(nil)
	ip := net.ParseIP("198.51.100.17")

	// PreCheckThreatCountBeforeBlock+1 failures, each from a
	// distinct port — old keying would put each in its own slot
	// (count=1 per port, never > threshold) and never block.
	var last *net.UDPAddr
	for i := 0; i <= PreCheckThreatCountBeforeBlock; i++ {
		last = &net.UDPAddr{IP: ip, Port: 10000 + i}
		s.recordPreCheckThreat(cache, last.IP.String())
	}
	if !s.IsBlockAddr(last) {
		t.Fatal("port-rotation amplification regressed — threats not accumulated at IP level")
	}
	// Block map is IP-keyed: every port from the same IP must now
	// be flagged as blocked. Old IP:port-keyed behavior left earlier
	// ports unblocked even when the IP tripped the threshold.
	for i := 0; i < PreCheckThreatCountBeforeBlock; i++ {
		earlier := &net.UDPAddr{IP: ip, Port: 10000 + i}
		if !s.IsBlockAddr(earlier) {
			t.Errorf("port %d on blocked IP must be blocked under IP-only keying (#1160 T3-12)", earlier.Port)
		}
	}
}

// TestRecordPreCheckThreat_ClearAllowsFurtherTraffic pins the
// success-side of the integration: a cleared IP can take fresh
// failures without immediately re-blocking. Mirrors the legit-
// traffic-resumes-after-transient-blip scenario.
func TestRecordPreCheckThreat_ClearAllowsFurtherTraffic(t *testing.T) {
	s := newTestServerForPreCheck(t)
	cache := newTestThreatCache(nil)
	addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.99"), Port: 9999}

	// A few failures, then a clear (simulates a valid precheck).
	for i := 0; i < PreCheckThreatCountBeforeBlock; i++ {
		s.recordPreCheckThreat(cache, addr.IP.String())
	}
	cache.Clear(addr.IP.String())

	// Same number of failures again — still not blocked because
	// the counter reset on Clear.
	for i := 0; i < PreCheckThreatCountBeforeBlock; i++ {
		s.recordPreCheckThreat(cache, addr.IP.String())
	}
	if s.IsBlockAddr(addr) {
		t.Fatal("Clear did not reset counter — legitimate traffic would be blocked after a single transient failure cluster")
	}
}
