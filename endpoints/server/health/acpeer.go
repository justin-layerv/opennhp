package health

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
)

// ACPeerCounter provides AC connection counts for health checking.
// Implemented by the UDP server to avoid import cycles (health -> server).
type ACPeerCounter interface {
	// ACPeerCount returns the number of connected AC peers.
	ACPeerCount() int
}

// DefaultACPeerGracePeriod is the default debounce window applied when
// the live AC peer count drops to zero. It tracks the AC-side keepalive
// failure-detection window (endpoints/ac/registration.go KeepaliveInterval
// × KeepaliveMaxRetries = 10s × 3): past that point a healthy AC has
// entered its own re-registration path, so holding the gate open longer
// would only hide sustained failures. If either AC-side constant changes,
// bump this too — TestACPeerChecker_DefaultTracksACKeepaliveWindow pins
// the invariant so drift surfaces as a unit-test failure rather than a
// prod flap.
//
// Note: AC re-registration applies exponential backoff
// (endpoints/ac/registration.go — KeepaliveInterval × 2^min(failures-1, 5)),
// so after repeated failures an AC's reconnect window can extend past 30s
// (20s after 2 failures, 40s after 3, …). Operators observing the gate
// flap against a known-flaky AC cluster should raise
// ACPeerGracePeriodSeconds toward MaxACPeerGracePeriod (5m) rather than
// assume the default covers every recovery path.
const DefaultACPeerGracePeriod = 30 * time.Second

// MinACPeerGracePeriod and MaxACPeerGracePeriod are the recommended
// bounds an operator-supplied grace period should be clamped into.
// This package does not clamp internally — the caller (httpserver.go
// acPeerGracePeriodFromConfig) owns clamping + the boot-time warning
// log so the project logger stays in package server. The constants
// live here because they're stated in the type's contract (too-small
// defeats debounce, too-large hides sustained outages), even though
// enforcement is at the call site.
//
// Min = one AC keepalive round-trip (a shorter window would flap the
// gate on every single missed NHP_AOL before the AC even retries).
// Max = 5 minutes (long enough for any plausibly-recoverable transient:
// NAT rebind, blue/green switchover, AC restart; short enough that a
// stuck server still surfaces within a deploy-window budget).
const (
	MinACPeerGracePeriod = 10 * time.Second
	MaxACPeerGracePeriod = 5 * time.Minute
)

// ACPeerChecker checks whether the server has any connected AC peers.
// A server with zero AC connections cannot process knock requests,
// so this checker is used on the NLB knock-traffic health check endpoint
// to prevent routing knock requests to servers that would fail them.
//
// Debounce semantics: when the live count drops to zero but the checker
// has previously seen a non-zero count within GracePeriod, the check
// reports CheckStatusPass with the cached count and a trailing
// "(cached, live=0 for Xs, within Ys grace)" suffix. This absorbs
// single-keepalive-cycle flickers (the NHP server's per-AC-ID slice
// momentarily empties when the only connection times out before the
// next NHP_AOL re-registers it) so NLB and smoke tests don't react to
// recoverable transients. A sustained zero past the grace window flips
// to CheckStatusFail honestly. If the checker has never seen a non-zero
// count (e.g., process boot, or an AC has never connected), zero fails
// immediately — the grace window is for recovery from a known-good
// state, not for hiding never-readiness.
//
// Atomic-field ordering invariant: the non-zero path writes
// lastNonZeroCount BEFORE lastNonZeroAt, and the zero/grace path reads
// lastNonZeroAt BEFORE lastNonZeroCount. With Go's sequentially
// consistent atomic ordering that guarantees: if a reader observes a
// non-zero timestamp, the count read that follows has already been
// published as non-zero. Without this ordering, the grace-window
// message could briefly render as "0 AC peer(s) connected (cached,
// ...)" on the very first probe after the first peer connects,
// which would trip the smoke regex's m[1] != "0" assertion on the
// exact contract the cached-count message is supposed to preserve.
//
// Concurrent-writer caveat: two concurrent non-zero writers can
// produce a reader-visible cross-pair (timestamp from writer A,
// count from writer B). Both values are still non-zero, so the
// grace-window message stays truthful — the count is a valid
// non-zero snapshot from a recent write, just possibly not the
// one paired with the timestamp. Acceptable because the check's
// contract is "is there a recent non-zero count?", not "exactly
// which write produced the timestamp?".
type ACPeerChecker struct {
	counter     ACPeerCounter
	gracePeriod time.Duration

	// lastNonZeroCount is the most recent non-zero count seen; used in
	// the grace-window message so the existing "N AC peer(s)
	// connected" pattern (consumed by smoke regex) keeps matching with
	// the cached value rather than 0. See type doc for the write-order
	// invariant with lastNonZeroAt.
	lastNonZeroCount atomic.Int32
	// lastNonZeroAt is the wall-clock nano timestamp at which the
	// counter last returned > 0. Atomic int64 for lock-free reads
	// from concurrent /health/knock-ready handlers.
	//
	// Stored as wall-clock nanoseconds (UnixNano), not a time.Time —
	// which means the monotonic-clock reading on the original time.Time
	// is stripped. The grace-window comparison is therefore a pure
	// wall-clock subtraction. A wall-clock jump backward (NTP step,
	// VM resume, leap-second smear) can produce a negative age (read
	// by the grace check as "within window" → spurious pass) or a very
	// large positive age (spurious fail). This is the standard trade-
	// off for lock-free atomic timestamps; the health check is a
	// failure-detection gate, not a billing ledger, so the drift
	// window matters less than the lock-free read path.
	//
	// An alternative — storing "nanos since checker boot" from a
	// monotonic time.Time captured at NewACPeerChecker — would
	// preserve monotonicity while staying int64-atomic. Passed on it
	// because (a) the failure mode is bounded to ~one probe's worth
	// of wrong verdict on either side of a jump, (b) NLB target-group
	// health checks are themselves debounced (multiple consecutive
	// failures before deregister), so one spurious 503 or 200 doesn't
	// move traffic, and (c) UnixNano keeps fake-clock tests simple —
	// they can seed any epoch without having to match a monotonic
	// anchor captured at construction.
	lastNonZeroAt atomic.Int64

	// now is injected for deterministic tests; production calls time.Now.
	// Used for the grace-window comparison AND for result.SetDuration so
	// fake-clock tests don't mix injected and wall-clock times.
	now func() time.Time

	// onGraceAbsorbed, if non-nil, fires once per Check() call that
	// returned pass from the grace-window branch. Wired in
	// endpoints/server/httpserver.go to MetricACGraceAbsorbed so
	// operators can distinguish "debounce absorbed a single-
	// keepalive flicker" from "AC cluster is broken and the grace
	// window is hiding it" (pair with KnockNoAC rate). Optional so
	// unit tests can instantiate the checker without a metrics surface.
	onGraceAbsorbed func()
}

// ACPeerCheckerConfig holds configuration for the AC peer checker.
type ACPeerCheckerConfig struct {
	// Counter provides access to the AC peer count.
	Counter ACPeerCounter
	// GracePeriod is the debounce window for transient zero-peer states.
	//
	// Resolution:
	//   - 0             → DefaultACPeerGracePeriod
	//   - negative      → disabled (zero peers fails immediately;
	//                     useful for failure-injection tests)
	//   - positive      → used as-is
	//
	// This package does NOT clamp the positive branch. Callers that
	// accept operator-supplied values (see
	// server.acPeerGracePeriodFromConfig) should clamp into
	// [MinACPeerGracePeriod, MaxACPeerGracePeriod] before passing here.
	GracePeriod time.Duration
	// OnGraceAbsorbed, if non-nil, is invoked once per Check() call
	// that returned pass from the grace-window branch. The health
	// package stays metrics-agnostic; this callback lets the caller
	// plug in any observability surface. Expected wiring is a
	// MetricCounter increment (see MetricACGraceAbsorbed).
	OnGraceAbsorbed func()
	// now is an optional clock injection for tests; nil uses time.Now.
	now func() time.Time
}

// NewACPeerChecker creates a new AC peer health checker.
func NewACPeerChecker(cfg *ACPeerCheckerConfig) *ACPeerChecker {
	gp := cfg.GracePeriod
	switch {
	case gp == 0:
		gp = DefaultACPeerGracePeriod
	case gp < 0:
		gp = 0 // disabled
	}
	nowFn := cfg.now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &ACPeerChecker{
		counter:         cfg.Counter,
		gracePeriod:     gp,
		now:             nowFn,
		onGraceAbsorbed: cfg.OnGraceAbsorbed,
	}
}

// Name returns the checker name.
func (c *ACPeerChecker) Name() string {
	return "ac_peers"
}

// IsCritical returns true — a server with no AC peers cannot serve knock traffic.
func (c *ACPeerChecker) IsCritical() bool {
	return true
}

// GracePeriod returns the effective grace window (after disabled handling).
// Exposed for the boot log line in httpserver.go so operators can confirm
// what's actually active, not just what was configured.
func (c *ACPeerChecker) GracePeriod() time.Duration {
	return c.gracePeriod
}

// Check counts connected AC peers and fails if zero, with a grace
// window that absorbs single-keepalive-cycle flickers (see type doc).
func (c *ACPeerChecker) Check(_ context.Context) *CheckResult {
	start := c.now()
	result := &CheckResult{
		Name:      c.Name(),
		Timestamp: start,
		Critical:  c.IsCritical(),
	}

	if c.counter == nil {
		result.Status = CheckStatusSkip
		result.Message = "AC peer counter not configured"
		result.SetDuration(c.now().Sub(start))
		return result
	}

	count := c.counter.ACPeerCount()
	if count > 0 {
		// Count before timestamp — see type doc's "atomic-field ordering
		// invariant" for the full reasoning.
		c.lastNonZeroCount.Store(int32(count)) //nolint:gosec // count is len(acConnectionMap); number of unique AC IDs is always far below int32 max
		c.lastNonZeroAt.Store(start.UnixNano())
		result.Status = CheckStatusPass
		result.Message = fmt.Sprintf("%d AC peer(s) connected", count)
		result.SetDuration(c.now().Sub(start))
		return result
	}

	// count == 0 — apply grace window if we've ever seen a non-zero count.
	lastNanos := c.lastNonZeroAt.Load()
	if c.gracePeriod > 0 && lastNanos > 0 {
		// Direct nano-subtraction avoids the intermediate time.Time
		// value that time.Unix(0, lastNanos) would build; same math,
		// zero allocation on the hot path. See the lastNonZeroAt
		// field doc for the wall-clock-jump caveat — either form
		// would observe it identically.
		age := time.Duration(start.UnixNano() - lastNanos)
		// Clamp negative ages to zero. A negative age can appear if
		// the wall clock steps backward (NTP adjustment, VM suspend)
		// between the non-zero write and this read. age <= gracePeriod
		// is already true for negatives so the grace path would render
		// anyway — but age.Round(time.Second) on a negative duration
		// renders as "-Xs", which the smoke regex's \d+[^,]+ suffix
		// pattern won't match (leading minus is not a digit). Rather
		// than surface a malformed wire-format string during a clock
		// jump, treat negative ages as "just happened" and continue.
		if age < 0 {
			age = 0
		}
		if age <= c.gracePeriod {
			cached := c.lastNonZeroCount.Load()
			result.Status = CheckStatusPass
			// WIRE-FORMAT CONTRACT — this Sprintf's shape is consumed
			// by the smoke test regex at
			//   tests/smoke/01_health_test.go (knockReadyPeerCountPattern)
			// which accepts both:
			//   "N AC peer(s) connected"
			//   "N AC peer(s) connected (cached, live=0 for <dur>, within <dur> grace)"
			// Renaming "cached", "live=0", or "grace"; moving the
			// parenthesized suffix; or adding a comma inside it will
			// break the smoke regex and trip downstream CI. If the
			// format needs to change, update that test's pattern in
			// the same PR.
			result.Message = fmt.Sprintf(
				"%d AC peer(s) connected (cached, live=0 for %s, within %s grace)",
				cached, age.Round(time.Second), c.gracePeriod,
			)
			if c.onGraceAbsorbed != nil {
				c.onGraceAbsorbed()
			}
			result.SetDuration(c.now().Sub(start))
			return result
		}
	}

	result.Status = CheckStatusFail
	result.Message = "no AC peers connected"
	result.SetDuration(c.now().Sub(start))
	return result
}

// Compile-time interface check.
var _ Checker = (*ACPeerChecker)(nil)
