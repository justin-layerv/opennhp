package server

import (
	"context"
	"errors"
	"testing"
	"time"
)

// newTestAnchor builds a fleetTrustAnchor with a controllable clock and a
// scripted discovery source. Mutate *clk between calls to advance time and
// reassign *result / *errp to script discovery; *calls counts discoveries.
func newTestAnchor(selfPub string, clk *time.Time, result *[]ServerInfo, errp *error, calls *int) *fleetTrustAnchor {
	return &fleetTrustAnchor{
		seen: make(map[string]time.Time),
		discover: func(context.Context) ([]ServerInfo, error) {
			*calls++
			return *result, *errp
		},
		selfPub: func() string { return selfPub },
		now:     func() time.Time { return *clk },
	}
}

// TestFleetTrustAnchor_Lifecycle walks one anchor through populate →
// throttle → sticky-survival → eviction, the revocation-critical path the
// handler/e2e tests bypass via injection.
func TestFleetTrustAnchor_Lifecycle(t *testing.T) {
	const self = "SELF_PUB"
	clk := time.Unix(1_700_000_000, 0)
	result := []ServerInfo{{PubKey: "A"}}
	var derr error
	var calls int
	a := newTestAnchor(self, &clk, &result, &derr, &calls)
	ctx := context.Background()

	// Populate: first call discovers A; A and self are trusted.
	set := a.known(ctx)
	if !set["A"] || !set[self] {
		t.Fatalf("after populate want A+self trusted, got %v", set)
	}
	if calls != 1 {
		t.Fatalf("want 1 discovery, got %d", calls)
	}

	// Throttle: a second call inside the refresh window does NOT re-discover.
	clk = clk.Add(forwardHopFleetCacheTTL / 2)
	set = a.known(ctx)
	if calls != 1 {
		t.Fatalf("throttle: want no extra discovery, got %d calls", calls)
	}
	if !set["A"] {
		t.Fatalf("throttle: A should still be trusted, got %v", set)
	}

	// Sticky survival: past the refresh window, A drops out of healthy
	// discovery (transient deploy unhealth) — but stays trusted because its
	// last sighting is within forwardHopTrustTTL.
	clk = clk.Add(forwardHopFleetCacheTTL) // now past refresh, ~0.75*cacheTTL+cacheTTL since last seen
	result = []ServerInfo{}                // A no longer healthy
	set = a.known(ctx)
	if calls != 2 {
		t.Fatalf("sticky: expected a refresh discovery, got %d calls", calls)
	}
	if !set["A"] {
		t.Fatalf("sticky: A should survive a transient health drop within TTL, got %v", set)
	}

	// Eviction: advance past forwardHopTrustTTL since A's last sighting; A is
	// now revoked (aged out) while self remains.
	clk = clk.Add(forwardHopTrustTTL)
	set = a.known(ctx)
	if set["A"] {
		t.Fatalf("eviction: A should be evicted past the trust TTL, got %v", set)
	}
	if !set[self] {
		t.Fatalf("eviction: self must remain trusted, got %v", set)
	}
}

// TestFleetTrustAnchor_DiscoveryErrorKeepsSet asserts a transient discovery
// error preserves the prior sticky set rather than failing closed.
func TestFleetTrustAnchor_DiscoveryErrorKeepsSet(t *testing.T) {
	const self = "SELF_PUB"
	clk := time.Unix(1_700_000_000, 0)
	result := []ServerInfo{{PubKey: "A"}}
	var derr error
	var calls int
	a := newTestAnchor(self, &clk, &result, &derr, &calls)
	ctx := context.Background()

	if set := a.known(ctx); !set["A"] {
		t.Fatalf("setup: A should be trusted, got %v", set)
	}

	clk = clk.Add(forwardHopFleetCacheTTL + time.Second)
	derr = errors.New("cloud map unavailable")
	result = []ServerInfo{{PubKey: "B"}} // would be merged if no error
	set := a.known(ctx)
	if !set["A"] {
		t.Fatalf("error path: prior set (A) must survive a discovery error, got %v", set)
	}
	if set["B"] {
		t.Fatalf("error path: failed discovery must not merge B, got %v", set)
	}
}

// TestFleetTrustAnchor_ErrorRetryBackoff asserts a failed discovery pulls the
// next attempt in to forwardHopFleetErrorRetry rather than waiting the full
// cache TTL — so a transient Cloud Map blip recovers promptly.
func TestFleetTrustAnchor_ErrorRetryBackoff(t *testing.T) {
	if forwardHopFleetErrorRetry+time.Second >= forwardHopFleetCacheTTL {
		t.Fatalf("test assumes error-retry (%v) < cache TTL (%v)", forwardHopFleetErrorRetry, forwardHopFleetCacheTTL)
	}
	const self = "SELF_PUB"
	clk := time.Unix(1_700_000_000, 0)
	result := []ServerInfo{}
	derr := errors.New("cloud map down")
	var calls int
	a := newTestAnchor(self, &clk, &result, &derr, &calls)
	ctx := context.Background()

	a.known(ctx) // discovery errors
	if calls != 1 {
		t.Fatalf("want 1 discovery, got %d", calls)
	}

	// Past the error-retry interval but still within the normal cache TTL:
	// discovery must retry (it wouldn't if the full TTL window were consumed).
	clk = clk.Add(forwardHopFleetErrorRetry + time.Second)
	derr = nil
	result = []ServerInfo{{PubKey: "A"}}
	set := a.known(ctx)
	if calls != 2 {
		t.Fatalf("error retry: want a re-discovery before the full cache TTL, got %d calls", calls)
	}
	if !set["A"] {
		t.Fatalf("after successful retry, A should be trusted, got %v", set)
	}
}

// TestFleetTrustAnchor_SelfAlwaysTrusted asserts self is trusted even when
// discovery returns nothing.
func TestFleetTrustAnchor_SelfAlwaysTrusted(t *testing.T) {
	const self = "SELF_PUB"
	clk := time.Unix(1_700_000_000, 0)
	result := []ServerInfo{}
	var derr error
	var calls int
	a := newTestAnchor(self, &clk, &result, &derr, &calls)

	set := a.known(context.Background())
	if !set[self] || len(set) != 1 {
		t.Fatalf("self must be trusted with empty discovery, got %v", set)
	}
}
