package server

import (
	"fmt"
	"testing"
	"time"
)

// TestOTPRateLimiter_PerKeyCapacityAndRefill fences the per-key bucket: a key
// gets exactly Capacity requests in a burst, is throttled once drained, then
// regains tokens as RefillInterval(s) elapse. Uses a small refill interval so
// the refill is observable without a real 5-minute wait, and a huge global
// capacity so the global bucket never interferes.
//
// DEFLAKE: this asserts a LOWER BOUND on the refill, never an exact count. A
// wall-clock sleep on a loaded CI runner can overshoot into extra RefillIntervals,
// so an "exactly one token refilled" assertion is inherently racy. Instead we
// drain the bucket, sleep well beyond a single interval, and require only that
// AT LEAST one token came back (proving time-based refill happens) while the
// bucket still never exceeds Capacity (proving the ceiling holds no matter how
// many intervals a slow runner slept through). Both bounds are timing-robust:
// oversleeping can only add tokens up to the Capacity cap, never past it.
func TestOTPRateLimiter_PerKeyCapacityAndRefill(t *testing.T) {
	const refill = 20 * time.Millisecond
	rl := NewOTPRateLimiter(OTPRateLimiterConfig{
		Capacity:       3,
		RefillInterval: refill,
		GlobalCapacity: 1_000_000,
		GlobalRate:     1_000_000,
		IdleTTL:        time.Minute,
		MaxKeys:        16,
	})

	const key = "keyA"
	// Fresh key starts full: exactly Capacity (3) admits, the 4th is throttled.
	for i := 0; i < 3; i++ {
		if !rl.Allow(key) {
			t.Fatalf("request %d for a fresh key was throttled; a fresh key must start at full capacity (3)", i+1)
		}
	}
	if rl.Allow(key) {
		t.Fatal("4th request in a burst was admitted; per-key capacity (3) must throttle it")
	}

	// Sleep well beyond a single interval (5x) so even a slow/loaded runner has
	// crossed at least one RefillInterval — a lower bound we can assert without
	// racing an exact token count.
	time.Sleep(5 * refill)
	if !rl.Allow(key) {
		t.Fatal("no token refilled after 5 refill intervals; the per-key bucket must regain tokens over time")
	}

	// The bucket must never exceed Capacity, no matter how many intervals elapsed:
	// drain it fully and confirm it admits at MOST Capacity-1 more (we already
	// spent one just above) before throttling. This upper bound is capped by
	// Capacity, not by interval timing, so oversleeping cannot make it flaky.
	admitted := 1 // the Allow above
	for i := 0; i < 3; i++ {
		if rl.Allow(key) {
			admitted++
		}
	}
	if admitted > 3 {
		t.Fatalf("bucket admitted %d requests after refilling; must never exceed Capacity=3 even after many idle intervals", admitted)
	}
	if rl.Allow(key) {
		t.Fatal("request admitted past a drained, Capacity-capped bucket; refill must not exceed Capacity")
	}
}

// TestOTPRateLimiter_KeysAreIndependent proves per-key isolation: exhausting one
// key does not throttle another (until the global bucket binds, which this test
// keeps out of the way with a large global capacity).
func TestOTPRateLimiter_KeysAreIndependent(t *testing.T) {
	rl := NewOTPRateLimiter(OTPRateLimiterConfig{
		Capacity:       2,
		RefillInterval: time.Hour, // effectively no refill during the test
		GlobalCapacity: 1_000_000,
		GlobalRate:     1_000_000,
		IdleTTL:        time.Minute,
		MaxKeys:        16,
	})

	// Drain keyA.
	if !rl.Allow("keyA") || !rl.Allow("keyA") {
		t.Fatal("keyA should admit its first 2 requests")
	}
	if rl.Allow("keyA") {
		t.Fatal("keyA should be throttled after its capacity is drained")
	}
	// keyB is unaffected.
	if !rl.Allow("keyB") || !rl.Allow("keyB") {
		t.Fatal("keyB should admit its own 2 requests independently of keyA")
	}
	if rl.Allow("keyB") {
		t.Fatal("keyB should throttle after its own capacity is drained")
	}
}

// TestOTPRateLimiter_GlobalCapBoundsAggregate proves the process-global bucket
// caps aggregate cost across MANY distinct keys — the key-rotation defense.
// Per-key capacity is generous, but the global bucket (2, no refill) admits only
// 2 requests total across a flood of fresh keys.
func TestOTPRateLimiter_GlobalCapBoundsAggregate(t *testing.T) {
	rl := NewOTPRateLimiter(OTPRateLimiterConfig{
		Capacity:       100, // per-key is not the binding constraint here
		RefillInterval: time.Millisecond,
		GlobalCapacity: 2,
		GlobalRate:     0.0000001, // effectively no global refill during the test
		IdleTTL:        time.Minute,
		MaxKeys:        4096,
	})

	admitted := 0
	for i := 0; i < 50; i++ {
		// A fresh key each iteration — per-key limits never bind; only the global
		// cap can stop this.
		if rl.Allow(fmt.Sprintf("rotating-key-%d", i)) {
			admitted++
		}
	}
	if admitted != 2 {
		t.Fatalf("global cap admitted %d requests across 50 fresh keys; want exactly GlobalCapacity=2 (key rotation must not defeat the aggregate cap)", admitted)
	}
}

// TestOTPRateLimiter_RejectDoesNotDrainGlobal proves a per-key reject does not
// consume from the global bucket: a key that is locally throttled must not burn
// the shared budget other keys depend on. Drains keyA locally (global has plenty),
// hammers keyA past its limit, then confirms a different key still has the full
// global budget minus only the admitted requests.
func TestOTPRateLimiter_RejectDoesNotDrainGlobal(t *testing.T) {
	rl := NewOTPRateLimiter(OTPRateLimiterConfig{
		Capacity:       1,
		RefillInterval: time.Hour,
		GlobalCapacity: 5,
		GlobalRate:     0.0000001,
		IdleTTL:        time.Minute,
		MaxKeys:        16,
	})

	// keyA: 1 admit (consumes 1 global), then many rejects (must consume 0 global).
	if !rl.Allow("keyA") {
		t.Fatal("keyA first request should be admitted")
	}
	for i := 0; i < 10; i++ {
		if rl.Allow("keyA") {
			t.Fatal("keyA should stay throttled after its single token is spent")
		}
	}

	// Global should have 4 left (5 - 1 admitted). Distinct fresh keys should be
	// able to consume exactly those 4, proving the 10 rejects burned nothing.
	admitted := 0
	for i := 0; i < 10; i++ {
		if rl.Allow(fmt.Sprintf("fresh-%d", i)) {
			admitted++
		}
	}
	if admitted != 4 {
		t.Fatalf("after 1 global consume + 10 per-key rejects, fresh keys admitted %d; want 4 (rejects must not drain the global bucket)", admitted)
	}
}

// TestOTPRateLimiter_LRUEvictsBeyondMaxKeys proves the per-key table is bounded:
// tracking never exceeds MaxKeys, so a key-rotating flood cannot grow it
// unbounded. (An evicted key simply re-arrives with a fresh bucket; the global
// cap still bounds aggregate cost.)
func TestOTPRateLimiter_LRUEvictsBeyondMaxKeys(t *testing.T) {
	const maxKeys = 8
	rl := NewOTPRateLimiter(OTPRateLimiterConfig{
		Capacity:       5,
		RefillInterval: time.Minute,
		GlobalCapacity: 1_000_000, // don't let the global cap stop the fresh keys
		GlobalRate:     1_000_000,
		IdleTTL:        time.Minute,
		MaxKeys:        maxKeys,
	})

	for i := 0; i < 100; i++ {
		rl.Allow(fmt.Sprintf("key-%d", i))
	}
	if got := rl.Len(); got > maxKeys {
		t.Fatalf("tracked keys = %d, want <= MaxKeys=%d (LRU must bound the table under key rotation)", got, maxKeys)
	}
}

// TestOTPRateLimiter_NilAllows proves a nil limiter admits everything — the
// test-only unbounded affordance mirroring the nil rateLimiter/handlerSem
// pattern, so bare &UdpServer{} literals in tests dispatch OTP without a limiter.
func TestOTPRateLimiter_NilAllows(t *testing.T) {
	var rl *OTPRateLimiter
	if !rl.Allow("anything") {
		t.Fatal("nil OTPRateLimiter must admit (unbounded) so test literals need no limiter wiring")
	}
}

// TestOTPRateLimiter_ZeroConfigFallsBackToDefaults proves the zero-value config
// is filled from DefaultOTPRateLimiterConfig (like NewIPRateLimiter), so a
// partial or empty config never yields a dead limiter (capacity 0 would throttle
// everything).
func TestOTPRateLimiter_ZeroConfigFallsBackToDefaults(t *testing.T) {
	rl := NewOTPRateLimiter(OTPRateLimiterConfig{})
	// Defaults give per-key capacity 3, so at least one request must be admitted.
	if !rl.Allow("k") {
		t.Fatal("zero-config limiter throttled the first request; zero fields must fall back to non-zero defaults")
	}
	def := DefaultOTPRateLimiterConfig()
	if rl.capacity != float64(def.Capacity) {
		t.Errorf("capacity = %v, want default %d", rl.capacity, def.Capacity)
	}
}
