package ac

import (
	"sync"
	"testing"
	"time"
)

// mockClock is a controllable clock for testing rate limiter timing.
type mockClock struct {
	mu  sync.Mutex
	now time.Time
}

func newMockClock(t time.Time) *mockClock {
	return &mockClock{now: t}
}

func (c *mockClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mockClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// TestDNSRateLimiter_FirstChangeAlwaysAllowed verifies that the first DNS
// change for a hostname is always processed.
func TestDNSRateLimiter_FirstChangeAlwaysAllowed(t *testing.T) {
	rl := NewDNSChangeRateLimiter()
	if !rl.ShouldProcess("server.test", "10.0.0.1:62206", "10.0.0.2:62206") {
		t.Error("First DNS change should always be allowed")
	}
}

// TestDNSRateLimiter_ChangesWithinThresholdAllowed verifies that DNS changes
// are allowed as long as the count stays within the maxEvents threshold.
func TestDNSRateLimiter_ChangesWithinThresholdAllowed(t *testing.T) {
	clock := newMockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	rl := NewDNSChangeRateLimiter(
		WithWindow(60*time.Second, 3),
		WithCooldown(30*time.Second),
	)
	rl.nowFunc = clock.Now

	// First 3 changes should be allowed (threshold is 3)
	for i := 0; i < 3; i++ {
		clock.Advance(1 * time.Second)
		if !rl.ShouldProcess("server.test", "old", "new") {
			t.Errorf("Change %d should be allowed (within threshold)", i+1)
		}
	}
}

// TestDNSRateLimiter_CooldownAfterThresholdExceeded verifies that once
// maxEvents+1 changes occur within the window, a cooldown is applied.
// The change that triggers the cooldown IS processed, but subsequent
// changes are suppressed.
func TestDNSRateLimiter_CooldownAfterThresholdExceeded(t *testing.T) {
	clock := newMockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	rl := NewDNSChangeRateLimiter(
		WithWindow(60*time.Second, 3),
		WithCooldown(30*time.Second),
	)
	rl.nowFunc = clock.Now

	// Generate maxEvents+1 changes to trigger cooldown
	for i := 0; i < 4; i++ {
		clock.Advance(1 * time.Second)
		allowed := rl.ShouldProcess("server.test", "old", "new")
		// All 4 should be processed — cooldown starts AFTER the 4th
		if !allowed {
			t.Errorf("Change %d should be allowed (cooldown starts after threshold exceeded)", i+1)
		}
	}

	// Next change should be suppressed (cooldown active)
	clock.Advance(1 * time.Second)
	if rl.ShouldProcess("server.test", "old", "new2") {
		t.Error("Change during cooldown should be suppressed")
	}
}

// TestDNSRateLimiter_CooldownExpires verifies that after the cooldown period,
// DNS changes are processed again.
func TestDNSRateLimiter_CooldownExpires(t *testing.T) {
	clock := newMockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	rl := NewDNSChangeRateLimiter(
		WithWindow(60*time.Second, 3),
		WithCooldown(30*time.Second),
	)
	rl.nowFunc = clock.Now

	// Trigger cooldown: 4 changes in rapid succession
	for i := 0; i < 4; i++ {
		clock.Advance(1 * time.Second)
		rl.ShouldProcess("server.test", "old", "new")
	}

	// Verify suppressed during cooldown
	clock.Advance(1 * time.Second)
	if rl.ShouldProcess("server.test", "old", "suppressed") {
		t.Error("Should be suppressed during cooldown")
	}

	// Advance past cooldown
	clock.Advance(30 * time.Second)

	// Should be allowed again
	if !rl.ShouldProcess("server.test", "old", "after-cooldown") {
		t.Error("Should be allowed after cooldown expires")
	}
}

// TestDNSRateLimiter_SlidingWindowPrunes verifies that old events outside
// the window are pruned, preventing permanent rate limiting.
func TestDNSRateLimiter_SlidingWindowPrunes(t *testing.T) {
	clock := newMockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	rl := NewDNSChangeRateLimiter(
		WithWindow(10*time.Second, 2),
		WithCooldown(5*time.Second),
	)
	rl.nowFunc = clock.Now

	// Two changes, both allowed (at threshold)
	rl.ShouldProcess("server.test", "old", "ip1")
	clock.Advance(1 * time.Second)
	rl.ShouldProcess("server.test", "ip1", "ip2")

	// Advance past the window so old events are pruned
	clock.Advance(11 * time.Second)

	// Two more changes should be allowed (old events pruned)
	if !rl.ShouldProcess("server.test", "ip2", "ip3") {
		t.Error("Should be allowed after window expires (old events pruned)")
	}
	clock.Advance(1 * time.Second)
	if !rl.ShouldProcess("server.test", "ip3", "ip4") {
		t.Error("Second change after window should be allowed")
	}
}

// TestDNSRateLimiter_IndependentHostnames verifies that rate limiting is
// per-hostname — changes to one hostname don't affect another.
func TestDNSRateLimiter_IndependentHostnames(t *testing.T) {
	clock := newMockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	rl := NewDNSChangeRateLimiter(
		WithWindow(60*time.Second, 2),
		WithCooldown(30*time.Second),
	)
	rl.nowFunc = clock.Now

	// Trigger cooldown on server-a
	for i := 0; i < 3; i++ {
		clock.Advance(1 * time.Second)
		rl.ShouldProcess("server-a", "old", "new")
	}

	// server-a should be suppressed
	clock.Advance(1 * time.Second)
	if rl.ShouldProcess("server-a", "old", "new") {
		t.Error("server-a should be rate-limited")
	}

	// server-b should be unaffected
	if !rl.ShouldProcess("server-b", "old", "new") {
		t.Error("server-b should not be affected by server-a rate limiting")
	}
}

// TestDNSRateLimiter_Reset verifies that Reset clears state for a hostname.
func TestDNSRateLimiter_Reset(t *testing.T) {
	clock := newMockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	rl := NewDNSChangeRateLimiter(
		WithWindow(60*time.Second, 2),
		WithCooldown(30*time.Second),
	)
	rl.nowFunc = clock.Now

	// Trigger cooldown
	for i := 0; i < 3; i++ {
		clock.Advance(1 * time.Second)
		rl.ShouldProcess("server.test", "old", "new")
	}

	// Should be suppressed
	clock.Advance(1 * time.Second)
	if rl.ShouldProcess("server.test", "old", "new") {
		t.Error("Should be suppressed before reset")
	}

	// Reset clears cooldown
	rl.Reset("server.test")

	// Should be allowed again
	if !rl.ShouldProcess("server.test", "old", "new") {
		t.Error("Should be allowed after reset")
	}
}

// TestDNSRateLimiter_ResetAll verifies that ResetAll clears all state.
func TestDNSRateLimiter_ResetAll(t *testing.T) {
	rl := NewDNSChangeRateLimiter()

	rl.ShouldProcess("server-a", "old", "new")
	rl.ShouldProcess("server-b", "old", "new")

	rl.ResetAll()

	// Stats should be empty
	changes, inCooldown, suppressed := rl.Stats("server-a")
	if changes != 0 || inCooldown || suppressed != 0 {
		t.Error("Stats should be zero after ResetAll")
	}
}

// TestDNSRateLimiter_Stats verifies that Stats returns accurate information.
func TestDNSRateLimiter_Stats(t *testing.T) {
	clock := newMockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	rl := NewDNSChangeRateLimiter(
		WithWindow(60*time.Second, 2),
		WithCooldown(30*time.Second),
	)
	rl.nowFunc = clock.Now

	// No state yet
	changes, inCooldown, suppressed := rl.Stats("server.test")
	if changes != 0 || inCooldown || suppressed != 0 {
		t.Error("Initial stats should be zero")
	}

	// Add some changes
	rl.ShouldProcess("server.test", "old", "ip1")
	clock.Advance(1 * time.Second)
	rl.ShouldProcess("server.test", "ip1", "ip2")

	changes, inCooldown, _ = rl.Stats("server.test")
	if changes != 2 {
		t.Errorf("Expected 2 changes in window, got %d", changes)
	}
	if inCooldown {
		t.Error("Should not be in cooldown yet (at threshold)")
	}

	// Trigger cooldown
	clock.Advance(1 * time.Second)
	rl.ShouldProcess("server.test", "ip2", "ip3")

	_, inCooldown, _ = rl.Stats("server.test")
	if !inCooldown {
		t.Error("Should be in cooldown after exceeding threshold")
	}

	// Suppress a change
	clock.Advance(1 * time.Second)
	rl.ShouldProcess("server.test", "ip3", "ip4")

	_, _, suppressed = rl.Stats("server.test")
	if suppressed != 1 {
		t.Errorf("Expected 1 suppressed, got %d", suppressed)
	}
}

// TestDNSRateLimiter_ConcurrentAccess verifies thread safety of the rate limiter.
func TestDNSRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewDNSChangeRateLimiter()

	const numGoroutines = 10
	const numIterations = 100
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			hostname := "server.test"
			for j := 0; j < numIterations; j++ {
				rl.ShouldProcess(hostname, "old", "new")
				rl.Stats(hostname)
			}
		}(i)
	}

	wg.Wait()
	// No panic = thread-safe
}

// TestDNSRateLimiter_CustomOptions verifies that custom options override defaults.
func TestDNSRateLimiter_CustomOptions(t *testing.T) {
	rl := NewDNSChangeRateLimiter(
		WithCooldown(10*time.Second),
		WithWindow(30*time.Second, 5),
	)

	if rl.cooldown != 10*time.Second {
		t.Errorf("Expected cooldown 10s, got %s", rl.cooldown)
	}
	if rl.windowSize != 30*time.Second {
		t.Errorf("Expected window 30s, got %s", rl.windowSize)
	}
	if rl.maxEvents != 5 {
		t.Errorf("Expected maxEvents 5, got %d", rl.maxEvents)
	}
}

// TestDNSRateLimiter_InvalidOptionsIgnored verifies that zero/negative options
// are ignored and defaults are used.
func TestDNSRateLimiter_InvalidOptionsIgnored(t *testing.T) {
	rl := NewDNSChangeRateLimiter(
		WithCooldown(0),
		WithCooldown(-1*time.Second),
		WithWindow(0, 0),
		WithWindow(-1*time.Second, -1),
	)

	if rl.cooldown != DefaultDNSChangeCooldown {
		t.Errorf("Expected default cooldown, got %s", rl.cooldown)
	}
	if rl.windowSize != DefaultDNSChangeWindowSize {
		t.Errorf("Expected default window, got %s", rl.windowSize)
	}
	if rl.maxEvents != DefaultDNSChangeMaxEvents {
		t.Errorf("Expected default maxEvents, got %d", rl.maxEvents)
	}
}

// TestDNSRateLimiter_SuppressedCountResetAfterCooldown verifies that the
// suppressed count is logged and reset when cooldown expires.
func TestDNSRateLimiter_SuppressedCountResetAfterCooldown(t *testing.T) {
	clock := newMockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	rl := NewDNSChangeRateLimiter(
		WithWindow(60*time.Second, 2),
		WithCooldown(10*time.Second),
	)
	rl.nowFunc = clock.Now

	// Trigger cooldown
	for i := 0; i < 3; i++ {
		clock.Advance(1 * time.Second)
		rl.ShouldProcess("server.test", "old", "new")
	}

	// Suppress 3 changes
	for i := 0; i < 3; i++ {
		clock.Advance(1 * time.Second)
		rl.ShouldProcess("server.test", "old", "suppressed")
	}

	_, _, suppressed := rl.Stats("server.test")
	if suppressed != 3 {
		t.Errorf("Expected 3 suppressed, got %d", suppressed)
	}

	// Advance past cooldown
	clock.Advance(10 * time.Second)

	// Process a new change — this should reset suppressed count
	if !rl.ShouldProcess("server.test", "old", "after-cooldown") {
		t.Error("Should be allowed after cooldown")
	}

	_, _, suppressed = rl.Stats("server.test")
	if suppressed != 0 {
		t.Errorf("Suppressed count should be reset after cooldown, got %d", suppressed)
	}
}

// TestDNSRateLimiter_MultipleCooldownCycles verifies that the rate limiter
// works correctly across multiple cooldown cycles.
func TestDNSRateLimiter_MultipleCooldownCycles(t *testing.T) {
	clock := newMockClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	rl := NewDNSChangeRateLimiter(
		WithWindow(5*time.Second, 2),
		WithCooldown(5*time.Second),
	)
	rl.nowFunc = clock.Now

	for cycle := 0; cycle < 3; cycle++ {
		// Wait for window to clear from previous cycle
		clock.Advance(10 * time.Second)

		// Trigger cooldown
		for i := 0; i < 3; i++ {
			clock.Advance(500 * time.Millisecond)
			allowed := rl.ShouldProcess("server.test", "old", "new")
			if !allowed {
				t.Errorf("Cycle %d, change %d: should be allowed", cycle, i+1)
			}
		}

		// Should be suppressed
		clock.Advance(500 * time.Millisecond)
		if rl.ShouldProcess("server.test", "old", "suppressed") {
			t.Errorf("Cycle %d: should be suppressed during cooldown", cycle)
		}

		// Wait for cooldown to expire
		clock.Advance(5 * time.Second)

		// Should be allowed again
		if !rl.ShouldProcess("server.test", "old", "after-cooldown") {
			t.Errorf("Cycle %d: should be allowed after cooldown", cycle)
		}
	}
}

func TestDNSRateLimiter_LastProcessedAddress(t *testing.T) {
	clock := newMockClock(time.Now())
	rl := NewDNSChangeRateLimiter(
		WithCooldown(10*time.Second),
		WithWindow(5*time.Second, 2),
	)
	rl.nowFunc = clock.Now

	// First change: addr-A is processed
	if !rl.ShouldProcess("server.test", "", "addr-A") {
		t.Fatal("first change should always be allowed")
	}

	// Second change: addr-B is processed (still within threshold)
	clock.Advance(100 * time.Millisecond)
	if !rl.ShouldProcess("server.test", "addr-A", "addr-B") {
		t.Fatal("second change should be allowed (at threshold)")
	}
	// At this point, lastProcessedAddress = "addr-B"

	// Third change triggers cooldown — addr-C is the last processed before cooldown suppression starts
	clock.Advance(100 * time.Millisecond)
	if !rl.ShouldProcess("server.test", "addr-B", "addr-C") {
		t.Fatal("third change should be allowed (triggers cooldown but still processed)")
	}

	// Verify cooldown is active
	clock.Advance(100 * time.Millisecond)
	if rl.ShouldProcess("server.test", "addr-C", "addr-D") {
		t.Fatal("fourth change should be suppressed during cooldown")
	}

	// addr-E is suppressed too
	clock.Advance(100 * time.Millisecond)
	if rl.ShouldProcess("server.test", "addr-D", "addr-E") {
		t.Fatal("fifth change should be suppressed during cooldown")
	}

	// Verify internal state: lastProcessedAddress should be addr-C (last one that was actually processed)
	rl.mu.Lock()
	state := rl.peers["server.test"]
	if state.lastProcessedAddress != "addr-C" {
		t.Errorf("lastProcessedAddress = %q, want %q", state.lastProcessedAddress, "addr-C")
	}
	rl.mu.Unlock()

	// Wait for cooldown to expire
	clock.Advance(10 * time.Second)

	// After cooldown, processing a new address should update lastProcessedAddress
	if !rl.ShouldProcess("server.test", "addr-E", "addr-F") {
		t.Fatal("should be allowed after cooldown expires")
	}

	rl.mu.Lock()
	state = rl.peers["server.test"]
	if state.lastProcessedAddress != "addr-F" {
		t.Errorf("after cooldown: lastProcessedAddress = %q, want %q", state.lastProcessedAddress, "addr-F")
	}
	rl.mu.Unlock()
}
