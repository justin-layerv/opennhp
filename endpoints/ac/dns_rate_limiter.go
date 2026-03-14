package ac

import (
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/nhp/log"
)

const (
	// DefaultDNSChangeCooldown is the minimum interval between processing
	// consecutive DNS address changes for the same server peer. If DNS flaps
	// (e.g., rapid A-record changes during an incident), this prevents the AC
	// from cycling through connections faster than it can establish them.
	//
	// 30 seconds allows a typical NHP connection to fully establish (TLS
	// handshake + NHP registration) before the next address change is
	// processed, preventing half-open connection storms.
	DefaultDNSChangeCooldown = 30 * time.Second

	// DefaultDNSChangeWindowSize is the sliding window duration used to count
	// DNS change events. If more than DefaultDNSChangeMaxEvents occur within
	// this window, the cooldown is applied.
	//
	// 60 seconds tolerates blue/green deployments (typically 1-2 DNS changes)
	// and brief DNS propagation glitches, while catching sustained flapping.
	DefaultDNSChangeWindowSize = 60 * time.Second

	// DefaultDNSChangeMaxEvents is the maximum number of DNS address changes
	// allowed within the sliding window before rate limiting kicks in.
	// The first change is always processed immediately; rate limiting only
	// applies to subsequent rapid changes.
	//
	// 3 changes per window allows: initial change + 1 retry + 1 correction.
	// A 4th change within 60 seconds indicates flapping, not a legitimate
	// deployment, and triggers the cooldown.
	DefaultDNSChangeMaxEvents = 3
)

// DNSChangeRateLimiter tracks DNS address changes per server peer and
// suppresses processing when changes occur too rapidly (DNS flapping).
//
// Thread-safe: all methods are safe for concurrent use.
type DNSChangeRateLimiter struct {
	mu sync.Mutex

	// Configurable parameters
	cooldown   time.Duration
	windowSize time.Duration
	maxEvents  int

	// Per-hostname state
	peers map[string]*dnsChangeState

	// nowFunc allows injecting a clock for testing.
	nowFunc func() time.Time
}

// dnsChangeState tracks the rate-limiting state for a single hostname.
type dnsChangeState struct {
	// changeTimestamps is a sliding window of recent DNS change timestamps.
	changeTimestamps []time.Time

	// cooldownUntil is the time until which further DNS changes are suppressed.
	// Zero value means no active cooldown.
	cooldownUntil time.Time

	// suppressedCount tracks how many changes were suppressed during cooldown,
	// for logging purposes.
	suppressedCount int

	// lastProcessedAddress is the address that was last actually processed
	// (not suppressed). Used to determine whether a change needs processing
	// after cooldown expires.
	lastProcessedAddress string
}

// DNSRateLimiterOption configures a DNSChangeRateLimiter.
type DNSRateLimiterOption func(*DNSChangeRateLimiter)

// WithCooldown sets the cooldown duration between DNS change processing.
func WithCooldown(d time.Duration) DNSRateLimiterOption {
	return func(r *DNSChangeRateLimiter) {
		if d > 0 {
			r.cooldown = d
		}
	}
}

// WithWindow sets the sliding window size and max events threshold.
func WithWindow(windowSize time.Duration, maxEvents int) DNSRateLimiterOption {
	return func(r *DNSChangeRateLimiter) {
		if windowSize > 0 {
			r.windowSize = windowSize
		}
		if maxEvents > 0 {
			r.maxEvents = maxEvents
		}
	}
}

// NewDNSChangeRateLimiter creates a rate limiter with the given options.
// Without options, defaults are used.
func NewDNSChangeRateLimiter(opts ...DNSRateLimiterOption) *DNSChangeRateLimiter {
	r := &DNSChangeRateLimiter{
		cooldown:   DefaultDNSChangeCooldown,
		windowSize: DefaultDNSChangeWindowSize,
		maxEvents:  DefaultDNSChangeMaxEvents,
		peers:      make(map[string]*dnsChangeState),
		nowFunc:    time.Now,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// ShouldProcess reports whether a DNS address change for the given hostname
// should be processed. It returns true if the change should be processed
// immediately, or false if it should be suppressed due to rate limiting.
//
// Parameters:
//   - hostname: the server peer hostname (used as the rate-limiting key)
//   - oldAddr: the previous address string (for logging)
//   - newAddr: the new address string
//
// The first change for a hostname is always allowed. Subsequent changes
// within the sliding window are counted; once maxEvents is exceeded, a
// cooldown is applied and further changes are suppressed until the cooldown
// expires.
func (r *DNSChangeRateLimiter) ShouldProcess(hostname, oldAddr, newAddr string) bool {
	// Deferred log messages — collected under lock, emitted after unlock.
	type logMsg struct {
		warning bool
		format  string
		args    []any
	}
	var logs []logMsg

	allowed := func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()

		now := r.nowFunc()

		state, exists := r.peers[hostname]
		if !exists {
			state = &dnsChangeState{}
			r.peers[hostname] = state
		}

		// Check if we're in a cooldown period
		if !state.cooldownUntil.IsZero() && now.Before(state.cooldownUntil) {
			state.suppressedCount++
			remaining := state.cooldownUntil.Sub(now).Round(time.Second)
			logs = append(logs, logMsg{warning: true,
				format: "[DNSRateLimiter] Suppressing DNS change for %s (%s -> %s): " +
					"cooldown active, %s remaining (%d changes suppressed)",
				args: []any{hostname, oldAddr, newAddr, remaining, state.suppressedCount}})
			return false
		}

		// If cooldown just expired, reset suppressed count and log
		if !state.cooldownUntil.IsZero() {
			if state.suppressedCount > 0 {
				logs = append(logs, logMsg{warning: false,
					format: "[DNSRateLimiter] Cooldown expired for %s, suppressed %d DNS changes. " +
						"Processing current address %s (last processed: %s)",
					args: []any{hostname, state.suppressedCount, newAddr, state.lastProcessedAddress}})
			}
			state.cooldownUntil = time.Time{}
			state.suppressedCount = 0
		}

		// Prune timestamps outside the sliding window
		cutoff := now.Add(-r.windowSize)
		pruned := state.changeTimestamps[:0]
		for _, ts := range state.changeTimestamps {
			if ts.After(cutoff) {
				pruned = append(pruned, ts)
			}
		}
		state.changeTimestamps = pruned

		// Record this change
		state.changeTimestamps = append(state.changeTimestamps, now)

		// Check if we've exceeded the threshold
		if len(state.changeTimestamps) > r.maxEvents {
			state.cooldownUntil = now.Add(r.cooldown)
			state.suppressedCount = 0
			logs = append(logs, logMsg{warning: true,
				format: "[DNSRateLimiter] DNS flapping detected for %s: %d changes in %s window. " +
					"Applying %s cooldown (processing this change, suppressing subsequent ones)",
				args: []any{hostname, len(state.changeTimestamps), r.windowSize, r.cooldown}})
		}

		state.lastProcessedAddress = newAddr
		return true
	}()

	// Emit logs outside the lock to avoid blocking other goroutines
	for _, l := range logs {
		if l.warning {
			log.Warning(l.format, l.args...)
		} else {
			log.Info(l.format, l.args...)
		}
	}

	return allowed
}

// Reset clears all rate-limiting state for the given hostname.
// Call this when a server peer is removed or the AC restarts.
func (r *DNSChangeRateLimiter) Reset(hostname string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.peers, hostname)
}

// ResetAll clears all rate-limiting state.
func (r *DNSChangeRateLimiter) ResetAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers = make(map[string]*dnsChangeState)
}

// Stats returns current rate-limiting statistics for a hostname.
// Useful for diagnostics and metrics.
func (r *DNSChangeRateLimiter) Stats(hostname string) (changesInWindow int, inCooldown bool, suppressedCount int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, exists := r.peers[hostname]
	if !exists {
		return 0, false, 0
	}

	now := r.nowFunc()

	// Count events in current window
	cutoff := now.Add(-r.windowSize)
	for _, ts := range state.changeTimestamps {
		if ts.After(cutoff) {
			changesInWindow++
		}
	}

	inCooldown = !state.cooldownUntil.IsZero() && now.Before(state.cooldownUntil)
	suppressedCount = state.suppressedCount

	return changesInWindow, inCooldown, suppressedCount
}
