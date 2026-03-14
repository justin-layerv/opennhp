package server

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// License Validation Rate Limiter
// ============================================================================
//
// Prevents brute-force attacks on license keys by rate limiting failed
// validation attempts per source IP and per AC ID. Uses a sliding window
// approach with in-memory counters.
//
// Design decisions:
// - In-memory (Option A from issue #153): simple, no external dependencies.
//   Not shared across server instances, but each instance independently
//   blocks abuse which is sufficient for our deployment model.
// - Separate limits per IP and per AC ID to catch both distributed and
//   targeted attacks.
// - Configurable via storage.toml [RateLimit] section.
// - Expired entries are cleaned up periodically to prevent memory leaks.
// ============================================================================

// maxTimestampsPerWindow caps stored failure timestamps per entry to prevent
// memory growth under sustained brute-force attacks. Once an entry exceeds
// the failure threshold it's already blocked, so recording more is unnecessary.
const maxTimestampsPerWindow = 10000

// maxTotalEntries caps the total number of tracked IPs/AC IDs across both maps.
// Prevents unbounded map growth from attacks using many spoofed source IPs.
const maxTotalEntries = 100000

// RateLimitConfig configures the license validation rate limiter.
type RateLimitConfig struct {
	// Enabled controls whether rate limiting is active.
	Enabled bool `toml:"Enabled"`

	// MaxFailuresPerIP is the maximum number of failed validation attempts
	// per source IP within the window. Default: 10.
	MaxFailuresPerIP int `toml:"MaxFailuresPerIP"`

	// MaxFailuresPerACID is the maximum number of failed validation attempts
	// per claimed AC ID within the window. Default: 5.
	MaxFailuresPerACID int `toml:"MaxFailuresPerACID"`

	// WindowSeconds is the sliding window duration in seconds. Default: 60.
	WindowSeconds int `toml:"WindowSeconds"`

	// CleanupIntervalSeconds is how often expired entries are purged. Default: 300.
	CleanupIntervalSeconds int `toml:"CleanupIntervalSeconds"`
}

// DefaultRateLimitConfig returns the default rate limit configuration.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Enabled:                true,
		MaxFailuresPerIP:       10,
		MaxFailuresPerACID:     5,
		WindowSeconds:          60,
		CleanupIntervalSeconds: 300,
	}
}

// LicenseRateLimiter tracks failed license validation attempts and blocks
// sources that exceed configured thresholds. Thread-safe for concurrent use.
type LicenseRateLimiter struct {
	config RateLimitConfig

	mu       sync.Mutex
	ipCounts map[string]*failureWindow // source IP -> failure window
	acCounts map[string]*failureWindow // AC ID -> failure window

	stopCh  chan struct{}
	stopped atomic.Bool
}

// failureWindow tracks failure timestamps within a sliding window.
type failureWindow struct {
	timestamps []time.Time
}

// NewLicenseRateLimiter creates a new rate limiter with the given configuration.
func NewLicenseRateLimiter(config RateLimitConfig) *LicenseRateLimiter {
	rl := &LicenseRateLimiter{
		config:   config,
		ipCounts: make(map[string]*failureWindow),
		acCounts: make(map[string]*failureWindow),
		stopCh:   make(chan struct{}),
	}

	if config.Enabled {
		go rl.cleanupLoop()
	}

	return rl
}

// CheckRateLimit returns a non-nil StorageError if the source IP or AC ID
// has exceeded the failure rate limit. This should be called BEFORE performing
// the expensive license validation (bcrypt).
func (rl *LicenseRateLimiter) CheckRateLimit(addrStr, acID string) *StorageError {
	if !rl.config.Enabled {
		return nil
	}

	srcIP := extractIP(addrStr)
	window := time.Duration(rl.config.WindowSeconds) * time.Second
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check per-IP limit
	if srcIP != "" {
		if fw, ok := rl.ipCounts[srcIP]; ok {
			fw.prune(now, window)
			if len(fw.timestamps) >= rl.config.MaxFailuresPerIP {
				return &StorageError{
					Code:    ErrCodeRateLimited,
					Message: fmt.Sprintf("rate limited: too many failed attempts from IP %s (%d in %v)", srcIP, len(fw.timestamps), window),
				}
			}
		}
	}

	// Check per-AC-ID limit
	if acID != "" {
		if fw, ok := rl.acCounts[acID]; ok {
			fw.prune(now, window)
			if len(fw.timestamps) >= rl.config.MaxFailuresPerACID {
				return &StorageError{
					Code:    ErrCodeRateLimited,
					Message: fmt.Sprintf("rate limited: too many failed attempts for AC %s (%d in %v)", acID, len(fw.timestamps), window),
				}
			}
		}
	}

	return nil
}

// RecordFailure records a failed license validation attempt for the given
// source IP and AC ID. Only failures are tracked; successful validations
// do not affect rate limiting.
func (rl *LicenseRateLimiter) RecordFailure(addrStr, acID string) {
	if !rl.config.Enabled {
		return
	}

	srcIP := extractIP(addrStr)
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Cap total tracked entries to prevent memory exhaustion from spoofed sources
	totalEntries := len(rl.ipCounts) + len(rl.acCounts)

	if srcIP != "" {
		fw, ok := rl.ipCounts[srcIP]
		if !ok {
			if totalEntries >= maxTotalEntries {
				return // at capacity, skip tracking new IPs
			}
			fw = &failureWindow{}
			rl.ipCounts[srcIP] = fw
		}
		// Cap stored timestamps to prevent memory growth under sustained attack.
		// Once the limit is exceeded, the IP is already blocked — no need to keep
		// recording additional failures.
		if len(fw.timestamps) < maxTimestampsPerWindow {
			fw.timestamps = append(fw.timestamps, now)
		}
	}

	if acID != "" {
		fw, ok := rl.acCounts[acID]
		if !ok {
			if totalEntries >= maxTotalEntries {
				return
			}
			fw = &failureWindow{}
			rl.acCounts[acID] = fw
		}
		if len(fw.timestamps) < maxTimestampsPerWindow {
			fw.timestamps = append(fw.timestamps, now)
		}
	}
}

// Stop terminates the background cleanup goroutine. Safe to call multiple times.
func (rl *LicenseRateLimiter) Stop() {
	if rl.stopped.CompareAndSwap(false, true) {
		close(rl.stopCh)
	}
}

// cleanupLoop periodically removes expired entries from the rate limiter.
func (rl *LicenseRateLimiter) cleanupLoop() {
	interval := time.Duration(rl.config.CleanupIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.cleanup()
		}
	}
}

// cleanup removes expired failure windows.
func (rl *LicenseRateLimiter) cleanup() {
	window := time.Duration(rl.config.WindowSeconds) * time.Second
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	for key, fw := range rl.ipCounts {
		fw.prune(now, window)
		if len(fw.timestamps) == 0 {
			delete(rl.ipCounts, key)
		}
	}

	for key, fw := range rl.acCounts {
		fw.prune(now, window)
		if len(fw.timestamps) == 0 {
			delete(rl.acCounts, key)
		}
	}
}

// prune removes timestamps outside the sliding window.
func (fw *failureWindow) prune(now time.Time, window time.Duration) {
	cutoff := now.Add(-window)
	// Find the first timestamp within the window (timestamps are in chronological order)
	i := 0
	for i < len(fw.timestamps) && fw.timestamps[i].Before(cutoff) {
		i++
	}
	if i > 0 {
		fw.timestamps = fw.timestamps[i:]
	}
}

// extractIP extracts the IP address from an "ip:port" string.
// Returns the IP portion, or the original string if no port separator is found.
func extractIP(addrStr string) string {
	host, _, err := net.SplitHostPort(addrStr)
	if err != nil {
		// May not have port, return as-is
		return addrStr
	}
	return host
}
