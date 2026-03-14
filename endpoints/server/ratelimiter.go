package server

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// IPRateLimiter provides per-source-IP rate limiting for UDP packets using
// a token bucket algorithm. It is designed for the hot path of packet
// reception, so it minimizes allocations and lock contention.
//
// This is the second layer of defense against UDP flood attacks. The first
// layer is iptables hashlimit rules (configured in Terraform user_data
// templates) which drop packets in the kernel before they reach userspace.
// This application-level limiter serves as a fallback for environments where
// iptables isn't configured and as defense-in-depth against iptables bugs.
// Both layers use the same rate/burst defaults for consistency.
//
// Each source IP gets an independent token bucket. Buckets are lazily created
// on first packet and periodically cleaned up when idle.
//
// Thread-safety: all methods are safe for concurrent use.
type IPRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket

	// Configuration (immutable after construction)
	rate       float64 // tokens per second
	burst      int     // max tokens (bucket capacity)
	maxBuckets int     // max tracked IPs; beyond this, new IPs are dropped
	idleTTL    time.Duration
	stopCh     chan struct{}
	stopped    atomic.Bool
}

// tokenBucket implements a token bucket rate limiter for a single IP.
// It uses a lazy refill strategy: tokens are computed on-demand based on
// elapsed time since the last check, avoiding per-tick goroutines.
type tokenBucket struct {
	tokens   float64
	lastTime time.Time
	lastSeen time.Time // for idle cleanup
}

// RateLimiterConfig holds configuration for the per-IP rate limiter.
type RateLimiterConfig struct {
	// Rate is the sustained packet rate (packets per second) allowed per source IP.
	// Default: 100 pps.
	Rate float64

	// Burst is the maximum number of packets allowed in a single burst above
	// the sustained rate. This accommodates legitimate traffic spikes (e.g.,
	// NHP handshake involves multiple rapid packets).
	// Default: 50 packets.
	Burst int

	// CleanupInterval is how often idle buckets are swept.
	// Default: 30 seconds.
	CleanupInterval time.Duration

	// IdleTTL is how long a bucket is kept after the last packet from that IP.
	// Default: 120 seconds.
	IdleTTL time.Duration

	// MaxBuckets is the maximum number of tracked source IPs. When exceeded,
	// packets from new (unseen) IPs are dropped. This caps memory usage during
	// volumetric attacks with many spoofed source IPs.
	// Default: 100,000 (~5MB at ~48 bytes per bucket).
	MaxBuckets int
}

// DefaultRateLimiterConfig returns sensible defaults for NHP knock rate limiting.
// 100 pps sustained with burst of 50 is generous for legitimate knock traffic
// (a normal client sends ~3-5 packets per knock) while blocking volumetric DoS.
//
// IMPORTANT: These defaults must match the iptables hashlimit rules in
// terraform/modules/compute/user_data.sh.tpl. Change both together.
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		Rate:            100,
		Burst:           50,
		CleanupInterval: 30 * time.Second,
		IdleTTL:         120 * time.Second,
		MaxBuckets:      100_000,
	}
}

// NewIPRateLimiter creates a new per-IP rate limiter and starts its cleanup goroutine.
// Call Stop() to release resources.
func NewIPRateLimiter(cfg RateLimiterConfig) *IPRateLimiter {
	if cfg.Rate <= 0 {
		cfg.Rate = 100
	}
	if cfg.Burst <= 0 {
		cfg.Burst = 50
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 30 * time.Second
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = 120 * time.Second
	}
	if cfg.MaxBuckets <= 0 {
		cfg.MaxBuckets = 100_000
	}

	rl := &IPRateLimiter{
		buckets:    make(map[string]*tokenBucket),
		rate:       cfg.Rate,
		burst:      cfg.Burst,
		maxBuckets: cfg.MaxBuckets,
		idleTTL:    cfg.IdleTTL,
		stopCh:     make(chan struct{}),
	}

	go rl.cleanupLoop(cfg.CleanupInterval)
	return rl
}

// Allow checks whether a packet from the given address should be accepted.
// Returns true if the packet is within rate limits, false if it should be dropped.
//
// The addr parameter should be the remote UDP address. Only the IP portion is
// used for rate limiting (port is ignored) since NAT may assign different
// source ports to packets from the same host.
func (rl *IPRateLimiter) Allow(addr *net.UDPAddr) bool {
	ip := addr.IP.String()
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, exists := rl.buckets[ip]
	if !exists {
		// Cap tracked IPs to prevent memory exhaustion from spoofed source attacks
		if len(rl.buckets) >= rl.maxBuckets {
			return false
		}
		// First packet from this IP: create bucket with full tokens minus 1
		b = &tokenBucket{
			tokens:   float64(rl.burst) - 1, // consume one token for this packet
			lastTime: now,
			lastSeen: now,
		}
		rl.buckets[ip] = b
		return true
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastTime = now
	b.lastSeen = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}

	return false
}

// Stop shuts down the cleanup goroutine. Safe to call multiple times.
func (rl *IPRateLimiter) Stop() {
	if rl.stopped.CompareAndSwap(false, true) {
		close(rl.stopCh)
	}
}

// Len returns the number of tracked IPs. Useful for monitoring/metrics.
func (rl *IPRateLimiter) Len() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.buckets)
}

// cleanupLoop periodically removes idle token buckets to prevent memory leaks
// from IPs that sent traffic once but never again.
func (rl *IPRateLimiter) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCh:
			return
		case now := <-ticker.C:
			rl.mu.Lock()
			for ip, b := range rl.buckets {
				if now.Sub(b.lastSeen) > rl.idleTTL {
					delete(rl.buckets, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}
