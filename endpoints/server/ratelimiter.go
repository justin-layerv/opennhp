package server

import (
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// IPRateLimiter is a per-source-IP token-bucket rate limiter for the UDP
// receive path. It is the application-layer fallback for environments
// without iptables hashlimit; the iptables hashlimit-burst and the app
// burst should track each other in *config* (see user_data.sh.tpl) but
// note the two layers diverge on *fresh-IP starter capacity*: iptables
// grants the full configured burst on first sight, the app limiter
// grants burst/2 (see #1160 T3-04 and the starter-capacity note below).
// This limiter has no aggregate cap — the burst/2 starter still admits
// 25 packets per fresh IP, so a sufficiently fast IP-rotating attacker
// extracts O(rotation-rate × 25) packets that the app layer can't
// stop. The iptables hashlimit aggregate cap (#1159) is the layer
// that bounds the rotation budget; this file only defends the
// per-IP envelope.
//
// Buckets are lazily created on first packet from an IP and live in an
// expirable.LRU keyed by IP string. The caller must pass
// addr.IP.String() (which normalizes IPv4-mapped-IPv6) as the key;
// note that net.IP.String drops the IPv6 zone identifier, so
// link-local addresses from different interfaces collide — fine on
// the production NLB path (link-local doesn't traverse it) but
// surprising under local debugging. Same caveat as
// preCheckThreatCache. The LRU bounds memory at MaxBuckets and ages
// idle entries out at IdleTTL — same pattern as the precheck threat
// cache (see precheck_threat_cache.go for the lifecycle caveat that
// expirable.LRU does not expose Stop, so its sweep goroutine outlives
// any individual UdpServer instance).
//
// Behavior at MaxBuckets: when full, the LRU evicts its oldest entry
// to admit a new IP. This is a deliberate change from a fail-closed
// "drop new IPs once full" policy: under that policy, an IP-rotation
// attacker who fills the table would lock out every subsequent legitimate
// fresh source. Under LRU eviction, an evicted legitimate client
// re-arriving simply gets a fresh burst/2 starter bucket — degraded
// first-knock latency under pressure, but no lockout.
//
// Fresh-IP starter capacity is half the burst rather than the full
// burst (#1160 T3-04): an attacker rotating source IPs cannot extract
// the full burst on first sight from each fresh IP. Half-burst was
// chosen over a zero-token start because the agent retry loop sleeps
// FailureRetryInterval (10s, nhp/core/constants.go) on each failed
// transaction, so a strict zero-start would add a full 10s wait
// before the first legitimate knock from an unseen IP would succeed
// — unacceptable for interactive flows. The per-knock transaction
// timeout (AgentLocalTransactionResponseTimeoutMs, 5s) bounds how
// long the agent waits for a response before declaring failure.
// With Burst=1
// the starter math goes negative (starterTokens = 0.5, then -0.5
// after consuming the current packet); the first packet still
// returns true, but subsequent packets need to refill from a
// negative balance — slightly stricter than nominal but not a bug,
// and not a configuration that arises in production.
//
// Thread-safety: expirable.LRU is internally synchronized, but a
// limiter-wide mutex still guards each Get-then-update sequence
// against concurrent updaters racing on the same IP — without it,
// two callers can each read tokens=N, each refill, and both write
// the post-decrement value, double-counting.
type IPRateLimiter struct {
	mu      sync.Mutex
	buckets *expirable.LRU[string, *tokenBucket]

	rate  float64
	burst int
}

// tokenBucket is a single IP's lazy-refill token bucket. Tokens are
// recomputed on demand from the elapsed wall-clock interval so there's
// no per-bucket goroutine.
type tokenBucket struct {
	tokens   float64
	lastTime time.Time
}

// RateLimiterConfig holds tunables for the per-IP rate limiter.
type RateLimiterConfig struct {
	// Rate is the sustained packet rate (pps) allowed per source IP.
	Rate float64

	// Burst is the maximum bucket capacity. Legitimate NHP knocks send
	// 3-5 rapid packets, so burst > 3 is required for normal operation.
	Burst int

	// IdleTTL is how long a bucket lives without a packet from the IP
	// before expirable.LRU sweeps it. Bounded above by the LRU's own
	// internal sweep cadence.
	IdleTTL time.Duration

	// MaxBuckets caps tracked source IPs. Beyond this, expirable.LRU
	// evicts the least-recently-used IP — a rotating attacker cannot
	// lock out fresh legitimate sources by filling the table.
	//
	// Sized at 10_000 (#1160 T3-04, was 100_000): smaller than
	// MaxConcurrentConnection (20_480, the blockAddrMap cap) because
	// every fresh source IP visits this LRU but only repeat offenders
	// (≥ PreCheckThreatCountBeforeBlock failures from one IP) reach
	// the block map, so the rate-limiter table churns faster under
	// IP rotation. Memory cost ~120 B/bucket → ~1-2 MiB at full
	// 10k occupancy. Worst case for a large enterprise tenant with
	// mobile/CGN churn (>10k unique IPs in a 120s window) is
	// recoverable: one degraded first knock per re-admit, not a
	// lockout. Revisit once #1505 telemetry lands.
	MaxBuckets int
}

// DefaultRateLimiterConfig returns the production defaults for NHP
// knock rate limiting. 100 pps sustained with burst of 50 is generous
// for legitimate clients in steady state (a knock is 3-5 packets);
// fresh-IP starter capacity is burst/2 = 25 packets per the type
// doc on IPRateLimiter (#1160 T3-04). 100 pps is well below the
// rate at which volumetric DoS becomes interesting.
//
// Rate and Burst should be kept in sync with the per-source-IP
// iptables hashlimit rule in terraform/modules/compute/user_data.sh.tpl
// — change both together. Note the *behavioral* asymmetry on a fresh
// IP: iptables grants the full hashlimit-burst (50) on first sight,
// the app limiter grants burst/2 (25). They converge once an IP has
// been seen, so steady-state behavior matches; the divergence only
// shows up in the "first knock from a never-seen-before IP under
// active rotation flood" scenario, which is precisely when the app
// limiter's stricter starter is doing useful work. The aggregate
// global cap added for #1159 is iptables-only; see the comment
// block in user_data.sh.tpl for follow-up.
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		Rate:       100,
		Burst:      50,
		IdleTTL:    120 * time.Second,
		MaxBuckets: 10_000,
	}
}

// NewIPRateLimiter constructs a rate limiter from cfg. Zero-valued
// fields fall back to DefaultRateLimiterConfig values.
//
// Lifecycle: each limiter starts an internal expirable.LRU sweep
// goroutine that lives for the process — there is no Stop hook.
// Production has one limiter per UdpServer, so this is a non-issue;
// tests that construct many limiters in a loop will leak one
// goroutine per construction. Same caveat as preCheckThreatCache.
// Tracking issue #1515 covers a Close-able shim or upstream PR.
func NewIPRateLimiter(cfg RateLimiterConfig) *IPRateLimiter {
	defaults := DefaultRateLimiterConfig()
	if cfg.Rate <= 0 {
		cfg.Rate = defaults.Rate
	}
	if cfg.Burst <= 0 {
		cfg.Burst = defaults.Burst
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = defaults.IdleTTL
	}
	if cfg.MaxBuckets <= 0 {
		cfg.MaxBuckets = defaults.MaxBuckets
	}

	return &IPRateLimiter{
		buckets: expirable.NewLRU[string, *tokenBucket](cfg.MaxBuckets, nil, cfg.IdleTTL),
		rate:    cfg.Rate,
		burst:   cfg.Burst,
	}
}

// Allow returns true iff a packet from ip is within the configured
// rate. Caller is the UDP recv loop, which has already converted
// remoteAddr.IP to a stable string once per packet — passing it as a
// string here keeps the conversion off this function (it would
// otherwise run twice in close succession alongside isBlockedIP).
func (rl *IPRateLimiter) Allow(ip string) bool {
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if b, ok := rl.buckets.Get(ip); ok {
		elapsed := now.Sub(b.lastTime).Seconds()
		b.tokens += elapsed * rl.rate
		if b.tokens > float64(rl.burst) {
			b.tokens = float64(rl.burst)
		}
		b.lastTime = now

		if b.tokens >= 1 {
			b.tokens--
			return true
		}
		return false
	}

	// Fresh IP: see type doc for why starter is burst/2 rather than
	// 0 or burst. Bucket admits this packet immediately (tokens -1).
	rl.buckets.Add(ip, &tokenBucket{
		tokens:   float64(rl.burst)/2 - 1,
		lastTime: now,
	})
	return true
}

// Len returns the number of currently tracked IPs. For metrics/tests.
// expirable.LRU.Len() is internally synchronized; rl.mu only serializes
// Get-then-update sequences in Allow, not single reads.
func (rl *IPRateLimiter) Len() int {
	return rl.buckets.Len()
}
