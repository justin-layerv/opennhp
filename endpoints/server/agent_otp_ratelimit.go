package server

import (
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// OTPRateLimiter is a pre-plugin token-bucket limiter for every native-UDP
// NHP_OTP request and for generic requests on non-direct ingress that are not
// claimed as Connector registration. Configured Connector registration on
// non-direct ingress is rejected before this limiter and counted by
// MetricConnectorRegistrationIngressRejected. The limiter is keyed by the
// inner device pubkey b64 (base64.StdEncoding.EncodeToString(ppd.RemotePubKey))
// — the cryptographically authenticated agent identity, not a spoofable message
// field — so one agent cannot flood the downstream OTP issuer.
//
// It mirrors IPRateLimiter (ratelimiter.go): a limiter-wide mutex guards each
// Get-then-refill-then-decrement sequence, and per-key buckets live in an
// expirable.LRU that bounds memory (Capacity=MaxKeys) and ages idle keys out
// (IdleTTL). Two structural differences from IPRateLimiter, both deliberate:
//
//  1. FRESH-KEY START IS FULL CAPACITY, not capacity/2. IPRateLimiter's half-burst
//     starter defends against IP-rotation floods where every fresh source is
//     attacker-controlled. Here the key is a Noise-authenticated pubkey: minting
//     a fresh key still costs a full X25519 handshake per key, and the GLOBAL
//     bucket below (not per-key starter math) is what bounds a key-rotating
//     attacker's aggregate email cost. A full starter keeps a legitimate agent's
//     first few registration attempts (OTP request → email → REG) from being
//     throttled on a cold bucket.
//
//  2. A PROCESS-GLOBAL bucket sits in FRONT of the per-key bucket. Per-key limits
//     alone are defeated by key rotation (each fresh pubkey gets its own bucket);
//     the global bucket caps aggregate OTP/email cost across ALL keys regardless
//     of key cardinality. It is checked FIRST and, on the allow path, consumes
//     from BOTH buckets — so a reject by either denies the request.
//
// DEFENSE-IN-DEPTH ONLY: the authoritative registration/OTP limits live
// qurl-service-side (Q2). This limiter's job is to shed an obvious per-key or
// aggregate flood at the NHP server before it reaches the plugin, not to be the
// system of record. On reject the caller drops SILENTLY (OTP is fire-and-forget;
// spec-aligned default-deny) and increments MetricOTPRejectRateLimited.
//
// OTP-ONLY, BY DESIGN: the sibling REG path (NHP_REG → dispatch) deliberately has
// NO equivalent per-key limiter. This one guards OTP specifically because each
// admitted OTP costs an outbound EMAIL downstream — the expensive, abusable side
// effect worth shedding pre-plugin. A REG request instead drives a plugin
// credential-validation call (no email, no per-request external send cost), so it
// does not need this pre-plugin per-key throttle; its abuse surface is covered by
// the shared per-source-IP UDP limiter + the authoritative qurl-service limits.
//
// Lifecycle caveat (same as IPRateLimiter / preCheckThreatCache): expirable.LRU
// starts a sweep goroutine that lives for the process and exposes no Stop, so a
// test constructing many limiters leaks one goroutine per construction.
// Production has one per UdpServer, so this is a non-issue. Tracked with the same
// #1515 shim as the IP limiter.
type OTPRateLimiter struct {
	mu      sync.Mutex
	buckets *expirable.LRU[string, *tokenBucket]

	// capacity is the per-key bucket ceiling; refillRate is tokens/sec derived
	// from RefillInterval (1 token per interval).
	capacity   float64
	refillRate float64

	// global is the single process-wide bucket bounding aggregate OTP cost
	// across all keys. Guarded by mu (same critical section as the per-key
	// update) so the two-bucket check-and-consume is atomic.
	global         tokenBucket
	globalCapacity float64
	globalRate     float64
}

// OTPRateLimiterConfig holds the OTP limiter tunables.
type OTPRateLimiterConfig struct {
	// Capacity is the per-key bucket size (max OTP requests in a burst from one
	// device key). Legitimate registration needs only 1-2 OTP requests, so a
	// small capacity is generous while still shedding a per-key flood.
	Capacity int

	// RefillInterval is the wall-clock time to regain ONE per-key token. The
	// sustained per-key rate is 1 / RefillInterval.
	RefillInterval time.Duration

	// GlobalCapacity is the process-wide bucket size; GlobalRate is the
	// sustained aggregate refill in tokens/sec (bounds total email cost
	// regardless of how many distinct keys are seen).
	GlobalCapacity int
	GlobalRate     float64

	// IdleTTL ages a per-key bucket out after this long without a request.
	IdleTTL time.Duration

	// MaxKeys caps tracked device keys; expirable.LRU evicts the LRU key beyond
	// this so a key-rotating attacker cannot grow the table unbounded. An evicted
	// legitimate key simply re-arrives with a fresh full bucket (the global
	// bucket still bounds aggregate cost).
	MaxKeys int
}

// DefaultOTPRateLimiterConfig returns the production defaults: per-key capacity
// 3, one token back every 5 minutes; a process-global ~30/min bucket; LRU of
// 4096 keys aged out after 30 minutes idle.
//
// Rationale: an agent registers rarely (once per device, plus retries), so 3
// OTP requests with a 5-minute refill is ample for a real client yet caps a
// single compromised key at ~12 emails/hr. The global ~30/min bucket bounds the
// aggregate email bill even under wide key rotation. These are intentionally NOT
// operator knobs (cf. relay's maxInFlightPerServer): the safe value is "well
// above one honest agent's need, well below a flood", which this is, and the
// authoritative limits live in qurl-service (Q2) anyway.
//
// SIZING NOTE: the ~30/min GLOBAL bucket caps aggregate OTP across every key, so
// a legitimate correlated burst — an enterprise rolling the agent to hundreds
// of devices on day one — would exhaust it and get silently dropped
// (default-deny). For generic relayed OTP
// that reaches this limiter, the client already saw HTTP 202; configured
// Connector registration over relay never reaches this point. Before enabling
// a flow that uses the limiter, size GlobalCapacity/GlobalRate for expected
// bulk-enrollment peaks and alarm on MetricOTPRejectRateLimited so operators see
// the shed rather than users seeing "accepted, no email". Tracked in T1.
//
// UPSTREAM (RELAY-SIDE) BOUND — DEFENSE-IN-DEPTH GAP: on the generic relayed
// path, an OTP forward is fire-and-forget — the relay releases its per-server
// in-flight slot as soon as it forwards, so that slot budget does not throttle
// request rate like it does for a reply-bearing knock. Traffic that reaches this
// path is bounded by the relay's per-source-IP UDP limiter and this server-side
// global bucket. Configured Connector lifecycle traffic instead stops at the
// ingress-rejection gate. If generic relay abuse shows this bound is too coarse,
// a dedicated relay-side OTP throttle may be warranted.
func DefaultOTPRateLimiterConfig() OTPRateLimiterConfig {
	return OTPRateLimiterConfig{
		Capacity:       3,
		RefillInterval: 5 * time.Minute,
		GlobalCapacity: 30,
		GlobalRate:     30.0 / 60.0, // ~30 per minute sustained
		IdleTTL:        30 * time.Minute,
		MaxKeys:        4096,
	}
}

// NewOTPRateLimiter builds an OTP limiter from cfg. Zero-valued fields fall back
// to DefaultOTPRateLimiterConfig. The global bucket starts full so a cold server
// does not throttle the first legitimate registrations.
func NewOTPRateLimiter(cfg OTPRateLimiterConfig) *OTPRateLimiter {
	defaults := DefaultOTPRateLimiterConfig()
	if cfg.Capacity <= 0 {
		cfg.Capacity = defaults.Capacity
	}
	if cfg.RefillInterval <= 0 {
		cfg.RefillInterval = defaults.RefillInterval
	}
	if cfg.GlobalCapacity <= 0 {
		cfg.GlobalCapacity = defaults.GlobalCapacity
	}
	if cfg.GlobalRate <= 0 {
		cfg.GlobalRate = defaults.GlobalRate
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = defaults.IdleTTL
	}
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = defaults.MaxKeys
	}

	return &OTPRateLimiter{
		buckets:        expirable.NewLRU[string, *tokenBucket](cfg.MaxKeys, nil, cfg.IdleTTL),
		capacity:       float64(cfg.Capacity),
		refillRate:     1.0 / cfg.RefillInterval.Seconds(),
		global:         tokenBucket{tokens: float64(cfg.GlobalCapacity), lastTime: time.Now()},
		globalCapacity: float64(cfg.GlobalCapacity),
		globalRate:     cfg.GlobalRate,
	}
}

// Allow reports whether an OTP request keyed by pubKeyB64 is within both the
// per-key and process-global rate. It consumes a token from each bucket only
// when BOTH have one — so a reject by either leaves both untouched (no partial
// consumption that would let a rejected request still drain the global budget).
//
// Both buckets refill lazily from elapsed wall-clock time (no per-bucket
// goroutine). The whole check-and-consume runs under mu so concurrent callers
// cannot double-spend either bucket.
func (rl *OTPRateLimiter) Allow(pubKeyB64 string) bool {
	if rl == nil {
		return true
	}
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Refill the global bucket first; if it's dry, reject WITHOUT touching the
	// per-key bucket so the aggregate cap is authoritative and a rejected request
	// costs nothing.
	globalElapsed := now.Sub(rl.global.lastTime).Seconds()
	rl.global.tokens += globalElapsed * rl.globalRate
	if rl.global.tokens > rl.globalCapacity {
		rl.global.tokens = rl.globalCapacity
	}
	rl.global.lastTime = now
	if rl.global.tokens < 1 {
		return false
	}

	// Per-key bucket. A fresh key starts full (see the type doc for why full,
	// not half). Compute whether the per-key bucket admits this request; only if
	// it does do we consume from BOTH.
	b, ok := rl.buckets.Get(pubKeyB64)
	if !ok {
		// Fresh key: full capacity, immediately consume this request from both
		// the per-key starter and the global bucket.
		rl.buckets.Add(pubKeyB64, &tokenBucket{
			tokens:   rl.capacity - 1,
			lastTime: now,
		})
		rl.global.tokens--
		return true
	}

	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * rl.refillRate
	if b.tokens > rl.capacity {
		b.tokens = rl.capacity
	}
	b.lastTime = now
	if b.tokens < 1 {
		// Per-key bucket empty: reject. The global bucket was refilled above but
		// NOT consumed (we only decrement it on the allow path), so a throttled
		// key does not drain the aggregate budget.
		return false
	}
	b.tokens--
	rl.global.tokens--
	return true
}

// Len returns the number of currently tracked device keys. For metrics/tests.
func (rl *OTPRateLimiter) Len() int {
	return rl.buckets.Len()
}
