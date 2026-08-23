package server

import (
	"math"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// Precheck-threat cache sizing (#1158).
//
// The counter the cache replaces was previously an unbounded
// `map[string]int32` keyed by attacker-controlled `IP:port` and
// grew with every malformed packet that failed RecvPrecheck. An
// IP-spoofing flood could grow the map by GB/sec — the #1158
// memory-DoS primitive.
//
// Cap (10_000 distinct source IPs): well below
// MaxConcurrentConnection (20_480, see constants.go) — threat
// tracking must not be able to outgrow the connection pool.
// Under normal traffic we expect <1000 distinct recent sources,
// so the cap is exercised only under attack. Accepted trade-off:
// a spoofed-IP flood filling the cache can LRU-evict a real
// attacker's entry before their counter reaches the threshold,
// forcing them to re-accumulate; this is strictly better than
// pre-PR behavior (which allocated without bound) and is offset
// by blockAddrMap persisting any already-tripped block
// independently for BlockAddrExpireTime. PreCheckThreatEviction
// is the ops signal that the cache is under sustained pressure.
//
// TTL (5 min): longer than the 90-second block duration
// (BlockAddrExpireTime) so legitimate retransmits from a source
// that hit the threshold stay blocked for their full block window
// even if they then go quiet. Short enough that a genuinely
// transient source (single malformed packet, then goes quiet
// for >5 min) releases its slot. Note: any source that sends
// another malformed packet within the TTL window refreshes the
// entry, so "transient" here means transient on the 5-min scale,
// not on the 90-second block scale. Side effect: when a blocked source stays silent
// through a full block window, their cache entry persists at
// count > threshold; their next malformed packet re-blocks them
// immediately, so effective block duration for a persistent
// attacker stretches up to roughly cache_TTL/block_window (~3.3×).
// This is strictly better than the designed block duration.
// Note: Increment is NOT called while a source is blocked —
// isBlockedIP short-circuits in recvPacketRoutine before
// RecvPrecheck runs — so TTL does not refresh during the block
// window. Only pre-block failures and post-unblock packets keep
// the entry warm.
const (
	PreCheckThreatCacheSize = 10_000
	PreCheckThreatCacheTTL  = 5 * time.Minute
)

// MetricPreCheckThreatEviction fires each time the precheck-threat
// cache drops an entry — either because the LRU is at capacity or
// because the entry's TTL expired. A non-zero rate in steady state
// means the cache is under pressure (scanning flood, IP spoofing
// storm, or size-cap too tight). The expirable LRU library does
// not distinguish capacity- from TTL-driven evictions at the
// callback boundary, so one counter covers both (#1272 tracks
// separating them).
//
// Callback-under-lock — expirable.LRU fires onEvict synchronously
// while holding its internal mutex. metrics.Publisher.IncrCounter
// takes its own (package-level, shared-across-the-server) mutex;
// the two nest LRU.mu → Publisher.mu and are currently uncontended,
// so the coupling is benign. Concretely, though: Publisher.mu
// serializes every metric increment in the process, so if metrics
// emission ever becomes contended (heavy fan-in from other hot
// paths), eviction callbacks will back up behind unrelated
// IncrCounter calls while holding the LRU's mutex — which in
// turn serializes cache operations. Keep any future onEvict body
// fast (no I/O, no blocking calls) and prefer lock-free counters
// over Publisher for hot eviction paths if that ever matters.
const MetricPreCheckThreatEviction = "PreCheckThreatEviction"

// preCheckThreatCache is a bounded, IP-keyed counter of precheck
// failures. The caller increments on every RecvPrecheck error and
// clears on every RecvPrecheck success; once a single IP's counter
// exceeds PreCheckThreatCountBeforeBlock the caller moves that
// source into the block map.
//
// Key choice — IP, not IP:port. A port-rotating attacker on a
// single source IP used to manufacture 65_535 distinct map entries
// per IP under the old keying; IP-only collapses that back to
// one slot per source. The trade-off: a successful precheck on any
// port from an IP now clears the IP's counter entirely. This is
// the intended semantics — if any port from a source looks
// legitimate, the source isn't a scanner.
//
// IPv6 zone ID is not part of the key — net.IP.String() renders
// only the address, not the UDPAddr.Zone. Link-local IPv6 should
// not reach a public-internet NHP server, so this is not a
// practical concern; noted here so any future dual-stack
// link-local deployment knows the zone isn't covered.
//
// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) collapse to the
// dotted-decimal form automatically — net.IP.String()'s stdlib
// implementation calls To4() internally and renders the mapped
// form as IPv4. So a dual-stack deployment where one real source
// arrives alternately as `1.2.3.4` and `::ffff:1.2.3.4` yields
// one slot per source, not two. No explicit normalization needed.
//
// Concurrency — the underlying expirable.LRU is internally
// thread-safe and spawns a background goroutine for TTL sweeping.
// recvPacketRoutine is a single goroutine today, so foreground
// concurrency is not exercised; the TTL-sweep goroutine still
// mutates state concurrently, so any test-side observer of
// eviction side effects needs its own synchronization (see the
// TTL test's atomic counter).
//
// Lifecycle — expirable.LRU v2.0.7 exposes no Close()/Stop() for
// its sweep goroutine. In production the cache lives for the
// server process's lifetime, so this is a non-issue. Any future
// multi-start flow (integration tests that spin up/tear down
// UdpServer in one process, or a graceful-reload path) would
// leak one goroutine per restart until the library adds a
// teardown hook.
type preCheckThreatCache struct {
	lru *expirable.LRU[string, int32]
}

// newPreCheckThreatCache builds a cache with caller-supplied size
// and TTL. Production uses PreCheckThreatCacheSize and
// PreCheckThreatCacheTTL (wired at the one call site in
// recvPacketRoutine); tests pass short values so TTL-eviction
// paths are exercised without 5-minute waits. onEvict (optional)
// fires for both capacity- and TTL-driven evictions — see
// MetricPreCheckThreatEviction.
func newPreCheckThreatCache(size int, ttl time.Duration, onEvict func()) *preCheckThreatCache {
	var cb expirable.EvictCallback[string, int32]
	if onEvict != nil {
		cb = func(_ string, _ int32) { onEvict() }
	}
	return &preCheckThreatCache{
		lru: expirable.NewLRU[string, int32](size, cb, ttl),
	}
}

// Increment is NOT SAFE for concurrent calls on the same key.
//
// Bumps the failure counter for ip and returns the new value.
// Missing or expired entries start from zero. Saturates at
// math.MaxInt32 so an attacker sending for years can't overflow
// the counter negative (at ~2.1B increments) and bypass the
// threshold comparison. Each call Adds the updated value, which
// also refreshes the entry's TTL — intentional: a source that
// keeps failing should keep its slot warm, not silently age out
// mid-attack.
//
// Concurrency — the read (Get) and write (Add) cross two lock
// acquisitions, so two callers racing on one IP can both see
// count=N and both write count=N+1, losing one bump. This is
// fine today because recvPacketRoutine is a single goroutine;
// if that ever changes (per-NIC listeners, worker pool) either
// switch to an atomic upsert API on the underlying LRU or guard
// with an external mutex. The constraint lives here and not just
// in the caller so a future multi-reader refactor doesn't
// silently break.
func (c *preCheckThreatCache) Increment(ip string) int32 {
	count, _ := c.lru.Get(ip)
	if count < math.MaxInt32 {
		count++
	}
	c.lru.Add(ip, count)
	return count
}

// Clear drops the failure counter for ip. Called on RecvPrecheck
// success; see preCheckThreatCache's docstring for why any success
// clears the whole IP. expirable.LRU.Remove is already a no-op for
// missing keys, so the common case (cache empty under legitimate
// traffic) still costs exactly one mutex acquisition — no fast-path
// guard needed.
func (c *preCheckThreatCache) Clear(ip string) {
	c.lru.Remove(ip)
}

// Count returns the current counter for ip. It is used by the real UDP receive
// integration test to fence KPL's deliberate exclusion from the clear path.
func (c *preCheckThreatCache) Count(ip string) (int32, bool) {
	return c.lru.Get(ip)
}

// Len is the current entry count. Useful for tests asserting
// cap behavior and for any future size-gauge metric.
func (c *preCheckThreatCache) Len() int {
	return c.lru.Len()
}

// recordPreCheckThreat increments the per-IP counter in cache for
// ip and, when the counter exceeds PreCheckThreatCountBeforeBlock,
// moves the IP into the block map. Separated from recvPacketRoutine
// so the threshold semantics are testable without driving the full
// UDP socket — cache is passed explicitly (not stored on UdpServer)
// so tests can construct an isolated cache without wiring up a full
// server. ip is assumed non-empty; the UDP stack delivers valid
// addresses via ReadFromUDP, so there is no validation here.
//
// Block map is keyed by remote IP only (#1160 T3-12), so a single
// port-rotating source produces one block entry rather than one
// per port — port rotation can no longer bypass an existing block.
func (s *UdpServer) recordPreCheckThreat(cache *preCheckThreatCache, ip string) {
	if cache.Increment(ip) > PreCheckThreatCountBeforeBlock {
		s.addBlockedIP(ip)
	}
}
