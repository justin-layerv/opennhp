package server

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func makeUDPAddr(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

func ipKey(addr *net.UDPAddr) string {
	return addr.IP.String()
}

// TestIPRateLimiter_StarterCapacity is the regression fence for #1160 T3-04.
// A new IP must be granted at most burst/2 starter tokens, not the full burst —
// that's the cap on the per-IP amplification an attacker rotating source IPs
// can extract from the limiter on first sight.
func TestIPRateLimiter_StarterCapacity(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    1, // very slow refill, so test isolates starter capacity
		Burst:   10,
		IdleTTL: time.Minute,
	})

	ip := ipKey(makeUDPAddr("203.0.113.1", 1234))

	// burst=10 ⇒ starter=5: exactly five packets accepted before pacing kicks in.
	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.Allow(ip) {
			allowed++
		}
	}
	if allowed != 5 {
		t.Errorf("fresh IP starter capacity: got %d allowed, want 5 (burst/2)", allowed)
	}
}

func TestIPRateLimiter_AllowBurst(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    10,
		Burst:   4, // starter=2
		IdleTTL: time.Minute,
	})

	ip := ipKey(makeUDPAddr("192.168.1.1", 12345))

	for i := 0; i < 2; i++ {
		if !rl.Allow(ip) {
			t.Errorf("packet %d should be allowed within starter capacity", i+1)
		}
	}

	if rl.Allow(ip) {
		t.Error("packet 3 should be rate limited (starter exhausted)")
	}
}

func TestIPRateLimiter_Refill(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    10, // 1 token per 100ms
		Burst:   4,
		IdleTTL: time.Minute,
	})

	ip := ipKey(makeUDPAddr("10.0.0.1", 9999))

	for i := 0; i < 2; i++ {
		rl.Allow(ip)
	}
	if rl.Allow(ip) {
		t.Fatal("should be rate limited after starter exhausted")
	}

	time.Sleep(150 * time.Millisecond)

	if !rl.Allow(ip) {
		t.Error("should be allowed after token refill")
	}
}

func TestIPRateLimiter_IndependentIPs(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    10,
		Burst:   4,
		IdleTTL: time.Minute,
	})

	ip1 := ipKey(makeUDPAddr("10.0.0.1", 1111))
	ip2 := ipKey(makeUDPAddr("10.0.0.2", 2222))

	for i := 0; i < 2; i++ {
		rl.Allow(ip1)
	}
	if rl.Allow(ip1) {
		t.Error("ip1 should be rate limited")
	}

	for i := 0; i < 2; i++ {
		if !rl.Allow(ip2) {
			t.Errorf("ip2 packet %d should be allowed", i+1)
		}
	}
}

func TestIPRateLimiter_SameIPDifferentPorts(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    10,
		Burst:   4,
		IdleTTL: time.Minute,
	})

	// Same IP, different ports key to the same string and share a bucket.
	addr1 := makeUDPAddr("10.0.0.1", 1111)
	addr2 := makeUDPAddr("10.0.0.1", 2222)

	for i := 0; i < 2; i++ {
		rl.Allow(ipKey(addr1))
	}

	if rl.Allow(ipKey(addr2)) {
		t.Error("same IP with different port should share rate limit bucket")
	}
}

func TestIPRateLimiter_Cleanup(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    100,
		Burst:   10,
		IdleTTL: 100 * time.Millisecond,
	})

	ip := ipKey(makeUDPAddr("192.168.1.1", 12345))
	rl.Allow(ip)

	if rl.Len() != 1 {
		t.Errorf("expected 1 tracked IP, got %d", rl.Len())
	}

	// Poll for eviction rather than time.Sleep'ing a fixed margin:
	// expirable.LRU sweeps internally every TTL/numBuckets (numBuckets=100
	// today, see hashicorp/golang-lru/v2 expirable_lru.go::deleteExpired),
	// so the entry should be gone within roughly TTL+TTL/numBuckets.
	// Polling lets a future upstream sweeper change (faster or slower)
	// keep this test correct without the test silently passing on
	// fortunate scheduling, and bounds the wait at the actual eviction
	// time rather than a worst-case multiplier.
	deadline := time.Now().Add(2 * time.Second)
	for rl.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if rl.Len() != 0 {
		// Flake here probably means upstream changed the sweeper cadence
		// (TTL/numBuckets ratio in expirable.LRU). Verify the upstream
		// constants before assuming the rate limiter itself is broken.
		t.Errorf("expected 0 tracked IPs after cleanup, got %d (waited up to 2s)", rl.Len())
	}
}

func TestIPRateLimiter_BurstCap(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    1000,
		Burst:   5, // starter=2.5
		IdleTTL: time.Minute,
	})

	ip := ipKey(makeUDPAddr("10.0.0.1", 1111))

	// Drain whatever's left after starter. Pre-Allow token-balance
	// trace for burst=5: bucket is constructed with starter-1 = 1.5
	// (call #1 already consumed its packet). Call #2: pre=1.5,
	// post=0.5, returns true. Call #3: pre=0.5, fails (no decrement).
	for i := 0; i < 3; i++ {
		rl.Allow(ip)
	}

	// Wait long enough that tokens would exceed burst if not capped.
	time.Sleep(100 * time.Millisecond)

	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.Allow(ip) {
			allowed++
		}
	}
	if allowed > 5 {
		t.Errorf("tokens should be capped at burst (%d), but %d were allowed", 5, allowed)
	}
}

func TestIPRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    1000,
		Burst:   100,
		IdleTTL: time.Minute,
	})

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ip := ipKey(makeUDPAddr(fmt.Sprintf("10.0.0.%d", idx+1), 12345))
			for j := 0; j < 200; j++ {
				rl.Allow(ip)
			}
		}(i)
	}
	wg.Wait()

	if rl.Len() != 10 {
		t.Errorf("expected 10 tracked IPs, got %d", rl.Len())
	}
}

func TestIPRateLimiter_DefaultConfig(t *testing.T) {
	cfg := DefaultRateLimiterConfig()
	if cfg.Rate != 100 {
		t.Errorf("expected default rate 100, got %f", cfg.Rate)
	}
	if cfg.Burst != 50 {
		t.Errorf("expected default burst 50, got %d", cfg.Burst)
	}
	if cfg.IdleTTL != 120*time.Second {
		t.Errorf("expected default idle TTL 120s, got %v", cfg.IdleTTL)
	}
	if cfg.MaxBuckets != 10_000 {
		t.Errorf("expected default MaxBuckets 10000, got %d", cfg.MaxBuckets)
	}
}

func TestIPRateLimiter_ZeroConfigUsesDefaults(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{})

	ip := ipKey(makeUDPAddr("10.0.0.1", 1111))
	// With default burst=50, starter=25: first 25 packets allowed.
	allowed := 0
	for i := 0; i < 50; i++ {
		if rl.Allow(ip) {
			allowed++
		}
	}
	if allowed != 25 {
		t.Errorf("default starter capacity (burst/2): got %d allowed, want 25", allowed)
	}
}

func BenchmarkIPRateLimiter_Allow_SingleIP(b *testing.B) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    10000,
		Burst:   10000,
		IdleTTL: time.Minute,
	})

	ip := ipKey(makeUDPAddr("10.0.0.1", 12345))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow(ip)
	}
}

func BenchmarkIPRateLimiter_Allow_MultipleIPs(b *testing.B) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    10000,
		Burst:   10000,
		IdleTTL: time.Minute,
		// MaxBuckets is intentionally larger than the production
		// default (10_000) here so the benchmark measures the
		// steady-state Get-then-update path, not the LRU eviction
		// path. The 100-IP working set fits comfortably under any
		// reasonable cap; this value just guarantees we never hit
		// the eviction branch during measurement.
		MaxBuckets: 1_000_000,
	})

	ips := make([]string, 100)
	for i := range ips {
		ips[i] = ipKey(makeUDPAddr(fmt.Sprintf("10.0.%d.%d", i/256, i%256), 12345))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow(ips[i%len(ips)])
	}
}

func BenchmarkIPRateLimiter_Allow_Parallel(b *testing.B) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    10000,
		Burst:   10000,
		IdleTTL: time.Minute,
	})

	b.RunParallel(func(pb *testing.PB) {
		ip := ipKey(makeUDPAddr("10.0.0.1", 12345))
		for pb.Next() {
			rl.Allow(ip)
		}
	})
}

// TestIPRateLimiter_MaxBucketsLRU is the regression fence for the
// MaxBuckets cap drop (#1160 T3-04, 100k → 10k). It also pins the
// *behavior change* introduced alongside the cap drop: at full
// capacity the limiter now evicts the LRU and admits the new IP,
// where the previous implementation dropped the new IP. This is a
// deliberate trade — drop-on-full lets a rotation attacker lock out
// every subsequent fresh legitimate source by filling the table;
// LRU-evict-on-full keeps the door open for legitimate fresh sources
// at the cost of churning oldest-idle entries (whose owners can just
// re-arrive with a fresh burst/2 starter).
func TestIPRateLimiter_MaxBucketsLRU(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:       100,
		Burst:      10,
		IdleTTL:    time.Hour,
		MaxBuckets: 5,
	})

	for i := 0; i < 5; i++ {
		ip := ipKey(makeUDPAddr(fmt.Sprintf("10.0.0.%d", i+1), 1000))
		if !rl.Allow(ip) {
			t.Errorf("IP %d should be allowed (under max buckets)", i+1)
		}
	}

	// Touch IP1 so IP2 becomes the LRU (IP1 just moved to MRU).
	// Relies on hashicorp/golang-lru contract: Get moves the entry to MRU.
	rl.Allow(ipKey(makeUDPAddr("10.0.0.1", 1000)))

	// New IP at capacity: LRU eviction triggers, IP2 is evicted.
	overflow := ipKey(makeUDPAddr("10.0.0.100", 1000))
	if !rl.Allow(overflow) {
		t.Error("new IP should be admitted via LRU eviction at capacity")
	}
	if rl.Len() != 5 {
		t.Errorf("expected 5 buckets after eviction, got %d", rl.Len())
	}

	// IP2 was evicted; sending from it again creates a fresh bucket.
	// Capacity is full, so another new bucket is created — IP3 (now LRU) evicted.
	if !rl.Allow(ipKey(makeUDPAddr("10.0.0.2", 1000))) {
		t.Error("re-introduced IP should re-admit via LRU eviction")
	}
}

// TestIPRateLimiter_EvictedIPGetsFreshStarter pins that an IP
// returning after LRU eviction is admitted as a *fresh* IP — i.e.
// it gets the burst/2 starter, not zero tokens or a stale balance.
// CR-requested fence for the LRU-eviction semantic on PR #1506.
func TestIPRateLimiter_EvictedIPGetsFreshStarter(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:       1, // very slow refill, so starter tokens dominate
		Burst:      10,
		IdleTTL:    time.Hour,
		MaxBuckets: 2,
	})

	victim := ipKey(makeUDPAddr("10.0.0.1", 1000))

	// Drain victim's starter (burst/2 = 5 tokens; first packet is
	// already consumed at admission, so 4 more drain to zero).
	for i := 0; i < 5; i++ {
		rl.Allow(victim)
	}
	if rl.Allow(victim) {
		t.Fatal("test setup: victim should be drained before eviction")
	}

	// Two new IPs evict victim (capacity=2, so the second new IP
	// pushes victim out of the LRU).
	rl.Allow(ipKey(makeUDPAddr("10.0.0.2", 1000)))
	rl.Allow(ipKey(makeUDPAddr("10.0.0.3", 1000)))

	// Victim returns: a fresh bucket should be created with burst/2
	// starter (5), not the drained-zero state from before eviction.
	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.Allow(victim) {
			allowed++
		}
	}
	if allowed != 5 {
		t.Errorf("re-admitted IP should get fresh burst/2=5 starter, got %d allowed", allowed)
	}
}

// TestIPRateLimiter_Burst1Degenerate pins the documented edge case
// from IPRateLimiter's type doc: with Burst=1, starter=0.5, post-
// admission balance is -0.5. The first packet still admits (the
// admission path returns true unconditionally on a fresh IP), but
// subsequent packets must wait for refill from a *negative* balance.
// Not a configuration that arises in production — fence is here so
// a future config-validation refactor doesn't silently change this
// edge case. Failure hint: if this starts failing, check whether
// NewIPRateLimiter started rejecting Burst<2 (the test is asserting
// behavior, not validating that Burst=1 should be allowed).
func TestIPRateLimiter_Burst1Degenerate(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    1, // 1 token per second; refill from -0.5 needs 1.5s for tokens >= 1
		Burst:   1,
		IdleTTL: time.Minute,
	})

	ip := ipKey(makeUDPAddr("198.51.100.1", 1234))

	if !rl.Allow(ip) {
		t.Fatal("first packet must admit on fresh IP regardless of starter math")
	}
	if rl.Allow(ip) {
		t.Error("second packet must be denied: balance is -0.5, refill not yet enough")
	}
}

// TestIPRateLimiter_FreshIPRefillCapsAtBurst pins that an IP
// admitted with burst/2 starter cannot refill past the full burst
// — i.e. the cap is on burst, not on starter capacity. CR-requested
// fence for PR #1506: TestIPRateLimiter_BurstCap covers established
// buckets, this covers the fresh-bucket path.
func TestIPRateLimiter_FreshIPRefillCapsAtBurst(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    100, // 1 token per 10ms
		Burst:   6,   // starter=3, full=6
		IdleTTL: time.Minute,
	})

	ip := ipKey(makeUDPAddr("10.0.0.1", 1000))

	// First packet admits and consumes one starter token (post: 2.0).
	if !rl.Allow(ip) {
		t.Fatal("first packet should be admitted")
	}

	// Wait long enough that uncapped refill would exceed burst.
	// 200ms * 100pps = 20 tokens; without burst cap, bucket would
	// hold 22. Capped at burst=6.
	time.Sleep(200 * time.Millisecond)

	allowed := 0
	for i := 0; i < 20; i++ {
		if rl.Allow(ip) {
			allowed++
		}
	}
	if allowed > 6 {
		t.Errorf("fresh-IP refill must cap at burst (6), got %d allowed (suggests starter-bucket path doesn't cap)", allowed)
	}
}

func TestIPRateLimiter_IPv6(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    10,
		Burst:   4,
		IdleTTL: time.Minute,
	})

	v6 := ipKey(makeUDPAddr("2001:db8::1", 5000))

	for i := 0; i < 2; i++ {
		if !rl.Allow(v6) {
			t.Errorf("IPv6 request %d should be allowed", i+1)
		}
	}
	if rl.Allow(v6) {
		t.Error("IPv6 should be rate limited after starter exhausted")
	}
}

func TestIPRateLimiter_IPv4MappedIPv6SharesBucket(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    10,
		Burst:   4,
		IdleTTL: time.Minute,
	})

	v4 := ipKey(makeUDPAddr("192.168.1.1", 5000))
	v6 := ipKey(makeUDPAddr("::ffff:192.168.1.1", 5000)) // IPv4-mapped IPv6

	for i := 0; i < 2; i++ {
		rl.Allow(v4)
	}

	// IPv4-mapped IPv6 normalizes to the same string ("192.168.1.1")
	// via Go's net.IP.String(), so they correctly share a bucket.
	if rl.Allow(v6) {
		t.Error("IPv4-mapped IPv6 should share bucket with IPv4 equivalent")
	}

	if rl.Len() != 1 {
		t.Errorf("expected 1 bucket (same underlying IP), got %d", rl.Len())
	}
}

func TestIPRateLimiter_IPv6VariousFormats(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    10,
		Burst:   4,
		IdleTTL: time.Minute,
	})

	addrs := []string{
		"2001:db8::1",
		"fe80::1",
		"::1",
		"2001:db8:85a3::8a2e:370:7334",
	}

	for _, ip := range addrs {
		key := ipKey(makeUDPAddr(ip, 5000))
		if !rl.Allow(key) {
			t.Errorf("first packet from %s should be allowed", ip)
		}
	}

	if rl.Len() != len(addrs) {
		t.Errorf("expected %d buckets, got %d", len(addrs), rl.Len())
	}
}

func TestIPRateLimiter_IPv6SameIPDifferentPorts(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:    10,
		Burst:   4,
		IdleTTL: time.Minute,
	})

	// Same IPv6, different ports — should share one bucket
	addr1 := makeUDPAddr("2001:db8::1", 1000)
	addr2 := makeUDPAddr("2001:db8::1", 2000)

	rl.Allow(ipKey(addr1))
	rl.Allow(ipKey(addr2)) // consumes from same bucket

	if rl.Allow(ipKey(makeUDPAddr("2001:db8::1", 3000))) {
		t.Error("same IPv6 different port should share bucket and be rate limited")
	}

	if rl.Len() != 1 {
		t.Errorf("expected 1 bucket (same IP), got %d", rl.Len())
	}
}
