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

func TestIPRateLimiter_AllowBurst(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:            10, // 10 pps
		Burst:           5,  // burst of 5
		CleanupInterval: time.Minute,
		IdleTTL:         time.Minute,
	})
	defer rl.Stop()

	addr := makeUDPAddr("192.168.1.1", 12345)

	// First 5 packets should be allowed (burst capacity)
	for i := 0; i < 5; i++ {
		if !rl.Allow(addr) {
			t.Errorf("packet %d should be allowed within burst", i+1)
		}
	}

	// 6th packet without waiting should be dropped
	if rl.Allow(addr) {
		t.Error("packet 6 should be rate limited (burst exhausted)")
	}
}

func TestIPRateLimiter_Refill(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:            10, // 10 pps = 1 token per 100ms
		Burst:           5,
		CleanupInterval: time.Minute,
		IdleTTL:         time.Minute,
	})
	defer rl.Stop()

	addr := makeUDPAddr("10.0.0.1", 9999)

	// Exhaust burst
	for i := 0; i < 5; i++ {
		rl.Allow(addr)
	}
	if rl.Allow(addr) {
		t.Fatal("should be rate limited after burst")
	}

	// Wait for 1 token to refill (100ms at 10 pps)
	time.Sleep(150 * time.Millisecond)

	if !rl.Allow(addr) {
		t.Error("should be allowed after token refill")
	}
}

func TestIPRateLimiter_IndependentIPs(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:            10,
		Burst:           3,
		CleanupInterval: time.Minute,
		IdleTTL:         time.Minute,
	})
	defer rl.Stop()

	addr1 := makeUDPAddr("10.0.0.1", 1111)
	addr2 := makeUDPAddr("10.0.0.2", 2222)

	// Exhaust burst for addr1
	for i := 0; i < 3; i++ {
		rl.Allow(addr1)
	}
	if rl.Allow(addr1) {
		t.Error("addr1 should be rate limited")
	}

	// addr2 should still have full burst
	for i := 0; i < 3; i++ {
		if !rl.Allow(addr2) {
			t.Errorf("addr2 packet %d should be allowed", i+1)
		}
	}
}

func TestIPRateLimiter_SameIPDifferentPorts(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:            10,
		Burst:           3,
		CleanupInterval: time.Minute,
		IdleTTL:         time.Minute,
	})
	defer rl.Stop()

	// Same IP, different ports should share the same bucket
	addr1 := makeUDPAddr("10.0.0.1", 1111)
	addr2 := makeUDPAddr("10.0.0.1", 2222)

	for i := 0; i < 3; i++ {
		rl.Allow(addr1)
	}

	// Same IP with different port should also be rate limited
	if rl.Allow(addr2) {
		t.Error("same IP with different port should share rate limit bucket")
	}
}

func TestIPRateLimiter_Cleanup(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:            100,
		Burst:           10,
		CleanupInterval: 50 * time.Millisecond,
		IdleTTL:         100 * time.Millisecond,
	})
	defer rl.Stop()

	addr := makeUDPAddr("192.168.1.1", 12345)
	rl.Allow(addr)

	if rl.Len() != 1 {
		t.Errorf("expected 1 tracked IP, got %d", rl.Len())
	}

	// Wait for cleanup
	time.Sleep(250 * time.Millisecond)

	if rl.Len() != 0 {
		t.Errorf("expected 0 tracked IPs after cleanup, got %d", rl.Len())
	}
}

func TestIPRateLimiter_BurstCap(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:            1000, // high rate
		Burst:           5,    // low burst
		CleanupInterval: time.Minute,
		IdleTTL:         time.Minute,
	})
	defer rl.Stop()

	addr := makeUDPAddr("10.0.0.1", 1111)

	// Exhaust burst
	for i := 0; i < 5; i++ {
		rl.Allow(addr)
	}

	// Wait long enough that tokens would exceed burst if not capped
	time.Sleep(100 * time.Millisecond)

	// Should have refilled but capped at burst
	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.Allow(addr) {
			allowed++
		}
	}
	if allowed > 5 {
		t.Errorf("tokens should be capped at burst (%d), but %d were allowed", 5, allowed)
	}
}

func TestIPRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:            1000,
		Burst:           100,
		CleanupInterval: time.Minute,
		IdleTTL:         time.Minute,
	})
	defer rl.Stop()

	var wg sync.WaitGroup
	// Simulate concurrent packet arrivals from multiple IPs
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			addr := makeUDPAddr(fmt.Sprintf("10.0.0.%d", idx+1), 12345)
			for j := 0; j < 200; j++ {
				rl.Allow(addr) // should not panic or race
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
	if cfg.CleanupInterval != 30*time.Second {
		t.Errorf("expected default cleanup interval 30s, got %v", cfg.CleanupInterval)
	}
	if cfg.IdleTTL != 120*time.Second {
		t.Errorf("expected default idle TTL 120s, got %v", cfg.IdleTTL)
	}
}

func TestIPRateLimiter_StopIdempotent(t *testing.T) {
	rl := NewIPRateLimiter(DefaultRateLimiterConfig())
	// Should not panic when called multiple times
	rl.Stop()
	rl.Stop()
	rl.Stop()
}

func TestIPRateLimiter_ZeroConfigUsesDefaults(t *testing.T) {
	// Zero-value config should fall back to defaults
	rl := NewIPRateLimiter(RateLimiterConfig{})
	defer rl.Stop()

	addr := makeUDPAddr("10.0.0.1", 1111)
	// With default burst=50, first 50 packets should be allowed
	for i := 0; i < 50; i++ {
		if !rl.Allow(addr) {
			t.Errorf("packet %d should be allowed with default burst", i+1)
		}
	}
}

func BenchmarkIPRateLimiter_Allow_SingleIP(b *testing.B) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:            10000,
		Burst:           10000,
		CleanupInterval: time.Minute,
		IdleTTL:         time.Minute,
	})
	defer rl.Stop()

	addr := makeUDPAddr("10.0.0.1", 12345)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow(addr)
	}
}

func BenchmarkIPRateLimiter_Allow_MultipleIPs(b *testing.B) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:            10000,
		Burst:           10000,
		CleanupInterval: time.Minute,
		IdleTTL:         time.Minute,
	})
	defer rl.Stop()

	addrs := make([]*net.UDPAddr, 100)
	for i := range addrs {
		addrs[i] = makeUDPAddr(fmt.Sprintf("10.0.%d.%d", i/256, i%256), 12345)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow(addrs[i%len(addrs)])
	}
}

func BenchmarkIPRateLimiter_Allow_Parallel(b *testing.B) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:            10000,
		Burst:           10000,
		CleanupInterval: time.Minute,
		IdleTTL:         time.Minute,
	})
	defer rl.Stop()

	b.RunParallel(func(pb *testing.PB) {
		addr := makeUDPAddr("10.0.0.1", 12345)
		for pb.Next() {
			rl.Allow(addr)
		}
	})
}

func TestIPRateLimiter_MaxBuckets(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:            100,
		Burst:           10,
		CleanupInterval: time.Hour, // no cleanup during test
		IdleTTL:         time.Hour,
		MaxBuckets:      5,
	})
	defer rl.Stop()

	// Fill to capacity — each new IP gets a bucket
	for i := 0; i < 5; i++ {
		addr := makeUDPAddr(fmt.Sprintf("10.0.0.%d", i+1), 1000)
		if !rl.Allow(addr) {
			t.Errorf("IP %d should be allowed (under max buckets)", i+1)
		}
	}

	// Next new IP should be dropped — at capacity
	overflow := makeUDPAddr("10.0.0.100", 1000)
	if rl.Allow(overflow) {
		t.Error("new IP should be dropped when at max bucket capacity")
	}

	// Existing IPs should still work
	existing := makeUDPAddr("10.0.0.1", 1000)
	if !rl.Allow(existing) {
		t.Error("existing IP should still be allowed")
	}
}

func TestIPRateLimiter_IPv6(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:            10,
		Burst:           3,
		CleanupInterval: time.Minute,
		IdleTTL:         time.Minute,
	})
	defer rl.Stop()

	v6Addr := makeUDPAddr("2001:db8::1", 5000)

	// Burst should work for IPv6
	for i := 0; i < 3; i++ {
		if !rl.Allow(v6Addr) {
			t.Errorf("IPv6 request %d should be allowed", i+1)
		}
	}
	if rl.Allow(v6Addr) {
		t.Error("IPv6 should be rate limited after burst")
	}
}

func TestIPRateLimiter_IPv4MappedIPv6SharesBucket(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:            10,
		Burst:           3,
		CleanupInterval: time.Minute,
		IdleTTL:         time.Minute,
	})
	defer rl.Stop()

	v4 := makeUDPAddr("192.168.1.1", 5000)
	v6 := makeUDPAddr("::ffff:192.168.1.1", 5000) // IPv4-mapped IPv6

	// Exhaust burst via v4
	for i := 0; i < 3; i++ {
		rl.Allow(v4)
	}

	// IPv4-mapped IPv6 normalizes to the same string ("192.168.1.1")
	// via Go's net.IP.String(), so they correctly share a bucket.
	if rl.Allow(v6) {
		t.Error("IPv4-mapped IPv6 should share bucket with IPv4 equivalent")
	}

	// Only one bucket should exist
	if rl.Len() != 1 {
		t.Errorf("expected 1 bucket (same underlying IP), got %d", rl.Len())
	}
}

func TestIPRateLimiter_IPv6VariousFormats(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:            10,
		Burst:           3,
		CleanupInterval: time.Minute,
		IdleTTL:         time.Minute,
	})
	defer rl.Stop()

	addrs := []string{
		"2001:db8::1",
		"fe80::1",
		"::1",
		"2001:db8:85a3::8a2e:370:7334",
	}

	for _, ip := range addrs {
		addr := makeUDPAddr(ip, 5000)
		if !rl.Allow(addr) {
			t.Errorf("first packet from %s should be allowed", ip)
		}
	}

	// Verify each has its own bucket (Len should be 4)
	if rl.Len() != len(addrs) {
		t.Errorf("expected %d buckets, got %d", len(addrs), rl.Len())
	}
}

func TestIPRateLimiter_IPv6SameIPDifferentPorts(t *testing.T) {
	rl := NewIPRateLimiter(RateLimiterConfig{
		Rate:            10,
		Burst:           2,
		CleanupInterval: time.Minute,
		IdleTTL:         time.Minute,
	})
	defer rl.Stop()

	// Same IPv6, different ports — should share one bucket
	addr1 := makeUDPAddr("2001:db8::1", 1000)
	addr2 := makeUDPAddr("2001:db8::1", 2000)

	rl.Allow(addr1)
	rl.Allow(addr2) // consumes from same bucket

	if rl.Allow(makeUDPAddr("2001:db8::1", 3000)) {
		t.Error("same IPv6 different port should share bucket and be rate limited")
	}

	if rl.Len() != 1 {
		t.Errorf("expected 1 bucket (same IP), got %d", rl.Len())
	}
}
