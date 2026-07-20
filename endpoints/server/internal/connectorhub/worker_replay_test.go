package connectorhub

import (
	"crypto/sha256"
	"testing"
	"time"
)

func TestPacketReplayCacheBoundsCapacityAndTTL(t *testing.T) {
	now := time.Unix(100, 0)
	cache := newPacketReplayCache(2)
	digestA := sha256.Sum256([]byte("a"))
	digestB := sha256.Sum256([]byte("b"))
	digestC := sha256.Sum256([]byte("c"))

	assertPacketReplayDecision(t, cache.accept(digestA, now), packetReplayAccepted)
	assertPacketReplayDecision(t, cache.accept(digestA, now.Add(time.Second)), packetReplayExact)
	assertPacketReplayDecision(t, cache.accept(digestB, now.Add(2*time.Second)), packetReplayAccepted)
	assertPacketReplayDecision(t, cache.accept(digestC, now.Add(3*time.Second)), packetReplayCapacityFull)
	if cache.order.Len() != 2 || len(cache.entries) != 2 {
		t.Fatalf("cache size = %d/%d, want capacity 2", cache.order.Len(), len(cache.entries))
	}
	// Capacity pressure must preserve every live digest rather than reopening
	// either replay. The rejected new digest is accepted only after strict TTL
	// expiry frees one entry.
	assertPacketReplayDecision(t, cache.accept(digestA, now.Add(4*time.Second)), packetReplayExact)
	assertPacketReplayDecision(t, cache.accept(digestB, now.Add(4*time.Second)), packetReplayExact)
	assertPacketReplayDecision(t, cache.accept(digestC, now.Add(hubWorkerReplayTTL)), packetReplayCapacityFull)
	assertPacketReplayDecision(t, cache.accept(digestC, now.Add(hubWorkerReplayTTL+time.Nanosecond)), packetReplayAccepted)
}

func TestPacketReplayCacheRetainsExactProtocolBoundary(t *testing.T) {
	now := time.Unix(100, 0)
	cache := newPacketReplayCache(1)
	digest := sha256.Sum256([]byte("boundary"))
	assertPacketReplayDecision(t, cache.accept(digest, now), packetReplayAccepted)
	assertPacketReplayDecision(t, cache.accept(digest, now.Add(hubWorkerReplayTTL)), packetReplayExact)
	assertPacketReplayDecision(t, cache.accept(digest, now.Add(hubWorkerReplayTTL+time.Nanosecond)), packetReplayAccepted)
}

func TestPacketReplayCacheClampsOutOfOrderAcceptanceTime(t *testing.T) {
	base := time.Unix(100, 0)
	cache := newPacketReplayCache(2)
	later := sha256.Sum256([]byte("later-lock-holder"))
	earlierSnapshot := sha256.Sum256([]byte("earlier-clock-snapshot"))

	// Model two goroutines that capture the clock before the mutex but acquire
	// it in the opposite order. The second insert must inherit the later clock
	// so its expiry cannot sit behind a live front entry.
	assertPacketReplayDecision(t, cache.accept(later, base.Add(200*time.Second)), packetReplayAccepted)
	assertPacketReplayDecision(t, cache.accept(earlierSnapshot, base.Add(100*time.Second)), packetReplayAccepted)
	assertPacketReplayDecision(t,
		cache.accept(earlierSnapshot, base.Add(100*time.Second+hubWorkerReplayTTL+time.Nanosecond)),
		packetReplayExact,
	)
	assertPacketReplayDecision(t,
		cache.accept(later, base.Add(200*time.Second+hubWorkerReplayTTL)),
		packetReplayExact,
	)
}

func assertPacketReplayDecision(t *testing.T, got, want packetReplayDecision) {
	t.Helper()
	if got != want {
		t.Fatalf("replay decision = %d, want %d", got, want)
	}
}

func TestDeriveReplayCapacityCoversFullAdmissionWindow(t *testing.T) {
	const (
		maxConcurrent = 2
		ratePerSecond = 5
		burst         = 3
	)
	want := maxConcurrent + burst + ratePerSecond*int(hubWorkerReplayTTL/time.Second)
	got, ok := deriveReplayCapacity(maxConcurrent, ratePerSecond, burst)
	if !ok || got != want {
		t.Fatalf("deriveReplayCapacity() = %d/%v, want %d/true", got, ok, want)
	}

	maxInt := int(^uint(0) >> 1)
	if _, ok := deriveReplayCapacity(maxInt, 1, 1); ok {
		t.Fatal("overflowing replay capacity accepted")
	}
	if _, ok := deriveReplayCapacity(1, maxInt, 1); ok {
		t.Fatal("overflowing rate window accepted")
	}
}
