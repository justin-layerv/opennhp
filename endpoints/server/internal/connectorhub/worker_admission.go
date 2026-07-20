package connectorhub

import (
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/nhp/core"
)

type aggregateAdmission struct {
	mu sync.Mutex

	ratePerSecond float64
	burst         float64
	tokens        float64
	last          time.Time
	concurrent    chan struct{}
}

func newAggregateAdmission(maxConcurrent, ratePerSecond, burst int, now time.Time) *aggregateAdmission {
	return &aggregateAdmission{
		ratePerSecond: float64(ratePerSecond),
		burst:         float64(burst),
		tokens:        float64(burst),
		last:          now,
		concurrent:    make(chan struct{}, maxConcurrent),
	}
}

func (a *aggregateAdmission) acquire(now time.Time) (release func(), outcome WorkerOutcome, ok bool) {
	// Spend the rate token before the concurrency check intentionally. A packet
	// rejected under contention still consumes public-edge budget, which is
	// conservative and keeps the replay-capacity derivation an overestimate.
	if !a.allowRate(now) {
		return nil, WorkerOutcomeAggregateRateRejected, false
	}
	select {
	case a.concurrent <- struct{}{}:
		return func() { <-a.concurrent }, "", true
	default:
		return nil, WorkerOutcomeAggregateLimitRejected, false
	}
}

func (a *aggregateAdmission) allowRate(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if now.After(a.last) {
		a.tokens += now.Sub(a.last).Seconds() * a.ratePerSecond
		if a.tokens > a.burst {
			a.tokens = a.burst
		}
		a.last = now
	}
	if a.tokens < 1 {
		return false
	}
	a.tokens--
	return true
}

type peerAdmission struct {
	mu       sync.Mutex
	limit    int
	inFlight map[[core.PublicKeySize]byte]int
}

func newPeerAdmission(limit int) *peerAdmission {
	return &peerAdmission{limit: limit, inFlight: make(map[[core.PublicKeySize]byte]int)}
}

func (a *peerAdmission) acquire(peer []byte) (release func(), outcome WorkerOutcome, ok bool) {
	if len(peer) != core.PublicKeySize {
		// PacketToMsg can only produce a canonical Curve25519 key here. Treat
		// wrong-length state as an internal crypto anomaly, not peer pressure.
		return nil, WorkerOutcomeCryptoRejected, false
	}
	var key [core.PublicKeySize]byte
	copy(key[:], peer)

	a.mu.Lock()
	if a.inFlight[key] >= a.limit {
		a.mu.Unlock()
		return nil, WorkerOutcomePeerLimitRejected, false
	}
	a.inFlight[key]++
	a.mu.Unlock()

	return func() {
		a.mu.Lock()
		if a.inFlight[key] <= 1 {
			delete(a.inFlight, key)
		} else {
			a.inFlight[key]--
		}
		a.mu.Unlock()
	}, "", true
}
