package ac

import (
	"errors"
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

const (
	// AOP packets are rejected once their authenticated timestamp is more than
	// 120 seconds old. Retaining the barrier for one additional scheduler/clock
	// margin prevents a delayed pre-barrier attempt from being admitted after
	// the close acknowledgement was sent.
	nhpRunAttemptBarrierTTL  = 125 * time.Second
	maxNHPRunAttemptBarriers = 100_000
)

var (
	errNHPRunAttemptBarrierMissing   = errors.New("NHP run-attempt barrier is missing")
	errNHPRunAttemptBarrierPending   = errors.New("NHP run-attempt barrier cleanup is pending")
	errNHPRunAttemptBarrierStale     = errors.New("NHP run attempt is stale")
	errNHPRunAttemptBarrierCapacity  = errors.New("NHP run-attempt barrier capacity exceeded")
	errNHPRunAttemptBarrierMalformed = errors.New("NHP run-attempt barrier is malformed")
)

type nhpRunAttemptBarrierKey struct {
	agentPublicKey string
	runID          string
}

type nhpRunAttemptBarrier struct {
	attempt         uint64
	flushGeneration uint64
	converged       bool
	expiresAt       time.Time
}

// nhpRunAttemptBarriers is the AC-local high watermark established by a
// strict run-scoped NHP_REV. A record starts pending before teardown and is
// promoted to converged only after every matching older rule is gone; only the
// converged attempt may admit NHP_AOP. It is independent of token membership:
// a barrier with zero matching older tokens is still authoritative and must
// survive long enough to reject delayed AOPs.
type nhpRunAttemptBarriers struct {
	mu      sync.Mutex
	entries map[nhpRunAttemptBarrierKey]nhpRunAttemptBarrier
	now     func() time.Time
}

func newNHPRunAttemptBarriers() *nhpRunAttemptBarriers {
	return &nhpRunAttemptBarriers{
		entries: make(map[nhpRunAttemptBarrierKey]nhpRunAttemptBarrier),
		now:     time.Now,
	}
}

func (b *nhpRunAttemptBarriers) sweepLocked(now time.Time) {
	for key, entry := range b.entries {
		// A failed cleanup must deny the requested attempt until an exact
		// authenticated retry converges; pending state therefore has no TTL.
		if entry.converged && !now.Before(entry.expiresAt) {
			delete(b.entries, key)
		}
	}
}

// record advances one run's monotonic admission watermark in pending state. A
// lower replay is accepted idempotently but never lowers the current attempt;
// an exact retry preserves an already-converged record. Saturation is fail
// closed for a new run: the AC sends no convergence ACK, so the server cannot
// proceed to AOP.
func (b *nhpRunAttemptBarriers) record(agentPublicKey, runID string, attempt, flushGeneration uint64) error {
	if b == nil || !common.ValidNHPAgentPublicKey(agentPublicKey) ||
		common.ValidateAgentKnockRunID(runID) != nil || attempt == 0 || flushGeneration == 0 {
		return errNHPRunAttemptBarrierMalformed
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.sweepLocked(now)
	key := nhpRunAttemptBarrierKey{agentPublicKey: agentPublicKey, runID: runID}
	current, found := b.entries[key]
	if !found && len(b.entries) >= maxNHPRunAttemptBarriers {
		return errNHPRunAttemptBarrierCapacity
	}
	if found && flushGeneration < current.flushGeneration {
		return errNHPRunAttemptBarrierStale
	}
	if !found || flushGeneration > current.flushGeneration || attempt > current.attempt {
		current.attempt = attempt
		current.flushGeneration = flushGeneration
		current.converged = false
	}
	if current.converged {
		current.expiresAt = now.Add(nhpRunAttemptBarrierTTL)
	} else {
		current.expiresAt = time.Time{}
	}
	b.entries[key] = current
	return nil
}

// commit promotes the exact pending watermark after verified teardown. It may
// not promote a stale close if a newer generation or attempt has already been
// recorded.
func (b *nhpRunAttemptBarriers) commit(agentPublicKey, runID string, attempt, flushGeneration uint64) error {
	if b == nil || !common.ValidNHPAgentPublicKey(agentPublicKey) ||
		common.ValidateAgentKnockRunID(runID) != nil || attempt == 0 || flushGeneration == 0 {
		return errNHPRunAttemptBarrierMalformed
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.sweepLocked(now)
	key := nhpRunAttemptBarrierKey{agentPublicKey: agentPublicKey, runID: runID}
	current, found := b.entries[key]
	if !found || flushGeneration > current.flushGeneration || attempt > current.attempt {
		return errNHPRunAttemptBarrierMissing
	}
	if flushGeneration < current.flushGeneration || attempt < current.attempt {
		return errNHPRunAttemptBarrierStale
	}
	current.converged = true
	current.expiresAt = now.Add(nhpRunAttemptBarrierTTL)
	b.entries[key] = current
	return nil
}

// requireExact admits only the attempt whose barrier has converged. A lower
// attempt is stale; a higher attempt has not yet established its barrier and
// is missing. Treating both as denial prevents delayed or reordered AOPs from
// reopening an older run.
func (b *nhpRunAttemptBarriers) requireExact(agentPublicKey, runID string, attempt, flushGeneration uint64) error {
	if b == nil || !common.ValidNHPAgentPublicKey(agentPublicKey) ||
		common.ValidateAgentKnockRunID(runID) != nil || attempt == 0 || flushGeneration == 0 {
		return errNHPRunAttemptBarrierMalformed
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.sweepLocked(now)
	entry, found := b.entries[nhpRunAttemptBarrierKey{agentPublicKey: agentPublicKey, runID: runID}]
	if !found || flushGeneration > entry.flushGeneration || attempt > entry.attempt {
		return errNHPRunAttemptBarrierMissing
	}
	if flushGeneration < entry.flushGeneration || attempt < entry.attempt {
		return errNHPRunAttemptBarrierStale
	}
	if !entry.converged {
		return errNHPRunAttemptBarrierPending
	}
	return nil
}
