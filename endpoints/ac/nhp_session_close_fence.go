package ac

import (
	"errors"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

var (
	errNHPExactCloseFenceMalformed  = errors.New("NHP exact close fence is malformed")
	errNHPExactCloseFenceMissing    = errors.New("NHP exact close fence is missing")
	errNHPExactCloseFenceCapacity   = errors.New("NHP exact close fence capacity exceeded")
	errNHPAgentCloseCutoffMalformed = errors.New("NHP agent close cutoff is malformed")
	errNHPAgentCloseCutoffMissing   = errors.New("NHP agent close cutoff is missing")
	errNHPAgentCloseCutoffPending   = errors.New("newer NHP agent close cutoff is pending")
	errNHPAgentCloseCutoffCapacity  = errors.New("NHP agent close cutoff capacity exceeded")
)

const (
	// AOP is accepted for 120 seconds. Retaining close fences for that complete
	// authenticated replay window plus clock/scheduler margin prevents a
	// reordered pre-close AOP from reopening after the close acknowledgement.
	nhpSessionCloseFenceTTL  = time.Duration(core.AOPRecvStalenessFloorSeconds)*time.Second + 5*time.Second
	maxNHPSessionCloseFences = 100_000
)

type nhpExactCloseFence struct {
	converged bool
	expiresAt time.Time
}

type nhpAgentCloseCutoff struct {
	issuedThroughMillis int64
	converged           bool
	expiresAt           time.Time
}

func (i *nhpSessionIndex) sweepCloseFencesLocked(now time.Time) {
	for key, fence := range i.exactCloseFences {
		// A failed cleanup must keep the exact tuple closed until the same
		// authenticated control operation retries and converges.
		if fence.converged && !now.Before(fence.expiresAt) {
			delete(i.exactCloseFences, key)
		}
	}
	for key, cutoff := range i.agentCloseCutoffs {
		// A failed cleanup must deny every same-agent admission until its
		// authenticated retry converges; pending state therefore has no TTL.
		if cutoff.converged && !now.Before(cutoff.expiresAt) {
			delete(i.agentCloseCutoffs, key)
		}
	}
	if !now.Before(i.closeFenceSaturatedUntil) {
		i.closeFenceSaturatedUntil = time.Time{}
	}
}

// beginExactCloseFence publishes a non-expiring pending tombstone before
// teardown begins. An exact retry preserves pending state; a replay after
// convergence refreshes the bounded authenticated replay fence.
func (i *nhpSessionIndex) beginExactCloseFence(agentPublicKey string, sessionID uint64, issuedAtMillis int64) error {
	if i == nil || !common.ValidNHPAgentPublicKey(agentPublicKey) || sessionID == 0 || issuedAtMillis <= 0 {
		return errNHPExactCloseFenceMalformed
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	now := i.now()
	i.sweepCloseFencesLocked(now)
	key := nhpExactSessionKey{agentPublicKey: agentPublicKey, sessionID: sessionID, issuedAtMillis: issuedAtMillis}
	fence, exists := i.exactCloseFences[key]
	if !exists && len(i.exactCloseFences)+len(i.agentCloseCutoffs) >= maxNHPSessionCloseFences {
		i.closeFenceSaturatedUntil = now.Add(nhpSessionCloseFenceTTL)
		return errNHPExactCloseFenceCapacity
	}
	if fence.converged {
		fence.expiresAt = now.Add(nhpSessionCloseFenceTTL)
	} else {
		fence.expiresAt = time.Time{}
	}
	i.exactCloseFences[key] = fence
	return nil
}

// commitExactCloseFence converts the exact pending tombstone into the bounded
// post-convergence replay fence. It cannot create a fence after teardown: begin
// must have succeeded first so admissions were denied throughout cleanup.
func (i *nhpSessionIndex) commitExactCloseFence(agentPublicKey string, sessionID uint64, issuedAtMillis int64) error {
	if i == nil || !common.ValidNHPAgentPublicKey(agentPublicKey) || sessionID == 0 || issuedAtMillis <= 0 {
		return errNHPExactCloseFenceMalformed
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	now := i.now()
	i.sweepCloseFencesLocked(now)
	key := nhpExactSessionKey{agentPublicKey: agentPublicKey, sessionID: sessionID, issuedAtMillis: issuedAtMillis}
	fence, exists := i.exactCloseFences[key]
	if !exists {
		return errNHPExactCloseFenceMissing
	}
	fence.converged = true
	fence.expiresAt = now.Add(nhpSessionCloseFenceTTL)
	i.exactCloseFences[key] = fence
	return nil
}

// beginAgentCloseCutoff publishes a pending same-agent fence before verified
// teardown. Exact retries preserve their prior pending/converged state; a
// higher cutoff becomes pending, while a lower replay is accepted only when a
// higher converged cutoff already proves it.
func (i *nhpSessionIndex) beginAgentCloseCutoff(agentPublicKey string, issuedThroughMillis int64) error {
	if i == nil || !common.ValidNHPAgentPublicKey(agentPublicKey) || issuedThroughMillis <= 0 {
		return errNHPAgentCloseCutoffMalformed
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	now := i.now()
	i.sweepCloseFencesLocked(now)
	current, exists := i.agentCloseCutoffs[agentPublicKey]
	if !exists && len(i.exactCloseFences)+len(i.agentCloseCutoffs) >= maxNHPSessionCloseFences {
		i.closeFenceSaturatedUntil = now.Add(nhpSessionCloseFenceTTL)
		return errNHPAgentCloseCutoffCapacity
	}
	if exists && issuedThroughMillis < current.issuedThroughMillis {
		if current.converged {
			return nil
		}
		return errNHPAgentCloseCutoffPending
	}
	if !exists || issuedThroughMillis > current.issuedThroughMillis {
		current.issuedThroughMillis = issuedThroughMillis
		current.converged = false
	}
	if current.converged {
		current.expiresAt = now.Add(nhpSessionCloseFenceTTL)
	} else {
		current.expiresAt = time.Time{}
	}
	i.agentCloseCutoffs[agentPublicKey] = current
	return nil
}

// commitAgentCloseCutoff converts the exact pending cutoff to the bounded
// post-convergence replay fence. A lower replay is already proven only when a
// higher cutoff has converged.
func (i *nhpSessionIndex) commitAgentCloseCutoff(agentPublicKey string, issuedThroughMillis int64) error {
	if i == nil || !common.ValidNHPAgentPublicKey(agentPublicKey) || issuedThroughMillis <= 0 {
		return errNHPAgentCloseCutoffMalformed
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	now := i.now()
	i.sweepCloseFencesLocked(now)
	current, exists := i.agentCloseCutoffs[agentPublicKey]
	if !exists || issuedThroughMillis > current.issuedThroughMillis {
		return errNHPAgentCloseCutoffMissing
	}
	if issuedThroughMillis < current.issuedThroughMillis {
		if current.converged {
			return nil
		}
		return errNHPAgentCloseCutoffPending
	}
	current.converged = true
	current.expiresAt = now.Add(nhpSessionCloseFenceTTL)
	i.agentCloseCutoffs[agentPublicKey] = current
	return nil
}

func (i *nhpSessionIndex) admitsSession(entry *AccessEntry) bool {
	if i == nil || entry == nil || !common.ValidNHPAgentPublicKey(entry.NHPAgentPublicKey) ||
		entry.NHPSessionId == 0 || entry.NHPSessionIssuedAtMillis <= 0 {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	now := i.now()
	i.sweepCloseFencesLocked(now)
	if now.Before(i.closeFenceSaturatedUntil) {
		return false
	}
	if cutoff, ok := i.agentCloseCutoffs[entry.NHPAgentPublicKey]; ok {
		if !cutoff.converged || entry.NHPSessionIssuedAtMillis <= cutoff.issuedThroughMillis {
			return false
		}
	}
	_, closed := i.exactCloseFences[nhpExactSessionKey{
		agentPublicKey: entry.NHPAgentPublicKey,
		sessionID:      entry.NHPSessionId,
		issuedAtMillis: entry.NHPSessionIssuedAtMillis,
	}]
	return !closed
}
