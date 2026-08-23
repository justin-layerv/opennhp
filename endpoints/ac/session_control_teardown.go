package ac

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

type sessionControlEntryPredicate func(*AccessEntry) bool

// closeSessionControlTokensVerified marks matching tokens unusable immediately,
// then removes every tracked kernel rule synchronously. A failed rule remains
// attached to the still-indexed closing entry, so an identical control retry
// repeats the actual teardown instead of mistaking a destructive first attempt
// for convergence.
func (a *UdpAC) closeSessionControlTokensVerified(ctx context.Context, tokens []string, matches sessionControlEntryPredicate) (int, error) {
	if a == nil || a.tokenStore == nil || a.expirySched == nil {
		return 0, errors.New("session-control verified teardown is unavailable")
	}
	if a.expirySched.dryRun.Load() {
		return 0, errors.New("session-control verified teardown cannot use a dry-run scheduler")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	closed := 0
	var firstErr error
	for _, token := range tokens {
		entry, ok := a.tokenStore.Load(token)
		if !ok || entry == nil || !matches(entry) {
			continue
		}
		entry.sessionControlClosing.Store(true)
		if err := a.flushSessionControlEntryVerified(ctx, entry); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("flush session-control token: %w", err)
			}
			continue
		}
		// Delete only after verified kernel convergence. cancel drains the
		// preserved key set and removes or re-anchors scheduler coverage for
		// any live sibling that shares a coarse FlowKey.
		a.deleteToken(token, entry)
		a.cancelAllScheduledFlows(entry)
		closed++
	}
	return closed, firstErr
}

func (a *UdpAC) flushSessionControlEntryVerified(ctx context.Context, entry *AccessEntry) error {
	candidates := a.tokenStore.Snapshot()
	now := time.Now()
	for _, key := range entry.snapshotScheduledKeys() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if siblingDeadline := a.latestOtherScheduledDeadline(candidates, entry, key, now); !siblingDeadline.IsZero() {
			if err := a.expirySched.reanchor(key, siblingDeadline); err != nil {
				return fmt.Errorf("preserve sibling allow/flow rule %s: %w", key, err)
			}
			continue
		}
		if err := a.expirySched.FlushNowAndWait(ctx, key, a.flushInheritedConntrack); err != nil {
			return fmt.Errorf("flush allow/flow rule %s: %w", key, err)
		}
	}
	return nil
}

func (a *UdpAC) closeNHPExactSessionVerified(ctx context.Context, agentPublicKey string, sessionID uint64, issuedAtMillis int64) (int, error) {
	if a == nil || a.nhpSessions == nil || !common.ValidNHPAgentPublicKey(agentPublicKey) || sessionID == 0 || issuedAtMillis <= 0 {
		return 0, errors.New("invalid exact NHP session close")
	}
	return a.closeSessionControlTokensVerified(ctx, a.nhpSessions.exactTokens(agentPublicKey, sessionID, issuedAtMillis), func(entry *AccessEntry) bool {
		return entry.NHPAgentPublicKey == agentPublicKey && entry.NHPSessionId == sessionID && entry.NHPSessionIssuedAtMillis == issuedAtMillis
	})
}

// closeNHPExactSessionWithFenceVerified publishes the pending exact tombstone,
// performs verified kernel teardown, then commits the bounded replay fence.
// The caller must hold sessionControlFlushMu across this complete operation so
// registered-agent admission cannot interleave with the fence transition.
func (a *UdpAC) closeNHPExactSessionWithFenceVerified(ctx context.Context, agentPublicKey string, sessionID uint64, issuedAtMillis int64) (int, error) {
	if a == nil || a.nhpSessions == nil {
		return 0, errors.New("NHP session index is unavailable")
	}
	if err := a.nhpSessions.beginExactCloseFence(agentPublicKey, sessionID, issuedAtMillis); err != nil {
		return 0, err
	}
	closed, err := a.closeNHPExactSessionVerified(ctx, agentPublicKey, sessionID, issuedAtMillis)
	if err != nil {
		return closed, err
	}
	if err := a.nhpSessions.commitExactCloseFence(agentPublicKey, sessionID, issuedAtMillis); err != nil {
		return closed, err
	}
	return closed, nil
}

func (a *UdpAC) closeNHPAgentSessionsThroughVerified(ctx context.Context, agentPublicKey string, issuedThroughMillis int64) (int, error) {
	if a == nil || a.nhpSessions == nil || !common.ValidNHPAgentPublicKey(agentPublicKey) || issuedThroughMillis <= 0 {
		return 0, errors.New("invalid agent NHP session close")
	}
	return a.closeSessionControlTokensVerified(ctx, a.nhpSessions.agentTokens(agentPublicKey), func(entry *AccessEntry) bool {
		return entry.NHPAgentPublicKey == agentPublicKey && entry.NHPSessionIssuedAtMillis > 0 && entry.NHPSessionIssuedAtMillis <= issuedThroughMillis
	})
}

func (a *UdpAC) closeNHPRunBeforeAttemptVerified(ctx context.Context, agentPublicKey, runID string, attempt uint64) (int, error) {
	if a == nil || a.nhpSessions == nil || !common.ValidNHPAgentPublicKey(agentPublicKey) || common.ValidateAgentKnockRunID(runID) != nil || attempt == 0 {
		return 0, errors.New("invalid run NHP session close")
	}
	return a.closeSessionControlTokensVerified(ctx, a.nhpSessions.runTokens(agentPublicKey, runID), func(entry *AccessEntry) bool {
		return entry.NHPAgentPublicKey == agentPublicKey && entry.NHPRunID == runID && entry.NHPRunAttempt > 0 && entry.NHPRunAttempt < attempt
	})
}

func (a *UdpAC) closeAllNHPSessionsVerified(ctx context.Context) (int, error) {
	if a == nil || a.nhpSessions == nil {
		return 0, errors.New("NHP session index is unavailable")
	}
	return a.closeSessionControlTokensVerified(ctx, a.nhpSessions.allTokens(), func(entry *AccessEntry) bool {
		return entry.NHPSessionId != 0
	})
}
