package server

import (
	"context"
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// testForwardedSessionDeps gives forwarding test doubles the same exact,
// collision-detecting reservation semantics as the production receiver.
type testForwardedSessionDeps struct {
	mu       sync.Mutex
	registry *liveNHPSessionRegistry
}

func (d *testForwardedSessionDeps) VerifyForwardedDurableNHPSession(_ context.Context,
	knkMsg *common.AgentKnockMsg,
) (common.AgentSessionReceipt, error) {
	if knkMsg == nil || knkMsg.AuthServiceId != common.RegisteredAgentAuthServiceID {
		return common.AgentSessionReceipt{}, nil
	}
	return common.AgentSessionReceipt{
		CellID: testSessionControlCellID, SessionID: knkMsg.NHPSessionId,
		SessionIssuedAtMillis: knkMsg.NHPSessionIssuedAt.UnixMilli(),
		RunID:                 knkMsg.RunID, RunAttempt: knkMsg.RunAttempt,
	}, nil
}

func (d *testForwardedSessionDeps) sessionRegistry() *liveNHPSessionRegistry {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.registry == nil {
		d.registry = newLiveNHPSessionRegistry()
	}
	return d.registry
}

func (d *testForwardedSessionDeps) ReserveForwardedNHPSession(agentPubKeyB64 string, sessionID uint64, issuedAt, expiresAt time.Time) error {
	agentPubKey, err := decodeAgentPublicKey(agentPubKeyB64)
	if err != nil {
		return errNHPSessionNotReserved
	}
	return d.sessionRegistry().reserveExact(agentPubKey, sessionID, issuedAt, expiresAt)
}

func (d *testForwardedSessionDeps) ReleaseForwardedNHPSession(agentPubKeyB64 string, sessionID uint64, issuedAt time.Time) {
	agentPubKey, err := decodeAgentPublicKey(agentPubKeyB64)
	if err != nil {
		return
	}
	d.sessionRegistry().release(agentPubKey, sessionID, issuedAt)
}

func (d *testForwardedSessionDeps) CompensateForwardedNHPSession(agentPubKeyB64 string, sessionID uint64, issuedAt time.Time) bool {
	agentPubKey, err := decodeAgentPublicKey(agentPubKeyB64)
	if err != nil {
		return false
	}
	snapshot, ok := d.sessionRegistry().snapshotExactSessionForCompensation(agentPubKey, sessionID, issuedAt)
	return !ok || d.sessionRegistry().completeExactSessionClose(agentPubKey, snapshot)
}
