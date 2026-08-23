package ac

import (
	"errors"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func sessionFenceEntry(agent string, sessionID uint64, issuedAt int64) *AccessEntry {
	return &AccessEntry{
		NHPSessionId:             sessionID,
		NHPAgentPublicKey:        agent,
		NHPSessionIssuedAtMillis: issuedAt,
	}
}

func TestNHPSessionCloseFencesRejectReorderedOpenAndPreserveSiblings(t *testing.T) {
	agentA := testNHPAgentKey('A')
	agentB := testNHPAgentKey('B')
	base := time.Unix(1_700_000_000, 0)
	now := base
	index := newNHPSessionIndex()
	index.now = func() time.Time { return now }

	if err := index.beginExactCloseFence(agentA, 77, 1000); err != nil {
		t.Fatal(err)
	}
	if err := index.commitExactCloseFence(agentA, 77, 1000); err != nil {
		t.Fatal(err)
	}
	if index.admitsSession(sessionFenceEntry(agentA, 77, 1000)) {
		t.Fatal("exact close-before-open admitted the reordered target")
	}
	for name, entry := range map[string]*AccessEntry{
		"different session":  sessionFenceEntry(agentA, 78, 1000),
		"different issuance": sessionFenceEntry(agentA, 77, 1001),
		"different agent":    sessionFenceEntry(agentB, 77, 1000),
	} {
		if !index.admitsSession(entry) {
			t.Fatalf("exact fence rejected %s sibling", name)
		}
	}

	if err := index.beginAgentCloseCutoff(agentA, 2000); err != nil {
		t.Fatal(err)
	}
	if index.admitsSession(sessionFenceEntry(agentA, 90, 2000)) {
		t.Fatal("agent cutoff admitted issuance at the cutoff")
	}
	if index.admitsSession(sessionFenceEntry(agentA, 91, 2001)) {
		t.Fatal("pending agent cutoff admitted a newer same-agent issuance")
	}
	if err := index.commitAgentCloseCutoff(agentA, 2000); err != nil {
		t.Fatal(err)
	}
	if !index.admitsSession(sessionFenceEntry(agentA, 91, 2001)) {
		t.Fatal("agent cutoff rejected post-cutoff issuance")
	}
	if !index.admitsSession(sessionFenceEntry(agentB, 90, 1000)) {
		t.Fatal("agent cutoff rejected another agent")
	}

	if got, want := nhpSessionCloseFenceTTL, 125*time.Second; got != want {
		t.Fatalf("close-fence TTL = %s, want AOP replay floor + margin %s", got, want)
	}
	now = base.Add(nhpSessionCloseFenceTTL - time.Nanosecond)
	if index.admitsSession(sessionFenceEntry(agentA, 77, 1000)) {
		t.Fatal("exact close fence expired one nanosecond before its replay boundary")
	}
	if index.admitsSession(sessionFenceEntry(agentA, 90, 2000)) {
		t.Fatal("agent close cutoff expired one nanosecond before its replay boundary")
	}
	now = base.Add(nhpSessionCloseFenceTTL)
	if !index.admitsSession(sessionFenceEntry(agentA, 77, 1000)) || !index.admitsSession(sessionFenceEntry(agentA, 90, 2000)) {
		t.Fatal("close fence continued rejecting at the exact TTL boundary")
	}
}

func TestNHPExactCloseFencePendingUntilRetryConverges(t *testing.T) {
	agent := testNHPAgentKey('A')
	otherAgent := testNHPAgentKey('B')
	base := time.Unix(1_700_000_000, 0)
	now := base
	index := newNHPSessionIndex()
	index.now = func() time.Time { return now }

	if err := index.beginExactCloseFence(agent, 77, 1000); err != nil {
		t.Fatal(err)
	}
	if err := index.beginExactCloseFence(agent, 77, 1000); err != nil {
		t.Fatalf("exact pending retry: %v", err)
	}
	now = base.Add(10 * nhpSessionCloseFenceTTL)
	if index.admitsSession(sessionFenceEntry(agent, 77, 1000)) {
		t.Fatal("failed cleanup's pending exact fence expired")
	}
	for name, entry := range map[string]*AccessEntry{
		"different session":  sessionFenceEntry(agent, 78, 1000),
		"different issuance": sessionFenceEntry(agent, 77, 1001),
		"different agent":    sessionFenceEntry(otherAgent, 77, 1000),
	} {
		if !index.admitsSession(entry) {
			t.Fatalf("pending exact fence rejected %s sibling", name)
		}
	}
	if err := index.commitExactCloseFence(agent, 77, 1000); err != nil {
		t.Fatalf("commit exact retry: %v", err)
	}
	now = now.Add(nhpSessionCloseFenceTTL)
	if !index.admitsSession(sessionFenceEntry(agent, 77, 1000)) {
		t.Fatal("converged exact fence did not expire at its replay boundary")
	}
}

func TestNHPAgentCloseCutoffPendingUntilExactRetryConverges(t *testing.T) {
	agent := testNHPAgentKey('A')
	otherAgent := testNHPAgentKey('B')
	base := time.Unix(1_700_000_000, 0)
	now := base
	index := newNHPSessionIndex()
	index.now = func() time.Time { return now }

	if err := index.beginAgentCloseCutoff(agent, 2000); err != nil {
		t.Fatal(err)
	}
	if err := index.beginAgentCloseCutoff(agent, 2000); err != nil {
		t.Fatalf("exact pending retry: %v", err)
	}
	now = base.Add(10 * nhpSessionCloseFenceTTL)
	if index.admitsSession(sessionFenceEntry(agent, 92, 3000)) {
		t.Fatal("failed cleanup's pending fence expired and admitted a newer same-agent session")
	}
	if !index.admitsSession(sessionFenceEntry(otherAgent, 92, 1000)) {
		t.Fatal("pending agent fence rejected an unrelated agent")
	}
	if err := index.commitAgentCloseCutoff(agent, 2000); err != nil {
		t.Fatalf("commit exact retry: %v", err)
	}
	if !index.admitsSession(sessionFenceEntry(agent, 92, 3000)) {
		t.Fatal("converged cutoff did not admit a newer same-agent session")
	}
	if index.admitsSession(sessionFenceEntry(agent, 93, 2000)) {
		t.Fatal("converged cutoff admitted an issuance at the cutoff")
	}
}

func TestRegisteredAgentAdmissionChecksCloseFenceUnderFlushLock(t *testing.T) {
	agent := testNHPAgentKey('A')
	const runID = "0123456789abcdef"
	index := newNHPSessionIndex()
	if err := index.beginExactCloseFence(agent, 77, 1000); err != nil {
		t.Fatal(err)
	}
	a := &UdpAC{nhpSessions: index}
	a.sessionFlushComplete.Store(true)
	a.sessionControlLeaseHeld.Store(true)
	a.sessionFlushGeneration.Store(1)
	if err := a.runAttemptBarriers().record(agent, runID, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := a.runAttemptBarriers().commit(agent, runID, 1, 1); err != nil {
		t.Fatal(err)
	}
	msg := &common.ServerACOpsMsg{
		AuthServiceId:         common.RegisteredAgentAuthServiceID,
		AgentPublicKey:        agent,
		SessionId:             77,
		SessionIssuedAtMillis: 1000,
		RunID:                 runID,
		RunAttempt:            1,
	}
	entry := sessionFenceEntry(agent, 77, 1000)
	if _, err := a.admitOpenAOPWithSessionControlFence(msg, entry, 60, &common.ACOpsResultMsg{}); !errors.Is(err, common.ErrACSessionControlNotReady) {
		t.Fatalf("reordered AOP error = %v, want session-control not ready", err)
	}
}
