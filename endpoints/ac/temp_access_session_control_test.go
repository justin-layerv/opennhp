package ac

import (
	"context"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

type tempAccessSessionFlusher struct{}

func (tempAccessSessionFlusher) Flush(context.Context, FlowKey) error { return nil }

func newTempAccessSessionTestAC(t *testing.T) *UdpAC {
	t.Helper()
	scheduler := NewScheduler(tempAccessSessionFlusher{}, WithTickInterval(time.Hour))
	scheduler.Start()
	t.Cleanup(func() { shutdownOrFail(t, scheduler) })
	a := &UdpAC{
		config:      &Config{FilterMode: FilterMode_IPTABLES},
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		revIndex:    newRevocationIndex(),
		nhpSessions: newNHPSessionIndex(),
		expirySched: scheduler,
	}
	a.sessionFlushGeneration.Store(1)
	a.sessionFlushComplete.Store(true)
	a.sessionControlLeaseHeld.Store(true)
	return a
}

func tempAccessSessionEntry(agentPublicKey, runID string, sessionID uint64, issuedAtMillis int64) *AccessEntry {
	return &AccessEntry{
		OpenTime:                 60,
		NHPSessionId:             sessionID,
		NHPServerPublicKey:       "server",
		NHPSessionOwnerId:        "00112233445566778899aabbccddeeff",
		NHPAgentPublicKey:        agentPublicKey,
		NHPSessionIssuedAtMillis: issuedAtMillis,
		NHPRunID:                 runID,
		NHPRunAttempt:            1,
	}
}

func assertInheritedNHPSessionMetadata(t *testing.T, got, want *AccessEntry) {
	t.Helper()
	if got.NHPSessionId != want.NHPSessionId ||
		got.NHPServerPublicKey != want.NHPServerPublicKey ||
		got.NHPSessionOwnerId != want.NHPSessionOwnerId ||
		got.NHPAgentPublicKey != want.NHPAgentPublicKey ||
		got.NHPSessionIssuedAtMillis != want.NHPSessionIssuedAtMillis ||
		got.NHPRunID != want.NHPRunID ||
		got.NHPRunAttempt != want.NHPRunAttempt {
		t.Fatalf("NHP session metadata = %#v, want immutable tuple from %#v", got, want)
	}
}

func tokenListContains(tokens []string, want string) bool {
	for _, token := range tokens {
		if token == want {
			return true
		}
	}
	return false
}

func tokenListContainsEntry(a *UdpAC, tokens []string, want *AccessEntry) bool {
	for _, token := range tokens {
		if entry, ok := a.tokenStore.Load(token); ok && entry == want {
			return true
		}
	}
	return false
}

func TestTempAccessDelayedACCDeniedAfterCleanupDuringWait(t *testing.T) {
	const (
		agentKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		runID    = "0123456789abcdef"
	)
	tests := []struct {
		name  string
		close func(*UdpAC, *AccessEntry) (int, error)
	}{
		{
			name: "exact",
			close: func(a *UdpAC, parent *AccessEntry) (int, error) {
				return a.closeNHPExactSessionVerified(context.Background(), parent.NHPAgentPublicKey, parent.NHPSessionId, parent.NHPSessionIssuedAtMillis)
			},
		},
		{
			name: "agent",
			close: func(a *UdpAC, parent *AccessEntry) (int, error) {
				return a.closeNHPAgentSessionsThroughVerified(context.Background(), parent.NHPAgentPublicKey, parent.NHPSessionIssuedAtMillis)
			},
		},
		{
			name: "run",
			close: func(a *UdpAC, parent *AccessEntry) (int, error) {
				return a.closeNHPRunBeforeAttemptVerified(context.Background(), parent.NHPAgentPublicKey, parent.NHPRunID, 2)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newTempAccessSessionTestAC(t)
			parent := tempAccessSessionEntry(agentKey, runID, 41, 1_700_000_000_000)
			a.GenerateAccessToken(parent)
			tempEntry := newTempAccessEntry(parent, nil, nil, nil, 30)
			assertInheritedNHPSessionMetadata(t, tempEntry, parent)
			tempToken := a.GenerateAccessToken(tempEntry)

			a.sessionControlFlushMu.Lock()
			closed, err := tt.close(a, parent)
			a.sessionControlFlushMu.Unlock()
			if err != nil {
				t.Fatalf("cleanup during temporary wait: %v", err)
			}
			if closed != 2 {
				t.Fatalf("cleanup during temporary wait closed %d records, want parent + temporary", closed)
			}

			derivedWrites := 0
			if admittedParent, admitted := a.lockAdmittedTempAccessParent(tempToken); admitted {
				a.registerTempAccessFlushEntry(admittedParent, nil, nil, nil, 60)
				derivedWrites++ // models the handler's following kernel-write block
				a.sessionControlFlushMu.Unlock()
			}
			if derivedWrites != 0 {
				t.Fatalf("delayed ACC performed %d derived/kernel mutation blocks after cleanup", derivedWrites)
			}
			if got := len(a.nhpSessions.allTokens()); got != 0 {
				t.Fatalf("live session-control tokens after cleanup + delayed ACC = %d, want 0", got)
			}
			if got := a.expirySched.EntryCount(); got != 0 {
				t.Fatalf("scheduled entries after cleanup + delayed ACC = %d, want 0", got)
			}
		})
	}
}

func TestTempAccessDelayedACCSerializesBehindConcurrentCleanup(t *testing.T) {
	const (
		agentKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		runID    = "0123456789abcdef"
	)
	a := newTempAccessSessionTestAC(t)
	parent := tempAccessSessionEntry(agentKey, runID, 42, 1_700_000_000_000)
	a.GenerateAccessToken(parent)
	tempToken := a.GenerateAccessToken(newTempAccessEntry(parent, nil, nil, nil, 30))

	a.sessionControlFlushMu.Lock()
	started := make(chan struct{})
	admitted := make(chan bool, 1)
	go func() {
		close(started)
		_, ok := a.lockAdmittedTempAccessParent(tempToken)
		if ok {
			a.sessionControlFlushMu.Unlock()
		}
		admitted <- ok
	}()
	<-started
	closed, err := a.closeNHPExactSessionVerified(context.Background(), agentKey, parent.NHPSessionId, parent.NHPSessionIssuedAtMillis)
	a.sessionControlFlushMu.Unlock()
	if err != nil || closed != 2 {
		t.Fatalf("concurrent cleanup = %d, %v; want parent + temporary", closed, err)
	}
	select {
	case ok := <-admitted:
		if ok {
			t.Fatal("delayed ACC admitted after cleanup won the session-control mutex")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("delayed ACC did not resume after cleanup released the session-control mutex")
	}
}

func TestTempAccessDerivedRecordCleanupPreservesUnrelatedSibling(t *testing.T) {
	const (
		agentKey   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		otherAgent = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
		runID      = "0123456789abcdef"
		otherRun   = "fedcba9876543210"
	)
	tests := []struct {
		name       string
		sibling    func() *AccessEntry
		close      func(*UdpAC, *AccessEntry) (int, error)
		wantAgentN int
	}{
		{
			name: "exact",
			sibling: func() *AccessEntry {
				return tempAccessSessionEntry(agentKey, otherRun, 52, 1_700_000_000_001)
			},
			close: func(a *UdpAC, parent *AccessEntry) (int, error) {
				return a.closeNHPExactSessionVerified(context.Background(), parent.NHPAgentPublicKey, parent.NHPSessionId, parent.NHPSessionIssuedAtMillis)
			},
			wantAgentN: 4,
		},
		{
			name: "agent",
			sibling: func() *AccessEntry {
				return tempAccessSessionEntry(otherAgent, otherRun, 52, 1_700_000_000_001)
			},
			close: func(a *UdpAC, parent *AccessEntry) (int, error) {
				return a.closeNHPAgentSessionsThroughVerified(context.Background(), parent.NHPAgentPublicKey, parent.NHPSessionIssuedAtMillis)
			},
			wantAgentN: 3,
		},
		{
			name: "run",
			sibling: func() *AccessEntry {
				return tempAccessSessionEntry(agentKey, otherRun, 52, 1_700_000_000_001)
			},
			close: func(a *UdpAC, parent *AccessEntry) (int, error) {
				return a.closeNHPRunBeforeAttemptVerified(context.Background(), parent.NHPAgentPublicKey, parent.NHPRunID, 2)
			},
			wantAgentN: 4,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newTempAccessSessionTestAC(t)
			parent := tempAccessSessionEntry(agentKey, runID, 51, 1_700_000_000_000)
			parentToken := a.GenerateAccessToken(parent)
			tempEntry := newTempAccessEntry(parent, nil, nil, nil, 30)
			tempToken := a.GenerateAccessToken(tempEntry)

			admittedParent, admitted := a.lockAdmittedTempAccessParent(tempToken)
			if !admitted {
				t.Fatal("temporary parent was not admitted before cleanup")
			}
			derived := a.registerTempAccessFlushEntry(admittedParent, nil, nil, nil, 60)
			a.sessionControlFlushMu.Unlock()
			if derived == nil {
				t.Fatal("derived long-lived entry was not created")
			}
			assertInheritedNHPSessionMetadata(t, tempEntry, parent)
			assertInheritedNHPSessionMetadata(t, derived, parent)

			exactTokens := a.nhpSessions.exactTokens(agentKey, parent.NHPSessionId, parent.NHPSessionIssuedAtMillis)
			if len(exactTokens) != 3 || !tokenListContains(exactTokens, parentToken) ||
				!tokenListContains(exactTokens, tempToken) || !tokenListContainsEntry(a, exactTokens, derived) {
				t.Fatalf("exact selection did not contain parent, temporary, and derived records: %v", exactTokens)
			}
			if got := len(a.nhpSessions.agentTokens(agentKey)); got != 3 {
				t.Fatalf("agent selection before sibling = %d, want 3", got)
			}
			if got := len(a.nhpSessions.runTokens(agentKey, runID)); got != 3 {
				t.Fatalf("run selection = %d, want 3", got)
			}
			if got := len(a.nhpSessions.allTokens()); got != 3 {
				t.Fatalf("all selection before sibling = %d, want 3", got)
			}

			sibling := tt.sibling()
			siblingToken := a.GenerateAccessToken(sibling)
			if got := len(a.nhpSessions.agentTokens(agentKey)); got != tt.wantAgentN {
				t.Fatalf("agent selection with sibling = %d, want %d", got, tt.wantAgentN)
			}
			if got := len(a.nhpSessions.allTokens()); got != 4 {
				t.Fatalf("all selection with sibling = %d, want 4", got)
			}

			a.sessionControlFlushMu.Lock()
			closed, err := tt.close(a, parent)
			a.sessionControlFlushMu.Unlock()
			if err != nil {
				t.Fatalf("%s cleanup: %v", tt.name, err)
			}
			if closed != 3 {
				t.Fatalf("%s cleanup closed %d records, want parent + temporary + derived", tt.name, closed)
			}
			if _, ok := a.tokenStore.Load(siblingToken); !ok {
				t.Fatalf("%s cleanup removed unrelated sibling", tt.name)
			}
			if got := len(a.nhpSessions.exactTokens(agentKey, parent.NHPSessionId, parent.NHPSessionIssuedAtMillis)); got != 0 {
				t.Fatalf("%s cleanup retained %d exact parent records", tt.name, got)
			}
			if got := len(a.nhpSessions.runTokens(agentKey, runID)); got != 0 {
				t.Fatalf("%s cleanup retained %d parent-run records", tt.name, got)
			}
			if got := len(a.nhpSessions.allTokens()); got != 1 {
				t.Fatalf("%s cleanup left %d all-session records, want sibling only", tt.name, got)
			}
		})
	}
}
