package ac

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func testNHPAgentKey(fill byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(fill), common.NHPAgentPublicKeyBytes)))
}

func TestCloseNHPSessionClosesAllExactEntriesOnly(t *testing.T) {
	a := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		revIndex:    newRevocationIndex(),
		nhpSessions: newNHPSessionIndex(),
	}
	const serverKey = "server-a-key"
	const owner = "00112233445566778899aabbccddeeff"
	oneA := &AccessEntry{OpenTime: 60, NHPSessionId: 77, NHPServerPublicKey: serverKey, NHPSessionOwnerId: owner}
	oneB := &AccessEntry{OpenTime: 60, NHPSessionId: 77, NHPServerPublicKey: serverKey, NHPSessionOwnerId: owner}
	other := &AccessEntry{OpenTime: 60, NHPSessionId: 88, NHPServerPublicKey: serverKey, NHPSessionOwnerId: owner}
	tokenA := a.GenerateAccessToken(oneA)
	tokenB := a.GenerateAccessToken(oneB)
	otherToken := a.GenerateAccessToken(other)

	if got := a.CloseNHPSession(serverKey, owner, 77); got != 2 {
		t.Fatalf("CloseNHPSession count = %d, want 2", got)
	}
	for _, token := range []string{tokenA, tokenB} {
		if _, ok := a.tokenStore.Load(token); ok {
			t.Fatalf("session token %q remained live", token)
		}
	}
	if _, ok := a.tokenStore.Load(otherToken); !ok {
		t.Fatal("different session token was removed")
	}
	if got := a.CloseNHPSession(serverKey, owner, 77); got != 0 {
		t.Fatalf("duplicate close count = %d, want 0", got)
	}
}

func TestCloseNHPSessionSameKeyAndIDFromDifferentProcessIsIsolated(t *testing.T) {
	a := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		revIndex:    newRevocationIndex(),
		nhpSessions: newNHPSessionIndex(),
	}
	serverA := &AccessEntry{OpenTime: 60, NHPSessionId: 77, NHPServerPublicKey: "shared-server-key", NHPSessionOwnerId: "00112233445566778899aabbccddeeff"}
	serverB := &AccessEntry{OpenTime: 60, NHPSessionId: 77, NHPServerPublicKey: "shared-server-key", NHPSessionOwnerId: "ffeeddccbbaa99887766554433221100"}
	tokenA := a.GenerateAccessToken(serverA)
	tokenB := a.GenerateAccessToken(serverB)

	if got := a.CloseNHPSession(serverA.NHPServerPublicKey, serverA.NHPSessionOwnerId, 77); got != 1 {
		t.Fatalf("server A close count = %d, want 1", got)
	}
	if _, ok := a.tokenStore.Load(tokenA); ok {
		t.Fatal("server A session remained live")
	}
	if _, ok := a.tokenStore.Load(tokenB); !ok {
		t.Fatal("same key and numeric session from process B was cross-closed")
	}
}

func TestNHPSessionIndexNaturalExpiryRemoval(t *testing.T) {
	a := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		revIndex:    newRevocationIndex(),
		nhpSessions: newNHPSessionIndex(),
	}
	a.installExpiryHook()
	entry := &AccessEntry{OpenTime: 60, NHPSessionId: 99, NHPServerPublicKey: "server-a-key", NHPSessionOwnerId: "00112233445566778899aabbccddeeff"}
	token := a.GenerateAccessToken(entry)
	entry.ExpireTime = entry.ExpireTime.Add(-2 * entry.ExpireTime.Sub(entry.FirstKnockTime))
	if got := a.tokenStore.CleanExpired(); got != 1 {
		t.Fatalf("CleanExpired removed %d, want 1", got)
	}
	if tokens := a.nhpSessions.tokens(entry.NHPServerPublicKey, entry.NHPSessionOwnerId, 99); len(tokens) != 0 {
		t.Fatalf("expired session index tokens = %v, want empty (token %q)", tokens, token)
	}
}

func TestNHPAgentSessionCloseScopesAreIsolated(t *testing.T) {
	a := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		revIndex:    newRevocationIndex(),
		nhpSessions: newNHPSessionIndex(),
	}
	const ownerA = "00112233445566778899aabbccddeeff"
	const ownerB = "ffeeddccbbaa99887766554433221100"
	agentA := testNHPAgentKey('A')
	agentB := testNHPAgentKey('B')
	entries := map[string]*AccessEntry{
		"exact_a":              {OpenTime: 60, NHPSessionId: 77, NHPServerPublicKey: "shared", NHPSessionOwnerId: ownerA, NHPAgentPublicKey: agentA, NHPSessionIssuedAtMillis: 1000, NHPRunID: "0123456789abcdef", NHPRunAttempt: 1},
		"same_id_new_issuance": {OpenTime: 60, NHPSessionId: 77, NHPServerPublicKey: "shared", NHPSessionOwnerId: ownerB, NHPAgentPublicKey: agentA, NHPSessionIssuedAtMillis: 2000, NHPRunID: "0123456789abcdef", NHPRunAttempt: 2},
		"same_run_new_attempt": {OpenTime: 60, NHPSessionId: 88, NHPServerPublicKey: "shared", NHPSessionOwnerId: ownerB, NHPAgentPublicKey: agentA, NHPSessionIssuedAtMillis: 3000, NHPRunID: "0123456789abcdef", NHPRunAttempt: 3},
		"fresh_run":            {OpenTime: 60, NHPSessionId: 99, NHPServerPublicKey: "shared", NHPSessionOwnerId: ownerB, NHPAgentPublicKey: agentA, NHPSessionIssuedAtMillis: 1500, NHPRunID: "fedcba9876543210", NHPRunAttempt: 1},
		"other_agent":          {OpenTime: 60, NHPSessionId: 77, NHPServerPublicKey: "shared", NHPSessionOwnerId: ownerA, NHPAgentPublicKey: agentB, NHPSessionIssuedAtMillis: 1000, NHPRunID: "0123456789abcdef", NHPRunAttempt: 1},
	}
	tokens := make(map[string]string, len(entries))
	for name, entry := range entries {
		tokens[name] = a.GenerateAccessToken(entry)
	}

	if got := a.CloseNHPExactSession(agentA, 77, 1000); got != 1 {
		t.Fatalf("CloseNHPExactSession count = %d, want 1", got)
	}
	if _, ok := a.tokenStore.Load(tokens["exact_a"]); ok {
		t.Fatal("exact target remained live")
	}
	for _, name := range []string{"same_id_new_issuance", "same_run_new_attempt", "fresh_run", "other_agent"} {
		if _, ok := a.tokenStore.Load(tokens[name]); !ok {
			t.Fatalf("exact close removed sibling %q", name)
		}
	}

	if got := a.CloseNHPRunBeforeAttempt(agentA, "0123456789abcdef", 3); got != 1 {
		t.Fatalf("CloseNHPRunBeforeAttempt count = %d, want 1", got)
	}
	if _, ok := a.tokenStore.Load(tokens["same_id_new_issuance"]); ok {
		t.Fatal("older same-run attempt remained live")
	}
	if _, ok := a.tokenStore.Load(tokens["same_run_new_attempt"]); !ok {
		t.Fatal("current same-run attempt was removed")
	}
	if _, ok := a.tokenStore.Load(tokens["fresh_run"]); !ok {
		t.Fatal("fresh RunID sibling was removed")
	}

	if got := a.CloseNHPAgentSessionsThrough(agentA, 2000); got != 1 {
		t.Fatalf("CloseNHPAgentSessionsThrough count = %d, want 1", got)
	}
	if _, ok := a.tokenStore.Load(tokens["fresh_run"]); ok {
		t.Fatal("agent session at cutoff remained live")
	}
	if _, ok := a.tokenStore.Load(tokens["same_run_new_attempt"]); !ok {
		t.Fatal("post-cutoff session was removed")
	}
	if _, ok := a.tokenStore.Load(tokens["other_agent"]); !ok {
		t.Fatal("other agent was removed")
	}

	if got := a.CloseAllNHPSessions(); got != 2 {
		t.Fatalf("CloseAllNHPSessions count = %d, want 2", got)
	}
}
