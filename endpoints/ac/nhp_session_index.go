package ac

import (
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// nhpSessionIndex maps the authenticated AOP server identity plus base NHP
// numeric session identifier and immutable agent/run selectors to every live
// AC token issued for that session. Strict NHP_REV session control and the
// legacy zero-open-time AOP close both use these indexes. It is deliberately
// separate from revocationIndex: QurlSessionId is an application identity,
// while NHPSessionId is the server-assigned AOP/ART/ACK session-control
// identity.
//
// Locking: mu is leaf-most. Callers snapshot token strings and release mu
// before touching tokenStore, revIndex, AccessEntry, or the expiry scheduler.
type nhpSessionIndex struct {
	mu                       sync.Mutex
	bySession                map[nhpSessionKey]map[string]struct{}
	byExact                  map[nhpExactSessionKey]map[string]struct{}
	byAgent                  map[string]map[string]struct{}
	byRun                    map[nhpAgentRunKey]map[string]struct{}
	exactCloseFences         map[nhpExactSessionKey]nhpExactCloseFence
	agentCloseCutoffs        map[string]nhpAgentCloseCutoff
	closeFenceSaturatedUntil time.Time
	now                      func() time.Time
}

type nhpSessionKey struct {
	serverPublicKey string
	sessionOwnerID  string
	sessionID       uint64
}

type nhpExactSessionKey struct {
	agentPublicKey string
	sessionID      uint64
	issuedAtMillis int64
}

type nhpAgentRunKey struct {
	agentPublicKey string
	runID          string
}

func newNHPSessionIndex() *nhpSessionIndex {
	return &nhpSessionIndex{
		bySession:         make(map[nhpSessionKey]map[string]struct{}),
		byExact:           make(map[nhpExactSessionKey]map[string]struct{}),
		byAgent:           make(map[string]map[string]struct{}),
		byRun:             make(map[nhpAgentRunKey]map[string]struct{}),
		exactCloseFences:  make(map[nhpExactSessionKey]nhpExactCloseFence),
		agentCloseCutoffs: make(map[string]nhpAgentCloseCutoff),
		now:               time.Now,
	}
}

func addTokenToIndex[K comparable](index map[K]map[string]struct{}, key K, token string) {
	tokens := index[key]
	if tokens == nil {
		tokens = make(map[string]struct{})
		index[key] = tokens
	}
	tokens[token] = struct{}{}
}

func removeTokenFromIndex[K comparable](index map[K]map[string]struct{}, key K, token string) {
	tokens := index[key]
	delete(tokens, token)
	if len(tokens) == 0 {
		delete(index, key)
	}
}

func (i *nhpSessionIndex) add(token string, entry *AccessEntry) {
	if i == nil || token == "" || entry == nil || entry.NHPSessionId == 0 || entry.NHPServerPublicKey == "" || !common.ValidNHPSessionOwnerID(entry.NHPSessionOwnerId) {
		return
	}
	key := nhpSessionKey{serverPublicKey: entry.NHPServerPublicKey, sessionOwnerID: entry.NHPSessionOwnerId, sessionID: entry.NHPSessionId}
	i.mu.Lock()
	defer i.mu.Unlock()
	addTokenToIndex(i.bySession, key, token)
	if common.ValidNHPAgentPublicKey(entry.NHPAgentPublicKey) && entry.NHPSessionIssuedAtMillis > 0 {
		addTokenToIndex(i.byExact, nhpExactSessionKey{
			agentPublicKey: entry.NHPAgentPublicKey,
			sessionID:      entry.NHPSessionId,
			issuedAtMillis: entry.NHPSessionIssuedAtMillis,
		}, token)
		addTokenToIndex(i.byAgent, entry.NHPAgentPublicKey, token)
		if entry.NHPRunID != "" {
			addTokenToIndex(i.byRun, nhpAgentRunKey{agentPublicKey: entry.NHPAgentPublicKey, runID: entry.NHPRunID}, token)
		}
	}
}

func (i *nhpSessionIndex) remove(token string, entry *AccessEntry) {
	if i == nil || token == "" || entry == nil || entry.NHPSessionId == 0 || entry.NHPServerPublicKey == "" || !common.ValidNHPSessionOwnerID(entry.NHPSessionOwnerId) {
		return
	}
	key := nhpSessionKey{serverPublicKey: entry.NHPServerPublicKey, sessionOwnerID: entry.NHPSessionOwnerId, sessionID: entry.NHPSessionId}
	i.mu.Lock()
	defer i.mu.Unlock()
	removeTokenFromIndex(i.bySession, key, token)
	if common.ValidNHPAgentPublicKey(entry.NHPAgentPublicKey) && entry.NHPSessionIssuedAtMillis > 0 {
		removeTokenFromIndex(i.byExact, nhpExactSessionKey{
			agentPublicKey: entry.NHPAgentPublicKey,
			sessionID:      entry.NHPSessionId,
			issuedAtMillis: entry.NHPSessionIssuedAtMillis,
		}, token)
		removeTokenFromIndex(i.byAgent, entry.NHPAgentPublicKey, token)
		if entry.NHPRunID != "" {
			removeTokenFromIndex(i.byRun, nhpAgentRunKey{agentPublicKey: entry.NHPAgentPublicKey, runID: entry.NHPRunID}, token)
		}
	}
}

func (i *nhpSessionIndex) tokens(serverPublicKey, sessionOwnerID string, sessionID uint64) []string {
	if i == nil || serverPublicKey == "" || !common.ValidNHPSessionOwnerID(sessionOwnerID) || sessionID == 0 {
		return nil
	}
	key := nhpSessionKey{serverPublicKey: serverPublicKey, sessionOwnerID: sessionOwnerID, sessionID: sessionID}
	i.mu.Lock()
	defer i.mu.Unlock()
	tokens := i.bySession[key]
	out := make([]string, 0, len(tokens))
	for token := range tokens {
		out = append(out, token)
	}
	return out
}

func snapshotTokenSet(tokens map[string]struct{}) []string {
	out := make([]string, 0, len(tokens))
	for token := range tokens {
		out = append(out, token)
	}
	return out
}

func (i *nhpSessionIndex) exactTokens(agentPublicKey string, sessionID uint64, issuedAtMillis int64) []string {
	if i == nil || !common.ValidNHPAgentPublicKey(agentPublicKey) || sessionID == 0 || issuedAtMillis <= 0 {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return snapshotTokenSet(i.byExact[nhpExactSessionKey{agentPublicKey: agentPublicKey, sessionID: sessionID, issuedAtMillis: issuedAtMillis}])
}

func (i *nhpSessionIndex) containsExactToken(token string, entry *AccessEntry) bool {
	if i == nil || token == "" || entry == nil || !common.ValidNHPAgentPublicKey(entry.NHPAgentPublicKey) ||
		entry.NHPSessionId == 0 || entry.NHPSessionIssuedAtMillis <= 0 {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	_, ok := i.byExact[nhpExactSessionKey{
		agentPublicKey: entry.NHPAgentPublicKey,
		sessionID:      entry.NHPSessionId,
		issuedAtMillis: entry.NHPSessionIssuedAtMillis,
	}][token]
	return ok
}

func (i *nhpSessionIndex) agentTokens(agentPublicKey string) []string {
	if i == nil || !common.ValidNHPAgentPublicKey(agentPublicKey) {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return snapshotTokenSet(i.byAgent[agentPublicKey])
}

func (i *nhpSessionIndex) runTokens(agentPublicKey, runID string) []string {
	if i == nil || !common.ValidNHPAgentPublicKey(agentPublicKey) || common.ValidateAgentKnockRunID(runID) != nil {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return snapshotTokenSet(i.byRun[nhpAgentRunKey{agentPublicKey: agentPublicKey, runID: runID}])
}

func (i *nhpSessionIndex) allTokens() []string {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	seen := make(map[string]struct{})
	for _, tokens := range i.bySession {
		for token := range tokens {
			seen[token] = struct{}{}
		}
	}
	return snapshotTokenSet(seen)
}
