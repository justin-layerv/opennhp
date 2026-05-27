package common

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"runtime/debug"
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// opaqueTokenBytes is the entropy budget for an access token. 32 bytes (256 bits)
// is overkill for collision resistance against any feasible attacker; it also
// preserves the 44-character base64-encoded shape that downstream consumers
// (NHP agent, qurl-service, traefik plugin) expect from the prior SHA-256
// construction.
const opaqueTokenBytes = 32

// GenerateOpaqueToken returns a base64-encoded random token suitable for use as
// an access token. The token is 32 bytes of crypto/rand entropy, base64-encoded
// to a 44-character string — wire-compatible with the previous SHA-256-derived
// tokens but not derivable from public inputs.
//
// The encoding is base64.StdEncoding (not RawURLEncoding), so the output may
// contain '+' and '/'. Callers that pass the token through a URL must
// percent-encode it; the AC's /refresh handler at endpoints/ac/httpac.go
// reverses this with url.QueryUnescape before lookup. The choice is
// load-bearing for wire compatibility — pre-1124 tokens used the same
// encoding and downstream consumers (qurl-service, traefik plugin, agent
// SDKs) already handle the percent-encoding round-trip.
//
// Panics if the OS entropy source is unavailable: an issued-but-empty or
// short-read token would be a security failure (an attacker who guesses the
// degenerate value would gain valid access), and there is no safe fallback.
func GenerateOpaqueToken() string {
	var buf [opaqueTokenBytes]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		panic("nhp: crypto/rand entropy unavailable: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(buf[:])
}

// tokenLogPrefixLen is the number of leading characters retained when
// redacting an access token for log output. 8 base64 chars carry 6 bytes
// (48 bits) of token entropy — enough to correlate log lines for the same
// session without revealing enough material to brute-force the remaining
// 26 bytes.
const tokenLogPrefixLen = 8

// AccessTokenLatePacketBufferSeconds is the shared late-packet buffer
// applied to AC-side AccessEntry retention and to server-side
// ACK-path ACTokenEntry retention. Both the AC's iptables/ipset
// pinhole and the server tokenStore must outlive the agent's open
// window long enough for a delayed packet/validate request to
// resolve while the AC would still accept the corresponding traffic.
//
// Single source of truth so the AC and server cannot drift: a future
// edit that bumps one side without the other is caught by the
// constant-pin tests in endpoints/ac/tokenstore_test.go and
// endpoints/server/tokenstore_test.go, both of which assert against
// this symbol. See endpoints/ac/tokenstore.go's GenerateAccessToken
// and endpoints/server/tokenstore.go's NewACKTokenEntry for the two
// call sites that consume it.
//
// Server-issued tokens (GenerateAccessToken on the server side) keep
// strict OpenTime retention because the server is the issuer, not
// the iptables/ipset enforcement point — the buffer asymmetry is
// about packet-arrival timing, not about who's allowed to verify.
const AccessTokenLatePacketBufferSeconds = 5

// RedactToken returns a log-safe representation of an access token: the
// first tokenLogPrefixLen characters followed by an ellipsis. Tokens of
// length tokenLogPrefixLen or less are returned unchanged with no
// ellipsis — they cannot be valid access tokens and will fail the
// wire-shape check downstream regardless.
//
// After nhp#1124 the access token IS the auth secret (no longer a hash
// of public inputs), so any log line that includes one must call this
// helper before formatting.
func RedactToken(token string) string {
	if len(token) <= tokenLogPrefixLen {
		return token
	}
	return token[:tokenLogPrefixLen] + "..."
}

// TokenEntry is an interface for token entries that have an expiration time.
// Both AccessEntry (AC) and ACTokenEntry (Server) implement this interface.
type TokenEntry interface {
	GetExpireTime() time.Time
}

// TokenStore is a generic two-level map for efficient token storage.
// The first level is indexed by the first character of the token for fast lookup.
// This design distributes tokens across ~64 buckets (base64 characters).
type TokenStore[E TokenEntry] struct {
	mu       sync.RWMutex
	store    map[string]map[string]E
	onExpire func(token string, entry E)
}

// NewTokenStore creates a new TokenStore instance.
func NewTokenStore[E TokenEntry]() *TokenStore[E] {
	return &TokenStore[E]{
		store: make(map[string]map[string]E),
	}
}

// SetOnExpire registers a callback fired for each entry CleanExpired
// removes. Pass nil to disable (default).
//
// Scope: only CleanExpired fires the hook. Delete does NOT — a
// future explicit-revoke caller that wants the same cleanup must
// invoke the hook itself or extend Delete.
//
// Lifecycle: CleanExpired captures the registered hook under
// ts.mu at the start of its run and uses that capture for the
// whole batch; SetOnExpire calls during an in-flight CleanExpired
// block on ts.mu, then return — but the captured pending entries
// still fire stale callbacks outside the lock. Callers needing
// strict cessation must coordinate via their own quiesce signal.
// Designed for once-at-startup registration, not hot-path swaps.
//
// The hook receives the entry pointer as captured at snapshot
// time. AccessEntry is effectively post-store immutable today; a
// future caller that mutates entries post-store must synchronize
// reads against those mutations.
//
// Hook panics are recovered per-entry (logged with a stack trace)
// so a single bad token does not abort the batch. Token-safety
// in the recovery log depends on two hook-author requirements:
//
//   - Don't close over token / session-secret values. The stack
//     trace prints function args as word-sized hex (for string
//     args: pointer + length, never dereferenced contents), so
//     the passed-in `token` arg is safe — but captured variables
//     read by the closure can show up in unredacted form.
//   - Don't panic with token / session-secret values. The
//     panic value is logged via %v; only the `token` arg is
//     RedactToken-wrapped.
func (ts *TokenStore[E]) SetOnExpire(fn func(token string, entry E)) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.onExpire = fn
}

// Store adds or updates a token entry in the store.
// Empty tokens are silently ignored.
func (ts *TokenStore[E]) Store(token string, entry E) {
	if len(token) == 0 {
		return
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	prefix := token[0:1]
	tokenMap, found := ts.store[prefix]
	if found {
		tokenMap[token] = entry
	} else {
		tokenMap = make(map[string]E)
		tokenMap[token] = entry
		ts.store[prefix] = tokenMap
	}
}

// Load retrieves a token entry from the store.
// Returns the entry and true if found, or zero value and false if not found.
// Empty tokens always return not found.
func (ts *TokenStore[E]) Load(token string) (E, bool) {
	if len(token) == 0 {
		var zero E
		return zero, false
	}

	ts.mu.RLock()
	defer ts.mu.RUnlock()

	prefix := token[0:1]
	tokenMap, found := ts.store[prefix]
	if found {
		entry, ok := tokenMap[token]
		if ok {
			return entry, true
		}
	}
	var zero E
	return zero, false
}

// Delete removes a token from the store.
// Empty tokens are silently ignored.
func (ts *TokenStore[E]) Delete(token string) {
	if len(token) == 0 {
		return
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	prefix := token[0:1]
	if tokenMap, found := ts.store[prefix]; found {
		delete(tokenMap, token)
		if len(tokenMap) == 0 {
			delete(ts.store, prefix)
		}
	}
}

// CleanExpired removes all expired tokens from the store and
// returns the number removed.
//
// If an OnExpire hook is registered, expired (token, entry) pairs
// are collected under the write lock and the hook is invoked AFTER
// the lock is released, so the hook may take other locks freely
// (the AC scheduler's shard locks, in production). Panicking hooks
// are recovered per-entry so a single bad token does not abort the
// batch or the background goroutine driving this call (see
// RunRefreshRoutine).
func (ts *TokenStore[E]) CleanExpired() int {
	type expiredPair struct {
		token string
		entry E
	}
	var (
		pending  []expiredPair
		onExpire func(string, E)
		removed  int
	)

	func() {
		ts.mu.Lock()
		defer ts.mu.Unlock()

		onExpire = ts.onExpire
		now := time.Now()

		for prefix, tokenMap := range ts.store {
			for token, entry := range tokenMap {
				if now.After(entry.GetExpireTime()) {
					if onExpire != nil {
						pending = append(pending, expiredPair{token, entry})
					}
					log.Info("[TokenStore] token %s expired, remove", RedactToken(token))
					delete(tokenMap, token)
					removed++
				}
			}
			if len(tokenMap) == 0 {
				delete(ts.store, prefix)
			}
		}
	}()

	for _, p := range pending {
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Stack trace: runtime.Stack prints args as
					// word-sized hex (for string args: pointer +
					// length, never dereferenced contents), so
					// the token bytes themselves don't appear in
					// the trace — only the redacted-arg log
					// prefix is sensitive. The %v on r reflects
					// whatever the hook panicked with; see
					// SetOnExpire godoc for the hook-must-not-
					// panic-with-token-material requirement.
					log.Error("[TokenStore] OnExpire hook panicked for token %s: %v\n%s",
						RedactToken(p.token), r, debug.Stack())
				}
			}()
			onExpire(p.token, p.entry)
		}()
	}
	return removed
}

// RunRefreshRoutine starts a background goroutine that periodically cleans
// expired tokens. It stops when the stop channel is closed.
// The wg.Done() is called when the routine exits.
func (ts *TokenStore[E]) RunRefreshRoutine(wg *sync.WaitGroup, stop <-chan struct{}, intervalSeconds int) {
	defer wg.Done()
	defer log.Info("tokenStoreRefreshRoutine stopped")

	log.Info("tokenStoreRefreshRoutine started")

	for {
		select {
		case <-stop:
			return
		case <-time.After(time.Duration(intervalSeconds) * time.Second):
			ts.CleanExpired()
		}
	}
}

// Size returns the total number of tokens in the store.
func (ts *TokenStore[E]) Size() int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	count := 0
	for _, tokenMap := range ts.store {
		count += len(tokenMap)
	}
	return count
}
