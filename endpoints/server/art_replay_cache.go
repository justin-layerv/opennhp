package server

import (
	"encoding/base64"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/OpenNHP/opennhp/nhp/core"
)

// ART TransactionId dedupe (#1457) — the symmetric server-side
// counterpart of the AC's NHP_AOP dedupe (#1123,
// endpoints/ac/aop_replay_cache.go).
//
// Threat — a captured NHP_ART (the AC's AEAD-authenticated response to
// a server NHP_AOP: ErrCode, OpenTime, and a possible PreAccessAction
// carrying an ACToken) can be replayed against the server. If it
// reaches processACOperation correlated to an in-flight transaction it
// feeds a STALE access result into a live knock flow — at worst handing
// one agent's knock the access decision/token minted for a different
// (src, dst, user). Within the default 600 s staleness floor a verbatim
// resend is cryptographically valid, so the "NHP messages are not
// replayable" invariant must hold here too.
//
// Existing defense and its gap — the server forks ART by TransactionId
// BEFORE decryption (recvPacketRoutine → FindLocalTransaction): a replay
// with no matching in-flight transaction is dropped at that correlation
// layer. That defense is real but (a) lives in the transaction layer,
// not at the cryptographic gate, so a correlation-path regression
// re-exposes the surface, and (b) the per-connection LastRemoteSendTime
// replay gate in core.responder (shouldCheckRecvAttack, which ART is
// subject to after #1457) resets on a fresh connection (server restart /
// AC failover / NAT-table flush) and uses strict less-than, so it misses
// both a same-timestamp in-connection resend and any cross-connection
// replay. This cache closes that gap by remembering recently observed
// (sender_pubkey, txid, send_time) triples keyed on the
// AEAD-authenticated values core.responder.validatePeer surfaces. It is
// invoked at the single post-validation chokepoint (packetToMsgRoutine
// via the Device recvReplayDedupe hook) so every ART — matched original
// and unmatched replay alike — is recorded there; recording the matched
// originals is exactly what lets a later replay be recognized (a
// consumer-only check, e.g. in processACOperation, would never see the
// original and so could not).
//
// Coverage limit (restart gap) — the cache is in-process, so a server
// restart resets it. A captured ART whose timestamp is still inside the
// staleness floor can replay successfully against a freshly-started
// server: responder gate and cache both empty. The staleness floor is
// the only gate that survives the wipe; ART uses the 600 s default
// (recvStalenessFloor in nhp/core/responder.go does NOT tighten ART the
// way #1464 tightened AOP to 120 s). Tightening the ART floor, or a
// persisted/shared dedupe set, would shrink this window and is a
// possible future hardening if the threat model escalates; it is out of
// scope for #1457, which mirrors #1461's two-layer (responder gate +
// in-process cache) shape.
//
// Operational note — every blue/green color flip on sandbox and canary
// instance roll on prod creates a fresh-cache server, so deploy cadence
// bounds this exposure window; oncall reading "we are protected" after
// an incident should attach the same deploy-window asterisk the AOP
// cache carries.
//
// CPU-amplification note — MarkSeen runs after the responder has
// AEAD-decrypted and authenticated the timestamp (it must, to trust the
// key), so an attacker replaying captured ARTs forces decrypt work for
// packets then dropped silently. The cross-connection threat this cache
// addresses sidesteps the per-connection responder gates by definition;
// at human-paced knock cadence the cost is immaterial, and any attacker
// who can AEAD-authenticate against the fresh-connection chain hash is
// already an authenticated compromise.
//
// Key — (peerPubkey, txid, sendTime):
//
//   - SendTime scoping is REQUIRED. The server's TransactionId comes
//     from `s.device.NextCounterIndex()` (atomic.AddUint64 over an
//     in-memory counter) which resets to zero on process restart, so
//     after a restart (or instance refresh) the first ~K post-restart
//     transactions reuse low txids a captured pre-restart ART can
//     collide with. Keying on the AEAD-authenticated AC send timestamp
//     in addition to (pubkey, txid) distinguishes a verbatim replay
//     (byte-identical timestamp — the timestamp is AEAD plaintext, so any
//     tweak fails verification in validatePeer before MarkSeen) from a
//     fresh transaction (fresh wall-clock timestamp). Replays still
//     collide on the full triple; legitimate traffic does not.
//
//   - Pubkey scoping is NOT strictly required on the server (it is on the
//     AC, whose txid space is shared across the servers it connects to
//     and can legitimately repeat). The server's NextCounterIndex is a
//     single global counter, so within one process lifetime each txid
//     maps to exactly one AOP→AC transaction and thus one AC pubkey; the
//     cache is wiped on the restart that resets the counter, so no
//     cross-restart pubkey collision is observable either. Pubkey is
//     included anyway: it ties the dedupe key to the authenticated
//     sender, fails safe if the txid-uniqueness invariant ever regresses,
//     and keeps the key shape identical to the AC cache so #1459 can lift
//     one implementation into nhp/core. The pubkey is AEAD-authenticated
//     by validatePeer.
//
// Legitimate AOP retries get a fresh txid via NextCounterIndex (each AOP
// is constructed with a new TransactionId — see processACOperation in
// udpserver.go), so the AC's ART for a retry carries a fresh txid and
// the cache never false-rejects a retry; only a byte-for-byte replay of
// the original ART collides on the full triple.
//
// Recorded-before-decrypt — the dedupe hook runs after validatePeer but
// BEFORE decryptBody (so a recognized replay costs no body decrypt), so a
// packet that authenticates yet then fails decryptBody is still recorded
// as seen. Harmless: the keyed fields (pubkey, txid, sendTime) are all
// AEAD-authenticated by validatePeer before MarkSeen, and a legitimate
// retry carries a fresh txid, so recording a decrypt-failing packet can
// never false-reject legitimate traffic.
//
// Key construction relies on the same fixed-pubkey-length invariant the
// AC cache documents: today every ppd.RemotePubKey is 32 bytes
// (core.PublicKeySize), so the ':' separators between the pubkey, the
// decimal txid, and the decimal sendTime are unambiguous. The MarkSeen
// length guard fails closed if a future cipher scheme lights up 64-byte
// pubkeys without revisiting this. #1459/#1460 track lifting the cache to
// nhp/core and moving to a fixed-size byte-array key.
//
// TTL must cover the upstream ART staleness floor
// (DefaultRecvStalenessFloorSeconds = 600 s in nhp/core/constants.go),
// else a captured ART aged between the TTL and the floor slips both
// gates: responder accepts it (not yet stale) and the cache has forgotten
// it. 11 min = 660 s covers 600 s with exactly ~60 s of one-direction
// clock-skew headroom. Note this margin is intentionally THIN — it is the
// 660 s TTL minus the 600 s floor, so the "TTL covers floor" invariant
// holds only while host skew stays inside ~60 s (NTP-aligned hosts do, by
// orders of magnitude). It is far tighter than the post-#1464 AOP cache,
// where the 120 s floor leaves the same 660 s TTL ~540 s of slack; ART
// keeps the 600 s floor (untightened — see art-floor note above), so 660 s
// is the floor here, not a comfortable over-cover. Raising the ART floor
// or the TTL would both widen it if the skew budget ever proves tight.
//
// Size (10 000 entries) — at 660 s TTL the steady-state sustained ART
// rate before the LRU evicts a live entry is 10_000 / 660 ≈ 15 ART/sec.
// Real fleet load is human-paced knock cadence (single-digit/sec), so
// the cap leaves >5× headroom for fan-in growth before resizing. An
// attacker cannot inflate the cache without first presenting an ART that
// HMAC-checks and AEAD-decrypts, so a pre-validation flood does not
// stress this budget. The duplicate-drop counter is
// MetricARTReplayDetected; an eviction counter (parity with #1458, the
// AOP eviction-metric item) is the next observability step.
//
// Lifecycle — expirable.LRU v2.0.7 has no Close()/Stop() hook for its
// TTL-sweep goroutine. In production the cache lives for the server
// process lifetime so this is a non-issue; the same constraint is
// documented on precheck_threat_cache.go and the AC cache.
const (
	artReplayCacheSize = 10_000
	artReplayCacheTTL  = 11 * time.Minute
)

// artReplayCache is a bounded, TTL-expiring set of recently observed
// (sender_pubkey, txid, send_time) triples.
//
// The dedupe hook runs inside packetToMsgRoutine, which core.Device.Start
// spawns as `cpus` concurrent workers, so MarkSeen must be safe under
// concurrent invocation. expirable.LRU is internally thread-safe, but
// the natural Get-then-Add idiom has a TOCTOU window where two replays
// of the same packet both observe "not seen" and both pass; the mutex
// closes that. (precheck_threat_cache.go can omit this mutex because its
// single caller is one goroutine; this one cannot.)
type artReplayCache struct {
	mu  sync.Mutex
	lru *expirable.LRU[string, struct{}]
}

func newARTReplayCache() *artReplayCache {
	return newARTReplayCacheWithParams(artReplayCacheSize, artReplayCacheTTL)
}

// newARTReplayCacheWithParams builds a cache with caller-supplied size
// and TTL. Production wires the constants via newARTReplayCache; tests
// pass short values so TTL-eviction paths run without minute-scale
// waits.
func newARTReplayCacheWithParams(size int, ttl time.Duration) *artReplayCache {
	return &artReplayCache{
		lru: expirable.NewLRU[string, struct{}](size, nil, ttl),
	}
}

// MarkSeen records the (peerPubkey, txid, sendTime) triple and returns
// true on first observation, false if it is already cached.
//
// Caller contract — peerPubkey and sendTime must be the
// AEAD-authenticated values from PacketParserData (ppd.RemotePubKey and
// ppd.RemoteSendTime); txid is ppd.SenderTrxId. The handler-level length
// guard in dedupeRecvART is the canonical place to reject an
// upstream-invariant violation (validatePeer should always populate
// RemotePubKey); the len != core.PublicKeySize guard here is fail-closed
// insurance so a caller that skips the handler guard cannot key every
// wrong-length ART under the same ":<txid>:<ts>" slot. It also enforces
// the fixed-pubkey-length invariant the key-construction docstring
// relies on.
//
// Contract caveat — a wrong-length pubkey returns false, the SAME value
// as a genuine duplicate. Callers MUST length-validate BEFORE calling
// MarkSeen (as dedupeRecvART does, returning the distinct
// ErrServerMissingPeerPubkey) so an upstream-invariant violation is not
// misclassified as a replay. When #1459 lifts this into nhp/core, keep
// that caller-side guard — or give MarkSeen a distinct invalid-input
// signal — so the lift does not silently fold "bad pubkey" into the
// duplicate metric/error.
func (c *artReplayCache) MarkSeen(peerPubkey []byte, txid uint64, sendTime int64) bool {
	if len(peerPubkey) != core.PublicKeySize {
		return false
	}

	key := artReplayKey(peerPubkey, txid, sendTime)

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.lru.Get(key); exists {
		return false
	}
	c.lru.Add(key, struct{}{})
	return true
}

// Len is the current entry count, exposed for tests. Takes the same
// mutex as MarkSeen so a Len() call never observes the cache between
// MarkSeen's Get and Add — needed for deterministic Len()==cap
// assertions ordered after a MarkSeen from the same goroutine.
func (c *artReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// artReplayKey concatenates pubkey bytes, the decimal txid, and the
// decimal sendTime with ':' separators. The fixed 32-byte pubkey plus
// digits-only txid and signed-decimal sendTime keep the separators
// unambiguous. #1460 tracks a zero-alloc fixed-size byte-array key;
// unneeded at current ART cadence.
func artReplayKey(peerPubkey []byte, txid uint64, sendTime int64) string {
	return string(peerPubkey) + ":" + strconv.FormatUint(txid, 10) + ":" + strconv.FormatInt(sendTime, 10)
}

// pubkeyFingerprint returns a short, log-friendly representation of a
// public key for breadcrumb correlation. It RawURL-base64-encodes the key
// — URL-safe (-, _) so log indexers that treat '/' as a path separator
// (Loki, CloudWatch Insights) don't fragment it — and delegates the
// truncate-to-a-readable-budget half to the package-standard
// pubkeyLogPrefix. Empty input returns "empty" so a missing-pubkey
// breadcrumb stays grep-able. (The AC's sibling cache inlines the same
// truncation; #1459's lift to nhp/core should reconcile the one helper
// against pubkeyLogPrefix.)
func pubkeyFingerprint(peerPubkey []byte) string {
	if len(peerPubkey) == 0 {
		return "empty"
	}
	return pubkeyLogPrefix(base64.RawURLEncoding.EncodeToString(peerPubkey))
}
