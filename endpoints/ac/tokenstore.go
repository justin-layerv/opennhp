package ac

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// accessTokenLatePacketBufferSeconds extends AC token retention beyond
// AccessEntry.OpenTime to handle requests that arrive after the AC has
// already torn down the iptables/ipset entry but before the client knows
// to re-knock.
//
// The value lives in nhp/common so the AC and server cannot drift —
// see common.AccessTokenLatePacketBufferSeconds for the full rationale
// (including the asymmetry: server-issued tokens keep strict OpenTime
// retention, while ACK-path entries on the server side DO extend by
// the same buffer so a delayed /nhp/internal/token/validate request
// still resolves while the AC would still accept a packet).
const accessTokenLatePacketBufferSeconds = common.AccessTokenLatePacketBufferSeconds

// AccessEntry represents an access token entry. FirstKnockTime anchors
// the absolute-deadline cap (#1942). The `json:"-"` tag is a STRUCTURAL
// fence only — it blocks a future serialization path from exposing the
// raw field as a top-level JSON key. It does NOT close the timing-leak
// angle: post-first-refresh `ExpireTime == FirstKnockTime + OpenTime +
// buffer` exactly, so `FirstKnockTime` is recoverable to nanosecond
// precision from the JSON shape regardless of the tag. Response-shape
// mitigation (slim DTO that drops ExpireTime + User + SrcAddrs) is
// tracked in #1959.
//
// scheduledKeys tracks the L3-flush scheduler FlowKeys this entry has
// scheduled and the latest deadline submitted for each key. It is populated
// before Scheduler.Schedule so sibling cleanup can preserve the exact deadline
// even in the record-before-schedule admission window.
// cancelAllScheduledFlows walks its keys directly instead of recomputing them
// from SrcAddrs × DstAddrs ×
// proto-variants — closes #2201 (multi-session races on shared
// FlowKeys) and #2205 (NAT'd temp-access where kernel-observed IP
// differs from AOL-declared IP) by making Cancel walk exactly what
// was Scheduled.
//
// Lock order: mu is leaf-most. Never hold it while taking
// tokenStore.mu or any scheduler lock (shard.mu / wheelMu /
// breakerErrMu). The OnExpire hook captures the entry pointer
// under tokenStore.mu, releases that lock, and only then takes mu
// to read scheduledKeys — see SetOnExpire godoc in
// nhp/common/tokenstore.go. The full lock-order discipline is
// documented in endpoints/ac/CLAUDE.md ("AccessEntry.mu is
// leaf-most" bullet).
//
// Pointer-identity invariant (load-bearing for
// latestOtherFirewallDeadline's self-skip): each *AccessEntry is
// stored under exactly ONE token in tokenStore for the duration of
// its admission. HandleUdpACOperations allocates a fresh
// &AccessEntry{} per admission and never reuses pointers across
// tokens. udpac.go's latestOtherFirewallDeadline relies on this to
// distinguish self from peers via pointer equality (`other ==
// self`); a future change that pools / reuses *AccessEntry pointers
// (object-pool optimization, connection-pool style entry reuse)
// would let `self` appear multiple times in tokenStore snapshots,
// each non-self copy falsely registering as an "other holder" of
// the entry's tracked FlowKeys — keeping scheduler entries alive
// past their genuine firewall deadlines (a silent security
// regression, not a panic). #2214 fences this at CI under
// `-tags=nhp_debug`: common.TokenStore.Store panics if the same
// pointer is stored under a second token (see
// nhp/common/tokenstore_debug_on.go + the AccessEntry-typed
// positive test in tokenstore_debug_test.go). Production builds
// pay zero overhead. #2215 tracks a stronger synthetic-entryID
// alternative; the two are non-exclusive.
//
// Test-author note: tests that legitimately re-key the same
// *AccessEntry under a new token (e.g. a token-rotation harness)
// must call tokenStore.Delete(oldToken) BEFORE
// tokenStore.Store(newToken, entry). Without the Delete, the
// nhp_debug-build fence will trip; production builds will accept
// the re-Store and silently break the pointer-identity invariant.
// Either way the test would be exercising a state production
// code never produces.
type AccessEntry struct {
	User           *common.AgentUser
	SrcAddrs       []*common.NetAddress
	DstAddrs       []*common.NetAddress
	OpenTime       int
	FirstKnockTime time.Time `json:"-"`
	// ExpireTime is the AC-authoritative firewall/pinhole expiry the timer wheel
	// schedules teardown against. Distinct from the qURL v2 Deadline field below
	// (the signed-claim exp, advisory revocation metadata): ExpireTime is what
	// the AC enforces; Deadline is carried for P4b indexing and is not an
	// enforcement input until a later slice wires it.
	ExpireTime time.Time
	// NHPSessionId is the non-zero server-assigned base NHP session carried
	// through AOP/ART/ACK. It is not the qURL application QurlSessionId. The AC
	// indexes this value so an opnTime=0 AOP can tear down exactly the sessions
	// selected by a bodyless, authenticated NHP_EXT.
	NHPSessionId uint64 `json:"-"`
	// NHPServerPublicKey is the canonical base64 Noise public key of the server
	// that authenticated and sent the AOP. The base numeric identifier is scoped
	// to this key so two servers independently choosing the same uint64 cannot
	// close each other's AC entries.
	NHPServerPublicKey string `json:"-"`
	// NHPSessionOwnerId is the canonical per-process boot identity authenticated
	// inside AOP/ART. Fleet members share the server Noise key, so this is the
	// collision-isolation scope for the numeric session ID.
	NHPSessionOwnerId string `json:"-"`
	// NHPAgentPublicKey is the canonical authenticated NHP-Agent public key from
	// the AOP Public Key field. Session teardown indexes use it instead of UserId
	// or source address, neither of which is a cryptographic agent identity.
	NHPAgentPublicKey string `json:"-"`
	// NHPSessionIssuedAtMillis is the immutable server issuance time used to
	// distinguish an exact logical session across delayed forwarding and retry.
	NHPSessionIssuedAtMillis int64 `json:"-"`
	// NHPRunID is the registered Connector's immutable knock/Login cycle ID.
	// Repeating the same agent+RunID replaces a pre-ACK orphan; a fresh MBB cycle
	// has a fresh RunID and remains a sibling.
	NHPRunID      string `json:"-"`
	NHPRunAttempt uint64 `json:"-"`
	// sessionControlClosing is set before verified session-control teardown
	// starts. The token and indexes remain present until every tracked kernel
	// rule has been synchronously removed, so a retry can resume real work after
	// a transient flusher error; token validation must nevertheless fail closed
	// as soon as teardown begins.
	sessionControlClosing atomic.Bool `json:"-"`

	// qURL v2 keyed-identity revocation metadata (P4a), carried verbatim from
	// the NHP-AOP (common.ServerACOpsMsg) onto the entry at admission. P4a only
	// stores these; the secondary indexes that key off them for immediate,
	// targeted revocation (qurl_user_public_key_hash / resource_public_key_hash /
	// session_id -> flow keys) are built in P4b. They are stored EXACTLY as
	// received from the AOP and are NOT recomputed on the AC side: the hashes are
	// produced once by the canonical server-side hasher
	// (qurlv2.PublicKeyHashFromB64), and re-hashing here would risk a divergent
	// digest that P4b's index match could never reconcile against the revoke
	// event's hash. Empty for legacy / non-qURL-v2 admissions, where the AOP
	// omits them (omitempty). See docs/design/QURL_V2_KEYED_IDENTITY.md ->
	// "AC Admission and Immediate Revocation".
	//
	// json:"-" on all six: httpac.go's /refresh handler returns the whole
	// AccessEntry via c.JSON, and these are internal revocation-index metadata
	// with no client consumer (the AC reads them in-process for P4b indexing).
	// Without the tag, untagged fields would emit on EVERY /refresh response —
	// including legacy entries, as present-but-zero PascalCase keys — re-opening
	// exactly the wire-shape leak that the FirstKnockTime json:"-" and the
	// OwnerId omitempty tags exist to prevent, and exposing per-admission
	// metadata to the refreshing client. If a future persistence path needs
	// these, switch to named ,omitempty tags rather than dropping json:"-".
	QurlUserPublicKeyHash string `json:"-"`
	ResourcePublicKeyHash string `json:"-"`
	QurlSessionId         string `json:"-"`
	AdmissionId           string `json:"-"`
	RevocationEpoch       uint64 `json:"-"`
	// Deadline is the signed-claim exp (unix seconds) carried from admission for
	// P4b — NOT the AC's firewall expiry. ExpireTime (above) is what the timer
	// wheel enforces; a future slice that gates on Deadline must reconcile the two
	// (they can differ: ExpireTime is clamped to the AC pinhole open-time, Deadline
	// is the claim's validity horizon).
	Deadline int64 `json:"-"`

	// mu is RWMutex so holdsScheduledKey (pure read, called from
	// latestOtherFirewallDeadline's per-peer loop) doesn't serialize
	// peer checks across cancels on different entries that share
	// peers. recordScheduledKey + drainScheduledKeys take the write
	// lock (Lock/Unlock); holdsScheduledKey takes RLock/RUnlock.
	mu            sync.RWMutex          `json:"-"`
	scheduledKeys map[FlowKey]time.Time `json:"-"`
}

// inheritNHPSessionMetadata copies the immutable base-session identity used by
// exact, agent, run, and all-session selection. PASS_PRE_ACCESS_IP creates
// short-lived and derived AccessEntries for one logical parent session; those
// records must remain in the same cleanup domain as the parent.
func inheritNHPSessionMetadata(dst, parent *AccessEntry) {
	if dst == nil || parent == nil {
		return
	}
	dst.NHPSessionId = parent.NHPSessionId
	dst.NHPServerPublicKey = parent.NHPServerPublicKey
	dst.NHPSessionOwnerId = parent.NHPSessionOwnerId
	dst.NHPAgentPublicKey = parent.NHPAgentPublicKey
	dst.NHPSessionIssuedAtMillis = parent.NHPSessionIssuedAtMillis
	dst.NHPRunID = parent.NHPRunID
	dst.NHPRunAttempt = parent.NHPRunAttempt
}

func newTempAccessEntry(parent *AccessEntry, au *common.AgentUser, srcAddrs, dstAddrs []*common.NetAddress, openTimeSec int) *AccessEntry {
	entry := &AccessEntry{
		User:     au,
		SrcAddrs: srcAddrs,
		DstAddrs: dstAddrs,
		OpenTime: openTimeSec,
	}
	inheritNHPSessionMetadata(entry, parent)
	return entry
}

// recordScheduledKey is the membership-only test seam. It is idempotent and
// records a zero deadline; production callers use recordScheduledDeadline via
// scheduleFlushIfEnabled. Tests call this directly to stage the partial-completion state
// (record-done-but-Schedule-not-yet) that
// TestUdpAC_CancelAllScheduledFlows_RecordBeforeScheduleClosesAdmissionRace
// uses to fence the cross-entry race.
func (e *AccessEntry) recordScheduledKey(key FlowKey) {
	e.recordScheduledDeadline(key, time.Time{})
}

// recordScheduledDeadline records key and the latest exact scheduler deadline
// submitted by this entry. Tests that only need set membership use
// recordScheduledKey; production scheduling uses this method.
func (e *AccessEntry) recordScheduledDeadline(key FlowKey, deadline time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.scheduledKeys == nil {
		e.scheduledKeys = make(map[FlowKey]time.Time)
	}
	current, exists := e.scheduledKeys[key]
	if !exists || current.IsZero() || deadline.After(current) {
		e.scheduledKeys[key] = deadline
	}
}

// holdsScheduledKey reports whether the entry currently has key in its
// tracked set. Used by cancelAllScheduledFlows's multi-session check
// (#2201) to detect another live AccessEntry that needs the shared
// scheduler entry to survive.
func (e *AccessEntry) holdsScheduledKey(key FlowKey) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.scheduledKeys[key]
	return ok
}

// scheduledDeadline returns the latest exact deadline recorded for key. A zero
// deadline with ok=true denotes test-staged membership without a production
// Schedule deadline.
func (e *AccessEntry) scheduledDeadline(key FlowKey) (deadline time.Time, ok bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	deadline, ok = e.scheduledKeys[key]
	return deadline, ok
}

// drainScheduledKeys returns the tracked set as a slice and resets the
// map, atomically under e.mu. cancelAllScheduledFlows uses this to walk
// the keys outside the lock — Scheduler.Cancel takes scheduler shard
// locks and the lock-order discipline forbids holding e.mu while taking
// those. Draining also closes a re-entrant Cancel race: if a second
// OnExpire fired for the same entry pointer (it can't today, but a
// future caller might), the second drain returns empty.
func (e *AccessEntry) drainScheduledKeys() []FlowKey {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.scheduledKeys) == 0 {
		return nil
	}
	keys := make([]FlowKey, 0, len(e.scheduledKeys))
	for k := range e.scheduledKeys {
		keys = append(keys, k)
	}
	e.scheduledKeys = nil
	return keys
}

func (e *AccessEntry) snapshotScheduledKeys() []FlowKey {
	if e == nil {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	keys := make([]FlowKey, 0, len(e.scheduledKeys))
	for key := range e.scheduledKeys {
		keys = append(keys, key)
	}
	return keys
}

// GetExpireTime implements the common.TokenEntry interface.
func (e *AccessEntry) GetExpireTime() time.Time {
	return e.ExpireTime
}

// storeToken stores (token, entry) in tokenStore and adds it to the qURL v2
// revocation index (P4b). Single funnel for every admission/refresh Store so
// the index can never drift from tokenStore membership. revIndex.add is a
// no-op for legacy entries (no qURL v2 metadata) and idempotent on re-Store of
// the same pair (the /refresh re-store path). The index op runs AFTER
// tokenStore.Store has released its lock, so revIndex.mu is taken outside
// tokenStore.mu — consistent with the lock order (revIndex.mu leaf-most).
func (a *UdpAC) storeToken(token string, entry *AccessEntry) {
	a.tokenStore.Store(token, entry)
	a.revIndex.add(token, entry)
	a.nhpSessions.add(token, entry)
}

// deleteToken removes token from tokenStore and the revocation index. Single
// funnel for every explicit Delete (failure cleanup, revocation). tokenStore's
// own CleanExpired path does NOT route through here — it fires the OnExpire
// hook, which deindexes instead (see installExpiryHook). entry is the
// AccessEntry being removed, needed because the index keys off its metadata;
// callers that already hold the entry pass it to avoid a re-Load.
func (a *UdpAC) deleteToken(token string, entry *AccessEntry) {
	a.tokenStore.Delete(token)
	a.revIndex.remove(token, entry)
	a.nhpSessions.remove(token, entry)
}

// GenerateAccessToken creates a new access token for the given entry. The
// token is opaque random bytes (see common.GenerateOpaqueToken) — not a hash
// of metadata. This closes nhp#1124: the prior SHA-256-over-public-inputs
// construction was offline-grindable given any timing signal.
//
// Token retention is OpenTime + accessTokenLatePacketBufferSeconds.
func (a *UdpAC) GenerateAccessToken(entry *AccessEntry) string {
	token := common.GenerateOpaqueToken()
	now := time.Now()
	entry.FirstKnockTime = now
	entry.ExpireTime = now.Add(time.Duration(entry.OpenTime+accessTokenLatePacketBufferSeconds) * time.Second)
	a.storeToken(token, entry)
	return token
}

// absoluteTokenDeadline returns the latest moment the token may validate:
// FirstKnockTime + OpenTime + buffer. Includes the late-packet buffer.
//
// FirstKnockTime carries time.Now()'s monotonic reading; Add / time.Until
// preserve it, so NTP step-backs and wall-clock skew cannot extend the
// cap. A future change that serializes the entry through Redis / disk
// would strip the monotonic component — re-anchor on Unix epoch then.
func (e *AccessEntry) absoluteTokenDeadline() time.Time {
	return e.FirstKnockTime.Add(time.Duration(e.OpenTime+accessTokenLatePacketBufferSeconds) * time.Second)
}

// firewallDeadline returns the moment the AC firewall pinhole closes
// for this entry: FirstKnockTime + OpenTime (NO late-packet buffer).
// Single source of truth for RemainingFirewallSeconds and the multi-
// session liveness check in udpac.go's latestOtherFirewallDeadline —
// keeps the formula in one place so a future arithmetic change
// (#1942 / #1962 lineage) can't drift between callers.
//
// IMMUTABILITY: FirstKnockTime is set ONCE at GenerateAccessToken
// (the pre-store moment in HandleUdpACOperations) and never mutated
// afterward. OpenTime is set at AccessEntry construction and never
// mutated afterward. Both fields are read without holding e.mu from
// latestOtherFirewallDeadline's snapshot-iterating loop — this is
// safe ONLY because of the immutability. A future change that
// mutates either field post-store re-introduces a race here AND
// breaks the absolute-deadline-cap semantics #1942 fenced. Such a
// change must either (a) lock e.mu around the read here, or (b)
// move the mutation to BEFORE the entry is stored in tokenStore.
//
// Per-field mutability classification (post-store):
//   - FirstKnockTime, OpenTime — IMMUTABLE (load-bearing for
//     firewallDeadline correctness; see above).
//   - User, DstAddrs — effectively immutable today; no production
//     mutator exists.
//   - SrcAddrs — MUTATED in place by httpac.go's /refresh-extend
//     path when a new client IP appears mid-session (tracked in
//     #1951 as an unbounded-slice-append race). Reads on
//     entry.SrcAddrs from latestOtherFirewallDeadline's walk would
//     race against this mutator IF the walk ever accessed SrcAddrs
//     — today it doesn't (only firewallDeadline + holdsScheduledKey
//     are called). The latent risk grew with #2209 because the
//     /refresh-extend path now threads the same *AccessEntry into
//     HandleAccessControl while the entry sits in the Snapshot
//     pool. If a future cancel-path code change starts reading
//     entry.SrcAddrs, this races; #1951's fix (copy-then-append +
//     atomic pointer or e.mu protection) becomes load-bearing.
//   - ExpireTime — MUTATED by VerifyAccessToken's sliding-deadline
//     extension. Read by tokenStore.CleanExpired without locking.
//     Documented elsewhere as a benign race (torn read at most
//     removes a still-valid entry one cleanup cycle early).
//   - scheduledKeys, mu — guarded by e.mu (the whole point).
func (e *AccessEntry) firewallDeadline() time.Time {
	return e.FirstKnockTime.Add(time.Duration(e.OpenTime) * time.Second)
}

// RemainingFirewallSeconds returns seconds left until the AC firewall
// must close. 0 = deadline passed; caller must refuse to re-open
// rather than call HandleAccessControl with a no-op timeout.
//
// Edge case: a return value of CloseWindowOpenTimeSec (1) trips
// HandleAccessControl's tempset-collapse branch (msghandler.go:152-158).
// On the /refresh path that branch is reached via PASS_KNOCKIP_WITH_RANGE
// (msghandler.go:336-417), so the adjacent-IP-range tempset entries
// also collapse to a 1s window — the desired behavior at this
// remainder. Issue #1962 tracks breaking the coupling by widening
// the dead zone to (0, 2)s.
func (e *AccessEntry) RemainingFirewallSeconds() int {
	remaining := time.Until(e.firewallDeadline())
	if remaining <= 0 {
		return 0
	}
	// Truncate-toward-zero (not Round): favors earlier firewall close.
	return int(remaining.Seconds())
}

// emitOrCleanupPreMintedToken is the post-admission gate paired with
// the pre-mint-then-pre-store in HandleUdpACOperations (#2201). On
// strict ErrSuccess it writes the token to artMsg so the server can
// hand it to the agent; on any non-success ErrCode (including the
// bare-return "" case) it drains any partially-scheduled FlowKeys
// AND Deletes the pre-stored entry.
//
// The cleanup-path drain (cancelAllScheduledFlows(entry)) closes a
// real leak the naive pre-store pattern introduced: kernel-write
// failures inside HandleAccessControl can leave behind scheduler
// entries from per-tuple Schedule calls that ran BEFORE the failing
// kernel write. tokenStore.Delete alone is silent (no OnExpire), so
// the scheduler-side cleanup must be explicit. With drain, the
// scheduler entries are Canceled exactly where they were Scheduled.
// No-op for the common early-return failure paths (breaker open,
// invalid openTime, empty addrs) where no Schedule call ran.
//
// The token-emit gate uses STRICT success-code equality, not the
// more permissive common.IsSuccessErrCode, so it stays aligned with
// the server's failure-log predicate at
// endpoints/server/udpserver.go:1861. The two predicates differ on
// the empty-string case: IsSuccessErrCode treats "" as success, but
// the server-side log treats "" as failure and would still leak the
// token. Several bare-return paths in HandleAccessControl can leave
// ErrCode == "" with err != nil; those must NOT emit a token.
//
// Open thread: forward.go:387 still uses IsSuccessErrCode and so will
// build a "success" ackMsg with an empty ACToken on the same
// bare-return paths the gate suppresses. Functionally safe (the
// empty token fails httpac.go's len-check) but produces a confusing
// user-visible failure mode. Tracked for cleanup in #1422.
func (a *UdpAC) emitOrCleanupPreMintedToken(artMsg *common.ACOpsResultMsg, token string, entry *AccessEntry) {
	if artMsg.ErrCode == common.ErrSuccess.ErrorCode() {
		artMsg.ACToken = token
		return
	}
	// Cancel-before-Delete is documentation-load-bearing, not
	// correctness-load-bearing — peers are in the Snapshot either
	// way (Delete only removes self), so latestOtherFirewallDeadline
	// finds peers holding the shared FlowKey regardless of order.
	// The difference is HOW self is filtered: cancel-first relies on
	// the pointer-equality `other == self` skip; Delete-first relies
	// on self being absent from the Snapshot entirely. Both paths
	// fire the peer-reschedule correctly. Keep cancel-first so the
	// surrounding godoc on cancelAllScheduledFlows (which describes
	// self-skip-via-pointer-equality) accurately models what runs.
	// The pointer-identity invariant load-bearing here (each
	// *AccessEntry is in tokenStore under exactly one token) is
	// documented on the AccessEntry struct godoc; #2214 / #2215 file
	// stronger guards.
	//
	// DO NOT reorder Delete before cancelAllScheduledFlows. Flipping
	// the order silently changes which invariant is load-bearing
	// (Delete-induced self-absence vs pointer-equality self-skip);
	// both are correct today, but the godocs above + the
	// AccessEntry struct's "Pointer-identity invariant" paragraph
	// describe pointer-equality. A reorder would leave those
	// descriptions accurate-but-vestigial — a maintainer reading
	// either would model the wrong self-filter mechanism. Tracked
	// in cr round 21.
	a.cancelAllScheduledFlows(entry)
	// deleteToken (Delete + revIndex deindex) preserves the documented
	// cancel-first ordering above: it does NOT itself cancel, so
	// cancelAllScheduledFlows still runs first. The deindex keeps the P4b
	// revocation index from retaining a token whose entry just failed
	// admission (a no-op for legacy / non-qURL-v2 entries).
	a.deleteToken(token, entry)
}

// VerifyAccessToken validates a token and extends its expiry time if
// valid. Sliding extension is capped at absoluteTokenDeadline (#1942).
//
// Concurrent verifies write ExpireTime without a per-entry lock; the
// tokenStore mutex protects the map, not the struct fields. This is a
// genuine Go memory-model data race — `go test -race` could surface it
// — not just a logical race. It's pre-existing and unrelated to the
// #1942 cap. Lost updates are benign at the value level because every
// write is bounded by the same immutable deadline, but a future
// contributor should NOT treat the comment as a claim that the race
// is race-detector-safe. CleanExpired (nhp/common/tokenstore.go)
// reading ExpireTime concurrently is the torn-read counterpart; in
// the worst case it removes a still-valid entry one cleanup cycle
// early — acceptable because the firewall close is the actual
// security boundary, not the tokenStore retention.
func (a *UdpAC) VerifyAccessToken(token string) *AccessEntry {
	entry, found := a.tokenStore.Load(token)
	if !found || entry == nil || entry.sessionControlClosing.Load() {
		return nil
	}
	if entry.NHPSessionId != 0 {
		a.sessionControlFlushMu.Lock()
		defer a.sessionControlFlushMu.Unlock()
	}
	return a.verifyAccessTokenCurrent(token, entry)
}

// verifyAccessTokenCurrent performs the current-token check and sliding expiry
// update without acquiring sessionControlFlushMu. When it may validate an NHP
// entry, the caller must hold sessionControlFlushMu; pointer equality prevents
// VerifyAccessToken's legacy fast path from validating a replacement entry of
// another class.
func (a *UdpAC) verifyAccessTokenCurrent(token string, expected *AccessEntry) *AccessEntry {
	entry, found := a.tokenStore.Load(token)
	if !found || entry == nil || (expected != nil && entry != expected) || entry.sessionControlClosing.Load() {
		return nil
	}
	if entry.NHPSessionId != 0 && (!a.sessionAdmissionReady() || a.nhpSessions == nil ||
		!a.nhpSessions.containsExactToken(token, entry) || !a.nhpSessions.admitsSession(entry)) {
		return nil
	}
	deadline := entry.absoluteTokenDeadline()
	// Use !Before (not After) so the exact-instant t==deadline is rejected.
	// A "simplification" to After() silently widens the cap by a nanosecond;
	// TestVerifyAccessToken_AbsoluteDeadlineCap fences the cap value but
	// not this comparator choice.
	if !time.Now().Before(deadline) {
		return nil
	}
	// Slide ExpireTime forward by OpenTime, capped at the absolute deadline.
	// Under current constants (ExpireTime initialized to deadline at issue
	// time, buffer > 0) the slide ALWAYS overshoots and the clamp ALWAYS
	// fires — so this is functionally equivalent to `entry.ExpireTime =
	// deadline`. Kept as slide-then-clamp for clarity (the call site reads
	// as a sliding window that's just been capped, which matches the
	// design narrative) and to remain correct under a future constant
	// flip (e.g., buffer = 0 or ExpireTime initialized to OpenTime only).
	newExpire := entry.ExpireTime.Add(time.Duration(entry.OpenTime) * time.Second)
	if newExpire.After(deadline) {
		newExpire = deadline
	}
	entry.ExpireTime = newExpire
	// Re-store through storeToken so the revocation index stays consistent.
	// add is idempotent: the entry was already indexed at admission, so a
	// refresh re-store is a no-op on the index side (same token, same keys).
	a.storeToken(token, entry)
	return entry
}
