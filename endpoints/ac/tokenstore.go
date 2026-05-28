package ac

import (
	"sync"
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
// successfully scheduled, populated by recordScheduledKey after a
// Scheduler.Schedule succeeds. cancelAllScheduledFlows walks this set
// directly instead of recomputing keys from SrcAddrs × DstAddrs ×
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
	ExpireTime     time.Time

	// mu is RWMutex so holdsScheduledKey (pure read, called from
	// latestOtherFirewallDeadline's per-peer loop) doesn't serialize
	// peer checks across cancels on different entries that share
	// peers. recordScheduledKey + drainScheduledKeys take the write
	// lock (Lock/Unlock); holdsScheduledKey takes RLock/RUnlock.
	mu            sync.RWMutex         `json:"-"`
	scheduledKeys map[FlowKey]struct{} `json:"-"`
}

// recordScheduledKey adds key to the entry's tracked set. Idempotent:
// re-Schedule of the same key (e.g. /refresh extension) is a no-op on
// the tracking side; the scheduler's longest-wins semantics handle the
// deadline side. Called by scheduleFlushIfEnabled BEFORE
// Scheduler.Schedule (#2201 cross-entry race fix — see
// scheduleFlushIfEnabled godoc for the rationale). On Schedule failure
// (malformed FlowKey, breaker open, shutdown), the tracked key
// remains; the next cancelAllScheduledFlows will issue Scheduler.Cancel
// for a non-existent scheduler entry, which is idempotently a no-op.
//
// Production callers go through scheduleFlushIfEnabled. Tests call
// this directly to stage the partial-completion state
// (record-done-but-Schedule-not-yet) that
// TestUdpAC_CancelAllScheduledFlows_RecordBeforeScheduleClosesAdmissionRace
// uses to fence the cross-entry race.
func (e *AccessEntry) recordScheduledKey(key FlowKey) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.scheduledKeys == nil {
		e.scheduledKeys = make(map[FlowKey]struct{})
	}
	e.scheduledKeys[key] = struct{}{}
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

// GetExpireTime implements the common.TokenEntry interface.
func (e *AccessEntry) GetExpireTime() time.Time {
	return e.ExpireTime
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
	a.tokenStore.Store(token, entry)
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
	a.tokenStore.Delete(token)
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
	if !found {
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
	a.tokenStore.Store(token, entry)
	return entry
}
