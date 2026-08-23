package ac

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	utilebpf "github.com/OpenNHP/opennhp/nhp/utils/ebpf"
)

// P4b: AC secondary revocation indexes + immediate-flush apply.
//
// This file gives the AC the ability to find the active AccessEntries that
// belong to a revoked qURL / resource / session and tear their L3 flow state
// down IMMEDIATELY, instead of waiting for the normal expiry timer wheel. It is
// the local apply half of qURL v2 immediate revocation; the network receive
// side that consumes qurl-service revocation events over the wire is P4e and
// calls ApplyRevocation through the seam exposed here.
//
// See docs/design/QURL_V2_KEYED_IDENTITY.md -> "AC Admission and Immediate
// Revocation". The qURL v2 revocation metadata the indexes key off
// (QurlUserPublicKeyHash / ResourcePublicKeyHash / SessionId / AdmissionId /
// RevocationEpoch) is carried onto each AccessEntry at admission by P4a (#2772);
// this slice only reads those fields and never recomputes them — re-hashing on
// the AC side would risk a digest that diverges from the revoke event's hash and
// could never match.
//
// Flow-granularity caveat (design "Flow granularity caveat"): the apply path
// reschedules an entry's tracked FlowKeys to fire now, reusing the existing
// scheduler/flusher. Current FlowKey is network-shaped (src/dst/port/proto) with
// no qURL/session dimension, so flushing a revoked qURL's key may also tear down
// a sibling session sharing the same tuple. That coarse OVER-flush is the
// accepted INTERIM behavior for this slice; the kernel-visible per-session
// discriminator that makes revoke surgical is P4c. This file does NOT touch
// FlowKey, the conntrack/bpf flushers, or endpoints/ac/ebpf/.

// revocationScope names the dimension a revocation event targets. The string
// values mirror qurl-service's revocation-event `scope` field (P4d,
// qurl-service #1009) so the two ends agree without a translation table.
type revocationScope string

const (
	scopeQurl     revocationScope = "qurl"
	scopeResource revocationScope = "resource"
	scopeSession  revocationScope = "session"

	// scopeAdmission is an AC-internal index dimension, NOT a qurl-service
	// revoke scope. It lets a future per-admission cancel seam target one
	// admission without an O(N) scan; qurl-service never emits it as a wire
	// scope. Kept here so the index can serve it, but ApplyRevocation callers
	// (P4e) only ever pass qurl/resource/session. Cost of stamping it now: one
	// extra single-entry byKey bucket (a small map + alloc) per live admission
	// with an AdmissionId, maintained on every store/delete for a seam with no
	// consumer until that cancel path lands. Accepted as negligible at current
	// scale; if it proves material the stamping can move to the PR that adds the
	// cancel consumer.
	scopeAdmission revocationScope = "admission"
)

const (
	// revocationWatermarkTTL bounds how long an inactive epoch watermark stays
	// resident after the AC applied a revoke for that (scope, scopeKey). It must
	// stay longer than the producer/server redelivery horizon. Today qurl-service
	// publishes revokes over a direct signed HTTP sink on a 10s detached
	// compensation context (5s per-request default), keeps only in-process
	// retry/dead-letter buffers, and documents rollback as having no persisted
	// redrive state; managed NHP fleets then retry NHP_REV to ACs for 60s before
	// age-out. This 24h default deliberately leaves wide slack over those bounded
	// paths without letting the map grow for an entire AC process lifetime. If a
	// future producer adds durable queue/DLQ redrive, its max retention must stay
	// below this TTL or this constant must move in the same rollout. This is a
	// code constant on purpose: setting it below a producer redrive horizon is a
	// correctness bug, not an operator preference.
	//
	// Scope-key reuse still relies on admitEpoch's cross-service contract below:
	// qurl-service must either deny re-admission of a revoked key or emit a
	// strictly advancing epoch for that (scope, scopeKey). The sweep only bounds
	// inactive retention; it does not weaken that contract. After a watermark is
	// pruned, a very late duplicate can be accepted cold again, but an inactive
	// key has no entries to flush, so the observable effect is a fresh ack/metric
	// rather than data-plane churn. A key that keeps getting re-admitted and
	// re-revoked with newer epochs stays retained, which represents active
	// producer input rather than stale AC-only residue.
	revocationWatermarkTTL = 24 * time.Hour
	// revocationWatermarkSweepInterval is coarse on purpose: the map is not on a
	// hot path, and pruning stale inactive watermarks does not need second-level
	// precision.
	revocationWatermarkSweepInterval = 5 * time.Minute
)

// indexKey is the composite key the secondary index is keyed by: the revocation
// scope plus the per-scope hash/id. Keeping scope in the key prevents a
// qurl-hash from colliding with a resource-hash that happens to share bytes, and
// lets one map serve all scopes. scopeKeysForEntry and admitEpoch must derive
// identical keys for the same producer scope/key; the live-watermark guard in
// sweepLastEpoch relies on that staying true as scopes evolve.
type indexKey struct {
	scope revocationScope
	key   string
}

type revocationEpochWatermark struct {
	epoch     uint64
	appliedAt time.Time
}

// scopeKeysForEntry returns the (scope, scopeKey) pairs an AccessEntry should be
// indexed under, derived from its P4a revocation metadata. Empty values are
// skipped: legacy / non-qURL-v2 admissions carry no metadata (the AOP omits it).
// SessionId is populated only on the qURL v2 steady-state authorize (re-knock)
// path — the first place a session id exists (prepare returns none); a
// freshly-admitted flow has no session index member until its first re-knock
// refreshes it under the session key. So the session index is a live seam that
// is empty for first-knock-only flows, NOT dead code.
func scopeKeysForEntry(entry *AccessEntry) []indexKey {
	if entry == nil {
		return nil
	}
	keys := make([]indexKey, 0, 4)
	if entry.QurlUserPublicKeyHash != "" {
		keys = append(keys, indexKey{scopeQurl, entry.QurlUserPublicKeyHash})
	}
	if entry.ResourcePublicKeyHash != "" {
		keys = append(keys, indexKey{scopeResource, entry.ResourcePublicKeyHash})
	}
	if entry.QurlSessionId != "" {
		keys = append(keys, indexKey{scopeSession, entry.QurlSessionId})
	}
	if entry.AdmissionId != "" {
		keys = append(keys, indexKey{scopeAdmission, entry.AdmissionId})
	}
	return keys
}

// revocationIndex maps each qURL v2 revocation key to the set of tokenStore
// tokens whose AccessEntry carries that key, plus the last revocation epoch
// applied per key. It is the reverse of the per-admission stamping P4a does:
// admission writes the hashes onto the entry, and this index lets a revoke for
// one of those hashes find every entry holding it in O(1) instead of an O(N)
// tokenStore scan.
//
// Locking: mu is leaf-most relative to tokenStore.mu and the scheduler locks —
// it is NEVER held while calling into tokenStore or the scheduler (see
// endpoints/ac/CLAUDE.md "Lock Order"). The maintenance funnels
// (storeToken/deleteToken) call tokenStore.Store/Delete FIRST (which take and
// release tokenStore.mu internally) and THEN add/remove on the index, so
// revIndex.mu is never nested inside tokenStore.mu. The OnExpire hook likewise
// runs after CleanExpired has released tokenStore.mu (see SetOnExpire godoc).
// The apply path snapshots the matching tokens under mu, RELEASES mu, and only
// then touches tokenStore / the scheduler. No call path holds two of
// {revIndex.mu, tokenStore.mu, scheduler shard/wheel mu} at once, so no
// inversion is possible.
type revocationIndex struct {
	mu sync.Mutex
	// byKey maps a (scope, scopeKey) to the set of tokens whose entry carries
	// that key. The inner map is a set; values are struct{}.
	byKey map[indexKey]map[string]struct{}
	// lastEpoch tracks the highest revocation epoch already applied per
	// (scope, scopeKey), for idempotency / ordering (mirrors P4d). An event
	// with epoch <= lastEpoch[k].epoch is a stale duplicate and is dropped.
	// admitEpoch refreshes appliedAt whenever it accepts a newer epoch, so
	// retention is measured from the latest applied revoke.
	// Retains a watermark per revoked key even after its entries are gone, but
	// only until sweepLastEpoch proves the key is inactive and the watermark has
	// outlived the upstream redelivery horizon (#2782).
	lastEpoch map[indexKey]revocationEpochWatermark
	// now is set once by newRevocationIndex. Tests may replace it before
	// concurrent use starts, but production code must not mutate it at runtime.
	now func() time.Time
}

func newRevocationIndex() *revocationIndex {
	return &revocationIndex{
		byKey:     make(map[indexKey]map[string]struct{}),
		lastEpoch: make(map[indexKey]revocationEpochWatermark),
		now:       time.Now,
	}
}

// add records token under every revocation key the entry carries. Idempotent:
// re-adding the same token under the same key is a no-op (set semantics), which
// matches a /refresh re-Store of the same (token, entry) pair.
func (ri *revocationIndex) add(token string, entry *AccessEntry) {
	if ri == nil || token == "" {
		return
	}
	keys := scopeKeysForEntry(entry)
	if len(keys) == 0 {
		return
	}
	ri.mu.Lock()
	defer ri.mu.Unlock()
	for _, k := range keys {
		set := ri.byKey[k]
		if set == nil {
			set = make(map[string]struct{})
			ri.byKey[k] = set
		}
		set[token] = struct{}{}
	}
}

// remove drops token from every revocation key the entry carries, pruning empty
// sets so the map does not grow unbounded as qURLs come and go. The lastEpoch
// watermark is intentionally NOT pruned synchronously with the set: a revoke can
// arrive after the last matching entry is gone (e.g. the session already
// expired), and the watermark must still reject a later stale-epoch duplicate.
// The background sweep reclaims inactive watermarks only after their appliedAt
// timestamp is older than revocationWatermarkTTL (#2782).
func (ri *revocationIndex) remove(token string, entry *AccessEntry) {
	if ri == nil || token == "" {
		return
	}
	keys := scopeKeysForEntry(entry)
	if len(keys) == 0 {
		return
	}
	ri.mu.Lock()
	defer ri.mu.Unlock()
	for _, k := range keys {
		set := ri.byKey[k]
		if set == nil {
			continue
		}
		delete(set, token)
		if len(set) == 0 {
			delete(ri.byKey, k)
		}
	}
}

// sweepLastEpoch prunes inactive epoch watermarks that have outlived ttl. A key
// still present in byKey is live and must keep its watermark regardless of age:
// without that guard, an ancient duplicate could flush a currently admitted
// entry after the sweep forgot the older epoch. The full O(n) scan is held under
// ri.mu because the background cadence is coarse and the TTL now bounds the map;
// split this into batches if watermark cardinality ever makes that visible.
func (ri *revocationIndex) sweepLastEpoch(ttl time.Duration) int {
	if ri == nil || ttl <= 0 {
		return 0
	}
	// ri.now is immutable after construction; tests swap it before concurrency.
	cutoff := ri.now().Add(-ttl)
	removed := 0

	ri.mu.Lock()
	defer ri.mu.Unlock()
	for k, wm := range ri.lastEpoch {
		if len(ri.byKey[k]) != 0 {
			continue
		}
		if wm.appliedAt.After(cutoff) {
			continue
		}
		delete(ri.lastEpoch, k)
		removed++
	}
	return removed
}

func (ri *revocationIndex) watermarkCount() int {
	if ri == nil {
		return 0
	}
	ri.mu.Lock()
	defer ri.mu.Unlock()
	return len(ri.lastEpoch)
}

// tokensFor returns a snapshot copy of the tokens currently indexed under
// (scope, scopeKey). The copy lets the apply path iterate without holding mu
// (so it can call tokenStore / the scheduler, which the lock order forbids while
// mu is held). nil/empty when nothing matches.
func (ri *revocationIndex) tokensFor(scope revocationScope, scopeKey string) []string {
	if ri == nil {
		return nil
	}
	ri.mu.Lock()
	defer ri.mu.Unlock()
	set := ri.byKey[indexKey{scope, scopeKey}]
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for tok := range set {
		out = append(out, tok)
	}
	return out
}

// admitEpoch records epoch as applied for (scope, scopeKey) and reports whether
// the event should be applied. It returns false (drop) when epoch is not
// strictly greater than the last applied epoch for that key, giving
// at-least-once delivery the idempotency + ordering guarantee P4d requires:
// duplicate or out-of-order (stale) events are dropped, the newest wins.
//
// The watermark is per (scope, scopeKey), matching P4d's per-(scope, scope_key)
// monotonic counter. This is a faithful mirror of the P4d contract
// (QURL_V2_KEYED_IDENTITY.md "revocation_epoch": initial value 0, apply only on
// strictly-greater) — deliberately NOT an epoch-0 special case, which would
// diverge from that contract and could let a stale epoch-0 straggler re-fire and
// over-flush a newer legitimate session. The first observation of a key has no
// prior watermark and is always applied; thereafter only a strictly greater
// epoch is applied. This also gives correct dedup in the pre-epoch world —
// before qurl-service #1010 emits real per-(scope,scope_key) epochs end-to-end —
// where every revoke shares epoch 0: the first epoch-0 event applies (unseen), a
// second epoch-0 event for the same key is dropped (seen && 0 <= 0).
//
// Cross-service precondition (the local primitive cannot enforce it). The cost
// of the above is that, until real epochs land, a (scope, scopeKey) can be
// revoke-APPLIED only once. This is safe ONLY while one of two cross-repo
// contracts holds, and this AC primitive can defend neither locally:
//
//  1. qurl-service denies re-admission of a revoked key with no positive-cache
//     window (QURL_V2_KEYED_IDENTITY.md "v2 admission uses no positive cache: a
//     revoked qURL is denied on the very next admission", and the "Proposed
//     Acceptance Bar": "no positive admission cache on the v2 admission path").
//     Without it a long-lived key (resource scope is the sharp case — its hash
//     is a durable resource public key, not a per-session value) could be
//     revoked, re-admitted, and a second epoch-0 revoke would be dropped
//     (0 <= 0), leaving the new session alive to natural expiry. This is the
//     active guard pre-epoch and is VERIFIED to hold on qurl-service main
//     (2026-06-30, #2781): every admission reads authoritative state fresh —
//     resource scope gates on !resource.IsActive() -> ErrResourceRevoked and
//     qURL scope on QurlStatusRevoked -> ErrQurlRevoked
//     (internal/service/resolve_service.go) — and v2 resources disable the
//     qurl-router L7 positive-auth cache (the IsV2() signal) so a revoke takes
//     effect on the next re-check. No positive admission cache exists on the v2
//     path.
//  2. qurl-service #1010 lands real per-(scope,scope_key) monotonic epochs
//     end-to-end (AOP metadata + revocation event), after which a re-revoke
//     carries a strictly greater epoch and applies normally, dissolving the
//     limitation entirely. (The symmetric qurl-service #1028 TOCTOU — a state row
//     whose resource_revocation_epoch can freeze stale — names this same AC
//     high-water mark as its authoritative backstop, so both ends want real
//     epochs.)
//
// Tracked by #2781. The P4e receive path is now wired in the AC (NHP_REV ->
// HandleUdpACRevocation -> ApplyRevocation), landed in the qURL v2 epic #2753
// with the server-side fanout in #2789 — so safety no longer rests on "no
// caller" (the original claim here, now stale). It rests on contract 1 above,
// which is verified. There is still no LIVE exposure: the qURL v2 stack ships
// dormant on main — v2 admission is gated off (QURL_V2_ADMISSION_ENABLED,
// #2769) and the revoke endpoint is inert until the qurl-service NHP Sink goes
// live (#2789 prod-rollout-ledger) — so no production revoke reaches here and no
// v2 key is admitted to recur. Contract 1 must stay verified before v2 admission
// and the revoke Sink are enabled in any live environment (gated rollouts; the
// #2789 ledger entry carries the pre-enablement gate).
func (ri *revocationIndex) admitEpoch(scope revocationScope, scopeKey string, epoch uint64) bool {
	if ri == nil {
		return true
	}
	k := indexKey{scope, scopeKey}
	ri.mu.Lock()
	defer ri.mu.Unlock()
	last, seen := ri.lastEpoch[k]
	if seen && epoch <= last.epoch {
		return false
	}
	ri.lastEpoch[k] = revocationEpochWatermark{
		epoch:     epoch,
		appliedAt: ri.now(),
	}
	return true
}

// peekStale reports whether epoch WOULD be dropped as stale/duplicate for
// (scope, scopeKey), without mutating the watermark. It exists only so the
// no-live-match path can still tick MetricRevocationStaleDropped for a genuine
// replay (an event whose epoch the AC already applied) without advancing the
// watermark on a never-seen key — preserving the replay-spike signal the
// metric godoc advertises. The AUTHORITATIVE gate remains the atomic
// check-and-set admitEpoch on the apply path; this is observability only.
func (ri *revocationIndex) peekStale(scope revocationScope, scopeKey string, epoch uint64) bool {
	if ri == nil {
		return false
	}
	ri.mu.Lock()
	defer ri.mu.Unlock()
	last, seen := ri.lastEpoch[indexKey{scope, scopeKey}]
	return seen && epoch <= last.epoch
}

func (a *UdpAC) runRevocationWatermarkSweepRoutine() {
	defer a.wg.Done()
	defer log.Debug("revocationWatermarkSweepRoutine stopped")

	log.Debug("revocationWatermarkSweepRoutine started (ttl=%s interval=%s)",
		revocationWatermarkTTL, revocationWatermarkSweepInterval)

	ticker := time.NewTicker(revocationWatermarkSweepInterval)
	defer ticker.Stop()
	a.runRevocationWatermarkSweepLoop(ticker.C)
}

func (a *UdpAC) runRevocationWatermarkSweepLoop(ticks <-chan time.Time) {
	for {
		select {
		case <-a.signals.stop:
			return
		case _, ok := <-ticks:
			if !ok {
				return
			}
			a.sweepRevocationWatermarksOnce()
		}
	}
}

func (a *UdpAC) sweepRevocationWatermarksOnce() {
	if a == nil || a.revIndex == nil {
		return
	}
	removed := a.revIndex.sweepLastEpoch(revocationWatermarkTTL)
	if removed > 0 {
		a.addMetric(MetricRevocationWatermarksPruned, uint64(removed))
		log.Info("[Revocation] pruned %d inactive epoch watermarks older than %s",
			removed, revocationWatermarkTTL)
	}
}

// ApplyRevocation is the local apply primitive and the seam P4e calls once it
// has received and validated a qurl-service revocation event off the wire. It:
//
//  1. looks up the matching AccessEntries via the secondary index. If none
//     match, returns 0 WITHOUT advancing the epoch watermark — a revoke that
//     races ahead of its admission must not poison the watermark and cause the
//     post-admission redelivery to be dropped (see the match-before-gate
//     comment in the body);
//  2. epoch-gates the matched event (idempotency / ordering; mirrors P4d) via
//     the atomic check-and-set admitEpoch. A stale or duplicate epoch is
//     dropped and 0 entries are reported flushed;
//  3. for each matching entry, via deleteThenFlushEntry, removes it from
//     tokenStore (deindexing it, so a refresh / re-knock cannot re-extend it)
//     and THEN flushes its active L3 flow state immediately — rescheduling the
//     entry's tracked FlowKeys to fire now, reusing the existing
//     scheduler/flusher (conntrack delete on iptables mode, XDP map delete on
//     eBPF mode) and the circuit breaker.
//
// Returns the number of tokenStore entries acted on (0 when dropped as stale or
// when nothing matched). Coarse OVER-flush of a shared FlowKey is accepted here
// per the design's interim caveat; surgical precision is P4c. The symmetric
// UNDER-flush direction is narrowed by deleteThenFlushEntry's delete-before-flush
// order (the #2784 interim — see its godoc for the mechanism and the two
// residual windows that remain, which are live-but-bounded, not dead code). P4c's
// per-session discriminator closes both directions entirely; tracked in #2784.
//
// Relatedly, the tokensFor snapshot is taken once and iterated: an admission for
// the same key that lands AFTER the snapshot is not in the set and survives this
// revoke. A sequential re-admission is covered by the qurl-service no-positive-
// cache "deny re-admission of a revoked key" precondition (#2781), but an
// in-flight admission already past that check is not defendable at this layer —
// it is the same class as #2781/#2784 and dissolves once real monotonic epochs
// (qurl-service #1010) make the redelivered revoke carry a strictly greater epoch.
//
// scopeKey is the bare per-scope hash/id (NOT the qurl-service "qurl:<hash>"
// prefixed scope_key form); P4e strips any transport-level prefix before
// calling. Empty scopeKey is a no-op.
func (a *UdpAC) ApplyRevocation(scope revocationScope, scopeKey string, epoch uint64) int {
	if a == nil || a.revIndex == nil || scopeKey == "" {
		return 0
	}
	// Match BEFORE the epoch gate. A no-live-match event must NOT advance the
	// watermark: otherwise a revoke that arrives before its admission (or on an
	// AC that never admitted it under cell-wide fan-out) would raise the
	// watermark to epoch, and the at-least-once redelivery that arrives AFTER
	// admission would be dropped as `epoch <= last` — leaving the entry that
	// should die alive to natural expiry (fail-open). The watermark must only
	// move once there is live state to protect; admitEpoch (the authoritative
	// atomic check-and-set) is therefore reached only on the matched path below.
	tokens := a.revIndex.tokensFor(scope, scopeKey)
	if len(tokens) == 0 {
		// No live entry: the session may have already expired (incl. the
		// common post-apply duplicate, whose entry we already deleted), this
		// AC never admitted it (cell-wide fan-out), or the admission has not
		// arrived yet. Not an error. We do NOT advance the watermark here (see
		// above). peekStale still lets a genuine replay — an epoch the AC
		// actually applied — tick the stale metric, so the replay-spike signal
		// survives the reorder; a brand-new key (unseen) does not.
		if a.revIndex.peekStale(scope, scopeKey, epoch) {
			a.incrMetric(MetricRevocationStaleDropped)
		}
		log.Debug("[Revocation] no live entries for scope=%s key=%s epoch=%d", scope, scopeKey, epoch)
		return 0
	}
	if !a.revIndex.admitEpoch(scope, scopeKey, epoch) {
		log.Info("[Revocation] dropping stale/duplicate revoke scope=%s key=%s epoch=%d (<= last applied)",
			scope, scopeKey, epoch)
		a.incrMetric(MetricRevocationStaleDropped)
		return 0
	}
	flushed := 0
	for _, token := range tokens {
		entry, found := a.tokenStore.Load(token)
		if !found || entry == nil {
			// Raced with normal expiry / Delete; the deindex hook already
			// dropped it from the index. Nothing to flush.
			continue
		}
		a.deleteThenFlushEntry(token, entry)
		flushed++
	}
	log.Info("[Revocation] applied scope=%s key=%s epoch=%d flushed=%d entries", scope, scopeKey, epoch, flushed)
	a.addMetric(MetricRevocationEntriesFlushed, uint64(flushed))
	return flushed
}

// deleteThenFlushEntry tears one revoked entry down in the #2784-mandated order:
// deleteToken BEFORE flushEntryNow. That order is load-bearing — it must not be
// reversed, nor may any tokenStore / revocation-index work be inserted between
// the two calls — so the pair is encapsulated here, where a refactor of
// ApplyRevocation's loop cannot accidentally split or reorder it. This is the
// single home for the delete-before-flush rationale (the call site and the
// ApplyRevocation godoc only point here).
//
// deleteToken removes the entry from tokenStore (so a late re-knock cannot
// re-extend its pinhole) AND deindexes it; tokenStore.Delete fires NO OnExpire
// hook, so the index maintenance is explicit. Doing it FIRST takes the entry out
// of the tokenStore snapshot a concurrent sibling expiry's
// cancelAllScheduledFlows reads: a sibling that snapshots after this delete sees
// no live holder of a shared FlowKey and Cancels it (or no-ops) instead of
// re-Scheduling the just-revoked deadline back to this entry's future firewall
// deadline via longest-wins Schedule — closing the dominant under-flush
// push-back that defeated the revoke.
//
// flushEntryNow still fires post-delete because it drains the tracked keys off
// the entry POINTER, not tokenStore. That off-pointer drain is the implicit
// contract this order depends on; a future edit that makes flushEntryNow re-Load
// the entry from tokenStore would silently break the flush, so it is fenced by
// TestFlushEntryNow_StillFiresAfterTokenDeleted.
//
// Two residuals remain and are P4c concerns: a sibling that snapshotted just
// BEFORE the delete can still push the deadline back, and a sibling Cancel
// landing after flushEntryNow's RescheduleEarlier drops the coarse reschedule.
// Both degrade only the COARSE allow-rule re-open barrier, not the
// established-flow teardown: flushEntryNow runs its surgical conntrack flush
// synchronously per key (see its godoc for the per-mode eBPF/iptables/v6 detail),
// so where that path applies the revoked established flows are already gone and
// only the allow-rule lingers to its kernel TTL. These are live-but-bounded, NOT
// dead code: the apply path is wired in prod (NHP_REV → HandleUdpACRevocation →
// ApplyRevocation → here, #2753), but each residual needs a real revoke applying
// in the microsecond window of a sibling's natural expiry on the same FlowKey,
// bounded by the kernel TTL — the same coarse shared-FlowKey limitation that is
// the accepted P4b interim. P4c's per-session FlowKey discriminator closes both
// directions (and both residuals) entirely.
func (a *UdpAC) deleteThenFlushEntry(token string, entry *AccessEntry) {
	a.deleteToken(token, entry)
	a.flushEntryNow(entry)
}

// CloseNHPSession tears down every live AccessEntry carrying the exact
// authenticated AOP server identity plus sessionID. The token snapshot is
// taken from the dedicated base-session index, then each entry follows the
// same delete-before-flush ordering as immediate revocation. Missing sessions
// are an idempotent success.
func (a *UdpAC) CloseNHPSession(serverPublicKey, sessionOwnerID string, sessionID uint64) int {
	if a == nil || a.nhpSessions == nil || a.tokenStore == nil || serverPublicKey == "" || !common.ValidNHPSessionOwnerID(sessionOwnerID) || sessionID == 0 {
		return 0
	}
	closed := 0
	for _, token := range a.nhpSessions.tokens(serverPublicKey, sessionOwnerID, sessionID) {
		entry, ok := a.tokenStore.Load(token)
		if !ok || entry == nil || entry.NHPSessionId != sessionID || entry.NHPServerPublicKey != serverPublicKey || entry.NHPSessionOwnerId != sessionOwnerID {
			continue
		}
		a.deleteThenFlushEntry(token, entry)
		closed++
	}
	return closed
}

// CloseNHPExactSession tears down one logical NHP session independent of the
// fleet server process that originally opened it. The issuance timestamp keeps
// a later reuse of the same random uint64 distinct.
func (a *UdpAC) CloseNHPExactSession(agentPublicKey string, sessionID uint64, issuedAtMillis int64) int {
	if a == nil || a.nhpSessions == nil || a.tokenStore == nil ||
		!common.ValidNHPAgentPublicKey(agentPublicKey) || sessionID == 0 || issuedAtMillis <= 0 {
		return 0
	}
	closed := 0
	for _, token := range a.nhpSessions.exactTokens(agentPublicKey, sessionID, issuedAtMillis) {
		entry, ok := a.tokenStore.Load(token)
		if !ok || entry == nil || entry.NHPAgentPublicKey != agentPublicKey ||
			entry.NHPSessionId != sessionID || entry.NHPSessionIssuedAtMillis != issuedAtMillis {
			continue
		}
		a.deleteThenFlushEntry(token, entry)
		closed++
	}
	return closed
}

// CloseNHPAgentSessionsThrough closes every session for an authenticated agent
// issued at or before the EXT cutoff. Sessions issued after the cutoff are a
// fresh post-EXT cycle and survive.
func (a *UdpAC) CloseNHPAgentSessionsThrough(agentPublicKey string, issuedThroughMillis int64) int {
	if a == nil || a.nhpSessions == nil || a.tokenStore == nil ||
		!common.ValidNHPAgentPublicKey(agentPublicKey) || issuedThroughMillis <= 0 {
		return 0
	}
	closed := 0
	for _, token := range a.nhpSessions.agentTokens(agentPublicKey) {
		entry, ok := a.tokenStore.Load(token)
		if !ok || entry == nil || entry.NHPAgentPublicKey != agentPublicKey ||
			entry.NHPSessionIssuedAtMillis <= 0 || entry.NHPSessionIssuedAtMillis > issuedThroughMillis {
			continue
		}
		a.deleteThenFlushEntry(token, entry)
		closed++
	}
	return closed
}

// CloseNHPRunBeforeAttempt closes admissions from older attempts of one RunID.
// Fresh RunIDs are separate index keys, so make-before-break siblings survive.
func (a *UdpAC) CloseNHPRunBeforeAttempt(agentPublicKey, runID string, attempt uint64) int {
	if a == nil || a.nhpSessions == nil || a.tokenStore == nil || attempt == 0 ||
		!common.ValidNHPAgentPublicKey(agentPublicKey) || common.ValidateAgentKnockRunID(runID) != nil {
		return 0
	}
	closed := 0
	for _, token := range a.nhpSessions.runTokens(agentPublicKey, runID) {
		entry, ok := a.tokenStore.Load(token)
		if !ok || entry == nil || entry.NHPAgentPublicKey != agentPublicKey ||
			entry.NHPRunID != runID || entry.NHPRunAttempt == 0 || entry.NHPRunAttempt >= attempt {
			continue
		}
		a.deleteThenFlushEntry(token, entry)
		closed++
	}
	return closed
}

// CloseAllNHPSessions is the AC fail-closed lease/boot-flush primitive. It is
// intentionally scoped to entries admitted by NHP and leaves unrelated local
// access-controller state alone.
func (a *UdpAC) CloseAllNHPSessions() int {
	if a == nil || a.nhpSessions == nil || a.tokenStore == nil {
		return 0
	}
	closed := 0
	for _, token := range a.nhpSessions.allTokens() {
		entry, ok := a.tokenStore.Load(token)
		if !ok || entry == nil || entry.NHPSessionId == 0 {
			continue
		}
		a.deleteThenFlushEntry(token, entry)
		closed++
	}
	return closed
}

// flushEntryNow forces every FlowKey the entry has scheduled to fire its flush
// immediately. It drains the tracked keys ONCE (drainScheduledKeys empties the
// set under e.mu and returns the keys), then drives BOTH teardown directions
// off that single slice:
//
//  1. COARSE allow-rule teardown (every mode, IPv4 keys ONLY):
//     Scheduler.RescheduleEarlier pulls each v4 FlowKey's deadline to now so the
//     scheduler/flusher (and its circuit breaker) tears the allow-rule entry down
//     on the next tick. This BARS RE-OPEN — a packet on a revoked tuple can no
//     longer re-create a conntrack short-circuit — and is the ONLY established-flow
//     teardown in iptables mode and the fallback when the surgical path is
//     unavailable. It is IPv4-only because both flushers' teardown is IPv4-only
//     (eBPF allow-rule maps; `conntrack -D` has no `-f ipv6`); a v6 reschedule
//     would be a pure no-op that only pollutes the expiry-skip counter, so v6 keys
//     skip this step (see the IPv6 note below — #2778 part 2).
//  2. SURGICAL conntrack teardown (eBPF/XDP + IPv4 only): for each drained v4
//     TCP/UDP key, enumerate the live conntrack 5-tuples on that allow-rule
//     tuple and FlushConn EXACTLY each one. Deleting the allow-rule alone does
//     NOT immediately drop an ESTABLISHED flow — the XDP conn_track
//     short-circuit keeps it passing until the entry's ttl_ns (anchored to the
//     allow-rule's ORIGINAL remaining lifetime) elapses, up to a full session
//     after the revoke. FlushConn deletes the conntrack entry so the very next
//     packet falls back through the (now-removed) allow-rule path → XDP_DROP.
//     Crucially it kills only the revoked admission's flow and leaves a
//     same-allow-tuple sibling (different source port, e.g. a second client
//     behind the same NAT) ALIVE — resolving the coarse over-flush #2784.
//
// drain-once-feed-both: the coarse RescheduleEarlier loop must NOT re-drain
// (drainScheduledKeys is destructive — a second call returns nil and the
// surgical step would silently no-op). Both steps iterate the same `keys`
// slice.
//
// Why RescheduleEarlier and not Schedule/Cancel for the coarse step: a live
// admitted flow is already scheduled at its future firewall deadline; Schedule
// is longest-wins so Schedule(key, now) no-ops against it, and Cancel only
// unlinks and lets the kernel rule self-expire by TTL rather than flushing now.
// RescheduleEarlier pulls the deadline earlier (preserving Schedule's in-flight
// barrier so a flow already being torn down isn't double-flushed) — the inverse
// of /refresh-shorten, which wants the flow to survive to a peer's deadline.
//
// IPv6 (#2778/#2794/#2837/#2165): the coarse RescheduleEarlier path is IPv4 by
// default, and is enabled for v6 only when FilterMode_IPTABLES is using the
// netlink ConntrackFlusher backend. That keeps the expiry-skip vs revoke-skip
// split intact for v4-only teardown paths while letting iptables+netlink tear v6
// down on the same coarse path iptables already uses for v4:
//
//   - EBPFXDP: surgicalFlushFlowKey routes the v6 key to surgicalFlushFlowKeyV6.
//     When the v6 conntrack seam is wired (FlushConnV6 + EnumerateConnTrackSrcPortsV6,
//     #2837) the v6 flow is torn down SURGICALLY (MetricRevocationSurgicalFlushedV6) —
//     a real immediate revoke. When the seam is unwired (v4-only build / non-Linux)
//     it ticks MetricRevocationIPv6HardFail and does NOT treat the absence of a v6
//     conntrack entry as "killed".
//   - FilterMode_IPTABLES, EXEC backend: the coarse RescheduleEarlier path stays
//     IPv4-only because `conntrack -D` is IPv4-only (no `-f ipv6`) and the
//     surgical seam is EBPFXDP-only. A v6 revoke therefore ticks
//     MetricRevocationIPv6HardFail directly here and is NOT folded into the
//     exec flusher's benign expiry-skip counter.
//   - FilterMode_IPTABLES, NETLINK backend (#2165, opt-in via
//     l3FlushConntrackBackend=netlink): the coarse Flush dumps + deletes both
//     families, so the v6 revoke is torn down on the next scheduler tick. No
//     hard-fail fires. This keeps iptables' existing coarse mass-delete semantics;
//     a sibling-preserving netlink surgical path is a separate follow-up.
//
// The hard-fail is raised whenever a v6 revoke has no teardown path: EBPFXDP via
// the surgical path (surgicalConnFlush != nil), and iptables via the explicit
// FilterMode_IPTABLES branch below ONLY when the coarse path is IPv4-only (the
// exec backend). With the netlink backend (coarseConntrackHandlesV6, #2165) the
// iptables v6 revoke IS torn down by the coarse Flush, so no hard-fail fires
// there. Either way ANY nonzero reading is a real immediate-revocation gap to
// alarm on, distinct from the benign expiry skip counters.
func (a *UdpAC) flushEntryNow(entry *AccessEntry) {
	if a.expirySched == nil || entry == nil {
		return
	}
	keys := entry.drainScheduledKeys()
	if len(keys) == 0 {
		return
	}
	now := time.Now()
	// surgicalConnFlush is non-nil ONLY in EBPFXDP-on-Linux mode (bound in
	// Start()); that is the single signal that the surgical path + v6 hard-fail
	// accounting apply. Build the ctx once for the whole entry's flushes.
	surgicalAvailable := a.surgicalConnFlush != nil
	var ctx context.Context
	if surgicalAvailable {
		ctx = context.Background()
	}
	// iptables mode (ConntrackFlusher) when the eBPF surgical seam is unwired.
	// Gate on FilterMode_IPTABLES explicitly rather than the bare !surgical
	// else, whose job is to EXCLUDE the EBPFXDP path from this hard-fail (that
	// path ticks the metric itself in surgicalFlushFlowKey). The other
	// surgical-nil cases reach this branch but are already inert by construction:
	// L3-flush-disabled schedules nothing (drainScheduledKeys returned empty →
	// we early-returned above), and ConntrackFlusher is //go:build linux so an
	// iptables-configured AC off-Linux can't wire L3 flush at all (same empty-
	// keys return). Because FilterMode_IPTABLES is the iota-zero default, a
	// partially-initialized non-nil config would also land here — harmless under
	// that same empty-keys guard, but the reason it's safe is the empty-keys
	// return, not the gate. config is non-nil for any real AC; the nil guard
	// keeps the surgical-seam-injecting unit helpers (config nil but
	// surgicalConnFlush set, so they never reach here) and the coarse-only v4
	// fallback test nil-safe.
	iptablesMode := a.config != nil && a.config.FilterMode == FilterMode_IPTABLES
	iptablesV6CoarseAvailable := iptablesMode && a.coarseConntrackHandlesV6.Load()
	for _, key := range keys {
		// Classify the key's family once — both the coarse reschedule and the
		// iptables v6 hard-fail branch below key off it.
		isV4 := isFlowKeyIPv4(key)
		// COARSE teardown. IPv4 is always supported. IPv6 is supported only when
		// iptables mode is backed by the #2165 netlink ConntrackFlusher; under
		// exec it would be a guaranteed no-op that only pollutes the expiry-skip
		// counter.
		if isV4 || iptablesV6CoarseAvailable {
			a.expirySched.RescheduleEarlier(key, now)
		}
		switch {
		case surgicalAvailable:
			// SURGICAL: kill established flows on this tuple without over-flushing
			// siblings. Only when the eBPF/XDP path is wired. surgicalFlushFlowKey
			// dispatches v4 inline (the coarse reschedule above already ran for it)
			// and v6 to surgicalFlushFlowKeyV6 (itself surgical when the v6 seam is
			// wired, else hard-fails — #2778/#2837).
			a.surgicalFlushFlowKey(ctx, key)
		case iptablesMode && !isV4:
			if iptablesV6CoarseAvailable {
				// Netlink backend (#2165): the coarse RescheduleEarlier above
				// reschedules ConntrackFlusher.Flush, which under netlink tears
				// down v6 conntrack entries too — so this v6 revoke IS torn down
				// (near-immediately, on the next scheduler tick). No #2794 gap,
				// hence no hard-fail. Same coarse-mass-delete semantics as v4;
				// the surgical sibling-preserving path stays the #2784 follow-up.
				break
			}
			// Exec backend: `conntrack -D` is IPv4-only (no -f ipv6), so the
			// coarse reschedule was intentionally skipped rather than handing a
			// guaranteed no-op to the flusher and polluting metricSkipped. Raise the
			// revocation-specific hard-fail so observability can tell "v6 revoke not
			// torn down" apart from a benign expiry skip. Closed by setting
			// l3FlushConntrackBackend=netlink (#2165). (#2778/#2794)
			a.incrMetric(MetricRevocationIPv6HardFail)
			log.Warning("[Revocation] IPv6 flow %s under iptables (exec backend) has no immediate conntrack teardown (conntrack -D is IPv4-only; set l3FlushConntrackBackend=netlink, #2165); flow will persist until kernel TTL (#2778/#2794)", key)
		}
	}
	a.incrMetric(MetricRevocationFlushScheduled)
}

// surgicalFlushFlowKey enumerates the live conntrack 5-tuples sharing the given
// allow-rule FlowKey and surgically FlushConn's each, so a revoke kills EXACTLY
// the revoked admission's established flows and leaves same-allow-tuple siblings
// (different source port) alive. Called only when the eBPF/XDP surgical path is
// wired (a.surgicalConnFlush != nil, i.e. EBPFXDP-on-Linux).
//
// Per-key decision tree (the order matters for getting the v6 metric right —
// see the IPv6 note on flushEntryNow):
//
//   - IPv6 key → surgicalFlushFlowKeyV6 (see its godoc for the wired-surgical /
//     unwired-hard-fail decision tree). #2778.
//   - IPv4 + ICMP / "any" → no conntrack entry exists by design (the XDP
//     established-flow short-circuit is port-keyed), so there is nothing to
//     surgically tear down; the coarse allow-rule teardown already done in
//     flushEntryNow suffices. No hard-fail.
//   - IPv4 + TCP/UDP → enumerate the conn_track source ports on this tuple and
//     FlushConn each full 5-tuple.
//
// Enumeration "map not pinned" (XDP not attached) is a soft fallback: the
// coarse allow-rule reschedule already ran, so there is nothing more to do —
// log at debug and return rather than erroring. Any other enumeration error is
// logged (best-effort: the coarse path already fired; revoke must not be taken
// down by an enumeration hiccup) but does not panic.
func (a *UdpAC) surgicalFlushFlowKey(ctx context.Context, key FlowKey) {
	// isFlowKeyIPv4 is the AND of both endpoints, so a (malformed) MIXED-family
	// key — one IPv4-mapped endpoint and one real v6 endpoint — is NOT v4 and
	// routes to the v6 path below. MakeFlowKey only ever produces all-v4 or
	// all-v6 keys, so a mixed key is unreachable in practice; but if one arose it
	// is NOT silently treated as torn down: surgicalFlushFlowKeyV6 calls the v6
	// enumerator, whose parseIP6 rejects the v4-mapped endpoint (rendered as a
	// dotted quad), yielding a non-not-pinned error → the enumeration-error
	// hard-fail branch (MetricRevocationIPv6HardFail) when conn_track_v6 is
	// pinned, or the benign soft fallback when it is not. Either way it surfaces,
	// never a silent success. (Defensive note for a corner the type system does
	// not forbid; no dedicated metric since it cannot occur via MakeFlowKey.)
	if !isFlowKeyIPv4(key) {
		a.surgicalFlushFlowKeyV6(ctx, key)
		return
	}
	proto, ok := key.Protocol.ianaL4Proto()
	if !ok {
		// ICMP / "any": no conntrack short-circuit, coarse allow-rule teardown
		// is sufficient. Nothing surgical to do.
		return
	}
	if a.enumerateConnSrcPorts == nil {
		// Defensive: surgicalConnFlush and enumerateConnSrcPorts are bound as a
		// pair in Start(), so this is unreachable in production. If a future
		// edit ever leaves them out of sync, fall back to coarse-only rather
		// than nil-panic — the allow-rule reschedule already ran.
		log.Error("[Revocation] surgical flush wired without an enumerator for %s; coarse allow-rule flush only", key)
		return
	}
	sports, err := a.enumerateConnSrcPorts(key.SrcIPString(), key.DstIPString(), proto, key.DstPort)
	if err != nil {
		if errors.Is(err, utilebpf.ErrConnTrackMapNotPinned) {
			// XDP not attached at the conn_track pin path — feature inert. The
			// coarse reschedule already ran; nothing else to do.
			log.Debug("[Revocation] conn_track not pinned, surgical flush skipped for %s (coarse allow-rule flush already scheduled): %v", key, err)
			return
		}
		log.Error("[Revocation] conntrack enumeration failed for %s; relying on coarse allow-rule flush only: %v", key, err)
		return
	}
	for _, sport := range sports {
		conn := ConnFlowKey{Flow: key, SrcPort: sport}
		if ferr := a.surgicalConnFlush(ctx, conn); ferr != nil {
			// FlushConn is idempotent on ENOENT (returns nil); a non-nil error
			// is a real teardown failure. The coarse path still bars re-open,
			// so log rather than abort the remaining siblings' flushes.
			log.Error("[Revocation] surgical FlushConn failed for %s: %v", conn, ferr)
			continue
		}
		a.incrMetric(MetricRevocationSurgicalFlushed)
	}
}

// surgicalFlushFlowKeyV6 is the IPv6 twin of surgicalFlushFlowKey's v4 body: it
// enumerates the live conn_track_v6 5-tuples sharing the given v6 allow-rule
// FlowKey and surgically FlushConnV6's each, closing the #2778 IPv6
// immediate-revocation gap on the eBPF/XDP path. Only the v6 seam is read here;
// the caller has already established key is v6.
//
// The decision tree mirrors the v4 path exactly, with one deliberate asymmetry
// on the enumeration-error branch (see below). The PROTO check precedes the
// seam-nil check (the inverse of an earlier ordering) so that an ICMP/"any" key
// — which never has a conn_track_v6 entry — short-circuits to a no-op before the
// seam-nil hard-fail, regardless of whether the seam is wired. Ordering them the
// other way over-counted MetricRevocationIPv6HardFail for unwired-seam ICMP keys
// (a "gap" for a protocol that never had a conntrack entry to leak):
//
//   - ICMP / "any" → no conn_track_v6 entry exists by design (the XDP
//     established-flow short-circuit is port-keyed); there is nothing to tear
//     down. No hard-fail, wired seam or not.
//   - TCP/UDP + v6 seam NOT wired (enumerateConnSrcPortsV6 == nil ||
//     neither surgicalConnFlushBatchV6 nor surgicalConnFlushV6 is available) →
//     MetricRevocationIPv6HardFail and RETURN. This is the iptables / non-Linux /
//     L3-disabled fallback: there is no conn_track_v6 to enumerate, and the
//     coarse allow-rule path is v4-only (so flushEntryNow skipped it for this v6
//     key), so the flow dies at kernel TTL — an explicit hard-fail, NOT a silent
//     success. (#2778 eBPF path; #2794 covers the iptables-mode v6 path
//     separately.)
//   - TCP/UDP + seam wired → enumerate conn_track_v6 source ports and batch
//     FlushConnsV6 all sibling 5-tuples when available, falling back to
//     FlushConnV6 per 5-tuple for injected single-flow seams. Tick
//     MetricRevocationSurgicalFlushedV6 per flushed flow (the v6-specific
//     counter, NOT the shared v4 one).
//
// Enumeration "map not pinned" (XDP not attached at the v6 pin) is a soft
// fallback: the v6 datapath is inert, so there is no live v6 flow to tear down —
// log at debug and return, no hard-fail. ASYMMETRY vs the v4 path: any OTHER
// enumeration error ticks MetricRevocationIPv6HardFail (in addition to a
// best-effort log), because for v6 there is no coarse fallback at all — the
// coarse reschedule is v4-only and was skipped for this key — so an enumeration
// failure means the v6 flow genuinely has no immediate teardown, which is exactly
// what the hard-fail metric exists to surface. The v4 path only logs because its
// coarse allow-rule reschedule still tears the v4 flow down.
//
// The same asymmetry applies PER FLOW inside the loop: a FlushConnV6 that
// returns a real (non-ENOENT) error left that specific 5-tuple alive with no
// coarse fallback, so it ALSO ticks MetricRevocationIPv6HardFail (then continues
// so one failed delete does not abort the surviving siblings). The v4 loop only
// logs there, since its coarse allow-rule flush still bars re-open.
func (a *UdpAC) surgicalFlushFlowKeyV6(ctx context.Context, key FlowKey) {
	proto, ok := key.Protocol.ianaL4Proto()
	if !ok {
		// ICMP / "any": no conn_track_v6 entry exists by design (the XDP
		// established-flow short-circuit is port-keyed), so there is nothing to
		// surgically tear down REGARDLESS of whether the v6 seam is wired — a
		// wired seam would no-op here too. Return before the seam-nil hard-fail
		// so an unwired-seam v6 ICMP key is NOT counted as an
		// immediate-revocation gap (it never had a conntrack entry to leak).
		return
	}
	if a.enumerateConnSrcPortsV6 == nil || (a.surgicalConnFlushBatchV6 == nil && a.surgicalConnFlushV6 == nil) {
		// v6 seam not wired AND this is a TCP/UDP key that DOES have a
		// conn_track_v6 entry: no surgical path, and the coarse path is v4-only
		// (so flushEntryNow skipped it for this v6 key), so the flow genuinely
		// leaks. This is the iptables / non-Linux / L3-disabled fallback — an
		// explicit hard-fail, NOT a silent success.
		a.incrMetric(MetricRevocationIPv6HardFail)
		log.Warning("[Revocation] IPv6 flow %s has no surgical conntrack teardown (eBPF/XDP v6 seam not wired — iptables mode or non-Linux); flow will persist until kernel TTL (#2778/#2794)", key)
		return
	}
	sports, err := a.enumerateConnSrcPortsV6(key.SrcIPString(), key.DstIPString(), proto, key.DstPort)
	if err != nil {
		if errors.Is(err, utilebpf.ErrConnTrackMapNotPinned) {
			// conn_track_v6 not pinned at its path — the v6 datapath is inert
			// (XDP not attached), so there is no live v6 flow to tear down;
			// nothing to do.
			log.Debug("[Revocation] conn_track_v6 not pinned, surgical flush skipped for %s: %v", key, err)
			return
		}
		// No working coarse fallback for v6 → this IS an immediate-revocation
		// gap; surface it on the hard-fail metric (asymmetry vs v4, see godoc).
		a.incrMetric(MetricRevocationIPv6HardFail)
		log.Error("[Revocation] conn_track_v6 enumeration failed for %s; v6 flow has no immediate teardown (#2778): %v", key, err)
		return
	}
	if a.surgicalConnFlushBatchV6 != nil {
		errs := a.surgicalConnFlushBatchV6(ctx, key, sports)
		if len(errs) != len(sports) {
			for range sports {
				a.incrMetric(MetricRevocationIPv6HardFail)
			}
			log.Error("[Revocation] surgical FlushConnsV6 returned %d results for %d source ports on %s; treating the batch as a v6 immediate-teardown gap (#2778)", len(errs), len(sports), key)
			return
		}
		for i, sport := range sports {
			conn := ConnFlowKey{Flow: key, SrcPort: sport}
			if ferr := errs[i]; ferr != nil {
				// A batch result error has the same fail-closed meaning as the
				// per-flow FlushConnV6 error below: conntrack deletion failed, or
				// conntrack was deleted but matching frag_state_v6 cleanup was not
				// verifiably completed.
				a.incrMetric(MetricRevocationIPv6HardFail)
				log.Error("[Revocation] surgical FlushConnsV6 failed for %s; v6 flow has no immediate teardown (#2778): %v", conn, ferr)
				continue
			}
			a.incrMetric(MetricRevocationSurgicalFlushedV6)
		}
		return
	}
	for _, sport := range sports {
		conn := ConnFlowKey{Flow: key, SrcPort: sport}
		if ferr := a.surgicalConnFlushV6(ctx, conn); ferr != nil {
			// FlushConnV6 is idempotent on ENOENT (returns nil), so a non-nil
			// error is a REAL teardown failure on THIS 5-tuple — a per-flow
			// immediate-revocation gap (no coarse fallback for v6; see godoc), so
			// tick the hard-fail metric per failed flow. Then continue: one port's
			// delete failing must not abort the remaining siblings' flushes.
			a.incrMetric(MetricRevocationIPv6HardFail)
			log.Error("[Revocation] surgical FlushConnV6 failed for %s; v6 flow has no immediate teardown (#2778): %v", conn, ferr)
			continue
		}
		// v6-specific counter, NOT the shared v4 one (see metric godoc).
		a.incrMetric(MetricRevocationSurgicalFlushedV6)
	}
}

// isFlowKeyIPv4 reports whether both endpoints of a FlowKey are IPv4 (stored in
// IPv4-mapped [16]byte form). The conntrack map and the eBPF allow-rule maps are
// IPv4-only; this is the cross-platform gate the surgical-revocation path uses
// to split v4 (enumerate + FlushConn) from v6 (hard-fail). net.IP.To4 returns
// non-nil exactly for the IPv4-mapped form MakeFlowKey produces for v4 inputs.
func isFlowKeyIPv4(key FlowKey) bool {
	return net.IP(key.SrcIP[:]).To4() != nil && net.IP(key.DstIP[:]).To4() != nil
}
