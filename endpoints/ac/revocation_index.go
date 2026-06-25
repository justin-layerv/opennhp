package ac

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

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
// values mirror qurl-service's revocation-event `scope` field (P4d, #1009) so
// the two ends agree without a translation table.
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

// indexKey is the composite key the secondary index is keyed by: the revocation
// scope plus the per-scope hash/id. Keeping scope in the key prevents a
// qurl-hash from colliding with a resource-hash that happens to share bytes, and
// lets one map serve all scopes.
type indexKey struct {
	scope revocationScope
	key   string
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
	if entry.SessionId != "" {
		keys = append(keys, indexKey{scopeSession, entry.SessionId})
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
	// with epoch <= lastEpoch[k] is a stale duplicate and is dropped. Retains a
	// watermark per revoked key even after its entries are gone; sweep tracked
	// in #2782 (see remove godoc).
	lastEpoch map[indexKey]uint64
}

func newRevocationIndex() *revocationIndex {
	return &revocationIndex{
		byKey:     make(map[indexKey]map[string]struct{}),
		lastEpoch: make(map[indexKey]uint64),
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
// watermark is intentionally NOT pruned with the set: a revoke can arrive after
// the last matching entry is gone (e.g. the session already expired), and the
// watermark must still reject a later stale-epoch duplicate. lastEpoch is
// bounded by the number of distinct revoked keys, which ages out with TTL on the
// qurl-service side; an AC-side sweep is a future optimization, not a leak that
// matters at current scale. A periodic sweep / removal-on-last-entry to reclaim
// stale watermarks is tracked in #2782.
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
// epoch is applied. This also gives correct dedup in the pre-#1010 world where
// every revoke shares epoch 0: the first epoch-0 event applies (unseen), a
// second epoch-0 event for the same key is dropped (seen && 0 <= 0).
//
// Cross-service precondition (the local primitive cannot enforce it). The cost
// of the above is that pre-#1010 a (scope, scopeKey) can be revoke-APPLIED only
// once. This is safe ONLY while two contracts hold, and this primitive cannot
// defend either locally — they are P4e / #1010 / qurl-service preconditions:
//
//  1. qurl-service denies re-admission of a revoked key with no stale-cache
//     window (QURL_V2_KEYED_IDENTITY.md "v2 admission uses no positive cache:
//     a revoked qURL is denied on the very next admission"). Without this, a
//     long-lived key (resource scope is the sharp case — its hash is a
//     durable resource public key, not a per-session value) could be revoked,
//     re-admitted, and a second epoch-0 revoke would be dropped (0 <= 0),
//     leaving the new session alive to natural expiry.
//  2. #1010 lands real per-(scope,scope_key) monotonic epochs, after which a
//     re-revoke carries a strictly greater epoch and applies normally,
//     dissolving the limitation entirely.
//
// Tracked by #2781. There is NO production caller of ApplyRevocation before P4e
// wires the receive path, so there is no live exposure to this window today;
// the limitation must be closed (by #1010) before P4e enables it in an
// environment where a revoked key can recur.
func (ri *revocationIndex) admitEpoch(scope revocationScope, scopeKey string, epoch uint64) bool {
	if ri == nil {
		return true
	}
	k := indexKey{scope, scopeKey}
	ri.mu.Lock()
	defer ri.mu.Unlock()
	last, seen := ri.lastEpoch[k]
	if seen && epoch <= last {
		return false
	}
	ri.lastEpoch[k] = epoch
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
	return seen && epoch <= last
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
//  3. flushes each matching entry's active L3 flow state IMMEDIATELY by
//     rescheduling its tracked FlowKeys to fire now, reusing the existing
//     scheduler/flusher (conntrack delete on iptables mode, XDP map delete on
//     eBPF mode) and the circuit breaker;
//  4. removes the entry from tokenStore so a refresh / re-knock cannot extend it.
//
// Returns the number of tokenStore entries acted on (0 when dropped as stale or
// when nothing matched). Coarse OVER-flush of a shared FlowKey is accepted here
// per the design's interim caveat; surgical precision is P4c. The symmetric
// UNDER-flush direction is also a P4c-deferred consequence of the network-shaped
// FlowKey: this orders flushEntryNow before deleteToken, so within that window a
// concurrent natural expiry of a sibling sharing the FlowKey can re-Schedule (or
// Cancel) the key off a tokenStore snapshot that still lists this entry and push
// the revoke deadline back. There is no production caller until P4e, and P4c's
// per-session discriminator closes both directions; tracked in #2784.
//
// Relatedly, the tokensFor snapshot is taken once and iterated: an admission for
// the same key that lands AFTER the snapshot is not in the set and survives this
// revoke. A sequential re-admission is covered by the qurl-service no-positive-
// cache "deny re-admission of a revoked key" precondition (#2781), but an
// in-flight admission already past that check is not defendable at this layer —
// it is the same class as #2781/#2784 and dissolves once real monotonic epochs
// (#1010) make the redelivered revoke carry a strictly greater epoch.
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
		log.Info("[Revocation] no live entries for scope=%s key=%s epoch=%d", scope, scopeKey, epoch)
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
		a.flushEntryNow(entry)
		// deleteToken removes the entry from tokenStore (so a late re-knock
		// cannot re-extend its pinhole) AND deindexes it. tokenStore.Delete
		// fires NO OnExpire hook, so index maintenance must be explicit.
		a.deleteToken(token, entry)
		flushed++
	}
	log.Info("[Revocation] applied scope=%s key=%s epoch=%d flushed=%d entries", scope, scopeKey, epoch, flushed)
	a.addMetric(MetricRevocationEntriesFlushed, uint64(flushed))
	return flushed
}

// flushEntryNow forces every FlowKey the entry has scheduled to fire its flush
// immediately. It drains the tracked keys ONCE (drainScheduledKeys empties the
// set under e.mu and returns the keys), then drives BOTH teardown directions
// off that single slice:
//
//  1. COARSE allow-rule teardown (always, every mode): Scheduler.RescheduleEarlier
//     pulls each FlowKey's deadline to now so the scheduler/flusher (and its
//     circuit breaker) tears the allow-rule entry down on the next tick. This
//     BARS RE-OPEN — a packet on a revoked tuple can no longer re-create a
//     conntrack short-circuit — and is the ONLY teardown available in iptables
//     mode and the fallback when the surgical path is unavailable.
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
// IPv6 (#2778/#2794): a v6 immediate revoke has NO real teardown in EITHER mode,
// so flushEntryNow ticks MetricRevocationIPv6HardFail (a revocation-specific
// failure signal, NOT a benign skip) for every v6 key and the flow only dies at
// kernel TTL:
//
//   - EBPFXDP: conn_track is IPv4-only (struct ipv4_ct_tuple uses __be32) so the
//     surgical FlushConn path can't address it, and the coarse allow-rule maps
//     are v4-only too. surgicalFlushFlowKey ticks the hard-fail per key and does
//     NOT treat the absence of a v6 conntrack entry as "killed".
//   - FilterMode_IPTABLES: the coarse RescheduleEarlier reschedules the v6 key
//     into the ConntrackFlusher, whose Flush is `conntrack -D` IPv4-ONLY (no
//     `-f ipv6`) — it rejects the v6 key at its boundary and ticks its own
//     conflated metricSkipped ("benign expiry leak"), returning nil. That skip
//     CANNOT distinguish "v6 revoke not torn down" from a benign expiry skip, so
//     flushEntryNow ALSO ticks MetricRevocationIPv6HardFail directly here. The
//     IPv4-only-netlink replacement is #2165 (UNbuilt); until it lands, v6
//     immediate revoke under iptables is DECLARED OUT OF SCOPE (see the gospel
//     "Filter-mode/IPv6 caveat" in docs/design/QURL_V2_KEYED_IDENTITY.md),
//     surfaced — not silently swallowed — via this hard-fail metric.
//
// The hard-fail is therefore raised in BOTH modes: EBPFXDP via the surgical path
// (surgicalConnFlush != nil), iptables via the explicit FilterMode_IPTABLES
// branch below. Either way ANY nonzero reading is a real immediate-revocation
// gap to alarm on, distinct from the benign expiry skip counters.
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
	for _, key := range keys {
		// COARSE first: bar re-open in every mode. See godoc — additive, never
		// gated by the surgical outcome.
		a.expirySched.RescheduleEarlier(key, now)
		switch {
		case surgicalAvailable:
			// SURGICAL: kill established flows on this tuple without over-flushing
			// siblings. Only when the eBPF/XDP+IPv4 path is wired. v6 keys hard-fail
			// inside surgicalFlushFlowKey.
			a.surgicalFlushFlowKey(ctx, key)
		case iptablesMode && !isFlowKeyIPv4(key):
			// v6 under iptables: the coarse RescheduleEarlier above just handed this
			// key to the IPv4-only `conntrack -D` flusher, which rejects it at its
			// boundary (conflated metricSkipped) and tears nothing down. Raise the
			// revocation-specific hard-fail so the breaker/observability can tell
			// "v6 revoke not torn down" apart from a benign expiry skip. Out of
			// scope until #2165 netlink — see godoc + design doc. (#2778/#2794)
			a.incrMetric(MetricRevocationIPv6HardFail)
			log.Warning("[Revocation] IPv6 flow %s under iptables has no immediate conntrack teardown (conntrack -D is IPv4-only; netlink is #2165); flow will persist until kernel TTL (#2778/#2794)", key)
		}
	}
	a.incrMetric(MetricRevocationFlushScheduled)
}

// surgicalFlushFlowKey enumerates the live conntrack 5-tuples sharing the given
// allow-rule FlowKey and surgically FlushConn's each, so a revoke kills EXACTLY
// the revoked admission's established flows and leaves same-allow-tuple siblings
// (different source port) alive. Called only when the eBPF/XDP+IPv4 surgical
// path is wired (a.surgicalConnFlush != nil, i.e. EBPFXDP-on-Linux).
//
// Per-key decision tree (the order matters for getting the v6 metric right —
// see the IPv6 note on flushEntryNow):
//
//   - IPv6 key → MetricRevocationIPv6HardFail and RETURN. conn_track is v4-only;
//     there is no entry to enumerate or delete, and the coarse allow-rule flush
//     (also v4-only) won't drop it either — the flow dies at kernel TTL. This is
//     an explicit hard-fail, NOT a silent success.
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
	if !isFlowKeyIPv4(key) {
		// v6 under EBPFXDP: no surgical path, coarse path is v4-only too.
		a.incrMetric(MetricRevocationIPv6HardFail)
		log.Warning("[Revocation] IPv6 flow %s under eBPF/XDP has no surgical conntrack teardown (conn_track is IPv4-only); flow will persist until kernel TTL (#2778)", key)
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

// isFlowKeyIPv4 reports whether both endpoints of a FlowKey are IPv4 (stored in
// IPv4-mapped [16]byte form). The conntrack map and the eBPF allow-rule maps are
// IPv4-only; this is the cross-platform gate the surgical-revocation path uses
// to split v4 (enumerate + FlushConn) from v6 (hard-fail). net.IP.To4 returns
// non-nil exactly for the IPv4-mapped form MakeFlowKey produces for v4 inputs.
func isFlowKeyIPv4(key FlowKey) bool {
	return net.IP(key.SrcIP[:]).To4() != nil && net.IP(key.DstIP[:]).To4() != nil
}
