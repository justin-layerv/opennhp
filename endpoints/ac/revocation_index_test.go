package ac

import (
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// newTestACWithScheduler builds a UdpAC wired with a real tokenStore, a fresh
// revocation index, and a started L3 flush scheduler backed by a recording
// flusher, so apply→flush can be observed end-to-end. registration is left nil;
// incrMetric/addMetric are nil-safe so the revocation metrics no-op in tests.
func newTestACWithScheduler(t *testing.T) (*UdpAC, *recordingFlusher) {
	t.Helper()
	f := newRecordingFlusher()
	sched := NewScheduler(f, WithTickInterval(2*time.Millisecond), WithWheelSize(256))
	sched.Start()
	t.Cleanup(func() { shutdownOrFail(t, sched) })

	a := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		revIndex:    newRevocationIndex(),
		expirySched: sched,
	}
	a.installExpiryHook()
	return a, f
}

// qurlV2Entry builds an AccessEntry carrying the P4a revocation metadata under
// test. SessionId is set only when sessionID != "" so the session-seam case can
// be exercised explicitly.
func qurlV2Entry(qurlHash, resHash, sessionID, admissionID string) *AccessEntry {
	return &AccessEntry{
		OpenTime:              10,
		QurlUserPublicKeyHash: qurlHash,
		ResourcePublicKeyHash: resHash,
		SessionId:             sessionID,
		AdmissionId:           admissionID,
	}
}

// keys returns a copy of the FlowKeys the recording flusher has seen.
func (r *recordingFlusher) snapshotKeys() []FlowKey {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]FlowKey, len(r.keys))
	copy(out, r.keys)
	return out
}

func TestRevocationIndex_AddLookupRemove(t *testing.T) {
	ri := newRevocationIndex()
	entry := qurlV2Entry("qhash1", "rhash1", "sess1", "adm1")

	// add → every scope key resolves to the token.
	ri.add("tokenA", entry)
	for _, tc := range []struct {
		scope revocationScope
		key   string
	}{
		{scopeQurl, "qhash1"},
		{scopeResource, "rhash1"},
		{scopeSession, "sess1"},
		{scopeAdmission, "adm1"},
	} {
		toks := ri.tokensFor(tc.scope, tc.key)
		if len(toks) != 1 || toks[0] != "tokenA" {
			t.Fatalf("after add: tokensFor(%s,%s)=%v, want [tokenA]", tc.scope, tc.key, toks)
		}
	}

	// remove → all scope keys go empty.
	ri.remove("tokenA", entry)
	for _, tc := range []struct {
		scope revocationScope
		key   string
	}{
		{scopeQurl, "qhash1"},
		{scopeResource, "rhash1"},
		{scopeSession, "sess1"},
		{scopeAdmission, "adm1"},
	} {
		if toks := ri.tokensFor(tc.scope, tc.key); len(toks) != 0 {
			t.Fatalf("after remove: tokensFor(%s,%s)=%v, want empty", tc.scope, tc.key, toks)
		}
	}
}

func TestRevocationIndex_MultipleTokensUnderResource(t *testing.T) {
	ri := newRevocationIndex()
	// Two different qURLs (distinct qurl hashes / sessions) for the SAME
	// resource — a resource-scope revoke must hit both.
	e1 := qurlV2Entry("q1", "sharedRes", "s1", "a1")
	e2 := qurlV2Entry("q2", "sharedRes", "s2", "a2")
	ri.add("tok1", e1)
	ri.add("tok2", e2)

	toks := ri.tokensFor(scopeResource, "sharedRes")
	if len(toks) != 2 {
		t.Fatalf("resource scope should resolve both tokens, got %v", toks)
	}
	// qURL scope is per-qURL: only the one token.
	if toks := ri.tokensFor(scopeQurl, "q1"); len(toks) != 1 || toks[0] != "tok1" {
		t.Fatalf("qurl scope q1 = %v, want [tok1]", toks)
	}

	// Removing one leaves the other under the shared resource key.
	ri.remove("tok1", e1)
	toks = ri.tokensFor(scopeResource, "sharedRes")
	if len(toks) != 1 || toks[0] != "tok2" {
		t.Fatalf("after removing tok1, resource scope = %v, want [tok2]", toks)
	}
}

func TestRevocationIndex_AddIdempotent(t *testing.T) {
	ri := newRevocationIndex()
	entry := qurlV2Entry("q", "r", "", "a")
	ri.add("tok", entry)
	ri.add("tok", entry) // re-store (refresh path) must not duplicate
	if toks := ri.tokensFor(scopeQurl, "q"); len(toks) != 1 {
		t.Fatalf("re-add should be idempotent, got %v", toks)
	}
}

func TestScopeKeysForEntry_LegacyAndSessionSeam(t *testing.T) {
	// Legacy / non-qURL-v2 entry: no metadata → no index keys at all.
	if got := scopeKeysForEntry(&AccessEntry{OpenTime: 5}); len(got) != 0 {
		t.Fatalf("legacy entry should yield no index keys, got %v", got)
	}
	// session_id seam: empty SessionId (pre qurl-service #1010) must NOT produce a
	// session key, but the other dimensions still index.
	got := scopeKeysForEntry(qurlV2Entry("q", "r", "", "a"))
	for _, k := range got {
		if k.scope == scopeSession {
			t.Fatalf("empty SessionId must not be indexed, got key %v", k)
		}
	}
	if len(got) != 3 { // qurl, resource, admission
		t.Fatalf("expected 3 keys (qurl,resource,admission) with empty session, got %v", got)
	}
	// Populated SessionId (post qurl-service #1010) indexes the session dimension.
	got = scopeKeysForEntry(qurlV2Entry("q", "r", "sess", "a"))
	if len(got) != 4 {
		t.Fatalf("expected 4 keys with populated session, got %v", got)
	}
}

func TestApplyRevocation_FlushesAndDeletesMatchingEntry(t *testing.T) {
	a, flusher := newTestACWithScheduler(t)

	// Admit a qURL v2 entry and schedule its flow key (mirrors what the
	// admission path does via scheduleFlushIfEnabled).
	entry := qurlV2Entry("qhashX", "rhashX", "", "admX")
	token := a.GenerateAccessToken(entry) // stores + indexes
	key := mustKey(t, "203.0.113.5", "198.51.100.9", 443, FlowProtoTCP)
	entry.recordScheduledKey(key)
	a.expirySched.Schedule(key, time.Now().Add(10*time.Second)) // far-future normal expiry

	// Sanity: indexed and present.
	if toks := a.revIndex.tokensFor(scopeQurl, "qhashX"); len(toks) != 1 {
		t.Fatalf("entry not indexed under qurl scope: %v", toks)
	}

	n := a.ApplyRevocation(scopeQurl, "qhashX", 1)
	if n != 1 {
		t.Fatalf("ApplyRevocation flushed %d, want 1", n)
	}

	// The flusher must have fired for exactly the revoked entry's key,
	// immediately — not at the 10s normal deadline.
	if !flusher.waitFor(1, 2*time.Second) {
		t.Fatalf("expected immediate flush of revoked flow, flusher saw %d", flusher.count())
	}
	if got := flusher.snapshotKeys(); len(got) != 1 || got[0] != key {
		t.Fatalf("flushed wrong key: got %v want [%v]", got, key)
	}

	// Entry removed from tokenStore so a re-knock cannot extend it.
	if _, found := a.tokenStore.Load(token); found {
		t.Fatalf("revoked entry still in tokenStore; re-knock could extend it")
	}
	// And deindexed.
	if toks := a.revIndex.tokensFor(scopeQurl, "qhashX"); len(toks) != 0 {
		t.Fatalf("revoked entry still indexed: %v", toks)
	}
}

func TestApplyRevocation_OnlyTargetEntryRemovedUnderResource(t *testing.T) {
	a, _ := newTestACWithScheduler(t)

	// Two qURLs under the same resource; revoke ONE by qURL scope must not
	// remove the sibling's tokenStore entry / index.
	e1 := qurlV2Entry("qA", "resShared", "", "aA")
	e2 := qurlV2Entry("qB", "resShared", "", "aB")
	tok1 := a.GenerateAccessToken(e1)
	tok2 := a.GenerateAccessToken(e2)

	if n := a.ApplyRevocation(scopeQurl, "qA", 1); n != 1 {
		t.Fatalf("revoke qA flushed %d, want 1", n)
	}
	if _, found := a.tokenStore.Load(tok1); found {
		t.Fatalf("qA entry should be gone")
	}
	if _, found := a.tokenStore.Load(tok2); !found {
		t.Fatalf("qB entry must survive a qA-scoped revoke")
	}
	// Resource index now resolves only the survivor.
	if toks := a.revIndex.tokensFor(scopeResource, "resShared"); len(toks) != 1 || toks[0] != tok2 {
		t.Fatalf("resource index after revoke = %v, want [%s]", toks, tok2)
	}
}

func TestApplyRevocation_ResourceScopeKillsAllQurls(t *testing.T) {
	a, _ := newTestACWithScheduler(t)
	tok1 := a.GenerateAccessToken(qurlV2Entry("q1", "res1", "", "a1"))
	tok2 := a.GenerateAccessToken(qurlV2Entry("q2", "res1", "", "a2"))

	if n := a.ApplyRevocation(scopeResource, "res1", 1); n != 2 {
		t.Fatalf("resource revoke flushed %d, want 2", n)
	}
	if _, f1 := a.tokenStore.Load(tok1); f1 {
		t.Fatalf("tok1 should be gone after resource revoke")
	}
	if _, f2 := a.tokenStore.Load(tok2); f2 {
		t.Fatalf("tok2 should be gone after resource revoke")
	}
}

func TestApplyRevocation_EpochIdempotencyDropsStale(t *testing.T) {
	a, _ := newTestACWithScheduler(t)
	tokFor := func(q string) (*AccessEntry, string) {
		e := qurlV2Entry(q, "r", "", "a-"+q)
		return e, a.GenerateAccessToken(e)
	}

	// epoch 5 applied.
	_, _ = tokFor("qE")
	if n := a.ApplyRevocation(scopeQurl, "qE", 5); n != 1 {
		t.Fatalf("epoch 5 should apply, flushed %d", n)
	}

	// Re-admit the same qURL hash (a fresh session/token), then replay older
	// and equal epochs — both must be DROPPED (no flush, returns 0).
	_, tok2 := tokFor("qE")
	if n := a.ApplyRevocation(scopeQurl, "qE", 4); n != 0 {
		t.Fatalf("stale epoch 4 must be dropped, flushed %d", n)
	}
	if n := a.ApplyRevocation(scopeQurl, "qE", 5); n != 0 {
		t.Fatalf("duplicate epoch 5 must be dropped, flushed %d", n)
	}
	// The replayed entry must still be alive — stale events did nothing.
	if _, found := a.tokenStore.Load(tok2); !found {
		t.Fatalf("entry wrongly removed by a stale/duplicate epoch")
	}

	// A strictly newer epoch (6) applies and removes it.
	if n := a.ApplyRevocation(scopeQurl, "qE", 6); n != 1 {
		t.Fatalf("newer epoch 6 should apply, flushed %d", n)
	}
	if _, found := a.tokenStore.Load(tok2); found {
		t.Fatalf("entry should be gone after epoch 6")
	}
}

func TestApplyRevocation_EpochIsPerScopeKey(t *testing.T) {
	a, _ := newTestACWithScheduler(t)
	a.GenerateAccessToken(qurlV2Entry("qOne", "r", "", "a1"))
	a.GenerateAccessToken(qurlV2Entry("qTwo", "r", "", "a2"))

	// epoch 9 on qOne must not raise the watermark for qTwo.
	a.ApplyRevocation(scopeQurl, "qOne", 9)
	if n := a.ApplyRevocation(scopeQurl, "qTwo", 1); n != 1 {
		t.Fatalf("epoch 1 on a different scope key must apply (independent watermark), flushed %d", n)
	}
}

func TestApplyRevocation_NoMatchAndEmptyKeyAreNoOps(t *testing.T) {
	a, _ := newTestACWithScheduler(t)
	if n := a.ApplyRevocation(scopeQurl, "nonexistent", 1); n != 0 {
		t.Fatalf("revoke of unknown key flushed %d, want 0", n)
	}
	if n := a.ApplyRevocation(scopeQurl, "", 1); n != 0 {
		t.Fatalf("revoke of empty scopeKey flushed %d, want 0", n)
	}
}

func TestApplyRevocation_ExpiryDeindexes(t *testing.T) {
	// When an entry expires normally (OnExpire hook), it must be deindexed so
	// a later revoke for its key finds nothing (and does not panic / double-act).
	a, _ := newTestACWithScheduler(t)
	entry := qurlV2Entry("qExp", "rExp", "", "aExp")
	token := a.GenerateAccessToken(entry)
	if toks := a.revIndex.tokensFor(scopeQurl, "qExp"); len(toks) != 1 {
		t.Fatalf("precondition: entry indexed, got %v", toks)
	}

	// Fire the OnExpire hook directly (what CleanExpired does after releasing
	// its lock).
	a.tokenStore.Delete(token) // simulate CleanExpired removal of the map entry
	a.revIndex.remove(token, entry)

	if toks := a.revIndex.tokensFor(scopeQurl, "qExp"); len(toks) != 0 {
		t.Fatalf("expired entry must be deindexed, got %v", toks)
	}
	if n := a.ApplyRevocation(scopeQurl, "qExp", 1); n != 0 {
		t.Fatalf("revoke after expiry should be a no-op, flushed %d", n)
	}
}

// TestApplyRevocation_RealOnExpireHookDeindexes fences the production wiring
// itself: installExpiryHook's SetOnExpire closure must call revIndex.remove, so
// that a qURL v2 entry removed by the normal CleanExpired path is deindexed
// without anyone calling revIndex.remove explicitly. The sibling
// TestApplyRevocation_ExpiryDeindexes simulates expiry by calling
// tokenStore.Delete + revIndex.remove by hand, which would still pass if the
// remove line were dropped from installExpiryHook — this one fires the REAL
// hook via CleanExpired so deleting that line turns the suite red (cr #2776).
func TestApplyRevocation_RealOnExpireHookDeindexes(t *testing.T) {
	a, _ := newTestACWithScheduler(t) // installs the production OnExpire hook
	entry := qurlV2Entry("qHook", "rHook", "", "aHook")
	token := a.GenerateAccessToken(entry) // storeToken → revIndex.add
	if toks := a.revIndex.tokensFor(scopeQurl, "qHook"); len(toks) != 1 {
		t.Fatalf("precondition: entry indexed via storeToken, got %v", toks)
	}

	// Expire the entry and drive the REAL CleanExpired path, which fires the
	// SetOnExpire closure installExpiryHook registered (the exact wiring
	// (*UdpAC).Start uses). No manual revIndex.remove here.
	entry.ExpireTime = time.Now().Add(-1 * time.Minute)
	a.tokenStore.Store(token, entry)
	if got := a.tokenStore.CleanExpired(); got != 1 {
		t.Fatalf("CleanExpired removed %d entries, want 1", got)
	}

	// The deindex must have happened through the hook alone.
	if toks := a.revIndex.tokensFor(scopeQurl, "qHook"); len(toks) != 0 {
		t.Fatalf("OnExpire hook did not deindex via revIndex.remove (installExpiryHook wiring broken), got %v", toks)
	}
	if toks := a.revIndex.tokensFor(scopeResource, "rHook"); len(toks) != 0 {
		t.Fatalf("resource index still holds the expired entry, got %v", toks)
	}
}

// TestApplyRevocation_RevokeBeforeAdmitDoesNotPoisonWatermark pins the
// fail-open closed: a revoke that arrives BEFORE its admission (or on an AC
// that never admitted it) must NOT advance the epoch watermark, so the
// at-least-once redelivery that arrives AFTER admission still applies. With
// the pre-fix ordering (watermark advanced before the index match) the
// redelivery was dropped as epoch<=last and the entry survived — a revoked
// session left alive to natural expiry.
func TestApplyRevocation_RevokeBeforeAdmitDoesNotPoisonWatermark(t *testing.T) {
	a, _ := newTestACWithScheduler(t)

	// Revoke arrives first, nothing admitted yet → no live match.
	if n := a.ApplyRevocation(scopeQurl, "qRace", 1); n != 0 {
		t.Fatalf("revoke before admit should flush nothing, got %d", n)
	}
	// The watermark must be untouched: a brand-new (unseen) key must not be
	// recorded by a no-match revoke.
	if a.revIndex.peekStale(scopeQurl, "qRace", 1) {
		t.Fatalf("no-match revoke wrongly advanced the watermark (epoch 1 now seen as stale)")
	}

	// Now the admission lands.
	entry := qurlV2Entry("qRace", "rRace", "", "aRace")
	token := a.GenerateAccessToken(entry)

	// The SAME epoch-1 revoke is redelivered (at-least-once). It must now apply
	// and tear the entry down — the pre-fix bug dropped it here.
	if n := a.ApplyRevocation(scopeQurl, "qRace", 1); n != 1 {
		t.Fatalf("redelivered revoke after admit must apply, flushed %d (fail-open: entry survived)", n)
	}
	if _, found := a.tokenStore.Load(token); found {
		t.Fatalf("entry survived a redelivered revoke — fail-open watermark poisoning regressed")
	}
}

// TestScheduler_RescheduleEarlier_PullsEarlierVsScheduleNoOp pins the scheduler
// primitive the revocation flush depends on, directly against the
// recording flusher (no UdpAC). It is the unit-level proof of the headline
// core bug: plain Schedule(now) is a no-op against a later-scheduled key
// (longest-wins), while RescheduleEarlier(now) actually fires it.
func TestScheduler_RescheduleEarlier_PullsEarlierVsScheduleNoOp(t *testing.T) {
	f := newRecordingFlusher()
	sched := NewScheduler(f, WithTickInterval(2*time.Millisecond), WithWheelSize(256))
	sched.Start()
	t.Cleanup(func() { shutdownOrFail(t, sched) })

	// Key A: scheduled far in the future, then plain Schedule(now) — longest-
	// wins makes that a no-op, so it must NOT fire within the window.
	keyA := mustKey(t, "203.0.113.1", "198.51.100.1", 443, FlowProtoTCP)
	sched.Schedule(keyA, time.Now().Add(30*time.Second))
	sched.Schedule(keyA, time.Now()) // no-op under longest-wins

	// Key B: scheduled far in the future, then RescheduleEarlier(now) — must
	// fire promptly.
	keyB := mustKey(t, "203.0.113.2", "198.51.100.2", 443, FlowProtoTCP)
	sched.Schedule(keyB, time.Now().Add(30*time.Second))
	sched.RescheduleEarlier(keyB, time.Now())

	if !f.waitFor(1, 2*time.Second) {
		t.Fatalf("RescheduleEarlier(now) did not fire the flush; flusher saw %d", f.count())
	}
	// Exactly key B fired; key A is still parked at its 30s deadline.
	got := f.snapshotKeys()
	if len(got) != 1 || got[0] != keyB {
		t.Fatalf("expected only keyB flushed, got %v", got)
	}

	// RescheduleEarlier must NOT push a deadline later: an entry already due
	// sooner stays put (shortest-wins skip).
	keyC := mustKey(t, "203.0.113.3", "198.51.100.3", 443, FlowProtoTCP)
	sched.Schedule(keyC, time.Now()) // due now
	sched.RescheduleEarlier(keyC, time.Now().Add(30*time.Second))
	if !f.waitFor(2, 2*time.Second) {
		t.Fatalf("RescheduleEarlier wrongly delayed a sooner deadline; flusher saw %d", f.count())
	}
}
