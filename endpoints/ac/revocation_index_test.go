package ac

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
)

// newTestACWithScheduler builds a UdpAC wired with a real tokenStore, a fresh
// revocation index, and a started L3 flush scheduler backed by a recording
// flusher, so apply→flush can be observed end-to-end. It also installs a real
// in-memory metrics publisher so the revocation apply-path counters are fenced.
func newTestACWithScheduler(t *testing.T) (*UdpAC, *recordingFlusher) {
	t.Helper()
	f := newRecordingFlusher()
	sched := NewScheduler(f, WithTickInterval(2*time.Millisecond), WithWheelSize(256))
	sched.Start()
	t.Cleanup(func() { shutdownOrFail(t, sched) })

	a := &UdpAC{
		tokenStore:   common.NewTokenStore[*AccessEntry](),
		revIndex:     newRevocationIndex(),
		nhpSessions:  newNHPSessionIndex(),
		expirySched:  sched,
		registration: &ACRegistration{metrics: metrics.NewPublisherForTest(t)},
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
		QurlSessionId:         sessionID,
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

func (r *recordingFlusher) snapshotAuthoritative() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]bool, len(r.authoritative))
	copy(out, r.authoritative)
	return out
}

// dimCounter reads counters emitted through addMetric/AddCounterWithDims with
// no dimensions. NewPublisherForTest has no base dims, so the dim-counter key
// is the metric name itself.
func dimCounter(t *testing.T, a *UdpAC, name string) float64 {
	t.Helper()
	if dims := a.registration.metrics.DimensionsForTest(t); len(dims) != 0 {
		t.Fatalf("dimCounter assumes no base dims, got %d", len(dims))
	}
	_, dimCounters := a.registration.metrics.CountersForTest(t)
	return dimCounters[name]
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

func TestRevocationIndex_SweepLastEpochPrunesOnlyInactiveExpiredWatermarks(t *testing.T) {
	ri := newRevocationIndex()
	now := time.Unix(1_725_000_000, 0)
	ri.now = func() time.Time { return now }

	if !ri.admitEpoch(scopeQurl, "qOld", 1) {
		t.Fatal("first qOld epoch should apply")
	}
	live := qurlV2Entry("qLive", "rLive", "", "aLive")
	ri.add("tok-live", live)
	if !ri.admitEpoch(scopeQurl, "qLive", 3) {
		t.Fatal("first qLive epoch should apply")
	}

	now = now.Add(revocationWatermarkTTL - time.Second)
	if !ri.admitEpoch(scopeQurl, "qFresh", 2) {
		t.Fatal("first qFresh epoch should apply")
	}

	now = time.Unix(1_725_000_000, 0).Add(revocationWatermarkTTL + time.Nanosecond)
	if removed := ri.sweepLastEpoch(revocationWatermarkTTL); removed != 1 {
		t.Fatalf("sweep removed %d watermarks, want 1 inactive+expired", removed)
	}
	if ri.peekStale(scopeQurl, "qOld", 1) {
		t.Fatal("expired inactive qOld watermark should be pruned")
	}
	if !ri.peekStale(scopeQurl, "qLive", 3) {
		t.Fatal("live qLive watermark must survive even when older than TTL")
	}
	if ri.admitEpoch(scopeQurl, "qLive", 2) {
		t.Fatal("older qLive epoch should remain rejected after sweep preserves the live watermark")
	}
	if !ri.peekStale(scopeQurl, "qFresh", 2) {
		t.Fatal("fresh inactive qFresh watermark should survive until TTL")
	}
	if got := ri.watermarkCount(); got != 2 {
		t.Fatalf("watermarkCount = %d, want 2 after first sweep", got)
	}

	ri.remove("tok-live", live)
	if removed := ri.sweepLastEpoch(revocationWatermarkTTL); removed != 1 {
		t.Fatalf("second sweep removed %d watermarks, want 1 newly-inactive expired live key", removed)
	}
	if ri.peekStale(scopeQurl, "qLive", 3) {
		t.Fatal("qLive watermark should prune once the key is inactive and past TTL")
	}
	if got := ri.watermarkCount(); got != 1 {
		t.Fatalf("watermarkCount = %d, want only qFresh remaining", got)
	}
}

func TestRevocationIndex_SweepLastEpochAllowsSameEpochAfterPrune(t *testing.T) {
	ri := newRevocationIndex()
	now := time.Unix(1_725_010_000, 0)
	ri.now = func() time.Time { return now }

	if !ri.admitEpoch(scopeQurl, "qPruned", 7) {
		t.Fatal("first qPruned epoch should apply")
	}
	now = now.Add(revocationWatermarkTTL + time.Nanosecond)
	if removed := ri.sweepLastEpoch(revocationWatermarkTTL); removed != 1 {
		t.Fatalf("sweep removed %d watermarks, want 1 inactive+expired", removed)
	}
	if !ri.admitEpoch(scopeQurl, "qPruned", 7) {
		t.Fatal("same epoch should apply again after its inactive watermark is pruned")
	}
}

func TestRevocationIndex_SweepLastEpochConcurrentWithAdmitEpoch(t *testing.T) {
	ri := newRevocationIndex()

	live := qurlV2Entry("qRaceLive", "rRaceLive", "", "aRaceLive")
	ri.add("tok-live", live)
	if !ri.admitEpoch(scopeQurl, "qRaceLive", 1) {
		t.Fatal("first qRaceLive epoch should apply")
	}

	const (
		writers    = 8
		sweepers   = 2
		iterations = 200
	)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < writers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				key := "qRace-" + strconv.Itoa(g) + "-" + strconv.Itoa(i)
				if !ri.admitEpoch(scopeQurl, key, uint64(i+1)) {
					t.Errorf("first epoch for %s should apply", key)
				}
			}
		}()
	}
	for g := 0; g < sweepers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				ri.sweepLastEpoch(time.Nanosecond)
			}
		}()
	}

	close(start)
	wg.Wait()

	if !ri.peekStale(scopeQurl, "qRaceLive", 1) {
		t.Fatal("live qRaceLive watermark must survive concurrent inactive sweeps")
	}
}

func TestACRegistration_RevocationWatermarksGauge(t *testing.T) {
	ri := newRevocationIndex()
	reg := &ACRegistration{ac: &UdpAC{revIndex: ri}}

	if got := reg.revocationWatermarksGauge(); got != 0 {
		t.Fatalf("empty revocationWatermarksGauge = %v, want 0", got)
	}
	if !ri.admitEpoch(scopeQurl, "qGauge", 1) {
		t.Fatal("first qGauge epoch should apply")
	}
	if !ri.admitEpoch(scopeResource, "rGauge", 1) {
		t.Fatal("first rGauge epoch should apply")
	}
	if got := reg.revocationWatermarksGauge(); got != 2 {
		t.Fatalf("revocationWatermarksGauge = %v, want 2", got)
	}

	reg.ac.revIndex = nil
	if got := reg.revocationWatermarksGauge(); got != 0 {
		t.Fatalf("nil revIndex revocationWatermarksGauge = %v, want 0", got)
	}
	reg.ac = nil
	if got := reg.revocationWatermarksGauge(); got != 0 {
		t.Fatalf("nil AC revocationWatermarksGauge = %v, want 0", got)
	}
}

func TestUdpAC_RevocationWatermarkSweepLoopPrunesEmitsMetricAndStops(t *testing.T) {
	ri := newRevocationIndex()
	now := time.Unix(1_725_020_000, 0)
	ri.now = func() time.Time { return now }
	if !ri.admitEpoch(scopeQurl, "qSweepLoop", 1) {
		t.Fatal("first qSweepLoop epoch should apply")
	}
	now = now.Add(revocationWatermarkTTL + time.Nanosecond)

	publisher := metrics.NewPublisherForTest(t)
	a := &UdpAC{
		revIndex:     ri,
		registration: &ACRegistration{metrics: publisher},
	}
	a.signals.stop = make(chan struct{})
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.runRevocationWatermarkSweepLoop(ticks)
	}()

	select {
	case ticks <- now:
	case <-time.After(time.Second):
		t.Fatal("timed out sending sweep tick")
	}
	waitForMetricValue(t, publisher, MetricRevocationWatermarksPruned, 1)
	if got := ri.watermarkCount(); got != 0 {
		t.Fatalf("watermarkCount = %d after sweep loop tick, want 0", got)
	}

	close(a.signals.stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sweep loop did not stop after signals.stop closed")
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

func waitForMetricValue(t *testing.T, publisher *metrics.Publisher, name string, want float64) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if got := counterValueForTest(t, publisher, name); got == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("%s counter did not reach %v; got %v", name, want, counterValueForTest(t, publisher, name))
		case <-tick.C:
		}
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
	if got := dimCounter(t, a, MetricRevocationEntriesFlushed); got != 1 {
		t.Fatalf("%s = %v, want 1 via AddCounterWithDims", MetricRevocationEntriesFlushed, got)
	}
	if got := counterValue(t, a, MetricRevocationFlushScheduled); got != 1 {
		t.Fatalf("%s = %v, want 1", MetricRevocationFlushScheduled, got)
	}
	if got := counterValue(t, a, MetricRevocationStaleDropped); got != 0 {
		t.Fatalf("%s = %v before duplicate, want 0", MetricRevocationStaleDropped, got)
	}

	// Entry removed from tokenStore so a re-knock cannot extend it.
	if _, found := a.tokenStore.Load(token); found {
		t.Fatalf("revoked entry still in tokenStore; re-knock could extend it")
	}
	// And deindexed.
	if toks := a.revIndex.tokensFor(scopeQurl, "qhashX"); len(toks) != 0 {
		t.Fatalf("revoked entry still indexed: %v", toks)
	}

	t.Run("duplicate after apply ticks stale metric", func(t *testing.T) {
		// A post-apply duplicate has no live entry, but it has a seen epoch and
		// must still tick the replay/stale metric without adding another flush
		// count.
		if n := a.ApplyRevocation(scopeQurl, "qhashX", 1); n != 0 {
			t.Fatalf("duplicate revoke flushed %d, want 0", n)
		}
		if got := counterValue(t, a, MetricRevocationStaleDropped); got != 1 {
			t.Fatalf("%s = %v after duplicate, want 1", MetricRevocationStaleDropped, got)
		}
		if got := dimCounter(t, a, MetricRevocationEntriesFlushed); got != 1 {
			t.Fatalf("%s = %v after duplicate, want unchanged 1", MetricRevocationEntriesFlushed, got)
		}
		if got := counterValue(t, a, MetricRevocationFlushScheduled); got != 1 {
			t.Fatalf("%s = %v after duplicate, want unchanged 1", MetricRevocationFlushScheduled, got)
		}
	})
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
	if got := dimCounter(t, a, MetricRevocationEntriesFlushed); got != 1 {
		t.Fatalf("%s = %v after first apply, want 1", MetricRevocationEntriesFlushed, got)
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
	if got := counterValue(t, a, MetricRevocationStaleDropped); got != 2 {
		t.Fatalf("%s = %v after stale+duplicate, want 2", MetricRevocationStaleDropped, got)
	}
	if got := dimCounter(t, a, MetricRevocationEntriesFlushed); got != 1 {
		t.Fatalf("%s = %v after stale+duplicate, want unchanged 1", MetricRevocationEntriesFlushed, got)
	}
	// The replayed entry must still be alive — stale events did nothing.
	if _, found := a.tokenStore.Load(tok2); !found {
		t.Fatalf("entry wrongly removed by a stale/duplicate epoch")
	}

	// A strictly newer epoch (6) applies and removes it.
	if n := a.ApplyRevocation(scopeQurl, "qE", 6); n != 1 {
		t.Fatalf("newer epoch 6 should apply, flushed %d", n)
	}
	if got := dimCounter(t, a, MetricRevocationEntriesFlushed); got != 2 {
		t.Fatalf("%s = %v after epoch 6, want 2", MetricRevocationEntriesFlushed, got)
	}
	if _, found := a.tokenStore.Load(tok2); found {
		t.Fatalf("entry should be gone after epoch 6")
	}
}

func TestApplyRevocation_ConcurrentDuplicateEpochAppliesOnce(t *testing.T) {
	a, _ := newTestACWithScheduler(t)
	token := a.GenerateAccessToken(qurlV2Entry("qConcurrent", "rConcurrent", "", "aConcurrent"))

	const goroutines = 32
	start := make(chan struct{})
	results := make(chan int, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			results <- a.ApplyRevocation(scopeQurl, "qConcurrent", 7)
		}()
	}

	close(start)
	wg.Wait()
	close(results)

	total := 0
	for n := range results {
		total += n
	}
	if total != 1 {
		t.Fatalf("concurrent duplicate revokes flushed %d total entries, want exactly 1", total)
	}
	if _, found := a.tokenStore.Load(token); found {
		t.Fatalf("entry should be gone after the one admitted concurrent revoke")
	}
	if got := dimCounter(t, a, MetricRevocationEntriesFlushed); got != 1 {
		t.Fatalf("%s = %v, want 1", MetricRevocationEntriesFlushed, got)
	}
	if got := counterValue(t, a, MetricRevocationStaleDropped); got != goroutines-1 {
		t.Fatalf("%s = %v, want %d duplicate drops", MetricRevocationStaleDropped, got, goroutines-1)
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

// TestFlushEntryNow_StillFiresAfterTokenDeleted fences the load-bearing
// assumption behind the #2784 under-flush interim: deleteThenFlushEntry calls
// deleteToken BEFORE flushEntryNow (delete-first removes the entry from the
// tokenStore snapshot a concurrent sibling expiry reads, closing the dominant
// longest-wins push-back). That order is only safe because flushEntryNow drains
// the tracked FlowKeys off the entry POINTER, not via a tokenStore re-Load — so
// the flush must still fire after the entry is gone from tokenStore and the
// revocation index.
//
// This test puts the AC in the exact post-delete state (entry removed from both
// tokenStore and the index) and then calls flushEntryNow directly, asserting the
// scheduled flow is still pulled to now and flushed. A regression that makes
// flushEntryNow look the entry up in tokenStore (it would find nothing
// post-delete) — or that drops the off-pointer drain — turns the immediate
// revoke into a silent no-op and turns this test red.
//
// Note on scope: the deleteToken/flushEntryNow ORDER itself is not observable
// from a single goroutine — both run synchronously and leave identical end
// state, so only a concurrent sibling expiry can tell the two orders apart (see
// the deleteThenFlushEntry godoc). This test fences the invariant the order
// depends on, which IS deterministically observable.
func TestFlushEntryNow_StillFiresAfterTokenDeleted(t *testing.T) {
	a, flusher := newTestACWithScheduler(t)

	// Admit a qURL v2 entry and schedule its flow key. The deadline is an
	// arbitrary far-future value (well beyond the 2s wait below); its exact
	// value — and the entry's OpenTime — are irrelevant here because
	// flushEntryNow's RescheduleEarlier pulls the key to now regardless of the
	// original deadline. recordScheduledKey + Schedule mirror what the admission
	// path does via scheduleFlushIfEnabled.
	entry := qurlV2Entry("qDel", "rDel", "", "aDel")
	token := a.GenerateAccessToken(entry) // storeToken → tokenStore + index
	key := mustKey(t, "203.0.113.7", "198.51.100.7", 443, FlowProtoTCP)
	entry.recordScheduledKey(key)
	a.expirySched.Schedule(key, time.Now().Add(30*time.Second))

	// Put the AC in ApplyRevocation's post-delete state: entry gone from
	// tokenStore AND deindexed, BEFORE the flush runs.
	a.deleteToken(token, entry)
	if _, found := a.tokenStore.Load(token); found {
		t.Fatalf("precondition: entry must be removed from tokenStore before flushEntryNow")
	}
	if toks := a.revIndex.tokensFor(scopeQurl, "qDel"); len(toks) != 0 {
		t.Fatalf("precondition: entry must be deindexed before flushEntryNow, got %v", toks)
	}
	// The entry pointer must still carry its tracked key — deleteToken does not
	// touch scheduledKeys; that is exactly what lets the off-pointer drain work.
	if !entry.holdsScheduledKey(key) {
		t.Fatalf("precondition: deleteToken must not drain the entry's scheduledKeys")
	}

	// flushEntryNow must still drain the key off the entry pointer and pull it to
	// now — NOT depend on a tokenStore lookup that would now miss.
	a.flushEntryNow(entry)

	if !flusher.waitFor(1, 2*time.Second) {
		t.Fatalf("flushEntryNow did not fire after the entry was deleted; flusher saw %d (off-pointer drain regressed?)", flusher.count())
	}
	if got := flusher.snapshotKeys(); len(got) != 1 || got[0] != key {
		t.Fatalf("flushed wrong key after delete: got %v want [%v]", got, key)
	}
}

// TestApplyRevocation_DeleteBeforeFlushOrderPreventsSiblingPushBack fences the
// #2784 order itself inside ApplyRevocation/deleteThenFlushEntry. The observable
// bad interleaving is:
//
//  1. revoked entry A and sibling B share one FlowKey;
//  2. ApplyRevocation for A reaches the delete/flush pair;
//  3. B expires in the tiny window between A's deleteToken and flushEntryNow.
//
// With the required delete-before-flush order, B's cancelAllScheduledFlows
// snapshot no longer sees A and must Cancel the shared key (EntryCount 0). If a
// future edit reverses the order to flush-before-delete, this test blocks inside
// flushEntryNow before A is deleted and times out waiting for the delete to
// become visible, making the regression deterministic instead of timing-based.
func TestApplyRevocation_DeleteBeforeFlushOrderPreventsSiblingPushBack(t *testing.T) {
	a, flusher := newTestACWithScheduler(t)
	const srcIP, dstIP, dstPort = "198.51.100.30", "203.0.113.30", 443
	key := mustKey(t, srcIP, dstIP, dstPort, FlowProtoTCP)
	const openSeconds = 600

	entryA := qurlV2Entry("qOrderA", "rSharedOrder", "", "aOrderA")
	entryB := qurlV2Entry("qOrderB", "rSharedOrder", "", "aOrderB")
	entryA.OpenTime, entryB.OpenTime = openSeconds, openSeconds
	tokA := a.GenerateAccessToken(entryA)
	_ = a.GenerateAccessToken(entryB) // stored so B is live; never revoked

	deadline := time.Now().Add(time.Duration(openSeconds) * time.Second)
	a.scheduleFlushIfEnabled(entryA, srcIP, dstIP, dstPort, FlowProtoTCP, deadline)
	a.scheduleFlushIfEnabled(entryB, srcIP, dstIP, dstPort, FlowProtoTCP, deadline)
	if got := a.expirySched.EntryCount(); got != 1 {
		t.Fatalf("precondition: EntryCount = %d, want 1 (shared key absorbed by longest-wins)", got)
	}

	// Stress note: run this with -race/-count=N to re-check the deterministic
	// interleave; the lock gate, not goroutine timing, is what makes it stable.
	// Hold A's entry lock so delete-before-flush reaches deleteToken, then blocks
	// when flushEntryNow tries to drain A's scheduled keys. A flush-before-delete
	// regression blocks before the delete instead, and the wait below fails.
	entryA.mu.Lock()
	unlockA := sync.OnceFunc(entryA.mu.Unlock)
	defer unlockA()

	done := make(chan int, 1)
	go func() {
		done <- a.ApplyRevocation(scopeQurl, "qOrderA", 1)
	}()

	if !waitUntil(func() bool {
		return len(a.revIndex.tokensFor(scopeQurl, "qOrderA")) == 0
	}, 2*time.Second) {
		unlockA()
		select {
		case <-done:
			t.Fatal("ApplyRevocation finished without deindexing the revoked entry before entering flushEntryNow")
		case <-time.After(2 * time.Second):
			t.Fatal("ApplyRevocation stayed blocked before deindexing; delete-before-flush order likely regressed or deleteToken now waits on AccessEntry.mu")
		}
	}
	if _, found := a.tokenStore.Load(tokA); found {
		t.Fatal("revoked entry still in tokenStore after deindexing between deleteToken and flushEntryNow")
	}

	// Drive the sibling expiry while A's flush is still blocked in the
	// post-delete/pre-flush window. A must be absent from B's tokenStore snapshot,
	// so B cancels the shared scheduler entry rather than pushing it back to A's
	// future deadline.
	a.cancelAllScheduledFlows(entryB)
	if got := a.expirySched.EntryCount(); got != 0 {
		t.Fatalf("EntryCount after sibling expiry between delete and flush = %d, want 0; revoked entry was counted as a live holder and pushed the shared key back (#2784)", got)
	}

	unlockA()
	select {
	case n := <-done:
		if n != 1 {
			t.Fatalf("ApplyRevocation flushed %d, want 1", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ApplyRevocation did not finish after releasing the flushEntryNow gate")
	}
	// B canceled the shared scheduler entry above; A's flush must reinsert it
	// via RescheduleEarlier before the flusher fires.
	if !flusher.waitFor(1, 2*time.Second) {
		t.Fatalf("revocation flush did not fire after releasing the gate; flusher saw %d", flusher.count())
	}
	if got := flusher.snapshotKeys(); len(got) != 1 || got[0] != key {
		t.Fatalf("flushed wrong key after releasing gate: got %v want [%v]", got, key)
	}
}

// TestUdpAC_CancelAllScheduledFlows_DeletedHolderNotCountedKeyCanceled fences the
// behavioral claim of the #2784 under-flush fix (not just its enabling
// off-pointer-drain invariant): once the revoked entry is removed from tokenStore
// (deleteThenFlushEntry's deleteToken step), a concurrent sibling's
// cancelAllScheduledFlows must CANCEL the shared FlowKey rather than re-Schedule
// (push back) the just-revoked deadline — because the revoked entry is gone from
// the Snapshot the cancel walks, even though its pointer still holds the key.
//
// It is the deterministic counterpart to
// TestUdpAC_CancelAllScheduledFlows_MultiSessionRaceKeepsKeyAlive: there the peer
// is STILL in tokenStore (a live holder) and the shared key is KEPT ALIVE; here
// the peer has been deleted (the revoke's delete-first step) and the key is
// CANCELED. The delete is exactly the lever that flips push-back → cancel: with
// the entry still present that mirror test asserts EntryCount 1, with it deleted
// this one asserts EntryCount 0.
//
// Scope: this drives the building blocks (deleteToken + cancelAllScheduledFlows)
// directly to reconstruct the exact post-delete snapshot state. The companion
// TestApplyRevocation_DeleteBeforeFlushOrderPreventsSiblingPushBack fences the
// ApplyRevocation/deleteThenFlushEntry order end-to-end; this test isolates the
// snapshot-membership property that flip depends on.
func TestUdpAC_CancelAllScheduledFlows_DeletedHolderNotCountedKeyCanceled(t *testing.T) {
	a, _ := newTestACWithScheduler(t)
	const srcIP, dstIP, dstPort = "198.51.100.20", "203.0.113.20", 443
	key := mustKey(t, srcIP, dstIP, dstPort, FlowProtoTCP)

	// A (revoked) and B (sibling) share one network-shaped FlowKey. A long
	// OpenTime keeps both firewall deadlines far in the future for the whole test
	// (so the shared scheduler entry is never close to firing on its own).
	entryA := qurlV2Entry("qA", "rShared", "", "aA")
	entryB := qurlV2Entry("qB", "rShared", "", "aB")
	entryA.OpenTime, entryB.OpenTime = 600, 600
	tokA := a.GenerateAccessToken(entryA) // storeToken → tokenStore + index; stamps FirstKnockTime=now
	_ = a.GenerateAccessToken(entryB)

	// Both schedule the shared key; longest-wins absorbs to a single scheduler entry.
	deadline := time.Now().Add(600 * time.Second)
	a.scheduleFlushIfEnabled(entryA, srcIP, dstIP, dstPort, FlowProtoTCP, deadline)
	a.scheduleFlushIfEnabled(entryB, srcIP, dstIP, dstPort, FlowProtoTCP, deadline)
	if got := a.expirySched.EntryCount(); got != 1 {
		t.Fatalf("precondition: EntryCount = %d, want 1 (shared key absorbed by longest-wins)", got)
	}

	// The revoke's delete-first step (deleteThenFlushEntry's deleteToken): A leaves
	// tokenStore. Its pointer still holds the key — flushEntryNow drains off the
	// pointer, not tokenStore — but it is now absent from the Snapshot a sibling's
	// cancelAllScheduledFlows walks.
	a.deleteToken(tokA, entryA)
	if !entryA.holdsScheduledKey(key) {
		t.Fatalf("precondition: deleteToken must not drain entryA's scheduledKeys")
	}

	// B expires naturally. With A gone from the snapshot, B finds no other live
	// holder and CANCELS the shared key — it must NOT re-Schedule it back to a
	// future firewall deadline (the under-flush push-back the fix prevents).
	a.cancelAllScheduledFlows(entryB)
	if got := a.expirySched.EntryCount(); got != 0 {
		t.Fatalf("EntryCount after sibling expiry = %d, want 0 — a deleted (revoked) entry was wrongly counted as a live holder and the shared key was pushed back (#2784 under-flush)", got)
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
	if got := f.snapshotAuthoritative(); len(got) != 1 || !got[0] {
		t.Fatalf("RescheduleEarlier flush authoritative flags = %v, want [true]", got)
	}

	// RescheduleEarlier must NOT push a deadline later: an entry already due
	// sooner stays put (shortest-wins skip).
	keyC := mustKey(t, "203.0.113.3", "198.51.100.3", 443, FlowProtoTCP)
	sched.Schedule(keyC, time.Now()) // due now
	sched.RescheduleEarlier(keyC, time.Now().Add(30*time.Second))
	if !f.waitFor(2, 2*time.Second) {
		t.Fatalf("RescheduleEarlier wrongly delayed a sooner deadline; flusher saw %d", f.count())
	}
	if got := f.snapshotAuthoritative(); len(got) != 2 || !got[1] {
		t.Fatalf("RescheduleEarlier shortest-wins flush authoritative flags = %v, want second true", got)
	}
}
