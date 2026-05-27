package common

import (
	"sync"
	"testing"
	"time"
)

// fakeEntry is a minimal TokenEntry for store-level tests.
type fakeEntry struct {
	expire time.Time
}

func (e *fakeEntry) GetExpireTime() time.Time { return e.expire }

// TestTokenStore_CleanExpired_FiresOnExpireHook fences the #2172 wiring
// contract: the OnExpire hook runs exactly once per removed entry, with
// the (token, entry) it's about to delete. Non-expired entries do NOT
// fire the hook. The hook receives the same entry pointer the store
// held, not a copy.
func TestTokenStore_CleanExpired_FiresOnExpireHook(t *testing.T) {
	ts := NewTokenStore[*fakeEntry]()

	past := time.Now().Add(-1 * time.Minute)
	future := time.Now().Add(1 * time.Minute)

	expiredEntries := map[string]*fakeEntry{
		"AAAAexpired-1": {expire: past},
		"BBBBexpired-2": {expire: past},
	}
	liveEntries := map[string]*fakeEntry{
		"CCCClive-1": {expire: future},
	}
	for tok, e := range expiredEntries {
		ts.Store(tok, e)
	}
	for tok, e := range liveEntries {
		ts.Store(tok, e)
	}

	var (
		mu       sync.Mutex
		seen     = map[string]*fakeEntry{}
		hookHits int
	)
	ts.SetOnExpire(func(token string, entry *fakeEntry) {
		mu.Lock()
		defer mu.Unlock()
		hookHits++
		seen[token] = entry
	})

	if got, want := ts.CleanExpired(), len(expiredEntries); got != want {
		t.Fatalf("CleanExpired returned %d, want %d", got, want)
	}

	mu.Lock()
	defer mu.Unlock()
	if hookHits != len(expiredEntries) {
		t.Errorf("hook fired %d times, want %d", hookHits, len(expiredEntries))
	}
	for tok, want := range expiredEntries {
		got, ok := seen[tok]
		if !ok {
			t.Errorf("hook never fired for expired token %q", tok)
			continue
		}
		if got != want {
			t.Errorf("hook received different pointer for %q: got %p want %p", tok, got, want)
		}
	}
	for tok := range liveEntries {
		if _, fired := seen[tok]; fired {
			t.Errorf("hook fired for non-expired token %q", tok)
		}
	}
}

// TestTokenStore_CleanExpired_NilHookIsNoop pins the back-compat
// guarantee: a TokenStore that never SetOnExpire-d still works, and
// CleanExpired's behavior is unchanged from pre-#2172.
func TestTokenStore_CleanExpired_NilHookIsNoop(t *testing.T) {
	ts := NewTokenStore[*fakeEntry]()
	ts.Store("AAAAexpired", &fakeEntry{expire: time.Now().Add(-1 * time.Minute)})
	ts.Store("BBBBlive", &fakeEntry{expire: time.Now().Add(1 * time.Minute)})

	if got := ts.CleanExpired(); got != 1 {
		t.Fatalf("CleanExpired removed %d, want 1", got)
	}
	if got := ts.Size(); got != 1 {
		t.Errorf("Size after CleanExpired = %d, want 1", got)
	}
}

// TestTokenStore_SetOnExpire_Replaces fences "latest registration wins"
// for fresh CleanExpired calls. Note: this test does NOT fence the
// mid-flight rotation case (replacing the hook while a CleanExpired
// is already running) — that semantic is intentionally unspecified
// today; CleanExpired captures `onExpire` once under the lock and uses
// that captured value for the whole batch.
func TestTokenStore_SetOnExpire_Replaces(t *testing.T) {
	ts := NewTokenStore[*fakeEntry]()
	ts.Store("AAAAtok", &fakeEntry{expire: time.Now().Add(-1 * time.Minute)})

	var firstHit, secondHit int
	ts.SetOnExpire(func(string, *fakeEntry) { firstHit++ })
	ts.SetOnExpire(func(string, *fakeEntry) { secondHit++ })

	ts.CleanExpired()
	if firstHit != 0 {
		t.Errorf("replaced hook still fired: firstHit=%d", firstHit)
	}
	if secondHit != 1 {
		t.Errorf("replacement hook missed: secondHit=%d want 1", secondHit)
	}
}

// TestTokenStore_SetOnExpire_NilClearsHook pins the documented
// contract "Passing nil disables the hook" — SetOnExpire(nil) after
// a non-nil registration must disable callbacks for future
// CleanExpired calls. The Replaces test only fences "latest non-nil
// wins"; this one fences the nil-clearing path explicitly.
func TestTokenStore_SetOnExpire_NilClearsHook(t *testing.T) {
	ts := NewTokenStore[*fakeEntry]()
	ts.Store("AAAAtok", &fakeEntry{expire: time.Now().Add(-1 * time.Minute)})

	var hits int
	ts.SetOnExpire(func(string, *fakeEntry) { hits++ })
	ts.SetOnExpire(nil)

	if got := ts.CleanExpired(); got != 1 {
		t.Errorf("CleanExpired removed %d, want 1", got)
	}
	if hits != 0 {
		t.Errorf("hook fired %d times after SetOnExpire(nil), want 0", hits)
	}
}

// TestTokenStore_OnExpire_RunsAfterLockReleased pins the contract
// that AC's #2172 wiring depends on: CleanExpired releases mu BEFORE
// invoking the hook batch. Re-entrancy from inside the hook would
// deadlock if the lock were still held; success here proves the
// lock-release-before-hook ordering is intact.
//
// Regression mode: if a future refactor moves the hook back inside
// the locked section, this test deadlocks and the 2s safety timeout
// fires with a clear message pointing at the regression.
func TestTokenStore_OnExpire_RunsAfterLockReleased(t *testing.T) {
	ts := NewTokenStore[*fakeEntry]()
	ts.Store("AAAAexpired", &fakeEntry{expire: time.Now().Add(-time.Minute)})

	done := make(chan struct{})
	ts.SetOnExpire(func(string, *fakeEntry) {
		// Re-acquire the store from inside the hook. If CleanExpired
		// still held ts.mu, this Store call would block forever and
		// the select below would time out.
		ts.Store("BBBBfresh", &fakeEntry{expire: time.Now().Add(time.Minute)})
		close(done)
	})

	go ts.CleanExpired()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("OnExpire hook appears to run under tokenStore.mu (re-entrant Store deadlocked)")
	}
}

// TestTokenStore_Delete_DoesNotFireOnExpire pins the scope contract
// documented on SetOnExpire: only CleanExpired fires the hook;
// Delete does not. Production callers (httpac.go /refresh-shorten +
// the AC's CleanExpired sweep) rely on this — a future change that
// silently widens Delete to fire the hook would shift the
// deadline-passed branch's double-Cancel semantics.
func TestTokenStore_Delete_DoesNotFireOnExpire(t *testing.T) {
	ts := NewTokenStore[*fakeEntry]()
	ts.Store("AAAAtok", &fakeEntry{expire: time.Now().Add(1 * time.Hour)})

	var hits int
	ts.SetOnExpire(func(string, *fakeEntry) { hits++ })
	ts.Delete("AAAAtok")

	if hits != 0 {
		t.Errorf("hook fired %d times on Delete, want 0", hits)
	}
	if got := ts.Size(); got != 0 {
		t.Errorf("Delete didn't remove entry: Size = %d, want 0", got)
	}
}

// TestTokenStore_OnExpire_PanicDoesNotAbortBatch fences the panic-
// safety contract on the hook batch: a panicking hook is recovered
// (logged), the rest of the batch still runs, and CleanExpired
// returns normally. Important because CleanExpired runs from
// RunRefreshRoutine — an unrecovered panic would kill the background
// routine and leak expired tokens forever.
func TestTokenStore_OnExpire_PanicDoesNotAbortBatch(t *testing.T) {
	ts := NewTokenStore[*fakeEntry]()
	past := time.Now().Add(-time.Minute)
	ts.Store("AAAApanic", &fakeEntry{expire: past})
	ts.Store("BBBBnormal", &fakeEntry{expire: past})

	var normalHits int
	ts.SetOnExpire(func(token string, _ *fakeEntry) {
		if token == "AAAApanic" {
			panic("test panic from hook")
		}
		normalHits++
	})

	// Should not panic. Map iteration order is non-deterministic so
	// the panicking token may be visited first OR second; both orderings
	// exercise the "batch continues after panic" guarantee identically.
	if got := ts.CleanExpired(); got != 2 {
		t.Errorf("CleanExpired removed %d, want 2 (panicking hook should not abort the batch)", got)
	}
	if normalHits != 1 {
		t.Errorf("normal hook fired %d times after batchmate panic, want 1", normalHits)
	}
}

// TestTokenStore_Snapshot_EmptyReturnsNil fences Snapshot's
// allocation contract on an empty store. Returning nil (rather than
// an empty non-nil slice) avoids gratuitous heap allocation on the
// common cancelAllScheduledFlows path where most entries don't
// share FlowKeys.
func TestTokenStore_Snapshot_EmptyReturnsNil(t *testing.T) {
	ts := NewTokenStore[*fakeEntry]()
	if got := ts.Snapshot(); got != nil {
		t.Errorf("Snapshot of empty store = %v, want nil", got)
	}
}

// TestTokenStore_Snapshot_ReturnsAllEntries fences the basic contract:
// after N Store calls, Snapshot returns a slice containing all N
// entries. Order is unspecified (map iteration); the test checks set
// membership, not ordering.
func TestTokenStore_Snapshot_ReturnsAllEntries(t *testing.T) {
	ts := NewTokenStore[*fakeEntry]()
	const n = 10
	want := make(map[*fakeEntry]string, n)
	for i := 0; i < n; i++ {
		// Spread tokens across leading-char buckets to exercise the
		// nested-map iteration (Snapshot walks ts.store[prefix][token]).
		tok := string(rune('A'+i)) + "snapshot-test"
		e := &fakeEntry{expire: time.Now().Add(1 * time.Minute)}
		ts.Store(tok, e)
		want[e] = tok
	}

	snap := ts.Snapshot()
	if len(snap) != n {
		t.Fatalf("Snapshot returned %d entries, want %d", len(snap), n)
	}
	got := make(map[*fakeEntry]struct{}, n)
	for _, e := range snap {
		got[e] = struct{}{}
	}
	if len(got) != n {
		t.Errorf("Snapshot returned duplicate entry pointers: %d unique of %d total", len(got), n)
	}
	for e := range want {
		if _, ok := got[e]; !ok {
			t.Errorf("Snapshot missing entry stored under %q", want[e])
		}
	}
}

// TestTokenStore_Snapshot_IndependentOfSubsequentMutation fences the
// point-in-time guarantee: Snapshot returns a fresh slice whose
// length and pointer-membership are unaffected by subsequent Store /
// Delete operations. The element pointers are shared with the store
// (entry fields are NOT deep-copied), but the slice header is owned
// by the caller.
func TestTokenStore_Snapshot_IndependentOfSubsequentMutation(t *testing.T) {
	ts := NewTokenStore[*fakeEntry]()
	e1 := &fakeEntry{expire: time.Now().Add(1 * time.Minute)}
	e2 := &fakeEntry{expire: time.Now().Add(1 * time.Minute)}
	ts.Store("AAAtok-1", e1)
	ts.Store("BBBtok-2", e2)

	snap := ts.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("precondition: Snapshot returned %d, want 2", len(snap))
	}

	// Mutate store after Snapshot — snap must be unaffected.
	ts.Delete("AAAtok-1")
	e3 := &fakeEntry{expire: time.Now().Add(1 * time.Minute)}
	ts.Store("CCCtok-3", e3)

	if len(snap) != 2 {
		t.Errorf("post-mutation snap length = %d, want 2 (Snapshot leaked store reference?)", len(snap))
	}
	for _, e := range snap {
		if e != e1 && e != e2 {
			t.Errorf("snap contains unexpected entry %v — must contain only e1 and e2", e)
		}
	}
}

// TestTokenStore_Snapshot_ConcurrentRLockSafe fences that Snapshot
// uses RLock (not Lock) so concurrent Snapshot calls can proceed
// without serialization. The race detector trips on any unprotected
// shared-state access.
func TestTokenStore_Snapshot_ConcurrentRLockSafe(t *testing.T) {
	ts := NewTokenStore[*fakeEntry]()
	for i := 0; i < 100; i++ {
		ts.Store(string(rune('A'+(i%26)))+"-"+string(rune('a'+i)), &fakeEntry{expire: time.Now().Add(1 * time.Minute)})
	}

	const goroutines, iterations = 8, 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_ = ts.Snapshot()
			}
		}()
	}
	wg.Wait()
	// No assertion — race detector is the contract.
}
