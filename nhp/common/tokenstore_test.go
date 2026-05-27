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
