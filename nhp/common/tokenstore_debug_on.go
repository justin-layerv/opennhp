//go:build nhp_debug

package common

import (
	"fmt"
	"reflect"
)

// assertUniquePointerLocked panics if `entry` is already stored under
// a token other than `token`. Caller must hold ts.mu (Store does).
//
// Why this exists: endpoints/ac.AccessEntry carries a load-bearing
// pointer-identity invariant — `latestOtherFirewallDeadline` uses
// `other == self` to skip self in the multi-session reschedule walk.
// A future refactor that pools / reuses *AccessEntry pointers would
// let self appear under multiple tokens; each non-self copy would
// falsely register as an "other holder" of the entry's tracked
// FlowKeys, keeping scheduler entries alive past their genuine
// firewall deadlines (a silent security regression — kernel rule
// outlives session, not a panic). #2214 tracks this fence; #2215
// tracks the synthetic-entryID alternative — when #2215 ships and
// the pointer-identity invariant is no longer load-bearing, this
// entire build-tag scaffold becomes obsolete and should be
// retired per the checklist in #2227. See the AccessEntry
// pointer-identity invariant godoc in endpoints/ac/tokenstore.go.
//
// Scope: meaningful for pointer-type `E`. Both production
// instantiations (TokenStore[*AccessEntry] on the AC and
// TokenStore[*ACTokenEntry] on the server) are pointer types and
// obey the invariant today; the fence catches a future refactor on
// either side that introduces pointer reuse. When adding a NEW
// pointer-typed TokenStore consumer (e.g. a hypothetical
// endpoints/db or endpoints/agent instantiation), extend the
// `-tags=nhp_debug` CI step in .github/workflows/build-and-push.yml to
// also exercise the new package — the fence runs automatically for
// every TokenStore[E] but only the packages CI compiles under the
// debug tag get the regression catch.
//
// Pointer-only guard: the fence's semantics ("same pointer under
// two tokens") have no meaning for non-pointer E. The reflect.Ptr
// kind check below silently no-ops the fence for value-typed E,
// which:
//   - prevents the any(stored) == any(entry) runtime panic on
//     non-comparable value Es ("comparing uncomparable type");
//   - prevents the %p panic-format leak: fmt's %p on a non-pointer
//     arg falls back to "%!p(...)" rendering that dumps the value's
//     fields, defeating the round-1 hygiene choice; and
//   - keeps the filter agreeing with the fence's documented scope.
//
// Production Es (*AccessEntry, *ACTokenEntry) are both pointer
// kinds. The reflect.TypeOf().Elem().Kind() call evaluates on
// every Store under nhp_debug — Go's reflect type table caches
// the underlying lookup but the per-call cost is real (a handful
// of nanoseconds), not amortized to "once per TokenStore[E]".
// Negligible under the CI-only nhp_debug tag.
//
// Cost: O(N) scan per Store call. A test that pre-populates a
// store with M entries and then issues N Stores under -tags=nhp_debug
// pays O(M*N) total; the existing 2m / 5m CI budgets cover today's
// max ~10k-entry test sizes but a future high-volume tokenStore
// stress test should expect runtime to scale quadratically. The
// production binary uses the no-op variant in
// tokenstore_debug_off.go and pays nothing.
//
// Critical-section length under nhp_debug: the scan runs inside
// ts.mu (held by Store), so concurrent Load / Snapshot callers
// block for the duration of the scan. At today's sizes this is
// invisible; under a future 100k+ stress test with concurrent
// readers, lock contention would dominate. Production builds use
// the no-op variant and pay nothing here.
//
// Panic-message hygiene: tokens are RedactToken-wrapped; the entry
// is formatted with %p (pointer hex only) — never %v — so a panic
// captured by CI logs cannot incidentally dump session-secret-bearing
// entry fields (e.g. AccessEntry.User.UserId, ACTokenEntry.KnockSrcIP).
// The pointer value is the actual subject of the message.
func (ts *TokenStore[E]) assertUniquePointerLocked(token string, entry E) {
	if reflect.TypeOf((*E)(nil)).Elem().Kind() != reflect.Pointer {
		return
	}
	// Typed-nil short-circuit: any(typed-nil) == any(typed-nil) is true,
	// so a caller that Stored (*AccessEntry)(nil) twice under different
	// tokens would false-trip the fence. Production never stores nil
	// entries (HandleUdpACOperations / NewACKTokenEntry both return
	// fresh non-nil), so this guards a test-construction footgun, not
	// a production path.
	//
	// Ordering dependency: reflect.Value.IsNil panics for kinds outside
	// {chan, func, interface, map, pointer, slice}. This call is safe
	// only because the Kind() == reflect.Pointer guard above runs
	// first. A future reorder or weakening of that guard would
	// re-introduce a confusing CI-time runtime panic — keep them
	// paired in this order.
	if reflect.ValueOf(any(entry)).IsNil() {
		return
	}
	for _, tokenMap := range ts.store {
		for existingToken, stored := range tokenMap {
			// Same-token re-Store is the legitimate update path —
			// AC's VerifyAccessToken slide-then-restore (one Store
			// per /refresh) re-Stores the same *AccessEntry under
			// the same token on every successful verify, the most
			// common production re-Store pattern. The fence is for
			// cross-token reuse only; idempotent same-token updates
			// are not violations. Fenced by
			// TestTokenStore_Debug_AssertUniquePointer_OkOnSameTokenReStore.
			if existingToken == token {
				continue
			}
			if any(stored) == any(entry) {
				panic(fmt.Sprintf(
					"[TokenStore] #2214 pointer-identity violation: entry %p already stored under %s, re-store attempted under %s",
					any(entry),
					RedactToken(existingToken),
					RedactToken(token),
				))
			}
		}
	}
}
