//go:build nhp_debug

package common

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestTokenStore_Debug_AssertUniquePointer_PanicsOnReuse fences the
// core mechanism of #2214: the same entry pointer stored under a
// second token must trip the assertion.
//
// AccessEntry-typed positive/negative tests live AC-side
// (endpoints/ac/tokenstore_debug_test.go); this file fences the
// generic mechanism with a minimal fakeEntry so the common package
// stays self-contained.
//
// The deferred recover anchors on the #2214 marker in the panic
// message rather than `r != nil` alone, so a future-introduced
// unrelated panic in Store (nil deref, runtime error, etc.) cannot
// silently make this test pass without the fence firing.
func TestTokenStore_Debug_AssertUniquePointer_PanicsOnReuse(t *testing.T) {
	ts := NewTokenStore[*fakeEntry]()
	entry := &fakeEntry{expire: time.Now().Add(time.Hour)}
	ts.Store("AAAAtoken1", entry)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("Store with reused pointer did not panic; expected #2214 assertion to fire")
		}
		if msg := fmt.Sprint(r); !strings.Contains(msg, "#2214") {
			t.Fatalf("panic message did not carry the #2214 anchor; got: %s", msg)
		}
	}()
	ts.Store("BBBBtoken2", entry)
}

// TestTokenStore_Debug_AssertUniquePointer_OkOnDistinctPointers
// fences the negative side: two distinct pointers with byte-identical
// field values must NOT trip the assertion. This is the case for the
// real production code, where each admission allocates a fresh
// &AccessEntry{} even when the agent re-knocks with the same
// (SrcAddrs, DstAddrs, OpenTime).
func TestTokenStore_Debug_AssertUniquePointer_OkOnDistinctPointers(t *testing.T) {
	ts := NewTokenStore[*fakeEntry]()
	expire := time.Now().Add(time.Hour)
	ts.Store("AAAAtoken1", &fakeEntry{expire: expire})
	ts.Store("BBBBtoken2", &fakeEntry{expire: expire})
}

// TestTokenStore_Debug_AssertUniquePointer_OkOnSameTokenReStore
// fences the update path: re-Storing the same entry under the same
// token (idempotent update) is not a violation. Only cross-token
// pointer reuse is.
func TestTokenStore_Debug_AssertUniquePointer_OkOnSameTokenReStore(t *testing.T) {
	ts := NewTokenStore[*fakeEntry]()
	entry := &fakeEntry{expire: time.Now().Add(time.Hour)}
	ts.Store("AAAAtoken1", entry)
	ts.Store("AAAAtoken1", entry)
}

// TestTokenStore_Debug_AssertUniquePointer_OkOnDeleteThenRestore
// fences the documented test-author escape hatch (see AccessEntry
// godoc in endpoints/ac/tokenstore.go): a test that legitimately
// re-keys the same entry under a new token MUST Delete the old
// token first. After the Delete, the pointer is no longer in the
// store, so Store under a new token does not trip the assertion.
//
// Without the Delete this same sequence panics (the
// _PanicsOnReuse test above fences the failure mode); together
// the two tests pin both sides of the contract the godoc
// documents.
func TestTokenStore_Debug_AssertUniquePointer_OkOnDeleteThenRestore(t *testing.T) {
	ts := NewTokenStore[*fakeEntry]()
	entry := &fakeEntry{expire: time.Now().Add(time.Hour)}
	ts.Store("AAAAtoken1", entry)
	ts.Delete("AAAAtoken1")
	ts.Store("BBBBtoken2", entry)
}

// uncomparableValueEntry is a value-typed TokenEntry whose embedded
// slice makes the type non-comparable. Used to fence one half of
// the Kind() == reflect.Ptr short-circuit (covers a value type
// that would also runtime-panic on the any-equality comparison).
type uncomparableValueEntry struct {
	expire  time.Time
	payload []int
}

func (e uncomparableValueEntry) GetExpireTime() time.Time { return e.expire }

// comparableValueEntry is a value-typed TokenEntry whose fields are
// all comparable. Comparable() would pass, but Kind() != reflect.Ptr
// still rejects it under the tightened guard — and rightly so,
// because %p on a non-pointer entry would render "%!p(...)" and
// dump field values, defeating the round-1 panic-format hygiene.
type comparableValueEntry struct {
	id     string
	expire time.Time
}

func (e comparableValueEntry) GetExpireTime() time.Time { return e.expire }

// TestTokenStore_Debug_AssertUniquePointer_TypedNil_NoPanic fences
// the typed-nil short-circuit in assertUniquePointerLocked. Without
// the IsNil() guard, any(typed-nil) == any(typed-nil) would be true,
// so a test that legitimately Stores a nil pointer under two tokens
// would false-trip the fence. Production never stores nil entries
// (HandleUdpACOperations / NewACKTokenEntry both return fresh
// non-nil), so this is a defense against a test-construction
// footgun, not a production path.
func TestTokenStore_Debug_AssertUniquePointer_TypedNil_NoPanic(t *testing.T) {
	ts := NewTokenStore[*fakeEntry]()
	var nilEntry *fakeEntry
	ts.Store("AAAAtoken1", nilEntry)
	ts.Store("BBBBtoken2", nilEntry)
}

// TestTokenStore_Debug_AssertUniquePointer_NonPointerE_SilentNoOp
// fences both arms of the Kind() == reflect.Ptr short-circuit in
// assertUniquePointerLocked. Storing twice with a non-pointer E
// must not runtime-panic (for non-comparable cases) and must not
// fire the fence (for comparable-value cases that would otherwise
// emit a leaky "%!p(...)" rendering). The guard makes the fence
// inert for instantiations where pointer-uniqueness is undefined.
func TestTokenStore_Debug_AssertUniquePointer_NonPointerE_SilentNoOp(t *testing.T) {
	t.Run("uncomparable_value", func(t *testing.T) {
		ts := NewTokenStore[uncomparableValueEntry]()
		entry := uncomparableValueEntry{expire: time.Now().Add(time.Hour), payload: []int{1, 2, 3}}
		ts.Store("AAAAtoken1", entry)
		ts.Store("BBBBtoken2", entry)
	})
	t.Run("comparable_value", func(t *testing.T) {
		ts := NewTokenStore[comparableValueEntry]()
		entry := comparableValueEntry{id: "x", expire: time.Now().Add(time.Hour)}
		ts.Store("AAAAtoken1", entry)
		ts.Store("BBBBtoken2", entry)
	})
}
