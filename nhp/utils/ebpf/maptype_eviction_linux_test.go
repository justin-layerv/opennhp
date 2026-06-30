//go:build linux

package ebpf

import (
	"errors"
	"os"
	"syscall"
	"testing"

	cebpf "github.com/cilium/ebpf"
)

// This file is the SEMANTIC proof for the #2163 fix at the real in-kernel BPF
// map-op layer: that an authoritative allow-rule map declared HASH FAILS CLOSED
// when full (insert returns -E2BIG, existing admitted entries survive), whereas
// the old LRU_HASH would silently EVICT an entry to admit the new one. A test
// that only asserted HASH-full-returns-error would re-prove generic kernel
// semantics; the load-bearing, non-vacuous part is the CONTRAST against LRU_HASH
// on an identical map shape — that is the exact property the map-type change
// turns on.
//
// Mirrors the graceful-skip / loud-skip contract of
// conntrack_delete_linux_test.go: needs a real kernel + CAP_BPF. When
// NHP_REQUIRE_BPF_TESTS=1, a map-creation failure is a hard t.Fatal (so a
// BPF-capable runner can't pass the gate without running the proof); otherwise
// it skips loudly (dev machines / unprivileged CI). On darwin this file does
// not build at all (the security/declaration coverage there is
// TestIsMapFull + TestXdpSource_* in maptype_test.go).

// allowRuleKeySize / allowRuleValueSize match the whitelist allow-rule map
// shape (struct whitelist_key = 11 packed bytes, struct whitelist_value).
// The exact bytes are irrelevant to a fill/insert/eviction test; only the
// distinctness of keys and the map TYPE under test matter.
const (
	allowRuleKeySize   = 11 // packed whitelist_key (src4+dst4+dport2+proto1)
	allowRuleValueSize = WhitelistValueSize
	testMaxEntries     = 8 // small so we fill deterministically
)

// newAllowRuleMap creates a real in-kernel map of the allow-rule shape with the
// given type. Returns (nil, false) to signal skip when the host can't create
// BPF maps, unless NHP_REQUIRE_BPF_TESTS=1 (then hard-fail).
func newAllowRuleMap(t *testing.T, typ cebpf.MapType) (*cebpf.Map, bool) {
	t.Helper()
	m, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "nhp_art_test",
		Type:       typ,
		KeySize:    allowRuleKeySize,
		ValueSize:  uint32(allowRuleValueSize),
		MaxEntries: testMaxEntries,
	})
	if err != nil {
		if os.Getenv("NHP_REQUIRE_BPF_TESTS") == "1" {
			t.Fatalf("NHP_REQUIRE_BPF_TESTS=1 but BPF %v map creation failed — the #2163 eviction-vs-reject semantic proof cannot run, and a silent skip would pass the gate green. Fix runner BPF capability or unset the flag. err=%v", typ, err)
		}
		t.Skipf("cannot create BPF %v map on this host (need CAP_BPF / privileged kernel); skipping kernel eviction-vs-reject test — TestIsMapFull + TestXdpSource_* still cover detection + declaration, and NHP_REQUIRE_BPF_TESTS is unset. err=%v", typ, err)
		return nil, false
	}
	return m, true
}

// keyN returns a distinct allow-rule key for index n.
func keyN(n int) []byte {
	k := make([]byte, allowRuleKeySize)
	// vary the first 4 bytes (src_ip slot) so each key is distinct
	k[0] = byte(n)
	k[1] = byte(n >> 8)
	k[2] = 0xAB
	k[3] = 0xCD
	return k
}

func zeroVal() []byte { return make([]byte, allowRuleValueSize) }

// fillToCapacity inserts testMaxEntries distinct keys with BPF_ANY (UpdateAny),
// matching the prod insert path (AddWhitelistRule uses ebpf.UpdateAny). Fails
// the test if any of the first testMaxEntries inserts is rejected — those must
// all fit.
func fillToCapacity(t *testing.T, m *cebpf.Map) {
	t.Helper()
	for i := 0; i < testMaxEntries; i++ {
		if err := m.Update(keyN(i), zeroVal(), cebpf.UpdateAny); err != nil {
			t.Fatalf("insert %d/%d into a non-full map must succeed; got %v", i+1, testMaxEntries, err)
		}
	}
}

func entryCount(t *testing.T, m *cebpf.Map) int {
	t.Helper()
	n := 0
	it := m.Iterate()
	var k [allowRuleKeySize]byte
	var v [16]byte // large enough for the value; content unused
	for it.Next(&k, &v) {
		n++
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}
	return n
}

// TestAllowRuleMap_Hash_FailsClosedOnFull is the authoritative-map proof:
// a full HASH map rejects a NEW admission with -E2BIG (IsMapFull) and EVERY
// existing admitted entry survives. This is exactly what an LRU_HASH map would
// VIOLATE (it would evict one to make room) — see the contrast test below.
func TestAllowRuleMap_Hash_FailsClosedOnFull(t *testing.T) {
	m, ok := newAllowRuleMap(t, cebpf.Hash)
	if !ok {
		return
	}
	defer m.Close()

	fillToCapacity(t, m)

	// Insert one MORE distinct key (a new admission past capacity).
	err := m.Update(keyN(testMaxEntries), zeroVal(), cebpf.UpdateAny)
	if err == nil {
		t.Fatal("HASH map at capacity admitted a NEW key — expected -E2BIG (fail-closed). This is the silent-overflow the #2163 fix must prevent.")
	}
	if !IsMapFull(err) {
		t.Fatalf("insert into full HASH map returned %v; want a map-full (E2BIG) error so the AC path can fail the admission closed", err)
	}

	// The survival property: all original admitted entries must still be present.
	if got := entryCount(t, m); got != testMaxEntries {
		t.Fatalf("after a rejected over-capacity insert, entry count = %d, want %d — no admitted entry may be lost", got, testMaxEntries)
	}
	for i := 0; i < testMaxEntries; i++ {
		v := zeroVal()
		if err := m.Lookup(keyN(i), v); err != nil {
			t.Fatalf("admitted entry %d was lost after the rejected insert: %v (a HASH map must NEVER evict to admit a new key)", i, err)
		}
	}
}

// TestAllowRuleMap_FullHash_UpdateExistingKeySucceeds proves that re-authorizing
// an EXISTING session is unaffected by a full map: updating an already-present
// key needs no new slot, so it does NOT return E2BIG. This backs the design
// claim that only genuinely-NEW admissions past capacity are rejected.
func TestAllowRuleMap_FullHash_UpdateExistingKeySucceeds(t *testing.T) {
	m, ok := newAllowRuleMap(t, cebpf.Hash)
	if !ok {
		return
	}
	defer m.Close()

	fillToCapacity(t, m)

	// Re-update an existing key (key 0) on the now-full map.
	if err := m.Update(keyN(0), zeroVal(), cebpf.UpdateAny); err != nil {
		t.Fatalf("updating an EXISTING key on a full HASH map must succeed (no new slot needed); got %v — session re-authorization must not be rejected by a full map", err)
	}
	if got := entryCount(t, m); got != testMaxEntries {
		t.Fatalf("entry count after re-updating an existing key = %d, want %d", got, testMaxEntries)
	}
}

// TestAllowRuleMap_Lru_EvictsOnFull is the CONTRAST half: an identically-shaped
// LRU_HASH map ADMITS the over-capacity key (no E2BIG) and sheds an entry to
// make room (count stays at capacity). This is the silent-eviction behavior the
// #2163 fix moves the allow-rule maps AWAY from — proving the type choice is
// load-bearing, not cosmetic.
//
// Deliberately does NOT assert WHICH key was evicted: kernel LRU eviction is
// approximate/batched (per-CPU LRU with a global fallback), so naming the victim
// is flaky. The deterministic, meaningful contrast is: LRU insert SUCCEEDS where
// HASH insert FAILS, and the map stays at capacity (something was shed).
func TestAllowRuleMap_Lru_EvictsOnFull(t *testing.T) {
	m, ok := newAllowRuleMap(t, cebpf.LRUHash)
	if !ok {
		return
	}
	defer m.Close()

	fillToCapacity(t, m)

	// Insert one MORE distinct key. On LRU this must SUCCEED (the opposite of
	// HASH) — the map silently evicts to make room.
	if err := m.Update(keyN(testMaxEntries), zeroVal(), cebpf.UpdateAny); err != nil {
		if IsMapFull(err) {
			t.Fatalf("LRU_HASH map returned E2BIG on a full insert — expected silent eviction (success). If the kernel changed LRU semantics this contrast assumption needs revisiting. err=%v", err)
		}
		t.Fatalf("unexpected error inserting into full LRU_HASH map: %v", err)
	}

	// LRU keeps the map at (approximately) capacity by shedding the coldest
	// entry. It must not exceed capacity, and the new key must be present.
	if got := entryCount(t, m); got > testMaxEntries {
		t.Fatalf("LRU map exceeded capacity: count=%d > max=%d", got, testMaxEntries)
	}
	v := zeroVal()
	if err := m.Lookup(keyN(testMaxEntries), v); err != nil {
		if errors.Is(err, cebpf.ErrKeyNotExist) || errors.Is(err, syscall.ENOENT) {
			t.Fatalf("the just-inserted key is absent from the LRU map — insert did not take effect")
		}
		t.Fatalf("lookup of newly inserted LRU key: %v", err)
	}
}
