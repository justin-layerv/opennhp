//go:build linux

package ebpf

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

// newTestWhitelistMap creates a real in-kernel HASH map matching the `spp`
// allow-rule shape (whitelistKeySize key, WhitelistValueSize value). Same
// graceful-skip / NHP_REQUIRE_BPF_TESTS loud-skip contract as
// newTestConnTrackMap (see conntrack_delete_linux_test.go).
func newTestWhitelistMap(t *testing.T) (*ebpf.Map, bool) {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "spp_reap_test",
		Type:       ebpf.Hash,
		KeySize:    uint32(whitelistKeySize),
		ValueSize:  uint32(WhitelistValueSize),
		MaxEntries: 16,
	})
	if err != nil {
		if os.Getenv("NHP_REQUIRE_BPF_TESTS") == "1" {
			t.Fatalf("NHP_REQUIRE_BPF_TESTS=1 but BPF map creation failed — the spp reaper semantic proof cannot run and a silent skip would pass the gate green. Fix runner BPF capability or unset the flag. err=%v", err)
		}
		t.Skipf("cannot create BPF map on this host (need CAP_BPF / privileged kernel); skipping spp reaper real-map test. err=%v", err)
		return nil, false
	}
	t.Cleanup(func() { _ = m.Close() })
	return m, true
}

func sppTestKey(b byte) []byte {
	k := make([]byte, whitelistKeySize)
	k[0] = b // vary the first byte so entries hash distinct
	return k
}

func sppValWithExpire(expireNs uint64) []byte {
	v := make([]byte, WhitelistValueSize)
	v[0] = 1 // allowed
	binary.LittleEndian.PutUint64(v[ExpireTimeOffset:ExpireTimeOffset+8], expireNs)
	return v
}

// TestReapExpiredWhitelistOnMap_DeletesExpiredKeepsLive is the semantic proof of
// the spp datapath-fill GC (#3019 review / #3021): the reaper deletes entries
// whose ExpireTime is already past `now` and leaves live ones untouched. That is
// the bound on tc-egress-written return-path pinholes, which have no scheduled
// flush (spp is HASH since #2163, so no LRU eviction) — and the "keeps live"
// half is the load-bearing safety property: the reaper must NEVER delete a live
// admission (a fresh rule carries a future ExpireTime).
func TestReapExpiredWhitelistOnMap_DeletesExpiredKeepsLive(t *testing.T) {
	m, ok := newTestWhitelistMap(t)
	if !ok {
		return
	}

	const now = uint64(1_000_000)
	expiredKey := sppTestKey(1)
	liveKey := sppTestKey(2)
	if err := m.Put(expiredKey, sppValWithExpire(now-1)); err != nil { // already expired
		t.Fatalf("put expired: %v", err)
	}
	if err := m.Put(liveKey, sppValWithExpire(now+1_000_000_000)); err != nil { // ~1s in the future
		t.Fatalf("put live: %v", err)
	}

	stats, err := reapExpiredWhitelistOnMap(m, now)
	if err != nil {
		t.Fatalf("reapExpiredWhitelistOnMap: %v", err)
	}
	if stats.Entries != 2 {
		t.Fatalf("Entries = %d, want 2 (both counted before reap)", stats.Entries)
	}
	if stats.ExpiredDeleted != 1 {
		t.Fatalf("ExpiredDeleted = %d, want 1 (only the expired entry)", stats.ExpiredDeleted)
	}

	out := make([]byte, WhitelistValueSize)
	if err := m.Lookup(expiredKey, &out); !isEbpfNoEntry(err) {
		t.Fatalf("expired spp lookup err = %v, want no-entry after reap", err)
	}
	out = make([]byte, WhitelistValueSize)
	if err := m.Lookup(liveKey, &out); err != nil {
		t.Fatalf("live spp lookup err = %v, want survivor untouched — the reaper must never delete a live admission", err)
	}
}

// TestReapExpiredWhitelistOnMap_RespectsValueSizeGuard proves the validate hook
// rejects a wrong-shaped map (a mispinned map at /sys/fs/bpf/spp) instead of
// decoding garbage ExpireTime bytes and deleting live entries.
func TestReapExpiredWhitelistOnMap_RespectsValueSizeGuard(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "spp_badshape",
		Type:       ebpf.Hash,
		KeySize:    uint32(whitelistKeySize),
		ValueSize:  uint32(WhitelistValueSize) + 4, // wrong value size
		MaxEntries: 4,
	})
	if err != nil {
		t.Skipf("cannot create BPF map on this host; skipping. err=%v", err)
	}
	defer func() { _ = m.Close() }()
	if _, err := reapExpiredWhitelistOnMap(m, 1_000_000); err == nil {
		t.Fatal("reapExpiredWhitelistOnMap on a wrong-value-size map = nil error, want a validate failure (must not decode garbage ExpireTime and delete live entries)")
	}
}
