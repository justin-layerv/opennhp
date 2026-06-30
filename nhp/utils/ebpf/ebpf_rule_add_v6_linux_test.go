//go:build linux

package ebpf

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

// This file is the E2 slice-4 SEMANTIC proof against a REAL in-kernel eBPF map:
// an IPv6 admission written through the production v6 allow-rule writers lands
// the right packed key in the right v6 map. It is the routing twin of
// conntrack_delete_linux_test.go's TestConnTrackDelete_Surgical_SiblingSurvives.
//
// Layering (mirrors the conntrack tests):
//   - The packed-byte CORRECTNESS of each v6 key is already fenced unconditionally
//     by the golden-byte tests in keys_v6_test.go (no kernel needed), and the
//     DATAPATH VERDICT (admit→XDP_PASS / deny→XDP_DROP over the real v6 maps) is
//     proven by s3's TestIPv6AdmissionDatapath. This file closes the remaining
//     gap: that the Go WRITE path actually inserts a retrievable entry under that
//     exact key into a real BPF map of the v6 shape.
//   - Skips gracefully where the host can't create BPF maps (unprivileged dev /
//     CI), with the same NHP_REQUIRE_BPF_TESTS loud-skip guard newTestConnTrackMap
//     uses — so a runner that SHOULD support BPF (the eBPF datapath CI job) can't
//     pass this green without actually exercising the write.
//
// The maps here are standalone ebpf.NewMap handles of the correct
// key/value SIZE, written via the injectable Add*RuleV6 writers (the same
// map-handle-injectable seam the v4 AddWhitelistRule etc. expose). The
// LoadPinnedMap wrappers (AddEbpfRuleFor*V6) keep the production pin-path
// contract and are covered by the golden + detection tests; the kernel pin
// itself is XDP/libbpf's responsibility, validated by s3's datapath test.

// v6WlValueSize is the on-wire size of the allow-rule value (whitelistValue:
// allowed + 7-pad + expire_time = 16 bytes). The v6 maps share the v4 value
// struct, so this equals WhitelistValueSize.
const v6WlValueSize = WhitelistValueSize

// newTestV6Map creates a real in-kernel BPF_MAP_TYPE_HASH map of the given key
// size and the allow-rule value size — the same HASH type the authoritative
// allow-rule maps use (#2163). Returns (nil, false) — signaling skip — when the
// host can't create BPF maps, unless NHP_REQUIRE_BPF_TESTS=1, in which case a
// creation failure is a hard t.Fatal (a silent skip on a should-be-capable
// runner would pass this acceptance proof green without running it). Identical
// loud-skip contract to newTestConnTrackMap.
func newTestV6Map(t *testing.T, name string, keySize uint32) (*ebpf.Map, bool) {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.Hash,
		KeySize:    keySize,
		ValueSize:  uint32(v6WlValueSize),
		MaxEntries: 16,
	})
	if err != nil {
		if os.Getenv("NHP_REQUIRE_BPF_TESTS") == "1" {
			t.Fatalf("NHP_REQUIRE_BPF_TESTS=1 but BPF map creation failed — the E2 s4 v6 routing semantic proof cannot run on this runner, and a silent skip would pass the gate green. Fix runner BPF capability or unset the flag. err=%v", err)
		}
		t.Skipf("cannot create BPF map on this host (need CAP_BPF / privileged kernel); skipping real-map v6 routing test — the golden-byte + detection tests cover key correctness, and NHP_REQUIRE_BPF_TESTS is unset. err=%v", err)
		return nil, false
	}
	return m, true
}

// TestAddWhitelistRuleV6_KeyLandsInMap writes a v6 TCP allow-rule via the
// production writer and asserts the entry is retrievable under the EXACT packed
// whitelist_key_v6 bytes — proving the write targets the right key in the right
// (spp_v6-shaped) map.
func TestAddWhitelistRuleV6_KeyLandsInMap(t *testing.T) {
	m, ok := newTestV6Map(t, "s4_spp_v6", whitelistKeyV6Size)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()

	src, err := parseIP6("2001:db8::7")
	if err != nil {
		t.Fatalf("parseIP6(src): %v", err)
	}
	dst, err := parseIP6("2001:db8::10")
	if err != nil {
		t.Fatalf("parseIP6(dst): %v", err)
	}
	rule := &whitelistKeyV6{SrcIP: src, DstIP: dst, DstPort: 443, Protocol: 6}

	if err := AddWhitelistRuleV6(m, rule, 30); err != nil {
		t.Fatalf("AddWhitelistRuleV6: %v", err)
	}

	// The entry must be retrievable under the SAME packed key the writer used.
	val := make([]byte, v6WlValueSize)
	if err := m.Lookup(rule.ToWlKeyV6(), &val); err != nil {
		t.Fatalf("Lookup by ToWlKeyV6() = %v, want hit — the writer did not land the entry under the expected whitelist_key_v6 bytes", err)
	}
	// allowed byte (offset 0) must be 1.
	if val[0] != 1 {
		t.Errorf("value allowed byte = %d, want 1", val[0])
	}

	// Negative control: a key differing only in the final src_ip byte must MISS,
	// proving the lookup hit above is keyed on the full address, not a partial.
	other := &whitelistKeyV6{SrcIP: mustParseIP6(t, "2001:db8::8"), DstIP: dst, DstPort: 443, Protocol: 6}
	if err := m.Lookup(other.ToWlKeyV6(), &val); err == nil {
		t.Error("Lookup of a different-src key unexpectedly hit — the write is not full-address-keyed")
	}
}

// TestAddSdWhitelistRuleV6_KeyLandsInMap covers the src+dst (sdwhitelist_v6 /
// icmp_wl_v6 shape) writer.
func TestAddSdWhitelistRuleV6_KeyLandsInMap(t *testing.T) {
	m, ok := newTestV6Map(t, "s4_sdwl_v6", srcDestKeyV6Size)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()

	rule := &srcDestKeyV6{SrcIP: mustParseIP6(t, "2001:db8::7"), DstIP: mustParseIP6(t, "2001:db8::10")}
	if err := AddSdWhitelistRuleV6(m, rule, 30); err != nil {
		t.Fatalf("AddSdWhitelistRuleV6: %v", err)
	}
	val := make([]byte, v6WlValueSize)
	if err := m.Lookup(rule.ToSdKeyV6(), &val); err != nil {
		t.Fatalf("Lookup by ToSdKeyV6() = %v, want hit", err)
	}
	if val[0] != 1 {
		t.Errorf("value allowed byte = %d, want 1", val[0])
	}
}

// TestAddSrcipDestPortRuleV6_KeyLandsInMap covers the src+single-port
// (src_port_v6 shape) writer.
func TestAddSrcipDestPortRuleV6_KeyLandsInMap(t *testing.T) {
	m, ok := newTestV6Map(t, "s4_srcport_v6", srcPortListKeyV6Size)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()

	rule := &srcIPdstPortKeyV6{SrcIP: mustParseIP6(t, "2001:db8::7"), DstPort: 8443}
	if err := AddSrcipDestPortRuleV6(m, rule, 30); err != nil {
		t.Fatalf("AddSrcipDestPortRuleV6: %v", err)
	}
	val := make([]byte, v6WlValueSize)
	if err := m.Lookup(rule.ToSpKeyV6(), &val); err != nil {
		t.Fatalf("Lookup by ToSpKeyV6() = %v, want hit", err)
	}
	if val[0] != 1 {
		t.Errorf("value allowed byte = %d, want 1", val[0])
	}
}

// TestAddSdPortlistRuleV6_KeyLandsInMap covers the src+port-range
// (port_list_v6 shape) writer.
func TestAddSdPortlistRuleV6_KeyLandsInMap(t *testing.T) {
	m, ok := newTestV6Map(t, "s4_portlist_v6", portListKeyV6Size)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()

	// All-ports-shaped rule: DstPortStart=0 is the canonical all-ports sentinel
	// (matches the XDP MIN_PORT=0 lookup, #2843). This is a self-consistent
	// round-trip (write via AddSdPortlistRuleV6, read back via ToPlKeyV6), so the
	// exact bounds don't affect the assertion — using 0 keeps the fixture from
	// implying min=1 is a valid all-ports start. (Byte-order coverage lives in
	// the keys_v6_test.go golden vectors, which use non-palindromic bounds.)
	rule := &portListKeyV6{SrcIP: mustParseIP6(t, "2001:db8::7"), DstPortStart: 0, DstPortEnd: 65535}
	if err := AddSdPortlistRuleV6(m, rule, 30); err != nil {
		t.Fatalf("AddSdPortlistRuleV6: %v", err)
	}
	val := make([]byte, v6WlValueSize)
	if err := m.Lookup(rule.ToPlKeyV6(), &val); err != nil {
		t.Fatalf("Lookup by ToPlKeyV6() = %v, want hit", err)
	}
	if val[0] != 1 {
		t.Errorf("value allowed byte = %d, want 1", val[0])
	}
}

// TestEbpfRuleAddV6_FailsClosedOnFullHashMap proves the v6 write path preserves
// the fail-CLOSED contract end to end: a full BPF_MAP_TYPE_HASH map returns
// kernel -E2BIG on insert of a NEW key (not a silent eviction — #2163), the v6
// writer propagates that error UNWRAPPED, and IsMapFull (errors.Is over
// syscall.E2BIG) still matches it. This is what lets the admission-side wrapper
// (recordEbpfInsertResult) raise MetricEbpfMapFull and refuse the admission for
// v6 exactly as for v4. A %v-wrap anywhere in the v6 chain would defeat this and
// silently degrade a full map into an unenforced admit.
func TestEbpfRuleAddV6_FailsClosedOnFullHashMap(t *testing.T) {
	// Capacity-1 HASH map so the second distinct key hits -E2BIG.
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "s4_full_v6",
		Type:       ebpf.Hash,
		KeySize:    whitelistKeyV6Size,
		ValueSize:  uint32(v6WlValueSize),
		MaxEntries: 1,
	})
	if err != nil {
		if os.Getenv("NHP_REQUIRE_BPF_TESTS") == "1" {
			t.Fatalf("NHP_REQUIRE_BPF_TESTS=1 but BPF map creation failed: %v", err)
		}
		t.Skipf("cannot create BPF map on this host; skipping v6 fail-closed proof. err=%v", err)
		return
	}
	defer func() { _ = m.Close() }()

	first := &whitelistKeyV6{SrcIP: mustParseIP6(t, "2001:db8::1"), DstIP: mustParseIP6(t, "2001:db8::10"), DstPort: 443, Protocol: 6}
	if err := AddWhitelistRuleV6(m, first, 30); err != nil {
		t.Fatalf("first v6 insert into capacity-1 map should succeed: %v", err)
	}

	// A second, DISTINCT key has no free slot → kernel -E2BIG.
	second := &whitelistKeyV6{SrcIP: mustParseIP6(t, "2001:db8::2"), DstIP: mustParseIP6(t, "2001:db8::10"), DstPort: 443, Protocol: 6}
	err = AddWhitelistRuleV6(m, second, 30)
	if err == nil {
		t.Fatal("second v6 insert into a FULL hash map succeeded — expected -E2BIG; a HASH map must NOT silently evict (would be a silent admit gap)")
	}
	if !IsMapFull(err) {
		t.Fatalf("IsMapFull(v6 full-map insert err) = false, err=%v — the v6 writer must propagate -E2BIG UNWRAPPED so the admission-side fail-closed wrapper (recordEbpfInsertResult/MetricEbpfMapFull) fires for v6 just like v4", err)
	}

	// Re-inserting the EXISTING key still succeeds (no new slot needed) — session
	// re-authorization is unaffected by a full map, mirroring the v4 contract.
	if err := AddWhitelistRuleV6(m, first, 60); err != nil {
		t.Errorf("re-insert of an EXISTING v6 key into a full map = %v, want nil (update-in-place needs no slot)", err)
	}
}

// mustParseIP6 is a test helper: parseIP6 or t.Fatal.
func mustParseIP6(t *testing.T, s string) [16]byte {
	t.Helper()
	ip, err := parseIP6(s)
	if err != nil {
		t.Fatalf("parseIP6(%q): %v", s, err)
	}
	return ip
}
