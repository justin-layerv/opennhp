//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

// This file is the P4c surgical-revocation proof at the eBPF map-op layer.
//
// Two layers of proof, mirroring the existing
// expiry_enumerate_ebpf_linux_test.go pattern:
//
//   - TestConnTrackKey_ToCtKey_GoldenBytes: the LOAD-BEARING correctness
//     fence. It pins the exact packed byte layout of the conntrack delete
//     key against the kernel `struct ipv4_ct_tuple`. A wrong field order,
//     byte order, or direction flag produces wrong key bytes, which hash
//     to a different map bucket — the Delete then silently ENOENT-no-ops
//     and the targeted flow is NEVER torn down. This test runs on any
//     Linux host (no privilege, no /sys/fs/bpf).
//
//   - TestConnTrackDelete_Surgical_SiblingSurvives: the SEMANTIC proof
//     against a REAL in-kernel eBPF map of the conntrack shape. It writes
//     two flows that share the allow-rule tuple {src,dst,dport,proto} but
//     differ only in source port (the NAT'd-clients-behind-one-IP case),
//     deletes ONE via the 5-tuple, and asserts the target is gone while
//     the sibling survives. Skips gracefully when the host can't create
//     BPF maps (unprivileged CI), exactly like the existing enumerate
//     test skips when /sys/fs/bpf isn't mounted.
//
// DEEPEST PROOF GAP (cannot be closed here): that deleting the conntrack
// entry actually drops the next REAL packet through the XDP program while
// the sibling keeps passing requires a live kernel + traffic through the
// attached XDP program. Map-op tests prove the delete targets exactly one
// flow; they do NOT exercise the XDP datapath's established-flow
// short-circuit. That end-to-end teardown is the #2753 Linux-integration
// responsibility (and only if its Linux job drives real packets).

// ctValueSize is a conntrack value size large enough to hold the kernel
// struct conn_value ({u64,u64,u64,u8,u8,u32,u32} ≈ 36 bytes with
// alignment). The exact value bytes are irrelevant to a delete-by-key
// test; only the key path is under test, so a zeroed value of a safe size
// is written.
const ctValueSize = 40

// newTestConnTrackMap creates a real in-kernel LRU_HASH map matching the
// conntrack key/value shape. Returns (nil, false) — signaling skip — if
// the host can't create BPF maps (no CAP_BPF / unprivileged runner /
// kernel too old). This mirrors expiry_enumerate_ebpf_linux_test.go's
// graceful-skip contract: the golden-bytes test covers correctness
// unconditionally; this map test adds semantic coverage only where the
// kernel allows it.
//
// LOUD-SKIP guard (memory: feedback_silent_failure_patterns.md): the
// surgical "sibling survives" test is the P4c acceptance gate, and a
// silent t.Skip on map-creation failure is GREEN-and-invisible — a runner
// that should support BPF but doesn't would pass the gate without ever
// running the semantic proof. So when NHP_REQUIRE_BPF_TESTS=1 is set (the
// #2753 Linux-integration runner is expected to set this once confirmed
// BPF-capable), map-creation failure is a hard t.Fatal, not a skip. Dev
// machines and known-constrained runners leave it unset and get the
// graceful skip.
func newTestConnTrackMap(t *testing.T) (*ebpf.Map, bool) {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "p4c_ct_test",
		Type:       ebpf.LRUHash,
		KeySize:    connTrackKeySize,
		ValueSize:  ctValueSize,
		MaxEntries: 16,
	})
	if err != nil {
		if os.Getenv("NHP_REQUIRE_BPF_TESTS") == "1" {
			t.Fatalf("NHP_REQUIRE_BPF_TESTS=1 but BPF map creation failed — the P4c surgical-kill semantic proof cannot run on this runner, and a silent skip would pass the acceptance gate green. Fix runner BPF capability or unset the flag. err=%v", err)
		}
		t.Skipf("cannot create BPF map on this host (need CAP_BPF / privileged kernel); skipping real-map surgical test — the golden-bytes test covers key correctness, and NHP_REQUIRE_BPF_TESTS is unset. err=%v", err)
		return nil, false
	}
	return m, true
}

// TestConnTrackKey_ToCtKey_GoldenBytes pins the packed wire layout of the
// conntrack delete key. Every assertion here mirrors a field of the
// kernel `struct ipv4_ct_tuple` (nhp/ebpf/xdp/nhp_ebpf_xdp.c):
//
//	struct ipv4_ct_tuple {
//	    __be32 daddr;   // bytes 0..3   (network order)
//	    __be32 saddr;   // bytes 4..7   (network order)
//	    __be16 dport;   // bytes 8..9   (network order)
//	    __be16 sport;   // bytes 10..11 (network order)
//	    __u8   nexthdr; // byte 12
//	    __u8   flags;   // byte 13      (CT_DIR_INGRESS = 0)
//	};                  // 14 field bytes + 2 trailing pad = 16-byte map key
//
// NOTE: the COMPILED conn_track map key is 16 bytes (14 field bytes + 2
// trailing pad), not 14. ToCtKey emits all 16 with the pad zeroed. Why the
// compiled key is 16 despite the C `} __packed;` is documented in full in
// connTrackKeySize's godoc (ebpf.go).
func TestConnTrackKey_ToCtKey_GoldenBytes(t *testing.T) {
	// Client 198.51.100.7:43210 -> resource 203.0.113.10:443 over TCP,
	// ingress direction. (Chosen so every IP/port octet is distinct and a
	// transposed field would visibly change the bytes.)
	srcIP, err := parseIP("198.51.100.7")
	if err != nil {
		t.Fatalf("parseIP(src): %v", err)
	}
	dstIP, err := parseIP("203.0.113.10")
	if err != nil {
		t.Fatalf("parseIP(dst): %v", err)
	}
	key := &connTrackKey{
		DstIP:   dstIP,
		SrcIP:   srcIP,
		DstPort: 443,
		SrcPort: 43210,
		NextHdr: 6, // TCP
		Flags:   ctDirIngress,
	}
	got := key.ToCtKey()

	if len(got) != connTrackKeySize {
		t.Fatalf("ToCtKey length = %d, want connTrackKeySize=%d (ipv4_ct_tuple map key: 14 field bytes + 2 trailing pad)", len(got), connTrackKeySize)
	}

	// daddr first (bytes 0..3), network order. 203.0.113.10 = CB 00 71 0A.
	wantDaddr := []byte{203, 0, 113, 10}
	if got[0] != wantDaddr[0] || got[1] != wantDaddr[1] || got[2] != wantDaddr[2] || got[3] != wantDaddr[3] {
		t.Errorf("bytes[0:4] daddr = % x, want % x (dest-before-source, network order)", got[0:4], wantDaddr)
	}
	// saddr second (bytes 4..7), network order. 198.51.100.7 = C6 33 64 07.
	wantSaddr := []byte{198, 51, 100, 7}
	if got[4] != wantSaddr[0] || got[5] != wantSaddr[1] || got[6] != wantSaddr[2] || got[7] != wantSaddr[3] {
		t.Errorf("bytes[4:8] saddr = % x, want % x (network order)", got[4:8], wantSaddr)
	}
	// dport (bytes 8..9), network/big-endian. 443 = 0x01BB.
	if dport := binary.BigEndian.Uint16(got[8:10]); dport != 443 {
		t.Errorf("bytes[8:10] dport (big-endian) = %d, want 443", dport)
	}
	// sport (bytes 10..11), network/big-endian. 43210 = 0xA8CA.
	if sport := binary.BigEndian.Uint16(got[10:12]); sport != 43210 {
		t.Errorf("bytes[10:12] sport (big-endian) = %d, want 43210 — the surgical discriminator", sport)
	}
	// nexthdr (byte 12).
	if got[12] != 6 {
		t.Errorf("byte[12] nexthdr = %d, want 6 (TCP)", got[12])
	}
	// flags (byte 13) = CT_DIR_INGRESS = 0.
	if got[13] != 0 {
		t.Errorf("byte[13] flags = %d, want 0 (CT_DIR_INGRESS) — a wrong direction silently ENOENTs", got[13])
	}
	// Trailing alignment pad (bytes 14..15) must be zero. The XDP program
	// hashes a zero-initialized ct_key (`ct_key = {}`), so a non-zero pad
	// here would hash to a different bucket and silently ENOENT the
	// delete/lookup against the real 16-byte-key map.
	if got[14] != 0 || got[15] != 0 {
		t.Errorf("bytes[14:16] trailing pad = % x, want 00 00 — must match the kernel's zero-initialized ct_key", got[14:16])
	}

	// Fence the C-struct contract directly: the const must equal the kernel
	// map's KeySize (14 meaningful field bytes + 2 trailing alignment pad).
	// Verified against the compiled object (conn_track KeySize=16). A future
	// field add to connTrackKey that forgets ToCtKey or the pad math is
	// caught here and by the length assertion above.
	if connTrackKeySize != 16 {
		t.Errorf("connTrackKeySize = %d, want 16 — must match the kernel conn_track map KeySize (14 field bytes + 2 trailing pad)", connTrackKeySize)
	}
	if connTrackKeyDataLen != 14 {
		t.Errorf("connTrackKeyDataLen = %d, want 14 — the summed ipv4_ct_tuple field sizes", connTrackKeyDataLen)
	}
}

// TestConnTrackKey_SiblingsDifferOnlyInSrcPort proves the discriminator IS
// the source port at the byte level: two flows identical except for source
// port serialize to keys that differ ONLY in the sport bytes (10..11). If
// ToCtKey ever dropped or transposed sport, the two keys would collide and
// a "surgical" delete would hit both — exactly the over-flush this slice
// exists to prevent. Runs unconditionally (no kernel needed).
func TestConnTrackKey_SiblingsDifferOnlyInSrcPort(t *testing.T) {
	mk := func(sport uint16) []byte {
		src, _ := parseIP("198.51.100.7")
		dst, _ := parseIP("203.0.113.10")
		k := &connTrackKey{DstIP: dst, SrcIP: src, DstPort: 443, SrcPort: sport, NextHdr: 6, Flags: ctDirIngress}
		return k.ToCtKey()
	}
	a := mk(43210)
	b := mk(43211)

	if string(a) == string(b) {
		t.Fatal("two flows differing only in source port produced IDENTICAL conntrack keys — the discriminator is lost; a revoke would over-flush the sibling")
	}
	// Confirm the ONLY differing bytes are the sport field (10..11).
	for i := range a {
		differs := a[i] != b[i]
		inSportRange := i == 10 || i == 11
		if differs && !inSportRange {
			t.Errorf("keys differ at byte %d (outside the sport field 10..11): %02x vs %02x — source port is not the sole discriminator", i, a[i], b[i])
		}
		if !differs && inSportRange {
			// 43210=0xA8CA vs 43211=0xA8CB differ only in the low byte
			// (11); byte 10 (0xA8) is equal. So only assert that byte 11
			// differs; byte 10 equality is fine.
			if i == 11 {
				t.Errorf("sport low byte (11) did NOT differ between 43210 and 43211 — sport not serialized")
			}
		}
	}
}

// TestConnTrackDelete_Surgical_SiblingSurvives is the semantic proof: in a
// REAL conntrack-shaped map, deleting one flow's 5-tuple removes EXACTLY
// that flow and leaves a same-allow-rule-tuple sibling (different source
// port) alive. Also asserts the target was genuinely present-then-absent,
// so a silent no-op cannot pass this test green.
func TestConnTrackDelete_Surgical_SiblingSurvives(t *testing.T) {
	m, ok := newTestConnTrackMap(t)
	if !ok {
		return // skipped inside helper
	}
	defer func() { _ = m.Close() }()

	const (
		srcStr     = "198.51.100.7" // shared client IP (one NAT)
		dstStr     = "203.0.113.10" // shared resource
		proto      = uint8(6)       // TCP
		dport      = uint16(443)    // shared destination port
		targetPort = uint16(43210)  // admission A
		siblingPrt = uint16(43211)  // admission B — same allow-rule tuple
	)
	src, _ := parseIP(srcStr)
	dst, _ := parseIP(dstStr)

	mkKey := func(sport uint16) []byte {
		k := &connTrackKey{DstIP: dst, SrcIP: src, DstPort: dport, SrcPort: sport, NextHdr: proto, Flags: ctDirIngress}
		return k.ToCtKey()
	}
	zeroVal := make([]byte, ctValueSize)

	// Insert both sibling flows.
	if err := m.Put(mkKey(targetPort), zeroVal); err != nil {
		t.Fatalf("put target flow: %v", err)
	}
	if err := m.Put(mkKey(siblingPrt), zeroVal); err != nil {
		t.Fatalf("put sibling flow: %v", err)
	}

	// Pre-condition: target is present (so the delete is meaningful, not a
	// vacuous no-op).
	out := make([]byte, ctValueSize)
	if err := m.Lookup(mkKey(targetPort), &out); err != nil {
		t.Fatalf("pre-delete: target flow should be present, got lookup err %v", err)
	}

	// Surgical delete of EXACTLY the target's 5-tuple via the production
	// delete path (key construction is the code under test).
	if err := delEbpfConnTrackOnMap(m, srcStr, dstStr, proto, targetPort, dport); err != nil {
		t.Fatalf("delEbpfConnTrackOnMap(target): %v", err)
	}

	// Assert 1: the target flow is GONE.
	if err := m.Lookup(mkKey(targetPort), &out); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("post-delete: target flow lookup err = %v, want ErrKeyNotExist (target was not actually deleted — a no-op would silently pass)", err)
	}

	// Assert 2: the SIBLING flow (same allow-rule tuple, different source
	// port) SURVIVES. This is the whole point of P4c: no over-flush.
	if err := m.Lookup(mkKey(siblingPrt), &out); err != nil {
		t.Errorf("post-delete: sibling flow lookup err = %v, want nil — surgical revoke OVER-FLUSHED a same-tuple sibling from another admission", err)
	}
}

// TestConnTrackDelete_Idempotent_NoEntry proves the breaker-safety
// contract: deleting a non-existent conntrack entry returns nil (ENOENT →
// nil), so a revoke racing the kernel's own check_conn_expiry GC — or a
// duplicate revoke event — does not surface an error that a future
// revocation breaker could trip on. Mirrors the allow-rule Del* contract.
func TestConnTrackDelete_Idempotent_NoEntry(t *testing.T) {
	m, ok := newTestConnTrackMap(t)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()

	// Map is empty; delete must be a clean no-op, not an error.
	if err := delEbpfConnTrackOnMap(m, "198.51.100.7", "203.0.113.10", 6, 43210, 443); err != nil {
		t.Errorf("delete of absent conntrack entry = %v, want nil (idempotent ENOENT→nil)", err)
	}
}
