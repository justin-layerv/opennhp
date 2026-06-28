package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// This file is the load-bearing serialization fence for the port-carrying
// allow-rule keys that the XDP datapath looks up by their packed wire bytes:
//
//   - src_port      (struct src_port_list_key = {src_ip, dst_port})           -> ToSpKey
//   - port_list     (struct port_list_key     = {src_ip, min_port, max_port}) -> ToPlKey
//   - protocol_port (struct protocol_port_key = {dst_port, protocol})         -> ToPpKey (fed by parsePort)
//
// All are HASH maps: a lookup matches only on byte-for-byte key equality, so
// the bytes Go writes must reproduce EXACTLY the bytes the XDP program builds
// per packet (nhp/ebpf/xdp/nhp_ebpf_xdp.c) — port fields big-endian on the wire
// (`__be16`, copied straight from the TCP/UDP header), src_ip little-endian
// (parseIP already returns the network-order octets LE-packed). The full WHY,
// the byteswap failure mode (a rule for 443 silently admitting 47873), and why
// it stayed masked are documented once on the ToSpKey godoc (ebpf.go) — the
// single source of truth; the per-test comments below only note what each case
// pins. (protocol_port reaches the same network order by the OPPOSITE route —
// parsePort pre-swaps, ToPpKey writes little-endian, they cancel — see its
// test for why that end-to-end invariant is pinned here.)
//
// SCOPE / PROOF GAP (mirrors conntrack_delete_linux_test.go's e2e note): these
// tests pin the Go serialization against the documented C struct ABI. They do
// NOT prove the XDP program PASSes a real packet against the inserted key —
// that requires a live kernel with the object attached and traffic driven
// through it (the datapath-gate / #2753 Linux-integration responsibility).
// They are the cheap, host-independent correctness fence under that gap.

// TestSrcIPDstPortKey_ToSpKey_GoldenBytes pins the packed wire layout of the
// `src_port` allow-rule key against the kernel struct
// (nhp/ebpf/xdp/nhp_ebpf_xdp.c):
//
//	struct src_port_list_key {
//	    __be32 src_ip;    // bytes 0..3  (network order)
//	    __be16 dst_port;  // bytes 4..5  (network order)
//	} __attribute__((packed));   // = 6 bytes
//
// Port 443 (0x01BB) is deliberately asymmetric: its big-endian bytes (01 BB)
// and little-endian bytes (BB 01) differ, so this test distinguishes the
// correct (network/big-endian) serialization from the byteswapped one. A
// palindromic port (e.g. 0 or 0x0101) would pass under either order and prove
// nothing.
func TestSrcIPDstPortKey_ToSpKey_GoldenBytes(t *testing.T) {
	// Client 198.51.100.7 admitted to destination port 443/TCP.
	srcIP, err := parseIP("198.51.100.7")
	if err != nil {
		t.Fatalf("parseIP(src): %v", err)
	}
	const dstPort uint16 = 443 // 0x01BB
	key := &srcIPdstPortKey{
		SrcIP:   srcIP,
		DstPort: dstPort,
	}
	got := key.ToSpKey()

	// struct src_port_list_key is fully __attribute__((packed)) = 6 bytes
	// (no trailing pad, unlike the 16-byte conn_track key).
	if len(got) != 6 {
		t.Fatalf("ToSpKey length = %d, want 6 (packed src_port_list_key: __be32 src_ip + __be16 dst_port)", len(got))
	}

	// src_ip (bytes 0..3), network order. 198.51.100.7 = C6 33 64 07.
	// LittleEndian-of-parseIP reproduces the network-order octets exactly,
	// matching the XDP `iph->saddr` (__be32).
	wantSrcIP := []byte{198, 51, 100, 7}
	if got[0] != wantSrcIP[0] || got[1] != wantSrcIP[1] || got[2] != wantSrcIP[2] || got[3] != wantSrcIP[3] {
		t.Errorf("bytes[0:4] src_ip = % x, want % x (network order, as parseIP returns)", got[0:4], wantSrcIP)
	}

	// dst_port (bytes 4..5), network/big-endian. 443 = 0x01BB -> bytes 01 BB.
	// Load-bearing: the XDP program looks up with spkey.dst_port = ct_key.dport
	// (the __be16 copied from the TCP/UDP header), so a little-endian write
	// (BB 01) hashes to a different bucket and matches the WRONG port
	// (byteswap(443) = 47873). Decoding big-endian and comparing to the named
	// constant both proves the order and catches a transposed golden literal.
	if dp := binary.BigEndian.Uint16(got[4:6]); dp != dstPort {
		t.Errorf("bytes[4:6] dst_port = % x (big-endian decode %d), want 01 bb (=%d) — a little-endian write admits byteswap(443)=47873, not 443", got[4:6], dp, dstPort)
	}
}

// TestPortListKey_ToPlKey_GoldenBytes pins the packed wire layout of the
// `port_list` allow-rule key against the kernel struct
// (nhp/ebpf/xdp/nhp_ebpf_xdp.c):
//
//	struct port_list_key {
//	    __be32 src_ip;    // bytes 0..3  (network order)
//	    __be16 min_port;  // bytes 4..5  (network order)
//	    __be16 max_port;  // bytes 6..7  (network order)
//	} __attribute__((packed));   // = 8 bytes
//
// IMPORTANT — what this does and does NOT prove. The byte order is pinned
// big-endian to match the __be16 fields and stay consistent with ToSpKey /
// ToCtKey. But TODAY this order is behaviorally INVISIBLE: the XDP program
// builds its port_list lookup key with the palindromic constants
// MIN_PORT=0 (00 00) and MAX_PORT=65535 (FF FF), which read identically in
// either byte order — that is why the previous little-endian write was never
// caught. The asymmetric values below (8000=0x1F40, 9000=0x2328) are chosen
// specifically so this test actually pins big-endian rather than passing
// vacuously on palindromes.
//
// This test does NOT assert that a port_list lookup SUCCEEDS. There is a
// separate, orthogonal latent mismatch (out of scope for the endianness fix):
// the inserter in endpoints/ac/msghandler.go builds the all-ports rule with
// DstPortStart=1, while the XDP side looks up min_port=MIN_PORT=0, so the key
// never matches regardless of byte order. That value mismatch is tracked
// separately; fixing the byte order here neither introduces nor resolves it.
func TestPortListKey_ToPlKey_GoldenBytes(t *testing.T) {
	srcIP, err := parseIP("198.51.100.7")
	if err != nil {
		t.Fatalf("parseIP(src): %v", err)
	}
	const minPort uint16 = 8000 // 0x1F40
	const maxPort uint16 = 9000 // 0x2328
	key := &portListKey{
		SrcIP:        srcIP,
		DstPortStart: minPort,
		DstPortEnd:   maxPort,
	}
	got := key.ToPlKey()

	if len(got) != 8 {
		t.Fatalf("ToPlKey length = %d, want 8 (packed port_list_key: __be32 src_ip + 2x __be16)", len(got))
	}

	// src_ip (bytes 0..3), network order.
	wantSrcIP := []byte{198, 51, 100, 7}
	if got[0] != wantSrcIP[0] || got[1] != wantSrcIP[1] || got[2] != wantSrcIP[2] || got[3] != wantSrcIP[3] {
		t.Errorf("bytes[0:4] src_ip = % x, want % x (network order)", got[0:4], wantSrcIP)
	}

	// min_port (bytes 4..5), network/big-endian. 8000 = 0x1F40 -> bytes 1F 40.
	// Asymmetric on purpose: a little-endian write would land 40 1F, so the
	// big-endian decode against the named constant pins the order.
	if mp := binary.BigEndian.Uint16(got[4:6]); mp != minPort {
		t.Errorf("bytes[4:6] min_port = % x (big-endian decode %d), want 1f 40 (=%d)", got[4:6], mp, minPort)
	}

	// max_port (bytes 6..7), network/big-endian. 9000 = 0x2328 -> bytes 23 28.
	if mp := binary.BigEndian.Uint16(got[6:8]); mp != maxPort {
		t.Errorf("bytes[6:8] max_port = % x (big-endian decode %d), want 23 28 (=%d)", got[6:8], mp, maxPort)
	}
}

// TestProtocolPortKey_ToPpKey_GoldenBytes pins the `protocol_port` key
// (struct protocol_port_key {__be16 dst_port; __u8 protocol;}) END TO END
// through its real feeder. Unlike the other allow-rule keys, this path reaches
// network order by a double-swap that must CANCEL: parsePort returns the port
// byte-swapped, then ToPpKey writes it little-endian. This test drives the
// actual parsePort -> ToPpKey path so the invariant is enforced, not just
// described: if either half changes without the other (e.g. parsePort is
// "simplified" to return host order, or ToPpKey is flipped to big-endian on its
// own), the cancellation breaks and bytes 0..1 stop equaling 01 BB.
func TestProtocolPortKey_ToPpKey_GoldenBytes(t *testing.T) {
	// tcp/443 admitted. parsePort("443") pre-swaps to 0xBB01; ToPpKey's
	// little-endian write then lands 01 BB = network order.
	const port uint16 = 443 // 0x01BB on the wire
	swapped, err := parsePort("443")
	if err != nil {
		t.Fatalf("parsePort: %v", err)
	}
	key := &procoPortKey{
		DstPort:  swapped,
		Protocol: 6, // TCP
	}
	got := key.ToPpKey()

	// struct protocol_port_key is packed = 3 bytes (__be16 + __u8).
	if len(got) != 3 {
		t.Fatalf("ToPpKey length = %d, want 3 (packed protocol_port_key: __be16 dst_port + __u8 protocol)", len(got))
	}

	// dst_port (bytes 0..1), network/big-endian. 443 -> 01 BB. A big-endian
	// decode that doesn't equal 443 means the parsePort/ToPpKey double-swap no
	// longer cancels.
	if dp := binary.BigEndian.Uint16(got[0:2]); dp != port {
		t.Errorf("bytes[0:2] dst_port = % x (big-endian decode %d), want 01 bb (=%d) — parsePort/ToPpKey swap+LE-write no longer cancels to network order", got[0:2], dp, port)
	}
	// protocol (byte 2).
	if got[2] != 6 {
		t.Errorf("byte[2] protocol = %d, want 6 (TCP)", got[2])
	}
}

// TestPortKeySerializers_V4V6_ByteOrderLockstep ENFORCES what the ToSpKey godoc
// only documents ("keep v4/v6 in lockstep"): the v4 and v6 port-key serializers
// must encode the same logical port to the same network-order wire bytes. Both
// families are looked up by the XDP datapath with the raw __be16 from the packet
// header, so if a future edit flips one family's byte order and not the other,
// that family's allow rule silently stops matching (the 443->47873 bug this PR
// fixes, reintroduced on one side). A prose "keep them consistent" note cannot
// catch that; this cross-family assertion does.
func TestPortKeySerializers_V4V6_ByteOrderLockstep(t *testing.T) {
	v4ip, err := parseIP("198.51.100.7")
	if err != nil {
		t.Fatalf("parseIP: %v", err)
	}
	v6ip, err := parseIP6("2001:db8::7")
	if err != nil {
		t.Fatalf("parseIP6: %v", err)
	}

	// src_port: v4 dst_port lives at bytes[4:6] (6-byte key); v6 dst_port at
	// bytes[16:18] (18-byte key). Both must be the network-order __be16 for 443.
	const port uint16 = 443
	wantPort := []byte{0x01, 0xBB} // network/big-endian for 443
	v4sp := (&srcIPdstPortKey{SrcIP: v4ip, DstPort: port}).ToSpKey()
	v6sp := (&srcIPdstPortKeyV6{SrcIP: v6ip, DstPort: port}).ToSpKeyV6()
	if !bytes.Equal(v4sp[4:6], wantPort) || !bytes.Equal(v6sp[16:18], wantPort) {
		t.Errorf("src_port dst_port byte order diverges: v4=% x v6=% x, want % x (both must be network-order __be16)", v4sp[4:6], v6sp[16:18], wantPort)
	}

	// port_list: v4 min/max at [4:6]/[6:8]; v6 min/max at [16:18]/[18:20].
	const lo, hi uint16 = 8000, 9000
	v4pl := (&portListKey{SrcIP: v4ip, DstPortStart: lo, DstPortEnd: hi}).ToPlKey()
	v6pl := (&portListKeyV6{SrcIP: v6ip, DstPortStart: lo, DstPortEnd: hi}).ToPlKeyV6()
	if !bytes.Equal(v4pl[4:6], v6pl[16:18]) || !bytes.Equal(v4pl[6:8], v6pl[18:20]) {
		t.Errorf("port_list byte order diverges: v4 min/max=% x/% x v6 min/max=% x/% x (families must agree)", v4pl[4:6], v4pl[6:8], v6pl[16:18], v6pl[18:20])
	}
	if binary.BigEndian.Uint16(v4pl[4:6]) != lo || binary.BigEndian.Uint16(v6pl[16:18]) != lo {
		t.Errorf("port_list min_port not network-order %d: v4=% x v6=% x", lo, v4pl[4:6], v6pl[16:18])
	}
}
