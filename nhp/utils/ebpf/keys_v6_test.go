package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// This file is the portable C↔Go size + layout fence for the IPv6 eBPF key
// serializers (E2 slice 2). It mirrors the IPv4 golden-bytes proof in
// conntrack_delete_linux_test.go, but is deliberately PURE: it asserts only
// over hand-packed bytes (no kernel, no /sys/fs/bpf, no cilium/ebpf map), so
// it runs on any OS including the macOS dev host. The real-map
// `map.KeySize() == GoSize` kernel assertion lands in slice 6 (the #2809
// ubuntu harness); these golden bytes are the guard available in Go CI today.
//
// WHY THIS MATTERS: each Go serializer emits a byte slice used directly as a
// kernel map key. If a Go struct/serializer size drifts from the C
// `_Static_assert(sizeof(struct ..._v6) == N)` in nhp/ebpf/xdp/nhp_ebpf_xdp.c,
// the key bytes hash to the wrong bucket (or are rejected by the map's fixed
// KeySize) and routing silently breaks — the exact 14-vs-16 class of bug that
// #2818 was. Pinning len(out) == the C size here makes that drift a red Go CI
// run, not a production miss. The size constants below are duplicated as
// literals (not the package consts) so a wrong edit to a package const is also
// caught — the test and the code can't drift together.

// C `_Static_assert` sizes from nhp/ebpf/xdp/nhp_ebpf_xdp.c (E2 slice 1). These
// are the SINGLE SOURCE OF TRUTH the Go serializers must match. Written as bare
// literals on purpose: asserting the package consts against these catches a
// fat-fingered const edit that would otherwise pass (const == itself).
const (
	cWhitelistKeyV6Size   = 35 // struct whitelist_key_v6
	cSrcDestKeyV6Size     = 32 // struct sdwhitelist_key_v6 / icmpwhitelist_key_v6
	cSrcPortListKeyV6Size = 18 // struct src_port_list_key_v6
	cPortListKeyV6Size    = 20 // struct port_list_key_v6
	cConnTrackKeyV6Size   = 38 // struct ipv6_ct_tuple
)

// TestKeyV6Sizes_MatchCStaticAsserts is the load-bearing guard against the
// #2818 size-drift class: every Go *V6 size constant MUST equal its C
// `_Static_assert(sizeof(...) == N)`. A mismatch here means the Go key and the
// kernel map's KeySize disagree.
func TestKeyV6Sizes_MatchCStaticAsserts(t *testing.T) {
	cases := []struct {
		name   string
		goSize int
		cSize  int
	}{
		{"whitelist_key_v6", whitelistKeyV6Size, cWhitelistKeyV6Size},
		{"sdwhitelist_key_v6/icmpwhitelist_key_v6", srcDestKeyV6Size, cSrcDestKeyV6Size},
		{"src_port_list_key_v6", srcPortListKeyV6Size, cSrcPortListKeyV6Size},
		{"port_list_key_v6", portListKeyV6Size, cPortListKeyV6Size},
		{"ipv6_ct_tuple", connTrackKeyV6Size, cConnTrackKeyV6Size},
	}
	for _, tc := range cases {
		if tc.goSize != tc.cSize {
			t.Errorf("Go size for %s = %d, want %d (C _Static_assert in nhp_ebpf_xdp.c) — C↔Go key-size drift, the #2818 class", tc.name, tc.goSize, tc.cSize)
		}
	}
}

// TestKeyV6Serializers_Length asserts each allow-rule serializer emits exactly
// its C struct's byte count. (Full byte layout for the allow-rule keys is not
// pinned here — only the load-bearing size; ToCtKeyV6 gets the full golden-byte
// treatment below.) Lengths are checked against the C literals so a serializer
// that emits the wrong number of bytes is caught regardless of the package
// const.
func TestKeyV6Serializers_Length(t *testing.T) {
	var v6a, v6b [16]byte
	copy(v6a[:], bytes.Repeat([]byte{0xAA}, 16))
	copy(v6b[:], bytes.Repeat([]byte{0xBB}, 16))

	cases := []struct {
		name string
		got  []byte
		want int
	}{
		{"ToWlKeyV6", (&whitelistKeyV6{SrcIP: v6a, DstIP: v6b, DstPort: 443, Protocol: 6}).ToWlKeyV6(), cWhitelistKeyV6Size},
		{"ToSdKeyV6", (&srcDestKeyV6{SrcIP: v6a, DstIP: v6b}).ToSdKeyV6(), cSrcDestKeyV6Size},
		{"ToSpKeyV6", (&srcIPdstPortKeyV6{SrcIP: v6a, DstPort: 443}).ToSpKeyV6(), cSrcPortListKeyV6Size},
		{"ToPlKeyV6", (&portListKeyV6{SrcIP: v6a, DstPortStart: 1, DstPortEnd: 2}).ToPlKeyV6(), cPortListKeyV6Size},
		{"ToCtKeyV6", (&connTrackKeyV6{DstIP: v6b, SrcIP: v6a, DstPort: 443, SrcPort: 43210, NextHdr: 6, Flags: ctDirIngress}).ToCtKeyV6(), cConnTrackKeyV6Size},
	}
	for _, tc := range cases {
		if len(tc.got) != tc.want {
			t.Errorf("%s emitted %d bytes, want %d (C struct size)", tc.name, len(tc.got), tc.want)
		}
	}
}

// TestWhitelistKeyV6_ToWlKeyV6_GoldenBytes pins the full packed wire layout of
// the allow-rule key against the kernel `struct whitelist_key_v6`
// (nhp/ebpf/xdp/nhp_ebpf_xdp.c):
//
//	struct whitelist_key_v6 {
//	    struct in6_addr src_ip;   // bytes  0..15  (network order)
//	    struct in6_addr dst_ip;   // bytes 16..31  (network order)
//	    __be16          dst_port; // bytes 32..33  (network order)
//	    __u8            protocol; // byte  34
//	} __attribute__((packed));    // 35 bytes, no padding
//
// This is the highest-value allow-rule golden test: it exercises BOTH 16-byte
// addresses, the big-endian port, AND the trailing protocol byte in one shot.
// A length-only assertion (TestKeyV6Serializers_Length) cannot catch a
// transposed src/dst, a wrong port endianness, or a misplaced protocol byte —
// all of which preserve the 35-byte length while silently mis-keying the
// kernel map (the #2818 class). This closes the layout half of the guard for
// the allow-rule path the same way the ToCtKeyV6 golden test does for
// conntrack, ahead of the slice-6 real-map harness.
func TestWhitelistKeyV6_ToWlKeyV6_GoldenBytes(t *testing.T) {
	srcIP, err := parseIP6("2001:db8::7")
	if err != nil {
		t.Fatalf("parseIP6(src): %v", err)
	}
	dstIP, err := parseIP6("2001:db8::10")
	if err != nil {
		t.Fatalf("parseIP6(dst): %v", err)
	}
	key := &whitelistKeyV6{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		DstPort:  443,
		Protocol: 6, // TCP
	}
	got := key.ToWlKeyV6()

	if len(got) != whitelistKeyV6Size {
		t.Fatalf("ToWlKeyV6 length = %d, want whitelistKeyV6Size=%d (packed whitelist_key_v6)", len(got), whitelistKeyV6Size)
	}

	want := []byte{
		// src_ip = 2001:db8::7   (bytes 0..15) — note src FIRST for allow-rule
		// keys, the opposite of the dest-first conntrack tuple.
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
		// dst_ip = 2001:db8::10  (bytes 16..31)
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
		0x01, 0xbb, // dst_port = 443 big-endian (bytes 32..33)
		0x06, // protocol = TCP           (byte 34)
	}
	if !bytes.Equal(got[0:16], want[0:16]) {
		t.Errorf("bytes[0:16] src_ip = % x, want % x (source FIRST for allow-rule keys)", got[0:16], want[0:16])
	}
	if !bytes.Equal(got[16:32], want[16:32]) {
		t.Errorf("bytes[16:32] dst_ip = % x, want % x", got[16:32], want[16:32])
	}
	if dport := binary.BigEndian.Uint16(got[32:34]); dport != 443 {
		t.Errorf("bytes[32:34] dst_port (big-endian) = %d, want 443", dport)
	}
	if got[34] != 6 {
		t.Errorf("byte[34] protocol = %d, want 6 (TCP)", got[34])
	}
}

// TestSrcDestKeyV6_ToSdKeyV6_GoldenBytes pins the full packed wire layout of the
// src+dst allow-rule key against the kernel `struct sdwhitelist_key_v6`
// (nhp/ebpf/xdp/nhp_ebpf_xdp.c) — which is byte-identical to
// `struct icmpwhitelist_key_v6` (a.k.a. the `icmp_wl_v6` map), so this single
// vector fences BOTH maps:
//
//	struct sdwhitelist_key_v6 {        // == icmpwhitelist_key_v6
//	    struct in6_addr src_ip;   // bytes  0..15  (network order)
//	    struct in6_addr dst_ip;   // bytes 16..31  (network order)
//	} __attribute__((packed));    // 32 bytes, no padding
//
// No ports, no protocol — just two verbatim 16-byte address copies. There is no
// endianness subtlety here (addresses are copied straight from To16()), so the
// thing a length-only check (TestKeyV6Serializers_Length) misses is a
// TRANSPOSED or duplicated src/dst: both keep the 32-byte length. Distinct src
// and dst addresses (…::7 vs …::10) make a swap fail by construction. This
// completes the allow-rule golden set — with ToWlKeyV6/ToSpKeyV6/ToPlKeyV6 (and
// ToCtKeyV6 for conntrack) all byte-pinned, every *V6 serializer now has a
// golden vector.
func TestSrcDestKeyV6_ToSdKeyV6_GoldenBytes(t *testing.T) {
	srcIP, err := parseIP6("2001:db8::7")
	if err != nil {
		t.Fatalf("parseIP6(src): %v", err)
	}
	dstIP, err := parseIP6("2001:db8::10")
	if err != nil {
		t.Fatalf("parseIP6(dst): %v", err)
	}
	key := &srcDestKeyV6{
		SrcIP: srcIP,
		DstIP: dstIP,
	}
	got := key.ToSdKeyV6()

	if len(got) != srcDestKeyV6Size {
		t.Fatalf("ToSdKeyV6 length = %d, want srcDestKeyV6Size=%d (packed sdwhitelist_key_v6)", len(got), srcDestKeyV6Size)
	}

	want := []byte{
		// src_ip = 2001:db8::7   (bytes 0..15) — source FIRST for allow-rule keys
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
		// dst_ip = 2001:db8::10  (bytes 16..31)
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	}
	if !bytes.Equal(got[0:16], want[0:16]) {
		t.Errorf("bytes[0:16] src_ip = % x, want % x (source FIRST; a transposed src/dst would put …::10 here)", got[0:16], want[0:16])
	}
	if !bytes.Equal(got[16:32], want[16:32]) {
		t.Errorf("bytes[16:32] dst_ip = % x, want % x", got[16:32], want[16:32])
	}
}

// TestSrcIPdstPortKeyV6_ToSpKeyV6_GoldenBytes pins the full packed wire layout
// of the src+dst-port allow-rule key against the kernel
// `struct src_port_list_key_v6` (nhp/ebpf/xdp/nhp_ebpf_xdp.c):
//
//	struct src_port_list_key_v6 {
//	    struct in6_addr src_ip;   // bytes  0..15  (network order)
//	    __u16           dst_port; // bytes 16..17  (BIG-endian / network order)
//	} __attribute__((packed));    // 18 bytes, no padding
//
// ToSpKeyV6 writes dst_port BIG-endian (network order), matching the
// ToWlKeyV6/ToCtKeyV6 ports AND the v6 XDP `src_port_v6` lookup, which keys on
// the raw network-order packet port (`spkey.dst_port = dport`, dport =
// tcp->dest, no bpf_ntohs). A length-only assertion (TestKeyV6Serializers_Length)
// cannot catch a wrong endianness — an LE write keeps the 18-byte length. So
// this test asserts the EXACT big-endian port bytes (0x01 0xBB for 443), not a
// round-tripped Uint16 read, because the byte order itself is the thing under
// test. An LE write (0xBB 0x01) — the former, buggy layout — turns this red.
//
// WHY BIG-ENDIAN: the v6 datapath builds `spkey.dst_port` straight from the
// __be16 packet port, so an LE serializer inserts 443 as `BB 01` while the
// kernel looks up `01 BB` → the rule silently never matches. This vector pins
// the byte order the slice-6 real-map BPF_PROG_TEST_RUN harness proves
// end-to-end. (The v4 twin ToSpKey had the same latent bug; it is now fixed to
// big-endian to match — #2842.) See the family note above ToSpKeyV6 in ebpf.go.
func TestSrcIPdstPortKeyV6_ToSpKeyV6_GoldenBytes(t *testing.T) {
	srcIP, err := parseIP6("2001:db8::7")
	if err != nil {
		t.Fatalf("parseIP6(src): %v", err)
	}
	key := &srcIPdstPortKeyV6{
		SrcIP:   srcIP,
		DstPort: 443, // 0x01BB -> big-endian (network order) on the wire = 0x01 0xBB
	}
	got := key.ToSpKeyV6()

	if len(got) != srcPortListKeyV6Size {
		t.Fatalf("ToSpKeyV6 length = %d, want srcPortListKeyV6Size=%d (packed src_port_list_key_v6)", len(got), srcPortListKeyV6Size)
	}

	want := []byte{
		// src_ip = 2001:db8::7   (bytes 0..15)
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
		0x01, 0xbb, // dst_port = 443 BIG-endian / network order (bytes 16..17)
	}
	if !bytes.Equal(got[0:16], want[0:16]) {
		t.Errorf("bytes[0:16] src_ip = % x, want % x", got[0:16], want[0:16])
	}
	// EXACT big-endian bytes — the on-wire __u16 layout, not a round-trip read.
	// 443 = 0x01BB, so network-order wire bytes are 0x01 0xBB (matching the
	// datapath's __be16 packet port); the former LE write emitted 0xBB 0x01 and
	// silently mis-keyed the kernel map.
	if !bytes.Equal(got[16:18], want[16:18]) {
		t.Errorf("bytes[16:18] dst_port = % x, want % x (big-endian 443 = 01 bb; the old LE write was bb 01)", got[16:18], want[16:18])
	}
}

// TestPortListKeyV6_ToPlKeyV6_GoldenBytes pins the full packed wire layout of
// the port-range allow-rule key against the kernel `struct port_list_key_v6`
// (nhp/ebpf/xdp/nhp_ebpf_xdp.c):
//
//	struct port_list_key_v6 {
//	    struct in6_addr src_ip;   // bytes  0..15  (network order)
//	    __u16           min_port; // bytes 16..17  (BIG-endian)
//	    __u16           max_port; // bytes 18..19  (BIG-endian)
//	} __attribute__((packed));    // 20 bytes, no padding
//
// The ports are BIG-endian for family uniformity with the rest of the *_v6
// keys. min_port and max_port are DISTINCT values with distinct byte pairs
// (443 -> 01 bb, 8080 -> 1f 90) so this single vector catches all three
// length-preserving #2818 mistakes at once: a wrong port endianness, a min/max
// field swap, AND a dropped/zeroed half of either port.
//
// BYTE-ORDER CAVEAT (unlike ToSpKeyV6): the v6 XDP `port_list_v6` lookup keys
// on the fixed sentinel CONSTANTS min_port=MIN_PORT(0)/max_port=MAX_PORT(65535)
// — never the packet port. 0x0000/0xFFFF are byte-order palindromes, so this
// serializer's min/max byte order is UNOBSERVABLE for the only key the datapath
// ever queries (flipping LE->BE here was a no-op for datapath matching). This
// vector therefore pins the chosen-for-uniformity BE layout and the field
// independence/no-swap contract — it is NOT, and cannot be, a byte-order proof
// against the datapath (the genuine byte-order guard is the ToSpKeyV6 vector +
// the slice-6 src_port_v6 PROG_TEST_RUN case). A real-RANGE port_list_v6 rule
// does not match regardless of byte order (range-vs-sentinel, not endianness).
// See the family note in ebpf.go (#2841).
func TestPortListKeyV6_ToPlKeyV6_GoldenBytes(t *testing.T) {
	srcIP, err := parseIP6("2001:db8::7")
	if err != nil {
		t.Fatalf("parseIP6(src): %v", err)
	}
	key := &portListKeyV6{
		SrcIP:        srcIP,
		DstPortStart: 443,  // min_port: 0x01BB -> BE wire = 0x01 0xBB
		DstPortEnd:   8080, // max_port: 0x1F90 -> BE wire = 0x1F 0x90
	}
	got := key.ToPlKeyV6()

	if len(got) != portListKeyV6Size {
		t.Fatalf("ToPlKeyV6 length = %d, want portListKeyV6Size=%d (packed port_list_key_v6)", len(got), portListKeyV6Size)
	}

	want := []byte{
		// src_ip = 2001:db8::7   (bytes 0..15)
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
		0x01, 0xbb, // min_port = 443  BIG-endian (bytes 16..17)
		0x1f, 0x90, // max_port = 8080 BIG-endian (bytes 18..19)
	}
	if !bytes.Equal(got[0:16], want[0:16]) {
		t.Errorf("bytes[0:16] src_ip = % x, want % x", got[0:16], want[0:16])
	}
	// EXACT big-endian bytes for BOTH ports. Distinct values (443 vs 8080) in
	// distinct slots mean a min/max swap (1f 90 01 bb), a wrong endianness
	// (bb 01 / 90 1f), or a dropped half all produce a mismatch here. (Asymmetric
	// values are used deliberately so the test is non-vacuous about byte order
	// even though the datapath's sentinel key is palindromic — see the caveat
	// above.)
	if !bytes.Equal(got[16:18], want[16:18]) {
		t.Errorf("bytes[16:18] min_port = % x, want % x (big-endian 443 = 01 bb)", got[16:18], want[16:18])
	}
	if !bytes.Equal(got[18:20], want[18:20]) {
		t.Errorf("bytes[18:20] max_port = % x, want % x (big-endian 8080 = 1f 90)", got[18:20], want[18:20])
	}
}

// TestConnTrackKeyV6_ToCtKeyV6_GoldenBytes pins the full packed wire layout of
// the IPv6 conntrack delete key against the kernel `struct ipv6_ct_tuple`
// (nhp/ebpf/xdp/nhp_ebpf_xdp.c):
//
//	struct ipv6_ct_tuple {
//	    struct in6_addr daddr;   // bytes  0..15  (network order)
//	    struct in6_addr saddr;   // bytes 16..31  (network order)
//	    __be16          dport;   // bytes 32..33  (network order)
//	    __be16          sport;   // bytes 34..35  (network order)
//	    __u8            nexthdr; // byte  36
//	    __u8            flags;   // byte  37       (CT_DIR_INGRESS = 0)
//	} __attribute__((packed));   // 38 bytes, no padding
//
// This is the IPv6 twin of TestConnTrackKey_ToCtKey_GoldenBytes. A wrong field
// order, byte order, or direction flag produces wrong key bytes → wrong bucket
// → silent ENOENT no-op on delete (or a rejected key on insert).
func TestConnTrackKeyV6_ToCtKeyV6_GoldenBytes(t *testing.T) {
	// Client [2001:db8::7]:43210 -> resource [2001:db8::10]:443 over TCP,
	// ingress direction. Source and dest differ only in their final byte
	// (07 vs 10), so a transposed daddr/saddr is visible in the bytes.
	srcIP, err := parseIP6("2001:db8::7")
	if err != nil {
		t.Fatalf("parseIP6(src): %v", err)
	}
	dstIP, err := parseIP6("2001:db8::10")
	if err != nil {
		t.Fatalf("parseIP6(dst): %v", err)
	}
	key := &connTrackKeyV6{
		DstIP:   dstIP,
		SrcIP:   srcIP,
		DstPort: 443,
		SrcPort: 43210,
		NextHdr: 6, // TCP
		Flags:   ctDirIngress,
	}
	got := key.ToCtKeyV6()

	if len(got) != connTrackKeyV6Size {
		t.Fatalf("ToCtKeyV6 length = %d, want connTrackKeyV6Size=%d (packed ipv6_ct_tuple)", len(got), connTrackKeyV6Size)
	}

	// Full golden byte vector. daddr (dest) first, then saddr (source),
	// big-endian ports, nexthdr, flags. 2001:db8::10 and 2001:db8::7 expand
	// to the 16-byte forms below.
	want := []byte{
		// daddr = 2001:db8::10  (bytes 0..15)
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
		// saddr = 2001:db8::7   (bytes 16..31)
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
		0x01, 0xbb, // dport = 443   big-endian (bytes 32..33)
		0xa8, 0xca, // sport = 43210 big-endian (bytes 34..35)
		0x06, // nexthdr = TCP            (byte 36)
		0x00, // flags = CT_DIR_INGRESS   (byte 37)
	}
	// Field-by-field assertions against the golden vector. These cover all 38
	// bytes ([0:16] daddr, [16:32] saddr, [32:34] dport, [34:36] sport, [36]
	// nexthdr, [37] flags), so they fully pin the layout while giving a
	// per-field failure message instead of one opaque whole-buffer diff. (A
	// preceding whole-vector bytes.Equal+Fatalf would Goexit on mismatch and
	// make every assertion below unreachable, so it is deliberately omitted.)
	if !bytes.Equal(got[0:16], want[0:16]) {
		t.Errorf("bytes[0:16] daddr = % x, want % x (dest-before-source, network order)", got[0:16], want[0:16])
	}
	if !bytes.Equal(got[16:32], want[16:32]) {
		t.Errorf("bytes[16:32] saddr = % x, want % x (network order)", got[16:32], want[16:32])
	}
	if dport := binary.BigEndian.Uint16(got[32:34]); dport != 443 {
		t.Errorf("bytes[32:34] dport (big-endian) = %d, want 443", dport)
	}
	if sport := binary.BigEndian.Uint16(got[34:36]); sport != 43210 {
		t.Errorf("bytes[34:36] sport (big-endian) = %d, want 43210 — the surgical discriminator", sport)
	}
	if got[36] != 6 {
		t.Errorf("byte[36] nexthdr = %d, want 6 (TCP)", got[36])
	}
	if got[37] != 0 {
		t.Errorf("byte[37] flags = %d, want 0 (CT_DIR_INGRESS) — a wrong direction silently ENOENTs", got[37])
	}
	// (The connTrackKeyV6Size == C-size fence lives in
	// TestKeyV6Sizes_MatchCStaticAsserts; not duplicated here.)
}

// TestConnTrackKeyV6_SiblingsDifferOnlyInSrcPort proves the discriminator IS
// the source port at the byte level: two IPv6 flows identical except for source
// port serialize to keys that differ ONLY in the sport bytes (34..35). The IPv6
// twin of TestConnTrackKey_SiblingsDifferOnlyInSrcPort. Runs with no kernel.
func TestConnTrackKeyV6_SiblingsDifferOnlyInSrcPort(t *testing.T) {
	mk := func(sport uint16) []byte {
		src, _ := parseIP6("2001:db8::7")
		dst, _ := parseIP6("2001:db8::10")
		k := &connTrackKeyV6{DstIP: dst, SrcIP: src, DstPort: 443, SrcPort: sport, NextHdr: 6, Flags: ctDirIngress}
		return k.ToCtKeyV6()
	}
	// 0x0100 vs 0x0200 so BOTH sport bytes (34 high, 35 low) differ — guards
	// against a serializer that drops or zeroes either half of the field.
	a := mk(0x0100)
	b := mk(0x0200)

	if bytes.Equal(a, b) {
		t.Fatal("two IPv6 flows differing only in source port produced IDENTICAL conntrack keys — the discriminator is lost; a revoke would over-flush the sibling")
	}
	for i := range a {
		differs := a[i] != b[i]
		inSportRange := i == 34 || i == 35
		if differs && !inSportRange {
			t.Errorf("keys differ at byte %d (outside the sport field 34..35): %02x vs %02x — source port is not the sole discriminator", i, a[i], b[i])
		}
	}
	// Both sport bytes must actually differ for 0x0100 vs 0x0200 (high byte),
	// confirming the full __be16 is serialized, not just one half.
	if a[34] == b[34] {
		t.Errorf("sport high byte (34) did NOT differ between 0x0100 and 0x0200 — sport high half not serialized")
	}
}

// TestParseIP6_V6 covers the family-rejecting contract: parseIP6 accepts IPv6
// and rejects BOTH malformed input AND IPv4 (including the IPv4-mapped ::ffff:
// form that net.IP.To16() would otherwise silently accept — the trap a naive
// To16()==nil check falls into). It is the mirror of parseIP, which rejects the
// other family. (The `_V6` suffix keeps it inside the `V6|IPv6` test filter.)
func TestParseIP6_V6(t *testing.T) {
	t.Run("accepts_ipv6", func(t *testing.T) {
		got, err := parseIP6("2001:db8::1")
		if err != nil {
			t.Fatalf("parseIP6(valid v6) error = %v, want nil", err)
		}
		want := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
		if got != want {
			t.Errorf("parseIP6(2001:db8::1) = % x, want % x", got, want)
		}
	})

	t.Run("accepts_loopback", func(t *testing.T) {
		got, err := parseIP6("::1")
		if err != nil {
			t.Fatalf("parseIP6(::1) error = %v, want nil", err)
		}
		want := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
		if got != want {
			t.Errorf("parseIP6(::1) = % x, want % x", got, want)
		}
	})

	// The load-bearing rejection: a dotted-quad IPv4 string. net.ParseIP
	// returns a non-nil IP whose To16() is the IPv4-mapped form, so only the
	// explicit To4()!=nil guard rejects it. Without that guard this would
	// wrongly succeed and encode v4 as ::ffff:a.b.c.d.
	t.Run("rejects_ipv4_dotted_quad", func(t *testing.T) {
		if _, err := parseIP6("198.51.100.7"); err == nil {
			t.Fatal("parseIP6(198.51.100.7) succeeded, want error — IPv4 must be rejected (would otherwise encode as IPv4-mapped v6)")
		}
	})

	// IPv4-mapped written explicitly in v6 notation is still an IPv4 address
	// (To4() is non-nil) and must be rejected for the same reason.
	t.Run("rejects_ipv4_mapped", func(t *testing.T) {
		if _, err := parseIP6("::ffff:198.51.100.7"); err == nil {
			t.Fatal("parseIP6(::ffff:198.51.100.7) succeeded, want error — IPv4-mapped is an IPv4 address")
		}
	})

	t.Run("rejects_garbage", func(t *testing.T) {
		if _, err := parseIP6("not-an-ip"); err == nil {
			t.Fatal("parseIP6(not-an-ip) succeeded, want error")
		}
	})

	t.Run("rejects_empty", func(t *testing.T) {
		if _, err := parseIP6(""); err == nil {
			t.Fatal("parseIP6(\"\") succeeded, want error")
		}
	})
}
