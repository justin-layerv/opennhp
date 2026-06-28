//go:build linux

package ebpf

// This file is the E2 IPv6 admission DATAPATH proof. It is the IPv6 twin of
// TestSurgicalKillDatapath (surgical_kill_datapath_linux_test.go) and closes
// the load-bearing gap the whole IPv6 slice (E2) exists to fix:
//
//	before this slice, the XDP program's ETH_P_IPV6 switch arm
//	unconditionally `return XDP_PASS`ed — IPv6 traffic FAILED OPEN. The
//	slice rewrites that arm (xdp_white_prog_v6 in nhp_ebpf_xdp.c) into a
//	filtered conntrack-fast-path -> allow-rule-cascade -> fail-CLOSED
//	admission, mirroring the IPv4 flow.
//
// The keys_v6_test.go golden-byte tests prove the Go serializers emit the
// exact packed bytes the kernel `*_v6` structs expect, but they are PURE
// (no kernel): they cannot prove the COMPILED program actually consults
// those maps and actually DROPs on no-match. This test does: it loads the
// REAL compiled XDP object, drives SYNTHETIC IPv6 packets through it via the
// kernel BPF_PROG_TEST_RUN syscall (cilium/ebpf Program.Run), and asserts:
//
//	PASS case  — a v6 packet matching a seeded sdwhitelist_v6 (src+dst)
//	             allow-rule is admitted -> XDP_PASS.
//	DROP case  — a v6 packet with NO matching allow-rule and NO conntrack
//	             entry falls through the whole v6 cascade -> XDP_DROP. This
//	             is the fail-closed proof: IPv6 no longer fails open.
//
// WHY sdwhitelist_v6 for the PASS seed: its key is src_ip+dst_ip ONLY (no
// port, no protocol — struct sdwhitelist_key_v6, 32 bytes). That is the
// cleanest allow-rule to seed deterministically: the PASS and DROP packets
// can be byte-identical except for the discriminator (the source IP), so a
// PASS-vs-DROP flip isolates exactly "an allow-rule matched" with nothing
// port- or protocol-special in play. The v6 datapath has NO port special-
// casing (the SSH/DHCP/DNS bypasses are IPv4-only), so dst_port=443 is an
// ordinary port here.
//
// NON-VACUITY: the PASS and DROP packets differ ONLY in the source IPv6
// address (the sole key discriminator for sdwhitelist_v6). Same EtherType,
// same dst IP, same ports, same TCP framing. So the verdict difference can
// come from nothing but the allow-rule match — neither assertion can pass
// vacuously while the other is broken.
//
// EXECUTION / CI: identical harness contract to TestSurgicalKillDatapath —
// needs CAP_BPF (or CAP_SYS_ADMIN) + a kernel that loads XDP + the compiled
// object at NHP_EBPF_XDP_OBJECT. Run via `make test-ebpf`. LOUD-SKIP guard
// (memory: feedback_silent_failure_patterns.md): with NHP_REQUIRE_BPF_TESTS=1
// any missing capability / kernel support / missing object is a hard
// t.Fatal, never a silent skip-pass. The shared loud-skip guard, verdict
// runner, XDP-action constants and names live in
// surgical_kill_datapath_linux_test.go and are reused here (same package).

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	// sdWhitelistV6MapName is the SEC(".maps") symbol name of the v6
	// src+dst allow-rule map in nhp_ebpf_xdp.c (`} sdwhitelist_v6
	// SEC(".maps");`). A rename in the C source makes the lookup return a
	// nil map -> hard Fatal below, the desired fail-loud rather than a
	// silent pass. (xdpProgName "xdp_white_prog" is shared from
	// surgical_kill_datapath_linux_test.go — the v6 path is reached through
	// the same program's ETH_P_IPV6 switch arm, not a separate program.)
	sdWhitelistV6MapName = "sdwhitelist_v6"

	// sppV6MapName is the SEC(".maps") symbol of the v6 per-port allow-rule
	// map (`} spp_v6 SEC(".maps");`). Its key is whitelist_key_v6 =
	// src_ip+dst_ip+dst_port+protocol (35 bytes), so it is the map the v6 UDP
	// case seeds (proto=IPPROTO_UDP). It is the FIRST rule in the v6 allow-rule
	// cascade (spp_v6 -> sdwhitelist_v6 -> src_port_v6 -> ...).
	sppV6MapName = "spp_v6"

	// icmpWlV6MapName is the SEC(".maps") symbol of the v6 ICMP allow-rule map.
	// The C struct is `icmpwhitelist_key_v6` but the MAP is named `icmp_wl_v6`
	// (the 15-char BPF map-name cap forces the abbreviation — see PinPath
	// comment in ebpf.go). Its key is src_ip+dst_ip (32 bytes, identical shape
	// to sdwhitelist_key_v6 -> serialized with ToSdKeyV6). ICMPv6 has no ports
	// and is gated SOLELY by this map (the C scopes the ICMPv6 branch so a miss
	// does not fall through to the port cascade).
	icmpWlV6MapName = "icmp_wl_v6"

	// srcPortV6MapName is the SEC(".maps") symbol of the v6 src+dst_port
	// allow-rule map (`} src_port_v6 SEC(".maps");`). Its key is
	// src_port_list_key_v6 = src_ip+dst_port (18 bytes), serialized via the
	// production ToSpKeyV6. It is the SECOND rule in the v6 allow-rule cascade
	// (spp_v6 -> sdwhitelist_v6 -> src_port_v6 -> port_list_v6 -> ...), so the
	// src_port_v6 datapath test seeds NEITHER spp_v6 nor sdwhitelist_v6 (a hit
	// in an earlier map would PASS first and never consult src_port_v6).
	srcPortV6MapName = "src_port_v6"

	// portListV6MapName is the SEC(".maps") symbol of the v6 src+port-range
	// allow-rule map (`} port_list_v6 SEC(".maps");`). Its key is
	// port_list_key_v6 = src_ip+min_port+max_port (20 bytes), serialized via
	// ToPlKeyV6. The C builds the lookup key with the COMPILE-TIME constants
	// MIN_PORT(0)/MAX_PORT(65535) (NOT packet-derived — nhp_ebpf_xdp.c
	// `.min_port = MIN_PORT, .max_port = MAX_PORT`), so the seeded rule MUST use
	// DstPortStart=0/DstPortEnd=65535 to match. It is the THIRD allow-rule in the
	// cascade, after src_port_v6.
	portListV6MapName = "port_list_v6"

	// portListMinPort / portListMaxPort are the exact MIN_PORT / MAX_PORT
	// compile-time constants the C `port_list_v6` lookup hardcodes into the key
	// (#define MIN_PORT 0 / #define MAX_PORT 65535 in nhp_ebpf_xdp.c). The
	// port_list_v6 seed MUST use these literal bounds — the C never derives the
	// range from the packet, so any other bounds produce a key the datapath
	// never looks up (a guaranteed miss that would make the PASS case fail).
	portListMinPort uint16 = 0
	portListMaxPort uint16 = 65535

	// IPv6 next-header / ICMPv6 type constants used by the TCP, UDP and ICMPv6
	// packet crafters. Spelled out here (not pulled from x/sys) to keep the
	// test dependency-free and to document the exact on-wire values the C
	// switch (nexthdr == IPPROTO_TCP / IPPROTO_UDP / IPPROTO_ICMPV6) and ICMPv6
	// type check (icmp6_type == ICMPV6_ECHO_REQUEST) compare against.
	ipprotoTCP        = 6   // IPPROTO_TCP
	ipprotoUDP        = 17  // IPPROTO_UDP
	ipprotoICMPv6     = 58  // IPPROTO_ICMPV6 (next header for ICMPv6)
	icmpv6EchoRequest = 128 // ICMPV6_ECHO_REQUEST (type)
)

// seedWhitelistValueV6 builds a whitelist_value byte buffer of the map's
// exact value size that is GUARANTEED allowed + not-expired. The kernel
// checks `val->expire_time < now` where `now = bpf_ktime_get_ns()` —
// CLOCK_MONOTONIC nanoseconds since boot, NOT wall-clock. A small/duration-
// shaped expire_time can read as already-expired on a runner with any
// uptime, in which case the XDP program DELETES the rule and DROPs — turning
// the PASS case into a spurious DROP. We therefore use 1<<62 (≈ 4.6e18 ns ≈
// 146 years), which dwarfs any plausible monotonic clock, exactly mirroring
// seedConnValue's never-expire constant.
//
// Layout matches `struct sdwhitelist_value { __u8 allowed; __u64 expire_time; }`
// (NOT __packed -> natural alignment): allowed at byte 0, expire_time at
// ExpireTimeOffset (8, after 7 alignment pad bytes). Both offsets come from the
// package's own whitelistValue layout consts so a future Go-struct change is a
// compile-time/const-driven failure, not a silent wrong-offset write. Padding
// bytes 1..7 stay zero (make zero-fills).
//
// ONE BUFFER FOR THREE MAPS: this seeds sdwhitelist_v6 / spp_v6 / icmp_wl_v6,
// whose C value structs (sdwhitelist_value / whitelist_value /
// icmpwhitelist_value) are hand-written identically as {__u8 allowed; __u64
// expire_time;}. The C does NOT _Static_assert the VALUE sizes (only the *key*
// structs are size-pinned — nhp_ebpf_xdp.c L116–145), so we cannot lean on a C
// assert to keep the three value layouts in lockstep. The guard below fences a
// SIZE divergence (any of the three maps' value size != the Go whitelistValue
// size ExpireTimeOffset comes from), which is the only mismatch that would write
// out of bounds or at a stale offset.
//
// It does NOT catch a same-size FIELD REORDER (e.g. swapping allowed/expire_time
// keeps 16 bytes). That residual is NOT fenced by any Go-side mechanism — the
// golden-byte tests / boot enumeration / production serializers all exercise the
// Go whitelistValue layout against itself and never load the compiled C struct,
// so none of them can observe a C-only reorder. The actual fence is THIS file's
// in-kernel PASS cases (deferred to consolidation here; macOS only compile-
// checks): the seed writes the Go layout (allowed@0, expire_time@8); a reordered
// C reads expire_time from bytes 0..7 = 0x..01 (≈1ns), which is < bpf_ktime now,
// so the C treats the rule as expired -> bpf_map_delete_elem + XDP_DROP (see the
// `sd_val->expire_time < now` arm in xdp_white_prog_v6) -> the PASS assertion
// fails loudly. (Such a reorder fails CLOSED in prod too — DROP, an outage, not
// a bypass.) The missing C value-size _Static_assert is a C-side hardening item,
// out of scope for this test-only slice.
func seedWhitelistValueV6(t *testing.T, valueSize uint32) []byte {
	t.Helper()
	// We write a uint64 at ExpireTimeOffset, so the buffer must be exactly the
	// Go whitelistValue size (16 bytes). An EXACT check (not just >=
	// ExpireTimeOffset+8) catches a grow as well as a shrink, i.e. any value-
	// size drift of these three maps away from the Go struct ExpireTimeOffset is
	// derived from — fail loud with the sizes rather than write at a stale
	// offset / panic with an opaque slice-bounds error.
	if int(valueSize) != WhitelistValueSize {
		t.Fatalf("v6 allow-rule map value size %d != Go whitelistValue size %d (allowed@0 + expire_time@%d) — the kernel sdwhitelist_value/whitelist_value/icmpwhitelist_value layout drifted from the Go struct; reconcile before trusting the offset write",
			valueSize, WhitelistValueSize, ExpireTimeOffset)
	}
	buf := make([]byte, valueSize)
	buf[0] = 1 // allowed = 1
	binary.LittleEndian.PutUint64(buf[ExpireTimeOffset:ExpireTimeOffset+8], uint64(1)<<62)
	return buf
}

// ethIPv6Header builds the shared 14-byte Ethernet + 40-byte IPv6 fixed-header
// prefix every v6 test frame starts with. nextHdr selects the L4 protocol
// (IPPROTO_TCP/UDP/ICMPV6) and payloadLen is the L4 byte count written into the
// IPv6 header's payload-length field. All three crafters (TCP/UDP/ICMPv6) share
// this so the eth+ip6 framing lives in exactly one place.
//
// IPv6 fixed header (40 bytes) layout written below:
//
//	byte  0      : 0x60  -> version=6 (high nibble); traffic-class/flow-label 0
//	bytes 1..3   : 0     -> rest of traffic class + 20-bit flow label
//	bytes 4..5   : payload length (big-endian) = L4 byte count (payloadLen)
//	byte  6      : next header (IPPROTO_TCP/UDP/ICMPV6)
//	byte  7      : hop limit = 64
//	bytes 8..23  : source address (16)
//	bytes 24..39 : destination address (16)
//	bytes 40..   : L4 header (appended by the caller)
//
// MAC addresses are arbitrary; the XDP switch keys only on the EtherType.
func ethIPv6Header(srcIP6, dstIP6 [16]byte, nextHdr uint8, payloadLen uint16) []byte {
	// Reserve room for the L4 header the caller appends next (payloadLen ==
	// the L4 byte count for all three crafters), so that append does not
	// realloc a buffer that would otherwise be returned at exactly cap 54.
	hdr := make([]byte, 0, 14+40+int(payloadLen))

	// Ethernet header (14 bytes): dst MAC, src MAC, EtherType 0x86DD (IPv6).
	hdr = append(hdr,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // dst MAC
		0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // src MAC
		0x86, 0xDD, // EtherType IPv6
	)

	// IPv6 fixed header (40 bytes).
	ip6 := make([]byte, 40)
	ip6[0] = 0x60                                    // version=6, traffic class hi nibble 0
	binary.BigEndian.PutUint16(ip6[4:6], payloadLen) // payload length = L4 length
	ip6[6] = nextHdr                                 // next header (TCP/UDP/ICMPv6)
	ip6[7] = 64                                      // hop limit
	copy(ip6[8:24], srcIP6[:])                       // source address
	copy(ip6[24:40], dstIP6[:])                      // destination address
	hdr = append(hdr, ip6...)

	return hdr
}

// craftTCPv6Packet builds a minimal Ethernet+IPv6+TCP frame for
// BPF_PROG_TEST_RUN. The XDP program routes 0x86DD -> xdp_white_prog_v6, which
// parses the 40-byte fixed IPv6 header (nexthdr must be directly TCP — no
// extension-header chaining is accepted) then the TCP header for sport/dport.
// The C builds the sdwhitelist_v6 key from ip6h->saddr/daddr, so the packet's
// source/dest addresses must equal the rule's SrcIP/DstIP — feed the SAME
// [16]byte into the packet here and into the srcDestKeyV6 to keep them in
// lockstep. srcIP6/dstIP6 are the on-wire 16 bytes (as produced by parseIP6).
func craftTCPv6Packet(t *testing.T, srcIP6, dstIP6 [16]byte, srcPort, dstPort uint16) []byte {
	t.Helper()

	const tcpLen = 20
	pkt := ethIPv6Header(srcIP6, dstIP6, ipprotoTCP, tcpLen)

	// TCP header (20 bytes, data offset = 5). The C reads only source/dest
	// ports; the SYN flag and zero checksum are cosmetic for the verdict and
	// the kernel BPF_PROG_TEST_RUN path does not validate the TCP checksum.
	tcpHdr := make([]byte, tcpLen)
	binary.BigEndian.PutUint16(tcpHdr[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHdr[2:4], dstPort)
	tcpHdr[12] = 0x50 // data offset = 5 (<<4)
	tcpHdr[13] = 0x02 // SYN
	pkt = append(pkt, tcpHdr...)

	return pkt
}

// craftUDPv6Packet builds a minimal Ethernet+IPv6+UDP frame for
// BPF_PROG_TEST_RUN. The XDP program routes 0x86DD -> xdp_white_prog_v6, which
// reads nexthdr=IPPROTO_UDP(17) then the 8-byte UDP header for sport/dport. The
// C builds the spp_v6 key from {saddr, daddr, udp->dest, nexthdr=17}, so the
// packet's dst_port (on-wire, big-endian) and protocol must match the seeded
// whitelist_key_v6. srcIP6/dstIP6 are the on-wire 16 bytes (as from parseIP6).
func craftUDPv6Packet(t *testing.T, srcIP6, dstIP6 [16]byte, srcPort, dstPort uint16) []byte {
	t.Helper()

	const udpLen = 8
	pkt := ethIPv6Header(srcIP6, dstIP6, ipprotoUDP, udpLen)

	// UDP header (8 bytes): src port, dst port, length, checksum. The C reads
	// only source/dest; length+checksum are cosmetic for the verdict (left 0 /
	// length-only) and the kernel BPF_PROG_TEST_RUN path does not validate the
	// UDP checksum.
	udpHdr := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udpHdr[0:2], srcPort)
	binary.BigEndian.PutUint16(udpHdr[2:4], dstPort)
	binary.BigEndian.PutUint16(udpHdr[4:6], udpLen) // UDP length (header only, no payload)
	pkt = append(pkt, udpHdr...)

	return pkt
}

// craftICMPv6EchoRequest builds a minimal Ethernet+IPv6+ICMPv6 Echo Request
// frame. nexthdr=IPPROTO_ICMPV6(58); the ICMPv6 header is the FULL 8 bytes
// (`struct icmp6hdr`: type+code+checksum + 4-byte echo body) the C bound
// `(icmp6 + 1) > data_end` requires — a short 4-byte header would DROP even the
// PASS packet. type=ICMPV6_ECHO_REQUEST(128), code=0 (the C admits an Echo
// Request only via a matching icmp_wl_v6 entry; Echo Reply(129) would PASS
// unconditionally and make the DROP case vacuous, so BOTH packets are Echo
// Requests). checksum + echo body (id/seq) are zero — the C reads neither.
func craftICMPv6EchoRequest(t *testing.T, srcIP6, dstIP6 [16]byte) []byte {
	t.Helper()

	const icmp6Len = 8
	pkt := ethIPv6Header(srcIP6, dstIP6, ipprotoICMPv6, icmp6Len)

	// ICMPv6 header (8 bytes): type, code, checksum[2], echo body (id[2]+seq[2]).
	icmp6 := make([]byte, icmp6Len)
	icmp6[0] = icmpv6EchoRequest // type = Echo Request (128)
	icmp6[1] = 0                 // code = 0
	// checksum (bytes 2..3) and echo id/seq (bytes 4..7) stay zero.
	pkt = append(pkt, icmp6...)

	return pkt
}

// v6TestAddrs parses the three IPv6 addresses every admission case shares and
// returns them already byte-decoded (allowedSrc, dst, deniedSrc). All three
// tests seed an allow-rule on (allowedSrc, dst) and craft a PASS packet from
// that pair plus a DROP packet that swaps allowedSrc -> deniedSrc, so the
// PASS-vs-DROP verdict is attributable to the source IP alone. The
// allowedSrc != deniedSrc check is the non-vacuity floor (identical source IPs
// would make the DROP packet identical to the PASS packet); it is asserted
// once here rather than copy-pasted into each test. assertDifferOnlyInV6SrcAddr
// is the per-packet companion fence that nothing OTHER than the source IP
// differs. Parsing goes through mustParseIP6 (hard Fatal on error): these are
// fixed literals, so a parse failure means parseIP6 itself regressed, not a
// test-input problem.
func v6TestAddrs(t *testing.T) (allowedSrc, dst, deniedSrc [16]byte) {
	t.Helper()
	allowedSrc = mustParseIP6(t, "2001:db8::7")
	dst = mustParseIP6(t, "2001:db8::10")
	deniedSrc = mustParseIP6(t, "2001:db8::dead")
	if allowedSrc == deniedSrc {
		t.Fatal("allowed and denied source IPs are identical — the DROP case would be vacuous")
	}
	return allowedSrc, dst, deniedSrc
}

// loadXDPCollectionV6 loads the compiled XDP object and returns the program +
// the whole collection. It mirrors loadXDPCollection's failure folding exactly
// (every environment failure -> skipOrFatal: Fatal when NHP_REQUIRE_BPF_TESTS=1,
// LOUD Skip otherwise) and strips PIN_BY_NAME from every map spec
// (BPF_PROG_TEST_RUN needs no bpffs; the object carries several PIN_BY_NAME maps
// and loading is whole-object). It returns the COLLECTION rather than a single
// map handle because the three v6 admission cases (TCP/UDP via spp_v6 &
// sdwhitelist_v6, ICMPv6 via icmp_wl_v6) all live in one object — one load
// yields every map. Callers pick the map they need via requireMapV6. The
// returned cleanup closes the collection.
func loadXDPCollectionV6(t *testing.T) (*ebpf.Program, *ebpf.Collection, func()) {
	t.Helper()

	objPath := os.Getenv(objectPathEnv)
	if objPath == "" {
		skipOrFatal(t, "no XDP object: %s is empty (run via `make test-ebpf`)", objectPathEnv)
		return nil, nil, nil
	}
	if _, err := os.Stat(objPath); err != nil {
		skipOrFatal(t, "XDP object %q not readable: %v (build it: `make test-ebpf`-style target compiles nhp_ebpf_xdp.o)", objPath, err)
		return nil, nil, nil
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		skipOrFatal(t, "rlimit.RemoveMemlock (needed to load the BPF maps; CAP_SYS_RESOURCE / CAP_BPF): %v", err)
		return nil, nil, nil
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		skipOrFatal(t, "LoadCollectionSpec(%q): %v", objPath, err)
		return nil, nil, nil
	}

	// Strip PIN_BY_NAME from all maps — BPF_PROG_TEST_RUN needs no bpffs.
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		// EPERM/ENOSYS here = no CAP_BPF / kernel can't load XDP: precisely
		// the "missing capability / kernel support" the guard turns into
		// Fatal-when-required, Skip-otherwise.
		skipOrFatal(t, "NewCollection (load XDP object into kernel): %v", err)
		return nil, nil, nil
	}

	prog := coll.Programs[xdpProgName]
	if prog == nil {
		coll.Close()
		// A nil program is NOT an environment problem — it means the C symbol
		// was renamed. Always fail loud regardless of the guard.
		t.Fatalf("program %q not found in %s (symbol renamed in nhp_ebpf_xdp.c?)", xdpProgName, objPath)
		return nil, nil, nil
	}

	return prog, coll, coll.Close
}

// requireMapV6 fetches a named map handle from the loaded collection, failing
// LOUD (never a silent skip-pass) if it is absent. A nil map is not an
// environment problem — it means the C SEC(".maps") symbol was renamed or the
// v6 maps were never integrated into the object — so this Fatals regardless of
// the NHP_REQUIRE_BPF_TESTS guard, mirroring loadXDPCollection's program/map
// nil-checks.
func requireMapV6(t *testing.T, coll *ebpf.Collection, name string) *ebpf.Map {
	t.Helper()
	m := coll.Maps[name]
	if m == nil {
		t.Fatalf("map %q not found in XDP object (symbol renamed in nhp_ebpf_xdp.c, or the v6 maps were not integrated into the object?)", name)
	}
	return m
}

// TestIPv6AdmissionDatapath is the E2 IPv6 fail-closed datapath proof. It
// seeds one sdwhitelist_v6 (src+dst) allow-rule, then asserts:
//
//	PASS — a v6 packet whose source/dest match the rule is admitted
//	       (XDP_PASS): the v6 allow-rule cascade actually consults
//	       sdwhitelist_v6 and admits on a hit.
//	DROP — a v6 packet identical except for its source IP (so it misses the
//	       rule) and with no conntrack entry is dropped (XDP_DROP): the
//	       ETH_P_IPV6 arm no longer fails open.
//
// The PASS-vs-DROP flip (packets differing only in the source IP, the sole
// sdwhitelist_v6 key discriminator) is the load-bearing, non-vacuous
// assertion.
func TestIPv6AdmissionDatapath(t *testing.T) {
	prog, coll, cleanup := loadXDPCollectionV6(t)
	if cleanup != nil {
		defer cleanup()
	}
	sdMap := requireMapV6(t, coll, sdWhitelistV6MapName)

	// Allow-rule + matching packet tuple (shared addresses + non-vacuity floor
	// via v6TestAddrs). The packet's saddr/daddr feed the C's sdwhitelist_v6 key
	// (src_ip=ip6h->saddr, dst_ip=ip6h->daddr), so the SAME [16]byte values go
	// into both the rule key and the packet. The DROP packet differs from the
	// PASS packet in EXACTLY one field — the source IP (allowedSrc -> deniedSrc);
	// same dst, same ports, same TCP framing -> the only thing that can change
	// the verdict is whether sdwhitelist_v6 matches.
	allowedSrc, dstIP, deniedSrc := v6TestAddrs(t)

	const (
		srcPort uint16 = 51000
		dstPort uint16 = 443 // ordinary port; the v6 path has no SSH/DHCP/DNS special-casing
	)

	// Seed the v6 allow-rule: sdwhitelist_v6[src=allowedSrc, dst=dstIP] =
	// {allowed:1, expire_time:never}. Key built via the production serializer
	// (ToSdKeyV6), value sized to the map's actual ValueSize.
	sdKey := (&srcDestKeyV6{SrcIP: allowedSrc, DstIP: dstIP}).ToSdKeyV6()
	sdVal := seedWhitelistValueV6(t, sdMap.ValueSize())
	if err := sdMap.Put(sdKey, sdVal); err != nil {
		t.Fatalf("seed sdwhitelist_v6[allow]: %v", err)
	}

	allowPkt := craftTCPv6Packet(t, allowedSrc, dstIP, srcPort, dstPort)
	denyPkt := craftTCPv6Packet(t, deniedSrc, dstIP, srcPort, dstPort)

	// Sanity: the two packets really are byte-identical except for the 16-byte
	// source-address field (IPv6 saddr at offset 14[eth]+8 .. +16). If they
	// differed anywhere else, the PASS-vs-DROP comparison would not isolate
	// the allow-rule match and the proof would be vacuous.
	assertDifferOnlyInV6SrcAddr(t, allowPkt, denyPkt)

	// PASS case: the v6 packet matches the seeded sdwhitelist_v6 rule. The C
	// v6 cascade misses spp_v6 (unseeded), hits sdwhitelist_v6, populates
	// conn_track_v6 and returns XDP_PASS.
	if got := runVerdict(t, prog, allowPkt); got != xdpPass {
		t.Fatalf("PASS case: verdict = %d (%s), want XDP_PASS(%d) — a v6 packet matching a seeded sdwhitelist_v6 (src+dst) rule must be admitted; if DROP, the v6 allow-rule cascade did not consult sdwhitelist_v6 (or the seeded rule read as expired)",
			got, xdpName(got), xdpPass)
	}

	// DROP case (the fail-closed proof): an IPv6+TCP packet with no matching
	// allow-rule (different source IP) and no conn_track_v6 entry falls
	// through the entire v6 cascade to XDP_DROP. Before this slice the
	// ETH_P_IPV6 arm fail-OPENed (unconditional XDP_PASS); a PASS here would
	// mean IPv6 still fails open.
	if got := runVerdict(t, prog, denyPkt); got != xdpDrop {
		t.Fatalf("DROP case: verdict = %d (%s), want XDP_DROP(%d) — an unmatched IPv6 packet (no allow-rule, no conntrack) must FAIL CLOSED. A PASS here means the ETH_P_IPV6 arm still fails open (the exact regression this E2 slice fixes); ABORTED means the program faulted",
			got, xdpName(got), xdpDrop)
	}
}

// TestIPv6AdmissionDatapathUDP is the IPv6+UDP twin of
// TestIPv6AdmissionDatapath. It exercises the spp_v6 per-port allow-rule
// (whitelist_key_v6 = src+dst+dst_port+protocol) — the FIRST rule in the v6
// cascade — with protocol=IPPROTO_UDP, asserting:
//
//	PASS — a v6 UDP packet whose {src,dst,dst_port,proto=17} matches a seeded
//	       spp_v6 rule is admitted (XDP_PASS).
//	DROP — a v6 UDP packet identical except for its source IP (so it misses
//	       spp_v6) and with no conntrack entry falls through the whole v6
//	       cascade to XDP_DROP (fail-closed).
//
// The PASS-vs-DROP flip differs ONLY in the source IP (fenced by
// assertDifferOnlyInV6SrcAddr, whose src-addr offset is L4-agnostic), so the
// verdict difference is attributable to the spp_v6 match alone. A fresh
// collection is loaded so no rule/conntrack state leaks from the TCP case.
func TestIPv6AdmissionDatapathUDP(t *testing.T) {
	prog, coll, cleanup := loadXDPCollectionV6(t)
	if cleanup != nil {
		defer cleanup()
	}
	sppMap := requireMapV6(t, coll, sppV6MapName)

	allowedSrc, dstIP, deniedSrc := v6TestAddrs(t)

	const (
		srcPort uint16 = 51000
		dstPort uint16 = 53 // ordinary UDP port; the v6 path has no DNS/DHCP special-casing
	)

	// Seed spp_v6[{src=allowedSrc, dst=dstIP, dst_port=53, proto=UDP}] =
	// {allowed:1, expire_time:never}. Key built via the production serializer
	// (ToWlKeyV6, which writes dst_port BIG-endian — matching the on-wire
	// big-endian dst_port the C reads from udp->dest). protocol=IPPROTO_UDP is
	// load-bearing: the spp_v6 key includes protocol, so a TCP-proto seed would
	// silently miss the UDP packet.
	wlKey := (&whitelistKeyV6{SrcIP: allowedSrc, DstIP: dstIP, DstPort: dstPort, Protocol: ipprotoUDP}).ToWlKeyV6()
	wlVal := seedWhitelistValueV6(t, sppMap.ValueSize())
	if err := sppMap.Put(wlKey, wlVal); err != nil {
		t.Fatalf("seed spp_v6[allow]: %v", err)
	}

	allowPkt := craftUDPv6Packet(t, allowedSrc, dstIP, srcPort, dstPort)
	denyPkt := craftUDPv6Packet(t, deniedSrc, dstIP, srcPort, dstPort)
	assertDifferOnlyInV6SrcAddr(t, allowPkt, denyPkt)

	// PASS: the v6 UDP packet matches the seeded spp_v6 rule -> XDP_PASS.
	if got := runVerdict(t, prog, allowPkt); got != xdpPass {
		t.Fatalf("UDP PASS case: verdict = %d (%s), want XDP_PASS(%d) — a v6 UDP packet matching a seeded spp_v6 {src,dst,dport,proto=UDP} rule must be admitted; if DROP, the v6 cascade did not consult spp_v6 (wrong protocol in the key? seeded rule read as expired?)",
			got, xdpName(got), xdpPass)
	}

	// DROP (fail-closed): a v6 UDP packet with no matching spp_v6 rule
	// (different source IP) and no conn_track_v6 entry must fall through the
	// whole cascade to XDP_DROP.
	if got := runVerdict(t, prog, denyPkt); got != xdpDrop {
		t.Fatalf("UDP DROP case: verdict = %d (%s), want XDP_DROP(%d) — an unmatched v6 UDP packet (no allow-rule, no conntrack) must FAIL CLOSED. A PASS here means the ETH_P_IPV6 arm still fails open for UDP",
			got, xdpName(got), xdpDrop)
	}
}

// TestIPv6AdmissionDatapathICMPv6 is the IPv6+ICMPv6 twin of
// TestIPv6AdmissionDatapath. ICMPv6 is portless and gated SOLELY by icmp_wl_v6
// (icmpwhitelist_key_v6 = src+dst; the C scopes the ICMPv6 branch so a miss
// does NOT fall through to the port cascade). It asserts:
//
//	PASS — an ICMPv6 Echo Request (type 128, code 0) whose {src,dst} matches a
//	       seeded icmp_wl_v6 rule is admitted (XDP_PASS).
//	DROP — an ICMPv6 Echo Request identical except for its source IP (so it
//	       misses icmp_wl_v6) is dropped (XDP_DROP, fail-closed).
//
// BOTH packets are Echo Requests on purpose: an Echo Reply (type 129) PASSes
// unconditionally in the C, which would make the DROP case vacuous. The
// PASS-vs-DROP flip differs ONLY in the source IP (fenced by
// assertDifferOnlyInV6SrcAddr). A fresh collection isolates this case.
func TestIPv6AdmissionDatapathICMPv6(t *testing.T) {
	prog, coll, cleanup := loadXDPCollectionV6(t)
	if cleanup != nil {
		defer cleanup()
	}
	icmpMap := requireMapV6(t, coll, icmpWlV6MapName)

	allowedSrc, dstIP, deniedSrc := v6TestAddrs(t)

	// Seed icmp_wl_v6[{src=allowedSrc, dst=dstIP}] = {allowed:1, never-expire}.
	// Key is src+dst only (icmpwhitelist_key_v6, identical shape to
	// sdwhitelist_key_v6) -> ToSdKeyV6. icmpwhitelist_value has the same
	// {allowed, expire_time} layout as sdwhitelist_value, so seedWhitelistValueV6
	// produces a correctly-sized never-expire value.
	icmpKey := (&srcDestKeyV6{SrcIP: allowedSrc, DstIP: dstIP}).ToSdKeyV6()
	icmpVal := seedWhitelistValueV6(t, icmpMap.ValueSize())
	if err := icmpMap.Put(icmpKey, icmpVal); err != nil {
		t.Fatalf("seed icmp_wl_v6[allow]: %v", err)
	}

	allowPkt := craftICMPv6EchoRequest(t, allowedSrc, dstIP)
	denyPkt := craftICMPv6EchoRequest(t, deniedSrc, dstIP)
	assertDifferOnlyInV6SrcAddr(t, allowPkt, denyPkt)

	// PASS: an Echo Request matching the seeded icmp_wl_v6 rule -> XDP_PASS.
	if got := runVerdict(t, prog, allowPkt); got != xdpPass {
		t.Fatalf("ICMPv6 PASS case: verdict = %d (%s), want XDP_PASS(%d) — an ICMPv6 Echo Request matching a seeded icmp_wl_v6 {src,dst} rule must be admitted; if DROP, the v6 ICMPv6 branch did not consult icmp_wl_v6 (seeded rule read as expired? echo body parsed wrong?)",
			got, xdpName(got), xdpPass)
	}

	// DROP (fail-closed): an Echo Request with no matching icmp_wl_v6 rule
	// (different source IP) must be dropped. Before this slice the ETH_P_IPV6
	// arm fail-OPENed; a PASS here means ICMPv6 still fails open.
	if got := runVerdict(t, prog, denyPkt); got != xdpDrop {
		t.Fatalf("ICMPv6 DROP case: verdict = %d (%s), want XDP_DROP(%d) — an unmatched ICMPv6 Echo Request (no icmp_wl_v6 rule) must FAIL CLOSED. A PASS here means the ICMPv6 path still fails open",
			got, xdpName(got), xdpDrop)
	}
}

// TestIPv6AdmissionDatapathSrcPort is the src_port_v6 twin of
// TestIPv6AdmissionDatapath and the END-TO-END regression guard for the s2
// ToSpKeyV6 byte-order fix. src_port_v6's key is src_port_list_key_v6 =
// {src_ip, dst_port}; the C builds the lookup key with `.dst_port = dport`,
// where `dport` is the on-wire BIG-endian __be16 read straight from the TCP
// header. So the seeded rule's dst_port byte-order MUST equal the packet's
// on-wire (big-endian) dst_port for the lookup to hit. This is the load-bearing
// assertion:
//
//	dst_port = 443 = 0x01BB is NON-palindromic, so a wrong serializer byte-order
//	is observable. After the s2 fix ToSpKeyV6 writes dst_port BIG-endian
//	(0x01,0xBB) == the on-wire bytes the C reads -> the PASS packet HITS
//	src_port_v6. With the pre-fix LITTLE-endian ToSpKeyV6 (0xBB,0x01) the seeded
//	key would NOT match the packet's key, the PASS case would DROP, and this test
//	would go RED — exactly the regression it guards. (This worktree still carries
//	the pre-fix LE serializer; the in-kernel run happens once s6 is rebased onto
//	qurl-v2 in the merge cascade with the BE s2 propagated up, which is why this
//	is compile-only here and runs green only after the rebase.)
//
//	PASS — a v6 TCP packet whose {src, dst_port} matches the seeded src_port_v6
//	       rule is admitted (XDP_PASS): the cascade actually consults src_port_v6
//	       AND the serialized dst_port byte-order matches the on-wire dst_port.
//	DROP — a v6 TCP packet identical except for its source IP (so it misses
//	       src_port_v6) and with no conntrack entry falls through to XDP_DROP
//	       (fail-closed).
//
// CASCADE ISOLATION: src_port_v6 is the SECOND allow-rule after sdwhitelist_v6
// (spp_v6 -> sdwhitelist_v6 -> src_port_v6). This test seeds ONLY src_port_v6 in
// a FRESH collection — neither spp_v6 nor sdwhitelist_v6 is touched — so the only
// map that can admit the PASS packet is src_port_v6; an earlier-map hit can't
// mask a src_port_v6 miss. The non-vacuity floor (PASS/DROP differ ONLY in the
// source IP) is fenced by assertDifferOnlyInV6SrcAddr exactly as in the siblings.
func TestIPv6AdmissionDatapathSrcPort(t *testing.T) {
	prog, coll, cleanup := loadXDPCollectionV6(t)
	if cleanup != nil {
		defer cleanup()
	}
	spMap := requireMapV6(t, coll, srcPortV6MapName)

	allowedSrc, dstIP, deniedSrc := v6TestAddrs(t)

	const (
		srcPort uint16 = 51000
		// dst_port = 443 = 0x01BB is deliberately NON-palindromic: it is the
		// discriminator that makes the dst_port byte-order observable end-to-end.
		// A palindromic port (e.g. 0 or 65535) would make BE and LE serialization
		// identical and the byte-order guard vacuous.
		dstPort uint16 = 443
	)

	// Seed src_port_v6[{src=allowedSrc, dst_port=443}] = {allowed:1, never-expire}.
	// Key built via the PRODUCTION serializer ToSpKeyV6 (the artifact under test —
	// NOT a hand-built key, which would byte-mirror the datapath on both sides and
	// pass even if the byte-order were wrong). The host-order dst_port (443) goes
	// into srcIPdstPortKeyV6; ToSpKeyV6 owns the on-wire byte-order. Value is the
	// shared never-expire sentinel (src_port_list_value is {allowed, expire_time},
	// same layout as sdwhitelist_value -> seedWhitelistValueV6 sizes it correctly).
	spKey := (&srcIPdstPortKeyV6{SrcIP: allowedSrc, DstPort: dstPort}).ToSpKeyV6()
	spVal := seedWhitelistValueV6(t, spMap.ValueSize())
	if err := spMap.Put(spKey, spVal); err != nil {
		t.Fatalf("seed src_port_v6[allow]: %v", err)
	}

	// The packet writes dst_port BIG-endian on the wire (craftTCPv6Packet uses
	// binary.BigEndian), which is what the C copies verbatim into the key's
	// dst_port. So this PASS packet matches the seeded rule iff ToSpKeyV6 also
	// emitted dst_port big-endian.
	allowPkt := craftTCPv6Packet(t, allowedSrc, dstIP, srcPort, dstPort)
	denyPkt := craftTCPv6Packet(t, deniedSrc, dstIP, srcPort, dstPort)
	assertDifferOnlyInV6SrcAddr(t, allowPkt, denyPkt)

	// PASS: the v6 TCP packet matches the seeded src_port_v6 rule -> XDP_PASS.
	// A DROP here means either the cascade did not consult src_port_v6 OR — the
	// regression this test exists for — ToSpKeyV6 serialized dst_port with the
	// wrong byte-order, so the seeded key did not match the on-wire dst_port.
	if got := runVerdict(t, prog, allowPkt); got != xdpPass {
		t.Fatalf("src_port_v6 PASS case: verdict = %d (%s), want XDP_PASS(%d) — a v6 TCP packet matching a seeded src_port_v6 {src,dst_port=443} rule must be admitted. A DROP means the cascade missed src_port_v6 OR ToSpKeyV6 wrote dst_port in the wrong byte-order (the s2 regression guarded here: seeded key's dst_port != the on-wire big-endian dst_port the C reads)",
			got, xdpName(got), xdpPass)
	}

	// DROP (fail-closed): a v6 TCP packet with no matching src_port_v6 rule
	// (different source IP) and no conn_track_v6 entry falls through the whole
	// cascade to XDP_DROP.
	if got := runVerdict(t, prog, denyPkt); got != xdpDrop {
		t.Fatalf("src_port_v6 DROP case: verdict = %d (%s), want XDP_DROP(%d) — an unmatched v6 TCP packet (no allow-rule, no conntrack) must FAIL CLOSED. A PASS here means the ETH_P_IPV6 arm still fails open",
			got, xdpName(got), xdpDrop)
	}
}

// TestIPv6AdmissionDatapathPortList is the port_list_v6 twin of
// TestIPv6AdmissionDatapath. port_list_v6's key is port_list_key_v6 =
// {src_ip, min_port, max_port}, and the C builds the lookup key with the
// COMPILE-TIME constants `.min_port = MIN_PORT(0), .max_port = MAX_PORT(65535)`
// — the port range is NOT derived from the packet. So a port_list_v6 rule is, in
// effect, a per-source-IP "any port in [0,65535]" allow, keyed only on src_ip
// plus those two fixed bounds. It asserts:
//
//	PASS — a v6 TCP packet whose source IP matches a seeded
//	       port_list_v6[{src, min=0, max=65535}] rule is admitted (XDP_PASS):
//	       the cascade actually reaches and consults port_list_v6.
//	DROP — a v6 TCP packet identical except for its source IP (so it misses
//	       port_list_v6) and with no conntrack entry falls through to XDP_DROP
//	       (fail-closed).
//
// SCOPE — this guards "the cascade REACHES port_list_v6 and fails closed on a
// miss", NOT the ToPlKeyV6 PORT byte-order. The C's key ports are the literal
// constants 0 and 65535, both BYTE-PALINDROMES (BE(0)==LE(0), BE(65535)==
// LE(65535)), so ToPlKeyV6's port byte-order is INVISIBLE through this datapath
// — a BE-vs-LE flip serializes to identical bytes for these two bounds. The
// ToPlKeyV6 port byte-order is covered instead by the keys_v6_test.go golden
// vectors, which use the NON-palindromic bounds 1/2. (The companion
// src_port_v6 test above IS the datapath byte-order guard, via the
// non-palindromic dst_port 443.) Seeding any bounds other than 0/65535 here
// would produce a key the C never looks up -> a guaranteed miss, which is why
// portListMinPort/portListMaxPort mirror MIN_PORT/MAX_PORT exactly.
//
// CASCADE ISOLATION: port_list_v6 is the THIRD allow-rule (after src_port_v6).
// This test seeds ONLY port_list_v6 in a FRESH collection, so no earlier map can
// admit the PASS packet and mask a port_list_v6 miss. Non-vacuity (PASS/DROP
// differ only in the source IP) is fenced by assertDifferOnlyInV6SrcAddr.
func TestIPv6AdmissionDatapathPortList(t *testing.T) {
	prog, coll, cleanup := loadXDPCollectionV6(t)
	if cleanup != nil {
		defer cleanup()
	}
	plMap := requireMapV6(t, coll, portListV6MapName)

	allowedSrc, dstIP, deniedSrc := v6TestAddrs(t)

	const (
		srcPort uint16 = 51000
		// Any dst_port works — the C does not key port_list_v6 on the packet's
		// dst_port (it uses MIN_PORT/MAX_PORT). 443 is reused for consistency with
		// the other TCP cases; it has no bearing on the port_list_v6 lookup.
		dstPort uint16 = 443
	)

	// Seed port_list_v6[{src=allowedSrc, min=0, max=65535}] = {allowed:1,
	// never-expire}. Key built via the PRODUCTION serializer ToPlKeyV6. The
	// bounds MUST be MIN_PORT(0)/MAX_PORT(65535) — the exact constants the C
	// hardcodes into the lookup key — else the seeded key is never consulted.
	// (These bounds are byte-palindromes, so this seed does NOT exercise
	// ToPlKeyV6's port byte-order; see the SCOPE note in the doc comment.)
	plKey := (&portListKeyV6{SrcIP: allowedSrc, DstPortStart: portListMinPort, DstPortEnd: portListMaxPort}).ToPlKeyV6()
	plVal := seedWhitelistValueV6(t, plMap.ValueSize())
	if err := plMap.Put(plKey, plVal); err != nil {
		t.Fatalf("seed port_list_v6[allow]: %v", err)
	}

	allowPkt := craftTCPv6Packet(t, allowedSrc, dstIP, srcPort, dstPort)
	denyPkt := craftTCPv6Packet(t, deniedSrc, dstIP, srcPort, dstPort)
	assertDifferOnlyInV6SrcAddr(t, allowPkt, denyPkt)

	// PASS: the v6 TCP packet's source IP matches the seeded port_list_v6 rule
	// (min=0/max=65535) -> XDP_PASS. A DROP means the cascade did not reach or
	// consult port_list_v6 (e.g. an earlier map short-circuited, or the seeded
	// bounds drifted from MIN_PORT/MAX_PORT so the C's key never matched).
	if got := runVerdict(t, prog, allowPkt); got != xdpPass {
		t.Fatalf("port_list_v6 PASS case: verdict = %d (%s), want XDP_PASS(%d) — a v6 TCP packet whose source IP matches a seeded port_list_v6 {src,min=0,max=65535} rule must be admitted; if DROP, the v6 cascade did not consult port_list_v6 (seeded bounds != MIN_PORT/MAX_PORT? seeded rule read as expired?)",
			got, xdpName(got), xdpPass)
	}

	// DROP (fail-closed): a v6 TCP packet with no matching port_list_v6 rule
	// (different source IP) and no conn_track_v6 entry must fall through the
	// whole cascade to XDP_DROP.
	if got := runVerdict(t, prog, denyPkt); got != xdpDrop {
		t.Fatalf("port_list_v6 DROP case: verdict = %d (%s), want XDP_DROP(%d) — an unmatched v6 TCP packet (no allow-rule, no conntrack) must FAIL CLOSED. A PASS here means the ETH_P_IPV6 arm still fails open",
			got, xdpName(got), xdpDrop)
	}
}

// assertDifferOnlyInV6SrcAddr fails the test unless the two crafted frames are
// byte-identical everywhere except the 16-byte IPv6 source-address field. That
// field sits at offset 14 (Ethernet) + 8 (into the IPv6 fixed header) = 22,
// spanning bytes 22..37. Pinning this makes the PASS-vs-DROP verdict
// difference attributable to the source IP alone (the sdwhitelist_v6
// discriminator) — i.e. it fences the non-vacuity of the proof.
func assertDifferOnlyInV6SrcAddr(t *testing.T, a, b []byte) {
	t.Helper()
	const srcAddrStart = 14 + 8 // Ethernet(14) + offset of saddr in the IPv6 header(8)
	const srcAddrEnd = srcAddrStart + 16
	if len(a) != len(b) {
		t.Fatalf("PASS/DROP packets differ in LENGTH (%d vs %d) — they must differ only in the source IP", len(a), len(b))
	}
	for i := range a {
		inSrcAddr := i >= srcAddrStart && i < srcAddrEnd
		if a[i] != b[i] && !inSrcAddr {
			t.Fatalf("PASS/DROP packets differ at byte %d (outside the IPv6 source-address field %d..%d): %02x vs %02x — the DROP case is not isolated to the source IP and the proof would be vacuous",
				i, srcAddrStart, srcAddrEnd-1, a[i], b[i])
		}
	}
	// And they MUST differ somewhere inside the source-address field, else the
	// two packets are identical and the DROP case is vacuous.
	if bytes.Equal(a[srcAddrStart:srcAddrEnd], b[srcAddrStart:srcAddrEnd]) {
		t.Fatal("PASS/DROP packets have IDENTICAL source addresses — the DROP case would be vacuous (same packet as PASS)")
	}
}
