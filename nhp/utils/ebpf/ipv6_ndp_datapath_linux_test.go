//go:build linux

package ebpf

// This file is the E2 slice-3 proof for the ICMPv6 type-filter behavior the
// IPv6 XDP datapath (xdp_white_prog_v6 in nhp_ebpf_xdp.c) MUST get right before
// the E5 FilterMode flip:
//
//   - Neighbor Discovery (RFC 4861 types 133–137: RS/RA/NS/NA/Redirect) must
//     PASS unconditionally. NDP is the IPv6 analog of ARP; the v4 path passes
//     ARP via `case ETH_P_ARP: return XDP_PASS`, but NDP rides inside ICMPv6 on
//     the ETH_P_IPV6 ethertype, so its passthrough lives in the ICMPv6 branch.
//     Without it, loading XDP on a v6-bearing interface blackholes neighbor
//     resolution (inbound NS for the AC's own address dropped -> no NA).
//   - Packet Too Big (type 2) must PASS: IPv6 PMTUD depends entirely on it
//     (routers never fragment), and its source is a path router whose address
//     can't be whitelisted, so no map could admit it (RFC 4890 §4.3.1).
//   - Everything else stays fail-CLOSED: Echo Request (128) without a matching
//     icmp_wl_v6 entry DROPs, and a non-passed type such as MLD Query (130)
//     DROPs. These two DROP cases are the load-bearing CONTRAST: they prove the
//     program discriminates BY TYPE and is not blanket-passing all ICMPv6.
//
// WHY this lives in slice 3 (not the slice-6 datapath test file): the .c change
// these cases prove is introduced by THIS slice, and the gate that re-proves it
// in-kernel (eBPF surgical-kill datapath proof, ebpf-datapath-test.yml) runs on
// this PR. Identifiers here are deliberately disjoint from
// ipv6_admission_datapath_linux_test.go (slice 6) so the two files coexist when
// the stack rebases — this file shares ONLY the primitives already present in
// slice 3's surgical_kill_datapath_linux_test.go (loadXDPCollection, runVerdict,
// the xdp* verdict constants/names, skipOrFatal). It seeds NO maps: the NDP/PTB
// PASS verdicts are unconditional, so loading the object and driving one packet
// is the whole proof — and the empty-collection PASS is itself evidence the
// verdict is unconditional, not accidentally map-gated.
//
// EXECUTION / CI: identical harness contract to TestSurgicalKillDatapath — needs
// CAP_BPF (or CAP_SYS_ADMIN) + a kernel that loads XDP + the compiled object at
// NHP_EBPF_XDP_OBJECT. Run via `make test-ebpf`. LOUD-SKIP guard (memory:
// feedback_silent_failure_patterns.md): with NHP_REQUIRE_BPF_TESTS=1 any missing
// capability / kernel support / missing object is a hard t.Fatal, never a silent
// skip-pass.

import (
	"encoding/binary"
	"net"
	"testing"
)

const (
	// ICMPv6 next header and the type numbers this test drives. Spelled out
	// here (not pulled from x/sys) to keep the test dependency-free and to
	// document the exact on-wire values the C ICMPv6 branch compares against
	// (icmp6_type == ICMPV6_ND_NEIGHBOR_SOLICIT, == ICMPV6_PKT_TOO_BIG, ...).
	ndpIPProtoICMPv6 = 58 // IPPROTO_ICMPV6 (IPv6 next header for ICMPv6)

	// PASS types (unconditional in the C):
	icmpv6PktTooBig       = 2   // Packet Too Big (PMTUD) -> PASS
	icmpv6NeighborSolicit = 135 // NDP Neighbor Solicitation (the v6 "who-has") -> PASS
	icmpv6RouterAdvert    = 134 // NDP Router Advertisement (SLAAC prefix/route) -> PASS
	icmpv6NeighborAdvert  = 136 // NDP Neighbor Advertisement (reply to an NS) -> PASS

	// DROP types (fail-closed in the C):
	icmpv6EchoReq  = 128 // Echo Request WITHOUT a seeded icmp_wl_v6 rule -> DROP
	icmpv6MLDQuery = 130 // Multicast Listener Query — a real type we do NOT pass -> DROP
)

// ip6Bytes returns the on-wire 16-byte form of an IPv6 address string, failing
// loud on a non-IPv6 input. Self-contained on purpose: slice 3 has no v6
// address serializer (parseIP6 lands in slice 2), and this test seeds no maps,
// so net.ParseIP(...).To16() is all the packet crafter needs. A To16() that
// returned an IPv4-mapped address would still be 16 bytes, so we also reject
// inputs that have a v4 representation, keeping the frame unambiguously v6.
func ip6Bytes(t *testing.T, s string) [16]byte {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("ip6Bytes: invalid IP %q", s)
	}
	if ip.To4() != nil {
		t.Fatalf("ip6Bytes: %q is IPv4, want IPv6", s)
	}
	v16 := ip.To16()
	if v16 == nil {
		t.Fatalf("ip6Bytes: %q has no 16-byte form", s)
	}
	var out [16]byte
	copy(out[:], v16)
	return out
}

// craftICMPv6TypePacket builds a minimal Ethernet + IPv6 fixed-header + ICMPv6
// frame carrying the given ICMPv6 type (code 0). The XDP program routes the
// 0x86DD ethertype to xdp_white_prog_v6, reads nexthdr=IPPROTO_ICMPV6(58), then
// the 8-byte ICMPv6 header. The header is the FULL 8 bytes the C's
// `(icmp6 + 1) > data_end` bound requires (type + code + checksum + 4-byte body);
// a short 4-byte header would DROP even a should-PASS type.
//
// MAC addresses are arbitrary; srcIP6/dstIP6 are the on-wire 16 bytes. For the
// NDP/PTB cases the addresses do not affect the verdict (those types PASS
// unconditionally, before any map lookup); they are real link-local-ish values
// only so the frame is well-formed. checksum and the 4-byte ICMPv6 body stay
// zero — the C reads neither for these types.
func craftICMPv6TypePacket(srcIP6, dstIP6 [16]byte, icmp6Type uint8) []byte {
	const icmp6Len = 8

	pkt := make([]byte, 0, 14+40+icmp6Len)

	// Ethernet header (14 bytes): dst MAC, src MAC, EtherType 0x86DD (IPv6).
	pkt = append(pkt,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // dst MAC
		0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // src MAC
		0x86, 0xDD, // EtherType IPv6
	)

	// IPv6 fixed header (40 bytes).
	ip6 := make([]byte, 40)
	ip6[0] = 0x60                                  // version=6, traffic class hi nibble 0
	binary.BigEndian.PutUint16(ip6[4:6], icmp6Len) // payload length = ICMPv6 header length
	ip6[6] = ndpIPProtoICMPv6                      // next header = ICMPv6
	ip6[7] = 255                                   // hop limit 255 (NDP packets use 255; cosmetic here — the C does not check it)
	copy(ip6[8:24], srcIP6[:])                     // source address
	copy(ip6[24:40], dstIP6[:])                    // destination address
	pkt = append(pkt, ip6...)

	// ICMPv6 header (8 bytes): type, code, checksum[2], body[4].
	icmp6 := make([]byte, icmp6Len)
	icmp6[0] = icmp6Type // type
	icmp6[1] = 0         // code = 0
	// checksum (bytes 2..3) and body (bytes 4..7) stay zero.
	pkt = append(pkt, icmp6...)

	return pkt
}

// TestIPv6NDPDatapath is the slice-3 ICMPv6 type-filter proof. It drives one
// synthetic ICMPv6 packet per type through the real compiled XDP program via
// BPF_PROG_TEST_RUN and asserts the verdict:
//
//	NS 135            -> XDP_PASS  (NDP, the v6 ARP analog — unconditional)
//	RA 134, NA 136    -> XDP_PASS  (NDP range coverage)
//	Packet Too Big 2  -> XDP_PASS  (PMTUD — unconditional)
//	Echo Request 128  -> XDP_DROP  (no icmp_wl_v6 rule seeded -> fail-closed)
//	MLD Query 130     -> XDP_DROP  (a real type we deliberately do NOT pass)
//
// The two DROP cases are the non-vacuity anchor: a program that blanket-PASSed
// all ICMPv6 (the bug this proof guards against) would FAIL them, and a program
// that blanket-DROPped all ICMPv6 (the pre-fix behavior for non-echo types)
// would FAIL the PASS cases. Only the correct type filter passes all five. NDP
// and PTB need NO map seed (their PASS is unconditional), so this loads the
// object and runs packets with an empty collection.
func TestIPv6NDPDatapath(t *testing.T) {
	prog, _, cleanup := loadXDPCollection(t)
	if cleanup != nil {
		defer cleanup()
	}

	// Well-formed (but verdict-irrelevant for the PASS types) addresses. NDP on
	// the wire uses link-local fe80::/10 + solicited-node multicast, but the C
	// passes 133–137 / type 2 before reading the addresses, so any well-formed
	// pair works.
	srcIP6 := ip6Bytes(t, "fe80::1")
	dstIP6 := ip6Bytes(t, "ff02::1")

	cases := []struct {
		name      string
		icmp6Type uint8
		want      uint32
		why       string
	}{
		{
			name:      "NeighborSolicitation_135_PASS",
			icmp6Type: icmpv6NeighborSolicit,
			want:      xdpPass,
			why:       "NDP Neighbor Solicitation is the v6 analog of ARP and MUST pass unconditionally (v4 passes ARP via the ETH_P_ARP arm); a DROP here would blackhole v6 neighbor resolution once XDP is loaded",
		},
		{
			name:      "RouterAdvertisement_134_PASS",
			icmp6Type: icmpv6RouterAdvert,
			want:      xdpPass,
			why:       "NDP Router Advertisement carries SLAAC prefix + default route; dropping it stalls v6 autoconfig",
		},
		{
			name:      "NeighborAdvertisement_136_PASS",
			icmp6Type: icmpv6NeighborAdvert,
			want:      xdpPass,
			why:       "NDP Neighbor Advertisement is the reply to an NS; dropping it means the AC can't resolve peers",
		},
		{
			name:      "PacketTooBig_2_PASS",
			icmp6Type: icmpv6PktTooBig,
			want:      xdpPass,
			why:       "ICMPv6 Packet Too Big is the sole PMTUD signal (IPv6 routers never fragment) and its source is an un-whitelistable path router; dropping it blackholes large v6 flows (RFC 4890 §4.3.1)",
		},
		{
			name:      "EchoRequest_128_no_rule_DROP",
			icmp6Type: icmpv6EchoReq,
			want:      xdpDrop,
			why:       "an Echo Request with no matching icmp_wl_v6 entry must FAIL CLOSED — it is gated by the map, not passed by the type filter; a PASS here would mean echo is fail-open",
		},
		{
			name:      "MLDQuery_130_DROP",
			icmp6Type: icmpv6MLDQuery,
			want:      xdpDrop,
			why:       "MLD Query (130) is a real ICMPv6 type we deliberately do NOT pass; a PASS here would mean the branch blanket-passes ICMPv6 instead of discriminating by type (the security regression this proof guards against)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := craftICMPv6TypePacket(srcIP6, dstIP6, tc.icmp6Type)
			got := runVerdict(t, prog, pkt)
			if got != tc.want {
				t.Fatalf("ICMPv6 type %d: verdict = %d (%s), want %d (%s) — %s",
					tc.icmp6Type, got, xdpName(got), tc.want, xdpName(tc.want), tc.why)
			}
		})
	}
}
