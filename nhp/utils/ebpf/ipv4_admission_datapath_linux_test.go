//go:build linux

package ebpf

// This file is the IPv4 admission DATAPATH proof. It is the IPv4 twin of
// TestIPv6AdmissionDatapath (ipv6_admission_datapath_linux_test.go) and closes
// a systemic coverage gap: before this file there was NO in-kernel test that a
// MATCHING v4 allow-rule admits (XDP_PASS) and an UNMATCHED v4 packet fails
// closed (XDP_DROP) for each allow-rule type. The IPv6 side already had a full
// per-rule datapath proof; the IPv4 side — the family that actually carries
// production traffic — did not.
//
// The load-bearing case is TestIPv4AdmissionDatapathPortListAllPorts, the
// in-kernel proof for the #2843 fix:
//
//	The "all ports" allow-rule is stored in the `port_list` map, whose key is
//	{src_ip, min_port, max_port}. The XDP program does NOT derive the port
//	range from the packet — it builds the lookup key with the COMPILE-TIME
//	constants `.min_port = MIN_PORT(0), .max_port = MAX_PORT(65535)`
//	(nhp_ebpf_xdp.c). The msghandler inserter used to seed this rule with
//	min_port=1, so the seeded key ({src, 1, 65535}) never equaled the key the
//	kernel looked up ({src, 0, 65535}) — the all-ports rule NEVER matched and
//	every packet under EBPFXDP fell through to XDP_DROP. #2843 changed the
//	inserter to min_port=0. This test pins that sentinel end-to-end: a rule
//	seeded with min_port=0 admits (PASS); a rule seeded with the OLD min_port=1
//	is never consulted and the packet DROPs — the regression guard.
//
// The golden-byte key tests (allowrule_port_key_test.go) prove the Go
// serializers emit the exact packed bytes the kernel structs expect, but they
// are PURE (no kernel): they cannot prove the COMPILED program actually
// consults those maps and actually DROPs on no-match. These tests do: they load
// the REAL compiled XDP object, drive SYNTHETIC IPv4 packets through it via the
// kernel BPF_PROG_TEST_RUN syscall (cilium/ebpf Program.Run), and assert the
// verdict.
//
// HARNESS REUSE: the whole environment-folding loader (loadXDPCollectionInner,
// surfaced as loadXDPCollectionV6), the named-map fetch (requireMap — generic
// despite the name), the loud-skip guard (skipOrFatal), the verdict runner
// (runVerdict), the XDP-action constants/names (xdpPass/xdpDrop/xdpName) and the
// v4 TCP packet crafter (craftTCPv4Packet) all live in
// surgical_kill_datapath_linux_test.go / ipv6_admission_datapath_linux_test.go
// and are reused here (same package). The whitelist value seeder
// (seedWhitelistValue) is also reused for the four non-packed-value maps
// (spp/sdwhitelist/src_port/port_list, whose C value structs natural-align to
// the same 16-byte {allowed, expire_time} the Go whitelistValue describes); the
// protocol_port map needs its own seeder because its C value struct is
// __attribute__((packed)) (9 bytes), see seedProtocolPortValue.
//
// CASCADE ISOLATION (identical to the v6 file): the v4 allow-rule cascade after
// a conn_track miss is spp -> sdwhitelist -> src_port -> port_list ->
// protocol_port (nhp_ebpf_xdp.c). Each test loads a FRESH collection and seeds
// ONLY the one map under test, so an earlier-map hit cannot mask a miss in the
// map being proven, and no rule/conntrack state leaks between tests.
//
// EXECUTION / CI: identical harness contract to TestSurgicalKillDatapath /
// TestIPv6AdmissionDatapath — needs CAP_BPF (or CAP_SYS_ADMIN) + a kernel that
// loads XDP + the compiled object at NHP_EBPF_XDP_OBJECT. Run via
// `make test-ebpf`. LOUD-SKIP guard (memory: feedback_silent_failure_patterns.md):
// with NHP_REQUIRE_BPF_TESTS=1 any missing capability / kernel support / missing
// object is a hard t.Fatal, never a silent skip-pass.

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

const (
	// v4 allow-rule map SEC(".maps") symbol names in nhp_ebpf_xdp.c. A rename
	// in the C source makes the requireMap lookup return a nil map -> hard
	// Fatal, the desired fail-loud rather than a silent pass. (xdpProgName
	// "xdp_white_prog" is shared from surgical_kill_datapath_linux_test.go — the
	// v4 path is the program's ETH_P_IP switch arm, the same program the v6 path
	// reaches through ETH_P_IPV6.)
	//
	//	spp           — whitelist_key {src_ip, dst_ip, dst_port, protocol} (ToWlKey)
	//	sdwhitelist   — sdwhitelist_key {src_ip, dst_ip}                    (ToSdKey)
	//	srcPort       — src_port_list_key {src_ip, dst_port}               (ToSpKey)
	//	portList      — port_list_key {src_ip, min_port, max_port}         (ToPlKey)
	//	protocolPort  — protocol_port_key {dst_port, protocol}             (ToPpKey)
	sppV4MapName          = "spp"
	sdWhitelistV4MapName  = "sdwhitelist"
	srcPortV4MapName      = "src_port"
	portListV4MapName     = "port_list"
	protocolPortV4MapName = "protocol_port"
)

const (
	// portListMinPortV4 / portListMaxPortV4 are the exact MIN_PORT / MAX_PORT
	// compile-time constants the C `port_list` lookup hardcodes into the key
	// (#define MIN_PORT 0 / #define MAX_PORT 65535 in nhp_ebpf_xdp.c, used as
	// `.min_port = MIN_PORT, .max_port = MAX_PORT`). The all-ports port_list seed
	// MUST use these literal bounds — the C never derives the range from the
	// packet, so any other bounds produce a key the datapath never looks up.
	// These mirror the v6 portListMinPort/portListMaxPort consts; they are NOT
	// reused from there only to keep this file's #2843 proof self-documenting.
	portListMinPortV4 uint16 = 0
	portListMaxPortV4 uint16 = 65535

	// portListBuggyMinPortV4 is the OLD pre-#2843 msghandler value for the
	// all-ports rule's min_port. The inserter seeded {src, 1, 65535} while the C
	// looks up {src, 0, 65535}, so the key never matched and the all-ports rule
	// silently never admitted anything under EBPFXDP. The DROP sub-case of the
	// all-ports test seeds a rule with THIS value to prove WHY #2843 was broken
	// and to guard the sentinel against a regression back to 1.
	portListBuggyMinPortV4 uint16 = 1

	// ipprotoTCPv4 is IPPROTO_TCP, the protocol byte written into the IPv4
	// header by craftTCPv4Packet and into the spp / protocol_port keys (which
	// include protocol). All five required cases are TCP. Spelled out (not pulled
	// from x/sys) to document the exact on-wire value the C `iph->protocol ==
	// IPPROTO_TCP` switch compares against and to keep this test dependency-free.
	// (The v6 file's ipprotoTCP const is for the v6 next-header byte; this is the
	// v4 IP protocol byte — same numeric value, separate name for clarity.)
	ipprotoTCPv4 uint8 = 6
)

// seedProtocolPortValue builds a protocol_port_value byte buffer that is
// GUARANTEED allowed + not-expired. UNLIKE the four other v4 allow-rule maps
// (spp/sdwhitelist/src_port/port_list), whose C value structs natural-align to
// 16 bytes and are seeded by seedWhitelistValue, the C `protocol_port_value`
// is `__attribute__((packed))`:
//
//	struct protocol_port_value { __u8 allowed; __u64 expire_time; } __packed;
//
// so it is 9 bytes with expire_time at offset 1 (NO 7-byte alignment pad). A
// Go value struct with those fields, by contrast, natural-aligns to 16 bytes
// (WhitelistValueSize), so seedWhitelistValue would (correctly) Fatal on the
// size mismatch if pointed at this map — which is exactly why the userspace
// writer emits packed bytes (ppValueBytes / ToPpValueBytes) rather than a
// struct. This seeder writes the PACKED layout the kernel reads: allowed=1 at
// byte 0, expire_time=never (1<<62) little-endian at byte 1.
//
// expire_time uses the same 1<<62 never-expire sentinel as seedConnValue /
// seedWhitelistValue: the kernel checks `val->expire_time < bpf_ktime_get_ns()`
// (CLOCK_MONOTONIC ns since boot); 1<<62 (~146 years) dwarfs any plausible
// runner uptime, so the rule never reads as expired (which would make the C
// DELETE it and DROP, turning the PASS case into a spurious DROP).
//
// The valueSize guard fences a SIZE divergence (the map's value size drifting
// from the packed 9 bytes) so a future C struct change fails loud with the sizes
// rather than writing out of bounds / at a stale offset. It does NOT catch a
// same-size field reorder; that residual is caught by the in-kernel PASS case
// (a reordered C would read expire_time from byte 0 = ~1ns < now -> expired ->
// DROP -> the PASS assertion fails loudly), exactly as documented for the v6
// value seeder.
func seedProtocolPortValue(t *testing.T, valueSize uint32) []byte {
	t.Helper()
	const packedExpireOff = 1 // expire_time directly after allowed (packed, no pad)
	const packedSize = packedExpireOff + 8
	if int(valueSize) != packedSize {
		t.Fatalf("protocol_port map value size %d != packed protocol_port_value size %d (allowed@0 + expire_time@%d, __attribute__((packed))) — the kernel protocol_port_value layout drifted; reconcile before trusting the offset write",
			valueSize, packedSize, packedExpireOff)
	}
	buf := make([]byte, valueSize)
	buf[0] = 1 // allowed = 1
	// LittleEndian here == NativeEndian on the LE XDP/CI hosts; the userspace
	// writer (ppValueBytes) spells the same layout as NativeEndian. Same bytes,
	// don't "reconcile" them to one spelling — each is deliberate in context.
	binary.LittleEndian.PutUint64(buf[packedExpireOff:packedExpireOff+8], uint64(1)<<62)
	return buf
}

// v4TestAddrs returns the three IPv4 addresses every src-keyed admission case
// shares: allowedSrc (seeded into the rule + the PASS packet), dst (shared by
// both packets), and deniedSrc (the DROP packet's source, which misses the
// rule). It is the v4 analog of v6TestAddrs. The addresses are returned as
// net.IP (the form craftTCPv4Packet takes); each test derives the uint32 the
// key structs need via parseIP(ip.String()) — feeding the SAME string into both
// keeps the key bytes and the on-wire packet bytes in lockstep (parseIP and the
// packet writer both reproduce the same network-order octets). The
// allowedSrc-vs-deniedSrc inequality is the non-vacuity floor for the four
// src-keyed tests (identical sources would make the DROP packet identical to the
// PASS packet); it is asserted once here. The protocol_port test does NOT use
// this helper — its key carries no src_ip, so its discriminator is the dst_port,
// not the source IP (see TestIPv4AdmissionDatapathProtocolPort).
func v4TestAddrs(t *testing.T) (allowedSrc, dst, deniedSrc net.IP) {
	t.Helper()
	allowedSrc = net.ParseIP("10.1.2.3")
	dst = net.ParseIP("10.9.8.7")
	deniedSrc = net.ParseIP("10.4.5.6")
	if allowedSrc == nil || dst == nil || deniedSrc == nil {
		t.Fatalf("v4TestAddrs: a fixed literal failed to parse (allowed=%v dst=%v denied=%v) — net.ParseIP regressed?", allowedSrc, dst, deniedSrc)
	}
	if allowedSrc.Equal(deniedSrc) {
		t.Fatal("allowed and denied source IPs are identical — the DROP case would be vacuous")
	}
	return allowedSrc, dst, deniedSrc
}

// mustParseIP4 converts a dotted-quad string to the network-order uint32 the v4
// key structs expect, via the PRODUCTION parseIP (the same path the AC's
// allow-rule writers use). A parse error on these fixed literals means parseIP
// itself regressed, not a test-input problem, so it is a hard Fatal. Using
// parseIP (not a hand-rolled conversion) keeps the seeded key's src_ip/dst_ip
// bytes byte-identical to what the kernel reads from iph->saddr/daddr for the
// same address.
func mustParseIP4(t *testing.T, ip net.IP) uint32 {
	t.Helper()
	u, err := parseIP(ip.String())
	if err != nil {
		t.Fatalf("parseIP(%q): %v", ip.String(), err)
	}
	return u
}

// v4SrcAddrRange / v4DstPortRange are the packet byte spans of the two
// discriminators the admission tests flip, used by assertV4PacketsDifferOnlyIn.
// craftTCPv4Packet lays out Ethernet(14) + IPv4(20) + TCP(20): the IPv4 source
// address sits at offset 14+12 = 26 (4 bytes), and the TCP destination port at
// offset 14+20+2 = 36 (2 bytes). Pinning the exact span makes a PASS-vs-DROP
// verdict difference attributable to that one field alone (the proof's
// non-vacuity fence). [start,end) half-open.
type byteRange struct{ start, end int }

var (
	v4SrcAddrRange = byteRange{start: 14 + 12, end: 14 + 12 + 4}     // 26..30
	v4DstPortRange = byteRange{start: 14 + 20 + 2, end: 14 + 20 + 4} // 36..38
)

// assertV4PacketsDifferOnlyIn fails the test unless the two crafted frames are
// byte-identical everywhere EXCEPT inside the given discriminator range, AND
// they actually differ somewhere inside it. This is the v4 analog of
// assertDifferOnlyInV6SrcAddr, generalized to a range because v4 has two
// discriminators across the suite: the source IP (v4SrcAddrRange) for the four
// src-keyed tests, and the dst_port (v4DstPortRange) for the protocol_port test
// (whose key carries no source IP). Pinning the discriminator makes the
// PASS-vs-DROP verdict difference attributable to that field alone — fencing the
// non-vacuity of each proof (neither assertion can pass vacuously while the
// other is broken).
func assertV4PacketsDifferOnlyIn(t *testing.T, a, b []byte, r byteRange) {
	t.Helper()
	if len(a) != len(b) {
		t.Fatalf("PASS/DROP packets differ in LENGTH (%d vs %d) — they must differ only in bytes %d..%d", len(a), len(b), r.start, r.end-1)
	}
	for i := range a {
		inRange := i >= r.start && i < r.end
		if a[i] != b[i] && !inRange {
			t.Fatalf("PASS/DROP packets differ at byte %d (outside the discriminator field %d..%d): %02x vs %02x — the DROP case is not isolated to the intended field and the proof would be vacuous",
				i, r.start, r.end-1, a[i], b[i])
		}
	}
	if bytes.Equal(a[r.start:r.end], b[r.start:r.end]) {
		t.Fatalf("PASS/DROP packets are IDENTICAL within the discriminator field %d..%d — the DROP case would be vacuous (same packet as PASS)", r.start, r.end-1)
	}
}

// TestIPv4AdmissionDatapathPortListAllPorts is the in-kernel proof for #2843:
// the "all ports" port_list allow-rule must be seeded with min_port=0 (the
// FIXED sentinel matching the C's compile-time MIN_PORT) to actually match.
//
// The C builds the port_list lookup key with the constants `.min_port =
// MIN_PORT(0), .max_port = MAX_PORT(65535)` — NOT from the packet — so an
// all-ports rule is effectively a per-source-IP "any port" allow keyed on
// {src_ip, 0, 65535}. This test asserts BOTH halves of the fix:
//
//	PASS — a port_list rule seeded with {src=allowedSrc, min=0, max=65535}
//	       (the post-#2843 sentinel) admits a v4 TCP packet from allowedSrc on
//	       an arbitrary dport -> XDP_PASS. Proves the cascade reaches port_list,
//	       the frame is valid, and the min=0/max=65535 key matches.
//	DROP — a port_list rule seeded with {src=deniedSrc, min=1, max=65535} (the
//	       OLD pre-#2843 buggy value) is never consulted (the C looks up
//	       {deniedSrc, 0, 65535}); with no other rule and no conntrack entry the
//	       packet from deniedSrc falls through to XDP_DROP. Proves WHY #2843 was
//	       broken and guards the sentinel against a regression back to min=1.
//
// WHY DIFFERENT SOURCES for the two sub-cases (load-bearing): the min=1 DROP
// rule MUST be keyed on a DIFFERENT source IP than the min=0 PASS rule. If both
// rules shared a source, the C's {src, 0, 65535} lookup would find the min=0
// rule and PASS the "DROP" packet too — the min=1 bug would be shadowed and the
// regression guard would be vacuous. The two sub-cases therefore use allowedSrc
// (min=0) and deniedSrc (min=1), and the two packets differ ONLY in the source
// IP (fenced by assertV4PacketsDifferOnlyIn over v4SrcAddrRange) so the verdict
// flip is attributable to "the seeded min_port matched the C's MIN_PORT" alone.
//
// NON-VACUITY: same crafter and same dport for both sub-cases (a framing bug
// can't fake the DROP), only port_list seeded (no other map can admit either
// packet). The min=0 PASS proves the cascade reaches port_list and the frame is
// valid; the min=1 DROP is then attributable solely to the min_port sentinel
// mismatch — the #2843 guard.
func TestIPv4AdmissionDatapathPortListAllPorts(t *testing.T) {
	prog, coll, cleanup := loadXDPCollectionV6(t)
	if cleanup != nil {
		defer cleanup()
	}
	plMap := requireMap(t, coll, portListV4MapName)

	allowedSrc, dstIP, deniedSrc := v4TestAddrs(t)

	const (
		srcPort uint16 = 51000
		// Arbitrary dport — the C does NOT key port_list on the packet's dport
		// (it uses MIN_PORT/MAX_PORT), so any non-special-cased port works. 8443
		// is deliberately NOT 22 (SSH, unconditional PASS) and is the same for
		// both packets so it cannot account for the verdict flip.
		dstPort uint16 = 8443
	)

	// Seed the FIXED (post-#2843) all-ports rule for allowedSrc: {min=0,
	// max=65535}, the exact constants the C hardcodes into its lookup key, so
	// this rule IS consulted and matches. Key built via the production serializer
	// ToPlKey; value is the shared never-expire sentinel (port_list_value is
	// non-packed {allowed, expire_time} = 16 bytes -> seedWhitelistValue sizes
	// it correctly).
	// The two seeds share one never-expire value sized to the map's ValueSize
	// (cached once — both rules write the same value layout).
	plVal := seedWhitelistValue(t, plMap.ValueSize())
	fixedKey := (&portListKey{SrcIP: mustParseIP4(t, allowedSrc), DstPortStart: portListMinPortV4, DstPortEnd: portListMaxPortV4}).ToPlKey()
	if err := plMap.Put(fixedKey, plVal); err != nil {
		t.Fatalf("seed port_list[allow, min=0]: %v", err)
	}

	// Seed the OLD (pre-#2843) buggy all-ports rule for deniedSrc: {min=1,
	// max=65535}. The C looks up {deniedSrc, 0, 65535}, so this {deniedSrc, 1,
	// 65535} key is NEVER consulted — modeling the exact bug #2843 fixed. Keyed
	// on deniedSrc (NOT allowedSrc) so the min=0 rule above cannot shadow it.
	buggyKey := (&portListKey{SrcIP: mustParseIP4(t, deniedSrc), DstPortStart: portListBuggyMinPortV4, DstPortEnd: portListMaxPortV4}).ToPlKey()
	if err := plMap.Put(buggyKey, plVal); err != nil {
		t.Fatalf("seed port_list[deny, min=1]: %v", err)
	}

	allowPkt := craftTCPv4Packet(t, allowedSrc, dstIP, srcPort, dstPort)
	denyPkt := craftTCPv4Packet(t, deniedSrc, dstIP, srcPort, dstPort)
	assertV4PacketsDifferOnlyIn(t, allowPkt, denyPkt, v4SrcAddrRange)

	// PASS: the min=0 all-ports rule matches -> XDP_PASS. A DROP here means the
	// post-#2843 sentinel does NOT match the C's MIN_PORT (the fix regressed) or
	// the cascade never reached port_list.
	if got := runVerdict(t, prog, allowPkt); got != xdpPass {
		t.Fatalf("all-ports PASS case (min_port=0): verdict = %d (%s), want XDP_PASS(%d) — the post-#2843 all-ports port_list rule {src,min=0,max=65535} must admit. A DROP means min_port=0 no longer matches the C's compile-time MIN_PORT, or the cascade never reached port_list",
			got, xdpName(got), xdpPass)
	}

	// DROP (the #2843 regression guard): the min=1 rule is never consulted, no
	// other rule or conntrack entry exists, so the packet falls through to
	// XDP_DROP. A PASS here would mean min_port=1 somehow matched the C's
	// MIN_PORT(0) lookup — i.e. the all-ports rule worked with the OLD buggy
	// value, contradicting #2843 (or the min=0 rule shadowed this source, which
	// the distinct deniedSrc prevents).
	if got := runVerdict(t, prog, denyPkt); got != xdpDrop {
		t.Fatalf("all-ports DROP case (min_port=1, the pre-#2843 bug): verdict = %d (%s), want XDP_DROP(%d) — a port_list rule seeded with the OLD min_port=1 must NOT match (the C looks up min_port=MIN_PORT=0), so the packet must FAIL CLOSED. A PASS here means the buggy min=1 value matched — the exact #2843 regression this guards",
			got, xdpName(got), xdpDrop)
	}
}

// TestIPv4AdmissionDatapathWhitelist is the spp (per-port) twin of the v6
// TestIPv6AdmissionDatapathUDP, for IPv4. spp's key is whitelist_key =
// {src_ip, dst_ip, dst_port, protocol} — the FIRST rule in the v4 cascade. It
// asserts:
//
//	PASS — a v4 TCP packet whose {src, dst, dst_port, proto=TCP} matches a
//	       seeded spp rule is admitted (XDP_PASS).
//	DROP — a v4 TCP packet identical except for its source IP (so it misses spp)
//	       and with no conntrack entry falls through the whole v4 cascade to
//	       XDP_DROP (fail-closed).
//
// The PASS-vs-DROP flip differs ONLY in the source IP (fenced by
// assertV4PacketsDifferOnlyIn over v4SrcAddrRange), so the verdict difference is
// attributable to the spp match alone. spp is already the first map consulted,
// so seeding only spp trivially isolates it.
func TestIPv4AdmissionDatapathWhitelist(t *testing.T) {
	prog, coll, cleanup := loadXDPCollectionV6(t)
	if cleanup != nil {
		defer cleanup()
	}
	sppMap := requireMap(t, coll, sppV4MapName)

	allowedSrc, dstIP, deniedSrc := v4TestAddrs(t)

	const (
		srcPort uint16 = 51000
		// Ordinary TCP port; NOT 22 (SSH, unconditionally PASSed before the
		// allow-rule cascade). 443 = 0x01BB is non-palindromic, so the spp key's
		// big-endian dst_port (ToWlKey writes dst_port BIG-endian) must equal the
		// on-wire big-endian dst_port the C copies from tcp->dest for the lookup
		// to hit — a wrong serializer byte-order would make the PASS case DROP.
		dstPort uint16 = 443
	)

	// Seed spp[{src=allowedSrc, dst=dstIP, dst_port=443, proto=TCP}] =
	// {allowed:1, never-expire}. Key via the production serializer ToWlKey.
	// protocol=IPPROTO_TCP is load-bearing: the spp key includes protocol, so a
	// UDP-proto seed would silently miss the TCP packet. Value is the shared
	// never-expire sentinel (whitelist_value is non-packed {allowed, expire_time}
	// = 16 bytes -> seedWhitelistValue sizes it correctly).
	wlKey := (&whitelistKey{SrcIP: mustParseIP4(t, allowedSrc), DstIP: mustParseIP4(t, dstIP), DstPort: dstPort, Protocol: ipprotoTCPv4}).ToWlKey()
	if err := sppMap.Put(wlKey, seedWhitelistValue(t, sppMap.ValueSize())); err != nil {
		t.Fatalf("seed spp[allow]: %v", err)
	}

	allowPkt := craftTCPv4Packet(t, allowedSrc, dstIP, srcPort, dstPort)
	denyPkt := craftTCPv4Packet(t, deniedSrc, dstIP, srcPort, dstPort)
	assertV4PacketsDifferOnlyIn(t, allowPkt, denyPkt, v4SrcAddrRange)

	// PASS: the v4 TCP packet matches the seeded spp rule -> XDP_PASS.
	if got := runVerdict(t, prog, allowPkt); got != xdpPass {
		t.Fatalf("spp PASS case: verdict = %d (%s), want XDP_PASS(%d) — a v4 TCP packet matching a seeded spp {src,dst,dport=443,proto=TCP} rule must be admitted; if DROP, the cascade did not consult spp (wrong protocol/byte-order in the key? seeded rule read as expired?)",
			got, xdpName(got), xdpPass)
	}

	// DROP (fail-closed): a v4 TCP packet with no matching spp rule (different
	// source IP) and no conn_track entry must fall through the whole cascade to
	// XDP_DROP.
	if got := runVerdict(t, prog, denyPkt); got != xdpDrop {
		t.Fatalf("spp DROP case: verdict = %d (%s), want XDP_DROP(%d) — an unmatched v4 TCP packet (no allow-rule, no conntrack) must FAIL CLOSED. A PASS here means an unmatched packet was admitted",
			got, xdpName(got), xdpDrop)
	}
}

// TestIPv4AdmissionDatapathSdWhitelist is the sdwhitelist (src+dst) twin of the
// v6 TestIPv6AdmissionDatapath, for IPv4. sdwhitelist's key is sdwhitelist_key =
// {src_ip, dst_ip} only (no port, no protocol) — the SECOND rule in the v4
// cascade (spp -> sdwhitelist -> ...). It asserts:
//
//	PASS — a v4 TCP packet whose {src, dst} matches a seeded sdwhitelist rule is
//	       admitted (XDP_PASS).
//	DROP — a v4 TCP packet identical except for its source IP (so it misses
//	       sdwhitelist) and with no conntrack entry falls through to XDP_DROP.
//
// CASCADE ISOLATION: this seeds ONLY sdwhitelist in a FRESH collection — spp is
// untouched — so the only map that can admit the PASS packet is sdwhitelist; an
// earlier-map hit can't mask an sdwhitelist miss. Non-vacuity (PASS/DROP differ
// only in the source IP) is fenced by assertV4PacketsDifferOnlyIn.
func TestIPv4AdmissionDatapathSdWhitelist(t *testing.T) {
	prog, coll, cleanup := loadXDPCollectionV6(t)
	if cleanup != nil {
		defer cleanup()
	}
	sdMap := requireMap(t, coll, sdWhitelistV4MapName)

	allowedSrc, dstIP, deniedSrc := v4TestAddrs(t)

	const (
		srcPort uint16 = 51000
		dstPort uint16 = 443 // ordinary TCP port; sdwhitelist ignores the port anyway
	)

	// Seed sdwhitelist[{src=allowedSrc, dst=dstIP}] = {allowed:1, never-expire}.
	// Key is src+dst only (ToSdKey). Value is the shared never-expire sentinel
	// (sdwhitelist_value is non-packed 16 bytes -> seedWhitelistValue).
	sdKey := (&srcDestKey{SrcIP: mustParseIP4(t, allowedSrc), DstIP: mustParseIP4(t, dstIP)}).ToSdKey()
	if err := sdMap.Put(sdKey, seedWhitelistValue(t, sdMap.ValueSize())); err != nil {
		t.Fatalf("seed sdwhitelist[allow]: %v", err)
	}

	allowPkt := craftTCPv4Packet(t, allowedSrc, dstIP, srcPort, dstPort)
	denyPkt := craftTCPv4Packet(t, deniedSrc, dstIP, srcPort, dstPort)
	assertV4PacketsDifferOnlyIn(t, allowPkt, denyPkt, v4SrcAddrRange)

	// PASS: the v4 TCP packet matches the seeded sdwhitelist rule -> XDP_PASS.
	// (The cascade misses spp — unseeded — then hits sdwhitelist.)
	if got := runVerdict(t, prog, allowPkt); got != xdpPass {
		t.Fatalf("sdwhitelist PASS case: verdict = %d (%s), want XDP_PASS(%d) — a v4 TCP packet matching a seeded sdwhitelist {src,dst} rule must be admitted; if DROP, the cascade did not consult sdwhitelist (seeded rule read as expired?)",
			got, xdpName(got), xdpPass)
	}

	// DROP (fail-closed): a v4 TCP packet with no matching sdwhitelist rule
	// (different source IP) and no conn_track entry must fall through to
	// XDP_DROP.
	if got := runVerdict(t, prog, denyPkt); got != xdpDrop {
		t.Fatalf("sdwhitelist DROP case: verdict = %d (%s), want XDP_DROP(%d) — an unmatched v4 TCP packet (no allow-rule, no conntrack) must FAIL CLOSED",
			got, xdpName(got), xdpDrop)
	}
}

// TestIPv4AdmissionDatapathSrcPort is the src_port (src+dst_port) twin of the v6
// TestIPv6AdmissionDatapathSrcPort, for IPv4. src_port's key is
// src_port_list_key = {src_ip, dst_port} — the THIRD rule in the v4 cascade
// (spp -> sdwhitelist -> src_port -> ...). It is ALSO the end-to-end regression
// guard for the #2842/#2844 ToSpKey byte-order fix:
//
//	The C builds the lookup key with `.dst_port = ct_key.dport`, where dport is
//	the on-wire BIG-endian __be16 read straight from the TCP header. So the
//	seeded rule's dst_port byte-order MUST equal the packet's on-wire dst_port.
//	dst_port = 443 = 0x01BB is NON-palindromic, so a wrong serializer byte-order
//	is observable: after the #2844 fix ToSpKey writes dst_port BIG-endian
//	(0x01,0xBB) == the on-wire bytes -> the PASS packet HITS src_port. With the
//	pre-fix LITTLE-endian ToSpKey (0xBB,0x01) the seeded key would NOT match and
//	the PASS case would DROP — exactly the regression this guards.
//
//	PASS — a v4 TCP packet whose {src, dst_port=443} matches the seeded src_port
//	       rule is admitted (XDP_PASS).
//	DROP — a v4 TCP packet identical except for its source IP (so it misses
//	       src_port) and with no conntrack entry falls through to XDP_DROP.
//
// CASCADE ISOLATION: seeds ONLY src_port in a FRESH collection — neither spp nor
// sdwhitelist is touched — so the only map that can admit the PASS packet is
// src_port. Non-vacuity is fenced by assertV4PacketsDifferOnlyIn (source IP).
func TestIPv4AdmissionDatapathSrcPort(t *testing.T) {
	prog, coll, cleanup := loadXDPCollectionV6(t)
	if cleanup != nil {
		defer cleanup()
	}
	spMap := requireMap(t, coll, srcPortV4MapName)

	allowedSrc, dstIP, deniedSrc := v4TestAddrs(t)

	const (
		srcPort uint16 = 51000
		// dst_port = 443 = 0x01BB is deliberately NON-palindromic: it makes the
		// dst_port byte-order observable end-to-end. A palindromic port (0/65535)
		// would make BE and LE serialization identical and the byte-order guard
		// vacuous. NOT 22 (SSH, unconditionally PASSed before the cascade).
		dstPort uint16 = 443
	)

	// Seed src_port[{src=allowedSrc, dst_port=443}] = {allowed:1, never-expire}.
	// Key built via the PRODUCTION serializer ToSpKey (the artifact under test —
	// NOT a hand-built key, which would byte-mirror the datapath on both sides and
	// pass even if the byte-order were wrong). The host-order dst_port (443) goes
	// into srcIPdstPortKey; ToSpKey owns the on-wire byte-order. Value is the
	// shared never-expire sentinel (src_port_list_value is non-packed 16 bytes).
	spKey := (&srcIPdstPortKey{SrcIP: mustParseIP4(t, allowedSrc), DstPort: dstPort}).ToSpKey()
	if err := spMap.Put(spKey, seedWhitelistValue(t, spMap.ValueSize())); err != nil {
		t.Fatalf("seed src_port[allow]: %v", err)
	}

	// The packet writes dst_port BIG-endian on the wire (craftTCPv4Packet uses
	// binary.BigEndian), which is what the C copies verbatim into the key's
	// dst_port. So this PASS packet matches the seeded rule iff ToSpKey also
	// emitted dst_port big-endian.
	allowPkt := craftTCPv4Packet(t, allowedSrc, dstIP, srcPort, dstPort)
	denyPkt := craftTCPv4Packet(t, deniedSrc, dstIP, srcPort, dstPort)
	assertV4PacketsDifferOnlyIn(t, allowPkt, denyPkt, v4SrcAddrRange)

	// PASS: the v4 TCP packet matches the seeded src_port rule -> XDP_PASS. A
	// DROP here means either the cascade did not consult src_port OR — the
	// regression this test exists for — ToSpKey serialized dst_port with the
	// wrong byte-order, so the seeded key did not match the on-wire dst_port.
	if got := runVerdict(t, prog, allowPkt); got != xdpPass {
		t.Fatalf("src_port PASS case: verdict = %d (%s), want XDP_PASS(%d) — a v4 TCP packet matching a seeded src_port {src,dst_port=443} rule must be admitted. A DROP means the cascade missed src_port OR ToSpKey wrote dst_port in the wrong byte-order (the #2842/#2844 regression guarded here: seeded key's dst_port != the on-wire big-endian dst_port the C reads)",
			got, xdpName(got), xdpPass)
	}

	// DROP (fail-closed): a v4 TCP packet with no matching src_port rule
	// (different source IP) and no conn_track entry must fall through to
	// XDP_DROP.
	if got := runVerdict(t, prog, denyPkt); got != xdpDrop {
		t.Fatalf("src_port DROP case: verdict = %d (%s), want XDP_DROP(%d) — an unmatched v4 TCP packet (no allow-rule, no conntrack) must FAIL CLOSED",
			got, xdpName(got), xdpDrop)
	}
}

// TestIPv4AdmissionDatapathProtocolPort is the protocol_port (proto+dst_port)
// admission proof — the LAST rule in the v4 cascade (spp -> sdwhitelist ->
// src_port -> port_list -> protocol_port). protocol_port's key is
// protocol_port_key = {dst_port, protocol} and carries NO src_ip (it is the
// IP-family-agnostic map, shared v4/v6). It asserts:
//
//	PASS — a v4 TCP packet whose {dst_port, proto=TCP} matches a seeded
//	       protocol_port rule is admitted (XDP_PASS).
//	DROP — a v4 TCP packet identical except for its DESTINATION PORT (so it
//	       misses protocol_port) and with no conntrack entry falls through to
//	       XDP_DROP (fail-closed).
//
// DISCRIMINATOR IS THE DST_PORT, NOT THE SOURCE IP (the key difference from the
// other four tests): protocol_port_key has no src_ip, so flipping the source IP
// would leave the lookup key IDENTICAL and BOTH packets would HIT — the DROP
// case would be vacuous. The non-vacuity flip is therefore the dst_port (443 ->
// 444, both ordinary TCP ports, neither SSH-special-cased), fenced by
// assertV4PacketsDifferOnlyIn over v4DstPortRange.
//
// BYTE-ORDER: the seeded key is built the PRODUCTION way — DstPort fed through
// parsePort (which byte-swaps to network order) then ToPpKey (which writes
// little-endian); the two swaps cancel to the on-wire big-endian __be16 the C
// reads from tcp->dest. Building it any other way (e.g. a raw host-order port
// into ToPpKey) would serialize the wrong bytes and miss — see the
// parsePort/ToPpKey double-swap note in ebpf.go and
// TestProtocolPortKey_ToPpKey_GoldenBytes.
//
// CASCADE ISOLATION: seeds ONLY protocol_port in a FRESH collection, so no
// earlier map can admit the PASS packet and mask a protocol_port miss.
// protocol_port also needs the PACKED value seeder (seedProtocolPortValue) — its
// C value struct is __attribute__((packed)) (9 bytes), unlike the 16-byte
// natural-aligned value structs of the other four maps.
func TestIPv4AdmissionDatapathProtocolPort(t *testing.T) {
	prog, coll, cleanup := loadXDPCollectionV6(t)
	if cleanup != nil {
		defer cleanup()
	}
	ppMap := requireMap(t, coll, protocolPortV4MapName)

	// protocol_port carries no src_ip, so a single source IP serves both packets;
	// the discriminator is the dst_port. v4TestAddrs' allowed/denied source
	// distinction is irrelevant here, so use a single fixed source + dest.
	srcIP := net.ParseIP("10.1.2.3")
	dstIP := net.ParseIP("10.9.8.7")
	if srcIP == nil || dstIP == nil {
		t.Fatalf("fixed literal failed to parse (src=%v dst=%v) — net.ParseIP regressed?", srcIP, dstIP)
	}

	const (
		srcPort uint16 = 51000
		// allowDstPort is seeded into protocol_port; denyDstPort is not. Both are
		// ordinary TCP ports (neither is 22/SSH), so neither is special-cased
		// before the cascade, and they differ so the PASS-vs-DROP flip is
		// attributable to the dst_port alone.
		allowDstPort uint16 = 443
		denyDstPort  uint16 = 444
	)

	// Seed protocol_port[{dst_port=443, proto=TCP}] = {allowed:1, never-expire}.
	// Built the PRODUCTION way: parsePort pre-swaps the port to network order,
	// ToPpKey writes it little-endian, the swaps cancel to the on-wire __be16 the
	// C reads. Value uses the PACKED seeder (protocol_port_value is __packed/9B).
	swappedPort, err := parsePort("443")
	if err != nil {
		t.Fatalf("parsePort(443): %v", err)
	}
	ppKey := (&procoPortKey{DstPort: swappedPort, Protocol: ipprotoTCPv4}).ToPpKey()
	if err := ppMap.Put(ppKey, seedProtocolPortValue(t, ppMap.ValueSize())); err != nil {
		t.Fatalf("seed protocol_port[allow]: %v", err)
	}

	allowPkt := craftTCPv4Packet(t, srcIP, dstIP, srcPort, allowDstPort)
	denyPkt := craftTCPv4Packet(t, srcIP, dstIP, srcPort, denyDstPort)
	assertV4PacketsDifferOnlyIn(t, allowPkt, denyPkt, v4DstPortRange)

	// PASS: the v4 TCP packet's {dst_port=443, proto=TCP} matches the seeded
	// protocol_port rule -> XDP_PASS. A DROP here means the cascade did not reach
	// or consult protocol_port (an earlier map short-circuited — impossible here
	// since only protocol_port is seeded), OR the parsePort/ToPpKey byte-order no
	// longer produces the on-wire dst_port the C reads.
	if got := runVerdict(t, prog, allowPkt); got != xdpPass {
		t.Fatalf("protocol_port PASS case (dport=443): verdict = %d (%s), want XDP_PASS(%d) — a v4 TCP packet matching a seeded protocol_port {dport=443,proto=TCP} rule must be admitted; if DROP, the cascade did not consult protocol_port (seeded rule read as expired? parsePort/ToPpKey byte-order drifted?)",
			got, xdpName(got), xdpPass)
	}

	// DROP (fail-closed): a v4 TCP packet to a DIFFERENT dst_port (444, unseeded)
	// misses protocol_port; with no other rule and no conntrack entry it falls
	// through to XDP_DROP. A PASS here would mean an unseeded dst_port was
	// admitted — protocol_port matched too broadly (or ignored the dst_port).
	if got := runVerdict(t, prog, denyPkt); got != xdpDrop {
		t.Fatalf("protocol_port DROP case (dport=444): verdict = %d (%s), want XDP_DROP(%d) — a v4 TCP packet to an unseeded dst_port must FAIL CLOSED. A PASS here means protocol_port admitted a port it was not seeded for",
			got, xdpName(got), xdpDrop)
	}
}
