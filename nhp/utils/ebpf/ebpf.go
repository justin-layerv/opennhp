package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/OpenNHP/opennhp/nhp/log"
)

type whitelistKey struct {
	SrcIP    uint32 `ebpf:"src_ip"`
	DstIP    uint32 `ebpf:"dst_ip"`
	DstPort  uint16 `ebpf:"dst_port"`
	Protocol uint8  `ebpf:"protocol"`
}

type srcDestKey struct {
	SrcIP uint32 `ebpf:"src_ip"`
	DstIP uint32 `ebpf:"dst_ip"`
}

type portListKey struct {
	SrcIP        uint32 `ebpf:"src_ip"`
	DstPortStart uint16 `ebpf:"dst_port_start"`
	DstPortEnd   uint16 `ebpf:"dst_port_end"`
}

type srcIPdstPortKey struct {
	SrcIP   uint32 `ebpf:"src_ip"`
	DstPort uint16 `ebpf:"dst_port"`
}

type procoPortKey struct {
	DstPort  uint16 `ebpf:"dst_port"`
	Protocol uint8  `ebpf:"protocol"`
}

// connTrackKey mirrors `struct ipv4_ct_tuple` in
// nhp/ebpf/xdp/nhp_ebpf_xdp.c byte-for-byte. It is the key of the
// established-flow conntrack map (PinPathConnTrack) and is the ONLY
// kernel-visible structure that distinguishes two sessions sharing the
// same {src_ip, dst_ip, dst_port, protocol} allow-rule tuple: it carries
// the per-flow source port, which two concurrent flows behind one NAT to
// the same destination necessarily have distinct values of (the NAT/stack
// demuxes replies by it). That source-port dimension is the P4c surgical
// discriminator — see DelEbpfConnTrackEntry.
//
// Layout discipline (a mismatch silently makes Delete a no-op — wrong key
// bytes hash to a different bucket, the kernel returns ENOENT, and the
// targeted flow is never torn down):
//
//   - Field ORDER is daddr, saddr, dport, sport, nexthdr, flags — note
//     destination-before-source, the opposite of the allow-rule keys. This
//     matches the C struct exactly; the kernel builds its lookup key in
//     this order on every packet.
//   - All multi-byte fields are NETWORK byte order (__be32 / __be16 in C).
//     The IP fields are stored exactly as parseIP returns them (the same
//     network-order-preserving uint32 the allow-rule keys use); the ports
//     are written big-endian to reproduce the on-wire __be16 the XDP
//     program copies straight from the TCP/UDP header.
//   - The six fields sum to 14 bytes (4+4+2+2+1+1) with no INTERIOR padding
//     (every field is naturally aligned), but the COMPILED conn_track map
//     key is 16 bytes: 14 field bytes + 2 trailing pad. ToCtKey emits all 16
//     (the pad is zero, matching the XDP's `ct_key = {}`). See
//     connTrackKeySize for WHY the compiled key is 16, not 14.
//   - flags selects the conntrack DIRECTION. The XDP program inserts the
//     ESTABLISHED entry with flags = CT_DIR_INGRESS (0) keyed on the
//     ingress orientation (saddr=client, daddr=resource). P4c deletes that
//     ingress entry; CT_DIR_INGRESS is the correct and only orientation to
//     delete for an inbound-admitted flow.
//
// Field tags mirror the kernel struct member names for consistency with
// the sibling key structs (whitelistKey/srcDestKey/etc.). They are
// decorative here — all serialization is hand-packed by ToCtKey, not
// reflection-driven — but keep the family uniform.
type connTrackKey struct {
	DstIP   uint32 `ebpf:"daddr"`   // __be32 daddr (network order, as parseIP returns)
	SrcIP   uint32 `ebpf:"saddr"`   // __be32 saddr (network order, as parseIP returns)
	DstPort uint16 `ebpf:"dport"`   // __be16 dport (network order)
	SrcPort uint16 `ebpf:"sport"`   // __be16 sport (network order)
	NextHdr uint8  `ebpf:"nexthdr"` // __u8 nexthdr (IPPROTO_TCP=6 / IPPROTO_UDP=17)
	Flags   uint8  `ebpf:"flags"`   // __u8 flags (CT_DIR_INGRESS=0)
}

// ctDirIngress mirrors CT_DIR_INGRESS in the XDP program. The conntrack
// entry for an inbound-admitted flow is inserted with this direction
// (saddr=client, daddr=protected resource); it is the orientation P4c
// deletes.
const ctDirIngress uint8 = 0

// connTrackKeySize is the size of the kernel `conn_track` map key — 16
// bytes. This is the authoritative length cilium/ebpf reports for the
// compiled object's `ipv4_ct_tuple` BTF type, and the length Map.Put/Delete
// require the marshalled key to be (a wrong length fails loudly with
// "doesn't marshal to N bytes"). The struct's six fields sum to 14
// (4+4+2+2+1+1); the trailing 2 bytes are alignment padding.
//
// WHY 16 and not 14 (the surprise this const exists to pin): `struct
// ipv4_ct_tuple` is NOT effectively packed, even though the C source ends it
// with `} __packed;`. `__packed` is the Linux `compiler.h` shorthand for
// `__attribute__((packed))`, but that header is not included in the XDP
// translation unit — so the bare token is UNDEFINED and applies no
// attribute (it parses as an unused global variable of that struct type;
// `nm nhp_ebpf_xdp.o` shows a BSS symbol literally named `__packed`). The
// struct therefore keeps natural 4-byte alignment and its 14 field bytes
// round up to a 16-byte size. The sibling allow-rule key structs (spp,
// src_port, …) use the fully-spelled `__attribute__((packed))` and keep
// their exact sizes (e.g. spp KeySize=11, NOT rounded to 12) — which is how
// we know the cause is the undefined token here, not clang rounding map
// keys in general. (Verified against release/nhp-ac/etc/nhp_ebpf_xdp.o:
// conn_track KeySize=16, spp=11.)
//
// The XDP program builds its lookup key from a zero-initialized
// `ct_key = {}` (nhp_ebpf_xdp.c), so the 2 trailing pad bytes it hashes are
// zero — ToCtKey's zero pad matches byte-for-byte. Treat the compiled
// KeySize as authoritative: the #2779 datapath gate seeds/deletes against
// the real object, so any future KeySize drift fails that gate loudly.
//
// The C-side decision (truly pack the struct to 14 vs. keep 16 as the
// intentional ABI) is tracked in #2818 — repacking is a breaking change for
// the LIBBPF_PIN_BY_NAME conn_track map and must be coordinated with eBPF-XDP
// mode adoption (prod runs FilterMode_IPTABLES today, so this path is
// dormant). Until then, 16 is the live ABI and this serialization matches it.
//
// connTrackKeyDataLen is the 14 meaningful bytes; the gap to
// connTrackKeySize is the trailing pad ToCtKey zero-fills and
// connTrackKeyFromBytes ignores.
const (
	connTrackKeyDataLen = 4 + 4 + 2 + 2 + 1 + 1 // 14 meaningful bytes
	connTrackKeySize    = 16                    // kernel map KeySize (14 + 2 trailing pad; see godoc)
)

// ToCtKey serializes the conntrack tuple into the 16 bytes the kernel
// `conn_track` map key expects: the 14 meaningful field bytes followed by 2
// zero pad bytes (see connTrackKeySize for why the map key is 16, not 14).
// IP fields are written little-endian because parseIP already returns the
// network-order bytes packed into a uint32 via LittleEndian (matching
// ToWlKey's __be32 handling); ports are written big-endian to reproduce the
// on-wire __be16. The trailing pad stays zero (make zero-fills it),
// matching the kernel's `ct_key = {}` zero-init, so the seeded/deleted key
// hashes identically to the one the XDP program builds. See connTrackKey's
// godoc for why every byte here is load-bearing.
func (r *connTrackKey) ToCtKey() []byte {
	keyBytes := make([]byte, connTrackKeySize)
	binary.LittleEndian.PutUint32(keyBytes[0:4], r.DstIP)
	binary.LittleEndian.PutUint32(keyBytes[4:8], r.SrcIP)
	binary.BigEndian.PutUint16(keyBytes[8:10], r.DstPort)
	binary.BigEndian.PutUint16(keyBytes[10:12], r.SrcPort)
	keyBytes[12] = r.NextHdr
	keyBytes[13] = r.Flags
	// keyBytes[14:16] left zero — trailing alignment pad, matching the
	// kernel's zero-initialized ct_key.
	return keyBytes
}

// connTrackKeyFromBytes is the EXACT inverse of ToCtKey: it decodes a kernel
// `ipv4_ct_tuple` map key (connTrackKeySize=16 bytes — 14 meaningful + 2
// trailing pad, which it ignores) back into a connTrackKey.
// The conntrack-enumeration path (P4e slice 5,
// conntrack_enumerate_linux.go) walks the pinned conn_track map and must
// recover each entry's per-flow SOURCE PORT — the surgical discriminator —
// from the raw key bytes the BPF iterator yields, so it can FlushConn
// exactly the revoked flow and leave same-allow-tuple siblings alive.
//
// Layout discipline (must stay byte-for-byte symmetric with ToCtKey — a
// wrong offset here silently decodes the wrong source port, the enumeration
// then filters the target out, and the "surgical" revoke degrades to the
// coarse over-flush this slice exists to remove). The two functions are a
// matched pair fenced by the ToCtKey golden-bytes test plus a round-trip
// test (parse(ToCtKey(k)) == k); change one, change the other.
//
// Returns an error if buf is not exactly connTrackKeySize bytes — a
// short/long buffer means the wrong map was pinned at the path or the
// kernel struct changed, both of which must fail loud rather than decode
// garbage from an out-of-bounds or truncated slice.
func connTrackKeyFromBytes(buf []byte) (connTrackKey, error) {
	if len(buf) != connTrackKeySize {
		return connTrackKey{}, fmt.Errorf("conntrack key length %d, want %d (ipv4_ct_tuple: %d field bytes + %d trailing pad)", len(buf), connTrackKeySize, connTrackKeyDataLen, connTrackKeySize-connTrackKeyDataLen)
	}
	return connTrackKey{
		DstIP:   binary.LittleEndian.Uint32(buf[0:4]),
		SrcIP:   binary.LittleEndian.Uint32(buf[4:8]),
		DstPort: binary.BigEndian.Uint16(buf[8:10]),
		SrcPort: binary.BigEndian.Uint16(buf[10:12]),
		NextHdr: buf[12],
		Flags:   buf[13],
	}, nil
}

// ---------------------------------------------------------------------------
// IPv6 key structs + serializers (E2 slice 2 — DECLARED ONLY, currently inert).
//
// These mirror the IPv4 key structs above, substituting a 16-byte [16]byte
// address (the wire form of `struct in6_addr`) for each uint32 `__be32`
// address. They are the Go counterparts of the `*_v6` packed C structs in
// nhp/ebpf/xdp/nhp_ebpf_xdp.c, whose exact sizes are pinned there with
// `_Static_assert`. Each `To*KeyV6` serializer emits exactly that many bytes;
// the golden-byte tests (keys_v6_test.go) assert len(out) == the C size so a
// Go/C size drift (the #2818 14-vs-16 class) fails Go CI rather than silently
// mis-keying the kernel map. NOTHING calls these yet — slice 4 wires routing.
//
// IP byte order: unlike the v4 structs (which store the network-order address
// packed into a uint32 and write it LittleEndian to undo Go's host order), the
// v6 address is already the on-wire 16 bytes (from net.IP.To16(), network
// order). It is copied verbatim — no byte-order transform — so the serialized
// bytes match `struct in6_addr` directly. The non-address fields keep their
// v4 twin's exact endianness (see each serializer).

type whitelistKeyV6 struct {
	SrcIP    [16]byte `ebpf:"src_ip"`
	DstIP    [16]byte `ebpf:"dst_ip"`
	DstPort  uint16   `ebpf:"dst_port"`
	Protocol uint8    `ebpf:"protocol"`
}

type srcDestKeyV6 struct {
	SrcIP [16]byte `ebpf:"src_ip"`
	DstIP [16]byte `ebpf:"dst_ip"`
}

// portListKeyV6 and srcIPdstPortKeyV6 write their PORT fields BIG-endian
// (network order) on the wire (see ToPlKeyV6/ToSpKeyV6), matching the sibling
// whitelistKeyV6/connTrackKeyV6 ports and the C `__be16` fields. The whole
// *_v6 key family is now uniformly network/big-endian — do NOT reintroduce the
// v4-mirrored little-endian write here (it was the lone outlier that silently
// mis-keyed the datapath; see below).
//
// DATAPATH AGREEMENT (now wired): the v6 XDP datapath's `xdp_white_prog_v6`
// (nhp/ebpf/xdp/nhp_ebpf_xdp.c, slices 3+) builds the two lookup keys thus:
//   - src_port_v6: `spkey.dst_port = dport` where `dport = tcp->dest`/`udp->dest`
//     — the RAW network-order (__be16) packet port, NOT bpf_ntohs'd. So
//     ToSpKeyV6 MUST write dst_port BIG-endian, or an asymmetric-port src_port
//     rule (e.g. 443 = 0x01BB) inserts `BB 01` while the kernel looks up
//     `01 BB` and the rule silently never matches. This was a real, latent
//     value-dependent bug (the v4 analog ToSpKey had the same bug, now fixed to
//     big-endian to match — #2842) and is the load-bearing reason for the byte
//     order here.
//   - port_list_v6: `pl_key.min_port = MIN_PORT(0)`, `.max_port = MAX_PORT(65535)`
//     — fixed host-order sentinel CONSTANTS, never the packet port. 0x0000 and
//     0xFFFF are byte-order palindromes, so ToPlKeyV6's min/max byte order is
//     UNOBSERVABLE for the only key the datapath ever queries. We still write
//     BIG-endian here for family uniformity (so a future real-range lookup, if
//     ever added, starts from a consistent serializer), NOT because a network
//     order matches the datapath's host-order constants. NOTE: because the
//     datapath only ever queries the (0,65535) sentinel, a real-RANGE
//     port_list_v6 allow-rule does not match regardless of byte order — that is
//     a separate range-vs-sentinel matter (shared with v4), not a byte-order
//     bug, and is untouched here.
//
// Byte-for-byte agreement is validated end-to-end by the slice-6 real-map
// BPF_PROG_TEST_RUN harness (the src_port_v6 case is the genuine byte-order
// guard; the port_list_v6 case proves the admit path, not the byte order).
// Tracked in #2841.
type portListKeyV6 struct {
	SrcIP        [16]byte `ebpf:"src_ip"`
	DstPortStart uint16   `ebpf:"min_port"`
	DstPortEnd   uint16   `ebpf:"max_port"`
}

type srcIPdstPortKeyV6 struct {
	SrcIP   [16]byte `ebpf:"src_ip"`
	DstPort uint16   `ebpf:"dst_port"` // BIG-endian (network order) on the wire — see the family note above ToSpKeyV6 / portListKeyV6.
}

// connTrackKeyV6 mirrors `struct ipv6_ct_tuple` in
// nhp/ebpf/xdp/nhp_ebpf_xdp.c byte-for-byte — the IPv6 twin of connTrackKey.
// Field ORDER is daddr, saddr, dport, sport, nexthdr, flags (destination-
// before-source, the opposite of the allow-rule keys), matching the C struct
// exactly. Addresses are the on-wire 16 bytes; ports are network/big-endian
// __be16 (see ToCtKeyV6). DECLARED ONLY in this slice.
type connTrackKeyV6 struct {
	DstIP   [16]byte `ebpf:"daddr"`   // in6_addr daddr (network order)
	SrcIP   [16]byte `ebpf:"saddr"`   // in6_addr saddr (network order)
	DstPort uint16   `ebpf:"dport"`   // __be16 dport (network order)
	SrcPort uint16   `ebpf:"sport"`   // __be16 sport (network order)
	NextHdr uint8    `ebpf:"nexthdr"` // __u8 nexthdr (IPPROTO_TCP=6 / IPPROTO_UDP=17)
	Flags   uint8    `ebpf:"flags"`   // __u8 flags (CT_DIR_INGRESS=0)
}

// On-wire sizes of the packed `*_v6` C structs. Each MUST equal the matching
// `_Static_assert(sizeof(struct ...) == N)` in nhp/ebpf/xdp/nhp_ebpf_xdp.c —
// that equality is the load-bearing C↔Go contract this slice exists to fence
// (a mismatch silently mis-keys the kernel map). NOTE: these are SUMS of field
// sizes, not unsafe.Sizeof(<struct>{}) — the Go structs are NOT packed (they
// carry Go alignment padding), whereas the kernel structs are packed; the
// To*KeyV6 serializers emit the packed form, and these consts fence it.
const (
	whitelistKeyV6Size   = 16 + 16 + 2 + 1         // 35: struct whitelist_key_v6
	srcDestKeyV6Size     = 16 + 16                 // 32: struct sdwhitelist_key_v6 / icmpwhitelist_key_v6
	srcPortListKeyV6Size = 16 + 2                  // 18: struct src_port_list_key_v6
	portListKeyV6Size    = 16 + 2 + 2              // 20: struct port_list_key_v6
	connTrackKeyV6Size   = 16 + 16 + 2 + 2 + 1 + 1 // 38: struct ipv6_ct_tuple
)

// ToWlKeyV6 serializes whitelistKeyV6 into the 35 packed bytes of
// `struct whitelist_key_v6`: src_ip[16] + dst_ip[16] + BigEndian dst_port[2]
// + protocol[1]. dst_port is big-endian to match ToWlKey's __be16 handling.
func (r *whitelistKeyV6) ToWlKeyV6() []byte {
	keyBytes := make([]byte, whitelistKeyV6Size)
	copy(keyBytes[0:16], r.SrcIP[:])
	copy(keyBytes[16:32], r.DstIP[:])
	binary.BigEndian.PutUint16(keyBytes[32:34], r.DstPort)
	keyBytes[34] = r.Protocol
	return keyBytes
}

// ToSdKeyV6 serializes srcDestKeyV6 into the 32 packed bytes of
// `struct sdwhitelist_key_v6` (and the identically-shaped
// `struct icmpwhitelist_key_v6`): src_ip[16] + dst_ip[16].
func (r *srcDestKeyV6) ToSdKeyV6() []byte {
	keyBytes := make([]byte, srcDestKeyV6Size)
	copy(keyBytes[0:16], r.SrcIP[:])
	copy(keyBytes[16:32], r.DstIP[:])
	return keyBytes
}

// ToPlKeyV6 serializes portListKeyV6 into the 20 packed bytes of
// `struct port_list_key_v6`: src_ip[16] + BigEndian min_port[2] +
// BigEndian max_port[2]. The ports are BIG-endian for family uniformity with
// the rest of the *_v6 keys (ToWlKeyV6/ToSpKeyV6/ToCtKeyV6 all network-order),
// NOT because a network order matches the datapath: the v6 XDP `port_list_v6`
// lookup builds its key from the fixed host-order sentinel CONSTANTS
// `min_port = MIN_PORT(0)` / `max_port = MAX_PORT(65535)` (see
// nhp/ebpf/xdp/nhp_ebpf_xdp.c), never the packet port. 0x0000/0xFFFF are
// byte-order palindromes, so this serializer's min/max byte order is
// UNOBSERVABLE for the only key the datapath ever queries — flipping it from
// the former little-endian to big-endian changes no datapath match today. (A
// real-RANGE port_list_v6 rule does not match regardless, because the datapath
// only queries the full-range sentinel — a separate range-vs-sentinel matter,
// not byte order.) INPUT CONTRACT: the live v4 twin AddEbpfRuleForSrcDestPortList
// passes safeIntToUint16(...) (a raw uint16), NOT parsePort(...) — so
// DstPortStart/DstPortEnd here are raw host-order values; slice 4 must feed
// these fields the same raw uint16, not a pre-swapped parsePort value.
// (parsePort's pre-swap dance is only on the procoPortKey/ToPpKey path.)
func (r *portListKeyV6) ToPlKeyV6() []byte {
	keyBytes := make([]byte, portListKeyV6Size)
	copy(keyBytes[0:16], r.SrcIP[:])
	binary.BigEndian.PutUint16(keyBytes[16:18], r.DstPortStart)
	binary.BigEndian.PutUint16(keyBytes[18:20], r.DstPortEnd)
	return keyBytes
}

// ToSpKeyV6 serializes srcIPdstPortKeyV6 into the 18 packed bytes of
// `struct src_port_list_key_v6`: src_ip[16] + BigEndian dst_port[2]. dst_port
// is BIG-endian (network order) to match the v6 XDP `src_port_v6` lookup, which
// builds its key as `spkey.dst_port = dport` where `dport = tcp->dest`/`udp->dest`
// — the RAW network-order packet port, NOT bpf_ntohs'd (nhp/ebpf/xdp/nhp_ebpf_xdp.c).
// This is the load-bearing byte order: a little-endian write inserts an
// asymmetric port (443 = 0x01BB) as `BB 01` while the kernel looks up `01 BB`,
// so the src_port rule silently never matches. (The v4 twin ToSpKey had this
// exact latent bug; it is now fixed to big-endian to match — #2842.) INPUT
// CONTRACT, same as ToPlKeyV6: the live v4 caller AddEbpfRuleForSrcDestPort
// passes safeIntToUint16(...) (a raw uint16), so DstPort here is a raw
// host-order value — slice 4 must do the same.
func (r *srcIPdstPortKeyV6) ToSpKeyV6() []byte {
	keyBytes := make([]byte, srcPortListKeyV6Size)
	copy(keyBytes[0:16], r.SrcIP[:])
	binary.BigEndian.PutUint16(keyBytes[16:18], r.DstPort)
	return keyBytes
}

// ToCtKeyV6 serializes the IPv6 conntrack tuple into the exact 38 packed bytes
// the kernel `struct ipv6_ct_tuple` map key expects: daddr[16] + saddr[16] +
// BigEndian dport[2] + BigEndian sport[2] + nexthdr[1] + flags[1]. Mirrors
// ToCtKey's field ORDER (destination-before-source) and big-endian ports. The
// addresses are the on-wire 16 bytes, copied verbatim (no byte-order swap).
func (r *connTrackKeyV6) ToCtKeyV6() []byte {
	keyBytes := make([]byte, connTrackKeyV6Size)
	copy(keyBytes[0:16], r.DstIP[:])
	copy(keyBytes[16:32], r.SrcIP[:])
	binary.BigEndian.PutUint16(keyBytes[32:34], r.DstPort)
	binary.BigEndian.PutUint16(keyBytes[34:36], r.SrcPort)
	keyBytes[36] = r.NextHdr
	keyBytes[37] = r.Flags
	return keyBytes
}

type whitelistValue struct {
	Allowed    uint8
	_          [7]byte
	ExpireTime uint64
}

type procoPortValue struct {
	Allowed    uint8
	ExpireTime uint64
}

const (
	MapTypeWhitelist     = 1
	MapTypeSdWhitelist   = 2
	MapTypeIcmpWhitelist = 3
	MapTypeSrcAndPort    = 4
	MapTypeSrcPortList   = 5
	MapTypeProtocolPort  = 6
)

// MapTypeName maps a MapType* constant to the BPF map's name as declared in
// nhp/ebpf/xdp/nhp_ebpf_xdp.c, so operator-facing logs can name the map that
// hit capacity instead of printing the bare 1..6 ordinal. Unknown values render
// as "unknown(<n>)" rather than panicking.
func MapTypeName(mapType int) string {
	switch mapType {
	case MapTypeWhitelist:
		return "spp"
	case MapTypeSdWhitelist:
		return "sdwhitelist"
	case MapTypeIcmpWhitelist:
		return "icmpwhitelist"
	case MapTypeSrcAndPort:
		return "src_port"
	case MapTypeSrcPortList:
		return "port_list"
	case MapTypeProtocolPort:
		return "protocol_port"
	default:
		return fmt.Sprintf("unknown(%d)", mapType)
	}
}

// Pinned-map filesystem paths. Single source of truth for both the
// producer side (Add* functions in this file) and the consumer side
// (boot enumeration in endpoints/ac/expiry_enumerate_ebpf_linux.go).
// A future XDP loader change to a different pin path becomes a
// compile error rather than a silent boot-enumeration miss
const (
	PinPathWhitelist     = "/sys/fs/bpf/spp"           // TCP/UDP per-port allow-rules (whitelistKey)
	PinPathSdWhitelist   = "/sys/fs/bpf/sdwhitelist"   // any-proto src+dst allow-rules (srcDestKey)
	PinPathIcmpWhitelist = "/sys/fs/bpf/icmpwhitelist" // ICMP allow-rules (srcDestKey)
	// PinPathConnTrack is the established-flow conntrack map. The XDP
	// program (nhp/ebpf/xdp/nhp_ebpf_xdp.c) pins it BY_NAME under its
	// map variable name `conn_track`, and short-circuits established
	// flows on it BEFORE consulting any allow-rule map. Deleting the
	// allow-rule alone therefore does NOT tear an established flow down
	// immediately: the conn_track entry's ttl_ns was anchored to the
	// allow-rule's remaining lifetime at flow creation, so the flow keeps
	// passing the conn_track short-circuit until that original deadline.
	// Surgical, immediate revocation (P4c) requires deleting the
	// conn_track 5-tuple entry directly — see DelEbpfConnTrackEntry and
	// docs/design/QURL_V2_KEYED_IDENTITY.md -> "Flow granularity caveat".
	PinPathConnTrack = "/sys/fs/bpf/conn_track"
)

// IPv6 pinned-map filesystem paths (E2 slice 4). One-for-one mirror of the v4
// pin paths above, for the `*_v6` maps the XDP program declares with
// LIBBPF_PIN_BY_NAME in nhp/ebpf/xdp/nhp_ebpf_xdp.c — so each path is
// "/sys/fs/bpf/<map-name>" using the C map's exact name. These must stay
// byte-identical to those SEC(".maps") names; a typo here pins/opens the wrong
// path and the v6 allow-rule write silently lands nowhere (or fails open).
//
// NOTE the two deliberate asymmetries with v4:
//   - icmp_wl_v6: the v6 ICMP map is named `icmp_wl_v6`, NOT `icmpwhitelist_v6`
//     — a BPF map name is capped at BPF_OBJ_NAME_LEN (16, incl. NUL), and
//     `icmpwhitelist_v6` is 17 chars (renamed in #2825/b696d248). So this path
//     does NOT mirror the v4 PinPathIcmpWhitelist suffix verbatim.
//   - protocol_port has NO v6 variant: its key is {dst_port, protocol} with no
//     address field, so the same map serves both families. EbpfRuleAddV6
//     therefore never handles MapTypeProtocolPort; that path stays on the
//     shared v4 helper (AddEbpfRuleForProtocolPort).
const (
	PinPathWhitelistV6     = "/sys/fs/bpf/spp_v6"         // TCP/UDP per-port allow-rules (whitelistKeyV6) — map `spp_v6`
	PinPathSdWhitelistV6   = "/sys/fs/bpf/sdwhitelist_v6" // any-proto src+dst allow-rules (srcDestKeyV6) — map `sdwhitelist_v6`
	PinPathIcmpWhitelistV6 = "/sys/fs/bpf/icmp_wl_v6"     // ICMPv6 allow-rules (srcDestKeyV6) — map `icmp_wl_v6` (15-char cap; see note)
	PinPathSrcPortV6       = "/sys/fs/bpf/src_port_v6"    // src+single-dst-port allow-rules (srcIPdstPortKeyV6) — map `src_port_v6`
	PinPathPortListV6      = "/sys/fs/bpf/port_list_v6"   // src+dst-port-range allow-rules (portListKeyV6) — map `port_list_v6`
)

// WhitelistValueSize is the on-wire size of whitelistValue
// (Allowed:1 + 7-pad + ExpireTime:8 = 16 bytes). Derived from
// unsafe.Sizeof so a future struct-layout change becomes a compile
// error at the consumer rather than a runtime sanity-check failure
// during AC boot enumeration
const WhitelistValueSize = int(unsafe.Sizeof(whitelistValue{}))

// ExpireTimeOffset is the byte offset of the ExpireTime field
// within whitelistValue. Boot enumeration in
// endpoints/ac/expiry_enumerate_ebpf_linux.go decodes the value
// bytes via `binary.LittleEndian.Uint64(valBytes[N:N+8])`, where N
// is this offset. Exposing it via unsafe.Offsetof means a future
// reordering of whitelistValue's fields becomes a compile error at
// the consumer instead of silently decoding garbage from the wrong
// 8 bytes — symmetric to WhitelistValueSize's struct-size fence
const ExpireTimeOffset = int(unsafe.Offsetof(whitelistValue{}.ExpireTime))

type EbpfRuleParams struct {
	SrcIP        string
	DstIP        string
	DstPort      int
	DstPortStart int
	DstPortEnd   int
	Protocol     string
}

func (r *whitelistKey) ToWlKey() []byte {
	keyBytes := make([]byte, 11)
	binary.LittleEndian.PutUint32(keyBytes[0:4], r.SrcIP)
	binary.LittleEndian.PutUint32(keyBytes[4:8], r.DstIP)
	binary.BigEndian.PutUint16(keyBytes[8:10], r.DstPort)
	keyBytes[10] = r.Protocol
	return keyBytes
}

func (r *whitelistKey) ToWlValue(ttlSec uint64) whitelistValue {
	now, _ := getBootTimeNanos()
	return whitelistValue{
		Allowed:    1,
		ExpireTime: now + ttlSec*1_000_000_000,
	}
}

func (r *srcDestKey) ToSdKey() []byte {
	keyBytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(keyBytes[0:4], r.SrcIP)
	binary.LittleEndian.PutUint32(keyBytes[4:8], r.DstIP)
	return keyBytes
}

func (r *srcDestKey) ToSdValue(ttlSec uint64) whitelistValue {
	now, _ := getBootTimeNanos()
	return whitelistValue{
		Allowed:    1,
		ExpireTime: now + ttlSec*1_000_000_000,
	}
}

// ToPpKey serializes the `protocol_port` key (struct protocol_port_key
// {__be16 dst_port; __u8 protocol;}). NOTE the divergent convention: unlike
// the host-order-port-in + BigEndian-out family (ToSpKey/ToPlKey/ToCtKey/
// ToWlKey), this path reaches the same network-order __be16 by the OPPOSITE
// route — its caller AddEbpfRuleForProtocolPort feeds a value from parsePort,
// which already byte-swaps to network order, and this then writes it
// LittleEndian. The two swaps cancel, so the bytes are correct today, but it
// is a footgun: "fixing" parsePort to return host order would silently break
// this write. Converging this path onto host-order + BigEndian (like the
// rest of the family) is tracked at #2845; do not change one half alone.
func (r *procoPortKey) ToPpKey() []byte {
	keyBytes := make([]byte, 3)
	binary.LittleEndian.PutUint16(keyBytes[0:2], r.DstPort)
	keyBytes[2] = r.Protocol
	return keyBytes
}

func (r *procoPortKey) ToPpValue(ttlSec uint64) procoPortValue {
	now, _ := getBootTimeNanos()
	return procoPortValue{
		Allowed:    1,
		ExpireTime: now + ttlSec*1_000_000_000,
	}
}

// ToPlKey serializes the `port_list` allow-rule key into the 8 packed bytes
// the kernel `port_list` HASH map expects, mirroring `struct port_list_key`
// {__be32 src_ip; __be16 min_port; __be16 max_port;} in nhp_ebpf_xdp.c. The
// port fields are big-endian for the same __be16 reason as ToSpKey (see its
// godoc) — keeping the whole allow-rule key family on one network-order
// convention.
//
// Unlike ToSpKey, this byte order is behaviorally INVISIBLE today: the XDP
// program builds its port_list lookup key with the palindromic constants
// MIN_PORT=0 (00 00) and MAX_PORT=65535 (FF FF), which read identically
// big- or little-endian — which is exactly why the previous LE write was
// never observed to fail. The change is a forward-looking consistency fix,
// pinned by TestPortListKey_ToPlKey_GoldenBytes with asymmetric values.
//
// ORTHOGONAL latent mismatch (NOT fixed here, tracked separately): the
// inserter in endpoints/ac/msghandler.go builds the all-ports rule with
// DstPortStart=1 while the XDP side looks up min_port=MIN_PORT=0, so the
// port_list key never matches regardless of byte order. That is a value
// mismatch in a different layer; this endianness fix neither causes nor
// resolves it.
func (r *portListKey) ToPlKey() []byte {
	keyBytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(keyBytes[0:4], r.SrcIP)
	binary.BigEndian.PutUint16(keyBytes[4:6], r.DstPortStart)
	binary.BigEndian.PutUint16(keyBytes[6:8], r.DstPortEnd)
	return keyBytes
}

func (r *portListKey) ToPlValue(ttlSec uint64) whitelistValue {
	now, _ := getBootTimeNanos()
	return whitelistValue{
		Allowed:    1,
		ExpireTime: now + ttlSec*1_000_000_000,
	}
}

// ToSpKey serializes the `src_port` allow-rule key into the 6 packed bytes
// the kernel `src_port` HASH map expects, mirroring `struct src_port_list_key`
// {__be32 src_ip; __be16 dst_port;} in nhp/ebpf/xdp/nhp_ebpf_xdp.c.
//
// Byte order (the load-bearing detail — see TestSrcIPDstPortKey_ToSpKey_GoldenBytes):
//   - src_ip is little-endian because parseIP already returns the
//     network-order octets packed into a uint32 via LittleEndian, so the LE
//     write reproduces network order — identical to ToCtKey/ToWlKey IP handling
//     and to the XDP `iph->saddr` (__be32).
//   - dst_port is BIG-endian to reproduce the on-wire __be16. The XDP program
//     builds its lookup key as `spkey.dst_port = ct_key.dport`, where
//     ct_key.dport is copied verbatim from the TCP/UDP header (tcp->dest /
//     udp->dest) — i.e. network byte order. A HASH lookup matches only on
//     exact key bytes, so the Go insert must use the SAME order.
//
// Why this was wrong before, and why it stayed hidden: this previously wrote
// dst_port little-endian. That makes the inserted key for port P carry the
// bytes of byteswap(P), so the kernel matches the rule against packets to
// byteswap(P), not P — a rule meant to admit "<src> -> tcp/443" (0x01BB) is
// stored as 0xBB 0x01 and actually admits tcp/47873 (0xBB01): the intended
// port is denied (allow lookup misses -> XDP_DROP) AND the wrong port is
// opened for that (already knock-authenticated) source — a least-privilege /
// policy-fidelity break, not an outsider hole. It was masked because (a) prod
// runs FilterMode_IPTABLES, so the XDP datapath is dormant; (b) the sibling
// protocol_port path compensates for the same LE write via parsePort's
// pre-swap, so the convention looked fine; and (c) no test pinned these bytes.
//
// IPv6 twin: the v6 serializers ToSpKeyV6/ToPlKeyV6 (merged in #2824) ALREADY
// use this big-endian convention, and the v6 XDP src_port_v6 lookup (#2825) is
// wired to match — they were the canary that surfaced this v4 bug, tracked as
// #2842 (which this fix closes). This change brings v4 into alignment with the
// already-correct v6; keep the two in lockstep.
func (r *srcIPdstPortKey) ToSpKey() []byte {
	keyBytes := make([]byte, 6)
	binary.LittleEndian.PutUint32(keyBytes[0:4], r.SrcIP)
	binary.BigEndian.PutUint16(keyBytes[4:6], r.DstPort)
	return keyBytes
}

func (r *srcIPdstPortKey) ToSpValue(ttlSec uint64) whitelistValue {
	now, _ := getBootTimeNanos()
	return whitelistValue{
		Allowed:    1,
		ExpireTime: now + ttlSec*1_000_000_000,
	}
}

// function for update whitelist map
func AddWhitelistRule(whitelistMap *ebpf.Map, rule *whitelistKey, ttlSec uint64) error {
	keyBytes := rule.ToWlKey()
	value := rule.ToWlValue(ttlSec)

	if err := whitelistMap.Update(keyBytes, &value, ebpf.UpdateAny); err != nil {
		log.Error("failed to update whitelist map: %v", err)
		return err
	}
	return nil
}

// function for update sdwhitelist map
func AddSdWhitelistRule(whitelistMap *ebpf.Map, rule *srcDestKey, ttlSec uint64) error {
	keyBytes := rule.ToSdKey()
	value := rule.ToSdValue(ttlSec)

	if err := whitelistMap.Update(keyBytes, &value, ebpf.UpdateAny); err != nil {
		log.Error("failed to update sdwhitelist map: %v", err)
		return err
	}
	return nil
}

// function for update sdportlist map
func AddSdPortlistRule(whitelistMap *ebpf.Map, rule *portListKey, ttlSec uint64) error {
	keyBytes := rule.ToPlKey()
	value := rule.ToPlValue(ttlSec)

	if err := whitelistMap.Update(keyBytes, &value, ebpf.UpdateAny); err != nil {
		log.Error("failed to update src dst portlist map: %v", err)
		return err
	}
	return nil
}

// function for update protocol_port map
func AddPpWhitelistRule(whitelistMap *ebpf.Map, rule *procoPortKey, ttlSec uint64) error {
	keyBytes := rule.ToPpKey()
	value := rule.ToPpValue(ttlSec)

	if err := whitelistMap.Update(keyBytes, &value, ebpf.UpdateAny); err != nil {
		log.Error("failed to update sdwhitelist map: %v", err)
		return err
	}
	return nil
}

// function for update src dst port map
func AddSrcipDestPortRule(whitelistMap *ebpf.Map, rule *srcIPdstPortKey, ttlSec uint64) error {
	keyBytes := rule.ToSpKey()
	value := rule.ToSpValue(ttlSec)

	if err := whitelistMap.Update(keyBytes, &value, ebpf.UpdateAny); err != nil {
		log.Error("failed to update src_port_list map: %v", err)
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// IPv6 allow-rule writers (E2 slice 4 — wiring v6 admissions to the v6 maps).
//
// One-for-one mirror of the v4 Add* writers above. Each builds the packed v6
// key via the s2 To*KeyV6 serializer and writes it to the supplied v6 map. The
// value bytes are family-agnostic: whitelistValue / procoPortValue carry only
// {allowed, expire_time} and no address, so the v4 To*Value constructors apply
// unchanged here (their receiver fields are unused — see ToWlValue).
//
// FAIL-CLOSED CONTRACT: like the v4 writers, these return the RAW *ebpf.Map
// Update error unwrapped. That is load-bearing — the admission path wraps
// EbpfRuleAdd in (*UdpAC).recordEbpfInsertResult, which calls IsMapFull
// (errors.Is over syscall.E2BIG) to detect a full HASH map and emit the LOUD
// fail-closed metric+log (#2163). A %v-wrap here would defeat errors.Is and
// silently degrade a full-map -E2BIG into a swallowed admit. Never wrap with %v.

// AddWhitelistRuleV6 writes a whitelistKeyV6 (spp_v6) entry.
func AddWhitelistRuleV6(whitelistMap *ebpf.Map, rule *whitelistKeyV6, ttlSec uint64) error {
	keyBytes := rule.ToWlKeyV6()
	value := (&whitelistKey{}).ToWlValue(ttlSec)

	if err := whitelistMap.Update(keyBytes, &value, ebpf.UpdateAny); err != nil {
		log.Error("failed to update spp_v6 map: %v", err)
		return err
	}
	return nil
}

// AddSdWhitelistRuleV6 writes a srcDestKeyV6 entry to a v6 src+dst map
// (sdwhitelist_v6 or the identically-shaped icmp_wl_v6).
func AddSdWhitelistRuleV6(whitelistMap *ebpf.Map, rule *srcDestKeyV6, ttlSec uint64) error {
	keyBytes := rule.ToSdKeyV6()
	value := (&srcDestKey{}).ToSdValue(ttlSec)

	if err := whitelistMap.Update(keyBytes, &value, ebpf.UpdateAny); err != nil {
		log.Error("failed to update sdwhitelist_v6/icmp_wl_v6 map: %v", err)
		return err
	}
	return nil
}

// AddSdPortlistRuleV6 writes a portListKeyV6 (port_list_v6) entry.
func AddSdPortlistRuleV6(whitelistMap *ebpf.Map, rule *portListKeyV6, ttlSec uint64) error {
	keyBytes := rule.ToPlKeyV6()
	value := (&portListKey{}).ToPlValue(ttlSec)

	if err := whitelistMap.Update(keyBytes, &value, ebpf.UpdateAny); err != nil {
		log.Error("failed to update port_list_v6 map: %v", err)
		return err
	}
	return nil
}

// AddSrcipDestPortRuleV6 writes a srcIPdstPortKeyV6 (src_port_v6) entry.
func AddSrcipDestPortRuleV6(whitelistMap *ebpf.Map, rule *srcIPdstPortKeyV6, ttlSec uint64) error {
	keyBytes := rule.ToSpKeyV6()
	value := (&srcIPdstPortKey{}).ToSpValue(ttlSec)

	if err := whitelistMap.Update(keyBytes, &value, ebpf.UpdateAny); err != nil {
		log.Error("failed to update src_port_v6 map: %v", err)
		return err
	}
	return nil
}

func AddEbpfRuleForSrcDstPortProto(srcIPStr, dstIPStr string, protocol uint8, dstPort uint16, ttlSec uint64) error {
	whitelistMap, err := ebpf.LoadPinnedMap(PinPathWhitelist, nil)
	if err != nil {
		log.Error("failed to load pinned whitelist map: %v", err)
		return err
	}
	defer func() { _ = whitelistMap.Close() }()

	srcIP, err := parseIP(srcIPStr)
	if err != nil {
		log.Error("invalid source IP: %v", err)
		return err
	}

	dstIP, err := parseIP(dstIPStr)
	if err != nil {
		log.Error("invalid destination IP: %v", err)
		return err
	}

	rule := &whitelistKey{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		DstPort:  dstPort,
		Protocol: protocol,
	}

	return AddWhitelistRule(whitelistMap, rule, ttlSec)
}

func AddEbpfRuleForSrcDst(srcIPStr, dstIPStr string, ttlSec uint64) error {
	whitelistMap, err := ebpf.LoadPinnedMap(PinPathSdWhitelist, nil)
	if err != nil {
		log.Error("failed to load pinned whitelist map: %v", err)
		return err
	}
	defer func() { _ = whitelistMap.Close() }()

	srcIP, err := parseIP(srcIPStr)
	if err != nil {
		log.Error("invalid source IP: %v", err)
		return err
	}

	dstIP, err := parseIP(dstIPStr)
	if err != nil {
		log.Error("invalid destination IP: %v", err)
		return err
	}

	rule := &srcDestKey{
		SrcIP: srcIP,
		DstIP: dstIP,
	}

	return AddSdWhitelistRule(whitelistMap, rule, ttlSec)
}

func AddEbpfRuleForSrcDestPort(srcIPStr string, dstPort int, ttlSec uint64) error {
	whitelistMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/src_port", nil)
	if err != nil {
		log.Error("failed to load pinned whitelist map: %v", err)
		return err
	}
	defer func() { _ = whitelistMap.Close() }()

	srcIP, err := parseIP(srcIPStr)
	if err != nil {
		log.Error("invalid source IP: %v", err)
		return err
	}

	dstPortu, err := safeIntToUint16(dstPort)

	if err != nil {
		log.Error("failed to safeIntToUint16 in src_port_list map: %v", err)
		return err
	}

	rule := &srcIPdstPortKey{
		SrcIP:   srcIP,
		DstPort: dstPortu,
	}
	return AddSrcipDestPortRule(whitelistMap, rule, ttlSec)
}

// function for update icmpwhitelist map
func AddEbpfIcmpRuleForSrcDst(srcIPStr, dstIPStr string, ttlSec uint64) error {
	whitelistMap, err := ebpf.LoadPinnedMap(PinPathIcmpWhitelist, nil)
	if err != nil {
		log.Error("failed to load pinned whitelist map: %v", err)
		return err
	}
	defer func() { _ = whitelistMap.Close() }()

	srcIP, err := parseIP(srcIPStr)
	if err != nil {
		log.Error("invalid source IP: %v", err)
		return err
	}

	dstIP, err := parseIP(dstIPStr)
	if err != nil {
		log.Error("invalid destination IP: %v", err)
		return err
	}

	rule := &srcDestKey{
		SrcIP: srcIP,
		DstIP: dstIP,
	}

	return AddSdWhitelistRule(whitelistMap, rule, ttlSec)
}

// function for update port_list map
func AddEbpfRuleForSrcDestPortList(srcIPStr string, dstPortStart, dstPortEnd int, ttlSec uint64) error {
	portListMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/port_list", nil)
	if err != nil {
		log.Error("failed to load pinned port_list map: %v", err)
		return err
	}
	defer func() { _ = portListMap.Close() }()

	srcIP, err := parseIP(srcIPStr)
	if err != nil {
		log.Error("invalid source IP: %v", err)
		return err
	}

	portStart, err := safeIntToUint16(dstPortStart)
	if err != nil {
		log.Error("failed to safeIntToUint16 for dstPortStart: %d", dstPortStart)
		return err
	}
	portEnd, err := safeIntToUint16(dstPortEnd)

	if err != nil {
		log.Error("failed to safeIntToUint16 for dstPortEnd: %d", dstPortEnd)
		return err
	}

	rule := &portListKey{
		SrcIP:        srcIP,
		DstPortStart: portStart,
		DstPortEnd:   portEnd,
	}

	return AddSdPortlistRule(portListMap, rule, ttlSec)
}

// function for update protocol dstport map
func AddEbpfRuleForProtocolPort(protocol uint8, dstPort uint16, ttlSec uint64) error {
	portStr := fmt.Sprintf("%d", dstPort)
	dstPortt, err := parsePort(portStr)
	if err != nil {
		log.Error("failed to parsePort: %v", portStr)
		return err
	}
	portListMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/protocol_port", nil)
	if err != nil {
		log.Error("failed to load pinned protocol_port map: %v", err)
		return err
	}
	defer func() { _ = portListMap.Close() }()

	rule := &procoPortKey{
		DstPort:  dstPortt,
		Protocol: protocol,
	}

	return AddPpWhitelistRule(portListMap, rule, ttlSec)
}

func safeIntToUint16(i int) (uint16, error) {
	if i < 0 || i > 65535 {
		return 0, fmt.Errorf("value %d is out of range for uint16", i)
	}
	return uint16(i), nil
}

// ---------------------------------------------------------------------------
// IPv6 load-pinned-map-and-write helpers (E2 slice 4). Each is the v6 twin of
// the matching v4 AddEbpfRuleFor* function: it loads the pinned `*_v6` map,
// parseIP6's the address(es) (which REJECTS IPv4 — keeping the families
// disjoint), builds the v6 key, and writes via the Add*RuleV6 injectable writer
// above. The raw map-Update error propagates unwrapped so the fail-closed
// wrapper (recordEbpfInsertResult → IsMapFull) still matches -E2BIG.

func AddEbpfRuleForSrcDstPortProtoV6(srcIPStr, dstIPStr string, protocol uint8, dstPort uint16, ttlSec uint64) error {
	whitelistMap, err := ebpf.LoadPinnedMap(PinPathWhitelistV6, nil)
	if err != nil {
		log.Error("failed to load pinned spp_v6 map: %v", err)
		return err
	}
	defer func() { _ = whitelistMap.Close() }()

	srcIP, err := parseIP6(srcIPStr)
	if err != nil {
		log.Error("invalid source IPv6: %v", err)
		return err
	}
	dstIP, err := parseIP6(dstIPStr)
	if err != nil {
		log.Error("invalid destination IPv6: %v", err)
		return err
	}

	rule := &whitelistKeyV6{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		DstPort:  dstPort,
		Protocol: protocol,
	}
	return AddWhitelistRuleV6(whitelistMap, rule, ttlSec)
}

func AddEbpfRuleForSrcDstV6(srcIPStr, dstIPStr string, ttlSec uint64) error {
	whitelistMap, err := ebpf.LoadPinnedMap(PinPathSdWhitelistV6, nil)
	if err != nil {
		log.Error("failed to load pinned sdwhitelist_v6 map: %v", err)
		return err
	}
	defer func() { _ = whitelistMap.Close() }()

	srcIP, err := parseIP6(srcIPStr)
	if err != nil {
		log.Error("invalid source IPv6: %v", err)
		return err
	}
	dstIP, err := parseIP6(dstIPStr)
	if err != nil {
		log.Error("invalid destination IPv6: %v", err)
		return err
	}

	rule := &srcDestKeyV6{
		SrcIP: srcIP,
		DstIP: dstIP,
	}
	return AddSdWhitelistRuleV6(whitelistMap, rule, ttlSec)
}

func AddEbpfIcmpRuleForSrcDstV6(srcIPStr, dstIPStr string, ttlSec uint64) error {
	whitelistMap, err := ebpf.LoadPinnedMap(PinPathIcmpWhitelistV6, nil)
	if err != nil {
		log.Error("failed to load pinned icmp_wl_v6 map: %v", err)
		return err
	}
	defer func() { _ = whitelistMap.Close() }()

	srcIP, err := parseIP6(srcIPStr)
	if err != nil {
		log.Error("invalid source IPv6: %v", err)
		return err
	}
	dstIP, err := parseIP6(dstIPStr)
	if err != nil {
		log.Error("invalid destination IPv6: %v", err)
		return err
	}

	rule := &srcDestKeyV6{
		SrcIP: srcIP,
		DstIP: dstIP,
	}
	return AddSdWhitelistRuleV6(whitelistMap, rule, ttlSec)
}

func AddEbpfRuleForSrcDestPortV6(srcIPStr string, dstPort int, ttlSec uint64) error {
	whitelistMap, err := ebpf.LoadPinnedMap(PinPathSrcPortV6, nil)
	if err != nil {
		log.Error("failed to load pinned src_port_v6 map: %v", err)
		return err
	}
	defer func() { _ = whitelistMap.Close() }()

	srcIP, err := parseIP6(srcIPStr)
	if err != nil {
		log.Error("invalid source IPv6: %v", err)
		return err
	}
	dstPortu, err := safeIntToUint16(dstPort)
	if err != nil {
		log.Error("failed to safeIntToUint16 in src_port_v6 map: %v", err)
		return err
	}

	rule := &srcIPdstPortKeyV6{
		SrcIP:   srcIP,
		DstPort: dstPortu,
	}
	return AddSrcipDestPortRuleV6(whitelistMap, rule, ttlSec)
}

func AddEbpfRuleForSrcDestPortListV6(srcIPStr string, dstPortStart, dstPortEnd int, ttlSec uint64) error {
	portListMap, err := ebpf.LoadPinnedMap(PinPathPortListV6, nil)
	if err != nil {
		log.Error("failed to load pinned port_list_v6 map: %v", err)
		return err
	}
	defer func() { _ = portListMap.Close() }()

	srcIP, err := parseIP6(srcIPStr)
	if err != nil {
		log.Error("invalid source IPv6: %v", err)
		return err
	}
	portStart, err := safeIntToUint16(dstPortStart)
	if err != nil {
		log.Error("failed to safeIntToUint16 for dstPortStart: %d", dstPortStart)
		return err
	}
	portEnd, err := safeIntToUint16(dstPortEnd)
	if err != nil {
		log.Error("failed to safeIntToUint16 for dstPortEnd: %d", dstPortEnd)
		return err
	}

	rule := &portListKeyV6{
		SrcIP:        srcIP,
		DstPortStart: portStart,
		DstPortEnd:   portEnd,
	}
	return AddSdPortlistRuleV6(portListMap, rule, ttlSec)
}

// EbpfRuleAddV6 is the IPv6 dispatcher: the v6 twin of EbpfRuleAdd's per-mapType
// switch. EbpfRuleAdd routes here once it has detected an IPv6 source address,
// so v6 admissions land in the `*_v6` maps. It deliberately does NOT change any
// caller — detection lives in EbpfRuleAdd so every msghandler call site stays
// family-agnostic (it just passes the address string through).
//
// MapTypeProtocolPort (6) is intentionally NOT handled here: the protocol_port
// map keys on {dst_port, protocol} with no address, so it is shared by both
// families and stays on the v4 AddEbpfRuleForProtocolPort path. EbpfRuleAdd
// never routes mapType 6 here (the family predicate requires a non-empty,
// non-IPv4 SrcIP; type-6 admissions carry no SrcIP), but this returns an
// explicit error rather than silently no-op'ing if that invariant is ever
// violated — a silent miss would be a fail-OPEN admission gap.
func EbpfRuleAddV6(mapType int, params EbpfRuleParams, TtlSec int) error {
	var err error
	TtlSec64 := uint64(TtlSec)
	var protocol uint8
	if len(params.Protocol) > 0 {
		switch params.Protocol {
		case "tcp":
			protocol = 6
		case "udp":
			protocol = 17
		case "icmp":
			// ICMPv6 is gated via icmp_wl_v6 (MapTypeIcmpWhitelist), not here:
			// that key is address-only (no nexthdr), so this byte is unused for
			// ICMP. Kept as 1 (IPPROTO_ICMP) to mirror the v4 switch; were a
			// MapTypeWhitelist v6 admission ever to carry "icmp", spp_v6 would
			// need 58 (IPPROTO_ICMPV6) to match the packet's nexthdr.
			protocol = 1
		default:
			return fmt.Errorf("unsupported protocol: %s", params.Protocol)
		}
	}

	switch mapType {
	case MapTypeWhitelist:
		err = AddEbpfRuleForSrcDstPortProtoV6(params.SrcIP, params.DstIP, protocol, uint16(params.DstPort), TtlSec64)
		if err != nil {
			log.Error("failed add ebpf v6 src: %s dst: %s, error: %v, protocol: %d, dstport: %d", params.SrcIP, params.DstIP, err, protocol, uint16(params.DstPort))
			return err
		}

	case MapTypeSdWhitelist:
		err = AddEbpfRuleForSrcDstV6(params.SrcIP, params.DstIP, TtlSec64)
		if err != nil {
			log.Error("failed add ebpf v6 src: %s dst: %s", params.SrcIP, params.DstIP)
			return err
		}

	case MapTypeIcmpWhitelist:
		err = AddEbpfIcmpRuleForSrcDstV6(params.SrcIP, params.DstIP, TtlSec64)
		if err != nil {
			log.Error("failed add ebpf v6 icmp src: %s dst: %s", params.SrcIP, params.DstIP)
			return err
		}

	case MapTypeSrcAndPort:
		err = AddEbpfRuleForSrcDestPortV6(params.SrcIP, params.DstPort, TtlSec64)
		if err != nil {
			log.Error("failed add ebpf v6 src: %s dst port: %d", params.SrcIP, params.DstPort)
			return err
		}

	case MapTypeSrcPortList:
		err = AddEbpfRuleForSrcDestPortListV6(params.SrcIP, params.DstPortStart, params.DstPortEnd, TtlSec64)
		if err != nil {
			log.Error("failed add ebpf v6 src: %s dst port start: %d dst port end: %d", params.SrcIP, params.DstPortStart, params.DstPortEnd)
			return err
		}

	case MapTypeProtocolPort:
		// protocol_port is address-less and shared v4/v6 — must never be
		// routed through the v6 dispatcher. EbpfRuleAdd's family predicate
		// keeps type 6 on the v4 path; reaching here means that invariant
		// broke. Fail loud rather than silently drop the admission.
		return fmt.Errorf("MapTypeProtocolPort (6) has no IPv6 map — it is address-less and shared; must route through the v4 path, not EbpfRuleAddV6")

	default:
		return fmt.Errorf("unsupported map type: %d", mapType)
	}

	return nil
}

// DelEbpfRuleForSrcDstPortProto removes the allow-rule entry from
// the spp (whitelist) map for the given 4-tuple. Idempotent on
// no-match (ENOENT → nil) — used by the L3 flush-on-expiry
// scheduler in endpoints/ac, which expects flushers to no-op on
// already-gone state.
func DelEbpfRuleForSrcDstPortProto(srcIPStr, dstIPStr string, protocol uint8, dstPort uint16) error {
	m, err := ebpf.LoadPinnedMap(PinPathWhitelist, nil)
	if err != nil {
		return fmt.Errorf("load pinned spp: %w", err)
	}
	defer func() { _ = m.Close() }()

	srcIP, err := parseIP(srcIPStr)
	if err != nil {
		return err
	}
	dstIP, err := parseIP(dstIPStr)
	if err != nil {
		return err
	}
	rule := &whitelistKey{SrcIP: srcIP, DstIP: dstIP, DstPort: dstPort, Protocol: protocol}
	if err := m.Delete(rule.ToWlKey()); err != nil && !isEbpfNoEntry(err) {
		return fmt.Errorf("delete from spp: %w", err)
	}
	return nil
}

// DelEbpfRuleForSrcDst removes the allow-rule entry from the
// sdwhitelist map for the given 2-tuple. Idempotent on no-match.
func DelEbpfRuleForSrcDst(srcIPStr, dstIPStr string) error {
	m, err := ebpf.LoadPinnedMap(PinPathSdWhitelist, nil)
	if err != nil {
		return fmt.Errorf("load pinned sdwhitelist: %w", err)
	}
	defer func() { _ = m.Close() }()

	srcIP, err := parseIP(srcIPStr)
	if err != nil {
		return err
	}
	dstIP, err := parseIP(dstIPStr)
	if err != nil {
		return err
	}
	rule := &srcDestKey{SrcIP: srcIP, DstIP: dstIP}
	if err := m.Delete(rule.ToSdKey()); err != nil && !isEbpfNoEntry(err) {
		return fmt.Errorf("delete from sdwhitelist: %w", err)
	}
	return nil
}

// DelEbpfIcmpRuleForSrcDst removes the allow-rule entry from the
// icmpwhitelist map for the given 2-tuple. Idempotent on no-match.
func DelEbpfIcmpRuleForSrcDst(srcIPStr, dstIPStr string) error {
	m, err := ebpf.LoadPinnedMap(PinPathIcmpWhitelist, nil)
	if err != nil {
		return fmt.Errorf("load pinned icmpwhitelist: %w", err)
	}
	defer func() { _ = m.Close() }()

	srcIP, err := parseIP(srcIPStr)
	if err != nil {
		return err
	}
	dstIP, err := parseIP(dstIPStr)
	if err != nil {
		return err
	}
	rule := &srcDestKey{SrcIP: srcIP, DstIP: dstIP}
	if err := m.Delete(rule.ToSdKey()); err != nil && !isEbpfNoEntry(err) {
		return fmt.Errorf("delete from icmpwhitelist: %w", err)
	}
	return nil
}

// DelEbpfConnTrackEntry removes a single established-flow entry from the
// conntrack map (PinPathConnTrack) by its full 5-tuple, including the
// per-flow source port. This is the P4c surgical-revocation primitive:
// unlike the allow-rule Del* helpers above (which key only on
// {src_ip,dst_ip,dst_port,proto} and so cannot distinguish two sessions
// behind one NAT), deleting the conntrack entry by 5-tuple tears down
// EXACTLY the target flow and leaves a sibling flow on the same
// allow-rule tuple — but with a different source port — untouched.
//
// It is also what makes revocation IMMEDIATE for an established flow:
// the XDP program short-circuits established flows on this map before any
// allow-rule lookup, and the entry's ttl_ns was anchored to the
// allow-rule's ORIGINAL remaining lifetime at flow creation. So deleting
// the allow-rule alone leaves the flow passing until that original
// deadline; deleting the conntrack entry forces the very next packet back
// through the allow-rule path (which a revoke also removes) → XDP_DROP.
//
// srcPort/dstPort are host-order (0..65535); they are written network
// order into the key to match the on-wire __be16 the XDP program copies
// from the packet. protocol is the IANA number (6=TCP, 17=UDP). Only
// connection-oriented / port-bearing protocols have conntrack entries;
// ICMP and "any" allow-rules create no conntrack short-circuit, so this
// helper is not called for them.
//
// Idempotent on no-match (ENOENT → nil): the kernel's own
// check_conn_expiry may have GC'd the entry, or a concurrent flush may
// have removed it. Mirrors the allow-rule Del* contract the L3 flush
// scheduler depends on (a flush against already-gone state must NOT trip
// the breaker).
//
// TEARDOWN-COMPLETENESS ASSUMPTION (code-verified, must be re-checked if
// the datapath changes): there is exactly ONE conntrack entry per flow,
// inserted by the XDP ingress program in the CT_DIR_INGRESS orientation
// (it reverses its working tuple back to ingress before the allow-rule
// checks — nhp_ebpf_xdp.c, and all five conn_track inserts use that one
// ingress-oriented key). The TC egress program (tc_egress.c) does NOT
// touch conn_track at all — it only writes a reverse-direction ALLOW-RULE
// to spp so reply traffic is permitted. Therefore deleting the single
// ingress-oriented conntrack entry is sufficient to drop the flow; there
// is no reversed/egress conntrack entry left behind. NOTE for P4e: the
// reverse allow-rule that tc_egress writes to spp is a separate object
// from this conntrack entry — barring re-open after a revoke requires
// removing that reverse allow-rule too (an allow-rule concern, out of
// scope for this conntrack-teardown primitive). If a future change makes
// tc_egress (or any program) insert a conntrack entry in the egress
// orientation, this helper must also delete the reversed tuple
// (daddr/saddr + dport/sport swapped, flags = egress).
func DelEbpfConnTrackEntry(srcIPStr, dstIPStr string, protocol uint8, srcPort, dstPort uint16) error {
	m, err := ebpf.LoadPinnedMap(PinPathConnTrack, nil)
	if err != nil {
		return fmt.Errorf("load pinned conn_track: %w", err)
	}
	defer func() { _ = m.Close() }()
	return delEbpfConnTrackOnMap(m, srcIPStr, dstIPStr, protocol, srcPort, dstPort)
}

// delEbpfConnTrackOnMap is the map-handle-injectable core of
// DelEbpfConnTrackEntry: it builds the conntrack 5-tuple key and issues
// the idempotent Delete against the supplied map. Splitting the pinned-map
// open out of the delete lets the surgical-revocation behavior be tested
// against a real in-test ebpf.Map of the conntrack shape (no /sys/fs/bpf
// pin required), proving that a 5-tuple delete removes EXACTLY the target
// flow and leaves a same-allow-rule-tuple sibling (different source port)
// intact. The public wrapper above keeps the production pin-path contract.
func delEbpfConnTrackOnMap(m *ebpf.Map, srcIPStr, dstIPStr string, protocol uint8, srcPort, dstPort uint16) error {
	srcIP, err := parseIP(srcIPStr)
	if err != nil {
		return err
	}
	dstIP, err := parseIP(dstIPStr)
	if err != nil {
		return err
	}
	key := &connTrackKey{
		DstIP:   dstIP,
		SrcIP:   srcIP,
		DstPort: dstPort,
		SrcPort: srcPort,
		NextHdr: protocol,
		Flags:   ctDirIngress,
	}
	if err := m.Delete(key.ToCtKey()); err != nil && !isEbpfNoEntry(err) {
		return fmt.Errorf("delete from conn_track: %w", err)
	}
	return nil
}

// isEbpfNoEntry returns true if err is the cilium/ebpf "key not
// found" error or a wrapped ENOENT. Both kernel GC and a concurrent
// flush can have removed the entry before us — treat as success.
//
// errors.Is reaches through wrappers — no error-text scraping
func isEbpfNoEntry(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ebpf.ErrKeyNotExist) || errors.Is(err, syscall.ENOENT)
}

// IsMapFull reports whether err is the kernel "map is full" signal from a BPF
// map insert — i.e. the map is at max_entries and cannot admit a NEW key.
//
// The kernel returns E2BIG from BPF_MAP_UPDATE_ELEM when a non-LRU map (our
// authoritative allow-rule maps are BPF_MAP_TYPE_HASH, #2163) is full. The
// cilium/ebpf library wraps it as `fmt.Errorf("key too big for map: %w", err)`
// over unix.E2BIG (see wrapMapError in syscalls.go); the "key too big" text is
// misleading — for our fixed-size keys the only update-time cause is a full
// map. errors.Is reaches through the wrapper, so we match the errno, never the
// text (memory: feedback_silent_failure_patterns.md — no error-text scraping).
//
// This is the fail-CLOSED signal: callers must REJECT the new admission (and
// raise a loud metric/log) rather than swallow it — an admitted-but-not-enforced
// session is a security hole. Updating an EXISTING key on a full map still
// succeeds (no new slot needed), so session re-authorization is unaffected.
func IsMapFull(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.E2BIG)
}

// isIPv6Src reports whether an admission's source-address string is an IPv6
// address that must route to the `*_v6` maps. It is the family-detection
// predicate EbpfRuleAdd uses to dispatch v4 vs v6; extracted as a pure function
// so the routing decision is unit-testable without a kernel or pinned maps.
//
// The predicate is `ip != nil && ip.To4() == nil` — identical to utils.IsIPv6
// (kept inline to avoid a new package dependency from this self-contained pkg;
// parseIP/parseIP6 likewise carry their own family logic).
//
//   - The `ip != nil` nil-guard is load-bearing: net.ParseIP("") is nil and
//     nil.To4() is also nil, so a bare `To4()==nil` check would misclassify an
//     EMPTY SrcIP as IPv6. MapTypeProtocolPort (6) admissions carry no SrcIP
//     (the map is address-less and shared v4/v6), so without the guard they
//     would wrongly route to a non-existent v6 protocol_port map. The guard
//     keeps empty-SrcIP (and any unparseable string) on the v4 path.
//   - IPv4-mapped IPv6 (::ffff:a.b.c.d) has a non-nil To4(), so it routes v4 —
//     consistent with parseIP6, which rejects it (keeping the families disjoint).
//   - SINGLE-FAMILY-PER-RULE invariant: dispatch keys ONLY on SrcIP, so a
//     mixed-family rule (v6 src + v4 dst) routes to v6, where parseIP6(dstIP)
//     rejects the v4 dst and the admission fail-closes — correct, never
//     mis-keyed, but it assumes one rule is one family end-to-end.
func isIPv6Src(srcIP string) bool {
	ip := net.ParseIP(srcIP)
	return ip != nil && ip.To4() == nil
}

// A generic entry function that calls the corresponding function to add whitelist entries based on mapTypeandparams.
//
// FAMILY DETECTION (E2 slice 4): centralized HERE (via isIPv6Src) so every
// msghandler call site stays family-agnostic — it just passes the admission's
// source-address string through and this function routes IPv6 admissions to the
// `*_v6` maps via EbpfRuleAddV6. Both the v4 and v6 paths return their raw insert
// error, so the admission-side fail-closed wrapper
// ((*UdpAC).recordEbpfInsertResult, which runs IsMapFull over -E2BIG) covers v6
// exactly as it covers v4 — v6 inserts are NOT bypassing it.
func EbpfRuleAdd(mapType int, params EbpfRuleParams, TtlSec int) error {
	if isIPv6Src(params.SrcIP) {
		return EbpfRuleAddV6(mapType, params, TtlSec)
	}

	var err error
	TtlSec64 := uint64(TtlSec)
	var protocol uint8
	if len(params.Protocol) > 0 {
		switch params.Protocol {
		case "tcp":
			protocol = 6
		case "udp":
			protocol = 17
		case "icmp":
			protocol = 1
		default:
			return fmt.Errorf("unsupported protocol: %s", params.Protocol)
		}
	}

	switch mapType {
	case MapTypeWhitelist:
		//base the map whitelist
		err = AddEbpfRuleForSrcDstPortProto(params.SrcIP, params.DstIP, protocol, uint16(params.DstPort), TtlSec64)
		if err != nil {
			log.Error("failed add ebpf src: %s dst: %s, error: %v, protocol: %d, dstport: %d", params.SrcIP, params.DstIP, err, protocol, uint16(params.DstPort))
			return err
		}

	case MapTypeSdWhitelist:
		//base the map sdwhitelist
		err = AddEbpfRuleForSrcDst(params.SrcIP, params.DstIP, TtlSec64)
		if err != nil {
			log.Error("failed add ebpf src: %s dst: %s", params.SrcIP, params.DstIP)
			return err
		}

	case MapTypeIcmpWhitelist:
		//base the map icmpwhitelist
		err = AddEbpfIcmpRuleForSrcDst(params.SrcIP, params.DstIP, TtlSec64)
		if err != nil {
			log.Error("failed add ebpf icmp src: %s dst: %s", params.SrcIP, params.DstIP)
			return err
		}

	case MapTypeSrcAndPort:
		//base the map src_port_list
		err = AddEbpfRuleForSrcDestPort(params.SrcIP, params.DstPort, TtlSec64)
		if err != nil {
			log.Error("failed add ebpf src: %s dst port: %d", params.SrcIP, params.DstPort)
			return err
		}

	case MapTypeSrcPortList:
		//base the map port_list
		err = AddEbpfRuleForSrcDestPortList(params.SrcIP, params.DstPortStart, params.DstPortEnd, TtlSec64)
		if err != nil {
			log.Error("failed add ebpf src: %s dst port start: %d dst port end: %d", params.SrcIP, params.DstPortStart, params.DstPortEnd)
			return err
		}

	case MapTypeProtocolPort:
		//base the map protocol_port
		dstPort := uint16(params.DstPort)
		err = AddEbpfRuleForProtocolPort(protocol, dstPort, TtlSec64)
		if err != nil {
			log.Error("failed add ebpf protocol: %s dst port: %d", params.Protocol, params.DstPort)
			return err
		}

	default:
		return fmt.Errorf("unsupported map type: %d", mapType)
	}

	return nil
}

// Parse the IP address
func parseIP(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Error("invalid IP address: %s", ipStr)
		return 0, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	ip = ip.To4()
	if ip == nil {
		log.Error("only IPv4 addresses are supported: %s", ipStr)
		return 0, fmt.Errorf("only IPv4 addresses are supported: %s", ipStr)
	}
	return binary.LittleEndian.Uint32(ip), nil
}

// parseIP6 is the IPv6 counterpart of parseIP: it parses an IPv6 address
// string into its 16 on-wire (network-order) bytes. It is the family-rejecting
// mirror of parseIP — where parseIP rejects IPv6 (To4()==nil), parseIP6
// rejects IPv4.
//
// The IPv4 rejection is EXPLICIT (To4()!=nil) and deliberately precedes
// To16(): net.IP.To16() returns a non-nil 16-byte slice for an IPv4 input too
// (the IPv4-mapped ::ffff:a.b.c.d form), so a To16()==nil check alone would
// NOT reject IPv4 — it would silently encode v4 as an IPv4-mapped v6 address
// and the "only IPv6 supported" error would be unreachable. Rejecting on
// To4() first keeps the v4 and v6 paths strictly disjoint, so a caller can't
// accidentally route a v4 address through a v6 map key (or vice versa).
func parseIP6(ipStr string) ([16]byte, error) {
	var out [16]byte
	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Error("invalid IP address: %s", ipStr)
		return out, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	if ip.To4() != nil {
		log.Error("only IPv6 addresses are supported: %s", ipStr)
		return out, fmt.Errorf("only IPv6 addresses are supported: %s", ipStr)
	}
	// To16() is guaranteed non-nil here: net.ParseIP already succeeded, and a
	// parsed IP that is not IPv4 (To4()==nil, rejected above) always has a
	// 16-byte To16() form. So no nil check is needed — a To16()==nil branch
	// would be dead code. copy from a 16-byte source fully fills out[16]byte.
	copy(out[:], ip.To16())
	return out, nil
}

// parsePort parses a decimal port and returns it BYTE-SWAPPED (network order
// packed into a host uint16): for 443 it returns 0xBB01, not 0x01BB. This swap
// is load-bearing — its only caller (AddEbpfRuleForProtocolPort) hands the
// result to ToPpKey, whose LittleEndian write cancels it back to network order.
// See ToPpKey's godoc for the full cancellation rationale and why changing one
// half without the other silently breaks the key (convergence tracked: #2845).
func parsePort(portStr string) (uint16, error) {
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16([]byte{byte(port >> 8), byte(port & 0xFF)}), nil
}
