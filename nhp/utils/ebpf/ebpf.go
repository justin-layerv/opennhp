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
//   - The struct is __packed in C (no trailing/interior padding): 4+4+2+2+
//     1+1 = 14 bytes. ToCtKey emits exactly those 14 bytes.
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

// connTrackKeySize is the on-wire size of the packed ipv4_ct_tuple
// (14 bytes). Derived so ToCtKey's hand-packed buffer length and the
// kernel key size cannot silently diverge. NOTE: this is the SUM of field
// sizes, not unsafe.Sizeof(connTrackKey{}) — the Go struct is NOT packed
// (it carries Go alignment padding), whereas the kernel struct is
// __packed. ToCtKey emits the packed form; this const fences that form.
const connTrackKeySize = 4 + 4 + 2 + 2 + 1 + 1

// ToCtKey serializes the conntrack tuple into the exact 14 packed bytes
// the kernel `ipv4_ct_tuple` map key expects. IP fields are written
// little-endian because parseIP already returns the network-order bytes
// packed into a uint32 via LittleEndian (matching ToWlKey's __be32
// handling); ports are written big-endian to reproduce the on-wire
// __be16. See connTrackKey's godoc for why every byte here is
// load-bearing.
func (r *connTrackKey) ToCtKey() []byte {
	keyBytes := make([]byte, connTrackKeySize)
	binary.LittleEndian.PutUint32(keyBytes[0:4], r.DstIP)
	binary.LittleEndian.PutUint32(keyBytes[4:8], r.SrcIP)
	binary.BigEndian.PutUint16(keyBytes[8:10], r.DstPort)
	binary.BigEndian.PutUint16(keyBytes[10:12], r.SrcPort)
	keyBytes[12] = r.NextHdr
	keyBytes[13] = r.Flags
	return keyBytes
}

// connTrackKeyFromBytes is the EXACT inverse of ToCtKey: it decodes the 14
// packed bytes of a kernel `ipv4_ct_tuple` map key back into a connTrackKey.
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
		return connTrackKey{}, fmt.Errorf("conntrack key length %d, want %d (packed ipv4_ct_tuple)", len(buf), connTrackKeySize)
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

func (r *portListKey) ToPlKey() []byte {
	keyBytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(keyBytes[0:4], r.SrcIP)
	binary.LittleEndian.PutUint16(keyBytes[4:6], r.DstPortStart)
	binary.LittleEndian.PutUint16(keyBytes[6:8], r.DstPortEnd)
	return keyBytes
}

func (r *portListKey) ToPlValue(ttlSec uint64) whitelistValue {
	now, _ := getBootTimeNanos()
	return whitelistValue{
		Allowed:    1,
		ExpireTime: now + ttlSec*1_000_000_000,
	}
}

func (r *srcIPdstPortKey) ToSpKey() []byte {
	keyBytes := make([]byte, 6)
	binary.LittleEndian.PutUint32(keyBytes[0:4], r.SrcIP)
	binary.LittleEndian.PutUint16(keyBytes[4:6], r.DstPort)
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

// A generic entry function that calls the corresponding function to add whitelist entries based on mapTypeandparams.
func EbpfRuleAdd(mapType int, params EbpfRuleParams, TtlSec int) error {
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

// Parse the port
func parsePort(portStr string) (uint16, error) {
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16([]byte{byte(port >> 8), byte(port & 0xFF)}), nil
}
