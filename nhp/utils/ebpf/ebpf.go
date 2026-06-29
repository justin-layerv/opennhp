package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// Key serializers preserve the byte order used by XDP lookups. IPv4 octets
// stay in network order because parseIP decodes them into uint32 values with
// LittleEndian and the serializers re-encode them the same way. Ports are
// written big-endian to match raw packet __be16 fields.
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
	SrcIP   uint32 `ebpf:"src_ip"`
	MinPort uint16 `ebpf:"min_port"`
	MaxPort uint16 `ebpf:"max_port"`
}

type srcIPdstPortKey struct {
	SrcIP   uint32 `ebpf:"src_ip"`
	DstPort uint16 `ebpf:"dst_port"`
}

type protocolPortKey struct {
	DstPort  uint16 `ebpf:"dst_port"`
	Protocol uint8  `ebpf:"protocol"`
}

type whitelistValue struct {
	Allowed    uint8
	_          [7]byte
	ExpireTime uint64
}

type protocolPortValue struct {
	Allowed    uint8
	_          [7]byte
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

// Pinned-map filesystem paths. Single source of truth for both the
// producer side (Add* functions in this file) and the consumer side
// (boot enumeration in endpoints/ac/expiry_enumerate_ebpf_linux.go).
// A future XDP loader change to a different pin path becomes a
// compile error rather than a silent boot-enumeration miss
const (
	PinPathWhitelist     = "/sys/fs/bpf/spp"           // TCP/UDP per-port allow-rules (whitelistKey)
	PinPathSdWhitelist   = "/sys/fs/bpf/sdwhitelist"   // any-proto src+dst allow-rules (srcDestKey)
	PinPathIcmpWhitelist = "/sys/fs/bpf/icmpwhitelist" // ICMP allow-rules (srcDestKey)
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

// Mirrors struct whitelist_key in ebpf/xdp/nhp_ebpf_xdp.c.
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

// Mirrors struct sdwhitelist_key and struct icmpwhitelist_key in
// ebpf/xdp/nhp_ebpf_xdp.c.
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

// Mirrors struct protocol_port_key in ebpf/xdp/nhp_ebpf_xdp.c.
func (r *protocolPortKey) ToPpKey() []byte {
	keyBytes := make([]byte, 3)
	binary.BigEndian.PutUint16(keyBytes[0:2], r.DstPort)
	keyBytes[2] = r.Protocol
	return keyBytes
}

func (r *protocolPortKey) ToPpValue(ttlSec uint64) protocolPortValue {
	now, _ := getBootTimeNanos()
	return protocolPortValue{
		Allowed:    1,
		ExpireTime: now + ttlSec*1_000_000_000,
	}
}

// Mirrors struct port_list_key in ebpf/xdp/nhp_ebpf_xdp.c.
func (r *portListKey) ToPlKey() []byte {
	keyBytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(keyBytes[0:4], r.SrcIP)
	binary.BigEndian.PutUint16(keyBytes[4:6], r.MinPort)
	binary.BigEndian.PutUint16(keyBytes[6:8], r.MaxPort)
	return keyBytes
}

func (r *portListKey) ToPlValue(ttlSec uint64) whitelistValue {
	now, _ := getBootTimeNanos()
	return whitelistValue{
		Allowed:    1,
		ExpireTime: now + ttlSec*1_000_000_000,
	}
}

// Mirrors struct src_port_list_key in ebpf/xdp/nhp_ebpf_xdp.c.
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
func AddProtocolPortWhitelistRule(whitelistMap *ebpf.Map, rule *protocolPortKey, ttlSec uint64) error {
	keyBytes := rule.ToPpKey()
	value := rule.ToPpValue(ttlSec)

	if err := whitelistMap.Update(keyBytes, &value, ebpf.UpdateAny); err != nil {
		log.Error("failed to update protocol_port map: %v", err)
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
		SrcIP: srcIP,
		// portListKey mirrors XDP's min_port/max_port field names; the
		// rule API keeps the start/end wording callers already use.
		MinPort: portStart,
		MaxPort: portEnd,
	}

	return AddSdPortlistRule(portListMap, rule, ttlSec)
}

// function for update protocol dstport map
func AddEbpfRuleForProtocolPort(protocol uint8, dstPort uint16, ttlSec uint64) error {
	protocolPortMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/protocol_port", nil)
	if err != nil {
		log.Error("failed to load pinned protocol_port map: %v", err)
		return err
	}
	defer func() { _ = protocolPortMap.Close() }()

	rule := &protocolPortKey{
		DstPort:  dstPort,
		Protocol: protocol,
	}

	return AddProtocolPortWhitelistRule(protocolPortMap, rule, ttlSec)
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
