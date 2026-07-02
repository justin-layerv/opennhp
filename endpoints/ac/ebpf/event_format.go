// Package ebpf — event decode + log-line formatting shared by the IPv4 and
// IPv6 perf-event readers.
//
// This file is intentionally build-tag-free (compiles on every platform) so the
// pure decode/format logic can be unit-tested with `go test` on macOS — the
// kernel-touching reader lives in ebpfegine.go behind //go:build linux, and the
// macOS-excludes-linux-files gotcha would otherwise silently skip any test
// placed there. The reader calls into these helpers; the tests exercise the
// SAME functions the reader uses, so an offset/byte-order bug cannot pass the
// test while shipping broken.
package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
)

// lostPerfSamples is the cumulative count of perf-buffer samples the kernel
// dropped (ring-buffer overflow) across BOTH the v4 and v6 readers. The kernel
// reports a per-read LostSamples count when its per-CPU ring fills before
// userspace drains it; we accumulate it here as the no-silent-loss safety net.
//
// The #2849 malformed-DENY limiter should keep this flat by bounding the
// attacker-controllable early-DENY surface before the ring overflows. A non-zero,
// growing value means filter-decision telemetry still escaped userspace and must
// page via MetricEbpfPerfLostSamples, not just a WARN log.
var lostPerfSamples atomic.Uint64

// recordLostSamples adds n to the cumulative lost-sample counter. Safe for
// concurrent use by the v4 and v6 reader goroutines.
func recordLostSamples(n uint64) {
	lostPerfSamples.Add(n)
}

// LostPerfSamples returns the cumulative number of perf-buffer samples dropped
// by the kernel across both readers since process start. This accessor stays in
// the build-tag-free file so untagged AC metric code compiles on non-Linux
// targets, where no reader runs and the counter remains zero.
func LostPerfSamples() uint64 {
	return lostPerfSamples.Load()
}

// --- DENY telemetry rate-limiter (#2849) userspace support ---
//
// The in-kernel side (nhp/ebpf/xdp/nhp_ebpf_xdp.c) gates ONLY the malformed/
// early-drop DENY submit_event sites behind a per-CPU token bucket; the no-match
// (unauthorized-access) DENY and all ACCEPT emissions stay unrate-limited. These
// helpers are the userspace half: the config the AC writes at load, and the
// suppressed-count it surfaces. Build-tag-free so the config layout + the
// per-CPU summing are unit-tested on any platform (the macOS-excludes-linux-files
// gotcha would otherwise skip a test placed in ebpfegine.go).

// DenyRlConfig mirrors `struct deny_rl_config_t` in nhp_ebpf_xdp.c (two __u64
// fields). The AC writes one shared copy (key 0) into the regular ARRAY
// `deny_rl_config`; the per-CPU datapath reads it on every malformed-DENY
// decision. Capacity == 0 disables the limiter (fail-open to always-emit) — the
// zero value before the AC writes, so a load that skips the write keeps today's
// behavior. cilium/ebpf marshals this native-endian, matching the kernel struct
// on the same host.
type DenyRlConfig struct {
	Capacity     uint64
	RefillPerSec uint64
}

// Default per-CPU DENY-telemetry rate-limit applied at eBPF load (#2849): up to
// DefaultDenyRlCapacity tokens of burst, refilled at DefaultDenyRlRefillPerSec
// tokens/sec, so a sustained malformed-packet flood is capped at ~refill
// events/sec/CPU while an incident's first packets still log. Conservative
// starting point; tunable at the E5 FilterMode flip with a single deny_rl_config
// map write and NO object regen (the cap lives in a map, not a #define — eases
// #2823). INERT until the flip (EbpfEngineLoad runs only under FilterMode=EBPFXDP).
const (
	DefaultDenyRlCapacity     uint64 = 1000
	DefaultDenyRlRefillPerSec uint64 = 1000
)

// suppressedDenyEvents holds the latest cumulative count of malformed/early-drop
// DENY events the in-kernel token bucket SHED, summed across CPUs by the monitor
// goroutine. Distinct from lostPerfSamples (unintended perf-ring overflow): a
// growing value here is the limiter working as designed under a flood. Exported
// via SuppressedDenyEvents for metric wiring + tests.
var suppressedDenyEvents atomic.Uint64

// recordSuppressedDeny stores the latest cumulative suppressed-DENY total. The
// in-kernel counter is itself cumulative (a per-CPU += that is never reset), so
// the monitor reads + sums it and stores the snapshot here — a Store, not an Add
// (contrast recordLostSamples, which accumulates per-read deltas).
func recordSuppressedDeny(total uint64) {
	suppressedDenyEvents.Store(total)
}

// SuppressedDenyEvents returns the latest cumulative count of DENY telemetry
// events shed by the rate limiter across all CPUs since process start. This
// accessor stays build-tag-free for the same reason as LostPerfSamples.
func SuppressedDenyEvents() uint64 {
	return suppressedDenyEvents.Load()
}

// sumPerCPUCounter sums the per-CPU values a PERCPU_ARRAY Lookup returns (one
// entry per possible CPU). Build-tag-free so the summing is unit-tested without a
// kernel.
func sumPerCPUCounter(perCPU []uint64) uint64 {
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total
}

// EventV4 mirrors `struct event_t` in nhp/ebpf/xdp/nhp_ebpf_xdp.c EXACTLY (same
// field order, packed, 24 bytes). It is the decode target of the IPv4 perf-event
// reader: addresses are host-order uint32 (the wire __be32 decoded BigEndian →
// host order, matching uint32ToIPv4). binary.Size(EventV4{}) must equal 24 — the
// C↔Go contract guard fenced by TestEventV4_BinarySize.
//
// NOTE: like EventV6, the `ebpf:"..."` tags are documentation of the C field
// names; the live decode path is offset-based (decodeEventV4) because the layout
// mixes native-endian (timestamp) and network-endian (addresses/ports/len)
// fields, which a single binary.Read byteorder cannot handle. The C field is
// named `len`; the Go field is `Len` (the v6 twin uses the same name) so the two
// decoders are symmetric.
type EventV4 struct {
	Timestamp uint64 `ebpf:"timestamp"`
	Action    uint8  `ebpf:"action"`
	SrcIP     uint32 `ebpf:"src_ip"`
	DstIP     uint32 `ebpf:"dst_ip"`
	SrcPort   uint16 `ebpf:"src_port"`
	DstPort   uint16 `ebpf:"dst_port"`
	Protocol  uint8  `ebpf:"protocol"`
	Len       uint16 `ebpf:"len"`
}

// EventV4Size is the exact wire size of a v4 perf-event record (packed).
// Layout: timestamp 8, action 1, src 4, dst 4, sport 2, dport 2, proto 1,
// len 2 => 24 bytes total. Mirrors `struct event_t` in nhp_ebpf_xdp.c.
const EventV4Size = 24

// Byte offsets of each field within a packed event_t record. These mirror the C
// struct layout field-for-field and are the single source of truth for the
// offset-based decode (decodeEventV4) — replacing the previously-inlined literal
// indices in the v4 reader so the v4 and v6 decoders share one shape.
const (
	ev4OffTimestamp = 0  // __u64  (native/little-endian)
	ev4OffAction    = 8  // __u8
	ev4OffSrcIP     = 9  // __be32 (network order)
	ev4OffDstIP     = 13 // __be32 (network order)
	ev4OffSrcPort   = 17 // __be16 (network order)
	ev4OffDstPort   = 19 // __be16 (network order)
	ev4OffProtocol  = 21 // __u8
	ev4OffLen       = 22 // __be16 (network order)
)

// decodeEventV4 parses a raw 24-byte perf sample into an EventV4, field by field,
// honoring the mixed endianness of the C struct (timestamp native/LE; addresses,
// ports and len network order / BE). It is the v4 counterpart of decodeEventV6:
// it returns an error (rather than panicking on a short slice) so a malformed/
// truncated sample is a loud, handled condition in the reader loop. This closes
// the latent index-out-of-range panic the old `len == 0`-only guard left open
// for 1–23-byte samples; fenced by TestDecodeEventV4_ShortSample.
func decodeEventV4(raw []byte) (EventV4, error) {
	var ev EventV4
	if len(raw) < EventV4Size {
		return ev, fmt.Errorf("v4 perf sample too short: got %d bytes, want >= %d", len(raw), EventV4Size)
	}
	ev.Timestamp = binary.LittleEndian.Uint64(raw[ev4OffTimestamp : ev4OffTimestamp+8])
	ev.Action = raw[ev4OffAction]
	ev.SrcIP = binary.BigEndian.Uint32(raw[ev4OffSrcIP : ev4OffSrcIP+4])
	ev.DstIP = binary.BigEndian.Uint32(raw[ev4OffDstIP : ev4OffDstIP+4])
	ev.SrcPort = binary.BigEndian.Uint16(raw[ev4OffSrcPort : ev4OffSrcPort+2])
	ev.DstPort = binary.BigEndian.Uint16(raw[ev4OffDstPort : ev4OffDstPort+2])
	ev.Protocol = raw[ev4OffProtocol]
	ev.Len = binary.BigEndian.Uint16(raw[ev4OffLen : ev4OffLen+2])
	return ev, nil
}

// EventV6 mirrors `struct event_t_v6` in nhp/ebpf/xdp/nhp_ebpf_xdp.c EXACTLY
// (same field order, packed, 48 bytes). It is the IPv6 counterpart of EventV4:
// addresses are 16-byte arrays (the wire bytes from ip6h->saddr/daddr, already
// network byte order). binary.Size(EventV6{}) must equal 48 — the C↔Go contract
// guard fenced by TestEventV6_BinarySize and the C `_Static_assert`.
//
// NOTE: like the v4 EventV4 struct, the `ebpf:"..."` tags are documentation of
// the C field names; the live decode path is offset-based (decodeEventV6) because
// the layout mixes native-endian (timestamp) and network-endian (ports/len)
// fields, which a single binary.Read byteorder cannot handle.
type EventV6 struct {
	Timestamp uint64   `ebpf:"timestamp"`
	Action    uint8    `ebpf:"action"`
	SrcIP     [16]byte `ebpf:"src_ip"`
	DstIP     [16]byte `ebpf:"dst_ip"`
	SrcPort   uint16   `ebpf:"src_port"`
	DstPort   uint16   `ebpf:"dst_port"`
	Protocol  uint8    `ebpf:"protocol"`
	Len       uint16   `ebpf:"len"`
}

// EventV6Size is the exact wire size of a v6 perf-event record (packed).
// Layout: timestamp 8, action 1, src 16, dst 16, sport 2, dport 2, proto 1,
// len 2 => 48 bytes total. Mirrors the C _Static_assert(sizeof==48).
const EventV6Size = 48

// Byte offsets of each field within a packed event_t_v6 record. These mirror the
// C struct layout field-for-field and are the single source of truth for the
// offset-based decode (decodeEventV6) and the byte-order unit test.
const (
	ev6OffTimestamp = 0  // __u64  (native/little-endian)
	ev6OffAction    = 8  // __u8
	ev6OffSrcIP     = 9  // struct in6_addr (16 bytes, network order)
	ev6OffDstIP     = 25 // struct in6_addr (16 bytes, network order)
	ev6OffSrcPort   = 41 // __be16 (network order)
	ev6OffDstPort   = 43 // __be16 (network order)
	ev6OffProtocol  = 45 // __u8
	ev6OffLen       = 46 // __be16 (network order)
)

// decodeEventV6 parses a raw 48-byte perf sample into an EventV6, field by
// field, honoring the mixed endianness of the C struct:
//   - timestamp: native-endian (bpf_ktime_get_ns writes host order; the eBPF
//     datapath only runs on little-endian platforms in this project, matching
//     the v4 reader's LittleEndian timestamp decode).
//   - src/dst IP: raw 16-byte copy (struct in6_addr is already network order on
//     the wire — no swap; a byte copy is byte-order-agnostic).
//   - ports/len: network order (__be16) → BigEndian, matching the v4 reader.
//
// It returns an error (rather than panicking on a short slice) so a malformed/
// truncated sample is a loud, handled condition in the reader loop.
func decodeEventV6(raw []byte) (EventV6, error) {
	var ev EventV6
	if len(raw) < EventV6Size {
		return ev, fmt.Errorf("v6 perf sample too short: got %d bytes, want >= %d", len(raw), EventV6Size)
	}
	ev.Timestamp = binary.LittleEndian.Uint64(raw[ev6OffTimestamp : ev6OffTimestamp+8])
	ev.Action = raw[ev6OffAction]
	copy(ev.SrcIP[:], raw[ev6OffSrcIP:ev6OffSrcIP+16])
	copy(ev.DstIP[:], raw[ev6OffDstIP:ev6OffDstIP+16])
	ev.SrcPort = binary.BigEndian.Uint16(raw[ev6OffSrcPort : ev6OffSrcPort+2])
	ev.DstPort = binary.BigEndian.Uint16(raw[ev6OffDstPort : ev6OffDstPort+2])
	ev.Protocol = raw[ev6OffProtocol]
	ev.Len = binary.BigEndian.Uint16(raw[ev6OffLen : ev6OffLen+2])
	return ev, nil
}

// ipv6BytesToString renders a 16-byte network-order IPv6 address as its
// canonical text form (e.g. "2001:db8::7"). The bytes are the on-wire order, so
// net.IP(b[:]) consumes them directly with NO byte swap — the address bytes are
// the same in memory and on the wire. net.IP.String() applies RFC 5952
// compression (lowercase, "::" run). A 16-byte input is always treated as IPv6
// by net.IP (To16 is identity), so an IPv4-mapped prefix would print in mixed
// form — not a concern here since these only ever carry real v6 addresses.
func ipv6BytesToString(b [16]byte) string {
	ip := make(net.IP, 16)
	copy(ip, b[:])
	return ip.String()
}

// actionString maps the event action byte to the log token used in the
// [NHP-<ACTION>] field. Shared by the v4 and v6 formatters so both families
// render identical action tokens (0=DENY, 1=ACCEPT). The IPv6 iptables LOG rules
// use [NHP-ACCEPT6]/[NHP-DENY6]; the eBPF reader deliberately does NOT append
// the "6" — the existing CloudWatch ingestion + dashboards key on the
// SRC/DST/LEN/PROTO/SPT/DPT FIELDS, not the action suffix, and v4/v6 events land
// in the same nhp_accept-*.log / nhp_deny-*.log streams.
func actionString(action uint8) string {
	switch action {
	case 0:
		return "DENY"
	case 1:
		return "ACCEPT"
	default:
		return "UNKNOWN"
	}
}

// uint32ToIPv4 renders a host-order uint32 IPv4 address as dotted-quad. The v4
// reader decodes ip bytes with BigEndian.Uint32 (network → host order), so the
// most-significant byte is the first octet. Shared with the v4 reader; lives
// here (build-tag-free) so the format test can exercise the production path.
func uint32ToIPv4(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xff,
		(ip>>16)&0xff,
		(ip>>8)&0xff,
		ip&0xff)
}

// protoToString maps an IP protocol number to its short name for the PROTO=
// field. Shared by the v4 and v6 readers (so both families render identical
// protocol tokens) and exercised directly by the cross-platform format test.
// Unknown protocols (including IPPROTO_ICMPV6 = 58, which has no dedicated case)
// render as "PROTO-<n>".
func protoToString(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 41:
		return "IPv6"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 88:
		return "EIGRP"
	case 89:
		return "OSPF"
	case 112:
		return "VRRP"
	default:
		return fmt.Sprintf("PROTO-%d", proto)
	}
}

// formatEventLine renders the shared filter-event log line in the EXACT format
// the v4 reader has always emitted (and that CloudWatch ingestion + dashboards
// parse):
//
//	HH:MM:SS <acId> [NHP-<ACTION>] SRC=<src> DST=<dst> LEN=<len> PROTO=<proto> SPT=<sport> DPT=<dport>
//
// Both the v4 and v6 readers call this with their already-stringified addresses,
// so a v6 line is identical to a v4 line except the SRC=/DST= values are IPv6
// text. timeStr is the formatted event time ("15:04:05"); protoStr is the
// protocol name (protoToString). Keeping this in one function guarantees the two
// families never drift in field order/spacing.
func formatEventLine(timeStr, acID, action, src, dst string, length int, protoStr string, sport, dport uint16) string {
	return fmt.Sprintf("%s %s [NHP-%s] SRC=%s DST=%s LEN=%d PROTO=%s SPT=%d DPT=%d",
		timeStr,
		acID,
		action,
		src,
		dst,
		length,
		protoStr,
		sport,
		dport,
	)
}
