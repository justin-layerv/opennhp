//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/cilium/ebpf"
)

// ErrConnTrackMapNotPinned is returned by EnumerateConnTrackSrcPorts when the
// conn_track pin path does not exist on the filesystem — the expected case
// when the XDP program isn't attached (feature inert), distinct from a real
// load error (permission denied, schema mismatch) which the caller must fail
// loud on. The revocation wiring (endpoints/ac) errors.Is for this sentinel to
// decide "fall back to coarse allow-rule flush" rather than treat XDP-not-
// attached as a hard failure. Mirrors endpoints/ac's errBpfMapNotPinned
// discipline for the allow-rule enumeration path.
var ErrConnTrackMapNotPinned = errors.New("conn_track bpf map not pinned")

// connTrackValueSizeMax is the maximum kernel conn_value struct size we will
// accept for the conn_track map. The iterator's value buffer must be exactly
// the map's ValueSize, which we read from the loaded map at runtime; this
// constant only fences a sane upper bound so a wildly-wrong map pinned at the
// path (whose ValueSize would force a huge per-iteration allocation) fails
// loud instead. The real kernel conn_value ({u64,u64,u64,u8,u8,u32,u32}) is
// ~40 bytes; 256 is generous headroom for struct growth without inviting a
// pathological allocation.
const connTrackValueSizeMax = 256

// EnumerateConnTrackSrcPorts walks the pinned established-flow conntrack map
// (PinPathConnTrack) and returns the per-flow SOURCE PORTS of every entry
// matching the given allow-rule tuple {srcIP, dstIP, protocol, dstPort} in the
// CT_DIR_INGRESS direction.
//
// This is the missing P4e-slice-5 primitive: P4c gave us DelEbpfConnTrackEntry
// (delete ONE flow by full 5-tuple) and the AC's FlushConn, but nothing could
// RECOVER the source ports those need — the allow-rule FlowKey carries only
// {src,dst,dport,proto}. Two concurrent admissions behind one NAT to the same
// resource collapse to a single allow-rule entry but have DISTINCT conntrack
// entries keyed on their distinct source ports. Enumerating the source ports
// here lets the revocation path FlushConn exactly the revoked admission's flow
// and leave a same-allow-tuple sibling (different source port) alive — surgical
// revocation, not the coarse over-flush of rescheduling the shared allow-rule.
//
// IPv4 only: the conntrack map key is `struct ipv4_ct_tuple` (__be32 addrs),
// so this enumerates v4 flows only. The caller (endpoints/ac) must NOT call
// this for IPv6 admissions — there is no v6 conntrack entry to enumerate, and
// an empty result for v6 means "no surgical path", not "no live flows". See the
// IPv6 hard-fail handling in revocation_index.go (#2778).
//
// protocol is the IANA L4 number (6=TCP, 17=UDP). Only TCP/UDP create conntrack
// entries in the XDP program (the established-flow short-circuit is port-keyed);
// ICMP and "any" allow-rules have no conntrack entry, so this returns an empty
// slice for them (the caller skips surgical teardown for those — coarse
// allow-rule teardown suffices).
//
// Returns ErrConnTrackMapNotPinned (wrapped) when the pin path is absent so the
// caller can fall back to the coarse path; any other load/iterate error is
// returned as-is for the caller to fail loud on. A nil error with an empty
// slice means the map was walked and no entry matched the tuple.
func EnumerateConnTrackSrcPorts(srcIPStr, dstIPStr string, protocol uint8, dstPort uint16) ([]uint16, error) {
	m, err := ebpf.LoadPinnedMap(PinPathConnTrack, nil)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// %w wraps the sentinel so callers can errors.Is; the underlying
			// fs.ErrNotExist text is folded in via %s for diagnostic context
			// (errorlint flags %v on an error, so render the already-formatted
			// text with %s). Mirrors enumerateBpfMap's sentinel handling.
			return nil, fmt.Errorf("%w: %s: %s", ErrConnTrackMapNotPinned, PinPathConnTrack, err.Error())
		}
		return nil, fmt.Errorf("load pinned conn_track: %w", err)
	}
	defer func() { _ = m.Close() }()
	return enumerateConnTrackSrcPortsOnMap(m, srcIPStr, dstIPStr, protocol, dstPort)
}

// enumerateConnTrackSrcPortsOnMap is the map-handle-injectable core of
// EnumerateConnTrackSrcPorts: it iterates the supplied conntrack-shaped map,
// decodes each key via connTrackKeyFromBytes (the exact inverse of ToCtKey),
// and collects the SOURCE PORTS of entries whose {daddr,saddr,dport,nexthdr}
// match the target allow-rule tuple in the CT_DIR_INGRESS direction. Splitting
// the pinned-map open out lets the surgical-enumeration behavior be tested
// against a real in-test ebpf.Map of the conntrack shape (no /sys/fs/bpf pin
// required) — proving that two sibling flows sharing an allow-rule tuple but
// differing in source port are BOTH enumerated with their correct ports.
//
// The match filter is the inverse of how the entries were inserted: the
// allow-rule tuple is {srcIP→dstIP:dstPort/proto}; in the conntrack key that is
// saddr=srcIP, daddr=dstIP, dport=dstPort, nexthdr=proto. sport is the free
// dimension we are recovering, so it is NOT part of the filter. flags must be
// CT_DIR_INGRESS — the only orientation the XDP program inserts and the only one
// a delete targets (see connTrackKey godoc / DelEbpfConnTrackEntry).
func enumerateConnTrackSrcPortsOnMap(m *ebpf.Map, srcIPStr, dstIPStr string, protocol uint8, dstPort uint16) ([]uint16, error) {
	srcIP, err := parseIP(srcIPStr)
	if err != nil {
		return nil, err
	}
	dstIP, err := parseIP(dstIPStr)
	if err != nil {
		return nil, err
	}

	// Validate the loaded map's key dimension against the packed conntrack key
	// size. A kernel struct-layout change (or the wrong map pinned at this path)
	// would otherwise let the iterator yield key bytes that
	// connTrackKeyFromBytes mis-decodes into bogus source ports — fail loud
	// rather than enumerate garbage. The value size is read (not asserted to a
	// fixed const, since the kernel conn_value layout is owned by the XDP
	// program and not mirrored in this package) but bounded so a wrong map
	// can't force a pathological per-iteration allocation.
	info, err := m.Info()
	if err != nil {
		return nil, fmt.Errorf("conn_track map info: %w", err)
	}
	if int(info.KeySize) != connTrackKeySize {
		return nil, fmt.Errorf("conn_track map key size %d, want %d (ipv4_ct_tuple: %d field bytes + %d trailing pad) — wrong map pinned at %s?", info.KeySize, connTrackKeySize, connTrackKeyDataLen, connTrackKeySize-connTrackKeyDataLen, PinPathConnTrack)
	}
	if info.ValueSize == 0 || int(info.ValueSize) > connTrackValueSizeMax {
		return nil, fmt.Errorf("conn_track map value size %d out of range (1..%d) — wrong map pinned at %s?", info.ValueSize, connTrackValueSizeMax, PinPathConnTrack)
	}

	keyBytes := make([]byte, connTrackKeySize)
	valBytes := make([]byte, info.ValueSize) // value is discarded; only the key carries the 5-tuple
	var sports []uint16

	iter := m.Iterate()
	for iter.Next(&keyBytes, &valBytes) {
		key, derr := connTrackKeyFromBytes(keyBytes)
		if derr != nil {
			// A decode error here means a key of unexpected length came back
			// from a map we already size-validated — treat as a hard error
			// rather than skip, so a kernel/layout regression is loud.
			return nil, fmt.Errorf("decode conn_track key: %w", derr)
		}
		if key.Flags != ctDirIngress {
			continue
		}
		if key.SrcIP == srcIP && key.DstIP == dstIP && key.DstPort == dstPort && key.NextHdr == protocol {
			sports = append(sports, key.SrcPort)
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate conn_track: %w", err)
	}
	return sports, nil
}
