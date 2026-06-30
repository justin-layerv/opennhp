package ac

// Portable conntrack-flow matching used by the netlink ConntrackFlusher
// backend (expiry_conntrack_flusher_netlink_linux.go).
//
// This lives in a build-tag-free file ON PURPOSE: the netlink datapath
// is Linux-only (it imports github.com/florianl/go-conntrack, which
// wraps NFNL_SUBSYS_CTNETLINK), but deciding WHICH dumped conntrack
// flows belong to an allow-rule FlowKey is pure arithmetic over the
// decoded 5-tuple. Keeping it here lets the match logic be unit-tested
// on any developer platform without a kernel rig — the same split the
// eBPF side uses with enumerateConnTrackSrcPortsOnMap.
//
// The match MUST mirror exactly the argument construction the v1 exec
// backend feeds to `conntrack -D` (see ConntrackFlusher.flushExec):
//
//	TCP  → -p tcp  [+ --dport P if P != 0]
//	UDP  → -p udp  [+ --dport P if P != 0]
//	ICMP → -p icmp (v4) / icmpv6 (v6); no port
//	Any  → no -p, no port (matches every protocol on the src→dst pair)
//
// FlowProtoAny is intentionally broad: it can match unrelated protocols
// sharing that src→dst pair, exactly like the exec backend's proto-less
// `conntrack -D -s ... -d ...`. Diverging here from the exec args would make
// the netlink backend flush a DIFFERENT set of flows than the exec backend for
// the same FlowKey — a silent behavior fork across the WithBackend toggle that
// the toggle's whole purpose (drop-in equivalence pending soak) forbids.

// ctTuple is a decoded conntrack ORIGINAL-direction 5-tuple. Source and
// destination IPs are held in the same 16-byte form FlowKey uses
// (IPv4-mapped for v4), so equality against FlowKey.SrcIP/DstIP is a
// direct array compare across both families.
type ctTuple struct {
	srcIP, dstIP [16]byte
	// srcPort is captured from the full kernel tuple for completeness and
	// debugging parity with the delete origin; matchesSpec ignores it by design
	// because FlowKey has no source-port dimension.
	srcPort uint16
	dstPort uint16
	proto   uint8
}

// conntrackMatchSpec resolves how a FlowKey filters kernel conntrack
// flows. The address family matters for ICMP only: IPv4 ICMP is IANA
// protocol 1, IPv6 ICMPv6 is protocol 58 — the exec backend's `-p icmp`
// is IPv4-only, so the v6 ICMP number is new ground the netlink backend
// covers. wantProto/filterProto encode the `-p` filter; filterPort
// encodes the `--dport` filter (TCP/UDP with a concrete port only).
func conntrackMatchSpec(key FlowKey, isV6 bool) (wantProto uint8, filterProto, filterPort bool) {
	// TCP/UDP defer to ianaL4Proto — the single source of the TCP/UDP→IANA
	// mapping (see its godoc: a divergent second copy could silently encode
	// the wrong protocol byte). Those are exactly the protocols filtered on a
	// concrete destination port. ICMP (v4=1, v6=58) and "any" are not L4-port
	// protocols, so they stay local here.
	if n, ok := key.Protocol.ianaL4Proto(); ok {
		return n, true, key.DstPort != 0
	}
	switch key.Protocol {
	case FlowProtoICMP:
		if isV6 {
			return 58, true, false // ICMPv6
		}
		return 1, true, false // ICMP
	default: // FlowProtoAny — no proto/port filter, src→dst only
		return 0, false, false
	}
}

// matchesKey reports whether this conntrack flow belongs to the allow-rule
// identified by key, in the given address family. Convenience wrapper that
// resolves the match spec then delegates to matchesSpec. The hot dump loop
// in flushNetlink resolves the (loop-invariant) spec ONCE per Flush and
// calls matchesSpec directly, to avoid recomputing it for every entry in
// the O(table) dump.
func (t ctTuple) matchesKey(key FlowKey, isV6 bool) bool {
	wantProto, filterProto, filterPort := conntrackMatchSpec(key, isV6)
	return t.matchesSpec(key, wantProto, filterProto, filterPort)
}

// matchesSpec is matchesKey with the match spec (from conntrackMatchSpec)
// pre-resolved by the caller. The source port is intentionally NOT
// compared: an allow-rule FlowKey carries no source port, and one
// allow-rule fans out to every established flow sharing {src,dst,dport,proto}
// regardless of the client's ephemeral source port (e.g. many clients
// behind one NAT). Recovering that free source-port dimension is exactly
// what enumeration returns.
func (t ctTuple) matchesSpec(key FlowKey, wantProto uint8, filterProto, filterPort bool) bool {
	if t.srcIP != key.SrcIP || t.dstIP != key.DstIP {
		return false
	}
	if filterProto && t.proto != wantProto {
		return false
	}
	if filterPort && t.dstPort != key.DstPort {
		return false
	}
	return true
}
