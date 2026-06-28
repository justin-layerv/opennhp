//go:build linux

package ebpf

import "testing"

// This file is the E2-slice-5 IPv6 surgical-ENUMERATION proof against a REAL
// in-kernel conn_track_v6-shaped map — the v6 twin of
// conntrack_enumerate_linux_test.go's semantic proof. The round-trip fence is in
// conntrack_enumerate_v6_test.go (untagged). It reuses newTestConnTrackMapV6 and
// portSet from the sibling _test files in this package.

// TestEnumerateConnTrackSrcPortsV6_Surgical is the v6 semantic proof: enumeration
// recovers EXACTLY the source ports of the entries on a given v6 allow-rule tuple
// (both NAT'd siblings), excludes entries on other tuples and in the wrong CT
// direction, and after a surgical delete of one sibling the OTHER still
// enumerates — no over-flush.
func TestEnumerateConnTrackSrcPortsV6_Surgical(t *testing.T) {
	m, ok := newTestConnTrackMapV6(t)
	if !ok {
		return // skipped inside helper (loud when NHP_REQUIRE_BPF_TESTS=1)
	}
	defer func() { _ = m.Close() }()

	const (
		srcStr     = "2001:db8::7"  // shared client (one NAT)
		dstStr     = "2001:db8::10" // shared resource
		proto      = uint8(6)       // TCP
		dport      = uint16(443)    // shared destination port
		targetPort = uint16(43210)  // admission A
		siblingPrt = uint16(43211)  // admission B — same allow-rule tuple
		otherPort  = uint16(43212)  // a flow on a DIFFERENT tuple (other dport)
		otherDport = uint16(8443)   // distinct destination port
		egressPort = uint16(43213)  // a flow in the WRONG CT direction
	)
	src, err := parseIP6(srcStr)
	if err != nil {
		t.Fatalf("parseIP6(src): %v", err)
	}
	dst, err := parseIP6(dstStr)
	if err != nil {
		t.Fatalf("parseIP6(dst): %v", err)
	}
	zeroVal := make([]byte, ctValueSize)

	put := func(k *connTrackKeyV6) {
		t.Helper()
		if err := m.Put(k.ToCtKeyV6(), zeroVal); err != nil {
			t.Fatalf("put %+v: %v", k, err)
		}
	}
	// Two siblings on the target allow-rule tuple, distinct source ports.
	put(&connTrackKeyV6{DstIP: dst, SrcIP: src, DstPort: dport, SrcPort: targetPort, NextHdr: proto, Flags: ctDirIngress})
	put(&connTrackKeyV6{DstIP: dst, SrcIP: src, DstPort: dport, SrcPort: siblingPrt, NextHdr: proto, Flags: ctDirIngress})
	// A flow on a DIFFERENT destination port — must be excluded by the filter.
	put(&connTrackKeyV6{DstIP: dst, SrcIP: src, DstPort: otherDport, SrcPort: otherPort, NextHdr: proto, Flags: ctDirIngress})
	// Same tuple, WRONG CT direction (flags != ingress) — must be excluded.
	put(&connTrackKeyV6{DstIP: dst, SrcIP: src, DstPort: dport, SrcPort: egressPort, NextHdr: proto, Flags: ctDirIngress + 1})

	sports, err := enumerateConnTrackSrcPortsOnMapV6(m, srcStr, dstStr, proto, dport)
	if err != nil {
		t.Fatalf("enumerateConnTrackSrcPortsOnMapV6: %v", err)
	}
	got := portSet(sports)
	if !got[targetPort] {
		t.Errorf("enumerate missing target source port %d; got %v — a wrong key parse drops the target and degrades surgical→hard-fail", targetPort, sports)
	}
	if !got[siblingPrt] {
		t.Errorf("enumerate missing sibling source port %d; got %v", siblingPrt, sports)
	}
	if got[otherPort] {
		t.Errorf("enumerate returned source port %d from a DIFFERENT destination-port tuple; filter leaked: %v", otherPort, sports)
	}
	if got[egressPort] {
		t.Errorf("enumerate returned source port %d from the WRONG CT direction; direction filter leaked: %v", egressPort, sports)
	}
	if len(sports) != 2 {
		t.Errorf("enumerate returned %d source ports, want exactly 2 (the two ingress siblings on the tuple): %v", len(sports), sports)
	}

	// Surgically delete EXACTLY the target's 5-tuple, then re-enumerate.
	if err := delEbpfConnTrackOnMapV6(m, srcStr, dstStr, proto, targetPort, dport); err != nil {
		t.Fatalf("delEbpfConnTrackOnMapV6(target): %v", err)
	}
	after, err := enumerateConnTrackSrcPortsOnMapV6(m, srcStr, dstStr, proto, dport)
	if err != nil {
		t.Fatalf("enumerate after delete: %v", err)
	}
	afterSet := portSet(after)
	if afterSet[targetPort] {
		t.Errorf("post-delete: target source port %d still enumerated — delete was a no-op: %v", targetPort, after)
	}
	if !afterSet[siblingPrt] {
		t.Errorf("post-delete: sibling source port %d no longer enumerated — surgical delete OVER-FLUSHED a same-tuple sibling: %v", siblingPrt, after)
	}
	if len(after) != 1 {
		t.Errorf("post-delete: enumerate returned %d source ports, want exactly 1 (the surviving sibling): %v", len(after), after)
	}
}

// TestEnumerateConnTrackSrcPortsV6_NoMatchEmpty proves a v6 tuple with no
// conntrack entries enumerates to an empty (non-error) result — the caller reads
// this as "no established v6 flows to surgically kill", NOT as an error.
func TestEnumerateConnTrackSrcPortsV6_NoMatchEmpty(t *testing.T) {
	m, ok := newTestConnTrackMapV6(t)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()

	sports, err := enumerateConnTrackSrcPortsOnMapV6(m, "2001:db8::7", "2001:db8::10", 6, 443)
	if err != nil {
		t.Fatalf("enumerate empty v6 map: %v", err)
	}
	if len(sports) != 0 {
		t.Errorf("enumerate of empty v6 map returned %v, want empty", sports)
	}
}
