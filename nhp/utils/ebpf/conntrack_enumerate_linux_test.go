//go:build linux

package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
)

// This file is the P4e-slice-5 surgical-ENUMERATION proof at the eBPF map-op
// layer, the mirror of conntrack_delete_linux_test.go's delete proof.
//
// Three layers, escalating in what they require of the host:
//
//   - TestConnTrackKey_RoundTrip: the LOAD-BEARING reverse-parse fence. P4c's
//     golden-bytes test pins ToCtKey (fields→bytes); this pins
//     connTrackKeyFromBytes (bytes→fields) as its exact inverse. The
//     enumeration path recovers each flow's SOURCE PORT — the surgical
//     discriminator — by decoding the raw iterator key bytes through this
//     function; a wrong offset here silently decodes the wrong source port, the
//     enumeration filters the target OUT, and the "surgical" revoke degrades to
//     the coarse over-flush this slice exists to remove. Runs on any host (no
//     kernel, no privilege).
//
//   - TestEnumerateConnTrackSrcPorts_Surgical: the SEMANTIC proof against a REAL
//     in-kernel conntrack-shaped map. Two sibling flows share the allow-rule
//     tuple {src,dst,dport,proto} but differ in source port (NAT'd clients
//     behind one IP); a third flow on a DIFFERENT tuple and a fourth in the
//     wrong CT direction are also present. Enumerate by the allow-rule tuple →
//     assert BOTH siblings' source ports are returned and the non-matching
//     entries are excluded. Then surgically delete ONE sibling and re-enumerate:
//     the target is gone, the other survives — the whole point of the slice.
//     Skips gracefully on hosts that can't create BPF maps unless
//     NHP_REQUIRE_BPF_TESTS=1 (P4c's loud-skip guard via newTestConnTrackMap).
//
// DEEPEST PROOF GAP (cannot be closed here): that deleting an enumerated
// conntrack entry actually drops the next REAL packet through the attached XDP
// program while the sibling keeps passing requires a live kernel + traffic. Map-
// op tests prove enumeration recovers exactly the right source ports and the
// delete targets one flow; they do NOT exercise the XDP datapath short-circuit.
// That end-to-end teardown is the #2779 kernel-rig responsibility.

// TestConnTrackKey_RoundTrip pins connTrackKeyFromBytes as the exact inverse of
// ToCtKey for a representative v4 5-tuple. If either function's byte offsets
// drift, the round trip fails here rather than the enumeration silently
// returning garbage source ports at runtime. Runs unconditionally.
func TestConnTrackKey_RoundTrip(t *testing.T) {
	src, err := parseIP("198.51.100.7")
	if err != nil {
		t.Fatalf("parseIP(src): %v", err)
	}
	dst, err := parseIP("203.0.113.10")
	if err != nil {
		t.Fatalf("parseIP(dst): %v", err)
	}
	want := connTrackKey{
		DstIP:   dst,
		SrcIP:   src,
		DstPort: 443,
		SrcPort: 43210, // the surgical discriminator
		NextHdr: 6,     // TCP
		Flags:   ctDirIngress,
	}
	got, err := connTrackKeyFromBytes(want.ToCtKey())
	if err != nil {
		t.Fatalf("connTrackKeyFromBytes(ToCtKey): unexpected err %v", err)
	}
	if got != want {
		t.Errorf("round trip mismatch:\n got  %+v\n want %+v\n(connTrackKeyFromBytes is not the exact inverse of ToCtKey — enumeration would decode the wrong source port)", got, want)
	}

	// A short/long buffer must fail loud, not decode out-of-bounds garbage.
	if _, err := connTrackKeyFromBytes(make([]byte, connTrackKeySize-1)); err == nil {
		t.Error("connTrackKeyFromBytes(short buf) = nil err, want error (a truncated key must fail loud)")
	}
	if _, err := connTrackKeyFromBytes(make([]byte, connTrackKeySize+1)); err == nil {
		t.Error("connTrackKeyFromBytes(long buf) = nil err, want error")
	}
}

// TestEnumerateConnTrackSrcPorts_Surgical is the semantic proof: enumeration
// recovers EXACTLY the source ports of the entries on a given allow-rule tuple
// (both NAT'd siblings), excludes entries on other tuples and in the wrong CT
// direction, and after a surgical delete of one sibling the OTHER still
// enumerates — no over-flush.
func TestEnumerateConnTrackSrcPorts_Surgical(t *testing.T) {
	m, ok := newTestConnTrackMap(t)
	if !ok {
		return // skipped inside helper (loud when NHP_REQUIRE_BPF_TESTS=1)
	}
	defer func() { _ = m.Close() }()

	const (
		srcStr     = "198.51.100.7" // shared client IP (one NAT)
		dstStr     = "203.0.113.10" // shared resource
		proto      = uint8(6)       // TCP
		dport      = uint16(443)    // shared destination port
		targetPort = uint16(43210)  // admission A
		siblingPrt = uint16(43211)  // admission B — same allow-rule tuple
		otherPort  = uint16(43212)  // a flow on a DIFFERENT tuple (other dport)
		otherDport = uint16(8443)   // distinct destination port
		egressPort = uint16(43213)  // a flow in the WRONG CT direction
	)
	src, _ := parseIP(srcStr)
	dst, _ := parseIP(dstStr)
	zeroVal := make([]byte, ctValueSize)

	put := func(k *connTrackKey) {
		t.Helper()
		if err := m.Put(k.ToCtKey(), zeroVal); err != nil {
			t.Fatalf("put %+v: %v", k, err)
		}
	}
	// Two siblings on the target allow-rule tuple, distinct source ports.
	put(&connTrackKey{DstIP: dst, SrcIP: src, DstPort: dport, SrcPort: targetPort, NextHdr: proto, Flags: ctDirIngress})
	put(&connTrackKey{DstIP: dst, SrcIP: src, DstPort: dport, SrcPort: siblingPrt, NextHdr: proto, Flags: ctDirIngress})
	// A flow on a DIFFERENT destination port — must be excluded by the filter.
	put(&connTrackKey{DstIP: dst, SrcIP: src, DstPort: otherDport, SrcPort: otherPort, NextHdr: proto, Flags: ctDirIngress})
	// A flow with the same tuple but the WRONG CT direction (flags=1) — must be
	// excluded (we only delete the ingress orientation; see connTrackKey godoc).
	put(&connTrackKey{DstIP: dst, SrcIP: src, DstPort: dport, SrcPort: egressPort, NextHdr: proto, Flags: ctDirIngress + 1})

	// Enumerate by the allow-rule tuple.
	sports, err := enumerateConnTrackSrcPortsOnMap(m, srcStr, dstStr, proto, dport)
	if err != nil {
		t.Fatalf("enumerateConnTrackSrcPortsOnMap: %v", err)
	}
	got := portSet(sports)
	// Both siblings present.
	if !got[targetPort] {
		t.Errorf("enumerate missing target source port %d; got %v — a wrong key parse drops the target and degrades surgical→coarse", targetPort, sports)
	}
	if !got[siblingPrt] {
		t.Errorf("enumerate missing sibling source port %d; got %v", siblingPrt, sports)
	}
	// Non-matching entries excluded.
	if got[otherPort] {
		t.Errorf("enumerate returned source port %d from a DIFFERENT destination-port tuple; filter leaked: %v", otherPort, sports)
	}
	if got[egressPort] {
		t.Errorf("enumerate returned source port %d from the WRONG CT direction; direction filter leaked: %v", egressPort, sports)
	}
	if len(sports) != 2 {
		t.Errorf("enumerate returned %d source ports, want exactly 2 (the two ingress siblings on the tuple): %v", len(sports), sports)
	}

	// Surgically delete EXACTLY the target's 5-tuple via the production delete
	// path, then re-enumerate.
	if err := delEbpfConnTrackOnMap(m, srcStr, dstStr, proto, targetPort, dport); err != nil {
		t.Fatalf("delEbpfConnTrackOnMap(target): %v", err)
	}
	after, err := enumerateConnTrackSrcPortsOnMap(m, srcStr, dstStr, proto, dport)
	if err != nil {
		t.Fatalf("enumerate after delete: %v", err)
	}
	afterSet := portSet(after)
	// Target gone (non-vacuous: it was present above).
	if afterSet[targetPort] {
		t.Errorf("post-delete: target source port %d still enumerated — delete was a no-op: %v", targetPort, after)
	}
	// Sibling SURVIVES — the whole point of surgical revoke.
	if !afterSet[siblingPrt] {
		t.Errorf("post-delete: sibling source port %d no longer enumerated — surgical delete OVER-FLUSHED a same-tuple sibling: %v", siblingPrt, after)
	}
	if len(after) != 1 {
		t.Errorf("post-delete: enumerate returned %d source ports, want exactly 1 (the surviving sibling): %v", len(after), after)
	}
}

// TestEnumerateConnTrackSrcPorts_NoMatchEmpty proves a tuple with no conntrack
// entries enumerates to an empty (non-error) result — the caller reads this as
// "no established flows to surgically kill" (e.g. only quiet/new pinholes), NOT
// as an error.
func TestEnumerateConnTrackSrcPorts_NoMatchEmpty(t *testing.T) {
	m, ok := newTestConnTrackMap(t)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()

	sports, err := enumerateConnTrackSrcPortsOnMap(m, "198.51.100.7", "203.0.113.10", 6, 443)
	if err != nil {
		t.Fatalf("enumerate empty map: %v", err)
	}
	if len(sports) != 0 {
		t.Errorf("enumerate of empty map returned %v, want empty", sports)
	}
}

func portSet(ports []uint16) map[uint16]bool {
	s := make(map[uint16]bool, len(ports))
	for _, p := range ports {
		s[p] = true
	}
	return s
}

// compile-time anchor: enumerateConnTrackSrcPortsOnMap takes a *ebpf.Map, the
// same injectable shape as delEbpfConnTrackOnMap, so the real-map proofs above
// exercise the exact production iterator/parse without a /sys/fs/bpf pin.
var _ = func(m *ebpf.Map) ([]uint16, error) {
	return enumerateConnTrackSrcPortsOnMap(m, "", "", 0, 0)
}
