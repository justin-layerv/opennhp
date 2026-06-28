package ebpf

import "testing"

// This file holds the cross-platform (no kernel, no build tag) E2-slice-5 IPv6
// enumeration fences: the connTrackKeyV6FromBytes round trip. The real-map
// semantic proof lives in conntrack_enumerate_v6_linux_test.go (linux-tagged).
// Keeping the round trip untagged means `go test -run V6` exercises the
// load-bearing decode on a developer's darwin machine, where the kernel-map
// tests skip.

// TestConnTrackKeyV6_RoundTrip pins connTrackKeyV6FromBytes as the EXACT inverse
// of ToCtKeyV6 for a representative v6 5-tuple. The v6 enumeration path recovers
// each flow's SOURCE PORT — the surgical discriminator — by decoding the raw
// iterator key bytes through this function; a wrong offset here silently decodes
// the wrong source port, enumeration filters the target OUT, and the "surgical"
// v6 revoke degrades to a coarse over-flush. Runs unconditionally.
func TestConnTrackKeyV6_RoundTrip(t *testing.T) {
	src, err := parseIP6("2001:db8::7")
	if err != nil {
		t.Fatalf("parseIP6(src): %v", err)
	}
	dst, err := parseIP6("2001:db8::10")
	if err != nil {
		t.Fatalf("parseIP6(dst): %v", err)
	}
	want := connTrackKeyV6{
		DstIP:   dst,
		SrcIP:   src,
		DstPort: 443,
		SrcPort: 43210, // the surgical discriminator
		NextHdr: 6,     // TCP
		Flags:   ctDirIngress,
	}
	got, err := connTrackKeyV6FromBytes(want.ToCtKeyV6())
	if err != nil {
		t.Fatalf("connTrackKeyV6FromBytes(ToCtKeyV6): unexpected err %v", err)
	}
	if got != want {
		t.Errorf("round trip mismatch:\n got  %+v\n want %+v\n(connTrackKeyV6FromBytes is not the exact inverse of ToCtKeyV6 — enumeration would decode the wrong source port)", got, want)
	}

	// A short/long buffer must fail loud, not decode out-of-bounds garbage.
	if _, err := connTrackKeyV6FromBytes(make([]byte, connTrackKeyV6Size-1)); err == nil {
		t.Error("connTrackKeyV6FromBytes(short buf) = nil err, want error (a truncated key must fail loud)")
	}
	if _, err := connTrackKeyV6FromBytes(make([]byte, connTrackKeyV6Size+1)); err == nil {
		t.Error("connTrackKeyV6FromBytes(long buf) = nil err, want error")
	}
}
