// Cross-platform (build-tag-free) unit tests for the eBPF event decode + log
// formatting. These run with plain `go test` on macOS AND Linux because
// event_format.go carries no //go:build linux tag — deliberately, so the
// macOS-excludes-linux-files gotcha cannot silently skip the C↔Go contract
// guard. They exercise the SAME decodeEventV6 / ipv6BytesToString /
// formatEventLine functions the production reader calls, so an offset or
// byte-order bug fails here rather than shipping.
package ebpf

import (
	"encoding/binary"
	"testing"
)

// TestEventV4_BinarySize is the Go-side C↔Go contract guard for the v4 perf
// event: EventV4 must be exactly 24 bytes, matching `struct event_t` (packed) in
// nhp_ebpf_xdp.c. The .c carries no `_Static_assert` on event_t (the .c/.o are
// the in-kernel datapath proof and are off-limits in this PR), so this one-sided
// Go guard is the canary for any v4 field add/reorder/type-change that would make
// the offset decode read the wrong bytes.
func TestEventV4_BinarySize(t *testing.T) {
	got := binary.Size(EventV4{})
	if got != 24 {
		t.Fatalf("binary.Size(EventV4{}) = %d, want 24 — the Go EventV4 struct drifted from the C struct event_t (24 bytes, packed, in nhp_ebpf_xdp.c). Reconcile both before trusting the offset decode", got)
	}
	if EventV4Size != 24 {
		t.Fatalf("EventV4Size const = %d, want 24", EventV4Size)
	}
}

// buildRawV4 hand-assembles a 24-byte event_t wire record from explicit field
// values at the documented offsets with the SAME byte-order the kernel uses (LE
// timestamp, BE __be32 addresses, BE ports/len). Independent of decodeEventV4 (no
// shared helper) so TestDecodeEventV4_ByteOrder is a genuine cross-check, not a
// tautology against the code under test.
func buildRawV4(timestamp uint64, action uint8, src, dst uint32, sport, dport uint16, proto uint8, length uint16) []byte {
	raw := make([]byte, 24)
	binary.LittleEndian.PutUint64(raw[0:8], timestamp)
	raw[8] = action
	binary.BigEndian.PutUint32(raw[9:13], src)
	binary.BigEndian.PutUint32(raw[13:17], dst)
	binary.BigEndian.PutUint16(raw[17:19], sport)
	binary.BigEndian.PutUint16(raw[19:21], dport)
	raw[21] = proto
	binary.BigEndian.PutUint16(raw[22:24], length)
	return raw
}

// TestDecodeEventV4_ByteOrder feeds a known wire record through the PRODUCTION
// decodeEventV4 and asserts every field decodes to the expected value (mixed
// endianness: LE timestamp, BE addresses/ports/len). The values are
// non-palindromic so a wrong offset or a spurious byte-swap is observable. It
// also asserts the rendered SRC=/DST= dotted-quads, since uint32ToIPv4 is the
// production address formatter for the v4 log line.
func TestDecodeEventV4_ByteOrder(t *testing.T) {
	const (
		ts     uint64 = 987654321
		action uint8  = 1
		src    uint32 = 0xC0A80101 // 192.168.1.1
		dst    uint32 = 0x08080404 // 8.8.4.4
		sport  uint16 = 0x01BB     // 443, non-palindromic so a BE/LE swap is visible
		dport  uint16 = 0x0035     // 53
		proto  uint8  = 6          // TCP
		length uint16 = 1480
	)
	raw := buildRawV4(ts, action, src, dst, sport, dport, proto, length)

	ev, err := decodeEventV4(raw)
	if err != nil {
		t.Fatalf("decodeEventV4: unexpected error: %v", err)
	}
	if ev.Timestamp != ts {
		t.Errorf("Timestamp = %d, want %d", ev.Timestamp, ts)
	}
	if ev.Action != action {
		t.Errorf("Action = %d, want %d", ev.Action, action)
	}
	if ev.SrcIP != src {
		t.Errorf("SrcIP = 0x%08x, want 0x%08x", ev.SrcIP, src)
	}
	if ev.DstIP != dst {
		t.Errorf("DstIP = 0x%08x, want 0x%08x", ev.DstIP, dst)
	}
	if ev.SrcPort != sport {
		t.Errorf("SrcPort = %d (0x%04x), want %d — wrong byte-order? __be16 must decode BigEndian", ev.SrcPort, ev.SrcPort, sport)
	}
	if ev.DstPort != dport {
		t.Errorf("DstPort = %d, want %d", ev.DstPort, dport)
	}
	if ev.Protocol != proto {
		t.Errorf("Protocol = %d, want %d", ev.Protocol, proto)
	}
	if ev.Len != length {
		t.Errorf("Len = %d, want %d", ev.Len, length)
	}

	if got, want := uint32ToIPv4(ev.SrcIP), "192.168.1.1"; got != want {
		t.Errorf("uint32ToIPv4(SrcIP) = %q, want %q (a byte-swap or wrong offset would corrupt this)", got, want)
	}
	if got, want := uint32ToIPv4(ev.DstIP), "8.8.4.4"; got != want {
		t.Errorf("uint32ToIPv4(DstIP) = %q, want %q", got, want)
	}
}

// TestDecodeEventV4_ShortSample asserts a truncated or empty v4 sample is a
// handled error, not a panic — mirroring TestDecodeEventV6_ShortSample. This is
// the guard the old `len == 0`-only check in the v4 reader was missing (a
// 1–23-byte sample indexed up to RawSample[22:24] would have panicked); the
// reader now routes through decodeEventV4, so the loop logs + continues.
func TestDecodeEventV4_ShortSample(t *testing.T) {
	for _, n := range []int{0, 1, 8, 17, 23} {
		if _, err := decodeEventV4(make([]byte, n)); err == nil {
			t.Errorf("decodeEventV4(%d bytes) = nil error, want a 'too short' error (a short sample must not be silently parsed or panic)", n)
		}
	}
	if _, err := decodeEventV4(nil); err == nil {
		t.Fatal("decodeEventV4(nil) = nil error, want a 'too short' error")
	}
}

// TestEventV6_BinarySize is the C↔Go contract guard: EventV6 must be exactly 48
// bytes, matching `_Static_assert(sizeof(struct event_t_v6) == 48)` in
// nhp_ebpf_xdp.c. binary.Size returns -1 if any field is not fixed-size — using
// [16]byte (not net.IP) keeps it computable. If this drifts, the offset-based
// decode below would read the wrong bytes, so this is the canary for any field
// add/reorder/type-change on either side.
func TestEventV6_BinarySize(t *testing.T) {
	got := binary.Size(EventV6{})
	if got != 48 {
		t.Fatalf("binary.Size(EventV6{}) = %d, want 48 — the Go EventV6 struct drifted from the C struct event_t_v6 (48 bytes, _Static_assert in nhp_ebpf_xdp.c). Reconcile both before trusting the offset decode", got)
	}
	if EventV6Size != 48 {
		t.Fatalf("EventV6Size const = %d, want 48", EventV6Size)
	}
}

// buildRawV6 hand-assembles a 48-byte event_t_v6 wire record from explicit
// field values, writing each field at its documented offset with the SAME
// byte-order the kernel uses (LE timestamp, raw 16-byte addresses, BE ports/len).
// It is independent of decodeEventV6 (no shared helper) so the round-trip test
// is a genuine cross-check, not a tautology against the code under test.
func buildRawV6(timestamp uint64, action uint8, src, dst [16]byte, sport, dport uint16, proto uint8, length uint16) []byte {
	raw := make([]byte, 48)
	binary.LittleEndian.PutUint64(raw[0:8], timestamp)
	raw[8] = action
	copy(raw[9:25], src[:])
	copy(raw[25:41], dst[:])
	binary.BigEndian.PutUint16(raw[41:43], sport)
	binary.BigEndian.PutUint16(raw[43:45], dport)
	raw[45] = proto
	binary.BigEndian.PutUint16(raw[46:48], length)
	return raw
}

// TestDecodeEventV6_ByteOrder feeds a known wire record through the PRODUCTION
// decodeEventV6 and asserts every field decodes to the expected value — the
// byte-order guard. The addresses are non-palindromic and chosen so a wrong
// offset or a spurious byte-swap is observable in the rendered string.
func TestDecodeEventV6_ByteOrder(t *testing.T) {
	// 2001:db8::7  = 20 01 0d b8 00..00 07  (network order, as on the wire)
	src := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x07}
	// 2001:db8::1:2 = 20 01 0d b8 00..00 01 00 02
	dst := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x02}

	const (
		ts     uint64 = 123456789
		action uint8  = 1
		sport  uint16 = 0x01BB // 443, non-palindromic so a BE/LE swap is visible
		dport  uint16 = 0x0035 // 53
		proto  uint8  = 6      // TCP
		length uint16 = 1480
	)
	raw := buildRawV6(ts, action, src, dst, sport, dport, proto, length)

	ev, err := decodeEventV6(raw)
	if err != nil {
		t.Fatalf("decodeEventV6: unexpected error: %v", err)
	}
	if ev.Timestamp != ts {
		t.Errorf("Timestamp = %d, want %d", ev.Timestamp, ts)
	}
	if ev.Action != action {
		t.Errorf("Action = %d, want %d", ev.Action, action)
	}
	if ev.SrcIP != src {
		t.Errorf("SrcIP = % x, want % x", ev.SrcIP, src)
	}
	if ev.DstIP != dst {
		t.Errorf("DstIP = % x, want % x", ev.DstIP, dst)
	}
	if ev.SrcPort != sport {
		t.Errorf("SrcPort = %d (0x%04x), want %d — wrong byte-order? __be16 must decode BigEndian", ev.SrcPort, ev.SrcPort, sport)
	}
	if ev.DstPort != dport {
		t.Errorf("DstPort = %d, want %d", ev.DstPort, dport)
	}
	if ev.Protocol != proto {
		t.Errorf("Protocol = %d, want %d", ev.Protocol, proto)
	}
	if ev.Len != length {
		t.Errorf("Len = %d, want %d", ev.Len, length)
	}

	// The address-string guard: the decoded SrcIP must render canonically.
	if got, want := ipv6BytesToString(ev.SrcIP), "2001:db8::7"; got != want {
		t.Errorf("ipv6BytesToString(SrcIP) = %q, want %q (a byte-swap or wrong offset would corrupt this)", got, want)
	}
	if got, want := ipv6BytesToString(ev.DstIP), "2001:db8::1:2"; got != want {
		t.Errorf("ipv6BytesToString(DstIP) = %q, want %q", got, want)
	}
}

// TestFormatEventLine_V6MatchesV4Format asserts a v6 event renders the EXACT
// same line shape the v4 reader emits (and that CloudWatch ingestion +
// dashboards parse) — only the SRC=/DST= values differ (IPv6 text). It runs a
// known v6 record through the production decode + format path end to end, so the
// assertion is on the literal bytes the reader would write to nhp_deny-*.log.
func TestFormatEventLine_V6MatchesV4Format(t *testing.T) {
	src := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x07}
	dst := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}
	raw := buildRawV6(0, 0 /*DENY*/, src, dst, 51000, 443, 6 /*TCP*/, 1480)

	ev, err := decodeEventV6(raw)
	if err != nil {
		t.Fatalf("decodeEventV6: %v", err)
	}

	line := formatEventLine(
		"15:04:05",
		"ac-test-01",
		actionString(ev.Action),
		ipv6BytesToString(ev.SrcIP),
		ipv6BytesToString(ev.DstIP),
		int(ev.Len),
		protoToString(ev.Protocol),
		ev.SrcPort,
		ev.DstPort,
	)

	want := "15:04:05 ac-test-01 [NHP-DENY] SRC=2001:db8::7 DST=2001:db8::10 LEN=1480 PROTO=TCP SPT=51000 DPT=443"
	if line != want {
		t.Fatalf("v6 log line mismatch:\n got: %q\nwant: %q\n(the v6 line MUST match the v4/iptables field format so CloudWatch parsing keeps working)", line, want)
	}
}

// TestActionString covers the action-token mapping shared by both families.
func TestActionString(t *testing.T) {
	cases := map[uint8]string{0: "DENY", 1: "ACCEPT", 2: "UNKNOWN", 255: "UNKNOWN"}
	for action, want := range cases {
		if got := actionString(action); got != want {
			t.Errorf("actionString(%d) = %q, want %q", action, got, want)
		}
	}
}

// TestDecodeEventV6_ShortSample asserts a truncated sample is a handled error,
// not a panic — the reader loop logs + continues rather than crashing.
func TestDecodeEventV6_ShortSample(t *testing.T) {
	if _, err := decodeEventV6(make([]byte, 47)); err == nil {
		t.Fatal("decodeEventV6(47 bytes) = nil error, want a 'too short' error (a short sample must not be silently parsed or panic)")
	}
	if _, err := decodeEventV6(nil); err == nil {
		t.Fatal("decodeEventV6(nil) = nil error, want a 'too short' error")
	}
}

// TestProtoToString_ICMPv6 documents that ICMPv6 (proto 58) — emitted by the v6
// unsupported-nexthdr and ICMPv6-truncation DENY sites — renders as "PROTO-58"
// (no dedicated case). If a future change adds an ICMPv6 case, update this and
// the log-parsing dashboards together.
func TestProtoToString_ICMPv6(t *testing.T) {
	if got, want := protoToString(58), "PROTO-58"; got != want {
		t.Errorf("protoToString(58 /*ICMPv6*/) = %q, want %q", got, want)
	}
	if got, want := protoToString(6), "TCP"; got != want {
		t.Errorf("protoToString(6) = %q, want %q", got, want)
	}
	if got, want := protoToString(17), "UDP"; got != want {
		t.Errorf("protoToString(17) = %q, want %q", got, want)
	}
}

// TestLostPerfSamplesCounter exercises the no-silent-loss counter the readers
// bump on perf-buffer overflow. Cross-platform so the counter logic is covered
// even where the kernel readers can't run.
func TestLostPerfSamplesCounter(t *testing.T) {
	start := LostPerfSamples()
	recordLostSamples(3)
	recordLostSamples(5)
	if got, want := LostPerfSamples()-start, uint64(8); got != want {
		t.Fatalf("LostPerfSamples delta = %d, want %d", got, want)
	}
}

// TestSuppressedDenyEventsCounter verifies recordSuppressedDeny STORES the latest
// cumulative snapshot rather than accumulating (contrast recordLostSamples, which
// Adds per-read deltas). The in-kernel deny_suppressed counter is itself
// cumulative, so the monitor sums it and stores the total each poll;
// SuppressedDenyEvents must reflect the most recent store exactly.
func TestSuppressedDenyEventsCounter(t *testing.T) {
	recordSuppressedDeny(42)
	if got := SuppressedDenyEvents(); got != 42 {
		t.Fatalf("after store 42: SuppressedDenyEvents() = %d, want 42", got)
	}
	// A later poll reads a higher cumulative total; the store reflects it exactly
	// (NOT 142) — proving Store, not Add.
	recordSuppressedDeny(100)
	if got := SuppressedDenyEvents(); got != 100 {
		t.Fatalf("after store 100: SuppressedDenyEvents() = %d, want 100 (Store, not Add)", got)
	}
}

// TestSumPerCPUCounter verifies the summing the monitor applies to the []uint64 a
// PERCPU_ARRAY Lookup returns (one entry per possible CPU). The deny_suppressed
// total the AC surfaces is the sum across all CPUs.
func TestSumPerCPUCounter(t *testing.T) {
	cases := []struct {
		name string
		in   []uint64
		want uint64
	}{
		{"nil", nil, 0},
		{"empty", []uint64{}, 0},
		{"single", []uint64{7}, 7},
		{"multi-cpu", []uint64{1, 2, 3, 4}, 10},
		{"some-idle-cpus", []uint64{0, 5, 0, 9}, 14},
	}
	for _, c := range cases {
		if got := sumPerCPUCounter(c.in); got != c.want {
			t.Errorf("%s: sumPerCPUCounter(%v) = %d, want %d", c.name, c.in, got, c.want)
		}
	}
}
