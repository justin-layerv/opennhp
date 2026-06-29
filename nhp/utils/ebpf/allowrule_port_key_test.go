package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestWhitelistKeyToWlKeyGoldenBytes(t *testing.T) {
	srcIP := mustParseIP(t, "198.51.100.7")
	dstIP := mustParseIP(t, "203.0.113.9")

	got := (&whitelistKey{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		DstPort:  443,
		Protocol: 6,
	}).ToWlKey()
	want := []byte{198, 51, 100, 7, 203, 0, 113, 9, 0x01, 0xbb, 0x06}
	if !bytes.Equal(got, want) {
		t.Fatalf("ToWlKey() = % x, want % x", got, want)
	}

	if port := binary.BigEndian.Uint16(got[8:10]); port != 443 {
		t.Fatalf("dst_port bytes = % x, big-endian decode = %d, want 443", got[8:10], port)
	}
	if got[10] != 6 {
		t.Fatalf("protocol byte = %d, want 6", got[10])
	}
}

func TestSrcIPDstPortKeyToSpKeyGoldenBytes(t *testing.T) {
	srcIP := mustParseIP(t, "198.51.100.7")

	got := (&srcIPdstPortKey{SrcIP: srcIP, DstPort: 443}).ToSpKey()
	want := []byte{198, 51, 100, 7, 0x01, 0xbb}
	if !bytes.Equal(got, want) {
		t.Fatalf("ToSpKey() = % x, want % x", got, want)
	}

	if port := binary.BigEndian.Uint16(got[4:6]); port != 443 {
		t.Fatalf("dst_port bytes = % x, big-endian decode = %d, want 443", got[4:6], port)
	}
}

func TestSrcDestKeyToSdKeyGoldenBytes(t *testing.T) {
	srcIP := mustParseIP(t, "198.51.100.7")
	dstIP := mustParseIP(t, "203.0.113.9")

	got := (&srcDestKey{SrcIP: srcIP, DstIP: dstIP}).ToSdKey()
	want := []byte{198, 51, 100, 7, 203, 0, 113, 9}
	if !bytes.Equal(got, want) {
		t.Fatalf("ToSdKey() = % x, want % x", got, want)
	}
}

func TestPortListKeyToPlKeyGoldenBytes(t *testing.T) {
	srcIP := mustParseIP(t, "198.51.100.7")

	// This locks the userspace ABI only; issue #2843 tracks the current XDP
	// full-range lookup that prevents port ranges, including 1..65535, from
	// matching.
	got := (&portListKey{
		SrcIP:   srcIP,
		MinPort: 8000,
		MaxPort: 9000,
	}).ToPlKey()
	want := []byte{198, 51, 100, 7, 0x1f, 0x40, 0x23, 0x28}
	if !bytes.Equal(got, want) {
		t.Fatalf("ToPlKey() = % x, want % x", got, want)
	}

	if port := binary.BigEndian.Uint16(got[4:6]); port != 8000 {
		t.Fatalf("min_port bytes = % x, big-endian decode = %d, want 8000", got[4:6], port)
	}
	if port := binary.BigEndian.Uint16(got[6:8]); port != 9000 {
		t.Fatalf("max_port bytes = % x, big-endian decode = %d, want 9000", got[6:8], port)
	}
}

func TestProtocolPortKeyToPpKeyGoldenBytes(t *testing.T) {
	got := (&protocolPortKey{DstPort: 443, Protocol: 6}).ToPpKey()
	want := []byte{0x01, 0xbb, 0x06}
	if !bytes.Equal(got, want) {
		t.Fatalf("ToPpKey() = % x, want % x", got, want)
	}

	if port := binary.BigEndian.Uint16(got[0:2]); port != 443 {
		t.Fatalf("dst_port bytes = % x, big-endian decode = %d, want 443", got[0:2], port)
	}
	if got[2] != 6 {
		t.Fatalf("protocol byte = %d, want 6", got[2])
	}
}

func mustParseIP(t *testing.T, s string) uint32 {
	t.Helper()
	ip, err := parseIP(s)
	if err != nil {
		t.Fatalf("parseIP(%q): %v", s, err)
	}
	return ip
}
