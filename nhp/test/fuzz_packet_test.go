package test

import (
	"bytes"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/core"
)

// FuzzHeaderTypeAndSize fuzzes the NHP wire-format header decoder at the
// earliest reachable point: HeaderTypeAndSize is called by recvPacketRoutine
// on every UDP datagram before any authentication, so a panic here is an
// unauthenticated remote DoS. The fuzz also exercises Flag() and Counter()
// once the input is long enough to safely call them.
//
// Scope: this harness builds &core.Packet{Content: data} directly. It does
// NOT exercise the pool-allocated PacketBuffer / Buf lifecycle — that's
// what TestPacketMinimalLengthPanicsAfterRelease in nhp/core fences.
//
// Note on the returned (type, size): the size is the lower 16 bits of the
// XOR-decoded preamble, so its range is [0, 65535] and routinely exceeds
// PacketBufferSize on random input. We don't assert a bound on size — the
// receiver enforces it via the totalLen check at packet.go:257 and
// recvPacketRoutine drops the packet on mismatch — and a fuzz-level
// assertion would fire constantly without indicating a real bug.
func FuzzHeaderTypeAndSize(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 7))
	f.Add(make([]byte, 8))
	f.Add(make([]byte, 24))
	f.Add(make([]byte, core.PacketBufferSize))
	f.Add(bytes.Repeat([]byte{0xFF}, 8))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Pad/truncate to [8, PacketBufferSize] so the fuzzer stays focused
		// on header logic instead of building gigabyte slices.
		if len(data) < 8 {
			data = append(data, make([]byte, 8-len(data))...)
		}
		if len(data) > core.PacketBufferSize {
			data = data[:core.PacketBufferSize]
		}
		pkt := &core.Packet{Content: data}
		_, _ = pkt.HeaderTypeAndSize()
		if len(data) >= 12 {
			_ = pkt.Flag()
		}
		if len(data) >= 24 {
			_ = pkt.Counter()
		}
	})
}
