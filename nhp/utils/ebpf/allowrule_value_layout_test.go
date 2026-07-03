package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestAllowRuleValueLayouts(t *testing.T) {
	if got := unsafe.Sizeof(whitelistValue{}); got != 16 {
		t.Fatalf("whitelistValue size = %d, want 16", got)
	}
	if got := unsafe.Offsetof(whitelistValue{}.ExpireTime); got != 8 {
		t.Fatalf("whitelistValue ExpireTime offset = %d, want 8", got)
	}
}

// TestProtocolPortValueBytes pins the packed 9-byte wire layout of the
// protocol_port map value. Unlike its 16-byte aligned siblings, `struct
// protocol_port_value` in nhp_ebpf_xdp.c is __attribute__((packed)) = 9 bytes,
// so the value MUST be emitted as explicit bytes (a Go struct's raw POD image
// is 16 bytes and cilium/ebpf rejects the Map.Update against the 9-byte map —
// the bug that left protocol_port silently unpopulated). byte 0 = allowed(1);
// bytes 1..8 = expire_time, native-endian to match the packed struct on the
// little-endian XDP hosts.
func TestProtocolPortValueBytes(t *testing.T) {
	const expireTime = uint64(0x0102030405060708)
	want := make([]byte, 9)
	want[0] = 1
	binary.NativeEndian.PutUint64(want[1:], expireTime)

	got := ppValueBytes(expireTime)
	if len(got) != 9 {
		t.Fatalf("protocol_port value = %d bytes, want 9 (packed C struct)", len(got))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ppValueBytes = % x, want % x", got, want)
	}
}

func TestAllowRuleValueGoldenBytes(t *testing.T) {
	// Map.Update receives these pointer-free value structs by address, so this
	// userspace proxy pins the raw host-endian POD memory image rather than a
	// kernel map round-trip. Supported XDP hosts are little-endian, matching
	// the boot-enumeration expire_time decoder.
	const expireTime = uint64(0x0102030405060708)
	want := []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.NativeEndian.PutUint64(want[8:], expireTime)

	whitelist := whitelistValue{Allowed: 1, ExpireTime: expireTime}
	if got := rawStructBytes(unsafe.Pointer(&whitelist), unsafe.Sizeof(whitelist)); !bytes.Equal(got, want) {
		t.Fatalf("whitelistValue bytes = % x, want % x", got, want)
	}
}

func rawStructBytes(ptr unsafe.Pointer, size uintptr) []byte {
	return append([]byte(nil), unsafe.Slice((*byte)(ptr), int(size))...)
}
