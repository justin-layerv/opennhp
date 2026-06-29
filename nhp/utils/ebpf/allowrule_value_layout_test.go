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

	if got := unsafe.Sizeof(protocolPortValue{}); got != 16 {
		t.Fatalf("protocolPortValue size = %d, want 16", got)
	}
	if got := unsafe.Offsetof(protocolPortValue{}.ExpireTime); got != 8 {
		t.Fatalf("protocolPortValue ExpireTime offset = %d, want 8", got)
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

	protocolPort := protocolPortValue{Allowed: 1, ExpireTime: expireTime}
	if got := rawStructBytes(unsafe.Pointer(&protocolPort), unsafe.Sizeof(protocolPort)); !bytes.Equal(got, want) {
		t.Fatalf("protocolPortValue bytes = % x, want % x", got, want)
	}
}

func rawStructBytes(ptr unsafe.Pointer, size uintptr) []byte {
	return append([]byte(nil), unsafe.Slice((*byte)(ptr), int(size))...)
}
