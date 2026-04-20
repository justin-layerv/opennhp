package test

import (
	"testing"

	"github.com/OpenNHP/opennhp/nhp/core"
)

// FuzzECDHFromKey tests ECDH key creation with random inputs.
// This is important for security as malformed keys should be handled gracefully.
func FuzzECDHFromKey(f *testing.F) {
	// Seed corpus with valid key sizes for Curve25519
	f.Add([]byte{})
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		// ECDHFromKey should not panic on any input
		// It should return an error for invalid keys
		e, err := core.ECDHFromKey(core.ECC_CURVE25519, data)
		if err != nil {
			return
		}
		// If key was accepted, verify basic operations don't panic
		_ = e.PublicKey()
		_ = e.PublicKeyBase64()
	})
}

// FuzzHeaderTypeToDeviceType fuzzes the header type to device type mapping
// and the corresponding string lookup. Asserts HeaderTypeToString never
// returns "" — empty would be a regression of the out-of-range fallback
// and would silently corrupt any caller that logs header type names.
func FuzzHeaderTypeToDeviceType(f *testing.F) {
	f.Add(-1)
	f.Add(0)
	f.Add(core.NHP_KNK)
	f.Add(core.NHP_AOP)
	f.Add(core.NHP_ARD) // table high-end — update this seed when adding a new NHP header type
	f.Add(99)
	f.Add(1 << 16)

	f.Fuzz(func(t *testing.T, headerType int) {
		_ = core.HeaderTypeToDeviceType(headerType)
		s := core.HeaderTypeToString(headerType)
		if s == "" {
			t.Fatalf("HeaderTypeToString(%d) returned empty string; expected \"UNKNOWN\" or a known type label", headerType)
		}
	})
}
