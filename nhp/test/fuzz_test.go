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

// FuzzHeaderTypeToDeviceType tests header type to device type mapping.
func FuzzHeaderTypeToDeviceType(f *testing.F) {
	// Seed with known valid types
	f.Add(0)  // NHP_KPL
	f.Add(1)  // NHP_KNK
	f.Add(10) // NHP_AOL
	f.Add(100)
	f.Add(-1)
	f.Add(1000000)

	f.Fuzz(func(t *testing.T, headerType int) {
		// Should not panic on any input
		_ = core.HeaderTypeToDeviceType(headerType)
		_ = core.HeaderTypeToString(headerType)
	})
}
