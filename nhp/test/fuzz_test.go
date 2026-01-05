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
		// It should return nil for invalid keys
		e := core.ECDHFromKey(core.ECC_CURVE25519, data)
		if e != nil {
			// If key was accepted, verify basic operations don't panic
			_ = e.PublicKey()
			_ = e.PublicKeyBase64()
		}
	})
}

// FuzzAESDecrypt tests AES decryption with random inputs.
// Ensures malformed ciphertext is handled without panics.
func FuzzAESDecrypt(f *testing.F) {
	// Seed corpus with various sizes
	f.Add(make([]byte, 16), make([]byte, 32)) // minimum block size
	f.Add(make([]byte, 32), make([]byte, 32)) // two blocks
	f.Add(make([]byte, 48), make([]byte, 32)) // three blocks
	f.Add([]byte{}, make([]byte, 32))         // empty ciphertext

	f.Fuzz(func(t *testing.T, ciphertext []byte, key []byte) {
		// Normalize key to 32 bytes (AES-256)
		if len(key) < 32 {
			paddedKey := make([]byte, 32)
			copy(paddedKey, key)
			key = paddedKey
		} else if len(key) > 32 {
			key = key[:32]
		}

		// AESDecrypt should not panic on any input
		_, _ = core.AESDecrypt(ciphertext, key)
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
