package test

import (
	"strings"
	"testing"

	core "github.com/OpenNHP/opennhp/nhp/core"
)

// TestNewHashInvalidType verifies that NewHash returns an error for invalid hash types.
func TestNewHashInvalidType(t *testing.T) {
	invalidType := core.HashTypeEnum(999)
	_, err := core.NewHash(invalidType)
	if err == nil {
		t.Error("Expected error for invalid hash type, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported hash type") {
		t.Errorf("Error message should mention 'unsupported hash type', got: %v", err)
	}
}

// TestNewHashValidTypes verifies that NewHash succeeds for all valid hash types.
func TestNewHashValidTypes(t *testing.T) {
	tests := []struct {
		name     string
		hashType core.HashTypeEnum
	}{
		{"BLAKE2S", core.HASH_BLAKE2S},
		{"SHA256", core.HASH_SHA256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := core.NewHash(tt.hashType)
			if err != nil {
				t.Errorf("NewHash(%s) returned unexpected error: %v", tt.name, err)
			}
			if h == nil {
				t.Errorf("NewHash(%s) returned nil hash", tt.name)
			}
		})
	}
}

// TestAeadFromKeyInvalidType verifies that AeadFromKey returns an error for invalid GCM types.
func TestAeadFromKeyInvalidType(t *testing.T) {
	key := [core.SymmetricKeySize]byte{}
	invalidType := core.GcmTypeEnum(999)
	_, err := core.AeadFromKey(invalidType, &key)
	if err == nil {
		t.Error("Expected error for invalid GCM type, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported GCM type") {
		t.Errorf("Error message should mention 'unsupported GCM type', got: %v", err)
	}
}

// TestAeadFromKeyValidTypes verifies that AeadFromKey succeeds for all valid GCM types.
func TestAeadFromKeyValidTypes(t *testing.T) {
	key := [core.SymmetricKeySize]byte{}
	// Fill with some non-zero data for a valid key
	for i := range key {
		key[i] = byte(i)
	}

	tests := []struct {
		name    string
		gcmType core.GcmTypeEnum
	}{
		{"AES256-GCM", core.GCM_AES256},
		{"ChaCha20-Poly1305", core.GCM_CHACHA20POLY1305},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aead, err := core.AeadFromKey(tt.gcmType, &key)
			if err != nil {
				t.Errorf("AeadFromKey(%s) returned unexpected error: %v", tt.name, err)
			}
			if aead == nil {
				t.Errorf("AeadFromKey(%s) returned nil AEAD", tt.name)
			}
		})
	}
}

// TestCBCEncryptionInvalidType verifies that CBCEncryption returns an error for invalid cipher types.
func TestCBCEncryptionInvalidType(t *testing.T) {
	key := [core.SymmetricKeySize]byte{}
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("test plaintext for encryption")
	invalidType := core.GcmTypeEnum(999)

	_, err := core.CBCEncryption(invalidType, &key, plaintext, false)
	if err == nil {
		t.Error("Expected error for invalid cipher type, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported cipher type") {
		t.Errorf("Error message should mention 'unsupported cipher type', got: %v", err)
	}
}

// TestCBCDecryptionInvalidType verifies that CBCDecryption returns an error for invalid cipher types.
func TestCBCDecryptionInvalidType(t *testing.T) {
	key := [core.SymmetricKeySize]byte{}
	for i := range key {
		key[i] = byte(i)
	}
	// Need at least one block of ciphertext
	ciphertext := make([]byte, 32)
	invalidType := core.GcmTypeEnum(999)

	_, err := core.CBCDecryption(invalidType, &key, ciphertext, false)
	if err == nil {
		t.Error("Expected error for invalid cipher type, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported cipher type") {
		t.Errorf("Error message should mention 'unsupported cipher type', got: %v", err)
	}
}

// TestCBCEncryptionChaChaNotApplicable verifies that CBCEncryption returns ErrNotApplicable for ChaCha20.
func TestCBCEncryptionChaChaNotApplicable(t *testing.T) {
	key := [core.SymmetricKeySize]byte{}
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("test plaintext")

	_, err := core.CBCEncryption(core.GCM_CHACHA20POLY1305, &key, plaintext, false)
	if err == nil {
		t.Error("Expected ErrNotApplicable for ChaCha20 CBC encryption, got nil")
	}
	if err != core.ErrNotApplicable {
		t.Errorf("Expected ErrNotApplicable, got: %v", err)
	}
}

// TestCBCDecryptionChaChaNotApplicable verifies that CBCDecryption returns ErrNotApplicable for ChaCha20.
func TestCBCDecryptionChaChaNotApplicable(t *testing.T) {
	key := [core.SymmetricKeySize]byte{}
	for i := range key {
		key[i] = byte(i)
	}
	ciphertext := make([]byte, 32)

	_, err := core.CBCDecryption(core.GCM_CHACHA20POLY1305, &key, ciphertext, false)
	if err == nil {
		t.Error("Expected ErrNotApplicable for ChaCha20 CBC decryption, got nil")
	}
	if err != core.ErrNotApplicable {
		t.Errorf("Expected ErrNotApplicable, got: %v", err)
	}
}
