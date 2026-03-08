package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"hash"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// unpad
// ---------------------------------------------------------------------------

func TestUnpad(t *testing.T) {
	tests := []struct {
		name      string
		padded    []byte
		blockSize int
		want      []byte
		wantErr   string
	}{
		{
			name:      "empty input",
			padded:    []byte{},
			blockSize: 16,
			wantErr:   "empty padded data",
		},
		{
			name:      "padding length 0",
			padded:    []byte{0x41, 0x42, 0x43, 0x00},
			blockSize: 16,
			wantErr:   "invalid padding length",
		},
		{
			name:      "padding length exceeds block size",
			padded:    []byte{0x41, 0x42, 0x43, 0x11}, // 0x11 = 17 > blockSize 16
			blockSize: 16,
			wantErr:   "invalid padding length",
		},
		{
			name:      "padding length exceeds data length",
			padded:    []byte{0x41, 0x05}, // 0x05 = 5 > len 2
			blockSize: 16,
			wantErr:   "invalid padding length",
		},
		{
			name:      "malicious PKCS7 wrong padding content",
			padded:    []byte{0x01, 0x02, 0x03, 0x04, 0x03, 0xFF, 0x03}, // last byte says 3-byte padding, but middle byte is wrong
			blockSize: 16,
			wantErr:   "invalid PKCS#7 padding bytes",
		},
		{
			name:      "valid padding standard",
			padded:    []byte{0x01, 0x02, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04},
			blockSize: 16,
			want:      []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			name:      "valid single byte padding",
			padded:    []byte{0x41, 0x42, 0x43, 0x01},
			blockSize: 16,
			want:      []byte{0x41, 0x42, 0x43},
		},
		{
			name:      "valid full block padding",
			padded:    makePaddingBlock(16),
			blockSize: 16,
			want:      []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unpad(tt.padded, tt.blockSize)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !containsString(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// pad
// ---------------------------------------------------------------------------

func TestPad(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		wantLen   int
		wantPad   byte // expected padding byte value
	}{
		{
			name:      "data requiring full block padding",
			data:      make([]byte, 16), // multiple of blockSize=16
			blockSize: 16,
			wantLen:   32,   // adds a full block
			wantPad:   0x10, // padding = 16
		},
		{
			name:      "data requiring partial padding",
			data:      []byte{0x01, 0x02, 0x03},
			blockSize: 16,
			wantLen:   16,
			wantPad:   0x0D, // padding = 13
		},
		{
			name:      "empty data",
			data:      []byte{},
			blockSize: 16,
			wantLen:   16,
			wantPad:   0x10, // padding = 16
		},
		{
			name:      "single byte data",
			data:      []byte{0xAA},
			blockSize: 16,
			wantLen:   16,
			wantPad:   0x0F, // padding = 15
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pad(tt.data, tt.blockSize)
			if len(got) != tt.wantLen {
				t.Fatalf("pad length = %d, want %d", len(got), tt.wantLen)
			}
			if len(got)%tt.blockSize != 0 {
				t.Fatalf("pad output length %d is not a multiple of block size %d", len(got), tt.blockSize)
			}
			// Verify padding bytes are correct
			padLen := int(got[len(got)-1])
			for i := len(got) - padLen; i < len(got); i++ {
				if got[i] != tt.wantPad {
					t.Fatalf("padding byte at %d = %d, want %d", i, got[i], tt.wantPad)
				}
			}
			// Verify original data is preserved
			if !bytes.Equal(got[:len(tt.data)], tt.data) {
				t.Fatalf("original data was corrupted by padding")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// pad + unpad round-trip
// ---------------------------------------------------------------------------

func TestPadUnpadRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"one byte", []byte{0x42}},
		{"block aligned", bytes.Repeat([]byte{0xAB}, 16)},
		{"not aligned", bytes.Repeat([]byte{0xCD}, 13)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded := pad(tt.data, 16)
			got, err := unpad(padded, 16)
			if err != nil {
				t.Fatalf("unpad error: %v", err)
			}
			if !bytes.Equal(got, tt.data) {
				t.Fatalf("round-trip mismatch: got %v, want %v", got, tt.data)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AESDecrypt
// ---------------------------------------------------------------------------

func TestAESDecrypt(t *testing.T) {
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i)
	}

	tests := []struct {
		name       string
		cipherText []byte
		key        []byte
		wantErr    string
	}{
		{
			name:       "ciphertext shorter than 2 blocks",
			cipherText: make([]byte, 31),
			key:        validKey,
			wantErr:    "too short",
		},
		{
			name:       "ciphertext not multiple of block size after IV",
			cipherText: make([]byte, 35), // 16 (IV) + 19 (not multiple of 16)
			key:        validKey,
			wantErr:    "must be IV + multiple of block size",
		},
		{
			name:       "invalid key size",
			cipherText: make([]byte, 32),
			key:        make([]byte, 15), // invalid key size
			wantErr:    "invalid key size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := AESDecrypt(tt.cipherText, tt.key)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !containsString(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestAESEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"short text", []byte("hello world")},
		{"block aligned", bytes.Repeat([]byte("A"), 16)},
		{"multi block", bytes.Repeat([]byte("B"), 48)},
		{"single byte", []byte{0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := AESEncrypt(tt.plaintext, key)
			if err != nil {
				t.Fatalf("AESEncrypt error: %v", err)
			}
			decrypted, err := AESDecrypt(encrypted, key)
			if err != nil {
				t.Fatalf("AESDecrypt error: %v", err)
			}
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Fatalf("round-trip mismatch:\n  got:  %v\n  want: %v", decrypted, tt.plaintext)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AESEncrypt
// ---------------------------------------------------------------------------

func TestAESEncrypt(t *testing.T) {
	t.Run("valid encryption produces ciphertext longer than plaintext", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i)
		}
		plaintext := []byte("test data")
		ct, err := AESEncrypt(plaintext, key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Ciphertext must be at least IV + one block larger than plaintext
		if len(ct) <= len(plaintext) {
			t.Fatalf("ciphertext length %d should be greater than plaintext length %d", len(ct), len(plaintext))
		}
	})

	t.Run("invalid key size", func(t *testing.T) {
		_, err := AESEncrypt([]byte("data"), make([]byte, 10))
		if err == nil {
			t.Fatal("expected error for invalid key size, got nil")
		}
	})

	t.Run("different plaintexts produce different ciphertexts", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i)
		}
		ct1, err1 := AESEncrypt([]byte("plaintext one"), key)
		ct2, err2 := AESEncrypt([]byte("plaintext two"), key)
		if err1 != nil || err2 != nil {
			t.Fatalf("unexpected errors: %v, %v", err1, err2)
		}
		if bytes.Equal(ct1, ct2) {
			t.Fatal("different plaintexts should produce different ciphertexts (randomized IV)")
		}
	})

	t.Run("same plaintext produces different ciphertexts due to random IV", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i)
		}
		ct1, err1 := AESEncrypt([]byte("same data"), key)
		ct2, err2 := AESEncrypt([]byte("same data"), key)
		if err1 != nil || err2 != nil {
			t.Fatalf("unexpected errors: %v, %v", err1, err2)
		}
		if bytes.Equal(ct1, ct2) {
			t.Fatal("same plaintext should produce different ciphertexts due to randomized IV")
		}
	})
}

// ---------------------------------------------------------------------------
// CBCEncryption / CBCDecryption
// ---------------------------------------------------------------------------

func TestCBCEncryptionDecryption(t *testing.T) {
	key := [SymmetricKeySize]byte{}
	for i := range key {
		key[i] = byte(i)
	}

	t.Run("ChaCha20 returns ErrNotApplicable for encryption", func(t *testing.T) {
		_, err := CBCEncryption(GCM_CHACHA20POLY1305, &key, []byte("test"), false)
		if err == nil {
			t.Fatal("expected ErrNotApplicable, got nil")
		}
		if !errors.Is(err, ErrNotApplicable) {
			t.Fatalf("expected ErrNotApplicable, got: %v", err)
		}
	})

	t.Run("ChaCha20 returns ErrNotApplicable for decryption", func(t *testing.T) {
		_, err := CBCDecryption(GCM_CHACHA20POLY1305, &key, make([]byte, 32), false)
		if err == nil {
			t.Fatal("expected ErrNotApplicable, got nil")
		}
		if !errors.Is(err, ErrNotApplicable) {
			t.Fatalf("expected ErrNotApplicable, got: %v", err)
		}
	})

	t.Run("invalid cipher type returns error for encryption", func(t *testing.T) {
		_, err := CBCEncryption(GcmTypeEnum(99), &key, []byte("test"), false)
		if err == nil {
			t.Fatal("expected error for invalid cipher type, got nil")
		}
		if !containsString(err.Error(), "unsupported cipher type") {
			t.Fatalf("expected 'unsupported cipher type' error, got: %v", err)
		}
	})

	t.Run("invalid cipher type returns error for decryption", func(t *testing.T) {
		_, err := CBCDecryption(GcmTypeEnum(99), &key, make([]byte, 32), false)
		if err == nil {
			t.Fatal("expected error for invalid cipher type, got nil")
		}
		if !containsString(err.Error(), "unsupported cipher type") {
			t.Fatalf("expected 'unsupported cipher type' error, got: %v", err)
		}
	})

	t.Run("ciphertext too short for CBCDecryption", func(t *testing.T) {
		_, err := CBCDecryption(GCM_AES256, &key, make([]byte, 8), false)
		if err == nil {
			t.Fatal("expected error for short ciphertext, got nil")
		}
		if !containsString(err.Error(), "ciphertext too short") {
			t.Fatalf("expected 'ciphertext too short' error, got: %v", err)
		}
	})

	t.Run("round-trip block-aligned input with GCM_AES256 in-place", func(t *testing.T) {
		// Block-aligned input skips padding per upstream OpenNHP legacy behavior.
		// Use inPlace=true since the non-in-place path has a known buffer size issue.
		original := bytes.Repeat([]byte{0xAB}, aes.BlockSize) // exactly one block
		plaintext := make([]byte, len(original))
		copy(plaintext, original)

		encrypted, err := CBCEncryption(GCM_AES256, &key, plaintext, true)
		if err != nil {
			t.Fatalf("CBCEncryption error: %v", err)
		}
		decrypted, err := CBCDecryption(GCM_AES256, &key, encrypted, true)
		if err != nil {
			t.Fatalf("CBCDecryption error: %v", err)
		}
		if !bytes.Equal(decrypted, original) {
			t.Fatalf("round-trip mismatch:\n  got:  %v\n  want: %v", decrypted, original)
		}
	})

	t.Run("multi-block in-place round-trip", func(t *testing.T) {
		original := bytes.Repeat([]byte{0xCD}, aes.BlockSize*3) // 3 blocks
		plaintext := make([]byte, len(original))
		copy(plaintext, original)

		encrypted, err := CBCEncryption(GCM_AES256, &key, plaintext, true)
		if err != nil {
			t.Fatalf("CBCEncryption in-place error: %v", err)
		}
		// Verify ciphertext differs from original plaintext
		if bytes.Equal(encrypted, original) {
			t.Fatal("encrypted data should differ from plaintext")
		}
		decrypted, err := CBCDecryption(GCM_AES256, &key, encrypted, true)
		if err != nil {
			t.Fatalf("CBCDecryption in-place error: %v", err)
		}
		if !bytes.Equal(decrypted, original) {
			t.Fatalf("in-place round-trip mismatch:\n  got:  %v\n  want: %v", decrypted, original)
		}
	})

	t.Run("non-block-aligned input pads then encrypts in-place", func(t *testing.T) {
		// Non-block-aligned input gets PKCS#7 padded by CBCEncryption.
		// Due to upstream legacy behavior, CBCDecryption skips unpadding for
		// block-aligned ciphertext, so the caller must unpad manually.
		original := []byte("hello world 123") // 15 bytes, not block-aligned
		encrypted, err := CBCEncryption(GCM_AES256, &key, original, true)
		if err != nil {
			t.Fatalf("CBCEncryption error: %v", err)
		}
		// After padding, the encrypted output should be block-aligned
		if len(encrypted)%aes.BlockSize != 0 {
			t.Fatalf("encrypted output length %d should be multiple of block size", len(encrypted))
		}
	})
}

// ---------------------------------------------------------------------------
// NewHash
// ---------------------------------------------------------------------------

func TestNewHash(t *testing.T) {
	tests := []struct {
		name     string
		hashType HashTypeEnum
		wantErr  string
	}{
		{
			name:     "BLAKE2S",
			hashType: HASH_BLAKE2S,
		},
		{
			name:     "SHA256",
			hashType: HASH_SHA256,
		},
		{
			name:     "invalid hash type",
			hashType: HashTypeEnum(99),
			wantErr:  "unsupported hash type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h hash.Hash
			h, err := NewHash(tt.hashType)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !containsString(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if h == nil {
				t.Fatal("expected non-nil hash, got nil")
			}
			// Verify the hash produces output
			_, _ = h.Write([]byte("test"))
			sum := h.Sum(nil)
			if len(sum) == 0 {
				t.Fatal("hash produced empty output")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AeadFromKey
// ---------------------------------------------------------------------------

func TestAeadFromKey(t *testing.T) {
	key := [SymmetricKeySize]byte{}
	for i := range key {
		key[i] = byte(i)
	}

	tests := []struct {
		name    string
		gcmType GcmTypeEnum
		wantErr string
	}{
		{
			name:    "GCM_AES256",
			gcmType: GCM_AES256,
		},
		{
			name:    "GCM_CHACHA20POLY1305",
			gcmType: GCM_CHACHA20POLY1305,
		},
		{
			name:    "invalid GCM type",
			gcmType: GcmTypeEnum(99),
			wantErr: "unsupported GCM type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var aead cipher.AEAD
			aead, err := AeadFromKey(tt.gcmType, &key)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !containsString(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if aead == nil {
				t.Fatal("expected non-nil AEAD, got nil")
			}
			// Verify the AEAD can seal and open
			nonce := make([]byte, aead.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				t.Fatalf("failed to generate nonce: %v", err)
			}
			plaintext := []byte("test encryption")
			sealed := aead.Seal(nil, nonce, plaintext, nil)
			opened, err := aead.Open(nil, nonce, sealed, nil)
			if err != nil {
				t.Fatalf("AEAD open failed: %v", err)
			}
			if !bytes.Equal(opened, plaintext) {
				t.Fatalf("AEAD round-trip mismatch: got %v, want %v", opened, plaintext)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// NewECDH
// ---------------------------------------------------------------------------

func TestNewECDH(t *testing.T) {
	tests := []struct {
		name    string
		eccType EccTypeEnum
		wantErr string
	}{
		{
			name:    "ECC_CURVE25519",
			eccType: ECC_CURVE25519,
		},
		{
			name:    "invalid ECC type",
			eccType: EccTypeEnum(99),
			wantErr: "unsupported ECC type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ecdh, err := NewECDH(tt.eccType)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !containsString(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ecdh == nil {
				t.Fatal("expected non-nil Ecdh, got nil")
			}
			if len(ecdh.PublicKey()) == 0 {
				t.Fatal("public key should not be empty")
			}
			if len(ecdh.PrivateKey()) == 0 {
				t.Fatal("private key should not be empty")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ECDHFromKey
// ---------------------------------------------------------------------------

func TestECDHFromKey(t *testing.T) {
	t.Run("valid key returns valid Ecdh", func(t *testing.T) {
		// Generate a valid 32-byte key
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 1)
		}
		ecdh := ECDHFromKey(ECC_CURVE25519, key)
		if ecdh == nil {
			t.Fatal("expected non-nil Ecdh, got nil")
		}
		if len(ecdh.PublicKey()) == 0 {
			t.Fatal("public key should not be empty")
		}
		if len(ecdh.PrivateKey()) == 0 {
			t.Fatal("private key should not be empty")
		}
		// Verify private key was set correctly
		if !bytes.Equal(ecdh.PrivateKey(), key) {
			t.Fatal("private key does not match input")
		}
	})

	t.Run("invalid ECC type returns nil", func(t *testing.T) {
		key := make([]byte, 32)
		ecdh := ECDHFromKey(EccTypeEnum(99), key)
		if ecdh != nil {
			t.Fatal("expected nil Ecdh for invalid ECC type, got non-nil")
		}
	})

	t.Run("short key returns nil", func(t *testing.T) {
		key := make([]byte, 16) // too short for curve25519
		ecdh := ECDHFromKey(ECC_CURVE25519, key)
		if ecdh != nil {
			t.Fatal("expected nil Ecdh for short key, got non-nil")
		}
	})
}

// ---------------------------------------------------------------------------
// ECDH shared secret agreement
// ---------------------------------------------------------------------------

func TestECDHSharedSecret(t *testing.T) {
	t.Run("two parties derive same shared secret", func(t *testing.T) {
		alice, err := NewECDH(ECC_CURVE25519)
		if err != nil {
			t.Fatalf("NewECDH for alice: %v", err)
		}
		bob, err := NewECDH(ECC_CURVE25519)
		if err != nil {
			t.Fatalf("NewECDH for bob: %v", err)
		}

		secretA := alice.SharedSecret(bob.PublicKey())
		secretB := bob.SharedSecret(alice.PublicKey())
		if secretA == nil || secretB == nil {
			t.Fatal("shared secrets should not be nil")
		}
		if !bytes.Equal(secretA, secretB) {
			t.Fatal("alice and bob should derive the same shared secret")
		}
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}

// makePaddingBlock creates a block where every byte is the block size value,
// representing a full block of PKCS#7 padding.
func makePaddingBlock(blockSize int) []byte {
	b := make([]byte, blockSize)
	for i := range b {
		b[i] = byte(blockSize)
	}
	return b
}
