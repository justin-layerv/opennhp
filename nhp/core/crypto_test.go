package core

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"hash"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

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
				if !strings.Contains(err.Error(), tt.wantErr) {
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

func TestHashSumScratchBufferDoesNotAllocate(t *testing.T) {
	hashTypes := []struct {
		name     string
		hashType HashTypeEnum
	}{
		{
			name:     "BLAKE2S",
			hashType: HASH_BLAKE2S,
		},
		{
			name:     "SHA256",
			hashType: HASH_SHA256,
		},
	}

	mad := &MsgAssemblerData{}
	ppd := &PacketParserData{}
	packetStates := []struct {
		name string
		dst  func() []byte
	}{
		{
			name: "MsgAssemblerData",
			dst:  func() []byte { return mad.hashBuf[:0] },
		},
		{
			name: "PacketParserData",
			dst:  func() []byte { return ppd.hashBuf[:0] },
		},
	}

	for _, ht := range hashTypes {
		for _, ps := range packetStates {
			t.Run(ht.name+"/"+ps.name, func(t *testing.T) {
				input := []byte("test")
				h, err := NewHash(ht.hashType)
				if err != nil {
					t.Fatalf("NewHash failed: %v", err)
				}
				if _, err := h.Write(input); err != nil {
					t.Fatalf("hash write failed: %v", err)
				}

				if got := len(h.Sum(ps.dst())); got != h.Size() {
					t.Fatalf("sum length = %d, want %d", got, h.Size())
				}

				var gotLen int
				allocs := testing.AllocsPerRun(1000, func() {
					h.Reset()
					_, _ = h.Write(input)
					gotLen = len(h.Sum(ps.dst()))
				})
				if gotLen != h.Size() {
					t.Fatalf("sum length = %d, want %d", gotLen, h.Size())
				}
				if allocs != 0 {
					t.Fatalf("Sum with %s scratch buffer allocated %.0f times, want 0", ps.name, allocs)
				}
			})
		}
	}
}

func TestCheckHMACDoesNotAllocateHashScratch(t *testing.T) {
	ciphers := NewCipherSuite()

	var packetBuf PacketBuffer
	pkt := &Packet{
		Buf:        &packetBuf,
		Content:    packetBuf[:],
		HeaderType: NHP_KNK,
	}
	header := pkt.HeaderWithCipherScheme(common.CIPHER_SCHEME_CURVE)
	header.SetCounter(1)
	header.SetTypeAndPayloadSize(NHP_KNK, 0)

	seed := []byte("test-hmac-seed")
	prefixLen := header.Size() - HashSize
	writeExpectedHMAC := func(cookie []byte) {
		expectedHash, err := NewHash(ciphers.HashType)
		if err != nil {
			t.Fatalf("NewHash failed: %v", err)
		}
		expectedHash.Write(seed)
		expectedHash.Write(header.Bytes()[:prefixLen])
		if cookie != nil {
			expectedHash.Write(cookie)
		}
		expectedHash.Sum(header.HMACBytes()[:0])
	}
	writeExpectedHMAC(nil)

	ppd := &PacketParserData{header: header}
	h, err := NewHash(ciphers.HashType)
	if err != nil {
		t.Fatalf("NewHash failed: %v", err)
	}

	runCheck := func(sumCookie bool) bool {
		h.Reset()
		h.Write(seed)
		ppd.hmacHash = h
		return ppd.checkHMAC(sumCookie)
	}

	if !runCheck(false) {
		t.Fatal("checkHMAC returned false")
	}

	ok := true
	allocs := testing.AllocsPerRun(1000, func() {
		if !runCheck(false) {
			ok = false
		}
	})
	if !ok {
		t.Fatal("checkHMAC returned false")
	}
	if allocs != 0 {
		t.Fatalf("checkHMAC allocated %.0f times, want 0", allocs)
	}

	header.HMACBytes()[0] ^= 0xff
	if runCheck(false) {
		t.Fatal("checkHMAC returned true for tampered HMAC")
	}

	cookieStore := &CookieStore{}
	for i := range cookieStore.CurrCookie {
		cookieStore.CurrCookie[i] = byte(i)
		cookieStore.PrevCookie[i] = byte(i + CookieSize)
	}
	cookieStore.LastCookieTime = 1
	ppd.ConnData = &ConnectionData{CookieStore: cookieStore}

	cookieTests := []struct {
		name          string
		localInitTime int64
		cookie        []byte
	}{
		{
			name:          "previous cookie",
			localInitTime: 0,
			cookie:        cookieStore.PrevCookie[:],
		},
		{
			name:          "current cookie",
			localInitTime: 1 << 60,
			cookie:        cookieStore.CurrCookie[:],
		},
	}

	for _, tt := range cookieTests {
		t.Run(tt.name, func(t *testing.T) {
			ppd.LocalInitTime = tt.localInitTime
			writeExpectedHMAC(tt.cookie)

			if !runCheck(true) {
				t.Fatal("checkHMAC returned false")
			}

			ok := true
			allocs := testing.AllocsPerRun(1000, func() {
				if !runCheck(true) {
					ok = false
				}
			})
			if !ok {
				t.Fatal("checkHMAC returned false")
			}
			if allocs != 0 {
				t.Fatalf("checkHMAC allocated %.0f times, want 0", allocs)
			}

			header.HMACBytes()[0] ^= 0xff
			if runCheck(true) {
				t.Fatal("checkHMAC returned true for tampered HMAC")
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
				if !strings.Contains(err.Error(), tt.wantErr) {
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
				if !strings.Contains(err.Error(), tt.wantErr) {
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
		ecdh, err := ECDHFromKey(ECC_CURVE25519, key)
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
		// Verify private key was set correctly
		if !bytes.Equal(ecdh.PrivateKey(), key) {
			t.Fatal("private key does not match input")
		}
	})

	t.Run("invalid ECC type returns error", func(t *testing.T) {
		key := make([]byte, 32)
		ecdh, err := ECDHFromKey(EccTypeEnum(99), key)
		if err == nil {
			t.Fatal("expected error for invalid ECC type, got nil")
		}
		if ecdh != nil {
			t.Fatal("expected nil Ecdh for invalid ECC type, got non-nil")
		}
	})

	t.Run("short key returns error", func(t *testing.T) {
		key := make([]byte, 16) // too short for curve25519
		_, err := ECDHFromKey(ECC_CURVE25519, key)
		if err == nil {
			t.Fatal("expected error for short key, got nil")
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
// Noise init material
// ---------------------------------------------------------------------------

// TestNoiseInitBytesMatchStrings guards the byte-identity invariant between
// the exported string constants and the precomputed []byte slices used on
// the crypto hot path. Divergence (e.g. a future refactor that swaps the
// initializer) would silently change the noise handshake for every packet;
// this test catches that at test time.
//
// Transposition between initialHashBytes and initialChainKeyBytes at a use
// site is separately covered by TestDecryptBodyRoundTrip in
// decryptbody_test.go — any swap fails HMAC validation on decrypt.
func TestNoiseInitBytesMatchStrings(t *testing.T) {
	if !bytes.Equal(initialHashBytes, []byte(InitialHashString)) {
		t.Fatalf("initialHashBytes diverged from InitialHashString: got %q want %q",
			initialHashBytes, InitialHashString)
	}
	if !bytes.Equal(initialChainKeyBytes, []byte(InitialChainKeyString)) {
		t.Fatalf("initialChainKeyBytes diverged from InitialChainKeyString: got %q want %q",
			initialChainKeyBytes, InitialChainKeyString)
	}
}
