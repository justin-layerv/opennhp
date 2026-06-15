package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"sync"
	"testing"

	"golang.org/x/crypto/blake2s"
)

const (
	kdfTestKey   = "KDF test key for vector coverage"
	kdfTestInput = "KDF test input for vector coverage"
)

type kdfVectorCase struct {
	name     string
	hashType HashTypeEnum
	newHash  func(*testing.T) hash.Hash
	dst0     string
	dst1     string
	dst2     string
}

// kdfVectorCases pins the NHP KDF (NoiseFactory) byte transcript. The dst*
// digests are hand-copied, identical, into the js-agent test
// (endpoints/js-agent/test/kdf.test.ts); the nhp-golden-vector markers let
// scripts/check-golden-vectors.sh fail CI if the two copies drift (#2556).
var kdfVectorCases = []kdfVectorCase{
	{
		name:     "BLAKE2s",
		hashType: HASH_BLAKE2S,
		newHash:  mustNewBlake2sHash,
		dst0:     "5603731d8149d45d1100909addb244063ab505e04288c9f2632fb0e167af0b95", // nhp-golden-vector: kdf-blake2s-dst0
		dst1:     "75c6a3037c6ac51ac536f94ce239b275d5d098092d6776b905cde91491d16807", // nhp-golden-vector: kdf-blake2s-dst1
		dst2:     "83c6cf425a88b426e3e92b1e9cd14ddb31066aeeb2071597a8106a36a4055a7d", // nhp-golden-vector: kdf-blake2s-dst2
	},
	{
		name:     "SHA256",
		hashType: HASH_SHA256,
		newHash:  mustNewSHA256Hash,
		dst0:     "f296bc34384ca0d49ab2bede40c5ddb126aca8ec5da639b8f631d4dc3ed42ac7", // nhp-golden-vector: kdf-sha256-dst0
		dst1:     "243c77a97d9402ffc50215ced8572d2784d61929bacedbbedceda91410564ab6", // nhp-golden-vector: kdf-sha256-dst1
		dst2:     "14dec35f867351badeb4bdd7ca7be63bd84338571d74e05f586872e28f3374a3", // nhp-golden-vector: kdf-sha256-dst2
	},
}

func TestKeyGenVectors(t *testing.T) {
	key := []byte(kdfTestKey)
	input := []byte(kdfTestInput)

	// These vectors pin the pre-optimization KDF byte transcript.
	// TestKeyGenVectorsAgainstIndependentHMAC cross-checks them with direct HMAC
	// calculations and local tag byte literals, not the package-level tag arrays.
	for _, tt := range kdfVectorCases {
		t.Run(tt.name, func(t *testing.T) {
			noise := &NoiseFactory{HashType: tt.hashType}
			expected0 := mustDecodeKDFHash(t, tt.dst0)
			expected1 := mustDecodeKDFHash(t, tt.dst1)
			expected2 := mustDecodeKDFHash(t, tt.dst2)

			var keyGen1 [HashSize]byte
			noise.KeyGen1(&keyGen1, key, input)
			assertKDFHashEqual(t, "KeyGen1 dst0", keyGen1, expected0)

			var keyGen2Dst0, keyGen2Dst1 [HashSize]byte
			noise.KeyGen2(&keyGen2Dst0, &keyGen2Dst1, key, input)
			assertKDFHashEqual(t, "KeyGen2 dst0", keyGen2Dst0, expected0)
			assertKDFHashEqual(t, "KeyGen2 dst1", keyGen2Dst1, expected1)

			var keyGen3Dst0, keyGen3Dst1, keyGen3Dst2 [HashSize]byte
			noise.KeyGen3(&keyGen3Dst0, &keyGen3Dst1, &keyGen3Dst2, key, input)
			assertKDFHashEqual(t, "KeyGen3 dst0", keyGen3Dst0, expected0)
			assertKDFHashEqual(t, "KeyGen3 dst1", keyGen3Dst1, expected1)
			assertKDFHashEqual(t, "KeyGen3 dst2", keyGen3Dst2, expected2)

			var mixKey [SymmetricKeySize]byte
			noise.MixKey(&mixKey, key, input)
			assertKDFHashEqual(t, "MixKey dst", mixKey, expected0)
		})
	}
}

func TestKDFTagsUnmodified(t *testing.T) {
	key := []byte(kdfTestKey)
	input := []byte(kdfTestInput)

	assertKDFTagValues(t, "before KDF calls")
	// The tag arrays are hash-agnostic, but both dispatch paths must share them
	// without mutation.
	for _, tt := range kdfVectorCases {
		t.Run(tt.name, func(t *testing.T) {
			noise := &NoiseFactory{HashType: tt.hashType}
			var wg sync.WaitGroup

			for worker := 0; worker < 8; worker++ {
				wg.Add(1)
				go func() {
					defer wg.Done()

					for round := 0; round < 128; round++ {
						var keyGen1 [HashSize]byte
						noise.KeyGen1(&keyGen1, key, input)

						var keyGen2Dst0, keyGen2Dst1 [HashSize]byte
						noise.KeyGen2(&keyGen2Dst0, &keyGen2Dst1, key, input)

						var keyGen3Dst0, keyGen3Dst1, keyGen3Dst2 [HashSize]byte
						noise.KeyGen3(&keyGen3Dst0, &keyGen3Dst1, &keyGen3Dst2, key, input)
					}
				}()
			}
			wg.Wait()

			assertKDFTagValues(t, "after KDF calls")
		})
	}
}

func TestKeyGenVectorsAgainstIndependentHMAC(t *testing.T) {
	key := []byte(kdfTestKey)
	input := []byte(kdfTestInput)

	for _, tt := range kdfVectorCases {
		t.Run(tt.name, func(t *testing.T) {
			expected0 := mustDecodeKDFHash(t, tt.dst0)
			expected1 := mustDecodeKDFHash(t, tt.dst1)
			expected2 := mustDecodeKDFHash(t, tt.dst2)

			keyGen1Dst0 := independentKeyGen1(t, tt.newHash, key, input)
			assertKDFHashEqual(t, "independent KeyGen1 dst0", keyGen1Dst0, expected0)

			keyGen2Dst0, keyGen2Dst1 := independentKeyGen2(t, tt.newHash, key, input)
			assertKDFHashEqual(t, "independent KeyGen2 dst0", keyGen2Dst0, expected0)
			assertKDFHashEqual(t, "independent KeyGen2 dst1", keyGen2Dst1, expected1)

			keyGen3Dst0, keyGen3Dst1, keyGen3Dst2 := independentKeyGen3(t, tt.newHash, key, input)
			assertKDFHashEqual(t, "independent KeyGen3 dst0", keyGen3Dst0, expected0)
			assertKDFHashEqual(t, "independent KeyGen3 dst1", keyGen3Dst1, expected1)
			assertKDFHashEqual(t, "independent KeyGen3 dst2", keyGen3Dst2, expected2)
		})
	}
}

func mustDecodeKDFHash(t *testing.T, s string) [HashSize]byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode KDF vector: %v", err)
	}
	if len(b) != HashSize {
		t.Fatalf("KDF vector length = %d, want %d", len(b), HashSize)
	}

	var out [HashSize]byte
	copy(out[:], b)
	return out
}

func mustNewBlake2sHash(t *testing.T) hash.Hash {
	t.Helper()

	h, err := blake2s.New256(nil)
	if err != nil {
		t.Fatalf("new BLAKE2s hash: %v", err)
	}
	return h
}

func mustNewSHA256Hash(t *testing.T) hash.Hash {
	t.Helper()

	return sha256.New()
}

func independentKeyGen1(t *testing.T, newHash func(*testing.T) hash.Hash, key, input []byte) [HashSize]byte {
	t.Helper()

	prk := independentHMAC(t, newHash, key, input)
	return independentHMAC(t, newHash, prk[:], []byte{0x1})
}

func independentKeyGen2(t *testing.T, newHash func(*testing.T) hash.Hash, key, input []byte) ([HashSize]byte, [HashSize]byte) {
	t.Helper()

	prk := independentHMAC(t, newHash, key, input)
	dst0 := independentHMAC(t, newHash, prk[:], []byte{0x1})
	dst1 := independentHMAC(t, newHash, prk[:], dst0[:], []byte{0x2})

	return dst0, dst1
}

func independentKeyGen3(t *testing.T, newHash func(*testing.T) hash.Hash, key, input []byte) ([HashSize]byte, [HashSize]byte, [HashSize]byte) {
	t.Helper()

	prk := independentHMAC(t, newHash, key, input)
	dst0 := independentHMAC(t, newHash, prk[:], []byte{0x1})
	dst1 := independentHMAC(t, newHash, prk[:], dst0[:], []byte{0x2})
	dst2 := independentHMAC(t, newHash, prk[:], dst1[:], []byte{0x3})

	return dst0, dst1, dst2
}

func independentHMAC(t *testing.T, newHash func(*testing.T) hash.Hash, key []byte, inputs ...[]byte) [HashSize]byte {
	t.Helper()

	ctor := func() hash.Hash {
		return newHash(t)
	}
	mac := hmac.New(ctor, key)
	for _, input := range inputs {
		mac.Write(input)
	}

	var out [HashSize]byte
	mac.Sum(out[:0])
	return out
}

func assertKDFHashEqual(t *testing.T, name string, got, want [HashSize]byte) {
	t.Helper()

	if !bytes.Equal(got[:], want[:]) {
		t.Fatalf("%s mismatch:\n got %x\nwant %x", name, got, want)
	}
}

func assertKDFTagValues(t *testing.T, phase string) {
	t.Helper()

	if kdfTag1 != [1]byte{0x1} {
		t.Fatalf("kdfTag1 %s = %x, want 01", phase, kdfTag1)
	}
	if kdfTag2 != [1]byte{0x2} {
		t.Fatalf("kdfTag2 %s = %x, want 02", phase, kdfTag2)
	}
	if kdfTag3 != [1]byte{0x3} {
		t.Fatalf("kdfTag3 %s = %x, want 03", phase, kdfTag3)
	}
}
