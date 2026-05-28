package core

import (
	"crypto/hmac"
	"crypto/subtle"
	"hash"
)

// makeHashFunc wraps NewHash into a panic-on-error constructor suitable for
// hmac.New. Using a package-level function value (rather than an inline
// closure) avoids a heap allocation on every HMAC call — the KDF chain
// invokes HMAC ~10 times per packet.
func makeHashFunc(t HashTypeEnum) func() hash.Hash {
	return func() hash.Hash {
		h, err := NewHash(t)
		if err != nil {
			panic("NewHash failed: " + err.Error())
		}
		return h
	}
}

// hashNewFuncs holds pre-allocated hash constructor functions keyed by
// HashTypeEnum. Must be kept in sync with HashTypeEnum values — adding a
// new hash type without extending this array causes an index-out-of-range
// panic at runtime.
var hashNewFuncs = [...]func() hash.Hash{
	HASH_BLAKE2S: makeHashFunc(HASH_BLAKE2S),
	HASH_SHA256:  makeHashFunc(HASH_SHA256),
}

// Pre-allocated single-byte KDF domain-separation tags. KeyGen1/2/3 pass
// these to HMAC.Write on every call (~4x per packet); hoisting them to
// package level turns heap-escaping []byte literals into shared static data.
// MUST NOT be mutated: these arrays are shared across all KDF calls and
// goroutines.
var (
	kdfTag1 = [1]byte{0x1}
	kdfTag2 = [1]byte{0x2}
	kdfTag3 = [1]byte{0x3}
)

type NoiseFactory struct {
	HashType HashTypeEnum
}

// hashFunc returns the pre-allocated hash constructor for this factory's
// HashType. Panics if HashType is out of range (programming error).
func (n *NoiseFactory) hashFunc() func() hash.Hash {
	return hashNewFuncs[n.HashType]
}

// HMAC1 performs HMAC with a single input.
// PANICS if HashType is invalid — this indicates a programming error since
// HashType is set from hardcoded values in the codebase.
func (n *NoiseFactory) HMAC1(dst *[HashSize]byte, key, in0 []byte) {
	mac := hmac.New(n.hashFunc(), key)
	mac.Write(in0)
	mac.Sum(dst[:0])
	mac.Reset()
}

// HMAC2 performs HMAC with two inputs.
// PANICS if HashType is invalid — see HMAC1 for rationale.
func (n *NoiseFactory) HMAC2(dst *[HashSize]byte, key, in0, in1 []byte) {
	mac := hmac.New(n.hashFunc(), key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(dst[:0])
	mac.Reset()
}

func (n *NoiseFactory) KeyGen1(dst0 *[HashSize]byte, key, input []byte) {
	n.HMAC1(dst0, key, input)
	n.HMAC1(dst0, dst0[:], kdfTag1[:])
}

func (n *NoiseFactory) KeyGen2(dst0, dst1 *[HashSize]byte, key, input []byte) {
	var prk [HashSize]byte
	n.HMAC1(&prk, key, input)
	mac := hmac.New(n.hashFunc(), prk[:])
	mac.Write(kdfTag1[:])
	mac.Sum(dst0[:0])
	mac.Reset()
	mac.Write(dst0[:])
	mac.Write(kdfTag2[:])
	mac.Sum(dst1[:0])
	SetZero(prk[:])
}

func (n *NoiseFactory) KeyGen3(dst0, dst1, dst2 *[HashSize]byte, key, input []byte) {
	var prk [HashSize]byte
	n.HMAC1(&prk, key, input)
	mac := hmac.New(n.hashFunc(), prk[:])
	mac.Write(kdfTag1[:])
	mac.Sum(dst0[:0])
	mac.Reset()
	mac.Write(dst0[:])
	mac.Write(kdfTag2[:])
	mac.Sum(dst1[:0])
	mac.Reset()
	mac.Write(dst1[:])
	mac.Write(kdfTag3[:])
	mac.Sum(dst2[:0])
	SetZero(prk[:])
}

func (n *NoiseFactory) MixKey(dst *[SymmetricKeySize]byte, key []byte, input []byte) {
	n.KeyGen1(dst, key, input)
}

// MixHash combines key and input into a hash output.
// PANICS if HashType is invalid — see HMAC1 for rationale.
func (n *NoiseFactory) MixHash(dst *[HashSize]byte, key []byte, input []byte) {
	h := n.hashFunc()()
	h.Write(key)
	h.Write(input)
	h.Sum(dst[:0])
	h.Reset()
}

func SetZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

func IsZero(arr []byte) bool {
	for _, b := range arr {
		r := subtle.ConstantTimeByteEq(b, 0)
		if r != 1 {
			return false
		}
	}
	return true
}
