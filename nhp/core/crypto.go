package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core/scheme/curve"
)

type HashTypeEnum int

const (
	HASH_BLAKE2S HashTypeEnum = iota
	HASH_SHA256
)

type EccTypeEnum int

const (
	ECC_CURVE25519 EccTypeEnum = iota
)

type GcmTypeEnum int

const (
	GCM_AES256 GcmTypeEnum = iota
	GCM_CHACHA20POLY1305
)

type CipherSuite struct {
	Scheme   int
	EccType  EccTypeEnum
	HashType HashTypeEnum
	GcmType  GcmTypeEnum
}

// defaultCipherSuite is a shared, read-only CipherSuite instance.
// All fields are immutable after init, so concurrent reads are safe.
var defaultCipherSuite = &CipherSuite{
	Scheme:   common.CIPHER_SCHEME_CURVE,
	HashType: HASH_BLAKE2S,
	EccType:  ECC_CURVE25519,
	GcmType:  GCM_AES256,
}

// NewCipherSuite returns the shared default CipherSuite. The returned
// pointer must not be modified — all fields are treated as immutable.
func NewCipherSuite() *CipherSuite {
	return defaultCipherSuite
}

func NewHash(t HashTypeEnum) (hash.Hash, error) {
	switch t {
	case HASH_BLAKE2S:
		h, err := blake2s.New256(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create BLAKE2s hash: %w", err)
		}
		return h, nil
	case HASH_SHA256:
		return sha256.New(), nil
	default:
		return nil, fmt.Errorf("unsupported hash type: %d", t)
	}
}

type Ecdh interface {
	SetPrivateKey(prk []byte) error
	PrivateKey() []byte
	PublicKey() []byte
	SharedSecret(pbk []byte) []byte
	Name() string
	PrivateKeyBase64() string
	PublicKeyBase64() string
	Identity() []byte
	MidPublicKey() []byte
}

func ECDHFromKey(t EccTypeEnum, prk []byte) (Ecdh, error) {
	switch t {
	case ECC_CURVE25519:
		var c curve.Curve25519ECDH
		if err := c.SetPrivateKey(prk); err != nil {
			return nil, fmt.Errorf("failed to set private key: %w", err)
		}
		return &c, nil
	default:
		return nil, fmt.Errorf("unsupported ECC type: %d", t)
	}
}

func NewECDH(t EccTypeEnum) (Ecdh, error) {
	switch t {
	case ECC_CURVE25519:
		return curve.NewECDH()
	}

	return nil, fmt.Errorf("unsupported ECC type: %d", t)
}

func AeadFromKey(t GcmTypeEnum, key *[SymmetricKeySize]byte) (cipher.AEAD, error) {
	switch t {
	case GCM_AES256:
		aesBlock, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %w", err)
		}
		return cipher.NewGCM(aesBlock)
	case GCM_CHACHA20POLY1305:
		return chacha20poly1305.New(key[:])
	default:
		return nil, fmt.Errorf("unsupported GCM type: %d", t)
	}
}
