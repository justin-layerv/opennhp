package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"

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

// init cipher suite
func NewCipherSuite() (ciphers *CipherSuite) {
	return &CipherSuite{
		Scheme:   common.CIPHER_SCHEME_CURVE,
		HashType: HASH_BLAKE2S,
		EccType:  ECC_CURVE25519,
		GcmType:  GCM_AES256,
	}
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

func ECDHFromKey(t EccTypeEnum, prk []byte) (e Ecdh) {
	switch t {
	case ECC_CURVE25519:
		var c curve.Curve25519ECDH
		err := c.SetPrivateKey(prk)
		if err != nil {
			return nil
		}
		e = &c
	}

	return e
}

func NewECDH(t EccTypeEnum) (e Ecdh) {
	switch t {
	case ECC_CURVE25519:
		e = curve.NewECDH()
	}

	return e
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

func CBCEncryption(t GcmTypeEnum, key *[SymmetricKeySize]byte, plaintext []byte, inPlace bool) ([]byte, error) {
	var block cipher.Block
	var iv []byte
	var err error
	switch t {
	case GCM_AES256:
		block, err = aes.NewCipher(key[:])
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %w", err)
		}
		iv = key[8:24]

	case GCM_CHACHA20POLY1305:
		return nil, ErrNotApplicable

	default:
		// Guard against future GcmTypeEnum additions - unreachable with current values
		return nil, fmt.Errorf("unsupported cipher type: %d", t)
	}

	var paddedPlainText []byte
	if len(plaintext)%block.BlockSize() == 0 {
		// NOTE: Non-standard PKCS#7 behavior from upstream OpenNHP. Standard PKCS#7
		// always pads (adding a full block when input is block-aligned). This legacy
		// behavior skips padding for block-aligned input for compatibility with
		// existing encrypted data. See CBCDecryption for matching unpadding logic.
		paddedPlainText = plaintext
	} else {
		paddedPlainText = pad(plaintext, block.BlockSize())
	}

	var ciphertext []byte
	if inPlace {
		ciphertext = paddedPlainText
	} else {
		ciphertext = make([]byte, 0, len(plaintext))
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, paddedPlainText)

	return ciphertext, nil
}

func CBCDecryption(t GcmTypeEnum, key *[SymmetricKeySize]byte, ciphertext []byte, inPlace bool) ([]byte, error) {
	var block cipher.Block
	var iv []byte
	var err error
	switch t {
	case GCM_AES256:
		block, err = aes.NewCipher(key[:])
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %w", err)
		}
		iv = key[8:24]

	case GCM_CHACHA20POLY1305:
		return nil, ErrNotApplicable

	default:
		// Guard against future GcmTypeEnum additions - unreachable with current values
		return nil, fmt.Errorf("unsupported cipher type: %d", t)
	}

	if len(ciphertext) < block.BlockSize() {
		return nil, errors.New("ciphertext too short")
	}

	var plaintext []byte
	if inPlace {
		plaintext = ciphertext
	} else {
		plaintext = make([]byte, len(ciphertext))
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(plaintext, ciphertext)

	if len(plaintext)%block.BlockSize() == 0 {
		// NOTE: Non-standard PKCS#7 behavior from upstream OpenNHP. This matches
		// the CBCEncryption logic which skips padding for block-aligned input.
		// Standard PKCS#7 always has padding, but this legacy behavior maintains
		// compatibility with existing encrypted data.
	} else {
		// Unpad plaintext
		plaintext, err = unpad(plaintext, block.BlockSize())
		if err != nil {
			return nil, fmt.Errorf("failed to unpad plaintext: %w", err)
		}
	}

	return plaintext, nil
}

// AESEncryption Function
func AESEncrypt(plainText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//Padding Plaintext
	plainText = pad(plainText, aes.BlockSize)
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)
	return cipherText, nil
}

// Filling function
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func AESDecrypt(cipherText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Validate ciphertext length:
	// - Must have at least IV (16 bytes) + one encrypted block (16 bytes)
	// - After IV extraction, remaining must be a multiple of block size
	if len(cipherText) < aes.BlockSize*2 {
		return nil, fmt.Errorf("cipherText too short: need at least %d bytes, got %d", aes.BlockSize*2, len(cipherText))
	}
	if (len(cipherText)-aes.BlockSize)%aes.BlockSize != 0 {
		return nil, errors.New("cipherText length invalid: must be IV + multiple of block size")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	// Decrypt
	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(cipherText))
	mode.CryptBlocks(decrypted, cipherText)

	// Remove padding
	decrypted, err = unpad(decrypted, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("failed to unpad decrypted data: %w", err)
	}

	return decrypted, nil
}

func unpad(padded []byte, blockSize int) ([]byte, error) {
	length := len(padded)
	if length == 0 {
		return nil, errors.New("empty padded data")
	}
	unpadLen := int(padded[length-1])
	if unpadLen == 0 || unpadLen > blockSize || unpadLen > length {
		return nil, fmt.Errorf("invalid padding length: %d", unpadLen)
	}
	// Validate all padding bytes match PKCS#7 requirements
	for i := length - unpadLen; i < length; i++ {
		if padded[i] != byte(unpadLen) {
			return nil, errors.New("invalid PKCS#7 padding bytes")
		}
	}
	return padded[:length-unpadLen], nil
}
