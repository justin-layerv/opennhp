package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
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

func NewHash(t HashTypeEnum) (h hash.Hash) {
	switch t {
	case HASH_BLAKE2S:
		h, _ = blake2s.New256(nil)

	case HASH_SHA256:
		h = sha256.New()
	}

	return h
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

func AeadFromKey(t GcmTypeEnum, key *[SymmetricKeySize]byte) (aead cipher.AEAD) {
	switch t {
	case GCM_AES256:
		aesBlock, _ := aes.NewCipher(key[:])
		aead, _ = cipher.NewGCM(aesBlock)

	case GCM_CHACHA20POLY1305:
		aead, _ = chacha20poly1305.New(key[:])
	}

	return aead
}

func CBCEncryption(t GcmTypeEnum, key *[SymmetricKeySize]byte, plaintext []byte, inPlace bool) ([]byte, error) {
	var block cipher.Block
	var iv []byte
	switch t {
	case GCM_AES256:
		block, _ = aes.NewCipher(key[:])
		iv = key[8:24]

	case GCM_CHACHA20POLY1305:
		return nil, ErrNotApplicable
	}

	var paddedPlainText []byte
	if len(plaintext)%block.BlockSize() == 0 {
		// skip padding
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
	switch t {
	case GCM_AES256:
		block, _ = aes.NewCipher(key[:])
		iv = key[8:24]

	case GCM_CHACHA20POLY1305:
		return nil, ErrNotApplicable
	}

	if len(ciphertext) < block.BlockSize() {
		return nil, fmt.Errorf("ciphertext too short")
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
		// skip unpadding
	} else {
		// Unpad plaintext
		plaintext = unpad(plaintext, block.BlockSize())
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
	// Need at least IV (16 bytes) + one block of data (16 bytes)
	if len(cipherText) < aes.BlockSize {
		return nil, fmt.Errorf("cipherText too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	// CBC requires ciphertext to be a multiple of block size
	if len(cipherText) == 0 || len(cipherText)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("cipherText length must be a multiple of block size")
	}

	// Decrypt
	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(cipherText))
	mode.CryptBlocks(decrypted, cipherText)

	// Remove padding
	decrypted = unpad(decrypted, aes.BlockSize)

	return decrypted, nil
}
func unpad(padded []byte, blockSize int) []byte {
	length := len(padded)
	unpadLen := int(padded[length-1])
	if unpadLen > blockSize || unpadLen > length {
		return nil
	}
	return padded[:length-unpadLen]
}
