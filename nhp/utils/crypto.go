package utils

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

func MD5(value string) string {
	_16bytes := md5.Sum([]byte(value))
	return hex.EncodeToString(_16bytes[:])
}

// SHA256 returns the lowercase hex-encoded SHA-256 of value. Shared by callers
// that key/identify by a token or key hash (e.g. acktoken.HashToken,
// licenseadmin.LicenseKeySHA256) so the sha256→hex idiom lives in one place.
func SHA256(value string) string {
	_32bytes := sha256.Sum256([]byte(value))
	return hex.EncodeToString(_32bytes[:])
}

func Base64(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

func Md5sum(fullFilePath string) (string, error) {
	fileInfo, err := os.Stat(fullFilePath)
	if err != nil {
		return "", fmt.Errorf("file not found: %w", err)
	}

	if !fileInfo.Mode().IsRegular() {
		return "", errors.New("path is not a regular file")
	}

	file, err := os.Open(fullFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	hasher := md5.New()

	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed to read file content: %w", err)
	}

	// Convert hash to hex string
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// PubKeyFingerprintLen is the length in characters of the short ID produced
// by PubKeyFingerprint. It comes from base64.RawURLEncoding of the first 8
// bytes of SHA-256 (8 bytes → 11 base64url chars, unpadded).
const PubKeyFingerprintLen = 11

// PubKeyFingerprint returns a short, URL-safe identifier derived from a raw
// public key: base64url(SHA-256(rawPubKey)[:8]), 11 characters with no
// padding. The same public key always produces the same fingerprint, so
// both Go and TypeScript implementations can compute it independently.
//
// This is a stable routing identifier, not a security primitive. The 64-bit
// truncation gives a ~2^-64 collision probability for any given pair of distinct
// keys; a collision within a *set* of keys becomes likely only near ~2^32 keys
// (the birthday bound) -- far more than the handful of upstream nhp-server
// clusters a relay hosts. Callers MUST NOT use it as an authentication token.
//
// Ported from OpenNHP upstream (#2208); the collision-probability wording is
// corrected here -- upstream conflated the per-pair probability (2^-64) with the
// birthday bound (~2^32 keys). Do not "re-sync" it back to the upstream phrasing.
func PubKeyFingerprint(rawPubKey []byte) string {
	sum := sha256.Sum256(rawPubKey)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// PubKeyFingerprintFromBase64 is a convenience wrapper that decodes a
// standard-base64-encoded public key (as stored in TOML configs) before
// hashing. Returns the fingerprint and any decode error.
func PubKeyFingerprintFromBase64(pubKeyBase64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return "", err
	}
	return PubKeyFingerprint(raw), nil
}
