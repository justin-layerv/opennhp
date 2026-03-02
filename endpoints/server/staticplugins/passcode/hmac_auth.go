package passcode

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"time"
)

// HMACConfig HMAC signature verification configuration
type HMACConfig struct {
	AccessKey string // Access key (using resId)
	SecretKey string // Signing key
	Algorithm string // Algorithm: "sha256", "sha512", "sha1"
	ExpireSec int    // Signature validity period (seconds), 0 means no expiration check
}

// HMACSigner HMAC signer
type HMACSigner struct {
	config *HMACConfig
}

// NewHMACSigner creates a new HMAC signer
func NewHMACSigner(config *HMACConfig) *HMACSigner {
	return &HMACSigner{config: config}
}

// Sign generates signature (for client use)
// Returns format: HMAC accessKey:timestamp:signature
func (s *HMACSigner) Sign() string {
	timestamp := time.Now().Unix()

	// Signature string: only uses timestamp
	signString := strconv.FormatInt(timestamp, 10)

	// Calculate HMAC
	signature := s.calcHMAC(signString)

	// Return complete authentication header
	return fmt.Sprintf("HMAC %s:%d:%s",
		s.config.AccessKey,
		timestamp,
		signature,
	)
}

// Verify verifies signature (for server use)
// authHeader format: HMAC accessKey:timestamp:signature
func (s *HMACSigner) Verify(authHeader string) (bool, error) {
	// 1. Parse format
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "HMAC" {
		return false, errors.New("invalid format: expected 'HMAC accessKey:timestamp:signature'")
	}

	// 2. Parse parameters
	params := strings.Split(parts[1], ":")
	if len(params) != 3 {
		return false, errors.New("invalid params: expected 'accessKey:timestamp:signature'")
	}

	accessKey := params[0]
	timestampStr := params[1]
	signature := params[2]

	// 3. Verify access key
	if accessKey != s.config.AccessKey {
		return false, errors.New("invalid access key")
	}

	// 4. Verify timestamp format
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false, errors.New("invalid timestamp format")
	}

	// 5. Check if expired (if expiration time is set)
	if s.config.ExpireSec > 0 {
		now := time.Now().Unix()
		diff := now - timestamp
		if diff < 0 {
			diff = -diff // Handle case where timestamp is in the future
		}
		if diff > int64(s.config.ExpireSec) {
			return false, fmt.Errorf("signature expired: timestamp diff %d seconds exceeds %d seconds", diff, s.config.ExpireSec)
		}
	}

	// 6. Recalculate signature
	signString := timestampStr
	expectedSignature := s.calcHMAC(signString)

	// 7. Compare signatures (using constant time comparison to prevent timing attacks)
	if !hmac.Equal([]byte(expectedSignature), []byte(signature)) {
		return false, errors.New("signature mismatch")
	}

	return true, nil
}

// calcHMAC calculates HMAC signature
func (s *HMACSigner) calcHMAC(data string) string {
	var mac hash.Hash

	switch strings.ToLower(s.config.Algorithm) {
	case "sha256":
		mac = hmac.New(sha256.New, []byte(s.config.SecretKey))
	case "sha512":
		mac = hmac.New(sha512.New, []byte(s.config.SecretKey))
	case "sha1":
		mac = hmac.New(sha1.New, []byte(s.config.SecretKey))
	default:
		// Default to sha256
		mac = hmac.New(sha256.New, []byte(s.config.SecretKey))
	}

	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyHMACFromHeader convenience function: verify HMAC signature from Authorization header
// resId: resource ID, used as AccessKey
// secretKey: signing key
// algorithm: algorithm (sha256/sha512/sha1)
// expireSec: expiration time (seconds), 0 means no check
// authHeader: Authorization header content
func VerifyHMACFromHeader(resId, secretKey, algorithm string, expireSec int, authHeader string) (bool, error) {
	if len(authHeader) == 0 {
		return false, errors.New("authorization header is empty")
	}

	config := &HMACConfig{
		AccessKey: resId,
		SecretKey: secretKey,
		Algorithm: algorithm,
		ExpireSec: expireSec,
	}

	signer := NewHMACSigner(config)
	return signer.Verify(authHeader)
}
