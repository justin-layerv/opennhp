package passcode

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

// TestNewHMACSigner tests creating a signer
func TestNewHMACSigner(t *testing.T) {
	config := &HMACConfig{
		AccessKey: "test-access-key",
		SecretKey: "test-secret-key",
		Algorithm: "sha256",
		ExpireSec: 300,
	}

	signer := NewHMACSigner(config)
	if signer == nil {
		t.Error("Expected non-nil signer")
	}
	if signer.config != config {
		t.Error("Signer config not set correctly")
	}
}

// TestSignAndVerify tests the sign and verify flow
func TestSignAndVerify(t *testing.T) {
	config := &HMACConfig{
		AccessKey: "myResId",
		SecretKey: "mySecretKey123",
		Algorithm: "sha256",
		ExpireSec: 300,
	}

	signer := NewHMACSigner(config)

	// Generate signature
	authHeader := signer.Sign()
	t.Logf("Generated auth header: %s", authHeader)

	// Verify signature
	valid, err := signer.Verify(authHeader)
	if err != nil {
		t.Errorf("Verification failed with error: %v", err)
	}
	if !valid {
		t.Error("Expected valid signature")
	}
}

// TestVerifyWithDifferentAlgorithms tests different hash algorithms
func TestVerifyWithDifferentAlgorithms(t *testing.T) {
	algorithms := []string{"sha256", "sha512", "sha1"}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			config := &HMACConfig{
				AccessKey: "testKey",
				SecretKey: "testSecret",
				Algorithm: algo,
				ExpireSec: 300,
			}

			signer := NewHMACSigner(config)
			authHeader := signer.Sign()

			valid, err := signer.Verify(authHeader)
			if err != nil {
				t.Errorf("Algorithm %s verification failed: %v", algo, err)
			}
			if !valid {
				t.Errorf("Algorithm %s signature should be valid", algo)
			}
		})
	}
}

// TestVerifyExpiredSignature tests expired signature rejection
func TestVerifyExpiredSignature(t *testing.T) {
	config := &HMACConfig{
		AccessKey: "testKey",
		SecretKey: "testSecret",
		Algorithm: "sha256",
		ExpireSec: 1, // 1 second expiration
	}

	signer := NewHMACSigner(config)

	// Create an old timestamp signature manually
	oldTimestamp := time.Now().Add(-10 * time.Second).Unix()
	signString := strconv.FormatInt(oldTimestamp, 10)
	signature := signer.calcHMAC(signString)
	authHeader := fmt.Sprintf("HMAC %s:%d:%s", config.AccessKey, oldTimestamp, signature)

	valid, err := signer.Verify(authHeader)
	if err == nil {
		t.Error("Expected error for expired signature")
	}
	if valid {
		t.Error("Expected invalid result for expired signature")
	}
	t.Logf("Expected error received: %v", err)
}

// TestVerifyInvalidFormat tests invalid format rejection
func TestVerifyInvalidFormat(t *testing.T) {
	config := &HMACConfig{
		AccessKey: "testKey",
		SecretKey: "testSecret",
		Algorithm: "sha256",
		ExpireSec: 300,
	}

	signer := NewHMACSigner(config)

	testCases := []struct {
		name       string
		authHeader string
	}{
		{"Empty", ""},
		{"Missing HMAC prefix", "testKey:123456:signature"},
		{"Wrong prefix", "BASIC testKey:123456:signature"},
		{"Missing parts", "HMAC testKey:signature"},
		{"Too many parts", "HMAC testKey:123456:signature:extra"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := signer.Verify(tc.authHeader)
			if valid {
				t.Errorf("Expected invalid for %s", tc.name)
			}
			if err == nil && tc.authHeader != "" {
				t.Errorf("Expected error for %s", tc.name)
			}
		})
	}
}

// TestVerifyWrongAccessKey tests wrong access key rejection
func TestVerifyWrongAccessKey(t *testing.T) {
	config := &HMACConfig{
		AccessKey: "correctKey",
		SecretKey: "testSecret",
		Algorithm: "sha256",
		ExpireSec: 300,
	}

	signer := NewHMACSigner(config)

	// Create signature with wrong access key
	timestamp := time.Now().Unix()
	signString := strconv.FormatInt(timestamp, 10)
	signature := signer.calcHMAC(signString)
	authHeader := fmt.Sprintf("HMAC wrongKey:%d:%s", timestamp, signature)

	valid, err := signer.Verify(authHeader)
	if err == nil {
		t.Error("Expected error for wrong access key")
	}
	if valid {
		t.Error("Expected invalid for wrong access key")
	}
}

// TestVerifyWrongSignature tests wrong signature rejection
func TestVerifyWrongSignature(t *testing.T) {
	config := &HMACConfig{
		AccessKey: "testKey",
		SecretKey: "testSecret",
		Algorithm: "sha256",
		ExpireSec: 300,
	}

	signer := NewHMACSigner(config)

	timestamp := time.Now().Unix()
	authHeader := fmt.Sprintf("HMAC %s:%d:wrongsignature", config.AccessKey, timestamp)

	valid, err := signer.Verify(authHeader)
	if err == nil {
		t.Error("Expected error for wrong signature")
	}
	if valid {
		t.Error("Expected invalid for wrong signature")
	}
}

// TestVerifyHMACFromHeader tests the convenience function
func TestVerifyHMACFromHeader(t *testing.T) {
	resId := "myResource"
	secretKey := "mySecret123"
	algorithm := "sha256"
	expireSec := 300

	// Generate a valid signature
	config := &HMACConfig{
		AccessKey: resId,
		SecretKey: secretKey,
		Algorithm: algorithm,
		ExpireSec: expireSec,
	}
	signer := NewHMACSigner(config)
	authHeader := signer.Sign()

	// Verify using convenience function
	valid, err := VerifyHMACFromHeader(resId, secretKey, algorithm, expireSec, authHeader)
	if err != nil {
		t.Errorf("VerifyHMACFromHeader failed: %v", err)
	}
	if !valid {
		t.Error("Expected valid signature")
	}
}

// TestNoExpirationCheck tests that expiration is skipped when ExpireSec is 0
func TestNoExpirationCheck(t *testing.T) {
	config := &HMACConfig{
		AccessKey: "testKey",
		SecretKey: "testSecret",
		Algorithm: "sha256",
		ExpireSec: 0, // No expiration check
	}

	signer := NewHMACSigner(config)

	// Create an old timestamp signature
	oldTimestamp := time.Now().Add(-1 * time.Hour).Unix()
	signString := strconv.FormatInt(oldTimestamp, 10)
	signature := signer.calcHMAC(signString)
	authHeader := fmt.Sprintf("HMAC %s:%d:%s", config.AccessKey, oldTimestamp, signature)

	// Should still be valid because ExpireSec is 0
	valid, err := signer.Verify(authHeader)
	if err != nil {
		t.Errorf("Expected no error when ExpireSec is 0: %v", err)
	}
	if !valid {
		t.Error("Expected valid when ExpireSec is 0")
	}
}

// BenchmarkSign benchmarks signature generation
func BenchmarkSign(b *testing.B) {
	config := &HMACConfig{
		AccessKey: "testKey",
		SecretKey: "testSecret",
		Algorithm: "sha256",
		ExpireSec: 300,
	}
	signer := NewHMACSigner(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signer.Sign()
	}
}

// BenchmarkVerify benchmarks signature verification
func BenchmarkVerify(b *testing.B) {
	config := &HMACConfig{
		AccessKey: "testKey",
		SecretKey: "testSecret",
		Algorithm: "sha256",
		ExpireSec: 300,
	}
	signer := NewHMACSigner(config)
	authHeader := signer.Sign()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signer.Verify(authHeader)
	}
}
