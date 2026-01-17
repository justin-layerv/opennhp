package server

import (
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"golang.org/x/crypto/bcrypt"
)

// testServer creates a minimal UdpServer for testing validateACLicense.
// It sets up cloud mode (DynamoDB storage) with the provided MemoryStorage.
func testServer(storage *MemoryStorage) *UdpServer {
	return &UdpServer{
		storage: storage,
		storageConfig: &StorageConfig{
			Backend: "dynamodb",
		},
	}
}

// testPacketParserData creates a minimal PacketParserData for testing.
func testPacketParserData() *core.PacketParserData {
	return &core.PacketParserData{}
}

// generateBcryptHash generates a bcrypt hash for testing.
func generateBcryptHash(key string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
	return string(hash)
}

// ============================================================================
// validateACLicense Tests
// ============================================================================

func TestValidateACLicense_ValidLicense(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	// Create license with bcrypt hash
	licenseKey := "test-license-key-12345"
	hash := generateBcryptHash(licenseKey)

	license := &License{
		CustomerID:     "cust-1",
		ResourceID:     "console",
		Active:         true,
		Tier:           "pro",
		ExpiresAt:      time.Now().Add(24 * time.Hour).Unix(),
		LicenseKeyHash: hash,
	}
	// Use PutLicenseWithKey to compute SHA256 for lookup
	storage.PutLicenseWithKey(license, licenseKey)

	// Create AC online message with matching credentials
	aolMsg := &common.ACOnlineMsg{
		ACId:       "ac-1",
		LicenseKey: licenseKey,
	}

	// Validate
	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err != nil {
		t.Fatalf("Expected validation to succeed, got error: %v", err)
	}
}

func TestValidateACLicense_MissingCredentials_LicenseKey(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	aolMsg := &common.ACOnlineMsg{
		ACId:       "ac-1",
		LicenseKey: "", // Missing
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected error for missing LicenseKey")
	}
}

func TestValidateACLicense_LicenseNotFound(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	aolMsg := &common.ACOnlineMsg{
		ACId:       "ac-1",
		LicenseKey: "nonexistent-key",
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected error for nonexistent license")
	}
}

func TestValidateACLicense_InactiveLicense(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	licenseKey := "some-key"
	license := &License{
		CustomerID: "cust-1",
		ResourceID: "console",
		Active:     false, // Inactive
		Tier:       "pro",
	}
	storage.PutLicenseWithKey(license, licenseKey)

	aolMsg := &common.ACOnlineMsg{
		ACId:       "ac-1",
		LicenseKey: licenseKey,
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected error for inactive license")
	}
}

func TestValidateACLicense_ExpiredLicense(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	licenseKey := "some-key"
	license := &License{
		CustomerID: "cust-1",
		ResourceID: "console",
		Active:     true,
		Tier:       "pro",
		ExpiresAt:  time.Now().Add(-1 * time.Hour).Unix(), // Expired
	}
	storage.PutLicenseWithKey(license, licenseKey)

	aolMsg := &common.ACOnlineMsg{
		ACId:       "ac-1",
		LicenseKey: licenseKey,
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected error for expired license")
	}
}

func TestValidateACLicense_WrongLicenseKey(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	// Create license with specific key hash
	correctKey := "correct-key"
	hash := generateBcryptHash(correctKey)
	license := &License{
		CustomerID:     "cust-1",
		ResourceID:     "console",
		Active:         true,
		Tier:           "pro",
		ExpiresAt:      time.Now().Add(24 * time.Hour).Unix(),
		LicenseKeyHash: hash,
	}
	storage.PutLicenseWithKey(license, correctKey)

	// Try with wrong key - this won't find the license since SHA256 won't match
	aolMsg := &common.ACOnlineMsg{
		ACId:       "ac-1",
		LicenseKey: "wrong-key", // Wrong key
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected error for wrong license key")
	}
}

func TestValidateACLicense_NoHashInDB_Rejected(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	// License has no hash - this is a misconfiguration that must be rejected
	licenseKey := "some-key"
	license := &License{
		CustomerID:     "cust-1",
		ResourceID:     "console",
		Active:         true,
		Tier:           "system",
		ExpiresAt:      time.Now().Add(24 * time.Hour).Unix(),
		LicenseKeyHash: "", // No hash = misconfiguration
	}
	storage.PutLicenseWithKey(license, licenseKey)

	// AC sends key but license has no hash - should be rejected
	aolMsg := &common.ACOnlineMsg{
		ACId:       "ac-1",
		LicenseKey: licenseKey,
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected failure for license without hash (misconfiguration), got success")
	}
}

func TestValidateACLicense_NoExpiration(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	licenseKey := "test-key"
	hash := generateBcryptHash(licenseKey)

	// License with no expiration (ExpiresAt = 0)
	license := &License{
		CustomerID:     "cust-1",
		ResourceID:     "console",
		Active:         true,
		Tier:           "enterprise",
		ExpiresAt:      0, // No expiration
		LicenseKeyHash: hash,
	}
	storage.PutLicenseWithKey(license, licenseKey)

	aolMsg := &common.ACOnlineMsg{
		ACId:       "ac-1",
		LicenseKey: licenseKey,
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err != nil {
		t.Fatalf("Expected success for license without expiration, got: %v", err)
	}
}

func TestValidateACLicense_StorageError(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	// Inject storage error
	storage.SetErrorOnNextCall(ErrCodeServiceUnavail, "DynamoDB unavailable")

	aolMsg := &common.ACOnlineMsg{
		ACId:       "ac-1",
		LicenseKey: "some-key",
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected error for storage failure")
	}
}

// ============================================================================
// Timing Attack Prevention Tests
// ============================================================================
// These tests verify that validateACLicense takes approximately the same time
// regardless of the failure reason, preventing timing-based enumeration attacks.

func TestValidateACLicense_TimingAttackPrevention(t *testing.T) {
	// This test measures response times for different failure modes.
	// All failures should take approximately the same time (dominated by bcrypt ~100ms).
	// We allow a generous tolerance since CI environments may have variable performance.

	const (
		iterations       = 3                      // Number of iterations to average
		maxDeviation     = 100 * time.Millisecond // Max allowed deviation from mean
		minExpectedTime  = 50 * time.Millisecond  // bcrypt should take at least this long
	)

	storage := NewMemoryStorage()
	s := testServer(storage)

	// Create a valid license for some tests
	validKey := "valid-license-key"
	hash := generateBcryptHash(validKey)
	license := &License{
		CustomerID:     "cust-1",
		ResourceID:     "console",
		Active:         true,
		Tier:           "pro",
		ExpiresAt:      time.Now().Add(24 * time.Hour).Unix(),
		LicenseKeyHash: hash,
	}
	storage.PutLicenseWithKey(license, validKey)

	// Create an inactive license
	inactiveKey := "inactive-license-key"
	inactiveHash := generateBcryptHash(inactiveKey)
	inactiveLicense := &License{
		CustomerID:     "cust-1",
		ResourceID:     "console",
		Active:         false, // Inactive
		Tier:           "pro",
		LicenseKeyHash: inactiveHash,
	}
	storage.PutLicenseWithKey(inactiveLicense, inactiveKey)

	// Create an expired license
	expiredKey := "expired-license-key"
	expiredHash := generateBcryptHash(expiredKey)
	expiredLicense := &License{
		CustomerID:     "cust-1",
		ResourceID:     "console",
		Active:         true,
		Tier:           "pro",
		ExpiresAt:      time.Now().Add(-1 * time.Hour).Unix(), // Expired
		LicenseKeyHash: expiredHash,
	}
	storage.PutLicenseWithKey(expiredLicense, expiredKey)

	// Test cases for timing comparison
	testCases := []struct {
		name       string
		licenseKey string
	}{
		{"NotFound", "nonexistent-key-12345"},
		{"Inactive", inactiveKey},
		{"Expired", expiredKey},
		{"ValidSuccess", validKey},
	}

	// Measure average time for each case
	times := make(map[string]time.Duration)
	for _, tc := range testCases {
		var total time.Duration
		for i := 0; i < iterations; i++ {
			aolMsg := &common.ACOnlineMsg{
				ACId:       "ac-1",
				LicenseKey: tc.licenseKey,
			}

			start := time.Now()
			_ = s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
			elapsed := time.Since(start)
			total += elapsed
		}
		times[tc.name] = total / time.Duration(iterations)
		t.Logf("%s: average time = %v", tc.name, times[tc.name])
	}

	// Verify all times are above minimum (bcrypt is running)
	for name, elapsed := range times {
		if elapsed < minExpectedTime {
			t.Errorf("%s took only %v, expected at least %v (bcrypt should dominate)",
				name, elapsed, minExpectedTime)
		}
	}

	// Calculate mean time across all failure cases (excluding success for comparison)
	var totalFailure time.Duration
	failureCases := []string{"NotFound", "Inactive", "Expired"}
	for _, name := range failureCases {
		totalFailure += times[name]
	}
	meanFailure := totalFailure / time.Duration(len(failureCases))

	// Verify all failure cases are within tolerance of the mean
	for _, name := range failureCases {
		deviation := times[name] - meanFailure
		if deviation < 0 {
			deviation = -deviation
		}
		if deviation > maxDeviation {
			t.Errorf("%s deviated %v from mean failure time %v (max allowed: %v)",
				name, deviation, meanFailure, maxDeviation)
		}
	}

	// Success case should also be similar (bcrypt dominates)
	successDeviation := times["ValidSuccess"] - meanFailure
	if successDeviation < 0 {
		successDeviation = -successDeviation
	}
	if successDeviation > maxDeviation {
		t.Errorf("ValidSuccess deviated %v from mean failure time %v (max allowed: %v)",
			successDeviation, meanFailure, maxDeviation)
	}

	t.Logf("Mean failure time: %v, all cases within tolerance", meanFailure)
}
