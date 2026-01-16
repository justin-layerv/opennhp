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
		ResourceFQDN:   "console.nhp.test",
		Active:         true,
		Tier:           "pro",
		ExpiresAt:      time.Now().Add(24 * time.Hour).Unix(),
		LicenseKeyHash: hash,
	}
	storage.PutLicense(license)

	// Create AC online message with matching credentials
	aolMsg := &common.ACOnlineMsg{
		ACId:         "ac-1",
		CustomerId:   "cust-1",
		ResourceFQDN: "console.nhp.test",
		LicenseKey:   licenseKey,
	}

	// Validate
	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err != nil {
		t.Fatalf("Expected validation to succeed, got error: %v", err)
	}
}

func TestValidateACLicense_MissingCredentials_CustomerId(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	aolMsg := &common.ACOnlineMsg{
		ACId:         "ac-1",
		CustomerId:   "", // Missing
		ResourceFQDN: "console.nhp.test",
		LicenseKey:   "some-key",
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected error for missing CustomerId")
	}
	if err.ErrorCode() != common.ErrServerACOpsFailed.ErrorCode() {
		t.Errorf("Expected ErrServerACOpsFailed, got %v", err)
	}
}

func TestValidateACLicense_MissingCredentials_ResourceFQDN(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	aolMsg := &common.ACOnlineMsg{
		ACId:         "ac-1",
		CustomerId:   "cust-1",
		ResourceFQDN: "", // Missing
		LicenseKey:   "some-key",
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected error for missing ResourceFQDN")
	}
}

func TestValidateACLicense_MissingCredentials_Both(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	aolMsg := &common.ACOnlineMsg{
		ACId:         "ac-1",
		CustomerId:   "", // Missing
		ResourceFQDN: "", // Missing
		LicenseKey:   "some-key",
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected error for missing credentials")
	}
}

func TestValidateACLicense_LicenseNotFound(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	aolMsg := &common.ACOnlineMsg{
		ACId:         "ac-1",
		CustomerId:   "nonexistent",
		ResourceFQDN: "console.nhp.test",
		LicenseKey:   "some-key",
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected error for nonexistent license")
	}
}

func TestValidateACLicense_InactiveLicense(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	license := &License{
		CustomerID:   "cust-1",
		ResourceFQDN: "console.nhp.test",
		Active:       false, // Inactive
		Tier:         "pro",
	}
	storage.PutLicense(license)

	aolMsg := &common.ACOnlineMsg{
		ACId:         "ac-1",
		CustomerId:   "cust-1",
		ResourceFQDN: "console.nhp.test",
		LicenseKey:   "some-key",
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected error for inactive license")
	}
}

func TestValidateACLicense_ExpiredLicense(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	license := &License{
		CustomerID:   "cust-1",
		ResourceFQDN: "console.nhp.test",
		Active:       true,
		Tier:         "pro",
		ExpiresAt:    time.Now().Add(-1 * time.Hour).Unix(), // Expired
	}
	storage.PutLicense(license)

	aolMsg := &common.ACOnlineMsg{
		ACId:         "ac-1",
		CustomerId:   "cust-1",
		ResourceFQDN: "console.nhp.test",
		LicenseKey:   "some-key",
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
	hash := generateBcryptHash("correct-key")
	license := &License{
		CustomerID:     "cust-1",
		ResourceFQDN:   "console.nhp.test",
		Active:         true,
		Tier:           "pro",
		ExpiresAt:      time.Now().Add(24 * time.Hour).Unix(),
		LicenseKeyHash: hash,
	}
	storage.PutLicense(license)

	aolMsg := &common.ACOnlineMsg{
		ACId:         "ac-1",
		CustomerId:   "cust-1",
		ResourceFQDN: "console.nhp.test",
		LicenseKey:   "wrong-key", // Wrong key
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected error for wrong license key")
	}
}

func TestValidateACLicense_EmptyLicenseKey_WithHashInDB(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	// License has a hash but AC sends empty key
	hash := generateBcryptHash("required-key")
	license := &License{
		CustomerID:     "cust-1",
		ResourceFQDN:   "console.nhp.test",
		Active:         true,
		Tier:           "pro",
		ExpiresAt:      time.Now().Add(24 * time.Hour).Unix(),
		LicenseKeyHash: hash,
	}
	storage.PutLicense(license)

	aolMsg := &common.ACOnlineMsg{
		ACId:         "ac-1",
		CustomerId:   "cust-1",
		ResourceFQDN: "console.nhp.test",
		LicenseKey:   "", // Empty - should fail
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected error when license key is required but not provided")
	}
}

func TestValidateACLicense_NoHashInDB_AnyKey(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(storage)

	// License has no hash (legacy/system AC)
	license := &License{
		CustomerID:     "cust-1",
		ResourceFQDN:   "console.nhp.test",
		Active:         true,
		Tier:           "system",
		ExpiresAt:      time.Now().Add(24 * time.Hour).Unix(),
		LicenseKeyHash: "", // No hash - key validation skipped
	}
	storage.PutLicense(license)

	// AC sends empty key - should be allowed
	aolMsg := &common.ACOnlineMsg{
		ACId:         "ac-1",
		CustomerId:   "cust-1",
		ResourceFQDN: "console.nhp.test",
		LicenseKey:   "",
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err != nil {
		t.Fatalf("Expected success for license without hash, got: %v", err)
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
		ResourceFQDN:   "console.nhp.test",
		Active:         true,
		Tier:           "enterprise",
		ExpiresAt:      0, // No expiration
		LicenseKeyHash: hash,
	}
	storage.PutLicense(license)

	aolMsg := &common.ACOnlineMsg{
		ACId:         "ac-1",
		CustomerId:   "cust-1",
		ResourceFQDN: "console.nhp.test",
		LicenseKey:   licenseKey,
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
		ACId:         "ac-1",
		CustomerId:   "cust-1",
		ResourceFQDN: "console.nhp.test",
		LicenseKey:   "some-key",
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected error for storage failure")
	}
}
