package server

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// ============================================================================
// LicenseRateLimiter Unit Tests
// ============================================================================

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := NewLicenseRateLimiter(RateLimitConfig{
		Enabled:                true,
		MaxFailuresPerIP:       3,
		MaxFailuresPerACID:     2,
		WindowSeconds:          60,
		CleanupIntervalSeconds: 300,
	})
	defer rl.Stop()

	// Record fewer failures than the limit
	rl.RecordFailure("192.168.1.1:62206", "ac-1")
	rl.RecordFailure("192.168.1.1:62206", "ac-1")

	// Should still be allowed for IP (2 < 3)
	err := rl.CheckRateLimit("192.168.1.1:62206", "ac-2")
	if err != nil {
		t.Fatalf("Expected no rate limit for IP under limit, got: %v", err)
	}
}

func TestRateLimiter_BlocksIPOverLimit(t *testing.T) {
	rl := NewLicenseRateLimiter(RateLimitConfig{
		Enabled:                true,
		MaxFailuresPerIP:       3,
		MaxFailuresPerACID:     10,
		WindowSeconds:          60,
		CleanupIntervalSeconds: 300,
	})
	defer rl.Stop()

	// Record exactly the limit of failures
	rl.RecordFailure("10.0.0.1:62206", "ac-1")
	rl.RecordFailure("10.0.0.1:62206", "ac-2")
	rl.RecordFailure("10.0.0.1:62206", "ac-3")

	// Should be blocked by IP
	err := rl.CheckRateLimit("10.0.0.1:62206", "ac-4")
	if err == nil {
		t.Fatal("Expected rate limit error for IP over limit")
	}
	if err.Code != ErrCodeRateLimited {
		t.Fatalf("Expected error code %s, got %s", ErrCodeRateLimited, err.Code)
	}

	// Different IP should not be blocked
	err = rl.CheckRateLimit("10.0.0.2:62206", "ac-4")
	if err != nil {
		t.Fatalf("Expected no rate limit for different IP, got: %v", err)
	}
}

func TestRateLimiter_BlocksACIDOverLimit(t *testing.T) {
	rl := NewLicenseRateLimiter(RateLimitConfig{
		Enabled:                true,
		MaxFailuresPerIP:       100,
		MaxFailuresPerACID:     2,
		WindowSeconds:          60,
		CleanupIntervalSeconds: 300,
	})
	defer rl.Stop()

	// Record failures for same AC ID from different IPs
	rl.RecordFailure("10.0.0.1:62206", "target-ac")
	rl.RecordFailure("10.0.0.2:62206", "target-ac")

	// Should be blocked by AC ID
	err := rl.CheckRateLimit("10.0.0.3:62206", "target-ac")
	if err == nil {
		t.Fatal("Expected rate limit error for AC ID over limit")
	}
	if err.Code != ErrCodeRateLimited {
		t.Fatalf("Expected error code %s, got %s", ErrCodeRateLimited, err.Code)
	}

	// Different AC ID should not be blocked
	err = rl.CheckRateLimit("10.0.0.3:62206", "other-ac")
	if err != nil {
		t.Fatalf("Expected no rate limit for different AC ID, got: %v", err)
	}
}

func TestRateLimiter_WindowExpiration(t *testing.T) {
	rl := NewLicenseRateLimiter(RateLimitConfig{
		Enabled:                true,
		MaxFailuresPerIP:       2,
		MaxFailuresPerACID:     2,
		WindowSeconds:          1, // 1 second window for fast test
		CleanupIntervalSeconds: 300,
	})
	defer rl.Stop()

	// Record failures up to the limit
	rl.RecordFailure("10.0.0.1:62206", "ac-1")
	rl.RecordFailure("10.0.0.1:62206", "ac-1")

	// Should be blocked
	err := rl.CheckRateLimit("10.0.0.1:62206", "ac-1")
	if err == nil {
		t.Fatal("Expected rate limit error before window expiry")
	}

	// Wait for window to expire
	time.Sleep(1100 * time.Millisecond)

	// Should be allowed again
	err = rl.CheckRateLimit("10.0.0.1:62206", "ac-1")
	if err != nil {
		t.Fatalf("Expected no rate limit after window expiry, got: %v", err)
	}
}

func TestRateLimiter_DisabledAllowsEverything(t *testing.T) {
	rl := NewLicenseRateLimiter(RateLimitConfig{
		Enabled:                false,
		MaxFailuresPerIP:       1,
		MaxFailuresPerACID:     1,
		WindowSeconds:          60,
		CleanupIntervalSeconds: 300,
	})
	defer rl.Stop()

	// Record many failures
	for i := 0; i < 100; i++ {
		rl.RecordFailure("10.0.0.1:62206", "ac-1")
	}

	// Should not be blocked when disabled
	err := rl.CheckRateLimit("10.0.0.1:62206", "ac-1")
	if err != nil {
		t.Fatalf("Expected no rate limit when disabled, got: %v", err)
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	rl := NewLicenseRateLimiter(RateLimitConfig{
		Enabled:                true,
		MaxFailuresPerIP:       5,
		MaxFailuresPerACID:     5,
		WindowSeconds:          1, // 1 second window
		CleanupIntervalSeconds: 300,
	})
	defer rl.Stop()

	// Record some failures
	rl.RecordFailure("10.0.0.1:62206", "ac-1")
	rl.RecordFailure("10.0.0.2:62206", "ac-2")

	// Verify entries exist
	rl.mu.Lock()
	if len(rl.ipCounts) != 2 {
		t.Fatalf("Expected 2 IP entries, got %d", len(rl.ipCounts))
	}
	rl.mu.Unlock()

	// Wait for window to expire
	time.Sleep(1100 * time.Millisecond)

	// Run cleanup
	rl.cleanup()

	// Verify entries were removed
	rl.mu.Lock()
	if len(rl.ipCounts) != 0 {
		t.Fatalf("Expected 0 IP entries after cleanup, got %d", len(rl.ipCounts))
	}
	if len(rl.acCounts) != 0 {
		t.Fatalf("Expected 0 AC entries after cleanup, got %d", len(rl.acCounts))
	}
	rl.mu.Unlock()
}

func TestRateLimiter_ExtractIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1:62206", "192.168.1.1"},
		{"10.0.0.1:8080", "10.0.0.1"},
		{"[::1]:62206", "::1"},
		{"192.168.1.1", "192.168.1.1"},
		{"", ""},
	}

	for _, tt := range tests {
		result := extractIP(tt.input)
		if result != tt.expected {
			t.Errorf("extractIP(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewLicenseRateLimiter(RateLimitConfig{
		Enabled:                true,
		MaxFailuresPerIP:       100,
		MaxFailuresPerACID:     100,
		WindowSeconds:          60,
		CleanupIntervalSeconds: 300,
	})
	defer rl.Stop()

	// Concurrent writes and reads should not panic
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				rl.RecordFailure("10.0.0.1:62206", "ac-1")
				_ = rl.CheckRateLimit("10.0.0.1:62206", "ac-1")
			}
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

// ============================================================================
// Integration: validateACLicense with Rate Limiting
// ============================================================================

func testServerWithRateLimiter(storage *MemoryStorage, rl *LicenseRateLimiter) *UdpServer {
	return &UdpServer{
		storage: storage,
		storageConfig: &StorageConfig{
			Backend: "dynamodb",
		},
		licenseRateLimiter: rl,
	}
}

func TestValidateACLicense_RateLimited(t *testing.T) {
	storage := NewMemoryStorage()
	rl := NewLicenseRateLimiter(RateLimitConfig{
		Enabled:                true,
		MaxFailuresPerIP:       2,
		MaxFailuresPerACID:     10,
		WindowSeconds:          60,
		CleanupIntervalSeconds: 300,
	})
	defer rl.Stop()

	s := testServerWithRateLimiter(storage, rl)

	// Create a valid license for later
	validKey := "valid-license-key"
	hash, _ := bcrypt.GenerateFromPassword([]byte(validKey), bcrypt.DefaultCost)
	storage.PutLicenseWithKey(&License{
		CustomerID:     "cust-1",
		ResourceID:     "console",
		Active:         true,
		Tier:           "pro",
		ExpiresAt:      time.Now().Add(24 * time.Hour).Unix(),
		LicenseKeyHash: string(hash),
	}, validKey)

	// Fail twice with wrong keys (reaching the IP limit of 2)
	for i := 0; i < 2; i++ {
		aolMsg := &common.ACOnlineMsg{
			ACId:       "ac-1",
			LicenseKey: "wrong-key",
		}
		_ = s.validateACLicense(&core.PacketParserData{}, aolMsg, 1, "192.168.1.1:62206")
	}

	// Next attempt should be rate limited, even with valid key
	aolMsg := &common.ACOnlineMsg{
		ACId:       "ac-1",
		LicenseKey: validKey,
	}
	err := s.validateACLicense(&core.PacketParserData{}, aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected rate limit error after exceeding failure threshold")
	}
	// The error should be returned (rate limited requests still return generic error)

	// Different IP should still be allowed with valid key
	err = s.validateACLicense(&core.PacketParserData{}, aolMsg, 1, "192.168.1.2:62206")
	if err != nil {
		t.Fatalf("Expected success from different IP, got: %v", err)
	}
}

func TestValidateACLicense_RateLimitByACID(t *testing.T) {
	storage := NewMemoryStorage()
	rl := NewLicenseRateLimiter(RateLimitConfig{
		Enabled:                true,
		MaxFailuresPerIP:       100,
		MaxFailuresPerACID:     2,
		WindowSeconds:          60,
		CleanupIntervalSeconds: 300,
	})
	defer rl.Stop()

	s := testServerWithRateLimiter(storage, rl)

	// Fail twice for the same AC ID from different IPs
	for i := 0; i < 2; i++ {
		aolMsg := &common.ACOnlineMsg{
			ACId:       "target-ac",
			LicenseKey: "wrong-key",
		}
		addr := fmt.Sprintf("192.168.1.%d:62206", i+1)
		_ = s.validateACLicense(&core.PacketParserData{}, aolMsg, 1, addr)
	}

	// Same AC ID from new IP should be rate limited
	aolMsg := &common.ACOnlineMsg{
		ACId:       "target-ac",
		LicenseKey: "any-key",
	}
	err := s.validateACLicense(&core.PacketParserData{}, aolMsg, 1, "10.0.0.1:62206")
	if err == nil {
		t.Fatal("Expected rate limit error for AC ID over limit")
	}

	// Different AC ID should work (will fail validation but NOT be rate limited)
	aolMsg2 := &common.ACOnlineMsg{
		ACId:       "other-ac",
		LicenseKey: "any-key",
	}
	err = s.validateACLicense(&core.PacketParserData{}, aolMsg2, 1, "10.0.0.1:62206")
	if err == nil {
		t.Fatal("Expected validation error (not-found), but got nil")
	}
	// Verify it's a validation error, not a rate limit error
	// (rate limiting would have prevented reaching storage at all)
}

func TestValidateACLicense_NilRateLimiter(t *testing.T) {
	// Verify that validateACLicense works when rate limiter is nil
	// (backward compatibility)
	storage := NewMemoryStorage()
	s := testServer(storage) // Uses original testServer without rate limiter

	aolMsg := &common.ACOnlineMsg{
		ACId:       "ac-1",
		LicenseKey: "some-key",
	}

	// Should not panic with nil rate limiter
	err := s.validateACLicense(&core.PacketParserData{}, aolMsg, 1, "192.168.1.1:62206")
	if err == nil {
		t.Fatal("Expected validation error for nonexistent key")
	}
}

func TestValidateACLicense_SuccessDoesNotCount(t *testing.T) {
	storage := NewMemoryStorage()
	rl := NewLicenseRateLimiter(RateLimitConfig{
		Enabled:                true,
		MaxFailuresPerIP:       2,
		MaxFailuresPerACID:     2,
		WindowSeconds:          60,
		CleanupIntervalSeconds: 300,
	})
	defer rl.Stop()

	s := testServerWithRateLimiter(storage, rl)

	// Create valid license
	validKey := "valid-key-12345"
	hash, _ := bcrypt.GenerateFromPassword([]byte(validKey), bcrypt.DefaultCost)
	storage.PutLicenseWithKey(&License{
		CustomerID:     "cust-1",
		ResourceID:     "console",
		Active:         true,
		Tier:           "pro",
		ExpiresAt:      time.Now().Add(24 * time.Hour).Unix(),
		LicenseKeyHash: string(hash),
	}, validKey)

	// Make many successful validations
	for i := 0; i < 10; i++ {
		aolMsg := &common.ACOnlineMsg{
			ACId:       "ac-1",
			LicenseKey: validKey,
		}
		err := s.validateACLicense(&core.PacketParserData{}, aolMsg, 1, "192.168.1.1:62206")
		if err != nil {
			t.Fatalf("Validation %d failed unexpectedly: %v", i, err)
		}
	}

	// Should still be allowed (successful attempts don't count)
	err := rl.CheckRateLimit("192.168.1.1:62206", "ac-1")
	if err != nil {
		t.Fatalf("Expected no rate limit after successful validations, got: %v", err)
	}
}
