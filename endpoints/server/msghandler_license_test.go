package server

import (
	"slices"
	"sort"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// testServer creates a minimal UdpServer for testing validateACLicense.
// It sets up cloud mode (DynamoDB storage) with the provided MemoryStorage
// and always wires a test metrics publisher. The metrics handle is
// non-nil in production (initialized at NewUdpServer) and the #1154
// gate assumes that invariant — see the cr round 2 thread on #1261 on
// the pattern-consistency decision to not defensively nil-guard
// s.metrics inside gate hot paths. Test helpers mirror that invariant.
func testServer(t *testing.T, storage *MemoryStorage) *UdpServer {
	t.Helper()
	return &UdpServer{
		metrics: metrics.NewPublisherForTest(t),
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
	s := testServer(t, storage)

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
	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206", "")
	if err != nil {
		t.Fatalf("Expected validation to succeed, got error: %v", err)
	}
}

func TestValidateACLicense_MissingCredentials_LicenseKey(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(t, storage)

	aolMsg := &common.ACOnlineMsg{
		ACId:       "ac-1",
		LicenseKey: "", // Missing
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206", "")
	if err == nil {
		t.Fatal("Expected error for missing LicenseKey")
	}
}

func TestValidateACLicense_LicenseNotFound(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(t, storage)

	aolMsg := &common.ACOnlineMsg{
		ACId:       "ac-1",
		LicenseKey: "nonexistent-key",
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206", "")
	if err == nil {
		t.Fatal("Expected error for nonexistent license")
	}
}

func TestValidateACLicense_InactiveLicense(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(t, storage)

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

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206", "")
	if err == nil {
		t.Fatal("Expected error for inactive license")
	}
}

func TestValidateACLicense_ExpiredLicense(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(t, storage)

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

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206", "")
	if err == nil {
		t.Fatal("Expected error for expired license")
	}
}

func TestValidateACLicense_WrongLicenseKey(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(t, storage)

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

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206", "")
	if err == nil {
		t.Fatal("Expected error for wrong license key")
	}
}

func TestValidateACLicense_NoHashInDB_Rejected(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(t, storage)

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

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206", "")
	if err == nil {
		t.Fatal("Expected failure for license without hash (misconfiguration), got success")
	}
}

func TestValidateACLicense_NoExpiration(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(t, storage)

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

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206", "")
	if err != nil {
		t.Fatalf("Expected success for license without expiration, got: %v", err)
	}
}

func TestValidateACLicense_StorageError(t *testing.T) {
	storage := NewMemoryStorage()
	s := testServer(t, storage)

	// Inject storage error
	storage.SetErrorOnNextCall(ErrCodeServiceUnavail, "DynamoDB unavailable")

	aolMsg := &common.ACOnlineMsg{
		ACId:       "ac-1",
		LicenseKey: "some-key",
	}

	err := s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206", "")
	if err == nil {
		t.Fatal("Expected error for storage failure")
	}
}

// ============================================================================
// Timing Attack Prevention Tests
// ============================================================================
// These tests verify that validateACLicense takes approximately the same time
// regardless of the failure reason, preventing timing-based enumeration attacks.
//
// Security context: Without constant-time validation, an attacker could:
// - Determine if a license key exists by measuring response time
// - Enumerate valid license keys through timing side-channel
//
// The defense: bcrypt comparison dominates timing (~100ms), making all paths
// take similar time regardless of whether the key exists, is expired, etc.

func TestValidateACLicense_TimingAttackPrevention(t *testing.T) {
	// Test configuration designed for reliability in CI while catching real attacks.
	//
	// A real timing attack would show 10x+ difference (e.g., 10ms vs 100ms).
	// We use relative tolerance to catch that while allowing CI variance.
	// Note: CI environments have significant timing variance due to virtualization.
	const (
		warmupRuns     = 2 // Discard first N runs (CPU cache warming)
		measuredRuns   = 8 // Runs to measure (after warmup)
		totalRuns      = warmupRuns + measuredRuns
		trimOutliers   = 1    // Remove N highest/lowest samples
		maxRelativeDev = 0.47 // Max 47% deviation from median (catches 10x attacks, allows CI noise)

		// Calibrated "did bcrypt run" floor (full rationale in the block
		// comment below): floor = bcryptFloorFraction of the fastest of
		// calibrationRuns bcrypt samples; minPlausibleBcrypt is the
		// absolute backstop.
		calibrationRuns     = 5
		bcryptFloorFraction = 0.5
		minPlausibleBcrypt  = 10 * time.Millisecond
	)

	// Calibrate the "did bcrypt run" floor against this machine's real
	// bcrypt cost instead of hardcoding it: a fixed 50ms floor false-failed
	// on fast CPUs where cost-10 bcrypt (DefaultCost, as in production's
	// dummyBcryptHash "$2a$10$...") finishes in ~46ms, dropping every path's
	// median just under 50ms while bcrypt ran fine. The relative-deviation
	// check below stays the primary constant-time assertion and is
	// untouched; this floor is only a belt-and-suspenders "did bcrypt run".
	//
	// Floor = bcryptFloorFraction of the fastest of calibrationRuns
	// bare-bcrypt samples (against the same cost-10 dummy hash the not-found
	// path uses). Calibration is decoupled from validateACLicense, so a path
	// that skipped bcrypt returns in microseconds and still trips the floor.
	// The fastest sample is the truest per-op lower bound (least
	// interrupted), so no warmup is needed and a transient blip can't
	// inflate the floor above the measured medians (bcrypt + storage lookup,
	// always >= a bare op).
	//
	// The floor tracks measured cost, so it asserts bcrypt *ran*, not a
	// specific cost value (pinned by DefaultCost / dummyBcryptHash, not this
	// test). minPlausibleBcrypt backstops that: real cost-10 never finishes
	// under it, so dropping below means a no-op or gross downgrade — fail
	// loudly. It is itself hardware-era; if a future CPU runs cost-10 under
	// it, bump it (loud, never silent).
	calibrationSamples := make([]time.Duration, 0, calibrationRuns)
	for i := 0; i < calibrationRuns; i++ {
		calStart := time.Now()
		// Key mismatch is fine: bcrypt cost is independent of the password
		// matching, and mirrors the production not-found path.
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte("calibration-key"))
		calibrationSamples = append(calibrationSamples, time.Since(calStart))
	}
	calibratedBcrypt := slices.Min(calibrationSamples)
	if calibratedBcrypt < minPlausibleBcrypt {
		t.Fatalf("bcrypt calibration measured %v (< %v); bcrypt is a no-op or running at a grossly reduced cost",
			calibratedBcrypt, minPlausibleBcrypt)
	}
	minExpectedTime := time.Duration(float64(calibratedBcrypt) * bcryptFloorFraction)
	t.Logf("Calibrated bcrypt cost: %v (samples: %v) -> absolute floor: %v",
		calibratedBcrypt, formatDurations(calibrationSamples), minExpectedTime)

	storage := NewMemoryStorage()
	s := testServer(t, storage)

	// Create test licenses with different states
	validKey := "valid-license-key"
	storage.PutLicenseWithKey(&License{
		CustomerID:     "cust-1",
		ResourceID:     "console",
		Active:         true,
		Tier:           "pro",
		ExpiresAt:      time.Now().Add(24 * time.Hour).Unix(),
		LicenseKeyHash: generateBcryptHash(validKey),
	}, validKey)

	inactiveKey := "inactive-license-key"
	storage.PutLicenseWithKey(&License{
		CustomerID:     "cust-1",
		ResourceID:     "console",
		Active:         false,
		Tier:           "pro",
		LicenseKeyHash: generateBcryptHash(inactiveKey),
	}, inactiveKey)

	expiredKey := "expired-license-key"
	storage.PutLicenseWithKey(&License{
		CustomerID:     "cust-1",
		ResourceID:     "console",
		Active:         true,
		Tier:           "pro",
		ExpiresAt:      time.Now().Add(-1 * time.Hour).Unix(),
		LicenseKeyHash: generateBcryptHash(expiredKey),
	}, expiredKey)

	// Test cases covering all validation paths
	testCases := []struct {
		name       string
		licenseKey string
	}{
		{"NotFound", "nonexistent-key-12345"},
		{"Inactive", inactiveKey},
		{"Expired", expiredKey},
		{"ValidSuccess", validKey},
	}

	// Collect timing samples for each case
	samples := make(map[string][]time.Duration)
	for _, tc := range testCases {
		samples[tc.name] = make([]time.Duration, 0, totalRuns)
		for i := 0; i < totalRuns; i++ {
			aolMsg := &common.ACOnlineMsg{
				ACId:       "ac-1",
				LicenseKey: tc.licenseKey,
			}
			start := time.Now()
			_ = s.validateACLicense(testPacketParserData(), aolMsg, 1, "192.168.1.1:62206", "")
			elapsed := time.Since(start)

			// Skip warmup runs
			if i >= warmupRuns {
				samples[tc.name] = append(samples[tc.name], elapsed)
			}
		}
	}

	// Calculate trimmed median for each case (robust to outliers)
	medians := make(map[string]time.Duration)
	for name, durations := range samples {
		medians[name] = trimmedMedian(durations, trimOutliers)
		t.Logf("%s: median time = %v (samples: %v)", name, medians[name], formatDurations(durations))
	}

	// Verify all times are above minimum (bcrypt is actually running)
	for name, median := range medians {
		if median < minExpectedTime {
			t.Errorf("%s median %v is below minimum %v - bcrypt may not be running",
				name, median, minExpectedTime)
		}
	}

	// Calculate overall median across all cases
	var allMedians []time.Duration
	for _, m := range medians {
		allMedians = append(allMedians, m)
	}
	overallMedian := trimmedMedian(allMedians, 0)

	// Verify all cases are within relative tolerance of overall median
	// This catches timing attacks (10x difference) while allowing CI variance (30%)
	for name, median := range medians {
		deviation := float64(median-overallMedian) / float64(overallMedian)
		if deviation < 0 {
			deviation = -deviation
		}
		if deviation > maxRelativeDev {
			t.Errorf("%s deviated %.1f%% from overall median %v (max allowed: %.0f%%)\n"+
				"  This could indicate a timing attack vulnerability.\n"+
				"  Expected: all paths should take similar time due to bcrypt.",
				name, deviation*100, overallMedian, maxRelativeDev*100)
		}
	}

	t.Logf("Overall median: %v, max relative deviation: %.1f%% (limit: %.0f%%)",
		overallMedian, maxRelativeDeviation(medians, overallMedian)*100, maxRelativeDev*100)
}

// trimmedMedian calculates the median after removing N highest and N lowest values.
// This provides robustness against outliers from CI noise (GC, context switches, etc).
func trimmedMedian(durations []time.Duration, trim int) time.Duration {
	if len(durations) == 0 {
		return 0
	}

	// Sort a copy to avoid mutating the original
	sorted := slices.Clone(durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	// Trim outliers
	if trim*2 >= len(sorted) {
		trim = 0 // Can't trim more than we have
	}
	trimmed := sorted[trim : len(sorted)-trim]

	// Calculate median
	n := len(trimmed)
	if n == 0 {
		return sorted[len(sorted)/2]
	}
	if n%2 == 0 {
		return (trimmed[n/2-1] + trimmed[n/2]) / 2
	}
	return trimmed[n/2]
}

// maxRelativeDeviation returns the maximum relative deviation from the reference.
func maxRelativeDeviation(medians map[string]time.Duration, reference time.Duration) float64 {
	var maxDev float64
	for _, m := range medians {
		dev := float64(m-reference) / float64(reference)
		if dev < 0 {
			dev = -dev
		}
		if dev > maxDev {
			maxDev = dev
		}
	}
	return maxDev
}

// formatDurations formats a slice of durations for logging.
func formatDurations(durations []time.Duration) string {
	if len(durations) == 0 {
		return "[]"
	}
	result := "["
	for i, d := range durations {
		if i > 0 {
			result += ", "
		}
		result += d.Round(time.Millisecond).String()
	}
	return result + "]"
}
