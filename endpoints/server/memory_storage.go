package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ============================================================================
// In-Memory Storage Backend (Testing)
// ============================================================================
//
// MemoryStorage provides an in-memory implementation of StorageBackend for
// testing purposes. It offers several advantages over mocking:
//
// - Full interface compliance without stub generation
// - Deterministic behavior for reliable tests
// - Configurable error injection for testing error paths
// - Configurable delays for testing timeouts
// - Thread-safe for concurrent test scenarios
// - No external dependencies (DynamoDB, etc.)
//
// Usage in tests:
//
//	storage := NewMemoryStorage()
//	storage.PutACAssignment(&ACAssignment{ACID: "ac-1", ...})
//	storage.SetErrorOnNextCall("NOT_FOUND") // Inject error
//	storage.SetDelayOnNextCall(5 * time.Second) // Inject delay
//
// ============================================================================

// MemoryStorage is an in-memory implementation of StorageBackend for testing.
type MemoryStorage struct {
	mu sync.RWMutex

	// Data stores
	acAssignments map[string]*ACAssignment // ACID -> Assignment
	licenses      map[string]*License      // licenseKeySHA256 -> License
	resources     map[string]*Resource     // customerID:resourceID -> Resource
	resourcesByAC map[string][]Resource    // ACID -> []Resource

	// Test control: error injection
	nextError     *StorageError
	errorOnMethod string // If set, only inject error for this method

	// Test control: delay injection
	nextDelay     time.Duration
	delayOnMethod string // If set, only inject delay for this method

	// Metrics for test assertions
	callCounts map[string]int
}

// Compile-time interface compliance check
var _ StorageBackend = (*MemoryStorage)(nil)

// NewMemoryStorage creates a new in-memory storage backend.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		acAssignments: make(map[string]*ACAssignment),
		licenses:      make(map[string]*License),
		resources:     make(map[string]*Resource),
		resourcesByAC: make(map[string][]Resource),
		callCounts:    make(map[string]int),
	}
}

// ============================================================================
// StorageBackend Interface Implementation
// ============================================================================

// GetACAssignment retrieves the server assignment for an AC.
func (m *MemoryStorage) GetACAssignment(ctx context.Context, acID string) (*ACAssignment, error) {
	m.mu.Lock()
	m.callCounts["GetACAssignment"]++
	m.mu.Unlock()

	if err := m.checkContextAndDelay(ctx, "GetACAssignment"); err != nil {
		return nil, err
	}
	if err := m.checkError("GetACAssignment"); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	assignment, ok := m.acAssignments[acID]
	if !ok {
		return nil, NewNotFoundError("AC assignment not found: " + acID)
	}

	// Return a copy to prevent mutation
	copy := *assignment
	copy.AssignedServers = make([]ServerInfo, len(assignment.AssignedServers))
	for i, s := range assignment.AssignedServers {
		copy.AssignedServers[i] = s
	}
	return &copy, nil
}

// GetACsByServer retrieves all ACs assigned to a specific server.
func (m *MemoryStorage) GetACsByServer(ctx context.Context, serverID string) ([]ACAssignment, error) {
	m.mu.Lock()
	m.callCounts["GetACsByServer"]++
	m.mu.Unlock()

	if err := m.checkContextAndDelay(ctx, "GetACsByServer"); err != nil {
		return nil, err
	}
	if err := m.checkError("GetACsByServer"); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []ACAssignment
	for _, assignment := range m.acAssignments {
		for _, server := range assignment.AssignedServers {
			if server.ID == serverID {
				// Return a copy
				copy := *assignment
				copy.AssignedServers = make([]ServerInfo, len(assignment.AssignedServers))
				for i, s := range assignment.AssignedServers {
					copy.AssignedServers[i] = s
				}
				results = append(results, copy)
				break
			}
		}
	}
	return results, nil
}

// GetLicense retrieves license information using the license key.
// The license key is hashed with SHA256 for lookup (matching DynamoDB implementation).
// License keys are globally unique, so no customer ID is needed.
func (m *MemoryStorage) GetLicense(ctx context.Context, licenseKey string) (*License, error) {
	m.mu.Lock()
	m.callCounts["GetLicense"]++
	m.mu.Unlock()

	if err := m.checkContextAndDelay(ctx, "GetLicense"); err != nil {
		return nil, err
	}
	if err := m.checkError("GetLicense"); err != nil {
		return nil, err
	}

	// Compute SHA256 of license key for lookup
	hash := sha256.Sum256([]byte(licenseKey))
	licenseKeySHA256 := hex.EncodeToString(hash[:])

	m.mu.RLock()
	defer m.mu.RUnlock()

	license, ok := m.licenses[licenseKeySHA256]
	if !ok {
		return nil, NewNotFoundError("license not found")
	}

	// Return a copy
	copy := *license
	return &copy, nil
}

// GetResource retrieves resource definition.
func (m *MemoryStorage) GetResource(ctx context.Context, customerID, resourceID string) (*Resource, error) {
	m.mu.Lock()
	m.callCounts["GetResource"]++
	m.mu.Unlock()

	if err := m.checkContextAndDelay(ctx, "GetResource"); err != nil {
		return nil, err
	}
	if err := m.checkError("GetResource"); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	key := customerID + ":" + resourceID
	resource, ok := m.resources[key]
	if !ok {
		return nil, NewNotFoundError("resource not found: " + key)
	}

	// Return a copy
	copy := *resource
	return &copy, nil
}

// GetResourceByACID retrieves resources associated with an AC.
func (m *MemoryStorage) GetResourceByACID(ctx context.Context, acID string) ([]Resource, error) {
	m.mu.Lock()
	m.callCounts["GetResourceByACID"]++
	m.mu.Unlock()

	if err := m.checkContextAndDelay(ctx, "GetResourceByACID"); err != nil {
		return nil, err
	}
	if err := m.checkError("GetResourceByACID"); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	resources, ok := m.resourcesByAC[acID]
	if !ok {
		return []Resource{}, nil // Empty slice, not error
	}

	// Return copies
	results := make([]Resource, len(resources))
	for i, r := range resources {
		results[i] = r
	}
	return results, nil
}

// Close releases resources.
func (m *MemoryStorage) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCounts["Close"]++
	// Clear all data
	m.acAssignments = make(map[string]*ACAssignment)
	m.licenses = make(map[string]*License)
	m.resources = make(map[string]*Resource)
	m.resourcesByAC = make(map[string][]Resource)
	return nil
}

// Name returns the backend name.
func (m *MemoryStorage) Name() string {
	return "memory"
}

// ============================================================================
// Test Data Management
// ============================================================================

// PutACAssignment stores an AC assignment.
func (m *MemoryStorage) PutACAssignment(assignment *ACAssignment) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store a copy
	copy := *assignment
	copy.AssignedServers = make([]ServerInfo, len(assignment.AssignedServers))
	for i, s := range assignment.AssignedServers {
		copy.AssignedServers[i] = s
	}
	m.acAssignments[assignment.ACID] = &copy
}

// DeleteACAssignment removes an AC assignment.
func (m *MemoryStorage) DeleteACAssignment(acID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.acAssignments, acID)
}

// PutLicense stores a license.
// The license must have LicenseKeySHA256 already computed (use PutLicenseWithKey helper).
func (m *MemoryStorage) PutLicense(license *License) {
	m.mu.Lock()
	defer m.mu.Unlock()

	copy := *license
	m.licenses[license.LicenseKeySHA256] = &copy
}

// PutLicenseWithKey stores a license and computes the SHA256 of the license key.
// This is a convenience method for testing.
func (m *MemoryStorage) PutLicenseWithKey(license *License, licenseKey string) {
	// Compute SHA256 of license key
	hash := sha256.Sum256([]byte(licenseKey))
	license.LicenseKeySHA256 = hex.EncodeToString(hash[:])

	m.PutLicense(license)
}

// DeleteLicense removes a license by license key SHA256.
func (m *MemoryStorage) DeleteLicense(licenseKeySHA256 string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.licenses, licenseKeySHA256)
}

// DeleteLicenseByKey removes a license using the plaintext license key.
// This is a convenience method for testing.
func (m *MemoryStorage) DeleteLicenseByKey(licenseKey string) {
	hash := sha256.Sum256([]byte(licenseKey))
	licenseKeySHA256 := hex.EncodeToString(hash[:])
	m.DeleteLicense(licenseKeySHA256)
}

// PutResource stores a resource.
func (m *MemoryStorage) PutResource(resource *Resource) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := resource.CustomerID + ":" + resource.ResourceID
	copy := *resource
	m.resources[key] = &copy

	// Also update resourcesByAC index
	if resource.ACID != "" {
		m.resourcesByAC[resource.ACID] = append(m.resourcesByAC[resource.ACID], copy)
	}
}

// DeleteResource removes a resource.
func (m *MemoryStorage) DeleteResource(customerID, resourceID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := customerID + ":" + resourceID
	delete(m.resources, key)
}

// Clear removes all data.
func (m *MemoryStorage) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acAssignments = make(map[string]*ACAssignment)
	m.licenses = make(map[string]*License)
	m.resources = make(map[string]*Resource)
	m.resourcesByAC = make(map[string][]Resource)
	m.callCounts = make(map[string]int)
}

// ============================================================================
// Test Control: Error Injection
// ============================================================================

// SetErrorOnNextCall configures an error to be returned on the next call.
// The error is consumed after one use.
func (m *MemoryStorage) SetErrorOnNextCall(code string, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextError = &StorageError{Code: code, Message: message}
	m.errorOnMethod = ""
}

// SetErrorOnNextCallForMethod configures an error for a specific method.
func (m *MemoryStorage) SetErrorOnNextCallForMethod(method, code, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextError = &StorageError{Code: code, Message: message}
	m.errorOnMethod = method
}

// SetServiceUnavailable configures a service unavailable error.
func (m *MemoryStorage) SetServiceUnavailable(message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextError = NewServiceUnavailableError(message, nil)
	m.errorOnMethod = ""
}

// ClearError removes any pending error.
func (m *MemoryStorage) ClearError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextError = nil
	m.errorOnMethod = ""
}

// checkError consumes and returns any pending error.
func (m *MemoryStorage) checkError(method string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.nextError == nil {
		return nil
	}

	// Check if error is for a specific method
	if m.errorOnMethod != "" && m.errorOnMethod != method {
		return nil
	}

	err := m.nextError
	m.nextError = nil
	m.errorOnMethod = ""
	return err
}

// ============================================================================
// Test Control: Delay Injection
// ============================================================================

// SetDelayOnNextCall configures a delay for the next call.
func (m *MemoryStorage) SetDelayOnNextCall(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextDelay = delay
	m.delayOnMethod = ""
}

// SetDelayOnNextCallForMethod configures a delay for a specific method.
func (m *MemoryStorage) SetDelayOnNextCallForMethod(method string, delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextDelay = delay
	m.delayOnMethod = method
}

// ClearDelay removes any pending delay.
func (m *MemoryStorage) ClearDelay() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextDelay = 0
	m.delayOnMethod = ""
}

// checkContextAndDelay checks context cancellation and applies any delay.
func (m *MemoryStorage) checkContextAndDelay(ctx context.Context, method string) error {
	// Check context first
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Check for configured delay
	m.mu.Lock()
	delay := m.nextDelay
	delayMethod := m.delayOnMethod
	if delay > 0 && (delayMethod == "" || delayMethod == method) {
		m.nextDelay = 0
		m.delayOnMethod = ""
	} else {
		delay = 0
	}
	m.mu.Unlock()

	if delay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}

	return nil
}

// ============================================================================
// Test Metrics
// ============================================================================

// GetCallCount returns how many times a method was called.
func (m *MemoryStorage) GetCallCount(method string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.callCounts[method]
}

// GetTotalCallCount returns total calls across all methods.
func (m *MemoryStorage) GetTotalCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	total := 0
	for _, count := range m.callCounts {
		total += count
	}
	return total
}

// ResetCallCounts clears all call counters.
func (m *MemoryStorage) ResetCallCounts() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCounts = make(map[string]int)
}

// ============================================================================
// Test Helpers
// ============================================================================

// CreateTestACAssignment creates a test AC assignment with sensible defaults.
func CreateTestACAssignment(acID string, serverIDs ...string) *ACAssignment {
	servers := make([]ServerInfo, len(serverIDs))
	for i, id := range serverIDs {
		servers[i] = ServerInfo{
			ID:         id,
			IP:         fmt.Sprintf("10.0.0.%d", i+1),
			InternalIP: fmt.Sprintf("192.168.0.%d", i+1),
			AZ:         "us-east-2" + string(rune('a'+i)),
			Port:       62206,
			PubKey:     "test-pubkey-" + id,
		}
	}
	return &ACAssignment{
		ACID:            acID,
		ResourceFQDN:    acID + ".nhp.test",
		CustomerID:      "test-customer",
		AssignedServers: servers,
		Version:         1,
		CreatedAt:       time.Now().Unix(),
		LastSeen:        time.Now().Unix(),
	}
}

// CreateTestLicense creates a test license with sensible defaults.
// The licenseKey parameter is used to compute the SHA256 for lookup.
func CreateTestLicense(licenseKey string, opts ...func(*License)) *License {
	// Compute SHA256 of license key for lookup
	hash := sha256.Sum256([]byte(licenseKey))
	licenseKeySHA256 := hex.EncodeToString(hash[:])

	license := &License{
		LicenseKeySHA256: licenseKeySHA256,
		LicenseKeyHash:   "$2a$10$testhashedlicensekey", // bcrypt hash for validation
		CustomerID:       "test-customer",
		ResourceID:       "test-resource",
		Tier:             "pro",
		MaxACs:           100,
		ExpiresAt:        time.Now().Add(365 * 24 * time.Hour).Unix(),
		Active:           true,
	}

	for _, opt := range opts {
		opt(license)
	}

	return license
}

// CreateTestResource creates a test resource with sensible defaults.
func CreateTestResource(customerID, resourceID, acID string) *Resource {
	return &Resource{
		CustomerID:    customerID,
		ResourceID:    resourceID,
		ResourceFQDN:  resourceID + ".nhp.test",
		ACID:          acID,
		DestHost:      "backend." + resourceID + ".local",
		DestPort:      443,
		OpenTime:      60,
		AuthServiceID: "test-auth-svc",
	}
}
