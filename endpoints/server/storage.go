package server

import (
	"context"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// ============================================================================
// Pluggable Storage Backend Interface (Phase 2)
// See docs/design/PLUGGABLE_STORAGE_BACKEND.md for architecture details.
//
// The storage layer is abstracted to support multiple backends:
// - DynamoDB (default for cloud deployments)
// - etcd (feature flag for on-prem deployments)
//
// All core logic (per-AC assignment, forwarding, Noise K) remains identical
// regardless of backend.
// ============================================================================

// StorageBackend provides access to persistent state for NHP servers.
// Implementations must be thread-safe as they're called from multiple goroutines.
type StorageBackend interface {
	// GetACAssignment retrieves the server assignment for an AC.
	// Returns ErrNotFound if the AC has no assignment.
	GetACAssignment(ctx context.Context, acID string) (*ACAssignment, error)

	// GetACsByServer retrieves all ACs assigned to a specific server.
	// Used for server failover and reassignment.
	GetACsByServer(ctx context.Context, serverID string) ([]ACAssignment, error)

	// GetLicense retrieves license information for a customer/resource combination.
	// Returns ErrNotFound if no license exists.
	GetLicense(ctx context.Context, customerID, resourceFQDN string) (*License, error)

	// GetResource retrieves resource definition by customer and resource ID.
	// Returns ErrNotFound if the resource doesn't exist.
	GetResource(ctx context.Context, customerID, resourceID string) (*Resource, error)

	// GetResourceByACID retrieves resources associated with a specific AC.
	GetResourceByACID(ctx context.Context, acID string) ([]Resource, error)

	// Close releases any resources held by the storage backend.
	Close() error

	// Name returns the backend name for logging/debugging.
	Name() string
}

// ============================================================================
// Data Types
// ============================================================================

// ACAssignment represents an AC's server assignment.
// Each AC is assigned to 3 servers in different AZs for resilience.
type ACAssignment struct {
	ACID            string         `json:"ac_id"`
	ResourceFQDN    string         `json:"resource_fqdn"`
	CustomerID      string         `json:"customer_id"`
	AssignedServers []ServerInfo   `json:"assigned_servers"`
	Version         int            `json:"version"`           // For optimistic locking during reassignment
	ReassignedAt    *int64         `json:"reassigned_at"`     // Unix timestamp, set when Console reassigns
	CreatedAt       int64          `json:"created_at"`
	LastSeen        int64          `json:"last_seen"`
	TTL             *int64         `json:"ttl,omitempty"`     // Unix timestamp for DynamoDB TTL
}

// ServerInfo represents an assigned server's connection details.
type ServerInfo struct {
	ID         string `json:"id"`                    // Server ID (e.g., "srv-abc123")
	IP         string `json:"ip"`                    // Public IP for AC connection
	InternalIP string `json:"internal_ip,omitempty"` // VPC IP for server-to-server forwarding
	AZ         string `json:"az,omitempty"`          // Availability Zone
	Port       int    `json:"port"`                  // NHP UDP port (default 62206)
	PubKey     string `json:"pub_key,omitempty"`     // Server's public key (for forwarding)
}

// License represents customer license information.
type License struct {
	CustomerID     string `json:"customer_id"`
	ResourceFQDN   string `json:"resource_fqdn"`
	LicenseKeyHash string `json:"license_key_hash"` // bcrypt hash
	Tier           string `json:"tier"`             // "free", "pro", "enterprise"
	MaxACs         int    `json:"max_acs"`
	ExpiresAt      int64  `json:"expires_at"`       // Unix timestamp
	Active         bool   `json:"active"`
}

// Resource represents a protected resource definition.
type Resource struct {
	CustomerID    string `json:"customer_id"`
	ResourceID    string `json:"resource_id"`
	ResourceFQDN  string `json:"resource_fqdn"`
	ACID          string `json:"ac_id"`
	DestHost      string `json:"dest_host"`
	DestPort      int    `json:"dest_port"`
	OpenTime      int    `json:"open_time"`      // Seconds
	AuthServiceID string `json:"auth_service_id"`
}

// ============================================================================
// Storage Errors
// ============================================================================

// StorageError represents an error from the storage backend.
type StorageError struct {
	Code    string
	Message string
	Err     error
}

func (e *StorageError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *StorageError) Unwrap() error {
	return e.Err
}

// Common storage error codes
const (
	ErrCodeNotFound         = "NOT_FOUND"
	ErrCodeServiceUnavail   = "SERVICE_UNAVAILABLE"
	ErrCodeValidationFailed = "VALIDATION_FAILED"
	ErrCodeRateLimited      = "RATE_LIMITED"
)

// NewNotFoundError creates a new not-found error.
func NewNotFoundError(msg string) *StorageError {
	return &StorageError{Code: ErrCodeNotFound, Message: msg}
}

// NewServiceUnavailableError creates a new service unavailable error.
func NewServiceUnavailableError(msg string, err error) *StorageError {
	return &StorageError{Code: ErrCodeServiceUnavail, Message: msg, Err: err}
}

// IsNotFoundError returns true if the error is a not-found error.
func IsNotFoundError(err error) bool {
	if se, ok := err.(*StorageError); ok {
		return se.Code == ErrCodeNotFound
	}
	return false
}

// ============================================================================
// Storage Configuration
// ============================================================================

// StorageConfig configures the storage backend.
type StorageConfig struct {
	// Backend specifies which storage backend to use: "dynamodb" or "etcd"
	Backend string `toml:"Backend"`

	// DynamoDB configuration (used when Backend = "dynamodb")
	DynamoDB DynamoDBConfig `toml:"DynamoDB"`

	// Etcd configuration (used when Backend = "etcd")
	Etcd EtcdStorageConfig `toml:"Etcd"`

	// Cache configuration
	Cache CacheConfig `toml:"Cache"`
}

// DynamoDBConfig configures the DynamoDB storage backend.
type DynamoDBConfig struct {
	Region              string `toml:"Region"`
	LicensesTable       string `toml:"LicensesTable"`
	ACAssignmentsTable  string `toml:"ACAssignmentsTable"`
	ResourcesTable      string `toml:"ResourcesTable"`
	Endpoint            string `toml:"Endpoint,omitempty"` // For local development
}

// EtcdStorageConfig configures the etcd storage backend.
type EtcdStorageConfig struct {
	Endpoints  []string `toml:"Endpoints"`
	TLS        bool     `toml:"TLS"`
	CACert     string   `toml:"CACert,omitempty"`
	ClientCert string   `toml:"ClientCert,omitempty"`
	ClientKey  string   `toml:"ClientKey,omitempty"`
	Username   string   `toml:"Username,omitempty"`
	Password   string   `toml:"Password,omitempty"`
}

// CacheConfig configures the assignment cache.
type CacheConfig struct {
	// MaxEntries is the maximum number of entries in the LRU cache.
	MaxEntries int `toml:"MaxEntries"`

	// DefaultTTL is the default cache TTL in seconds.
	DefaultTTL int `toml:"DefaultTTL"`

	// ReassignmentTTL is the short TTL used during reassignment (in seconds).
	ReassignmentTTL int `toml:"ReassignmentTTL"`

	// ReassignmentWindow is how long after reassignment to use short TTL (in seconds).
	ReassignmentWindow int `toml:"ReassignmentWindow"`
}

// DefaultStorageConfig returns the default storage configuration.
func DefaultStorageConfig() StorageConfig {
	return StorageConfig{
		Backend: "dynamodb",
		DynamoDB: DynamoDBConfig{
			Region:              "us-east-2",
			LicensesTable:       "nhp-licenses",
			ACAssignmentsTable:  "nhp-ac-assignments",
			ResourcesTable:      "nhp-resources",
		},
		Cache: CacheConfig{
			MaxEntries:         10000,
			DefaultTTL:         60,  // 60 seconds
			ReassignmentTTL:    5,   // 5 seconds
			ReassignmentWindow: 300, // 5 minutes
		},
	}
}

// ============================================================================
// Cached Storage Wrapper
// ============================================================================

// CachedStorage wraps a StorageBackend with an LRU cache.
type CachedStorage struct {
	backend StorageBackend
	cache   *AssignmentCache
}

// Compile-time interface compliance check
var _ StorageBackend = (*CachedStorage)(nil)

// NewCachedStorage creates a new cached storage wrapper.
func NewCachedStorage(backend StorageBackend, config CacheConfig) *CachedStorage {
	return &CachedStorage{
		backend: backend,
		cache:   NewAssignmentCache(config),
	}
}

// GetACAssignment retrieves the AC assignment, using cache when available.
func (cs *CachedStorage) GetACAssignment(ctx context.Context, acID string) (*ACAssignment, error) {
	// Check cache first
	if assignment := cs.cache.Get(acID); assignment != nil {
		return assignment, nil
	}

	// Cache miss - fetch from backend
	assignment, err := cs.backend.GetACAssignment(ctx, acID)
	if err != nil {
		return nil, err
	}

	// Store in cache
	cs.cache.Set(acID, assignment)
	return assignment, nil
}

// GetACsByServer retrieves ACs assigned to a server (not cached, used rarely).
func (cs *CachedStorage) GetACsByServer(ctx context.Context, serverID string) ([]ACAssignment, error) {
	return cs.backend.GetACsByServer(ctx, serverID)
}

// GetLicense retrieves license (not cached, used during registration only).
func (cs *CachedStorage) GetLicense(ctx context.Context, customerID, resourceFQDN string) (*License, error) {
	return cs.backend.GetLicense(ctx, customerID, resourceFQDN)
}

// GetResource retrieves resource definition (could be cached in future).
func (cs *CachedStorage) GetResource(ctx context.Context, customerID, resourceID string) (*Resource, error) {
	return cs.backend.GetResource(ctx, customerID, resourceID)
}

// GetResourceByACID retrieves resources by AC ID (could be cached in future).
func (cs *CachedStorage) GetResourceByACID(ctx context.Context, acID string) ([]Resource, error) {
	return cs.backend.GetResourceByACID(ctx, acID)
}

// Close releases resources.
func (cs *CachedStorage) Close() error {
	return cs.backend.Close()
}

// Name returns the backend name.
func (cs *CachedStorage) Name() string {
	return cs.backend.Name() + " (cached)"
}

// InvalidateACAssignment removes an AC assignment from the cache.
// Note: This is intentionally NOT part of the StorageBackend interface because
// cache invalidation is specific to CachedStorage. Callers needing this method
// should type-assert to *CachedStorage or use it directly when constructing.
func (cs *CachedStorage) InvalidateACAssignment(acID string) {
	cs.cache.Delete(acID)
}

// ============================================================================
// Assignment Cache with Adaptive TTL (using hashicorp/golang-lru)
// ============================================================================

// AssignmentCacheEntry stores a cached assignment with metadata.
type AssignmentCacheEntry struct {
	Assignment *ACAssignment
	FetchedAt  time.Time
}

// AssignmentCache implements an LRU cache with adaptive TTL for AC assignments.
// Uses hashicorp/golang-lru for efficient O(1) LRU eviction.
// Thread-safe: the underlying LRU is thread-safe, additional mutex for TTL checks.
type AssignmentCache struct {
	config CacheConfig
	cache  *lru.Cache[string, *AssignmentCacheEntry]
	mu     sync.RWMutex // Protects TTL-based expiration logic
}

// NewAssignmentCache creates a new assignment cache.
func NewAssignmentCache(config CacheConfig) *AssignmentCache {
	maxEntries := config.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 10000 // Default
	}

	cache, err := lru.New[string, *AssignmentCacheEntry](maxEntries)
	if err != nil {
		// This should never happen with valid size
		panic("failed to create LRU cache: " + err.Error())
	}

	return &AssignmentCache{
		config: config,
		cache:  cache,
	}
}

// Get retrieves an assignment from cache if valid.
func (c *AssignmentCache) Get(acID string) *ACAssignment {
	entry, ok := c.cache.Get(acID)
	if !ok {
		return nil
	}

	// Check TTL
	c.mu.RLock()
	ttl := c.getTTL(entry)
	c.mu.RUnlock()

	if time.Since(entry.FetchedAt) > ttl {
		c.cache.Remove(acID)
		return nil
	}

	return entry.Assignment
}

// Set stores an assignment in the cache.
// The LRU automatically evicts the least recently used entry when at capacity.
func (c *AssignmentCache) Set(acID string, assignment *ACAssignment) {
	entry := &AssignmentCacheEntry{
		Assignment: assignment,
		FetchedAt:  time.Now(),
	}
	c.cache.Add(acID, entry)
}

// Delete removes an assignment from the cache.
func (c *AssignmentCache) Delete(acID string) {
	c.cache.Remove(acID)
}

// getTTL calculates the appropriate TTL for an entry.
// Uses short TTL during reassignment window for faster convergence.
func (c *AssignmentCache) getTTL(entry *AssignmentCacheEntry) time.Duration {
	if entry.Assignment.ReassignedAt != nil {
		timeSinceReassign := time.Since(time.Unix(*entry.Assignment.ReassignedAt, 0))
		if timeSinceReassign < time.Duration(c.config.ReassignmentWindow)*time.Second {
			return time.Duration(c.config.ReassignmentTTL) * time.Second
		}
	}
	return time.Duration(c.config.DefaultTTL) * time.Second
}

// Len returns the number of entries in the cache.
func (c *AssignmentCache) Len() int {
	return c.cache.Len()
}
