package server

import (
	"context"
	"errors"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// ============================================================================
// Pluggable Storage Backend Interface
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
	//
	// Ownership contract: the returned *ACAssignment is exclusively
	// owned by the caller and safe to mutate. Implementations must
	// return a freshly-allocated copy per call, never a pointer aliased
	// with internal state (#1540). Every mutating caller depends on this.
	GetACAssignment(ctx context.Context, acID string) (*ACAssignment, error)

	// GetACsByServer retrieves all ACs assigned to a specific server.
	// Used for server failover and reassignment.
	GetACsByServer(ctx context.Context, serverID string) ([]ACAssignment, error)

	// GetLicense retrieves license information using the license key.
	// The licenseKey is the plaintext key - the implementation computes SHA256 for lookup.
	// License keys are globally unique, so no customer ID is needed.
	// Returns ErrNotFound if no license exists.
	GetLicense(ctx context.Context, licenseKey string) (*License, error)

	// GetResource retrieves resource definition by customer and resource ID.
	// Returns ErrNotFound if the resource doesn't exist.
	GetResource(ctx context.Context, customerID, resourceID string) (*Resource, error)

	// GetResourceByACID retrieves resources associated with a specific AC.
	GetResourceByACID(ctx context.Context, acID string) ([]Resource, error)

	// SaveACAssignment stores or updates an AC assignment.
	// Used by server-side auto-assignment to persist AC-to-server mappings.
	//
	// The assignment is read-only to the backend: CachedStorage passes a
	// Clone (#1545), so an implementation must not communicate results
	// back by mutating the input in place (e.g. stamping a generated
	// field) — the caller would not observe it. Return such state by
	// other means.
	SaveACAssignment(ctx context.Context, assignment *ACAssignment) error

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
	ACID            string       `json:"ac_id" dynamodbav:"ac_id"`
	ResourceFQDN    string       `json:"resource_fqdn,omitempty" dynamodbav:"resource_fqdn,omitempty"`
	CustomerID      string       `json:"customer_id,omitempty" dynamodbav:"customer_id,omitempty"`
	AssignedServers []ServerInfo `json:"assigned_servers" dynamodbav:"assigned_servers"`
	Version         int          `json:"version" dynamodbav:"version"`             // For optimistic locking during reassignment
	ReassignedAt    *int64       `json:"reassigned_at" dynamodbav:"reassigned_at"` // Unix timestamp, set when Console reassigns
	CreatedAt       int64        `json:"created_at" dynamodbav:"created_at"`
	LastSeen        int64        `json:"last_seen" dynamodbav:"last_seen"`
	TTL             *int64       `json:"ttl,omitempty" dynamodbav:"ttl,omitempty"` // Unix timestamp for DynamoDB TTL
	// RevokedPubKeys is the per-acId denylist of padded standard
	// base64 AC static public keys rejected at registration (#1507).
	//
	// DDB encoding: `,stringset` forces a String Set (SS) so the
	// operator runbook can use idempotent ADD / DELETE update
	// expressions. Round-trip is fenced by
	// TestACAssignment_RevokedPubKeys_RoundTripsAsStringSet — a
	// future tag-edit that flips encoding back to L (List) would
	// silently fail to unmarshal hand-written SS rows, so the test
	// surfaces the regression at PR time.
	//
	// Construction contract: callers SHOULD use nil for the empty
	// case, NOT []string{}. The SDK encodes nil as "attribute
	// omitted" and []string{} as "attribute NULL"; both are
	// DDB-accepted but create silent shape divergence between rows.
	// This is enforced, not just documented: Clone() normalizes
	// empty → nil, and CachedStorage.SaveACAssignment Clones every
	// write at the boundary (#1545), so a direct
	// ACAssignment{RevokedPubKeys: []string{}} save still round-trips
	// as nil. #1536's CLI normalizes on the operator-tooling side too.
	RevokedPubKeys []string `json:"revoked_pubkeys,omitempty" dynamodbav:"revoked_pubkeys,omitempty,stringset"`

	// SessionControlTargets is the authoritative bounded set of AC process
	// boots that may own NHP access rules for this AC ID. A target remains
	// required when its live control connection disappears; membership changes
	// only when the same authenticated AC static key reports a completed newer
	// boot flush, or through an explicit control-plane decommission.
	SessionControlTargets []ACSessionControlTarget `json:"session_control_targets,omitempty" dynamodbav:"session_control_targets,omitempty"`
}

// ACSessionControlTarget identifies one fail-closed AC process boot. PublicKey
// is the authenticated Curve25519 static key in canonical standard base64;
// BootID is a per-process random identity and FlushGeneration is monotonic
// within that boot.
type ACSessionControlTarget struct {
	PublicKey       string `json:"public_key" dynamodbav:"public_key"`
	BootID          string `json:"boot_id" dynamodbav:"boot_id"`
	FlushGeneration uint64 `json:"flush_generation" dynamodbav:"flush_generation"`
	RegisteredAt    int64  `json:"registered_at" dynamodbav:"registered_at"`
	LastSeen        int64  `json:"last_seen" dynamodbav:"last_seen"`
}

// Clone returns a copy of the assignment, safe to mutate without
// affecting cached pointers. Pointer fields and the AssignedServers
// slice are deep-copied; callers can freely modify the clone.
func (a *ACAssignment) Clone() *ACAssignment {
	clone := *a
	if a.TTL != nil {
		ttl := *a.TTL
		clone.TTL = &ttl
	}
	if a.ReassignedAt != nil {
		ra := *a.ReassignedAt
		clone.ReassignedAt = &ra
	}
	if a.AssignedServers != nil {
		clone.AssignedServers = make([]ServerInfo, len(a.AssignedServers))
		copy(clone.AssignedServers, a.AssignedServers)
	}
	if a.SessionControlTargets != nil {
		clone.SessionControlTargets = make([]ACSessionControlTarget, len(a.SessionControlTargets))
		copy(clone.SessionControlTargets, a.SessionControlTargets)
	}
	// Normalize empty → nil per the RevokedPubKeys construction
	// contract above. The `clone := *a` above shallow-copies the
	// slice header, so a non-nil empty input would otherwise survive
	// as a non-nil empty slice in the clone.
	if len(a.RevokedPubKeys) > 0 {
		clone.RevokedPubKeys = make([]string, len(a.RevokedPubKeys))
		copy(clone.RevokedPubKeys, a.RevokedPubKeys)
	} else {
		clone.RevokedPubKeys = nil
	}
	return &clone
}

// ServerInfo represents an assigned server's connection details.
type ServerInfo struct {
	ID         string `json:"id" dynamodbav:"id"`                                       // Server ID (e.g., "srv-abc123")
	IP         string `json:"ip" dynamodbav:"ip"`                                       // Public IP for AC connection
	InternalIP string `json:"internal_ip,omitempty" dynamodbav:"internal_ip,omitempty"` // VPC IP for server-to-server forwarding
	AZ         string `json:"az,omitempty" dynamodbav:"az,omitempty"`                   // Availability Zone
	Port       int    `json:"port" dynamodbav:"port"`                                   // NHP UDP port (default 62206)
	HTTPPort   int    `json:"http_port,omitempty" dynamodbav:"http_port,omitempty"`     // Direct private HTTP port for authenticated fleet control
	PubKey     string `json:"pub_key,omitempty" dynamodbav:"pub_key,omitempty"`         // Server's public key (for forwarding)
	ASGName    string `json:"asg_name,omitempty" dynamodbav:"asg_name,omitempty"`       // ASG name for blue/green filtering
}

// serverInfosToRedirectTargets converts a slice of ServerInfo to RedirectTarget,
// using VPC private IPs for direct AC-to-server connectivity.
// sharedPubKey is used as fallback when a server's pubkey is empty (e.g., during
// rolling updates when Cloud Map cache hasn't picked up the new server's key yet).
//
// Servers with empty InternalIP are skipped loudly: emitting a hostname-only /
// IP-less RedirectTarget would violate the RedirectTarget contract and corrupt
// the AC's assignedServers slice (see #832). This should never happen in
// practice — InternalIP is set at server startup by utils.GetLocalOutbound-
// Address() — but we defend against it rather than silently emit an invalid
// target.
func serverInfosToRedirectTargets(servers []ServerInfo, sharedPubKey string) []common.RedirectTarget {
	targets := make([]common.RedirectTarget, 0, len(servers))
	for _, srv := range servers {
		if srv.InternalIP == "" {
			log.Error("BUG: serverInfosToRedirectTargets skipping server %q with empty InternalIP (see #832)", srv.ID)
			continue
		}
		pubKey := srv.PubKey
		if pubKey == "" {
			pubKey = sharedPubKey
		}
		targets = append(targets, common.RedirectTarget{
			IP:           srv.InternalIP,
			Port:         srv.Port,
			PubKeyBase64: pubKey,
			AZ:           srv.AZ,
			ServerID:     srv.ID,
		})
	}
	return targets
}

// License represents customer license information.
// License keys are globally unique and serve as the primary lookup key.
type License struct {
	LicenseKeySHA256 string `json:"license_key_sha256" dynamodbav:"license_key_sha256"` // SHA256 of plaintext key (partition key for lookup)
	LicenseKeyHash   string `json:"license_key_hash" dynamodbav:"license_key_hash"`     // bcrypt hash for validation
	CustomerID       string `json:"customer_id" dynamodbav:"customer_id"`               // Customer ID (ULID, for GSI queries)
	ResourceID       string `json:"resource_id" dynamodbav:"resource_id"`               // Resource identifier (informational)
	Tier             string `json:"tier" dynamodbav:"tier"`                             // "free", "pro", "enterprise"
	MaxACs           int    `json:"max_acs" dynamodbav:"max_acs"`
	ExpiresAt        int64  `json:"expires_at" dynamodbav:"expires_at"` // Unix timestamp (0 = never expires)
	Active           bool   `json:"active" dynamodbav:"active"`
	CreatedAt        int64  `json:"created_at" dynamodbav:"created_at"` // Unix timestamp
	UpdatedAt        int64  `json:"updated_at" dynamodbav:"updated_at"` // Unix timestamp
	// BoundPubKeys is the allowlist of base64-encoded AC static public
	// keys permitted to register under this license (#1155).
	//
	// Pre-#1155 a license was an unbound bearer token: anyone holding
	// the key could register with any keypair for any acId, and the
	// server dumped plaintext NHP_AOP to the attacker's connection.
	// This field bolts identity onto the license — the server-side
	// gate rejects registrations whose ppd.RemotePubKey doesn't appear
	// in this list.
	//
	// Empty list = legacy / unprovisioned. Permit mode logs a legacy
	// warning and accepts (so the gate can roll out without breaking
	// existing deployments); strict mode rejects with 52013 so
	// operators can't quietly keep shipping unbound licenses once the
	// gate is flipped. Populate with the nhp-license-admin CLI
	// (endpoints/licenseadmin/main, #1262); strict-flip runbook at
	// docs/runbooks/license-pubkey-strict-flip.md.
	//
	// Canonical encoding: entries MUST be padded standard base64
	// (RFC 4648 §4 — alphabet A-Z a-z 0-9 + /, with = padding). The
	// server compares entries against base64.StdEncoding.EncodeToString
	// of ppd.RemotePubKey with exact string equality. URL-safe base64
	// (RFC 4648 §5 — alphabet with - _), unpadded base64, or entries
	// with leading/trailing whitespace will NOT match a legitimate
	// registration and the AC will be rejected with
	// ErrLicensePubkeyMismatch — indistinguishable from an actual
	// attack. nhp-license-admin enforces this canonical encoding at
	// write time (see licenseadmin.CanonicalizeBoundPubKey, #1262).
	BoundPubKeys []string `json:"bound_pubkeys,omitempty" dynamodbav:"bound_pubkeys,omitempty"`
}

// Resource represents a protected resource definition.
type Resource struct {
	CustomerID    string `json:"customer_id" dynamodbav:"customer_id"`
	ResourceID    string `json:"resource_id" dynamodbav:"resource_id"`
	ResourceFQDN  string `json:"resource_fqdn" dynamodbav:"resource_fqdn"`
	ACID          string `json:"ac_id" dynamodbav:"ac_id"`
	DestHost      string `json:"dest_host" dynamodbav:"dest_host"`
	DestPort      int    `json:"dest_port" dynamodbav:"dest_port"`
	PortSuffix    bool   `json:"port_suffix,omitempty" dynamodbav:"port_suffix,omitempty"`
	OpenTime      int    `json:"open_time" dynamodbav:"open_time"` // Seconds
	AuthServiceID string `json:"auth_service_id" dynamodbav:"auth_service_id"`
	TTL           int64  `json:"ttl,omitempty" dynamodbav:"ttl,omitempty"`

	// qURL v2 protected-resource public key (read side, P1b). qurl-service
	// (P1a) writes these as ADDITIVE attributes on the catalog row using the
	// exact attribute names below; they do NOT change the (customer_id,
	// resource_id) key schema. `omitempty` + tolerant UnmarshalMap keep legacy
	// / feature-off rows (which carry neither attribute) decoding unchanged.
	//
	// CONTRACT — these two `dynamodbav` names are the entire cross-repo wire
	// contract and must stay byte-identical to the writer. The writer is
	// qurl-service `internal/repository/dynamodb/nhp_resource_catalog_repo.go`
	// (qURL v2 P1a, qurl-service PR #993). Because P1b is a dumb carrier with
	// no validation, a name typo/drift on either side surfaces an EMPTY value
	// rather than erroring — a failure mode that escapes both repos' unit
	// tests. If you rename either attribute, change both repos in lockstep.
	// (A cross-repo mint→read e2e test is the durable guard; deferred to the
	// phase that first makes this value load-bearing — P3/P4.)
	//
	// P1b only READS and SURFACES these (onto common.ResourceData) so later
	// admission phases (P3/P4) can key on the resource public key. P1b does NOT
	// validate, decode, or admission-gate on them — a malformed value still
	// surfaces; verification is a later phase.
	//
	//   ResourcePublicKeyB64:  unpadded base64url DER SPKI of the resource pubkey
	//   ResourcePublicKeyHash: lowercase hex SHA-256 of the DECODED DER bytes
	ResourcePublicKeyB64  string `json:"resource_public_key_b64,omitempty" dynamodbav:"resource_public_key_b64,omitempty"`
	ResourcePublicKeyHash string `json:"resource_public_key_hash,omitempty" dynamodbav:"resource_public_key_hash,omitempty"`
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

// ACAssignmentAuthorityError marks candidate-routing failures that cannot use
// the ordinary availability-first assignment fallback. A candidate server must
// prove the distinct active row before it can admit the physical AC; otherwise
// a missing/malformed authority row or a transient read failure could bypass a
// live revoked_pubkeys entry.
type ACAssignmentAuthorityError struct{ Err error }

func (e *ACAssignmentAuthorityError) Error() string {
	return "AC assignment authority unavailable: " + e.Err.Error()
}

func (e *ACAssignmentAuthorityError) Unwrap() error { return e.Err }

func NewACAssignmentAuthorityError(err error) *ACAssignmentAuthorityError {
	return &ACAssignmentAuthorityError{Err: err}
}

func IsACAssignmentAuthorityError(err error) bool {
	var authorityErr *ACAssignmentAuthorityError
	return errors.As(err, &authorityErr)
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
	ErrCodeVersionConflict  = "VERSION_CONFLICT"
)

// NewNotFoundError creates a new not-found error.
func NewNotFoundError(msg string) *StorageError {
	return &StorageError{Code: ErrCodeNotFound, Message: msg}
}

// NewServiceUnavailableError creates a new service unavailable error.
func NewServiceUnavailableError(msg string, err error) *StorageError {
	return &StorageError{Code: ErrCodeServiceUnavail, Message: msg, Err: err}
}

// NewVersionConflictError creates a new version conflict error.
func NewVersionConflictError(msg string) *StorageError {
	return &StorageError{Code: ErrCodeVersionConflict, Message: msg}
}

// IsNotFoundError returns true if the error is a not-found error.
func IsNotFoundError(err error) bool {
	var se *StorageError
	if errors.As(err, &se) {
		return se.Code == ErrCodeNotFound
	}
	return false
}

// IsVersionConflictError returns true if the error is a version conflict error.
func IsVersionConflictError(err error) bool {
	var se *StorageError
	if errors.As(err, &se) {
		return se.Code == ErrCodeVersionConflict
	}
	return false
}

// ============================================================================
// Storage Configuration
// ============================================================================

// Storage backend type constants.
const (
	StorageBackendDynamoDB = "dynamodb"
	StorageBackendEtcd     = "etcd"
)

// SlowOperationThreshold is the duration above which a storage operation is
// considered slow. Used by both MetricsStorage (to increment a slow counter)
// and LoggingStorage (to escalate log level to Warning).
const SlowOperationThreshold = 500 * time.Millisecond

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

	// CloudMap configuration for server health discovery.
	// Used to filter stale AC assignments pointing to terminated servers.
	// See docs/design/PLUGGABLE_STORAGE_BACKEND.md for details.
	CloudMap CloudMapConfig `toml:"CloudMap"`

	// RateLimit configuration for license validation brute-force prevention.
	RateLimit RateLimitConfig `toml:"RateLimit"`
}

// DynamoDBConfig configures the DynamoDB storage backend.
type DynamoDBConfig struct {
	AccountID                  string `toml:"AccountID"`
	Region                     string `toml:"Region"`
	LicensesTable              string `toml:"LicensesTable"`
	ACAssignmentsTable         string `toml:"ACAssignmentsTable"`
	ACAssignmentAuthorityTable string `toml:"ACAssignmentAuthorityTable"`
	ResourcesTable             string `toml:"ResourcesTable"`
	// AgentKeysTable holds sidecar agent registrations written by
	// qurl-service's bootstrap path. nhp-server reads it on every
	// knock receipt via the `pubkey-index` GSI to resolve the
	// presented public key back to a registered agent. Empty
	// disables the lookup (legacy etcd/file path stays in effect).
	// PR-1b plan reference.
	AgentKeysTable string `toml:"AgentKeysTable"`
	// RelayKeysTable is the reserved dynamic relay registry table. It is
	// intentionally empty today because relay authorization still comes from
	// relay.toml; if a future registry wires this, relay.toml must not coexist
	// with it or the file watcher can wipe dynamically resolved relay peers.
	RelayKeysTable string `toml:"RelayKeysTable"`
	// AckTokensTable holds short-lived AC-issued ACK token metadata.
	// nhp-server writes an item when it publishes ackMsg.ACTokens and
	// /nhp/internal/token/validate reads it on a local tokenStore miss
	// so validation works across a multi-server fleet.
	AckTokensTable string `toml:"AckTokensTable"`
	// SessionControlTable holds non-expiring authority plus durable session,
	// close-operation, and per-target recovery rows. Pending rows never rely on
	// DynamoDB TTL for correctness; recovery reads the base PK/SK strongly.
	SessionControlTable string `toml:"SessionControlTable"`
	// NativeSessionOperations enables the sandbox-only durable registered-agent
	// operation protocol. Production remains false until a separately reviewed
	// matched-cohort rollout is authorized.
	NativeSessionOperations bool   `toml:"NativeSessionOperations"`
	Endpoint                string `toml:"Endpoint,omitempty"` // For local development
}

// EtcdStorageConfig configures the etcd storage backend.
type EtcdStorageConfig struct {
	Endpoints  []string `toml:"Endpoints"`
	TLS        bool     `toml:"TLS"`
	CACert     string   `toml:"CACert,omitempty"`
	ClientCert string   `toml:"ClientCert,omitempty"`
	ClientKey  string   `toml:"ClientKey,omitempty"` //nolint:gosec // G117: TOML tag only (no JSON), never serialized — TLS client key path
	Username   string   `toml:"Username,omitempty"`
	Password   string   `toml:"Password,omitempty"` //nolint:gosec // G117: TOML tag only (no JSON), never serialized — etcd auth config
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
			SessionControlTable: "nhp-session-control",
		},
		Cache: CacheConfig{
			MaxEntries:         10000,
			DefaultTTL:         60,  // 60 seconds
			ReassignmentTTL:    5,   // 5 seconds
			ReassignmentWindow: 300, // 5 minutes
		},
		CloudMap: CloudMapConfig{
			Enabled: false, // Disabled by default, enable via storage.toml
		},
	}
}

// ============================================================================
// Cached Storage Wrapper
// ============================================================================

// CachedStorage wraps a StorageBackend with an LRU cache.
type CachedStorage struct {
	backend                 StorageBackend
	cache                   *AssignmentCache
	bypassACAssignmentCache bool
}

// Compile-time interface compliance check
var _ StorageBackend = (*CachedStorage)(nil)

// NewCachedStorage creates a new cached storage wrapper.
func NewCachedStorage(backend StorageBackend, config CacheConfig) *CachedStorage {
	return &CachedStorage{
		backend:                 backend,
		cache:                   NewAssignmentCache(config),
		bypassACAssignmentCache: backendUsesExternalACAssignmentAuthority(backend),
	}
}

// backendUsesExternalACAssignmentAuthority identifies the candidate-only
// routing mode through the normal decorator chain. In that mode each
// assignment read must reach DynamoDB so a newly-added active-table
// revoked_pubkeys member is authoritative for the next AOL; caching the merged
// row would extend admission after revocation. A malformed/cyclic wrapper chain
// fails safe by bypassing the cache.
func backendUsesExternalACAssignmentAuthority(backend StorageBackend) bool {
	type cacheSafeLeaf interface{ acAssignmentCacheSafeLeaf() }
	type unwrapper interface{ Backend() StorageBackend }
	for hops := 0; backend != nil && hops < unwrapMaxHops; hops++ {
		if ddb, ok := backend.(*DynamoDBStorage); ok {
			return ddb.config.ACAssignmentAuthorityTable != ""
		}
		if _, ok := backend.(cacheSafeLeaf); ok {
			return false
		}
		wrapped, ok := backend.(unwrapper)
		if !ok {
			return true
		}
		next := wrapped.Backend()
		if next == backend {
			return true
		}
		backend = next
	}
	return backend != nil
}

// acAssignmentCacheSafeLeaf is an explicit opt-in. New opaque storage
// implementations and decorators bypass the assignment cache until they
// expose their backend or establish that they have no external revocation
// authority hidden below them.
func (*MemoryStorage) acAssignmentCacheSafeLeaf() {}
func (*EtcdStorage) acAssignmentCacheSafeLeaf()   {}

// GetACAssignment retrieves the AC assignment, using cache when available.
//
// Per the StorageBackend.GetACAssignment ownership contract, the
// returned *ACAssignment is an exclusively-owned copy. The single tail
// Clone enforces this on BOTH the cache-hit and cache-miss paths — on a
// miss the freshly-fetched pointer is aliased by the cache entry just
// Set, so it can no more be returned raw than the hit pointer can. (The
// issue's AssignmentCache.Get-only sketch missed the miss path; cloning
// at this boundary covers both.) Without it, a future in-place mutator
// would race the F4/F5 registration kernels reading the cached entry on
// a concurrent AOL (#1540). The cost is one Clone per call — a shallow
// struct copy plus small slice copies — immaterial next to the work each
// call fronts: a storage round-trip on a cache miss, and on the native forward
// path the cross-server round-trip. Those forward lookups do run per knock that needs
// forwarding, but prod forward traffic is sparse and the registration
// kernels are periodic, so the rate is low regardless.
func (cs *CachedStorage) GetACAssignment(ctx context.Context, acID string) (*ACAssignment, error) {
	if cs.bypassACAssignmentCache {
		assignment, err := cs.backend.GetACAssignment(ctx, acID)
		if err != nil || assignment == nil {
			return assignment, err
		}
		return assignment.Clone(), nil
	}
	assignment := cs.cache.Get(acID)
	if assignment == nil {
		fetched, err := cs.backend.GetACAssignment(ctx, acID)
		if err != nil {
			return nil, err
		}
		// Defense against a backend (nil, nil) contract violation:
		// return gracefully rather than caching nil or nil-derefing in
		// the tail Clone. A compliant backend returns ErrNotFound, never
		// (nil, nil); this preserves the pre-clone behavior and mirrors
		// the same guard in evaluateACPubkeyRevokeVerdict so the gate's
		// documented nil-defense stays reachable through the cache layer.
		if fetched == nil {
			return nil, nil
		}
		cs.cache.Set(acID, fetched)
		assignment = fetched
	}
	return assignment.Clone(), nil
}

// GetACsByServer retrieves ACs assigned to a server (not cached, used rarely).
func (cs *CachedStorage) GetACsByServer(ctx context.Context, serverID string) ([]ACAssignment, error) {
	return cs.backend.GetACsByServer(ctx, serverID)
}

// GetLicense retrieves license (not cached, used during registration only).
func (cs *CachedStorage) GetLicense(ctx context.Context, licenseKey string) (*License, error) {
	return cs.backend.GetLicense(ctx, licenseKey)
}

// GetResource retrieves resource definition (could be cached in future).
func (cs *CachedStorage) GetResource(ctx context.Context, customerID, resourceID string) (*Resource, error) {
	return cs.backend.GetResource(ctx, customerID, resourceID)
}

// GetResourceByACID retrieves resources by AC ID (could be cached in future).
func (cs *CachedStorage) GetResourceByACID(ctx context.Context, acID string) ([]Resource, error) {
	return cs.backend.GetResourceByACID(ctx, acID)
}

// SaveACAssignment stores an AC assignment (write-through: backend then cache).
//
// The assignment is Cloned once at this boundary, which does two jobs:
// it normalizes RevokedPubKeys per the field's construction contract
// (see ACAssignment.RevokedPubKeys) so a direct save that skips Clone
// still round-trips correctly (#1545), and it de-aliases the cached
// entry from the caller's pointer — the write-side mirror of
// GetACAssignment's owned-copy contract (#1540).
func (cs *CachedStorage) SaveACAssignment(ctx context.Context, assignment *ACAssignment) error {
	toSave := assignment.Clone()
	if err := cs.backend.SaveACAssignment(ctx, toSave); err != nil {
		return err
	}
	if cs.bypassACAssignmentCache {
		return nil
	}
	// toSave is deliberately shared between the backend write and the
	// cache entry: the StorageBackend.SaveACAssignment contract forbids
	// backends from mutating the input, so this aliasing can't
	// reintroduce the cache/caller sharing #1540 removed.
	cs.cache.Set(toSave.ACID, toSave)
	return nil
}

// Close releases resources.
func (cs *CachedStorage) Close() error {
	return cs.backend.Close()
}

// Name returns the backend name.
func (cs *CachedStorage) Name() string {
	return cs.backend.Name() + " (cached)"
}

// Backend returns the underlying storage backend.
// This allows callers to unwrap the cache layer for type assertions
// (e.g., checking if the underlying backend implements DynamoDBPinger).
func (cs *CachedStorage) Backend() StorageBackend {
	return cs.backend
}

// Pinger is the interface for storage backends that support health checks.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Ping forwards to the underlying backend's Ping method if available.
// This allows health checks to work through the cache layer.
func (cs *CachedStorage) Ping(ctx context.Context) error {
	if pinger, ok := cs.backend.(Pinger); ok {
		return pinger.Ping(ctx)
	}
	// Backend doesn't support Ping - consider healthy
	return nil
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
//
// It returns the cache's INTERNAL pointer, not a copy — the sole caller
// is CachedStorage.GetACAssignment, which Clones before handing the
// value to application code (#1540). Do not return this pointer to a
// caller that may mutate it without cloning first.
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
