package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/OpenNHP/opennhp/nhp/etcd"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// ============================================================================
// etcd Storage Backend
// See docs/design/PLUGGABLE_STORAGE_BACKEND.md for architecture details.
//
// Feature-flagged storage backend for on-prem deployments.
// Uses etcd for:
// - /nhp/ac-assignments/{ac_id}: AC-to-server assignment mapping
// - /nhp/licenses/{license_key_sha256}: License validation (globally unique keys)
// - /nhp/resources/{customer_id}/{resource_id}: Resource definitions per customer
// - /nhp/resources-by-ac/{ac_id}/{resource_id}: Secondary index for resources by AC
//
// Note on secondary indexes:
// The /nhp/resources-by-ac/ index is maintained by Console when writing resources.
// This backend only reads from etcd; Console is responsible for write operations.
//
// Context handling:
// The GetValueWithKey/SetValueWithKey methods propagate the caller's context
// to etcd operations, enabling proper timeout and cancellation support.
// ============================================================================

const (
	// Key prefixes for etcd storage
	etcdACAssignmentsPrefix = "/nhp/ac-assignments/"
	etcdLicensesPrefix      = "/nhp/licenses/"
	etcdResourcesPrefix     = "/nhp/resources/"
	etcdResourcesByACPrefix = "/nhp/resources-by-ac/"
)

// EtcdStorage implements StorageBackend using etcd.
type EtcdStorage struct {
	conn   *etcd.EtcdConn
	config EtcdStorageConfig
}

// Compile-time interface compliance check
var _ StorageBackend = (*EtcdStorage)(nil)

// NewEtcdStorage creates a new etcd storage backend.
func NewEtcdStorage(ctx context.Context, cfg EtcdStorageConfig) (*EtcdStorage, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("etcd endpoints are required")
	}

	conn := &etcd.EtcdConn{
		Endpoints:  cfg.Endpoints,
		Username:   cfg.Username,
		Password:   cfg.Password,
		TLS:        cfg.TLS,
		CACert:     cfg.CACert,
		ClientCert: cfg.ClientCert,
		ClientKey:  cfg.ClientKey,
	}

	if err := conn.InitClient(); err != nil {
		return nil, fmt.Errorf("failed to initialize etcd client: %w", err)
	}

	storage := &EtcdStorage{
		conn:   conn,
		config: cfg,
	}

	log.Info("etcd storage initialized: endpoints=%v, tls=%v",
		cfg.Endpoints, cfg.TLS)

	return storage, nil
}

// Name returns the backend name.
func (e *EtcdStorage) Name() string {
	return "etcd"
}

// Close releases resources.
func (e *EtcdStorage) Close() error {
	if e.conn != nil {
		e.conn.Close()
	}
	return nil
}

// Ping checks if etcd is reachable and responsive.
// This is used for health checks to verify the storage backend is available.
func (e *EtcdStorage) Ping(ctx context.Context) error {
	if e.conn == nil || e.conn.Client() == nil {
		return etcd.ErrClientNotInitialized
	}

	// Get status from the first endpoint
	// NOTE: For clustered etcd deployments, this only checks the first endpoint.
	// If the first endpoint is down but other cluster members are healthy,
	// this will report unhealthy even though the cluster is functional.
	// This is acceptable for single-endpoint deployments (our current setup).
	if len(e.config.Endpoints) == 0 {
		return errors.New("no etcd endpoints configured")
	}

	_, err := e.conn.Client().Status(ctx, e.config.Endpoints[0])
	return err
}

// ============================================================================
// AC Assignment Operations
// ============================================================================

// acAssignmentKey returns the etcd key for an AC assignment.
func acAssignmentKey(acID string) string {
	return etcdACAssignmentsPrefix + acID
}

// GetACAssignment retrieves the server assignment for an AC.
func (e *EtcdStorage) GetACAssignment(ctx context.Context, acID string) (*ACAssignment, error) {
	key := acAssignmentKey(acID)

	data, err := e.conn.GetValueWithKey(ctx, key)
	if err != nil {
		if errors.Is(err, etcd.ErrKeyNotFound) || errors.Is(err, etcd.ErrValueNotSet) {
			return nil, NewNotFoundError(fmt.Sprintf("AC assignment not found: %s", acID))
		}
		log.Error("etcd GetValue failed for AC %s: %v", acID, err)
		return nil, NewServiceUnavailableError("etcd unavailable", err)
	}

	var assignment ACAssignment
	if err := json.Unmarshal(data, &assignment); err != nil {
		log.Error("Failed to unmarshal AC assignment %s: %v", acID, err)
		return nil, &StorageError{Code: ErrCodeValidationFailed, Message: "failed to unmarshal assignment", Err: err}
	}

	return &assignment, nil
}

// SaveACAssignment stores or updates an AC assignment.
func (e *EtcdStorage) SaveACAssignment(ctx context.Context, assignment *ACAssignment) error {
	key := acAssignmentKey(assignment.ACID)

	data, err := json.Marshal(assignment)
	if err != nil {
		log.Error("Failed to marshal AC assignment %s: %v", assignment.ACID, err)
		return &StorageError{Code: ErrCodeValidationFailed, Message: "failed to marshal assignment", Err: err}
	}

	if err := e.conn.SetValueWithKey(ctx, key, string(data)); err != nil {
		log.Error("etcd SetValueWithKey failed for AC %s: %v", assignment.ACID, err)
		return NewServiceUnavailableError("etcd unavailable", err)
	}

	log.Info("Saved AC assignment %s with %d servers", assignment.ACID, len(assignment.AssignedServers))
	return nil
}

// GetACsByServer retrieves all ACs assigned to a specific server.
// This scans all AC assignments and filters by server ID.
// Note: For large deployments, consider adding a secondary index.
func (e *EtcdStorage) GetACsByServer(ctx context.Context, serverID string) ([]ACAssignment, error) {
	allAssignments, err := e.conn.GetPrefixWithContext(ctx, etcdACAssignmentsPrefix)
	if err != nil {
		log.Error("etcd GetPrefix failed for AC assignments: %v", err)
		return nil, NewServiceUnavailableError("etcd unavailable", err)
	}

	var results []ACAssignment
	for key, data := range allAssignments {
		var assignment ACAssignment
		if err := json.Unmarshal(data, &assignment); err != nil {
			log.Warning("Failed to unmarshal AC assignment from key %s: %v", key, err)
			continue
		}

		// Check if this AC is assigned to the specified server
		for _, server := range assignment.AssignedServers {
			if server.ID == serverID {
				results = append(results, assignment)
				break
			}
		}
	}

	return results, nil
}

// ============================================================================
// License Operations
// ============================================================================

// licenseEtcdKey returns the etcd key for a license.
// Uses SHA256 of the license key as the sole component (globally unique).
func licenseEtcdKey(licenseKeySHA256 string) string {
	return etcdLicensesPrefix + licenseKeySHA256
}

// GetLicense retrieves license information using the license key.
// The license key is hashed with SHA256 for the etcd key lookup.
// License keys are globally unique, so no customer ID is needed.
func (e *EtcdStorage) GetLicense(ctx context.Context, licenseKey string) (*License, error) {
	// Compute SHA256 of license key for lookup
	hash := sha256.Sum256([]byte(licenseKey))
	licenseKeySHA256 := hex.EncodeToString(hash[:])

	key := licenseEtcdKey(licenseKeySHA256)

	data, err := e.conn.GetValueWithKey(ctx, key)
	if err != nil {
		if errors.Is(err, etcd.ErrKeyNotFound) || errors.Is(err, etcd.ErrValueNotSet) {
			return nil, NewNotFoundError("license not found")
		}
		log.Error("etcd GetValue failed for license: %v", err)
		return nil, NewServiceUnavailableError("etcd unavailable", err)
	}

	var license License
	if err := json.Unmarshal(data, &license); err != nil {
		log.Error("Failed to unmarshal license: %v", err)
		return nil, &StorageError{Code: ErrCodeValidationFailed, Message: "failed to unmarshal license", Err: err}
	}

	return &license, nil
}

// ============================================================================
// Resource Operations
// ============================================================================

// resourceKey returns the etcd key for a resource.
func resourceKey(customerID, resourceID string) string {
	return etcdResourcesPrefix + customerID + "/" + resourceID
}

// resourceByACPrefix returns the etcd key prefix for resources by AC.
func resourceByACPrefix(acID string) string {
	return etcdResourcesByACPrefix + acID + "/"
}

// GetResource retrieves resource definition by customer and resource ID.
func (e *EtcdStorage) GetResource(ctx context.Context, customerID, resourceID string) (*Resource, error) {
	key := resourceKey(customerID, resourceID)

	data, err := e.conn.GetValueWithKey(ctx, key)
	if err != nil {
		if errors.Is(err, etcd.ErrKeyNotFound) || errors.Is(err, etcd.ErrValueNotSet) {
			return nil, NewNotFoundError(fmt.Sprintf("resource not found: %s/%s", customerID, resourceID))
		}
		log.Error("etcd GetValue failed for resource %s/%s: %v", customerID, resourceID, err)
		return nil, NewServiceUnavailableError("etcd unavailable", err)
	}

	var resource Resource
	if err := json.Unmarshal(data, &resource); err != nil {
		log.Error("Failed to unmarshal resource %s/%s: %v", customerID, resourceID, err)
		return nil, &StorageError{Code: ErrCodeValidationFailed, Message: "failed to unmarshal resource", Err: err}
	}

	return &resource, nil
}

// GetResourceByACID retrieves resources associated with a specific AC.
// This uses a secondary index stored under /nhp/resources-by-ac/{ac_id}/.
func (e *EtcdStorage) GetResourceByACID(ctx context.Context, acID string) ([]Resource, error) {
	prefix := resourceByACPrefix(acID)

	allResources, err := e.conn.GetPrefixWithContext(ctx, prefix)
	if err != nil {
		log.Error("etcd GetPrefix failed for resources by AC %s: %v", acID, err)
		return nil, NewServiceUnavailableError("etcd unavailable", err)
	}

	if len(allResources) == 0 {
		return nil, NewNotFoundError(fmt.Sprintf("no resources found for AC: %s", acID))
	}

	var resources []Resource
	for key, data := range allResources {
		var resource Resource
		if err := json.Unmarshal(data, &resource); err != nil {
			log.Warning("Failed to unmarshal resource from key %s: %v", key, err)
			continue
		}
		resources = append(resources, resource)
	}

	if len(resources) == 0 {
		return nil, NewNotFoundError(fmt.Sprintf("no resources found for AC: %s", acID))
	}

	return resources, nil
}
