package server

import (
	"context"
	"time"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// ============================================================================
// Logging Storage Wrapper
// ============================================================================
//
// LoggingStorage wraps a StorageBackend with structured context logging.
// Every operation is logged with:
// - Operation name and backend type
// - Key parameters (acID, customerID, resourceID, serverID)
// - Duration in milliseconds
// - Request ID (when present in context via ContextWithRequestID)
// - Error details on failure
//
// This wrapper is transparent to callers and composes with CachedStorage:
//   backend -> LoggingStorage -> CachedStorage
//
// Log levels:
// - Debug: successful operations (avoids noise in production)
// - Warning: slow operations (above slowThreshold)
// - Error: failed operations (with error details)
// ============================================================================

const (
	// slowThresholdMs is the millisecond threshold above which a storage
	// operation is logged at Warning level instead of Debug. This helps
	// surface latency issues without overwhelming logs during normal operation.
	slowThresholdMs int64 = 500
)

// contextKey is an unexported type for context keys to prevent collisions.
type contextKey struct{}

// requestIDCtxKey is the context key for propagating request IDs into storage logs.
var requestIDCtxKey = contextKey{}

// ContextWithRequestID returns a derived context carrying a request ID.
// Storage operations called with this context will include the ID in log output.
func ContextWithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDCtxKey, requestID)
}

// requestIDFromCtx extracts the request ID from ctx, returning "-" when absent.
// Used as a regular format parameter in log lines for consistent structured output.
func requestIDFromCtx(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDCtxKey).(string); ok && id != "" {
		return id
	}
	return "-"
}

// LoggingStorage wraps a StorageBackend with structured context logging.
type LoggingStorage struct {
	backend StorageBackend
}

// Compile-time interface compliance check
var _ StorageBackend = (*LoggingStorage)(nil)

// NewLoggingStorage creates a new logging storage wrapper.
func NewLoggingStorage(backend StorageBackend) *LoggingStorage {
	return &LoggingStorage{backend: backend}
}

// GetACAssignment retrieves the AC assignment, logging the operation.
func (ls *LoggingStorage) GetACAssignment(ctx context.Context, acID string) (*ACAssignment, error) {
	start := time.Now()
	assignment, err := ls.backend.GetACAssignment(ctx, acID)
	ms := time.Since(start).Milliseconds()
	rid := requestIDFromCtx(ctx)

	if err != nil {
		if !IsNotFoundError(err) {
			log.Error("[storage] GetACAssignment failed: backend=%s acID=%s req_id=%s duration_ms=%d error=%v",
				ls.backend.Name(), acID, rid, ms, err)
		} else {
			log.Debug("[storage] GetACAssignment not found: backend=%s acID=%s req_id=%s duration_ms=%d",
				ls.backend.Name(), acID, rid, ms)
		}
		return nil, err
	}

	serverCount := len(assignment.AssignedServers)
	if ms > slowThresholdMs {
		log.Warning("[storage] GetACAssignment slow: backend=%s acID=%s servers=%d req_id=%s duration_ms=%d",
			ls.backend.Name(), acID, serverCount, rid, ms)
	} else {
		log.Debug("[storage] GetACAssignment ok: backend=%s acID=%s servers=%d req_id=%s duration_ms=%d",
			ls.backend.Name(), acID, serverCount, rid, ms)
	}

	return assignment, nil
}

// GetACsByServer retrieves ACs assigned to a server, logging the operation.
func (ls *LoggingStorage) GetACsByServer(ctx context.Context, serverID string) ([]ACAssignment, error) {
	start := time.Now()
	assignments, err := ls.backend.GetACsByServer(ctx, serverID)
	ms := time.Since(start).Milliseconds()
	rid := requestIDFromCtx(ctx)

	if err != nil {
		if !IsNotFoundError(err) {
			log.Error("[storage] GetACsByServer failed: backend=%s serverID=%s req_id=%s duration_ms=%d error=%v",
				ls.backend.Name(), serverID, rid, ms, err)
		} else {
			log.Debug("[storage] GetACsByServer not found: backend=%s serverID=%s req_id=%s duration_ms=%d",
				ls.backend.Name(), serverID, rid, ms)
		}
		return nil, err
	}

	if ms > slowThresholdMs {
		log.Warning("[storage] GetACsByServer slow: backend=%s serverID=%s results=%d req_id=%s duration_ms=%d",
			ls.backend.Name(), serverID, len(assignments), rid, ms)
	} else {
		log.Debug("[storage] GetACsByServer ok: backend=%s serverID=%s results=%d req_id=%s duration_ms=%d",
			ls.backend.Name(), serverID, len(assignments), rid, ms)
	}

	return assignments, nil
}

// GetLicense retrieves license information, logging the operation.
// The license key is not logged to avoid leaking sensitive data.
func (ls *LoggingStorage) GetLicense(ctx context.Context, licenseKey string) (*License, error) {
	start := time.Now()
	license, err := ls.backend.GetLicense(ctx, licenseKey)
	ms := time.Since(start).Milliseconds()
	rid := requestIDFromCtx(ctx)

	if err != nil {
		if !IsNotFoundError(err) {
			log.Error("[storage] GetLicense failed: backend=%s req_id=%s duration_ms=%d error=%v",
				ls.backend.Name(), rid, ms, err)
		} else {
			log.Debug("[storage] GetLicense not found: backend=%s req_id=%s duration_ms=%d",
				ls.backend.Name(), rid, ms)
		}
		return nil, err
	}

	if ms > slowThresholdMs {
		log.Warning("[storage] GetLicense slow: backend=%s customerID=%s tier=%s req_id=%s duration_ms=%d",
			ls.backend.Name(), license.CustomerID, license.Tier, rid, ms)
	} else {
		log.Debug("[storage] GetLicense ok: backend=%s customerID=%s tier=%s req_id=%s duration_ms=%d",
			ls.backend.Name(), license.CustomerID, license.Tier, rid, ms)
	}

	return license, nil
}

// GetResource retrieves a resource definition, logging the operation.
func (ls *LoggingStorage) GetResource(ctx context.Context, customerID, resourceID string) (*Resource, error) {
	start := time.Now()
	resource, err := ls.backend.GetResource(ctx, customerID, resourceID)
	ms := time.Since(start).Milliseconds()
	rid := requestIDFromCtx(ctx)

	if err != nil {
		if !IsNotFoundError(err) {
			log.Error("[storage] GetResource failed: backend=%s customerID=%s resourceID=%s req_id=%s duration_ms=%d error=%v",
				ls.backend.Name(), customerID, resourceID, rid, ms, err)
		} else {
			log.Debug("[storage] GetResource not found: backend=%s customerID=%s resourceID=%s req_id=%s duration_ms=%d",
				ls.backend.Name(), customerID, resourceID, rid, ms)
		}
		return nil, err
	}

	if ms > slowThresholdMs {
		log.Warning("[storage] GetResource slow: backend=%s customerID=%s resourceID=%s acID=%s req_id=%s duration_ms=%d",
			ls.backend.Name(), customerID, resourceID, resource.ACID, rid, ms)
	} else {
		log.Debug("[storage] GetResource ok: backend=%s customerID=%s resourceID=%s acID=%s req_id=%s duration_ms=%d",
			ls.backend.Name(), customerID, resourceID, resource.ACID, rid, ms)
	}

	return resource, nil
}

// GetResourceByACID retrieves resources by AC ID, logging the operation.
func (ls *LoggingStorage) GetResourceByACID(ctx context.Context, acID string) ([]Resource, error) {
	start := time.Now()
	resources, err := ls.backend.GetResourceByACID(ctx, acID)
	ms := time.Since(start).Milliseconds()
	rid := requestIDFromCtx(ctx)

	if err != nil {
		if !IsNotFoundError(err) {
			log.Error("[storage] GetResourceByACID failed: backend=%s acID=%s req_id=%s duration_ms=%d error=%v",
				ls.backend.Name(), acID, rid, ms, err)
		} else {
			log.Debug("[storage] GetResourceByACID not found: backend=%s acID=%s req_id=%s duration_ms=%d",
				ls.backend.Name(), acID, rid, ms)
		}
		return nil, err
	}

	if ms > slowThresholdMs {
		log.Warning("[storage] GetResourceByACID slow: backend=%s acID=%s results=%d req_id=%s duration_ms=%d",
			ls.backend.Name(), acID, len(resources), rid, ms)
	} else {
		log.Debug("[storage] GetResourceByACID ok: backend=%s acID=%s results=%d req_id=%s duration_ms=%d",
			ls.backend.Name(), acID, len(resources), rid, ms)
	}

	return resources, nil
}

// SaveACAssignment stores an AC assignment, logging the operation.
func (ls *LoggingStorage) SaveACAssignment(ctx context.Context, assignment *ACAssignment) error {
	start := time.Now()
	err := ls.backend.SaveACAssignment(ctx, assignment)
	ms := time.Since(start).Milliseconds()
	rid := requestIDFromCtx(ctx)

	if err != nil {
		log.Error("[storage] SaveACAssignment failed: backend=%s acID=%s version=%d servers=%d req_id=%s duration_ms=%d error=%v",
			ls.backend.Name(), assignment.ACID, assignment.Version,
			len(assignment.AssignedServers), rid, ms, err)
		return err
	}

	if ms > slowThresholdMs {
		log.Warning("[storage] SaveACAssignment slow: backend=%s acID=%s version=%d servers=%d req_id=%s duration_ms=%d",
			ls.backend.Name(), assignment.ACID, assignment.Version,
			len(assignment.AssignedServers), rid, ms)
	} else {
		log.Debug("[storage] SaveACAssignment ok: backend=%s acID=%s version=%d servers=%d req_id=%s duration_ms=%d",
			ls.backend.Name(), assignment.ACID, assignment.Version,
			len(assignment.AssignedServers), rid, ms)
	}

	return nil
}

// Close releases resources held by the underlying backend.
func (ls *LoggingStorage) Close() error {
	log.Info("[storage] Closing storage backend: %s", ls.backend.Name())
	return ls.backend.Close()
}

// Name returns the backend name with a logging indicator.
func (ls *LoggingStorage) Name() string {
	return ls.backend.Name() + " (logged)"
}

// Backend returns the underlying storage backend.
// This allows callers to unwrap the logging layer for type assertions.
func (ls *LoggingStorage) Backend() StorageBackend {
	return ls.backend
}

// Ping forwards to the underlying backend's Ping method if available.
func (ls *LoggingStorage) Ping(ctx context.Context) error {
	if pinger, ok := ls.backend.(Pinger); ok {
		start := time.Now()
		err := pinger.Ping(ctx)
		ms := time.Since(start).Milliseconds()
		rid := requestIDFromCtx(ctx)

		if err != nil {
			log.Error("[storage] Ping failed: backend=%s req_id=%s duration_ms=%d error=%v",
				ls.backend.Name(), rid, ms, err)
			return err
		}

		if ms > slowThresholdMs {
			log.Warning("[storage] Ping slow: backend=%s req_id=%s duration_ms=%d",
				ls.backend.Name(), rid, ms)
		} else {
			log.Debug("[storage] Ping ok: backend=%s req_id=%s duration_ms=%d",
				ls.backend.Name(), rid, ms)
		}
		return nil
	}
	return nil
}
