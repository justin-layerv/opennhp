package server

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// ============================================================================
// Metrics Storage Wrapper
// ============================================================================
//
// MetricsStorage wraps a StorageBackend with OpenTelemetry metrics emission.
// Every operation records:
//   - Duration histogram (storage.operation.duration) for p50/p95/p99 dashboards
//   - Total counter   (storage.operation.total)    for throughput / error-rate alerting
//   - Slow counter    (storage.operation.slow)     for latency-spike alerting
//
// All instruments carry attributes: operation, backend, status (ok/error/not_found).
//
// Layering. CreateStorageBackend builds the chain so calls flow:
//
//	caller → CachedStorage → LoggingStorage → MetricsStorage → backend
//
// MetricsStorage sits closest to the backend, so it measures only real backend
// round-trips — cache hits short-circuit at CachedStorage and never reach this
// layer. That is intentional (we want to know how the backend itself is
// behaving, not how often the cache short-circuits it). Cache hit-rate is a
// separate concern tracked in CachedStorage (see follow-up issue).
//
// Note on log output: LoggingStorage wraps MetricsStorage in the chain above,
// so log lines emitted by LoggingStorage will report Name() as
// "<backend> (metrics)" rather than the raw backend name. That is the wrapped
// name on purpose (it makes the layering visible in logs); operators searching
// logs by backend should match on the prefix.
//
// Ping behavior: backends that do not implement the Pinger interface get a
// nil return from MetricsStorage.Ping with no metric recorded — there is no
// operation to time. This is consistent with LoggingStorage.
//
// The decorator uses the global OTEL MeterProvider so that metrics are exported
// alongside existing traces (configured via otelgin middleware). In tests without
// a configured provider, the noop meter is used automatically.
// ============================================================================

const (
	// meterName identifies this instrumentation library in OTEL output.
	meterName = "github.com/layervai/nhp/endpoints/server/storage"
)

// Status attribute values for storage operation outcomes.
const (
	statusOK       = "ok"
	statusError    = "error"
	statusNotFound = "not_found"
)

// Attribute keys used across all storage metrics.
var (
	attrOperation = attribute.Key("operation")
	attrBackend   = attribute.Key("backend")
	attrStatus    = attribute.Key("status")
)

// storageMetrics holds the pre-created OTEL instruments.
// Instruments are safe for concurrent use after creation.
type storageMetrics struct {
	duration metric.Float64Histogram
	total    metric.Int64Counter
	slow     metric.Int64Counter
}

// MetricsStorage wraps a StorageBackend with OpenTelemetry metrics.
type MetricsStorage struct {
	backend StorageBackend
	metrics storageMetrics
	// backendName is captured at construction so the per-call hot path
	// avoids a method call (and any string allocation an implementation may
	// perform inside Name()) on every operation.
	backendName string
}

// Compile-time interface compliance check
var _ StorageBackend = (*MetricsStorage)(nil)

// NewMetricsStorage creates a new metrics storage wrapper using the global
// OTEL MeterProvider. Instrument creation errors are handled by OTEL's
// global error handler; in practice, meter creation never fails.
func NewMetricsStorage(backend StorageBackend) *MetricsStorage {
	meter := otel.Meter(meterName)
	return newMetricsStorageWithMeter(backend, meter)
}

// newMetricsStorageWithMeter creates a MetricsStorage with an explicit meter.
// Used for testing with a manual reader; production code should use NewMetricsStorage.
//
// Instrument creation errors are intentionally ignored: the OTEL SDK returns
// a working no-op instrument on failure and forwards the error to the global
// error handler, so we always receive a usable value and do not need to bail
// out of construction here.
func newMetricsStorageWithMeter(backend StorageBackend, meter metric.Meter) *MetricsStorage {
	// Explicit bucket boundaries (ms) tuned for storage operations: sub-ms
	// cache-adjacent calls on the low end, up to multi-second DynamoDB calls
	// on the high end. These give meaningful p50/p95/p99 resolution without
	// relying on OTEL's default buckets (which bias toward HTTP latencies).
	duration, _ := meter.Float64Histogram(
		"storage.operation.duration",
		metric.WithDescription("Duration of storage operations in milliseconds"),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(0.5, 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000),
	)
	total, _ := meter.Int64Counter(
		"storage.operation.total",
		metric.WithDescription("Total number of storage operations"),
	)
	slow, _ := meter.Int64Counter(
		"storage.operation.slow",
		metric.WithDescription(fmt.Sprintf("Number of storage operations exceeding %s", SlowOperationThreshold)),
	)

	return &MetricsStorage{
		backend:     backend,
		backendName: backend.Name(),
		metrics: storageMetrics{
			duration: duration,
			total:    total,
			slow:     slow,
		},
	}
}

// record emits duration histogram, total counter, and (conditionally) slow counter.
//
// The recording context is intentionally decoupled from the caller's context:
// when an operation fails because the caller's context was canceled, we still
// want the resulting metric to flow through the OTEL exporter rather than be
// dropped because the canceled context propagates into the SDK. We use
// context.Background() for the metric writes for that reason.
func (ms *MetricsStorage) record(ctx context.Context, operation string, d time.Duration, err error) {
	status := statusOK
	if err != nil {
		if IsNotFoundError(err) {
			status = statusNotFound
		} else {
			status = statusError
		}
	}

	attrs := metric.WithAttributes(
		attrOperation.String(operation),
		attrBackend.String(ms.backendName),
		attrStatus.String(status),
	)

	// Sub-millisecond precision: nanoseconds → milliseconds float division.
	durationMs := float64(d.Nanoseconds()) / float64(time.Millisecond)
	// Use a fresh background context so cancellation of the caller's context
	// (a common cause of error recordings) does not also lose the metric.
	recCtx := context.Background()
	ms.metrics.duration.Record(recCtx, durationMs, attrs)
	ms.metrics.total.Add(recCtx, 1, attrs)

	if d >= SlowOperationThreshold {
		ms.metrics.slow.Add(recCtx, 1, attrs)
	}
	_ = ctx // retained in signature for future tracing integration
}

// GetACAssignment retrieves the AC assignment, recording metrics.
func (ms *MetricsStorage) GetACAssignment(ctx context.Context, acID string) (*ACAssignment, error) {
	start := time.Now()
	assignment, err := ms.backend.GetACAssignment(ctx, acID)
	ms.record(ctx, "GetACAssignment", time.Since(start), err)
	return assignment, err
}

// GetACsByServer retrieves ACs assigned to a server, recording metrics.
func (ms *MetricsStorage) GetACsByServer(ctx context.Context, serverID string) ([]ACAssignment, error) {
	start := time.Now()
	assignments, err := ms.backend.GetACsByServer(ctx, serverID)
	ms.record(ctx, "GetACsByServer", time.Since(start), err)
	return assignments, err
}

// GetLicense retrieves license information, recording metrics.
func (ms *MetricsStorage) GetLicense(ctx context.Context, licenseKey string) (*License, error) {
	start := time.Now()
	license, err := ms.backend.GetLicense(ctx, licenseKey)
	ms.record(ctx, "GetLicense", time.Since(start), err)
	return license, err
}

// GetResource retrieves a resource definition, recording metrics.
func (ms *MetricsStorage) GetResource(ctx context.Context, customerID, resourceID string) (*Resource, error) {
	start := time.Now()
	resource, err := ms.backend.GetResource(ctx, customerID, resourceID)
	ms.record(ctx, "GetResource", time.Since(start), err)
	return resource, err
}

// GetResourceByACID retrieves resources by AC ID, recording metrics.
func (ms *MetricsStorage) GetResourceByACID(ctx context.Context, acID string) ([]Resource, error) {
	start := time.Now()
	resources, err := ms.backend.GetResourceByACID(ctx, acID)
	ms.record(ctx, "GetResourceByACID", time.Since(start), err)
	return resources, err
}

// SaveACAssignment stores an AC assignment, recording metrics.
func (ms *MetricsStorage) SaveACAssignment(ctx context.Context, assignment *ACAssignment) error {
	start := time.Now()
	err := ms.backend.SaveACAssignment(ctx, assignment)
	ms.record(ctx, "SaveACAssignment", time.Since(start), err)
	return err
}

// Close releases resources held by the underlying backend.
func (ms *MetricsStorage) Close() error {
	return ms.backend.Close()
}

// Name returns the backend name with a metrics indicator.
func (ms *MetricsStorage) Name() string {
	return ms.backend.Name() + " (metrics)"
}

// Backend returns the underlying storage backend.
// This allows callers to unwrap the metrics layer for type assertions.
func (ms *MetricsStorage) Backend() StorageBackend {
	return ms.backend
}

// Ping forwards to the underlying backend's Ping method if available.
func (ms *MetricsStorage) Ping(ctx context.Context) error {
	if pinger, ok := ms.backend.(Pinger); ok {
		start := time.Now()
		err := pinger.Ping(ctx)
		ms.record(ctx, "Ping", time.Since(start), err)
		return err
	}
	return nil
}
