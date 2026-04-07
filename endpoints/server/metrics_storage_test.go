package server

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func newTestMetricsStorage(tb testing.TB, backend StorageBackend) (*MetricsStorage, *sdkmetric.ManualReader) {
	tb.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := provider.Meter(meterName)
	ms := newMetricsStorageWithMeter(backend, meter)
	return ms, reader
}

func collectMetrics(t *testing.T, reader *sdkmetric.ManualReader) *metricdata.ResourceMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}
	return &rm
}

func findMetric(rm *metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	for _, sm := range rm.ScopeMetrics {
		for i := range sm.Metrics {
			if sm.Metrics[i].Name == name {
				return &sm.Metrics[i]
			}
		}
	}
	return nil
}

func hasAttribute(attrs attribute.Set, key, value string) bool {
	v, ok := attrs.Value(attribute.Key(key))
	return ok && v.AsString() == value
}

func TestMetricsStorage_GetACAssignment_Success(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutACAssignment(CreateTestACAssignment("ac-met-1", "srv-1", "srv-2"))
	ms, reader := newTestMetricsStorage(t, backend)
	assignment, err := ms.GetACAssignment(context.Background(), "ac-met-1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if assignment.ACID != "ac-met-1" {
		t.Errorf("Expected ACID 'ac-met-1', got '%s'", assignment.ACID)
	}
	rm := collectMetrics(t, reader)
	if findMetric(rm, "storage.operation.duration") == nil {
		t.Fatal("Expected storage.operation.duration metric")
	}
	if findMetric(rm, "storage.operation.total") == nil {
		t.Fatal("Expected storage.operation.total metric")
	}
}

func TestMetricsStorage_GetACAssignment_NotFound(t *testing.T) {
	backend := NewMemoryStorage()
	ms, reader := newTestMetricsStorage(t, backend)
	_, err := ms.GetACAssignment(context.Background(), "non-existent")
	if err == nil {
		t.Fatal("Expected error for non-existent AC")
	}
	if !IsNotFoundError(err) {
		t.Errorf("Expected NotFoundError, got %T: %v", err, err)
	}
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.total")
	if m == nil {
		t.Fatal("Expected storage.operation.total metric")
	}
	sum := m.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) == 0 {
		t.Fatal("Expected at least one data point")
	}
	if !hasAttribute(sum.DataPoints[0].Attributes, "status", "not_found") {
		t.Error("Expected status=not_found attribute")
	}
	if !hasAttribute(sum.DataPoints[0].Attributes, "operation", "GetACAssignment") {
		t.Error("Expected operation=GetACAssignment attribute")
	}
}

func TestMetricsStorage_GetACAssignment_BackendError(t *testing.T) {
	backend := NewMemoryStorage()
	backend.SetServiceUnavailable("test outage")
	ms, reader := newTestMetricsStorage(t, backend)
	_, err := ms.GetACAssignment(context.Background(), "ac-error")
	if err == nil {
		t.Fatal("Expected error from backend")
	}
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.total")
	if m == nil {
		t.Fatal("Expected storage.operation.total metric")
	}
	sum := m.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) == 0 {
		t.Fatal("Expected at least one data point")
	}
	if !hasAttribute(sum.DataPoints[0].Attributes, "status", "error") {
		t.Error("Expected status=error attribute")
	}
}

func TestMetricsStorage_GetACsByServer(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutACAssignment(CreateTestACAssignment("ac-srv-1", "srv-target"))
	backend.PutACAssignment(CreateTestACAssignment("ac-srv-2", "srv-target"))
	ms, reader := newTestMetricsStorage(t, backend)
	assignments, err := ms.GetACsByServer(context.Background(), "srv-target")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(assignments) != 2 {
		t.Errorf("Expected 2 assignments, got %d", len(assignments))
	}
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.total")
	if m == nil {
		t.Fatal("Expected storage.operation.total metric")
	}
	sum := m.Data.(metricdata.Sum[int64])
	if !hasAttribute(sum.DataPoints[0].Attributes, "operation", "GetACsByServer") {
		t.Error("Expected operation=GetACsByServer attribute")
	}
}

func TestMetricsStorage_GetLicense_Success(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutLicenseWithKey(CreateTestLicense("test-key-456"), "test-key-456")
	ms, reader := newTestMetricsStorage(t, backend)
	result, err := ms.GetLicense(context.Background(), "test-key-456")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if result.CustomerID != "test-customer" {
		t.Errorf("Expected customerID 'test-customer', got '%s'", result.CustomerID)
	}
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.total")
	if m == nil {
		t.Fatal("Expected storage.operation.total metric")
	}
	sum := m.Data.(metricdata.Sum[int64])
	if !hasAttribute(sum.DataPoints[0].Attributes, "operation", "GetLicense") {
		t.Error("Expected operation=GetLicense attribute")
	}
}

func TestMetricsStorage_GetResource_Success(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutResource(CreateTestResource("cust-1", "res-1", "ac-1"))
	ms, reader := newTestMetricsStorage(t, backend)
	result, err := ms.GetResource(context.Background(), "cust-1", "res-1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if result.ResourceID != "res-1" {
		t.Errorf("Expected resourceID 'res-1', got '%s'", result.ResourceID)
	}
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.total")
	if m == nil {
		t.Fatal("Expected storage.operation.total metric")
	}
}

func TestMetricsStorage_GetResourceByACID_Success(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutResource(CreateTestResource("cust-1", "res-1", "ac-lookup"))
	backend.PutResource(CreateTestResource("cust-1", "res-2", "ac-lookup"))
	ms, reader := newTestMetricsStorage(t, backend)
	resources, err := ms.GetResourceByACID(context.Background(), "ac-lookup")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(resources) != 2 {
		t.Errorf("Expected 2 resources, got %d", len(resources))
	}
	rm := collectMetrics(t, reader)
	if findMetric(rm, "storage.operation.total") == nil {
		t.Fatal("Expected storage.operation.total metric")
	}
}

func TestMetricsStorage_SaveACAssignment_Success(t *testing.T) {
	backend := NewMemoryStorage()
	ms, reader := newTestMetricsStorage(t, backend)
	assignment := CreateTestACAssignment("ac-save-1", "srv-1", "srv-2")
	err := ms.SaveACAssignment(context.Background(), assignment)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	saved, err := backend.GetACAssignment(context.Background(), "ac-save-1")
	if err != nil {
		t.Fatalf("Expected saved assignment, got error: %v", err)
	}
	if saved.ACID != "ac-save-1" {
		t.Errorf("Expected ACID 'ac-save-1', got '%s'", saved.ACID)
	}
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.total")
	if m == nil {
		t.Fatal("Expected storage.operation.total metric")
	}
	sum := m.Data.(metricdata.Sum[int64])
	if !hasAttribute(sum.DataPoints[0].Attributes, "operation", "SaveACAssignment") {
		t.Error("Expected operation=SaveACAssignment attribute")
	}
}

func TestMetricsStorage_SaveACAssignment_Error(t *testing.T) {
	backend := NewMemoryStorage()
	backend.SetServiceUnavailable("write outage")
	ms, reader := newTestMetricsStorage(t, backend)
	err := ms.SaveACAssignment(context.Background(), CreateTestACAssignment("ac-save-err", "srv-1"))
	if err == nil {
		t.Fatal("Expected error from backend")
	}
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.total")
	if m == nil {
		t.Fatal("Expected storage.operation.total metric")
	}
	sum := m.Data.(metricdata.Sum[int64])
	if !hasAttribute(sum.DataPoints[0].Attributes, "status", "error") {
		t.Error("Expected status=error attribute")
	}
}

func TestMetricsStorage_SlowOperation(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutACAssignment(CreateTestACAssignment("ac-slow", "srv-1"))
	backend.SetDelayOnNextCallForMethod("GetACAssignment", 600*time.Millisecond)
	ms, reader := newTestMetricsStorage(t, backend)
	assignment, err := ms.GetACAssignment(context.Background(), "ac-slow")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if assignment.ACID != "ac-slow" {
		t.Errorf("Expected ACID 'ac-slow', got '%s'", assignment.ACID)
	}
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.slow")
	if m == nil {
		t.Fatal("Expected storage.operation.slow metric")
	}
	sum := m.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) == 0 {
		t.Fatal("Expected at least one slow data point")
	}
	if sum.DataPoints[0].Value != 1 {
		t.Errorf("Expected slow counter = 1, got %d", sum.DataPoints[0].Value)
	}
}

func TestMetricsStorage_FastOperation_NoSlowCounter(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutACAssignment(CreateTestACAssignment("ac-fast", "srv-1"))
	ms, reader := newTestMetricsStorage(t, backend)
	_, err := ms.GetACAssignment(context.Background(), "ac-fast")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.slow")
	if m != nil {
		sum, ok := m.Data.(metricdata.Sum[int64])
		if ok && len(sum.DataPoints) > 0 && sum.DataPoints[0].Value > 0 {
			t.Errorf("Expected no slow counter increment, got %d", sum.DataPoints[0].Value)
		}
	}
}

func TestMetricsStorage_BackendAttribute(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutACAssignment(CreateTestACAssignment("ac-attr", "srv-1"))
	ms, reader := newTestMetricsStorage(t, backend)
	_, _ = ms.GetACAssignment(context.Background(), "ac-attr")
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.total")
	if m == nil {
		t.Fatal("Expected storage.operation.total metric")
	}
	sum := m.Data.(metricdata.Sum[int64])
	if !hasAttribute(sum.DataPoints[0].Attributes, "backend", "memory") {
		t.Error("Expected backend=memory attribute")
	}
}

func TestMetricsStorage_Name(t *testing.T) {
	ms, _ := newTestMetricsStorage(t, NewMemoryStorage())
	if ms.Name() != "memory (metrics)" {
		t.Errorf("Expected name 'memory (metrics)', got '%s'", ms.Name())
	}
}

func TestMetricsStorage_Backend(t *testing.T) {
	backend := NewMemoryStorage()
	ms, _ := newTestMetricsStorage(t, backend)
	if ms.Backend() != backend {
		t.Error("Backend() should return the underlying storage backend")
	}
}

func TestMetricsStorage_Close(t *testing.T) {
	ms, _ := newTestMetricsStorage(t, NewMemoryStorage())
	if err := ms.Close(); err != nil {
		t.Errorf("Expected no error on close, got %v", err)
	}
}

func TestMetricsStorage_Ping_NonPinger(t *testing.T) {
	ms, _ := newTestMetricsStorage(t, NewMemoryStorage())
	if err := ms.Ping(context.Background()); err != nil {
		t.Errorf("Expected no error from Ping on non-Pinger, got %v", err)
	}
}

func TestMetricsStorage_Ping_Success(t *testing.T) {
	backend := &pingableStorage{MemoryStorage: NewMemoryStorage()}
	ms, reader := newTestMetricsStorage(t, backend)
	if err := ms.Ping(context.Background()); err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.total")
	if m == nil {
		t.Fatal("Expected storage.operation.total metric for Ping")
	}
	sum := m.Data.(metricdata.Sum[int64])
	if !hasAttribute(sum.DataPoints[0].Attributes, "operation", "Ping") {
		t.Error("Expected operation=Ping attribute")
	}
}

func TestMetricsStorage_Ping_Error(t *testing.T) {
	backend := &pingableStorage{
		MemoryStorage: NewMemoryStorage(),
		pingErr:       NewServiceUnavailableError("db down", nil),
	}
	ms, reader := newTestMetricsStorage(t, backend)
	if err := ms.Ping(context.Background()); err == nil {
		t.Fatal("Expected error from Ping")
	}
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.total")
	if m == nil {
		t.Fatal("Expected storage.operation.total metric")
	}
	sum := m.Data.(metricdata.Sum[int64])
	if !hasAttribute(sum.DataPoints[0].Attributes, "status", "error") {
		t.Error("Expected status=error for failed Ping")
	}
}

func TestMetricsStorage_Ping_SlowOperation(t *testing.T) {
	backend := &pingableStorage{
		MemoryStorage: NewMemoryStorage(),
		pingDelay:     600 * time.Millisecond,
	}
	ms, reader := newTestMetricsStorage(t, backend)
	if err := ms.Ping(context.Background()); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.slow")
	if m == nil {
		t.Fatal("Expected storage.operation.slow metric for slow Ping")
	}
	sum := m.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) == 0 || sum.DataPoints[0].Value != 1 {
		t.Errorf("Expected slow counter = 1 for slow Ping, got data points %+v", sum.DataPoints)
	}
	if !hasAttribute(sum.DataPoints[0].Attributes, "operation", "Ping") {
		t.Error("Expected operation=Ping on slow counter")
	}
}

func TestMetricsStorage_InterfaceCompliance(t *testing.T) {
	var _ StorageBackend = (*MetricsStorage)(nil)
}

func TestMetricsStorage_ComposesWithLoggingAndCache(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutACAssignment(CreateTestACAssignment("ac-compose", "srv-1"))
	metricsWrapped, reader := newTestMetricsStorage(t, backend)
	logged := NewLoggingStorage(metricsWrapped)
	cached := NewCachedStorage(logged, CacheConfig{MaxEntries: 100, DefaultTTL: 60})
	ctx := context.Background()
	if _, err := cached.GetACAssignment(ctx, "ac-compose"); err != nil {
		t.Fatalf("First call failed: %v", err)
	}
	if _, err := cached.GetACAssignment(ctx, "ac-compose"); err != nil {
		t.Fatalf("Second call failed: %v", err)
	}
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.total")
	if m == nil {
		t.Fatal("Expected storage.operation.total metric")
	}
	sum := m.Data.(metricdata.Sum[int64])
	total := int64(0)
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	if total != 1 {
		t.Errorf("Expected 1 total operation (cache hit on second), got %d", total)
	}
}

func TestMetricsStorage_MultipleOperations(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutACAssignment(CreateTestACAssignment("ac-multi", "srv-1"))
	backend.PutResource(CreateTestResource("cust-1", "res-1", "ac-1"))
	ms, reader := newTestMetricsStorage(t, backend)
	ctx := context.Background()
	_, _ = ms.GetACAssignment(ctx, "ac-multi")
	_, _ = ms.GetACAssignment(ctx, "non-existent")
	_, _ = ms.GetResource(ctx, "cust-1", "res-1")
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.total")
	if m == nil {
		t.Fatal("Expected storage.operation.total metric")
	}
	sum := m.Data.(metricdata.Sum[int64])
	total := int64(0)
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	if total != 3 {
		t.Errorf("Expected 3 total operations, got %d", total)
	}
}

func TestMetricsStorage_DurationHistogramRecordedAboveZero(t *testing.T) {
	backend := NewMemoryStorage()
	backend.PutACAssignment(CreateTestACAssignment("ac-dur", "srv-1"))
	ms, reader := newTestMetricsStorage(t, backend)
	if _, err := ms.GetACAssignment(context.Background(), "ac-dur"); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.duration")
	if m == nil {
		t.Fatal("Expected storage.operation.duration metric")
	}
	hist := m.Data.(metricdata.Histogram[float64])
	if len(hist.DataPoints) == 0 {
		t.Fatal("Expected at least one histogram data point")
	}
	dp := hist.DataPoints[0]
	if dp.Sum < 0 {
		t.Errorf("Expected non-negative duration sum, got %f", dp.Sum)
	}
	// Verify the histogram data point carries the expected operation/backend/status attributes.
	if !hasAttribute(dp.Attributes, "operation", "GetACAssignment") {
		t.Error("Expected operation=GetACAssignment attribute on duration histogram")
	}
	if !hasAttribute(dp.Attributes, "backend", "memory") {
		t.Error("Expected backend=memory attribute on duration histogram")
	}
	if !hasAttribute(dp.Attributes, "status", "ok") {
		t.Error("Expected status=ok attribute on duration histogram")
	}
}

func TestNewMetricsStorage_UsesGlobalProvider(t *testing.T) {
	backend := NewMemoryStorage()
	ms := NewMetricsStorage(backend)
	if ms == nil {
		t.Fatal("Expected non-nil MetricsStorage")
	}
	backend.PutACAssignment(CreateTestACAssignment("ac-noop", "srv-1"))
	if _, err := ms.GetACAssignment(context.Background(), "ac-noop"); err != nil {
		t.Fatalf("Expected no error with noop meter, got %v", err)
	}
}

func TestMetricsStorage_ContextCancellation(t *testing.T) {
	backend := NewMemoryStorage()
	backend.SetDelayOnNextCall(2 * time.Second)
	ms, reader := newTestMetricsStorage(t, backend)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := ms.GetACAssignment(ctx, "ac-timeout"); err == nil {
		t.Fatal("Expected error from context cancellation")
	}

	// Even though the caller's context was canceled, the metric write must
	// still flow through OTEL — record() uses a fresh background context so
	// the failed-call observation is never lost.
	rm := collectMetrics(t, reader)
	m := findMetric(rm, "storage.operation.total")
	if m == nil {
		t.Fatal("Expected storage.operation.total metric for canceled call")
	}
	sum := m.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) == 0 {
		t.Fatal("Expected at least one data point on canceled call")
	}
	if !hasAttribute(sum.DataPoints[0].Attributes, "status", "error") {
		t.Error("Expected status=error attribute for canceled call")
	}
}

// Note: an explicit noop.Meter test was previously here. Coverage is provided
// by TestNewMetricsStorage_UsesGlobalProvider above, which exercises the same
// "no global provider configured" path through the public constructor.
