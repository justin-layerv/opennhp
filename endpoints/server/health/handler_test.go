package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// handlerTestChecker implements Checker for handler tests
// Named differently to avoid conflict with mockChecker in health_test.go
type handlerTestChecker struct {
	name     string
	status   CheckStatus
	critical bool
	message  string
}

func (m *handlerTestChecker) Name() string     { return m.name }
func (m *handlerTestChecker) IsCritical() bool { return m.critical }
func (m *handlerTestChecker) Check(_ context.Context) *CheckResult {
	return &CheckResult{
		Name:      m.name,
		Status:    m.status,
		Critical:  m.critical,
		Message:   m.message,
		Timestamp: time.Now(),
	}
}

func setupTestHandler(checkers ...Checker) (*Handler, *gin.Engine) {
	cfg := &ManagerConfig{
		Service:        "test-service",
		Version:        "1.0.0",
		Timeout:        5 * time.Second,
		StartupTimeout: 60 * time.Second,
	}
	manager := NewManager(cfg)
	for _, c := range checkers {
		manager.Register(c)
	}

	handler := NewHandler(manager)
	router := gin.New()
	handler.RegisterRoutes(router)

	return handler, router
}

func TestHandler_Liveness(t *testing.T) {
	t.Parallel()

	_, router := setupTestHandler()

	req, _ := http.NewRequest("GET", "/health/live", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp LivenessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Status != string(StatusHealthy) {
		t.Errorf("expected status %s, got %s", StatusHealthy, resp.Status)
	}
	if resp.Service != "test-service" {
		t.Errorf("expected service 'test-service', got %s", resp.Service)
	}
	if resp.Version != "1.0.0" {
		t.Errorf("expected version '1.0.0', got %s", resp.Version)
	}

	// Verify Cache-Control header
	cacheControl := w.Header().Get("Cache-Control")
	if cacheControl != "no-cache, no-store, must-revalidate" {
		t.Errorf("expected Cache-Control header, got %s", cacheControl)
	}
}

func TestHandler_Readiness_Healthy(t *testing.T) {
	t.Parallel()

	checker := &handlerTestChecker{
		name:     "etcd",
		status:   CheckStatusPass,
		critical: true,
	}
	_, router := setupTestHandler(checker)

	req, _ := http.NewRequest("GET", "/health/ready", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp ReadinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Status != string(StatusHealthy) {
		t.Errorf("expected status %s, got %s", StatusHealthy, resp.Status)
	}
}

func TestHandler_Readiness_Unhealthy(t *testing.T) {
	t.Parallel()

	checker := &handlerTestChecker{
		name:     "etcd",
		status:   CheckStatusFail,
		critical: true,
		message:  "connection refused",
	}
	_, router := setupTestHandler(checker)

	req, _ := http.NewRequest("GET", "/health/ready", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}

	var resp ReadinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Status != string(StatusUnhealthy) {
		t.Errorf("expected status %s, got %s", StatusUnhealthy, resp.Status)
	}

	// Verify checks are included
	if len(resp.Checks) == 0 {
		t.Error("expected checks in response")
	}
	if check, ok := resp.Checks["etcd"]; ok {
		if check.Status != CheckStatusFail {
			t.Errorf("expected check status %s, got %s", CheckStatusFail, check.Status)
		}
	} else {
		t.Error("expected etcd check in response")
	}
}

func TestHandler_Readiness_Degraded(t *testing.T) {
	t.Parallel()

	// Non-critical checker failing = degraded (still returns 200)
	checker := &handlerTestChecker{
		name:     "cache",
		status:   CheckStatusFail,
		critical: false,
		message:  "cache unavailable",
	}
	_, router := setupTestHandler(checker)

	req, _ := http.NewRequest("GET", "/health/ready", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Degraded still returns 200 (can accept traffic)
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200 for degraded, got %d", w.Code)
	}

	var resp ReadinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Status != string(StatusDegraded) {
		t.Errorf("expected status %s, got %s", StatusDegraded, resp.Status)
	}
}

func TestHandler_Startup_NotReady(t *testing.T) {
	t.Parallel()

	// Startup check with failing critical checker
	checker := &handlerTestChecker{
		name:     "etcd",
		status:   CheckStatusFail,
		critical: true,
	}
	_, router := setupTestHandler(checker)

	req, _ := http.NewRequest("GET", "/health/startup", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Startup not complete = 503
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}
}

func TestHandler_Startup_Ready(t *testing.T) {
	t.Parallel()

	checker := &handlerTestChecker{
		name:     "etcd",
		status:   CheckStatusPass,
		critical: true,
	}
	_, router := setupTestHandler(checker)

	// First request triggers startup success
	req, _ := http.NewRequest("GET", "/health/startup", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp ReadinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Status != string(StatusHealthy) {
		t.Errorf("expected status %s, got %s", StatusHealthy, resp.Status)
	}
}

func TestHandler_Health_Alias(t *testing.T) {
	t.Parallel()

	checker := &handlerTestChecker{
		name:     "etcd",
		status:   CheckStatusPass,
		critical: true,
	}
	_, router := setupTestHandler(checker)

	// /health should behave same as /health/ready
	req, _ := http.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp ReadinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Status != string(StatusHealthy) {
		t.Errorf("expected status %s, got %s", StatusHealthy, resp.Status)
	}
}

func TestHandler_RegisterRoutes(t *testing.T) {
	t.Parallel()

	_, router := setupTestHandler()

	routes := []string{"/health", "/health/live", "/health/ready", "/health/startup"}
	for _, route := range routes {
		req, _ := http.NewRequest("GET", route, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// All routes should return a response (not 404)
		if w.Code == http.StatusNotFound {
			t.Errorf("route %s not registered", route)
		}
	}
}

func TestHandler_Liveness_RequestID(t *testing.T) {
	t.Parallel()

	_, router := setupTestHandler()

	req, _ := http.NewRequest("GET", "/health/live", nil)
	req.Header.Set("X-Request-ID", "test-request-123")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Verify request ID is included in JSON response
	var resp LivenessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.RequestID != "test-request-123" {
		t.Errorf("expected request_id 'test-request-123', got '%s'", resp.RequestID)
	}
}

func TestHandler_Readiness_RequestID(t *testing.T) {
	t.Parallel()

	checker := &handlerTestChecker{
		name:     "etcd",
		status:   CheckStatusPass,
		critical: true,
	}
	_, router := setupTestHandler(checker)

	req, _ := http.NewRequest("GET", "/health/ready", nil)
	req.Header.Set("X-Request-ID", "test-request-456")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Verify request ID is included in JSON response
	var resp ReadinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.RequestID != "test-request-456" {
		t.Errorf("expected request_id 'test-request-456', got '%s'", resp.RequestID)
	}
}

func TestHandler_Startup_RequestID(t *testing.T) {
	t.Parallel()

	checker := &handlerTestChecker{
		name:     "etcd",
		status:   CheckStatusPass,
		critical: true,
	}
	_, router := setupTestHandler(checker)

	req, _ := http.NewRequest("GET", "/health/startup", nil)
	req.Header.Set("X-Request-ID", "test-request-789")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Verify request ID is included in JSON response
	var resp ReadinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.RequestID != "test-request-789" {
		t.Errorf("expected request_id 'test-request-789', got '%s'", resp.RequestID)
	}
}

// Integration tests for HTTP status code behavior
// These tests verify the contract between health check results and HTTP responses

func TestHandler_Integration_StatusCodeMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		endpoint       string
		checkers       []Checker
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "liveness always returns 200",
			endpoint:       "/health/live",
			checkers:       nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "healthy",
		},
		{
			name:     "readiness with passing critical checker returns 200",
			endpoint: "/health/ready",
			checkers: []Checker{
				&handlerTestChecker{name: "storage", status: CheckStatusPass, critical: true},
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "healthy",
		},
		{
			name:     "readiness with failing critical checker returns 503",
			endpoint: "/health/ready",
			checkers: []Checker{
				&handlerTestChecker{name: "storage", status: CheckStatusFail, critical: true},
			},
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   "unhealthy",
		},
		{
			name:     "readiness with failing non-critical checker returns 200 (degraded)",
			endpoint: "/health/ready",
			checkers: []Checker{
				&handlerTestChecker{name: "cache", status: CheckStatusFail, critical: false},
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "degraded",
		},
		{
			name:     "readiness with warning checker returns 200 (degraded)",
			endpoint: "/health/ready",
			checkers: []Checker{
				&handlerTestChecker{name: "cache", status: CheckStatusWarn, critical: false},
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "degraded",
		},
		{
			name:     "readiness with mixed checkers - critical pass, non-critical fail",
			endpoint: "/health/ready",
			checkers: []Checker{
				&handlerTestChecker{name: "storage", status: CheckStatusPass, critical: true},
				&handlerTestChecker{name: "cache", status: CheckStatusFail, critical: false},
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "degraded",
		},
		{
			name:     "readiness with mixed checkers - critical fail takes precedence",
			endpoint: "/health/ready",
			checkers: []Checker{
				&handlerTestChecker{name: "storage", status: CheckStatusFail, critical: true},
				&handlerTestChecker{name: "cache", status: CheckStatusPass, critical: false},
			},
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   "unhealthy",
		},
		{
			name:     "startup with failing critical checker returns 503",
			endpoint: "/health/startup",
			checkers: []Checker{
				&handlerTestChecker{name: "storage", status: CheckStatusFail, critical: true},
			},
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   "unhealthy",
		},
		{
			name:     "startup with passing critical checker returns 200",
			endpoint: "/health/startup",
			checkers: []Checker{
				&handlerTestChecker{name: "storage", status: CheckStatusPass, critical: true},
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "healthy",
		},
		{
			name:     "readiness with skip status on non-critical checker returns healthy",
			endpoint: "/health/ready",
			checkers: []Checker{
				&handlerTestChecker{name: "storage", status: CheckStatusPass, critical: true},
				&handlerTestChecker{name: "optional", status: CheckStatusSkip, critical: false},
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "healthy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, router := setupTestHandler(tt.checkers...)

			req, _ := http.NewRequest("GET", tt.endpoint, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Verify response body contains expected status
			var resp map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}
			if resp["status"] != tt.expectedBody {
				t.Errorf("expected body status '%s', got '%v'", tt.expectedBody, resp["status"])
			}
		})
	}
}

func TestHandler_Integration_MultipleCheckersConcurrent(t *testing.T) {
	t.Parallel()

	// Test with multiple checkers that may complete at different times
	checkers := []Checker{
		&handlerTestChecker{name: "fast", status: CheckStatusPass, critical: true},
		&handlerTestChecker{name: "medium", status: CheckStatusPass, critical: true},
		&handlerTestChecker{name: "slow", status: CheckStatusPass, critical: false},
	}
	_, router := setupTestHandler(checkers...)

	req, _ := http.NewRequest("GET", "/health/ready", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp ReadinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Verify all checkers are included in response
	if len(resp.Checks) != 3 {
		t.Errorf("expected 3 checks, got %d", len(resp.Checks))
	}
	for _, name := range []string{"fast", "medium", "slow"} {
		if _, ok := resp.Checks[name]; !ok {
			t.Errorf("expected check %q in response", name)
		}
	}
}

func TestHandler_Integration_RequestIDOmittedWhenEmpty(t *testing.T) {
	t.Parallel()

	_, router := setupTestHandler()

	// Request without X-Request-ID header
	req, _ := http.NewRequest("GET", "/health/live", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify request_id is omitted (omitempty)
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if _, ok := resp["request_id"]; ok {
		t.Error("expected request_id to be omitted when empty")
	}
}

func TestBaseHealthResponse_JSONSerialization(t *testing.T) {
	t.Parallel()

	// Verify BaseHealthResponse embeds correctly into LivenessResponse
	liveness := LivenessResponse{
		BaseHealthResponse: BaseHealthResponse{
			Status:    "healthy",
			Service:   "test-service",
			Version:   "1.0.0",
			Timestamp: "2024-01-01T00:00:00Z",
		},
	}

	data, err := json.Marshal(liveness)
	if err != nil {
		t.Fatalf("failed to marshal LivenessResponse: %v", err)
	}

	// Verify fields are at top level (not nested under "BaseHealthResponse")
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	if _, ok := parsed["BaseHealthResponse"]; ok {
		t.Error("BaseHealthResponse should be embedded, not a nested field")
	}
	if parsed["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %v", parsed["status"])
	}
	if parsed["service"] != "test-service" {
		t.Errorf("expected service 'test-service', got %v", parsed["service"])
	}

	// Verify ReadinessResponse with checks
	readiness := ReadinessResponse{
		BaseHealthResponse: BaseHealthResponse{
			Status:    "healthy",
			Service:   "test-service",
			Version:   "1.0.0",
			Timestamp: "2024-01-01T00:00:00Z",
		},
		Checks: map[string]*CheckResult{
			"etcd": {Name: "etcd", Status: CheckStatusPass},
		},
	}

	data, err = json.Marshal(readiness)
	if err != nil {
		t.Fatalf("failed to marshal ReadinessResponse: %v", err)
	}

	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	if _, ok := parsed["BaseHealthResponse"]; ok {
		t.Error("BaseHealthResponse should be embedded, not a nested field")
	}
	if parsed["checks"] == nil {
		t.Error("expected checks field in ReadinessResponse")
	}
}
