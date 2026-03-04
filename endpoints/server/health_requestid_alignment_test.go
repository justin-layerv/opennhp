package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/endpoints/server/health"
)

// TestHealthHandler_RequestIDAlignedWithServerMiddleware is a drift-detection test.
// It verifies that server.requestIDMiddleware and health.GetRequestID agree on the
// same context key semantics. If server.RequestIDKey and health.requestIDKey ever
// diverge, health responses will stop carrying request_id and this test will fail.
func TestHealthHandler_RequestIDAlignedWithServerMiddleware(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(requestIDMiddleware())

	manager := health.NewManager(&health.ManagerConfig{
		Service:        "test-service",
		Version:        "1.0.0",
		Timeout:        5 * time.Second,
		StartupTimeout: 30 * time.Second,
	})
	health.NewHandler(manager).RegisterRoutes(router)

	req, _ := http.NewRequest("GET", "/health/live", nil)
	req.Header.Set(RequestIDHeader, "alignment-test-id")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if got, ok := resp["request_id"].(string); !ok || got != "alignment-test-id" {
		t.Fatalf("expected request_id %q from middleware context, got %v", "alignment-test-id", resp["request_id"])
	}
}
