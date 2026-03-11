package health

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// requestIDKey must stay aligned with server.RequestIDKey in
	// endpoints/server/requestid.go. If these values drift, health handlers may
	// miss middleware-injected IDs and return empty request IDs unexpectedly.
	//
	// Duplicating this constant avoids an import cycle: server -> health -> server.
	requestIDKey = "request_id"
)

// Handler handles health check HTTP endpoints.
type Handler struct {
	manager      *Manager
	knockManager *Manager // optional: includes AC peer checker for knock-traffic readiness
}

// NewHandler creates a new health handler.
func NewHandler(manager *Manager) *Handler {
	return &Handler{manager: manager}
}

// SetKnockManager sets a separate manager for the /health/knock-ready endpoint.
// This manager should include the AC peer checker as a critical check, so the NLB
// only routes knock traffic to servers with connected AC peers.
func (h *Handler) SetKnockManager(m *Manager) {
	h.knockManager = m
}

// BaseHealthResponse contains common fields for all health check responses.
// This avoids duplication between LivenessResponse and ReadinessResponse.
type BaseHealthResponse struct {
	Status    string `json:"status"`
	Service   string `json:"service"`
	Version   string `json:"version,omitempty"`
	Timestamp string `json:"timestamp"`
	RequestID string `json:"request_id,omitempty"`
}

// LivenessResponse is the JSON structure for liveness probe responses.
type LivenessResponse struct {
	BaseHealthResponse
}

// ReadinessResponse is the JSON structure for readiness probe responses.
type ReadinessResponse struct {
	BaseHealthResponse
	Checks map[string]*CheckResult `json:"checks,omitempty"`
}

// Liveness handles GET /health/live - Kubernetes liveness probe.
// This is a fast check that only verifies the service is running.
// Returns 200 if the service is alive, regardless of dependency status.
func (h *Handler) Liveness(c *gin.Context) {
	// Prevent caching of health check responses
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")

	// Extract request ID for distributed tracing
	requestID := GetRequestID(c)
	resp := h.manager.CheckLivenessWithRequestID(c.Request.Context(), requestID)

	c.JSON(http.StatusOK, LivenessResponse{
		BaseHealthResponse: BaseHealthResponse{
			Status:    string(resp.Status),
			Service:   resp.Service,
			Version:   resp.Version,
			Timestamp: resp.Timestamp.Format(time.RFC3339),
			RequestID: resp.RequestID,
		},
	})
}

// Readiness handles GET /health/ready - Kubernetes readiness probe.
// This performs deep health checks on all registered components.
// Returns:
//   - 200 if healthy or degraded (can accept traffic)
//   - 503 if unhealthy (critical dependencies failed)
func (h *Handler) Readiness(c *gin.Context) {
	h.serveReadinessCheck(c, h.manager)
}

// Startup handles GET /health/startup - Kubernetes startup probe.
// Startup probes (Kubernetes 1.16+) prevent liveness probes from killing
// slow-starting containers.
// Returns:
//   - 200 if startup completed successfully
//   - 503 if startup is still in progress or failed
func (h *Handler) Startup(c *gin.Context) {
	// Prevent caching of health check responses
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")

	// Extract request ID for distributed tracing
	requestID := GetRequestID(c)
	resp := h.manager.CheckStartupWithRequestID(c.Request.Context(), requestID)

	httpStatus := http.StatusOK
	if resp.Status == StatusUnhealthy {
		httpStatus = http.StatusServiceUnavailable
	}

	c.JSON(httpStatus, ReadinessResponse{
		BaseHealthResponse: BaseHealthResponse{
			Status:    string(resp.Status),
			Service:   resp.Service,
			Version:   resp.Version,
			Timestamp: resp.Timestamp.Format(time.RFC3339),
			RequestID: resp.RequestID,
		},
		Checks: resp.Checks,
	})
}

// KnockReadiness handles GET /health/knock-ready.
// This checks whether the server can process knock requests, which requires
// at least one connected AC peer in addition to storage being healthy.
//
// Used by the NLB HTTPS listener health check to prevent routing knock traffic
// to servers that would fail every request. Separate from /health/ready so that
// ASG/Docker health checks (which use /health/live) don't terminate servers
// that are healthy but waiting for AC connections.
//
// Returns:
//   - 200 if all checks pass (storage + AC peers connected)
//   - 503 if any critical check fails (no AC peers or storage down)
func (h *Handler) KnockReadiness(c *gin.Context) {
	if h.knockManager == nil {
		// Fall back to regular readiness if knock manager not configured.
		h.Readiness(c)
		return
	}
	h.serveReadinessCheck(c, h.knockManager)
}

// serveReadinessCheck runs readiness checks on the given manager and writes
// the JSON response. Shared by Readiness and KnockReadiness handlers.
func (h *Handler) serveReadinessCheck(c *gin.Context, m *Manager) {
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")

	requestID := GetRequestID(c)
	resp := m.CheckReadinessWithRequestID(c.Request.Context(), requestID)

	httpStatus := http.StatusOK
	if resp.Status == StatusUnhealthy {
		httpStatus = http.StatusServiceUnavailable
	}

	c.JSON(httpStatus, ReadinessResponse{
		BaseHealthResponse: BaseHealthResponse{
			Status:    string(resp.Status),
			Service:   resp.Service,
			Version:   resp.Version,
			Timestamp: resp.Timestamp.Format(time.RFC3339),
			RequestID: resp.RequestID,
		},
		Checks: resp.Checks,
	})
}

// Health handles GET /health - Standard health check endpoint.
// This is an alias for the readiness check.
func (h *Handler) Health(c *gin.Context) {
	h.Readiness(c)
}

// GetRequestID retrieves the request ID from Gin context.
//
// Health handlers intentionally read request IDs from context only, not directly
// from headers. This keeps behavior aligned with middleware-driven request ID
// propagation in the server package. Routes using this helper must run behind
// requestIDMiddleware to guarantee request_id is populated.
//
// It mirrors server/requestid.go behavior and avoids package import cycles.
func GetRequestID(c *gin.Context) string {
	if id, exists := c.Get(requestIDKey); exists {
		if s, ok := id.(string); ok {
			return s
		}
	}
	return ""
}

// RegisterRoutes registers health check routes on the given Gin engine.
func (h *Handler) RegisterRoutes(g *gin.Engine) {
	g.GET("/health", h.Health)
	g.GET("/health/live", h.Liveness)
	g.GET("/health/ready", h.Readiness)
	g.GET("/health/knock-ready", h.KnockReadiness)
	g.GET("/health/startup", h.Startup)
}
