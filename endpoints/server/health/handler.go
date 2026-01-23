package health

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Handler handles health check HTTP endpoints.
type Handler struct {
	manager *Manager
}

// NewHandler creates a new health handler.
func NewHandler(manager *Manager) *Handler {
	return &Handler{manager: manager}
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
	requestID := c.GetHeader("X-Request-ID")
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
	// Prevent caching of health check responses
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")

	// Extract request ID for distributed tracing
	requestID := c.GetHeader("X-Request-ID")
	resp := h.manager.CheckReadinessWithRequestID(c.Request.Context(), requestID)

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
	requestID := c.GetHeader("X-Request-ID")
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

// Health handles GET /health - Standard health check endpoint.
// This is an alias for the readiness check.
func (h *Handler) Health(c *gin.Context) {
	h.Readiness(c)
}

// RegisterRoutes registers health check routes on the given Gin engine.
func (h *Handler) RegisterRoutes(g *gin.Engine) {
	g.GET("/health", h.Health)
	g.GET("/health/live", h.Liveness)
	g.GET("/health/ready", h.Readiness)
	g.GET("/health/startup", h.Startup)
}
