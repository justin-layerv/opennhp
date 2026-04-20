// Package health provides health checking infrastructure for the NHP server.
// It supports liveness and readiness probes following Kubernetes patterns,
// with deep health checks for critical dependencies like etcd.
//
// Health endpoints are served on the internal HTTP port (8888) which is
// only accessible within the VPC, maintaining NHP's minimal public footprint.
package health

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// Status represents the overall health status of the service.
type Status string

const (
	// StatusHealthy indicates all checks passed.
	StatusHealthy Status = "healthy"
	// StatusDegraded indicates some non-critical checks failed.
	StatusDegraded Status = "degraded"
	// StatusUnhealthy indicates critical checks failed.
	StatusUnhealthy Status = "unhealthy"
)

// CheckStatus represents the status of an individual health check.
type CheckStatus string

const (
	// CheckStatusPass indicates the check passed.
	CheckStatusPass CheckStatus = "pass"
	// CheckStatusWarn indicates the check passed with warnings.
	CheckStatusWarn CheckStatus = "warn"
	// CheckStatusFail indicates the check failed.
	CheckStatusFail CheckStatus = "fail"
	// CheckStatusSkip indicates the check was skipped (not configured).
	CheckStatusSkip CheckStatus = "skip"
)

// CheckResult represents the result of a single health check.
type CheckResult struct {
	// Name is the identifier for this check (e.g., "etcd").
	Name string `json:"name"`
	// Status is the result of the check.
	Status CheckStatus `json:"status"`
	// Message provides additional details about the check result.
	Message string `json:"message,omitempty"`
	// DurationMS is how long the check took in milliseconds.
	DurationMS int64 `json:"duration_ms"`
	// Critical indicates if this check failing means the service is unhealthy.
	Critical bool `json:"critical"`
	// Timestamp is when the check was performed.
	Timestamp time.Time `json:"timestamp"`

	// duration stores the actual duration for internal use.
	duration time.Duration `json:"-"`
}

// SetDuration sets the check duration and updates DurationMS for JSON serialization.
func (r *CheckResult) SetDuration(d time.Duration) {
	r.duration = d
	r.DurationMS = d.Milliseconds()
}

// Duration returns the check duration.
func (r *CheckResult) Duration() time.Duration {
	return r.duration
}

// HealthResponse represents the complete health check response.
// Follows IETF draft-inadarei-api-health-check format.
type HealthResponse struct {
	// Status is the overall health status.
	Status Status `json:"status"`
	// Service identifies this service (serviceId in IETF draft).
	Service string `json:"service"`
	// Version is the service version (if available).
	Version string `json:"version,omitempty"`
	// Checks contains individual check results.
	Checks map[string]*CheckResult `json:"checks,omitempty"`
	// Timestamp is when the health check was performed.
	Timestamp time.Time `json:"timestamp"`
	// RequestID is the trace identifier for this health check request.
	RequestID string `json:"request_id,omitempty"`
}

// Checker is the interface that health check components must implement.
type Checker interface {
	// Name returns the identifier for this checker.
	Name() string
	// Check performs the health check and returns the result.
	Check(ctx context.Context) *CheckResult
	// IsCritical returns true if this check failing means the service is unhealthy.
	IsCritical() bool
}

// Manager coordinates health checks across multiple components.
type Manager struct {
	mu             sync.RWMutex
	checkers       []Checker
	service        string
	version        string
	timeout        time.Duration
	startupTimeout time.Duration
	startupReady   atomic.Bool // true once startup checks have passed
	startedAt      time.Time
}

// ManagerConfig holds configuration for the health manager.
type ManagerConfig struct {
	// Service is the service name to include in responses.
	Service string
	// Version is the service version to include in responses.
	Version string
	// Timeout is the maximum time to wait for all checks to complete.
	Timeout time.Duration
	// StartupTimeout is the maximum time allowed for startup before failing.
	StartupTimeout time.Duration
}

// NewManager creates a new health check manager.
func NewManager(cfg *ManagerConfig) *Manager {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	startupTimeout := cfg.StartupTimeout
	if startupTimeout == 0 {
		startupTimeout = 60 * time.Second
	}

	return &Manager{
		checkers:       make([]Checker, 0),
		service:        cfg.Service,
		version:        cfg.Version,
		timeout:        timeout,
		startupTimeout: startupTimeout,
		startedAt:      time.Now(),
	}
}

// Register adds a health checker to the manager.
func (m *Manager) Register(checker Checker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkers = append(m.checkers, checker)
}

// CheckLiveness performs a simple liveness check.
// This should be fast and only verify the service is running.
func (m *Manager) CheckLiveness(ctx context.Context) *HealthResponse {
	return m.CheckLivenessWithRequestID(ctx, "")
}

// CheckLivenessWithRequestID performs liveness check with a request ID for tracing.
func (m *Manager) CheckLivenessWithRequestID(_ context.Context, requestID string) *HealthResponse {
	return &HealthResponse{
		Status:    StatusHealthy,
		Service:   m.service,
		Version:   m.version,
		Timestamp: time.Now().UTC(),
		RequestID: requestID,
	}
}

// CheckStartup performs a startup check for Kubernetes startup probes.
// This runs all health checks like readiness, but also tracks whether
// the service has completed its initial startup successfully.
//
// Startup probes (Kubernetes 1.16+) are useful for slow-starting containers.
// They prevent liveness probes from killing the container before it's ready.
//
// Returns unhealthy if:
// - Any critical health check fails
// - The startup timeout has been exceeded
func (m *Manager) CheckStartup(ctx context.Context) *HealthResponse {
	return m.CheckStartupWithRequestID(ctx, "")
}

// CheckStartupWithRequestID performs startup check with a request ID for tracing.
func (m *Manager) CheckStartupWithRequestID(ctx context.Context, requestID string) *HealthResponse {
	// Check if we've exceeded the startup timeout
	if time.Since(m.startedAt) > m.startupTimeout && !m.startupReady.Load() {
		return &HealthResponse{
			Status:    StatusUnhealthy,
			Service:   m.service,
			Version:   m.version,
			Timestamp: time.Now().UTC(),
			RequestID: requestID,
			Checks: map[string]*CheckResult{
				"startup_timeout": {
					Name:      "startup_timeout",
					Status:    CheckStatusFail,
					Message:   fmt.Sprintf("startup timeout exceeded (%v)", m.startupTimeout),
					Timestamp: time.Now(),
					Critical:  true,
				},
			},
		}
	}

	// Run readiness checks
	resp := m.checkReadinessWithRequestID(ctx, requestID)

	// If all checks pass, mark startup as complete
	if resp.Status == StatusHealthy {
		m.startupReady.Store(true)
	}

	return resp
}

// StartupTimeout returns the configured startup grace period — the window
// during which CheckStartup will still run readiness probes to flip
// startupReady. Callers typically use this to bound a startup-probe
// warming loop (see HttpServer.warmStartupProbe).
func (m *Manager) StartupTimeout() time.Duration {
	return m.startupTimeout
}

// IsStartupComplete returns true if the service has completed startup successfully.
func (m *Manager) IsStartupComplete() bool {
	return m.startupReady.Load()
}

// MarkStartupComplete manually marks the service as having completed startup.
func (m *Manager) MarkStartupComplete() {
	m.startupReady.Store(true)
}

// CheckReadiness performs deep health checks on all registered components.
// This verifies the service is ready to accept traffic.
// Panics in individual checkers are recovered and reported as failures.
func (m *Manager) CheckReadiness(ctx context.Context) *HealthResponse {
	return m.checkReadinessWithRequestID(ctx, "")
}

// CheckReadinessWithRequestID performs readiness check with a request ID for tracing.
func (m *Manager) CheckReadinessWithRequestID(ctx context.Context, requestID string) *HealthResponse {
	return m.checkReadinessWithRequestID(ctx, requestID)
}

func (m *Manager) checkReadinessWithRequestID(ctx context.Context, requestID string) *HealthResponse {
	m.mu.RLock()
	checkers := slices.Clone(m.checkers)
	m.mu.RUnlock()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	// Run all checks in parallel with panic recovery
	results := make(chan *CheckResult, len(checkers))
	var wg sync.WaitGroup

	for _, checker := range checkers {
		wg.Add(1)
		go func(c Checker) {
			defer wg.Done()
			result := m.runCheckerSafe(ctx, c)
			results <- result
		}(checker)
	}

	// Wait for all checks to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	checks := make(map[string]*CheckResult)
	overallStatus := StatusHealthy
	hasCriticalFailure := false
	hasWarning := false

	for result := range results {
		checks[result.Name] = result

		// CheckStatusSkip is treated as healthy (not configured = OK).
		// This is safe because HttpServer.initHealthManager() fails fast at startup
		// if no storage backend is configured (ErrNoStorageBackend). The Skip status
		// is only relevant for truly optional checkers (e.g., cache, metrics).
		switch result.Status {
		case CheckStatusSkip:
			// Log warning if a critical checker returns Skip - this shouldn't happen
			// if the system is properly configured, but helps catch misconfigurations.
			if result.Critical {
				log.Warning("health check: critical checker %q returned Skip status - verify configuration", result.Name)
			}
		case CheckStatusFail:
			if result.Critical {
				hasCriticalFailure = true
			} else {
				hasWarning = true
			}
		case CheckStatusWarn:
			hasWarning = true
		}
	}

	// Determine overall status
	if hasCriticalFailure {
		overallStatus = StatusUnhealthy
	} else if hasWarning {
		overallStatus = StatusDegraded
	}

	return &HealthResponse{
		Status:    overallStatus,
		Service:   m.service,
		Version:   m.version,
		Checks:    checks,
		Timestamp: time.Now().UTC(),
		RequestID: requestID,
	}
}

// runCheckerSafe runs a health checker with panic recovery.
// If the checker panics, it returns a failed result instead of crashing.
func (m *Manager) runCheckerSafe(ctx context.Context, c Checker) (result *CheckResult) {
	start := time.Now()

	// Recover from panics in the checker
	defer func() {
		if r := recover(); r != nil {
			result = &CheckResult{
				Name:      c.Name(),
				Status:    CheckStatusFail,
				Message:   fmt.Sprintf("checker panicked: %v", r),
				Timestamp: start,
				Critical:  c.IsCritical(),
			}
			result.SetDuration(time.Since(start))
		}
	}()

	result = c.Check(ctx)
	result.Critical = c.IsCritical()
	return result
}

// CheckHealth performs the standard health check (alias for readiness).
func (m *Manager) CheckHealth(ctx context.Context) *HealthResponse {
	return m.CheckReadiness(ctx)
}

// IsHealthy returns true if the readiness check indicates healthy or degraded status.
func (m *Manager) IsHealthy(ctx context.Context) bool {
	resp := m.CheckReadiness(ctx)
	return resp.Status != StatusUnhealthy
}
