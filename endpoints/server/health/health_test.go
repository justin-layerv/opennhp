package health

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *ManagerConfig
		wantSvc string
		wantVer string
	}{
		{
			name: "with all config",
			cfg: &ManagerConfig{
				Service: "test-service",
				Version: "1.0.0",
				Timeout: 5 * time.Second,
			},
			wantSvc: "test-service",
			wantVer: "1.0.0",
		},
		{
			name: "with default timeout",
			cfg: &ManagerConfig{
				Service: "svc",
				Version: "v2",
			},
			wantSvc: "svc",
			wantVer: "v2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := NewManager(tt.cfg)
			if m.service != tt.wantSvc {
				t.Errorf("service = %q, want %q", m.service, tt.wantSvc)
			}
			if m.version != tt.wantVer {
				t.Errorf("version = %q, want %q", m.version, tt.wantVer)
			}
		})
	}
}

func TestManager_Register(t *testing.T) {
	t.Parallel()

	m := NewManager(&ManagerConfig{Service: "test"})

	// Register a mock checker
	checker := &mockChecker{name: "test-checker", critical: true}
	m.Register(checker)

	if len(m.checkers) != 1 {
		t.Errorf("expected 1 checker, got %d", len(m.checkers))
	}

	// Register another
	m.Register(&mockChecker{name: "another"})
	if len(m.checkers) != 2 {
		t.Errorf("expected 2 checkers, got %d", len(m.checkers))
	}
}

func TestManager_CheckLiveness(t *testing.T) {
	t.Parallel()

	m := NewManager(&ManagerConfig{
		Service: "nhp-server",
		Version: "1.2.3",
	})

	resp := m.CheckLiveness(context.Background())

	if resp.Status != StatusHealthy {
		t.Errorf("status = %q, want %q", resp.Status, StatusHealthy)
	}
	if resp.Service != "nhp-server" {
		t.Errorf("service = %q, want %q", resp.Service, "nhp-server")
	}
	if resp.Version != "1.2.3" {
		t.Errorf("version = %q, want %q", resp.Version, "1.2.3")
	}
	if resp.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
}

func TestManager_CheckReadiness(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		checkers   []Checker
		wantStatus Status
	}{
		{
			name:       "no checkers - healthy",
			checkers:   nil,
			wantStatus: StatusHealthy,
		},
		{
			name: "all pass - healthy",
			checkers: []Checker{
				&mockChecker{name: "etcd", status: CheckStatusPass, critical: true},
			},
			wantStatus: StatusHealthy,
		},
		{
			name: "critical fail - unhealthy",
			checkers: []Checker{
				&mockChecker{name: "etcd", status: CheckStatusFail, critical: true},
			},
			wantStatus: StatusUnhealthy,
		},
		{
			name: "non-critical fail - degraded",
			checkers: []Checker{
				&mockChecker{name: "etcd", status: CheckStatusPass, critical: true},
				&mockChecker{name: "cache", status: CheckStatusFail, critical: false},
			},
			wantStatus: StatusDegraded,
		},
		{
			name: "warn - degraded",
			checkers: []Checker{
				&mockChecker{name: "etcd", status: CheckStatusWarn, critical: true},
			},
			wantStatus: StatusDegraded,
		},
		{
			name: "skip - healthy (not configured is ok)",
			checkers: []Checker{
				&mockChecker{name: "etcd", status: CheckStatusSkip, critical: true},
			},
			wantStatus: StatusHealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := NewManager(&ManagerConfig{Service: "test", Timeout: time.Second})
			for _, c := range tt.checkers {
				m.Register(c)
			}

			resp := m.CheckReadiness(context.Background())

			if resp.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", resp.Status, tt.wantStatus)
			}
			if len(resp.Checks) != len(tt.checkers) {
				t.Errorf("checks = %d, want %d", len(resp.Checks), len(tt.checkers))
			}
		})
	}
}

func TestManager_CheckReadiness_PanicRecovery(t *testing.T) {
	t.Parallel()

	m := NewManager(&ManagerConfig{
		Service: "test",
		Timeout: time.Second,
	})

	// Register a checker that will panic
	m.Register(&panicChecker{name: "panicking", critical: true})

	// Register a normal checker to verify others still run
	m.Register(&mockChecker{name: "normal", status: CheckStatusPass, critical: false})

	resp := m.CheckReadiness(context.Background())

	// The panicking checker should be reported as failed
	if resp.Status != StatusUnhealthy {
		t.Errorf("status = %q, want %q (panicking checker is critical)", resp.Status, StatusUnhealthy)
	}

	// Both checks should be in the response
	if len(resp.Checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(resp.Checks))
	}

	// Verify panicking checker result
	panicResult, ok := resp.Checks["panicking"]
	if !ok {
		t.Fatal("panicking check not found in response")
	}
	if panicResult.Status != CheckStatusFail {
		t.Errorf("panic check status = %q, want %q", panicResult.Status, CheckStatusFail)
	}

	// Verify normal checker still ran
	normalResult, ok := resp.Checks["normal"]
	if !ok {
		t.Fatal("normal check not found in response")
	}
	if normalResult.Status != CheckStatusPass {
		t.Errorf("normal check status = %q, want %q", normalResult.Status, CheckStatusPass)
	}
}

func TestManager_CheckStartup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		checkers   []Checker
		wantStatus Status
		wantReady  bool
	}{
		{
			name:       "no checkers - healthy and ready",
			checkers:   nil,
			wantStatus: StatusHealthy,
			wantReady:  true,
		},
		{
			name: "all pass - marks startup complete",
			checkers: []Checker{
				&mockChecker{name: "etcd", status: CheckStatusPass, critical: true},
			},
			wantStatus: StatusHealthy,
			wantReady:  true,
		},
		{
			name: "critical fail - unhealthy, not ready",
			checkers: []Checker{
				&mockChecker{name: "etcd", status: CheckStatusFail, critical: true},
			},
			wantStatus: StatusUnhealthy,
			wantReady:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := NewManager(&ManagerConfig{
				Service:        "test",
				Timeout:        time.Second,
				StartupTimeout: 60 * time.Second,
			})
			for _, c := range tt.checkers {
				m.Register(c)
			}

			resp := m.CheckStartup(context.Background())

			if resp.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", resp.Status, tt.wantStatus)
			}
			if m.IsStartupComplete() != tt.wantReady {
				t.Errorf("IsStartupComplete() = %v, want %v", m.IsStartupComplete(), tt.wantReady)
			}
		})
	}
}

func TestManager_CheckStartup_Timeout(t *testing.T) {
	t.Parallel()

	// Create manager with very short startup timeout that has already passed
	m := NewManager(&ManagerConfig{
		Service:        "test",
		Timeout:        time.Second,
		StartupTimeout: 1 * time.Nanosecond, // Already expired
	})

	// Wait a tiny bit to ensure startup timeout passes
	time.Sleep(1 * time.Millisecond)

	// Register a failing checker so startup never completes
	m.Register(&mockChecker{name: "etcd", status: CheckStatusFail, critical: true})

	resp := m.CheckStartup(context.Background())

	// Should be unhealthy due to timeout
	if resp.Status != StatusUnhealthy {
		t.Errorf("status = %q, want %q", resp.Status, StatusUnhealthy)
	}

	// Should have a startup_timeout check
	if _, exists := resp.Checks["startup_timeout"]; !exists {
		t.Error("expected startup_timeout check in response")
	}
}

func TestManager_MarkStartupComplete(t *testing.T) {
	t.Parallel()

	m := NewManager(&ManagerConfig{Service: "test"})

	if m.IsStartupComplete() {
		t.Error("new manager should not be startup complete")
	}

	m.MarkStartupComplete()

	if !m.IsStartupComplete() {
		t.Error("manager should be startup complete after MarkStartupComplete()")
	}
}

func TestManager_IsHealthy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		checker *mockChecker
		want    bool
	}{
		{
			name:    "healthy",
			checker: &mockChecker{name: "etcd", status: CheckStatusPass, critical: true},
			want:    true,
		},
		{
			name:    "degraded is still healthy for traffic",
			checker: &mockChecker{name: "cache", status: CheckStatusWarn, critical: false},
			want:    true,
		},
		{
			name:    "unhealthy",
			checker: &mockChecker{name: "etcd", status: CheckStatusFail, critical: true},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := NewManager(&ManagerConfig{Service: "test", Timeout: time.Second})
			m.Register(tt.checker)

			got := m.IsHealthy(context.Background())
			if got != tt.want {
				t.Errorf("IsHealthy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckResult_DurationSerialization(t *testing.T) {
	t.Parallel()

	result := &CheckResult{
		Name:      "test",
		Status:    CheckStatusPass,
		Message:   "test message",
		Timestamp: time.Now(),
		Critical:  true,
	}

	// Set duration to 150ms
	result.SetDuration(150 * time.Millisecond)

	// Verify internal duration is stored
	if result.Duration() != 150*time.Millisecond {
		t.Errorf("Duration() = %v, want %v", result.Duration(), 150*time.Millisecond)
	}

	// Verify DurationMS is set correctly
	if result.DurationMS != 150 {
		t.Errorf("DurationMS = %d, want 150", result.DurationMS)
	}

	// Verify JSON serialization
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var unmarshaled map[string]any
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// duration_ms should be a number (150), not nanoseconds
	durationMS, ok := unmarshaled["duration_ms"].(float64)
	if !ok {
		t.Fatalf("duration_ms not found or not a number: %v", unmarshaled["duration_ms"])
	}
	if durationMS != 150 {
		t.Errorf("JSON duration_ms = %v, want 150", durationMS)
	}
}

// mockChecker is a test double for the Checker interface.
type mockChecker struct {
	name     string
	status   CheckStatus
	critical bool
	delay    time.Duration
	message  string
}

func (m *mockChecker) Name() string {
	return m.name
}

func (m *mockChecker) IsCritical() bool {
	return m.critical
}

func (m *mockChecker) Check(ctx context.Context) *CheckResult {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return &CheckResult{
				Name:      m.name,
				Status:    CheckStatusFail,
				Message:   "timeout",
				Timestamp: time.Now(),
				Critical:  m.critical,
			}
		}
	}

	msg := m.message
	if msg == "" {
		msg = "mock check"
	}

	result := &CheckResult{
		Name:      m.name,
		Status:    m.status,
		Message:   msg,
		Timestamp: time.Now(),
		Critical:  m.critical,
	}
	result.SetDuration(m.delay)
	return result
}

// panicChecker is a test double that panics during Check.
type panicChecker struct {
	name     string
	critical bool
}

func (p *panicChecker) Name() string {
	return p.name
}

func (p *panicChecker) IsCritical() bool {
	return p.critical
}

func (p *panicChecker) Check(_ context.Context) *CheckResult {
	panic("intentional panic for testing")
}

func TestManager_CheckLivenessWithRequestID(t *testing.T) {
	t.Parallel()

	m := NewManager(&ManagerConfig{
		Service: "test",
		Version: "1.0.0",
	})

	requestID := "test-request-123"
	resp := m.CheckLivenessWithRequestID(context.Background(), requestID)

	if resp.RequestID != requestID {
		t.Errorf("RequestID = %q, want %q", resp.RequestID, requestID)
	}
	if resp.Status != StatusHealthy {
		t.Errorf("status = %q, want %q", resp.Status, StatusHealthy)
	}
}

func TestManager_CheckReadinessWithRequestID(t *testing.T) {
	t.Parallel()

	m := NewManager(&ManagerConfig{
		Service: "test",
		Timeout: time.Second,
	})
	m.Register(&mockChecker{name: "db", status: CheckStatusPass, critical: true})

	requestID := "test-request-456"
	resp := m.CheckReadinessWithRequestID(context.Background(), requestID)

	if resp.RequestID != requestID {
		t.Errorf("RequestID = %q, want %q", resp.RequestID, requestID)
	}
	if resp.Status != StatusHealthy {
		t.Errorf("status = %q, want %q", resp.Status, StatusHealthy)
	}
}

func TestManager_CheckStartupWithRequestID(t *testing.T) {
	t.Parallel()

	m := NewManager(&ManagerConfig{
		Service:        "test",
		Timeout:        time.Second,
		StartupTimeout: 60 * time.Second,
	})
	m.Register(&mockChecker{name: "db", status: CheckStatusPass, critical: true})

	requestID := "test-request-789"
	resp := m.CheckStartupWithRequestID(context.Background(), requestID)

	if resp.RequestID != requestID {
		t.Errorf("RequestID = %q, want %q", resp.RequestID, requestID)
	}
	if resp.Status != StatusHealthy {
		t.Errorf("status = %q, want %q", resp.Status, StatusHealthy)
	}
}

func TestManager_CheckStartupWithRequestID_Timeout(t *testing.T) {
	t.Parallel()

	// Create manager with very short startup timeout that has already passed
	m := NewManager(&ManagerConfig{
		Service:        "test",
		Timeout:        time.Second,
		StartupTimeout: 1 * time.Nanosecond, // Already expired
	})

	// Wait a tiny bit to ensure startup timeout passes
	time.Sleep(1 * time.Millisecond)

	// Register a failing checker so startup never completes
	m.Register(&mockChecker{name: "db", status: CheckStatusFail, critical: true})

	requestID := "test-timeout-request"
	resp := m.CheckStartupWithRequestID(context.Background(), requestID)

	// Should be unhealthy due to timeout
	if resp.Status != StatusUnhealthy {
		t.Errorf("status = %q, want %q", resp.Status, StatusUnhealthy)
	}

	// RequestID should still be set even on timeout
	if resp.RequestID != requestID {
		t.Errorf("RequestID = %q, want %q", resp.RequestID, requestID)
	}

	// Should have a startup_timeout check
	if _, exists := resp.Checks["startup_timeout"]; !exists {
		t.Error("expected startup_timeout check in response")
	}
}
