package health

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewEtcdChecker(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		cfg         *EtcdCheckerConfig
		wantTimeout time.Duration
	}{
		{
			name: "with timeout",
			cfg: &EtcdCheckerConfig{
				Client:  &mockEtcdPinger{},
				Timeout: 10 * time.Second,
			},
			wantTimeout: 10 * time.Second,
		},
		{
			name: "default timeout",
			cfg: &EtcdCheckerConfig{
				Client: &mockEtcdPinger{},
			},
			wantTimeout: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := NewEtcdChecker(tt.cfg)
			if c.timeout != tt.wantTimeout {
				t.Errorf("timeout = %v, want %v", c.timeout, tt.wantTimeout)
			}
		})
	}
}

func TestEtcdChecker_Name(t *testing.T) {
	t.Parallel()

	c := NewEtcdChecker(&EtcdCheckerConfig{Client: &mockEtcdPinger{}})
	if c.Name() != "etcd" {
		t.Errorf("Name() = %q, want %q", c.Name(), "etcd")
	}
}

func TestEtcdChecker_IsCritical(t *testing.T) {
	t.Parallel()

	c := NewEtcdChecker(&EtcdCheckerConfig{Client: &mockEtcdPinger{}})
	if !c.IsCritical() {
		t.Error("etcd checker should be critical")
	}
}

func TestEtcdChecker_Check_NoClient(t *testing.T) {
	t.Parallel()

	c := NewEtcdChecker(&EtcdCheckerConfig{
		Client: nil,
	})

	result := c.Check(context.Background())

	if result.Status != CheckStatusSkip {
		t.Errorf("status = %q, want %q", result.Status, CheckStatusSkip)
	}
	if result.Message != "etcd client not configured" {
		t.Errorf("message = %q, want 'etcd client not configured'", result.Message)
	}
}

func TestEtcdChecker_Check_Success(t *testing.T) {
	t.Parallel()

	c := NewEtcdChecker(&EtcdCheckerConfig{
		Client:  &mockEtcdPinger{err: nil},
		Timeout: 5 * time.Second,
	})

	result := c.Check(context.Background())

	if result.Status != CheckStatusPass {
		t.Errorf("status = %q, want %q", result.Status, CheckStatusPass)
	}
	if result.Message != "etcd is healthy" {
		t.Errorf("message = %q, want 'etcd is healthy'", result.Message)
	}
	if result.DurationMS < 0 {
		t.Errorf("DurationMS = %d, should be >= 0", result.DurationMS)
	}
}

func TestEtcdChecker_Check_Failure(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("connection refused")
	c := NewEtcdChecker(&EtcdCheckerConfig{
		Client:  &mockEtcdPinger{err: expectedErr},
		Timeout: 5 * time.Second,
	})

	result := c.Check(context.Background())

	if result.Status != CheckStatusFail {
		t.Errorf("status = %q, want %q", result.Status, CheckStatusFail)
	}
	if result.Message == "" {
		t.Error("message should not be empty on failure")
	}
}

func TestEtcdChecker_Check_Timeout(t *testing.T) {
	t.Parallel()

	c := NewEtcdChecker(&EtcdCheckerConfig{
		Client:  &mockEtcdPinger{delay: 200 * time.Millisecond},
		Timeout: 50 * time.Millisecond, // Shorter than delay
	})

	result := c.Check(context.Background())

	// Should fail due to timeout
	if result.Status != CheckStatusFail {
		t.Errorf("status = %q, want %q", result.Status, CheckStatusFail)
	}
}

func TestEtcdChecker_Interface(t *testing.T) {
	t.Parallel()

	// Verify EtcdChecker implements Checker interface
	var _ Checker = (*EtcdChecker)(nil)
}

// mockEtcdPinger is a test double for EtcdPinger.
type mockEtcdPinger struct {
	err   error
	delay time.Duration
}

func (m *mockEtcdPinger) Ping(ctx context.Context) error {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return m.err
}
