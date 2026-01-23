package health

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewDynamoDBChecker(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		cfg         *DynamoDBCheckerConfig
		wantTimeout time.Duration
	}{
		{
			name: "with timeout",
			cfg: &DynamoDBCheckerConfig{
				Client:  &mockDynamoDBPinger{},
				Timeout: 10 * time.Second,
			},
			wantTimeout: 10 * time.Second,
		},
		{
			name: "default timeout",
			cfg: &DynamoDBCheckerConfig{
				Client: &mockDynamoDBPinger{},
			},
			wantTimeout: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := NewDynamoDBChecker(tt.cfg)
			if c.timeout != tt.wantTimeout {
				t.Errorf("timeout = %v, want %v", c.timeout, tt.wantTimeout)
			}
		})
	}
}

func TestDynamoDBChecker_Name(t *testing.T) {
	t.Parallel()

	c := NewDynamoDBChecker(&DynamoDBCheckerConfig{Client: &mockDynamoDBPinger{}})
	if c.Name() != "dynamodb" {
		t.Errorf("Name() = %q, want %q", c.Name(), "dynamodb")
	}
}

func TestDynamoDBChecker_IsCritical(t *testing.T) {
	t.Parallel()

	c := NewDynamoDBChecker(&DynamoDBCheckerConfig{Client: &mockDynamoDBPinger{}})
	if !c.IsCritical() {
		t.Error("DynamoDB checker should be critical")
	}
}

func TestDynamoDBChecker_Check_NoClient(t *testing.T) {
	t.Parallel()

	c := NewDynamoDBChecker(&DynamoDBCheckerConfig{
		Client: nil,
	})

	result := c.Check(context.Background())

	if result.Status != CheckStatusSkip {
		t.Errorf("status = %q, want %q", result.Status, CheckStatusSkip)
	}
	if result.Message != "DynamoDB client not configured" {
		t.Errorf("message = %q, want 'DynamoDB client not configured'", result.Message)
	}
}

func TestDynamoDBChecker_Check_Success(t *testing.T) {
	t.Parallel()

	c := NewDynamoDBChecker(&DynamoDBCheckerConfig{
		Client:  &mockDynamoDBPinger{err: nil},
		Timeout: 5 * time.Second,
	})

	result := c.Check(context.Background())

	if result.Status != CheckStatusPass {
		t.Errorf("status = %q, want %q", result.Status, CheckStatusPass)
	}
	if result.Message != "DynamoDB connection successful" {
		t.Errorf("message = %q, want 'DynamoDB connection successful'", result.Message)
	}
	if result.DurationMS < 0 {
		t.Errorf("DurationMS = %d, should be >= 0", result.DurationMS)
	}
}

func TestDynamoDBChecker_Check_Failure(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("connection refused")
	c := NewDynamoDBChecker(&DynamoDBCheckerConfig{
		Client:  &mockDynamoDBPinger{err: expectedErr},
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

func TestDynamoDBChecker_Check_Timeout(t *testing.T) {
	t.Parallel()

	c := NewDynamoDBChecker(&DynamoDBCheckerConfig{
		Client:  &mockDynamoDBPinger{delay: 200 * time.Millisecond},
		Timeout: 50 * time.Millisecond, // Shorter than delay
	})

	result := c.Check(context.Background())

	// Should fail due to timeout
	if result.Status != CheckStatusFail {
		t.Errorf("status = %q, want %q", result.Status, CheckStatusFail)
	}
}

func TestDynamoDBChecker_Interface(t *testing.T) {
	t.Parallel()

	// Verify DynamoDBChecker implements Checker interface
	var _ Checker = (*DynamoDBChecker)(nil)
}

// mockDynamoDBPinger is a test double for DynamoDBPinger.
type mockDynamoDBPinger struct {
	err   error
	delay time.Duration
}

func (m *mockDynamoDBPinger) Ping(ctx context.Context) error {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return m.err
}
