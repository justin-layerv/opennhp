package health

import (
	"context"
	"testing"
)

// mockACPeerCounter is a test double for ACPeerCounter.
type mockACPeerCounter struct {
	count int
}

func (m *mockACPeerCounter) ACPeerCount() int {
	return m.count
}

func TestNewACPeerChecker(t *testing.T) {
	t.Parallel()

	c := NewACPeerChecker(&ACPeerCheckerConfig{
		Counter: &mockACPeerCounter{count: 3},
	})
	if c.counter == nil {
		t.Error("counter should not be nil")
	}
}

func TestACPeerChecker_Name(t *testing.T) {
	t.Parallel()

	c := NewACPeerChecker(&ACPeerCheckerConfig{Counter: &mockACPeerCounter{}})
	if c.Name() != "ac_peers" {
		t.Errorf("Name() = %q, want %q", c.Name(), "ac_peers")
	}
}

func TestACPeerChecker_IsCritical(t *testing.T) {
	t.Parallel()

	c := NewACPeerChecker(&ACPeerCheckerConfig{Counter: &mockACPeerCounter{}})
	if !c.IsCritical() {
		t.Error("AC peer checker should be critical")
	}
}

func TestACPeerChecker_Check_NoCounter(t *testing.T) {
	t.Parallel()

	c := NewACPeerChecker(&ACPeerCheckerConfig{Counter: nil})
	result := c.Check(context.Background())

	if result.Status != CheckStatusSkip {
		t.Errorf("status = %q, want %q", result.Status, CheckStatusSkip)
	}
	if result.Message != "AC peer counter not configured" {
		t.Errorf("message = %q, want 'AC peer counter not configured'", result.Message)
	}
}

func TestACPeerChecker_Check_ZeroPeers(t *testing.T) {
	t.Parallel()

	c := NewACPeerChecker(&ACPeerCheckerConfig{
		Counter: &mockACPeerCounter{count: 0},
	})
	result := c.Check(context.Background())

	if result.Status != CheckStatusFail {
		t.Errorf("status = %q, want %q", result.Status, CheckStatusFail)
	}
	if result.Message != "no AC peers connected" {
		t.Errorf("message = %q, want 'no AC peers connected'", result.Message)
	}
	if !result.Critical {
		t.Error("result should be critical")
	}
}

func TestACPeerChecker_Check_HasPeers(t *testing.T) {
	t.Parallel()

	c := NewACPeerChecker(&ACPeerCheckerConfig{
		Counter: &mockACPeerCounter{count: 5},
	})
	result := c.Check(context.Background())

	if result.Status != CheckStatusPass {
		t.Errorf("status = %q, want %q", result.Status, CheckStatusPass)
	}
	if result.Message != "5 AC peer(s) connected" {
		t.Errorf("message = %q, want '5 AC peer(s) connected'", result.Message)
	}
	if result.DurationMS < 0 {
		t.Errorf("DurationMS = %d, should be >= 0", result.DurationMS)
	}
}

func TestACPeerChecker_Check_OnePeer(t *testing.T) {
	t.Parallel()

	c := NewACPeerChecker(&ACPeerCheckerConfig{
		Counter: &mockACPeerCounter{count: 1},
	})
	result := c.Check(context.Background())

	if result.Status != CheckStatusPass {
		t.Errorf("status = %q, want %q", result.Status, CheckStatusPass)
	}
	if result.Message != "1 AC peer(s) connected" {
		t.Errorf("message = %q, want '1 AC peer(s) connected'", result.Message)
	}
}

func TestACPeerChecker_Interface(t *testing.T) {
	t.Parallel()

	// Verify ACPeerChecker implements Checker interface
	var _ Checker = (*ACPeerChecker)(nil)
}
