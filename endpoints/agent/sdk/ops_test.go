package sdk

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestNilInstanceGuards verifies that every public function handles a nil
// singleton gracefully (the agent has not been initialised).
func TestNilInstanceGuards(t *testing.T) {
	// Ensure instance is nil for this test group.
	instance = nil

	t.Run("Close", func(t *testing.T) {
		Close() // should not panic
	})

	t.Run("KnockloopStart", func(t *testing.T) {
		if got := KnockloopStart(); got != -1 {
			t.Errorf("expected -1, got %d", got)
		}
	})

	t.Run("KnockloopStop", func(t *testing.T) {
		KnockloopStop() // should not panic
	})

	t.Run("SetKnockUser", func(t *testing.T) {
		if SetKnockUser("u", "d", "o", "") {
			t.Error("expected false")
		}
	})

	t.Run("AddServer", func(t *testing.T) {
		if AddServer("key", "1.2.3.4", "", 0, 0) {
			t.Error("expected false")
		}
	})

	t.Run("RemoveServer", func(t *testing.T) {
		RemoveServer("key") // should not panic
	})

	t.Run("AddResource", func(t *testing.T) {
		if AddResource("asp", "res", "1.2.3.4", "", 0) {
			t.Error("expected false")
		}
	})

	t.Run("RemoveResource", func(t *testing.T) {
		RemoveResource("asp", "res") // should not panic
	})

	t.Run("KnockResource", func(t *testing.T) {
		result := KnockResource("asp", "res", "1.2.3.4", "", common.DefaultNHPPort)
		var ack common.ServerKnockAckMsg
		if err := json.Unmarshal([]byte(result), &ack); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if ack.ErrCode != common.ErrNoAgentInstance.ErrorCode() {
			t.Errorf("expected ErrNoAgentInstance code, got %s", ack.ErrCode)
		}
	})

	t.Run("ExitResource", func(t *testing.T) {
		if ExitResource("asp", "res", "1.2.3.4", "", common.DefaultNHPPort) {
			t.Error("expected false")
		}
	})
}

// TestBuildTargetValidation verifies input validation in buildTarget.
func TestBuildTargetValidation(t *testing.T) {
	instance = nil

	t.Run("nil instance", func(t *testing.T) {
		target, ack := buildTarget("asp", "res", "1.2.3.4", "", common.DefaultNHPPort)
		if target != nil {
			t.Error("expected nil target")
		}
		if ack.ErrCode != common.ErrNoAgentInstance.ErrorCode() {
			t.Errorf("expected ErrNoAgentInstance, got %s", ack.ErrCode)
		}
	})
}

// TestAddServerValidation verifies input validation in AddServer.
func TestAddServerValidation(t *testing.T) {
	// Use a non-nil instance stub to isolate input validation from nil guard.
	// We can't easily construct a real UdpAgent, so we only test the nil-instance
	// and empty-input branches.
	instance = nil

	t.Run("empty pubkey", func(t *testing.T) {
		// With nil instance, returns false before reaching validation.
		if AddServer("", "1.2.3.4", "", 0, 0) {
			t.Error("expected false")
		}
	})

	t.Run("empty ip and host", func(t *testing.T) {
		if AddServer("key", "", "", 0, 0) {
			t.Error("expected false")
		}
	})
}

// TestGenerateKeys verifies key generation returns the expected format.
func TestGenerateKeys(t *testing.T) {
	result := GenerateKeys()
	parts := strings.SplitN(result, "|", 2)
	if len(parts) != 2 {
		t.Fatalf("expected 'priv|pub' format, got %q", result)
	}
	if parts[0] == "" || parts[1] == "" {
		t.Errorf("expected non-empty keys, got priv=%q pub=%q", parts[0], parts[1])
	}
}

// TestPrivkeyToPubkey verifies round-trip key derivation.
func TestPrivkeyToPubkey(t *testing.T) {
	result := GenerateKeys()
	parts := strings.SplitN(result, "|", 2)
	priv, expectedPub := parts[0], parts[1]

	pub := PrivkeyToPubkey(priv)
	if pub != expectedPub {
		t.Errorf("expected %q, got %q", expectedPub, pub)
	}
}

// TestPrivkeyToPubkeyInvalid verifies error handling for bad input.
func TestPrivkeyToPubkeyInvalid(t *testing.T) {
	t.Run("invalid base64", func(t *testing.T) {
		if got := PrivkeyToPubkey("not-valid-base64!!!"); got != "" {
			t.Errorf("expected empty string, got %q", got)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		// Empty string is valid base64 (decodes to empty bytes) but not a valid key.
		if got := PrivkeyToPubkey(""); got != "" {
			t.Errorf("expected empty string, got %q", got)
		}
	})
}
