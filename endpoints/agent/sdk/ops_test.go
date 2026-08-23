package sdk

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/agent"
	"github.com/OpenNHP/opennhp/nhp/common"
)

const sdkTestAgentPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func installTestInstance(t *testing.T, current *agent.UdpAgent) {
	t.Helper()
	generationMu.Lock()
	instanceMu.Lock()
	previous := instance
	instance = current
	instanceMu.Unlock()
	generationMu.Unlock()
	t.Cleanup(func() {
		generationMu.Lock()
		instanceMu.Lock()
		instance = previous
		instanceMu.Unlock()
		generationMu.Unlock()
	})
}

func newSDKTestWorkingDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	etcDir := filepath.Join(dir, "etc")
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatalf("mkdir etc: %v", err)
	}
	config := []byte(`PrivateKeyBase64 = "` + sdkTestAgentPrivateKey + `"` + "\n")
	if err := os.WriteFile(filepath.Join(etcDir, "config.toml"), config, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return dir
}

// TestNilInstanceGuards verifies that every public function handles a nil
// singleton gracefully (the agent has not been initialized).
func TestNilInstanceGuards(t *testing.T) {
	installTestInstance(t, nil)

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

	t.Run("KnockResourceWithRunID", func(t *testing.T) {
		result := KnockResourceWithRunID("asp", "res", "0123456789abcdef", "1.2.3.4", "", common.DefaultNHPPort)
		var ack common.ServerKnockAckMsg
		if err := json.Unmarshal([]byte(result), &ack); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if ack.ErrCode != common.ErrNoAgentInstance.ErrorCode() {
			t.Errorf("expected ErrNoAgentInstance code, got %s", ack.ErrCode)
		}
	})

	t.Run("KnockResourceWithRunBinding", func(t *testing.T) {
		result := KnockResourceWithRunBinding("asp", "res", "0123456789abcdef", 1, "1.2.3.4", "", common.DefaultNHPPort)
		var ack common.ServerKnockAckMsg
		if err := json.Unmarshal([]byte(result), &ack); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if ack.ErrCode != common.ErrNoAgentInstance.ErrorCode() {
			t.Errorf("expected ErrNoAgentInstance code, got %s", ack.ErrCode)
		}
	})

	t.Run("RetireSession", func(t *testing.T) {
		result := RetireSession(`{}`, "1.2.3.4", "", common.DefaultNHPPort)
		var ack common.ServerExactSessionCloseAckMsg
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

	t.Run("ExitResourceWithRunID", func(t *testing.T) {
		if ExitResourceWithRunID("asp", "res", "0123456789abcdef", "1.2.3.4", "", common.DefaultNHPPort) {
			t.Error("expected false")
		}
	})
}

// TestBuildTargetValidation verifies input validation in buildTarget.
func TestBuildTargetValidation(t *testing.T) {
	t.Run("nil instance", func(t *testing.T) {
		target, ack := buildTarget(nil, "asp", "res", "", 0, "1.2.3.4", "", common.DefaultNHPPort)
		if target != nil {
			t.Error("expected nil target")
		}
		if ack.ErrCode != common.ErrNoAgentInstance.ErrorCode() {
			t.Errorf("expected ErrNoAgentInstance, got %s", ack.ErrCode)
		}
	})

	t.Run("registered agent missing runID", func(t *testing.T) {
		target, ack := buildTarget(&agent.UdpAgent{}, common.RegisteredAgentAuthServiceID, "res", "", 0, "1.2.3.4", "", common.DefaultNHPPort)
		if target != nil {
			t.Error("expected nil target")
		}
		if ack.ErrCode != common.ErrKnockRunIDInvalid.ErrorCode() {
			t.Errorf("expected ErrKnockRunIDInvalid, got %s", ack.ErrCode)
		}
	})

	t.Run("registered agent missing runAttempt", func(t *testing.T) {
		target, ack := buildTarget(&agent.UdpAgent{}, common.RegisteredAgentAuthServiceID, "res", "0123456789abcdef", 0, "1.2.3.4", "", common.DefaultNHPPort)
		if target != nil {
			t.Error("expected nil target")
		}
		if ack.ErrCode != common.ErrKnockRunAttemptInvalid.ErrorCode() {
			t.Errorf("expected ErrKnockRunAttemptInvalid, got %s", ack.ErrCode)
		}
	})

	t.Run("noncanonical supplied runID", func(t *testing.T) {
		target, ack := buildTarget(&agent.UdpAgent{}, "legacy", "res", "invalid", 0, "1.2.3.4", "", common.DefaultNHPPort)
		if target != nil {
			t.Error("expected nil target")
		}
		if ack.ErrCode != common.ErrKnockRunIDInvalid.ErrorCode() {
			t.Errorf("expected ErrKnockRunIDInvalid, got %s", ack.ErrCode)
		}
	})
}

func TestRegisteredAgentSDKRunIDGate(t *testing.T) {
	installTestInstance(t, &agent.UdpAgent{})

	tests := []struct {
		name string
		call func() string
	}{
		{
			name: "legacy wrapper has no implicit default",
			call: func() string {
				return KnockResource(common.RegisteredAgentAuthServiceID, "res", "127.0.0.1", "", common.DefaultNHPPort)
			},
		},
		{
			name: "explicit wrapper rejects noncanonical",
			call: func() string {
				return KnockResourceWithRunID(common.RegisteredAgentAuthServiceID, "res", "INVALID", "127.0.0.1", "", common.DefaultNHPPort)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ack common.ServerKnockAckMsg
			if err := json.Unmarshal([]byte(tt.call()), &ack); err != nil {
				t.Fatalf("invalid ack JSON: %v", err)
			}
			if ack.ErrCode != common.ErrKnockRunIDInvalid.ErrorCode() || ack.ErrMsg != common.ErrKnockRunIDInvalid.Error() {
				t.Fatalf("ack = (%q, %q), want stable ErrKnockRunIDInvalid", ack.ErrCode, ack.ErrMsg)
			}
		})
	}

	if ExitResource(common.RegisteredAgentAuthServiceID, "res", "127.0.0.1", "", common.DefaultNHPPort) {
		t.Fatal("legacy registered-agent ExitResource must fail closed without runID")
	}
	if ExitResourceWithRunID(common.RegisteredAgentAuthServiceID, "res", "INVALID", "127.0.0.1", "", common.DefaultNHPPort) {
		t.Fatal("registered-agent ExitResourceWithRunID must reject noncanonical runID")
	}
	if AddResource(common.RegisteredAgentAuthServiceID, "res", "127.0.0.1", "", common.DefaultNHPPort) {
		t.Fatal("registered-agent AddResource must reject unsupported background-loop configuration")
	}
}

func TestRetireSessionRejectsMalformedReceiptBeforeRouteLookup(t *testing.T) {
	installTestInstance(t, &agent.UdpAgent{})
	valid := `{"sessId":77,"cellId":"cell-01","sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":3,"errCode":"0","resHost":{"resource":"127.0.0.1:443"},"opnTime":30,"agentAddr":"198.51.100.8:44444","acTokens":{"resource":"token"}}`
	for name, body := range map[string]string{
		"missing":   strings.Replace(valid, `"cellId":"cell-01",`, ``, 1),
		"unknown":   strings.TrimSuffix(valid, `}`) + `,"future":1}`,
		"duplicate": strings.Replace(valid, `"sessId":77`, `"sessId":77,"sessId":77`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			var ack common.ServerExactSessionCloseAckMsg
			if err := json.Unmarshal([]byte(RetireSession(body, "127.0.0.1", "", common.DefaultNHPPort)), &ack); err != nil {
				t.Fatal(err)
			}
			if ack.ErrCode != common.ErrInvalidInput.ErrorCode() || ack.ErrMsg != common.ErrInvalidInput.Error() {
				t.Fatalf("RetireSession malformed receipt ACK = %#v", ack)
			}
		})
	}
}

func TestRetireSessionUnresolvableOriginalRouteReturnsStrictDenial(t *testing.T) {
	dir := newSDKTestWorkingDir(t)
	if !Init(dir, 0) {
		t.Fatal("Init returned false")
	}
	t.Cleanup(Close)
	keys := strings.Split(GenerateKeys(), "|")
	if len(keys) != 2 || !AddServer(keys[1], "999.999.999.999", "", common.DefaultNHPPort, 0) {
		t.Fatal("failed to install deliberately unresolvable original server route")
	}
	knockAck := `{"errCode":"0","sessId":77,"cellId":"cell-01","sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":3,"resHost":{"resource":"127.0.0.1:443"},"opnTime":30,"agentAddr":"198.51.100.8:44444","acTokens":{"resource":"token"}}`
	raw := RetireSession(knockAck, "999.999.999.999", "", common.DefaultNHPPort)
	if raw == "null" || raw == "{}" {
		t.Fatalf("RetireSession returned non-authoritative JSON %q", raw)
	}
	var ack common.ServerExactSessionCloseAckMsg
	if err := common.DecodeServerExactSessionCloseAckMsg([]byte(raw), &ack); err != nil {
		t.Fatalf("strict denial decode: %v (raw=%s)", err, raw)
	}
	if ack.ErrCode != common.ErrKnockServerNotFound.ErrorCode() || ack.ErrMsg != common.ErrKnockServerNotFound.Error() {
		t.Fatalf("RetireSession denial = %#v", ack)
	}
}

func TestExactCloseResultJSONNeverFabricatesNull(t *testing.T) {
	for name, tc := range map[string]struct {
		ack  *common.ServerExactSessionCloseAckMsg
		err  error
		code string
	}{
		"nil with route failure": {err: common.ErrKnockServerNotFound, code: common.ErrKnockServerNotFound.ErrorCode()},
		"nil without error":      {code: common.ErrTransactionFailedByClosedConnection.ErrorCode()},
		"known local denial": {
			ack:  &common.ServerExactSessionCloseAckMsg{ErrCode: common.ErrInvalidInput.ErrorCode(), ErrMsg: common.ErrInvalidInput.Error()},
			err:  common.ErrInvalidInput,
			code: common.ErrInvalidInput.ErrorCode(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw := exactCloseResultJSON(tc.ack, tc.err)
			var got common.ServerExactSessionCloseAckMsg
			if err := common.DecodeServerExactSessionCloseAckMsg([]byte(raw), &got); err != nil {
				t.Fatalf("strict denial decode: %v (raw=%s)", err, raw)
			}
			if got.ErrCode != tc.code {
				t.Fatalf("code=%q want=%q", got.ErrCode, tc.code)
			}
		})
	}
}

func TestBuildTargetRetainsExactCallerRunID(t *testing.T) {
	dir := newSDKTestWorkingDir(t)
	if !Init(dir, 0) {
		t.Fatal("Init returned false")
	}
	t.Cleanup(Close)
	if !AddServer(sdkTestAgentPrivateKey, "127.0.0.1", "", common.DefaultNHPPort, 0) {
		t.Fatal("AddServer returned false")
	}

	instanceMu.RLock()
	target, ack := buildTarget(instance, common.RegisteredAgentAuthServiceID, "res", "0123456789abcdef", 1, "127.0.0.1", "", common.DefaultNHPPort)
	instanceMu.RUnlock()
	if target == nil {
		t.Fatalf("buildTarget returned nil target: %#v", ack)
	}
	if target.RunID != "0123456789abcdef" || target.RunAttempt != 1 {
		t.Fatalf("target run binding = (%q,%d), want exact caller value", target.RunID, target.RunAttempt)
	}
}

func TestSingletonLifecycleSerializesPublicCalls(t *testing.T) {
	dir := newSDKTestWorkingDir(t)
	if !Init(dir, 0) {
		t.Fatal("initial Init returned false")
	}
	t.Cleanup(Close)

	var wg sync.WaitGroup
	errs := make(chan string, 1)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 3 {
			Close()
			if !Init(dir, 0) {
				select {
				case errs <- "Init returned false during lifecycle race":
				default:
				}
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range 100 {
			_ = SetKnockUser("user", "device", "org", `{}`)
			_ = AddResource(common.RegisteredAgentAuthServiceID, "res", "127.0.0.1", "", common.DefaultNHPPort)
			_ = KnockResourceWithRunID(common.RegisteredAgentAuthServiceID, "res", "INVALID", "127.0.0.1", "", common.DefaultNHPPort)
			_ = ExitResourceWithRunID(common.RegisteredAgentAuthServiceID, "res", "INVALID", "127.0.0.1", "", common.DefaultNHPPort)
		}
	}()
	wg.Wait()
	select {
	case msg := <-errs:
		t.Fatal(msg)
	default:
	}
}

func TestCloseInterruptsInFlightRegisteredAgentKnock(t *testing.T) {
	dir := newSDKTestWorkingDir(t)
	if !Init(dir, 0) {
		t.Fatal("Init returned false")
	}
	t.Cleanup(Close)
	const unusedPort = 65534
	keyParts := strings.SplitN(GenerateKeys(), "|", 2)
	if len(keyParts) != 2 {
		t.Fatalf("GenerateKeys returned malformed result")
	}
	if !AddServer(keyParts[1], "127.0.0.1", "", unusedPort, 0) {
		t.Fatal("AddServer returned false")
	}

	knockDone := make(chan struct{})
	go func() {
		defer close(knockDone)
		_ = KnockResourceWithRunBinding(common.RegisteredAgentAuthServiceID, "res", "0123456789abcdef", 1, "127.0.0.1", "", unusedPort)
	}()
	for i := range 1_000 {
		_ = SetKnockUser("user", "device", "org", fmt.Sprintf(`{"iteration":%d}`, i))
	}
	select {
	case <-knockDone:
		t.Fatal("knock returned before Close; test did not reach the response wait")
	case <-time.After(200 * time.Millisecond):
	}

	closeDone := make(chan struct{})
	go func() {
		Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not interrupt the in-flight knock")
	}
	select {
	case <-knockDone:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight knock did not return after Close")
	}
	if !Init(dir, 0) {
		t.Fatal("Init could not start a new generation after Close completed")
	}
}

// TestAddServerValidation verifies input validation in AddServer.
func TestAddServerValidation(t *testing.T) {
	// Use a non-nil instance stub to isolate input validation from nil guard.
	// We can't easily construct a real UdpAgent, so we only test the nil-instance
	// and empty-input branches.
	installTestInstance(t, nil)

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
