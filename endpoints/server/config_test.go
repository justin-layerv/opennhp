package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

func TestParseACRegistryEntry(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(*ACRegistryEntry) bool
	}{
		{
			name: "valid TOML entry",
			input: `# AC Registry Entry
PublicKey = "dGVzdHB1YmtleWJhc2U2NA=="
InstanceId = "i-1234567890abcdef0"
Ip = "10.0.0.100"
Port = 62206
RegisteredAt = 1703980800
`,
			wantErr: false,
			check: func(e *ACRegistryEntry) bool {
				return e.PublicKey == "dGVzdHB1YmtleWJhc2U2NA==" &&
					e.InstanceId == "i-1234567890abcdef0" &&
					e.Ip == "10.0.0.100" &&
					e.Port == common.DefaultNHPPort &&
					e.RegisteredAt == 1703980800
			},
		},
		{
			name:    "invalid TOML",
			input:   `not valid toml [[[`,
			wantErr: true,
		},
		{
			name: "minimal entry",
			input: `PublicKey = "abc123"
InstanceId = "i-test"
`,
			wantErr: false,
			check: func(e *ACRegistryEntry) bool {
				return e.PublicKey == "abc123" && e.InstanceId == "i-test"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := parseACRegistryEntry([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("parseACRegistryEntry() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.check != nil && !tt.check(entry) {
				t.Errorf("parseACRegistryEntry() check failed, got %+v", entry)
			}
		})
	}
}

func TestACRegistryPrefix(t *testing.T) {
	if ACRegistryPrefix != "/nhp/ac-registry/" {
		t.Errorf("ACRegistryPrefix = %q, want %q", ACRegistryPrefix, "/nhp/ac-registry/")
	}
}

// TestUpdateBaseConfig_DoesNotHotReloadACPeerGracePeriodSeconds fences
// the "restart required" contract documented on
// Config.ACPeerGracePeriodSeconds. updateBaseConfig's reload branch
// does NOT propagate the value — the ACPeerChecker is built once at
// initHealthManager. If a future contributor adds propagation here
// without also wiring a checker-side Set, or adds checker propagation
// without dropping the restart-required docstring, this test fails.
//
// Plumbs a real *log.Logger onto the UdpServer so any future
// unconditional s.log.* call inside updateBaseConfig (e.g. a new
// info-log on every reload) doesn't nil-deref and mask the actual
// contract assertion. The logger writes to no directory (empty dir
// arg) and is Closed via t.Cleanup so its background writer
// goroutines don't outlive the test.
func TestUpdateBaseConfig_DoesNotHotReloadACPeerGracePeriodSeconds(t *testing.T) {
	const initialGrace = 60
	const newGrace = 120

	// Level 0 (silent) gates every log-writing method
	// (Info/Warning/Error/…) before the write path, so this plumbing
	// only guards the nil-method-ref boundary — the test's intent.
	// A future contributor who adds an unconditional s.log.Info(...)
	// to the reload branch will exercise the method lookup (no
	// panic), and the contract assertion below runs on its merits.
	// Setter methods on the logger (e.g., SetLogLevel) aren't level-
	// gated, but they also don't nil-deref on a real *log.Logger.
	//
	// Defense-in-depth: dir is t.TempDir() rather than "", so any
	// future test-level change that bumps the log level above 0 (or
	// any change to NewLogger's silent-level gating) won't leave
	// evaluate/audit log files littering the test's working
	// directory. t.TempDir cleans up automatically.
	logger := log.NewLogger("test", 0, t.TempDir(), "")
	t.Cleanup(logger.Close)

	s := &UdpServer{
		log:    logger,
		config: &Config{ACPeerGracePeriodSeconds: initialGrace},
	}
	incoming := Config{ACPeerGracePeriodSeconds: newGrace}

	if err := s.updateBaseConfig(incoming); err != nil {
		t.Fatalf("updateBaseConfig: %v", err)
	}

	if got := s.config.ACPeerGracePeriodSeconds; got != initialGrace {
		t.Errorf("s.config.ACPeerGracePeriodSeconds = %d after hot-reload, want %d "+
			"(restart-required contract). If propagation was intentionally added, "+
			"also wire a checker-side Set so the live checker adopts the new value, "+
			"and drop the restart-required docstring on Config.ACPeerGracePeriodSeconds.",
			got, initialGrace)
	}
}

// TestUpdateBaseConfig_DisableAgentValidationHotReloadPreservesCloudModeOverride
// fences the hot-reload regression on DisableAgentValidation in
// cloud mode. Start() resolves DisableAgentValidation against the
// cloud-mode override (operator || (cloudMode && agentPeerLookup
// != nil)) and feeds the result into device.NewDevice, but the
// pre-fix updateBaseConfig hot-reload path passed
// conf.DisableAgentValidation unmodified to device.SetOption. On
// a server.toml edit in cloud mode, the device flipped back to
// the operator literal `false` — every cloud-mode agent
// first-knock then failed at the responder layer with no metric
// to alarm on (the lookup is wired, just never reached).
//
// Fix: updateBaseConfig now re-applies the override via
// computeEffectiveDisableAgentValidation. This test reproduces
// the scenario:
//   - cloud mode is on (storageConfig.Backend == dynamodb)
//   - agentPeerLookup is non-nil
//   - operator's DisableAgentValidation flips false→true→false
//   - device.Option().DisableAgentPeerValidation must stay TRUE
//     on every reload (the override is non-negotiable while the
//     lookup is wired).
func TestUpdateBaseConfig_DisableAgentValidationHotReloadPreservesCloudModeOverride(t *testing.T) {
	logger := log.NewLogger("test", 0, t.TempDir(), "")
	t.Cleanup(logger.Close)

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), &core.DeviceOptions{
		// Start at the resolved value as Start() would have left it.
		DisableAgentPeerValidation: true,
	})
	if device == nil {
		t.Fatal("core.NewDevice returned nil")
	}
	defer device.Stop()

	// Construct a minimal lookup; non-nil is all the helper checks.
	inner := newFakeAgentKeysQuerier()
	lookup, err := NewAgentPeerLookup(inner, "qurl-agent-keys-test")
	if err != nil {
		t.Fatalf("NewAgentPeerLookup: %v", err)
	}

	s := &UdpServer{
		log:             logger,
		config:          &Config{DisableAgentValidation: true}, // matches what Start would have observed
		device:          device,
		agentPeerLookup: lookup,
		storageConfig:   &StorageConfig{Backend: StorageBackendDynamoDB},
	}

	// Hot-reload #1: operator drops DisableAgentValidation back to
	// false. Pre-fix this flipped the device option to false; the
	// cloud-mode override must keep it true.
	if err := s.updateBaseConfig(Config{DisableAgentValidation: false}); err != nil {
		t.Fatalf("updateBaseConfig: %v", err)
	}
	if got := device.Option().DisableAgentPeerValidation; !got {
		t.Errorf("after hot-reload to operator=false in cloud mode, device.Option().DisableAgentPeerValidation=%v want true (cloud-mode override must be re-applied; otherwise every agent first-knock fails at the responder layer)", got)
	}
	if got := s.config.DisableAgentValidation; got != false {
		t.Errorf("s.config.DisableAgentValidation=%v want false (cached file state must reflect operator's literal so the next delta-compare works)", got)
	}

	// Hot-reload #2: operator flips back to true (matches override).
	// Device stays at true.
	if err := s.updateBaseConfig(Config{DisableAgentValidation: true}); err != nil {
		t.Fatalf("updateBaseConfig: %v", err)
	}
	if got := device.Option().DisableAgentPeerValidation; !got {
		t.Errorf("after hot-reload to operator=true, device option=%v want true", got)
	}
}

// TestUpdateBaseConfig_DisableRelayValidationHotReload fences the #2208 relay
// flag wiring against the SetOption-REPLACE trap: a hot-reload that toggles
// DisableRelayValidation must apply the relay option WITHOUT resetting the agent
// or AC options (deviceOptions() is the single source of truth), and the relay
// flag is threaded DIRECTLY from the operator config (no cloud-mode override —
// the relay is deployed only where configured, so prod with no relay stays dark).
func TestUpdateBaseConfig_DisableRelayValidationHotReload(t *testing.T) {
	logger := log.NewLogger("test", 0, t.TempDir(), "")
	t.Cleanup(logger.Close)

	// As Start() leaves it in cloud mode: agent + AC validation disabled, relay
	// not yet.
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), &core.DeviceOptions{
		DisableAgentPeerValidation: true,
		DisableACPeerValidation:    true,
	})
	if device == nil {
		t.Fatal("core.NewDevice returned nil")
	}
	defer device.Stop()

	inner := newFakeAgentKeysQuerier()
	lookup, err := NewAgentPeerLookup(inner, "qurl-agent-keys-test")
	if err != nil {
		t.Fatalf("NewAgentPeerLookup: %v", err)
	}

	s := &UdpServer{
		log:             logger,
		config:          &Config{DisableAgentValidation: true, DisableRelayValidation: false},
		device:          device,
		agentPeerLookup: lookup,
		storageConfig:   &StorageConfig{Backend: StorageBackendDynamoDB},
	}

	// Reload: relay validation disabled (false→true), agent unchanged. The reload
	// must fire on the relay delta and SetOption must apply the FULL option set.
	if err := s.updateBaseConfig(Config{DisableAgentValidation: true, DisableRelayValidation: true}); err != nil {
		t.Fatalf("updateBaseConfig (relay on): %v", err)
	}
	opt := device.Option()
	if !opt.DisableRelayPeerValidation {
		t.Error("DisableRelayPeerValidation=false after reload to true; relay flag did not apply")
	}
	if !opt.DisableAgentPeerValidation {
		t.Error("DisableAgentPeerValidation reset to false when the relay flag changed — SetOption replaces the whole struct; deviceOptions() must re-apply it")
	}
	if !opt.DisableACPeerValidation {
		t.Error("DisableACPeerValidation reset to false when the relay flag changed — SetOption replaces the whole struct; deviceOptions() must re-apply it")
	}
	if !s.config.DisableRelayValidation {
		t.Error("s.config.DisableRelayValidation=false; cached state must reflect the reload for the next delta-compare")
	}

	// Reload back: relay validation re-enabled (true→false). The relay flag is
	// threaded directly (no cloud-mode override), so it follows the operator.
	if err := s.updateBaseConfig(Config{DisableAgentValidation: true, DisableRelayValidation: false}); err != nil {
		t.Fatalf("updateBaseConfig (relay off): %v", err)
	}
	opt = device.Option()
	if opt.DisableRelayPeerValidation {
		t.Error("DisableRelayPeerValidation=true after reload to false; relay flag must follow the operator config (no cloud-mode override)")
	}
	// Fence the SetOption-replace in this direction too: toggling relay off must
	// not reset the agent/AC options either.
	if !opt.DisableAgentPeerValidation {
		t.Error("DisableAgentPeerValidation reset to false when the relay flag toggled off — SetOption replaces the whole struct; deviceOptions() must re-apply it")
	}
	if !opt.DisableACPeerValidation {
		t.Error("DisableACPeerValidation reset to false when the relay flag toggled off — SetOption replaces the whole struct; deviceOptions() must re-apply it")
	}
}

// TestDeviceOptions_RelayFromConfig locks the Start (boot) path: deviceOptions()
// is the single source of truth NewDevice consumes at Start, and must render
// DisableRelayPeerValidation directly from config (no cloud-mode override) while
// keeping the cloud-mode agent + AC options. The hot-reload test above exercises
// the SetOption path; this fences the boot path the two share.
func TestDeviceOptions_RelayFromConfig(t *testing.T) {
	logger := log.NewLogger("test", 0, t.TempDir(), "")
	t.Cleanup(logger.Close)

	inner := newFakeAgentKeysQuerier()
	lookup, err := NewAgentPeerLookup(inner, "qurl-agent-keys-test")
	if err != nil {
		t.Fatalf("NewAgentPeerLookup: %v", err)
	}

	// Cloud mode (DynamoDB) with the agent peer lookup wired, as Start() leaves
	// it: agent + AC validation disabled independent of the relay flag.
	s := &UdpServer{
		log:             logger,
		agentPeerLookup: lookup,
		storageConfig:   &StorageConfig{Backend: StorageBackendDynamoDB},
	}

	for _, relayOn := range []bool{true, false} {
		opt := s.deviceOptions(&Config{DisableRelayValidation: relayOn})
		if opt.DisableRelayPeerValidation != relayOn {
			t.Errorf("DisableRelayPeerValidation=%v, want %v — boot path must follow config directly (no cloud-mode override)", opt.DisableRelayPeerValidation, relayOn)
		}
		if !opt.DisableAgentPeerValidation {
			t.Errorf("DisableAgentPeerValidation=false with relayOn=%v; the cloud-mode agent override must hold regardless of the relay flag", relayOn)
		}
		if !opt.DisableACPeerValidation {
			t.Errorf("DisableACPeerValidation=false with relayOn=%v; cloud mode must disable AC validation regardless of the relay flag", relayOn)
		}
	}
}

// TestLoadPeers_RefusesCloudModeWithAgentTomlCoexistence fences
// the agent.toml + cloud-mode coexistence guard. The two paths
// cannot coexist: updateAgentPeers (called from loadPeers and the
// agent.toml WatchFile callback) builds a fresh peer map and
// removes from device.peerMap any pubkey absent from the new map
// — wiping every DDB-resolved peer on each agent.toml touch.
// loadPeers must refuse boot when both are wired.
func TestLoadPeers_RefusesCloudModeWithAgentTomlCoexistence(t *testing.T) {
	tmpDir := t.TempDir()
	etcDir := filepath.Join(tmpDir, "etc")
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatalf("mkdir etc: %v", err)
	}
	// Empty agent.toml — even an empty [[Agents]] block triggers
	// the watcher-wipe hazard the guard fences.
	if err := os.WriteFile(filepath.Join(etcDir, "agent.toml"), []byte("[[Agents]]\n"), 0o644); err != nil {
		t.Fatalf("write agent.toml: %v", err)
	}
	// server.toml is required by loadPeers' earlier sections; provide
	// a minimal valid file so we reach the agent.toml branch.
	if err := os.WriteFile(filepath.Join(etcDir, "server.toml"), []byte(""), 0o644); err != nil {
		t.Fatalf("write server.toml: %v", err)
	}

	orig := ExeDirPath
	t.Cleanup(func() { ExeDirPath = orig })
	ExeDirPath = tmpDir

	inner := newFakeAgentKeysQuerier()
	lookup, err := NewAgentPeerLookup(inner, "qurl-agent-keys-test")
	if err != nil {
		t.Fatalf("NewAgentPeerLookup: %v", err)
	}

	logger := log.NewLogger("test", 0, t.TempDir(), "")
	t.Cleanup(logger.Close)

	s := &UdpServer{
		log:             logger,
		config:          &Config{},
		agentPeerLookup: lookup,
		storageConfig:   &StorageConfig{Backend: StorageBackendDynamoDB},
	}

	loadErr := s.loadPeers()
	if loadErr == nil {
		t.Fatal("loadPeers returned nil error; expected coexistence-conflict refusal")
	}
	if !strings.Contains(loadErr.Error(), "agent peer registry conflict") {
		t.Errorf("loadPeers err=%q does not mention 'agent peer registry conflict' — guard message regressed", loadErr.Error())
	}
}

func TestUpdateResources_NilAspData(t *testing.T) {
	// This test verifies that updateResources handles nil aspData entries gracefully.
	// TOML unmarshals empty tables (e.g., "[passcode]" with no fields) as nil pointers.
	// The server should skip these entries without panicking.

	s := &UdpServer{}

	// Create a map with nil entry (simulates TOML empty table)
	aspMap := common.AuthSvcProviderMap{
		"passcode": nil, // Simulate TOML empty table like "[passcode]\n# comment only"
	}

	// Should not panic
	err := s.updateResources(aspMap)
	if err != nil {
		t.Errorf("updateResources() unexpected error = %v", err)
	}

	// Verify the nil entry is preserved in the map (for static plugin lookup)
	if len(s.authServiceMap) != 1 {
		t.Errorf("authServiceMap length = %d, want 1", len(s.authServiceMap))
	}
}

func TestUpdateResources_MixedNilAndValid(t *testing.T) {
	// Test that valid entries are processed even when nil entries exist

	s := &UdpServer{}

	aspMap := common.AuthSvcProviderMap{
		"nil-plugin":   nil, // Empty table
		"valid-plugin": &common.AuthServiceProviderData{PluginPath: ""},
	}

	err := s.updateResources(aspMap)
	if err != nil {
		t.Errorf("updateResources() unexpected error = %v", err)
	}

	// Both entries should be in the map
	if len(s.authServiceMap) != 2 {
		t.Errorf("authServiceMap length = %d, want 2", len(s.authServiceMap))
	}

	// Valid entry should have AuthSvcId set
	if s.authServiceMap["valid-plugin"] != nil && s.authServiceMap["valid-plugin"].AuthSvcId != "valid-plugin" {
		t.Errorf("valid-plugin AuthSvcId = %q, want %q", s.authServiceMap["valid-plugin"].AuthSvcId, "valid-plugin")
	}
}

// TestApplyHttpTimeoutDefaults table-drives the floor-up logic that
// guards the CloudFront keep-alive contract (see PR #1795). Pure logic,
// no UdpServer required.
func TestApplyHttpTimeoutDefaults(t *testing.T) {
	tests := []struct {
		name      string
		in        HttpConfig
		wantRead  int
		wantWrite int
		wantIdle  int
	}{
		{
			name:      "zero values get defaulted (normal not-set case)",
			in:        HttpConfig{},
			wantRead:  DefaultHttpRequestReadTimeoutMs,
			wantWrite: DefaultHttpResponseWriteTimeoutMs,
			wantIdle:  DefaultHttpServerIdleTimeoutMs,
		},
		{
			name:      "below-floor positive values get defaulted up",
			in:        HttpConfig{ReadTimeoutMs: 100, WriteTimeoutMs: 500, IdleTimeoutMs: 999},
			wantRead:  DefaultHttpRequestReadTimeoutMs,
			wantWrite: DefaultHttpResponseWriteTimeoutMs,
			wantIdle:  DefaultHttpServerIdleTimeoutMs,
		},
		{
			name:      "exact floor (1000) carries through unchanged",
			in:        HttpConfig{ReadTimeoutMs: 1000, WriteTimeoutMs: 1000, IdleTimeoutMs: 1000},
			wantRead:  1000,
			wantWrite: 1000,
			wantIdle:  1000,
		},
		{
			name:      "above-floor values carry through unchanged",
			in:        HttpConfig{ReadTimeoutMs: 60000, WriteTimeoutMs: 45000, IdleTimeoutMs: 90000},
			wantRead:  60000,
			wantWrite: 45000,
			wantIdle:  90000,
		},
		{
			// IdleTimeoutMs > 1000 but < DefaultHttpServerIdleTimeoutMs:
			// permitted (carries through) but emits a separate Warning
			// about the keep-alive contract risk. The Warning side-effect
			// isn't asserted here (capturing log output cleanly is more
			// plumbing than the test warrants); just verify the value
			// itself isn't silently floored, which would mask any
			// deliberate operator override.
			name:      "above-1000ms-floor but below safe default carries through",
			in:        HttpConfig{ReadTimeoutMs: 30000, WriteTimeoutMs: 30000, IdleTimeoutMs: 5000},
			wantRead:  30000,
			wantWrite: 30000,
			wantIdle:  5000,
		},
		{
			name:      "mixed: one below floor, others above",
			in:        HttpConfig{ReadTimeoutMs: 50, WriteTimeoutMs: 30000, IdleTimeoutMs: 36000},
			wantRead:  DefaultHttpRequestReadTimeoutMs,
			wantWrite: 30000,
			wantIdle:  36000,
		},
		{
			name:      "negative values get defaulted (treated as below-floor)",
			in:        HttpConfig{ReadTimeoutMs: -1, WriteTimeoutMs: -100, IdleTimeoutMs: -1},
			wantRead:  DefaultHttpRequestReadTimeoutMs,
			wantWrite: DefaultHttpResponseWriteTimeoutMs,
			wantIdle:  DefaultHttpServerIdleTimeoutMs,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf := tc.in
			applyHttpTimeoutDefaults(&conf)
			if conf.ReadTimeoutMs != tc.wantRead {
				t.Errorf("ReadTimeoutMs: got %d, want %d", conf.ReadTimeoutMs, tc.wantRead)
			}
			if conf.WriteTimeoutMs != tc.wantWrite {
				t.Errorf("WriteTimeoutMs: got %d, want %d", conf.WriteTimeoutMs, tc.wantWrite)
			}
			if conf.IdleTimeoutMs != tc.wantIdle {
				t.Errorf("IdleTimeoutMs: got %d, want %d", conf.IdleTimeoutMs, tc.wantIdle)
			}
		})
	}

	// Sanity check: defaults themselves carry the keep-alive contract.
	// Any future bump to the constants must keep idle >= 30000 (CF
	// origin_keepalive_timeout) + a buffer. This isn't a contract test
	// per se — that lives in TF — but a regression here would mean the
	// constants no longer satisfy the LayerV deployment topology.
	if DefaultHttpServerIdleTimeoutMs < 30000 {
		t.Errorf("DefaultHttpServerIdleTimeoutMs = %d is below CloudFront origin_keepalive_timeout (30000ms); contract violation. See PR #1795.", DefaultHttpServerIdleTimeoutMs)
	}
}
