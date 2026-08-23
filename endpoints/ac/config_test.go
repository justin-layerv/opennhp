package ac

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/OpenNHP/opennhp/nhp/log"
)

func TestConfig_LocalFile(t *testing.T) {
	// Test local config.toml format (with private key)
	configToml := `
ACId = "sandbox-ac-i-1234567890"
DefaultIp = "10.0.0.100"
PrivateKeyBase64 = "cHJpdmF0ZWtleWJhc2U2NA=="
DefaultCipherScheme = 0
IpPassMode = 0
LogLevel = 4
AuthServiceId = "agent"
ResourceIds = ["demo", "mini-app-demo"]
FilterMode = 0
`

	var config Config
	err := toml.Unmarshal([]byte(configToml), &config)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	if config.ACId != "sandbox-ac-i-1234567890" {
		t.Errorf("ACId mismatch: got %s", config.ACId)
	}
	if config.PrivateKeyBase64 == "" {
		t.Error("PrivateKeyBase64 should not be empty")
	}
	if config.AuthServiceId != "agent" {
		t.Errorf("AuthServiceId mismatch: got %s", config.AuthServiceId)
	}
	if len(config.ResourceIds) != 2 {
		t.Errorf("Expected 2 ResourceIds, got %d", len(config.ResourceIds))
	}
}

func TestHttpConfig_Parse(t *testing.T) {
	configToml := `
EnableHttp = true
EnableTLS = false
HttpListenIp = "127.0.0.1"
HttpListenPort = 8888
`

	var config HttpConfig
	err := toml.Unmarshal([]byte(configToml), &config)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	if !config.EnableHttp {
		t.Error("EnableHttp should be true")
	}
	if config.EnableTLS {
		t.Error("EnableTLS should be false")
	}
	if config.HttpListenPort != 8888 {
		t.Errorf("HttpListenPort mismatch: got %d", config.HttpListenPort)
	}
}

// setupTestDir creates a temporary directory with etc and logs subdirectories for config tests
func setupTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	etcDir := filepath.Join(dir, "etc")
	logsDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		t.Fatalf("Failed to create etc dir: %v", err)
	}
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		t.Fatalf("Failed to create logs dir: %v", err)
	}
	return dir
}

// setupTestAC creates a UdpAC with initialized logger for testing
func setupTestAC(t *testing.T, dir string) *UdpAC {
	t.Helper()
	ac := &UdpAC{}
	ac.log = log.NewLogger("NHP-AC-TEST", 0, filepath.Join(dir, "logs"), "test")
	return ac
}

func TestLoadBaseConfig_MissingFile(t *testing.T) {
	dir := setupTestDir(t)

	// Set ExeDirPath to temp directory (no config.toml exists)
	oldExeDirPath := ExeDirPath
	ExeDirPath = dir
	defer func() { ExeDirPath = oldExeDirPath }()

	ac := setupTestAC(t, dir)
	err := ac.loadBaseConfig()

	if err == nil {
		t.Fatal("Expected error for missing config.toml, got nil")
	}
	if !strings.Contains(err.Error(), "failed to read base config") {
		t.Errorf("Expected 'failed to read' error, got: %v", err)
	}
}

func TestLoadBaseConfig_MalformedTOML(t *testing.T) {
	dir := setupTestDir(t)

	// Write malformed TOML
	configPath := filepath.Join(dir, "etc", "config.toml")
	if err := os.WriteFile(configPath, []byte("this is not valid toml {{{"), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	oldExeDirPath := ExeDirPath
	ExeDirPath = dir
	defer func() { ExeDirPath = oldExeDirPath }()

	ac := setupTestAC(t, dir)
	err := ac.loadBaseConfig()

	if err == nil {
		t.Fatal("Expected error for malformed TOML, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse base config") {
		t.Errorf("Expected 'failed to parse' error, got: %v", err)
	}
}

func TestLoadBaseConfig_MissingPrivateKey(t *testing.T) {
	dir := setupTestDir(t)

	// Write config without PrivateKeyBase64
	configPath := filepath.Join(dir, "etc", "config.toml")
	configContent := `
ACId = "test-ac"
DefaultIp = "10.0.0.1"
LogLevel = 4
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	oldExeDirPath := ExeDirPath
	ExeDirPath = dir
	defer func() { ExeDirPath = oldExeDirPath }()

	ac := setupTestAC(t, dir)
	err := ac.loadBaseConfig()

	if err == nil {
		t.Fatal("Expected error for missing PrivateKeyBase64, got nil")
	}
	if !strings.Contains(err.Error(), "privateKeyBase64 is required") {
		t.Errorf("Expected 'privateKeyBase64 is required' error, got: %v", err)
	}
}

func TestLoadBaseConfig_ValidConfig(t *testing.T) {
	dir := setupTestDir(t)

	// Write valid config
	configPath := filepath.Join(dir, "etc", "config.toml")
	configContent := `
ACId = "test-ac"
DefaultIp = "10.0.0.1"
PrivateKeyBase64 = "dGVzdHByaXZhdGVrZXkxMjM0NTY3ODkwYWJjZGVm"
LogLevel = 4
AuthServiceId = "agent"
ResourceIds = ["demo"]
FilterMode = 0
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	oldExeDirPath := ExeDirPath
	ExeDirPath = dir
	defer func() { ExeDirPath = oldExeDirPath }()

	ac := setupTestAC(t, dir)
	err := ac.loadBaseConfig()

	if err != nil {
		t.Fatalf("Expected no error for valid config, got: %v", err)
	}
	if ac.config == nil {
		t.Fatal("Expected config to be set")
	}
	if ac.config.ACId != "test-ac" {
		t.Errorf("ACId mismatch: got %s", ac.config.ACId)
	}
	if ac.config.PrivateKeyBase64 == "" {
		t.Error("PrivateKeyBase64 should not be empty")
	}
}

// TestLoadBaseConfig_HealthCheckPort verifies the health-check port normalizes
// to DefaultHealthCheckPort when config.toml omits it (so an in-place AC
// upgrade self-heals health checks even before user_data re-renders the field)
// and preserves an explicit value otherwise.
func TestLoadBaseConfig_HealthCheckPort(t *testing.T) {
	const base = `
ACId = "test-ac"
DefaultIp = "10.0.0.1"
PrivateKeyBase64 = "dGVzdHByaXZhdGVrZXkxMjM0NTY3ODkwYWJjZGVm"
LogLevel = 4
AuthServiceId = "agent"
ResourceIds = ["demo"]
FilterMode = 1
`
	load := func(t *testing.T, content string) *Config {
		t.Helper()
		dir := setupTestDir(t)
		if err := os.WriteFile(filepath.Join(dir, "etc", "config.toml"), []byte(content), 0644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		oldExeDirPath := ExeDirPath
		ExeDirPath = dir
		defer func() { ExeDirPath = oldExeDirPath }()
		ac := setupTestAC(t, dir)
		if err := ac.loadBaseConfig(); err != nil {
			t.Fatalf("loadBaseConfig: %v", err)
		}
		// loadBaseConfig starts a process-global file watcher. Close the exact
		// watcher created by this table row before the next row overwrites the
		// global handle; otherwise prior temp-directory watchers survive into
		// later rows and package-level race runs become order-sensitive.
		watch := baseConfigWatch
		if watch != nil {
			if err := watch.Close(); err != nil {
				t.Fatalf("close base config watcher: %v", err)
			}
			if baseConfigWatch == watch {
				baseConfigWatch = nil
			}
		}
		return ac.config
	}

	t.Run("unset defaults", func(t *testing.T) {
		if got := load(t, base).HealthCheckPort; got != DefaultHealthCheckPort {
			t.Errorf("HealthCheckPort = %d, want default %d", got, DefaultHealthCheckPort)
		}
	})

	t.Run("explicit value preserved", func(t *testing.T) {
		// config.toml keys are the Go struct field names, not json tags.
		if got := load(t, base+"HealthCheckPort = 9091\n").HealthCheckPort; got != 9091 {
			t.Errorf("HealthCheckPort = %d, want 9091", got)
		}
	})

	t.Run("out of range falls back to default", func(t *testing.T) {
		// >65535 would truncate to a wrong port at uint16 narrowing; the
		// normalizer must reject it rather than silently seed a bad rule.
		if got := load(t, base+"HealthCheckPort = 70000\n").HealthCheckPort; got != DefaultHealthCheckPort {
			t.Errorf("HealthCheckPort = %d, want default %d (out-of-range fallback)", got, DefaultHealthCheckPort)
		}
	})
}

func TestLoadHttpConfig_MissingFile_OK(t *testing.T) {
	dir := setupTestDir(t)

	oldExeDirPath := ExeDirPath
	ExeDirPath = dir
	defer func() { ExeDirPath = oldExeDirPath }()

	ac := setupTestAC(t, dir)
	err := ac.loadHttpConfig()

	// Missing http.toml should NOT be an error (it's optional)
	if err != nil {
		t.Fatalf("Expected no error for missing http.toml (optional), got: %v", err)
	}
}

func TestLoadHttpConfig_MalformedTOML(t *testing.T) {
	dir := setupTestDir(t)

	// Write malformed TOML
	configPath := filepath.Join(dir, "etc", "http.toml")
	if err := os.WriteFile(configPath, []byte("invalid toml {{{"), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	oldExeDirPath := ExeDirPath
	ExeDirPath = dir
	defer func() { ExeDirPath = oldExeDirPath }()

	ac := setupTestAC(t, dir)
	err := ac.loadHttpConfig()

	if err == nil {
		t.Fatal("Expected error for malformed http.toml, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse http config") {
		t.Errorf("Expected 'failed to parse' error, got: %v", err)
	}
}

func TestLoadPeers_MissingFile_OK(t *testing.T) {
	dir := setupTestDir(t)

	oldExeDirPath := ExeDirPath
	ExeDirPath = dir
	defer func() { ExeDirPath = oldExeDirPath }()

	ac := setupTestAC(t, dir)
	err := ac.loadPeers()

	// Missing server.toml should NOT be an error (it's optional)
	if err != nil {
		t.Fatalf("Expected no error for missing server.toml (optional), got: %v", err)
	}
}

func TestLoadPeers_MalformedTOML(t *testing.T) {
	dir := setupTestDir(t)

	// Write malformed TOML
	configPath := filepath.Join(dir, "etc", "server.toml")
	if err := os.WriteFile(configPath, []byte("invalid toml {{{"), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	oldExeDirPath := ExeDirPath
	ExeDirPath = dir
	defer func() { ExeDirPath = oldExeDirPath }()

	ac := setupTestAC(t, dir)
	err := ac.loadPeers()

	if err == nil {
		t.Fatal("Expected error for malformed server.toml, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse server peer config") {
		t.Errorf("Expected 'failed to parse' error, got: %v", err)
	}
}

// Note: TestLoadPeers_ValidConfig is omitted because loadPeers calls
// updateServerPeers which requires a fully initialized device (a.device).
// The fail-fast error handling is covered by TestLoadPeers_MalformedTOML
// and TestLoadPeers_MissingFile_OK.

// TestL3FlushDryRunSafety_FirstLoad_ForcesDryRun fences the boot-time
// safety branch in updateBaseConfig's `a.config == nil` (first-load)
// path. A fresh boot that already has EnableL3FlushOnExpiry=true with
// L3FlushDryRun=false (the most-dangerous case the safety exists for)
// must land in dry-run mode unless the distinct durable acknowledgement is
// present; an explicit false alone cannot be distinguished from omission.
//
// Regression fence for cr task #48 first-load gap (the previous
// implementation only guarded the reload path).
func TestL3FlushDryRunSafety_FirstLoad_ForcesDryRun(t *testing.T) {
	dir := setupTestDir(t)
	ac := setupTestAC(t, dir)
	conf := Config{
		EnableL3FlushOnExpiry: true,
		L3FlushDryRun:         false, // explicitly unsafe — should be overridden
	}
	if err := ac.updateBaseConfig(conf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ac.config.L3FlushDryRun {
		t.Errorf("first-load safety should have forced L3FlushDryRun=true; got false")
	}
	if !ac.config.EnableL3FlushOnExpiry {
		t.Errorf("EnableL3FlushOnExpiry should still be true; got false")
	}
}

func TestL3FlushDryRunSafety_FirstLoad_RespectsDurableRealModeAcknowledgement(t *testing.T) {
	dir := setupTestDir(t)
	ac := setupTestAC(t, dir)
	conf := Config{
		EnableL3FlushOnExpiry:       true,
		L3FlushDryRun:               false,
		L3FlushRealModeAcknowledged: true,
	}
	if err := ac.updateBaseConfig(conf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ac.config.L3FlushDryRun || !ac.config.L3FlushRealModeAcknowledged {
		t.Fatalf("durably acknowledged first load = dryRun:%t acknowledged:%t, want false/true",
			ac.config.L3FlushDryRun, ac.config.L3FlushRealModeAcknowledged)
	}
}

// TestL3FlushDryRunSafety_FirstLoad_RespectsExplicitDryRun fences that
// the safety doesn't change L3FlushDryRun when it's already true — the
// safety only forces dry-run ON, never back off.
func TestL3FlushDryRunSafety_FirstLoad_RespectsExplicitDryRun(t *testing.T) {
	dir := setupTestDir(t)
	ac := setupTestAC(t, dir)
	conf := Config{
		EnableL3FlushOnExpiry: true,
		L3FlushDryRun:         true,
	}
	if err := ac.updateBaseConfig(conf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ac.config.L3FlushDryRun {
		t.Errorf("L3FlushDryRun should remain true; got false")
	}
}

// TestL3FlushDryRunSafety_Reload_ForcesDryRunOnFalseToTrueEdge fences
// the reload-path safety: enabling the feature on a config that
// previously had it disabled forces dry-run regardless of the TOML's
// L3FlushDryRun setting.
//
// Regression fence for cr task #48 — the original implementation
// reassigned a.config.EnableL3FlushOnExpiry before the safety check,
// making the inner branch dead code.
func TestL3FlushDryRunSafety_Reload_ForcesDryRunOnFalseToTrueEdge(t *testing.T) {
	dir := setupTestDir(t)
	ac := setupTestAC(t, dir)
	// First load: feature disabled.
	if err := ac.updateBaseConfig(Config{EnableL3FlushOnExpiry: false}); err != nil {
		t.Fatalf("first load: unexpected error: %v", err)
	}
	if ac.config.EnableL3FlushOnExpiry {
		t.Fatalf("first load: expected EnableL3FlushOnExpiry=false; got true")
	}
	// Second load: flip enable=true with dry-run=false. Safety must
	// force dry-run=true.
	if err := ac.updateBaseConfig(Config{EnableL3FlushOnExpiry: true, L3FlushDryRun: false}); err != nil {
		t.Fatalf("reload: unexpected error: %v", err)
	}
	if !ac.config.EnableL3FlushOnExpiry {
		t.Errorf("EnableL3FlushOnExpiry should be true after reload; got false")
	}
	if !ac.config.L3FlushDryRun {
		t.Errorf("reload safety should have forced L3FlushDryRun=true on false→true edge; got false")
	}
}

func TestL3FlushDryRunSafety_Reload_RespectsDurableRealModeAcknowledgement(t *testing.T) {
	dir := setupTestDir(t)
	ac := setupTestAC(t, dir)
	if err := ac.updateBaseConfig(Config{EnableL3FlushOnExpiry: false}); err != nil {
		t.Fatalf("first load: unexpected error: %v", err)
	}
	if err := ac.updateBaseConfig(Config{EnableL3FlushOnExpiry: true, L3FlushDryRun: false,
		L3FlushRealModeAcknowledged: true}); err != nil {
		t.Fatalf("reload: unexpected error: %v", err)
	}
	if ac.config.L3FlushDryRun || !ac.config.L3FlushRealModeAcknowledged {
		t.Fatalf("durably acknowledged reload = dryRun:%t acknowledged:%t, want false/true",
			ac.config.L3FlushDryRun, ac.config.L3FlushRealModeAcknowledged)
	}
}

// TestL3FlushDryRunSafety_Reload_RespectsExplicitDryRunAfterEnabled
// fences the two-reload UX: after the first reload (which forces
// dry-run regardless), the second reload with the same explicit
// L3FlushDryRun=false should be honored — the safety only fires once
// per false→true enable edge.
func TestL3FlushDryRunSafety_Reload_RespectsExplicitDryRunAfterEnabled(t *testing.T) {
	dir := setupTestDir(t)
	ac := setupTestAC(t, dir)
	// First load: feature already enabled (first-load safety forces dry-run).
	if err := ac.updateBaseConfig(Config{EnableL3FlushOnExpiry: true, L3FlushDryRun: false}); err != nil {
		t.Fatalf("first load: unexpected error: %v", err)
	}
	if !ac.config.L3FlushDryRun {
		t.Fatalf("first load: expected L3FlushDryRun=true (forced); got false")
	}
	// Second reload: same setting. prevEnabled is now true, so the
	// reload-path safety does not fire — explicit false is honored.
	if err := ac.updateBaseConfig(Config{EnableL3FlushOnExpiry: true, L3FlushDryRun: false}); err != nil {
		t.Fatalf("second load: unexpected error: %v", err)
	}
	if ac.config.L3FlushDryRun {
		t.Errorf("second reload should honor explicit L3FlushDryRun=false; got true")
	}
}

// TestL3FlushConfigReload_PropagatesToLiveScheduler fences the
// SetDryRun / SetBreakerParams propagation path on config reload:
// an operator who flips L3FlushDryRun in config.toml should see
// the live scheduler honor the new value WITHOUT requiring an AC
// restart
func TestL3FlushConfigReload_PropagatesToLiveScheduler(t *testing.T) {
	dir := setupTestDir(t)
	ac := setupTestAC(t, dir)
	// Attach a live scheduler with known initial params.
	sched := NewScheduler(&NoOpFlusher{},
		WithDryRun(true),
		WithBreakerThreshold(10),
		WithBreakerWindow(60*time.Second),
	)
	sched.Start()
	defer func() { _ = sched.Shutdown(context.Background()) }()
	ac.expirySched = sched

	// First-load: feature enabled, dry-run=true. Sets a.config.
	if err := ac.updateBaseConfig(Config{
		EnableL3FlushOnExpiry: true,
		L3FlushDryRun:         true,
		L3FlushErrorThreshold: 10,
		L3FlushErrorWindowSec: 60,
	}); err != nil {
		t.Fatalf("first load: %v", err)
	}

	// Reload with dry-run=false. Reload-path safety does NOT fire
	// because prevEnabled=true (already enabled). New value must
	// propagate to the live scheduler atomically.
	if err := ac.updateBaseConfig(Config{
		EnableL3FlushOnExpiry: true,
		L3FlushDryRun:         false,
		L3FlushErrorThreshold: 25,
		L3FlushErrorWindowSec: 120,
	}); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if sched.dryRun.Load() {
		t.Errorf("scheduler.dryRun should be false after reload propagation; got true")
	}
	// Threshold + window are written under breakerErrMu; read the
	// same way to avoid a race-detector hit.
	sched.breakerErrMu.Lock()
	gotThreshold := sched.breakerThreshold
	gotWindow := sched.breakerWindow
	sched.breakerErrMu.Unlock()
	if gotThreshold != 25 {
		t.Errorf("breakerThreshold: got %d want 25", gotThreshold)
	}
	if gotWindow != 120*time.Second {
		t.Errorf("breakerWindow: got %s want 120s", gotWindow)
	}
}

func TestL3FlushConntrackReloadRecordsConfigButKeepsConstructedFlusher(t *testing.T) {
	dir := setupTestDir(t)
	ac := setupTestAC(t, dir)

	if err := ac.updateBaseConfig(Config{
		EnableL3FlushOnExpiry:    true,
		L3FlushDryRun:            true,
		L3FlushConntrackBackend:  "exec",
		L3FlushConntrackPoolSize: defaultConntrackNetlinkPoolSize,
		L3FlushErrorThreshold:    10,
		L3FlushErrorWindowSec:    60,
	}); err != nil {
		t.Fatalf("first load: %v", err)
	}
	constructed := &ConntrackFlusher{}
	ac.conntrackFlusher.Store(constructed)

	if err := ac.updateBaseConfig(Config{
		EnableL3FlushOnExpiry:    true,
		L3FlushDryRun:            true,
		L3FlushConntrackBackend:  "netlink",
		L3FlushConntrackPoolSize: 32,
		L3FlushErrorThreshold:    10,
		L3FlushErrorWindowSec:    60,
	}); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := ac.config.L3FlushConntrackBackend; got != "netlink" {
		t.Errorf("L3FlushConntrackBackend after reload = %q, want netlink", got)
	}
	if got := ac.config.L3FlushConntrackPoolSize; got != 32 {
		t.Errorf("L3FlushConntrackPoolSize after reload = %d, want 32", got)
	}
	if got := ac.conntrackFlusher.Load(); got != constructed {
		t.Errorf("conntrack flusher pointer changed on reload: got %p want %p", got, constructed)
	}
}

func TestL3FlushConntrackReloadDedupesRepeatedUnknownBackend(t *testing.T) {
	dir := setupTestDir(t)
	ac := setupTestAC(t, dir)

	if err := ac.updateBaseConfig(Config{
		EnableL3FlushOnExpiry:    true,
		L3FlushDryRun:            true,
		L3FlushConntrackBackend:  "bogus",
		L3FlushConntrackPoolSize: defaultConntrackNetlinkPoolSize,
		L3FlushErrorThreshold:    10,
		L3FlushErrorWindowSec:    60,
	}); err != nil {
		t.Fatalf("first load: %v", err)
	}
	if got := ac.config.L3FlushConntrackBackend; got != "exec" {
		t.Fatalf("first-load backend = %q, want normalized exec", got)
	}
	if got := ac.lastInvalidL3FlushConntrackBackend; got != "bogus" {
		t.Fatalf("remembered invalid backend = %q, want bogus", got)
	}

	if err := ac.updateBaseConfig(Config{
		EnableL3FlushOnExpiry:    true,
		L3FlushDryRun:            true,
		L3FlushConntrackBackend:  "bogus",
		L3FlushConntrackPoolSize: defaultConntrackNetlinkPoolSize,
		L3FlushErrorThreshold:    10,
		L3FlushErrorWindowSec:    60,
	}); err != nil {
		t.Fatalf("same invalid reload: %v", err)
	}
	if got := ac.config.L3FlushConntrackBackend; got != "exec" {
		t.Fatalf("same-invalid reload backend = %q, want normalized exec", got)
	}
	if got := ac.lastInvalidL3FlushConntrackBackend; got != "bogus" {
		t.Fatalf("same-invalid remembered backend = %q, want bogus", got)
	}

	if err := ac.updateBaseConfig(Config{
		EnableL3FlushOnExpiry:    true,
		L3FlushDryRun:            true,
		L3FlushConntrackBackend:  "netlink",
		L3FlushConntrackPoolSize: defaultConntrackNetlinkPoolSize,
		L3FlushErrorThreshold:    10,
		L3FlushErrorWindowSec:    60,
	}); err != nil {
		t.Fatalf("valid reload: %v", err)
	}
	if got := ac.lastInvalidL3FlushConntrackBackend; got != "" {
		t.Fatalf("remembered invalid backend after valid reload = %q, want cleared", got)
	}
}

// TestL3FlushConfigReload_ClampsThresholdToRing fences the
// clamp behavior when an operator's new threshold outgrows the
// breaker ring sized at scheduler construction. The ring at
// construction is max(default, initialThreshold); bumping past
// that on reload would otherwise store a threshold the breaker
// can never reach. The clamp turns the operator footgun
// ("stored but unprotectable") into a loud Warning + the
// largest-still-protectable value.
func TestL3FlushConfigReload_ClampsThresholdToRing(t *testing.T) {
	dir := setupTestDir(t)
	ac := setupTestAC(t, dir)
	// Construct a tiny ring (default is 128; with a small initial
	// threshold the ring sizes to the default).
	sched := NewScheduler(&NoOpFlusher{}, WithBreakerThreshold(10))
	sched.Start()
	defer func() { _ = sched.Shutdown(context.Background()) }()
	ac.expirySched = sched

	if got := sched.BreakerRingSize(); got != 128 {
		t.Fatalf("setup: expected ring size 128; got %d", got)
	}
	// First load.
	if err := ac.updateBaseConfig(Config{
		EnableL3FlushOnExpiry: true,
		L3FlushDryRun:         true,
		L3FlushErrorThreshold: 10,
		L3FlushErrorWindowSec: 60,
	}); err != nil {
		t.Fatalf("first load: %v", err)
	}
	// Reload with threshold > ring. SetBreakerParams clamps to
	// the ring size so the breaker stays protectable.
	if err := ac.updateBaseConfig(Config{
		EnableL3FlushOnExpiry: true,
		L3FlushDryRun:         true,
		L3FlushErrorThreshold: 500, // > ring size of 128
		L3FlushErrorWindowSec: 60,
	}); err != nil {
		t.Fatalf("reload: %v", err)
	}
	sched.breakerErrMu.Lock()
	gotThreshold := sched.breakerThreshold
	sched.breakerErrMu.Unlock()
	if gotThreshold != 128 {
		t.Errorf("breakerThreshold should be clamped to ring size 128; got %d", gotThreshold)
	}
}

// TestL3FlushFirstLoad_NormalizesBreakerTunables fences the critical
// fix from cr round 5: a first-load with EnableL3FlushOnExpiry=true
// and L3FlushErrorThreshold omitted (TOML zero value) must NOT land
// breakerThreshold=0 — `count >= 0` would be true on the first
// flush error and the breaker would open instantly, refusing every
// NHP-AOP. Both threshold AND window must be normalized via
// intOrDefault on first-load (mirror of the reload-path behavior).
func TestL3FlushFirstLoad_NormalizesBreakerTunables(t *testing.T) {
	dir := setupTestDir(t)
	ac := setupTestAC(t, dir)
	// First-load with breaker tunables OMITTED (TOML zero values).
	if err := ac.updateBaseConfig(Config{
		EnableL3FlushOnExpiry: true,
		L3FlushDryRun:         true,
		// L3FlushErrorThreshold + L3FlushErrorWindowSec left at zero.
	}); err != nil {
		t.Fatalf("first load: %v", err)
	}
	if ac.config.L3FlushErrorThreshold != DefaultL3FlushErrorThreshold {
		t.Errorf("first-load L3FlushErrorThreshold should normalize to default %d; got %d",
			DefaultL3FlushErrorThreshold, ac.config.L3FlushErrorThreshold)
	}
	if ac.config.L3FlushErrorWindowSec != DefaultL3FlushErrorWindowSec {
		t.Errorf("first-load L3FlushErrorWindowSec should normalize to default %d; got %d",
			DefaultL3FlushErrorWindowSec, ac.config.L3FlushErrorWindowSec)
	}
}

// TestL3FlushFirstLoad_RespectsExplicitBreakerTunables fences that
// the first-load normalization doesn't clobber operator-supplied
// values — only zero / negative TOML inputs are replaced.
func TestL3FlushFirstLoad_RespectsExplicitBreakerTunables(t *testing.T) {
	dir := setupTestDir(t)
	ac := setupTestAC(t, dir)
	if err := ac.updateBaseConfig(Config{
		EnableL3FlushOnExpiry: true,
		L3FlushDryRun:         true,
		L3FlushErrorThreshold: 99,
		L3FlushErrorWindowSec: 42,
	}); err != nil {
		t.Fatalf("first load: %v", err)
	}
	if ac.config.L3FlushErrorThreshold != 99 {
		t.Errorf("explicit L3FlushErrorThreshold=99 should be preserved; got %d", ac.config.L3FlushErrorThreshold)
	}
	if ac.config.L3FlushErrorWindowSec != 42 {
		t.Errorf("explicit L3FlushErrorWindowSec=42 should be preserved; got %d", ac.config.L3FlushErrorWindowSec)
	}
}

// TestIntOrDefault_NegativeValueUsesDefault fences the cr round 3
// safety: a typo'd negative TOML threshold/window must NOT silently
// disappear into the default — intOrDefault logs a Warning and
// uses the default. This test covers the negative path that
// cr round 8 finding 5 noted was unreached by existing tests.
func TestIntOrDefault_NegativeValueUsesDefault(t *testing.T) {
	cases := []struct {
		name string
		v    int
		def  int
		want int
	}{
		{"positive-passthrough", 42, 99, 42},
		{"zero-uses-default", 0, 99, 99},
		{"negative-uses-default", -1, 99, 99},
		{"negative-large-uses-default", -1000, 99, 99},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := intOrDefault(c.v, c.def); got != c.want {
				t.Errorf("intOrDefault(%d, %d): got %d want %d", c.v, c.def, got, c.want)
			}
		})
	}
}
