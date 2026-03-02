package ac

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
AuthServiceId = "layerv"
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
	if config.AuthServiceId != "layerv" {
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
AuthServiceId = "layerv"
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
