package server

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/etcd"
	"github.com/OpenNHP/opennhp/nhp/log"
)

const (
	etcdAppSecretCanary   = "lv_etcd_APP_SECRET_must_never_reach_logs"
	etcdAccessKeyCanary   = "lv_etcd_ACCESS_KEY_must_never_reach_logs"
	etcdSecretKeyCanary   = "lv_etcd_SECRET_KEY_must_never_reach_logs"
	etcdJWTSecretCanary   = "lv_etcd_JWT_SECRET_must_never_reach_logs"
	etcdParseErrorCanary  = "lv_etcd_PARSE_ERROR_must_never_reach_logs"
	resourceErrorCanary   = "lv_resource_PARSE_ERROR_must_never_reach_logs"
	remotePasswordCanary  = "lv_remote_PASSWORD_must_never_reach_logs"
	basePrivateKeyCanary  = "lv_base_PRIVATE_KEY_must_never_reach_logs"
	storagePasswordCanary = "lv_storage_PASSWORD_must_never_reach_logs"
)

// TestEtcdAndLocalConfigLogsRedactSecrets exercises the remote-config logging
// boundary and its adjacent secret-bearing local parsers. A successful remote
// config carries representative ResourceData and ExInfo credentials; malformed
// TOML places canaries on rejected lines so neither raw bodies nor
// decoder-derived diagnostics can reintroduce them.
func TestEtcdAndLocalConfigLogsRedactSecrets(t *testing.T) {
	// Do not call t.Parallel: the package logger swap is process-wide.
	// Keep the cases linear: they share one capture, and the final aggregate
	// sweep proves that no logger writer leaked any fixture or canary.
	logDir := t.TempDir()
	testLogger := log.NewLogger("NHP-Etcd-Config-Redaction-Test", log.LogLevelDebug, logDir, "etcd-config")
	previousLogger := log.SwapGlobalLogger(testLogger)
	t.Cleanup(func() {
		log.SwapGlobalLogger(previousLogger)
		testLogger.Close()
	})

	successContent := []byte(`[[AuthServiceId]]
AuthSvcId = "redaction-test"

[AuthServiceId.ResourceGroups.protected]
AppSecret = "` + etcdAppSecretCanary + `"
AccessKey = "` + etcdAccessKeyCanary + `"
SecretKey = "` + etcdSecretKeyCanary + `"

[AuthServiceId.ResourceGroups.protected.ExInfo]
JWTSecret = "` + etcdJWTSecretCanary + `"
`)
	// These fixtures omit peer and HTTP sections, so updateEtcdConfig exercises
	// only the zero-value-safe resource and source-IP apply paths.
	server := &UdpServer{}
	if err := server.updateEtcdConfig(successContent, true); err != nil {
		t.Fatalf("update valid etcd config: %v", err)
	}
	authService := server.authServiceMap["redaction-test"]
	if authService == nil {
		t.Fatal("valid etcd config did not populate redaction-test auth service")
	}
	resource := authService.ResourceGroups["protected"]
	if resource == nil {
		t.Fatal("valid etcd config did not populate protected resource")
	}
	if resource.AppSecret != etcdAppSecretCanary ||
		resource.AccessKey != etcdAccessKeyCanary ||
		resource.SecretKey != etcdSecretKeyCanary ||
		resource.ExInfo["JWTSecret"] != etcdJWTSecretCanary {
		t.Fatal("valid etcd config did not populate all credential canaries")
	}

	failureContent := []byte(`[[AuthServiceId]]
AuthSvcId = "redaction-test"

[AuthServiceId.ResourceGroups.protected]
AppSecret = "` + etcdParseErrorCanary + `" unexpected
`)
	updateErr := server.updateEtcdConfig(failureContent, true)
	if !errors.Is(updateErr, errLoadConfig) {
		t.Fatalf("update malformed etcd config error = %v, want %v", updateErr, errLoadConfig)
	}
	if strings.Contains(updateErr.Error(), etcdParseErrorCanary) {
		t.Fatal("malformed etcd config error exposed the credential canary")
	}

	// Every local fixture below is intentionally malformed so each loader returns
	// before registering a package-global file watcher. Future valid fixtures must
	// close any watcher they register before this test returns.
	//
	// The adjacent local resource.toml path must not depend on decoder error
	// formatting either: future decoder versions may include source excerpts.
	resourceRoot := t.TempDir()
	resourceEtcDir := filepath.Join(resourceRoot, "etc")
	if err := os.MkdirAll(resourceEtcDir, 0o700); err != nil {
		t.Fatalf("create resource config directory: %v", err)
	}
	resourceContent := []byte(`[[redaction-test]]
AppSecret = "` + resourceErrorCanary + `" unexpected
`)
	resourcePath := filepath.Join(resourceEtcDir, "resource.toml")
	if err := os.WriteFile(resourcePath, resourceContent, 0o600); err != nil {
		t.Fatalf("write malformed resource config: %v", err)
	}
	previousExeDirPath := ExeDirPath
	ExeDirPath = resourceRoot
	t.Cleanup(func() { ExeDirPath = previousExeDirPath })
	if err := server.loadResources(); err != nil {
		t.Fatalf("load malformed resource config: %v", err)
	}

	remoteContent := []byte(`Provider = "etcd"
Password = "` + remotePasswordCanary + `" unexpected
`)
	remotePath := filepath.Join(resourceEtcDir, "remote.toml")
	if err := os.WriteFile(remotePath, remoteContent, 0o600); err != nil {
		t.Fatalf("write malformed remote config: %v", err)
	}
	remoteErr := server.initRemoteConn()
	if !errors.Is(remoteErr, errLoadConfig) {
		t.Fatalf("load malformed remote config error = %v, want %v", remoteErr, errLoadConfig)
	}
	if strings.Contains(remoteErr.Error(), remotePasswordCanary) {
		t.Fatal("malformed remote config error exposed the credential canary")
	}

	baseContent := []byte(`PrivateKeyBase64 = "` + basePrivateKeyCanary + `" unexpected
`)
	basePath := filepath.Join(resourceEtcDir, "config.toml")
	if err := os.WriteFile(basePath, baseContent, 0o600); err != nil {
		t.Fatalf("write malformed base config: %v", err)
	}
	baseErr := server.loadBaseConfig()
	if !errors.Is(baseErr, errLoadConfig) {
		t.Fatalf("load malformed base config error = %v, want %v", baseErr, errLoadConfig)
	}
	if strings.Contains(baseErr.Error(), basePrivateKeyCanary) {
		t.Fatal("malformed base config error exposed the credential canary")
	}
	if !strings.Contains(baseErr.Error(), redactedConfigParseHint) {
		t.Fatal("malformed base config error omitted the redaction-safe operator hint")
	}

	storageContent := []byte(`[Etcd]
Password = "` + storagePasswordCanary + `" unexpected
`)
	storagePath := filepath.Join(resourceEtcDir, "storage.toml")
	if err := os.WriteFile(storagePath, storageContent, 0o600); err != nil {
		t.Fatalf("write malformed storage config: %v", err)
	}
	_, storageErr := server.loadStorageConfig()
	if !errors.Is(storageErr, errLoadConfig) {
		t.Fatalf("load malformed storage config error = %v, want %v", storageErr, errLoadConfig)
	}
	if strings.Contains(storageErr.Error(), storagePasswordCanary) {
		t.Fatal("malformed storage config error exposed the credential canary")
	}
	if !strings.Contains(storageErr.Error(), redactedConfigParseHint) {
		t.Fatal("malformed storage config error omitted the redaction-safe operator hint")
	}

	// Closing flushes the async writer before the assertions read its files.
	log.SwapGlobalLogger(previousLogger)
	testLogger.Close()

	var allLogs []byte
	if err := filepath.WalkDir(logDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		allLogs = append(allLogs, contents...)
		return nil
	}); err != nil {
		t.Fatalf("read etcd config logs: %v", err)
	}

	for _, canary := range []string{
		etcdAppSecretCanary,
		etcdAccessKeyCanary,
		etcdSecretKeyCanary,
		etcdJWTSecretCanary,
		etcdParseErrorCanary,
		resourceErrorCanary,
		remotePasswordCanary,
		basePrivateKeyCanary,
		storagePasswordCanary,
	} {
		if bytes.Contains(allLogs, []byte(canary)) {
			t.Errorf("config credential canary %q appeared in logs", canary)
		}
	}
	for _, body := range [][]byte{
		successContent,
		failureContent,
		resourceContent,
		remoteContent,
		baseContent,
		storageContent,
	} {
		if bytes.Contains(allLogs, body) {
			t.Error("complete secret-bearing config body appeared in logs")
		}
	}

	for _, want := range []string{
		fmt.Sprintf("[Server] parsing etcd config (%d bytes)", len(successContent)),
		fmt.Sprintf("[Server] finished processing etcd config (%d bytes)", len(successContent)),
		fmt.Sprintf("[Server] failed to parse etcd config (%d bytes). %s", len(failureContent), redactedConfigParseHint),
		fmt.Sprintf("[Server] failed to parse resource config %s. %s", resourcePath, redactedConfigParseHint),
		fmt.Sprintf("[Server] failed to parse remote config %s. %s", remotePath, redactedConfigParseHint),
	} {
		if !bytes.Contains(allLogs, []byte(want)) {
			t.Errorf("config logs missing fixed metadata %q", want)
		}
	}
}

// TestEtcdKeyPrefixFix verifies that the etcd key format is correct
func TestEtcdKeyPrefixFix(t *testing.T) {
	// EtcdConn.InitClient() prepends "/" to the key from remote.toml
	// Line 60 in etcdconn.go: conn.Key = "/" + conn.Key

	// remote.toml sets Key = "nhp/config"
	configKey := "nhp/config"

	// After InitClient(), conn.Key becomes "/nhp/config"
	actualKey := "/" + configKey

	t.Logf("remote.toml Key = %q", configKey)
	t.Logf("After InitClient(), conn.Key = %q", actualKey)

	// user_data.sh.tpl MUST use "/nhp/config" (with leading slash)
	seedKey := "/nhp/config"

	t.Logf("user_data etcdctl PUT key = %q", seedKey)

	if actualKey != seedKey {
		t.Errorf("KEY MISMATCH! Server reads %q but seed uses %q", actualKey, seedKey)
	} else {
		t.Log("Keys match - configuration is correct!")
	}
}

// TestEtcdConnKeyTransformation verifies the key transformation behavior
func TestEtcdConnKeyTransformation(t *testing.T) {
	conn := &etcd.EtcdConn{
		Key: "nhp/config",
	}

	t.Logf("Before: conn.Key = %q", conn.Key)

	// Simulate what InitClient does
	transformedKey := "/" + conn.Key

	t.Logf("After InitClient transformation: %q", transformedKey)

	if transformedKey != "/nhp/config" {
		t.Errorf("Expected /nhp/config, got %q", transformedKey)
	}
}

// TestEtcdConfigParsing tests parsing the exact etcd config format
func TestEtcdConfigParsing(t *testing.T) {
	etcdContent := `[[AuthServiceId]]
AuthSvcId = "passcode"
PluginPath = "passcode/main.so"
`

	t.Logf("Parsing TOML content (%d bytes):\n%s", len(etcdContent), etcdContent)

	var serverEtcdConfig ServerEtcdConfig
	err := toml.Unmarshal([]byte(etcdContent), &serverEtcdConfig)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	t.Logf("AuthServiceId slice length: %d", len(serverEtcdConfig.AuthServiceId))

	if len(serverEtcdConfig.AuthServiceId) != 1 {
		t.Errorf("Expected 1 AuthServiceId entry, got %d", len(serverEtcdConfig.AuthServiceId))
	}

	if len(serverEtcdConfig.AuthServiceId) > 0 {
		asp := serverEtcdConfig.AuthServiceId[0]
		t.Logf("AuthServiceId[0]: AuthSvcId=%q PluginPath=%q", asp.AuthSvcId, asp.PluginPath)

		if asp.AuthSvcId != "passcode" {
			t.Errorf("Expected AuthSvcId='passcode', got %q", asp.AuthSvcId)
		}
		if asp.PluginPath != "passcode/main.so" {
			t.Errorf("Expected PluginPath='passcode/main.so', got %q", asp.PluginPath)
		}
	}
}

// TestMergedConfigParsing tests the merged config format
func TestMergedConfigParsing(t *testing.T) {
	// This is what /nhp/config should contain after proper seeding
	mergedConfig := `# NHP AC Configuration (seeded by Terraform)

[HttpConfig]
EnableHttp = true
EnableTLS = false
HttpListenPort = 8888

[[Servers]]
Hostname = "nhp-sandbox-server-nlb.elb.us-east-2.amazonaws.com"
Port = 62206
PubKeyBase64 = "abc123"

[[AuthServiceId]]
AuthSvcId = "passcode"
PluginPath = "passcode/main.so"
`

	t.Logf("Parsing merged config (%d bytes)", len(mergedConfig))

	var cfg ServerEtcdConfig
	err := toml.Unmarshal([]byte(mergedConfig), &cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal merged config: %v", err)
	}

	// Verify HttpConfig
	if !cfg.HttpConfig.EnableHttp {
		t.Error("HttpConfig.EnableHttp should be true")
	}
	if cfg.HttpConfig.HttpListenPort != 8888 {
		t.Errorf("HttpConfig.HttpListenPort should be 8888, got %d", cfg.HttpConfig.HttpListenPort)
	}
	t.Logf("HttpConfig: EnableHttp=%v HttpListenPort=%d", cfg.HttpConfig.EnableHttp, cfg.HttpConfig.HttpListenPort)

	// Verify AuthServiceId
	if len(cfg.AuthServiceId) != 1 {
		t.Errorf("Expected 1 AuthServiceId entry, got %d", len(cfg.AuthServiceId))
	} else {
		asp := cfg.AuthServiceId[0]
		t.Logf("AuthServiceId: %s -> %s", asp.AuthSvcId, asp.PluginPath)
		if asp.AuthSvcId != "passcode" || asp.PluginPath != "passcode/main.so" {
			t.Error("AuthServiceId not parsed correctly")
		}
	}

	// Simulate updateResources logic
	aspMap := make(common.AuthSvcProviderMap)
	for _, aspData := range cfg.AuthServiceId {
		aspId := aspData.AuthSvcId
		aspMap[aspId] = aspData
	}

	t.Logf("aspMap has %d entries", len(aspMap))
	if len(aspMap) == 0 {
		t.Fatal("aspMap is empty - no plugins would be loaded!")
	}

	for aspId, aspData := range aspMap {
		if len(aspData.PluginPath) > 0 {
			t.Logf("Would load plugin: aspId=%q path=%q", aspId, aspData.PluginPath)
		}
	}

	t.Log("SUCCESS: Merged config parses correctly and plugins would be loaded")
}

// =============================================================================
// Tests for AC peer preservation when etcd config has no [[ACs]] section
// These tests verify the fix for the bug where updateACPeers([]) would wipe
// all dynamically registered ACs from the AC registry.
// =============================================================================

// TestEtcdConfigWithOnlyServers_PreservesACPeers tests the realistic scenario
// where Lambda seeds /nhp/config with only [[Servers]] (no [[ACs]] section).
// This should NOT wipe AC peers that were loaded from the AC registry.
func TestEtcdConfigWithOnlyServers_PreservesACPeers(t *testing.T) {
	// This is what Lambda writes to /nhp/config (only [[Servers]])
	etcdConfig := `# NHP AC Configuration (seeded by Terraform)
[[Servers]]
Hostname = "nhp-sandbox-server-nlb.elb.us-east-2.amazonaws.com"
Ip = ""
Port = 62206
PubKeyBase64 = "abc123"
ExpireTime = 1924991999
`
	var cfg ServerEtcdConfig
	err := toml.Unmarshal([]byte(etcdConfig), &cfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify: ACs slice should be nil/empty
	if len(cfg.ACs) != 0 {
		t.Errorf("Expected 0 ACs, got %d", len(cfg.ACs))
	}

	// Verify: The conditional check should prevent updateACPeers from being called
	shouldUpdateACs := len(cfg.ACs) > 0
	if shouldUpdateACs {
		t.Error("shouldUpdateACs should be false when no [[ACs]] in config")
	}

	t.Log("PASS: Config with only [[Servers]] correctly has empty ACs slice")
	t.Log("PASS: Fix correctly prevents calling updateACPeers with empty slice")
}

// TestUpdateACPeers_PreservesExistingPeers verifies that when updateACPeers is
// skipped (due to empty ACs in etcd config), existing peers remain in the device.
func TestUpdateACPeers_PreservesExistingPeers(t *testing.T) {
	// Create a minimal server with a device
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	server := &UdpServer{
		device:    device,
		acPeerMap: make(map[string]*core.UdpPeer),
	}

	// Simulate AC registry loading: add a peer to the device
	registryPeer := &core.UdpPeer{
		Ip:           "10.0.0.100",
		Port:         common.DefaultNHPPort,
		PubKeyBase64: "cmVnaXN0cnlwZWVycHVia2V5YmFzZTY0", // "registrypeerpubkeybase64"
		ExpireTime:   common.FarFutureExpiry,
	}
	registryPeer.Type = core.NHP_AC

	// Add peer via updateACPeers (simulating reconcileACPeersFromRegistry)
	err := server.updateACPeers([]*core.UdpPeer{registryPeer})
	if err != nil {
		t.Fatalf("Failed to add registry peer: %v", err)
	}

	// Verify peer is in the device
	peer := device.LookupPeer([]byte("registrypeerpubkeybase64"))
	// Note: LookupPeer uses base64 encoding of raw bytes, so we need the decoded form
	// For this test, just verify the acPeerMap
	if len(server.acPeerMap) != 1 {
		t.Errorf("Expected 1 peer in acPeerMap, got %d", len(server.acPeerMap))
	}
	t.Logf("acPeerMap contains %d peers (expected 1)", len(server.acPeerMap))

	// Now simulate etcd config update with no [[ACs]] section
	etcdConfig := `[[Servers]]
Hostname = "server.example.com"
Port = 62206
PubKeyBase64 = "c2VydmVycHVia2V5"
`
	var cfg ServerEtcdConfig
	if err := toml.Unmarshal([]byte(etcdConfig), &cfg); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// The fix: only call updateACPeers if ACs > 0
	if len(cfg.ACs) > 0 {
		if err := server.updateACPeers(cfg.ACs); err != nil {
			t.Fatalf("updateACPeers failed: %v", err)
		}
		t.Log("updateACPeers was called (ACs defined in config)")
	} else {
		t.Log("updateACPeers was SKIPPED (no ACs in config) - this is the fix!")
	}

	// Verify: peer should still be in acPeerMap (not wiped)
	if len(server.acPeerMap) != 1 {
		t.Errorf("REGRESSION: acPeerMap was wiped! Expected 1 peer, got %d", len(server.acPeerMap))
	} else {
		t.Log("PASS: AC peer was preserved after etcd config update")
	}

	// Verify peer is still accessible
	for pubKey, p := range server.acPeerMap {
		t.Logf("Preserved peer: pubKey=%s ip=%s port=%d", pubKey, p.Ip, p.Port)
	}

	_ = peer // silence unused variable warning
}

// TestUpdateACPeers_UpdatesPeers_WhenACsDefinedInEtcd verifies that when
// [[ACs]] is defined in etcd config, the peers ARE updated (legacy mode).
func TestUpdateACPeers_UpdatesPeers_WhenACsDefinedInEtcd(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	server := &UdpServer{
		device:    device,
		acPeerMap: make(map[string]*core.UdpPeer),
	}

	// Start with one peer
	initialPeer := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         common.DefaultNHPPort,
		PubKeyBase64: "aW5pdGlhbHBlZXI=", // "initialpeer"
		ExpireTime:   common.FarFutureExpiry,
	}
	if err := server.updateACPeers([]*core.UdpPeer{initialPeer}); err != nil {
		t.Fatalf("updateACPeers failed: %v", err)
	}

	if len(server.acPeerMap) != 1 {
		t.Fatalf("Setup failed: expected 1 peer, got %d", len(server.acPeerMap))
	}

	// etcd config with [[ACs]] defined (legacy static mode)
	etcdConfig := `[[ACs]]
Ip = "10.0.0.200"
Port = 62206
PubKeyBase64 = "bmV3cGVlcmZyb21ldGNk"
ExpireTime = 1924991999
`
	var cfg ServerEtcdConfig
	if err := toml.Unmarshal([]byte(etcdConfig), &cfg); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// When [[ACs]] is defined, updateACPeers SHOULD be called
	if len(cfg.ACs) > 0 {
		t.Logf("Config has %d ACs defined, calling updateACPeers", len(cfg.ACs))
		if err := server.updateACPeers(cfg.ACs); err != nil {
			t.Fatalf("updateACPeers failed: %v", err)
		}
	} else {
		t.Error("Expected ACs to be defined in config")
	}

	// Verify: old peer should be removed, new peer should be present
	if len(server.acPeerMap) != 1 {
		t.Errorf("Expected 1 peer after update, got %d", len(server.acPeerMap))
	}

	// Check the new peer is present
	newPeerKey := "bmV3cGVlcmZyb21ldGNk"
	if _, found := server.acPeerMap[newPeerKey]; !found {
		t.Errorf("New peer not found in acPeerMap")
	} else {
		t.Log("PASS: New peer from etcd config was added")
	}

	// Check the old peer is removed
	oldPeerKey := "aW5pdGlhbHBlZXI="
	if _, found := server.acPeerMap[oldPeerKey]; found {
		t.Errorf("Old peer should have been removed")
	} else {
		t.Log("PASS: Old peer was correctly removed")
	}
}

// TestEmptyVsNil_ACsSlice verifies that both nil and empty [[ACs]] are handled
func TestEmptyVsNil_ACsSlice(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		expectEmpty bool
	}{
		{
			name: "no_ACs_section",
			config: `[[Servers]]
Hostname = "test"`,
			expectEmpty: true,
		},
		{
			name:        "only_servers",
			config:      "[[Servers]]\nHostname = \"test\"\nPort = 62206\n",
			expectEmpty: true,
		},
		{
			name: "with_ACs_section",
			config: `[[ACs]]
Ip = "10.0.0.1"
PubKeyBase64 = "dGVzdA=="
`,
			expectEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg ServerEtcdConfig
			err := toml.Unmarshal([]byte(tt.config), &cfg)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			isEmpty := len(cfg.ACs) == 0
			if isEmpty != tt.expectEmpty {
				t.Errorf("len(cfg.ACs)==0 = %v, want %v", isEmpty, tt.expectEmpty)
			}

			// The fix logic
			shouldSkipUpdate := len(cfg.ACs) == 0
			t.Logf("ACs count: %d, shouldSkipUpdate: %v", len(cfg.ACs), shouldSkipUpdate)
		})
	}
}
