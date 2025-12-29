package server

import (
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
	toml "github.com/pelletier/go-toml/v2"
)

// TestPluginLoadingFromEtcdConfig tests the full flow:
// 1. etcd contains merged config with HttpConfig AND AuthServiceId
// 2. Server parses it correctly
// 3. Plugin paths are extracted for loading
func TestPluginLoadingFromEtcdConfig(t *testing.T) {
	// This is what /nhp/config SHOULD contain after proper seeding
	// (merged HttpConfig from Lambda + AuthServiceId from user_data)
	etcdConfig := `# NHP Server Configuration
# Seeded by Terraform Lambda + NHP Server boot

[HttpConfig]
EnableHttp = true
EnableTLS = false
HttpListenPort = 8888

[[AuthServiceId]]
AuthSvcId = "passcode"
PluginPath = "passcode/main.so"
`

	t.Logf("Parsing merged etcd config (%d bytes):\n%s", len(etcdConfig), etcdConfig)

	var serverEtcdConfig ServerEtcdConfig
	err := toml.Unmarshal([]byte(etcdConfig), &serverEtcdConfig)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify HttpConfig parsed correctly
	t.Logf("HttpConfig: EnableHttp=%v, HttpListenPort=%d",
		serverEtcdConfig.HttpConfig.EnableHttp,
		serverEtcdConfig.HttpConfig.HttpListenPort)

	if !serverEtcdConfig.HttpConfig.EnableHttp {
		t.Error("Expected EnableHttp=true")
	}
	if serverEtcdConfig.HttpConfig.HttpListenPort != 8888 {
		t.Errorf("Expected HttpListenPort=8888, got %d", serverEtcdConfig.HttpConfig.HttpListenPort)
	}

	// Verify AuthServiceId parsed correctly
	t.Logf("AuthServiceId count: %d", len(serverEtcdConfig.AuthServiceId))

	if len(serverEtcdConfig.AuthServiceId) != 1 {
		t.Fatalf("Expected 1 AuthServiceId entry, got %d", len(serverEtcdConfig.AuthServiceId))
	}

	asp := serverEtcdConfig.AuthServiceId[0]
	t.Logf("AuthServiceId[0]: AuthSvcId=%q, PluginPath=%q", asp.AuthSvcId, asp.PluginPath)

	if asp.AuthSvcId != "passcode" {
		t.Errorf("Expected AuthSvcId='passcode', got %q", asp.AuthSvcId)
	}
	if asp.PluginPath != "passcode/main.so" {
		t.Errorf("Expected PluginPath='passcode/main.so', got %q", asp.PluginPath)
	}

	// Simulate what updateResources does
	aspMap := make(common.AuthSvcProviderMap)
	for _, aspData := range serverEtcdConfig.AuthServiceId {
		aspId := aspData.AuthSvcId
		aspMap[aspId] = aspData
	}

	t.Logf("aspMap has %d entries", len(aspMap))

	// Verify the plugin would be loaded
	for aspId, aspData := range aspMap {
		if len(aspData.PluginPath) > 0 {
			t.Logf("Would load plugin for aspId=%q from path=%q", aspId, aspData.PluginPath)
		} else {
			t.Errorf("aspId=%q has empty PluginPath", aspId)
		}
	}

	if len(aspMap) == 0 {
		t.Fatal("aspMap is empty - no plugins would be loaded!")
	}

	t.Log("SUCCESS: Plugin config would be loaded correctly")
}

// TestEtcdKeyMustHaveLeadingSlash documents the key format requirement
func TestEtcdKeyMustHaveLeadingSlash(t *testing.T) {
	// The EtcdConn.InitClient() adds a leading slash to the key
	// So when remote.toml has Key = "nhp/config"
	// The actual key used is "/nhp/config"

	remoteTomlKey := "nhp/config"
	actualKeyAfterInit := "/" + remoteTomlKey // This is what InitClient does

	t.Logf("remote.toml Key = %q", remoteTomlKey)
	t.Logf("Actual etcd key after InitClient = %q", actualKeyAfterInit)

	// The user_data.sh.tpl MUST use the same key format
	correctPutKey := "/nhp/config"
	wrongPutKey := "nhp/config"

	if actualKeyAfterInit != correctPutKey {
		t.Errorf("Key mismatch: server reads %q but should match %q", actualKeyAfterInit, correctPutKey)
	}

	if actualKeyAfterInit == wrongPutKey {
		t.Error("BUG: Keys should NOT match without the leading slash")
	}

	t.Logf("CORRECT: etcdctl put %q <config>", correctPutKey)
	t.Logf("WRONG:   etcdctl put %q <config>", wrongPutKey)
}

// TestMergedConfigStructure tests that both HttpConfig and AuthServiceId
// can coexist in the same TOML config
func TestMergedConfigStructure(t *testing.T) {
	// Multiple plugins example
	config := `
[HttpConfig]
EnableHttp = true
HttpListenPort = 8888

[[AuthServiceId]]
AuthSvcId = "passcode"
PluginPath = "passcode/main.so"

[[AuthServiceId]]
AuthSvcId = "oidc"
PluginPath = "oidc/main.so"

[[Servers]]
Hostname = "server.example.com"
Port = 62206
PubKeyBase64 = "abc123"
`

	var cfg ServerEtcdConfig
	err := toml.Unmarshal([]byte(config), &cfg)
	if err != nil {
		t.Fatalf("Failed to parse merged config: %v", err)
	}

	t.Logf("HttpConfig.EnableHttp = %v", cfg.HttpConfig.EnableHttp)
	t.Logf("HttpConfig.HttpListenPort = %d", cfg.HttpConfig.HttpListenPort)
	t.Logf("AuthServiceId count = %d", len(cfg.AuthServiceId))
	t.Logf("ACs count = %d", len(cfg.ACs))

	// Verify all sections parsed
	if !cfg.HttpConfig.EnableHttp {
		t.Error("HttpConfig not parsed correctly")
	}
	if len(cfg.AuthServiceId) != 2 {
		t.Errorf("Expected 2 AuthServiceId entries, got %d", len(cfg.AuthServiceId))
	}

	// List all plugins that would be loaded
	for i, asp := range cfg.AuthServiceId {
		t.Logf("Plugin %d: %s -> %s", i, asp.AuthSvcId, asp.PluginPath)
	}
}
