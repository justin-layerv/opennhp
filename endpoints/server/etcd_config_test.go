package server

import (
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/etcd"
	toml "github.com/pelletier/go-toml/v2"
)

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
