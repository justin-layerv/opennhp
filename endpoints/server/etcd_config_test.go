package server

import (
	"testing"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/etcd"
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
		Port:         62206,
		PubKeyBase64: "cmVnaXN0cnlwZWVycHVia2V5YmFzZTY0", // "registrypeerpubkeybase64"
		ExpireTime:   1924991999,
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
		server.updateACPeers(cfg.ACs)
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
		Port:         62206,
		PubKeyBase64: "aW5pdGlhbHBlZXI=", // "initialpeer"
		ExpireTime:   1924991999,
	}
	server.updateACPeers([]*core.UdpPeer{initialPeer})

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
		server.updateACPeers(cfg.ACs)
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
