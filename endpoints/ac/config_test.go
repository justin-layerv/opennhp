package ac

import (
	"testing"

	toml "github.com/pelletier/go-toml/v2"
)

func TestACEtcdConfig_Parse(t *testing.T) {
	configToml := `
[BaseConfig]
PrivateKeyBase64 = "dGVzdHByaXZhdGVrZXk="
ACId = "test-ac"
DefaultIp = "10.0.0.1"
AuthServiceId = "layerv"
ResourceIds = ["demo", "test"]
LogLevel = 4
DefaultCipherScheme = 0

[HttpConfig]
EnableHttp = true
EnableTLS = false
HttpListenPort = 8888

[[Servers]]
Hostname = "server.example.com"
Ip = ""
Port = 62206
PubKeyBase64 = "c2VydmVycHVia2V5"
ExpireTime = 1924991999
`

	var config ACEtcdConfig
	err := toml.Unmarshal([]byte(configToml), &config)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// Check BaseConfig
	if config.BaseConfig.ACId != "test-ac" {
		t.Errorf("ACId mismatch: got %s", config.BaseConfig.ACId)
	}
	if config.BaseConfig.AuthServiceId != "layerv" {
		t.Errorf("AuthServiceId mismatch: got %s", config.BaseConfig.AuthServiceId)
	}
	if config.BaseConfig.LogLevel != 4 {
		t.Errorf("LogLevel mismatch: got %d", config.BaseConfig.LogLevel)
	}

	// Check HttpConfig
	if !config.HttpConfig.EnableHttp {
		t.Error("EnableHttp should be true")
	}
	if config.HttpConfig.HttpListenPort != 8888 {
		t.Errorf("HttpListenPort mismatch: got %d", config.HttpConfig.HttpListenPort)
	}

	// Check Servers
	if len(config.Servers) != 1 {
		t.Fatalf("Expected 1 server, got %d", len(config.Servers))
	}
	if config.Servers[0].Hostname != "server.example.com" {
		t.Errorf("Server hostname mismatch: got %s", config.Servers[0].Hostname)
	}
}

func TestACEtcdConfig_NoPrivateKey(t *testing.T) {
	// Test config without private key (as seeded by Terraform)
	configToml := `
[HttpConfig]
EnableHttp = true
EnableTLS = false
HttpListenPort = 8888

[[Servers]]
Hostname = "nlb.example.com"
Ip = ""
Port = 62206
PubKeyBase64 = "c2VydmVycHVia2V5"
ExpireTime = 1924991999
`

	var config ACEtcdConfig
	err := toml.Unmarshal([]byte(configToml), &config)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// BaseConfig should have zero values
	if config.BaseConfig.PrivateKeyBase64 != "" {
		t.Errorf("PrivateKeyBase64 should be empty, got %s", config.BaseConfig.PrivateKeyBase64)
	}
	if config.BaseConfig.ACId != "" {
		t.Errorf("ACId should be empty, got %s", config.BaseConfig.ACId)
	}

	// But HttpConfig and Servers should be populated
	if !config.HttpConfig.EnableHttp {
		t.Error("EnableHttp should be true")
	}
	if len(config.Servers) != 1 {
		t.Fatalf("Expected 1 server, got %d", len(config.Servers))
	}
}

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

func TestRemoteConfig_TLS(t *testing.T) {
	configToml := `
Provider = "etcd"
Key = "nhp/config"
Endpoints = ["https://etcd.example.com:2379"]
TLS = true
CACert = "/opt/layerv/nhp-ac/etc/tls/ca.crt"
ClientCert = "/opt/layerv/nhp-ac/etc/tls/client.crt"
ClientKey = "/opt/layerv/nhp-ac/etc/tls/client.key"
`

	var config RemoteConfig
	err := toml.Unmarshal([]byte(configToml), &config)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	if config.Provider != "etcd" {
		t.Errorf("Provider mismatch: got %s", config.Provider)
	}
	if !config.TLS {
		t.Error("TLS should be enabled")
	}
	if config.CACert == "" {
		t.Error("CACert should not be empty")
	}
	if config.ClientCert == "" {
		t.Error("ClientCert should not be empty")
	}
	if config.ClientKey == "" {
		t.Error("ClientKey should not be empty")
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
