package hub

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytesOf(value, 32))
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = value
	}
	return result
}

func validConfig() Config {
	return Config{
		Environment:                     "sandbox",
		UDPListenAddr:                   "127.0.0.1:62206",
		HealthListenAddr:                "127.0.0.1:62207",
		PrivateKeyBase64:                testKey(1),
		ActiveCookieKeyBase64:           testKey(2),
		AWSRegion:                       "us-east-2",
		AWSAccountID:                    "123456789012",
		IssueAssignmentAliasARN:         "arn:aws:lambda:us-east-2:123456789012:function:issue-assignment:active",
		RefreshAssignmentAliasARN:       "arn:aws:lambda:us-east-2:123456789012:function:refresh-assignment:active",
		IssueCredentialRecoveryAliasARN: "arn:aws:lambda:us-east-2:123456789012:function:issue-credential-recovery:active",
		MaxConcurrentPackets:            4,
		PacketsPerSecond:                1,
		PacketBurst:                     4,
		MaxConcurrentPerPeer:            1,
		ResponseQueueCapacity:           4,
	}
}

func TestLoadConfigStrictRoundTrip(t *testing.T) {
	config := validConfig()
	contents := `environment = "sandbox"
udp_listen_addr = "127.0.0.1:62206"
health_listen_addr = "127.0.0.1:62207"
private_key = "` + config.PrivateKeyBase64 + `"
active_cookie_key = "` + config.ActiveCookieKeyBase64 + `"
previous_cookie_key = "` + testKey(3) + `"
aws_region = "us-east-2"
aws_account_id = "123456789012"
issue_assignment_alias_arn = "arn:aws:lambda:us-east-2:123456789012:function:issue-assignment:active"
refresh_assignment_alias_arn = "arn:aws:lambda:us-east-2:123456789012:function:refresh-assignment:active"
issue_credential_recovery_alias_arn = "arn:aws:lambda:us-east-2:123456789012:function:issue-credential-recovery:active"
max_concurrent_packets = 4
packets_per_second = 1
packet_burst = 4
max_concurrent_per_peer = 1
response_queue_capacity = 4
`
	path := filepath.Join(t.TempDir(), "hub.toml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got != (Config{
		Environment: config.Environment, UDPListenAddr: config.UDPListenAddr,
		HealthListenAddr: config.HealthListenAddr, PrivateKeyBase64: config.PrivateKeyBase64,
		ActiveCookieKeyBase64: config.ActiveCookieKeyBase64, PreviousCookieKeyBase64: testKey(3),
		AWSRegion: config.AWSRegion, AWSAccountID: config.AWSAccountID,
		IssueAssignmentAliasARN:         config.IssueAssignmentAliasARN,
		RefreshAssignmentAliasARN:       config.RefreshAssignmentAliasARN,
		IssueCredentialRecoveryAliasARN: config.IssueCredentialRecoveryAliasARN,
		MaxConcurrentPackets:            config.MaxConcurrentPackets, PacketsPerSecond: config.PacketsPerSecond,
		PacketBurst: config.PacketBurst, MaxConcurrentPerPeer: config.MaxConcurrentPerPeer,
		ResponseQueueCapacity: config.ResponseQueueCapacity,
	}) {
		t.Fatal("loaded configuration does not match the strict input")
	}
}

func TestLoadConfigRejectsUnknownFieldWithoutEchoingSecret(t *testing.T) {
	secret := "do-not-log-this-private-value"
	path := filepath.Join(t.TempDir(), "hub.toml")
	if err := os.WriteFile(path, []byte("private_key_typo = \""+secret+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("LoadConfig accepted an unknown key")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("LoadConfig error exposed a secret-bearing value")
	}
}

func TestLoadConfigRejectsOversizedDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.toml")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxConfigBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("LoadConfig error = %v, want ErrInvalidConfig", err)
	}
}

func TestShippedConfigFailsClosedUntilProvisioned(t *testing.T) {
	// Read the committed source placeholder, which `make hubd` copies verbatim
	// into release/nhp-hub/etc/. Asserting against the source keeps the test
	// hermetic: release/ is a gitignored build artifact absent on a clean
	// `go test ./...` (the required CI Test job builds no binaries).
	path := filepath.Join("main", "etc", "hub.toml")
	if _, err := LoadConfig(path); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("LoadConfig(shipped placeholder) error = %v, want ErrInvalidConfig", err)
	}
}

func TestConfigRejectsHostnameAndWhitespace(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"udp hostname":       func(c *Config) { c.UDPListenAddr = "hub.internal:62206" },
		"health hostname":    func(c *Config) { c.HealthListenAddr = "hub.internal:62207" },
		"zero UDP port":      func(c *Config) { c.UDPListenAddr = "127.0.0.1:0" },
		"spaced environment": func(c *Config) { c.Environment = " sandbox" },
		"spaced key":         func(c *Config) { c.PrivateKeyBase64 += " " },
		"short key":          func(c *Config) { c.ActiveCookieKeyBase64 = testKey(2)[:40] },
		"zero key":           func(c *Config) { c.ActiveCookieKeyBase64 = testKey(0) },
		"bad account":        func(c *Config) { c.AWSAccountID = "1234" },
		"wrong alias region": func(c *Config) {
			c.IssueAssignmentAliasARN = "arn:aws:lambda:us-west-2:123456789012:function:issue-assignment:active"
		},
		"unqualified alias": func(c *Config) {
			c.RefreshAssignmentAliasARN = "arn:aws:lambda:us-east-2:123456789012:function:refresh-assignment"
		},
		"duplicate alias": func(c *Config) { c.RefreshAssignmentAliasARN = c.IssueAssignmentAliasARN },
		// The recovery alias is the third :active target wired by this composition;
		// it must fail closed on the same contract as the other two.
		"empty recovery alias": func(c *Config) { c.IssueCredentialRecoveryAliasARN = "" },
		"unqualified recovery alias": func(c *Config) {
			c.IssueCredentialRecoveryAliasARN = "arn:aws:lambda:us-east-2:123456789012:function:issue-credential-recovery"
		},
		"duplicate recovery alias": func(c *Config) { c.IssueCredentialRecoveryAliasARN = c.IssueAssignmentAliasARN },
	} {
		t.Run(name, func(t *testing.T) {
			config := validConfig()
			mutate(&config)
			if _, _, err := config.validate(); err == nil {
				t.Fatal("configuration unexpectedly passed validation")
			}
		})
	}
}
