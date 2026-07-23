package hub

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorhub"
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
		PreviousCookieKeyBase64:         testKey(3),
		AWSRegion:                       "us-east-2",
		AWSAccountID:                    "123456789012",
		IssueAssignmentAliasARN:         "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-ia:blue",
		RefreshAssignmentAliasARN:       "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-ra:blue",
		IssueCredentialRecoveryAliasARN: "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-icr:blue",
		AuthorityLambdaTimeout:          "3s",
		HandlerBudget:                   "3100ms",
		PacketBudget:                    "3500ms",
		ResponseReserve:                 "400ms",
		WriteBudget:                     "173ms",
		MaxConcurrentPackets:            4,
		PacketsPerSecond:                1,
		PacketBurst:                     4,
		MaxConcurrentPerPeer:            1,
		ResponseQueueCapacity:           4,
	}
}

func validConfigTOML(config Config) string {
	return `environment = "sandbox"
udp_listen_addr = "127.0.0.1:62206"
health_listen_addr = "127.0.0.1:62207"
private_key = "` + config.PrivateKeyBase64 + `"
active_cookie_key = "` + config.ActiveCookieKeyBase64 + `"
previous_cookie_key = "` + config.PreviousCookieKeyBase64 + `"
aws_region = "us-east-2"
aws_account_id = "123456789012"
issue_assignment_alias_arn = "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-ia:blue"
refresh_assignment_alias_arn = "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-ra:blue"
issue_credential_recovery_alias_arn = "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-icr:blue"
authority_lambda_timeout = "` + config.AuthorityLambdaTimeout + `"
handler_budget = "` + config.HandlerBudget + `"
packet_budget = "` + config.PacketBudget + `"
response_reserve = "` + config.ResponseReserve + `"
write_budget = "` + config.WriteBudget + `"
max_concurrent_packets = 4
packets_per_second = 1
packet_burst = 4
max_concurrent_per_peer = 1
response_queue_capacity = 4
`
}

func TestLoadConfigStrictRoundTrip(t *testing.T) {
	config := validConfig()
	contents := validConfigTOML(config)
	path := filepath.Join(t.TempDir(), "hub.toml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got != config {
		t.Fatal("loaded configuration does not match the strict input")
	}
}

func TestLoadConfigRequiresEveryTimingField(t *testing.T) {
	contents := validConfigTOML(validConfig())
	for _, field := range []string{
		"authority_lambda_timeout",
		"handler_budget",
		"packet_budget",
		"response_reserve",
		"write_budget",
	} {
		t.Run(field, func(t *testing.T) {
			needle := "\n" + field + " = "
			start := strings.Index(contents, needle)
			if start < 0 {
				t.Fatalf("valid fixture is missing %s", field)
			}
			start++
			end := strings.Index(contents[start:], "\n")
			if end < 0 {
				t.Fatalf("valid fixture field %s has no line ending", field)
			}
			withoutField := contents[:start] + contents[start+end+1:]
			path := filepath.Join(t.TempDir(), "hub.toml")
			if err := os.WriteFile(path, []byte(withoutField), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("LoadConfig without %s error = %v, want ErrInvalidConfig", field, err)
			}
		})
	}
}

func TestConfigWorkerTimingMapsEveryFieldExactly(t *testing.T) {
	config := validConfig()
	config.AuthorityLambdaTimeout = "4s"
	config.HandlerBudget = "4123ms"
	config.PacketBudget = "4987ms"
	config.ResponseReserve = "864ms"
	config.WriteBudget = "137ms"

	got, err := config.workerTiming()
	if err != nil {
		t.Fatalf("workerTiming: %v", err)
	}
	want := connectorhub.WorkerTiming{
		AuthorityLambdaTimeout: 4 * time.Second,
		HandlerBudget:          4123 * time.Millisecond,
		PacketBudget:           4987 * time.Millisecond,
		ResponseReserve:        864 * time.Millisecond,
		WriteBudget:            137 * time.Millisecond,
	}
	if got != want {
		t.Fatalf("workerTiming = %#v, want %#v", got, want)
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

func TestLoadConfigRejectsInvalidTimingWithoutEchoingValue(t *testing.T) {
	secret := "do-not-log-this-timing-value"
	contents := strings.Replace(
		validConfigTOML(validConfig()),
		`handler_budget = "3100ms"`,
		`handler_budget = "`+secret+`"`,
		1,
	)
	path := filepath.Join(t.TempDir(), "hub.toml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("LoadConfig error = %v, want ErrInvalidConfig", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("LoadConfig error exposed an invalid timing value")
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
			c.IssueAssignmentAliasARN = "arn:aws:lambda:us-west-2:123456789012:function:layerv-nhp-sandbox-ca-ia:blue"
		},
		"unqualified alias": func(c *Config) {
			c.RefreshAssignmentAliasARN = "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-ra"
		},
		"legacy active alias": func(c *Config) {
			c.RefreshAssignmentAliasARN = "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-ra:active"
		},
		"wrong operation alias": func(c *Config) {
			c.RefreshAssignmentAliasARN = "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-ia:blue"
		},
		"duplicate alias": func(c *Config) { c.RefreshAssignmentAliasARN = c.IssueAssignmentAliasARN },
		"mixed alias color": func(c *Config) {
			c.RefreshAssignmentAliasARN = "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-ra:green"
		},
		// The recovery alias is the third operation-specific target wired by
		// this composition; it must fail closed on the same graph as the other two.
		"empty recovery alias": func(c *Config) { c.IssueCredentialRecoveryAliasARN = "" },
		"unqualified recovery alias": func(c *Config) {
			c.IssueCredentialRecoveryAliasARN = "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-icr"
		},
		"duplicate recovery alias":  func(c *Config) { c.IssueCredentialRecoveryAliasARN = c.IssueAssignmentAliasARN },
		"empty lambda timeout":      func(c *Config) { c.AuthorityLambdaTimeout = "" },
		"spaced handler budget":     func(c *Config) { c.HandlerBudget = " 3100ms" },
		"invalid packet budget":     func(c *Config) { c.PacketBudget = "3500" },
		"zero response reserve":     func(c *Config) { c.ResponseReserve = "0s" },
		"negative write budget":     func(c *Config) { c.WriteBudget = "-1ms" },
		"fractional lambda timeout": func(c *Config) { c.AuthorityLambdaTimeout = "3001ms" },
		"lambda below floor":        func(c *Config) { c.AuthorityLambdaTimeout = "2s" },
		"lambda reaches handler":    func(c *Config) { c.AuthorityLambdaTimeout = c.HandlerBudget },
		"handler reaches packet":    func(c *Config) { c.HandlerBudget = c.PacketBudget },
		"reserve exceeds tail":      func(c *Config) { c.ResponseReserve = "401ms" },
		"write exceeds reserve":     func(c *Config) { c.WriteBudget = "401ms" },
		"packet reaches ceiling":    func(c *Config) { c.PacketBudget = "30s" },
	} {
		t.Run(name, func(t *testing.T) {
			config := validConfig()
			mutate(&config)
			if _, _, _, err := config.validate(); err == nil {
				t.Fatal("configuration unexpectedly passed validation")
			}
		})
	}
}
