package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/server/hub"
)

func mainTestKey(value byte) string {
	data := make([]byte, 32)
	for index := range data {
		data[index] = value
	}
	return base64.StdEncoding.EncodeToString(data)
}

func writeMainTestConfig(t *testing.T, healthListenAddr string) string {
	t.Helper()
	document := `environment = "sandbox"
udp_listen_addr = "127.0.0.1:62206"
health_listen_addr = "` + healthListenAddr + `"
private_key = "` + mainTestKey(1) + `"
active_cookie_key = "` + mainTestKey(2) + `"
previous_cookie_key = ""
aws_region = "us-east-2"
aws_account_id = "123456789012"
issue_assignment_alias_arn = "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-ia:blue"
refresh_assignment_alias_arn = "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-ra:blue"
issue_credential_recovery_alias_arn = "arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-icr:blue"
authority_lambda_timeout = "3s"
handler_budget = "3100ms"
packet_budget = "3500ms"
response_reserve = "400ms"
write_budget = "173ms"
max_concurrent_packets = 4
packets_per_second = 1
packet_burst = 4
max_concurrent_per_peer = 1
response_queue_capacity = 4
`
	path := filepath.Join(t.TempDir(), "hub.toml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHealthcheckUsesConfiguredPortAndLoopbackForWildcard(t *testing.T) {
	path := writeMainTestConfig(t, "0.0.0.0:62419")
	var network, target string
	var deadline time.Time
	peer, connection := net.Pipe()
	defer peer.Close()

	err := healthcheckApp(
		context.Background(),
		path,
		func(ctx context.Context, gotNetwork, gotTarget string) (net.Conn, error) {
			network = gotNetwork
			target = gotTarget
			deadline, _ = ctx.Deadline()
			return connection, nil
		},
	)
	if err != nil {
		t.Fatalf("healthcheckApp: %v", err)
	}
	if network != "tcp" || target != "127.0.0.1:62419" {
		t.Fatalf("dial = %s %s, want tcp 127.0.0.1:62419", network, target)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > healthcheckTimeout {
		t.Fatalf("healthcheck deadline remaining = %v, want within (0, %v]", remaining, healthcheckTimeout)
	}
}

func TestHealthcheckTargetPreservesSpecificAndMapsIPv6Wildcard(t *testing.T) {
	tests := map[string]string{
		"127.0.0.1:62207": "127.0.0.1:62207",
		"10.0.2.17:62207": "10.0.2.17:62207",
		"[::]:62207":      "[::1]:62207",
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			got, err := healthcheckTarget(input)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("healthcheckTarget(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

func TestHealthcheckFailsClosedWithoutLeakingDialError(t *testing.T) {
	path := writeMainTestConfig(t, "127.0.0.1:62207")
	secret := "do-not-return-this-dial-detail"
	err := healthcheckApp(
		context.Background(),
		path,
		func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New(secret)
		},
	)
	if !errors.Is(err, errHealthcheckFailed) {
		t.Fatalf("healthcheckApp error = %v, want errHealthcheckFailed", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("healthcheck exposed dial diagnostics")
	}
}

func TestConsumeMaterializeEnvironmentReadsThenUnsetsEveryInput(t *testing.T) {
	values := map[string]string{
		hub.PublicConfigEnv:      `{"environment":"sandbox"}`,
		hub.PrivateKeyEnv:        "private-key",
		hub.ActiveCookieKeyEnv:   "active-cookie-key",
		hub.PreviousCookieKeyEnv: "previous-cookie-key",
	}
	input, err := consumeMaterializeEnvironment(
		func(name string) (string, bool) {
			value, ok := values[name]
			return value, ok
		},
		func(name string) error {
			delete(values, name)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if input.PublicConfigJSON != `{"environment":"sandbox"}` ||
		input.PrivateKeyBase64 != "private-key" ||
		input.ActiveCookieKeyBase64 != "active-cookie-key" ||
		input.PreviousCookieKeyBase64 != "previous-cookie-key" {
		t.Fatal("consumeMaterializeEnvironment did not preserve the exact init input")
	}
	if len(values) != 0 {
		t.Fatalf("init environment was not fully unset: %v", values)
	}
}

func TestConsumeMaterializeEnvironmentFailsClosedOnUnsetFailure(t *testing.T) {
	secret := "do-not-echo-this-unset-value"
	_, err := consumeMaterializeEnvironment(
		func(string) (string, bool) { return secret, true },
		func(string) error { return errors.New(secret) },
	)
	if !errors.Is(err, hub.ErrConfigMaterialization) {
		t.Fatalf("consumeMaterializeEnvironment error = %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("unset failure exposed secret material")
	}
}

func TestLongLivedCommandsRejectInitOnlyEnvironment(t *testing.T) {
	if err := rejectInitEnvironment(func(string) (string, bool) { return "", false }); err != nil {
		t.Fatalf("rejectInitEnvironment with clean environment: %v", err)
	}
	for _, name := range []string{
		hub.PublicConfigEnv,
		hub.PrivateKeyEnv,
		hub.ActiveCookieKeyEnv,
		hub.PreviousCookieKeyEnv,
	} {
		t.Run(name, func(t *testing.T) {
			err := rejectInitEnvironment(func(candidate string) (string, bool) {
				return "present", candidate == name
			})
			if !errors.Is(err, hub.ErrInvalidConfig) {
				t.Fatalf("rejectInitEnvironment error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}
