package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func b64key(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

// TestLoadConfig covers the daemon's config seam: a relay.toml round-trips into a
// Config with the fork's snake_case keys + the [[servers]] table decoded.
func TestLoadConfig(t *testing.T) {
	toml := `
listen_addr = "0.0.0.0:8080"
udp_listen_addr = "0.0.0.0:62207"
private_key = "` + b64key(0x80) + `"
source_addr_mode = "trusted_header"
trusted_header = "X-Real-IP"
enable_tls = true
tls_cert_file = "/c.pem"
tls_key_file = "/k.pem"
trusted_proxy = true

[[servers]]
name = "cell0"
public_key = "` + b64key(0x40) + `"
host = "server.internal"
port = 62206
`
	path := filepath.Join(t.TempDir(), "relay.toml")
	if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ListenAddr != "0.0.0.0:8080" || cfg.UDPListenAddr != "0.0.0.0:62207" {
		t.Errorf("listen addrs decoded wrong: %q / %q", cfg.ListenAddr, cfg.UDPListenAddr)
	}
	if cfg.SourceAddrMode != SourceAddrModeTrustedHeader || cfg.TrustedHeader != "X-Real-IP" {
		t.Errorf("source-addr fields decoded wrong: %q / %q", cfg.SourceAddrMode, cfg.TrustedHeader)
	}
	if !cfg.EnableTLS || cfg.TLSCertFile != "/c.pem" || cfg.TLSKeyFile != "/k.pem" {
		t.Errorf("tls fields decoded wrong: %v / %q / %q", cfg.EnableTLS, cfg.TLSCertFile, cfg.TLSKeyFile)
	}
	if !cfg.TrustedProxy {
		t.Error("trusted_proxy decoded false, want true")
	}
	if len(cfg.Servers) != 1 {
		t.Fatalf("want 1 server, got %d", len(cfg.Servers))
	}
	s := cfg.Servers[0]
	if s.Name != "cell0" || s.Host != "server.internal" || s.Port != 62206 || s.PubKeyBase64 != b64key(0x40) {
		t.Errorf("server decoded wrong: %+v", s)
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.toml")); err == nil {
		t.Fatal("want error for missing config file, got nil")
	}
}

// A typo'd key (e.g. udp_listen_adr) must fail loud under strict decode, not be
// silently dropped into a wrong/ephemeral bind the server then rejects.
func TestLoadConfig_StrictRejectsUnknownKey(t *testing.T) {
	toml := "listen_addr = \"0.0.0.0:8080\"\nudp_listen_adr = \"0.0.0.0:62207\"\n"
	path := filepath.Join(t.TempDir(), "relay.toml")
	if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("want error for unknown key (udp_listen_adr typo), got nil")
	}
}

func TestLoadConfig_RejectsRemovedNativeIngressKeys(t *testing.T) {
	for _, key := range []string{"native_listen_addr", "native_server"} {
		t.Run(key, func(t *testing.T) {
			toml := "listen_addr = \"0.0.0.0:8080\"\n" + key + " = \"removed\"\n"
			path := filepath.Join(t.TempDir(), "relay.toml")
			if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatalf("want error for removed %s key, got nil", key)
			}
		})
	}
}

// TestHandleHealthLive: GET -> 200 "ok"; any other method -> 405. The probe is
// process-up only and needs no server/peer state, so a zero-value RelayServer
// suffices.
func TestHandleHealthLive(t *testing.T) {
	rs := &RelayServer{}

	rec := httptest.NewRecorder()
	rs.handleHealthLive(rec, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Errorf("GET /health/live = %d %q, want 200 \"ok\"", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	rs.handleHealthLive(rec, httptest.NewRequest(http.MethodPost, "/health/live", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /health/live = %d, want 405", rec.Code)
	}
}

// freeTCPAddr grabs a currently-free 127.0.0.1 port. There is a tiny TOCTOU
// window before the caller re-binds it, acceptable in a single test process.
func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestBoot exercises the daemon wiring end to end — LoadConfig -> New -> Start ->
// Stop — the path nhp-relayd/main runs. The RelayServer body is covered by
// relay_test.go; this proves the config decode + lifecycle hold together.
func TestBoot(t *testing.T) {
	listenAddr := freeTCPAddr(t)
	toml := `
listen_addr = "` + listenAddr + `"
udp_listen_addr = "127.0.0.1:0"
private_key = "` + b64key(0x80) + `"

[[servers]]
name = "cell0"
public_key = "` + b64key(0x40) + `"
host = "127.0.0.1"
port = 62206
`
	path := filepath.Join(t.TempDir(), "relay.toml")
	if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	rs, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- rs.Start() }()

	// Poll until the listener is actually serving (readiness) instead of a fixed
	// sleep that flakes under CI load: Shutdown racing an unbound listener can let
	// Start return before it ever served.
	url := "http://" + listenAddr + "/health/live"
	for deadline := time.Now().Add(3 * time.Second); ; {
		resp, err := http.Get(url) //nolint:noctx // test-local readiness poll
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("relay did not become healthy")
		}
		time.Sleep(10 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rs.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Start returned %v, want nil (clean shutdown)", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}
