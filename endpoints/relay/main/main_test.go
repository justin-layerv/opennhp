package main

import (
	"bytes"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func b64key(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

// freeUDPAddr grabs a currently-free 127.0.0.1 UDP port (tiny TOCTOU window
// before the relay re-binds it, acceptable in a single test process).
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := c.LocalAddr().String()
	_ = c.Close()
	return addr
}

// TestRunApp_ServeError pins the cr-round-1 fix: when Start fails (the HTTP listen
// address is already in use), runApp must (a) return the serve-error wrap and
// (b) still Stop the relay — relay.Start's contract is that the device + UDP
// recvLoop keep running until Stop, even on a serve error. We prove (b) by
// re-binding the relay's UDP port after runApp returns (before the fix it leaked).
func TestRunApp_ServeError(t *testing.T) {
	// Occupy the HTTP listen port so ListenAndServe fails with "address in use".
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = occupied.Close() }()
	httpAddr := occupied.Addr().String()
	udpAddr := freeUDPAddr(t)

	toml := `
listen_addr = "` + httpAddr + `"
udp_listen_addr = "` + udpAddr + `"
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

	if err := runApp(path); err == nil || !strings.Contains(err.Error(), "serve error") {
		t.Fatalf("runApp = %v, want a serve-error wrap", err)
	}

	// Stop ran on the serve-error path: the relay's UDP socket is released, so we
	// can re-bind it. A leak here (the pre-fix behavior) would fail to bind.
	c, err := net.ListenPacket("udp", udpAddr)
	if err != nil {
		t.Fatalf("relay UDP socket %s not released after serve-error — Stop did not run: %v", udpAddr, err)
	}
	_ = c.Close()
}
