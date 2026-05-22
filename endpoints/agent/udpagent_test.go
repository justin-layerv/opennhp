package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStart_InitializesPerStartMaps fences the regression class
// fixed by initializing `knockTargetMap` and `serverPeerMap` at
// Start-time: a zero-value UdpAgent leaves both maps nil, and any
// post-Start caller that registers resources or servers via
// AddResource / AddServer (rather than via the resource.toml /
// server.toml config-reload path) trips `assignment to entry in nil
// map` at the first write.
//
// updateResources / updateServerPeers (config.go) both early-return
// on a missing `etc/resource.toml` / `etc/server.toml` and only
// assign the parsed map on success, so callers that don't ship
// those files (e.g. tunnel-client, the motivating consumer) never
// reach the assignment path. The test runs Start against a minimal
// tmp-dir config (no resource.toml, no server.toml) and asserts
// both maps are non-nil post-Start. Doesn't exercise AddResource /
// AddServer calls directly because the regression class is the
// nil-map itself; a non-nil map is the contract every downstream
// write depends on.
func TestStart_InitializesPerStartMaps(t *testing.T) {
	tmp := t.TempDir()
	etcDir := filepath.Join(tmp, "etc")
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatalf("mkdir etc: %v", err)
	}
	// Minimal config.toml: a valid 32-byte X25519 private key, base64-encoded.
	// All-zero bytes is a valid curve25519 scalar — it makes the device
	// derivation succeed (NewDevice runs scalar clamping). The agent's
	// PrivateKeyBase64 parser only validates base64-decodability + length;
	// it doesn't sanity-check the key material.
	configTOML := `PrivateKeyBase64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="` + "\n"
	if err := os.WriteFile(filepath.Join(etcDir, "config.toml"), []byte(configTOML), 0o600); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}

	a := &UdpAgent{}
	if err := a.Start(tmp, 1); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer a.Stop()

	a.knockTargetMapMutex.Lock()
	gotKnockTargets := a.knockTargetMap
	a.knockTargetMapMutex.Unlock()

	if gotKnockTargets == nil {
		t.Fatal("after Start, knockTargetMap is nil — any post-Start AddResource write panics with \"assignment to entry in nil map\"; regression of the init fix in Start (udpagent.go)")
	}

	a.serverPeerMutex.Lock()
	gotServerPeers := a.serverPeerMap
	a.serverPeerMutex.Unlock()

	if gotServerPeers == nil {
		t.Fatal("after Start, serverPeerMap is nil — any post-Start AddServer write panics with \"assignment to entry in nil map\"; symmetric regression of the init fix in Start (udpagent.go)")
	}
}
