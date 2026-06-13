package server

import (
	"encoding/base64"
	"testing"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// testRelayPubKeyBase64 is a valid-length (32-byte curve25519) public key,
// std-base64 encoded, so the tests reflect production input rather than a
// short placeholder.
func testRelayPubKeyBase64() string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// TestUpdateRelayPeers_RegistersRelay verifies the relay.toml load path (#2208):
// a configured relay is registered as an NHP_RELAY device peer (so its NHP_RLY
// can be authenticated), and an empty update removes it via the shared
// updatePeers stale-removal path.
func TestUpdateRelayPeers_RegistersRelay(t *testing.T) {
	testPrivateKey := make([]byte, 32)
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey, nil)
	if device == nil {
		t.Fatal("core.NewDevice returned nil")
	}
	defer device.Stop()

	server := &UdpServer{device: device}

	relayPeer := &core.UdpPeer{
		Ip:           "203.0.113.50",
		Port:         common.DefaultNHPPort,
		PubKeyBase64: testRelayPubKeyBase64(),
		ExpireTime:   common.FarFutureExpiry,
	}
	if err := server.updateRelayPeers([]*core.UdpPeer{relayPeer}); err != nil {
		t.Fatalf("updateRelayPeers failed: %v", err)
	}
	if relayPeer.Type != core.NHP_RELAY {
		t.Errorf("relay peer Type = %d; want NHP_RELAY (%d)", relayPeer.Type, core.NHP_RELAY)
	}
	if len(server.relayPeerMap) != 1 {
		t.Errorf("relayPeerMap len = %d; want 1", len(server.relayPeerMap))
	}

	// Empty update removes the stale peer (the updatePeers removal path).
	if err := server.updateRelayPeers(nil); err != nil {
		t.Fatalf("updateRelayPeers(nil) failed: %v", err)
	}
	if len(server.relayPeerMap) != 0 {
		t.Errorf("relayPeerMap len after empty update = %d; want 0", len(server.relayPeerMap))
	}
}

// TestRelayTomlParsesIntoPeers locks the relay.toml shape: a [[Relays]] table
// unmarshals into Peers.Relays with the expected fields.
func TestRelayTomlParsesIntoPeers(t *testing.T) {
	relayToml := "[[Relays]]\n" +
		"Ip = \"203.0.113.50\"\n" +
		"Port = 62206\n" +
		"PubKeyBase64 = \"" + testRelayPubKeyBase64() + "\"\n" +
		"ExpireTime = 1924991999\n"
	var p Peers
	if err := toml.Unmarshal([]byte(relayToml), &p); err != nil {
		t.Fatalf("parse relay.toml: %v", err)
	}
	if len(p.Relays) != 1 {
		t.Fatalf("Relays len = %d; want 1", len(p.Relays))
	}
	if p.Relays[0].Ip != "203.0.113.50" || p.Relays[0].Port != 62206 {
		t.Errorf("parsed relay = %+v; want Ip=203.0.113.50 Port=62206", p.Relays[0])
	}
}
