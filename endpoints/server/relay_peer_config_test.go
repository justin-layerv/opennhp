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
	return testRelayPubKeyBase64From(1)
}

func testRelayPubKeyBase64From(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i) + seed
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

// TestRelayIdentityRotationOverlap locks the zero-outage trust transition:
// relay.toml accepts two identities at once, both reach the same authenticated
// peer lookup used by the Noise dispatch path, and a subsequent new-only update
// removes the retired identity from both server and device maps.
func TestRelayIdentityRotationOverlap(t *testing.T) {
	oldKey := testRelayPubKeyBase64From(1)
	newKey := testRelayPubKeyBase64From(101)
	relayToml := "[[Relays]]\n" +
		"Ip = \"203.0.113.50\"\n" +
		"Port = 62206\n" +
		"PubKeyBase64 = \"" + oldKey + "\"\n" +
		"ExpireTime = 1924991999\n\n" +
		"[[Relays]]\n" +
		"Ip = \"203.0.113.50\"\n" +
		"Port = 62206\n" +
		"PubKeyBase64 = \"" + newKey + "\"\n" +
		"ExpireTime = 1924991999\n"

	var peers Peers
	if err := toml.Unmarshal([]byte(relayToml), &peers); err != nil {
		t.Fatalf("parse overlap relay.toml: %v", err)
	}
	if len(peers.Relays) != 2 {
		t.Fatalf("overlap Relays len = %d; want 2", len(peers.Relays))
	}

	privateKey := make([]byte, 32)
	for i := range privateKey {
		privateKey[i] = byte(i + 11)
	}
	device := core.NewDevice(core.NHP_SERVER, privateKey, nil)
	if device == nil {
		t.Fatal("core.NewDevice returned nil")
	}
	defer device.Stop()
	server := &UdpServer{device: device}

	if err := server.updateRelayPeers(peers.Relays); err != nil {
		t.Fatalf("register overlap peers: %v", err)
	}
	for _, trusted := range []string{oldKey, newKey} {
		raw, err := base64.StdEncoding.DecodeString(trusted)
		if err != nil {
			t.Fatalf("decode trusted key: %v", err)
		}
		if server.lookupRelayPeer(trusted) == nil {
			t.Errorf("relay authorization map rejected trusted key %q", trusted)
		}
		if device.LookupPeer(raw) == nil {
			t.Errorf("Noise device lookup rejected trusted key %q", trusted)
		}
	}

	if err := server.updateRelayPeers(peers.Relays[1:]); err != nil {
		t.Fatalf("retire old relay identity: %v", err)
	}
	oldRaw, _ := base64.StdEncoding.DecodeString(oldKey)
	newRaw, _ := base64.StdEncoding.DecodeString(newKey)
	if server.lookupRelayPeer(oldKey) != nil || device.LookupPeer(oldRaw) != nil {
		t.Error("retired relay identity remains accepted after new-only update")
	}
	if server.lookupRelayPeer(newKey) == nil || device.LookupPeer(newRaw) == nil {
		t.Error("new relay identity was removed during old-key retirement")
	}
}
