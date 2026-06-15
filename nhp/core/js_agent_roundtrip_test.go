package core

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

// TestJsAgentKnockRoundTrip is the cross-language fence for the browser js-agent
// (#2208). It decrypts a knock packet produced by the TypeScript handshake
// (endpoints/js-agent/src/crypto/handshake.ts) and asserts the Go responder
// recovers the initiator static key, the send timestamp, and the body the TS
// side sealed — i.e. the browser and the server agree on the wire format
// end-to-end. The fixture is committed under
// endpoints/js-agent/test/testdata/knock.json and is also pinned from the TS
// side (handshake.test.ts asserts buildKnock(...) reproduces packetHex), so a
// drift on either side fails its own suite.
func TestJsAgentKnockRoundTrip(t *testing.T) {
	const fixturePath = "../../endpoints/js-agent/test/testdata/knock.json"
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		if os.IsNotExist(err) {
			// Degrade gracefully when nhp/ is tested without the sibling js-agent
			// tree present, rather than hard-failing the core suite.
			t.Skipf("fixture %s not present (run from the full repo tree): %v", fixturePath, err)
		}
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}
	var fx struct {
		ServerStaticPrivHex string `json:"serverStaticPrivHex"`
		ServerStaticPubHex  string `json:"serverStaticPubHex"`
		DeviceStaticPubHex  string `json:"deviceStaticPubHex"`
		TimestampNanos      string `json:"timestampNanos"`
		BodyHex             string `json:"bodyHex"`
		PacketHex           string `json:"packetHex"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	mustHex := func(name, s string) []byte {
		b, herr := hex.DecodeString(s)
		if herr != nil {
			t.Fatalf("decode %s hex: %v", name, herr)
		}
		return b
	}
	serverPriv := mustHex("serverStaticPriv", fx.ServerStaticPrivHex)
	deviceStaticPub := mustHex("deviceStaticPub", fx.DeviceStaticPubHex)
	wantBody := mustHex("body", fx.BodyHex)
	packet := mustHex("packet", fx.PacketHex)
	wantTs, err := strconv.ParseInt(fx.TimestampNanos, 10, 64)
	if err != nil {
		t.Fatalf("parse timestampNanos: %v", err)
	}

	// Responder (server) device keyed with the static key the TS knock targeted.
	serverDevice := NewDevice(NHP_SERVER, serverPriv, nil)
	if serverDevice == nil {
		t.Fatal("failed to create server device")
	}
	if got, want := serverDevice.PublicKeyBase64(), base64.StdEncoding.EncodeToString(mustHex("serverStaticPub", fx.ServerStaticPubHex)); got != want {
		t.Fatalf("server pubkey mismatch: device=%s fixture=%s", got, want)
	}

	// Register the initiator (agent) peer so validatePeer's lookup succeeds; its
	// address must match the connection's RemoteAddr (CheckRecvAddress).
	serverDevice.AddPeer(&UdpPeer{
		PubKeyBase64: base64.StdEncoding.EncodeToString(deviceStaticPub),
		Ip:           "127.0.0.1",
		Port:         12345,
		Type:         NHP_AGENT,
	})

	var serverBuf PacketBuffer
	copy(serverBuf[:], packet)
	serverPkt := &Packet{
		Buf:        &serverBuf,
		Content:    serverBuf[:len(packet)],
		HeaderType: NHP_KNK,
	}

	// Standard server-side decrypt connection (LocalPort 12346, RemotePort 12345
	// matching the registered agent peer). Its InitTime is irrelevant — the
	// staleness gate reads LocalInitTime from PacketData.InitTime, set to wantTs.
	connData := validatePeerConnectionData(serverDevice, 12346, 12345)

	// Drive the responder stages directly (rather than PacketToMsg, which stamps
	// LocalInitTime = now) so InitTime == the packet's fixed send time and the
	// staleness gate accepts the committed fixture no matter when this runs. The
	// staged calls also localize a wire mismatch: createPacketParserData fails on
	// a bad header digest, validatePeer on the static/timestamp AEAD, decryptBody
	// on the body AEAD.
	ppd, err := serverDevice.createPacketParserData(&PacketData{
		BasePacket: serverPkt,
		ConnData:   connData,
		InitTime:   wantTs,
	})
	if err != nil {
		t.Fatalf("createPacketParserData (header digest): %v", err)
	}
	if err := ppd.validatePeer(); err != nil {
		t.Fatalf("validatePeer (static/timestamp decrypt): %v", err)
	}
	if err := ppd.decryptBody(); err != nil {
		t.Fatalf("decryptBody: %v", err)
	}

	if !bytes.Equal(ppd.RemotePubKey, deviceStaticPub) {
		t.Errorf("recovered initiator pubkey mismatch\n got:  %x\n want: %x", ppd.RemotePubKey, deviceStaticPub)
	}
	if ppd.RemoteSendTime != wantTs {
		t.Errorf("recovered send timestamp = %d, want %d", ppd.RemoteSendTime, wantTs)
	}
	if !bytes.Equal(ppd.BodyMessage, wantBody) {
		t.Errorf("recovered body mismatch\n got:  %q\n want: %q", ppd.BodyMessage, wantBody)
	}
}
