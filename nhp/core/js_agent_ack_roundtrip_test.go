package core

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// Cross-language fence for the browser js-agent ACK decrypt (#2208 PR-4). The
// server seals a ServerKnockAckMsg to the agent (NHP_ACK); the TS side
// (endpoints/js-agent/src/crypto/ack.ts decryptReply) must recover it. The fixture
// at endpoints/js-agent/test/testdata/ack.json is decrypted by BOTH this Go test
// and the TS test, both asserting the same ServerKnockAckMsg — so a drift on
// either side reddens its own suite. Unlike the knock (PR-3), the ACK's
// ephemeral is the server's (random), so the fixture is a frozen Go-generated
// value rather than something TS can reproduce.

const ackFixturePath = "../../endpoints/js-agent/test/testdata/ack.json"

type ackFixture struct {
	ServerStaticPubHex string `json:"serverStaticPubHex"`
	AgentStaticPrivHex string `json:"agentStaticPrivHex"`
	TimestampNanos     string `json:"timestampNanos"`
	BodyHex            string `json:"bodyHex"`
	AckPacketHex       string `json:"ackPacketHex"`
}

// sampleAckMsg is the representative ServerKnockAckMsg the fixture exercises —
// success + open time + a resource host + an AC token, so the TS side decodes a
// realistic JSON shape, not an empty struct.
func sampleAckMsg() *common.ServerKnockAckMsg {
	return &common.ServerKnockAckMsg{
		ErrCode:      common.ErrSuccess.ErrorCode(),
		OpenTime:     900,
		ResourceHost: map[string]string{"r_jsagent": "10.0.0.7"},
		ACTokens:     map[string]string{"r_jsagent": "tok-abc123"},
		AgentAddr:    "203.0.113.9",
	}
}

// TestJsAgentAckGenerateFixture (re)builds the committed ACK fixture. Skipped
// unless UPDATE_JS_AGENT_FIXTURES=1 — the server ephemeral is random so each run
// differs; the committed fixture is the frozen value both decoders agree on.
// This is also the regen tooling carried forward from PR-3.
func TestJsAgentAckGenerateFixture(t *testing.T) {
	if os.Getenv("UPDATE_JS_AGENT_FIXTURES") == "" {
		t.Skip("set UPDATE_JS_AGENT_FIXTURES=1 to regenerate the ACK fixture")
	}

	serverPriv := validatePeerPrivateKey(0x01)
	agentPriv := validatePeerPrivateKey(0x41)
	serverDev := NewDevice(NHP_SERVER, serverPriv, nil)
	agentDev := NewDevice(NHP_AGENT, agentPriv, nil)
	serverPub, _ := base64.StdEncoding.DecodeString(serverDev.PublicKeyBase64())
	agentPub, _ := base64.StdEncoding.DecodeString(agentDev.PublicKeyBase64())

	ackBytes, err := json.Marshal(sampleAckMsg())
	if err != nil {
		t.Fatalf("marshal ack: %v", err)
	}

	// Server seals the ACK to the agent, compressed (makeMsgData sets Compress).
	mad, err := serverDev.MsgToPacket(&MsgData{
		ConnData:      validatePeerConnectionData(serverDev, 62206, 40000),
		PeerPk:        agentPub,
		HeaderType:    NHP_ACK,
		TransactionId: 0x1122334455667788,
		Compress:      true,
		Message:       ackBytes,
	})
	if err != nil {
		t.Fatalf("MsgToPacket(ACK): %v", err)
	}
	packet := bytes.Clone(mad.BasePacket.Content)
	tsNanos := mad.LocalInitTime
	mad.Destroy()

	out, err := json.MarshalIndent(ackFixture{
		ServerStaticPubHex: hex.EncodeToString(serverPub),
		AgentStaticPrivHex: hex.EncodeToString(agentPriv),
		TimestampNanos:     strconv.FormatInt(tsNanos, 10),
		BodyHex:            hex.EncodeToString(ackBytes),
		AckPacketHex:       hex.EncodeToString(packet),
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(ackFixturePath, append(out, '\n'), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote %s (%d-byte ACK)", ackFixturePath, len(packet))
}

// TestJsAgentAckRoundTrip decrypts the committed ACK fixture with the real
// responder path and recovers the ServerKnockAckMsg — the Go half of the fence.
func TestJsAgentAckRoundTrip(t *testing.T) {
	raw, err := os.ReadFile(ackFixturePath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("fixture %s not present (run from the full repo tree): %v", ackFixturePath, err)
		}
		t.Fatalf("read fixture %s: %v", ackFixturePath, err)
	}
	var fx ackFixture
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
	agentPriv := mustHex("agentStaticPriv", fx.AgentStaticPrivHex)
	serverPub := mustHex("serverStaticPub", fx.ServerStaticPubHex)
	wantBody := mustHex("body", fx.BodyHex)
	packet := mustHex("ackPacket", fx.AckPacketHex)
	wantTs, err := strconv.ParseInt(fx.TimestampNanos, 10, 64)
	if err != nil {
		t.Fatalf("parse timestampNanos: %v", err)
	}

	agentDev := NewDevice(NHP_AGENT, agentPriv, nil)
	// NHP_ACK's sender is NHP_SERVER, so the agent validates the server peer.
	agentDev.AddPeer(&UdpPeer{
		PubKeyBase64: base64.StdEncoding.EncodeToString(serverPub),
		Ip:           "127.0.0.1",
		Port:         62206,
		Type:         NHP_SERVER,
	})

	var buf PacketBuffer
	copy(buf[:], packet)
	pkt := &Packet{Buf: &buf, Content: buf[:len(packet)], HeaderType: NHP_ACK}

	// Drive the stages directly with InitTime = the ACK's fixed send time so the
	// staleness gate accepts the frozen fixture (same approach as the knock test).
	ppd, err := agentDev.createPacketParserData(&PacketData{
		BasePacket: pkt,
		ConnData:   validatePeerConnectionData(agentDev, 40000, 62206),
		InitTime:   wantTs,
	})
	if err != nil {
		t.Fatalf("createPacketParserData (header digest): %v", err)
	}
	if err := ppd.validatePeer(); err != nil {
		t.Fatalf("validatePeer (static/timestamp decrypt): %v", err)
	}
	if err := ppd.decryptBody(); err != nil {
		t.Fatalf("decryptBody (inflate): %v", err)
	}

	if !bytes.Equal(ppd.RemotePubKey, serverPub) {
		t.Errorf("recovered server pubkey mismatch\n got:  %x\n want: %x", ppd.RemotePubKey, serverPub)
	}
	if ppd.RemoteSendTime != wantTs {
		t.Errorf("recovered send timestamp = %d, want %d", ppd.RemoteSendTime, wantTs)
	}
	if !bytes.Equal(ppd.BodyMessage, wantBody) {
		t.Errorf("recovered ACK body mismatch\n got:  %q\n want: %q", ppd.BodyMessage, wantBody)
	}
}
