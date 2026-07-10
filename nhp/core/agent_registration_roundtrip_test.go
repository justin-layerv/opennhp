package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// Cross-language fence for the NHP agent-registration golden vectors (C1). It
// decrypts the OTP/REG/RAK golden packets — pinned in the public
// qurl-conformance repo as agent_registration_golden.json and re-hosted here
// under testdata/ (the js-agent knock.json precedent) — with the real Go
// responder path, and asserts the server recovers the initiator static key, the
// send timestamp, the header type, and the sealed registration body. This is the
// INDEPENDENT reference decrypt: the deterministic OTP/REG packet_hex is produced
// by a type-parameterized NHP initiator, and THIS test (a different codebase)
// proving it opens is the fence — so a drift on either side reddens its own suite.
// The frozen RAK reply (sealed by the Go server with a random ephemeral) is
// decrypted with the agent's static key.
//
// Keep testdata/agent_registration_golden.json byte-identical to the
// qurl-conformance vectors/agent_registration_golden.json it mirrors. The SHA pin
// below catches a LOCAL drift — an accidental edit, or a partial re-sync that
// touches the JSON without the constant (or vice versa) — reddening this fence
// rather than passing against locally-inconsistent bytes. It does NOT detect a
// silent upstream change to the canonical artifact (this copy and the constant
// stay mutually consistent when both are left untouched); cross-repo drift
// detection would need a CI job that fetches and diffs the canonical artifact.

const agentRegFixturePath = "testdata/agent_registration_golden.json"

// agentRegFixtureSHA256 pins the byte-identity of the local testdata copy to the
// qurl-conformance canonical artifact. Update it deliberately when re-syncing the
// vectors after an upstream change.
const agentRegFixtureSHA256 = "77dc8634eb15e8a986df1093923b70b341386ba3c15421814ffed1a668f2d2bc"

type agentRegDeterministicCase struct {
	ServerStaticPrivHex string `json:"server_static_priv_hex"`
	ServerStaticPubHex  string `json:"server_static_pub_hex"`
	DeviceStaticPrivHex string `json:"device_static_priv_hex"`
	DeviceStaticPubHex  string `json:"device_static_pub_hex"`
	EphemeralPrivHex    string `json:"ephemeral_priv_hex"`
	TimestampNanos      string `json:"timestamp_nanos"`
	Counter             string `json:"counter"`
	PreambleHex         string `json:"preamble_hex"`
	BodyHex             string `json:"body_hex"`
	PacketHex           string `json:"packet_hex"`
}

type agentRegFrozenCase struct {
	ServerStaticPubHex string `json:"server_static_pub_hex"`
	AgentStaticPrivHex string `json:"agent_static_priv_hex"`
	TimestampNanos     string `json:"timestamp_nanos"`
	CounterHex         string `json:"counter_hex"`
	BodyHex            string `json:"body_hex"`
	PacketHex          string `json:"packet_hex"`
}

type agentRegFixture struct {
	Artifact      string                    `json:"artifact"`
	SchemaVersion int                       `json:"schema_version"`
	OTP           agentRegDeterministicCase `json:"otp"`
	RegEmailed    agentRegDeterministicCase `json:"reg_emailed"`
	RegPreissued  agentRegDeterministicCase `json:"reg_preissued"`
	RakSuccess    agentRegFrozenCase        `json:"rak_success"`
	RakError      agentRegFrozenCase        `json:"rak_error"`
}

func loadAgentRegFixture(t *testing.T) *agentRegFixture {
	t.Helper()
	raw, err := os.ReadFile(agentRegFixturePath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("fixture %s not present (run from the full repo tree): %v", agentRegFixturePath, err)
		}
		t.Fatalf("read fixture %s: %v", agentRegFixturePath, err)
	}
	if got := sha256.Sum256(raw); hex.EncodeToString(got[:]) != agentRegFixtureSHA256 {
		t.Fatalf("fixture %s sha256 = %x, want %s — the local copy drifted from the pinned qurl-conformance artifact; re-sync it and update agentRegFixtureSHA256", agentRegFixturePath, got, agentRegFixtureSHA256)
	}
	var fx agentRegFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if fx.Artifact != "qurl-agent-registration-golden-vectors" {
		t.Fatalf("fixture artifact = %q, want qurl-agent-registration-golden-vectors", fx.Artifact)
	}
	if fx.SchemaVersion == 0 {
		t.Fatalf("fixture missing schema_version")
	}
	return &fx
}

func mustHexT(t *testing.T, name, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %s hex: %v", name, err)
	}
	return b
}

// decryptInitiatorPacket runs the responder stages over a DETERMINISTIC
// initiator (agent) packet (OTP/REG) with the Go server device keyed to the
// packet's target server static key, asserting the recovered initiator static
// key, send timestamp, header type, and sealed body. Mirrors
// TestJsAgentKnockRoundTrip.
func decryptInitiatorPacket(t *testing.T, name string, c agentRegDeterministicCase, wantType int) []byte {
	t.Helper()

	serverPriv := mustHexT(t, "serverStaticPriv", c.ServerStaticPrivHex)
	deviceStaticPub := mustHexT(t, "deviceStaticPub", c.DeviceStaticPubHex)
	wantBody := mustHexT(t, "body", c.BodyHex)
	packet := mustHexT(t, "packet", c.PacketHex)
	wantTs, err := strconv.ParseInt(c.TimestampNanos, 10, 64)
	if err != nil {
		t.Fatalf("%s: parse timestampNanos: %v", name, err)
	}

	serverDevice := NewDevice(NHP_SERVER, serverPriv, nil)
	if serverDevice == nil {
		t.Fatalf("%s: failed to create server device", name)
	}
	if got, want := serverDevice.PublicKeyBase64(), base64.StdEncoding.EncodeToString(mustHexT(t, "serverStaticPub", c.ServerStaticPubHex)); got != want {
		t.Fatalf("%s: server pubkey mismatch: device=%s fixture=%s", name, got, want)
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
		HeaderType: wantType,
	}

	// Confirm the obfuscated header type/size decode matches the expected type
	// before the crypto stages (localizes a type-field regression).
	if gotType, _ := serverPkt.HeaderTypeAndSize(); gotType != wantType {
		t.Fatalf("%s: header type = %d, want %d", name, gotType, wantType)
	}

	connData := validatePeerConnectionData(serverDevice, 12346, 12345)

	// Drive the responder stages directly (rather than PacketToMsg, which stamps
	// LocalInitTime = now) so InitTime == the packet's fixed send time and the
	// staleness gate accepts the committed fixture no matter when this runs.
	ppd, err := serverDevice.createPacketParserData(&PacketData{
		BasePacket: serverPkt,
		ConnData:   connData,
		InitTime:   wantTs,
	})
	if err != nil {
		t.Fatalf("%s: createPacketParserData (header digest): %v", name, err)
	}
	if err := ppd.validatePeer(); err != nil {
		t.Fatalf("%s: validatePeer (static/timestamp decrypt): %v", name, err)
	}
	if err := ppd.decryptBody(); err != nil {
		t.Fatalf("%s: decryptBody: %v", name, err)
	}

	if !bytes.Equal(ppd.RemotePubKey, deviceStaticPub) {
		t.Errorf("%s: recovered initiator pubkey mismatch\n got:  %x\n want: %x", name, ppd.RemotePubKey, deviceStaticPub)
	}
	if ppd.RemoteSendTime != wantTs {
		t.Errorf("%s: recovered send timestamp = %d, want %d", name, ppd.RemoteSendTime, wantTs)
	}
	if !bytes.Equal(ppd.BodyMessage, wantBody) {
		t.Errorf("%s: recovered body mismatch\n got:  %q\n want: %q", name, ppd.BodyMessage, wantBody)
	}
	return ppd.BodyMessage
}

// TestAgentRegistrationOTPRoundTrip decrypts the deterministic OTP (type 12)
// packet and asserts the Go server recovers the AgentOTPMsg fields.
func TestAgentRegistrationOTPRoundTrip(t *testing.T) {
	fx := loadAgentRegFixture(t)
	body := decryptInitiatorPacket(t, "otp", fx.OTP, NHP_OTP)

	var msg common.AgentOTPMsg
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatalf("otp: unmarshal AgentOTPMsg: %v", err)
	}
	if msg.UserId == "" || msg.DeviceId == "" || msg.AuthServiceId == "" {
		t.Errorf("otp: AgentOTPMsg missing required fields: %+v", msg)
	}
	if msg.Passcode == "" {
		t.Errorf("otp: AgentOTPMsg pass is empty")
	}
}

// TestAgentRegistrationREGRoundTrip decrypts both deterministic REG (type 13)
// packets (emailed-code and pre-issued-key) and asserts the Go server recovers
// the AgentRegisterMsg fields, including the usrData registration metadata
// (hostname/version/takeover — the real cross-language contract). The two packets
// differ in the body otp value and in usrData.takeover (reg_emailed omits it;
// reg_preissued sets it true).
func TestAgentRegistrationREGRoundTrip(t *testing.T) {
	fx := loadAgentRegFixture(t)

	for _, tc := range []struct {
		name         string
		c            agentRegDeterministicCase
		wantTakeover bool // reg_emailed omits takeover (false); reg_preissued sets it true
	}{
		{"reg_emailed", fx.RegEmailed, false},
		{"reg_preissued", fx.RegPreissued, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := decryptInitiatorPacket(t, tc.name, tc.c, NHP_REG)
			var msg common.AgentRegisterMsg
			if err := json.Unmarshal(body, &msg); err != nil {
				t.Fatalf("%s: unmarshal AgentRegisterMsg: %v", tc.name, err)
			}
			if msg.UserId == "" || msg.DeviceId == "" || msg.AuthServiceId == "" {
				t.Errorf("%s: AgentRegisterMsg missing required fields: %+v", tc.name, msg)
			}
			if msg.OTP == "" {
				t.Errorf("%s: AgentRegisterMsg otp is empty", tc.name)
			}
			// usrData is the real registration-metadata contract
			// (hostname/version/takeover). Assert the server recovers it so the
			// fence pins the corrected field names, not just body-present.
			if msg.UserData == nil {
				t.Fatalf("%s: AgentRegisterMsg usrData is absent", tc.name)
			}
			if h, _ := msg.UserData["hostname"].(string); h == "" {
				t.Errorf("%s: usrData.hostname missing/empty: %v", tc.name, msg.UserData["hostname"])
			}
			if v, _ := msg.UserData["version"].(string); v == "" {
				t.Errorf("%s: usrData.version missing/empty: %v", tc.name, msg.UserData["version"])
			}
			// takeover is omitempty: present+true only for reg_preissued; for
			// reg_emailed the key is omitted entirely (not JSON null), so the map
			// lookup returns nil and the comma-ok bool assertion yields false.
			gotTakeover, _ := msg.UserData["takeover"].(bool)
			if gotTakeover != tc.wantTakeover {
				t.Errorf("%s: usrData.takeover = %v, want %v", tc.name, msg.UserData["takeover"], tc.wantTakeover)
			}
		})
	}

	// conformance#19: reg_emailed's counter must equal the RAK counter (the
	// counter-echo pair). This REG test — not the RAK test — is where the matched
	// pair is pinned, since the assertion needs both the reg_emailed counter and
	// the RAK counter_hex. Only reg_emailed is part of the pair; reg_preissued's
	// counter (12, per the vector notes) is intentionally NOT cross-checked here —
	// it is a standalone REG that documents the wire is identical, not a RAK match.
	regCounter, err := strconv.ParseUint(fx.RegEmailed.Counter, 10, 64)
	if err != nil {
		t.Fatalf("parse reg_emailed counter: %v", err)
	}
	rakCounter, err := strconv.ParseUint(fx.RakSuccess.CounterHex, 16, 64)
	if err != nil {
		t.Fatalf("parse rak_success counter_hex: %v", err)
	}
	if regCounter != rakCounter {
		t.Errorf("counter-echo pair broken: reg_emailed.counter=%d, rak_success.counter=%d", regCounter, rakCounter)
	}
}

// decryptRAK decrypts a FROZEN RAK (type 14) reply with the agent's static key
// (the server is the initiator of this fresh handshake) and asserts the recovered
// server static key, header type, counter, and body. Mirrors
// TestJsAgentAckRoundTrip.
func decryptRAK(t *testing.T, name string, c agentRegFrozenCase) []byte {
	t.Helper()

	agentPriv := mustHexT(t, "agentStaticPriv", c.AgentStaticPrivHex)
	serverPub := mustHexT(t, "serverStaticPub", c.ServerStaticPubHex)
	wantBody := mustHexT(t, "body", c.BodyHex)
	packet := mustHexT(t, "packet", c.PacketHex)
	wantTs, err := strconv.ParseInt(c.TimestampNanos, 10, 64)
	if err != nil {
		t.Fatalf("%s: parse timestampNanos: %v", name, err)
	}
	wantCounter, err := strconv.ParseUint(c.CounterHex, 16, 64)
	if err != nil {
		t.Fatalf("%s: parse counter_hex: %v", name, err)
	}

	agentDev := NewDevice(NHP_AGENT, agentPriv, nil)
	if agentDev == nil {
		t.Fatalf("%s: failed to create agent device", name)
	}
	// NHP_RAK's sender is NHP_SERVER, so the agent validates the server peer.
	agentDev.AddPeer(&UdpPeer{
		PubKeyBase64: base64.StdEncoding.EncodeToString(serverPub),
		Ip:           "127.0.0.1",
		Port:         62206,
		Type:         NHP_SERVER,
	})

	var buf PacketBuffer
	copy(buf[:], packet)
	pkt := &Packet{Buf: &buf, Content: buf[:len(packet)], HeaderType: NHP_RAK}

	if gotType, _ := pkt.HeaderTypeAndSize(); gotType != NHP_RAK {
		t.Fatalf("%s: header type = %d, want %d (NHP_RAK)", name, gotType, NHP_RAK)
	}
	if gotCounter := pkt.Counter(); gotCounter != wantCounter {
		t.Errorf("%s: header counter = %d, want %d", name, gotCounter, wantCounter)
	}

	ppd, err := agentDev.createPacketParserData(&PacketData{
		BasePacket: pkt,
		ConnData:   validatePeerConnectionData(agentDev, 40000, 62206),
		InitTime:   wantTs,
	})
	if err != nil {
		t.Fatalf("%s: createPacketParserData (header digest): %v", name, err)
	}
	if err := ppd.validatePeer(); err != nil {
		t.Fatalf("%s: validatePeer (static/timestamp decrypt): %v", name, err)
	}
	if err := ppd.decryptBody(); err != nil {
		t.Fatalf("%s: decryptBody: %v", name, err)
	}

	if !bytes.Equal(ppd.RemotePubKey, serverPub) {
		t.Errorf("%s: recovered server pubkey mismatch\n got:  %x\n want: %x", name, ppd.RemotePubKey, serverPub)
	}
	if ppd.RemoteSendTime != wantTs {
		t.Errorf("%s: recovered send timestamp = %d, want %d", name, ppd.RemoteSendTime, wantTs)
	}
	if !bytes.Equal(ppd.BodyMessage, wantBody) {
		t.Errorf("%s: recovered RAK body mismatch\n got:  %q\n want: %q", name, ppd.BodyMessage, wantBody)
	}
	return ppd.BodyMessage
}

// TestAgentRegistrationRAKRoundTrip decrypts the frozen RAK success/error (type
// 14) replies and asserts the recovered ServerRegisterAckMsg errCode.
func TestAgentRegistrationRAKRoundTrip(t *testing.T) {
	fx := loadAgentRegFixture(t)

	t.Run("rak_success", func(t *testing.T) {
		body := decryptRAK(t, "rak_success", fx.RakSuccess)
		var msg common.ServerRegisterAckMsg
		if err := json.Unmarshal(body, &msg); err != nil {
			t.Fatalf("rak_success: unmarshal ServerRegisterAckMsg: %v", err)
		}
		if msg.ErrCode != "0" {
			t.Errorf("rak_success: errCode = %q, want %q", msg.ErrCode, "0")
		}
		if msg.AuthServiceId == "" {
			t.Errorf("rak_success: aspId is empty")
		}
	})

	t.Run("rak_error", func(t *testing.T) {
		body := decryptRAK(t, "rak_error", fx.RakError)
		var msg common.ServerRegisterAckMsg
		if err := json.Unmarshal(body, &msg); err != nil {
			t.Fatalf("rak_error: unmarshal ServerRegisterAckMsg: %v", err)
		}
		if msg.ErrCode == "" || msg.ErrCode == "0" {
			t.Errorf("rak_error: errCode = %q, want a non-zero error code", msg.ErrCode)
		}
		if msg.ErrMsg == "" {
			t.Errorf("rak_error: errMsg is empty")
		}
	})
}
