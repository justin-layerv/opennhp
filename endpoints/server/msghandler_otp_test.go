package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// capturingOTPHandler wraps mockPluginHandler (httpauth_test.go) and records
// the request HandleOTPRequest hands to the plugin, so the test can assert on
// exactly what a plugin would observe.
type capturingOTPHandler struct {
	mockPluginHandler
	got *common.NhpOTPRequest
}

func (c *capturingOTPHandler) RequestOTP(req *common.NhpOTPRequest, _ *plugins.NhpServerPluginHelper) error {
	c.got = req
	return nil
}

// TestHandleOTPRequest_PreservesRawBodyAndPublicKey fences the direct UDP OTP
// plugin boundary. The plugin receives both the exact decrypted body for strict
// duplicate/unknown-field validation and the independently Noise-authenticated
// initiator static key. RawBody must not alias the handler-owned BodyMessage,
// preserving independent ownership if either side later mutates its slice.
func TestHandleOTPRequest_PreservesRawBodyAndPublicKey(t *testing.T) {
	const aspID = "asp-otp-n1"
	handler := &capturingOTPHandler{}
	s := &UdpServer{
		device:           core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil),
		pluginHandlerMap: map[string]plugins.PluginHandler{aspID: handler},
	}

	body := []byte("{\n  \"usrId\":\"first\",\"usrId\":\"user-1\",\"devId\":\"device-1\",\"aspId\":\"" + aspID + "\",\"pass\":\"secret\",\"unknown\":\"otp-raw-only\",\"pubKey\":\"attacker-json-key\"\n}\n\t")
	wantRawBody := bytes.Clone(body)

	// A fixed 32-byte "peer static key" as core.responder.validatePeer would
	// have left it on the ppd after the Noise handshake check.
	rawPubKey := testPubkey(0xC0)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("10.9.8.7"), Port: 54321}
	ppd := &core.PacketParserData{
		ConnData:     &core.ConnectionData{RemoteAddr: remoteAddr},
		SenderTrxId:  71,
		HeaderType:   core.NHP_OTP,
		BodyMessage:  body,
		RemotePubKey: rawPubKey,
	}

	if err := s.HandleOTPRequest(ppd); err != nil {
		t.Fatalf("HandleOTPRequest returned error: %v", err)
	}
	if handler.got == nil {
		t.Fatal("plugin RequestOTP was not invoked")
	}

	if want := base64.StdEncoding.EncodeToString(rawPubKey); handler.got.PublicKey != want {
		t.Errorf("NhpOTPRequest.PublicKey = %q, want %q (std-base64 of ppd.RemotePubKey)",
			handler.got.PublicKey, want)
	}
	if handler.got.Msg == nil || handler.got.Msg.UserId != "user-1" ||
		handler.got.Msg.AuthServiceId != aspID {
		t.Errorf("NhpOTPRequest.Msg not passed through: %+v", handler.got.Msg)
	}
	if !bytes.Equal(handler.got.RawBody, wantRawBody) {
		t.Fatalf("NhpOTPRequest.RawBody = %q, want exact decrypted body %q", handler.got.RawBody, wantRawBody)
	}
	if &handler.got.RawBody[0] == &body[0] {
		t.Fatal("NhpOTPRequest.RawBody aliases ppd.BodyMessage; plugin ownership must be defensive")
	}
	handler.got.RawBody[0] = '!'
	if !bytes.Equal(body, wantRawBody) {
		t.Fatal("mutating NhpOTPRequest.RawBody changed ppd.BodyMessage")
	}
	handler.got.RawBody[0] = wantRawBody[0]
	body[0] = '!'
	if !bytes.Equal(handler.got.RawBody, wantRawBody) {
		t.Fatal("reusing ppd.BodyMessage changed NhpOTPRequest.RawBody")
	}
	serialized, err := json.Marshal(handler.got)
	if err != nil {
		t.Fatalf("marshal NhpOTPRequest: %v", err)
	}
	if bytes.Contains(serialized, []byte("otp-raw-only")) || bytes.Contains(serialized, []byte("attacker-json-key")) {
		t.Fatalf("json:\"-\" RawBody leaked through request serialization: %s", serialized)
	}
	if handler.got.SrcAddr == nil || handler.got.SrcAddr.Ip != "10.9.8.7" ||
		handler.got.SrcAddr.Port != 54321 {
		t.Errorf("NhpOTPRequest.SrcAddr = %+v, want 10.9.8.7:54321", handler.got.SrcAddr)
	}
}
