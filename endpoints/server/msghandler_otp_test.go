package server

import (
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

// TestHandleOTPRequest_PopulatesPublicKey fences the NhpOTPRequest.PublicKey
// plumbing added for NHP-native agent registration (N1): HandleOTPRequest must
// hand plugins the Noise-authenticated initiator static key (std-base64 of
// ppd.RemotePubKey), the same way HandleRegisterRequest populates
// NhpRegisterRequest.PublicKey. Without this a plugin issuing one-time
// registration credentials could only key them on message fields the client
// chooses freely (UserId/DeviceId), not on the cryptographically authenticated
// agent identity. There was no prior HandleOTPRequest unit test; this also
// pins the pre-existing Msg/SrcAddr pass-through.
func TestHandleOTPRequest_PopulatesPublicKey(t *testing.T) {
	const aspID = "asp-otp-n1"
	handler := &capturingOTPHandler{}
	s := &UdpServer{
		device:           core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil),
		pluginHandlerMap: map[string]plugins.PluginHandler{aspID: handler},
	}

	otpMsg := &common.AgentOTPMsg{
		UserId:        "user-1",
		DeviceId:      "device-1",
		AuthServiceId: aspID,
	}
	body, err := json.Marshal(otpMsg)
	if err != nil {
		t.Fatalf("marshal AgentOTPMsg: %v", err)
	}

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
	if handler.got.Msg == nil || handler.got.Msg.UserId != otpMsg.UserId ||
		handler.got.Msg.AuthServiceId != aspID {
		t.Errorf("NhpOTPRequest.Msg not passed through: %+v", handler.got.Msg)
	}
	if handler.got.SrcAddr == nil || handler.got.SrcAddr.Ip != "10.9.8.7" ||
		handler.got.SrcAddr.Port != 54321 {
		t.Errorf("NhpOTPRequest.SrcAddr = %+v, want 10.9.8.7:54321", handler.got.SrcAddr)
	}
}
