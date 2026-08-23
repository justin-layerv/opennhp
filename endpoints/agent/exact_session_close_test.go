package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

func newExactCloseClientAgent(t *testing.T) *UdpAgent {
	t.Helper()
	device := core.NewDevice(core.NHP_AGENT, make([]byte, core.PrivateKeySize), nil)
	if device == nil {
		t.Fatal("NewDevice returned nil")
	}
	a := &UdpAgent{
		config:    &Config{DefaultCipherScheme: 0},
		device:    device,
		knockUser: &KnockUser{UserId: "agent-user"},
		sendMsgCh: make(chan *core.MsgData, 2),
	}
	a.signals.stop = make(chan struct{})
	a.running.Store(true)
	return a
}

func exactCloseClientPeer(fill byte, ip string, port int) *core.UdpPeer {
	return &core.UdpPeer{
		Type: core.NHP_SERVER, PubKeyBase64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, core.PublicKeySize)),
		Ip: ip, Port: port,
	}
}

func exactCloseClientReceipt() common.AgentSessionReceipt {
	return common.AgentSessionReceipt{
		CellID: "cell-01", SessionID: 77, SessionIssuedAtMillis: 1_700_000_000_000,
		RunID: "0123456789abcdef", RunAttempt: 2,
	}
}

func exactCloseSuccessBody(t *testing.T, receipt common.AgentSessionReceipt) []byte {
	t.Helper()
	body, err := json.Marshal(&common.ServerExactSessionCloseAckMsg{
		ErrCode: common.ErrSuccess.ErrorCode(), CellID: receipt.CellID, SessionID: receipt.SessionID,
		SessionIssuedAtMillis: receipt.SessionIssuedAtMillis, RunID: receipt.RunID,
		RunAttempt: receipt.RunAttempt, CloseEventID: "0123456789abcdef0123456789abcdef", State: "closing",
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestRegisteredKnockRetainsReceiptAndExactExitUsesIssuingPeer(t *testing.T) {
	a := newExactCloseClientAgent(t)
	originalPeer := exactCloseClientPeer(0x31, "127.0.0.1", 62206)
	reassignedPeer := exactCloseClientPeer(0x32, "127.0.0.2", 62207)
	target := &KnockTarget{KnockResource: KnockResource{
		AuthServiceId: common.RegisteredAgentAuthServiceID, ResourceId: "resource",
		RunID: "0123456789abcdef", RunAttempt: 2,
	}, ServerPeer: originalPeer}
	receipt := exactCloseClientReceipt()

	knockObserved := make(chan struct{})
	go func() {
		md := <-a.sendMsgCh
		if md.HeaderType != core.NHP_KNK || !bytes.Equal(md.PeerPk, originalPeer.PublicKey()) {
			t.Errorf("KNK route = type %d peer %x", md.HeaderType, md.PeerPk)
		}
		var request common.AgentKnockMsg
		if err := json.Unmarshal(md.Message, &request); err != nil {
			t.Errorf("decode KNK: %v", err)
		} else if request.RunID != receipt.RunID || request.RunAttempt != receipt.RunAttempt {
			t.Errorf("KNK run binding = (%q,%d)", request.RunID, request.RunAttempt)
		}
		ackBytes, _ := json.Marshal(&common.ServerKnockAckMsg{
			ErrCode: common.ErrSuccess.ErrorCode(), SessionId: receipt.SessionID, CellId: receipt.CellID,
			SessionIssuedAtMillis: receipt.SessionIssuedAtMillis, RunID: receipt.RunID,
			RunAttempt: receipt.RunAttempt, OpenTime: 30, AgentAddr: "198.51.100.8:44444",
			ResourceHost: map[string]string{"resource": "127.0.0.1:443"},
			ACTokens:     map[string]string{"resource": "token"},
		})
		md.ResponseMsgCh <- &core.PacketParserData{HeaderType: core.NHP_ACK, BodyMessage: ackBytes}
		close(knockObserved)
	}()
	ack, err := a.Knock(target)
	if err != nil || ack == nil || ack.SessionId != receipt.SessionID {
		t.Fatalf("Knock = %#v, %v", ack, err)
	}
	<-knockObserved

	// A later assignment update changes the target's current server. Retirement
	// must still use the peer captured with the original admission receipt.
	target.SetServerPeer(reassignedPeer)
	exitObserved := make(chan struct{})
	go func() {
		md := <-a.sendMsgCh
		if md.HeaderType != core.NHP_EXT || !bytes.Equal(md.PeerPk, originalPeer.PublicKey()) ||
			!md.RemoteAddr.IP.Equal(net.ParseIP(originalPeer.Ip)) || md.RemoteAddr.Port != originalPeer.Port {
			t.Errorf("EXT route = type %d peer %x addr %v, want original peer", md.HeaderType, md.PeerPk, md.RemoteAddr)
		}
		if strings.Contains(string(md.Message), `"resId"`) || strings.Contains(string(md.Message), `"opnTime"`) {
			t.Errorf("EXT reused resource/open body: %s", md.Message)
		}
		var request common.AgentExactSessionCloseMsg
		if err := common.DecodeAgentExactSessionCloseMsg(md.Message, &request); err != nil {
			t.Errorf("decode exact EXT: %v", err)
		} else if request.CellID != receipt.CellID || request.SessionID != receipt.SessionID ||
			request.SessionIssuedAtMillis != receipt.SessionIssuedAtMillis || request.RunID != receipt.RunID ||
			request.RunAttempt != receipt.RunAttempt {
			t.Errorf("exact EXT = %#v, receipt %#v", request, receipt)
		}
		md.ResponseMsgCh <- &core.PacketParserData{HeaderType: core.NHP_ACK, BodyMessage: exactCloseSuccessBody(t, receipt)}
		close(exitObserved)
	}()
	closeAck, err := a.ExitKnockRequest(target)
	if err != nil || closeAck == nil || closeAck.CloseEventID != "0123456789abcdef0123456789abcdef" || closeAck.State != "closing" {
		t.Fatalf("ExitKnockRequest = %#v, %v", closeAck, err)
	}
	<-exitObserved
}

func TestExitKnockRequestRejectsResourceShapedExitBeforeIO(t *testing.T) {
	a := newExactCloseClientAgent(t)
	target := &KnockTarget{KnockResource: KnockResource{
		AuthServiceId: "legacy", ResourceId: "resource",
	}, ServerPeer: exactCloseClientPeer(0x41, "127.0.0.1", 62206)}
	ack, err := a.ExitKnockRequest(target)
	if !errors.Is(err, common.ErrInvalidInput) || ack == nil || ack.ErrCode != common.ErrInvalidInput.ErrorCode() {
		t.Fatalf("resource-shaped exit = %#v, %v", ack, err)
	}
	if len(a.sendMsgCh) != 0 {
		t.Fatalf("resource-shaped exit queued %d messages", len(a.sendMsgCh))
	}
}

func TestRegisteredKnockRequiresPositiveRunAttemptBeforeIO(t *testing.T) {
	a := newExactCloseClientAgent(t)
	target := &KnockTarget{KnockResource: KnockResource{
		AuthServiceId: common.RegisteredAgentAuthServiceID, ResourceId: "resource", RunID: "0123456789abcdef",
	}, ServerPeer: exactCloseClientPeer(0x42, "127.0.0.1", 62206)}
	ack, err := a.Knock(target)
	if !errors.Is(err, common.ErrKnockRunAttemptInvalid) || ack == nil || ack.ErrCode != common.ErrKnockRunAttemptInvalid.ErrorCode() {
		t.Fatalf("missing run attempt = %#v, %v", ack, err)
	}
	if len(a.sendMsgCh) != 0 {
		t.Fatalf("missing run attempt queued %d messages", len(a.sendMsgCh))
	}
}

func TestExitKnockRequestStrictAckAndReceiptDrift(t *testing.T) {
	receipt := exactCloseClientReceipt()
	valid := string(exactCloseSuccessBody(t, receipt))
	tests := map[string]string{
		"missing":   strings.Replace(valid, `,"cellId":"cell-01"`, ``, 1),
		"unknown":   strings.Replace(valid, `}`, `,"future":1}`, 1),
		"duplicate": strings.Replace(valid, `"sessId":77`, `"sessId":77,"sessId":77`, 1),
		"drift":     strings.Replace(valid, `"sessId":77`, `"sessId":78`, 1),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			a := newExactCloseClientAgent(t)
			peer := exactCloseClientPeer(0x51, "127.0.0.1", 62206)
			target, err := NewSessionRetirementTarget(receipt, peer)
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				md := <-a.sendMsgCh
				md.ResponseMsgCh <- &core.PacketParserData{HeaderType: core.NHP_ACK, BodyMessage: []byte(body)}
			}()
			ack, err := a.ExitKnockRequest(target)
			if err == nil || ack == nil || ack.ErrCode != common.ErrJsonParseFailed.ErrorCode() {
				t.Fatalf("malformed/drift ACK = %#v, %v", ack, err)
			}
		})
	}
}

func TestExitKnockRequestStrictDenial(t *testing.T) {
	a := newExactCloseClientAgent(t)
	target, err := NewSessionRetirementTarget(exactCloseClientReceipt(), exactCloseClientPeer(0x52, "127.0.0.1", 62206))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		md := <-a.sendMsgCh
		md.ResponseMsgCh <- &core.PacketParserData{
			HeaderType:  core.NHP_ACK,
			BodyMessage: []byte(`{"errCode":"52004","errMsg":"denied"}`),
		}
	}()
	ack, err := a.ExitKnockRequest(target)
	if err == nil || ack == nil || ack.ErrCode != "52004" || ack.ErrMsg != "denied" {
		t.Fatalf("strict denial = %#v, %v", ack, err)
	}
}

func TestRegisteredKnockRejectsMissingReceiptBeforeRetention(t *testing.T) {
	a := newExactCloseClientAgent(t)
	peer := exactCloseClientPeer(0x61, "127.0.0.1", 62206)
	target := &KnockTarget{KnockResource: KnockResource{
		AuthServiceId: common.RegisteredAgentAuthServiceID, ResourceId: "resource",
		RunID: "0123456789abcdef", RunAttempt: 2,
	}, ServerPeer: peer}
	go func() {
		md := <-a.sendMsgCh
		body, _ := json.Marshal(&common.ServerKnockAckMsg{
			ErrCode: common.ErrSuccess.ErrorCode(), SessionId: 77, OpenTime: 30,
			AgentAddr: "198.51.100.8:44444", ResourceHost: map[string]string{"resource": "127.0.0.1:443"},
			ACTokens: map[string]string{"resource": "token"},
		})
		md.ResponseMsgCh <- &core.PacketParserData{HeaderType: core.NHP_ACK, BodyMessage: body}
	}()
	ack, err := a.Knock(target)
	if err == nil || ack == nil || ack.ErrCode != common.ErrJsonParseFailed.ErrorCode() {
		t.Fatalf("missing receipt ACK = %#v, %v", ack, err)
	}
	if _, ok := target.getSessionReceipt(); ok {
		t.Fatal("malformed success ACK installed a session receipt")
	}
}

// Keep the test's fake transaction responses comfortably inside the agent's
// real transaction timeout while still catching accidental hangs.
func TestExactSessionCloseClientNoGoroutineLeak(t *testing.T) {
	a := newExactCloseClientAgent(t)
	receipt := exactCloseClientReceipt()
	target, err := NewSessionRetirementTarget(receipt, exactCloseClientPeer(0x71, "127.0.0.1", 62206))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		md := <-a.sendMsgCh
		md.ResponseMsgCh <- &core.PacketParserData{HeaderType: core.NHP_ACK, BodyMessage: exactCloseSuccessBody(t, receipt)}
	}()
	if _, err := a.ExitKnockRequest(target); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("exact close response goroutine did not exit")
	}
}
