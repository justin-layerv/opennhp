package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

type nilKnockACKPlugin struct {
	fakePluginHandler
	ack *common.ServerKnockAckMsg
	err error
}

type mutatingSessionKnockPlugin struct {
	fakePluginHandler
	seenID       uint64
	seenIssuedAt time.Time
	reject       bool
}

func (p *mutatingSessionKnockPlugin) AuthWithNHP(req *common.NhpAuthRequest,
	_ *plugins.NhpServerPluginHelper,
) (*common.ServerKnockAckMsg, error) {
	p.seenID = req.SessionId
	p.seenIssuedAt = req.SessionIssuedAt
	req.Msg.NHPSessionId = req.SessionId + 1
	req.Msg.NHPSessionIssuedAt = req.SessionIssuedAt.Add(24 * time.Hour)
	ack := &common.ServerKnockAckMsg{ErrCode: common.ErrSuccess.ErrorCode(), OpenTime: 60}
	if p.reject {
		return ack, errors.New("plugin rejected after mutating request session")
	}
	return ack, nil
}

func TestBuildKnockAck_RejectsBodylessEXTBeforeKnockPipeline(t *testing.T) {
	s := &UdpServer{metrics: metrics.NewPublisherForTest(t)}
	ack, userID, err := s.buildKnockAck(&core.PacketParserData{HeaderType: core.NHP_EXT})
	if err == nil || ack != nil || userID != "" {
		t.Fatalf("bodyless EXT knock result = ack %x user %q err %v, want no ACK and an error", ack, userID, err)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if counters[MetricKnockRequest] != 0 {
		t.Fatalf("bodyless EXT entered knock metrics/pipeline: KnockRequest=%v", counters[MetricKnockRequest])
	}
}

func (p nilKnockACKPlugin) AuthWithNHP(*common.NhpAuthRequest, *plugins.NhpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	return p.ack, p.err
}

// TestBuildKnockAck_RejectReturnsNilErrorWithErrCodeInBytes locks the one
// contract the NHP_RLY relay handler (#2208) reuse rests on: on an
// auth/validation REJECT, buildKnockAck returns a nil error AND a marshaled
// ack whose ErrCode is the reject code. The reject rides in the bytes, not the
// returned error, so the caller (direct knock path today, relay path next)
// still delivers the ack to the agent.
//
// The structural guard (local closureErr, no named returns) makes a stray bare
// `return` a compile error, but only a behavioral test stops a future change
// from deliberately threading closureErr into the return tuple — which would
// regress the relay path into dropping the ack on every reject. This test is
// that fence.
func TestBuildKnockAck_RejectReturnsNilErrorWithErrCodeInBytes(t *testing.T) {
	mismatchBody, err := json.Marshal(&common.AgentKnockMsg{
		HeaderType:    core.NHP_RKN, // body type disagrees with the NHP_KNK wire type below
		UserId:        "reject-user",
		AuthServiceId: "asp",
		ResourceId:    "res",
	})
	if err != nil {
		t.Fatalf("marshal mismatch knock: %v", err)
	}
	missingRunIDBody, err := json.Marshal(&common.AgentKnockMsg{
		HeaderType:    core.NHP_KNK,
		UserId:        "missing-run-id-user",
		AuthServiceId: common.RegisteredAgentAuthServiceID,
		ResourceId:    "connector",
	})
	if err != nil {
		t.Fatalf("marshal missing-RunID knock: %v", err)
	}
	missingAttemptBody, err := json.Marshal(&common.AgentKnockMsg{
		HeaderType:    core.NHP_KNK,
		UserId:        "missing-run-attempt-user",
		AuthServiceId: common.RegisteredAgentAuthServiceID,
		ResourceId:    "connector",
		RunID:         "0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("marshal missing-runAttempt knock: %v", err)
	}

	cases := []struct {
		name        string
		strictGate  bool
		body        []byte
		wantErrCode string
		wantErrMsg  string
		wantUserID  string
		strictAgent bool
	}{
		{
			name:        "json parse failure",
			body:        []byte("{ not valid json"),
			wantErrCode: common.ErrJsonParseFailed.ErrorCode(),
			wantUserID:  "", // body never parsed, so no user id is recovered
		},
		{
			name:        "registered-agent missing RunID",
			body:        missingRunIDBody,
			wantErrCode: common.ErrKnockRunIDInvalid.ErrorCode(),
			wantErrMsg:  common.ErrKnockRunIDInvalid.Error(),
			wantUserID:  "missing-run-id-user",
			strictAgent: true,
		},
		{
			name:        "registered-agent missing runAttempt",
			body:        missingAttemptBody,
			wantErrCode: common.ErrKnockRunAttemptInvalid.ErrorCode(),
			wantErrMsg:  common.ErrKnockRunAttemptInvalid.Error(),
			wantUserID:  "missing-run-attempt-user",
			strictAgent: true,
		},
		{
			name:        "registered-agent malformed RunID uses stable protocol error",
			body:        []byte(`{"headerType":1,"usrId":"invalid-run-id-user","devId":"device","aspId":"agent","resId":"connector","runId":"0123456789ABCDEF"}`),
			wantErrCode: common.ErrKnockRunIDInvalid.ErrorCode(),
			wantErrMsg:  common.ErrKnockRunIDInvalid.Error(),
			wantUserID:  "", // strict parser rejects before committing the decoded struct
		},
		{
			name:        "header-type mismatch under strict gate (#1154)",
			strictGate:  true,
			body:        mismatchBody,
			wantErrCode: common.ErrKnockHeaderTypeMismatch.ErrorCode(),
			wantUserID:  "reject-user",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			querier := newFakeAgentKeysQuerier()
			s := &UdpServer{
				metrics:                      metrics.NewPublisherForTest(t),
				knockHeaderTypeVerifyRequire: tc.strictGate,
				agentPeerLookup:              newTestLookup(t, querier),
			}
			ppd := &core.PacketParserData{
				HeaderType:  core.NHP_KNK,
				SenderTrxId: 7,
				ConnData: &core.ConnectionData{
					RemoteAddr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 51000},
				},
				BodyMessage: tc.body,
			}

			ackBytes, userID, err := s.buildKnockAck(ppd)
			if err != nil {
				t.Fatalf("buildKnockAck returned non-nil error on a reject: %v — the reject must ride in the ack bytes, not the returned error", err)
			}
			if userID != tc.wantUserID {
				t.Errorf("userID = %q, want %q", userID, tc.wantUserID)
			}

			var ack common.ServerKnockAckMsg
			if err := json.Unmarshal(ackBytes, &ack); err != nil {
				t.Fatalf("unmarshal returned ack bytes: %v", err)
			}
			if ack.ErrCode != tc.wantErrCode {
				t.Errorf("ack.ErrCode = %q, want %q", ack.ErrCode, tc.wantErrCode)
			}
			if tc.wantErrMsg != "" && ack.ErrMsg != tc.wantErrMsg {
				t.Errorf("ack.ErrMsg = %q, want %q", ack.ErrMsg, tc.wantErrMsg)
			}
			if ack.ErrCode == common.ErrSuccess.ErrorCode() {
				t.Errorf("reject produced the success ErrCode %q — a relayed agent would never see the reject", ack.ErrCode)
			}
			var wire map[string]json.RawMessage
			if err := json.Unmarshal(ackBytes, &wire); err != nil {
				t.Fatalf("unmarshal returned ACK object: %v", err)
			}
			if got := string(wire["opnTime"]); got != "0" {
				t.Errorf("denied ACK opnTime = %s, want required canonical JSON number 0", got)
			}
			if tc.strictAgent {
				if len(wire) != 3 {
					t.Errorf("registered-agent denial fields = %v, want exactly errCode, errMsg, opnTime", wire)
				}
				var strict common.ServerKnockAckMsg
				if err := common.DecodeRegisteredAgentKnockAckMsg(ackBytes, &strict, "", 0, ""); err != nil {
					t.Errorf("strict decode producer denial: %v", err)
				}
			}
			if _, present := wire["sessId"]; present {
				t.Errorf("denied ACK unexpectedly contains sessId: %s", wire["sessId"])
			}
			if calls := querier.callCount(); calls != 0 {
				t.Errorf("agent registry DDB calls = %d, want 0; structural and RunID rejects must precede pubkey lookup", calls)
			}
		})
	}
}

func TestBuildKnockAck_InvalidPluginACKFailsClosedAndReleasesSession(t *testing.T) {
	for name, pluginResult := range map[string]struct {
		ack *common.ServerKnockAckMsg
		err error
	}{
		"nil ack and nil error": {},
		"nil ack and error": {
			err: errors.New("plugin failed after session allocation"),
		},
		"success ack and error": {
			ack: &common.ServerKnockAckMsg{ErrCode: common.ErrSuccess.ErrorCode(), OpenTime: 42},
			err: errors.New("plugin failed after constructing success ACK"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
			if device == nil {
				t.Fatal("NewDevice returned nil")
			}
			t.Cleanup(device.Stop)
			server := &UdpServer{
				device:  device,
				metrics: metrics.NewPublisherForTest(t),
				authServiceMap: common.AuthSvcProviderMap{
					"test": {AuthSvcId: "test"},
				},
				pluginHandlerMap: map[string]plugins.PluginHandler{
					"test": nilKnockACKPlugin{ack: pluginResult.ack, err: pluginResult.err},
				},
			}
			body, err := json.Marshal(&common.AgentKnockMsg{
				HeaderType:    core.NHP_KNK,
				UserId:        "plugin-nil-user",
				AuthServiceId: "test",
				ResourceId:    "test-resource",
			})
			if err != nil {
				t.Fatal(err)
			}
			ackBytes, _, err := server.buildKnockAck(&core.PacketParserData{
				HeaderType:   core.NHP_KNK,
				SenderTrxId:  8,
				RemotePubKey: bytes.Repeat([]byte{0x31}, 32),
				ConnData: &core.ConnectionData{
					RemoteAddr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 51001},
					StopSignal: make(chan struct{}),
				},
				BodyMessage: body,
			})
			if err != nil {
				t.Fatalf("buildKnockAck: %v", err)
			}

			var ack common.ServerKnockAckMsg
			if err := json.Unmarshal(ackBytes, &ack); err != nil {
				t.Fatalf("unmarshal ACK: %v", err)
			}
			if ack.ErrCode != common.ErrServerACOpsFailed.ErrorCode() || ack.OpenTime != 0 || ack.SessionId != 0 {
				t.Fatalf("invalid-plugin ACK = %+v, want canonical denied ACK", ack)
			}
			var wire map[string]json.RawMessage
			if err := json.Unmarshal(ackBytes, &wire); err != nil {
				t.Fatal(err)
			}
			if got := string(wire["opnTime"]); got != "0" {
				t.Fatalf("denied ACK opnTime = %s, want 0", got)
			}
			if _, present := wire["sessId"]; present {
				t.Fatalf("denied ACK unexpectedly contains sessId: %s", wire["sessId"])
			}
			registry := server.sessionRegistry()
			registry.mu.Lock()
			remaining := len(registry.sessions)
			registry.mu.Unlock()
			if remaining != 0 {
				t.Fatalf("live session reservations = %d, want 0 after plugin denial", remaining)
			}
		})
	}
}

func TestBuildKnockAck_PluginCannotRewriteServerSessionAuthority(t *testing.T) {
	for _, reject := range []bool{false, true} {
		name := "success"
		if reject {
			name = "reject"
		}
		t.Run(name, func(t *testing.T) {
			plugin := &mutatingSessionKnockPlugin{reject: reject}
			device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
			if device == nil {
				t.Fatal("NewDevice returned nil")
			}
			t.Cleanup(device.Stop)
			server := &UdpServer{
				device: device, metrics: metrics.NewPublisherForTest(t),
				authServiceMap: common.AuthSvcProviderMap{
					"test": {AuthSvcId: "test"},
				},
				pluginHandlerMap: map[string]plugins.PluginHandler{"test": plugin},
			}
			body, err := json.Marshal(&common.AgentKnockMsg{
				HeaderType: core.NHP_KNK, UserId: "plugin-mutation-user",
				AuthServiceId: "test", ResourceId: "test-resource",
			})
			if err != nil {
				t.Fatal(err)
			}
			agentKey := bytes.Repeat([]byte{0x41}, 32)
			ackBytes, _, err := server.buildKnockAck(&core.PacketParserData{
				HeaderType: core.NHP_KNK, SenderTrxId: 9, RemotePubKey: agentKey,
				ConnData: &core.ConnectionData{
					RemoteAddr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 11), Port: 51002},
					StopSignal: make(chan struct{}),
				},
				BodyMessage: body,
			})
			if err != nil {
				t.Fatalf("buildKnockAck: %v", err)
			}
			if plugin.seenID == 0 || plugin.seenIssuedAt.IsZero() {
				t.Fatal("plugin did not observe a server session authority")
			}
			var ack common.ServerKnockAckMsg
			if err := json.Unmarshal(ackBytes, &ack); err != nil {
				t.Fatal(err)
			}
			registry := server.sessionRegistry()
			registry.mu.Lock()
			_, originalPresent := registry.sessions[plugin.seenID]
			_, mutatedPresent := registry.sessions[plugin.seenID+1]
			remaining := len(registry.sessions)
			registry.mu.Unlock()
			if reject {
				if ack.SessionId != 0 || remaining != 0 {
					t.Fatalf("rejected mutated session ACK/registry = %d/%d, want 0/0", ack.SessionId, remaining)
				}
				return
			}
			if ack.SessionId != plugin.seenID || !originalPresent || mutatedPresent || remaining != 1 {
				t.Fatalf("successful mutated session ACK=%d original=%t mutant=%t remaining=%d; want %d/true/false/1",
					ack.SessionId, originalPresent, mutatedPresent, remaining, plugin.seenID)
			}
			registry.release(agentKey, plugin.seenID, plugin.seenIssuedAt)
		})
	}
}

func TestPluginCallbackRestoresFullServerSessionAuthority(t *testing.T) {
	issuedAt := time.Now().Round(0)
	agentPublicKey := testPubkeyB64(0x61)
	originalMessage := &common.AgentKnockMsg{
		NHPSessionId: 991, NHPSessionIssuedAt: issuedAt.Add(24 * time.Hour),
		NHPAgentPublicKey: testPubkeyB64(0x62), RunID: "fedcba9876543210", RunAttempt: 9,
		ResourceId: "plugin-normalized-resource",
	}
	mutated := &common.NhpAuthRequest{
		Msg: originalMessage, SessionId: 992, SessionIssuedAt: issuedAt.Add(48 * time.Hour),
		PublicKey: testPubkeyB64(0x63),
	}
	bound, err := bindServerSessionAuthorityForPluginCallback(mutated, 990, issuedAt,
		agentPublicKey, "0123456789abcdef", 3)
	if err != nil {
		t.Fatal(err)
	}
	if bound.SessionId != 990 || !bound.SessionIssuedAt.Equal(issuedAt) || bound.PublicKey != agentPublicKey ||
		bound.Msg.NHPSessionId != 990 || !bound.Msg.NHPSessionIssuedAt.Equal(issuedAt) ||
		bound.Msg.NHPAgentPublicKey != agentPublicKey || bound.Msg.RunID != "0123456789abcdef" ||
		bound.Msg.RunAttempt != 3 || bound.Msg.ResourceId != "plugin-normalized-resource" {
		t.Fatalf("bound callback authority = %#v", bound)
	}
	if mutated.SessionId != 992 || mutated.Msg.NHPSessionId != 991 || mutated.Msg.ResourceId != "plugin-normalized-resource" {
		t.Fatal("callback authority binding mutated the plugin-owned request")
	}
}
