package server

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

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
		HeaderType:    core.NHP_EXT, // body type disagrees with the NHP_KNK wire type below
		UserId:        "reject-user",
		AuthServiceId: "asp",
		ResourceId:    "res",
	})
	if err != nil {
		t.Fatalf("marshal mismatch knock: %v", err)
	}

	cases := []struct {
		name        string
		strictGate  bool
		body        []byte
		wantErrCode string
		wantUserID  string
	}{
		{
			name:        "json parse failure",
			body:        []byte("{ not valid json"),
			wantErrCode: common.ErrJsonParseFailed.ErrorCode(),
			wantUserID:  "", // body never parsed, so no user id is recovered
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
			s := &UdpServer{
				metrics:                      metrics.NewPublisherForTest(t),
				knockHeaderTypeVerifyRequire: tc.strictGate,
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
			if ack.ErrCode == common.ErrSuccess.ErrorCode() {
				t.Errorf("reject produced the success ErrCode %q — a relayed agent would never see the reject", ack.ErrCode)
			}
		})
	}
}
