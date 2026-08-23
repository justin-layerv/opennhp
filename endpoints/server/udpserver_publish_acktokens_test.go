package server

import (
	"context"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestHandleNhpOpenResource_PublishACKTokens_RoundTrip fences the
// load-bearing contract PR-2a introduces at the UDP knock handler:
// after handleNhpOpenResource returns successfully, the AC token the
// AC issued must be resolvable via VerifyAccessToken, populated with
// the knock's source IP, OpenTime, and User fields. PR-2b's
// /nhp/internal/token/validate is the downstream reader; if a future
// PR drops the s.PublishACKTokens call from this handler, or moves it
// back inside the AC goroutine before acWg.Wait() returns, the
// validate endpoint silently starts returning nil in production.
//
// processACOperationBroadcastFn is the seam — see the field doc on
// UdpServer. Driving the real method would require a full Noise
// cipher state; the seam lets us assert the publication contract
// without that. The handler is otherwise exercised end-to-end: the
// real acConnectionMap lookup, the real snapshotLiveACConns filter,
// the real acWg.Wait() barrier, and the real PublishACKTokens call
// all execute.
//
// Companion to TestHandleHttpOpenResource_PublishACKTokens_RoundTrip
// in httpserver_publish_acktokens_test.go.
func TestHandleNhpOpenResource_PublishACKTokens_RoundTrip(t *testing.T) {
	const (
		acId      = "ac-int-test"
		resName   = "resource-alpha"
		issuedTok = "ac-token-from-fake-broadcast"
		knockerIP = "203.0.113.42"
		wantRunID = "0123456789abcdef"
		wantOpen  = uint32(60)
	)

	// Capture what the seam was called with so we can fence the
	// arguments the handler computes (knkMsg, srcAddr, openTime) in
	// addition to the post-Wait publication contract.
	var (
		gotSrcIp    string
		gotOpenTime uint32
		gotUserId   string
		gotConnsLen int
	)

	s := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
		acConnectionMap: map[string][]*ACConn{
			acId: {newACConnWithLastRecv(time.Now().UnixNano())},
		},
		processACOperationBroadcastFn: func(
			_ context.Context,
			knkMsg *common.AgentKnockMsg,
			conns []*ACConn,
			srcAddr *common.NetAddress,
			_ []*common.NetAddress,
			openTime uint32,
			_ *common.ResourceData,
		) (*common.ACOpsResultMsg, error) {
			gotConnsLen = len(conns)
			gotSrcIp = srcAddr.Ip
			gotOpenTime = openTime
			gotUserId = knkMsg.UserId
			return &common.ACOpsResultMsg{
				ErrCode:  common.ErrSuccess.ErrorCode(),
				ACToken:  issuedTok,
				OpenTime: openTime,
				PreAccessAction: &common.PreAccessInfo{
					AccessIp: "10.0.0.5",
				},
			}, nil
		},
	}

	knkMsg := &common.AgentKnockMsg{
		UserId:             "u-int",
		DeviceId:           "d-int",
		OrganizationId:     "o-int",
		AuthServiceId:      common.RegisteredAgentAuthServiceID,
		ResourceId:         resName,
		RunID:              wantRunID,
		NHPSessionId:       1,
		NHPSessionIssuedAt: time.Now(),
	}
	srcAddr := &common.NetAddress{Ip: knockerIP, Port: 51820}
	ackMsg := &common.ServerKnockAckMsg{SessionId: 1, OpenTime: wantOpen}
	req := &common.NhpAuthRequest{Msg: knkMsg, SrcAddr: srcAddr, Ack: ackMsg, SessionId: 1, SessionIssuedAt: knkMsg.NHPSessionIssuedAt}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			ResourceId: resName,
			OpenTime:   wantOpen,
			Resources: map[string]*common.ResourceInfo{
				resName: {
					ACId: acId,
					Addr: &common.NetAddress{Ip: "10.0.0.5", Port: 443},
				},
			},
		},
		ResourcePublicKeyB64: testProtectedResourceID,
	}

	gotAck, err := s.handleNhpOpenResource(req, res)
	if err != nil {
		t.Fatalf("handleNhpOpenResource returned error: %v", err)
	}
	if gotAck.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Fatalf("ack ErrCode = %q, want success (PublishACKTokens runs even on partial failure but a complete success path is the most stable shape)", gotAck.ErrCode)
	}

	// Seam-arg fence: the handler must pass the correct knock context
	// into the AC broadcast. A regression that, say, hoists openTime
	// from the wrong scope would surface here before the publication
	// assertions below.
	if gotConnsLen != 1 {
		t.Errorf("seam saw %d conns, want 1 (acConnectionMap[%q] seeded with one fresh conn)", gotConnsLen, acId)
	}
	if gotSrcIp != knockerIP {
		t.Errorf("seam saw srcIp %q, want %q", gotSrcIp, knockerIP)
	}
	if gotOpenTime != wantOpen {
		t.Errorf("seam saw openTime %d, want %d", gotOpenTime, wantOpen)
	}
	if gotUserId != "u-int" {
		t.Errorf("seam saw UserId %q, want %q", gotUserId, "u-int")
	}

	// Load-bearing assertion: the AC-issued token must round-trip
	// through tokenStore. This is what PR-2b's reader depends on.
	entry := s.VerifyAccessToken(issuedTok)
	if entry == nil {
		t.Fatal("VerifyAccessToken returned nil for the AC-issued token; the post-Wait PublishACKTokens contract is broken")
	}
	if entry.ResourceId != resName {
		t.Errorf("entry.ResourceId = %q, want %q", entry.ResourceId, resName)
	}
	if entry.ProtectedResourceId != testProtectedResourceID {
		t.Errorf("entry.ProtectedResourceId = %q, want resolved public resource %q", entry.ProtectedResourceId, testProtectedResourceID)
	}
	if entry.KnockSrcIP != knockerIP {
		t.Errorf("entry.KnockSrcIP = %q, want %q — the cross-check input PR-2b feeds into the FRP login gate would be wrong", entry.KnockSrcIP, knockerIP)
	}
	if entry.OpenTime != int(wantOpen) {
		t.Errorf("entry.OpenTime = %d, want %d", entry.OpenTime, wantOpen)
	}
	if entry.RunID != wantRunID {
		t.Errorf("entry.RunID = %q, want authenticated knock RunID %q", entry.RunID, wantRunID)
	}
	if entry.User == nil {
		t.Fatal("entry.User is nil")
	}
	if entry.User.UserId != "u-int" {
		t.Errorf("entry.User.UserId = %q, want %q", entry.User.UserId, "u-int")
	}
	if entry.User.OrganizationId != "o-int" {
		t.Errorf("entry.User.OrganizationId = %q, want %q", entry.User.OrganizationId, "o-int")
	}

	// ackMsg.ACTokens must also reflect what the AC issued (this is
	// what the agent receives in the knock ACK). A regression that
	// trims the assignment in the AC goroutine would surface here.
	if got := ackMsg.ACTokens[resName]; got != issuedTok {
		t.Errorf("ackMsg.ACTokens[%q] = %q, want %q", resName, got, issuedTok)
	}
}

func TestPublishACKTokens_LegacySuppliedRunIDStaysUnbound(t *testing.T) {
	const token = "legacy-token"
	s := &UdpServer{tokenStore: common.NewTokenStore[*ACTokenEntry]()}
	err := s.PublishACKTokens(context.Background(), &common.AgentKnockMsg{
		AuthServiceId:      "legacy",
		ResourceId:         "public-resource",
		RunID:              "0123456789abcdef",
		NHPSessionId:       1,
		NHPSessionIssuedAt: time.Now(),
	}, &common.ServerKnockAckMsg{
		SessionId: 1,
		ACTokens:  map[string]string{"resource": token},
	}, "203.0.113.42", 60, "")
	if err != nil {
		t.Fatalf("PublishACKTokens: %v", err)
	}
	entry := s.VerifyAccessToken(token)
	if entry == nil {
		t.Fatal("VerifyAccessToken returned nil")
	}
	if entry.RunID != "" {
		t.Fatalf("legacy entry.RunID = %q, want empty", entry.RunID)
	}
}

// TestHandleNhpOpenResource_PublishACKTokens_NoLeakOnFail fences the
// negative case: when the AC broadcast fails, no entry must be
// persisted under the (empty) token. The handler should still call
// PublishACKTokens — the empty-token skip inside PublishACKTokens is
// what protects us — but a future regression that publishes the
// failure shape directly would corrupt the store.
func TestHandleNhpOpenResource_PublishACKTokens_NoLeakOnFail(t *testing.T) {
	const acId = "ac-int-fail"

	s := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
		acConnectionMap: map[string][]*ACConn{
			acId: {newACConnWithLastRecv(time.Now().UnixNano())},
		},
		processACOperationBroadcastFn: func(
			_ context.Context,
			_ *common.AgentKnockMsg,
			_ []*ACConn,
			_ *common.NetAddress,
			_ []*common.NetAddress,
			_ uint32,
			_ *common.ResourceData,
		) (*common.ACOpsResultMsg, error) {
			// Failure shape: error and an artMsg the production code
			// uses to signal the failure to the agent.
			return &common.ACOpsResultMsg{
				ErrCode: common.ErrACOperationFailed.ErrorCode(),
				ErrMsg:  "synthetic AC failure",
			}, common.ErrACOperationFailed
		},
	}

	knkMsg := &common.AgentKnockMsg{UserId: "u-fail", ResourceId: "r-fail", NHPSessionId: 1, NHPSessionIssuedAt: time.Now()}
	srcAddr := &common.NetAddress{Ip: "198.51.100.4"}
	ackMsg := &common.ServerKnockAckMsg{SessionId: 1}
	req := &common.NhpAuthRequest{Msg: knkMsg, SrcAddr: srcAddr, Ack: ackMsg, SessionId: 1, SessionIssuedAt: knkMsg.NHPSessionIssuedAt}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			ResourceId: "r-fail",
			OpenTime:   30,
			Resources: map[string]*common.ResourceInfo{
				"r-fail": {
					ACId: acId,
					Addr: &common.NetAddress{Ip: "10.0.0.6"},
				},
			},
		},
	}

	_, err := s.handleNhpOpenResource(req, res)
	if err == nil {
		t.Fatal("expected handleNhpOpenResource to return error when every AC op fails")
	}

	// VerifyAccessToken on the empty string — the only "token" the
	// failure shape could have leaked — must be nil.
	if got := s.VerifyAccessToken(""); got != nil {
		t.Errorf("VerifyAccessToken(\"\") returned %+v; the empty-token skip is broken", got)
	}
	if got := ackMsg.ACTokens["r-fail"]; got != "" {
		t.Errorf("ackMsg.ACTokens[r-fail] = %q, want \"\" on failure", got)
	}
}

// TestHandleNhpOpenResource_NilBroadcastResult fences the nil-guard in the
// AC broadcast goroutine: processACOperationBroadcast can return (nil, err)
// on a marshal/guard path, and the artMsgs map must never hold nil — both
// the successCount loop and the failure-log loop deref entries
// unconditionally. Without the guard this panics; with it, the handler
// synthesizes a failure entry and returns the all-failed error cleanly.
func TestHandleNhpOpenResource_NilBroadcastResult(t *testing.T) {
	const acId = "ac-nil-result"

	s := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
		acConnectionMap: map[string][]*ACConn{
			acId: {newACConnWithLastRecv(time.Now().UnixNano())},
		},
		processACOperationBroadcastFn: func(
			_ context.Context,
			_ *common.AgentKnockMsg,
			_ []*ACConn,
			_ *common.NetAddress,
			_ []*common.NetAddress,
			_ uint32,
			_ *common.ResourceData,
		) (*common.ACOpsResultMsg, error) {
			// nil artMsg with an error — the marshal/guard shape that the
			// store-site guard must absorb before the deref loops run.
			return nil, common.ErrACOperationFailed
		},
	}

	knkMsg := &common.AgentKnockMsg{UserId: "u-nil", ResourceId: "r-nil", NHPSessionId: 1, NHPSessionIssuedAt: time.Now()}
	srcAddr := &common.NetAddress{Ip: "198.51.100.9"}
	ackMsg := &common.ServerKnockAckMsg{SessionId: 1}
	req := &common.NhpAuthRequest{Msg: knkMsg, SrcAddr: srcAddr, Ack: ackMsg, SessionId: 1, SessionIssuedAt: knkMsg.NHPSessionIssuedAt}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			ResourceId: "r-nil",
			OpenTime:   30,
			Resources: map[string]*common.ResourceInfo{
				"r-nil": {
					ACId: acId,
					Addr: &common.NetAddress{Ip: "10.0.0.7"},
				},
			},
		},
	}

	// Must not panic on the nil broadcast result, and must report failure.
	_, err := s.handleNhpOpenResource(req, res)
	if err == nil {
		t.Fatal("expected handleNhpOpenResource to return error when the AC broadcast returns a nil result")
	}
	if ackMsg.ErrCode != common.ErrServerACOpsFailed.ErrorCode() {
		t.Errorf("ackMsg.ErrCode = %q, want %q (all-failed shape)", ackMsg.ErrCode, common.ErrServerACOpsFailed.ErrorCode())
	}
}
