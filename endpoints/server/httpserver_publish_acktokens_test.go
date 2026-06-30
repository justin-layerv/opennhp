package server

import (
	"context"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestHandleHttpOpenResource_PublishACKTokens_RoundTrip is the HTTP
// twin of TestHandleNhpOpenResource_PublishACKTokens_RoundTrip in
// udpserver_publish_acktokens_test.go. It fences the same load-bearing
// publication contract on the second knock entry point (HTTP knock,
// reached via /plugins/:aspid and /plugins/:aspid/:resid/valid).
//
// A future PR that drops s.PublishACKTokens from handleHttpOpenResource
// — or reorders it before acWg.Wait() — would leave the UDP test
// passing while silently breaking HTTP-path validate. Two tests are the
// minimum to catch a drift between the paths.
func TestHandleHttpOpenResource_PublishACKTokens_RoundTrip(t *testing.T) {
	const (
		acId      = "ac-http-int-test"
		resName   = "resource-beta"
		issuedTok = "ac-token-from-http-fake"
		knockerIP = "203.0.113.77"
		wantOpen  = uint32(45)
	)

	var (
		gotSrcIp    string
		gotOpenTime uint32
	)

	us := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
		acConnectionMap: map[string][]*ACConn{
			acId: {newACConnWithLastRecv(time.Now().UnixNano())},
		},
		processACOperationBroadcastFn: func(
			_ context.Context,
			_ *common.AgentKnockMsg,
			_ []*ACConn,
			srcAddr *common.NetAddress,
			_ []*common.NetAddress,
			openTime uint32,
			_ *common.ResourceData,
		) (*common.ACOpsResultMsg, error) {
			gotSrcIp = srcAddr.Ip
			gotOpenTime = openTime
			return &common.ACOpsResultMsg{
				ErrCode:  common.ErrSuccess.ErrorCode(),
				ACToken:  issuedTok,
				OpenTime: openTime,
				PreAccessAction: &common.PreAccessInfo{
					AccessIp: "10.0.0.7",
				},
			}, nil
		},
	}
	hs := &HttpServer{udpServer: us}

	req := &common.HttpKnockRequest{
		UserId:         "u-http",
		DeviceId:       "d-http",
		OrganizationId: "o-http",
		AuthServiceId:  "asp-http",
		ResourceId:     resName,
		SrcIp:          knockerIP,
		Ctx:            context.Background(),
	}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			ResourceId: resName,
			OpenTime:   wantOpen,
			Resources: map[string]*common.ResourceInfo{
				resName: {
					ACId: acId,
					Addr: &common.NetAddress{Ip: "10.0.0.7", Port: 443},
				},
			},
		},
	}

	gotAck, err := hs.handleHttpOpenResource(req, res)
	if err != nil {
		t.Fatalf("handleHttpOpenResource returned error: %v", err)
	}
	if gotAck.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Fatalf("ack ErrCode = %q, want success", gotAck.ErrCode)
	}

	if gotSrcIp != knockerIP {
		t.Errorf("seam saw srcIp %q, want %q (req.SrcIp must flow through to the AC call)", gotSrcIp, knockerIP)
	}
	if gotOpenTime != wantOpen {
		t.Errorf("seam saw openTime %d, want %d", gotOpenTime, wantOpen)
	}

	entry := us.VerifyAccessToken(issuedTok)
	if entry == nil {
		t.Fatal("VerifyAccessToken returned nil for the AC-issued token on the HTTP path; the post-Wait PublishACKTokens contract is broken")
	}
	if entry.ResourceId != resName {
		t.Errorf("entry.ResourceId = %q, want %q", entry.ResourceId, resName)
	}
	if entry.KnockSrcIP != knockerIP {
		t.Errorf("entry.KnockSrcIP = %q, want %q — req.SrcIp (set by ctx.ClientIP() upstream) must land in KnockSrcIP for PR-2b's cross-check", entry.KnockSrcIP, knockerIP)
	}
	if entry.OpenTime != int(wantOpen) {
		t.Errorf("entry.OpenTime = %d, want %d", entry.OpenTime, wantOpen)
	}
	if entry.User == nil {
		t.Fatal("entry.User is nil")
	}
	if entry.User.UserId != "u-http" {
		t.Errorf("entry.User.UserId = %q, want %q", entry.User.UserId, "u-http")
	}
	if entry.User.AuthServiceId != "asp-http" {
		t.Errorf("entry.User.AuthServiceId = %q, want %q", entry.User.AuthServiceId, "asp-http")
	}
}

// TestHandleHttpOpenResource_PublishACKTokens_ExitCommand fences the
// NHP_EXT branch of the openTime hoist in handleHttpOpenResource: a
// "exit" command flips knkMsg.HeaderType to NHP_EXT, which drops
// openTime to 1 regardless of res.OpenTime. The downstream stored
// entry must reflect openTime=1 — a regression that re-derives
// openTime inside the AC goroutine could observe the original
// res.OpenTime and store the wrong value, which would extend the
// pinhole-window cross-check past the actual AC pinhole.
func TestHandleHttpOpenResource_PublishACKTokens_ExitCommand(t *testing.T) {
	const (
		acId      = "ac-http-exit"
		resName   = "resource-exit"
		issuedTok = "ac-token-from-http-exit"
	)

	us := &UdpServer{
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
			openTime uint32,
			_ *common.ResourceData,
		) (*common.ACOpsResultMsg, error) {
			return &common.ACOpsResultMsg{
				ErrCode:  common.ErrSuccess.ErrorCode(),
				ACToken:  issuedTok,
				OpenTime: openTime,
			}, nil
		},
	}
	hs := &HttpServer{udpServer: us}

	req := &common.HttpKnockRequest{
		UserId:        "u-exit",
		AuthServiceId: "asp-exit",
		ResourceId:    resName,
		SrcIp:         "203.0.113.78",
		Command:       "exit", // flips HeaderType to NHP_EXT
		Ctx:           context.Background(),
	}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			ResourceId: resName,
			OpenTime:   60, // would be 60 normally; exit must override to 1
			Resources: map[string]*common.ResourceInfo{
				resName: {ACId: acId, Addr: &common.NetAddress{Ip: "10.0.0.8"}},
			},
		},
	}

	if _, err := hs.handleHttpOpenResource(req, res); err != nil {
		t.Fatalf("handleHttpOpenResource returned error: %v", err)
	}

	entry := us.VerifyAccessToken(issuedTok)
	if entry == nil {
		t.Fatal("VerifyAccessToken returned nil for the exit-command AC token")
	}
	if entry.OpenTime != 1 {
		t.Errorf("entry.OpenTime = %d, want 1 (exit command must override res.OpenTime=60)", entry.OpenTime)
	}
}
