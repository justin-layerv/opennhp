package qurl

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// setTestResolver points the package-level resolver at a fake /authorize server
// and restores the previous value at test end.
func setTestResolver(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	prev := resolver
	resolver = &QurlResolver{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      server.URL,
		serviceToken: "test-token",
	}
	t.Cleanup(func() { resolver = prev })
}

func testAspData(resourceID string, openTime uint32) *common.AuthServiceProviderData {
	return &common.AuthServiceProviderData{
		AuthSvcId: PluginID,
		ResourceGroups: common.ResourceGroupMap{
			resourceID: &common.ResourceData{
				ResourceGroup: common.ResourceGroup{
					AuthServiceId: PluginID,
					ResourceId:    resourceID,
					OpenTime:      openTime,
					Resources: map[string]*common.ResourceInfo{
						"ac-1": {ACId: "ac-1", Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443}},
					},
				},
				SkipAuth: true,
			},
		},
	}
}

func testAuthReq(resourceID string) *common.NhpAuthRequest {
	return &common.NhpAuthRequest{
		Msg:       &common.AgentKnockMsg{ResourceId: resourceID, UserId: "u"},
		Ack:       &common.ServerKnockAckMsg{},
		PublicKey: "dGVzdC1wdWJrZXk=",
		SrcAddr:   &common.NetAddress{Ip: "203.0.113.7", Port: 44444},
	}
}

func TestAuthWithNHP_Allow_OpensPinhole_CapsOpenTime(t *testing.T) {
	setTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"remaining_seconds":20}`)) // < catalog OpenTime 60 -> cap to 20
	})
	const resID = "r_allow000000"
	var opened bool
	var openedOpenTime uint32
	helper := &plugins.NhpServerPluginHelper{
		AspData: testAspData(resID, 60),
		AuthWithNhpCallbackFunc: func(req *common.NhpAuthRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			opened = true
			openedOpenTime = res.OpenTime
			req.Ack.ErrCode = common.ErrSuccess.ErrorCode()
			return req.Ack, nil
		},
	}
	ack, err := AuthWithNHP(testAuthReq(resID), helper)
	if err != nil {
		t.Fatalf("AuthWithNHP: %v", err)
	}
	if !opened {
		t.Fatal("pinhole callback was not invoked on allow")
	}
	if openedOpenTime != 20 {
		t.Errorf("open_time handed to callback = %d, want capped 20", openedOpenTime)
	}
	// The capped value must also reach the wire ACK (ackMsg.OpenTime), or the
	// agent's open-timer resets to 0 and hammers the server.
	if ack.OpenTime != 20 {
		t.Errorf("ack.OpenTime = %d, want capped 20 on the wire", ack.OpenTime)
	}
	if ack.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Errorf("ack.ErrCode = %q, want success", ack.ErrCode)
	}
}

func TestAuthWithNHP_Bootstrap_ResolvesTokenRegistersPubkeyAndOpens(t *testing.T) {
	const (
		accessToken = "at_1234567890123456789012"
		userAgent   = "Mozilla/5.0 qurl-link-test"
		publicKey   = "mN5hEQiIhhwAhpiIxbgMsAqf6x9SZB8Z1Z4h6q67AD4="
		resourceID  = "r_bootstrap01"
		redirectURL = "https://r_bootstrap01.qurl.site"
	)

	setTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/browser-relay/resolve" {
			t.Errorf("resolve path = %s, want /internal/v1/browser-relay/resolve", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get(ServiceTokenHeader); got != "test-token" {
			t.Errorf("%s = %q, want test-token", ServiceTokenHeader, got)
		}

		var got BrowserRelayResolveRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode browser relay resolve request: %v", err)
		}
		if got.AccessToken != accessToken {
			t.Errorf("access_token = %q, want %q", got.AccessToken, accessToken)
		}
		if got.SrcIP != "203.0.113.7" {
			t.Errorf("src_ip = %q, want 203.0.113.7", got.SrcIP)
		}
		if got.UserAgent != userAgent {
			t.Errorf("user_agent = %q, want %q", got.UserAgent, userAgent)
		}
		if got.AuthenticatedAgentPublicKey != publicKey {
			t.Errorf("authenticated_agent_public_key = %q, want %q", got.AuthenticatedAgentPublicKey, publicKey)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(internalResolveResponse{
			Success: true,
			Data: &ResolveResponse{
				ResourceID:    resourceID,
				NHPResourceID: testNHPResourceID,
				QurlSiteURL:   redirectURL,
				JWTSecret:     "test-jwt-secret",
				TokenExpire:   3600,
				OpenTime:      20,
				CookieDomain:  ".qurl.site",
			},
		})
	})

	req := testAuthReq(qurlBootstrapResourceID)
	req.PublicKey = publicKey
	req.Msg.AuthServiceId = PluginID
	req.Msg.UserData = map[string]any{
		qurlAccessTokenUserDataKey: accessToken,
		qurlUserAgentUserDataKey:   userAgent,
	}

	var catalogResolved bool
	var opened bool
	helper := &plugins.NhpServerPluginHelper{
		AspData: testAspData("unused-bootstrap-sentinel", 60),
		ResolveResourceFunc: func(aspID, resID, srcIP string) (*common.ResourceData, error) {
			catalogResolved = true
			if aspID != PluginID {
				t.Errorf("catalog aspID = %q, want %q", aspID, PluginID)
			}
			if resID != testNHPResourceID {
				t.Errorf("catalog resID = %q, want %q", resID, testNHPResourceID)
			}
			if srcIP != "203.0.113.7" {
				t.Errorf("catalog srcIP = %q, want 203.0.113.7", srcIP)
			}
			return &common.ResourceData{
				ResourceGroup: common.ResourceGroup{
					AuthServiceId: aspID,
					ResourceId:    resID,
					OpenTime:      60,
					Resources: map[string]*common.ResourceInfo{
						"ac-1": {ACId: "ac-1", Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443}},
					},
				},
				SkipAuth: true,
			}, nil
		},
		AuthWithNhpCallbackFunc: func(req *common.NhpAuthRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			opened = true
			if req.Msg.ResourceId != resourceID {
				t.Errorf("knock ResourceId passed to callback = %q, want public resource id %q", req.Msg.ResourceId, resourceID)
			}
			if res.ResourceId != resourceID {
				t.Errorf("opened ResourceId = %q, want %q", res.ResourceId, resourceID)
			}
			if res.OpenTime != 20 {
				t.Errorf("opened OpenTime = %d, want qurl-service clamp 20", res.OpenTime)
			}
			if res.RedirectUrl != redirectURL {
				t.Errorf("opened RedirectUrl = %q, want %q", res.RedirectUrl, redirectURL)
			}
			req.Ack.ErrCode = common.ErrSuccess.ErrorCode()
			return req.Ack, nil
		},
	}

	ack, err := AuthWithNHP(req, helper)
	if err != nil {
		t.Fatalf("AuthWithNHP bootstrap: %v", err)
	}
	if !catalogResolved {
		t.Fatal("bootstrap did not resolve AC routing from the NHP catalog")
	}
	if !opened {
		t.Fatal("bootstrap did not open the AC pinhole")
	}
	if ack.OpenTime != 20 {
		t.Errorf("ack.OpenTime = %d, want 20", ack.OpenTime)
	}
	if ack.RedirectUrl != redirectURL {
		t.Errorf("ack.RedirectUrl = %q, want %q", ack.RedirectUrl, redirectURL)
	}
}

func TestAuthWithNHP_BootstrapTerminalDeny_NoPinhole(t *testing.T) {
	setTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/browser-relay/resolve" {
			t.Errorf("resolve path = %s, want browser-relay endpoint", r.URL.Path)
		}
		w.WriteHeader(http.StatusGone)
		_ = json.NewEncoder(w).Encode(internalResolveResponse{
			Success: false,
			Error:   &resolveError{Code: "token_consumed", Message: "token consumed"},
		})
	})

	req := testAuthReq(qurlBootstrapResourceID)
	req.Msg.AuthServiceId = PluginID
	req.Msg.UserData = map[string]any{
		qurlAccessTokenUserDataKey: "at_1234567890123456789012",
		qurlUserAgentUserDataKey:   "Mozilla/5.0 qurl-link-test",
	}

	opened := false
	helper := &plugins.NhpServerPluginHelper{
		AspData:             testAspData("unused-bootstrap-sentinel", 60),
		ResolveResourceFunc: defaultCatalogResolver(),
		AuthWithNhpCallbackFunc: func(*common.NhpAuthRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			opened = true
			return nil, nil
		},
	}
	ack, err := AuthWithNHP(req, helper)
	if err == nil {
		t.Fatal("expected bootstrap terminal deny")
	}
	if opened {
		t.Fatal("terminal token denial must not open the AC pinhole")
	}
	if ack.ErrCode != common.ErrQurlSessionExpired.ErrorCode() {
		t.Errorf("ack.ErrCode = %q, want qurl-session-expired", ack.ErrCode)
	}
}

func TestAuthWithNHP_BootstrapAgentIdentityConflict_NoPinhole(t *testing.T) {
	setTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/browser-relay/resolve" {
			t.Errorf("resolve path = %s, want browser-relay endpoint", r.URL.Path)
		}
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(internalResolveResponse{
			Success: false,
			Error:   &resolveError{Code: "agent_identity_conflict", Message: "agent identity conflict"},
		})
	})

	req := testAuthReq(qurlBootstrapResourceID)
	req.Msg.AuthServiceId = PluginID
	req.Msg.UserData = map[string]any{
		qurlAccessTokenUserDataKey: "at_1234567890123456789012",
		qurlUserAgentUserDataKey:   "Mozilla/5.0 qurl-link-test",
	}

	opened := false
	helper := &plugins.NhpServerPluginHelper{
		AspData:             testAspData("unused-bootstrap-sentinel", 60),
		ResolveResourceFunc: defaultCatalogResolver(),
		AuthWithNhpCallbackFunc: func(*common.NhpAuthRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			opened = true
			return nil, nil
		},
	}
	ack, err := AuthWithNHP(req, helper)
	if err == nil {
		t.Fatal("expected bootstrap terminal deny")
	}
	if opened {
		t.Fatal("agent identity conflict must not open the AC pinhole")
	}
	if ack.ErrCode != common.ErrQurlSessionExpired.ErrorCode() {
		t.Errorf("ack.ErrCode = %q, want qurl-session-expired", ack.ErrCode)
	}
}

func TestAuthWithNHP_TransientError_MapsToApiFailed(t *testing.T) {
	setTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	const resID = "r_transient00"
	opened := false
	helper := &plugins.NhpServerPluginHelper{
		AspData: testAspData(resID, 60),
		AuthWithNhpCallbackFunc: func(*common.NhpAuthRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			opened = true
			return nil, nil
		},
	}
	ack, err := AuthWithNHP(testAuthReq(resID), helper)
	if err == nil || opened {
		t.Errorf("transient authorize error must reject without opening; err=%v opened=%v", err, opened)
	}
	if ack.ErrCode != common.ErrKnockApiRequestFailed.ErrorCode() {
		t.Errorf("ack.ErrCode = %q, want knock-api-request-failed", ack.ErrCode)
	}
	// The wire ErrMsg must not leak the internal qurl-service URL / client_ip
	// (the detailed error is logged server-side, not echoed to the agent).
	if strings.Contains(ack.ErrMsg, "http") || strings.Contains(ack.ErrMsg, "client_ip") || strings.Contains(ack.ErrMsg, "127.0.0.1") {
		t.Errorf("transient ACK ErrMsg leaks internal detail: %q", ack.ErrMsg)
	}
}

func TestAuthWithNHP_ZeroCatalogOpenTime_FallsBackToRemaining(t *testing.T) {
	// A catalog row with OpenTime==0 must not produce a zero-duration pinhole
	// (which would reset the agent's open-timer). With a valid session it falls
	// back to the session's remaining lifetime.
	setTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"remaining_seconds":30}`))
	})
	const resID = "r_zerocfg0000"
	var openedOpenTime uint32
	helper := &plugins.NhpServerPluginHelper{
		AspData: testAspData(resID, 0), // catalog OpenTime == 0 (unset/misconfigured)
		AuthWithNhpCallbackFunc: func(req *common.NhpAuthRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			openedOpenTime = res.OpenTime
			return req.Ack, nil
		},
	}
	ack, err := AuthWithNHP(testAuthReq(resID), helper)
	if err != nil {
		t.Fatalf("AuthWithNHP: %v", err)
	}
	if openedOpenTime != 30 || ack.OpenTime != 30 {
		t.Errorf("open_time=%d ack.OpenTime=%d, want session remaining 30 (never 0) for a zero catalog OpenTime", openedOpenTime, ack.OpenTime)
	}
}

func TestAuthWithNHP_Allow_DoesNotCapWhenSessionLonger(t *testing.T) {
	setTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"remaining_seconds":3600}`)) // > catalog OpenTime -> keep catalog OpenTime
	})
	const resID = "r_nocap000000"
	var openedOpenTime uint32
	helper := &plugins.NhpServerPluginHelper{
		AspData: testAspData(resID, 60),
		AuthWithNhpCallbackFunc: func(req *common.NhpAuthRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			openedOpenTime = res.OpenTime
			return req.Ack, nil
		},
	}
	if _, err := AuthWithNHP(testAuthReq(resID), helper); err != nil {
		t.Fatalf("AuthWithNHP: %v", err)
	}
	if openedOpenTime != 60 {
		t.Errorf("open_time = %d, want unchanged catalog value 60", openedOpenTime)
	}
}

func TestAuthWithNHP_Deny_NoPinhole(t *testing.T) {
	setTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	const resID = "r_deny0000000"
	opened := false
	helper := &plugins.NhpServerPluginHelper{
		AspData: testAspData(resID, 60),
		AuthWithNhpCallbackFunc: func(*common.NhpAuthRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			opened = true
			return nil, nil
		},
	}
	ack, err := AuthWithNHP(testAuthReq(resID), helper)
	if err == nil {
		t.Fatal("expected deny error")
	}
	if opened {
		t.Error("pinhole must NOT open on deny")
	}
	if ack.ErrCode != common.ErrQurlSessionExpired.ErrorCode() {
		t.Errorf("ack.ErrCode = %q, want qurl-session-expired (deny)", ack.ErrCode)
	}
}

func TestAuthWithNHP_ZeroRemainingNonTunnel_Denied(t *testing.T) {
	// A non-tunnel 200 with remaining_seconds:0 is a contract violation; it must
	// fail closed (deny), NOT fall through and open a full-OpenTime pinhole.
	setTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"remaining_seconds":0}`))
	})
	const resID = "r_zerolife000"
	opened := false
	helper := &plugins.NhpServerPluginHelper{
		AspData: testAspData(resID, 60),
		AuthWithNhpCallbackFunc: func(*common.NhpAuthRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			opened = true
			return nil, nil
		},
	}
	ack, err := AuthWithNHP(testAuthReq(resID), helper)
	if err == nil || opened {
		t.Errorf("zero-remaining non-tunnel must deny without opening; err=%v opened=%v", err, opened)
	}
	if ack.ErrCode != common.ErrQurlSessionExpired.ErrorCode() {
		t.Errorf("ack.ErrCode = %q, want qurl-session-expired", ack.ErrCode)
	}
}

func TestAuthWithNHP_Tunnel_Rejected(t *testing.T) {
	setTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"remaining_seconds":0,"tunnel":true}`))
	})
	const resID = "r_tunnel00000"
	opened := false
	helper := &plugins.NhpServerPluginHelper{
		AspData: testAspData(resID, 60),
		AuthWithNhpCallbackFunc: func(*common.NhpAuthRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			opened = true
			return nil, nil
		},
	}
	if _, err := AuthWithNHP(testAuthReq(resID), helper); err == nil || opened {
		t.Errorf("tunnel resource must be rejected without opening; err=%v opened=%v", err, opened)
	}
}

func TestAuthWithNHP_ResourceNotInCatalog(t *testing.T) {
	setTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("/authorize must not be called when the resource is absent from the catalog")
	})
	helper := &plugins.NhpServerPluginHelper{
		AspData:                 testAspData("r_other000000", 60),
		AuthWithNhpCallbackFunc: func(*common.NhpAuthRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) { return nil, nil },
	}
	ack, err := AuthWithNHP(testAuthReq("r_missing0000"), helper)
	if err == nil || ack.ErrCode != common.ErrResourceNotFound.ErrorCode() {
		t.Errorf("want ErrResourceNotFound, got err=%v code=%q", err, ack.ErrCode)
	}
}

func TestAuthWithNHP_GuardsReject(t *testing.T) {
	setTestResolver(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	const resID = "r_guard000000"
	mkHelper := func() *plugins.NhpServerPluginHelper {
		return &plugins.NhpServerPluginHelper{
			AspData:                 testAspData(resID, 60),
			AuthWithNhpCallbackFunc: func(*common.NhpAuthRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) { return nil, nil },
		}
	}

	t.Run("missing pubkey", func(t *testing.T) {
		req := testAuthReq(resID)
		req.PublicKey = ""
		if _, err := AuthWithNHP(req, mkHelper()); err == nil {
			t.Error("missing pubkey must reject")
		}
	})
	t.Run("missing src addr", func(t *testing.T) {
		req := testAuthReq(resID)
		req.SrcAddr = nil
		if _, err := AuthWithNHP(req, mkHelper()); err == nil {
			t.Error("missing src addr must reject")
		}
	})
	t.Run("nil AspData", func(t *testing.T) {
		h := &plugins.NhpServerPluginHelper{
			AuthWithNhpCallbackFunc: func(*common.NhpAuthRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) { return nil, nil },
		}
		if _, err := AuthWithNHP(testAuthReq(resID), h); err == nil {
			t.Error("nil AspData must reject")
		}
	})
	t.Run("nil callback", func(t *testing.T) {
		h := &plugins.NhpServerPluginHelper{AspData: testAspData(resID, 60)}
		if _, err := AuthWithNHP(testAuthReq(resID), h); err == nil {
			t.Error("nil AuthWithNhpCallbackFunc must reject")
		}
	})
	t.Run("nil resolver", func(t *testing.T) {
		prev := resolver
		resolver = nil
		defer func() { resolver = prev }()
		if _, err := AuthWithNHP(testAuthReq(resID), mkHelper()); err == nil {
			t.Error("nil resolver must reject")
		}
	})
}
