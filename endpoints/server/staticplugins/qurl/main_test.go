package qurl

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	nhpserver "github.com/OpenNHP/opennhp/endpoints/server"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestVersion verifies the version string format
func TestVersion(t *testing.T) {
	v := Version()
	if v != "qurl v1.0.0" {
		t.Errorf("Version() = %q, want %q", v, "qurl v1.0.0")
	}
}

// TestClose verifies Close() handles nil resolver gracefully
func TestClose(t *testing.T) {
	// Save and clear resolver
	oldResolver := resolver
	resolver = nil
	defer func() { resolver = oldResolver }()

	// Close should not panic with nil resolver
	err := Close()
	if err != nil {
		t.Errorf("Close() with nil resolver returned error: %v", err)
	}
}

// TestInit_ErrorPropagation verifies that Init returns wrapped errors from NewQurlResolver.
// Note: This test manipulates package-level state and should run in isolation.
func TestInit_ErrorPropagation(t *testing.T) {
	// Save original state (sync.Once cannot be copied, so we just reset it)
	oldResolver := resolver
	oldInitErr := initErr

	// Reset state for this test
	resolver = nil
	initOnce = sync.Once{}
	initErr = nil

	// Restore state after test
	defer func() {
		resolver = oldResolver
		initOnce = sync.Once{} // Reset to fresh Once for next test
		initErr = oldInitErr
	}()

	// Clear all env vars to force an error
	envVars := []string{
		"QURL_API_URL",
		"QURL_SERVICE_TOKEN",
		"QURL_ALLOWED_REDIRECT_DOMAIN",
		"QURL_API_TIMEOUT",
		"QURL_MAX_IDLE_CONNS",
		"QURL_MAX_IDLE_CONNS_PER_HOST",
		"QURL_IDLE_CONN_TIMEOUT",
	}
	for _, key := range envVars {
		t.Setenv(key, "") // registers restore of original value
		os.Unsetenv(key)
	}

	// Call Init - should fail due to missing config
	err := Init(nil)
	if err == nil {
		t.Fatal("Init() with missing config should return error")
	}

	// Verify error is wrapped with [QURL] prefix
	if !strings.Contains(err.Error(), "[QURL] failed to initialize") {
		t.Errorf("Init() error = %q, want to contain %q", err.Error(), "[QURL] failed to initialize")
	}

	// Verify idempotency - second call returns same error
	err2 := Init(nil)
	if !errors.Is(err2, err) {
		t.Errorf("Init() second call returned different error: %v vs %v", err2, err)
	}
}

// TestInit_Success verifies successful initialization with valid config.
func TestInit_Success(t *testing.T) {
	// Save original state (sync.Once cannot be copied, so we just reset it)
	oldResolver := resolver
	oldInitErr := initErr

	// Reset state for this test
	resolver = nil
	initOnce = sync.Once{}
	initErr = nil

	// Restore state after test
	defer func() {
		resolver = oldResolver
		initOnce = sync.Once{} // Reset to fresh Once for next test
		initErr = oldInitErr
	}()

	// Set all required env vars
	envVars := map[string]string{
		"QURL_API_URL":                 "https://qurl-api.test.local",
		"QURL_SERVICE_TOKEN":           "test-token",
		"QURL_ALLOWED_REDIRECT_DOMAIN": "qurl.site",
		"QURL_API_TIMEOUT":             "10",
		"QURL_MAX_IDLE_CONNS":          "10",
		"QURL_MAX_IDLE_CONNS_PER_HOST": "5",
		"QURL_IDLE_CONN_TIMEOUT":       "30",
	}

	// Set env vars (t.Setenv handles save/restore automatically)
	for key, val := range envVars {
		t.Setenv(key, val)
	}

	// Call Init - should succeed
	err := Init(nil)
	if err != nil {
		t.Fatalf("Init() with valid config returned error: %v", err)
	}

	// Verify resolver was created
	if resolver == nil {
		t.Error("Init() succeeded but resolver is nil")
	}

	// Verify idempotency - second call returns nil (same result)
	err2 := Init(nil)
	if err2 != nil {
		t.Errorf("Init() second call returned error: %v", err2)
	}
}

func TestHandleResolveError_KnownErrors_Return403(t *testing.T) {
	// Known token errors return a branded HTML error page to avoid
	// exposing raw JSON to end users in the browser.
	testCases := []struct {
		name string
		err  error
	}{
		{"token not found", ErrTokenNotFound},
		{"token consumed", ErrTokenConsumed},
		{"token expired", ErrTokenExpired},
		{"policy violation", ErrPolicyViolation},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)

			handleResolveError(ctx, tt.err)

			if w.Code != http.StatusForbidden {
				t.Errorf("handleResolveError(%v) status = %d, want %d", tt.err, w.Code, http.StatusForbidden)
			}

			contentType := w.Header().Get("Content-Type")
			if contentType != "text/html; charset=utf-8" {
				t.Errorf("handleResolveError(%v) Content-Type = %q, want text/html", tt.err, contentType)
			}

			body := w.Body.String()
			if !strings.Contains(body, "Access Link Invalid") {
				t.Errorf("handleResolveError(%v) body missing 'Access Link Invalid' title", tt.err)
			}

			if !ctx.IsAborted() {
				t.Errorf("handleResolveError(%v) did not abort context", tt.err)
			}
		})
	}
}

func TestHandleResolveError_InvalidResolve_Return502(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	handleResolveError(ctx, ErrInvalidResolveResponse)

	if w.Code != http.StatusBadGateway {
		t.Errorf("handleResolveError(ErrInvalidResolveResponse) status = %d, want %d", w.Code, http.StatusBadGateway)
	}
	contentType := w.Header().Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html", contentType)
	}
	if !strings.Contains(w.Body.String(), "Access Link Invalid") {
		t.Error("body missing Access Link Invalid title")
	}
	if !ctx.IsAborted() {
		t.Error("context not aborted")
	}
}

func TestHandleResolveError_UnknownErrors_ShowErrorPage(t *testing.T) {
	// Unknown/unexpected errors also show branded error page (no info leaked)
	testCases := []struct {
		name string
		err  error
	}{
		{"service error", ErrServiceError},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)

			handleResolveError(ctx, tt.err)

			if w.Code != http.StatusForbidden {
				t.Errorf("handleResolveError(%v) status = %d, want %d", tt.err, w.Code, http.StatusForbidden)
			}
			body := w.Body.String()
			if !strings.Contains(body, "Access Link Invalid") {
				t.Errorf("handleResolveError(%v) should show branded error page", tt.err)
			}

			if !ctx.IsAborted() {
				t.Errorf("handleResolveError(%v) did not abort context", tt.err)
			}
		})
	}
}

func TestNhpDrop(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	nhpDrop(ctx)

	// httptest.ResponseRecorder doesn't implement http.Hijacker,
	// so nhpDrop falls back to ctx.Abort() — verify that path works
	if !ctx.IsAborted() {
		t.Error("nhpDrop did not abort context")
	}
	if body := w.Body.String(); body != "" {
		t.Errorf("nhpDrop wrote body %q, want empty", body)
	}
}

func TestBuildResourceData(t *testing.T) {
	resp := &ResolveResponse{
		ResourceID:   "r_test123",
		TargetURL:    "https://backend.example.com",
		QurlSiteURL:  "https://r_test123.qurl.site",
		JWTSecret:    "test-secret",
		TokenExpire:  3600,
		OpenTime:     300,
		CookieDomain: ".qurl.site",
	}

	res := buildResourceData(resp)

	if res.ResourceId != "r_test123" {
		t.Errorf("ResourceId = %q, want %q", res.ResourceId, "r_test123")
	}
	if res.AuthServiceId != PluginID {
		t.Errorf("AuthServiceId = %q, want %q", res.AuthServiceId, PluginID)
	}
	if res.OpenTime != 300 {
		t.Errorf("OpenTime = %d, want %d", res.OpenTime, 300)
	}
	if res.RedirectUrl != "https://r_test123.qurl.site" {
		t.Errorf("RedirectUrl = %q, want %q", res.RedirectUrl, "https://r_test123.qurl.site")
	}
	if res.CookieDomain != ".qurl.site" {
		t.Errorf("CookieDomain = %q, want %q", res.CookieDomain, ".qurl.site")
	}

	// Check ExInfo
	if res.ExInfo[ExInfoKeyJWTSecret] != "test-secret" {
		t.Errorf("ExInfo[JWTSecret] = %v, want %q", res.ExInfo[ExInfoKeyJWTSecret], "test-secret")
	}
	if res.ExInfo[ExInfoKeyTokenExpire] != int64(3600) {
		t.Errorf("ExInfo[TokenExpire] = %v, want %d", res.ExInfo[ExInfoKeyTokenExpire], 3600)
	}
}

func TestAuthWithHttp_FullFlow_POST(t *testing.T) {
	// Create mock QURL API server
	qurlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Request-ID"); got != "req-fullflow-123" {
			t.Errorf("expected X-Request-ID=req-fullflow-123, got %q", got)
		}
		if r.URL.Path != "/internal/v1/resolve" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Parse request to get the token
		var req ResolveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Return success response
		resp := internalResolveResponse{
			Success: true,
			Data: &ResolveResponse{
				ResourceID:  "r_test123",
				TargetURL:   "https://backend.example.com",
				QurlSiteURL: "https://r_test123.qurl.site",
				Resources: map[string]*common.ResourceInfo{
					"default": {
						ACId:     "ac-001",
						Hostname: "backend.example.com",
						Addr:     &common.NetAddress{Ip: "10.0.0.1", Port: 443},
					},
				},
				JWTSecret:    "test-jwt-secret-key-for-signing",
				TokenExpire:  3600,
				OpenTime:     300,
				CookieDomain: ".qurl.site",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer qurlServer.Close()

	// Set up package-level resolver for testing
	oldResolver := resolver
	resolver = &QurlResolver{
		httpClient:            &http.Client{Timeout: 5 * time.Second},
		baseURL:               qurlServer.URL,
		serviceToken:          "test-service-token",
		allowedRedirectDomain: "qurl.site",
	}
	defer func() { resolver = oldResolver }()

	// Create gin test context
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	form := "token=valid_test_token_123"
	ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl", strings.NewReader(form))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Set(nhpserver.RequestIDKey, "req-fullflow-123") // simulate requestIDMiddleware

	// Create mock helper with callback
	callbackCalled := false
	helper := &plugins.HttpServerPluginHelper{
		AuthWithHttpCallbackFunc: func(req *common.HttpKnockRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			callbackCalled = true
			// Verify resource data was passed correctly
			if res.ResourceId != "r_test123" {
				t.Errorf("callback received wrong ResourceId: %s", res.ResourceId)
			}
			// Return successful knock response
			return &common.ServerKnockAckMsg{
				ResourceHost: map[string]string{"default": "10.0.0.1:443"},
			}, nil
		},
	}

	// Call the handler
	req := &common.HttpKnockRequest{}
	ackMsg, err := AuthWithHttp(ctx, req, helper)

	// Verify results
	if err != nil {
		t.Fatalf("AuthWithHttp returned unexpected error: %v", err)
	}
	if !callbackCalled {
		t.Error("helper callback was not called")
	}
	if ackMsg == nil {
		t.Fatal("ackMsg is nil")
	}
	if len(ackMsg.ResourceHost) == 0 {
		t.Error("ackMsg has no resource hosts")
	}

	// Verify redirect response.
	// Use ctx.Writer.Status() instead of w.Code: for POST requests, http.Redirect
	// skips the response body, so gin's wrapper never flushes the status to the
	// underlying httptest.ResponseRecorder (w.Code stays at default 200).
	if ctx.Writer.Status() != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, ctx.Writer.Status())
	}
	location := w.Header().Get("Location")
	if location != "https://r_test123.qurl.site" {
		t.Errorf("expected redirect to https://r_test123.qurl.site, got %s", location)
	}
	if got := w.Header().Get("X-Request-ID"); got != "req-fullflow-123" {
		t.Errorf("expected response X-Request-ID=req-fullflow-123, got %q", got)
	}

	// Verify cookies were set
	cookies := w.Result().Cookies()
	var nhpTokenCookie, refreshTokenCookie *http.Cookie
	for _, c := range cookies {
		switch c.Name {
		case CookieNHPToken:
			nhpTokenCookie = c
		case CookieNHPRefreshToken:
			refreshTokenCookie = c
		}
	}
	if nhpTokenCookie == nil {
		t.Fatal("nhp_token cookie not set")
	}
	if refreshTokenCookie == nil {
		t.Fatal("nhp_refresh_token cookie not set")
	}
	// Cookie MaxAge should equal token_expire (3600) when session_duration is not set.
	if nhpTokenCookie.MaxAge != 3600 {
		t.Errorf("nhp_token MaxAge: expected 3600 (token_expire), got %d", nhpTokenCookie.MaxAge)
	}
	if refreshTokenCookie.MaxAge != 3600 {
		t.Errorf("nhp_refresh_token MaxAge: expected 3600 (token_expire), got %d", refreshTokenCookie.MaxAge)
	}
}

// TestAuthWithHttp_FullFlow_GET_BackwardCompat verifies the deprecated GET
// query parameter path still works (backward compatibility).
func TestAuthWithHttp_FullFlow_GET_BackwardCompat(t *testing.T) {
	// Create mock QURL API server
	qurlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := internalResolveResponse{
			Success: true,
			Data: &ResolveResponse{
				ResourceID:  "r_test123",
				TargetURL:   "https://backend.example.com",
				QurlSiteURL: "https://r_test123.qurl.site",
				Resources: map[string]*common.ResourceInfo{
					"default": {
						ACId:     "ac-001",
						Hostname: "backend.example.com",
						Addr:     &common.NetAddress{Ip: "10.0.0.1", Port: 443},
					},
				},
				JWTSecret:    "test-jwt-secret-key-for-signing",
				TokenExpire:  3600,
				OpenTime:     300,
				CookieDomain: ".qurl.site",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer qurlServer.Close()

	oldResolver := resolver
	resolver = &QurlResolver{
		httpClient:            &http.Client{Timeout: 5 * time.Second},
		baseURL:               qurlServer.URL,
		serviceToken:          "test-service-token",
		allowedRedirectDomain: "qurl.site",
	}
	defer func() { resolver = oldResolver }()

	// Create gin test context with GET query param (deprecated path)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/plugins/qurl?token=valid_test_token_123", nil)

	helper := successKnockHelper()
	_, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper)
	if err != nil {
		t.Fatalf("AuthWithHttp GET backward compat returned unexpected error: %v", err)
	}
	if w.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, w.Code)
	}
}

// TestAuthWithHttp_POST_EmptyBody_FallsBackToQuery verifies that a POST with
// an empty body falls back to the query parameter. This path still works but
// logs a deprecation warning — the token is in the URL regardless of method.
func TestAuthWithHttp_POST_EmptyBody_FallsBackToQuery(t *testing.T) {
	qurlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := internalResolveResponse{
			Success: true,
			Data: &ResolveResponse{
				ResourceID:  "r_test123",
				TargetURL:   "https://backend.example.com",
				QurlSiteURL: "https://r_test123.qurl.site",
				Resources: map[string]*common.ResourceInfo{
					"default": {
						ACId:     "ac-001",
						Hostname: "backend.example.com",
						Addr:     &common.NetAddress{Ip: "10.0.0.1", Port: 443},
					},
				},
				JWTSecret:    "test-jwt-secret-key-for-signing",
				TokenExpire:  3600,
				OpenTime:     300,
				CookieDomain: ".qurl.site",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer qurlServer.Close()

	oldResolver := resolver
	resolver = &QurlResolver{
		httpClient:            &http.Client{Timeout: 5 * time.Second},
		baseURL:               qurlServer.URL,
		serviceToken:          "test-service-token",
		allowedRedirectDomain: "qurl.site",
	}
	defer func() { resolver = oldResolver }()

	// POST with empty body but token in query param
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl?token=valid_test_token_123", nil)

	helper := successKnockHelper()
	_, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper)
	if err != nil {
		t.Fatalf("POST with query param fallback returned error: %v", err)
	}
	if ctx.Writer.Status() != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, ctx.Writer.Status())
	}
}

// TestAuthWithHttp_POST_InvalidToken verifies POST with invalid token returns 403.
func TestAuthWithHttp_POST_InvalidToken(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	form := "token=invalid"
	ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl", strings.NewReader(form))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	helper := &plugins.HttpServerPluginHelper{
		AuthWithHttpCallbackFunc: func(req *common.HttpKnockRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			t.Error("callback should not be called for invalid token")
			return nil, nil
		},
	}

	_, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper)
	if err == nil {
		t.Error("expected error for invalid POST token")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("invalid POST token status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

// customDomainTestSetup holds shared state for custom domain test cases.
type customDomainTestSetup struct {
	recorder *httptest.ResponseRecorder
	ctx      *gin.Context
}

// setupCustomDomainTest creates a mock QURL API that returns the given response,
// wires up the package-level resolver, and returns a gin test context.
func setupCustomDomainTest(t *testing.T, resp *ResolveResponse) *customDomainTestSetup {
	t.Helper()

	qurlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(internalResolveResponse{Success: true, Data: resp})
	}))

	oldResolver := resolver
	resolver = &QurlResolver{
		httpClient:            &http.Client{Timeout: 5 * time.Second},
		baseURL:               qurlServer.URL,
		serviceToken:          "test-service-token",
		allowedRedirectDomain: "qurl.site",
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	form := "token=valid_test_token_123"
	ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl", strings.NewReader(form))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	t.Cleanup(func() {
		qurlServer.Close()
		resolver = oldResolver
	})

	return &customDomainTestSetup{
		recorder: w,
		ctx:      ctx,
	}
}

// successKnockHelper returns a helper whose callback always succeeds.
func successKnockHelper() *plugins.HttpServerPluginHelper {
	return &plugins.HttpServerPluginHelper{
		AuthWithHttpCallbackFunc: func(req *common.HttpKnockRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			return &common.ServerKnockAckMsg{
				ResourceHost: map[string]string{"default": "10.0.0.1:443"},
			}, nil
		},
	}
}

func TestAuthWithHttp_CustomDomain_FullFlow(t *testing.T) {
	setup := setupCustomDomainTest(t, &ResolveResponse{
		ResourceID:  "r_custom123",
		TargetURL:   "https://backend.example.com",
		QurlSiteURL: "https://app.mycorp.com",
		Resources: map[string]*common.ResourceInfo{
			"default": {
				ACId:     "ac-001",
				Hostname: "backend.example.com",
				Addr:     &common.NetAddress{Ip: "10.0.0.1", Port: 443},
			},
		},
		JWTSecret:      "test-jwt-secret-key-for-signing",
		TokenExpire:    3600,
		OpenTime:       300,
		CookieDomain:   ".mycorp.com",
		IsCustomDomain: true,
	})

	helper := &plugins.HttpServerPluginHelper{
		AuthWithHttpCallbackFunc: func(req *common.HttpKnockRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			if res.CookieDomain != ".mycorp.com" {
				t.Errorf("callback received wrong CookieDomain: %s", res.CookieDomain)
			}
			if res.RedirectUrl != "https://app.mycorp.com" {
				t.Errorf("callback received wrong RedirectUrl: %s", res.RedirectUrl)
			}
			return &common.ServerKnockAckMsg{
				ResourceHost: map[string]string{"default": "10.0.0.1:443"},
			}, nil
		},
	}

	ackMsg, err := AuthWithHttp(setup.ctx, &common.HttpKnockRequest{}, helper)

	if err != nil {
		t.Fatalf("AuthWithHttp returned unexpected error: %v", err)
	}
	if ackMsg == nil || len(ackMsg.ResourceHost) == 0 {
		t.Fatal("expected resource hosts in ack message")
	}

	// Verify redirect to custom domain (not qurl.site)
	if setup.ctx.Writer.Status() != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, setup.ctx.Writer.Status())
	}
	location := setup.recorder.Header().Get("Location")
	if location != "https://app.mycorp.com" {
		t.Errorf("expected redirect to https://app.mycorp.com, got %s", location)
	}

	// Verify cookies were set with custom domain
	// Note: Go's http.ReadSetCookies strips the leading dot from cookie domains,
	// so ".mycorp.com" becomes "mycorp.com" when read back via w.Result().Cookies().
	cookies := setup.recorder.Result().Cookies()
	for _, c := range cookies {
		if c.Name == CookieNHPToken || c.Name == CookieNHPRefreshToken {
			if c.Domain != "mycorp.com" {
				t.Errorf("cookie %s domain = %q, want %q", c.Name, c.Domain, "mycorp.com")
			}
		}
	}
}

func TestAuthWithHttp_CustomDomain_RejectsHTTPRedirect(t *testing.T) {
	setup := setupCustomDomainTest(t, &ResolveResponse{
		ResourceID:  "r_custom_http",
		TargetURL:   "https://backend.example.com",
		QurlSiteURL: "http://app.mycorp.com", // HTTP - should be rejected
		Resources: map[string]*common.ResourceInfo{
			"default": {
				ACId:     "ac-001",
				Hostname: "backend.example.com",
				Addr:     &common.NetAddress{Ip: "10.0.0.1", Port: 443},
			},
		},
		JWTSecret:      "test-jwt-secret-key-for-signing",
		TokenExpire:    3600,
		OpenTime:       300,
		CookieDomain:   ".mycorp.com",
		IsCustomDomain: true,
	})

	_, err := AuthWithHttp(setup.ctx, &common.HttpKnockRequest{}, successKnockHelper())

	if err == nil {
		t.Fatal("expected error for HTTP custom domain redirect")
	}
	if setup.recorder.Code != http.StatusBadGateway {
		t.Errorf("expected status %d, got %d", http.StatusBadGateway, setup.recorder.Code)
	}
	if !strings.Contains(err.Error(), "invalid redirect URL") {
		t.Errorf("expected 'invalid redirect URL' error, got: %v", err)
	}
}

func TestAuthWithHttp_CustomDomain_RejectsInvalidCookieDomain(t *testing.T) {
	setup := setupCustomDomainTest(t, &ResolveResponse{
		ResourceID:  "r_custom_bad_cookie",
		TargetURL:   "https://backend.example.com",
		QurlSiteURL: "https://app.mycorp.com",
		Resources: map[string]*common.ResourceInfo{
			"default": {
				ACId:     "ac-001",
				Hostname: "backend.example.com",
				Addr:     &common.NetAddress{Ip: "10.0.0.1", Port: 443},
			},
		},
		JWTSecret:      "test-jwt-secret-key-for-signing",
		TokenExpire:    3600,
		OpenTime:       300,
		CookieDomain:   "mycorp.com", // missing leading dot
		IsCustomDomain: true,
	})

	_, err := AuthWithHttp(setup.ctx, &common.HttpKnockRequest{}, successKnockHelper())

	if err == nil {
		t.Fatal("expected error for custom domain cookie domain without leading dot")
	}
	if setup.recorder.Code != http.StatusBadGateway {
		t.Errorf("expected status %d, got %d", http.StatusBadGateway, setup.recorder.Code)
	}
	if !strings.Contains(err.Error(), "invalid cookie domain") {
		t.Errorf("expected 'invalid cookie domain' error, got: %v", err)
	}
}

func TestAuthWithHttp_GeneratesRequestIDWhenMissing(t *testing.T) {
	var downstreamReqID string
	qurlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downstreamReqID = r.Header.Get("X-Request-ID")
		resp := internalResolveResponse{
			Success: true,
			Data: &ResolveResponse{
				ResourceID:  "r_generated",
				QurlSiteURL: "https://r_generated.qurl.site",
				Resources: map[string]*common.ResourceInfo{
					"default": {
						ACId:     "ac-001",
						Hostname: "backend.example.com",
						Addr:     &common.NetAddress{Ip: "10.0.0.1", Port: 443},
					},
				},
				JWTSecret:    "test-jwt-secret-key-for-signing",
				TokenExpire:  3600,
				OpenTime:     300,
				CookieDomain: ".qurl.site",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer qurlServer.Close()

	oldResolver := resolver
	resolver = &QurlResolver{
		httpClient:            &http.Client{Timeout: 5 * time.Second},
		baseURL:               qurlServer.URL,
		serviceToken:          "test-service-token",
		allowedRedirectDomain: "qurl.site",
	}
	defer func() { resolver = oldResolver }()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	form := "token=valid_generated_token_123"
	ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl", strings.NewReader(form))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	helper := &plugins.HttpServerPluginHelper{
		AuthWithHttpCallbackFunc: func(req *common.HttpKnockRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			return &common.ServerKnockAckMsg{
				ResourceHost: map[string]string{"default": "10.0.0.1:443"},
			}, nil
		},
	}

	req := &common.HttpKnockRequest{}
	_, err := AuthWithHttp(ctx, req, helper)
	if err != nil {
		t.Fatalf("AuthWithHttp returned unexpected error: %v", err)
	}

	respReqID := w.Header().Get("X-Request-ID")
	if respReqID == "" {
		t.Fatal("expected response X-Request-ID to be set")
	}
	if _, err := uuid.Parse(respReqID); err != nil {
		t.Fatalf("expected generated X-Request-ID to be a UUID, got %q", respReqID)
	}
	if downstreamReqID != respReqID {
		t.Fatalf("expected downstream X-Request-ID %q, got %q", respReqID, downstreamReqID)
	}
}

func TestAuthWithHttp_InvalidToken(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	form := "token="
	ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl", strings.NewReader(form))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	helper := &plugins.HttpServerPluginHelper{
		AuthWithHttpCallbackFunc: func(req *common.HttpKnockRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			t.Error("callback should not be called for invalid token")
			return nil, nil
		},
	}

	req := &common.HttpKnockRequest{}
	_, err := AuthWithHttp(ctx, req, helper)

	if err == nil {
		t.Error("expected error for empty token")
	}
	// Invalid tokens show the same branded error page as expired/consumed tokens
	if w.Code != http.StatusForbidden {
		t.Errorf("invalid token status = %d, want %d", w.Code, http.StatusForbidden)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Access Link Invalid") {
		t.Errorf("invalid token should show branded error page, got: %s", body[:min(len(body), 200)])
	}
	if !ctx.IsAborted() {
		t.Error("invalid token should abort context")
	}
}

func TestAuthWithHttp_NilHelper(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/plugins/qurl?token=valid_token_123", nil)

	req := &common.HttpKnockRequest{}
	_, err := AuthWithHttp(ctx, req, nil)

	if err == nil {
		t.Error("expected error for nil helper")
	}
	if !strings.Contains(err.Error(), "helper is null") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAuthWithHttp_ResolverError(t *testing.T) {
	// Create mock QURL API server that returns an error
	qurlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		resp := internalResolveResponse{
			Success: false,
			Error: &resolveError{
				Code:    "token_not_found",
				Message: "Token not found",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer qurlServer.Close()

	// Set up package-level resolver for testing
	oldResolver := resolver
	resolver = &QurlResolver{
		httpClient:            &http.Client{Timeout: 5 * time.Second},
		baseURL:               qurlServer.URL,
		serviceToken:          "test-service-token",
		allowedRedirectDomain: "qurl.site",
	}
	defer func() { resolver = oldResolver }()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	form := "token=unknown_token_123"
	ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl", strings.NewReader(form))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	helper := &plugins.HttpServerPluginHelper{
		AuthWithHttpCallbackFunc: func(req *common.HttpKnockRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			t.Error("callback should not be called when resolver fails")
			return nil, nil
		},
	}

	req := &common.HttpKnockRequest{}
	_, err := AuthWithHttp(ctx, req, helper)

	if err == nil {
		t.Error("expected error when resolver fails")
	}
	// Known token errors return branded HTML error page (avoids CloudFront 502 from silent drop)
	if w.Code != http.StatusForbidden {
		t.Errorf("resolver error status = %d, want %d", w.Code, http.StatusForbidden)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Access Link Invalid") {
		t.Errorf("expected branded HTML error page, got: %s", body[:min(len(body), 200)])
	}
	if !ctx.IsAborted() {
		t.Error("resolver error should abort context")
	}
}

func TestAuthWithHttp_KnockRetrySuccess(t *testing.T) {
	// Create mock QURL API server that returns success
	qurlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := internalResolveResponse{
			Success: true,
			Data: &ResolveResponse{
				ResourceID:  "r_retry",
				TargetURL:   "https://backend.example.com",
				QurlSiteURL: "https://r_retry.qurl.site",
				Resources: map[string]*common.ResourceInfo{
					"default": {
						ACId:     "ac-001",
						Hostname: "backend.example.com",
						Addr:     &common.NetAddress{Ip: "10.0.0.1", Port: 443},
					},
				},
				JWTSecret:    "test-jwt-secret-key-for-signing",
				TokenExpire:  3600,
				OpenTime:     300,
				CookieDomain: ".qurl.site",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer qurlServer.Close()

	oldResolver := resolver
	resolver = &QurlResolver{
		httpClient:            &http.Client{Timeout: 5 * time.Second},
		baseURL:               qurlServer.URL,
		serviceToken:          "test-service-token",
		allowedRedirectDomain: "qurl.site",
	}
	defer func() { resolver = oldResolver }()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	form := "token=valid_test_token_123"
	ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl", strings.NewReader(form))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// First knock fails, second succeeds
	var attempts int
	helper := &plugins.HttpServerPluginHelper{
		AuthWithHttpCallbackFunc: func(req *common.HttpKnockRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			attempts++
			if attempts == 1 {
				return nil, errors.New("AC connection closed")
			}
			return &common.ServerKnockAckMsg{
				ResourceHost: map[string]string{"default": "10.0.0.1:443"},
			}, nil
		},
	}

	req := &common.HttpKnockRequest{}
	ackMsg, err := AuthWithHttp(ctx, req, helper)

	if err != nil {
		t.Fatalf("expected success after retry, got error: %v", err)
	}
	if attempts != 2 {
		t.Errorf("expected exactly 2 knock attempts, got %d", attempts)
	}
	if ackMsg == nil || len(ackMsg.ResourceHost) == 0 {
		t.Error("expected resource hosts in ack message")
	}
	if ctx.Writer.Status() != http.StatusFound {
		t.Errorf("expected redirect (302), got %d", ctx.Writer.Status())
	}
}

func TestAuthWithHttp_KnockRetryExhausted(t *testing.T) {
	// Create mock QURL API server that returns success
	qurlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := internalResolveResponse{
			Success: true,
			Data: &ResolveResponse{
				ResourceID:  "r_fail",
				TargetURL:   "https://backend.example.com",
				QurlSiteURL: "https://r_fail.qurl.site",
				Resources: map[string]*common.ResourceInfo{
					"default": {
						ACId:     "ac-001",
						Hostname: "backend.example.com",
						Addr:     &common.NetAddress{Ip: "10.0.0.1", Port: 443},
					},
				},
				JWTSecret:    "test-jwt-secret-key-for-signing",
				TokenExpire:  3600,
				OpenTime:     300,
				CookieDomain: ".qurl.site",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer qurlServer.Close()

	oldResolver := resolver
	resolver = &QurlResolver{
		httpClient:            &http.Client{Timeout: 5 * time.Second},
		baseURL:               qurlServer.URL,
		serviceToken:          "test-service-token",
		allowedRedirectDomain: "qurl.site",
	}
	defer func() { resolver = oldResolver }()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	form := "token=valid_test_token_123"
	ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl", strings.NewReader(form))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Both knock attempts fail
	var attempts int
	helper := &plugins.HttpServerPluginHelper{
		AuthWithHttpCallbackFunc: func(req *common.HttpKnockRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			attempts++
			return nil, errors.New("AC connection closed")
		},
	}

	req := &common.HttpKnockRequest{}
	_, err := AuthWithHttp(ctx, req, helper)

	if err == nil {
		t.Fatal("expected error after all attempts fail")
	}
	if attempts != knockMaxAttempts {
		t.Errorf("expected %d knock attempts, got %d", knockMaxAttempts, attempts)
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	if body["error"] != "knock_failed" {
		t.Errorf("expected error='knock_failed', got %q", body["error"])
	}
}

// TestBuildResourceData_ExInfoKeys verifies that buildResourceData includes
// all required ExInfo keys, including SessionDuration for per-QURL session control.
func TestBuildResourceData_ExInfoKeys(t *testing.T) {
	resp := &ResolveResponse{
		ResourceID:      "r_test",
		JWTSecret:       "secret",
		TokenExpire:     3600,
		SessionDuration: 900,
		OpenTime:        300,
		CookieDomain:    ".qurl.site",
		QurlSiteURL:     "https://r_test.qurl.site",
		Resources:       map[string]*common.ResourceInfo{},
	}

	data := buildResourceData(resp)

	// Verify all ExInfo keys are present
	if data.ExInfo[ExInfoKeyJWTSecret] != "secret" {
		t.Errorf("ExInfo[JWTSecret] = %v, want %q", data.ExInfo[ExInfoKeyJWTSecret], "secret")
	}
	if data.ExInfo[ExInfoKeyTokenExpire] != int64(3600) {
		t.Errorf("ExInfo[TokenExpire] = %v, want 3600", data.ExInfo[ExInfoKeyTokenExpire])
	}
	if data.ExInfo[ExInfoKeySessionDuration] != 900 {
		t.Errorf("ExInfo[SessionDuration] = %v, want 900", data.ExInfo[ExInfoKeySessionDuration])
	}

	// Verify SessionDuration=0 is also propagated (NHP server needs to see it)
	resp.SessionDuration = 0
	data = buildResourceData(resp)
	if data.ExInfo[ExInfoKeySessionDuration] != 0 {
		t.Errorf("ExInfo[SessionDuration] = %v, want 0", data.ExInfo[ExInfoKeySessionDuration])
	}
}

// TestAuthWithHttp_SessionDuration verifies that per-QURL session_duration
// overrides token_expire for the NHP cookie MaxAge.
func TestAuthWithHttp_SessionDuration(t *testing.T) {
	setup := setupCustomDomainTest(t, &ResolveResponse{
		ResourceID:      "r_sessiondur",
		TargetURL:       "https://backend.example.com",
		QurlSiteURL:     "https://r_sessiondur.qurl.site",
		Resources:       map[string]*common.ResourceInfo{"default": {ACId: "ac-001", Hostname: "backend.example.com", Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443}}},
		JWTSecret:       "test-jwt-secret-key-for-signing",
		TokenExpire:     3600, // 1 hour global default
		SessionDuration: 900,  // 15 minutes per-QURL override
		OpenTime:        300,
		CookieDomain:    ".qurl.site",
	})

	_, err := AuthWithHttp(setup.ctx, &common.HttpKnockRequest{}, successKnockHelper())
	if err != nil {
		t.Fatalf("AuthWithHttp returned unexpected error: %v", err)
	}

	// Verify NHP cookies use session_duration (900s) not token_expire (3600s)
	cookies := setup.recorder.Result().Cookies()
	var foundTTLCookie bool
	for _, c := range cookies {
		if c.Name == CookieNHPToken || c.Name == CookieNHPRefreshToken {
			if c.MaxAge != 900 {
				t.Errorf("cookie %s: expected MaxAge=900 (session_duration), got %d", c.Name, c.MaxAge)
			}
		}
		if c.Name == CookieNHPSessionTTL {
			foundTTLCookie = true
			if c.Value != "900" {
				t.Errorf("cookie %s: expected value='900', got %q", c.Name, c.Value)
			}
			if c.MaxAge != 900 {
				t.Errorf("cookie %s: expected MaxAge=900, got %d", c.Name, c.MaxAge)
			}
		}
	}
	if !foundTTLCookie {
		t.Error("nhp_session_ttl cookie not set")
	}
}

// TestAuthWithHttp_SessionDurationDefault verifies that when session_duration
// is 0 (not set), the NHP cookie uses token_expire as MaxAge.
func TestAuthWithHttp_SessionDurationDefault(t *testing.T) {
	setup := setupCustomDomainTest(t, &ResolveResponse{
		ResourceID:      "r_sessiondefault",
		TargetURL:       "https://backend.example.com",
		QurlSiteURL:     "https://r_sessiondefault.qurl.site",
		Resources:       map[string]*common.ResourceInfo{"default": {ACId: "ac-001", Hostname: "backend.example.com", Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443}}},
		JWTSecret:       "test-jwt-secret-key-for-signing",
		TokenExpire:     3600, // 1 hour
		SessionDuration: 0,    // not set — should fall back to token_expire
		OpenTime:        300,
		CookieDomain:    ".qurl.site",
	})

	_, err := AuthWithHttp(setup.ctx, &common.HttpKnockRequest{}, successKnockHelper())
	if err != nil {
		t.Fatalf("AuthWithHttp returned unexpected error: %v", err)
	}

	// Verify NHP cookies use token_expire (3600s) when session_duration is 0
	cookies := setup.recorder.Result().Cookies()
	var foundTTLCookie bool
	for _, c := range cookies {
		if c.Name == CookieNHPToken || c.Name == CookieNHPRefreshToken {
			if c.MaxAge != 3600 {
				t.Errorf("cookie %s: expected MaxAge=3600 (token_expire fallback), got %d", c.Name, c.MaxAge)
			}
		}
		if c.Name == CookieNHPSessionTTL {
			foundTTLCookie = true
			if c.Value != "3600" {
				t.Errorf("cookie %s: expected value='3600' (token_expire fallback), got %q", c.Name, c.Value)
			}
		}
	}
	if !foundTTLCookie {
		t.Error("nhp_session_ttl cookie not set")
	}
}
