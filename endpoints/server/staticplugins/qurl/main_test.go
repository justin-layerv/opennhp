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
	// Known token errors return generic 403 to avoid CloudFront 502s
	// from silent connection drops behind CDN infrastructure.
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

			var body map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("handleResolveError(%v) response not valid JSON: %v", tt.err, err)
			}
			if body["error"] != "access_denied" {
				t.Errorf("handleResolveError(%v) error = %q, want \"access_denied\"", tt.err, body["error"])
			}

			if !ctx.IsAborted() {
				t.Errorf("handleResolveError(%v) did not abort context", tt.err)
			}
		})
	}
}

func TestHandleResolveError_UnknownErrors_NHPDrop(t *testing.T) {
	// Unknown/unexpected errors still trigger NHP silent drop
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

			// NHP silence: no response body written
			if body := w.Body.String(); body != "" {
				t.Errorf("handleResolveError(%v) wrote body %q, want empty (NHP silence)", tt.err, body)
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
	if res.ExInfo["JWTSecret"] != "test-secret" {
		t.Errorf("ExInfo[JWTSecret] = %v, want %q", res.ExInfo["JWTSecret"], "test-secret")
	}
	if res.ExInfo["TokenExpire"] != int64(3600) {
		t.Errorf("ExInfo[TokenExpire] = %v, want %d", res.ExInfo["TokenExpire"], 3600)
	}
}

func TestAuthWithHttp_FullFlow(t *testing.T) {
	// Create mock QURL API server
	qurlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	ctx.Request = httptest.NewRequest(http.MethodGet, "/plugins/qurl?token=valid_test_token_123", nil)

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

	// Verify redirect response
	if w.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, w.Code)
	}
	location := w.Header().Get("Location")
	if location != "https://r_test123.qurl.site" {
		t.Errorf("expected redirect to https://r_test123.qurl.site, got %s", location)
	}

	// Verify cookies were set
	cookies := w.Result().Cookies()
	var nhpTokenCookie, refreshTokenCookie *http.Cookie
	for _, c := range cookies {
		switch c.Name {
		case "nhp_token":
			nhpTokenCookie = c
		case "nhp_refresh_token":
			refreshTokenCookie = c
		}
	}
	if nhpTokenCookie == nil {
		t.Error("nhp_token cookie not set")
	}
	if refreshTokenCookie == nil {
		t.Error("nhp_refresh_token cookie not set")
	}
}

func TestAuthWithHttp_InvalidToken(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/plugins/qurl?token=", nil)

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
	// NHP behavior: invalid token gets silent drop, no HTTP response
	if body := w.Body.String(); body != "" {
		t.Errorf("invalid token should produce NHP silence, got body: %s", body)
	}
	if !ctx.IsAborted() {
		t.Error("invalid token should abort context (NHP drop)")
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
	ctx.Request = httptest.NewRequest(http.MethodGet, "/plugins/qurl?token=unknown_token_123", nil)

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
	// Known token errors return 403 (avoids CloudFront 502 from silent drop)
	if w.Code != http.StatusForbidden {
		t.Errorf("resolver error status = %d, want %d", w.Code, http.StatusForbidden)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	if body["error"] != "access_denied" {
		t.Errorf("expected error='access_denied', got %q", body["error"])
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
	ctx.Request = httptest.NewRequest(http.MethodGet, "/plugins/qurl?token=valid_test_token_123", nil)

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
		t.Errorf("expected 2 knock attempts, got %d", attempts)
	}
	if ackMsg == nil || len(ackMsg.ResourceHost) == 0 {
		t.Error("expected resource hosts in ack message")
	}
	if w.Code != http.StatusFound {
		t.Errorf("expected redirect (302), got %d", w.Code)
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
	ctx.Request = httptest.NewRequest(http.MethodGet, "/plugins/qurl?token=valid_test_token_123", nil)

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
		t.Fatal("expected error after both attempts fail")
	}
	if attempts != 2 {
		t.Errorf("expected 2 knock attempts, got %d", attempts)
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
