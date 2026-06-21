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

// testNHPResourceID is the q_ display id used by tests as the catalog key the
// #2540 plugin path resolves AC routing by. It matches qurl-service's
// QurlDisplayID format (q_ + 11 hex) so IsQURLDynamicResourceID accepts it.
const testNHPResourceID = "q_0123456789a"

// defaultCatalogResolver returns a ResolveResourceFunc that stands in for the
// host server's catalog lookup (#2540): given (aspId, resId) it returns a valid
// single-AC routing map, mirroring the shape resolveInternalKnockResource
// produces from a dynamic q_ catalog row. AuthWithHttp's catalog step needs a
// non-empty Resources map to proceed to the knock; the content is otherwise
// inert (no test inspects res.Resources).
func defaultCatalogResolver() plugins.HttpPluginResolveResourceFunc {
	return func(aspId, resId, _ string) (*common.ResourceData, error) {
		return &common.ResourceData{
			ResourceGroup: common.ResourceGroup{
				AuthServiceId: aspId,
				ResourceId:    resId,
				OpenTime:      300,
				Resources: map[string]*common.ResourceInfo{
					resId: {
						ACId:       "ac-catalog",
						Hostname:   "catalog.example.com",
						PortSuffix: true,
						Addr:       &common.NetAddress{Port: 443, Protocol: "tcp"},
					},
				},
			},
			SkipAuth: true,
		}, nil
	}
}

// knockHelper builds a full-flow HTTP plugin helper: the given success/knock
// callback plus the default #2540 catalog resolver so AuthWithHttp reaches the
// knock instead of failing closed at the catalog step.
func knockHelper(cb plugins.HttpPluginPostAuthFunc) *plugins.HttpServerPluginHelper {
	return &plugins.HttpServerPluginHelper{
		AuthWithHttpCallbackFunc: cb,
		ResolveResourceFunc:      defaultCatalogResolver(),
	}
}

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
		{"agent identity conflict", ErrAgentIdentityConflict},
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
		ResourceID:    "r_test123",
		NHPResourceID: testNHPResourceID,
		TargetURL:     "https://backend.example.com",
		QurlSiteURL:   "https://r_test123.qurl.site",
		JWTSecret:     "test-secret",
		TokenExpire:   3600,
		OpenTime:      300,
		CookieDomain:  ".qurl.site",
		// Body-supplied routing that MUST be ignored (#2540): buildResourceData
		// takes its Resources from the catalog argument, never from resp.
		Resources: map[string]*common.ResourceInfo{
			"body-should-be-ignored": {ACId: "ac-body", Addr: &common.NetAddress{Ip: "9.9.9.9", Port: 1}},
		},
	}
	catalogResources := map[string]*common.ResourceInfo{
		testNHPResourceID: {ACId: "ac-catalog", Hostname: "catalog.example.com", Addr: &common.NetAddress{Port: 443}},
	}

	// openTime is the caller-computed effective window (passed in), NOT
	// resp.OpenTime — use a distinct value so a regression that reads
	// resp.OpenTime (300) instead of the argument (180) is caught.
	res := buildResourceData(resp, catalogResources, 180)

	if res.ResourceId != "r_test123" {
		t.Errorf("ResourceId = %q, want %q", res.ResourceId, "r_test123")
	}
	if res.AuthServiceId != PluginID {
		t.Errorf("AuthServiceId = %q, want %q", res.AuthServiceId, PluginID)
	}
	if res.OpenTime != 180 {
		t.Errorf("OpenTime = %d, want caller-supplied %d (not resp.OpenTime)", res.OpenTime, 180)
	}
	if res.RedirectUrl != "https://r_test123.qurl.site" {
		t.Errorf("RedirectUrl = %q, want %q", res.RedirectUrl, "https://r_test123.qurl.site")
	}
	if res.CookieDomain != ".qurl.site" {
		t.Errorf("CookieDomain = %q, want %q", res.CookieDomain, ".qurl.site")
	}

	// Routing must come from the catalog argument, not resp.Resources.
	if _, leaked := res.Resources["body-should-be-ignored"]; leaked {
		t.Error("buildResourceData used resp.Resources; it must use the catalog argument (#2540)")
	}
	info, ok := res.Resources[testNHPResourceID]
	if !ok {
		t.Fatalf("catalog routing missing: res.Resources = %v", res.Resources)
	}
	if info.ACId != "ac-catalog" {
		t.Errorf("ACId = %q, want catalog-supplied %q", info.ACId, "ac-catalog")
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
				NHPResourceID: testNHPResourceID,
				ResourceID:    "r_test123",
				TargetURL:     "https://backend.example.com",
				QurlSiteURL:   "https://r_test123.qurl.site",
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
		ResolveResourceFunc: defaultCatalogResolver(),
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
				NHPResourceID: testNHPResourceID,
				ResourceID:    "r_test123",
				TargetURL:     "https://backend.example.com",
				QurlSiteURL:   "https://r_test123.qurl.site",
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
				NHPResourceID: testNHPResourceID,
				ResourceID:    "r_test123",
				TargetURL:     "https://backend.example.com",
				QurlSiteURL:   "https://r_test123.qurl.site",
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

	// validateResolveResponse now requires nhp_resource_id (#2540); default it
	// so existing fixtures that predate the field still resolve successfully.
	if resp.NHPResourceID == "" {
		resp.NHPResourceID = testNHPResourceID
	}

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
	return knockHelper(func(req *common.HttpKnockRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		return &common.ServerKnockAckMsg{
			ResourceHost: map[string]string{"default": "10.0.0.1:443"},
		}, nil
	})
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
		ResolveResourceFunc: defaultCatalogResolver(),
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
				NHPResourceID: testNHPResourceID,
				ResourceID:    "r_generated",
				QurlSiteURL:   "https://r_generated.qurl.site",
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
		ResolveResourceFunc: defaultCatalogResolver(),
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
				NHPResourceID: testNHPResourceID,
				ResourceID:    "r_retry",
				TargetURL:     "https://backend.example.com",
				QurlSiteURL:   "https://r_retry.qurl.site",
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
		ResolveResourceFunc: defaultCatalogResolver(),
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
				NHPResourceID: testNHPResourceID,
				ResourceID:    "r_fail",
				TargetURL:     "https://backend.example.com",
				QurlSiteURL:   "https://r_fail.qurl.site",
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
		ResolveResourceFunc: defaultCatalogResolver(),
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

// TestAuthWithHttp_AcceptJSON_InvalidRedirectStays502JSON fences the
// invalid_redirect 502 branch (handler emits inline JSON, not branded
// HTML, when the QURL API returns a malformed redirect URL). The
// existing TestAuthWithHttp_CustomDomain_RejectsHTTPRedirect covers
// the same code path under default Accept; this row pins that
// Accept: application/json doesn't change the 502 + JSON shape.
func TestAuthWithHttp_AcceptJSON_InvalidRedirectStays502JSON(t *testing.T) {
	setup := setupCustomDomainTest(t, &ResolveResponse{
		ResourceID:     "r_bad_redirect",
		TargetURL:      "https://backend.example.com",
		QurlSiteURL:    "http://app.mycorp.com", // HTTP — rejected by ValidateCustomDomainRedirectURL
		Resources:      map[string]*common.ResourceInfo{"default": {ACId: "ac-001", Hostname: "backend.example.com", Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443}}},
		JWTSecret:      "test-jwt-secret-key-for-signing",
		TokenExpire:    3600,
		OpenTime:       300,
		CookieDomain:   ".mycorp.com",
		IsCustomDomain: true,
	})
	setup.ctx.Request.Header.Set("Accept", "application/json")

	_, err := AuthWithHttp(setup.ctx, &common.HttpKnockRequest{}, successKnockHelper())
	if err == nil {
		t.Fatal("expected error for HTTP custom domain redirect")
	}
	if setup.recorder.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", setup.recorder.Code)
	}
	ct := setup.recorder.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("invalid_redirect Content-Type with Accept: application/json = %q, want application/json (inline 5xx contract)", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(setup.recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode JSON body: %v", err)
	}
	if body["error"] != "invalid_redirect" {
		t.Errorf("error field = %q, want %q", body["error"], "invalid_redirect")
	}
}

// TestAuthWithHttp_AcceptJSON_KnockFailedStaysJSON pins the contract
// that the 5xx knock-failed branch keeps its existing JSON
// {error,message,detail} shape even when the caller sent
// Accept: application/json. The handler godoc promises this; a future
// refactor that wraps the 5xx in branded HTML (or vice versa) for any
// reason would silently break the SPA's error-rendering branch.
func TestAuthWithHttp_AcceptJSON_KnockFailedStaysJSON(t *testing.T) {
	qurlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(internalResolveResponse{
			Success: true,
			Data: &ResolveResponse{
				NHPResourceID: testNHPResourceID,
				ResourceID:    "r_knockfail",
				QurlSiteURL:   "https://r_knockfail.qurl.site",
				Resources:     map[string]*common.ResourceInfo{"default": {ACId: "ac-001", Hostname: "backend.example.com", Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443}}},
				JWTSecret:     "test-jwt-secret-key-for-signing",
				TokenExpire:   3600,
				OpenTime:      300,
				CookieDomain:  ".qurl.site",
			},
		})
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
	ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl",
		strings.NewReader("token=at_validknock1234567890123"))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Request.Header.Set("Accept", "application/json")

	// Helper that always fails the knock — exhausts retries and
	// triggers the 5xx knock_failed branch.
	helper := &plugins.HttpServerPluginHelper{
		ResolveResourceFunc: defaultCatalogResolver(),
		AuthWithHttpCallbackFunc: func(req *common.HttpKnockRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			return nil, errors.New("AC connection closed")
		},
	}

	_, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper)
	if err == nil {
		t.Fatal("expected error after knock retries exhausted")
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("knock_failed Content-Type = %q, want application/json (existing 5xx contract)", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode 5xx JSON body: %v", err)
	}
	if body["error"] != "knock_failed" {
		t.Errorf("error field = %q, want %q", body["error"], "knock_failed")
	}
}

// TestAuthWithHttp_AcceptJSON_ErrorStaysHTML is the unit-level twin of
// TestResolve_AcceptJSON_ErrorPathStaysHTML in tests/smoke. It pins the
// SPA contract: even when the caller sends Accept: application/json,
// error paths (token-invalid 403) keep their existing branded-HTML
// shape. Catches the regression at unit-test time so a future refactor
// that wraps the 403 in JSON fails fast instead of waiting for sandbox.
func TestAuthWithHttp_AcceptJSON_ErrorStaysHTML(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl",
		strings.NewReader("token="))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Request.Header.Set("Accept", "application/json")

	helper := &plugins.HttpServerPluginHelper{
		AuthWithHttpCallbackFunc: func(req *common.HttpKnockRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			t.Error("callback should not be called on token-invalid path")
			return nil, nil
		},
	}

	_, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper)
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("error-path Content-Type with Accept: application/json = %q, want text/html (SPA branches on this)", ct)
	}
	if !strings.Contains(w.Body.String(), "Access Link Invalid") {
		t.Errorf("error-path body missing branded marker")
	}
}

// TestAuthWithHttp_AcceptJSON_HeaderValuesNotGet fences the documented
// Header.Values fold in wantsJSON: a client that emits Accept twice via
// Header.Add (instead of one comma-separated header) still triggers the
// JSON branch. Real clients always send one header; this row covers a
// future Go SDK that uses Header.Add naively.
func TestAuthWithHttp_AcceptJSON_HeaderValuesNotGet(t *testing.T) {
	setup := setupCustomDomainTest(t, &ResolveResponse{
		ResourceID:   "r_multihdr",
		TargetURL:    "https://backend.example.com",
		QurlSiteURL:  "https://r_multihdr.qurl.site",
		Resources:    map[string]*common.ResourceInfo{"default": {ACId: "ac-001", Hostname: "backend.example.com", Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443}}},
		JWTSecret:    "test-jwt-secret-key-for-signing",
		TokenExpire:  3600,
		OpenTime:     300,
		CookieDomain: ".qurl.site",
	})
	// Two Accept headers via Header.Add — equivalent under RFC 7230 to
	// one comma-separated header, but Header.Get returns only the first.
	// wantsJSON uses Header.Values to fold them.
	setup.ctx.Request.Header.Add("Accept", "text/html")
	setup.ctx.Request.Header.Add("Accept", "application/json")

	if _, err := AuthWithHttp(setup.ctx, &common.HttpKnockRequest{}, successKnockHelper()); err != nil {
		t.Fatalf("AuthWithHttp returned unexpected error: %v", err)
	}
	if setup.ctx.Writer.Status() != http.StatusOK {
		t.Errorf("expected 200 (JSON branch via folded Accept headers), got %d", setup.ctx.Writer.Status())
	}
}

// TestAuthWithHttp_AcceptJSON_VaryAddDoesNotClobberPreexisting fences the
// production layering: the platform CORS middleware in httpserver.go
// runs Set("Vary", "Origin") upstream of this handler, and code in
// this handler must Add (not Set) Vary so that value survives.
// Pre-seeds Vary: Origin on the response writer (simulating the
// upstream middleware) before calling AuthWithHttp and asserts both
// values survive.
func TestAuthWithHttp_AcceptJSON_VaryAddDoesNotClobberPreexisting(t *testing.T) {
	setup := setupCustomDomainTest(t, &ResolveResponse{
		ResourceID:   "r_origin",
		TargetURL:    "https://backend.example.com",
		QurlSiteURL:  "https://r_origin.qurl.site",
		Resources:    map[string]*common.ResourceInfo{"default": {ACId: "ac-001", Hostname: "backend.example.com", Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443}}},
		JWTSecret:    "test-jwt-secret-key-for-signing",
		TokenExpire:  3600,
		OpenTime:     300,
		CookieDomain: ".qurl.site",
	})
	// Pre-seed Vary: Origin to simulate the upstream platform CORS
	// middleware (endpoints/server/httpserver.go:corsMiddleware).
	setup.ctx.Writer.Header().Set("Vary", "Origin")
	setup.ctx.Request.Header.Set("Accept", "application/json")
	setup.ctx.Request.Header.Set("Origin", "https://qurl.link")

	if _, err := AuthWithHttp(setup.ctx, &common.HttpKnockRequest{}, successKnockHelper()); err != nil {
		t.Fatalf("AuthWithHttp returned unexpected error: %v", err)
	}
	// Vary is multi-valued (slice on the underlying http.Header). Header.Get
	// would only return the first entry; Values returns all so we can assert
	// both Origin (from upstream Set) and Accept (from our Add) survive.
	got := strings.Join(setup.recorder.Header().Values("Vary"), ", ")
	if !strings.Contains(got, "Accept") {
		t.Errorf("Vary = %q, want it to contain Accept", got)
	}
	if !strings.Contains(got, "Origin") {
		t.Errorf("Vary = %q, want upstream Origin to survive", got)
	}
}

// TestAuthWithHttp_AcceptJSON_DoesNotClobberExposeHeaders fences the
// regression caught by smoke test TestResolve_AcceptJSON_CORSCredentialsHeaders:
// the engine-level corsMiddleware in httpserver.go writes
// Access-Control-Expose-Headers (with Set-Cookie) before this handler
// runs, and nothing in this handler may touch that header. Browsers
// only surface Set-Cookie on a credentialed fetch when its name appears
// in the engine's value, so a handler-side clobber silently breaks
// SPA cookie pickup.
//
// Seeds a sentinel value rather than the production literal so the
// fence is decoupled from httpserver.go's Expose-Headers list — any
// handler write to this header at all (clobber, append, partial
// preserve) flips the exact-match assertion. The sibling passcode-side
// test TestAuthWithHttp_DoesNotClobberExposeHeaders uses the same
// pattern so #1394's lint can grep both with one substring.
func TestAuthWithHttp_AcceptJSON_DoesNotClobberExposeHeaders(t *testing.T) {
	setup := setupCustomDomainTest(t, &ResolveResponse{
		ResourceID:   "r_origin",
		TargetURL:    "https://backend.example.com",
		QurlSiteURL:  "https://r_origin.qurl.site",
		Resources:    map[string]*common.ResourceInfo{"default": {ACId: "ac-001", Hostname: "backend.example.com", Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443}}},
		JWTSecret:    "test-jwt-secret-key-for-signing",
		TokenExpire:  3600,
		OpenTime:     300,
		CookieDomain: ".qurl.site",
	})
	const sentinel = "X-Sentinel-DoNotTouch"
	// Seed via the recorder so it surfaces that the engine middleware
	// would have written here in production. Matches the stub style
	// in passcode/auth_with_http_cors_test.go.
	setup.recorder.Header().Set("Access-Control-Expose-Headers", sentinel)
	setup.ctx.Request.Header.Set("Accept", "application/json")

	if _, err := AuthWithHttp(setup.ctx, &common.HttpKnockRequest{}, successKnockHelper()); err != nil {
		t.Fatalf("AuthWithHttp returned unexpected error: %v", err)
	}
	got := setup.recorder.Header().Get("Access-Control-Expose-Headers")
	if got != sentinel {
		t.Errorf("Access-Control-Expose-Headers = %q, want %q unchanged (handler must not touch this header)", got, sentinel)
	}
}

// TestAuthWithHttp_VaryAcceptOnResolveErrorPath complements
// TestAuthWithHttp_VaryAcceptOnErrorPath: the latter covers the
// empty-token validation branch; this one covers the resolve-failure
// branch (handleResolveError). Both paths emit branded HTML 403 with
// different code routes, and both must carry Vary: Accept symmetrically.
//
// Not safe to run with t.Parallel(): mutates the package-global
// resolver. Same caveat applies to TestAuthWithHttp_AcceptJSON_KnockFailedStaysJSON
// and to the existing tests in this file that swap the resolver.
// Migrate to context-injected resolver before parallelizing.
func TestAuthWithHttp_VaryAcceptOnResolveErrorPath(t *testing.T) {
	// Mock QURL API that always returns "token not found"
	qurlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(internalResolveResponse{
			Success: false,
			Error:   &resolveError{Code: "token_not_found", Message: "Token not found"},
		})
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
	ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl",
		strings.NewReader("token=at_unknown1234567890123456"))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Request.Header.Set("Accept", "application/json")

	_, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, successKnockHelper())
	if err == nil {
		t.Fatal("expected error for unknown token")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
	if got := w.Header().Get("Vary"); !strings.Contains(got, "Accept") {
		t.Errorf("Vary on resolve-error path = %q, want it to contain Accept", got)
	}
}

// TestAuthWithHttp_VaryAcceptOnErrorPath fences the symmetry of the
// Vary: Accept defense — every response from this handler past the
// CORS middleware, including the branded 403 token-invalid path, must
// carry it. Asymmetric Vary would defeat its own purpose: a cache
// that stored a JSON-less error could later serve it to a JSON-asking
// client.
func TestAuthWithHttp_VaryAcceptOnErrorPath(t *testing.T) {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	form := "token="
	ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl", strings.NewReader(form))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Request.Header.Set("Accept", "application/json")

	helper := &plugins.HttpServerPluginHelper{
		AuthWithHttpCallbackFunc: func(req *common.HttpKnockRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			t.Error("callback should not be called on token-invalid path")
			return nil, nil
		},
	}

	_, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper)
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 token error, got %d", w.Code)
	}
	if got := w.Header().Get("Vary"); !strings.Contains(got, "Accept") {
		t.Errorf("Vary on error path = %q, want it to contain Accept", got)
	}
}

// TestAuthWithHttp_AcceptJSON_ReturnsJSONNotRedirect verifies that callers
// with Accept: application/json receive a 200 + JSON body containing the
// redirect URL, instead of the legacy 302 redirect. The qurl.link SPA uses
// this branch to render progressive UI without the browser blanking the tab.
func TestAuthWithHttp_AcceptJSON_ReturnsJSONNotRedirect(t *testing.T) {
	setup := setupCustomDomainTest(t, &ResolveResponse{
		ResourceID:   "r_jsonflow",
		TargetURL:    "https://backend.example.com",
		QurlSiteURL:  "https://r_jsonflow.qurl.site",
		Resources:    map[string]*common.ResourceInfo{"default": {ACId: "ac-001", Hostname: "backend.example.com", Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443}}},
		JWTSecret:    "test-jwt-secret-key-for-signing",
		TokenExpire:  3600,
		OpenTime:     300,
		CookieDomain: ".qurl.site",
	})
	setup.ctx.Request.Header.Set("Accept", "application/json")

	_, err := AuthWithHttp(setup.ctx, &common.HttpKnockRequest{}, successKnockHelper())
	if err != nil {
		t.Fatalf("AuthWithHttp returned unexpected error: %v", err)
	}

	if setup.ctx.Writer.Status() != http.StatusOK {
		t.Errorf("expected 200 for JSON path, got %d", setup.ctx.Writer.Status())
	}
	if got := setup.recorder.Header().Get("Location"); got != "" {
		t.Errorf("expected no Location header on JSON path, got %q", got)
	}
	contentType := setup.recorder.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}

	body := map[string]any{}
	if err := json.Unmarshal(setup.recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode JSON body: %v", err)
	}
	if got := body[redirectURLField]; got != "https://r_jsonflow.qurl.site" {
		t.Errorf("%s = %v, want %q", redirectURLField, got, "https://r_jsonflow.qurl.site")
	}

	// Cookies must still be set on the JSON path with the same security
	// attributes the 302 path uses — Domain/HttpOnly/Secure/SameSite. If
	// a future refactor accidentally moved the SetCookie calls into the
	// 302 arm, the SPA would do window.location.replace(redirect_url) and
	// land unauthenticated. Asserting the attributes here, not just
	// presence, fences that regression.
	//
	// Counting matches (rather than overwriting on each loop iteration)
	// also catches a future bug that emits two nhp_token Set-Cookie
	// headers, which a "last-wins" assignment would silently inspect
	// only the second of.
	cookies := setup.recorder.Result().Cookies()
	var nhpToken *http.Cookie
	var nhpTokenCount int
	for _, c := range cookies {
		if c.Name == CookieNHPToken {
			nhpTokenCount++
			nhpToken = c
		}
	}
	if nhpTokenCount == 0 {
		t.Fatal("nhp_token cookie not set on JSON response path")
	}
	if nhpTokenCount > 1 {
		t.Errorf("nhp_token cookie emitted %d times, want 1", nhpTokenCount)
	}
	if nhpToken.Value == "" {
		t.Error("nhp_token cookie on JSON path has empty value — a SetCookie arg-order regression would land here")
	}
	if !nhpToken.HttpOnly {
		t.Error("nhp_token cookie on JSON path missing HttpOnly")
	}
	if !nhpToken.Secure {
		t.Error("nhp_token cookie on JSON path missing Secure")
	}
	if nhpToken.SameSite != http.SameSiteNoneMode {
		t.Errorf("nhp_token cookie on JSON path SameSite = %v, want SameSiteNoneMode (cross-subdomain flow needs this)", nhpToken.SameSite)
	}
	// Go's http.ReadSetCookies strips the leading dot from cookie domains,
	// so ".qurl.site" set by SetCookie comes back as "qurl.site" here.
	if nhpToken.Domain != "qurl.site" {
		t.Errorf("nhp_token cookie on JSON path Domain = %q, want %q", nhpToken.Domain, "qurl.site")
	}
}

// TestAuthWithHttp_AcceptJSONVariants exercises the parser surface: every
// header form a real client might send that should land on the JSON branch
// (with a non-empty redirect_url) or stay on the 302 path. Unifies the q,
// charset, uppercase, and multi-value cases under one table so adding a
// new variant is a one-line edit.
func TestAuthWithHttp_AcceptJSONVariants(t *testing.T) {
	tests := []struct {
		name       string
		accept     string
		wantStatus int
	}{
		{"plain", "application/json", http.StatusOK},
		{"with q-param", "application/json;q=0.9, */*;q=0.5", http.StatusOK},
		{"with charset", "application/json; charset=utf-8", http.StatusOK},
		{"uppercase media type", "APPLICATION/JSON", http.StatusOK},
		{"json first, multi-value, no q", "application/json, text/html", http.StatusOK},
		{"json after html, no q", "text/html, application/json", http.StatusOK},
		// "json + wildcard" is the most likely real fetch() default header
		// shape (Accept: application/json,*/*); pin it so the parser
		// doesn't get fooled into matching the wildcard first.
		{"json plus wildcard", "application/json,*/*", http.StatusOK},
		// q=0 is RFC 7231 "not acceptable", but wantsJSON's godoc declares
		// this a deliberate simplification — q values are ignored entirely.
		// This row pins the documented behavior so a future refactor that
		// honors q=0 would fail this test, surfacing the doc/code drift
		// instead of silently changing the contract.
		{"q=0 deliberately accepted", "application/json;q=0", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupCustomDomainTest(t, &ResolveResponse{
				ResourceID:   "r_variants",
				TargetURL:    "https://backend.example.com",
				QurlSiteURL:  "https://r_variants.qurl.site",
				Resources:    map[string]*common.ResourceInfo{"default": {ACId: "ac-001", Hostname: "backend.example.com", Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443}}},
				JWTSecret:    "test-jwt-secret-key-for-signing",
				TokenExpire:  3600,
				OpenTime:     300,
				CookieDomain: ".qurl.site",
			})
			setup.ctx.Request.Header.Set("Accept", tt.accept)

			if _, err := AuthWithHttp(setup.ctx, &common.HttpKnockRequest{}, successKnockHelper()); err != nil {
				t.Fatalf("AuthWithHttp returned unexpected error: %v", err)
			}
			if setup.ctx.Writer.Status() != tt.wantStatus {
				t.Errorf("status = %d, want %d", setup.ctx.Writer.Status(), tt.wantStatus)
			}
			// Body assertion: a status-only assertion would silently pass if
			// wantsJSON returned true but ctx.JSON wrote garbage, so decode
			// the body and check the redirect_url survived.
			body := map[string]any{}
			if err := json.Unmarshal(setup.recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode JSON body: %v", err)
			}
			if got := body[redirectURLField]; got != "https://r_variants.qurl.site" {
				t.Errorf("%s = %v, want %q", redirectURLField, got, "https://r_variants.qurl.site")
			}

			// Vary: Accept must be set so any caching intermediary keys on
			// the negotiated shape rather than the URL alone.
			if got := setup.recorder.Header().Get("Vary"); !strings.Contains(got, "Accept") {
				t.Errorf("Vary header = %q, want it to contain Accept", got)
			}
		})
	}
}

// TestAuthWithHttp_AcceptWildcard_StaysOn302 verifies Accept: */* (or no
// Accept header) still gets the legacy 302 path so existing form-POST callers
// — including any other intermediary that doesn't ask for JSON — keep working.
func TestAuthWithHttp_AcceptWildcard_StaysOn302(t *testing.T) {
	tests := []struct {
		name   string
		accept string
	}{
		{"wildcard", "*/*"},
		{"text/html", "text/html,application/xhtml+xml"},
		{"empty", ""},
		// Malformed Accept must fall through to the 302 path rather than
		// panic or accidentally matching JSON. The parser treats unknown
		// media types as "not application/json" and stays on legacy.
		{"malformed", "not-a-mediatype"},
		// Subtype wildcard (RFC 7231 §5.3.2 syntax for "any application
		// type") does NOT match per the documented simplifications in
		// wantsJSON's godoc — only literal application/json triggers
		// the JSON branch. This row pins that boundary so a future
		// refactor can't quietly start matching application/*.
		{"subtype wildcard", "application/*"},
		// Pin the "only literal application/json" boundary against
		// nearby-but-not-equal types: a prefix-only string and a
		// +json suffix type. Both must stay on 302 per the
		// documented simplifications.
		{"json prefix only", "application/jsonfoo"},
		{"+json suffix", "application/hal+json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupCustomDomainTest(t, &ResolveResponse{
				ResourceID:   "r_legacy",
				TargetURL:    "https://backend.example.com",
				QurlSiteURL:  "https://r_legacy.qurl.site",
				Resources:    map[string]*common.ResourceInfo{"default": {ACId: "ac-001", Hostname: "backend.example.com", Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443}}},
				JWTSecret:    "test-jwt-secret-key-for-signing",
				TokenExpire:  3600,
				OpenTime:     300,
				CookieDomain: ".qurl.site",
			})
			if tt.accept != "" {
				setup.ctx.Request.Header.Set("Accept", tt.accept)
			}

			if _, err := AuthWithHttp(setup.ctx, &common.HttpKnockRequest{}, successKnockHelper()); err != nil {
				t.Fatalf("AuthWithHttp returned unexpected error: %v", err)
			}
			if setup.ctx.Writer.Status() != http.StatusFound {
				t.Errorf("expected 302 for legacy path, got %d", setup.ctx.Writer.Status())
			}
			if got := setup.recorder.Header().Get("Location"); got != "https://r_legacy.qurl.site" {
				t.Errorf("Location = %q, want %q", got, "https://r_legacy.qurl.site")
			}
			// Vary: Accept must also be set on the 302 branch so a cache
			// can't serve a stored 302 to a later request that asks for
			// JSON. Symmetric with the JSON branch's assertion.
			if got := setup.recorder.Header().Get("Vary"); !strings.Contains(got, "Accept") {
				t.Errorf("Vary header on 302 branch = %q, want it to contain Accept", got)
			}
		})
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

	data := buildResourceData(resp, nil, resp.OpenTime)

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
	data = buildResourceData(resp, nil, resp.OpenTime)
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
	for _, c := range cookies {
		if c.Name == CookieNHPToken || c.Name == CookieNHPRefreshToken {
			if c.MaxAge != 900 {
				t.Errorf("cookie %s: expected MaxAge=900 (session_duration), got %d", c.Name, c.MaxAge)
			}
		}
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
	for _, c := range cookies {
		if c.Name == CookieNHPToken || c.Name == CookieNHPRefreshToken {
			if c.MaxAge != 3600 {
				t.Errorf("cookie %s: expected MaxAge=3600 (token_expire fallback), got %d", c.Name, c.MaxAge)
			}
		}
	}
}
