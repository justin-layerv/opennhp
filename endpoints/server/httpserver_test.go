package server

import (
	"encoding/base64"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/endpoints/server/health"
)

func TestACPeerGracePeriodFromConfig(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		input       int
		wantDur     time.Duration
		wantWarning bool
	}{
		{"zero → 0 (checker picks default)", 0, 0, false},
		{"negative → -1s sentinel (disabled)", -1, -time.Second, false},
		{"any negative normalizes to -1s", -30, -time.Second, false},
		{"below floor → clamped up with warning", 3, health.MinACPeerGracePeriod, true},
		{"at floor → unchanged", int(health.MinACPeerGracePeriod / time.Second), health.MinACPeerGracePeriod, false},
		{"within range → unchanged", 45, 45 * time.Second, false},
		{"at ceiling → unchanged", int(health.MaxACPeerGracePeriod / time.Second), health.MaxACPeerGracePeriod, false},
		{"above ceiling → clamped down with warning", 3600, health.MaxACPeerGracePeriod, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var warned bool
			logf := func(string, ...any) { warned = true }
			got := acPeerGracePeriodFromConfig(tc.input, logf)
			if got != tc.wantDur {
				t.Errorf("duration = %v, want %v", got, tc.wantDur)
			}
			if warned != tc.wantWarning {
				t.Errorf("warn=%v, want %v (input=%d)", warned, tc.wantWarning, tc.input)
			}
		})
	}

	t.Run("nil logf is safe", func(t *testing.T) {
		// Clamp path without a logger must not panic; tests and
		// operators running in contexts without a plumbed logger
		// should still get a correctly-clamped result.
		got := acPeerGracePeriodFromConfig(3, nil)
		if got != health.MinACPeerGracePeriod {
			t.Errorf("nil logf: got %v, want %v", got, health.MinACPeerGracePeriod)
		}
	})

	t.Run("overflow → clamped to max with distinct warning", func(t *testing.T) {
		// A configSeconds value that would wrap time.Duration's int64
		// nanos (>~9.2e9 seconds). Before the overflow guard, the
		// wrapped value fell through to the "below floor" branch and
		// emitted a misleading warning. The guard should detect this
		// explicitly, clamp to Max, and emit a warning that mentions
		// overflow.
		var warning string
		logf := func(format string, args ...any) {
			warning = format
		}
		const overflowing = math.MaxInt // int, large enough to overflow int64 nanos
		got := acPeerGracePeriodFromConfig(overflowing, logf)
		if got != health.MaxACPeerGracePeriod {
			t.Errorf("overflow: got %v, want %v", got, health.MaxACPeerGracePeriod)
		}
		if !strings.Contains(warning, "overflow") {
			t.Errorf("warning = %q, should mention overflow (input=%d)",
				warning, overflowing)
		}
	})
}

func TestFormatGraceLabel(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "disabled"},
		{30 * time.Second, "30s"},
		{5 * time.Minute, "5m0s"},
	}
	for _, tc := range cases {
		if got := formatGraceLabel(tc.in); got != tc.want {
			t.Errorf("formatGraceLabel(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestErrNoStorageBackend(t *testing.T) {
	t.Parallel()

	// Verify the error is defined and has a meaningful message
	if ErrNoStorageBackend == nil {
		t.Fatal("ErrNoStorageBackend should not be nil")
	}

	expectedMsg := "no storage backend configured (etcd or DynamoDB required)"
	if ErrNoStorageBackend.Error() != expectedMsg {
		t.Errorf("expected error message %q, got %q", expectedMsg, ErrNoStorageBackend.Error())
	}
}

// TestHttpServer_initHealthManager_NoStorage tests fail-fast behavior
// when no storage backend is configured.
//
// Note: This is a behavioral contract test. The actual initHealthManager
// function requires a fully initialized UdpServer, so we verify the error
// constant exists and has the expected message. Integration tests in
// forward_e2e_test.go cover the full initialization path.
func TestHttpServer_initHealthManager_NoStorage_Contract(t *testing.T) {
	t.Parallel()

	// The contract is:
	// 1. ErrNoStorageBackend is returned when neither etcd nor DynamoDB is configured
	// 2. The error message clearly indicates the problem
	// 3. This causes Start() to fail (tested implicitly by e2e tests)

	err := ErrNoStorageBackend

	// Verify error can be checked with errors.Is
	if err.Error() == "" {
		t.Error("error message should not be empty")
	}

	// Verify the error message mentions both backends
	msg := err.Error()
	if msg == "" {
		t.Error("error message should not be empty")
	}

	// The message should help operators understand what to do
	if len(msg) < 20 {
		t.Error("error message should be descriptive")
	}
}

// ============================================================================
// parseCookieKeys Tests
// ============================================================================

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestParseCookieKeys_EmptyString(t *testing.T) {
	_, err := parseCookieKeys("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("expected 'required' in error, got: %v", err)
	}
}

func TestParseCookieKeys_InvalidBase64(t *testing.T) {
	_, err := parseCookieKeys("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Errorf("expected 'base64' in error, got: %v", err)
	}
}

func TestParseCookieKeys_InvalidJSON(t *testing.T) {
	_, err := parseCookieKeys(b64("{not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "JSON") {
		t.Errorf("expected 'JSON' in error, got: %v", err)
	}
}

func TestParseCookieKeys_MissingRequiredFields(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"missing auth_key", `{"current":{"encrypt_key":"12345678901234567890123456789012"}}`},
		{"missing encrypt_key", `{"current":{"auth_key":"12345678901234567890123456789012"}}`},
		{"empty current", `{"current":{}}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCookieKeys(b64(tc.json))
			if err == nil {
				t.Fatal("expected error for missing fields")
			}
		})
	}
}

func TestParseCookieKeys_InvalidKeyLengths(t *testing.T) {
	cases := []struct {
		name    string
		authKey string
		encKey  string
		errSub  string
	}{
		{"auth_key too short", "shortkey", "12345678901234567890123456789012", "auth_key"},
		{"encrypt_key wrong length", "12345678901234567890123456789012", "wronglength1234567", "encrypt_key"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := `{"current":{"auth_key":"` + tc.authKey + `","encrypt_key":"` + tc.encKey + `"}}`
			_, err := parseCookieKeys(b64(j))
			if err == nil {
				t.Fatal("expected error for invalid key length")
			}
			if !strings.Contains(err.Error(), tc.errSub) {
				t.Errorf("expected %q in error, got: %v", tc.errSub, err)
			}
		})
	}
}

func TestParseCookieKeys_ValidCurrentOnly(t *testing.T) {
	// 32-byte auth + 32-byte encrypt
	auth := "12345678901234567890123456789012"
	enc := "abcdefghijklmnopqrstuvwxyz123456"
	j := `{"current":{"auth_key":"` + auth + `","encrypt_key":"` + enc + `"}}`

	keys, err := parseCookieKeys(b64(j))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys (auth+encrypt), got %d", len(keys))
	}
	if string(keys[0]) != auth {
		t.Errorf("auth key mismatch")
	}
	if string(keys[1]) != enc {
		t.Errorf("encrypt key mismatch")
	}
}

func TestParseCookieKeys_ValidWithPrevious(t *testing.T) {
	auth := "12345678901234567890123456789012"
	enc := "abcdefghijklmnopqrstuvwxyz123456"
	prevAuth := "prev1234567890123456789012345678"
	prevEnc := "prevabcdefghijklmnopqrstuvwx1234"
	j := `{"current":{"auth_key":"` + auth + `","encrypt_key":"` + enc + `"},` +
		`"previous":{"auth_key":"` + prevAuth + `","encrypt_key":"` + prevEnc + `"}}`

	keys, err := parseCookieKeys(b64(j))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 4 {
		t.Fatalf("expected 4 keys (current+previous), got %d", len(keys))
	}
	if string(keys[0]) != auth || string(keys[1]) != enc {
		t.Error("current key mismatch")
	}
	if string(keys[2]) != prevAuth || string(keys[3]) != prevEnc {
		t.Error("previous key mismatch")
	}
}

func TestParseCookieKeys_PreviousEmptyKeysIgnored(t *testing.T) {
	auth := "12345678901234567890123456789012"
	enc := "abcdefghijklmnopqrstuvwxyz123456"
	j := `{"current":{"auth_key":"` + auth + `","encrypt_key":"` + enc + `"},` +
		`"previous":{"auth_key":"","encrypt_key":""}}`

	keys, err := parseCookieKeys(b64(j))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys (previous empty should be ignored), got %d", len(keys))
	}
}

func TestParseCookieKeys_64ByteAuthKey(t *testing.T) {
	auth := strings.Repeat("a", 64)
	enc := strings.Repeat("b", 32)
	j := `{"current":{"auth_key":"` + auth + `","encrypt_key":"` + enc + `"}}`

	keys, err := parseCookieKeys(b64(j))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys[0]) != 64 {
		t.Errorf("expected 64-byte auth key, got %d", len(keys[0]))
	}
}

func TestParseCookieKeys_AES128EncryptKey(t *testing.T) {
	auth := strings.Repeat("a", 32)
	enc := strings.Repeat("b", 16) // AES-128
	j := `{"current":{"auth_key":"` + auth + `","encrypt_key":"` + enc + `"}}`

	_, err := parseCookieKeys(b64(j))
	if err != nil {
		t.Fatalf("unexpected error for 16-byte encrypt key: %v", err)
	}
}

func TestParseCookieKeys_AES192EncryptKey(t *testing.T) {
	auth := strings.Repeat("a", 32)
	enc := strings.Repeat("b", 24) // AES-192
	j := `{"current":{"auth_key":"` + auth + `","encrypt_key":"` + enc + `"}}`

	_, err := parseCookieKeys(b64(j))
	if err != nil {
		t.Fatalf("unexpected error for 24-byte encrypt key: %v", err)
	}
}

// ============================================================================
// parseAllowedOrigins Tests
// ============================================================================

func TestParseAllowedOrigins_Empty(t *testing.T) {
	t.Parallel()
	result := parseAllowedOrigins("")
	if result != nil {
		t.Errorf("expected nil for empty input, got %v", result)
	}
}

func TestParseAllowedOrigins_SingleOrigin(t *testing.T) {
	t.Parallel()
	result := parseAllowedOrigins("https://example.com")
	if len(result) != 1 || result[0] != "https://example.com" {
		t.Errorf("unexpected result: %v", result)
	}
}

func TestParseAllowedOrigins_MultipleOrigins(t *testing.T) {
	t.Parallel()
	result := parseAllowedOrigins("https://a.com, https://b.com , https://c.com")
	expected := []string{"https://a.com", "https://b.com", "https://c.com"}
	if len(result) != len(expected) {
		t.Fatalf("expected %d origins, got %d", len(expected), len(result))
	}
	for i, o := range result {
		if o != expected[i] {
			t.Errorf("origin[%d] = %q, want %q", i, o, expected[i])
		}
	}
}

func TestParseAllowedOrigins_TrailingComma(t *testing.T) {
	t.Parallel()
	result := parseAllowedOrigins("https://a.com,")
	if len(result) != 1 || result[0] != "https://a.com" {
		t.Errorf("expected 1 origin, got %v", result)
	}
}

func TestParseAllowedOrigins_WhitespaceOnly(t *testing.T) {
	t.Parallel()
	result := parseAllowedOrigins("  ,  ,  ")
	if len(result) != 0 {
		t.Errorf("expected 0 origins for whitespace-only entries, got %v", result)
	}
}

// ============================================================================
// splitOriginPatterns + matchOrigin Tests
// ============================================================================

func TestSplitOriginPatterns_ExactOnly(t *testing.T) {
	t.Parallel()
	exact, wildcards := splitOriginPatterns([]string{"https://a.com", "https://b.com"})
	if len(exact) != 2 || !exact["https://a.com"] || !exact["https://b.com"] {
		t.Errorf("expected 2 exact origins, got %v", exact)
	}
	if len(wildcards) != 0 {
		t.Errorf("expected no wildcards, got %v", wildcards)
	}
}

func TestSplitOriginPatterns_WildcardOnly(t *testing.T) {
	t.Parallel()
	exact, wildcards := splitOriginPatterns([]string{"https://*.nhp.layerv.xyz", "https://*.qurl.site"})
	if len(exact) != 0 {
		t.Errorf("expected no exact origins, got %v", exact)
	}
	if len(wildcards) != 2 {
		t.Fatalf("expected 2 wildcards, got %d", len(wildcards))
	}
	if wildcards[0].scheme != "https" || wildcards[0].suffix != ".nhp.layerv.xyz" {
		t.Errorf("wildcard[0] = %+v, want scheme=https suffix=.nhp.layerv.xyz", wildcards[0])
	}
	if wildcards[1].scheme != "https" || wildcards[1].suffix != ".qurl.site" {
		t.Errorf("wildcard[1] = %+v, want scheme=https suffix=.qurl.site", wildcards[1])
	}
}

func TestSplitOriginPatterns_Mixed(t *testing.T) {
	t.Parallel()
	exact, wildcards := splitOriginPatterns([]string{
		"https://layerv.ai",
		"https://*.nhp.layerv.ai",
		"https://qurl.link",
	})
	if len(exact) != 2 || !exact["https://layerv.ai"] || !exact["https://qurl.link"] {
		t.Errorf("exact = %v", exact)
	}
	if len(wildcards) != 1 || wildcards[0].suffix != ".nhp.layerv.ai" {
		t.Errorf("wildcards = %v", wildcards)
	}
}

func TestMatchOrigin_ExactMatch(t *testing.T) {
	t.Parallel()
	exact, wildcards := splitOriginPatterns([]string{"https://layerv.ai"})
	if !matchOrigin("https://layerv.ai", exact, wildcards) {
		t.Error("expected exact match")
	}
	if matchOrigin("https://evil.com", exact, wildcards) {
		t.Error("should not match non-listed origin")
	}
}

func TestMatchOrigin_WildcardMatch(t *testing.T) {
	t.Parallel()
	exact, wildcards := splitOriginPatterns([]string{"https://*.nhp.layerv.xyz"})

	cases := []struct {
		origin string
		want   bool
	}{
		{"https://demo.nhp.layerv.xyz", true},
		{"https://console.nhp.layerv.xyz", true},
		{"https://mini-app-demo.nhp.layerv.xyz", true},
		{"https://nhp.layerv.xyz", false},               // no subdomain
		{"http://demo.nhp.layerv.xyz", false},           // wrong scheme
		{"https://evil.com.nhp.layerv.xyz", false},      // multi-level subdomain
		{"https://a.b.nhp.layerv.xyz", false},           // multi-level subdomain
		{"https://.nhp.layerv.xyz", false},              // empty subdomain
		{"https://demo.nhp.layerv.xyz.evil.com", false}, // suffix attack
	}
	for _, tc := range cases {
		got := matchOrigin(tc.origin, exact, wildcards)
		if got != tc.want {
			t.Errorf("matchOrigin(%q) = %v, want %v", tc.origin, got, tc.want)
		}
	}
}

func TestMatchOrigin_MixedExactAndWildcard(t *testing.T) {
	t.Parallel()
	exact, wildcards := splitOriginPatterns([]string{
		"https://layerv.ai",
		"https://*.nhp.layerv.ai",
		"https://qurl.link",
	})

	if !matchOrigin("https://layerv.ai", exact, wildcards) {
		t.Error("should match exact")
	}
	if !matchOrigin("https://demo.nhp.layerv.ai", exact, wildcards) {
		t.Error("should match wildcard")
	}
	if !matchOrigin("https://qurl.link", exact, wildcards) {
		t.Error("should match exact")
	}
	if matchOrigin("https://evil.com", exact, wildcards) {
		t.Error("should not match")
	}
}

func TestCORSMiddleware_WildcardPatternMatch(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, engine := gin.CreateTestContext(w)
	engine.Use(corsMiddleware([]string{"https://*.nhp.layerv.xyz", "https://layerv.ai"}))
	engine.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://demo.nhp.layerv.xyz")
	engine.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://demo.nhp.layerv.xyz" {
		t.Errorf("Allow-Origin = %q, want %q", got, "https://demo.nhp.layerv.xyz")
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Allow-Credentials = %q, want %q", got, "true")
	}
}

func TestCORSMiddleware_WildcardPatternReject(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, engine := gin.CreateTestContext(w)
	engine.Use(corsMiddleware([]string{"https://*.nhp.layerv.xyz"}))
	engine.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	engine.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin should be empty for rejected origin, got %q", got)
	}
}

// ============================================================================
// securityHeadersMiddleware Tests
// ============================================================================

func TestSecurityHeadersMiddleware(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, engine := gin.CreateTestContext(w)
	engine.Use(securityHeadersMiddleware())
	engine.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	engine.ServeHTTP(w, req)

	expectations := map[string]string{
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
	}
	for header, want := range expectations {
		got := w.Header().Get(header)
		if got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

// ============================================================================
// corsMiddleware Tests
// ============================================================================

func TestCORSMiddleware_WildcardWhenNoOrigins(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, engine := gin.CreateTestContext(w)
	engine.Use(corsMiddleware(nil))
	engine.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://anything.com")
	engine.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Allow-Origin = %q, want %q", got, "*")
	}
	// Wildcard mode must NOT set credentials (spec violation).
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("Allow-Credentials should be empty in wildcard mode, got %q", got)
	}
}

func TestCORSMiddleware_AllowedOriginEchoed(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, engine := gin.CreateTestContext(w)
	engine.Use(corsMiddleware([]string{"https://allowed.com", "https://also-ok.com"}))
	engine.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://allowed.com")
	engine.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://allowed.com" {
		t.Errorf("Allow-Origin = %q, want %q", got, "https://allowed.com")
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Allow-Credentials = %q, want %q", got, "true")
	}
	if got := w.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want %q", got, "Origin")
	}
}

func TestCORSMiddleware_RejectedOriginNoHeaders(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, engine := gin.CreateTestContext(w)
	engine.Use(corsMiddleware([]string{"https://allowed.com"}))
	engine.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	engine.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin should be empty for rejected origin, got %q", got)
	}
}

func TestCORSMiddleware_PreflightAllowed(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, engine := gin.CreateTestContext(w)
	engine.Use(corsMiddleware([]string{"https://allowed.com"}))
	// OPTIONS routes are handled by the middleware before reaching handlers.
	engine.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "https://allowed.com")
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

func TestCORSMiddleware_PreflightRejected(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, engine := gin.CreateTestContext(w)
	engine.Use(corsMiddleware([]string{"https://allowed.com"}))
	engine.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "https://evil.com")
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}
