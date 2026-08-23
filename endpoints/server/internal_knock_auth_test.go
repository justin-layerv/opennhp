package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/layervai/nhp/internalauth"
)

// Tests in this file fence the HMAC gate on /nhp/internal/knock.
// They assert the handler's contract at the auth boundary only:
//   legacy mode (signer nil)                  → no change
//   permit mode (signer set, require=false)   → warn + allow through
//   strict mode (signer set, require=true)    → reject unsigned with 401
//
// The "allow through" rows still stop before opening an AC pinhole —
// the router uses a zero-value HttpServer, so successful auth reaches
// server-owned resource resolution and returns 500 because the test fixture
// intentionally has no UdpServer.

const (
	testInternalKnockSecret = "test-secret-for-internal-knock-auth-tests"
	// Used by tests that want a valid-but-different signer to produce
	// a "wrong secret" signature. Kept as a separate const so the
	// wrong-vs-right pairing is grep-able; both satisfy MinSecretLength.
	testInternalKnockWrongSecret = "wrong-secret-for-internal-knock-tests"
)

// internalKnockTestBody mirrors emptyKnockBody in the fuzz test.
// Keeping it separate (private to this file) lets the auth tests evolve
// without coupling to the fuzz seed format.
const internalKnockTestBody = `{"request":{"aspId":"qurl","resId":"nhp-resource","srcIp":"203.0.113.25"},"resource":{"aspId":"qurl","resId":"nhp-resource"}}`

// newAuthTestRouter builds a Gin router with a signer-configured
// HttpServer. require toggles strict vs permit mode.
func newAuthTestRouter(t *testing.T, require bool) (*gin.Engine, *internalauth.Signer) {
	t.Helper()
	r, signer, _ := newAuthTestRouterWithCounters(t, require)
	return r, signer
}

// newAuthTestRouterWithCounters is the capturing variant: also returns
// a map of metric-name → count that the handler increments via
// hs.internalAuthEmit. Callers that don't care pass through the
// convenience wrapper above.
func newAuthTestRouterWithCounters(t *testing.T, require bool) (*gin.Engine, *internalauth.Signer, map[string]int) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	signer, err := internalauth.New(testInternalKnockSecret)
	if err != nil {
		t.Fatalf("internalauth.New: %v", err)
	}
	var mu sync.Mutex
	counts := map[string]int{}
	emit := func(name string) {
		mu.Lock()
		defer mu.Unlock()
		counts[name]++
	}
	hs := &HttpServer{
		internalAuthSigner:  signer,
		internalAuthRequire: require,
		internalAuthEmit:    emit,
	}
	r := gin.New()
	if err := r.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies(nil): %v", err)
	}
	r.POST("/nhp/internal/knock", hs.handleInternalKnock)
	return r, signer, counts
}

// doRequest sends a POST to /nhp/internal/knock with the given body and
// optional X-Nhp-Auth header. Source IP is loopback (127.0.0.1) so the
// pre-existing RFC-1918 check never fires.
func doRequest(t *testing.T, r *gin.Engine, body string, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/nhp/internal/knock", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set(internalauth.Header, authHeader)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// TestInternalKnock_StrictMode_RejectsUnsigned locks the HMAC-gate
// contract: with auth required, an unsigned request gets 401, not
// the permissive 200 the pre-gate legacy code would have returned.
func TestInternalKnock_StrictMode_RejectsUnsigned(t *testing.T) {
	r, _ := newAuthTestRouter(t, true)
	rec := doRequest(t, r, internalKnockTestBody, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned request: code = %d, want 401. body=%s", rec.Code, rec.Body.String())
	}
	// Response body must carry only the fixed sentinel — attackers
	// learn nothing about which arm of the check failed.
	if !strings.Contains(rec.Body.String(), internalauth.ErrInternalAuth.Error()) {
		t.Errorf("body should echo sentinel %q, got %q", internalauth.ErrInternalAuth.Error(), rec.Body.String())
	}
}

// TestInternalKnock_StrictMode_AcceptsValidSignature pins the happy
// path: a correctly signed request passes the gate and the handler
// proceeds to downstream resource resolution. The zero-value test
// server has no UdpServer, so the post-auth resource resolver returns
// 500. That body shape is the positive signal "auth accepted; the
// resolver path executed and refused an uninitialized server."
//
// Asserting only "not 401" would silently weaken if a future refactor
// short-circuited downstream entirely: the test would still pass on
// any non-401 response.
func TestInternalKnock_StrictMode_AcceptsValidSignature(t *testing.T) {
	r, signer := newAuthTestRouter(t, true)
	body := internalKnockTestBody
	sig := signer.Sign(http.MethodPost, "/nhp/internal/knock", []byte(body))

	rec := doRequest(t, r, body, sig)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("valid signature rejected with 401: %s", rec.Body.String())
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("valid signature code = %d, want 500 from resource resolver. body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "resource resolution failed") {
		t.Errorf("resource resolver did not run: %s", rec.Body.String())
	}
}

// TestInternalKnock_StrictMode_RejectsTamperedBody fences against an
// attacker who replays a captured header with a modified body — the
// body hash is part of the signed string, so the verifier must catch
// the mismatch.
func TestInternalKnock_StrictMode_RejectsTamperedBody(t *testing.T) {
	r, signer := newAuthTestRouter(t, true)
	sig := signer.Sign(http.MethodPost, "/nhp/internal/knock", []byte(internalKnockTestBody))
	// Different body ⇒ different hash ⇒ signature must fail.
	tampered := `{"request":{"UserId":"attacker"},"resource":{}}`
	rec := doRequest(t, r, tampered, sig)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("tampered body accepted: code = %d. body=%s", rec.Code, rec.Body.String())
	}
}

// TestInternalKnock_StrictMode_RejectsWrongSecret: a peer signing
// with a different secret produces a valid-looking header that must
// not pass the verifier. Catches a key-rotation regression where
// old-secret callers are silently accepted.
func TestInternalKnock_StrictMode_RejectsWrongSecret(t *testing.T) {
	r, _ := newAuthTestRouter(t, true)
	otherSigner, err := internalauth.New(testInternalKnockWrongSecret)
	if err != nil {
		t.Fatalf("internalauth.New: %v", err)
	}
	sig := otherSigner.Sign(http.MethodPost, "/nhp/internal/knock", []byte(internalKnockTestBody))
	rec := doRequest(t, r, internalKnockTestBody, sig)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-secret signature accepted: code = %d", rec.Code)
	}
}

// TestInternalKnock_PermitMode_AllowsUnsigned documents the rollout-
// window behavior: when a signer is configured but require=false, an
// unsigned request logs a warning, increments
// MetricInternalAuthFailPermit (parse-stage), and is allowed through
// to the downstream resource-resolution path. Asserting the counter
// explicitly pins the "every non-success hits the counter" contract
// on the unsigned shape (parse-stage); the sibling test
// AllowsTamperedSignature covers the signature-stage shape.
func TestInternalKnock_PermitMode_AllowsUnsigned(t *testing.T) {
	r, _, counts := newAuthTestRouterWithCounters(t, false)
	rec := doRequest(t, r, internalKnockTestBody, "")
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("permit-mode rejected unsigned request: body=%s", rec.Body.String())
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("permit-mode unsigned code = %d, want 500 from resource resolver. body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "resource resolution failed") {
		t.Errorf("resource resolver did not run: %s", rec.Body.String())
	}
	if counts[MetricInternalAuthFailPermit] != 1 {
		t.Errorf("MetricInternalAuthFailPermit = %d, want 1", counts[MetricInternalAuthFailPermit])
	}
	if counts[MetricInternalAuthSuccess] != 0 {
		t.Errorf("MetricInternalAuthSuccess = %d, want 0 (unsigned is not success)", counts[MetricInternalAuthSuccess])
	}
}

// TestInternalKnock_PermitMode_AllowsTamperedSignature fences the
// rollout-window contract that a caller signing with the wrong
// secret (the shape a mid-rollout misconfiguration emits) is still
// allowed through — that's the whole point of permit mode — AND
// that the MetricInternalAuthFailPermit counter increments. That
// counter is the rollout alarm signal operators watch to decide when
// it's safe to flip to strict; a regression that skips the IncrCounter
// call would silently unblock strict-mode flipping.
func TestInternalKnock_PermitMode_AllowsTamperedSignature(t *testing.T) {
	r, _, counts := newAuthTestRouterWithCounters(t, false)
	// A signer with a different secret produces a well-formed header
	// the real signer will reject. In permit mode that's the exact
	// shape a mid-rollout mis-configuration emits.
	otherSigner, err := internalauth.New(testInternalKnockWrongSecret)
	if err != nil {
		t.Fatalf("internalauth.New: %v", err)
	}
	sig := otherSigner.Sign(http.MethodPost, "/nhp/internal/knock", []byte(internalKnockTestBody))
	rec := doRequest(t, r, internalKnockTestBody, sig)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("permit-mode rejected tampered-sig request: body=%s", rec.Body.String())
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("permit-mode bad-sig code = %d, want 500 from resource resolver. body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "resource resolution failed") {
		t.Errorf("permit-mode with bad sig did not reach resource resolver: %s", rec.Body.String())
	}
	if counts[MetricInternalAuthFailPermit] != 1 {
		t.Errorf("MetricInternalAuthFailPermit = %d, want 1", counts[MetricInternalAuthFailPermit])
	}
	if counts[MetricInternalAuthSuccess] != 0 {
		t.Errorf("MetricInternalAuthSuccess = %d, want 0 (bad sig is not success)", counts[MetricInternalAuthSuccess])
	}
}

// TestInternalKnock_StrictMode_IncrementsFailStrict fences the strict-
// mode counter contract: a 401 must be paired with exactly one
// MetricInternalAuthFailStrict increment so the rollout dashboard
// counts rejections accurately.
func TestInternalKnock_StrictMode_IncrementsFailStrict(t *testing.T) {
	r, _, counts := newAuthTestRouterWithCounters(t, true)
	rec := doRequest(t, r, internalKnockTestBody, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned strict-mode request: code = %d, want 401", rec.Code)
	}
	if counts[MetricInternalAuthFailStrict] != 1 {
		t.Errorf("MetricInternalAuthFailStrict = %d, want 1", counts[MetricInternalAuthFailStrict])
	}
}

// TestInternalKnock_IncrementsSuccess fences the positive counter:
// a validly signed request must increment MetricInternalAuthSuccess.
// Without this fence, "FailPermit → 0" alone is ambiguous (no traffic
// vs. everyone signed) and the strict-mode flip becomes unsafe.
func TestInternalKnock_IncrementsSuccess(t *testing.T) {
	r, signer, counts := newAuthTestRouterWithCounters(t, false)
	sig := signer.Sign(http.MethodPost, "/nhp/internal/knock", []byte(internalKnockTestBody))
	rec := doRequest(t, r, internalKnockTestBody, sig)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("valid sig rejected: body=%s", rec.Body.String())
	}
	if counts[MetricInternalAuthSuccess] != 1 {
		t.Errorf("MetricInternalAuthSuccess = %d, want 1", counts[MetricInternalAuthSuccess])
	}
	if counts[MetricInternalAuthFailPermit] != 0 {
		t.Errorf("MetricInternalAuthFailPermit = %d, want 0 (valid sig is not a failure)", counts[MetricInternalAuthFailPermit])
	}
}

// TestInternalKnock_CounterEmission_RequestBySourceAndCallerIP fences the
// #1140 internal-surface visibility signal: once a /nhp/internal/knock
// request is parsed and accepted by the auth gate, operators should get a
// base request counter plus Source/CallerIP attribution, even if catalog
// resolution later rejects it.
func TestInternalKnock_CounterEmission_RequestBySourceAndCallerIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	us := &UdpServer{
		metrics:        metrics.NewPublisherForTest(t),
		authServiceMap: common.AuthSvcProviderMap{},
	}
	hs := &HttpServer{udpServer: us}
	fwdReq := HttpKnockForwardRequest{
		Request: &common.HttpKnockRequest{
			AuthServiceId: "qurl",
			ResourceId:    "nhp-resource",
			SrcIp:         "203.0.113.25",
		},
		Source: SourceAPI,
	}

	rec := callHandleInternalKnock(t, hs, fwdReq)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 from missing ASP. body=%s", rec.Code, rec.Body.String())
	}

	counters, dimCounters := us.metrics.CountersForTest(t)
	if got := counters[MetricInternalKnockRequest]; got != 1 {
		t.Fatalf("%s base counter = %v, want 1", MetricInternalKnockRequest, got)
	}
	if got := sumDimCounterMatching(dimCounters, MetricInternalKnockRequest, "Source=api", "CallerIP=10.0.1.100"); got != 1 {
		t.Fatalf("%s Source/CallerIP breakdown = %v, want 1 (dimCounters=%v)", MetricInternalKnockRequest, got, dimCounters)
	}
}

func TestNormalizeInternalKnockMetricSource(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{name: "api", source: SourceAPI, want: SourceAPI},
		{name: "server", source: "", want: "server"},
		{name: "unknown", source: "partner", want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeInternalKnockMetricSource(tt.source); got != tt.want {
				t.Fatalf("normalizeInternalKnockMetricSource(%q) = %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}

// TestInternalKnock_LegacyMode_NoSignerSet documents the pre-gate
// baseline: a handler with no signer configured behaves exactly as
// before — no auth layer, RFC-1918 gate only. The pre-fix code
// passed unsigned requests straight through to downstream; this test
// pins both halves: not-401 (no accidental enforcement) and the
// downstream resource-resolution 500 (positive "reached downstream" signal).
//
// Test design: zero-value HttpServer{} (nil udpServer) is
// deliberate. The current post-auth path resolves ResourceData from
// the server-owned catalog before reaching the retired direct-admission
// terminal, so the zero-value fixture returns
// an internal server-not-ready error instead of trusting caller-supplied
// ResourceData.
func TestInternalKnock_LegacyMode_NoSignerSet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	hs := &HttpServer{} // no signer
	r := gin.New()
	if err := r.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies(nil): %v", err)
	}
	r.POST("/nhp/internal/knock", hs.handleInternalKnock)
	rec := doRequest(t, r, internalKnockTestBody, "")
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("legacy mode emitted 401 (gate regressed on): body=%s", rec.Body.String())
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("legacy mode code = %d, want 500 from resource resolver. body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "resource resolution failed") {
		t.Errorf("legacy mode did not reach resource resolver: %s", rec.Body.String())
	}
}

// Replay-window coverage lives in TestVerify_ClockSkew in the
// common package — the pure-verifier tests use a time-injected signer
// that can actually produce a valid-HMAC-but-stale-timestamp header.
// A handler-level duplicate would be structurally weaker (the
// handler's signer is pinned to time.Now) and add test surface
// without adding fence.

// TestInternalKnock_StrictMode_RejectsCrossPathReplay: a signature
// valid for a different path must not pass verification on the knock
// endpoint. The path is in the signing string so a captured signature
// for e.g. /nhp/internal/other can't be replayed here.
func TestInternalKnock_StrictMode_RejectsCrossPathReplay(t *testing.T) {
	r, signer := newAuthTestRouter(t, true)
	// Sign for the wrong path.
	sig := signer.Sign(http.MethodPost, "/nhp/internal/other", []byte(internalKnockTestBody))
	rec := doRequest(t, r, internalKnockTestBody, sig)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cross-path signature accepted: code = %d", rec.Code)
	}
}

// TestInternalKnock_RejectsQueryString fences the "signing string
// covers method+path+body, NOT query" footgun. A future endpoint
// that adds ?max_age=5 would silently leave that parameter un-
// signed; rejecting the request at the handler means the first
// person to grow the API surface gets a loud failure. Runs in both
// strict and permit modes — the rejection is a shape check, not an
// auth check, so it must fire regardless of signer configuration.
// (Fragment rejection is defensive in the handler but not testable
// via HTTP — clients strip fragments before sending, so the check
// is only reachable through code paths that construct URL directly.)
func TestInternalKnock_RejectsQueryString(t *testing.T) {
	cases := []struct {
		name   string
		strict bool
	}{
		{"strict", true},
		{"permit", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := newAuthTestRouter(t, tc.strict)
			req := httptest.NewRequest(http.MethodPost, "/nhp/internal/knock?foo=bar", strings.NewReader(internalKnockTestBody))
			req.RemoteAddr = "127.0.0.1:54321"
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("query-bearing URL not rejected: code=%d body=%s", rec.Code, rec.Body.String())
			}
			// Body must be the shape-error string ("bad request"), not
			// the auth sentinel — a future refactor that accidentally
			// routes query-bearing requests through the auth branch
			// would leak internalauth.ErrInternalAuth.Error() into the body
			// and this assertion would fire.
			if !strings.Contains(rec.Body.String(), "bad request") {
				t.Errorf("expected shape-error body, got %q", rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), internalauth.ErrInternalAuth.Error()) {
				t.Errorf("body leaked auth sentinel into query-reject path: %q", rec.Body.String())
			}
		})
	}
}

// TestInternalKnock_HeaderCaseInsensitive fences the contract that
// ctx.GetHeader canonicalizes via net/http — a client sending
// "x-nhp-auth" (lowercase) instead of the canonical "X-Nhp-Auth"
// must still be accepted. Without this test a future refactor to a
// case-sensitive header lookup (e.g. raw map access) would break
// interop with any client library that lower-cases header names.
func TestInternalKnock_HeaderCaseInsensitive(t *testing.T) {
	r, signer := newAuthTestRouter(t, true)
	sig := signer.Sign(http.MethodPost, "/nhp/internal/knock", []byte(internalKnockTestBody))
	req := httptest.NewRequest(http.MethodPost, "/nhp/internal/knock", strings.NewReader(internalKnockTestBody))
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("Content-Type", "application/json")
	// Set with lowercase name — net/http canonicalizes to
	// X-Nhp-Auth internally, so ctx.GetHeader(internalauth.Header)
	// should still see this value.
	req.Header.Set("x-nhp-auth", sig)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Errorf("lowercase header name rejected: body=%s", rec.Body.String())
	}
}

// TestInternalKnock_IgnoresXForwardedFor fences the contract that
// handleInternalKnock uses RemoteAddr, not X-Forwarded-For, for the
// private-IP gate. If the operator ever configures NHP_TRUSTED_PROXY_CIDRS
// with a broad range (common misconfig), ctx.ClientIP() would walk
// XFF and a workload at a public IP could spoof 10.0.0.1 to pass
// the gate. Using RemoteAddr (the socket peer, unspoofable at L4)
// makes the internal surface independent of the server-wide
// trusted-proxy setting.
func TestInternalKnock_IgnoresXForwardedFor(t *testing.T) {
	r, _ := newAuthTestRouter(t, false)
	req := httptest.NewRequest(http.MethodPost, "/nhp/internal/knock", strings.NewReader(internalKnockTestBody))
	// Socket peer: public IP. Gate must reject.
	req.RemoteAddr = "8.8.8.8:12345"
	req.Header.Set("Content-Type", "application/json")
	// Attacker-controlled XFF claims a private IP. If the gate
	// used ctx.ClientIP() with a permissive trusted-proxy config,
	// this would spoof past the check.
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("XFF-spoofed request not rejected: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestInternalKnock_StrictMode_SourceIPGateStillApplies locks the
// layered-defense contract: even with a valid signature, a non-
// private source IP must still be rejected by layer-1. Removing the
// IP gate without replacing it would let an attacker who stole the
// secret hit the endpoint from the public internet.
func TestInternalKnock_StrictMode_SourceIPGateStillApplies(t *testing.T) {
	r, signer := newAuthTestRouter(t, true)
	sig := signer.Sign(http.MethodPost, "/nhp/internal/knock", []byte(internalKnockTestBody))
	req := httptest.NewRequest(http.MethodPost, "/nhp/internal/knock", strings.NewReader(internalKnockTestBody))
	req.RemoteAddr = "8.8.8.8:12345" // public source
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(internalauth.Header, sig)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("public source with valid sig not 403: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestInternalKnock_StrictMode_BodyLimit pins that the size guard
// fires before the signature check. A client that uploads a giant
// body can't force expensive HMAC computation on the server before
// getting rejected. Two rows: one at the exact limit (must NOT
// 413 — check is `>`, not `>=`) and one one byte over (must 413).
// Pinning the boundary explicitly stops a future refactor from
// flipping `>` to `>=` and silently tightening the contract.
func TestInternalKnock_StrictMode_BodyLimit(t *testing.T) {
	cases := []struct {
		name       string
		size       int
		wantStatus int
	}{
		// At limit: reaches the signer, which rejects unsigned with 401.
		// The assertion is "not 413" — any non-413 means the size
		// check passed. 401 is the expected downstream outcome here.
		{"at limit (65536)", 65536, http.StatusUnauthorized},
		// One byte over: the size guard must fire first, returning 413
		// without reaching the signer.
		{"one over (65537)", 65537, http.StatusRequestEntityTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := newAuthTestRouter(t, true)
			body := bytes.Repeat([]byte("a"), tc.size)
			req := httptest.NewRequest(http.MethodPost, "/nhp/internal/knock", bytes.NewReader(body))
			req.RemoteAddr = "127.0.0.1:54321"
			req.Header.Set("Content-Type", "application/json")
			// No auth header — even so, a body-size reject must come first when over.
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("size=%d: code = %d, want %d. body=%s", tc.size, rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

// TestParseInternalAuthRequire fences the typo-detection contract on
// NHP_INTERNAL_AUTH_REQUIRE: only documented truthy/falsy tokens may
// produce a result; everything else must error so a Terraform typo
// like `=1` (intent: strict) doesn't silently leave the bypass open.
func TestParseInternalAuthRequire(t *testing.T) {
	cases := []struct {
		raw     string
		want    bool
		wantErr bool
	}{
		{"", false, false}, // unset → false (permit)
		{"true", true, false},
		{"True", true, false},
		{"TRUE", true, false},
		{"1", true, false},
		{"yes", true, false},
		{"on", true, false},
		{"  true  ", true, false}, // whitespace tolerant
		{"false", false, false},
		{"0", false, false},
		{"no", false, false},
		{"off", false, false},
		// Typos / misspellings must error so the operator notices —
		// a silent permit-mode default on a typo is the bug class
		// this whole flag was added to defend against.
		{"trueish", false, true},
		{"truee", false, true},
		{"enable", false, true},
		{"enabled", false, true},
		{"y", false, true}, // not in the accepted set
		{"random", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := parseInternalAuthRequire(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("raw=%q: want error, got nil", tc.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("raw=%q: unexpected error: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Errorf("raw=%q: got %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestLoadInternalAuthConfig fences the three misconfiguration
// classes the loader must refuse at startup. Each row is a Terraform-
// shape mistake that would otherwise leave the runtime in legacy
// mode — the exact VPC-wide bypass this gate is closing.
func TestLoadInternalAuthConfig(t *testing.T) {
	validSecret := "a-valid-secret-bytes-padded-to-32+"
	cases := []struct {
		name        string
		secret      string
		require     string
		wantMode    string
		wantSigner  bool
		wantRequire bool
		wantErrSub  string
	}{
		{
			name:       "empty secret, empty require → legacy",
			wantMode:   "legacy",
			wantSigner: false,
		},
		{
			name:       "empty secret, require=false → legacy",
			require:    "false",
			wantMode:   "legacy",
			wantSigner: false,
		},
		{
			// Whitespace-only secret must trim to empty → legacy,
			// NOT hit the 32-byte-min error path. The loader's
			// whitespace-tolerance contract lives here.
			name:       "whitespace-only secret → legacy (trimmed to empty)",
			secret:     "   \t\n  ",
			wantMode:   "legacy",
			wantSigner: false,
		},
		{
			// Secret with surrounding whitespace must be trimmed
			// and otherwise behave like the clean value — this
			// fences the "Secrets Manager template with trailing
			// \n" case against producing a subtly-wrong HMAC.
			name:       "secret with surrounding whitespace → permit",
			secret:     "  " + validSecret + "\n",
			wantMode:   "permit",
			wantSigner: true,
		},
		{
			name:       "secret set, require unset → permit",
			secret:     validSecret,
			wantMode:   "permit",
			wantSigner: true,
		},
		{
			name:        "secret set, require=true → strict",
			secret:      validSecret,
			require:     "true",
			wantMode:    "strict",
			wantSigner:  true,
			wantRequire: true,
		},
		{
			// The regression this whole fence exists for: operator
			// flips require=true but forgets the secret → legacy
			// mode. Must fail Start so it never reaches runtime.
			name:       "require=true without secret fails loud",
			require:    "true",
			wantErrSub: "requires NHP_INTERNAL_AUTH_SECRET to be set",
		},
		{
			name:       "malformed require token fails loud",
			secret:     validSecret,
			require:    "enabled",
			wantErrSub: "NHP_INTERNAL_AUTH_REQUIRE",
		},
		{
			name:       "short secret fails loud (signer constructor)",
			secret:     "too-short",
			wantErrSub: "NHP_INTERNAL_AUTH_SECRET",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer, require, mode, err := loadInternalAuthConfig(tc.secret, tc.require)
			if tc.wantErrSub != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got nil (mode=%q, signer=%v)", tc.wantErrSub, mode, signer)
				}
				if !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Errorf("err %q missing substring %q", err.Error(), tc.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mode != tc.wantMode {
				t.Errorf("mode = %q, want %q", mode, tc.wantMode)
			}
			// Assert require directly, not just indirectly via mode,
			// so a future refactor that accidentally swaps the
			// bool-to-mode mapping is caught.
			if require != tc.wantRequire {
				t.Errorf("require = %v, want %v", require, tc.wantRequire)
			}
			if tc.wantSigner && signer == nil {
				t.Error("want non-nil signer")
			}
			if !tc.wantSigner && signer != nil {
				t.Errorf("want nil signer, got %v", signer)
			}
		})
	}
}

// TestInternalAuthSigner_Concurrent exercises Sign and Verify under
// parallel load. The signer's `secret` is immutable after construction
// and `now` is `time.Now` in production, so concurrent use is safe by
// construction — this test is a -race fence so that a future edit
// introducing mutable per-call state (e.g. a cached buffer or
// stateful HMAC) trips the race detector instead of silently
// corrupting signatures.
//
// Defensive duplication: the canonical concurrency fence now lives at
// internalauth.TestSign_ConcurrentUse (in the shared module). This
// test stays here because nhp-server is the consumer that would
// observe a regression first if the module's invariant broke under
// the in-tree replace directive (vs. a tagged module bump). When the
// cross-repo tag-cut protocol (#1836) is established and qurl-service
// + qurl-reverse-tunnel-server pin to a real version, this test
// becomes pure duplication and can be deleted in favor of trusting
// the module's own fence.
func TestInternalAuthSigner_Concurrent(t *testing.T) {
	signer, err := internalauth.New(testInternalKnockSecret)
	if err != nil {
		t.Fatalf("internalauth.New: %v", err)
	}
	const workers = 16
	const iters = 200
	errCh := make(chan error, workers*iters)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			body := []byte(fmt.Sprintf(`{"worker":%d}`, id))
			for j := 0; j < iters; j++ {
				hdr := signer.Sign("POST", "/nhp/internal/knock", body)
				if verr := signer.Verify(hdr, "POST", "/nhp/internal/knock", body, 0); verr != nil {
					errCh <- fmt.Errorf("worker %d iter %d: %w", id, j, verr)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Error(e)
	}
}
