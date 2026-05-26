package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/layervai/nhp/internalauth"
)

// Tests in this file fence the contract on
// POST /nhp/internal/token/validate (PR-2b). The handler is shaped to
// match handleInternalKnock's auth posture exactly — re-using the
// same signer + emit + require state — so most tests focus on the
// validate-specific contract:
//
//   - happy path returns the entry's metadata
//   - expired entry returns valid=false, error="expired"
//   - zero ExpireTime treated as expired (fail-closed)
//   - unknown token returns valid=false, error="not_found"
//   - HMAC mismatch in strict mode returns 401
//   - idempotency: two validations within TTL return identical bodies
//   - missing/empty token field returns 400
//   - nil entry.User: handler doesn't panic, returns empty KnockUser
//
// The auth-layer rows (RFC-1918 gate, body limit, query rejection,
// permit-mode allow-through, counter-emission) ARE re-asserted here
// rather than delegated to internal_knock_auth_test.go. The two
// handlers each carry their own copy of the gate (only the signer
// is shared), so a cut-paste regression in one wouldn't be caught
// by tests pinned on the other. Cross-cutting concerns that are
// genuinely once-per-process (header case sensitivity at the gin
// layer, XFF spoof posture) stay delegated.

const (
	testTokenValidateSecret      = "test-secret-for-token-validate-tests-32"
	testTokenValidateWrongSecret = "wrong-secret-for-token-validate-tests-32"
)

// newTokenValidateRouter builds a Gin router with a signer-configured
// HttpServer wired to a real (in-memory) tokenStore so the validate
// handler can resolve actual entries.
func newTokenValidateRouter(t *testing.T, require bool) (*gin.Engine, *internalauth.Signer, *UdpServer) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	signer, err := internalauth.New(testTokenValidateSecret)
	if err != nil {
		t.Fatalf("internalauth.New: %v", err)
	}
	// No mutex: the function discards its argument (this helper
	// drops counter visibility on purpose — see
	// newTokenValidateRouterWithCounters for the counter-capturing
	// variant). Mirrors the no-mutex rationale on that sibling.
	emit := func(string) {}
	us := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
	}
	hs := &HttpServer{
		udpServer:           us,
		internalAuthSigner:  signer,
		internalAuthRequire: require,
		internalAuthEmit:    emit,
	}
	r := gin.New()
	if err := r.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies(nil): %v", err)
	}
	r.POST("/nhp/internal/token/validate", hs.handleInternalTokenValidate)
	return r, signer, us
}

// newTokenValidateRouterWithCounters is the counter-capturing
// variant of newTokenValidateRouter. The returned map keys on the
// metric-name string the handler passes to internalAuthEmit; tests
// assert against it directly. Mirrors newAuthTestRouterWithCounters
// in internal_knock_auth_test.go — kept separate because the two
// handlers have independent emit-site copies and a regression in
// one wouldn't be caught by tests pinned on the other.
//
// No mutex on the counts map: gin processes one request at a time
// per Engine.ServeHTTP call, and these tests don't fan out via
// goroutines. If a future test reaches for concurrent t.Parallel
// fan-out against the same router, wrap counts with a sync.Mutex
// here.
func newTokenValidateRouterWithCounters(t *testing.T, require bool) (*gin.Engine, *internalauth.Signer, *UdpServer, map[string]int) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	signer, err := internalauth.New(testTokenValidateSecret)
	if err != nil {
		t.Fatalf("internalauth.New: %v", err)
	}
	counts := map[string]int{}
	emit := func(name string) {
		counts[name]++
	}
	us := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
	}
	hs := &HttpServer{
		udpServer:           us,
		internalAuthSigner:  signer,
		internalAuthRequire: require,
		internalAuthEmit:    emit,
	}
	r := gin.New()
	if err := r.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies(nil): %v", err)
	}
	r.POST("/nhp/internal/token/validate", hs.handleInternalTokenValidate)
	return r, signer, us, counts
}

// doValidateRequest sends a POST to /nhp/internal/token/validate.
// Source IP is loopback so the RFC-1918 gate never fires.
func doValidateRequest(t *testing.T, r *gin.Engine, body string, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/nhp/internal/token/validate", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set(internalauth.Header, authHeader)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// signValidate signs a body for /nhp/internal/token/validate.
func signValidate(t *testing.T, signer *internalauth.Signer, body string) string {
	t.Helper()
	return signer.Sign(http.MethodPost, "/nhp/internal/token/validate", []byte(body))
}

type fakeACKTokenStore struct {
	entry     *ACTokenEntry
	found     bool
	err       error
	loadCalls int
}

func (f *fakeACKTokenStore) StoreACToken(context.Context, string, *ACTokenEntry) error {
	return nil
}

func (f *fakeACKTokenStore) LoadACToken(context.Context, string) (*ACTokenEntry, bool, error) {
	f.loadCalls++
	return f.entry, f.found, f.err
}

func storeTestACToken(t *testing.T, us *UdpServer, token string, entry *ACTokenEntry) {
	t.Helper()
	if err := us.storeACToken(context.Background(), token, entry); err != nil {
		t.Fatalf("storeACToken(%q): %v", token, err)
	}
}

// TestInternalTokenValidate_Happy locks the success contract: a
// stored, unexpired entry returns valid=true with every metadata
// field populated. Asserts the round-trip of KnockSrcIP, KnockUser,
// RunID, and an RFC3339Nano ExpiresAt — the exact fields tunnel-server
// PR-2c's knock_validator consumes.
//
// Deliberately does NOT pre-truncate expire to whole seconds: the
// handler advertises sub-second precision via RFC3339Nano, and the
// round-trip parse must equal the in-memory ExpireTime exactly. A
// regression to RFC3339 would round down here and trip the Equal()
// assertion below.
func TestInternalTokenValidate_Happy(t *testing.T) {
	r, signer, us := newTokenValidateRouter(t, true)

	expire := time.Now().Add(60 * time.Second).UTC()
	entry := &ACTokenEntry{
		User: &common.AgentUser{
			UserId:         "user-happy",
			DeviceId:       "device-1",
			OrganizationId: "org-1",
			AuthServiceId:  "asp-1",
			OwnerId:        "owner-from-pubkey-lookup",
		},
		ResourceId: "r-happy",
		ACTokens:   map[string]string{"r-happy": "ac-token-happy"},
		KnockSrcIP: "203.0.113.42",
		RunID:      "run-happy",
		OpenTime:   60,
		ExpireTime: expire,
	}
	storeTestACToken(t, us, "ac-token-happy", entry)

	body := `{"token":"ac-token-happy","agent_run_id":"run-from-caller"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))

	if rec.Code != http.StatusOK {
		t.Fatalf("happy path: code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	var got internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v. body=%s", err, rec.Body.String())
	}
	if !got.Valid {
		t.Errorf("Valid = false, want true (body=%s)", rec.Body.String())
	}
	if got.KnockSrcIP != "203.0.113.42" {
		t.Errorf("KnockSrcIP = %q, want %q", got.KnockSrcIP, "203.0.113.42")
	}
	if got.KnockUser != "user-happy" {
		t.Errorf("KnockUser = %q, want %q", got.KnockUser, "user-happy")
	}
	// OwnerId surfaces the server-resolved tenant identity stamped by
	// NewACKTokenEntry. Per CSA Stealth Mode SDP §"NHP Workflow",
	// the NHP-Server's pubkey-based authentication is the
	// authoritative identity signal — this validator response is the
	// downstream surfacing of that resolution for tunnel-server (or
	// any other protected-service consumer) to use as the authorization
	// identity without re-resolving from client-supplied labels.
	if got.OwnerId != "owner-from-pubkey-lookup" {
		t.Errorf("OwnerId = %q, want %q", got.OwnerId, "owner-from-pubkey-lookup")
	}
	// RunID echoes the entry's stored RunID, not the request's
	// agent_run_id, when the entry has one. PR-2c's handoff is
	// "trust the entry over the caller" so a misbehaving caller
	// can't claim ownership of a different run's pinhole.
	if got.RunID != "run-happy" {
		t.Errorf("RunID = %q, want %q (entry.RunID wins over request.agent_run_id)", got.RunID, "run-happy")
	}
	if got.Error != "" {
		t.Errorf("Error = %q, want empty", got.Error)
	}
	// ExpiresAt is RFC3339Nano; round-trip parse to confirm shape
	// AND that sub-second precision survives the wire encoding.
	parsedExp, err := time.Parse(time.RFC3339Nano, got.ExpiresAt)
	if err != nil {
		t.Errorf("ExpiresAt %q is not RFC3339Nano: %v", got.ExpiresAt, err)
	} else if !parsedExp.Equal(expire) {
		t.Errorf("ExpiresAt round-trip mismatch: got %v, want %v (RFC3339 would round to seconds)", parsedExp, expire)
	}
	// Belt-and-braces: resource_id is intentionally omitted from
	// the response (entry.ResourceId is held server-side but the
	// wire contract does not surface it today — see the handler's
	// "entry.ResourceId is intentionally omitted" comment). A
	// future change that adds the field without coordinating with
	// the tunnel-server consumer would land silently. Fail loud
	// if a regression reintroduces it.
	//
	// Check key absence at the JSON layer rather than substring,
	// otherwise a future field whose value happens to contain
	// "resource_id" (e.g., an Error string) would false-positive.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &fields); err != nil {
		t.Errorf("decode response into fields map: %v", err)
	} else if _, present := fields["resource_id"]; present {
		t.Errorf("response body contains resource_id key (expected omitted until paired tunnel-server change): %s", rec.Body.String())
	}
}

// TestInternalTokenValidate_HappyEchoesRunIDOnEmptyEntry pins the
// "callers running ahead of PR-2c get their run_id back" contract.
// Entry.RunID is empty (the ACK-path default until PR-2c plumbs the
// agent registration thread); the handler must echo the request's
// agent_run_id so caller-side correlation works during the
// transition window.
func TestInternalTokenValidate_HappyEchoesRunIDOnEmptyEntry(t *testing.T) {
	r, signer, us := newTokenValidateRouter(t, true)

	storeTestACToken(t, us, "ac-token-no-runid", &ACTokenEntry{
		User:       &common.AgentUser{UserId: "u"},
		ResourceId: "r",
		KnockSrcIP: "10.0.0.5",
		// RunID intentionally empty — the ACK-path default before PR-2c.
		OpenTime:   60,
		ExpireTime: time.Now().Add(60 * time.Second),
	})

	body := `{"token":"ac-token-no-runid","agent_run_id":"caller-supplied-run"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	var got internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Valid {
		t.Fatalf("Valid = false, want true. body=%s", rec.Body.String())
	}
	if got.RunID != "caller-supplied-run" {
		t.Errorf("RunID = %q, want caller's agent_run_id %q (entry.RunID was empty)",
			got.RunID, "caller-supplied-run")
	}
}

// TestInternalTokenValidate_EmptyOwnerId pins the omitempty wire
// contract on the OwnerId field. Entries created via paths that
// don't have a pubkey-bound resolution at the publish hop (the HTTP
// knock path, the forward-receiver path, the legacy non-cloud-mode
// UDP path) have entry.User.OwnerId == "". The response field is
// json:"owner_id,omitempty", so the key must be ABSENT from the
// wire — not present with an empty string.
//
// A regression that drops the omitempty tag, or a future consumer
// that flips OwnerId to a required field, would land silently
// without this assertion. Mirrors the resource_id absence pattern at
// the tail of TestInternalTokenValidate_Happy: assert key-absence
// at the JSON-fields layer rather than substring-match, so a future
// field whose value happens to contain "owner_id" doesn't
// false-positive.
func TestInternalTokenValidate_EmptyOwnerId(t *testing.T) {
	r, signer, us := newTokenValidateRouter(t, true)

	storeTestACToken(t, us, "ac-token-no-owner", &ACTokenEntry{
		User: &common.AgentUser{
			UserId:  "u",
			OwnerId: "", // explicit zero value: the HTTP/forward/legacy-non-cloud-mode shape
		},
		ResourceId: "r",
		KnockSrcIP: "10.0.0.6",
		OpenTime:   60,
		ExpireTime: time.Now().Add(60 * time.Second),
	})

	body := `{"token":"ac-token-no-owner","agent_run_id":"caller-supplied-run"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}

	// Assert key absence at the JSON-fields layer so a future field
	// whose value happens to contain "owner_id" doesn't trip a
	// substring match.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &fields); err != nil {
		t.Fatalf("decode response into fields map: %v", err)
	}
	if _, present := fields["owner_id"]; present {
		t.Errorf("response body contains owner_id key with empty entry.User.OwnerId (expected omitted via json:\"owner_id,omitempty\"): %s",
			rec.Body.String())
	}
}

// TestInternalTokenValidate_Expired locks the "valid=false +
// error=expired" branch. Entry is in the store but ExpireTime is in
// the past — VerifyAccessToken doesn't consult expiry (CleanExpired
// does, on a refresh interval), so the handler must check ExpireTime
// itself. Catches a regression where the handler trusts the absence
// of a not_found result as proof of validity.
func TestInternalTokenValidate_Expired(t *testing.T) {
	r, signer, us := newTokenValidateRouter(t, true)

	storeTestACToken(t, us, "ac-token-expired", &ACTokenEntry{
		User:       &common.AgentUser{UserId: "u"},
		ResourceId: "r-expired",
		KnockSrcIP: "10.0.0.10",
		OpenTime:   60,
		ExpireTime: time.Now().Add(-time.Second),
	})

	body := `{"token":"ac-token-expired"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))

	if rec.Code != http.StatusOK {
		t.Fatalf("expired: code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	var got internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Valid {
		t.Errorf("Valid = true, want false (entry expired)")
	}
	if got.Error != "expired" {
		t.Errorf("Error = %q, want %q", got.Error, "expired")
	}
	// Belt-and-braces: the handler must not leak metadata on a
	// failed validation. Otherwise an attacker hitting the
	// endpoint with valid stolen secrets could enumerate
	// post-expiry knock_src_ip / user values.
	if got.KnockSrcIP != "" {
		t.Errorf("KnockSrcIP leaked on expired: %q", got.KnockSrcIP)
	}
	if got.KnockUser != "" {
		t.Errorf("KnockUser leaked on expired: %q", got.KnockUser)
	}
}

// TestInternalTokenValidate_ExpiredEchoesRunID fences the
// "expired branch echoes caller's agent_run_id" contract. The
// handler deliberately echoes req.AgentRunID (not entry.RunID)
// on the expired path — the rationale is that the live pinhole
// is gone, so the run_id is purely a request/response
// correlation key for the caller's log dive. A regression that
// flipped this to entry.RunID would silently drop the caller's
// correlation key for ACK-path tokens (where entry.RunID is
// empty until PR-2c wires the registration thread).
func TestInternalTokenValidate_ExpiredEchoesRunID(t *testing.T) {
	r, signer, us := newTokenValidateRouter(t, true)
	storeTestACToken(t, us, "ac-token-expired-runid", &ACTokenEntry{
		User:       &common.AgentUser{UserId: "u"},
		ResourceId: "r",
		KnockSrcIP: "10.0.0.10",
		RunID:      "entry-stored-run",
		OpenTime:   60,
		ExpireTime: time.Now().Add(-time.Second),
	})
	body := `{"token":"ac-token-expired-runid","agent_run_id":"caller-run"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	var got internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.RunID != "caller-run" {
		t.Errorf("RunID = %q, want %q (expired branch must echo caller's agent_run_id, not entry.RunID)",
			got.RunID, "caller-run")
	}
}

// TestInternalTokenValidate_UnknownFieldsTolerated fences the
// forward-compat contract: a body with fields the server doesn't
// recognize must be accepted, not rejected. Documented at the
// handler's body-decode site — a tunnel-server caller bumped to
// a future PR's body shape (e.g., resource_id added later)
// should be able to probe an older server without being rejected
// on the wire. A future regression that calls
// DisallowUnknownFields() would silently break that promise.
func TestInternalTokenValidate_UnknownFieldsTolerated(t *testing.T) {
	r, signer, us := newTokenValidateRouter(t, true)
	storeTestACToken(t, us, "ac-token-unknown-field", &ACTokenEntry{
		User:       &common.AgentUser{UserId: "u"},
		ResourceId: "r",
		KnockSrcIP: "10.0.0.7",
		OpenTime:   60,
		ExpireTime: time.Now().Add(60 * time.Second),
	})
	// Body carries a field the server doesn't know about.
	body := `{"token":"ac-token-unknown-field","future_field":"y","resource_id":"r"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("unknown-field-tolerated: code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	var got internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Valid {
		t.Errorf("Valid = false, want true (unknown fields must be tolerated, not rejected)")
	}
}

// TestInternalTokenValidate_ZeroExpireTime fences the fail-closed
// posture on a zero ExpireTime. Production construction paths
// (NewACKTokenEntry, GenerateAccessToken) always set ExpireTime,
// so this is unreachable today — but a future path that forgets
// to set it must NOT return valid=true. The handler treats a zero
// ExpireTime as expired rather than fall through to the happy
// path, which would otherwise grant immortal validation.
func TestInternalTokenValidate_ZeroExpireTime(t *testing.T) {
	r, signer, us := newTokenValidateRouter(t, true)

	storeTestACToken(t, us, "ac-token-zero-expiry", &ACTokenEntry{
		User:       &common.AgentUser{UserId: "u"},
		ResourceId: "r-zero",
		KnockSrcIP: "10.0.0.11",
		OpenTime:   60,
		// ExpireTime intentionally omitted — zero value.
	})

	body := `{"token":"ac-token-zero-expiry"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))

	if rec.Code != http.StatusOK {
		t.Fatalf("zero-expiry: code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	var got internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Valid {
		t.Errorf("Valid = true, want false (zero ExpireTime must fail closed)")
	}
	if got.Error != "expired" {
		t.Errorf("Error = %q, want %q", got.Error, "expired")
	}
}

// TestInternalTokenValidate_NotFound locks the "valid=false +
// error=not_found" branch for an unknown token.
func TestInternalTokenValidate_NotFound(t *testing.T) {
	r, signer, _ := newTokenValidateRouter(t, true)

	body := `{"token":"never-issued"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))

	if rec.Code != http.StatusOK {
		t.Fatalf("not_found: code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	var got internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Valid {
		t.Errorf("Valid = true, want false (token not in store)")
	}
	if got.Error != "not_found" {
		t.Errorf("Error = %q, want %q", got.Error, "not_found")
	}
}

// TestInternalTokenValidate_NotFoundEchoesRunID pins the contract
// that a not_found response still echoes the caller's
// agent_run_id — the tunnel-server uses run_id for log correlation
// even on negative results.
func TestInternalTokenValidate_NotFoundEchoesRunID(t *testing.T) {
	r, signer, _ := newTokenValidateRouter(t, true)
	body := `{"token":"never-issued","agent_run_id":"run-correlate"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("not_found echo: code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	var got internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.RunID != "run-correlate" {
		t.Errorf("RunID = %q, want %q (caller-supplied; preserved on not_found)", got.RunID, "run-correlate")
	}
}

// TestInternalTokenValidate_SharedStoreHitOnLocalMiss fences the
// multi-server FRPS/NHP deployment shape: the NHP instance validating
// a tunnel login is not necessarily the NHP instance that minted the
// ACK token. A local tokenStore miss must consult the fleet-visible
// ACK-token store before returning not_found.
// Shared-store hits deliberately do not warm the local tokenStore because
// the persisted entry omits ACTokens; tokenStore entries remain locally
// minted only so VerifyAccessToken callers see a stable entry shape.
func TestInternalTokenValidate_SharedStoreHitOnLocalMiss(t *testing.T) {
	r, signer, us := newTokenValidateRouter(t, true)
	us.metrics = metrics.NewPublisherForTest(t)

	expire := time.Now().Add(60 * time.Second).UTC()
	entry := &ACTokenEntry{
		User: &common.AgentUser{
			UserId:         "user-shared",
			DeviceId:       "device-shared",
			OrganizationId: "org-shared",
			AuthServiceId:  "asp-shared",
			OwnerId:        "owner-shared",
		},
		ResourceId: "r-shared",
		KnockSrcIP: "203.0.113.77",
		RunID:      "run-shared",
		OpenTime:   60,
		ExpireTime: expire,
	}
	store := &fakeACKTokenStore{entry: entry, found: true}
	us.ackTokenStore = store

	body := `{"token":"ac-token-shared","agent_run_id":"caller-run"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))

	if rec.Code != http.StatusOK {
		t.Fatalf("shared-store hit: code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	if store.loadCalls != 1 {
		t.Fatalf("shared-store LoadACToken calls = %d, want 1", store.loadCalls)
	}
	var got internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v. body=%s", err, rec.Body.String())
	}
	if !got.Valid {
		t.Fatalf("Valid = false, want true for shared-store hit. body=%s", rec.Body.String())
	}
	if got.KnockUser != "user-shared" {
		t.Errorf("KnockUser = %q, want %q", got.KnockUser, "user-shared")
	}
	if got.OwnerId != "owner-shared" {
		t.Errorf("OwnerId = %q, want %q", got.OwnerId, "owner-shared")
	}
	if got.RunID != "run-shared" {
		t.Errorf("RunID = %q, want %q (entry.RunID wins over caller)", got.RunID, "run-shared")
	}
	if got.KnockSrcIP != "203.0.113.77" {
		t.Errorf("KnockSrcIP = %q, want %q", got.KnockSrcIP, "203.0.113.77")
	}
	if cached, found := us.tokenStore.Load("ac-token-shared"); found {
		t.Fatalf("shared-store hit warmed local tokenStore with cached=%p; want no cache fill because shared entries omit ACTokens", cached)
	}
	counters, _ := us.metrics.CountersForTest(t)
	if got := counters[MetricACKTokenSharedStoreHit]; got != 1 {
		t.Fatalf("%s counter = %v, want 1", MetricACKTokenSharedStoreHit, got)
	}
	if got := counters[MetricACKTokenSharedStoreReadFailure]; got != 0 {
		t.Fatalf("%s counter = %v, want 0", MetricACKTokenSharedStoreReadFailure, got)
	}
}

func TestInternalTokenValidate_LocalHitDoesNotConsultSharedStore(t *testing.T) {
	r, signer, us := newTokenValidateRouter(t, true)

	entry := &ACTokenEntry{
		User: &common.AgentUser{
			UserId:  "user-local",
			OwnerId: "owner-local",
		},
		ResourceId: "r-local",
		KnockSrcIP: "203.0.113.78",
		RunID:      "run-local",
		OpenTime:   60,
		ExpireTime: time.Now().Add(60 * time.Second).UTC(),
	}
	us.tokenStore.Store("ac-token-local", entry)
	store := &fakeACKTokenStore{err: errors.New("shared store should not be called on local hit")}
	us.ackTokenStore = store

	body := `{"token":"ac-token-local","agent_run_id":"caller-run"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))

	if rec.Code != http.StatusOK {
		t.Fatalf("local hit: code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	if store.loadCalls != 0 {
		t.Fatalf("shared-store LoadACToken calls = %d, want 0 on local hit", store.loadCalls)
	}
	var got internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v. body=%s", err, rec.Body.String())
	}
	if !got.Valid {
		t.Fatalf("Valid = false, want true for local hit. body=%s", rec.Body.String())
	}
	if got.RunID != "run-local" {
		t.Errorf("RunID = %q, want %q", got.RunID, "run-local")
	}
}

func TestInternalTokenValidate_SharedStoreExpiredHitIsNotCached(t *testing.T) {
	r, signer, us := newTokenValidateRouter(t, true)
	us.metrics = metrics.NewPublisherForTest(t)

	entry := &ACTokenEntry{
		User:       &common.AgentUser{UserId: "user-expired"},
		ResourceId: "r-expired",
		KnockSrcIP: "203.0.113.79",
		RunID:      "run-expired",
		OpenTime:   60,
		ExpireTime: time.Now().Add(-time.Second).UTC(),
	}
	store := &fakeACKTokenStore{entry: entry, found: true}
	us.ackTokenStore = store

	body := `{"token":"ac-token-expired-shared","agent_run_id":"caller-run"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))

	if rec.Code != http.StatusOK {
		t.Fatalf("shared expired hit: code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	if store.loadCalls != 1 {
		t.Fatalf("shared-store LoadACToken calls = %d, want 1", store.loadCalls)
	}
	var got internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v. body=%s", err, rec.Body.String())
	}
	if got.Valid || got.Error != "expired" {
		t.Fatalf("response = %+v, want invalid expired", got)
	}
	if _, found := us.tokenStore.Load("ac-token-expired-shared"); found {
		t.Fatal("expired shared-store hit was cached in local tokenStore, want no cache fill")
	}
	counters, _ := us.metrics.CountersForTest(t)
	if got := counters[MetricACKTokenSharedStoreHit]; got != 0 {
		t.Fatalf("%s counter = %v, want 0 for expired shared-store entry", MetricACKTokenSharedStoreHit, got)
	}
	if got := counters[MetricACKTokenSharedStoreReadFailure]; got != 0 {
		t.Fatalf("%s counter = %v, want 0 for clean expired response", MetricACKTokenSharedStoreReadFailure, got)
	}
}

// TestInternalTokenValidate_SharedStoreMissFallsThroughToNotFound
// preserves the existing not_found vocabulary after the shared-store
// fallback is enabled. A real miss must remain a negative validation
// result, not an infrastructural error.
func TestInternalTokenValidate_SharedStoreMissFallsThroughToNotFound(t *testing.T) {
	r, signer, us := newTokenValidateRouter(t, true)
	store := &fakeACKTokenStore{found: false}
	us.ackTokenStore = store

	body := `{"token":"never-issued-anywhere","agent_run_id":"run-shared-miss"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))

	if rec.Code != http.StatusOK {
		t.Fatalf("shared-store miss: code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	if store.loadCalls != 1 {
		t.Fatalf("shared-store LoadACToken calls = %d, want 1", store.loadCalls)
	}
	var got internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Valid {
		t.Errorf("Valid = true, want false")
	}
	if got.Error != "not_found" {
		t.Errorf("Error = %q, want %q", got.Error, "not_found")
	}
	if got.RunID != "run-shared-miss" {
		t.Errorf("RunID = %q, want %q", got.RunID, "run-shared-miss")
	}
}

// TestInternalTokenValidate_SharedStoreErrorReturnsUnavailable makes
// the fail-closed posture explicit. If the fleet-visible store cannot
// answer, returning not_found would incorrectly tell tunnel-server
// the ACK token is bad. 503 lets the caller retry as infrastructure
// flake instead.
func TestInternalTokenValidate_SharedStoreErrorReturnsUnavailable(t *testing.T) {
	r, signer, us := newTokenValidateRouter(t, true)
	us.metrics = metrics.NewPublisherForTest(t)
	store := &fakeACKTokenStore{err: errors.New("dynamodb unavailable")}
	us.ackTokenStore = store

	body := `{"token":"ac-token-store-error","agent_run_id":"run-error"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("shared-store error: code = %d, want 503. body=%s", rec.Code, rec.Body.String())
	}
	if store.loadCalls != 1 {
		t.Fatalf("shared-store LoadACToken calls = %d, want 1", store.loadCalls)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["error"] != "token store unavailable" {
		t.Errorf("error = %q, want %q", got["error"], "token store unavailable")
	}
	counters, _ := us.metrics.CountersForTest(t)
	if got := counters[MetricACKTokenSharedStoreReadFailure]; got != 1 {
		t.Fatalf("%s counter = %v, want 1", MetricACKTokenSharedStoreReadFailure, got)
	}
	if got := counters[MetricACKTokenSharedStoreHit]; got != 0 {
		t.Fatalf("%s counter = %v, want 0 on shared-store read failure", MetricACKTokenSharedStoreHit, got)
	}
}

// TestInternalTokenValidate_HMACMismatch locks the strict-mode
// auth contract: a request signed with the wrong secret returns
// 401 before any tokenStore lookup. Mirrors
// TestInternalKnock_StrictMode_RejectsWrongSecret.
func TestInternalTokenValidate_HMACMismatch(t *testing.T) {
	r, _, us := newTokenValidateRouter(t, true)
	// A real entry — proves the 401 is triggered by the auth
	// gate, not by a token-lookup miss.
	storeTestACToken(t, us, "ac-token-real", &ACTokenEntry{
		User:       &common.AgentUser{UserId: "u"},
		ResourceId: "r",
		KnockSrcIP: "10.0.0.20",
		OpenTime:   60,
		ExpireTime: time.Now().Add(60 * time.Second),
	})

	wrongSigner, err := internalauth.New(testTokenValidateWrongSecret)
	if err != nil {
		t.Fatalf("wrong signer: %v", err)
	}
	body := `{"token":"ac-token-real"}`
	rec := doValidateRequest(t, r, body, signValidate(t, wrongSigner, body))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-secret: code = %d, want 401. body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), internalauth.ErrInternalAuth.Error()) {
		t.Errorf("body should echo sentinel %q, got %q", internalauth.ErrInternalAuth.Error(), rec.Body.String())
	}
}

// TestInternalTokenValidate_Idempotent locks the idempotency
// contract: two validations of the same token within TTL return
// identical bodies byte-for-byte. The server's tokenStore comment
// promises "server does not extend expiry on verify" — this test
// fails loud the moment that contract regresses.
//
// Asserts byte-for-byte equality (not just structural equality)
// because tunnel-server PR-2c may eventually cache validated
// responses keyed on the response body hash; even cosmetic
// differences (timestamp re-serialization, field reordering)
// would defeat that.
func TestInternalTokenValidate_Idempotent(t *testing.T) {
	r, signer, us := newTokenValidateRouter(t, true)

	// Deliberately does NOT pre-truncate to whole seconds. The
	// handler reads ExpireTime by reference and never mutates it,
	// so two formats of the same (sub-second-precision) time
	// produce identical bytes regardless of the format string. A
	// truncated ExpireTime would mask a regression where the
	// handler accidentally re-derived ExpireTime from time.Now()
	// on each call (the bug this test fences).
	storeTestACToken(t, us, "ac-token-idem", &ACTokenEntry{
		User:       &common.AgentUser{UserId: "user-idem"},
		ResourceId: "r-idem",
		KnockSrcIP: "10.0.0.30",
		RunID:      "run-idem",
		OpenTime:   60,
		ExpireTime: time.Now().Add(60 * time.Second).UTC(),
	})

	body := `{"token":"ac-token-idem"}`
	auth := signValidate(t, signer, body)

	first := doValidateRequest(t, r, body, auth).Body.Bytes()
	second := doValidateRequest(t, r, body, auth).Body.Bytes()

	if !bytes.Equal(first, second) {
		t.Fatalf("idempotency violated:\nfirst:  %s\nsecond: %s", first, second)
	}
	// Sanity: confirm we're comparing two non-trivial valid
	// responses, not (e.g.) two identical 500s.
	var got internalTokenValidateResponse
	if err := json.Unmarshal(first, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Valid {
		t.Fatalf("idempotency test must run on a happy-path response; got %+v", got)
	}
}

// TestInternalTokenValidate_MalformedBody locks the 400 contract
// for two shape-error rows: an unparseable JSON body and a
// well-formed JSON missing the token field.
//
// The empty-token row deliberately returns 400 (not valid=false +
// error=invalid_format) — a tunnel-server caller that omits the
// token field has a bug, not a token to validate. Returning a
// "validation result" body would let that bug get cached as if
// the result were authoritative.
func TestInternalTokenValidate_MalformedBody(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"unparseable JSON", `{`},
		{"missing token field", `{"agent_run_id":"r"}`},
		{"empty token field", `{"token":""}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, signer, _ := newTokenValidateRouter(t, true)
			rec := doValidateRequest(t, r, tc.body, signValidate(t, signer, tc.body))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("code = %d, want 400. body=%s", rec.Code, rec.Body.String())
			}
			// Body must NOT carry the validation envelope —
			// otherwise a caller might cache the 400 body as
			// "valid=false" and trust it as authoritative.
			if strings.Contains(rec.Body.String(), `"valid"`) {
				t.Errorf("malformed body should not return a validation envelope; got %q", rec.Body.String())
			}
		})
	}
}

// TestInternalTokenValidate_AgentRunIDCap fences the defense-in-depth
// cap on req.AgentRunID. The handler echoes AgentRunID verbatim into
// the response `run_id` on every code path, so an oversize value would
// inflate any downstream response-by-hash cache (the tunnel-server PR
// description floats this). Caller is HMAC-authed so the threat model
// is small, but the cap is cheap and removes the amplification.
//
// Pins both sides of the boundary explicitly: exactly at the cap must
// pass, one byte over must 400 — stops a future refactor from flipping
// `>` to `>=` and silently tightening the contract.
func TestInternalTokenValidate_AgentRunIDCap(t *testing.T) {
	runIDCap := maxAgentRunIDBytes
	cases := []struct {
		name    string
		size    int
		want400 bool
	}{
		// At the cap: check is `>`, so this must NOT 400.
		{"exact cap", runIDCap, false},
		// One byte over: must 400 before any tokenStore lookup.
		{"cap + 1", runIDCap + 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, signer, us := newTokenValidateRouter(t, true)
			storeTestACToken(t, us, "ac-token-runid-cap", &ACTokenEntry{
				User:       &common.AgentUser{UserId: "u"},
				ResourceId: "r",
				KnockSrcIP: "10.0.0.77",
				OpenTime:   60,
				ExpireTime: time.Now().Add(60 * time.Second),
			})
			runID := strings.Repeat("a", tc.size)
			body, err := json.Marshal(internalTokenValidateRequest{
				Token:      "ac-token-runid-cap",
				AgentRunID: runID,
			})
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			rec := doValidateRequest(t, r, string(body), signValidate(t, signer, string(body)))
			if tc.want400 && rec.Code != http.StatusBadRequest {
				t.Fatalf("oversize agent_run_id not 400: code=%d body=%s", rec.Code, rec.Body.String())
			}
			if !tc.want400 {
				if rec.Code != http.StatusOK {
					t.Fatalf("at-cap agent_run_id incorrectly rejected: code=%d body=%s (cap check must be `>`, not `>=`)", rec.Code, rec.Body.String())
				}
				// Prove the request reached the handler body, not
				// just "didn't 400": at-cap must surface a valid=true
				// envelope with the echoed run_id intact.
				var got internalTokenValidateResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
					t.Fatalf("at-cap response not JSON: %v body=%s", err, rec.Body.String())
				}
				if !got.Valid {
					t.Errorf("at-cap Valid = false, want true. body=%s", rec.Body.String())
				}
				if got.RunID != runID {
					t.Errorf("at-cap RunID echo mismatch: got %q want %q", got.RunID, runID)
				}
			}
		})
	}
}

// TestInternalTokenValidate_PermitMode_AllowsUnsigned fences the
// rollout-window default: when internalAuthRequire is false, a
// request without an HMAC header (or with a bad signature) still
// reaches the handler and returns the happy-path body. Mirrors
// TestInternalKnock_PermitMode_AllowsUnsigned on the sibling
// endpoint. The two handlers each have their own copy of the
// permit/strict branch (only the signer is shared), so a cut-paste
// regression in one wouldn't be caught by tests for the other.
func TestInternalTokenValidate_PermitMode_AllowsUnsigned(t *testing.T) {
	r, _, us := newTokenValidateRouter(t, false)
	storeTestACToken(t, us, "ac-token-permit", &ACTokenEntry{
		User:       &common.AgentUser{UserId: "u-permit"},
		ResourceId: "r-permit",
		KnockSrcIP: "10.0.0.50",
		OpenTime:   60,
		ExpireTime: time.Now().Add(60 * time.Second),
	})
	body := `{"token":"ac-token-permit"}`
	// No auth header — permit-mode must allow through.
	rec := doValidateRequest(t, r, body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("permit-mode unsigned: code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	var got internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Valid {
		t.Errorf("Valid = false, want true (permit-mode should resolve happy-path)")
	}
	if got.KnockUser != "u-permit" {
		t.Errorf("KnockUser = %q, want %q", got.KnockUser, "u-permit")
	}
}

// TestInternalTokenValidate_PermitMode_TamperedSignature fences the
// rollout-window contract that a caller signing with the wrong secret
// (the shape a mid-rollout misconfiguration emits — header is present
// and well-formed, just signed against a different key) is still
// allowed through AND increments MetricInternalAuthFailPermit. The
// sibling TestInternalTokenValidate_PermitMode_AllowsUnsigned covers
// the no-header row; this row covers the bad-header row, which goes
// through Verify → ClassifyAuthFailure → permit-counter rather than
// the missing-header short-circuit. Mirrors
// TestInternalKnock_PermitMode_AllowsTamperedSignature on the sibling
// endpoint — the two handlers each carry their own copy of this
// branch, so a cut-paste regression in one wouldn't be caught by
// tests pinned on the other.
func TestInternalTokenValidate_PermitMode_TamperedSignature(t *testing.T) {
	r, _, us, counts := newTokenValidateRouterWithCounters(t, false)
	storeTestACToken(t, us, "ac-token-permit-bad-sig", &ACTokenEntry{
		User:       &common.AgentUser{UserId: "u-permit-bad-sig"},
		ResourceId: "r-permit-bad-sig",
		KnockSrcIP: "10.0.0.51",
		OpenTime:   60,
		ExpireTime: time.Now().Add(60 * time.Second),
	})
	// A signer with a different secret produces a well-formed header
	// the real signer will reject. In permit mode that's the exact
	// shape a mid-rollout mis-configuration emits.
	wrongSigner, err := internalauth.New(testTokenValidateWrongSecret)
	if err != nil {
		t.Fatalf("internalauth.New (wrong secret): %v", err)
	}
	body := `{"token":"ac-token-permit-bad-sig"}`
	rec := doValidateRequest(t, r, body, signValidate(t, wrongSigner, body))
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("permit-mode rejected tampered-sig request: body=%s", rec.Body.String())
	}
	// Positive "reached the validate path" signal: a happy-path
	// response on a real entry.
	var got internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Valid {
		t.Errorf("Valid = false, want true (permit-mode tampered sig should fall through to validate)")
	}
	if got.KnockUser != "u-permit-bad-sig" {
		t.Errorf("KnockUser = %q, want %q", got.KnockUser, "u-permit-bad-sig")
	}
	if counts[MetricInternalAuthFailPermit] != 1 {
		t.Errorf("MetricInternalAuthFailPermit = %d, want 1", counts[MetricInternalAuthFailPermit])
	}
	if counts[MetricInternalAuthSuccess] != 0 {
		t.Errorf("MetricInternalAuthSuccess = %d, want 0 (bad sig is not success)", counts[MetricInternalAuthSuccess])
	}
	if counts[MetricInternalAuthFailStrict] != 0 {
		t.Errorf("MetricInternalAuthFailStrict = %d, want 0 (permit mode)", counts[MetricInternalAuthFailStrict])
	}
}

// TestInternalTokenValidate_CounterEmission_Success fences that a
// validated, HMAC-signed request increments MetricInternalAuthSuccess
// (and not the failure counters). The rollout alarm "flip require=true
// when MetricInternalAuthFailPermit stays at 0" depends on these emits
// firing on this endpoint too — a regression that drops the emit would
// be invisible to monitoring until rollout time.
func TestInternalTokenValidate_CounterEmission_Success(t *testing.T) {
	r, signer, us, counts := newTokenValidateRouterWithCounters(t, true)
	storeTestACToken(t, us, "ac-token-counter-ok", &ACTokenEntry{
		User:       &common.AgentUser{UserId: "u"},
		ResourceId: "r",
		KnockSrcIP: "10.0.0.99",
		OpenTime:   60,
		ExpireTime: time.Now().Add(60 * time.Second),
	})
	body := `{"token":"ac-token-counter-ok"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	if counts[MetricInternalAuthSuccess] != 1 {
		t.Errorf("MetricInternalAuthSuccess = %d, want 1", counts[MetricInternalAuthSuccess])
	}
	if counts[MetricInternalAuthFailStrict] != 0 {
		t.Errorf("MetricInternalAuthFailStrict = %d, want 0", counts[MetricInternalAuthFailStrict])
	}
	if counts[MetricInternalAuthFailPermit] != 0 {
		t.Errorf("MetricInternalAuthFailPermit = %d, want 0", counts[MetricInternalAuthFailPermit])
	}
}

// TestInternalTokenValidate_CounterEmission_StrictReject fences that
// a strict-mode HMAC mismatch increments MetricInternalAuthFailStrict
// (and not Success or Permit). Catches a cut-paste regression from
// the knock handler where the validate handler accidentally emitted
// the wrong counter on rejection.
func TestInternalTokenValidate_CounterEmission_StrictReject(t *testing.T) {
	r, _, _, counts := newTokenValidateRouterWithCounters(t, true)
	body := `{"token":"x"}`
	// No auth header — strict-mode must reject.
	rec := doValidateRequest(t, r, body, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401. body=%s", rec.Code, rec.Body.String())
	}
	if counts[MetricInternalAuthFailStrict] != 1 {
		t.Errorf("MetricInternalAuthFailStrict = %d, want 1", counts[MetricInternalAuthFailStrict])
	}
	if counts[MetricInternalAuthSuccess] != 0 {
		t.Errorf("MetricInternalAuthSuccess = %d, want 0 (rejected)", counts[MetricInternalAuthSuccess])
	}
	if counts[MetricInternalAuthFailPermit] != 0 {
		t.Errorf("MetricInternalAuthFailPermit = %d, want 0 (strict mode)", counts[MetricInternalAuthFailPermit])
	}
}

// TestInternalTokenValidate_CounterEmission_PermitUnsigned fences that
// a permit-mode unsigned request increments MetricInternalAuthFailPermit
// (the signal the rollout alarm pages on) and not Success. The
// permit-counter is the load-bearing metric of the rollout — a regression
// in this emit would let a future rollout flip from permit→strict
// while a client is still unsigned, and the alarm would silently miss it.
func TestInternalTokenValidate_CounterEmission_PermitUnsigned(t *testing.T) {
	r, _, us, counts := newTokenValidateRouterWithCounters(t, false)
	storeTestACToken(t, us, "ac-token-counter-permit", &ACTokenEntry{
		User:       &common.AgentUser{UserId: "u"},
		ResourceId: "r",
		KnockSrcIP: "10.0.0.99",
		OpenTime:   60,
		ExpireTime: time.Now().Add(60 * time.Second),
	})
	body := `{"token":"ac-token-counter-permit"}`
	// No auth header — permit-mode allows through but counts the miss.
	rec := doValidateRequest(t, r, body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (permit-mode allows). body=%s", rec.Code, rec.Body.String())
	}
	if counts[MetricInternalAuthFailPermit] != 1 {
		t.Errorf("MetricInternalAuthFailPermit = %d, want 1", counts[MetricInternalAuthFailPermit])
	}
	if counts[MetricInternalAuthSuccess] != 0 {
		t.Errorf("MetricInternalAuthSuccess = %d, want 0 (unsigned is not success)", counts[MetricInternalAuthSuccess])
	}
	if counts[MetricInternalAuthFailStrict] != 0 {
		t.Errorf("MetricInternalAuthFailStrict = %d, want 0 (permit mode)", counts[MetricInternalAuthFailStrict])
	}
}

// TestInternalTokenValidate_RFC1918Gate_RejectsPublicIP fences the
// source-IP gate: a request from a non-private RemoteAddr returns
// 403, regardless of any X-Forwarded-For header. The two handlers
// (knock + validate) each carry their own copy of this gate; the
// sibling test (TestInternalKnock_*) doesn't cover this handler's
// branch.
func TestInternalTokenValidate_RFC1918Gate_RejectsPublicIP(t *testing.T) {
	r, signer, _ := newTokenValidateRouter(t, true)
	body := `{"token":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/nhp/internal/token/validate", strings.NewReader(body))
	req.RemoteAddr = "8.8.8.8:12345" // public source
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(internalauth.Header, signValidate(t, signer, body))
	// XFF claim to a private IP must not bypass the gate (RemoteAddr,
	// not ClientIP, is the source-of-truth here).
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("public source IP not rejected: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestInternalTokenValidate_QueryRejected fences the query/fragment
// rejection in strict mode: a URL with a query string returns 400
// before any signature check or tokenStore lookup. The query is not
// part of the signed canonical string, so accepting it would let
// future endpoint changes silently leave a parameter unsigned.
func TestInternalTokenValidate_QueryRejected(t *testing.T) {
	r, signer, _ := newTokenValidateRouter(t, true)
	body := `{"token":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/nhp/internal/token/validate?ignored=1", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("Content-Type", "application/json")
	// Even with a valid signature, a query string must 400.
	req.Header.Set(internalauth.Header, signValidate(t, signer, body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("query-bearing URL not rejected: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestInternalTokenValidate_BodyLimit fences the body-cap boundary
// in strict mode. Two rows: exactly at the limit (must NOT 413 —
// check is `>`, not `>=`) and one byte over (must 413). Pinning
// both sides of the boundary explicitly stops a future refactor
// from flipping `>` to `>=` and silently tightening the contract;
// limit+1 alone would be rejected under both comparisons.
func TestInternalTokenValidate_BodyLimit(t *testing.T) {
	limit := int(maxInternalTokenValidateRequestSize)
	cases := []struct {
		name    string
		size    int
		want413 bool
	}{
		// At the limit: size check is `>`, so this must NOT trip 413.
		// The body is non-JSON `aaaa...` so the handler will return
		// some non-413 status (likely 400 from JSON decode); the
		// boundary assertion is "size check didn't fire," not the
		// downstream parse outcome.
		{"exact limit", limit, false},
		// One byte over: must trip 413 before any compute.
		{"limit + 1", limit + 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, signer, _ := newTokenValidateRouter(t, true)
			bodyBytes := bytes.Repeat([]byte("a"), tc.size)
			req := httptest.NewRequest(http.MethodPost, "/nhp/internal/token/validate", bytes.NewReader(bodyBytes))
			req.RemoteAddr = "127.0.0.1:54321"
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(internalauth.Header, signValidate(t, signer, string(bodyBytes)))
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if tc.want413 && rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("oversize body not 413: code=%d body=%s", rec.Code, rec.Body.String())
			}
			// At-limit must pass the size check AND reach the JSON
			// decoder, which rejects `aaaa...` as malformed JSON →
			// 400. Pinning the specific code (not just "not 413")
			// keeps a future regression that 500s on this row from
			// silently passing.
			if !tc.want413 && rec.Code != http.StatusBadRequest {
				t.Fatalf("at-limit body should JSON-decode-400 (size check `>`, body is non-JSON), got code=%d body=%s", rec.Code, rec.Body.String())
			}
			if !tc.want413 && rec.Code == http.StatusRequestEntityTooLarge {
				t.Fatalf("at-limit body incorrectly 413'd: code=%d (size check must be `>`, not `>=`)", rec.Code)
			}
		})
	}
}

// TestInternalTokenValidate_LegacyMode_NoSigner fences the
// no-signer (legacy) branch — the handler's MaxBytesReader path
// when internalAuthSigner is nil. An oversize body in that posture
// must still be rejected, but via a JSON-decode 400 (the
// MaxBytesReader surfaces as a read error during Decode), NOT the
// 413 that strict mode emits. Documents the intentional
// response-code asymmetry between the two postures.
func TestInternalTokenValidate_LegacyMode_NoSigner(t *testing.T) {
	gin.SetMode(gin.TestMode)
	us := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
	}
	hs := &HttpServer{
		udpServer: us,
		// internalAuthSigner: nil — legacy posture.
	}
	r := gin.New()
	if err := r.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies(nil): %v", err)
	}
	r.POST("/nhp/internal/token/validate", hs.handleInternalTokenValidate)

	limit := int(maxInternalTokenValidateRequestSize)
	bodyBytes := bytes.Repeat([]byte("a"), limit+1)
	req := httptest.NewRequest(http.MethodPost, "/nhp/internal/token/validate", bytes.NewReader(bodyBytes))
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("Content-Type", "application/json")
	// No auth header — legacy mode.
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("legacy-mode oversize body: code=%d, want 400 (MaxBytesReader surfaces as decode error). body=%s",
			rec.Code, rec.Body.String())
	}
}

// TestInternalTokenValidate_LegacyMode_NoCounterEmit locks the
// invariant that the auth-counter trio is signer-gated: a handler
// with internalAuthSigner == nil (legacy posture) must NOT emit any
// of MetricInternalAuthSuccess / FailStrict / FailPermit, regardless
// of request shape. The strict/permit counter tests already cover
// signer-set; this row pins the signer-nil baseline so a future
// refactor that moves the emit calls out from under the signer
// nil-check would trip this immediately.
func TestInternalTokenValidate_LegacyMode_NoCounterEmit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	counts := map[string]int{}
	emit := func(name string) {
		counts[name]++
	}
	us := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
	}
	hs := &HttpServer{
		udpServer: us,
		// internalAuthSigner intentionally nil — legacy posture.
		// internalAuthEmit IS set so a regression that emits without
		// a signer would land in the counts map rather than nil-panic.
		internalAuthEmit: emit,
	}
	r := gin.New()
	if err := r.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies(nil): %v", err)
	}
	r.POST("/nhp/internal/token/validate", hs.handleInternalTokenValidate)

	storeTestACToken(t, us, "ac-token-legacy", &ACTokenEntry{
		User:       &common.AgentUser{UserId: "u"},
		ResourceId: "r",
		KnockSrcIP: "10.0.0.42",
		OpenTime:   60,
		ExpireTime: time.Now().Add(60 * time.Second),
	})
	body := `{"token":"ac-token-legacy"}`
	rec := doValidateRequest(t, r, body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy mode: code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	if counts[MetricInternalAuthSuccess] != 0 {
		t.Errorf("MetricInternalAuthSuccess = %d, want 0 (legacy mode must not emit auth counters)", counts[MetricInternalAuthSuccess])
	}
	if counts[MetricInternalAuthFailStrict] != 0 {
		t.Errorf("MetricInternalAuthFailStrict = %d, want 0 (legacy mode must not emit auth counters)", counts[MetricInternalAuthFailStrict])
	}
	if counts[MetricInternalAuthFailPermit] != 0 {
		t.Errorf("MetricInternalAuthFailPermit = %d, want 0 (legacy mode must not emit auth counters)", counts[MetricInternalAuthFailPermit])
	}
}

// TestInternalTokenValidate_StrictMode_EmptyBody fences the
// empty-body branch in strict mode: an empty POST body must 401
// (HMAC verify fails — the signature was computed over a non-empty
// canonical and the request carries either no header or a stale
// header). The check that the body is non-empty must happen at or
// after the HMAC verify, not before — a future refactor that
// short-circuits on empty body before signature check would let a
// permit-mode caller skip the rollout counter and a strict-mode
// caller surface a misleading 400.
func TestInternalTokenValidate_StrictMode_EmptyBody(t *testing.T) {
	r, signer, _ := newTokenValidateRouter(t, true)
	// Explicit canary on the load-bearing assumption: internalauth's
	// Signer.Sign/Verify must accept an empty body in their canonical
	// (method|path|sha256(body)). If a future internalauth change
	// adds a min-body-length rule for replay-window or
	// anti-amplification reasons, this verify trips before the row
	// below silently flips from 400 to 401 and obscures the cause.
	emptyHeader := signValidate(t, signer, "")
	if err := signer.Verify(emptyHeader, http.MethodPost, "/nhp/internal/token/validate", []byte(""), 0); err != nil {
		t.Fatalf("internalauth.Signer no longer accepts empty body: %v — the row below assumes it does", err)
	}
	// Sign the empty body. In permit mode this would pass through;
	// in strict mode it should still proceed past auth and trip the
	// JSON-decode 400 (empty body is not valid JSON).
	rec := doValidateRequest(t, r, "", emptyHeader)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty-body strict mode (signed): code=%d, want 400 (auth passes, JSON decode fails). body=%s", rec.Code, rec.Body.String())
	}
	// Unsigned empty body in strict mode must 401 — auth verify
	// fires before the decode.
	rec = doValidateRequest(t, r, "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("empty-body strict mode (unsigned): code=%d, want 401 (auth must run before decode). body=%s", rec.Code, rec.Body.String())
	}
}

// TestInternalTokenValidate_HappyNoUserGuard fences the defensive
// nil-check on entry.User: if a future construction path stores an
// entry with a nil User, the handler returns valid=true with an
// empty knock_user rather than panicking. The defensive code is at
// internal_token_validate.go's `if entry.User != nil` guard.
func TestInternalTokenValidate_HappyNoUserGuard(t *testing.T) {
	r, signer, us := newTokenValidateRouter(t, true)
	storeTestACToken(t, us, "ac-token-no-user", &ACTokenEntry{
		// User intentionally nil — exercises the handler's defensive
		// nil-check on entry.User before the .UserId deref.
		ResourceId: "r-no-user",
		KnockSrcIP: "10.0.0.66",
		OpenTime:   60,
		ExpireTime: time.Now().Add(60 * time.Second),
	})
	body := `{"token":"ac-token-no-user"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	var got internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Valid {
		t.Errorf("Valid = false, want true (nil User must not panic)")
	}
	if got.KnockUser != "" {
		t.Errorf("KnockUser = %q, want empty (entry.User was nil)", got.KnockUser)
	}
}

// TestInternalTokenValidate_MethodNotAllowed pins the verb gate: the
// route is registered at POST only. A GET (or any non-POST verb) must
// 405 via gin's default not-allowed handler — a future router refactor
// that adds Any() or a GET handler would silently expose the endpoint
// to GETs that skip body-cap / HMAC / decode entirely.
func TestInternalTokenValidate_MethodNotAllowed(t *testing.T) {
	r, _, _ := newTokenValidateRouter(t, true)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/nhp/internal/token/validate", nil)
			req.RemoteAddr = "127.0.0.1:54321"
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			// Tolerate either gin default: NoMethod handler returns 405,
			// no-route fallback returns 404. Both are correct "not the
			// handler"; a 500 (or worse, 200) is the regression we fence.
			if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s on POST-only route: code=%d, want 404 or 405", method, rec.Code)
			}
		})
	}
}

// TestInternalTokenValidate_ConcurrentValidates proves the lock-free
// read invariant ACTokenEntry's godoc claims. Two goroutines validate
// the same token simultaneously under -race; if a future construction
// path mutates a stored entry the race detector trips. Mirrors the
// "Post-store mutation is forbidden" comment in tokenstore.go.
func TestInternalTokenValidate_ConcurrentValidates(t *testing.T) {
	r, signer, us := newTokenValidateRouter(t, true)
	storeTestACToken(t, us, "ac-token-concurrent", &ACTokenEntry{
		User:       &common.AgentUser{UserId: "u-concurrent"},
		ResourceId: "r-concurrent",
		KnockSrcIP: "10.0.0.55",
		OpenTime:   60,
		ExpireTime: time.Now().Add(60 * time.Second),
	})
	body := `{"token":"ac-token-concurrent"}`
	sig := signValidate(t, signer, body)

	const N = 32
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			rec := doValidateRequest(t, r, body, sig)
			if rec.Code != http.StatusOK {
				t.Errorf("concurrent validate: code=%d body=%s", rec.Code, rec.Body.String())
			}
		}()
	}
	wg.Wait()
}

// TestInternalTokenValidate_ServerIssuedTokenResolves fences the
// flat-keyspace contract documented at tokenstore.go: the handler
// validates any live entry in tokenStore, AC-issued or server-issued
// alike. The endpoint's contract is "this server has a live token
// entry for X", not "this is specifically an AC-issued knock token."
// A future divergence in storage path (e.g., separating the
// keyspaces, or adding an issuer discriminator) would silently flip
// this row from valid=true to not_found and break the consumer
// contract advertised in the response struct godoc.
func TestInternalTokenValidate_ServerIssuedTokenResolves(t *testing.T) {
	r, signer, us := newTokenValidateRouter(t, true)
	entry := &ACTokenEntry{
		User:       &common.AgentUser{UserId: "u-server-issued"},
		ResourceId: "r-server-issued",
		KnockSrcIP: "10.0.0.88",
		OpenTime:   60,
	}
	token := us.GenerateAccessToken(entry)
	body := `{"token":"` + token + `"}`
	rec := doValidateRequest(t, r, body, signValidate(t, signer, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("server-issued token validate: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var got internalTokenValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Valid {
		t.Errorf("Valid = false; server-issued token should validate the same as AC-issued (shared keyspace)")
	}
	if got.KnockUser != "u-server-issued" {
		t.Errorf("KnockUser = %q, want %q", got.KnockUser, "u-server-issued")
	}
}

// TestInternalTokenValidate_RejectsTrailingGarbage pins the dec.More()
// fence: a body like `{"token":"x"}{"extra":"y"}` must 400 before
// reaching the tokenStore. Without dec.More(), two distinct payloads
// would parse identically — which matters if a future tunnel-server
// caches validation responses by request-body hash.
func TestInternalTokenValidate_RejectsTrailingGarbage(t *testing.T) {
	r, signer, _ := newTokenValidateRouter(t, true)
	cases := []struct {
		name string
		body string
	}{
		{"extra-object", `{"token":"x"}{"extra":"y"}`},
		{"trailing-text", `{"token":"x"}garbage`},
		{"two-objects-spaced", `{"token":"x"} {"token":"x"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doValidateRequest(t, r, tc.body, signValidate(t, signer, tc.body))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("trailing-garbage body accepted: code=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}
