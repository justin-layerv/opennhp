package qurl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	nhpserver "github.com/OpenNHP/opennhp/endpoints/server"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/qurlv2"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// ---- test issuer signer (KMS-free, mirrors the production signing input) ----

const testV2KID = "qurl-issuer-key-test"

type v2TestIssuer struct {
	priv *ecdsa.PrivateKey
}

func newV2TestIssuer(t *testing.T) *v2TestIssuer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	return &v2TestIssuer{priv: priv}
}

// trustStoreJSON returns the QURL_V2_ISSUER_TRUST_STORE JSON value for this
// issuer (kid -> base64(DER SPKI)).
func (s *v2TestIssuer) trustStoreJSON(t *testing.T) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&s.priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal issuer pub: %v", err)
	}
	b, err := json.Marshal(map[string]string{testV2KID: base64.StdEncoding.EncodeToString(der)})
	if err != nil {
		t.Fatalf("marshal trust store json: %v", err)
	}
	return string(b)
}

// trustStore builds the parsed trust store directly (for tests that set
// v2TrustStore without going through Init/env).
func (s *v2TestIssuer) trustStore(t *testing.T) *qurlv2.TrustStore {
	t.Helper()
	ts, err := LoadV2TrustStore(s.trustStoreJSON(t))
	if err != nil {
		t.Fatalf("LoadV2TrustStore: %v", err)
	}
	return ts
}

// sign returns (claimsB64, sigB64) for the given claims map, signing the exact
// base64url claims bytes with the documented domain-separated signing input
// ("NHP-QURL-V2-ISSUER" + 0x00 + claimsB64), SHA-256, ECDSA P-256, raw r||s
// low-S. This duplicates the production signing input deliberately: it is the
// cross-impl wire contract, and a test that re-derived it from package internals
// could not catch a drift between the contract and the verifier.
func (s *v2TestIssuer) sign(t *testing.T, claims map[string]any) (string, string) {
	t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	claimsB64 := base64.RawURLEncoding.EncodeToString(raw)

	input := append([]byte("NHP-QURL-V2-ISSUER\x00"), claimsB64...)
	digest := sha256.Sum256(input)
	der, err := ecdsa.SignASN1(rand.Reader, s.priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return claimsB64, base64.RawURLEncoding.EncodeToString(derToRawLowSForTest(t, der))
}

// derToRawLowSForTest converts a DER ECDSA signature to fixed-width raw r||s,
// low-S normalized — the pinned wire form verifyRawSignature requires.
func derToRawLowSForTest(t *testing.T, der []byte) []byte {
	t.Helper()
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		t.Fatalf("unmarshal DER sig: %v", err)
	}
	n := elliptic.P256().Params().N
	halfN := new(big.Int).Rsh(n, 1)
	s := sig.S
	if s.Cmp(halfN) > 0 {
		s = new(big.Int).Sub(n, s)
	}
	out := make([]byte, 64)
	sig.R.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

// x25519KeyPair returns a 32-byte key as (base64url, std-base64) so a test can
// place the base64url form in a claim and the std-base64 form where nhp would
// (req.PublicKey / ServerCellPublicKeyB64).
func x25519KeyPair(t *testing.T, filler byte) (b64url, stdB64 string) {
	t.Helper()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = filler + byte(i)
	}
	return base64.RawURLEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw)
}

// resourceKeyPair returns a representative P-256 SPKI resource key as
// (base64url, base64url) — the knock resource identity uses the same base64url
// encoding as the claim. Returns the same string twice for the matching case.
func resourceKeyB64URL(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen resource key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal resource key: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

// ---- recording admission server ----

// admissionRecorder is a fake qurl-service admission endpoint that records the
// ORDER of authorize/prepare/commit/cancel calls so a test can assert the
// authorize-first dispatch, commit-before-AC-open, and no-cancel-after-commit.
//
// By DEFAULT authorize returns 403 access_denied (ErrNoLiveSession), so the
// recorder models a FIRST knock: authorize → fall through → prepare → commit →
// open. A re-knock test overrides authorizeStatus/authorizeBody with a live-
// session 200 (and typically sets prepareStatus to a consumed/revoked terminal so
// a regression that wrongly routes the re-knock to prepare is caught).
type admissionRecorder struct {
	mu     sync.Mutex
	calls  []string
	server *httptest.Server

	// authorizeReq captures the decoded /authorize request body so a test can
	// assert the wire shape on the re-knock/refresh path (where prepare is never
	// called and PrepareRequestShape therefore covers nothing).
	authorizeReq map[string]any

	// configurable behavior
	authorizeStatus int
	authorizeBody   string
	prepareStatus   int
	prepareBody     string
	commitStatus    int
	cancelStatus    int
}

// mustPubKeyHashB64 is the hex(sha256(base64url key)) NHP + qurl-service both use.
func mustPubKeyHashB64(t *testing.T, b64 string) string {
	t.Helper()
	h, err := qurlv2.PublicKeyHashFromB64(b64)
	if err != nil {
		t.Fatalf("PublicKeyHashFromB64(%q): %v", b64, err)
	}
	return h
}

// prepareBodyJSON builds a success prepare response body with the given
// qurl_user_public_key_hash + ac_routing. Extracted so a test can vary the hash
// (e.g. to exercise the #3032 commit-path drift guard).
func prepareBodyJSON(hash string, ac *ACRouting) string {
	body, _ := json.Marshal(internalAdmissionPrepareResponse{
		Success: true,
		Data: &AdmissionPrepareResponse{
			QurlUserPublicKeyHash: hash,
			AdmissionID:           "adm_test123",
			QurlID:                "q_abc12345678",
			OpenTime:              30,
			QurlSiteURL:           "https://q.qurl.site/p",
			ACRouting:             ac,
		},
	})
	return string(body)
}

func newAdmissionRecorder(t *testing.T, ac *ACRouting) *admissionRecorder {
	t.Helper()
	rec := &admissionRecorder{
		// Default: authorize denies (no live session) so the flow falls through to
		// the first-knock prepare path. Re-knock tests override this.
		authorizeStatus: http.StatusForbidden,
		authorizeBody:   `{"success":false,"error":{"code":"access_denied"}}`,
		prepareStatus:   http.StatusOK,
		commitStatus:    http.StatusOK,
		cancelStatus:    http.StatusOK,
	}
	// Echo the hash of the fixture's agent key (x25519KeyPair(0x40), the key
	// newV2Fixture puts in qurl_user_public_key_b64) so first-knock tests take the
	// NO-drift path through the #3032 commit-path guard by default. A drift test
	// overrides rec.prepareBody with a mismatched hash.
	agentURL, _ := x25519KeyPair(t, 0x40)
	rec.prepareBody = prepareBodyJSON(mustPubKeyHashB64(t, agentURL), ac)
	return rec
}

// liveAuthorize configures the recorder so authorize returns a live session 200
// (the steady-state re-knock case): remaining_seconds + the matched session id +
// the AC routing to refresh. Used by the consumed-session-survives test.
func (rec *admissionRecorder) liveAuthorize(sessionID string, remaining uint32, ac *ACRouting) {
	body, _ := json.Marshal(internalAdmissionAuthorizeResponse{
		Success: true,
		Data: &AdmissionAuthorizeResponse{
			SessionID:        sessionID,
			RemainingSeconds: remaining,
			ACRouting:        ac,
		},
	})
	rec.authorizeStatus = http.StatusOK
	rec.authorizeBody = string(body)
}

func (rec *admissionRecorder) record(op string) {
	rec.mu.Lock()
	rec.calls = append(rec.calls, op)
	rec.mu.Unlock()
}

func (rec *admissionRecorder) callOrder() []string {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	out := make([]string, len(rec.calls))
	copy(out, rec.calls)
	return out
}

// authorizeRequest returns the decoded /authorize request body captured by the
// handler (nil if authorize was never called).
func (rec *admissionRecorder) authorizeRequest() map[string]any {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return rec.authorizeReq
}

func (rec *admissionRecorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == admissionAuthorizePath:
			rec.record("authorize")
			rec.mu.Lock()
			_ = json.NewDecoder(r.Body).Decode(&rec.authorizeReq)
			rec.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(rec.authorizeStatus)
			_, _ = w.Write([]byte(rec.authorizeBody))
		case r.URL.Path == admissionPreparePath:
			rec.record("prepare")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(rec.prepareStatus)
			_, _ = w.Write([]byte(rec.prepareBody))
		case r.Method == http.MethodPost && len(r.URL.Path) > 0 && hasSuffix(r.URL.Path, "/commit"):
			rec.record("commit")
			w.WriteHeader(rec.commitStatus)
		case r.Method == http.MethodPost && hasSuffix(r.URL.Path, "/cancel"):
			rec.record("cancel")
			w.WriteHeader(rec.cancelStatus)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func hasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

// setRecordingResolver points the package resolver at the recorder's server.
func setRecordingResolver(t *testing.T, rec *admissionRecorder) {
	t.Helper()
	server := httptest.NewServer(rec.handler())
	rec.server = server
	t.Cleanup(server.Close)
	prev := resolver
	resolver = &QurlResolver{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      server.URL,
		serviceToken: "test-token",
	}
	t.Cleanup(func() { resolver = prev })
}

// enableV2 sets the package-level v2 admission state for the test and restores it.
func enableV2(t *testing.T, ts *qurlv2.TrustStore) {
	t.Helper()
	prevEnabled, prevTS := v2AdmissionEnabled, v2TrustStore
	v2AdmissionEnabled, v2TrustStore = true, ts
	t.Cleanup(func() { v2AdmissionEnabled, v2TrustStore = prevEnabled, prevTS })
}

// v2Fixture bundles a matching issuer/keys/claims set plus the helper and request
// wired so all four binding checks pass by default. Individual tests then mutate
// one field to drive a specific rejection.
type v2Fixture struct {
	issuer       *v2TestIssuer
	claimsB64    string
	sigB64       string
	cellStdB64   string
	agentStdB64  string
	agentURLB64  string
	resourceB64  string
	req          *common.NhpAuthRequest
	openedCalled *bool
}

func newV2Fixture(t *testing.T, mutate func(claims map[string]any)) *v2Fixture {
	t.Helper()
	issuer := newV2TestIssuer(t)

	cellURL, cellStd := x25519KeyPair(t, 0x10)
	agentURL, agentStd := x25519KeyPair(t, 0x40)
	resB64 := resourceKeyB64URL(t)

	now := time.Now().Unix()
	claims := map[string]any{
		"v":                        2,
		"iss":                      "qurl-service",
		"kid":                      testV2KID,
		"iat":                      now - 10,
		"nbf":                      now - 10,
		"exp":                      now + 300,
		"jti":                      "qurl_testjti",
		"cell_public_key_b64":      cellURL,
		"relay_url":                "https://relay.example.com",
		"resource_public_key_b64":  resB64,
		"qurl_user_public_key_b64": agentURL,
	}
	if mutate != nil {
		mutate(claims)
	}
	claimsB64, sigB64 := issuer.sign(t, claims)

	opened := false
	req := &common.NhpAuthRequest{
		Msg: &common.AgentKnockMsg{
			AuthServiceId: PluginID,
			ResourceId:    resB64,
			UserId:        "u",
			UserData: map[string]any{
				qurlV2ClaimsUserDataKey:    claimsB64,
				qurlV2IssuerSigUserDataKey: sigB64,
			},
		},
		Ack:       &common.ServerKnockAckMsg{},
		PublicKey: agentStd,
		SrcAddr:   &common.NetAddress{Ip: "203.0.113.9", Port: 5555},
	}

	return &v2Fixture{
		issuer:       issuer,
		claimsB64:    claimsB64,
		sigB64:       sigB64,
		cellStdB64:   cellStd,
		agentStdB64:  agentStd,
		agentURLB64:  agentURL,
		resourceB64:  resB64,
		req:          req,
		openedCalled: &opened,
	}
}

func (f *v2Fixture) helper(openErr error) *plugins.NhpServerPluginHelper {
	return &plugins.NhpServerPluginHelper{
		// AspData is always plumbed by NewNhpServerHelper on the real knock path;
		// the top-level AuthWithNHP guard requires it before any dispatch. The qv2
		// path itself does not read it (routing comes from prepare's ac_routing).
		AspData:                testAspData(f.resourceB64, 60),
		ServerCellPublicKeyB64: f.cellStdB64,
		AuthWithNhpCallbackFunc: func(req *common.NhpAuthRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			*f.openedCalled = true
			if openErr != nil {
				return req.Ack, openErr
			}
			req.Ack.ErrCode = common.ErrSuccess.ErrorCode()
			return req.Ack, nil
		},
	}
}

// defaultACRouting is the AC the prepare step selects in tests.
func defaultACRouting() *ACRouting {
	return &ACRouting{ACId: "ac-test-1", DestHost: "10.0.0.5", DestPort: 8443}
}

// ---- tests ----

// TestAuthWithNHPClaims_FirstKnock_AuthorizeThenPrepareCommitBeforeACOpen is the
// load-bearing first-knock test: a fully-valid qv2 knock with NO live session
// calls authorize (which 403s — ErrNoLiveSession), falls through to prepare, THEN
// commit, THEN opens the AC (in that order), and never calls cancel. The leading
// authorize is the new steady-state gate; a first knock correctly falls through it.
func TestAuthWithNHPClaims_FirstKnock_AuthorizeThenPrepareCommitBeforeACOpen(t *testing.T) {
	f := newV2Fixture(t, nil)
	enableV2(t, f.issuer.trustStore(t))

	ac := defaultACRouting()
	rec := newAdmissionRecorder(t, ac)

	// Record AC-open position relative to prepare/commit by appending into the
	// same recorder when the callback fires.
	helper := &plugins.NhpServerPluginHelper{
		AspData:                testAspData(f.resourceB64, 60),
		ServerCellPublicKeyB64: f.cellStdB64,
		AuthWithNhpCallbackFunc: func(req *common.NhpAuthRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			rec.record("ac_open")
			// The opened AC must be the one prepare selected.
			info, ok := res.Resources[ac.ACId]
			if !ok || info == nil {
				t.Errorf("opened ResourceData missing ac_routing ACId %q; got %#v", ac.ACId, res.Resources)
			} else {
				if info.ACId != ac.ACId {
					t.Errorf("opened ACId = %q, want %q", info.ACId, ac.ACId)
				}
				// Addr.Ip MUST be empty (the AC substitutes its own LOCAL_IP via
				// applyDefaultIpSubstitution) — NOT dest_host, which would fail the
				// AC's eBPF parseIP for a hostname and mis-key the rule for a raw IP
				// (see acRoutingToResourceInfo). dest_host is carried informationally
				// on Hostname; port/proto match the qv1 catalog shape.
				if info.Addr == nil || info.Addr.Ip != "" || info.Addr.Port != ac.DestPort || info.Addr.Protocol != "tcp" {
					t.Errorf("opened Addr = %#v, want Ip=\"\" (→AC LOCAL_IP) Port=%d Protocol=tcp", info.Addr, ac.DestPort)
				}
				if info.Hostname != ac.DestHost {
					t.Errorf("opened Hostname = %q, want dest_host %q (informational, feeds ack ResourceHost)", info.Hostname, ac.DestHost)
				}
			}
			req.Ack.ErrCode = common.ErrSuccess.ErrorCode()
			return req.Ack, nil
		},
	}
	setRecordingResolver(t, rec)

	ack, err := AuthWithNHP(f.req, helper)
	if err != nil {
		t.Fatalf("AuthWithNHP qv2: %v", err)
	}
	if ack.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Errorf("ack.ErrCode = %q, want success", ack.ErrCode)
	}
	if ack.RedirectUrl != "https://q.qurl.site/p" {
		t.Errorf("ack.RedirectUrl = %q, want the prepare qurl_site_url", ack.RedirectUrl)
	}

	want := []string{"authorize", "prepare", "commit", "ac_open"}
	got := rec.callOrder()
	if len(got) != len(want) {
		t.Fatalf("call order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("call order = %v, want %v (authorize MUST precede prepare; commit MUST precede ac_open; cancel MUST NOT appear)", got, want)
		}
	}
}

// TestAuthWithNHPClaims_CommitFailure_CancelsLease_NoACOpen proves that when
// commit fails, the still-PENDING prepare lease is released via cancel and the
// AC is NOT opened. (The lease is pending because consume did not durably land;
// releasing it promptly avoids wedging a one-time-use / max-session slot until
// the lease TTL reclaims it.)
func TestAuthWithNHPClaims_CommitFailure_CancelsLease_NoACOpen(t *testing.T) {
	f := newV2Fixture(t, nil)
	enableV2(t, f.issuer.trustStore(t))

	rec := newAdmissionRecorder(t, defaultACRouting())
	rec.commitStatus = http.StatusInternalServerError
	setRecordingResolver(t, rec)

	_, err := AuthWithNHP(f.req, f.helper(nil))
	if err == nil {
		t.Fatal("expected commit failure to produce an error ack")
	}
	if *f.openedCalled {
		t.Error("AC must NOT be opened when commit fails")
	}
	order := rec.callOrder()
	want := []string{"authorize", "prepare", "commit", "cancel"}
	if len(order) != len(want) {
		t.Fatalf("call order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("call order = %v, want %v (commit failure must release the pending lease via cancel)", order, want)
		}
	}
	for _, c := range order {
		if c == "ac_open" {
			t.Error("ac_open must not appear after a failed commit")
		}
	}
}

// TestAuthWithNHPClaims_ACOpenFailureAfterCommit_NoCancel proves the fail-closed
// branch: commit succeeded, AC open then fails — we surface the error and do NOT
// cancel (the contract forbids silently un-consuming a one-time-use qURL).
func TestAuthWithNHPClaims_ACOpenFailureAfterCommit_NoCancel(t *testing.T) {
	f := newV2Fixture(t, nil)
	enableV2(t, f.issuer.trustStore(t))

	rec := newAdmissionRecorder(t, defaultACRouting())
	setRecordingResolver(t, rec)

	_, err := AuthWithNHP(f.req, f.helper(errACOpenBoom))
	if err == nil {
		t.Fatal("expected AC-open failure to surface an error")
	}
	if !*f.openedCalled {
		t.Error("AC open should have been attempted (after commit)")
	}
	order := rec.callOrder()
	// authorize (fall-through) + prepare + commit must all have happened before
	// the failed open.
	if len(order) < 3 || order[0] != "authorize" || order[1] != "prepare" || order[2] != "commit" {
		t.Fatalf("call order = %v, want authorize,prepare,commit before the failed open", order)
	}
	for _, c := range order {
		if c == "cancel" {
			t.Error("cancel must NOT be called after a successful commit")
		}
	}
}

var errACOpenBoom = &boomErr{}

type boomErr struct{}

func (*boomErr) Error() string { return "ac open boom" }

// TestAuthWithNHPClaims_AdmissionDenied_NoCommit proves a terminal prepare deny
// (e.g. consumed/revoked) yields a session-expired ack and never commits or opens.
func TestAuthWithNHPClaims_AdmissionDenied_NoCommit(t *testing.T) {
	f := newV2Fixture(t, nil)
	enableV2(t, f.issuer.trustStore(t))

	rec := newAdmissionRecorder(t, defaultACRouting())
	rec.prepareStatus = http.StatusGone
	rec.prepareBody = `{"success":false,"error":{"code":"qurl_consumed","message":"gone"}}`
	setRecordingResolver(t, rec)

	ack, err := AuthWithNHP(f.req, f.helper(nil))
	if err == nil {
		t.Fatal("expected denied admission to error")
	}
	if ack.ErrCode != common.ErrQurlSessionExpired.ErrorCode() {
		t.Errorf("ack.ErrCode = %q, want ErrQurlSessionExpired", ack.ErrCode)
	}
	if *f.openedCalled {
		t.Error("AC must not open on a denied admission")
	}
	for _, c := range rec.callOrder() {
		if c == "commit" || c == "ac_open" {
			t.Errorf("unexpected call %q after a denied prepare", c)
		}
	}
}

// TestAuthWithNHPClaims_ConsumedReKnock_AuthorizeRefreshes_SessionSurvives is the
// MAJOR-closing proof. A CONSUMED one-time-use qURL re-knocks: its session is
// still live, so authorize returns 200 (the refresh) and the AC re-opens for the
// session's remaining lifetime — the session SURVIVES. It is NOT routed to
// prepare (which would 410 `consumed` and kill the still-live session at the first
// OpenTime expiry — the exact MAJOR being closed).
//
// Non-vacuous BY CONSTRUCTION: prepare is wired to 410 `qurl_consumed`. The
// correct authorize-first impl never touches it; a regression that routes a
// consumed re-knock to prepare hits the 410 and the test fails (session denied,
// no AC open, prepare recorded). The assertions pin: AC opened, OpenTime ==
// authorize remaining_seconds, the AOP carries authorize's session_id, and prepare
// was NEVER called.
func TestAuthWithNHPClaims_ConsumedReKnock_AuthorizeRefreshes_SessionSurvives(t *testing.T) {
	f := newV2Fixture(t, nil)
	enableV2(t, f.issuer.trustStore(t))

	refreshAC := &ACRouting{ACId: "ac-refresh-7", DestHost: "10.0.0.9", DestPort: 9443}
	rec := newAdmissionRecorder(t, defaultACRouting())
	// Live session -> authorize 200 refresh (remaining 120s, session sess_live_1).
	rec.liveAuthorize("sess_live_1", 120, refreshAC)
	// HOSTILE: prepare would 410 `consumed`. If the impl ever routes this consumed
	// re-knock to prepare, it dies here — exactly the regression we are guarding.
	rec.prepareStatus = http.StatusGone
	rec.prepareBody = `{"success":false,"error":{"code":"qurl_consumed","message":"already consumed"}}`

	var captured *common.ResourceData
	helper := &plugins.NhpServerPluginHelper{
		AspData:                testAspData(f.resourceB64, 60),
		ServerCellPublicKeyB64: f.cellStdB64,
		AuthWithNhpCallbackFunc: func(req *common.NhpAuthRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			captured = res
			req.Ack.ErrCode = common.ErrSuccess.ErrorCode()
			return req.Ack, nil
		},
	}
	setRecordingResolver(t, rec)

	ack, err := AuthWithNHP(f.req, helper)
	if err != nil {
		t.Fatalf("consumed re-knock must REFRESH (session survives), got error: %v", err)
	}
	if ack.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Errorf("ack.ErrCode = %q, want success (the live session refreshed)", ack.ErrCode)
	}
	if captured == nil {
		t.Fatal("AC refresh callback never fired; the session was NOT refreshed (likely routed to prepare)")
	}

	// The refresh must open the AC authorize selected, for the session's remaining
	// lifetime, and carry the session id into the AOP revocation metadata.
	if _, ok := captured.Resources[refreshAC.ACId]; !ok {
		t.Errorf("refreshed ResourceData missing authorize ac_routing %q; got %#v", refreshAC.ACId, captured.Resources)
	}
	if captured.OpenTime != 120 {
		t.Errorf("OpenTime = %d, want 120 (clamped to authorize remaining_seconds)", captured.OpenTime)
	}
	if ack.OpenTime != 120 {
		t.Errorf("ack.OpenTime = %d, want 120 (agent paces re-knock to the refreshed pinhole)", ack.OpenTime)
	}
	if captured.QurlSessionId != "sess_live_1" {
		t.Errorf("QurlSessionId = %q, want sess_live_1 (authorize's matched session, stamped into the AOP)", captured.QurlSessionId)
	}
	// A re-knock refresh does not re-navigate the browser.
	if ack.RedirectUrl != "" {
		t.Errorf("ack.RedirectUrl = %q, want empty on a re-knock refresh", ack.RedirectUrl)
	}

	// THE non-vacuity assertion: authorize alone admitted; prepare/commit/cancel
	// were never called. If this fails with "prepare" present, the impl is routing
	// consumed re-knocks to prepare and the MAJOR is reopened.
	order := rec.callOrder()
	if len(order) != 1 || order[0] != "authorize" {
		t.Fatalf("call order = %v, want [authorize] only (a consumed re-knock must refresh via authorize, NOT prepare)", order)
	}
}

// TestAuthWithNHPClaims_AuthorizeRequestKeyEncoding closes the coverage gap noted
// in review of the qv2 admission key-encoding fix: PrepareRequestShape asserts only
// the prepare body, but on the steady-state re-knock path authorize returns a live
// session and prepare is NEVER called — and authorize is where the live HTTP 400
// actually fired. Assert the authorize request carries authenticated_qurl_public_key_b64
// as UNPADDED base64url (what qurl-service's RawURLEncoding decoder accepts), never
// the std base64 form (padded) that 400'd every qv2 knock.
func TestAuthWithNHPClaims_AuthorizeRequestKeyEncoding(t *testing.T) {
	f := newV2Fixture(t, nil)
	enableV2(t, f.issuer.trustStore(t))

	rec := newAdmissionRecorder(t, defaultACRouting())
	rec.liveAuthorize("sess_live_1", 120, &ACRouting{ACId: "ac-1", DestHost: "10.0.0.9", DestPort: 9443})
	setRecordingResolver(t, rec)

	helper := &plugins.NhpServerPluginHelper{
		AspData:                testAspData(f.resourceB64, 60),
		ServerCellPublicKeyB64: f.cellStdB64,
		AuthWithNhpCallbackFunc: func(req *common.NhpAuthRequest, _ *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			req.Ack.ErrCode = common.ErrSuccess.ErrorCode()
			return req.Ack, nil
		},
	}
	if _, err := AuthWithNHP(f.req, helper); err != nil {
		t.Fatalf("AuthWithNHP (re-knock refresh): %v", err)
	}

	// Sanity: authorize alone admitted; prepare was never called — so this test
	// exercises the authorize-only path PrepareRequestShape cannot reach.
	if order := rec.callOrder(); len(order) != 1 || order[0] != "authorize" {
		t.Fatalf("call order = %v, want [authorize] only", order)
	}

	body := rec.authorizeRequest()
	if body == nil {
		t.Fatal("authorize request body was not captured")
	}
	if body["authenticated_qurl_public_key_b64"] != f.agentURLB64 {
		t.Errorf("authorize authenticated_qurl_public_key_b64 = %v, want base64url %q", body["authenticated_qurl_public_key_b64"], f.agentURLB64)
	}
	if body["authenticated_qurl_public_key_b64"] == f.agentStdB64 {
		t.Error("authorize authenticated_qurl_public_key_b64 is Std base64 (padded); qurl-service decodes RawURLEncoding and would 400 it")
	}
}

// TestAuthWithNHPClaims_HashDriftGuard covers the #3032 commit-path guard: when
// the qurl_user_public_key_hash qurl-service echoes in the prepare response
// diverges from the hash NHP recomputes locally (the revocation-index preimage),
// the first-knock commit path bumps MetricQurlV2CommitHashDrift; when they match
// it stays silent.
func TestAuthWithNHPClaims_HashDriftGuard(t *testing.T) {
	runFirstKnock := func(t *testing.T, echoedPrepareHash string) (driftCount int) {
		f := newV2Fixture(t, nil)
		enableV2(t, f.issuer.trustStore(t))
		ac := defaultACRouting()
		rec := newAdmissionRecorder(t, ac)
		rec.prepareBody = prepareBodyJSON(echoedPrepareHash, ac) // vary the echoed hash
		setRecordingResolver(t, rec)

		helper := &plugins.NhpServerPluginHelper{
			AspData:                testAspData(f.resourceB64, 60),
			ServerCellPublicKeyB64: f.cellStdB64,
			IncrCounter: func(name string) {
				if name == nhpserver.MetricQurlV2CommitHashDrift {
					driftCount++
				}
			},
			AuthWithNhpCallbackFunc: func(req *common.NhpAuthRequest, _ *common.ResourceData) (*common.ServerKnockAckMsg, error) {
				req.Ack.ErrCode = common.ErrSuccess.ErrorCode()
				return req.Ack, nil
			},
		}
		if _, err := AuthWithNHP(f.req, helper); err != nil {
			t.Fatalf("AuthWithNHP: %v", err)
		}
		return driftCount
	}

	t.Run("drift bumps the metric", func(t *testing.T) {
		// A value that cannot equal hex(sha256(...)) of the fixture's claims key.
		if got := runFirstKnock(t, "not-the-real-hash"); got != 1 {
			t.Errorf("MetricQurlV2CommitHashDrift fired %d times, want 1 (echoed hash != local recompute)", got)
		}
	})
	t.Run("matching hash stays silent", func(t *testing.T) {
		agentURL, _ := x25519KeyPair(t, 0x40) // the key newV2Fixture signs into the claims
		if got := runFirstKnock(t, mustPubKeyHashB64(t, agentURL)); got != 0 {
			t.Errorf("MetricQurlV2CommitHashDrift fired %d times, want 0 (hashes match)", got)
		}
	})
}

// TestAuthWithNHPClaims_LivenessPrecedesAuthorizeRefresh is the #2770 fence:
// an expired or not-yet-valid signed qv2 claim must be rejected BEFORE NHP asks
// qurl-service to refresh a live session. The fake authorize endpoint is hostile
// and would return a valid live-session refresh if contacted; the correct path
// never calls it, because signed exp/nbf liveness is part of NHP's local
// integrity boundary and is checked before any qurl-service side effect.
func TestAuthWithNHPClaims_LivenessPrecedesAuthorizeRefresh(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(claims map[string]any)
	}{
		{
			name: "expired claims",
			mutate: func(claims map[string]any) {
				now := time.Now().Unix()
				claims["iat"] = now - 1000
				claims["nbf"] = now - 1000
				claims["exp"] = now - 500 // well past skew
			},
		},
		{
			name: "not yet valid claims",
			mutate: func(claims map[string]any) {
				now := time.Now().Unix()
				claims["iat"] = now - 10   // already issued; only nbf is in the future
				claims["nbf"] = now + 1000 // future beyond skew
				claims["exp"] = now + 2000
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newV2Fixture(t, tt.mutate)
			enableV2(t, f.issuer.trustStore(t))

			rec := newAdmissionRecorder(t, defaultACRouting())
			rec.liveAuthorize("sess_stale_claim_should_not_refresh", 120, defaultACRouting())
			setRecordingResolver(t, rec)

			ack, err := AuthWithNHP(f.req, f.helper(nil))
			if err == nil {
				t.Fatal("stale signed claims must produce an error ack")
			}
			if ack.ErrCode != common.ErrQurlSessionExpired.ErrorCode() {
				t.Errorf("ack.ErrCode = %q, want ErrQurlSessionExpired", ack.ErrCode)
			}
			if *f.openedCalled {
				t.Error("AC must NOT open when signed claim liveness fails")
			}
			if got := rec.callOrder(); len(got) != 0 {
				t.Fatalf("signed claim liveness must reject before any qurl-service authorize/prepare call; got %v", got)
			}
		})
	}
}

// TestAuthWithNHPClaims_RevokedQurlReKnock_AuthorizeDenies_PrepareReDenies proves
// the safe side of authorize's 403-conflation: when the qURL itself is revoked,
// authorize finds no live session (403 -> fall through) AND prepare re-denies
// (410 `qurl_revoked`), so the knock is terminally denied with no AC open. This is
// the conflation working correctly — a genuinely-dead qURL that 403s on authorize
// is caught by prepare's stronger qURL-state gate.
func TestAuthWithNHPClaims_RevokedQurlReKnock_AuthorizeDenies_PrepareReDenies(t *testing.T) {
	f := newV2Fixture(t, nil)
	enableV2(t, f.issuer.trustStore(t))

	rec := newAdmissionRecorder(t, defaultACRouting())
	// authorize 403 (default: no live session) -> fall through to prepare.
	// prepare re-denies: the qURL is revoked.
	rec.prepareStatus = http.StatusGone
	rec.prepareBody = `{"success":false,"error":{"code":"qurl_revoked","message":"revoked"}}`
	setRecordingResolver(t, rec)

	ack, err := AuthWithNHP(f.req, f.helper(nil))
	if err == nil {
		t.Fatal("a revoked qURL re-knock must be denied")
	}
	if ack.ErrCode != common.ErrQurlSessionExpired.ErrorCode() {
		t.Errorf("ack.ErrCode = %q, want ErrQurlSessionExpired", ack.ErrCode)
	}
	if *f.openedCalled {
		t.Error("no AC may open for a revoked qURL")
	}
	// authorize then prepare (the fall-through), then a terminal deny — no commit,
	// no open.
	order := rec.callOrder()
	want := []string{"authorize", "prepare"}
	if len(order) != len(want) || order[0] != want[0] || order[1] != want[1] {
		t.Fatalf("call order = %v, want %v (authorize falls through, prepare re-denies)", order, want)
	}
}

// TestAuthWithNHPClaims_AuthorizeTerminalDeny_NoFallthrough proves a TERMINAL
// authorize denial (not the access_denied/no-session 403, but e.g. a structured
// qurl_revoked code) denies immediately and does NOT fall through to prepare. Only
// ErrNoLiveSession falls through; a provably-not-admissible authorize result is a
// hard deny.
func TestAuthWithNHPClaims_AuthorizeTerminalDeny_NoFallthrough(t *testing.T) {
	f := newV2Fixture(t, nil)
	enableV2(t, f.issuer.trustStore(t))

	rec := newAdmissionRecorder(t, defaultACRouting())
	rec.authorizeStatus = http.StatusGone
	rec.authorizeBody = `{"success":false,"error":{"code":"qurl_revoked","message":"revoked"}}`
	setRecordingResolver(t, rec)

	ack, err := AuthWithNHP(f.req, f.helper(nil))
	if err == nil {
		t.Fatal("a terminal authorize deny must error")
	}
	if ack.ErrCode != common.ErrQurlSessionExpired.ErrorCode() {
		t.Errorf("ack.ErrCode = %q, want ErrQurlSessionExpired", ack.ErrCode)
	}
	if *f.openedCalled {
		t.Error("no AC may open on a terminal authorize deny")
	}
	order := rec.callOrder()
	if len(order) != 1 || order[0] != "authorize" {
		t.Fatalf("call order = %v, want [authorize] only (a terminal authorize deny must NOT fall through to prepare)", order)
	}
}

// TestAuthWithNHPClaims_AuthorizeTransient_NoFallthrough proves the security-
// critical no-fallthrough-on-transient rule: a 5xx/transport authorize failure
// must NOT fall through to prepare. If it did, a consumed-but-live one-time-use
// session would be re-denied at prepare's status gate on every transient blip —
// reopening the MAJOR through the back door. The knock returns a retryable error
// ack (the agent's next re-knock refreshes cleanly), and prepare is never called.
func TestAuthWithNHPClaims_AuthorizeTransient_NoFallthrough(t *testing.T) {
	f := newV2Fixture(t, nil)
	enableV2(t, f.issuer.trustStore(t))

	rec := newAdmissionRecorder(t, defaultACRouting())
	rec.authorizeStatus = http.StatusInternalServerError
	rec.authorizeBody = `{"success":false,"error":{"code":"internal_error"}}`
	setRecordingResolver(t, rec)

	ack, err := AuthWithNHP(f.req, f.helper(nil))
	if err == nil {
		t.Fatal("a transient authorize failure must surface a (retryable) error")
	}
	if ack.ErrCode != common.ErrKnockApiRequestFailed.ErrorCode() {
		t.Errorf("ack.ErrCode = %q, want ErrKnockApiRequestFailed (retryable, not a hard deny)", ack.ErrCode)
	}
	if *f.openedCalled {
		t.Error("no AC may open on a transient authorize failure")
	}
	order := rec.callOrder()
	if len(order) != 1 || order[0] != "authorize" {
		t.Fatalf("call order = %v, want [authorize] only (a transient authorize failure must NOT fall through to prepare — that would re-deny a consumed-but-live session)", order)
	}
}

// crypto-check rejections: each must fail BEFORE prepare (no admission calls) and
// must NOT open the AC.
func TestAuthWithNHPClaims_CryptoChecksFailClosed(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (*v2Fixture, *plugins.NhpServerPluginHelper)
		wantErr *common.Error
	}{
		{
			name: "bad issuer signature",
			setup: func(t *testing.T) (*v2Fixture, *plugins.NhpServerPluginHelper) {
				f := newV2Fixture(t, nil)
				// Corrupt the signature so VerifyClaims fails.
				bad := []byte(f.sigB64)
				if bad[0] == 'A' {
					bad[0] = 'B'
				} else {
					bad[0] = 'A'
				}
				f.req.Msg.UserData[qurlV2IssuerSigUserDataKey] = string(bad)
				return f, f.helper(nil)
			},
			wantErr: common.ErrInvalidInput,
		},
		{
			name: "cell key mismatch (qURL minted for another cell)",
			setup: func(t *testing.T) (*v2Fixture, *plugins.NhpServerPluginHelper) {
				f := newV2Fixture(t, nil)
				h := f.helper(nil)
				_, otherCellStd := x25519KeyPair(t, 0x99) // different cell key
				h.ServerCellPublicKeyB64 = otherCellStd
				return f, h
			},
			wantErr: common.ErrInvalidInput,
		},
		{
			name: "proof-of-possession mismatch (authenticated key != claims)",
			setup: func(t *testing.T) (*v2Fixture, *plugins.NhpServerPluginHelper) {
				f := newV2Fixture(t, nil)
				_, otherAgentStd := x25519KeyPair(t, 0x88)
				f.req.PublicKey = otherAgentStd // authenticated as a different key
				return f, f.helper(nil)
			},
			wantErr: common.ErrInvalidInput,
		},
		{
			name: "resource identity mismatch (knock resource != claims)",
			setup: func(t *testing.T) (*v2Fixture, *plugins.NhpServerPluginHelper) {
				f := newV2Fixture(t, nil)
				f.req.Msg.ResourceId = resourceKeyB64URL(t) // different resource key
				return f, f.helper(nil)
			},
			wantErr: common.ErrResourceNotFound,
		},
		{
			name: "expired claims",
			setup: func(t *testing.T) (*v2Fixture, *plugins.NhpServerPluginHelper) {
				f := newV2Fixture(t, func(claims map[string]any) {
					now := time.Now().Unix()
					claims["iat"] = now - 1000
					claims["nbf"] = now - 1000
					claims["exp"] = now - 500 // well past skew
				})
				return f, f.helper(nil)
			},
			wantErr: common.ErrQurlSessionExpired,
		},
		{
			name: "not yet valid claims",
			setup: func(t *testing.T) (*v2Fixture, *plugins.NhpServerPluginHelper) {
				f := newV2Fixture(t, func(claims map[string]any) {
					now := time.Now().Unix()
					claims["iat"] = now - 10   // already issued; only nbf is in the future
					claims["nbf"] = now + 1000 // future beyond skew
					claims["exp"] = now + 2000
				})
				return f, f.helper(nil)
			},
			wantErr: common.ErrQurlSessionExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, helper := tt.setup(t)
			enableV2(t, f.issuer.trustStore(t))

			rec := newAdmissionRecorder(t, defaultACRouting())
			setRecordingResolver(t, rec)

			ack, err := AuthWithNHP(f.req, helper)
			if err == nil {
				t.Fatal("expected a crypto-check failure to error")
			}
			if ack.ErrCode != tt.wantErr.ErrorCode() {
				t.Errorf("ack.ErrCode = %q, want %q", ack.ErrCode, tt.wantErr.ErrorCode())
			}
			if *f.openedCalled {
				t.Error("AC must NOT open when a crypto check fails")
			}
			if len(rec.callOrder()) != 0 {
				t.Errorf("no qurl-service admission call may happen before the integrity boundary passes; got %v", rec.callOrder())
			}
		})
	}
}

// TestAuthWithNHPClaims_FlagOff_FailsClosed proves that with the feature OFF a
// qv2-shaped knock is DENIED at the dispatch and never reaches the legacy
// steady-state path. This is the math-first boundary: a qv2-shaped knock must
// verify or fail closed — it must NOT be admitted on a pre-existing legacy
// session without the qv2 issuer-sig / PoP / cell / resource binding.
//
// The hostile case: flag OFF, qv2 blobs present, ResourceId set to a legacy r_
// catalog id, and the resolver's /authorize WOULD allow (an active legacy session
// for this client IP). The knock must still be denied, and /authorize must never
// be called.
func TestAuthWithNHPClaims_FlagOff_FailsClosed(t *testing.T) {
	f := newV2Fixture(t, nil)
	// Do NOT enableV2 — feature stays off (default).
	if v2AdmissionEnabled {
		t.Fatal("precondition: v2 admission must be off by default in this test")
	}

	// Attacker shapes the knock as a legacy steady-state knock (legacy r_ resource
	// id) while still carrying qv2 blobs, to try to ride the legacy session path.
	f.req.Msg.ResourceId = "r_legacy00000"

	// Resolver that records calls and, on /authorize, WOULD allow (active session).
	// If the qv2 knock wrongly fell through to steady-state, this would admit it.
	var authorizeCalled bool
	var prepareCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case hasSuffix(r.URL.Path, "/authorize"):
			authorizeCalled = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"remaining_seconds":300}`)) // active session -> would allow
		case r.URL.Path == admissionPreparePath:
			prepareCalled = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(server.Close)
	prev := resolver
	resolver = &QurlResolver{httpClient: &http.Client{Timeout: 5 * time.Second}, baseURL: server.URL, serviceToken: "test-token"}
	t.Cleanup(func() { resolver = prev })

	ack, err := AuthWithNHP(f.req, f.helper(nil))
	if err == nil {
		t.Fatal("a qv2-shaped knock must be DENIED when v2 admission is disabled")
	}
	if ack.ErrCode != common.ErrQurlSessionExpired.ErrorCode() {
		t.Errorf("ack.ErrCode = %q, want ErrQurlSessionExpired (fail-closed deny)", ack.ErrCode)
	}
	if *f.openedCalled {
		t.Error("no AC may open for a qv2 knock when the feature is off")
	}
	if authorizeCalled {
		t.Error("steady-state /authorize must NEVER be called for a qv2-shaped knock (math-first boundary bypass)")
	}
	if prepareCalled {
		t.Error("v2 prepare must not be called when the feature is off")
	}
}

// TestAuthWithNHPClaims_PrepareRequestShape asserts the prepare request carries
// exactly the signed-claims blobs + authenticated facts, and no unsigned
// duplicate derived fields.
func TestAuthWithNHPClaims_PrepareRequestShape(t *testing.T) {
	f := newV2Fixture(t, nil)
	enableV2(t, f.issuer.trustStore(t))

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == admissionAuthorizePath {
			// First knock: no live session -> 403 access_denied -> fall through to
			// prepare (the path this test asserts the request shape of).
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"success":false,"error":{"code":"access_denied"}}`))
			return
		}
		if r.URL.Path == admissionPreparePath {
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			if got := r.Header.Get(ServiceTokenHeader); got != "test-token" {
				t.Errorf("service token header = %q, want test-token", got)
			}
			body, _ := json.Marshal(internalAdmissionPrepareResponse{
				Success: true,
				Data: &AdmissionPrepareResponse{
					QurlUserPublicKeyHash: "test-qhash",
					AdmissionID:           "adm_x", QurlID: "q_x", OpenTime: 30,
					QurlSiteURL: "https://q.qurl.site/p",
					ACRouting:   defaultACRouting(),
				},
			})
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
			return
		}
		w.WriteHeader(http.StatusOK) // commit
	}))
	t.Cleanup(server.Close)
	prev := resolver
	resolver = &QurlResolver{httpClient: &http.Client{Timeout: 5 * time.Second}, baseURL: server.URL, serviceToken: "test-token"}
	t.Cleanup(func() { resolver = prev })

	if _, err := AuthWithNHP(f.req, f.helper(nil)); err != nil {
		t.Fatalf("AuthWithNHP: %v", err)
	}

	if gotBody["qurl_claims_b64"] != f.claimsB64 {
		t.Errorf("prepare qurl_claims_b64 = %v, want the wire claims bytes", gotBody["qurl_claims_b64"])
	}
	if gotBody["qurl_issuer_sig_b64"] != f.sigB64 {
		t.Errorf("prepare qurl_issuer_sig_b64 mismatch")
	}
	// authenticated_qurl_public_key_b64 MUST be UNPADDED base64url — that is the
	// encoding qurl-service's admission decoder (RawURLEncoding) accepts, per the
	// qURL v2 contract. The Noise-authenticated key is the same bytes; sending its
	// Std base64 form (req.PublicKey / agentStdB64, padded) is the regression that
	// 400'd every qv2 knock. Assert the base64url form and guard against Std.
	if gotBody["authenticated_qurl_public_key_b64"] != f.agentURLB64 {
		t.Errorf("prepare authenticated_qurl_public_key_b64 = %v, want base64url %q", gotBody["authenticated_qurl_public_key_b64"], f.agentURLB64)
	}
	if gotBody["authenticated_qurl_public_key_b64"] == f.agentStdB64 {
		t.Error("prepare authenticated_qurl_public_key_b64 is Std base64 (padded); qurl-service decodes RawURLEncoding and would 400 it")
	}
	if gotBody["src_ip"] != "203.0.113.9" {
		t.Errorf("prepare src_ip = %v, want 203.0.113.9", gotBody["src_ip"])
	}
	// No unsigned duplicate derived fields: qurl-service derives these FROM the
	// signed claims and must not receive copies.
	for _, forbidden := range []string{"resource_public_key_b64", "cell_public_key_b64", "qurl_user_public_key_b64", "exp", "jti"} {
		if _, present := gotBody[forbidden]; present {
			t.Errorf("prepare request must NOT carry unsigned derived field %q", forbidden)
		}
	}
}

// sanity: the test signer actually verifies against the real VerifyClaims, so a
// green binding test is not masking a broken signer.
func TestV2TestIssuer_SignsVerifiableClaims(t *testing.T) {
	f := newV2Fixture(t, nil)
	ts := f.issuer.trustStore(t)
	if _, err := qurlv2.VerifyClaims(f.claimsB64, f.sigB64, ts); err != nil {
		t.Fatalf("test-signed claims must verify against VerifyClaims: %v", err)
	}
}

// TestAuthWithNHPClaims_ResourceIDEncodingContract pins the cross-impl contract
// that the knock resource identity (req.Msg.ResourceId) is the protected-resource
// public key in unpadded base64url — the SAME pinned encoding as the claim's
// resource_public_key_b64. The js-agent must emit it that way. If it ever emits
// std-base64 or padded, the resource-binding check fails closed (safe, but a
// silent total outage), so this test catches a divergence at build time:
//   - the normal fixture (base64url ResourceId) admits;
//   - the SAME resource key re-encoded as std-base64/padded is DENIED at the
//     resource-binding check, before any qurl-service call.
func TestAuthWithNHPClaims_ResourceIDEncodingContract(t *testing.T) {
	// Control: base64url ResourceId admits (full happy path).
	f := newV2Fixture(t, nil)
	enableV2(t, f.issuer.trustStore(t))
	rec := newAdmissionRecorder(t, defaultACRouting())
	setRecordingResolver(t, rec)
	if _, err := AuthWithNHP(f.req, f.helper(nil)); err != nil {
		t.Fatalf("control: base64url ResourceId must admit, got %v", err)
	}

	// Divergence: re-encode the SAME resource key bytes as STANDARD base64
	// (padded) — the wrong encoding. The resource-binding check must reject it and
	// no qurl-service admission call may happen.
	f2 := newV2Fixture(t, nil)
	enableV2(t, f2.issuer.trustStore(t))
	rawResource, decErr := base64.RawURLEncoding.DecodeString(f2.resourceB64)
	if decErr != nil {
		t.Fatalf("decode fixture resource key: %v", decErr)
	}
	f2.req.Msg.ResourceId = base64.StdEncoding.EncodeToString(rawResource) // wrong encoding
	rec2 := newAdmissionRecorder(t, defaultACRouting())
	setRecordingResolver(t, rec2)

	ack, err := AuthWithNHP(f2.req, f2.helper(nil))
	if err == nil {
		t.Fatal("a std-base64 (wrong-encoding) ResourceId must be denied — the contract is unpadded base64url")
	}
	if ack.ErrCode != common.ErrResourceNotFound.ErrorCode() {
		t.Errorf("ack.ErrCode = %q, want ErrResourceNotFound (resource-binding mismatch)", ack.ErrCode)
	}
	if *f2.openedCalled {
		t.Error("no AC may open on a resource-binding mismatch")
	}
	if len(rec2.callOrder()) != 0 {
		t.Errorf("no qurl-service admission call may happen on a resource-binding mismatch; got %v", rec2.callOrder())
	}
}

// TestAuthWithNHPClaims_PopulatesRevocationMetadata proves the v2 admission path
// stamps the qURL v2 revocation metadata (P4a) onto the ResourceData handed to
// AuthWithNhpCallbackFunc (which the server then carries to the AOP and the AC):
//
//   - qurl_user_public_key_hash and resource_public_key_hash are the canonical
//     hashes of the VERIFIED claim keys (recomputed via the same canonical hasher
//     the production path uses, asserting the value flows through correctly;
//     the hasher's FORMAT is pinned independently in qurlv2 claims_hash_test.go);
//   - admission_id is the id prepare returned;
//   - deadline is the claim exp;
//   - session_id and revocation_epoch are intentionally not carried on
//     ResourceData at all (the admission prepare contract does not return them),
//     so the deferral is structurally enforced, not merely left unset.
func TestAuthWithNHPClaims_PopulatesRevocationMetadata(t *testing.T) {
	issuer := newV2TestIssuer(t)
	cellURL, cellStd := x25519KeyPair(t, 0x10)
	agentURL, agentStd := x25519KeyPair(t, 0x40)
	resB64 := resourceKeyB64URL(t)

	now := time.Now().Unix()
	exp := now + 300
	claims := map[string]any{
		"v":                        2,
		"iss":                      "qurl-service",
		"kid":                      testV2KID,
		"iat":                      now - 10,
		"nbf":                      now - 10,
		"exp":                      exp,
		"jti":                      "qurl_meta_test",
		"cell_public_key_b64":      cellURL,
		"relay_url":                "https://relay.example.com",
		"resource_public_key_b64":  resB64,
		"qurl_user_public_key_b64": agentURL,
	}
	claimsB64, sigB64 := issuer.sign(t, claims)
	enableV2(t, issuer.trustStore(t))
	setRecordingResolver(t, newAdmissionRecorder(t, defaultACRouting()))

	// Canonical expected hashes for the verified claim keys.
	wantUserHash, err := qurlv2.PublicKeyHashFromB64(agentURL)
	if err != nil {
		t.Fatalf("hash agent key: %v", err)
	}
	wantResHash, err := qurlv2.PublicKeyHashFromB64(resB64)
	if err != nil {
		t.Fatalf("hash resource key: %v", err)
	}

	var captured *common.ResourceData
	helper := &plugins.NhpServerPluginHelper{
		AspData:                testAspData(resB64, 60),
		ServerCellPublicKeyB64: cellStd,
		AuthWithNhpCallbackFunc: func(req *common.NhpAuthRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			captured = res
			req.Ack.ErrCode = common.ErrSuccess.ErrorCode()
			return req.Ack, nil
		},
	}

	req := &common.NhpAuthRequest{
		Msg: &common.AgentKnockMsg{
			AuthServiceId: PluginID,
			ResourceId:    resB64,
			UserId:        "u",
			UserData: map[string]any{
				qurlV2ClaimsUserDataKey:    claimsB64,
				qurlV2IssuerSigUserDataKey: sigB64,
			},
		},
		Ack:       &common.ServerKnockAckMsg{},
		PublicKey: agentStd,
		SrcAddr:   &common.NetAddress{Ip: "203.0.113.9", Port: 5555},
	}

	if _, err := AuthWithNHP(req, helper); err != nil {
		t.Fatalf("AuthWithNHP qv2: %v", err)
	}
	if captured == nil {
		t.Fatal("AC-open callback never fired; ResourceData not captured")
	}

	if captured.QurlUserPublicKeyHash != wantUserHash {
		t.Errorf("QurlUserPublicKeyHash = %q, want %q", captured.QurlUserPublicKeyHash, wantUserHash)
	}
	if captured.ResourcePublicKeyHash != wantResHash {
		t.Errorf("ResourcePublicKeyHash = %q, want %q", captured.ResourcePublicKeyHash, wantResHash)
	}
	if captured.AdmissionId != "adm_test123" {
		t.Errorf("AdmissionId = %q, want %q (from prepare)", captured.AdmissionId, "adm_test123")
	}
	if captured.Deadline != exp {
		t.Errorf("Deadline = %d, want claim exp %d", captured.Deadline, exp)
	}
	// QurlSessionId MUST be empty on the FIRST-KNOCK (prepare) path: prepare returns no
	// session id, and only the steady-state authorize/refresh path carries one.
	// This locks in that a first knock never leaks a session id into the AOP.
	if captured.QurlSessionId != "" {
		t.Errorf("QurlSessionId = %q, want empty on the first-knock (prepare) path", captured.QurlSessionId)
	}
	// revocation_epoch is deferred and has NO field on ResourceData by design (no
	// admission response returns it), so the deferral is structurally enforced.
}

// TestBuildV2ResourceData_HashError_FailsOpenAndCounts pins the deliberate
// fail-open-but-observable behavior of the hash branch in buildV2ResourceData:
// when a claim key cannot be hashed (e.g. a non-base64url value that should be
// unreachable post-VerifyClaims), the admission is NOT failed — the returned
// ResourceData carries an EMPTY hash for that key — AND the
// MetricQurlV2RevocationHashError counter fires so the regression is alertable
// rather than log-only. This is the test that would break if someone removed the
// counter or "hardened" the branch into a fail-closed return.
func TestBuildV2ResourceData_HashError_FailsOpenAndCounts(t *testing.T) {
	resB64 := resourceKeyB64URL(t)
	goodResHash, err := qurlv2.PublicKeyHashFromB64(resB64)
	if err != nil {
		t.Fatalf("hash good resource key: %v", err)
	}

	resp := &AdmissionPrepareResponse{
		QurlUserPublicKeyHash: "test-qhash",
		AdmissionID:           "adm_failopen",
		QurlID:                "q_failopen",
		OpenTime:              60,
		ACRouting:             defaultACRouting(),
	}
	// qurl-user key is invalid base64url (padding is rejected by the strict
	// decoder); resource key is valid. Only the qurl-user hash should fail.
	claims := &qurlv2.Claims{
		QurlUserPublicKeyB64: "not_base64url====",
		ResourcePublicKeyB64: resB64,
		Exp:                  1781910300,
	}

	var hashErrCount int
	got := buildV2ResourceData(resp, claims, func(name string) {
		if name == nhpserver.MetricQurlV2RevocationHashError {
			hashErrCount++
		}
	})

	if got == nil {
		t.Fatal("buildV2ResourceData returned nil on hash error; must fail open, not abort")
	}
	// Fail-open: the bad key yields an empty hash, the admission still produces a
	// ResourceData (the AC pinhole + per-admission fields are intact).
	if got.QurlUserPublicKeyHash != "" {
		t.Errorf("QurlUserPublicKeyHash = %q, want empty on hash failure (fail-open)", got.QurlUserPublicKeyHash)
	}
	if got.ResourcePublicKeyHash != goodResHash {
		t.Errorf("ResourcePublicKeyHash = %q, want %q (the valid key still hashes)", got.ResourcePublicKeyHash, goodResHash)
	}
	if got.AdmissionId != "adm_failopen" {
		t.Errorf("AdmissionId = %q, want %q (admission metadata intact)", got.AdmissionId, "adm_failopen")
	}
	if got.Deadline != 1781910300 {
		t.Errorf("Deadline = %d, want 1781910300 (admission metadata intact)", got.Deadline)
	}
	// Observable: exactly one counter emission, for the one bad key.
	if hashErrCount != 1 {
		t.Errorf("MetricQurlV2RevocationHashError fired %d times, want 1 (one bad key)", hashErrCount)
	}
}

// TestBuildV2ResourceData_NoHashError_DoesNotCount is the negative control: with
// both claim keys valid, the hash-error counter must NOT fire, so the metric is
// a true regression signal and not noise on the happy path.
func TestBuildV2ResourceData_NoHashError_DoesNotCount(t *testing.T) {
	resB64 := resourceKeyB64URL(t)
	userURL, _ := x25519KeyPair(t, 0x40)

	resp := &AdmissionPrepareResponse{
		QurlUserPublicKeyHash: "test-qhash",
		AdmissionID:           "adm_ok",
		OpenTime:              60,
		ACRouting:             defaultACRouting(),
	}
	claims := &qurlv2.Claims{
		QurlUserPublicKeyB64: userURL,
		ResourcePublicKeyB64: resB64,
		Exp:                  1781910300,
	}

	var hashErrCount int
	got := buildV2ResourceData(resp, claims, func(name string) {
		if name == nhpserver.MetricQurlV2RevocationHashError {
			hashErrCount++
		}
	})
	if got.QurlUserPublicKeyHash == "" || got.ResourcePublicKeyHash == "" {
		t.Fatalf("valid keys must hash non-empty; got user=%q res=%q", got.QurlUserPublicKeyHash, got.ResourcePublicKeyHash)
	}
	if hashErrCount != 0 {
		t.Errorf("MetricQurlV2RevocationHashError fired %d times on valid keys, want 0", hashErrCount)
	}
}

// TestBuildV2ResourceData_NilClaims_GuardedNotPanic pins the defensive guard at
// this now-test-reachable seam: a nil claims (documented invariant violation)
// must NOT panic — it builds the pinhole-only ResourceData (the AC still opens)
// with empty revocation hashes and bumps the same counter so the anomaly is
// observable. The AC pinhole fields (from resp, not claims) stay intact.
func TestBuildV2ResourceData_NilClaims_GuardedNotPanic(t *testing.T) {
	resp := &AdmissionPrepareResponse{
		QurlUserPublicKeyHash: "test-qhash",
		AdmissionID:           "adm_nilclaims",
		QurlID:                "q_nilclaims",
		OpenTime:              60,
		ACRouting:             defaultACRouting(),
	}

	var hashErrCount int
	got := buildV2ResourceData(resp, nil, func(name string) {
		if name == nhpserver.MetricQurlV2RevocationHashError {
			hashErrCount++
		}
	})

	if got == nil {
		t.Fatal("buildV2ResourceData returned nil on nil claims; must build pinhole-only, not abort")
	}
	// Pinhole / AC-open fields come from resp and must be intact.
	if got.ResourceId != "q_nilclaims" || got.AdmissionId != "adm_nilclaims" {
		t.Errorf("pinhole/admission fields wrong: ResourceId=%q AdmissionId=%q", got.ResourceId, got.AdmissionId)
	}
	if _, ok := got.Resources[defaultACRouting().ACId]; !ok {
		t.Errorf("AC routing missing from pinhole ResourceData: %#v", got.Resources)
	}
	// Revocation hashes + claim-derived deadline are empty/zero (no claims).
	if got.QurlUserPublicKeyHash != "" || got.ResourcePublicKeyHash != "" || got.Deadline != 0 {
		t.Errorf("nil claims must yield empty hashes + zero deadline; got user=%q res=%q deadline=%d",
			got.QurlUserPublicKeyHash, got.ResourcePublicKeyHash, got.Deadline)
	}
	// Observable: the counter fires once for the nil-claims anomaly.
	if hashErrCount != 1 {
		t.Errorf("MetricQurlV2RevocationHashError fired %d times on nil claims, want 1", hashErrCount)
	}
}

// TestAcRoutingToResourceInfo_LeavesAddrIpEmpty is the mode-1 regression fence:
// the AOP destination built from a qurl-service ac_routing must leave Addr.Ip
// EMPTY (so the AC's applyDefaultIpSubstitution writes its own LOCAL_IP) for BOTH
// a hostname dest_host (which previously failed the AC's eBPF parseIP →
// ErrServerACOpsFailed/52005 on every knock) and a raw-IP dest_host (which
// previously mis-keyed the rule on the resource IP → silent datapath deny of real
// customer traffic). dest_host must ride Hostname (informational; feeds the ack
// ResourceHost), and the shape must match the qv1 catalog (Protocol="tcp",
// Port=dest_port).
func TestAcRoutingToResourceInfo_LeavesAddrIpEmpty(t *testing.T) {
	for _, tc := range []struct {
		name     string
		destHost string
	}{
		{"hostname_dest_was_reproducible_52005", "app.internal"},
		{"ip_dest_was_silent_datapath_deny", "172.66.147.243"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := acRoutingToResourceInfo(&ACRouting{ACId: "ac-9", DestHost: tc.destHost, DestPort: 8443})
			if info.Addr == nil {
				t.Fatal("Addr is nil")
			}
			if info.Addr.Ip != "" {
				t.Errorf("Addr.Ip = %q, want \"\" so the AC substitutes its LOCAL_IP (dest_host must NOT reach the eBPF datapath)", info.Addr.Ip)
			}
			if info.Hostname != tc.destHost {
				t.Errorf("Hostname = %q, want dest_host %q (informational ack ResourceHost)", info.Hostname, tc.destHost)
			}
			if info.Addr.Port != 8443 {
				t.Errorf("Addr.Port = %d, want 8443 (customer-facing/ingress port from dest_port)", info.Addr.Port)
			}
			if info.Addr.Protocol != "tcp" {
				t.Errorf("Addr.Protocol = %q, want tcp (qURL is TCP; matches qv1 catalog)", info.Addr.Protocol)
			}
			if info.ACId != "ac-9" {
				t.Errorf("ACId = %q, want ac-9", info.ACId)
			}
			// The ack's ResourceHost still surfaces dest_host via Hostname, so the
			// datapath fix does not change the ack the agent sees.
			if got := info.DestHost(); got != tc.destHost {
				t.Errorf("DestHost() = %q, want %q (ack ResourceHost preserved)", got, tc.destHost)
			}
		})
	}
}

// TestBuildV2ResourceData_And_Refresh_UseEmptyAddrIp pins that BOTH the
// first-knock and re-knock builders route ac_routing through
// acRoutingToResourceInfo, so neither qURL v2 admission path can regress the AC
// datapath by leaking dest_host into the pinhole destination IP.
func TestBuildV2ResourceData_And_Refresh_UseEmptyAddrIp(t *testing.T) {
	noop := func(string) {}

	prep := &AdmissionPrepareResponse{
		AdmissionID: "adm_1", QurlID: "q_1", QurlUserPublicKeyHash: "h", OpenTime: 60,
		ACRouting: &ACRouting{ACId: "ac-first", DestHost: "app.internal", DestPort: 443},
	}
	// Real (empty) Claims, not nil: the datapath fields under test are independent
	// of the revocation hashes, and an empty Claims exercises the builder without
	// tripping revocationHashesFromClaims' fail-open nil-claims error log (empty
	// key strings decode to empty bytes and hash cleanly — no hash-error log either).
	first := buildV2ResourceData(prep, &qurlv2.Claims{}, noop)
	if info := first.Resources["ac-first"]; info == nil || info.Addr == nil || info.Addr.Ip != "" || info.Hostname != "app.internal" {
		t.Errorf("first-knock: got %#v, want empty Addr.Ip + Hostname=app.internal", first.Resources["ac-first"])
	}

	auth := &AdmissionAuthorizeResponse{
		SessionID: "sess_1", RemainingSeconds: 120,
		ACRouting: &ACRouting{ACId: "ac-refresh", DestHost: "10.0.0.9", DestPort: 9443},
	}
	refresh := buildV2RefreshResourceData(auth, &qurlv2.Claims{}, noop)
	if info := refresh.Resources["ac-refresh"]; info == nil || info.Addr == nil || info.Addr.Ip != "" || info.Hostname != "10.0.0.9" {
		t.Errorf("re-knock: got %#v, want empty Addr.Ip + Hostname=10.0.0.9", refresh.Resources["ac-refresh"])
	}
}
