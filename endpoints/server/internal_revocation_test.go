package server

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/endpoints/internal/revocationscope"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/layervai/nhp/internalauth"
)

// --- harness ---------------------------------------------------------------

func udpAddr(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

func newRevocationRouter(hs *HttpServer) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	group := router.Group("/nhp/internal")
	group.POST("/revocation", hs.handleInternalRevocation)
	return router
}

func newRevocationSigner(t *testing.T) *internalauth.Signer {
	t.Helper()
	signer, err := internalauth.New("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("internalauth.New: %v", err)
	}
	return signer
}

// newRevocationTestServer is newRevokeDropTestServer plus a buffered sendMsgCh
// so fanoutRevocation can enqueue NHP_REV. A nil sendMsgCh would make every
// non-blocking send hit the default arm (a send on a nil channel blocks
// forever, so select picks default) and report spurious backpressure — buf
// sizes the queue per test.
func newRevocationTestServer(t *testing.T, sendBuf int) *UdpServer {
	t.Helper()
	s := newRevokeDropTestServer(t)
	s.sendMsgCh = make(chan *core.MsgData, sendBuf)
	return s
}

// signedRevocationRequest builds a POST with a valid HMAC header over the body.
func signedRevocationRequest(t *testing.T, signer *internalauth.Signer, body []byte) *http.Request {
	t.Helper()
	const path = "/nhp/internal/revocation"
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
	req.RemoteAddr = "10.0.0.5:53100"
	if signer != nil {
		req.Header.Set(internalauth.Header, signer.Sign(http.MethodPost, path, body))
	}
	return req
}

// validCellWideEvent is a well-formed cell-wide revocation event (the only mode
// qurl-service emits today). mutate lets a test perturb a single field.
func validCellWideEvent(mutate func(*revocationEvent)) []byte {
	evt := revocationEvent{
		Scope:           "resource",
		ScopeKey:        "resource:abc123",
		RevocationEpoch: 7,
		EventID:         "evt_test_1",
		FanoutMode:      revocationFanoutCellWide,
	}
	if mutate != nil {
		mutate(&evt)
	}
	b, _ := json.Marshal(evt)
	return b
}

// drainSend collects everything currently buffered on the server's send queue.
func drainSend(s *UdpServer) []*core.MsgData {
	var out []*core.MsgData
	for {
		select {
		case md := <-s.sendMsgCh:
			out = append(out, md)
		default:
			return out
		}
	}
}

// --- auth gates ------------------------------------------------------------

func TestInternalRevocation_StrictNoAuthHeader401(t *testing.T) {
	s := newRevocationTestServer(t, 16)
	hs := &HttpServer{udpServer: s, internalAuthSigner: newRevocationSigner(t), internalAuthRequire: true}
	router := newRevocationRouter(hs)

	// No auth header → strict mode rejects with 401.
	req := signedRevocationRequest(t, nil, validCellWideEvent(nil))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", rec.Code, rec.Body.String())
	}
	if got := drainSend(s); len(got) != 0 {
		t.Fatalf("fanout happened on a rejected request: %d msgs", len(got))
	}
}

func TestInternalRevocation_StrictBadSignature401(t *testing.T) {
	signer := newRevocationSigner(t)
	s := newRevocationTestServer(t, 16)
	hs := &HttpServer{udpServer: s, internalAuthSigner: signer, internalAuthRequire: true}
	router := newRevocationRouter(hs)

	const path = "/nhp/internal/revocation"
	signedBody := validCellWideEvent(nil)
	// Sign the original body, then POST a DIFFERENT (tampered) body: the
	// recomputed body hash won't match the signature → strict 401.
	tampered := validCellWideEvent(func(e *revocationEvent) { e.RevocationEpoch = 99 })
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(tampered)))
	req.RemoteAddr = "10.0.0.5:53100"
	req.Header.Set(internalauth.Header, signer.Sign(http.MethodPost, path, signedBody))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401 (body/sig mismatch)", rec.Code, rec.Body.String())
	}
}

func TestInternalRevocation_PublicSourceIP403(t *testing.T) {
	signer := newRevocationSigner(t)
	s := newRevocationTestServer(t, 16)
	hs := &HttpServer{udpServer: s, internalAuthSigner: signer, internalAuthRequire: true}
	router := newRevocationRouter(hs)

	body := validCellWideEvent(nil)
	req := signedRevocationRequest(t, signer, body)
	req.RemoteAddr = "203.0.113.7:40000" // public IP → rejected before auth
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403", rec.Code, rec.Body.String())
	}
}

func TestInternalRevocation_PermitModeUnsignedAllowed(t *testing.T) {
	// Permit mode (signer set, require=false): an unsigned request is allowed
	// through during the rollout and still fans out.
	signer := newRevocationSigner(t)
	s := newRevocationTestServer(t, 16)
	putRevokeDropConn(s, "ac-permit", 0xD1, udpAddr("10.0.0.31", 47031))
	hs := &HttpServer{udpServer: s, internalAuthSigner: signer, internalAuthRequire: false}
	router := newRevocationRouter(hs)

	req := signedRevocationRequest(t, nil, validCellWideEvent(nil)) // no auth header
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 (permit mode)", rec.Code, rec.Body.String())
	}
	if got := drainSend(s); len(got) != 1 {
		t.Fatalf("permit-mode fanout sent %d msgs, want 1", len(got))
	}
}

// --- validation ------------------------------------------------------------

func TestInternalRevocation_ValidationRejects400(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"unknown_scope", validCellWideEvent(func(e *revocationEvent) { e.Scope = "bogus" })},
		{"admission_is_not_a_wire_scope", validCellWideEvent(func(e *revocationEvent) { e.Scope = "admission" })},
		{"empty_scope_key", validCellWideEvent(func(e *revocationEvent) { e.ScopeKey = "" })},
		{"negative_epoch", validCellWideEvent(func(e *revocationEvent) { e.RevocationEpoch = -1 })},
		{"unknown_fanout_mode", validCellWideEvent(func(e *revocationEvent) { e.FanoutMode = "broadcast" })},
		{"empty_fanout_mode", validCellWideEvent(func(e *revocationEvent) { e.FanoutMode = "" })},
		{"malformed_json", []byte(`{"scope":`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer := newRevocationSigner(t)
			s := newRevocationTestServer(t, 16)
			putRevokeDropConn(s, "ac-v", 0xE1, udpAddr("10.0.0.41", 47041))
			hs := &HttpServer{udpServer: s, internalAuthSigner: signer, internalAuthRequire: true}
			router := newRevocationRouter(hs)

			req := signedRevocationRequest(t, signer, tc.body)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
			}
			if got := drainSend(s); len(got) != 0 {
				t.Fatalf("invalid event fanned out: %d msgs", len(got))
			}
		})
	}
}

func TestInternalRevocation_IncompleteTargeted400(t *testing.T) {
	signer := newRevocationSigner(t)
	s := newRevocationTestServer(t, 16)
	putRevokeDropConn(s, "ac-x", 0xF1, udpAddr("10.0.0.51", 47051))
	hs := &HttpServer{udpServer: s, internalAuthSigner: signer, internalAuthRequire: true}
	router := newRevocationRouter(hs)

	body := validCellWideEvent(func(e *revocationEvent) {
		e.FanoutMode = revocationFanoutTargeted
		e.TargetSetComplete = false // the gate
		e.TargetACIDs = []string{"ac-x"}
	})
	req := signedRevocationRequest(t, signer, body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400 (incomplete targeted)", rec.Code, rec.Body.String())
	}
	if got := drainSend(s); len(got) != 0 {
		t.Fatalf("incomplete-targeted event fanned out: %d msgs", len(got))
	}
}

// --- fanout ----------------------------------------------------------------

func TestInternalRevocation_CellWideFansOutToAllACs(t *testing.T) {
	signer := newRevocationSigner(t)
	s := newRevocationTestServer(t, 16)
	putRevokeDropConn(s, "ac-a", 0x01, udpAddr("10.0.0.61", 47061))
	putRevokeDropConn(s, "ac-b", 0x02, udpAddr("10.0.0.62", 47062))
	putRevokeDropConn(s, "ac-c", 0x03, udpAddr("10.0.0.63", 47063))
	hs := &HttpServer{udpServer: s, internalAuthSigner: signer, internalAuthRequire: true}
	router := newRevocationRouter(hs)

	body := validCellWideEvent(nil)
	req := signedRevocationRequest(t, signer, body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	got := drainSend(s)
	if len(got) != 3 {
		t.Fatalf("cell-wide fanout sent %d msgs, want 3 (all ACs)", len(got))
	}
	var resp struct {
		ACsTargeted int `json:"acs_targeted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ACsTargeted != 3 {
		t.Errorf("acs_targeted=%d, want 3", resp.ACsTargeted)
	}
}

func TestInternalRevocation_TargetedFansOutToFilteredACsOnly(t *testing.T) {
	signer := newRevocationSigner(t)
	s := newRevocationTestServer(t, 16)
	putRevokeDropConn(s, "ac-a", 0x11, udpAddr("10.0.0.71", 47071))
	putRevokeDropConn(s, "ac-b", 0x12, udpAddr("10.0.0.72", 47072))
	putRevokeDropConn(s, "ac-c", 0x13, udpAddr("10.0.0.73", 47073))
	hs := &HttpServer{udpServer: s, internalAuthSigner: signer, internalAuthRequire: true}
	router := newRevocationRouter(hs)

	// Target only ac-a and ac-c (skip ac-b); include a phantom id that matches
	// no connection — it must not error or send.
	body := validCellWideEvent(func(e *revocationEvent) {
		e.FanoutMode = revocationFanoutTargeted
		e.TargetSetComplete = true
		e.TargetACIDs = []string{"ac-a", "ac-c", "ac-not-connected"}
	})
	req := signedRevocationRequest(t, signer, body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	got := drainSend(s)
	if len(got) != 2 {
		t.Fatalf("targeted fanout sent %d msgs, want 2 (ac-a, ac-c)", len(got))
	}
	// Confirm the recipients are exactly ac-a and ac-c by pubkey, and that
	// ac-b's pubkey is NOT among them.
	bPub := testPubkeyB64(0x12)
	wantA := testPubkeyB64(0x11)
	wantC := testPubkeyB64(0x13)
	seen := map[string]bool{}
	for _, md := range got {
		for _, candidate := range []string{wantA, wantC, bPub} {
			peer := &core.UdpPeer{PubKeyBase64: candidate}
			if string(md.PeerPk) == string(peer.PublicKey()) {
				seen[candidate] = true
			}
		}
	}
	if !seen[wantA] || !seen[wantC] {
		t.Errorf("targeted recipients missing ac-a/ac-c: seen=%v", seen)
	}
	if seen[bPub] {
		t.Errorf("targeted fanout reached non-targeted ac-b")
	}
}

func TestInternalRevocation_EmptyMatchIsNoOp200(t *testing.T) {
	signer := newRevocationSigner(t)
	s := newRevocationTestServer(t, 16) // no AC connections registered
	hs := &HttpServer{udpServer: s, internalAuthSigner: signer, internalAuthRequire: true}
	router := newRevocationRouter(hs)

	// Cell-wide with zero connected ACs → success, nothing to flush here.
	req := signedRevocationRequest(t, signer, validCellWideEvent(nil))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 (empty match no-op)", rec.Code, rec.Body.String())
	}
	if got := drainSend(s); len(got) != 0 {
		t.Fatalf("empty match still sent %d msgs", len(got))
	}
}

// --- backpressure ----------------------------------------------------------

func TestInternalRevocation_BackpressureReturns503(t *testing.T) {
	signer := newRevocationSigner(t)
	// sendBuf=0 (unbuffered) with no reader → the first non-blocking enqueue
	// hits the default arm immediately → backpressure.
	s := newRevocationTestServer(t, 0)
	putRevokeDropConn(s, "ac-a", 0x21, udpAddr("10.0.0.81", 47081))
	hs := &HttpServer{udpServer: s, internalAuthSigner: signer, internalAuthRequire: true}
	router := newRevocationRouter(hs)

	req := signedRevocationRequest(t, signer, validCellWideEvent(nil))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s, want 503 (backpressure)", rec.Code, rec.Body.String())
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricRevocationFanoutBackpressure]; c != 1 {
		t.Errorf("%s counter=%v, want 1", MetricRevocationFanoutBackpressure, c)
	}
}

// --- NHP_REV message shape -------------------------------------------------

func TestInternalRevocation_NHPRevMsgDataShape(t *testing.T) {
	signer := newRevocationSigner(t)
	s := newRevocationTestServer(t, 16)
	const acID = "ac-shape"
	const seed = 0x31
	conn, _ := putRevokeDropConn(s, acID, seed, udpAddr("10.0.0.91", 47091))
	hs := &HttpServer{udpServer: s, internalAuthSigner: signer, internalAuthRequire: true}
	router := newRevocationRouter(hs)

	body := validCellWideEvent(func(e *revocationEvent) {
		e.Scope = "qurl"
		e.ScopeKey = "qurl:deadbeef" // MUST remain prefixed on the wire to the AC
		e.RevocationEpoch = 42
		e.EventID = "evt_shape"
	})
	req := signedRevocationRequest(t, signer, body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	got := drainSend(s)
	if len(got) != 1 {
		t.Fatalf("sent %d msgs, want 1", len(got))
	}
	md := got[0]

	// Transport envelope.
	if md.HeaderType != core.NHP_REV {
		t.Errorf("HeaderType=%d, want NHP_REV(%d)", md.HeaderType, core.NHP_REV)
	}
	if md.CipherScheme != conn.ACCipherScheme {
		t.Errorf("CipherScheme=%d, want %d (per-AC)", md.CipherScheme, conn.ACCipherScheme)
	}
	if md.ConnData != conn.ConnData {
		t.Error("ConnData is not the AC's connection (per-AC encryption target)")
	}
	if string(md.PeerPk) != string(conn.ACPeer.PublicKey()) {
		t.Error("PeerPk is not the AC's public key")
	}
	if !md.Compress {
		t.Error("Compress=false, want true (mirrors NHP_ARD drain)")
	}
	if md.ResponseMsgCh != nil {
		t.Error("ResponseMsgCh set, want nil (fire-and-forget)")
	}

	// Payload: field-copied ACRevocationMsg with scope_key still PREFIXED.
	var revMsg common.ACRevocationMsg
	if err := json.Unmarshal(md.Message, &revMsg); err != nil {
		t.Fatalf("decode ACRevocationMsg: %v", err)
	}
	if revMsg.Scope != "qurl" {
		t.Errorf("Scope=%q, want qurl", revMsg.Scope)
	}
	if revMsg.ScopeKey != "qurl:deadbeef" {
		t.Errorf("ScopeKey=%q, want the VERBATIM prefixed key 'qurl:deadbeef' (server must NOT strip)", revMsg.ScopeKey)
	}
	if revMsg.RevocationEpoch != 42 {
		t.Errorf("RevocationEpoch=%d, want 42", revMsg.RevocationEpoch)
	}
	if revMsg.EventId != "evt_shape" {
		t.Errorf("EventId=%q, want evt_shape", revMsg.EventId)
	}
}

// --- route path anchor -----------------------------------------------------

// TestInternalRevocation_RoutePathIsSigningAnchor pins the exact request path
// the handler is mounted at. That path ("/nhp/internal/revocation") is the
// cross-repo HMAC signing anchor: internalauth signs over method+path+body, so
// a drift here (a typo, a doubled slash, a renamed segment) versus what
// qurl-service's NHP Sink signs is a SILENT 401, not a routing 404. The
// assertion is that a request signed against this literal path resolves to this
// handler and is accepted (not 404, not 401) — i.e. the production route string
// and the signed path agree.
func TestInternalRevocation_RoutePathIsSigningAnchor(t *testing.T) {
	signer := newRevocationSigner(t)
	s := newRevocationTestServer(t, 16)
	hs := &HttpServer{udpServer: s, internalAuthSigner: signer, internalAuthRequire: true}

	// Register exactly as production does (httpserver.go initRouter):
	// group "/nhp/internal" + POST "/revocation".
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Group("/nhp/internal").POST("/revocation", hs.handleInternalRevocation)

	const wantPath = "/nhp/internal/revocation"
	found := false
	for _, r := range router.Routes() {
		if r.Method == http.MethodPost && r.Path == wantPath {
			found = true
		}
	}
	if !found {
		t.Fatalf("no POST route at %q; the cross-repo HMAC signing anchor drifted", wantPath)
	}

	// And prove the signed-path round-trip: signing against wantPath reaches the
	// handler and is accepted (cell-wide, no ACs → 200 no-op), not 401/404.
	req := signedRevocationRequest(t, signer, validCellWideEvent(nil))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("signed request to %q got %d (%s); want 200 — path/signing anchor mismatch",
			wantPath, rec.Code, rec.Body.String())
	}
}

// --- server unavailable ----------------------------------------------------

func TestInternalRevocation_NilUdpServer503(t *testing.T) {
	signer := newRevocationSigner(t)
	hs := &HttpServer{udpServer: nil, internalAuthSigner: signer, internalAuthRequire: true}
	router := newRevocationRouter(hs)

	req := signedRevocationRequest(t, signer, validCellWideEvent(nil))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s, want 503 (nil udpServer)", rec.Code, rec.Body.String())
	}
}

// TestRevocationWireScopes_SupersetOfAckable pins the structural relationship
// between the two server-side scope sets now that ackability is sourced from the
// shared endpoints/internal/revocationscope package: every scope the AC acks
// (revocationscope.All) MUST also be a scope the server accepts on the wire
// (revocationWireScopes) — the server cannot proof-track a scope it would reject
// at the door. It also pins that "cell" is accepted-on-wire but NOT ackable (the
// exact #2793 split). The AC↔server ackability lockstep itself is now drift-proof
// by construction (both sides call revocationscope.Contains), so it needs no
// mirror test here; this only guards the accept ⊇ ackable superset invariant.
func TestRevocationWireScopes_SupersetOfAckable(t *testing.T) {
	for _, s := range revocationscope.All() {
		if _, ok := revocationWireScopes[s]; !ok {
			t.Errorf("ackable scope %q is not accepted in revocationWireScopes (accept set must be a superset of ackable)", s)
		}
	}
	// "cell" is the load-bearing split: accepted on the wire and fanned out, but
	// NOT ackable (the AC drops it), so the server must not proof-track it.
	if _, ok := revocationWireScopes["cell"]; !ok {
		t.Error(`revocationWireScopes must accept "cell" (the server fans it out cell-wide)`)
	}
	if revocationscope.Contains("cell") {
		t.Error(`revocationscope must NOT mark "cell" ackable (the AC drops it without acking — #2793)`)
	}
}
