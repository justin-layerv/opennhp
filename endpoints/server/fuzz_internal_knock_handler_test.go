package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	// gin.TestMode is the same mode the per-test SetMode calls scattered
	// through this package use (httpstorage_test.go, requestid_test.go);
	// setting it once in init keeps fuzz iterations from depending on
	// which other test ran first.
	gin.SetMode(gin.TestMode)
}

// FuzzHandleInternalKnockBypass drives the handler with mutated
// (remoteAddr, X-Forwarded-For, body) triples and asserts the gate
// contract: a non-private TCP source must receive 403 regardless of
// header content.
//
// Private-source inputs short-circuit before ServeHTTP so this fence stays
// focused on the non-private path, which is the only branch the gate contract
// speaks to. The terminal direct-admission handler itself is fail-closed.
// Minimal well-formed body shared by seeds and the canary — empty request +
// resource objects. Keeps the seed table scannable and makes diffs on new
// seeds small.
const emptyKnockBody = `{"request":{},"resource":{}}`

func FuzzHandleInternalKnockBypass(f *testing.F) {
	r := newInternalKnockRouter()

	// Only public-source seeds reach ServeHTTP; private sources short-
	// circuit before the handler runs (see the body of f.Fuzz). Private
	// seeds still feed the fuzzer's mutation pool — a single bit-flip on
	// "10.0.0.1" can produce a public address the assertion evaluates.
	f.Add("8.8.8.8:12345", "", emptyKnockBody)
	f.Add("8.8.8.8:12345", "10.0.0.1", emptyKnockBody) // attacker XFF ignored under SetTrustedProxies(nil); #1170 tracks XFF-walk coverage
	f.Add("10.0.0.1:12345", "", emptyKnockBody)
	f.Add("10.0.0.1:12345", "8.8.8.8", emptyKnockBody)
	f.Add("[::1]:12345", "", emptyKnockBody)
	f.Add("[2001:db8::1]:12345", "", emptyKnockBody)
	// v4-in-v6 canonicalization: stdlib net.IP.IsPrivate() and IsLoopback()
	// canonicalize via To4() before classifying, so these seeds correctly
	// route to the v4 attacker-public / v4 private cases.
	f.Add("[::ffff:8.8.8.8]:12345", "", emptyKnockBody)
	f.Add("[::ffff:10.0.0.1]:12345", "", emptyKnockBody)
	// Zone-scoped v6: net.ParseIP rejects zone IDs (nil), so isPrivateIP
	// returns false. Asserted as public; also fodder for mutation around
	// the rarely-tested zone-ID parsing path.
	f.Add("[fe80::1%eth0]:1234", "", emptyKnockBody)
	// Empty RemoteAddr → httptest default 192.0.2.1 (TEST-NET-1, public).
	f.Add("", "10.0.0.1", emptyKnockBody)

	f.Fuzz(func(t *testing.T, remoteAddr, xff, body string) {
		// Skip private-source inputs before ServeHTTP — the gate's contract
		// only fences the non-private path.
		// Check before the size cap so len() doesn't fire on inputs we'd
		// drop anyway.
		if isRemoteAddrPrivate(remoteAddr) {
			return
		}
		if len(body) > 32*1024 {
			return
		}

		req := httptest.NewRequest(http.MethodPost, "/nhp/internal/knock", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if remoteAddr != "" {
			req.RemoteAddr = remoteAddr
		}
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}

		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		// Handler returns 403 immediately for non-private sources (before
		// reading the body), so 403 is the only legitimate response on
		// this asserted path. Anything else — 200 (bypass), 400 (gate
		// reordered behind body parse), 5xx (panic-recovered, future
		// middleware) — is a regression.
		if rec.Code != http.StatusForbidden {
			t.Fatalf("gate weakened: non-private remote %q got status=%d, want %d (xff=%q, body=%q)",
				remoteAddr, rec.Code, http.StatusForbidden, xff, body)
		}
	})
}

// TestInternalKnockRejectsPublicSource is a deterministic canary that the
// fuzzer's bypass assertion is doing real work. If a future change moves
// the gate upstream of isPrivateIP without updating the helper (a class of
// silent-weakening the fuzz docstring warns about), this test still fails
// loudly because it asserts directly on known attacker-public sources
// across both v4 and v6, and across well-formed and malformed bodies.
//
// The malformed-body case fences gate-vs-body-parse ordering: the gate
// must fire BEFORE ShouldBindJSON, so a public source with garbage JSON
// must still get 403 (not 400).
func TestInternalKnockRejectsPublicSource(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		body       string
	}{
		{"v4 public", "8.8.8.8:12345", emptyKnockBody},
		{"v4 public alt", "1.1.1.1:443", emptyKnockBody},
		{"v6 public", "[2001:db8::1]:12345", emptyKnockBody},
		{"v4-in-v6 public", "[::ffff:8.8.8.8]:12345", emptyKnockBody},
		{"public + malformed body", "8.8.8.8:12345", `{not json`},
	}
	r := newInternalKnockRouter()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/nhp/internal/knock",
				strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = tc.remoteAddr
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("gate weakened: public source %q got status=%d, want %d", tc.remoteAddr, rec.Code, http.StatusForbidden)
			}
		})
	}
}

// newInternalKnockRouter builds the minimal gin engine + zero-value
// HttpServer used by both FuzzHandleInternalKnockBypass and the canary,
// so the two test sites can't drift in setup. The router intentionally
// uses SetTrustedProxies(nil) to disable Gin's XFF walk — see #1170 for
// the trusted-CIDR coverage follow-up. If a future edit adds a trusted
// CIDR here, isRemoteAddrPrivate's contract no longer matches Gin's
// ClientIP() and the fuzz assertion silently weakens; keep this helper
// pinned to the safe production default.
func newInternalKnockRouter() *gin.Engine {
	r := gin.New()
	// SetTrustedProxies(nil) is documented as nil-safe in Gin ≥1.9.
	// Panic loudly if a future Gin version changes that — the fuzz
	// assertion's correctness depends on this call succeeding so that
	// ClientIP() returns RemoteAddr's host portion verbatim (no XFF walk).
	if err := r.SetTrustedProxies(nil); err != nil {
		panic("SetTrustedProxies(nil) errored — Gin version regression: " + err.Error())
	}
	// Deliberately zero-valued: handleInternalKnock returns 403 before
	// touching any HttpServer field, so the gate-contract tests don't
	// need a fully wired server. A non-private request that slipped
	// past the gate would nil-panic inside acConnectionMapMutex.RLock —
	// surfacing the regression loudly.
	hs := &HttpServer{}
	r.POST("/nhp/internal/knock", hs.handleInternalKnock)
	return r
}

// isRemoteAddrPrivate splits "ip:port" (or "[v6]:port") and delegates to
// the production isPrivateIP helper so the fuzz assertion tracks the
// handler's exact RFC-1918 / loopback definition. Empty or unparseable
// addresses are treated as "not private" so the bypass assertion is not
// skipped on malformed input.
//
// This helper assumes Gin ≥1.9 semantics for RemoteIP(): a SplitHostPort
// failure yields "" (treated as not-private here). Older Gin fell back to
// raw RemoteAddr — under that older behavior, a host-without-port input
// like "10.0.0.1" would be private to production but not to this helper,
// admitting a fuzz body that nil-panics in the zero-value HttpServer.
// If the project ever downgrades Gin below 1.9, revisit this contract.
//
// This helper does NOT mirror Gin's ClientIP() resolution logic; the test
// keeps SetTrustedProxies(nil), under which ClientIP returns RemoteAddr's
// host portion and isPrivateIP receives the same value this helper checks.
// If the production gate moves upstream of isPrivateIP (e.g., to a header
// read), this helper falls out of sync and the fuzz assertion silently
// weakens — TestInternalKnockRejectsPublicSource above is the loud canary.
func isRemoteAddrPrivate(remoteAddr string) bool {
	// Match the production handler's pre-processing at
	// httpserver.go:1366-1372: SplitHostPort first, but FALL THROUGH
	// to the raw string on error rather than short-circuiting to
	// "not private." Without the fallthrough, a fuzz-generated
	// input like "10.0.0.0" (no port) would be treated as not-
	// private here but as private by the production isPrivateIP
	// check — driving the fuzzer to assert 403 against a real
	// response that correctly continues past the gate to body
	// parse (returning 400 on invalid JSON).
	//
	// The whitespace trim is kept because Gin's RemoteIP() also
	// trims — matching Gin means the fuzzer's skip aligns with
	// the gate observed through Gin, not with the raw
	// ctx.Request.RemoteAddr at httpserver.go:1366-1372 (which
	// does NOT trim). Real net/http never puts whitespace in
	// RemoteAddr, so the divergence is untriggerable from real
	// traffic; the trim just removes a false-negative for
	// fuzz-generated whitespace inputs the handler would
	// coincidentally accept.
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr // match production fallthrough
	}
	return isPrivateIP(host)
}
