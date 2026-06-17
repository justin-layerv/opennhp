package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/core"
)

// The relay's only cross-origin caller is the qURL knock portal (qurl.link). The
// resource domains (*.qurl.site, custom whitelabel) are the data plane and
// connect directly through the AC — never the relay — so they are NOT allowed.
// These fence: knock origin echoed (never "*"), others denied (no header) but
// still Vary'd, OPTIONS answered before the serverId lookup, headers on all
// paths, and disabled-by-default.

const testKnockOrigin = "https://qurl.link"

// TestNewCORSAllowlist fences the multi-origin parse contract the config/var/
// terraform comments promise (today the derivation feeds one origin, but the
// daemon accepts a comma-separated list): split, trim, skip empties, empty-disables.
func TestNewCORSAllowlist(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string // allowed
		deny []string // denied
	}{
		{"single", "https://qurl.link", []string{"https://qurl.link"}, []string{"https://evil.com", ""}},
		{"multi with whitespace", " https://qurl.link , https://staging.layerv.ai ", []string{"https://qurl.link", "https://staging.layerv.ai"}, []string{"https://evil.com"}},
		{"empty elements skipped", "https://a.com,,  ,https://b.com,", []string{"https://a.com", "https://b.com"}, []string{""}},
		{"empty disables all", "", nil, []string{"https://qurl.link", ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newCORSAllowlist(tc.raw)
			for _, o := range tc.want {
				if !a.allowed(o) {
					t.Errorf("allowed(%q) = false, want true", o)
				}
			}
			for _, o := range tc.deny {
				if a.allowed(o) {
					t.Errorf("allowed(%q) = true, want false", o)
				}
			}
		})
	}
}

func corsTestRelay(t *testing.T) *RelayServer {
	t.Helper()
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr)
	rs.cors = newCORSAllowlist(testKnockOrigin)
	return rs
}

func assertCORSAllowed(t *testing.T, h http.Header, origin string) {
	t.Helper()
	if got := h.Get("Access-Control-Allow-Origin"); got != origin {
		t.Errorf("Allow-Origin = %q, want the echoed origin %q (never *)", got, origin)
	}
	if got := h.Get("Access-Control-Allow-Methods"); got != "POST, OPTIONS" {
		t.Errorf("Allow-Methods = %q", got)
	}
	if got := h.Get("Access-Control-Allow-Headers"); got != "Content-Type" {
		t.Errorf("Allow-Headers = %q", got)
	}
	if got := h.Get("Access-Control-Max-Age"); got != "7200" {
		t.Errorf("Max-Age = %q, want 7200", got)
	}
	if got := h.Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("Allow-Credentials = %q, want unset", got)
	}
	if got := h.Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want Origin", got)
	}
}

func TestHandleRelay_CORSPreflight_KnockOriginEchoed(t *testing.T) {
	rs := corsTestRelay(t)
	req := httptest.NewRequest(http.MethodOptions, "/relay/anything", nil)
	req.Header.Set("Origin", testKnockOrigin)
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	assertCORSAllowed(t, w.Header(), testKnockOrigin)
}

func TestHandleRelay_CORSPreflight_ResourceAndForeignOriginsDenied(t *testing.T) {
	// Resource/whitelabel/unrelated origins are not relay callers: 204 with NO
	// Access-Control-Allow-Origin (browser blocks the follow-up POST), but still
	// Vary: Origin so a shared cache can't cross them.
	rs := corsTestRelay(t)
	for _, origin := range []string{
		"https://app-7.qurl.site",     // resource (data plane, direct-connect)
		"https://stats.mycompany.com", // custom whitelabel resource
		"https://evil.com",            // unrelated
	} {
		req := httptest.NewRequest(http.MethodOptions, "/relay/anything", nil)
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		rs.handleRelay(w, req)
		if w.Code != http.StatusNoContent {
			t.Errorf("origin %q: status = %d, want 204", origin, w.Code)
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("origin %q: Allow-Origin = %q, want unset (not a relay caller)", origin, got)
		}
		if got := w.Header().Get("Vary"); got != "Origin" {
			t.Errorf("origin %q: Vary = %q, want Origin even when denied", origin, got)
		}
	}
}

func TestHandleRelay_CORSPreflight_UnknownServerIDStill204(t *testing.T) {
	// A preflight is about method/headers, not resource existence — answered
	// before the serverId lookup, so an unknown serverId must not 404 it.
	rs := corsTestRelay(t)
	req := httptest.NewRequest(http.MethodOptions, "/relay/does-not-exist", nil)
	req.Header.Set("Origin", testKnockOrigin)
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204 (preflight precedes serverId lookup)", w.Code)
	}
	assertCORSAllowed(t, w.Header(), testKnockOrigin)
}

func TestHandleRelay_CORSHeaderOnPOSTErrorPath(t *testing.T) {
	// The browser must read the failure status, so the CORS header rides POST error
	// responses too (set before the serverId lookup). A POST to an unknown serverId
	// 404s fast (no forward/hang) and must still echo the allowed origin.
	rs := corsTestRelay(t)
	req := httptest.NewRequest(http.MethodPost, "/relay/does-not-exist", nil)
	req.Header.Set("Origin", testKnockOrigin)
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != testKnockOrigin {
		t.Errorf("Allow-Origin = %q, want %q on the error response too", got, testKnockOrigin)
	}
}

func TestHandleRelay_CORSHeaderOnMethodNotAllowed(t *testing.T) {
	// Headers are set before the method check, so a disallowed method (GET) carries
	// them alongside the 405 — locks in header-before-method-gate.
	rs := corsTestRelay(t)
	req := httptest.NewRequest(http.MethodGet, "/relay/anything", nil)
	req.Header.Set("Origin", testKnockOrigin)
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != testKnockOrigin {
		t.Errorf("Allow-Origin = %q, want %q on the 405 response too", got, testKnockOrigin)
	}
}

func TestHandleRelay_CORSDisabledByDefault(t *testing.T) {
	// An empty allowlist (default) disables CORS: even the knock origin gets no
	// Access-Control-Allow-Origin, so nothing leaks until origins are configured.
	serverPub := devicePubKey(t, core.NHP_SERVER, keyBytes(0x40))
	rs := newTestRelay(t, serverPub, 62206, SourceAddrModeRemoteAddr) // no CORSAllowedOrigins
	req := httptest.NewRequest(http.MethodOptions, "/relay/anything", nil)
	req.Header.Set("Origin", testKnockOrigin)
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q, want unset when no origins configured (dark-safe)", got)
	}
	// Vary: Origin is still emitted unconditionally even with CORS disabled — the
	// caching invariant doesn't depend on the allowlist being populated.
	if got := w.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want Origin even when CORS is disabled", got)
	}
}

func TestHandleRelay_CORSPreflight_NoOriginHeader(t *testing.T) {
	// A non-CORS / non-browser OPTIONS (no Origin header) still 204s but leaks no
	// CORS headers — allowed("") is false. Vary: Origin is still set.
	rs := corsTestRelay(t)
	req := httptest.NewRequest(http.MethodOptions, "/relay/anything", nil)
	w := httptest.NewRecorder()
	rs.handleRelay(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q, want unset when no Origin header", got)
	}
	if got := w.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want Origin", got)
	}
}
