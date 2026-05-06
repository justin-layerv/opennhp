//go:build smoke

package smoke

// Tier 2: NHP server plugin dispatcher surface.
//
// Capability: /plugins/:aspid routes requests to registered static
// plugin handlers (today: only "qurl"). This file fences:
//   - the unknown-aspid path returns 404 (issue #1017)
//   - the publicly-visible error surface — the access-denied page
//     that every no-token or bad-token request hits.
//
// Source of truth: endpoints/server/staticplugins/qurl/main.go and
// endpoints/server/httpserver.go's plugin route registration.
//
// Deferred to follow-up: /plugins/qurl with no token currently
// returns 403 WITHOUT a Cache-Control header. CDN-side error
// caching masks this today (x-cache: Error from cloudfront), but
// an explicit Cache-Control: no-cache is still the belt-and-
// suspenders posture the plan called for. Tracked in issue #1018.

import (
	"net/http"
	"strings"
	"testing"
)

// TestPlugins_UnknownASPIDReturns404 fences issue #1017: a request
// for /plugins/{unknown} must return 404, not 200. A 200 lets any
// downstream consumer that treats status_code == 200 as "succeeded"
// silently treat a missing plugin as success.
//
// Asserts on the dispatcher's JSON body (not just status) so a
// future regression where some upstream layer (NLB, ALB rule, an
// errant gin middleware) starts answering 404 with a different
// body would still fire the test.
//
// GET-only is sufficient: gin registers one closure for both GET
// and POST on /plugins/:aspid (httpserver.go:664-665) and the
// no-handler branch is method-agnostic, so a method-split would
// be a separate regression class with its own fence.
func TestPlugins_UnknownASPIDReturns404(t *testing.T) {
	resp, body := doGetNoRedirect(t, testConfig.NHPServerBaseURL, "/plugins/nonexistent", nil)
	assertStatusCode(t, resp, http.StatusNotFound)

	if !strings.Contains(string(body), `"errMsg"`) {
		// Surface CDN/proxy headers so the failure points at the right
		// layer when an upstream (NLB rule, errant middleware, future
		// CDN) — not the NHP dispatcher — is the one answering 404.
		t.Logf("x-cache=%q via=%q server=%q",
			resp.Header.Get("X-Cache"),
			resp.Header.Get("Via"),
			resp.Header.Get("Server"))
		t.Fatalf("404 body is not the dispatcher's JSON error shape (missing errMsg key)\nbody: %s",
			truncate(body, 200))
	}
}

// TestPlugins_NoTokenReturnsBranded403 fences the
// no-token-or-bad-token path for the qurl plugin. A GET to
// /plugins/qurl with no token (or an invalid one) must return 403
// with the branded "Access Link Invalid" HTML marker — not a 5xx,
// not a whitelabel error, and not the resolved content.
//
// This overlaps slightly with TestResolve_UnknownTokenReturns403
// and TestResolve_MalformedTokenReturns403 in 10_resolve_test.go.
// The deliberate overlap is: those tests fence the behavior from
// the resolve handler's perspective (what happens when a token
// fails validation); this test fences the behavior from the
// plugin dispatcher's perspective (what happens when the handler
// returns an error). A regression in either path fails a test.
func TestPlugins_NoTokenReturnsBranded403(t *testing.T) {
	resp, body := doGetNoRedirect(t, testConfig.NHPServerBaseURL, "/plugins/qurl", nil)
	assertStatusCode(t, resp, http.StatusForbidden)

	// content-type must be HTML — the page is meant to be read by
	// humans who land on a broken link, not parsed by a machine.
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html* (the access-denied page must render)", ct)
	}

	marker := accessLinkInvalidMarker
	if !strings.Contains(string(body), marker) {
		t.Fatalf("403 body does not contain expected marker %q\nbody: %s",
			marker, truncate(body, 400))
	}
}
