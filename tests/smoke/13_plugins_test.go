//go:build smoke

package smoke

// Tier 2: NHP server plugin dispatcher surface.
//
// Capability: /plugins/:aspid routes requests to registered static
// plugin handlers (today: only "qurl"). This file fences the
// publicly-visible error surface — the access-denied page that
// every no-token or bad-token request hits.
//
// Source of truth: endpoints/server/staticplugins/qurl/main.go and
// endpoints/server/httpserver.go's plugin route registration.
//
// Notes on coverage not in PR2:
//
//  1. Unknown aspid (/plugins/nonexistent) currently returns HTTP
//     200 with {"errMsg":"no auth handler provided"} instead of
//     404. This is a regression class worth a dedicated fence —
//     filed as a follow-up. Not testable here until the server
//     returns the right status code.
//
//  2. /plugins/qurl with no token currently returns 403 WITHOUT
//     a Cache-Control header. CDN-side error caching masks this
//     today (x-cache: Error from cloudfront), but an explicit
//     Cache-Control: no-cache is still the belt-and-suspenders
//     posture the plan called for. Filed as a follow-up.
//
// The remaining coverage in this file is the access-denied page
// assertion itself: the 403 HTML is branded and should keep its
// marker across releases so a regression to a generic 500 or a
// whitelabel error page would fire the test.

import (
	"net/http"
	"strings"
	"testing"
)

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
