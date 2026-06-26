//go:build smoke

package smoke

// Tier 2: QURL resolve REJECTION path — the NHP server's static qurl
// plugin (registered at /plugins/qurl) maps a missing / unknown /
// malformed access token to a branded 403 "Access Link Invalid" page.
//
// The happy-path resolve tests (mint a real QURL via qurl-service +
// Auth0, assert the 302 → r_{id}.qurl.site redirect, cookies, and
// Accept-negotiation) were removed: qURL minting is a qurl-service
// concern, not nhp's (see tests/smoke/CLAUDE.md).
// TODO(qurl-service#1020): backfill the deleted /plugins/qurl resolve,
// qurl-router silent-drop, and knock-ready "lie detector" coverage in
// qurl-service so this gap can't quietly become permanent.
// What remains here is the rejection contract, which is pure NHP-handler
// behavior and needs no minted QURL — a bogus token is enough to reach
// the 403 path.
//
// These run remote-only (the deployed qurl plugin must be wired for the
// host) and skip on the local target via requireRemote.
//
// Source of truth: endpoints/server/staticplugins/qurl/main.go
// (the AuthWithHttp handler).

import (
	"net/http"
	"strings"
	"testing"
)

// accessLinkInvalidMarker is the branded HTML page title returned by the
// qurl plugin when an access token is missing, invalid, or expired. Used
// by both the resolve rejection tests here and the plugin dispatcher test
// (13_plugins_test.go) as the single source of truth for the marker.
const accessLinkInvalidMarker = "Access Link Invalid"

// TestResolve_UnknownTokenReturns403_POST fences the access-denied
// path via POST (preferred path) for a syntactically well-formed but
// nonexistent access token. Real access tokens are at_ + 22 chars of
// base62 (25 chars total). The bogus token below matches that
// length/shape so if the server has a length-precheck it still
// reaches the store-lookup path, where the lookup fails and the
// handler returns the branded 403.
func TestResolve_UnknownTokenReturns403_POST(t *testing.T) {
	requireRemote(t)                     // remote-only: qURL bad-token 403 needs a provisioned qURL resource (qurl-service).
	bogus := "at_nonexistentyyyyyyyyyyy" // at_ + 22 chars

	resp, body := doPostFormNoRedirect(t, testConfig.NHPServerBaseURL,
		"/plugins/qurl", "token="+bogus, nil)
	assertStatusCode(t, resp, http.StatusForbidden)

	marker := accessLinkInvalidMarker
	if !strings.Contains(string(body), marker) {
		t.Fatalf("403 body does not contain %q (body: %s)", marker, truncate(body, 400))
	}
}

// TestResolve_UnknownTokenReturns403_GET_BackwardCompat verifies the
// deprecated GET query parameter path still returns a proper 403 for
// unknown tokens (backward compatibility).
func TestResolve_UnknownTokenReturns403_GET_BackwardCompat(t *testing.T) {
	requireRemote(t)                     // remote-only: qURL bad-token 403 needs a provisioned qURL resource (qurl-service).
	bogus := "at_nonexistentyyyyyyyyyyy" // at_ + 22 chars

	resp, body := doGetNoRedirect(t, testConfig.NHPServerBaseURL,
		"/plugins/qurl?token="+bogus, nil)
	assertStatusCode(t, resp, http.StatusForbidden)

	marker := accessLinkInvalidMarker
	if !strings.Contains(string(body), marker) {
		t.Fatalf("403 body does not contain %q (body: %s)", marker, truncate(body, 400))
	}
}

// TestResolve_MalformedTokenReturns403 fences the error path for
// tokens that don't even parse as access tokens (no at_ prefix).
// The response must be 403 — not 500, not 400, not a panic.
func TestResolve_MalformedTokenReturns403(t *testing.T) {
	requireRemote(t) // remote-only: qURL bad-token 403 needs a provisioned qURL resource (qurl-service).
	garbage := "definitely-not-a-token"

	resp, _ := doPostFormNoRedirect(t, testConfig.NHPServerBaseURL,
		"/plugins/qurl", "token="+garbage, nil)
	assertStatusCode(t, resp, http.StatusForbidden)
}
