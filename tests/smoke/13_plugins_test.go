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
	// The /plugins dispatcher lives on the nhp-server HTTP surface at
	// NHPServerBaseURL, which the JS-agent + relay topology takes private.
	// Runs where that surface is live (prod + localhost), skips in JS-agent envs.
	skipIfResolveEndpointDisabled(t)
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
	// The branded 403 page is served only when a qURL resource/plugin is
	// provisioned for the host. The self-contained local stack has no qURL
	// resource (qURL provisioning is a qurl-service concern), so /plugins/qurl
	// returns a plain 404 there — skip on local; this fence runs on remote.
	requireRemote(t)
	skipIfResolveEndpointDisabled(t) // branded-403 page is served by the legacy resolve plugin; gone under the JS-agent topology
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

// TestPlugins_OversizedPOSTReturns413 fences the server-side body
// cap on /plugins/:aspid added in #1841. A POST body larger than the
// cap (16 KiB) must return 413 — with a body identifying it as the
// server's 413, not an upstream layer's — before any downstream
// parser (e.g. the qurl plugin's strconv.ParseFloat on browser-timing
// fields) sees the bytes. This protects against the unbounded-form
// DoS path that PR #1824's review identified.
//
// Probes NHPServerOriginURL (NLB-direct), not NHPServerBaseURL (via
// CloudFront), because the production CF path runs through a WAFv2
// web ACL with AWSManagedRulesCommonRuleSet (terraform/main.tf::
// aws_wafv2_web_acl.qurl_resolve), whose SizeRestrictions_BODY rule
// blocks POST bodies > 8 KiB at the edge — well under the server's
// 16 KiB cap. Oversize POSTs are structurally unreachable to the
// server through CloudFront, so this test would only ever observe
// WAF's 403 ("Request blocked" / x-cache: Error from cloudfront)
// on that path. WAF + cap is layered defense; this test fences the
// cap layer. Edge-layer enforcement is owned by Terraform and TF
// plan-time review.
//
// Asserts status AND body marker: a regression where some other
// middleware (or upstream proxy) starts answering with a generic 413
// still fails the test.
//
// 64 KiB is comfortably over the 16 KiB cap and small enough not to
// stress the test transport.
func TestPlugins_OversizedPOSTReturns413(t *testing.T) {
	// The /plugins body cap lives on the resolve-origin NLB surface, which
	// the JS-agent + relay topology tears down (along with the resolve-origin
	// Route53 record). Skip there; runs where the surface is live (prod).
	skipIfResolveEndpointDisabled(t)
	if testConfig.NHPServerOriginURL == "" {
		// Sandbox and prod are KNOWN to have a separate
		// resolve-origin.<env> Route53 record (see
		// terraform/main.tf::aws_route53_record.qurl_link_resolve_origin
		// and tests/smoke/dns.go::deriveEndpoints). A missing origin URL
		// in either of those envs means the wiring regressed — fail
		// loudly, don't silently turn off the cap fence.
		switch testConfig.Environment {
		case "prod":
			// sandbox is handled by skipIfResolveEndpointDisabled above —
			// under the JS-agent topology it legitimately has no
			// resolve-origin record. prod still must, so fail loudly there.
			t.Fatalf("NHPServerOriginURL is empty for env %q, which is expected to have a separate resolve-origin record (see tests/smoke/dns.go::deriveEndpoints + terraform/main.tf::aws_route53_record.qurl_link_resolve_origin). Either the record is missing or the smoke wiring regressed; this fence cannot be silently skipped in a known env.", testConfig.Environment)
		default:
			t.Skipf("skipped: NHPServerOriginURL not set for env %q (no separate origin record)", testConfig.Environment)
		}
	}

	oversized := strings.Repeat("a", 64*1024) // 64 KiB > 16 KiB cap
	body := "token=" + oversized

	resp, respBody := doPostFormNoRedirect(t, testConfig.NHPServerOriginURL,
		"/plugins/qurl", body, nil)
	assertStatusCode(t, resp, http.StatusRequestEntityTooLarge)

	const marker = "body too large"
	if !strings.Contains(string(respBody), marker) {
		t.Fatalf("413 body does not contain server marker %q (some other layer may be answering 413)\n  body: %s",
			marker, truncate(respBody, 200))
	}
}
