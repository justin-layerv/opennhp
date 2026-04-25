//go:build smoke

package smoke

// Tier 2: Accept-header negotiation on /plugins/qurl.
//
// Capability: when the client sends Accept: application/json, the qurl
// plugin returns a 200 + JSON body containing `redirect_url` instead of
// the legacy 302 + Location. The qurl.link SPA depends on this so it can
// hold the page and render progressive UI ("Verifying access token…",
// "Opening firewall…", "Redirecting to <host>…") instead of the browser
// blanking the tab during a cross-origin POST navigation.
//
// Source of truth: endpoints/server/staticplugins/qurl/main.go's wantsJSON
// branch. Capability added in PR #1321 as a precondition for the qurl.link
// SPA rewrite that closes layervai/website#242.
//
// This file fences both halves of the contract:
//   - Accept: application/json → 200 + {"redirect_url": "..."}
//   - Accept absent / wildcard → 302 + Location (legacy form-POST path)
// A regression in either branch breaks one of the two consumers.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// doPostUntilStatus POSTs to fullURL with the given headers, retrying on
// transport errors and 5xx responses within the same budget+cap envelope
// the resolve helpers use. Body is built per attempt via bodyFn so callers
// can re-mint tokens or rebuild a request body that gets consumed on each
// Do call. Fails fast on any other status (4xx mismatch, 3xx that wasn't
// expected) so an access regression isn't masked as "exhausted budget."
//
// Used by smoke tests that don't fit postResolveWithAccept's mint-per-
// attempt shape — e.g., bogus-token error-path tests where the body is
// constant, or CORS-header tests that need the same retry posture but
// custom request setup. Lives in this _test.go file because it
// references constants (resolveRetryBudget, resolvePerAttemptTimeout,
// postFlipPollInterval) defined in other _test.go files in this package.
func doPostUntilStatus(ctx context.Context, t *testing.T, fullURL string, bodyFn func() io.Reader, headers map[string]string, wantStatus int) (*http.Response, []byte) {
	t.Helper()

	deadline := time.Now().Add(resolveRetryBudget)
	var lastErr error
	for attempt := 1; ; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, resolvePerAttemptTimeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, fullURL, bodyFn())
		if err != nil {
			cancel()
			t.Fatalf("doPostUntilStatus: build request: %v", err)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, doErr := testConfig.NoRedirectClient.Do(req)
		if doErr != nil {
			cancel()
			lastErr = fmt.Errorf("attempt %d: transport error: %w", attempt, doErr)
			t.Logf("doPostUntilStatus: %v", lastErr)
		} else {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			cancel()
			if readErr != nil {
				t.Fatalf("doPostUntilStatus: read body on attempt %d: %v", attempt, readErr)
			}
			switch {
			case resp.StatusCode == wantStatus:
				if attempt > 1 {
					t.Logf("doPostUntilStatus: succeeded on attempt %d", attempt)
				}
				return resp, body
			case resp.StatusCode >= 500:
				lastErr = fmt.Errorf("attempt %d: 5xx status %d (retryable)", attempt, resp.StatusCode)
				t.Logf("doPostUntilStatus: %v", lastErr)
			case wantStatus == http.StatusOK && resp.StatusCode == http.StatusFound &&
				strings.EqualFold(headers["Accept"], "application/json"):
				// Blue/green deploy window: a request that asks for JSON
				// can land on a stale instance still running the legacy
				// code that returns 302 to every Accept. Retry rather
				// than fail-fast — the new instance will return JSON.
				lastErr = fmt.Errorf("attempt %d: stale-instance 302 to JSON request (retryable during deploy)", attempt)
				t.Logf("doPostUntilStatus: %v", lastErr)
			default:
				t.Fatalf("doPostUntilStatus: unexpected status %d on attempt %d (want %d)\nbody: %s",
					resp.StatusCode, attempt, wantStatus, truncate(body, 200))
			}
		}

		if attempt >= maxResolveAttempts {
			t.Fatalf("doPostUntilStatus: exhausted %d attempts: %v", maxResolveAttempts, lastErr)
		}
		if time.Now().After(deadline) {
			t.Fatalf("doPostUntilStatus: exhausted %s budget after %d attempts: %v", resolveRetryBudget, attempt, lastErr)
		}
		time.Sleep(postFlipPollInterval)
	}
}

// redirectURLField mirrors the same-named const in
// endpoints/server/staticplugins/qurl/main.go. Both modules must rename
// in lockstep — the smoke module can't import the plugin package. Same
// name on both sides shrinks #1325's CI grep guard from a name-pair
// check to a literal grep for `redirectURLField`.
const redirectURLField = "redirect_url"

// resolveResp bundles a drained HTTP response with its body so cookies,
// headers, and JSON body are all addressable from one return value.
type resolveResp struct {
	*http.Response
	body []byte
}

// TestResolve_AcceptJSON_ReturnsJSONBody fences the JSON branch of the
// resolve handler. The qurl.link SPA sets this header so it can stay
// on the page during the resolve and render progressive UI before
// navigating via window.location.replace.
func TestResolve_AcceptJSON_ReturnsJSONBody(t *testing.T) {
	ctx := context.Background()
	resp := postResolveWithAccept(ctx, t, "application/json", http.StatusOK)

	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("Accept: application/json should not return Location header, got %q", loc)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	body := map[string]any{}
	if err := json.Unmarshal(resp.body, &body); err != nil {
		t.Fatalf("decode JSON body: %v\nbody: %s", err, truncate(resp.body, 400))
	}
	redirectURL, _ := body[redirectURLField].(string)
	if redirectURL == "" {
		t.Fatalf("response missing %s field", redirectURLField)
	}
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("%s %q is not a valid URL: %v", redirectURLField, redirectURL, err)
	}
	if !strings.HasSuffix(parsed.Host, testConfig.QURLSiteDomain) {
		t.Errorf("%s host %q does not suffix with %q", redirectURLField, parsed.Host, testConfig.QURLSiteDomain)
	}

	// Fence Vary: Accept on the deployed JSON success path. Unit tests
	// catch in-process clobbering; this catches an intermediary
	// (CloudFront, Traefik, NLB) stripping the header in prod, which is
	// exactly what Vary is defending against.
	if got := resp.Header.Get("Vary"); !strings.Contains(got, "Accept") {
		t.Errorf("Vary on JSON success path = %q, want it to contain Accept", got)
	}

	// Cookies must still be set on the JSON response — the SPA performs
	// window.location.replace(redirect_url) and the redirected GET to
	// r_{id}.qurl.site.* needs the nhp_token cookie present.
	var foundNHPToken bool
	for _, c := range resp.Cookies() {
		if c.Name == nhpTokenCookie {
			foundNHPToken = true
			if c.Value == "" {
				t.Error("nhp_token cookie value is empty on JSON response")
			}
		}
	}
	if !foundNHPToken {
		t.Error("nhp_token cookie not set on JSON response — SPA-initiated redirect would land unauthenticated")
	}
}

// TestResolve_NoAcceptHeader_StaysOn302 fences the legacy branch:
// without Accept: application/json, the handler must return a 302 so
// existing form-POST callers (and stale cached qurl.link HTML) keep
// working during a deploy.
//
// Note: there's intentional overlap with TestResolve_ValidTokenReturns302ToQurlSite
// in 10_resolve_test.go. The flagship resolve test fences the happy-path
// capability; this one fences the negotiation contract specifically.
// If the flagship is ever pivoted to send Accept: application/json (e.g.,
// after the SPA rewrite is dogfooded), the legacy 302 path's regression
// protection will rest on this file alone — do not delete without
// re-homing the assertion.
func TestResolve_NoAcceptHeader_StaysOn302(t *testing.T) {
	ctx := context.Background()
	resp := postResolveWithAccept(ctx, t, "", http.StatusFound)

	if loc := resp.Header.Get("Location"); loc == "" {
		t.Error("302 response missing Location header")
	}
	// Same Vary fence as the JSON success path — the 302 branch must
	// also carry it so a cache can't later serve a stored 302 to a
	// fetch() caller asking for JSON.
	if got := resp.Header.Get("Vary"); !strings.Contains(got, "Accept") {
		t.Errorf("Vary on 302 path = %q, want it to contain Accept", got)
	}
}

// TestResolve_AcceptJSON_CORSCredentialsHeaders fences the load-bearing
// invariant the SPA rewrite depends on: when the qurl.link page calls
// `fetch(resolveURL, {credentials: 'include', headers: {Accept:
// 'application/json', Origin: ...}})`, the response must carry
// Access-Control-Allow-Credentials: true AND a non-wildcard
// Access-Control-Allow-Origin echoing the request's Origin. Browsers
// silently reject (and drop the cookie from) any cross-origin
// credentialed fetch where ACAO is "*" or absent. If this regresses
// in production, the SPA-side PR is the first thing that catches it —
// and by then the one-time access token has been consumed. Fence here
// to fail loud on a deployed-env regression instead.
//
// Uses the retry envelope (transport-error + 5xx retries within the
// 45s wall-clock budget and 5-attempt cap) so a blue/green flip
// doesn't flake this fence.
func TestResolve_AcceptJSON_CORSCredentialsHeaders(t *testing.T) {
	ctx := context.Background()

	// Pick the qurl.link origin per environment from testConfig so the
	// server's CORS allowlist (NHP_CORS_ALLOWED_ORIGINS in tfvars) matches
	// and echoes it back. Centralizing the mapping in dns.go's
	// derivedEndpoints means a future env (staging, prod-canary) is a
	// one-place edit.
	origin := testConfig.QURLLinkOrigin

	// Mint per attempt because each resolve consumes a single-use token.
	bodyFn := func() io.Reader {
		minted := mintSmokeQURL(ctx, t, "https://example.com")
		return strings.NewReader("token=" + url.QueryEscape(minted.AccessToken()))
	}
	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/x-www-form-urlencoded",
		"Origin":       origin,
	}
	resp, _ := doPostUntilStatus(ctx, t,
		testConfig.NHPServerBaseURL+"/plugins/qurl",
		bodyFn, headers, http.StatusOK)

	// Allow-Credentials must be the literal "true" — anything else (or
	// absent) prevents the browser from storing Set-Cookie on a
	// credentialed fetch.
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want %q (SPA fetch with credentials: 'include' would silently drop cookies)", got, "true")
	}
	// Allow-Origin must echo the request Origin exactly (not "*").
	// Wildcard + credentials is a CORS spec violation that browsers
	// reject; many servers silently downgrade to wildcard if Origin is
	// not allowlisted, which would also drop cookies.
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q (must echo request Origin, not wildcard)", got, origin)
	}
	// Expose-Headers must include Set-Cookie so the browser surfaces
	// the cookie to the credentialed fetch. A regression dropping it
	// would silently break the SPA cookie pickup while passing the
	// Allow-Credentials/Allow-Origin assertions above.
	if got := resp.Header.Get("Access-Control-Expose-Headers"); !strings.Contains(got, "Set-Cookie") {
		t.Errorf("Access-Control-Expose-Headers = %q, want it to contain Set-Cookie", got)
	}
}

// TestResolve_AcceptJSON_ErrorPathStaysHTML fences the contract the SPA
// must implement: even when the client requests JSON, error paths
// (token-invalid 403) keep their existing branded-HTML shape. The SPA
// branches on Content-Type so a future refactor wrapping the 403 in
// JSON would silently break the SPA's error rendering.
//
// Uses a syntactically valid but nonexistent token so the handler
// reaches token validation and emits the branded 403 — same shape as
// TestResolve_UnknownTokenReturns403_POST in 10_resolve_test.go but
// fences the Accept negotiation behavior on the error path. Routes
// through the retry envelope so a deploy-window 5xx doesn't flake
// the test.
func TestResolve_AcceptJSON_ErrorPathStaysHTML(t *testing.T) {
	ctx := context.Background()
	bogus := "at_nonexistentyyyyyyyyyyy" // at_ + 22 chars
	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/x-www-form-urlencoded",
	}
	formBody := "token=" + url.QueryEscape(bogus)
	bodyFn := func() io.Reader { return strings.NewReader(formBody) }

	resp, body := doPostUntilStatus(ctx, t,
		testConfig.NHPServerBaseURL+"/plugins/qurl",
		bodyFn, headers, http.StatusForbidden)

	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("error-path Content-Type = %q, want text/html (SPA branches on this)", ct)
	}
	if !strings.Contains(string(body), accessLinkInvalidMarker) {
		t.Errorf("error-path body missing %q (body: %s)", accessLinkInvalidMarker, truncate(body, 200))
	}
	if got := resp.Header.Get("Vary"); !strings.Contains(got, "Accept") {
		t.Errorf("Vary on error path = %q, want it to contain Accept", got)
	}
}

// postResolveWithAccept mints a fresh QURL per attempt, POSTs its token
// to /plugins/qurl with the given Accept header, and returns the response
// only when its status matches wantStatus. Single-use tokens require
// minting per attempt; that's the per-attempt body builder this helper
// provides. The retry envelope (transport + 5xx retries, fail-fast on
// other status, wall-clock + attempt-cap guards) is delegated to
// doPostUntilStatus.
func postResolveWithAccept(ctx context.Context, t *testing.T, accept string, wantStatus int) *resolveResp {
	t.Helper()

	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if accept != "" {
		headers["Accept"] = accept
	}
	bodyFn := func() io.Reader {
		minted := mintSmokeQURL(ctx, t, "https://example.com")
		return strings.NewReader("token=" + url.QueryEscape(minted.AccessToken()))
	}
	resp, body := doPostUntilStatus(ctx, t,
		testConfig.NHPServerBaseURL+"/plugins/qurl",
		bodyFn, headers, wantStatus)
	return &resolveResp{Response: resp, body: body}
}
