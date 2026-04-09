//go:build smoke

package smoke

// Tier 2: QURL resolve flow — the customer-critical path from
// /plugins/qurl?token=... to a 302 redirect to the proxied resource.
//
// Capability: the NHP server's static qurl plugin, registered at
// /plugins/qurl, which:
//
//  1. Extracts the access token from the query parameter
//  2. Calls qurl-service's POST /internal/v1/resolve to look up the
//     resource metadata
//  3. Emits a knock to the AC (opening the client IP in ipset)
//  4. Returns HTTP 302 with a Location pointing at r_{id}.qurl.site.*
//     and sets nhp_token / nhp_refresh_token / nhp_session_ttl cookies
//     scoped to the qurl.site parent domain
//
// Every test in this file mints a fresh QURL via qurl-service's
// public API (POST /v1/qurls with an Auth0 M2M bearer), exercises
// the resolve flow, and deletes the QURL in t.Cleanup. The short
// expires_in ("60s") is a fallback in case cleanup fails.
//
// Source of truth: endpoints/server/staticplugins/qurl/main.go
// (the AuthWithHttp handler).

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Cookie names set by the NHP qurl plugin's resolve handler.
// Defined once so a rename in the server is a single-place edit
// in the test suite.
const (
	nhpTokenCookie        = "nhp_token"
	nhpRefreshTokenCookie = "nhp_refresh_token"
	nhpSessionTTLCookie   = "nhp_session_ttl"
)

// accessLinkInvalidMarker is the branded HTML page title returned
// by the qurl plugin when an access token is missing, invalid, or
// expired. Used by both resolve tests and the plugin dispatcher
// test as the single source of truth for the error-page marker.
const accessLinkInvalidMarker = "Access Link Invalid"

// mintSmokeQURL is a small wrapper that mints a QURL with a label
// derived from the test name and registers cleanup. Returns the
// mint response so the test can read qurl_link / access token /
// qurl_site.
func mintSmokeQURL(ctx context.Context, t *testing.T, targetURL string) *QURLResponse {
	t.Helper()
	resp, err := MintQURL(ctx, t, MintOptions{
		Label:     t.Name(),
		TargetURL: targetURL,
		ExpiresIn: "120s", // long enough for the test body + a follow-redirect chain
	})
	if err != nil {
		t.Fatalf("mint QURL: %v", err)
	}
	if resp.Data.ResourceID == "" {
		t.Fatalf("mint returned empty resource_id: %+v", resp)
	}
	if resp.AccessToken() == "" {
		t.Fatalf("mint returned qurl_link with no access token fragment: %s", resp.Data.QURLLink)
	}
	t.Cleanup(func() {
		DeleteQURL(context.Background(), t, resp.Data.ResourceID)
	})
	return resp
}

// resolveWithRetries performs the happy-path resolve GET against
// /plugins/qurl?token=... and returns the response on success or
// an error on retry-exhausted failure.
//
// Retry policy: retry on 5xx responses (flake class during
// blue/green flips), fail immediately on 4xx (that's a real
// token/access decision the server made, not a flake). Transport
// errors from the underlying doGetNoRedirect are surfaced via
// t.Fatalf immediately (they indicate a DNS/TLS/network failure
// that retrying won't help). This prevents a genuine access
// regression — e.g., a broken resolve lookup returning 403 for
// every valid token — from being masked by retries.
//
// Because each resolve consumes the single-use access token
// (max_sessions=1), the caller must mint a fresh QURL on every
// retry. resolveWithRetries takes a mintFunc instead of a
// pre-minted token to enforce this.
func resolveWithRetries(ctx context.Context, t *testing.T, mintFunc func() *QURLResponse) *http.Response {
	t.Helper()

	deadline := time.Now().Add(postFlipMaxWait)
	var lastErr error
	attempt := 0

	for {
		attempt++
		minted := mintFunc()
		resp, _ := doGetNoRedirect(t, testConfig.NHPServerBaseURL,
			"/plugins/qurl?token="+minted.AccessToken(), nil)

		switch {
		case resp.StatusCode == http.StatusFound:
			if attempt > 1 {
				t.Logf("resolveWithRetries: succeeded on attempt %d", attempt)
			}
			return resp
		case resp.StatusCode >= 500:
			lastErr = fmt.Errorf("attempt %d: 5xx status %d (retryable)", attempt, resp.StatusCode)
		default:
			// 4xx or unexpected: the server made a decision. Fail
			// immediately — do not mask an access regression with
			// retries.
			t.Fatalf("resolveWithRetries: non-retryable status %d on attempt %d", resp.StatusCode, attempt)
		}

		if time.Now().After(deadline) {
			t.Fatalf("resolveWithRetries: exhausted %s budget after %d attempts: %v",
				postFlipMaxWait, attempt, lastErr)
		}
		time.Sleep(postFlipPollInterval)
	}
}

// TestResolve_ValidTokenReturns302ToQurlSite fences the primary
// business path: mint a QURL, resolve its access token via
// /plugins/qurl?token=..., assert HTTP 302 with a Location host
// that suffixes with QURLSiteDomain and that the nhp_token cookie
// is set with HttpOnly/Secure/Domain attributes.
//
// This is the single most important test in the whole smoke suite.
// If it fails, the QURL customer flow is broken.
//
// Retries on transport errors and 5xx via resolveWithRetries. A
// 4xx response fails immediately — that's a real access decision,
// not a flake, and retries would mask a regression.
func TestResolve_ValidTokenReturns302ToQurlSite(t *testing.T) {
	ctx := context.Background()
	resp := resolveWithRetries(ctx, t, func() *QURLResponse {
		return mintSmokeQURL(ctx, t, "https://example.com")
	})

	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("302 response has no Location header")
	}
	locURL, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location %q: %v", loc, err)
	}
	if !strings.HasSuffix(locURL.Host, testConfig.QURLSiteDomain) {
		t.Fatalf("Location host %q does not suffix with expected domain %q", locURL.Host, testConfig.QURLSiteDomain)
	}

	// Find nhp_token cookie in the Set-Cookie header and assert its
	// security attributes. The cookie's Domain attribute is checked
	// in a separate test (TestResolve_CookiesHaveExpectedDomain) so
	// that a domain-only regression doesn't swallow this one's
	// signal.
	//
	// SameSite=None is load-bearing here: the cookie is set on
	// resolve.qurl.link.* but must be sent to r_{id}.qurl.site.*
	// during the follow-redirect navigation. A different parent
	// domain is a cross-site context as far as the browser is
	// concerned. SameSite=Lax or SameSite=Strict would block the
	// cookie on the cross-site redirect and silently break auth.
	// SameSite=None is only permitted with Secure (which we also
	// assert), so both flags are checked together.
	var foundNhpToken bool
	for _, c := range resp.Cookies() {
		if c.Name != nhpTokenCookie {
			continue
		}
		foundNhpToken = true
		if !c.HttpOnly {
			t.Errorf("nhp_token cookie is missing HttpOnly")
		}
		if !c.Secure {
			t.Errorf("nhp_token cookie is missing Secure")
		}
		if c.SameSite != http.SameSiteNoneMode {
			t.Errorf("nhp_token cookie SameSite = %v, want SameSiteNoneMode (value %d) for cross-subdomain flow",
				c.SameSite, http.SameSiteNoneMode)
		}
		if c.Value == "" {
			t.Errorf("nhp_token cookie has empty value")
		}
	}
	if !foundNhpToken {
		t.Fatal("response does not set nhp_token cookie")
	}
}

// TestResolve_CookiesHaveExpectedDomain fences the domain scoping
// of the nhp_token / nhp_refresh_token / nhp_session_ttl cookies.
// A cookie scoped to the wrong parent domain would silently fail
// to propagate when the browser visits r_{id}.qurl.site.*, making
// the resolve flow appear to work but authentication fail on the
// next request.
func TestResolve_CookiesHaveExpectedDomain(t *testing.T) {
	ctx := context.Background()
	resp := resolveWithRetries(ctx, t, func() *QURLResponse {
		return mintSmokeQURL(ctx, t, "https://example.com")
	})

	expectedCookies := map[string]bool{
		nhpTokenCookie:        false,
		nhpRefreshTokenCookie: false,
		nhpSessionTTLCookie:   false,
	}
	for _, c := range resp.Cookies() {
		if _, want := expectedCookies[c.Name]; !want {
			continue
		}
		expectedCookies[c.Name] = true
		// Go's net/http does not strip the leading dot from
		// cookie Domain attributes (legacy RFC 6265 allows either
		// shape). The sandbox today sends bare "qurl.site.*"
		// (no dot) but we accept both to avoid a spurious fail
		// if the server ever emits the dotted form.
		got := strings.TrimPrefix(c.Domain, ".")
		if got != testConfig.QURLSiteDomain {
			t.Errorf("cookie %s: Domain=%q, want %q", c.Name, c.Domain, testConfig.QURLSiteDomain)
		}
	}
	for name, seen := range expectedCookies {
		if !seen {
			t.Errorf("expected cookie %s not set", name)
		}
	}
}

// TestResolve_FollowsRedirectAndReachesProtectedResource is the
// indirect proof that the AC ipset opened for the runner's IP
// during the resolve. We mint a QURL pointing at example.com,
// follow the redirect chain with a cookie jar, and assert the
// final response body contains the target's content marker.
//
// If this test passes, the full flow works end-to-end:
//
//	(runner) → /plugins/qurl?token=... → 302
//	        → r_{id}.qurl.site.* (AC proxies) → target → 200 body
//
// A failure in this test with 02_docker_image_test and the health
// tests passing indicates a knock-forwarding or ipset regression.
//
// Retries the full chain on transport errors and 5xx via a local
// loop (resolveWithRetries doesn't apply here because we need the
// follow-redirect client, not the no-redirect one). A single mint
// is consumed per attempt — up to 4 QURLs may be created during
// a flake window, each with a 60s TTL.
func TestResolve_FollowsRedirectAndReachesProtectedResource(t *testing.T) {
	ctx := context.Background()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
	}

	// example.com's canonical body marker. If example.com ever
	// changes its HTML, this test will need to pick a new marker
	// or a new target URL.
	marker := "Example Domain"

	deadline := time.Now().Add(postFlipMaxWait)
	attempt := 0
	var lastErr error

	for {
		attempt++
		minted := mintSmokeQURL(ctx, t, "https://example.com")

		reqURL := testConfig.NHPServerBaseURL + "/plugins/qurl?token=" + minted.AccessToken()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("attempt %d: transport error: %w", attempt, err)
		} else if resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("attempt %d: 5xx status %d", attempt, resp.StatusCode)
		} else if resp.StatusCode != http.StatusOK {
			// 4xx: real access decision, not a flake. Fail loud.
			resp.Body.Close()
			t.Fatalf("attempt %d: final status=%d, want 200 (non-retryable)", attempt, resp.StatusCode)
		} else {
			// 200: read body up to 64 KB and check for the marker.
			// Using io.ReadAll(io.LimitReader(...)) is safer than
			// a single Read() which may return fewer bytes than
			// requested.
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			resp.Body.Close()
			if readErr != nil {
				t.Fatalf("read resolved body: %v", readErr)
			}
			if !strings.Contains(string(body), marker) {
				t.Fatalf("final body does not contain %q\nbody: %s", marker, truncate(body, 400))
			}
			if attempt > 1 {
				t.Logf("TestResolve_FollowsRedirect: succeeded on attempt %d", attempt)
			}
			return
		}

		if time.Now().After(deadline) {
			t.Fatalf("exhausted %s budget after %d attempts: %v", postFlipMaxWait, attempt, lastErr)
		}
		time.Sleep(postFlipPollInterval)
	}
}

// TestResolve_UnknownTokenReturns403 fences the access-denied
// path for a syntactically well-formed but nonexistent access
// token. Real access tokens are at_ + 22 chars of base62 (25
// chars total, verified 2026-04-09 against sandbox: e.g.
// at_5an_tpqwyh5kwaz539mykg). The bogus token below matches that
// length/shape so if the server has a length-precheck it still
// reaches the store-lookup path, where the lookup fails and the
// handler returns the branded 403.
//
// A companion test (TestResolve_MalformedTokenReturns403) uses a
// completely invalid shape to fence the handler's early-reject
// path. Both currently return the same 403, but via different
// server code paths — the redundancy is intentional.
func TestResolve_UnknownTokenReturns403(t *testing.T) {
	// 25-char token shape: at_ + 22-char body. The body contains
	// "nonexistent" as a hint for anyone reading sandbox logs.
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
	garbage := "definitely-not-a-token"

	resp, _ := doGetNoRedirect(t, testConfig.NHPServerBaseURL,
		"/plugins/qurl?token="+garbage, nil)
	assertStatusCode(t, resp, http.StatusForbidden)
}
