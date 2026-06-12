//go:build smoke

package smoke

// Tier 2: QURL resolve flow — the customer-critical path from
// POST /plugins/qurl (token in form body) to a 302 redirect to
// the proxied resource.
//
// Capability: the NHP server's static qurl plugin, registered at
// /plugins/qurl, which:
//
//  1. Extracts the access token from the POST form body (preferred)
//     or GET query parameter (deprecated, backward compat)
//  2. Calls qurl-service's POST /internal/v1/resolve to look up the
//     resource metadata
//  3. Emits a knock to the AC (opening the client IP in ipset)
//  4. Returns HTTP 302 with a Location pointing at r_{id}.qurl.site.*
//     and sets nhp_token / nhp_refresh_token cookies scoped to the
//     qurl.site parent domain
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
)

// accessLinkInvalidMarker is the branded HTML page title returned
// by the qurl plugin when an access token is missing, invalid, or
// expired. Used by both resolve tests and the plugin dispatcher
// test as the single source of truth for the error-page marker.
const accessLinkInvalidMarker = "Access Link Invalid"

// mintSmokeQURL mints a QURL with a label derived from the test name and
// registers cleanup. Returns the mint response so the test can read qurl_link /
// access token / qurl_site.
func mintSmokeQURL(ctx context.Context, t *testing.T, targetURL string) *QURLResponse {
	t.Helper()
	return mintSmokeQURLLabeled(ctx, t, targetURL, "")
}

// mintSmokeQURLLabeled keeps setup/precondition failures grep-friendly for
// tests where a later assertion is the actual gate under test.
func mintSmokeQURLLabeled(ctx context.Context, t *testing.T, targetURL, failureContext string) *QURLResponse {
	t.Helper()
	resp, err := MintQURL(ctx, t, MintOptions{
		Label:     t.Name(),
		TargetURL: targetURL,
		ExpiresIn: "120s", // long enough for the test body + a follow-redirect chain
	})
	if err != nil {
		fatalWithContextLabel(t, failureContext, "mint QURL: %v", err)
	}
	if resp.Data.ResourceID == "" {
		fatalWithContextLabel(t, failureContext, "mint returned empty resource_id: %+v", resp)
	}
	if resp.AccessToken() == "" {
		fatalWithContextLabel(t, failureContext, "mint returned qurl_link with no access token fragment: %s", resp.Data.QURLLink)
	}
	t.Cleanup(func() {
		DeleteQURL(context.Background(), t, resp.Data.ResourceID)
	})
	return resp
}

func fatalWithContextLabel(t *testing.T, contextLabel, format string, args ...any) {
	t.Helper()
	if contextLabel != "" {
		args = append([]any{contextLabel}, args...)
		format = "%s: " + format
	}
	t.Fatalf(format, args...)
}

// resolveRetryBudget is the total wall-clock time resolveWithRetries
// will spend retrying before giving up. Longer than postFlipMaxWait
// because each attempt uses a per-attempt timeout that eats into the
// budget — ~4 attempts if every one times out (5s timeout + 5s poll
// = 10s each), up to ~8 if failures are fast (sub-second + 5s poll).
const resolveRetryBudget = 45 * time.Second

// resolvePerAttemptTimeout bounds each individual resolve HTTP call.
// Short enough to fit multiple retries into resolveRetryBudget, long
// enough to tolerate a slow NLB target registration (~2-3s typical).
const resolvePerAttemptTimeout = 5 * time.Second

// resolveWithRetries performs the happy-path resolve POST against
// /plugins/qurl with the token in the form body (not URL query string)
// and returns the response on success or fails the test on
// retry-exhausted failure.
//
// Retry policy: retry on transport errors (timeouts during
// blue/green flips) and 5xx responses. Fail immediately on 4xx
// (that's a real token/access decision the server made, not a
// flake). This prevents a genuine access regression — e.g., a
// broken resolve lookup returning 403 for every valid token —
// from being masked by retries.
//
// Because each resolve consumes the single-use access token
// (max_sessions=1), the caller must mint a fresh QURL on every
// retry. resolveWithRetries takes a mintFunc instead of a
// pre-minted token to enforce this.
//
// Callers receive an *http.Response with headers intact but body
// drained and closed — only header/cookie inspection is valid.
//
// Intentionally NOT consolidated with postResolveWithAccept in
// 15_resolve_accept_negotiation_test.go: that helper returns the body
// for shape assertions and takes a parametric Accept + wantStatus.
// This one hard-codes "expect 302" and discards the body. Keeping
// them separate keeps both call sites locally clear.
func resolveWithRetries(ctx context.Context, t *testing.T, mintFunc func() *QURLResponse) *http.Response {
	t.Helper()
	return resolveWithRetriesLabeled(ctx, t, mintFunc, "")
}

// resolveWithRetriesLabeled labels setup/precondition failures without changing
// cleanup timing on freshly minted QURLs.
func resolveWithRetriesLabeled(ctx context.Context, t *testing.T, mintFunc func() *QURLResponse, failureContext string) *http.Response {
	t.Helper()

	deadline := time.Now().Add(resolveRetryBudget)
	var lastErr error
	attempt := 0

	for {
		attempt++
		minted := mintFunc()

		reqCtx, cancel := context.WithTimeout(ctx, resolvePerAttemptTimeout)
		reqURL := testConfig.NHPServerBaseURL + "/plugins/qurl"
		formData := "token=" + url.QueryEscape(minted.AccessToken())
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, reqURL, strings.NewReader(formData))
		if err != nil {
			cancel()
			fatalWithContextLabel(t, failureContext, "resolveWithRetries: build request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := testConfig.NoRedirectClient.Do(req)

		if err != nil {
			cancel()
			// Transport error (timeout, connection refused, etc.) —
			// retryable during blue/green flips.
			lastErr = fmt.Errorf("attempt %d: transport error: %w", attempt, err)
			t.Logf("resolveWithRetries: %v", lastErr)
		} else {
			// Drain body before canceling the context so the
			// connection returns to the pool instead of being torn
			// down by the canceled context.
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			cancel()

			switch {
			case resp.StatusCode == http.StatusFound:
				if attempt > 1 {
					t.Logf("resolveWithRetries: succeeded on attempt %d", attempt)
				}
				return resp
			case resp.StatusCode >= 500:
				lastErr = fmt.Errorf("attempt %d: 5xx status %d (retryable)", attempt, resp.StatusCode)
				t.Logf("resolveWithRetries: %v", lastErr)
			default:
				// 4xx or unexpected: the server made a decision. Fail
				// immediately — do not mask an access regression with
				// retries.
				fatalWithContextLabel(t, failureContext, "resolveWithRetries: non-retryable status %d on attempt %d", resp.StatusCode, attempt)
			}
		}

		// Two guards: wall-clock budget catches slow failures, attempt
		// cap catches fast-failing 5xx that would otherwise thrash
		// Auth0+qurl-service. maxResolveAttempts is shared via
		// assertions.go.
		if attempt >= maxResolveAttempts {
			fatalWithContextLabel(t, failureContext, "resolveWithRetries: exhausted %d attempts: %v",
				maxResolveAttempts, lastErr)
		}
		if time.Now().After(deadline) {
			fatalWithContextLabel(t, failureContext, "resolveWithRetries: exhausted %s budget after %d attempts: %v",
				resolveRetryBudget, attempt, lastErr)
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
// of the nhp_token / nhp_refresh_token cookies. A cookie scoped to
// the wrong parent domain would silently fail to propagate when
// the browser visits r_{id}.qurl.site.*, making the resolve flow
// appear to work but authentication fail on the next request.
func TestResolve_CookiesHaveExpectedDomain(t *testing.T) {
	ctx := context.Background()
	resp := resolveWithRetries(ctx, t, func() *QURLResponse {
		return mintSmokeQURL(ctx, t, "https://example.com")
	})

	expectedCookies := map[string]bool{
		nhpTokenCookie:        false,
		nhpRefreshTokenCookie: false,
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
// indirect proof that the AC ipset opened for the runner's IP during
// the resolve. We mint a QURL pointing at example.com, resolve it to a
// 302, then follow that redirect to r_{id}.qurl.site.* and assert the
// proxied response reaches the target's content marker.
//
// If this test passes, the full flow works end-to-end:
//
//	(runner) → POST /plugins/qurl (token in body) → 302
//	        → r_{id}.qurl.site.* (AC proxies) → target → 200 body
//
// A failure with the health tests and the sibling resolve tests
// passing indicates a knock-forwarding or ipset regression.
//
// Two-phase structure (closes #1026, the retry-loop follow-up to
// PR #1025):
//
//  1. resolveWithRetries gets the 302 on the no-redirect client. It is
//     the single place that classifies the resolve server's own access
//     decision: a 4xx on the direct /plugins/qurl response (e.g. 403
//     token rejected) fails loud and non-retryable; a transport error
//     or 5xx retries with a fresh mint. The decision is made on the
//     single-hop response, never inferred from a redirect chain.
//
//  2. We then follow the 302 ourselves and treat the GET as pure
//     reachability. A non-200 here is NOT the resolve server's access
//     decision — it traverses qurl-service's router and the AC proxy.
//     A freshly-minted resource's r_{id}.qurl.site route can briefly
//     race propagation and 404 before it is ready (observed ~1/20
//     locally), so we retry the GET (same session, no re-mint) within
//     resolveRetryBudget instead of failing on the first blip. A
//     persistent failure still fails once the budget exhausts.
//
// Each mint is a distinct resource (see uniqueSmokeTarget), so this
// test never contends with the sibling resolve tests for a shared
// per-resource max_sessions slot.
func TestResolve_FollowsRedirectAndReachesProtectedResource(t *testing.T) {
	ctx := context.Background()

	// Phase 1: resolve to a 302. The access decision is made here, on
	// the direct /plugins/qurl response — a bad token fails loud inside
	// resolveWithRetries and never reaches phase 2.
	resolveResp := resolveWithRetries(ctx, t, func() *QURLResponse {
		return mintSmokeQURL(ctx, t, "https://example.com")
	})
	loc := resolveResp.Header.Get("Location")
	if loc == "" {
		t.Fatal("302 response has no Location header")
	}
	locURL, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location %q: %v", loc, err)
	}

	// Phase 2: follow the 302 to the protected resource. Seed a fresh
	// cookie jar with the session cookies from the 302 (nhp_token /
	// nhp_refresh_token, scoped to the qurl.site parent domain) so the
	// AC's L7 authz gate honors the GET. Re-GETting with the established
	// session needs no re-mint — the ipset stays open for the runner's
	// IP and the session cookie is reusable.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	jar.SetCookies(locURL, resolveResp.Cookies())
	client := &http.Client{Jar: jar}

	// example.com's canonical body marker (#1022: external dependency).
	const marker = "Example Domain"

	deadline := time.Now().Add(resolveRetryBudget)
	attempt := 0
	var lastErr error
	for {
		attempt++

		reqCtx, cancel := context.WithTimeout(ctx, resolvePerAttemptTimeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, locURL.String(), nil)
		if err != nil {
			cancel()
			t.Fatalf("build follow request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("attempt %d: transport error: %w", attempt, err)
			t.Logf("follow-redirect: %v", lastErr)
		} else {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			resp.Body.Close()
			cancel()
			switch {
			case readErr != nil:
				lastErr = fmt.Errorf("attempt %d: read body: %w", attempt, readErr)
				t.Logf("follow-redirect: %v", lastErr)
			case resp.StatusCode == http.StatusOK && strings.Contains(string(body), marker):
				if attempt > 1 {
					t.Logf("follow-redirect: reached target on attempt %d", attempt)
				}
				return
			case resp.StatusCode == http.StatusOK:
				// Reached a 200 but not the proxied target — during
				// propagation the AC can briefly serve a fallback /
				// interstitial. Retry; persistent wrong content fails
				// once the budget exhausts.
				lastErr = fmt.Errorf("attempt %d: status 200 but body missing %q: %s",
					attempt, marker, truncate(body, 200))
				t.Logf("follow-redirect: %v", lastErr)
			default:
				// Non-200 from a downstream hop: the freshly-minted
				// r_{id} route racing propagation (404) or a blue/green
				// flip (5xx). Retryable — NOT the resolve server's
				// access decision (that was settled in phase 1).
				lastErr = fmt.Errorf("attempt %d: downstream status %d (retryable)", attempt, resp.StatusCode)
				t.Logf("follow-redirect: %v", lastErr)
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("follow-redirect: exhausted %s budget after %d attempts: %v",
				resolveRetryBudget, attempt, lastErr)
		}
		time.Sleep(postFlipPollInterval)
	}
}

// TestResolve_UnknownTokenReturns403_POST fences the access-denied
// path via POST (preferred path) for a syntactically well-formed but
// nonexistent access token. Real access tokens are at_ + 22 chars of
// base62 (25 chars total). The bogus token below matches that
// length/shape so if the server has a length-precheck it still
// reaches the store-lookup path, where the lookup fails and the
// handler returns the branded 403.
func TestResolve_UnknownTokenReturns403_POST(t *testing.T) {
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

	resp, _ := doPostFormNoRedirect(t, testConfig.NHPServerBaseURL,
		"/plugins/qurl", "token="+garbage, nil)
	assertStatusCode(t, resp, http.StatusForbidden)
}
