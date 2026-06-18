//go:build smoke

package smoke

// Tier 2: qurl.link frontend consumer-contract fences.
//
// This file lives in the Tier 2 range deliberately. The dominant
// framing is the consumer contract NHP makes: the deployed SPA must
// contain the JS that constructs and submits the six t_*_ms fields,
// must POST to a hostname-derived resolve endpoint, must include the
// serving host in the allowlist, and must serve the CSP that lets the
// inline IIFE execute. The PR #1842 "regression fence" framing is a
// secondary reading of the same contract from a Tier 1 angle.
//
// Capability added in PR #1824. A drift where terraform uploads a
// stripped-down build loses the wire silently — visits stay up,
// errors stay down, but every server-side QurlResolveBrowser{DNS,TCP,
// TLS,TTFB,DOMInteractive,ToSubmit} histogram goes to zero
// observations.
//
// The byte-pattern assertions are intentionally narrow (function name
// + field-name literals + the URL concat). They survive whitespace /
// minification but trip on a different instrumentation API, which
// should pair the smoke fence with the new wire. Critically, that
// means a future innocent JS refactor — function rename, template
// literal for the URL concat — fails this test even though the wire
// is fine. That is the intended trade-off; the test is a tripwire,
// not a behavioral check. If you're touching the SPA's instrumentation
// API and this fails, update the test in the same commit.
//
// Source of truth: terraform/modules/qurl-link/frontend/index.html
// (deploys via terraform/modules/qurl-link/main.tf::aws_s3_object.index).
//
// Assumption: both deployed envs always set var.deploy_qurl_link=true.
// All four tests below GET testConfig.QURLLinkOrigin unconditionally;
// a future env that disables qurl-link entirely would fail these on
// DNS resolution. If that day comes, gate this file behind a
// skipIfQurlLinkNotDeployed(t) helper backed by an SSM probe.
//
// Cache window: terraform_data.qurl_link_invalidation (root) blocks
// apply on `aws cloudfront wait invalidation-completed`, so by the
// time smoke runs the new bytes are live at every CF edge. CloudFront
// response-header policy changes have their own propagation path; the
// sandbox deploy workflow polls the live CSP before this smoke suite
// runs so CSP-only drift fails at the deploy gate, not as a late smoke
// surprise. If a future change tears out either guard, re-add the
// corresponding cache/propagation caveat here.

import (
	"bytes"
	"image"
	"image/png"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// TestQurlLinkFrontend_DeploysBrowserTimingInstrumentation fences
// the structural drift class introduced and fenced by PR #1842.
//
// Bytes, not behavior: a syntax error in the SPA that breaks
// execution would still pass this test as long as the source strings
// are present. Headless-browser execution is out of scope for smoke
// per CLAUDE.md; the end-to-end wire is verified by
// 12_qurl_browser_timings_test.go (server contract) +
// post-deploy click-through (acceptance gate).
func TestQurlLinkFrontend_DeploysBrowserTimingInstrumentation(t *testing.T) {
	resp, body := doGet(t, testConfig.QURLLinkOrigin, "/", nil)
	assertStatusCode(t, resp, http.StatusOK)
	bodyStr := string(body)

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html* (qurl.link / must serve the SPA, not a JSON / redirect)", ct)
	}

	// appendBrowserTimings is the load-bearing entry point. A build
	// that drops it has no path to constructing the t_*_ms fields.
	if !strings.Contains(bodyStr, "appendBrowserTimings") {
		t.Fatalf("deployed SPA does not contain appendBrowserTimings — frontend timing instrumentation regressed.")
	}

	// Partial drift (one or two field names disappearing) is harder to
	// notice in a dashboard than a full wire-cut, so check all six.
	wantFields := []string{
		"t_dns_ms",
		"t_tcp_ms",
		"t_tls_ms",
		"t_ttfb_ms",
		"t_dom_interactive_ms",
		"t_to_submit_ms",
	}
	var missing []string
	for _, f := range wantFields {
		if !strings.Contains(bodyStr, f) {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("deployed SPA is missing timing field name(s): %v — each missing name silently zeros its server-side QurlResolveBrowser* histogram until restored.",
			missing)
	}
}

// TestQurlLinkFrontend_RootServesConsumerLandingPage fences the
// no-fragment root experience. qurl.link used to be only an access-token
// interstitial; it is now also the consumer marketing front door, so the
// deployed root must keep serving the landing copy rather than reverting to a
// spinner-only verifier.
func TestQurlLinkFrontend_RootServesConsumerLandingPage(t *testing.T) {
	resp, body := doGet(t, testConfig.QURLLinkOrigin, "/", nil)
	assertStatusCode(t, resp, http.StatusOK)
	bodyStr := string(body)

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html* (qurl.link / must serve the landing page)", ct)
	}

	wantCopy := []string{
		"Share the link. Not the exposure.",
		"layerv-wordmark.svg",
		"Create a secure link",
		"Access link invalid",
		// Source-text proxy for behavior smoke cannot execute; update it with
		// any copy refactor that preserves the UX.
		"If you opened this page from a qURL access link",
		`rel="canonical" href="https://qurl.link/"`,
		`property="og:image" content="https://qurl.link/og-image.png"`,
	}
	for _, want := range wantCopy {
		if !strings.Contains(bodyStr, want) {
			t.Fatalf("deployed qurl.link root is missing landing/verifier copy %q", want)
		}
	}

	if !reducedMotionScrollBehaviorRE.MatchString(bodyStr) {
		t.Fatal("deployed qurl.link root is missing the reduced-motion smooth-scroll override.")
	}

	if !noscriptFallbackStyleRE.MatchString(bodyStr) {
		t.Fatal("deployed qurl.link root is missing the no-JS fallback visibility overrides.")
	}

	if hasRobotsNoindexMeta(bodyStr) {
		t.Fatal("deployed qurl.link root still carries noindex,nofollow; the consumer landing page should be indexable.")
	}

	if match := staticBodyClassAttrRE.FindStringSubmatch(bodyStr); len(match) == 2 {
		for _, className := range strings.Fields(match[1]) {
			if className == "verifying" {
				t.Fatal("deployed qurl.link root bakes in verifier mode; fragment-less visits must render the landing page.")
			}
		}
	}

	robotsHeader := strings.ToLower(resp.Header.Get("X-Robots-Tag"))
	if testConfig.Environment == "prod" {
		if strings.Contains(robotsHeader, "noindex") {
			t.Fatalf("prod qurl.link response has X-Robots-Tag=%q; prod landing page should be indexable.", robotsHeader)
		}
	} else if !strings.Contains(robotsHeader, "noindex") {
		t.Fatalf("%s qurl.link response has X-Robots-Tag=%q; non-prod qurl-link hosts should remain noindex.", testConfig.Environment, robotsHeader)
	}
}

func TestQurlLinkFrontend_ServesCrawlerAssets(t *testing.T) {
	resp, body := doGet(t, testConfig.QURLLinkOrigin, "/robots.txt", nil)
	assertStatusCode(t, resp, http.StatusOK)

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain* (qurl.link /robots.txt must not fall back to index.html)", ct)
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "User-agent: *") {
		t.Fatalf("qurl.link robots.txt = %q, want User-agent: * directive", bodyStr)
	}
	if testConfig.Environment == "prod" {
		if !strings.Contains(bodyStr, "Allow: /") || strings.Contains(bodyStr, "Disallow: /") {
			t.Fatalf("prod qurl.link robots.txt = %q, want Allow: / and no Disallow: /", bodyStr)
		}
	} else if !strings.Contains(bodyStr, "Disallow: /") {
		t.Fatalf("%s qurl.link robots.txt = %q, want Disallow: /", testConfig.Environment, bodyStr)
	}

	for _, path := range []string{"/favicon.ico", "/favicon.svg"} {
		resp, body = doGet(t, testConfig.QURLLinkOrigin, path, nil)
		assertStatusCode(t, resp, http.StatusOK)

		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "image/svg+xml") {
			t.Fatalf("Content-Type = %q, want image/svg+xml* (qurl.link %s must not fall back to index.html)", ct, path)
		}
		if !strings.Contains(string(body), "<svg") {
			t.Fatalf("qurl.link %s did not return the favicon SVG body.", path)
		}
	}

	resp, body = doGet(t, testConfig.QURLLinkOrigin, "/og-image.png", nil)
	assertStatusCode(t, resp, http.StatusOK)

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "image/png") {
		t.Fatalf("Content-Type = %q, want image/png* (qurl.link /og-image.png must not fall back to index.html)", ct)
	}
	if !bytes.HasPrefix(body, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("qurl.link /og-image.png did not return a PNG body.")
	}
	assertQurlOGImageHasLayerVWordmark(t, body)

	resp, body = doGet(t, testConfig.QURLLinkOrigin, "/layerv-wordmark.svg", nil)
	assertStatusCode(t, resp, http.StatusOK)

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "image/svg+xml") {
		t.Fatalf("Content-Type = %q, want image/svg+xml* (qurl.link /layerv-wordmark.svg must not fall back to index.html)", ct)
	}
	if !strings.Contains(string(body), "<svg") || !strings.Contains(string(body), "viewBox=") {
		t.Fatal("qurl.link /layerv-wordmark.svg did not return the LayerV wordmark SVG body.")
	}
}

func assertQurlOGImageHasLayerVWordmark(t *testing.T, body []byte) {
	t.Helper()

	img, err := png.Decode(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("qurl.link /og-image.png did not decode as a PNG image: %v", err)
	}
	if w, h := img.Bounds().Dx(), img.Bounds().Dy(); w != 1200 || h != 630 {
		t.Fatalf("qurl.link /og-image.png dimensions = %dx%d, want 1200x630.", w, h)
	}
	if !qurlOGImageHasLayerVWordmarkPixels(img) {
		t.Fatal("qurl.link /og-image.png is missing visible LayerV wordmark pixels in the expected social-preview brand area.")
	}
}

func qurlOGImageHasLayerVWordmarkPixels(img image.Image) bool {
	bounds := img.Bounds()
	// README.md composites the width-preserved 244px wordmark at +80+74. Keep
	// this deployed-origin tripwire in sync with scripts/check-qurl-link-og-image.sh,
	// which checks the committed PNG before it reaches CloudFront.
	// This generous region contains the placement while tolerating anti-aliasing
	// and minor reexports; the untouched SVG source paints only a dark background here.
	brandRegion := image.Rect(bounds.Min.X+70, bounds.Min.Y+55, bounds.Min.X+360, bounds.Min.Y+140).Intersect(bounds)
	brandPixels := 0

	for y := brandRegion.Min.Y; y < brandRegion.Max.Y; y += 2 {
		for x := brandRegion.Min.X; x < brandRegion.Max.X; x += 2 {
			r, g, b, a := img.At(x, y).RGBA()
			if a < 0x8000 {
				continue
			}
			r8, g8, b8 := int(r>>8), int(g>>8), int(b>>8)
			maxChannel := max(r8, g8, b8)
			minChannel := min(r8, g8, b8)
			if maxChannel > 180 || (maxChannel > 80 && maxChannel-minChannel > 40) {
				brandPixels++
			}
		}
	}

	return brandPixels >= 120
}

// TestQurlLinkFrontend_PostsToHostnameDerivedResolveURL fences the
// hostname-derivation invariant. Reintroducing a baked-in URL (e.g.,
// the dropped var.nhp_resolve_url) would re-couple every new env to a
// frontend rebuild — exactly the coupling this PR removed.
func TestQurlLinkFrontend_PostsToHostnameDerivedResolveURL(t *testing.T) {
	resp, body := doGet(t, testConfig.QURLLinkOrigin, "/", nil)
	assertStatusCode(t, resp, http.StatusOK)

	want := "'https://resolve.' + hostname + '/plugins/qurl'"
	if !strings.Contains(string(body), want) {
		t.Fatalf("deployed SPA does not derive RESOLVE_URL from window.location.hostname; expected substring %q.", want)
	}
}

// TestQurlLinkFrontend_AllowlistContainsServingHost is belt-and-
// suspenders to the lifecycle.precondition on aws_s3_object.index.
// The precondition fences the deploy path at plan time; this fence
// catches the post-deploy drift case where the deployed object some-
// how doesn't match the file the precondition validated (e.g., a
// bucket re-target outside terraform's view, or a stale upload that
// terraform didn't roll forward). Failure here means real users hit
// the SPA's branded error page on every visit.
func TestQurlLinkFrontend_AllowlistContainsServingHost(t *testing.T) {
	u, err := url.Parse(testConfig.QURLLinkOrigin)
	if err != nil || u.Hostname() == "" {
		t.Fatalf("testConfig.QURLLinkOrigin = %q does not parse to a usable host: %v", testConfig.QURLLinkOrigin, err)
	}
	resp, body := doGet(t, testConfig.QURLLinkOrigin, "/", nil)
	assertStatusCode(t, resp, http.StatusOK)

	// u.Hostname() strips a port if present; the SPA's ALLOWED_HOSTS
	// contains the bare hostname, so QURL_LINK_ORIGIN=https://host:443
	// (debugging / mitm proxy) still matches.
	want := "'" + u.Hostname() + "'"
	if !strings.Contains(string(body), want) {
		t.Fatalf("deployed SPA's ALLOWED_HOSTS does not include %q — every visit would hit the branded error page. "+
			"This means terraform plan accepted the upload but the deployed bytes don't match what the precondition validated.", want)
	}
}

// TestQurlLinkFrontend_CSPAllowsInlineScript fences both supported CSP postures
// the response_headers_policy declares:
//
//  1. 'unsafe-inline' is present — without it, the inline IIFE refuses
//     to execute in any modern browser and users see the loading
//     spinner forever.
//  2. Envs without the browser NHP agent keep NO other sources listed: the
//     bucket only serves the inline-script page, so same-origin .js loads
//     stay blocked and connect-src falls back to default-src 'self'.
//  3. Envs with the browser NHP agent explicitly allow 'self', matching the
//     Terraform switch that uploads nhp-agent.min.js beside the verifier shell.
//  4. Envs with the browser NHP agent also list the relay origin in
//     connect-src, plus the resolve origin that hands the browser those relay
//     inputs; otherwise the first cross-origin fetch is blocked by default-src
//     'self' before resolve, relay, or server can see it.
//
// If a future PR moves to a hash- or nonce-based CSP, that PR must
// update this assertion in lockstep.
//
// Regex anchor: `script-src` value must be exactly one of the supported
// postures, ending either with `;` (directive separator) or end-of-string.
// Anchored on start-of-string or a preceding directive separator instead of
// `\b` so a future CSP shape with hyphenated tokens before the directive can't
// accidentally satisfy the boundary.
var (
	// Order-independent detection of a robots meta tag whose content asks
	// crawlers not to index the page. Go's RE2 engine has no lookahead, so
	// the "both attributes present, any order" check can't live in a single
	// pattern — instead we enumerate <meta> elements (metaTagRE) and test
	// each for the two attributes independently (see hasRobotsNoindexMeta).
	metaTagRE             = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	robotsNameAttrRE      = regexp.MustCompile(`(?i)\bname=["']robots["']`)
	noindexContentAttrRE  = regexp.MustCompile(`(?i)\bcontent=["'][^"']*noindex`)
	staticBodyClassAttrRE = regexp.MustCompile(`(?is)<body\b[^>]*\bclass=["']([^"']*)["'][^>]*>`)
	scriptSrcOnlyInlineRE = regexp.MustCompile(`(?i)(?:^|;\s*)script-src\s+'unsafe-inline'\s*(?:;|$)`)
	// Keep this directive-level posture in lockstep with build-and-push.yml's
	// qurl.link CSP propagation gate.
	scriptSrcInlineAndSelfRE      = regexp.MustCompile(`(?i)(?:^|;\s*)script-src\s+'unsafe-inline'\s+'self'\s*(?:;|$)`)
	reducedMotionScrollBehaviorRE = regexp.MustCompile(
		`(?is)@media\s*\(\s*prefers-reduced-motion\s*:\s*reduce\s*\)\s*\{[^{}]*html\s*\{[^{}]*scroll-behavior\s*:\s*auto\s*;`,
	)
	noscriptFallbackStyleRE = regexp.MustCompile(
		`(?is)<noscript>.*?\.access-shell\s*\{[^{}]*display\s*:\s*grid\s*;.*?\.access-noscript\s*\{[^{}]*display\s*:\s*block\s*;`,
	)
)

// qurlLinkJSAgentEnabledEnvs mirrors the env-level
// qurl_link_js_agent_enabled tfvars switch. The smoke CSP fence allows
// same-origin script loads only while Terraform is intentionally serving the
// browser NHP agent bundle in that env.
var qurlLinkJSAgentEnabledEnvs = map[string]bool{
	"sandbox": true,
}

// qurlLinkJSAgentNetworkOrigins mirrors the resolve.<qurl-link-host> convention
// and the relay_dns_name Terraform input used to derive relay_connect_src_origin
// for qurl-link. This is the full non-self browser connection set allowed by
// CSP on the agent path; future telemetry or agent fetches to another host must
// update Terraform and this smoke mirror together. Keep this in lockstep with
// the env tfvars when the browser agent is enabled in another env.
var qurlLinkJSAgentNetworkOrigins = map[string][]string{
	"sandbox": {
		"https://resolve.qurl.link.layerv.xyz",
		"https://relay.qurl.link.layerv.xyz",
	},
}

// hasRobotsNoindexMeta reports whether body contains a <meta> element that
// carries both name="robots" and a content value including "noindex", in any
// attribute order. RE2 lacks lookahead, so we enumerate meta tags and test the
// two attributes per tag rather than expressing "both present" in one pattern.
func hasRobotsNoindexMeta(body string) bool {
	for _, tag := range metaTagRE.FindAllString(body, -1) {
		if robotsNameAttrRE.MatchString(tag) && noindexContentAttrRE.MatchString(tag) {
			return true
		}
	}
	return false
}

func cspDirectiveFields(csp, directiveName string) []string {
	for _, directive := range strings.Split(csp, ";") {
		fields := strings.Fields(strings.TrimSpace(directive))
		if len(fields) > 0 && strings.EqualFold(fields[0], directiveName) {
			return fields[1:]
		}
	}
	return nil
}

func sameStringSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	counts := make(map[string]int, len(want))
	for _, field := range want {
		counts[field]++
	}
	for _, field := range got {
		if counts[field] == 0 {
			return false
		}
		counts[field]--
	}
	return true
}

func TestQurlLinkFrontend_CSPAllowsInlineScript(t *testing.T) {
	resp, _ := doGet(t, testConfig.QURLLinkOrigin, "/", nil)
	assertStatusCode(t, resp, http.StatusOK)

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy response header is empty — the response_headers_policy is not attached, or CloudFront stopped emitting it.")
	}

	wantPosture := "'unsafe-inline'-only"
	wantRE := scriptSrcOnlyInlineRE
	if qurlLinkJSAgentEnabledEnvs[testConfig.Environment] {
		wantPosture = "'unsafe-inline' plus 'self' for the same-origin browser NHP agent bundle"
		wantRE = scriptSrcInlineAndSelfRE
	}
	if !wantRE.MatchString(csp) {
		t.Fatalf("CSP script-src directive does not match the expected %s posture. "+
			"Either 'unsafe-inline' is missing (SPA won't execute) or the allowed script sources drifted from the env's Terraform switch. "+
			"CSP: %q", wantPosture, csp)
	}

	connectSrc := cspDirectiveFields(csp, "connect-src")
	if qurlLinkJSAgentEnabledEnvs[testConfig.Environment] {
		networkOrigins := qurlLinkJSAgentNetworkOrigins[testConfig.Environment]
		if len(networkOrigins) == 0 {
			t.Fatalf("qurlLinkJSAgentEnabledEnvs marks env %q enabled but no network connect-src origins are configured in the smoke mirror.", testConfig.Environment)
		}
		wantConnectSrcFields := append([]string{"'self'"}, networkOrigins...)
		if !sameStringSet(connectSrc, wantConnectSrcFields) {
			t.Fatalf("CSP connect-src directive fields = %q, want set %q so the browser cutover can fetch resolve inputs and POST knocks to the relay. CSP: %q",
				connectSrc, wantConnectSrcFields, csp)
		}
	} else if connectSrc != nil {
		t.Fatalf("CSP connect-src directive is present in env %q while qurl-link JS agent is disabled; legacy qurl-link should rely on default-src 'self'. CSP: %q",
			testConfig.Environment, csp)
	}
}
