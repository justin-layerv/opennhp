//go:build smoke

package smoke

// Tier 2: qurl.link frontend consumer-contract fences.
//
// This file lives in the Tier 2 range deliberately. The dominant
// framing is the consumer contract NHP makes: the deployed SPA must
// contain the verifier JS for the environment's selected qurl.link ingress:
// sandbox uses the same-origin JS agent and HTTPS relay, while legacy envs
// still POST to a hostname-derived resolve endpoint. The deployed page must
// include the serving host in the allowlist and must serve the CSP that lets
// only hash-authorized inline scripts execute.
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
// Source of truth: terraform/modules/qurl-link/frontend/index.html (rendered
// and hash-pinned by terraform/modules/qurl-link/main.tf).
//
// Assumption: both deployed envs always set var.deploy_qurl_link=true.
// All four tests below GET testConfig.QURLLinkOrigin unconditionally;
// a future env that disables qurl-link entirely would fail these on
// DNS resolution. If that day comes, gate this file behind a
// skipIfQurlLinkNotDeployed(t) helper backed by an SSM probe.
//
// Cache window: when the JS agent is mounted, Terraform serves both
// index.html and nhp-agent.min.js with no-cache so browser caches
// revalidate the SRI-pinned pair instead of mixing new integrity metadata
// with a stale bundle. terraform_data.qurl_link_invalidation (root) blocks
// apply on `aws cloudfront wait invalidation-completed`, so by the
// time smoke runs the new bytes are live at every CF edge. CloudFront
// response-header policy changes have their own propagation path; the
// sandbox deploy workflow polls the live CSP before this smoke suite
// runs so CSP-only drift fails at the deploy gate, not as a late smoke
// surprise. If a future change tears out either guard, re-add the
// corresponding cache/propagation caveat here.

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestQurlLinkFrontend_VerifierWireContract fences the verifier ingress shape.
// Bytes, not behavior: a syntax error in the SPA that breaks execution would
// still pass this test as long as the source strings are present. Headless
// browser execution is out of scope for smoke per CLAUDE.md; this is a deployed
// byte tripwire.
func TestQurlLinkFrontend_VerifierWireContract(t *testing.T) {
	requireRemote(t) // remote-only: serves the qurl.link SPA, which is not part of the NHP stack.
	resp, body := doGet(t, testConfig.QURLLinkOrigin, "/", nil)
	assertStatusCode(t, resp, http.StatusOK)
	htmlStr := string(body)

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html* (qurl.link / must serve the SPA, not a JSON / redirect)", ct)
	}
	bodyStr := inlineVerifierScript(t, htmlStr)

	if qurlLinkJSAgentEnabledEnvs[testConfig.Environment] {
		wantSnippets := []string{
			"QURL_LINK_CONFIG",
			"qv1.",
			"parseQurlBootstrapFragment",
			"agent_private_key_b64",
			"agent_public_key_b64",
			"server_public_key_b64",
			"relay_url",
			"clearSensitiveFragment",
			"isSensitiveQurlFragment",
			"isAllowedRelayUrl",
			"requested.username === ''",
			"requested.password === ''",
			"bootstrap.serverPublicKeyB64 && !QURL_LINK_CONFIG.serverStaticPubB64",
			"bootstrap.serverPublicKeyB64 !== QURL_LINK_CONFIG.serverStaticPubB64",
			"Relay verifier identity mismatch",
			"Relay verifier origin not allowed",
			"import('/nhp-agent.min.js')",
			"agent.x25519KeyFromBase64(bootstrap.agentPrivateKeyB64)",
			"agent.knock({",
			"qurlAccessToken: bootstrap.accessToken",
			"qurlUserAgent:",
			"serverStaticPubB64",
			"relayBaseUrl",
			// qURL v2 (keyed-identity) verifier wiring must be present in the
			// JS-agent render regardless of whether qv2 is enabled in this env: the
			// config keys, the fragment dispatch, and the knock call. This is the
			// same byte-tripwire posture as the qv1 snippets above — it proves the
			// glue is deployed, not that a qv2 link opens (that needs a headless
			// browser, tracked with the qv1 execution gap in #2748). When qv2 is
			// enabled in an env, TestQurlLinkFrontend_QurlV2ConfigPopulated
			// additionally asserts issuerTrustStore is non-empty there.
			"issuerTrustStore:",
			"relayAllowlist:",
			"fragment.startsWith('qv2')",
			"window.addEventListener('hashchange', processLocationFragment)",
			"handleQurlV2Fragment",
			"agent.TrustStore.fromSpkiDerB64(QURL_LINK_CONFIG.issuerTrustStore)",
			"new agent.RelayAllowlist(QURL_LINK_CONFIG.relayAllowlist)",
			"agent.knockQurlV2(fragment,",
		}
		var missing []string
		for _, want := range wantSnippets {
			if !strings.Contains(bodyStr, want) {
				missing = append(missing, want)
			}
		}
		if len(missing) > 0 {
			t.Fatalf("deployed JS-agent qurl.link verifier is missing snippet(s): %v", missing)
		}
		if strings.Contains(bodyStr, "https://resolve.") || strings.Contains(bodyStr, "/plugins/qurl") || strings.Contains(bodyStr, "appendBrowserTimings") {
			t.Fatalf("deployed JS-agent qurl.link verifier still contains legacy browser-to-resolve code; browser ingress must be relay-only in env %q.", testConfig.Environment)
		}
		// NOTE: this is a substring byte-contract — it proves the qv1 bundle
		// security guards are PRESENT in the deployed page (so an SPA refactor
		// can't silently drop the userinfo check, the server-pubkey fail-closed/
		// mismatch branches, or isAllowedRelayUrl), but it does not EXECUTE the
		// rejection path. Driving isAllowedRelayUrl's reject cases (origin
		// mismatch, embedded userinfo, non-root path, query/fragment) needs a
		// headless-browser/JS harness that Go smoke is not. Tracked in #2748.
		return
	}

	// Legacy envs still use the browser timing form POST until their JS-agent
	// cutover flag flips. appendBrowserTimings is the load-bearing entry point.
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
	requireRemote(t) // remote-only: serves the qurl.link SPA, which is not part of the NHP stack.
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
	requireRemote(t) // remote-only: serves the qurl.link SPA, which is not part of the NHP stack.
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

// TestQurlLinkFrontend_UsesExpectedIngress fences the environment-specific
// ingress: JS-agent environments must use relay only; legacy environments keep
// the hostname-derived resolve endpoint until their cutover flag flips.
func TestQurlLinkFrontend_UsesExpectedIngress(t *testing.T) {
	requireRemote(t) // remote-only: serves the qurl.link SPA, which is not part of the NHP stack.
	resp, body := doGet(t, testConfig.QURLLinkOrigin, "/", nil)
	assertStatusCode(t, resp, http.StatusOK)
	script := inlineVerifierScript(t, string(body))

	if qurlLinkJSAgentEnabledEnvs[testConfig.Environment] {
		for _, want := range qurlLinkJSAgentNetworkOrigins[testConfig.Environment] {
			if !strings.Contains(script, want) {
				t.Fatalf("deployed JS-agent qurl.link verifier does not contain relay origin %q.", want)
			}
		}
		if strings.Contains(script, "'https://resolve.' + hostname + '/plugins/qurl'") {
			t.Fatalf("deployed JS-agent qurl.link verifier still derives resolve URL from window.location.hostname.")
		}
		return
	}

	want := "'https://resolve.' + hostname + '/plugins/qurl'"
	if !strings.Contains(script, want) {
		t.Fatalf("legacy deployed SPA does not derive resolve URL from window.location.hostname; expected substring %q.", want)
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
	requireRemote(t) // remote-only: serves the qurl.link SPA, which is not part of the NHP stack.
	u, err := url.Parse(testConfig.QURLLinkOrigin)
	if err != nil || u.Hostname() == "" {
		t.Fatalf("testConfig.QURLLinkOrigin = %q does not parse to a usable host: %v", testConfig.QURLLinkOrigin, err)
	}
	resp, body := doGet(t, testConfig.QURLLinkOrigin, "/", nil)
	assertStatusCode(t, resp, http.StatusOK)
	script := inlineVerifierScript(t, string(body))

	// u.Hostname() strips a port if present; the SPA's ALLOWED_HOSTS
	// contains the bare hostname, so QURL_LINK_ORIGIN=https://host:443
	// (debugging / mitm proxy) still matches.
	want := "\"" + u.Hostname() + "\""
	if !strings.Contains(script, want) {
		t.Fatalf("deployed SPA's ALLOWED_HOSTS does not include %q — every visit would hit the branded error page. "+
			"This means terraform plan accepted the upload but the deployed bytes don't match what the precondition validated.", want)
	}
}

// TestQurlLinkFrontend_QurlV2ConfigPopulated fences the qURL v2 (keyed-identity)
// issuer trust material in the DEPLOYED browser verifier. It mirrors
// TestQurlLinkFrontend_AllowlistContainsServingHost: the qv2 config KEYS and the
// dispatch branch must always be present in a JS-agent render (a structural
// tripwire so an SPA refactor can't silently drop the qv2 glue), and when qv2 is
// enabled in this env the issuerTrustStore must additionally be POPULATED with the
// expected kid (and the relayAllowlist with the expected host) rather than the {}
// fail-closed form — an empty/mismatched store on an enabled env would make every
// real qv2 link show the invalid-access page.
//
// This asserts the LIVE deployed bytes; TestQurlLinkFrontend_QurlV2ConfigRenders-
// Populated is the companion PRE-DEPLOY check that renders the committed template
// with the same env inputs. Like the rest of this file this is a deployed
// byte-contract, not an execution check: it does not verify a signature or open a
// link (that needs the headless browser harness tracked in #2748). It only proves
// the trust material reached CloudFront.
func TestQurlLinkFrontend_QurlV2ConfigPopulated(t *testing.T) {
	requireRemote(t) // remote-only: serves the qurl.link SPA, which is not part of the NHP stack.
	resp, body := doGet(t, testConfig.QURLLinkOrigin, "/", nil)
	assertStatusCode(t, resp, http.StatusOK)

	// The qv2 verifier glue only ships on the JS-agent render (it needs the
	// same-origin bundle + relay connect-src). Legacy envs have no qv2 path.
	if !qurlLinkJSAgentEnabledEnvs[testConfig.Environment] {
		return
	}
	script := inlineVerifierScript(t, string(body))
	assertQurlV2VerifierWiring(t, script)

	trustStore := qurlV2IssuerTrustStoreLiteral(t, script)
	relayAllowlist := qurlV2RelayAllowlistLiteral(t, script)
	env, enabled := qurlLinkQurlV2EnabledEnvs[testConfig.Environment]
	assertQurlV2ConfigState(t, "deployed", trustStore, relayAllowlist, env, enabled)
}

// TestQurlLinkFrontend_QurlV2ConfigRendersPopulated is the PRE-DEPLOY companion to
// TestQurlLinkFrontend_QurlV2ConfigPopulated: it renders the committed qurl-link
// index.html template with this env's qv2 inputs and asserts the same populated
// (or empty, fail-closed) shape BEFORE any CloudFront deploy. Terraform computes
// the issuer trust store from the live KMS key, which is not knowable here, so the
// render uses a representative SPKI-DER-base64url placeholder for the enabled env
// while pinning the exact Kid and RelayHost from the env tfvars mirror — the
// wiring, not the key bytes, is what this fence guards. It performs no network I/O,
// so it runs in the local tier too (it is the qv2 analogue of the plan-time
// aws_s3_object.index preconditions, exercised from Go).
func TestQurlLinkFrontend_QurlV2ConfigRendersPopulated(t *testing.T) {
	env, enabled := qurlLinkQurlV2EnabledEnvs[testConfig.Environment]

	var trustStoreMap map[string]string
	var relayAllowlist []string
	if enabled {
		// Representative base64url SPKI DER (unpadded, url alphabet) under the real
		// Kid; a 91-byte P-256 SPKI is 122 base64url chars, but only the alphabet +
		// presence matters to this wiring fence.
		trustStoreMap = map[string]string{
			env.Kid: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExampleSandboxIssuerSpkiDerBase64Url-_",
		}
		relayAllowlist = []string{env.RelayHost}
	} else {
		// Disabled env: empty map/list -> the {}/[] fail-closed render.
		trustStoreMap = map[string]string{}
		relayAllowlist = []string{}
	}

	script := renderQurlLinkVerifierScript(t, trustStoreMap, relayAllowlist)
	assertQurlV2VerifierWiring(t, script)

	gotTrust := qurlV2IssuerTrustStoreLiteral(t, script)
	gotRelay := qurlV2RelayAllowlistLiteral(t, script)
	assertQurlV2ConfigState(t, "rendered", gotTrust, gotRelay, env, enabled)
}

// TestQurlLinkFrontend_QurlV2ShareTransportRoutingRenders is the executable
// source-level seam for the share-safe qv2t1 transport. The JS-agent unit tests
// own the decoder grammar; this test proves the page routes the whole raw
// fragment into that one decoder, enters verifier mode before loading the agent,
// clears every qv2-looking credential from history, and does not log caught
// credential-derived parser errors. It performs no network I/O and is included in
// the local smoke tier.
func TestQurlLinkFrontend_QurlV2ShareTransportRoutingRenders(t *testing.T) {
	raw, err := os.ReadFile(qurlLinkTemplatePath(t))
	if err != nil {
		t.Fatalf("read qurl-link template: %v", err)
	}
	scripts := inlineExecutableScripts(string(raw))
	if len(scripts) != 2 {
		t.Fatalf("qurl-link template has %d executable inline scripts, want preload + verifier", len(scripts))
	}

	preload := scripts[0]
	for _, want := range []string{
		"hash.startsWith('qv2')",
		"document.documentElement.classList.add('verifying')",
	} {
		if !strings.Contains(preload, want) {
			t.Fatalf("qurl.link preload is missing qv2t1 verifier-state wiring %q.", want)
		}
	}

	verifier := inlineVerifierScript(t, string(raw))
	for _, want := range []string{
		"fragment.startsWith('qv2')",
		"enterVerifierState()",
		"clearSensitiveFragment(fragment)",
		"handleQurlV2Fragment(fragment, requestID)",
		"fragment.startsWith('qv2') || fragment.startsWith('qv1.')",
		"agent.knockQurlV2(fragment,",
		"catch {",
		"showError('qURL v2 verification failed')",
	} {
		if !strings.Contains(verifier, want) {
			t.Fatalf("qurl.link verifier is missing qv2t1 transport wiring %q.", want)
		}
	}

	routeAt := strings.Index(verifier, "if (fragment.startsWith('qv2'))")
	if routeAt < 0 {
		t.Fatal("qurl.link verifier has no qv2 dispatch branch.")
	}
	addVerifyingAt := strings.Index(verifier[routeAt:], "enterVerifierState()")
	clearAt := strings.Index(verifier, "clearSensitiveFragment(fragment)")
	handleAt := strings.Index(verifier, "handleQurlV2Fragment(fragment, requestID)")
	if addVerifyingAt < 0 || clearAt < routeAt+addVerifyingAt || handleAt < clearAt {
		t.Fatalf("qurl.link qv2 route ordering is not verifying -> history clear -> handler: route=%d verifying=%d clear=%d handler=%d", routeAt, addVerifyingAt, clearAt, handleAt)
	}

	for _, forbidden := range []string{
		"fragment.startsWith('qv2.')",
		"console.error('qURL v2 verification failed:', error)",
	} {
		if strings.Contains(verifier, forbidden) {
			t.Fatalf("qurl.link verifier retains forbidden legacy/secret-logging wiring %q.", forbidden)
		}
	}
}

// TestQurlLinkFrontend_SameDocumentCredentialNavigationRenders fences the
// reader seam where an already-open qurl.link tab receives a new fragment. A
// hash-only navigation does not reload the page, so the initial-load dispatcher
// alone would leave the credential visible and never invoke the verifier.
func TestQurlLinkFrontend_SameDocumentCredentialNavigationRenders(t *testing.T) {
	raw, err := os.ReadFile(qurlLinkTemplatePath(t))
	if err != nil {
		t.Fatalf("read qurl-link template: %v", err)
	}
	verifier := inlineVerifierScript(t, string(raw))

	listener := "window.addEventListener('hashchange', processLocationFragment)"
	listenerAt := strings.Index(verifier, listener)
	dispatchAt := strings.Index(verifier, "processLocationFragment();")
	handlerAt := strings.Index(verifier, "function processLocationFragment()")
	fragmentReadAt := strings.Index(verifier, "const fragment = window.location.hash.substring(1)")
	if listenerAt < 0 || dispatchAt < listenerAt || handlerAt < dispatchAt || fragmentReadAt < handlerAt {
		t.Fatalf("qurl.link fragment dispatch must register hashchange, run once, then reread location.hash inside the handler: listener=%d dispatch=%d handler=%d read=%d", listenerAt, dispatchAt, handlerAt, fragmentReadAt)
	}

	for _, want := range []string{
		"const requestID = ++activeFragmentRequest",
		"handleQurlV2Fragment(fragment, requestID)",
		"verifyWithRelay(bootstrap, requestID)",
		"if (!isActiveFragmentRequest(requestID))",
		"history.replaceState(null, '', window.location.pathname + window.location.search)",
	} {
		if !strings.Contains(verifier, want) {
			t.Fatalf("qurl.link same-document credential handler is missing %q.", want)
		}
	}
}

// assertQurlV2VerifierWiring checks the qv2 config keys + dispatch branch are
// present in a verifier script, regardless of qv2 enablement. Shared by the
// deployed-bytes and rendered-template fences.
func assertQurlV2VerifierWiring(t *testing.T, script string) {
	t.Helper()
	for _, want := range []string{
		"issuerTrustStore:",
		"relayAllowlist:",
		"fragment.startsWith('qv2')",
		"window.addEventListener('hashchange', processLocationFragment)",
		"handleQurlV2Fragment",
		"agent.knockQurlV2(fragment,",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("qurl.link verifier is missing qURL v2 wiring %q.", want)
		}
	}
}

// assertQurlV2ConfigState checks the issuerTrustStore/relayAllowlist config
// literals against the env's qv2 enablement: enabled -> the store carries the
// expected kid and the allowlist the expected host; disabled -> both are the empty
// fail-closed form. `source` labels the origin ("deployed" or "rendered") in
// failure messages.
func assertQurlV2ConfigState(t *testing.T, source, trustStore, relayAllowlist string, env qurlV2EnabledEnv, enabled bool) {
	t.Helper()
	if enabled {
		if !strings.Contains(trustStore, "\""+env.Kid+"\"") || !strings.Contains(trustStore, ":") {
			t.Fatalf("env %q enables qURL v2 but the %s verifier issuerTrustStore (%q) does not carry kid %q; qv2 links would fail closed with ErrUnknownKID. "+
				"Check root local.qurl_v2_portal_issuer_trust_store and the qurl-link templatefile wiring.", testConfig.Environment, source, trustStore, env.Kid)
		}
		if !strings.Contains(relayAllowlist, "\""+env.RelayHost+"\"") {
			t.Fatalf("env %q enables qURL v2 but the %s verifier relayAllowlist (%q) does not carry host %q; every signed relay_url would be rejected.",
				testConfig.Environment, source, relayAllowlist, env.RelayHost)
		}
		return
	}
	// Disabled env: both MUST be the empty fail-closed form. A populated store on a
	// not-yet-enabled env means the enablement gate drifted from the smoke mirror.
	if strings.TrimSpace(trustStore) != "{}" {
		t.Fatalf("env %q does not enable qURL v2 (not in qurlLinkQurlV2EnabledEnvs) but the %s verifier issuerTrustStore is populated (%q); "+
			"add the env to qurlLinkQurlV2EnabledEnvs in the same change that flips its qurl_v2 admission tfvars.", testConfig.Environment, source, trustStore)
	}
	if strings.TrimSpace(relayAllowlist) != "[]" {
		t.Fatalf("env %q does not enable qURL v2 but the %s verifier relayAllowlist is populated (%q); it must be the empty fail-closed form.",
			testConfig.Environment, source, relayAllowlist)
	}
}

// qurlV2IssuerTrustStoreLiteral extracts the JS object literal assigned to
// issuerTrustStore in the QURL_LINK_CONFIG block. The value is a jsonencode()d
// map rendered by Terraform, so it is a balanced { ... } with no nested braces
// (values are strings). See qurlV2ConfigLiteral.
func qurlV2IssuerTrustStoreLiteral(t *testing.T, script string) string {
	t.Helper()
	return qurlV2ConfigLiteral(t, script, "issuerTrustStore:", '{', '}')
}

// qurlV2RelayAllowlistLiteral extracts the JS array literal assigned to
// relayAllowlist in the QURL_LINK_CONFIG block. jsonencode()d list of strings, so
// a balanced [ ... ] with no nested brackets. See qurlV2ConfigLiteral.
func qurlV2RelayAllowlistLiteral(t *testing.T, script string) string {
	t.Helper()
	return qurlV2ConfigLiteral(t, script, "relayAllowlist:", '[', ']')
}

// qurlV2ConfigLiteral returns the balanced open..close delimited slice assigned to
// `key` in the verifier script. The value is a jsonencode()d map/list with no
// nested delimiters (values are strings), so delimiter-matching from the first
// `open` after the key is exact for that shape. If a future config nests the same
// delimiter inside this value, replace this with a real JSON scan.
func qurlV2ConfigLiteral(t *testing.T, script, key string, open, close byte) string {
	t.Helper()
	idx := strings.Index(script, key)
	if idx < 0 {
		t.Fatalf("verifier has no %s key to extract.", key)
	}
	rest := script[idx+len(key):]
	start := strings.IndexByte(rest, open)
	if start < 0 {
		t.Fatalf("%s value does not start with %q: %.40q", key, string(open), rest)
	}
	depth := 0
	for i := start; i < len(rest); i++ {
		switch rest[i] {
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return rest[start : i+1]
			}
		}
	}
	t.Fatalf("%s literal is unbalanced: %.80q", key, rest[start:])
	return ""
}

// qurlLinkTemplatePath resolves the committed qurl-link index.html template from
// this test file's location (tests/smoke -> repo root -> the module). Used by the
// pre-deploy render fence.
func qurlLinkTemplatePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve this test file path via runtime.Caller.")
	}
	// tests/smoke/16_..._test.go -> repo root is two dirs up.
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	return filepath.Join(repoRoot, "terraform", "modules", "qurl-link", "frontend", "index.html")
}

// renderQurlLinkVerifierScript renders the committed qurl-link index.html template
// for the JS-agent posture with the given qv2 trust store / relay allowlist, then
// returns the inline verifier script. It substitutes the exact template inputs the
// qurl-link module passes (the qv2 maps as Go-side JSON, mirroring Terraform's
// jsonencode) and resolves the `%{ if js_agent_enabled ~}` blocks to the enabled
// branch — the only posture where qv2 is reachable. This is a faithful-enough
// stand-in for `templatefile` for the config block this fence inspects; it is not
// a general HCL template engine.
func renderQurlLinkVerifierScript(t *testing.T, trustStore map[string]string, relayAllowlist []string) string {
	t.Helper()
	raw, err := os.ReadFile(qurlLinkTemplatePath(t))
	if err != nil {
		t.Fatalf("read qurl-link template: %v", err)
	}
	tmpl := string(raw)

	trustJSON, err := json.Marshal(trustStore)
	if err != nil {
		t.Fatalf("marshal trust store: %v", err)
	}
	relayJSON, err := json.Marshal(relayAllowlist)
	if err != nil {
		t.Fatalf("marshal relay allowlist: %v", err)
	}

	// Scalar ${...} inputs the module passes (JS-agent posture). allowed_hosts_json
	// and the qv2 maps are jsonencode()d; the rest are plain strings.
	replacements := map[string]string{
		"${allowed_hosts_json}":              `["qurl.link.layerv.xyz"]`,
		"${js_agent_enabled}":                "true",
		"${js_agent_key}":                    "nhp-agent.min.js",
		"${js_agent_sri}":                    "sha384-EXAMPLE",
		"${relay_base_url}":                  "https://relay.qurl.link.layerv.xyz",
		"${server_static_pub_b64}":           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"${qurl_v2_issuer_trust_store_json}": string(trustJSON),
		"${qurl_v2_relay_allowlist_json}":    string(relayJSON),
	}
	for from, to := range replacements {
		tmpl = strings.ReplaceAll(tmpl, from, to)
	}

	// Resolve `%{ if js_agent_enabled ~} A %{ else ~} B %{ endif ~}` to A (the
	// enabled branch). The template uses only this single boolean directive.
	tmpl = resolveTemplateIfBlocks(tmpl, "js_agent_enabled", true)

	if strings.Contains(tmpl, "${") || strings.Contains(tmpl, "%{") {
		t.Fatalf("qurl-link template still has unresolved template markers after render; a new ${...}/%%{...} input was added without updating renderQurlLinkVerifierScript.")
	}
	return inlineVerifierScript(t, tmpl)
}

// resolveTemplateIfBlocks resolves `%{ if <name> ~} A [%{ else ~} B] %{ endif ~}`
// blocks for a single known boolean, keeping the taken branch. It is deliberately
// narrow — one directive name, optional else, and branch bodies that contain no
// further directive markers (so a match cannot span across an adjacent block) —
// matching the qurl-link template's shape; it is not a general HCL parser. Branch
// bodies are matched as "no `%{` marker inside" via BRANCH so the first (no-else)
// block cannot greedily pair its `if` with a later block's `else`/`endif`.
func resolveTemplateIfBlocks(tmpl, name string, cond bool) string {
	// A branch body: any run that does not contain a `%{` directive opener.
	const branch = `((?:[^%]|%(?:[^{]|$))*?)`
	openMarker := `%\{[~\s]*if\s+` + regexp.QuoteMeta(name) + `[~\s]*\}`
	elseMarker := `%\{[~\s]*else[~\s]*\}`
	endMarker := `%\{[~\s]*endif[~\s]*\}`

	// if ... else ... endif
	ifElseRE := regexp.MustCompile(`(?s)` + openMarker + branch + elseMarker + branch + endMarker)
	tmpl = ifElseRE.ReplaceAllStringFunc(tmpl, func(m string) string {
		sub := ifElseRE.FindStringSubmatch(m)
		if cond {
			return sub[1]
		}
		return sub[2]
	})
	// if ... endif (no else)
	ifNoElseRE := regexp.MustCompile(`(?s)` + openMarker + branch + endMarker)
	tmpl = ifNoElseRE.ReplaceAllStringFunc(tmpl, func(m string) string {
		sub := ifNoElseRE.FindStringSubmatch(m)
		if cond {
			return sub[1]
		}
		return ""
	})
	return tmpl
}

// TestQurlLinkFrontend_CSPOmitsUnsafeInlineScript fences both supported CSP postures
// the response_headers_policy declares:
//
//  1. script-src omits 'unsafe-inline' and includes a sha256 source for every
//     executable inline script served in index.html.
//  2. Envs with the browser NHP agent additionally include 'self' so the
//     same-origin NHP agent bundle can execute.
//  3. Envs without the browser NHP agent keep connect-src unset, so legacy
//     qurl-link falls back to default-src 'self' for fetch/XHR.
//  4. Envs with the browser NHP agent list the relay origin in connect-src;
//     otherwise the cross-origin relay POST is blocked by default-src 'self'
//     before relay or server can see it.
//
// Regex anchor: sandbox's script-src value must be 'self' followed by one or
// more sha256 hashes, ending either with `;` (directive separator) or
// end-of-string. This mirrors the workflow propagation gate; the parser checks
// below perform the exact source-list assertions.
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
	htmlAttrRE            = regexp.MustCompile(`(?is)\b([a-zA-Z][\w:-]*)\s*=\s*["']([^"']+)["']`)
	robotsNameAttrRE      = regexp.MustCompile(`(?i)\bname=["']robots["']`)
	noindexContentAttrRE  = regexp.MustCompile(`(?i)\bcontent=["'][^"']*noindex`)
	staticBodyClassAttrRE = regexp.MustCompile(`(?is)<body\b[^>]*\bclass=["']([^"']*)["'][^>]*>`)
	jsAgentScriptTagRE    = regexp.MustCompile(`(?is)<script\b[^>]*\bsrc=["']/nhp-agent\.min\.js["'][^>]*></script>`)
	// Mirrored with Terraform for the controlled qurl-link template only.
	// If a future verifier script embeds literal </script> or a script
	// attribute containing >, replace both extractors with a real parser.
	scriptElementRE  = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)
	scriptSrcAttrRE  = regexp.MustCompile(`(?i)(?:^|\s)src\s*=`)
	scriptTypeAttrRE = regexp.MustCompile(`(?i)(?:^|\s)type\s*=\s*["']?([^"'\s>]+)`)
	// Keep this directive-level posture in lockstep with build-and-push.yml's
	// qurl.link CSP propagation gate.
	scriptSrcSandboxHashRE        = regexp.MustCompile(`(?i)(?:^|;\s*)script-src\s+'self'(?:\s+'sha256-[A-Za-z0-9+/]+={0,2}')+\s*(?:;|$)`)
	scriptHashSourceFieldRE       = regexp.MustCompile(`^'sha256-[A-Za-z0-9+/]+={0,2}'$`)
	reducedMotionScrollBehaviorRE = regexp.MustCompile(
		`(?is)@media\s*\(\s*prefers-reduced-motion\s*:\s*reduce\s*\)\s*\{[^{}]*html\s*\{[^{}]*scroll-behavior\s*:\s*auto\s*;`,
	)
	noscriptFallbackStyleRE = regexp.MustCompile(
		`(?is)<noscript>.*?\.access-shell\s*\{[^{}]*display\s*:\s*grid\s*;.*?\.access-noscript\s*\{[^{}]*display\s*:\s*block\s*;`,
	)
)

// qurlLinkJSAgentEnabledEnvs mirrors the env-level
// qurl_link_js_agent_enabled tfvars switch. Enabled envs allow the same-origin
// NHP agent bundle via 'self' and require the browser-agent connect-src network
// allowlist.
var qurlLinkJSAgentEnabledEnvs = map[string]bool{
	"sandbox": true,
}

// qurlV2EnabledEnv mirrors the env tfvars that make root
// local.qurl_v2_admission_ready TRUE, which is what populates the qurl.link
// browser verifier's qv2 issuer trust material. When an env has an entry here,
// the rendered issuerTrustStore MUST carry this exact Kid (the issuer signer's
// QURL_V2_ISSUER_KEY_KID and the NHP-server trust-store key are the same var, so
// a mismatch here would ErrUnknownKID every admission) and the relayAllowlist MUST
// carry RelayHost.
type qurlV2EnabledEnv struct {
	// Kid is env var.qurl_v2_issuer_kid.
	Kid string
	// RelayHost is the single host in env var.qurl_v2_relay_allowlist.
	RelayHost string
}

// qurlLinkQurlV2EnabledEnvs mirrors the env-level gate that populates the
// qurl.link browser verifier's qURL v2 issuer trust material (root
// local.qurl_v2_admission_ready: qurl_v2_admission_enabled &&
// qurl_v2_issuer_key_enabled && qurl_v2_issuer_kid != ""). An env absent here is
// treated as qv2-disabled: its rendered issuerTrustStore must be the empty {}
// fail-closed form. Add an env here in the SAME change that flips its qurl_v2
// admission tfvars so this fence tracks the enablement rather than lagging it.
//
// sandbox: terraform/environments/sandbox/terraform.tfvars sets
// qurl_v2_admission_enabled = qurl_v2_issuer_key_enabled = true with
// qurl_v2_issuer_kid = "qurl-issuer-sandbox-2026-07" and
// qurl_v2_relay_allowlist = "relay.qurl.link.layerv.xyz", so admission_ready is
// TRUE and the portal populates. Keep these values in lockstep with that tfvars.
var qurlLinkQurlV2EnabledEnvs = map[string]qurlV2EnabledEnv{
	"sandbox": {
		Kid:       "qurl-issuer-sandbox-2026-07",
		RelayHost: "relay.qurl.link.layerv.xyz",
	},
}

// qurlLinkJSAgentNetworkOrigins mirrors the relay_dns_name Terraform input used
// to derive relay_connect_src_origin for qurl-link. This is the full non-self
// browser connection set allowed by CSP on the agent path; future telemetry or
// agent fetches to another host must update Terraform and this smoke mirror
// together. Keep this in lockstep with the env tfvars when the browser agent is
// enabled in another env.
var qurlLinkJSAgentNetworkOrigins = map[string][]string{
	"sandbox": {
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

func inlineVerifierScript(t *testing.T, body string) string {
	t.Helper()

	scripts := inlineExecutableScripts(body)
	for _, script := range scripts {
		if strings.Contains(script, "QURL_LINK_CONFIG") {
			return script
		}
	}
	t.Fatalf("deployed SPA has %d executable inline script block(s), but none contains the qurl.link verifier config.", len(scripts))
	return ""
}

func inlineExecutableScripts(body string) []string {
	var scripts []string
	for _, match := range scriptElementRE.FindAllStringSubmatch(body, -1) {
		attrs, scriptBody := match[1], match[2]
		if scriptSrcAttrRE.MatchString(attrs) || isNonExecutableScriptElement(attrs) {
			continue
		}
		if strings.TrimSpace(scriptBody) != "" {
			scripts = append(scripts, scriptBody)
		}
	}
	return scripts
}

func isNonExecutableScriptElement(attrs string) bool {
	match := scriptTypeAttrRE.FindStringSubmatch(attrs)
	if len(match) != 2 {
		return false
	}
	scriptType := strings.ToLower(strings.TrimSpace(match[1]))
	return scriptType != "" &&
		scriptType != "text/javascript" &&
		scriptType != "application/javascript" &&
		scriptType != "module"
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

func scriptHashSource(script string) string {
	sum := sha256.Sum256([]byte(script))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func isScriptHashSource(field string) bool {
	return scriptHashSourceFieldRE.MatchString(field)
}

func uniqueHTMLAttrValue(t *testing.T, tag, name string) (string, bool) {
	t.Helper()

	var value string
	found := false
	for _, match := range htmlAttrRE.FindAllStringSubmatch(tag, -1) {
		if strings.EqualFold(match[1], name) {
			if found {
				t.Fatalf("script tag has duplicate %q attributes; refusing first-match parsing. Tag: %s", name, tag)
			}
			value = match[2]
			found = true
		}
	}
	return value, found
}

func sha384SRI(body []byte) string {
	sum := sha512.Sum384(body)
	return "sha384-" + base64.StdEncoding.EncodeToString(sum[:])
}

func TestQurlLinkFrontend_JSAgentBundleIntegrity(t *testing.T) {
	requireRemote(t) // remote-only: serves the qurl.link SPA, which is not part of the NHP stack.
	resp, body := doGet(t, testConfig.QURLLinkOrigin, "/", nil)
	assertStatusCode(t, resp, http.StatusOK)

	bodyStr := string(body)
	scriptTag := jsAgentScriptTagRE.FindString(bodyStr)
	if !qurlLinkJSAgentEnabledEnvs[testConfig.Environment] {
		if scriptTag != "" {
			t.Fatalf("env %q disables the qurl-link JS agent, but the root HTML still renders the nhp-agent.min.js script tag: %s",
				testConfig.Environment, scriptTag)
		}
		if cacheControl := strings.ToLower(resp.Header.Get("Cache-Control")); !strings.Contains(cacheControl, "max-age=3600") || !strings.Contains(cacheControl, "must-revalidate") {
			t.Fatalf("env %q disables the qurl-link JS agent, but the root HTML Cache-Control = %q, want max-age=3600, must-revalidate.",
				testConfig.Environment, resp.Header.Get("Cache-Control"))
		}
		bundleResp, _ := doGet(t, testConfig.QURLLinkOrigin, "/nhp-agent.min.js", nil)
		if ct := bundleResp.Header.Get("Content-Type"); bundleResp.StatusCode >= 200 && bundleResp.StatusCode < 300 && strings.HasPrefix(ct, "text/javascript") {
			t.Fatalf("env %q disables the qurl-link JS agent, but /nhp-agent.min.js is still served as JavaScript: status=%d Content-Type=%q",
				testConfig.Environment, bundleResp.StatusCode, ct)
		}
		if bundleResp.StatusCode >= 200 && bundleResp.StatusCode < 300 {
			if cacheControl := strings.ToLower(bundleResp.Header.Get("Cache-Control")); !strings.Contains(cacheControl, "max-age=3600") || !strings.Contains(cacheControl, "must-revalidate") {
				t.Fatalf("env %q disables the qurl-link JS agent, but /nhp-agent.min.js fallback Cache-Control = %q, want max-age=3600, must-revalidate.",
					testConfig.Environment, bundleResp.Header.Get("Cache-Control"))
			}
		}
		return
	}

	if scriptTag == "" {
		t.Fatal("qurl-link JS agent is enabled, but the root HTML does not render a script tag for /nhp-agent.min.js.")
	}
	if cacheControl := strings.ToLower(resp.Header.Get("Cache-Control")); !strings.Contains(cacheControl, "no-cache") {
		t.Fatalf("qurl-link HTML Cache-Control = %q, want no-cache while the SRI-pinned JS agent is enabled so cached HTML cannot drift from the served bundle.",
			resp.Header.Get("Cache-Control"))
	}
	if scriptType, ok := uniqueHTMLAttrValue(t, scriptTag, "type"); !ok || !strings.EqualFold(scriptType, "module") {
		t.Fatalf("qurl-link JS agent script tag type = %q, want module. Tag: %s", scriptType, scriptTag)
	}
	integrity, ok := uniqueHTMLAttrValue(t, scriptTag, "integrity")
	if !ok || integrity == "" {
		t.Fatalf("qurl-link JS agent script tag is missing integrity metadata. Tag: %s", scriptTag)
	}

	// CloudFront may compress this behavior for browsers; browser SRI verifies
	// decoded resource bytes, so request identity bytes before hashing.
	bundleResp, bundleBody := doGet(t, testConfig.QURLLinkOrigin, "/nhp-agent.min.js", map[string]string{
		"Accept-Encoding": "identity",
	})
	assertStatusCode(t, bundleResp, http.StatusOK)
	if ct := bundleResp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Fatalf("Content-Type = %q, want text/javascript* (qurl.link /nhp-agent.min.js must serve the JS bundle, not an HTML fallback)", ct)
	}
	if cacheControl := strings.ToLower(bundleResp.Header.Get("Cache-Control")); !strings.Contains(cacheControl, "no-cache") {
		t.Fatalf("qurl-link JS agent Cache-Control = %q, want no-cache so cached bundles cannot drift from the rendered SRI metadata.",
			bundleResp.Header.Get("Cache-Control"))
	}
	if encoding := bundleResp.Header.Get("Content-Encoding"); encoding != "" {
		t.Fatalf("qurl-link JS agent Content-Encoding = %q, want empty because smoke requests identity encoding and hashes the exact deployed bundle bytes for browser SRI semantics. "+
			"If this asset intentionally starts serving compressed bytes even for identity requests, update this assertion to decode the served bytes before hashing.", encoding)
	}

	wantIntegrity := sha384SRI(bundleBody)
	if integrity != wantIntegrity {
		t.Fatalf("qurl-link JS agent integrity = %q, want %q from the deployed /nhp-agent.min.js bytes.", integrity, wantIntegrity)
	}

	csp := resp.Header.Get("Content-Security-Policy")
	if hashSource := "'" + wantIntegrity + "'"; slices.Contains(cspDirectiveFields(csp, "script-src"), hashSource) {
		t.Fatalf("CSP script-src includes JS agent SRI hash-source %q; same-origin execution should be authorized by 'self' while exact-byte pinning lives on the script integrity attribute. CSP: %q",
			hashSource, csp)
	}
}

func TestQurlLinkFrontend_CSPOmitsUnsafeInlineScript(t *testing.T) {
	requireRemote(t) // remote-only: serves the qurl.link SPA, which is not part of the NHP stack.
	resp, body := doGet(t, testConfig.QURLLinkOrigin, "/", nil)
	assertStatusCode(t, resp, http.StatusOK)

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy response header is empty — the response_headers_policy is not attached, or CloudFront stopped emitting it.")
	}

	scriptSrc := cspDirectiveFields(csp, "script-src")
	if len(scriptSrc) == 0 {
		t.Fatalf("CSP script-src directive is missing; qurl.link must explicitly authorize only hash-pinned verifier scripts. CSP: %q", csp)
	}
	if slices.Contains(scriptSrc, "'unsafe-inline'") {
		t.Fatalf("CSP script-src still contains 'unsafe-inline'; qurl.link verifier scripts must be hash-authorized. CSP: %q", csp)
	}

	scripts := inlineExecutableScripts(string(body))
	// Keep this count in lockstep with the Terraform qurl-link precondition and
	// Python CSP drift lint; all three mirror the controlled template shape.
	if len(scripts) != 2 {
		t.Fatalf("deployed SPA has %d executable inline script block(s), want exactly 2 hash-authorized verifier scripts.", len(scripts))
	}
	for _, script := range scripts {
		wantHash := scriptHashSource(script)
		if !slices.Contains(scriptSrc, wantHash) {
			t.Fatalf("CSP script-src does not include hash %s for a deployed inline verifier script. script-src=%q CSP=%q", wantHash, scriptSrc, csp)
		}
	}

	agentEnabled := qurlLinkJSAgentEnabledEnvs[testConfig.Environment]
	if agentEnabled {
		if !scriptSrcSandboxHashRE.MatchString(csp) {
			t.Fatalf("CSP script-src directive does not match the sandbox workflow propagation posture ('self' plus sha256 hashes). CSP: %q", csp)
		}
		if !slices.Contains(scriptSrc, "'self'") {
			t.Fatalf("CSP script-src directive omits 'self' while qurl-link JS agent is enabled; the same-origin agent bundle would be blocked. CSP: %q", csp)
		}
	} else if slices.Contains(scriptSrc, "'self'") {
		t.Fatalf("CSP script-src directive includes 'self' in env %q while qurl-link JS agent is disabled; legacy qurl.link should allow only hash-pinned inline verifier scripts. CSP: %q",
			testConfig.Environment, csp)
	}
	for _, field := range scriptSrc {
		if field != "'self'" && !isScriptHashSource(field) {
			t.Fatalf("CSP script-src directive has unsupported field %q; want only sha256 hashes plus optional 'self' for the JS-agent bundle. CSP: %q", field, csp)
		}
	}

	connectSrc := cspDirectiveFields(csp, "connect-src")
	if agentEnabled {
		networkOrigins := qurlLinkJSAgentNetworkOrigins[testConfig.Environment]
		if len(networkOrigins) == 0 {
			t.Fatalf("qurlLinkJSAgentEnabledEnvs marks env %q enabled but no network connect-src origins are configured in the smoke mirror.", testConfig.Environment)
		}
		wantConnectSrcFields := append([]string{"'self'"}, networkOrigins...)
		if !sameStringSet(connectSrc, wantConnectSrcFields) {
			t.Fatalf("CSP connect-src directive fields = %q, want set %q so the browser cutover can POST knocks to the relay. CSP: %q",
				connectSrc, wantConnectSrcFields, csp)
		}
	} else if connectSrc != nil {
		t.Fatalf("CSP connect-src directive is present in env %q while qurl-link JS agent is disabled; legacy qurl-link should rely on default-src 'self'. CSP: %q",
			testConfig.Environment, csp)
	}
}
