//go:build smoke

package smoke

// Tier 2: qurl plugin browser-timing form-field passthrough.
//
// Capability added in PR #1824: the qurl.link interstitial posts
// PerformanceNavigationTiming phase durations as additional hidden
// form fields (t_dns_ms, t_tcp_ms, t_tls_ms, t_ttfb_ms,
// t_dom_interactive_ms, t_to_submit_ms) on the existing resolve POST.
// nhp-server's qurl plugin parses, validates, and emits each as a
// CloudWatch histogram observation. The contract this file fences:
//
//   - The presence of the six t_*_ms form fields MUST NOT change the
//     status code, content type, or body shape of the resolve POST
//     compared to the same POST without them. A frontend that adds
//     these fields cannot break a backend that doesn't understand
//     them; a backend that adds parse logic cannot break a frontend
//     still sending only "token=".
//
//   - Conversely, omitting the fields MUST be a no-op on the server
//     side — recordBrowserTimings exits silently when no fields are
//     present, the rejected counters do not increment.
//
// The metric-emission contract (samples reach CloudWatch within the
// publisher flush window, with the publisher's base dim set
// `{Component, Environment, Region}`) is verified out-of-band by the
// alarm wiring in #1840 — it requires a CloudWatch query against the
// publisher's flush window and is the right place for that fence.
//
// Source of truth: endpoints/server/staticplugins/qurl/main.go::
// recordBrowserTimings, endpoints/server/msghandler.go::
// MetricQurlResolveBrowser*.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestQurlBrowserTimings_ExtraFieldsDoNotChangeResponseShape fences
// the frontend↔backend drift contract: a POST to /plugins/qurl with
// the six t_*_ms fields attached must produce the same response
// shape (status, content-type, branded marker) as the same POST
// without them, for the bogus-token case. Uses the same syntactically-
// valid-but-nonexistent token shape as TestResolve_UnknownToken-
// Returns403_POST so the resolve handler reaches the same store-
// lookup-fails branch in both arms.
//
// Asserts on a control-arm-vs-instrumented-arm equality so the test
// doesn't have to hard-code the expected status code (a future change
// to the unknown-token response would update both arms together).
//
// Load-bearing assumption: the bogus token reliably routes to 403
// (not 502). handleResolveError returns 502 on
// ErrInvalidResolveResponse — that branch is structurally distinct
// from the not-found branch the bogus-token shape exercises.
// TestResolve_UnknownTokenReturns403_POST in 10_resolve_test.go
// already fences this; we rely on it transitively.
func TestQurlBrowserTimings_ExtraFieldsDoNotChangeResponseShape(t *testing.T) {
	bogus := "at_nonexistentyyyyyyyyyyy" // at_ + 22 chars; same shape as the bogus token in 10_resolve_test.go

	// Control arm: POST without timing fields.
	ctrlForm := url.Values{"token": {bogus}}.Encode()
	ctrlResp, ctrlBody := doPostFormNoRedirect(t, testConfig.NHPServerBaseURL, "/plugins/qurl", ctrlForm, nil)

	// Instrumented arm: POST with all six timing fields populated as
	// realistic-looking honest-browser values (under cap, non-zero,
	// no NaN/Inf — exercises the happy parse path on the server).
	instrForm := url.Values{
		"token":                {bogus},
		"t_dns_ms":             {"12"},
		"t_tcp_ms":             {"45"},
		"t_tls_ms":             {"90"},
		"t_ttfb_ms":            {"250"},
		"t_dom_interactive_ms": {"480"},
		"t_to_submit_ms":       {"1100"},
	}.Encode()
	instrResp, instrBody := doPostFormNoRedirect(t, testConfig.NHPServerBaseURL, "/plugins/qurl", instrForm, nil)

	// Status code parity: the timing fields must not change the
	// resolve outcome. Both arms hit the same branded-403 path.
	if ctrlResp.StatusCode != instrResp.StatusCode {
		t.Fatalf("status code drift: control=%d instrumented=%d (timing fields must not change outcome)",
			ctrlResp.StatusCode, instrResp.StatusCode)
	}
	assertStatusCode(t, instrResp, http.StatusForbidden)

	// Content-type parity: the access-denied page is HTML on both
	// arms; a content-type drift would mean recordBrowserTimings is
	// hijacking the response writer (it shouldn't — the plugin only
	// records metrics, never writes to the response).
	ctrlCT := ctrlResp.Header.Get("Content-Type")
	instrCT := instrResp.Header.Get("Content-Type")
	if ctrlCT != instrCT {
		t.Fatalf("content-type drift: control=%q instrumented=%q", ctrlCT, instrCT)
	}

	// Body shape: both arms produce the branded marker. We assert on
	// the marker rather than byte-equal bodies because some response
	// bodies include per-request request-IDs or timestamps.
	marker := accessLinkInvalidMarker
	if !strings.Contains(string(ctrlBody), marker) {
		t.Fatalf("control body does not contain marker %q (body: %s)", marker, truncate(ctrlBody, 400))
	}
	if !strings.Contains(string(instrBody), marker) {
		t.Fatalf("instrumented body does not contain marker %q (body: %s)", marker, truncate(instrBody, 400))
	}
}

// TestQurlBrowserTimings_AdversarialFieldsAreRejectedSilently fences
// the adversarial-input contract: a POST with NaN, out-of-range, and
// unparseable t_*_ms values must still produce the same response
// shape as a clean POST. The cap-then-drop + rejected-counter path
// in recordBrowserTimings handles the corruption inside the function
// without surfacing any error to the resolve handler. A regression
// where adversarial timing values caused a 5xx (e.g., a panic in
// strconv.ParseFloat handling, or a missing nil guard) would fail
// this test.
//
// The metric-emission verification (rejected counters increment) is
// out of scope for smoke — it requires CloudWatch — and is the right
// place for #1840's alarm-wiring tests.
func TestQurlBrowserTimings_AdversarialFieldsAreRejectedSilently(t *testing.T) {
	bogus := "at_nonexistentyyyyyyyyyyy"

	// Adversarial mix: NaN (case-insensitive), +Inf, negative,
	// over-cap, unparseable, empty. Covers every reject path in
	// recordBrowserTimings.
	adversarial := url.Values{
		"token":                {bogus},
		"t_dns_ms":             {"nan"},      // NaN guard
		"t_tcp_ms":             {"-1"},       // negative
		"t_tls_ms":             {"99999999"}, // over-cap
		"t_ttfb_ms":            {"Infinity"}, // +Inf → out-of-range
		"t_dom_interactive_ms": {"abc"},      // unparseable
		"t_to_submit_ms":       {""},         // empty (treated as absent)
	}.Encode()

	resp, body := doPostFormNoRedirect(t, testConfig.NHPServerBaseURL, "/plugins/qurl", adversarial, nil)

	// The bogus token still drives the response — adversarial timings
	// must not promote a 403 to a 5xx.
	assertStatusCode(t, resp, http.StatusForbidden)

	marker := accessLinkInvalidMarker
	if !strings.Contains(string(body), marker) {
		t.Fatalf("adversarial-fields body does not contain marker %q (body: %s)", marker, truncate(body, 400))
	}
}
