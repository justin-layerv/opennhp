//go:build smoke

package smoke

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Tier 1 regression fence for the qurl-service /internal/* public-ALB
// lockdown (qurl-service #335 PR4).
//
// FILE LAYOUT — two test categories live in this file:
//   1. RULE-COVERAGE FENCES: TestPublicALB_InternalPathReturns404
//      and TestPublicALB_HTTPRedirectStillReachesLockdown assert the
//      priority-1 rule fires the lockdown body shape (404 + JSON +
//      `{"error":"not found"}`). These exercise paths the rule
//      explicitly covers.
//   2. BACKEND-BACKSTOP FENCES: TestPublicALB_GinCaseBackstop,
//      TestPublicALB_PercentEncodedTraversalBackstop, and
//      TestPublicALB_PercentSlashSeparatorBackstop assert that
//      paths the rule INTENTIONALLY does NOT cover (uppercase, case-
//      traversal, %2e traversal, %2f separator) still don't produce
//      a successful response. These guard backend invariants the rule
//      explicitly delegates to (gin's case sensitivity, no decode-
//      then-route). The assertion shape is "not 2xx/3xx" rather than
//      "lockdown body" because the rule isn't supposed to fire on
//      these paths — the contract is the broader "public surface
//      doesn't serve them," not "the rule fences them."
//   3. INVERSE FENCE: TestPublicALB_PublicPathNotLockdownShaped
//      asserts known non-internal paths do NOT match the lockdown
//      shape (priority-1-glob-too-wide regression fence).
//
// SLOT BUDGET: AWS ALB caps a single path_pattern condition at 5
// values, and all 5 are used. Adding a 6th bypass class CANNOT
// extend the existing rule's path_pattern.values list — it requires
// a SECOND `aws_lb_listener_rule` at priority 2. Don't waste a plan
// cycle finding this out empirically; see the resource header in
// terraform/modules/qurl-service/main.tf for slot-budget guidance.
//
// Capability under test: the public ALB (api.layerv.{xyz,ai}) returns
// 404 for any /internal* path. Internal callers reach the surface via
// the internal ALB (internal-api.qurl.layerv.{xyz,ai}), fenced by the
// 07_ tests in this suite.
//
// Regression classes this fences:
//   - tfvars revert / Terraform refactor that drops
//     `aws_lb_listener_rule.public_internal_block`, opening the public
//     surface back up.
//   - Path-pattern drift where the rule is left in place but its
//     pattern is narrowed (e.g., back to `/internal/*` only without
//     the bare-prefix entry), re-opening the prefix-fishing class.
//   - Common case-variant bypass: AWS ALB `path_pattern` is case-
//     sensitive. The rule covers the two most likely typos (Title
//     case `/Internal*`); fully-uppercase and mixed-case variants
//     (`/INTERNAL/v1/resolve`, `/iNTERNAL/...`) are NOT covered by
//     the rule and rely on gin's case sensitivity at the backend.
//     This is a defense-in-depth gap, not a vulnerability — the
//     surface is closed; the body shape just differs (gin's
//     text/plain 404 vs ALB's `{"error":"not found"}`).
//   - Path-traversal bypass (`/foo/bar/../internal/...`): AWS ALB
//     performs RFC 3986 § 5.2.4 dot-segment removal on the request
//     path BEFORE matching against `path_pattern` conditions. So a
//     traversal-shaped attack like `/v1/qurls/../internal/v1/resolve`
//     is normalized to `/v1/internal/v1/resolve` and matches NONE of
//     the lockdown patterns — but it also can't reach the internal
//     handler, because the same normalized path is what arrives at
//     qurl-service's gin router. The `/*../internal/*` glob entry
//     therefore only fences "literal `..` substring with no real
//     traversal segment" (e.g., `/foo/bar../internal/baz` where
//     `bar..` is a single segment that doesn't trigger normalization)
//     — verified empirically by the `path_traversal_substring_only`
//     subtest below.
//     The positive-property fence for the canonical traversal class
//     is the `normalizes_to_canonical` subtest: probes
//     `/x/../internal/v1/resolve` and asserts the lockdown JSON fires.
//     Today this passes via canonical `/internal/*` after ALB's
//     pre-match dot-segment removal; under a hypothetical pass-through
//     flip at ALB, the same raw path would match the broad
//     `/*../internal/*` glob instead. The body shape is identical
//     across all 5 TF rule patterns (slot-budget patterns, not
//     subtests), so the fence cannot discriminate — it pins the
//     weaker contract "the lockdown rule still fires for canonical-
//     traversal-shaped paths" rather than which-pattern-matched.
//     Per-pattern discrimination is tracked at #1642.
//   - Fixed-response action accidentally swapped for a forward action
//     during a refactor, returning 200 from the qurl-service backend
//     for /internal/* on the public path. The body-shape assertion
//     below (Content-Type + literal body) is the discriminator.
//   - Redirect-action regression: someone swaps `fixed-response` for
//     a `redirect` action; the custom http.Client below disables
//     redirect-following so the assertion is strictly about what the
//     listener rule emitted, not what we eventually landed on.
//
// (Priority-collision shadow regressions are structurally eliminated
// by the rule's `priority = 1` — nothing can ever route over it, and
// AWS rejects priority collisions at apply. Per CLAUDE.md smoke-rule
// #5, no fence here for that class.)
//
// The check is a single-curl from the CI runner — no SSM, no AWS API.
// It runs unconditionally when the rollout's
// `NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED` env var is set (sourced by
// the smoke harness in setup_test.go); on greenfield envs without
// the lockdown wired the test skips cleanly via
// skipIfQurlInternalALBDisabled.

const (
	publicALBLockdownExpectedStatus = http.StatusNotFound
	publicALBLockdownExpectedCT     = "application/json"
	publicALBLockdownBodyCap        = 4096
)

// httpListenerOptOutEnvs marks environments that don't publish a
// public-ALB HTTP listener on port 80; the HTTP-redirect fence
// (TestPublicALB_HTTPRedirectStillReachesLockdown) skips cleanly
// in those envs rather than fataling on the pre-flight TCP probe.
//
// Empty today — both sandbox and prod publish port 80 via
// `aws_lb_listener.http` (the HTTP-to-HTTPS-301 redirect listener,
// present whenever `var.domain_name != null`). Add e.g.
// `"https-only-sandbox": true` once a greenfield env with
// HTTP-listener-disabled tfvars lands.
//
// FOURTH COORDINATION POINT: this map is a fourth env-keyed state
// that must update in lockstep with the three sites listed in
// dns.go::deriveEndpoints (the workflow `||` chain on
// NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED, the env case in dns.go
// itself, and the env's tfvars). #1640's SSM-sourced consolidation
// is the long-term fix for all four; until that lands, adding a
// new env requires four edits.
var httpListenerOptOutEnvs = map[string]bool{}

// publicALBLockdownExpectedBody is the parsed shape of the fixed-response
// body the listener rule emits. Comparing parsed maps (not raw strings)
// keeps this assertion stable against benign re-encodings — key reorder,
// whitespace, escaped vs unescaped characters — that AWS could introduce
// without semantically changing the response. The contract under test is
// "the body decodes to {error: not found}", not "the body is one specific
// byte sequence".
//
// Coordinated change required: the lockdown body shape is duplicated in
// `terraform/modules/qurl-service/main.tf::aws_lb_listener_rule.public_internal_block`'s
// `fixed_response.message_body`. If that ever changes (e.g., switching
// to gin's text/plain to close the body-shape fingerprint leak — see
// resource header), this constant + the type of `publicALBLockdownExpectedBody`
// + every test that asserts it must be updated in the SAME PR. There
// is no compile-time link between the TF and Go sides of this contract.
//
// Type is `map[string]string` — load-bearing. A future body-shape change
// adding a numeric or object field (e.g.,
// `{"error":"not found","retry_after":30}`) would fail to decode into
// this map. That's the desired behavior — a body-shape change should
// fail the test loudly so the maintainer revisits the contract — but
// the failure surfaces as a parse error, not a body-mismatch. New
// string-valued keys (e.g., `request_id`) decode fine and fail loudly
// on `maps.Equal`.
var publicALBLockdownExpectedBody = map[string]string{"error": "not found"}

// TestPublicALB_InternalPathReturns404 covers each regression class
// enumerated above with its own subtest. Adding a new bypass class
// is one row in this table — keeps the suite single-source-of-truth
// as the lockdown pattern set evolves.
//
// Method coverage: ALB path_pattern conditions are method-agnostic,
// so a working rule 404s every method on a covered path. The
// `primary_post` case asserts this directly — POST is the production
// method on /internal/v1/resolve, and an http_request_method
// condition added to the rule (narrowing it to GET only) would
// regress the production path silently otherwise. Other cases stay
// GET-only by design: the fences they protect are path-class, not
// method-class, and the production threat model is GET enumeration +
// POST /resolve. A future http_request_method rule that narrowed
// method on a non-primary path (e.g., case_variant on GET only)
// would slip past this fence — accepted gap, not an oversight.
//
// OPTIONS / CORS preflight: the lockdown is intentionally
// method-agnostic — OPTIONS gets 404'd alongside GET/POST/PUT.
// `/internal/v1/*` is a service-to-service surface (no browser
// consumer today), so the lockdown's "no Access-Control-Allow-*
// headers, just 404" response is correct: a browser preflight
// would fail loudly rather than silently land on a permissive
// CORS response from a fall-through default. If a browser
// consumer is ever introduced, that consumer's CORS contract
// belongs at a different ALB rule (or a different listener
// entirely), NOT at the lockdown.
//
// Wire-side normalization: see file header (Path-traversal bypass)
// for the ALB-normalize-before-match contract pinned by the
// `normalizes_to_canonical` subtest. Go-side preservation of `..`
// at URL-build time is fenced by the pre-flight in
// assertPublicLockdownReturns404; the which-pattern-matched
// discrimination gap is in the same helper's comment.
//
// Regression fence for PR #1635 (qurl-service #335 PR4).
func TestPublicALB_InternalPathReturns404(t *testing.T) {
	skipIfQurlInternalALBDisabled(t)

	// Slash-spanning `*` semantics — triage routing:
	// AWS ALB's `path_pattern` `*` matches ANY character including `/`
	// (the "0 or more of any character" semantics, per AWS docs). The
	// `primary` case is the load-bearing fence for this property:
	// matching `/internal/v1/resolve` against `/internal/*` requires
	// `*` to span `/`. A silent AWS change to path-segment-bounded `*`
	// would fail `primary`, `primary_post`, `case_variant`,
	// `with_query_string`, `path_traversal_substring_only`, and
	// `normalizes_to_canonical` — any case whose matching pattern has
	// `*` adjacent to a `/` it must span. `bare_prefix_trailing_slash`
	// fences a different axis (`*`-accepts-zero-chars), not this one.
	// If you're triaging an ALB-`*`-semantics regression, start with
	// `primary` — the others co-fall but `primary` is the simplest
	// minimal repro.
	cases := []struct {
		name   string
		method string
		path   string
		// why is the regression class this case fences. Comments
		// here describe what would change to make the test fail in
		// a way that pinpoints the bypass.
		why string
	}{
		{
			name:   "primary",
			method: http.MethodGet,
			path:   "/internal/v1/resolve",
			why:    "the canonical /internal/v1/* path the body-src_ip handler lives on. Also the minimal-repro fence for AWS ALB's slash-spanning `*` semantics — see the comment block above this slice for the full triage map",
		},
		{
			name:   "primary_post",
			method: http.MethodPost,
			path:   "/internal/v1/resolve",
			why:    "POST is the production method on /internal/v1/resolve; an http_request_method condition narrowing the rule to GET would silently regress the prod path while every other case here still passed",
		},
		{
			name:   "bare_prefix",
			method: http.MethodGet,
			path:   "/internal",
			why:    "ALB path_pattern matches /internal/* on at-least-one char after the slash; the bare /internal entry on the rule fences the prefix-fishing class",
		},
		{
			name:   "bare_prefix_trailing_slash",
			method: http.MethodGet,
			path:   "/internal/",
			why:    "AWS ALB path_pattern `*` accepts zero chars, so `/internal/*` matches `/internal/` (trailing slash, nothing after). Hardens that AWS-`*`-semantics assumption — if AWS ever changed `*` to require ≥1 char, the prefix-fishing fence would quietly degrade and only `/internal` (literal) would catch the bare class",
		},
		{
			name:   "with_query_string",
			method: http.MethodGet,
			path:   "/internal/v1/resolve?foo=bar&baz=qux",
			why:    "AWS ALB strips query string before path_pattern matching, so the rule matches against `/internal/v1/resolve`. Fences a hypothetical regression where someone adds a `query_string` condition to the rule that narrows the match — that would let `?foo=bar` paths fall through to the default forward",
		},
		{
			name:   "case_variant",
			method: http.MethodGet,
			path:   "/Internal/v1/resolve",
			why:    "AWS ALB path_pattern is case-sensitive; without the case entry on the rule, /Internal/v1/resolve falls through to the default forward",
		},
		{
			name:   "path_traversal_substring_only",
			method: http.MethodGet,
			path:   "/foo/bar../internal/baz",
			why:    "the `/*../internal/*` glob matches paths with a literal `../internal/` substring where `..` is NOT a real traversal segment (here `bar..` is a single non-traversal segment, so AWS ALB's pre-match dot-segment normalization leaves the path unchanged). Fences a regression that narrowed the glob to require a true `/../` separator — see `normalizes_to_canonical` below for the canonical-traversal class fence. NOTE: if a future legitimate public path ever needs literal `../internal/` substrings (tracked in #1641), the fix would split this fence — replace the broad glob with narrower entries that exclude the legitimate path, and update this case to assert the narrower coverage.",
		},
		// normalizes_to_canonical: documentation fence rather than a
		// discriminating one. `/x/../internal/v1/resolve` normalizes
		// to `/internal/v1/resolve` and matches the canonical entry
		// today; under a hypothetical ALB pass-through flip it would
		// still match the broad `/*../internal/*` glob, and the body
		// shape is identical across all 5 TF rule patterns
		// (slot-budget patterns, not subtests), so this case cannot
		// tell which pattern fired — see #1642 for the structural
		// fix (per-pattern discriminator on the listener rule).
		//
		// Path-choice rationale: post-normalization must address an
		// internal route. Non-traversal forms like
		// `/v1/qurls/../internal/...` normalize to
		// `/v1/internal/...`, hit no internal handler, and are not
		// worth fencing. `/x/../internal/v1/resolve` is the minimal
		// canonical-traversal shape that lands on `/internal/*`.
		//
		// Empirical verification: PR #1893 (curl `--path-as-is`
		// probes triangulating ALB's dot-segment normalization).
		{
			name:   "normalizes_to_canonical",
			method: http.MethodGet,
			path:   "/x/../internal/v1/resolve",
			why:    "positive-property documentation fence — the lockdown still fires for canonical-traversal-shaped paths whose post-normalization form lands on `/internal/*`. See comment above this case for the path-choice and indiscriminability rationale",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertPublicLockdownReturns404(t, tc.method, tc.path, tc.why)
		})
	}
}

// method is the HTTP method on the request; path is the request path
// being asserted; why is the regression class this case fences. why
// threads into failure messages so a future engineer triaging a red
// test sees the bug class label inline, not just in the file's prose
// comment block.
//
// Failure surface note: a non-JSON 404 (e.g., gin's text/plain
// "404 page not found") fails this helper at the json.Unmarshal step
// with a parse error, not a body-mismatch. The failure message names
// both the raw body and the regression class so triage doesn't chase
// the wrong root cause — but if the smoke fence ever surfaces a
// fixed-response → forward regression where the backend hands back a
// non-JSON body, expect the parse-error framing.
func assertPublicLockdownReturns404(t *testing.T, method, path, why string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	fullURL := testConfig.QURLAPIBaseURL + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	// Verify Go's net/http URL build preserves the literal path — no
	// `..` collapsing, no case folding, no percent-encoding shifts.
	// If a future Go release ever changes this, the
	// `normalizes_to_canonical` case would silently shift fences:
	// e.g., `/x/../internal/v1/resolve` pre-collapsed to
	// `/internal/v1/resolve` by Go before send would still match the
	// canonical `/internal/*` entry and pass — but it would pass via
	// the canonical-shape pattern, not the post-ALB-normalize pattern,
	// silently invalidating the ALB-normalizes-before-matching
	// assumption that case exists to pin.
	//
	// Pre-flight covers `url.Parse` and the request build, NOT the
	// Transport.RoundTrip stage. Go's HTTP/1 and HTTP/2 transports
	// both write `req.URL.RequestURI()` verbatim today (no late
	// normalization), so the pre-flight is sufficient for the
	// Go-side preservation contract. The fixed-response is identical
	// across all 5 TF rule patterns (the slot-budget count, not the
	// subtest count), so we still can't discriminate
	// which pattern matched without server-side plumbing — accepted
	// gap; the right structural fix is a per-pattern discriminator on
	// the listener rule (custom response header or Lambda target),
	// tracked at #1642.
	if got, want := req.URL.RequestURI(), path; got != want {
		t.Fatalf("request URI = %q, want %q (transport unexpectedly normalized the path; regression class: %s)", got, want, why)
	}

	// testConfig.NoRedirectClient (setup_test.go) is the suite-wide
	// `CheckRedirect = ErrUseLastResponse` client — same pattern used
	// by 10_resolve_test.go and 15_resolve_accept_negotiation_test.go.
	// The 10s context timeout above is enforced via NewRequestWithContext
	// regardless of the client's own Timeout field. Disabling redirect
	// following ensures the assertion is strictly about what the
	// listener rule emitted, not what we eventually landed on — a
	// hypothetical fixed-response → redirect swap would be hidden by
	// the default 10-redirect-follow client otherwise.
	resp, err := testConfig.NoRedirectClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, fullURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != publicALBLockdownExpectedStatus {
		t.Errorf("%s %s: status = %d, want %d (regression class: %s)", method, fullURL, resp.StatusCode, publicALBLockdownExpectedStatus, why)
	}

	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, publicALBLockdownExpectedCT) {
		t.Errorf("%s %s: Content-Type = %q, want prefix %q (regression class: %s)", method, fullURL, got, publicALBLockdownExpectedCT, why)
	}

	body := readCappedBody(t, resp)
	// Decode-then-compare keeps the assertion stable against benign
	// re-encodings (key order, whitespace, escape style) that AWS
	// could introduce without changing the response semantics. A
	// hypothetical body-shape regression (e.g., the rule swapped to
	// `{"message":"..."}`) still fails on map equality.
	// `map[string]string` (not `map[string]any`) so a future body-shape
	// addition of a non-string field (e.g., `retry_after: 30`) fails
	// loudly at unmarshal — the failure surface is "schema evolved",
	// not "body malformed". The error message names both possibilities
	// so a maintainer triaging a non-JSON 404 (gin fixed-response
	// regression) vs a schema-added-numeric-field doesn't chase the
	// wrong root cause.
	var got map[string]string
	if err := json.Unmarshal(body, &got); err != nil {
		t.Errorf("%s %s: body = %q failed to decode into map[string]string: %v (regression class: %s). Likely cause: (a) fixed-response → forward regression returning a non-JSON body, OR (b) lockdown body schema evolved to include a non-string field (e.g., retry_after) — in case (b), widen the decode type to map[string]any and update publicALBLockdownExpectedBody to match.", method, fullURL, string(body), err, why)
		return
	}
	if !maps.Equal(got, publicALBLockdownExpectedBody) {
		t.Errorf("%s %s: body decoded to %v, want %v (regression class: %s)", method, fullURL, got, publicALBLockdownExpectedBody, why)
	}
}

// TestPublicALB_PublicPathNotLockdownShaped fences the
// priority-1-glob-too-wide regression class: a future edit that
// broadens path_pattern (e.g., to `/v1/*` or `/*`) would silently
// start 404-ing legitimate public paths with the lockdown body
// shape. Assert the inverse — a known non-internal path must NOT
// respond with the lockdown triple (`404 + Content-Type: application/json
// + body == {"error":"not found"}`).
//
// Probe: `/v1/qurls` — a real production path. Catches the
// "rule pattern broadened to /v1/* or wider" regression. Unauth
// GET returns 401 from Auth0 today (different body shape), so the
// assertion holds without test-side credentials.
//
// Backend coupling note: this case is the only `TestPublicALB_*`
// case that reaches a real Auth0-fronted handler instead of the
// listener-rule fixed-response. If smoke ever runs in parallel
// across many PRs against sandbox, watch this case for `429`s
// from Auth0 — the other 09_* cases hit ALB-only and are
// rate-limit-safe at any fanout. A 429 here is not a regression
// in the lockdown; if it shows up, switch to a 404-routed
// alternative probe (any non-prefix-of-`/internal*` path the rule
// can't match) — the contract under test is "priority 1 doesn't
// match this path," not "this path returns 401."
//
// PRIOR `/internalfoo` PROBE REMOVED: a previous version of this
// test included `/internalfoo` to fence the narrower regression
// where a maintainer replaces `/internal` (literal) with
// `/internal*` (glob) in the rule's path_pattern values. That
// case load-beared on qurl-service emitting gin's text/plain
// default 404 — a cross-repo body-shape coupling. If qurl-service
// ever shipped a JSON 404 middleware, the case would false-
// positive without anyone touching nhp. The replacement-with-glob
// regression is also visible in TF review of the rule's values
// list, while a cross-repo body-shape change is not. The case was
// dropped to remove the cross-repo fragility; lean on TF review for
// the literal→glob class. The proper structural fix (a non-body-
// shape discriminator — e.g., a custom response header on the
// fixed_response action, which AWS ALB does NOT support today, or
// a Lambda target group emitting headers) is tracked at #1642.
//
// Any non-lockdown response (200, 401, 403, even a 404 with a
// different body) is a pass — the contract under test is "priority
// 1 doesn't match this path", not "this path returns a specific
// status".
//
// Regression fence for PR #1635 (qurl-service #335 PR4).
func TestPublicALB_PublicPathNotLockdownShaped(t *testing.T) {
	skipIfQurlInternalALBDisabled(t)

	cases := []struct {
		name string
		path string
		why  string
	}{
		{
			name: "v1_qurls",
			path: "/v1/qurls",
			// TODO(429-swap): if this case ever starts flaking with
			// HTTP 429 from Auth0 under parallel smoke fanout
			// against sandbox, switch the path to a route that the
			// rule can't match but the backend serves cheaply WITHOUT
			// Auth0 (a candidate is `/v1/billing/portal` — it goes to
			// Auth0 same as /v1/qurls, so NOT this one; the safer
			// swap is to introduce a new tier-3 inverse-fence probe
			// against an unauthenticated public path like `/health`
			// if one is added to qurl-service, or to drop the case
			// and lean on the `root` case below). The contract
			// under test is "priority 1 doesn't match this path",
			// not "this path returns 401" — any non-lockdown shape
			// is acceptable.
			why: "real production path; catches a rule pattern broadened to /v1/* or wider",
		},
		{
			// Root path adds a different prefix-family probe so a
			// hypothetical broadening that affects one path-family
			// but not the other doesn't slip past. Examples the two
			// probes together catch (one probe alone wouldn't):
			//   - rule narrowed to `/v1/qu*` but still misses some
			//     `/v1/*` paths → /v1/qurls fences /v1/qu* class.
			//   - rule broadened to `/*` → root fences this class.
			// Root is not Auth0-fronted (no middleware on unrouted
			// paths) so it carries no 429 risk under parallel smoke
			// fanout, unlike the /v1/qurls probe.
			name: "root",
			path: "/",
			why:  "different-prefix-family probe; catches a rule broadening that affects root or a non-/v1 prefix without touching /v1/qurls",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertPublicPathNotLockdownShaped(t, tc.path, tc.why)
		})
	}
}

func assertPublicPathNotLockdownShaped(t *testing.T, path, why string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	fullURL := testConfig.QURLAPIBaseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	resp, err := testConfig.NoRedirectClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", fullURL, err)
	}
	defer resp.Body.Close()

	body := readCappedBody(t, resp)

	// Compute the three discriminators independently so a failure
	// message names exactly which axis matched the lockdown shape.
	statusMatches := resp.StatusCode == publicALBLockdownExpectedStatus
	ctMatches := strings.HasPrefix(resp.Header.Get("Content-Type"), publicALBLockdownExpectedCT)
	bodyMatches := false
	var parsed map[string]string
	if json.Unmarshal(body, &parsed) == nil {
		bodyMatches = maps.Equal(parsed, publicALBLockdownExpectedBody)
	}

	if statusMatches && ctMatches && bodyMatches {
		t.Errorf("GET %s matched the lockdown shape (status=%d + CT=%q + body=%v).\n  Triage: this is a TWO-CAUSE failure — investigate in this order:\n    (A) terraform/modules/qurl-service/main.tf — was `aws_lb_listener_rule.public_internal_block`'s path_pattern broadened (the regression this fence is for)?\n    (B) qurl-service backend middleware — did a JSON 404 handler ship that emits the lockdown body shape (which would falsely trip this fence even with the rule unchanged)?\n  Per-case context: %s", fullURL, resp.StatusCode, resp.Header.Get("Content-Type"), parsed, why)
	}
}

// TestPublicALB_GinCaseBackstop is a belt-and-suspenders fence
// for the case-variant + case-traversal defense-in-depth gaps. The
// listener rule's path_pattern set explicitly omits two classes:
//
//   - Fully-uppercase (`/INTERNAL*`): the rule covers `/Internal*`
//     (Title case) but not all-caps. AWS ALB path_pattern is case-
//     sensitive on raw bytes.
//   - Title-case + traversal (`/*../Internal/*`): explicitly omitted
//     from the 5-slot path_pattern budget. Backstopped by gin's
//     case sensitivity at the resolve handler (registered under
//     lowercase `/internal/v1/resolve`).
//
// Both classes are backstopped today by gin (qurl-service's router):
// the unrouted path 404s at the backend. This test fences a future
// qurl-service router migration to a case-folding mux (e.g., chi
// with case-insensitive routing, or a new http.ServeMux variant) —
// either path would reach the resolve handler. Even unauthenticated
// requests would not return 200, but the contract is the broader
// "the public surface does not serve these path variants with a
// successful response under any future router migration."
//
// Assertion is intentionally weak — the contract is "this path
// does NOT result in a successful resolve OR a redirect to one,"
// not "this path returns a specific shape." Failing on 2xx OR 3xx
// catches both: a 200 from a case-folding router that reached the
// handler, AND a 3xx from a future case-folding redirect rule
// (e.g., /INTERNAL/* → /internal/*) that would land on a successful
// response after the redirect. NoRedirectClient surfaces the 3xx
// as the response status without following it.
//
// Helper assertion shape differs from `assertPublicLockdownReturns404`
// because the rule does NOT cover these paths — the existing helper's
// lockdown-body check would fail. Separate test keeps both contracts
// crisp.
//
// Regression fence for PR #1635 (qurl-service #335 PR4).
func TestPublicALB_GinCaseBackstop(t *testing.T) {
	skipIfQurlInternalALBDisabled(t)

	cases := []struct {
		name string
		path string
		why  string
	}{
		{
			name: "uppercase",
			path: "/INTERNAL/v1/resolve",
			why:  "fully-uppercase — rule covers /Internal* (Title case) but not all-caps; backed by gin case sensitivity",
		},
		{
			name: "case_traversal",
			path: "/v1/qurls/../Internal/v1/resolve",
			why:  "Title-case + traversal — explicitly omitted from the 5-slot path_pattern budget; backed by gin case sensitivity",
		},
		{
			name: "uppercase_traversal",
			path: "/v1/qurls/../INTERNAL/v1/resolve",
			why:  "Fully-uppercase + traversal — covered by neither the rule's `/Internal*` Title-case entry nor the lowercase `/*../internal/*` glob; backed by gin case sensitivity. Closes the matrix corner that pairs the uppercase gap with the traversal gap",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			t.Cleanup(cancel)

			fullURL := testConfig.QURLAPIBaseURL + tc.path
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}

			resp, err := testConfig.NoRedirectClient.Do(req)
			if err != nil {
				t.Fatalf("GET %s: %v", fullURL, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				t.Errorf("GET %s: status = %d (2xx or 3xx) — path produced a successful response or a redirect that could land on one. Likely cause: qurl-service migrated to a case-folding router and the listener rule's case-variant entries no longer cover this class, OR a case-folding redirect rule was added (e.g., /INTERNAL/* → /internal/*). Fix: add the missing path_pattern entries to a SECOND aws_lb_listener_rule at priority 2 (5/5 slots are full on the priority-1 rule), or restore case-sensitive routing at the backend. Per-case context: %s", fullURL, resp.StatusCode, tc.why)
			}
		})
	}
}

// TestPublicALB_PercentEncodedTraversalBackstop fences the
// percent-encoded traversal bypass class. The lockdown rule's
// `/*../internal/*` entry covers literal `..` segments only — AWS
// ALB documentation says path_pattern matches operate on the raw
// URL before percent-decoding, so `%2e%2e` (or `%2E%2E`) in the
// path falls through the rule.
//
// Today this is benign: gin (qurl-service's router) does not
// decode-then-route by default, so a request like
// `/v1/qurls/%2e%2e/internal/v1/resolve` arrives at the backend
// as the literal path, doesn't match any registered route, and
// returns text/plain 404. The surface stays closed; only the body
// shape differs from the lockdown JSON.
//
// The regression vectors fenced here:
//   - AWS changes ALB path_pattern to decode-before-match (silent
//     policy flip): the request would still 404 via the canonical
//     pattern AFTER decode, so this test would still pass — but
//     the assertion shape ("non-2xx/non-3xx") doesn't depend on
//     which side of the decode question we're on.
//   - qurl-service migrates to a router that decodes-then-routes
//     (e.g., `net/http.ServeMux` or chi with path-cleaning): the
//     request would route to the resolve handler. Without service
//     token, returns 401 (still not 200). With a future bypass on
//     the auth check, could 200 — this fence catches that.
//   - HTTP/2 transport-level normalization at ALB silently
//     decodes `%2e%2e` before path_pattern matching (Go's
//     net/http2 has shifted here before): same as case 1.
//
// Probes both case variants for both `%2e` (encoded `..`) and
// `%2f` (encoded `/`) since AWS ALB path_pattern is case-sensitive
// on the raw bytes. See #1638 for the manual verification of ALB
// percent-decode behavior — this fence converts it from a one-time
// curl into a permanent regression fence at no path_pattern slot
// cost.
//
// Regression fence for PR #1635 (qurl-service #335 PR4) and #1638.
func TestPublicALB_PercentEncodedTraversalBackstop(t *testing.T) {
	skipIfQurlInternalALBDisabled(t)

	cases := []struct {
		name string
		path string
	}{
		{name: "lowercase_2e", path: "/v1/qurls/%2e%2e/internal/v1/resolve"},
		{name: "uppercase_2e", path: "/v1/qurls/%2E%2E/internal/v1/resolve"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertPercentEncodedPathNotSuccessful(t, tc.path)
		})
	}
}

// TestPublicALB_PercentSlashSeparatorBackstop fences the
// percent-encoded `/` separator bypass class. Distinct from
// TestPublicALB_PercentEncodedTraversalBackstop's `%2e` traversal:
// the `%2f` / `%2F` encoding hides the path separator itself, so
// the path-pattern matcher sees a single segment rather than the
// `/internal/v1/...` segment chain.
//
// `/internal%2fv1%2fresolve`:
//   - Does NOT match the rule's `/internal/*` entry (path_pattern
//     requires the literal `/` after `internal`).
//   - Does NOT match the `/internal` literal entry (not an exact
//     match).
//
// Today benign — either ALB rejects paths containing `%2F` with
// 400 at the listener (configuration-dependent), or gin's default
// 404 fires if ALB passes through. Either way non-2xx/non-3xx.
// The soak-time curl (test plan) determines which layer is the
// load-bearing rejector.
//
// Joint-regression fence: same shape as the `%2e` traversal class
// — a 2xx requires BOTH (a) decode-before-match at ALB or backend
// AND (b) auth-layer bypass at qurl-service#439. A single-axis
// regression won't trip this case.
//
// Regression fence for PR #1635 (qurl-service #335 PR4) and #1638.
func TestPublicALB_PercentSlashSeparatorBackstop(t *testing.T) {
	skipIfQurlInternalALBDisabled(t)

	cases := []struct {
		name string
		path string
	}{
		{name: "lowercase_2f", path: "/internal%2fv1%2fresolve"},
		{name: "uppercase_2f", path: "/internal%2Fv1%2Fresolve"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertPercentEncodedPathNotSuccessful(t, tc.path)
		})
	}
}

// assertPercentEncodedPathNotSuccessful is the shared assertion
// shared between the %2e (traversal) and %2f (separator) test
// classes. Builds a request with the exact literal path, verifies
// Go's transport doesn't normalize it before sending, dispatches
// without following redirects, and fails the test on any 2xx/3xx
// response.
//
// Pre-flight `req.URL.RequestURI() == path` catches Go-side
// regressions (canonicalization, decode, HTTP/2 normalization)
// that would silently shift this fence to a different bypass
// class. A Contains check would be too weak — a partial decode
// (e.g., `%2f → /`) would still contain `%2` but fence the wrong
// thing.
func assertPercentEncodedPathNotSuccessful(t *testing.T, path string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	fullURL := testConfig.QURLAPIBaseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if got := req.URL.RequestURI(); got != path {
		t.Fatalf("request URI = %q, want %q — Go transport altered the path before sending. Likely causes: (a) url.Parse canonicalized percent-encoding case (e.g., %%2f → %%2F or vice versa), (b) transport decoded the percent-encoded segment, (c) HTTP/2 path canonicalization shifted bytes. This test would silently stop fencing the percent-encoded class.", got, path)
	}

	resp, err := testConfig.NoRedirectClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", fullURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		// JOINT-REGRESSION-ONLY fence — failing requires BOTH:
		//   (A) ALB or transport decodes percent-encoded segments
		//       before path_pattern matching, AND
		//   (B) the auth-layer X-Service-Token check at the
		//       qurl-service /internal/v1/* handler bypasses
		//       (tracked at qurl-service#439).
		t.Errorf("GET %s: status = %d (2xx or 3xx) — percent-encoded path produced a successful response or a redirect that could land on one. JOINT-REGRESSION TRIAGE: both axes must regress for this fence to fire.\n  (A) Decode-side: did ALB start decoding %%2e/%%2f before path_pattern matching (silent policy flip)? OR did qurl-service migrate to a router that decodes-then-routes? See #1638 for the manual verification of ALB decode behavior.\n  (B) Auth-side: did the X-Service-Token check at /internal/v1/* handlers bypass? See qurl-service#439 for the Tier-2 fence on that auth-layer contract.\n  If only (A) regressed, the lockdown's `/*../internal/*` glob already catches the post-decode form (for %%2e variants) and this test passes via that route — i.e., a 2xx here implies (B) is the load-bearing failure.", fullURL, resp.StatusCode)
	}
}

// TestPublicALB_HTTPRedirectStillReachesLockdown probes the http://
// (port 80) entry point for /internal/*. The HTTP listener is
// configured to 301 → HTTPS when `domain_name != null`, so the
// follow-redirect client should land on the HTTPS listener's
// priority-1 rule and get the lockdown 404. Fences the regression
// class where someone disables the HTTP-to-HTTPS redirect (the HTTP
// listener's default action becomes forward to TG; /internal/*
// would forward unencrypted to qurl-service on port 8080) OR adds a
// parallel rule on the HTTP listener that doesn't include the
// /internal/* lockdown patterns.
//
// Uses a default-config http.Client (follows redirects up to 10) —
// NOT the suite's NoRedirectClient. The lockdown-after-redirect
// assertion is the whole point of this test, so redirect-following
// is the correct mode here.
//
// Regression fence for PR #1635 (qurl-service #335 PR4).
func TestPublicALB_HTTPRedirectStillReachesLockdown(t *testing.T) {
	t.Parallel()
	skipIfQurlInternalALBDisabled(t)

	// Use url.Parse so a future QURLAPIBaseURL that includes a path
	// segment (e.g., `https://api.layerv.xyz/api`) doesn't silently
	// produce `http://api.layerv.xyz/api/internal/v1/resolve` and
	// fence a different path class than this test intends.
	parsedBase, err := url.Parse(testConfig.QURLAPIBaseURL)
	if err != nil {
		t.Fatalf("parse QURLAPIBaseURL = %q: %v", testConfig.QURLAPIBaseURL, err)
	}
	if parsedBase.Scheme != "https" {
		t.Fatalf("QURLAPIBaseURL scheme = %q; expected https", parsedBase.Scheme)
	}
	// Hostname() strips any port from QURLAPIBaseURL — if a future env
	// ever sets it to e.g. `https://api.layerv.xyz:8443`, we still
	// hit `http://api.layerv.xyz/internal/v1/resolve` (port 80) rather
	// than `http://api.layerv.xyz:8443/...` which would target the
	// HTTPS port over plaintext. Port-stripping keeps this test
	// targeting the actual HTTP listener regardless of base-URL shape.
	//
	// PORT 80 ASSUMPTION: this test assumes the public ALB has an HTTP
	// listener on port 80 that 301-redirects to HTTPS (which it does
	// today via aws_lb_listener.http when domain_name != null — see
	// terraform/modules/qurl-service/main.tf). Pre-flight TCP probe
	// turns "no HTTP listener on this env" into a clean t.Skipf
	// rather than an opaque "connection refused" failure mid-test —
	// keeps the suite greenfield-tolerant for a future env that
	// publishes only HTTPS.
	hostname := parsedBase.Hostname()

	// Pre-flight TCP probe runs on its own context so the request
	// budget below is not pre-spent on a probe that exists only to
	// short-circuit a skip path. A worst-case 5s probe would
	// otherwise consume half the 10s request budget before the real
	// GET runs.
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer probeCancel()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	probeConn, probeErr := dialer.DialContext(probeCtx, "tcp", hostname+":80")
	// Defensive close in case Go ever returns a non-nil conn AND a
	// non-nil err simultaneously (rare per the net.Dialer contract,
	// but the cost of leaking a conn here is non-zero — kept the
	// close idempotent so the success branch below is a no-op when
	// reached, and the error branches don't need to repeat it).
	if probeConn != nil {
		_ = probeConn.Close()
	}
	// Any non-nil probe error is treated uniformly. ECONNREFUSED and
	// DeadlineExceeded are the canonical "no listener on port 80"
	// signals, but other dial errors (EHOSTUNREACH, ENETUNREACH,
	// DNS resolution failure) are equally diagnostic — they all
	// mean the pre-flight failed to reach the HTTP listener. By
	// surfacing all of them through the opt-out / fatal branch with
	// the underlying error attached, a triaging engineer sees the
	// probe-stage cause in the failure message rather than the
	// less-diagnostic client.Do error that would otherwise follow
	// when execution fell through to the real request. The branch
	// names the specific error for readability; opt-out envs short-
	// circuit cleanly without paying the request budget.
	if probeErr != nil {
		if !httpListenerOptOutEnvs[testConfig.Environment] {
			t.Fatalf("HTTP listener on port 80 unreachable for %s in env %q: %v — current envs publish HTTP via aws_lb_listener.http on the public ALB. Likely causes: (a) the resource was dropped or its default action was mis-edited, (b) public DNS for %s does not resolve (NXDOMAIN/SERVFAIL), or (c) the host route is filtered (EHOSTUNREACH/ENETUNREACH). If a future HTTPS-only env should skip this fence, add it to httpListenerOptOutEnvs in this test.", hostname, testConfig.Environment, probeErr, hostname)
		}
		t.Skipf("HTTP listener on port 80 unreachable for %s in opt-out env %q (%v) — skipping HTTPRedirect fence", hostname, testConfig.Environment, probeErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	httpURL := "http://" + hostname + "/internal/v1/resolve"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	// Local client with default redirect policy (follow up to 10
	// hops). The zero-value `&http.Client{}` matches DefaultClient's
	// redirect behavior. NoRedirectClient (suite-wide) would stop at
	// the 301 and never assert the lockdown landing, so we don't
	// reuse that here. Timeout matches NoRedirectClient's 15s for
	// consistency, though the request-level context above (10s) is
	// the binding limit.
	//
	// Note on isolation: this client is isolated for redirect policy
	// and timeout, but it still resolves to `http.DefaultTransport`
	// (Transport is unset). A test that ever mutated
	// `DefaultTransport.Proxy` / `TLSClientConfig` elsewhere in the
	// suite would affect this client. No test in tests/smoke/ does
	// today; if a future one does, construct a private `&http.Transport{}`
	// here to fully isolate.
	//
	// CheckRedirect captures the chain so a redirect-loop regression
	// (e.g., HTTPS listener configured to 301 back to HTTP on
	// /internal/*) surfaces with the actual hop list — not just the
	// generic "stopped after 10 redirects" Go default. The hop count
	// limit matches default behavior so non-loop redirects aren't
	// rejected.
	//
	// `hops` is captured by closure with no synchronization — safe
	// today because Go's net/http documents CheckRedirect as called
	// synchronously on the goroutine that invoked Do. If a future
	// refactor ever wraps this client in errgroup or otherwise calls
	// Do concurrently from multiple goroutines, the closure becomes
	// racy.
	var hops []string
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			hops = append(hops, req.URL.String())
			if len(via) >= 10 {
				return fmt.Errorf("redirect chain exceeded 10 hops on %s — possible loop. Hops: %v", httpURL, hops)
			}
			return nil
		},
	}
	t.Cleanup(client.CloseIdleConnections)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", httpURL, err)
	}
	defer resp.Body.Close()

	// Surface the redirect chain unconditionally so any downstream
	// status/CT/body assertion failure has the actual hop list in
	// the failure log — without it, a triaging engineer can't tell
	// whether the chain went through expected hops or detoured
	// (e.g., CloudFront-fronted ALB that redirects via a different
	// hostname on a misconfigured cert).
	t.Logf("GET %s: redirect chain hops=%v final=%s status=%d", httpURL, hops, resp.Request.URL, resp.StatusCode)

	if resp.StatusCode != publicALBLockdownExpectedStatus {
		t.Errorf("GET %s (after redirect): status = %d, want %d (regression class: HTTP-to-HTTPS redirect disabled or HTTP listener has parallel rule without lockdown)", httpURL, resp.StatusCode, publicALBLockdownExpectedStatus)
	}

	// CT check matches the assertion shape used by
	// assertPublicLockdownReturns404 — fences a hypothetical regression
	// where the redirect target serves a custom 404 with a non-JSON
	// content type but the right body shape (e.g., a custom 404 handler
	// page emitting `{"error":"not found"}` as text/html). Status + body
	// alone wouldn't catch that.
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, publicALBLockdownExpectedCT) {
		t.Errorf("GET %s (after redirect): Content-Type = %q, want prefix %q", httpURL, got, publicALBLockdownExpectedCT)
	}

	body := readCappedBody(t, resp)
	var parsed map[string]string
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Errorf("GET %s (after redirect): body = %q does not parse as JSON object: %v", httpURL, string(body), err)
		return
	}
	if !maps.Equal(parsed, publicALBLockdownExpectedBody) {
		t.Errorf("GET %s (after redirect): body decoded to %v, want %v", httpURL, parsed, publicALBLockdownExpectedBody)
	}
}

// readCappedBody reads up to publicALBLockdownBodyCap bytes off resp.Body
// and t.Fatal's with a discriminating message if the body would have been
// larger. The cap-then-fatal pattern surfaces overflow as "body too large"
// rather than letting it cascade into a truncated json.Unmarshal parse
// error — which would name the wrong root cause to a triaging engineer.
//
// publicALBLockdownBodyCap=4096 is comfortable headroom over the ~30-byte
// fixed-response body. Overflow signals a fixed-response → forward
// regression where the backend hands back a large payload (e.g., the full
// QURL list from a misconfigured router).
func readCappedBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	const limit = publicALBLockdownBodyCap
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit+1)))
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) > limit {
		t.Fatalf("body overflowed %d-byte cap (got %d bytes — likely a fixed-response → forward regression returning a large payload)", limit, len(body))
	}
	return body
}
