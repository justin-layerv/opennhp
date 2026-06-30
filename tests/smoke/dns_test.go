//go:build smoke

// Unit tests for the helpers in dns.go. Not a tiered smoke test —
// this file pairs with dns.go the same way ssm_probe_test.go pairs
// with ssm_probe.go (no 01_–29_ prefix, no live AWS or network).
// The smoke-suite maintenance rules in CLAUDE.md (one-file-per-
// capability, tier-prefix naming) apply to capability tests, not
// helper tests.

package smoke

import (
	"slices"
	"testing"
)

// TestDeriveEndpoints_ProdQurlHostsAreRegisteredApexes fences the
// regression class that produced #1329: a prod entry in
// deriveEndpoints that still carried a sandbox-shaped `.layerv.*`
// sub-FQDN where prod terraform uses the registered apexes
// `qurl.site` / `qurl.link`. NHPServerBaseURL and QURLAPIBaseURL
// are intentionally not checked here — they legitimately ride
// other apexes (qurl.link, layerv.ai) per
// terraform/environments/prod/terraform.tfvars.
//
// Exact-equality (not a substring check) so a typo or a
// well-meaning swap like `qurl.link` ⇄ `qurl.site` also fails —
// these are checked-in defaults, not values that legitimately
// change at runtime, so coupling the test to the value is free.
func TestDeriveEndpoints_ProdQurlHostsAreRegisteredApexes(t *testing.T) {
	prod, err := deriveEndpoints("prod")
	if err != nil {
		t.Fatalf("deriveEndpoints(prod): %v", err)
	}

	cases := []struct {
		field, got, want string
	}{
		{"QURLSiteDomain", prod.QURLSiteDomain, "qurl.site"},
		{"QURLLinkOrigin", prod.QURLLinkOrigin, "https://qurl.link"},
		// Pin the qurl-service #335 internal-ALB hostname so a
		// rebrand like "internal-api" → "private-api" doesn't slip
		// past review. The hostname must stay under qurl.layerv.ai
		// so the public DNS-01 cert validation continues to work
		// against the layerv.ai mgmt zone.
		{"QURLInternalAPIHostname", prod.QURLInternalAPIHostname, "internal-api.qurl.layerv.ai"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("prod %s = %q, want %q (drift away from registered apex — see #1329)",
				c.field, c.got, c.want)
		}
	}
}

// TestDeriveEndpoints_SandboxValuesArePinned guards the inverse —
// sandbox values are expected to be sub-FQDNs under layerv.xyz so a
// future "fix" that mistakenly switches them to the prod apex would
// also be caught. Pairs with the prod test above to lock both rows
// of the table.
//
// Exact-equality matches the prod test's shape — the same rationale
// applies (checked-in defaults, no runtime mutation, coupling is
// free).
func TestDeriveEndpoints_SandboxValuesArePinned(t *testing.T) {
	sandbox, err := deriveEndpoints("sandbox")
	if err != nil {
		t.Fatalf("deriveEndpoints(sandbox): %v", err)
	}

	cases := []struct {
		field, got, want string
	}{
		{"NHPServerBaseURL", sandbox.NHPServerBaseURL, "https://resolve.qurl.link.layerv.xyz"},
		{"QURLAPIBaseURL", sandbox.QURLAPIBaseURL, "https://api.layerv.xyz"},
		{"QURLInternalAPIHostname", sandbox.QURLInternalAPIHostname, "internal-api.qurl.layerv.xyz"},
		{"QURLSiteDomain", sandbox.QURLSiteDomain, "qurl.site.layerv.xyz"},
		{"QURLLinkOrigin", sandbox.QURLLinkOrigin, "https://qurl.link.layerv.xyz"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("sandbox %s = %q, want %q", c.field, c.got, c.want)
		}
	}
}

// TestDeriveEndpoints_ResolveEndpointTracksJSAgent fences the
// topology gate that 01/09/10/12/13/14/21/24 key on: an env's
// derivedEndpoints.ResolveEndpointEnabled MUST be the inverse of the
// browser-JS-agent switch (qurlLinkJSAgentEnabledEnvs, the smoke
// mirror of qurl_link_js_agent_enabled), because turning on the
// JS-agent + relay topology is exactly what tears down the legacy
// server-side resolve.qurl.link surface (terraform local
// `qurl_resolve_endpoint_enabled = deploy_qurl_link &&
// !qurl_link_js_agent_enabled`). Without this fence the two per-env
// mirrors could drift — e.g. someone flips qurlLinkJSAgentEnabledEnvs
// for a new env but forgets ResolveEndpointEnabled — and the gated
// tests would either hammer a dead endpoint or skip a live one.
//
// RelayBaseURL is pinned alongside so the protocol-surface re-home
// target can't silently go empty in a JS-agent env (which would make
// nhpIngressTLSURL skip the TLS fence instead of asserting it), and is
// additionally cross-checked against qurlLinkJSAgentNetworkOrigins (the
// CSP connect-src mirror of the same relay_dns_name tfvar) so the relay
// host has a single drift fence rather than two independent literals.
func TestDeriveEndpoints_ResolveEndpointTracksJSAgent(t *testing.T) {
	cases := []struct {
		env                string
		wantResolveEnabled bool
		wantRelayBaseURL   string
	}{
		{"local", true, ""},
		{"sandbox", false, "https://relay.qurl.link.layerv.xyz"},
		{"prod", true, ""},
	}
	for _, c := range cases {
		d, err := deriveEndpoints(c.env)
		if err != nil {
			t.Fatalf("deriveEndpoints(%q): %v", c.env, err)
		}
		if d.ResolveEndpointEnabled != c.wantResolveEnabled {
			t.Errorf("%s ResolveEndpointEnabled = %v, want %v", c.env, d.ResolveEndpointEnabled, c.wantResolveEnabled)
		}
		if d.RelayBaseURL != c.wantRelayBaseURL {
			t.Errorf("%s RelayBaseURL = %q, want %q", c.env, d.RelayBaseURL, c.wantRelayBaseURL)
		}
		// The load-bearing invariant: resolve surface present iff the
		// JS-agent is NOT enabled for this env.
		if want := !qurlLinkJSAgentEnabledEnvs[c.env]; d.ResolveEndpointEnabled != want {
			t.Errorf("%s: ResolveEndpointEnabled (%v) must equal !qurlLinkJSAgentEnabledEnvs[%q] (%v) — the two per-env mirrors drifted",
				c.env, d.ResolveEndpointEnabled, c.env, want)
		}
		// Single source of truth for the relay host: in a JS-agent env the
		// re-home target (RelayBaseURL) must be one of the browser connect-src
		// origins the CSP mirror already pins (qurlLinkJSAgentNetworkOrigins),
		// so the two relay-DNS mirrors of relay_dns_name can't drift apart.
		if qurlLinkJSAgentEnabledEnvs[c.env] {
			if origins := qurlLinkJSAgentNetworkOrigins[c.env]; !slices.Contains(origins, d.RelayBaseURL) {
				t.Errorf("%s: RelayBaseURL %q not in qurlLinkJSAgentNetworkOrigins[%q] %v — the two relay-DNS mirrors drifted",
					c.env, d.RelayBaseURL, c.env, origins)
			}
		}
	}

	// Anti-drift: the loop only fences envs present in `cases`. Assert every
	// JS-agent env is covered, so a new entry in qurlLinkJSAgentEnabledEnvs
	// (the CLAUDE.md "both-places edit") can't silently escape the
	// ResolveEndpointEnabled-inverse and RelayBaseURL cross-checks above.
	// (Widening this to assert `cases` covers every env deriveEndpoints accepts
	// needs a canonical env enum that doesn't exist yet — tracked in #2915.)
	covered := make(map[string]bool, len(cases))
	for _, c := range cases {
		covered[c.env] = true
	}
	for env := range qurlLinkJSAgentEnabledEnvs {
		if !covered[env] {
			t.Errorf("qurlLinkJSAgentEnabledEnvs has env %q with no case in TestDeriveEndpoints_ResolveEndpointTracksJSAgent — add it so its resolve/relay invariants are fenced", env)
		}
	}
}

// TestDeriveEndpoints_UnknownEnvErrors keeps the error path on its
// contract: anything other than {sandbox, prod} returns a non-nil
// error and a zero-value struct. A silent fallback would mask
// misconfiguration in CI.
//
// The argument is a synthetic name rather than a plausible env
// like "staging" so this test cannot break by side effect when
// a real new environment is added — see the doc comment on
// deriveEndpoints which already calls out staging as an example.
func TestDeriveEndpoints_UnknownEnvErrors(t *testing.T) {
	const notARealEnv = "not-a-real-env"
	got, err := deriveEndpoints(notARealEnv)
	if err == nil {
		t.Fatalf("deriveEndpoints(%q): want error, got nil with %+v", notARealEnv, got)
	}
	if got != (derivedEndpoints{}) {
		t.Errorf("deriveEndpoints(%q) returned non-zero struct on error: %+v", notARealEnv, got)
	}
}
