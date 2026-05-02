//go:build smoke

// Unit tests for the helpers in dns.go. Not a tiered smoke test —
// this file pairs with dns.go the same way ssm_probe_test.go pairs
// with ssm_probe.go (no 01_–29_ prefix, no live AWS or network).
// The smoke-suite maintenance rules in CLAUDE.md (one-file-per-
// capability, tier-prefix naming) apply to capability tests, not
// helper tests.

package smoke

import "testing"

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
