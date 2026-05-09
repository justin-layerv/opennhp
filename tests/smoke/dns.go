//go:build smoke

package smoke

import "fmt"

// derivedEndpoints holds the default URLs for a given NHP environment.
// Tests and TestMain read these as fallbacks; explicit env vars take
// precedence.
//
// NOTE: NHPServerBaseURL is the nhp-server's NLB endpoint at
// resolve.qurl.link.*, NOT api.layerv.* (which is QURL service).
// /health/* and /plugins/* are served on the NHP server; /v1/* is
// served on the QURL API.
type derivedEndpoints struct {
	NHPServerBaseURL string

	// NHPServerOriginURL is the NLB-direct hostname for the NHP server's
	// HTTPS plugin endpoint, BYPASSING any CloudFront in front of
	// resolve.qurl.link. Used by the keep-alive idle-timeout fence
	// (09_resolve_origin_idle_timeout_test.go) to probe the server
	// directly. Prefer NHPServerBaseURL for any test that wants the
	// production traffic path; this is for tests that specifically need
	// to bypass CF (e.g., to fence server-side timeout behavior, which
	// CF would mask via origin connection pooling and retries).
	NHPServerOriginURL string

	QURLAPIBaseURL string

	// QURLInternalAPIHostname is the qurl-service internal ALB hostname.
	// Empty when the internal ALB is not yet enabled (allowing the new
	// fence tests to skip cleanly in pre-rollout environments).
	QURLInternalAPIHostname string

	// QURLSiteDomain is the parent domain of per-resource qurl.site
	// hostnames. The shape differs by environment: sandbox uses the
	// sub-FQDN `qurl.site.layerv.xyz` (so per-resource hosts are
	// r_{id}.qurl.site.layerv.xyz); prod uses the registered apex
	// `qurl.site` directly (so per-resource hosts are r_{id}.qurl.site).
	// Tier 2 resolve tests assert cookies are scoped to this domain
	// and that the 302 Location host has this as its suffix.
	QURLSiteDomain string

	// QURLLinkOrigin is the origin (scheme + host) of the qurl.link
	// page that the SPA loads from. Tier 2 negotiation tests use it
	// as the Origin header on cross-origin fetch() simulations and
	// assert the server echoes it back in Access-Control-Allow-Origin.
	QURLLinkOrigin string
}

// deriveEndpoints returns the default URL set for the named environment.
// Adding a new environment (e.g., staging) means adding a case here —
// no test body needs to change.
func deriveEndpoints(env string) (derivedEndpoints, error) {
	switch env {
	case "sandbox":
		return derivedEndpoints{
			NHPServerBaseURL:        "https://resolve.qurl.link.layerv.xyz",
			NHPServerOriginURL:      "https://resolve-origin.qurl.link.layerv.xyz",
			QURLAPIBaseURL:          "https://api.layerv.xyz",
			QURLInternalAPIHostname: "internal-api.qurl.layerv.xyz",
			QURLSiteDomain:          "qurl.site.layerv.xyz",
			QURLLinkOrigin:          "https://qurl.link.layerv.xyz",
		}, nil
	case "prod":
		return derivedEndpoints{
			NHPServerBaseURL:        "https://resolve.qurl.link",
			NHPServerOriginURL:      "https://resolve-origin.qurl.link",
			QURLAPIBaseURL:          "https://api.layerv.ai",
			QURLInternalAPIHostname: "internal-api.qurl.layerv.ai",
			// Prod uses the registered apex `qurl.site` directly, so
			// per-resource hosts are r_{id}.qurl.site (not the
			// sandbox-style `qurl.site.layerv.xyz`). Mirrors the
			// terraform/environments/prod qurl_site_domain value.
			QURLSiteDomain: "qurl.site",
			QURLLinkOrigin: "https://qurl.link",
		}, nil
	default:
		return derivedEndpoints{}, fmt.Errorf("unknown environment %q (want sandbox or prod)", env)
	}
}
