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
	QURLAPIBaseURL   string

	// QURLSiteDomain is the parent domain of per-resource qurl.site
	// hostnames (e.g., qurl.site.layerv.xyz in sandbox — every
	// resource gets r_{id}.qurl.site.layerv.xyz). Tier 2 resolve
	// tests assert cookies are scoped to this domain and that the
	// 302 Location host has this as its suffix.
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
			NHPServerBaseURL: "https://resolve.qurl.link.layerv.xyz",
			QURLAPIBaseURL:   "https://api.layerv.xyz",
			QURLSiteDomain:   "qurl.site.layerv.xyz",
			QURLLinkOrigin:   "https://qurl.link.layerv.xyz",
		}, nil
	case "prod":
		return derivedEndpoints{
			NHPServerBaseURL: "https://resolve.qurl.link",
			QURLAPIBaseURL:   "https://api.layerv.ai",
			QURLSiteDomain:   "qurl.site.layerv.ai",
			QURLLinkOrigin:   "https://qurl.link",
		}, nil
	default:
		return derivedEndpoints{}, fmt.Errorf("unknown environment %q (want sandbox or prod)", env)
	}
}
